#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Durable, authenticated per-run process supervisor.

Windows production builds use a current-user-only named pipe and a named Job
Object. The Job deliberately omits KILL_ON_JOB_CLOSE so console restarts do not
terminate managed applications. TCP exists only as an explicit test transport.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


METADATA_SCHEMA_VERSION = 2
PROTOCOL_VERSION = 2
SUPERVISOR_VERSION = "2.0.0"
MAX_REQUEST = 64 * 1024
AUTH_CLOCK_SKEW_SEC = 30.0
NONCE_TTL_SEC = 90.0


class RuntimeCleanupUnconfirmed(RuntimeError):
    """A launched runtime could not be published or proven terminated."""


def _windows_runtime():
    import supervisor_windows
    return supervisor_windows


def _secure_directory(path, secure_windows=True):
    os.makedirs(path, exist_ok=True)
    if os.name == "nt" and secure_windows:
        _windows_runtime().secure_path(path, directory=True)
    elif os.name != "nt":
        os.chmod(path, 0o700)


def _atomic_json(path, value, secure_windows=True):
    directory = os.path.dirname(os.path.abspath(path))
    _secure_directory(directory, secure_windows=secure_windows)
    fd, temporary = tempfile.mkstemp(prefix="runtime-", suffix=".tmp", dir=directory)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        replace_deadline = time.monotonic() + 1.0
        while True:
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                # A Windows reader that opened the previous metadata without
                # FILE_SHARE_DELETE can make ReplaceFile/MoveFileEx fail with
                # ERROR_ACCESS_DENIED for a few milliseconds.  The launcher
                # polls this file during starting -> running publication, so
                # retry only this transient class with a strict bound.  A
                # persistent denial still enters the startup rollback path.
                if os.name != "nt" or time.monotonic() >= replace_deadline:
                    raise
                time.sleep(0.01)
        if os.name == "nt" and secure_windows:
            _windows_runtime().secure_path(path, directory=False)
        elif os.name != "nt":
            os.chmod(path, 0o600)
    finally:
        try:
            os.remove(temporary)
        except OSError:
            pass


def _read_socket_request(connection):
    chunks = []
    size = 0
    while True:
        chunk = connection.recv(min(4096, MAX_REQUEST - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if b"\n" in chunk:
            break
        if size >= MAX_REQUEST:
            raise ValueError("request too large")
    raw = b"".join(chunks).split(b"\n", 1)[0]
    if not raw:
        raise ValueError("empty request")
    return raw


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _request_message(action, nonce, issued_at=None, run_id=None):
    if issued_at is None and run_id is None:
        # Compatibility for primitive-level tests only. Production requires all fields.
        return (str(action) + "\n" + str(nonce)).encode("utf-8")
    return ("%s\n%s\n%s\n%s\n%s" % (
        PROTOCOL_VERSION, run_id, action, nonce, issued_at
    )).encode("utf-8")


def _sign(token, action, nonce, issued_at=None, run_id=None):
    return hmac.new(
        token.encode("utf-8"),
        _request_message(action, nonce, issued_at, run_id),
        hashlib.sha256,
    ).hexdigest()


def _sign_response(token, request_nonce, value):
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    payload = ("response\n%s\n%s" % (request_nonce, canonical)).encode("utf-8")
    return hmac.new(token.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _native_launch_command(command):
    """Prepare an exact CreateProcess command line for ``cmd /S /C``.

    ``cmd.exe`` does not use the normal Windows argv parser. Passing a user
    command containing quotes as the last item of an argv list makes Python's
    ``list2cmdline`` escape those quotes with backslashes, which cmd treats as
    literal characters. Keep argv for every other executable, but give cmd a
    raw command line with the outer quote pair around the complete command.
    """
    if os.name != "nt" or not isinstance(command, (list, tuple)):
        return command
    if len(command) != 5:
        return command
    argv = [str(part) for part in command]
    executable = os.path.basename(argv[0]).casefold()
    if (executable not in ("cmd", "cmd.exe")
            or [part.casefold() for part in argv[1:4]]
            != ["/d", "/s", "/c"]):
        return command
    return subprocess.list2cmdline(argv[:4]) + ' "' + argv[4] + '"'


def _derived_wsl_token(token, run_id):
    return hmac.new(
        token.encode("utf-8"),
        ("wsl-session\n" + run_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _parse_json_line(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    for line in reversed([line.strip() for line in str(data).splitlines() if line.strip()]):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("helper did not return a JSON object")


class Supervisor:
    def __init__(self, args):
        self.args = args
        self.token = args.token or os.environ.get("CONSOLE_SUPERVISOR_TOKEN", "")
        if len(self.token) < 32:
            raise ValueError("supervisor token must contain at least 32 characters")
        self.token_hash = _token_hash(self.token)
        expected_cancel = os.path.abspath(args.metadata) + ".startup-cancel"
        startup_cancel = getattr(args, "startup_cancel", expected_cancel)
        if os.path.abspath(startup_cancel) != expected_cancel:
            raise ValueError("invalid supervisor startup cancel marker")
        self._startup_cancel = startup_cancel
        self._raise_if_startup_cancelled()
        self.started_at = time.time()
        self.child = None
        self.child_identity = None
        self.exit_code = None
        self.stop_requested = False
        self.force_requested = False
        self._closed = threading.Event()
        self._lock = threading.RLock()
        self._persist_lock = threading.Lock()
        self._server = None
        self._port = None
        self._pipe_name = None
        self._job_name = None
        self._job = None
        self._nonce_times = {}
        self._control_thread = None
        self._response_in_flight = threading.Event()
        self._final_persisted = threading.Event()
        self._terminal_metadata_durable = False
        self._terminal_reported = threading.Event()
        self._terminal_observed = threading.Event()
        self._transport = None
        self._owner_sid = None
        self._supervisor_identity = None
        self._wsl_token = None
        self._wsl_last_status = None
        self._wsl_running = False
        self._wsl_child_pid = None
        self._wsl_child_create_time = None
        self._wsl_child_uid = None
        self._wsl_launcher_pid = None
        self._wsl_launch_attempted = False
        self._wsl_control_lock = threading.Lock()
        self._wsl_terminal_reason = None
        # The control endpoint and this authenticated starting identity are
        # published before any user process/session is created.  If the first
        # running-state write later fails, this durable identity remains a
        # recovery anchor for the launcher and console.
        self._launch_state = "starting"
        self._launch_failure_error = None
        self._volatile_recovery = False
        self._startup_published = False
        # ``launch()`` returns only after the first running or terminal
        # identity was durably published.  From that point onward no failure
        # is a startup failure: the supervisor must keep its authenticated
        # control endpoint alive until it can prove/serve a terminal state.
        self._runtime_committed = False
        self._configure_platform()

    def _raise_if_startup_cancelled(self):
        """Fail closed when the launching client has abandoned this start."""
        marker = self._startup_cancel
        try:
            with open(marker, "r", encoding="ascii") as stream:
                value = stream.read(129)
        except FileNotFoundError:
            return
        if len(value) > 128 or not hmac.compare_digest(
                value.strip(), self.token_hash):
            raise RuntimeError("invalid supervisor startup cancel marker")
        raise TimeoutError("supervisor startup canceled by launcher")

    def _configure_platform(self):
        if self.args.test_transport:
            if (self.args.test_transport != "tcp" or
                    os.environ.get("CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT") != "1"):
                raise RuntimeError("insecure test transport is not enabled")
            self._transport = "test-tcp"
            self._owner_sid = "test-current-user" if os.name == "nt" else "uid:%s" % os.getuid()
            self._supervisor_identity = {
                "pid": os.getpid(), "createTime": self.started_at, "ownerSid": self._owner_sid,
            }
            return
        if os.name != "nt":
            self._transport = "test-tcp"
            self._owner_sid = "uid:%s" % os.getuid()
            self._supervisor_identity = {
                "pid": os.getpid(), "createTime": self.started_at, "ownerSid": self._owner_sid,
            }
            return
        windows = _windows_runtime()
        windows.validate_runtime()
        windows.ensure_private_console(
            expect_preallocated=bool(
                getattr(self.args, "preallocated_console", False)))
        self._transport = "windows-named-pipe"
        self._owner_sid = windows.current_user_sid()
        self._supervisor_identity = windows.process_identity(os.getpid())
        self._pipe_name, self._job_name = windows.names(self.args.run_id, self.token_hash)
        self._job = windows.create_job(self._job_name)

    def metadata(self):
        with self._lock:
            native_exit_pending = False
            if self.args.environment == "wsl":
                running = bool(self._wsl_running)
                child_pid = self._wsl_child_pid
                child_create_time = self._wsl_child_create_time
                child_owner = (
                    "wsl:%s:uid:%s" % (self.args.distro, self._wsl_child_uid)
                    if self._wsl_child_uid is not None else None
                )
            else:
                job_pids = self._native_process_ids()
                running = bool(job_pids)
                job_processes = self._native_process_identities()
                child_pid = self.child.pid if self.child else None
                child_create_time = self.child_identity.get("createTime") if self.child_identity else None
                child_owner = self.child_identity.get("ownerSid") if self.child_identity else None
                # A Windows Job can become empty a few milliseconds before the
                # root Popen handle reports its exit code. Make this a metadata
                # invariant rather than relying on a launch-thread state write:
                # no writer may ever publish native exited/null and let a
                # client ACK (or classify) it before the code is reaped.
                native_exit_pending = bool(
                    self.child is not None and not running
                    and self.exit_code is None
                    and not self._final_persisted.is_set())
                if native_exit_pending:
                    running = True
            state = self._launch_state
            if native_exit_pending:
                state = "exiting"
            elif not state:
                state = (
                    self._wsl_terminal_reason or
                    ("running" if running else "exited")
                    if self.args.environment == "wsl"
                    else ("running" if running else "exited")
                )
            result = {
                "schemaVersion": METADATA_SCHEMA_VERSION,
                "protocolVersion": PROTOCOL_VERSION,
                "supervisorVersion": self.args.supervisor_version,
                "supervisorImplementationVersion": SUPERVISOR_VERSION,
                "supervisorExecutable": os.path.abspath(
                    sys.executable if getattr(sys, "frozen", False) else __file__
                ),
                "runId": self.args.run_id,
                "environment": self.args.environment,
                "distro": self.args.distro,
                "transport": self._transport,
                "testOnly": self._transport == "test-tcp",
                "supervisorPid": os.getpid(),
                "supervisorCreateTime": self._supervisor_identity["createTime"],
                "ownerSid": self._owner_sid,
                "childPid": child_pid,
                "childCreateTime": child_create_time,
                "childOwnerSid": child_owner,
                "createTime": self.started_at,
                "pipeName": self._pipe_name,
                "controlHost": "127.0.0.1" if self._transport == "test-tcp" else None,
                "controlPort": self._port,
                "jobName": self._job_name,
                "jobProcessIds": job_pids if self.args.environment == "native" else [],
                "jobProcesses": job_processes if self.args.environment == "native" else [],
                "tokenHash": self.token_hash,
                "commandHash": hashlib.sha256("\0".join(self.args.command).encode("utf-8")).hexdigest(),
                "running": running,
                "state": state,
                "startupError": self._launch_failure_error,
                "stopRequested": self.stop_requested,
                "forceRequested": self.force_requested,
                "exitCode": self.exit_code,
                "updatedAt": time.time(),
            }
            if self.args.environment == "wsl":
                result["wsl"] = {
                    "distro": self.args.distro,
                    "bootId": self.args.wsl_boot_id,
                    "sessionId": self.args.run_id,
                    "socket": self.args.wsl_socket,
                    "metadata": self.args.wsl_metadata,
                    "helperPath": self.args.wsl_helper_path,
                    "logPath": self.args.wsl_log,
                    "tokenHash": _token_hash(self._wsl_token or ""),
                    "launcherPid": self._wsl_launcher_pid,
                    "lastStatus": self._wsl_last_status,
                }
            return result

    def persist(self):
        # All writers use state -> persist lock order.  Keeping the state lock
        # through the replace means a delayed running writer cannot complete
        # after (and overwrite) a newer terminal/stop snapshot.
        with self._lock:
            with self._persist_lock:
                _atomic_json(
                    self.args.metadata,
                    self.metadata(),
                    secure_windows=self._transport != "test-tcp",
                )

    def _persist_control_state(self):
        """Persist a post-launch transition without disabling recovery control.

        The initial ``starting`` and first running/terminal publications use
        ``persist()`` directly and retain their transactional rollback rules.
        Every later control/terminal write is different: a durable runtime
        identity already exists, so a storage error must keep the Job/session
        and authenticated control endpoint alive instead of escaping to
        ``main()`` and being mislabeled as ``startup-failed``.
        """
        try:
            self.persist()
            return True
        except Exception as exc:
            self._enter_volatile_recovery(
                "runtime metadata persistence failed", exc)
            return False

    def _enter_volatile_recovery(self, context, error):
        """Record a post-publication fault without surrendering control."""
        message = "%s: %s" % (context, error)
        should_log = False
        with self._lock:
            self._volatile_recovery = True
            existing = str(self._launch_failure_error or "")
            if message not in existing:
                self._launch_failure_error = (
                    "%s; %s" % (existing, message) if existing else message
                )
                should_log = True
        if should_log:
            try:
                self._append_supervisor_log(
                    "\n[supervisor recovery; retaining control] %s\n" % message
                )
            except Exception:
                pass

    def _abort_unpublished_launch(self):
        """Clean up a runtime whose running identity was not committed.

        Returns ``(ok, error)``.  A false result means the caller must keep this
        supervisor and its token alive; it is never safe to turn an unproven
        cleanup into an ordinary startup failure.
        """
        if self.args.environment == "wsl":
            # The caller reached this path because the running-state publish
            # failed (or the start handshake was unusable). A successful
            # authenticated force-stop is cleanup proof even if persisting its
            # terminal helper status hits the same storage error again.
            self._volatile_recovery = True
            # session-start launches session-run with setsid before returning
            # its authenticated JSON handshake.  A timeout, malformed reply,
            # or helper-side handshake error can therefore leave a controllable
            # session even though _update_wsl_status has not run yet.  Always
            # try the token-authenticated force-stop after wsl.exe was launched;
            # the helper itself rejects missing, stale, or mismatched sessions.
            if (self._wsl_running or
                    getattr(self, "_wsl_launch_attempted", False)):
                try:
                    result = self._wsl_control("force-stop")
                except Exception as exc:
                    return False, "WSL force-stop cleanup failed: %s" % exc
                if result.get("ok") is True and not result.get("running"):
                    return True, None
                return False, str(
                    result.get("error") or
                    "WSL force-stop did not prove a terminal session")
            return True, None
        if self.child is None:
            return True, None
        try:
            if (os.name == "nt" and self._transport == "windows-named-pipe"
                    and self._job is not None):
                windows = _windows_runtime()
                windows.terminate_job(self._job, 130)
                self._wait_native_exit(5.0)
                remaining = windows.job_process_ids(self._job)
                if remaining:
                    return False, "managed Job still contains processes: %s" % remaining
            elif self.child.poll() is None:
                if os.name != "nt":
                    os.killpg(self.child.pid, signal.SIGKILL)
                else:
                    self.child.kill()
                try:
                    self.child.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    return False, "unpublished child did not exit after SIGKILL"
            if self.child.poll() is None:
                return False, "unpublished child is still running"
            return True, None
        except (OSError, RuntimeError, ProcessLookupError) as exc:
            return False, "unpublished runtime cleanup failed: %s" % exc

    def _retain_unpublished_runtime(self, original_error, cleanup_error):
        self._volatile_recovery = True
        self._launch_state = "startup-cleanup-failed"
        self._launch_failure_error = (
            "running metadata publication failed: %s; cleanup unconfirmed: %s"
            % (original_error, cleanup_error or "unknown error")
        )
        return RuntimeCleanupUnconfirmed(self._launch_failure_error)

    def _native_launch_options(self):
        if os.name == "nt" and self._transport == "windows-named-pipe":
            return _windows_runtime().hidden_process_options()
        if os.name != "nt":
            return {"start_new_session": True}
        return {"creationflags": (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) |
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )}

    def _wsl_start_command(self):
        required = {
            "distro": self.args.distro,
            "helper path": self.args.wsl_helper_path,
            "socket": self.args.wsl_socket,
            "metadata": self.args.wsl_metadata,
            "Linux log path": self.args.wsl_log,
            "boot ID": self.args.wsl_boot_id,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError("WSL supervisor missing: " + ", ".join(missing))
        if not str(self.args.wsl_helper_path).startswith("/"):
            raise ValueError("WSL helper path must be an absolute Linux path")
        distro = str(self.args.distro)
        if (len(distro) > 128 or distro.startswith("-") or
                any(mark in distro for mark in ("/", "\\")) or
                any(ord(char) < 32 for char in distro)):
            raise ValueError("invalid WSL distribution name")
        for name, value in required.items():
            if any(mark in str(value) for mark in ("\x00", "\r", "\n")):
                raise ValueError("invalid WSL %s" % name)
        self._wsl_token = _derived_wsl_token(self.token, self.args.run_id)
        command_text = self.args.command[0] if len(self.args.command) == 1 else shlex.join(self.args.command)
        return [
            "wsl.exe", "-d", self.args.distro, "--", self.args.wsl_helper_path,
            "session-start", "--json", "--session-id", self.args.run_id,
            "--token-stdin", "--socket", self.args.wsl_socket,
            "--metadata", self.args.wsl_metadata, "--log", self.args.wsl_log,
            "--cwd", self.args.cwd or "/", "--kind", self.args.wsl_kind,
            "--command", command_text,
        ]

    @staticmethod
    def _decode_windows_output(data):
        if not data:
            return ""
        if isinstance(data, str):
            return data
        # Legacy wsl.exe commonly writes UTF-16LE when stdout is redirected.
        encoding = "utf-16-le" if b"\x00" in data[:8] else "utf-8"
        return data.decode(encoding, errors="replace").replace("\x00", "")

    def _append_supervisor_log(self, text):
        if not text:
            return
        with open(self.args.log, "ab", buffering=0) as stream:
            stream.write(str(text).encode("utf-8", errors="replace"))

    def _update_wsl_status(self, result, require_running_identity=False):
        if not isinstance(result, dict):
            raise ValueError("WSL helper response is not an object")
        if result.get("ok") is not True:
            return result
        if result.get("sessionId") != self.args.run_id:
            raise ValueError("WSL session identity changed")
        if result.get("bootId") != self.args.wsl_boot_id:
            raise ValueError("WSL distribution boot identity changed")
        response_hash = result.get("tokenHash")
        expected_hash = _token_hash(self._wsl_token)
        if response_hash is not None and not hmac.compare_digest(str(response_hash), expected_hash):
            raise ValueError("WSL session token identity changed")
        state = str(result.get("state") or "").lower()
        running = result.get("running")
        if not isinstance(running, bool):
            running = state in ("starting", "running", "stopping")
        pid = result.get("pid", result.get("childPid"))
        if running and (not isinstance(pid, int) or pid <= 0):
            raise ValueError("running WSL session omitted its Linux PID")
        response_uid = result.get("uid")
        if running and (not isinstance(response_uid, int) or response_uid < 0):
            raise ValueError("running WSL session omitted its Linux UID")
        if (self._wsl_child_uid is not None and response_uid is not None and
                response_uid != self._wsl_child_uid):
            raise ValueError("WSL session user identity changed")
        if (require_running_identity and not running and
                result.get("exitCode") is None and not isinstance(result.get("exit"), dict)):
            raise ValueError("WSL session did not reach a running or completed state")
        self._wsl_running = bool(running)
        self._wsl_child_pid = pid if isinstance(pid, int) and pid > 0 else self._wsl_child_pid
        self._wsl_child_create_time = result.get(
            "startTicks",
            result.get("startTimeTicks", result.get("createTime", self._wsl_child_create_time)),
        )
        self._wsl_child_uid = response_uid if response_uid is not None else self._wsl_child_uid
        exit_record = result.get("exit")
        if not running and isinstance(exit_record, dict):
            code = exit_record.get("code")
            exit_signal = exit_record.get("signal")
            if isinstance(code, int):
                self.exit_code = code
            elif isinstance(exit_signal, int):
                self.exit_code = 128 + exit_signal
        elif not running and result.get("exitCode") is not None:
            self.exit_code = int(result["exitCode"])
        self._wsl_last_status = result
        return result

    def _launch_wsl_session(self):
        self._raise_if_startup_cancelled()
        command = self._wsl_start_command()
        options = {}
        if os.name == "nt":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        env = dict(os.environ)
        env.pop("CONSOLE_SUPERVISOR_TOKEN", None)
        env.pop("CONSOLE_RUN_TOKEN", None)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            **options,
        )
        self._wsl_launcher_pid = process.pid
        self._wsl_launch_attempted = True
        try:
            try:
                stdout, stderr = process.communicate(
                    input=(self._wsl_token + "\n").encode("utf-8"), timeout=20.0
                )
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5.0)
                raise RuntimeError("WSL helper session-start timed out")
            if stderr:
                self._append_supervisor_log(self._decode_windows_output(stderr))
            try:
                result = _parse_json_line(
                    self._decode_windows_output(stdout)
                    or self._decode_windows_output(stderr)
                )
            except ValueError as exc:
                raise RuntimeError(
                    "WSL helper session-start returned invalid JSON") from exc
            if process.returncode and result.get("ok") is not True:
                raise RuntimeError(
                    result.get("error") or "WSL helper session-start failed")
            self._update_wsl_status(result, require_running_identity=True)
            self._raise_if_startup_cancelled()
            self._launch_state = None
            self.persist()
        except Exception as exc:
            # This covers failures before identity parsing as well as first
            # persistence.  Once Popen succeeded, session-run may already be
            # detached from the short-lived wsl.exe launcher.
            cleanup_ok, cleanup_error = self._abort_unpublished_launch()
            if not cleanup_ok:
                raise self._retain_unpublished_runtime(
                    exc, cleanup_error) from exc
            raise
        if not self._wsl_running:
            self._terminal_metadata_durable = True
            self._final_persisted.set()

    def launch(self):
        self._raise_if_startup_cancelled()
        if self.args.environment == "wsl":
            os.makedirs(os.path.dirname(os.path.abspath(self.args.log)), exist_ok=True)
            self._append_supervisor_log("\n===== supervisor %s · %s =====\n" % (
                self.args.run_id, time.strftime("%Y-%m-%d %H:%M:%S")
            ))
            self._launch_wsl_session()
            return
        command = _native_launch_command(self.args.command)
        cwd = self.args.cwd or None
        env = dict(os.environ)
        # Never leak the control secret to a managed application.
        env.pop("CONSOLE_SUPERVISOR_TOKEN", None)
        env.pop("CONSOLE_RUN_TOKEN", None)
        env["CONSOLE_RUN_ID"] = self.args.run_id
        os.makedirs(os.path.dirname(os.path.abspath(self.args.log)), exist_ok=True)
        log = open(self.args.log, "ab", buffering=0)
        log.write(("\n===== supervisor %s · %s =====\n" % (
            self.args.run_id, time.strftime("%Y-%m-%d %H:%M:%S")
        )).encode("utf-8"))
        try:
            self.child = subprocess.Popen(
                command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, **self._native_launch_options(),
            )
            if os.name == "nt" and self._transport == "windows-named-pipe":
                windows = _windows_runtime()
                try:
                    self.child_identity = windows.process_identity(self.child.pid)
                    if self.child.poll() is None:
                        windows.assign_process(self._job, self.child.pid)
                        # The native root is still CREATE_SUSPENDED here.  A
                        # launcher timeout marker must win before user code is
                        # ever resumed.
                        self._raise_if_startup_cancelled()
                        windows.resume_process(self.child.pid)
                except Exception:
                    if self.child.poll() is None:
                        self.child.kill()
                        self.child.wait(timeout=5)
                        raise
                    # A very short task may finish before OpenProcess/Job
                    # assignment. It no longer represents a running identity,
                    # so record its completed result instead of misclassifying
                    # the launch itself as a supervisor failure.
                    self.child_identity = {
                        "pid": self.child.pid,
                        "createTime": None,
                        "ownerSid": self._owner_sid,
                    }
            else:
                self.child_identity = {
                    "pid": self.child.pid, "createTime": time.time(), "ownerSid": self._owner_sid,
                }
        finally:
            log.close()
        try:
            self._raise_if_startup_cancelled()
            # Status can reap the same fast child. Keep state selection and its
            # first publication in one state-lock transaction so a completed
            # terminal write can never be overwritten by a delayed exiting
            # snapshot from this launch thread.
            with self._lock:
                self._launch_state = None
                native_exit = self._finalize_native_exit(wait_timeout=0.0)
                if native_exit != "exited":
                    if native_exit == "exiting":
                        self._launch_state = "exiting"
                    self.persist()
        except Exception as exc:
            cleanup_ok, cleanup_error = self._abort_unpublished_launch()
            if not cleanup_ok:
                raise self._retain_unpublished_runtime(
                    exc, cleanup_error) from exc
            raise

    def _prune_nonces(self, now):
        self._nonce_times = {
            nonce: used for nonce, used in self._nonce_times.items()
            if now - used <= NONCE_TTL_SEC
        }

    def _authenticated(self, request):
        action = request.get("action")
        nonce = request.get("nonce")
        signature = request.get("signature")
        issued_at = request.get("issuedAt")
        run_id = request.get("runId")
        if (
            request.get("protocolVersion") != PROTOCOL_VERSION or run_id != self.args.run_id or
            not isinstance(action, str) or not isinstance(nonce, str) or
            not 16 <= len(nonce) <= 128 or not isinstance(signature, str) or
            not isinstance(issued_at, (int, float))
        ):
            return False
        now = time.time()
        if abs(now - float(issued_at)) > AUTH_CLOCK_SKEW_SEC:
            return False
        with self._lock:
            self._prune_nonces(now)
            if nonce in self._nonce_times:
                return False
            expected = _sign(self.token, action, nonce, issued_at, run_id)
            if not hmac.compare_digest(signature, expected):
                return False
            self._nonce_times[nonce] = now
        return True

    def _signed_response(self, value, nonce):
        response = {**value, "protocolVersion": PROTOCOL_VERSION, "requestNonce": nonce}
        response["responseSignature"] = _sign_response(self.token, nonce, response)
        return response

    def _record_exit(self):
        with self._lock:
            if (self.child and self.child.poll() is not None
                    and not self._final_persisted.is_set()):
                self.exit_code = self.child.returncode
                self._terminal_metadata_durable = (
                    self._persist_control_state())
                self._final_persisted.set()

    def _finalize_native_exit(self, wait_timeout=0.0):
        """Reap a Job-empty native root before publishing a terminal state.

        Returns ``running``, ``exiting``, ``exited``, or ``unavailable``.
        The short optional wait closes the normal Job-empty/Popen-signaled
        race for status requests. If the handle is not signaled, callers must
        expose the non-terminal ``exiting`` state instead of exited/null.
        """
        if self.args.environment != "native" or self.child is None:
            return "unavailable"
        if self._native_process_ids():
            return "running"
        return_code = self.child.poll()
        if return_code is None and float(wait_timeout) > 0:
            try:
                return_code = self.child.wait(
                    timeout=max(0.0, float(wait_timeout)))
            except subprocess.TimeoutExpired:
                return_code = self.child.poll()
        if return_code is None:
            return "exiting"
        with self._lock:
            self.exit_code = int(return_code)
            self._launch_state = None
            # _record_exit makes the terminal write/final-persisted event
            # happen before any signed terminal response can be ACKed.
            self._record_exit()
        return "exited"

    def _native_process_ids(self):
        if os.name == "nt" and self._transport == "windows-named-pipe" and self._job is not None:
            return _windows_runtime().job_process_ids(self._job)
        if self.child and self.child.poll() is None:
            return [self.child.pid]
        return []

    def _native_process_identities(self):
        if (os.name == "nt" and self._transport == "windows-named-pipe"
                and self._job is not None):
            return _windows_runtime().job_process_identities(
                self._job, expected_owner_sid=self._owner_sid)
        if self.child and self.child.poll() is None and self.child_identity:
            return [dict(self.child_identity)]
        return []

    def _wait_native_exit(self, timeout):
        deadline = time.monotonic() + max(0.0, float(timeout))
        while self._native_process_ids():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.025)
        if self.child and self.child.poll() is None:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                self.child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                return False
        return True

    def _send_windows_ctrl_break(self, process_group_id, expected_process_ids):
        """Send CTRL_BREAK to the managed group on the private console."""
        _windows_runtime().send_ctrl_break(
            int(process_group_id), expected_process_ids)

    def _wsl_distro_running(self):
        options = {}
        if os.name == "nt":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(
                ["wsl.exe", "--list", "--running", "--quiet"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3.0,
                check=False,
                **options,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, "cannot query running WSL distributions: %s" % exc
        if completed.returncode:
            return False, self._decode_windows_output(completed.stderr).strip() or "wsl.exe --list failed"
        names = {
            line.strip().casefold()
            for line in self._decode_windows_output(completed.stdout).splitlines()
            if line.strip()
        }
        return str(self.args.distro).casefold() in names, None

    def _wsl_runtime_identity(self):
        """Read the current distro boot/UID before touching a session socket."""
        command = [
            "wsl.exe", "-d", self.args.distro, "--", self.args.wsl_helper_path,
            "status", "--json",
        ]
        options = {}
        if os.name == "nt":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=3.0, check=False, **options,
            )
            result = _parse_json_line(
                self._decode_windows_output(completed.stdout)
                or self._decode_windows_output(completed.stderr)
            )
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return None, "cannot verify current WSL boot identity: %s" % exc
        if completed.returncode or result.get("ok") is not True:
            return None, str(
                result.get("error") or
                "WSL helper status exited %s" % completed.returncode)
        if result.get("protocolVersion") != PROTOCOL_VERSION:
            return None, "WSL helper status protocol version changed"
        boot_id = result.get("bootId")
        uid = result.get("uid")
        if not isinstance(boot_id, str) or not boot_id:
            return None, "WSL helper status omitted bootId"
        if not isinstance(uid, int) or uid < 0:
            return None, "WSL helper status omitted uid"
        return {"bootId": boot_id, "uid": uid}, None

    def _finalize_wsl_identity_loss(self, state, error, **flags):
        with self._lock:
            self._wsl_running = False
            self._wsl_terminal_reason = state
            self._launch_state = None
            result = {
                "ok": False,
                "running": False,
                "state": state,
                "sessionId": self.args.run_id,
                "bootId": self.args.wsl_boot_id,
                "error": error,
                **flags,
            }
            self._wsl_last_status = result
            self._terminal_metadata_durable = (
                self._persist_control_state())
            self._final_persisted.set()
            return result

    def _wsl_control(self, action):
        if not self._wsl_token:
            return {"ok": False, "error": "WSL session token unavailable"}
        with self._wsl_control_lock:
            running, query_error = self._wsl_distro_running()
            if not running:
                if query_error:
                    return {"ok": False, "error": query_error}
                return self._finalize_wsl_identity_loss(
                    "distro-stopped",
                    "WSL distribution is no longer running",
                    distroStopped=True,
                )
            runtime_identity, identity_error = self._wsl_runtime_identity()
            if runtime_identity is None:
                return {"ok": False, "error": identity_error}
            expected_uid = self._wsl_child_uid
            if (runtime_identity["bootId"] != self.args.wsl_boot_id or
                    (expected_uid is not None and
                     runtime_identity["uid"] != expected_uid)):
                return self._finalize_wsl_identity_loss(
                    "distro-restarted",
                    "WSL distribution boot or user identity changed",
                    distroRestarted=True,
                    identityMismatch=True,
                    currentBootId=runtime_identity["bootId"],
                    currentUid=runtime_identity["uid"],
                )
            timeout_ms = max(1, int(self.args.stop_timeout * 1000))
            command = [
                "wsl.exe", "-d", self.args.distro, "--", self.args.wsl_helper_path,
                "session-control", "--json", "--socket", self.args.wsl_socket,
                "--metadata", self.args.wsl_metadata, "--token-stdin",
                "--action", action,
                "--timeout-ms", str(timeout_ms),
            ]
            options = {}
            if os.name == "nt":
                options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                completed = subprocess.run(
                    command, input=(self._wsl_token + "\n").encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=max(2.0, self.args.stop_timeout + 2.0),
                    check=False, **options,
                )
                result = _parse_json_line(
                    self._decode_windows_output(completed.stdout)
                    or self._decode_windows_output(completed.stderr)
                )
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                return {"ok": False, "error": "WSL helper control failed: %s" % exc}
            if completed.returncode and result.get("ok") is not True:
                result.setdefault("error", "WSL helper exited %s" % completed.returncode)
            error_text = str(result.get("error") or "")
            if (result.get("ok") is not True and
                    "metadata still reports running" in error_text):
                # This exact marker is emitted only after the helper has
                # authenticated the private metadata file, boot ID, paths,
                # current UID, and token hash.  With the current boot already
                # verified above, a missing/stale socket is a terminal lost
                # session rather than a transient state to retry forever.
                return self._finalize_wsl_identity_loss(
                    "session-lost",
                    "authenticated WSL metadata is running but its control socket is unavailable",
                    sessionLost=True,
                )
            previous = (
                self._wsl_running, self._wsl_child_pid, self.exit_code,
                (self._wsl_last_status or {}).get("state"),
            )
            try:
                self._update_wsl_status(result)
            except ValueError as exc:
                return {"ok": False, "identityMismatch": True, "error": str(exc)}
            current = (
                self._wsl_running, self._wsl_child_pid, self.exit_code,
                (self._wsl_last_status or {}).get("state"),
            )
            if previous != current or action != "status":
                if not self._wsl_running:
                    self._wsl_terminal_reason = "exited"
                    self._launch_state = None
                durable = self._persist_control_state()
                if not self._wsl_running:
                    self._terminal_metadata_durable = durable
                    self._final_persisted.set()
            return result

    def _stop_native(self, force=False):
        with self._lock:
            process_ids = self._native_process_ids()
            if not process_ids:
                self._launch_state = None
                self._record_exit()
                return {"ok": True, "running": False}
            self.stop_requested = True
            self.force_requested = self.force_requested or bool(force)
            self._persist_control_state()
            try:
                if force:
                    if os.name == "nt" and self._transport == "windows-named-pipe":
                        if self._job is None:
                            return {"ok": False, "error": "managed Job is unavailable"}
                        _windows_runtime().terminate_job(self._job, 130)
                    elif os.name != "nt":
                        os.killpg(self.child.pid, signal.SIGKILL)
                    else:
                        self.child.kill()  # explicit test transport only
                elif os.name == "nt" and self._transport == "windows-named-pipe":
                    # CREATE_NEW_PROCESS_GROUP fixes the group ID to the root
                    # PID for the group's entire lifetime.  Descendants keep
                    # that ID even after the root shell exits.
                    self._send_windows_ctrl_break(self.child.pid, process_ids)
                elif os.name != "nt":
                    os.killpg(self.child.pid, signal.SIGTERM)
                else:
                    self.child.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
            except ProcessLookupError:
                self._record_exit()
                return {"ok": True, "running": False}
            except (PermissionError, OSError, RuntimeError) as exc:
                return {"ok": False, "running": bool(self._native_process_ids()),
                        "requiresForce": not force, "error": str(exc)}
        if not self._wait_native_exit(self.args.stop_timeout):
            if not force:
                return {"ok": False, "requiresForce": True, "running": True,
                        "error": "应用未在 %.1f 秒内退出" % self.args.stop_timeout}
            return {"ok": False, "running": True, "error": "Job termination did not complete"}
        self._launch_state = None
        self._record_exit()
        return {"ok": True, "running": False, "exitCode": self.exit_code}

    def _stop(self, force=False):
        if self.args.environment == "wsl":
            with self._lock:
                self.stop_requested = True
                self.force_requested = self.force_requested or bool(force)
                self._persist_control_state()
            result = self._wsl_control("force-stop" if force else "stop")
            if not force and result.get("running"):
                result.setdefault("ok", False)
                result["requiresForce"] = True
            return self._wrap_wsl_response(result)
        return self._stop_native(force)

    def _wrap_wsl_response(self, helper_status):
        """Keep Linux helper identity nested below the Windows supervisor."""
        response = {
            **self.metadata(),
            "ok": helper_status.get("ok") is True,
            "wslStatus": helper_status,
        }
        for key in ("running", "requiresForce", "error", "exit", "state"):
            if key in helper_status:
                response[key] = helper_status[key]
        return response

    def _status(self):
        if (self.args.environment == "wsl" and
                (self._wsl_running or
                 (self._volatile_recovery and self._wsl_launch_attempted))):
            helper_status = self._wsl_control("status")
            return self._wrap_wsl_response(helper_status)
        if self.args.environment == "native":
            native_exit = self._finalize_native_exit(wait_timeout=0.25)
            if native_exit == "exiting":
                value = self.metadata()
                value.update(running=True, state="exiting", exitCode=None)
                return {"ok": True, **value}
        return {"ok": True, **self.metadata()}

    def _handle_bytes(self, raw):
        nonce = ""
        try:
            request = json.loads(raw.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            nonce = request.get("nonce") if isinstance(request.get("nonce"), str) else ""
            if not self._authenticated(request):
                return _json_bytes(self._signed_response({"ok": False, "error": "unauthorized"}, nonce))
            action = request.get("action")
            if action == "status":
                result = self._status()
            elif action == "stop":
                result = self._stop(False)
            elif action == "force-stop":
                result = self._stop(True)
            elif action == "ack-terminal":
                with self._lock:
                    if not self._terminal_reported.is_set():
                        result = {
                            "ok": False,
                            "running": True,
                            "error": "no terminal response has been reported",
                        }
                    else:
                        # The caller can send this only with the run token.  It
                        # is emitted after the client verified a signed terminal
                        # response, so a volatile recovery supervisor may now
                        # retire even if its final metadata write failed.
                        self._terminal_observed.set()
                        result = {
                            **self.metadata(),
                            "ok": True,
                            "terminalAcknowledged": True,
                        }
            else:
                result = {"ok": False, "error": "unknown action"}
            if (action != "ack-terminal"
                    and result.get("running") is False
                    and result.get("state") not in (
                        "starting", "startup-cleanup-failed")
                    and (result.get("ok") is True
                         or self._final_persisted.is_set())):
                # This is not yet an observation: it only records that the
                # supervisor issued a signed terminal response.  A separate
                # token-authenticated ACK proves a client verified it.
                self._terminal_reported.set()
            return _json_bytes(self._signed_response(result, nonce))
        except Exception as exc:
            return _json_bytes(self._signed_response({"ok": False, "error": str(exc)}, nonce))

    def _test_tcp_loop(self):
        while not self._closed.is_set():
            try:
                connection, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                try:
                    self._response_in_flight.set()
                    response = self._handle_bytes(_read_socket_request(connection))
                    connection.sendall(response)
                except Exception as exc:
                    try:
                        connection.sendall(_json_bytes({"ok": False, "error": str(exc)}))
                    except OSError:
                        pass
                finally:
                    self._response_in_flight.clear()

    def _pipe_loop(self):
        windows = _windows_runtime()
        while not self._closed.is_set():
            pipe = None
            try:
                pipe = windows.create_pipe(self._pipe_name)
                windows.accept_pipe(pipe)
                self._response_in_flight.set()
                response = self._handle_bytes(windows.read_pipe(pipe))
                windows.write_pipe(pipe, response)
            except Exception as exc:
                try:
                    self._append_supervisor_log(
                        "\n[supervisor control pipe error] %r\n" % (exc,)
                    )
                except Exception:
                    pass
                if self._closed.is_set():
                    break
            finally:
                self._response_in_flight.clear()
                if pipe is not None:
                    try:
                        windows.close_pipe(pipe)
                    except Exception:
                        pass

    def _start_control(self):
        if self._transport == "windows-named-pipe":
            target = self._pipe_loop
        else:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("127.0.0.1", 0))
            self._server.listen(8)
            self._server.settimeout(0.25)
            self._port = int(self._server.getsockname()[1])
            target = self._test_tcp_loop
        self._control_thread = threading.Thread(
            target=target, name="supervisor-control", daemon=True
        )
        self._control_thread.start()

    def _monitor_wsl_until_terminal(self, recovery):
        while (self._wsl_running or
               (recovery and not self._final_persisted.is_set())):
            time.sleep(2.0)
            result = self._wsl_control("status")
            if (result.get("distroStopped") or
                    result.get("distroRestarted") or
                    result.get("sessionLost") or
                    result.get("identityMismatch")):
                break
            # Transient command/pipe failures keep the authenticated
            # supervisor alive. A later console/status request can recover
            # without starting a stopped distribution.
            if result.get("ok") and not self._wsl_running:
                break
        if not self._final_persisted.is_set():
            with self._lock:
                if not self._final_persisted.is_set():
                    self._launch_state = None
                    self._terminal_metadata_durable = (
                        self._persist_control_state())
                    self._final_persisted.set()

    def _monitor_native_until_terminal(self):
        while True:
            process_ids = self._native_process_ids()
            if process_ids:
                time.sleep(0.1)
                continue
            if self.child is None:
                raise RuntimeError(
                    "committed native runtime has no root process handle")
            return_code = self.child.poll()
            if return_code is None:
                try:
                    # An empty Job may precede the Popen handle signal. Keep
                    # the control endpoint alive and harvest in short bounded
                    # waits; TimeoutExpired is an ordinary ``exiting`` race,
                    # never a reason to surrender the published identity.
                    return_code = self.child.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    continue
            if return_code is None:
                continue
            with self._lock:
                self.exit_code = int(return_code)
                self._launch_state = None
                self._record_exit()
            return

    def _retire_after_terminal(self):
        if self._volatile_recovery and not self._terminal_metadata_durable:
            # The last durable record may still say ``starting`` or
            # ``running``. Stay authenticated and controllable until a caller
            # that verified a signed terminal response sends a second
            # authenticated ACK. A successful server-side WriteFile/sendall
            # alone does not prove that a non-transactional client received
            # the response.
            while not self._terminal_observed.wait(0.25):
                pass
        # A force-stop request may be the event that made the child exit. Let
        # the control thread flush its authenticated response first.
        response_deadline = time.monotonic() + 2.0
        while (self._response_in_flight.is_set() and
               time.monotonic() < response_deadline):
            time.sleep(0.01)

    def serve(self):
        self._start_control()
        try:
            self._raise_if_startup_cancelled()
            if self.args.environment == "wsl":
                # The derived session token hash is part of the durable
                # starting identity and must exist before user code can run.
                self._wsl_token = _derived_wsl_token(
                    self.token, self.args.run_id)
            self._launch_state = "starting"
            self.persist()
            self._startup_published = True
            self._raise_if_startup_cancelled()
            recovery = False
            try:
                self.launch()
            except RuntimeCleanupUnconfirmed:
                # The durable starting metadata and live authenticated control
                # endpoint remain available.  Do not let main() overwrite that
                # recovery anchor with a terminal startup-failed record.
                recovery = True
            except Exception as exc:
                # ``launch()`` normally performs its own transactional
                # rollback after a process/session exists. Reconfirm that
                # invariant at the serve boundary as well so even an
                # unforeseen exception between Popen and first publication
                # cannot reach main() as an allegedly safe startup failure.
                try:
                    cleanup_ok, cleanup_error = (
                        self._abort_unpublished_launch())
                except Exception as cleanup_exc:
                    cleanup_ok = False
                    cleanup_error = (
                        "unpublished runtime cleanup raised: %s" %
                        cleanup_exc)
                if not cleanup_ok:
                    self._retain_unpublished_runtime(exc, cleanup_error)
                    recovery = True
                else:
                    # WSL cleanup temporarily enables volatile persistence so
                    # a cleanup status-write failure cannot block force-stop.
                    # Once cleanup itself is authenticated and terminal, this
                    # is again a proven ordinary startup failure.
                    self._volatile_recovery = False
                    raise
            else:
                self._runtime_committed = True

            # Everything below owns either a committed runtime or an
            # unpublished runtime whose cleanup could not be proven. Any
            # unexpected fault must therefore stay inside this retrying state
            # machine: closing the pipe would strand a Job/session and letting
            # main() write startup-failed would destroy its recovery anchor.
            while True:
                try:
                    if self.args.environment == "wsl":
                        self._monitor_wsl_until_terminal(recovery)
                    else:
                        self._monitor_native_until_terminal()
                    self._retire_after_terminal()
                    return int(self.exit_code or 0)
                except Exception as exc:
                    if not (self._runtime_committed or
                            self._volatile_recovery):
                        raise
                    recovery = True
                    self._enter_volatile_recovery(
                        "post-launch supervision failed", exc)
                    time.sleep(0.25)
        finally:
            self._closed.set()
            if self._server is not None:
                try:
                    self._server.close()
                except OSError:
                    pass


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--startup-cancel", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--token")
    parser.add_argument("--supervisor-version", default=SUPERVISOR_VERSION)
    parser.add_argument("--environment", choices=("native", "wsl"), default="native")
    parser.add_argument("--distro")
    parser.add_argument("--cwd")
    parser.add_argument("--stop-timeout", type=float, default=5.0)
    parser.add_argument("--wsl-helper-path")
    parser.add_argument("--wsl-socket")
    parser.add_argument("--wsl-metadata")
    parser.add_argument("--wsl-log")
    parser.add_argument("--wsl-boot-id")
    parser.add_argument("--wsl-kind", choices=("service", "task"), default="service")
    parser.add_argument("--preallocated-console", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--test-transport", choices=("tcp",), help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv=None):
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv == ["--runtime-check"]:
        try:
            _windows_runtime().validate_runtime()
            return 0
        except Exception as exc:
            try:
                print(str(exc), file=sys.stderr)
            except Exception:
                pass
            return 1
    args = build_parser().parse_args(raw_argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        raise SystemExit("supervisor requires a command after --")
    instance = None
    try:
        instance = Supervisor(args)
        return instance.serve()
    except Exception as exc:
        if (instance is not None and
                (instance._runtime_committed or
                 instance._volatile_recovery)):
            # ``serve()`` is expected to contain every post-publication fault
            # and retain its authenticated endpoint. This is a final fail-safe:
            # never destroy a committed/recovery identity by relabeling it as
            # a startup failure if an unforeseen exception still escapes.
            try:
                instance._append_supervisor_log(
                    "\n[supervisor fatal recovery escape; metadata retained] "
                    "%s\n" % exc)
            except Exception:
                pass
            return 1
        # Production launches redirect stderr; persist startup failure so the
        # tray console can report it without relying on a terminal. Reaching
        # this branch means no runtime identity was committed and cleanup did
        # not enter the unconfirmed/volatile recovery state.
        try:
            _atomic_json(args.metadata, {
                "schemaVersion": METADATA_SCHEMA_VERSION,
                "protocolVersion": PROTOCOL_VERSION,
                "supervisorVersion": args.supervisor_version,
                "runId": args.run_id,
                "environment": args.environment,
                "running": False,
                "state": "startup-failed",
                "error": str(exc),
                "updatedAt": time.time(),
            }, secure_windows=not bool(args.test_transport))
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
