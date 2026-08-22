"""Authenticated client and durable metadata helpers for ``supervisor.py``."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


METADATA_SCHEMA_VERSION = 2
PROTOCOL_VERSION = 2
SUPERVISOR_VERSION = "2.0.0"
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]{1,96}$")


def _windows_runtime():
    import supervisor_windows
    return supervisor_windows


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _expected_sha256(path):
    with open(path, "r", encoding="ascii") as stream:
        raw = stream.read(513)
    if len(raw) > 512:
        raise ValueError("supervisor SHA-256 attestation is too large")
    line = raw.strip()
    match = re.fullmatch(r"([0-9A-Fa-f]{64})(?:\s+\*?[^\r\n]+)?", line)
    if not match:
        raise ValueError("invalid supervisor SHA-256 attestation")
    return match.group(1).lower()


def _bundled_supervisor(base_dir, version):
    filename = "console-supervisor-%s.exe" % version
    roots = [
        os.path.join(base_dir, "_internal"),
        getattr(sys, "_MEIPASS", None),
        base_dir,
    ]
    for root in roots:
        if not root:
            continue
        candidate = os.path.join(root, "supervisors", filename)
        attestation = candidate + ".sha256"
        if os.path.isfile(candidate) and os.path.isfile(attestation):
            return candidate, attestation
    raise FileNotFoundError("bundled versioned supervisor is missing: %s" % version)


def _install_bundled_supervisor(base_dir, data_dir, version):
    """Verify the bundle then atomically install an immutable per-user copy."""
    if os.name != "nt":
        raise RuntimeError("bundled supervisor installation is Windows-only")
    windows = _windows_runtime()
    windows.validate_runtime()
    source, attestation = _bundled_supervisor(base_dir, version)
    expected = _expected_sha256(attestation)
    if not hmac.compare_digest(_file_sha256(source), expected):
        raise ValueError("bundled supervisor SHA-256 mismatch")
    target_dir = os.path.join(os.path.abspath(data_dir), "supervisors")
    os.makedirs(target_dir, exist_ok=True)
    windows.secure_path(target_dir, directory=True)
    filename = "console-supervisor-%s.exe" % version
    target = os.path.join(target_dir, filename)
    target_attestation = target + ".sha256"
    if os.path.isfile(target) and hmac.compare_digest(_file_sha256(target), expected):
        windows.secure_path(target, directory=False)
        return target
    fd, temporary = tempfile.mkstemp(prefix="supervisor-", suffix=".tmp", dir=target_dir)
    try:
        with os.fdopen(fd, "wb") as output, open(source, "rb") as source_stream:
            shutil.copyfileobj(source_stream, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        if not hmac.compare_digest(_file_sha256(temporary), expected):
            raise ValueError("copied supervisor SHA-256 mismatch")
        os.replace(temporary, target)
        windows.secure_path(target, directory=False)
        sha_fd, sha_temporary = tempfile.mkstemp(
            prefix="supervisor-sha-", suffix=".tmp", dir=target_dir
        )
        try:
            with os.fdopen(sha_fd, "w", encoding="ascii", newline="\n") as stream:
                stream.write("%s  %s\n" % (expected, filename))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(sha_temporary, target_attestation)
            windows.secure_path(target_attestation, directory=False)
        finally:
            try:
                os.remove(sha_temporary)
            except OSError:
                pass
    finally:
        try:
            os.remove(temporary)
        except OSError:
            pass
    return target


def supervisor_executable(base_dir, version=None, data_dir=None):
    """Return argv prefix for the immutable, versioned supervisor executable."""
    version = version or SUPERVISOR_VERSION
    base_dir = os.path.abspath(base_dir)
    if getattr(sys, "frozen", False):
        if not data_dir:
            raise ValueError("data_dir is required for a frozen supervisor")
        return [_install_bundled_supervisor(base_dir, data_dir, version)]
    source = os.path.join(base_dir, "supervisor.py")
    if not os.path.isfile(source):
        raise FileNotFoundError(source)
    return [sys.executable, source]


def runtime_dir(data_dir):
    return os.path.join(data_dir, "runtime")


def metadata_path(data_dir, run_id):
    if not _SAFE_RUN_ID.fullmatch(str(run_id)):
        raise ValueError("invalid run id")
    return os.path.join(runtime_dir(data_dir), "%s.json" % run_id)


def load_metadata(path):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def cleanup_unused_supervisors(data_dir, keep_versions=()):
    """Remove only persisted supervisor versions not referenced by live metadata."""
    supervisor_dir = os.path.join(os.path.abspath(data_dir), "supervisors")
    if not os.path.isdir(supervisor_dir):
        return []
    referenced = {str(value) for value in keep_versions}
    runs = runtime_dir(data_dir)
    try:
        entries = os.listdir(runs)
    except OSError:
        entries = []
    for entry in entries:
        if not entry.endswith(".json"):
            continue
        value = load_metadata(os.path.join(runs, entry))
        if not value or not value.get("supervisorVersion"):
            continue
        # ``starting`` is a durable rollback anchor and
        # ``startup-cleanup-failed`` deliberately keeps the authenticated
        # supervisor alive when runtime cleanup could not be proven.  Neither
        # state may report ``running: true`` yet both still reference the exact
        # executable that owns the recovery pipe/token.
        if (value.get("running") or value.get("state") in
                ("starting", "startup-cleanup-failed")):
            referenced.add(str(value["supervisorVersion"]))
    removed = []
    for entry in os.listdir(supervisor_dir):
        match = re.fullmatch(r"console-supervisor-([0-9A-Za-z][0-9A-Za-z.+-]{0,63})\.exe", entry)
        if not match or match.group(1) in referenced:
            continue
        path = os.path.join(supervisor_dir, entry)
        try:
            os.remove(path)
            removed.append(path)
            try:
                os.remove(path + ".sha256")
            except OSError:
                pass
        except OSError:
            # A running old one-file executable may still be locked. Keep it.
            continue
    return removed


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _sign(token, action, nonce, issued_at, run_id):
    payload = ("%s\n%s\n%s\n%s\n%s" % (
        PROTOCOL_VERSION, run_id, action, nonce, issued_at
    )).encode("utf-8")
    return hmac.new(token.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _sign_response(token, request_nonce, value):
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    payload = ("response\n%s\n%s" % (request_nonce, canonical)).encode("utf-8")
    return hmac.new(token.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _failure(error, **fields):
    return {"ok": False, "error": str(error), **fields}


def _metadata_identity(metadata, token, allow_test_transport=False):
    if not isinstance(metadata, dict):
        return _failure("invalid supervisor metadata", stale=True)
    if metadata.get("schemaVersion") != METADATA_SCHEMA_VERSION:
        return _failure("unsupported supervisor metadata version", stale=True)
    if metadata.get("protocolVersion") != PROTOCOL_VERSION:
        return _failure("unsupported supervisor protocol", stale=True)
    run_id = metadata.get("runId")
    if not isinstance(run_id, str) or not _SAFE_RUN_ID.fullmatch(run_id):
        return _failure("invalid supervisor run identity", stale=True)
    if not isinstance(token, str) or len(token) < 32:
        return _failure("invalid supervisor token", unauthorized=True)
    expected_hash = metadata.get("tokenHash")
    if not isinstance(expected_hash, str) or not hmac.compare_digest(expected_hash, _token_hash(token)):
        return _failure("supervisor token mismatch", unauthorized=True)
    transport = metadata.get("transport")
    if transport == "test-tcp":
        if not allow_test_transport:
            return _failure("test-only supervisor transport refused", insecureTransport=True)
        if metadata.get("controlHost") != "127.0.0.1" or not isinstance(metadata.get("controlPort"), int):
            return _failure("invalid test supervisor endpoint", stale=True)
        return {"ok": True}
    if transport != "windows-named-pipe":
        return _failure("invalid supervisor transport", stale=True)
    if os.name != "nt":
        return _failure("Windows named pipe unavailable on this platform")
    try:
        windows = _windows_runtime()
        windows.validate_runtime()
        current_sid = windows.current_user_sid()
        if metadata.get("ownerSid") != current_sid:
            return _failure("supervisor belongs to another user", identityMismatch=True)
        expected = {
            "pid": metadata.get("supervisorPid"),
            "createTime": metadata.get("supervisorCreateTime"),
            "ownerSid": metadata.get("ownerSid"),
        }
        actual = windows.process_identity(metadata.get("supervisorPid"))
        if not windows.identity_matches(expected, actual):
            return _failure("supervisor process identity changed", identityMismatch=True, stale=True)
    except Exception as exc:
        return _failure("cannot verify supervisor identity: %s" % exc, stale=True)
    pipe_name = metadata.get("pipeName")
    if not isinstance(pipe_name, str) or not pipe_name.startswith(r"\\.\pipe\LocalOps.Supervisor."):
        return _failure("invalid supervisor pipe name", stale=True)
    return {"ok": True}


def _socket_request(metadata, raw, timeout):
    with socket.create_connection(
        (metadata["controlHost"], metadata["controlPort"]), timeout=timeout
    ) as sock:
        sock.settimeout(timeout)
        sock.sendall(raw)
        chunks = []
        total = 0
        while total < 64 * 1024:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\n" in chunk:
                break
    if total >= 64 * 1024:
        raise ValueError("supervisor response too large")
    return b"".join(chunks).split(b"\n", 1)[0]


def _call_supervisor_once(metadata, token, action, timeout=6.0,
                          allow_test_transport=False):
    """Authenticate, verify immutable process identity, then perform an action."""
    if action not in ("status", "stop", "force-stop", "ack-terminal"):
        return _failure("invalid supervisor action")
    verified = _metadata_identity(metadata, token, allow_test_transport)
    if not verified.get("ok"):
        return verified
    nonce = secrets.token_urlsafe(24)
    issued_at = int(time.time() * 1000) / 1000.0
    run_id = metadata["runId"]
    request = {
        "protocolVersion": PROTOCOL_VERSION,
        "runId": run_id,
        "action": action,
        "nonce": nonce,
        "issuedAt": issued_at,
        "signature": _sign(token, action, nonce, issued_at, run_id),
    }
    raw = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        if metadata["transport"] == "windows-named-pipe":
            response_raw = _windows_runtime().pipe_request(
                metadata["pipeName"], raw, timeout=timeout
            )
        else:
            response_raw = _socket_request(metadata, raw, timeout)
        response = json.loads(response_raw.decode("utf-8"))
        if not isinstance(response, dict):
            raise ValueError("response is not an object")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TimeoutError) as exc:
        return _failure(exc, stale=True)
    signature = response.pop("responseSignature", None)
    if response.get("requestNonce") != nonce or not isinstance(signature, str):
        return _failure("unauthenticated supervisor response", unauthorized=True)
    expected_signature = _sign_response(token, nonce, response)
    if not hmac.compare_digest(signature, expected_signature):
        return _failure("supervisor response signature mismatch", unauthorized=True)
    if response.get("protocolVersion") != PROTOCOL_VERSION:
        return _failure("supervisor response protocol mismatch", stale=True)
    # The authenticated live response must still describe the immutable process
    # that was verified before connecting; this catches stale/replaced metadata.
    for key in ("runId", "supervisorPid", "supervisorCreateTime", "ownerSid"):
        if key in response and response.get(key) != metadata.get(key):
            return _failure("supervisor response identity mismatch", identityMismatch=True)
    return response


def call_supervisor(metadata, token, action, timeout=6.0,
                    allow_test_transport=False):
    """Perform a public action and ACK a verified terminal response.

    The second authenticated request is intentionally best-effort.  Once this
    client has verified the first signed terminal response it no longer needs
    the supervisor, while a recovery supervisor needs the ACK to know it can
    retire when final metadata could not be written.
    """
    if action not in ("status", "stop", "force-stop"):
        return _failure("invalid supervisor action")
    response = _call_supervisor_once(
        metadata, token, action, timeout=timeout,
        allow_test_transport=allow_test_transport)
    if (response.get("running") is False
            and response.get("state") not in (
                "starting", "startup-cleanup-failed")):
        try:
            ack_timeout = min(1.0, max(0.05, float(timeout)))
        except (TypeError, ValueError):
            ack_timeout = 1.0
        _call_supervisor_once(
            metadata, token, "ack-terminal", timeout=ack_timeout,
            allow_test_transport=allow_test_transport)
    return response


def wait_for_metadata(path, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = load_metadata(path)
        if value:
            if value.get("state") == "startup-failed":
                return value
            endpoint_ready = (
                value.get("transport") == "windows-named-pipe"
                and value.get("pipeName")
            ) or (
                value.get("transport") == "test-tcp"
                and isinstance(value.get("controlPort"), int)
            )
            # ``starting`` is deliberately durable before any user runtime is
            # created. It is an authenticated rollback/recovery anchor, not a
            # successful launch result.
            if endpoint_ready and value.get("state") not in (
                    "starting", "startup-cleanup-failed"):
                return value
        time.sleep(0.025)
    return None


def startup_cancel_path(path):
    return os.path.abspath(os.fspath(path)) + ".startup-cancel"


def _write_startup_cancel(path, token, allow_test_transport=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (_token_hash(token) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "nt" and not allow_test_transport:
        _windows_runtime().secure_path(path, directory=False)
    elif os.name != "nt":
        os.chmod(path, 0o600)


def _terminate_exact_launcher(process, timeout=5.0):
    if process.poll() is not None:
        return True
    try:
        process.terminate()
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)
    except OSError:
        pass
    return process.poll() is not None


def _job_missing(exc):
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None):
        code = exc.args[0]
    return code == 2  # ERROR_FILE_NOT_FOUND


def _terminate_exact_startup_job(run_id, token, process):
    """Stop the exact launcher and token-derived Job without PID guessing."""
    windows = _windows_runtime()
    job_name = windows.names(run_id, _token_hash(token))[1]
    job = None
    job_opened = False
    errors = []
    try:
        try:
            # Hold a Job handle across launcher termination.  If the child was
            # already assigned, this closes the create/open/kill race.
            job = windows.open_job(job_name)
            job_opened = True
        except Exception as exc:
            if not _job_missing(exc):
                errors.append(str(exc))
        if not _terminate_exact_launcher(process):
            errors.append("supervisor launcher did not exit")
        if job is None:
            try:
                job = windows.open_job(job_name)
                job_opened = True
            except Exception as exc:
                if not _job_missing(exc):
                    errors.append(str(exc))
        if job is not None:
            windows.terminate_job(job, 130)
            deadline = time.monotonic() + 5.0
            while windows.job_process_ids(job) and time.monotonic() < deadline:
                time.sleep(0.025)
            if windows.job_process_ids(job):
                errors.append("managed Job still contains processes")
    finally:
        if job is not None:
            try:
                job.Close()
            except Exception:
                pass
    return {
        "ok": not errors,
        "errors": errors,
        "jobName": job_name,
        "jobOpened": job_opened,
    }


def _cancel_timed_out_start(
        process, path, run_id, token, environment, allow_test_transport=False):
    """Cancel a timed-out start and prove its launcher/session was reclaimed."""
    cancel_path = startup_cancel_path(path)
    try:
        _write_startup_cancel(cancel_path, token, allow_test_transport)
    except FileExistsError:
        return {"ok": False, "error": "startup cancel marker already exists"}
    cleanup = None
    marker_can_be_removed = False
    recoverable_metadata = None
    recoverable_error = None
    deadline = time.monotonic() + (25.0 if environment == "wsl" else 10.0)
    try:
        while time.monotonic() < deadline:
            metadata = load_metadata(path)
            if metadata:
                if metadata.get("state") == "startup-failed":
                    break
                transport_ready = (
                    metadata.get("transport") == "windows-named-pipe"
                    and metadata.get("pipeName")
                ) or (
                    allow_test_transport
                    and metadata.get("transport") == "test-tcp"
                    and isinstance(metadata.get("controlPort"), int)
                )
                if transport_ready:
                    verified = _metadata_identity(
                        metadata, token,
                        allow_test_transport=allow_test_transport)
                    if not verified.get("ok"):
                        if process.poll() is not None:
                            break
                        time.sleep(0.05)
                        continue
                    stopped = stop_supervisor(
                        metadata, token, force=True, timeout=5.0,
                        allow_test_transport=allow_test_transport,
                    )
                    if stopped.get("ok") and not stopped.get("running"):
                        cleanup = {"ok": True, "method": "authenticated-force"}
                        marker_can_be_removed = True
                        break
                    # The metadata identity and response were authenticated.
                    # Do not terminate this recovery anchor merely because a
                    # force-stop could not yet prove the user runtime exited.
                    recoverable_error = str(
                        stopped.get("error") or
                        "authenticated force-stop did not prove cleanup")
                    status = status_supervisor(
                        metadata, token, timeout=3.0,
                        allow_test_transport=allow_test_transport,
                    )
                    recoverable_metadata = (
                        status if status.get("ok") else metadata)
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if recoverable_metadata is not None and cleanup is None:
            return {
                "ok": False,
                "method": "authenticated-recovery",
                "error": recoverable_error,
                "recoverable": True,
                "metadata": recoverable_metadata,
            }
        if (os.name == "nt" and not allow_test_transport
                and environment == "native"):
            exact = _terminate_exact_startup_job(run_id, token, process)
            cleanup = cleanup or {**exact, "method": "exact-job-rollback"}
            marker_can_be_removed = bool(exact.get("ok") and exact.get("jobOpened"))
        else:
            launcher_stopped = _terminate_exact_launcher(process)
            if cleanup is None:
                cleanup = {
                    "ok": launcher_stopped,
                    "method": "cancel-marker",
                    "error": None if launcher_stopped else "supervisor launcher did not exit",
                }
        return cleanup
    finally:
        # A PyInstaller onefile launcher can have a later child process that
        # has not yet created the token-derived Job.  Launcher exit + a missing
        # Job is therefore not proof of cleanup.  Retain this tiny, random-run
        # marker so any late supervisor child fails before spawning user code.
        if marker_can_be_removed and process.poll() is not None:
            try:
                os.remove(cancel_path)
            except FileNotFoundError:
                pass


def _secure_runtime_directory(path, allow_test_transport=False):
    os.makedirs(path, exist_ok=True)
    if os.name == "nt" and not allow_test_transport:
        windows = _windows_runtime()
        windows.validate_runtime()
        windows.secure_path(path, directory=True)
    elif os.name != "nt":
        os.chmod(path, 0o700)


def launch_supervisor(
    base_dir,
    data_dir,
    log_path,
    run_id,
    token,
    command,
    *,
    cwd=None,
    environment="native",
    distro=None,
    stop_timeout=5.0,
    supervisor_version=None,
    helper_path=None,
    wsl_socket=None,
    wsl_metadata=None,
    wsl_log_path=None,
    wsl_boot_id=None,
    wsl_kind="service",
    launch_env=None,
    startup_timeout=15.0,
    allow_test_transport=False,
):
    """Spawn a detached supervisor and wait for its authenticated metadata."""
    try:
        if not _SAFE_RUN_ID.fullmatch(str(run_id)):
            raise ValueError("invalid run id")
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("supervisor token must contain at least 32 characters")
        if environment not in ("native", "wsl"):
            raise ValueError("invalid execution environment")
        if isinstance(command, str):
            command = [command]
        elif isinstance(command, (list, tuple)):
            command = [str(part) for part in command]
        else:
            raise TypeError("command must be a string or argv sequence")
        if not command or any("\x00" in part for part in command):
            raise ValueError("invalid command")
        startup_timeout = float(startup_timeout)
        if not 1.0 <= startup_timeout <= 60.0:
            raise ValueError("startup timeout must be between 1 and 60 seconds")
        if environment == "wsl":
            required = {
                "distro": distro, "helper_path": helper_path,
                "wsl_socket": wsl_socket, "wsl_metadata": wsl_metadata,
                "wsl_log_path": wsl_log_path, "wsl_boot_id": wsl_boot_id,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError("WSL launch missing: " + ", ".join(missing))
        version = supervisor_version or SUPERVISOR_VERSION
        path = metadata_path(data_dir, run_id)
        cancel_path = startup_cancel_path(path)
        _secure_runtime_directory(runtime_dir(data_dir), allow_test_transport)
        if os.path.lexists(cancel_path):
            raise FileExistsError("stale supervisor startup cancel marker exists")
        if os.path.exists(path):
            existing = load_metadata(path)
            if existing and existing.get("running"):
                return _failure("run identity already exists", conflict=True, metadata=existing)
            raise FileExistsError("stale runtime metadata already exists")
        argv = supervisor_executable(base_dir, version, data_dir=data_dir) + [
            "--metadata", path,
            "--startup-cancel", cancel_path,
            "--log", os.path.abspath(log_path),
            "--run-id", str(run_id),
            "--supervisor-version", str(version),
            "--environment", environment,
            "--stop-timeout", str(float(stop_timeout)),
        ]
        if distro:
            argv += ["--distro", str(distro)]
        if cwd:
            argv += ["--cwd", str(cwd)]
        if environment == "wsl":
            argv += [
                "--wsl-helper-path", str(helper_path),
                "--wsl-socket", str(wsl_socket),
                "--wsl-metadata", str(wsl_metadata),
                "--wsl-log", str(wsl_log_path),
                "--wsl-boot-id", str(wsl_boot_id),
                "--wsl-kind", str(wsl_kind),
            ]
        if allow_test_transport:
            argv += ["--test-transport", "tcp"]
        if os.name == "nt" and not allow_test_transport:
            # CREATE_NEW_CONSOLE association can complete just after the new
            # process begins executing.  This internal hint only permits a
            # bounded wait; the supervisor still proves console membership.
            argv += ["--preallocated-console"]
        argv += ["--", *command]
        if launch_env is None:
            env = dict(os.environ)
        elif hasattr(launch_env, "items"):
            env = {str(name): str(value)
                   for name, value in launch_env.items()}
        else:
            raise TypeError("launch_env must be a mapping")
        env["CONSOLE_SUPERVISOR_TOKEN"] = token
        if allow_test_transport:
            env["CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT"] = "1"
        popen_options = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
            "env": env,
        }
        if os.name == "nt":
            windows = _windows_runtime()
            if not allow_test_transport:
                windows.validate_runtime()
            # Allocate the supervisor's private console as part of
            # CreateProcess.  Rapid FreeConsole/AllocConsole cycles are not
            # reliable on all supported Windows builds, while a managed child
            # still gets its own CREATE_NEW_PROCESS_GROUP inside this console.
            popen_options["creationflags"] = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            )
            popen_options["startupinfo"] = windows.subprocess_startupinfo()
        else:
            popen_options["start_new_session"] = True
        process = subprocess.Popen(argv, **popen_options)
        # Retain/reap the detached handle without tying its lifetime to the
        # console process. A daemon waiter prevents Popen ResourceWarning and
        # closes the Windows process handle once the supervisor exits.
        threading.Thread(target=process.wait, name="supervisor-reaper", daemon=True).start()
        metadata = wait_for_metadata(path, timeout=startup_timeout)
        if not metadata:
            try:
                cleanup = _cancel_timed_out_start(
                    process, path, str(run_id), token, environment,
                    allow_test_transport=allow_test_transport,
                )
            except Exception as exc:
                starting = load_metadata(path)
                verified = _metadata_identity(
                    starting, token,
                    allow_test_transport=allow_test_transport)
                authenticated_starting = (
                    starting if verified.get("ok") else None)
                cleanup = {
                    "ok": False,
                    "method": "cleanup-error",
                    "error": str(exc),
                    "recoverable": authenticated_starting is not None,
                    "metadata": authenticated_starting,
                }
            recoverable = bool(
                not cleanup.get("ok")
                and cleanup.get("recoverable")
                and isinstance(cleanup.get("metadata"), dict)
            )
            recoverable_metadata = None
            if recoverable:
                recoverable_metadata = dict(cleanup["metadata"])
                recoverable_metadata["recoveryPending"] = True
                cleanup["metadata"] = recoverable_metadata
            return _failure(
                "supervisor startup timed out", supervisorPid=process.pid,
                startupTimedOut=True, cleanup=cleanup,
                recoverable=recoverable,
                metadata=recoverable_metadata,
            )
        if metadata.get("state") == "startup-failed":
            return _failure(metadata.get("error", "supervisor startup failed"),
                            supervisorPid=process.pid, metadata=metadata)
        if getattr(sys, "frozen", False):
            cleanup_unused_supervisors(data_dir, keep_versions=(version,))
        return {
            "ok": True,
            "supervisorPid": int(metadata.get("supervisorPid") or process.pid),
            "launcherPid": process.pid,
            "metadata": metadata,
        }
    except Exception as exc:
        return _failure(exc)


def _metadata_value(metadata_or_path):
    if isinstance(metadata_or_path, (str, os.PathLike)):
        return load_metadata(os.fspath(metadata_or_path))
    return metadata_or_path


def status_supervisor(metadata_or_path, token, timeout=6.0, allow_test_transport=False):
    metadata = _metadata_value(metadata_or_path)
    return call_supervisor(metadata, token, "status", timeout, allow_test_transport)


def stop_supervisor(metadata_or_path, token, force=False, timeout=7.0,
                    allow_test_transport=False):
    metadata = _metadata_value(metadata_or_path)
    return call_supervisor(
        metadata, token, "force-stop" if force else "stop",
        timeout, allow_test_transport,
    )


def reclaim_supervisor(path, token, expected=None, timeout=6.0,
                       allow_test_transport=False):
    """Safely reconnect after console restart without trusting a PID alone."""
    metadata = load_metadata(path)
    if not metadata:
        return _failure("runtime metadata is missing or unreadable", stale=True)
    if expected:
        for key in ("runId", "environment", "distro"):
            if key in expected and metadata.get(key) != expected.get(key):
                return _failure("runtime metadata does not match application",
                                identityMismatch=True)
        expected_boot = expected.get("bootId")
        if expected_boot and (metadata.get("wsl") or {}).get("bootId") != expected_boot:
            return _failure("WSL boot identity changed", identityMismatch=True)
    return call_supervisor(metadata, token, "status", timeout, allow_test_transport)
