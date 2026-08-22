"""Windows native adapter with lazily loaded optional process support."""

from __future__ import annotations

import csv
import functools
import getpass
import importlib
import io
import ntpath
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Iterable, Mapping, Optional

from .base import AdapterUnavailable, BasePlatformAdapter, RuntimeDirs, UserIdentity
from .common import call_runner, command_stdout, first_command_token, normalize_pids, resolve_runtime_dir, windows_quote


_UNSET = object()
_SID_RE = re.compile(r"S-\d-(?:\d+-)+\d+", re.IGNORECASE)


@functools.lru_cache(maxsize=1)
def _current_process_sid() -> str:
    """Read the current token SID once without spawning a console process."""
    from .windows_security import current_user_sid
    return current_user_sid()


def _clean_wsl_line(value: str) -> str:
    return value.replace("\ufeff", "").replace("\x00", "").strip()


def discover_wsl_distros(runner=None, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Return installed WSL distributions without starting any distribution.

    The running set is queried separately so parsing does not depend on the
    localized spelling of the STATE column in ``wsl --list --verbose``.  The
    timeout is one shared budget for both commands, not a per-command timeout.
    """
    deadline = time.monotonic() + max(0.0, float(timeout))

    def run_with_deadline(args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AdapterUnavailable("WSL 发行版枚举超时")
        return call_runner(runner, args, timeout=remaining)

    verbose = run_with_deadline(["wsl.exe", "--list", "--verbose"])
    if verbose.returncode != 0:
        raise AdapterUnavailable(
            "WSL 发行版枚举失败: %s" %
            (verbose.stderr.strip() or verbose.stdout.strip()
             or "wsl.exe exit %s" % verbose.returncode))
    running_output = run_with_deadline(
        ["wsl.exe", "--list", "--running", "--quiet"])
    if running_output.returncode != 0:
        raise AdapterUnavailable(
            "WSL 运行状态枚举失败: %s" %
            (running_output.stderr.strip() or running_output.stdout.strip()
             or "wsl.exe exit %s" % running_output.returncode))
    running = {
        _clean_wsl_line(line).casefold()
        for line in running_output.stdout.splitlines()
        if _clean_wsl_line(line)
    }

    result: list[dict[str, Any]] = []
    for raw_line in verbose.stdout.splitlines():
        line = _clean_wsl_line(raw_line)
        if not line:
            continue
        default = line.startswith("*")
        body = line[1:].strip() if default else line
        fields = body.rsplit(None, 2)
        if len(fields) != 3 or fields[2] not in ("1", "2"):
            continue  # localized header or a diagnostic line
        name, _localized_state, version_text = fields
        name = name.strip()
        if not name:
            continue
        version = int(version_text)
        is_running = name.casefold() in running
        item = {
            "name": name,
            "version": version,
            "state": "running" if is_running else "stopped",
            "running": is_running,
            "default": default,
            "available": version == 2,
        }
        if version != 2:
            item["reason"] = "WSL1 不受支持；请运行 wsl --set-version %s 2" % name
        result.append(item)
    return result


class WindowsAdapter(BasePlatformAdapter):
    system = "windows"
    environment = "native"
    shells = ("auto", "cmd", "powershell")
    path_style = "windows"

    def __init__(
        self,
        runner=None,
        command_runner=None,
        psutil_module: Any = _UNSET,
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        if runner is not None and command_runner is not None:
            raise TypeError("runner 与 command_runner 不能同时指定")
        runner = command_runner if command_runner is not None else runner
        super().__init__(runner=runner)
        self._psutil_module = psutil_module
        self._environ = dict(os.environ if environ is None else environ)
        self._identity: Optional[UserIdentity] = None

    @property
    def current_uid(self) -> int:
        # Compatibility only: process_snapshot uses 0 for the current account
        # and -1 for foreign/unknown.  SID + creation time are the secure key.
        return 0

    def _psutil(self):
        if self._psutil_module is _UNSET:
            try:
                self._psutil_module = importlib.import_module("psutil")
            except (ImportError, OSError) as exc:
                self._psutil_module = None
                raise AdapterUnavailable(
                    "Windows 进程监控需要可选依赖 psutil") from exc
        if self._psutil_module is None:
            raise AdapterUnavailable("Windows 进程监控需要可选依赖 psutil")
        return self._psutil_module

    def _current_username(self) -> str:
        user = (self._environ.get("USERNAME") or getpass.getuser() or "").strip()
        domain = (self._environ.get("USERDOMAIN") or "").strip()
        if domain and "\\" not in user and "@" not in user:
            return "%s\\%s" % (domain, user)
        return user

    @staticmethod
    def _username_key(value: Any) -> str:
        return str(value or "").strip().replace("/", "\\").casefold()

    def _is_current_username(self, username: Any) -> bool:
        actual = self._username_key(username)
        current = self._username_key(self._current_username())
        if not actual or not current:
            return False
        if actual == current:
            return True
        # psutil may return either DOMAIN\name or just name depending on the
        # Windows account provider.  This compatibility bit is not used for
        # destructive authorization; exact SID checks belong to that path.
        return actual.rsplit("\\", 1)[-1] == current.rsplit("\\", 1)[-1]

    @staticmethod
    def _sid_for_username(username: str) -> Optional[str]:
        try:
            from .windows_security import sid_for_username
            return sid_for_username(username)
        except Exception:
            return None

    def current_user_identity(self) -> UserIdentity:
        if self._identity is not None:
            return self._identity
        username = self._current_username()
        if self.runner is None and os.name == "nt":
            # Production Windows state polling must never spawn whoami.exe.
            # The process token is both more authoritative and available
            # in-process; the module-level cache serves the many short-lived
            # adapter instances created by the platform-neutral server layer.
            sid = _current_process_sid()
            self._identity = UserIdentity("sid", sid, username)
            return self._identity

        if self.runner is None:
            # Host-independent adapter tests also exercise this module on
            # macOS/Linux, where the Windows Token API does not exist.  Keep
            # that read-only surface process-free and deliberately return a
            # non-authoritative identity: destructive Windows paths require
            # ``kind == "sid"`` and therefore fail closed.
            self._identity = UserIdentity("username", username, username)
            return self._identity

        # Explicit injected runners keep the textual whoami surface used by
        # host-independent unit tests and integrations. Production never
        # reaches this fallback.
        output = command_stdout(
            self.runner,
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        )
        sid = None
        try:
            row = next(csv.reader(io.StringIO(output)))
            sid = next((item.strip() for item in row if _SID_RE.fullmatch(item.strip())), None)
            if row and row[0].strip():
                username = row[0].strip()
        except (StopIteration, csv.Error):
            pass
        if sid is None:
            match = _SID_RE.search(output)
            sid = match.group(0) if match else None
        self._identity = UserIdentity(
            "sid" if sid else "username", sid or username, username)
        return self._identity

    def runtime_dirs(
        self,
        app_name: str = "总控台",
        environ: Optional[Mapping[str, str]] = None,
        home: Optional[str] = None,
    ) -> RuntimeDirs:
        env = dict(self._environ if environ is None else environ)
        home_dir = ntpath.normpath(
            home or env.get("USERPROFILE") or ntpath.expanduser("~"))
        local_app_data = env.get("LOCALAPPDATA") or ntpath.join(home_dir, "AppData", "Local")
        data_default = ntpath.join(local_app_data, app_name)
        log_default = ntpath.join(data_default, "logs")
        data_drive, _ = ntpath.splitdrive(data_default)
        roots = [home_dir]
        if data_drive:
            roots.append(data_drive + "\\")
        data_dir, data_overridden = resolve_runtime_dir(
            "CONSOLE_DATA_DIR", data_default, env, ntpath, roots)
        log_dir, log_overridden = resolve_runtime_dir(
            "CONSOLE_LOG_DIR", log_default, env, ntpath, roots)
        return RuntimeDirs(data_dir, log_dir, data_overridden, log_overridden)

    def platform_info(
        self,
        packaged=None,
        *,
        wsl_distros: Any = _UNSET,
        wsl_discovery_error: Any = _UNSET,
        wsl_discovery_pending: Any = _UNSET,
        wsl_discovery_ready: Any = _UNSET,
        wsl_discovery_stale: Any = _UNSET,
    ) -> dict[str, Any]:
        precomputed = (
            wsl_distros is not _UNSET
            or wsl_discovery_error is not _UNSET
            or wsl_discovery_pending is not _UNSET
            or wsl_discovery_ready is not _UNSET
            or wsl_discovery_stale is not _UNSET
        )
        if precomputed:
            if packaged is None:
                packaged = bool(getattr(sys, "frozen", False))
            info = {
                "os": self.system,
                "system": self.system,
                "environment": self.environment,
                "arch": platform.machine().lower() or "unknown",
                "architecture": platform.machine() or "unknown",
                "shells": list(self.shells),
                "pathStyle": self.path_style,
                "packaged": bool(packaged),
                "wslDistros": [
                    dict(item) for item in (
                        [] if wsl_distros is _UNSET else (wsl_distros or [])
                    )
                ],
            }
            discovery_error = (
                None if wsl_discovery_error is _UNSET
                else wsl_discovery_error
            )
            discovery_pending = (
                False if wsl_discovery_pending is _UNSET
                else bool(wsl_discovery_pending)
            )
            discovery_ready = (
                True if wsl_discovery_ready is _UNSET
                else bool(wsl_discovery_ready)
            )
            discovery_stale = (
                False if wsl_discovery_stale is _UNSET
                else bool(wsl_discovery_stale)
            )
        else:
            info = super().platform_info(packaged=packaged)
            discovery_error = getattr(self, "_wsl_discovery_error", None)
            discovery_pending = False
            discovery_ready = True
            discovery_stale = False
        info["version"] = platform.version()
        info["release"] = platform.release()
        info["wslAvailable"] = bool(shutil.which("wsl.exe"))
        info["wslOperational"] = bool(
            info["wslAvailable"]
            and discovery_ready
            and not discovery_error
        )
        info["wslDiscoveryPending"] = discovery_pending
        info["wslDiscoveryStale"] = discovery_stale
        if discovery_error:
            info["wslDiscoveryError"] = str(discovery_error)
        try:
            self._psutil()
            info["processMonitoring"] = True
        except AdapterUnavailable as exc:
            info["processMonitoring"] = False
            info["processMonitoringError"] = str(exc)
        return info

    def discover_wsl_distros(self) -> list[dict[str, Any]]:
        if self.runner is None and not shutil.which("wsl.exe"):
            self._wsl_discovery_error = None
            return []
        try:
            result = discover_wsl_distros(self.runner)
            self._wsl_discovery_error = None
            return result
        except AdapterUnavailable as exc:
            # /api/platform remains available even if the WSL service is
            # missing, denied, or unhealthy; expose the distinction instead
            # of pretending that a failed query means no distributions.
            self._wsl_discovery_error = str(exc)
            return []

    def scan_listeners(self) -> dict[tuple[int, int], set[str]]:
        psutil = self._psutil()
        try:
            connections = psutil.net_connections(kind="tcp")
        except Exception as exc:
            raise AdapterUnavailable("无法读取 Windows TCP 监听快照: %s" % exc) from exc
        found: dict[tuple[int, int], set[str]] = {}
        listen_state = getattr(psutil, "CONN_LISTEN", "LISTEN")
        for connection in connections:
            if getattr(connection, "status", None) not in (listen_state, "LISTEN"):
                continue
            pid = getattr(connection, "pid", None)
            address = getattr(connection, "laddr", None)
            if pid is None or not address:
                continue
            try:
                host = address.ip
                port = int(address.port)
            except AttributeError:
                try:
                    host, port = address[0], int(address[1])
                except (IndexError, TypeError, ValueError):
                    continue
            found.setdefault((int(pid), port), set()).add(str(host or ""))
        return found

    @staticmethod
    def _process_value(process: Any, info: dict[str, Any], name: str, default=None):
        if name in info and info[name] is not None:
            return info[name]
        value = getattr(process, name, None)
        if callable(value):
            try:
                return value()
            except Exception:
                return default
        return value if value is not None else default

    def process_snapshot(
        self,
        pids: Optional[Iterable[int]] = None,
        with_identity: bool = True,
    ) -> dict[int, dict[str, Any]]:
        psutil = self._psutil()
        selected = normalize_pids(pids)
        if selected == []:
            return {}
        attrs = ["pid", "ppid", "name", "exe", "cmdline", "username",
                 "cpu_percent", "memory_percent", "create_time"]
        if selected is None:
            try:
                processes = list(psutil.process_iter(attrs=attrs))
            except Exception as exc:
                raise AdapterUnavailable("无法枚举 Windows 进程: %s" % exc) from exc
        else:
            processes = []
            for pid in selected:
                try:
                    processes.append(psutil.Process(pid))
                except Exception:
                    continue
        now = time.time()
        current_identity = self.current_user_identity() if with_identity else None
        snapshot: dict[int, dict[str, Any]] = {}
        for process in processes:
            try:
                info = dict(getattr(process, "info", None) or {})
                pid = int(info.get("pid") or getattr(process, "pid"))
                create_time = float(self._process_value(
                    process, info, "create_time", 0.0) or 0.0)
                command_line = self._process_value(process, info, "cmdline", []) or []
                if isinstance(command_line, str):
                    args = command_line
                else:
                    args = subprocess.list2cmdline([str(item) for item in command_line])
                executable = self._process_value(process, info, "exe", "") or ""
                name = self._process_value(process, info, "name", "") or ""
                entry: dict[str, Any] = {
                    "comm": str(executable or name),
                    "args": args,
                    "cpu": float(self._process_value(
                        process, info, "cpu_percent", 0.0) or 0.0),
                    "mem": float(self._process_value(
                        process, info, "memory_percent", 0.0) or 0.0),
                    "etime": max(0, int(now - create_time)) if create_time else 0,
                    "ppid": int(self._process_value(process, info, "ppid", 0) or 0),
                    "create_time": create_time,
                }
                if with_identity:
                    username = str(self._process_value(
                        process, info, "username", "") or "")
                    sid = self._sid_for_username(username)
                    if sid and current_identity and current_identity.kind == "sid":
                        owner_is_current = (
                            sid.casefold()
                            == str(current_identity.value).casefold()
                        )
                    else:
                        owner_is_current = self._is_current_username(username)
                    entry["uid"] = 0 if owner_is_current else -1
                    entry["identity"] = sid or username or None
                    entry["identity_kind"] = "sid" if sid else "username"
                    entry["username"] = username or None
                snapshot[pid] = entry
            except Exception:
                # AccessDenied/NoSuchProcess races are expected during a global
                # process scan.  Omitting an unverifiable entry is safest.
                continue
        return snapshot

    def process_cwds(self, pids: Iterable[int]) -> dict[int, str]:
        psutil = self._psutil()
        result: dict[int, str] = {}
        for pid in normalize_pids(pids) or []:
            try:
                cwd = psutil.Process(pid).cwd()
                if cwd:
                    result[pid] = str(cwd)
            except Exception:
                continue
        return result

    def process_lineage(
        self,
        pids: Iterable[int],
        max_depth: int = 12,
    ) -> dict[int, tuple[int, str]]:
        """Read only the ancestry needed for origin attribution.

        Asking ``psutil.process_iter`` for every process command line is very
        expensive on a busy Windows host.  Listener attribution only needs the
        small union of their parent chains, so walk those chains lazily and
        cache shared ancestors within this snapshot.
        """
        psutil = self._psutil()
        frontier = set(normalize_pids(pids) or [])
        depth_limit = max(1, min(32, int(max_depth)))
        result: dict[int, tuple[int, str]] = {}
        for _depth in range(depth_limit + 1):
            if not frontier:
                break
            parents: set[int] = set()
            for pid in sorted(frontier):
                if pid in result:
                    continue
                try:
                    process = psutil.Process(pid)
                    info = dict(getattr(process, "info", None) or {})
                    ppid = int(self._process_value(
                        process, info, "ppid", 0) or 0)
                    command_line = self._process_value(
                        process, info, "cmdline", []) or []
                    if isinstance(command_line, str):
                        args = command_line
                    else:
                        args = subprocess.list2cmdline(
                            [str(item) for item in command_line])
                    if not args:
                        args = str(self._process_value(
                            process, info, "exe", "") or
                            self._process_value(
                                process, info, "name", "") or "")
                    result[pid] = (ppid, args)
                    if ppid > 0 and ppid not in result:
                        parents.add(ppid)
                except Exception:
                    # AccessDenied/NoSuchProcess races merely truncate this
                    # best-effort display chain; they never affect ownership.
                    continue
            frontier = parents
        return result

    def terminate_process(self, identity: Mapping[str, Any]) -> None:
        """Force-terminate one exact current-user process identity.

        ``psutil.Process.kill`` performs its own PID-reuse check on Windows.
        We additionally revalidate creation time and both owner/current SIDs
        immediately before that call so callers never degrade to a bare PID.
        """
        if not isinstance(identity, Mapping):
            raise ValueError("Windows 进程身份记录无效")
        pid = identity.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("Windows 进程身份记录无效")
        process = self._psutil().Process(pid)
        expected_time = identity.get("createTime")
        actual_time = float(process.create_time())
        try:
            same_time = abs(float(expected_time) - actual_time) < 0.001
        except (TypeError, ValueError, OverflowError):
            same_time = False
        if not same_time:
            raise AdapterUnavailable("PID 已被复用，进程身份已失效")
        owner_sid = self._sid_for_username(str(process.username() or ""))
        current = self.current_user_identity()
        expected_sid = identity.get("identity")
        if (not owner_sid or current.kind != "sid"
                or owner_sid.casefold() != str(current.value).casefold()
                or (expected_sid is not None
                    and owner_sid.casefold() != str(expected_sid).casefold())):
            raise AdapterUnavailable("无法用 Windows SID 证明进程属于当前用户")
        process.kill()

    def build_shell_command(self, command: str, shell: str = "auto") -> list[str]:
        shell = (shell or "auto").casefold()
        auto_ps_script = False
        if shell == "auto":
            first = first_command_token(str(command)).casefold()
            auto_ps_script = first.endswith(".ps1")
            shell = "powershell" if auto_ps_script else "cmd"
        if shell == "cmd":
            return ["cmd.exe", "/d", "/s", "/c", str(command)]
        if shell in ("powershell", "windows-powershell"):
            # Deliberately do not add -ExecutionPolicy Bypass.
            # A quoted .ps1 path alone is only a PowerShell string expression;
            # the call operator is required to execute it.  Keep explicit
            # PowerShell mode as raw user-authored -Command semantics.
            script = ("& " + str(command)) if auto_ps_script else str(command)
            return ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", script]
        raise ValueError("Windows shell 必须是 auto、cmd 或 powershell")

    def command_for_script(self, path: str) -> str:
        normalized = ntpath.abspath(ntpath.expanduser(str(path)))
        quoted = windows_quote(normalized)
        suffix = ntpath.splitext(normalized)[1].casefold()
        if suffix == ".py":
            return "py -3 -- %s" % quoted
        if suffix == ".ps1":
            return "powershell.exe -NoLogo -NoProfile -File %s" % quoted
        if suffix in (".cmd", ".bat"):
            return quoted
        return quoted
