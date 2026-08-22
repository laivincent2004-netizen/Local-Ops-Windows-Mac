"""macOS adapter preserving the original lsof/ps based server semantics."""

from __future__ import annotations

import getpass
import os
import platform
import posixpath
import re
import shlex
import time
from typing import Any, Iterable, Mapping, Optional

from .base import BasePlatformAdapter, RuntimeDirs, UserIdentity
from .common import command_stdout, normalize_pids, parse_etime, resolve_runtime_dir, to_float


class MacOSAdapter(BasePlatformAdapter):
    system = "macos"
    environment = "native"
    shells = ("posix",)
    path_style = "posix"

    def __init__(self, runner=None, command_runner=None) -> None:
        if runner is not None and command_runner is not None:
            raise TypeError("runner 与 command_runner 不能同时指定")
        runner = command_runner if command_runner is not None else runner
        super().__init__(runner=runner)
        self._uid = int(os.getuid()) if hasattr(os, "getuid") else -1

    @property
    def current_uid(self) -> int:
        return self._uid

    def platform_info(self, packaged=None) -> dict[str, Any]:
        info = super().platform_info(packaged=packaged)
        info["version"] = platform.mac_ver()[0] or platform.release()
        return info

    def current_user_identity(self) -> UserIdentity:
        name = getpass.getuser()
        try:
            import pwd  # POSIX-only; never imported by Windows adapters.
            name = pwd.getpwuid(self._uid).pw_name
        except (ImportError, KeyError, OSError):
            pass
        return UserIdentity("uid", self._uid, name)

    def runtime_dirs(
        self,
        app_name: str = "总控台",
        environ: Optional[Mapping[str, str]] = None,
        home: Optional[str] = None,
    ) -> RuntimeDirs:
        env = dict(os.environ if environ is None else environ)
        home_dir = posixpath.abspath(home or os.path.expanduser("~").replace("\\", "/"))
        data_default = posixpath.join(home_dir, "Library", "Application Support", app_name)
        log_default = posixpath.join(home_dir, "Library", "Logs", app_name)
        data_dir, data_overridden = resolve_runtime_dir(
            "CONSOLE_DATA_DIR", data_default, env, posixpath,
            forbidden=("/", home_dir),
        )
        log_dir, log_overridden = resolve_runtime_dir(
            "CONSOLE_LOG_DIR", log_default, env, posixpath,
            forbidden=("/", home_dir),
        )
        return RuntimeDirs(data_dir, log_dir, data_overridden, log_overridden)

    def scan_listeners(self) -> dict[tuple[int, int], set[str]]:
        output = command_stdout(
            self.runner, ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"])
        found: dict[tuple[int, int], set[str]] = {}
        for line in output.splitlines():
            if not line or line.startswith("COMMAND"):
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            port = None
            bind_host = None
            for token in reversed(parts):
                match = re.search(r":(\d+)$", token)
                if match:
                    port = int(match.group(1))
                    bind_host = token[:match.start()]
                    if bind_host.startswith("[") and bind_host.endswith("]"):
                        bind_host = bind_host[1:-1]
                    break
            if port is not None:
                found.setdefault((pid, port), set()).add(bind_host or "")
        return found

    def process_snapshot(
        self,
        pids: Optional[Iterable[int]] = None,
        with_identity: bool = True,
    ) -> dict[int, dict[str, Any]]:
        selected = normalize_pids(pids)
        if selected == []:
            return {}
        base = ["ps", "-ax"] if selected is None else [
            "ps", "-p", ",".join(str(pid) for pid in selected)]
        fields = ["pid"] + (["uid"] if with_identity else []) + [
            "ppid", "etime", "%cpu", "%mem", "comm"]
        details = command_stdout(self.runner, base + ["-o", ",".join(fields)])
        arguments = command_stdout(self.runner, base + ["-o", "pid,args"])
        snapshot: dict[int, dict[str, Any]] = {}
        # pid [uid] ppid etime cpu mem comm
        minimum = 7 if with_identity else 6
        now = time.time()
        for line in details.splitlines():
            tokens = line.split()
            if len(tokens) < minimum:
                continue
            try:
                pid = int(tokens[0])
            except ValueError:
                continue
            index = 1
            entry: dict[str, Any] = {"args": ""}
            if with_identity:
                try:
                    uid = int(tokens[index])
                except ValueError:
                    uid = -1
                entry["uid"] = uid
                entry["identity"] = uid
                index += 1
            try:
                entry["ppid"] = int(tokens[index])
            except ValueError:
                entry["ppid"] = 0
            elapsed = parse_etime(tokens[index + 1])
            entry["etime"] = elapsed
            entry["create_time"] = max(0.0, now - elapsed)
            entry["cpu"] = to_float(tokens[index + 2])
            entry["mem"] = to_float(tokens[index + 3])
            entry["comm"] = " ".join(tokens[index + 4:])
            snapshot[pid] = entry
        for line in arguments.splitlines():
            tokens = line.split(None, 1)
            if not tokens:
                continue
            try:
                pid = int(tokens[0])
            except ValueError:
                continue
            if pid in snapshot:
                snapshot[pid]["args"] = tokens[1] if len(tokens) > 1 else ""
        return snapshot

    def process_cwds(self, pids: Iterable[int]) -> dict[int, str]:
        selected = normalize_pids(pids) or []
        if not selected:
            return {}
        output = command_stdout(
            self.runner,
            ["lsof", "-a", "-p", ",".join(str(pid) for pid in selected),
             "-d", "cwd", "-Fn"],
        )
        result: dict[int, str] = {}
        current_pid = None
        for line in output.splitlines():
            if line.startswith("p"):
                try:
                    current_pid = int(line[1:])
                except ValueError:
                    current_pid = None
            elif line.startswith("n") and current_pid is not None:
                result[current_pid] = line[1:]
        return result

    def build_shell_command(self, command: str, shell: str = "auto") -> list[str]:
        if shell not in ("auto", "posix", "bash"):
            raise ValueError("macOS 仅支持 posix shell")
        return ["/bin/bash", "-c", str(command)]

    def command_for_script(self, path: str) -> str:
        normalized = posixpath.abspath(posixpath.expanduser(str(path)).replace("\\", "/"))
        quoted = shlex.quote(normalized)
        suffix = posixpath.splitext(normalized)[1].lower()
        if suffix == ".py":
            return "python3 -- %s" % quoted
        if suffix == ".zsh":
            return "/bin/zsh -- %s" % quoted
        if suffix in (".sh", ".bash"):
            return "/bin/bash -- %s" % quoted
        if os.access(normalized, os.X_OK):
            return quoted
        return "/bin/bash -- %s" % quoted


# Backward-friendly spelling for callers that use MacOS instead of macOS.
MacAdapter = MacOSAdapter
