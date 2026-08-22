"""WSL2 execution adapter and versioned-helper protocol boundary."""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
import shlex
from typing import Any, Iterable, Mapping, Optional

from .base import AdapterUnavailable, BasePlatformAdapter, RuntimeDirs, UserIdentity
from .common import call_runner, command_stdout, normalize_pids


def validate_distro_name(value: Any) -> str:
    name = str(value or "").strip()
    if (not name or len(name) > 128 or name.startswith("-")
            or name in (".", "..") or name.endswith(".")
            or any(char in '\\/:*?"<>|' for char in name)
            or any(ord(char) < 32 for char in name)):
        raise ValueError("WSL 发行版名称无效")
    return name


def normalize_wsl_path(path: str, distro: str) -> str:
    """Normalize Linux, drive-letter, and \\wsl.localhost paths for a distro."""
    value = str(path).strip()
    if not value:
        return value
    unc = re.match(
        r"^\\\\(?:wsl\.localhost|wsl\$)\\([^\\]+)(?:\\(.*))?$",
        value, re.IGNORECASE)
    if unc:
        path_distro, remainder = unc.groups()
        if path_distro.casefold() != distro.casefold():
            raise ValueError("UNC 路径属于另一个 WSL 发行版")
        return "/" + (remainder or "").replace("\\", "/").lstrip("/")
    drive, remainder = ntpath.splitdrive(value)
    if drive and len(drive) == 2 and drive[1] == ":":
        return "/mnt/%s/%s" % (
            drive[0].casefold(), remainder.replace("\\", "/").lstrip("/"))
    return posixpath.normpath(value.replace("\\", "/"))


class WSLAdapter(BasePlatformAdapter):
    """Adapter for commands and snapshots inside one registered WSL2 distro.

    Process/listener data comes from the separately versioned Linux helper
    described by wsl_helper/PROTOCOL.md.  ``helper_provider`` is the in-process protocol seam
    used by tests and desktop hosts; ``helper_path`` invokes an already-installed
    helper in the distribution.  The adapter never installs or starts a distro.
    """

    system = "wsl"
    environment = "wsl"
    shells = ("posix",)
    path_style = "posix"

    def __init__(
        self,
        distro: str,
        runner=None,
        command_runner=None,
        helper_provider=None,
        helper_path: Optional[str] = None,
        host_environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        if runner is not None and command_runner is not None:
            raise TypeError("runner 与 command_runner 不能同时指定")
        runner = command_runner if command_runner is not None else runner
        super().__init__(runner=runner)
        self.distro = validate_distro_name(distro)
        self.helper_provider = helper_provider
        self.helper_path = str(helper_path) if helper_path else None
        self.host_environ = dict(os.environ if host_environ is None else host_environ)
        self._identity: Optional[UserIdentity] = None

    def build_shell_command(self, command: str, shell: str = "auto") -> list[str]:
        if shell not in ("auto", "posix", "sh"):
            raise ValueError("WSL 仅支持 posix shell")
        return [
            "wsl.exe", "--distribution", self.distro, "--",
            "/bin/sh", "-lc", str(command),
        ]

    def _inside_stdout(self, command: str, timeout: float = 5.0) -> str:
        return command_stdout(
            self.runner, self.build_shell_command(command), timeout=timeout)

    @property
    def current_uid(self) -> int:
        identity = self.current_user_identity()
        return int(identity.value) if isinstance(identity.value, int) else -1

    def current_user_identity(self) -> UserIdentity:
        if self._identity is not None:
            return self._identity
        output = self._inside_stdout("id -u; id -un")
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        try:
            uid = int(lines[0])
        except (IndexError, ValueError) as exc:
            raise AdapterUnavailable(
                "无法读取 WSL 发行版 %s 的当前用户" % self.distro) from exc
        name = lines[1] if len(lines) > 1 else str(uid)
        self._identity = UserIdentity("uid", uid, name)
        return self._identity

    def runtime_dirs(
        self,
        app_name: str = "总控台",
        environ: Optional[Mapping[str, str]] = None,
        home: Optional[str] = None,
    ) -> RuntimeDirs:
        # WSL applications are supervised by the Windows desktop host.  Their
        # config, logs and durable identities therefore remain in LOCALAPPDATA
        # and survive distribution shutdown/replacement.
        from .windows import WindowsAdapter
        return WindowsAdapter(
            runner=self.runner,
            psutil_module=None,
            environ=self.host_environ,
        ).runtime_dirs(app_name=app_name, environ=environ, home=home)

    def discover_wsl_distros(self) -> list[dict[str, Any]]:
        from .windows import discover_wsl_distros
        return discover_wsl_distros(self.runner)

    def platform_info(self, packaged=None) -> dict[str, Any]:
        info = super().platform_info(packaged=packaged)
        info["distro"] = self.distro
        architecture = self._inside_stdout("uname -m").strip()
        if architecture:
            info["architecture"] = architecture.splitlines()[0]
            info["arch"] = info["architecture"].lower()
        info["helperConfigured"] = bool(self.helper_provider or self.helper_path)
        return info

    def _helper_call(
        self,
        operation: str,
        pids: Optional[Iterable[int]] = None,
    ) -> Any:
        selected = normalize_pids(pids)
        if self.helper_provider is not None:
            try:
                return self.helper_provider(
                    operation=operation, distro=self.distro, pids=selected)
            except TypeError:
                return self.helper_provider(operation, self.distro, selected)
        if not self.helper_path:
            raise AdapterUnavailable(
                "WSL 进程监控 helper 尚未配置；不会回退到自动启动发行版")
        if not self.helper_path.startswith("/"):
            raise AdapterUnavailable("WSL helper_path 必须是 Linux 绝对路径")
        matching = next(
            (item for item in self.discover_wsl_distros()
             if item.get("name", "").casefold() == self.distro.casefold()),
            None,
        )
        if matching is None:
            raise AdapterUnavailable("WSL 发行版 %s 未安装" % self.distro)
        if matching.get("version") != 2:
            raise AdapterUnavailable("WSL1 不受支持: %s" % self.distro)
        if not matching.get("running"):
            raise AdapterUnavailable(
                "WSL 发行版 %s 未运行；监控不会自动启动它" % self.distro)
        args = [
            "wsl.exe", "--distribution", self.distro, "--",
            self.helper_path, operation, "--json",
        ]
        if selected is not None:
            args.extend(["--pids", ",".join(str(pid) for pid in selected)])
        result = call_runner(self.runner, args, timeout=5.0)
        if result.returncode != 0:
            raise AdapterUnavailable(
                "WSL helper %s 失败: %s" % (
                    operation, result.stderr.strip() or "exit %s" % result.returncode))
        try:
            return json.loads(result.stdout)
        except (TypeError, ValueError) as exc:
            raise AdapterUnavailable("WSL helper 返回了无效 JSON") from exc

    def scan_listeners(self) -> dict[tuple[int, int], set[str]]:
        payload = self._helper_call("listeners")
        if isinstance(payload, dict):
            payload = payload.get("listeners", payload.get("items", []))
        if not isinstance(payload, list):
            raise AdapterUnavailable("WSL helper listeners 数据形状无效")
        found: dict[tuple[int, int], set[str]] = {}
        for item in payload:
            if not isinstance(item, dict):
                continue
            try:
                pid = int(item["pid"])
                port = int(item["port"])
            except (KeyError, TypeError, ValueError):
                continue
            hosts = item.get("bind_hosts", item.get("hosts", item.get("bind_host", "")))
            if isinstance(hosts, str):
                hosts = [hosts]
            if not isinstance(hosts, (list, tuple, set)):
                hosts = [""]
            found.setdefault((pid, port), set()).update(str(host) for host in hosts)
        return found

    def process_snapshot(
        self,
        pids: Optional[Iterable[int]] = None,
        with_identity: bool = True,
    ) -> dict[int, dict[str, Any]]:
        payload = self._helper_call("processes", pids=pids)
        if isinstance(payload, dict) and "processes" in payload:
            payload = payload["processes"]
        if isinstance(payload, dict):
            items = []
            for pid, value in payload.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("pid", pid)
                    items.append(item)
        elif isinstance(payload, list):
            items = payload
        else:
            raise AdapterUnavailable("WSL helper processes 数据形状无效")
        result: dict[int, dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                pid = int(item["pid"])
            except (KeyError, TypeError, ValueError):
                continue
            entry = {
                "comm": str(item.get("comm") or item.get("name") or ""),
                "args": str(item.get("args") or ""),
                "cpu": float(item.get("cpu") or 0.0),
                "mem": float(item.get("mem") or 0.0),
                "etime": max(0, int(item.get("etime") or 0)),
                "ppid": int(item.get("ppid") or 0),
                "create_time": item.get("create_time") or item.get("startTicks") or 0,
                "start_ticks": item.get("startTicks", item.get("start_ticks")),
                "boot_id": item.get("bootId", item.get("boot_id")),
                "pgid": int(item.get("pgid") or 0),
                "sid": int(item.get("sid") or 0),
                "cwd": item.get("cwd"),
            }
            if with_identity:
                try:
                    uid = int(item.get("uid", -1))
                except (TypeError, ValueError):
                    uid = -1
                entry["uid"] = uid
                entry["identity"] = uid
            result[pid] = entry
        return result

    def process_cwds(self, pids: Iterable[int]) -> dict[int, str]:
        payload = self._helper_call("cwds", pids=pids)
        if isinstance(payload, dict) and "cwds" in payload:
            payload = payload["cwds"]
        if not isinstance(payload, dict):
            raise AdapterUnavailable("WSL helper cwds 数据形状无效")
        result: dict[int, str] = {}
        for pid, cwd in payload.items():
            try:
                key = int(pid)
            except (TypeError, ValueError):
                continue
            if isinstance(cwd, str) and cwd:
                result[key] = cwd
        return result

    def command_for_script(self, path: str) -> str:
        normalized = normalize_wsl_path(str(path), self.distro)
        quoted = shlex.quote(normalized)
        suffix = posixpath.splitext(normalized)[1].casefold()
        if suffix == ".py":
            return "python3 -- %s" % quoted
        if suffix in (".sh", ".bash", ".command"):
            return "/bin/sh -- %s" % quoted
        return quoted
