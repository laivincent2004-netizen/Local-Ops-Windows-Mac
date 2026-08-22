"""Stable interfaces shared by the native and WSL platform adapters."""

from __future__ import annotations

from dataclasses import dataclass
import platform as _platform
import sys
from typing import Any, Callable, Iterable, Mapping, Optional


class AdapterError(RuntimeError):
    """Base error raised by a platform adapter."""


class AdapterUnavailable(AdapterError):
    """The requested capability is not installed or cannot be reached."""


@dataclass(frozen=True)
class UserIdentity:
    """An operating-system identity suitable for display and exact comparison.

    ``value`` is a numeric uid on POSIX and a SID (or a username fallback) on
    Windows.  Windows adapters intentionally expose a separate numeric
    ``current_uid`` compatibility surrogate; it must not be used as a security
    identity.
    """

    kind: str
    value: Any
    name: str

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "name": self.name}


@dataclass(frozen=True)
class RuntimeDirs:
    """Host-side persistent directories selected for the console."""

    data_dir: str
    log_dir: str
    data_overridden: bool = False
    log_overridden: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "dataDir": self.data_dir,
            "logDir": self.log_dir,
            "dataOverridden": self.data_overridden,
            "logOverridden": self.log_overridden,
        }


Runner = Callable[..., Any]


class BasePlatformAdapter:
    """Common adapter surface used by the platform-neutral server layer.

    Listener snapshots preserve the existing server shape::

        {(pid, port): {"127.0.0.1", "::1"}}

    Process snapshots preserve the existing keys ``uid``, ``comm``, ``args``,
    ``cpu``, ``mem`` and ``etime``.  Adapters may add ``identity``, ``ppid`` and
    ``create_time`` when the operating system can provide them.
    """

    system = "unknown"
    environment = "native"
    shells: tuple[str, ...] = ()
    path_style = "posix"

    def __init__(self, runner: Optional[Runner] = None) -> None:
        self.runner = runner

    @property
    def current_uid(self) -> int:
        identity = self.current_user_identity()
        return identity.value if isinstance(identity.value, int) else 0

    def platform_info(self, packaged: Optional[bool] = None) -> dict[str, Any]:
        if packaged is None:
            packaged = bool(getattr(sys, "frozen", False))
        return {
            "os": self.system,
            "system": self.system,
            "environment": self.environment,
            "arch": _platform.machine().lower() or "unknown",
            "architecture": _platform.machine() or "unknown",
            "shells": list(self.shells),
            "pathStyle": self.path_style,
            "packaged": bool(packaged),
            "wslDistros": self.discover_wsl_distros(),
        }

    def current_user_identity(self) -> UserIdentity:
        raise NotImplementedError

    def runtime_dirs(
        self,
        app_name: str = "总控台",
        environ: Optional[Mapping[str, str]] = None,
        home: Optional[str] = None,
    ) -> RuntimeDirs:
        raise NotImplementedError

    def scan_listeners(self) -> dict[tuple[int, int], set[str]]:
        raise NotImplementedError

    def process_snapshot(
        self,
        pids: Optional[Iterable[int]] = None,
        with_identity: bool = True,
    ) -> dict[int, dict[str, Any]]:
        raise NotImplementedError

    def process_cwds(self, pids: Iterable[int]) -> dict[int, str]:
        raise NotImplementedError

    def build_shell_command(self, command: str, shell: str = "auto") -> list[str]:
        raise NotImplementedError

    def command_for_script(self, path: str) -> str:
        raise NotImplementedError

    def discover_wsl_distros(self) -> list[dict[str, Any]]:
        return []
