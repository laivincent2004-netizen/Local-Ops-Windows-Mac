"""Lazy cross-platform adapter selection for 总控台."""

from __future__ import annotations

import os
import platform
import sys

from .base import AdapterError, AdapterUnavailable, BasePlatformAdapter, RuntimeDirs, UserIdentity


def _detected_system() -> str:
    if os.name == "nt" or sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin" or platform.system().casefold() == "darwin":
        return "macos"
    if (os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME")
            or "microsoft" in platform.release().casefold()):
        return "wsl"
    return platform.system().casefold() or "unknown"


def get_adapter(system=None, **kwargs):
    """Create an adapter; platform-specific modules are imported on demand."""
    selected = str(system or _detected_system()).strip().casefold()
    if selected in ("darwin", "mac", "macos", "osx"):
        from .macos import MacOSAdapter
        return MacOSAdapter(**kwargs)
    if selected in ("win", "win32", "windows"):
        from .windows import WindowsAdapter
        return WindowsAdapter(**kwargs)
    if selected in ("wsl", "wsl2"):
        from .wsl import WSLAdapter
        if not kwargs.get("distro"):
            distro = os.environ.get("WSL_DISTRO_NAME")
            if distro:
                kwargs["distro"] = distro
        return WSLAdapter(**kwargs)
    raise AdapterUnavailable("不支持的平台: %s" % selected)


def __getattr__(name):
    # Keep importing this package safe on macOS installations that do not have
    # Windows-only optional dependencies.
    if name in ("MacOSAdapter", "MacAdapter"):
        from .macos import MacOSAdapter
        return MacOSAdapter
    if name == "WindowsAdapter":
        from .windows import WindowsAdapter
        return WindowsAdapter
    if name == "WSLAdapter":
        from .wsl import WSLAdapter
        return WSLAdapter
    raise AttributeError(name)


__all__ = [
    "AdapterError", "AdapterUnavailable", "BasePlatformAdapter", "RuntimeDirs",
    "UserIdentity", "MacOSAdapter", "MacAdapter", "WindowsAdapter",
    "WSLAdapter", "get_adapter",
]
