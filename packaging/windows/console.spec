# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onedir/windowed specification for the Windows tray host."""

from pathlib import Path


ROOT = Path(SPEC).resolve().parents[2]
ICON = ROOT / "static" / "assets" / "favicon.ico"


a = Analysis(
    [str(ROOT / "desktop" / "windows_host.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / "static"), "static"),
        (str(ROOT / "VERSION"), "."),
        (str(ROOT / "LICENSE"), "."),
        (str(ROOT / "THIRD_PARTY_NOTICES.md"), "."),
        (str(ROOT / "ASSET_PROVENANCE.md"), "."),
        (str(ROOT / "licenses"), "licenses"),
        (str(ROOT / "server.py"), "."),
    ],
    # server.py is executed from its data copy only after runtime directories
    # and ACLs exist.  It must still be analyzed as a hidden import so every
    # stdlib module and lazy platform package it uses is present in the frozen
    # interpreter.
    hiddenimports=[
        "PIL._tkinter_finder",
        "server",
        "supervisor_client",
        "supervisor_windows",
        "console_platform",
        "console_platform.base",
        "console_platform.common",
        "console_platform.macos",
        "console_platform.windows",
        "console_platform.wsl",
        "console_platform.wsl_host",
        "console_platform.windows_security",
        "psutil",
        "pystray._win32",
        "tkinter",
        "tkinter.filedialog",
        "ntsecuritycon",
        "win32api",
        "win32con",
        "win32event",
        "win32file",
        "win32job",
        "win32pipe",
        "win32process",
        "win32security",
        "pywintypes",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["test", "unittest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="总控台",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    # Runtime checks return an explicit exit code; production windowed failures
    # are logged by the host.  Never display PyInstaller's blocking traceback UI.
    disable_windowed_traceback=True,
    argv_emulation=False,
    icon=str(ICON),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="总控台",
)
