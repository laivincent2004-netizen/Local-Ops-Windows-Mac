# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onefile/console specification for the Windows supervisor.

The supervisor needs a real private console so its managed child process
groups can receive targeted CTRL_BREAK events.  The launcher creates that
console with CREATE_NEW_CONSOLE and supplies SW_HIDE; the tray host remains a
separate windowed executable.
"""

from pathlib import Path


ROOT = Path(SPEC).resolve().parents[2]


a = Analysis(
    [str(ROOT / "supervisor.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "VERSION"), ".")],
    hiddenimports=[
        "supervisor_windows",
        "psutil",
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
    excludes=["tkinter", "test", "unittest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="console-supervisor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
)
