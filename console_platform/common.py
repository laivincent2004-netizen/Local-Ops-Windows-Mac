"""Dependency-free parsing and command helpers for platform adapters."""

from __future__ import annotations

from dataclasses import dataclass
import locale
import os
import re
import shlex
import subprocess
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class CommandOutput:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


def hidden_subprocess_options() -> dict[str, int]:
    """Keep background console programs invisible in a Windows GUI host.

    PyInstaller's windowed host has no inherited console.  Without
    ``CREATE_NO_WINDOW``, each short-lived ``wsl.exe``/console command gets a
    new visible Command Prompt window.  Keep the option Windows-only because
    POSIX ``subprocess`` rejects ``creationflags``.
    """
    if os.name != "nt":
        return {}
    return {
        "creationflags": int(
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        ),
    }


def decode_command_output(value: Any) -> str:
    """Decode native command output, including redirected UTF-16 WSL output."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return str(value)
    raw = bytes(value)
    if not raw:
        return ""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace").replace("\x00", "")
    # Older wsl.exe versions commonly emit UTF-16LE without a BOM when stdout
    # is redirected.  A high NUL density is a reliable signal for its ASCII
    # and localized table output.
    if raw.count(b"\x00") >= max(2, len(raw) // 8):
        return raw.decode("utf-16-le", errors="replace").replace("\x00", "")
    encodings = ("utf-8", locale.getpreferredencoding(False), "cp1252")
    for encoding in encodings:
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            pass
    return raw.decode("utf-8", errors="replace")


def run_command(args: Iterable[str], timeout: float = 5.0) -> CommandOutput:
    """Run an argv command without a shell and retain diagnostic status."""
    try:
        completed = subprocess.run(
            list(args), capture_output=True, timeout=timeout, check=False,
            **hidden_subprocess_options())
        return CommandOutput(
            decode_command_output(completed.stdout),
            decode_command_output(completed.stderr),
            int(completed.returncode),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandOutput(
            decode_command_output(exc.stdout),
            decode_command_output(exc.stderr) or "command timed out",
            124,
        )
    except OSError as exc:
        return CommandOutput("", str(exc), 127)


def call_runner(runner: Any, args: Iterable[str], timeout: float = 5.0) -> CommandOutput:
    """Call a production or injected runner and normalize its result.

    Test and host integrations may return ``str``/``bytes``, a
    ``subprocess.CompletedProcess``, :class:`CommandOutput`, a mapping, or a
    ``(stdout, stderr, returncode)`` tuple.
    """
    if runner is None:
        return run_command(args, timeout=timeout)
    argv = list(args)
    try:
        try:
            value = runner(argv, timeout=timeout)
        except TypeError:
            value = runner(argv)
    except subprocess.TimeoutExpired as exc:
        return CommandOutput(
            decode_command_output(exc.stdout),
            decode_command_output(exc.stderr) or "command timed out",
            124,
        )
    except OSError as exc:
        return CommandOutput("", str(exc), 127)
    if isinstance(value, CommandOutput):
        return value
    if isinstance(value, (str, bytes, bytearray, memoryview)) or value is None:
        return CommandOutput(decode_command_output(value), "", 0)
    if isinstance(value, dict):
        return CommandOutput(
            decode_command_output(value.get("stdout")),
            decode_command_output(value.get("stderr")),
            int(value.get("returncode", value.get("code", 0))),
        )
    if isinstance(value, tuple):
        if len(value) == 2:
            stdout, returncode = value
            return CommandOutput(decode_command_output(stdout), "", int(returncode))
        if len(value) >= 3:
            stdout, stderr, returncode = value[:3]
            return CommandOutput(
                decode_command_output(stdout),
                decode_command_output(stderr),
                int(returncode),
            )
    return CommandOutput(
        decode_command_output(getattr(value, "stdout", "")),
        decode_command_output(getattr(value, "stderr", "")),
        int(getattr(value, "returncode", 0)),
    )


def command_stdout(runner: Any, args: Iterable[str], timeout: float = 5.0) -> str:
    result = call_runner(runner, args, timeout=timeout)
    return result.stdout if result.returncode == 0 else ""


def normalize_pids(pids: Optional[Iterable[int]]) -> Optional[list[int]]:
    if pids is None:
        return None
    result = []
    seen = set()
    for value in pids:
        try:
            pid = int(value)
        except (TypeError, ValueError):
            continue
        if pid > 0 and pid not in seen:
            seen.add(pid)
            result.append(pid)
    return result


def parse_etime(value: Any) -> int:
    """Parse ps ``[[dd-]hh:]mm:ss`` elapsed time; invalid values become 0."""
    try:
        text = str(value).strip()
        days = 0
        if "-" in text:
            day_text, text = text.split("-", 1)
            days = int(day_text)
        parts = [int(part) for part in text.split(":")]
        if len(parts) == 2:
            hours, minutes, seconds = 0, parts[0], parts[1]
        elif len(parts) == 3:
            hours, minutes, seconds = parts
        else:
            return 0
        if min(hours, minutes, seconds, days) < 0:
            return 0
        return days * 86400 + hours * 3600 + minutes * 60 + seconds
    except (TypeError, ValueError):
        return 0


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def resolve_runtime_dir(
    env_name: str,
    default: str,
    environ: dict[str, str],
    path_module: Any = os.path,
    forbidden: Iterable[str] = (),
) -> tuple[str, bool]:
    """Resolve a dedicated runtime directory with the server's safety rules."""
    overridden = env_name in environ
    raw = environ.get(env_name, default)
    if overridden and not (raw or "").strip():
        raise RuntimeError("%s 不能为空" % env_name)
    raw = str(raw).strip()
    path = path_module.normpath(raw)
    if not path_module.isabs(path):
        raise RuntimeError("%s 必须是绝对路径" % env_name)
    forbidden_paths = {path_module.normcase(path_module.normpath(item))
                       for item in forbidden if item}
    if path_module.normcase(path) in forbidden_paths:
        raise RuntimeError("%s 必须指向专用子目录" % env_name)
    return path, overridden


def posix_quote(value: Any) -> str:
    return shlex.quote(str(value))


def windows_quote(value: Any) -> str:
    return subprocess.list2cmdline([str(value)])


def first_command_token(command: str) -> str:
    """Best-effort first-token extraction for Windows shell auto selection."""
    text = (command or "").lstrip()
    if not text:
        return ""
    if text[0] in ('"', "'"):
        quote = text[0]
        end = text.find(quote, 1)
        return text[1:] if end < 0 else text[1:end]
    match = re.match(r"[^\s|&;<>]+", text)
    return match.group(0) if match else ""
