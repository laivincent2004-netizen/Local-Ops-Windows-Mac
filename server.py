#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""总控台后端（单文件，仅 Python 3 标准库）。

本地服务监控 + 快速启动台：
    python3 server.py  →  绑定 127.0.0.1，端口 9600 起（被占 +1，最多 10 个）
API 契约与实现要点见 AGENTS.md。
"""

import glob
import base64
import functools
import errno
import hashlib
import hmac
import json
import logging
import ntpath
import os
import platform
import posixpath
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # POSIX only; Windows uses msvcrt below.
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None

try:  # Windows only; kept conditional so macOS remains dependency-free.
    import msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    msvcrt = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
LEGACY_DATA_DIR = os.path.join(BASE_DIR, "data")
IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    _LOCAL_APP_DATA = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")
    DEFAULT_DATA_DIR = os.path.join(_LOCAL_APP_DATA, "总控台")
    DEFAULT_LOGS_DIR = os.path.join(DEFAULT_DATA_DIR, "logs")
else:
    DEFAULT_DATA_DIR = os.path.expanduser(
        "~/Library/Application Support/总控台")
    DEFAULT_LOGS_DIR = os.path.expanduser("~/Library/Logs/总控台")


def resolve_runtime_dir(name, default):
    """解析专用运行目录，拒绝空值、相对路径和过宽目标。"""
    if name not in os.environ:
        return os.path.abspath(default), False
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        raise RuntimeError("%s 不能为空" % name)
    expanded = os.path.expanduser(raw)
    if not os.path.isabs(expanded):
        raise RuntimeError("%s 必须是绝对路径" % name)
    path = os.path.abspath(expanded)
    forbidden = {os.path.abspath(os.sep), os.path.abspath(os.path.expanduser("~")),
                 os.path.abspath(BASE_DIR)}
    if path in forbidden:
        raise RuntimeError("%s 必须指向专用子目录" % name)
    return path, True


DATA_DIR, DATA_DIR_OVERRIDDEN = resolve_runtime_dir(
    "CONSOLE_DATA_DIR", DEFAULT_DATA_DIR)
ICONS_DIR = os.path.join(DATA_DIR, "icons")
LOGS_DIR, LOGS_DIR_OVERRIDDEN = resolve_runtime_dir(
    "CONSOLE_LOG_DIR", DEFAULT_LOGS_DIR)
STATIC_DIR = os.path.join(BASE_DIR, "static")
THEMES_DIR = os.path.join(STATIC_DIR, "themes")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
INSTANCE_LOCK_PATH = os.path.join(DATA_DIR, "console.lock")

CURRENT_SCHEMA_VERSION = 2

# 默认 UI 主题：新安装与无偏好回退均使用它，主题清单中固定排首位。
DEFAULT_UI_THEME = "ops"


def read_project_version(path=VERSION_PATH):
    """读取根目录 VERSION。失败时保持服务可诊断，但标记为降级。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read(128).strip()
        if not re.fullmatch(
                r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value):
            raise ValueError("VERSION 不是合法的 SemVer")
        return value, None
    except (OSError, UnicodeError, ValueError) as e:
        return "0.0.0+unknown", str(e)


APP_VERSION, VERSION_LOAD_ERROR = read_project_version()

HOST = "127.0.0.1"
PORT_START = 9600
PORT_TRIES = 10
SUBPROCESS_TIMEOUT = 5          # lsof/ps 等子进程超时（秒）
WSL_DISCOVERY_PENDING_MESSAGE = "WSL 发行版枚举正在后台进行"
MAX_ICON_BYTES = 5 * 1024 * 1024
MAX_JSON_BYTES = 1 * 1024 * 1024
MAX_DETECT_FILE_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 10 * 1024 * 1024
LOG_BACKUPS = 3
LOG_MAINTENANCE_SEC = 30
STARTUP_PROBE_SEC = 0.25
APP_STOP_TIMEOUT_SEC = 5.0
RUN_TOKEN_ENV = "CONSOLE_RUN_TOKEN"
RUN_TOKEN_ARG_PREFIX = "console-run:"
TASK_CANCELED_EXIT_CODE = 130
SUPERVISOR_TERMINAL_STATES = frozenset({
    "exited", "stopped", "distro-stopped", "distro-restarted",
    "session-lost", "startup-failed",
})
SUPERVISOR_IDENTITY_LOSS_STATES = frozenset({
    "distro-stopped", "distro-restarted", "session-lost",
    "startup-failed",
})

SELF_PID = os.getpid()
SELF_UID = os.getuid() if hasattr(os, "getuid") else 0
ICON_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".ico")
LOG = logging.getLogger("console")
LOG_LOCK = threading.RLock()
MANUAL_STOP_LOCK = threading.RLock()
MANUAL_STOP_TOKENS = set()
INSTANCE_KEY_SECRET = secrets.token_bytes(32)
_WSL_MANAGER = None
_WSL_MANAGER_LOCK = threading.Lock()
_PLATFORM_WSL_UNSET = object()


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value):
    raw = value.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _identity_digest(value):
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8", "surrogatepass")).hexdigest()


def make_instance_key(environment, pid, create_time, distro=None,
                      boot_id=None, port=None, identity=None, cwd=None,
                      command=None, cwd_hash=None, command_hash=None):
    """Return a process identity token authenticated to this console run."""
    payload = {
        "v": 1,
        "environment": environment,
        "distro": distro,
        "bootId": boot_id,
        "pid": int(pid),
        "createTime": str(create_time),
        "port": int(port) if port is not None else None,
        "identity": str(identity) if identity is not None else None,
        "cwdHash": cwd_hash or _identity_digest(cwd),
        "commandHash": command_hash or _identity_digest(command),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    signature = hmac.new(INSTANCE_KEY_SECRET, raw, hashlib.sha256).digest()
    return "ik1.%s.%s" % (_b64url(raw), _b64url(signature))


def parse_instance_key(value):
    """Verify and decode an instance key; invalid/tampered keys return None."""
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        prefix, encoded, encoded_signature = value.split(".", 2)
        if prefix != "ik1":
            return None
        raw = _b64url_decode(encoded)
        signature = _b64url_decode(encoded_signature)
        expected = hmac.new(INSTANCE_KEY_SECRET, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(raw.decode("utf-8"))
        if (not isinstance(payload, dict) or payload.get("v") != 1
                or payload.get("environment") not in ("native", "wsl")
                or isinstance(payload.get("pid"), bool)
                or not isinstance(payload.get("pid"), int)
                or payload.get("pid") <= 0):
            return None
        distro = payload.get("distro")
        if distro is not None and (not isinstance(distro, str)
                                   or len(distro) > 128
                                   or any(ch in distro for ch in "\r\n\0")):
            return None
        if payload.get("environment") == "wsl" and not distro:
            return None
        return payload
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return None


def get_platform_info(
        *, wsl_distros=_PLATFORM_WSL_UNSET,
        wsl_discovery_error=_PLATFORM_WSL_UNSET,
        wsl_discovery_pending=_PLATFORM_WSL_UNSET,
        wsl_discovery_ready=_PLATFORM_WSL_UNSET,
        wsl_discovery_stale=_PLATFORM_WSL_UNSET):
    """Return the stable public platform contract without starting WSL."""
    precomputed_wsl = (
        wsl_distros is not _PLATFORM_WSL_UNSET
        or wsl_discovery_error is not _PLATFORM_WSL_UNSET
        or wsl_discovery_pending is not _PLATFORM_WSL_UNSET
        or wsl_discovery_ready is not _PLATFORM_WSL_UNSET
        or wsl_discovery_stale is not _PLATFORM_WSL_UNSET
    )
    if IS_WINDOWS and not precomputed_wsl:
        try:
            manager = get_wsl_manager()
            monitor = manager.monitor_discovery() if manager else {
                "distros": [], "error": None, "pending": False,
                "ready": True, "stale": False,
            }
        except Exception as exc:
            LOG.warning("启动 WSL 后台枚举失败: %s", exc)
            monitor = {
                "distros": [], "error": str(exc), "pending": False,
                "ready": True, "stale": False,
            }
        wsl_distros = monitor.get("distros") or []
        wsl_discovery_error = monitor.get("error")
        wsl_discovery_pending = bool(monitor.get("pending"))
        wsl_discovery_ready = bool(monitor.get("ready"))
        wsl_discovery_stale = bool(monitor.get("stale"))
        precomputed_wsl = True
    try:
        from console_platform import get_adapter
        adapter = get_adapter()
        if IS_WINDOWS and precomputed_wsl:
            info = dict(adapter.platform_info(
                wsl_distros=(
                    [] if wsl_distros is _PLATFORM_WSL_UNSET
                    else wsl_distros
                ),
                wsl_discovery_error=(
                    None if wsl_discovery_error is _PLATFORM_WSL_UNSET
                    else wsl_discovery_error
                ),
                wsl_discovery_pending=(
                    False if wsl_discovery_pending is _PLATFORM_WSL_UNSET
                    else wsl_discovery_pending
                ),
                wsl_discovery_ready=(
                    True if wsl_discovery_ready is _PLATFORM_WSL_UNSET
                    else wsl_discovery_ready
                ),
                wsl_discovery_stale=(
                    False if wsl_discovery_stale is _PLATFORM_WSL_UNSET
                    else wsl_discovery_stale
                ),
            ))
        else:
            info = dict(adapter.platform_info())
    except Exception as exc:
        LOG.warning("平台适配器不可用: %s", exc)
        info = {
            "os": "windows" if IS_WINDOWS else "macos",
            "arch": platform.machine().lower(),
            "shells": (["auto", "cmd", "powershell"] if IS_WINDOWS
                       else ["posix"]),
            "packaged": bool(getattr(sys, "frozen", False)),
            "wslDistros": [],
        }
        if IS_WINDOWS and precomputed_wsl:
            info["wslDistros"] = [
                dict(item) for item in (
                    [] if wsl_distros is _PLATFORM_WSL_UNSET
                    else (wsl_distros or [])
                )
            ]
            error = (
                None if wsl_discovery_error is _PLATFORM_WSL_UNSET
                else wsl_discovery_error
            )
            pending = (
                False if wsl_discovery_pending is _PLATFORM_WSL_UNSET
                else bool(wsl_discovery_pending)
            )
            ready = (
                True if wsl_discovery_ready is _PLATFORM_WSL_UNSET
                else bool(wsl_discovery_ready)
            )
            stale = (
                False if wsl_discovery_stale is _PLATFORM_WSL_UNSET
                else bool(wsl_discovery_stale)
            )
            info["wslOperational"] = bool(ready and not error)
            info["wslDiscoveryPending"] = pending
            info["wslDiscoveryStale"] = stale
            if error:
                info["wslDiscoveryError"] = str(error)
    info.setdefault("os", "windows" if IS_WINDOWS else "macos")
    info.setdefault("arch", platform.machine().lower())
    info.setdefault("shells", ["auto", "cmd", "powershell"]
                    if IS_WINDOWS else ["posix"])
    info.setdefault("packaged", bool(getattr(sys, "frozen", False)))
    info.setdefault("wslDistros", [])
    return info


def get_wsl_manager():
    """Return the process-wide host manager without probing or starting WSL."""
    global _WSL_MANAGER
    if not IS_WINDOWS:
        return None
    with _WSL_MANAGER_LOCK:
        if _WSL_MANAGER is None:
            from console_platform.wsl_host import WSLHostManager
            _WSL_MANAGER = WSLHostManager(BASE_DIR, DATA_DIR)
        return _WSL_MANAGER


def classify_task_exit(code):
    """把一次性任务的退出码归一为稳定的产品语义。"""
    if code == 0:
        return "succeeded"
    if code == TASK_CANCELED_EXIT_CODE:
        return "canceled"
    return "failed"


def public_last_exit(app):
    """兼容旧配置：只在 API 输出时补齐任务状态，不改写磁盘。"""
    value = app.get("lastExit")
    if not isinstance(value, dict):
        return value
    result = dict(value)
    if (app.get("kind") or "service") == "task":
        # 旧版把“总控台按钮停止”记作 canceled + null；新协议中它是 stopped。
        if result.get("status") == "canceled" and result.get("code") is None:
            result["status"] = "stopped"
        elif (result.get("status") not in
              {"succeeded", "canceled", "failed", "stopped"}
              and isinstance(result.get("code"), int)):
            result["status"] = classify_task_exit(result["code"])
    return result


STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".otf": "font/otf",
    ".woff2": "font/woff2",
}

PLACEHOLDER_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>总控台</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f7;color:#1d1d1f}
.card{background:#fff;border:1px solid rgba(0,0,0,.06);border-radius:14px;padding:36px 44px;box-shadow:0 8px 30px rgba(0,0,0,.08);max-width:540px;text-align:center}
h1{font-size:20px;margin:0 0 14px}p{color:#6e6e73;font-size:14px;line-height:1.8;margin:6px 0}
code{background:#f5f5f7;border:1px solid rgba(0,0,0,.05);border-radius:6px;padding:2px 7px;font-family:ui-monospace,Menlo,monospace;font-size:13px}
</style></head>
<body><div class="card">
<h1>🖥 总控台后端运行中</h1>
<p>前端文件 <code>static/index.html</code> 尚未提供，界面暂不可用。</p>
<p>API 已就绪：<code>GET /api/state</code></p>
</div></body></html>"""

APP_ROUTE_RE = re.compile(
    r"^/api/apps/([0-9a-fA-F]{8})(?:/(start|stop|restart|icon|logs|favicon|diagnose|attach))?$")


# ---------------------------------------------------------------- 运行目录

def _ensure_private_dir(path):
    if os.path.islink(path):
        raise OSError("私有运行目录不能是符号链接: %s" % path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.path.islink(path) or not os.path.isdir(path):
        raise OSError("私有运行路径不是安全目录: %s" % path)
    try:
        if not IS_WINDOWS:
            os.chmod(path, 0o700)
        else:
            from console_platform.windows_security import secure_private_path
            secure_private_path(path, directory=True)
    except OSError:
        LOG.warning("无法收紧目录权限: %s", path)


def _copy_private_regular_file(source, target):
    """不跟随符号链接地复制普通文件，目标权限固定为 0600。"""
    try:
        source_stat = os.lstat(source)
    except OSError:
        return False
    if not stat.S_ISREG(source_stat.st_mode):
        return False
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, source_flags)
    try:
        target_fd = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(os.dup(source_fd), "rb") as src, \
                    os.fdopen(target_fd, "wb") as dst:
                target_fd = -1
                shutil.copyfileobj(src, dst, length=1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
        finally:
            if target_fd >= 0:
                os.close(target_fd)
    finally:
        os.close(source_fd)
    if not IS_WINDOWS:
        os.chmod(target, 0o600)
    return True


def _install_migrated_directory(target, populate):
    """在目标不存在时原子安装一份迁移副本。"""
    if os.path.lexists(target):
        return False
    parent = os.path.dirname(target) or "."
    # parent 可能是用户共用的 ~/Library/Application Support，
    # 只确保存在，不擅自改它的现有权限。
    os.makedirs(parent, mode=0o700, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".console-migration-", dir=parent)
    installed = False
    try:
        if not IS_WINDOWS:
            os.chmod(staging, 0o700)
        populate(staging)
        try:
            os.rename(staging, target)
            installed = True
        except OSError as e:
            # 另一个同时启动的实例可能已经完成迁移。
            if not os.path.lexists(target) or e.errno not in (
                    errno.EEXIST, errno.ENOTEMPTY):
                raise
        return installed
    finally:
        if not installed and os.path.isdir(staging):
            shutil.rmtree(staging)


def migrate_legacy_runtime_data(
        data_dir=DATA_DIR, logs_dir=LOGS_DIR,
        legacy_data_dir=LEGACY_DATA_DIR,
        data_overridden=DATA_DIR_OVERRIDDEN,
        logs_overridden=LOGS_DIR_OVERRIDDEN):
    """首次运行时将项目内旧数据复制到 macOS 用户目录。

    只在对应目标完全不存在且没有显式环境变量覆盖时执行。
    旧文件不会被删除或改权限。
    """
    result = {"dataMigrated": False, "logsMigrated": False}
    # Windows always starts with a fresh LOCALAPPDATA configuration.  The
    # repository-local legacy directory belongs to the macOS distribution and
    # must never be imported implicitly.
    if IS_WINDOWS:
        return result
    legacy_data_dir = os.path.abspath(legacy_data_dir)
    data_dir = os.path.abspath(data_dir)
    logs_dir = os.path.abspath(logs_dir)

    if (not data_overridden and data_dir != legacy_data_dir
            and os.path.isdir(legacy_data_dir)
            and not os.path.lexists(data_dir)):
        def populate_data(staging):
            for name in ("config.json", "config.json.bak"):
                _copy_private_regular_file(
                    os.path.join(legacy_data_dir, name),
                    os.path.join(staging, name))
            source_icons = os.path.join(legacy_data_dir, "icons")
            if os.path.isdir(source_icons) and not os.path.islink(source_icons):
                target_icons = os.path.join(staging, "icons")
                os.mkdir(target_icons, 0o700)
                for name in os.listdir(source_icons):
                    if os.path.basename(name) != name:
                        continue
                    _copy_private_regular_file(
                        os.path.join(source_icons, name),
                        os.path.join(target_icons, name))

        result["dataMigrated"] = _install_migrated_directory(
            data_dir, populate_data)

    legacy_logs = os.path.join(legacy_data_dir, "logs")
    if (not logs_overridden and logs_dir != legacy_logs
            and os.path.isdir(legacy_logs) and not os.path.islink(legacy_logs)
            and not os.path.lexists(logs_dir)):
        def populate_logs(staging):
            for name in os.listdir(legacy_logs):
                if os.path.basename(name) != name:
                    continue
                _copy_private_regular_file(
                    os.path.join(legacy_logs, name),
                    os.path.join(staging, name))

        result["logsMigrated"] = _install_migrated_directory(
            logs_dir, populate_logs)
    return result


def prepare_runtime_storage():
    migration = migrate_legacy_runtime_data()
    for private_dir in (DATA_DIR, ICONS_DIR, LOGS_DIR):
        _ensure_private_dir(private_dir)
    for path in (CONFIG_PATH, CONFIG_PATH + ".bak", INSTANCE_LOCK_PATH):
        try:
            if stat.S_ISREG(os.lstat(path).st_mode):
                os.chmod(path, 0o600)
        except OSError:
            pass
    for directory in (ICONS_DIR, LOGS_DIR):
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        os.chmod(entry.path, 0o600)
                except OSError:
                    LOG.warning("无法收紧文件权限: %s", entry.path)
    return migration


def write_private_bytes(path, payload):
    """Atomically write a private user-data file without following a link."""
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if os.path.lexists(path) and os.path.islink(path):
        raise OSError("拒绝写入符号链接: %s" % path)
    fd, tmp = tempfile.mkstemp(prefix=".private-", dir=parent)
    installed = False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if not IS_WINDOWS:
            os.chmod(tmp, 0o600)
        else:
            from console_platform.windows_security import secure_private_path
            secure_private_path(tmp)
        # os.replace replaces a concurrently-created symlink itself; it never
        # opens or truncates the symlink target.
        os.replace(tmp, path)
        installed = True
        if IS_WINDOWS:
            from console_platform.windows_security import secure_private_path
            secure_private_path(path)
    finally:
        if not installed:
            try:
                os.remove(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------- 配置


class ConfigSchemaError(ValueError):
    pass


class FutureConfigSchemaError(ConfigSchemaError):
    pass


def normalize_execution(value, default_shell=None):
    """Validate an execution descriptor and return a canonical copy."""
    default_shell = default_shell or ("auto" if IS_WINDOWS else "posix")
    if value is None:
        value = {"environment": "native", "shell": default_shell,
                 "distro": None}
    if not isinstance(value, dict):
        return None, "execution 必须是 JSON 对象"
    environment = value.get("environment", "native")
    shell = value.get("shell", default_shell)
    distro = value.get("distro")
    if environment not in ("native", "wsl"):
        return None, "execution.environment 必须是 native/wsl"
    if environment == "wsl":
        if not IS_WINDOWS:
            return None, "当前平台不支持 WSL 执行环境"
        if shell != "posix":
            return None, "WSL 执行环境必须使用 posix shell"
        if not isinstance(distro, str) or not distro.strip():
            return None, "WSL 执行环境必须指定发行版"
        try:
            from console_platform.wsl import validate_distro_name
            distro = validate_distro_name(distro)
        except (TypeError, ValueError):
            return None, "WSL 发行版名称无效"
        return {"environment": "wsl", "shell": "posix",
                "distro": distro}, None
    allowed = {"posix"} if not IS_WINDOWS else {"auto", "cmd", "powershell"}
    if shell not in allowed:
        return None, "当前平台不支持 shell: %s" % shell
    if distro not in (None, ""):
        return None, "原生执行环境不能指定 WSL 发行版"
    return {"environment": "native", "shell": shell, "distro": None}, None


def migrate_config_v0_to_v1(raw):
    """旧配置没有 schemaVersion；v1 只建立显式版本基线。"""
    migrated = dict(raw)
    migrated["schemaVersion"] = 1
    return migrated


def migrate_config_v1_to_v2(raw):
    """为旧 macOS 卡片补齐显式的原生 POSIX 执行环境。"""
    migrated = dict(raw)
    apps = []
    for item in migrated.get("apps") or []:
        if not isinstance(item, dict):
            apps.append(item)
            continue
        app = dict(item)
        # v1 had no execution contract.  Do not let an incidental/invalid
        # field bypass the explicit legacy macOS migration.
        app["execution"] = {
            "environment": "native", "shell": "posix", "distro": None,
        }
        apps.append(app)
    migrated["apps"] = apps
    migrated["schemaVersion"] = 2
    return migrated


CONFIG_MIGRATIONS = {
    0: migrate_config_v0_to_v1,
    1: migrate_config_v1_to_v2,
}


def migrate_config(raw):
    """将任意已支持的旧 schema 逐版幂等迁移到当前版本。"""
    if not isinstance(raw, dict):
        raise ConfigSchemaError("配置根节点必须是 JSON 对象")
    version = raw.get("schemaVersion", 0)
    if type(version) is not int or version < 0:
        raise ConfigSchemaError("schemaVersion 必须是非负整数")
    if version > CURRENT_SCHEMA_VERSION:
        raise FutureConfigSchemaError(
            "配置 schemaVersion=%d 新于当前程序支持的 %d" %
            (version, CURRENT_SCHEMA_VERSION))
    source_version = version
    migrated = json.loads(json.dumps(raw, ensure_ascii=False))
    while version < CURRENT_SCHEMA_VERSION:
        migration = CONFIG_MIGRATIONS.get(version)
        if migration is None:
            raise ConfigSchemaError("缺少 schemaVersion=%d 的迁移器" % version)
        migrated = migration(migrated)
        next_version = migrated.get("schemaVersion")
        if next_version != version + 1:
            raise ConfigSchemaError("配置迁移器未正确递增 schemaVersion")
        version = next_version
    return migrated, source_version


class Config:
    """配置读写：显式 schema 迁移 + 原子写 + 上一份良好备份。"""

    DEFAULT = {"schemaVersion": CURRENT_SCHEMA_VERSION,
               "apps": [], "hidden": [], "pinned": [], "promoted": [],
               "watchedKeywords": [], "uiTheme": DEFAULT_UI_THEME}
    APP_DEFAULT = {"id": None, "name": "", "command": "", "cwd": None,
                   "port": None, "emoji": None, "glyph": None, "icon": None,
                   "favicon": None, "kind": "service", "lastPid": None,
                   "lastPgid": None, "runToken": None,
                   "execution": None, "instanceKey": None,
                   "processIdentity": None,
                   "attached": False, "lastExit": None, "createdAt": 0}

    def __init__(self, path):
        self._lock = threading.RLock()
        self._path = path
        self._writable = True
        self._recovered_from_backup = False
        self._migration_from = None
        self._health_issues = []
        self._data = self._load()

    @staticmethod
    def _payload(data):
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"

    @classmethod
    def _normalize(cls, raw):
        data = {"schemaVersion": CURRENT_SCHEMA_VERSION}
        for key, default in cls.DEFAULT.items():
            if key == "schemaVersion":
                continue
            value = raw.get(key)
            if isinstance(value, type(default)):
                data[key] = (json.loads(json.dumps(value, ensure_ascii=False))
                             if isinstance(value, (list, dict)) else value)
            else:
                data[key] = list(default) if isinstance(default, list) else default
        apps = []
        for item in data["apps"]:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            app = dict(cls.APP_DEFAULT)
            for key in app:
                if key in item:
                    app[key] = item[key]
            fallback_shell = "auto" if IS_WINDOWS else "posix"
            if "execution" not in item or item.get("execution") is None:
                raise ConfigSchemaError(
                    "应用 %s 缺少 schema v2 execution" % item.get("id"))
            execution, error = normalize_execution(
                app.get("execution"), default_shell=fallback_shell)
            if error:
                raise ConfigSchemaError(
                    "应用 %s execution 无效: %s" % (item.get("id"), error))
            app["execution"] = execution
            apps.append(app)
        data["apps"] = apps
        return data

    def _load(self):
        paths = (self._path, self._path + ".bak")
        found_candidate = False
        for index, path in enumerate(paths):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                migrated, source_version = migrate_config(raw)
                data = self._normalize(migrated)
                if index:
                    self._recovered_from_backup = True
                    LOG.warning("主配置不可读，已从备份恢复: %s", path)
                if source_version < CURRENT_SCHEMA_VERSION:
                    self._migration_from = source_version
                self._persist_loaded_state(
                    data, raw, source_index=index,
                    source_version=source_version)
                return data
            except FileNotFoundError:
                continue
            except FutureConfigSchemaError as e:
                # 回退到旧程序时绝不用旧 .bak 覆盖更新 schema 的主文件。
                found_candidate = True
                self._health_issues.append(str(e))
                LOG.error("拒绝降级读取配置: %s", path)
                break
            except (OSError, UnicodeError, json.JSONDecodeError,
                    ConfigSchemaError, TypeError, ValueError):
                found_candidate = True
                LOG.exception("读取配置失败: %s", path)
        data = self._normalize(self.DEFAULT)
        if found_candidate:
            # 配置和备份都不可用时，展示空状态但禁止写入，
            # 避免一次 UI 操作就把尚可人工恢复的文件覆盖。
            self._writable = False
            self._health_issues.append(
                "主配置与备份均不可读，已进入只读保护状态")
            return data
        try:
            self._write_atomic(self._path, self._payload(data))
        except OSError as e:
            self._writable = False
            self._health_issues.append("无法创建配置文件: %s" % e)
        return data

    def _persist_loaded_state(self, data, raw, source_index, source_version):
        """将已恢复/迁移的配置落回主文件，不破坏良好备份。"""
        needs_migration = source_version < CURRENT_SCHEMA_VERSION
        if not source_index and not needs_migration:
            return
        try:
            if not source_index and needs_migration:
                # 迁移前的配置是上一份良好版本。
                self._write_atomic(self._path + ".bak", self._payload(raw))
            # 从 .bak 恢复时只修复主文件，保留已验证的备份。
            self._write_atomic(self._path, self._payload(data))
        except OSError as e:
            self._writable = False
            self._health_issues.append("配置恢复/迁移落盘失败: %s" % e)
            LOG.exception("配置恢复/迁移落盘失败")

    def snapshot(self):
        """返回配置的深拷贝（数据均为 JSON 可序列化）。"""
        with self._lock:
            return json.loads(json.dumps(self._data, ensure_ascii=False))

    def health_info(self):
        with self._lock:
            return {
                "writable": self._writable,
                "recoveredFromBackup": self._recovered_from_backup,
                "migratedFromSchema": self._migration_from,
                "issues": list(self._health_issues),
            }

    def retain_in_memory(self, fn, issue):
        """Apply an emergency in-memory mutation without claiming it is durable.

        This is reserved for a runtime identity that could neither be written
        to disk nor rolled back.  Keeping the token in the live Config makes
        the process visible and stoppable until storage can be repaired; the
        health issue makes the restart risk explicit.
        """
        with self._lock:
            result = fn(self._data)
            if result:
                message = str(issue or "配置存在仅保留在内存中的运行身份")
                if message not in self._health_issues:
                    self._health_issues.append(message)
                invalidate_state_cache()
            return result

    def update(self, fn):
        """在锁内执行 fn(self._data) 修改配置，随后原子落盘，返回 fn 的返回值。"""
        with self._lock:
            if not self._writable:
                raise OSError("配置处于只读保护状态，请先恢复配置或权限")
            previous = json.loads(json.dumps(self._data, ensure_ascii=False))
            try:
                result = fn(self._data)
                payload = self._payload(self._data)
                previous_payload = self._payload(previous)
                # 先保存上一份良好内容，再替换主文件。
                self._write_atomic(self._path + ".bak", previous_payload)
                self._write_atomic(self._path, payload)
                invalidate_state_cache()
                return result
            except Exception:
                self._data = previous
                raise

    @staticmethod
    def _write_atomic(path, payload):
        _ensure_private_dir(os.path.dirname(path) or ".")
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if IS_WINDOWS:
            from console_platform.windows_security import secure_private_path
            secure_private_path(tmp)
        os.replace(tmp, path)
        if not IS_WINDOWS:
            os.chmod(path, 0o600)
        else:
            from console_platform.windows_security import secure_private_path
            secure_private_path(path)


def acquire_instance_lock(path=INSTANCE_LOCK_PATH):
    """Acquire the per-project process lock and keep its file object alive.

    Port fallback alone is not a single-instance guarantee: two servers on
    :9600/:9601 would still update the same config.  flock ties exclusivity to
    this data directory and is released automatically if the process crashes.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    lock_file = os.fdopen(fd, "r+", encoding="ascii")
    try:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:
            # Lock one persistent byte. Windows locking is released by the OS
            # when the owning process exits, matching flock crash semantics.
            lock_file.seek(0)
            if os.path.getsize(path) == 0:
                lock_file.write("0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:  # pragma: no cover - all supported platforms provide one.
            raise OSError("当前平台不支持实例锁")
    except OSError as e:
        lock_file.close()
        if (e.errno in (errno.EACCES, errno.EAGAIN)
                or getattr(e, "winerror", None) in (32, 33, 36)):
            return None
        raise
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(lock_file.fileno(), 0o600)
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write("%d\n" % SELF_PID)
        lock_file.flush()
        os.fsync(lock_file.fileno())
        if IS_WINDOWS:
            from console_platform.windows_security import secure_private_path
            secure_private_path(path)
    except OSError:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        elif msvcrt is not None:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        lock_file.close()
        raise
    return lock_file


def release_instance_lock(lock_file):
    if lock_file is None:
        return
    try:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        elif msvcrt is not None:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
    finally:
        lock_file.close()


# ---------------------------------------------------------------- 子进程与解析

def run_cmd(args, timeout=SUBPROCESS_TIMEOUT):
    """运行命令并返回 stdout；任何异常/超时都返回空串，绝不上抛。"""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout or ""
    except Exception:
        LOG.exception("命令执行失败: %r", args)
        return ""


def parse_etime(s):
    """ps 的 etime：[[dd-]hh:]mm:ss → 秒。异常返回 0。"""
    try:
        s = s.strip()
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = [int(p) for p in s.split(":")]
        if len(parts) == 2:
            hours, minutes, secs = 0, parts[0], parts[1]
        elif len(parts) == 3:
            hours, minutes, secs = parts
        else:
            return 0
        return days * 86400 + hours * 3600 + minutes * 60 + secs
    except Exception:
        return 0


def _to_float(tok, default=0.0):
    try:
        return float(tok)
    except (TypeError, ValueError):
        return default


def _native_adapter():
    try:
        from console_platform import get_adapter
        return get_adapter()
    except Exception:
        return None


def scan_listeners():
    """lsof 监听快照 → {(pid, port): {bind_host, ...}}。

    字典仍可像旧集合一样迭代/判断 ``(pid, port)``，同时保留监听地址，
    供前端区分仅监听 ``::1`` 的服务（需通过 localhost 打开）。
    """
    if IS_WINDOWS:
        adapter = _native_adapter()
        if adapter is not None:
            try:
                return adapter.scan_listeners()
            except Exception:
                LOG.exception("Windows 端口扫描失败")
        return {}
    out = run_cmd(["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"])
    found = {}
    for line in out.splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        # NAME 列形如 *:8791 / 127.0.0.1:8080 / [::1]:8765，末尾可能跟 "(LISTEN)"
        port = None
        bind_host = None
        for tok in reversed(parts):
            m = re.search(r":(\d+)$", tok)
            if m:
                port = int(m.group(1))
                bind_host = tok[:m.start()]
                if bind_host.startswith("[") and bind_host.endswith("]"):
                    bind_host = bind_host[1:-1]
                break
        if port is None:
            continue
        found.setdefault((pid, port), set()).add(bind_host or "")
    return found


def listener_open_host(listeners, port, pids=None):
    """返回浏览器访问监听端口时应使用的本地主机名。

    macOS 上有些开发服务器只绑定 IPv6 回环 ``::1``；这时
    ``127.0.0.1`` 会直接拒绝连接，而 ``localhost`` 能正确解析到它。
    对旧测试/旧调用传入的 set 快照则保持原来的 IPv4 默认值。
    """
    if not isinstance(listeners, dict):
        return "127.0.0.1"
    allowed_pids = set(pids) if pids is not None else None
    hosts = set()
    for (pid, listening_port), values in listeners.items():
        if listening_port != port or (
                allowed_pids is not None and pid not in allowed_pids):
            continue
        if isinstance(values, str):
            hosts.add(values)
        elif isinstance(values, (set, list, tuple)):
            hosts.update(value for value in values if isinstance(value, str))
    normalized = {host.strip("[]").casefold() for host in hosts if host}
    ipv4_capable = any(
        host in ("*", "0.0.0.0") or host.startswith("127.")
        for host in normalized)
    ipv6_loopback_only = bool(normalized) and not ipv4_capable and all(
        host in ("::", "::1", "localhost") for host in normalized)
    return "localhost" if ipv6_loopback_only else "127.0.0.1"


def ps_snapshot(pids=None, with_uid=True):
    """批量进程信息 → {pid: {"uid","comm","args","cpu","mem","etime"}}。

    pids=None 表示全部进程（ps -ax）。解析：左边固定列 pid[/uid]/etime/cpu/mem，
    其余部分（可含空格）即 comm；args 单独一次 ps 取。
    注意：不能用 `comm=` 抑制表头——macOS ps 会把空表头列压到 16 字节截断
    内容；保留表头后解析时跳过表头行即可（首列非数字的行）。
    """
    if IS_WINDOWS:
        adapter = _native_adapter()
        if adapter is not None:
            try:
                return adapter.process_snapshot(
                    pids, with_identity=with_uid)
            except Exception:
                LOG.exception("Windows 进程快照失败")
        return {}
    base = ["ps"]
    if pids is None:
        base.append("-ax")
    else:
        pids = [int(p) for p in pids]
        if not pids:
            return {}
        base += ["-p", ",".join(str(p) for p in pids)]
    # comm 必须放在最后一列：macOS ps 只保证最后一列不被定宽截断
    # （comm 在中间列时会被压成约 16 字节，长路径被砍断）。
    fields = ["pid"] + (["uid"] if with_uid else []) + \
             ["etime", "%cpu", "%mem", "comm"]
    out1 = run_cmd(base + ["-o", ",".join(fields)])
    out2 = run_cmd(base + ["-o", "pid,args"])

    snap = {}
    fixed = 5 if with_uid else 4  # pid [uid] etime cpu mem 之后的都是 comm
    for line in out1.splitlines():
        toks = line.split()
        if len(toks) < fixed + 1:
            continue
        try:
            pid = int(toks[0])
        except ValueError:
            continue  # 表头行
        i = 1
        entry = {"args": ""}
        if with_uid:
            try:
                entry["uid"] = int(toks[1])
            except ValueError:
                entry["uid"] = -1
            i = 2
        entry["etime"] = parse_etime(toks[i])
        entry["cpu"] = _to_float(toks[i + 1])
        entry["mem"] = _to_float(toks[i + 2])
        entry["comm"] = " ".join(toks[i + 3:])
        snap[pid] = entry
    for line in out2.splitlines():
        toks = line.split(None, 1)
        if not toks:
            continue
        try:
            pid = int(toks[0])
        except ValueError:
            continue
        if pid in snap:
            snap[pid]["args"] = toks[1] if len(toks) > 1 else ""
    return snap


def lsof_cwds(pids):
    """lsof -a -p <pids> -d cwd -Fn → {pid: cwd}。"""
    pids = [int(p) for p in pids]
    if IS_WINDOWS:
        adapter = _native_adapter()
        if adapter is not None:
            try:
                return adapter.process_cwds(pids)
            except Exception:
                LOG.exception("Windows cwd 快照失败")
        return {}
    if not pids:
        return {}
    out = run_cmd(["lsof", "-a", "-p", ",".join(str(p) for p in pids),
                   "-d", "cwd", "-Fn"])
    result = {}
    cur = None
    for line in out.splitlines():
        if line.startswith("p"):
            try:
                cur = int(line[1:])
            except ValueError:
                cur = None
        elif line.startswith("n") and cur is not None:
            result[cur] = line[1:]
    return result


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True
    except (OSError, ValueError, TypeError):
        return False


# ---------------------------------------------------------------- 状态构建

SYSTEM_PATH_PREFIXES = ("/usr/libexec/", "/usr/sbin/", "/sbin/", "/System/", "/usr/lib/")

# 开发服务关键词：命中 name/args 时优先归为 "mine"（覆盖 .app 规则，
# 例如 ollama 守护进程在 Ollama.app 内、Docker 在 Docker.app 内）
DEV_KEYWORDS = (
    "python", "node", "ruby", "php", "nginx", "caddy", "postgres",
    "mysql", "redis", "mongo", "ollama", "docker", "deno", "bun",
    "uvicorn", "gunicorn", "hugo", "vite", "streamlit", "jupyter",
    "ngrok", "frp", "code-server", "java",
)


def classify_group(key, name, comm, args, cwd, promoted):
    if key in promoted:
        return "mine"
    text = name.lower()
    if any(k in text for k in DEV_KEYWORDS):
        return "mine"
    if ".app/Contents/" in comm or ".app/Contents/" in args:
        return "background"
    if comm.startswith(SYSTEM_PATH_PREFIXES):
        return "background"
    if "/Library/Containers/" in comm or "/Library/Containers/" in (cwd or ""):
        return "background"
    return "mine"


HOME_DIR = os.path.expanduser("~")


def project_name(cwd):
    """从工作目录推断项目名（最后一段目录名），无有效 cwd 时返回 None。"""
    if not cwd:
        return None
    cwd = cwd.rstrip("/")
    if not cwd or cwd == "/" or cwd == HOME_DIR:
        return None
    return os.path.basename(cwd) or None


# ---------------------------------------------------------------- 进程溯源
# 沿 PPID 链向上识别「是谁启动了这个服务」：AI 编程助手、编辑器、终端、
# 总控台自身或 launchd。结果只是展示用的尽力判断，不影响任何启停逻辑。

# 向上爬时要跳过的包装层（按 argv[0] 基名匹配）：壳、包管理器与任务执行器
_ORIGIN_SKIP_NAMES = {
    "zsh", "bash", "sh", "dash", "fish", "login", "su", "sudo", "env",
    "command", "xargs", "nohup", "setsid", "script", "expect", "caffeinate",
    "launchd",
    "npm", "npx", "pnpm", "yarn", "corepack", "make", "just",
    "node", "tsx", "nodemon", "deno", "bun", "bunx",
    "python", "python3", "uv", "poetry", "pip", "pipx",
    "ruby", "php", "java", "dotnet", "go", "cargo",
}

# 已知 AI 编程助手签名（在祖先 args 中做词边界匹配，按顺序取先命中者）
_ORIGIN_AGENT_PATTERNS = (
    (re.compile(r"\bcodex\b", re.I), "Codex"),
    (re.compile(r"claude-code|\bclaude\b", re.I), "Claude Code"),
    (re.compile(r"\bkimi\b", re.I), "Kimi"),
    (re.compile(r"\bgemini\b", re.I), "Gemini"),
    (re.compile(r"\baider\b", re.I), "Aider"),
    (re.compile(r"\bopencode\b", re.I), "OpenCode"),
    (re.compile(r"\bgoose\b", re.I), "Goose"),
    (re.compile(r"\bcursor-agent\b", re.I), "Cursor"),
    (re.compile(r"\bcopilot\b", re.I), "Copilot"),
    (re.compile(r"\bqwen\b", re.I), "Qwen"),
    (re.compile(r"\bqoder\b", re.I), "Qoder"),
    (re.compile(r"\bamp\b", re.I), "Amp"),
    (re.compile(r"\bcodebuddy\b", re.I), "CodeBuddy"),
)

# .app 包名 → (展示名, 图标)。未列出的包按原名 + package 图标展示
_ORIGIN_APP_ALIASES = {
    "visual studio code": ("VS Code", "code"),
    "visual studio code - insiders": ("VS Code", "code"),
    "cursor": ("Cursor", "code"),
    "trae": ("Trae", "code"),
    "windsurf": ("Windsurf", "code"),
    "zed": ("Zed", "code"),
    "sublime text": ("Sublime", "code"),
    "webstorm": ("WebStorm", "code"),
    "intellij idea": ("IDEA", "code"),
    "goland": ("GoLand", "code"),
    "pycharm": ("PyCharm", "code"),
    "nova": ("Nova", "code"),
    "xcode": ("Xcode", "code"),
    "iterm2": ("iTerm", "terminal"),
    "iterm": ("iTerm", "terminal"),
    "terminal": ("终端", "terminal"),
    "warp": ("Warp", "terminal"),
    "kitty": ("kitty", "terminal"),
    "alacritty": ("Alacritty", "terminal"),
    "wezterm": ("WezTerm", "terminal"),
    "docker": ("Docker", "package"),
    "ollama": ("Ollama", "package"),
    "obsidian": ("Obsidian", "package"),
}
_ORIGIN_BUNDLE_RE = re.compile(r"/([^/]+)\.app/Contents/MacOS/", re.I)

# 终端复用器（直接以 comm 命名，不进跳过表）
_ORIGIN_MULTIPLEXERS = {"tmux": "tmux", "screen": "screen"}
_ORIGIN_WINDOWS_APPS = {
    "code": ("VS Code", "code"),
    "code-insiders": ("VS Code", "code"),
    "cursor": ("Cursor", "code"),
    "windsurf": ("Windsurf", "code"),
    "windowsterminal": ("Windows Terminal", "terminal"),
    "microsoft.windowsterminal": ("Windows Terminal", "terminal"),
    "wt": ("Windows Terminal", "terminal"),
    "cmd": ("CMD", "terminal"),
    "powershell": ("PowerShell", "terminal"),
    "pwsh": ("PowerShell", "terminal"),
}


def origin_snapshot(pids=None):
    """ps -axo pid=,ppid=,args → {pid: (ppid, args)}，供来源溯源。"""
    if IS_WINDOWS:
        adapter = _native_adapter()
        if pids is not None and adapter is not None and hasattr(
                adapter, "process_lineage"):
            return adapter.process_lineage(pids, max_depth=12)
        return {
            pid: (int(info.get("ppid") or 0), info.get("args") or "")
            for pid, info in ps_snapshot(None, with_uid=False).items()
        }
    table = {}
    for line in run_cmd(["ps", "-axo", "pid=,ppid=,args"]).splitlines():
        toks = line.split(None, 2)
        if len(toks) < 2:
            continue
        try:
            pid, ppid = int(toks[0]), int(toks[1])
        except ValueError:
            continue
        table[pid] = (ppid, toks[2] if len(toks) > 2 else "")
    return table


def attribute_origin(pid, table):
    """沿 PPID 链识别来源应用，返回 {"label", "icon"} 或 None。

    祖先 args 中带有总控台 run-token 前缀（console-run:）即判定为
    「总控台启动」——本机任一总控台实例的受管进程组都持有该标记。
    未识别的中间层先记为候选并继续上爬；AI 助手 / 编辑器 / 终端 /
    总控台 / launchd 是更优答案，都没有时才以最近的未识别进程命名。
    最多上爬 12 层，遇到环或缺失即终止。
    """
    cur, seen, candidate = pid, set(), None
    for _ in range(12):
        entry = table.get(cur)
        if not entry:
            break
        ppid, _ = entry
        if ppid in seen:
            break
        seen.add(ppid)
        parent_args = (table.get(ppid) or (0, ""))[1] or ""
        if ppid <= 1:
            return candidate or {"label": "系统", "icon": "server"}
        if RUN_TOKEN_ARG_PREFIX in parent_args:
            return {"label": "总控台", "icon": "rocket"}
        hay = parent_args.casefold()
        for pattern, label in _ORIGIN_AGENT_PATTERNS:
            if pattern.search(hay):
                return {"label": label, "icon": "bot"}
        bundle = _ORIGIN_BUNDLE_RE.search(parent_args)
        if bundle:
            app_name = bundle.group(1)
            label, icon = _ORIGIN_APP_ALIASES.get(
                app_name.casefold(), (app_name, "package"))
            return {"label": label, "icon": icon}
        from console_platform.common import first_command_token
        first = first_command_token(parent_args)
        # ntpath handles a quoted Windows executable even while the macOS test
        # suite exercises this pure attribution function.
        path_module = ntpath if re.match(r"^[A-Za-z]:[\\/]", first) else os.path
        base = path_module.basename(first).lstrip("-") if first else ""
        base = os.path.splitext(base.strip('"'))[0].casefold()
        if base in _ORIGIN_WINDOWS_APPS:
            label, icon = _ORIGIN_WINDOWS_APPS[base]
            return {"label": label, "icon": icon}
        if base in _ORIGIN_MULTIPLEXERS:
            return {"label": _ORIGIN_MULTIPLEXERS[base], "icon": "terminal"}
        if base and base not in _ORIGIN_SKIP_NAMES and candidate is None:
            candidate = {"label": base, "icon": "package"}
        cur = ppid
    return candidate


def build_services(cfg, groups=None):
    """返回 (services, listeners)。只含当前用户进程，排除控制台自身。"""
    listeners = scan_listeners()
    snap = ps_snapshot({pid for pid, _ in listeners}, with_uid=True)
    mine_pids = [pid for pid, _ in listeners
                 if pid != SELF_PID and pid in snap
                 and snap[pid].get("uid") == SELF_UID]
    cwds = lsof_cwds(mine_pids)
    origin_table = origin_snapshot(mine_pids)

    hidden = set(cfg.get("hidden") or [])
    pinned = set(cfg.get("pinned") or [])
    promoted = set(cfg.get("promoted") or [])
    # “配置了相同端口”不代表“拥有当前监听进程”。只有 run token / 进程组
    # 校验通过（或严格命中旧版身份）的进程才关联启动台卡片。
    app_by_pid = listener_app_owners(
        cfg.get("apps") or [], listeners, snap, cwds, groups)

    services = []
    for pid, port in sorted(listeners, key=lambda x: (x[1], x[0])):
        if pid == SELF_PID:
            continue
        info = snap.get(pid)
        if not info or info.get("uid") != SELF_UID:
            continue
        comm = info.get("comm") or ""
        args = info.get("args") or comm
        name = os.path.basename(comm) if comm else "?"
        key = "%s:%d" % (name, port)
        cwd = cwds.get(pid)
        app = app_by_pid.get(pid)
        create_time = info.get("create_time")
        instance_key = (
            make_instance_key(
                "native", pid, create_time, port=port,
                identity=info.get("identity"), cwd=cwd, command=args)
            if IS_WINDOWS and create_time else "%d:%d" % (pid, port)
        )
        services.append({
            "key": key,
            # key 保持 name:port 以兼容既有隐藏/置顶配置；instanceKey 用于
            # 区分同名同端口在不同时间出现的新进程，以及极少数共享监听。
            "instanceKey": instance_key,
            "pid": pid, "name": name, "port": port,
            "openHost": listener_open_host(listeners, port, {pid}),
            "cwd": cwd, "project": project_name(cwd), "cmd": args,
            "cpu": info["cpu"], "mem": info["mem"], "uptimeSec": info["etime"],
            "group": classify_group(key, name, comm, args, cwd, promoted),
            "pinned": key in pinned, "hidden": key in hidden,
            "promoted": key in promoted,
            "appId": app["id"] if app else None,
            "appName": app["name"] if app else None,
            # 来源溯源（尽力判断）：哪个应用/AI 助手启动了这个进程
            "origin": attribute_origin(pid, origin_table),
            "execution": {
                "environment": "native",
                "shell": "auto" if IS_WINDOWS else "posix",
                "distro": None,
            },
        })
    return services, listeners


def build_wsl_services(cfg, scans=None, discovered_distros=None):
    """Build monitor rows for all running WSL2 distros independently."""
    if not IS_WINDOWS:
        return [], [], []
    if scans is None:
        manager = get_wsl_manager()
        scans, errors = (
            manager.scan_running(discovered_distros)
            if manager else ([], [])
        )
    else:
        errors = []
    hidden = set(cfg.get("hidden") or [])
    pinned = set(cfg.get("pinned") or [])
    promoted = set(cfg.get("promoted") or [])
    services = []
    for scan in scans:
        distro = scan.get("distro")
        boot_id = scan.get("bootId")
        try:
            current_uid = int(scan.get("uid"))
        except (TypeError, ValueError):
            continue
        process_items = scan.get("processes") or []
        process_map = {}
        origin_table = {}
        for item in process_items:
            if not isinstance(item, dict):
                continue
            try:
                pid = int(item.get("pid"))
                ppid = int(item.get("ppid") or 0)
            except (TypeError, ValueError):
                continue
            process_map[pid] = item
            origin_table[pid] = (ppid, str(item.get("args") or ""))
        cwds = scan.get("cwds") or {}
        preferred = scan.get("preferredAddress")
        for listener in scan.get("listeners") or []:
            if not isinstance(listener, dict):
                continue
            try:
                pid = int(listener.get("pid"))
                port = int(listener.get("port"))
            except (TypeError, ValueError):
                continue
            info = process_map.get(pid)
            if not info:
                continue
            try:
                uid = int(info.get("uid"))
            except (TypeError, ValueError):
                continue
            if uid != current_uid:
                continue
            comm = str(info.get("comm") or "")
            args = str(info.get("args") or comm)
            name = os.path.basename(comm) or "?"
            cwd = (info.get("cwd") or cwds.get(str(pid))
                   or cwds.get(pid))
            key = "wsl:%s:%s:%d" % (distro, name, port)
            create_time = info.get("startTicks", info.get("create_time"))
            instance_key = make_instance_key(
                "wsl", pid, create_time, distro=distro,
                boot_id=boot_id, port=port, identity=uid,
                cwd=cwd, command=args,
                cwd_hash=info.get("cwdHash"),
                command_hash=info.get("commandHash"))
            origin = attribute_origin(pid, origin_table)
            if origin:
                origin = dict(origin)
                origin["label"] = "%s · %s" % (distro, origin["label"])
            else:
                origin = {"label": "WSL · %s" % distro,
                          "icon": "terminal"}
            services.append({
                "key": key,
                "instanceKey": instance_key,
                "pid": pid,
                "name": name,
                "port": port,
                "openHost": "localhost",
                "fallbackHost": preferred,
                "cwd": cwd,
                "project": project_name(cwd),
                "cmd": args,
                "cpu": float(info.get("cpu") or 0.0),
                "mem": float(info.get("mem") or 0.0),
                "uptimeSec": max(0, int(info.get("etime") or 0)),
                "group": classify_group(
                    key, name, comm, args, cwd, promoted),
                "pinned": key in pinned,
                "hidden": key in hidden,
                "promoted": key in promoted,
                "appId": None,
                "appName": None,
                "origin": origin,
                "execution": {"environment": "wsl", "shell": "posix",
                              "distro": distro},
                "distro": distro,
                "bootId": boot_id,
            })
    services.sort(key=lambda row: (
        row.get("distro", "").casefold(), row["port"], row["pid"]))
    return services, scans, errors


def build_watched(keywords):
    """关注进程：每个 PID 只返回一次，并合并它命中的全部关键字。"""
    normalized = []
    seen_keywords = set()
    for keyword in (keywords or []):
        if not isinstance(keyword, str) or not keyword.strip():
            continue
        keyword = keyword.strip()
        lowered = keyword.casefold()
        if lowered in seen_keywords:
            continue
        seen_keywords.add(lowered)
        normalized.append((keyword, lowered))
    if not normalized:
        return []
    snap = ps_snapshot(None, with_uid=True)
    result = []
    for pid, info in sorted(snap.items()):
        if pid == SELF_PID or info.get("uid") != SELF_UID:
            continue
        name = os.path.basename(info.get("comm") or "") or "?"
        if name in ("ps", "lsof"):
            continue
        args = info.get("args") or ""
        args_lower = args.casefold()
        matched = [keyword for keyword, lowered in normalized
                   if lowered in args_lower]
        if not matched:
            continue
        result.append({"pid": pid, "name": name, "cmd": args,
                       "cpu": info["cpu"], "mem": info["mem"],
                       "uptimeSec": info["etime"],
                       # keyword 保留给旧前端，keywords 提供无损结构化数据。
                       "keyword": "、".join(matched), "keywords": matched})
    if IS_WINDOWS and result:
        cwds = lsof_cwds([row["pid"] for row in result])
        for row in result:
            info = snap.get(row["pid"]) or {}
            create_time = info.get("create_time")
            # Destructive Windows operations fail closed unless an exact SID
            # and creation time can be represented in the signed identity.
            if create_time and info.get("identity_kind") == "sid":
                row["instanceKey"] = make_instance_key(
                    "native", row["pid"], create_time,
                    identity=info.get("identity"),
                    cwd=cwds.get(row["pid"]), command=row["cmd"])
    return result


_WINDOWS_WATCH_LOCK = threading.RLock()
_WINDOWS_WATCH_THREAD = None
_WINDOWS_WATCH_DESIRED = ()
_WINDOWS_WATCH_CACHE_KEY = ()
_WINDOWS_WATCH_CACHE = []
_WINDOWS_WATCH_LAST_SCAN = 0.0
_WINDOWS_WATCH_REFRESH_SEC = 2.0


def _watch_keyword_key(keywords):
    result = []
    seen = set()
    for value in keywords or []:
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        lowered = value.casefold()
        if lowered in seen:
            continue
        seen.add(lowered)
        result.append(value)
    return tuple(result)


def _windows_watch_worker(keyword_key):
    global _WINDOWS_WATCH_THREAD, _WINDOWS_WATCH_CACHE
    global _WINDOWS_WATCH_CACHE_KEY, _WINDOWS_WATCH_LAST_SCAN
    try:
        rows = build_watched(keyword_key)
    except Exception:
        LOG.exception("构建 Windows 关注进程快照失败")
        rows = None
    with _WINDOWS_WATCH_LOCK:
        if rows is not None and keyword_key == _WINDOWS_WATCH_DESIRED:
            _WINDOWS_WATCH_CACHE = [dict(row) for row in rows]
            _WINDOWS_WATCH_CACHE_KEY = keyword_key
        _WINDOWS_WATCH_LAST_SCAN = time.monotonic()
        _WINDOWS_WATCH_THREAD = None


def windows_watched_snapshot(keywords):
    """Return the latest Windows watch scan without blocking ``/api/state``.

    Reading command lines for every Windows process can take several seconds
    on a busy machine.  A single daemon worker refreshes that optional view;
    2-second state polling keeps returning the last complete snapshot and
    never stacks duplicate global scans.
    """
    global _WINDOWS_WATCH_THREAD, _WINDOWS_WATCH_DESIRED
    global _WINDOWS_WATCH_CACHE, _WINDOWS_WATCH_CACHE_KEY
    keyword_key = _watch_keyword_key(keywords)
    with _WINDOWS_WATCH_LOCK:
        _WINDOWS_WATCH_DESIRED = keyword_key
        if not keyword_key:
            _WINDOWS_WATCH_CACHE = []
            _WINDOWS_WATCH_CACHE_KEY = ()
            return []
        if _WINDOWS_WATCH_CACHE_KEY != keyword_key:
            _WINDOWS_WATCH_CACHE = []
        due = (time.monotonic() - _WINDOWS_WATCH_LAST_SCAN
               >= _WINDOWS_WATCH_REFRESH_SEC)
        if _WINDOWS_WATCH_THREAD is None and (
                _WINDOWS_WATCH_CACHE_KEY != keyword_key or due):
            _WINDOWS_WATCH_THREAD = threading.Thread(
                target=_windows_watch_worker,
                args=(keyword_key,),
                name="windows-watched-scan",
                daemon=True,
            )
            _WINDOWS_WATCH_THREAD.start()
        return [dict(row) for row in _WINDOWS_WATCH_CACHE]


def pgid_members_map():
    """ps -axo pid=,pgid= → {pgid: [pid, ...]}。
    进程退出后其子孙仍保留原 pgid（被 launchd 收养也不变），
    因此按 pgid 能找到「脚本把服务放后台后自己退出」的存活成员。"""
    if IS_WINDOWS:
        snap = ps_snapshot(None, with_uid=True)
        children = {}
        for pid, info in snap.items():
            ppid = info.get("ppid")
            if isinstance(ppid, int):
                children.setdefault(ppid, []).append(pid)
        groups = {}
        for root in snap:
            found, stack = [], [root]
            while stack:
                current = stack.pop()
                if current in found:
                    continue
                found.append(current)
                stack.extend(children.get(current, []))
            groups[root] = found
        return groups
    groups = {}
    for line in run_cmd(["ps", "-axo", "pid=,pgid="]).splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pid, pgid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        groups.setdefault(pgid, []).append(pid)
    return groups


def _managed_candidates(app, groups):
    token = app.get("runToken")
    pgid = app.get("lastPgid") or app.get("lastPid")
    if not isinstance(token, str) or not token or not isinstance(pgid, int) or pgid <= 0:
        return set()
    return set(groups.get(pgid, []))


def supervisor_runtime_status(app):
    """Reclaim and authenticate an app's immutable supervisor metadata."""
    identity = app.get("processIdentity")
    token = app.get("runToken")
    if (not isinstance(identity, dict)
            or identity.get("type") != "supervisor"
            or not isinstance(token, str) or len(token) < 32):
        return None
    run_id = identity.get("runId")
    metadata_file = identity.get("metadataPath")
    try:
        from supervisor_client import load_metadata, metadata_path, reclaim_supervisor
        expected_path = metadata_path(DATA_DIR, run_id)
        if (not isinstance(metadata_file, str)
                or os.path.normcase(os.path.abspath(metadata_file))
                != os.path.normcase(os.path.abspath(expected_path))):
            return {"ok": False, "identityMismatch": True,
                    "error": "supervisor 元数据路径无效"}
        expected = {
            "runId": run_id,
            "environment": identity.get("environment"),
            "distro": identity.get("distro"),
            "bootId": identity.get("bootId"),
        }
        status = reclaim_supervisor(
            expected_path, token, expected=expected, timeout=3.0)
        if status.get("ok"):
            return status
        # A completed supervisor closes its pipe after atomically persisting
        # the final state.  That final file is authoritative only after its
        # token hash and immutable fields were checked by reclaim_supervisor;
        # re-run the local structural comparisons before exposing it.
        metadata = load_metadata(expected_path)
        metadata_wsl = (metadata or {}).get("wsl") or {}
        boot_matches = (
            identity.get("environment") != "wsl"
            or metadata_wsl.get("bootId") == identity.get("bootId")
        )
        if (metadata and metadata.get("state") in SUPERVISOR_TERMINAL_STATES
                and metadata.get("runId") == run_id
                and metadata.get("environment") == identity.get("environment")
                and metadata.get("distro") == identity.get("distro")
                and boot_matches):
            import hashlib as _hashlib
            if hmac.compare_digest(
                    str(metadata.get("tokenHash") or ""),
                    _hashlib.sha256(token.encode("utf-8")).hexdigest()):
                return {"ok": True, **metadata, "running": False}
        return status
    except Exception as exc:
        return {"ok": False, "error": str(exc), "stale": True}


def runtime_last_exit(app, status=None):
    stored = public_last_exit(app)
    identity = app.get("processIdentity") or {}
    if not IS_WINDOWS or identity.get("type") != "supervisor":
        return stored
    status = status or supervisor_runtime_status(app) or {}
    if not status.get("ok") or status.get("running"):
        return stored
    code = status.get("exitCode")
    wsl_status = status.get("wslStatus") or (status.get("wsl") or {}).get("lastStatus") or {}
    wsl_exit = wsl_status.get("exit") or {}
    if not isinstance(code, int):
        code = wsl_exit.get("code") if isinstance(wsl_exit.get("code"), int) else None
    ended = (wsl_exit.get("at") or status.get("updatedAt") or time.time())
    started = status.get("createTime")
    value = {"code": code, "at": int(float(ended))}
    if started:
        value["startedAt"] = int(float(started) * 1000)
        value["durationSec"] = round(max(0.0, float(ended) - float(started)), 3)
    if (status.get("state") in SUPERVISOR_IDENTITY_LOSS_STATES
            and not isinstance(code, int)):
        code = 1
        value["code"] = code
    if (app.get("kind") or "service") == "task":
        value["status"] = (wsl_exit.get("status")
                           if wsl_exit.get("status") in
                           {"succeeded", "canceled", "failed", "stopped"}
                           else classify_task_exit(code if isinstance(code, int) else 1))
    return value


def _native_supervisor_job_processes(app, status):
    """Return structurally valid identities from an authenticated live status.

    ``supervisor_runtime_status`` only returns a running status after the
    supervisor client has authenticated the live response.  Bare
    ``jobProcessIds`` remain diagnostic; authorization/state uses the signed
    per-member create-time and SID records exclusively.
    """
    identity = app.get("processIdentity") or {}
    if (not isinstance(status, dict) or not status.get("ok")
            or not status.get("running")
            or status.get("environment") != "native"
            or status.get("runId") != identity.get("runId")):
        return {}
    owner_sid = status.get("ownerSid")
    if (not isinstance(owner_sid, str) or not owner_sid
            or (identity.get("ownerSid") is not None
                and str(identity.get("ownerSid")).casefold()
                != owner_sid.casefold())):
        return {}
    items = status.get("jobProcesses")
    if not isinstance(items, list):
        return {}
    result = {}
    duplicates = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        pid = item.get("pid")
        create_time = item.get("createTime")
        member_owner = item.get("ownerSid")
        if (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
                or create_time is None or not isinstance(member_owner, str)
                or member_owner.casefold() != owner_sid.casefold()):
            continue
        if pid in result:
            duplicates.add(pid)
            continue
        result[pid] = {
            "pid": pid,
            "createTime": create_time,
            "ownerSid": member_owner,
        }
    for pid in duplicates:
        result.pop(pid, None)
    return result


def _current_windows_sid():
    try:
        adapter = _native_adapter()
        identity = adapter.current_user_identity() if adapter else None
    except Exception:
        return None
    if identity is None or identity.kind != "sid" or not identity.value:
        return None
    return str(identity.value)


def managed_process_index(apps, groups=None):
    """批量校验应用的受控进程，返回 (appId -> [pid], ps, groups)。

    必须同时满足：属于记录的进程组、属于当前用户、argv 中带本次启动的
    随机 token。即使 PID/PGID 被系统复用，也不会把无关进程当成应用或停止它。
    """
    if IS_WINDOWS:
        if not apps:
            return {}, {}, {}
        candidates = {}
        all_pids = set()
        for app in apps:
            identity = app.get("processIdentity") or {}
            if (identity.get("type") == "supervisor"
                    and identity.get("environment") == "native"):
                status = supervisor_runtime_status(app) or {}
                members = _native_supervisor_job_processes(app, status)
            else:
                members = {}
            candidates[app.get("id")] = members
            all_pids.update(members)
        snap = ps_snapshot(all_pids, with_uid=True) if all_pids else {}
        current_sid = _current_windows_sid()
        result = {}
        for app in apps:
            verified = []
            for pid, expected in candidates.get(app.get("id"), {}).items():
                info = snap.get(pid, {})
                if (current_sid is not None
                        and info.get("uid") == SELF_UID
                        and info.get("identity_kind") == "sid"
                        and str(expected.get("ownerSid")).casefold()
                        == current_sid.casefold()
                        and str(info.get("identity") or "").casefold()
                        == current_sid.casefold()
                        and _same_process_time(
                            expected.get("createTime"),
                            info.get("create_time"))):
                    verified.append(pid)
            result[app.get("id")] = sorted(verified)
        return result, snap, {}
    if groups is None:
        needs_groups = any(
            app.get("runToken")
            and isinstance(app.get("lastPgid") or app.get("lastPid"), int)
            for app in apps)
        groups = pgid_members_map() if needs_groups else {}
    candidates = {}
    all_pids = set()
    for app in apps:
        pids = _managed_candidates(app, groups)
        candidates[app.get("id")] = pids
        all_pids.update(pids)
    snap = ps_snapshot(all_pids, with_uid=True) if all_pids else {}
    result = {}
    for app in apps:
        token = app.get("runToken")
        marker = RUN_TOKEN_ARG_PREFIX + token if token else None
        current_user = sorted(
            pid for pid in candidates.get(app.get("id"), set())
            if snap.get(pid, {}).get("uid") == SELF_UID)
        controller_found = bool(marker and any(
            marker in snap.get(pid, {}).get("args", "") for pid in current_user))
        # 随机标记在进程组的常驻外层 shell 上；校验后整组均为受控后代。
        result[app.get("id")] = current_user if controller_found else []
    return result, snap, groups


def managed_pids(app, groups=None):
    index, _, _ = managed_process_index([app], groups)
    return index.get(app.get("id"), [])


def legacy_managed_pid(app, listeners=None, snap=None, cwds=None):
    """识别升级前身份或用户明确认领的外部监听进程。

    普通旧数据仍只接受原 lastPid。明确 ``attached`` 的卡片允许监听子进程
    换 PID，但仍必须在配置端口上按当前 UID + 真实 cwd 唯一命中；因此
    Next/Vite 等重建子进程后不会丢失关联，也不会只凭端口误认其他项目。
    """
    if IS_WINDOWS:
        identity = app.get("processIdentity")
        if not isinstance(identity, dict) or identity.get("type") != "external":
            return None
        if identity.get("environment") != "native":
            return None
        verified, error = verify_native_process_identity(
            identity, require_listener=True)
        if error:
            return None
        if app.get("port") != verified.get("port"):
            return None
        expected_cwd = app.get("cwd")
        if expected_cwd:
            try:
                if os.path.normcase(os.path.realpath(expected_cwd)) != os.path.normcase(
                        os.path.realpath(verified.get("cwd") or "")):
                    return None
            except OSError:
                return None
        return verified["pid"]
    if app.get("runToken"):
        return None
    recorded_pid = app.get("lastPid")
    port = app.get("port")
    expected_cwd = app.get("cwd")
    if (not isinstance(port, int) or port <= 0
            or not isinstance(expected_cwd, str) or not expected_cwd):
        return None
    if listeners is None:
        listeners = scan_listeners()
    port_pids = {pid for pid, listening_port in listeners
                 if listening_port == port}
    if not app.get("attached"):
        if not isinstance(recorded_pid, int) or recorded_pid <= 0:
            return None
        port_pids.intersection_update({recorded_pid})
    if not port_pids:
        return None
    if snap is None:
        snap = ps_snapshot(port_pids, with_uid=True)
    if cwds is None:
        cwds = lsof_cwds(port_pids)
    matches = []
    for pid in sorted(port_pids):
        if snap.get(pid, {}).get("uid") != SELF_UID:
            continue
        actual_cwd = cwds.get(pid)
        if not actual_cwd:
            continue
        try:
            same_cwd = (
                os.path.realpath(actual_cwd) == os.path.realpath(expected_cwd))
        except OSError:
            same_cwd = False
        if same_cwd:
            matches.append(pid)
    if recorded_pid in matches:
        return recorded_pid
    return matches[0] if app.get("attached") and len(matches) == 1 else None


def listener_app_owners(apps, listeners, snap, cwds, groups=None):
    """返回真实受管监听进程的 ``pid -> app`` 映射。

    端口只是配置与网络资源，不能作为进程所有权证明。映射沿用应用状态的
    run token / PGID / UID 校验，并为升级前的进程保留严格 legacy 识别。
    如果异常配置让同一 PID 同时命中多张卡片，则不做关联，避免误导 UI。
    """
    managed, _, _ = managed_process_index(apps, groups)
    candidates = {}
    for app in apps:
        live = managed.get(app.get("id"), [])
        if not live:
            legacy_pid = legacy_managed_pid(app, listeners, snap, cwds)
            live = [legacy_pid] if legacy_pid else []
        for pid in live:
            candidates.setdefault(pid, []).append(app)
    return {
        pid: owners[0]
        for pid, owners in candidates.items()
        if len(owners) == 1
    }


def _wsl_scan_index(scans):
    indexed = {}
    for scan in scans or []:
        distro = str(scan.get("distro") or "")
        processes = {}
        for item in scan.get("processes") or []:
            if isinstance(item, dict):
                try:
                    processes[int(item.get("pid"))] = item
                except (TypeError, ValueError):
                    pass
        listeners = {}
        for item in scan.get("listeners") or []:
            if not isinstance(item, dict):
                continue
            try:
                pid, port = int(item.get("pid")), int(item.get("port"))
            except (TypeError, ValueError):
                continue
            listeners.setdefault(pid, []).append((port, item))
        indexed[distro.casefold()] = {
            "scan": scan, "processes": processes, "listeners": listeners,
        }
    return indexed


def _build_wsl_app(
        app, wsl_index, native_listeners,
        native_snapshot=None, native_cwds=None,
        wsl_distros=_PLATFORM_WSL_UNSET,
        wsl_discovery_ready=True, wsl_discovery_error=None):
    execution = app.get("execution") or {}
    distro = str(execution.get("distro") or "")
    indexed = wsl_index.get(distro.casefold()) or {}
    scan = indexed.get("scan") or {}
    identity = app.get("processIdentity") or {}
    if identity.get("type") == "external":
        # ``scan`` is the already-published monitor snapshot.  Passing an
        # explicit empty mapping is significant: state polling must report the
        # external process as temporarily unverifiable instead of falling back
        # to a synchronous ``wsl.exe`` scan on the HTTP request thread.
        verified, verify_error = verify_wsl_process_identity(
            identity, scan=scan, require_listener=True)
        running = verified is not None
        status = {"ok": running, "running": running,
                  "error": verify_error}
        wsl_status = verified or {}
        pid = verified.get("pid") if verified else None
    else:
        status = supervisor_runtime_status(app) or {}
        recovery_pending = bool(
            identity.get("recoveryPending")
            and not status.get("identityMismatch")
            and not (status.get("ok") and not status.get("running")
                     and status.get("state") not in (
                         "starting", "startup-cleanup-failed")))
        running = bool(
            (status.get("ok") and status.get("running"))
            or recovery_pending)
        wsl_status = status.get("wslStatus") or (status.get("wsl") or {}).get("lastStatus") or {}
        pid = (wsl_status.get("pid") or status.get("childPid")
               or identity.get("pid") or app.get("lastPid"))
    if not isinstance(pid, int) or pid <= 0:
        pid = None
    boot_id = wsl_status.get("bootId") or (status.get("wsl") or {}).get("bootId")
    if scan.get("bootId") and boot_id and scan.get("bootId") != boot_id:
        running, pid = False, None
    process = (indexed.get("processes") or {}).get(pid) if pid else None
    listener_items = (indexed.get("listeners") or {}).get(pid, []) if pid else []
    actual_ports = sorted({port for port, _item in listener_items})
    port = app.get("port")
    listening = bool(running and port in actual_ports)
    wsl_port_owners = []
    for distro_key, other_indexed in wsl_index.items():
        for other_pid, values in (other_indexed.get("listeners") or {}).items():
            if distro_key == distro.casefold() and other_pid == pid:
                continue
            if any(item_port == port for item_port, _item in values):
                wsl_port_owners.append((distro_key, other_pid))
    native_port_owners = [native_pid for native_pid, native_port in native_listeners
                          if native_port == port]
    occupied = bool(port and not listening
                    and (wsl_port_owners or native_port_owners))
    owner_entry = ((wsl_port_owners or [(None, native_pid)
                    for native_pid in native_port_owners] or [(None, None)])[0]
                   if occupied else (None, None))
    owner_distro, owner_pid = owner_entry
    port_owner = None
    if owner_pid:
        if owner_distro is not None:
            owner_index = wsl_index.get(owner_distro) or {}
            owner_scan = owner_index.get("scan") or {}
            owner_process = (owner_index.get("processes") or {}).get(owner_pid) or {}
            owner_distro_name = str(owner_scan.get("distro") or owner_distro)
            owner_ticks = owner_process.get(
                "startTicks", owner_process.get("create_time"))
            owner_boot = owner_scan.get("bootId")
            owner_uid = owner_process.get("uid")
            owner_key = None
            if owner_ticks and owner_boot and owner_uid is not None:
                owner_key = make_instance_key(
                    "wsl", owner_pid, owner_ticks,
                    distro=owner_distro_name, boot_id=owner_boot,
                    port=port, identity=owner_uid,
                    cwd=owner_process.get("cwd"),
                    command=owner_process.get("args"),
                    cwd_hash=owner_process.get("cwdHash"),
                    command_hash=owner_process.get("commandHash"))
            port_owner = {
                "pid": owner_pid,
                "distro": owner_distro_name,
                "name": os.path.basename(str(owner_process.get("comm") or "")) or "?",
                "cmd": owner_process.get("args") or owner_process.get("comm"),
                "cwd": owner_process.get("cwd"),
                "currentUser": str(owner_uid) == str(owner_scan.get("uid")),
                "instanceKey": owner_key,
                "execution": {"environment": "wsl", "shell": "posix",
                              "distro": owner_distro_name},
            }
        else:
            owner_info = (native_snapshot or {}).get(owner_pid, {})
            owner_cwd = (native_cwds or {}).get(owner_pid)
            owner_key = None
            if (owner_info.get("create_time")
                    and owner_info.get("identity_kind") == "sid"):
                owner_key = make_instance_key(
                    "native", owner_pid, owner_info["create_time"],
                    port=port, identity=owner_info.get("identity"),
                    cwd=owner_cwd,
                    command=owner_info.get("args") or owner_info.get("comm"))
            port_owner = {
                "pid": owner_pid,
                "distro": None,
                "name": os.path.basename(str(owner_info.get("comm") or "")) or "?",
                "cmd": owner_info.get("args") or owner_info.get("comm"),
                "cwd": owner_cwd,
                "currentUser": owner_info.get("uid") == SELF_UID,
                "instanceKey": owner_key,
                "execution": {"environment": "native", "shell": "auto",
                              "distro": None},
            }
    health = inspect_app_health(
        app,
        wsl_distros=wsl_distros,
        wsl_discovery_ready=wsl_discovery_ready,
        wsl_discovery_error=wsl_discovery_error,
    )
    instance_key = None
    if running and pid:
        create_time = (wsl_status.get("startTicks")
                       or (process or {}).get("startTicks")
                       or (process or {}).get("create_time"))
        if create_time and boot_id:
            instance_key = make_instance_key(
                "wsl", pid, create_time, distro=distro,
                boot_id=boot_id, port=port,
                identity=(process or {}).get("uid"),
                cwd=(process or {}).get("cwd") or app.get("cwd"),
                command=(process or {}).get("args") or app.get("command"),
                cwd_hash=(process or {}).get("cwdHash"),
                command_hash=(process or {}).get("commandHash"))
    preferred = scan.get("preferredAddress")
    open_hosts = {str(actual_port): "localhost"
                  for actual_port in actual_ports}
    uptime_sec = (process or {}).get("etime") if pid else None
    if running and uptime_sec is None:
        # Tasks need no listener and may finish before the next /proc scan.
        # Both values below came through the authenticated supervisor status;
        # helper ``startedAt`` is more precise, supervisor createTime is the
        # durable fallback for older helper responses.
        started_at = wsl_status.get("startedAt") or status.get("createTime")
        try:
            uptime_sec = max(0, int(time.time() - float(started_at)))
        except (TypeError, ValueError, OverflowError):
            uptime_sec = None
    return {
        "id": app["id"], "name": app["name"],
        "command": app["command"], "cwd": app.get("cwd"), "port": port,
        "emoji": app.get("emoji"), "glyph": app.get("glyph"),
        "icon": app.get("icon"), "favicon": app.get("favicon"),
        "running": running, "pid": pid,
        "uptimeSec": uptime_sec,
        "kind": app.get("kind") or "service",
        "execution": execution, "distro": distro,
        "instanceKey": instance_key,
        "attached": bool(app.get("attached")),
        "lastExit": runtime_last_exit(app, status), "health": health,
        "ports": actual_ports, "openHosts": open_hosts,
        "fallbackHost": preferred,
        "listening": listening, "portOccupied": occupied,
        "portOccupiedPid": owner_pid,
        "portOwner": port_owner,
        "portConflict": False, "portConflictApps": [],
        "legacyManaged": False,
    }


def build_apps(
        cfg, listeners, groups=None, wsl_scans=None,
        wsl_distros=_PLATFORM_WSL_UNSET,
        wsl_discovery_ready=True, wsl_discovery_error=None):
    """token 校验通过或严格命中旧版身份的进程才算 running。

    多张卡片可共享配置端口；只有当前真实监听者不属于本卡片时才返回
    “端口被其他进程占用”，不再把任意监听者误当成应用本身。
    """
    port_map = {}
    for pid, port in listeners:
        port_map.setdefault(port, []).append(pid)
    apps_cfg = cfg.get("apps") or []
    wsl_index = _wsl_scan_index(wsl_scans)
    managed, snap, _ = managed_process_index(apps_cfg, groups)
    listen_by_pid = {}
    for pid, port in listeners:
        listen_by_pid.setdefault(pid, []).append(port)
    configured_ports = {
        app["port"] for app in apps_cfg if app.get("port")}

    # 端口诊断需要展示占用者的真实身份，一次批量取详情，避免逐卡 ps。
    configured_listener_pids = {
        pid for port in configured_ports for pid in port_map.get(port, [])}
    listener_snap = (ps_snapshot(configured_listener_pids, with_uid=True)
                     if configured_listener_pids else {})
    listener_cwds = lsof_cwds(configured_listener_pids)
    verified_owner = listener_app_owners(
        apps_cfg, listeners, listener_snap, listener_cwds)

    apps = []
    for app in apps_cfg:
        execution = app.get("execution") or normalize_execution(None)[0]
        if IS_WINDOWS and execution.get("environment") == "wsl":
            apps.append(_build_wsl_app(
                app, wsl_index, listeners, listener_snap, listener_cwds,
                wsl_distros=wsl_distros,
                wsl_discovery_ready=wsl_discovery_ready,
                wsl_discovery_error=wsl_discovery_error,
            ))
            continue
        runtime_status = (supervisor_runtime_status(app)
                          if IS_WINDOWS and
                          (app.get("processIdentity") or {}).get("type") == "supervisor"
                          else None)
        recovery_pending = bool(
            (app.get("processIdentity") or {}).get("recoveryPending")
            and not (runtime_status or {}).get("identityMismatch")
            and not ((runtime_status or {}).get("ok")
                     and not (runtime_status or {}).get("running")
                     and (runtime_status or {}).get("state") not in (
                         "starting", "startup-cleanup-failed")))
        managed_live = managed.get(app["id"], [])
        legacy_pid = None if managed_live else legacy_managed_pid(
            app, listeners, listener_snap, listener_cwds)
        if (legacy_pid and
                (verified_owner.get(legacy_pid) or {}).get("id") != app.get("id")):
            legacy_pid = None
        live = managed_live or ([legacy_pid] if legacy_pid else [])
        lp = app.get("lastPid")
        pid = (lp if lp in live else
               (live[0] if live else (lp if recovery_pending else None)))
        port = app.get("port")
        configured_listeners = port_map.get(port, []) if port else []
        listening = bool(port and any(p in live for p in configured_listeners))
        occupied = bool(port and configured_listeners and not listening)
        owner_pid = configured_listeners[0] if occupied else None
        owner_info = listener_snap.get(owner_pid, {}) if owner_pid else {}
        owner_app = verified_owner.get(owner_pid)
        owner_cwd = listener_cwds.get(owner_pid) if owner_pid else None
        port_owner = None
        if owner_pid:
            comm = owner_info.get("comm") or ""
            owner_instance_key = None
            if (IS_WINDOWS and owner_info.get("create_time")
                    and owner_info.get("identity_kind") == "sid"):
                owner_instance_key = make_instance_key(
                    "native", owner_pid, owner_info["create_time"],
                    port=port, identity=owner_info.get("identity"),
                    cwd=owner_cwd,
                    command=owner_info.get("args") or comm)
            port_owner = {
                "pid": owner_pid,
                "openHost": listener_open_host(
                    listeners, port, {owner_pid}),
                "name": os.path.basename(comm) or "?",
                "cmd": owner_info.get("args") or comm,
                "cwd": owner_cwd,
                "project": project_name(owner_cwd),
                "uid": owner_info.get("uid"),
                "currentUser": owner_info.get("uid") == SELF_UID,
                "uptimeSec": owner_info.get("etime"),
                "appId": owner_app.get("id") if owner_app else None,
                "appName": owner_app.get("name") if owner_app else None,
                "instanceKey": owner_instance_key,
                "execution": {
                    "environment": "native",
                    "shell": "auto" if IS_WINDOWS else "posix",
                    "distro": None,
                },
            }
        actual_ports = sorted({p for member in live
                               for p in listen_by_pid.get(member, [])})
        open_hosts = {
            str(actual_port): listener_open_host(
                listeners, actual_port, set(live))
            for actual_port in actual_ports
        }
        try:
            health = inspect_app_health(app)
        except Exception as exc:
            LOG.warning("检查应用配置失败（%s）：%s", app.get("id"), exc)
            health = {"status": "unknown", "blocking": False, "issues": []}
        apps.append({
            "id": app["id"], "name": app["name"], "command": app["command"],
            "cwd": app.get("cwd"), "port": port,
            "emoji": app.get("emoji"), "glyph": app.get("glyph"), "icon": app.get("icon"),
            "favicon": app.get("favicon"),
            "running": bool(live or recovery_pending), "pid": pid,
            "uptimeSec": ((snap.get(pid) or listener_snap.get(pid) or {}).get("etime")
                          if pid else None),
            "kind": app.get("kind") or "service",
            "execution": execution,
            "instanceKey": (
                make_instance_key(
                    "native", pid,
                    (snap.get(pid) or listener_snap.get(pid) or {}).get("create_time"),
                    port=port,
                    identity=(snap.get(pid) or listener_snap.get(pid) or {}).get("identity"),
                    cwd=listener_cwds.get(pid) or app.get("cwd"),
                    command=(snap.get(pid) or listener_snap.get(pid) or {}).get("args"))
                if IS_WINDOWS and pid and
                (snap.get(pid) or listener_snap.get(pid) or {}).get("create_time")
                else app.get("instanceKey")),
            "attached": bool(app.get("attached")),
            "lastExit": runtime_last_exit(app, runtime_status),
            "health": health,
            "ports": actual_ports,
            "openHosts": open_hosts,
            "listening": listening,
            "portOccupied": occupied,
            "portOccupiedPid": configured_listeners[0] if occupied else None,
            "portOwner": port_owner,
            # 多张停止卡片可以共享常见开发端口；只有真正启动时的监听占用
            # 才是冲突。字段保留给旧前端兼容，但不再表示配置重复。
            "portConflict": False,
            "portConflictApps": [],
            "legacyManaged": bool(legacy_pid),
        })
    return apps


def build_state(cfg, console_port, config_health=None):
    degraded_reasons = []
    # 一次 pgid 快照供 build_services / build_apps 共享，避免每轮两次全量 ps。
    needs_groups = not IS_WINDOWS and any(
        app.get("runToken")
        and isinstance(app.get("lastPgid") or app.get("lastPid"), int)
        for app in cfg.get("apps") or [])
    groups = pgid_members_map() if needs_groups else None
    try:
        services, listeners = build_services(cfg, groups)
    except Exception as e:
        LOG.exception("构建服务监控状态失败")
        services, listeners = [], set()
        degraded_reasons.append({"component": "services"})
    wsl_scans = []
    wsl_distros = _PLATFORM_WSL_UNSET
    wsl_discovery_error = _PLATFORM_WSL_UNSET
    wsl_discovery_pending = _PLATFORM_WSL_UNSET
    wsl_discovery_ready = _PLATFORM_WSL_UNSET
    wsl_discovery_stale = _PLATFORM_WSL_UNSET
    if IS_WINDOWS:
        try:
            manager = get_wsl_manager()
            monitor = manager.monitor_discovery() if manager else {
                "distros": [], "scans": [], "scanErrors": [],
                "error": None, "pending": False, "ready": True,
                "stale": False,
            }
        except Exception as e:
            LOG.exception("读取 WSL 后台监控快照失败")
            monitor = {
                "distros": [], "scans": [], "scanErrors": [],
                "error": str(e), "pending": False, "ready": True,
                "stale": False,
            }
        wsl_distros = monitor.get("distros") or []
        wsl_scans = monitor.get("scans") or []
        wsl_errors = monitor.get("scanErrors") or []
        wsl_discovery_error = monitor.get("error")
        wsl_discovery_pending = bool(monitor.get("pending"))
        wsl_discovery_ready = bool(monitor.get("ready"))
        wsl_discovery_stale = bool(monitor.get("stale"))
        if not wsl_discovery_ready:
            degraded_reasons.append({
                "component": "wsl",
                "error": WSL_DISCOVERY_PENDING_MESSAGE,
                "pending": True,
            })
        elif wsl_discovery_error:
            degraded_reasons.append({
                "component": "wsl", "error": wsl_discovery_error})
        try:
            wsl_services, _used_scans, _unused_errors = build_wsl_services(
                cfg, scans=wsl_scans)
            services.extend(wsl_services)
            for error in wsl_errors:
                degraded_reasons.append({
                    "component": "wsl",
                    "distro": error.get("distro"),
                    "error": error.get("error"),
                })
        except Exception as e:
            LOG.exception("构建 WSL 服务监控状态失败")
            degraded_reasons.append({
                "component": "wsl", "error": str(e)})
    try:
        watched = (windows_watched_snapshot(cfg.get("watchedKeywords"))
                   if IS_WINDOWS else
                   build_watched(cfg.get("watchedKeywords")))
    except Exception as e:
        LOG.exception("构建关注进程状态失败")
        watched = []
        degraded_reasons.append({"component": "watched"})
    try:
        apps = build_apps(
            cfg, listeners, groups,
            wsl_scans=wsl_scans,
            wsl_distros=wsl_distros,
            wsl_discovery_ready=(
                True if wsl_discovery_ready is _PLATFORM_WSL_UNSET
                else wsl_discovery_ready
            ),
            wsl_discovery_error=(
                None if wsl_discovery_error is _PLATFORM_WSL_UNSET
                else wsl_discovery_error
            ),
        )
    except Exception as e:
        LOG.exception("构建启动台状态失败")
        apps = []
        degraded_reasons.append({"component": "apps"})
    live_wsl_apps = {
        (str((app.get("execution") or {}).get("distro") or "").casefold(),
         app.get("pid")): app
        for app in apps
        if app.get("running")
        and (app.get("execution") or {}).get("environment") == "wsl"
        and isinstance(app.get("pid"), int)
    }
    for service in services:
        execution = service.get("execution") or {}
        if execution.get("environment") != "wsl":
            continue
        owner = live_wsl_apps.get((
            str(execution.get("distro") or "").casefold(),
            service.get("pid")))
        if owner:
            service["appId"] = owner.get("id")
            service["appName"] = owner.get("name")
    if VERSION_LOAD_ERROR:
        degraded_reasons.append(
            {"component": "version", "error": VERSION_LOAD_ERROR})
    for issue in (config_health or {}).get("issues", []):
        degraded_reasons.append({"component": "config", "error": issue})
    return {
        "services": services,
        "watched": watched,
        "apps": apps,
        "watchedKeywords": cfg.get("watchedKeywords") or [],
        "consolePort": console_port,
        "consolePid": SELF_PID,
        "consoleCwd": BASE_DIR,
        "version": APP_VERSION,
        "schemaVersion": cfg.get("schemaVersion", CURRENT_SCHEMA_VERSION),
        "degraded": bool(degraded_reasons),
        "degradedReasons": degraded_reasons,
        "configHealth": dict(config_health or {}),
        "uiTheme": cfg.get("uiTheme") or DEFAULT_UI_THEME,
        "themes": list_themes(),
        "platform": (
            get_platform_info(
                wsl_distros=wsl_distros,
                wsl_discovery_error=wsl_discovery_error,
                wsl_discovery_pending=wsl_discovery_pending,
                wsl_discovery_ready=wsl_discovery_ready,
                wsl_discovery_stale=wsl_discovery_stale,
            )
            if IS_WINDOWS else get_platform_info()
        ),
    }


# ---------------------------------------------------------------- 状态快照缓存
# 每次快照要跑约十余个 ps/lsof 子进程。TTL 略大于前端 2s 轮询周期：
# 单标签页约每 2-3 轮重建一次，多标签页请求自动合并（锁内构建排队后
# 第二个请求直接命中缓存）。配置/进程变更时 invalidate 立即失效。
STATE_CACHE_TTL = 2.2  # 秒
_state_cache_lock = threading.Lock()
_state_build_lock = threading.Lock()
_state_cache = {"mono": 0.0, "state": None, "generation": 0}


def invalidate_state_cache():
    with _state_cache_lock:
        _state_cache["state"] = None
        _state_cache["generation"] = int(
            _state_cache.get("generation", 0)) + 1


def get_state_snapshot(cfg, console_port):
    now = time.monotonic()
    with _state_cache_lock:
        cached = _state_cache["state"]
        if cached is not None and now - _state_cache["mono"] < STATE_CACHE_TTL:
            return cached

    # Serialize expensive builds without holding the cache lock while taking
    # Config._lock. Config.update() invalidates the cache while holding its own
    # lock; the former cache->config ordering could therefore deadlock against
    # update's config->cache ordering.
    with _state_build_lock:
        now = time.monotonic()
        with _state_cache_lock:
            cached = _state_cache["state"]
            if (cached is not None
                    and now - _state_cache["mono"] < STATE_CACHE_TTL):
                return cached
            generation = int(_state_cache.get("generation", 0))

        state = build_state(cfg.snapshot(), console_port, cfg.health_info())

        with _state_cache_lock:
            # A concurrent config/runtime mutation may have invalidated while
            # this snapshot was building. Return the coherent local result to
            # its caller, but never publish it as the next request's cache.
            if int(_state_cache.get("generation", 0)) == generation:
                _state_cache["mono"] = time.monotonic()
                _state_cache["state"] = state
        return state


def build_health(cfg):
    """不执行 ps/lsof 的轻量健康检查。"""
    health = cfg.health_info()
    issues = list(health.get("issues") or [])
    if VERSION_LOAD_ERROR:
        issues.append("VERSION 读取失败: %s" % VERSION_LOAD_ERROR)
    for label, path in (("data", DATA_DIR), ("icons", ICONS_DIR),
                        ("logs", LOGS_DIR)):
        if not os.path.isdir(path):
            issues.append("%s 目录不存在" % label)
        elif not os.access(path, os.R_OK | os.W_OK | os.X_OK):
            issues.append("%s 目录不可读写" % label)
        else:
            try:
                mode = os.lstat(path).st_mode
                if stat.S_ISLNK(mode) or (not IS_WINDOWS and mode & 0o077):
                    issues.append("%s 目录权限不是 0700" % label)
            except OSError as e:
                issues.append("无法检查 %s 目录: %s" % (label, e))
    for label, path in (("config", CONFIG_PATH),
                        ("configBackup", CONFIG_PATH + ".bak")):
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            if label == "config":
                issues.append("主配置文件不存在")
            continue
        except OSError as e:
            issues.append("无法检查 %s: %s" % (label, e))
            continue
        if not stat.S_ISREG(mode) or (not IS_WINDOWS and mode & 0o077):
            issues.append("%s 文件权限不是 0600" % label)
        elif IS_WINDOWS and getattr(sys, "frozen", False):
            try:
                from console_platform.windows_security import private_path_is_secure
                if private_path_is_secure(path) is not True:
                    issues.append("%s 文件 DACL 不是仅当前用户和 SYSTEM" % label)
            except Exception as exc:
                issues.append("无法检查 %s Windows DACL: %s" % (label, exc))
    degraded = bool(issues)
    snapshot = cfg.snapshot()
    return {
        "ok": not degraded,
        "status": "degraded" if degraded else "ok",
        "version": APP_VERSION,
        "schemaVersion": snapshot.get(
            "schemaVersion", CURRENT_SCHEMA_VERSION),
        "degraded": degraded,
        "issues": issues,
        "config": health,
    }


def list_themes():
    """扫描 static/themes/*.json 主题清单（css 文件必须存在），供注册切换。
    默认主题固定排在首位，其余按文件名排序。"""
    themes = []
    try:
        names = sorted(os.listdir(THEMES_DIR))
    except OSError:
        return themes
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(THEMES_DIR, name), "r", encoding="utf-8") as f:
                meta = json.load(f)
            theme_id = str(meta.get("id") or os.path.splitext(name)[0])
            if not theme_id or not os.path.isfile(
                    os.path.join(THEMES_DIR, theme_id + ".css")):
                continue
            themes.append({
                "id": theme_id,
                "name": str(meta.get("name") or theme_id),
                "author": str(meta.get("author") or ""),
                "desc": str(meta.get("desc") or ""),
                "colors": [str(c) for c in (meta.get("colors") or [])][:6],
            })
        except Exception:
            LOG.exception("读取主题清单失败: %s", name)
    themes.sort(key=lambda t: t["id"] != DEFAULT_UI_THEME)
    return themes


# ---------------------------------------------------------------- 进程/应用操作

def process_uid(pid):
    """返回进程 uid；进程不存在返回 None。"""
    if IS_WINDOWS:
        return (ps_snapshot([pid], with_uid=True).get(int(pid)) or {}).get("uid")
    out = run_cmd(["ps", "-o", "uid=", "-p", str(int(pid))])
    toks = out.split()
    if not toks:
        return None
    try:
        return int(toks[0])
    except ValueError:
        return None


def _same_process_time(expected, actual):
    try:
        return abs(float(expected) - float(actual)) < 0.001
    except (TypeError, ValueError, OverflowError):
        return str(expected) == str(actual)


def same_runtime_identity(left, right):
    """Compare complete persisted runtime identities across environments.

    Windows native identity is PID + process creation time.  WSL identity is
    distribution + boot ID + PID + Linux ``startTicks``.  In particular, WSL
    identities must never compare equal merely because both lack the native
    ``createTime`` field.
    """
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    environment = left.get("environment")
    if environment not in ("native", "wsl") or right.get("environment") != environment:
        return False
    left_pid, right_pid = left.get("pid"), right.get("pid")
    if (isinstance(left_pid, bool) or isinstance(right_pid, bool)
            or not isinstance(left_pid, int) or not isinstance(right_pid, int)
            or left_pid <= 0 or left_pid != right_pid):
        return False
    if environment == "native":
        left_time, right_time = left.get("createTime"), right.get("createTime")
        return (left_time is not None and right_time is not None
                and _same_process_time(left_time, right_time))
    left_distro = str(left.get("distro") or "")
    right_distro = str(right.get("distro") or "")
    left_boot, right_boot = left.get("bootId"), right.get("bootId")
    left_ticks, right_ticks = left.get("startTicks"), right.get("startTicks")
    return bool(
        left_distro and right_distro
        and left_distro.casefold() == right_distro.casefold()
        and left_boot is not None and right_boot is not None
        and str(left_boot) == str(right_boot)
        and left_ticks is not None and right_ticks is not None
        and str(left_ticks) == str(right_ticks)
    )


def verify_native_process_identity(identity, *, require_listener=False):
    """Verify a persisted native Windows identity without trusting a PID."""
    if not isinstance(identity, dict) or identity.get("environment") != "native":
        return None, "Windows 进程身份记录无效"
    pid = identity.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None, "Windows 进程身份记录无效"
    if pid == SELF_PID:
        return None, "不能操作总控台自身进程"
    info = ps_snapshot([pid], with_uid=True).get(pid)
    if not info:
        return None, "进程不存在或无法验证"
    if info.get("uid") != SELF_UID:
        return None, "只能操作当前用户的进程"
    if not _same_process_time(identity.get("createTime"),
                              info.get("create_time")):
        return None, "PID 已被复用，进程身份已失效"
    try:
        adapter = _native_adapter()
        current_identity = adapter.current_user_identity() if adapter else None
    except Exception:
        current_identity = None
    if (current_identity is None or current_identity.kind != "sid"
            or info.get("identity_kind") != "sid"
            or str(info.get("identity")).casefold()
            != str(current_identity.value).casefold()):
        return None, "无法用 Windows SID 证明进程属于当前用户"
    if (identity.get("identity") is not None
            and str(identity.get("identity")).casefold()
            != str(info.get("identity")).casefold()):
        return None, "进程所有者身份已变化"
    cwd = lsof_cwds([pid]).get(pid)
    args = info.get("args") or info.get("comm") or ""
    if identity.get("cwdHash") and identity["cwdHash"] != _identity_digest(cwd):
        return None, "进程工作目录已变化，身份已失效"
    if (identity.get("commandHash")
            and identity["commandHash"] != _identity_digest(args)):
        return None, "进程命令身份已变化，身份已失效"
    port = identity.get("port")
    if require_listener:
        if not isinstance(port, int) or (pid, port) not in scan_listeners():
            return None, "进程已不再监听原端口"
    verified = dict(identity)
    verified.update({
        "type": identity.get("type") or "external",
        "environment": "native",
        "pid": pid,
        "createTime": info.get("create_time"),
        "identity": info.get("identity"),
        "identityKind": info.get("identity_kind"),
        "cwd": cwd,
        "cwdHash": _identity_digest(cwd),
        "commandHash": _identity_digest(args),
        "port": port,
    })
    return verified, None


def verify_native_instance_key(value, *, require_listener=False):
    """Revalidate a signed Windows process identity against a live snapshot."""
    payload = parse_instance_key(value)
    if not payload or payload.get("environment") != "native":
        return None, None, "进程身份已失效，请刷新后重试"
    identity = {
        "type": "external",
        "environment": "native",
        "pid": payload["pid"],
        "createTime": payload.get("createTime"),
        "identity": payload.get("identity"),
        "cwdHash": payload.get("cwdHash"),
        "commandHash": payload.get("commandHash"),
        "port": payload.get("port"),
    }
    verified, error = verify_native_process_identity(
        identity, require_listener=require_listener)
    if error:
        return None, None, error
    info = ps_snapshot([payload["pid"]], with_uid=True).get(payload["pid"])
    return verified, info, None


def verify_wsl_process_identity(identity, *, scan=None,
                                require_listener=False):
    if (not isinstance(identity, dict) or identity.get("environment") != "wsl"):
        return None, "WSL 进程身份记录无效"
    distro = identity.get("distro")
    try:
        from console_platform.wsl import validate_distro_name
        distro = validate_distro_name(distro)
        # ``None`` means an explicit operation requested a fresh verification.
        # An empty mapping is a trusted negative cache entry from monitoring
        # and must not trigger WSL work on an HTTP state request.
        if scan is None:
            scan = get_wsl_manager().scan_distro(distro)
    except Exception as exc:
        return None, "无法验证 WSL 发行版: %s" % exc
    if scan.get("bootId") != identity.get("bootId"):
        return None, "WSL 发行版已重启，进程身份已失效"
    try:
        current_uid = int(scan.get("uid"))
        pid = int(identity.get("pid"))
    except (TypeError, ValueError):
        return None, "WSL 进程身份记录无效"
    process = next((item for item in scan.get("processes") or []
                    if isinstance(item, dict)
                    and str(item.get("pid")) == str(pid)), None)
    if not process:
        return None, "WSL 进程不存在或无法验证"
    try:
        uid = int(process.get("uid"))
    except (TypeError, ValueError):
        return None, "WSL 进程 UID 无法验证"
    if uid != current_uid or uid != int(identity.get("uid", -1)):
        return None, "WSL 进程不属于发行版当前用户"
    actual_ticks = process.get("startTicks", process.get("start_ticks"))
    if str(actual_ticks) != str(identity.get("startTicks")):
        return None, "WSL PID 已被复用，进程身份已失效"
    if (identity.get("cwdHash")
            and identity["cwdHash"] != process.get("cwdHash")):
        return None, "WSL 进程工作目录身份已变化"
    if (identity.get("commandHash")
            and identity["commandHash"] != process.get("commandHash")):
        return None, "WSL 进程命令身份已变化"
    port = identity.get("port")
    if require_listener:
        matched = any(
            isinstance(item, dict)
            and str(item.get("pid")) == str(pid)
            and item.get("port") == port
            for item in scan.get("listeners") or [])
        if not matched:
            return None, "WSL 进程已不再监听原端口"
    verified = dict(identity)
    verified.update({
        "type": identity.get("type") or "external",
        "environment": "wsl", "distro": distro,
        "bootId": scan.get("bootId"), "pid": pid, "uid": uid,
        "startTicks": actual_ticks, "cwd": process.get("cwd"),
        "cwdHash": process.get("cwdHash"),
        "commandHash": process.get("commandHash"), "port": port,
    })
    return verified, None


def verify_wsl_instance_key(value, *, require_listener=False):
    payload = parse_instance_key(value)
    if not payload or payload.get("environment") != "wsl":
        return None, "WSL 进程身份已失效，请刷新后重试"
    try:
        scan = get_wsl_manager().scan_distro(payload["distro"])
    except Exception as exc:
        return None, str(exc)
    process = next((item for item in scan.get("processes") or []
                    if isinstance(item, dict)
                    and str(item.get("pid")) == str(payload.get("pid"))), None)
    if not process:
        return None, "WSL 进程不存在或无法验证"
    identity = {
        "type": "external", "environment": "wsl",
        "distro": payload.get("distro"), "bootId": payload.get("bootId"),
        "pid": payload.get("pid"), "uid": process.get("uid"),
        "startTicks": payload.get("createTime"),
        "cwdHash": payload.get("cwdHash"),
        "commandHash": payload.get("commandHash"),
        "port": payload.get("port"),
    }
    return verify_wsl_process_identity(
        identity, scan=scan, require_listener=require_listener)


def kill_process(pid, force, instance_key=None):
    """结束单个进程；返回 ``(ok, error, requires_force)``。"""
    if IS_WINDOWS:
        payload = parse_instance_key(instance_key)
        identity, _info, error = verify_native_instance_key(
            instance_key,
            require_listener=bool(payload and payload.get("port") is not None))
        if error:
            return False, error, False
        if identity["pid"] != pid:
            return False, "PID 与 instanceKey 不匹配", False
        if not force:
            return (False,
                    "外部 Windows 进程无法证明安全的优雅停止；请确认后强制结束",
                    True)
        try:
            adapter = _native_adapter()
            if adapter is None:
                return False, "Windows 平台适配器不可用", False
            adapter.terminate_process(identity)
        except Exception as exc:
            return False, "强制结束失败: %s" % exc, False
        return True, None, False
    if pid == SELF_PID:
        return False, "不能结束总控台自身进程", False
    uid = process_uid(pid)
    if uid is None:
        return False, "进程不存在", False
    if uid != SELF_UID:
        return False, "只能结束当前用户的进程", False
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return False, "进程不存在", False
    except PermissionError:
        return False, "没有权限结束该进程", False
    except OSError as e:
        return False, "结束失败: %s" % e, False
    return True, None, False


def kill_wsl_process(instance_key, force=False):
    identity, error = verify_wsl_instance_key(
        instance_key, require_listener=True)
    if error:
        return False, error, False
    try:
        result = get_wsl_manager().process_control(
            identity, "force-stop" if force else "stop",
            timeout_ms=int(APP_STOP_TIMEOUT_SEC * 1000))
    except Exception as exc:
        return False, str(exc), False
    if result.get("ok") and not result.get("running"):
        return True, None, False
    return False, result.get("error") or "WSL 进程未退出", bool(
        result.get("requiresForce") and not force)


def stop_pid_tree(pid, sig=signal.SIGTERM):
    """向受控进程组发信号；返回 (ok, error)。

    ProcessLookupError means the target completed between validation and the
    signal and is therefore an idempotent success. Permission and other OS
    failures must never be swallowed: callers use them to retain management
    identity instead of creating an orphan process.
    """
    if IS_WINDOWS:
        try:
            if sig in (signal.SIGTERM, getattr(signal, "SIGBREAK", signal.SIGTERM)):
                os.kill(int(pid), getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
            else:
                os.kill(int(pid), sig)
            return True, None
        except ProcessLookupError:
            return True, None
        except PermissionError:
            return False, "没有权限停止受控进程树"
        except OSError as e:
            return False, "停止受控进程树失败: %s" % e
    try:
        os.killpg(int(pid), sig)
        return True, None
    except ProcessLookupError:
        return True, None
    except PermissionError:
        return False, "没有权限停止受控进程组"
    except OSError as e:
        return False, "停止受控进程组失败: %s" % e


def app_running(app, listeners=None):
    if IS_WINDOWS:
        identity = app.get("processIdentity") or {}
        if identity.get("type") == "supervisor":
            status = supervisor_runtime_status(app) or {}
            if status.get("ok"):
                return bool(
                    status.get("running") or
                    status.get("state") in (
                        "starting", "startup-cleanup-failed"))
            return bool(identity.get("recoveryPending")
                        and not status.get("identityMismatch"))
        if (identity.get("type") == "external"
                and identity.get("environment") == "wsl"):
            verified, _error = verify_wsl_process_identity(
                identity, require_listener=True)
            return verified is not None
    return bool(managed_pids(app) or legacy_managed_pid(app, listeners))


def app_alive_sign(app, listeners=None):
    """start/stop 的存活判断：新版 token 或严格校验通过的旧版身份。"""
    return app_running(app, listeners)


def configured_port_occupant(app, *, activate_wsl=False):
    """Return one real native/WSL listener for the configured service port."""
    port = app.get("port")
    if not isinstance(port, int) or port <= 0:
        return None
    for pid, listening_port in scan_listeners():
        if listening_port == port:
            return {"environment": "native", "pid": pid, "port": port}
    if not IS_WINDOWS:
        return None
    execution = app.get("execution") or normalize_execution(None)[0]
    manager = get_wsl_manager()
    if activate_wsl and execution.get("environment") == "wsl":
        manager.activate_distro(execution["distro"])
    try:
        scans, _errors = manager.scan_running()
    except Exception:
        return None
    for scan in scans:
        for item in scan.get("listeners") or []:
            try:
                if int(item.get("port")) == port:
                    return {"environment": "wsl",
                            "distro": scan.get("distro"),
                            "pid": int(item.get("pid")), "port": port}
            except (TypeError, ValueError):
                continue
    return None


def build_launch_env(token, environ=None):
    """构建无 Terminal 启动时仍可找到常见开发工具的环境。

    Finder/LSUIElement 启动的应用通常只有系统 PATH，不会读取用户 shell 配置；
    因此显式补入 Homebrew、npm/pnpm、Volta、NVM、fnm 等常见目录。
    """
    env = dict(os.environ if environ is None else environ)
    home = os.path.expanduser("~")
    if IS_WINDOWS:
        preferred = [
            os.path.join(home, ".local", "bin"),
            os.path.join(home, ".volta", "bin"),
            os.path.join(home, ".bun", "bin"),
            os.path.join(home, "AppData", "Roaming", "npm"),
            os.path.join(home, "AppData", "Local", "pnpm"),
        ]
        preferred.extend((env.get("PATH") or "").split(os.pathsep))
        seen = set()
        unique = []
        for path in preferred:
            if not path:
                continue
            key = os.path.normcase(os.path.normpath(path))
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        env["PATH"] = os.pathsep.join(unique)
        env[RUN_TOKEN_ENV] = token
        return env
    preferred = [
        os.path.join(home, ".local", "bin"),
        os.path.join(home, ".volta", "bin"),
        os.path.join(home, ".bun", "bin"),
        os.path.join(home, "Library", "pnpm"),
        os.path.join(home, ".asdf", "shims"),
        "/opt/homebrew/bin", "/opt/homebrew/sbin",
        "/usr/local/bin", "/usr/local/sbin",
    ]
    preferred.extend(sorted(
        glob.glob(os.path.join(home, ".nvm", "versions", "node", "*", "bin")),
        reverse=True))
    preferred.extend(sorted(
        glob.glob(os.path.join(home, ".fnm", "node-versions", "*", "installation", "bin")),
        reverse=True))
    preferred.extend((env.get("PATH") or "").split(os.pathsep))
    preferred.extend(("/usr/bin", "/bin", "/usr/sbin", "/sbin"))
    seen = set()
    env["PATH"] = os.pathsep.join(
        path for path in preferred if path and not (path in seen or seen.add(path)))
    env.setdefault("PNPM_HOME", os.path.join(home, "Library", "pnpm"))
    env[RUN_TOKEN_ENV] = token
    return env


class SupervisorRuntimeHandle:
    """Small Popen-compatible view over a durable Windows supervisor."""

    def __init__(self, metadata_path, metadata, token):
        self.metadata_path = metadata_path
        self.metadata = dict(metadata)
        self.token = token
        self.pid = int(metadata.get("childPid")
                       or metadata.get("supervisorPid") or 0)
        self.supervisor_pid = int(metadata.get("supervisorPid") or 0)
        self.returncode = None
        wsl = metadata.get("wsl") or {}
        self.runtime_identity = {
            "type": "supervisor",
            "environment": metadata.get("environment") or "native",
            "distro": metadata.get("distro"),
            "runId": metadata.get("runId"),
            "metadataPath": metadata_path,
            "supervisorVersion": metadata.get("supervisorVersion"),
            "supervisorPid": metadata.get("supervisorPid"),
            "supervisorCreateTime": metadata.get("supervisorCreateTime"),
            "ownerSid": metadata.get("ownerSid"),
            "pid": metadata.get("childPid"),
            "createTime": metadata.get("childCreateTime"),
            "startTicks": (metadata.get("childCreateTime")
                           if metadata.get("environment") == "wsl" else None),
            "bootId": wsl.get("bootId"),
            "sessionId": wsl.get("sessionId"),
            "recoveryPending": bool(
                metadata.get("recoveryPending")
                or metadata.get("startupError")
                or metadata.get("state") in (
                    "starting", "startup-cleanup-failed")),
            "startupError": metadata.get("startupError"),
        }

    @staticmethod
    def _exit_code(value):
        if not isinstance(value, dict):
            return None
        if isinstance(value.get("exitCode"), int):
            return value["exitCode"]
        wsl_status = value.get("wslStatus") or (value.get("wsl") or {}).get("lastStatus") or {}
        exit_info = wsl_status.get("exit") or {}
        if isinstance(exit_info.get("code"), int):
            return exit_info["code"]
        if exit_info.get("status") == "canceled":
            return TASK_CANCELED_EXIT_CODE
        if exit_info.get("status") == "stopped":
            return -signal.SIGTERM
        return None

    def _snapshot(self):
        from supervisor_client import load_metadata, status_supervisor
        metadata = load_metadata(self.metadata_path) or self.metadata
        if (not metadata.get("running")
                and metadata.get("state") in SUPERVISOR_TERMINAL_STATES):
            return metadata
        status = status_supervisor(metadata, self.token, timeout=3.0)
        if status.get("ok"):
            self.metadata = dict(status)
            return status
        latest = load_metadata(self.metadata_path)
        return latest or status

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        value = self._snapshot()
        if value.get("running") is True or value.get("state") == "running":
            return None
        if value.get("state") in ("starting", "startup-cleanup-failed"):
            # Cleanup was not proven. A failed control request is not evidence
            # that the user runtime exited, so keep the recovery token alive.
            return None
        code = self._exit_code(value)
        self.returncode = code if isinstance(code, int) else 1
        return self.returncode

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + max(0, timeout)
        while True:
            code = self.poll()
            if code is not None:
                return code
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("supervisor", timeout)
            time.sleep(0.2)


def start_app_supervised(app):
    """Launch a native Windows or WSL app through the durable supervisor."""
    from supervisor_client import (
        SUPERVISOR_VERSION,
        launch_supervisor,
        metadata_path,
    )

    _ensure_private_dir(LOGS_DIR)
    log_path = os.path.join(LOGS_DIR, "%s.log" % app["id"])
    rotate_log_file(log_path)
    token = secrets.token_urlsafe(32)
    run_id = "%s-%s" % (app["id"], secrets.token_hex(8))
    execution = app.get("execution") or normalize_execution(None)[0]
    launch_kwargs = {
        "cwd": app.get("cwd") or os.path.expanduser("~"),
        "environment": execution["environment"],
        "distro": execution.get("distro"),
        "stop_timeout": APP_STOP_TIMEOUT_SEC,
        # App VERSION and the independently versioned supervisor protocol are
        # deliberately unrelated.  Frozen builds contain the latter name.
        "supervisor_version": SUPERVISOR_VERSION,
        "launch_env": build_launch_env(token),
    }
    if execution["environment"] == "native":
        adapter = _native_adapter()
        if adapter is None:
            return False, "Windows 平台适配器不可用", None, None, None
        command = adapter.build_shell_command(
            app["command"], execution.get("shell") or "auto")
    else:
        try:
            from console_platform.wsl_host import windows_path_to_wsl

            manager = get_wsl_manager()
            manager.activate_distro(execution["distro"])
            installed = manager.ensure_helper(execution["distro"])
            status = manager.call(execution["distro"], "status")
            paths = manager.session_paths(
                execution["distro"], run_id, log_path)
            command = app["command"]
            configured_cwd = app.get("cwd")
            linux_cwd = (windows_path_to_wsl(
                configured_cwd, execution["distro"])
                if configured_cwd else installed.get("home") or "/")
            launch_kwargs.update({
                "cwd": linux_cwd,
                "helper_path": installed["path"],
                "wsl_socket": paths["socket"],
                "wsl_metadata": paths["metadata"],
                "wsl_log_path": paths["log"],
                "wsl_boot_id": status.get("bootId"),
                "wsl_kind": app.get("kind") or "service",
            })
        except Exception as exc:
            return False, "WSL 启动准备失败: %s" % exc, None, None, None
    launched = launch_supervisor(
        BASE_DIR, DATA_DIR, log_path, run_id, token, command,
        **launch_kwargs)
    if not launched.get("ok"):
        error = "启动 supervisor 失败: %s" % launched.get(
            "error", "未知错误")
        cleanup_error = (launched.get("cleanup") or {}).get("error")
        if cleanup_error:
            error += "；启动清理未获确认: %s" % cleanup_error
        metadata = launched.get("metadata")
        if launched.get("recoverable") and isinstance(metadata, dict):
            # Cleanup was not proven. Preserve the token and authenticated
            # starting/live supervisor identity through the normal config
            # transaction so the failed API call remains explicitly stoppable.
            handle = SupervisorRuntimeHandle(
                metadata_path(DATA_DIR, run_id), metadata, token)
            return (False, error, handle,
                    int(metadata.get("supervisorPid")
                        or launched.get("supervisorPid") or 0), token)
        return False, error, None, None, None
    meta_path = metadata_path(DATA_DIR, run_id)
    metadata = launched["metadata"]
    handle = SupervisorRuntimeHandle(meta_path, metadata, token)
    if handle.pid <= 0:
        return False, "supervisor 未返回受管进程身份", None, None, None
    return True, None, handle, handle.supervisor_pid, token


def start_app(app):
    """返回 (ok, error, proc|None, pgid|None, token|None)。"""
    if IS_WINDOWS:
        return start_app_supervised(app)
    _ensure_private_dir(LOGS_DIR)
    log_path = os.path.join(LOGS_DIR, "%s.log" % app["id"])
    rotate_log_file(log_path)
    cwd = app.get("cwd") or os.path.expanduser("~")
    try:
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(log_fd, 0o600)
        logf = os.fdopen(log_fd, "ab", buffering=0)
    except OSError as e:
        return False, "无法打开日志文件: %s" % e, None, None, None
    token = secrets.token_urlsafe(24)
    env = build_launch_env(token)
    marker = RUN_TOKEN_ARG_PREFIX + token
    # 外层 shell 在 argv[0] 中持有随机标记并等待内层；内层等待用户命令
    # 留下的后台作业。因此进程组既可验证，也不会因启动脚本过早退出而失去锚点。
    outer_script = '/bin/bash -c "$1"\nconsole_status=$?\nexit "$console_status"'
    inner_script = (app["command"] +
                    '\nconsole_status=$?\nwait\nexit "$console_status"')
    try:
        header = "\n===== 启动于 %s =====\n" % time.strftime("%Y-%m-%d %H:%M:%S")
        logf.write(header.encode("utf-8"))
        execution = app.get("execution") or normalize_execution(None)[0]
        if execution["environment"] == "wsl":
            distro = execution["distro"]
            launch = ["wsl.exe", "--distribution", distro, "--",
                      "/bin/sh", "-lc", app["command"]]
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            proc = subprocess.Popen(
                launch, cwd=cwd if os.path.isdir(cwd) else None,
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=creationflags, env=env)
        elif IS_WINDOWS:
            adapter = _native_adapter()
            shell = execution.get("shell") or "auto"
            launch = (adapter.build_shell_command(app["command"], shell)
                      if adapter is not None else
                      ["cmd.exe", "/d", "/s", "/c", app["command"]])
            creationflags = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                             | getattr(subprocess, "CREATE_NO_WINDOW", 0))
            proc = subprocess.Popen(
                launch, cwd=cwd, stdout=logf, stderr=subprocess.STDOUT,
                creationflags=creationflags, env=env)
        else:
            proc = subprocess.Popen(
                ["/bin/bash", "-c", outer_script, marker, inner_script],
                cwd=cwd, stdout=logf, stderr=subprocess.STDOUT,
                start_new_session=True, env=env)
    except Exception as e:
        logf.close()
        return False, "启动失败: %s" % e, None, None, None
    logf.close()  # 子进程已持有副本，父进程关闭避免 fd 泄漏
    return True, None, proc, proc.pid, token


def startup_failure_message(app_id, code):
    """从日志末尾提取一行可直接显示给用户的启动错误。"""
    text = read_log_tail(app_id, 30)
    for line in reversed(text.splitlines()):
        line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line).strip()
        if line and not line.startswith("====="):
            if len(line) > 180:
                line = line[:179] + "…"
            return "启动命令立即退出（exit %s）：%s" % (code, line)
    return "启动命令立即退出（exit %s），请查看日志" % code


def cleanup_finished_supervisor_versions():
    """Remove unreferenced frozen supervisor versions after a managed exit."""
    if not IS_WINDOWS or not getattr(sys, "frozen", False):
        return []
    try:
        from supervisor_client import (
            SUPERVISOR_VERSION,
            cleanup_unused_supervisors,
        )
        return cleanup_unused_supervisors(
            DATA_DIR, keep_versions=(SUPERVISOR_VERSION,))
    except Exception:
        # Cleanup is best-effort and must never turn a successfully observed
        # application exit into a failed state transition.
        LOG.exception("清理未引用的旧 supervisor 失败")
        return []


def watch_app_exit(cfg, app_id, proc, token, started_at=None):
    """后台线程等子进程退出：若期间未被手动 stop/重启（lastPid 仍指向它），
    记录 lastExit（退出码、结束时间和运行耗时）。保留 lastPid 作为进程组锚点——
    脚本可能把服务放后台后退出，后续的运行判定/停止都靠 pgid 找到存活成员。"""
    started_at = time.time() if started_at is None else started_at

    def _wait():
        code = proc.wait()
        ended_at = time.time()
        duration = round(max(0.0, ended_at - started_at), 3)

        with MANUAL_STOP_LOCK:
            manually_stopped = (app_id, token) in MANUAL_STOP_TOKENS

        def op(c):
            target = find_app(c, app_id)
            if (not manually_stopped and target
                    and target.get("lastPid") == proc.pid
                    and target.get("runToken") == token):
                last_exit = {
                    "code": code,
                    "at": int(ended_at),
                    "startedAt": int(started_at * 1000),
                    "durationSec": duration,
                }
                if (target.get("kind") or "service") == "task":
                    last_exit["status"] = classify_task_exit(code)
                target["lastExit"] = last_exit
        cfg.update(op)
        rotate_log_file(os.path.join(LOGS_DIR, "%s.log" % app_id))
        cleanup_finished_supervisor_versions()
    thread = threading.Thread(target=_wait, daemon=True)
    thread.start()
    return thread


def _set_started_runtime(target, proc, pgid, token):
    target["lastPid"] = proc.pid
    target["lastPgid"] = pgid
    target["runToken"] = token
    target["processIdentity"] = getattr(proc, "runtime_identity", None)
    target["instanceKey"] = None
    target["attached"] = False
    # 批处理任务运行时先保留上一次结果；自然退出或手动停止后再原子覆盖。
    if (target.get("kind") or "service") != "task":
        target["lastExit"] = None


def persist_started_app(cfg, app_id, proc, pgid, token):
    """保存新的受控身份并启动退出监视线程。"""
    started_at = time.time()

    def op(c):
        target = find_app(c, app_id)
        if not target:
            return False
        _set_started_runtime(target, proc, pgid, token)
        return True

    saved = cfg.update(op)
    if saved:
        watch_app_exit(cfg, app_id, proc, token, started_at)
    return saved


def cancel_unpersisted_runtime(proc, pgid, token):
    """Force rollback of an unpublished runtime and report proof of cleanup."""
    if IS_WINDOWS and isinstance(proc, SupervisorRuntimeHandle):
        try:
            from supervisor_client import stop_supervisor
            result = stop_supervisor(
                proc.metadata_path, token, force=True,
                timeout=APP_STOP_TIMEOUT_SEC + 3.0)
        except Exception as exc:
            LOG.exception("清理未持久化 supervisor 失败")
            return False, "清理未持久化 supervisor 失败: %s" % exc
        if result.get("ok") and not result.get("running"):
            return True, None
        error = result.get("error") or "supervisor 未确认受管进程已经退出"
        LOG.error("清理未持久化 supervisor 未获确认: %s", error)
        return False, error

    # This is an internal rollback before the runtime identity is durable, so
    # there is no safe opportunity for a later user-confirmed escalation.
    ok, error = stop_pid_tree(pgid, signal.SIGKILL)
    if not ok:
        LOG.error("清理未持久化进程组失败: %s", error)
        return False, error
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _current_user_group_members(pgid):
            return True, None
        time.sleep(0.05)
    error = "未持久化进程组在强制停止后仍有成员存活"
    LOG.error("%s: PGID %s", error, pgid)
    return False, error


def retain_started_runtime_in_memory(cfg, app_id, proc, pgid, token,
                                     persist_error, cleanup_error):
    """Keep an unrolled-back identity controllable without claiming durability."""
    started_at = time.time()
    issue = (
        "应用 %s 的运行身份未能写入磁盘，自动回滚也失败；身份仅保留在当前总控台内存中，"
        "退出总控台前必须停止该应用" % app_id
    )

    def op(c):
        target = find_app(c, app_id)
        if not target:
            return False
        _set_started_runtime(target, proc, pgid, token)
        return True

    retained = cfg.retain_in_memory(op, issue)
    if retained:
        watch_app_exit(cfg, app_id, proc, token, started_at)
        LOG.critical(
            "%s；配置错误: %s；回滚错误: %s",
            issue, persist_error, cleanup_error,
        )
    else:
        LOG.critical(
            "应用 %s 的运行身份落盘失败且回滚失败，配置中已无卡片；"
            "supervisor token 只能由当前请求持有。配置错误: %s；回滚错误: %s",
            app_id, persist_error, cleanup_error,
        )
    return retained


def persist_started_app_or_rollback(cfg, app_id, proc, pgid, token):
    """Commit a started runtime or prove rollback while retaining its token."""
    persist_error = None
    try:
        saved = persist_started_app(cfg, app_id, proc, pgid, token)
    except Exception as exc:
        saved = False
        persist_error = str(exc) or exc.__class__.__name__
    if saved:
        return True, None, False

    cleanup_ok, cleanup_error = cancel_unpersisted_runtime(proc, pgid, token)
    if cleanup_ok:
        if persist_error:
            return (False,
                    "运行身份保存失败，已回滚新进程: %s" % persist_error,
                    False)
        return False, "应用已被删除，已取消启动", False

    retained = retain_started_runtime_in_memory(
        cfg, app_id, proc, pgid, token,
        persist_error or "应用卡片已不存在", cleanup_error,
    )
    error = (
        "运行身份保存失败，自动回滚也失败；%s。配置错误: %s；回滚错误: %s" % (
            ("当前总控台已在内存中保留管理身份，请勿退出并立即停止该应用"
             if retained else
             "当前配置中已无应用卡片，无法建立可恢复管理身份"),
            persist_error or "应用卡片已不存在",
            cleanup_error or "未知错误",
        )
    )
    return False, error, retained


def clear_app_runtime(cfg, app_id, expected_token=None, last_exit=None):
    """清除受控身份；可用 token 防竞态，并可原子写入本次退出结果。"""
    def op(c):
        target = find_app(c, app_id)
        if not target:
            return False
        if expected_token is not None and target.get("runToken") != expected_token:
            return False
        target["lastPid"] = None
        target["lastPgid"] = None
        target["runToken"] = None
        target["processIdentity"] = None
        target["instanceKey"] = None
        target["attached"] = False
        if last_exit is not None:
            target["lastExit"] = last_exit
        return True
    return cfg.update(op)


def stop_app_for_update(cfg, app, timeout=5.0):
    """为修改运行参数安全停止应用；返回 (ok, error, stopped)。"""
    if not app_alive_sign(app):
        return True, None, False
    ok, error = stop_app_and_clear(cfg, app, timeout)
    return ok, error, bool(ok)


def pick_path(what, language="zh"):
    """Open the native file/directory picker. Return (path, canceled)."""
    language = "en" if language == "en" else "zh"
    directory_title = ("Choose a working folder" if language == "en"
                       else "选择工作目录")
    script_title = ("Choose a batch script" if language == "en"
                    else "选择批处理脚本")
    if IS_WINDOWS:
        try:
            import tkinter
            from tkinter import filedialog
            root = tkinter.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            value = (filedialog.askdirectory(title=directory_title)
                     if what == "dir" else
                     filedialog.askopenfilename(
                         title=script_title,
                         filetypes=[
                             (("Scripts" if language == "en" else "脚本"),
                              "*.py *.ps1 *.cmd *.bat"),
                             (("All files" if language == "en" else "所有文件"),
                              "*.*"),
                         ]))
            root.destroy()
            return (os.path.normpath(value), False) if value else (None, True)
        except Exception:
            LOG.exception("Windows 文件选择框失败")
            return None, False
    if what == "dir":
        script = ('POSIX path of (choose folder with prompt "%s")' %
                  directory_title)
    else:
        script = ('POSIX path of (choose file with prompt "%s")' %
                  script_title)
    try:
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=180)
    except Exception:
        return None, False
    if r.returncode != 0:  # 用户按了取消（"User canceled."）
        return None, True
    return r.stdout.strip().rstrip("/") or None, False


def command_for_script(path, execution=None):
    """按脚本类型生成可直接保存的 shell 命令，并安全引用任意文件名。"""
    execution, _ = normalize_execution(execution)
    if IS_WINDOWS and execution["environment"] == "wsl":
        try:
            from console_platform import get_adapter
            return get_adapter(
                system="wsl", distro=execution["distro"]).command_for_script(path)
        except Exception:
            from console_platform.wsl import normalize_wsl_path
            normalized = normalize_wsl_path(str(path), execution["distro"])
            quoted = shlex.quote(normalized)
            suffix = os.path.splitext(normalized)[1].lower()
            return ("python3 -- %s" % quoted if suffix == ".py"
                    else "/bin/sh -- %s" % quoted
                    if suffix in (".sh", ".bash", ".command")
                    else quoted)
    normalized = os.path.abspath(os.path.expanduser(str(path)))
    if IS_WINDOWS and execution["environment"] == "native":
        adapter = _native_adapter()
        if adapter is not None:
            return adapter.command_for_script(normalized)
        quoted = subprocess.list2cmdline([normalized])
        return quoted
    quoted = shlex.quote(normalized)
    suffix = os.path.splitext(normalized)[1].lower()
    if suffix == ".py":
        return "python3 -- %s" % quoted
    if suffix == ".zsh":
        return "/bin/zsh -- %s" % quoted
    if suffix in (".sh", ".bash"):
        return "/bin/bash -- %s" % quoted
    if os.access(normalized, os.X_OK):
        return quoted
    # .command 常见于 Finder 双击脚本；没有执行位时仍可明确交给 bash。
    return "/bin/bash -- %s" % quoted


SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".command",
                   ".ps1", ".cmd", ".bat"}
SHELL_BUILTINS = {
    ".", ":", "[", "alias", "break", "cd", "command", "continue", "echo",
    "eval", "exec", "exit", "export", "false", "printf", "pwd", "read",
    "return", "set", "shift", "source", "test", "true", "type", "ulimit",
    "umask", "unalias", "unset", "wait",
}


def _simple_command_tokens(command, posix=True):
    """解析无管道/重定向/展开的简单命令；不确定时返回 None。"""
    if not isinstance(command, str) or not command.strip():
        return []
    try:
        lexer = shlex.shlex(
            command, posix=posix, punctuation_chars="|&;<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return None
    if not tokens:
        return []
    if any(token and all(char in "|&;<>()" for char in token)
           for token in tokens):
        return None
    # 健康检查绝不展开变量、通配符或命令替换；这类命令照常允许运行。
    if any(any(char in token for char in ("$", "*", "?", "[", "]", "`"))
           for token in tokens):
        return None
    return tokens


def _resolve_command_path(value, cwd, path_module=os.path):
    value = path_module.expanduser(value)
    if path_module.isabs(value):
        return path_module.normpath(value)
    return path_module.normpath(path_module.join(cwd, value))


def _script_target(tokens, cwd, native_windows=False):
    """提取 (路径, 是否直接执行, 原路径是否相对)，否则返回空。"""
    if not tokens:
        return None, False, False
    index = 0
    while index < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index >= len(tokens):
        return None, False, False
    executable = tokens[index]
    path_module = __import__("ntpath") if native_windows else os.path
    executable = executable.strip('"')
    base = path_module.basename(executable).casefold()
    args = tokens[index + 1:]

    if (re.fullmatch(r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?", base)
            or native_windows and base in ("py", "py.exe")):
        if "-m" in args or "-c" in args:
            return None, False, False
        if args and args[0] == "--":
            args = args[1:]
        candidate = next((arg for arg in args if not arg.startswith("-")), None)
        if candidate and (os.path.splitext(candidate)[1].lower() in SCRIPT_SUFFIXES
                          or "/" in candidate):
            return (_resolve_command_path(candidate, cwd, path_module), False,
                    not path_module.isabs(path_module.expanduser(candidate)))
        return None, False, False

    if native_windows and base in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
        file_index = next((index for index, value in enumerate(args)
                           if value.casefold() in ("-file", "-f")), None)
        if file_index is not None and file_index + 1 < len(args):
            candidate = args[file_index + 1].strip('"')
            return (_resolve_command_path(candidate, cwd, path_module), False,
                    not path_module.isabs(path_module.expanduser(candidate)))
        return None, False, False

    if base in {"bash", "sh", "zsh"}:
        if any(arg == "--command"
               or (arg.startswith("-") and "c" in arg[1:])
               for arg in args):
            return None, False, False
        if args and args[0] == "--":
            args = args[1:]
        candidate = next((arg for arg in args if not arg.startswith("-")), None)
        if candidate and (os.path.splitext(candidate)[1].lower() in SCRIPT_SUFFIXES
                          or "/" in candidate):
            return (_resolve_command_path(candidate, cwd, path_module), False,
                    not path_module.isabs(path_module.expanduser(candidate)))
        return None, False, False

    suffix = path_module.splitext(executable)[1].lower()
    has_separator = "/" in executable or native_windows and "\\" in executable
    if suffix in SCRIPT_SUFFIXES or has_separator:
        return (_resolve_command_path(executable, cwd, path_module), True,
                not path_module.isabs(path_module.expanduser(executable)))
    return None, False, False


def inspect_app_health(
        app, *, wsl_distros=_PLATFORM_WSL_UNSET,
        wsl_discovery_ready=True, wsl_discovery_error=None):
    """静态检查配置是否可运行；只读文件系统，绝不执行或展开用户命令。"""
    issues = []

    def add(kind, title, detail, fix, action):
        issues.append({
            "kind": kind,
            "severity": "error",
            "title": title,
            "detail": detail,
            "fix": fix,
            "action": action,
        })

    execution, execution_error = normalize_execution(app.get("execution"))
    if execution_error:
        add("execution-invalid", "运行环境无效", execution_error,
            "编辑应用并重新选择运行环境。", "edit-command")
        return {"status": "error", "blocking": True, "issues": issues}
    if IS_WINDOWS and execution["environment"] == "wsl":
        if wsl_distros is not _PLATFORM_WSL_UNSET:
            # State polling uses only the async monitor snapshot.  In
            # particular, do not fall through to distro_info() or touch a WSL
            # UNC path while discovery is pending/stale/failed: either can
            # block the HTTP request behind wsl.exe or a redirector timeout.
            if not wsl_discovery_ready or wsl_discovery_error:
                return {"status": "unknown", "blocking": False, "issues": []}
            distro = next((
                item for item in (wsl_distros or [])
                if str(item.get("name") or "").casefold()
                == execution["distro"].casefold()
            ), None)
            if distro is None:
                unavailable = "WSL 发行版未安装: %s" % execution["distro"]
            elif distro.get("version") != 2:
                unavailable = (
                    "WSL1 不受支持；请运行 wsl --set-version %s 2"
                    % execution["distro"]
                )
            else:
                # A cached distro record is enough to validate the execution
                # choice.  Filesystem health is checked by explicit actions;
                # monitoring never probes \\wsl.localhost synchronously.
                return {"status": "unknown", "blocking": False, "issues": []}
            add("wsl-unavailable", "WSL 发行版不可用", unavailable,
                "安装 WSL2 发行版或修正卡片的发行版设置。", "edit-command")
            return {"status": "error", "blocking": True, "issues": issues}

        try:
            manager = get_wsl_manager()
            distro = manager.distro_info(
                execution["distro"], require_running=False)
        except Exception as exc:
            add("wsl-unavailable", "WSL 发行版不可用", str(exc),
                "安装 WSL2 发行版或修正卡片的发行版设置。", "edit-command")
            return {"status": "error", "blocking": True, "issues": issues}
        if not distro.get("running"):
            return {"status": "unknown", "blocking": False, "issues": []}
        configured = app.get("cwd")
        if configured:
            try:
                from console_platform.wsl_host import wsl_path_to_windows
                host_cwd = wsl_path_to_windows(configured, execution["distro"])
                if not os.path.isdir(host_cwd):
                    add("cwd-missing", "工作目录不可用",
                        "找不到 WSL 工作目录：%s" % configured,
                        "编辑这个项目并检查发行版与 Linux 路径。", "pick-cwd")
            except Exception as exc:
                add("cwd-missing", "工作目录不可用", str(exc),
                    "编辑这个项目并检查发行版与 Linux 路径。", "pick-cwd")
        return {
            "status": "error" if issues else "unknown",
            "blocking": bool(issues), "issues": issues,
        }

    native_windows = IS_WINDOWS and execution["environment"] == "native"
    path_module = __import__("ntpath") if native_windows else os.path
    configured_cwd = app.get("cwd")
    cwd = configured_cwd or os.path.expanduser("~")
    cwd_ok = os.path.isdir(cwd)
    if configured_cwd and not cwd_ok:
        add(
            "cwd-missing", "工作目录不可用",
            "找不到配置的工作目录：%s" % configured_cwd,
            "编辑这个项目，重新选择工作区文件夹。",
            "pick-cwd",
        )

    tokens = _simple_command_tokens(
        app.get("command") or "", posix=not native_windows)
    if tokens is None:
        return {
            "status": "error" if issues else "unknown",
            "blocking": bool(issues),
            "issues": issues,
        }

    script_path, direct, script_was_relative = _script_target(
        tokens, cwd, native_windows=native_windows)
    if script_path and (cwd_ok or not script_was_relative):
        if not os.path.isfile(script_path):
            add(
                "script-missing", "脚本不可用",
                "找不到脚本：%s" % script_path,
                "编辑这个任务，重新选择脚本或修改执行命令。",
                "pick-script",
            )
        elif not os.access(script_path, os.R_OK):
            add(
                "path-unreadable", "脚本不可读取",
                "当前用户没有读取权限：%s" % script_path,
                "检查脚本权限，或重新选择一个可读取的脚本。",
                "pick-script",
            )
        elif direct and not os.access(script_path, os.X_OK):
            add(
                "script-not-executable", "脚本不可执行",
                "直接运行的脚本没有执行权限：%s" % script_path,
                "给脚本执行权限，或改为使用 bash / python3 执行。",
                "edit-command",
            )

    # 直接脚本已由上面的文件检查覆盖；其他简单命令检查首个运行时。
    index = 0
    while tokens and index < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    executable = tokens[index] if tokens and index < len(tokens) else ""
    executable = executable.strip('"')
    executable_base = path_module.basename(executable)
    if executable and not direct and executable_base not in SHELL_BUILTINS:
        if "/" in executable or native_windows and "\\" in executable:
            runtime = _resolve_command_path(executable, cwd, path_module)
            runtime_ok = os.path.isfile(runtime) and os.access(runtime, os.X_OK)
        else:
            runtime = executable
            runtime_ok = bool(shutil.which(
                executable, path=build_launch_env("health-check").get("PATH")))
        if not runtime_ok:
            add(
                "runtime-missing", "找不到 %s" % executable_base,
                "总控台的运行环境里找不到命令：%s" % executable,
                "安装对应运行时，或在编辑中修改执行命令。",
                "edit-command",
            )

    return {
        "status": "error" if issues else "ok",
        "blocking": bool(issues),
        "issues": issues,
    }


# ---------------------------------------------------------------- 项目启动识别

def _read_project_text(root, name):
    """只读取项目根目录下的小型文本配置；不存在、过大或不可读均返回 None。"""
    path = os.path.join(root, name)
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_DETECT_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(MAX_DETECT_FILE_BYTES + 1)
    except OSError:
        return None


def _port_from_command(command):
    """从常见 CLI 参数和环境变量中提取显式端口。"""
    patterns = (
        r"(?:^|\s)--port(?:=|\s+)(\d{1,5})(?=\s|$)",
        r"(?:^|\s)-p\s+(\d{1,5})(?=\s|$)",
        r"(?:^|\s)PORT\s*=\s*(\d{1,5})(?=\s|$)",
        r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{1,5})",
        r"\bhttp\.server\s+(\d{1,5})(?=\s|$)",
    )
    for pattern in patterns:
        match = re.search(pattern, command, re.IGNORECASE)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port
    return None


def _package_default_port(script_name, command, dependencies):
    """根据直接依赖和脚本内容给出开发服务器的惯用端口。"""
    haystack = " ".join((script_name, command, " ".join(dependencies))).lower()
    defaults = (
        (("hexo",), 4000),
        (("gatsby",), 8000),
        (("@docusaurus/", "docusaurus"), 3000),
        (("vuepress",), 8080),
        (("docsify",), 3000),
        (("eleventy", "@11ty/eleventy"), 8080),
        (("astro",), 4321),
        (("next", "nextjs"), 3000),
        (("nuxt",), 3000),
        (("react-scripts",), 3000),
        (("vue-cli-service", "@vue/cli-service"), 8080),
        (("vite",), 4173 if script_name == "preview" else 5173),
    )
    for needles, port in defaults:
        if any(needle in haystack for needle in needles):
            return port
    return None


def detect_project(root, execution=None):
    """只读分析项目根目录，返回可由启动台直接使用的启动候选。"""
    execution, execution_error = normalize_execution(execution)
    if execution_error:
        return None, execution_error
    native_windows = IS_WINDOWS and execution["environment"] == "native"
    python_command = "py -3" if native_windows else "python3"
    if not isinstance(root, str) or not root.strip():
        return None, "请选择项目文件夹"
    root = os.path.abspath(os.path.expanduser(root.strip()))
    if not os.path.isdir(root):
        return None, "项目文件夹不存在或不可访问"

    candidates = []
    detected_files = []

    def note_file(name, text=None):
        path = os.path.join(root, name)
        exists = text is not None or os.path.isfile(path)
        if exists and name not in detected_files:
            detected_files.append(name)
        return exists

    def add(command, label, source, port=None, priority=50, detail=None,
            kind="service"):
        if not command or any(item["command"] == command for item in candidates):
            return
        if port is not None and not (isinstance(port, int) and 1 <= port <= 65535):
            port = None
        candidates.append({
            "command": command,
            "label": label,
            "source": source,
            "port": port,
            "kind": "task" if kind == "task" else "service",
            "detail": detail,
            "_priority": priority,
        })

    # Node / 前端 / 博客项目：优先读取 package.json 的 scripts。
    package = {}
    scripts = {}
    deps = set()
    hexo_config = os.path.isfile(os.path.join(root, "_config.yml"))
    is_hexo = hexo_config and (
        os.path.isdir(os.path.join(root, "source")) or
        os.path.isdir(os.path.join(root, "scaffolds")) or
        os.path.isdir(os.path.join(root, "themes")))
    package_text = _read_project_text(root, "package.json")
    if package_text is not None:
        note_file("package.json", package_text)
        try:
            package = json.loads(package_text)
        except (TypeError, ValueError):
            package = {}
        scripts = package.get("scripts") if isinstance(package, dict) else {}
        if not isinstance(scripts, dict):
            scripts = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            values = package.get(key) if isinstance(package, dict) else None
            if isinstance(values, dict):
                deps.update(str(name).lower() for name in values)
        is_hexo = (is_hexo or "hexo" in deps or
                   (isinstance(package, dict) and isinstance(package.get("hexo"), dict)))

        if os.path.isfile(os.path.join(root, "pnpm-lock.yaml")):
            runner = "pnpm run"
            note_file("pnpm-lock.yaml")
        elif (os.path.isfile(os.path.join(root, "bun.lock")) or
              os.path.isfile(os.path.join(root, "bun.lockb"))):
            runner = "bun run"
            note_file("bun.lock" if os.path.isfile(os.path.join(root, "bun.lock")) else "bun.lockb")
        elif os.path.isfile(os.path.join(root, "yarn.lock")):
            runner = "yarn"
            note_file("yarn.lock")
        else:
            runner = "npm run"

        labels = {
            "dev": "开发服务器", "develop": "开发服务器",
            "start": "正式启动", "serve": "本地服务", "server": "本地服务",
            "preview": "本地预览", "docs": "文档站",
            "storybook": "组件预览",
        }
        preferred = ("dev", "develop", "start", "serve", "server", "preview", "docs", "storybook")
        ordered = [name for name in preferred if name in scripts]
        service_name = re.compile(r"(?:^|[:_-])(dev|develop|start|serve|server|preview|watch|docs|storybook|web|blog)(?:$|[:_-])", re.I)
        ordered.extend(name for name in scripts if name not in ordered and service_name.search(str(name)))
        for index, name in enumerate(ordered[:8]):
            script = scripts.get(name)
            if not isinstance(script, str):
                continue
            if is_hexo and str(name).lower() == "server" and re.search(
                    r"\bhexo\s+(?:s|server)\b", script, re.I):
                continue  # 下方提供更短、更通用的 hexo s，不重复同一操作
            command = "%s %s" % (runner, shlex.quote(str(name)))
            port = _port_from_command(script)
            if port is None:
                port = _package_default_port(str(name).lower(), script, deps)
            add(command, labels.get(str(name).lower(), "项目脚本：%s" % name),
                "package.json · scripts.%s" % name, port,
                10 + index, "由项目自己的脚本定义")

    # Hexo 即使没有 scripts 也有稳定 CLI：服务与清缓存分别作为服务/任务。
    if is_hexo:
        if hexo_config:
            note_file("_config.yml")
        add("hexo s", "Hexo 本地服务", "Hexo 项目结构", 4000, 8,
            "等同于 hexo server")
        add("hexo cl", "Hexo 清除缓存", "Hexo 项目结构", None, 9,
            "清除缓存和已生成文件，不启动服务", kind="task")

    # 常见博客与静态站点生成器。
    hugo_config = next((name for name in ("hugo.toml", "hugo.yaml", "hugo.yml")
                        if os.path.isfile(os.path.join(root, name))), None)
    if hugo_config or (os.path.isdir(os.path.join(root, "content")) and
                       os.path.isdir(os.path.join(root, "layouts")) and
                       os.path.isfile(os.path.join(root, "config.toml"))):
        source = hugo_config or "config.toml"
        note_file(source)
        add("hugo server -D", "Hugo 本地预览", source, 1313, 18,
            "包含草稿内容")

    gemfile = _read_project_text(root, "Gemfile")
    if gemfile is not None:
        note_file("Gemfile", gemfile)
        if "jekyll" in gemfile.lower():
            add("bundle exec jekyll serve", "Jekyll 本地预览", "Gemfile", 4000, 19)

    # Python Web 项目。
    pyproject = _read_project_text(root, "pyproject.toml")
    requirements = _read_project_text(root, "requirements.txt")
    if pyproject is not None:
        note_file("pyproject.toml", pyproject)
    if requirements is not None:
        note_file("requirements.txt", requirements)
    py_deps = "\n".join(text for text in (pyproject, requirements) if text).lower()
    python_runner = ("uv run" if os.path.isfile(os.path.join(root, "uv.lock"))
                     else python_command + " -m")
    if os.path.isfile(os.path.join(root, "uv.lock")):
        note_file("uv.lock")
    if os.path.isfile(os.path.join(root, "manage.py")):
        note_file("manage.py")
        prefix = "uv run python" if python_runner == "uv run" else python_command
        add(prefix + " manage.py runserver", "Django 开发服务器", "manage.py", 8000, 20)
    else:
        for module_file in ("app.py", "main.py", "server.py"):
            module_text = _read_project_text(root, module_file)
            if module_text is None:
                continue
            module = os.path.splitext(module_file)[0]
            imports_streamlit = re.search(
                r"(?m)^\s*(?:import\s+streamlit\b|from\s+streamlit\b)", module_text)
            imports_fastapi = re.search(
                r"(?m)^\s*(?:import\s+fastapi\b|from\s+fastapi\b)", module_text)
            imports_flask = re.search(
                r"(?m)^\s*(?:import\s+flask\b|from\s+flask\b)", module_text)
            if "streamlit" in py_deps or imports_streamlit:
                note_file(module_file, module_text)
                prefix = "uv run" if python_runner == "uv run" else python_command + " -m"
                add(prefix + " streamlit run " + module_file,
                    "Streamlit 应用", module_file, 8501, 22)
                break
            if "fastapi" in py_deps or imports_fastapi:
                note_file(module_file, module_text)
                prefix = "uv run" if python_runner == "uv run" else python_command + " -m"
                add(prefix + " uvicorn %s:app --reload" % module,
                    "FastAPI 开发服务器", module_file, 8000, 23)
                break
            if "flask" in py_deps or imports_flask:
                note_file(module_file, module_text)
                prefix = "uv run" if python_runner == "uv run" else python_command + " -m"
                add(prefix + " flask --app %s run --debug" % module,
                    "Flask 开发服务器", module_file, 5000, 24)
                break

    # Docker Compose、Go、Rust 和已有的常用启动脚本。
    compose_name = next((name for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
                         if os.path.isfile(os.path.join(root, name))), None)
    if compose_name:
        compose_text = _read_project_text(root, compose_name)
        note_file(compose_name, compose_text)
        port = None
        if compose_text:
            match = re.search(r"[\"']?(\d{2,5})\s*:\s*\d{2,5}[\"']?", compose_text)
            if match and 1 <= int(match.group(1)) <= 65535:
                port = int(match.group(1))
        add("docker compose up", "Docker Compose", compose_name, port, 55,
            "以前台方式运行，停止按钮可正常关闭")
    if os.path.isfile(os.path.join(root, "go.mod")):
        note_file("go.mod")
        add("go run .", "Go 项目", "go.mod", None, 60)
    if os.path.isfile(os.path.join(root, "Cargo.toml")):
        note_file("Cargo.toml")
        add("cargo run", "Rust 项目", "Cargo.toml", None, 61)

    script_names = (("start.ps1", "dev.ps1", "run.ps1",
                     "start.cmd", "dev.cmd", "run.cmd",
                     "start.bat", "dev.bat", "run.bat")
                    if native_windows else
                    ("start.command", "dev.command", "run.command",
                     "start.sh", "dev.sh", "run.sh"))
    for script_name in script_names:
        if os.path.isfile(os.path.join(root, script_name)):
            note_file(script_name)
            if native_windows and script_name.lower().endswith(".ps1"):
                script_command = (
                    "powershell.exe -NoLogo -NoProfile -File %s" %
                    subprocess.list2cmdline([".\\" + script_name]))
            elif native_windows:
                script_command = subprocess.list2cmdline([".\\" + script_name])
            else:
                script_command = "bash %s" % shlex.quote("./" + script_name)
            add(script_command,
                "现有启动脚本", script_name, None, 70,
                "也可以继续使用“选择脚本”手动指定")
            break

    # 纯静态站点最后兜底，避免把 Vite/Next 等项目误当成普通文件目录。
    if not candidates and os.path.isfile(os.path.join(root, "index.html")):
        note_file("index.html")
        add(python_command + " -m http.server 8000",
            "静态网站预览", "index.html", 8000, 90)

    candidates.sort(key=lambda item: item.pop("_priority"))
    return {
        "ok": True,
        "cwd": root,
        "name": os.path.basename(root) or root,
        "files": detected_files,
        "candidates": candidates[:8],
    }, None


def _current_user_group_members(pgid):
    """Return live current-user members of a previously verified group.

    Once SIGTERM is sent the token-bearing controller may exit before a child
    that ignores SIGTERM.  Requiring the marker again would incorrectly report
    success, so the wait phase follows the already-verified PGID until empty.
    """
    members = pgid_members_map().get(pgid, [])
    if not members:
        return []
    snap = ps_snapshot(members, with_uid=True)
    return sorted(pid for pid in members
                  if snap.get(pid, {}).get("uid") == SELF_UID)


def resolve_app_stop_target(app, listeners=None):
    """Resolve and validate a stop target before any signal is sent."""
    if IS_WINDOWS:
        identity = app.get("processIdentity") or {}
        if identity.get("type") == "supervisor":
            status = supervisor_runtime_status(app) or {}
            recovery_pending = bool(
                identity.get("recoveryPending")
                and not status.get("identityMismatch"))
            if not status.get("ok") and not recovery_pending:
                return None, status.get("error") or "无法验证 supervisor 身份"
            if (status.get("ok") and not status.get("running")
                    and status.get("state") not in (
                        "starting", "startup-cleanup-failed")):
                return None, "应用未在运行"
            members = sorted(_native_supervisor_job_processes(app, status))
            return {
                "kind": "supervisor", "id": identity.get("runId"),
                "metadataPath": identity.get("metadataPath"),
                "token": app.get("runToken"),
                "members": members,
            }, None
        if identity.get("type") == "external" and identity.get("environment") == "native":
            verified, error = verify_native_process_identity(
                identity, require_listener=True)
            if error:
                return None, error
            return {"kind": "external-native", "id": verified["pid"],
                    "identity": verified, "members": [verified["pid"]]}, None
        if identity.get("type") == "external" and identity.get("environment") == "wsl":
            verified, error = verify_wsl_process_identity(
                identity, require_listener=True)
            if error:
                return None, error
            return {"kind": "external-wsl", "id": verified["pid"],
                    "identity": verified, "members": [verified["pid"]]}, None
        return None, "无法确认受控进程，未执行停止"
    current = managed_pids(app)
    if current:
        pgid = app.get("lastPgid") or app.get("lastPid")
        if isinstance(pgid, int) and pgid > 0:
            return {"kind": "group", "id": pgid, "members": list(current)}, None
        return None, "受控进程组信息无效"
    legacy_pid = legacy_managed_pid(app, listeners)
    if legacy_pid:
        if app.get("attached"):
            try:
                pgid = os.getpgid(legacy_pid)
            except (ProcessLookupError, PermissionError, OSError):
                pgid = None
            if isinstance(pgid, int) and pgid > 0 and pgid != os.getpgrp():
                members = _current_user_group_members(pgid)
                member_cwds = lsof_cwds(members)
                expected_cwd = app.get("cwd")
                try:
                    safe_group = bool(members and expected_cwd) and all(
                        member_cwds.get(pid)
                        and os.path.realpath(member_cwds[pid])
                        == os.path.realpath(expected_cwd)
                        for pid in members
                    )
                except OSError:
                    safe_group = False
                if safe_group:
                    return {
                        "kind": "group",
                        "id": pgid,
                        "members": list(members),
                    }, None
        return {"kind": "pid", "id": legacy_pid, "members": [legacy_pid]}, None
    return None, "无法确认受控进程，未执行停止"


class ProcessControlError(str):
    def __new__(cls, value, *, requires_force=False):
        result = str.__new__(cls, value)
        result.requires_force = bool(requires_force)
        return result


def signal_app_stop(target, sig=signal.SIGTERM, force=False):
    """Signal a target returned by resolve_app_stop_target."""
    ident = target["id"]
    if target["kind"] == "supervisor":
        try:
            from supervisor_client import stop_supervisor
            result = stop_supervisor(
                target["metadataPath"], target["token"], force=force,
                timeout=APP_STOP_TIMEOUT_SEC + 3.0)
        except Exception as exc:
            return False, ProcessControlError(str(exc))
        if result.get("ok") and not result.get("running"):
            return True, None
        return False, ProcessControlError(
            result.get("error") or "supervisor 未能停止应用",
            requires_force=bool(result.get("requiresForce") and not force))
    if target["kind"] == "external-native":
        verified, error = verify_native_process_identity(
            target["identity"], require_listener=True)
        if error:
            return False, ProcessControlError(error)
        if not force:
            return False, ProcessControlError(
                "外部 Windows 进程无法证明安全的优雅树停止；请确认后强制结束",
                requires_force=True)
        try:
            adapter = _native_adapter()
            if adapter is None:
                raise RuntimeError("Windows 平台适配器不可用")
            adapter.terminate_process(verified)
            return True, None
        except Exception as exc:
            return False, ProcessControlError("强制结束失败: %s" % exc)
    if target["kind"] == "external-wsl":
        try:
            result = get_wsl_manager().process_control(
                target["identity"], "force-stop" if force else "stop",
                timeout_ms=int(APP_STOP_TIMEOUT_SEC * 1000))
        except Exception as exc:
            return False, ProcessControlError(str(exc))
        if result.get("ok") and not result.get("running"):
            return True, None
        return False, ProcessControlError(
            result.get("error") or "WSL 进程未退出",
            requires_force=bool(result.get("requiresForce") and not force))
    if target["kind"] == "group":
        return stop_pid_tree(ident, sig)
    try:
        os.kill(ident, sig)
        return True, None
    except ProcessLookupError:
        return True, None
    except PermissionError:
        return False, "没有权限停止受控进程"
    except OSError as e:
        return False, "停止受控进程失败: %s" % e


def stop_target_alive(target, expected_uid=None):
    if target["kind"] == "supervisor":
        try:
            from supervisor_client import status_supervisor
            status = status_supervisor(
                target["metadataPath"], target["token"], timeout=2.0)
            return bool(status.get("ok") and status.get("running"))
        except Exception:
            return True
    if target["kind"] == "external-native":
        verified, _error = verify_native_process_identity(
            target["identity"], require_listener=False)
        return verified is not None
    if target["kind"] == "external-wsl":
        verified, _error = verify_wsl_process_identity(
            target["identity"], require_listener=False)
        return verified is not None
    if target["kind"] == "group":
        try:
            os.killpg(target["id"], 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return True
    try:
        os.kill(target["id"], 0)
        if expected_uid is None:
            expected_uid = process_uid(target["id"])
        return expected_uid == SELF_UID
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True


def stop_app_and_wait(app, timeout=APP_STOP_TIMEOUT_SEC, listeners=None,
                      force=False):
    """Signal a verified app and wait until the exact target is gone.

    Returns (ok, error).  A timeout is deliberately not escalated to SIGKILL;
    the caller keeps the runtime token so the user can retry or choose a force
    action without losing control of a still-live process.
    """
    target, error = resolve_app_stop_target(app, listeners)
    if target is None:
        return False, error
    # Windows has no signal.SIGKILL.  Supervisor and identity-checked native
    # targets use the explicit ``force`` flag; the signal value is only used
    # by the POSIX process/group fallback below.
    stop_signal = signal.SIGTERM
    if force and not IS_WINDOWS:
        stop_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    ok, error = signal_app_stop(target, stop_signal, force=force)
    if not ok:
        return False, error
    if target["kind"] == "supervisor":
        return True, None
    deadline = time.monotonic() + max(0.0, timeout)
    # uid 只查一次：信号已在循环外发出，循环仅做存活探测，
    # 避免 50ms 一次的 ps 子进程（PID 复用时最坏多等一个超时周期，无副作用）。
    expected_uid = (process_uid(target["id"]) if target["kind"] == "pid"
                    else None)
    while stop_target_alive(target, expected_uid):
        if time.monotonic() >= deadline:
            # Only a POSIX process-group target needs a fresh group scan.
            # Windows/WSL external identities carry platform-local PIDs that
            # must never be interpreted as a host POSIX PGID merely to format
            # a timeout diagnostic.
            remaining = (_current_user_group_members(target["id"])
                         if target["kind"] == "group"
                         else list(target.get("members") or []))
            suffix = "（PID %s）" % "、".join(str(p) for p in remaining) if remaining else ""
            return False, ProcessControlError(
                "应用未在 %.1f 秒内退出%s，仍保留管理状态" % (timeout, suffix),
                requires_force=not force)
        time.sleep(0.05)
    return True, None


def stop_app_and_clear(cfg, app, timeout=APP_STOP_TIMEOUT_SEC, listeners=None,
                       force=False):
    """Manual stop transaction: wait first, clear persisted identity last."""
    marker = (app.get("id"), app.get("runToken"))
    with MANUAL_STOP_LOCK:
        MANUAL_STOP_TOKENS.add(marker)
    try:
        ok, error = stop_app_and_wait(
            app, timeout, listeners, force=force)
        if not ok:
            return False, error
        last_exit = None
        if (app.get("kind") or "service") == "task":
            # 覆盖可能保留的旧成功记录，避免“刚刚手动停止”仍显示上次成功。
            last_exit = {
                "status": "stopped",
                "code": None,
                "at": int(time.time()),
            }
        if not clear_app_runtime(
                cfg, app["id"], app.get("runToken"), last_exit=last_exit):
            return False, "进程已停止，但应用状态已变化，请刷新后重试"
        return True, None
    finally:
        with MANUAL_STOP_LOCK:
            MANUAL_STOP_TOKENS.discard(marker)


def inspect_attach_process(cfg, app, pid=None, instance_key=None):
    """只读校验待认领进程，返回其可信工作目录。

    创建卡片时先调用本函数，再把卡片与运行身份一次写入配置，避免前端
    “先创建、再认领”只完成一半。已有卡片的手动认领也复用同一套校验。"""
    if (app.get("kind") or "service") != "service":
        return False, "批处理任务没有端口，无法认领进程", {"status": 422}
    port = app.get("port")
    if not isinstance(port, int) or port <= 0:
        return False, "卡片未配置端口，无法认领进程", {"status": 422}
    if app_alive_sign(app):
        return False, "应用已在运行", {"status": 409}
    execution = app.get("execution") or normalize_execution(None)[0]
    if IS_WINDOWS:
        payload = parse_instance_key(instance_key)
        if not payload:
            return False, "Windows/WSL 认领必须使用有效 instanceKey", {"status": 400}
        if payload.get("environment") != execution.get("environment"):
            return False, "进程运行环境与卡片不一致", {"status": 409}
        if execution.get("environment") == "wsl":
            if str(payload.get("distro") or "").casefold() != str(
                    execution.get("distro") or "").casefold():
                return False, "WSL 发行版与卡片不一致", {"status": 409}
            identity, error = verify_wsl_instance_key(
                instance_key, require_listener=True)
            if error:
                return False, error, {"status": 409}
            if identity.get("port") != port:
                return False, "instanceKey 的监听端口与卡片不一致", {"status": 409}
            actual_cwd = identity.get("cwd")
            if not actual_cwd:
                return False, "无法读取 WSL 进程工作目录", {"status": 409}
            cfg_now = cfg.snapshot()
            for other in cfg_now.get("apps") or []:
                other_identity = other.get("processIdentity") or {}
                if (other.get("id") != app.get("id")
                        and same_runtime_identity(other_identity, identity)):
                    return False, "该 WSL 进程已由其他卡片管理", {"status": 409}
            return True, None, {
                "status": 200, "cwd": actual_cwd, "pid": identity["pid"],
                "processIdentity": identity,
            }
        identity, _info, error = verify_native_instance_key(
            instance_key, require_listener=True)
        if error:
            return False, error, {"status": 409}
        pid = identity["pid"]
        if identity.get("port") != port:
            return False, "instanceKey 的监听端口与卡片不一致", {"status": 409}
        actual_cwd = identity.get("cwd")
        if not actual_cwd:
            return False, "无法读取进程工作目录，已取消认领", {"status": 409}
        cfg_now = cfg.snapshot()
        for other in cfg_now.get("apps") or []:
            other_identity = other.get("processIdentity") or {}
            if (other.get("id") != app.get("id")
                    and same_runtime_identity(other_identity, identity)):
                return False, "该进程已由其他卡片管理", {"status": 409}
        return True, None, {
            "status": 200, "cwd": actual_cwd,
            "pid": pid, "processIdentity": identity,
        }
    if pid == os.getpid():
        return False, "不能认领总控台自身", {"status": 409}
    listeners = scan_listeners()
    if (pid, port) not in listeners:
        return False, "PID %d 并未监听端口 %d，进程可能已退出" % (pid, port), {"status": 409}
    snap = ps_snapshot({pid}, with_uid=True)
    if snap.get(pid, {}).get("uid") != SELF_UID:
        return False, "该进程不属于当前用户，不能认领", {"status": 403}
    cfg_now = cfg.snapshot()
    owners = listener_app_owners(cfg_now.get("apps") or [], listeners, snap, None)
    if pid in owners:
        return False, "该进程已由卡片「%s」管理" % owners[pid].get("name", ""), {"status": 409}
    actual_cwd = lsof_cwds({pid}).get(pid)
    if not actual_cwd:
        return False, "无法读取进程工作目录，已取消认领", {"status": 409}
    return True, None, {"status": 200, "cwd": actual_cwd, "pid": pid}


def attach_app_process(cfg, app_id, app, pid=None, instance_key=None):
    """把已在监听配置端口的当前用户进程认领为本卡片受管进程。

    认领走旧版身份通道（lastPid + 监听端口 + 当前 UID + 真实 cwd 四重校验），
    与卡片 cwd 不一致时原子同步卡片 cwd。认领后卡片显示运行中，可正常
    停止/重启（重启后转为 token 受管）。返回 (ok, error, info)。"""
    cwd_updated = False
    pid_conflict = False
    validation_failure = None
    claimed = {}

    def op(c):
        nonlocal cwd_updated, pid_conflict, validation_failure
        target = find_app(c, app_id)
        if not target:
            return False
        # Live identity verification and the config write share the same
        # re-entrant Config lock.  This prevents another request from winning
        # a stale pre-lock verification window or changing the target card
        # before the exact PID/create-time/boot identity is persisted.
        ok, error, identity = inspect_attach_process(
            cfg, target, pid, instance_key=instance_key)
        if not ok:
            validation_failure = (error, identity)
            return False
        actual_cwd = identity["cwd"]
        claimed_pid = identity.get("pid", pid)
        process_identity = identity.get("processIdentity")
        for other in c.get("apps") or []:
            if other.get("id") == app_id:
                continue
            other_identity = other.get("processIdentity") or {}
            same_identity = same_runtime_identity(
                other_identity, process_identity)
            if same_identity or (not process_identity
                                 and other.get("lastPid") == claimed_pid):
                pid_conflict = True
                return False
        target["lastPid"] = claimed_pid
        target["lastPgid"] = None
        target["runToken"] = None
        target["processIdentity"] = process_identity
        target["instanceKey"] = None
        target["attached"] = True
        target["lastExit"] = None
        try:
            same = (isinstance(target.get("cwd"), str) and target["cwd"]
                    and os.path.realpath(target["cwd"]) == os.path.realpath(actual_cwd))
        except OSError:
            same = False
        if not same:
            target["cwd"] = actual_cwd
            cwd_updated = True
        claimed.update({"pid": claimed_pid, "cwd": actual_cwd})
        return True

    if not cfg.update(op):
        if validation_failure is not None:
            error, info = validation_failure
            return False, error, info
        if pid_conflict:
            return False, "该进程已由其他卡片管理", {"status": 409}
        return False, "应用已被删除", {"status": 404}
    info = {"pid": claimed["pid"]}
    if cwd_updated:
        info["cwdUpdated"] = True
        info["cwd"] = claimed["cwd"]
    return True, None, info


# ---------------------------------------------------------------- 日志

def rotate_log_file(path, max_bytes=MAX_LOG_BYTES, backups=LOG_BACKUPS):
    """超限后 copy-truncate，保持子进程已打开的文件描述符继续可写。"""
    with LOG_LOCK:
        try:
            if os.path.getsize(path) <= max_bytes:
                return False
        except OSError:
            return False
        try:
            for index in range(backups, 1, -1):
                older = "%s.%d" % (path, index - 1)
                newer = "%s.%d" % (path, index)
                if os.path.exists(older):
                    os.replace(older, newer)
            shutil.copyfile(path, path + ".1")
            if not IS_WINDOWS:
                os.chmod(path + ".1", 0o600)
            with open(path, "r+b") as f:
                f.truncate(0)
            if not IS_WINDOWS:
                os.chmod(path, 0o600)
            return True
        except OSError:
            LOG.exception("轮转日志失败: %s", path)
            return False


def _tail_file_lines(path, count, block_size=65536):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            chunks = []
            newlines = 0
            while pos > 0 and newlines <= count:
                size = min(block_size, pos)
                pos -= size
                f.seek(pos)
                chunk = f.read(size)
                if not chunk.strip(b"\x00"):
                    break  # 空洞/被外部截断后残留的 NUL 段：之前没有内容，停止回扫
                chunks.append(chunk)
                newlines += chunk.count(b"\n")
        data = b"".join(reversed(chunks))
        return data.decode("utf-8", errors="replace").splitlines()[-count:]
    except OSError:
        return []


def read_log_tail(app_id, count):
    """从当前日志和轮转备份中高效读取最后 count 行。"""
    path = os.path.join(LOGS_DIR, "%s.log" % app_id)
    rotate_log_file(path)
    collected = []
    with LOG_LOCK:
        for candidate in [path] + ["%s.%d" % (path, i)
                                   for i in range(1, LOG_BACKUPS + 1)]:
            remaining = count - len(collected)
            if remaining <= 0:
                break
            lines = _tail_file_lines(candidate, remaining)
            collected = lines + collected
    return "\n".join(collected[-count:])


def start_log_maintenance():
    def _maintain():
        while True:
            try:
                for name in os.listdir(LOGS_DIR):
                    if name.endswith(".log"):
                        rotate_log_file(os.path.join(LOGS_DIR, name))
            except OSError:
                LOG.exception("日志维护失败")
            time.sleep(LOG_MAINTENANCE_SEC)
    threading.Thread(target=_maintain, daemon=True).start()


def sniff_image(data):
    """magic bytes 校验 → "png" / "jpg" / "webp" / None。"""
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


# ---------------------------------------------------------------- 站点图标抓取

ICON_LINK_RE = re.compile(
    r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


def is_loopback_service_url(url, port):
    """仅允许抓取指定端口的明文 loopback URL，避免 favicon SSRF。"""
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == "http"
                and (parsed.hostname or "").lower() in (
                    "127.0.0.1", "localhost", "::1")
                and parsed.port == port
                and not parsed.username and not parsed.password)
    except (TypeError, ValueError, UnicodeError):
        return False


class LoopbackRedirectHandler(urllib.request.HTTPRedirectHandler):
    """只跟随仍停留在同一 loopback 端口的重定向。"""

    def __init__(self, port):
        super().__init__()
        self.port = port

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_loopback_service_url(newurl, self.port):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url, port, timeout=3, limit=262144):
    """GET → (bytes, content-type) | (None, None)。仅抓同一 loopback 端口。"""
    if not is_loopback_service_url(url, port):
        return None, None
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Console/1.0", "Accept": "*/*"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), LoopbackRedirectHandler(port))
        with opener.open(req, timeout=timeout) as response:
            return response.read(limit), (
                response.headers.get("Content-Type") or "")
    except Exception:
        return None, None


def is_exact_service_url(url, host, port):
    """Allow one discovered WSL endpoint only; never redirect across hosts."""
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == "http"
                and (parsed.hostname or "").casefold() == str(host).casefold()
                and parsed.port == int(port)
                and not parsed.username and not parsed.password)
    except (TypeError, ValueError, UnicodeError):
        return False


class ExactEndpointRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, host, port):
        super().__init__()
        self.host, self.port = host, int(port)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_exact_service_url(newurl, self.host, self.port):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get_exact_endpoint(url, host, port, timeout=3, limit=262144):
    if not is_exact_service_url(url, host, port):
        return None, None
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Console/1.0", "Accept": "*/*"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            ExactEndpointRedirectHandler(host, port))
        with opener.open(req, timeout=timeout) as response:
            return response.read(limit), (
                response.headers.get("Content-Type") or "")
    except Exception:
        return None, None


def sniff_icon_bytes(data, ctype=""):
    """→ "png" / "jpg" / "webp" / "ico" / None。拒绝主动 SVG 内容。"""
    if len(data) >= 4 and data[:4] == b"\x00\x00\x01\x00":
        return "ico"
    ext = sniff_image(data)
    if ext:
        return ext
    return None


def fetch_favicon(port, host="127.0.0.1"):
    """抓本地站点图标 → (bytes, ext) | (None, None)。
    先解析首页 <link rel=...icon...>（含 apple-touch-icon），兜底 /favicon.ico。"""
    if host not in ("127.0.0.1", "localhost"):
        host = "127.0.0.1"
    base = "http://%s:%d" % (host, port)
    candidates = []
    html, _ = http_get(base + "/", port)
    if html:
        text = html.decode("utf-8", errors="replace")
        for m in ICON_LINK_RE.finditer(text):
            hm = HREF_RE.search(m.group(0))
            if hm:
                url = urllib.parse.urljoin(base + "/", hm.group(1))
                if is_loopback_service_url(url, port):
                    candidates.append(url)
    candidates.append(base + "/favicon.ico")
    for url in candidates[:4]:
        data, ctype = http_get(url, port, limit=1024 * 1024)
        if data:
            ext = sniff_icon_bytes(data, ctype)
            if ext:
                return data, ext
    return None, None


def fetch_wsl_favicon(port, hosts):
    """Try only endpoints discovered for this WSL service, without proxies."""
    for host in [str(value) for value in hosts if value]:
        display_host = "[%s]" % host if ":" in host and not host.startswith("[") else host
        base = "http://%s:%d" % (display_host, port)
        candidates = []
        html, _ = http_get_exact_endpoint(base + "/", host, port)
        if html:
            text = html.decode("utf-8", errors="replace")
            for match in ICON_LINK_RE.finditer(text):
                href = HREF_RE.search(match.group(0))
                if href:
                    url = urllib.parse.urljoin(base + "/", href.group(1))
                    if is_exact_service_url(url, host, port):
                        candidates.append(url)
        candidates.append(base + "/favicon.ico")
        for url in candidates[:4]:
            data, ctype = http_get_exact_endpoint(
                url, host, port, limit=1024 * 1024)
            if data:
                ext = sniff_icon_bytes(data, ctype)
                if ext:
                    return data, ext
    return None, None


def find_app(cfg, app_id):
    for app in cfg.get("apps") or []:
        if app.get("id") == app_id:
            return app
    return None


def diagnose_app(cfg, app):
    """规则诊断：退出码 + 日志模式 + 文件系统检查 → 可执行的修复建议列表。

    覆盖常见失败：依赖未装、命令/脚本不存在、运行时缺失、npm 脚本名错误、
    端口占用、权限不足、Python 包缺失。
    """
    issues = []

    def add(kind, title, detail, fix, action=None):
        if not any(i["kind"] == kind for i in issues):
            issue = {"kind": kind, "title": title,
                     "detail": detail, "fix": fix}
            if action:
                issue["action"] = action
            issues.append(issue)

    app_id = app.get("id") or ""
    cwd = app.get("cwd") or ""
    last_exit = app.get("lastExit") or {}
    code = last_exit.get("code")
    port = app.get("port")
    log_tail = read_log_tail(app_id, 150) if app_id else ""
    log_lower = log_tail.lower()

    # ---- 配置层检查（不依赖日志） ----
    for health_issue in inspect_app_health(app).get("issues", []):
        add(
            health_issue["kind"],
            health_issue["title"],
            health_issue["detail"],
            health_issue["fix"],
            health_issue.get("action"),
        )

    pkg_json = os.path.join(cwd, "package.json") if cwd else ""
    has_pkg = bool(cwd) and os.path.isfile(pkg_json)
    has_node_modules = bool(cwd) and os.path.isdir(os.path.join(cwd, "node_modules"))
    if has_pkg and not has_node_modules:
        mgr = ("yarn" if os.path.isfile(os.path.join(cwd, "yarn.lock"))
               else "pnpm" if os.path.isfile(os.path.join(cwd, "pnpm-lock.yaml"))
               else "npm")
        add("deps-missing", "依赖未安装（node_modules 缺失）",
            "目录里有 package.json，但没有 node_modules。",
            "终端执行：cd \"%s\" && %s install，装完再启动。" % (cwd, mgr))

    # ---- 日志模式匹配 ----
    m = re.search(r"cannot find module '([^']+)'", log_lower)
    if m:
        add("deps-missing", "找不到模块 %s" % m.group(1),
            "日志报 Cannot find module '%s'，通常是依赖没装或装坏了。" % m.group(1),
            "终端执行：cd \"%s\" && npm install（仍报错再 rm -rf node_modules 后重装）。" % (cwd or "<项目目录>"))

    m = re.search(r"(?:env: )?(\S+): (?:no such file or directory|command not found)", log_lower)
    if m and "cannot find module" not in log_lower:
        add("runtime-missing", "找不到运行时：%s" % m.group(1),
            "系统里找不到 %s 这个命令。" % m.group(1),
            "确认该运行时已安装（如 node / python3 / pnpm）；总控台启动时会补常见 PATH，但程序本身需要存在。")

    if "missing script" in log_lower and has_pkg:
        script_names = []
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                script_names = list((json.load(f).get("scripts") or {}).keys())
        except Exception:
            pass
        hint = ("package.json 里可用的脚本：%s。" % "、".join(script_names)
                if script_names else "package.json 里没有 scripts。")
        add("npm-script", "npm 脚本名写错了",
            "日志报 missing script。%s" % hint,
            "把启动命令改成上面列出的脚本名，例如 npm run %s。" % (script_names[0] if script_names else "dev"))

    if "eaddrinuse" in log_lower or "address already in use" in log_lower:
        add("port-busy", "端口被占用",
            "日志报地址已占用%s。" % ("（:%s）" % port if port else ""),
            "点卡片上的端口数字看是谁占用的，停掉它或给本应用换个端口。")

    if "eacces" in log_lower or "permission denied" in log_lower:
        add("perm", "权限不足",
            "日志报权限不足（EACCES / permission denied）。",
            "检查文件/目录权限；脚本需要可执行权限：chmod +x <脚本>。不要简单用 sudo 运行。")

    m = re.search(r"modulenotfounderror: no module named '([^']+)'", log_lower)
    if m:
        add("pip-missing", "缺少 Python 包：%s" % m.group(1),
            "日志报 ModuleNotFoundError: No module named '%s'。" % m.group(1),
            "建议在项目目录建虚拟环境再装：python3 -m venv .venv && .venv/bin/pip install %s" % m.group(1))

    if re.search(r"no such file or directory", log_lower) and not issues:
        add("file-missing", "命令里的文件/脚本不存在",
            "日志报 No such file or directory，命令里引用的路径可能写错了。",
            "检查启动命令和工作目录里的相对路径是否正确。")

    # ---- 退出码兜底 ----
    if not issues:
        if code == 126:
            add("not-exec", "命令没有执行权限（exit 126）",
                "退出码 126 表示文件不可执行。",
                "给脚本加执行权限：chmod +x <脚本>，或用 bash <脚本> 启动。")
        elif code == 127:
            add("not-found", "命令不存在（exit 127）",
                "退出码 127 表示 shell 找不到这个命令。",
                "确认命令已安装且在 PATH 里；总控台会补常见路径，但程序本身要存在。")
        elif (isinstance(code, int) and code == 0
              and (app.get("kind") or "service") != "task"):
            add("quick-exit", "命令立即正常退出（exit 0）",
                "进程启动后马上正常结束——长期服务命令不应立刻退出。",
                "确认写的是常驻命令（如 hexo s / npm run dev），而不是一次就完成的命令。")
        elif isinstance(code, int) and code < 0:
            add("signaled", "进程被信号终止（signal %d）" % -code,
                "进程不是自然退出，是被系统信号杀掉的。",
                "常见于内存不足被系统回收或外部 kill；查看系统日志确认原因。")

    # ---- 汇总 ----
    if issues:
        summary = "发现 %d 个可能原因，按「修复建议」处理后再启动。" % len(issues)
    elif not log_tail.strip():
        summary = "暂无日志可供诊断；先启动一次让日志产生，再看完整日志定位。"
    elif code is None:
        summary = "该应用还没有退出记录；当前日志未见明显异常。"
    else:
        summary = "日志里没有命中常见错误模式，建议打开完整日志人工排查。"
    return {"ok": True, "issues": issues, "summary": summary}


def validate_port(value):
    """→ (port|None, error|None)。接受 null / 整数 / 数字字符串，范围 1-65535。"""
    if value is None or value == "":
        return None, None
    if isinstance(value, bool):
        return None, "port 必须是 1-65535 的整数"
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        return None, "port 必须是 1-65535 的整数"
    if not (1 <= port <= 65535):
        return None, "port 必须在 1-65535 之间"
    return port, None


def validate_app_fields(data, partial):
    """校验/规范化应用字段。partial=True 时仅校验出现的字段。
    返回 (fields, error)：fields 为规范化后的字段子集。"""
    fields = {}
    for key in ("name", "command"):
        if key in data:
            v = data[key]
            if not isinstance(v, str) or not v.strip():
                return None, "字段 %s 必须是非空字符串" % key
            fields[key] = v.strip()
        elif not partial:
            return None, "缺少字段 %s" % key
    if "cwd" in data:
        v = data["cwd"]
        if v is not None and not isinstance(v, str):
            return None, "cwd 必须是字符串或 null"
        fields["cwd"] = (v or "").strip() or None if isinstance(v, str) else None
    elif not partial:
        fields["cwd"] = None
    if "port" in data:
        port, err = validate_port(data["port"])
        if err:
            return None, err
        fields["port"] = port
    elif not partial:
        fields["port"] = None
    if "emoji" in data:
        v = data["emoji"]
        if v is not None and not isinstance(v, str):
            return None, "emoji 必须是字符串或 null"
        fields["emoji"] = (v or None)
    elif not partial:
        fields["emoji"] = None
    if "glyph" in data:
        v = data["glyph"]
        if v is not None and (not isinstance(v, str) or len(v) > 40):
            return None, "glyph 必须是字符串或 null"
        fields["glyph"] = (v or None)
    elif not partial:
        fields["glyph"] = None
    if "kind" in data:
        if data["kind"] not in ("service", "task"):
            return None, "kind 必须是 service/task"
        fields["kind"] = data["kind"]
    elif not partial:
        fields["kind"] = "service"
    if "execution" in data:
        execution, err = normalize_execution(data["execution"])
        if err:
            return None, err
        fields["execution"] = execution
    elif not partial:
        execution, _ = normalize_execution(None)
        fields["execution"] = execution
    if fields.get("kind") == "task":
        fields["port"] = None  # 批处理任务无端口语义
    return fields, None


# ---------------------------------------------------------------- HTTP 处理

def serialized_app_operation(fn):
    """Reject overlapping mutations for one app instead of racing/queueing."""
    @functools.wraps(fn)
    def wrapped(self, app_id, *args, **kwargs):
        lock = self.server.try_app_operation(app_id)
        if lock is None:
            self.send_err(409, "该应用正在执行其他操作，请稍后重试")
            return None
        try:
            return fn(self, app_id, *args, **kwargs)
        finally:
            lock.release()
    return wrapped


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler_cls, cfg, port):
        super().__init__(addr, handler_cls)
        self.cfg = cfg
        self.console_port = self.server_address[1]
        self.control_token = secrets.token_urlsafe(32)
        self._app_locks = {}
        self._app_locks_guard = threading.Lock()
        self._console_action_guard = threading.Lock()
        self._console_action = None
        self._console_helper_pid = None

    def handle_error(self, request, client_address):
        """空闲连接超时 / 客户端中途断开属正常现象，不刷 traceback。"""
        exc_type, exc, _ = sys.exc_info()
        if exc_type and isinstance(exc, (TimeoutError, BrokenPipeError,
                                         ConnectionResetError)):
            return
        super().handle_error(request, client_address)

    def try_app_operation(self, app_id):
        with self._app_locks_guard:
            lock = self._app_locks.setdefault(app_id, threading.Lock())
        return lock if lock.acquire(blocking=False) else None

    def forget_app_lock(self, app_id):
        """应用删除后回收其操作锁（调用方应已持有该锁）。"""
        with self._app_locks_guard:
            self._app_locks.pop(app_id, None)

    def reserve_console_action(self, action):
        with self._console_action_guard:
            if self._console_action is not None:
                return False, self._console_action, self._console_helper_pid
            self._console_action = action
            return True, action, None

    def set_console_helper_pid(self, pid):
        with self._console_action_guard:
            self._console_helper_pid = pid

    def release_console_action(self, action):
        with self._console_action_guard:
            if self._console_action == action:
                self._console_action = None
                self._console_helper_pid = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Console/%s" % APP_VERSION
    # 每连接 socket 超时：慢速/谎报 Content-Length 的客户端无法无限占住
    # 线程（默认 None 会永久阻塞 rfile.read）；空闲 keep-alive 连接也会回收。
    SOCKET_TIMEOUT_SEC = 30.0

    def setup(self):
        super().setup()
        try:
            self.connection.settimeout(self.SOCKET_TIMEOUT_SEC)
        except OSError:
            pass

    # ---------- 基础工具 ----------

    def log_message(self, fmt, *args):
        try:
            if self.path.startswith("/api/state"):
                return  # 2s 轮询不刷日志
        except Exception:
            pass
        message = "%s - %s" % (self.client_address[0], fmt % args)
        stream = sys.stderr
        if stream is not None and hasattr(stream, "write"):
            try:
                stream.write(message + "\n")
                return
            except Exception:
                # PyInstaller's windowed host normally exposes no stderr, and
                # a replaced/closed stream must not abort an HTTP response.
                pass
        LOG.info("%s", message)

    def _parsed_request_host(self):
        """Return (hostname, port) only for the exact local console origin."""
        raw = (self.headers.get("Host") or "").strip()
        if not raw or any(ch in raw for ch in "\r\n,@/"):
            return None
        try:
            parsed = urllib.parse.urlsplit("http://" + raw)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
        except (ValueError, UnicodeError):
            return None
        if hostname not in ("127.0.0.1", "localhost", "::1"):
            return None
        if port != self.server.console_port:
            return None
        return hostname, port

    def _request_host_allowed(self):
        if self._parsed_request_host() is None:
            return False
        try:
            return self.client_address[0] in ("127.0.0.1", "::1")
        except (AttributeError, IndexError):
            return False

    def _same_origin(self, origin, host):
        try:
            parsed = urllib.parse.urlsplit(origin)
            port = parsed.port or (80 if parsed.scheme == "http" else 443)
            return (parsed.scheme == "http"
                    and (parsed.hostname or "").lower() == host[0]
                    and port == host[1]
                    and not parsed.username and not parsed.password
                    and not parsed.path and not parsed.query and not parsed.fragment)
        except (ValueError, UnicodeError):
            return False

    def _has_control_cookie(self):
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie") or "")
            morsel = cookie.get("console_session")
            return bool(morsel and secrets.compare_digest(
                morsel.value, self.server.control_token))
        except (KeyError, TypeError, ValueError):
            return False

    def _deny_request(self, status, message):
        # Do not consume attacker-controlled bodies. Closing after the bounded
        # JSON error prevents keep-alive request smuggling via leftover bytes.
        self.close_connection = True
        self.send_err(status, message)
        return False

    def _handle_request_error(self, method, exc):
        """请求处理异常统一入口：细节只进日志，响应不回内部信息。"""
        LOG.exception("%s %s 处理失败", method, self.path)
        try:
            self.send_err(500, "服务器错误")
        except Exception:
            pass

    def authorize_request(self, mutating=False, content_kind=None):
        """Enforce the loopback browser trust boundary.

        Browser writes require exact same-origin metadata plus the HttpOnly
        session cookie issued by this process. Headerless local CLI clients stay
        compatible, but JSON/image Content-Type rules keep those paths
        unavailable to simple cross-site HTML forms.
        """
        host = self._parsed_request_host()
        if host is None or not self._request_host_allowed():
            return self._deny_request(421, "请求 Host 不是当前本地控制台")
        if not mutating:
            return True

        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        origin = (self.headers.get("Origin") or "").strip()
        if site and site not in ("same-origin", "none"):
            return self._deny_request(403, "拒绝跨站控制请求")
        if origin and not self._same_origin(origin, host):
            return self._deny_request(403, "请求 Origin 不是当前控制台")
        if (site or origin) and not self._has_control_cookie():
            return self._deny_request(403, "控制会话已失效，请刷新页面")

        if self.headers.get("Transfer-Encoding"):
            return self._deny_request(400, "不支持 Transfer-Encoding 请求体")

        media_type = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        media_type = media_type.strip().lower()
        if content_kind == "json" and media_type != "application/json":
            return self._deny_request(415, "接口仅接受 application/json")
        if content_kind == "image" and media_type not in (
                "image/png", "image/jpeg", "image/webp",
                "application/octet-stream"):
            return self._deny_request(415, "图标接口仅接受 PNG/JPEG/WebP 原始数据")
        if content_kind:
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1:
                return self._deny_request(400, "请求必须包含唯一的 Content-Length")
            try:
                length = int(lengths[0])
            except ValueError:
                return self._deny_request(400, "非法的 Content-Length")
            limit = MAX_ICON_BYTES if content_kind == "image" else MAX_JSON_BYTES
            if length < 0 or length > limit:
                return self._deny_request(413, "请求体过大")
        return True

    def _send(self, body, status=200, ctype="text/plain; charset=utf-8",
              set_cookie=True):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; connect-src 'self'; img-src 'self' data: blob:; "
            "font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
        if set_cookie and self._request_host_allowed():
            self.send_header(
                "Set-Cookie",
                "console_session=%s; Path=/; HttpOnly; SameSite=Strict" %
                self.server.control_token)
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def send_json(self, obj, status=200):
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   status, "application/json; charset=utf-8")

    def send_err(self, status, msg):
        self.send_json({"ok": False, "error": msg}, status)

    def discard_body(self):
        """读掉并丢弃请求体。keep-alive 连接复用前必须清空，
        否则残留字节会污染同一连接上的下一个请求（method 解析错乱 → 501）。"""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def read_json_body(self):
        """→ (data|None, error|None)。非法 JSON / 非对象 / 超限都返回 error。"""
        media_type = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        if media_type.strip().lower() != "application/json":
            return None, "Content-Type 必须是 application/json"
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "非法的 Content-Length"
        if length < 0 or length > MAX_JSON_BYTES:
            return None, "请求体过大"
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return None, "请求体不是合法 JSON"
        if not isinstance(data, dict):
            return None, "请求体必须是 JSON 对象"
        return data, None

    def _get_app_or_404(self, app_id):
        cfg = self.server.cfg.snapshot()
        app = find_app(cfg, app_id)
        if app is None:
            self.send_err(404, "应用不存在")
            return None, None
        return cfg, app

    # ---------- GET ----------

    def do_GET(self):
        try:
            if not self.authorize_request():
                return
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if path == "/favicon.ico":
                self.serve_static("/assets/favicon.ico")
                return
            if path == "/api/health":
                self.send_json(build_health(self.server.cfg))
                return
            if path == "/api/platform":
                self.send_json(get_platform_info())
                return
            if path == "/api/state":
                self.send_json(get_state_snapshot(self.server.cfg,
                                                  self.server.console_port))
                return
            if path == "/api/console/log":
                self.handle_console_log(parsed.query)
                return
            m = APP_ROUTE_RE.match(path)
            if m and m.group(2) == "logs":
                self.handle_logs(m.group(1), parsed.query)
                return
            if path.startswith("/api/"):
                self.send_err(404, "接口不存在")
                return
            if path.startswith("/icons/"):
                self.serve_icon(path)
                return
            self.serve_static(path)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("GET", e)

    def serve_static(self, path):
        rel = urllib.parse.unquote(path).lstrip("/") or "index.html"
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        # realpath 解析后必须仍在 STATIC_DIR 内，防路径穿越与符号链接逃逸。
        try:
            inside = os.path.commonpath(
                [os.path.realpath(STATIC_DIR), os.path.realpath(full)]
            ) == os.path.realpath(STATIC_DIR)
        except (ValueError, OSError):
            inside = False
        if not inside or not os.path.isfile(full):
            if rel == "index.html":
                self._send(PLACEHOLDER_HTML.encode("utf-8"), 200,
                           "text/html; charset=utf-8")
            else:
                self._send(b"404 Not Found", 404, set_cookie=False)
            return
        ctype = STATIC_TYPES.get(os.path.splitext(full)[1].lower(),
                                 "application/octet-stream")
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            self._send(b"404 Not Found", 404, set_cookie=False)
            return
        self._send(data, 200, ctype, set_cookie=False)

    def serve_icon(self, path):
        name = os.path.basename(urllib.parse.unquote(path[len("/icons/"):]))
        ext = os.path.splitext(name)[1].lower()
        if ext not in ICON_EXTS:
            self._send(b"404 Not Found", 404)
            return
        icons_root = os.path.realpath(ICONS_DIR)
        full = os.path.realpath(os.path.join(ICONS_DIR, name))
        try:
            inside = os.path.commonpath([icons_root, full]) == icons_root
        except (ValueError, OSError):
            inside = False
        if not inside or not os.path.isfile(full):
            self._send(b"404 Not Found", 404, set_cookie=False)
            return
        ctype = STATIC_TYPES.get(ext, "application/octet-stream")
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            self._send(b"404 Not Found", 404, set_cookie=False)
            return
        self._send(data, 200, ctype, set_cookie=False)

    def handle_logs(self, app_id, query):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        tail = self._parse_log_tail(query)
        self.send_json({"text": read_log_tail(app_id, tail)})

    def handle_console_log(self, query):
        """总控台自身日志（data/logs/console.log），与维护线程共用轮转。"""
        tail = self._parse_log_tail(query)
        self.send_json({"text": read_log_tail("console", tail)})

    @staticmethod
    def _parse_log_tail(query, default=300):
        try:
            tail = int(urllib.parse.parse_qs(query).get("tail", [default])[0])
        except (ValueError, IndexError):
            tail = default
        return max(1, min(tail, 5000))

    # ---------- POST ----------

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            route_match = APP_ROUTE_RE.match(path)
            content_kind = ("image" if route_match and
                            route_match.group(2) == "icon" else "json")
            if not self.authorize_request(mutating=True,
                                          content_kind=content_kind):
                return
            if path == "/api/kill":
                self.handle_kill()
                return
            if path == "/api/services/flag":
                self.handle_flag()
                return
            if path == "/api/watch":
                self.handle_watch()
                return
            if path == "/api/ui/theme":
                self.handle_ui_theme()
                return
            if path == "/api/pick":
                self.handle_pick()
                return
            if path == "/api/project/detect":
                self.handle_project_detect()
                return
            if path == "/api/console/restart":
                self.discard_body()
                self.handle_console_restart()
                return
            if path == "/api/console/stop":
                self.discard_body()
                self.handle_console_stop()
                return
            if path == "/api/apps":
                self.handle_app_create()
                return
            if path == "/api/apps/reorder":
                self.handle_apps_reorder()
                return
            m = APP_ROUTE_RE.match(path)
            if m:
                app_id, action = m.group(1), m.group(2)
                if action == "start":
                    self.discard_body()
                    self.handle_app_start(app_id)
                    return
                if action == "stop":
                    self.handle_app_stop(app_id)
                    return
                if action == "restart":
                    self.discard_body()
                    self.handle_app_restart(app_id)
                    return
                if action == "diagnose":
                    self.discard_body()
                    self.handle_app_diagnose(app_id)
                    return
                if action == "attach":
                    self.handle_app_attach(app_id)
                    return
                if action == "icon":
                    self.handle_icon_upload(app_id)
                    return
                if action == "favicon":
                    self.discard_body()
                    self.handle_fetch_favicon(app_id)
                    return
            self.discard_body()
            self.send_err(404, "接口不存在")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("POST", e)

    def handle_pick(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        what = data.get("what")
        if what not in ("dir", "script"):
            self.send_err(400, "what 必须是 dir/script")
            return
        execution, execution_error = normalize_execution(data.get("execution"))
        if execution_error:
            self.send_err(400, execution_error)
            return
        language = "en" if data.get("language") == "en" else "zh"
        path, canceled = pick_path(what, language=language)
        if canceled:  # 用户取消不是 HTTP 错误，前端静默
            self.send_json({"ok": False, "canceled": True})
        elif not path:
            self.send_json({"ok": False, "error": "无法打开系统选择框"})
        else:
            if execution["environment"] == "wsl":
                try:
                    from console_platform.wsl_host import windows_path_to_wsl
                    path = windows_path_to_wsl(path, execution["distro"])
                except (TypeError, ValueError) as exc:
                    self.send_json({"ok": False, "error": str(exc)}, 400)
                    return
            result = {"ok": True, "path": path}
            if what == "script":
                result["command"] = command_for_script(path, execution)
            self.send_json(result)

    def handle_project_detect(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        execution, execution_error = normalize_execution(data.get("execution"))
        if execution_error:
            self.send_err(400, execution_error)
            return
        requested_cwd = data.get("cwd")
        if execution["environment"] == "wsl":
            try:
                from console_platform.wsl_host import (
                    windows_path_to_wsl, wsl_path_to_windows)
                manager = get_wsl_manager()
                manager.distro_info(execution["distro"], require_running=True)
                canonical_cwd = windows_path_to_wsl(
                    requested_cwd, execution["distro"])
                host_cwd = wsl_path_to_windows(
                    canonical_cwd, execution["distro"])
                result, err = detect_project(host_cwd, execution)
                if result:
                    result["cwd"] = canonical_cwd
                    result["name"] = posixpath.basename(
                        canonical_cwd.rstrip("/")) or canonical_cwd
            except (ValueError, OSError, RuntimeError) as exc:
                result, err = None, str(exc)
        else:
            result, err = detect_project(requested_cwd, execution)
        if err:
            self.send_err(400, err)
            return
        self.send_json(result)

    def handle_app_diagnose(self, app_id):
        cfg = self.server.cfg.snapshot()
        app = find_app(cfg, app_id)
        if not app:
            self.send_err(404, "应用不存在")
            return
        self.send_json(diagnose_app(cfg, app))

    def handle_ui_theme(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        theme_id = str(data.get("theme") or "")
        known = {t["id"] for t in list_themes()}
        if theme_id not in known:
            self.send_err(400, "未知主题: %s" % theme_id)
            return
        self.server.cfg.update(lambda d: d.__setitem__("uiTheme", theme_id))
        self.send_json({"ok": True, "theme": theme_id})

    def handle_console_restart(self):
        reserved, current, helper_pid = self.server.reserve_console_action("restart")
        if not reserved:
            if current == "restart":
                self.send_json({"ok": True, "pid": SELF_PID,
                                "helperPid": helper_pid,
                                "port": self.server.console_port,
                                "alreadyScheduled": True})
            else:
                self.send_err(409, "总控台正在停止，无法重复重启")
            return
        try:
            helper_pid = schedule_console_restart(
                self.server, self.server.console_port)
        except OSError as e:
            self.server.release_console_action("restart")
            self.send_err(500, "无法启动重启程序: %s" % e)
            return
        self.server.set_console_helper_pid(helper_pid)
        invalidate_state_cache()
        self.send_json({"ok": True, "pid": SELF_PID,
                        "helperPid": helper_pid,
                        "port": self.server.console_port})

    def handle_console_stop(self):
        reserved, current, _ = self.server.reserve_console_action("stop")
        if not reserved:
            if current == "stop":
                self.send_json({"ok": True, "pid": SELF_PID,
                                "port": self.server.console_port,
                                "alreadyScheduled": True})
            else:
                self.send_err(409, "总控台正在重启，无法同时停止")
            return
        schedule_console_stop(self.server)
        invalidate_state_cache()
        self.send_json({"ok": True, "pid": SELF_PID,
                        "port": self.server.console_port})

    def handle_kill(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        force = data.get("force", False)
        if not isinstance(force, bool):
            self.send_err(400, "force 必须是布尔值")
            return
        instance_key = data.get("instanceKey")
        payload = parse_instance_key(instance_key) if instance_key else None
        if IS_WINDOWS:
            if not payload:
                self.send_err(400, "Windows/WSL 操作必须提供有效 instanceKey")
                return
            if payload.get("environment") == "wsl":
                ok, error, requires_force = kill_wsl_process(
                    instance_key, force=force)
                response = ({"ok": True} if ok else
                            {"ok": False, "error": error})
                if requires_force:
                    response["requiresForce"] = True
                if ok:
                    invalidate_state_cache()
                self.send_json(response, 200 if ok else 409)
                return
            pid = payload["pid"]
        else:
            pid = data.get("pid")
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                self.send_err(400, "缺少字段 pid（正整数）")
                return
        ok, err, requires_force = kill_process(
            pid, force, instance_key=instance_key)
        if ok:
            invalidate_state_cache()
        response = {"ok": True} if ok else {"ok": False, "error": err}
        if requires_force:
            response["requiresForce"] = True
        self.send_json(response, 200 if ok else 409)

    def handle_flag(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        key, flag, value = data.get("key"), data.get("flag"), data.get("value")
        if not isinstance(key, str) or not key:
            self.send_err(400, "缺少字段 key")
            return
        if flag not in ("hidden", "pinned", "promoted"):
            self.send_err(400, "flag 必须是 hidden/pinned/promoted")
            return
        if not isinstance(value, bool):
            self.send_err(400, "value 必须是布尔值")
            return

        def op(c):
            lst = c.setdefault(flag, [])
            if value and key not in lst:
                lst.append(key)
            elif not value and key in lst:
                lst.remove(key)

        self.server.cfg.update(op)
        self.send_json({"ok": True})

    def handle_watch(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        keyword, action = data.get("keyword"), data.get("action")
        if not isinstance(keyword, str) or not keyword.strip():
            self.send_err(400, "缺少字段 keyword")
            return
        if action not in ("add", "remove"):
            self.send_err(400, "action 必须是 add/remove")
            return
        keyword = keyword.strip()

        def op(c):
            kws = c.setdefault("watchedKeywords", [])
            if action == "add" and keyword not in kws:
                kws.append(keyword)
            elif action == "remove":
                c["watchedKeywords"] = [k for k in kws if k != keyword]
            return list(c["watchedKeywords"])

        keywords = self.server.cfg.update(op)
        self.send_json({"ok": True, "keywords": keywords})

    def handle_app_create(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        attach_pid = data.get("attachPid")
        attach_instance_key = data.get("attachInstanceKey")
        if attach_instance_key is None and isinstance(data.get("instanceKey"), str):
            attach_instance_key = data.get("instanceKey")
        if attach_instance_key is not None and not isinstance(attach_instance_key, str):
            self.send_err(400, "attachInstanceKey 必须是字符串")
            return
        if IS_WINDOWS and attach_pid is not None:
            self.send_err(400, "Windows/WSL 创建认领必须使用 attachInstanceKey")
            return
        if attach_pid is not None and (
                not isinstance(attach_pid, int)
                or isinstance(attach_pid, bool)
                or attach_pid <= 0):
            self.send_err(400, "attachPid 必须是正整数")
            return
        fields, err = validate_app_fields(data, partial=False)
        if err:
            self.send_err(400, err)
            return

        snapshot = self.server.cfg.snapshot()
        new_id = secrets.token_hex(4)
        while find_app(snapshot, new_id):
            new_id = secrets.token_hex(4)
        app = {"id": new_id, "name": fields["name"],
               "command": fields["command"], "cwd": fields["cwd"],
               "port": fields["port"], "emoji": fields["emoji"],
               "glyph": fields["glyph"], "kind": fields["kind"],
               "execution": fields["execution"],
               "icon": None, "favicon": None, "lastPid": None,
               "lastPgid": None, "runToken": None,
               "instanceKey": None, "processIdentity": None,
               "attached": False, "lastExit": None,
               "createdAt": int(time.time())}
        cwd_updated = False
        attach_requested = attach_instance_key is not None or attach_pid is not None
        attach_conflict = [False]
        attach_failure = [None]

        def op(c):
            nonlocal cwd_updated, attach_pid
            if find_app(c, new_id):
                return None
            if attach_requested:
                ok, error, identity = inspect_attach_process(
                    self.server.cfg, app, attach_pid,
                    instance_key=attach_instance_key)
                if not ok:
                    attach_failure[0] = (error, identity)
                    return None
                actual_cwd = identity["cwd"]
                try:
                    cwd_updated = (
                        not app.get("cwd")
                        or os.path.realpath(app["cwd"])
                        != os.path.realpath(actual_cwd)
                    )
                except OSError:
                    cwd_updated = True
                app["cwd"] = actual_cwd
                attach_pid = identity.get("pid", attach_pid)
                app["lastPid"] = attach_pid
                app["processIdentity"] = identity.get("processIdentity")
                app["attached"] = True
                for other in c.get("apps") or []:
                    other_identity = other.get("processIdentity") or {}
                    same_identity = same_runtime_identity(
                        other_identity, app.get("processIdentity"))
                    if same_identity or (
                            not app.get("processIdentity")
                            and other.get("lastPid") == attach_pid):
                        attach_conflict[0] = True
                        return None
            c["apps"].append(app)
            return dict(app)

        created = self.server.cfg.update(op)
        if created is None:
            if attach_failure[0] is not None:
                error, info = attach_failure[0]
                self.send_json(
                    {"ok": False, "error": error}, info.get("status", 409))
            elif attach_conflict[0]:
                self.send_json(
                    {"ok": False, "error": "该进程已由其他卡片管理"}, 409)
            else:
                self.send_err(409, "应用标识发生冲突，请重试")
            return
        if attach_requested:
            created.update({
                "attached": True,
                "running": True,
                "pid": attach_pid,
                "cwdUpdated": cwd_updated,
            })
        self.send_json(created)

    @serialized_app_operation
    def handle_fetch_favicon(self, app_id):
        """抓取应用有效端口对应站点的 favicon，存为 data/icons/fav-{id}.{ext}。
        优先级低于用户自定义 icon/glyph，仅作兜底。"""
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        execution = app.get("execution") or normalize_execution(None)[0]
        port = None
        if IS_WINDOWS and execution.get("environment") == "wsl":
            try:
                scan = get_wsl_manager().scan_distro(execution["distro"])
                public_app = _build_wsl_app(
                    app, _wsl_scan_index([scan]), scan_listeners())
                if public_app.get("running"):
                    configured_port = app.get("port")
                    owned_ports = public_app.get("ports") or []
                    port = (configured_port if configured_port in owned_ports
                            else owned_ports[0] if owned_ports else None)
                hosts = ["localhost", scan.get("preferredAddress")]
            except Exception as exc:
                self.send_json({"ok": False,
                                "error": "WSL 端点验证失败: %s" % exc}, 409)
                return
        else:
            live = set(managed_pids(app))
            listeners = scan_listeners()
            configured_port = app.get("port")
            if configured_port and any(pid in live and p == configured_port
                                       for pid, p in listeners):
                port = configured_port
            if not port:
                owned_ports = sorted({p for pid, p in listeners if pid in live})
                port = owned_ports[0] if owned_ports else None
        if not port:
            self.send_json({"ok": False, "error": "应用未运行或无可用端口"})
            return
        if IS_WINDOWS and execution.get("environment") == "wsl":
            data, ext = fetch_wsl_favicon(port, hosts)
        else:
            host = listener_open_host(listeners, port, live)
            data, ext = fetch_favicon(port, host)
        if not data:
            self.send_json({"ok": False, "error": "未找到站点图标"})
            return
        fname = "fav-%s.%s" % (app_id, ext)
        try:
            _ensure_private_dir(ICONS_DIR)
            write_private_bytes(os.path.join(ICONS_DIR, fname), data)
        except OSError as e:
            self.send_json({"ok": False, "error": "图标保存失败: %s" % e})
            return
        url = "/icons/" + fname

        def op(c):
            target = find_app(c, app_id)
            if target:
                target["favicon"] = url

        self.server.cfg.update(op)
        self.send_json({"ok": True, "favicon": url})

    def handle_apps_reorder(self):
        """按收到的 id 顺序重排 apps（Python sort 稳定：未涉及的 id 相对顺序不变，
        服务/任务两区可独立排序互不干扰）。"""
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        ids = data.get("ids")
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            self.send_err(400, "ids 必须是字符串数组")
            return
        order = {i: n for n, i in enumerate(ids)}

        def op(c):
            c["apps"].sort(key=lambda a: order.get(a.get("id"), len(order)))

        self.server.cfg.update(op)
        self.send_json({"ok": True})

    @serialized_app_operation
    def handle_app_start(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if app_alive_sign(app):
            self.send_json({"ok": False, "error": "应用已在运行"})
            return
        health = inspect_app_health(app)
        if health["blocking"]:
            issue = health["issues"][0]
            self.send_json({
                "ok": False,
                "error": "%s：%s" % (issue["title"], issue["detail"]),
                "health": health,
            }, 422)
            return
        port = app.get("port")
        occupied = configured_port_occupant(app, activate_wsl=True)
        if occupied:
            label = ("WSL %s" % occupied.get("distro")
                     if occupied.get("environment") == "wsl" else "Windows")
            self.send_json({"ok": False,
                            "error": "端口 %d 已被 %s PID %d 占用" %
                            (port, label, occupied["pid"])}, 409)
            return
        ok, err, proc, pgid, token = start_app(app)
        if not ok:
            response = {"ok": False, "error": err}
            if proc is not None and token:
                committed, recovery_error, retained = (
                    persist_started_app_or_rollback(
                        self.server.cfg, app_id, proc, pgid, token))
                identity_retained = bool(committed or retained)
                response["runtimeRetained"] = identity_retained
                response["pid"] = proc.pid
                if recovery_error:
                    response["recoveryError"] = recovery_error
                if identity_retained:
                    response["error"] += (
                        "；清理未获确认，管理身份已保留，"
                        "请使用停止/强制停止重试")
            self.send_json(response, 500 if proc is not None else 200)
            return
        committed, commit_error, runtime_retained = persist_started_app_or_rollback(
            self.server.cfg, app_id, proc, pgid, token)
        if not committed:
            response = {"ok": False, "error": commit_error}
            if runtime_retained:
                response["runtimeRetained"] = True
                response["pid"] = proc.pid
            status = (409 if commit_error.startswith("应用已被删除")
                      else 500)
            self.send_json(response, status)
            return
        # 一次性任务的正常形态就是快速退出，不能沿用服务的启动探测逻辑把
        # `echo`、清缓存等成功任务误判成“启动失败”。退出线程会独立记录结果。
        if (app.get("kind") or "service") == "task":
            self.send_json({"ok": True, "pid": proc.pid})
            return
        deadline = time.monotonic() + STARTUP_PROBE_SEC
        code = proc.poll()
        while code is None and time.monotonic() < deadline:
            time.sleep(0.025)
            code = proc.poll()
        if code is not None:
            self.send_json({"ok": False,
                            "error": startup_failure_message(app_id, code)}, 422)
            return
        self.send_json({"ok": True, "pid": proc.pid})

    @serialized_app_operation
    def handle_app_stop(self, app_id):
        data, body_error = self.read_json_body()
        if body_error:
            self.send_err(400, body_error)
            return
        force = data.get("force", False)
        if not isinstance(force, bool):
            self.send_err(400, "force 必须是布尔值")
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if not app_alive_sign(app):
            self.send_json({"ok": False, "error": "应用未在运行"})
            return
        ok, error = stop_app_and_clear(
            self.server.cfg, app, force=force)
        if not ok:
            response = {"ok": False, "error": str(error)}
            if getattr(error, "requires_force", False):
                response["requiresForce"] = True
            self.send_json(response, 409)
            return
        self.send_json({"ok": True})

    @serialized_app_operation
    def handle_app_attach(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        instance_key = data.get("instanceKey")
        pid = data.get("pid")
        if IS_WINDOWS:
            if not isinstance(instance_key, str) or not instance_key:
                self.send_err(400, "Windows/WSL 认领必须提供 instanceKey")
                return
            pid = None
        elif not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            self.send_err(400, "pid 必须是正整数")
            return
        ok, error, info = attach_app_process(
            self.server.cfg, app_id, app, pid,
            instance_key=instance_key)
        if not ok:
            self.send_json({"ok": False, "error": error}, info.get("status", 409))
            return
        resp = {"ok": True, "pid": info.get("pid", pid)}
        resp.update(info)
        self.send_json(resp)

    @serialized_app_operation
    def handle_app_restart(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if not app_alive_sign(app):
            self.send_err(409, "应用未在运行")
            return
        # 必须在停止旧服务前预检；配置已失效时保留仍在工作的旧进程。
        health = inspect_app_health(app)
        if health["blocking"]:
            issue = health["issues"][0]
            self.send_json({
                "ok": False,
                "error": "%s：%s。旧服务仍在运行" %
                         (issue["title"], issue["detail"]),
                "health": health,
            }, 422)
            return

        stopped, error = stop_app_and_clear(self.server.cfg, app)
        if not stopped:
            self.send_err(409, error or "旧进程停止失败，已取消重启")
            return

        port = app.get("port")
        occupied = configured_port_occupant(app, activate_wsl=True)
        if occupied:
            self.send_err(409, "端口 %d 已被 PID %d 占用，旧应用已停止" %
                          (port, occupied["pid"]))
            return

        latest = self.server.cfg.snapshot()
        current = find_app(latest, app_id)
        if not current:
            self.send_err(404, "应用已被删除")
            return
        ok, err, proc, pgid, new_token = start_app(current)
        if not ok:
            response = {"ok": False, "error": err}
            if proc is not None and new_token:
                committed, recovery_error, retained = (
                    persist_started_app_or_rollback(
                        self.server.cfg, app_id, proc, pgid, new_token))
                identity_retained = bool(committed or retained)
                response["runtimeRetained"] = identity_retained
                response["pid"] = proc.pid
                if recovery_error:
                    response["recoveryError"] = recovery_error
                if identity_retained:
                    response["error"] += (
                        "；清理未获确认，管理身份已保留，"
                        "请使用停止/强制停止重试")
            self.send_json(response, 500)
            return
        committed, commit_error, runtime_retained = persist_started_app_or_rollback(
            self.server.cfg, app_id, proc, pgid, new_token)
        if not committed:
            response = {"ok": False, "error": commit_error}
            if runtime_retained:
                response["runtimeRetained"] = True
                response["pid"] = proc.pid
            status = (409 if commit_error.startswith("应用已被删除")
                      else 500)
            self.send_json(response, status)
            return
        self.send_json({"ok": True, "pid": proc.pid})

    @serialized_app_operation
    def handle_icon_upload(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        try:
            length = int(self.headers.get("Content-Length") or -1)
        except ValueError:
            length = -1
        if length < 0:
            self.send_err(400, "缺少 Content-Length")
            return
        if length > MAX_ICON_BYTES:
            self.send_err(400, "图标大小不能超过 5MB")
            return
        raw = self.rfile.read(length)
        kind = sniff_image(raw)
        if kind is None:
            self.send_err(400, "仅支持 PNG / JPEG / WebP 图片")
            return
        _ensure_private_dir(ICONS_DIR)
        for ext in ICON_EXTS:
            old = os.path.join(ICONS_DIR, app_id + ext)
            if ext != "." + kind and os.path.isfile(old):
                try:
                    os.remove(old)
                except OSError:
                    pass
        fname = "%s.%s" % (app_id, kind)
        try:
            write_private_bytes(os.path.join(ICONS_DIR, fname), raw)
        except OSError as e:
            self.send_err(500, "图标保存失败: %s" % e)
            return
        icon_url = "/icons/" + fname

        def op(c):
            target = find_app(c, app_id)
            if target:
                target["icon"] = icon_url

        self.server.cfg.update(op)
        self.send_json({"ok": True, "icon": icon_url})

    # ---------- PUT ----------

    def do_PUT(self):
        operation_lock = None
        try:
            if not self.authorize_request(mutating=True,
                                          content_kind="json"):
                return
            path = urllib.parse.urlparse(self.path).path
            m = APP_ROUTE_RE.match(path)
            if not (m and m.group(2) is None):
                self.discard_body()
                self.send_err(404, "接口不存在")
                return
            operation_lock = self.server.try_app_operation(m.group(1))
            if operation_lock is None:
                self.discard_body()
                self.send_err(409, "该应用正在执行其他操作，请稍后重试")
                return
            data, err = self.read_json_body()
            if err:
                self.send_err(400, err)
                return
            stop_before_update = data.get("stopBeforeUpdate", False)
            if not isinstance(stop_before_update, bool):
                self.send_err(400, "stopBeforeUpdate 必须是布尔值")
                return
            _, app = self._get_app_or_404(m.group(1))
            if app is None:
                return
            fields, err = validate_app_fields(data, partial=True)
            if err:
                self.send_err(400, err)
                return
            if not fields:
                self.send_err(400, "没有可更新的字段")
                return
            lifecycle_fields = {"command", "cwd", "port", "kind", "execution"}
            lifecycle_changed = any(
                key in fields and fields[key] != app.get(key)
                for key in lifecycle_fields)
            stopped_for_update = False
            if lifecycle_changed and app_alive_sign(app):
                if not stop_before_update:
                    stop_label = ("中止任务"
                                  if (app.get("kind") or "service") == "task"
                                  else "停止服务")
                    self.send_json({
                        "ok": False,
                        "error": "应用正在运行，请先在当前编辑面板%s；填写内容会保留" %
                                 stop_label,
                        "requiresStop": True,
                    }, 409)
                    return
                ok, stop_error, stopped_for_update = stop_app_for_update(
                    self.server.cfg, app)
                if not ok:
                    self.send_err(409, stop_error)
                    return

            def op(c):
                target = find_app(c, m.group(1))
                target.update(fields)
                return dict(target)

            updated = self.server.cfg.update(op)
            if stopped_for_update:
                updated = dict(updated)
                updated["stoppedForUpdate"] = True
            self.send_json(updated)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("PUT", e)
        finally:
            if operation_lock is not None:
                operation_lock.release()

    # ---------- DELETE ----------

    def do_DELETE(self):
        try:
            if not self.authorize_request(mutating=True):
                return
            path = urllib.parse.urlparse(self.path).path
            m = APP_ROUTE_RE.match(path)
            if not m:
                self.send_err(404, "接口不存在")
                return
            app_id, action = m.group(1), m.group(2)
            if action is None:
                self.handle_app_delete(app_id)
                return
            if action == "icon":
                self.handle_icon_delete(app_id)
                return
            self.send_err(404, "接口不存在")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("DELETE", e)

    def do_OPTIONS(self):
        # No CORS endpoint exists. An explicit denial is clearer than the
        # BaseHTTPRequestHandler HTML 501 response and never grants ACAO.
        self._deny_request(403, "控制台不接受跨域预检请求")

    @serialized_app_operation
    def handle_app_delete(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if app_running(app):
            stopped, error = stop_app_and_clear(self.server.cfg, app)
            if not stopped:
                self.send_err(409, "删除已取消：%s" %
                              (error or "应用未能正常退出"))
                return

        def op(c):
            before = len(c["apps"])
            c["apps"] = [a for a in c["apps"] if a.get("id") != app_id]
            return len(c["apps"]) != before

        if not self.server.cfg.update(op):
            self.send_err(404, "应用不存在")
            return
        self.server.forget_app_lock(app_id)

        for ext in ICON_EXTS:
            for fname in (app_id + ext, "fav-" + app_id + ext):
                try:
                    os.remove(os.path.join(ICONS_DIR, fname))
                except OSError:
                    pass
        log_path = os.path.join(LOGS_DIR, "%s.log" % app_id)
        for candidate in [log_path] + ["%s.%d" % (log_path, i)
                                       for i in range(1, LOG_BACKUPS + 1)]:
            try:
                os.remove(candidate)
            except OSError:
                pass

        self.send_json({"ok": True})

    @serialized_app_operation
    def handle_icon_delete(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        for ext in ICON_EXTS:
            try:
                os.remove(os.path.join(ICONS_DIR, app_id + ext))
            except OSError:
                pass

        def op(c):
            target = find_app(c, app_id)
            if target:
                target["icon"] = None

        self.server.cfg.update(op)
        self.send_json({"ok": True})


# ---------------------------------------------------------------- 启动

def open_browser_later(port, delay=0.8):
    def _open():
        try:
            time.sleep(delay)
            webbrowser.open("http://%s:%d/" % (HOST, port))
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


def find_console_instances():
    """查找从同一项目目录启动的总控台，用于双击启动器去重。"""
    snap = ps_snapshot(None, with_uid=True)
    candidates = []
    for pid, info in snap.items():
        args = info.get("args") or ""
        if (pid == SELF_PID or info.get("uid") != SELF_UID
                or "server.py" not in args
                or "--restart-helper" in args):
            continue
        candidates.append(pid)
    cwds = lsof_cwds(candidates)
    listener_map = {}
    for pid, port in scan_listeners():
        listener_map.setdefault(pid, []).append(port)
    result = []
    for pid in candidates:
        cwd = cwds.get(pid)
        try:
            same_dir = cwd and os.path.realpath(cwd) == os.path.realpath(BASE_DIR)
        except OSError:
            same_dir = False
        if not same_dir:
            continue
        info = snap.get(pid, {})
        result.append({
            "pid": pid,
            "ports": sorted(listener_map.get(pid, [])),
            "cmd": info.get("args") or "",
            "cwd": cwd,
            "uptimeSec": info.get("etime"),
        })
    return sorted(result, key=lambda item: (item["ports"] or [65536], item["pid"]))


def _launcher_dialog(message):
    script = """on run argv
set messageText to item 1 of argv
display dialog messageText with title "总控台" buttons {"取消", "重新启动", "打开控制台"} default button "打开控制台" cancel button "取消" with icon note
return button returned of result
end run"""
    try:
        result = subprocess.run(
            ["osascript", "-e", script, message], capture_output=True,
            text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _launcher_alert(message):
    script = """on run argv
display alert "总控台" message (item 1 of argv) as critical
end run"""
    try:
        subprocess.run(["osascript", "-e", script, message],
                       capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def launcher_main():
    """start.command 的无命令启动入口。"""
    instances = find_console_instances()
    if not instances:
        try:
            main(log_to_file=True)
        except Exception:
            _launcher_alert("总控台启动失败。请检查数据目录权限和 console.log。")
            raise
        return
    labels = []
    for item in instances:
        ports = " / ".join(":%d" % p for p in item["ports"]) or "未监听"
        labels.append("%s  ·  PID %d" % (ports, item["pid"]))
    extra = ("\n\n检测到 %d 个同项目实例，重启时会合并为一个。" % len(instances)
             if len(instances) > 1 else "")
    choice = _launcher_dialog(
        "总控台已在运行：\n" + "\n".join(labels) + extra)
    if choice == "打开控制台":
        ports = [p for item in instances for p in item["ports"]]
        port = min(ports) if ports else PORT_START
        webbrowser.open("http://%s:%d/" % (HOST, port))
        return
    if choice != "重新启动":
        return

    preferred_ports = [p for item in instances for p in item["ports"]]
    preferred = min(preferred_ports) if preferred_ports else PORT_START
    targets = [item["pid"] for item in instances]
    for pid in targets:
        if process_uid(pid) == SELF_UID:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline and any(pid_alive(pid) for pid in targets):
        time.sleep(0.1)
    survivors = [pid for pid in targets if pid_alive(pid)]
    if survivors:
        _launcher_alert("旧总控台未能正常退出（PID %s），未强制结束。" %
                        "、".join(str(pid) for pid in survivors))
        return
    try:
        main(preferred_port=preferred, log_to_file=True)
    except Exception:
        _launcher_alert("总控台重启失败。请检查数据目录权限和 console.log。")
        raise


def schedule_console_restart(server, preferred_port):
    """启动独立 helper，响应发出后关闭当前 HTTP 服务。"""
    helper = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--restart-helper",
         str(SELF_PID), str(int(preferred_port))],
        cwd=BASE_DIR, start_new_session=True, close_fds=True)

    def _shutdown():
        time.sleep(0.25)
        server.shutdown()
    threading.Thread(target=_shutdown, daemon=True).start()
    return helper.pid


def schedule_console_stop(server):
    """响应发送完成后关闭 HTTP 服务，不结束启动台里的独立进程组。"""
    def _shutdown():
        time.sleep(0.25)
        server.shutdown()
    threading.Thread(target=_shutdown, daemon=True).start()


def restart_helper(old_pid, preferred_port):
    """等旧进程释放端口后，在 helper 原地 exec 新总控台。"""
    deadline = time.monotonic() + 12.0
    while time.monotonic() < deadline and pid_alive(old_pid):
        time.sleep(0.1)
    if pid_alive(old_pid):
        return 1
    args = [sys.executable, os.path.abspath(__file__),
            "--preferred-port", str(int(preferred_port)), "--no-browser"]
    os.execv(sys.executable, args)
    return 0


def _run_console(preferred_port=None, open_browser=True):
    # Redirected Windows consoles commonly inherit a legacy code page even
    # though every project/runtime file is UTF-8.  Reconfigure text wrappers
    # before emitting Chinese status or log messages; PyInstaller windowed
    # hosts expose ``None`` streams and are intentionally left untouched.
    for stream in (sys.stdout, sys.stderr):
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError, ValueError):
            pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for private_dir in (DATA_DIR, ICONS_DIR, LOGS_DIR):
        _ensure_private_dir(private_dir)
    start_log_maintenance()
    cfg = Config(CONFIG_PATH)

    server, port = None, None
    candidates = list(range(PORT_START, PORT_START + PORT_TRIES))
    if isinstance(preferred_port, int) and preferred_port in candidates:
        candidates.remove(preferred_port)
        candidates.insert(0, preferred_port)
    for p in candidates:
        try:
            server = ConsoleServer((HOST, p), Handler, cfg, p)
            port = p
            break
        except OSError:
            continue
    if server is None:
        print("错误：端口 %d-%d 均被占用，无法启动。" %
              (PORT_START, PORT_START + PORT_TRIES - 1))
        sys.exit(1)

    print("总控台已启动: http://%s:%d/  (Ctrl+C 停止)" % (HOST, port), flush=True)
    if open_browser:
        open_browser_later(port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("已停止", flush=True)


def redirect_console_output():
    """在运行目录迁移完成后，将 .app 输出安全追加到 Library Logs。"""
    path = os.path.join(LOGS_DIR, "console.log")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except (AttributeError, OSError):
                pass
        os.dup2(fd, 1)
        os.dup2(fd, 2)
    finally:
        os.close(fd)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, OSError):
            pass


def main(preferred_port=None, open_browser=True, log_to_file=False):
    """Run exactly one console for this project/data directory."""
    migration = prepare_runtime_storage()
    if log_to_file:
        redirect_console_output()
    if migration["dataMigrated"]:
        print("已将项目内旧配置和图标复制到: %s" % DATA_DIR,
              flush=True)
    if migration["logsMigrated"]:
        print("已将项目内旧日志复制到: %s" % LOGS_DIR,
              flush=True)
    instance_lock = acquire_instance_lock()
    if instance_lock is None:
        print("总控台已在运行（同一数据目录只允许一个实例）。", flush=True)
        if open_browser:
            instances = find_console_instances()
            ports = [port for item in instances for port in item.get("ports", [])]
            if ports:
                webbrowser.open("http://%s:%d/" % (HOST, min(ports)))
        return False
    try:
        _run_console(preferred_port, open_browser)
        return True
    finally:
        release_instance_lock(instance_lock)


if __name__ == "__main__":
    if "--prepare-storage" in sys.argv:
        # 供安装/诊断流程预先验证迁移和目录权限，不启动 HTTP。
        prepare_runtime_storage()
    elif "--launcher" in sys.argv:
        launcher_main()
    elif "--restart-helper" in sys.argv:
        index = sys.argv.index("--restart-helper")
        try:
            old = int(sys.argv[index + 1])
            preferred = int(sys.argv[index + 2])
        except (ValueError, IndexError):
            sys.exit(2)
        sys.exit(restart_helper(old, preferred))
    else:
        preferred = None
        if "--preferred-port" in sys.argv:
            index = sys.argv.index("--preferred-port")
            try:
                preferred = int(sys.argv[index + 1])
            except (ValueError, IndexError):
                sys.exit(2)
        main(preferred_port=preferred, open_browser="--no-browser" not in sys.argv)
