#!/usr/bin/env python3
"""Windows system-tray host for 总控台.

The host owns the HTTP server lifecycle, while supervised user applications are
deliberately left alone when the tray process stops.  Platform modules are
imported lazily so release-contract tests can import this module on non-Windows
builders.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import webbrowser


APP_NAME = "总控台"
PORT_START = 9600
PORT_END = 9609
PIPE_BYTES = 4096
ACTIVATION_ACTIONS = frozenset(
    {"open", "start", "stop", "restart", "quit", "wake"}
)
LOG = logging.getLogger("console.windows-host")
_SERVER_RUNTIME = None


class _EmbeddedRestartCancelled(RuntimeError):
    """An API restart lost ownership to a newer explicit stop intent."""


def resource_root() -> Path:
    """Return the PyInstaller data root, or the repository root in source runs."""
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root).resolve()
    return Path(__file__).resolve().parents[1]


def load_server_runtime():
    """Load bundled server.py after platform/environment setup is complete."""
    global _SERVER_RUNTIME
    if _SERVER_RUNTIME is not None:
        return _SERVER_RUNTIME
    path = resource_root() / "server.py"
    spec = importlib.util.spec_from_file_location("local_ops_server", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载后端：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _SERVER_RUNTIME = module
    return module


def runtime_paths(local_app_data: str | os.PathLike[str]) -> tuple[Path, Path]:
    root = Path(local_app_data).expanduser().resolve() / APP_NAME
    return root, root / "logs"


def user_object_key(sid_text: str) -> str:
    """Create a stable, non-identifying suffix for per-user kernel objects."""
    parts = sid_text.split("-") if isinstance(sid_text, str) else []
    if (
        len(parts) < 4
        or parts[0] != "S"
        or any(not part.isascii() or not part.isdigit() for part in parts[1:])
    ):
        raise ValueError("invalid Windows SID")
    return hashlib.sha256(sid_text.encode("ascii")).hexdigest()[:24]


def parse_activation(payload: bytes) -> str | None:
    if not payload or len(payload) > PIPE_BYTES:
        return None
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {"action"}:
        return None
    action = value.get("action")
    return action if action in ACTIVATION_ACTIONS else None


class WindowsApi:
    """Small lazy-import facade around the Win32 and tray dependencies."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows desktop host can only run on Windows")
        import pystray  # type: ignore[import-not-found]
        import pywintypes  # type: ignore[import-not-found]
        import win32api  # type: ignore[import-not-found]
        import win32con  # type: ignore[import-not-found]
        import win32event  # type: ignore[import-not-found]
        import win32file  # type: ignore[import-not-found]
        import win32pipe  # type: ignore[import-not-found]
        import win32security  # type: ignore[import-not-found]
        import winerror  # type: ignore[import-not-found]
        from PIL import Image  # type: ignore[import-not-found]

        self.pystray = pystray
        self.pywintypes = pywintypes
        self.win32api = win32api
        self.win32con = win32con
        self.win32event = win32event
        self.win32file = win32file
        self.win32pipe = win32pipe
        self.win32security = win32security
        self.winerror = winerror
        self.Image = Image

    def current_user_sid(self):
        token = self.win32security.OpenProcessToken(
            self.win32api.GetCurrentProcess(), self.win32con.TOKEN_QUERY
        )
        try:
            return self.win32security.GetTokenInformation(
                token, self.win32security.TokenUser
            )[0]
        finally:
            self.win32api.CloseHandle(token)

    def security_attributes(self):
        """DACL allowing only the current user and LocalSystem."""
        user_sid = self.current_user_sid()
        system_sid = self.win32security.CreateWellKnownSid(
            self.win32security.WinLocalSystemSid, None
        )
        acl = self.win32security.ACL()
        for sid in (user_sid, system_sid):
            acl.AddAccessAllowedAce(
                self.win32security.ACL_REVISION,
                self.win32con.GENERIC_ALL,
                sid,
            )
        descriptor = self.win32security.SECURITY_DESCRIPTOR()
        descriptor.SetSecurityDescriptorDacl(True, acl, False)
        attributes = self.pywintypes.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = descriptor
        return attributes

    def protect_directory(self, path: Path) -> None:
        user_sid = self.current_user_sid()
        system_sid = self.win32security.CreateWellKnownSid(
            self.win32security.WinLocalSystemSid, None
        )
        acl = self.win32security.ACL()
        inherit = (
            self.win32con.OBJECT_INHERIT_ACE | self.win32con.CONTAINER_INHERIT_ACE
        )
        for sid in (user_sid, system_sid):
            acl.AddAccessAllowedAceEx(
                self.win32security.ACL_REVISION,
                inherit,
                self.win32file.FILE_ALL_ACCESS,
                sid,
            )
        self.win32security.SetNamedSecurityInfo(
            str(path),
            self.win32security.SE_FILE_OBJECT,
            self.win32security.DACL_SECURITY_INFORMATION
            | self.win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            acl,
            None,
        )


class SingleInstance:
    """Current-user mutex plus an ACL-restricted activation named pipe."""

    def __init__(self, api: WindowsApi) -> None:
        self.api = api
        sid = api.win32security.ConvertSidToStringSid(api.current_user_sid())
        suffix = user_object_key(sid)
        self.mutex_name = rf"Local\LocalOpsTray-{suffix}"
        # A stable, per-session guard lets Inno Setup detect/close the tray
        # before replacing files.  The SID-derived mutex remains authoritative.
        self.installer_mutex_name = r"Local\LocalOpsTrayInstallerGuard"
        self.pipe_name = rf"\\.\pipe\LocalOpsTray-{suffix}"
        self.mutex = None
        self.installer_mutex = None
        self.already_running = False

    def acquire(self) -> bool:
        self.mutex = self.api.win32event.CreateMutex(
            self.api.security_attributes(), False, self.mutex_name
        )
        self.already_running = (
            self.api.win32api.GetLastError()
            == self.api.winerror.ERROR_ALREADY_EXISTS
        )
        if not self.already_running:
            self.installer_mutex = self.api.win32event.CreateMutex(
                self.api.security_attributes(), False, self.installer_mutex_name
            )
        return not self.already_running

    def send(self, action: str, timeout: float = 3.0) -> bool:
        if action not in ACTIVATION_ACTIONS:
            raise ValueError(f"unsupported activation action: {action}")
        payload = json.dumps(
            {"action": action}, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            handle = None
            try:
                handle = self.api.win32file.CreateFile(
                    self.pipe_name,
                    self.api.win32con.GENERIC_WRITE,
                    0,
                    None,
                    self.api.win32con.OPEN_EXISTING,
                    0,
                    None,
                )
                self.api.win32file.WriteFile(handle, payload)
                return True
            except self.api.pywintypes.error:
                time.sleep(0.08)
            finally:
                if handle is not None:
                    self.api.win32file.CloseHandle(handle)
        return False

    def close(self) -> None:
        if self.mutex is not None:
            self.api.win32api.CloseHandle(self.mutex)
            self.mutex = None
        if self.installer_mutex is not None:
            self.api.win32api.CloseHandle(self.installer_mutex)
            self.installer_mutex = None


class ActivationListener:
    def __init__(self, api: WindowsApi, pipe_name: str, callback) -> None:
        self.api = api
        self.pipe_name = pipe_name
        self.callback = callback
        self.stopping = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._run, name="activation-pipe", daemon=True
        )
        self.thread.start()

    def _run(self) -> None:
        while not self.stopping.is_set():
            handle = None
            try:
                handle = self.api.win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    self.api.win32pipe.PIPE_ACCESS_INBOUND
                    | getattr(
                        self.api.win32pipe,
                        "FILE_FLAG_FIRST_PIPE_INSTANCE",
                        0x00080000,
                    ),
                    self.api.win32pipe.PIPE_TYPE_MESSAGE
                    | self.api.win32pipe.PIPE_READMODE_MESSAGE
                    | self.api.win32pipe.PIPE_WAIT
                    | getattr(
                        self.api.win32pipe,
                        "PIPE_REJECT_REMOTE_CLIENTS",
                        0x00000008,
                    ),
                    1,
                    PIPE_BYTES,
                    PIPE_BYTES,
                    0,
                    self.api.security_attributes(),
                )
                try:
                    self.api.win32pipe.ConnectNamedPipe(handle, None)
                except self.api.pywintypes.error as exc:
                    if getattr(exc, "winerror", None) != 535:  # ERROR_PIPE_CONNECTED
                        raise
                _, payload = self.api.win32file.ReadFile(handle, PIPE_BYTES)
                action = parse_activation(bytes(payload))
                if action and action != "wake" and not self.stopping.is_set():
                    self.callback(action)
            except self.api.pywintypes.error:
                if not self.stopping.is_set():
                    LOG.exception("Activation pipe failed")
                    time.sleep(0.2)
            finally:
                if handle is not None:
                    try:
                        self.api.win32pipe.DisconnectNamedPipe(handle)
                    except self.api.pywintypes.error:
                        pass
                    self.api.win32file.CloseHandle(handle)

    def stop(self, instance: SingleInstance) -> None:
        self.stopping.set()
        instance.send("wake", timeout=0.5)
        if self.thread is not None:
            self.thread.join(timeout=1.5)


class ServerController:
    """Own one embedded ConsoleServer without touching supervised children."""

    def __init__(self, on_change=None) -> None:
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._server = None
        self._port: int | None = None
        self._last_port: int | None = None
        self._error: BaseException | None = None
        self._ready = threading.Event()
        self._generation = 0
        self._stop_epoch = 0
        self._runtime_prepared = False
        self._on_change = on_change or (lambda: None)

    @property
    def running(self) -> bool:
        with self._lock:
            return self._server is not None and bool(
                self._thread and self._thread.is_alive()
            )

    @property
    def port(self) -> int | None:
        with self._lock:
            return self._port

    def start(
        self,
        *,
        preferred_port: int | None = None,
        timeout: float = 12.0,
        _expected_stop_epoch: int | None = None,
    ) -> int:
        with self._lock:
            if (
                _expected_stop_epoch is not None
                and _expected_stop_epoch != self._stop_epoch
            ):
                raise _EmbeddedRestartCancelled("内嵌重启已被新的停止请求取消")
            if self.running:
                return int(self._port)
            if self._thread is not None and self._thread.is_alive():
                # Another activation request reached the tray while the first
                # HTTP thread was still binding.  Join the same readiness event
                # so a second launch can open the browser once it is ready.
                pass
            else:
                self._generation += 1
                generation = self._generation
                stop_epoch = self._stop_epoch
                self._error = None
                self._ready.clear()
                preferred = preferred_port if preferred_port is not None else self._last_port
                self._thread = threading.Thread(
                    target=self._serve,
                    args=(generation, preferred, stop_epoch),
                    name="console-http",
                    daemon=True,
                )
                self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("总控台启动超时，请查看 desktop.log")
        with self._lock:
            if self._error is not None:
                raise RuntimeError(f"总控台启动失败：{self._error}") from self._error
            if self._port is None:
                raise RuntimeError("总控台启动后没有监听端口")
            return self._port

    def _prepare_runtime(self, runtime) -> None:
        if self._runtime_prepared:
            return
        runtime.prepare_runtime_storage()
        for path_name in ("DATA_DIR", "ICONS_DIR", "LOGS_DIR"):
            runtime._ensure_private_dir(getattr(runtime, path_name))
        runtime.start_log_maintenance()
        self._runtime_prepared = True

    def _schedule_embedded_restart(
        self,
        active_server,
        preferred_port: int,
        generation: int,
        stop_epoch: int,
    ) -> int:
        """Replace server.py's exec-based helper inside the frozen tray host."""

        def restart_after_response() -> None:
            time.sleep(0.25)
            active_server.shutdown()
            with self._lock:
                thread = self._thread
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=12.0)
            with self._lock:
                if (
                    self._generation != generation
                    or self._stop_epoch != stop_epoch
                ):
                    return
            try:
                # start() checks the epoch again while holding the same lock
                # that publishes the replacement thread, closing the gap
                # between the check above and the actual start.
                self.start(
                    preferred_port=preferred_port,
                    _expected_stop_epoch=stop_epoch,
                )
            except _EmbeddedRestartCancelled:
                return
            except Exception:
                LOG.exception("HTTP API requested restart failed")

        threading.Thread(
            target=restart_after_response,
            name="console-api-restart",
            daemon=True,
        ).start()
        # API compatibility: there is no helper process in the embedded host.
        return os.getpid()

    def _serve(
        self, generation: int, preferred_port: int | None, stop_epoch: int
    ) -> None:
        runtime = None
        instance_lock = None
        server = None
        try:
            runtime = load_server_runtime()
            self._prepare_runtime(runtime)
            runtime.schedule_console_restart = (
                lambda active_server, preferred_port: self._schedule_embedded_restart(
                    active_server, preferred_port, generation, stop_epoch
                )
            )
            instance_lock = runtime.acquire_instance_lock()
            if instance_lock is None:
                raise RuntimeError("同一数据目录已有总控台实例")
            candidates = list(range(PORT_START, PORT_END + 1))
            if preferred_port in candidates:
                candidates.remove(preferred_port)
                candidates.insert(0, preferred_port)
            cfg = runtime.Config(runtime.CONFIG_PATH)
            for port in candidates:
                try:
                    server = runtime.ConsoleServer(
                        (runtime.HOST, port), runtime.Handler, cfg, port
                    )
                    break
                except OSError:
                    continue
            if server is None:
                raise RuntimeError(f"端口 {PORT_START}-{PORT_END} 均被占用")
            with self._lock:
                if generation != self._generation:
                    raise RuntimeError("启动请求已过期")
                self._server = server
                self._port = int(server.server_address[1])
                self._last_port = self._port
            self._ready.set()
            self._on_change()
            server.serve_forever()
        except BaseException as exc:
            LOG.exception("Embedded HTTP server stopped with an error")
            with self._lock:
                self._error = exc
            self._ready.set()
        finally:
            if server is not None:
                try:
                    server.server_close()
                except Exception:
                    LOG.exception("Could not close HTTP server")
            if runtime is not None and instance_lock is not None:
                runtime.release_instance_lock(instance_lock)
            with self._lock:
                if generation == self._generation:
                    self._server = None
                    self._port = None
            self._ready.set()
            self._on_change()

    def stop(self, timeout: float = 12.0) -> None:
        with self._lock:
            # Publish cancellation before inspecting or waiting for the HTTP
            # thread.  A queued API restart therefore cannot revive the server
            # after this stop intent, even if its shutdown is already underway.
            self._stop_epoch += 1
            server = self._server
            thread = self._thread
        if server is None and thread is not None and thread.is_alive():
            # A pipe/menu stop can arrive while the HTTP thread is still
            # binding.  Wait for that same generation's readiness signal and
            # then stop it, instead of returning early and unexpectedly
            # leaving a newly-started server behind.
            if not self._ready.wait(timeout):
                raise RuntimeError("HTTP 服务仍在启动，未能在等待时间内停止")
            with self._lock:
                server = self._server
                thread = self._thread
        if server is None:
            return
        server.shutdown()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
            if thread.is_alive():
                raise RuntimeError("HTTP 服务未能正常停止；未强制结束任何进程")

    def restart(self) -> int:
        preferred = self.port or self._last_port
        # stop() cancels older API restarts; this explicit replacement is a new
        # intent and deliberately starts without their stale epoch token.
        self.stop()
        return self.start(preferred_port=preferred)

    def open_browser(self) -> bool:
        port = self.port
        if port is None:
            return False
        return bool(webbrowser.open(f"http://127.0.0.1:{port}/"))


class TrayApplication:
    def __init__(self, api: WindowsApi, instance: SingleInstance) -> None:
        self.api = api
        self.instance = instance
        self.icon = None
        self.quitting = threading.Event()
        self.action_lock = threading.Lock()
        self.controller = ServerController(self._server_changed)
        self.listener = ActivationListener(api, instance.pipe_name, self.dispatch)

    def _server_changed(self) -> None:
        if self.icon is not None:
            try:
                self.icon.update_menu()
            except Exception:
                LOG.debug("Tray menu update failed", exc_info=True)

    def _notify(self, message: str, title: str = APP_NAME) -> None:
        if self.icon is not None:
            try:
                self.icon.notify(message, title)
            except Exception:
                LOG.debug("Tray notification failed", exc_info=True)

    def _run_action(self, action: str) -> None:
        # Menu callbacks and activation-pipe requests arrive on independent
        # threads.  Serialize lifecycle transitions so a rapid stop/start pair
        # cannot race and leave an unexpected HTTP instance behind.
        with self.action_lock:
            self._run_action_serial(action)

    def _run_action_serial(self, action: str) -> None:
        try:
            if action == "open":
                if not self.controller.running:
                    self.controller.start()
                self.controller.open_browser()
            elif action == "start":
                port = self.controller.start()
                self._notify(f"总控台已在 127.0.0.1:{port} 启动")
            elif action == "stop":
                self.controller.stop()
                self._notify("HTTP 服务已停止；受管应用继续运行")
            elif action == "restart":
                port = self.controller.restart()
                self._notify(f"总控台已在 127.0.0.1:{port} 重新启动")
            elif action == "quit":
                self._request_quit(confirm=False)
        except Exception as exc:
            LOG.exception("Tray action %s failed", action)
            self._notify(str(exc), "总控台操作失败")
        finally:
            self._server_changed()

    def dispatch(self, action: str) -> None:
        if action not in ACTIVATION_ACTIONS or action == "wake":
            return
        threading.Thread(
            target=self._run_action,
            args=(action,),
            name=f"tray-{action}",
            daemon=True,
        ).start()

    def _confirm_quit(self) -> bool:
        result = self.api.win32api.MessageBox(
            0,
            "退出将关闭托盘和总控台 HTTP 服务。\n\n"
            "由总控台启动或认领的应用不会被结束，仍会继续运行。",
            "退出总控台？",
            self.api.win32con.MB_YESNO
            | self.api.win32con.MB_ICONWARNING
            | self.api.win32con.MB_DEFBUTTON2
            | self.api.win32con.MB_TOPMOST,
        )
        return result == self.api.win32con.IDYES

    def _request_quit(self, *, confirm: bool) -> None:
        if self.quitting.is_set() or (confirm and not self._confirm_quit()):
            return
        self.quitting.set()

        def finish() -> None:
            try:
                self.controller.stop()
            except Exception:
                LOG.exception("HTTP service did not stop cleanly during exit")
            self.listener.stop(self.instance)
            if self.icon is not None:
                self.icon.stop()

        threading.Thread(target=finish, name="tray-exit", daemon=True).start()

    def _quit(self, _icon=None, _item=None) -> None:
        if not self.quitting.is_set() and self._confirm_quit():
            self.dispatch("quit")

    def run(self, *, open_on_start: bool) -> None:
        icon_path = resource_root() / "static" / "assets" / "console-app-icon.png"
        image = self.api.Image.open(icon_path).convert("RGBA")
        menu = self.api.pystray.Menu(
            self.api.pystray.MenuItem(
                "打开总控台", lambda *_: self.dispatch("open"), default=True
            ),
            self.api.pystray.Menu.SEPARATOR,
            self.api.pystray.MenuItem(
                "启动总控台",
                lambda *_: self.dispatch("start"),
                enabled=lambda _item: not self.controller.running,
            ),
            self.api.pystray.MenuItem(
                "停止总控台",
                lambda *_: self.dispatch("stop"),
                enabled=lambda _item: self.controller.running,
            ),
            self.api.pystray.MenuItem(
                "重新启动总控台",
                lambda *_: self.dispatch("restart"),
                enabled=lambda _item: self.controller.running,
            ),
            self.api.pystray.Menu.SEPARATOR,
            self.api.pystray.MenuItem("退出", self._quit),
        )
        self.icon = self.api.pystray.Icon("local-ops", image, APP_NAME, menu)
        self.listener.start()
        try:
            self.controller.start()
            if open_on_start:
                self.controller.open_browser()
        except Exception as exc:
            LOG.exception("Initial server start failed")
            self._notify(str(exc), "总控台启动失败")
        self.icon.run()


def configure_runtime(api: WindowsApi) -> tuple[Path, Path]:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA 未设置")
    data_dir, log_dir = runtime_paths(local_app_data)
    data_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    api.protect_directory(data_dir)
    api.protect_directory(log_dir)
    # The installed tray host always owns this per-user location.  Do not honor
    # inherited overrides here: applying a protected DACL to an arbitrary
    # environment-supplied directory could alter an unsafe broad path.  Source
    # users can still run server.py directly with its validated overrides.
    os.environ["CONSOLE_DATA_DIR"] = str(data_dir)
    os.environ["CONSOLE_LOG_DIR"] = str(log_dir)
    handler = RotatingFileHandler(
        log_dir / "desktop.log",
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    return data_dir, log_dir


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="总控台 Windows 托盘宿主")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--start", action="store_const", const="start", dest="action")
    group.add_argument("--stop", action="store_const", const="stop", dest="action")
    group.add_argument(
        "--restart", action="store_const", const="restart", dest="action"
    )
    group.add_argument("--open", action="store_const", const="open", dest="action")
    group.add_argument(
        "--quit",
        action="store_const",
        const="quit",
        dest="action",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--runtime-check",
        action="store_const",
        const="runtime-check",
        dest="action",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--background",
        action="store_true",
        help="启动托盘但不自动打开浏览器（用于可选开机启动）",
    )
    parser.set_defaults(action="open")
    return parser.parse_args(argv)


def runtime_check() -> None:
    """Validate every dependency required by the frozen windowed host."""
    # Constructing the facade proves the tray, Pillow, and pywin32 imports are
    # usable.  Keep this check headless: build.ps1 invokes it before packaging.
    api = WindowsApi()
    runtime = load_server_runtime()
    if not hasattr(runtime, "ConsoleServer"):
        raise RuntimeError("bundled server runtime is incomplete")
    # The Windows path picker is a required product surface, not an optional
    # development convenience. Import it here so release builds fail if Tcl/Tk
    # was omitted from Python or the PyInstaller bundle.
    picker_runtime = __import__("tkinter.filedialog", fromlist=["filedialog"])
    if not hasattr(picker_runtime, "askopenfilename"):
        raise RuntimeError("bundled Windows file picker is incomplete")
    supervisor_runtime = __import__("supervisor_windows")
    supervisor_runtime.validate_runtime()
    security_runtime = __import__(
        "console_platform.windows_security", fromlist=["current_user_sid"]
    )
    if not security_runtime.current_user_sid():
        raise RuntimeError("current Windows SID is unavailable")
    # Exercise the exact mutex + security-descriptor path used before the tray
    # can publish HTTP or write a useful activation error. The random names
    # avoid colliding with either a running installed tray or another check.
    mutex_probe = SingleInstance(api)
    mutex_probe_suffix = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    mutex_probe.mutex_name = rf"Local\LocalOpsRuntimeCheck-{mutex_probe_suffix}"
    mutex_probe.installer_mutex_name = (
        rf"Local\LocalOpsRuntimeCheckInstaller-{mutex_probe_suffix}"
    )
    try:
        if not mutex_probe.acquire():
            raise RuntimeError("temporary Windows mutex self-check collided")
    finally:
        mutex_probe.close()
    # Exercise the exact DACL path used before the tray listener and logging are
    # available. A missing/moved pywin32 access-mask constant would otherwise
    # become a silent windowed startup failure after installation.
    with tempfile.TemporaryDirectory(prefix="local-ops-runtime-check-") as path:
        api.protect_directory(Path(path))
        if security_runtime.private_path_is_secure(path) is not True:
            raise RuntimeError("temporary Windows DACL self-check failed")
    wsl_runtime = __import__("console_platform.wsl_host", fromlist=["HELPER_NAME"])
    if not getattr(wsl_runtime, "HELPER_NAME", None):
        raise RuntimeError("bundled WSL host adapter is incomplete")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.action == "runtime-check":
        try:
            runtime_check()
        except BaseException:
            # A windowed PyInstaller executable has no stderr.  Never let an
            # import/runtime failure escape into PyInstaller's traceback dialog
            # (which would block an unattended release build indefinitely).
            return 1
        else:
            return 0
    api = WindowsApi()
    configure_runtime(api)
    instance = SingleInstance(api)
    if not instance.acquire():
        sent = instance.send(args.action)
        instance.close()
        return 0 if sent else 2
    if args.action in {"stop", "quit"}:
        instance.close()
        return 0
    try:
        app = TrayApplication(api, instance)
        app.run(open_on_start=not args.background and args.action == "open")
        return 0
    finally:
        instance.close()


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    raise SystemExit(main())
