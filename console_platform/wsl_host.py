"""Windows host orchestration for the bundled, dependency-free WSL helper."""

from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import json
import ntpath
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any, Iterable, Optional

from .base import AdapterUnavailable
from .common import hidden_subprocess_options
from .windows import discover_wsl_distros
from .wsl import normalize_wsl_path, validate_distro_name


HELPER_PROTOCOL_VERSION = 2
HELPER_NAME = "wsl-helper-x86_64"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def resource_root(base_dir: str) -> str:
    return os.path.abspath(getattr(sys, "_MEIPASS", base_dir))


def windows_path_to_wsl(path: str, distro: str) -> str:
    """Map Linux/UNC/drive paths without invoking or starting a distro."""
    value = str(path or "").strip()
    if not value:
        raise ValueError("路径不能为空")
    if value.startswith("/"):
        return normalize_wsl_path(value, distro)
    return normalize_wsl_path(ntpath.abspath(value), distro)


def wsl_path_to_windows(path: str, distro: str) -> str:
    distro = validate_distro_name(distro)
    value = normalize_wsl_path(path, distro)
    match = re.match(r"^/mnt/([a-zA-Z])(?:/(.*))?$", value)
    if match:
        drive, rest = match.groups()
        return ntpath.normpath("%s:\\%s" % (
            drive.upper(), (rest or "").replace("/", "\\")))
    return ntpath.normpath(
        "\\\\wsl.localhost\\%s\\%s" %
        (distro, value.lstrip("/").replace("/", "\\")))


class WSLHostManager:
    """Install and query helpers only in distributions already running.

    Distribution discovery uses ``wsl --list`` and never executes a command in
    a stopped distro.  Each active distro is scanned on its own worker so a
    broken instance yields a local degraded reason instead of blocking native
    Windows monitoring.
    """

    def __init__(self, base_dir: str, data_dir: str, runner=None,
                 timeout: float = 5.0,
                 monitor_refresh: float = 2.0) -> None:
        self.base_dir = os.path.abspath(base_dir)
        self.data_dir = os.path.abspath(data_dir)
        # Keep ``None`` as the production discovery sentinel.  The shared
        # discovery helper adds capture_output/check options only on its own
        # subprocess path; passing bare subprocess.run as an injected runner
        # would otherwise inherit WSL's table output and parse an empty list.
        # _run() still resolves None to subprocess.run for helper invocations.
        self.runner = runner
        self.timeout = max(0.25, float(timeout))
        self._cache: dict[str, dict[str, str]] = {}
        self._lock = threading.RLock()
        self._scan_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="wsl-scan")
        self._scan_futures: dict[
            str, tuple[str, concurrent.futures.Future, bool]
        ] = {}
        self._monitor_refresh = max(0.25, float(monitor_refresh))
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_distros: list[dict[str, Any]] = []
        self._monitor_scans: list[dict[str, Any]] = []
        self._monitor_scan_errors: list[dict[str, Any]] = []
        self._monitor_error: Optional[str] = None
        self._monitor_has_result = False
        self._monitor_has_success = False
        self._monitor_updated_at = 0.0
        self._closed = False

    def _run(self, args: list[str], *, timeout: Optional[float] = None,
             input_bytes: Optional[bytes] = None):
        runner = self.runner or subprocess.run
        kwargs = {
            "capture_output": True,
            "timeout": self.timeout if timeout is None else timeout,
            "check": False,
        }
        if self.runner is None:
            kwargs.update(hidden_subprocess_options())
        if input_bytes is not None:
            kwargs["input"] = input_bytes
        try:
            return runner(args, **kwargs)
        except TypeError:
            # Simple injected runners used in unit tests may only implement the
            # subprocess.run surface needed by discovery.
            kwargs.pop("check", None)
            return runner(args, **kwargs)
        except Exception as exc:
            raise AdapterUnavailable("WSL 命令失败: %s" % exc) from exc

    @staticmethod
    def _text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    def discover(self, timeout: Optional[float] = None) -> list[dict[str, Any]]:
        budget = self.timeout if timeout is None else max(0.0, float(timeout))
        return discover_wsl_distros(self.runner, timeout=budget)

    def _monitor_snapshot_locked(self) -> dict[str, Any]:
        pending = self._monitor_thread is not None
        stale = bool(
            self._monitor_has_success
            and (pending or self._monitor_error is not None)
        )
        return {
            "distros": copy.deepcopy(self._monitor_distros),
            "scans": copy.deepcopy(self._monitor_scans),
            "scanErrors": copy.deepcopy(self._monitor_scan_errors),
            "error": self._monitor_error,
            "pending": pending,
            "ready": self._monitor_has_result,
            "stale": stale,
            "updatedAt": self._monitor_updated_at or None,
        }

    def _monitor_discovery_worker(self) -> None:
        discovery_error = None
        scan_errors: list[dict[str, Any]] = []
        distros = None
        scans = None
        try:
            # This is intentionally the normal 5-second explicit discovery
            # surface. A broken wsl.exe (including subprocess cleanup that
            # outlives its nominal timeout) can strand only this daemon
            # worker; HTTP request threads never join it.
            distros = self.discover()
        except Exception as exc:
            discovery_error = str(exc)
        if discovery_error is None:
            try:
                scans, scan_errors = self.scan_running(distros)
            except Exception as exc:
                scans = []
                scan_errors = [{"distro": None, "error": str(exc)}]

        with self._lock:
            if discovery_error is None:
                self._monitor_distros = copy.deepcopy(distros or [])
                self._monitor_scans = copy.deepcopy(scans or [])
                self._monitor_scan_errors = copy.deepcopy(scan_errors)
                self._monitor_error = None
                self._monitor_has_success = True
            else:
                # Keep the last complete successful snapshot for display, but
                # surface the failed refresh and never execute against stale
                # distro state from an HTTP request.
                self._monitor_error = discovery_error
            self._monitor_has_result = True
            self._monitor_updated_at = time.monotonic()
            self._monitor_thread = None

    def monitor_discovery(self) -> dict[str, Any]:
        """Return last-known WSL monitoring data and refresh it asynchronously.

        At most one daemon worker may own discovery and helper scanning. The
        caller only copies already-published data, so ``/api/platform`` and
        ``/api/state`` never wait for or directly execute ``wsl.exe``.
        """
        worker = None
        now = time.monotonic()
        with self._lock:
            due = (
                not self._closed
                and self._monitor_thread is None
                and (
                    not self._monitor_has_result
                    or now - self._monitor_updated_at >= self._monitor_refresh
                )
            )
            if due:
                worker = threading.Thread(
                    target=self._monitor_discovery_worker,
                    name="wsl-monitor-discovery",
                    daemon=True,
                )
                self._monitor_thread = worker
            # Capture before start so the first caller deterministically gets
            # a pending snapshot even if a fast worker finishes immediately.
            snapshot = self._monitor_snapshot_locked()
            if worker is not None:
                # Start while holding the lifecycle lock.  Otherwise close()
                # could set _closed after the due check but before start(),
                # allowing a new WSL subprocess after shutdown had returned.
                # The worker never needs this lock until publication, so this
                # lock order cannot deadlock with Thread.start().
                try:
                    worker.start()
                except Exception as exc:
                    if self._monitor_thread is worker:
                        self._monitor_thread = None
                        self._monitor_error = (
                            "无法启动 WSL 后台枚举: %s" % exc
                        )
                        self._monitor_has_result = True
                        self._monitor_updated_at = time.monotonic()
                    snapshot = self._monitor_snapshot_locked()
        return snapshot

    def distro_info(self, distro: str, *, require_running: bool = True):
        name = validate_distro_name(distro)
        info = next((item for item in self.discover()
                     if item.get("name", "").casefold() == name.casefold()), None)
        if info is None:
            raise AdapterUnavailable("WSL 发行版未安装: %s" % name)
        if info.get("version") != 2:
            raise AdapterUnavailable(
                "WSL1 不受支持；请运行 wsl --set-version %s 2" % name)
        if require_running and not info.get("running"):
            raise AdapterUnavailable(
                "WSL 发行版 %s 未运行；监控不会自动启动它" % name)
        return info

    def activate_distro(self, distro: str):
        """Start a WSL2 distro only for an explicit user launch action."""
        info = self.distro_info(distro, require_running=False)
        if info.get("running"):
            return info
        result = self._run([
            "wsl.exe", "--distribution", info["name"], "--", "/bin/sh",
            "-lc", ":",
        ], timeout=max(self.timeout, 15.0))
        if int(getattr(result, "returncode", 1)) != 0:
            raise AdapterUnavailable("无法启动 WSL 发行版 %s: %s" % (
                info["name"], self._text(getattr(result, "stderr", "")).strip()))
        return self.distro_info(info["name"], require_running=True)

    def helper_source(self) -> tuple[str, str]:
        root = resource_root(self.base_dir)
        candidates = [
            os.path.join(root, "wsl", HELPER_NAME),
            # The reproducible Rust build writes its source-run artifact to the
            # repository-level dist directory.  Frozen builds still prefer the
            # embedded _MEIPASS/wsl copy above.
            os.path.join(root, "dist", HELPER_NAME),
            os.path.join(self.base_dir, "wsl_helper", "target",
                         "x86_64-unknown-linux-musl", "release", "wsl-helper"),
        ]
        source = next((path for path in candidates if os.path.isfile(path)), None)
        if source is None:
            raise AdapterUnavailable("安装包中缺少 WSL helper")
        with open(source, "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
        companion = source + ".sha256"
        if getattr(sys, "frozen", False) and not os.path.isfile(companion):
            raise AdapterUnavailable("安装包中缺少 WSL helper SHA-256 清单")
        if os.path.isfile(companion):
            with open(companion, "r", encoding="ascii") as stream:
                expected = stream.read(256).strip().split()[0].casefold()
            if not _SHA256_RE.fullmatch(expected) or expected != digest:
                raise AdapterUnavailable("WSL helper SHA-256 清单校验失败")
        return source, digest

    def _helper_json(self, distro: str, helper_path: str,
                     arguments: Iterable[str], *, timeout: Optional[float] = None,
                     allow_error: bool = False):
        args = ["wsl.exe", "--distribution", validate_distro_name(distro),
                "--", helper_path, *[str(item) for item in arguments]]
        result = self._run(args, timeout=timeout)
        stdout = self._text(getattr(result, "stdout", ""))
        stderr = self._text(getattr(result, "stderr", ""))
        if int(getattr(result, "returncode", 1)) != 0:
            raise AdapterUnavailable(
                "WSL helper 失败: %s" % (stderr.strip() or stdout.strip()
                                         or "exit %s" % result.returncode))
        try:
            payload = json.loads(stdout)
        except (TypeError, ValueError) as exc:
            raise AdapterUnavailable("WSL helper 返回了无效 JSON") from exc
        if not isinstance(payload, dict) or (payload.get("ok") is False
                                             and not allow_error):
            raise AdapterUnavailable(str(
                payload.get("error") if isinstance(payload, dict)
                else "WSL helper 响应无效"))
        protocol = payload.get("protocolVersion", HELPER_PROTOCOL_VERSION)
        if int(protocol) != HELPER_PROTOCOL_VERSION:
            raise AdapterUnavailable("WSL helper 协议版本不兼容")
        return payload

    def ensure_helper(self, distro: str,
                      known_info: Optional[dict[str, Any]] = None) -> dict[str, str]:
        if known_info is None:
            info = self.distro_info(distro, require_running=True)
        else:
            requested = validate_distro_name(distro)
            info = dict(known_info)
            if str(info.get("name", "")).casefold() != requested.casefold():
                raise AdapterUnavailable("WSL 发行版身份不匹配: %s" % requested)
            if info.get("version") != 2 or not info.get("available"):
                raise AdapterUnavailable("WSL1 不受支持；请升级到 WSL2")
            if not info.get("running"):
                raise AdapterUnavailable(
                    "WSL 发行版 %s 未运行；监控不会自动启动它" % requested)
        name = info["name"]
        source, digest = self.helper_source()
        cache_key = name.casefold()
        with self._lock:
            cached = self._cache.get(cache_key)
        if cached and cached.get("sha256") == digest:
            try:
                cached_status = self._helper_json(
                    name, cached["path"], ["status", "--json"])
                if cached_status.get("selfSha256") == digest:
                    return dict(cached)
            except AdapterUnavailable:
                pass

        home_result = self._run([
            "wsl.exe", "--distribution", name, "--", "/bin/sh", "-lc",
            'printf "%s" "$HOME"',
        ])
        if int(getattr(home_result, "returncode", 1)) != 0:
            raise AdapterUnavailable("无法读取 WSL 当前用户主目录")
        home = self._text(getattr(home_result, "stdout", "")).strip()
        if not home.startswith("/") or any(ch in home for ch in "\r\n\0"):
            raise AdapterUnavailable("WSL 当前用户主目录无效")
        target = "%s/.local/share/local-ops/%s-%s" % (
            home.rstrip("/"), HELPER_NAME, digest[:16])
        source_inside = windows_path_to_wsl(source, name)
        try:
            status = self._helper_json(name, target, ["status", "--json"])
            if status.get("selfSha256") == digest:
                installed = {"path": target, "sha256": digest, "home": home}
                with self._lock:
                    self._cache[cache_key] = installed
                return dict(installed)
        except AdapterUnavailable:
            pass
        installed_payload = self._helper_json(
            name, source_inside,
            ["install", "--json", "--target", target,
             "--sha256", digest], timeout=max(self.timeout, 15.0))
        if installed_payload.get("installedSha256") != digest:
            raise AdapterUnavailable("WSL helper 安装后 SHA-256 不一致")
        status = self._helper_json(name, target, ["status", "--json"])
        if status.get("selfSha256") != digest:
            raise AdapterUnavailable("WSL helper 回读校验失败")
        installed = {"path": target, "sha256": digest, "home": home}
        with self._lock:
            self._cache[cache_key] = installed
        return dict(installed)

    def call(self, distro: str, operation: str,
             pids: Optional[Iterable[int]] = None):
        installed = self.ensure_helper(distro)
        args = [operation, "--json"]
        if pids is not None:
            selected = sorted({int(pid) for pid in pids if int(pid) > 0})
            args.extend(["--pids", ",".join(str(pid) for pid in selected)])
        return self._helper_json(distro, installed["path"], args)

    def process_control(self, identity: dict[str, Any], action: str,
                        timeout_ms: int = 5000):
        """Signal only a complete, helper-revalidated external identity."""
        if action not in ("stop", "force-stop"):
            raise ValueError("WSL process action 无效")
        required = ("distro", "bootId", "pid", "uid", "startTicks",
                    "cwdHash", "commandHash")
        missing = [key for key in required if identity.get(key) in (None, "")]
        if missing:
            raise ValueError("WSL 进程身份不完整: %s" % ", ".join(missing))
        installed = self.ensure_helper(identity["distro"])
        args = [
            "process-control", "--json", "--action", action,
            "--pid", str(int(identity["pid"])),
            "--uid", str(int(identity["uid"])),
            "--boot-id", str(identity["bootId"]),
            "--start-ticks", str(identity["startTicks"]),
            "--cwd-hash", str(identity["cwdHash"]),
            "--command-hash", str(identity["commandHash"]),
            "--timeout-ms", str(max(0, min(30000, int(timeout_ms)))),
        ]
        return self._helper_json(
            identity["distro"], installed["path"], args,
            timeout=max(self.timeout, timeout_ms / 1000.0 + 2.0),
            allow_error=True)

    def session_paths(self, distro: str, run_id: str,
                      windows_log_path: str) -> dict[str, str]:
        if not re.fullmatch(r"[0-9A-Za-z_-]{8,128}", str(run_id)):
            raise ValueError("WSL session id 无效")
        installed = self.ensure_helper(distro)
        root = "%s/.local/share/local-ops/sessions" % installed["home"].rstrip("/")
        return {
            "helperPath": installed["path"],
            "socket": "%s/%s.sock" % (root, run_id),
            "metadata": "%s/%s.json" % (root, run_id),
            "log": windows_path_to_wsl(windows_log_path, distro),
        }

    def scan_distro(self, distro: str,
                    known_info: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        name = validate_distro_name(distro)
        installed = self.ensure_helper(name, known_info=known_info)
        helper_path = installed["path"]

        def helper(operation: str):
            return self._helper_json(name, helper_path, [operation, "--json"])

        status = helper("status")
        listeners_payload = helper("listeners")
        listeners = listeners_payload.get("listeners") or []
        # The helper already scopes this snapshot to its current UID.  Request
        # the full snapshot once so listener rows retain their complete PPID
        # ancestry for origin attribution.  cwd is part of each process row,
        # so a separate cwds invocation would only repeat /proc work.
        processes = helper("processes").get("processes") or []
        cwds = {
            str(item["pid"]): item.get("cwd")
            for item in processes
            if isinstance(item, dict) and item.get("pid") is not None
            and item.get("cwd") is not None
        }
        try:
            network = helper("network")
        except AdapterUnavailable:
            network = {"addresses": [], "preferredAddress": None}
        return {
            "distro": name,
            "bootId": status.get("bootId"),
            "uid": status.get("uid"),
            "listeners": listeners,
            "processes": processes,
            "cwds": cwds,
            "addresses": network.get("addresses") or [],
            "preferredAddress": network.get("preferredAddress"),
        }

    def scan_running(
        self, discovered_distros: Optional[Iterable[dict[str, Any]]] = None
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        distros = (
            self.discover()
            if discovered_distros is None
            else list(discovered_distros)
        )
        running = [item for item in distros
                   if item.get("available") and item.get("running")]
        scans: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        running_by_key = {item["name"].casefold(): item for item in running}
        pending: list[
            tuple[str, str, concurrent.futures.Future, bool]
        ] = []
        with self._lock:
            for key, (name, future, valid) in list(self._scan_futures.items()):
                if key not in running_by_key:
                    if future.done():
                        self._scan_futures.pop(key, None)
                    elif valid:
                        # If the distro stops while a worker is active, never
                        # publish that pre-stop snapshot after a fast restart.
                        self._scan_futures[key] = (name, future, False)
            for key, item in running_by_key.items():
                entry = self._scan_futures.get(key)
                if entry is not None and not entry[2] and entry[1].done():
                    self._scan_futures.pop(key, None)
                    entry = None
                if entry is None:
                    name = item["name"]
                    future = self._scan_pool.submit(
                        self.scan_distro, name, dict(item))
                    valid = True
                    self._scan_futures[key] = (name, future, valid)
                else:
                    name, future, valid = entry
                pending.append((key, name, future, valid))

        if not pending:
            return [], []

        # One deadline covers every distro.  Timed-out work remains registered
        # and is reused by the next 2-second poll rather than spawning another
        # unbounded worker.  Never use a ThreadPoolExecutor context manager
        # here: its implicit shutdown(wait=True) defeats the timeout.
        deadline = time.monotonic() + max(0.25, min(self.timeout, 2.0))
        futures = [future for _key, _name, future, _valid in pending]
        if futures:
            concurrent.futures.wait(
                futures, timeout=max(0.0, deadline - time.monotonic()))
        for key, name, future, valid in pending:
            if not future.done():
                errors.append({
                    "distro": name,
                    "error": (
                        "WSL 上一次扫描仍在结束；不会并发重复扫描"
                        if not valid else
                        "WSL 扫描超时；后台扫描仍在进行"
                    ),
                })
                continue
            with self._lock:
                current = self._scan_futures.get(key)
                if current is not None and current[1] is future:
                    self._scan_futures.pop(key, None)
            if not valid:
                errors.append({
                    "distro": name,
                    "error": "WSL 发行版停止后旧扫描已丢弃",
                })
                continue
            try:
                scans.append(future.result())
            except Exception as exc:
                errors.append({"distro": name, "error": str(exc)})
        scans.sort(key=lambda item: item["distro"].casefold())
        errors.sort(key=lambda item: item["distro"].casefold())
        return scans, errors

    def close(self) -> None:
        with self._lock:
            self._closed = True
        self._scan_pool.shutdown(wait=False, cancel_futures=True)
