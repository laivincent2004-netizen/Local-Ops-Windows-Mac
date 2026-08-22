import json
import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import server
import console_platform.wsl_host as wsl_host_module
from console_platform.base import AdapterUnavailable
from console_platform.wsl_host import (
    WSLHostManager,
    windows_path_to_wsl,
    wsl_path_to_windows,
)
from tests.test_hardening import HttpHarness


WSL_EXECUTION = {
    "environment": "wsl", "shell": "posix", "distro": "Ubuntu-24.04",
}


class WSLPathMappingTests(unittest.TestCase):
    def test_linux_drive_and_unc_paths_round_trip_without_starting_wsl(self):
        self.assertEqual(
            windows_path_to_wsl("/home/example/项目", "Ubuntu-24.04"),
            "/home/example/项目")
        self.assertEqual(
            windows_path_to_wsl(r"C:\Users\example\My Project", "Ubuntu-24.04"),
            "/mnt/c/Users/example/My Project")
        self.assertEqual(
            windows_path_to_wsl(
                r"\\wsl.localhost\Ubuntu-24.04\home\example\项目",
                "Ubuntu-24.04"),
            "/home/example/项目")
        self.assertEqual(
            wsl_path_to_windows("/mnt/d/work space/app", "Ubuntu-24.04"),
            r"D:\work space\app")
        self.assertEqual(
            wsl_path_to_windows("/home/example/app", "Ubuntu-24.04"),
            r"\\wsl.localhost\Ubuntu-24.04\home\example\app")

    def test_unc_from_another_distro_and_malicious_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "另一个"):
            windows_path_to_wsl(
                r"\\wsl.localhost\Debian\home\example", "Ubuntu-24.04")
        for distro in ("", "-Ubuntu", "Ubuntu\nInjected", "..",
                       "Ubuntu\\Injected", "Ubuntu/Injected"):
            with self.subTest(distro=repr(distro)), self.assertRaises(ValueError):
                wsl_path_to_windows("/home/example", distro)


class WSLHostScanTests(unittest.TestCase):
    def _manager(self):
        manager = WSLHostManager(os.getcwd(), tempfile.gettempdir(), timeout=0.25)
        self.addCleanup(manager.close)
        return manager

    def test_default_discovery_captures_real_subprocess_output(self):
        calls = []

        def run(args, **kwargs):
            calls.append((list(args), dict(kwargs)))
            if "--verbose" in args:
                stdout = (
                    "  NAME                              STATE       VERSION\r\n"
                    "  LocalOps-Alpine-Smoke-9c19e23a    Stopped     2\r\n"
                ).encode("utf-16-le")
            else:
                stdout = b""
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr=b"")

        manager = self._manager()
        with mock.patch("console_platform.common.subprocess.run", side_effect=run):
            distros = manager.discover()

        self.assertEqual([item["name"] for item in distros], [
            "LocalOps-Alpine-Smoke-9c19e23a",
        ])
        self.assertEqual(len(calls), 2)
        for _args, kwargs in calls:
            self.assertTrue(kwargs["capture_output"])
            self.assertFalse(kwargs["check"])

    def test_default_helper_runner_hides_console_on_windows(self):
        manager = self._manager()
        completed = subprocess.CompletedProcess(
            ["wsl.exe", "--status"], 0, stdout=b"ok", stderr=b"")
        with mock.patch.object(wsl_host_module.os, "name", "nt"), \
                mock.patch.object(
                    wsl_host_module.subprocess,
                    "CREATE_NO_WINDOW",
                    0x08000000,
                    create=True,
                ), mock.patch.object(
                    wsl_host_module.subprocess,
                    "run",
                    return_value=completed,
                ) as run:
            result = manager._run(["wsl.exe", "--status"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(run.call_args.kwargs["creationflags"], 0x08000000)

    def test_injected_discovery_runner_remains_supported(self):
        calls = []

        def runner(args, timeout=None):
            calls.append((list(args), timeout))
            stdout = (
                "  NAME       STATE       VERSION\r\n"
                "  Debian     Running     2\r\n"
                if "--verbose" in args else "Debian\r\n"
            )
            return subprocess.CompletedProcess(
                args, 0, stdout=stdout, stderr="")

        manager = WSLHostManager(
            os.getcwd(), tempfile.gettempdir(), runner=runner, timeout=0.25)
        self.addCleanup(manager.close)

        distros = manager.discover()

        self.assertEqual(len(calls), 2)
        self.assertEqual(distros[0]["name"], "Debian")
        self.assertTrue(distros[0]["running"])

    def test_injected_helper_runner_keeps_input_without_windows_flags(self):
        calls = []

        def runner(args, **kwargs):
            calls.append((list(args), dict(kwargs)))
            return subprocess.CompletedProcess(
                args, 0, stdout=b"ok", stderr=b"")

        manager = WSLHostManager(
            os.getcwd(), tempfile.gettempdir(), runner=runner, timeout=0.25)
        self.addCleanup(manager.close)

        result = manager._run(
            ["wsl.exe", "--status"], timeout=0.5,
            input_bytes=b"private-token\n")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        _args, kwargs = calls[0]
        self.assertEqual(kwargs["input"], b"private-token\n")
        self.assertTrue(kwargs["capture_output"])
        self.assertEqual(kwargs["timeout"], 0.5)
        self.assertNotIn("creationflags", kwargs)

    def test_discovery_override_does_not_change_default_manager_budget(self):
        manager = WSLHostManager(
            os.getcwd(), tempfile.gettempdir(), timeout=5.0)
        self.addCleanup(manager.close)
        with mock.patch(
            "console_platform.wsl_host.discover_wsl_distros",
            return_value=[],
        ) as discover:
            manager.discover(timeout=2.0)
            manager.discover()

        self.assertEqual(discover.call_args_list, [
            mock.call(manager.runner, timeout=2.0),
            mock.call(manager.runner, timeout=5.0),
        ])

    def test_monitor_discovery_is_nonblocking_and_single_worker(self):
        manager = self._manager()
        entered = threading.Event()
        release = threading.Event()
        worker_threads = []
        distros = [{
            "name": "Ubuntu", "version": 2,
            "running": False, "available": True,
        }]

        def blocked_discovery():
            worker_threads.append(threading.get_ident())
            entered.set()
            release.wait(5)
            return distros

        caller_thread = threading.get_ident()
        try:
            with mock.patch.object(
                    manager, "discover", side_effect=blocked_discovery) as discover:
                started = time.monotonic()
                first = manager.monitor_discovery()
                first_elapsed = time.monotonic() - started
                self.assertTrue(entered.wait(1))
                second = manager.monitor_discovery()
                third = manager.monitor_discovery()

                self.assertLess(first_elapsed, 0.1)
                self.assertTrue(first["pending"])
                self.assertFalse(first["ready"])
                self.assertTrue(second["pending"])
                self.assertTrue(third["pending"])
                self.assertEqual(discover.call_count, 1)
                self.assertEqual(len(worker_threads), 1)
                self.assertNotEqual(worker_threads[0], caller_thread)

                release.set()
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    published = manager.monitor_discovery()
                    if published["ready"] and not published["pending"]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("monitor snapshot was not published")

                self.assertEqual(published["distros"], distros)
                self.assertEqual(published["scans"], [])
                self.assertIsNone(published["error"])
                self.assertFalse(published["stale"])
                self.assertEqual(discover.call_count, 1)
        finally:
            release.set()

    def test_monitor_discovery_publishes_error_without_blocking_callers(self):
        manager = self._manager()
        entered = threading.Event()
        release = threading.Event()

        def failed_discovery():
            entered.set()
            release.wait(5)
            raise AdapterUnavailable("background discovery failed")

        try:
            with mock.patch.object(manager, "discover",
                                   side_effect=failed_discovery) as discover:
                first = manager.monitor_discovery()
                self.assertTrue(entered.wait(1))
                self.assertTrue(first["pending"])
                self.assertFalse(first["ready"])
                release.set()

                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    published = manager.monitor_discovery()
                    if published["ready"] and not published["pending"]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("monitor error was not published")

                self.assertEqual(published["distros"], [])
                self.assertEqual(
                    published["error"], "background discovery failed")
                self.assertFalse(published["stale"])
                self.assertEqual(discover.call_count, 1)
        finally:
            release.set()

    def test_monitor_discovery_never_starts_after_close(self):
        manager = self._manager()
        manager.close()
        with mock.patch.object(
                manager, "discover",
                side_effect=AssertionError("closed manager must not discover"),
        ) as discover:
            snapshot = manager.monitor_discovery()

        discover.assert_not_called()
        self.assertFalse(snapshot["pending"])
        self.assertFalse(snapshot["ready"])

    def test_monitor_refresh_preserves_stale_last_known_snapshot(self):
        manager = WSLHostManager(
            os.getcwd(), tempfile.gettempdir(), timeout=0.25,
            monitor_refresh=0.25,
        )
        self.addCleanup(manager.close)
        distros = [{
            "name": "Debian", "version": 2,
            "running": False, "available": True,
        }]
        refresh_entered = threading.Event()
        refresh_release = threading.Event()
        calls = []

        def phased_discovery():
            calls.append(threading.get_ident())
            if len(calls) == 1:
                return distros
            refresh_entered.set()
            refresh_release.wait(5)
            raise AdapterUnavailable("refresh failed")

        try:
            with mock.patch.object(manager, "discover",
                                   side_effect=phased_discovery) as discover:
                manager.monitor_discovery()
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    initial = manager.monitor_discovery()
                    if initial["ready"] and not initial["pending"]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("initial monitor snapshot was not published")

                self.assertEqual(initial["distros"], distros)
                time.sleep(0.27)
                refreshing = manager.monitor_discovery()
                self.assertTrue(refresh_entered.wait(1))
                self.assertEqual(refreshing["distros"], distros)
                self.assertTrue(refreshing["pending"])
                self.assertTrue(refreshing["stale"])
                self.assertEqual(discover.call_count, 2)

                refresh_release.set()
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    failed = manager.monitor_discovery()
                    if failed["error"] and not failed["pending"]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("refresh failure was not published")

                self.assertEqual(failed["distros"], distros)
                self.assertEqual(failed["error"], "refresh failed")
                self.assertTrue(failed["stale"])
                self.assertEqual(discover.call_count, 2)
        finally:
            refresh_release.set()

    def test_pre_discovered_scan_does_not_discover_again(self):
        manager = self._manager()
        distros = [{
            "name": "Ubuntu", "version": 2,
            "running": True, "available": True,
        }]
        with mock.patch.object(
            manager, "discover", side_effect=AssertionError("duplicate discovery")
        ) as discover, mock.patch.object(
            manager, "scan_distro",
            return_value={
                "distro": "Ubuntu", "listeners": [], "processes": []
            },
        ) as scan:
            scans, errors = manager.scan_running(distros)

        discover.assert_not_called()
        scan.assert_called_once_with("Ubuntu", distros[0])
        self.assertEqual([item["distro"] for item in scans], ["Ubuntu"])
        self.assertEqual(errors, [])

    def test_only_running_wsl2_distros_are_scanned_and_failure_is_local(self):
        manager = self._manager()
        distros = [
            {"name": "Ubuntu-24.04", "version": 2,
             "running": True, "available": True},
            {"name": "Debian", "version": 2,
             "running": True, "available": True},
            {"name": "Stopped", "version": 2,
             "running": False, "available": True},
            {"name": "Legacy", "version": 1,
             "running": True, "available": False},
        ]

        def scan(name, _known_info=None):
            if name == "Debian":
                raise AdapterUnavailable("helper timed out")
            return {"distro": name, "listeners": [], "processes": []}

        with mock.patch.object(manager, "discover", return_value=distros), \
                mock.patch.object(manager, "scan_distro", side_effect=scan) as call:
            scans, errors = manager.scan_running()

        self.assertEqual([item["distro"] for item in scans], ["Ubuntu-24.04"])
        self.assertEqual(errors, [{"distro": "Debian",
                                   "error": "helper timed out"}])
        self.assertCountEqual(
            [item.args[0] for item in call.call_args_list],
            ["Ubuntu-24.04", "Debian"])

    def test_scan_timeout_returns_promptly_and_reuses_unfinished_future(self):
        manager = self._manager()
        release = threading.Event()
        entered = threading.Event()

        def blocked_scan(name, _known_info=None):
            entered.set()
            release.wait(5)
            return {"distro": name, "listeners": [], "processes": []}

        distros = [{"name": "Ubuntu", "version": 2,
                    "running": True, "available": True}]
        try:
            with mock.patch.object(manager, "discover", return_value=distros), \
                    mock.patch.object(manager, "scan_distro",
                                      side_effect=blocked_scan) as scan:
                started = time.monotonic()
                first = manager.scan_running()
                first_elapsed = time.monotonic() - started
                self.assertTrue(entered.wait(1))

                started = time.monotonic()
                second = manager.scan_running()
                second_elapsed = time.monotonic() - started

                self.assertLess(first_elapsed, 0.9)
                self.assertLess(second_elapsed, 0.9)
                self.assertEqual(scan.call_count, 1)
                self.assertIn("扫描超时", first[1][0]["error"])
                self.assertIn("扫描超时", second[1][0]["error"])
        finally:
            release.set()
            manager.close()

    def test_scan_distro_installs_once_and_keeps_full_parent_chain(self):
        manager = self._manager()
        rows = [{"pid": 40, "ppid": 1, "cwd": "/home/example"},
                {"pid": 41, "ppid": 40, "cwd": "/home/example/app"}]

        def helper(_distro, _path, arguments, **_kwargs):
            operation = arguments[0]
            payloads = {
                "status": {"ok": True, "protocolVersion": 2,
                           "bootId": "boot", "uid": 1000},
                "listeners": {"ok": True, "protocolVersion": 2,
                              "listeners": [{"pid": 41, "port": 3000}]},
                "processes": {"ok": True, "protocolVersion": 2,
                              "processes": rows},
                "network": {"ok": True, "protocolVersion": 2,
                            "addresses": ["172.20.0.2"],
                            "preferredAddress": "172.20.0.2"},
            }
            return payloads[operation]

        with mock.patch.object(manager, "ensure_helper", return_value={
                "path": "/home/example/.local/share/local-ops/helper",
        }) as ensure, mock.patch.object(
                manager, "_helper_json", side_effect=helper) as invoke:
            scan = manager.scan_distro("Ubuntu", {
                "name": "Ubuntu", "version": 2,
                "running": True, "available": True,
            })

        ensure.assert_called_once()
        self.assertEqual(
            [item.args[2][0] for item in invoke.call_args_list],
            ["status", "listeners", "processes", "network"])
        self.assertEqual(scan["processes"], rows)
        self.assertEqual(scan["processes"][1]["ppid"], 40)
        self.assertEqual(scan["cwds"], {
            "40": "/home/example", "41": "/home/example/app"})

    def test_monitor_discovery_never_executes_inside_a_stopped_distro(self):
        manager = self._manager()
        with mock.patch.object(manager, "discover", return_value=[{
                "name": "Ubuntu", "version": 2,
                "running": False, "available": True,
        }]), mock.patch.object(manager, "scan_distro") as scan:
            self.assertEqual(manager.scan_running(), ([], []))
        scan.assert_not_called()

    def test_explicit_activation_reports_wsl_failure_without_name_error(self):
        manager = self._manager()
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 1, stdout=b"", stderr="launch failed".encode())
        with mock.patch.object(manager, "distro_info", return_value={
                "name": "Ubuntu", "version": 2, "running": False,
        }), mock.patch.object(manager, "_run", return_value=completed) as run:
            with self.assertRaisesRegex(AdapterUnavailable, "launch failed"):
                manager.activate_distro("Ubuntu")
        self.assertEqual(run.call_args.kwargs["timeout"], 15.0)

    def test_legacy_nested_dist_is_not_a_helper_source(self):
        with tempfile.TemporaryDirectory() as td:
            directory = os.path.join(td, "wsl_helper", "dist")
            os.makedirs(directory)
            path = os.path.join(directory, "wsl-helper-x86_64")
            with open(path, "wb") as output:
                output.write(b"obsolete helper bytes")
            with open(path + ".sha256", "w", encoding="ascii") as output:
                output.write(hashlib.sha256(b"obsolete helper bytes").hexdigest()
                             + "  wsl-helper-x86_64\n")
            manager = WSLHostManager(td, tempfile.gettempdir())
            self.addCleanup(manager.close)
            with self.assertRaisesRegex(AdapterUnavailable, "缺少 WSL helper"):
                manager.helper_source()

    def test_source_helper_uses_root_dist_and_validates_its_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            directory = os.path.join(td, "dist")
            os.makedirs(directory)
            path = os.path.join(directory, "wsl-helper-x86_64")
            content = b"root dist helper bytes"
            digest = hashlib.sha256(content).hexdigest()
            with open(path, "wb") as output:
                output.write(content)
            with open(path + ".sha256", "w", encoding="ascii") as output:
                output.write("0" * 64 + "  wsl-helper-x86_64\n")
            manager = WSLHostManager(td, tempfile.gettempdir())
            self.addCleanup(manager.close)

            with self.assertRaisesRegex(AdapterUnavailable, "SHA-256"):
                manager.helper_source()

            with open(path + ".sha256", "w", encoding="ascii") as output:
                output.write(digest + "  wsl-helper-x86_64\n")
            self.assertEqual(manager.helper_source(), (path, digest))

    def test_frozen_resource_wsl_helper_precedes_source_dist(self):
        with tempfile.TemporaryDirectory() as td, \
                tempfile.TemporaryDirectory() as resource_dir:
            source_dir = os.path.join(td, "dist")
            packaged_dir = os.path.join(resource_dir, "wsl")
            os.makedirs(source_dir)
            os.makedirs(packaged_dir)
            source_path = os.path.join(source_dir, "wsl-helper-x86_64")
            packaged_path = os.path.join(packaged_dir, "wsl-helper-x86_64")
            with open(source_path, "wb") as output:
                output.write(b"source")
            with open(packaged_path, "wb") as output:
                output.write(b"packaged")
            manager = WSLHostManager(td, tempfile.gettempdir())
            self.addCleanup(manager.close)

            with mock.patch.object(sys, "_MEIPASS", resource_dir, create=True):
                selected, digest = manager.helper_source()

            self.assertEqual(selected, packaged_path)
            self.assertEqual(digest, hashlib.sha256(b"packaged").hexdigest())

    def test_helper_install_passes_expected_digest_and_versioned_target(self):
        manager = self._manager()
        digest = hashlib.sha256(b"helper").hexdigest()
        home_result = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=b"/home/example", stderr=b"")
        calls = []

        def helper_json(distro, helper_path, arguments, **_kwargs):
            calls.append((distro, helper_path, list(arguments)))
            if arguments[0] == "status" and helper_path.startswith("/home/"):
                if len(calls) == 1:
                    raise AdapterUnavailable("not installed")
                return {"ok": True, "protocolVersion": 2,
                        "selfSha256": digest}
            return {"ok": True, "protocolVersion": 2,
                    "installedSha256": digest}

        with mock.patch.object(manager, "distro_info", return_value={
                "name": "Ubuntu", "version": 2, "running": True,
        }), mock.patch.object(manager, "helper_source",
                             return_value=(r"C:\bundle\wsl-helper", digest)), \
                mock.patch.object(manager, "_run", return_value=home_result), \
                mock.patch.object(manager, "_helper_json",
                                  side_effect=helper_json):
            installed = manager.ensure_helper("Ubuntu")

        self.assertEqual(installed["sha256"], digest)
        install = next(arguments for _distro, _path, arguments in calls
                       if arguments[0] == "install")
        self.assertIn("--sha256", install)
        self.assertEqual(install[install.index("--sha256") + 1], digest)
        target = install[install.index("--target") + 1]
        self.assertIn(digest[:16], target)

    def test_cold_restart_reuses_only_a_status_attested_helper(self):
        manager = self._manager()
        digest = hashlib.sha256(b"helper-v1").hexdigest()
        target = "/home/example/.local/share/local-ops/wsl-helper-x86_64-%s" % digest[:16]
        home_result = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=b"/home/example", stderr=b"")

        def helper_json(_distro, helper_path, arguments, **_kwargs):
            self.assertEqual(arguments[0], "status")
            self.assertEqual(helper_path, target)
            return {"ok": True, "protocolVersion": 2,
                    "selfSha256": digest}

        with mock.patch.object(manager, "distro_info", return_value={
                "name": "Ubuntu", "version": 2, "running": True,
        }), mock.patch.object(manager, "helper_source",
                             return_value=(r"C:\bundle\wsl-helper", digest)), \
                mock.patch.object(manager, "_run", return_value=home_result), \
                mock.patch.object(manager, "_helper_json",
                                  side_effect=helper_json) as helper:
            installed = manager.ensure_helper("Ubuntu")

        self.assertEqual(installed["path"], target)
        self.assertEqual(installed["sha256"], digest)
        self.assertEqual(helper.call_count, 1)
        self.assertFalse(any(
            call.args[2][0] == "install" for call in helper.call_args_list))

    def test_cached_corrupt_helper_is_reinstalled_and_reverified(self):
        manager = self._manager()
        digest = hashlib.sha256(b"helper-v1").hexdigest()
        corrupt_digest = hashlib.sha256(b"corrupt").hexdigest()
        target = "/home/example/.local/share/local-ops/wsl-helper-x86_64-%s" % digest[:16]
        manager._cache["ubuntu"] = {
            "path": target, "sha256": digest, "home": "/home/example",
        }
        home_result = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=b"/home/example", stderr=b"")
        installed = False
        calls = []

        def helper_json(_distro, helper_path, arguments, **_kwargs):
            nonlocal installed
            calls.append((helper_path, list(arguments)))
            if arguments[0] == "install":
                installed = True
                return {"ok": True, "protocolVersion": 2,
                        "installedSha256": digest}
            return {"ok": True, "protocolVersion": 2,
                    "selfSha256": digest if installed else corrupt_digest}

        with mock.patch.object(manager, "distro_info", return_value={
                "name": "Ubuntu", "version": 2, "running": True,
        }), mock.patch.object(manager, "helper_source",
                             return_value=(r"C:\bundle\wsl-helper", digest)), \
                mock.patch.object(manager, "_run", return_value=home_result), \
                mock.patch.object(manager, "_helper_json",
                                  side_effect=helper_json):
            result = manager.ensure_helper("Ubuntu")

        self.assertTrue(installed)
        self.assertEqual(result["path"], target)
        self.assertEqual(result["sha256"], digest)
        self.assertEqual([args[0] for _path, args in calls],
                         ["status", "status", "install", "status"])

    def test_helper_digest_change_uses_a_new_versioned_path(self):
        manager = self._manager()
        old_digest = hashlib.sha256(b"helper-v1").hexdigest()
        new_digest = hashlib.sha256(b"helper-v2").hexdigest()
        old_target = "/home/example/.local/share/local-ops/wsl-helper-x86_64-%s" % old_digest[:16]
        manager._cache["ubuntu"] = {
            "path": old_target, "sha256": old_digest, "home": "/home/example",
        }
        home_result = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=b"/home/example", stderr=b"")
        calls = []

        def helper_json(_distro, helper_path, arguments, **_kwargs):
            calls.append((helper_path, list(arguments)))
            if arguments[0] == "status" and len(calls) == 1:
                raise AdapterUnavailable("new helper not installed")
            if arguments[0] == "install":
                return {"ok": True, "protocolVersion": 2,
                        "installedSha256": new_digest}
            return {"ok": True, "protocolVersion": 2,
                    "selfSha256": new_digest}

        with mock.patch.object(manager, "distro_info", return_value={
                "name": "Ubuntu", "version": 2, "running": True,
        }), mock.patch.object(manager, "helper_source",
                             return_value=(r"C:\bundle\wsl-helper", new_digest)), \
                mock.patch.object(manager, "_run", return_value=home_result), \
                mock.patch.object(manager, "_helper_json",
                                  side_effect=helper_json):
            result = manager.ensure_helper("Ubuntu")

        self.assertNotEqual(result["path"], old_target)
        self.assertIn(new_digest[:16], result["path"])
        self.assertTrue(all(path != old_target for path, _args in calls))

    def test_post_install_status_requires_exact_self_sha256(self):
        manager = self._manager()
        digest = hashlib.sha256(b"helper").hexdigest()
        home_result = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=b"/home/example", stderr=b"")
        statuses = 0

        def helper_json(_distro, _helper_path, arguments, **_kwargs):
            nonlocal statuses
            if arguments[0] == "install":
                return {"ok": True, "protocolVersion": 2,
                        "installedSha256": digest}
            statuses += 1
            if statuses == 1:
                raise AdapterUnavailable("not installed")
            return {"ok": True, "protocolVersion": 2}

        with mock.patch.object(manager, "distro_info", return_value={
                "name": "Ubuntu", "version": 2, "running": True,
        }), mock.patch.object(manager, "helper_source",
                             return_value=(r"C:\bundle\wsl-helper", digest)), \
                mock.patch.object(manager, "_run", return_value=home_result), \
                mock.patch.object(manager, "_helper_json",
                                  side_effect=helper_json):
            with self.assertRaisesRegex(AdapterUnavailable, "回读校验失败"):
                manager.ensure_helper("Ubuntu")


class WSLProcessControlTests(unittest.TestCase):
    def setUp(self):
        self.manager = WSLHostManager(
            os.getcwd(), tempfile.gettempdir(), timeout=0.25)
        self.identity = {
            "distro": "Ubuntu-24.04", "bootId": "boot-123", "pid": 4242,
            "uid": 1000, "startTicks": 9001,
            "cwdHash": "a" * 64, "commandHash": "b" * 64,
        }

    def test_control_sends_every_identity_field_to_helper(self):
        response = {"ok": False, "running": True, "requiresForce": True}
        with mock.patch.object(self.manager, "ensure_helper", return_value={
                "path": "/home/example/.local/share/local-ops/helper"}), \
                mock.patch.object(self.manager, "_helper_json",
                                  return_value=response) as helper:
            result = self.manager.process_control(
                self.identity, "stop", timeout_ms=1234)

        self.assertEqual(result, response)
        distro, helper_path, arguments = helper.call_args.args
        self.assertEqual(distro, "Ubuntu-24.04")
        self.assertEqual(helper_path,
                         "/home/example/.local/share/local-ops/helper")
        joined = "\0".join(arguments)
        for expected in (
                "process-control", "stop", "4242", "1000", "boot-123",
                "9001", "a" * 64, "b" * 64, "1234"):
            self.assertIn(expected, joined)
        self.assertTrue(helper.call_args.kwargs["allow_error"])

    def test_control_rejects_partial_identity_and_unknown_action(self):
        partial = dict(self.identity)
        partial.pop("startTicks")
        with self.assertRaisesRegex(ValueError, "startTicks"):
            self.manager.process_control(partial, "stop")
        with self.assertRaisesRegex(ValueError, "无效"):
            self.manager.process_control(self.identity, "kill")

    def test_wsl_verification_rejects_boot_and_start_tick_reuse(self):
        scan = {
            "distro": "Ubuntu-24.04", "bootId": "boot-123", "uid": 1000,
            "processes": [{
                "pid": 4242, "uid": 1000, "startTicks": 9001,
                "cwd": "/home/example/app", "cwdHash": "a" * 64,
                "commandHash": "b" * 64,
            }],
            "listeners": [{"pid": 4242, "port": 3000}],
        }
        identity = {**self.identity, "environment": "wsl", "port": 3000}
        verified, error = server.verify_wsl_process_identity(
            identity, scan=scan, require_listener=True)
        self.assertIsNone(error)
        self.assertEqual(verified["pid"], 4242)

        reused = dict(scan)
        reused["processes"] = [dict(scan["processes"][0], startTicks=9002)]
        verified, error = server.verify_wsl_process_identity(
            identity, scan=reused, require_listener=True)
        self.assertIsNone(verified)
        self.assertIn("PID 已被复用", error)

        restarted = dict(scan, bootId="boot-new")
        verified, error = server.verify_wsl_process_identity(
            identity, scan=restarted, require_listener=True)
        self.assertIsNone(verified)
        self.assertIn("已重启", error)


class WSLProjectDetectionTests(unittest.TestCase):
    def setUp(self):
        self.harness = HttpHarness()

    def tearDown(self):
        self.harness.close()

    def test_picker_cancel_is_explicit_unsuccessful_result(self):
        with mock.patch.object(server, "pick_path", return_value=(None, True)) as picker:
            status, body, _headers = self.harness.request(
                "POST", "/api/pick",
                json.dumps({"what": "dir", "language": "en"}),
                {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": False, "canceled": True})
        picker.assert_called_once_with("dir", language="en")

    def test_picker_invalid_language_safely_falls_back_to_chinese(self):
        with mock.patch.object(server, "pick_path", return_value=(None, True)) as picker:
            status, body, _headers = self.harness.request(
                "POST", "/api/pick",
                json.dumps({"what": "dir", "language": "not-a-language"}),
                {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": False, "canceled": True})
        picker.assert_called_once_with("dir", language="zh")

    def test_wsl_picker_maps_unc_script_and_returns_linux_command(self):
        selected = (
            r"\\wsl.localhost\Ubuntu-24.04\home\example\My Project\job.py"
        )
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "pick_path",
                                  return_value=(selected, False)):
            status, body, _headers = self.harness.request(
                "POST", "/api/pick",
                json.dumps({"what": "script", "execution": WSL_EXECUTION}),
                {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(body["path"], "/home/example/My Project/job.py")
        self.assertEqual(
            body["command"], "python3 -- '/home/example/My Project/job.py'")

    def test_wsl_picker_rejects_unc_from_another_distro(self):
        selected = r"\\wsl.localhost\Debian\home\example\job.sh"
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "pick_path",
                                  return_value=(selected, False)):
            status, body, _headers = self.harness.request(
                "POST", "/api/pick",
                json.dumps({"what": "script", "execution": WSL_EXECUTION}),
                {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertIn("另一个 WSL 发行版", body["error"])

    def test_api_maps_linux_path_for_read_only_detection_and_returns_linux_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "manage.py"), "w", encoding="utf-8") as out:
                out.write("#!/usr/bin/env python3\n")
            manager = mock.Mock()
            manager.distro_info.return_value = {
                "name": "Ubuntu-24.04", "version": 2, "running": True,
            }
            with mock.patch.object(server, "IS_WINDOWS", True), \
                    mock.patch.object(server, "get_wsl_manager",
                                      return_value=manager), \
                    mock.patch("console_platform.wsl_host.wsl_path_to_windows",
                               return_value=td):
                status, body, _headers = self.harness.request(
                    "POST", "/api/project/detect",
                    json.dumps({"cwd": "/home/example/项目",
                                "execution": WSL_EXECUTION}),
                    {"Content-Type": "application/json"})

        self.assertEqual(status, 200)
        self.assertEqual(body["cwd"], "/home/example/项目")
        self.assertEqual(body["name"], "项目")
        self.assertEqual(body["candidates"][0]["command"],
                         "python3 manage.py runserver")
        manager.distro_info.assert_called_once_with(
            "Ubuntu-24.04", require_running=True)

    def test_api_refuses_detection_when_distro_is_stopped(self):
        manager = mock.Mock()
        manager.distro_info.side_effect = AdapterUnavailable(
            "发行版未运行；监控不会自动启动它")
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager):
            status, body, _headers = self.harness.request(
                "POST", "/api/project/detect",
                json.dumps({"cwd": "/home/example/app",
                            "execution": WSL_EXECUTION}),
                {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertIn("未运行", body["error"])


class StrictFaviconEndpointTests(unittest.TestCase):
    PNG = b"\x89PNG\r\n\x1a\n" + b"payload"

    def test_native_fetch_uses_no_proxy_and_same_loopback_redirect_policy(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"ok"
        response.headers = {"Content-Type": "text/plain"}
        opener = mock.Mock()
        opener.open.return_value = response

        with mock.patch.object(server.urllib.request, "build_opener",
                               return_value=opener) as build:
            data, content_type = server.http_get(
                "http://127.0.0.1:4187/", 4187)

        self.assertEqual((data, content_type), (b"ok", "text/plain"))
        self.assertEqual(build.call_args.args[0].proxies, {})
        redirect = build.call_args.args[1]
        self.assertIsInstance(redirect, server.LoopbackRedirectHandler)
        self.assertIsNone(redirect.redirect_request(
            mock.Mock(), None, 302, "Found", {},
            "http://example.com:4187/icon.png"))

    def test_wsl_favicon_never_leaves_discovered_host_and_port(self):
        html = (b'<link rel="icon" href="http://evil.example/track.png">'
                b'<link rel="icon" href="/safe.png">')
        calls = []

        def get(url, host, port, timeout=3, limit=262144):
            calls.append((url, host, port))
            if url.endswith("/"):
                return html, "text/html"
            if url.endswith("/safe.png"):
                return self.PNG, "image/png"
            return None, None

        with mock.patch.object(server, "http_get_exact_endpoint",
                               side_effect=get):
            data, extension = server.fetch_wsl_favicon(
                4187, ["localhost", "172.29.20.5"])

        self.assertEqual((data, extension), (self.PNG, "png"))
        self.assertTrue(all(host == "localhost" for _url, host, _port in calls))
        self.assertFalse(any("evil.example" in url for url, _host, _port in calls))
        self.assertTrue(all(port == 4187 for _url, _host, port in calls))

    def test_exact_endpoint_rejects_credentials_cross_host_and_cross_port(self):
        self.assertTrue(server.is_exact_service_url(
            "http://172.29.20.5:4187/icon.png", "172.29.20.5", 4187))
        for url in (
                "http://evil.example:4187/icon.png",
                "http://172.29.20.5:4188/icon.png",
                "http://user@172.29.20.5:4187/icon.png",
                "https://172.29.20.5:4187/icon.png"):
            with self.subTest(url=url):
                self.assertFalse(server.is_exact_service_url(
                    url, "172.29.20.5", 4187))


if __name__ == "__main__":
    unittest.main()
