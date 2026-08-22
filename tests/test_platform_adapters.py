import importlib
import os
import subprocess
import sys
import types
import unittest
from unittest import mock

import console_platform.windows as windows_module
import console_platform.common as common_module
from console_platform import AdapterUnavailable, get_adapter
from console_platform.common import (
    CommandOutput,
    decode_command_output,
    parse_etime,
    run_command,
)
from console_platform.macos import MacOSAdapter
from console_platform.windows import WindowsAdapter, discover_wsl_distros
from console_platform.wsl import WSLAdapter, normalize_wsl_path, validate_distro_name


class FakeRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, args, timeout=None):
        self.calls.append((list(args), timeout))
        key = tuple(args)
        value = self.responses.get(key, "")
        if callable(value):
            value = value(args)
        return value


class CommonTests(unittest.TestCase):
    def test_parse_etime_preserves_server_semantics(self):
        self.assertEqual(parse_etime("02-03:04:05"), 183845)
        self.assertEqual(parse_etime("04:05"), 245)
        self.assertEqual(parse_etime("bad"), 0)

    def test_utf16_wsl_output_is_decoded(self):
        value = "  NAME STATE VERSION\r\n* Ubuntu Running 2\r\n".encode("utf-16-le")
        self.assertIn("Ubuntu", decode_command_output(value))

    def test_production_windows_command_uses_no_window_creation_flag(self):
        completed = subprocess.CompletedProcess(
            ["wsl.exe", "--list", "--verbose"], 0,
            stdout=b"", stderr=b"",
        )
        with mock.patch.object(common_module.os, "name", "nt"), \
                mock.patch.object(
                    common_module.subprocess,
                    "CREATE_NO_WINDOW",
                    0x08000000,
                    create=True,
                ), mock.patch.object(
                    common_module.subprocess,
                    "run",
                    return_value=completed,
                ) as run:
            result = run_command(["wsl.exe", "--list", "--verbose"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(run.call_args.kwargs["creationflags"], 0x08000000)

    def test_posix_command_does_not_receive_windows_creation_flags(self):
        completed = subprocess.CompletedProcess(
            ["ps"], 0, stdout=b"", stderr=b"")
        with mock.patch.object(common_module.os, "name", "posix"), \
                mock.patch.object(
                    common_module.subprocess,
                    "run",
                    return_value=completed,
                ) as run:
            run_command(["ps"])

        self.assertNotIn("creationflags", run.call_args.kwargs)


class FactoryTests(unittest.TestCase):
    def test_explicit_factory_is_host_independent(self):
        self.assertIsInstance(get_adapter("macos"), MacOSAdapter)
        self.assertIsInstance(
            get_adapter("windows", psutil_module=None), WindowsAdapter)
        self.assertIsInstance(
            get_adapter("wsl", distro="Ubuntu", helper_provider=lambda **_: []),
            WSLAdapter,
        )

    def test_package_does_not_eagerly_import_windows_module(self):
        # A clean re-import of the package must not import psutil or the Windows
        # adapter until the factory explicitly asks for Windows.
        with mock.patch.dict(sys.modules, {
                "console_platform.windows": None, "psutil": None}):
            sys.modules.pop("console_platform", None)
            package = importlib.import_module("console_platform")
            self.assertTrue(callable(package.get_adapter))
        # Restore the package object used by the rest of the test process.
        sys.modules.pop("console_platform", None)
        importlib.import_module("console_platform")


class MacOSAdapterTests(unittest.TestCase):
    def test_listener_snapshot_matches_existing_shape(self):
        output = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
python3 42 alice 7u IPv4 0 0t0 TCP 127.0.0.1:8080 (LISTEN)
python3 42 alice 8u IPv6 0 0t0 TCP [::1]:8080 (LISTEN)
"""
        runner = FakeRunner({
            ("lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"): output,
        })
        listeners = MacOSAdapter(runner=runner).scan_listeners()
        self.assertEqual(listeners, {(42, 8080): {"127.0.0.1", "::1"}})

    def test_process_snapshot_and_cwds_keep_legacy_keys(self):
        details = """PID UID PPID ELAPSED %CPU %MEM COMM
42 501 1 01:02 1.5 2.5 /usr/bin/python3
"""
        args = "PID ARGS\n42 python3 app.py --port 8080\n"
        cwd = "p42\nn/Users/example/My Project\n"
        runner = FakeRunner({
            ("ps", "-p", "42", "-o", "pid,uid,ppid,etime,%cpu,%mem,comm"): details,
            ("ps", "-p", "42", "-o", "pid,args"): args,
            ("lsof", "-a", "-p", "42", "-d", "cwd", "-Fn"): cwd,
        })
        adapter = MacOSAdapter(runner=runner)
        snapshot = adapter.process_snapshot([42])
        self.assertEqual(snapshot[42]["uid"], 501)
        self.assertEqual(snapshot[42]["ppid"], 1)
        self.assertEqual(snapshot[42]["etime"], 62)
        self.assertEqual(snapshot[42]["comm"], "/usr/bin/python3")
        self.assertEqual(snapshot[42]["args"], "python3 app.py --port 8080")
        self.assertEqual(adapter.process_cwds([42]), {42: "/Users/example/My Project"})

    def test_macos_dirs_and_script_commands_preserve_paths(self):
        adapter = MacOSAdapter()
        dirs = adapter.runtime_dirs(environ={}, home="/Users/example")
        self.assertEqual(
            dirs.data_dir, "/Users/example/Library/Application Support/总控台")
        self.assertEqual(dirs.log_dir, "/Users/example/Library/Logs/总控台")
        self.assertEqual(
            adapter.command_for_script("/tmp/a script.py"),
            "python3 -- '/tmp/a script.py'",
        )
        self.assertEqual(
            adapter.build_shell_command("echo ok"),
            ["/bin/bash", "-c", "echo ok"],
        )


class _Address:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _Connection:
    def __init__(self, pid, host, port, status="LISTEN"):
        self.pid = pid
        self.laddr = _Address(host, port)
        self.status = status


class _Process:
    def __init__(self, pid, username="ACME\\alice", cwd=r"C:\work"):
        self.pid = pid
        self.info = {
            "pid": pid,
            "ppid": 1,
            "name": "python.exe",
            "exe": r"C:\Python\python.exe",
            "cmdline": [r"C:\Python\python.exe", "app.py"],
            "username": username,
            "cpu_percent": 1.25,
            "memory_percent": 2.5,
            "create_time": 100.0,
        }
        self._cwd = cwd

    def cwd(self):
        return self._cwd


class _Psutil:
    CONN_LISTEN = "LISTEN"

    def __init__(self):
        self.processes = {
            42: _Process(42),
            43: _Process(43, username="ACME\\bob"),
        }

    def net_connections(self, kind):
        if kind != "tcp":
            raise AssertionError(kind)
        return [
            _Connection(42, "127.0.0.1", 8080),
            _Connection(42, "::1", 8080),
            _Connection(43, "127.0.0.1", 8081, status="NONE"),
        ]

    def process_iter(self, attrs):
        return list(self.processes.values())

    def Process(self, pid):
        return self.processes[pid]


class WindowsAdapterTests(unittest.TestCase):
    _DEFAULT_PSUTIL = object()
    _DEFAULT_RUNNER = object()

    def make_adapter(self, psutil_module=_DEFAULT_PSUTIL,
                     runner=_DEFAULT_RUNNER):
        if runner is self._DEFAULT_RUNNER:
            runner = FakeRunner({
                ("whoami.exe", "/user", "/fo", "csv", "/nh"):
                    '"ACME\\alice","S-1-5-21-123-456-789-1001"\r\n',
            })
        return WindowsAdapter(
            psutil_module=(
                _Psutil() if psutil_module is self._DEFAULT_PSUTIL
                else psutil_module),
            runner=runner,
            environ={
                "USERNAME": "alice", "USERDOMAIN": "ACME",
                "USERPROFILE": r"C:\Users\example",
                "LOCALAPPDATA": r"C:\Users\example\AppData\Local",
            },
        )

    def test_windows_listeners_processes_cwds_and_uid_surrogate(self):
        adapter = self.make_adapter()
        self.assertEqual(adapter.current_uid, 0)
        self.assertEqual(
            adapter.scan_listeners(), {(42, 8080): {"127.0.0.1", "::1"}})
        snapshot = adapter.process_snapshot()
        self.assertEqual(snapshot[42]["uid"], 0)
        self.assertEqual(snapshot[43]["uid"], -1)
        self.assertEqual(snapshot[42]["identity"], "ACME\\alice")
        self.assertEqual(snapshot[42]["comm"], r"C:\Python\python.exe")
        self.assertEqual(adapter.process_cwds([42]), {42: r"C:\work"})

    def test_windows_origin_snapshot_walks_only_requested_ancestry(self):
        adapter = self.make_adapter()
        lineage = adapter.process_lineage([42])
        self.assertEqual(lineage[42][0], 1)
        self.assertIn("python.exe", lineage[42][1])
        self.assertNotIn(43, lineage)

    def test_sid_is_the_exact_windows_identity(self):
        runner = FakeRunner({
            ("whoami.exe", "/user", "/fo", "csv", "/nh"):
                '"ACME\\alice","S-1-5-21-123-456-789-1001"\r\n',
        })
        identity = self.make_adapter(runner=runner).current_user_identity()
        self.assertEqual(identity.kind, "sid")
        self.assertEqual(identity.value, "S-1-5-21-123-456-789-1001")
        self.assertEqual(identity.name, "ACME\\alice")

    def test_production_identity_uses_cached_token_sid_without_whoami(self):
        sid = "S-1-5-21-999-888-777-1001"
        windows_module._current_process_sid.cache_clear()
        self.addCleanup(windows_module._current_process_sid.cache_clear)
        with mock.patch.object(windows_module.os, "name", "nt"), \
                mock.patch(
                    "console_platform.windows_security.current_user_sid",
                    return_value=sid,
                ) as token_sid, mock.patch.object(
                    windows_module, "command_stdout",
                    side_effect=AssertionError("whoami must not run"),
                ):
            first = self.make_adapter(runner=None).current_user_identity()
            second = self.make_adapter(runner=None).current_user_identity()

        self.assertEqual((first.kind, first.value), ("sid", sid))
        self.assertEqual((second.kind, second.value), ("sid", sid))
        token_sid.assert_called_once_with()

    def test_non_windows_host_fallback_is_process_free_and_not_authoritative(self):
        with mock.patch.object(windows_module.os, "name", "posix"), \
                mock.patch.object(
                    windows_module, "_current_process_sid",
                    side_effect=AssertionError("Token API must not run"),
                ), mock.patch.object(
                    windows_module, "command_stdout",
                    side_effect=AssertionError("whoami must not run"),
                ):
            identity = self.make_adapter(runner=None).current_user_identity()

        self.assertEqual(identity.kind, "username")
        self.assertEqual(identity.value, "ACME\\alice")

    def test_windows_data_and_log_dirs_use_local_app_data(self):
        dirs = self.make_adapter().runtime_dirs(environ={
            "USERPROFILE": r"C:\Users\example",
            "LOCALAPPDATA": r"C:\Users\example\AppData\Local",
        })
        self.assertEqual(dirs.data_dir, r"C:\Users\example\AppData\Local\总控台")
        self.assertEqual(dirs.log_dir, r"C:\Users\example\AppData\Local\总控台\logs")

    def test_windows_shell_selection_does_not_bypass_execution_policy(self):
        adapter = self.make_adapter()
        self.assertEqual(
            adapter.build_shell_command("npm run dev"),
            ["cmd.exe", "/d", "/s", "/c", "npm run dev"],
        )
        powershell = adapter.build_shell_command(r'"C:\My Scripts\go.ps1" -Fast')
        self.assertEqual(powershell[:4], [
            "powershell.exe", "-NoLogo", "-NoProfile", "-Command"])
        self.assertEqual(
            powershell[4], r'& "C:\My Scripts\go.ps1" -Fast')
        self.assertNotIn("-ExecutionPolicy", powershell)
        self.assertEqual(
            adapter.build_shell_command(
                r'"C:\My Scripts\go.ps1" -Fast', shell="powershell")[4],
            r'"C:\My Scripts\go.ps1" -Fast',
        )
        self.assertEqual(
            adapter.command_for_script(r"C:\My Scripts\job.ps1"),
            'powershell.exe -NoLogo -NoProfile -File "C:\\My Scripts\\job.ps1"',
        )

    def test_missing_psutil_is_explicit_but_import_is_safe(self):
        adapter = self.make_adapter(psutil_module=None)
        with self.assertRaisesRegex(AdapterUnavailable, "psutil"):
            adapter.scan_listeners()


class WSLDiscoveryTests(unittest.TestCase):
    def test_discovery_supports_spaces_localized_state_and_utf16(self):
        verbose = (
            "  NAME                   STATE           VERSION\r\n"
            "* Ubuntu 24.04           Running         2\r\n"
            "  Legacy Linux           Stopped         1\r\n"
        ).encode("utf-16-le")
        running = "Ubuntu 24.04\r\n".encode("utf-16-le")
        runner = FakeRunner({
            ("wsl.exe", "--list", "--verbose"): verbose,
            ("wsl.exe", "--list", "--running", "--quiet"): running,
        })
        distros = discover_wsl_distros(runner)
        self.assertEqual([item["name"] for item in distros], [
            "Ubuntu 24.04", "Legacy Linux"])
        self.assertTrue(distros[0]["running"])
        self.assertTrue(distros[0]["available"])
        self.assertFalse(distros[1]["available"])
        self.assertIn("--set-version Legacy Linux 2", distros[1]["reason"])

    def test_discovery_failure_is_not_misreported_as_no_distros(self):
        runner = FakeRunner({
            ("wsl.exe", "--list", "--verbose"):
                CommandOutput("", "Access is denied", 5),
        })
        with self.assertRaisesRegex(AdapterUnavailable, "Access is denied"):
            discover_wsl_distros(runner)

        adapter = WindowsAdapter(
            psutil_module=_Psutil(), runner=runner,
            environ={"USERPROFILE": r"C:\Users\example"},
        )
        info = adapter.platform_info()
        self.assertEqual(info["wslDistros"], [])
        self.assertFalse(info["wslOperational"])
        self.assertIn("Access is denied", info["wslDiscoveryError"])

    def test_discovery_commands_share_one_total_timeout_budget(self):
        runner = FakeRunner({
            ("wsl.exe", "--list", "--verbose"):
                "  Ubuntu Running 2\r\n",
            ("wsl.exe", "--list", "--running", "--quiet"):
                "Ubuntu\r\n",
        })
        with mock.patch(
            "console_platform.windows.time.monotonic",
            side_effect=[100.0, 100.25, 100.75],
        ):
            distros = discover_wsl_distros(runner, timeout=1.0)

        self.assertEqual([item["name"] for item in distros], ["Ubuntu"])
        self.assertEqual(len(runner.calls), 2)
        self.assertAlmostEqual(runner.calls[0][1], 0.75)
        self.assertAlmostEqual(runner.calls[1][1], 0.25)

    def test_discovery_does_not_start_second_command_after_deadline(self):
        runner = FakeRunner({
            ("wsl.exe", "--list", "--verbose"):
                "  Ubuntu Running 2\r\n",
        })
        with mock.patch(
            "console_platform.windows.time.monotonic",
            side_effect=[100.0, 100.1, 101.1],
        ), self.assertRaisesRegex(AdapterUnavailable, "枚举超时"):
            discover_wsl_distros(runner, timeout=1.0)

        self.assertEqual(len(runner.calls), 1)

    def test_zero_discovery_timeout_never_invokes_runner(self):
        runner = mock.Mock(side_effect=AssertionError("runner must not run"))
        with self.assertRaisesRegex(AdapterUnavailable, "枚举超时"):
            discover_wsl_distros(runner, timeout=0)
        runner.assert_not_called()

    def test_precomputed_platform_info_never_invokes_wsl_runner(self):
        runner = mock.Mock(side_effect=AssertionError("runner must not run"))
        adapter = WindowsAdapter(
            psutil_module=_Psutil(), runner=runner,
            environ={"USERPROFILE": r"C:\Users\example"},
        )
        distros = [{
            "name": "Ubuntu", "version": 2, "running": True,
            "available": True,
        }]
        with mock.patch(
            "console_platform.windows.shutil.which",
            return_value=r"C:\Windows\System32\wsl.exe",
        ):
            info = adapter.platform_info(
                packaged=True,
                wsl_distros=distros,
                wsl_discovery_error="shared discovery deadline expired",
            )

        runner.assert_not_called()
        self.assertEqual(info["wslDistros"], distros)
        self.assertFalse(info["wslOperational"])
        self.assertEqual(
            info["wslDiscoveryError"],
            "shared discovery deadline expired",
        )
        self.assertTrue(info["packaged"])

    def test_precomputed_pending_platform_is_degraded_without_runner(self):
        runner = mock.Mock(side_effect=AssertionError("runner must not run"))
        adapter = WindowsAdapter(
            psutil_module=_Psutil(), runner=runner,
            environ={"USERPROFILE": r"C:\Users\example"},
        )
        with mock.patch(
            "console_platform.windows.shutil.which",
            return_value=r"C:\Windows\System32\wsl.exe",
        ):
            info = adapter.platform_info(
                wsl_distros=[],
                wsl_discovery_error=None,
                wsl_discovery_pending=True,
                wsl_discovery_ready=False,
                wsl_discovery_stale=False,
            )

        runner.assert_not_called()
        self.assertFalse(info["wslOperational"])
        self.assertTrue(info["wslDiscoveryPending"])
        self.assertFalse(info["wslDiscoveryStale"])
        self.assertNotIn("wslDiscoveryError", info)

    def test_invalid_or_dangerous_distro_names_are_rejected(self):
        for name in ("", "-Ubuntu", "Bad\nName"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_distro_name(name)


class WSLAdapterTests(unittest.TestCase):
    def setUp(self):
        self.payloads = {
            "listeners": [
                {"pid": 91, "port": 3000, "bind_hosts": ["127.0.0.1", "::1"]},
            ],
            "processes": [
                {"pid": 91, "uid": 1000, "ppid": 2, "comm": "node",
                 "args": "node app.js", "cpu": 1.0, "mem": 2.0,
                 "etime": 15, "create_time": 123.5},
            ],
            "cwds": {"91": "/home/example/project"},
        }

        def provider(operation, distro, pids):
            self.assertEqual(distro, "Ubuntu")
            return self.payloads[operation]

        self.adapter = WSLAdapter(
            "Ubuntu", helper_provider=provider,
            host_environ={
                "USERPROFILE": r"C:\Users\example",
                "LOCALAPPDATA": r"C:\Users\example\AppData\Local",
            },
        )

    def test_helper_snapshots_match_native_shapes(self):
        self.assertEqual(
            self.adapter.scan_listeners(), {(91, 3000): {"127.0.0.1", "::1"}})
        snapshot = self.adapter.process_snapshot([91])
        self.assertEqual(snapshot[91]["uid"], 1000)
        self.assertEqual(snapshot[91]["comm"], "node")
        self.assertEqual(
            self.adapter.process_cwds([91]), {91: "/home/example/project"})

    def test_shell_and_path_mapping_are_explicit(self):
        self.assertEqual(
            self.adapter.build_shell_command("npm run dev"),
            ["wsl.exe", "--distribution", "Ubuntu", "--",
             "/bin/sh", "-lc", "npm run dev"],
        )
        self.assertEqual(
            normalize_wsl_path(r"C:\Work\My App", "Ubuntu"),
            "/mnt/c/Work/My App",
        )
        self.assertEqual(
            normalize_wsl_path(
                r"\\wsl.localhost\Ubuntu\home\example\My App", "Ubuntu"),
            "/home/example/My App",
        )
        with self.assertRaises(ValueError):
            normalize_wsl_path(
                r"\\wsl.localhost\Debian\home\example", "Ubuntu")
        self.assertEqual(
            self.adapter.command_for_script(r"C:\Work\My App\run.sh"),
            "/bin/sh -- '/mnt/c/Work/My App/run.sh'",
        )

    def test_no_helper_is_an_explicit_degraded_capability(self):
        adapter = WSLAdapter("Ubuntu")
        with self.assertRaisesRegex(AdapterUnavailable, "helper"):
            adapter.scan_listeners()

    def test_host_runtime_dirs_remain_in_local_app_data(self):
        dirs = self.adapter.runtime_dirs()
        self.assertEqual(dirs.data_dir, r"C:\Users\example\AppData\Local\总控台")
        self.assertEqual(dirs.log_dir, r"C:\Users\example\AppData\Local\总控台\logs")


if __name__ == "__main__":
    unittest.main()
