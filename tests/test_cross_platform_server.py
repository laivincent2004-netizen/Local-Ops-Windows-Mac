import json
import http.client
import os
import tempfile
import unittest
from unittest import mock

import server
from console_platform.base import AdapterUnavailable, UserIdentity
from console_platform.windows import WindowsAdapter
from tests.test_hardening import HttpHarness


WINDOWS_EXECUTION = {
    "environment": "native", "shell": "auto", "distro": None,
}
WSL_EXECUTION = {
    "environment": "wsl", "shell": "posix", "distro": "Ubuntu-24.04",
}


class SchemaV2Tests(unittest.TestCase):
    def test_v1_apps_migrate_to_native_posix_without_losing_fields(self):
        original = {
            "schemaVersion": 1,
            "apps": [{"id": "deadbeef", "name": "旧服务",
                      "command": "python3 app.py", "port": 8000}],
            "hidden": [], "pinned": [], "promoted": [],
            "watchedKeywords": ["ffmpeg"], "uiTheme": "ops",
        }

        migrated, source_version = server.migrate_config(original)

        self.assertEqual(source_version, 1)
        self.assertEqual(migrated["schemaVersion"], 2)
        self.assertEqual(migrated["apps"][0]["execution"], {
            "environment": "native", "shell": "posix", "distro": None,
        })
        self.assertEqual(migrated["apps"][0]["command"], "python3 app.py")
        self.assertNotIn("execution", original["apps"][0])

    def test_execution_matrix_is_platform_specific(self):
        with mock.patch.object(server, "IS_WINDOWS", False):
            value, error = server.normalize_execution({
                "environment": "native", "shell": "posix", "distro": None})
            self.assertIsNone(error)
            self.assertEqual(value["shell"], "posix")
            self.assertIsNotNone(server.normalize_execution({
                "environment": "native", "shell": "cmd", "distro": None})[1])
            self.assertIsNotNone(server.normalize_execution(WSL_EXECUTION)[1])

        with mock.patch.object(server, "IS_WINDOWS", True):
            for shell in ("auto", "cmd", "powershell"):
                with self.subTest(shell=shell):
                    value, error = server.normalize_execution({
                        "environment": "native", "shell": shell,
                        "distro": None})
                    self.assertIsNone(error)
                    self.assertEqual(value["shell"], shell)
            self.assertIsNotNone(server.normalize_execution({
                "environment": "native", "shell": "posix", "distro": None})[1])
            value, error = server.normalize_execution(WSL_EXECUTION)
            self.assertIsNone(error)
            self.assertEqual(value, WSL_EXECUTION)
            self.assertIsNotNone(server.normalize_execution({
                "environment": "wsl", "shell": "posix", "distro": ""})[1])
            for distro in ("../Ubuntu", r"Ubuntu\evil", "-Ubuntu", "Ubuntu:"):
                with self.subTest(distro=distro):
                    self.assertIsNotNone(server.normalize_execution({
                        "environment": "wsl", "shell": "posix",
                        "distro": distro})[1])

    def test_fresh_windows_app_defaults_to_native_auto(self):
        with mock.patch.object(server, "IS_WINDOWS", True):
            fields, error = server.validate_app_fields({
                "name": "Windows 服务", "command": "npm run dev",
                "kind": "service", "port": 3000,
            }, partial=False)
        self.assertIsNone(error)
        self.assertEqual(fields["execution"], WINDOWS_EXECUTION)

    def test_invalid_schema_v2_execution_is_not_silently_run_as_native(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            invalid = {
                **server.Config.DEFAULT,
                "apps": [{
                    **server.Config.APP_DEFAULT,
                    "id": "deadbeef", "name": "Unsafe",
                    "command": "./linux-only.sh",
                    "execution": {
                        "environment": "native", "shell": "posix",
                        "distro": None,
                    },
                }],
            }
            with open(path, "w", encoding="utf-8") as stream:
                json.dump(invalid, stream)
            with mock.patch.object(server, "IS_WINDOWS", True):
                cfg = server.Config(path)

            self.assertFalse(cfg.health_info()["writable"])
            self.assertEqual(cfg.snapshot()["apps"], [])
            with open(path, "r", encoding="utf-8") as stream:
                self.assertEqual(json.load(stream), invalid)

    def test_runtime_identity_comparison_uses_environment_specific_clock(self):
        native = {"environment": "native", "pid": 42, "createTime": 100.5}
        self.assertTrue(server.same_runtime_identity(native, dict(native)))
        self.assertFalse(server.same_runtime_identity(
            native, {"environment": "native", "pid": 42,
                     "createTime": None}))

        wsl = {
            "environment": "wsl", "distro": "Ubuntu", "bootId": "boot-a",
            "pid": 42, "startTicks": 9001,
        }
        self.assertTrue(server.same_runtime_identity(
            wsl, dict(wsl, distro="ubuntu")))
        self.assertFalse(server.same_runtime_identity(
            wsl, dict(wsl, startTicks=9002)))
        self.assertFalse(server.same_runtime_identity(
            wsl, dict(wsl, bootId="boot-b")))


class WindowsInstanceIdentityTests(unittest.TestCase):
    SID = "S-1-5-21-100-200-300-1001"

    def _key(self, create_time="1723456789.125"):
        return server.make_instance_key(
            "native", 4242, create_time, port=3000, identity=self.SID,
            cwd=r"C:\工作区\博客", command="node server.js")

    def _snapshot(self, create_time=1723456789.125, identity=None):
        return {4242: {
            "uid": server.SELF_UID,
            "identity": identity or self.SID,
            "identity_kind": "sid",
            "create_time": create_time,
            "comm": r"C:\Program Files\nodejs\node.exe",
            "args": "node server.js",
            "cpu": 0.1, "mem": 0.2, "etime": 4,
        }}

    def _adapter(self):
        adapter = mock.Mock()
        adapter.current_user_identity.return_value = UserIdentity(
            "sid", self.SID, "DOMAIN\\user")
        return adapter

    def test_instance_key_carries_sid_create_time_and_rejects_tampering(self):
        key = self._key()
        payload = server.parse_instance_key(key)
        self.assertEqual(payload["environment"], "native")
        self.assertEqual(payload["pid"], 4242)
        self.assertEqual(payload["createTime"], "1723456789.125")
        self.assertEqual(payload["identity"], self.SID)
        self.assertEqual(payload["port"], 3000)
        self.assertEqual(len(payload["cwdHash"]), 64)
        self.assertEqual(len(payload["commandHash"]), 64)

        prefix, encoded, signature = key.split(".", 2)
        altered = ("A" if signature[0] != "A" else "B") + signature[1:]
        self.assertIsNone(server.parse_instance_key(
            ".".join((prefix, encoded, altered))))

    def test_live_identity_revalidation_blocks_pid_reuse_and_sid_change(self):
        key = self._key()
        common = [
            mock.patch.object(server, "_native_adapter",
                              return_value=self._adapter()),
            mock.patch.object(server, "lsof_cwds",
                              return_value={4242: r"C:\工作区\博客"}),
            mock.patch.object(server, "scan_listeners",
                              return_value={(4242, 3000)}),
        ]
        with common[0], common[1], common[2], \
                mock.patch.object(server, "ps_snapshot",
                                  return_value=self._snapshot()):
            verified, info, error = server.verify_native_instance_key(
                key, require_listener=True)
        self.assertIsNone(error)
        self.assertEqual(verified["identityKind"], "sid")
        self.assertEqual(info["create_time"], 1723456789.125)

        with common[0], common[1], common[2], \
                mock.patch.object(server, "ps_snapshot",
                                  return_value=self._snapshot(1723456799.0)):
            verified, _info, error = server.verify_native_instance_key(
                key, require_listener=True)
        self.assertIsNone(verified)
        self.assertIn("PID 已被复用", error)

        with common[0], common[1], common[2], \
                mock.patch.object(server, "ps_snapshot", return_value=
                                  self._snapshot(identity="S-1-5-21-foreign")):
            verified, _info, error = server.verify_native_instance_key(
                key, require_listener=True)
        self.assertIsNone(verified)
        self.assertIn("SID", error)

    def test_windows_service_rows_publish_opaque_instance_keys(self):
        snapshot = self._snapshot()
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "scan_listeners",
                                  return_value={(4242, 3000): {"127.0.0.1"}}), \
                mock.patch.object(server, "ps_snapshot", return_value=snapshot), \
                mock.patch.object(server, "lsof_cwds",
                                  return_value={4242: r"C:\工作区\博客"}), \
                mock.patch.object(server, "origin_snapshot",
                                  return_value={}) as origin, \
                mock.patch.object(server, "listener_app_owners", return_value={}):
            rows, _listeners = server.build_services({"apps": []})

        origin.assert_called_once_with([4242])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["instanceKey"].startswith("ik1."))
        payload = server.parse_instance_key(rows[0]["instanceKey"])
        self.assertEqual(payload["identity"], self.SID)
        self.assertEqual(payload["createTime"], "1723456789.125")

    def test_windows_watched_rows_publish_non_listener_instance_keys(self):
        snapshot = self._snapshot()
        snapshot[4242]["args"] = "ffmpeg -i input.mov output.mp4"
        snapshot[4242]["comm"] = r"C:\tools\ffmpeg.exe"
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "ps_snapshot", return_value=snapshot), \
                mock.patch.object(server, "lsof_cwds",
                                  return_value={4242: r"C:\工作区\视频"}):
            rows = server.build_watched(["ffmpeg"])

        self.assertEqual(len(rows), 1)
        payload = server.parse_instance_key(rows[0]["instanceKey"])
        self.assertEqual(payload["pid"], 4242)
        self.assertIsNone(payload["port"])

    def test_native_port_owner_publishes_listener_bound_instance_key(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Stopped", "command": "npm start",
            "port": 3000, "execution": WINDOWS_EXECUTION,
        }
        snapshot = self._snapshot()
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "managed_process_index",
                                  return_value=({"deadbeef": []}, {}, {})), \
                mock.patch.object(server, "ps_snapshot", return_value=snapshot), \
                mock.patch.object(server, "lsof_cwds",
                                  return_value={4242: r"C:\工作区\博客"}), \
                mock.patch.object(server, "listener_app_owners", return_value={}):
            result = server.build_apps(
                {"apps": [app]}, {(4242, 3000): {"127.0.0.1"}})[0]
        owner = result["portOwner"]
        self.assertTrue(owner["instanceKey"].startswith("ik1."))
        payload = server.parse_instance_key(owner["instanceKey"])
        self.assertEqual(payload["port"], 3000)
        self.assertEqual(payload["identity"], self.SID)

    def test_wsl_port_owner_publishes_boot_bound_instance_key(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Stopped WSL", "command": "npm start",
            "port": 4000, "execution": WSL_EXECUTION,
        }
        scan = {
            "distro": "Ubuntu-24.04", "bootId": "boot-a", "uid": 1000,
            "processes": [{
                "pid": 91, "uid": 1000, "startTicks": 12345,
                "comm": "node", "args": "node server.js",
                "cwd": "/home/example/project",
                "cwdHash": "a" * 64, "commandHash": "b" * 64,
            }],
            "listeners": [{"pid": 91, "port": 4000,
                           "bind_hosts": ["127.0.0.1"]}],
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "supervisor_runtime_status",
                                  return_value=None), \
                mock.patch.object(server, "inspect_app_health", return_value={
                    "status": "ok", "blocking": False, "issues": []}):
            result = server._build_wsl_app(
                app, server._wsl_scan_index([scan]), set())
        owner = result["portOwner"]
        payload = server.parse_instance_key(owner["instanceKey"])
        self.assertEqual(payload["environment"], "wsl")
        self.assertEqual(payload["distro"], "Ubuntu-24.04")
        self.assertEqual(payload["bootId"], "boot-a")
        self.assertEqual(payload["port"], 4000)
        self.assertEqual(payload["identity"], "1000")


class WindowsAdapterAuthorizationTests(unittest.TestCase):
    SID = WindowsInstanceIdentityTests.SID

    def _adapter_and_process(self, owner="DOMAIN\\user", create_time=100.25):
        process = mock.Mock(pid=4242)
        process.info = {
            "pid": 4242, "ppid": 1, "name": "node.exe",
            "exe": r"C:\Program Files\nodejs\node.exe",
            "cmdline": ["node", "server.js"], "username": owner,
            "cpu_percent": 0.0, "memory_percent": 0.1,
            "create_time": create_time,
        }
        process.create_time.return_value = create_time
        process.username.return_value = owner
        psutil = mock.Mock()
        psutil.Process.return_value = process
        adapter = WindowsAdapter(
            psutil_module=psutil,
            environ={"USERNAME": "user", "USERDOMAIN": "DOMAIN"})
        adapter._identity = UserIdentity("sid", self.SID, "DOMAIN\\user")
        return adapter, process

    def test_snapshot_marks_foreign_owner_sid_as_non_current(self):
        adapter, _process = self._adapter_and_process(owner="DOMAIN\\other")
        with mock.patch.object(
                adapter, "_sid_for_username",
                return_value="S-1-5-21-foreign"):
            snapshot = adapter.process_snapshot([4242])

        self.assertEqual(snapshot[4242]["uid"], -1)
        self.assertEqual(snapshot[4242]["identity"], "S-1-5-21-foreign")
        self.assertEqual(snapshot[4242]["identity_kind"], "sid")

    def test_force_termination_revalidates_create_time_and_sid(self):
        adapter, process = self._adapter_and_process()
        identity = {"pid": 4242, "createTime": 100.25,
                    "identity": self.SID}
        with mock.patch.object(adapter, "_sid_for_username",
                               return_value=self.SID):
            adapter.terminate_process(identity)
        process.kill.assert_called_once_with()

        process.reset_mock()
        with mock.patch.object(adapter, "_sid_for_username",
                               return_value=self.SID):
            with self.assertRaisesRegex(AdapterUnavailable, "PID 已被复用"):
                adapter.terminate_process(dict(identity, createTime=99.0))
        process.kill.assert_not_called()

        with mock.patch.object(adapter, "_sid_for_username",
                               return_value="S-1-5-21-foreign"):
            with self.assertRaisesRegex(AdapterUnavailable, "SID"):
                adapter.terminate_process(identity)
        process.kill.assert_not_called()


class PlatformEndpointTests(unittest.TestCase):
    def setUp(self):
        self.harness = HttpHarness()

    def tearDown(self):
        self.harness.close()

    def test_platform_endpoint_preserves_wsl_capability_and_error_shape(self):
        payload = {
            "os": "windows", "arch": "amd64",
            "shells": ["auto", "cmd", "powershell"],
            "packaged": True, "wslAvailable": True,
            "wslOperational": False, "wslDistros": [],
            "wslDiscoveryError": "Access is denied",
        }
        with mock.patch.object(server, "get_platform_info",
                               return_value=payload):
            status, body, _headers = self.harness.request(
                "GET", "/api/platform")
        self.assertEqual(status, 200)
        self.assertEqual(body, payload)


class WindowsDestructiveEndpointTests(unittest.TestCase):
    SID = WindowsInstanceIdentityTests.SID

    def setUp(self):
        self.harness = HttpHarness()
        self.headers = {"Content-Type": "application/json"}
        self.key = server.make_instance_key(
            "native", 4242, 100.25, port=3000, identity=self.SID,
            cwd=r"C:\workspace\blog", command="node server.js")
        self.identity = {
            "type": "external", "environment": "native", "pid": 4242,
            "createTime": 100.25, "identity": self.SID,
            "identityKind": "sid", "cwd": r"C:\workspace\blog",
            "cwdHash": server._identity_digest(r"C:\workspace\blog"),
            "commandHash": server._identity_digest("node server.js"),
            "port": 3000,
        }

    def tearDown(self):
        self.harness.close()

    def _request(self, path, payload):
        return self.harness.request(
            "POST", path, json.dumps(payload), self.headers)

    def _put(self, path, payload):
        return self.harness.request(
            "PUT", path, json.dumps(payload), self.headers)

    def test_unknown_post_body_is_drained_before_keep_alive_reuse(self):
        conn = http.client.HTTPConnection(
            server.HOST, self.harness.port, timeout=4)
        try:
            conn.request(
                "POST", "/api/not-a-route", body=b"{}",
                headers={"Content-Type": "application/json"})
            missing = conn.getresponse()
            missing.read()
            self.assertEqual(missing.status, 404)

            conn.request("GET", "/api/health")
            health = conn.getresponse()
            body = json.loads(health.read().decode("utf-8"))
            self.assertEqual(health.status, 200)
            self.assertIn("status", body)
        finally:
            conn.close()

    def test_put_early_rejections_drain_body_before_keep_alive_reuse(self):
        cases = (("/api/not-a-route", 404, False),
                 ("/api/apps/deadbeef", 409, True))
        for path, expected_status, hold_operation in cases:
            with self.subTest(path=path):
                held = (self.harness.httpd.try_app_operation("deadbeef")
                        if hold_operation else None)
                conn = http.client.HTTPConnection(
                    server.HOST, self.harness.port, timeout=4)
                try:
                    conn.request(
                        "PUT", path, body=b"{}",
                        headers={"Content-Type": "application/json"})
                    rejected = conn.getresponse()
                    rejected.read()
                    self.assertEqual(rejected.status, expected_status)

                    conn.request("GET", "/api/health")
                    health = conn.getresponse()
                    body = json.loads(health.read().decode("utf-8"))
                    self.assertEqual(health.status, 200)
                    self.assertIn("status", body)
                finally:
                    conn.close()
                    if held is not None:
                        held.release()

    def test_running_app_cannot_switch_execution_without_stop(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Service", "command": "npm start",
            "port": 3000, "kind": "service",
            "execution": WINDOWS_EXECUTION,
            "runToken": "t" * 43,
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))
        requested = {
            "environment": "native", "shell": "powershell", "distro": None,
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=True), \
                mock.patch.object(server, "stop_app_for_update") as stop:
            status, body, _ = self._put(
                "/api/apps/deadbeef", {"execution": requested})

        self.assertEqual(status, 409)
        self.assertTrue(body["requiresStop"])
        stop.assert_not_called()
        stored = server.find_app(self.harness.cfg.snapshot(), "deadbeef")
        self.assertEqual(stored["execution"], WINDOWS_EXECUTION)

    def test_start_config_write_error_rolls_back_started_supervisor(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Service", "command": "npm start",
            "port": 3000, "kind": "service", "execution": WINDOWS_EXECUTION,
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))
        proc = mock.Mock(pid=4242)
        proc.runtime_identity = {
            "type": "supervisor", "runId": "run-1",
            "metadataPath": "runtime.json",
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=False), \
                mock.patch.object(server, "inspect_app_health", return_value={
                    "status": "ok", "blocking": False, "issues": []}), \
                mock.patch.object(server, "configured_port_occupant",
                                  return_value=None), \
                mock.patch.object(
                    server, "start_app",
                    return_value=(True, None, proc, 111, "runtime-token")), \
                mock.patch.object(
                    server, "persist_started_app",
                    side_effect=OSError("config disk full")), \
                mock.patch.object(
                    server, "cancel_unpersisted_runtime",
                    return_value=(True, None)) as cancel:
            status, body, _ = self._request(
                "/api/apps/deadbeef/start", {})

        self.assertEqual(status, 500)
        self.assertFalse(body["ok"])
        self.assertIn("config disk full", body["error"])
        self.assertNotIn("runtimeRetained", body)
        cancel.assert_called_once_with(proc, 111, "runtime-token")

    def test_start_timeout_with_unconfirmed_cleanup_retains_handle_and_token(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Service", "command": "npm start",
            "port": 3000, "kind": "service", "execution": WINDOWS_EXECUTION,
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))
        token = "recoverable-runtime-token-" + "t" * 32
        metadata = {
            "state": "startup-cleanup-failed", "running": True,
            "environment": "native", "distro": None,
            "runId": "deadbeef-recovery", "supervisorVersion": "2.0.0",
            "supervisorPid": 111, "supervisorCreateTime": 100.5,
            "ownerSid": self.SID, "childPid": 222,
            "childCreateTime": 101.5,
        }
        proc = server.SupervisorRuntimeHandle(
            "runtime-recovery.json", metadata, token)
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=False), \
                mock.patch.object(server, "inspect_app_health", return_value={
                    "status": "ok", "blocking": False, "issues": []}), \
                mock.patch.object(server, "configured_port_occupant",
                                  return_value=None), \
                mock.patch.object(
                    server, "start_app",
                    return_value=(False, "supervisor startup timed out",
                                  proc, 111, token)), \
                mock.patch.object(server, "watch_app_exit") as watch:
            status, body, _ = self._request(
                "/api/apps/deadbeef/start", {})

        self.assertEqual(status, 500)
        self.assertFalse(body["ok"])
        self.assertTrue(body["runtimeRetained"])
        self.assertEqual(body["pid"], 222)
        stored = server.find_app(
            self.harness.cfg.snapshot(), "deadbeef")
        self.assertEqual(stored["runToken"], token)
        self.assertEqual(stored["processIdentity"]["runId"],
                         "deadbeef-recovery")
        self.assertTrue(stored["processIdentity"]["recoveryPending"])
        watch.assert_called_once()

    def test_restart_config_write_error_rolls_back_replacement_supervisor(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Service", "command": "npm start",
            "port": 3000, "kind": "service", "execution": WINDOWS_EXECUTION,
            "runToken": "old-runtime-token",
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))
        proc = mock.Mock(pid=5252)
        proc.runtime_identity = {
            "type": "supervisor", "runId": "run-2",
            "metadataPath": "replacement-runtime.json",
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=True), \
                mock.patch.object(server, "inspect_app_health", return_value={
                    "status": "ok", "blocking": False, "issues": []}), \
                mock.patch.object(server, "stop_app_and_clear",
                                  return_value=(True, None)) as stop, \
                mock.patch.object(server, "configured_port_occupant",
                                  return_value=None), \
                mock.patch.object(
                    server, "start_app",
                    return_value=(True, None, proc, 222, "new-runtime-token")), \
                mock.patch.object(
                    server, "persist_started_app",
                    side_effect=OSError("restart config disk full")), \
                mock.patch.object(
                    server, "cancel_unpersisted_runtime",
                    return_value=(True, None)) as cancel:
            status, body, _ = self._request(
                "/api/apps/deadbeef/restart", {})

        self.assertEqual(status, 500)
        self.assertFalse(body["ok"])
        self.assertIn("restart config disk full", body["error"])
        self.assertNotIn("runtimeRetained", body)
        stop.assert_called_once()
        cancel.assert_called_once_with(proc, 222, "new-runtime-token")

    def test_restart_timeout_with_unconfirmed_cleanup_retains_new_identity(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Service", "command": "npm start",
            "port": 3000, "kind": "service", "execution": WINDOWS_EXECUTION,
            "runToken": "old-runtime-token",
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))
        token = "restart-recovery-token-" + "t" * 32
        metadata = {
            "state": "startup-cleanup-failed", "running": True,
            "environment": "native", "distro": None,
            "runId": "restart-recovery", "supervisorVersion": "2.0.0",
            "supervisorPid": 311, "supervisorCreateTime": 200.5,
            "ownerSid": self.SID, "childPid": 322,
            "childCreateTime": 201.5, "recoveryPending": True,
        }
        proc = server.SupervisorRuntimeHandle(
            "restart-recovery.json", metadata, token)
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=True), \
                mock.patch.object(server, "inspect_app_health", return_value={
                    "status": "ok", "blocking": False, "issues": []}), \
                mock.patch.object(server, "stop_app_and_clear",
                                  return_value=(True, None)) as stop, \
                mock.patch.object(server, "configured_port_occupant",
                                  return_value=None), \
                mock.patch.object(
                    server, "start_app",
                    return_value=(False, "supervisor startup timed out",
                                  proc, 311, token)), \
                mock.patch.object(server, "watch_app_exit") as watch:
            status, body, _ = self._request(
                "/api/apps/deadbeef/restart", {})

        self.assertEqual(status, 500)
        self.assertFalse(body["ok"])
        self.assertTrue(body["runtimeRetained"])
        self.assertEqual(body["pid"], 322)
        stored = server.find_app(
            self.harness.cfg.snapshot(), "deadbeef")
        self.assertEqual(stored["runToken"], token)
        self.assertEqual(stored["processIdentity"]["runId"],
                         "restart-recovery")
        self.assertTrue(stored["processIdentity"]["recoveryPending"])
        stop.assert_called_once()
        watch.assert_called_once()

    def test_windows_kill_refuses_bare_pid_and_requires_force_for_external(self):
        with mock.patch.object(server, "IS_WINDOWS", True):
            status, body, _ = self._request("/api/kill", {"pid": 4242})
        self.assertEqual(status, 400)
        self.assertIn("instanceKey", body["error"])

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "verify_native_instance_key",
                                  return_value=(self.identity, {}, None)), \
                mock.patch.object(server, "_native_adapter") as adapter:
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": self.key})
        self.assertEqual(status, 409)
        self.assertTrue(body["requiresForce"])
        adapter.assert_not_called()

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "verify_native_instance_key",
                                  return_value=(None, None,
                                                "进程身份已失效，请刷新后重试")):
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": self.key})
        self.assertEqual(status, 409)
        self.assertFalse(body["ok"])
        self.assertNotIn("requiresForce", body)
        self.assertIn("刷新", body["error"])

        adapter = mock.Mock()
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "verify_native_instance_key",
                                  return_value=(self.identity, {}, None)), \
                mock.patch.object(server, "_native_adapter",
                                  return_value=adapter):
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": self.key, "force": True})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        adapter.terminate_process.assert_called_once_with(self.identity)

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "kill_process") as kill:
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": self.key, "force": "true"})
        self.assertEqual(status, 400)
        self.assertIn("布尔", body["error"])
        kill.assert_not_called()

    def test_watched_process_identity_does_not_require_a_listener(self):
        key = server.make_instance_key(
            "native", 4242, 100.25, identity=self.SID,
            cwd=r"C:\workspace\video",
            command="ffmpeg -i input.mov output.mp4")
        identity = dict(self.identity, port=None,
                        cwd=r"C:\workspace\video")
        identity["cwdHash"] = server._identity_digest(identity["cwd"])
        identity["commandHash"] = server._identity_digest(
            "ffmpeg -i input.mov output.mp4")
        adapter = mock.Mock()
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "verify_native_instance_key",
                                  return_value=(identity, {}, None)) as verify, \
                mock.patch.object(server, "_native_adapter",
                                  return_value=adapter):
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": key, "force": True})

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        verify.assert_called_once_with(key, require_listener=False)
        adapter.terminate_process.assert_called_once_with(identity)

    def test_windows_attach_requires_instance_key_and_persists_full_identity(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "博客", "command": "node server.js",
            "cwd": r"C:\old", "port": 3000, "kind": "service",
            "execution": WINDOWS_EXECUTION,
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))

        with mock.patch.object(server, "IS_WINDOWS", True):
            status, body, _ = self._request(
                "/api/apps/deadbeef/attach", {"pid": 4242})
        self.assertEqual(status, 400)
        self.assertIn("instanceKey", body["error"])

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=False), \
                mock.patch.object(server, "verify_native_instance_key",
                                  return_value=(self.identity, {}, None)):
            status, body, _ = self._request(
                "/api/apps/deadbeef/attach", {"instanceKey": self.key})

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        stored = server.find_app(self.harness.cfg.snapshot(), "deadbeef")
        self.assertEqual(stored["processIdentity"], self.identity)
        self.assertEqual(stored["lastPid"], 4242)
        self.assertTrue(stored["attached"])

    def test_windows_create_attach_is_atomic_and_rejects_legacy_attach_pid(self):
        payload = {
            "name": "博客", "command": "node server.js",
            "cwd": r"C:\old", "port": 3000, "kind": "service",
            "execution": WINDOWS_EXECUTION,
        }
        with mock.patch.object(server, "IS_WINDOWS", True):
            status, body, _ = self._request(
                "/api/apps", {**payload, "attachPid": 4242})
        self.assertEqual(status, 400)
        self.assertEqual(self.harness.cfg.snapshot()["apps"], [])

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=False), \
                mock.patch.object(server, "verify_native_instance_key",
                                  return_value=(self.identity, {}, None)):
            status, body, _ = self._request(
                "/api/apps", {**payload, "attachInstanceKey": self.key})
        self.assertEqual(status, 200)
        self.assertTrue(body["attached"])
        self.assertEqual(len(self.harness.cfg.snapshot()["apps"]), 1)

    def test_wsl_atomic_attach_does_not_compare_missing_native_create_time(self):
        existing_identity = {
            "type": "external", "environment": "wsl", "distro": "Ubuntu",
            "bootId": "boot-a", "pid": 77, "startTicks": 100,
        }
        existing = {
            **server.Config.APP_DEFAULT,
            "id": "existing", "name": "Existing", "command": "npm start",
            "cwd": "/home/example/one", "port": 3000,
            "execution": {"environment": "wsl", "shell": "posix",
                          "distro": "Ubuntu"},
            "processIdentity": existing_identity, "attached": True,
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(existing))
        payload = {
            "name": "Second", "command": "npm start",
            "cwd": "/home/example/two", "port": 3000, "kind": "service",
            "execution": {"environment": "wsl", "shell": "posix",
                          "distro": "Ubuntu"},
            "attachInstanceKey": "signed-key",
        }
        new_identity = dict(existing_identity, startTicks=200)
        inspected = {
            "status": 200, "cwd": "/home/example/two", "pid": 77,
            "processIdentity": new_identity,
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "inspect_attach_process",
                                  return_value=(True, None, inspected)):
            status, body, _ = self._request("/api/apps", payload)

        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.harness.cfg.snapshot()["apps"]), 2)

    def test_wsl_existing_attach_rechecks_start_ticks_inside_write_lock(self):
        old_identity = {
            "type": "external", "environment": "wsl", "distro": "Ubuntu",
            "bootId": "boot-a", "pid": 77, "startTicks": 100,
        }
        existing = {
            **server.Config.APP_DEFAULT,
            "id": "existing", "name": "Existing", "command": "npm start",
            "cwd": "/home/example/one", "port": 3000,
            "execution": {"environment": "wsl", "shell": "posix",
                          "distro": "Ubuntu"},
            "processIdentity": old_identity, "attached": True,
        }
        target = {
            **server.Config.APP_DEFAULT,
            "id": "target", "name": "Target", "command": "npm start",
            "cwd": "/home/example/two", "port": 3000,
            "execution": {"environment": "wsl", "shell": "posix",
                          "distro": "Ubuntu"},
        }
        self.harness.cfg.update(
            lambda cfg: cfg["apps"].extend([existing, target]))
        new_identity = dict(old_identity, startTicks=200)
        inspected = {
            "status": 200, "cwd": "/home/example/two", "pid": 77,
            "processIdentity": new_identity,
        }
        with mock.patch.object(
                server, "inspect_attach_process",
                return_value=(True, None, inspected)):
            ok, error, _info = server.attach_app_process(
                self.harness.cfg, "target", target,
                instance_key="signed-key")

        self.assertTrue(ok, error)
        stored = server.find_app(self.harness.cfg.snapshot(), "target")
        self.assertEqual(stored["processIdentity"]["startTicks"], 200)

    def test_wsl_kill_routes_signed_identity_and_propagates_force_prompt(self):
        key = server.make_instance_key(
            "wsl", 77, 9001, distro="Ubuntu-24.04", boot_id="boot-1",
            port=4187, identity=1000, cwd_hash="a" * 64,
            command_hash="b" * 64)
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "kill_wsl_process", return_value=(
                    False, "SIGTERM timed out", True)) as kill:
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": key})
        self.assertEqual(status, 409)
        self.assertTrue(body["requiresForce"])
        kill.assert_called_once_with(key, force=False)

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "kill_wsl_process",
                                  return_value=(True, None, False)) as kill:
            status, body, _ = self._request(
                "/api/kill", {"instanceKey": key, "force": True})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        kill.assert_called_once_with(key, force=True)

    def test_app_stop_timeout_keeps_identity_and_returns_requires_force(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Service", "command": "node app.js",
            "runToken": "t" * 43,
            "processIdentity": {"type": "supervisor", "runId": "run-1"},
        }
        self.harness.cfg.update(lambda cfg: cfg["apps"].append(app))
        error = server.ProcessControlError(
            "应用未在 5 秒内退出，仍保留管理状态", requires_force=True)
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "app_alive_sign", return_value=True), \
                mock.patch.object(server, "stop_app_and_clear",
                                  return_value=(False, error)) as stop:
            status, body, _ = self._request(
                "/api/apps/deadbeef/stop", {})

        self.assertEqual(status, 409)
        self.assertTrue(body["requiresForce"])
        self.assertEqual(
            server.find_app(self.harness.cfg.snapshot(), "deadbeef")["runToken"],
            "t" * 43)
        self.assertFalse(stop.call_args.kwargs.get("force", False))

    def test_wsl_timeout_diagnostic_never_treats_linux_pid_as_host_pgid(self):
        target = {
            "kind": "external-wsl", "id": 77, "members": [77],
            "identity": {"environment": "wsl", "pid": 77},
        }
        with mock.patch.object(server, "resolve_app_stop_target",
                               return_value=(target, None)), \
                mock.patch.object(server, "signal_app_stop",
                                  return_value=(True, None)), \
                mock.patch.object(server, "stop_target_alive",
                                  return_value=True), \
                mock.patch.object(server, "_current_user_group_members") as groups:
            ok, error = server.stop_app_and_wait({}, timeout=0)
        self.assertFalse(ok)
        self.assertTrue(error.requires_force)
        self.assertIn("PID 77", str(error))
        groups.assert_not_called()


class SupervisorReclaimTests(unittest.TestCase):
    SID = WindowsInstanceIdentityTests.SID

    def _app(self, data_dir):
        from supervisor_client import metadata_path
        token = "t" * 43
        run_id = "deadbeef-0123456789abcdef"
        return {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "runToken": token, "lastPid": 8800,
            "processIdentity": {
                "type": "supervisor", "environment": "native",
                "distro": None, "bootId": None, "runId": run_id,
                "metadataPath": metadata_path(data_dir, run_id),
                "pid": 9900, "createTime": 200.5,
                "ownerSid": self.SID,
            },
        }

    def _adapter(self):
        adapter = mock.Mock()
        adapter.current_user_identity.return_value = UserIdentity(
            "sid", self.SID, "DOMAIN\\user")
        return adapter

    def test_restart_reclaims_persisted_supervisor_identity(self):
        with tempfile.TemporaryDirectory() as td:
            app = self._app(td)
            status = {
                "ok": True, "running": True, "childPid": 9900,
                "runId": app["processIdentity"]["runId"],
            }
            with mock.patch.object(server, "DATA_DIR", td), \
                    mock.patch("supervisor_client.reclaim_supervisor",
                               return_value=status) as reclaim:
                result = server.supervisor_runtime_status(app)

        self.assertEqual(result, status)
        expected = reclaim.call_args.kwargs["expected"]
        self.assertEqual(expected["runId"], app["processIdentity"]["runId"])
        self.assertEqual(expected["environment"], "native")

    def test_recovery_pending_identity_stays_running_and_stoppable_on_pipe_error(self):
        with tempfile.TemporaryDirectory() as td:
            app = self._app(td)
            app["processIdentity"]["recoveryPending"] = True
            unavailable = {
                "ok": False, "stale": True,
                "error": "supervisor pipe temporarily unavailable",
            }
            with mock.patch.object(server, "IS_WINDOWS", True), \
                    mock.patch.object(server, "supervisor_runtime_status",
                                      return_value=unavailable):
                self.assertTrue(server.app_alive_sign(app))
                target, error = server.resolve_app_stop_target(app)

        self.assertIsNone(error)
        self.assertEqual(target["kind"], "supervisor")
        self.assertEqual(target["metadataPath"],
                         app["processIdentity"]["metadataPath"])
        self.assertEqual(target["token"], app["runToken"])

    def test_windows_managed_index_uses_live_job_member_after_root_exits(self):
        with tempfile.TemporaryDirectory() as td:
            app = self._app(td)
            app.update({
                "name": "Service", "command": "npm start", "port": 3000,
                "kind": "service", "execution": WINDOWS_EXECUTION,
            })
            status = {
                "ok": True, "running": True, "environment": "native",
                "runId": app["processIdentity"]["runId"],
                "ownerSid": self.SID, "childPid": 9900,
                "childCreateTime": 123.5,
                "jobProcessIds": [9910],
                "jobProcesses": [{
                    "pid": 9910, "createTime": 124.5,
                    "ownerSid": self.SID,
                }],
            }
            snapshot = {9910: {
                "uid": server.SELF_UID, "create_time": 124.5,
                "identity": self.SID, "identity_kind": "sid",
                "comm": "node.exe", "args": "node server.js",
                "cpu": 0.0, "mem": 0.1, "etime": 8,
            }}
            with mock.patch.object(server, "IS_WINDOWS", True), \
                    mock.patch.object(server, "supervisor_runtime_status",
                                      return_value=status), \
                    mock.patch.object(server, "_native_adapter",
                                      return_value=self._adapter()), \
                    mock.patch.object(server, "ps_snapshot",
                                      return_value=snapshot), \
                    mock.patch.object(server, "lsof_cwds",
                                      return_value={9910: r"C:\workspace\app"}), \
                    mock.patch.object(server, "inspect_app_health", return_value={
                        "status": "ok", "blocking": False, "issues": []}):
                index, _snapshot, _groups = server.managed_process_index([app])
                public = server.build_apps(
                    {"apps": [app]},
                    {(9910, 3000): {"127.0.0.1"}},
                )[0]

            self.assertEqual(index["deadbeef"], [9910])
            self.assertTrue(public["running"])
            self.assertEqual(public["pid"], 9910)
            self.assertTrue(public["listening"])
            self.assertFalse(public["portOccupied"])
            self.assertEqual(public["ports"], [3000])

    def test_windows_job_member_revalidates_create_time_and_current_sid(self):
        with tempfile.TemporaryDirectory() as td:
            app = self._app(td)
            status = {
                "ok": True, "running": True, "environment": "native",
                "runId": app["processIdentity"]["runId"],
                "ownerSid": self.SID,
                "jobProcessIds": [9910],
                "jobProcesses": [{
                    "pid": 9910, "createTime": 124.5,
                    "ownerSid": self.SID,
                }],
            }
            snapshot = {9910: {
                "uid": server.SELF_UID, "create_time": 125.5,
                "identity": self.SID, "identity_kind": "sid",
                "comm": "node.exe", "args": "node server.js",
            }}
            patches = (
                mock.patch.object(server, "IS_WINDOWS", True),
                mock.patch.object(server, "supervisor_runtime_status",
                                  return_value=status),
                mock.patch.object(server, "_native_adapter",
                                  return_value=self._adapter()),
                mock.patch.object(server, "ps_snapshot", return_value=snapshot),
            )
            with patches[0], patches[1], patches[2], patches[3]:
                index, _snapshot, _groups = server.managed_process_index([app])
            self.assertEqual(index["deadbeef"], [])

            snapshot[9910]["create_time"] = 124.5
            snapshot[9910]["identity"] = "S-1-5-21-foreign"
            with mock.patch.object(server, "IS_WINDOWS", True), \
                    mock.patch.object(server, "supervisor_runtime_status",
                                      return_value=status), \
                    mock.patch.object(server, "_native_adapter",
                                      return_value=self._adapter()), \
                    mock.patch.object(server, "ps_snapshot", return_value=snapshot):
                index, _snapshot, _groups = server.managed_process_index([app])
            self.assertEqual(index["deadbeef"], [])

    def test_supervisor_timeout_surfaces_requires_force_without_escalation(self):
        target = {
            "kind": "supervisor", "id": "run", "metadataPath": "meta.json",
            "token": "t" * 43, "members": [9900],
        }
        with mock.patch("supervisor_client.stop_supervisor", return_value={
                "ok": False, "running": True, "requiresForce": True,
                "error": "timed out"}) as stop:
            ok, error = server.signal_app_stop(target, force=False)
        self.assertFalse(ok)
        self.assertTrue(error.requires_force)
        stop.assert_called_once()
        self.assertFalse(stop.call_args.kwargs["force"])

    def test_windows_force_stop_does_not_require_sigkill_constant(self):
        target = {
            "kind": "external-native", "id": 9900,
            "identity": {"pid": 9900}, "members": [9900],
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "resolve_app_stop_target",
                                  return_value=(target, None)), \
                mock.patch.object(server, "signal_app_stop",
                                  return_value=(True, None)) as send, \
                mock.patch.object(server, "stop_target_alive",
                                  return_value=False):
            ok, error = server.stop_app_and_wait({}, force=True)

        self.assertTrue(ok)
        self.assertIsNone(error)
        send.assert_called_once_with(target, server.signal.SIGTERM, force=True)

    def test_posix_force_stop_uses_sigkill(self):
        target = {"kind": "group", "id": 9900, "members": [9900]}
        with mock.patch.object(server, "IS_WINDOWS", False), \
                mock.patch.object(server.signal, "SIGKILL", 9, create=True), \
                mock.patch.object(server, "resolve_app_stop_target",
                                  return_value=(target, None)), \
                mock.patch.object(server, "signal_app_stop",
                                  return_value=(True, None)) as send, \
                mock.patch.object(server, "stop_target_alive",
                                  return_value=False):
            ok, error = server.stop_app_and_wait({}, force=True)

        self.assertTrue(ok)
        self.assertIsNone(error)
        send.assert_called_once_with(target, 9, force=True)

    def test_frozen_windows_exit_cleans_only_unreferenced_supervisors(self):
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server.sys, "frozen", True, create=True), \
                mock.patch("supervisor_client.cleanup_unused_supervisors",
                           return_value=["old.exe"]) as cleanup:
            removed = server.cleanup_finished_supervisor_versions()

        self.assertEqual(removed, ["old.exe"])
        cleanup.assert_called_once_with(
            server.DATA_DIR,
            keep_versions=(__import__("supervisor_client").SUPERVISOR_VERSION,))

    def test_all_terminal_metadata_states_avoid_dead_pipe_retry(self):
        for state in sorted(server.SUPERVISOR_TERMINAL_STATES):
            with self.subTest(state=state):
                metadata = {
                    "state": state, "running": False,
                    "environment": "wsl", "runId": "run-1",
                }
                handle = server.SupervisorRuntimeHandle(
                    "runtime.json", metadata, "t" * 43)
                with mock.patch("supervisor_client.load_metadata",
                                return_value=metadata), \
                        mock.patch("supervisor_client.status_supervisor") as status:
                    result = handle._snapshot()

                self.assertEqual(result, metadata)
                status.assert_not_called()

    def test_authenticated_wsl_identity_loss_metadata_reclaims_offline(self):
        import hashlib

        token = "t" * 43
        for state in ("distro-restarted", "session-lost"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as td:
                app = self._app(td)
                app["kind"] = "task"
                app["processIdentity"].update({
                    "environment": "wsl", "distro": "Ubuntu",
                    "bootId": "boot-a",
                })
                metadata = {
                    "state": state, "running": False,
                    "environment": "wsl", "distro": "Ubuntu",
                    "runId": app["processIdentity"]["runId"],
                    "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
                    "updatedAt": 1234,
                    "wsl": {"bootId": "boot-a"},
                }
                app["runToken"] = token
                with mock.patch.object(server, "IS_WINDOWS", True), \
                        mock.patch.object(server, "DATA_DIR", td), \
                        mock.patch("supervisor_client.reclaim_supervisor",
                                   return_value={"ok": False, "stale": True}), \
                        mock.patch("supervisor_client.load_metadata",
                                   return_value=metadata):
                    status = server.supervisor_runtime_status(app)
                    last_exit = server.runtime_last_exit(app, status)
                self.assertTrue(status["ok"])
                self.assertFalse(status["running"])
                self.assertEqual(last_exit["status"], "failed")
                self.assertEqual(last_exit["code"], 1)

    def test_offline_wsl_terminal_metadata_rejects_changed_boot(self):
        import hashlib

        with tempfile.TemporaryDirectory() as td:
            app = self._app(td)
            token = app["runToken"]
            app["processIdentity"].update({
                "environment": "wsl", "distro": "Ubuntu",
                "bootId": "boot-a",
            })
            metadata = {
                "state": "session-lost", "running": False,
                "environment": "wsl", "distro": "Ubuntu",
                "runId": app["processIdentity"]["runId"],
                "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
                "wsl": {"bootId": "boot-b"},
            }
            with mock.patch.object(server, "IS_WINDOWS", True), \
                    mock.patch.object(server, "DATA_DIR", td), \
                    mock.patch("supervisor_client.reclaim_supervisor",
                               return_value={"ok": False, "stale": True}), \
                    mock.patch("supervisor_client.load_metadata",
                               return_value=metadata):
                result = server.supervisor_runtime_status(app)
            self.assertFalse(result["ok"])


class WSLStateIsolationTests(unittest.TestCase):
    def test_platform_request_reads_monitor_snapshot_without_discovery(self):
        manager = mock.Mock()
        manager.monitor_discovery.return_value = {
            "distros": [], "scans": [], "scanErrors": [],
            "error": None, "pending": True, "ready": False,
            "stale": False,
        }
        manager.discover.side_effect = AssertionError(
            "platform request must not discover synchronously")
        adapter = mock.Mock()
        adapter.platform_info.return_value = {
            "os": "windows", "wslAvailable": True,
            "wslOperational": False, "wslDiscoveryPending": True,
            "wslDiscoveryStale": False, "wslDistros": [],
        }

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch("console_platform.get_adapter",
                           return_value=adapter):
            info = server.get_platform_info()

        manager.monitor_discovery.assert_called_once_with()
        manager.discover.assert_not_called()
        adapter.platform_info.assert_called_once_with(
            wsl_distros=[],
            wsl_discovery_error=None,
            wsl_discovery_pending=True,
            wsl_discovery_ready=False,
            wsl_discovery_stale=False,
        )
        self.assertFalse(info["wslOperational"])
        self.assertTrue(info["wslDiscoveryPending"])

    def test_running_wsl_task_uptime_uses_authenticated_started_at_without_scan(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Task", "command": "sleep 30",
            "kind": "task", "port": None, "execution": WSL_EXECUTION,
            "runToken": "t" * 43,
            "processIdentity": {
                "type": "supervisor", "environment": "wsl",
                "runId": "run-1", "distro": "Ubuntu-24.04",
            },
        }
        status = {
            "ok": True, "running": True, "environment": "wsl",
            "runId": "run-1", "childPid": 77, "createTime": 980.0,
            "wslStatus": {
                "ok": True, "running": True, "pid": 77,
                "bootId": "boot-a", "startTicks": 12345,
                "startedAt": 990.0,
            },
            "wsl": {"bootId": "boot-a"},
        }
        scan = {
            "distro": "Ubuntu-24.04", "bootId": "boot-a", "uid": 1000,
            "processes": [], "listeners": [],
        }
        with mock.patch.object(server, "supervisor_runtime_status",
                               return_value=status), \
                mock.patch.object(server.time, "time", return_value=1000.0), \
                mock.patch.object(server, "inspect_app_health", return_value={
                    "status": "ok", "blocking": False, "issues": []}):
            public = server._build_wsl_app(
                app, server._wsl_scan_index([scan]), set())

        self.assertTrue(public["running"])
        self.assertEqual(public["pid"], 77)
        self.assertEqual(public["uptimeSec"], 10)

    def test_wsl_supervised_launch_maps_unc_cwd_to_linux(self):
        manager = mock.Mock()
        manager.ensure_helper.return_value = {
            "path": "/home/example/.local/bin/wsl-helper",
            "home": "/home/example",
        }
        manager.call.return_value = {"bootId": "boot-1"}
        manager.session_paths.return_value = {
            "socket": "/home/example/.local/share/console/run.sock",
            "metadata": "/home/example/.local/share/console/run.json",
            "log": "/mnt/c/logs/app.log",
        }
        app = {
            "id": "deadbeef", "name": "WSL app", "kind": "service",
            "command": "python3 app.py",
            "cwd": r"\\wsl.localhost\Ubuntu\home\example\My App",
            "execution": {
                "environment": "wsl", "shell": "posix",
                "distro": "Ubuntu",
            },
        }
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(server, "LOGS_DIR", td), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch("supervisor_client.launch_supervisor",
                           return_value={"ok": False, "error": "sentinel"}) as launch:
            ok, error, _handle, _pid, _token = server.start_app_supervised(app)

        self.assertFalse(ok)
        self.assertIn("sentinel", error)
        self.assertEqual(launch.call_args.kwargs["cwd"],
                         "/home/example/My App")

    def test_wsl_supervised_launch_without_cwd_uses_distro_home(self):
        manager = mock.Mock()
        manager.ensure_helper.return_value = {
            "path": "/home/example/.local/bin/wsl-helper",
            "home": "/home/example",
        }
        manager.call.return_value = {"bootId": "boot-1"}
        manager.session_paths.return_value = {
            "socket": "/home/example/.local/share/console/run.sock",
            "metadata": "/home/example/.local/share/console/run.json",
            "log": "/mnt/c/logs/app.log",
        }
        app = {
            "id": "deadbeef", "name": "WSL app", "kind": "task",
            "command": "true", "cwd": None,
            "execution": {
                "environment": "wsl", "shell": "posix",
                "distro": "Ubuntu",
            },
        }
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(server, "LOGS_DIR", td), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch("supervisor_client.launch_supervisor",
                           return_value={"ok": False, "error": "sentinel"}) as launch:
            ok, _error, _handle, _pid, _token = server.start_app_supervised(app)

        self.assertFalse(ok)
        self.assertEqual(launch.call_args.kwargs["cwd"], "/home/example")

    def test_one_failed_distro_only_degrades_its_wsl_component(self):
        native = {"key": "node.exe:3000", "pid": 12, "port": 3000,
                  "execution": WINDOWS_EXECUTION}
        ubuntu = {"key": "wsl:Ubuntu:node:4000", "pid": 22, "port": 4000,
                  "execution": WSL_EXECUTION}
        distros = [{
            "name": "Ubuntu-24.04", "version": 2,
            "running": True, "available": True,
        }]
        scans = [{
            "distro": "Ubuntu-24.04", "bootId": "boot-a", "uid": 1000,
            "listeners": [], "processes": [],
        }]
        manager = mock.Mock()
        manager.monitor_discovery.return_value = {
            "distros": distros,
            "scans": scans,
            "scanErrors": [{"distro": "Debian",
                            "error": "helper timeout"}],
            "error": None, "pending": False, "ready": True,
            "stale": False,
        }
        manager.discover.side_effect = AssertionError(
            "state request must not discover synchronously")
        platform = {
            "os": "windows", "wslAvailable": True,
            "wslOperational": True, "wslDistros": distros,
        }
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch.object(server, "build_services",
                                  return_value=([native], set())), \
                mock.patch.object(server, "build_wsl_services", return_value=(
                    [ubuntu], scans, [])) as wsl, \
                mock.patch.object(server, "windows_watched_snapshot",
                                  return_value=[]), \
                mock.patch.object(server, "build_apps", return_value=[]), \
                mock.patch.object(server, "list_themes", return_value=[]), \
                mock.patch.object(server, "get_platform_info",
                                  return_value=platform) as platform_info:
            state = server.build_state(server.Config.DEFAULT, 9600)

        manager.monitor_discovery.assert_called_once_with()
        manager.discover.assert_not_called()
        wsl.assert_called_once_with(server.Config.DEFAULT, scans=scans)
        platform_info.assert_called_once_with(
            wsl_distros=distros,
            wsl_discovery_error=None,
            wsl_discovery_pending=False,
            wsl_discovery_ready=True,
            wsl_discovery_stale=False,
        )
        self.assertEqual([row["key"] for row in state["services"]],
                         [native["key"], ubuntu["key"]])
        self.assertTrue(state["degraded"])
        self.assertIn({"component": "wsl", "distro": "Debian",
                       "error": "helper timeout"}, state["degradedReasons"])
        self.assertFalse(any(reason.get("component") == "services"
                             for reason in state["degradedReasons"]))

    def test_wsl_discovery_timeout_preserves_native_state_and_platform_error(self):
        native = {"key": "python.exe:8000", "pid": 31, "port": 8000,
                  "execution": WINDOWS_EXECUTION}
        manager = mock.Mock()
        manager.monitor_discovery.return_value = {
            "distros": [], "scans": [], "scanErrors": [],
            "error": "WSL 发行版枚举失败: command timed out",
            "pending": False, "ready": True, "stale": False,
        }
        manager.discover.side_effect = AssertionError(
            "state request must not discover synchronously")

        def platform_from_precomputed(**kwargs):
            error = kwargs["wsl_discovery_error"]
            return {
                "os": "windows", "wslAvailable": True,
                "wslOperational": bool(
                    kwargs["wsl_discovery_ready"] and not error),
                "wslDiscoveryError": error,
                "wslDiscoveryPending": kwargs["wsl_discovery_pending"],
                "wslDiscoveryStale": kwargs["wsl_discovery_stale"],
                "wslDistros": kwargs["wsl_distros"],
            }

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch.object(server, "build_services",
                                  return_value=([native], set())), \
                mock.patch.object(server, "build_wsl_services",
                                  return_value=([], [], [])) as wsl, \
                mock.patch.object(server, "windows_watched_snapshot",
                                  return_value=[]), \
                mock.patch.object(server, "build_apps", return_value=[]), \
                mock.patch.object(server, "list_themes", return_value=[]), \
                mock.patch.object(
                    server, "get_platform_info",
                    side_effect=platform_from_precomputed,
                ) as platform_info:
            state = server.build_state(server.Config.DEFAULT, 9600)

        manager.monitor_discovery.assert_called_once_with()
        manager.discover.assert_not_called()
        wsl.assert_called_once_with(server.Config.DEFAULT, scans=[])
        platform_info.assert_called_once_with(
            wsl_distros=[],
            wsl_discovery_error=(
                "WSL 发行版枚举失败: command timed out"
            ),
            wsl_discovery_pending=False,
            wsl_discovery_ready=True,
            wsl_discovery_stale=False,
        )
        self.assertEqual(state["services"], [native])
        self.assertEqual(state["platform"]["wslDistros"], [])
        self.assertFalse(state["platform"]["wslOperational"])
        self.assertIn("command timed out",
                      state["platform"]["wslDiscoveryError"])
        self.assertIn({
            "component": "wsl",
            "error": "WSL 发行版枚举失败: command timed out",
        }, state["degradedReasons"])
        self.assertFalse(any(
            reason.get("component") == "services"
            for reason in state["degradedReasons"]
        ))

    def test_first_background_discovery_pending_preserves_native_state(self):
        native = {"key": "python.exe:8000", "pid": 31, "port": 8000,
                  "execution": WINDOWS_EXECUTION}
        manager = mock.Mock()
        manager.monitor_discovery.return_value = {
            "distros": [], "scans": [], "scanErrors": [],
            "error": None, "pending": True, "ready": False,
            "stale": False,
        }
        manager.discover.side_effect = AssertionError(
            "pending state request must not discover synchronously")

        def platform_from_precomputed(**kwargs):
            return {
                "os": "windows", "wslAvailable": True,
                "wslOperational": bool(
                    kwargs["wsl_discovery_ready"]
                    and not kwargs["wsl_discovery_error"]),
                "wslDiscoveryPending": kwargs["wsl_discovery_pending"],
                "wslDiscoveryStale": kwargs["wsl_discovery_stale"],
                "wslDistros": kwargs["wsl_distros"],
            }

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch.object(server, "build_services",
                                  return_value=([native], set())), \
                mock.patch.object(server, "build_wsl_services",
                                  return_value=([], [], [])), \
                mock.patch.object(server, "windows_watched_snapshot",
                                  return_value=[]), \
                mock.patch.object(server, "build_apps", return_value=[]), \
                mock.patch.object(server, "list_themes", return_value=[]), \
                mock.patch.object(
                    server, "get_platform_info",
                    side_effect=platform_from_precomputed,
                ):
            state = server.build_state(server.Config.DEFAULT, 9600)

        manager.discover.assert_not_called()
        self.assertEqual(state["services"], [native])
        self.assertFalse(state["platform"]["wslOperational"])
        self.assertTrue(state["platform"]["wslDiscoveryPending"])
        self.assertIn({
            "component": "wsl",
            "error": server.WSL_DISCOVERY_PENDING_MESSAGE,
            "pending": True,
        }, state["degradedReasons"])

    def test_pending_state_does_not_sync_scan_external_wsl_app(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Attached WSL",
            "command": "node server.js", "cwd": "/home/example/app",
            "port": 3000, "execution": WSL_EXECUTION,
            "attached": True,
            "processIdentity": {
                "type": "external", "environment": "wsl",
                "distro": "Ubuntu-24.04", "bootId": "boot-a",
                "pid": 91, "uid": 1000, "startTicks": 12345,
                "port": 3000,
            },
        }
        cfg = {**server.Config.DEFAULT, "apps": [app]}
        manager = mock.Mock()
        manager.monitor_discovery.return_value = {
            "distros": [], "scans": [], "scanErrors": [],
            "error": None, "pending": True, "ready": False,
            "stale": False,
        }
        manager.scan_distro.side_effect = AssertionError(
            "state request must not scan a distro synchronously")

        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(server, "get_wsl_manager",
                                  return_value=manager), \
                mock.patch.object(server, "build_services",
                                  return_value=([], set())), \
                mock.patch.object(server, "windows_watched_snapshot",
                                  return_value=[]), \
                mock.patch.object(server, "list_themes", return_value=[]), \
                mock.patch.object(server, "_current_windows_sid",
                                  return_value="S-1-5-21-test"), \
                mock.patch.object(server, "get_platform_info", return_value={
                    "os": "windows", "wslAvailable": True,
                    "wslOperational": False,
                    "wslDiscoveryPending": True, "wslDistros": [],
                }):
            state = server.build_state(cfg, 9600)

        manager.scan_distro.assert_not_called()
        self.assertEqual(len(state["apps"]), 1)
        self.assertFalse(state["apps"][0]["running"])
        self.assertEqual(state["apps"][0]["health"]["status"], "unknown")
        self.assertTrue(state["degraded"])
        self.assertTrue(any(
            reason.get("component") == "wsl" and reason.get("pending")
            for reason in state["degradedReasons"]
        ))

    def test_cached_wsl_health_never_discovers_or_touches_unc(self):
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef", "name": "Cached WSL",
            "command": "node server.js", "cwd": "/home/example/app",
            "port": 3000, "execution": WSL_EXECUTION,
        }
        distros = [{
            "name": "Ubuntu-24.04", "version": 2,
            "running": True, "available": True,
        }]
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(
                    server, "get_wsl_manager",
                    side_effect=AssertionError("must not discover"),
                ), mock.patch.object(
                    server.os.path, "isdir",
                    side_effect=AssertionError("must not touch WSL UNC"),
                ):
            health = server.inspect_app_health(
                app, wsl_distros=distros,
                wsl_discovery_ready=True,
                wsl_discovery_error=None,
            )
            missing = server.inspect_app_health(
                app, wsl_distros=[],
                wsl_discovery_ready=True,
                wsl_discovery_error=None,
            )

        self.assertEqual(health["status"], "unknown")
        self.assertFalse(health["blocking"])
        self.assertEqual(missing["status"], "error")
        self.assertTrue(missing["blocking"])
        self.assertEqual(missing["issues"][0]["kind"], "wsl-unavailable")

    def test_empty_windows_app_indexes_never_request_current_sid(self):
        with mock.patch.object(server, "IS_WINDOWS", True), \
                mock.patch.object(
                    server, "_current_windows_sid",
                    side_effect=AssertionError("SID must not be requested"),
                ):
            self.assertEqual(server.managed_process_index([]), ({}, {}, {}))
            self.assertEqual(
                server.listener_app_owners([], set(), {}, {}), {})


if __name__ == "__main__":
    unittest.main()
