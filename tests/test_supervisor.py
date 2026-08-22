import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import supervisor
import supervisor_client
import supervisor_windows


ROOT = Path(__file__).resolve().parents[1]


def make_wsl_supervisor(distro="Ubuntu Test"):
    args = types.SimpleNamespace(
        token="t" * 40,
        run_id="wsl-lifecycle",
        test_transport="tcp",
        supervisor_version="2.0.0",
        environment="wsl",
        distro=distro,
        wsl_boot_id="boot-a",
        wsl_socket="/home/example/.local/run/local-ops.sock",
        wsl_metadata="/home/example/.local/state/local-ops.json",
        wsl_helper_path="/home/example/.local/bin/local-ops-helper",
        wsl_log="/home/example/.local/state/local-ops.log",
        wsl_kind="service",
        cwd="/home/example/My Project",
        command=["npm run dev"],
        metadata="unused",
        log="unused",
        stop_timeout=5.0,
    )
    with mock.patch.dict(
        os.environ,
        {"CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"},
    ):
        instance = supervisor.Supervisor(args)
    instance._wsl_start_command()
    instance._update_wsl_status({
        "ok": True,
        "sessionId": args.run_id,
        "bootId": args.wsl_boot_id,
        "state": "running",
        "running": True,
        "pid": 4321,
        "uid": 1000,
        "startTicks": 987654,
        "tokenHash": hashlib.sha256(instance._wsl_token.encode()).hexdigest(),
        "exit": None,
    }, require_running_identity=True)
    return instance


class SupervisorTests(unittest.TestCase):
    def test_unpublished_native_job_is_terminated(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="native")
        instance._transport = "windows-named-pipe"
        instance._job = object()
        instance.child = mock.Mock(pid=9001)
        instance._wait_native_exit = mock.Mock(return_value=True)
        runtime = mock.Mock()
        with mock.patch.object(supervisor.os, "name", "nt"), \
                mock.patch.object(supervisor, "_windows_runtime",
                                  return_value=runtime):
            instance._abort_unpublished_launch()
        runtime.terminate_job.assert_called_once_with(instance._job, 130)
        instance._wait_native_exit.assert_called_once_with(5.0)

    def test_unpublished_wsl_session_is_force_stopped(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="wsl")
        instance._wsl_running = True
        instance._wsl_control = mock.Mock(return_value={
            "ok": True, "running": False,
        })
        instance._abort_unpublished_launch()
        instance._wsl_control.assert_called_once_with("force-stop")

    def test_unpublished_wsl_attempt_is_stopped_before_identity_update(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="wsl")
        instance._wsl_running = False
        instance._wsl_launch_attempted = True
        instance._wsl_control = mock.Mock(return_value={
            "ok": True, "running": False,
        })
        instance._abort_unpublished_launch()
        instance._wsl_control.assert_called_once_with("force-stop")

    def test_wsl_invalid_start_handshake_aborts_possible_detached_session(self):
        instance = make_wsl_supervisor()
        instance._wsl_running = False
        instance._wsl_last_status = None
        process = mock.Mock(pid=4242, returncode=0)
        process.communicate.return_value = (b"not-json", b"")
        instance._abort_unpublished_launch = mock.Mock(
            return_value=(True, None))
        with mock.patch.object(supervisor.subprocess, "Popen",
                               return_value=process):
            with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                instance._launch_wsl_session()
        self.assertTrue(instance._wsl_launch_attempted)
        instance._abort_unpublished_launch.assert_called_once_with()

    def test_wsl_publish_failure_and_unconfirmed_cleanup_retains_control(self):
        instance = make_wsl_supervisor()
        result = {
            "ok": True, "sessionId": instance.args.run_id,
            "bootId": instance.args.wsl_boot_id,
            "state": "running", "running": True,
            "pid": 4321, "uid": 1000, "startTicks": 987654,
            "tokenHash": hashlib.sha256(
                instance._wsl_token.encode()).hexdigest(),
        }
        process = mock.Mock(pid=4242, returncode=0)
        process.communicate.return_value = (
            json.dumps(result).encode("utf-8"), b"")
        instance.persist = mock.Mock(side_effect=OSError("metadata disk full"))
        instance._abort_unpublished_launch = mock.Mock(
            return_value=(False, "authenticated force-stop still running"))

        with mock.patch.object(supervisor.subprocess, "Popen",
                               return_value=process):
            with self.assertRaises(supervisor.RuntimeCleanupUnconfirmed):
                instance._launch_wsl_session()

        self.assertTrue(instance._volatile_recovery)
        self.assertEqual(instance._launch_state, "startup-cleanup-failed")
        self.assertIn("metadata disk full", instance._launch_failure_error)
        self.assertIn("still running", instance._launch_failure_error)

    def test_unpublished_wsl_cleanup_requires_ok_and_terminal(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="wsl")
        instance._wsl_running = True
        instance._wsl_launch_attempted = True
        instance._wsl_control = mock.Mock(return_value={
            "ok": True, "running": True,
            "error": "force request accepted but session remains",
        })

        cleaned, error = instance._abort_unpublished_launch()

        self.assertFalse(cleaned)
        self.assertIn("session remains", error)

    def test_wsl_stop_keeps_windows_identity_above_helper_status(self):
        instance = make_wsl_supervisor()
        helper = {
            "ok": True, "running": False, "state": "exited",
            "supervisorPid": 4242,
            "exit": {"code": 0, "status": "succeeded"},
        }
        instance._wsl_control = mock.Mock(return_value=helper)
        instance._persist_control_state = mock.Mock(return_value=True)
        with mock.patch.object(instance, "metadata", return_value={
                "runId": instance.args.run_id,
                "supervisorPid": 9000,
                "supervisorCreateTime": 123.5,
                "ownerSid": "S-1-5-21-test",
                "running": False, "state": "exited",
        }):
            stopped = instance._stop(False)

        self.assertTrue(stopped["ok"])
        self.assertFalse(stopped["running"])
        self.assertEqual(stopped["state"], "exited")
        self.assertEqual(stopped["exit"], helper["exit"])
        self.assertEqual(stopped["supervisorPid"], 9000)
        self.assertEqual(stopped["wslStatus"]["supervisorPid"], 4242)

    def test_wsl_status_error_keeps_linux_identity_nested(self):
        instance = make_wsl_supervisor()
        helper = {
            "ok": False, "running": True,
            "supervisorPid": 4242, "error": "temporary helper failure",
        }
        instance._wsl_control = mock.Mock(return_value=helper)
        with mock.patch.object(instance, "metadata", return_value={
                "runId": instance.args.run_id,
                "supervisorPid": 9000,
                "supervisorCreateTime": 123.5,
                "ownerSid": "S-1-5-21-test",
                "running": True, "state": "running",
        }):
            status = instance._status()

        self.assertFalse(status["ok"])
        self.assertTrue(status["running"])
        self.assertEqual(status["error"], "temporary helper failure")
        self.assertEqual(status["supervisorPid"], 9000)
        self.assertEqual(status["wslStatus"]["supervisorPid"], 4242)

    def test_wsl_terminal_persist_failure_is_not_marked_durable(self):
        instance = make_wsl_supervisor()
        helper = {
            "ok": True, "sessionId": instance.args.run_id,
            "bootId": instance.args.wsl_boot_id,
            "state": "exited", "running": False,
            "pid": 4321, "uid": 1000, "startTicks": 987654,
            "tokenHash": hashlib.sha256(
                instance._wsl_token.encode()).hexdigest(),
            "exit": {"code": 0, "status": "succeeded"},
        }
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=json.dumps(helper).encode(), stderr=b"")
        instance._volatile_recovery = True
        with mock.patch.object(
                instance, "_wsl_distro_running", return_value=(True, None)), \
                mock.patch.object(instance, "_wsl_runtime_identity", return_value=(
                    {"bootId": instance.args.wsl_boot_id, "uid": 1000}, None)), \
                mock.patch.object(supervisor.subprocess, "run",
                                  return_value=completed), \
                mock.patch.object(instance, "_persist_control_state",
                                  return_value=False):
            result = instance._wsl_control("status")

        self.assertTrue(result["ok"])
        self.assertFalse(result["running"])
        self.assertTrue(instance._final_persisted.is_set())
        self.assertFalse(instance._terminal_metadata_durable)

    def test_terminal_response_requires_authenticated_ack(self):
        instance = make_wsl_supervisor()
        instance._status = mock.Mock(return_value={
            "ok": True, "running": False, "state": "exited",
        })
        instance._volatile_recovery = True
        instance._terminal_metadata_durable = False

        def request(action, nonce):
            issued_at = time.time()
            value = {
                "protocolVersion": supervisor.PROTOCOL_VERSION,
                "runId": instance.args.run_id,
                "action": action,
                "nonce": nonce,
                "issuedAt": issued_at,
            }
            value["signature"] = supervisor._sign(
                instance.token, action, nonce, issued_at,
                instance.args.run_id)
            return json.loads(instance._handle_bytes(
                json.dumps(value).encode("utf-8")))

        premature = request("ack-terminal", "p" * 24)
        self.assertFalse(premature["ok"])
        self.assertFalse(instance._terminal_observed.is_set())

        response = request("status", "n" * 24)

        self.assertTrue(response["ok"])
        self.assertTrue(instance._terminal_reported.is_set())
        self.assertFalse(instance._terminal_observed.is_set())
        acknowledged = request("ack-terminal", "a" * 24)
        self.assertTrue(acknowledged["ok"])
        self.assertTrue(acknowledged["terminalAcknowledged"])
        self.assertTrue(instance._terminal_observed.is_set())

    def test_client_acknowledges_only_after_verifying_terminal_response(self):
        metadata = {
            "schemaVersion": supervisor_client.METADATA_SCHEMA_VERSION,
            "protocolVersion": supervisor_client.PROTOCOL_VERSION,
            "runId": "terminal-ack", "tokenHash": hashlib.sha256(
                ("a" * 40).encode()).hexdigest(),
            "transport": "test-tcp", "testOnly": True,
            "controlHost": "127.0.0.1", "controlPort": 1234,
        }
        terminal = {"ok": True, "running": False, "state": "exited"}
        with mock.patch.object(
                supervisor_client, "_call_supervisor_once",
                side_effect=[terminal, {"ok": True,
                                        "terminalAcknowledged": True}]) as call:
            result = supervisor_client.call_supervisor(
                metadata, "a" * 40, "status", allow_test_transport=True)

        self.assertEqual(result, terminal)
        self.assertEqual(call.call_args_list[0].args[2], "status")
        self.assertEqual(call.call_args_list[1].args[2], "ack-terminal")

    def test_atomic_metadata_replace_retries_transient_windows_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = os.path.join(temporary, "runtime.json")
            denial = PermissionError(13, "sharing violation")
            with mock.patch.object(supervisor.os, "name", "nt"), \
                    mock.patch.object(supervisor.os, "replace",
                                      side_effect=[denial, None]) as replace, \
                    mock.patch.object(supervisor.time, "sleep") as sleep, \
                    mock.patch.object(supervisor, "_windows_runtime") as runtime:
                supervisor._atomic_json(path, {"state": "running"})

        self.assertEqual(replace.call_count, 2)
        sleep.assert_called_once_with(0.01)
        runtime.return_value.secure_path.assert_called()

    def test_persist_serializes_running_before_newer_terminal_snapshot(self):
        instance = object.__new__(supervisor.Supervisor)
        instance._lock = threading.RLock()
        instance._persist_lock = threading.Lock()
        instance._transport = "test-tcp"
        instance.args = types.SimpleNamespace(metadata="runtime.json")
        state = {"state": "running", "running": True}
        instance.metadata = lambda: dict(state)
        first_write = threading.Event()
        release_first = threading.Event()
        writes = []

        def atomic(_path, value, secure_windows=True):
            writes.append(dict(value))
            if len(writes) == 1:
                first_write.set()
                release_first.wait(2.0)

        running_writer = threading.Thread(target=instance.persist)

        def persist_terminal():
            with instance._lock:
                state.update(state="exited", running=False)
                instance.persist()

        terminal_writer = threading.Thread(target=persist_terminal)
        with mock.patch.object(supervisor, "_atomic_json", side_effect=atomic):
            running_writer.start()
            self.assertTrue(first_write.wait(1.0))
            terminal_writer.start()
            time.sleep(0.02)
            self.assertTrue(terminal_writer.is_alive())
            release_first.set()
            running_writer.join(2.0)
            terminal_writer.join(2.0)

        self.assertFalse(running_writer.is_alive())
        self.assertFalse(terminal_writer.is_alive())
        self.assertEqual([item["state"] for item in writes],
                         ["running", "exited"])

    def test_queued_persist_after_terminal_cannot_write_stale_running_state(self):
        instance = object.__new__(supervisor.Supervisor)
        instance._lock = threading.RLock()
        instance._persist_lock = threading.Lock()
        instance._transport = "test-tcp"
        instance.args = types.SimpleNamespace(metadata="runtime.json")
        state = {"state": "exited", "running": False}
        instance.metadata = lambda: dict(state)
        first_write = threading.Event()
        release_first = threading.Event()
        writes = []

        def atomic(_path, value, secure_windows=True):
            writes.append(dict(value))
            if len(writes) == 1:
                first_write.set()
                release_first.wait(2.0)

        terminal_writer = threading.Thread(target=instance.persist)
        delayed_writer = threading.Thread(target=instance.persist)
        with mock.patch.object(supervisor, "_atomic_json", side_effect=atomic):
            terminal_writer.start()
            self.assertTrue(first_write.wait(1.0))
            delayed_writer.start()
            time.sleep(0.02)
            self.assertTrue(delayed_writer.is_alive())
            release_first.set()
            terminal_writer.join(2.0)
            delayed_writer.join(2.0)

        self.assertFalse(terminal_writer.is_alive())
        self.assertFalse(delayed_writer.is_alive())
        self.assertEqual([item["state"] for item in writes],
                         ["exited", "exited"])

    def test_native_status_never_signs_terminal_before_exit_code_is_reaped(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="native")
        instance._finalize_native_exit = mock.Mock(return_value="exiting")
        instance.metadata = mock.Mock(return_value={
            "running": False, "state": "exited", "exitCode": None,
        })

        status = instance._status()

        self.assertTrue(status["ok"])
        self.assertTrue(status["running"])
        self.assertEqual(status["state"], "exiting")
        self.assertIsNone(status["exitCode"])
        instance._finalize_native_exit.assert_called_once_with(
            wait_timeout=0.25)

    def test_native_status_reaps_and_persists_before_terminal_response(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="native")
        instance.child = mock.Mock(returncode=7)
        instance.child.poll.return_value = 7
        instance._native_process_ids = mock.Mock(return_value=[])
        instance._lock = threading.RLock()
        instance._launch_state = None
        instance.exit_code = None
        instance._record_exit = mock.Mock()

        state = instance._finalize_native_exit(wait_timeout=0.25)

        self.assertEqual(state, "exited")
        self.assertEqual(instance.exit_code, 7)
        instance._record_exit.assert_called_once_with()

    def test_native_volatile_recovery_is_final_before_terminal_ack(self):
        instance = object.__new__(supervisor.Supervisor)
        instance.args = types.SimpleNamespace(environment="native")
        instance.child = mock.Mock(returncode=0)
        instance.child.poll.return_value = 0
        instance._native_process_ids = mock.Mock(return_value=[])
        instance._lock = threading.RLock()
        instance._launch_state = "startup-cleanup-failed"
        instance.exit_code = None
        instance._final_persisted = threading.Event()
        instance._terminal_metadata_durable = False
        instance._persist_control_state = mock.Mock(return_value=False)

        state = instance._finalize_native_exit(wait_timeout=0.25)

        self.assertEqual(state, "exited")
        self.assertEqual(instance.exit_code, 0)
        self.assertTrue(instance._final_persisted.is_set())
        self.assertFalse(instance._terminal_metadata_durable)
        instance._persist_control_state.assert_called_once_with()

    def test_published_native_runtime_retries_transient_job_query_failure(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="published-job-retry",
            test_transport="tcp", supervisor_version="2.0.0",
            environment="native", distro=None,
            command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3220, returncode=0)
        child.poll.return_value = 0
        instance.child = child
        instance._start_control = mock.Mock()
        instance.persist = mock.Mock()
        instance.launch = mock.Mock()
        instance._native_process_ids = mock.Mock(side_effect=[
            RuntimeError("transient Job query failure"), [],
        ])
        instance._append_supervisor_log = mock.Mock()

        with mock.patch.object(supervisor.time, "sleep") as sleep:
            result = instance.serve()

        self.assertEqual(result, 0)
        self.assertEqual(instance._native_process_ids.call_count, 2)
        sleep.assert_called_once_with(0.25)
        instance._append_supervisor_log.assert_called_once()
        self.assertIn(
            "transient Job query failure",
            instance._append_supervisor_log.call_args.args[0],
        )
        self.assertEqual(instance.persist.call_count, 2)
        self.assertTrue(instance._runtime_committed)
        self.assertTrue(instance._volatile_recovery)
        self.assertTrue(instance._terminal_metadata_durable)
        self.assertTrue(instance._final_persisted.is_set())
        self.assertIn("transient Job query failure",
                      instance._launch_failure_error)
        self.assertEqual(instance._launch_state, None)
        self.assertEqual(instance.exit_code, 0)

    def test_job_empty_wait_timeout_retries_until_root_is_reaped(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="job-empty-handle-lag",
            test_transport="tcp", supervisor_version="2.0.0",
            environment="native", distro=None,
            command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3221, returncode=7)
        child.poll.side_effect = [None, 7, 7]
        child.wait.side_effect = subprocess.TimeoutExpired(
            cmd="managed-root", timeout=0.25)
        instance.child = child
        instance._start_control = mock.Mock()
        instance.persist = mock.Mock()
        instance.launch = mock.Mock()
        instance._native_process_ids = mock.Mock(return_value=[])

        result = instance.serve()

        self.assertEqual(result, 7)
        self.assertEqual(instance._native_process_ids.call_count, 2)
        child.wait.assert_called_once_with(timeout=0.25)
        self.assertEqual(instance.persist.call_count, 2)
        self.assertTrue(instance._runtime_committed)
        self.assertFalse(instance._volatile_recovery)
        self.assertTrue(instance._terminal_metadata_durable)
        self.assertTrue(instance._final_persisted.is_set())
        self.assertEqual(instance.exit_code, 7)

    def test_normal_terminal_persist_failure_stays_until_observed(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="terminal-persist-recovery",
            test_transport="tcp", supervisor_version="2.0.0",
            environment="native", distro=None,
            command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3222, returncode=0)
        child.poll.return_value = 0
        instance.child = child
        instance._start_control = mock.Mock()
        instance.persist = mock.Mock(side_effect=[
            None, OSError("terminal metadata disk full"),
        ])
        instance.launch = mock.Mock()
        instance._native_process_ids = mock.Mock(return_value=[])
        instance._append_supervisor_log = mock.Mock()
        outcome = []
        failures = []

        def run():
            try:
                outcome.append(instance.serve())
            except Exception as exc:
                failures.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(instance._final_persisted.wait(1.0))
        self.assertTrue(worker.is_alive())
        self.assertTrue(instance._runtime_committed)
        self.assertTrue(instance._volatile_recovery)
        self.assertFalse(instance._terminal_metadata_durable)
        self.assertIn("terminal metadata disk full",
                      instance._launch_failure_error)
        instance._terminal_observed.set()
        worker.join(2.0)

        self.assertFalse(worker.is_alive())
        self.assertFalse(failures)
        self.assertEqual(outcome, [0])
        self.assertEqual(instance.persist.call_count, 2)
        instance._append_supervisor_log.assert_called_once()

    def test_unexpected_post_publish_exception_enters_retrying_recovery(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="unexpected-post-publish",
            test_transport="tcp", supervisor_version="2.0.0",
            environment="native", distro=None,
            command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        instance._start_control = mock.Mock()
        instance.persist = mock.Mock()
        instance.launch = mock.Mock()
        instance._append_supervisor_log = mock.Mock()
        calls = []

        def monitor():
            calls.append(True)
            if len(calls) == 1:
                raise RuntimeError("unexpected committed monitor failure")
            instance.exit_code = 0
            instance._terminal_metadata_durable = True
            instance._final_persisted.set()

        instance._monitor_native_until_terminal = mock.Mock(
            side_effect=monitor)
        with mock.patch.object(supervisor.time, "sleep") as sleep:
            result = instance.serve()

        self.assertEqual(result, 0)
        self.assertEqual(instance._monitor_native_until_terminal.call_count, 2)
        sleep.assert_called_once_with(0.25)
        self.assertTrue(instance._runtime_committed)
        self.assertTrue(instance._volatile_recovery)
        self.assertIn("unexpected committed monitor failure",
                      instance._launch_failure_error)
        instance._append_supervisor_log.assert_called_once()

    def test_serve_reconfirms_cleanup_before_ordinary_startup_failure(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="serve-cleanup-proof",
            test_transport="tcp", supervisor_version="2.0.0",
            environment="native", distro=None,
            command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        instance._start_control = mock.Mock()
        instance.persist = mock.Mock()
        instance.launch = mock.Mock(
            side_effect=RuntimeError("unexpected launch gap"))

        def prove_cleanup():
            # WSL cleanup enables volatile persistence while force-stopping;
            # authenticated terminal cleanup must clear it again.
            instance._volatile_recovery = True
            return True, None

        instance._abort_unpublished_launch = mock.Mock(
            side_effect=prove_cleanup)

        with self.assertRaisesRegex(RuntimeError, "unexpected launch gap"):
            instance.serve()

        instance._abort_unpublished_launch.assert_called_once_with()
        self.assertFalse(instance._runtime_committed)
        self.assertFalse(instance._volatile_recovery)

    def test_serve_retains_unconfirmed_unpublished_runtime(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="serve-unconfirmed-cleanup",
            test_transport="tcp", supervisor_version="2.0.0",
            environment="native", distro=None,
            command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        instance._start_control = mock.Mock()
        instance.persist = mock.Mock()
        instance.launch = mock.Mock(
            side_effect=RuntimeError("unexpected launch gap"))
        instance._abort_unpublished_launch = mock.Mock(
            return_value=(False, "runtime still alive"))

        def monitor():
            instance.exit_code = 0
            instance._terminal_metadata_durable = True
            instance._final_persisted.set()

        instance._monitor_native_until_terminal = mock.Mock(
            side_effect=monitor)

        result = instance.serve()

        self.assertEqual(result, 0)
        self.assertFalse(instance._runtime_committed)
        self.assertTrue(instance._volatile_recovery)
        self.assertEqual(instance._launch_state, "startup-cleanup-failed")
        self.assertIn("unexpected launch gap",
                      instance._launch_failure_error)
        self.assertIn("runtime still alive",
                      instance._launch_failure_error)

    def test_fast_native_launch_persists_exit_code_before_first_publication(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="fast-terminal", test_transport="tcp",
            supervisor_version="2.0.0", environment="native", distro=None,
            cwd=None, command=[sys.executable, "-c", "raise SystemExit(7)"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3211, returncode=7)
        child.poll.return_value = 7
        instance.persist = mock.Mock()
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(instance.args, "log", os.path.join(td, "app.log")), \
                mock.patch.object(supervisor.subprocess, "Popen",
                                  return_value=child):
            instance.launch()

        self.assertEqual(instance.exit_code, 7)
        self.assertTrue(instance._final_persisted.is_set())
        self.assertTrue(instance._terminal_metadata_durable)
        instance.persist.assert_called_once_with()

    def test_first_persist_stays_exiting_when_job_empties_after_harvest(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="empty-after-harvest", test_transport="tcp",
            supervisor_version="2.0.0", environment="native", distro=None,
            cwd=None, command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3213, returncode=None)
        child.poll.return_value = None
        snapshots = []
        instance._finalize_native_exit = mock.Mock(return_value="running")
        instance._native_process_ids = mock.Mock(return_value=[])
        instance._native_process_identities = mock.Mock(return_value=[])
        instance.persist = mock.Mock(side_effect=lambda: snapshots.append(
            instance.metadata()))
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(instance.args, "log", os.path.join(td, "app.log")), \
                mock.patch.object(supervisor.subprocess, "Popen",
                                  return_value=child):
            instance.launch()

        self.assertEqual(len(snapshots), 1)
        self.assertTrue(snapshots[0]["running"])
        self.assertEqual(snapshots[0]["state"], "exiting")
        self.assertIsNone(snapshots[0]["exitCode"])

    def test_launch_exiting_snapshot_cannot_overwrite_racing_terminal_writer(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="fast-terminal-race", test_transport="tcp",
            supervisor_version="2.0.0", environment="native", distro=None,
            cwd=None, command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3212, returncode=None)
        child.poll.return_value = None
        launch_harvested = threading.Event()
        status_attempted = threading.Event()
        status_persisted = threading.Event()
        writes = []
        failures = []

        def finalize_from_launch(wait_timeout=0.0):
            self.assertEqual(wait_timeout, 0.0)
            launch_harvested.set()
            self.assertTrue(status_attempted.wait(1.0))
            # The competing terminal writer must still be blocked on _lock.
            time.sleep(0.02)
            self.assertFalse(status_persisted.is_set())
            return "exiting"

        def persist_snapshot():
            writes.append({
                "state": instance._launch_state or "exited",
                "exitCode": instance.exit_code,
            })

        def terminal_writer():
            try:
                self.assertTrue(launch_harvested.wait(1.0))
                status_attempted.set()
                with instance._lock:
                    instance.exit_code = 0
                    instance._launch_state = None
                    instance._final_persisted.set()
                    instance.persist()
                status_persisted.set()
            except Exception as exc:
                failures.append(exc)

        instance._finalize_native_exit = mock.Mock(
            side_effect=finalize_from_launch)
        instance.persist = mock.Mock(side_effect=persist_snapshot)
        writer = threading.Thread(target=terminal_writer)
        writer.start()
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(instance.args, "log", os.path.join(td, "app.log")), \
                mock.patch.object(supervisor.subprocess, "Popen",
                                  return_value=child):
            instance.launch()
        writer.join(2.0)

        self.assertFalse(writer.is_alive())
        self.assertFalse(failures)
        self.assertEqual(writes, [
            {"state": "exiting", "exitCode": None},
            {"state": "exited", "exitCode": 0},
        ])

    def test_native_launch_invokes_abort_when_first_persist_fails(self):
        args = types.SimpleNamespace(
            token="t" * 40, run_id="publish-failure", test_transport="tcp",
            supervisor_version="2.0.0", environment="native", distro=None,
            cwd=None, command=[sys.executable, "-c", "pass"],
            metadata="unused", log="unused", stop_timeout=1.0,
        )
        with mock.patch.dict(os.environ, {
                "CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"}):
            instance = supervisor.Supervisor(args)
        child = mock.Mock(pid=3210)
        child.poll.return_value = None
        instance.persist = mock.Mock(side_effect=OSError("disk full"))
        instance._abort_unpublished_launch = mock.Mock(
            return_value=(True, None))
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(instance.args, "log", os.path.join(td, "app.log")), \
                mock.patch.object(supervisor.subprocess, "Popen",
                                  return_value=child):
            with self.assertRaisesRegex(OSError, "disk full"):
                instance.launch()
        instance._abort_unpublished_launch.assert_called_once_with()

    def test_launch_supervisor_uses_explicit_launch_environment(self):
        metadata = {
            "state": "running", "running": True,
            "transport": "test-tcp", "controlPort": 1,
            "supervisorPid": 12, "childPid": 34,
        }
        process = mock.Mock(pid=12)
        process.wait.return_value = 0
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(
                    supervisor_client, "supervisor_executable",
                    return_value=[sys.executable, str(ROOT / "supervisor.py")]
                ), mock.patch.object(
                    supervisor_client, "wait_for_metadata", return_value=metadata
                ) as wait_for_metadata, mock.patch.object(
                    supervisor_client.subprocess, "Popen", return_value=process
                ) as popen:
            result = supervisor_client.launch_supervisor(
                str(ROOT), temporary, os.path.join(temporary, "app.log"),
                "env-test", "t" * 40, ["echo", "ok"],
                launch_env={"PATH": "custom-path", "LOCAL_OPS_MARK": "yes"},
                stop_timeout=0.1,
                startup_timeout=12.5,
                allow_test_transport=True,
            )
        self.assertTrue(result["ok"])
        passed = popen.call_args.kwargs["env"]
        self.assertEqual(passed["PATH"], "custom-path")
        self.assertEqual(passed["LOCAL_OPS_MARK"], "yes")
        self.assertEqual(passed["CONSOLE_SUPERVISOR_TOKEN"], "t" * 40)
        wait_for_metadata.assert_called_once_with(mock.ANY, timeout=12.5)

    def test_wait_for_metadata_does_not_publish_starting_as_success(self):
        starting = {
            "state": "starting", "transport": "test-tcp",
            "controlPort": 1234,
        }
        running = {**starting, "state": "running", "running": True}
        with mock.patch.object(
                supervisor_client, "load_metadata",
                side_effect=[starting, running]), \
                mock.patch.object(supervisor_client.time, "sleep"):
            result = supervisor_client.wait_for_metadata(
                "runtime.json", timeout=1.0)
        self.assertEqual(result, running)

    def test_timeout_cleanup_ok_but_running_is_recoverable_not_success(self):
        token = "r" * 40
        metadata = {
            "schemaVersion": supervisor_client.METADATA_SCHEMA_VERSION,
            "protocolVersion": supervisor_client.PROTOCOL_VERSION,
            "runId": "recoverable-timeout",
            "environment": "native", "distro": None,
            "transport": "test-tcp", "testOnly": True,
            "controlHost": "127.0.0.1", "controlPort": 1234,
            "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
            "state": "starting", "running": False,
            "supervisorPid": 111,
        }
        process = mock.Mock(pid=111)
        process.poll.side_effect = [None, 0, 0]
        live = {**metadata, "ok": True,
                "state": "startup-cleanup-failed", "running": True,
                "childPid": 222}
        with mock.patch.object(
                supervisor_client, "_write_startup_cancel"), \
                mock.patch.object(
                    supervisor_client, "load_metadata",
                    return_value=metadata), \
                mock.patch.object(
                    supervisor_client, "stop_supervisor",
                    return_value={"ok": True, "running": True,
                                  "error": "still running"}), \
                mock.patch.object(
                    supervisor_client, "status_supervisor",
                    return_value=live):
            cleanup = supervisor_client._cancel_timed_out_start(
                process, "runtime.json", metadata["runId"], token,
                "native", allow_test_transport=True)

        self.assertFalse(cleanup["ok"])
        self.assertTrue(cleanup["recoverable"])
        self.assertEqual(cleanup["metadata"], live)

    def test_launch_timeout_surfaces_recoverable_metadata(self):
        token = "q" * 40
        metadata = {
            "state": "startup-cleanup-failed", "running": True,
            "transport": "test-tcp", "controlPort": 1234,
            "supervisorPid": 111, "childPid": 222,
        }
        process = mock.Mock(pid=111)
        process.wait.return_value = 0
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(
                    supervisor_client, "wait_for_metadata", return_value=None), \
                mock.patch.object(
                    supervisor_client, "_cancel_timed_out_start",
                    return_value={
                        "ok": False, "recoverable": True,
                        "error": "force-stop unconfirmed",
                        "metadata": metadata,
                    }), \
                mock.patch.object(
                    supervisor_client.subprocess, "Popen",
                    return_value=process):
            result = supervisor_client.launch_supervisor(
                str(ROOT), temporary, os.path.join(temporary, "app.log"),
                "recoverable-timeout", token,
                [sys.executable, "-c", "pass"],
                allow_test_transport=True, startup_timeout=1.0)

        self.assertFalse(result["ok"])
        self.assertTrue(result["recoverable"])
        self.assertEqual(
            {key: value for key, value in result["metadata"].items()
             if key != "recoveryPending"}, metadata)
        self.assertTrue(result["metadata"]["recoveryPending"])

    @unittest.skipUnless(os.name == "nt", "Windows creation flag contract")
    def test_supervisor_launcher_preallocates_a_hidden_private_console(self):
        metadata = {
            "state": "running", "running": True,
            "transport": "windows-named-pipe",
            "pipeName": r"\\.\pipe\LocalOps.Supervisor.test",
            "supervisorPid": 12,
        }
        process = mock.Mock(pid=12)
        process.wait.return_value = 0
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(
                    supervisor_client, "supervisor_executable",
                    return_value=[sys.executable, str(ROOT / "supervisor.py")]
                ), mock.patch.object(
                    supervisor_client, "_secure_runtime_directory"
                ), mock.patch.object(
                    supervisor_client, "wait_for_metadata", return_value=metadata
                ), mock.patch.object(
                    supervisor_client, "_windows_runtime",
                    return_value=supervisor_windows,
                ), mock.patch.object(
                    supervisor_client.subprocess, "Popen", return_value=process
                ) as popen:
            result = supervisor_client.launch_supervisor(
                str(ROOT), temporary, os.path.join(temporary, "app.log"),
                "flag-test", "t" * 40, ["echo", "ok"],
            )
        self.assertTrue(result["ok"], result)
        flags = popen.call_args.kwargs["creationflags"]
        self.assertTrue(flags & subprocess.CREATE_NEW_PROCESS_GROUP)
        self.assertTrue(flags & subprocess.CREATE_NEW_CONSOLE)
        self.assertFalse(flags & subprocess.CREATE_NO_WINDOW)
        self.assertFalse(flags & subprocess.DETACHED_PROCESS)
        self.assertIn("--preallocated-console", popen.call_args.args[0])
        startup = popen.call_args.kwargs["startupinfo"]
        self.assertTrue(startup.dwFlags & subprocess.STARTF_USESHOWWINDOW)
        self.assertEqual(startup.wShowWindow, subprocess.SW_HIDE)

    @unittest.skipUnless(os.name == "nt", "Windows startup rollback integration")
    def test_windows_startup_timeout_cancels_before_command_and_removes_job(self):
        try:
            supervisor_windows.validate_runtime()
        except supervisor_windows.WindowsRuntimeUnavailable as exc:
            self.skipTest(str(exc))
        token = "startup-timeout-test-" + secrets.token_hex(24)
        run_id = "timeout" + secrets.token_hex(6)
        with tempfile.TemporaryDirectory() as temporary:
            command_marker = Path(temporary, "command-started")
            code = (
                "from pathlib import Path; import time; "
                f"Path({str(command_marker)!r}).write_text('started'); "
                "time.sleep(60)"
            )
            # Force the launcher-side deadline before the new Python process
            # can finish importing.  The private cancel marker must be seen
            # before the suspended managed command is resumed.
            with mock.patch.object(
                    supervisor_client, "wait_for_metadata", return_value=None):
                launched = supervisor_client.launch_supervisor(
                    str(ROOT), temporary, os.path.join(temporary, "run.log"),
                    run_id, token, [sys.executable, "-c", code],
                    startup_timeout=1.0,
                )
            self.assertFalse(launched["ok"], launched)
            self.assertTrue(launched.get("startupTimedOut"), launched)
            self.assertTrue(launched.get("cleanup", {}).get("ok"), launched)
            self.assertFalse(command_marker.exists(), launched)
            metadata = supervisor_client.metadata_path(temporary, run_id)
            cancel_marker = supervisor_client.startup_cancel_path(metadata)
            if launched["cleanup"].get("jobOpened"):
                self.assertFalse(os.path.exists(cancel_marker))
            else:
                self.assertEqual(
                    Path(cancel_marker).read_text(encoding="ascii").strip(),
                    hashlib.sha256(token.encode("utf-8")).hexdigest(),
                )
            import psutil
            with self.assertRaises(psutil.NoSuchProcess):
                psutil.Process(launched["supervisorPid"])
            job_name = supervisor_windows.names(
                run_id, hashlib.sha256(token.encode("utf-8")).hexdigest()
            )[1]
            with self.assertRaises(Exception):
                handle = supervisor_windows.open_job(job_name)
                try:
                    supervisor_windows.terminate_job(handle, 130)
                finally:
                    handle.Close()

    def test_late_onefile_child_observes_retained_startup_cancel_marker(self):
        token = "late-bootloader-child-" + "b" * 32
        with tempfile.TemporaryDirectory() as temporary:
            metadata = supervisor_client.metadata_path(temporary, "late-child")
            os.makedirs(os.path.dirname(metadata), exist_ok=True)
            process = mock.Mock(pid=1234)
            process.poll.return_value = 0
            with mock.patch.object(
                    supervisor_client, "_terminate_exact_startup_job",
                    return_value={
                        "ok": True, "errors": [], "jobName": "job",
                        "jobOpened": False,
                    }):
                cleanup = supervisor_client._cancel_timed_out_start(
                    process, metadata, "late-child", token, "native"
                )
            self.assertTrue(cleanup["ok"], cleanup)
            marker = supervisor_client.startup_cancel_path(metadata)
            self.assertTrue(os.path.isfile(marker))
            args = types.SimpleNamespace(
                token=token, run_id="late-child", test_transport="tcp",
                supervisor_version="2.0.0", environment="native", distro=None,
                cwd=None, command=[sys.executable, "-c", "pass"],
                metadata=metadata, startup_cancel=marker,
                log=os.path.join(temporary, "run.log"), stop_timeout=1.0,
            )
            with mock.patch.object(supervisor.Supervisor, "_configure_platform") as configure:
                with self.assertRaisesRegex(TimeoutError, "canceled by launcher"):
                    supervisor.Supervisor(args)
            configure.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows cmd.exe behavior")
    def test_cmd_shell_preserves_quotes_paths_and_pipeline(self):
        commands = [
            '"%s" -c "print(\'quoted python ok\')"' % sys.executable,
            "echo pipeline-ok|findstr pipeline-ok",
        ]

        with tempfile.TemporaryDirectory(prefix="cmd quoting ") as temporary:
            script = Path(temporary) / "task with spaces.cmd"
            script.write_text(
                "@echo off\r\necho script-ok:%~1\r\n", encoding="utf-8"
            )
            commands.append('"%s" "hello world"' % script)

            expected = (
                "quoted python ok", "pipeline-ok", "script-ok:hello world"
            )
            for command, marker in zip(commands, expected):
                with self.subTest(command=command):
                    launch = supervisor._native_launch_command(
                        ["cmd.exe", "/d", "/s", "/c", command]
                    )
                    self.assertIsInstance(launch, str)
                    completed = subprocess.run(
                        launch, capture_output=True, text=True, timeout=10
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn(marker, completed.stdout)

    def test_runtime_check_has_no_metadata_or_command_requirement(self):
        runtime = mock.Mock()
        with mock.patch.object(supervisor, "_windows_runtime", return_value=runtime):
            self.assertEqual(supervisor.main(["--runtime-check"]), 0)
        runtime.validate_runtime.assert_called_once_with()

    def test_main_never_overwrites_committed_or_volatile_metadata(self):
        argv = [
            "--metadata", "runtime.json",
            "--startup-cancel", "runtime.json.startup-cancel",
            "--log", "run.log",
            "--run-id", "main-recovery-guard",
            "--test-transport", "tcp",
            "--", "echo", "ok",
        ]
        for committed, volatile in ((True, False), (False, True)):
            with self.subTest(committed=committed, volatile=volatile):
                instance = mock.Mock()
                instance._runtime_committed = committed
                instance._volatile_recovery = volatile
                instance.serve.side_effect = RuntimeError(
                    "unexpected recovery escape")
                with mock.patch.object(
                        supervisor, "Supervisor", return_value=instance), \
                        mock.patch.object(supervisor, "_atomic_json") as atomic:
                    result = supervisor.main(argv)

                self.assertEqual(result, 1)
                atomic.assert_not_called()
                instance._append_supervisor_log.assert_called_once()

    def test_main_persists_proven_ordinary_startup_failure(self):
        argv = [
            "--metadata", "runtime.json",
            "--startup-cancel", "runtime.json.startup-cancel",
            "--log", "run.log",
            "--run-id", "main-startup-failure",
            "--test-transport", "tcp",
            "--", "echo", "ok",
        ]
        instance = mock.Mock()
        instance._runtime_committed = False
        instance._volatile_recovery = False
        instance.serve.side_effect = RuntimeError("ordinary startup failure")
        with mock.patch.object(
                supervisor, "Supervisor", return_value=instance), \
                mock.patch.object(supervisor, "_atomic_json") as atomic:
            result = supervisor.main(argv)

        self.assertEqual(result, 1)
        atomic.assert_called_once()
        self.assertEqual(atomic.call_args.args[1]["state"], "startup-failed")
        self.assertEqual(atomic.call_args.args[1]["error"],
                         "ordinary startup failure")

    def test_signature_rejects_wrong_token(self):
        self.assertNotEqual(
            supervisor._sign("one", "status", "nonce-value-1234"),
            supervisor._sign("two", "status", "nonce-value-1234"),
        )

    def test_metadata_paths_reject_traversal(self):
        with self.assertRaises(ValueError):
            supervisor_client.metadata_path("data", "../escape")
        self.assertTrue(
            supervisor_client.metadata_path("data", "run_123").endswith(
                os.path.join("runtime", "run_123.json")
            )
        )

    def test_windows_names_are_token_bound_and_reject_injection(self):
        token_hash = hashlib.sha256(b"secret").hexdigest()
        pipe, job = supervisor_windows.names("run-1", token_hash)
        self.assertTrue(pipe.startswith(r"\\.\pipe\LocalOps.Supervisor."))
        self.assertTrue(job.startswith(r"Local\LocalOps.Supervisor."))
        self.assertIn(token_hash[:20], pipe)
        with self.assertRaises(ValueError):
            supervisor_windows.names("bad\\name", token_hash)

    def test_process_identity_comparison_rejects_pid_reuse_or_owner_change(self):
        expected = {"pid": 42, "createTime": 1000.25, "ownerSid": "S-1-5-21-a"}
        self.assertTrue(supervisor_windows.identity_matches(
            expected, {"pid": 42, "createTime": 1000.30, "ownerSid": "S-1-5-21-a"}
        ))
        self.assertFalse(supervisor_windows.identity_matches(
            expected, {"pid": 42, "createTime": 1002.0, "ownerSid": "S-1-5-21-a"}
        ))
        self.assertFalse(supervisor_windows.identity_matches(
            expected, {"pid": 42, "createTime": 1000.25, "ownerSid": "S-1-5-21-b"}
        ))

    def test_job_process_identities_require_stable_membership_and_owner(self):
        sid = "S-1-5-21-current"

        def identity(pid, _mods):
            owners = {10: sid, 11: sid, 12: "S-1-5-21-foreign"}
            return {"pid": pid, "createTime": 1000.0 + pid,
                    "ownerSid": owners[pid]}

        with mock.patch.object(
                supervisor_windows, "job_process_ids",
                side_effect=[[10, 11, 12], [11, 12]]) as query, \
                mock.patch.object(
                    supervisor_windows, "process_identity",
                    side_effect=identity):
            result = supervisor_windows.job_process_identities(
                object(), expected_owner_sid=sid, mods=mock.Mock())

        self.assertEqual(result, [{
            "pid": 11, "createTime": 1011.0, "ownerSid": sid,
        }])
        self.assertEqual(query.call_count, 2)

    def test_test_transport_is_refused_without_explicit_opt_in(self):
        metadata = {
            "schemaVersion": 2,
            "protocolVersion": 2,
            "runId": "run1",
            "tokenHash": hashlib.sha256(("x" * 40).encode()).hexdigest(),
            "transport": "test-tcp",
            "testOnly": True,
            "controlHost": "127.0.0.1",
            "controlPort": 1,
        }
        result = supervisor_client.call_supervisor(metadata, "x" * 40, "status")
        self.assertFalse(result["ok"])
        self.assertTrue(result["insecureTransport"])

    def test_native_stop_keeps_original_group_id_and_reports_live_job(self):
        instance = object.__new__(supervisor.Supervisor)
        instance._lock = mock.MagicMock()
        instance._transport = "windows-named-pipe"
        instance._native_process_ids = mock.Mock(side_effect=[[9102], [9102]])
        instance.child = types.SimpleNamespace(pid=9001)
        instance.stop_requested = False
        instance.force_requested = False
        instance.persist = mock.Mock()
        instance._send_windows_ctrl_break = mock.Mock(
            side_effect=RuntimeError("synthetic control failure"))
        instance.args = types.SimpleNamespace(stop_timeout=1.0)

        with mock.patch.object(supervisor.os, "name", "nt"):
            result = supervisor.Supervisor._stop_native(instance)

        instance._send_windows_ctrl_break.assert_called_once_with(9001, [9102])
        self.assertFalse(result["ok"])
        self.assertTrue(result["running"])
        self.assertTrue(result["requiresForce"])

    def test_wsl_start_uses_helper_session_protocol_not_shell_bypass(self):
        args = types.SimpleNamespace(
            token="t" * 40,
            run_id="wsl-run",
            test_transport="tcp",
            supervisor_version="2.0.0",
            environment="wsl",
            distro="Ubuntu Test",
            wsl_boot_id="boot-a",
            wsl_socket="/home/example/.local/run/local-ops.sock",
            wsl_metadata="/home/example/.local/state/local-ops.json",
            wsl_helper_path="/home/example/.local/bin/local-ops-helper",
            wsl_log="/home/example/.local/state/local-ops.log",
            wsl_kind="service",
            cwd="/home/example/My Project",
            command=["npm run dev"],
            metadata="unused",
            log="unused",
            stop_timeout=5.0,
        )
        with mock.patch.dict(
            os.environ,
            {"CONSOLE_SUPERVISOR_ALLOW_INSECURE_TEST_TRANSPORT": "1"},
        ):
            instance = supervisor.Supervisor(args)
        command = instance._wsl_start_command()
        self.assertEqual(command[:4], ["wsl.exe", "-d", "Ubuntu Test", "--"])
        self.assertIn("session-start", command)
        self.assertNotIn("sh", command)
        self.assertNotIn("-lc", command)
        self.assertNotIn("t" * 40, command)
        self.assertIn("--token-stdin", command)
        self.assertNotIn("--token", command)
        self.assertNotIn(instance._wsl_token, command)
        instance._update_wsl_status({
            "ok": True,
            "sessionId": "wsl-run",
            "bootId": "boot-a",
            "state": "running",
            "running": True,
            "pid": 4321,
            "uid": 1000,
            "startTicks": 987654,
            "tokenHash": hashlib.sha256(instance._wsl_token.encode()).hexdigest(),
            "exit": None,
        }, require_running_identity=True)
        metadata = instance.metadata()
        self.assertEqual(metadata["childPid"], 4321)
        self.assertEqual(metadata["childCreateTime"], 987654)
        self.assertEqual(metadata["wsl"]["lastStatus"]["startTicks"], 987654)
        response = {
            "ok": True, "sessionId": "wsl-run", "bootId": "boot-a",
            "state": "running", "running": True, "pid": 4321,
            "uid": 1000, "startTicks": 987654,
            "tokenHash": hashlib.sha256(instance._wsl_token.encode()).hexdigest(),
            "exit": None,
        }
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=json.dumps(response).encode(), stderr=b""
        )
        with (
            mock.patch.object(instance, "_wsl_distro_running", return_value=(True, None)),
            mock.patch.object(instance, "_wsl_runtime_identity", return_value=(
                {"bootId": "boot-a", "uid": 1000}, None)),
            mock.patch.object(supervisor.subprocess, "run", return_value=completed) as run,
        ):
            controlled = instance._wsl_control("status")
        self.assertTrue(controlled["ok"], controlled)
        control_command = run.call_args.args[0]
        self.assertIn("--token-stdin", control_command)
        self.assertIn("--metadata", control_command)
        self.assertEqual(
            control_command[control_command.index("--metadata") + 1],
            args.wsl_metadata,
        )
        self.assertNotIn(instance._wsl_token, control_command)
        self.assertEqual(
            run.call_args.kwargs["input"], (instance._wsl_token + "\n").encode()
        )

    def test_wsl_running_distro_name_comparison_is_case_insensitive(self):
        instance = make_wsl_supervisor(distro="Ubuntu Test")
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=b"ubuntu test\n", stderr=b"")
        with mock.patch.object(supervisor.subprocess, "run",
                               return_value=completed):
            self.assertEqual(instance._wsl_distro_running(), (True, None))

    def test_wsl_boot_restart_is_terminal_before_old_socket_control(self):
        instance = make_wsl_supervisor()
        runtime = {
            "ok": True, "protocolVersion": 2,
            "bootId": "boot-b", "uid": 1000,
        }
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 0, stdout=json.dumps(runtime).encode(), stderr=b"")
        with (
            mock.patch.object(instance, "_wsl_distro_running",
                              return_value=(True, None)),
            mock.patch.object(supervisor.subprocess, "run",
                              return_value=completed) as run,
            mock.patch.object(instance, "persist") as persist,
        ):
            result = instance._wsl_control("status")

        self.assertFalse(result["running"])
        self.assertTrue(result["distroRestarted"])
        self.assertTrue(result["identityMismatch"])
        self.assertEqual(instance.metadata()["state"], "distro-restarted")
        persist.assert_called_once_with()
        self.assertEqual(run.call_count, 1)
        self.assertIn("status", run.call_args.args[0])
        self.assertNotIn("session-control", run.call_args.args[0])

    def test_authenticated_stale_wsl_socket_becomes_session_lost(self):
        instance = make_wsl_supervisor()
        stale = {
            "ok": False,
            "error": (
                "cannot connect to session socket: Connection refused; "
                "authenticated offline metadata unavailable: session control "
                "unavailable while metadata still reports running"
            ),
        }
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 2, stdout=b"", stderr=json.dumps(stale).encode())
        with (
            mock.patch.object(instance, "_wsl_distro_running",
                              return_value=(True, None)),
            mock.patch.object(instance, "_wsl_runtime_identity", return_value=(
                {"bootId": "boot-a", "uid": 1000}, None)),
            mock.patch.object(supervisor.subprocess, "run",
                              return_value=completed),
            mock.patch.object(instance, "persist") as persist,
        ):
            result = instance._wsl_control("status")

        self.assertFalse(result["running"])
        self.assertTrue(result["sessionLost"])
        self.assertEqual(instance.metadata()["state"], "session-lost")
        self.assertTrue(instance._final_persisted.is_set())
        persist.assert_called_once_with()

    def test_wsl_user_change_is_terminal_before_old_socket_control(self):
        instance = make_wsl_supervisor()
        with (
            mock.patch.object(instance, "_wsl_distro_running",
                              return_value=(True, None)),
            mock.patch.object(instance, "_wsl_runtime_identity", return_value=(
                {"bootId": "boot-a", "uid": 2000}, None)),
            mock.patch.object(supervisor.subprocess, "run") as run,
            mock.patch.object(instance, "persist"),
        ):
            result = instance._wsl_control("status")

        self.assertTrue(result["distroRestarted"])
        self.assertEqual(result["currentUid"], 2000)
        self.assertFalse(result["running"])
        run.assert_not_called()

    def test_unauthenticated_offline_error_does_not_claim_session_lost(self):
        instance = make_wsl_supervisor()
        rejected = {"ok": False,
                    "error": "session metadata token authentication failed"}
        completed = subprocess.CompletedProcess(
            ["wsl.exe"], 2, stdout=b"", stderr=json.dumps(rejected).encode())
        with (
            mock.patch.object(instance, "_wsl_distro_running",
                              return_value=(True, None)),
            mock.patch.object(instance, "_wsl_runtime_identity", return_value=(
                {"bootId": "boot-a", "uid": 1000}, None)),
            mock.patch.object(supervisor.subprocess, "run",
                              return_value=completed),
            mock.patch.object(instance, "persist") as persist,
        ):
            result = instance._wsl_control("status")

        self.assertFalse(result["ok"])
        self.assertNotIn("sessionLost", result)
        self.assertTrue(instance._wsl_running)
        persist.assert_not_called()

    def test_authenticated_control_retains_identity_until_explicit_force(self):
        with tempfile.TemporaryDirectory() as td:
            token = "test-token-" + "x" * 32
            if os.name == "nt":
                ignore_code = (
                    "import signal,time; "
                    "signal.signal(signal.SIGBREAK, lambda *a: None); "
                    "print('ready', flush=True); time.sleep(30)"
                )
            else:
                ignore_code = (
                    "import signal,time; "
                    "signal.signal(signal.SIGTERM, lambda *a: None); "
                    "print('ready', flush=True); time.sleep(30)"
                )
            launched = supervisor_client.launch_supervisor(
                str(ROOT), td, os.path.join(td, "run.log"), "deadbeef",
                token, [sys.executable, "-c", ignore_code],
                stop_timeout=0.25, allow_test_transport=True,
            )
            self.assertTrue(launched["ok"], launched)
            metadata = launched["metadata"]
            self.assertEqual(metadata["schemaVersion"], 2)
            self.assertEqual(metadata["protocolVersion"], 2)
            self.assertEqual(metadata["transport"], "test-tcp")
            self.assertNotIn(token, json.dumps(metadata))
            wrong = supervisor_client.call_supervisor(
                metadata, "wrong-token-" + "y" * 32, "status",
                allow_test_transport=True,
            )
            self.assertFalse(wrong["ok"])
            status = supervisor_client.status_supervisor(
                metadata, token, allow_test_transport=True,
            )
            self.assertTrue(status["ok"], status)
            self.assertTrue(status["running"])
            stopped = supervisor_client.stop_supervisor(
                metadata, token, timeout=2, allow_test_transport=True,
            )
            self.assertFalse(stopped["ok"], stopped)
            self.assertTrue(stopped.get("requiresForce"), stopped)
            retained = supervisor_client.status_supervisor(
                metadata, token, allow_test_transport=True,
            )
            self.assertTrue(retained["ok"], retained)
            self.assertTrue(retained["running"])
            forced = supervisor_client.stop_supervisor(
                metadata, token, force=True, timeout=2,
                allow_test_transport=True,
            )
            self.assertTrue(forced["ok"], forced)
            deadline = time.monotonic() + 5
            final = None
            path = supervisor_client.metadata_path(td, "deadbeef")
            while time.monotonic() < deadline:
                final = supervisor_client.load_metadata(path)
                if final and not final.get("running"):
                    break
                time.sleep(0.05)
            self.assertIsNotNone(final)
            self.assertFalse(final["running"])
            self.assertTrue(final["forceRequested"])

    @unittest.skipUnless(os.name == "nt", "Windows-only production transport")
    def test_windows_production_dependencies_fail_closed(self):
        with mock.patch.object(
            supervisor_client, "_windows_runtime"
        ) as runtime:
            runtime.return_value.validate_runtime.side_effect = RuntimeError("missing pywin32")
            with tempfile.TemporaryDirectory() as td:
                result = supervisor_client.launch_supervisor(
                    str(ROOT), td, os.path.join(td, "run.log"), "failclosed",
                    "z" * 40, [sys.executable, "-c", "pass"],
                )
        self.assertFalse(result["ok"])
        self.assertIn("missing pywin32", result["error"])

    @unittest.skipUnless(os.name == "nt", "Windows-only console allocation")
    def test_private_console_retries_transient_allocation_failure(self):
        kernel32 = mock.Mock()
        kernel32.FreeConsole.return_value = True
        kernel32.AllocConsole.side_effect = [False, True]
        kernel32.GetConsoleCP.return_value = 0
        kernel32.GetConsoleWindow.return_value = 0
        user32 = mock.Mock()
        with mock.patch.object(
                supervisor_windows.ctypes, "WinDLL",
                side_effect=[kernel32, user32]), \
                mock.patch.object(supervisor_windows.ctypes,
                                  "set_last_error") as clear_error, \
                mock.patch.object(supervisor_windows.ctypes,
                                  "get_last_error", return_value=317), \
                mock.patch.object(supervisor_windows.time, "sleep") as sleep:
            self.assertTrue(supervisor_windows.ensure_private_console())

        self.assertEqual(kernel32.AllocConsole.call_count, 2)
        self.assertEqual(kernel32.GetConsoleCP.call_count, 2)
        self.assertEqual(clear_error.call_count, 2)
        sleep.assert_called_once_with(0.05)

    @unittest.skipUnless(os.name == "nt", "Windows-only console isolation")
    def test_private_console_detection_rejects_a_shared_source_console(self):
        from ctypes import wintypes

        def process_list(values, _capacity):
            values[0] = os.getpid()
            values[1] = 99999
            return 2

        kernel32 = mock.Mock()
        kernel32.GetConsoleCP.return_value = 65001
        kernel32.GetConsoleProcessList.side_effect = process_list
        with mock.patch.object(sys, "frozen", False, create=True):
            private = supervisor_windows._current_console_is_private(
                kernel32, wintypes)
        self.assertFalse(private)

    @unittest.skipUnless(os.name == "nt", "Windows-only console isolation")
    def test_private_console_detection_accepts_only_current_source_process(self):
        from ctypes import wintypes

        def process_list(values, _capacity):
            values[0] = os.getpid()
            return 1

        kernel32 = mock.Mock()
        kernel32.GetConsoleCP.return_value = 65001
        kernel32.GetConsoleProcessList.side_effect = process_list
        with mock.patch.object(sys, "frozen", False, create=True):
            private = supervisor_windows._current_console_is_private(
                kernel32, wintypes)
        self.assertTrue(private)

    @unittest.skipUnless(os.name == "nt", "Windows-only console isolation")
    def test_private_console_accepts_matching_venv_bootstrap_chain(self):
        from ctypes import wintypes

        current_pid = os.getpid()
        parent_pid = current_pid + 100000
        command_tail = [str(ROOT / "supervisor.py"), "--metadata", "run.json"]

        def process_list(values, _capacity):
            values[0] = current_pid
            values[1] = parent_pid
            return 2

        class FakeProcess:
            def __init__(self, pid):
                self.pid = pid

            def exe(self):
                if self.pid == current_pid:
                    return r"C:\Python312\python.exe"
                return r"C:\venv\Scripts\python.exe"

            def cmdline(self):
                return [self.exe(), *command_tail]

            def ppid(self):
                return parent_pid if self.pid == current_pid else 1

        kernel32 = mock.Mock()
        kernel32.GetConsoleCP.return_value = 65001
        kernel32.GetConsoleProcessList.side_effect = process_list
        modules = types.SimpleNamespace(
            psutil=types.SimpleNamespace(Process=FakeProcess))
        with mock.patch.object(sys, "frozen", False, create=True), \
                mock.patch.object(supervisor_windows, "_modules",
                                  return_value=modules):
            private = supervisor_windows._current_console_is_private(
                kernel32, wintypes)
        self.assertTrue(private)

    def test_pipe_request_normalizes_terminal_pywintypes_error(self):
        class PipeError(Exception):
            pass

        pipe_error = PipeError(109, "ReadFile", "The pipe has been ended")
        pipe_error.winerror = 109
        modules = types.SimpleNamespace(
            pywintypes=types.SimpleNamespace(error=PipeError),
            win32pipe=types.SimpleNamespace(
                WaitNamedPipe=mock.Mock(side_effect=pipe_error)),
        )

        with self.assertRaises(OSError) as raised:
            supervisor_windows.pipe_request(
                r"\\.\pipe\LocalOps.Supervisor.test", b"{}\n", mods=modules)

        self.assertEqual(raised.exception.errno, 109)
        self.assertIs(raised.exception.__cause__, pipe_error)

    @unittest.skipUnless(os.name == "nt", "Windows-only persisted executable")
    def test_frozen_supervisor_is_hash_verified_and_copied_to_data_dir(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td, "app")
            bundled = base / "_internal" / "supervisors"
            bundled.mkdir(parents=True)
            source = bundled / "console-supervisor-1.2.3.exe"
            source.write_bytes(b"immutable-supervisor")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            Path(str(source) + ".sha256").write_text(
                digest + "  " + source.name + "\n", encoding="ascii"
            )
            data = Path(td, "data")
            windows = mock.Mock()
            windows.validate_runtime.return_value = True
            with (
                mock.patch.object(sys, "frozen", True, create=True),
                mock.patch.object(supervisor_client, "_windows_runtime", return_value=windows),
            ):
                argv = supervisor_client.supervisor_executable(
                    str(base), "1.2.3", data_dir=str(data)
                )
            target = Path(argv[0])
            self.assertEqual(target.parent, data / "supervisors")
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertGreaterEqual(windows.secure_path.call_count, 2)

    @unittest.skipUnless(os.name == "nt", "Windows-only persisted executable")
    def test_frozen_default_uses_supervisor_version_not_app_version(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td, "app")
            bundled = base / "_internal" / "supervisors"
            bundled.mkdir(parents=True)
            (base / "VERSION").write_text("1.0.0\n", encoding="ascii")
            source = bundled / "console-supervisor-2.0.0.exe"
            source.write_bytes(b"supervisor-v2")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            Path(str(source) + ".sha256").write_text(
                digest + "  " + source.name + "\n", encoding="ascii"
            )
            windows = mock.Mock()
            windows.validate_runtime.return_value = True
            with (
                mock.patch.object(sys, "frozen", True, create=True),
                mock.patch.object(supervisor_client, "_windows_runtime", return_value=windows),
            ):
                argv = supervisor_client.supervisor_executable(
                    str(base), data_dir=str(Path(td, "data"))
                )
            self.assertEqual(Path(argv[0]).name, "console-supervisor-2.0.0.exe")

    def test_cleanup_preserves_versions_referenced_by_running_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            supervisors = Path(td, "supervisors")
            runtime = Path(td, "runtime")
            supervisors.mkdir()
            runtime.mkdir()
            active = supervisors / "console-supervisor-1.0.0.exe"
            stale = supervisors / "console-supervisor-0.9.0.exe"
            active.write_bytes(b"active")
            stale.write_bytes(b"stale")
            Path(str(stale) + ".sha256").write_text("0" * 64, encoding="ascii")
            (runtime / "run.json").write_text(json.dumps({
                "running": True, "supervisorVersion": "1.0.0"
            }), encoding="utf-8")
            removed = supervisor_client.cleanup_unused_supervisors(td)
            self.assertTrue(active.exists())
            self.assertFalse(stale.exists())
            self.assertEqual(removed, [str(stale)])

    def test_cleanup_preserves_versions_referenced_by_recovery_metadata(self):
        for state in ("starting", "startup-cleanup-failed"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as td:
                supervisors = Path(td, "supervisors")
                runtime = Path(td, "runtime")
                supervisors.mkdir()
                runtime.mkdir()
                recovery = supervisors / "console-supervisor-1.1.0.exe"
                stale = supervisors / "console-supervisor-0.9.0.exe"
                recovery.write_bytes(b"recovery")
                stale.write_bytes(b"stale")
                (runtime / "run.json").write_text(json.dumps({
                    "running": False,
                    "state": state,
                    "supervisorVersion": "1.1.0",
                }), encoding="utf-8")

                removed = supervisor_client.cleanup_unused_supervisors(td)

                self.assertTrue(recovery.exists())
                self.assertFalse(stale.exists())
                self.assertEqual(removed, [str(stale)])

    @unittest.skipUnless(os.name == "nt", "Windows-only named pipe/Job integration")
    def test_windows_named_pipe_and_job_integration_when_dependencies_exist(self):
        try:
            supervisor_windows.validate_runtime()
        except supervisor_windows.WindowsRuntimeUnavailable as exc:
            self.skipTest(str(exc))
        token = "production-test-" + "p" * 32
        with tempfile.TemporaryDirectory() as td:
            code = (
                "import os,signal,time; "
                "signal.signal(signal.SIGBREAK, lambda *a: "
                "(print('break-received', flush=True), os._exit(0))); "
                "print('ready', flush=True)\n"
                "while True: time.sleep(0.05)"
            )
            launched = supervisor_client.launch_supervisor(
                str(ROOT), td, os.path.join(td, "run.log"), "nativejob",
                token, [sys.executable, "-c", code], stop_timeout=2.0,
            )
            self.assertTrue(launched["ok"], launched)
            metadata = launched["metadata"]
            self.assertEqual(metadata["transport"], "windows-named-pipe")
            self.assertTrue(metadata["jobName"].startswith(r"Local\LocalOps.Supervisor."))
            status = supervisor_client.status_supervisor(metadata, token)
            self.assertTrue(status["ok"], status)
            self.assertTrue(status["jobProcesses"], status)
            for member in status["jobProcesses"]:
                self.assertEqual(
                    set(member), {"pid", "createTime", "ownerSid"})
                self.assertEqual(member["ownerSid"], status["ownerSid"])
            stopped = supervisor_client.stop_supervisor(metadata, token, timeout=4)
            if not stopped.get("ok"):
                import psutil
                stopped["processes"] = []
                for pid in status.get("jobProcessIds", []):
                    try:
                        process = psutil.Process(pid)
                        stopped["processes"].append(
                            {"pid": pid, "name": process.name(), "cmdline": process.cmdline()}
                        )
                    except psutil.Error:
                        pass
                # Preserve explicit-force semantics during cleanup while still
                # surfacing the ordinary-stop defect in the assertion below.
                supervisor_client.stop_supervisor(metadata, token, force=True, timeout=4)
            if not stopped.get("ok"):
                stopped["log"] = Path(td, "run.log").read_text(
                    encoding="utf-8", errors="replace"
                )
            self.assertTrue(stopped["ok"], stopped)

    @unittest.skipUnless(os.name == "nt", "Windows-only Job force integration")
    def test_windows_normal_timeout_requires_explicit_job_force(self):
        try:
            supervisor_windows.validate_runtime()
        except supervisor_windows.WindowsRuntimeUnavailable as exc:
            self.skipTest(str(exc))
        token = "production-force-test-" + "f" * 32
        with tempfile.TemporaryDirectory() as td:
            code = (
                "import signal,time; "
                "signal.signal(signal.SIGBREAK, lambda *a: None); "
                "print('ready', flush=True)\n"
                "while True: time.sleep(0.05)"
            )
            launched = supervisor_client.launch_supervisor(
                str(ROOT), td, os.path.join(td, "run.log"), "nativeforce",
                token, [sys.executable, "-c", code], stop_timeout=0.2,
            )
            self.assertTrue(launched["ok"], launched)
            metadata = launched["metadata"]
            ready_deadline = time.monotonic() + 3
            while time.monotonic() < ready_deadline:
                if "ready" in Path(td, "run.log").read_text(
                    encoding="utf-8", errors="replace"
                ):
                    break
                time.sleep(0.025)
            else:
                supervisor_client.stop_supervisor(
                    metadata, token, force=True, timeout=3
                )
                self.fail("managed process did not reach its CTRL_BREAK handler")
            stopped = supervisor_client.stop_supervisor(metadata, token, timeout=3)
            self.assertFalse(stopped["ok"], stopped)
            self.assertTrue(stopped.get("requiresForce"), stopped)
            retained = supervisor_client.status_supervisor(metadata, token)
            self.assertTrue(retained["ok"], retained)
            self.assertTrue(retained["running"], retained)
            forced = supervisor_client.stop_supervisor(
                metadata, token, force=True, timeout=3
            )
            self.assertTrue(forced["ok"], forced)
            final = supervisor_client.load_metadata(
                supervisor_client.metadata_path(td, "nativeforce")
            )
            self.assertFalse(final["running"], final)
            self.assertTrue(final["forceRequested"], final)

    @unittest.skipUnless(os.name == "nt", "Windows-only descendant group integration")
    def test_windows_ctrl_break_uses_original_group_after_root_exits(self):
        try:
            supervisor_windows.validate_runtime()
        except supervisor_windows.WindowsRuntimeUnavailable as exc:
            self.skipTest(str(exc))
        token = "production-descendant-test-" + "d" * 32
        with tempfile.TemporaryDirectory() as td:
            ready = Path(td, "descendant.ready")
            broke = Path(td, "descendant.break")
            child_code = """
import os
import signal
import sys
import time

ready, broke = sys.argv[1:3]

def handle_break(*_args):
    with open(broke, "w", encoding="ascii") as stream:
        stream.write(str(os.getpid()))
    os._exit(0)

signal.signal(signal.SIGBREAK, handle_break)
with open(ready, "w", encoding="ascii") as stream:
    stream.write(str(os.getpid()))
while True:
    time.sleep(0.05)
"""
            root_code = (
                "import subprocess,sys; "
                "subprocess.Popen([sys.executable,'-c',%r,%r,%r])"
                % (child_code, str(ready), str(broke))
            )
            metadata = None
            try:
                launched = supervisor_client.launch_supervisor(
                    str(ROOT), td, os.path.join(td, "run.log"),
                    "nativedescendant", token,
                    [sys.executable, "-c", root_code], stop_timeout=2.0,
                )
                self.assertTrue(launched["ok"], launched)
                metadata = launched["metadata"]
                root_pid = metadata["childPid"]
                deadline = time.monotonic() + 5.0
                child_pid = None
                status = None
                while time.monotonic() < deadline:
                    if ready.exists():
                        ready_text = ready.read_text(encoding="ascii").strip()
                        # The child creates the file before its buffered write
                        # is visible; an empty observation is a normal race.
                        if ready_text.isdecimal():
                            child_pid = int(ready_text)
                    status = supervisor_client.status_supervisor(metadata, token)
                    members = set(status.get("jobProcessIds") or [])
                    if child_pid in members and root_pid not in members:
                        break
                    time.sleep(0.025)
                else:
                    self.fail({
                        "error": "root did not exit while its Job descendant stayed alive",
                        "rootPid": root_pid,
                        "childPid": child_pid,
                        "status": status,
                    })

                stopped = supervisor_client.stop_supervisor(
                    metadata, token, timeout=4)
                self.assertTrue(stopped["ok"], stopped)
                self.assertFalse(stopped.get("requiresForce", False), stopped)
                marker_deadline = time.monotonic() + 2.0
                while time.monotonic() < marker_deadline and not broke.exists():
                    time.sleep(0.025)
                self.assertTrue(broke.exists(), "descendant did not receive CTRL_BREAK")
                self.assertEqual(int(broke.read_text(encoding="ascii")), child_pid)
            finally:
                if metadata is not None:
                    current = supervisor_client.status_supervisor(metadata, token)
                    if current.get("running"):
                        supervisor_client.stop_supervisor(
                            metadata, token, force=True, timeout=4)


if __name__ == "__main__":
    unittest.main()
