import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "wsl_helper"
SOURCE = (HELPER / "src" / "main.rs").read_text(encoding="utf-8")
PROTOCOL = (HELPER / "PROTOCOL.md").read_text(encoding="utf-8")


class WslHelperBuildTests(unittest.TestCase):
    def test_manifest_is_dependency_free_and_toolchain_is_pinned(self):
        manifest = (HELPER / "Cargo.toml").read_text(encoding="utf-8")
        toolchain = (HELPER / "rust-toolchain.toml").read_text(encoding="utf-8")
        lock = (HELPER / "Cargo.lock").read_text(encoding="utf-8")
        self.assertNotIn("[dependencies]", manifest)
        self.assertIn('rust-version = "1.88"', manifest)
        self.assertIn('channel = "1.88.0"', toolchain)
        self.assertIn('targets = ["x86_64-unknown-linux-musl"]', toolchain)
        self.assertEqual(lock.count("[[package]]"), 1)

    def test_build_runs_locked_musl_tests_before_release(self):
        script = (HELPER / "build.sh").read_text(encoding="utf-8")
        test_pos = script.index("cargo test --locked --target")
        build_pos = script.index("cargo build --locked --release --target")
        self.assertLess(test_pos, build_pos)
        self.assertIn("x86_64-unknown-linux-musl", script)
        self.assertIn('sha256sum "$root/$output"', script)
        self.assertIn('> "$root/$output.sha256"', script)

    def test_rust_integration_test_exercises_real_session_boundary(self):
        integration = (HELPER / "tests" / "helper_cli.rs").read_text(encoding="utf-8")
        self.assertIn("session-start", integration)
        self.assertIn("session-stop", integration)
        self.assertIn("requiresForce", integration)
        self.assertIn("session-force-stop", integration)
        self.assertIn("permissions().mode() & 0o777, 0o600", integration)
        self.assertIn("assert!(!metadata_text.contains(token))", integration)
        self.assertIn("installedSha256", integration)
        self.assertIn("install_rejects_target_and_ancestor_symbolic_links", integration)
        self.assertIn("session_start_rejects_target_and_ancestor_symbolic_links", integration)
        self.assertIn("session_stop_signals_a_second_pgid_in_the_pinned_sid", integration)
        self.assertIn("session_force_stop_kills_a_term_resistant_second_pgid", integration)
        self.assertIn("natural_root_exit_waits_for_a_second_pgid_in_the_pinned_sid", integration)
        self.assertIn("failed_start_cleans_a_term_resistant_second_pgid", integration)
        self.assertIn("failed_start_fallback_keeps_the_dead_leader_unreaped_until_sid_cleanup", integration)


class WslHelperProtocolTests(unittest.TestCase):
    def test_inspection_protocol_is_proc_only_and_uid_scoped(self):
        for operation in ("status", "boot-id", "network", "processes", "cwds", "listeners"):
            self.assertRegex(SOURCE, rf'"{re.escape(operation)}"')
        self.assertIn('"/proc/net/tcp"', SOURCE)
        self.assertIn('"/proc/net/tcp6"', SOURCE)
        self.assertIn('pid_owned_by_current_user', SOURCE)
        self.assertIn('metadata.uid() == current_uid()', SOURCE)
        for forbidden in ('Command::new("ps")', 'Command::new("lsof")',
                          'Command::new("ip")', 'Command::new("hostname")'):
            self.assertNotIn(forbidden, SOURCE)

    def test_network_fallback_is_filtered_without_external_commands(self):
        self.assertIn('"/proc/net/fib_trie"', SOURCE)
        self.assertIn('"/proc/net/if_inet6"', SOURCE)
        self.assertIn('preferredAddress', SOURCE)
        self.assertIn('is_loopback()', SOURCE)
        self.assertIn('is_unicast_link_local()', SOURCE)
        self.assertIn('"network"', SOURCE)
        self.assertIn("preferredAddress", PROTOCOL)
        self.assertIn("fib_trie", PROTOCOL)
        self.assertIn("No route or network command is executed.", PROTOCOL)

    def test_session_protocol_has_private_authenticated_socket(self):
        for operation in ("session-start", "session-control", "session-status",
                          "session-stop", "session-force-stop"):
            self.assertIn(f'"{operation}"', SOURCE)
        self.assertIn("SO_PEERCRED", SOURCE)
        self.assertIn("peer_uid(stream)? != current_uid()", SOURCE)
        self.assertIn("Permissions::from_mode(0o600)", SOURCE)
        self.assertIn("metadata.mode() & 0o777 != 0o600", SOURCE)
        self.assertIn("constant_time_eq", SOURCE)
        self.assertIn("token_hash", SOURCE)
        self.assertIn("--token-stdin", SOURCE)

    def test_stop_is_term_first_and_force_is_explicit_kill(self):
        stop_arm = SOURCE.index('"stop"=>{', SOURCE.index("fn handle_session_request"))
        force_arm = SOURCE.index('"force-stop"=>{', stop_arm)
        self.assertIn("signal_session_members", SOURCE[stop_arm:force_arm])
        self.assertIn("SIGTERM", SOURCE[stop_arm:force_arm])
        self.assertNotIn("SIGKILL", SOURCE[stop_arm:force_arm])
        self.assertIn("force_signal_exact_session_members_until", SOURCE[force_arm:])
        self.assertIn("SIGKILL", SOURCE[SOURCE.index("fn force_signal_exact_session_members_until"):])
        self.assertIn("requiresForce", SOURCE)
        self.assertIn("stat.start_ticks != expected.start_ticks", SOURCE)
        self.assertIn("stat.pgid != expected.pgid", SOURCE)
        self.assertNotRegex(SOURCE, r'kill\([^\n]*port')

    def test_session_lifecycle_tracks_the_spawn_pinned_sid(self):
        sid_scan = SOURCE[
            SOURCE.index("fn exact_session_members"):
            SOURCE.index("fn process_still_matches")
        ]
        self.assertIn("stat.sid != identity.pid", sid_scan)
        self.assertIn("stat.state == 'Z'", sid_scan)
        self.assertIn("details.uid() != identity.uid", sid_scan)
        self.assertIn("stat.start_ticks != expected.start_ticks", sid_scan)
        self.assertIn("stat.pgid != expected.pgid", sid_scan)
        self.assertIn("SYS_PIDFD_OPEN_X86_64", sid_scan)
        self.assertIn("signal_exact_session_snapshot", sid_scan)
        self.assertIn("Some(identity.pid)", sid_scan)
        self.assertIn("open_verified_session_member", sid_scan)
        self.assertIn("signal_pidfd_allow_exited(handle, signal)", sid_scan)

        lifecycle = SOURCE[
            SOURCE.index("fn poll_session_child"):
            SOURCE.index("fn control_request")
        ]
        self.assertIn("wait_for_session_members_exit", lifecycle)
        self.assertGreaterEqual(lifecycle.count("session_members_running(record, identity)?"), 3)
        self.assertIn("child_status: &mut Option<ExitStatus>", lifecycle)
        self.assertIn("completed_session_response(record, child_status, false)", lifecycle)
        self.assertNotIn("match wait_for_child(child", lifecycle)

        session_run = SOURCE[SOURCE.index("fn session_run"):SOURCE.index("fn control_request")]
        self.assertIn("session_members_running(&record, &supervisor_identity)", session_run)
        self.assertIn("child_status.is_some()", session_run)

        cleanup = SOURCE[
            SOURCE.index("fn finish_failed_session_start_cleanup"):
            SOURCE.index("fn cleanup_failed_session_start")
        ]
        force_pos = cleanup.index("force_kill_exact_session_members")
        proof_pos = cleanup.index("exact_session_members")
        reap_pos = cleanup.index("wait_for_supervisor_exit")
        remove_pos = cleanup.index("remove_authenticated_session_files")
        self.assertLess(force_pos, proof_pos)
        self.assertLess(proof_pos, reap_pos)
        self.assertLess(reap_pos, remove_pos)

        startup_cleanup = SOURCE[
            SOURCE.index("fn cleanup_failed_session_start"):
            SOURCE.index("fn session_start_failure")
        ]
        self.assertNotIn("supervisor.try_wait()", startup_cleanup)
        self.assertIn("validate_session_supervisor_if_present(identity)", startup_cleanup)

        session_start = SOURCE[SOURCE.index("fn session_start(cli"):SOURCE.index("fn inspection_output")]
        sigchld_pos = session_start.index("c_signal(SIGCHLD, SIG_DFL)")
        spawn_pos = session_start.index("child_command.spawn()")
        self.assertLess(sigchld_pos, spawn_pos)
        self.assertNotIn("supervisor.try_wait()", session_start)
        self.assertIn("unreaped", PROTOCOL)

        session_exec = SOURCE[SOURCE.index("fn session_exec"):SOURCE.index("fn session_run")]
        self.assertIn("stable process-group leader", session_exec)
        self.assertIn("c_signal(SIGTERM, SIG_IGN)", session_exec)
        self.assertIn("current_user_group_has_other_members", session_exec)

    def test_external_process_control_requires_full_pidfd_identity(self):
        control = SOURCE[SOURCE.index("fn process_control(cli"):SOURCE.index("fn exit_record")]
        for option in ("pid", "uid", "boot-id", "start-ticks", "cwd-hash", "command-hash"):
            self.assertIn(f'required_value(cli, "{option}")', control)
        self.assertIn("SYS_PIDFD_OPEN_X86_64", SOURCE)
        self.assertIn("SYS_PIDFD_SEND_SIGNAL_X86_64", SOURCE)
        self.assertIn("open_verified_pidfd", control)
        self.assertIn("fingerprint_matches", SOURCE)
        self.assertIn('action == "stop" { SIGTERM } else { SIGKILL }', control)
        self.assertIn("requiresForce", SOURCE)
        self.assertIn("cwdHash", SOURCE)
        self.assertIn("commandHash", SOURCE)

    def test_session_metadata_is_atomic_and_does_not_store_plain_token(self):
        metadata_fn = SOURCE[SOURCE.index("fn metadata_json"):SOURCE.index("fn public_session_json")]
        public_fn = SOURCE[SOURCE.index("fn public_session_json"):SOURCE.index("fn write_metadata")]
        self.assertIn("tokenHash", metadata_fn)
        self.assertNotIn('"token"', metadata_fn)
        self.assertIn("tokenHash", public_fn)
        self.assertIn('"running"', public_fn)
        self.assertNotIn('"token"', public_fn)
        self.assertIn("create_new(true)", SOURCE)
        self.assertIn("fs::rename(&temporary", SOURCE)
        self.assertIn("file.sync_all()", SOURCE)
        self.assertIn("c_setsid", SOURCE)
        self.assertIn("shell.process_group(0)", SOURCE)

    def test_offline_terminal_metadata_is_authenticated_and_never_controls_running_state(self):
        fallback = SOURCE[
            SOURCE.index("fn read_private_metadata"):
            SOURCE.index("fn read_socket_line")
        ]
        self.assertIn("O_NOFOLLOW", fallback)
        self.assertIn("details.is_file()", fallback)
        self.assertIn("details.uid() != current_uid()", fallback)
        self.assertIn("details.mode() & 0o777 != 0o600", fallback)
        self.assertIn("constant_time_eq(metadata_boot.as_bytes()", fallback)
        self.assertIn("constant_time_eq(stored_hash.as_bytes()", fallback)
        self.assertIn('state != "exited"', fallback)
        self.assertIn("metadata still reports running", fallback)
        control = SOURCE[SOURCE.index("fn control_request"):SOURCE.index("fn session_start")]
        self.assertIn("offline_session_result(metadata_path,socket,token)", control)
        self.assertIn("authenticated offline metadata unavailable", control)
        self.assertIn("session socket transport failed", control)
        self.assertIn("Unix socket message is empty", SOURCE)
        self.assertNotIn("_=>return Err(format!(\"cannot connect to session socket", control)
        self.assertIn('required_value(cli,"metadata")', control)

    def test_session_child_handshake_precedes_command_exec(self):
        session_exec = SOURCE[SOURCE.index("fn session_exec"):SOURCE.index("fn session_run")]
        session_run = SOURCE[SOURCE.index("fn session_run"):SOURCE.index("fn control_request")]
        self.assertIn("read_exact(&mut ready)", session_exec)
        self.assertIn('Command::new("/bin/sh")', session_exec)
        self.assertIn('write_metadata(&record,"running"', session_run)
        self.assertIn("handshake.write_all(&[1])", session_run)
        self.assertLess(
            session_run.index('write_metadata(&record,"running"'),
            session_run.index("handshake.write_all(&[1])"),
        )

    def test_self_install_is_sha_verified_and_atomic(self):
        install = SOURCE[SOURCE.index("fn install_helper"):SOURCE.index("fn exit_json")]
        self.assertIn("env::current_exe()", install)
        self.assertIn("SHA-256", install)
        self.assertIn("sha256_reader", install)
        self.assertGreaterEqual(install.count("constant_time_eq"), 3)
        self.assertIn("Permissions::from_mode(0o700)", install)
        self.assertIn("fs::rename(&temporary, &target)", install)
        self.assertIn("sync_directory(parent)", install)
        self.assertIn("installedSha256", install)
        self.assertIn("refusing symbolic link", SOURCE)

    def test_status_attests_actual_executable_and_private_paths_check_ancestors(self):
        status = SOURCE[SOURCE.index("fn current_executable_sha256"):
                        SOURCE.index('"boot-id"=>')]
        self.assertIn('File::open("/proc/self/exe")', status)
        self.assertIn("selfSha256", status)
        ancestor_check = SOURCE[
            SOURCE.index("fn check_ancestors_not_symlinks"):
            SOURCE.index("fn sync_directory")
        ]
        self.assertIn("symlink_metadata(&current)", ancestor_check)
        self.assertGreaterEqual(
            ancestor_check.count("check_ancestors_not_symlinks(parent"), 5)
        self.assertIn("selfSha256", PROTOCOL)
        self.assertIn("actual executable inode", PROTOCOL)

    def test_protocol_document_matches_json_contract(self):
        self.assertIn("protocol v2", PROTOCOL)
        self.assertIn("SIGTERM", PROTOCOL)
        self.assertIn("SIGKILL", PROTOCOL)
        self.assertIn("requiresForce", PROTOCOL)
        self.assertIn("installedSha256", PROTOCOL)
        self.assertIn("selfSha256", PROTOCOL)
        self.assertIn("SO_PEERCRED", PROTOCOL)
        self.assertIn("startTicks", PROTOCOL)


if __name__ == "__main__":
    unittest.main()
