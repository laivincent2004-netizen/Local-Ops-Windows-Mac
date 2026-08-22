#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_wsl-helper")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(helper()).args(arguments).output().expect("run helper")
}

fn run_with_stdin(arguments: &[&str], input: &str) -> Output {
    let mut child = Command::new(helper()).args(arguments)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("run helper with stdin");
    child.stdin.take().expect("helper stdin").write_all(input.as_bytes())
        .expect("write helper stdin");
    child.wait_with_output().expect("wait for helper")
}

fn run_with_stdin_env(arguments: &[&str], input: &str, name: &str, value: &str) -> Output {
    let mut child = Command::new(helper()).args(arguments).env(name, value)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("run helper with stdin and environment");
    child.stdin.take().expect("helper stdin").write_all(input.as_bytes())
        .expect("write helper stdin");
    child.wait_with_output().expect("wait for helper")
}

fn output_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 helper stdout")
}

fn json_string_field(text: &str, name: &str) -> String {
    let marker = format!("\"{name}\":\"");
    let start = text.find(&marker).expect("JSON string field") + marker.len();
    let end = text[start..].find('"').expect("JSON string terminator") + start;
    text[start..end].to_string()
}

fn json_u32_field(text: &str, name: &str) -> u32 {
    let marker = format!("\"{name}\":");
    let start = text.find(&marker).expect("JSON integer field") + marker.len();
    let end = text[start..].find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(text.len() - start) + start;
    text[start..end].parse().expect("positive JSON integer")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn wait_for_path(path: &Path) {
    for _ in 0..200 {
        if path.exists() { return; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}

fn wait_for_session_empty(sid: u32) {
    for _ in 0..200 {
        if session_members(sid).is_empty() { return; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("SID {sid} still contains {:?}", session_member_details(sid));
}

fn process_group_members(pgid: u32) -> Vec<u32> {
    let mut members = Vec::new();
    for entry in fs::read_dir("/proc").expect("read /proc").flatten() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(close) = stat.rfind(") ") else { continue; };
        let mut fields = stat[close + 2..].split_whitespace();
        let state = fields.next().unwrap_or("");
        let _ppid = fields.next();
        let member_pgid = fields.next().and_then(|value| value.parse::<u32>().ok());
        if member_pgid == Some(pgid) && state != "Z" { members.push(pid); }
    }
    members.sort_unstable();
    members
}

fn session_members(sid: u32) -> Vec<u32> {
    let mut members = Vec::new();
    for entry in fs::read_dir("/proc").expect("read /proc").flatten() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(close) = stat.rfind(") ") else { continue; };
        let mut fields = stat[close + 2..].split_whitespace();
        let state = fields.next().unwrap_or("");
        let _ppid = fields.next();
        let _pgid = fields.next();
        let member_sid = fields.next().and_then(|value| value.parse::<u32>().ok());
        if member_sid == Some(sid) && state != "Z" { members.push(pid); }
    }
    members.sort_unstable();
    members
}

fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(") ")?;
    stat[close + 2..].split_whitespace().next()?.chars().next()
}

fn session_member_details(sid: u32) -> Vec<String> {
    let mut members = Vec::new();
    for pid in session_members(sid) {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap_or_default();
        let Some(close) = stat.rfind(") ") else { continue; };
        let fields = stat[close + 2..].split_whitespace().collect::<Vec<_>>();
        let command = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
            .unwrap_or_default();
        members.push(format!(
            "pid={pid} state={} ppid={} pgid={} sid={} startTicks={} cmd={command}",
            fields.first().copied().unwrap_or("?"),
            fields.get(1).copied().unwrap_or("?"),
            fields.get(2).copied().unwrap_or("?"),
            fields.get(3).copied().unwrap_or("?"),
            fields.get(19).copied().unwrap_or("?"),
        ));
    }
    members
}

fn second_pgid_command(ready: &Path, lifetime_ms: u64, ignore_term: bool,
                       wait_for_member: bool) -> String {
    format!(
        "{} session-test-member --ready {} --lifetime-ms {}{} & {}",
        shell_quote(helper()), shell_quote(&as_text(ready)), lifetime_ms,
        if ignore_term { " --ignore-term" } else { "" },
        if wait_for_member { "wait" } else { "exit 0" },
    )
}

fn processes_containing(marker: &str) -> Vec<u32> {
    let mut matches = Vec::new();
    for entry in fs::read_dir("/proc").expect("read /proc").flatten() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else { continue; };
        if cmdline.windows(marker.len()).any(|window| window == marker.as_bytes()) {
            matches.push(pid);
        }
    }
    matches.sort_unstable();
    matches
}

fn private_test_dir() -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("local-ops-wsl-helper-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).expect("create private test directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("protect test directory");
    path
}

fn as_text(path: &Path) -> String {
    path.to_str().expect("test path is UTF-8").to_string()
}

struct SessionCleanup {
    socket: PathBuf,
    metadata: PathBuf,
    token: String,
    directory: PathBuf,
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        if self.socket.exists() {
            let _ = Command::new(helper()).args([
                "session-force-stop", "--json", "--socket",
                self.socket.to_str().unwrap_or(""), "--metadata",
                self.metadata.to_str().unwrap_or(""), "--token", &self.token,
                "--timeout-ms", "5000",
            ]).output();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn inspection_endpoints_emit_current_boot_and_process_identity() {
    let status = run(&["status", "--json"]);
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let status = output_text(&status);
    assert!(status.contains("\"protocolVersion\":2"));
    assert!(status.contains("\"bootId\":"));
    assert!(status.contains("\"pidfd-process-control\""));
    let self_sha256 = json_string_field(&status, "selfSha256");
    assert_eq!(self_sha256.len(), 64);
    assert!(self_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let own_pid = std::process::id().to_string();
    let processes = run(&["processes", "--json", "--pids", &own_pid]);
    assert!(processes.status.success(), "{}", String::from_utf8_lossy(&processes.stderr));
    let processes = output_text(&processes);
    assert!(processes.contains("\"startTicks\":"));
    assert!(processes.contains("\"cwdHash\":"));
    assert!(processes.contains("\"commandHash\":"));

    let network = run(&["network", "--json"]);
    assert!(network.status.success(), "{}", String::from_utf8_lossy(&network.stderr));
    assert!(output_text(&network).contains("\"preferredAddress\":"));
}

#[test]
fn verified_install_reports_the_hash_of_the_actual_installed_executable() {
    let directory = private_test_dir();
    let target = directory.join("installed-helper");
    let status = run(&["status", "--json"]);
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let expected = json_string_field(&output_text(&status), "selfSha256");

    let install = run(&[
        "install", "--json", "--target", &as_text(&target),
        "--sha256", &expected,
    ]);
    assert!(install.status.success(), "{}", String::from_utf8_lossy(&install.stderr));
    assert!(output_text(&install).contains(&format!("\"installedSha256\":\"{expected}\"")));
    assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o700);

    let installed_status = Command::new(&target).args(["status", "--json"])
        .output().expect("run installed helper");
    assert!(installed_status.status.success(), "{}", String::from_utf8_lossy(&installed_status.stderr));
    assert_eq!(
        json_string_field(&output_text(&installed_status), "selfSha256"),
        expected,
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn install_rejects_target_and_ancestor_symbolic_links() {
    let directory = private_test_dir();
    let status = run(&["status", "--json"]);
    let expected = json_string_field(&output_text(&status), "selfSha256");

    let victim = directory.join("victim");
    fs::write(&victim, b"must remain unchanged").unwrap();
    let linked_target = directory.join("linked-helper");
    symlink(&victim, &linked_target).unwrap();
    let target_result = run(&[
        "install", "--json", "--target", &as_text(&linked_target),
        "--sha256", &expected,
    ]);
    assert!(!target_result.status.success());
    assert!(String::from_utf8_lossy(&target_result.stderr).contains("symbolic link"));
    assert_eq!(fs::read(&victim).unwrap(), b"must remain unchanged");

    let actual_parent = directory.join("actual-parent");
    fs::create_dir(&actual_parent).unwrap();
    fs::set_permissions(&actual_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let linked_parent = directory.join("linked-parent");
    symlink(&actual_parent, &linked_parent).unwrap();
    let ancestor_target = linked_parent.join("helper");
    let ancestor_result = run(&[
        "install", "--json", "--target", &as_text(&ancestor_target),
        "--sha256", &expected,
    ]);
    assert!(!ancestor_result.status.success());
    assert!(String::from_utf8_lossy(&ancestor_result.stderr)
        .contains("symbolic-link path ancestor"));
    assert!(!actual_parent.join("helper").exists());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn session_start_rejects_target_and_ancestor_symbolic_links() {
    let directory = private_test_dir();
    let token = "89abcdef0123456789abcdef0123456789abcdef01234567";
    let real_state = directory.join("real-state");
    fs::create_dir(&real_state).unwrap();
    fs::set_permissions(&real_state, fs::Permissions::from_mode(0o700)).unwrap();
    let linked_state = directory.join("linked-state");
    symlink(&real_state, &linked_state).unwrap();
    let ancestor_result = run_with_stdin(&[
        "session-start", "--json", "--session-id", "symlink-session-ancestor",
        "--token-stdin", "--socket", &as_text(&linked_state.join("session.sock")),
        "--metadata", &as_text(&linked_state.join("session.json")),
        "--log", &as_text(&directory.join("session.log")),
        "--kind", "task", "--command", "exit 0",
    ], &format!("{token}\n"));
    assert!(!ancestor_result.status.success());
    assert!(String::from_utf8_lossy(&ancestor_result.stderr)
        .contains("symbolic-link path ancestor"));

    let socket = directory.join("target.sock");
    let victim = directory.join("socket-victim");
    fs::write(&victim, b"must remain unchanged").unwrap();
    symlink(&victim, &socket).unwrap();
    let target_result = run_with_stdin(&[
        "session-start", "--json", "--session-id", "symlink-session-target",
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&directory.join("target.json")),
        "--log", &as_text(&directory.join("target.log")),
        "--kind", "task", "--command", "exit 0",
    ], &format!("{token}\n"));
    assert!(!target_result.status.success());
    assert!(String::from_utf8_lossy(&target_result.stderr).contains("symbolic link"));
    assert_eq!(fs::read(&victim).unwrap(), b"must remain unchanged");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn session_socket_authentication_and_force_boundary_work_end_to_end() {
    let directory = private_test_dir();
    let socket = directory.join("session.sock");
    let metadata = directory.join("session.json");
    let log = directory.join("session.log");
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef";
    let _cleanup = SessionCleanup {
        socket: socket.clone(),
        metadata: metadata.clone(),
        token: token.to_string(),
        directory: directory.clone(),
    };
    let start = run_with_stdin(&[
        "session-start", "--json",
        "--session-id", "integration-session-0001",
        "--token-stdin",
        "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata),
        "--log", &as_text(&log),
        "--kind", "service",
        "--command", "trap '' TERM; while :; do sleep 1; done",
    ], &format!("{token}\n"));
    assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
    let start_text = output_text(&start);
    assert!(start_text.contains("\"running\":true"));
    assert!(start_text.contains("\"tokenHash\":"));
    assert!(!start_text.contains(token));
    assert_eq!(fs::symlink_metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&metadata).unwrap().permissions().mode() & 0o777, 0o600);
    let metadata_text = fs::read_to_string(&metadata).unwrap();
    assert!(metadata_text.contains("\"tokenHash\":"));
    assert!(!metadata_text.contains(token));

    let status = run(&[
        "session-status", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
    ]);
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    assert!(output_text(&status).contains("\"running\":true"));

    let stop = run(&[
        "session-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "100",
    ]);
    assert!(stop.status.success(), "{}", String::from_utf8_lossy(&stop.stderr));
    let stop_text = output_text(&stop);
    assert!(stop_text.contains("\"requiresForce\":true"));
    assert!(stop_text.contains("\"running\":true"));

    let force = run(&[
        "session-force-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "5000",
    ]);
    assert!(force.status.success(), "{}", String::from_utf8_lossy(&force.stderr));
    let force_text = output_text(&force);
    assert!(force_text.contains("\"running\":false"));
    assert!(force_text.contains("\"status\":\"stopped\""));

    for _ in 0..100 {
        if !socket.exists() { break; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!socket.exists(), "session socket should be removed after final metadata");
    let offline = run(&[
        "session-status", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
    ]);
    assert!(offline.status.success(), "{}", String::from_utf8_lossy(&offline.stderr));
    let offline_text = output_text(&offline);
    assert!(offline_text.contains("\"running\":false"));
    assert!(offline_text.contains("\"status\":\"stopped\""));

}

#[test]
fn session_stop_signals_a_second_pgid_in_the_pinned_sid() {
    let directory = private_test_dir();
    let socket = directory.join("second-pgid-stop.sock");
    let metadata = directory.join("second-pgid-stop.json");
    let log = directory.join("second-pgid-stop.log");
    let ready = directory.join("second-pgid-stop.ready");
    let token = "111122223333444455556666777788889999aaaabbbbcccc";
    let _cleanup = SessionCleanup {
        socket: socket.clone(), metadata: metadata.clone(),
        token: token.to_string(), directory: directory.clone(),
    };
    let command = second_pgid_command(&ready, 15_000, false, true);
    let start = run_with_stdin(&[
        "session-start", "--json", "--session-id", "integration-second-pgid-stop-0001",
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ], &format!("{token}\n"));
    assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
    let start_text = output_text(&start);
    wait_for_path(&ready);
    let member = fs::read_to_string(&ready).expect("read second-PGID identity");
    let sid = json_u32_field(&member, "sid");
    assert_eq!(sid, json_u32_field(&start_text, "supervisorPid"));
    assert_ne!(json_u32_field(&member, "pgid"), json_u32_field(&start_text, "pgid"));

    let stop = run(&[
        "session-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "5000",
    ]);
    assert!(stop.status.success(), "{}", String::from_utf8_lossy(&stop.stderr));
    let stop_text = output_text(&stop);
    assert!(stop_text.contains("\"running\":false"), "{stop_text}");
    assert!(stop_text.contains("\"status\":\"stopped\""), "{stop_text}");
    wait_for_session_empty(sid);
}

#[test]
fn session_force_stop_kills_a_term_resistant_second_pgid() {
    let directory = private_test_dir();
    let socket = directory.join("second-pgid-force.sock");
    let metadata = directory.join("second-pgid-force.json");
    let log = directory.join("second-pgid-force.log");
    let ready = directory.join("second-pgid-force.ready");
    let token = "aaaabbbbccccddddeeeeffff000011112222333344445555";
    let _cleanup = SessionCleanup {
        socket: socket.clone(), metadata: metadata.clone(),
        token: token.to_string(), directory: directory.clone(),
    };
    let command = second_pgid_command(&ready, 15_000, true, true);
    let start = run_with_stdin(&[
        "session-start", "--json", "--session-id", "integration-second-pgid-force-0001",
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ], &format!("{token}\n"));
    assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
    let start_text = output_text(&start);
    wait_for_path(&ready);
    let member = fs::read_to_string(&ready).expect("read second-PGID identity");
    let sid = json_u32_field(&member, "sid");
    assert_eq!(sid, json_u32_field(&start_text, "supervisorPid"));
    assert_ne!(json_u32_field(&member, "pgid"), json_u32_field(&start_text, "pgid"));

    let stop = run(&[
        "session-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "100",
    ]);
    assert!(stop.status.success(), "{}", String::from_utf8_lossy(&stop.stderr));
    let stop_text = output_text(&stop);
    assert!(stop_text.contains("\"running\":true"), "{stop_text}");
    assert!(stop_text.contains("\"requiresForce\":true"), "{stop_text}");
    assert!(!session_members(sid).is_empty());

    let force = run(&[
        "session-force-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "5000",
    ]);
    assert!(force.status.success(), "{}", String::from_utf8_lossy(&force.stderr));
    let force_text = output_text(&force);
    assert!(force_text.contains("\"running\":false"), "{force_text}");
    assert!(force_text.contains("\"status\":\"stopped\""), "{force_text}");
    wait_for_session_empty(sid);
}

#[test]
fn natural_root_exit_waits_for_a_second_pgid_in_the_pinned_sid() {
    let directory = private_test_dir();
    let socket = directory.join("second-pgid-natural.sock");
    let metadata = directory.join("second-pgid-natural.json");
    let log = directory.join("second-pgid-natural.log");
    let ready = directory.join("second-pgid-natural.ready");
    let token = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let _cleanup = SessionCleanup {
        socket: socket.clone(), metadata: metadata.clone(),
        token: token.to_string(), directory: directory.clone(),
    };
    let command = second_pgid_command(&ready, 1_500, false, false);
    let start = run_with_stdin(&[
        "session-start", "--json", "--session-id", "integration-second-pgid-natural-0001",
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "task", "--command", &command,
    ], &format!("{token}\n"));
    assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
    let start_text = output_text(&start);
    assert!(start_text.contains("\"running\":true"), "{start_text}");
    wait_for_path(&ready);
    let member = fs::read_to_string(&ready).expect("read second-PGID identity");
    let sid = json_u32_field(&member, "sid");
    assert_eq!(sid, json_u32_field(&start_text, "supervisorPid"));
    assert_ne!(json_u32_field(&member, "pgid"), json_u32_field(&start_text, "pgid"));

    let mut final_text = String::new();
    for _ in 0..100 {
        let status = run(&[
            "session-status", "--json", "--socket", &as_text(&socket),
            "--metadata", &as_text(&metadata), "--token", token,
        ]);
        if status.status.success() {
            final_text = output_text(&status);
            if final_text.contains("\"running\":false") { break; }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(final_text.contains("\"running\":false"),
        "{final_text}; live SID members: {:?}", session_member_details(sid));
    assert!(final_text.contains("\"status\":\"succeeded\""), "{final_text}");
    wait_for_session_empty(sid);
}

#[test]
fn failed_start_cleans_a_term_resistant_second_pgid_before_removing_identity() {
    let directory = private_test_dir();
    let socket = directory.join("second-pgid-failed-start.sock");
    let metadata = directory.join("second-pgid-failed-start.json");
    let log = directory.join("second-pgid-failed-start.log");
    let ready = directory.join("second-pgid-failed-start.ready");
    let token = "012301230123012301230123012301230123012301230123";
    let session_id = "integration-second-pgid-failed-start-0001";
    let _cleanup = SessionCleanup {
        socket: socket.clone(), metadata: metadata.clone(),
        token: token.to_string(), directory: directory.clone(),
    };
    let command = second_pgid_command(&ready, 15_000, true, true);
    let start = run_with_stdin_env(&[
        "session-start", "--json", "--session-id", session_id,
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ], &format!("{token}\n"), "LOCAL_OPS_WSL_HELPER_TEST_FAIL_START_STATUS", "1");
    assert!(!start.status.success(), "injected startup failure unexpectedly succeeded");
    let error = String::from_utf8_lossy(&start.stderr);
    assert!(error.contains("session token authentication failed"), "{error}");
    assert!(error.contains("authenticated force-stop cleanup completed"), "{error}");
    wait_for_path(&ready);
    let member = fs::read_to_string(&ready).expect("read failed-start member identity");
    let sid = json_u32_field(&member, "sid");
    wait_for_session_empty(sid);
    assert!(!socket.exists(), "failed start left its private socket");
    assert!(!metadata.exists(), "failed start left retry-blocking metadata");
}

#[test]
fn failed_start_fallback_keeps_the_dead_leader_unreaped_until_sid_cleanup() {
    let directory = private_test_dir();
    let socket = directory.join("unreaped-leader.sock");
    let metadata = directory.join("unreaped-leader.json");
    let log = directory.join("unreaped-leader.log");
    let ready = directory.join("unreaped-leader.ready");
    let token = "a1b2c3d4e5f607182736455463728190aabbccddeeff0011";
    let session_id = "integration-unreaped-leader-fallback-0001";
    let _cleanup = SessionCleanup {
        socket: socket.clone(), metadata: metadata.clone(),
        token: token.to_string(), directory: directory.clone(),
    };
    let command = second_pgid_command(&ready, 15_000, true, true);
    let mut start = Command::new(helper()).args([
        "session-start", "--json", "--session-id", session_id,
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ]).env("LOCAL_OPS_WSL_HELPER_TEST_EXIT_BEFORE_CONTROL", "1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("start unreaped-leader fallback fixture");
    start.stdin.take().expect("fixture stdin")
        .write_all(format!("{token}\n").as_bytes()).expect("write fixture token");

    wait_for_path(&ready);
    let member = fs::read_to_string(&ready).expect("read unreaped-leader member identity");
    let sid = json_u32_field(&member, "sid");
    let mut saw_zombie_leader = false;
    for _ in 0..200 {
        if process_state(sid) == Some('Z') {
            saw_zombie_leader = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(saw_zombie_leader, "session leader {sid} was reaped before exact-SID cleanup");

    let output = start.wait_with_output().expect("wait for startup fallback");
    assert!(!output.status.success(), "forced leader exit unexpectedly started a session");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("fallback cleanup completed"), "{error}");
    wait_for_session_empty(sid);
    assert!(process_state(sid).is_none(), "session leader {sid} was not reaped after cleanup");
    assert!(!socket.exists(), "fallback left its private socket");
    assert!(!metadata.exists(), "fallback left retry-blocking metadata");
}

#[test]
fn failed_start_handshake_force_stops_the_published_session_without_residue() {
    let directory = private_test_dir();
    let socket = directory.join("failed-start.sock");
    let metadata = directory.join("failed-start.json");
    let log = directory.join("failed-start.log");
    let pgid_file = directory.join("failed-start.pgid");
    let token = "13579bdf02468ace13579bdf02468ace13579bdf02468ace";
    let session_id = "integration-session-failed-start-0001";
    let _cleanup = SessionCleanup {
        socket: socket.clone(),
        metadata: metadata.clone(),
        token: token.to_string(),
        directory: directory.clone(),
    };
    let command = format!(
        "printf '%s\\n' \"$PPID\" > '{}'; trap '' TERM; while :; do sleep 1; done",
        as_text(&pgid_file),
    );
    let start = run_with_stdin_env(&[
        "session-start", "--json", "--session-id", session_id,
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ], &format!("{token}\n"), "LOCAL_OPS_WSL_HELPER_TEST_FAIL_START_STATUS", "1");
    assert!(!start.status.success(), "injected startup failure unexpectedly succeeded");
    let error = String::from_utf8_lossy(&start.stderr);
    assert!(error.contains("session token authentication failed"), "{error}");
    assert!(error.contains("authenticated force-stop cleanup completed"), "{error}");

    let pgid = fs::read_to_string(&pgid_file).expect("command wrote its process group")
        .trim().parse::<u32>().expect("numeric process group");
    for _ in 0..100 {
        if process_group_members(pgid).is_empty()
                && processes_containing(session_id).is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(process_group_members(pgid).is_empty(),
        "failed start left PGID {pgid}: {:?}", process_group_members(pgid));
    assert!(processes_containing(session_id).is_empty(),
        "failed start left session helper processes: {:?}", processes_containing(session_id));
    assert!(!socket.exists(), "failed start left its private socket");
    assert!(!metadata.exists(), "failed start left retry-blocking metadata");
}

#[test]
fn failed_start_with_inaccessible_control_kills_only_the_pinned_session_without_residue() {
    let directory = private_test_dir();
    let socket = directory.join("broken-control.sock");
    let metadata = directory.join("broken-control.json");
    let log = directory.join("broken-control.log");
    let pgid_file = directory.join("broken-control.pgid");
    let token = "2468ace013579bdf2468ace013579bdf2468ace013579bdf";
    let session_id = "integration-session-broken-control-0001";
    let _cleanup = SessionCleanup {
        socket: socket.clone(),
        metadata: metadata.clone(),
        token: token.to_string(),
        directory: directory.clone(),
    };
    let command = format!(
        "printf '%s\\n' \"$PPID\" > '{}'; trap '' TERM; while :; do sleep 1; done",
        as_text(&pgid_file),
    );
    let start = run_with_stdin_env(&[
        "session-start", "--json", "--session-id", session_id,
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ], &format!("{token}\n"), "LOCAL_OPS_WSL_HELPER_TEST_BREAK_START_CONTROL", "1");
    assert!(!start.status.success(), "inaccessible startup control unexpectedly succeeded");
    let error = String::from_utf8_lossy(&start.stderr);
    assert!(error.contains("private current-user control endpoint"), "{error}");
    assert!(error.contains("exact SID/UID/start-time fallback cleanup completed"), "{error}");

    let pgid = fs::read_to_string(&pgid_file).expect("command was released before control failure")
        .trim().parse::<u32>().expect("numeric process group");
    for _ in 0..100 {
        if process_group_members(pgid).is_empty()
                && processes_containing(session_id).is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(process_group_members(pgid).is_empty(),
        "inaccessible control left PGID {pgid}: {:?}", process_group_members(pgid));
    assert!(processes_containing(session_id).is_empty(),
        "inaccessible control left session processes: {:?}", processes_containing(session_id));
    assert!(!socket.exists(), "inaccessible control left its Unix socket");
    assert!(!metadata.exists(), "inaccessible control left retry-blocking metadata");
}

#[test]
fn post_release_session_loop_failure_cleans_the_exact_session_and_files() {
    let directory = private_test_dir();
    let socket = directory.join("loop-failure.sock");
    let metadata = directory.join("loop-failure.json");
    let log = directory.join("loop-failure.log");
    let pgid_file = directory.join("loop-failure.pgid");
    let token = "a5a5b6b6c7c7d8d8a5a5b6b6c7c7d8d8a5a5b6b6c7c7d8d8";
    let session_id = "integration-session-loop-failure-0001";
    let _cleanup = SessionCleanup {
        socket: socket.clone(),
        metadata: metadata.clone(),
        token: token.to_string(),
        directory: directory.clone(),
    };
    let command = format!(
        "printf '%s\\n' \"$PPID\" > '{}'; trap '' TERM; while :; do sleep 1; done",
        as_text(&pgid_file),
    );
    let start = run_with_stdin_env(&[
        "session-start", "--json", "--session-id", session_id,
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service", "--command", &command,
    ], &format!("{token}\n"), "LOCAL_OPS_WSL_HELPER_TEST_FAIL_SESSION_LOOP", "1");
    assert!(!start.status.success(), "injected post-release loop failure unexpectedly succeeded");
    let error = String::from_utf8_lossy(&start.stderr);
    assert!(error.contains("cleanup completed"), "{error}");

    let pgid = fs::read_to_string(&pgid_file).expect("post-release command wrote its process group")
        .trim().parse::<u32>().expect("numeric process group");
    for _ in 0..100 {
        if process_group_members(pgid).is_empty()
                && processes_containing(session_id).is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(process_group_members(pgid).is_empty(),
        "post-release failure left PGID {pgid}: {:?}", process_group_members(pgid));
    assert!(processes_containing(session_id).is_empty(),
        "post-release failure left session processes: {:?}", processes_containing(session_id));
    assert!(!socket.exists(), "post-release failure left its Unix socket");
    assert!(!metadata.exists(), "post-release failure left retry-blocking metadata");
}

#[test]
fn ultrafast_session_start_returns_authenticated_final_metadata() {
    let directory = private_test_dir();
    let socket = directory.join("quick.sock");
    let metadata = directory.join("quick.json");
    let log = directory.join("quick.log");
    let token = "abcdef0123456789abcdef0123456789abcdef0123456789";
    let _cleanup = SessionCleanup {
        socket: socket.clone(), metadata: metadata.clone(),
        token: token.to_string(), directory: directory.clone(),
    };
    let start = run_with_stdin(&[
        "session-start", "--json", "--session-id", "integration-session-fast-0001",
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "task", "--command", "exit 0",
    ], &format!("{token}\n"));
    assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
    let mut final_text = output_text(&start);
    assert!(!final_text.contains(token));
    for _ in 0..100 {
        if final_text.contains("\"running\":false") { break; }
        let status = run(&[
            "session-status", "--json", "--socket", &as_text(&socket),
            "--metadata", &as_text(&metadata), "--token", token,
        ]);
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        final_text = output_text(&status);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(final_text.contains("\"running\":false"), "{final_text}");
    assert!(final_text.contains("\"status\":\"succeeded\""), "{final_text}");
    assert!(!final_text.contains(token));
}

#[test]
fn session_stays_running_until_background_process_group_descendants_exit() {
    let directory = private_test_dir();
    let socket = directory.join("descendant.sock");
    let metadata = directory.join("descendant.json");
    let log = directory.join("descendant.log");
    let token = "fedcba9876543210fedcba9876543210fedcba9876543210";
    let _cleanup = SessionCleanup {
        socket: socket.clone(),
        metadata: metadata.clone(),
        token: token.to_string(),
        directory: directory.clone(),
    };
    let start = run_with_stdin(&[
        "session-start", "--json", "--session-id", "integration-session-descendant-0001",
        "--token-stdin", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--log", &as_text(&log),
        "--kind", "service",
        "--command", "trap '' TERM; while :; do sleep 1; done & exit 0",
    ], &format!("{token}\n"));
    assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
    assert!(output_text(&start).contains("\"running\":true"));
    std::thread::sleep(std::time::Duration::from_millis(100));

    let status = run(&[
        "session-status", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
    ]);
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    assert!(output_text(&status).contains("\"running\":true"));

    let stop = run(&[
        "session-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "100",
    ]);
    assert!(stop.status.success(), "{}", String::from_utf8_lossy(&stop.stderr));
    let stop_text = output_text(&stop);
    assert!(stop_text.contains("\"running\":true"), "{stop_text}");
    assert!(stop_text.contains("\"requiresForce\":true"), "{stop_text}");

    let force = run(&[
        "session-force-stop", "--json", "--socket", &as_text(&socket),
        "--metadata", &as_text(&metadata), "--token", token,
        "--timeout-ms", "5000",
    ]);
    assert!(force.status.success(), "{}", String::from_utf8_lossy(&force.stderr));
    let force_text = output_text(&force);
    assert!(force_text.contains("\"running\":false"), "{force_text}");
    assert!(force_text.contains("\"status\":\"stopped\""), "{force_text}");
}
