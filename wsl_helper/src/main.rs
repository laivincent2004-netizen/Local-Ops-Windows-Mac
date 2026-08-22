//! Dependency-free Linux helper used inside running WSL2 distributions.
//!
//! The helper deliberately uses only Rust's standard library. The release
//! artifact is built for x86_64-unknown-linux-musl so a distribution does not
//! need glibc, Python, ps, lsof, sha256sum, cp, or setsid.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown};
use std::os::raw::{c_int, c_long, c_uint, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROTOCOL_VERSION: u32 = 2;
const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_PROC_TEXT: u64 = 32 * 1024 * 1024;
const MAX_CMDLINE: u64 = 1024 * 1024;
const MAX_REQUEST: u64 = 8192;
const MAX_RESPONSE: u64 = 64 * 1024;
const MAX_INSTALL_SIZE: u64 = 64 * 1024 * 1024;
const MAX_PIDS: usize = 4096;
const O_NOFOLLOW: c_int = 0x20000;
const SIGTERM: c_int = 15;
const SIGKILL: c_int = 9;
const SIGCHLD: c_int = 17;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SIG_ERR: usize = usize::MAX;
const ESRCH: i32 = 3;
const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;
const SC_CLK_TCK: c_int = 2;
const SC_PAGESIZE: c_int = 30;
// The release target is pinned to x86_64 Linux in Cargo/build.sh.
const SYS_PIDFD_SEND_SIGNAL_X86_64: c_long = 424;
const SYS_PIDFD_OPEN_X86_64: c_long = 434;

extern "C" {
    #[link_name = "setsid"]
    fn c_setsid() -> c_int;
    #[link_name = "kill"]
    fn c_kill(pid: c_int, signal: c_int) -> c_int;
    #[cfg(debug_assertions)]
    #[link_name = "setpgid"]
    fn c_setpgid(pid: c_int, pgid: c_int) -> c_int;
    #[link_name = "signal"]
    fn c_signal(signal: c_int, handler: usize) -> usize;
    #[link_name = "getuid"]
    fn c_getuid() -> u32;
    #[link_name = "sysconf"]
    fn c_sysconf(name: c_int) -> i64;
    #[link_name = "getsockopt"]
    fn c_getsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *mut c_void,
        option_len: *mut u32,
    ) -> c_int;
    #[link_name = "syscall"]
    fn c_syscall(number: c_long, ...) -> c_long;
}

#[repr(C)]
#[derive(Default)]
struct PeerCredentials {
    pid: c_int,
    uid: u32,
    gid: u32,
}

#[derive(Default)]
struct Cli {
    operation: String,
    flags: BTreeSet<String>,
    values: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct ProcStat {
    comm: String,
    state: char,
    ppid: u32,
    pgid: u32,
    sid: u32,
    user_ticks: u64,
    system_ticks: u64,
    start_ticks: u64,
    rss_pages: i64,
}

#[derive(Clone)]
struct ProcessFingerprint {
    pid: u32,
    uid: u32,
    boot_id: String,
    start_ticks: u64,
    cwd_hash: String,
    command_hash: String,
}

#[derive(Clone)]
struct SessionRecord {
    session_id: String,
    token_hash: String,
    boot_id: String,
    uid: u32,
    supervisor_pid: u32,
    pid: u32,
    pgid: u32,
    start_ticks: u64,
    socket: PathBuf,
    metadata: PathBuf,
    log: PathBuf,
    cwd: Option<PathBuf>,
    kind: String,
    command_hash: String,
    started_at: f64,
}

struct SessionSupervisorIdentity {
    pid: u32,
    uid: u32,
    start_ticks: u64,
    pidfd: OwnedFd,
}

#[derive(Clone, Copy, Debug)]
struct SessionMemberIdentity {
    pid: u32,
    uid: u32,
    pgid: u32,
    sid: u32,
    start_ticks: u64,
}

#[derive(Clone)]
struct ExitRecord {
    status: String,
    code: Option<i32>,
    signal: Option<i32>,
    at: f64,
    duration_sec: f64,
}

struct SocketPathGuard(PathBuf);

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Clone, Debug)]
enum JsonValue {
    String(String),
    Number(i64),
    Float(f64),
    Boolean(bool),
    Null,
    Object(BTreeMap<String, JsonValue>),
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot mutate Rust-owned memory.
    unsafe { c_getuid() }
}

fn epoch_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn epoch_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_error(message: &str) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", json_string(message))
}

fn read_limited(path: impl AsRef<Path>, limit: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    read_file_limited(file, limit)
}

fn read_file_limited(file: File, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file is too large"));
    }
    Ok(bytes)
}

fn read_text(path: impl AsRef<Path>, limit: u64) -> String {
    read_limited(path, limit)
        .map(|value| String::from_utf8_lossy(&value).trim().to_string())
        .unwrap_or_default()
}

fn boot_id() -> Result<String, String> {
    let value = read_text("/proc/sys/kernel/random/boot_id", 256);
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_whitespace) {
        return Err("cannot read a valid Linux boot ID".into());
    }
    Ok(value)
}

fn uptime() -> f64 {
    read_text("/proc/uptime", 4096)
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}

fn sysconf_positive(name: c_int, fallback: f64) -> f64 {
    // SAFETY: sysconf reads an integer process setting for a constant key.
    let value = unsafe { c_sysconf(name) };
    if value > 0 { value as f64 } else { fallback }
}

fn clock_ticks() -> f64 {
    sysconf_positive(SC_CLK_TCK, 100.0)
}

fn page_size() -> f64 {
    sysconf_positive(SC_PAGESIZE, 4096.0)
}

fn total_memory_bytes() -> f64 {
    for line in read_text("/proc/meminfo", 1024 * 1024).lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            if let Some(kib) = rest.split_whitespace().next().and_then(|value| value.parse::<f64>().ok()) {
                return kib * 1024.0;
            }
        }
    }
    0.0
}

fn parse_stat_line(line: &str) -> Option<ProcStat> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = line.get(open + 1..close)?.to_string();
    let fields: Vec<&str> = line.get(close + 2..)?.split_whitespace().collect();
    Some(ProcStat {
        comm,
        state: fields.first()?.chars().next()?,
        ppid: fields.get(1)?.parse().ok()?,
        pgid: fields.get(2)?.parse().ok()?,
        sid: fields.get(3)?.parse().ok()?,
        user_ticks: fields.get(11)?.parse().ok()?,
        system_ticks: fields.get(12)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
        rss_pages: fields.get(21)?.parse().ok()?,
    })
}

fn proc_stat(pid: u32) -> Option<ProcStat> {
    parse_stat_line(&read_text(format!("/proc/{pid}/stat"), 64 * 1024))
}

fn strict_proc_stat(pid: u32) -> Result<Option<ProcStat>, String> {
    let path = format!("/proc/{pid}/stat");
    let file = match File::open(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot open exact session member stat {pid}: {error}")),
    };
    let bytes = read_file_limited(file, 64 * 1024)
        .map_err(|error| format!("cannot read exact session member stat {pid}: {error}"))?;
    let text = String::from_utf8_lossy(&bytes);
    parse_stat_line(text.trim()).map(Some)
        .ok_or_else(|| format!("cannot parse exact session member stat {pid}"))
}

fn pid_owned_by_current_user(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}"))
        .map(|metadata| metadata.uid() == current_uid())
        .unwrap_or(false)
}

fn process_ids(filter: &BTreeSet<u32>) -> Vec<u32> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if result.len() >= MAX_PIDS {
                break;
            }
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                if (filter.is_empty() || filter.contains(&pid)) && pid_owned_by_current_user(pid) {
                    result.push(pid);
                }
            }
        }
    }
    result.sort_unstable();
    result
}

fn process_json(
    pid: u32,
    system_uptime: f64,
    ticks: f64,
    memory_bytes: f64,
    current_boot_id: &str,
) -> Option<String> {
    if !pid_owned_by_current_user(pid) {
        return None;
    }
    let stat = proc_stat(pid)?;
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let uid = fs::metadata(&proc_path).ok()?.uid();
    if uid != current_uid() {
        return None;
    }
    let cmdline = read_limited(proc_path.join("cmdline"), MAX_CMDLINE).unwrap_or_default();
    let command_hash = sha256_bytes(&cmdline);
    let args = String::from_utf8_lossy(&cmdline).replace('\0', " ").trim().to_string();
    let cwd_path = fs::read_link(proc_path.join("cwd")).ok();
    let cwd_hash = cwd_path.as_ref().map(|path| sha256_bytes(path.as_os_str().as_bytes()));
    let cwd = cwd_path.as_ref().map(|path| path.to_string_lossy().into_owned());
    let elapsed = (system_uptime - stat.start_ticks as f64 / ticks).max(0.0);
    let cpu_seconds = (stat.user_ticks + stat.system_ticks) as f64 / ticks;
    let cpu = if elapsed > 0.0 { (cpu_seconds / elapsed) * 100.0 } else { 0.0 };
    let rss_bytes = stat.rss_pages.max(0) as f64 * page_size();
    let mem = if memory_bytes > 0.0 { (rss_bytes / memory_bytes) * 100.0 } else { 0.0 };
    let create_time = (epoch_seconds() - system_uptime + stat.start_ticks as f64 / ticks).max(0.0);
    Some(format!(
        concat!(
            "{{\"pid\":{pid},\"uid\":{uid},\"ppid\":{ppid},",
            "\"pgid\":{pgid},\"sid\":{sid},\"comm\":{comm},",
            "\"args\":{args},\"cwd\":{cwd},\"cpu\":{cpu:.4},",
            "\"mem\":{mem:.4},\"etime\":{etime},",
            "\"create_time\":{create_time:.6},\"startTicks\":{start_ticks},",
            "\"cwdHash\":{cwd_hash},\"commandHash\":{command_hash},",
            "\"boot_id\":{boot_id}}}"
        ),
        pid = pid,
        uid = uid,
        ppid = stat.ppid,
        pgid = stat.pgid,
        sid = stat.sid,
        comm = json_string(&stat.comm),
        args = json_string(&args),
        cwd = cwd.as_deref().map(json_string).unwrap_or_else(|| "null".into()),
        cpu = cpu,
        mem = mem,
        etime = elapsed as u64,
        create_time = create_time,
        start_ticks = stat.start_ticks,
        cwd_hash = cwd_hash.as_deref().map(json_string).unwrap_or_else(|| "null".into()),
        command_hash = json_string(&command_hash),
        boot_id = json_string(current_boot_id),
    ))
}

fn decode_ipv4(value: &str) -> Option<String> {
    let raw = u32::from_str_radix(value, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn decode_ipv6(value: &str) -> Option<String> {
    if value.len() != 32 { return None; }
    let mut bytes = [0u8; 16];
    for index in 0..4 {
        let chunk = value.get(index * 8..index * 8 + 8)?;
        let word = u32::from_str_radix(chunk, 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

fn socket_inodes(pid: u32) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    if !pid_owned_by_current_user(pid) { return result; }
    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) {
        for entry in entries.flatten().take(65_536) {
            if let Ok(target) = fs::read_link(entry.path()) {
                let text = target.to_string_lossy();
                if let Some(value) = text.strip_prefix("socket:[").and_then(|value| value.strip_suffix(']')) {
                    if let Ok(inode) = value.parse() { result.insert(inode); }
                }
            }
        }
    }
    result
}

fn tcp_listeners() -> BTreeMap<u64, (u16, String)> {
    let mut result = BTreeMap::new();
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        for line in read_text(path, MAX_PROC_TEXT).lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != "0A" { continue; }
            let mut local = fields[1].split(':');
            let address = local.next().unwrap_or("");
            let port = local.next().and_then(|value| u16::from_str_radix(value, 16).ok());
            let inode = fields[9].parse::<u64>().ok();
            if let (Some(port), Some(inode)) = (port, inode) {
                let host = if ipv6 { decode_ipv6(address) } else { decode_ipv4(address) }
                    .unwrap_or_else(|| address.to_string());
                result.insert(inode, (port, host));
            }
        }
    }
    result
}

fn usable_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => !value.is_loopback() && !value.is_link_local()
            && !value.is_unspecified() && !value.is_multicast(),
        IpAddr::V6(value) => !value.is_loopback() && !value.is_unicast_link_local()
            && !value.is_unspecified() && !value.is_multicast(),
    }
}

fn parse_fib_trie(input: &str) -> BTreeSet<IpAddr> {
    let mut addresses = BTreeSet::new();
    let mut candidate = None;
    for line in input.lines() {
        if let Some(value) = line.split_whitespace().last().and_then(|value| value.parse::<Ipv4Addr>().ok()) {
            candidate = Some(value);
        }
        if line.contains("/32 host LOCAL") {
            if let Some(value) = candidate.take() {
                let address = IpAddr::V4(value);
                if usable_address(address) { addresses.insert(address); }
            }
        }
    }
    addresses
}

fn parse_if_inet6(input: &str) -> BTreeSet<IpAddr> {
    let mut addresses = BTreeSet::new();
    for line in input.lines() {
        let encoded = line.split_whitespace().next().unwrap_or("");
        if encoded.len() != 32 { continue; }
        let mut bytes = [0u8; 16];
        let mut valid = true;
        for index in 0..16 {
            match u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16) {
                Ok(value) => bytes[index] = value,
                Err(_) => { valid = false; break; }
            }
        }
        if valid {
            let address = IpAddr::V6(Ipv6Addr::from(bytes));
            if usable_address(address) { addresses.insert(address); }
        }
    }
    addresses
}

fn network_addresses() -> Vec<IpAddr> {
    let mut addresses = parse_fib_trie(&read_text("/proc/net/fib_trie", MAX_PROC_TEXT));
    addresses.extend(parse_if_inet6(&read_text("/proc/net/if_inet6", 4 * 1024 * 1024)));
    let mut result: Vec<IpAddr> = addresses.into_iter().collect();
    result.sort_by_key(|address| match address { IpAddr::V4(_) => 0, IpAddr::V6(_) => 1 });
    result
}

fn parse_cli() -> Result<Cli, String> {
    let mut args = env::args().skip(1);
    let operation = args.next().unwrap_or_else(|| "status".into());
    if operation.starts_with('-') { return Err("operation must be the first argument".into()); }
    let mut cli = Cli { operation, ..Cli::default() };
    while let Some(argument) = args.next() {
        if !argument.starts_with("--") || argument.len() <= 2 {
            return Err(format!("unexpected positional argument: {argument}"));
        }
        let name = argument.trim_start_matches("--").to_string();
        if name == "json" || name == "token-stdin" {
            if !cli.flags.insert(name.clone()) { return Err(format!("duplicate option: --{name}")); }
            continue;
        }
        #[cfg(debug_assertions)]
        if name == "ignore-term" {
            if !cli.flags.insert(name.clone()) { return Err(format!("duplicate option: --{name}")); }
            continue;
        }
        let value = args.next().ok_or_else(|| format!("missing value for --{name}"))?;
        if cli.values.insert(name.clone(), value).is_some() {
            return Err(format!("duplicate option: --{name}"));
        }
    }
    Ok(cli)
}

fn validate_options(cli: &Cli, allowed_values: &[&str], allowed_flags: &[&str]) -> Result<(), String> {
    for name in cli.values.keys() {
        if !allowed_values.iter().any(|allowed| name == allowed) {
            return Err(format!("unsupported option for {}: --{}", cli.operation, name));
        }
    }
    for name in &cli.flags {
        if name != "json" && !allowed_flags.iter().any(|allowed| name == allowed) {
            return Err(format!("unsupported flag for {}: --{}", cli.operation, name));
        }
    }
    Ok(())
}

fn required_value<'a>(cli: &'a Cli, name: &str) -> Result<&'a str, String> {
    cli.values.get(name).map(String::as_str).ok_or_else(|| format!("missing --{name}"))
}

fn parse_pids(cli: &Cli) -> Result<BTreeSet<u32>, String> {
    let mut result = BTreeSet::new();
    if let Some(values) = cli.values.get("pids") {
        if values.is_empty() { return Err("--pids cannot be empty".into()); }
        for value in values.split(',') {
            let pid = value.parse::<u32>().map_err(|_| "--pids must contain positive integers")?;
            if pid == 0 { return Err("--pids must contain positive integers".into()); }
            result.insert(pid);
            if result.len() > MAX_PIDS { return Err("too many PIDs requested".into()); }
        }
    }
    Ok(result)
}

fn validate_session_id(value: &str) -> Result<String, String> {
    if value.len() < 8 || value.len() > 128
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("session ID must be 8-128 safe ASCII characters".into());
    }
    Ok(value.to_string())
}

fn validate_token(value: &str) -> Result<String, String> {
    if value.len() < 32 || value.len() > 512
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err("token must be 32-512 safe ASCII characters".into());
    }
    Ok(value.to_string())
}

fn read_secret_stdin() -> Result<String, String> {
    let mut bytes = Vec::new();
    io::stdin().take(514).read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read token from stdin: {error}"))?;
    if bytes.len() > 513 { return Err("stdin token is too large".into()); }
    while bytes.last().is_some_and(|byte| *byte == b'\n' || *byte == b'\r') { bytes.pop(); }
    let value = String::from_utf8(bytes).map_err(|_| "stdin token must be UTF-8")?;
    validate_token(&value)
}

fn token_from_cli(cli: &Cli) -> Result<String, String> {
    let inline = cli.values.get("token");
    let from_stdin = cli.flags.contains("token-stdin");
    if inline.is_some() == from_stdin {
        return Err("provide exactly one of --token or --token-stdin".into());
    }
    match inline { Some(value) => validate_token(value), None => read_secret_stdin() }
}

fn validate_absolute_path(name: &str, value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() { return Err(format!("--{name} must be an absolute Linux path")); }
    if value.as_bytes().contains(&0) || path.components().any(|part| matches!(part, Component::ParentDir)) {
        return Err(format!("--{name} contains an unsafe path component"));
    }
    Ok(path)
}

fn check_not_symlink(path: &Path, allow_missing: bool) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("refusing symbolic link: {}", path.display()))
        }
        Ok(_) => Ok(()),
        Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

fn check_ancestors_not_symlinks(path: &Path, allow_missing: bool) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    let mut current = PathBuf::new();
    let mut missing = false;
    for component in path.components() {
        current.push(component.as_os_str());
        if missing {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "refusing symbolic-link path ancestor: {}", current.display()
                ));
            }
            Ok(metadata) if current != path && !metadata.is_dir() => {
                return Err(format!(
                    "path ancestor is not a directory: {}", current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {
                missing = true;
            }
            Err(error) => {
                return Err(format!("cannot inspect {}: {error}", current.display()));
            }
        }
    }
    Ok(())
}

fn ensure_private_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "path has no parent directory".to_string())?;
    check_ancestors_not_symlinks(parent, true)?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect {}: {error}", parent.display()))?;
    }
    check_ancestors_not_symlinks(parent, false)?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect {}: {error}", parent.display()))?;
    if !metadata.is_dir() || metadata.uid() != current_uid() {
        return Err(format!("state directory is not owned by the current WSL user: {}", parent.display()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!("state directory permissions must exclude group/other users: {}", parent.display()));
    }
    Ok(())
}

fn validate_private_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "path has no parent directory".to_string())?;
    check_ancestors_not_symlinks(parent, false)?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect {}: {error}", parent.display()))?;
    if !metadata.is_dir() || metadata.uid() != current_uid() {
        return Err(format!(
            "state directory is not owned by the current WSL user: {}", parent.display()
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "state directory permissions must exclude group/other users: {}", parent.display()
        ));
    }
    Ok(())
}

fn ensure_log_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "log path has no parent directory".to_string())?;
    check_ancestors_not_symlinks(parent, true)?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    check_ancestors_not_symlinks(parent, false)
}

fn sync_directory(path: &Path) {
    if let Ok(directory) = File::open(path) { let _ = directory.sync_all(); }
}

fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    ensure_private_parent(path)?;
    check_not_symlink(path, true)?;
    if let Ok(existing) = fs::metadata(path) {
        if !existing.is_file() || existing.uid() != current_uid() {
            return Err(format!("refusing to replace foreign/non-file metadata: {}", path.display()));
        }
    }
    let parent = path.parent().unwrap();
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("state");
    let temporary = parent.join(format!(".{name}.{}-{}.tmp", std::process::id(), epoch_nanos()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&temporary).map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
        file.write_all(contents).map_err(|error| format!("cannot write metadata: {error}"))?;
        file.sync_all().map_err(|error| format!("cannot sync metadata: {error}"))?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot protect metadata: {error}"))?;
        fs::rename(&temporary, path).map_err(|error| format!("cannot install metadata: {error}"))?;
        sync_directory(parent);
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

fn open_private_log(path: &Path) -> Result<File, String> {
    ensure_log_parent(path)?;
    check_not_symlink(path, true)?;
    if let Ok(metadata) = fs::metadata(path) {
        if !metadata.is_file() || metadata.uid() != current_uid() {
            return Err(format!("refusing foreign/non-file log target: {}", path.display()));
        }
    }
    let file = OpenOptions::new().create(true).append(true).mode(0o600).open(path)
        .map_err(|error| format!("cannot open log {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot protect log {}: {error}", path.display()))?;
    Ok(file)
}

fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut credentials = PeerCredentials::default();
    let mut length = std::mem::size_of::<PeerCredentials>() as u32;
    // SAFETY: output points to a correctly sized POD and the descriptor stays valid.
    let result = unsafe {
        c_getsockopt(stream.as_raw_fd(), SOL_SOCKET, SO_PEERCRED,
            &mut credentials as *mut PeerCredentials as *mut c_void, &mut length)
    };
    if result != 0 || length < std::mem::size_of::<PeerCredentials>() as u32 {
        return Err(format!("cannot authenticate Unix socket peer: {}", io::Error::last_os_error()));
    }
    Ok(credentials.uid)
}

fn bind_private_socket(path: &Path) -> Result<UnixListener, String> {
    ensure_private_parent(path)?;
    if path.as_os_str().as_bytes().len() > 100 { return Err("Unix socket path is too long".into()); }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket()
                || metadata.uid() != current_uid()
            {
                return Err(format!("refusing unsafe existing socket path: {}", path.display()));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(format!("a live session already owns socket {}", path.display()));
            }
            fs::remove_file(path).map_err(|error| format!("cannot remove stale socket: {error}"))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect socket path: {error}")),
    }
    let listener = UnixListener::bind(path).map_err(|error| format!("cannot bind Unix socket: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot set Unix socket permissions: {error}"))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("cannot inspect Unix socket: {error}"))?;
    if metadata.uid() != current_uid() || metadata.mode() & 0o777 != 0o600 || !metadata.file_type().is_socket() {
        let _ = fs::remove_file(path);
        return Err("Unix socket owner or mode validation failed".into());
    }
    listener.set_nonblocking(true).map_err(|error| format!("cannot configure Unix socket: {error}"))?;
    Ok(listener)
}

fn parse_json_string(bytes: &[u8], index: &mut usize) -> Result<String, String> {
    if bytes.get(*index) != Some(&b'"') { return Err("expected JSON string".into()); }
    *index += 1;
    let mut output = String::new();
    while *index < bytes.len() {
        let byte = bytes[*index];
        *index += 1;
        match byte {
            b'"' => return Ok(output),
            b'\\' => {
                let escaped = *bytes.get(*index).ok_or("truncated JSON escape")?;
                *index += 1;
                match escaped {
                    b'"' => output.push('"'), b'\\' => output.push('\\'), b'/' => output.push('/'),
                    b'b' => output.push('\u{08}'), b'f' => output.push('\u{0c}'),
                    b'n' => output.push('\n'), b'r' => output.push('\r'), b't' => output.push('\t'),
                    b'u' => {
                        let end = *index + 4;
                        let digits = bytes.get(*index..end).ok_or("truncated Unicode escape")?;
                        let text = std::str::from_utf8(digits).map_err(|_| "invalid Unicode escape")?;
                        let value = u32::from_str_radix(text, 16).map_err(|_| "invalid Unicode escape")?;
                        output.push(char::from_u32(value).ok_or("invalid Unicode scalar")?);
                        *index = end;
                    }
                    _ => return Err("invalid JSON escape".into()),
                }
            }
            value if value < 0x20 => return Err("control character in JSON string".into()),
            value if value.is_ascii() => output.push(value as char),
            _ => {
                let start = *index - 1;
                let remaining = std::str::from_utf8(&bytes[start..]).map_err(|_| "invalid UTF-8 in JSON")?;
                let ch = remaining.chars().next().ok_or("invalid UTF-8 in JSON")?;
                output.push(ch);
                *index = start + ch.len_utf8();
            }
        }
    }
    Err("unterminated JSON string".into())
}

fn skip_space(bytes: &[u8], index: &mut usize) {
    while bytes.get(*index).is_some_and(u8::is_ascii_whitespace) { *index += 1; }
}

fn parse_json_number(bytes: &[u8], index: &mut usize) -> Result<JsonValue, String> {
    let start = *index;
    if bytes.get(*index) == Some(&b'-') { *index += 1; }
    match bytes.get(*index) {
        Some(b'0') => *index += 1,
        Some(b'1'..=b'9') => {
            *index += 1;
            while bytes.get(*index).is_some_and(u8::is_ascii_digit) { *index += 1; }
        }
        _ => return Err("invalid JSON number".into()),
    }
    let mut floating = false;
    if bytes.get(*index) == Some(&b'.') {
        floating = true;
        *index += 1;
        let fraction_start = *index;
        while bytes.get(*index).is_some_and(u8::is_ascii_digit) { *index += 1; }
        if *index == fraction_start { return Err("invalid JSON fraction".into()); }
    }
    if matches!(bytes.get(*index), Some(b'e' | b'E')) {
        floating = true;
        *index += 1;
        if matches!(bytes.get(*index), Some(b'+' | b'-')) { *index += 1; }
        let exponent_start = *index;
        while bytes.get(*index).is_some_and(u8::is_ascii_digit) { *index += 1; }
        if *index == exponent_start { return Err("invalid JSON exponent".into()); }
    }
    let text = std::str::from_utf8(&bytes[start..*index]).map_err(|_| "invalid JSON number")?;
    if floating {
        let value = text.parse::<f64>().map_err(|_| "invalid JSON number")?;
        if !value.is_finite() { return Err("non-finite JSON number".into()); }
        Ok(JsonValue::Float(value))
    } else {
        Ok(JsonValue::Number(text.parse().map_err(|_| "invalid JSON integer")?))
    }
}

fn parse_json_value(bytes: &[u8], index: &mut usize, depth: usize) -> Result<JsonValue, String> {
    if depth > 8 { return Err("JSON nesting is too deep".into()); }
    skip_space(bytes, index);
    match bytes.get(*index) {
        Some(b'"') => Ok(JsonValue::String(parse_json_string(bytes, index)?)),
        Some(b'{') => Ok(JsonValue::Object(parse_json_object_at(bytes, index, depth + 1)?)),
        Some(b'-' | b'0'..=b'9') => parse_json_number(bytes, index),
        Some(_) if bytes[*index..].starts_with(b"true") => {
            *index += 4; Ok(JsonValue::Boolean(true))
        }
        Some(_) if bytes[*index..].starts_with(b"false") => {
            *index += 5; Ok(JsonValue::Boolean(false))
        }
        Some(_) if bytes[*index..].starts_with(b"null") => {
            *index += 4; Ok(JsonValue::Null)
        }
        _ => Err("unsupported JSON value".into()),
    }
}

fn parse_json_object_at(bytes: &[u8], index: &mut usize, depth: usize)
    -> Result<BTreeMap<String, JsonValue>, String>
{
    let mut result = BTreeMap::new();
    skip_space(bytes, index);
    if bytes.get(*index) != Some(&b'{') { return Err("expected JSON object".into()); }
    *index += 1;
    loop {
        skip_space(bytes, index);
        if bytes.get(*index) == Some(&b'}') { *index += 1; break; }
        let key = parse_json_string(bytes, index)?;
        skip_space(bytes, index);
        if bytes.get(*index) != Some(&b':') { return Err("expected colon in JSON object".into()); }
        *index += 1;
        let value = parse_json_value(bytes, index, depth)?;
        if result.insert(key, value).is_some() { return Err("duplicate JSON key".into()); }
        skip_space(bytes, index);
        match bytes.get(*index) {
            Some(b',') => {
                *index += 1;
                skip_space(bytes, index);
                if bytes.get(*index) == Some(&b'}') {
                    return Err("trailing comma in JSON object".into());
                }
            }
            Some(b'}') => { *index += 1; break; }
            _ => return Err("expected comma or closing brace in JSON object".into()),
        }
    }
    Ok(result)
}

fn parse_json_object(input: &str) -> Result<BTreeMap<String, JsonValue>, String> {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    skip_space(bytes, &mut index);
    let result = parse_json_object_at(bytes, &mut index, 0)
        .map_err(|error| if error == "expected JSON object" {
            "request must be a JSON object".to_string()
        } else { error })?;
    skip_space(bytes, &mut index);
    if index != bytes.len() { return Err("trailing content after JSON object".into()); }
    Ok(result)
}

fn json_string_field<'a>(object: &'a BTreeMap<String, JsonValue>, name: &str)
    -> Result<&'a str, String>
{
    match object.get(name) {
        Some(JsonValue::String(value)) => Ok(value),
        _ => Err(format!("metadata {name} must be a string")),
    }
}

fn json_integer_field(object: &BTreeMap<String, JsonValue>, name: &str)
    -> Result<i64, String>
{
    match object.get(name) {
        Some(JsonValue::Number(value)) => Ok(*value),
        _ => Err(format!("metadata {name} must be an integer")),
    }
}

fn json_bool_field(object: &BTreeMap<String, JsonValue>, name: &str)
    -> Result<bool, String>
{
    match object.get(name) {
        Some(JsonValue::Boolean(value)) => Ok(*value),
        _ => Err(format!("metadata {name} must be a boolean")),
    }
}

fn json_f64(value: Option<&JsonValue>, name: &str) -> Result<f64, String> {
    let result = match value {
        Some(JsonValue::Float(value)) => *value,
        Some(JsonValue::Number(value)) => *value as f64,
        _ => return Err(format!("metadata {name} must be a number")),
    };
    if !result.is_finite() { return Err(format!("metadata {name} is not finite")); }
    Ok(result)
}

fn read_private_metadata(path: &Path) -> Result<(String, BTreeMap<String, JsonValue>), String> {
    validate_private_parent(path)?;
    check_not_symlink(path, false)?;
    let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path)
        .map_err(|error| format!("cannot open session metadata {}: {error}", path.display()))?;
    let details = file.metadata()
        .map_err(|error| format!("cannot inspect session metadata {}: {error}", path.display()))?;
    if !details.is_file() || details.uid() != current_uid() || details.mode() & 0o777 != 0o600 {
        return Err("session metadata is not a private current-user regular file".into());
    }
    let bytes = read_file_limited(file, MAX_RESPONSE)
        .map_err(|error| format!("cannot read session metadata {}: {error}", path.display()))?;
    let text = String::from_utf8(bytes).map_err(|_| "session metadata must be UTF-8")?;
    let object = parse_json_object(text.trim())
        .map_err(|error| format!("invalid session metadata: {error}"))?;
    Ok((text.trim().to_string(), object))
}

fn offline_session_result(metadata_path: &Path, socket: &Path, token: &str)
    -> Result<String, String>
{
    let (text, object) = read_private_metadata(metadata_path)?;
    if !json_bool_field(&object, "ok")? {
        return Err("session metadata does not describe a successful session".into());
    }
    if json_integer_field(&object, "protocolVersion")? != PROTOCOL_VERSION as i64 {
        return Err("session metadata protocol version mismatch".into());
    }
    let session_id = json_string_field(&object, "sessionId")?;
    validate_session_id(session_id)?;
    let metadata_boot = json_string_field(&object, "bootId")?;
    let current_boot = boot_id()?;
    if !constant_time_eq(metadata_boot.as_bytes(), current_boot.as_bytes()) {
        return Err("session metadata belongs to a different distribution boot".into());
    }
    if json_integer_field(&object, "uid")? != current_uid() as i64 {
        return Err("session metadata belongs to a different WSL user".into());
    }
    for name in ["supervisorPid", "pid", "pgid", "startTicks"] {
        if json_integer_field(&object, name)? <= 0 {
            return Err(format!("session metadata {name} must be positive"));
        }
    }
    let socket_text = socket.to_string_lossy();
    if json_string_field(&object, "socket")? != socket_text.as_ref() {
        return Err("session metadata socket identity does not match --socket".into());
    }
    let metadata_text = metadata_path.to_string_lossy();
    if json_string_field(&object, "metadata")? != metadata_text.as_ref() {
        return Err("session metadata path identity does not match --metadata".into());
    }
    let expected_hash = sha256_bytes(token.as_bytes());
    let stored_hash = json_string_field(&object, "tokenHash")?;
    if stored_hash.len() != 64 || !stored_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !constant_time_eq(stored_hash.as_bytes(), expected_hash.as_bytes())
    {
        return Err("session metadata token authentication failed".into());
    }
    let state = json_string_field(&object, "state")?;
    let running = json_bool_field(&object, "running")?;
    if running || state != "exited" {
        return Err("session control unavailable while metadata still reports running".into());
    }
    let exit = match object.get("exit") {
        Some(JsonValue::Object(value)) => value,
        _ => return Err("final session metadata has no exit record".into()),
    };
    if !matches!(json_string_field(exit, "status")?, "succeeded" | "canceled" | "failed" | "stopped") {
        return Err("final session metadata has an invalid exit status".into());
    }
    for name in ["code", "signal"] {
        if !matches!(exit.get(name), Some(JsonValue::Number(_)) | Some(JsonValue::Null)) {
            return Err(format!("final session metadata exit.{name} is invalid"));
        }
    }
    if json_f64(exit.get("at"), "exit.at")? < 0.0
        || json_f64(exit.get("durationSec"), "exit.durationSec")? < 0.0
    {
        return Err("final session metadata contains a negative exit time".into());
    }
    Ok(text)
}

fn read_socket_line(stream: &mut UnixStream, limit: u64) -> Result<String, String> {
    let mut bytes = Vec::new();
    BufReader::new(stream).take(limit + 1).read_until(b'\n', &mut bytes)
        .map_err(|error| format!("cannot read Unix socket: {error}"))?;
    if bytes.len() as u64 > limit { return Err("Unix socket message is too large".into()); }
    while bytes.last().is_some_and(|byte| *byte == b'\n' || *byte == b'\r') { bytes.pop(); }
    if bytes.is_empty() { return Err("Unix socket message is empty".into()); }
    String::from_utf8(bytes).map_err(|_| "Unix socket message must be UTF-8".into())
}

fn request_fields(input: &str) -> Result<(String, String, u64), String> {
    let mut object = parse_json_object(input)?;
    let action = match object.remove("action") {
        Some(JsonValue::String(value)) => value,
        _ => return Err("request action must be a string".into()),
    };
    let token = match object.remove("token") {
        Some(JsonValue::String(value)) => validate_token(&value)?,
        _ => return Err("request token must be a string".into()),
    };
    let timeout_ms = match object.remove("timeoutMs") {
        Some(JsonValue::Number(value)) if (0..=30_000).contains(&value) => value as u64,
        Some(_) => return Err("timeoutMs must be an integer from 0 through 30000".into()),
        None => 5_000,
    };
    if let Some(version) = object.remove("protocolVersion") {
        if !matches!(version, JsonValue::Number(value) if value == PROTOCOL_VERSION as i64) {
            return Err("control protocol version mismatch".into());
        }
    }
    if !object.is_empty() { return Err("unknown control request field".into()); }
    if !matches!(action.as_str(), "status" | "stop" | "force-stop") {
        return Err("unsupported session action".into());
    }
    Ok((action, token, timeout_ms))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() { return false; }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) { difference |= a ^ b; }
    difference == 0
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bytes: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buffer: [0; 64], buffer_len: 0, length_bytes: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length_bytes = self.length_bytes.saturating_add(data.len() as u64);
        if self.buffer_len > 0 {
            let count = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + count].copy_from_slice(&data[..count]);
            self.buffer_len += count;
            data = &data[count..];
            if self.buffer_len == 64 {
                let block = self.buffer; self.compress(&block); self.buffer_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64]; block.copy_from_slice(&data[..64]);
            self.compress(&block); data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data); self.buffer_len = data.len();
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index-15].rotate_right(7) ^ words[index-15].rotate_right(18) ^ (words[index-15] >> 3);
            let s1 = words[index-2].rotate_right(17) ^ words[index-2].rotate_right(19) ^ (words[index-2] >> 10);
            words[index] = words[index-16].wrapping_add(s0).wrapping_add(words[index-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h] = self.state;
        for index in 0..64 {
            let upper_e = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(upper_e).wrapping_add(choice).wrapping_add(K[index]).wrapping_add(words[index]);
            let upper_a = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = upper_a.wrapping_add(majority);
            h=g; g=f; f=e; e=d.wrapping_add(temp1); d=c; c=b; b=a; a=temp1.wrapping_add(temp2);
        }
        for (slot,value) in self.state.iter_mut().zip([a,b,c,d,e,f,g,h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.length_bytes.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80; self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer; self.compress(&block);
            self.buffer = [0;64]; self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer; self.compress(&block);
        let mut output = [0u8;32];
        for (index,value) in self.state.iter().enumerate() {
            output[index*4..index*4+4].copy_from_slice(&value.to_be_bytes());
        }
        output
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len()*2);
    for byte in bytes { output.push_str(&format!("{byte:02x}")); }
    output
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new(); digest.update(bytes); hex_bytes(&digest.finalize())
}

fn sha256_reader(mut reader: impl Read) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64*1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer).map_err(|error| format!("cannot read helper binary: {error}"))?;
        if count == 0 { break; }
        total += count as u64;
        if total > MAX_INSTALL_SIZE { return Err("helper binary exceeds the installation size limit".into()); }
        digest.update(&buffer[..count]);
    }
    Ok(hex_bytes(&digest.finalize()))
}

fn current_executable_sha256() -> Result<String, String> {
    // /proc/self/exe opens the inode that this process is actually executing,
    // even if the launch path is renamed or replaced after exec.  Hashing a
    // reconstructed argv/current_exe path would attest the path, not this
    // running helper.
    let executable = File::open("/proc/self/exe")
        .map_err(|error| format!("cannot open the running helper executable: {error}"))?;
    sha256_reader(executable)
}

fn install_helper(cli: &Cli) -> Result<String, String> {
    validate_options(cli, &["target", "sha256"], &[])?;
    let target = validate_absolute_path("target", required_value(cli, "target")?)?;
    let expected = required_value(cli, "sha256")?.to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--sha256 must be a 64-character hexadecimal SHA-256".into());
    }
    ensure_private_parent(&target)?;
    check_not_symlink(&target, true)?;
    if let Ok(metadata) = fs::metadata(&target) {
        if !metadata.is_file() || metadata.uid() != current_uid() {
            return Err(format!("refusing to replace foreign/non-file target: {}", target.display()));
        }
    }
    let source_path = env::current_exe().map_err(|error| format!("cannot locate running helper: {error}"))?;
    let source = File::open(&source_path).map_err(|error| format!("cannot open running helper: {error}"))?;
    let parent = target.parent().unwrap();
    let name = target.file_name().and_then(OsStr::to_str).ok_or("target filename is invalid UTF-8")?;
    let temporary = parent.join(format!(".{name}.install-{}-{}.tmp", std::process::id(), epoch_nanos()));
    let result = (|| -> Result<String, String> {
        let mut input = source;
        let mut output = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&temporary).map_err(|error| format!("cannot create install temporary file: {error}"))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64*1024];
        let mut total = 0u64;
        loop {
            let count = input.read(&mut buffer).map_err(|error| format!("cannot read running helper: {error}"))?;
            if count == 0 { break; }
            total += count as u64;
            if total > MAX_INSTALL_SIZE { return Err("helper binary exceeds the installation size limit".into()); }
            digest.update(&buffer[..count]);
            output.write_all(&buffer[..count]).map_err(|error| format!("cannot copy helper: {error}"))?;
        }
        output.sync_all().map_err(|error| format!("cannot sync installed helper: {error}"))?;
        let copied_hash = hex_bytes(&digest.finalize());
        if !constant_time_eq(copied_hash.as_bytes(), expected.as_bytes()) {
            return Err("running helper SHA-256 does not match --sha256".into());
        }
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot set installed helper mode 0700: {error}"))?;
        let reread = sha256_reader(File::open(&temporary)
            .map_err(|error| format!("cannot reopen installed helper: {error}"))?)?;
        if !constant_time_eq(reread.as_bytes(), expected.as_bytes()) {
            return Err("installed helper failed read-back SHA-256 verification".into());
        }
        fs::rename(&temporary, &target).map_err(|error| format!("cannot atomically install helper: {error}"))?;
        sync_directory(parent);
        let installed = sha256_reader(File::open(&target)
            .map_err(|error| format!("cannot verify final helper: {error}"))?)?;
        if !constant_time_eq(installed.as_bytes(), expected.as_bytes()) {
            return Err("final installed helper failed SHA-256 verification".into());
        }
        Ok(installed)
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    let installed = result?;
    Ok(format!(
        "{{\"ok\":true,\"protocolVersion\":{PROTOCOL_VERSION},\"version\":{},\"target\":{},\"installedSha256\":{},\"mode\":\"0700\"}}",
        json_string(HELPER_VERSION), json_string(&target.to_string_lossy()), json_string(&installed)
    ))
}

fn exit_json(exit: Option<&ExitRecord>) -> String {
    match exit {
        Some(value) => format!(
            "{{\"status\":{},\"code\":{},\"signal\":{},\"at\":{:.6},\"durationSec\":{:.3}}}",
            json_string(&value.status),
            value.code.map(|code| code.to_string()).unwrap_or_else(|| "null".into()),
            value.signal.map(|signal| signal.to_string()).unwrap_or_else(|| "null".into()),
            value.at, value.duration_sec,
        ),
        None => "null".into(),
    }
}

fn metadata_json(record: &SessionRecord, state: &str, exit: Option<&ExitRecord>, ok: bool, error: Option<&str>) -> String {
    format!(
        concat!(
            "{{\"ok\":{ok},\"protocolVersion\":{protocol},\"version\":{version},",
            "\"sessionId\":{session_id},\"bootId\":{boot_id},\"uid\":{uid},",
            "\"supervisorPid\":{supervisor_pid},\"pid\":{pid},\"pgid\":{pgid},",
            "\"startTicks\":{start_ticks},\"socket\":{socket},\"metadata\":{metadata},",
            "\"log\":{log},\"cwd\":{cwd},\"kind\":{kind},",
            "\"commandHash\":{command_hash},\"tokenHash\":{token_hash},",
            "\"startedAt\":{started_at:.6},\"state\":{state},\"running\":{running},",
            "\"requiresForce\":false,\"exit\":{exit_json},",
            "\"error\":{error}}}"
        ),
        ok=if ok{"true"}else{"false"}, protocol=PROTOCOL_VERSION,
        version=json_string(HELPER_VERSION), session_id=json_string(&record.session_id),
        boot_id=json_string(&record.boot_id), uid=record.uid,
        supervisor_pid=record.supervisor_pid, pid=record.pid, pgid=record.pgid,
        start_ticks=record.start_ticks, socket=json_string(&record.socket.to_string_lossy()),
        metadata=json_string(&record.metadata.to_string_lossy()),
        log=json_string(&record.log.to_string_lossy()),
        cwd=record.cwd.as_ref().map(|path|json_string(&path.to_string_lossy())).unwrap_or_else(||"null".into()),
        kind=json_string(&record.kind), command_hash=json_string(&record.command_hash),
        token_hash=json_string(&record.token_hash), started_at=record.started_at,
        state=json_string(state),running=if state=="running"{"true"}else{"false"},
        exit_json=exit_json(exit),
        error=error.map(json_string).unwrap_or_else(||"null".into()),
    )
}

fn public_session_json(record: &SessionRecord, state: &str, exit: Option<&ExitRecord>, ok: bool,
                       error: Option<&str>, requires_force: bool) -> String {
    format!(
        concat!(
            "{{\"ok\":{ok},\"protocolVersion\":{protocol},\"version\":{version},",
            "\"sessionId\":{session_id},\"bootId\":{boot_id},\"uid\":{uid},",
            "\"supervisorPid\":{supervisor_pid},\"pid\":{pid},\"pgid\":{pgid},",
            "\"startTicks\":{start_ticks},\"socket\":{socket},\"metadata\":{metadata},",
            "\"log\":{log},\"kind\":{kind},\"startedAt\":{started_at:.6},",
            "\"state\":{state},\"running\":{running},\"tokenHash\":{token_hash},",
            "\"requiresForce\":{requires_force},\"exit\":{exit_json},",
            "\"error\":{error}}}"
        ),
        ok=if ok{"true"}else{"false"}, protocol=PROTOCOL_VERSION,
        version=json_string(HELPER_VERSION), session_id=json_string(&record.session_id),
        boot_id=json_string(&record.boot_id), uid=record.uid,
        supervisor_pid=record.supervisor_pid, pid=record.pid, pgid=record.pgid,
        start_ticks=record.start_ticks, socket=json_string(&record.socket.to_string_lossy()),
        metadata=json_string(&record.metadata.to_string_lossy()),
        log=json_string(&record.log.to_string_lossy()), kind=json_string(&record.kind),
        started_at=record.started_at, state=json_string(state),
        running=if state=="running"{"true"}else{"false"},token_hash=json_string(&record.token_hash),
        requires_force=if requires_force{"true"}else{"false"}, exit_json=exit_json(exit),
        error=error.map(json_string).unwrap_or_else(||"null".into()),
    )
}

fn write_metadata(record: &SessionRecord, state: &str, exit: Option<&ExitRecord>, ok: bool,
                  error: Option<&str>) -> Result<(), String> {
    atomic_write_private(&record.metadata, metadata_json(record,state,exit,ok,error).as_bytes())
}

fn validate_sha256_option(name: &str, value: &str) -> Result<String, String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("--{name} must be a 64-character hexadecimal SHA-256"));
    }
    Ok(normalized)
}

fn capture_process_fingerprint(pid: u32) -> Result<ProcessFingerprint, String> {
    if pid <= 1 || pid == std::process::id() {
        return Err("refusing unsafe or helper-owned PID".into());
    }
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let metadata = fs::metadata(&proc_path)
        .map_err(|_| "process no longer exists".to_string())?;
    if metadata.uid() != current_uid() {
        return Err("process is not owned by the current WSL user".into());
    }
    let stat = proc_stat(pid).ok_or_else(|| "cannot read process start identity".to_string())?;
    let cwd = fs::read_link(proc_path.join("cwd"))
        .map_err(|_| "cannot read exact process working directory".to_string())?;
    let command = read_limited(proc_path.join("cmdline"), MAX_CMDLINE)
        .map_err(|_| "cannot read exact process command line".to_string())?;
    Ok(ProcessFingerprint {
        pid,
        uid: metadata.uid(),
        boot_id: boot_id()?,
        start_ticks: stat.start_ticks,
        cwd_hash: sha256_bytes(cwd.as_os_str().as_bytes()),
        command_hash: sha256_bytes(&command),
    })
}

fn fingerprint_matches(actual: &ProcessFingerprint, expected: &ProcessFingerprint) -> bool {
    actual.pid == expected.pid
        && actual.uid == expected.uid
        && actual.start_ticks == expected.start_ticks
        && constant_time_eq(actual.boot_id.as_bytes(), expected.boot_id.as_bytes())
        && constant_time_eq(actual.cwd_hash.as_bytes(), expected.cwd_hash.as_bytes())
        && constant_time_eq(actual.command_hash.as_bytes(), expected.command_hash.as_bytes())
}

fn open_verified_pidfd(expected: &ProcessFingerprint) -> Result<OwnedFd, String> {
    let pid = c_int::try_from(expected.pid).map_err(|_| "process PID is out of range")?;
    // SAFETY: x86_64 Linux pidfd_open takes a numeric PID and zero flags. The
    // resulting descriptor pins that exact process across later PID reuse.
    let descriptor = unsafe { c_syscall(SYS_PIDFD_OPEN_X86_64, pid, 0 as c_uint) };
    if descriptor < 0 {
        return Err(format!(
            "cannot open a PID-safe process handle; no signal was sent: {}",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: a successful pidfd_open returns a newly owned descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as c_int) };
    let actual = capture_process_fingerprint(expected.pid)?;
    if !fingerprint_matches(&actual, expected) {
        return Err("process identity does not exactly match the supplied instance identity".into());
    }
    Ok(descriptor)
}

fn signal_pidfd(descriptor: &OwnedFd, signal: c_int) -> Result<(), String> {
    // SAFETY: pidfd_send_signal receives an owned pidfd, a fixed signal, no
    // siginfo pointer, and zero flags. It cannot target a reused PID.
    let result = unsafe {
        c_syscall(
            SYS_PIDFD_SEND_SIGNAL_X86_64,
            descriptor.as_raw_fd(),
            signal,
            std::ptr::null::<c_void>(),
            0 as c_uint,
        )
    };
    if result != 0 {
        return Err(format!("cannot signal verified process handle: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn capture_session_supervisor_identity(pid: u32) -> Result<SessionSupervisorIdentity, String> {
    if pid <= 1 {
        return Err("refusing unsafe detached session helper PID".into());
    }
    let uid = current_uid();
    let first_details = fs::metadata(format!("/proc/{pid}"))
        .map_err(|error| format!("cannot inspect detached session helper {pid}: {error}"))?;
    let first_stat = strict_proc_stat(pid)?
        .ok_or_else(|| "cannot read detached session helper identity".to_string())?;
    if first_details.uid() != uid || first_stat.state == 'Z'
        || first_stat.sid != pid || first_stat.pgid != pid
    {
        return Err("detached session helper is not the live current-user session leader".into());
    }
    let numeric_pid = c_int::try_from(pid)
        .map_err(|_| "detached session helper PID is out of range")?;
    // SAFETY: pidfd_open pins the exact session leader across later PID reuse.
    let descriptor = unsafe { c_syscall(SYS_PIDFD_OPEN_X86_64, numeric_pid, 0 as c_uint) };
    if descriptor < 0 {
        return Err(format!(
            "cannot pin detached session helper identity with pidfd: {}",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: a successful pidfd_open returns a newly owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as c_int) };
    let second_details = fs::metadata(format!("/proc/{pid}"))
        .map_err(|_| "detached session helper exited while its identity was pinned".to_string())?;
    let second_stat = strict_proc_stat(pid)?
        .ok_or_else(|| "detached session helper exited while its identity was pinned".to_string())?;
    if second_details.uid() != uid || second_stat.state == 'Z'
        || second_stat.sid != pid || second_stat.pgid != pid
        || second_stat.start_ticks != first_stat.start_ticks
    {
        return Err("detached session helper identity changed while it was pinned".into());
    }
    Ok(SessionSupervisorIdentity {
        pid,
        uid,
        start_ticks: first_stat.start_ticks,
        pidfd,
    })
}

fn validate_session_supervisor_if_present(
    identity: &SessionSupervisorIdentity,
) -> Result<bool, String> {
    let Some(stat) = strict_proc_stat(identity.pid)? else { return Ok(false); };
    let details = match fs::metadata(format!("/proc/{}", identity.pid)) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!(
            "cannot revalidate detached session helper {}: {error}", identity.pid,
        )),
    };
    if details.uid() != identity.uid || stat.start_ticks != identity.start_ticks
        || stat.sid != identity.pid || stat.pgid != identity.pid
    {
        return Err("detached session helper PID no longer has the pinned UID/SID/start-time identity".into());
    }
    Ok(stat.state != 'Z')
}

fn exact_session_members(
    identity: &SessionSupervisorIdentity,
) -> Result<Vec<SessionMemberIdentity>, String> {
    if current_uid() != identity.uid {
        return Err("WSL user identity changed during exact session cleanup".into());
    }
    // If the numeric leader PID is present, it must still be the exact process
    // pinned at spawn. The held pidfd prevents reuse after the leader exits.
    let _ = validate_session_supervisor_if_present(identity)?;
    let entries = fs::read_dir("/proc")
        .map_err(|error| format!("cannot enumerate exact Linux session: {error}"))?;
    let mut members = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot enumerate exact Linux session entry: {error}"))?;
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else { continue; };
        let Some(stat) = strict_proc_stat(pid)? else { continue; };
        if stat.sid != identity.pid || stat.state == 'Z' { continue; }
        let details = match fs::metadata(format!("/proc/{pid}")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot validate exact session member {pid}: {error}")),
        };
        if details.uid() != identity.uid {
            return Err(format!(
                "exact Linux session {} contains foreign-UID process {pid}", identity.pid,
            ));
        }
        if stat.pgid <= 1 {
            return Err(format!("exact Linux session member {pid} has an unsafe PGID"));
        }
        if pid == identity.pid
            && (stat.start_ticks != identity.start_ticks || stat.pgid != identity.pid)
        {
            return Err("detached session helper identity changed during cleanup".into());
        }
        members.push(SessionMemberIdentity {
            pid,
            uid: details.uid(),
            pgid: stat.pgid,
            sid: stat.sid,
            start_ticks: stat.start_ticks,
        });
        if members.len() > MAX_PIDS {
            return Err("exact Linux session exceeds the safe member limit".into());
        }
    }
    members.sort_unstable_by_key(|member| member.pid);
    Ok(members)
}

fn open_verified_session_member(
    expected: &SessionMemberIdentity,
) -> Result<Option<OwnedFd>, String> {
    let pid = c_int::try_from(expected.pid)
        .map_err(|_| "exact session member PID is out of range")?;
    // SAFETY: pidfd_open pins this enumerated member before any signal is sent.
    let descriptor = unsafe { c_syscall(SYS_PIDFD_OPEN_X86_64, pid, 0 as c_uint) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ESRCH) { return Ok(None); }
        return Err(format!("cannot pin exact session member {}: {error}", expected.pid));
    }
    // SAFETY: a successful pidfd_open returns a newly owned descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as c_int) };
    let Some(stat) = strict_proc_stat(expected.pid)? else { return Ok(None); };
    let details = match fs::metadata(format!("/proc/{}", expected.pid)) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!(
            "cannot revalidate exact session member {}: {error}", expected.pid,
        )),
    };
    if stat.state == 'Z' { return Ok(None); }
    if details.uid() != expected.uid || stat.start_ticks != expected.start_ticks
        || stat.sid != expected.sid || stat.pgid != expected.pgid
    {
        return Err(format!(
            "exact session member {} changed UID/SID/PGID/start-time before cleanup",
            expected.pid,
        ));
    }
    Ok(Some(descriptor))
}

fn signal_pidfd_allow_exited(descriptor: &OwnedFd, signal: c_int) -> Result<(), String> {
    // SAFETY: the descriptor pins the exact process and no siginfo is supplied.
    let result = unsafe {
        c_syscall(
            SYS_PIDFD_SEND_SIGNAL_X86_64,
            descriptor.as_raw_fd(),
            signal,
            std::ptr::null::<c_void>(),
            0 as c_uint,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ESRCH) { return Ok(()); }
        return Err(format!("cannot signal exact session member with signal {signal}: {error}"));
    }
    Ok(())
}

fn signal_exact_session_snapshot(
    identity: &SessionSupervisorIdentity,
    excluded_pid: Option<u32>,
    signal: c_int,
) -> Result<usize, String> {
    let targets: Vec<SessionMemberIdentity> = exact_session_members(identity)?
        .into_iter()
        .filter(|member| Some(member.pid) != excluded_pid)
        .collect();
    if targets.is_empty() { return Ok(0); }

    // Pin and revalidate the entire snapshot before signalling any member. If
    // one PID crossed an identity boundary, the operation fails without a
    // partial signal fan-out. A member that has already exited is harmless.
    let mut handles = Vec::new();
    let mut leader_present = false;
    for member in &targets {
        if member.pid == identity.pid {
            leader_present = true;
        } else if let Some(handle) = open_verified_session_member(member)? {
            handles.push(handle);
        }
    }
    if leader_present {
        let _ = validate_session_supervisor_if_present(identity)?;
    }
    for handle in &handles {
        signal_pidfd_allow_exited(handle, signal)?;
    }
    // Startup rollback may include session-run itself. Keep its spawn-pinned
    // session leader alive until every other exact member has been signalled.
    if leader_present {
        signal_pidfd_allow_exited(&identity.pidfd, signal)?;
    }
    Ok(targets.len())
}

fn force_signal_exact_session_members_until(
    identity: &SessionSupervisorIdentity,
    excluded_pid: Option<u32>,
    timeout: Duration,
) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if signal_exact_session_snapshot(identity, excluded_pid, SIGKILL)? == 0 {
            return Ok(true);
        }

        if Instant::now() >= deadline {
            let remaining = exact_session_members(identity)?
                .into_iter()
                .filter(|member| Some(member.pid) != excluded_pid)
                .collect::<Vec<_>>();
            return Ok(remaining.is_empty());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn force_kill_exact_session_members(
    identity: &SessionSupervisorIdentity,
    excluded_pid: Option<u32>,
    timeout: Duration,
) -> Result<(), String> {
    if force_signal_exact_session_members_until(identity, excluded_pid, timeout)? {
        return Ok(());
    }
    let remaining = exact_session_members(identity)?
        .into_iter()
        .filter(|member| Some(member.pid) != excluded_pid)
        .map(|member| format!("{}/pgid{}", member.pid, member.pgid))
        .collect::<Vec<_>>();
    if remaining.is_empty() { return Ok(()); }
    Err(format!(
        "SIGKILL did not empty exact SID {} before timeout; remaining {}",
        identity.pid, remaining.join(","),
    ))
}

fn session_owned_members(
    record: &SessionRecord,
    identity: &SessionSupervisorIdentity,
) -> Result<Vec<SessionMemberIdentity>, String> {
    if current_uid() != record.uid || identity.uid != record.uid {
        return Err("WSL user identity changed while controlling the session".into());
    }
    if boot_id()? != record.boot_id {
        return Err("distribution boot ID changed while controlling the session".into());
    }
    if record.supervisor_pid != identity.pid {
        return Err("session metadata does not match the pinned supervisor identity".into());
    }
    Ok(exact_session_members(identity)?
        .into_iter()
        .filter(|member| member.pid != identity.pid)
        .collect())
}

fn session_members_running(
    record: &SessionRecord,
    identity: &SessionSupervisorIdentity,
) -> Result<bool, String> {
    Ok(!session_owned_members(record, identity)?.is_empty())
}

fn signal_session_members(
    record: &SessionRecord,
    identity: &SessionSupervisorIdentity,
    signal: c_int,
) -> Result<(), String> {
    // Validate the durable boot/UID/supervisor binding before opening pidfds.
    let _ = session_owned_members(record, identity)?;
    let _ = signal_exact_session_snapshot(identity, Some(identity.pid), signal)?;
    Ok(())
}

fn process_still_matches(expected: &ProcessFingerprint) -> Result<bool, String> {
    match capture_process_fingerprint(expected.pid) {
        Ok(actual) => Ok(fingerprint_matches(&actual, expected)),
        Err(error) if error == "process no longer exists" => Ok(false),
        // A different identity at the same PID means the original target has
        // exited. It must never receive a follow-up signal.
        Err(error) if error.contains("not owned") || error.contains("cannot read exact")
            || error.contains("cannot read process start") => Ok(false),
        Err(error) => Err(error),
    }
}

fn wait_for_verified_process_exit(expected: &ProcessFingerprint, timeout_ms: u64) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if !process_still_matches(expected)? { return Ok(true); }
        if Instant::now() >= deadline { return Ok(false); }
        thread::sleep(Duration::from_millis(20));
    }
}

fn process_control_json(expected: &ProcessFingerprint, ok: bool, running: bool,
                        requires_force: bool, error: Option<&str>) -> String {
    format!(
        concat!(
            "{{\"ok\":{ok},\"protocolVersion\":{protocol},\"actionScope\":\"exact-process\",",
            "\"bootId\":{boot_id},\"pid\":{pid},\"uid\":{uid},\"startTicks\":{start_ticks},",
            "\"cwdHash\":{cwd_hash},\"commandHash\":{command_hash},",
            "\"state\":{state},\"running\":{running},\"requiresForce\":{requires_force},",
            "\"exit\":null,\"error\":{error}}}"
        ),
        ok=if ok{"true"}else{"false"}, protocol=PROTOCOL_VERSION,
        boot_id=json_string(&expected.boot_id), pid=expected.pid, uid=expected.uid,
        start_ticks=expected.start_ticks, cwd_hash=json_string(&expected.cwd_hash),
        command_hash=json_string(&expected.command_hash),
        state=json_string(if running{"running"}else{"exited"}),
        running=if running{"true"}else{"false"},
        requires_force=if requires_force{"true"}else{"false"},
        error=error.map(json_string).unwrap_or_else(||"null".into()),
    )
}

fn process_control(cli: &Cli) -> Result<String, String> {
    validate_options(
        cli,
        &["action", "pid", "uid", "boot-id", "start-ticks", "cwd-hash", "command-hash", "timeout-ms"],
        &[],
    )?;
    let action = required_value(cli, "action")?;
    if !matches!(action, "stop" | "force-stop") {
        return Err("--action must be stop or force-stop".into());
    }
    let pid = required_value(cli, "pid")?.parse::<u32>().map_err(|_| "--pid must be a positive integer")?;
    let uid = required_value(cli, "uid")?.parse::<u32>().map_err(|_| "--uid must be an unsigned integer")?;
    if uid != current_uid() { return Err("--uid is not the current WSL user".into()); }
    let expected = ProcessFingerprint {
        pid,
        uid,
        boot_id: required_value(cli, "boot-id")?.to_string(),
        start_ticks: required_value(cli, "start-ticks")?.parse::<u64>()
            .map_err(|_| "--start-ticks must be an unsigned integer")?,
        cwd_hash: validate_sha256_option("cwd-hash", required_value(cli, "cwd-hash")?)?,
        command_hash: validate_sha256_option("command-hash", required_value(cli, "command-hash")?)?,
    };
    if expected.boot_id != boot_id()? { return Err("--boot-id does not match this distribution boot".into()); }
    let timeout_ms = cli.values.get("timeout-ms")
        .map(|value| value.parse::<u64>().map_err(|_| "--timeout-ms must be an integer".to_string()))
        .transpose()?.unwrap_or(5_000);
    if timeout_ms > 30_000 { return Err("--timeout-ms must not exceed 30000".into()); }
    let descriptor = open_verified_pidfd(&expected)?;
    let signal = if action == "stop" { SIGTERM } else { SIGKILL };
    signal_pidfd(&descriptor, signal)?;
    let exited = wait_for_verified_process_exit(&expected, if signal == SIGKILL { timeout_ms.max(1_000) } else { timeout_ms })?;
    if exited {
        Ok(process_control_json(&expected, true, false, false, None))
    } else if signal == SIGTERM {
        Ok(process_control_json(
            &expected, false, true, true, Some("process did not exit after SIGTERM")))
    } else {
        Ok(process_control_json(
            &expected, false, true, false, Some("SIGKILL has not completed")))
    }
}

fn exit_record(status: ExitStatus, record: &SessionRecord, stopped: bool) -> ExitRecord {
    let code=status.code(); let signal=status.signal();
    let label=if stopped{"stopped"}else if code==Some(0){"succeeded"}
        else if code==Some(130){"canceled"}else{"failed"};
    let at=epoch_seconds();
    ExitRecord{status:label.into(),code,signal,at,duration_sec:(at-record.started_at).max(0.0)}
}

fn poll_session_child(child: &mut Child, child_status: &mut Option<ExitStatus>) -> Result<(), String> {
    if child_status.is_none() {
        *child_status = child.try_wait()
            .map_err(|error| format!("cannot query session child: {error}"))?;
    }
    Ok(())
}

fn wait_for_session_members_exit(
    child: &mut Child,
    child_status: &mut Option<ExitStatus>,
    record: &SessionRecord,
    identity: &SessionSupervisorIdentity,
    timeout_ms: u64,
) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        poll_session_child(child, child_status)?;
        if !session_members_running(record, identity)? { return Ok(true); }
        if Instant::now() >= deadline { return Ok(false); }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_session_child_reap(
    child: &mut Child,
    child_status: &mut Option<ExitStatus>,
    timeout: Duration,
) -> Result<(), String> {
    if child_status.is_some() { return Ok(()); }
    let deadline = Instant::now() + timeout;
    loop {
        poll_session_child(child, child_status)?;
        if child_status.is_some() { return Ok(()); }
        if Instant::now() >= deadline {
            return Err("session child was not reaped before cleanup timeout".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn completed_session_response(
    record: &SessionRecord,
    child_status: &mut Option<ExitStatus>,
    stopped: bool,
) -> Result<String, String> {
    let status = child_status.take()
        .ok_or_else(|| "session descendants exited before the root status was available".to_string())?;
    let exit = exit_record(status, record, stopped);
    write_metadata(record, "exited", Some(&exit), true, None)?;
    Ok(public_session_json(record, "exited", Some(&exit), true, None, false))
}

fn handle_session_request(stream: &mut UnixStream, record: &SessionRecord,
                          identity: &SessionSupervisorIdentity,
                          child: &mut Child, child_status: &mut Option<ExitStatus>) -> Result<bool,String> {
    stream.set_read_timeout(Some(Duration::from_secs(35))).map_err(|error|error.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|error|error.to_string())?;
    if peer_uid(stream)? != current_uid() { return Err("Unix socket peer UID is not the session owner".into()); }
    let request=read_socket_line(stream,MAX_REQUEST)?;
    let (action,token,timeout_ms)=request_fields(&request)?;
    let supplied_hash=sha256_bytes(token.as_bytes());
    if !constant_time_eq(supplied_hash.as_bytes(),record.token_hash.as_bytes()) {
        return Err("session token authentication failed".into());
    }
    let (response,should_exit)=match action.as_str() {
        "status"=>{
            poll_session_child(child, child_status)?;
            if session_members_running(record, identity)? {
                (public_session_json(record,"running",None,true,None,false),false)
            } else {
                (completed_session_response(record, child_status, false)?, true)
            }
        }
        "stop"=>{
            poll_session_child(child, child_status)?;
            if !session_members_running(record, identity)? {
                (completed_session_response(record, child_status, false)?, true)
            } else {
                signal_session_members(record,identity,SIGTERM)?;
                if wait_for_session_members_exit(
                    child,child_status,record,identity,timeout_ms,
                )? {
                    (completed_session_response(record, child_status, true)?, true)
                } else {
                    (public_session_json(record,"running",None,false,
                        Some("session did not exit after SIGTERM"),true),false)
                }
            }
        }
        "force-stop"=>{
            poll_session_child(child, child_status)?;
            if !session_members_running(record, identity)? {
                (completed_session_response(record, child_status, false)?, true)
            } else {
                // Keep session-run alive so it can publish and return the final
                // authenticated result, but kill every other exact SID member.
                let _ = session_owned_members(record, identity)?;
                let killed = force_signal_exact_session_members_until(
                    identity, Some(identity.pid),
                    Duration::from_millis(timeout_ms.max(1_000)),
                )?;
                if killed && wait_for_session_members_exit(
                    child,child_status,record,identity,timeout_ms.max(1_000),
                )? {
                    (completed_session_response(record, child_status, true)?, true)
                } else {
                    (public_session_json(record,"running",None,false,
                        Some("SIGKILL has not completed"),false),false)
                }
            }
        }
        _=>unreachable!(),
    };
    stream.write_all(response.as_bytes()).map_err(|error|format!("cannot write Unix socket: {error}"))?;
    stream.write_all(b"\n").map_err(|error|format!("cannot write Unix socket: {error}"))?;
    Ok(should_exit)
}

fn current_user_group_has_other_members(pgid: u32, own_pid: u32) -> Result<bool, String> {
    let own_stat = proc_stat(own_pid)
        .ok_or_else(|| "cannot validate command process-group leader".to_string())?;
    let entries = fs::read_dir("/proc")
        .map_err(|error| format!("cannot enumerate command process group: {error}"))?;
    let mut inspected = 0usize;
    let mut found = false;
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else { continue; };
        if pid == own_pid { continue; }
        let Some(stat) = proc_stat(pid) else { continue; };
        if stat.pgid != pgid || stat.state == 'Z' { continue; }
        if stat.sid != own_stat.sid {
            return Err("command PGID belongs to a different Linux session".into());
        }
        let details = match fs::metadata(format!("/proc/{pid}")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot validate command group member {pid}: {error}")),
        };
        if details.uid() != current_uid() {
            return Err("command process group contains a process owned by another WSL user".into());
        }
        inspected += 1;
        if inspected > MAX_PIDS {
            return Err("command process group exceeds the safe member limit".into());
        }
        found = true;
    }
    Ok(found)
}

fn finish_with_command_status(status: ExitStatus) -> Result<String, String> {
    if let Some(code) = status.code() {
        if code == 0 { return Ok(String::new()); }
        std::process::exit(code);
    }
    let signal = status.signal().ok_or_else(|| "session command returned no exit identity".to_string())?;
    // Restore the command's terminating signal for the stable group leader so
    // session-run records the same signal after every descendant has exited.
    let restored = unsafe { c_signal(signal, SIG_DFL) };
    if restored == SIG_ERR {
        return Err(format!("cannot restore session command signal {signal}"));
    }
    let result = unsafe { c_kill(std::process::id() as c_int, signal) };
    if result != 0 {
        return Err(format!("cannot reproduce session command signal: {}", io::Error::last_os_error()));
    }
    std::process::exit(128 + signal);
}

fn session_exec(cli: &Cli) -> Result<String, String> {
    validate_options(cli, &["command"], &[])?;
    let command = required_value(cli, "command")?;
    if command.is_empty() || command.len() > 65_536 || command.as_bytes().contains(&0) {
        return Err("--command must contain 1-65536 bytes".into());
    }
    let mut ready = [0u8; 1];
    io::stdin().read_exact(&mut ready)
        .map_err(|error| format!("session launch handshake failed: {error}"))?;
    if ready[0] != 1 { return Err("session launch handshake was invalid".into()); }
    // session-exec is the stable process-group leader.  It ignores SIGTERM
    // itself, while the actual shell restores the default disposition before
    // exec.  Therefore a TERM-resistant descendant cannot orphan the group
    // identity or make session-run tear down its socket prematurely.
    let previous = unsafe { c_signal(SIGTERM, SIG_IGN) };
    if previous == SIG_ERR { return Err("cannot protect session process-group leader".into()); }
    let mut shell = Command::new("/bin/sh");
    shell.args(["-lc", command]).stdin(Stdio::null());
    // SAFETY: pre_exec invokes only the C signal primitive to restore the
    // default SIGTERM disposition inherited by the command process.
    unsafe {
        shell.pre_exec(|| {
            if c_signal(SIGTERM, SIG_DFL) == SIG_ERR {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut command_child = match shell.spawn() {
        Ok(value) => value,
        Err(error) => {
            let _ = unsafe { c_signal(SIGTERM, previous) };
            return Err(format!("cannot start /bin/sh session: {error}"));
        }
    };
    let status = command_child.wait()
        .map_err(|error| format!("cannot wait for /bin/sh session: {error}"))?;
    let pgid = std::process::id();
    while current_user_group_has_other_members(pgid, std::process::id())? {
        thread::sleep(Duration::from_millis(20));
    }
    finish_with_command_status(status)
}

#[cfg(debug_assertions)]
fn session_test_member(cli: &Cli) -> Result<String, String> {
    validate_options(cli, &["ready", "lifetime-ms"], &["ignore-term"])?;
    let ready = validate_absolute_path("ready", required_value(cli, "ready")?)?;
    let lifetime_ms = required_value(cli, "lifetime-ms")?.parse::<u64>()
        .map_err(|_| "--lifetime-ms must be an integer".to_string())?;
    if !(100..=30_000).contains(&lifetime_ms) {
        return Err("--lifetime-ms must be between 100 and 30000".into());
    }
    // This debug-only CLI fixture creates a second process group while keeping
    // the session inherited from session-run. Integration tests use it to prove
    // that lifecycle control follows the exact SID rather than only one PGID.
    if unsafe { c_setpgid(0, 0) } != 0 {
        return Err(format!(
            "cannot create test process group: {}", io::Error::last_os_error(),
        ));
    }
    if cli.flags.contains("ignore-term")
            && unsafe { c_signal(SIGTERM, SIG_IGN) } == SIG_ERR {
        return Err("cannot ignore SIGTERM in test process-group member".into());
    }
    let pid = std::process::id();
    let stat = strict_proc_stat(pid)?
        .ok_or_else(|| "cannot inspect test process-group member".to_string())?;
    if stat.pgid != pid || stat.sid == pid || stat.state == 'Z' {
        return Err("test member did not enter a second PGID in the inherited SID".into());
    }
    atomic_write_private(
        &ready,
        format!(
            "{{\"pid\":{pid},\"pgid\":{},\"sid\":{},\"startTicks\":{}}}",
            stat.pgid, stat.sid, stat.start_ticks,
        ).as_bytes(),
    )?;
    thread::sleep(Duration::from_millis(lifetime_ms));
    Ok(String::new())
}

fn session_run(cli: &Cli) -> Result<String,String> {
    validate_options(cli,
        &["session-id","socket","metadata","log","cwd","kind","command"],
        &["token-stdin"])?;
    if !cli.flags.contains("token-stdin") { return Err("internal session-run requires --token-stdin".into()); }
    let token=token_from_cli(cli)?;
    let session_id=validate_session_id(required_value(cli,"session-id")?)?;
    let socket=validate_absolute_path("socket",required_value(cli,"socket")?)?;
    let metadata=validate_absolute_path("metadata",required_value(cli,"metadata")?)?;
    let log=validate_absolute_path("log",required_value(cli,"log")?)?;
    let cwd=cli.values.get("cwd").map(|value|validate_absolute_path("cwd",value)).transpose()?;
    if let Some(path)=&cwd {
        let details=fs::metadata(path).map_err(|error|format!("cannot inspect cwd {}: {error}",path.display()))?;
        if !details.is_dir(){return Err("--cwd must name a directory".into());}
    }
    let kind=cli.values.get("kind").map(String::as_str).unwrap_or("service");
    if !matches!(kind,"service"|"task"){return Err("--kind must be service or task".into());}
    let command=required_value(cli,"command")?;
    if command.is_empty()||command.len()>65_536||command.as_bytes().contains(&0){
        return Err("--command must contain 1-65536 bytes".into());
    }
    let session_boot_id=boot_id()?;
    let session_uid=current_uid();
    let supervisor_identity=capture_session_supervisor_identity(std::process::id())?;
    let listener=bind_private_socket(&socket)?;
    let _socket_guard=SocketPathGuard(socket.clone());
    let log_file=open_private_log(&log)?;
    let stderr_file=log_file.try_clone().map_err(|error|format!("cannot clone log handle: {error}"))?;
    let executable=env::current_exe().map_err(|error|format!("cannot locate helper executable: {error}"))?;
    let mut shell=Command::new(executable);
    shell.args(["session-exec","--command",command]).stdin(Stdio::piped())
        .stdout(Stdio::from(log_file)).stderr(Stdio::from(stderr_file));
    if let Some(path)=&cwd{shell.current_dir(path);}
    shell.process_group(0);
    let mut child=match shell.spawn(){
        Ok(child)=>child,
        Err(error)=>return Err(format!("cannot start /bin/sh session: {error}")),
    };
    let pid=child.id();
    let stat=proc_stat(pid).ok_or_else(||"cannot read new session process identity".to_string())?;
    if stat.pgid!=pid || stat.sid!=supervisor_identity.pid || stat.state=='Z'
        || !pid_owned_by_current_user(pid)
    {
        let _=child.kill();let _=child.wait();
        return Err("new session process group identity validation failed".into());
    }
    let record=SessionRecord{
        session_id,token_hash:sha256_bytes(token.as_bytes()),boot_id:session_boot_id,
        uid:session_uid,supervisor_pid:supervisor_identity.pid,pid,pgid:stat.pgid,
        start_ticks:stat.start_ticks,socket:socket.clone(),metadata,log,cwd,
        kind:kind.into(),command_hash:sha256_bytes(command.as_bytes()),started_at:epoch_seconds(),
    };
    if let Err(error)=write_metadata(&record,"running",None,true,None){
        let mut child_status = None;
        return Err(session_run_failure(
            &record, &supervisor_identity, &token, &mut child, &mut child_status, error,
        ));
    }
    if let Some(mut handshake)=child.stdin.take(){
        if let Err(error)=handshake.write_all(&[1]){
            let mut child_status = None;
            return Err(session_run_failure(
                &record, &supervisor_identity, &token, &mut child, &mut child_status,
                format!("cannot release session launch handshake: {error}"),
            ));
        }
    }else{
        let mut child_status = None;
        return Err(session_run_failure(
            &record, &supervisor_identity, &token, &mut child, &mut child_status,
            "session child has no private launch handshake",
        ));
    }
    let mut child_status = None;
    let run_result = (|| -> Result<(), String> {
        #[cfg(debug_assertions)]
        if env::var_os("LOCAL_OPS_WSL_HELPER_TEST_FAIL_SESSION_LOOP").is_some() {
            // Let the real TERM-resistant command prove that it was released
            // before exercising the unified post-release cleanup path.
            thread::sleep(Duration::from_millis(100));
            return Err("injected post-release session loop failure".into());
        }
        #[cfg(debug_assertions)]
        if env::var_os("LOCAL_OPS_WSL_HELPER_TEST_EXIT_BEFORE_CONTROL").is_some() {
            // Exercise startup fallback with a real, unreaped session leader:
            // wait until a descendant has created another PGID in this SID,
            // then bypass Rust destructors and internal cleanup entirely.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let has_second_group = session_owned_members(&record, &supervisor_identity)?
                    .iter().any(|member| member.pgid != record.pgid);
                if has_second_group { break; }
                if Instant::now() >= deadline {
                    return Err("test second process group was not created before forced leader exit".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            std::process::exit(86);
        }
        loop {
            poll_session_child(&mut child, &mut child_status)?;
            if child_status.is_some()
                    && !session_members_running(&record, &supervisor_identity)? {
                let _ = completed_session_response(&record, &mut child_status, false)?;
                return Ok(());
            }
            match listener.accept(){
                Ok((mut stream,_))=>{
                    let should_exit=match handle_session_request(
                        &mut stream,&record,&supervisor_identity,
                        &mut child,&mut child_status){
                        Ok(value)=>value,
                        Err(error)=>{let response=json_error(&error);let _=stream.write_all(response.as_bytes());
                            let _=stream.write_all(b"\n");false}
                    };
                    if should_exit{return Ok(());}
                }
                Err(error) if error.kind()==io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(20)),
                Err(error)=>return Err(format!("Unix socket accept failed: {error}")),
            }
        }
    })();
    match run_result {
        Ok(()) => Ok(String::new()),
        Err(error) => Err(session_run_failure(
            &record, &supervisor_identity, &token, &mut child, &mut child_status, error,
        )),
    }
}

fn control_request(socket:&Path,metadata_path:&Path,token:&str,action:&str,timeout_ms:u64)->Result<String,String>{
    let metadata=match fs::symlink_metadata(socket){
        Ok(value)=>value,
        Err(error) if error.kind()==io::ErrorKind::NotFound=>{
            return offline_session_result(metadata_path,socket,token);
        }
        Err(error)=>return Err(format!("cannot inspect Unix socket: {error}")),
    };
    if !metadata.file_type().is_socket()||metadata.uid()!=current_uid()||metadata.mode()&0o777!=0o600{
        return Err("Unix socket is not a private current-user control endpoint".into());
    }
    let mut stream=match UnixStream::connect(socket){
        Ok(value)=>value,
        Err(error)=>{
            // A crashed helper can leave a 0600 socket inode behind.  Accept
            // only token-authenticated terminal metadata in that case; a
            // still-running metadata record remains a hard session-lost error
            // for the Windows supervisor instead of an infinite retry loop.
            return offline_session_result(metadata_path,socket,token).map_err(|offline_error|
                format!("cannot connect to session socket: {error}; authenticated offline metadata unavailable: {offline_error}"));
        }
    };
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|error|error.to_string())?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms+5_000))).map_err(|error|error.to_string())?;
    let request=format!(
        "{{\"protocolVersion\":{PROTOCOL_VERSION},\"action\":{},\"token\":{},\"timeoutMs\":{timeout_ms}}}\n",
        json_string(action),json_string(token));
    let transport = (|| -> Result<String, String> {
        stream.write_all(request.as_bytes())
            .map_err(|error|format!("cannot write session request: {error}"))?;
        stream.shutdown(Shutdown::Write)
            .map_err(|error|format!("cannot finish session request: {error}"))?;
        read_socket_line(&mut stream,MAX_RESPONSE)
    })();
    match transport {
        Ok(response) => Ok(response),
        Err(error) => offline_session_result(metadata_path, socket, token).map_err(|offline_error|
            format!("session socket transport failed: {error}; authenticated offline metadata unavailable: {offline_error}")),
    }
}

fn session_control(cli:&Cli,implicit_action:Option<&str>)->Result<String,String>{
    validate_options(cli,&["socket","metadata","token","action","timeout-ms"],&["token-stdin"])?;
    let socket=validate_absolute_path("socket",required_value(cli,"socket")?)?;
    let metadata=validate_absolute_path("metadata",required_value(cli,"metadata")?)?;
    let token=token_from_cli(cli)?;
    let action=match implicit_action{
        Some(value)=>{if cli.values.contains_key("action"){return Err("action alias cannot also use --action".into());}value}
        None=>required_value(cli,"action")?,
    };
    if !matches!(action,"status"|"stop"|"force-stop"){
        return Err("--action must be status, stop, or force-stop".into());
    }
    let timeout_ms=cli.values.get("timeout-ms")
        .map(|value|value.parse::<u64>().map_err(|_|"--timeout-ms must be an integer".to_string()))
        .transpose()?.unwrap_or(5_000);
    if timeout_ms>30_000{return Err("--timeout-ms must not exceed 30000".into());}
    control_request(&socket,&metadata,&token,action,timeout_ms)
}

fn validate_session_response(
    response: &str,
    session_id: &str,
    socket: &Path,
    metadata: &Path,
    token: &str,
    supervisor_pid: u32,
    require_stopped: bool,
) -> Result<(), String> {
    let object = parse_json_object(response)
        .map_err(|error| format!("invalid session response JSON: {error}"))?;
    if !json_bool_field(&object, "ok")? {
        let error = match object.get("error") {
            Some(JsonValue::String(value)) => value.as_str(),
            _ => "session endpoint returned an unspecified error",
        };
        return Err(error.to_string());
    }
    if json_integer_field(&object, "protocolVersion")? != PROTOCOL_VERSION as i64 {
        return Err("session response protocol version mismatch".into());
    }
    if json_string_field(&object, "sessionId")? != session_id {
        return Err("session response ID mismatch".into());
    }
    if json_string_field(&object, "bootId")? != boot_id()? {
        return Err("session response distribution boot mismatch".into());
    }
    if json_integer_field(&object, "uid")? != current_uid() as i64 {
        return Err("session response WSL user mismatch".into());
    }
    if json_integer_field(&object, "supervisorPid")? != supervisor_pid as i64 {
        return Err("session response supervisor PID mismatch".into());
    }
    for name in ["pid", "pgid", "startTicks"] {
        if json_integer_field(&object, name)? <= 0 {
            return Err(format!("session response {name} must be positive"));
        }
    }
    if json_string_field(&object, "socket")? != socket.to_string_lossy().as_ref() {
        return Err("session response socket path mismatch".into());
    }
    if json_string_field(&object, "metadata")? != metadata.to_string_lossy().as_ref() {
        return Err("session response metadata path mismatch".into());
    }
    let expected_hash = sha256_bytes(token.as_bytes());
    if !constant_time_eq(
        json_string_field(&object, "tokenHash")?.as_bytes(),
        expected_hash.as_bytes(),
    ) {
        return Err("session response token hash mismatch".into());
    }
    let running = json_bool_field(&object, "running")?;
    let state = json_string_field(&object, "state")?;
    if require_stopped {
        if running || state != "exited" {
            return Err("force-stop response did not prove a terminal session".into());
        }
    } else if (running && state != "running") || (!running && state != "exited") {
        return Err("session response state is inconsistent".into());
    }
    Ok(())
}

fn wait_for_supervisor_exit(supervisor: &mut Child, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match supervisor.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => return Err("detached session helper did not exit before cleanup timeout".into()),
            Err(error) => return Err(format!("cannot query detached session helper during cleanup: {error}")),
        }
    }
}

fn validate_removable_session_socket(socket: &Path) -> Result<bool, String> {
    let details = match fs::symlink_metadata(socket) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect failed-session socket: {error}")),
    };
    validate_private_parent(socket)?;
    if details.file_type().is_symlink() || !details.file_type().is_socket()
        || details.uid() != current_uid()
    {
        return Err("failed-session socket is not a current-user Unix socket".into());
    }
    Ok(true)
}

fn remove_authenticated_session_files(
    session_id: &str,
    socket: &Path,
    metadata: &Path,
    token: &str,
    supervisor_pid: u32,
) -> Result<(), String> {
    let metadata_exists = match fs::symlink_metadata(metadata) {
        Ok(_) => {
            let (text, _) = read_private_metadata(metadata)?;
            validate_session_response(
                &text, session_id, socket, metadata, token, supervisor_pid, false,
            ).map_err(|error| format!("cannot authenticate cleanup metadata: {error}"))?;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("cannot inspect failed-session metadata: {error}")),
    };
    let socket_exists = validate_removable_session_socket(socket)?;

    if metadata_exists {
        fs::remove_file(metadata)
            .map_err(|error| format!("cannot remove authenticated failed-session metadata: {error}"))?;
        if let Some(parent) = metadata.parent() { sync_directory(parent); }
    }
    if socket_exists {
        fs::remove_file(socket)
            .map_err(|error| format!("cannot remove owned failed-session socket: {error}"))?;
        if let Some(parent) = socket.parent() { sync_directory(parent); }
    }
    Ok(())
}

fn session_run_failure(
    record: &SessionRecord,
    identity: &SessionSupervisorIdentity,
    token: &str,
    child: &mut Child,
    child_status: &mut Option<ExitStatus>,
    cause: impl AsRef<str>,
) -> String {
    let cleanup = (|| -> Result<(), String> {
        force_kill_exact_session_members(
            identity, Some(identity.pid), Duration::from_secs(5),
        )?;
        wait_for_session_child_reap(child, child_status, Duration::from_secs(2))?;
        let remaining = exact_session_members(identity)?
            .into_iter()
            .filter(|member| member.pid != identity.pid)
            .map(|member| format!("{}/pgid{}", member.pid, member.pgid))
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            return Err(format!(
                "exact SID {} still contains {}", identity.pid, remaining.join(","),
            ));
        }
        remove_authenticated_session_files(
            &record.session_id, &record.socket, &record.metadata, token, identity.pid,
        )?;
        Ok(())
    })();
    match cleanup {
        Ok(()) => format!("{}; post-release exact SID cleanup completed", cause.as_ref()),
        Err(error) => format!(
            "{}; post-release exact SID cleanup failed: {error}", cause.as_ref(),
        ),
    }
}

fn finish_failed_session_start_cleanup(
    supervisor: &mut Child,
    identity: &SessionSupervisorIdentity,
    session_id: &str,
    socket: &Path,
    metadata: &Path,
    token: &str,
) -> Result<(), String> {
    // Even an authenticated terminal response only proves that the original
    // command PGID is terminal. A descendant may have created another PGID in
    // this same pinned Linux session, so always empty the entire SID before
    // deleting its only recoverable metadata and socket.
    force_kill_exact_session_members(identity, None, Duration::from_secs(5))?;
    // Do not reap the session leader until the numeric SID has been proven
    // empty. Linux can recycle a PID/SID after wait(2), even while a pidfd
    // still refers to the old struct pid; enumerating by that recycled SID
    // could otherwise cross into an unrelated same-UID session.
    let remaining = exact_session_members(identity)?
        .into_iter()
        .map(|member| format!("{}/pgid{}", member.pid, member.pgid))
        .collect::<Vec<_>>();
    if !remaining.is_empty() {
        return Err(format!(
            "exact SID {} was not empty after startup cleanup; remaining {}",
            identity.pid, remaining.join(","),
        ));
    }
    wait_for_supervisor_exit(supervisor, Duration::from_secs(2))?;
    remove_authenticated_session_files(
        session_id, socket, metadata, token, identity.pid,
    )
}

fn cleanup_failed_session_start(
    supervisor: &mut Child,
    identity: &SessionSupervisorIdentity,
    session_id: &str,
    socket: &Path,
    metadata: &Path,
    token: &str,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut last_control_error = None;
    loop {
        if socket.exists() {
            match control_request(socket, metadata, token, "force-stop", 1_000) {
                Ok(response) => {
                    match validate_session_response(
                        &response, session_id, socket, metadata, token,
                        identity.pid, true,
                    ) {
                        Ok(()) => {
                            match finish_failed_session_start_cleanup(
                                supervisor, identity, session_id, socket, metadata, token,
                            ) {
                                Ok(()) => return Ok(
                                    "authenticated force-stop cleanup completed after exact SID proof".into(),
                                ),
                                Err(error) => last_control_error = Some(error),
                            }
                        }
                        Err(error) => last_control_error = Some(format!(
                            "authenticated force-stop response was rejected: {error}"
                        )),
                    }
                }
                Err(error) => last_control_error = Some(error),
            }
        } else if metadata.exists() {
            match offline_session_result(metadata, socket, token).and_then(|response| {
                validate_session_response(
                    &response, session_id, socket, metadata, token,
                    identity.pid, true,
                )?;
                Ok(response)
            }) {
                Ok(_) => {
                    match finish_failed_session_start_cleanup(
                        supervisor, identity, session_id, socket, metadata, token,
                    ) {
                        Ok(()) => return Ok(
                            "authenticated terminal-session cleanup completed after exact SID proof".into(),
                        ),
                        Err(error) => last_control_error = Some(error),
                    }
                }
                Err(error) => last_control_error = Some(error),
            }
        }

        // Observe exit through /proc without wait(2). The Child must remain
        // unreaped so its numeric session-leader PID cannot be reused before
        // exact-SID cleanup has completed.
        match validate_session_supervisor_if_present(identity) {
            Ok(false) if !socket.exists() && !metadata.exists() => {
                last_control_error = Some(
                    "detached session launcher exited before publishing identity".into(),
                );
                break;
            }
            Ok(_) => {}
            Err(error) => return Err(format!(
                "cannot inspect detached session helper during cleanup: {error}"
            )),
        }
        if Instant::now() >= deadline { break; }
        thread::sleep(Duration::from_millis(25));
    }

    // Control may be unavailable because the socket is corrupt, inaccessible,
    // or stuck in accept/read. Fall back to the spawn-pinned session leader:
    // kill every current-UID member of only that SID through a revalidated
    // pidfd, then prove the SID empty before removing authenticated files.
    finish_failed_session_start_cleanup(
        supervisor, identity, session_id, socket, metadata, token,
    )?;
    Ok(format!(
        "exact SID/UID/start-time fallback cleanup completed{}",
        last_control_error
            .map(|error| format!(" after control failure: {error}"))
            .unwrap_or_default(),
    ))
}

fn session_start_failure(
    supervisor: &mut Child,
    identity: &SessionSupervisorIdentity,
    session_id: &str,
    socket: &Path,
    metadata: &Path,
    token: &str,
    cause: impl AsRef<str>,
) -> String {
    match cleanup_failed_session_start(
        supervisor, identity, session_id, socket, metadata, token,
    ) {
        Ok(cleanup) => format!("{}; {cleanup}", cause.as_ref()),
        Err(cleanup) => format!(
            "{}; session startup cleanup failed: {cleanup}", cause.as_ref()
        ),
    }
}

fn session_start_probe_token(token: &str) -> &str {
    #[cfg(debug_assertions)]
    if env::var_os("LOCAL_OPS_WSL_HELPER_TEST_FAIL_START_STATUS").is_some() {
        // Give the debug-only regression fixture time to prove that a real
        // command group was released before the injected status failure.
        thread::sleep(Duration::from_millis(100));
        return "ffffffffffffffffffffffffffffffffffffffffffffffff";
    }
    token
}

fn session_start(cli:&Cli)->Result<String,String>{
    validate_options(cli,
        &["session-id","token","socket","metadata","log","cwd","kind","command"],
        &["token-stdin"])?;
    let token=token_from_cli(cli)?;
    let session_id=validate_session_id(required_value(cli,"session-id")?)?;
    let socket=validate_absolute_path("socket",required_value(cli,"socket")?)?;
    let metadata=validate_absolute_path("metadata",required_value(cli,"metadata")?)?;
    let log=validate_absolute_path("log",required_value(cli,"log")?)?;
    ensure_private_parent(&socket)?;ensure_private_parent(&metadata)?;
    check_not_symlink(&socket,true)?;check_not_symlink(&metadata,true)?;check_not_symlink(&log,true)?;
    if metadata.exists(){return Err("session metadata already exists; refusing to overwrite an existing identity".into());}
    if socket.exists(){return Err("session socket already exists; use a fresh session ID".into());}
    let kind=cli.values.get("kind").map(String::as_str).unwrap_or("service");
    if !matches!(kind,"service"|"task"){return Err("--kind must be service or task".into());}
    let command=required_value(cli,"command")?;
    if command.is_empty()||command.len()>65_536||command.as_bytes().contains(&0){
        return Err("--command must contain 1-65536 bytes".into());
    }
    // A caller may have inherited SIGCHLD=SIG_IGN or SA_NOCLDWAIT. Restore
    // the default disposition before spawning session-run so a terminated
    // leader remains an unreaped zombie, reserving its numeric SID until the
    // exact-SID cleanup proof and explicit Child::wait/try_wait complete.
    if unsafe { c_signal(SIGCHLD, SIG_DFL) } == SIG_ERR {
        return Err("cannot establish reap-safe detached helper identity".into());
    }
    let executable=env::current_exe().map_err(|error|format!("cannot locate helper executable: {error}"))?;
    let mut child_command=Command::new(executable);
    child_command.arg("session-run").arg("--json").arg("--token-stdin")
        .arg("--session-id").arg(&session_id).arg("--socket").arg(&socket)
        .arg("--metadata").arg(&metadata).arg("--log").arg(&log)
        .arg("--kind").arg(kind).arg("--command").arg(command)
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(cwd)=cli.values.get("cwd"){child_command.arg("--cwd").arg(cwd);}
    // SAFETY: pre_exec calls only the async-signal-safe setsid syscall.
    unsafe{child_command.pre_exec(||if c_setsid()<0{Err(io::Error::last_os_error())}else{Ok(())});}
    let mut supervisor=child_command.spawn().map_err(|error|format!("cannot spawn detached WSL session helper: {error}"))?;
    let supervisor_identity = match capture_session_supervisor_identity(supervisor.id()) {
        Ok(value) => value,
        Err(error) => {
            let termination = supervisor.kill()
                .and_then(|_| supervisor.wait().map(|_| ()))
                .map_err(|cleanup| format!("; cannot terminate unpinned helper: {cleanup}"))
                .err().unwrap_or_default();
            return Err(format!("cannot pin detached WSL session helper: {error}{termination}"));
        }
    };
    let token_result = match supervisor.stdin.take() {
        Some(mut stdin) => stdin.write_all(token.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|error| format!("cannot send session token: {error}")),
        None => Err("detached WSL session helper has no private token pipe".into()),
    };
    if let Err(error) = token_result {
        return Err(session_start_failure(
            &mut supervisor, &supervisor_identity, &session_id, &socket, &metadata, &token, error,
        ));
    }
    let deadline=Instant::now()+Duration::from_secs(5);
    let mut last_probe_error = None;
    #[cfg(debug_assertions)]
    let break_start_control =
        env::var_os("LOCAL_OPS_WSL_HELPER_TEST_BREAK_START_CONTROL").is_some();
    #[cfg(not(debug_assertions))]
    let break_start_control = false;
    let mut control_broken = false;
    loop{
        if socket.exists(){
            if break_start_control && !control_broken {
                let publication_deadline = Instant::now() + Duration::from_secs(1);
                while !metadata.exists() && Instant::now() < publication_deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                thread::sleep(Duration::from_millis(100));
                if let Err(error) = fs::set_permissions(
                    &socket, fs::Permissions::from_mode(0o666),
                ) {
                    return Err(session_start_failure(
                        &mut supervisor, &supervisor_identity, &session_id, &socket,
                        &metadata, &token,
                        format!("cannot inject inaccessible startup control socket: {error}"),
                    ));
                }
                control_broken = true;
            }
            match control_request(
                &socket, &metadata, session_start_probe_token(&token), "status", 0,
            ) {
                Ok(response) => match validate_session_response(
                    &response, &session_id, &socket, &metadata, &token,
                    supervisor_identity.pid, false,
                ) {
                    Ok(()) => return Ok(response),
                    Err(error) => return Err(session_start_failure(
                        &mut supervisor, &supervisor_identity, &session_id, &socket,
                        &metadata, &token,
                        format!("WSL session startup handshake failed: {error}"),
                    )),
                },
                Err(error) if !control_broken && Instant::now()<deadline => {
                    last_probe_error = Some(error)
                }
                Err(error) => return Err(session_start_failure(
                    &mut supervisor, &supervisor_identity, &session_id, &socket,
                    &metadata, &token,
                    format!("WSL session startup handshake failed: {error}"),
                )),
            }
        }
        let supervisor_running = match validate_session_supervisor_if_present(
            &supervisor_identity,
        ) {
            Ok(value) => value,
            Err(error) => return Err(session_start_failure(
                &mut supervisor, &supervisor_identity, &session_id, &socket,
                &metadata, &token,
                format!("cannot inspect detached helper during startup: {error}"),
            )),
        };
        if !supervisor_running {
            let result = control_request(&socket,&metadata,&token,"status",0)
                .and_then(|response| {
                    validate_session_response(
                        &response, &session_id, &socket, &metadata, &token,
                        supervisor_identity.pid, false,
                    )?;
                    Ok(response)
                });
            return match result {
                Ok(response) => Ok(response),
                Err(error) => Err(session_start_failure(
                    &mut supervisor, &supervisor_identity, &session_id, &socket,
                    &metadata, &token,
                    format!(
                        "detached WSL session helper exited during startup: {error}"
                    ),
                )),
            };
        }
        if Instant::now()>=deadline{
            let cause = if socket.exists() {
                format!(
                    "timed out authenticating the WSL session socket{}",
                    last_probe_error
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default(),
                )
            } else {
                "timed out before the WSL session created a control socket".into()
            };
            return Err(session_start_failure(
                &mut supervisor, &supervisor_identity, &session_id, &socket,
                &metadata, &token, cause,
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn inspection_output(cli:&Cli)->Result<String,String>{
    let current_boot_id=boot_id()?;
    match cli.operation.as_str(){
        "status"=>{validate_options(cli,&[],&[])?;let self_sha256=current_executable_sha256()?;Ok(format!(
            concat!("{{\"ok\":true,\"protocolVersion\":{protocol_version},",
                "\"version\":{version},\"selfSha256\":{self_sha256},",
                "\"bootId\":{boot_id},\"uid\":{uid},\"pid\":{pid},",
                "\"capabilities\":[\"proc\",\"listeners\",\"network\",\"sessions\",",
                "\"private-unix-socket\",\"pidfd-process-control\",\"self-install-sha256\"]}}"),
            protocol_version=PROTOCOL_VERSION,version=json_string(HELPER_VERSION),boot_id=json_string(&current_boot_id),
            self_sha256=json_string(&self_sha256),uid=current_uid(),pid=std::process::id()))}
        "boot-id"=>{validate_options(cli,&[],&[])?;Ok(format!(
            "{{\"ok\":true,\"protocolVersion\":{PROTOCOL_VERSION},\"bootId\":{},\"uid\":{}}}",
            json_string(&current_boot_id),current_uid()))}
        "network"=>{validate_options(cli,&[],&[])?;let addresses=network_addresses();
            let rows=addresses.iter().map(|address|json_string(&address.to_string())).collect::<Vec<_>>().join(",");
            let preferred=addresses.first().map(|address|json_string(&address.to_string())).unwrap_or_else(||"null".into());
            Ok(format!("{{\"ok\":true,\"bootId\":{},\"uid\":{},\"addresses\":[{}],\"preferredAddress\":{}}}",
                json_string(&current_boot_id),current_uid(),rows,preferred))}
        "processes"=>{validate_options(cli,&["pids"],&[])?;let filter=parse_pids(cli)?;
            let up=uptime();let ticks=clock_ticks();let memory=total_memory_bytes();
            let rows:Vec<String>=process_ids(&filter).iter()
                .filter_map(|pid|process_json(*pid,up,ticks,memory,&current_boot_id)).collect();
            Ok(format!("{{\"ok\":true,\"bootId\":{},\"uid\":{},\"processes\":[{}]}}",
                json_string(&current_boot_id),current_uid(),rows.join(",")))}
        "cwds"=>{validate_options(cli,&["pids"],&[])?;let filter=parse_pids(cli)?;
            let rows:Vec<String>=process_ids(&filter).iter().filter_map(|pid|{
                if !pid_owned_by_current_user(*pid){return None;}
                fs::read_link(format!("/proc/{pid}/cwd")).ok().map(|path|
                    format!("{}:{}",json_string(&pid.to_string()),json_string(&path.to_string_lossy())))
            }).collect();
            Ok(format!("{{\"ok\":true,\"bootId\":{},\"uid\":{},\"cwds\":{{{}}}}}",
                json_string(&current_boot_id),current_uid(),rows.join(",")))}
        "listeners"=>{validate_options(cli,&["pids"],&[])?;let filter=parse_pids(cli)?;
            let sockets=tcp_listeners();let mut grouped:BTreeMap<(u32,u16),BTreeSet<String>>=BTreeMap::new();
            for pid in process_ids(&filter){for inode in socket_inodes(pid){
                if let Some((port,host))=sockets.get(&inode){grouped.entry((pid,*port)).or_default().insert(host.clone());}
            }}
            let rows:Vec<String>=grouped.into_iter().map(|((pid,port),hosts)|{
                let hosts=hosts.iter().map(|host|json_string(host)).collect::<Vec<_>>().join(",");
                format!("{{\"pid\":{pid},\"port\":{port},\"bind_hosts\":[{hosts}]}}")
            }).collect();
            Ok(format!("{{\"ok\":true,\"bootId\":{},\"uid\":{},\"listeners\":[{}]}}",
                json_string(&current_boot_id),current_uid(),rows.join(",")))}
        _=>Err("unknown inspection operation".into()),
    }
}

fn dispatch(cli:&Cli)->Result<String,String>{
    match cli.operation.as_str(){
        "status"|"boot-id"|"network"|"processes"|"cwds"|"listeners"=>inspection_output(cli),
        "install"=>install_helper(cli),"session-start"=>session_start(cli),
        "session-run"=>session_run(cli),"session-exec"=>session_exec(cli),
        #[cfg(debug_assertions)]
        "session-test-member"=>session_test_member(cli),
        "process-control"=>process_control(cli),
        "session-control"=>session_control(cli,None),"session-status"=>session_control(cli,Some("status")),
        "session-stop"=>session_control(cli,Some("stop")),
        "session-force-stop"=>session_control(cli,Some("force-stop")),
        _=>Err(format!("unknown operation: {}",cli.operation)),
    }
}

fn main(){
    let result=parse_cli().and_then(|cli|dispatch(&cli));
    match result{
        Ok(output)=>if !output.is_empty(){let mut stdout=io::stdout().lock();
            let _=stdout.write_all(output.as_bytes());let _=stdout.write_all(b"\n");},
        Err(error)=>{eprintln!("{}",json_error(&error));std::process::exit(2);}
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn sha256_matches_standard_vectors(){
        assert_eq!(sha256_bytes(b""),"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_bytes(b"abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn stat_parser_handles_spaces_and_closing_parentheses(){
        let line="123 (odd ) name) S 7 123 99 0 0 0 0 0 0 0 10 20 0 0 0 0 1 0 456 789 12";
        let stat=parse_stat_line(line).unwrap();
        assert_eq!(stat.comm,"odd ) name");assert_eq!(stat.ppid,7);assert_eq!(stat.pgid,123);
        assert_eq!(stat.sid,99);assert_eq!(stat.start_ticks,456);assert_eq!(stat.rss_pages,12);
    }

    #[test]
    fn control_json_rejects_duplicate_or_unknown_fields(){
        assert!(request_fields(r#"{"action":"status","action":"stop","token":"abcdefghijklmnopqrstuvwxyzABCDEF"}"#).is_err());
        assert!(request_fields(r#"{"action":"status","token":"abcdefghijklmnopqrstuvwxyzABCDEF","pid":1}"#).is_err());
    }

    #[test]
    fn control_json_accepts_versioned_valid_request(){
        let request=r#"{"protocolVersion":2,"action":"stop","token":"abcdefghijklmnopqrstuvwxyzABCDEF","timeoutMs":5000}"#;
        let (action,token,timeout)=request_fields(request).unwrap();
        assert_eq!(action,"stop");assert_eq!(token,"abcdefghijklmnopqrstuvwxyzABCDEF");assert_eq!(timeout,5000);
    }

    #[test]
    fn path_and_identity_inputs_are_fail_closed(){
        assert!(validate_absolute_path("target","relative/helper").is_err());
        assert!(validate_absolute_path("target","/tmp/../etc/helper").is_err());
        assert!(validate_session_id("short").is_err());assert!(validate_token("too-short").is_err());
    }

    #[test]
    fn proc_ipv6_words_are_decoded_from_linux_byte_order(){
        assert_eq!(decode_ipv6("00000000000000000000000001000000").as_deref(),Some("::1"));
        assert_eq!(decode_ipv6("0000000000000000FFFF00000100007F").as_deref(),Some("::ffff:127.0.0.1"));
    }

    #[test]
    fn network_parsers_exclude_loopback_and_link_local(){
        let fib=" |-- 127.0.0.1\n    /32 host LOCAL\n |-- 172.29.1.20\n    /32 host LOCAL\n |-- 169.254.2.3\n    /32 host LOCAL\n";
        let ipv4=parse_fib_trie(fib);
        assert!(ipv4.contains(&"172.29.1.20".parse().unwrap()));assert_eq!(ipv4.len(),1);
        let ipv6=parse_if_inet6("00000000000000000000000000000001 01 80 10 80 lo\nfd001234000000000000000000000001 02 40 00 80 eth0\nfe800000000000000000000000000001 02 40 20 80 eth0\n");
        assert!(ipv6.contains(&"fd00:1234::1".parse().unwrap()));assert_eq!(ipv6.len(),1);
    }
}
