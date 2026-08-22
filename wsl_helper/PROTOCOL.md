# WSL helper protocol v2

`wsl-helper` is a dependency-free, static `x86_64-unknown-linux-musl`
executable. Every successful command writes exactly one JSON object followed by
a newline to stdout. Validation and transport failures write an `{ok:false}`
JSON object to stderr and exit with status 2.

The Windows host must invoke the helper through the target distribution's
default user. Inspection never returns another Linux UID's process data, and
monitoring commands never start a stopped distribution.

## Inspection

```text
wsl-helper status --json
wsl-helper boot-id --json
wsl-helper network --json
wsl-helper processes --json [--pids 12,34]
wsl-helper cwds --json [--pids 12,34]
wsl-helper listeners --json [--pids 12,34]
```

`status` returns `protocolVersion`, helper `version`, `selfSha256`, `bootId`,
`uid`, `pid`, and capability names. `selfSha256` is computed from
`/proc/self/exe`, so it attests the actual executable inode running the status
request rather than only its launch path. `network` reads `/proc/net/fib_trie` and
`/proc/net/if_inet6`, excludes loopback/link-local/unspecified/multicast
addresses, and returns `addresses` plus the IPv4-preferred
`preferredAddress`. No route or network command is executed.

Process identities include `boot_id`, numeric `pid`, `uid`, `ppid`, `pgid`,
`sid`, exact `startTicks`, and epoch `create_time`. Listener rows are grouped as
`{pid,port,bind_hosts}`. Each process also includes `cwdHash` (SHA-256 of the
raw `/proc/PID/cwd` link path bytes) and `commandHash` (SHA-256 of the exact raw
`/proc/PID/cmdline` bytes). `processes`, `cwds`, and `listeners` filter all rows to
the helper's real UID even when a caller supplies `--pids`.

An explicitly attached external WSL process is controlled only with its full
identity:

```text
wsl-helper process-control --json --action stop|force-stop \
  --pid PID --uid UID --boot-id BOOT_ID --start-ticks START_TICKS \
  --cwd-hash SHA256 --command-hash SHA256 [--timeout-ms 5000]
```

Every identity field is required. The helper opens a Linux pidfd, then rereads
and compares current UID, boot ID, start ticks, cwd hash, and command hash before
sending any signal through that pidfd. A reused PID therefore cannot receive a
signal. `stop` sends SIGTERM and returns `requiresForce:true` on timeout; only
`force-stop` sends SIGKILL. No command accepts PID as the sole control identity.

## Verified self-install

The bundled helper can copy itself from a DrvFS path without `cp`, `chmod`, or
`sha256sum`:

```text
/mnt/c/.../wsl-helper install --json \
  --target /home/example/.local/share/console/bin/wsl-helper-0.1.0 \
  --sha256 64_LOWER_OR_UPPER_HEX_DIGITS
```

The target must be absolute, its private parent must belong to the current UID,
and no existing target or ancestor component may be a symbolic link. Root,
home, and mount ancestors may retain their normal owners and modes; only the
final private state directory must belong to the current UID and exclude
group/other access. Installation uses a
mode-0600 temporary file, fsync, SHA-256 verification, chmod 0700, a second
read-back verification, atomic rename, directory fsync, and final verification.
The response contains `installedSha256`, `version`, `target`, and `mode`.

## Sessions

Start a new, randomly named session with fresh paths in a mode-0700 directory:

```text
wsl-helper session-start --json \
  --session-id 32_SAFE_RANDOM_CHARS \
  --token-stdin \
  --socket /home/example/.local/share/console/sessions/ID.sock \
  --metadata /home/example/.local/share/console/sessions/ID.json \
  --log /home/example/.local/share/console/logs/APP.log \
  --cwd /home/example/project \
  --kind service \
  --command 'exec npm run dev'
```

`--token-stdin` may replace `--token` and is preferred. The launcher starts a
detached `setsid` helper, transfers the token through a private pipe (the
persistent helper argv never contains it), starts a stable group leader and
`/bin/sh -lc` in a dedicated process group, and waits up to five seconds for
the socket. The leader retains the root command's exit status. The session
helper remains until every non-zombie current-UID member of its pinned Linux
session has exited, including descendants that create a second process group.
Metadata is written
atomically with mode 0600 and stores only `tokenHash` (SHA-256), never the token.
The Unix socket is owned by the current UID with exact mode 0600.

`session-start` does not publish a failed handshake as a recoverable running
identity.  If its initial authenticated status exchange fails or times out
after the private socket is published, it uses the original session ID, socket,
metadata path, and token to issue a bounded authenticated `force-stop`, waits
for the exact detached helper and every member of its pinned SID to exit, and removes the
retry-blocking terminal metadata. Before transferring the token, the launcher
also pins the `session-run` process with a pidfd and records its current UID,
session-leader PID, and start ticks. If socket control is inaccessible,
malformed, or times out, cleanup enumerates only non-zombie processes whose SID
is that pinned PID, requires the same current UID, opens and revalidates a pidfd
for every member's UID/SID/PGID/start ticks, sends SIGKILL to those exact
processes with the session leader last, and waits until that SID is empty. The
launcher restores the default SIGCHLD disposition and deliberately leaves the
terminated leader unreaped until this proof is complete, so Linux cannot recycle
the numeric PID/SID into an unrelated session during fallback cleanup. It
then removes only token-authenticated mode-0600 metadata and a current-UID Unix
socket in the private state directory. A cleanup that cannot prove any of these
boundaries is reported explicitly as a startup cleanup failure; it is never
described as a successfully preserved session.

After the command launch handshake is released, every internal `session-run`
error uses the same bounded exact-SID cleanup while keeping the pinned
`session-run` process itself alive to supervise it. The command leader and all
remaining same-SID descendants are killed through revalidated pidfds, reaped,
and proven absent before authenticated metadata and socket paths are removed.
Authenticated force-stop and offline-terminal startup cleanup repeat that exact
SID proof before removing the last recoverable files. Only normal terminal
handling disarms this failure cleanup.

Control can use the general command or aliases:

```text
wsl-helper session-control --json --socket /abs/ID.sock --metadata /abs/ID.json --token-stdin \
  --action status|stop|force-stop [--timeout-ms 5000]
wsl-helper session-status     --json --socket /abs/ID.sock --metadata /abs/ID.json --token-stdin
wsl-helper session-stop       --json --socket /abs/ID.sock --metadata /abs/ID.json --token-stdin
wsl-helper session-force-stop --json --socket /abs/ID.sock --metadata /abs/ID.json --token-stdin
```

`--token-stdin` is also accepted here. The on-socket protocol is one UTF-8 JSON
line, limited to 8192 bytes:

```json
{"protocolVersion":2,"action":"status","token":"...","timeoutMs":5000}
```

The server validates Linux `SO_PEERCRED` and the token hash in constant time.
For lifecycle status and control it anchors the original `setsid` supervisor
with a spawn-pinned pidfd, UID, boot ID, SID and start ticks, enumerates every
non-zombie current-UID member of that exact SID except the supervisor, then
opens and revalidates each member's pidfd, UID, SID, PGID and start ticks before
signalling any member. Processes cannot join an unrelated existing Linux SID;
changing PGID within the managed SID therefore does not escape control. Zombie
rows do not keep a session running. There is no PID/port kill interface. `stop`
sends SIGTERM to the exact members across all PGIDs and, if any remain after the
requested timeout, returns `ok:false`, `requiresForce:true` while retaining the
running identity. Only explicit `force-stop` sends SIGKILL.

If the socket has disappeared, a stale 0600 socket inode refuses connection, or
the endpoint closes during a natural-exit request, control validates `--metadata` with
`O_NOFOLLOW`, requiring a current-UID regular file with exact mode 0600 in a
private current-UID directory. It verifies the current boot ID, valid session
ID, socket and metadata paths, and `tokenHash` in constant time. Only an
authenticated `state:"exited", running:false` record with a valid exit object
is returned offline; a running record reports control unavailable. This closes
the natural/ultrafast-exit race without treating stale metadata as live control.

Session responses contain `sessionId`, `bootId`, `uid`, `supervisorPid`, `pid`,
`pgid`, `startTicks`, `tokenHash`, paths, `kind`, `state`, `running`, and
optional exit data. The hash is safe to compare with Windows metadata and no
response ever contains the plaintext token. Natural
exit 0 is `succeeded`, natural exit 130 is `canceled`, other natural exits are
`failed`, and a helper stop is `stopped`. Durable metadata additionally contains
`commandHash` and `tokenHash`; public socket responses expose only the hashes.
