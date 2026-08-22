#!/bin/sh
set -eu

fail() {
    printf '%s\n' "distro smoke failed: $*" >&2
    exit 1
}

helper=${1:-}
case "$helper" in
    /*) ;;
    *) fail "helper path must be absolute" ;;
esac
[ -f "$helper" ] || fail "helper is not a regular file: $helper"
[ -x "$helper" ] || fail "helper is not executable: $helper"

hash_line=$(sha256sum -- "$helper")
expected=${hash_line%% *}
status=$($helper status --json)
case "$status" in
    *"\"protocolVersion\":2"*"\"selfSha256\":\"$expected\""*) ;;
    *) fail "status did not attest the running executable: $status" ;;
esac

$helper boot-id --json >/dev/null
$helper network --json >/dev/null
$helper processes --json --pids "$$" >/dev/null
$helper cwds --json --pids "$$" >/dev/null
$helper listeners --json --pids "$$" >/dev/null

tmp=$(mktemp -d "${TMPDIR:-/tmp}/local-ops-wsl-helper.XXXXXX")
session_socket=
session_metadata=
session_token=0123456789abcdef0123456789abcdef0123456789abcdef
cleanup() {
    if [ -n "$session_socket" ] && [ -S "$session_socket" ]; then
        "$helper" session-force-stop --json \
            --socket "$session_socket" --metadata "$session_metadata" \
            --token "$session_token" --timeout-ms 5000 >/dev/null 2>&1 || true
    fi
    case "$tmp" in
        "${TMPDIR:-/tmp}"/local-ops-wsl-helper.*) rm -rf -- "$tmp" ;;
        *) fail "refusing to clean unexpected path: $tmp" ;;
    esac
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "$tmp"

target="$tmp/installed-helper"
install=$($helper install --json --target "$target" --sha256 "$expected")
case "$install" in
    *"\"installedSha256\":\"$expected\""*"\"mode\":\"0700\""*) ;;
    *) fail "verified install response was incomplete: $install" ;;
esac
[ "$(stat -c %a -- "$target")" = 700 ] || fail "installed helper mode is not 0700"
installed_status=$($target status --json)
case "$installed_status" in
    *"\"selfSha256\":\"$expected\""*) ;;
    *) fail "installed helper self-attestation mismatch" ;;
esac

printf X >>"$target"
corrupt_line=$(sha256sum -- "$target")
[ "${corrupt_line%% *}" != "$expected" ] || fail "corruption did not change the helper hash"
$helper install --json --target "$target" --sha256 "$expected" >/dev/null
restored_line=$(sha256sum -- "$target")
[ "${restored_line%% *}" = "$expected" ] || fail "corrupted helper was not repaired"

cp -- /bin/true "$target"
chmod 0700 "$target"
old_line=$(sha256sum -- "$target")
[ "${old_line%% *}" != "$expected" ] || fail "upgrade fixture unexpectedly matches helper"
$helper install --json --target "$target" --sha256 "$expected" >/dev/null
upgraded_line=$(sha256sum -- "$target")
[ "${upgraded_line%% *}" = "$expected" ] || fail "existing helper was not upgraded"

victim="$tmp/victim"
printf '%s\n' 'must remain unchanged' >"$victim"
victim_line=$(sha256sum -- "$victim")
linked_target="$tmp/linked-helper"
ln -s -- "$victim" "$linked_target"
if $helper install --json --target "$linked_target" --sha256 "$expected" \
        >"$tmp/target-symlink.out" 2>&1; then
    fail "install accepted a symbolic-link target"
fi
grep -q 'symbolic link' "$tmp/target-symlink.out" || fail "target symlink rejection was not explicit"
after_line=$(sha256sum -- "$victim")
[ "$victim_line" = "$after_line" ] || fail "symlink target victim was modified"

real_parent="$tmp/real-parent"
linked_parent="$tmp/linked-parent"
mkdir "$real_parent"
chmod 0700 "$real_parent"
ln -s -- "$real_parent" "$linked_parent"
if $helper install --json --target "$linked_parent/helper" --sha256 "$expected" \
        >"$tmp/ancestor-symlink.out" 2>&1; then
    fail "install accepted a symbolic-link ancestor"
fi
grep -q 'symbolic-link path ancestor' "$tmp/ancestor-symlink.out" || \
    fail "ancestor symlink rejection was not explicit"
[ ! -e "$real_parent/helper" ] || fail "ancestor symlink installation wrote through the link"

wrong_hash=0000000000000000000000000000000000000000000000000000000000000000
if $helper install --json --target "$tmp/wrong-hash-helper" --sha256 "$wrong_hash" \
        >"$tmp/wrong-hash.out" 2>&1; then
    fail "install accepted a forged artifact hash"
fi

session_socket="$tmp/session.sock"
session_metadata="$tmp/session.json"
session_log="$tmp/session.log"
start=$(printf '%s\n' "$session_token" | $target session-start --json \
    --session-id distro-smoke-session-0001 --token-stdin \
    --socket "$session_socket" --metadata "$session_metadata" --log "$session_log" \
    --kind service --command "trap '' TERM; while :; do sleep 1; done")
case "$start" in
    *"\"running\":true"*"\"tokenHash\":"*) ;;
    *) fail "session did not start: $start" ;;
esac
[ "$(stat -c %a -- "$session_socket")" = 600 ] || fail "session socket mode is not 0600"
[ "$(stat -c %a -- "$session_metadata")" = 600 ] || fail "session metadata mode is not 0600"

forged_token=ffffffffffffffffffffffffffffffffffffffffffffffff
if forged=$($target session-status --json --socket "$session_socket" \
        --metadata "$session_metadata" --token "$forged_token" 2>&1); then
    :
fi
case "$forged" in
    *"\"ok\":false"*"session token authentication failed"*) ;;
    *) fail "forged token was not explicitly rejected: $forged" ;;
esac

stop=$($target session-stop --json --socket "$session_socket" \
    --metadata "$session_metadata" --token "$session_token" --timeout-ms 100)
case "$stop" in
    *"\"running\":true"*"\"requiresForce\":true"*) ;;
    *) fail "graceful stop did not preserve force boundary: $stop" ;;
esac
forced=$($target session-force-stop --json --socket "$session_socket" \
    --metadata "$session_metadata" --token "$session_token" --timeout-ms 5000)
case "$forced" in
    *"\"running\":false"*"\"status\":\"stopped\""*) ;;
    *) fail "force stop did not finish the session: $forced" ;;
esac
session_socket=

printf '%s\n' "distro smoke passed: sha256=$expected"
