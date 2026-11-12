#!/usr/bin/env bash
# wicketd with real, different uids (#12), without installing anything: the daemon runs as this
# user, and the CLI as `nobody` (an operator the policy names) and as root (the host break-glass),
# through sudo. Checks that the operator's uid can read state but can't open the data or approve,
# and that root can. Needs passwordless sudo (GitHub's runners have it).
#   ci/daemon-uids.sh [path/to/wicket]
set -euo pipefail
bin=$(realpath "${1:-target/debug/wicket}")
d=$(mktemp -d /tmp/wicket-uids.XXXXXX)
chmod 755 "$d"
pid=
cleanup() {
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$d"
}
trap cleanup EXIT

cp "$bin" "$d/wicket"
chmod 755 "$d/wicket"
nobody_uid=$(id -u nobody)
printf 'read: {users: ["%s"]}\nrun: {users: ["%s"]}\nrevoke: {users: ["%s"]}\n' "$nobody_uid" "$nobody_uid" "$nobody_uid" >"$d/policy.yaml"
WICKET_HOME="$d/data" HOME="$d/data" "$d/wicket" daemon --socket "$d/wicketd.sock" --policy "$d/policy.yaml" 2>"$d/daemon.log" &
pid=$!
for _ in $(seq 50); do [ -S "$d/wicketd.sock" ] && break; sleep 0.1; done
[ -S "$d/wicketd.sock" ] || { cat "$d/daemon.log"; exit 1; }

as_nobody() { (cd / && sudo -n -u nobody env -i PATH=/usr/bin:/bin WICKET_DAEMON_SOCKET="$d/wicketd.sock" "$d/wicket" "$@"); }
as_root() { (cd / && sudo -n env -i PATH=/usr/bin:/bin WICKET_DAEMON_SOCKET="$d/wicketd.sock" "$d/wicket" "$@"); }
fail() { echo "FAIL: $*"; cat "$d/daemon.log"; exit 1; }

# Root sets up the issuer, as the install script does.
as_root identity init --trust-domain wicket.example.com >/dev/null || fail "root: identity init"

# The operator reads state through the daemon...
out=$(as_nobody pending) || fail "nobody: pending: $out"
[ "$out" = "no pending requests" ] || fail "nobody: pending said: $out"
as_nobody audit --verify >/dev/null || fail "nobody: audit --verify"
echo "ok: the operator's uid reads state through wicketd"

# ...but can't open the data itself.
[ "$(stat -c %a "$d/data")" = 700 ] || fail "data dir mode $(stat -c %a "$d/data")"
if sudo -n -u nobody cat "$d/data/ledger.db" >/dev/null 2>&1; then fail "nobody opened the ledger"; fi
if sudo -n -u nobody ls "$d/data" >/dev/null 2>&1; then fail "nobody listed the data dir"; fi
echo "ok: the operator's uid can't open the data directory or the ledger"

# It can't approve, deny, set secrets or enrol a passkey.
for c in "approve R1" "deny R1" "operator enrol-link" "operator reset" "identity init --trust-domain x.example"; do
    # shellcheck disable=SC2086
    if out=$(as_nobody $c 2>&1); then fail "nobody: $c succeeded: $out"; fi
    case "$out" in *"needs root on the host"*) ;; *) fail "nobody: $c: $out" ;; esac
done
if out=$(echo value | as_nobody secret set x 2>&1); then fail "nobody: secret set succeeded: $out"; fi
echo "ok: the operator's uid can't approve, deny, enrol a passkey or set a secret"

# Root gets through the policy (and then finds no such request).
out=$(as_root approve R1 2>&1) && fail "root: approve of a missing request succeeded"
case "$out" in *"needs root"*) fail "root was refused: $out" ;; esac
case "$out" in *R1*) ;; *) fail "root: approve: $out" ;; esac
echo "value-from-root" | as_root secret set ci-test >/dev/null || fail "root: secret set"
[ "$(as_root secret list)" = "ci-test" ] || fail "root: secret list"
[ "$(cat "$d/data/.config/wicket/secrets/ci-test")" = "value-from-root" ] || fail "the secret didn't land in the daemon's vault"
[ "$(stat -c %U "$d/data/.config/wicket/secrets/ci-test")" = "$(id -un)" ] || fail "the secret is not the daemon user's"
echo "ok: root (the host break-glass) approves and sets secrets, as the daemon's user"

# Refusals are audited, and the chain verifies.
n=$(as_root audit --tail 100 | grep -c daemon.refused) || true
[ "$n" -ge 6 ] || fail "only $n refusals audited"
as_root audit --verify >/dev/null || fail "audit chain"
echo "ok: $n refusals in the audit log; the chain verifies"
echo "daemon-uids: all checks passed"
