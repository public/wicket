#!/usr/bin/env bash
# The attack matrix (#215, #326): a program box told to get out of its reach, with values planted
# where it must not get to, and every way out it tries checked from outside. Deterministic: no model.
# Needs Docker with the runsc runtime and the agent image (`wicket image`); the network for
# example.com and an echo host (httpbin.org or httpbingo.org; if neither answers, their rows are
# skipped, with a warning).
#
#   WICKET=target/debug/wicket ci/attack-matrix.sh      (IMAGE=tag for an image other than the default)
#
# Planted (fresh random values each run):
#   - a secret injected only on an allowed host (the echo host, which answers with the request it got);
#   - a file outside the box's volumes, in a host directory and in wicket's data directory;
#   - another box's exposed port, and a request of its own left pending;
#   - the control host's sockets: a unix socket by path, an abstract one, and an HTTP canary on all the
#     host's addresses;
#   - a per-node service the box's zone uses, whose reach is wider than the box's (so its link needs a
#     human, who never comes);
#   - a value the box holds (BOX_MARK), which must leave only to the hosts its zone reaches.
# The box (ci/attack/attack.sh) writes one line per attempt; ci/attack/expected.tsv says what each
# must come to, and is compared exactly: an attempt that got through (GOT), changed outcome, is new
# or is missing fails the run, named. Then, from outside: no canary in anything the box got back or
# left behind, the canaries' listeners saw nothing, no file appeared outside the run, the audit
# allowed only what the zone reaches (and the one prefix an operator granted here), nothing else was
# granted, linked or approved, a run claiming the service's zone was refused, and the audit chain and
# `wicket doctor --invariants` hold.
#
# Env: WICKET, IMAGE, ATTACK_KEEP=1 (keep the work dir), ATTACK_TMP (where it goes, default /tmp:
# keep it short, the runs' unix sockets live under it).
set -euo pipefail

WICKET=$(realpath "${WICKET:-target/debug/wicket}")
cd "$(dirname "$0")/.."
here=$PWD

work=$(mktemp -d "${ATTACK_TMP:-/tmp}/watk.XXXXXX")
chmod 755 "$work"
if [ ${#work} -gt 24 ]; then echo "$work: too long a path for the runs' sockets (ATTACK_TMP=/tmp)" >&2; rm -rf "$work"; exit 2; fi
export WICKET_HOME=$work/home HOME=$work/userhome
export WICKET_BOX_PREFIX=atk-$$
mkdir -p "$WICKET_HOME" "$HOME"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  "$WICKET" service remove atk-svc >/dev/null 2>&1 || true
  # The boxes this run started (named after its prefix).
  docker ps -aq --filter "name=^$WICKET_BOX_PREFIX-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  if [ "${ATTACK_KEEP:-}" = 1 ]; then echo "kept $work"; else rm -rf "$work" 2>/dev/null || sudo -n rm -rf "$work" 2>/dev/null || true; fi
}
trap cleanup EXIT
w() { "$WICKET" "$@"; }
rand() { python3 -I -c 'import secrets; print(secrets.token_hex(16))'; }
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
wait_for() { local n=$1; shift; for _ in $(seq "$n"); do (set +o pipefail; eval "$1") && return 0; sleep 1; done; return 1; }
run_id_of() { sed -n 's/^wicket run \(run_[a-z0-9]*\).*/\1/p' "$1" | head -1; }
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; [ -z "${GITHUB_ACTIONS:-}" ] || echo "::error title=attack matrix::$1"; fi; }
log() { echo "== $*"; }

# ---- the planted values ----
C_INJECT=atk$(rand)  # the injected secret
C_FILE=atk$(rand)    # a host file, and one in wicket's data directory
C_PEER=atk$(rand)    # another box's exposed port
C_SOCK=atk$(rand)    # the host's unix sockets
C_SVC=atk$(rand)     # the service's port
BOX_MARK=atk$(rand)  # held by the box: may leave only to what its zone reaches
canaries=("$C_INJECT" "$C_FILE" "$C_PEER" "$C_SOCK" "$C_SVC")
names=(injected-secret host-file peer-port host-socket service-port)

log "setup"
w identity init --trust-domain atk.wicket.test >/dev/null
printf '%s' "$C_INJECT" | w secret set atk-canary --hosts httpbin.org,httpbingo.org >/dev/null
printf '%s\n' "$C_FILE" >"$work/host-secret.txt"
printf '%s\n' "$C_FILE" >"$WICKET_HOME/atk-canary.txt"
host_sum=$(sha256sum "$work/host-secret.txt")

# An HTTP canary on every host address, and unix sockets by path and abstract: each logs any hit.
canary_port=$(free_port)
host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
abstract=atk-$(rand)
: >"$work/hits.log"
python3 -I - "$canary_port" "$work/hits.log" "$work/ctl.sock" "$abstract" "$C_SOCK" <<'PY' &
import http.server, socket, sys, threading
port, log, path, abstract, value = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5].encode()
def hit(what):
    with open(log, "a") as f:
        f.write(what + "\n")
class Canary(http.server.BaseHTTPRequestHandler):
    def h(self):
        hit(f"http {self.client_address[0]} {self.command} {self.path}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(value)
    do_GET = do_POST = do_PUT = do_CONNECT = do_HEAD = h
    def log_message(self, *a):
        pass
def unix(addr, what):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(addr)
    s.listen(8)
    while True:
        c, _ = s.accept()
        hit(what)
        c.sendall(value)
        c.close()
threading.Thread(target=unix, args=(path, "unix socket"), daemon=True).start()
threading.Thread(target=unix, args=("\0" + abstract, "abstract socket"), daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", port), Canary).serve_forever()
PY
pids+=("$!")
wait_for 10 "(exec 3<>/dev/tcp/127.0.0.1/$canary_port) 2>/dev/null"
: >"$work/hits.log"

# ---- the service (#579), and runs claiming its zone ----
mkdir -p "$work/svc/svc/www"
cp ci/attack/svc.yaml "$work/svc/svc.yaml"
printf '%s\n' "$C_SVC" >"$work/svc/svc/www/index.html"
w service add "$work/svc/svc.yaml" >"$work/svc-add.log" 2>&1
check "the service atk-svc is installed" 'w service list 2>/dev/null | grep -q atk-svc'
# A run in the service's zone (it would share the service's volumes), and one saying it is the service.
printf 'task: claim\nprogram: { name: claim, command: [cat, /workspace/www/index.html] }\nzone: { name: atk-svc, isolation: gvisor }\n' >"$work/svc/claim-zone.yaml"
mkdir -p "$work/claim/www"
claim_status=0
timeout 120 "$WICKET" run "$work/svc/claim-zone.yaml" --workdir "$work/claim" ${IMAGE:+--image "$IMAGE"} >"$work/claim-zone.log" 2>&1 || claim_status=$?
check "a run claiming the service's zone is refused" '[ "$claim_status" != 0 ] && grep -q "is service atk-svc" "$work/claim-zone.log"'

# ---- the peer: a canary port, exposed, and a request of its own ----
mkdir -p "$work/peer/www"
cp ci/attack/peer.sh "$work/peer/"
printf '%s\n' "$C_PEER" >"$work/peer/www/index.html"
"$WICKET" run ci/attack/peer.yaml --workdir "$work/peer" ${IMAGE:+--image "$IMAGE"} >"$work/peer.log" 2>&1 &
pids+=("$!")
wait_for 120 '[ -n "$(run_id_of "$work/peer.log")" ]' || true
peer=$(run_id_of "$work/peer.log")
peer_dir=$WICKET_HOME/runs/$peer
wait_for 120 '[ -e "$peer_dir/workspace/out/ready" ]' || true
check "the peer box runs and exposed its port" '[ -e "$peer_dir/workspace/out/ready" ] && grep -q "8000" "$peer_dir/workspace/out/expose.json"'
peer_request=$(grep -oE 'r-[0-9a-z]+' "$peer_dir/workspace/out/request.json" 2>/dev/null | head -1 || true)
peer_principal=$(grep -oE 'spiffe://[^"\\ ]+/a/peer' "$peer_dir/workspace/out/whoami.json" 2>/dev/null | head -1 || true)
check "the peer has a request pending (${peer_request:-none})" '[ -n "$peer_request" ]'

# ---- the attacker ----
ws=$work/atk
mkdir -p "$ws/out"
cp ci/attack/attack.sh "$ws/"
cat >"$ws/atk.env" <<EOF
HOST_IP=${host_ip:-127.0.0.1}
CANARY_PORT=$canary_port
HOST_DIR=$work
HOST_FILE=$work/host-secret.txt
DATA_FILE=$WICKET_HOME/atk-canary.txt
VAULT_FILE=$HOME/.config/wicket/secrets
HOST_SOCK=$work/ctl.sock
ABSTRACT=$abstract
PEER_RUN=$peer
PEER_DIR=$peer_dir
PEER_PRINCIPAL=$peer_principal
PEER_REQUEST=$peer_request
SVC_PORT=4873
BOX_MARK=$BOX_MARK
EOF
# The run's own directory, as the host names it, once it has one.
# The reconciler keeps the service's instance on this node while the attacker uses it.
"$WICKET" reconcile --every 10s >"$work/reconcile.log" 2>&1 &
pids+=("$!")
# The operator: grants the one prefix the attacker asks for (scope prefix), nothing else.
(
  for _ in $(seq 240); do
    id=$(w pending 2>/dev/null | grep 'anything/granted' | grep -oE 'r-[0-9a-z]+' | head -1 || true)
    if [ -n "$id" ]; then w approve "$id" --uses 20 --yes >"$work/approve.log" 2>&1; exit; fi
    sleep 1
  done
) &
pids+=("$!")
# The service's instance, named to the attacker (in its live workspace) once it starts.
(
  for _ in $(seq 300); do
    svc_run=$(w audit --tail 2000 2>/dev/null | awk '$3 == "service.instance_started" {print $4}' | tail -1)
    atk_now=$(run_id_of "$work/attack.log")
    if [ -n "$svc_run" ] && [ -n "$atk_now" ] && [ -d "$WICKET_HOME/runs/$atk_now/workspace" ]; then
      printf '%s\n' "$svc_run" >"$WICKET_HOME/runs/$atk_now/workspace/svc.run"
      exit
    fi
    sleep 1
  done
) &
pids+=("$!")
log "wicket run ci/attack/attack.yaml"
atk_status=0
# RUN_DIR: the attacker learns its run id from WICKET_RUN; the host path is the data dir's.
echo "RUN_DIR=$WICKET_HOME/runs/\$WICKET_RUN" >>"$ws/atk.env"
timeout 600 "$WICKET" run ci/attack/attack.yaml --workdir "$ws" ${IMAGE:+--image "$IMAGE"} >"$work/attack.log" 2>&1 || atk_status=$?
atk=$(run_id_of "$work/attack.log")
atk_dir=$WICKET_HOME/runs/$atk
grep -E '^\[(wicket|egress)\]' "$work/attack.log" | sed 's/^/   /' | head -400
for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
wait 2>/dev/null || true
pids=()

log "the matrix"
attempts=$atk_dir/workspace/out/attempts.tsv
check "the attacker ran (run ${atk:-?}, exit $atk_status) and wrote its attempts" '[ -s "$attempts" ]'
# Every attempt against expected.tsv, exactly. GOT is never expected.
compare=$(python3 -I - ci/attack/expected.tsv "$attempts" <<'PY'
import sys
exp, got = {}, {}
for line in open(sys.argv[1]):
    if line.strip() and not line.startswith("#"):
        a, o = line.rstrip("\n").split("\t")[:2]
        exp[a] = o
detail = {}
for line in open(sys.argv[2]):
    f = line.rstrip("\n").split("\t")
    if len(f) >= 2:
        got[f[0]] = f[1]
        detail[f[0]] = f[2] if len(f) > 2 else ""
for a, o in got.items():
    # Not tried here (an upstream or a name it needs didn't answer): warned about, never an escape.
    if o == "skipped" and a in exp:
        print(f"SKIPPED\t{a}\t{detail[a]}")
        continue
    if o == "GOT":
        print(f"ESCAPED\t{a}\t{detail[a]}")
    elif a not in exp:
        print(f"NEW\t{a}\t{o}: {detail[a]}")
    elif exp[a] != o:
        print(f"CHANGED\t{a}\texpected {exp[a]}, got {o}: {detail[a]}")
for a in exp:
    if a not in got:
        print(f"MISSING\t{a}\texpected {exp[a]}, not tried")
PY
)
total=$(grep -c . "$attempts" 2>/dev/null || true)
echo "   $total attempts; $(awk -F'\t' '$2 == "GOT"' "$attempts" 2>/dev/null | grep -c . || true) got through"
if [ -n "$compare" ]; then
  while IFS=$'\t' read -r kind a d; do
    echo "   $kind $a: $d"
    level=error
    [ "$kind" != SKIPPED ] || level=warning
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::$level title=attack matrix: $kind $a::$(sed 's/%/%25/g' <<<"$d")"
  done <<<"$compare"
fi
check "no attempt got through (GOT)" '! grep -q "^ESCAPED" <<<"$compare"'
check "every attempt came to what expected.tsv says (skipped ones warned about)" '[ -z "$compare" ] || ! grep -qv "^SKIPPED" <<<"$compare"'

log "the canaries, from outside"
b64() { printf '%s' "$1" | base64 -w0; }
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
# Anywhere the box could read or leave anything: its run directory (workspace, state, the forwarder's
# directory), its volumes, and the output it printed.
box_seen() { # value
  grep -rqsF -e "$1" -e "$(b64 "$1")" -e "$(hex "$1")" "$atk_dir" "$WICKET_HOME/local-node" 2>/dev/null && return 0
  grep -qF -e "$1" -e "$(b64 "$1")" "$work/attack.log" 2>/dev/null
}
for i in "${!canaries[@]}"; do
  where=$(grep -rlsF -e "${canaries[$i]}" -e "$(b64 "${canaries[$i]}")" -e "$(hex "${canaries[$i]}")" "$atk_dir" "$WICKET_HOME/local-node" "$work/attack.log" 2>/dev/null | sed "s#$work/##" | head -5 | tr '\n' ' ' || true)
  check "the ${names[$i]} canary is nowhere the box could see${where:+ (found in: $where)}" '! box_seen "${canaries[$i]}"'
done
check "the canary listeners (HTTP on every host address, unix and abstract sockets) saw nothing" '[ ! -s "$work/hits.log" ] || { sed "s/^/     hit: /" "$work/hits.log"; false; }'
check "nothing was written outside the run through its symlinks" '[ ! -e "$work/pwned-out" ] && [ ! -e "$work/pwned-vol" ]'
check "the host file is unchanged" '[ "$(sha256sum "$work/host-secret.txt")" = "$host_sum" ]'
check "the box's own Authorization header never reached the echo host" '! grep -qsF "$BOX_MARK" "$atk_dir/workspace/out/bodies/reflect-own-auth"'

log "the audit, from outside"
# The attacker's allowed egress: method, host and path of each request the audit allowed (DNS
# answers are wicket's own, from its synthetic range: nothing leaves by them).
allowed() {
  w audit --tail 50000 | python3 -I -c '
import json, sys
run = sys.argv[1]
for line in sys.stdin:
    f = line.split(None, 4)
    if len(f) < 5 or f[3] != run:
        continue
    try:
        b = json.loads(f[4])
        if f[2] == "node.audit":
            b = json.loads(b["body"]) if b.get("kind") == "op" else {}
    except (ValueError, KeyError, TypeError):
        continue
    if b.get("kind") == "egress" and b.get("outcome") in ("allow", "spliced") and b.get("method") != "DNS":
        print(b.get("method"), b.get("host"), b.get("path"))
' "$atk"
}
unexpected() {
  allowed | python3 -I -c '
import posixpath, re, sys, urllib.parse
ECHO = ("httpbin.org", "httpbingo.org")
for line in sys.stdin:
    m, h, p = (line.split(" ", 2) + ["", ""])[:3]
    p = p.strip().split("?")[0]
    q = posixpath.normpath(urllib.parse.unquote(p)) if p else p
    ok = m == "GET" and (
        (h == "example.com" and p == "/")
        or (h in ECHO and (q == "/get" or q.startswith("/anything/public/")) and not q.lower().startswith("/anything/public/forbidden"))
        or (h in ECHO and (q == "/anything/granted" or q.startswith("/anything/granted/")))
        or re.fullmatch(r"([0-9.]+\.)?nip\.io|localtest\.me", h or "") is not None
    )
    if not ok:
        print(line.rstrip())
' | sort | uniq -c
}
check "the audit allowed the attacker nothing its zone and the one prefix grant don't cover" '[ -z "$(unexpected)" ] || { unexpected | sed "s/^/     allowed: /"; false; }'
check "  and nothing it holds left to any other host" '! allowed | grep -vE "^GET (example\.com|httpbin\.org|httpbingo\.org) " | grep -qF "$BOX_MARK"'
# Grants other than each run's quotas and the operator's digest grant: only the prefix.
grants=$(w grant list --all 2>/dev/null | grep -vE "quota |  DIGEST " || true)
prefix_req=$(cat "$atk_dir/workspace/out/prefix.request" 2>/dev/null || true)
check "the only grant is the one prefix the operator granted" '[ "$(grep -c . <<<"$grants")" = 1 ] && grep -q "anything/granted/\* \[prefix\]" <<<"$grants" || { sed "s/^/     grant: /" <<<"$grants"; false; }'
decisions=$(w audit --tail 50000 | awk '$3 == "decision"' || true)
check "the only decision is the operator's on that prefix (${prefix_req:-?}): nothing the attacker said decided the peer's" '[ -n "$prefix_req" ] && [ "$(grep -c . <<<"$decisions")" = 1 ] && grep -q "\"request\":\"$prefix_req\"" <<<"$decisions"'
check "no standing rule was approved (the attacker's ask is pending)" 'w standing list --all 2>/dev/null | grep -q "pending" && ! w standing list --all 2>/dev/null | grep -qiE "approved|active"'
check "the service's instance ran on the node (so its link was there to refuse)" 'w audit --tail 50000 | awk "\$3 == \"service.instance_started\"" | grep -q "\"error\":null"'
links=$(w links --tail 200 2>/dev/null || true)
check "no link opened to the peer or the service for the attacker" '! grep "$atk" <<<"$links" | grep -iE "open|live" | grep -qE "$peer|atk-svc|8000|4873"'
check "the service's link needed a human, who never came" 'grep -qE "atk-svc on node .*(approv|request)" "$work/attack.log"'
check "the audit chain verifies" 'w audit --verify >/dev/null'
check "wicket doctor --invariants holds" 'w doctor --invariants >"$work/invariants.log" 2>&1 || { tail -20 "$work/invariants.log"; false; }'

if [ "$fail" != 0 ]; then
  echo "== the attacker's attempts"; cat "$attempts" 2>/dev/null || true
  echo "== the attacker's run (tail)"; tail -60 "$work/attack.log" || true
  echo "attack matrix FAILED"
  exit 1
fi
echo "attack matrix passed: $total attempts, none got through"
