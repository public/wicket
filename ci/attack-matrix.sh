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
C_SVC2=atk$(rand)    # the second service's port (one the attacker's zone doesn't use)
BOX_MARK=atk$(rand)  # held by the box: may leave only to what its zone reaches
DOMAIN_MARK=atk$(rand) # the registered domain the box makes wicket look up (#19's known channel)
canaries=("$C_INJECT" "$C_FILE" "$C_PEER" "$C_SOCK" "$C_SVC" "$C_SVC2")
names=(injected-secret host-file peer-port host-socket service-port second-service-port)

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

# ---- the services (#579), and a run claiming one's zone ----
svc_add() { # manifest, canary, dir
  mkdir -p "$work/$3/svc/www"
  cp "ci/attack/$1" "$work/$3/$1"
  printf '%s\n' "$2" >"$work/$3/svc/www/index.html"
  w service add "$work/$3/$1" >"$work/$3/add.log" 2>&1
}
svc_add svc.yaml "$C_SVC" svc
svc_add svc2.yaml "$C_SVC2" svc2
check "the services atk-svc and atk-svc2 are installed" 'w service list 2>/dev/null | grep -q "atk-svc " && w service list 2>/dev/null | grep -q atk-svc2'
# A run in the service's zone: it would share the service's volumes.
printf 'task: claim\nprogram: { name: claim, command: [cat, /workspace/www/index.html] }\nzone: { name: atk-svc, isolation: gvisor }\n' >"$work/svc/claim-zone.yaml"
mkdir -p "$work/claim/www"
claim_status=0
timeout 120 "$WICKET" run "$work/svc/claim-zone.yaml" --workdir "$work/claim" ${IMAGE:+--image "$IMAGE"} >"$work/claim-zone.log" 2>&1 || claim_status=$?
check "a run claiming the service's zone is refused" '[ "$claim_status" != 0 ] && grep -q "is service atk-svc" "$work/claim-zone.log"'

# The reconciler keeps each service's instance on this node while a box uses it.
"$WICKET" reconcile --every 10s >"$work/reconcile.log" 2>&1 &
pids+=("$!")

# ---- the peer: a canary port, exposed; a request and a standing ask of its own; atk-svc2 ----
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
peer_standing=$(grep -oE 's-[0-9a-z]+' "$peer_dir/workspace/out/standing.json" 2>/dev/null | head -1 || true)
peer_principal=$(grep -oE 'spiffe://[^"\\ ]+/a/peer' "$peer_dir/workspace/out/whoami.json" 2>/dev/null | head -1 || true)
check "the peer has a request (${peer_request:-none}) and a standing ask (${peer_standing:-none}) pending" '[ -n "$peer_request" ] && [ -n "$peer_standing" ]'

# ---- the host's DNS traffic, captured while the attacker runs ----
# Whether a label the box chose left the host: BOX_MARK must never be in it; DOMAIN_MARK (#19's
# registered-domain lookup, which the box triggers on purpose) must be, or the capture saw nothing.
pcap=$work/dns.pcap
capture=0
if command -v tcpdump >/dev/null && sudo -n true 2>/dev/null; then
  sudo -n tcpdump -i any -n -U -s 0 -w "$pcap" 'port 53' >"$work/tcpdump.log" 2>&1 &
  tcpdump_pid=$!
  sleep 2
  capture=1
elif [ -n "${GITHUB_ACTIONS:-}" ]; then
  check "tcpdump and sudo are here to capture the host's DNS traffic" false
else
  echo "WARNING: no tcpdump (or no sudo): the host's DNS traffic isn't checked"
fi

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
PEER_STANDING=$peer_standing
SVC_PORT=4873
SVC2_PORT=4874
BOX_MARK=$BOX_MARK
DOMAIN_MARK=$DOMAIN_MARK
EOF
# RUN_DIR: the attacker learns its run id from WICKET_RUN; the host path is the data dir's.
echo "RUN_DIR=$WICKET_HOME/runs/\$WICKET_RUN" >>"$ws/atk.env"
# The operator: grants the one prefix and approves the one narrow standing rule the attacker asks
# for, nothing else.
(
  done_p='' done_s=''
  for _ in $(seq 400); do
    if [ -z "$done_p" ]; then
      id=$(w pending 2>/dev/null | grep 'anything/granted' | grep -oE 'r-[0-9a-z]+' | head -1 || true)
      [ -z "$id" ] || { w approve "$id" --uses 20 --yes >"$work/approve.log" 2>&1; done_p=1; }
    fi
    if [ -z "$done_s" ]; then
      id=$(w standing list 2>/dev/null | grep 'anything/standing' | grep pending | grep -oE '^s-[0-9a-z]+' | head -1 || true)
      [ -z "$id" ] || { w standing approve "$id" --lasts 1h --yes >"$work/standing-approve.log" 2>&1; done_s=1; }
    fi
    [ -n "$done_p" ] && [ -n "$done_s" ] && exit
    sleep 1
  done
) &
pids+=("$!")
# Each service's instance, named to the attacker (in its live workspace) once it starts.
(
  n1='' n2=''
  for _ in $(seq 400); do
    atk_now=$(run_id_of "$work/attack.log")
    if [ -n "$atk_now" ] && [ -d "$WICKET_HOME/runs/$atk_now/workspace" ]; then
      started=$(w audit --tail 5000 2>/dev/null | awk '$3 == "service.instance_started"' || true)
      r1=$(grep '"service":"atk-svc"' <<<"$started" | awk '{print $4}' | tail -1 || true)
      r2=$(grep '"service":"atk-svc2"' <<<"$started" | awk '{print $4}' | tail -1 || true)
      [ -n "$n1" ] || [ -z "$r1" ] || { printf '%s\n' "$r1" >"$WICKET_HOME/runs/$atk_now/workspace/svc.run"; n1=1; }
      [ -n "$n2" ] || [ -z "$r2" ] || { printf '%s\n' "$r2" >"$WICKET_HOME/runs/$atk_now/workspace/svc2.run"; n2=1; }
      [ -n "$n1" ] && [ -n "$n2" ] && exit
    fi
    sleep 1
  done
) &
pids+=("$!")
log "wicket run ci/attack/attack.yaml"
atk_status=0
timeout 600 "$WICKET" run ci/attack/attack.yaml --workdir "$ws" ${IMAGE:+--image "$IMAGE"} >"$work/attack.log" 2>&1 || atk_status=$?
atk=$(run_id_of "$work/attack.log")
atk_dir=$WICKET_HOME/runs/$atk
grep -E '^\[(wicket|egress)\]' "$work/attack.log" | sed 's/^/   /' | head -400
if [ "$capture" = 1 ]; then sudo -n kill "$tcpdump_pid" 2>/dev/null || sudo -n pkill -f "tcpdump -i any -n -U -s 0 -w $pcap" || true; sleep 1; fi
for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
wait 2>/dev/null || true
pids=()

log "the matrix"
attempts=$atk_dir/workspace/out/attempts.tsv
check "the attacker ran (run ${atk:-?}, exit $atk_status) and wrote its attempts" '[ -s "$attempts" ]'
# Every line against expected.tsv, exactly: a GOT on any line, an attempt tried twice, one changed,
# new or missing fails. GOT is never expected. Skips are warned about, and bounded below.
compare=$(python3 -I - ci/attack/expected.tsv "$attempts" <<'PY'
import sys
exp, got, detail = {}, {}, {}
for line in open(sys.argv[1]):
    if line.strip() and not line.startswith("#"):
        a, o = line.rstrip("\n").split("\t")[:2]
        exp[a] = o
for line in open(sys.argv[2]):
    f = line.rstrip("\n").split("\t")
    if len(f) < 2:
        continue
    a, o, d = f[0], f[1], (f[2] if len(f) > 2 else "")
    if o == "GOT":
        print(f"ESCAPED\t{a}\t{d}")
    if a in got:
        print(f"TWICE\t{a}\t{got[a]}, then {o}: {d}")
        continue
    got[a], detail[a] = o, d
for a, o in got.items():
    if o == "GOT":
        continue
    if o == "skipped" and a in exp:
        print(f"SKIPPED\t{a}\t{detail[a]}")
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
skips=$(grep -c '^SKIPPED' <<<"$compare" || true)
check "no attempt got through (GOT)" '! grep -q "^ESCAPED" <<<"$compare"'
check "every attempt came to what expected.tsv says (skipped ones warned about)" '[ -z "$compare" ] || ! grep -qv "^SKIPPED" <<<"$compare"'
# Skips are bounded: in CI the echo host must answer (or its ~50 rows would only warn), and at most
# MAX_SKIPS rows may be skipped anywhere (the rebind rows, when a name doesn't resolve on the host).
check "at most ${MAX_SKIPS:=6} attempts skipped ($skips)" '[ "$skips" -le "$MAX_SKIPS" ]'
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  check "an echo host answered (its rows weren't skipped)" '! grep -q $'"'"'^control-echo\tskipped'"'"' "$attempts"'
fi

log "the canaries, from outside"
b64() { printf '%s' "$1" | base64 -w0; }
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
# Anywhere the box could read or leave anything (its run directory: workspace, state, the
# forwarder's directory; the node's directory, its volumes), and the output it printed: raw, in
# base64 and in hex.
seen_in() { grep -rlsF -e "$1" -e "$(b64 "$1")" -e "$(hex "$1")" "$atk_dir" "$WICKET_HOME/local-node" "$work/attack.log" 2>/dev/null || true; }
for i in "${!canaries[@]}"; do
  where=$(seen_in "${canaries[$i]}" | sed "s#$work/##" | head -5 | tr '\n' ' ')
  check "the ${names[$i]} canary is nowhere the box could see${where:+ (found in: $where)}" '[ -z "$where" ]'
done
check "the canary listeners (HTTP on every host address, unix and abstract sockets) saw nothing" '[ ! -s "$work/hits.log" ] || { sed "s/^/     hit: /" "$work/hits.log"; false; }'
check "nothing was written outside the run through its symlinks" '[ ! -e "$work/pwned-out" ] && [ ! -e "$work/pwned-vol" ]'
check "the host file is unchanged" '[ "$(sha256sum "$work/host-secret.txt")" = "$host_sum" ]'
check "the box's own Authorization header never reached the echo host" '[ -s "$atk_dir/workspace/out/bodies/reflect-own-auth" ] && ! grep -qsF "$BOX_MARK" "$atk_dir/workspace/out/bodies/reflect-own-auth"'
if [ "$capture" = 1 ]; then
  # Every name the host asked its resolvers for, while the attacker ran.
  sudo -n tcpdump -nr "$pcap" 'dst port 53' 2>/dev/null | grep -oE '[A-Z]+\? [^ ]+' | awk '{print tolower($2)}' | sed 's/\.$//' | sort -u >"$work/dns-names.txt" || true
  # The names the box chose carry one of the run's marks. #19's lookups (DOMAIN_MARK) are the known
  # channel: each only a registered domain (one label under .com, as the box asked for them), at
  # most 256 per run. Any other name with a mark (BOX_MARK, or a label under a registered domain)
  # is a label that left.
  chosen=$(grep -E "atk[0-9a-f]{32}" "$work/dns-names.txt" || true)
  known=$(grep -xE "${DOMAIN_MARK}(n[0-9]+)?\.com" <<<"$chosen" || true)
  leaked=$(grep -vxE "${DOMAIN_MARK}(n[0-9]+)?\.com" <<<"$chosen" | grep . || true)
  n_known=$(grep -c . <<<"$known" || true)
  echo "   the host's DNS capture: $(grep -c . "$work/dns-names.txt" || true) names, $n_known registered-domain lookups the box chose (#19)"
  check "the host's DNS capture saw the registered-domain lookup (#19), so it saw DNS at all" 'grep -qx "$DOMAIN_MARK.com" <<<"$known"'
  check "  #19's lookups stayed within its bound: at most 256 per run (${n_known})" '[ "$n_known" -le 256 ]'
  check "no other label the box chose left the host by DNS" '[ -z "$leaked" ] || { sed "s/^/     left: /" <<<"$leaked" | head -20; false; }'
fi

log "the audit, from outside"
audit_all=$work/audit.txt
audit_ok=0
w audit --tail 50000 >"$audit_all" 2>"$work/audit.err" && audit_ok=1
check "wicket audit reads" '[ "$audit_ok" = 1 ] && [ -s "$audit_all" ] || { cat "$work/audit.err"; false; }'
# The attacker's allowed egress: method, host and path of each request the audit allowed (DNS
# answers are wicket's own, from its synthetic range: the capture above checks nothing left by them).
# The audit's egress records carry no port; the port rows are checked in the box (other-port*).
allowed() {
  python3 -I -c '
import json, sys
run = sys.argv[1]
for line in open(sys.argv[2]):
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
' "$atk" "$audit_all"
}
allowed >"$work/allowed.txt"
echo_host=$(sed -n 's#^control-echo\tok\tGET https://\([^/]*\)/get.*#\1#p' "$attempts")
check "the audit shows the zone's own requests allowed (GET example.com / and GET ${echo_host:-<echo>} /get)" 'grep -qx "GET example.com /" "$work/allowed.txt" && { [ -z "$echo_host" ] || grep -qx "GET $echo_host /get" "$work/allowed.txt"; }'
unexpected() {
  python3 -I -c '
import posixpath, re, sys, urllib.parse
ECHO = ("httpbin.org", "httpbingo.org")
for line in open(sys.argv[1]):
    m, h, p = (line.split(" ", 2) + ["", ""])[:3]
    p = p.strip().split("?")[0]
    q = posixpath.normpath(urllib.parse.unquote(p)) if p else p
    ok = m == "GET" and (
        (h == "example.com" and p == "/")
        or (h in ECHO and (q == "/get" or q.startswith("/anything/public/")) and not q.lower().startswith("/anything/public/forbidden"))
        or (h in ECHO and (q == "/anything/granted" or q.startswith("/anything/granted/")))
        or (h in ECHO and q.startswith("/anything/standing/"))
        or re.fullmatch(r"([0-9.]+\.)?nip\.io|localtest\.me", h or "") is not None
    )
    if not ok:
        print(line.rstrip())
' "$work/allowed.txt" | sort | uniq -c
}
check "the audit allowed the attacker nothing its zone, the prefix grant and the standing rule don't cover" '[ -z "$(unexpected)" ] || { unexpected | sed "s/^/     allowed: /"; false; }'
check "  and nothing it holds left to any other host" '! grep -vE "^GET (example\.com|httpbin\.org|httpbingo\.org) " "$work/allowed.txt" | grep -qF "$BOX_MARK"'
# Grants: each run's quotas aside, the operator's digest grants for the services' zones, and the one
# prefix, made by the one decision on the attacker's prefix request.
grants_all=$work/grants.txt
grants_ok=0
w grant list --all --tail 500 >"$grants_all" 2>&1 && grants_ok=1
prefix_req=$(cat "$atk_dir/workspace/out/prefix.request" 2>/dev/null || true)
decisions=$(awk '$3 == "decision"' "$audit_all")
prefix_grant=$(grep "\"request\":\"$prefix_req\"" <<<"$decisions" | grep -oE '"grant":"g-[0-9a-z]+"' | cut -d'"' -f4 | head -1)
standing_req=$(cat "$atk_dir/workspace/out/standing.request" 2>/dev/null || true)
check "the only decisions are the operator's on the prefix (${prefix_req:-?}, ${prefix_grant:-no grant}) and the narrow standing rule (${standing_req:-?}): nothing the attacker said decided the peer's" '[ -n "$prefix_req" ] && [ -n "$prefix_grant" ] && [ -n "$standing_req" ] && [ "$(grep -c . <<<"$decisions")" = 2 ] && grep -q "\"standing\":\"$standing_req\"" <<<"$decisions" || { sed "s/^/     decision: /" <<<"$decisions" | cut -c1-200; false; }'
other_grants=$(grep -vE "^\S+ +quota " "$grants_all" | grep -vE "^\S+ +DIGEST .* any run in zone atk-svc2?," | grep -v "^$prefix_grant " || true)
check "the grants are the quotas, the services' digest grants and that prefix only" '[ "$grants_ok" = 1 ] && grep -q "^$prefix_grant .*anything/granted/\* \[prefix\]" "$grants_all" && [ -z "$other_grants" ] || { sed "s/^/     grant: /" <<<"$other_grants"; false; }'
standing_all=$(w standing list --all 2>&1) || standing_all="ERROR: $standing_all"
approved=$(grep -E '^s-' <<<"$standing_all" | grep -vE ' (pending|denied|revoked|lapsed)$' || true)
check "the only standing rule approved is the narrow one the operator approved (${standing_req:-?})" '[ -n "$standing_req" ] && [ "$(grep -c . <<<"$approved")" = 1 ] && grep -q "^$standing_req " <<<"$approved" || { sed "s/^/     standing: /" <<<"$standing_all"; false; }'
check "  and the peer's and the attacker's other standing asks are still pending" 'grep -q "^$peer_standing .* pending$" <<<"$standing_all" && grep -q "example.org.*attacker.* pending$" <<<"$standing_all"'
started=$(awk '$3 == "service.instance_started"' "$audit_all")
check "both services' instances ran on the node (so their links were there to refuse)" 'grep "\"service\":\"atk-svc\"" <<<"$started" | grep -q "\"error\":null" && grep "\"service\":\"atk-svc2\"" <<<"$started" | grep -q "\"error\":null"'
links_ok=0
links=$(w links --tail 500 2>&1) && links_ok=1
check "wicket links reads" '[ "$links_ok" = 1 ] || { echo "     $links"; false; }'
check "no link has the attacker at either end (its port exposed as atk-svc included)" '! grep -qF "$atk" <<<"$links" || { grep -F "$atk" <<<"$links" | sed "s/^/     link: /"; false; }'
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
