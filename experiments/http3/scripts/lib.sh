# Shared setup for the chain: origin + terminator on the host, a gVisor box with wicket's flags.
# Source it; call `start_host` then `box CMD` (runs CMD in a fresh box with the forwarder running).
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${BIN:-$here/target/x86_64-unknown-linux-musl/release/http3-spike}
IMG=${IMG:-wicket/claude-code:poc}
RT=${RT:-runsc}
run=$(mktemp -d /tmp/h3-run.XXXXXX)
chmod 0755 "$run"
mkdir -p "$run/sock" "$run/ca"
chmod 0777 "$run/sock"
LOGS=${LOGS:-$here/logs}
pids=()

cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  sudo -n docker rm -f "h3-box-$$" >/dev/null 2>&1
  rm -rf "$run"
}
trap cleanup EXIT

zone() {
  cat > "$run/zone.json" <<'EOF'
{
  "name": "h3zone",
  "unlisted_hosts": "hide",
  "reach": [
    {"host": "h3.test", "methods": ["GET", "HEAD", "POST"], "paths": ["/allowed/**", "/bytes/**", "/small"]},
    {"host": "h2only.test", "paths": ["/**"]},
    {"host": "*.wild.test", "paths": ["/**"]}
  ],
  "forbid": [{"host": "h3.test", "paths": ["/admin/**"]}]
}
EOF
}

start_host() {
  zone
  "$BIN" origin --ca-out "$run/origin-ca.pem" --h3 127.0.0.1:4433 --h3-names h3.test,a.wild.test \
    --h2 127.0.0.1:4434 --h2-names h2only.test 2> "$run/origin.log" &
  pids+=($!)
  ORIGIN_PID=$!
  sleep 0.3
  "$BIN" term --sock "$run/sock/udp.sock" --zone "$run/zone.json" --ca-out "$run/ca/ca.pem" \
    --origin-ca "$run/origin-ca.pem" --audit "$run/audit.jsonl" \
    --upstream h3.test=127.0.0.1:4433 --upstream a.wild.test=127.0.0.1:4433 --upstream h2only.test=127.0.0.1:4434 \
    "$@" 2> "$run/term.log" &
  pids+=($!)
  TERM_PID=$!
  for _ in $(seq 50); do [ -S "$run/sock/udp.sock" ] && break; sleep 0.1; done
}

# box SCRIPT: wicket's box flags (crates/wicket-sandbox build_args); as root, give lo wicket.internal
# and the synthetic /16 (one address makes the whole prefix local), drop every capability, start the
# forwarder, run SCRIPT as uid 1000.
box() {
  local script=$1
  sudo -n docker run --rm --init --name "h3-box-$$" --runtime "$RT" --network none --dns 198.18.0.1 \
    --memory 2g --cpus 2 --pids-limit 512 \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=256m --user 0:0 \
    --mount "type=bind,source=$BIN,target=/opt/h3spike,readonly" \
    --mount "type=bind,source=$run/ca,target=/wicket/ca,readonly" \
    --mount "type=bind,source=$run/sock,target=/wicket/sock" \
    --env FWD_ARGS="${FWD_ARGS:-}" \
    --entrypoint bash "$IMG" -c '
set -eu
ip addr add 198.18.0.1/32 dev lo
ip addr add 198.19.0.1/16 dev lo
drop() { setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --bounding-set=-all -- "$@"; }
setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --bounding-set=-all -- /opt/h3spike fwd $FWD_ARGS 2>/tmp/fwd.log &
echo $! > /tmp/fwd.pid
sleep 0.3
export HOME=/tmp
exec setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --bounding-set=-all -- bash -c "$0"
' "$script"
}

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }
