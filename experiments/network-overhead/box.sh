#!/bin/bash
# The in-box legs: curl inside a container with no network, through socat and a bind-mounted unix socket,
# as wicket-entry sets it up, to the egress proxy replica (mitm) and the splice-through prototype (pass)
# on the host. Runs the same script under runc and gVisor (runsc --host-uds=open), and a runc container
# on the host network straight to the origin as the baseline. The mitm-nodelay leg is socat with TCP_NODELAY;
# the raw leg is the hop alone, TLS end to end with the origin; the local leg is an origin inside the box.
# *-b256k legs: socat with -b 262144 (its default buffer is 8 KiB) and nodelay.
#
#   ./box.sh target/release/netbench IMAGE logs/   (IMAGE needs sh, socat, curl and openssl; needs docker access)
set -euo pipefail
BIN=$(realpath "$1"); IMAGE=$2; OUT=$(realpath "$3")
N=${N:-200}; BIG=${BIG:-100000000}; DL=${DL:-5}
W=$(mktemp -d); mkdir -p "$W/sock" "$W/ca"
cleanup() { kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT

"$BIN" origin --listen 127.0.0.1:18443 --dir "$W/ca" &
until [ -f "$W/ca/origin-ca.der" ]; do sleep 0.1; done
"$BIN" mitm --listen "unix:$W/sock/mitm.sock" --dir "$W/ca" --upstream-port 18443 --ledger "$W/ledger.db" &
"$BIN" pass --listen "unix:$W/sock/pass.sock" --mode connect --copy splice --upstream-port 18443 &
# raw: no proxy at all, only the hop (in-box socat, the unix socket, a host socat to the origin).
socat UNIX-LISTEN:"$W/sock/raw.sock",fork,mode=666 TCP:127.0.0.1:18443,nodelay &
until [ -S "$W/sock/raw.sock" ] && [ -S "$W/sock/mitm.sock" ] && [ -S "$W/sock/pass.sock" ] && [ -f "$W/ca/run-ca.pem" ]; do sleep 0.1; done
chmod 0777 "$W/sock"; chmod 0666 "$W/sock"/*.sock; chmod 0644 "$W/ca"/*

FMT='%{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{speed_download}\n'
INBOX=$(cat <<EOF
set -eu
socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/wicket/sock/mitm.sock &
socat TCP-LISTEN:3129,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/wicket/sock/pass.sock &
socat TCP-LISTEN:3130,bind=127.0.0.1,fork,reuseaddr,nodelay UNIX-CONNECT:/wicket/sock/mitm.sock &
socat TCP-LISTEN:18443,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/wicket/sock/raw.sock &  # fails, harmlessly, on the host-network direct leg
socat -b 262144 TCP-LISTEN:18444,bind=127.0.0.1,fork,reuseaddr,nodelay UNIX-CONNECT:/wicket/sock/raw.sock &
socat -b 262144 TCP-LISTEN:3131,bind=127.0.0.1,fork,reuseaddr,nodelay UNIX-CONNECT:/wicket/sock/mitm.sock &
sleep 0.5
run() { # leg proxy-args ca url-prefix
  leg=\$1; px=\$2; ca=\$3; base=\$4
  curl -s -o /dev/null \$px --cacert \$ca \$base/1k   # warm: leaf minted, upstream pool filled
  for i in \$(seq $N); do curl -s -o /dev/null \$px --cacert \$ca -w "\$leg new $FMT" \$base/1k; done
  args=""; for i in \$(seq $N); do args="\$args -o /dev/null \$base/1k"; done
  curl -s \$px --cacert \$ca -w "\$leg keep $FMT" \$args
  for i in \$(seq $DL); do curl -s -o /dev/null \$px --cacert \$ca -w "\$leg big $FMT" \$base/bytes/$BIG; done
}
EOF
)
PROXIED="$INBOX
run mitm '-x http://127.0.0.1:3128' /wicket/ca/run-ca.pem https://origin.test
run mitm-nodelay '-x http://127.0.0.1:3130' /wicket/ca/run-ca.pem https://origin.test
run pass '-x http://127.0.0.1:3129' /wicket/ca/origin-ca.pem https://origin.test
run raw '--resolve origin.test:18443:127.0.0.1' /wicket/ca/origin-ca.pem https://origin.test:18443
run raw-b256k '--resolve origin.test:18444:127.0.0.1' /wicket/ca/origin-ca.pem https://origin.test:18444
run mitm-b256k '-x http://127.0.0.1:3131' /wicket/ca/run-ca.pem https://origin.test
# local: an origin inside the box itself (openssl s_server), so neither the hop nor the host is involved.
cd /tmp && mkdir -p bytes && head -c $BIG /dev/zero > bytes/$BIG && head -c 1024 /dev/zero > 1k
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=origin.test -addext subjectAltName=DNS:origin.test -keyout k.pem -out c.pem -days 1 2>/dev/null
openssl s_server -quiet -WWW -accept 127.0.0.1:4443 -cert c.pem -key k.pem >/dev/null 2>&1 &
sleep 0.5
run local '--resolve origin.test:4443:127.0.0.1' /tmp/c.pem https://origin.test:4443"
DIRECT="$INBOX
run direct '--resolve origin.test:18443:127.0.0.1' /wicket/ca/origin-ca.pem https://origin.test:18443"

box() { docker run --rm --user 65534:65534 --entrypoint sh -v "$W/sock:/wicket/sock" -v "$W/ca:/wicket/ca:ro" "$@"; }
# Baseline: the same curl on the host network, straight to the origin. (gVisor keeps its own loopback,
# so it can't reach the host's; the raw leg below is its transport-only baseline.)
box --runtime runc --network host "$IMAGE" -c "$DIRECT" > "$OUT/box-runc-direct.txt"
for rt in runc runsc; do
  box --runtime $rt --network none "$IMAGE" -c "$PROXIED" > "$OUT/box-$rt.txt"
done
