#!/bin/bash
# In-box forwarder legs (as experiment #62's box.sh): curl inside a --network none box reaches an HTTP
# origin on the host only through a forwarder and a bind-mounted unix socket. Legs, interleaved per round:
#   socat         socat TCP-LISTEN,fork,reuseaddr UNIX-CONNECT, as wicket-entry ran it before wicket-fwd
#   fwd-rw        wicket-fwd --copy rw
#   fwd-splice    wicket-fwd --copy splice
# Each leg per round: N new-connection GETs of 1 KB (one curl each), then DL downloads of BIG bytes.
#
#   bench/box.sh WICKET_FWD IMAGE OUT.txt [RUNTIME]   (IMAGE needs bash and curl; WICKET_FWD a static
#                                                     binary, or "image" for the image's own wicket-fwd)
# Env: N (200), BIG (100000000), DL (5), ROUNDS (2), LEGS ("socat fwd-rw fwd-splice"; socat needs it in
# the image), DOCKER ("docker"), NAME (container name, fwd-bench).
set -euo pipefail
FWD=$1; IMAGE=$2; OUT=$3; RT=${4:-runsc}
LEGS=${LEGS:-socat fwd-rw fwd-splice}; N=${N:-200}; BIG=${BIG:-100000000}; DL=${DL:-5}; ROUNDS=${ROUNDS:-2}
DOCKER=${DOCKER:-docker}; NAME=${NAME:-fwd-bench}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d); mkdir -p "$W/sock"; chmod 0777 "$W/sock"
cleanup() { kill "${origin:-}" 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT

python3 -I "$HERE/origin.py" "$W/sock/origin.sock" &
origin=$!
until [ -S "$W/sock/origin.sock" ]; do sleep 0.1; done

MOUNT=(); [ "$FWD" = image ] || MOUNT=(-v "$(realpath "$FWD"):/fwd:ro")
FMT='%{time_connect} %{time_starttransfer} %{time_total} %{speed_download}\n'
INBOX=$(cat <<EOS
set -eu
S=/wicket/sock/origin.sock
F=/fwd; [ -x \$F ] || F=wicket-fwd
case " $LEGS " in *" socat "*) socat TCP-LISTEN:7001,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:\$S & ;; esac
\$F --listen 127.0.0.1:7002=\$S --copy rw &
\$F --listen 127.0.0.1:7003=\$S --copy splice &
sleep 1
leg() { # name port
  curl -s -o /dev/null http://127.0.0.1:\$2/1k
  for i in \$(seq $N); do curl -s -o /dev/null -w "\$1 new $FMT" http://127.0.0.1:\$2/1k; done
  for i in \$(seq $DL); do curl -s -o /dev/null -w "\$1 big $FMT" http://127.0.0.1:\$2/bytes/$BIG; done
}
port() { case \$1 in socat) echo 7001;; fwd-rw) echo 7002;; fwd-splice) echo 7003;; esac; }
for r in \$(seq $ROUNDS); do for l in $LEGS; do leg \$l \$(port \$l); done; done
EOS
)
$DOCKER run --rm --name "$NAME" --runtime "$RT" --network none --user 65534:65534 --entrypoint bash \
  -v "$W/sock:/wicket/sock" "${MOUNT[@]}" "$IMAGE" -c "$INBOX" > "$OUT"
echo "wrote $OUT"
