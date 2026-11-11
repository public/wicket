#!/bin/bash
# The listen address disappearing and coming back (what a gVisor restore does to wicket.internal,
# experiment #70), in a real --network none box: expect "up: 200", "gone: 000", "back: 200", and the
# forwarder's "is gone" / "is back" log lines.
#
#   bench/addr-gone.sh IMAGE [RUNTIME]   (IMAGE: the agent image, with wicket-fwd; env DOCKER)
set -euo pipefail
IMAGE=$1; RT=${2:-runsc}; DOCKER=${DOCKER:-docker}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d); mkdir -p "$W/sock"; chmod 0777 "$W/sock"
cleanup() { kill "${origin:-}" 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT
python3 -I "$HERE/origin.py" "$W/sock/origin.sock" &
origin=$!
until [ -S "$W/sock/origin.sock" ]; do sleep 0.1; done
$DOCKER run --rm --runtime "$RT" --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID \
  --cap-add SETGID --entrypoint bash -v "$W/sock:/wicket/sock" "$IMAGE" -c '
A=198.18.0.1
ip addr add $A/32 dev lo
setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all -- \
  wicket-fwd --listen $A:3128=/wicket/sock/origin.sock &
sleep 1
g() { curl -s -m 3 -o /dev/null -w "%{http_code}" http://$A:3128/1k || true; }
echo "up: $(g)"; ip addr del $A/32 dev lo; sleep 2.5; echo "gone: $(g)"
ip addr add $A/32 dev lo; sleep 2.5; echo "back: $(g)"'
