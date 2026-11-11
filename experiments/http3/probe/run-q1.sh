#!/bin/bash
# Question 1: UDP on lo, IP_PKTINFO, host unix sockets of each type, MTU, GSO, inside a box started
# with wicket's flags (crates/wicket-sandbox build_args). Usage: probe/run-q1.sh [runsc|runc] [image]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
rt=${1:-runsc}
img=${2:-wicket/claude-code:poc}
sock=$(mktemp -d /tmp/h3-q1.XXXXXX)
chmod 0777 "$sock"
python3 "$here/host_echo.py" "$sock" &
echo_pid=$!
trap 'kill $echo_pid 2>/dev/null; rm -rf "$sock"' EXIT
sleep 0.5

# As root with NET_ADMIN (like wicket-entry): wicket.internal, two synthetic addresses, and a local
# route for the whole synthetic /16, then drop everything and probe.
setup='
set -u
ip addr add 198.18.0.1/32 dev lo
ip addr add 198.19.0.5/32 dev lo
ip addr add 198.19.0.6/32 dev lo
if ip route add local 198.19.0.0/16 dev lo table local 2>/tmp/route.err; then echo "route-local-198.19.0.0/16: ok"; else echo "route-local-198.19.0.0/16: FAIL $(cat /tmp/route.err)"; fi
# A whole /16 as one address with its prefix (Linux makes the prefix local on lo), and a pool of
# 4096 /32s, timed.
if ip addr add 198.20.0.1/16 dev lo 2>/tmp/p.err; then echo "addr-prefix-198.20.0.1/16: ok"; else echo "addr-prefix: FAIL $(cat /tmp/p.err)"; fi
t0=$(date +%s%N)
for a in $(seq 0 15); do for b in $(seq 0 255); do echo "address add 198.21.$a.$b/32 dev lo"; done; done | ip -batch - 2>/tmp/pool.err && echo "pool-4096-addrs: ok in $(( ($(date +%s%N) - t0) / 1000000 )) ms" || echo "pool-4096-addrs: FAIL $(head -2 /tmp/pool.err)"
ip link show lo | head -1
echo "--- ip addr / ip route (table local)"; ip -4 addr show dev lo | sed -n "s/^ *inet /inet /p" | grep -v "198.21" ; echo "(198.21.x: $(ip -4 addr show dev lo | grep -c 198.21) addresses)"; ip route show table local 2>&1 | head -20
echo "--- resolv.conf"; cat /etc/resolv.conf
echo "---"
exec setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --bounding-set=-all -- python3 /probe/box_probe.py
'
sudo -n docker run --rm --name "h3-q1-$rt" --runtime "$rt" --network none --dns 198.18.0.1 \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=64m --user 0:0 \
  --mount "type=bind,source=$here,target=/probe,readonly" --mount "type=bind,source=$sock,target=/wicket/sock" \
  --entrypoint bash "$img" -c "$setup"
