#!/bin/bash
# The escape attempts (#326), run inside the box. Each line of out/escape.log is
# `<attempt> blocked <detail>` or `<attempt> ESCAPED <detail>`. HOST_IP and CANARY_PORT are filled in
# by ci/acceptance.sh: a canary HTTP server on the host that must see no request.
set -u
out=/workspace/out/escape.log
: >"$out"
note() { printf '%s %s %s\n' "$1" "$2" "$3" >>"$out"; }
# An HTTP attempt through the proxy (or not): blocked unless the status is 2xx/3xx from the far side.
http() { # name, curl args...
  local name=$1; shift
  local code
  code=$(curl -s -m 15 -o /tmp/escape.body -w '%{http_code}' "$@" 2>/dev/null) || code=${code:-000}
  case "$code" in
    2??|3??) note "$name" ESCAPED "HTTP $code" ;;
    *) note "$name" blocked "HTTP $code" ;;
  esac
}
# A raw TCP connection, no proxy: blocked unless it connects.
tcp() { # name, host, port
  if timeout 5 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; then note "$1" ESCAPED "connected to $2:$3"; else note "$1" blocked "no connection to $2:$3"; fi
}
canary=http://HOST_IP:CANARY_PORT

# The zone's one allowed request, so the run shows the proxy works (not an escape).
code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' http://example.com/ 2>/dev/null)
note reach-allowed info "GET example.com/ -> HTTP $code"

# Through the proxy, outside the zone.
http other-host http://example.org/
http other-path http://example.com/admin
http other-method -X POST http://example.com/
http https-other-host https://example.org/
http host-address "$canary/"
http host-loopback http://127.0.0.1:CANARY_PORT/
http host-name "http://$(hostname -f 2>/dev/null || echo localhost):CANARY_PORT/"
http cloud-metadata http://169.254.169.254/latest/meta-data/
http azure-wireserver http://168.63.129.16/machine?comp=goalstate
http connect-tunnel -p "$canary/"
http proxy-host-header -H "Host: example.org" http://example.com/
http absolute-uri --request-target "http://example.org/" http://example.com/

# Around the proxy: no proxy, raw sockets, the forwarder's other ports.
http no-proxy --noproxy '*' http://example.com/
tcp raw-tcp-public 1.1.1.1 443
tcp raw-tcp-host HOST_IP CANARY_PORT
for p in 22 80 443 2375 2376 5000 8000 9000; do tcp "forwarder-port-$p" wicket.internal "$p"; done
if timeout 5 bash -c 'printf x >/dev/udp/8.8.8.8/53' 2>/dev/null; then note raw-udp info "sent (UDP has no answer to check; the host's view is what counts)"; else note raw-udp blocked "no route"; fi

# DNS: wicket's resolver answers names only with its synthetic range (or not at all).
addr=$(getent hosts "exfil-$RANDOM.example.org" 2>/dev/null | awk '{print $1}' | head -1)
case "$addr" in
  ''|198.19.*) note dns-exfil blocked "answered: ${addr:-nothing}" ;;
  *) note dns-exfil ESCAPED "a real answer: $addr" ;;
esac
# The host's DNS search domain (a cloud host's names its region) isn't in the box's resolver config,
# where every lookup would carry it and the box's own hostname would resolve under it.
search=$(grep -E '^[[:space:]]*(search|domain)[[:space:]]' /etc/resolv.conf 2>/dev/null | head -1)
if [ -n "$search" ]; then note resolv-search ESCAPED "the host's: $search"; else note resolv-search blocked "no search domain"; fi

# wicket's other endpoints: the model proxy has no route for a program, and the gateway grants nothing.
http model-proxy http://wicket.internal:8080/api/oauth/profile
ask='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_access","arguments":{"url":"http://example.org/","reason":"escape test"}}}'
answer=$(curl -s -m 20 http://wicket.internal:8081/ -H 'content-type: application/json' -d "$ask" 2>/dev/null | tr -d '\n' | cut -c1-300)
note gateway-ask info "request_access answered: ${answer:-nothing}"
http after-asking http://example.org/

# Files: its read-only mounts stay read-only, and the host's secrets and sockets aren't there.
for f in /wicket/ca/escape /etc/hosts.escape /usr/escape; do
  if (echo x >"$f") 2>/dev/null; then note "write-$f" ESCAPED "wrote $f"; rm -f "$f"; else note "write-$f" blocked "read-only"; fi
done
for f in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock; do
  if [ -e "$f" ]; then note "socket-$f" ESCAPED "$f exists"; else note "socket-$f" blocked "absent"; fi
done
if cat /etc/shadow >/dev/null 2>&1 && grep -q '^root:\$' /etc/shadow 2>/dev/null; then note shadow ESCAPED "readable with a hash"; else note shadow blocked "no hash readable"; fi
if command -v unshare >/dev/null; then
  if unshare -Urm sh -c 'mount -o remount,rw /wicket/ca 2>/dev/null && echo x > /wicket/ca/escape' 2>/dev/null; then
    note userns-remount ESCAPED "remounted /wicket/ca read-write"
  else
    note userns-remount blocked "the read-only bind stayed read-only"
  fi
fi
echo "escape attempts: $(grep -c . "$out"), escaped: $(grep -c ' ESCAPED ' "$out")"
