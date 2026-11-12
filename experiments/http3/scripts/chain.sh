#!/bin/bash
# Questions 2-4: DNS through the relay (musl, glibc, Node), then HTTP/3 requests from inside a gVisor
# box through the forwarder and the host's QUIC termination: allowed, out of reach, forbidden,
# HTTP/2-only upstream, wildcard host, hidden host, SNI that doesn't match the address.
# Writes logs/chain.log and logs/chain-audit.jsonl.
set -u
. "$(dirname "$0")/lib.sh"
start_host --https-records
out=$LOGS/chain.log
{
echo "# $(date -u +%FT%TZ) runtime $RT ($(runsc --version | head -1)), image $IMG"
box '
G="/opt/h3spike get --ca /wicket/ca/ca.pem"
echo "== resolv.conf: $(grep ^nameserver /etc/resolv.conf)"
echo "== musl getaddrinfo (static binary)"
/opt/h3spike resolve h3.test h2only.test a.wild.test b.wild.test hidden.test example.com
echo "== glibc getaddrinfo (getent ahosts)"
for n in h3.test a.wild.test hidden.test; do echo "-- $n"; getent ahosts $n || echo "exit $? (not found)"; done
echo "== Node $(node --version): dns.lookup (getaddrinfo) and dns.resolve4/resolve6/resolve HTTPS (c-ares)"
node -e "
const dns = require(\"dns\").promises;
(async () => {
  for (const n of [\"h3.test\", \"hidden.test\"]) {
    for (const [what, f] of [[\"lookup\", () => dns.lookup(n, {all: true})], [\"resolve4\", () => dns.resolve4(n)], [\"resolve6\", () => dns.resolve6(n)]]) {
      try { console.log(n, what, JSON.stringify(await f())); } catch (e) { console.log(n, what, \"error\", e.code); }
    }
  }
  try { console.log(\"h3.test HTTPS\", JSON.stringify(await dns.resolve(\"h3.test\", \"HTTPS\"))); } catch (e) { console.log(\"h3.test HTTPS error\", e.code, e.message); }
})();
"
echo "== HTTPS (type 65) record, raw query from python"
python3 -c "
import socket, struct
q = struct.pack(\">HHHHHH\", 0x4242, 0x0100, 1, 0, 0, 0) + b\"\".join(bytes([len(l)]) + l.encode() for l in \"h3.test\".split(\".\")) + b\"\\0\" + struct.pack(\">HH\", 65, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(q, (\"198.18.0.1\", 53)); r = s.recv(512)
an = struct.unpack(\">H\", r[6:8])[0]; rd = r[len(q):]
t, _, ttl, ln = struct.unpack(\">HHIH\", rd[2:12]); d = rd[12:12+ln]
print(\"answers\", an, \"type\", t, \"ttl\", ttl, \"rdata\", d.hex(), \"priority\", struct.unpack(\">H\", d[:2])[0], \"alpn\", d[8:10], \"ipv4hint\", socket.inet_ntoa(d[-4:]))
"
echo "== HTTP/3: allowed path"
$G https://h3.test/allowed/hello
echo "== HTTP/3: POST to an allowed path"
$G --method POST --body 100 https://h3.test/allowed/form
echo "== HTTP/3: out of reach (403 over HTTP/3)"
$G https://h3.test/secret
echo "== HTTP/3: forbidden path"
$G https://h3.test/admin/users
echo "== HTTP/3: upstream has HTTP/2 only (fallback), twice (second time remembered)"
$G --n 2 https://h2only.test/hi
echo "== HTTP/3: wildcard host *.wild.test"
$G https://a.wild.test/x
echo "== HTTP/3: hidden host (does not resolve)"
$G https://hidden.test/ ; echo "exit $?"
echo "== HTTP/3: SNI h3.test sent to h2only.test synthetic address"
$G --connect h3.test=$(/opt/h3spike resolve h2only.test | sed -E "s/.*addrs\":\[\"([0-9.]+)\".*/\1/"):443 --idle 3 https://h3.test/allowed/x ; echo "exit $?"
echo "== HTTP/3: asking this connection for another host (:authority h2only.test on the h3.test connection)"
$G https://h3.test/allowed/a https://h2only.test/hi
echo "== fwd log"; cat /tmp/fwd.log
'
echo "== term log"; cat "$run/term.log"
echo "== origin log"; cat "$run/origin.log"
} 2>&1 | tee "$out"
cp "$run/audit.jsonl" "$LOGS/chain-audit.jsonl"
