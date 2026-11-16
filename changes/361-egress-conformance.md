---
area: Approvals
type: Security
---
- An egress conformance pack ([#361](https://github.com/public/wicket/issues/361)) pins known
  proxy and sandbox bypasses as tests: upgrades and request smuggling, IP spellings and ports, Host
  and SNI fronting, relayed CONNECT and SOCKS, DNS exfiltration, oversized bodies, and credential
  reflection in response headers and split chunks. A new `canon` fuzz target covers
  `canonical_host` and `canonical_path`. Three gaps it found are closed. The egress proxy now
  refuses a request with more than one Host header, and a request inside a tunnel whose
  absolute-form URL names another host, port or scheme than the tunnel's (it used to be sent to the
  tunnel's host anyway). It also answers 502 when an upstream replies `101 Switching Protocols` to a
  request that asked for no upgrade, instead of relaying the 101 into the box.
