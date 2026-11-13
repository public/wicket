# Use HTTP/3

Nothing to configure: a box's HTTP/3 goes through wicket and is decided exactly like an HTTP/1.1
request. This page says how it works, how to make it fast, and how to turn its DNS hint off.

## How a box reaches a host over HTTP/3

- The box resolves names through wicket's DNS. Each host the zone can reach gets a synthetic address
  in 198.19.0.0/16; hidden and forbidden hosts get NXDOMAIN, so a lookup can't carry data out.
- QUIC sent to a synthetic address is relayed to wicket over a unix socket. wicket terminates it with
  the run's CA (or, on a node, the node CA) and decides each request as it would an HTTP/1.1 one.
- 0-RTT is refused. Request bodies over HTTP/3 are read whole, up to 64 MiB.
- An HTTP/3 connection serves one host only: a request for another gets a 421 `misdirected`.
- HTTP/3 is always terminated and inspected: splice-through applies to TCP only.

Older agent images lack the forwarder that relays QUIC: rebuild with `wicket image` (on a node,
`~/.local/bin/wicket image` there).

## Make it faster

Under gVisor each UDP datagram costs the box about 110 µs of CPU, so downloads run at 40–100 Mbit/s
with standard 1452-byte packets. The box's leg is loopback and a unix socket, not a real link, so it
can use bigger packets for clients that accept them:

```sh
WICKET_H3_BOX_MTU=16000 wicket run task.yaml       # 430–460 Mbit/s in #92's measurements
```

Set it where the box's proxies run: for `wicket run` on this host, in its environment; installed, in
the environment of the unit that runs the box. Over TCP, HTTPS is faster still in a gVisor box.
[Performance](../explanation/performance.md#http3) has the measurements.

## Stop advertising HTTP/3

wicket's DNS answers HTTPS records with `alpn=h3`, which tells clients they may use HTTP/3. To stop
that, so clients stay on TCP:

```sh
WICKET_H3_HTTPS_RECORDS=0 wicket run task.yaml
```

## Check it

`ci/acceptance.sh` fetches a page over HTTP/3, in reach and out of it, with `ci/h3get`, a small
static HTTP/3 client. HTTP/3 hasn't been checked with `curl --http3` or a browser yet.
