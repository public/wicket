# Performance of the network path

Every byte a box sends goes through wicket. The box has no network of its own: its connections go
through a forwarder in the box (`wicket-fwd`), over a bind-mounted unix socket, to the egress proxy on
the host. This page gives what that path costs, measured, and what each change in 0.0.1 did to it
([#62](https://github.com/public/wicket/issues/62)).

**The machine.** Every number here comes from one shared VPS: 4 vCPUs (Intel Broadwell), 8 GB of RAM,
no KVM, gVisor `release-20261102.0` on the systrap platform. Other jobs ran on it at the same time
(load 2–9), so wall-clock figures carry ±30% noise, and download throughput much more: see the
min–max columns. CPU seconds per GB, CPU per request and audit-row counts are much steadier. Compare
arms only within one table, where they were interleaved in the same run.

## In short

| | before | after |
|---|---|---|
| audit row per allowed request (batched writer) | 1.3 ms kept-alive request, 930 req/s | 0.47 ms, about 7,000 req/s |
| in-box forwarder, gVisor (`wicket-fwd` in place of socat) | 14–17 ms new connection, 10–33 MB/s | 4.2–7.3 ms, 170–350 MB/s |
| egress CPU per GB, host allowed wholesale (splice-through) | 2.67 CPU-s/GB | 0.33 CPU-s/GB |
| egress CPU per 1,000 kept-alive requests, same host | 162 CPU-ms | 32 CPU-ms |
| `cargo fetch` of a mid-size project in a gVisor box | 24.3 s, 1,012 audit rows | 15.8 s, 19 audit rows |
| 10 MB upload through an inspected host (streamed bodies) | 44 ms, whole body buffered, 64 MiB cap | 25 ms, streamed, 4 GiB cap |
| egress CPU per GB, spliced on a remote node | inspected: 2.47 CPU-s/GB | 0.37 CPU-s/GB, while the box's token allows the host |

## Splice-through for hosts allowed wholesale

The egress proxy terminates TLS for a host so it can decide each request on its own: method, path
and risk. It also attaches the zone's credential. A host that a reach rule allows wholesale gains
nothing from that, because every request the decision could see would be allowed anyway. For such a
host the proxy decides on the hostname at `CONNECT` and relays the box's TLS unmodified. It uses
splice(2) from the event loop, so the bytes never enter userspace. The box sees the origin's own
certificate.

**Wholesale** is decided in one place, `wicket_core::splice::inspection`. All of these must hold:

- some reach rule for the host lists every method the proxy forwards (`GET HEAD OPTIONS POST PUT
  PATCH DELETE`) and the path `/**`;
- for a host the dangerous-pattern list can rate R3 or higher (GitHub, `*.amazonaws.com`, metadata
  endpoints), that rule also has `allow_dangerous`;
- no forbid rule names the host, whatever its paths;
- no credential is injected for the host or swapped in;
- the host is not the model host;
- the box's TLS ClientHello names the `CONNECT` host in SNI and doesn't use Encrypted ClientHello.

Browsers send a GREASE ECH extension even when they have no ECH configuration, so a browser's
connections are always intercepted. curl, cargo, npm, git and other command-line clients don't send
one.

When any check fails, the proxy intercepts as before. That includes a ClientHello with no SNI or a
different name: the bytes already read are replayed into the normal interception path. When in doubt,
it intercepts.

**What still applies to a spliced connection:**

- the host verdict (forbidden and hidden hosts);
- the superseded-activation check at `CONNECT` and every 2 s while the connection lasts;
- the dial-time address check ([#116](https://github.com/public/wicket/issues/116)). The proxy
  resolves and dials the host itself, at public addresses only, before it answers the `CONNECT`, so
  a refused dial is the `CONNECT`'s answer.

Each connection writes one audit row when it closes (`outcome: spliced`), with the reach rule and the
bytes each way.

**What a spliced host gives up.** The proxy can't see inside a spliced connection, so it loses:

- per-request audit rows;
- the request header allow-list ([#130](https://github.com/public/wicket/issues/130));
- dropping the box's own `Authorization` header;
- the request-shape checks;
- Host pinning.

Without Host pinning, a spliced host behind a shared CDN can be used to reach other sites behind the
same CDN (domain fronting). To keep a host inspected, add a forbid rule for it, even on a path nothing
uses. To see which hosts are spliced, run `wicket zone MANIFEST`, or look at the manifest list in the
console:

```
$ wicket zone examples/self-hosting/manifest.yaml
zone wicket-src: egress over HTTPS (HTTP/3 is always terminated and inspected)
  index.crates.io   INSPECTED  reach limits methods, paths or risk
  static.crates.io  INSPECTED  reach limits methods, paths or risk
  github.com        INSPECTED  a credential is injected for github.com
  api.github.com    INSPECTED  a credential is injected for api.github.com
```

**Not spliced, by design in 0.0.1:**

- **HTTP/3.** wicket terminates QUIC for every host and decides each request, wholesale or not. A
  client that wants the fast path to a spliced host should use HTTP/2 or HTTP/1.1 over TCP.
- **Plain HTTP.** It is always inspected.
- **Remote nodes.** A node splices a host while its replica is fresh or offline and the box's token
  still allows it ([#141](https://github.com/public/wicket/issues/141), #153); a lagging or closed
  replica, or an expired token, refuses per request, which a hostname can't carry. The checks above hold
  on the node too. In addition, the box's own token must allow the host for every method the proxy
  forwards, at the root and at a deep path, by its ceiling alone. The node checks the token, not just the
  zone it was minted from. Only top-level boxes are spliced on a node. A child box's token is narrowed by
  its ancestors' ceilings, which the node can't read back from the token, so the node always inspects a
  child box's connections. When the token stops allowing the host (it expired, or the replica is
  lagging or closed), the node cuts the connections it spliced at the next 2 s check, and inspects new
  ones, deciding each request. Hosts the node forwards to the control host (credentials it doesn't
  hold, the node CA's name
  constraints) are still forwarded, and the control host decides there whether to splice them.

### Measured: the real proxy, with and without splice-through

`netbench bench --only direct,egress-` in `experiments/network-overhead` runs this. It starts
`wicket_proxy::egress::Egress` the way `wicket run` does: a file ledger with the batched audit writer,
the run's CA and the central decider. The upstream is a local HTTPS origin that the zone allows
wholesale. The inspected arm is the same zone with a forbid rule on a path the bench never asks for.
The client is on the host and connects to the proxy's socket directly (`unix`), or through a forwarder
(`fwd`, the experiment's own, splicing).

Each workload ran 3 rounds, interleaved, and each figure is the median of the rounds. A round has:

- 150 new-connection requests;
- 1,000 kept-alive requests;
- 4 s at 16 connections, kept alive and then new;
- three 100 MB downloads;
- three 10 MB uploads.

Measured 2026-11-12.

| setup | new conn p50 (ms) | kept-alive p50 / p99 (µs) | req/s, 16 kept | proxy CPU-ms per 1,000 kept requests | 100 MB, MB/s median (min–max) | proxy CPU-s per GB | 10 MB upload (ms) |
|---|---|---|---|---|---|---|---|
| direct | 1.33 | 126 / 1,378 | 25,702 | – | 555 (420–871) | – | 20 |
| direct, h2 | 1.68 | 195 / 1,330 | 14,450 | – | 336 (244–418) | – | 30 |
| **inspected** | 1.99 | **409** / 2,673 | **7,789** | **162** | 275 (201–379) | **2.67** | 61 |
| **spliced** | 2.33 | **208** / 898 | **16,414** | **32** | 523 (343–650) | **0.33** | 20 |
| spliced, h2 | 2.65 | 288 / 2,000 | 9,781 | 37 | 362 (236–421) | 0.47 | 23 |
| inspected, via forwarder | 2.52 | 477 / 1,998 | 5,183 | 178 | 310 (259–468) | 2.50 (+0.60 forwarder) | 48 |
| spliced, via forwarder | 2.41 | 278 / 960 | 15,583 | 47 | 608 (465–753) | 0.37 (+0.27 forwarder) | 22 |

- **Per GB, splice-through costs an eighth of interception** (0.33 against 2.67 CPU-s). Per kept-alive
  request it costs a fifth (32 against 162 CPU-ms per 1,000), and a kept-alive request takes half as
  long. The prototype measured 0.17 CPU-s/GB using two blocking threads per connection. The
  production version drives splice from the event loop: it pays for readiness wakeups, and doesn't
  use a thread per connection.
- **Uploads aren't buffered.** Spliced, a 10 MB upload takes as long as direct. The intercepting path
  streams bodies too since [#142](https://github.com/public/wicket/issues/142): see below.
- **HTTP/2 goes end to end.** Intercepted, the box side is HTTP/1.1. The upstream side is HTTP/2 where
  the upstream offers it.
- **A new spliced connection is about 0.3 ms slower than an intercepted one.** The proxy dials the
  upstream before it answers the `CONNECT`, so that the address check can refuse it. Interception
  reuses a pooled upstream connection.

## Intercepted hosts: streamed bodies and HTTP/2 upstreams

Before [#142](https://github.com/public/wicket/issues/142), the intercepting path read a whole request
body before it sent it upstream. A body over 64 MiB failed, and responses lost their
`content-length`. Upstream connections were pooled over HTTP/1.1 only. Now:

- **Request bodies stream upstream** as they arrive, with the box's backpressure: an upstream that
  reads slowly slows the box's writes, so the proxy holds only what sits in its buffers. A declared
  `content-length` goes upstream as declared, and a body without one goes chunked. A body over 4 GiB
  is refused: up front when it declares its length, otherwise when it passes the limit.
- **Some bodies are still read whole.** GET and HEAD are refused if they carry a body at all.
  Requests that arrived over HTTP/3 are read whole (up to 64 MiB), so they can be sent again over
  HTTP/2 if the HTTP/3 upstream connection is gone. Model calls through the model proxy keep its own
  checks and limit, and the model proxy reads their bodies.
- **Responses keep `content-length`**, so clients see download sizes and progress. The body passes
  through unchanged (wicket doesn't decompress), including through the model proxy's accounting.
- **Upstream connections use HTTP/2 where the upstream offers it (ALPN),** HTTP/1.1 otherwise. Requests
  from many box connections to one host share one pooled HTTP/2 connection. Windows are fixed at
  8 MiB per stream and 16 MiB per connection, with 1 MiB frames. hyper's adaptive window, which
  follows the bandwidth-delay product with pings, cut 100 MB downloads to 150–160 MB/s on this
  machine, against about 340–360 MB/s with fixed windows. The box side stays HTTP/1.1.

### Measured: streamed bodies, HTTP/2 upstreams and node splicing

The same bench as above (`netbench bench`), 3 interleaved rounds, measured 2026-11-12. The origin
offers HTTP/2 and HTTP/1.1. The arms:

- **inspected, 0.0.1 before #142**: the proxy built from the commit before this change (buffered bodies,
  HTTP/1.1 upstream);
- **inspected, HTTP/1.1 upstream**: streamed bodies, the upstream held to HTTP/1.1
  (`Upstream::http1_only`);
- **inspected**: streamed bodies, the HTTP/2 upstream pool, as wicket runs it;
- **spliced**, and **spliced on a node**: the node's decider over a fresh feed replica, as
  `wicket node serve` runs it.

| setup | new conn p50 (ms) | kept-alive p50 / p99 (µs) | req/s, 16 kept | proxy CPU-ms per 1,000 kept requests | 100 MB, MB/s median (min–max) | proxy CPU-s per GB | 10 MB upload (ms) |
|---|---|---|---|---|---|---|---|
| direct | 1.23 | 118 / 208 | 38,968 | – | 765 (625–866) | – | 13 |
| inspected, before #142 | 1.58 | 400 / 577 | 9,898 | 157 | 412 (298–465) | 2.47 | 44 |
| inspected, HTTP/1.1 upstream | 1.64 | 370 / 806 | 11,632 | 149 | 391 (319–454) | 2.43 | 24 |
| **inspected** | 1.75 | 442 / 879 | 9,554 | 154 | 418 (352–495) | 3.00 | **25** |
| spliced | 1.78 | 193 / 415 | 23,311 | 35 | 671 (457–723) | 0.37 | 14 |
| **spliced on a node** | 1.72 | 183 / 334 | 25,186 | 35 | 761 (614–838) | **0.37** | 13 |

- **A 10 MB upload through an inspected host takes 25 ms instead of 44 ms.** The rest is the TLS work
  on both sides. A body over 64 MiB, which used to fail, now streams. The regression test sends
  80 MiB to an origin that stops reading, and checks that the box's writes stop too.
- **HTTP/2 upstreams cost CPU on loopback, and save connections on the internet.** Per GB, the HTTP/2
  upstream costs about 0.6 CPU-s more than HTTP/1.1 (3.00 against 2.43), and the origin pays more too.
  Throughput and per-request cost are about the same. What it buys is one upstream connection, and
  one TLS handshake, for many box connections to the same host. With a local origin that saves
  nothing; with a real one it saves a TCP and TLS handshake of round trips per new upstream
  connection. Set `Upstream::http1_only` to keep a deployment on HTTP/1.1.
- **On a node, splicing costs what it costs on the control host:** 0.37 CPU-s per GB and 35 CPU-ms per
  1,000 kept-alive requests, against 2.47 and 157 inspected. The node checks the box's token at each
  `CONNECT`: 14 token decisions (7 methods, 2 paths). That adds about 0.08 ms to the `CONNECT`
  (0.39 ms against 0.31 ms on the control host), and the same check runs every 2 s on each spliced
  connection.

### Measured: real workloads in a gVisor box

These ran with `wicket run` (a program, gVisor, 2 CPUs, 2 GB of RAM) against the real registries and a
1 GiB test file. The zone allowed each host wholesale. The inspected arm adds a forbid rule per host
on an unused path. `experiments/network-overhead/workloads/` has the manifests and scripts.

The workloads:
- `cargo fetch --locked` of wicket's own workspace (about 300 crates);
- `npm install` of a project with 168 packages;
- a 1 GiB download with curl.

Each arm ran once, spliced first, so the registries' caches were no colder for the inspected arm.

| workload | inspected | spliced |
|---|---|---|
| `cargo fetch` (319 index and 366 crate requests) | 24.3 s | 15.8 s |
| `npm install` (326 requests, 20 MB) | 16.1 s | 19.1 s |
| 1 GiB download | 10.5 s (103 MB/s) | 8.9 s (121 MB/s) |
| CPU of the `wicket run` process, whole run | 4.7 s | 1.0 s |
| audit rows | 1,012 | 19 (one per connection) |

**Wall time here is set by the network and the box, not the proxy.** An earlier run of the same
workloads had the package caches on the box's `/tmp`, where `npm install` ran out of space. In that
run, `cargo fetch` took 7.6 s inspected and 7.0 s spliced, and the 1 GiB download took 4.7 s
inspected and 5.2 s spliced (233 and 211 MB/s).

What holds across both runs:
- the CPU: spliced, wicket spends about a fifth;
- the audit rows: one per connection instead of one per request;
- `cargo fetch` keeps HTTP/2 when spliced: its 366 crate downloads went over 2 connections to
  `static.crates.io`. Intercepted, they were 366 HTTP/1.1 requests.

**Re-measured after [#142](https://github.com/public/wicket/issues/142)** (2026-11-12, release build,
the same workloads, spliced first). The intercepting path now streams bodies, keeps
`content-length` and uses HTTP/2 to registries that offer it.

| workload | inspected | spliced |
|---|---|---|
| `cargo fetch` | 17.7 s | 18.8 s |
| `npm install` | 16.8 s | 16.1 s |
| 1 GiB download | 5.8 s (186 MB/s) | 6.6 s (167 MB/s) |
| CPU of the `wicket run` process, whole run | 6.1 s | 2.8 s |

The 1 GiB download through the intercepting path now runs as fast as spliced: both are set by the
network, not the proxy. Before, it took 10.5 s inspected against 8.9 s spliced. The CPU figures
include starting the run and the box, and spliced still costs less than half.

**npm scoped packages through an inspected registry.** npm asks for a scoped package as
`@scope%2fname`. The intercepting proxy refuses an encoded `/` in a path as ambiguous
([#114](https://github.com/public/wicket/issues/114)), with one exception
([#143](https://github.com/public/wicket/issues/143)): a first segment of exactly that shape is decided
as `/@scope/name` and sent upstream as written. The npm project above has no scoped packages; these
runs predate the exception.

## The audit writer

Every allowed request is an audit row. Until #62's first fix, each row was written inline with an
fsync, under the ledger lock, on a tokio worker. That was the largest per-request cost. Now one writer
per process commits rows in batches (`docs/reference/audit.md`). Rows for requests allowed by a grant
are the exception: they still wait for their commit, to fail closed.

| | kept-alive p50 / p99 (µs) | req/s, 16 kept connections | audit row, p50 (µs) |
|---|---|---|---|
| inline fsync (before) | 1,231–1,423 / 3,692–7,166 | 718–1,207 | 2,524–2,752 |
| batched writer (after) | 413–466 / 1,388–2,326 | 6,651–7,903 | 7.4–7.8 (an enqueue) |
| in-memory ledger (no disk at all) | 464–516 / 1,497–1,993 | 5,962–6,028 | 75–84 |

These ranges are the three rounds' values. They come from the proxy replica in
`experiments/network-overhead`, §7 of its `RESULTS.md`.

## The in-box forwarder

`wicket-fwd` replaced socat in the box. socat didn't set `TCP_NODELAY`, so Nagle and delayed ACKs
added about 40 ms to most new connections. Its 8 KiB buffer also held gVisor downloads to 14 MB/s.
`wicket-fwd` is one process that sets `TCP_NODELAY` and splices through a 256 KiB pipe. These figures
are new-connection p50 and 100 MB download medians, from curl in a `--network none` box, over three
runs:

| box | socat (before) | `wicket-fwd --copy rw` | `wicket-fwd --copy splice` (default) |
|---|---|---|---|
| gVisor (systrap) | 14–17 ms, 10–33 MB/s | 4.4–7.5 ms, 141–205 MB/s | 4.2–7.3 ms, 170–350 MB/s |
| runc | 2.3 ms, 366 MB/s | 1.7 ms, 1,070 MB/s | 2.5 ms, 1,160 MB/s |

In gVisor, the box's own network stack is the ceiling. A download from an origin inside the box, with
no hop at all, ran at about 100–240 MB/s.

## HTTP/3

A box's QUIC is relayed as datagrams over a unix `SOCK_SEQPACKET` socket and terminated on the host,
and every request is decided like any other. gVisor spends about 110 µs of CPU per UDP datagram on
the box's loopback, against about 8 µs in runc. With the standard 1452-byte packets, a gVisor box
downloads at 40–100 Mbit/s and costs about 190 CPU-s per GB. With `WICKET_H3_BOX_MTU=16000`, a client
that accepts large packets reaches 430–460 Mbit/s at about 43 CPU-s per GB
(`experiments/http3/RESULTS.md`, [#92](https://github.com/public/wicket/issues/92)). Over TCP, HTTPS is
faster in a gVisor box, and it is the path that splice-through applies to.

## Next

- Read-through caches for package registries on each node ([#139](https://github.com/public/wicket/issues/139)).
- Large inputs and outputs fetched and uploaded host-side ([#140](https://github.com/public/wicket/issues/140)).
- The `filtered` network mode, for protocols the proxy can't carry ([#63](https://github.com/public/wicket/issues/63)).

## Reproducing

```sh
cd experiments/network-overhead
CARGO_BUILD_JOBS=1 cargo build --release
# Proxy, per request and per GB: direct, inspected, spliced (about 4 minutes; ports 18128/18443).
target/release/netbench bench --only direct,egress- --rounds 3 --secs 4 --out logs/splice-through
# Streamed bodies, HTTP/2 upstreams and node splicing (#141, #142). The "before" arm needs this
# harness built from the commit before #142, as NETBENCH_BASELINE; without it, that arm is skipped.
NETBENCH_BASELINE=/path/to/old/netbench target/release/netbench bench \
  --only direct,egress-inspect/unix,egress-inspect-h1up,egress-inspect-base,egress-splice/unix,egress-node-splice \
  --rounds 3 --secs 4 --out logs/node-proxy
# Real workloads in a gVisor box (needs Docker with runsc, the agent image, and the internet).
workloads/prepare.sh /tmp/ws
for arm in splice inspect; do wicket run workloads/$arm.yaml --workdir /tmp/ws; done
```

The raw results are in `experiments/network-overhead/logs/splice-through/results.json` and
`logs/node-proxy/results.json`.
