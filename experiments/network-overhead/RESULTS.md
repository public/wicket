# Experiment #62: what the egress proxy costs, and where the time goes

**Question (#62, for design §7.3):** every byte a box sends goes through wicket's egress proxy, which
terminates TLS with the run's CA, decides each request, and re-originates TLS upstream. The box reaches
it through socat and a bind-mounted unix socket. What does that cost per request and per gigabyte?
Which parts cost the most? What would a host-only check with splice-through save, and when are the
`filtered` and `direct` modes worth it?

**Answer: interception is not the main cost today. Two small things are: the audit write and socat.**
- **The audit row costs more than everything else per request.** Every allowed request writes a
  hash-chained SQLite row with an fsync (0.71 ms p50), under the ledger mutex, on a tokio worker. A
  kept-alive 1 KB request takes 1.32 ms through the proxy against 0.13 ms direct. With an in-memory
  ledger it takes 0.47 ms. It also caps a run at about 930 requests/s (16 connections). With an
  in-memory ledger the same run does 5,900, and direct does 19,700.
- **socat in the box adds 40 ms stalls and caps gVisor downloads.** Without `nodelay`, Nagle plus
  delayed ACK adds about 40 ms to most new connections. In a runc box, curl's new-connection time is
  46.9 ms through the proxy and 9.3 ms with `nodelay`. socat's 8 KiB buffer holds downloads in a gVisor
  box to 14 MB/s. With `-b 262144` they reach 170 MB/s.
- **TLS interception itself costs 2.4 CPU-seconds per GB** and 0.2–0.35 ms of CPU per request. About a
  third of its CPU is AES-GCM (decrypt and re-encrypt), and most of the rest is copying. Leaf
  certificates are already cached (0.22 µs a lookup; 0.13 ms to mint the first time for a host). The
  decision costs 1 µs. Neither needs work.
- **Splice-through for hosts allowed wholesale is cheap and keeps HTTP/2.** It checks the host at
  CONNECT and the SNI in the ClientHello, then moves encrypted bytes with splice(2). It costs 0.17
  CPU-seconds per GB (14 times less than interception) and 0.18 ms per kept-alive request (direct:
  0.13 ms). It downloads at 523 MB/s (direct: 477; both noisy). h2 passes through end to end.
- **`filtered` buys little speed over mediated with splice-through.** An SNI-only proxy without
  CONNECT (the `filtered`/`direct` shape) measures the same as CONNECT splice-through, within noise. In
  gVisor the box's own network stack is the ceiling: about 100 MB/s even to an origin inside the box.
  A real interface in gVisor still goes through that stack.

All numbers come from a shared 4 vCPU Vultr VPS on 2026-11-11. Other jobs ran at the same time (load
3–5), so timings carry ±30% noise, and download throughput much more (see the min–max columns). CPU per
GB and per request are steadier than wall-clock throughput.

## 1. What was built

This is a standalone Cargo project with its own `[workspace]`. It depends on `wicket-core`,
`wicket-store` and `wicket-proxy` by path (at 727e50f). It is one binary, `netbench`, with one role
per process, so each process's CPU can be read from `/proc`.

| file | role |
|---|---|
| `src/origin.rs` | HTTPS origin for `origin.test` with its own CA, HTTP/1.1 and h2. Serves `/1k`, `/bytes/N` (streamed from one static buffer) and `POST /upload`. |
| `src/mitm.rs` | A replica of `egress.rs`'s allowed-by-reach path, using the same crates and calls (below). |
| `src/pass.rs` | The splice-through prototype: CONNECT, host decision, SNI check, then copy (tokio) or splice(2). `--mode sni` drops CONNECT. Also `fwd`, a TCP-to-unix forwarder in place of socat. |
| `src/splice.rs` | splice(2) through a pipe, two blocking threads per connection. |
| `src/client.rs` | The box's client: CONNECT or direct TLS, HTTP/1.1 or h2, with per-phase timings. TLS resumption is off, as for a fresh process. |
| `src/driver.rs` | `bench`: 15 setups × 3 rounds; starts each chain, runs the workloads, reads CPU. |
| `src/micro.rs` | In-process costs: leaf minting, a TLS handshake, the decision, the audit row. |
| `box.sh` | The in-box legs: curl inside a runc or gVisor container with `--network none`, through socat and a bind-mounted socket, as `wicket-entry` sets it up. |
| `perf.sh` | perf profiles of the mitm and pass processes during 5 × 100 MB downloads. |
| `summarize.py` | The tables below, from `logs/results.json` and `logs/box-*.txt`. |
| `zone.yaml` | The bench zone: the self-hosting example's reach plus `origin.test`, allowed for every method and path. |

**The replica (`mitm.rs`)** runs the same steps as the real proxy:
- hyper HTTP/1.1 on a unix socket, CONNECT and upgrade;
- the real `RunCa::server_config`, then a rustls accept and hyper HTTP/1.1 inside the tunnel;
- the Host check, `canonical_path`, `Op::egress_with_query` and `CompiledZone::evaluate`;
- the event written as an audit row to a file `Ledger` (`wicket_store`, as `wicket run` opens it) under
  its mutex, then sent on the event channel;
- a shared `reqwest::Client` (rustls, no h2) that buffers the request body (64 MB limit), strips
  headers with the same lists and streams the response.

It differs in four ways:
- the upstream URL carries the origin's port;
- the reqwest client resolves `origin.test` to 127.0.0.1 and trusts the origin's CA;
- grants, approvals, credential swaps and strikes are left out (the bench sends only allowed requests);
- it records stage timings.

**Routing.** The real proxy can't reach a local origin: its upstream client trusts only the public
roots, and it always connects to port 443. The replica above is how this experiment got around that.
`origin.test` is an ordinary hostname to the zone (`never_reachable` only rejects IP literals and
`localhost`).

**Setups** (`driver.rs`). `unix` means the client connects to the proxy's socket directly. `socat` is
`TCP-LISTEN,fork,reuseaddr` to `UNIX-CONNECT`, as in `wicket-entry`. `fwd` is this experiment's
forwarder.
- `direct`, `direct-h2`: client to origin.
- `mitm/{unix,socat,socat-nodelay,fwd}`: the replica, today's path being `mitm/socat`.
- `mitm-memaudit/unix`: audit rows to an in-memory ledger. `mitm-nopool/unix`: no upstream keep-alive.
- `pass/{unix,socat}`, `pass-splice/{unix,fwd-splice}`, `pass-h2/unix`: splice-through.
- `sni/tcp`, `sni-splice/tcp`: SNI only, no CONNECT; the `filtered`/`direct` estimate.

## 2. Per request (1 KB, HTTP/1.1 unless noted; client on the host, no sandbox)

Each figure is the median over 3 rounds of that round's p50 or p99. Per round there are 150 new-connection
requests, 1,000 kept-alive ones and 4 s at 16 concurrent workers each way.

| setup | new conn p50 / p99 (ms) | kept-alive p50 / p99 (µs) | req/s, 16 kept conns | req/s, 16 workers, new conn each |
|---|---|---|---|---|
| direct | 1.48 / 4.28 | 125 / 336 | 19,660 | 1,072 |
| direct-h2 | 1.62 / 4.51 | 181 / 672 | 9,890 | 722 |
| **mitm/socat (today)** | **12.87 / 59.16** | **2,132 / 8,408** | **730** | **334** |
| mitm/socat-nodelay | 4.27 / 11.76 | 1,318 / 2,615 | 1,354 | 679 |
| mitm/fwd | 3.18 / 8.65 | 1,286 / 2,500 | 1,167 | 633 |
| mitm/unix | 4.41 / 8.10 | 1,318 / 5,435 | 930 | 462 |
| mitm-memaudit/unix | 1.75 / 4.55 | 467 / 1,298 | 5,949 | 1,572 |
| mitm-nopool/unix | 4.04 / 6.81 | 2,430 / 7,199 | 520 | 483 |
| pass/unix | 1.66 / 2.41 | 180 / 447 | 18,847 | 1,310 |
| pass/socat | 43.19 / 45.96 | 269 / 1,034 | 9,624 | 516 |
| pass-splice/unix | 1.73 / 4.57 | 183 / 462 | 17,704 | 843 |
| pass-splice/fwd-splice | 2.67 / 11.68 | 242 / 616 | 5,977 | 516 |
| pass-h2/unix | 1.88 / 4.16 | 254 / 539 | 12,103 | 1,070 |
| sni/tcp | 1.62 / 2.86 | 209 / 331 | 15,165 | 1,144 |
| sni-splice/tcp | 1.75 / 4.55 | 182 / 596 | 7,588 | 1,012 |

The splice prototype uses two blocking threads per connection. That is why it does worse than tokio's
copy on short connections and at 16 kept connections. A production version would drive splice from the
event loop.

**CPU per request** (16 kept connections, CPU-ms per 1,000 requests):

| setup | proxy | hop |
|---|---|---|
| mitm/unix | 360 | – |
| mitm/socat | 363 | 115 |
| mitm-memaudit/unix | 200 | – |
| mitm-nopool/unix | 895 | – |
| pass/unix | 27 | – |
| pass/socat | 38 | 35 |
| pass-splice/unix | 40 | – |

## 3. Where the time goes

**A new connection, phase by phase** (p50, µs, as the client sees it):

| setup | connect | CONNECT | TLS handshake | first response | total |
|---|---|---|---|---|---|
| direct | 200 | – | 908 | 281 | 1,477 |
| mitm/unix | 170 | 156 | 947 | 2,419 | 4,414 |
| mitm-memaudit/unix | 110 | 143 | 807 | 596 | 1,745 |
| mitm/socat | 716 | 1,174 | 1,251 | 6,030 | 12,875 |
| mitm/socat-nodelay | 326 | 703 | 944 | 1,736 | 4,271 |
| pass/unix | 99 | 117 | 1,070 | 318 | 1,665 |
| pass/socat | 494 | 731 | 1,336 | 40,818 | 43,190 |

**In-process costs** (`logs/micro.json`, p50 / p99, µs):

| step | p50 | p99 | when |
|---|---|---|---|
| audit row, file ledger (WAL, fsync per commit) | 711 | 4,044 | every request |
| audit row, in-memory ledger | 18 | 58 | (comparison) |
| TLS 1.3 handshake, both sides in memory | 638 | 1,427 | every new box connection (box side) |
| leaf: first `server_config` for a host | 129 | 325 | once per host per run |
| leaf: cached `server_config` | 0.22 | 0.50 | every new box connection |
| P-256 key generation alone | 41 | 102 | inside the first mint |
| `canonical_path` + `Op` + `evaluate` | 1.0 | 2.2 | every request |
| `host_verdict` | 0.07 | 0.12 | every CONNECT |
| splice-through check (`needs_inspection`) | 0.39 | 0.91 | every CONNECT |

In order of cost:
1. **The audit row.** SQLite's default `synchronous=FULL` syncs the WAL on every commit. The write also
   reads the previous row's hash first. It holds the ledger mutex and blocks a tokio worker while it
   does this. So concurrent requests queue behind each other's fsync. Under 16 connections the
   replica's own timings show 2.4 ms p50 and 25 ms p99 inside `audit_emit` (`logs/results.json`,
   `proxy_stamps`). With an in-memory ledger: 65 µs p50.
2. **The in-box socat.** It doesn't set `TCP_NODELAY` on its TCP side. When the response leaves the
   proxy as several small writes, Nagle holds the second one until the client ACKs the first, and the
   client delays that ACK by 40 ms. That's the 40.8 ms "first response" in `pass/socat`. It hits
   `mitm/socat` on some connections (p50 12.9 ms, p99 59 ms). With `nodelay` it is gone. socat also
   forks a process per connection: 1.3 CPU-ms per new connection, more than the proxy itself (0.85).
3. **TLS on two legs.** The box-side handshake is a full handshake for every new box connection (a
   fresh process has no session to resume): about 0.6 ms of CPU. The upstream side is pooled by reqwest.
   Without the pool (`mitm-nopool`), each request also pays an upstream handshake: +1.1 ms per request,
   and throughput drops from 930 to 520 requests/s.
4. **HTTP twice.** With the audit row out of the way (`mitm-memaudit`), a kept-alive request costs
   about 0.34 ms more than direct. That is the second HTTP/1.1 parse and serialize, the second
   decrypt and encrypt, and the extra hop.
5. **The decision and the leaf** are microseconds. The leaf cache works: 0.6 µs median in the proxy's
   own timings.

**Where the CPU goes on large downloads** (`logs/perf-mitm.txt`, `logs/perf-pass.txt`, perf on the
proxy during 5 × 100 MB):
- mitm: AES-GCM 33% (open and seal about half each); userspace memmove 9.5%; kernel copies 9.2%;
  zeroing fresh pages 6.5% (a new buffer per chunk); the rest is syscalls, scheduling and allocation.
- pass with tokio copy: no crypto; kernel copies 16%, socket locking and wakeups 11%, recv/send.
- pass with splice: almost nothing (0.17 CPU-s per GB).

## 4. Large transfers (100 MB, client on the host)

9 downloads per setup (3 per round). Throughput is noisy on this machine. CPU-seconds per GB are the
better measure.

| setup | MB/s median (min–max) | proxy CPU s/GB | hop CPU s/GB |
|---|---|---|---|
| direct | 477 (275–910) | – | – |
| direct-h2 | 271 (207–616) | – | – |
| mitm/unix | 202 (156–459) | 2.43 | – |
| mitm/socat | 230 (159–343) | 2.57 | 0.90 |
| mitm/fwd (tokio copy) | 197 (117–259) | 2.63 | 1.63 |
| mitm-memaudit/unix | 334 (241–482) | 2.37 | – |
| pass/unix (tokio copy) | 378 (160–705) | 1.07 | – |
| pass/socat | 261 (188–312) | 1.10 | 0.97 |
| pass-splice/unix | 523 (400–892) | 0.17 | – |
| pass-splice/fwd-splice | 562 (310–802) | 0.23 | 0.30 |
| pass-h2/unix | 346 (203–509) | 1.03 | – |
| sni/tcp | 366 (136–705) | 1.43 | – |
| sni-splice/tcp | 590 (331–829) | 0.23 | – |

For scale: the client and the origin each spend 1.0–1.4 CPU-s per GB on their own TLS. Interception
adds 2.4 on top, so one core proxies at most about 400 MB/s. tokio's `copy_bidirectional` (8 KiB
buffer) costs more than socat as a forwarder. splice costs a fifth of either.

**Uploads.** The proxy buffers whole request bodies before sending them upstream. A 10 MB upload takes
57 ms through `mitm/unix` against 24 ms direct and 30 ms through `pass/unix`. A body over 64 MB fails.

## 5. Inside a box: runc and gVisor (`box.sh`)

curl (the image's own) runs inside `wicket/claude-code:poc` with `--network none`. It goes through
socat to the bind-mounted unix socket, as `wicket-entry` sets it up. gVisor is `runsc --host-uds=open`
on the systrap platform (no KVM on this VPS). There are 300 requests per leg and 5 downloads of
100 MB.

Legs:
- `direct`: runc on the host network, straight to the origin.
- `local`: an origin inside the box (`openssl s_server -WWW`). It shows the box's own ceiling. It closes
  every connection, so it has no kept-alive figure.
- `raw`: the hop alone (in-box socat, the socket, a host socat to the origin), TLS end to end.
- `-b256k`: in-box socat with `-b 262144,nodelay`. `nodelay` is `nodelay` alone.

| box | leg | new conn total p50 / p99 (ms) | kept-alive (ms) | 100 MB MB/s (median; all 5) |
|---|---|---|---|---|
| runc | direct (host net) | 6.4 / 11.9 | 0.21 | 455 |
| runc | local | 6.3 / 11.5 | – | 443 |
| runc | **mitm (today)** | **46.9 / 53.6** | 1.43 | 250 |
| runc | mitm-nodelay | 9.2 / 22.7 | 1.43 | 172 |
| runc | mitm-b256k | 9.3 / 18.5 | 1.75 | 235 |
| runc | pass (splice) | 11.6 / 54.9 | 0.35 | 305 |
| runc | raw | 46.3 / 53.8 | 0.39 | 247 |
| runc | raw-b256k | 7.2 / 15.6 | 0.34 | 407 |
| gVisor | local | 9.0 / 20.4 | – | 104 (97–239) |
| gVisor | **mitm (today)** | **21.5 / 44.9** | 3.91 | **14** (12–15) |
| gVisor | mitm-nodelay | 39.2 / 68.2 | 4.36 | 11 (10–48) |
| gVisor | mitm-b256k | 26.3 / 59.2 | 1.69 | **170** (147–211) |
| gVisor | pass (splice) | 21.4 / 41.5 | 0.92 | 47 (41–52) |
| gVisor | raw | 16.9 / 35.3 | 0.77 | 46 (37–55) |
| gVisor | raw-b256k | 16.5 / 31.4 | 0.83 | 104 (79–117) |

- In runc, the 40 ms socat stall shows on most new connections (`mitm`, `raw`, and `pass` at p99).
  `nodelay` removes it.
- In gVisor, every read and write socat makes is a trapped syscall. Its 8 KiB buffer holds the proxied
  download to 14 MB/s. With 256 KiB it is 170 MB/s, at the box's own ceiling (`local`: 97–239 MB/s in
  this run; other gVisor work was running on the machine). `pass` and `raw` still used 8 KiB socat,
  which is why they are slow here.
- gVisor's new-connection time (17–26 ms) is mostly the box's own TLS and network stack: `local`, with
  no hop at all, takes 9 ms.
- An earlier, otherwise identical run gave gVisor `local` 46 MB/s and `mitm` 41 MB/s. Only the
  ordering is reliable: the 8 KiB socat buffer is the bottleneck in gVisor, and the proxy is not.

## 6. Recommendations for #62

In order of payoff per line of code:
1. **Take the audit write off the request path.** Send events to one writer thread that commits in
   batches (group commit: one fsync per batch, the hash chain kept in memory). Or use
   `synchronous=NORMAL` in WAL mode, which loses at most the last few rows on power loss, not on a
   crash. Don't hold a `std::sync::Mutex` across SQLite calls on a tokio worker. Expected effect:
   1.32 → about 0.47 ms per kept-alive request, and 930 → about 5,900 requests/s per run.
2. **Fix socat in `wicket-entry` now:** `socat -b 262144 TCP-LISTEN:…,fork,reuseaddr,nodelay
   UNIX-CONNECT:…`. That's two options on three lines. It removes the 40 ms stalls (runc: 47 → 9 ms per new
   connection) and raises gVisor downloads 12 times (14 → 170 MB/s). Then replace socat with wicket's
   own forwarder (§1 of #62, item 4). It needs no fork per connection (socat spends 1.3 CPU-ms per
   connection), large buffers, `TCP_NODELAY`, and splice where the kernel supports it (in runc,
   `fwd-splice` costs 0.30 CPU-s per GB against socat's 0.90). Measure it in gVisor, where splice and
   buffer sizes behave differently.
3. **Splice-through for hosts a zone allows wholesale with nothing injected** (item 3 of #62). Decide
   at CONNECT. Require the ClientHello's SNI to equal the CONNECT host. Audit once per connection,
   not per request, because requests aren't visible. It costs 14 times less CPU per GB (2.4 → 0.17 s)
   and about 10 times less per request (360 → 27–40 CPU-ms per 1,000), keeps h2 end to end, and avoids the upload buffering. The check
   costs 0.4 µs.
   - The zone needs a clear way to say "wholesale". This prototype treats a reach rule with `/**` and
     every method as wholesale, if no inject or forbid rule names the host.
   - The zone view should mark these hosts "not inspected".
   - Drive splice from the event loop: the two-threads-per-connection prototype is slow on short
     connections.
4. **Keep what already works.** Leaf caching (0.22 µs; the first mint is 0.13 ms per host per run)
   and upstream pooling (saves 1.1 ms per request) are fine. The decision (1 µs) is noise.
   Pre-minting leaves or a faster key type would save 0.13 ms once per host: not worth it.
5. **Stream request bodies** in the intercepting path instead of collecting them. Uploads take 2.4
   times as long as direct, and anything over 64 MB fails (a `git push` of a large pack, a release
   upload).
6. **Upstream h2** (reqwest's `http2` feature) would let one upstream connection serve many box
   connections. It doesn't matter at these rates once item 1 is done. The box side should stay
   HTTP/1.1 for intercepted hosts, as `ca.rs` intends.
7. **`filtered` and `direct` aren't needed for speed.** After items 1–3, mediated traffic to
   uninspected hosts measures the same as an SNI-only proxy on a real interface, within noise. That
   proxy is a user-space stand-in for `filtered`. Real `filtered` (host nftables) would also save the
   last 0.17–0.23 CPU-s per GB, but it can't get past gVisor's own network stack either. In gVisor the box's own stack is the ceiling either way. Keep them for
   protocols the proxy can't carry (UDP, HTTP/3, non-TLS TCP), not for throughput. This supports
   §7.3's "measure before reaching for `direct`".

Also noted: the proxy strips `content-length` from responses (`STRIP_RESPONSE`), so the box gets
every body chunked. Clients lose download sizes and progress bars. It's cheap to keep the header when
the body is passed through unchanged.

**Not measured here.** Real workloads (`cargo fetch`, `npm install`, model streaming) and the
remote-node round trip over SSH need external hosts or a second node. The breakdown above says what
they will hit:
- many small requests: the audit row and the socat stall;
- large downloads: TLS and socat's buffer;
- remote nodes: the round trip on every request, until #57 moves the proxy onto the node.

## 8. After the fix: the batched audit writer (2026-11-12)

#62's first fix is in: `wicket run` now starts one background audit writer per process, which
commits in batches (`wicket-store`'s `writer.rs`, `docs/audit-export.md`). The replica has a
`--batched` mode that does what `RunCtx::emit` now does. With a writer present, it holds the ledger
lock only long enough to clone the writer, then queues an allowed-by-reach row without waiting for
it. Same box, same day, load 5–6. The three arms were interleaved over 3 rounds (`netbench bench
--only mitm/unix,mitm-batched/unix,mitm-memaudit/unix,mitm/fwd,mitm-batched/fwd --rounds 3 --big
20000000`). Raw output is in `logs/batched-writer/`.

| setup | kept-alive p50 / p99 (µs) | new conn p50 (ms) | req/s, 16 kept conns | `audit_emit` p50 / p99 (µs) |
|---|---|---|---|---|
| mitm/unix (inline fsync, as before) | 1,231–1,423 / 3,692–7,166 | 2.74–4.99 | 718–1,207 | 2,524–2,752 / 12,452–30,800 |
| **mitm-batched/unix** | **413–466 / 1,388–2,326** | **1.89–2.12** | **6,651–7,903** | **7.4–7.8 / 795–1,049** |
| mitm-memaudit/unix (in-memory ledger) | 464–516 / 1,497–1,993 | 1.64–2.01 | 5,962–6,028 | 75–84 / 2,737–2,969 |
| mitm/fwd | 1,408–1,575 / 4,048–5,618 | 3.61–5.50 | 778–1,068 | 2,647–3,029 / 15,873–19,462 |
| mitm-batched/fwd | 504–543 / 1,203–1,907 | 2.55–2.88 | 4,845–7,594 | 7.2–7.6 / 601–992 |

Ranges are the three rounds' values. The batched writer brings a kept-alive request down to what it
costs with no disk at all: 0.47 ms, against 1.3 ms with the inline fsync. It raises throughput about
7×, past the in-memory arm. Under 16 connections, `audit_emit` used to be mostly waiting for the
ledger mutex (2.5 ms p50). It is now a 7 µs enqueue. The in-memory arm still writes under the lock,
which is why it lands a little behind the batched arm.

In-process (`netbench micro`, `logs/batched-writer/micro.json`):

| step | p50 (µs) | p99 (µs) |
|---|---|---|
| audit row, file ledger, inline (fsync per row) | 647 | 2,590 |
| queue a row with the batched writer (`submit`) | 0.62 | 7.2 |
| durable append, one thread alone (`append`: waits for its commit) | 746 | 2,705 |
| durable append, 16 threads at once (mean per record) | 80 | – |
| audit row, in-memory ledger | 19 | 54 |

Requests allowed by a human's grant, decisions and approvals still wait for their commit. That is
one fsync when nothing else is writing, and a share of one under load.

## 7. Reproducing

```sh
cd experiments/network-overhead
CARGO_BUILD_JOBS=1 cargo build --release
target/release/netbench micro > logs/micro.json
target/release/netbench bench --rounds 3 --secs 4 --out logs     # about 15 minutes; ports 18128/18129/18443
sudo ./box.sh target/release/netbench wicket/claude-code:poc logs/   # needs docker with a runsc runtime (--host-uds=open)
sudo ./perf.sh target/release/netbench logs/
python3 summarize.py logs/results.json > logs/summary.md
```

`logs/` holds:
- `results.json`: every setup and round, with the proxy's stage timings;
- `summary.md`: all tables;
- `micro.json`;
- `box-{runc-direct,runc,runsc}.txt`: raw curl `-w` lines: connect, TLS done, first byte, total,
  bytes/s;
- `perf-{mitm,pass}.txt` and the client throughput during each profile.

Each run used one heavy job at a time with a 1-hour timeout, on a shared 4 vCPU Vultr VPS.
