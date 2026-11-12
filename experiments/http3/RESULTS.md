# Experiment #92: HTTP/3 egress for boxes (phase 1, the spike)

## Answer

**Yes, it works in gVisor, and the plan in #92 holds with three changes.** An HTTP/3 client in a
`--runtime runsc --network none` box resolves through wicket DNS and sends QUIC to a synthetic address
on `lo`. A forwarder relays the datagrams over a bind-mounted unix `SOCK_SEQPACKET` socket, and the host
terminates QUIC (quinn 0.11 + h3 0.0.8) with a leaf from the run CA. Each request is decided by
`wicket_core::CompiledZone::evaluate` and audited, then re-originated over HTTP/3, falling back to
HTTP/2. The issue's done-when is met in the spike: the allowed URL, the 403 over HTTP/3, the hidden
host, and the audit lines.

The three changes:

1. **Raise the QUIC MTU bound on the box leg.** gVisor's loopback costs about 110 µs of CPU per UDP
   datagram, against about 8 µs in runc, and `sendmmsg`/`recvmmsg` don't change that. At the usual 1452-byte MTU, a box
   downloads at 40–100 Mbit/s and burns about 190 CPU-s per GB. The box leg is `lo` plus a unix socket,
   with no real link. With the PMTUD upper bound at 16000 on both ends, gVisor reaches 430–460 Mbit/s
   at about 43 CPU-s/GB, as cheap as runc at 1452. **That only applies to clients that advertise a
   large `max_udp_payload_size`.** With the bound on the terminator alone and a stock quinn client
   (advertising 1472), the MTU stayed at 1472 and throughput stayed at 27–86 Mbit/s. Real clients are
   unverified, so plan for the stock-client number: 40–100 Mbit/s and about 190 CPU-s/GB.
2. **The relay frame should be stateless, not flow-id based.** It carries the client's and the
   destination's address and port in both directions. The forwarder then keeps no flow table and no
   idle timer, so QUIC idle timeouts and migration are handled end to end. Add a segment-size field
   (GSO/GRO over the relay).
3. **Use `SOCK_SEQPACKET` only. `SOCK_DGRAM` is not a usable fallback** (under the box's current runsc
   flags, `--host-uds=open`). In gVisor the host can't
   answer a box's datagram socket: the socket is unnamed, abstract names stay in the sentry, and a
   bound path never reaches the host. Fall back to a length-framed stream.

Also: put the synthetic range on `lo` as **one address with a /16 prefix**. gVisor makes the whole
prefix local. gVisor refuses `ip route add local` (`Operation not supported`), and adding 4096 /32s
takes 10.7–12.7 s.

## Setup

- Code: `src/` is one static musl binary with roles `fwd` (in the box), `term`, `origin`, `get` (the
  HTTP/3 client), `resolve` and `udpbench`.
- Scripts:
  - `probe/run-q1.sh` (question 1);
  - `scripts/chain.sh` (questions 2–4);
  - `scripts/bench.sh` (question 5);
  - `scripts/gotchas.sh` and `scripts/upload.sh` (question 6).
- Boxes get wicket's flags: `--network none`, `--read-only`, every capability dropped after setup,
  uid 1000 and no-new-privileges. Root first runs `ip addr add 198.18.0.1/32` and
  `198.19.0.1/16 dev lo`, as `wicket-entry` would.
- Versions: gVisor `release-20261102.0` (systrap); image `wicket/claude-code:poc` (Debian glibc, Node
  22).
- Machine: the shared 4 vCPU VPS. It was busy (load 4–7 from other sessions), so wall-clock throughput
  is noisy, while CPU per GB and per datagram hold up. Compare arms only within one table.
- Measured 2026-11-12.

## 1. UDP on `lo` inside gVisor

| probe (`probe/run-q1.sh`) | runsc | runc |
|---|---|---|
| bind 198.19.0.5:443 and 198.19.0.6:443 (/32s on lo) | ok | ok |
| wildcard `0.0.0.0:443` + `IP_PKTINFO`: original destination seen, reply sent from it | ok | ok |
| `ip addr add 198.18.64.1/18 dev lo`, then traffic to 198.18.67.4, 198.18.64.9, 198.18.77.1 (also with the wildcard socket) | ok (the whole prefix is local) | ok |
| `ip route add local 198.19.0.0/16 dev lo table local` | **refused** (`Operation not supported`) | ok |
| 4096 /32s via `ip -batch` | ok, 10.7–12.7 s | ok, 0.7 s |
| UDP 1500 / 9000 / 65000-byte datagrams on lo (lo MTU 65522) | ok | ok |
| unix `SOCK_STREAM`, `SOCK_SEQPACKET` to a host socket (1 B – 65000 B, boundaries kept) | ok | ok |
| unix `SOCK_DGRAM`, connected | host receives, can't reply (peer unnamed) | same |
| unix `SOCK_DGRAM`, autobound / bound to a path in the mounted dir | nothing reaches the host | host receives; the reply failed on the probe's file permissions (not a runc limit) |
| `UDP_SEGMENT` (GSO), 3600 bytes at segment 1200 | **accepted but ignored**: one 3600-byte datagram | three 1200-byte datagrams |
| `UDP_GRO`, `IP_RECVTOS`, `IP_MTU_DISCOVER=PROBE`, `sendmmsg`/`recvmmsg` | accepted | accepted |

- In gVisor, `recvmmsg` refuses `MSG_WAITFORONE` (EINVAL). Block in `recvmsg` for the first datagram,
  then use `recvmmsg(MSG_DONTWAIT)` for the rest.

## 2. wicket DNS

- The forwarder relays UDP DNS on `198.18.0.1:53` (`--dns 198.18.0.1`) to the host over the same
  frame.
- An allowed name gets one synthetic 198.19.x.y address, stable for the run. 198.19.0.0/24 is
  reserved for wicket.
- A hidden name gets NXDOMAIN.
- AAAA for an allowed name is NOERROR with no answer: NXDOMAIN would make resolvers drop the A answer.
- HTTPS (type 65) answers `1 . alpn=h3 ipv4hint=<synthetic>`.

| resolver in the box | allowed (`h3.test`, `*.wild.test`) | hidden (`hidden.test`, `example.com`) |
|---|---|---|
| musl `getaddrinfo` (static binary) | 198.19.1.x, 0.8–2.7 ms | `Name does not resolve` |
| glibc `getent ahosts` | 198.19.1.x | exit 2 |
| Node 22 `dns.lookup` / `resolve4` / `resolve6` | address / address / `ENODATA` | `ENOTFOUND` for all three |
| raw HTTPS query (python) | `alpn h3 ipv4hint 198.19.1.0`, TTL 300 | — |

- Node 22's `dns.resolve(name, "HTTPS")` rejects the rrtype, so it can't use the HTTPS record.

## 3–4. Termination, decisions, and a real HTTP/3 client in the box

The client is `get` (quinn + h3, from the experiment). It trusts the run CA mounted at `/wicket/ca/`.
All cases are in `scripts/chain.sh`, in gVisor:

| case | result |
|---|---|
| allowed GET, allowed POST | 200 from the HTTP/3 origin, audited `allow (reach rule 0)` |
| out of reach (`/secret`) | **403 over HTTP/3**, wicket's problem JSON, `x-wicket: out-of-reach` |
| forbidden (`/admin/**`) | 403, `x-wicket: forbidden` |
| upstream has HTTP/2 only | 200 via HTTP/2. The first request costs **507 ms** (the HTTP/3 connect timeout). The second takes 1.7 ms (h2 remembered per host). |
| wildcard host `a.wild.test` | 200 |
| hidden host | doesn't resolve |
| SNI `h3.test` sent to `h2only.test`'s synthetic address | handshake refused: no certificate for that name |
| `:authority h2only.test` on the `h3.test` connection | 421 `misdirected`: a connection serves only the host its address was minted for |

- The terminator picks the server config by the datagram's synthetic destination address, so the
  certificate resolver mints only for that name.
- The request's `:authority` must match it too.
- Decisions took 10–265 µs (`decide_us` in the audit).

## 5. Cost

### Small requests

Same-run medians (`bench-k1452`, gVisor, MTU 1452, 30 new connections and 300 requests on one
connection, `/small` = 42 bytes):

| | direct HTTP/3 (host client → origin) | through wicket from a gVisor box |
|---|---|---|
| new connection: handshake + h3 ready | 2.1 ms | 5.5 ms |
| first request on it | 0.8 ms (p90 1.1) | 3.1 ms (p90 5.1) |
| request on an open connection | 0.28 ms (p90 0.42) | 1.41 ms (p90 2.1) |
| same, runc box | — | 1.02 ms (new: 2.3 ms, handshake 2.5 ms) |

Over all the gVisor runs at MTU 1452, the chain's open-connection p50 was 1.4–2.3 ms and the first
request 3.1–8.2 ms.
The noise came from the box's load.

### 100 MB downloads and CPU per GB

The gVisor arms are 2 × 100 MB, runc 1 × 100 MB, and direct 3 × 100 MB (the CPU) or 2 × 100 MB (the Mbit/s). Mbit/s is per download; CPU is from `/proc` and the box's cgroup `cpu.stat`
over the downloads, scaled to 1 GB.

| arm | Mbit/s | box cgroup (sentry + client + fwd) | of which fwd | terminator | origin | total CPU-s/GB |
|---|---|---|---|---|---|---|
| direct HTTP/3 on the host | 1,400–1,650 | — (client 6.2) | — | — | 5.5 | **11.7** |
| gVisor, MTU 1452 | 80–96 | 166 | 80 | 18.7 | 6.8 | **191** |
| gVisor, bound 16000/60000 on the terminator only (stock client, MTU stays 1472) | 27–86 | — | — | — | — | (as 1452) |
| gVisor, `--mtu-upper 16000` on both ends | 433–458 | 26 | 12.7 | 10.5 | 6.1 | **43** |
| gVisor, `--mtu-upper 32000` | 470–483 | 23 | 11.8 | 11.4 | 6.5 | 41 |
| gVisor, `--mtu-upper 60000` | 545–573 | 17.7 | 7.2 | 10.9 | 6.2 | **35** |
| runc, MTU 1452 | 364 | 16.3 | 6.6 | 13.7 | 6.4 | 36 |

- **Attribution** (`udpbench`, in the box, 50,000 datagrams of 1452 B on `lo`):

  | | per datagram, wall | per datagram, CPU | MB/s |
  |---|---|---|---|
  | gVisor | 62–95 µs | 107–171 µs | 15–23 |
  | runc | 4–7 µs | 7–8 µs | ~200 |

  - In gVisor, `sendmmsg`/`recvmmsg` save about a third at most. 9000-byte datagrams reach 95 MB/s in
    gVisor, so the cost is per datagram.
  - The terminator's own CPU (8–19 s/GB) and the host-side relay are minor.
  - At MTU 1452 the box runs near its `--cpus 2` cap: 1.4–1.7 CPUs busy, and up to 23 throttled
    periods per run. With a large MTU it has room to spare.
- **Batching over the relay** (GSO from quinn into one unix message, split with `sendmmsg` in the
  box; GRO the other way) helps a little at MTU 1452. In two interleaved pairs, fwd CPU fell by 20–22%
  (18.8 → 14.6 and 25.0 → 20.0 s per 200 MB), and throughput went 75 → 92 and 58 → 72 Mbit/s. It makes no difference with a large MTU. Keep it: it's cheap.
- **Large MTU caveat 1: the client must allow it.** The terminator's packets to the client are capped
  by the client's `max_udp_payload_size` transport parameter. quinn clients advertise 1472 unless
  configured; the RFC's default when the parameter is absent is 65527. Which agents' HTTP/3 clients
  (curl/ngtcp2, quiche, Chromium) advertise more, and whether they probe up, is phase 2's first
  check. Uploads are bounded by the client's own PMTUD.
- **Large MTU caveat 2: latency on new connections.** At bound ≥ 32000, the first request on a new
  connection took about 60 ms (p50) instead of 3 ms. At 16000, p50 was 4.8 ms and p90 37 ms.
  - Requests on an open connection were unaffected.
  - Relay batching off didn't change it. Client GSO off halved the median (33 ms) but not the p90
    (69 ms).
  - The terminator handled those requests in under 1 ms, so the delay is in the transport, during
    PMTUD (probably a probe or pacing interaction). It's unexplained; see the plan.
- Setting `initial_mtu` to 16000 on both ends hung the connection; leave the start at 1200 and let
  PMTUD climb.

## 6. Gotchas

- **0-RTT is refused.** The terminator's rustls config has `max_early_data_size` 0, so tickets
  allow no early data, and a reconnecting client doesn't offer it (`gotchas.sh`: `offered: false`).
  Keep it that way: replayed early data would replay a request that was already decided and audited,
  and grants and injection make replay matter.
- **Migration works and should stay on.**
  - A client that rebinds to a new port mid-connection carries on: 3 of 3 requests, and the terminator
    sees the new port.
  - With migration disabled, the connection times out.
  - The stateless frame is what makes this free: the forwarder has no flow to lose.
  - Only the client's port and address inside the box can change. The destination is fixed by the
    synthetic address, and the terminator ties the connection to that host.
- **Idle timeout.** The negotiated timeout is the minimum of both ends. With the terminator at 3 s, a
  client pausing 5 s gets `Timeout` on its next request and has to reconnect. Use 30 s or more (quinn's
  and most clients' default). The forwarder has no timer of its own.
- **GSO in gVisor is broken for QUIC senders.**
  - gVisor accepts `UDP_SEGMENT` but sends the whole buffer as one datagram. A QUIC short-header packet
    runs to the end of the datagram, so the coalesced packets fail to decrypt.
  - In-box quinn uploads (8 MB POST) lose packets with GSO on. At MTU 1452: 8 lost and 2 congestion
    events against 0 with GSO off, taking 1.3–1.7 s against 0.9–1.4 s. At MTU 16000 (forwarder
    `--gro 1`, see below): 3–4 lost against 0, taking 258–347 ms against 218–245 ms.
  - Spike bug found on the way: with the forwarder's GRO at 32 and MTU 16000, runs of four or more
    16000-byte datagrams overflowed the terminator's receive slot (16000 × 3) and were truncated,
    losing 34–49 packets per upload with or without GSO. Phase 2 must cap a batch at the receiver's
    slot size.
  - It still completes (loss recovery). The forwarder can't re-split: the segment size is lost.
  - quinn is affected (measured). ngtcp2 and quiche also use GSO on Linux, so they probably are too;
    that is to check. This is a gVisor bug to report
    upstream. Until it's fixed, a seccomp-style refusal of `UDP_SEGMENT` would be the fix inside the box,
    since clients fall back when the setsockopt fails. Check whether `wicket-entry` can do that under
    runsc.
- **MTU in gVisor.** `lo`'s MTU is 65522 and datagrams up to 65000 bytes pass. quinn's PMTUD on the
  default bound settles at 1326–1452 on short connections: probes are still in flight when they close.
- **HTTP/2 fallback cost.** The first request to an HTTP/2-only upstream waits for the HTTP/3 connect
  timeout (500 ms in the spike). Race HTTP/3 against HTTP/2, or learn from the upstream's Alt-Svc or
  HTTPS record and default to HTTP/2.
- **Request bodies.** The spike buffers up to 16 MiB before forwarding, and answers 413 above that.
  Phase 2 streams bodies, as the HTTP/1 and HTTP/2 path does.

## Implementation plan (phase 2, in `crates/`)

1. **`wicket-fwd`: datagram listeners** (`--udp ADDR:PORT=PATH`, `--udp '*:443=PATH'`), std threads,
   no runtime.
   - **Frame:** one `SOCK_SEQPACKET` message per datagram or batch, with a 16-byte header:
     `version u8 (1) | kind u8 (0 QUIC, 1 DNS) | seg u16 | src port u16 | dst port u16 | src v4 | dst v4`.
     Use the same header in both directions, with no flow table. This replaces the 28-byte flow-id
     design in its docs.
   - **Wildcard socket:** `IP_PKTINFO` in, `ipi_spec_dst` out, and drop anything outside the
     synthetic /16.
   - **Batching:** `recvmsg` then `recvmmsg(MSG_DONTWAIT)`, coalescing same-flow equal-size runs (GRO);
     split `seg` batches with `sendmmsg`. Cap a coalesced batch at what the receiver's slot holds
     (segments × max UDP payload, agreed in the frame's setup or fixed per version); the spike didn't
     and truncated uploads at MTU 16000.
   - **Fallback:** a length-prefixed stream; drop the `SOCK_DGRAM` fallback.
   - **DNS:** a `--udp 198.18.0.1:53` listener over the same frame.
2. **`wicket-entry`:**
   - add `198.19.0.1/16` to `lo` alongside 198.18.0.1 (and to `--restore-hook`);
   - set the box's resolver to 198.18.0.1 (`--dns`);
   - start `wicket-fwd` with the two `--udp` listeners;
   - (if feasible) refuse `UDP_SEGMENT`.
3. **wicket DNS on the host (`wicket-proxy::dns`):**
   - mint synthetic addresses per run, the host → address map shared with the terminator;
   - answer NXDOMAIN for hidden hosts, NODATA for AAAA, and optionally HTTPS `alpn=h3`;
   - audit every query, which closes DNS as an exfiltration path.
4. **QUIC termination (`wicket-proxy::h3`):**
   - Sockets: quinn on a custom `AsyncUdpSocket` over the relay (the spike's `term.rs` `Relay`),
     `max_transmit_segments`/`max_receive_segments` = 32, and `may_fragment` false.
   - Certificates: per-host `ServerConfig` from the same minter as egress (`RunCa::server_config` with
     ALPN `h3`; `NodeCa` and routing on nodes), selected by the destination address.
   - Request checks: `:authority` must match (421 otherwise), 0-RTT off, migration on, idle 30 s.
   - MTU: PMTUD upper bound 16000 on the box leg until the new-connection latency at higher bounds is
     understood. Look at quinn's PMTUD probe timing and pacing with a large MTU first.
   - Decisions go through the same `Decider` and `Relay` path as `Egress`: reach, forbid, risk, grants,
     injection, audit. Bodies are streamed.
5. **Upstream:**
   - re-originate over HTTP/3 (pooled quinn connection per host, ordinary 1452 MTU);
   - fall back to the existing HTTP/2 client, racing it, remembered per host;
   - the routing rule on nodes applies as for TCP.
6. **Tests and smoke:**
   - unit tests for the frame, DNS answers and the synthetic map;
   - an integration test (quinn client ↔ relay ↔ terminator over a socketpair);
   - a `ci/smoke.sh` scenario with the done-when of #92, using `get` as the in-box client (allowed
     200 + audit line, 403 over HTTP/3, hidden NXDOMAIN).
7. **Before 0.0.1, check real clients**: curl with HTTP/3 and Chromium-based tools, for whether
   they advertise a large `max_udp_payload_size` and use GSO in gVisor.
