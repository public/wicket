# Experiment: where wicket's CPU goes, and what cursed-http and cursed-jwt could take off it

**Question.** wicket could link our own HTTP and crypto code
([cursed-http](https://github.com/public/cursed-http), [cursed-jwt](https://github.com/public/cursed-jwt)) as
optional, off-by-default backends. Which of wicket's paths would that make cheaper, and by how much?

**Answer: none of the hot paths, measurably. One cold path, Ed25519 verification, by 2.6–3.2×.**
- **Where the request path spends its CPU.** In wicket's real egress proxy, with the host inspected, the
  kernel takes 32–43%, tokio and allocation take most of the rest, and the TLS record layer takes 24–69%.
  AES-GCM is 30% of a download's CPU, and X25519 is 11% of a new connection's. Neither library implements
  AES-GCM or X25519.
- **HTTP/1.1 parsing.** httparse, the code cursed-http's `fbparse.h` would replace, takes **0.2%** of
  the CPU of a kept-alive inspected request. `fbparse.h` parses the same requests about 2× faster with
  AVX2, and at parity on the x86-64 baseline. So the most it could save is about 0.1% of the request
  path, well under this machine's ±20% noise. hyper also has no seam for its parser.
- **Signatures.** No Ed25519 verification happens per request. A node verifies Biscuit tokens once,
  when a feed delta loads them, and decides each request with the compiled token: 3.5% of a kept-alive
  request's CPU on a node, all of it Datalog. Signatures are verified only on cold paths:
  - feed statements as a node applies them, all under the feed key;
  - tokens as they load, where block 0 is under the authority root and the other blocks are under
    one-time keys;
  - identities, envelopes and checkpoints in `wicket audit verify` and at message delivery, all under
    the issuer key.

  For a key that verifies many signatures, cursed-jwt's Ed25519 takes 24–28 µs per signature, against
  65–69 µs for `ed25519-dalek`'s `verify` and 78 µs for its `verify_strict`. Building its per-key tables
  costs 3.2–3.6 ms, so it pays from about 60–80 signatures on one key.

Ranked by the share of CPU each could remove (§4), only the Ed25519 backend is worth building, and only
for keys that verify many signatures. The design is in §5; what isn't integrated, and why, is in §6.

## 1. Method

**Machine.** One shared VPS, used for every number here: 4 vCPUs (Intel Broadwell, AVX2, no SHA-NI, no
AVX-512), 8 GB of RAM, Ubuntu 24.04, kernel 6.8, Rust 1.99.1. Other sessions' builds ran at the same
time (load 3–9). Read the CPU-seconds per unit as ±20% and the shares within a profile as steadier.

**The proxy under load** (`profile.sh`). It runs `netbench egress` from `experiments/network-overhead`.
That is `wicket_proxy::egress::Egress`, started the way `wicket run` starts it: a file ledger with the
batched audit writer, the run's CA and the central decider (`--node`: a node's decider over a feed
replica). The upstream is the harness's local HTTPS origin (HTTP/2 and HTTP/1.1). The client is the
harness's probe on the proxy's unix socket. Three arms:

| arm | what |
|---|---|
| inspect | the zone allows the origin, with a forbid rule on an unused path, so every request is intercepted, decided and audited |
| splice | the zone allows the origin wholesale: decided at `CONNECT`, then relayed with splice(2) |
| node | inspect, decided by a node's decider: the box's Biscuit token, loaded from a feed replica |

Three workloads per arm:
- `keep`: 20,000 kept-alive 1 KB GETs on one connection;
- `new`: 1,000 GETs, each on a new connection with its own `CONNECT` and TLS handshake;
- `download`: 5 × 100 MB.

Each workload runs twice. The first pass is unprofiled, and gives CPU-seconds per unit from
`/proc/PID/stat`. The second runs under `perf record -F 999 --call-graph dwarf` and gives the shares.
`fold.py` folds every stack and counts a sample toward a component if any frame matches it, so the
inclusive shares overlap (`hyper h1` contains the httparse frames under it). Raw: `logs/profile/`
(`*.cpu.json`, `*.shares.json`, `*.top.txt` self-time tops, `*.client.json` latencies).

**Kernels in-process** (`micro/`). This times httparse 1.10 against `fbparse.h` (cursed-http
`5e10ca8`), built twice: the x86-64 baseline (SSE2) and `-mavx2`. It uses seven request heads of the
shapes boxes send:
- cargo index and crate fetches;
- curl;
- npm;
- git upload-pack;
- a Chrome navigation;
- a model call.

It also times `ed25519-dalek` 2.2 against cursed-jwt's Rust port (`b453535`, `pk` without `asm`: no C)
on 200 B and 1,200 B messages, and `sha2` on audit-row-sized inputs. Each figure is the median of 3
runs, each run the median of 9–15 rounds. Raw: `logs/micro.jsonl`.

**Not run:** the gVisor workloads (`cargo fetch` in a box) and HTTP/3. In both, the proxy runs the
same code as the `inspect` arm. The extra cost is in the box's network stack, which this experiment
can't change: gVisor spends about 110 µs per UDP datagram (`experiments/http3/RESULTS.md`).

## 2. CPU per unit (unprofiled pass)

| arm | kept-alive request | new connection + request | download |
|---|---|---|---|
| inspect | 320 µs | 1,450 µs | 3.34 CPU-s/GB |
| splice | 79 µs | 910 µs | 0.38 CPU-s/GB |
| node | 352 µs | 1,160 µs | 3.06 CPU-s/GB |

These are about twice `docs/explanation/performance.md`'s figures (162 µs per kept-alive request and
2.67 CPU-s/GB inspected). That page measured under lower load (load 2–9 there, 3–9 here, and much of
it from parallel builds). Only the shares below are used for the ranking.

## 3. Where it goes (inclusive % of the proxy's samples)

| component | insp keep | insp new | insp dl | splice keep | splice new | node keep | node new | node dl |
|---|---|---|---|---|---|---|---|---|
| **httparse** (h1 parse) | **0.2** | **0.1** | 0.0 | 0.0 | 0.6 | 0.1 | 0.3 | 0.0 |
| hyper h1 (all of it, incl. what it calls) | 37.1 | 22.3 | 39.3 | 0.0 | 16.8 | 39.6 | 23.4 | 40.8 |
| h2 crate (upstream HTTP/2) | 24.3 | 8.7 | 56.5 | 0.0 | 0.0 | 24.4 | 9.0 | 55.6 |
| rustls (records, handshake) | 24.1 | 42.8 | 69.1 | 0.0 | 0.0 | 23.8 | 44.5 | 70.6 |
| **AES-GCM / GHASH** (ring asm) | 1.5 | 1.0 | **30.2** | 0.0 | 0.0 | 1.4 | 1.3 | **33.6** |
| ring, other (P-256 signing, SHA-384) | 2.5 | 23.2 | 36.7 | 0.0 | 0.0 | 2.3 | 24.5 | 41.1 |
| **X25519** (ring's curve25519) | 0.0 | **11.0** | 0.1 | 0.0 | 0.0 | 0.0 | **11.7** | 0.0 |
| sqlite (audit ledger) | 11.3 | 11.0 | 0.1 | 0.0 | 13.9 | 9.9 | 9.5 | 0.0 |
| sha2 (audit chain) | 1.0 | 0.6 | 0.0 | 0.0 | 0.0 | 0.6 | 0.2 | 0.0 |
| **Biscuit decide** (compiled token) | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | **3.5** | 1.1 | 0.0 |
| **Ed25519 verification** | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| wicket_core (decide, zone) | 2.4 | 1.4 | 0.0 | 0.0 | 0.6 | 2.1 | 1.9 | 0.0 |
| allocator | 6.3 | 5.8 | 9.3 | 0.9 | 3.2 | 7.3 | 6.8 | 8.5 |
| user memcpy | 2.0 | 2.3 | 27.5 | 0.0 | 1.0 | 2.6 | 2.0 | 25.9 |
| kernel (self) | 35.8 | 31.5 | 42.8 | 70.7 | 60.0 | 34.7 | 32.2 | 38.0 |
| samples | 6,654 | 1,113 | 1,555 | 1,478 | 898 | 7,360 | 1,030 | 1,364 |

The splice download profile has 163 samples, so it's left out. It is almost all splice(2) in the kernel.

**Self time** (`*.top.txt`):
- **kept-alive inspected:** the kernel's wakeups and scheduling (`_raw_spin_unlock_irqrestore` 8.8%,
  `finish_task_switch` 6.0%), then memmove, malloc and free. No single wicket, hyper or rustls function
  takes over 1%.
- **new connection:** `x25519_scalar_mult` is 6.6% self, SHA-512 blocks are 3.6% (TLS 1.3's SHA-384
  key schedule), and the rest of X25519 is key generation. P-256 signing (`ecp_nistz256_*`, the leaf's
  CertificateVerify) is about 3%.
- **download:** `aes_hw_ctr32_encrypt_blocks` and GHASH (open and seal), memmove, then kernel copies.

## 4. Ranking: the share each backend could remove

The ceiling for a kernel is its inclusive share × (1 − 1/speedup), with the speedup from §4.1.

| candidate | where | share | speedup here | ceiling | verdict |
|---|---|---|---|---|---|
| cursed-http `fbparse.h` for the box's HTTP/1.1 request heads | inspected and node, per request | 0.1–0.3% | 1.4–2.1× (AVX2); 0.9–1.2× (SSE2) | **≤ 0.15%** | not worth it: under the noise, and hyper has no parser seam (§6) |
| cursed-jwt Ed25519 for feed, identity, envelope and checkpoint signatures | cold paths | 0% of the request path | 2.6–3.2× once a key's tables exist | **0% per request; 55–65% of the signature time on the cold paths** | **build**, for long-lived keys only (§5) |
| cursed-jwt HS256, ES256, RS256 | — | wicket uses none of them | — | 0 | nothing to integrate |
| cursed-http HTTP/2 (`h2.h`) for the upstream side | inspected, per request | h2 crate 24% keep, 56% download | — | — | not applicable: `h2.h` is a server engine, and the upstream side is a client (§6) |
| AES-GCM, X25519, P-256 signing, SHA-384 | TLS | 30% of download, ~15% of new | — | — | neither library has them, apart from ES256 signing, which uses the same nistz256 code ring does |

### 4.1 Kernels

**HTTP/1.1 request heads**, ns per parse (median of 3 runs):

| request | bytes | httparse | fbparse.h SSE2 | fbparse.h AVX2 |
|---|---|---|---|---|
| cargo index | 171 | 292 | 243 | 194 |
| cargo crate | 157 | 260 | 238 | 149 |
| curl | 76 | 201 | 181 | 115 |
| npm | 412 | 425 | 468 | 230 |
| git upload-pack | 279 | 331 | 347 | 175 |
| Chrome | 775 | 686 | 680 | 324 |
| model call | 274 | 338 | 385 | 189 |

At most 0.36 µs of a 320 µs request: about 0.1%.

**Ed25519 verification**, µs per signature, one key:

| message | dalek `verify` | dalek `verify_strict` | cursed-jwt, one at a time | cursed-jwt, 16 at a time | cursed-jwt key setup |
|---|---|---|---|---|---|
| 200 B | 65.2 | 78.4 | 24.2 | 19.2 | 3,406 |
| 1,200 B | 69.3 | 78.2 | 28.2 | 24.6 | 3,224 |

- Break-even against `verify_strict` is about 3.3 ms / 54 µs ≈ 60 signatures on one key, and about 80
  against `verify`.
- SHA-256 (the audit chain's hash) takes 2.2 µs for 300 B and 6.8 µs for 1,000 B with `sha2` on this
  CPU. That is 1% of a request, and cursed-jwt has no public single-message SHA-256.

## 5. Design: the seams

**Rules for every backend.**
- A Cargo feature, off by default. The default build is unchanged and needs no C toolchain beyond today's.
- The pinned code is a vendored copy with its licence (`third_party/`, like the Biscuit fork), not a git
  dependency. Cargo resolves optional dependencies even when their feature is off, so a git
  dependency would put github.com on the default build's path.
- A thin wrapper owns every call. Nothing of the backend's types escapes it, and it is fuzzed.
- Each backend has a differential test: the same inputs through both, identical results, malformed and
  adversarial inputs included.
- CI builds and tests each feature on its own job, and the default build as today.
- Runtime CPU dispatch stays inside the library. wicket never assumes AVX2 or AVX-512.

### 5.1 `cursed-jwt` feature: Ed25519 verification for long-lived keys (to build)

**Seam.** A new crate, `wicket-sig`, holds a `PinnedKey`: a verifying key used for many signatures.
`PinnedKey::verify` and `PinnedKey::verify_strict` take the same arguments as `ed25519-dalek`'s and
give the same yes/no:
- Without the feature, they are `ed25519-dalek`'s.
- With `cursed-jwt`, a key builds cursed-jwt's comb tables after 64 verifications, once, and then
  verifies with them.
  - Strict mode adds dalek's two checks around cursed-jwt's cofactorless check: no small-order R, and
    no small-order key. Both libraries compare `encode(R') == R` byte for byte and require S < L.
  - A key that dalek accepts and cursed-jwt doesn't decode (a non-canonical encoding) stays on dalek.

**Call sites:**
- `wicket-feed`'s JWS open (the feed key, `verify_strict`);
- `wicket-identity`'s identity, envelope and checkpoint verification (the issuer key);
- the authority-key certificate (the root).

Biscuit's own block signatures are not touched. They sit inside the vendored biscuit-auth, and most
are under one-time keys.

**What it pulls in.** The vendored code is cursed-jwt's Rust port (`rust/cursed-jwt` at `b453535`),
built with `default-features = false, features = ["std", "pk"]`:
- pure Rust, no C, no assembly;
- MIT;
- `fiat-crypto` (MIT / Apache-2.0 / BSD-1), `sha2` (already in the tree) and `memchr`.

None of the code under cursed-jwt's `licenses/` (OpenSSL, intel-ipsec-mb, Firedancer) is in that
port's `pk` build: it is all C or assembly, used by the C library and the port's optional `asm` feature.

**Checks:**
- a differential test, dalek against the backend, over valid and tampered signatures, small-order R
  and keys, non-canonical S and R, wrong lengths and random bytes, in both modes;
- a fuzz target on `PinnedKey` (`cargo fuzz`);
- a CI job `cursed-jwt`: `cargo test -p wicket-sig --features cursed-jwt` plus the feed and identity
  tests with the feature.

### 5.2 `cursed-http` feature: not built (design only)

**The only seam that matters is the box-facing HTTP/1.1 server.** That is hyper's `http1::Builder`
in `egress/mod.rs` and `egress/connect.rs`. hyper parses with httparse internally and has no
pluggable parser. Cargo can't put `[patch]` behind a feature. So the feature would have to replace
hyper's HTTP/1.1 server connection on the box side with wicket's own:
- `chp_fb_parse_request` (cursed-http's `chp.h`, which dispatches at load time) for the head;
- wicket's own body framing, keep-alive and upgrades (`CONNECT`).

Its differential test against hyper would have to cover every smuggling-relevant difference. That is
needed because `fbparse.h` gives picohttpparser's results, not httparse's: bare-LF line ends, a skipped
leading empty line, obs-fold, any `HTTP/1.<digit>`. The ceiling is 0.15% of a request, so the
smuggling surface isn't worth it.

## 6. Not integrated, and why

- **HTTP/1.1 parsing** (`fbparse.h`, `fastparse.h`, `batchparse.h`): 0.2% of the request path (§5.2).
  - `fastparse.h` routes a known API, and the proxy forwards arbitrary paths.
  - `batchparse.h` needs a loop that holds many connections' heads at once. hyper's per-connection
    tasks don't.
- **HTTP/2** (`h2.h`, `hpack.h`). On the box side wicket speaks only HTTP/1.1, and on the upstream side
  it is an HTTP/2 client. `h2.h` is a server engine. To use it, the box side would have to accept
  HTTP/2 through a sans-IO engine driven by wicket's own loop: hyper's server would be replaced
  wholesale for that protocol. The h2 crate is 24% of a kept-alive request and 56% of a download
  inclusive, but most of that is the TLS writes and reads under it. Its self time is 5% and 1%. A
  realistic gain is a few percent of the request path, for the largest change in this list.
- **HTTP/3 and QUIC** (`h3.h`, `qpack.h`, `quic.h`). These would replace quinn and h3 wholesale.
  - `quic.h` depends on picotls and OpenSSL's libcrypto: a C toolchain plus OpenSSL in the build.
  - It has no 0-RTT, Retry or migration, and isn't tested against browsers.
  - wicket's HTTP/3 cost in a gVisor box is the box's UDP stack (about 110 µs per datagram), not the
    host side.
  - What it would take: an engine adapter for `h3.rs` (datagrams in and out over the box's SEQPACKET
    socket), the QUIC TLS handshake through picotls with the run CA's leaf, and a differential test
    against quinn's behaviour on the same packet traces. It would win nothing measurable until the
    box side stops dominating.
- **cursed-iouring.** Splice-through costs 0.38 CPU-s/GB and 79 µs per kept-alive request. Most of
  that is the kernel's wakeups (71% kernel self time in the splice arm). The io_uring study's fixed
  configuration fits the splice pump: SINGLE_ISSUER and DEFER_TASKRUN, multishot recv with provided
  buffers, a splice SQE chain per direction. It could cut those wakeups. It is not HTTP or crypto
  code, so it is out of this experiment's scope. It is the next thing to measure for the splice path.
- **HS256, ES256 and RS256 verification, and the JWT front end**: wicket verifies no JWTs of those kinds.
- **SHA-256 for the audit chain**: 1% of a request, and cursed-jwt exposes no single-message SHA-256.

## 7. For the library owners

- **cursed-http.** `chp.h` already gives a load-time-dispatched ABI, which is what wicket would need.
  The README's "identical to picohttpparser" is the right contract for C users. A Rust wrapper would
  also want a strict mode that rejects bare LF and obs-fold, to match httparse and hyper's request
  smuggling posture.
- **cursed-jwt (Rust port):**
  - `verify_signatures` is documented as "for tests and benchmarks". wicket would depend on it as the
    raw Ed25519 API. Please make it a supported entry point.
  - Add an optional strict mode (no small-order R or A), matching `ed25519-dalek`'s `verify_strict`.
    wicket's wrapper adds those two checks itself for now.
  - Key setup is 3.2–3.6 ms on Broadwell (284 KB tables per base point). A smaller window for keys
    used tens of times would move the break-even down.

## 8. Reproducing

```sh
# The harnesses (release). micro needs a cursed-http checkout at 5e10ca8 for fbparse.h.
(cd ../network-overhead && cargo build --release)
(cd micro && CURSED_HTTP_DIR=/path/to/cursed-http cargo build --release)
# The proxy profile: three arms, three workloads; about 10 minutes, needs perf and sudo.
./profile.sh ../network-overhead/target/release/netbench logs/profile inspect splice node
# The kernels, three runs.
for i in 1 2 3; do micro/target/release/cursed-micro; done > logs/micro.jsonl
```
