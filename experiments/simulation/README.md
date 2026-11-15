# Simulation: madsim or turmoil (#324)

**Question.** Which deterministic simulator should run wicket's control host, nodes and boxes in one
process, on a simulated network and clock, with faults from a seed?

**Verdict: turmoil (0.7).** The simulation is `crates/wicket-sim`. It isn't a standalone project
like the other experiments, because CI runs its seeds.

## What wicket's code needs

- **tokio everywhere.** The proxies are hyper on tokio (`wicket-proxy`), and the CLI is tokio
  with reqwest and quinn.
- **unix sockets** for the box's proxies (`ctl/*.sock`, `wicket_proxy::sockpath::listen`) and
  for this host's own node (`wicket node serve`'s socket).
- **The node channel** (`wicket-cli/src/chan.rs`): a length-prefixed byte stream over ssh's
  stdio or that unix socket. Its framing (`read_frame`) is generic over `AsyncRead`, but
  `nodesrv.rs` and `noderun.rs` name `tokio::net::UnixStream` directly.
- **The clock and randomness.** wicket-feed is already sans-IO: every function takes `now`
  (Unix ms) from its caller, and the feed's tests inject it. The model proxy's budget accounting
  (`Llm`) reads no clock. Randomness is key generation (ed25519, Biscuit's per-block keys) and
  ids (ulid), and none of it changes a decision.

## The two candidates

| | madsim 0.2.34 | turmoil 0.7.2 |
|---|---|---|
| how code opts in | Build the whole dependency graph with `RUSTFLAGS=--cfg madsim`. `madsim-tokio` replaces tokio in every crate that uses it. reqwest, quinn and hyper need madsim's patched forks, or get cut out. | A library. Code under test uses `turmoil::net::{TcpStream, TcpListener}` where it would use tokio's. Everything else is ordinary tokio, on turmoil's per-host runtimes with simulated time. |
| unix sockets | `madsim::net::unix::UnixStream` exists, but every method is `todo!()` (checked in the 0.2.34 source). | None. |
| TCP | yes | yes |
| faults | Kill and restart nodes, partitions (`NetSim`), latency, packet loss. | `crash`, `bounce` (restart), `partition`/`repair` (one-way too), `hold`/`release` (delay a link, then deliver), per-link latency and fail rate. |
| determinism | Strong. It intercepts `getrandom` and `clock_gettime` process-wide, so even OS randomness replays. | Scheduling, latency and loss come from a seed (`Builder::rng_seed`), and `tokio::time` and the epoch are simulated. OS randomness (`getrandom`) and `SystemTime::now` stay real, so code must take its clock and rng from a seam. |
| cost on a 4 GiB box | A second full build of every dependency under the cfg, in its own target dir. | One more crate, plus turmoil's `rand 0.9`, `indexmap` and `scoped-tls`. |
| crash semantics | Node restart. | `crash` drops the host's runtime (every task). `bounce` restarts it from its constructor, so state comes back only from what the host persisted. |

## Why turmoil

1. **Neither one simulates unix sockets**, so with either, wicket's sockets need a seam. With
   turmoil, the seam is a stream type at the few places that open a connection. With madsim, it
   is a workspace-wide cfg plus forks of hyper, reqwest and quinn. Production builds would carry
   that risk, and CI would need a second full build.
2. **The parts with the protocol bugs are already sans-IO.** The feed (`Publisher`,
   `Replica<BoxAuthority>`) and the budget accounting (`Llm`'s reserve and settle) take time as an
   argument, so madsim's process-wide clock interception buys little there. The simulation needs
   a network, crashes and a clock to feed them, and turmoil gives exactly that.
3. **Determinism where it matters.** OS randomness only picks key bytes and ids, and decisions
   don't depend on them. The simulation keeps its own state in ordered maps and takes every
   choice from its seed. It also checks its own determinism: one seed, run twice, must give the
   same trace hash (`crates/wicket-sim/tests/scenario.rs`).
4. **A crash drops the runtime**, which matches a `wicket node serve` crash. What comes back is
   what the node persisted (its replica directory, its slices, its spend file), and the simulation
   has to say exactly what that is.

The cost: code that opens sockets itself (`nodesrv.rs`, `noderun.rs`) can't be simulated as it
is. In this first slice, the simulated node and control host are thin drivers around the real
library code, written to follow those files and naming the functions they follow. The next step is
to move the channel (`chan.rs`) and the node's run loop out of the binary and behind a stream
trait. The crate docs and the PR's list of remaining work cover this.
