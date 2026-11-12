# Changelog

User-facing changes, grouped by area. Numbers link to the pull requests.

## 0.0.1 (unreleased)

The first release: one control host runs Claude Code agents in gVisor boxes with no network, brokers
everything they reach, and can run boxes on remote nodes it enrols or provisions.

### Boxes and the egress path

- Claude Code in a gVisor box with `--network none`, a read-only root and no capabilities. The model API,
  HTTP egress and MCP go through proxies outside the box, over bind-mounted unix sockets; the box holds
  only placeholders ([#1](https://github.com/public/wicket/pull/1)).
- Zones: reach rules by host, method and path, `forbid` rules, `unlisted_hosts: hide`, credential
  injection into one declared header, and clear refusals that tell the agent whether to ask, wait or give
  up ([#1](https://github.com/public/wicket/pull/1), [#4](https://github.com/public/wicket/pull/4)).
- wicket has its own address in the box, `wicket.internal` (198.18.0.1), so the agent keeps all of
  localhost ([#4](https://github.com/public/wicket/pull/4)).
- `wicket-fwd`, wicket's own static forwarder, replaces socat in the box: new connections about 3× faster
  and downloads up to 10× faster in gVisor ([#97](https://github.com/public/wicket/pull/97)).
- HTTP/3: the box resolves names through wicket's DNS (synthetic addresses for reachable hosts, NXDOMAIN
  for the rest), and wicket terminates QUIC and decides each request exactly as it decides HTTP/1.1. 0-RTT
  is refused ([#104](https://github.com/public/wicket/pull/104), [#108](https://github.com/public/wicket/pull/108)).
- Zone globs are compiled once per run: allowed requests decide in about 0.5 µs instead of 34–63 µs
  ([#80](https://github.com/public/wicket/pull/80)).
- The audit write is off the request path: kept-alive requests went from about 1.3 ms to 0.45 ms through
  the proxy, and throughput from about 1,000 to 7,000 requests/s ([#93](https://github.com/public/wicket/pull/93),
  [#107](https://github.com/public/wicket/pull/107)).

### Model budgets

- Request, output-token and input-token budgets per zone, enforced by the LLM proxy. Cached input tokens
  count toward usage and the new `llm.max_input_tokens` ([#86](https://github.com/public/wicket/pull/86)).

### Approvals and the console

- Out-of-reach requests become pending requests; `wicket approve` / `wicket deny` grant single-use,
  expiring access recorded in a SQLite ledger. `await_grant` lets an agent wait for the answer, and
  `request_access` lets it ask ahead ([#1](https://github.com/public/wicket/pull/1), [#4](https://github.com/public/wicket/pull/4)).
- `wicket serve`, the operator console: passkey sign-in, and every decision signed again with a passkey
  and re-verified offline by `wicket audit --verify` ([#1](https://github.com/public/wicket/pull/1)).
- The console can start runs from allowlisted manifests, send follow-ups, revoke identities and answer
  `request_access` asks, each action passkey-signed ([#87](https://github.com/public/wicket/pull/87)).
- The console is built to face the internet: TLS from files or ACME, passkeys only, enrolment only through
  one-time links from the host (`wicket operator enrol-link`), rate limits and lockouts, strict browser
  headers, bounded HTTP ([#99](https://github.com/public/wicket/pull/99)).

### Identity, spawn and links

- Every box gets an identity from the installation (`spiffe://<trust domain>/…`), short-lived and rotated,
  naming the human it acts for. Agents message each other only through wicket, signed by wicket
  ([#2](https://github.com/public/wicket/pull/2)).
- The trust domain is set once per installation with `wicket identity init --trust-domain`
  ([#81](https://github.com/public/wicket/pull/81)).
- `spawn`: an agent starts an agent or a program in a zone it writes, which must be a subset of its own,
  or a human approves exactly that zone ([#30](https://github.com/public/wicket/pull/30)). Child zones keep
  the parent's `forbid` rules, and one-segment `*` globs are proven ([#79](https://github.com/public/wicket/pull/79)).
- Links: `expose`, `connect` and `link` let boxes reach each other's ports through relays wicket runs;
  every link is audited and can be cut ([#103](https://github.com/public/wicket/pull/103)).
- `wicket-authz`: zone ceilings, spawns and grants as Biscuit tokens, checked by a vendored, patched
  `biscuit-auth` ([#83](https://github.com/public/wicket/pull/83)). Served nodes decide with these tokens
  ([#102](https://github.com/public/wicket/pull/102)); the control host decides from the compiled zone and
  the ledger.

### Remote nodes and capacity

- Node enrolment: one-time join tokens, pinned ssh host keys, a node key and a name-constrained node CA
  that never leave the node ([#85](https://github.com/public/wicket/pull/85)).
- `wicket node serve`: the node runs the box and decides its egress from a signed policy feed, so the box
  keeps working, failing narrow, while the control host is unreachable
  ([#84](https://github.com/public/wicket/pull/84), [#88](https://github.com/public/wicket/pull/88),
  [#95](https://github.com/public/wicket/pull/95)). The feed carries each box's authority as a Biscuit token
  chain ([#102](https://github.com/public/wicket/pull/102)).
- Node identity certificates and a mutually authenticated control channel
  ([#100](https://github.com/public/wicket/pull/100)).
- `wicket place`: provision nodes on Vultr or use static hosts, inside an hourly and total money envelope,
  each create confirmed on the terminal ([#89](https://github.com/public/wicket/pull/89)).
- `wicket reconcile`, capacity leases and `request_capacity`: agents ask for machines, a human approves,
  and the reconciler provisions, places children and destroys nodes at the lease's end
  ([#98](https://github.com/public/wicket/pull/98)).

### Long-lived agents

- Volumes that persist between runs of a zone, follow-ups (`wicket say`), idle sessions, and in-place
  workspaces (`--workspace-dir`) ([#3](https://github.com/public/wicket/pull/3)).
- Hibernate and wake: an idle agent's box is paused, then stopped with its whole writable state bundled;
  a wake rebuilds the box and resumes the Claude Code session. Budgets span the agent's whole life
  ([#90](https://github.com/public/wicket/pull/90), [#106](https://github.com/public/wicket/pull/106)).
- `wicket wrap` runs an agent another program launches, such as a Remote Control session, inside a box
  ([#4](https://github.com/public/wicket/pull/4)).
- Programs: deterministic workloads pinned by source digest, run without a model under the same boundary
  ([#1](https://github.com/public/wicket/pull/1)).

### Operations and audit

- A hash-chained audit log; `wicket audit --verify` re-checks the chain, every identity, signature and
  node chain offline ([#1](https://github.com/public/wicket/pull/1)).
- Audit export to JSON lines and OTLP, with signed chain checkpoints and `wicket audit --verify --against`
  ([#107](https://github.com/public/wicket/pull/107)).
- `wicket doctor` and `wicket reap` find and stop boxes whose `wicket run` died
  ([#82](https://github.com/public/wicket/pull/82)); `wicket reconcile` subsumes the reaper
  ([#98](https://github.com/public/wicket/pull/98)).
- `wicket secret link` can reference a whole file, re-read at each use
  ([#96](https://github.com/public/wicket/pull/96)).
- CI on every pull request: a secrets and machine-details check, fmt, clippy, tests, and gVisor smoke,
  hibernate and HTTP/3 tests ([#78](https://github.com/public/wicket/pull/78), [#94](https://github.com/public/wicket/pull/94)).

### Fixed

- The audit hash chain could fork when two processes appended at once
  ([#103](https://github.com/public/wicket/pull/103)).
- A run whose timeout fired kept re-firing it while its node was unreachable, writing gigabytes of log
  ([#88](https://github.com/public/wicket/pull/88)).
- A console approval of a prefix ask signed an exact path while granting the whole prefix
  ([#87](https://github.com/public/wicket/pull/87)).
- ACME TLS-ALPN-01 certificates never loaded under rustls 0.23.46 ([#99](https://github.com/public/wicket/pull/99)).

### Upgrading from a development checkout

- Rebuild the agent image (`wicket image`) for the new entry script and forwarder
  ([#97](https://github.com/public/wicket/pull/97), [#108](https://github.com/public/wicket/pull/108)).
- Nodes enrolled before [#100](https://github.com/public/wicket/pull/100) and
  [#102](https://github.com/public/wicket/pull/102) need `wicket node renew-ca <name>` once.
