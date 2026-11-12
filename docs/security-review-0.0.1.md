# Security review before 0.0.1 (#44)

*Review of `main` at d680cd1 (after #108), 2026-11-12. Read-only on the code. This review found the problems below; other
changes fix them, tracked in the issues linked here.*

## Scope and method

This was an adversarial review of the merged 0.0.1 stack. Five attackers were considered:
- a hostile agent in a box, with full code execution as the agent user;
- a compromised node;
- a hostile peer agent, linked or not;
- an operator without root on the control host;
- an outside attacker who can reach the console.

For each, the review asked whether they could:
- escape the box or reach the network directly;
- obtain a credential;
- exceed their zone or budget;
- forge identity or audit records;
- make a human approve the wrong thing.

Six areas were reviewed in parallel, and the higher findings were then re-traced by hand:
- the box and its plumbing;
- egress and the model proxy;
- authority (subset, spawn, gateway, Biscuit);
- identity, nodes and the feed;
- lifecycle (placement, hibernate, audit);
- the console.

Two findings were confirmed by running scratch programs against `wicket-core` (the glob subset bypass and zero resource limits).
The rest come from reading the code. A **suspected** finding depends on behaviour outside wicket (an upstream server, Docker, a
browser) that wasn't exercised. The daemon and system user (#12) are not merged and are out of scope.

Severity:
- **critical:** box escape, a credential, or arbitrary network access or authority from a realistic position, without preconditions;
- **high:** the same with modest preconditions, or a major control (audit, budget, approval) defeated;
- **medium:** a real bypass with meaningful preconditions or limited impact;
- **low:** defence in depth.

## Summary

| Severity | Count | Where |
|---|---|---|
| critical | 2 | withheld until fixed |
| high | 9 | #111–#119 |
| medium | 11 | #120–#130 |
| low | 30 | this document |

The themes:
- **Approval surfaces trust agent-shaped input.** The agent can file requests in wicket's own namespace, prefix grants are wider
  than the card says, and the cards hide what matters.
- **String matching stands in for parsing.** This affects hosts, paths, risk patterns, globs and prefixes.
- **The model proxy enforces less than the egress proxy.**
- **Nothing re-checks the parent at decision time.** The subset check at spawn time is the only bound on a child, so any bug in it
  widens authority. Design §4.1 says such a bug costs only usability.

## Critical (withheld)

Two critical findings are withheld until they are fixed; the maintainers have the details.

## High

- **#111. The subset check accepts child path globs wider than the parent's.**
  - A parent `*` segment is taken to cover any child segment. But globset classes and ranges (`[!~]`, `[.-0]`) match `/`.
  - Example: with a parent rule of `/x/*`, a child of `/x/*[!~]*[!~]*` passes, and the child is then allowed `/x/admin/users/delete`.
  - No ancestor zone is evaluated at decision time (`central()`; node tokens are minted per run with `Issuer::root`), so nothing
    else catches it.
  - Confirmed by a scratch run.
- **#112. Model proxy: server-side tool stripping is a three-prefix denylist on `tools[]`.**
  - Top-level fields like `mcp_servers` pass, as do future tool types.
  - A body that doesn't parse is forwarded unchanged.
  - Wrapped Claude Code sessions skip the model proxy, so they get neither stripping nor budgets.
- **#113. The output-token budget is undercounted.**
  - Usage is charged only from a bounded copy of the stream once it ends. Closing the socket before `message_delta`, or exceeding
    8 MiB, charges about 1 token.
  - Parallel requests overshoot the cap.
- **#114. The risk classifier works on substrings.**
  - Workflow edits through the git data API (blobs, trees, commits, refs), `POST /graphql` and `update-branch` are rated R2, while
    the same edit through the contents API is R4.
  - Percent-escaped letters avoid the patterns. That part is suspected: it depends on GitHub decoding them.
- **#115. Forbid globs match the raw, case-sensitive path.** Case variants, unreserved percent-escapes, `;` parameters and `..;`
  get past a forbid that is narrower than reach.
- **#116. No check of the resolved address at dial time.**
  - A reached or approved name that resolves to metadata, loopback or private addresses is dialled.
  - `never_reachable` is a string check: numeric and hex IPv4 and bracketed IPv6 escape it.
  - `is_public_ip` misses NAT64, 6to4, multicast and reserved ranges.
- **#117. `request_access` can file `SPAWN`, `LINK` and `CAPACITY` requests on `wicket.internal`.**
  - The agent can get a prefix grant that covers every later beyond-parent spawn.
  - It can pre-word the card wicket would have raised itself.
  - Through `wicket deny`, it can end a lease its request doesn't own.
- **#118. Beyond-parent spawn cards don't show the child's model upstream, secret name or injected credentials.** The card is rated R2,
  so a one-hour approval is offered, and once approved the child sends the secret to the upstream it named.
- **#119. Prefix grants are raw string prefixes with no risk bound.**
  - A grant for `/repos/acme/app` also covers `/repos/acme/app-secrets/…`.
  - An R2-labelled prefix grant also covers R4 operations under the same prefix.

## Medium

- **#120. Audit records: the chain doesn't cover all fields, and nodes choose their own attribution.**
  - `chain_hash` covers only `prev`, `kind` and `body`. A record's `seq`, `ts`, `tenant` and `run` can be changed without breaking
    verification.
  - Nodes pick the tenant and run of the records they ship, and can restart their chain at will.
- **#121. A compromised node writes its own approval requests.** The control host stores its Op, risk label and reason as sent, and
  `wicket approve` approves by id without showing the request.
- **#122. Pre-auth login challenges share one 1024-entry store with sessions' action challenges.** About 128 addresses can keep it
  full and block every signed console action.
- **#123. X-Forwarded-For handling:**
  - Only the first XFF line is read.
  - `--behind-tls-terminator` without `--trusted-proxy` makes every client one address.
  - The sign-in limiter refuses everyone once its table is full.
- **#124. Approval cards re-render every 2 s under the cursor, and the passkey prompt doesn't state the action.** A tap can sign a
  different request. Suspected; not browser-tested.
- **#125. Concurrent `spawn` calls race past `max_children` and the budget carve-out.** A child's own `max_children` isn't charged to
  the parent either.
- **#126. Zero memory, CPU and pids limits pass the subset check.** Docker reads 0 as unlimited; that half is suspected.
- **#127. Grants and pending requests bind to the zone name, not the run.** Any other run in the zone (including an agent-named child)
  can use a grant, and spawned zone names can collide.
- **#128. `wicket pending` prints agent text raw.** Terminal escape sequences in it can rewrite what the operator reads before they
  approve.
- **#129. Credentials are injected into absolute-form `http://` requests.** Reach rules, grants and inject rules carry no scheme or
  port.
- **#130. Request headers are forwarded by denylist.** Method-override and URL-rewrite headers pass, and so do `TRACE` and bodies on
  `GET`.

## Low

Box and plumbing:
- **The manifest env blocklist misses some variables.** `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV` and `ENV` get through (`PATH` is blocked),
  and they would apply in `wicket-entry`'s root phase, which still holds `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP`. Only the
  operator's manifest can set them; children copy their parent's env.
- **Nothing refuses uid 0 for the agent.** If wicket or `node serve` runs as root, `WICKET_AS_USER` becomes `0:0`.
- **The link relay has no limit.** It starts one `docker exec` per incoming connection, so a linked box can flood the host's Docker
  daemon.

Egress and the model proxy:
- **The run CA has no name constraints.** Design §9.1 asks for them; the node CA does have them.
- **Some maps grow without bound:** the leaf-certificate cache, per-host QUIC configurations and the strikes map.
- **Strikes are advisory only.**
- **Vault errors leak paths.** They appear in 502 problem details, including host file paths.
- **The model proxy has no model allow-list.**

Authority:
- **Agent text inside the trusted part of a card.** In capacity requests, the agent's unvalidated `region` (and, per the lifecycle
  review, its reason) is spliced into the trusted part of the approval text, with no length cap.
- **A denied prefix request can be refiled at once.** The recent-denial check ignores the `:prefix` digest suffix.
- **Child volumes aren't subset-checked.** They mount a fresh per-zone directory, so they only matter through #127's name collisions.

Identity, nodes and the feed:
- **A compromised node can exhaust control-host memory.** Frames can be 16 MiB and go into an unbounded channel. Suspected.
- **The per-second revocation check fails open.** `untrusted()` keeps a node trusted when the ledger read fails or its certificate row
  is missing.
- **Feed key certificates name no node.** One leaked per-node feed key could serve any node's feed. Separately, a peer on a node's
  control socket can push another feed's certificate and leave that node in narrow mode.
- **Identity JWS verification isn't strict.** It uses non-strict Ed25519; the feed uses strict.
- **Revoked node-CA serials go nowhere.** They are recorded but never distributed, though `enrol.rs` says they feed a revocation list.
- **SPIFFE ID components aren't validated.** A `/` in a zone or agent name makes the ID ambiguous. Only operators can set them.

Lifecycle and money:
- **The worst-case cost understates long lifetimes.** It caps the whole lifetime at 672 hours, not 672 per month, and
  `wicket place create --lifetime` has no upper bound. Operator-only: agent requests are capped at 24 h.
- **The reconciler destroys nodes made with `wicket place create`.** They carry the owner tag but no lease.
- **Money control depends on `wicket reconcile --every` running.** Without it, a lease's node keeps billing past its end.
- **The ledger and data directory are created under the umask** (typically 0644 and 0755), not 0600 and 0700.

Console:
- **Anyone can lock out a passkey.** The credential lockout is counted before the challenge is checked, so anyone who knows a
  credential id can lock that passkey out for up to 24 h. The id appears in audit records and exports.
- **Enrolment links:**
  - A plain GET uses one up, so link-preview bots can consume it.
  - The first-start link is printed to stdout, which ends up in the journal.
- **Adding a passkey isn't announced** on the other devices, as design §14.1.3 says it should be.
- **The R3/R4 "no unlimited" rule is enforced only in the browser.** `build_action` ignores risk.
- **The idle timeout never fires.** The 2 s poll counts as activity, so an open tab stays signed in for the full 8 h.
- **Failed sign-ins can flood the audit log.** Their records push real events out of the dashboard's Activity tail.
- **Cloned authenticators can race the counter.** The signature counter is checked and updated in separate steps, so two concurrent
  assertions can both pass.
- **Connection caps can be filled:** 256 in total and 16 per address, so 16 addresses can hold every slot.
- **Card text isn't fully cleaned:**
  - `strip()` misses U+00AD, U+061C, U+2060–2064, U+FEFF, C1 controls and tag characters.
  - `request_access` doesn't validate the method or host.
  - The agent's reason isn't behind the "untrusted" fold that design §14.1.3 requires.

## Checked and found sound

Box:
- **Docker flags:** `--network none`, `--cap-drop ALL` with only the four entry capabilities, `no-new-privileges`, a read-only rootfs,
  no devices and no Docker socket.
- **`wicket-entry`'s privilege drop:** `setpriv` clears the groups and the inheritable, ambient and bounding sets before anything
  agent-controlled runs, and the forwarder runs unprivileged.
- **Host-side files:** run and volume directories are 0700, and remote nodes use umask 077. The hosts file lives outside anything
  the box can write.
- **Links:**
  - Link sockets live only in the connecting box's directory.
  - Link addresses and ports are numeric and checked against the pool.
  - A link needs the target's consent and reach containment.
- **The node tunnel** accepts only the `egress`, `llm` and `gateway` targets.
- **Isolation:** a child zone can't pick weaker isolation than its parent.

Egress:
- **Keep-alive and pipelining:** every request on a reused or pipelined tunnel goes through `handle`.
- **Request smuggling:** framing headers are stripped and bodies fully collected.
- **No HTTP/2 multiplexing:** ALPN offers http/1.1 only.
- **Upgrades:** `Upgrade` is stripped.
- **Host pinning:** the `Host` header is pinned, and the URL is built from the CONNECT host.
- **Redirects** are not followed.
- **Upstream TLS is verified:** rustls with no `danger_*`; HTTP/3 uses webpki roots, with SNI set to the host.
- **Credential swaps** are host-bound, exact-match and `Authorization`-only, and injected values are scrubbed from response headers.
- **wicket DNS** never makes a real lookup.
- **HTTP/3:** the SNI and `:authority` must match the synthetic address's host, and 0-RTT is off.
- **The activation fence** is checked on CONNECT, on every request, and on DNS, QUIC and the model proxy.
- **Grant use** is recorded durably before the request goes ahead.

Authority:
- **The Biscuit structural check:**
  - A block appended by a node can't widen authority.
  - Grants are bound by key trust.
  - Values are bound as parameters, never written into the Datalog text.
- **The step budget** fails closed.
- **Feed token checks:** box path, grant re-binding to box and epoch, exact-path grants, narrow mode.
- **Spawn placement** only reaches the caller's own node or a lease the same run holds.
- **Inheritance:** forbids are inherited, and the subset check covers isolation, images, injected credentials, `unlisted_hosts` and
  `accept_from`.
- **What an agent can see:** `await_grant` and `pending_requests` show only the caller's own requests.
- **Manifest validation:** `deny_unknown_fields`, reserved env names, the adapter-settings allowlist, and broken globs are refused.

Identity:
- **The node handshake:**
  - Both nonces, the role, the name, the certificate digest and the channel binding are signed.
  - Proof types are kept separate, so replay and reflection fail.
  - The control host checks the certificate, the ledger serial and the node's status before it proves anything.
  - A node with no certificate refuses the connection, and only an authenticated connection replaces the current one.
- **Join tokens, host keys and node names:** join tokens are single-use and redeemed atomically, host keys are pinned, and node names
  are validated before they reach shell scripts.
- **The node CA's name constraints** and IP exclusion hold.
- **The feed** refuses rollback, forks, replay, freezes and over-long statements, and only the control host holds feed keys.
- **Envelopes** are checked at the ledger's record time and bound to sender and recipient.

Lifecycle:
- **Wake** claims and generation fencing hold.
- **Budgets across hibernate:** spend carries across hibernate and wake, and a spent agent is never woken.
- **Bundle restore:**
  - It refuses path escapes, odd entry types and tampered blobs.
  - Pack and restore don't follow symlinks.
  - `hibernate::write_new` refuses to write through planted links.
- **Object-store keys** are validated.
- **Leases:**
  - Reservations are checked and inserted atomically, and the approver is bound to the lease.
  - Ownership is re-checked before every destroy.
- **SQL** is parameterised throughout.
- **Checkpoints:** signatures and the truncation and re-chaining checks work.
- **Exported formats:** JSON lines and OTLP output can't be broken by attacker strings.

Console:
- **WebAuthn:** exact type, challenge and origin checks; `crossOrigin` refused; rpIdHash checked; user presence and verification
  required; ES256 keys on the curve; the counter must rise.
- **Action binding:** the challenge is a hash of server-built JSON, and `apply()` re-checks the pending state, identity, run state
  and the manifest's hash.
- **Challenges** are single-use, last 120 s and are bound to the session that asked for them.
- **Session cookies** are `__Host-`, Secure, HttpOnly and SameSite=Strict. They are stored hashed, rotated at sign-in, revocable,
  and die with their passkey.
- **Enrolment links** are 192-bit, hashed, single-use and minted on the host only. A bootstrap session can register only one passkey.
- **Pre-auth surface:** the Host check runs first, with one uniform 401.
- **CSRF:** a custom header, plus exact `Origin` and `Sec-Fetch-Site` checks on every POST.
- **XSS:** no `innerHTML`, a strict CSP with SRI, and `frame-ancestors 'none'`.
- **TLS:** 1.2 and 1.3 with ECDHE and AEAD only, no 0-RTT, HSTS. The ACME certificate is served only for `acme-tls/1` with the
  exact SNI, and ACME files are 0600.
- **Plain HTTP** is loopback-only unless a terminator is declared.

## Not covered, or only partly

- **`wicket-fwd`:** only spot-checked, not reviewed in depth. Unchecked: the host-side handling of its frames, and resource limits in
  its UDP relay.
- **The MCP gateway:** tools other than `request_access`, `spawn`, `send_message` and `await_message` were only skimmed.
- **The compiled Biscuit evaluator:** only its scope filtering was checked against the reference, not the whole evaluator.
- **gVisor and Docker:** their own behaviour was taken as documented. Nothing was run in a box.
- **`wicket-placement`'s Vultr adapter:** read only; the API was never called.
