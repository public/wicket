# Proof of concept: test record

## 2026-11-08: the control host (local) and a Vultr node (vhp-1c-2gb, London)

Claude Code 2.1.319 in gVisor (`runsc release-20261102.0`), driven by a scripted mock model
(`wicket dev mock-llm`) so the whole path runs without a credential. Results were the same locally and on the
Vultr node, where the run was driven from the control host over ssh with forwarded sockets.

| Check | Result |
| --- | --- |
| The box runs on gVisor's kernel | `Linux version 4.19.0-gvisor`, "Starting gVisor..." |
| No network inside the box | Only loopback; a direct connection fails with "Network is unreachable" |
| Model credential never in the box | The mock upstream saw the injected token on every call, never the placeholder |
| Subscription mode | With a placeholder `CLAUDE_CODE_OAUTH_TOKEN`, Claude Code sends every model call via `ANTHROPIC_BASE_URL`, and makes no other outbound calls |
| Allowed read | `GET api.github.com/repos/octocat/Hello-World` allowed by reach rule; real data returned |
| Metadata endpoint | `169.254.169.254` blocked outright |
| Outside reach | `GET example.com/` returns 403 problem+json `pending-approval` with a request id; retries deduplicate onto one request |
| Approval | `wicket approve` (1 use, 5 min): the next retry returns 200, the following one 403 again |
| Git push | Caught at `info/refs?service=git-receive-pack` (R4, `gh.git_push`); `wicket deny` gives git a 403 |
| Run end | Requests still pending are withdrawn; the outbox `result.json` is parsed outside the box |
| Audit | `wicket audit --verify`: chain intact |
| Node hygiene | After the runs the node held no run directories, no token-shaped strings, no private keys, and no listeners besides sshd |

The Vultr node lived 215 s and cost about $0.02.

**Console (`wicket serve`):**
- Requests without the cookie get 401; a bad sign-in token gets 403; a POST without the CSRF header gets 403;
  a non-loopback listen is refused.
- Approving through the console's API unblocked a waiting agent: three pending retries, then allowed by the
  grant.
- Screenshot: `docs/console-poc.png`.

**MCP gateway (`await_grant`):**
- Claude Code connects to wicket's MCP server, its only one, through a third forwarded socket (`status:
  connected`), and lists `mcp__wicket__await_grant` and `mcp__wicket__pending_requests`.
- A blocked request's `await_grant` call waited 10 s until the operator approved, returned `granted`, and
  the retry got 200.
- A run can only wait on its own requests.

**Real Claude:** see the section below.

## Passkeys (headless Chrome with a virtual authenticator)

| Check | Result |
| --- | --- |
| Console API without a session | 401 |
| Enrol the first passkey via the one-time link | registered; the enrolment session ends, so the next step is a real sign-in |
| Reuse the enrolment link | 403 (single use) |
| Sign in with the passkey | signed in |
| A signature for "approve once" submitted as "approve unlimited" | rejected: challenge does not match the one issued |
| Deny a push with the passkey, then replay the same signed deny | denied once; replay rejected (single-use challenge) |
| Approve a waiting request by tapping the button | approved; the agent's retry went through on the grant |
| Decide from another browser with no session | 401 |
| `wicket audit --verify` | hash chain intact; 2 passkey-signed decisions verified offline |
| Revoke all passkeys, then verify again | still 2 verified: revocation keeps public keys |

Found and fixed along the way:
- the enrolment session used to survive registration;
- `operator reset` used to delete keys, which made earlier signed decisions unverifiable. It now revokes.

## Real Claude run (2026-11-08)

Claude Code 2.1.319 on the owner's Claude subscription, in gVisor on the control host, with
`examples/hello-github.yaml`. The model credential is the host's existing Claude login, used **by reference**
(`wicket secret link claude-oauth --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken`).
The model proxy reads the current access token at each request, never the refresh token, and never writes
the file. Never an API key.

| What happened | Result |
| --- | --- |
| Allowed GitHub API reads (repo, contents, commits, README) | allowed by reach rule |
| `GET example.com/` | pending → the agent **called `mcp__wicket__await_grant` on its own** → approved (1 use) → retry allowed by the grant |
| `GET raw.githubusercontent.com/...` (outside reach) | pending; the agent used an allowed API route instead and listed the request in its result; withdrawn at run end |
| Outcome | succeeded in 27 s, 5 model calls; `result.json` parsed outside the box |
| Real token anywhere the box could see, in the transcript, or in the ledger | **not found** (0 matches) |

Gap found: the proxy counts `input_tokens` only. With prompt caching most input is
`cache_read_input_tokens`, so input usage is under-reported. Output budgets are unaffected.

## Programs: deterministic workloads without an agent

`examples/program-repo-stats.yaml` runs `programs/repo-stats/stats.sh` in the same gVisor box with the same egress
proxy, but with no model.

| Run | Result |
| --- | --- |
| Unpinned (development) | runs; prints the digest to approve; the allowed GitHub read works; `example.com` is **blocked** without a pending request (`on_pending: fail`); typed output in 2 s |
| Pinned to the approved digest | same result in 1 s; the digest is recorded in `run.start` |
| Pinned, after appending one comment line | refused: the source digest differs from the approved one |

## Subagent attribution (2026-11-08)

The task asked Claude Code (in gVisor, zone `research`, empty reach) to start two subagents in parallel.
"Fetch example page" ran `curl https://example.com/`; "Count files" ran `ls /workspace | wc -l`.

- wicket labelled each subagent's lines in the run output (`↳ [subagent general-purpose: Fetch example page]`)
  from `parent_tool_use_id` in Claude Code's stream-json.
- The blocked request was attributed to the right subagent while both were running (`basis: matched`, by host):
  `wicket pending` showed `for: subagent general-purpose: Fetch example page via Bash: curl -sS … https://example.com/`.
- The subagent found `mcp__wicket__await_grant` through ToolSearch and waited on it by itself.
- The approval's audit record carries `requested_by: ["subagent general-purpose: Fetch example page"]`. The
  passkey-signed console path signs the same field.
- After approval the retry was allowed, and the audit records `grant g-…; used by subagent general-purpose:
  Fetch example page via Bash: curl …`. No mismatch warning, since the same subagent used it.
- The run succeeded in 36 s.

Not yet covered: the console card was changed but not exercised in a browser in this run, and the
"used by a different agent" warning is covered only by inspection, not by a test.

## Agent identity and child agents (2026-11-08)

Manifest: agent `lead`, `max_children: 1`, `in_box_subagents: false`, zone `research` with empty reach.

- `lead` started as `spiffe://wicket.local/t/t0/z/research/a/lead`, called `whoami`, then `spawn_agent`
  ("fetcher"). The child ran as a separate `wicket run` with its own gVisor box, sockets, proxies and identity
  `spiffe://wicket.local/t/t0/z/research/a/fetcher`, with `parent_run` set.
- The child's `curl https://example.com/` became pending. `wicket pending` showed
  `agent: spiffe://wicket.local/t/t0/z/research/a/fetcher [verified], child of lead (run_…)`.
- Approved with the CLI. The decision record carries the verified identity (agent, zone, parent, image,
  manifest digest, identity digest). The child retried and got 200.
- The child sent `{"http_status": 200, "my_identity": …}` to its parent with `send_message`. Its runner then
  sent a signed `run_finished`. The parent received both through `await_message`, each with
  `from.id = …/a/fetcher` and `relation: "your child"`, set and verified by wicket, and wrote them to its
  result.json.
- Parent 97 s, child 83 s; the parent stopped no children, because the child had already finished.
- `wicket identity list` verified both identities. `wicket audit --verify` passed: the chain, plus 4 identities
  and messages verified offline.

Unit tests cover what the live run didn't:
- tampered and foreign-issuer identity documents;
- a spoofed envelope (one agent's identity, another agent's key);
- cross-zone refusal without `accept_from`, and cross-tenant refusal;
- size limits;
- a forged envelope planted in the ledger;
- a genuine envelope replayed to the wrong recipient.

The console's identity display and its approval refusal for unverified identities were not exercised in a
browser (the page script was syntax-checked only).

## Short-lived identities, revocation and the chain to the human (2026-11-08)

Same parent/child manifest, with `WICKET_IDENTITY_TTL=30`: identities valid 30 s, re-issued every 15 s.

- The run started with `acting for claude (cli, unix-user) → lead`. The child's pending request showed
  `agent: …/a/fetcher [verified]  acting for: claude (cli, unix-user) → lead → fetcher`. The child's runner
  built that chain from the parent's verified identity.
- Within 40 s the audit log held 6 `identity.rotated` records across both runs, each with a new key and
  identity digest.
- `wicket identity revoke <lead run>` while the child waited for approval:
  - The lead's runner logged that the identity was revoked, stopped its box and interrupted its child. The
    lead ended as `revoked`.
  - The child's attempt to send `run_finished` was refused (`this agent's identity was revoked (revoked:
    <lead run>)`), and its pending request was withdrawn.
  - `wicket identity list` showed both as NOT VERIFIED: the lead revoked, and the child through its
    ancestor.
- `wicket audit --verify` passed: 96 audit records, and 12 identity documents and messages verified offline.
  These include every rotation, plus messages from the earlier run whose identities predate the
  `principal` claim.

Unit tests add:
- a genuine envelope signed with an expired key and recorded now, which is dropped;
- messages from a sender revoked after sending;
- sending after revocation;
- revocation cascading to children;
- validity windows;
- the delegation chain over three generations.

## wicket working on wicket (2026-11-09)

Workload: `examples/self-hosting/`. The image is the agent image plus Rust 1.99.1. The workspace is a separate
clone of this repository, mounted with `--workspace-dir`. Two volumes (cargo home, target dir). Reach covers
crates.io, git fetch of this repository, and its GitHub API. A GitHub token would be injected if stored; none
was.

Session 1 (idle timeout shortened to 3 minutes):
- Inside gVisor, Claude Code read the GitHub repository (`git ls-remote origin`, anonymous) and fetched ~60
  crates through the egress proxy. It ran `cargo test -p wicket-core`, then added a unit test (reserved
  `PATH` and `USER` in `agent.env`), re-ran the tests and committed on a new branch.
- First turn ≈ 4 minutes, most of it the cold fetch and build.
- A follow-up sent with `wicket say` arrived as the next turn: clippy, 0 warnings. After 3 idle minutes
  the session closed and the run ended as succeeded.
- The volumes then held 58 MB of crates and 349 MB of build output.
- The agent's commit carried Claude Code's default `Co-Authored-By` trailer. That led to
  `agent.adapter_settings`, which the example uses to turn attribution off.

Session 2 (one-shot):
- `cargo test -p wicket-core` took 2.0 s from the warm volumes.
- An empty commit made by the agent had no trailer, and `result.json` reached the outbox.
- The run took 12 s.

The agent's test is in this branch as `test: cover reserved PATH and USER in agent.env`, with the trailer removed.
Not exercised: pushes and pull requests (no token stored, and each would wait for approval), and wicket's own
end-to-end tests (they need Docker in the box; design §21).

## Remote Control inside wicket, and agents at the edge (2026-11-09)

- **Remote Control in a box.** A Claude Code Remote Control bridge on the host, with
  `CLAUDE_CODE_PROCESS_WRAPPER=examples/remote-control/wrap.sh`, put each session process in a gVisor box
  (`wicket wrap`). The owner chatted with it live from the Claude desktop app.
  - Model calls, the worker registration, and the session's event stream and deliveries all went through the
    egress proxy.
  - The box held only a placeholder login file and a placeholder session token; the proxy swapped in the
    real ones toward `api.anthropic.com` only.
  - The identity read `acting for: claude.ai account … (remote-control) → rc-agent`.
- **Connectors.** The first session tried the account's 11 claude.ai connectors (`mcp-proxy.anthropic.com`).
  Those requests were denied, then forbidden in the zone; a later session's connector listing was refused
  outright, and no connector requests reached the queue.
- **The agent didn't know it was sandboxed**, and WebFetch showed only a bare 403, so the agent retried by
  other means. That led to:
  - status lines and bodies that say which kind of block it is;
  - a shared sandbox notice for wrapped sessions;
  - `request_access`;
  - spin detection.
- **The live check after those changes.** A batch agent blocked on `news.ycombinator.com` and a made-up
  domain said "Both need approval. I'll wait on the grants", waited with `await_grant`, and retried each
  once after the owner approved from the console with a passkey.
  - The made-up domain failed at DNS on the host after approval, and the agent reported that it doesn't
    exist.
