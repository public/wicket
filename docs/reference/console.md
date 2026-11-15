# The operator console

The console (`wicket serve`) shows what's waiting for you, runs, recent decisions and activity, and you approve
or deny from a browser or phone. Its options are in the [command line reference](cli.md#wicket-serve); [put the console on the
internet](../how-to/put-the-console-on-the-internet.md) sets it up behind TLS.

## Passkeys

It uses **passkeys**:
- passkeys are enrolled only through one-time links from the host: `wicket serve` prints one at start-up while no
  passkey exists, and `wicket operator enrol-link [--ttl 10m] [--origin URL]` prints a fresh one at any time
  (single use, 10 minutes by default and at most 1 hour; the session it opens can only enrol one passkey).
  An installed console runs with `--no-bootstrap-link`, so there you use `sudo wicket operator enrol-link`. A
  signed-in console session can't add a passkey, so a stolen cookie can't either;
- sign-in is a passkey with user verification;
- **every approve or deny is signed again**, over a challenge that is the hash of exactly that decision
  (request, method, host, path, decision, uses, lifetime). The server checks it, uses it once, and stores the
  signed record, so `wicket audit --verify` re-verifies every decision offline;
- **signing takes two steps.** A tap on Approve, Deny, Send, Revoke or Start asks the server for the exact
  action. The page then shows that action in a confirmation pinned to the top of the screen, above where a
  phone's passkey sheet opens, and only its own button starts the passkey ceremony. The authenticator's sheet
  shows only the site's name, so this confirmation is what tells you what you're signing. While it is open,
  nothing on the page is redrawn. Pending cards are kept by request id, and a tap within a moment of the cards
  moving is ignored, so an agent can't slide another request under your finger;
- `wicket operator reset` (host only) revokes passkeys but keeps their public keys for verification.

## Actions

Signed in, the console can also do what was CLI-only, each action signed with a fresh passkey assertion over
exactly its parameters, checked again when applied, audited with the passkey that signed it and re-verified by
`wicket audit --verify`:
- **start a run** from a manifest in an allowlisted directory, with an optional task override. The directories are
  the installation's `manifests/` (`$WICKET_HOME/manifests`, by default `~/.local/share/wicket/manifests`) and
  `examples/` of the directory `wicket serve` was started in. The browser picks a directory and a file name from
  the list the server offers (regular files named `*.yaml`/`*.yml` directly in them; no symlinks, subdirectories
  or paths), and the passkey signs the manifest's SHA-256, so a file changed after you saw it is not started. The
  start card shows, and the passkey signs, the image the box starts from: the manifest's `agent.image` (default:
  the installation's agent image); a manifest whose image isn't in its `zone.images` is refused. The run is a detached `wicket run` (it outlives the console; its log is `runs/<run>/console.log`), and its principal
  is you, the passkey-signed-in operator (`passkey:<name>, via console`, with your operator identity
  `spiffe://<domain>/t/<tenant>/op/passkey/<name>` as its `sub`), not the host's unix user. What you may
  approve is your authority in [`operators.yaml`](configuration.md#operatorsyaml) (anything by default);
- **open a run's session** (an ACP agent's: the row's *session* link), below;
- **send a follow-up** to a running agent (`wicket say`; for an ACP agent, the session's prompts replace it);
- **revoke an identity** with a reason (`wicket identity revoke`);
- **answer `request_access` asks**, including prefix asks: the passkey signs that the grant covers every path
  under the prefix, and, as for every approval, the agent's verified identity. A prefix covers whole path
  segments (`/repos/acme/app/…` covers `/repos/acme/app` and what's under it, not `/repos/acme/app-secrets`),
  and every grant covers nothing riskier than the request you were shown: approving an R2 prefix doesn't
  allow the R4 operations (workflow edits, merges, access changes) under it. An agent whose identity
  doesn't verify (or was revoked since you were shown the ask) can be denied, not approved.

Open it as `http://localhost:8787` (WebAuthn needs a secure context). `wicket approve` on the host remains a
break-glass path and is audited as such.

## Sessions

A running ACP agent's session, live, on its own page (#327): `/session?run=<run>`, opened from the
run's *session* link in **Runs** (shown for running ACP runs, whose supervisor keeps
`acp-client.jsonl`). How-to: [work with a running agent in the console](../how-to/work-with-a-running-agent-in-the-console.md).

**What the page shows,** as it streams:
- the agent's messages and thoughts (thoughts folded), as plain text: no markdown or HTML is
  rendered, so nothing the agent writes becomes page markup;
- its tool calls with their arguments and results (text and diffs), and how wicket's policy answered
  each of the agent's own permission requests ("allowed by wicket's policy");
- its plan, with each entry's status;
- other principals' prompts (the task, other operators, wicket's notices), each with who sent it;
- **wicket's escalations** for the run, inline: what was asked (method, host, path, risk, reason)
  with **Approve once (passkey)** and **Deny (passkey)**. A tap asks `/api/decide/begin` for the
  decision, the confirmation at the top states it (as on the front page), and its own button has the
  passkey sign it through `/api/decide/finish`: the same signed decide action as the front page's
  cards (#256), approving once for 10 minutes. An escalation decided elsewhere (the front page,
  another device) updates in place.

**Prompts** typed on the page are ACP `session/prompt`s on the endpoint: each becomes an operator
message from your principal (`passkey:<name>`), which the supervisor hands to the agent as its next
turn (queued if a turn is running). **Stop** sends `session/cancel`: the supervisor cancels the
agent's running turn within a second or so (ACP's own `session/cancel`), the turn ends with
`cancelled`, and prompts queued behind it stay queued. With no turn running, Stop does nothing (and
says so in the audit).

**Opening** takes your passkey: a tap on *Open session* shows the `open_session` action (run,
agent, your principal), and signing it gets a single-use ticket for that run and this console
session, valid 60 s. The page then opens the WebSocket `GET /api/runs/<run>/acp` (ACP v1, wicket as
the agent, the session id being the run id) with the `acp.v1` subprotocol and the ticket as a
`wicket.ticket.<hex>` subprotocol, never in the URL. The upgrade needs the session cookie, the
console's own `Origin` and the ticket; the cookie alone opens nothing. A reload or a reconnect signs
a new open; the session replays from the start of the kept transcript. The socket closes when your
console session ends (sign-out, idle, expiry, a revoked passkey) or the run ends.

**What the endpoint filters** (`crates/wicket-cli/src/serve/session.rs` is the reference): the
agent's `_meta` is dropped everywhere and only ACP v1's `session/update` kinds pass; the agent's
own requests are never forwarded; tool-call ids starting `wicket:` are reserved for wicket's
escalations, so nothing the agent sends can raise one. **An ACP answer to an escalation prompt
decides nothing**: only the signed decide action does; the endpoint records what the client said
next to the ledger's status (`session.escalation_answered`).

**Limits:** prompts of up to 16 KiB of text (no images or resources yet), 16 waiting per socket,
messages from the browser up to 256 KiB, one cancel a second per socket. Session sockets are capped
at **4 per console session** and **32 in all** (upgraded sockets leave `--max-connections`): over a
cap the open is refused before a ticket is issued, and an upgrade gets 429 without spending its
ticket, which still works within its 60 s once a socket closes.

**Audit:** `session.opened` (with the signed assertion), `session.attached`, `session.prompt` (by
principal, with the operator message it queued and the text's length and sha256), `session.cancel`
and the supervisor's `run.turn_cancel` (whether a turn was running), `session.escalation_answered`,
and `session.closed`; decisions are `decision` records, as from anywhere.

**The view** is `web/session/` in the repository: a Vue fork of
[acp-ui](https://github.com/formulahendry/acp-ui) (MIT; `web/session/FORK.md` says what was kept and
changed), about 33 KB gzipped. CI builds it from its committed lockfile (`ci/session-view.sh`:
`npm ci --ignore-scripts`, a licence check, then the build twice from fresh installs, which must give
the same bytes) and the binary embeds it (`crates/wicket-cli/build.rs`, from the directory in
`WICKET_SESSION_VIEW`), served as `/static/session.<hash>.js` and `.css` with Subresource Integrity
under the console's CSP. A build without `WICKET_SESSION_VIEW` (a plain `cargo build`) embeds a
placeholder page saying the view wasn't built, and `wicket serve` says so at start-up. To build one
with the view:

```sh
ci/session-view.sh                                  # needs Node 22.12+ and npm; prints the dist path
WICKET_SESSION_VIEW=$PWD/web/session/dist cargo build --release -p wicket-cli
```

Not yet: answering the agent's own permission requests from the page (wicket's policy answers
them, #67), images and resources in prompts, and the box tree, budgets and hibernate controls
next to the session (#327's later slices).

## Authority views

Read-only, behind the session like the rest of the page (#173). Nothing here changes authority:
that stays a signed action.

- **A run's authority** (its row's *authority* link; `GET /api/runs/<run>/authority`): its token as
  its node's feed holds it now, read from the feed's delta log without writing anything.
  - Every block decoded to Datalog: block 0 (the zone's policy compiled, the org layer, the box's
    lifetime), each spawn block (the chain back to its root run), and each grant block, with the
    public key of whoever signed it.
  - Whether each block is revoked, with a **fingerprint** of its revocation id. In Biscuit a
    revocation id is the block's signature, so the id itself is never shown.
  - Each grant: what it allows, its uses (counted on the node) and expiry, who approved it (passkey
    or root) and when, whether it was revoked, and whether its node has the feed delta that carries it.
  - The policy version it was minted under, against the installed one; its deadline (when its
    authority ends) and whether its box stopped; which node holds it and its feed's epoch.
  - What its node holds for it (#152): the secrets it fetched, **by name only**, and its budget
    slice.
  - The zone's policy as Cedar, generated from the manifest.
  - Whether the token loads (it may not, for instance once its issuing key's certificate ended).
  An ended run's token is gone from its node's feed; its page says so.
- **Explain a decision** (an activity row's *explain* link; `GET /api/explain/<seq>`): the request
  that row records, as it was decided then (by whom, the control host or the box's node, and the
  detail recorded), and the run's token's decision for it **as the token is now**: the ceilings,
  the grant that allows it, or the failed checks, each naming its block. Grants and policy may have
  changed since; the page says so. Explaining spends no grant use and asks no node.
- **The org policy** (the *Policy* section; `GET /api/policy`): the applied Cedar and its entities,
  whether `org.cedar` still matches what was applied (a hand edit refuses every mint), every kept
  version with when and by whom it was applied, and each running run with the version it was minted
  under: current, older, or revoked by a later `wicket policy apply`.

**Never shown:** a serialized token, any signature (a block's or a JWS's), a secret's value, a private
key. Each view is built from named fields, never by serializing a stored record, and a test fetches
every console endpoint and scans each answer for the token, any 24-byte run of its bytes (base64url,
base64 and hex, except runs inside a public key), identity JWSs and private keys.
## Manifests

The **Manifests** section lists the manifests runs can be started from (#172). The installation's
`manifests` directory can be edited; `examples/` is read-only.

- **Viewing** a manifest (`GET /api/manifests/<root>/<name>`) shows:
  - whether it validates, with the error `wicket run` would give;
  - every field with its effective value, marking those the file doesn't set (defaults);
  - what it grants: the task, the agent or program and its image, the isolation, each reach rule,
    which hosts the egress proxy splices and which it inspects (and why), each forbid, each
    injection's secret **by name**, with whether the vault has it and binds it to that host, the
    model route and budgets, volumes and limits;
  - with an org policy applied, its layer for this zone and whether a box minted from it passes;
  - the raw YAML, and the saved versions.
  Secret values are never shown.
- **Editing** checks the YAML as you type (`POST /api/manifests/check`, read-only): the same
  validation `wicket run` uses, and the **authority diff** against the saved version:
  - every reach, forbid, injection, volume, image and `accept_from` rule added or removed, and the
    isolation, model route, budgets, limits and `max_children` before and after;
  - whether it **widens** authority, and how: the test a spawned zone passes against its parent's,
    with the saved version as the parent, plus a removed forbid, another model route or a new
    injection. A new manifest always widens.
- **Saving** is a signed action, `save_manifest`. The passkey signs the new bytes' sha256, the sha256
  of the version they replace, and the authority diff, and the confirmation says plainly when it
  widens. Applying it checks the file is still the version shown (else it refuses), keeps that
  version in `manifests/.history/<name>/<time>-<sha256 prefix>.yaml`, writes the new one, and audits
  `manifest.saved` with the signed record (`wicket audit --verify` re-verifies it offline).
- **Restoring** a saved version is a signed action too, `restore_manifest`, recorded the same way;
  the version it replaces is kept as well.

Runs keep the manifest they started with: each run records its manifest's text at start, and the
console's Start signs the manifest's sha256.

## On the internet

The console is built to be reachable directly from the internet, with no VPN or access proxy in front
(#23). Passkeys stay the only authentication. This is what it enforces; the setup is in [put the
console on the internet](../how-to/put-the-console-on-the-internet.md).

- **Client addresses.** `X-Forwarded-For` is read only on connections from a `--trusted-proxy`. All
  of its header lines are read, in order, and the client is the right-most entry that isn't a
  trusted proxy. Anything further left is whatever the client sent.
- **Transport.** A non-loopback listener refuses to start in plain HTTP unless `--behind-tls-terminator` is given
  with an `https://` `--origin`. TLS is rustls: TLS 1.3, and TLS 1.2 with ECDHE and AEAD suites only; HTTP/1.1
  only (no h2, so there is one HTTP implementation to bound). HTTPS responses carry
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (submitting the domain to the
  preload list is your step). ACME keeps its account and certificate in `$WICKET_HOME/acme` (0700/0600) and
  renews 30 days before expiry; binding :443 needs `CAP_NET_BIND_SERVICE` (or a port redirect).
- **Before sign-in** a client can fetch only the page and the session page (`/session`, the same
  for every run, with no data in it), their static files (scripts, stylesheets, manifest, icons)
  and the passkey sign-in endpoints. Everything else, whatever the method or path, gets the same 401 and body:
  no runs, counts, passkey ids or version. Enrolment is only via a one-time link issued on the host (`wicket operator enrol-link`).
- **Sign-in** needs user verification; there is no password or fallback. Attempts are limited per client
  address (IPv4, or IPv6 /64; `X-Forwarded-For` is honoured only from a `--trusted-proxy`) and per passkey:
  20 a minute, and 5 failures lock out for 15 minutes, doubling up to a day. Pending challenges expire after 2
  minutes and come from two bounded pools. Sign-in challenges get 512 in all, 8 per client and 32 per
  IPv4 /24 or IPv6 /48. Signed-in sessions' action and enrolment challenges get 512 in all and 8 per
  session. A flood of sign-in attempts therefore never stops the operator from approving. Every failure looks the same to the client, and every failure
  and lockout is in the audit log. The limiter remembers 4096 clients. When every entry is a live lockout, the
  oldest one is dropped to make room, so new clients aren't all refused.
- **Sessions** are `__Host-wicket_sid` cookies (Secure, HttpOnly, SameSite=Strict, Path=/), new at every
  sign-in, ending after 15 minutes idle or 8 hours in any case. `wicket operator sessions` lists them on the
  host and `wicket operator revoke-session ID` (or `--all`) ends them. Every action is still separately
  passkey-signed, so a stolen cookie alone approves nothing.
- **Browser.** No inline script or style (the script and stylesheet are hashed static files with Subresource
  Integrity), `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src
  'self'; img-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  no CORS, `Referrer-Policy: no-referrer`, `nosniff`, `Cross-Origin-Opener-Policy: same-origin`. POSTs need the
  `x-wicket-csrf` header and the console's own `Origin`. Requests for another `Host` get the 401.
- **HTTP limits:** 256 connections (`--max-connections`), 16 per client address, 10 s each for the TLS
  handshake, the request headers and the body, 2 minutes per connection, 16 KiB and 64 header lines, 64 KiB
  bodies. Session WebSockets have their own caps, 4 per console session and 32 in all ([sessions](#sessions)). A fuzz-style test throws random methods, paths, headers and bytes at the router and the wire and
  checks it never panics and never reaches a signed-in handler.
- **Installable:** the console has a web app manifest and icons, so it can be added to a phone's home screen.
- **Privilege separation** is #12: the console is meant to run as the unprivileged wicket system user. Nothing
  here needs root (bind :443 with `CAP_NET_BIND_SERVICE` instead), its TLS and ACME state is in its own files,
  and it starts runs through one launch callback (a detached `wicket run`), so moving launching behind a
  separate, more privileged process later changes only that callback.

![The console: a pending request with its verified identity, and the approve and deny buttons](../images/console-passkey.png)
