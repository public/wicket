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
- **revoke an identity** with a reason (`wicket identity revoke`);
- **answer `request_access` asks**, including prefix asks: the passkey signs that the grant covers every path
  under the prefix, and, as for every approval, the agent's verified identity. A prefix covers whole path
  segments (`/repos/acme/app/…` covers `/repos/acme/app` and what's under it, not `/repos/acme/app-secrets`),
  and every grant covers nothing riskier than the request you were shown: approving an R2 prefix doesn't
  allow the R4 operations (workflow edits, merges, access changes) under it. An agent whose identity
  doesn't verify (or was revoked since you were shown the ask) can be denied, not approved. The
  passkey also signs the request's [effect descriptor](../explanation/approvals-bound-to-effects.md)
  (`effect`, `effect_sha256`): who asks, the target, the risk, the terms and the arguments' hash. If
  the request is no longer that effect when the decision is applied, it is refused. Before an
  approval that widens (a prefix, more than one use, over an hour, or zone-wide), the confirmation
  shows its blast radius: what else it would allow, with requests this run made, and how many of
  the run's last 200 egress requests it would have covered.
- **approve an agent's `request_update`, which installs its build** (#465): the confirmation shows,
  and the passkey signs as `update`, the file in the run's `/workspace/out` with the requested
  sha256, its size, the commit the agent says it is, and the nodes it reaches after the control
  host. Approving runs `wicket self apply-update <request>` (log:
  `<data dir>/runs/<run>/update-<request>.log`): the blue/green update with its health gate and
  rollback, then the nodes; the agent is told how it ended. For a box on another node, the
  confirmation says the outbox is fetched from that node once you approve, and the file is found
  in it by its sha256 then. If the file isn't there, the confirmation says why, and approving only
  accepts the sha256 for a
  `sudo wicket self update` on the host ([run wicket in wicket](../how-to/run-wicket-in-wicket.md)).
- **register a device for notifications, and show the request on one** (`push_subscribe`,
  `push_details`): see [notifications](#notifications). Removing a device and hiding the request
  need only the session.
- **store or replace a secret, change its hosts, or delete it** (`set_secret`, `secret_hosts`,
  `delete_secret`): see [secrets](#secrets). The passkey signs a salted sha256 of a value, never
  the value.
- **issue and renew a capacity grant** (`capacity_grant`, `capacity_renew`): see
  [capacity grants](#capacity-grants). Revoking one needs only the session.
- **release a run's fence** (`release_fence`, #690), the console's path beside root's `wicket node
  release-fence`. A run is fenced while its box may still be running on a node that hasn't confirmed
  it stopped (see [the wake fence](nodes.md)): its agent isn't woken and the run isn't ended. Every
  box a node runs is fenced while its authority is live, and a reporting node ends its boxes' fences
  itself, so the **Fenced runs** card lists only fences their node can't end: its node is revoked,
  no longer enrolled, or hasn't reported for the feed's TTL plus two report intervals (90 s by
  default). Each row shows the node, when it last reported, when the fence ends (or that it lasts
  until the node confirms), and why. **Release…** asks for a reason; the passkey signs the run, its
  node, the node's status and last report, the fence's end, the reason and its effect, and a
  release of a fence that changed since you were shown it (its node reported again, say) is refused.
  A fence whose node is enrolled and reporting is refused (409), and only an operator whose authority
  in [`operators.yaml`](configuration.md#operatorsyaml) covers `fence` at R4 may release one (403
  before the passkey; refusals when applied are audited as `decision.refused` with your identity).
  It is audited as `run.fence_released` with your passkey and operator identity, the record root's
  command writes too (`granter` `human` or `root`, `via` `console` or `cli`). If that record can't
  be written, the release is undone. The box may still be running: release a fence only for a node
  that will never run it again.

Open it as `http://localhost:8787` (WebAuthn needs a secure context). `wicket approve` on the host remains a
break-glass path and is audited as such.

## Capacity grants

A capacity grant lets a principal lease nodes with `wicket node create` without asking each time
([#256](https://github.com/public/wicket/issues/256)). The Capacity card issues one to a principal:
an operator as `unix/<user>` or `passkey/<name>`, or any identity as `spiffe://…`. The grant names:
- the plans and regions it covers;
- the most its nodes may cost per hour together, and the most the nodes it approves in any day may
  cost (their worst cases);
- how many of its nodes may exist at once;
- its lifetime, at most 24 hours.

The passkey signs all of it. The grant is one grant record (`QUOTA wicket.internal /quota/capacity`,
its daily money as its amount, `wicket grant list` lists it) and a `decision` audit record.

`wicket node create` files its spend as a request, `CAPACITY wicket.internal /capacity/node/<name>`,
from the operator who runs it. If one of that operator's live grants covers the node, the request
is approved at once through the same decide function as every approval. The decision is audited
against the grant (`capacity_grant`, the ask, and what its uses took before). Otherwise the
request waits in **Waiting for you**, with a notification on your devices, for up to `create
--wait` (default 15 minutes).

Each row of the card shows what the grant covers, what its nodes use and leave, and when it ends.
**Renew** is a signed decision that gives it a new end, from now (the form's hours, at most 24).
**Revoke** ends it at once: nothing more is approved under it, and the nodes made under it keep
their own leases. Whatever the grant, the node's money is reserved first against the limits in
[`placement.yaml`](configuration.md#placementyaml), which leases share (#256), before anything is
asked or created. An operator whose authority in [`operators.yaml`](configuration.md#operatorsyaml)
doesn't include `capacity` may not issue or renew one.

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

**In a terminal,** `wicket session <run>` opens the same session at the host's shell, through the same
bridge (`crates/wicket-cli/src/session.rs`): it runs as the operator wicketd names, with no passkey
(as `wicket approve` does), shows what the page shows as text, and sends each line typed as a prompt;
`/stop` is Stop. Escalations are decided with `wicket approve` or `wicket deny`, or here. It also
opens a Claude Code agent's session (stream-json, which has no ACP stream): its messages, tool calls
and turn ends from the transcript. Its records carry `via: terminal`. `wicket say` and the console's
**Follow-up** box are gone (#198): prompts are sent in a session.

**Audit:** `session.opened` (with the signed assertion), `session.attached`, `session.prompt` (by
principal, with the prompt it queued (its message id) and the text's length and sha256), `session.cancel`
and the supervisor's `run.turn_cancel` (whether a turn was running), `session.escalation_answered`,
and `session.closed`; decisions are `decision` records, as from anywhere.

**The view** is `web/session/` in the repository: a Vue fork of
[acp-ui](https://github.com/formulahendry/acp-ui) (MIT; `web/session/FORK.md` says what was kept and
changed), about 33 KB gzipped. CI builds it from its committed lockfile (`ci/session-view.sh`:
`npm ci --ignore-scripts`, a licence check, then the build twice from fresh installs, which must give
the same bytes; then a UI check under jsdom and the view's client against the real endpoint) and
the binary embeds it (`crates/wicket-cli/build.rs`, from the directory in
`WICKET_SESSION_VIEW`), served as `/static/session.<hash>.js` and `.css` with Subresource Integrity
under the console's CSP. A build without `WICKET_SESSION_VIEW` (a plain `cargo build`) embeds a
placeholder page saying the view wasn't built, and `wicket serve` says so at start-up. To build one
with the view:

```sh
ci/session-view.sh                                  # needs Node 20.19+ or 22.12+ and npm; prints the dist path
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

## Secrets

The *Secrets* section shows the vault by name, as `wicket secret list` does, and changes it with
your passkey. It is read-only without a passkey signature.

- **What it shows**, for each secret: its name; its kind, a stored *value* or a *reference* (a link
  to a file on the host, as `wicket secret link` makes, with the file and JSON pointer it names);
  the hosts it may be sent to; when it was last set (its file's time); every use in the allowlisted
  manifests (the zone and manifest, and for an injection its host, `header` and `format`, or that it
  is a zone's model credential); and the running runs that use it (runs in a zone that uses it, and
  runs whose node was given it). Names the manifests use that aren't in the vault are listed as
  *not set*, with a **Set…** button. **Never a value**, nor anything derived from one: no prefix,
  length or digest. The view is built from names, bindings and file times; the server never reads a
  value to build it.
- **Store or replace a value** (`set_secret`): **New secret…**, **Set…** or **Replace value…**
  open a form with a name, a value and hosts. The value field is a password field
  (`autocomplete=off`), cleared as soon as you submit. The page picks a random 16-byte salt and
  sends `value_salt` and `value_sha256` (the sha256 of the salt and the value) with `begin`. The
  passkey signs those, the name, the hosts and whether it replaces a value, never the value. The
  value goes only in the body of `finish`, over HTTPS (or loopback), and must hash to what was
  signed; a `begin` carrying a value is refused. So the value is never kept with a pending
  challenge, never in a response, a log or the audit (which keeps the salted digest the passkey
  signed, for `wicket audit --verify`), and the server zeroizes it, and the request body it came
  in, once stored. A value must be one line (no control characters) of at most 16 KiB. Hosts work
  as for `wicket secret set --hosts`: those given, else those the secret had, else, for a harness's
  default model secret, its model host; a new secret with none is sent nowhere.
- **Change hosts** (`secret_hosts`, **Hosts…**), as `wicket secret hosts`: replaces the list; a
  secret is sent only to hosts it is bound to. At least one host; `*.example.com` covers every host
  under it. A reference's hosts can be changed too.
- **Delete** (`delete_secret`, **Delete…**), as `wicket secret remove`: a first tap shows which zones
  and running runs use it, and the passkey's confirmation names them again. A reference's deletion
  removes only the reference, not the file.
- **References are made on the host.** A reference names a path on the host, so the console can't
  create one: `wicket secret link NAME --file PATH [--pointer /json/pointer]`. The section says so.
- **Checked again when applied.** Each action fails if the secret changed between `begin` and
  `finish` (it appeared or went, became a reference, or was rebound), so you sign what you saw.
- **Unsigned asks** (`POST /api/secrets/…`) are refused with 403 and audited as `secret.refused`,
  as is a secret action whose signature fails. Signed actions are audited as `secret.set`,
  `secret.hosts` and `secret.removed`, by name and hosts, with the passkey and the signed record.
  Secret actions share the other actions' limits (at most 8 passkey ceremonies pending per session,
  each expiring after 2 minutes).
- **Running boxes** use secrets as before: the proxies read the vault at each use, and a node
  holding a copy is told to drop it when it changes, so a new value is used from the next request.
- The console writes the vault of the user it runs as (installed: the `wicket` user's,
  `/var/lib/wicket/.config/wicket/secrets/`), the vault the proxies read.

## The state store and the audit export

The *Health* section starts with the state store's rows ([#635](https://github.com/public/wicket/issues/635)),
when `state-store.yaml` or `audit-sinks.yaml` exists. `wicket top` shows the same lines.

- **State store**: the endpoint and bucket, and the ledger stream's state, as Litestream reports it
  on its control socket: `streaming`, `starting`, `lagging` or `stopped`. Then when the store was
  last brought up to date and Litestream's last error, the same as `wicket state check`. The row is
  marked once the stream is lagging or stopped.
- **Audit export**, one row per sink, the same as `wicket audit export --status`: how many records
  the sink is behind the chain head and how long the oldest of them has waited, where its cursor
  is, how long ago its last signed checkpoint was, and its last error.
- A config that can't be read is a line of its own. It doesn't stop the rest of the page.
- **Alerts.** Three conditions are health alerts, pushed like a node's: once when one appears, and
  again only after it has cleared, under the `wicket-health` tag. Their text names the condition,
  never an error (that stays in the rows, as it can quote a collector's reply).
  - **The ledger stream** is in any state but streaming, and its last sync was more than 5 minutes
    ago. When Litestream doesn't report a last sync (it is stopped, or restarting), that counts from
    the last sync the console saw while it was streaming, or from when the console started.
  - **An audit sink**'s oldest unacknowledged record has waited more than 5 minutes, or the sink is
    more than 10,000 records behind. A `jsonl` sink to standard output (`path: "-"`) is fed only by
    `wicket audit export` in the foreground: its row says *manual*, and it never alerts.
  - **A config** (`state-store.yaml` or `audit-sinks.yaml`) can't be read for more than 5 minutes.
- The console reads all of this every 3 seconds in the background, whether or not notifications are
  on, and the page shows what it last read: a request never waits on Litestream.

The data is under `health.state_store` in `/api/state`: `stream`, `audit` and `errors`.

## Notifications

The console can notify your devices when a request is waiting for you (Web Push: RFC 8030, with
RFC 8291 message encryption and RFC 8292 VAPID). This covers egress asks and wicket's own capacity,
update, spawn and link asks. It works in desktop browsers and in the console added to an iPhone or
iPad home screen (iOS 16.4 or later; Safari tabs can't get pushes). [Get notified of
approvals](../how-to/get-notified-of-approvals.md) sets it up.

- **Registering a device is a signed action**, `push_subscribe`, like approving or starting a run:
  a stolen session cookie alone can't add a device that receives notifications. The **Enable
  notifications** button in the *Notifications* section asks for the browser's permission (only on
  that tap, as iOS requires), registers the service worker at `/sw.js` with scope `/`, subscribes
  with the console's VAPID public key, and asks your passkey to sign the registration. The
  confirmation, and the JSON the passkey signs, name the device by its id (the first 16 hex digits
  of the endpoint's sha256), its label and push service and whether it shows details, with the
  sha256 of its endpoint and of its keys (never the endpoint or keys themselves). The endpoint and
  keys are checked at `begin`, before anything is signed.
- **Showing the request on a device is signed too**, `push_details` (ticking *Show the agent and
  what it asks for*), as it widens what the device's lock screen shows.
- **What a session alone may do**: list devices (`GET /api/push`), remove one
  (`POST /api/push/remove`) and turn a device's details off (`POST /api/push/details` with
  `"details": false`). These only narrow what a device receives. `POST /api/push/subscribe`, and
  `POST /api/push/details` with `"details": true`, are refused with 403 and audited as
  `operator.push_refused` (with the passkey the session belongs to and the reason).
- **Whose devices.** Each device belongs to the passkey that was signed in when it was registered
  (any of the operator's passkeys may sign). An operator sees and changes only their own devices,
  and a passkey that is no longer enrolled gets no pushes.
- **Audit.** Every change is audited with the device's id, never its endpoint:
  `operator.push_subscribed` and `operator.push_details` (details on) with the passkey and the signed
  record, which `wicket audit --verify` re-verifies offline; `operator.push_details` (details off)
  and `operator.push_removed` with the session's passkey; `operator.push_refused` for an unsigned
  attempt to widen.
- **Where pushes go.** A subscription's endpoint must be an `https://` URL on the default port with
  no user info, on a known push service: `fcm.googleapis.com` (Chrome, Edge on Android),
  `*.push.apple.com` (Safari, iOS), `updates.push.services.mozilla.com` (Firefox) or
  `*.notify.windows.com` (Edge on Windows). Any other URL is refused when the device subscribes, and
  checked again before each push. The console's client is reqwest (rustls), HTTPS only, and follows
  no redirects. The console host needs outbound HTTPS to these hosts.
- **When.** The console checks the ledger every 3 seconds. A new pending request is owed to every
  subscribed device. A device gets at most one push every 30 seconds, and requests that arrive in
  between are coalesced into its next push. Nothing is sent if everything was decided before the
  push was due, and requests already waiting when the console starts are not announced. Each push
  is `aes128gcm`-encrypted for that device, with `TTL: 3600`, `Urgency: high` and
  `Topic: wicket-pending`, so a push service holding undelivered pushes for a device keeps only the
  latest. The device shows one notification at a time, replaced by the next.
- **What it says.** By default only "N requests waiting" and the id of the newest request, because
  lock screens show notifications. A device opted in with *Show the agent and what it asks for*
  also gets that request's agent and method, host and path (`lead asks GET api.example.com/x`,
  cleaned of control and bidi characters and cut to 200 characters). Reasons, attributions and
  identities are never sent. Push services see only ciphertext, its size and when it was sent.
- **Tapping a notification** focuses the console if it is open and marks that request's card, or
  opens `/#pending/<id>`. Approving still needs a sign-in and a passkey signature, as always.
- **A replaced subscription.** A browser may replace a device's subscription (Chrome and Firefox
  fire `pushsubscriptionchange`; Safari doesn't). The service worker can't register the new one: a
  registration is signed, and only the page can ask for the passkey. So it subscribes again with the
  same VAPID key if the browser hasn't already, tells any open console, and shows one notification
  ("Notifications on this device need renewing"); tapping it opens `/#notifications`. Whenever the
  console is open and this browser holds a subscription it doesn't know, *Notifications* says so and
  offers **Re-register this device**, a signed `push_subscribe`. Until then the device gets nothing;
  the old subscription is dropped when its push service answers 404 or 410.
- **Gone devices.** A push service that answers 404 or 410 has dropped the subscription. The
  console removes it and audits `operator.push_removed` with `"by": "push service"`. Other failures
  are logged with the device id and push service host, never the endpoint.
- **State.** The VAPID key pair is made once, at the first start, in `$WICKET_HOME/console/vapid.key`
  (0600, in a 0700 directory). Its private half is never logged or shown, and replacing it means
  every device has to subscribe again. Subscriptions are in `$WICKET_HOME/console/push-subscriptions.json`
  (0600): endpoint, `p256dh` and `auth` keys, label, setting, when made, last delivery. At most 10
  devices per passkey and 100 in all.
- **CSP.** Unchanged. The service worker is a same-origin script, allowed by `script-src 'self'`
  (with no `worker-src`, workers fall back to it). It is served at `/sw.js` with `Cache-Control:
  no-cache` so a new build reaches devices. It fetches and caches nothing, and shows the payload as
  notification text only.

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
  for every run, with no data in it), their static files (scripts, stylesheets, service worker, manifest, icons)
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
  passkey-signed, so a stolen cookie alone approves nothing, and registers no notification device.
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
