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
- **send a follow-up** to a running agent (`wicket say`);
- **revoke an identity** with a reason (`wicket identity revoke`);
- **answer `request_access` asks**, including prefix asks: the passkey signs that the grant covers every path
  under the prefix, and, as for every approval, the agent's verified identity. A prefix covers whole path
  segments (`/repos/acme/app/…` covers `/repos/acme/app` and what's under it, not `/repos/acme/app-secrets`),
  and every grant covers nothing riskier than the request you were shown: approving an R2 prefix doesn't
  allow the R4 operations (workflow edits, merges, access changes) under it. An agent whose identity
  doesn't verify (or was revoked since you were shown the ask) can be denied, not approved.
- **register a device for notifications, and show the request on one** (`push_subscribe`,
  `push_details`): see [notifications](#notifications). Removing a device and hiding the request
  need only the session.

Open it as `http://localhost:8787` (WebAuthn needs a secure context). `wicket approve` on the host remains a
break-glass path and is audited as such.

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
- **Before sign-in** a client can fetch only the page, its static files (script, stylesheet, service worker, manifest, icons)
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
  bodies. A fuzz-style test throws random methods, paths, headers and bytes at the router and the wire and
  checks it never panics and never reaches a signed-in handler.
- **Installable:** the console has a web app manifest and icons, so it can be added to a phone's home screen.
- **Privilege separation** is #12: the console is meant to run as the unprivileged wicket system user. Nothing
  here needs root (bind :443 with `CAP_NET_BIND_SERVICE` instead), its TLS and ACME state is in its own files,
  and it starts runs through one launch callback (a detached `wicket run`), so moving launching behind a
  separate, more privileged process later changes only that callback.

![The console: a pending request with its verified identity, and the approve and deny buttons](../images/console-passkey.png)
