# Fire a trigger from a webhook

A webhook or GitHub trigger wakes or messages an agent when a delivery arrives: "CI failed on a pull
request", "an issue was labelled", or any service that can POST a signed body. It fires with your
authority as its owner, never more, and only its own trigger: each one has its own URL.

The control host never takes webhooks itself. A small service, `wicket node intake`, does, on a
node you choose. It checks each delivery and hands what it verified to that node, and the
reconciler collects it from there. [Webhook intake](../explanation/trigger-intake.md) explains why.

## 1. Choose and label an intake node

Use a node with a public address. Mark it:

```sh
wicket node set edge-1 --label wicket.intake=true
```

The node must talk protocol 20 or later (`wicket node list` shows it), so update it first if it
doesn't. The local node, `local`, is the control host's own machine: a trigger takes it only with
`wicket trigger create --allow-local-intake`. Inbound internet traffic would then reach the machine
with the ledger, the vault and the keys, so use a separate node if you can.

## 2. Run intake on the node, as its own user

Intake parses whatever the internet sends it, so it runs as a user of its own, `wicket-intake`,
which can't read the node's keys, its boxes or its spool. It reaches the node's `wicket node serve`
only through a socket that `serve` checks by the peer's uid. As root, on the node:

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin wicket-intake
# The socket's directory: setgid, so the socket wicket makes there is group wicket-intake.
echo 'd /run/wicket-intake 2750 wicket wicket-intake -' > /etc/tmpfiles.d/wicket-intake.conf
systemd-tmpfiles --create /etc/tmpfiles.d/wicket-intake.conf
install -d -m 750 -o root -g wicket-intake /etc/wicket-intake   # cert.pem and key.pem go here, mode 640
```

Tell the node's `serve` where intake's socket is and whose it is, in its `node.json`
(`~wicket/.local/share/wicket-node/node.json`), then restart `wicket node serve`:

```json
"intake_socket": "/run/wicket-intake/intake.sock",
"intake_uid": 998
```

(`id -u wicket-intake` gives the uid.) Then install and start the unit:

```sh
install -m 644 deploy/node/wicket-intake.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wicket-intake
```

The unit (`deploy/node/wicket-intake.service`) gives intake nothing else. It has no home, no
devices and no privileges, a read-only system, memory and task limits, and only the IPv4, IPv6 and
unix socket families. Restart it after a self update of the node.

- **TLS.** Give it a certificate and key in `/etc/wicket-intake`. Or drop `--tls-cert` and
  `--tls-key` from its command, and put a TLS-terminating reverse proxy in front.
  - It then listens on plain HTTP, so bind it to an address only the proxy reaches.
  - Name the proxy with `--trusted-proxy <address or CIDR>`, so intake takes the client's address
    from its `X-Forwarded-For`. Otherwise every request looks like the proxy's.
- **What it holds.** Its table of triggers (their URL tokens' hashes and verify secrets) comes from
  `wicket node serve` every 10 s, in memory, and only this node's triggers.
  - While that `serve` isn't running, or hasn't heard from the control host since it started (up to
    a reconcile pass), deliveries get 503, and senders that retry try again.
  - GitHub doesn't redeliver on its own: a delivery refused then shows in the hook's "Recent
    Deliveries", where you can redeliver it.
- **Trying it out.** Without `intake_uid`, `serve` takes intake as its own user, on
  `ctl/intake.sock`: `wicket node intake --listen 127.0.0.1:8443`, as the wicket user. Keep that
  for a test node.

## 3. Store the webhook's secret as a verify secret

On the control host:

```sh
wicket secret set gh-hook-acme            # the secret you'll give GitHub (or the sender)
wicket secret verify gh-hook-acme
```

A verify secret only checks deliveries' signatures. It is sent to no host, and can't be bound to
one, so no box's egress can ever read it.

## 4. Make the trigger

```yaml
trigger: ci-failed
source:
  github:
    repo: acme/app
    events: [check_suite]
    verify: { hmac_sha256: gh-hook-acme }
filter: { check.conclusion: failure }
action:
  wake: release-captain
  message:
    body: "CI failed on PR {{ event.pr.number }} ({{ event.branch }}): {{ event.check.url }}"
```

```sh
wicket trigger create --file ci-failed.yaml
```

It prints the trigger's URL path, once: `https://<the node's intake address>/hook/<trigger>/<token>`.
wicket keeps only the token's hash. If you lose it, `wicket trigger rotate-url ci-failed` makes a
new one, and the old one stops working within a reconcile pass. With several intake nodes, name one
with `--intake-node`.

- **On GitHub.** Under the repository's Settings, Webhooks, add the URL, set the content type to
  `application/json`, give it the secret, and pick the events the trigger listens to. GitHub signs
  each delivery (`X-Hub-Signature-256`) and names it (`X-GitHub-Delivery`).
- **A generic webhook.** Use `webhook: { verify: { hmac_sha256: <secret> } }` as the source. The
  sender sends:
  - `X-Wicket-Timestamp`: the time, in Unix seconds;
  - optionally `X-Wicket-Delivery`: an id for the delivery, which wicket uses to drop resends (the
    body's sha256 otherwise);
  - `X-Wicket-Signature-256: sha256=<hex>`: the HMAC-SHA256, under the secret, of
    `v1:<timestamp>:<length of the delivery id>:<delivery id>:` followed by the raw body (the id
    empty, length 0, if it sends none). The id's length is signed, so a delivery can't be split
    differently between its id and its body.

  A delivery more than 5 minutes from intake's clock, or under another id than it was signed with,
  is refused, so one that was seen can't be sent again.

## What a delivery becomes

- **Fields, not the body.** A trigger, its filter and its template see only a short list of fields,
  each capped and stripped of control characters. The raw body is never kept, only its sha256.
  - **GitHub:** `event`, `action`, `repo`, `sender`, `branch`, `sha`, `labels` (comma-separated),
    `pr.number`, `pr.author`, `pr.title`, `pr.url`, `pr.draft`, `base`, `review.state`,
    `issue.number`, `issue.author`, `issue.title`, `issue.url`, `comment.author`, `comment.url`,
    `check.name`, `check.status`, `check.conclusion`, `check.url`, `pusher`, `delivery`.
  - **Generic:** the body's top-level strings, numbers and booleans, if it is a JSON object: at most
    32 keys of `a-z`, `0-9`, `_` and `-` (the first by key order), each value at most 512 bytes.
  - **Both:** plus `delivery` and `at`, wicket's own, which a body's keys of those names don't
    replace.
  - **Forks.** A pull request from a fork names the fork's branch, often `main`. Use `fork: false`
    (or `head_repo`) with `branch` when it matters whose branch it is.
    - A pull request whose head repository is gone (a deleted fork) counts as a fork.
    - Other events don't say where their change came from (a check suite or run, an issue comment,
      a push), so `fork` is false there. GitHub lists no pull request on a check from a fork.
- **Data, never authority.** Everything in a delivery was written by whoever sent it. A valid
  signature only says they had the secret. Control characters are stripped on the node, and a node
  that sends any is refused on the control host. Fields reach the agent as quoted event input in
  its message, and never a manifest, a zone or a limit.
- **Loops.** An agent that pushes, comments or opens a pull request makes GitHub send a delivery,
  which can fire its own trigger again. Filter out what the agent does itself, for example
  `sender: "!my-agent-bot"` or `pusher: "!my-agent-bot"`.
- **Once.** A resent delivery fires once: the same delivery id, or, for GitHub, the same body
  under another id.
  - For a generic webhook the whole signed message counts (its time, its id and its body), so the
    same body sent as a new delivery isn't taken for a resend.
  - Intake also remembers what it handed on for 24 hours, and answers a resend 202 without counting
    it against the trigger, so a replayed body can't use up the trigger's rate.
  - GitHub doesn't sign its delivery id or a time. So a GitHub delivery someone captured (GitHub
    shows them on the hook's page) could be sent again under another id. wicket drops the same body
    for as long as it keeps the event, 14 days, but not after.
  - If that matters, filter on fields that age out (`action`, a check's status), or rotate the
    secret.
- **Within limits.**
  - Intake checks the path and token before it reads a body, and caps the body at 1 MiB.
  - A request with a trigger's token is never slowed down for what its address did before.
    - Requests with no trigger's token are counted by address, an IPv6 address by its /64, and an
      address that keeps sending them is answered 429.
    - Bad signatures are counted by trigger, never by an address another sender may share (GitHub
      sends from shared addresses).
  - Only verified deliveries count against a trigger's 60 a minute (bursts of 20), and the node's
    600, so a leaked URL alone can't use up a trigger's rate.
  - The trigger's `per_hour` still applies when it fires.
  - A paused trigger records deliveries and fires nothing.
  - A delivery read more than 15 minutes after it arrived (the reconciler was down) is passed over.
- **What's refused.** Bad tokens, bad signatures and deliveries over the rate are answered at once,
  and never reach the control host. They are counted, and audited at most once an hour per node
  (`trigger.intake_refused`).

## Latency

Deliveries are collected by each reconcile pass (`wicket reconcile --every 1m`), so a delivery
fires within about a minute. Intake answers the sender as soon as the node has the delivery
(202), so GitHub doesn't wait or retry.
