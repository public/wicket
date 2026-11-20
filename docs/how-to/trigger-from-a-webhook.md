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

The node must talk protocol 21 or later (`wicket node list` shows it), so update it first if it
doesn't. On a one-machine installation you can label the local node, `local`, but then inbound
traffic reaches the control host's machine.

## 2. Run intake on the node

On the node, as its `wicket` user, run `wicket node intake` as a user service beside
`wicket node serve`:

```ini
# ~/.config/systemd/user/wicket-intake.service
[Unit]
Description=wicket webhook intake
After=wicket-node.service

[Service]
ExecStart=%h/.local/bin/wicket node intake --listen 0.0.0.0:8443 --tls-cert %h/intake/cert.pem --tls-key %h/intake/key.pem
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now wicket-intake
```

- **TLS.** Give it a certificate and key with `--tls-cert` and `--tls-key`. Or leave them out and
  put a TLS-terminating reverse proxy in front: then it listens on plain HTTP, so bind it to an
  address only the proxy reaches.
- **What it holds.** Its table of triggers (their URL tokens' hashes and verify secrets) comes from
  `wicket node serve` every 10 s, in memory. While that `serve` isn't running, every delivery gets
  404.

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
  sender signs the raw body: `X-Wicket-Signature-256: sha256=<hex HMAC-SHA256>`. It may name the
  delivery with `X-Wicket-Delivery`, which wicket uses to drop resends; otherwise the body's sha256
  is used.

## What a delivery becomes

- **Fields, not the body.** A trigger, its filter and its template see only a short list of fields,
  each capped and stripped of control characters. The raw body is never kept, only its sha256.
  - **GitHub:** `event`, `action`, `repo`, `sender`, `branch`, `sha`, `labels` (comma-separated),
    `pr.number`, `pr.author`, `pr.title`, `pr.url`, `pr.draft`, `base`, `review.state`,
    `issue.number`, `issue.author`, `issue.title`, `issue.url`, `comment.author`, `comment.url`,
    `check.name`, `check.status`, `check.conclusion`, `check.url`, `pusher`, `delivery`.
  - **Generic:** the body's top-level strings, numbers and booleans, if it is a JSON object: at most
    32 keys of `a-z`, `0-9`, `_` and `-`, each value at most 512 bytes. Plus `delivery`.
- **Data, never authority.** Everything in a delivery was written by whoever sent it. A valid
  signature only says they had the secret. Fields reach the agent as quoted event input in its
  message, and never a manifest, a zone or a limit.
- **Once.** A resent delivery (the same delivery id) fires once.
- **Within limits.**
  - Intake allows each trigger 60 deliveries a minute (bursts of 20), and the node 600.
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
