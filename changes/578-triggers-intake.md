---
area: Long-lived agents
type: Added
---
- Webhook and GitHub triggers ([#578](https://github.com/public/wicket/issues/578) step 4). A
  `webhook` or `github` trigger wakes or messages an agent when a signed delivery arrives at its own
  URL, with its owner's authority and never more.
  - **Where deliveries arrive.** `wicket node intake`, a small service on a node you label
    `wicket.intake=true`, takes deliveries, never the control host.
    - It runs as its own user (`deploy/node/wicket-intake.service`, hardened), and reaches the
      node's `wicket node serve` only through a socket checked by peer uid.
    - It holds no ledger, no vault and no authority: only its triggers' URL token hashes and verify
      secrets, in memory.
    - It is bounded as the console's server is (connections, addresses, header and body timeouts),
      and checks the URL's token before it reads a body.
    - It checks each delivery's signature (HMAC-SHA256: GitHub's `X-Hub-Signature-256`, or
      `X-Wicket-Signature-256` over a timestamp, the delivery id and the body), and for GitHub the
      event and repository.
    - It hands what it verified to `wicket node serve`, which spools it.
    - The control host's own machine takes intake only with `--allow-local-intake`.
  - **Collected each reconcile pass** over the node channel (protocol 21), and fired once per
    delivery id.
  - **Fields, not the body.** A delivery is a short list of fields, capped and stripped of control
    characters, quoted to the agent as event input. Its raw body is kept only as a sha256.
  - **Verify secrets.** `wicket secret verify <name>` makes a vault secret a webhook's HMAC key. It
    is sent to no host, and can't be bound to one.
  - **Its URL.** `wicket trigger create` shows a trigger's URL once (`--intake-node` picks among
    several intake nodes). `wicket trigger rotate-url` replaces it.
  - **Limits.**
    - Only verified deliveries count against a trigger's 60 a minute and the node's 600.
    - An address that keeps failing is slowed down.
    - The trigger's `per_hour` still holds, counted on the control host's clock.
    - A delivery read more than 15 minutes late is passed over.
    - The same body under a new delivery id fires once.
    - Refusals are audited at most once an hour per node.
  - **Protocol 21.** wicket now speaks protocol 21 with a skew of 2: nodes at 17 or 18 must be
    updated with or before their control host. Ledger schema 35 adds `trigger_intake`.
  - [Fire a trigger from a webhook](../docs/how-to/trigger-from-a-webhook.md),
    [webhook intake](../docs/explanation/trigger-intake.md).
