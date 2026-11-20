# Webhook intake for triggers

Design note for [#578](https://github.com/public/wicket/issues/578) step 4: triggers fired by
webhooks, generic and GitHub's. It settles the question the triggers design left open: where intake
terminates. It was written before the code, and the code follows it.

## The question

The triggers design put intake at the edge, like the proxies, and left its default place to decide:
the control host beside the console, or a node. The control host only issues authority and takes
approvals. A webhook endpoint is unauthenticated internet traffic until its signature is checked,
from senders wicket doesn't control, at rates it doesn't choose. Three places were possible.

| | On the control host (wicketd or the console) | Inside `wicket node serve` | A small service of its own, on a node |
|---|---|---|---|
| Inbound internet on the machine that holds the ledger, the vault and the roots | yes | no | no |
| Parsing hostile HTTP in a process that holds every box's secrets and relays | yes (wicketd) | yes | no |
| Identity, enrolment and a channel to the control host | needs none | the node's | the node's, through its `node serve` |
| What it can do if it's compromised | everything the control host can | everything a node can | fire its own triggers with forged deliveries, within their owners' authority and limits |

**The choice: intake is its own small service, `wicket node intake`, that runs on an enrolled node,
beside that node's `wicket node serve`.**

- It holds no ledger, no vault, no authority and no files. It has a listener, the table of triggers
  it serves, and a unix socket to its `node serve`.
- The control host never terminates a webhook. A single-machine installation can still put intake on
  its local node, but has to choose to.
- The node keeps what intake hands it in a bounded spool. The control host pulls the spool over the
  node channel, as it already does everything else (it dials nodes; nodes never dial it).

## How it works

```
GitHub / a sender ──HTTPS──▶ wicket node intake ──unix socket──▶ wicket node serve ◀──node channel (pull)── control host
   POST /hook/<trigger>/<token>   token, signature, normalise        spool (bounded)        IntakeSync, protocol 21
```

### 1. Creating a webhook trigger

- `wicket trigger create` with a `webhook` or `github` source names an **intake node**: a node
  labelled `wicket.intake=true` (`wicket node set <node> --label wicket.intake=true`). With one such node it is chosen; with several,
  `--intake-node` picks.
- **Protocol 21.** The node must talk protocol 21 or later, as last noted (#691's notes). Otherwise
  the trigger is refused, saying so.
- **The URL's token.** Create mints a random 32-byte token for the trigger. It shows the URL once,
  `https://<intake host>/hook/<trigger id>/<token>`, and keeps only the token's sha256 (ledger schema
  35, `trigger_intake`). A trigger's URL can't be guessed from its id. A lost token is replaced with
  `wicket trigger rotate-url`, which makes a new one.
- **The `verify` binding.** The trigger's `verify.hmac_sha256` names a vault secret that must have
  that binding. It is new, set with `wicket secret verify <name>`:
  - a `verify` secret is bound to no host;
  - `wicket secret hosts` refuses to bind one, and an injection, a credential swap or the model proxy
    can't read it (their `get_for` refuses a secret with no hosts, as it always has);
  - binding hosts to a secret makes it no longer a verify secret, and the reverse is refused while it
    has hosts.
- **Approval, as before.** An operator's trigger is the operator's own decision, audited
  (`trigger.created`, naming the intake node).

### 2. Intake

`wicket node intake --listen <addr> [--tls-cert <pem> --tls-key <pem>]`, a user service of the
wicket user on the node (`wicket-intake`), like `wicket node serve`.

- **What it knows.** Every 10 s it asks `node serve`, over `<node dir>/intake.sock`, for the triggers
  it serves: each one's id, its kind (`webhook` or `github`), the token's sha256, the verify secret,
  and for GitHub its repository and events.
  - `node serve` holds that table in memory only, as the control host last sent it (§3). After a
    `node serve` restart the table is empty until the next pull, and intake answers 503 meanwhile.
  - Secrets reach the node as they do today for boxes (#152): over the authenticated channel, held
    in memory, never written to disk.
- **One delivery.** It accepts only `POST /hook/<trigger>/<token>`, and checks, in order:
  1. the path's shape;
  2. a body of at most 1 MiB (413 past it, read no further);
  3. the trigger is served here, and the token's sha256 matches (constant time; 404 otherwise, the
     same answer as for an unknown trigger);
  4. the trigger's rate (a token bucket: 60 a minute, a burst of 20; 429 past it);
  5. the signature: HMAC-SHA256 of the raw body under the verify secret, compared in constant time
     (401 otherwise);
     - GitHub's `X-Hub-Signature-256: sha256=<hex>`;
     - a generic webhook's `X-Wicket-Signature-256: sha256=<hex>`, the same scheme;
  6. for GitHub: the `X-GitHub-Event` is one the trigger listens to and the payload's
     `repository.full_name` is its repository. Others are answered 202 and dropped, so GitHub doesn't
     retry what wicket will never fire on.
- **No echoes.** It answers with a status and a fixed word, never the payload. It logs refusals
  (counted, rate-limited), never bodies.
- **Normalising.** It turns a verified delivery into an **event**, `{trigger, source, kind,
  delivery, received_at, fields, raw_sha256}`. `fields` is the only part of the body that goes
  further (§4).
- **Spooling.** It hands the event to `node serve`, which writes it to `<node dir>/intake/spool/`
  (atomically, synced), then answers 202.
  - The spool is bounded: 10,000 events or 64 MiB. Past that, intake answers 503 and the sender
    retries later.
  - An event older than 24 h is dropped from the spool, counted.

### 3. The hand-off: protocol 21

- **`IntakeSync { id, triggers, ack }`** (control host to node), answered with **`IntakeEvents { id,
  events, rejected }`**.
  - `triggers` is the whole table the node's intake serves, replacing the last one.
  - `ack` lists the events the control host has recorded, which the node deletes from its spool.
  - The answer carries at most 500 events (or 4 MiB), oldest first, and the counts of refusals since
    the last sync.
- **Who sends it.** The reconciler's trigger pass, every pass (`--every 1m`, so a delivery fires
  within about a minute), for each node labelled for intake:
  - it syncs and records what comes back;
  - then it syncs again with the acks, until the spool is empty or the pass's cap (2,000 events a
    node) is reached.
- **Delivery is at least once.** An event the control host recorded but didn't ack comes again. The
  ledger records an event once per `(source, delivery)` (`trigger_events`, as for every source), so
  it fires once.

### 4. From event to firing

- **Only its own trigger.** A delivery fires only the trigger its URL names. It's checked against
  that trigger again on the control host:
  - it exists and is active;
  - it is a webhook or GitHub trigger served by the node that sent the event;
  - the event's tenant is the trigger's.
- **Fields are attacker-written.** The sender writes every byte, verified or not. A verified
  signature says the sender had the secret, not that the content is safe.
  - **A generic webhook's fields:** the top-level scalars of a JSON object body: at most 32 keys
    (`[a-z0-9_.-]`, 64 bytes), each value at most 512 bytes. A body that isn't a JSON object gives no
    fields, only its sha256 and length.
  - **GitHub's fields:** a fixed list per event: the repository, the action, the sender, the branch,
    labels (at most 20), the pull request's number, author, title and URL, the check's name,
    conclusion and URL, the issue's or comment's number and URL. Each string is capped at 256 bytes.
  - **Both:** control characters are stripped (`text::strip`) on the node, and again on the control
    host. The raw body is never kept, only its sha256.
  - Templates put fields into a task or a message as a **quoted block marked as event input**
    (step 2's rule): never into a manifest's fields, the zone, reach, secrets or limits.
- **The owner's authority, never more.** The firing goes through the same path as a schedule's:
  - the owner is checked again when it fires (`OwnerCheck`): a definite no pauses the trigger, and
    an owner who can't be checked holds its events until it can;
  - the action runs as the owner, and its identity chain says `owner → trigger:<id>`.
- **Limits and audit, bounded.**
  - `per_hour` counts every firing. Over it, one `trigger.skipped` record an hour counts the rest, as
    for schedules. After 5 failures in a row the trigger is paused.
  - A delivery the filter doesn't admit is recorded as an event, not audited. Events are pruned
    after 14 days.
  - A node's refusals (bad tokens, signatures, rates) come back as counts, audited at most once an
    hour per node (`trigger.intake_refused`).
- **No catch-up storms.**
  - An event older than the cutoff (15 minutes, `EVENT_STALE_SECS`) when the control host reads it is
    recorded and passed over, counted once a pass.
  - A trigger that was paused fires nothing for what arrived meanwhile.
  - The pass's per-node cap and the spool's bound mean a long outage comes back as a bounded backlog,
    most of it passed over as stale.

## What it doesn't do yet

- **Latency is the reconciler's interval.** It's about a minute. A standing link per node, which
  #582 step 5's node links would give, can push instead.
- **ACME.** Intake takes a certificate and key from files, or listens without TLS behind a reverse
  proxy that has them. It doesn't get its own certificate.
- **Routing** (`claim_work`, `owner_of`), `start`, debounce, concurrency, the queue, retries and
  dead letters are step 5. Until then a webhook trigger may `wake` or `message`, like the others.
- **Polling GitHub** for installations with no inbound path is step 8.
