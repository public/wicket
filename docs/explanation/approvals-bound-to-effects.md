# Approvals bound to their effect

An approval is the point where a person (or an agent with grant rights) widens what a box may do,
so it is where an attacker who can plant text in the box's context aims. Three things go wrong in
agent runtimes generally ([#369](https://github.com/public/wicket/issues/369)):

- **The approval is wider than what was looked at.** The agent asks for a broad rule, and once it is
  approved, everything under it happens without another question.
- **The arguments change after the approval.** The decision was on one call; a different call runs
  under it.
- **Siblings race past a pending decision.** While one branch waits for an answer, another runs an
  action the answer was meant to govern.

wicket binds each approval to one effect, shows what else a wide approval allows before it is made,
and holds related actions until the decision.

## The effect descriptor

Every request has an effect descriptor (`wicket_core::effect::Effect`), built from the ledger's
record of the request and, once decided, the terms it is decided with:

| field | what it is |
|---|---|
| `kind` | `access` (egress), or the reserved request kind: `spawn`, `link`, `capacity`, `update` |
| `tenant`, `zone`, `run` | who asks: the run is the principal's instance the grant is bound to |
| `requested_by` | the subagents that reportedly asked inside the box |
| `method`, `host`, `path`, `prefix` | the target: the canonical host and path, or the segment prefix a grant covers |
| `risk` | the risk class it was asked at, the riskiest the grant covers |
| `args_sha256` | the sha256 of the arguments the decision is on, for the kinds whose outcome depends on more than the target |
| `terms` | `uses`, `ttl_secs` and `scope` (`run` or `zone`), once decided |

Its canonical JSON has sorted keys and no whitespace, and its sha256 is what is signed:

- **`wicket approve`** prints the descriptor and its hash before it asks, and the approval is made
  only if the request is still that descriptor.
- **The console** signs the descriptor and its hash (`effect`, `effect_sha256`) with the passkey,
  in the same JSON as the rest of the decision.
- **An agent's `decide`** signs the hash into its decision envelope; the gateway lists the requests
  it may decide with each one's hash.

[`grant::decide`](one-decision-path.md) rebuilds the descriptor from the ledger when the decision is
recorded. If it differs from the one that was shown or signed (another asker joined the request,
its risk was rewritten, other terms were picked), the decision is refused and audited as
`decision.refused`. Otherwise the grant is made with the descriptor's hash (`grants.effect_sha256`)
and the arguments' hash (`grants.args_sha256`), and the decision record carries both.

What the arguments are, per kind:

| kind | target (the op's path) | arguments hashed |
|---|---|---|
| `spawn` | `/zones/<child zone>/<child name>` | name, kind, task, command, image, zone, reach hosts, children, placement |
| `link` | `/links/<from run>/<to run>/<port>` | the name the link is exposed under |
| `capacity` | `/capacity/<lease>` | the lease's provider, spec, hourly cap, reservation and duration |
| `update` | `/self/<sha256>` | the artifact's sha256 |

A grant for a reserved kind is used (`Ledger::use_effect_grant`) only:

- for exactly its target, never through a prefix grant;
- with exactly the arguments it was decided on. A call whose arguments changed after the approval
  is refused, and the refusal is audited as `effect.refused`, with both hashes;
- while it is live, checked when the action runs, not when it was decided;
- as many times as its uses allow. A call presented again after its last use finds it spent: a
  spawn says the child was already started, and nothing is asked again.

The reconciler provisions an approved capacity lease only while its grant is live and the lease is
still what was approved; otherwise it closes the lease as denied and audits `effect.refused`.

## The blast radius

An approval widens when it grants a prefix, more than one use (or unlimited uses), a lifetime over
an hour, or every run in the zone. Before such an approval, `wicket approve` and the console's
confirmation show:

- how it is wider than the one request;
- concrete requests it would also allow: ones this run made (from its audit trail), and example
  paths under the prefix;
- how many of the run's last 200 egress requests it would have covered;
- the zone's reach rules for the same host: what the run may already do there.

## Hold until decided

While a request from a run is pending:

- an ask for the same target with other arguments files nothing; the caller is told to wait for
  the pending request (`Filed::Held`);
- an egress request a pending prefix ask from the run covers gets that ask's id, not a request of
  its own, so it is decided by the same decision;
- an action for that target waits, even under a grant made earlier (`EffectUse::Held`). The spawn
  and link tools answer "waiting: request … is not decided yet".

Requests from other runs are not held: each run is its own principal's instance, and a child's
requests are filed under the child's run, not relayed as its parent's.

## The model

`verification/tla/ApprovalEffect.tla` checks these properties with TLC: hold until decided across
siblings, exactly once on replay, no action after a grant expires, identity kept across the
delegation hop, and arguments bound. Each has a `fail_effect_*` variant that turns its rule off,
and TLC must find the property broken there (see its [README](../../verification/tla/README.md)).
