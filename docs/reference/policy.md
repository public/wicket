# Policy in Cedar

The human-authored layers of policy are [Cedar](https://www.cedarpolicy.com): the installation's
**org policy**, a ceiling and forbids over every zone, and each **zone's policy**, generated from its
manifest. They are reviewed as Cedar, analysed with SymCC in CI, and compiled into each box's Biscuit
token when it is minted. Nodes evaluate the token only: no Cedar engine runs at the edge (#51,
design §5).

## The decision

A request is allowed when:
- the **org policy** allows it (no org policy: nothing to check);
- the **zone's policy** allows it, or a grant does;
- **no forbid** in either matches it.

**Where it's enforced.** The org layer is enforced at every point that decides:
- **On a node**, the box's token decides egress. Under an org policy a node splices a host through
  (without inspecting it, #144) only if the org layer allows that host wholesale: no forbid can match
  it, and no permit conditions it on a method, path or risk. Its probes can't vouch for a path rule.
- **On the control host**, the same compiled layer is checked by:
  - the egress proxy, for hosts the node forwards (credentialed ones) and local boxes;
  - injections, before a credential goes in;
  - `spawn`, before a child starts;
  - message delivery, at the receiving box: a message from a zone or principal it doesn't accept is
    dropped, and the agent told.

The two layers are separate Cedar policy sets, evaluated separately. Merged into one set, an org
permit would OR with the zone's permits and widen every zone. A grant lifts the zone layer only: the
org ceiling is hard, and a forbid beats every grant.

## The schema

Every policy is validated strictly against this schema (`crates/wicket-policy/src/schema.rs`).
Strict validation is what keeps a policy from erroring at evaluation: Cedar skips a policy whose
condition errors, and for a forbid that would fail open.

| | Principal | Resource | Context |
|---|---|---|---|
| `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` | `Box` | `Url`: `host`, `path`, `path_matches`, `path_matches_any_case` | `risk` (0–4) |
| `spawn` | `Box` | `Image` | `isolation`, `memory`, `cpus_milli`, `pids`, `timeout_s` |
| `message` | `Box` | `Zone` (the sender's) | `sender` (its principal id, `spiffe://…`; `""` if unknown) |
| `inject` | `Box` | `Secret` | `host`, `header` |

- A `Box` has `zone`, `tenant`, `principal` (`<type>:<id>` of who it acts for) and `depth` (spawn
  links above it). It is in its `Zone`, which may be in `Group`s (`org-entities.json`).
- `resource.path_matches` holds the wicket path globs the path matches (`*` within a segment, `**`
  across): write `resource.path_matches.contains("/repos/acme/**")`.
- `path_matches_any_case` is the same, ignoring ASCII case, as zone forbids do.
- `resource.path like "…"` is Cedar's own wildcard, where `*` crosses `/`.

## What compiles

Conditions on the **principal** (its attributes, `principal in Group::"…"`, `principal in
Zone::"…"`) are decided when the token is minted, and gone from the token. Conditions on the
**request** must map onto what a node checks:
- **Hosts:** `resource.host == "h"`, `!= "h"`, or `like "*.suffix"`.
- **Paths:** `resource.path_matches.contains(…)`, `path_matches_any_case.contains(…)`, or
  `resource.path like "…"`.
- **Integers:** `context.risk` compared with an integer; for a spawn, `context.isolation >= n` and
  `context.memory`/`cpus_milli`/`pids`/`timeout_s <= n`.
- **Names:** images, sending zones and secrets, by `resource ==` or `resource in [...]`. An `inject`
  permit names its secret, `context.host` and `context.header` exactly.
- **Senders:** a `message` permit names the sender's zone (`resource in [Zone::"ops"]`) or its
  principal id (`context.sender == "spiffe://…"`, or `["spiffe://…", …].contains(context.sender)`),
  not both in one conjunction. A zone's `accept_from` reads the same way: a zone entry matches the
  sender's zone, a principal entry (one with `://`) its id, so a zone's policy says
  `permit(principal, action == Action::"message", resource) when { resource in [Zone::"ops"] ||
  ["spiffe://…/a/auditor"].contains(context.sender) };`.

`&&`, `||`, `!` and `unless` combine them. Anything else is a compile error that names the construct:
- a negated path or image;
- a wildcard inside a host;
- `has`, `if`, extension functions;
- templates;
- a forbid on `spawn`, `message` or `inject` (write a narrower permit);
- a negated `context.sender`, a sender that isn't a principal's id, or a `Zone` named like one;
- naming a `Box`.

Permits become a check's alternatives (a first-party Biscuit block can't hold rules), and forbids
`reject if` checks. Each token records the org policy's version.

## The org policy

`<data dir>/policy/org.cedar` (`/var/lib/wicket/policy/org.cedar` installed), with
`org-entities.json` beside it. For example:

```cedar
// Every zone may do what its own policy says, within this (spawns are narrowed below).
permit(principal, action in [Action::"GET", Action::"HEAD", Action::"POST", Action::"PUT", Action::"PATCH",
  Action::"DELETE", Action::"OPTIONS", Action::"message", Action::"inject"], resource);

// Nobody deletes on production, and nothing reaches the metadata service.
forbid(principal, action in [Action::"DELETE"], resource) when { resource.host == "prod.example.com" };
forbid(principal, action in [Action::"GET", Action::"POST"], resource) when { resource.host == "metadata.google.internal" };

// Development zones never write to the main repository.
forbid(principal in Group::"dev", action in [Action::"PUT", Action::"POST", Action::"PATCH", Action::"DELETE"], resource)
  when { resource.host == "api.github.com" && resource.path_matches.contains("/repos/acme/main/**") };

// Children spawned by agents stay on gVisor and under 2 GiB.
permit(principal, action == Action::"spawn", resource) when { context.isolation >= 2 && context.memory <= 2147483648 };
```

The first `permit` keeps the org policy a ceiling over what zones say, rather than the only thing
allowed. Cedar denies by default, so an action no permit covers is never allowed. It ORs permits too:
a `permit(principal, action, resource)` here would make the spawn rule below it moot.

```
wicket policy check org.cedar --entities org-entities.json   # validate and compile, change nothing
wicket policy apply org.cedar --entities org-entities.json --dry-run   # what it would do, change nothing
wicket policy apply org.cedar --entities org-entities.json   # install it
wicket policy show                                           # its version, runs minted under another
wicket policy zone manifest.yaml                             # a zone's own policy, as Cedar
```

**Applying a version.**
- **Checks before anything changes:**
  - the policy must compile and mint a token a node loads, for every running run's zone, as a member
    of no group, of every group and of each group alone (the node's caps on alternatives, regexes and
    token size show here);
  - every active node must answer (a node that does talks a protocol that reads tokens with an org
    layer). `apply` names the nodes that can't be asked.
- `apply` keeps every version under `policy/versions/<version>.cedar` and records `policy.applied`
  in the audit log.
- It records the installed version in `policy/installed`. A missing `org.cedar`, or one changed by
  hand, then refuses every mint until it's applied: a deleted file mustn't silently remove the
  ceiling.
- A re-attached run is minted again under the version it was first minted under (kept in
  `versions/`).
- The recovery kit (`wicket state kit`) carries `policy/`.
- It revokes the running runs minted under an older version, as they are once it is installed (a
  run started while the nodes were asked is one of them): their boxes stop, and their tokens are
  revoked on their nodes. `--keep-runs` leaves them on the policy they were minted under until they
  end. One apply runs at a time (`policy/apply.lock`), from the last check to the last revocation, and
  ends with `policy.apply_finished` (what it revoked, and any beyond what its preview listed). A
  failure after the policy was installed is `policy.apply_incomplete`, never "nothing changed".
- A run's version is in the ledger, and in its token's `policy` fact.
- `--dry-run` changes nothing. It prints:
  - the version, the one it replaces, and the sha256 of its Cedar text and of its entities;
  - what it changes against the applied policy, from the layers each compiles to: for each running
    zone (with its groups under the old entities and the new, so moving a zone into a group shows),
    for a zone in each group alone (the first 32 groups) and for a zone in no group. Each change is
    a permit, forbid, spawn, message or injection rule added or removed, marked as widening (`+`)
    or narrowing (`-`). An added alternative reads as widening even where another covered it. With
    no policy applied, every constraint narrows;
  - what it couldn't compare (a running zone whose record can't be read, groups over the cap, an
    applied policy that doesn't parse), never skipped silently;
  - the zones it doesn't mint for, the running runs it would revoke (or keep, with `--keep-runs`),
    and the effect's sha256, over all of that: what the console signs.

  It compares compiled layers, which are what tokens enforce. The SymCC check CI runs on policy
  changes (below) is not run here.

**From the console** (#712). An operator pastes or uploads a policy and its entities and sees the
same preview (`POST /api/policy/preview`; the policy and its entities at most 60 KiB together, the
console's request limit; apply a larger one on the host). Applying it is a passkey-signed action
(`policy_apply`, with a reason) on that preview, allowed to an operator whose `operators.yaml`
authority covers `policy` at R4. The decision is audited first (`policy.apply_decided`, with the
preview's changes and the sha256 of the Cedar and entities). Then the console runs `wicket policy apply`
itself on the policy it staged under `policy/staged/`, with the decision's sequence. That apply
asks every node as root's does, and applies only if the decision is under 10 minutes old, unused,
its Cedar and entities are the ones signed, and its effect is still what was signed: no run started
or ended in between, and no other apply came first. `policy.applied` then names the decision and the
passkey; a failure before anything is installed is `policy.apply_failed`. Its output is in
`policy/apply-<seq>.log`, and its staged files are removed when it ends.

## SymCC in CI

`wicket-policy-diff OLD.cedar NEW.cedar` asks SymCC (with cvc5 1.3.1, a per-query time limit) whether
the new policy allows anything the old one doesn't, action by action. It exits 0 if it narrows or
keeps, and 1 if it widens, printing a counterexample request. A timeout, an `unknown` or a solver
error exits 2, a failure: never a pass. `ci/policy-diff.sh` runs it in CI:
- on the policies in `examples/policy/` a pull request changes;
- on its fixtures, known narrowings and widenings.

Path globs are opaque to the solver (a set it knows nothing more about), so a changed glob reads as
"may widen" even where it narrows; hosts, methods, risk, images, zones and groups are exact.

## Not policy

Model budgets, grant use counts and output limits are leased counters, not policy: they stay
outside Cedar.
