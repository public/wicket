# The Lean spec of authority and matching (#322)

wicket's core security claim is that authority only narrows. This directory states it in Lean 4
for the code that decides it, proves it with no `sorry`, axiom or Mathlib, and runs the same
definitions as an oracle that wicket-core's decisions are checked against.

| File | Rust it restates | What is proved |
| --- | --- | --- |
| `Wicket/Glob.lean` | `manifest::compile_glob` (globset, `literal_separator`) | `segsB_iff`: the matcher is the declarative language `SegsM`; `no_globstar_same_slashes`: without `**` a match has as many `/` as the glob (`*` and `?` never cross one); `globstar_crosses`: `Q/**` matches everything under `Q/`; a forbid match ignoring case is a case-sensitive match of a same-case spelling |
| `Wicket/Host.lean` | `manifest::host_matches`, `subset::host_covers` | `hostCovers_sound` |
| `Wicket/Zone.lean` | `CompiledZone::evaluate` | `forbid_wins`: a matching forbid rule forbids, whatever the reach rules say; `forbid_any_case`; `evaluate_reach_set`: reach rules are a set; `allow_lower_risk` |
| `Wicket/Subset.lean` | `subset::check`, `reach_within`, `path_covered`, `segments_cover`, `segment_covers` | `pathCovered_sound`; `reach_sound` and `forbidden_sound`: an admitted child is allowed by reach nothing its parent isn't, and forbids all it forbids; `check_within`: an admitted child is `Within` its parent (reach, forbid, escalation, isolation, hidden hosts, wildcards, injections, model route, memory, cpus, output, pids, authority); `within_trans` and `grandchild_within`: narrowing composes |
| `Wicket/Canon.lean` | `canon::canonical_path`, `prefix_covers` | `upstream_eq`: an upstream that percent-decodes and resolves dot segments, in either order, names the canonical path's segments; `decode_eq_unreserved`: no escape spells an unreserved character; `reach_no_escape`, `forbid_no_escape`: a canonical path can't get out from under a rule `Q/**`; `prefixCovers_iff`: a prefix grant (#568) covers its directory and paths continuing it with `/`, never a sibling; `prefix_covers_segments`, `prefix_grant_is_globstar`: no wider than its directory and the rule `Q/**`; `prefix_no_escape`: a covered canonical path keeps the directory's segments as an upstream reads it |
| `Wicket/Spawn.lean` | `manifest::model_covers`, `LlmSpec::allows_model`, `subset::model_violations`, `manifest::accepts`, `Token::attenuate`, a node's spawn (`nodegw::spawn`: `plan_child`, `peek_spawn`, `derive_child`) | `check_models`: an admitted child calls no model its parent may not (for well-formed patterns, as manifests require); `accept_narrow`, `check_accepts`: it hears only from its parent's zone or a sender its parent hears from; `attenuate_allow`, `attenuate_forbid`, `attenuate_live`, `attenuate_spawns`: an appended spawn block never widens a token; `node_spawn_within`: a child its node starts is within its parent, and its token allows, outlives and starts nothing its parent's doesn't |
| `Wicket/Grant.lean` | `grant::within_authority`, `check_terms`, `agent_terms`, `outlasts`, `operators::may_decide` | `agent_grant_within`: every use an agent's grant permits is one the agent's own zone allows by reach, by a strict descendant, before the agent's authority ends, for one or more uses; `grant_within_ancestor`: and within every zone the agent's is within; `agent_renewal_within`; `operator_within` (#320) |
| `Wicket/Message.lean` | `message::relation` (#565), decided by the control host and by a node cut off from it | `peer_iff`: a message goes to a peer exactly when its receiver's `accept_from` names the sender's zone (a zone entry) or principal (a principal entry); `refused_iff`; `no_peer_without_accept_from`; `less_known_allows_no_more` and `less_known_same_relation`: a side that doesn't know the sender's principal refuses whatever one that knows it refuses, and otherwise decides the same relation (or sees an answer where the other sees a named peer) |

## What it doesn't cover

The proofs are about the Rust functions in the table, restated in Lean, and the oracle checks that
wicket-core decides as the spec does on its fixtures and generated cases. They don't cover:

- **The Biscuit evaluator** that decides requests on nodes (the vendored, patched `biscuit-auth`,
  its compiled evaluator and the structural check). It is tested, not proved:
  `crates/wicket-authz/tests/integration/oracles.rs` checks token decisions against wicket-core's
  `CompiledZone::evaluate` (single blocks and random chains), and the compiled evaluator against the
  fork's generic engine and its unpatched `AuthorizerBuilder` path. Nothing compares it with the
  upstream crate itself.
- **The Cedar compiler** (org and zone policies to token checks): differentially tested against
  Cedar's own evaluation, not proved.
- **How a token of blocks decides.** `Spawn.lean` models a token as its first-party blocks, deciding
  as their intersection (`chainVerdict`), and proves that an appended spawn block never widens it.
  That the Biscuit evaluator decides as `chainVerdict` is tested (the oracle's `chain` cases mint
  tokens and append spawn blocks), not proved. What each block allows a box to start (`peek_spawn`'s
  facts) is a predicate of the block.
- Everything else: the proxies, parsing, the ledger, the feed's signatures and the node's replica.

## What the spec takes as given

- **Pure inputs.** An op's risk (`classify`) and whether its host is never reachable
  (`never_reachable`, WHATWG host parsing) are carried on the op; wicket's reserved namespace and
  git pushes (`git::grant_terms`) are functions of the request. Each is the same for every zone and
  granter, so none changes which one allows more.
- **Parsed limits.** Byte sizes (`parse_bytes`) and durations come parsed; cpus is the `f32`'s exact
  value. Image admission (`image::matching`, by digest) is an input to `check`.
- **The glob language.** Literals, `*`, `?` and `**` segments. A glob with a class, an alternation
  or an escape is outside it, and the oracle answers `unsupported` rather than guess (the Rust check
  treats those conservatively: only the same text covers them). Two of globset's readings are part
  of the spec: it matches bytes (`?` is one byte of UTF-8), and a glob made only of `**` segments
  (`**/`, `**/**/`) matches everything.
- **Canonical paths.** The theorems that need them take an absolute path (`AbsPath`), as
  `canonical_path` guarantees. `canonicalPath` refuses what `check_plain` refuses, over UTF-8 bytes:
  besides backslashes, control characters, `;`, bad escapes and dot or empty segments, anything a
  URL parser would percent-encode on the way upstream (space, `"`, `#`, `<`, `>`, `?`, `` ` ``,
  `{`, `}`, and every byte of a non-ASCII character), which must come percent-encoded (#323).
  Refusing more keeps every theorem about canonical paths true: they assume `plainOk`.
- **The org layer** is a predicate. `within_authority` asks it at the request's risk;
  `agent_grant_org` extends that to every use only for an org layer that allows at a lower risk
  what it allows at a higher one. The token's org checks still apply at every use.
- **The ledger's identities** are a parent function. That an agent never decides its own request
  (`not_own`) needs them acyclic.

## Decisions in wicket-core's pure functions (`Wicket/Decisions.lean`)

The decisions #325 moved into pure functions for Kani, each defined as the Rust computes it, with
`Int` and `Nat` for its numbers (so no overflow: the Rust's exact sums are what the oracle holds it
to). Each Kani harness names its theorem here.

| Rust (wicket-core) | Lean | theorems |
|---|---|---|
| `op::is_public_ip`, the SSRF guard | `isPublic4`, `isPublic6`: outside `v4Blocks`, `v6Blocks` | `in_block_not_public4`, `in_block_not_public6`, `metadata_never_public` |
| `quota::not_after_for`, `token_secs`, `token_allows` (#342) | `notAfterFor`, `tokenSecs`, `tokenAllows` | `token_ends_at_ledger_ms`: for every end after the epoch and every reading, the token allows exactly while the ledger's grant is live |
| `authority::agent_term_refusal` | `agentTermRefusal` | `default_rules_refuse`, `each_rule_lifts_its_own` |
| `escalation::check_escalatable`, `needs_grant` | `checkEscalatable`, `refusalNeedsGrant` | `org_policy_never_escalatable`, `needs_grant_fail_closed` |
| `quota::take_use` | `takeUse` | `take_use_never_below_zero`, `take_use_refused_at_zero` |
| `quota::money_fits` | `moneyFits` | `money_fits_exactly` |
| `quota::SpawnLimits::admits` | `spawnAdmits` | `spawn_within_admitted` |

`metadata_never_public` is decided by evaluation, over concrete addresses (169.254.169.254 and
168.63.129.16, and the first behind IPv4-mapped, NAT64 and 6to4 forms). For every address, the
oracle compares the table with the Rust, and Kani compares it with the Rust over every address.

## Running it

`ci/lean.sh` installs the pinned toolchain (`lean-toolchain`, by URL and SHA-256), builds the spec
(a `sorry` fails it), then runs `crates/wicket-authz/tests/lean_oracle.rs`. That test is ignored by
default. It writes every case to a JSON file and runs `lake env lean --run Oracle.lean` on it, then
compares each decision with wicket-core's and fails on any difference, with the case. The cases are
the fixtures (the zones and probes of `oracles.rs`, and the parents and children of
`subset_cases.rs`), plus generated globs, paths, hosts, path spellings and parent/child zones, model
allowlists and `accept_from` lists (`check`, `allows_model`, `accepts`), and tokens of up to four
blocks, minted and attenuated by wicket-authz and decided by its evaluator (`chain`). Section 8 of the
test adds the pure decisions above: generated IPv4 and IPv6 addresses (biased to the special blocks
and the IPv4 forms), grant ends and clock readings around the boundary, every combination of
agents' rules and escalation classes, lists of failed checks, counted uses, money amounts at the
edges of `i64`, and spawn limits and asks. Section 10 adds the message rule (#565):
`message::relation` on generated family, reply, `accept_from` and senders.

In GitHub Actions, `ci/lean.sh` also turns the build's errors and the oracle's divergences into
annotations on the run, so they show in the pull request without its log.

With elan, `lake build` here builds the spec, and `LAKE=lake cargo test -p wicket-authz --test
lean_oracle -- --ignored` runs the oracle.
