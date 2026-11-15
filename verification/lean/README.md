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
| `Wicket/Canon.lean` | `canon::canonical_path` | `upstream_eq`: an upstream that percent-decodes and resolves dot segments, in either order, names the canonical path's segments; `decode_eq_unreserved`: no escape spells an unreserved character; `reach_no_escape`, `forbid_no_escape`: a canonical path can't get out from under a rule `Q/**` |
| `Wicket/Grant.lean` | `grant::within_authority`, `check_terms`, `agent_terms`, `outlasts`, `operators::may_decide` | `agent_grant_within`: every use an agent's grant permits is one the agent's own zone allows by reach, by a strict descendant, before the agent's authority ends, for one or more uses; `grant_within_ancestor`: and within every zone the agent's is within; `agent_renewal_within`; `operator_within` (#320) |

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

## Running it

`ci/lean.sh` installs the pinned toolchain (`lean-toolchain`, by URL and SHA-256), builds the spec
(a `sorry` fails it), then runs `crates/wicket-authz/tests/lean_oracle.rs`. That test is ignored by
default. It writes every case to a JSON file and runs `lake env lean --run Oracle.lean` on it, then
compares each decision with wicket-core's and fails on any difference, with the case. The cases are
the fixtures (the zones and probes of `oracles.rs`, and the parents and children of
`subset_cases.rs`), plus generated globs, paths, hosts, path spellings and parent/child zones.

With elan, `lake build` here builds the spec, and `LAKE=lake cargo test -p wicket-authz --test
lean_oracle -- --ignored` runs the oracle.
