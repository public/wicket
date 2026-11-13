# Risk classes

Every request a box makes is normalised into an `Op` (method, host, canonical path) and given a risk
class (`crates/wicket-core/src/op.rs`, `classify`). The class decides whether reach alone can allow
it, and bounds what a grant covers.

| class | name in the ledger and in `wicket pending` | given to |
|---|---|---|
| R0 | `R0Read` | Nothing in 0.0.1: the lowest class `classify` gives is R1. |
| R1 | `R1ReadScoped` | `GET`, `HEAD` and `OPTIONS`; a git fetch (`POST …/git-upload-pack` on github.com). |
| R2 | `R2WriteReversible` | Every other method, unless a pattern below raises it. |
| R3 | `R3ExternalOrIrreversible` | Posting visible content on GitHub (below). |
| R4 | `R4ExecOrPrivilege` | Pushes, CI, merges, settings and access on GitHub; cloud APIs and metadata endpoints; every `SPAWN` beyond the parent's zone and every `UPDATE` request. |

## What the class does

- **Reach.** A request is allowed by a reach rule only if its class is R2 or lower, or the rule has
  `allow_dangerous: true`. An R3 or R4 request otherwise needs a grant, even inside reach.
- **Grants.** A grant covers nothing riskier than the request the human approved. Approving an R2
  prefix (`wicket approve --prefix`, or a `request_access` with `scope: prefix`) doesn't allow the R4
  operations under it.
- **Splice-through.** A host the list can rate R3 or higher (GitHub, `*.amazonaws.com`, metadata
  endpoints) is spliced through only if its wholesale rule has `allow_dangerous`.

## The dangerous-pattern list

The list is short and hand-maintained, and can only raise a class. GitHub paths are matched on their
segments, lowercased, after canonicalisation (no escaped unreserved characters, no `;`, no dot
segments), so a path is spelled one way.

| pattern id | host | matches | class |
|---|---|---|---|
| `gh.git_push` | `github.com` | a path ending `/git-receive-pack`; `…/info/refs` with any query but none or `service=git-upload-pack` | R4 |
| `gh.graphql` | `api.github.com`, R2+ | `/graphql` (wicket can't read the operation) | R4 |
| `gh.repo_settings` | `api.github.com`, R2+ | `/repos/{owner}/{repo}` itself | R4 |
| `gh.workflow_path` | `api.github.com`, R2+ | `/repos/{owner}/{repo}/contents/.github/…` | R4 |
| `gh.git_ref` | `api.github.com`, R2+ | `/repos/{owner}/{repo}/git/refs…` | R4 |
| `gh.exec` | `api.github.com`, R2+ | a segment `merge`, `merges`, `merge-upstream`, `dispatches`, `actions` or `deployments`; `/pulls/{n}/update-branch` | R4 |
| `gh.perm_manage` | `api.github.com`, R2+ | a segment `collaborators`, `invitations`, `keys`, `gpg_keys`, `ssh_signing_keys`, `hooks`, `secrets`, `variables`, `environments`, `protection`, `rulesets`, `transfer`, `members` or `memberships` | R4 |
| `gh.notify` | `api.github.com`, R2+ | a segment `comments`, `reviews` or `releases`; a path ending `/issues` or `/pulls` | R3 |
| `cloud` | `*.amazonaws.com`, `metadata.google.internal`, `169.254.169.254` | any | R4 |

"R2+" means the pattern is checked only for methods already R2 or higher, so reads of these paths
stay R1. Blobs, trees and commits made through the git data API stay R2: they do nothing until a
ref points at them.

## wicket's own requests

Some pending requests aren't HTTP. They use reserved methods on `wicket.internal`, which no box can
send itself:

| request | from | class |
|---|---|---|
| `SPAWN wicket.internal/zones/<zone>/<digest>` | `spawn` with `ask_human`, for a zone beyond the parent's | R4 |
| `LINK wicket.internal/links/<from run>/<to run>/<port>` | `connect` or `link` beyond the default policy | R2 |
| `CAPACITY wicket.internal/capacity/<lease>` | `request_capacity` | R2 |
| `UPDATE wicket.internal/self/<sha256>` | `request_update` | R4 |

Metadata endpoints and every non-public address are refused before any class is given: see
[concepts](../explanation/concepts.md#zones-and-the-subset-rule).
