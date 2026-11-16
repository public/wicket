---
area: Approvals and the console
type: Added
---
- Approvals are bound to their effect ([#369](https://github.com/public/wicket/issues/369)). Every
  request has an effect descriptor: who asks, the target (method, canonical host, path or prefix),
  its risk, the grant's terms, and for spawn, link, capacity and update the sha256 of the arguments
  decided on. `wicket approve` prints it, the console's passkey signs it (`effect`, `effect_sha256`
  in the signed decision), and an agent's `decide` names the `effect` `pending_requests` listed and
  signs the hash of the one it grants. The decision is made only if
  the request is still that effect when it is recorded; otherwise it is refused and audited as
  `decision.refused`. The grant records the descriptor's and the arguments' hashes.
- A grant for a spawn, link, capacity lease or update is used only for exactly its target and
  arguments: never through a prefix grant, and a call whose arguments changed after the approval is
  refused and audited as `effect.refused`. A spawn's target is now `/zones/<zone>/<name>`, not a
  digest prefix. An approved spawn starts one child: calling again after it started asks again. A
  denial refuses only the arguments it was made on. The reconciler provisions an approved capacity lease only while its grant is
  live and the lease is still what was approved.
- Before an approval that widens (a prefix, more than one use, a lifetime over an hour, or
  zone-wide), `wicket approve` and the console's confirmation show its blast radius: how it is
  wider, concrete requests it would also allow (ones the run made, and examples under the prefix),
  how many of the run's last 200 egress requests it would have covered, and the zone's reach rules
  for that host.
- While a request is pending, related asks from the same run wait on it instead of filing their
  own: the same target with other arguments, or an egress request under a pending prefix ask, is
  answered with the pending request. A granted spawn or link waits while another request for it is
  pending.
- Ledger schema 8 (expand) adds `requests.args_sha256`, `grants.args_sha256`,
  `grants.effect_sha256`, and indexes on `audit (run, seq)` and `requests (run, status)`.
- `verification/tla/ApprovalEffect.tla` models these rules for TLC: hold until decided across
  siblings, exactly once on replay, no action after a grant expires, and identity kept across a
  delegation hop, each with a must-fail variant. `ci/tla.sh` picks a variant's model from its
  `\* model:` line.
