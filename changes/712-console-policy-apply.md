---
area: Approvals and the console
type: Added
---
- The org policy can be applied from the console (#712). An operator pastes or uploads it and sees what
  applying it would do (`POST /api/policy/preview`): its version and the one it replaces, what it changes against the
  applied policy for each running zone and group (widens or narrows), the zones it doesn't mint for, and the
  running runs it would revoke. Applying it is a passkey-signed action on that
  preview, for an operator whose `operators.yaml` authority covers the new `policy` kind at R4. The decision
  is audited first (`policy.apply_decided`), then the console runs `wicket policy apply` with it, which
  applies only that preview, once. `wicket policy apply --dry-run` prints the same preview and changes
  nothing ([#712](https://github.com/public/wicket/issues/712)).
- `wicket policy apply` now revokes the runs minted under another version as they are once the new policy
  is installed, so a run started while the nodes were asked is revoked too, and records how each apply
  ends (`policy.apply_finished`, or `policy.apply_incomplete` after the policy was installed). One apply
  runs at a time ([#712](https://github.com/public/wicket/issues/712)).
