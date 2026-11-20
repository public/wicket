---
area: Console
type: Added
---
- The console's **Fenced runs** card lists runs whose box may still be running on a node that
  hasn't confirmed it stopped, with the node, when the fence ends and why. An operator whose
  authority in `operators.yaml` covers the new `fence` kind at R4 releases one with a passkey and a
  reason, on the fence as shown, instead of as root with `wicket node release-fence`
  ([#690](https://github.com/public/wicket/issues/690)). It is audited as `run.fence_released` with
  the operator's identity, and a refusal as `decision.refused`.
