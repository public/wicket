---
area: Console
type: Added
---
- The console's **Fenced runs** card lists runs whose box may still be running on a node that
  can never end its fence (revoked or no longer enrolled), with the node, when it last reported,
  when the fence ends and why. An operator whose authority in `operators.yaml` covers the
  new `fence` kind at R4 releases one with a passkey and a reason, on the fence as shown, instead of
  as root with `wicket node release-fence` ([#690](https://github.com/public/wicket/issues/690)).
  An enrolled node's boxes are never released there (revoke the node first). Both paths write the same `run.fence_released`
  record, with the decider's identity; a refusal is audited as `decision.refused`.
