---
area: Operations and audit
type: Fixed
---
- Model calls from a driven Remote Control box no longer fail with 400. Claude Code sends a
  `diagnostics` field there (`{"previous_message_id": …}`, with the `cache-diagnosis-2026-04-07`
  beta) so the provider can explain prompt-cache misses. It only names an earlier message of the
  same conversation and runs nothing on the provider's side, so the model gate now forwards it
  ([#307](https://github.com/public/wicket/issues/307)).
