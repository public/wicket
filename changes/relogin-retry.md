---
area: Secrets
type: Fixed
---
- A model call that races a login refresh no longer fails with `401 … token revoked`: when the
  upstream refuses the credential the model proxy sent, it reads the secret again (a node asks its
  control host for the current value) and, only if the value changed, sends the call once more with
  the new one. The retry is audited; an unchanged value is never resent, so a real revocation still
  reaches the box as the 401 ([#360](https://github.com/public/wicket/issues/360)).
