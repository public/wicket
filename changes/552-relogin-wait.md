---
area: Secrets
type: Fixed
---
- A model call that races a login refresh no longer ends the agent's turn. A refresh revokes the
  old access token as soon as the new one is issued, and the login's owner writes the new one a
  moment later. Until now, the model proxy's single re-read after the 401 often still saw the old
  value, so the 401 went to the box, and Claude Code's own retries hit the same gap. Now the proxy
  reads the secret again for up to 10 s until it changes, then sends the call once more with the
  new value. This covers the first call and any client retry that arrives during the refresh. A
  secret that doesn't change (a real revocation) still passes its 401 through, now after those
  10 s ([#552](https://github.com/public/wicket/issues/552)).
