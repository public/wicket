---
area: Secrets
type: Fixed
---
- A model call that races a login refresh no longer ends the agent's turn
  ([#552](https://github.com/public/wicket/issues/552)). #360's retry after a 401 only ran on the
  model proxy's own route. A wrapped session's calls, such as Claude Code in a box, go through the
  egress gate, which swaps the credential in, and never had a retry. Their 401 went straight to the
  box, with nothing in the call's audit note.

  Both routes now retry. After a 401 the proxy reads the secret again for up to 10 s until it
  changes, then sends the call once more with the new value. The wait covers a refresh, which
  revokes the old token a moment before its owner writes the new one. A secret that stays the same
  (a real revocation) passes its 401 through, after those 10 s. Either way the call's `op` audit
  record now says what happened.
