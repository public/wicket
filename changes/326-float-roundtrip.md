---
area: Secrets
type: Fixed
---
- A number in JSON wicket reads (a secret link's `meta`, among others) is now parsed exactly, so it
  writes back as itself: some, such as `42e66`, were read a little off and drifted when written
  again. Found by the new `vault_ref` fuzz target ([#326](https://github.com/public/wicket/issues/326)).
