---
area: Updates
type: Fixed
---
- After a self-update, a node keeps using the secrets its old `serve` handed to the new one through a
  memfd, and fetches none again. Since #415, every new connection to a node revoked every secret
  released to its runs, so the node dropped the cache it had just been handed and fetched each secret
  again. Now a connection sends again only the revokes that may have been lost on a link that died,
  and checks at once for secrets that changed meanwhile. A supervisor that takes a run over reads each
  secret's digest from the run's holdings, so it revokes only what changed
  ([#818](https://github.com/public/wicket/issues/818)).
