---
area: Remote nodes and capacity
type: Fixed
---
- On a node, a wrapped or remote session's swap value is now kept for its own run only. Two such runs
  on one node shared the cache entry named after the swap's index, so one run's first use replaced the
  value, and the other run's requests could carry that run's credential. Vault secrets are still kept
  once for every run that uses them ([#773](https://github.com/public/wicket/issues/773)).
