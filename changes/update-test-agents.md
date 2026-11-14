---
area: Updates
type: Fixed
---
- `ci/update.sh` no longer ends its long-lived agents' runs, or another test's boxes on the same Docker
  daemon, at its prune step. The agents now take a turn after the CI-signed updates too.
