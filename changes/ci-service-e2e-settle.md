---
area: Development
type: Fixed
---
- The gVisor smoke test's npm-cache check no longer fails at random: it counts only the cache's own
  upstream requests for left-pad, and reads the count once box A's tarball fetch is in the
  service's log and the count has stopped changing, so a log line written late is no longer taken
  for box B going to the registry again.
