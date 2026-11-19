---
area: Build and CI
type: Fixed
---
- The install test's container fetches its packages from the runner's own Ubuntu mirror, over IPv4
  ([#219](https://github.com/public/wicket/issues/219)). The mirror was found only when the
  runner's `ubuntu.sources` named one `http(s)://` URI, and only the archive stanza was moved to it,
  so apt fell back to archive and security.ubuntu.com, over IPv6 the runner can't route
  ("Network is unreachable"). It now reads every URI and follows a `mirror+file:` list, uses it for
  every stanza as plain http (the image has no CA certificates), and sets `Acquire::ForceIPv4`.
  `ci/install-test.sh --host-mirror [sources]` prints the mirror it would use.
