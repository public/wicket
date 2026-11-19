---
area: Updates
type: Fixed
---
- `sudo wicket self trust-key KEY` and `sudo wicket self update ARTIFACT` work with files only root
  can read (in `/root`, say). Both run in wicketd, as the `wicket` user, which read the paths
  itself and failed with "Permission denied". The CLI now sends the key, the build and its
  signature to wicketd as content, as it already did for a run's manifest and workdir, and the
  command runs on wicketd's staged copies. Root still makes its own copy of the build from the
  path it named (only from an artifact the `wicket` user can't write).
