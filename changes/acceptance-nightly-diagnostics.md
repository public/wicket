---
area: Development
type: Fixed
---
- The nightly acceptance run now says what failed, even where its log can't be read. Its installed
  run passes `GITHUB_ACTIONS` into the container, so failed checks and wicketd's log become
  annotations. A command that aborts the script outside a check now names its line and command.
  The flows that ran for the first time on 2026-11-18 (wicketd's re-exec and restart, a self update
  over a run) and on 2026-11-19 (`install.sh` over a run) turn a failed setup step into a failed
  check instead of ending the run.
