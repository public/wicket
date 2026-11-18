---
area: Updates
type: Added
---
- When root's link (`/usr/local/bin/wicket`) runs a different build from the one wicket's services
  run, as after an update applied from the console, every command it runs prints one line on
  stderr. The line says which build each runs, and how to catch up: `sudo wicket self update
  <artifact>` or `deploy/install.sh`. `wicket doctor` says so too
  ([#465](https://github.com/public/wicket/issues/465)).
