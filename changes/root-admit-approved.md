---
area: Updates
type: Added
---
- An update applied from the console now also moves root's copy of wicket and
  `/usr/local/bin/wicket`. This takes `sudo wicket self trust-operator <name>` once per passkey.
  The new root unit `wicket-admit.path` then runs `wicket self admit-approved`. It copies a queued
  build only if a passkey in root's own list (`/etc/wicket/update-approvers/`) signed the approval
  of exactly its sha256. `deploy/install.sh` installs and enables it. On a host already installed,
  apply the new units once (`sudo /usr/local/lib/wicket/<id>/wicket self apply-units`, as a refused
  update says) and `systemctl enable --now wicket-admit.path`
  ([#261](https://github.com/public/wicket/issues/261)).
