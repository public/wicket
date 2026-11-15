---
area: Secrets
type: Added
---
- `wicket secret serve`, the secret helper (#350): run as the owner of a file a secret is linked to
  (a systemd user unit: deploy/systemd-user/wicket-secret-helper.service), it serves that secret's current
  value and expiry to wicketd over a unix socket, and nothing else from the file. `wicket secret link
  --via-helper` links a secret through it, so an operator's Claude login needs no ACL for the
  `wicket` user, keeps working across Claude Code's refreshes, and its refresh token never leaves
  its owner. Both ends check the other's uid by `SO_PEERCRED`.
- A plain link to a file wicket can't read says to use the helper.
- The model proxy reads an unreadable model secret again for up to 3 seconds, then answers `503`
  naming the secret and the cause, instead of a bare `502 … Permission denied`.
- `wicket doctor` checks every linked secret: its helper is reachable and holds a current value, or
  its file is readable. See [store and link secrets](../docs/how-to/store-and-link-secrets.md#link-a-login-without-an-acl-the-secret-helper).
