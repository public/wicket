---
area: Approvals and the console
type: Added
---
- The console has a *Secrets* section: every secret in the vault by name, its kind (a stored value
  or a reference to a file on the host), the hosts it may be sent to, when it was last set, and the
  zones (each injection's host, header and format) and running runs that use it, never its value or
  anything derived from one. Names the manifests use that aren't stored are listed too. Storing or
  replacing a value (`set_secret`), changing a secret's hosts (`secret_hosts`) and deleting it
  (`delete_secret`) are passkey-signed actions, checked again when applied and audited by name as
  `secret.set`, `secret.hosts` and `secret.removed`. A value is typed into a password field that
  is cleared on submit. The passkey signs a salted sha256 of it, and the value itself goes only with
  the action's `finish`, so it is never in a pending challenge, a response, a log or the audit. The
  server zeroizes it once stored. Delete first lists the zones and runs that use the secret.
  Unsigned changes (`POST /api/secrets/…`) are refused and audited as `secret.refused`. Making a
  reference stays CLI-only (`wicket secret link`, which names a path on the host). See
  [secrets](../docs/reference/console.md#secrets) and [store and link
  secrets](../docs/how-to/store-and-link-secrets.md#from-the-console).
