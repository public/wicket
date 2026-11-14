---
area: Secrets
type: Fixed
---
- The vault accepts a secret file, or a file a secret links to, that a POSIX ACL shares read-only
  with the user wicket runs as alone (`setfacl -m u:wicket:r ~/.claude/.credentials.json`), instead
  of refusing it for the ACL mask in its group bits. A file anyone else can read is still refused,
  and the error now says who. See [secrets](../docs/reference/secrets.md).
