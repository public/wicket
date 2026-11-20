---
area: Operations and audit
type: Fixed
---
- A node's feed on the control host fails closed in more cases ([#582](https://github.com/public/wicket/issues/582), step 3).
  - A publisher that is behind the delta log, or whose log was set aside for a new generation,
    refuses to commit, to serve a catch-up and to sign a statement on its timer until it catches
    up. `statement` and `snapshot`, which other callers use directly, are documented as for a
    current publisher.
  - A run that panicked holding the feed has it opened again from its files before anything is
    published. If that fails, the next use tries again rather than trusting the publisher.
  - A certificate renewal that fails is logged, and the commit or revocation it came with is still
    published with the current certificate, while that certificate is valid and the one on disk
    is of the same version (one missing or unreadable is not); otherwise the lock fails.
  - A statement tick that can't take the feed is logged, at most once a minute.
  - `wicket keys certify` starting a new generation takes the node feed's lock first.
  - Opening one node's feed no longer holds up runs opening another node's.
