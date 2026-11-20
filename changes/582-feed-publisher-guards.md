---
area: Operations and audit
type: Fixed
---
- A node's feed on the control host fails closed in more cases ([#582](https://github.com/public/wicket/issues/582), step 3).
  - A publisher that is behind the delta log, or whose log was set aside for a new generation,
    refuses to commit, to serve a catch-up and to sign a statement until it catches up.
  - A run that panicked holding the feed has it opened again from its files before anything is
    published. If that fails, the next use tries again rather than trusting the publisher.
  - A certificate renewal that fails is logged, and the commit or revocation it came with is still
    published with the current certificate.
  - Opening one node's feed no longer holds up runs opening another node's.
