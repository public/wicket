---
area: Manifests
type: Fixed
---
- A forbid rule's class with a range that crosses from letters to other characters, or between the
  cases (`[a-~]`, `[0-Z]`, `[A-z]`), now ignores case for the letters inside it, as forbid rules do
  everywhere else: `[a-~]` forbids `/B` as well as `/b`. Before, such a range kept its letters'
  case (forbidding less than written), and `[A-z]` didn't compile. A class that starts with a range
  from `-` or `]` (`[--a]`) keeps that range whole (#326).
