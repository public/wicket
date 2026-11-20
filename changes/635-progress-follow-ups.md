---
area: Approvals and the console
type: Fixed
---
- The console's state store rows say when they may be out of date: after 30 seconds without a
  successful read, and as an alert after 5 minutes. A question to Litestream's control socket gives
  up after 3 seconds, connecting included. The section lists its alerts above the rows, so a sink
  past its threshold shows with notifications off. The config alert names the broken file, and a
  stored error no longer keeps a secret containing `/` from a URL's user info
  ([#635](https://github.com/public/wicket/issues/635)).
