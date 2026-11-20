---
area: Console
type: Changed
---
- A request card leads with what is asked, who asks, the risk and the buttons. On whose behalf, who
  in the box asked, the ids and how a push is granted are under **Details**, and a run id is cut in
  the middle on screen but copied whole (#574 review).
- wicket's own requests read as sentences: "Lease a node: 2 vCPU, 4096 MiB, … at most $0.036/h",
  "Start a child agent named reader in zone research", "Link run_a → run_b, port 8080", "Install
  wicket build 9f86d081884c…", with the raw request under Details and one **Approve**
  ([#621](https://github.com/public/wicket/issues/621)).
- Opening the console from a notification scrolls to that request's card, clear of the header, or
  says the request is no longer waiting ([#644](https://github.com/public/wicket/issues/644)). When a
  console session ends, the sign-in card says so ([#618](https://github.com/public/wicket/issues/618)).
- Revoking a capacity grant or a standing rule asks in the page first, and its button sits apart
  from Renew ([#640](https://github.com/public/wicket/issues/640)).
- A run's authority view leads with what it can reach: its zone's rules, its live grants and the
  standing rules for it, each with when it ends. The token, its blocks and the zone's Cedar are under
  Details, and a manifest's limits read "memory 2GiB · 2 CPUs · timeout 1h". The authority endpoint
  now includes the zone's `reach` ([#651](https://github.com/public/wicket/issues/651)).
