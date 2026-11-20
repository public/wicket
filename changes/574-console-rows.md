---
area: Console
type: Changed
---
- The console says times one way: how far off ("in 8 h", "2 h ago") with the local time ("19:20",
  "Wed 19:20"), counted from the server's clock, and the exact UTC time on hover. Expiries read "ends"
  ([#645](https://github.com/public/wicket/issues/645)).
- Capacity grants read in lines and plain money: "Allows: 2 nodes at once of vc2-1c-2gb in lhr, up to
  $0.05/h and $1.00 a day", "Used today", "Left today" and "Ends 16:29 (in 8 h)", with the principal
  as `unix/alex`, a passkey or an agent's name ([#639](https://github.com/public/wicket/issues/639)).
- A run row leads with the agent's name, its zone and its state, then when it started and ended, with
  the run id quieter; its links say **Live session** and **Remote Control session ↗**
  ([#641](https://github.com/public/wicket/issues/641)).
- Activity lines have a time, a tag and a sentence for every record kind, including standing reach
  and grant revocations, refused decisions, capacity and lease requests and node records; tokens read
  "12,345 in / 567 out tokens" ([#646](https://github.com/public/wicket/issues/646)).
- Empty states show commands as code and use the glossary's words ("No leased nodes.")
  ([#648](https://github.com/public/wicket/issues/648)). A node past its lease that a run still holds
  says so calmly, with `wicket node release <id>` in a block to copy
  ([#649](https://github.com/public/wicket/issues/649)).
