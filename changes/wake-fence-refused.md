---
area: Long-lived agents
type: Changed
---
- `wicket wake` refused by the wake fence (the agent's last activation may still be running on a
  node this host can't confirm stopped) now exits 3, refused, and says "not woken yet", as a wake
  refused because another wake holds the agent does. Of two wakes at once, the loser is refused the
  same way whichever of the two it meets ([#153](https://github.com/public/wicket/issues/153),
  [#574](https://github.com/public/wicket/issues/574)).
