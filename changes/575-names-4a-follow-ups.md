---
area: Identity, spawn and links
type: Changed
---
- Public names ([#575](https://github.com/public/wicket/issues/575), follow-ups to step 4a):
  - Asks for public names are listed by `wicket pending` (text and `--json`), and pushed to the
    operator's devices like other asks. `wicket approve` and `wicket deny` on an `n-…` id point at
    `wicket names`.
  - An agent's `decide` refuses an ask for a public name outright.
  - The reason is marked as the agent's.
  - After a denial, the same agent can't ask for the same name for 15 minutes.
  - A standing ask nobody decides is withdrawn after 14 days.
  - Revoking an internal name stops offering the port its name exposed.
  - An internal `request_name` refuses `scope: standing` and `service`.
  - The answers no longer promise that later runs hold a standing name: they will from the next step.
