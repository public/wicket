---
area: Console
type: Changed
---
- The console has one layout and visual system: a spacing and type scale, one set of colours with
  at least 5.2:1 text contrast in light and dark, the same cards, buttons and status pills
  everywhere, and buttons at least 44 px tall. Sections come in the order they are acted on: what
  waits for your decision (requests and standing reach asks together), then health (nodes, the state
  store, leased nodes), then runs, activity, and the settings under Manage. A section bar under the
  header jumps to each. On a wide screen requests sit two to a row and runs share a row with starting
  one and recent decisions; on a phone every label-and-value row stacks, and the page honours the
  screen's safe areas ([#574](https://github.com/public/wicket/issues/574),
  [#642](https://github.com/public/wicket/issues/642), [#643](https://github.com/public/wicket/issues/643)).
- How many decisions wait is in the tab's title (`(2) wicket`), the heading, the section bar and,
  where the browser supports it, the installed app's badge
  ([#650](https://github.com/public/wicket/issues/650)).
- `ci/console-preview.sh` serves the console against a mock of its API with made-up data, and takes
  desktop and phone screenshots in light and dark, for reviewing a change to the page.
