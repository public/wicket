# What each prototype builds

The same three screens of the redesigned console (`docs/explanation/console-design.md`), in each
candidate framework, against the same mock API, with the same CSS. The reference is the plain-JS
console on this branch (`crates/wicket-cli/src/serve/static/console.js` and `console.html`). Match its
words and class names, so that `shared/console.css` styles every prototype the same way and the
screenshots compare like for like.

## The screens

1. **Inbox** (`#inbox`, the default):
   - the status line (`p.status`): "N agents working · M requests waiting for you · K problems",
     each part a link;
   - **Needs you** (`h3.sub` + `div.deck`): one card per pending request (`div.card.req`), built as
     `pendingCard` builds it:
     - `div.req-head`: the risk pill (`span.risk.rN`, the words from `riskLabel`) and the age;
     - `dl.fields`: Who (agent and zone, or the unconfirmed-identity line), Wants to (the verb from
       `verb`, or `asks()` for wicket's own kinds), Where (host and path), Why (the reason in quotes);
     - the buttons (`div.buttons.ladder`), by the same rules as the reference. Allow once, Allow for
       1 hour and Don't allow, each logging `{id, choice}` with `console.info("decide", …)` (no
       signing in a prototype);
     - `details.more.req-more` with Details: the raw request and the ids;
   - **Problems** (`div#problems`): the reference's `problemList`, as `a.problem.bad|warn` links.
2. **Agents** (`#agents`): one row per run (`div.row.run`) as `renderRun` builds it (name link, zone,
   state pill, "started …", the id cut in the middle, links).
3. **An agent's page** (`#agent/<run>`):
   - its head (`renderRun` in page mode, with **Stop agent…** logging `console.info("stop", run)`);
   - **Permissions** from `GET /api/runs/<run>/authority`: the "Can reach" lines, then "Where it
     runs";
   - its recent activity, filtered from the state's `audit`.

Navigation: the four tabs in `header.top > nav` (`a[data-view]`, `aria-current="page"` on the
current one), routed by `location.hash`, with the back button working.

## Behaviour that must hold

- Poll `GET /api/state` every 2 s. A card or row whose data didn't change must stay the **same DOM
  node** across polls, so a tap mid-poll lands on the button it was aimed at; keyed lists do this.
- Every string from the API is text: no `innerHTML`, `v-html`, `{@html}`, `dangerouslySetInnerHTML`
  or `unsafeHTML`. Strip the control and bidi characters the reference's `strip` removes.
- The page runs under the console's CSP, which `serve.mjs` sends: no inline script or style, no
  `eval` or `new Function`, scripts and styles only from files. A framework that needs `unsafe-eval`
  or inline styles in its production build fails.
- Accessible as the reference: real buttons and links, labels, `details`/`summary`, focus outlines
  (from the CSS), `aria-current` on the tab.

## The build

- In `<framework>/`: `package.json` with exact versions, `package-lock.json` committed, and
  `npm ci && npm run build` producing `dist/index.html`, `dist/app.js` and `dist/app.css` (fixed names:
  `serve.mjs` serves them). `app.css` is `../shared/console.css` plus nothing, or the framework's
  scoped styles if it insists. Use Vite (already in the repository's pipeline, `web/session`) unless
  the framework needs nothing at all.
- No CDN, no network at run time, no source maps in `dist/`.
- Keep the code as small and as readable as you would ship it. Copy the reference's helpers you need
  (`strip`, `rel`, `riskLabel`, `verb`, `asks`, `problemList`, `principalName`) into a plain
  `shared/`-style module: they are the same in every candidate and are not what is being compared.
  Note in `NOTES.md` anything the framework made easier or harder.
