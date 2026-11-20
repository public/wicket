# Lit prototype: notes

Lit 3.3.3 (lit-html templates only), bundled by Vite 8.3.8. `src/app.js` is the prototype, and
`src/helpers.js` holds the reference's helpers.

## Light DOM: plain `render()`, not LitElement

The whole page is one lit-html template, rendered with `render(page(), document.body)`. There is no
LitElement and no custom element. The reasons:

- `console.css` is global and uses ids and child selectors (`#detail-body .row > .meta:first-child`,
  `.grid > *`, `.log > div`). A custom-element wrapper would add a node between parent and child,
  and shadow DOM would hide the elements from the stylesheet. Plain `render()` produces exactly the
  reference's tree.
- The state is one object polled every 2 s, so components with their own reactive properties would
  add nothing. `draw()` re-renders the page, and lit-html only touches the bindings that changed.

## What was easy

- Keyed lists. `repeat(s.pending, p => p.id, pendingCard)` replaces the reference's hand-written
  `cards` map and its `JSON.stringify` key comparison. Unchanged cards keep their DOM node across
  polls (checked: 8/8 cards, 11/11 agent rows and 3/3 log lines kept after a poll). An age that
  changes is updated in place, and the card is not rebuilt.
- UI state survives re-renders without extra code. An open `<details>` stays open because lit
  never binds `open`. The unfolded identity (`aria-expanded`, `.idline[hidden]`) is a `Set` of ids
  that the template reads.
- Text only, by default. Every `${}` in content is a text binding. Escaping is never needed, and
  there is no `unsafeHTML`.
- Attribute toggles such as `?hidden=${…}` and `aria-current=${… ? "page" : nothing}` replace the
  reference's `show()` loop over elements.
- No compiler, no JSX and no plugin. Vite only bundles and minifies.

## What was awkward

- Whitespace. Template literals keep their newlines, so in inline contexts (the status line, `run-head`,
  `who-ask`, a `meta` line) the markup has to stay on one line, or stray spaces appear between
  elements. The long one-line templates in `renderRun` and `whoAsks` come from this.
- There are no components or local state. The identity toggle needs a module-level `Set` and a
  manual `draw()`. That is fine at this size, but it scales worse than a framework with per-component
  state.
- Conditionals are ternaries returning `nothing`. That reads fine for one branch and gets dense
  when nested (`technical()`, the button ladder).
- The `\u` escapes in the source are a tooling note, not Lit. The file writer turned them into
  literal characters, and a literal U+2028 inside `strip`'s regex broke the parse. That line is now
  copied byte for byte from the reference.

## Scope (what is not here)

- Signing, toasts, and the reference's `settled()` tap guard after the layout moves. Decisions log
  `console.info("decide", {id, choice})`, and Stop agent… logs `console.info("stop", run)`.
- The standing asks are counted in the status line and the nav badge, as the reference counts
  them, but their cards are not rendered (the spec does not ask for them).
- `#pending/<id>` does not highlight a card. Activity and Settings are placeholders.
- "why?" on an egress log line logs `console.info("why", seq)`, because the mock has no explain
  endpoint.
- The authority view re-renders on each poll from `lastState`, so standing rules and grant expiry
  stay current. The reference computes it once.

## Lines of code

Counted without blank and comment lines:

- `src/app.js`: 243.
- `vite.config.js`: 8.
- `index.html`: 12.
- Total written: **263**.

`src/helpers.js` (139 lines) is excluded. It holds the copied helpers (`strip`, `rel`, `clock`,
`riskLabel`, `verb`, `verbsOf`, `asks`, `problemList`, `principalName`, `span`, …). It also holds
`describeOp`, which is the reference's `line` switch changed to return `[tag, tone, text]` instead
of building DOM. The words are the reference's, so it counts as a helper.

## CSP

Nothing in the production build broke the CSP. The checks found no `securitypolicyviolation`
events and no console errors on any of the three screens. lit-html builds templates from
`<template>` elements and `document.importNode`, with no `eval` and no inline styles. The build
was set up to stay that way:

- `modulePreload: { polyfill: false }` keeps Vite's preload polyfill out. It is not needed for a
  single chunk.
- `sourcemap: false`.
- The output names are fixed through `rolldownOptions.output`. Vite 8 uses Rolldown, and
  `rollupOptions` is deprecated there.

The resulting `dist/index.html` has one `<script type="module" src="/app.js">` and one
`<link rel="stylesheet" href="/app.css">`. A grep finds no `eval(` or `new Function` in `app.js`.

## Build and size

- `npm ci && npm run build` takes about **1.4 s** (1.41, 1.36 and 1.45 s over three clean runs:
  `rm -rf node_modules dist` each time, warm npm cache). Vite's own step takes about 65 ms.
- `dist/app.js` is 38.0 kB, **14,736 B** with `gzip -9`.
- `dist/app.css` is 23.1 kB, **5,573 B** with `gzip -9`.
- `package-lock.json` lists 53 packages. Most are Rolldown's and Lightning CSS's optional
  per-platform binaries. On linux-x64, 23 packages are installed in `node_modules`.

## Checks

These were run with Playwright against `node serve.mjs lit 8815`, after the timestamp fix to the
mock, at 1440x900:

- **Inbox**: 8 cards, no errors. All 8 kept their DOM node over a 2.5 s wait with a poll in it.
- **Agents**: 11 rows, all 11 kept.
- **Agent page**: 3 activity lines, all kept. 3 "Can reach" lines, then "Where it runs".
- `aria-current="page"` is on the right tab, including Agents for an agent's page.
- The back button returns from an agent's page to `#agents`.
- The decide and stop buttons log as specified.
- An open Details and an unfolded identity both survive a poll.

The screenshots in `shots/` match the baseline's pixel for pixel, apart from the relative ages. In
comparison, the baseline keeps its request cards but replaces its agent rows on every poll, because
it uses `renderRows`.
