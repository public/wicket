# SolidJS prototype

Versions are pinned exactly: `solid-js` 1.9.20, `vite-plugin-solid` 2.11.17 (which brings Babel and
`babel-preset-solid`), and `vite` 8.3.8, the version `web/session` uses. `vite-plugin-solid` supports
Vite 8, so I didn't need a different Vite.

**Why Solid 1.9 and not 2.0.** `solid-js@latest` is 2.0.3, released 2026-11-19. Solid 2.0 shipped on
2026-11-17. It doesn't work with `vite-plugin-solid`: the latest stable 2.11.17 requires
`solid-js ^1.7.2`. Solid 2 needs a renamed plugin, `@solidjs/vite-plugin` 3.x, and `@solidjs/web`.
The brief asks for `vite-plugin-solid`, so this prototype uses the stable 1.x line, `v1-latest`
1.9.20. A Solid 2 version would be a separate comparison: its store and list APIs changed.

## Files

- `src/main.jsx`: the app, written for this prototype.
- `src/helpers.js`: copied from the reference. It contains `strip`, `rel`, `clock`, `at`, `riskLabel`,
  `verb`, `verbsOf`, `asks`, `problemList`, `principalName` and others. It also has `lineOf`, which is
  the reference's `line` changed to return `{cat, tag, tone, text}` instead of an element.
- `vite.config.js`: sets the output names `app.js` and `app.css`, turns off source maps and turns off
  the modulepreload polyfill.
- `index.html`: the page shell.

## Lines of code

Counts exclude blank lines and lines that are only a comment.

| File | Lines |
| --- | --- |
| `src/main.jsx` | 346 |
| `vite.config.js` + `index.html` + `package.json` | 49 |
| `src/helpers.js` (copied, not counted) | 135 |

Of the 135 lines in `helpers.js`, about 45 are `lineOf`. It is adapted from the reference's `line`
rather than copied as is.

## What was easy

- **Keeping the same DOM node across polls.** Each poll's JSON goes into one store with
  `setS(reconcile(json, { key: "id" }))`. `reconcile` matches items by id and changes the existing
  proxies in place. `<For>` keys by reference, so it keeps every card and row, and only the text that
  changed is updated (the age, for example).
  - This held even with the old mock, whose timestamps changed on every poll. Changed fields update
    inside the existing node; the card is not rebuilt.
  - The reference instead rebuilds a card whenever its content key changes.
- **Not recreating every row.** A plain `setSignal(await r.json())` would give `<For>` new objects
  on every poll, so it would rebuild every row. `reconcile` is what prevents that.
- **Fine-grained updates.** The reference has several hand-written caches: the `cards` Map,
  `renderKeyed`, `problemsKey` and `dataset.key`. None of them are needed here.
- **Text only.** API strings become text nodes in JSX, so `strip` plus JSX covers the "text only"
  rule without any extra code.
- **Routing.** One `hash` signal and a memo handle routing. `aria-current` and `hidden` are plain
  bindings.
- **Small pieces.** Per-card UI state, such as the identity line's toggle, is a local
  `createSignal` inside the card component.
- **Fetching permissions.** `createResource` keyed on `(view, run)` fetches the authority once each
  time the page opens, as the reference does, with loading and error states.

## What was awkward

- **Audit records have no `id`.** `reconcile` takes only one key name. I gave each record an id
  before reconciling (`id: "seq:" + op.seq`). Without that, records would be matched by position, and
  a window that slides would rewrite every line's text.
- **The problems list.** `problemList` returns new tuples on every poll. I used `<Index>` (keyed by
  position) so each `a.problem` stays the same node and only its text updates.
- **Destructuring props.** Destructuring props breaks reactivity. I keep `props.x` as one store proxy
  per row (stable for that row's lifetime) and read its fields lazily. You have to know this rule.
- **Reading a resource that failed.** Reading a resource in its error state throws. The `Switch` has
  to test `authority.error` before it calls `authority()`.
- **Choosing the version.** A major version had shipped three days earlier, and the plugin named in
  the brief doesn't support it (see above).

## CSP

Nothing broke the CSP. With the console's CSP, the three screens showed no console errors, no
`securitypolicyviolation` events and no page errors.

- **The built page.** `dist/index.html` has only `<script type="module" src="/app.js">` and
  `<link rel="stylesheet" href="/app.css">`. There is no inline script or style.
- **Settings I turned off as a precaution.** `modulePreload.polyfill: false` and
  `assetsInlineLimit: 0`. Neither was actually needed.
- **No eval.** `dist/app.js` contains no `eval` and no `new Function`.
- **Solid uses `innerHTML` internally.** Its compiled templates call `template()`, which sets
  `innerHTML` on a `<template>` element. Those strings are fixed at compile time: the static HTML
  from the JSX, never API data. The console's CSP doesn't use Trusted Types
  (`require-trusted-types-for`), so this is allowed. If the CSP ever added Trusted Types, Solid 1.x
  would need a policy for this.
- **My own code** never uses `innerHTML`.

## Build

- `npm ci && npm run build` took about 3.2 s wall time from a clean `node_modules`: about 2.9 s for
  `npm ci` and 0.3 s for `vite build`.
- `package-lock.json` lists 106 packages, mostly Babel.

| File | Size | gzip -9 |
| --- | --- | --- |
| `dist/app.js` | 49.5 kB | 17,482 B |
| `dist/app.css` | 23.1 kB | 5,551 B |

`dist/app.css` is `../shared/console.css` minified by Vite, with nothing added.

## Checks

Run with Playwright against `node serve.mjs solid 8814`, after the mock's timestamp fix.

- **Inbox:** 8 request cards and 6 problems.
- **Agents:** 11 rows; `aria-current` is on the Agents tab.
- **Agent page:** permissions lines and 3 activity lines.
- **Same node across a poll:** for each screen, every card, row or line was tagged with a JS
  property. After 2.5 s and one `/api/state` poll, each was still the same connected node.
- **Buttons:** Allow once logs `decide {id, choice}`. Stop agent… logs `stop <run>`.
- **Back button:** returns to the Inbox.
- **Screenshots:** `shots/` has the three screens at 1440x900. They match the reference's layout and
  words.

## Left out

These are outside the spec's three screens:

- The standing "always allowed" asks: they are counted in the status line and badge, as the
  reference counts them, but have no cards.
- The Activity and Settings views: their tabs show a placeholder.
- Sign-in.
- The passkey confirmation sheet.
- The 800 ms tap guard after a layout change.

Some controls are there but do little:

- "Start an agent…" is shown but does nothing.
- "why?" on egress lines logs `console.info("explain", seq)`. The mock has no `/api/explain`.
