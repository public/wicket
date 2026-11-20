# Svelte 5 prototype: notes

Svelte 5.58.0 (runes), `@sveltejs/vite-plugin-svelte` 7.3.1, Vite 8.3.8: the repository's pinned Vite,
which the plugin supports (`peerDependencies: vite ^8.0.0`). Plain Svelte, no SvelteKit.

## Layout

- `src/helpers.js`: the reference's helpers, copied (`strip`, `rel`, `clock`, `at`, `riskLabel`, `verb`,
  `verbsOf`, `asks`, `problemList`, `principalName`, `ruleText`, ...). `line` is the reference's
  sentence builder unchanged in its words, but returning `{tag, tone, text, why}` instead of a DOM node.
- `App.svelte`: header, tabs (`aria-current`), hash routing, the 2 s poll, the stale banner.
- `Inbox.svelte`, `PendingCard.svelte`: status line, Needs you (keyed by request id), Problems.
- `Agents.svelte`, `RunRow.svelte`: the runs list (keyed by run id); `RunRow` in page mode is the agent's head.
- `AgentPage.svelte`: head, Permissions from `/api/runs/<run>/authority`, recent activity (keyed by `seq`).
- `Time.svelte`, `IdShort.svelte`, `LogLine.svelte`: the reference's `timeEl`, `idEl` and `logLine`.

## What was easy

- Keyed lists are one line: `{#each s.pending as p (p.id)}`. Cards and rows keep their DOM node across
  polls with no cache, no content key and no "did anything change" comparison; the reference needs a
  `Map` of cards, a JSON key per card and a node-by-node comparison for that. A card whose data changed
  is patched in place rather than rebuilt.
- `$state.raw` for the polled state: each poll replaces it whole, so there is no deep proxy over a
  large object and the each-blocks diff by key.
- Local UI state stays where it belongs: the identity line's open/closed (`showId`) lives in the card,
  and survives polls for free (in the reference it survives only because the card node is reused).
- Text is text by default (`{expr}` sets text content); with no `{@html}` there is no way to parse a
  string as markup. Markup compared against the reference, normalised for whitespace and attribute
  order, is identical for the cards, the runs, the agent's head and its log.
- No styles in components, so `app.css` is `shared/console.css`, minified, and nothing else.

## What was awkward

- Whitespace. Svelte collapses whitespace between tags into a single space, and the reference builds
  its rows with no whitespace at all; text like `"✓ "` or `" · zone "` has to go in as `{"..."}`
  expressions to keep its spaces, and inline runs (status line, run head) are kept on one line.
  (The extra spaces between block elements don't show: they are in flex and grid containers.)
- Lots of logic in templates: the reference's string-building (`renderWho`, the button ladder, the
  authority view's reach lines) reads less directly as `{#if}` chains than as plain JS. I moved the
  authority view's reach lines into a `$derived.by` returning plain objects to keep the markup short.
- `$effect` for the authority fetch needs a guard (`want === run`) against a late answer for a page
  already left; there is no built-in resource/await-with-cancellation in plain Svelte (`{#await}`
  would work, but re-renders loading on every route change the same way).
- The Write tool turned the `\uXXXX` escapes in `strip`'s regex into literal characters, including
  U+2028, which broke the regex; I copied the line from `console.js` verbatim instead. Not Svelte's
  fault, but worth knowing for anyone copying the helpers.

## Lines of code

Written by me, excluding `helpers.js` (145 lines, copied; of which `line` is 41 lines adapted to
return data):

| file | lines |
|---|---|
| `AgentPage.svelte` | 96 |
| `App.svelte` | 81 |
| `PendingCard.svelte` | 72 |
| `RunRow.svelte` | 30 |
| `Inbox.svelte` | 28 |
| `Agents.svelte` | 12 |
| `LogLine.svelte` | 10 |
| `IdShort.svelte` | 8 |
| `Time.svelte` | 7 |
| `main.js` | 6 |
| `vite.config.js` | 17 |
| `index.html` | 14 |
| **total** | **381** (344 without blank and comment-only lines) |

## CSP

Nothing broke the CSP. Svelte 5's production build has no `eval` or `new Function`. What was needed:

- `compilerOptions: { css: "external" }` with `emitCss: true` (the plugin's default for builds): no
  component style is injected at run time. There are no `<style>` blocks anyway.
- `build.modulePreload.polyfill: false`, `sourcemap: false`, `cssCodeSplit: false`,
  `assetsInlineLimit: 0`, and `rollupOptions.output` naming the entry `app.js` and the CSS `app.css`.
  `dist/index.html` then has only `<script type="module" src="/app.js">` and `<link href="/app.css">`.
- The Svelte runtime does use `innerHTML`, but only on a `<template>` element with the compiler's own
  static markup (to clone it); API strings always go through text nodes. The page sets no Trusted
  Types policy, so the CSP doesn't see this.

Checked in Chromium (Playwright) under `serve.mjs`'s CSP: no console errors, no
`securitypolicyviolation` events, on `/`, `#agents` and `#agent/run_01JDRELEASEQQQQQQQQQQQQQQQ`.

## Build time

`npm ci && npm run build` from an empty `node_modules`: about 2.2 s (npm ci 1.2 s, 41 packages
installed; vite build 1.0 s wall, "built in 402ms").

## Sizes

`dist/app.js` 65.7 kB (24,909 bytes gzip -9), `dist/app.css` 23.1 kB (5,573 bytes gzip -9).
`package-lock.json` lists 71 packages (41 installed on linux-x64; the rest are other platforms'
optional native bindings of rolldown and lightningcss).

## Left out, against the reference

- The standing asks ("Asking to be always allowed") under Needs you: not in SPEC; their count is still
  in the status line, the heading and the tab, as in the reference.
- The tap-settle guard (`layoutAt`, `settled()`) and the `#pending/<id>`/`#health` scrolling. `#health`
  shows the Inbox.
- The Activity and Settings tabs route to a placeholder; "Start an agent…" and "why?" only log.
- `data-cat` on log lines (used only by the Activity filter).
