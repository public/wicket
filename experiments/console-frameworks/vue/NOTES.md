# Vue 3 candidate

Vue 3.5.45, @vitejs/plugin-vue 6.0.11 and Vite 8.3.8: the same versions as `web/session`, nothing else.
Single-file components with `<script setup>`. Templates are compiled at build time and `vue` resolves
to its runtime-only build.

## Numbers

- `dist/app.js` 84.6 kB, **32,219 bytes gzipped** (`gzip -9`); `dist/app.css` 23.1 kB, **5,573 bytes gzipped**.
  `app.css` is `../shared/console.css`, minified by Vite and otherwise unchanged.
- `package-lock.json`: **67 packages**. 33 are rolldown/lightningcss platform binaries marked optional,
  so 34 are installed on one machine.
- **Lines written: 442 non-blank** (397 without comment lines). That covers the `.vue` files,
  `main.js`, `vite.config.js` and `index.html`. The helpers copied from the reference are excluded:
  `src/shared.js`, 148 lines.
- **Build time** `npm ci && npm run build`: about 1.5 s with a warm npm cache (1.0 s `npm ci`, 0.5 s `vite build`).

## Checks (Playwright, against `node serve.mjs vue 8811`)

All of them passed:
- No console errors or warnings. A `securitypolicyviolation` listener recorded no CSP violations.
- `#inbox`: 8 request cards. `#agents`: 11 run rows. `#agent/run_01JDRELEASE…`: the head, the Permissions
  block and 3 log lines.
- On all three screens, every card, row and log line was tagged with a JS property and was still the
  same node after 2.5 s, with polls landing in between (2 in 4.5 s on a second check). The approve
  button inside a card was the same node too. The baseline fails this on rows and log lines, because
  it rebuilds them each poll.
- The buttons log `decide {id, choice}` and `stop <run>`. `aria-current` follows the tab, `#agent/…` marks
  Agents, and the back button returns to `#agents`.
- The screenshots in `shots/` match the baseline at 1440x900. Only the clock-driven ages differ.

## What was easy

- **Keyed lists.** `v-for … :key="p.id"` alone gives the "same DOM node across the poll" behaviour.
  The reference does this by hand: a `cards` map, content keys and the `replaceChildren` comparison.
  Vue also patches the age text inside an unchanged card instead of rebuilding the card.
- **The poll.** Swapping in the new `state` object each poll is enough. Nothing needs to diff by hand.
- **Text only.** `{{ }}` is always text, so nothing could reach `innerHTML`. Every API string still goes
  through `strip`.
- **CSP.** Nothing broke it. The runtime-only build has no `new Function`. Vite's output is one
  `<script type="module" src="/app.js">` and one `<link rel=stylesheet>`. No style attributes are used
  (`hidden` instead of `v-show`). The runtime bundle still contains `innerHTML` for `v-html` and
  static-content hoisting, but this code uses neither.
- `aria-current` takes `undefined` to drop the attribute, so tab state is one expression.

## What was awkward

- **Inline text runs.** Text interleaved with elements (`✓ name · zone x`, `started … · ended … · id`,
  the status line's `a · a · span`) needs `<template>` pieces and `{{ " · " }}` written against Vue's
  whitespace condensing, or a space appears or disappears. The plain-JS reference's
  `append(text, el, text)` is easier to read here.
- **Builders become data.** The reference's `line()` builds an element. It had to return data
  (`{ts, tag, tone, text, why}`) so a template can render it. `reachLine`'s "end" (text plus a `<time>`)
  became `{pre, t, tText, note}`. That is small work, but every helper that returns DOM needs it.
- **Fixed file names.** These need `rollupOptions.output` (`entryFileNames`, plus an `assetFileNames`
  function for the CSS), `cssCodeSplit: false` and `modulePreload: false`. Vite also adds `crossorigin`
  to the tags, which is harmless on the same origin.
- **Unicode escapes.** When the copied helpers were written to disk, the ` ` in `strip`'s regex
  became a raw character and broke the parse (a U+2028 ends a line in a regex literal). Re-escaping
  fixed it. This was not Vue's fault, but it is worth knowing for any copy.

## Not done (outside SPEC's three screens)

- The standing asks ("Asking to be always allowed") are not built, so the Inbox has no section for them
  (the status line still counts them). The same goes for the "Start an agent…" form (the button only
  logs), the Stop form (the button logs `stop`, as SPEC asks), sign-in, the stale banner's "since …",
  `#pending/<id>` and `#health` scrolling, and the "taps ignored while the layout settles" guard.
- "why?" on a log line opens a line saying there is no explanation, because the mock API has no
  `/api/explain`.
- Activity and Settings show "Not in this prototype."
