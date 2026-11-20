# Preact prototype: notes

Preact 11.2.0 (the current `latest`) with hooks and Vite 8.3.8, the version `web/session` pins. JSX goes
through Vite's own Oxc transform (`oxc.jsx.importSource: "preact"` in `vite.config.js`), not
`@preact/preset-vite`. The preset needs `@babel/core` as a peer, which would add Babel and its whole
tree to the lockfile. All we would lose is prefresh hot reload in dev, which a prototype doesn't need.

- `src/helpers.js`: helpers copied from the reference (`strip`, `rel`, `clock`, `riskLabel`, `verb`,
  `verbsOf`, `asks`, `problemList`, `principalName`, `money`, `ruleText`, `egressOf`, …). `line` is the
  only one changed: it returns `[tag, tone, text]` instead of an element.
- `src/main.jsx`: the Inbox, Agents and agent page, routing and polling.

## Easy

- **Keeping DOM nodes across polls costs nothing.** `key={p.id}` on cards, `key={x.id}` on runs and
  `key={op.seq}` on log lines covers it. The reference needs a `cards` map with a content key,
  `renderKeyed`, and checks that compare children. Here each poll re-renders and Preact patches only
  the text that changed, such as a card's age. So an open `<details>`, a revealed identity line (local
  `useState` in `WhoAsks`) and the button under the cursor all survive the 2 s poll. The baseline's
  Agents rows and agent log are rebuilt on every poll, because it uses `renderRows`. Here they keep
  their node as well.
- **Text-only output is the default.** Every API string is a JSX child or attribute, so markup can't
  be injected unless someone writes `dangerouslySetInnerHTML`, which this code never does.
- **The structure reads like the HTML.** `pendingCard`'s button ladder becomes a single expression
  (`!idOk ? deny : single ? <>{once}{deny}</> : <>{once}{hour}{deny}</>`).
- **The authority view loses its bookkeeping.** It is one `useEffect` keyed on the run, with a `live`
  flag so a late answer for another run is dropped. It re-renders with each poll's state, for example
  the standing rules.
- The build is fast: about 0.1 s for `vite build`.

## Awkward

- **Hooks rules.** `WhoAsks` has to call `useState` before its early returns. `useState2s` and
  `useRoute` are small, but they are still hand-written subscriptions with cleanup.
- **Falsy values in `&&`.** `{x.ended_at && …}` would render a literal `0` for a zero timestamp, so
  numbers need a ternary. Strings and booleans are fine.
- **One element doesn't map to one component.** The reference's `whoAsks` returns `[element, ok]`. In
  JSX the "is the identity good enough to approve" flag has to be computed apart from the component
  that shows it.
- **`line` had to change shape.** It builds DOM, so the copied helper now returns parts and the JSX
  builds the row.
- **Vite 8 options differ from older Vite.** Vite 8 has `rolldownOptions` and `oxc` where older
  versions had `rollupOptions` and `esbuild`. The fixed `app.js`/`app.css` names come from
  `entryFileNames` and `assetFileNames: "app[extname]"`.

## CSP

Nothing broke the CSP. The production build is one external module script plus one stylesheet link
(`dist/index.html` has no inline script or style), with no `eval` or `new Function`. Preact sets
`style` only through the CSSOM (no `style` attributes are used anyway), and that is allowed under
`style-src 'self'`. `modulePreload: false` keeps Vite from injecting its preload polyfill. That
polyfill is an external file today, but it isn't needed.

The minified `app.js` contains the string `innerHTML` twice, both inside Preact's own runtime: its
handling of the `dangerouslySetInnerHTML` prop. This code never passes that prop, so the paths never
run. A grep-based lint for `innerHTML` in `dist/` would flag it, so lint the source instead.

## Left out (outside the spec's three screens)

- the `/api/me` sign-in and boot flow: the page starts polling straight away;
- the standing-ask cards (they are still counted in the status line, the tab badge and "Needs you (N)");
- the "why?" explain button on log lines;
- the Activity and Settings views (they show a placeholder);
- the reference's `settled()` guard, which ignores taps for 800 ms after a layout move;
- the app badge.

Views are rendered on demand rather than kept in the DOM with `hidden` toggled.

## Numbers

- **Lines written:** `src/main.jsx` has 414 lines (371 without blank and comment lines). Add
  `vite.config.js` (14) and `index.html` (11), so 439 in all. `src/helpers.js` (152) is copied from the
  reference and is not counted. Its converted `line` is about 45 lines of that.
- **Packages:** 48 in `package-lock.json`. Only `preact` is a runtime dependency. The rest are Vite 8,
  rolldown, lightningcss and their optional platform binaries.
- **Gzipped (`gzip -9`):** `dist/app.js` 13,834 B, `dist/app.css` 5,560 B.
- **Build time:** `npm ci && npm run build` from a clean `node_modules` took 1.5 s wall (with a warm
  npm cache); `vite build` alone takes about 0.1 s.
- **Checks:** run with Playwright against `node serve.mjs preact 8812`, after the mock's timestamp fix.
  On all three screens there were no console errors and no CSP violations, the cards and rows
  rendered, and the first card, row or log line was the same tagged DOM node after 2.5 s. An open
  Details and a revealed identity line also survived a poll. The decide and stop `console.info` calls
  logged, `aria-current` was on the right tab, and back went from the agent page to `#agents`.
  Screenshots are in `shots/`. They match the baseline's.
