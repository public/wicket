# Solid without Babel (`solid-h`)

The `../solid` prototype rebuilt without its compiler. The aim is to measure what dropping
`vite-plugin-solid` saves. That plugin brings in Babel and `babel-preset-solid`: 25 of the 106
packages in its lockfile. Here, esbuild turns the JSX into plain `h(tag, props, ...children)` calls
to `solid-js/h`, Solid's hyperscript runtime. There is no Vite, no Babel and no plugin.
`solid-js/html` is not an option: it compiles templates with `new Function`, and the CSP forbids that.

## What changed

- `package.json`: `solid-js` 1.9.20 and `esbuild` 0.28.2, both pinned. `vite` and
  `vite-plugin-solid` are gone.
- `build.mjs` (10 lines): one esbuild call bundles and minifies `src/main.jsx` into `dist/app.js`
  (ES2022, ESM, no source map). A second call minifies `../shared/console.css` into `dist/app.css`.
  The script then copies `index.html`. `npm ci` takes 0.6 s and the build 0.25 s, against about 2.9 s
  and 0.3 s for `../solid`. `node_modules` is 15 MB instead of 88 MB.
- `index.html` links `/app.js` and `/app.css` directly, because nothing rewrites it now.
- `src/helpers.js`: unchanged.
- `src/main.jsx`: the same components and markup, with the same words and class names, converted as
  follows:
  - **Everything reactive is a function.** This covers text (`{() => strip(p.host)}`), attributes
    (`class={() => "risk " + riskClass(p.risk)}`, `hidden={() => view() !== "inbox"}`), conditions
    (`when={() => a().internal}`), lists (`each={() => s.pending}`) and component props
    (`t={() => p.created_at}`). Zero-argument functions passed to a component become getters, so
    inside the component `props.t` reads just as it does with the compiler. The file has 120
    `() =>`, against 39 in `../solid`.
  - **A branch that can come and go, and holds reactive content, is written as a function:**
    `<Show when={waiting}>{() => <>…</>}</Show>`. `h()` builds an element once and keeps it. Without
    the function, showing a branch a second time would reuse the old element, whose bindings were
    disposed when it was hidden.
  - **`For`, `Index`, `Show` and `Match` are wrapped** by a 9-line `eager` helper (see below).
  - The JSX factory is imported (`import h from "solid-js/h"`). A callback parameter named `h`
    would shadow it, so `held => …` replaces `h => …`.
  - `Reach` reads its props once, as plain values. Its words come from the fetched authority, and
    the `<Time>` inside it keeps itself current.
- `reconcile` with `<For>` is unchanged: one store, reconciled by `id` on each 2 s poll. An
  unchanged card, row or log line keeps its DOM node.

## Lines of code

Counts exclude blank lines and lines that are only a comment, as in `../solid/NOTES.md`.

| File | `solid-h` | `../solid` |
| --- | --- | --- |
| `src/main.jsx` | 352 | 346 |
| build config + `index.html` + `package.json` | 36 (`build.mjs`) | 49 (`vite.config.js`) |
| `src/helpers.js` (copied, not counted) | 135 | 135 |

The net change is six more lines: the 9-line wrapper header, minus a few lines saved where a ternary
replaced a `<Show>`.

## What was awkward

1. **Every expression must be a function, and nothing warns you.** If you forget `() =>`, the value
   renders correctly once and then never updates. The page looks fine on first load, so only a test
   that waits for a poll catches it. With the compiler, this whole class of bug does not exist.
2. **The automatic JSX runtime (`--jsx=automatic --jsx-import-source=solid-js/h`) is broken for
   real pages.** It passes `children` inside props, so `spread` and `assign` insert all of an
   element's children through one shared effect. When any reactive sibling changes, such as a
   `<Show>` in the status line, that effect re-runs and disposes the bindings of every other child.
   That was my first build, and the status line was stuck on "0 agents working". esbuild's classic
   transform (`jsx: "transform", jsxFactory: "h", jsxFragment: "h.Fragment"`) calls
   `h(tag, props, ...children)`, and `h` then gives each child its own `insert`. Use that.
3. **`h()` is lazy, and that breaks `<For>` rows without a workaround.** `h()` returns a function
   that builds the element when first called. A `<For>` row callback therefore returns an unbuilt
   element. The row is built later, inside whichever effect inserts the list, and it is owned by that
   effect rather than by the row's own root. Each poll changes the list, the effect re-runs, and
   every row's bindings are dropped. The DOM nodes stay, but their text freezes. This showed up as
   the grant times on the agent page stuck at "in 20777 days", computed while `now` was still 0.
   The fix is the `eager` wrapper around `For`, `Index`, `Show` and `Match`. It builds rows and
   branches inside Solid's own scope. It recognises unbuilt elements by `h`'s private symbol,
   which it finds with `Object.getOwnPropertySymbols(h("i"))[0]`. The wrapper is short, but it
   depends on an internal detail of the runtime. Nothing in the docs suggests the problem exists.
4. Function children must keep their arity. `Switch` and `Show` tell a callback child (`a => …`)
   from a plain child by `fn.length`, so the wrapper returns `(x, i) => …` and not `(...a) => …`.
5. There is no compile-time check of any of this. Getting it right took a test that removes a card
   and then changes another card's data mid-session (described below), not just a first render.

What was easier: the build. It is one 10-line esbuild script with 6 installed packages, runs in a
quarter of a second, and has no plugin to keep in step with Solid's releases. That matters with
Solid 2.0 out and `vite-plugin-solid` not supporting it yet.

## Size

| | `solid-h` | `../solid` |
| --- | --- | --- |
| `dist/app.js` | 54.1 kB | 49.5 kB |
| `dist/app.js`, `gzip -9 -c dist/app.js \| wc -c` | **20,043 B** | **17,482 B** |
| `dist/app.css`, gzip -9 | 5,520 B | 5,551 B |
| `package-lock.json` packages | 31 (6 installed: 5 plus one `@esbuild/*` binary; the other 25 are optional platform builds) | 106 |

Dropping Babel makes the JS **2.5 kB (15 %) bigger**, not smaller. The compiler turns JSX into cloned
`<template>`s and calls only the DOM operations each element needs, so unused code is tree-shaken
away. Hyperscript ships `h` itself, plus the generic `spread`/`assign`/`assignProp` machinery: every
property, attribute, event, `style` and `classList` path, and the alias tables. It also builds
elements one at a time instead of cloning templates. The saving is all at build time: 75 fewer
lockfile packages, 73 MB less `node_modules`, and no compiler plugin.

## Checks

These ran against `node ../serve.mjs solid-h 8821`, with `../solid` on 8822 for comparison, in
Playwright Chromium.

| | `/` | `#agents` | `#agent/run_01JDRELEASEQQQQQQQQQQQQQQQ` |
| --- | --- | --- | --- |
| console errors / CSP violations | none | none | none |
| count | 8 request cards | 11 runs | 3 log lines |
| same DOM node after 3 s (every card, row and log line, tagged) | 19/19 | 19/19 | 23/23 |
| status line equals `../solid`'s | yes | yes | yes |

The status line read "6 agents working · 10 requests waiting for you · 6 problems" on both. The whole
`<main>` text matched `../solid`'s too. The only differences were relative times a minute apart,
because the pages loaded seconds apart. The identity toggle (`button.idname`) still works after
the polls.

An extra check rewrote `/api/state` in the browser: it dropped the first card, then changed another
card's reason. Both builds kept the 7 remaining cards as the same nodes, showed the new reason, and
updated the status line to "9 requests waiting". Before the `eager` wrapper, this case left the
remaining cards' text frozen.
