# Console frameworks (#574): plain JS, Vue, Preact, Svelte, Solid or Lit?

**Question.** The console is about 1,900 lines of hand-written DOM code. The operator allowed a small,
fast framework for the redesign (`docs/explanation/console-design.md`), if it holds up. Which one, or
none?

**Method.** Each candidate builds the same three screens of the redesign: the Inbox with its request
cards, the Agents list, and an agent's page. They follow `SPEC.md`:
- the same CSS (`shared/console.css`), words and class names;
- the same mock API (`serve.mjs`, the console preview's fixture, with timestamps fixed as a ledger's
  are), under the console's CSP;
- a 2 s poll in which an unchanged card must stay the same DOM node;
- every API string set as text.

"vanilla" is the same three screens in plain DOM code, the way the console is written today, and
"baseline" is today's whole console (every view, plus its `/api/me` round trip), for reference. The five
framework prototypes were written by separate agents from the same brief; vanilla was then ported
from the Preact one, screen for screen. `preact-esbuild`, `lit-esbuild` and `solid-h` are the same
code with a smaller build (see "Size optimisation"). The framework prototypes each have a `NOTES.md`
on what was easy and awkward.
- `measure.mjs` loads each one cold, 7 times, on a phone profile: 390×844 at DPR 2, the CPU slowed
  4×, and Lighthouse's slow 4G (150 ms RTT, 1.6 Mbit/s down). It reports medians.
- `static.sh` builds each from clean twice: size, packages, build time and whether the bytes repeat.

Everything ran on one shared 4 vCPU box, on 2026-11-20, one candidate at a time with nothing else running.

## Results

Medians of 7 cold loads on the throttled phone profile, then the static build measures. The first-card
range is the fastest and slowest of the 7.

| candidate | first card (ms) | range | first paint (ms) | script per 2 s poll (ms) | JS heap (KB) | elements | JS gzip (B) | packages, all (shipped) |
|---|---|---|---|---|---|---|---|---|
| plain JS (esbuild) | 1143 | 1121–1214 | 616 | 1.9 | 1946 | 333 | 8,364 | 27 (0) |
| Lit (lit-html, Vite) | 1152 | 1110–1193 | 1072 | 2.3 | 2137 | 322 | 12,231 | 49 (2) |
| Lit (lit-html, esbuild) | 1176 | 1132–1228 | 1104 | 2.4 | 2137 | 320 | 12,432 | 29 (2) |
| Preact (Vite) | 1201 | 1141–1252 | 716 | 8.9 | 2178 | 315 | 13,866 | 48 (1) |
| Preact (esbuild) | 1233 | 1160–1290 | 708 | 9.6 | 2179 | 315 | 14,056 | 28 (1) |
| Solid (Vite, Babel plugin) | 1294 | 1240–1440 | 796 | 2.1 | 2805 | 483 | 17,482 | 106 (4) |
| Solid (`solid-js/h`, esbuild) | 1349 | 1321–1652 | 808 | 2.1 | 2978 | 483 | 20,043 | 31 (4) |
| Vue (Vite) | 1654 | 1638–1678 | 976 | 2.2 | 2658 | 318 | 32,219 | 67 (23) |
| Svelte (Vite) | 1684 | 1643–1720 | 900 | 10.4 | 2533 | 317 | 24,858 | 71 (19) |
| *today's whole console (reference)* | 1853 | 1779–2014 | 684 | 2.2 | 2240 | 1012 | 35,946 unminified | 0 |

**Fairness.** An earlier draft of this note compared an unminified plain-JS prototype that lacked
features the others had; it was withdrawn. Now:
- every prototype is checked by `parity.mjs`: the visible text and the visible buttons, links and
  disclosures of all three screens, with every disclosure open, match Preact's (times masked). All
  nine match;
- every bundle is minified for production (ES2022, no source map), and every candidate makes the same
  requests (Lit and Svelte had made an extra `/api/me` call; removed);
- plain JS's own `h()` and `keyed()` (about 60 lines, the work a framework does) count in its lines;
  only `helpers.js`, the same domain helpers in every candidate, is left out;
- "today's whole console" is not a candidate: it builds every view (three times the elements) and is
  unminified. It is there to show where the console starts from.

**What the numbers say.**
- **Plain JS, Lit and Preact tie to the first card**: 1143, 1152 and 1201 ms, with the ranges
  overlapping. Solid is about 0.15 s behind; Vue and Svelte about 0.5 s, because starting their
  larger runtime is the cost on a 4× slower CPU.
- **Lit paints late** (about 1.1 s against 0.6–0.7 s): it paints nothing before its first render.
- **Per poll**, Preact and Svelte re-render the tree and spend 9–10 ms of script every 2 s on the
  slowed CPU (under 0.5% of it); the others about 2 ms. Neither matters to a person.
- **Memory** is 1.9–3.0 MB of JS heap for all of them.
- Every candidate passed every check: no console errors, no CSP violations (no `eval`, no inline
  script or style), cards kept across polls, and the same bytes on a clean rebuild.

### Size optimisation: what Babel, Vite and the compilers cost

The question was whether each build carries tooling it doesn't need.
- **Babel is needed only by Solid**: its JSX compiler is a Babel plugin (`babel-preset-solid`), 18
  `@babel/*` packages of its 106. Vue's SFC compiler uses `@babel/parser` only (4 packages). Preact,
  Lit and Svelte use none: Vite 8 transforms JSX with Oxc.
- **Solid without Babel** (`solid-h`: esbuild turns JSX into `solid-js/h` calls) drops 75 packages,
  but the bundle grows 2.5 KB and starts about 50 ms later, because templates are built at run time,
  not compiled. Every reactive expression must also be wrapped by hand (120 `() =>` against 39); see
  `solid-h/NOTES.md`. `solid-js/html` is not an option: it uses `new Function`, which the CSP forbids.
- **Vite or esbuild alone** (`preact-esbuild`, `lit-esbuild`): about 20 fewer packages and a 0.7 s
  clean build instead of 1.3 s, for bundles 0.2 KB (1–2%) larger and no measurable change in speed.
- **Lit**: depending on `lit-html` alone instead of `lit` cut 2.5 KB (14.7 to 12.2 KB) and four
  packages; the prototype uses templates only, not `LitElement`.

### Build, supply chain and fit

| | Runtime packages shipped | Lockfile (all) | Compiler | Fits `ci/session-view.sh` |
|---|---|---|---|---|
| plain JS | 0 | 0 (27 if minified with esbuild) | none | nothing to build if shipped unminified, as today |
| Preact 11.2 | 1 (`preact`) | 48, or 28 with esbuild | none (Vite's own JSX transform) | yes: Vite 8.3.8, already pinned |
| Lit (lit-html 3.3) | 2 (`lit-html`, `@types/trusted-types`) | 49, or 29 with esbuild | none (tagged templates) | yes |
| Solid 1.9 | 4 | 106 (Babel), or 31 without | Babel plugin | yes, but Solid 2.0 shipped on 2026-11-17 and its plugin doesn't support it yet |
| Svelte 5.58 | 19 (the `svelte` package carries its compiler's deps) | 71 | Svelte compiler | yes |
| Vue 3.5 | 23 | 67 | Vue SFC compiler | **already in it**: `web/session` uses these exact versions, so it adds no new package to the repository |

Every framework would put the console behind a Node build, as the session view is today. CI builds
it from a committed lockfile with `npm ci --ignore-scripts`, checks licences and that two fresh builds
match, and the binary embeds the result (`WICKET_SESSION_VIEW`). `cargo build` itself fetches nothing.
That is the real cost of a framework here. Today the console is the one part of wicket that needs only
`cargo build`, and it is how an operator approves anything: a build without the bundle would have no
console, where today it has no session page only.

### Readability

Lines each author wrote (the line counts in the table below come from the authors' first versions;
`static.sh` gives today's), excluding the helpers copied from the reference (`strip`, `rel`, `asks`, `problemList`, and so on, the same in each):

| | Lines | What the authors said |
|---|---|---|
| Lit | 263 | No compiler, keyed lists by `repeat`, text by default. Whitespace in templates bites inline layouts, and there is no component-local state. |
| Svelte | 344 | Keyed `{#each}` is one line, and local state stays in the component. Logic in templates gets long, and spaces between inline elements need care. |
| Solid | 346 | `reconcile` and `<For>` keep nodes with no caches. You must know not to destructure props, that resources throw on error, and that records need an id. |
| Preact | 371 | Keys make node-keeping free, and JSX reads like the HTML. Hooks rules, and `&&` with numbers, need care. |
| Vue | 397 | Templates and keyed `v-for`, all at build time; the most familiar to most people. More files (nine components). |
| plain JS | 330 | Its own `h()` and `keyed()` included. Every "keep this node" rule is hand-written: the two bugs this work found in the real console were both of that kind (rows rebuilt every poll, times gone stale in kept rows). |

### Complexity: is plain JS more code to maintain?

`complexity.mjs` counts every candidate's own source the same way, templates included (logic in a
Vue or Svelte template counts as much as logic in a script), leaving out the shared domain helpers.
"Size" is syntax nodes, which doesn't depend on formatting: markup counts one per element, attribute
and text run in every form (JSX, templates, Lit literals). "Branches" counts every condition and every
loop however it is written: `if`, `?:`, `&&`, `.map()`, `repeat()`, `<Show>`, `<For>`, `v-if`, `v-for`,
`{#if}`, `{#each}`. "Writes" are state changes made by hand, setter calls included. "DOM calls" are uses
of the browser's DOM API by name. As a check, one small component written in all six styles scores
the same 2 branches each, and 48–58 nodes.

| candidate | lines | size (nodes) | branches | worst unit | functions | writes | DOM calls |
|---|---|---|---|---|---|---|---|
| Lit | 243 | 3,644 | 188 | 34 | 62 | 18 | 2 |
| Solid | 346 | 3,692 | 171 | 28 | 87 | 8 | 3 |
| Preact | 371 | 3,932 | 189 | 37 | 64 | 16 | 0 |
| Svelte | 310 | 4,125 | 180 | 41 | 32 | 19 | 2 |
| plain JS | 285 | 4,439 | 223 | 37 | 71 | 35 | 39 |
| Vue | 382 | 4,550 | 190 | 20 | 48 | 17 | 0 |
| *plain JS, screens only (without `h`, `keyed`, live times)* | 235 | 3,892 | 190 | 37 | 62 | 29 | 22 |

- **Plain JS is more to maintain, though not by much in size.** It is 8–22% more code than Lit,
  Solid and Preact, has the most branches (223 against 171–190), about twice the state written by
  hand, and is the only one managing the page itself (39 DOM calls against 0–3).
- The difference is mostly its framework-like part: without `h`, `keyed` and the live times, the
  screens alone are Preact's size and branches. That part is fixed (about 60 lines), but it is where
  the hand-written caching lives, and both bugs this work found in the real console were there.
- **Lit is the smallest**; Vue is the largest but splits best (its busiest unit has 20 branches,
  against 28–41).

### Unthrottled

On a desktop with no throttling, the first card arrives in 85–102 ms for plain JS, Lit, Vue and
Preact alike (`results/runtime-unthrottled.md`). The differences above exist only on a slow phone.

### Without a build: Lit as committed files

`lit-html` publishes minified browser modules, so Lit needs no Node build: `lit-nobuild/` commits
lit-html 3.3.3's four files (`lit-html.js`, `directive.js`, `directive-helpers.js`,
`directives/repeat.js`: 4.4 KB gzip, BSD-3-Clause, unchanged) and loads the app as native modules,
with `modulepreload` so they arrive at once. `vanilla-nobuild/` does the same for plain JS, as the
console is served today. Both match the reference (`parity.mjs`).

| candidate | first card (ms) | first paint (ms) | JS gzip, all files |
|---|---|---|---|
| plain JS, no build | 1163 | 724 | 11.6 KB |
| plain JS, esbuild | 1199 | 628 | 8.4 KB |
| Lit, no build | 1288 | 1212 | 16.5 KB |
| Lit, Vite | 1159 | 1060 | 12.2 KB |

(One run, the four together; the same builds' medians moved by up to 56 ms between runs.) Lit without a
build costs about 0.1 s on the slow phone. Its late first paint is the prototype's, not the
library's, as far as I can tell (about 70% confident): Lit's page is empty until its first render,
where plain JS's `index.html` holds the header and tabs. That is untested.

### Vercel's UI SDK

Vercel Labs released UI SDK in beta on 2026-11-12 (`@ui-sdk/core`, `@ui-sdk/web` and adapters for
React, Vue, Svelte and Solid; 0.1.0-beta.13 when tested, Apache-2.0). It is not a rendering framework
like the others: it is a library of headless, accessible behaviours (dialogs, menus, tabs, toasts,
comboboxes, about 50) with keyboard, focus and screen reader support, plus an "agent bridge" that lets
an AI agent read and operate the page's components.

Tested with `@ui-sdk/web` (its web components, no framework), bundled and minified with esbuild
(`ui-sdk/`: `npm ci`, `node build-and-size.cjs`, then `node check.cjs` to load it under the CSP):
- **Size**: the dialog alone is 48.6 KB gzip; dialog, tabs and toast together 64.7 KB, plus 12.6 KB of
  CSS. That is more than the whole Vue prototype, for three widgets.
- **CSP**: they work (the dialog opens, takes focus and closes on Escape; tabs switch), but setting
  inline styles breaks the console's CSP 31 times on one page; it would need `style-src
  'unsafe-inline'`. One component (`token-input`) also writes `innerHTML`.
- **Fit**: an agent bridge is the wrong direction for this console: its whole job is to be the place
  where a person, not an agent, decides. Actions still need a passkey signature, so a bridge couldn't
  approve anything, but it would be one more surface to keep out.
- No dependencies, and no `eval`. It is a beta: its README says the API may change.

Not a candidate for the console. Its behaviours might be worth reading for accessibility details.

## Verdict

**Recommended: Lit (`lit-html` only), committed as files with no build** (about 60% confident).
Plain JS is a close second.

- It answers the worry about plain JS. Lit is the least code (3,644 nodes against plain JS's 4,439),
  needs no DOM code by hand (2 calls against 39), and keeps rows across polls with `repeat()` instead
  of a hand-written cache, which is where this work's bugs were.
- It keeps what plain JS had: `cargo build` alone gives a working console. The four vendored files are
  4.4 KB gzip; there is no compiler, and nothing runs at build time.
- It costs about 0.1 s to the first card on a slow phone (none on a desktop), and one vendored
  dependency to keep current.

Plain JS stays reasonable if no dependency at all is the rule. Vue is close in code shape (the best
split, no DOM by hand) and already in the repository, but is 0.5 s slower on a phone and needs its
compiler, so a Node build. Preact, Solid and Svelte add a build step without a gain over Lit here.

If this fails, the likely causes: Lit's late first paint is not just the prototype's (test: put the
header and tabs in `index.html`, as plain JS does); the vendored copy falls behind (needs a check, as
`ci/session-view.sh` checks its lockfile); or template whitespace quirks in inline layouts (the Lit
author's main complaint).

## Files

- `SPEC.md`: what each prototype builds.
- `serve.mjs`, `measure.mjs`, `static.sh`, `parity.mjs`, `complexity.mjs`: the mock, the measurements,
  the check that every candidate shows the same thing, and the code measures.
- `ui-sdk/`: the Vercel UI SDK size and CSP check.
- `fixture.js`: a copy of the console preview's made-up data, so the experiment runs on its own.
- `results/`: the tables (`runtime.md`, `runtime-unthrottled.md`, `static.md`, `complexity.md`) and their JSON.
- `<candidate>/`: each prototype and its `NOTES.md`. `npm ci && npm run build`, then
  `node serve.mjs <candidate>` to try it.
