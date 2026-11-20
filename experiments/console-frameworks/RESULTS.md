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
- `measure.mjs` loads each one cold, 7 times, on a phone profile: 390×844 at DPR 2, the CPU slowed to
  a Pixel 8 Pro's (1.4× here; the first runs used 4×), and Lighthouse's slow 4G (150 ms RTT,
  1.6 Mbit/s down). It reports medians. `UNTHROTTLED=1` runs the same with no slowdown.
- `static.sh` builds each from clean twice: size, packages, build time and whether the bytes repeat.

Everything ran on one shared 4 vCPU box, on 2026-11-20, one candidate at a time with nothing else running.

## Results on a Pixel 8 Pro profile

Every measure of every build, all from one run (2026-11-20, one candidate at a time, nothing else
running): `results/all.md`, built by `combine.mjs`. Svelte and Vue were dropped by the operator after
the first results below and are not in this run.

**Profile.** The CPU slowdown is calibrated to a Pixel 8 Pro: `speedometer.mjs` runs Speedometer 3.0
in this machine's Chromium. Unslowed it scores 15.1 ± 0.9; slowed 1.6× 7.84 ± 0.51; slowed 1.4×
9.72 ± 0.54, against about 9.5 reported for a Pixel 8 Pro's Chrome (one owner's run, early 2024;
Google kept reviewers from benchmarking the Tensor G3, and Chrome has got faster since, so this is if
anything slow). The network is unchanged: slow 4G, 150 ms RTT, 1.6 Mbit/s down. 390×844 at DPR 2.
"Desktop" is the same with no slowdown at all. Medians of 7 cold loads.

| candidate | first card, phone (ms) | range of 7 | first paint, phone (ms) | script per poll, phone (ms) | JS heap (KB) | elements | first card, desktop (ms) | JS gzip (B) | CSS gzip (B) | npm packages (shipped) | node_modules | clean build (s) | Node needed to build | size (nodes) | branches | worst unit | writes by hand | DOM calls |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain JS, esbuild | 1009 | 1004–1036 | 572 | 0.7 | 1946 | 333 | 102 | 8364 | 5520 | 27 (0) | 12M | 0.5 | yes | 4439 | 223 | 37 | 35 | 39 |
| Preact, esbuild | 1013 | 1003–1031 | 652 | 2.7 | 2179 | 315 | 105 | 14056 | 5520 | 28 (1) | 13M | 0.7 | yes | 3932 | 189 | 37 | 16 | 0 |
| Preact, Vite | 1016 | 1001–1029 | 648 | 2.9 | 2162 | 315 | 111 | 13866 | 5560 | 48 (1) | 66M | 1.3 | yes | 3932 | 189 | 37 | 16 | 0 |
| Lit (lit-html), esbuild | 1020 | 1014–1034 | 940 | 0.8 | 2137 | 320 | 106 | 12432 | 5520 | 29 (2) | 14M | 0.7 | yes | 3644 | 188 | 34 | 18 | 2 |
| Lit (lit-html), Vite | 1023 | 1015–1041 | 932 | 0.7 | 2137 | 322 | 95 | 12231 | 5573 | 49 (2) | 68M | 1.3 | yes | 3644 | 188 | 34 | 18 | 2 |
| plain JS, no build | 1024 | 1014–1043 | 664 | 0.7 | 1955 | 334 | 95 | 11637 | 7288 | 0 (0) | 0 | 0 (none) | no | 4439 | 223 | 37 | 35 | 39 |
| Solid, Vite (Babel) | 1061 | 1044–1516 | 724 | 0.8 | 2805 | 483 | 118 | 17482 | 5551 | 106 (4) | 88M | 2.4 | yes | 3692 | 171 | 28 | 8 | 3 |
| Lit (lit-html), no build (4 files committed) | 1071 | 1042–1079 | 1048 | 0.7 | 2159 | 327 | 95 | 16392 | 7288 | 0 (1) | 0 | 0 (none) | no | 3644 | 188 | 34 | 18 | 2 |
| Solid, esbuild (no Babel) | 1516 | 1084–1524 | 740 | 0.8 | 2982 | 483 | 116 | 20043 | 5520 | 31 (4) | 15M | 0.6 | yes | 3692 | 171 | 28 | 8 | 3 |
| today's console on main (reference) | 1530 | 1508–1552 | 436 | 0.8 | 2061 | 569 | 109 | 25581 | 3114 | 0 (0) | 0 | 0 (none) | no | – | – | – | – | – |

- **The network sets the time, not the framework.** Every build under about 14 KB of JavaScript shows
  the first card in 1.01–1.07 s, and the same build moves by about 30 ms between loads: they tie.
  On a desktop all of them take 95–118 ms.
- **A file over about 14 KB costs a round trip.** Solid without Babel (20 KB) took about 1.5 s in 6 of
  7 loads, Solid with Babel (17.5 KB) in 1 of 7, and today's console on main (25.6 KB, unminified)
  in all 7. A new TCP connection sends about 14.6 KB (10 segments) before it waits for an
  acknowledgement, and the 0.45–0.5 s steps are three of these 150 ms round trips; this is the likely
  cause (about 60% confident). Lit without a build is 16.4 KB but in five files fetched at once, and
  paid nothing. For the console, staying under about 14 KB per file matters more than the framework.
- **First paint**: plain JS and Preact at 0.57–0.66 s, Lit at 0.93–1.05 s. The cause was the Lit
  prototype, not Lit: its `boot()` waited for the first `/api/state` before drawing anything, so the
  page stayed blank for a round trip, where plain JS's `index.html` already holds the header and tabs.
  `lit-nobuild-paint/` draws once before that fetch (one line). In one run of the three:

  | Pixel 8 Pro, slow 4G | first card (ms) | first paint (ms) |
  |---|---|---|
  | Lit, no build | 1068 | 1048 |
  | Lit, no build, drawn before the fetch | 1064 | 740 |
  | plain JS, no build | 1013 | 660 |

  The 80 ms left is Lit's modules arriving and running before the header can be drawn; the header
  and tabs as plain HTML in `index.html` would remove it. (`LOAD_ONLY=1 node measure.mjs` checks
  loading alone in about 2 s a load; it gave the same: 744 and 660 ms.)
- **Script per poll** is under 3 ms for all, and **memory** 1.9–3.0 MB.
- **Code to maintain** and **build cost** are as in the sections below: Lit is the least code; plain JS
  the most, and the only one managing the DOM by hand; only the two no-build variants keep the
  console buildable by `cargo build` alone.
- Tested in Chromium only; Firefox and Safari are unverified.

## First results (CPU slowed 4×)

The first runs slowed the CPU 4× (Lighthouse's default), a phone about 2.5 times slower than a Pixel
8 Pro by Speedometer, and included Svelte and Vue. Kept for the record (`results/runtime-4x.md`);
the tables in "Complexity", "Without a build" and the sections after it come from these runs too.


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

An earlier unthrottled run of plain JS, Lit, Vue and Preact gave 85–102 ms to the first card; the
Pixel 8 Pro run's desktop column (95–118 ms, every build) replaces it (`results/runtime-unthrottled.md`).

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
(`ui-sdk/`: `npm install --ignore-scripts`, `node build-and-size.cjs`, then `node check.cjs` to load it under the CSP):
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

### Minified by Oxc from Rust: `cargo build` alone

The operator accepted a build step but wants `cargo build` to fetch whatever it needs, as it fetches
crates; Cargo can't fetch npm packages, and a `build.rs` that ran `npm ci` would use the network
mid-build (breaking `cargo build --offline`, `cargo vendor` and sandboxed builders) and need Node on
every build machine. Oxc, the JS toolchain under Vite 8, is published as Rust crates. `oxc-minify/`
(20 lines, `oxc_minifier` 0.158.0, the newest at least 7 days old) minifies each ES module as a
`build.rs` would; `lit-oxc/` is `lit-nobuild-paint` with its two modules minified so. It matches the
reference (`parity.mjs`). Load-only, one run of the four (Pixel 8 Pro profile):

| | first card (ms) | first paint (ms) | JS gzip | the build needs |
|---|---|---|---|---|
| Lit, Oxc from Rust | 1026 | 704 | 13.7 KB, 4 files | cargo |
| Lit, esbuild | 1022 | 928* | 12.4 KB, 1 file | Node and 29 npm packages |
| Lit, no build | 1071 | 740 | 15.7 KB, 5 files | nothing |
| plain JS, esbuild | 1018 | 576 | 8.4 KB, 1 file | Node |

\* without the draw-before-fetch fix.

Oxc shrinks Lit's code less than a bundler might: the HTML inside `html` templates is left as written.
It doesn't bundle, so the browser loads a few small modules (preloaded together), which a console split
by view wants anyway. Its cost: about 60 crates new to wicket's lockfile, about 30 s on a clean build
(then 18 ms a file, even in a debug build), and weekly 0.x releases whose API moves, so it is pinned
exactly. **The operator chose this: Oxc in `build.rs`, lit-html committed with its hashes.**

## Verdict

**Chosen by the operator: Lit (`lit-html` only), its files committed, the console's modules minified
by Oxc in `build.rs`** (see the section above). It had been recommended as committed files with no
build; the operator accepted a build step as long as `cargo build` stays the only one.

- On the target phone, speed doesn't separate them: both no-build variants show the first card in
  1.02–1.07 s, and on a desktop in 95 ms.
- Lit is the least code (3,644 nodes against plain JS's 4,439), needs no DOM code by hand (2 calls
  against 39), and keeps rows across polls with `repeat()` instead of a hand-written cache, which is
  where this work's bugs were.
- Both keep `cargo build` alone giving a working console. Lit's four vendored files are 4.4 KB gzip;
  there is no compiler, and nothing runs at build time. They need a pinned version, hashes and a CI
  check, as the session view's lockfile has.
- Whatever is chosen, keep each file the console loads under about 14 KB gzip, or the first visit pays
  an extra round trip (about 0.5 s on slow 4G).

Preact ties on speed but adds a build step; Solid adds Babel or crosses the 14 KB line. Vue and Svelte
were dropped.

Lit's late first paint was the prototype's (see above): draw before the first fetch, and put the
header and tabs in `index.html`.

If this fails, the likely causes: the vendored copy falls behind; template whitespace quirks in
inline layouts (the Lit author's main complaint); or Firefox or Safari behave differently (untested).

## Files

- `SPEC.md`: what each prototype builds.
- `serve.mjs`, `measure.mjs`, `static.sh`, `parity.mjs`, `complexity.mjs`: the mock, the measurements,
  the check that every candidate shows the same thing, and the code measures.
- `ui-sdk/`: the Vercel UI SDK size and CSP check.
- `speedometer.mjs`: the Pixel 8 Pro calibration. `combine.mjs`: every measure in one table.
- `fixture.js`: a copy of the console preview's made-up data, so the experiment runs on its own.
- `results/`: the tables (`runtime.md`, `runtime-unthrottled.md`, `static.md`, `complexity.md`) and their JSON.
- `<candidate>/`: each prototype and its `NOTES.md`. `npm install --ignore-scripts && npm run build`
  (`lit-nobuild` and `vanilla-nobuild`: `./build.sh`), then `node serve.mjs <candidate>` to try it.

**Lockfiles.** Every build was measured from a committed `package-lock.json`; the lockfiles were then
removed (#737 review), so that the repository's dependency tooling doesn't scan or update code wicket
won't ship. Each `package.json` keeps exact versions, but an install today resolves their own
dependencies afresh and may get newer versions than were measured. The package counts in the tables
are from the lockfiles as measured. `lit-nobuild` needs no install: its four lit-html files are
committed.
