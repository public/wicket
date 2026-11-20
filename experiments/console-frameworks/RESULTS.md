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

## Verdict

Three candidates tie on speed: plain JS, Lit and Preact. The choice is about upkeep against the build:

- **Plain JS (recommended, about 65% confident).** The fastest first paint, the smallest download,
  no dependency, and `cargo build` alone still gives a working console: the one screen an operator
  approves things on keeps no Node step between it and the binary. The cost is hand-written
  node-keeping; the `keyed()` and `h()` helpers from this prototype (about 60 lines) would go into the
  console with tests, so that each view stops writing its own.
- **Lit (lit-html only)**, if a library is wanted: keyed lists by `repeat`, text by default, no
  compiler, two packages. It needs the Node build the session view has (or a vendored, pinned copy of
  `lit-html`'s ES module, which this note did not test).
- **Preact**: as fast to the first card, JSX most people know; the same build cost, and 4× the
  script per poll (still invisible).

Not recommended: Solid (Babel, or slower without it, and 2.0 just changed its API), and Vue and
Svelte (0.5 s slower to the first card on a phone).

If this fails, the likely cause is the hand-written caching growing faster than its tests, which
would show as rebuilt-every-poll or stale-text bugs in new views. The check: every new view gets the
"same node across polls" test the prototypes already pass.

## Files

- `SPEC.md`: what each prototype builds.
- `serve.mjs`, `measure.mjs`, `static.sh`, `parity.mjs`: the mock, the measurements and the check
  that every candidate shows the same thing.
- `results/`: the tables (`runtime.md`, `static.md`, `runtime.json`).
- `<candidate>/`: each prototype and its `NOTES.md`. `npm ci && npm run build`, then
  `node serve.mjs <candidate>` to try it.
