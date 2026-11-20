---
area: Development
type: Added
---
- `experiments/console-frameworks/` compares building the console redesign in plain JS, Lit,
  Preact, Solid, Svelte and Vue: the same three screens in each, checked to show the same text and
  controls, measured cold on a throttled phone and on a desktop, with sizes, packages, build cost and
  code complexity. It also tests Vercel's UI SDK. It recommends Lit (`lit-html` only), committed as
  files with no build step ([#574](https://github.com/public/wicket/issues/574)).
