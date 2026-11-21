---
area: Approvals and the console
type: Changed
---
- `wicket serve` sends the console's text files Brotli-compressed to browsers that accept it,
  compressed once when wicket is built, and the originals to any that don't say so
  ([#574](https://github.com/public/wicket/issues/574)): the page and its files go from about 136 KB
  to 39 KB.
- Every file under `/static/` is now named by its content's hash and cached as immutable, the icons
  and the web app manifest too (the manifest moved from `/manifest.webmanifest` to
  `/static/manifest.<hash>.webmanifest`). The pages and `/sw.js` keep their names.
