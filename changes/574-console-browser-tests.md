---
area: Development
type: Added
---
- `ci/console-browsers.sh` runs the console as `wicket serve` sends it in Chromium, Firefox and WebKit,
  against the preview's mock API, failing on an error, a CSP violation, a Trusted Types report, a card
  replaced by an unchanged poll or a page that scrolls sideways; CI runs it when the console changes.
  `wicket dev console-assets DIR` writes the page, its files and its headers for it
  ([#574](https://github.com/public/wicket/issues/574)).
