---
area: Approvals and the console
type: Security
---
- The console enforces Trusted Types ([#739](https://github.com/public/wicket/issues/739)): its
  Content-Security-Policy now has `require-trusted-types-for 'script'; trusted-types lit-html
  wicket-sw`, so a browser refuses any write of a string to an HTML or script sink (`innerHTML` and
  the like). HTML reaches the page only through lit-html's templates, and the service worker's URL
  only through `wicket-sw`, which makes `/sw.js` and nothing else. It was reported only before.
- A run's session page has a policy of its own that allows only Vue's (`trusted-types vue`). Vue's
  passes any string through, so there what keeps an agent's text out of HTML is that the session
  view has no `v-html` or `innerHTML` binding; `ci/session-view.sh` now fails on one.
- The browser tests check that a raw write throws on each page, that enabling notifications
  registers the service worker with a trusted URL, and mount a run's session view in Chromium,
  Firefox and WebKit.
