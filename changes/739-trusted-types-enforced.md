---
area: Approvals and the console
type: Security
---
- The console enforces Trusted Types ([#739](https://github.com/public/wicket/issues/739)): its
  Content-Security-Policy now has `require-trusted-types-for 'script'; trusted-types lit-html vue
  wicket-sw`, so a browser refuses any write of a string to an HTML or script sink (`innerHTML` and
  the like). HTML reaches the page only through lit-html's templates or the session view's Vue, and
  the service worker's URL only through `wicket-sw`, which makes `/sw.js` and nothing else. It was
  reported only before. The browser tests check that such a write throws and that the service worker
  still registers, and now also mount a run's session view in Chromium, Firefox and WebKit.
