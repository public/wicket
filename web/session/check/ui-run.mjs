// Runs check-dist/ui.js (the session view's App, mounted) under jsdom: the page as a browser would
// have it, with fetch, passkeys and the WebSocket played by check/ui.ts. No real browser here; this
// is what renders, what each tap sends, and that agent text stays text.
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
  url: 'http://localhost:8787/session?run=run_s',
  pretendToBeVisual: true,
});
const w = dom.window;
w.matchMedia = (q) => ({ matches: q.includes('pointer: fine'), media: q, addEventListener() {}, removeEventListener() {} });
w.scrollTo = () => {};
for (const k of ['window', 'document', 'navigator', 'location', 'HTMLElement', 'Element', 'Node', 'Document', 'DocumentFragment', 'Text', 'Comment', 'HTMLInputElement', 'HTMLTextAreaElement', 'HTMLSelectElement', 'SVGElement', 'CustomEvent', 'Event', 'KeyboardEvent', 'MouseEvent', 'getComputedStyle', 'requestAnimationFrame', 'cancelAnimationFrame', 'matchMedia', 'scrollTo']) {
  Object.defineProperty(globalThis, k, { value: k === 'window' ? w : typeof w[k] === 'function' && /^[a-z]/.test(k) ? w[k].bind(w) : w[k], configurable: true, writable: true });
}
await import(new URL('../check-dist/ui.js', import.meta.url).href);
