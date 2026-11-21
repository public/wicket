// What the console's views (inbox.js, agents.js, activity.js, settings.js) draw with: lit-html
// helpers shared by them (#574). Every string goes in as a template value, set as text.
import { html, render, nothing } from "lit-html";

// lit-html renders after what a container already holds: the first time, it is emptied of the
// page's own placeholder.
const owned = new WeakSet();
export function draw(value, box) {
  if (!owned.has(box)) { box.replaceChildren(); owned.add(box); }
  render(value, box);
}

// A time: the text given (else its local time and how long ago), its exact time in `title` and
// `datetime`.
export const time = (t, text, cls) => html`<time class=${cls || nothing} title=${t ? iso(t) : nothing} datetime=${t ? iso(t) : nothing}>${text === undefined ? at(t) : text}</time>`;

// A label and its value, on a row.
export const kv = (k, v) => html`<div class="row"><span class="meta">${k}</span><span class="mono">${strip(v)}</span></div>`;

// A URL broken only after its slashes and dots, so it wraps at a segment, not mid-word.
export const wrapped = (cls, text) => html`<div class=${cls}>${String(text).split(/(?<=[/.?&])/).map(part => html`${part}<wbr>`)}</div>`;

// A command to run on the host, with a Copy button (#715 review): one tap copies it whole.
export const copyButton = cmd => html`<button type="button" class="link copy" aria-label=${"Copy " + cmd} @click=${async () => {
  try { await navigator.clipboard.writeText(cmd); toast("Copied: " + cmd); } catch { toast("Couldn't copy here; select the command instead.", true); }
}}>Copy</button>`;

// A sentence with `commands` in backticks as code spans (#648), the rest text; those in `copy` are
// instructions to run, each with a Copy button (#715 review).
export const code = (text, copy = []) => String(text).split("`").map((part, i) => !part ? nothing
  : i % 2 === 0 ? part : html`<code>${part}</code>${copy.includes(part) ? copyButton(part) : nothing}`);

// Server text with UTC times in it, in the page's local time; the original in `title` (#707 review).
const hasUtc = text => { const r = UTC_TIME.test(String(text)); UTC_TIME.lastIndex = 0; return r; };
export const serverText = (cls, text) => html`<span class=${cls} title=${hasUtc(text) ? strip(text) : nothing}>${localTimes(text)}</span>`;
export const serverLine = (cls, text) => html`<div class=${cls} title=${hasUtc(text) ? strip(text) : nothing}>${localTimes(text)}</div>`;

// Elements made by console.js's helpers (a principal or a run id that a tap shows whole, a time that
// refreshRel keeps true) kept across draws by a key, so a tapped one stays open after a poll. One per
// list: `get` while drawing it, then `done`, which forgets those not asked for.
export function keeper() {
  let was = new Map(), now = new Map();
  return {
    get(key, make) { const e = now.get(key) || was.get(key) || make(); now.set(key, e); return e; },
    done() { was = now; now = new Map(); },
  };
}
