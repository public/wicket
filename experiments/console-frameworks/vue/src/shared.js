// Helpers copied from the reference console (crates/wicket-cli/src/serve/static/console.js), the same in
// every candidate. Only `line` changed shape: it returns the log line as data (time, tag, tone, text)
// instead of building the element, so a template can render it.

// The same set as wicket_core::text::is_unsafe: C0, DEL, C1, bidi, zero-width, line separators (#128).
export const strip = s => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, " ");
let skewSecs = 0;
export const setSkew = now => { if (typeof now === "number") skewSecs = now - Date.now() / 1000; };
export const nowSecs = () => Date.now() / 1000 + skewSecs;
export const plural = (n, one, many) => n + " " + (n === 1 ? one : (many || one + "s"));
export function rel(t, now) {
  const d = t - (now === undefined ? nowSecs() : now), a = Math.abs(d);
  if (a < 5) return "just now";
  const v = a < 90 ? Math.round(a) + " s" : a < 5400 ? Math.round(a / 60) + " min" : a < 172800 ? Math.round(a / 3600) + " h" : plural(Math.round(a / 86400), "day");
  return d > 0 ? "in " + v : v + " ago";
}
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function clock(t, now) {
  const d = new Date(t * 1000), n = new Date((now === undefined ? nowSecs() : now) * 1000);
  const hm = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  if (d.toDateString() === n.toDateString()) return hm;
  if (Math.abs(d - n) < 6 * 86400000) return DAYS[d.getDay()] + " " + hm;
  return d.getDate() + " " + MONTHS[d.getMonth()] + (d.getFullYear() !== n.getFullYear() ? " " + d.getFullYear() : "") + " " + hm;
}
export const iso = t => new Date(t * 1000).toISOString().replace(/\.\d+Z$/, "Z");
export const at = (t, now) => t ? clock(t, now) + " (" + rel(t, now) + ")" : "\u2014";
export const riskClass = r => ({ R0Read: "r0", R1ReadScoped: "r1", R2WriteReversible: "r2", R3ExternalOrIrreversible: "r3", R4ExecOrPrivilege: "r4" })[r] || "r4";
export const riskLabel = r => ({ R0Read: "Only reads", R1ReadScoped: "Only reads", R2WriteReversible: "Changes data that can be put back", R3ExternalOrIrreversible: "Others will see it, or it can't be undone", R4ExecOrPrivilege: "Pushes code, deploys, or gains privileges" })[r] || strip(r);
export const riskCode = r => ({ R0Read: "R0", R1ReadScoped: "R1", R2WriteReversible: "R2", R3ExternalOrIrreversible: "R3", R4ExecOrPrivilege: "R4" })[r] || strip(r);
export function money(v) {
  const m = /^\$(\d+)(?:\.(\d+))?$/.exec(String(v ?? "").trim());
  if (!m) return strip(v);
  const frac = (m[2] || "").replace(/0+$/, "").padEnd(2, "0");
  return "$" + m[1] + "." + frac;
}
export const microUsd = u => money("$" + (Number(u || 0) / 1e6).toFixed(6));
export function principalName(p) {
  const x = String(p || "");
  const op = /\/op\/((?:unix|passkey)\/[^/]+)$/.exec(x);
  if (op) return strip(op[1]);
  const ag = /\/z\/([^/]+)\/a\/([^/]+)$/.exec(x);
  if (ag) return strip(ag[2]) + " (zone " + strip(ag[1]) + ")";
  return strip(x);
}
export const span = secs => { const s = Math.round(secs || 0); return s >= 3600 && s % 3600 === 0 ? (s / 3600) + (s === 3600 ? " hour" : " hours") : Math.round(s / 60) + " min"; };
const shortText = id => id.length > 18 ? id.slice(0, 10) + "\u2026" + id.slice(-6) : id;
export function asks(p) {
  const raw = strip(p.method + " " + p.host + p.path);
  if (p.host !== "wicket.internal") return { what: raw + (p.scope_prefix ? "\u2026  (every path under it)" : ""), raw: "", why: strip(p.reason), internal: false };
  const seg = String(p.path || "").split("/").filter(Boolean).map(strip);
  let what = raw, why = strip(p.reason);
  if (p.method === "CAPACITY") {
    const m = /^capacity lease ([^:]+): ([\s\S]*?)\. Asked by the agent: ([\s\S]*)$/.exec(String(p.reason || ""));
    what = m ? "Lease a node: " + strip(m[2]) : "Lease a node (" + seg.slice(1).join("/") + ")";
    if (m) why = strip(m[3]);
  } else if (p.method === "SPAWN" && seg[0] === "zones") what = "Start a child agent" + (seg[2] ? " named " + seg[2] : "") + " in zone " + seg[1];
  else if (p.method === "LINK" && seg[0] === "links") what = "Link " + shortText(seg[1]) + " \u2192 " + shortText(seg[2]) + (seg[3] ? ", port " + seg[3] : "");
  else if (p.method === "UPDATE" && seg[0] === "self") what = "Install wicket build " + String(seg[1] || "").slice(0, 12) + "\u2026";
  return { what, raw, why, internal: true };
}
export function verb(p) {
  if (/git-receive-pack$|service=git-receive-pack/.test(p.path || "")) return "push code to";
  if (/git-upload-pack$|service=git-upload-pack/.test(p.path || "")) return "fetch code from";
  return ({ GET: "read", HEAD: "read", OPTIONS: "read", POST: "send data to", PUT: "change", PATCH: "change", DELETE: "delete" })[String(p.method).toUpperCase()] || strip(p.method);
}
export function verbsOf(methods) {
  const v = [];
  for (const m of methods && methods.length ? methods : ["GET"]) { const w = verb({ method: m, path: "" }); if (!v.includes(w)) v.push(w); }
  return v.length > 1 ? v.slice(0, -1).join(", ") + " and " + v[v.length - 1] : v[0];
}
export const num = n => Number(n || 0).toLocaleString("en-US");
const byName = x => strip(String(x || "").replace(/^passkey:/, ""));
const by = b => b.by ? " by " + byName(b.by) + (b.signed ? ", signed with a passkey" : "") : "";
export const when = t => at(t);
export const whenMs = ms => ms ? at(ms / 1000) : "\u2014";
export const methodsText = m => (m || []).map(strip).join(", ") || "GET, HEAD";
export const pathsText = p => (p || ["/**"]).map(strip).join(" ");
export function ruleText(r) {
  r = r || {};
  return "{ host: " + strip(r.host) + ", methods: [" + (r.methods || []).map(strip).join(", ") + "], paths: [" +
    (r.paths || []).map(p => "'" + strip(p) + "'").join(", ") + "]" + (r.allow_dangerous ? ", allow_dangerous: true" : "") + " }";
}

export function problemList(s) {
  const out = [];
  const h = s.health || {};
  for (const n of h.nodes || []) for (const a of n.alerts || []) out.push(["bad", "Server " + strip(a), "#settings"]);
  if (h.control_disk_pct > 85) out.push(["bad", "The control host's disk is " + h.control_disk_pct + "% full", "#settings"]);
  const st = h.state_store;
  if (st) {
    for (const a of st.alerts || []) out.push(["warn", "Record backup: " + strip(a), "#settings"]);
    if (st.stream && st.stream.state !== "streaming" && st.stream.state !== "starting") out.push(["bad", "The record backup isn't running (" + strip(st.stream.state) + ")", "#settings"]);
  }
  for (const p of s.placed || []) if (p.past_lease && p.held_by) out.push(["warn", "Rented server " + strip(p.name) + " is still billing after its rental ended", "#settings"]);
  for (const m of ((s.secrets || {}).missing) || []) out.push(["warn", "Key " + strip(m.name) + " isn't set, and a task setup needs it", "#settings"]);
  return out;
}

function egressOf(op) {
  const b = op.body || {};
  if (op.kind === "op" && b.kind === "egress") return [b, ""];
  if (op.kind === "node.audit" && typeof b.body === "string") {
    try { const n = JSON.parse(b.body); if (n && n.kind === "egress") return [n, " (node)"]; } catch (e) { /* not a decision */ }
  }
  return null;
}
// An agent run by its agent's name where the latest list knows it; its id otherwise.
const runName = (runs, id) => { const x = (runs || []).find(r => r.id === id); return x ? (x.agent ? strip(x.agent) : "a program") : strip(id); };
// One record of activity as a sentence (#646), as data: { ts, tag, tone, text, why }.
export function line(op, runs) {
  const b = op.body || {};
  const r = op.run ? runName(runs, op.run) : "";
  const L = (tag, tone, text, why) => ({ ts: op.ts, tag, tone: tone || "", text, why: !!why });
  const eg = egressOf(op);
  if (eg) {
    const [x, where] = eg;
    const outcome = String(x.outcome || "?");
    const tone = outcome === "allow" || outcome === "spliced" ? "ok" : outcome === "pending" ? "pend" : "blocked";
    const said = ({ allow: "allowed", spliced: "allowed", pending: "waiting", forbidden: "blocked", denied: "blocked", deny: "blocked" })[outcome] || outcome;
    return L(said, tone, (r ? r + ": " : "") + verb(x) + " " + strip(x.host + x.path + where), op.run);
  }
  switch (op.kind === "op" ? "op." + b.kind : op.kind) {
    case "op.llm": return L("model", "", strip(b.model || "?") + " request #" + num(b.requests) + " \u2192 " + strip(b.status) +
      " \u00b7 " + num(b.input_tokens) + " in / " + num(b.output_tokens) + " out tokens" + (r ? " \u00b7 " + r : ""));
    case "op.box": return L("box", "pend", strip(b.what) + ": " + strip(b.detail) + (r ? " \u00b7 " + r : ""));
    case "decision": return L(b.decision === "approve" ? "you allowed" : "you refused", b.decision === "approve" ? "ok" : "blocked", strip(b.request) + by(b));
    case "decision.refused": return L("refused", "blocked", "a decision (" + strip(b.decision) + ") on " + strip(b.target) + " was refused" +
      (b.by ? " for " + strip(b.by) : "") + ": " + strip(b.why));
    case "grant.revoked": return L("revoked", "", "grant " + strip(b.grant) + " revoked" + by(b));
    case "standing.revoked": return L("revoked", "", "standing reach " + strip(b.standing) + (b.rule ? " (" + ruleText(b.rule) + ")" : "") + " revoked" + by(b));
    case "capacity.requested": return L("capacity", "pend", "capacity asked for" + (b.principal ? " by " + principalName(b.principal) : "") +
      (b.ask ? ": " + strip(b.ask) : "") + (b.lifetime_secs ? " for " + span(b.lifetime_secs) : "") + (b.request ? " (" + strip(b.request) + ")" : ""));
    case "lease.requested": return L("lease", "pend", "lease " + strip(b.lease) + " asked for" + (b.spec && b.spec.plan ? ": " + strip(b.spec.plan) + " in " + strip(b.spec.region) : "") +
      (b.hourly_cap_usd_micros ? ", at most " + microUsd(b.hourly_cap_usd_micros) + "/h" : "") + (b.duration_secs ? " for " + span(b.duration_secs) : "") +
      (b.request ? " (" + strip(b.request) + ")" : "") + (r ? " \u00b7 " + r : ""));
    case "operator.passkey_added": return L("passkey", "", "passkey " + strip(b.name) + " added via " + strip(b.via));
    case "run.start": return L("start", "", r + " started: agent " + strip(b.agent) + " in zone " + strip(b.zone));
    case "operator.message": case "session.prompt": return L("message", "", "a message of " + plural(b.chars || 0, "character") + " to " + r + by(b) + (b.via ? " in the " + strip(b.via) : ""));
    case "identity.revoked": return L("stopped", "blocked", r + " stopped" + by(b) + ": " + strip(b.reason));
    case "run.console_start": return L("started", "", r + " started from " + strip(b.manifest) + " by " + byName(b.by) + ", signed with a passkey");
    case "run.exit_cause": return L("failed", "blocked", r + " failed (exit status " + strip(b.code) + "): " + strip(b.cause));
    case "run.end": return L("finished", b.cause ? "blocked" : "", r + " " + (b.status === "exited" ? "finished" : strip(b.status)) + " after " + plural(b.model_requests || 0, "model call"));
  }
  if (op.kind === "node.audit") {
    let inner = "";
    try { inner = String((JSON.parse(b.body) || {}).kind || ""); } catch (e) { /* not JSON */ }
    return L("node", "", "node " + strip(b.node) + ": " + (inner ? strip(inner) : "a record") + (r ? " \u00b7 " + r : ""));
  }
  return L("record", "", strip(op.kind) + (r ? " \u00b7 " + r : ""));
}
