<script setup>
// A run's authority, as the reference's showAuthority shows it: what it can reach first (its zone's
// rules, its live grants, the standing rules that apply to it, each with when it ends), then where it
// runs, and the token's internals under Details. Every string is text.
import { computed } from "vue";
import { strip, at, plural, verb, verbsOf, pathsText, whenMs, when, num, nowSecs } from "../shared.js";
import TimeEl from "./TimeEl.vue";

const props = defineProps({ a: Object, s: Object, run: String });
const t = computed(() => props.a.token || {});
// Each line: { text, pre, t, tText, note }: `pre` and the time are when it ends, `note` the rest.
const reach = computed(() => {
  const tk = t.value, now = nowSecs(), out = [];
  for (const r of tk.reach || []) out.push({ text: verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths),
    note: "from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "") });
  for (const g of (tk.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > now))) out.push({
    text: verb(g) + " " + strip(g.host + g.path), pre: "you allowed it; ends ", t: g.expires_at,
    note: (g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) + " · allowed by " + strip(g.approved_by || "?") +
      (g.reached_node === false ? " · not yet on its server" : "") });
  const row = (props.s.runs || []).find(x => x.id === props.run) || {};
  const rules = ((props.s.standing || {}).rules || []).filter(r => r.live && (r.for === "zone" ? r.zone === tk.zone :
    row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent)));
  for (const r of rules) out.push({ text: verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths),
    pre: "always allowed, " + (r.expires_at ? "" : "until removed"), t: r.expires_at, tText: r.expires_at ? "ends " + at(r.expires_at) : undefined,
    note: r.for === "zone" ? "for every agent in its zone" : "for this agent" });
  return out;
});
const kvs = computed(() => {
  const a = props.a, out = [["server", strip(a.node)]];
  if (a.deadline) out.push(["its permissions end", whenMs(a.deadline.until_ms) + (a.deadline.stopped ? " (stopped)" : "")]);
  if (a.holdings) {
    const sl = a.holdings.slice;
    out.push(["keys it can use", a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"]);
    out.push(["model budget left on its server", sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" + (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none"]);
  }
  const p = a.policy || {};
  out.push(["organisation rules", p.version ? strip(p.version) + (p.current ? " (current)" : " (not the installed " + strip(p.installed || "none") + ")") : "none"]);
  return out;
});
const grantLine = g => strip(g.method + " " + g.host + g.path) + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
  " · ends " + when(g.expires_at) + " · approved by " + strip(g.approved_by || "?") + " at " + when(g.approved_at) +
  (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : "");
</script>

<template>
  <h4>Can reach</h4>
  <div v-for="(r, i) in reach" :key="i" class="reach">
    <div class="mono">{{ r.text }}</div>
    <div class="meta">{{ r.pre }}<TimeEl v-if="r.t" :t="r.t" :text="r.tText" />{{ (r.pre ? " · " : "") + r.note }}</div>
  </div>
  <div v-if="!t.held" class="note">No token now: {{ strip(t.why) }}</div>
  <div v-else-if="!reach.length" class="empty">Nothing: everything it asks for waits for you.</div>
  <h4>Where it runs</h4>
  <div v-if="a.revoked" class="callout warn">Stopped by {{ strip(a.revoked.by) }}: {{ strip(a.revoked.reason) }}</div>
  <div v-for="[k, v] in kvs" :key="k" class="row"><span class="meta">{{ k }}</span><span class="mono">{{ v }}</span></div>
  <details v-if="t.held" class="more">
    <summary>Technical details: its token, grants and zone policy</summary>
    <div class="row"><span class="meta">status</span><span class="mono">{{ strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : "") }}</span></div>
    <div class="row"><span class="meta">token</span><span class="mono">{{ "box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) +
      " · minted by " + strip(t.issued_by) + (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || "")) }}</span></div>
    <template v-for="b in t.blocks || []" :key="b.index">
      <div class="row"><span :class="b.revoked ? 'blocked' : 'ok'">{{ "block " + b.index + " · " + strip(b.kind) + (b.revoked ? " · REVOKED" : "") }}</span><span
        class="meta">{{ "revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " · signed by " + strip(b.signed_by) : "") }}</span></div>
      <pre class="src">{{ b.source }}</pre>
    </template>
    <div v-for="g in t.grants || []" :key="g.id" class="row"><span class="meta">{{ strip(g.id) }}</span><span class="mono">{{ grantLine(g) }}</span></div>
    <template v-if="t.zone_cedar"><div class="meta">zone policy (Cedar, generated from the manifest)</div><pre class="src">{{ t.zone_cedar }}</pre></template>
  </details>
</template>
