<script setup>
// An agent's page: its name, state and links, what it can reach (fetched once per run, as the
// reference's showAuthority does), and what it did, filtered from the polled state's audit.
import { computed, ref, watch } from "vue";
import { line, clock } from "../shared.js";
import RunRow from "./RunRow.vue";
import Authority from "./Authority.vue";
import TimeEl from "./TimeEl.vue";

const props = defineProps({ s: Object, run: String });
const x = computed(() => (props.s.runs || []).find(r => r.id === props.run));
const log = computed(() => (props.s.audit || []).filter(op => op.run === props.run).slice().reverse()
  .map(op => ({ seq: op.seq, ...line(op, props.s.runs) })));

const auth = ref(null), authError = ref("");
watch(() => props.run, async run => {
  auth.value = null; authError.value = "";
  try {
    const r = await fetch("/api/runs/" + encodeURIComponent(run) + "/authority");
    const j = await r.json().catch(() => ({ error: "unreadable answer" }));
    if (!r.ok) throw new Error(j.error || r.statusText);
    if (run === props.run) auth.value = j;
  } catch (e) { if (run === props.run) authError.value = String(e.message); }
}, { immediate: true });
// "why?" opens the decision's explanation under its line; the mock API has none, so it says so.
const open = ref(new Set());
const toggle = seq => { const o = new Set(open.value); o.has(seq) ? o.delete(seq) : o.add(seq); open.value = o; };
</script>

<template>
  <section class="view" id="view-agent" aria-labelledby="detail-title">
    <a class="back" href="#agents">‹ Agents</a>
    <div id="agent-head">
      <RunRow v-if="x" :s="s" :x="x" page />
      <template v-else><h2>Agent</h2><p class="note">This agent run isn't in the latest list (only the 15 most recent are).</p></template>
    </div>
    <div class="card" id="detail">
      <div class="card-head"><h3 id="detail-title">Permissions</h3></div>
      <div id="detail-body">
        <div v-if="authError" class="blocked">{{ authError }}</div>
        <Authority v-else-if="auth" :a="auth" :s="s" :run="run" />
        <div v-else class="meta">loading…</div>
      </div>
    </div>
    <div class="card"><h3>Recent activity</h3><div class="log" id="agent-log">
      <template v-for="l in log" :key="l.seq">
        <div class="logline">
          <TimeEl v-if="l.ts" :t="l.ts" :text="clock(l.ts)" /><span v-else></span><span :class="'tag ' + l.tone">{{ l.tag }}</span><span
            class="text">{{ l.text }}<template v-if="l.why">{{ " " }}<button class="link" @click="toggle(l.seq)">why?</button></template></span>
        </div>
        <div v-if="open.has(l.seq)" class="explained"><div class="meta">No explanation in this prototype (the mock API has none).</div></div>
      </template>
      <div v-if="!log.length" class="empty">Nothing recorded for it in the latest activity.</div>
    </div></div>
  </section>
</template>
