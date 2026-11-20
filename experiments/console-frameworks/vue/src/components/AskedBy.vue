<script setup>
// Which call in the box asked, as the agent's event stream reports it: helpful, not proof, and always
// with the note that anything in the box could use the grant (the reference's renderWho).
import { computed } from "vue";
import { strip } from "../shared.js";

const props = defineProps({ list: Array });
const say = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
// Each line as { text, cls }: one asker with no call in flight is said by the note alone.
const lines = computed(() => {
  const list = props.list, out = [];
  if (!list.length) out.push({ text: "Asked by (in the box): unknown (no agent event stream)" });
  for (const a of list) {
    const rs = a.requesters || [];
    if (a.basis === "none" || !rs.length) { if (list.length > 1) out.push({ text: "Asked by (in the box): unknown — no tool call was in flight" }); continue; }
    if (a.basis === "ambiguous") {
      out.push({ text: "Asked by (in the box): one of " + rs.length + " concurrent calls:" });
      for (const r of rs) out.push({ text: "• " + say(r), cls: "cand" });
    } else out.push({ text: "Asked by (in the box): " + say(rs[0]) });
  }
  if (list.length > 1) out.push({ text: "Asked by more than one agent: one grant would serve all of them.", cls: "warn" });
  out.push({ text: (list.length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant.", cls: "note" });
  return out;
});
</script>

<template>
  <div class="who"><div v-for="(x, i) in lines" :key="i" :class="x.cls">{{ x.text }}</div></div>
</template>
