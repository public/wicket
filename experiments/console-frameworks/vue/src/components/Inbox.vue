<script setup>
// The Inbox: one line of how things are, what needs a decision, and what is wrong.
import { computed } from "vue";
import { plural, problemList } from "../shared.js";
import PendingCard from "./PendingCard.vue";

const props = defineProps({ s: Object });
const problems = computed(() => problemList(props.s));
// The first line: how things are, each part a link to where it is.
const parts = computed(() => {
  const s = props.s;
  const working = (s.runs || []).filter(r => r.status === "running" && !r.revoked).length;
  const waiting = (s.pending || []).length + ((s.standing || {}).asks || []).length;
  const n = problems.value.length;
  const out = [{ text: plural(working, "agent working", "agents working"), href: "#agents", cls: "" }];
  if (waiting) out.push({ text: plural(waiting, "request waiting for you", "requests waiting for you"), href: "#inbox", cls: "warn" });
  out.push(n ? { text: plural(n, "problem", "problems"), href: "#health", cls: "bad" } : { text: "no problems", cls: "ok" });
  return out;
});
const waiting = computed(() => props.s.pending.length + ((props.s.standing || {}).asks || []).length);
</script>

<template>
  <section class="view" id="view-inbox" aria-labelledby="inbox-h">
    <h2 id="inbox-h" class="sr-only">Inbox</h2>
    <p class="status" id="status" aria-live="polite"><template v-for="(x, i) in parts" :key="x.text">{{ i ? " · " : "" }}<a
      v-if="x.href" :class="x.cls" :href="x.href">{{ x.text }}</a><span v-else :class="x.cls">{{ x.text }}</span></template></p>
    <div class="grid inbox">
      <div>
        <h3 class="sub" id="waiting-h">{{ waiting ? "Needs you (" + waiting + ")" : "Needs you" }}</h3>
        <div id="pending" class="deck">
          <PendingCard v-for="p in s.pending" :key="p.id" :p="p" :now="s.now" />
          <div v-if="!s.pending.length" class="empty">Nothing is waiting for you.</div>
        </div>
      </div>
      <div>
        <h3 class="sub">Problems</h3>
        <div id="problems" class="card flush">
          <a v-for="([tone, text, href], i) in problems" :key="i + text" :class="'problem ' + tone" :href="href">{{ text }}</a>
          <div v-if="!problems.length" class="empty">Nothing is wrong.</div>
        </div>
      </div>
    </div>
  </section>
</template>
