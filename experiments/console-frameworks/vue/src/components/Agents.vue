<script setup>
// Agents: who is working, waiting, finished or failed; each opens its own page.
import RunRow from "./RunRow.vue";
defineProps({ s: Object });
</script>

<template>
  <section class="view" id="view-agents" aria-labelledby="agents-h">
    <div class="view-head"><h2 id="agents-h">Agents</h2><button type="button" class="approve" id="start-open" @click="console.info('start')">Start an agent…</button></div>
    <div class="card flush" id="runs">
      <RunRow v-for="x in s.runs" :key="x.id" :s="s" :x="x" />
      <div v-if="!s.runs.length" class="empty">No runs yet.</div>
    </div>
  </section>
</template>
