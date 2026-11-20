<script setup>
// A run as the reference's renderRun builds it: the agent first, its zone and state; the run id quieter
// under it; its pages. On its own page (`page`) the name is the heading and a running agent can be stopped.
import { computed } from "vue";
import { strip, rel } from "../shared.js";
import TimeEl from "./TimeEl.vue";
import IdShort from "./IdShort.vue";

const props = defineProps({ s: Object, x: Object, page: Boolean });
const href = computed(() => "#agent/" + encodeURIComponent(props.x.id));
const name = computed(() => props.x.agent ? strip(props.x.agent) : "program run");
const pill = computed(() => {
  const x = props.x, status = x.revoked ? "revoked" : String(x.status || "");
  if ((props.s.pending || []).some(p => p.run === x.id)) return ["warn", "waiting for you"];
  const tone = ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[status] || "";
  return [tone, ({ running: "working", exited: "finished", revoked: "stopped by you", hibernated: "asleep" })[status] || strip(status)];
});
const live = computed(() => props.x.status === "running" && !props.x.revoked);
const remote = computed(() => props.x.remote_url && props.x.remote_url.startsWith("https://") ? props.x.remote_url : "");
</script>

<template>
  <div class="row run">
    <div>
      <div class="run-head">
        <h2 v-if="page" class="run-name">{{ name }}</h2>
        <a v-else class="run-name" :href="href">{{ name }}</a>
        <span class="meta">{{ " · zone " + strip(x.zone) }}</span>
        <span :class="'pill ' + pill[0]">{{ pill[1] }}</span>
      </div>
      <div class="meta">
        <TimeEl :t="x.started_at" :text="'started ' + rel(x.started_at, s.now)" /><template
          v-if="x.ended_at">{{ " · " }}<TimeEl :t="x.ended_at" :text="'ended ' + rel(x.ended_at, s.now)" /></template>{{ " · " }}<IdShort :id="x.id" />
      </div>
      <div class="links">
        <a v-if="x.acp && live" class="session" :href="'/session?run=' + encodeURIComponent(x.id)">Live session</a>
        <a v-if="remote" class="session" :href="remote" target="_blank" rel="noopener noreferrer">Remote Control session ↗</a>
        <a v-if="!page" :href="href">What it can reach ›</a>
      </div>
    </div>
    <span v-if="page && live && x.has_identity" class="acts">
      <button class="deny" @click="console.info('stop', x.id)">Stop agent…</button>
    </span>
  </div>
</template>
