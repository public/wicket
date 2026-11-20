<script setup>
// The console's shell: the header and its nav, the poll, and the views routed by the address's hash
// (#inbox, the default; #agents; #agent/<run>; #activity and #settings are not in this prototype).
import { ref, computed, watchEffect, onMounted, onUnmounted } from "vue";
import { setSkew, problemList } from "./shared.js";
import Inbox from "./components/Inbox.vue";
import Agents from "./components/Agents.vue";
import AgentPage from "./components/AgentPage.vue";

const state = ref(null);
const stale = ref("");
const hash = ref(location.hash);

const route = computed(() => {
  const ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(hash.value);
  if (ag) return { view: "agent", run: ag[1] };
  const v = hash.value.slice(1);
  return { view: ["agents", "activity", "settings"].includes(v) ? v : "inbox" };
});
const current = v => v === route.value.view || (v === "agents" && route.value.view === "agent") ? "page" : undefined;
const waiting = computed(() => state.value ? state.value.pending.length + ((state.value.standing || {}).asks || []).length : 0);
const problems = computed(() => state.value ? problemList(state.value).length : 0);
const tabs = [["inbox", "Inbox"], ["agents", "Agents"], ["activity", "Activity"], ["settings", "Settings"]];

watchEffect(() => { document.title = waiting.value ? "(" + waiting.value + ") wicket" : "wicket"; });

// One poll at a time, each bounded: a hung fetch is a stale page, said so.
let polling = false, timer;
async function refresh() {
  if (polling) return;
  polling = true;
  try {
    const r = await fetch("/api/state", { signal: AbortSignal.timeout(10000) });
    if (!r.ok) { stale.value = "HTTP " + r.status; return; }
    const s = await r.json();
    setSkew(s.now);
    state.value = s;
    stale.value = "";
  } catch (e) {
    stale.value = e && e.name === "TimeoutError" ? "no answer in 10 s" : "no answer";
  } finally { polling = false; }
}
const onHash = () => { hash.value = location.hash; window.scrollTo(0, 0); };
onMounted(() => { addEventListener("hashchange", onHash); refresh(); timer = setInterval(refresh, 2000); });
onUnmounted(() => { removeEventListener("hashchange", onHash); clearInterval(timer); });
</script>

<template>
  <a class="skip" href="#main">Skip to the page</a>
  <header class="top">
    <div class="bar"><h1>wicket</h1><span id="tenant">{{ state ? "tenant " + state.tenant : "" }}</span></div>
    <nav id="nav" aria-label="Views">
      <a v-for="[v, label] in tabs" :key="v" :href="'#' + v" :data-view="v" :aria-current="current(v)">{{ label }}<span
        v-if="v === 'inbox' && waiting" class="count" id="nav-waiting">{{ waiting }}</span><span
        v-if="v === 'settings' && problems" class="count bad" id="nav-health">{{ problems }}</span></a>
    </nav>
  </header>
  <div class="banner" id="stale" role="status" :hidden="!stale">Can't reach wicket ({{ stale }}). Retrying.</div>
  <main id="main">
    <div id="console" v-if="state">
      <Inbox v-if="route.view === 'inbox'" :s="state" />
      <Agents v-else-if="route.view === 'agents'" :s="state" />
      <AgentPage v-else-if="route.view === 'agent'" :s="state" :run="route.run" />
      <section v-else class="view" :id="'view-' + route.view">
        <h2>{{ route.view === "activity" ? "Activity" : "Settings" }}</h2>
        <p class="note">Not in this prototype.</p>
      </section>
    </div>
  </main>
</template>
