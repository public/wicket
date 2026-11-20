<script setup>
// A request waiting for a decision, as the reference's pendingCard builds it: who, wants to, where,
// why, risk; then the choices; the rest (on whose behalf, who in the box asked, the exact request, the
// ids) under Details. Kept by request id in the list, so an unchanged card is the same element.
import { computed, ref } from "vue";
import { strip, rel, span, riskClass, riskLabel, riskCode, asks, verb } from "../shared.js";
import TimeEl from "./TimeEl.vue";
import IdShort from "./IdShort.vue";
import AskedBy from "./AskedBy.vue";

const props = defineProps({ p: Object, now: Number });
const id = computed(() => props.p.identity || {});
const a = computed(() => asks(props.p));
// Approve needs a known agent: a verified identity, or a program with none issued.
const program = computed(() => !id.value.verified && (id.value.error || "").startsWith("no identity was issued"));
const idOk = computed(() => id.value.verified || program.value);
const showId = ref(false);
// A URL broken only after its slashes and dots, so it wraps at a segment, not mid-word.
const pathParts = computed(() => (strip(props.p.path) + (props.p.scope_prefix ? "…" : "")).split(/(?<=[/.?&])/));
// The first button's words are the server's terms for it (`once_terms`): a git push is granted as a
// window whatever is picked. Only the steps the server grants: a push is one window, R3 and R4 one
// use, wicket's own kinds one decision.
const ot = computed(() => props.p.once_terms || { uses: 1, ttl_secs: 600 });
const window_ = computed(() => ot.value.uses !== 1);
const onceLabel = computed(() => window_.value ? "Allow for " + span(ot.value.ttl_secs) : a.value.internal ? "Allow" : "Allow once");
const oneStep = computed(() => window_.value || props.p.risk === "R4ExecOrPrivilege" || props.p.risk === "R3ExternalOrIrreversible");
const decide = choice => console.info("decide", { id: props.p.id, choice });
</script>

<template>
  <div class="card req" :data-id="p.id">
    <div class="req-head">
      <span :class="'risk ' + riskClass(p.risk)">{{ riskLabel(p.risk) }}</span>
      <TimeEl class="age" :t="p.created_at" :text="rel(p.created_at, now)" />
    </div>
    <dl class="fields">
      <dt>Who</dt>
      <dd><span class="who-ask">
        <template v-if="id.verified"><span class="ok">{{ "✓ " }}</span><button type="button" class="idname" title="Show its identity"
          :aria-expanded="String(showId)" @click="showId = !showId">{{ strip(id.agent) }}</button>{{ " · zone " + strip(id.zone) }}<div
          class="idline" :hidden="!showId">{{ strip(id.id) }}</div></template>
        <template v-else-if="program">a program (it has no agent identity)</template>
        <span v-else class="bad">We can't confirm which agent this is ({{ strip(id.error || "unknown") }}). Only Don't allow is offered.</span>
      </span></dd>
      <template v-if="a.internal">
        <dt>Wants to</dt><dd class="said">{{ a.what.charAt(0).toLowerCase() + a.what.slice(1) }}</dd>
      </template>
      <template v-else>
        <dt>Wants to</dt><dd class="said">{{ verb(p) }}</dd>
        <dt>Where</dt>
        <dd><div class="where">
          <span class="host">{{ strip(p.host) }}</span>
          <div v-if="p.path && p.path !== '/'" class="path"><template v-for="(part, i) in pathParts" :key="i">{{ part }}<wbr></template></div>
          <div v-if="p.scope_prefix" class="meta">and every page under it</div>
        </div></dd>
      </template>
      <dt>Why</dt><dd class="why">{{ "“" + a.why + "”" }}</dd>
    </dl>
    <div class="buttons ladder">
      <template v-if="idOk">
        <button class="approve" @click="decide('once')">{{ onceLabel }}</button>
        <button v-if="!a.internal && !oneStep" @click="decide('hour')">Allow for 1 hour</button>
      </template>
      <button class="deny apart" @click="decide('deny')">Don't allow</button>
    </div>
    <details class="more req-more">
      <summary>Details</summary>
      <div v-if="id.verified" class="chain">On behalf of: {{ (id.acting_for || []).map(strip).join(" → ") }}</div>
      <div class="mono raw">{{ strip(p.method + " " + p.host + p.path) + " · risk class " + riskCode(p.risk) }}</div>
      <AskedBy :list="p.attribution || []" />
      <div class="meta">{{ strip(p.id) + " · zone " + strip(p.zone) + " · run " }}<IdShort :id="p.run" /></div>
      <div v-if="idOk && !a.internal && oneStep" class="note">{{ window_
        ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload."
        : "This kind is allowed one request at a time." }}</div>
    </details>
  </div>
</template>
