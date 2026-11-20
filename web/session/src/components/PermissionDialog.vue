<!-- Upstream: formulahendry/acp-ui@cd9c3cb src/components/PermissionDialog.vue (MIT). wicket fork: inline,
     not a modal; once options only; and a wicket request is decided with the console's signed decide
     action (`/api/decide/*`: the server's description in the signing sheet, then a passkey assertion)
     before the ACP answer goes back. The ACP answer itself decides nothing (the endpoint audits it). -->
<script setup lang="ts">
import { computed, ref } from 'vue';
import type { PermissionRequest } from '../lib/types';
import { decideBody, riskLabel } from '../lib/wicket';
import { signed } from '../lib/sign';

const props = defineProps<{
  request: PermissionRequest;
}>();

const emit = defineEmits<{
  select: [optionId: string];
  cancel: [];
}>();

// Once options only (#66): an "always" option would be a policy write.
const options = computed(() => props.request.options.filter((o) => o.kind === 'allow_once' || o.kind === 'reject_once'));
const state = ref('');
const busy = ref(false);

async function choose(optionId: string, kind: string) {
  const e = props.request.escalation;
  if (!e) return emit('select', optionId);
  busy.value = true;
  state.value = '';
  try {
    const r = await signed(decideBody(e.id, kind === 'allow_once'));
    if (r) {
      state.value = String(r.ok ?? 'decided');
      emit('select', optionId);
    }
  } catch (x) {
    state.value = String((x as Error).message);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="ask" :class="{ escalation: request.escalation }">
    <div class="label">{{ request.escalation ? 'Request waiting for you' : 'The agent asks (not enforced by wicket)' }}</div>
    <template v-if="request.escalation">
      <div class="op">{{ request.escalation.method }} {{ request.escalation.host }}{{ request.escalation.path }}<template v-if="request.escalation.prefix">… (every path under it)</template></div>
      <div class="meta">{{ riskLabel(request.escalation.risk) }} · request {{ request.escalation.id }}</div>
      <div v-if="request.escalation.reason" class="why">{{ request.escalation.reason }}</div>
    </template>
    <div v-else class="op">{{ request.toolCall.title }}</div>
    <div class="buttons">
      <button
        v-for="o in options"
        :key="o.optionId"
        type="button"
        :class="o.kind === 'allow_once' ? 'approve' : 'deny'"
        :disabled="busy"
        @click="choose(o.optionId, o.kind)"
      >{{ o.name }}</button>
      <button v-if="!request.escalation" type="button" :disabled="busy" @click="emit('cancel')">Cancel</button>
    </div>
    <div v-if="request.escalation" class="note">wicket enforces this one: the box can't do it until it is approved. Approving is once, for 10 minutes. Your passkey signs the decision; you can also decide it on the console's front page.</div>
    <div v-if="state" class="state">{{ state }}</div>
  </div>
</template>

<style scoped>
.ask { margin: 8px 0; padding: 12px 14px; border-radius: 10px; border: 1px solid var(--line); background: var(--card); }
.ask.escalation { border: 2px solid var(--warn); }
.label { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: var(--warn); }
.op { font: 500 14px/1.45 var(--mono); margin-top: 6px; word-break: break-all; }
.meta, .note, .state { color: var(--quiet); font-size: 12.5px; margin-top: 6px; }
.why { color: var(--soft); font-size: 14px; margin-top: 6px; white-space: pre-wrap; }
.buttons { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.buttons button { flex: 1 1 140px; }
</style>
