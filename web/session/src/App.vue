<!-- wicket's session view (#327): one boxed run's ACP session in the console, opened from the run's row.
     Forked from acp-ui (formulahendry/acp-ui@cd9c3cb, MIT): the chat layout follows upstream's
     ChatView.vue without its markdown (upstream renders agent text with `marked` into a raw-HTML
     binding, unsanitized, which would let an agent put its own HTML, such as fake approve buttons, on the
     operator's console). Every string here is text interpolation. -->
<script setup lang="ts">
import { computed, nextTick, onMounted, ref, shallowRef, watch } from 'vue';
import { AcpClientBridge } from './lib/acp-bridge';
import { WebSocketTransport } from './lib/transport/websocket';
import ToolCallCard from './components/ToolCallCard.vue';
import PermissionDialog from './components/PermissionDialog.vue';
import SignSheet from './components/SignSheet.vue';
import { addUser, handleSessionUpdate, messages, reset } from './session';
import { requestState, riskLabel, runFromLocation, socket } from './lib/wicket';
import { sheet, signed } from './lib/sign';
import type { PermissionRequest } from './lib/types';

const run = runFromLocation();
const state = ref<'idle' | 'opening' | 'connecting' | 'open' | 'closed'>('idle');
const error = ref('');
const inFlight = ref(0);
const input = ref('');
const bridge = shallowRef<AcpClientBridge | null>(null);
const permissions = computed<PermissionRequest[]>(() => bridge.value?.permissions.value ?? []);
const label = computed(() => ({ idle: 'not open', opening: 'opening…', connecting: 'connecting…', open: 'live', closed: 'closed' })[state.value]);

onMounted(() => {
  if (run) document.title = `wicket · ${run}`;
});

async function open() {
  if (!run || sheet.value) return;
  error.value = '';
  state.value = 'opening';
  try {
    const r = await signed({ action: 'open_session', run });
    if (!r) {
      state.value = bridge.value ? 'closed' : 'idle';
      return;
    }
    await connect(String(r.ticket));
  } catch (e) {
    state.value = bridge.value ? 'closed' : 'idle';
    error.value = String((e as Error).message);
  }
}

async function connect(ticket: string) {
  state.value = 'connecting';
  const { url, protocols } = socket(run, ticket);
  try {
    const t = await WebSocketTransport.connect({ url, protocols: protocols.slice(1) });
    // A reopened socket replays the session from its start.
    reset();
    inFlight.value = 0;
    const b = new AcpClientBridge(t);
    bridge.value = b;
    b.onSessionUpdate = handleSessionUpdate;
    b.onTransportClose = (why) => {
      if (bridge.value !== b) return;
      state.value = 'closed';
      error.value = why ? `The session closed: ${why}` : 'The session closed.';
      inFlight.value = 0;
    };
    await b.initialize({
      protocolVersion: 1,
      clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
      clientInfo: { name: 'wicket-console', version: '1' },
    });
    await b.newSession({ cwd: '/', mcpServers: [] });
    state.value = 'open';
  } catch (e) {
    state.value = 'closed';
    error.value = String((e as Error).message);
  }
}

async function send() {
  const text = input.value.trim();
  const b = bridge.value;
  if (!text || !b || state.value !== 'open') return;
  input.value = '';
  addUser(text);
  stick.value = true;
  inFlight.value++;
  try {
    const r = await b.prompt({ sessionId: run, prompt: [{ type: 'text', text }] });
    if (r?.stopReason && r.stopReason !== 'end_turn') messages.value.push({ id: `s${Date.now()}`, role: 'system', content: `[wicket] the turn ended: ${r.stopReason}\n`, timestamp: Date.now() });
  } catch (e) {
    error.value = String((e as Error).message);
  } finally {
    inFlight.value = Math.max(0, inFlight.value - 1);
  }
}

async function stop() {
  try {
    await bridge.value?.cancel(run);
  } catch (e) {
    error.value = String((e as Error).message);
  }
}

// A request decided elsewhere (the console's front page, another device, its expiry) withdraws
// its prompt here: answered "cancelled", which the endpoint audits next to the ledger's status.
watch(
  () => messages.value.flatMap((m) => m.toolCalls ?? []).filter((t) => t.escalation && t.escalation.status !== 'pending').map((t) => t.toolCallId),
  (done) => {
    for (const r of permissions.value) if (r.escalation && done.includes(r.toolCall.toolCallId)) bridge.value?.answerPermission(r.rpcId!, null);
  },
);
const knownTools = computed(() => new Set(messages.value.flatMap((m) => (m.toolCalls ?? []).map((t) => t.toolCallId))));
const orphans = computed(() => permissions.value.filter((p) => !knownTools.value.has(p.toolCall.toolCallId)));

// Follows the stream while the operator is at the bottom; leaves them be when they scrolled up.
const stick = ref(true);
const atBottom = () => window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 80;
window.addEventListener('scroll', () => (stick.value = atBottom()), { passive: true });
watch(
  () => [messages.value.length, messages.value[messages.value.length - 1]?.content.length, permissions.value.length],
  async () => {
    if (!stick.value) return;
    await nextTick();
    window.scrollTo({ top: document.documentElement.scrollHeight });
  },
);

function onKey(e: KeyboardEvent) {
  // Enter sends on a keyboard; on a phone the return key makes a new line (the Send button sends).
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && window.matchMedia('(pointer: fine)').matches) {
    e.preventDefault();
    void send();
  }
}
</script>

<template>
  <header class="bar">
    <a href="/" class="back" aria-label="Back to the console">‹ Console</a>
    <div class="title">
      <span class="mono run">{{ run || 'no run' }}</span>
      <span class="state" :class="state">{{ label }}<template v-if="inFlight"> · working</template></span>
    </div>
  </header>
  <main>
    <div v-if="!run" class="card">This page shows a run's session: open it from a running run in the console's Runs list.</div>
    <div v-else-if="state !== 'open' && !messages.length" class="card intro">
      <div>Open <span class="mono">{{ run }}</span>'s session: the agent's messages, tool calls and plans as they stream, wicket's requests waiting for your decision, and prompts from you. Your passkey signs the open.</div>
      <div class="buttons"><button type="button" class="approve" :disabled="state === 'opening' || state === 'connecting'" @click="open">Open session</button></div>
    </div>
    <div v-if="error" class="card err" role="status">{{ error }}<div v-if="state === 'closed'" class="buttons"><button type="button" @click="open">Reopen</button></div></div>

    <div class="messages" aria-live="polite">
      <div v-for="m in messages" :key="m.id" :class="['msg', m.role]">
        <div v-if="m.role === 'user'" class="by">{{ m.by === 'you' ? 'you' : m.by }}</div>
        <details v-if="m.thought" class="thought"><summary>thinking</summary><pre>{{ m.thought }}</pre></details>
        <div v-if="m.content" class="text">{{ m.content }}</div>
        <div v-if="m.plan?.length" class="plan">
          <div class="label">Plan</div>
          <ol>
            <li v-for="(p, i) in m.plan" :key="i" :class="p.status">{{ p.content }} <span class="status">{{ p.status }}</span></li>
          </ol>
        </div>
        <template v-for="tc in m.toolCalls ?? []" :key="tc.toolCallId">
          <div v-if="tc.escalation" class="escalation" :class="requestState(tc.escalation.status).cls">
            <span class="label">wicket request · {{ requestState(tc.escalation.status).word }}</span>
            <span class="mono">{{ tc.escalation.method }} {{ tc.escalation.host }}{{ tc.escalation.path }}</span>
            <span class="meta">{{ riskLabel(tc.escalation.risk) }} · request {{ tc.escalation.id }}</span>
          </div>
          <ToolCallCard v-else :tool-call="tc" />
          <PermissionDialog
            v-for="r in permissions.filter((p) => p.toolCall.toolCallId === tc.toolCallId)"
            :key="String(r.rpcId)"
            :request="r"
            @select="(o: string) => bridge?.answerPermission(r.rpcId!, o)"
            @cancel="bridge?.answerPermission(r.rpcId!, null)"
          />
        </template>
      </div>
      <PermissionDialog
        v-for="r in orphans"
        :key="String(r.rpcId)"
        :request="r"
        @select="(o: string) => bridge?.answerPermission(r.rpcId!, o)"
        @cancel="bridge?.answerPermission(r.rpcId!, null)"
      />
    </div>
  </main>
  <form v-if="state === 'open'" class="composer" @submit.prevent="send">
    <textarea v-model="input" rows="1" maxlength="16384" placeholder="Prompt the agent…" aria-label="Prompt" enterkeyhint="send" @keydown="onKey" />
    <div class="acts">
      <button type="submit" class="approve" :disabled="!input.trim()">Send</button>
      <button type="button" class="deny" title="Cancel the agent's running turn" @click="stop">Stop</button>
    </div>
  </form>
  <SignSheet />
</template>
