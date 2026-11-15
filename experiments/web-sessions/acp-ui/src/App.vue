<!-- wicket fork of acp-ui: one boxed run's session. The chat layout follows upstream's ChatView.vue
     (formulahendry/acp-ui@cd9c3cb, MIT) without its markdown: upstream renders agent text with
     `marked` into v-html, unsanitized, which lets an agent put its own HTML (forms, fake approve
     buttons) on the operator's console. Here every string is text interpolation. -->
<script setup lang="ts">
import { computed, ref, shallowRef } from 'vue';
import { AcpClientBridge } from './lib/acp-bridge';
import { WebSocketTransport } from './lib/transport/websocket';
import ToolCallCard from './components/ToolCallCard.vue';
import PermissionDialog from './components/PermissionDialog.vue';
import { addUser, handleSessionUpdate, messages } from './session';
import { begin, describe, finish, runFromLocation, socket, type Begun } from '../../common/wicket';

const run = runFromLocation();
const state = ref<'idle' | 'connecting' | 'open' | 'closed'>('idle');
const error = ref('');
const begun = ref<Begun | null>(null);
const running = ref(false);
const input = ref('');
let bridge: AcpClientBridge | null = null;
const bridgeRef = shallowRef<AcpClientBridge | null>(null);
const permissions = computed(() => bridgeRef.value?.permissions.value ?? []);

async function open() {
  try {
    begun.value = await begin({ action: 'open_session', run });
  } catch (e) {
    error.value = String((e as Error).message);
  }
}

async function sign() {
  if (!begun.value) return;
  try {
    const r = await finish(begun.value);
    begun.value = null;
    await connect(r.ticket);
  } catch (e) {
    error.value = String((e as Error).message);
  }
}

async function connect(ticket: string) {
  state.value = 'connecting';
  const { url, protocols } = socket(run, ticket);
  try {
    const t = await WebSocketTransport.connect({ url, protocols: protocols.slice(1) });
    bridge = new AcpClientBridge(t);
    bridgeRef.value = bridge;
    bridge.onSessionUpdate = handleSessionUpdate;
    bridge.onTransportClose = (why) => {
      state.value = 'closed';
      error.value = why ?? '';
      running.value = false;
    };
    await bridge.initialize({
      protocolVersion: 1,
      clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
      clientInfo: { name: 'wicket-console-acp-ui', version: '0' },
    });
    await bridge.newSession({ cwd: '/', mcpServers: [] });
    state.value = 'open';
  } catch (e) {
    state.value = 'closed';
    error.value = String((e as Error).message);
  }
}

async function send() {
  const text = input.value.trim();
  if (!text || !bridge) return;
  input.value = '';
  addUser(text);
  running.value = true;
  try {
    await bridge.prompt({ sessionId: run, prompt: [{ type: 'text', text }] });
  } catch (e) {
    error.value = String((e as Error).message);
  }
  running.value = false;
}
</script>

<template>
  <div class="app">
    <header>
      <b>wicket</b> session <code>{{ run || '(add ?run=<id>)' }}</code>
      <span class="state">{{ state }}<template v-if="running"> · running</template></span>
      <span v-if="error" class="err">{{ error }}</span>
    </header>
    <button v-if="state === 'idle' && !begun" :disabled="!run" @click="open">Open session</button>
    <div v-if="begun" class="confirm">
      <div class="what">{{ describe(begun.action) }}</div>
      <button class="approve" @click="sign">Sign with passkey</button>
      <button @click="begun = null">Cancel</button>
    </div>
    <main class="messages">
      <div v-for="m in messages" :key="m.id" :class="['message', m.role]">
        <div v-if="m.role === 'user' && m.by && m.by !== 'you'" class="by">{{ m.by }}</div>
        <details v-if="m.thought" class="thought"><summary>thinking</summary><pre>{{ m.thought }}</pre></details>
        <div v-if="m.content" class="content">{{ m.content }}</div>
        <ol v-if="m.plan?.length" class="plan">
          <li v-for="(p, i) in m.plan" :key="i" :class="p.status">{{ p.content }} <span class="status">{{ p.status }}</span></li>
        </ol>
        <template v-for="tc in m.toolCalls ?? []" :key="tc.toolCallId">
          <div v-if="tc.escalation" class="escalation" :class="tc.escalation.status">
            wicket escalation {{ tc.escalation.id }}: {{ tc.escalation.method }} {{ tc.escalation.host }}{{ tc.escalation.path }}
            · <b>{{ tc.escalation.status }}</b>
          </div>
          <ToolCallCard v-else :tool-call="tc" />
          <PermissionDialog
            v-for="r in permissions.filter((p) => p.toolCall.toolCallId === tc.toolCallId)"
            :key="String(r.rpcId)"
            :request="r"
            @select="(o: string) => bridgeRef?.answerPermission(r.rpcId!, o)"
            @cancel="bridgeRef?.answerPermission(r.rpcId!, null)"
          />
        </template>
      </div>
    </main>
    <form v-if="state === 'open'" class="composer" @submit.prevent="send">
      <textarea v-model="input" rows="2" placeholder="Prompt the agent…" @keydown.enter.exact.prevent="send" />
      <button type="submit">Send</button>
    </form>
  </div>
</template>

<style>
:root { color-scheme: light dark; font: 15px/1.45 system-ui, sans-serif; }
body { margin: 0; }
.app { max-width: 920px; margin: 0 auto; padding: 12px; display: flex; flex-direction: column; height: 100vh; box-sizing: border-box; }
header { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; padding: 6px 0; }
.state { opacity: .6; } .err { color: #c33; }
.messages { flex: 1; overflow-y: auto; }
.message { margin: 8px 0; padding: 8px 10px; border-radius: 8px; }
.message.user { background: #8882; margin-left: 15%; }
.content { white-space: pre-wrap; }
.by { font-size: 12px; opacity: .7; }
pre { white-space: pre-wrap; word-break: break-word; }
.plan .completed { text-decoration: line-through; opacity: .7; } .plan .status { font-size: 12px; opacity: .7; }
.escalation { border: 2px solid #d90; border-radius: 6px; padding: 6px; font-family: monospace; }
.escalation.approved { border-color: #2a6; } .escalation.denied { border-color: #c33; }
.confirm { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; } .confirm .what { flex-basis: 100%; font-weight: 600; }
button { font: inherit; padding: 6px 12px; border-radius: 6px; border: 1px solid #8886; cursor: pointer; }
button.approve { background: #2a6; color: white; }
.composer { display: flex; gap: 8px; padding: 8px 0; } .composer textarea { flex: 1; font: inherit; padding: 8px; }
</style>
