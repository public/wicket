<!-- Upstream: formulahendry/acp-ui@cd9c3cb src/components/ToolCallCard.vue (MIT). wicket fork: the call's
     input, output and diffs (upstream showed title, kind, status and paths only), and wicket's answer to
     the agent's permission request; the console's colours, light and dark. Everything is text
     interpolation: no raw-HTML binding (ci/session-view.sh checks). -->
<script setup lang="ts">
import { computed } from 'vue';
import type { ToolCallInfo } from '../lib/types';

const props = defineProps<{
  toolCall: ToolCallInfo;
}>();

const statusLabel = computed(() => {
  switch (props.toolCall.status) {
    case 'pending': return 'pending';
    case 'in_progress': return 'running';
    case 'completed': return 'done';
    case 'failed': return 'failed';
    default: return String(props.toolCall.status);
  }
});

const kindIcon = computed(() => {
  switch (props.toolCall.kind) {
    case 'read': return '📖';
    case 'edit': return '✏️';
    case 'delete': return '🗑️';
    case 'move': return '📦';
    case 'search': return '🔎';
    case 'execute': return '▶️';
    case 'think': return '💭';
    case 'fetch': return '🌐';
    default: return '🔧';
  }
});

// wicket's policy answered the agent's permission request: allowed or not.
const refused = computed(() => {
  const p = props.toolCall.permission;
  return !!p && (p.outcome !== 'selected' || p.optionId === 'r' || /reject|deny/i.test(String(p.optionId)));
});
const json = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v, null, 2));
</script>

<template>
  <div class="tool" :class="toolCall.status">
    <div class="head">
      <span class="kind" aria-hidden="true">{{ kindIcon }}</span>
      <span class="title">{{ toolCall.title || toolCall.toolCallId }}</span>
      <span class="status">{{ statusLabel }}</span>
    </div>
    <div v-if="toolCall.permission" class="permission" :class="{ refused }">
      {{ refused ? 'refused' : 'allowed' }} by {{ toolCall.permission.by }}<template v-if="toolCall.permission.optionId"> ({{ toolCall.permission.optionId }})</template>
    </div>
    <div v-if="toolCall.locations?.length" class="locations">
      <div v-for="(loc, i) in toolCall.locations" :key="i" class="mono">{{ loc.path }}</div>
    </div>
    <details v-if="toolCall.rawInput !== undefined" class="io">
      <summary>arguments</summary>
      <pre>{{ json(toolCall.rawInput) }}</pre>
    </details>
    <details v-if="toolCall.output?.length" class="io" :open="toolCall.output.some((o) => o.type === 'diff')">
      <summary>result</summary>
      <template v-for="(o, i) in toolCall.output" :key="i">
        <pre v-if="o.type === 'text'">{{ o.text }}</pre>
        <div v-else class="diff">
          <div class="mono">{{ o.path }}</div>
          <pre v-if="o.oldText !== null" class="old">{{ o.oldText }}</pre>
          <pre class="new">{{ o.newText }}</pre>
        </div>
      </template>
    </details>
    <details v-else-if="toolCall.rawOutput !== undefined" class="io">
      <summary>result</summary>
      <pre>{{ json(toolCall.rawOutput) }}</pre>
    </details>
  </div>
</template>

<style scoped>
.tool { margin: 8px 0; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); border-left: 3px solid var(--quiet); background: var(--tint); }
.tool.pending { border-left-color: var(--warn); }
.tool.in_progress { border-left-color: var(--accent); }
.tool.completed { border-left-color: var(--good); }
.tool.failed { border-left-color: var(--bad); }
.head { display: flex; align-items: baseline; gap: 8px; }
.title { flex: 1; min-width: 0; font-weight: 600; font-size: 14px; word-break: break-word; }
.status { font-size: 12px; color: var(--quiet); flex-shrink: 0; }
.permission { margin-top: 4px; font-size: 12.5px; color: var(--good); }
.permission.refused { color: var(--bad); }
.locations { margin-top: 4px; color: var(--soft); }
.io { margin-top: 6px; }
.io summary { font-size: 12.5px; color: var(--quiet); cursor: pointer; padding: 4px 0; }
pre { font: 12px/1.5 var(--mono); white-space: pre-wrap; word-break: break-word; margin: 4px 0; padding: 6px 8px; border-radius: 8px; background: var(--card); max-height: 360px; overflow: auto; }
.diff pre.old { background: color-mix(in srgb, var(--bad) 10%, var(--card)); }
.diff pre.new { background: color-mix(in srgb, var(--good) 10%, var(--card)); }
</style>
