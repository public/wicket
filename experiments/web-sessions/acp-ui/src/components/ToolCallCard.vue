<!-- Upstream: formulahendry/acp-ui@cd9c3cb src/components/ToolCallCard.vue (MIT). wicket fork: the call's
     input, output and diffs (upstream showed title, kind, status and paths only), and wicket's answer to
     the agent's permission request. Everything is text interpolation: no v-html. -->
<script setup lang="ts">
import { computed } from 'vue';
import type { ToolCallInfo } from '../lib/types';

const props = defineProps<{
  toolCall: ToolCallInfo;
}>();

const statusClass = computed(() => {
  switch (props.toolCall.status) {
    case 'pending': return 'status-pending';
    case 'in_progress': return 'status-running';
    case 'completed': return 'status-completed';
    case 'failed': return 'status-failed';
    default: return '';
  }
});

const statusIcon = computed(() => {
  switch (props.toolCall.status) {
    case 'pending': return '⏳';
    case 'in_progress': return '⚙️';
    case 'completed': return '✅';
    case 'failed': return '❌';
    default: return '🔧';
  }
});

const kindIcon = computed(() => {
  switch (props.toolCall.kind) {
    case 'read': return '📖';
    case 'edit': return '✏️';
    case 'write': return '📝';
    case 'execute': return '▶️';
    default: return '🔧';
  }
});
</script>

<template>
  <div class="tool-call-card" :class="statusClass">
    <div class="tool-header">
      <span class="kind-icon">{{ kindIcon }}</span>
      <span class="tool-title">{{ toolCall.title }}</span>
      <span class="status-icon">{{ statusIcon }}</span>
    </div>
    
    <div v-if="toolCall.permission" class="tool-permission" :class="{ refused: toolCall.permission.outcome !== 'selected' || toolCall.permission.optionId === 'r' }">
      permission: {{ toolCall.permission.outcome }}<template v-if="toolCall.permission.optionId"> ({{ toolCall.permission.optionId }})</template> · by {{ toolCall.permission.by }}
    </div>
    <details v-if="toolCall.rawInput !== undefined" class="tool-input">
      <summary>input</summary>
      <pre>{{ JSON.stringify(toolCall.rawInput, null, 2) }}</pre>
    </details>
    <div v-for="(o, i) in toolCall.output ?? []" :key="i" class="tool-output">
      <pre v-if="o.type === 'text'">{{ o.text }}</pre>
      <div v-else class="diff">
        <div class="diff-path">{{ o.path }}</div>
        <pre v-if="o.oldText !== null" class="diff-old">{{ o.oldText }}</pre>
        <pre class="diff-new">{{ o.newText }}</pre>
      </div>
    </div>
    <div v-if="toolCall.locations?.length" class="tool-locations">
      <div 
        v-for="(loc, index) in toolCall.locations" 
        :key="index"
        class="location"
      >
        📁 {{ loc.path }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.tool-call-card {
  padding: 0.75rem;
  border-radius: 6px;
  margin: 0.5rem 0;
  border-left: 3px solid var(--border-color, #ccc);
  background: var(--bg-tool, #f9f9f9);
}

.status-pending {
  border-left-color: #ffc107;
  background: #fffbf0;
}

.status-running {
  border-left-color: #17a2b8;
  background: #f0f9ff;
}

.status-completed {
  border-left-color: #28a745;
  background: #f0fff4;
}

.status-failed {
  border-left-color: #dc3545;
  background: #fff5f5;
}

.tool-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.kind-icon {
  font-size: 1rem;
}

.tool-title {
  flex: 1;
  font-weight: 500;
  font-size: 0.9rem;
}

.status-icon {
  font-size: 0.875rem;
}

.tool-locations {
  margin-top: 0.5rem;
  padding-left: 1.5rem;
}

.location {
  font-family: monospace;
  font-size: 0.8rem;
  color: var(--text-muted, #666);
  padding: 0.125rem 0;
}
.tool-permission { margin-top: .4rem; font-size: .8rem; color: #1a7f37; }
.tool-permission.refused { color: #b42318; }
.tool-input pre, .tool-output pre { white-space: pre-wrap; word-break: break-word; font-size: .8rem; margin: .25rem 0; }
.diff-path { font-family: monospace; font-size: .8rem; }
.diff-old { background: #fff0f0; }
.diff-new { background: #f0fff4; }
</style>
