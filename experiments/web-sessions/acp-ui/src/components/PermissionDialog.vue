<!-- Upstream: formulahendry/acp-ui@cd9c3cb src/components/PermissionDialog.vue (MIT). wicket fork: a wicket
     escalation is decided with the console's signed decide action (the server's description, then a
     passkey assertion) before the ACP answer goes back; "always" options are never offered, and the
     dialog is inline (upstream: a modal overlay). -->
<script setup lang="ts">
import { computed, ref } from 'vue';
import type { PermissionRequest } from '../lib/types';
import { beginDecide, describe, finish, type Begun } from '../../../common/wicket';

const props = defineProps<{
  request: PermissionRequest;
}>();

// Once options only (#66): an "always" option would be a policy write.
const options = computed(() => props.request.options.filter((o) => o.kind === 'allow_once' || o.kind === 'reject_once'));
const begun = ref<Begun | null>(null);
const state = ref('');

async function decide(optionId: string) {
  const e = props.request.escalation;
  if (!e) return handleSelect(optionId);
  try {
    begun.value = await beginDecide(e.id, optionId === 'approve');
    state.value = '';
  } catch (x) {
    state.value = String((x as Error).message);
  }
}

async function sign() {
  if (!begun.value) return;
  state.value = 'Waiting for your passkey…';
  try {
    await finish(begun.value);
    const approve = begun.value.action.decision === 'approve';
    begun.value = null;
    handleSelect(approve ? 'approve' : 'deny');
  } catch (x) {
    state.value = String((x as Error).message);
  }
}

const emit = defineEmits<{
  select: [optionId: string];
  cancel: [];
}>();

function handleSelect(optionId: string) {
  emit('select', optionId);
}

function handleCancel() {
  emit('cancel');
}
</script>

<template>
  <div class="permission-inline">
    <div class="permission-dialog" :class="{ escalation: request.escalation }">
      <div class="dialog-header">
        <span class="icon">🔐</span>
        <h3>{{ request.escalation ? 'wicket escalation' : 'Permission Required' }}</h3>
      </div>
      
      <div class="dialog-content">
        <div class="tool-info">
          <span class="tool-title">{{ request.toolCall.title }}</span>
          <span class="tool-kind">{{ request.toolCall.kind }}</span>
        </div>
        
        <div v-if="request.escalation" class="escalation-detail">
          <div class="op">{{ request.escalation.method }} {{ request.escalation.host }}{{ request.escalation.path }}<template v-if="request.escalation.prefix">… (every path under it)</template></div>
          <div class="risk">{{ request.escalation.risk }} · request {{ request.escalation.id }}</div>
          <div class="reason">{{ request.escalation.reason }}</div>
        </div>
        <div v-if="begun" class="confirm">
          <div class="what">{{ describe(begun.action) }}</div>
          <button class="option-btn option-allow_once" @click="sign">Sign with passkey</button>
          <button class="cancel-btn" @click="begun = null">Back</button>
        </div>
        <div v-if="state" class="state">{{ state }}</div>
        <div v-if="request.toolCall.locations?.length" class="locations">
          <div 
            v-for="(loc, index) in request.toolCall.locations" 
            :key="index"
            class="location"
          >
            📁 {{ loc.path }}
          </div>
        </div>
      </div>
      
      <div v-if="!begun" class="dialog-actions">
        <button 
          v-for="option in options" 
          :key="option.optionId"
          :class="['option-btn', `option-${option.kind}`]"
          @click="decide(option.optionId)"
        >
          {{ option.name }}
        </button>
        <button class="cancel-btn" @click="handleCancel">
          Cancel
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.permission-inline { margin: .5rem 0; }
.permission-dialog.escalation { border: 2px solid #d90; }
.escalation-detail .op { font-family: monospace; }
.escalation-detail .reason, .state { opacity: .8; font-size: .9rem; }
.confirm .what { font-weight: 600; margin: .5rem 0; }

.permission-dialog {
  background: var(--bg-dialog, #fff);
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
  max-width: 480px;
  width: 90%;
  overflow: hidden;
}

.dialog-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem;
  background: var(--bg-header, #f5f5f5);
  border-bottom: 1px solid var(--border-color, #e0e0e0);
}

.dialog-header .icon {
  font-size: 1.5rem;
}

.dialog-header h3 {
  margin: 0;
  font-size: 1.1rem;
}

.dialog-content {
  padding: 1rem;
}

.tool-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.tool-title {
  font-weight: 600;
  font-size: 1rem;
}

.tool-kind {
  font-size: 0.875rem;
  color: var(--text-muted, #666);
  text-transform: capitalize;
}

.locations {
  margin-top: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-hover, #f5f5f5);
  border-radius: 4px;
  border: 1px solid var(--border-color, #e0e0e0);
}

.location {
  font-family: monospace;
  font-size: 0.8rem;
  padding: 0.125rem 0;
  color: var(--text-primary, #333);
  word-break: break-all;
}

.dialog-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  padding: 1rem;
  border-top: 1px solid var(--border-color, #e0e0e0);
  background: var(--bg-footer, #fafafa);
}

.option-btn {
  flex: 1;
  min-width: 120px;
  padding: 0.625rem 1rem;
  border: none;
  border-radius: 4px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s;
}

.option-allow_once,
.option-allow_always {
  background: var(--bg-success, #28a745);
  color: white;
}

.option-allow_once:hover,
.option-allow_always:hover {
  background: var(--bg-success-hover, #218838);
}

.option-reject_once,
.option-reject_always {
  background: var(--bg-danger, #dc3545);
  color: white;
}

.option-reject_once:hover,
.option-reject_always:hover {
  background: var(--bg-danger-hover, #c82333);
}

.cancel-btn {
  flex: 1;
  min-width: 120px;
  padding: 0.625rem 1rem;
  border: 1px solid var(--border-color, #ccc);
  border-radius: 4px;
  background: var(--bg-button, #fff);
  font-size: 0.9rem;
  cursor: pointer;
}

.cancel-btn:hover {
  background: var(--bg-hover, #f0f0f0);
}
</style>
