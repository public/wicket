// Upstream: formulahendry/acp-ui@cd9c3cb src/stores/session.ts's handleSessionUpdate (MIT), without
// pinia, saved sessions, agents, modes or models. wicket fork:
// - a tool call that comes first in a turn starts an assistant message (upstream kept it only in its
//   map, so it was never shown: wicket's escalations arrive that way);
// - tool calls keep rawInput, content (text and diffs) and wicket's `_meta` (permission, escalation);
// - `plan` updates are shown (upstream logged them as unhandled);
// - user turns from other principals carry who sent them.
import { ref } from 'vue';
import type { ChatMessage, ToolCallInfo, ToolOutput } from './lib/types';
import { escalationOf, permissionOf } from '../../common/wicket';

export const messages = ref<ChatMessage[]>([]);
let n = 0;
const id = () => `m${n++}`;

function assistant(): ChatMessage {
  const last = messages.value[messages.value.length - 1];
  if (last && last.role === 'assistant') return last;
  messages.value.push({ id: id(), role: 'assistant', content: '', timestamp: Date.now(), toolCalls: [] });
  return messages.value[messages.value.length - 1];
}

function findTool(toolCallId: string): ToolCallInfo | undefined {
  for (let i = messages.value.length - 1; i >= 0; i--) {
    const t = messages.value[i].toolCalls?.find((x) => x.toolCallId === toolCallId);
    if (t) return t;
  }
  return undefined;
}

export function addUser(text: string, by = 'you') {
  messages.value.push({ id: id(), role: 'user', content: text, timestamp: Date.now(), by });
}

export function handleSessionUpdate(notification: any) {
  const update = notification.update;
  const text = (c: any) => (c?.type === 'text' ? String(c.text ?? '') : '');
  switch (update.sessionUpdate) {
    case 'user_message_chunk': {
      const by = update._meta?.wicket?.by ?? 'someone';
      const last = messages.value[messages.value.length - 1];
      if (last && last.role === 'user' && last.by === by) last.content += text(update.content);
      else addUser(text(update.content), by);
      break;
    }
    case 'agent_message_chunk':
      assistant().content += text(update.content);
      break;
    case 'agent_thought_chunk': {
      const m = assistant();
      m.thought = (m.thought || '') + text(update.content);
      break;
    }
    case 'tool_call':
      assistant().toolCalls!.push({
        toolCallId: update.toolCallId,
        title: update.title ?? '',
        kind: update.kind || 'other',
        status: update.status || 'pending',
        locations: update.locations,
        rawInput: update.rawInput,
        escalation: escalationOf(update) ?? undefined,
      });
      break;
    case 'tool_call_update': {
      const tc = findTool(update.toolCallId);
      if (!tc) break;
      if (update.status) tc.status = update.status;
      if (update.title) tc.title = update.title;
      if (update.rawInput !== undefined) tc.rawInput = update.rawInput;
      if (Array.isArray(update.content) && update.content.length) {
        tc.output = update.content.map((c: any): ToolOutput =>
          c.type === 'diff'
            ? { type: 'diff', path: String(c.path ?? ''), oldText: c.oldText ?? null, newText: String(c.newText ?? '') }
            : { type: 'text', text: c.type === 'content' ? text(c.content) : JSON.stringify(c) },
        );
      }
      const p = permissionOf(update);
      if (p) tc.permission = p;
      const e = escalationOf(update);
      if (e && tc.escalation) tc.escalation = { ...tc.escalation, status: e.status };
      break;
    }
    case 'plan':
      assistant().plan = update.entries ?? [];
      break;
    default:
      break;
  }
}
