// Upstream: formulahendry/acp-ui@cd9c3cb src/stores/session.ts's handleSessionUpdate (MIT), without
// pinia, saved sessions, agents, modes or models. wicket fork:
// - a tool call that comes first in a turn starts an assistant message (upstream kept it only in its
//   map, so it was never shown: wicket's escalations arrive that way);
// - tool calls keep rawInput, content (text and diffs) and wicket's `_meta` (permission, escalation);
//   a repeated `tool_call` updates the call, and an update for a call not seen yet starts it;
// - `plan` updates are shown (upstream logged them as unhandled);
// - user turns from other principals carry who sent them, and wicket's notices are its own messages.
import { ref } from 'vue';
import type { ChatMessage, ToolCallInfo, ToolOutput } from './lib/types';
import { escalationOf, isNotice, permissionOf } from './lib/wicket';

export const messages = ref<ChatMessage[]>([]);
let n = 0;
const id = () => `m${n++}`;

/** Forgets the session's history: a reopened socket replays it from the start. */
export function reset() {
  messages.value = [];
}

function last(): ChatMessage | undefined {
  return messages.value[messages.value.length - 1];
}

function push(m: Omit<ChatMessage, 'id' | 'timestamp'>): ChatMessage {
  messages.value.push({ id: id(), timestamp: Date.now(), ...m });
  return messages.value[messages.value.length - 1];
}

function assistant(): ChatMessage {
  const l = last();
  return l && l.role === 'assistant' ? l : push({ role: 'assistant', content: '', toolCalls: [] });
}

function findTool(toolCallId: string): ToolCallInfo | undefined {
  for (let i = messages.value.length - 1; i >= 0; i--) {
    const t = messages.value[i].toolCalls?.find((x) => x.toolCallId === toolCallId);
    if (t) return t;
  }
  return undefined;
}

export function addUser(text: string, by = 'you') {
  push({ role: 'user', content: text, by });
}

const text = (c: any) => (c?.type === 'text' ? String(c.text ?? '') : '');

function outputs(content: any[]): ToolOutput[] {
  return content.map((c: any): ToolOutput =>
    c?.type === 'diff'
      ? { type: 'diff', path: String(c.path ?? ''), oldText: c.oldText == null ? null : String(c.oldText), newText: String(c.newText ?? '') }
      : c?.type === 'terminal'
        ? { type: 'text', text: `(terminal ${String(c.terminalId ?? '')})` }
        : { type: 'text', text: c?.type === 'content' ? text(c.content) : JSON.stringify(c) },
  );
}

function apply(tc: ToolCallInfo, u: any) {
  if (u.status) tc.status = u.status;
  if (u.title) tc.title = String(u.title);
  if (u.kind) tc.kind = String(u.kind);
  if (Array.isArray(u.locations)) tc.locations = u.locations;
  if (u.rawInput !== undefined) tc.rawInput = u.rawInput;
  if (u.rawOutput !== undefined) tc.rawOutput = u.rawOutput;
  if (Array.isArray(u.content) && u.content.length) tc.output = outputs(u.content);
  const p = permissionOf(u);
  if (p) tc.permission = p;
  const e = escalationOf(u);
  if (e) tc.escalation = tc.escalation ? { ...tc.escalation, status: e.status } : e;
}

export function handleSessionUpdate(notification: any) {
  const update = notification?.update;
  if (!update) return;
  switch (update.sessionUpdate) {
    case 'user_message_chunk': {
      const by = String(update._meta?.wicket?.by ?? 'someone');
      const l = last();
      if (l && l.role === 'user' && l.by === by) l.content += text(update.content);
      else addUser(text(update.content), by);
      break;
    }
    case 'agent_message_chunk': {
      if (isNotice(update)) {
        const l = last();
        if (l && l.role === 'system') l.content += text(update.content);
        else push({ role: 'system', content: text(update.content) });
        break;
      }
      assistant().content += text(update.content);
      break;
    }
    case 'agent_thought_chunk': {
      const m = assistant();
      m.thought = (m.thought || '') + text(update.content);
      break;
    }
    case 'tool_call':
    case 'tool_call_update': {
      if (typeof update.toolCallId !== 'string') break;
      let tc = findTool(update.toolCallId);
      if (!tc) {
        const m = assistant();
        m.toolCalls!.push({ toolCallId: update.toolCallId, title: '', kind: 'other', status: 'pending' });
        tc = m.toolCalls![m.toolCalls!.length - 1];
      }
      apply(tc, update);
      break;
    }
    case 'plan':
      assistant().plan = Array.isArray(update.entries) ? update.entries : [];
      break;
    default:
      break;
  }
}
