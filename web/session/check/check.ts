// The session view's own client stack (its WebSocket transport, JSON-RPC bridge and update handler)
// against wicket's endpoint, in node. Run by the endpoint's ignored test
// `the_views_client_drives_the_endpoint` (ci/session-view.sh), which plays the supervisor.
import { WebSocketTransport } from '../src/lib/transport/websocket';
import { AcpClientBridge } from '../src/lib/acp-bridge';
import { addUser, handleSessionUpdate, messages } from '../src/session';

const env = (k: string) => process.env[k] ?? '';
class WS extends WebSocket {
  constructor(url: string, protocols?: string | string[]) {
    super(url, { protocols, headers: { cookie: env('COOKIE'), origin: env('ORIGIN') } } as any);
  }
}
const fail = (why: string) => {
  console.log(JSON.stringify(messages.value));
  console.error(why);
  process.exit(1);
};
const until = async (what: string, ok: () => boolean) => {
  for (let i = 0; i < 100 && !ok(); i++) await new Promise((r) => setTimeout(r, 100));
  if (!ok()) fail(`never saw ${what}`);
};

const t = await WebSocketTransport.connect({ url: env('WS_URL'), protocols: [`wicket.ticket.${env('TICKET')}`], WebSocketCtor: WS as any, heartbeatMs: 0 });
const b = new AcpClientBridge(t);
b.onSessionUpdate = handleSessionUpdate;
await b.initialize({ protocolVersion: 1, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false } });
await b.newSession({ cwd: '/', mcpServers: [] });
const msgs = () => messages.value;
const tool = () => msgs().flatMap((m) => m.toolCalls ?? []).find((x) => x.toolCallId === 't1');
await until('the history', () => msgs().some((m) => m.content === 'fixed'));
if (!msgs().some((m) => m.role === 'user' && m.by === 'task')) fail("the task's prompt");
if (!msgs().some((m) => m.thought === 'look first')) fail('the thought');
if (!msgs().some((m) => m.plan?.[0]?.content === 'read main.rs')) fail('the plan');
if ((tool()?.rawInput as any)?.file_path !== '/workspace/main.rs') fail("the tool call's input");
if ((tool()?.output?.[0] as any)?.newText !== 'b') fail("the tool call's diff");
if (tool()?.permission?.optionId !== 'a') fail("wicket's answer to the permission request");
await until('the escalation', () => b.permissions.value.length === 1);
const r = b.permissions.value[0];
if (!msgs().some((m) => m.toolCalls?.some((x) => x.escalation?.id === r.escalation?.id))) fail("the escalation's card");
if (r.options.map((o) => o.kind).join() !== 'allow_once,reject_once') fail('once options');
b.answerPermission(r.rpcId!, 'approve');
addUser('and now?');
const { stopReason } = await b.prompt({ sessionId: env('RUN'), prompt: [{ type: 'text', text: 'and now?' }] });
await until('the reply', () => msgs().some((m) => m.content.includes('you said: and now?')));
// A turn that runs until it is cancelled: session/cancel goes through the ledger to the supervisor.
addUser('wait for me');
const waiting = b.prompt({ sessionId: env('RUN'), prompt: [{ type: 'text', text: 'wait for me' }] });
await until('the waiting turn', () => msgs().some((m) => m.content.includes('you said: wait for me')));
await b.cancel(env('RUN'));
const cancelled = (await waiting).stopReason;
await until("wicket's notice of the cancel", () => msgs().some((m) => m.role === 'system' && m.content.includes('stop its running turn')));
console.log(JSON.stringify({ stop: stopReason, cancelled, escalation: r.escalation?.id, messages: msgs().length }));
process.exit(0);
