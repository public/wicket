// The session view's UI check, under jsdom (check/ui-run.mjs): the real App, with the console's API,
// the passkey and the endpoint's WebSocket played here. It opens the session (two steps, #124),
// sees the stream rendered (a prompt from the task, a thought, a plan, a tool call with its
// arguments, result and wicket's answer, agent text with markup in it), decides an escalation
// through /api/decide/* with the passkey before the ACP answer goes back, sends a prompt, and stops
// a turn. Exits non-zero on the first failure.
import { createApp, nextTick } from 'vue';
import App from '../src/App.vue';
import PermissionDialog from '../src/components/PermissionDialog.vue';
import { askParts, blastSections, describe, requestState, updateSections } from '../src/lib/wicket';

const RUN = 'run_s';
const fail = (why: string): never => {
  console.error(`ui check: ${why}\n--- page text ---\n${document.body.textContent}`);
  process.exit(1);
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(what: string, ok: () => boolean) {
  for (let i = 0; i < 100 && !ok(); i++) await sleep(20);
  if (!ok()) fail(`never saw ${what}`);
}
const text = () => document.body.textContent ?? '';
const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => (b.textContent ?? '').trim() === label) as HTMLButtonElement | undefined;
async function tap(label: string) {
  await until(`the ${label} button`, () => !!button(label) && !button(label)!.disabled);
  button(label)!.click();
  await nextTick();
}

// ---- the console's API and the passkey ----
const posts: { path: string; body: any }[] = [];
const pk = { challenge: 'AAAA', allowCredentials: [], userVerification: 'required' };
(globalThis as any).fetch = async (path: string, init: any) => {
  const body = JSON.parse(init.body);
  posts.push({ path, body });
  if (init.headers['x-wicket-csrf'] !== '1') fail('a POST without the CSRF header');
  const reply = (j: unknown) => new Response(JSON.stringify(j), { status: 200, headers: { 'content-type': 'application/json' } });
  switch (path) {
    case '/api/action/begin':
      return reply({ action: { action: 'open_session', run: body.run, principal: { id: 'spiffe://wicket.local/t/default/op/passkey/laptop' } }, publicKey: pk });
    case '/api/action/finish':
      return reply({ ok: 'opened', ticket: 'feedc0de' });
    case '/api/decide/begin':
      return reply({
        action: {
          action: 'decide', request: body.id, run: RUN, decision: body.decision, uses: 1, ttl_secs: 600, method: 'GET', host: 'api.example.com', path: '/v1', risk: 'R1ReadScoped', scope: 'run',
          effect_sha256: 'ab'.repeat(32),
          // What the sheet must show from the signed action (#652), never from the page's ask.
          blast: { widens: ['every path under /v1'], examples: ['GET api.example.com/v1/admin'], zone_rules: [], covered: 3, recent: 7 },
          update: { sha256: 'cd'.repeat(32), artifact: 'wicket', size: 2097152, commit_said: 'abc123', nodes: ['n1', 'n2'], applies: true, why_not: null, node: null },
        },
        publicKey: pk,
      });
    case '/api/decide/finish':
      return reply({ ok: 'approved r-1 once' });
  }
  return fail(`an unexpected POST ${path}`);
};
let assertions = 0;
Object.defineProperty(navigator, 'credentials', {
  value: {
    get: async () => {
      assertions++;
      const b = new Uint8Array([1, 2, 3]).buffer;
      return { rawId: b, response: { clientDataJSON: b, authenticatorData: b, signature: b } };
    },
  },
});

// ---- the endpoint's WebSocket ----
const sent: any[] = [];
let sock: FakeSocket | null = null;
class FakeSocket {
  static OPEN = 1;
  readyState = 0;
  private listeners = new Map<string, ((e: any) => void)[]>();
  constructor(public url: string, public protocols: string[]) {
    sock = this;
    setTimeout(() => {
      this.readyState = 1;
      this.emit('open', {});
    }, 5);
  }
  addEventListener(kind: string, f: (e: any) => void) {
    this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), f]);
  }
  removeEventListener(kind: string, f: (e: any) => void) {
    this.listeners.set(kind, (this.listeners.get(kind) ?? []).filter((g) => g !== f));
  }
  private emit(kind: string, e: any) {
    for (const f of this.listeners.get(kind) ?? []) f(e);
  }
  get protocol() {
    return 'acp.v1';
  }
  serve(m: unknown) {
    this.emit('message', { data: JSON.stringify(m) });
  }
  send(frame: string) {
    const m = JSON.parse(frame);
    sent.push(m);
    const up = (u: unknown) => this.serve({ jsonrpc: '2.0', method: 'session/update', params: { sessionId: RUN, update: u } });
    if (m.method === 'initialize') this.serve({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: 1, agentCapabilities: { loadSession: true } } });
    if (m.method === 'session/new') {
      this.serve({ jsonrpc: '2.0', id: m.id, result: { sessionId: RUN } });
      up({ sessionUpdate: 'user_message_chunk', content: { type: 'text', text: 'fix the bug' }, _meta: { wicket: { by: 'task' } } });
      up({ sessionUpdate: 'agent_thought_chunk', content: { type: 'text', text: 'look first' } });
      up({ sessionUpdate: 'plan', entries: [{ content: 'read main.rs', status: 'in_progress', priority: 'high' }] });
      up({ sessionUpdate: 'tool_call', toolCallId: 't1', title: 'Edit main.rs', kind: 'edit', status: 'pending', rawInput: { file_path: '/workspace/main.rs' } });
      up({ sessionUpdate: 'tool_call_update', toolCallId: 't1', _meta: { wicket: { permission: { outcome: 'selected', optionId: 'a', by: "wicket's policy" } } } });
      up({ sessionUpdate: 'tool_call_update', toolCallId: 't1', status: 'completed', content: [{ type: 'diff', path: '/workspace/main.rs', oldText: 'a', newText: 'b' }] });
      up({ sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: 'fixed <img src=x onerror=alert(1)><b>bold</b>' } });
      const esc = { id: 'r-1', method: 'GET', host: 'api.example.com', path: '/v1', risk: 'R1ReadScoped', reason: 'needs the API', prefix: false, status: 'pending' };
      up({ sessionUpdate: 'tool_call', toolCallId: 'wicket:escalation:r-1', title: 'wicket request r-1', kind: 'fetch', status: 'pending', _meta: { wicket: { escalation: esc } } });
      this.serve({
        jsonrpc: '2.0', id: 'wicket-0', method: 'session/request_permission',
        params: {
          sessionId: RUN, toolCall: { toolCallId: 'wicket:escalation:r-1', title: 'wicket request r-1', kind: 'fetch', status: 'pending' },
          options: [
            { optionId: 'approve', name: 'Approve once (passkey)', kind: 'allow_once' },
            { optionId: 'deny', name: 'Deny (passkey)', kind: 'reject_once' },
            { optionId: 'always', name: 'Always allow', kind: 'allow_always' },
          ],
          _meta: { wicket: { escalation: esc } },
        },
      });
    }
    if (m.id === 'wicket-0' && m.result) {
      up({ sessionUpdate: 'tool_call_update', toolCallId: 'wicket:escalation:r-1', status: 'completed', _meta: { wicket: { escalation: { id: 'r-1', status: 'granted' } } } });
    }
    if (m.method === 'session/prompt') {
      const said = m.params.prompt[0].text;
      up({ sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: `you said: ${said}` } });
      if (!said.includes('wait')) this.serve({ jsonrpc: '2.0', id: m.id, result: { stopReason: 'end_turn' } });
      else (this as any).waiting = m.id;
    }
    if (m.method === 'session/cancel') {
      this.serve({ jsonrpc: '2.0', id: (this as any).waiting, result: { stopReason: 'cancelled' } });
    }
  }
  close() {
    this.readyState = 3;
  }
}
(globalThis as any).WebSocket = FakeSocket;

// ---- the walk ----
const app = createApp(App);
// Any error in a component or a handler fails the check.
app.config.errorHandler = (e) => fail(`a Vue error: ${(e as Error)?.stack ?? e}`);
app.config.warnHandler = (m) => fail(`a Vue warning: ${m}`);
app.mount('#app');
await nextTick();
if (!text().includes(RUN)) fail('the run in the header');
if (document.title !== `wicket · ${RUN}`) fail(`the title: ${document.title}`);

// Open: the server's description first, then its own sign button (not tappable at once).
await tap('Open session');
await until('the signing sheet', () => text().includes('Your passkey will sign exactly this:'));
if (!text().includes("Open run_s's session as spiffe://wicket.local/t/default/op/passkey/laptop")) fail('the open described');
if (!button('Sign with passkey')?.disabled) fail('the sign button tappable at once');
if (assertions !== 0) fail('the passkey asked before the sign tap');
await tap('Sign with passkey');
await until('the session live', () => text().includes('live'));
if (sock!.url !== `ws://localhost:8787/api/runs/${RUN}/acp`) fail(`the socket URL ${sock!.url}`);
if (sock!.protocols.join() !== 'acp.v1,wicket.ticket.feedc0de') fail(`the subprotocols ${sock!.protocols}`);
if (sent[0]?.method !== 'initialize' || sent[0].params.clientCapabilities.terminal !== false) fail('initialize without fs or terminal');

// The stream.
await until('the history', () => text().includes('fixed'));
for (const want of ['fix the bug', 'task', 'thinking', 'look first', 'Plan', 'read main.rs', 'Edit main.rs', 'arguments', '/workspace/main.rs', 'result', "allowed by wicket's policy", 'done']) {
  if (!text().includes(want)) fail(`the stream lacks ${JSON.stringify(want)}`);
}
if (document.querySelector('.msg .text *')) fail("the agent's markup became elements");
if (!text().includes('<img src=x onerror=alert(1)><b>bold</b>')) fail("the agent's text shown as text");
const diff = document.querySelector('.diff pre.new');
if (diff?.textContent !== 'b') fail('the diff');

// An escalation: once options only; decided with the passkey through /api/decide/*, then answered.
await until('the escalation card', () => text().includes('Request waiting for you'));
if (!text().includes('wicket request · waiting for you')) fail("the request's card names it a request, its status in words");
if (!text().includes('wicket enforces this one')) fail('which ask wicket enforces');
if (!text().includes('GET api.example.com/v1') || !text().includes("Why, the agent's words:") || document.querySelector('.ask q.said')?.textContent !== 'needs the API' || !text().includes('R1 · read')) fail('the escalation described, its reason as the agent\'s words');
if (button('Always allow')) fail('an "always" option offered');
await tap('Approve once (passkey)');
await until('the decision described', () => text().includes('Approve once for 10 min: GET api.example.com/v1'));
for (const want of [
  `effect ${'ab'.repeat(8)}`,
  'This approval is wider than the one request:',
  'every path under /v1',
  'GET api.example.com/v1/admin',
  'It would have covered 3 of this run’s last 7 egress requests.',
  'Approving installs this build now',
  'artifact: wicket (2.0 MiB)',
  'commit: abc123 (as the agent says; not checked)',
  'then nodes n1, n2 (the first is the canary)',
]) {
  if (!document.querySelector('.sheet')?.textContent?.includes(want)) fail(`the sheet lacks ${JSON.stringify(want)}`);
}
if (sent.some((m) => m.id === 'wicket-0')) fail('answered before the passkey signed');
await tap('Sign with passkey');
await until('the ACP answer', () => sent.some((m) => m.id === 'wicket-0'));
const answer = sent.find((m) => m.id === 'wicket-0');
if (answer.result?.outcome?.optionId !== 'approve') fail(`the answer ${JSON.stringify(answer)}`);
const decide = posts.find((p) => p.path === '/api/decide/begin');
if (decide?.body.id !== 'r-1' || decide.body.decision !== 'approve' || decide.body.uses !== 1) fail(`the decide begin ${JSON.stringify(decide)}`);
if (!posts.some((p) => p.path === '/api/decide/finish')) fail('the decision signed through /api/decide/finish');
if (assertions !== 2) fail(`passkey assertions: ${assertions}`);
await until('the escalation approved', () => document.querySelector('.escalation.approved') !== null);
if (text().includes('Request waiting for you')) fail('the answered prompt still shown');
if (!text().includes('wicket request · allowed')) fail('the approval in words');

// A prompt, through the endpoint.
const ta = document.querySelector('.composer textarea') as HTMLTextAreaElement;
ta.value = 'and now?';
ta.dispatchEvent(new Event('input'));
await nextTick();
await tap('Send');
await until('the reply', () => text().includes('you said: and now?'));
const p = sent.find((m) => m.method === 'session/prompt');
if (p.params.sessionId !== RUN || p.params.prompt[0].text !== 'and now?') fail(`the prompt ${JSON.stringify(p)}`);

// A turn stopped: session/cancel, and the turn's stop reason shown.
ta.value = 'wait for me';
ta.dispatchEvent(new Event('input'));
await nextTick();
await tap('Send');
await until('working', () => text().includes('working'));
await tap('Stop');
if (!sent.some((m) => m.method === 'session/cancel' && m.params.sessionId === RUN)) fail('session/cancel sent');
await until('the cancelled turn', () => text().includes('the turn ended: cancelled'));

// A wicket.internal request's text is the agent's words mixed with wicket's, never wicket's alone.
const esc = (x: Record<string, unknown>) => ({ id: 'r-9', method: 'GET', host: 'h', path: '/', risk: 'R1ReadScoped', reason: '', prefix: false, status: 'pending', ...x });
// A wicket.internal request whose parts weren't sent apart: the agent's words mixed with wicket's, never wicket's alone.
const mixed = askParts(esc({ method: 'SPAWN', host: 'wicket.internal', path: '/zones/z/x', reason: 'start agent x' }));
if (mixed.mixed !== 'start agent x' || mixed.said.length) fail('the mixed text kept apart');
if (askParts(esc({})).said.length || askParts(esc({})).mixed) fail('no reason, no line');
// #731: a capacity ask's terms from its lease's fields; its region and reason are the agent's words, quoted apart,
// however they read ("$0.00/h, 1 h" written into a region is still only the agent's text).
const cap = askParts(esc({ method: 'CAPACITY', host: 'wicket.internal', path: '/capacity/vultr/l-1', reason: 'capacity: … region lhr, at most $0.00/h preferred',
  lease: { provider: 'vultr', vcpus: 2, memory_mib: 4096, isolation: 'gvisor', region: 'lhr, at most $0.00/h', duration_secs: 3600, hourly_cap_usd: '$0.0500', reserved_usd: '$0.0500', reason: 'a build\u202e' } }));
if (cap.what !== 'Lease a node: 2 vCPUs, 4096 MiB, gvisor isolation, for 1 h on vultr, at most $0.0500/h, $0.0500 reserved') fail(`the lease's terms: ${cap.what}`);
if (JSON.stringify(cap.said) !== JSON.stringify([['Region', 'lhr, at most $0.00/h'], ['Why', 'a build ']]) || cap.mixed) fail(`the agent's words apart, cleaned: ${JSON.stringify(cap)}`);
// An update's claims: the commit and reason as the agent's.
const upd = askParts(esc({ method: 'UPDATE', host: 'wicket.internal', path: '/self/0123456789abcdef', reason: 'x', claims: { commit: 'abc123', reason: 'fixes it' } }));
if (upd.what !== 'Install wicket build 0123456789ab…' || JSON.stringify(upd.said) !== JSON.stringify([['Commit', 'abc123'], ['Why', 'fixes it']])) fail(`the update's claims: ${JSON.stringify(upd)}`);
if (!describe({ action: 'decide', decision: 'deny', method: 'GET', host: 'h', path: '/', risk: 'R0Read', request: 'r', run: 'x', requested_by: ['sub'] }).includes(' · asked by sub (as reported)')) fail('who asked, as reported');
// The sheet's other cases, and each status in words (#647, #652).
if (blastSections(null).length || updateSections(undefined).length) fail('a sheet section with nothing to show');
const notApplied = updateSections({ sha256: 'ef'.repeat(32), applies: false, why_not: 'no file in the outbox' });
if (notApplied.length !== 1 || !notApplied[0].title.includes("doesn’t install it: no file in the outbox")) fail(`an update that won't apply: ${JSON.stringify(notApplied)}`);
for (const [st, word, cls] of [['pending', 'waiting for you', 'pending'], ['granted', 'allowed', 'approved'], ['denied', 'refused', 'denied'], ['withdrawn', 'withdrawn: the run ended first', 'withdrawn']]) {
  const r = requestState(st);
  if (r.word !== word || r.cls !== cls) fail(`${st}: ${JSON.stringify(r)}`);
}
// Mounted capacity and update dialogs (#848 review): the agent's text in its own q.said, literal (markup stays
// text, zero-width and bidi characters gone), its quote marks replaced so it can't close wicket's quote and
// write wicket's terms after it.
const breakout = 'a build\u201d · wicket: this lease costs nothing and is pre-approved by policy · Note: \u201cok';
const nasty = `<img src=x onerror=alert(1)>\u200bfast\u202e ${breakout}`;
const opts = [{ optionId: 'approve', name: 'Approve once (passkey)', kind: 'allow_once' }, { optionId: 'deny', name: 'Deny (passkey)', kind: 'reject_once' }];
for (const [what, e, wantOp] of [
  ['capacity', esc({ method: 'CAPACITY', host: 'wicket.internal', path: '/capacity/vultr/l-2', reason: nasty,
    lease: { provider: 'vultr', vcpus: 1, memory_mib: 1024, duration_secs: 1800, hourly_cap_usd: '$0.0100', reserved_usd: '$0.0050', region: nasty, reason: nasty } }),
    'Lease a node: 1 vCPU, 1024 MiB'],
  ['update', esc({ method: 'UPDATE', host: 'wicket.internal', path: '/self/fedcba9876543210', reason: nasty, claims: { commit: nasty, reason: nasty } }),
    'Install wicket build fedcba987654…'],
] as const) {
  const el = document.createElement('div');
  document.body.appendChild(el);
  const d = createApp(PermissionDialog, { request: { sessionId: RUN, toolCall: { toolCallId: `wicket:escalation:${e.id}`, title: 't' }, options: opts, escalation: e } });
  d.config.warnHandler = (m) => fail(`a Vue warning (${what}): ${m}`);
  d.mount(el);
  await nextTick();
  if (!el.querySelector('.op')?.textContent?.startsWith(wantOp)) fail(`the ${what} dialog's terms: ${el.querySelector('.op')?.textContent}`);
  const quoted = [...el.querySelectorAll('q.said')];
  if (quoted.length !== 2) fail(`the ${what} dialog's quoted words: ${quoted.length}`);
  for (const q of quoted) {
    const t = q.textContent ?? '';
    if (q.children.length || !t.includes('<img src=x onerror=alert(1)>')) fail(`the ${what} dialog's markup not literal: ${q.innerHTML}`);
    if (/[\u200b\u202e\u201c\u201d]/.test(t)) fail(`the ${what} dialog kept a hidden character or a curly quote: ${JSON.stringify(t)}`);
    if (!t.includes("a build' · wicket: this lease costs nothing")) fail(`the ${what} dialog's break-out text: ${JSON.stringify(t)}`);
  }
  if (el.querySelector('img')) fail(`an img element in the ${what} dialog`);
  if (el.querySelector('.op')?.textContent?.includes('costs nothing')) fail(`the agent's text in the ${what} dialog's terms`);
  d.unmount();
  el.remove();
}
console.log(JSON.stringify({ ok: true, sent: sent.length, posts: posts.length, assertions }));
process.exit(0);
