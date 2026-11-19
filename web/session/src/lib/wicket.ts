// The console's API as the session view uses it: its signed actions (a passkey assertion per action,
// as the console's own page does), opening a run's ACP session socket, and wicket's escalations.
// Framework-free: the Vue components and the node check (check/check.ts) both import it.

/** The console's POST: its CSRF header, JSON both ways. */
export async function post<T = any>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-wicket-csrf': '1' },
    body: JSON.stringify(body ?? {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j as T;
}

const b2a = (buf: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const a2b = (s: string) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '==='.slice((s.length + 3) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};

async function assertWith(pk: any) {
  const opts = { ...pk, challenge: a2b(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c: any) => ({ ...c, id: a2b(c.id) })) };
  const cred = (await navigator.credentials.get({ publicKey: opts })) as PublicKeyCredential;
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    challenge: pk.challenge,
    id: b2a(cred.rawId),
    clientDataJSON: b2a(r.clientDataJSON),
    authenticatorData: b2a(r.authenticatorData),
    signature: b2a(r.signature),
  };
}

/** A signed action, begun: what the server will have the passkey sign (its own reading of it). */
export interface Begun {
  action: Record<string, any>;
  publicKey: any;
  /** Where its assertion goes. */
  finish: string;
}

/** Step one (#124): the server builds the action; the view shows `describe(begun.action)`. A
 * decision goes through `/api/decide/*`, the decide path every other view uses (#256). */
export async function begin(body: Record<string, unknown>): Promise<Begun> {
  const decide = body.action === 'decide';
  const r = await post<Omit<Begun, 'finish'>>(decide ? '/api/decide/begin' : '/api/action/begin', body);
  return { ...r, finish: decide ? '/api/decide/finish' : '/api/action/finish' };
}

/** Step two, on its own tap: the passkey signs it, and the server applies it. */
export async function finish(b: Begun): Promise<any> {
  return post(b.finish, await assertWith(b.publicKey));
}

// The same set as wicket_core::text::is_unsafe: control, bidi and zero-width characters (#128).
export const strip = (s: unknown) =>
  String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, ' ');

const RISK: Record<string, string> = {
  R0Read: 'R0 · read',
  R1ReadScoped: 'R1 · read (scoped)',
  R2WriteReversible: 'R2 · changes data',
  R3ExternalOrIrreversible: "R3 · visible to others, or can't be undone",
  R4ExecOrPrivilege: 'R4 · push, deploy or privilege',
};
export const riskLabel = (r: unknown) => RISK[String(r)] ?? strip(r);

/** What the passkey is about to sign, in words, from the server's action (never the page's ask).
 * The decide wording is the console's (console.js `describe`). */
export function describe(a: Record<string, any>): string {
  const s = strip;
  if (a.action === 'open_session') return `Open ${s(a.run)}'s session as ${s(a.principal?.id)}${a.agent ? ` · agent ${s(a.agent)}` : ''}`;
  if (a.action === 'decide') {
    // The terms are the effect's (what the passkey signs and the grant is made with), not the
    // page's ask: a git push's grant is a window, unlimited uses for 5 minutes (#26, #574).
    const t = a.effect?.terms ?? { uses: a.uses, ttl_secs: a.ttl_secs };
    const verb = a.decision === 'deny' ? 'Deny' : t.uses === 1 ? 'Approve once' : `Approve${t.uses ? ` ${t.uses} uses` : ' any number of uses'}`;
    const secs = Math.round(t.ttl_secs || 0);
    const how = a.decision === 'deny' ? '' : ` for ${secs >= 3600 && secs % 3600 === 0 ? `${secs / 3600} hour${secs === 3600 ? '' : 's'}` : `${Math.round(secs / 60)} min`}`;
    const what = a.path_prefix ? s(a.method + ' ' + a.host + a.path_prefix) : s(a.method + ' ' + a.host + a.path);
    return (
      `${verb}${how}: ${what}${a.prefix ? '… (every path under it)' : ''}` +
      (a.scope === 'zone' ? ` · any run in zone ${s(a.zone)}` : '') +
      ` · ${riskLabel(a.risk)} · request ${s(a.request)} · run ${s(a.run)}` +
      (a.agent ? ` · agent ${s(a.agent)}` : '') +
      ((a.requested_by || []).length ? ` (${a.requested_by.map(s).join(', ')})` : '')
    );
  }
  return s(a.action);
}

/** The run's ACP socket, and the subprotocols that carry the open's ticket. */
export function socket(run: string, ticket: string): { url: string; protocols: string[] } {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  return { url: `${scheme}://${location.host}/api/runs/${encodeURIComponent(run)}/acp`, protocols: ['acp.v1', `wicket.ticket.${ticket}`] };
}

/** The run a page is for: `/session?run=<id>`, as the console's runs list links it. */
export function runFromLocation(): string {
  const r = new URLSearchParams(location.search).get('run') ?? '';
  return /^[A-Za-z0-9_-]{1,64}$/.test(r) ? r : '';
}

/** wicket's own escalation, as the endpoint describes it in `_meta.wicket.escalation`. */
export interface Escalation {
  id: string;
  method: string;
  host: string;
  path: string;
  risk: string;
  reason: string;
  prefix: boolean;
  status: string;
}

/** The escalation a permission request or tool call carries, if it is wicket's. Only the endpoint
 * sends `session/request_permission` (it never forwards the agent's), and only it sets `_meta`. */
export function escalationOf(x: any): Escalation | null {
  const e = x?._meta?.wicket?.escalation;
  return e && typeof e.id === 'string' ? (e as Escalation) : null;
}

/** How wicket's policy answered one of the agent's own permission requests. */
export function permissionOf(x: any): { outcome: string; optionId: string | null; by: string } | null {
  return x?._meta?.wicket?.permission ?? null;
}

/** Whether a message is wicket's own notice about the session (not the agent's words). */
export const isNotice = (x: any) => x?._meta?.wicket?.notice === true;

/** An escalation's decision, as the console's pending card asks for it: approve once for 10
 * minutes, or deny. Begun here; the sheet shows the server's description before the passkey signs. */
export const decideBody = (id: string, approve: boolean): Record<string, unknown> =>
  approve ? { action: 'decide', id, decision: 'approve', uses: 1, ttl_secs: 600 } : { action: 'decide', id, decision: 'deny' };
