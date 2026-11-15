// What both session views share: the console's signed actions (a passkey assertion per action, as
// the console's own page does), opening a run's ACP session socket, and wicket's escalation prompts.
//
// Framework-free on purpose: both views (React with assistant-ui, Vue with acp-ui's components)
// import this file, so the comparison is of the views, not of two takes on wicket's API.

/** The console's POST: its CSRF header, JSON both ways. */
export async function post<T = any>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-wicket-csrf": "1" },
    body: JSON.stringify(body ?? {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j as T;
}

const b2a = (buf: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const a2b = (s: string) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "===".slice((s.length + 3) % 4);
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
}

/** Step one (#124): the server builds the action; the view shows `describe(begun.action)`. */
export const begin = (body: Record<string, unknown>) => post<Begun>("/api/action/begin", body);

/** Step two, on its own tap: the passkey signs it, and the server applies it. */
export async function finish(b: Begun): Promise<any> {
  return post("/api/action/finish", await assertWith(b.publicKey));
}

// The same set as wicket_core::text::is_unsafe: control, bidi and zero-width characters (#128).
export const strip = (s: unknown) =>
  String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, " ");

/** What the passkey is about to sign, in words, from the server's action (never the page's ask). */
export function describe(a: Record<string, any>): string {
  if (a.action === "open_session") return `Open ${strip(a.run)}'s session as ${strip(a.principal?.id)}${a.agent ? ` · agent ${strip(a.agent)}` : ""}`;
  if (a.action === "decide") {
    const verb = a.decision === "deny" ? "Deny" : a.uses === 1 ? "Approve once" : `Allow ${a.uses ?? "unlimited"} uses`;
    return `${verb}: ${strip(a.method)} ${strip(a.host)}${strip(a.path)} · ${strip(a.risk)} · request ${strip(a.request)} · run ${strip(a.run)}`;
  }
  return strip(a.action);
}

/** The run's ACP socket, and the subprotocols that carry the open's ticket. */
export function socket(run: string, ticket: string): { url: string; protocols: string[] } {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return { url: `${scheme}://${location.host}/api/runs/${encodeURIComponent(run)}/acp`, protocols: ["acp.v1", `wicket.ticket.${ticket}`] };
}

/** The run a view is for: `?run=<id>`. */
export const runFromLocation = () => new URLSearchParams(location.search).get("run") ?? "";

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
  return e && typeof e.id === "string" ? (e as Escalation) : null;
}

/** How wicket's policy answered one of the agent's own permission requests. */
export function permissionOf(x: any): { outcome: string; optionId: string | null; by: string } | null {
  return x?._meta?.wicket?.permission ?? null;
}

/** Decides an escalation through the console's signed decide action: begin (shown), then sign. */
export const beginDecide = (id: string, approve: boolean) =>
  begin({ action: "decide", id, decision: approve ? "approve" : "deny", uses: 1, ttl_secs: 600 });
