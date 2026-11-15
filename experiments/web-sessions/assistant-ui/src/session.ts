// The ACP side: the official TypeScript SDK's client over its WebSocket stream, folded into a small
// store of messages that assistant-ui's external-store runtime renders.
import { client, methods, type RequestPermissionRequest, type RequestPermissionResponse, type SessionNotification } from "@agentclientprotocol/sdk";
import { createWebSocketStream } from "@agentclientprotocol/sdk/experimental/ws-client";
import { escalationOf, permissionOf, socket, type Escalation } from "../../common/wicket";

export type Part =
  | { type: "text"; text: string }
  | { type: "reasoning"; text: string }
  | {
      type: "tool-call";
      toolCallId: string;
      toolName: string;
      title: string;
      kind: string;
      status: string;
      args: Record<string, unknown>;
      result?: unknown;
      isError?: boolean;
      permission?: { outcome: string; optionId: string | null; by: string };
      escalation?: Escalation;
    }
  | { type: "data-plan"; data: { entries: { content: string; status: string; priority?: string }[] } };

export interface Msg {
  id: string;
  role: "user" | "assistant";
  by?: string;
  parts: Part[];
}

/** An escalation prompt waiting for the operator, answered once the console has the decision. */
export interface Asked {
  escalation: Escalation;
  resolve: (r: RequestPermissionResponse) => void;
}

type Listener = () => void;

export class Session {
  messages: Msg[] = [];
  running = false;
  state: "idle" | "connecting" | "open" | "closed" = "idle";
  error = "";
  asked = new Map<string, Asked>();
  private listeners = new Set<Listener>();
  private conn: ReturnType<ReturnType<typeof client>["connect"]> | null = null;
  private n = 0;
  constructor(readonly run: string) {}

  subscribe = (l: Listener) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };
  private changed() {
    // New array identities, so React sees the change.
    this.messages = [...this.messages];
    this.listeners.forEach((l) => l());
  }

  async connect(ticket: string) {
    this.state = "connecting";
    this.changed();
    const { url, protocols } = socket(this.run, ticket);
    const app = client({ name: "wicket-console" })
      .onNotification(methods.client.session.update, ({ params }: { params: SessionNotification }) => this.update(params))
      .onRequest(methods.client.session.requestPermission, ({ params }: { params: RequestPermissionRequest }) => this.permission(params));
    const conn = app.connect(createWebSocketStream(url, { protocols }));
    this.conn = conn;
    conn.closed.then(() => {
      this.state = "closed";
      this.running = false;
      this.changed();
    });
    try {
      // wicket's endpoint offers nothing to the client, and the client offers nothing back.
      await conn.agent.request(methods.agent.initialize, {
        protocolVersion: 1,
        clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
        clientInfo: { name: "wicket-console", version: "0" },
      });
      await conn.agent.request(methods.agent.session.new, { cwd: "/", mcpServers: [] });
      this.state = "open";
    } catch (e) {
      this.error = String((e as Error).message ?? e);
      this.state = "closed";
    }
    this.changed();
  }

  async prompt(text: string) {
    if (!this.conn) return;
    this.messages.push({ id: `u${this.n++}`, role: "user", by: "you", parts: [{ type: "text", text }] });
    this.running = true;
    this.changed();
    try {
      await this.conn.agent.request(methods.agent.session.prompt, { sessionId: this.run, prompt: [{ type: "text", text }] });
    } catch (e) {
      this.error = String((e as Error).message ?? e);
    }
    this.running = false;
    this.changed();
  }

  /** The assistant message the next part goes into (a new one after a user message). */
  private assistant(): Msg {
    const last = this.messages[this.messages.length - 1];
    if (last?.role === "assistant") return last;
    const m: Msg = { id: `a${this.n++}`, role: "assistant", parts: [] };
    this.messages.push(m);
    return m;
  }

  private tool(id: string): Extract<Part, { type: "tool-call" }> | undefined {
    for (let i = this.messages.length - 1; i >= 0; i--) {
      for (const p of this.messages[i].parts) if (p.type === "tool-call" && p.toolCallId === id) return p;
    }
    return undefined;
  }

  private update(n: SessionNotification) {
    const u: any = n.update;
    const text = (c: any) => (c?.type === "text" ? String(c.text ?? "") : "");
    switch (u.sessionUpdate) {
      case "user_message_chunk": {
        const by = u._meta?.wicket?.by ?? "someone";
        const last = this.messages[this.messages.length - 1];
        if (last?.role === "user" && last.by === by && last.parts[0]?.type === "text") last.parts[0].text += text(u.content);
        else this.messages.push({ id: `u${this.n++}`, role: "user", by, parts: [{ type: "text", text: text(u.content) }] });
        break;
      }
      case "agent_message_chunk":
      case "agent_thought_chunk": {
        const kind = u.sessionUpdate === "agent_message_chunk" ? "text" : "reasoning";
        const m = this.assistant();
        const last = m.parts[m.parts.length - 1];
        if (last && last.type === kind) last.text += text(u.content);
        else m.parts.push({ type: kind, text: text(u.content) });
        m.parts = [...m.parts];
        break;
      }
      case "tool_call": {
        const m = this.assistant();
        const esc = escalationOf(u);
        m.parts = [
          ...m.parts,
          {
            type: "tool-call",
            toolCallId: u.toolCallId,
            toolName: esc ? "wicket_escalation" : String(u.kind ?? "other"),
            title: String(u.title ?? ""),
            kind: String(u.kind ?? "other"),
            status: String(u.status ?? "pending"),
            args: (u.rawInput && typeof u.rawInput === "object" ? u.rawInput : {}) as Record<string, unknown>,
            escalation: esc ?? undefined,
          },
        ];
        break;
      }
      case "tool_call_update": {
        const p = this.tool(u.toolCallId);
        if (!p) break;
        if (u.status) p.status = u.status;
        if (u.title) p.title = u.title;
        if (u.rawInput) p.args = u.rawInput;
        if (u.status === "failed") p.isError = true;
        const content = (u.content ?? []) as any[];
        if (content.length) {
          p.result = content.map((c) =>
            c.type === "diff" ? { diff: { path: c.path, oldText: c.oldText ?? null, newText: c.newText } } : c.type === "content" ? text(c.content) : c,
          );
        } else if (u.rawOutput !== undefined) p.result = u.rawOutput;
        const perm = permissionOf(u);
        if (perm) p.permission = perm;
        const esc = escalationOf(u);
        if (esc && p.escalation) p.escalation = { ...p.escalation, status: esc.status };
        this.touch(u.toolCallId);
        break;
      }
      case "plan": {
        const m = this.assistant();
        const plan: Part = { type: "data-plan", data: { entries: u.entries ?? [] } };
        // One plan per message: the newest replaces the last.
        const i = m.parts.findIndex((x) => x.type === "data-plan");
        m.parts = i >= 0 ? m.parts.map((x, j) => (j === i ? plan : x)) : [...m.parts, plan];
        break;
      }
      default:
        break;
    }
    this.changed();
  }

  /** Replaces the message holding a tool call, so its part re-renders. */
  private touch(id: string) {
    for (const m of this.messages) {
      if (m.parts.some((p) => p.type === "tool-call" && p.toolCallId === id)) m.parts = m.parts.map((p) => ({ ...p }));
    }
  }

  /** wicket's escalation prompts: held until the operator decides inline (with their passkey). */
  private permission(p: RequestPermissionRequest): Promise<RequestPermissionResponse> {
    const esc = escalationOf(p);
    if (!esc) return Promise.resolve({ outcome: { outcome: "cancelled" } });
    return new Promise((resolve) => {
      this.asked.set(p.toolCall.toolCallId, { escalation: esc, resolve });
      this.changed();
    });
  }

  /** The operator decided (the console has the signed decision): tell the endpoint. */
  answered(toolCallId: string, approve: boolean) {
    const a = this.asked.get(toolCallId);
    if (!a) return;
    this.asked.delete(toolCallId);
    a.resolve({ outcome: { outcome: "selected", optionId: approve ? "approve" : "deny" } });
    this.changed();
  }
}
