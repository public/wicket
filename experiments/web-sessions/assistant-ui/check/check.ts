// The view's own client stack (src/session.ts: the ACP SDK over its WebSocket stream, folded into
// what assistant-ui renders) against wicket's endpoint, in node. Run by the endpoint's ignored test
// `the_views_clients_drive_the_endpoint`; built with `npm run check:build`.
import { Session } from "../src/session";

const env = (k: string) => process.env[k] ?? "";
// Node's WebSocket takes headers: the console session's cookie and its origin, as a browser sends.
class WS extends WebSocket {
  constructor(url: string, protocols?: string | string[]) {
    super(url, { protocols, headers: { cookie: env("COOKIE"), origin: env("ORIGIN") } } as any);
  }
}
const fail = (why: string, s: Session) => {
  console.log(JSON.stringify(s.messages));
  console.error(why);
  process.exit(1);
};
const until = async (s: Session, what: string, ok: () => boolean) => {
  for (let i = 0; i < 100 && !ok(); i++) await new Promise((r) => setTimeout(r, 100));
  if (!ok()) fail(`never saw ${what}`, s);
};

const s = new Session(env("RUN"));
await s.connect(env("TICKET"), { url: env("WS_URL"), WebSocket: WS });
if (s.state !== "open") fail(`not open: ${s.error}`, s);
const parts = () => s.messages.flatMap((m) => m.parts.map((p) => ({ ...p, role: m.role, by: m.by })));
const tool = () => parts().find((p: any) => p.type === "tool-call" && p.toolCallId === "t1") as any;
await until(s, "the history", () => parts().some((p: any) => p.type === "text" && p.text === "fixed"));
if (!parts().some((p: any) => p.role === "user" && p.by === "task")) fail("the task's prompt", s);
if (!parts().some((p: any) => p.type === "reasoning")) fail("the thought", s);
if (!parts().some((p: any) => p.type === "data-plan" && p.data.entries[0].content === "read main.rs")) fail("the plan", s);
if (tool()?.args?.file_path !== "/workspace/main.rs") fail("the tool call's input", s);
if (tool()?.result?.[0]?.diff?.newText !== "b") fail("the tool call's diff", s);
if (tool()?.permission?.optionId !== "a") fail("wicket's answer to the permission request", s);
await until(s, "the escalation", () => s.asked.size === 1);
const [toolCallId, asked] = [...s.asked.entries()][0];
if (!parts().some((p: any) => p.toolName === "wicket_escalation" && p.toolCallId === toolCallId)) fail("the escalation's card", s);
// Answered without the passkey decision: the endpoint must decide nothing.
s.answered(toolCallId, true);
const stop = await s.prompt("and now?");
await until(s, "the reply", () => parts().some((p: any) => p.type === "text" && p.text.includes("you said: and now?")));
console.log(JSON.stringify({ stop, escalation: asked.escalation.id, messages: s.messages.length }));
process.exit(0);
