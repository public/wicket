import { useMemo, useState, useSyncExternalStore, type FC } from "react";
import {
  AssistantRuntimeProvider,
  ComposerPrimitive,
  MessagePrimitive,
  ThreadPrimitive,
  useExternalStoreRuntime,
  type ThreadMessageLike,
  type ToolCallMessagePartProps,
} from "@assistant-ui/react";
import { begin, beginDecide, describe, finish, runFromLocation, strip, type Begun } from "../../common/wicket";
import { Session, type Msg } from "./session";

const convert = (m: Msg): ThreadMessageLike => ({
  id: m.id,
  role: m.role,
  content: m.parts.map((p) =>
    p.type === "tool-call"
      ? { type: "tool-call", toolCallId: p.toolCallId, toolName: p.toolName, args: p.args as any, result: p.result, isError: p.isError, artifact: p }
      : p,
  ) as any,
  metadata: { custom: { by: m.by } },
});

/** The two-step signed action (#124): the server's description, then its own sign button. */
const Confirm: FC<{ begun: Begun; onDone: (r: any) => void; onCancel: () => void }> = ({ begun, onDone, onCancel }) => {
  const [state, setState] = useState("");
  return (
    <div className="confirm">
      <div className="what">{describe(begun.action)}</div>
      <button
        className={begun.action.decision === "deny" ? "deny" : "approve"}
        onClick={async () => {
          setState("Waiting for your passkey…");
          try {
            onDone(await finish(begun));
          } catch (e) {
            setState(String((e as Error).message));
          }
        }}
      >
        Sign with passkey
      </button>
      <button onClick={onCancel}>Cancel</button>
      <span className="state">{state}</span>
    </div>
  );
};

const SessionContext = { current: null as Session | null };

/** An ordinary tool call: its kind, title, arguments, result, and how wicket answered its prompt. */
const ToolCard: FC<ToolCallMessagePartProps> = ({ args, result, isError, artifact }) => {
  const p: any = artifact ?? {};
  return (
    <details className={`tool ${isError ? "error" : ""}`} open={p.status !== "completed"}>
      <summary>
        <span className="kind">{strip(p.kind)}</span> {strip(p.title)} <span className="status">{strip(p.status)}</span>
        {p.permission && (
          <span className={`perm ${p.permission.optionId === "r" || p.permission.outcome !== "selected" ? "no" : ""}`}>
            permission: {strip(p.permission.outcome)} {p.permission.optionId ? `(${strip(p.permission.optionId)})` : ""} by {strip(p.permission.by)}
          </span>
        )}
      </summary>
      <pre className="args">{JSON.stringify(args, null, 2)}</pre>
      {result !== undefined && <Result result={result} />}
    </details>
  );
};

const Result: FC<{ result: any }> = ({ result }) => (
  <div className="result">
    {(Array.isArray(result) ? result : [result]).map((r, i) =>
      r && typeof r === "object" && r.diff ? (
        <div key={i} className="diff">
          <div className="path">{strip(r.diff.path)}</div>
          {r.diff.oldText != null && <pre className="old">{r.diff.oldText}</pre>}
          <pre className="new">{r.diff.newText}</pre>
        </div>
      ) : (
        <pre key={i}>{typeof r === "string" ? r : JSON.stringify(r, null, 2)}</pre>
      ),
    )}
  </div>
);

/** wicket's escalation, decided inline: the console's signed decide action, then the ACP answer. */
const EscalationCard: FC<ToolCallMessagePartProps> = ({ toolCallId, artifact }) => {
  const s = SessionContext.current!;
  useSyncExternalStore(s.subscribe, () => s.messages);
  const p: any = artifact ?? {};
  const e = p.escalation;
  const asked = s.asked.get(toolCallId);
  const [begun, setBegun] = useState<Begun | null>(null);
  const [err, setErr] = useState("");
  const decided = e?.status && e.status !== "pending";
  return (
    <div className={`escalation ${decided ? e.status : ""}`}>
      <div className="head">
        wicket escalation <code>{strip(e?.id)}</code> · <span className="risk">{strip(e?.risk)}</span>
      </div>
      <div className="op">
        {strip(e?.method)} {strip(e?.host)}
        {strip(e?.path)}
        {e?.prefix ? "… (every path under it)" : ""}
      </div>
      <div className="reason">{strip(e?.reason)}</div>
      {decided && <div className="decided">{strip(e.status)}</div>}
      {!decided && asked && !begun && (
        <div className="buttons">
          {(["approve", "deny"] as const).map((d) => (
            <button
              key={d}
              className={d}
              onClick={async () => {
                try {
                  setBegun(await beginDecide(e.id, d === "approve"));
                } catch (x) {
                  setErr(String((x as Error).message));
                }
              }}
            >
              {d === "approve" ? "Approve once" : "Deny"}
            </button>
          ))}
        </div>
      )}
      {begun && (
        <Confirm
          begun={begun}
          onCancel={() => setBegun(null)}
          onDone={() => {
            setBegun(null);
            s.answered(toolCallId, begun.action.decision === "approve");
          }}
        />
      )}
      {err && <div className="err">{err}</div>}
    </div>
  );
};

const Plan: FC<{ data: any }> = ({ data }) => (
  <ol className="plan">
    {(data?.entries ?? []).map((x: any, i: number) => (
      <li key={i} className={strip(x.status)}>
        {strip(x.content)} <span className="status">{strip(x.status)}</span>
      </li>
    ))}
  </ol>
);

const Reasoning: FC<{ text: string }> = ({ text }) => (
  <details className="thought">
    <summary>thinking</summary>
    <pre>{text}</pre>
  </details>
);

const UserMessage: FC = () => (
  <MessagePrimitive.Root className="msg user">
    <MessagePrimitive.Parts />
  </MessagePrimitive.Root>
);

const AssistantMessage: FC = () => (
  <MessagePrimitive.Root className="msg assistant">
    <MessagePrimitive.Parts
      components={{
        Reasoning,
        tools: { by_name: { wicket_escalation: EscalationCard }, Fallback: ToolCard },
        data: { by_name: { plan: Plan } },
      }}
    />
  </MessagePrimitive.Root>
);

const Thread: FC<{ s: Session }> = ({ s }) => {
  const messages = useSyncExternalStore(s.subscribe, () => s.messages);
  const runtime = useExternalStoreRuntime<Msg>({
    messages,
    isRunning: s.running,
    convertMessage: convert,
    onNew: async (m) => {
      const text = m.content.map((c) => (c.type === "text" ? c.text : "")).join("");
      await s.prompt(text);
    },
  });
  return (
    <AssistantRuntimeProvider runtime={runtime}>
      <ThreadPrimitive.Root className="thread">
        <ThreadPrimitive.Viewport className="viewport">
          <ThreadPrimitive.Messages components={{ UserMessage, AssistantMessage }} />
        </ThreadPrimitive.Viewport>
        <ComposerPrimitive.Root className="composer">
          <ComposerPrimitive.Input placeholder="Prompt the agent…" />
          <ComposerPrimitive.Send>Send</ComposerPrimitive.Send>
        </ComposerPrimitive.Root>
      </ThreadPrimitive.Root>
    </AssistantRuntimeProvider>
  );
};

export const App: FC = () => {
  const run = runFromLocation();
  const s = useMemo(() => new Session(run), [run]);
  SessionContext.current = s;
  useSyncExternalStore(s.subscribe, () => s.messages);
  const [begun, setBegun] = useState<Begun | null>(null);
  const [err, setErr] = useState("");
  return (
    <div className="app">
      <header>
        <b>wicket</b> session <code>{strip(run) || "(add ?run=<id>)"}</code> <span className="state">{s.state}</span>
        {s.error && <span className="err">{s.error}</span>}
      </header>
      {s.state === "idle" && !begun && (
        <button
          disabled={!run}
          onClick={async () => {
            try {
              setBegun(await begin({ action: "open_session", run }));
            } catch (e) {
              setErr(String((e as Error).message));
            }
          }}
        >
          Open session
        </button>
      )}
      {begun && (
        <Confirm
          begun={begun}
          onCancel={() => setBegun(null)}
          onDone={(r) => {
            setBegun(null);
            void s.connect(r.ticket);
          }}
        />
      )}
      {err && <div className="err">{err}</div>}
      {s.state !== "idle" && <Thread s={s} />}
    </div>
  );
};
