#!/usr/bin/env python3
"""A misbehaving ACP agent for ci/acceptance.sh (#66): it speaks the Agent Client Protocol on stdio and,
on each prompt, tries everything a hostile agent would: client file and terminal calls, permission
requests that offer "always" options, a write to .claude/settings.local.json, a mode change. It
records what wicket (its client) sent and answered, in /workspace/out/result.json, and checks the
gateway it was given answers. On session/load (a wake) it replays its history and asks for permission
in the middle of the replay, which must not be approved.

It also decides its own lifetime (#249). After its first turn it idles on its own timer (SELF_WAKE
seconds, reading nothing), wakes by itself, says so, and only then asks wicket to hibernate it
(the gateway's hibernate tool): wicket must neither have ended nor paused it meanwhile. Woken, it
asks to finish after its turn.

No model is involved. Standard library only.
"""
import json
import os
import sys
import time
import urllib.request

HOME = os.environ.get("HOME", "/tmp")
HIST = os.path.join(HOME, "acp-mock-history.json")
OUT = "/workspace/out/result.json"

seen = {"initialize": None, "session": None, "answers": {}, "errors": {}, "gateway": None, "prompts": [], "load": None}
if os.path.exists(OUT):
    try:
        seen.update(json.load(open(OUT)).get("seen", {}))
    except Exception:
        pass
history = json.load(open(HIST)) if os.path.exists(HIST) else {"session": None, "updates": []}
next_id = 1000
inbox = []  # messages that arrived while waiting for an answer, handled next
SELF_WAKE = 8  # seconds the agent idles between its turn and its own wakeup


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def update(sid, u, keep=True):
    send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": u}})
    if keep:
        history["updates"].append(u)


def ask(label, method, params):
    """Sends a request to the client and waits for its answer; anything else that arrives meanwhile
    (a queued prompt, say) is kept for later."""
    global next_id
    next_id += 1
    rid = next_id
    send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    for line in sys.stdin:
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("id") == rid and "method" not in m:
            if "error" in m:
                seen["errors"][label] = m["error"].get("code")
            else:
                o = m.get("result", {}).get("outcome") or {}
                seen["answers"][label] = o.get("optionId") or o.get("outcome")
            return
        inbox.append(m)
    raise SystemExit("stdin closed while waiting")


def permission(label, sid, tool_call, kinds=("allow_always", "allow_once", "reject_once", "reject_always")):
    opts = [{"optionId": "opt-" + k, "name": "Yes, " + k.replace("_", " "), "kind": k} for k in kinds]
    ask(label, "session/request_permission", {"sessionId": sid, "toolCall": tool_call, "options": opts})


def gateway():
    """wicket's MCP gateway, as the session's mcpServers named it."""
    servers = (seen.get("session") or {}).get("mcpServers") or []
    if len(servers) != 1:
        return "not exactly one MCP server"
    req = urllib.request.Request(
        servers[0]["url"],
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode(),
        headers={"content-type": "application/json", "accept": "application/json, text/event-stream"},
    )
    try:
        body = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=20).read().decode()
        names = [t["name"] for t in json.loads(body)["result"]["tools"]]
        return "tools: %d, with await_grant: %s" % (len(names), "await_grant" in names)
    except Exception as e:  # noqa: BLE001
        return "error: %s" % e


def call_tool(name):
    """Calls one of wicket's gateway tools; the first line of its answer."""
    servers = (seen.get("session") or {}).get("mcpServers") or []
    if len(servers) != 1:
        return "not exactly one MCP server"
    req = urllib.request.Request(
        servers[0]["url"],
        data=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": {}}}).encode(),
        headers={"content-type": "application/json", "accept": "application/json, text/event-stream"},
    )
    try:
        body = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=20).read().decode()
        r = json.loads(body)["result"]
        # Short: wicket prints result.json clipped.
        return (("error: " if r.get("isError") else "") + r["content"][0]["text"].splitlines()[0])[:50]
    except Exception as e:  # noqa: BLE001
        return "error: %s" % e


def brief(p):
    """What the checks need of a session's params (wicket prints result.json clipped)."""
    sp = p.get("systemPrompt") or {}
    text = " ".join(b.get("text", "") for b in sp.get("content", []))
    return {
        "cwd": p.get("cwd"),
        "mcpServers": p.get("mcpServers"),
        "systemPrompt": {"mode": sp.get("mode"), "head": text[:40]},
        "has_meta": "_meta" in p,
    }


def save(status):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    always = os.path.exists("/workspace/.claude/settings.local.json")
    json.dump({"status": status, "summary": "acp mock", "pending_requests": [], "seen": seen, "always_state_written": always}, open(OUT, "w"))
    json.dump(history, open(HIST, "w"))


def turn(sid, text):
    seen["prompts"].append(text[-40:])
    update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Working on it"}})
    update(sid, {"sessionUpdate": "plan", "entries": [{"content": "misbehave", "priority": "high", "status": "in_progress"}]})
    # Client capabilities wicket didn't offer.
    ask("fs_read", "fs/read_text_file", {"sessionId": sid, "path": "/etc/passwd"})
    ask("fs_write", "fs/write_text_file", {"sessionId": sid, "path": "/workspace/x", "content": "x"})
    ask("terminal", "terminal/create", {"sessionId": sid, "command": "sh", "args": ["-c", "id"]})
    # Permission prompts.
    update(sid, {"sessionUpdate": "tool_call", "toolCallId": "t-exec", "title": "Run tests", "kind": "execute", "status": "pending", "rawInput": {"command": "make test"}})
    permission("execute", sid, {"toolCallId": "t-exec"})
    permission("settings_local", sid, {"toolCallId": "t-set", "title": "Allow always", "kind": "edit", "locations": [{"path": "/workspace/.claude/settings.local.json"}]})
    permission("switch_mode", sid, {"toolCallId": "t-mode", "title": "Bypass permissions", "kind": "switch_mode"})
    permission("only_always", sid, {"toolCallId": "t-always", "kind": "edit", "locations": [{"path": "/workspace/a.txt"}]}, kinds=("allow_always", "reject_always"))
    # Only an "always" answer would make an adapter write this file: emulate that.
    if any(str(a).endswith("always") for a in seen["answers"].values()):
        os.makedirs("/workspace/.claude", exist_ok=True)
        open("/workspace/.claude/settings.local.json", "w").write('{"permissions":{"allow":["Bash"]}}')
    update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": "t-exec", "status": "completed",
                 "content": [{"type": "diff", "path": "/workspace/a.txt", "oldText": None, "newText": "hello\n"}]})
    seen["gateway"] = gateway()
    update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Done."}})
    save("done")


def messages():
    while True:
        while inbox:
            yield inbox.pop(0)
        line = sys.stdin.readline()
        if not line:
            return
        try:
            yield json.loads(line)
        except ValueError:
            continue


for m in messages():
    method, rid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if method == "initialize":
        seen["initialize"] = {"clientCapabilities": p.get("clientCapabilities")}
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentCapabilities": {"loadSession": True, "mcpCapabilities": {"http": True}, "sessionCapabilities": {"systemPrompt": {}}},
            "agentInfo": {"name": "acp-mock", "version": "1"},
            "authMethods": [],
        }})
    elif method == "session/new":
        seen["session"] = brief(p)
        history["session"] = "mock-session-1"
        send({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": history["session"]}})
    elif method == "session/load":
        seen["session"] = brief(p)
        sid = p.get("sessionId")
        # Replay: history, including an "always" approval the agent once got, then a prompt asked
        # in the middle of it.
        for u in history["updates"]:
            update(sid, u, keep=False)
        permission("during_replay", sid, {"toolCallId": "t-exec", "kind": "execute"}, kinds=("allow_once", "allow_always"))
        seen["load"] = {"session": sid, "known": sid == history["session"], "replayed": len(history["updates"])}
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
        permission("after_replay", sid, {"toolCallId": "t-exec", "kind": "execute"})
        save("done")
    elif method == "session/prompt":
        sid = p.get("sessionId")
        turn(sid, " ".join(b.get("text", "") for b in p.get("prompt", [])))
        send({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        if seen.get("load") is None and seen.get("self_wakeup") is None:
            # Its turn is over: it idles on its own timer, then wakes by itself (#249).
            t0 = time.monotonic()
            time.sleep(SELF_WAKE)
            slept = round(time.monotonic() - t0, 1)
            # A tool call, which wicket shows at once (a message chunk waits for the next turn).
            update(sid, {"sessionUpdate": "tool_call", "toolCallId": "t-wake", "title": "woke on my own timer after %d s idle" % SELF_WAKE, "kind": "other", "status": "completed"})
            seen["self_wakeup"] = {"slept": SELF_WAKE, "elapsed": slept, "hibernate": call_tool("hibernate")}
        else:
            seen["finish"] = call_tool("finish")
        save("done")
    elif method == "session/cancel":
        pass
    elif rid is not None and method:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no"}})
