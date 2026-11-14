#!/usr/bin/env python3
"""An ACP agent whose harness lingers after its session (ci/acceptance.sh, #293). On its prompt it
writes a file to its workspace, starts a background process that never exits, asks wicket to finish
(the gateway's finish tool) and ends its turn. When wicket closes its session (EOF on stdin) it
doesn't exit: it waits for its background process, as a harness waiting on a background task does.
wicket must end the run after its zone's limits.exit_grace, stop what is left, sync the workspace
back, record the run as succeeded and name the process it stopped.

No model is involved. Standard library only.
"""
import json
import os
import subprocess
import sys
import urllib.request

OUT = "/workspace/out/result.json"
servers = []


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def call_tool(name):
    """Calls one of wicket's gateway tools; the first line of its answer."""
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
        return (("error: " if r.get("isError") else "") + r["content"][0]["text"].splitlines()[0])[:50]
    except Exception as e:  # noqa: BLE001
        return "error: %s" % e


child = None
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    method, rid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentCapabilities": {"loadSession": False, "mcpCapabilities": {"http": True}},
            "agentInfo": {"name": "acp-linger", "version": "1"},
            "authMethods": [],
        }})
    elif method == "session/new":
        servers = p.get("mcpServers") or []
        send({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": "linger-1"}})
    elif method == "session/prompt":
        os.makedirs("/workspace/out", exist_ok=True)
        open("/workspace/out/linger.txt", "w").write("written before finishing\n")
        # A background process that never exits (86399: a name the checks can find).
        child = subprocess.Popen(["sleep", "86399"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finish = call_tool("finish")
        json.dump({"status": "done", "summary": "linger mock", "finish": finish, "child": child.pid}, open(OUT, "w"))
        send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "linger-1", "update": {
            "sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Done; finishing."}}}})
        send({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
    elif rid is not None and method:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no"}})

# Its session is closed: it lingers, waiting for its background process.
if child is not None:
    child.wait()
