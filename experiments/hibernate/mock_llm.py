#!/usr/bin/env python3
"""A scripted Anthropic Messages mock for the hibernate experiment (stdlib only).

It extends the idea of `wicket dev mock-llm`: the reply is a pure function of the request body, so the
mock can restart and still answer a resumed session correctly.

- Task turn (the newest user text has no HIB-WAKE): run SCRIPT step by step (Bash, Read, Write, Edit),
  where the step is the number of assistant messages since that user text. Then end with T1_DONE.
- Wake turn (the newest user text contains HIB-WAKE): one Bash call, then a text answer that reports
  what the request carried from before the wake: message count and whether the task and T1_DONE
  markers are present. That is the proof that `claude --resume` sent the prior conversation.
- A user text containing HIB-SLOW makes the mock hold its answer for HIB_SLOW_S seconds (default 20),
  to leave a request in flight across a checkpoint.
- Requests without the Bash tool (titles, summaries) get a short text.

Every request is logged as one JSON line on stderr (or to --log).
"""
import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TASK_MARK = "HIB-TASK-ALPHA"
T1_DONE = "HIB-T1-DONE"
WAKE_MARK = "HIB-WAKE"
SLOW_MARK = "HIB-SLOW"

# A survey of the workspace, shaped like a real coding session: reads, searches, a file written then
# edited (which fills file-history), and writes to a volume.
SCRIPT = [
    ("Bash", {"command": "cd /workspace && git log --oneline | head -80 && ls -la", "description": "look around"}),
    ("Read", {"file_path": "/workspace/README.md"}),
    ("Bash", {"command": "cd /workspace && rg -n 'pub fn ' crates | head -300", "description": "public functions"}),
    ("Read", {"file_path": "/workspace/docs/design.md"}),
    ("Read", {"file_path": "/workspace/crates/wicket-cli/src/run.rs"}),
    ("Read", {"file_path": "/workspace/crates/wicket-sandbox/src/lib.rs"}),
    ("Write", {"file_path": "/workspace/notes/hibernate.md",
               "content": "# Notes\n\n" + "".join(f"- observation {i}: the box keeps its state in /wicket/state.\n" for i in range(120))}),
    ("Read", {"file_path": "/workspace/notes/hibernate.md"}),
    ("Edit", {"file_path": "/workspace/notes/hibernate.md", "old_string": "- observation 7:", "new_string": "- observation 7 (edited):"}),
    ("Bash", {"command": "cd /workspace && git diff --stat HEAD~20 | tail -40", "description": "recent changes"}),
    ("Read", {"file_path": "/workspace/crates/wicket-agent/src/lib.rs"}),
    ("Read", {"file_path": "/workspace/docs/research/22-pause-resume-hibernate.md"}),
    ("Bash", {"command": "mkdir -p /volumes/cache && seq 1 20000 > /volumes/cache/seq.txt && du -sh /volumes/cache", "description": "use the volume"}),
    ("Bash", {"command": "cd /workspace && rg -c 'fn ' crates | sort -t: -k2 -n | tail -40", "description": "biggest files"}),
    ("Read", {"file_path": "/workspace/crates/wicket-cli/src/mock.rs"}),
    ("Edit", {"file_path": "/workspace/notes/hibernate.md", "old_string": "- observation 9:", "new_string": "- observation 9 (edited):"}),
    ("Bash", {"command": "cd /workspace && cat Cargo.toml && wc -l crates/*/src/*.rs | tail -1", "description": "workspace size"}),
    ("Read", {"file_path": "/workspace/docs/research/02-isolation.md"}),
    ("Bash", {"command": "cd /workspace && git log -p -3 --stat | head -400", "description": "last commits"}),
    ("Bash", {"command": "date -u +%FT%TZ > /workspace/notes/when.txt && cat /workspace/notes/when.txt", "description": "timestamp"}),
]


def user_texts(msg):
    c = msg.get("content")
    if isinstance(c, str):
        return [c]
    out = []
    for b in c or []:
        if b.get("type") == "text":
            out.append(b.get("text", ""))
    return out


def has_tool_result(msg):
    c = msg.get("content")
    return isinstance(c, list) and any(b.get("type") == "tool_result" for b in c)


def decide(body):
    msgs = body.get("messages") or []
    tools = [t.get("name") for t in body.get("tools") or []]
    raw = json.dumps(msgs)
    info = {
        "messages": len(msgs),
        "tools": len(tools),
        "task_marker": TASK_MARK in raw,
        "t1_done_marker": T1_DONE in raw,
        "bytes": len(raw),
    }
    if os.environ.get("HIB_SHAPE"):
        info["shape"] = [m.get("role", "?")[0] + ":" + ",".join(
            (b.get("type", "?")[:4] + ("=" + b.get("text", "")[:24].replace("\n", " ") if b.get("type") == "text" else ""))
            for b in (m.get("content") if isinstance(m.get("content"), list) else [{"type": "text", "text": m.get("content", "")}]))
            for m in msgs[-4:]]
    if "Bash" not in tools:
        return ("text", "ok"), info, False
    # The current prompt: the newest user message carrying one of our markers. Claude Code merges a
    # new prompt into the message that holds the previous turn's tool results, so don't skip those.
    idx, prompt = None, ""
    for i in range(len(msgs) - 1, -1, -1):
        m = msgs[i]
        texts = [t for t in user_texts(m) if TASK_MARK in t or WAKE_MARK in t]
        if m.get("role") == "user" and texts:
            idx, prompt = i, "\n".join(texts)
            break
    # Claude Code merges consecutive messages, so count tool calls, not assistant messages.
    step = sum(1 for m in msgs[(idx or 0) + 1:] if m.get("role") == "assistant" and isinstance(m.get("content"), list)
               for b in m["content"] if b.get("type") == "tool_use")
    slow = SLOW_MARK in prompt and step == 0
    info["step"] = step
    if WAKE_MARK in prompt:
        info["phase"] = "wake"
        if step == 0:
            return ("tool", "Bash", {"command": "ls /workspace/notes && wc -l /volumes/cache/seq.txt", "description": "check the trees"}), info, slow
        before = msgs[:idx]
        text = (f"RESUMED messages_before_wake={len(before)} task_marker={TASK_MARK in json.dumps(before)} "
                f"t1_done_marker={T1_DONE in json.dumps(before)}")
        return ("text", text), info, slow
    info["phase"] = "task"
    if step < len(SCRIPT):
        name, inp = SCRIPT[step]
        return ("tool", name, inp), info, slow
    return ("text", f"{T1_DONE}: surveyed the workspace in {len(SCRIPT)} steps."), info, slow


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, data):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(404, "application/json", b"{}")

    def do_HEAD(self):
        self._send(200, "application/json", b"")

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw or b"null") or {}
        except ValueError:
            body = {}
        path = self.path.split("?")[0]
        t0 = time.time()
        if path.endswith("/count_tokens"):
            return self._send(200, "application/json", b'{"input_tokens":10}')
        if not path.endswith("/v1/messages"):
            return self._send(404, "application/json", b"{}")
        action, info, slow = decide(body)
        info.update({"t": round(t0, 3), "path": path, "action": action[0] if action[0] == "text" else action[1]})
        if action[0] == "text":
            info["text"] = action[1][:200]
        LOG.write(json.dumps(info) + "\n")
        LOG.flush()
        if slow:
            time.sleep(float(os.environ.get("HIB_SLOW_S", "20")))
        model = body.get("model") or "mock"
        # A fresh message id per response: Claude Code merges transcript entries that share one when
        # it loads a session, so a constant id would fold every assistant turn into one on --resume.
        mid = f"msg_hib_{time.time_ns()}"
        if action[0] == "tool":
            block = {"type": "tool_use", "id": f"toolu_hib_{time.time_ns()}", "name": action[1], "input": action[2]}
            stop = "tool_use"
        else:
            block = {"type": "text", "text": action[1]}
            stop = "end_turn"
        if not body.get("stream"):
            return self._send(200, "application/json", json.dumps({
                "id": mid, "type": "message", "role": "assistant", "model": model, "content": [block],
                "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 20}}).encode())
        ev = []

        def e(name, data):
            ev.append(f"event: {name}\ndata: {json.dumps(data)}\n\n")

        e("message_start", {"type": "message_start", "message": {"id": mid, "type": "message", "role": "assistant", "model": model,
                                                                  "content": [], "stop_reason": None, "stop_sequence": None,
                                                                  "usage": {"input_tokens": 10, "output_tokens": 1}}})
        if block["type"] == "tool_use":
            start = dict(block, input={})
            e("content_block_start", {"type": "content_block_start", "index": 0, "content_block": start})
            e("content_block_delta", {"type": "content_block_delta", "index": 0,
                                      "delta": {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}})
        else:
            e("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
            e("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": block["text"]}})
        e("content_block_stop", {"type": "content_block_stop", "index": 0})
        e("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 20}})
        e("message_stop", {"type": "message_stop"})
        self._send(200, "text/event-stream", "".join(ev).encode())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:9999")
    ap.add_argument("--log")
    a = ap.parse_args()
    LOG = open(a.log, "a") if a.log else sys.stderr
    host, port = a.listen.rsplit(":", 1)
    ThreadingHTTPServer((host, int(port)), H).serve_forever()
