#!/usr/bin/env python3
"""A stand-in Docker Engine API on a unix socket, for timing wicket's own part of a box start (#287).

Containers are "created", "started" and "exit" at once: a box's start costs Docker nothing here,
so what `measure.sh` reports with it is wicket's own work (the control host, the node, the proxies,
the token and feed, the channel) and the Engine API round trips themselves. Each container's logs
are its command's last argument (what `sh -c 'echo …'` would print), so measure.sh sees its hello.

    python3 fake-engine.py /path/to/docker.sock
    WICKET_DOCKER="docker -H unix:///path/to/docker.sock" experiments/box-start/measure.sh -n 20 --isolation runc

Only what a box start asks is answered: _ping, image inspect, create, start, inspect, logs, wait,
kill, delete, and the image events (held open, none sent). Anything else is a 404.
"""
import datetime
import json
import os
import socketserver
import struct
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler

IMAGE_ID = "sha256:" + "0" * 64
boxes = {}
lock = threading.Lock()


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, code, body=None, ctype="application/json"):
        b = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def route(self, method):
        u = urllib.parse.urlparse(self.path)
        p = [urllib.parse.unquote(x) for x in u.path.strip("/").split("/")]
        q = urllib.parse.parse_qs(u.query)
        if p[0] == "_ping":
            return self.reply(200, b"OK", "text/plain")
        if p[0] == "images" and p[-1] == "json":
            return self.reply(200, {"Id": IMAGE_ID, "RepoDigests": [], "RepoTags": ["/".join(p[1:-1])]})
        if p[0] == "events":
            # Held open, as Docker's: the node's image cache is then trusted (no event, no change).
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.flush()
            threading.Event().wait()
            return
        if p[0] != "containers":
            return self.reply(404, {"message": "not here"})
        if p[1] == "create" and method == "POST":
            name = q.get("name", ["box"])[0]
            spec = self.body()
            with lock:
                boxes[name] = {"created": now(), "cmd": spec.get("Cmd") or []}
            return self.reply(201, {"Id": name, "Warnings": []})
        name = p[1]
        with lock:
            b = boxes.get(name)
        if b is None:
            return self.reply(404, {"message": f"No such container: {name}"})
        op = p[2] if len(p) > 2 else ""
        if op == "start":
            t = now()
            b["started"] = t
            b["finished"] = t
            return self.reply(204)
        if op == "json":
            return self.reply(200, {
                "Id": name, "Name": "/" + name, "Created": b["created"],
                "State": {"Running": False, "Pid": 0, "ExitCode": 0, "OOMKilled": False, "Error": "",
                          "StartedAt": b.get("started", "0001-01-01T00:00:00Z"),
                          "FinishedAt": b.get("finished", "0001-01-01T00:00:00Z")},
            })
        if op == "logs":
            text = (b["cmd"][-1] if b["cmd"] else "") + "\n"
            out = text.encode()
            frame = struct.pack(">BxxxI", 1, len(out)) + out
            return self.reply(200, frame, "application/vnd.docker.multiplexed-stream")
        if op == "wait":
            return self.reply(200, {"StatusCode": 0, "Error": None})
        if op in ("kill", "pause", "unpause"):
            return self.reply(204)
        if method == "DELETE":
            with lock:
                boxes.pop(name, None)
            return self.reply(204)
        return self.reply(404, {"message": "not here"})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    def do_HEAD(self):
        self.route("HEAD")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        req, _ = super().get_request()
        return req, ("fake-engine", 0)


if __name__ == "__main__":
    path = sys.argv[1]
    if os.path.exists(path):
        os.unlink(path)
    Server(path, Handler).serve_forever()
