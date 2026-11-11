#!/usr/bin/env python3
"""HTTP/1.1 origin on a unix socket, for bench/box.sh: GET /1k, GET /bytes/N (N bytes, streamed).

Headers and body go out in separate writes, as most servers' do, so a forwarder without TCP_NODELAY
shows its Nagle stall.

Usage: origin.py SOCKET_PATH
"""

import http.server
import os
import socket
import socketserver
import sys

CHUNK = b"\0" * (256 * 1024)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/1k":
            n = 1024
        elif self.path.startswith("/bytes/"):
            n = int(self.path[len("/bytes/"):])
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        while n > 0:
            k = min(n, len(CHUNK))
            self.wfile.write(CHUNK[:k])
            n -= k

    def address_string(self):
        return "unix"

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


path = sys.argv[1]
if os.path.exists(path):
    os.unlink(path)
srv = Server(path, Handler)
os.chmod(path, 0o666)
srv.serve_forever()
