#!/usr/bin/env python3
"""Question 1, host side: echo servers on unix sockets of each type in DIR (bind-mounted into the box).

stream: 4-byte big-endian length + message, echoed back. seqpacket and dgram: each message echoed.
Logs what it sees (peer addresses matter for dgram: an unnamed peer can't be answered).
"""
import os, socket, struct, sys, threading

d = sys.argv[1]


def log(*a):
    print("host:", *a, flush=True)


def serve_stream():
    p = f"{d}/stream.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(p); os.chmod(p, 0o777); s.listen()
    while True:
        c, _ = s.accept()
        threading.Thread(target=echo_stream, args=(c,), daemon=True).start()


def recvn(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x:
            raise EOFError
        b += x
    return b


def echo_stream(c):
    try:
        while True:
            n = struct.unpack(">I", recvn(c, 4))[0]
            c.sendall(struct.pack(">I", n) + recvn(c, n))
    except EOFError:
        pass


def serve_seqpacket():
    p = f"{d}/seqpacket.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.bind(p); os.chmod(p, 0o777); s.listen()
    while True:
        c, _ = s.accept()
        log("seqpacket accepted")
        threading.Thread(target=echo_msgs, args=(c,), daemon=True).start()


def echo_msgs(c):
    while True:
        m = c.recv(70000)
        if not m:
            return
        c.send(m)


def serve_dgram():
    p = f"{d}/dgram.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(p); os.chmod(p, 0o777)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    while True:
        m, peer = s.recvfrom(70000)
        log(f"dgram {len(m)} bytes from {peer!r}")
        try:
            s.sendto(m, peer)
        except Exception as e:  # noqa: BLE001
            log(f"dgram reply to {peer!r} failed: {e!r}")


for f in (serve_stream, serve_seqpacket, serve_dgram):
    threading.Thread(target=f, daemon=True).start()
log("ready")
threading.Event().wait()
