#!/usr/bin/env python3
"""Question 1, inside the box (run by probe/run-q1.sh, after wicket-entry-like setup as root).

Prints one line per check: `name: ok|FAIL detail`. Runs as the box user with no capabilities.
"""
import os, socket, struct, sys, time

SOCKDIR = "/wicket/sock"
results = []


def check(name, fn):
    try:
        detail = fn()
        results.append((name, True, detail))
        print(f"{name}: ok {detail or ''}", flush=True)
    except Exception as e:  # noqa: BLE001  (a probe reports every failure)
        results.append((name, False, repr(e)))
        print(f"{name}: FAIL {e!r}", flush=True)


def udp_roundtrip(listen, send_to, src=None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(listen)
    srv.settimeout(2)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src:
        cli.bind(src)
    cli.settimeout(2)
    cli.sendto(b"ping", send_to)
    data, peer = srv.recvfrom(2048)
    srv.sendto(b"pong:" + data, peer)
    back, frm = cli.recvfrom(2048)
    srv.close(); cli.close()
    return f"server saw {peer}, client got {back!r} from {frm}"


def pktinfo_wildcard(port, targets):
    """A wildcard UDP socket learns each datagram's original destination with IP_PKTINFO and replies from it."""
    IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_IP, IP_PKTINFO, 1)
    srv.bind(("0.0.0.0", port))
    srv.settimeout(2)
    seen = []
    for t in targets:
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli.settimeout(2)
        cli.sendto(b"hello " + t.encode(), (t, port))
        data, anc, _flags, peer = srv.recvmsg(2048, socket.CMSG_SPACE(12))
        dst = None
        for level, typ, cdata in anc:
            if level == socket.SOL_IP and typ == IP_PKTINFO:
                _ifindex, spec_dst, addr = struct.unpack("I4s4s", cdata[:12])
                dst = socket.inet_ntoa(addr)
                spec = socket.inet_ntoa(spec_dst)
        if dst != t:
            raise RuntimeError(f"sent to {t}, PKTINFO said {dst}")
        # Reply with the original destination as source (ipi_spec_dst), as the forwarder must.
        info = struct.pack("I4s4s", 0, socket.inet_aton(t), b"\0\0\0\0")
        srv.sendmsg([b"reply"], [(socket.SOL_IP, IP_PKTINFO, info)], 0, peer)
        back, frm = cli.recvfrom(2048)
        if frm[0] != t:
            raise RuntimeError(f"reply came from {frm}, wanted {t}")
        seen.append(f"{t}->pktinfo {dst}, reply from {frm[0]}")
        cli.close()
    srv.close()
    return "; ".join(seen)


def uds(kind_name, kind):
    path = f"{SOCKDIR}/{kind_name}.sock"
    s = socket.socket(socket.AF_UNIX, kind)
    s.settimeout(3)
    s.connect(path)
    sizes = [1, 1200, 1452, 1500, 9000, 65000]
    for n in sizes:
        msg = bytes([n % 251]) * n
        if kind == socket.SOCK_STREAM:
            s.sendall(struct.pack(">I", n) + msg)
            hdr = b""
            while len(hdr) < 4:
                hdr += s.recv(4 - len(hdr))
            want = struct.unpack(">I", hdr)[0]
            got = b""
            while len(got) < want:
                got += s.recv(want - len(got))
        else:
            s.send(msg)
            got = s.recv(70000)
        if got != msg:
            raise RuntimeError(f"{n}-byte message came back as {len(got)} bytes")
    # Boundaries: two sends must arrive as two messages (the host echoes each).
    if kind != socket.SOCK_STREAM:
        s.send(b"a" * 10); s.send(b"b" * 20)
        a = s.recv(100); b = s.recv(100)
        if (len(a), len(b)) != (10, 20):
            raise RuntimeError(f"boundaries lost: {len(a)}, {len(b)}")
    s.close()
    return "echoed " + ",".join(map(str, sizes)) + " bytes" + ("" if kind == socket.SOCK_STREAM else ", boundaries kept")


def uds_dgram_unconnected():
    """sendto() a host datagram socket without connect, from an autobound address: can the host reply?"""
    path = f"{SOCKDIR}/dgram.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.bind("")  # autobind (abstract name) so the host has a reply address
    s.sendto(b"x" * 1200, path)
    got = s.recv(2000)
    return f"reply {len(got)} bytes to autobound {s.getsockname()!r}"


def mtu():
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SIOCGIFMTU = 0x8921
    r = fcntl.ioctl(s, SIOCGIFMTU, struct.pack("16si", b"lo", 0))
    return "lo mtu " + str(struct.unpack("16si", r)[1])


def big_datagram(n):
    return udp_roundtrip_n(("198.19.0.5", 4600 + n % 1000), n)


def udp_roundtrip_n(addr, n):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(addr); srv.settimeout(1)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.sendto(b"q" * n, addr)
    got = srv.recv(70000)
    return f"{len(got)} bytes arrived"


def gso():
    UDP_SEGMENT = 103
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_UDP, UDP_SEGMENT, 1200)
    return "setsockopt(UDP_SEGMENT) accepted"


def gro():
    UDP_GRO = 104
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_UDP, UDP_GRO, 1)
    return "setsockopt(UDP_GRO) accepted"


def gso_send():
    """Send one 3600-byte buffer with UDP_SEGMENT=1200: does the receiver see three 1200-byte datagrams?"""
    UDP_SEGMENT = 103
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("198.19.0.5", 4500)); srv.settimeout(1)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.setsockopt(socket.SOL_UDP, UDP_SEGMENT, 1200)
    cli.sendto(b"z" * 3600, ("198.19.0.5", 4500))
    lens = []
    try:
        while True:
            lens.append(len(srv.recv(70000)))
    except socket.timeout:
        pass
    return f"receiver saw datagrams of {lens}"


def ecn():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 2)
    s.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_RECVTOS", 13), 1)
    return "IP_TOS/IP_RECVTOS accepted"


def df():
    IP_MTU_DISCOVER, IP_PMTUDISC_PROBE = 10, 3
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)
    return "IP_MTU_DISCOVER=PROBE accepted"


def mmsg():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    return "recvmmsg/sendmmsg symbols present" if hasattr(libc, "recvmmsg") and hasattr(libc, "sendmmsg") else "absent"


print(f"uid={os.getuid()} caps={open('/proc/self/status').read().split('CapEff:')[1].split()[0]}", flush=True)
check("mtu", mtu)
check("udp-bound-198.19.0.5:443", lambda: udp_roundtrip(("198.19.0.5", 443), ("198.19.0.5", 443)))
check("udp-bound-198.19.0.6:443", lambda: udp_roundtrip(("198.19.0.6", 443), ("198.19.0.6", 443)))
check("udp-routed-local-198.19.200.7:443", lambda: udp_roundtrip(("198.19.200.7", 443), ("198.19.200.7", 443)))
check("udp-pktinfo-wildcard-443", lambda: pktinfo_wildcard(443, ["198.19.0.5", "198.19.0.6"]))
check("udp-prefix16-198.20.3.4:443", lambda: udp_roundtrip(("198.20.3.4", 443), ("198.20.3.4", 443)))
check("udp-pktinfo-wildcard-prefix16", lambda: pktinfo_wildcard(8443, ["198.20.0.9", "198.20.77.1"]))
check("udp-pool-198.21.15.250:443", lambda: udp_roundtrip(("198.21.15.250", 443), ("198.21.15.250", 443)))
check("udp-127.0.0.2:443", lambda: udp_roundtrip(("127.0.0.2", 443), ("127.0.0.2", 443)))
for n in (1500, 9000, 65000):
    check(f"udp-datagram-{n}", lambda n=n: big_datagram(n))
check("udp-dns-198.18.0.1:53", lambda: udp_roundtrip(("198.18.0.1", 53), ("198.18.0.1", 53)))
check("uds-stream", lambda: uds("stream", socket.SOCK_STREAM))
check("uds-seqpacket", lambda: uds("seqpacket", socket.SOCK_SEQPACKET))
check("uds-dgram-connected", lambda: uds("dgram", socket.SOCK_DGRAM))
check("uds-dgram-unconnected", uds_dgram_unconnected)
check("udp-gso-setsockopt", gso)
check("udp-gso-send", gso_send)
check("udp-gro-setsockopt", gro)
check("udp-ecn", ecn)
check("udp-df-probe", df)
check("libc-mmsg", mmsg)
sys.exit(0)
