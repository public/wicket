#!/usr/bin/env python3
"""Collapse `perf script` output into inclusive shares per component.

    perf script -i perf.data -F ip,sym,dso | python3 -I fold.py > shares.json

A sample counts toward a component if any frame of its stack matches it (inclusive), so components
overlap: "hyper h1" includes the httparse frames under it. Symbols are matched in their mangled form
(Rust v0 names carry crate names as <len><name>), so no demangler is needed.
"""
import json
import re
import sys

# (component, regex over one frame's "sym (dso)"); first match wins for the "self" column.
COMPONENTS = [
    ("httparse (h1 request/response parse)", r"8httparse|httparse::"),
    ("hyper h1 (role, encode, decode, dispatch)", r"5hyper5proto2h1|hyper::proto::h1"),
    ("h2 crate (upstream HTTP/2 framing, hpack)", r"2h25proto|2h26hpack|2h27codec|2h25frame|h2::"),
    ("AES-GCM / GHASH (ring asm)", r"aes_hw|aesni_gcm|gcm_|ghash|ring_core.*(aes|gcm)"),
    ("rustls record layer and handshake", r"6rustls|rustls::"),
    ("ring other (ECDHE, signatures, SHA)", r"4ring|ring_core"),
    ("rcgen / leaf minting", r"5rcgen|rcgen::"),
    ("sqlite (audit ledger)", r"sqlite3|8rusqlite"),
    ("sha2 (audit chain)", r"4sha2|sha2::"),
    ("ed25519 / curve25519", r"ed25519|curve25519"),
    ("biscuit (token decide)", r"biscuit|11wicket_authz"),
    ("wicket_core (decide, zone)", r"11wicket_core|wicket_core::"),
    ("wicket_proxy (handle, forward, audit)", r"12wicket_proxy|wicket_proxy::"),
    ("reqwest / hyper_util client", r"7reqwest|10hyper_util|reqwest::|hyper_util::"),
    ("serde_json", r"10serde_json|serde_json::"),
    ("tracing", r"7tracing|tracing::"),
    ("tokio runtime", r"5tokio|tokio::"),
    ("allocator (malloc/free)", r"malloc|cfree|_int_free|_int_malloc|malloc_consolidate|realloc"),
    ("memcpy/memmove (user)", r"__memmove|__memcpy|__memset"),
    ("kernel", r"\[kernel"),
]
RX = [(n, re.compile(p)) for n, p in COMPONENTS]


def main():
    incl = {n: 0 for n, _ in COMPONENTS}
    self_ = {n: 0 for n, _ in COMPONENTS}
    self_other = 0
    total = 0
    stack = []

    def flush():
        nonlocal total, self_other
        if not stack:
            return
        total += 1
        seen = set()
        for f in stack:
            for n, rx in RX:
                if n not in seen and rx.search(f):
                    seen.add(n)
        for n in seen:
            incl[n] += 1
        leaf = stack[0]
        for n, rx in RX:
            if rx.search(leaf):
                self_[n] += 1
                break
        else:
            self_other += 1

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line.strip():
            flush()
            stack = []
            continue
        if line.startswith("\t") or line.startswith(" "):
            parts = line.strip().split(None, 1)
            stack.append(parts[1] if len(parts) > 1 else parts[0])
    flush()
    out = {
        "samples": total,
        "inclusive_pct": {n: round(100 * c / max(total, 1), 2) for n, c in incl.items()},
        "self_pct": {n: round(100 * c / max(total, 1), 2) for n, c in self_.items()},
        "self_other_pct": round(100 * self_other / max(total, 1), 2),
    }
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
