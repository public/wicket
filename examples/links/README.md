# Links between boxes

Agents wire boxes together (a browser driven over DevTools, a database, a service of their own) without
wicket knowing anything about the workloads. Boxes still have no network: wicket relays every link through
host-side unix sockets, so each one is allowed, logged and can be cut (issue #6, design §4.3, §8.2).

## Tools (wicket's MCP gateway)

- `expose(port, name?)`: offer a port of this box. Your parent can connect without it.
- `connect(box, port)`: reach a port of a child (by name or run id), or of a box that exposed it. Returns the
  address to use in your box, `<name>.wicket.internal:<port>`.
- `link(from, to, port)`: wire two boxes you control (yourself or your own children): `from` gets the name.
- `unlink(link)`, `links()`.

Operators: `wicket links`, `wicket unlink <id>`, and `wicket identity revoke <run>` (which closes every link
of that run and of everything it started).

## Policy

- A box's own children are connectable by default.
- Any other box must have exposed the port, and its zone's `accept_from` must list the connector's zone;
  otherwise a human approves exactly that link (`connect` returns a request id for `await_grant`).
- A link lends the connector the target's authority, so the target's reach must be within the connector's:
  every reach rule covered, the connector's `forbid` rules kept, no credential injection or model route the
  connector lacks. Otherwise a human approves.
- Revoking either end (or an ancestor), ending either run, or cutting the link closes it within two seconds,
  live connections included.
- Data labels don't cross links yet: wicket has no label mechanism to carry (design §4.2). Each link's
  `link.open` audit record says so.

## How it works

- `wicket-entry` adds 198.18.1.1–198.18.1.32 to the box's loopback at start, while it still has
  `NET_ADMIN`. Each linked name in a box gets one of them, and a line in the box's `/etc/hosts`: a file
  wicket owns and rewrites, mounted read-only.
- In the connecting box, wicket starts (as the agent's user) a `wicket-fwd --listen` on that address and port,
  forwarding to the link's unix socket in the box's socket directory, where wicket listens.
- For each connection, wicket runs `wicket-fwd --dial 127.0.0.1:<port>` in the target box with `docker exec -i`,
  as the agent's user, and copies bytes both ways. Under gVisor a box can connect out to a host socket,
  but a socket the box creates can't be reached from the host, so wicket reaches in. That costs about
  0.15 s per new connection (144 ms measured by the demo on a shared 4 vCPU VPS), which is fine for
  DevTools (one WebSocket) or keep-alive HTTP.
- Both images need `wicket-fwd` (any image built on wicket's agent image), and the boxes must run on this
  host: remote nodes can't link yet.

## Demo (no model needed)

`demo.sh` runs `demo.yaml` with `wicket dev mock-llm`: the agent runs `box/drive.sh`, which calls the gateway
the way an agent's own code would. It starts an HTTP server as a program box, connects to it, fetches a page
over the link, then cuts the link and checks that nothing gets through and the name is gone.

```bash
docker build -t wicket/claude-code:links images/claude-code
WICKET=target/debug/wicket IMAGE=wicket/claude-code:links examples/links/demo.sh
```

## Headless Chromium over DevTools

`chrome.yaml` asks an agent to start Chromium (`chrome/Dockerfile`, built on the agent image) with
`--remote-debugging-port=9222`, connect to it, and drive it with a script it writes. The browser box's own
egress still goes through wicket's proxy (`--proxy-server=http://wicket.internal:3128`), within its zone.
Chromium doesn't read the run CA from `SSL_CERT_FILE`, so the manifest passes `--ignore-certificate-errors`:
that hop ends at wicket's own proxy, which verifies the real upstream itself.
Chromium answers DevTools HTTP only for a `Host` of an IP address or `localhost`, so clients send
`Host: localhost:9222`; the WebSocket URL it returns then needs its host replaced with the link's name.
