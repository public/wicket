# Put the console on the internet

The console is built to face the internet directly, with no VPN or access proxy in front (#23).
Passkeys stay the only authentication. Pick one of three ways to serve it over HTTPS. What the
console then enforces (TLS versions, headers, rate limits, sessions) is in the
[console reference](../reference/console.md#on-the-internet).

WebAuthn needs a secure context, so a passkey enrolled for `http://localhost:8787` won't sign in at
`https://console.example.com`: enrol one for the new origin (step 3 below).

## 1. Choose how TLS is served

**From wicket, with a Let's Encrypt certificate** validated over TLS-ALPN-01 on the listener itself,
so it must listen on :443:

```sh
wicket serve --listen 0.0.0.0:443 --acme-domain console.example.com --acme-agree-tos \
    --acme-contact mailto:ops@example.com          # --acme-staging to try it out first
```

ACME keeps its account and certificate in `$WICKET_HOME/acme` (0700/0600) and renews 30 days before
expiry. ACME has been tested against a mock CA only, not yet against Let's Encrypt itself.

**From wicket, with certificate files**, re-read when they change (after certbot renews them, say):

```sh
wicket serve --listen 0.0.0.0:443 --origin https://console.example.com \
    --tls-cert /etc/wicket/fullchain.pem --tls-key /etc/wicket/privkey.pem
```

**Behind a TLS-terminating proxy** (nginx, HAProxy, Caddy, a cloud load balancer), which then must
be the only way in:

```sh
wicket serve --listen 10.0.0.5:8787 --behind-tls-terminator --origin https://console.example.com \
    --trusted-proxy 10.0.0.2
```

`--trusted-proxy` is required here. It takes the address or range the proxy connects from, and is
repeatable. Without it every client would look like the proxy: one client's failed sign-ins would
lock everyone out, and a few slow connections would fill the per-client connection cap. Two rules for
the proxy:

- **It must add the address it saw.** nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
  HAProxy: `option forwardfor`, which adds a header line of its own; wicket reads every line, so that
  is fine. Caddy's `reverse_proxy` does it by default.
- **It must be the only way in.** Listen on an address that only the proxy can reach, or firewall the
  port to the proxy. If there are several proxies in a chain, trust each of them.

A non-loopback listener refuses to start in plain HTTP unless `--behind-tls-terminator` is given with
an `https://` `--origin`.

## 2. On an installed host, put the options in `console.env`

`wicket serve` is refused through the daemon: the console is the `wicket-console` unit, running as
the `wicket` user. Put the options in `/etc/wicket/console.env` and restart it:

```sh
sudo tee /etc/wicket/console.env <<'EOF'
WICKET_CONSOLE_ARGS="--listen 0.0.0.0:443 --acme-domain console.example.com --acme-agree-tos --acme-contact mailto:ops@example.com --no-bootstrap-link"
EOF
sudo systemctl restart wicket-console
```

Binding :443 needs `CAP_NET_BIND_SERVICE` (or a port redirect); nothing in the console needs root.
`deploy/install.sh --console-origin URL` writes the `--origin` for you on a first install.

## 3. Enrol a passkey for the new origin

```sh
sudo wicket operator enrol-link --origin https://console.example.com    # single use, 10 minutes
```

Open the link on the device that holds the passkey (a phone works: the console can be added to its
home screen). A signed-in console session can't add a passkey, so a stolen cookie can't either.

## 4. Check it

- `curl -sI https://console.example.com/` shows `Strict-Transport-Security` and the other headers.
  Submitting the domain to the HSTS preload list is your step.
- Before sign-in, anything but the page, its static files and the sign-in endpoints gets the same
  401.
- `wicket doctor` reads `console.env` and checks the console's options.
- Sessions: `wicket operator sessions`, and `sudo wicket operator revoke-session ID` (or `--all`).

The console hasn't had its dedicated external review yet, or a TLS and headers scan on a real
hostname ([limits](../explanation/limits.md#the-console)).
