# Install wicket on a host

Set up a control host the way it is meant to run: wicket as its own system user, behind `wicketd`.
For a quick try as your own user instead, see [your first box](../tutorials/first-box.md), which uses
development mode.

You need a fresh Ubuntu 24.04 or Debian 12 host, x86-64, and root. wicket 0.0.1 is the first
release, for Linux: read [limits](../explanation/limits.md) before you trust it with anything.

## 1. Download and check the release

```sh
curl -fsSLO https://github.com/public/wicket/releases/download/v0.0.1/wicket-0.0.1-x86_64-linux.tar.gz
curl -fsSLO https://github.com/public/wicket/releases/download/v0.0.1/wicket-0.0.1-x86_64-linux.tar.gz.sha256
sha256sum -c wicket-0.0.1-x86_64-linux.tar.gz.sha256 && tar xzf wicket-0.0.1-x86_64-linux.tar.gz
```

The archive holds the binary, `deploy/install.sh` and its systemd units, `images/`, `examples/`,
`README.md` and `LICENSE`. The `docs/` pages are in the repository, not the archive. From a checkout
instead, run `cargo build --release -p wicket-cli` first and use `deploy/install.sh` from there.

## 2. Run the installer

```sh
sudo wicket-0.0.1-x86_64-linux/deploy/install.sh --trust-domain wicket.example.com
```

It is safe to run again: it changes only what is missing or out of date. What it does:

- installs Docker (the distribution's `docker.io`) and gVisor from its signed apt repository, and
  registers gVisor as `runsc` with `--host-uds=open` in `/etc/docker/daemon.json`, keeping whatever
  else that file says;
- creates the `wicket` system user, alone in the `docker` group (Docker is root on the host), and the
  `wicket-operators` group. It adds you (or each `--operator USER`) to `wicket-operators`, and takes
  operators out of `docker`;
- creates `/var/lib/wicket` (0700, the `wicket` user's) for the ledger, vault, keys, runs and their
  sockets;
- installs the binary twice: as root's own copy, `/usr/local/lib/wicket/<build id>/wicket`, which
  `/usr/local/bin/wicket` (what `sudo wicket` runs) links to; and as the `wicket` user's version under
  `/var/lib/wicket-versions`, whose `current` wicket's services run and `wicket self update`
  switches (root never runs a binary there: #261). The image sources go under
  `/usr/local/share/wicket`;
- writes the daemon's policy (`/etc/wicket/wicketd.yaml`) and the console's options
  (`/etc/wicket/console.env`) if they don't exist;
- trusts a release key if you pass `--release-key FILE.pub`;
- sets up the identity issuer for `--trust-domain` (default `wicket.<short hostname>`); the trust
  domain is fixed once set;
- installs, enables and starts the `wicketd`, `wicket-console`, `wicket-reconcile` and `wicket-state`
  units (`wicket-state` starts only once a state store is configured);
- builds the agent image, `wicket/claude-code:<build id>` with `:poc` as an alias, and pulls the
  pinned Litestream image for the ledger's stream.

Options: `--binary PATH`, `--operator USER` (repeatable), `--trust-domain NAME`, `--console-origin
URL`, `--release-key FILE.pub`, `--skip-gvisor`, `--skip-image`, `--no-start`; `--help` lists them.

## 3. Log in again

Your new group (`wicket-operators`) applies to new logins. Log out and in, then check everything:

```sh
wicket doctor
```

## 4. Store the model credential

The one secret wicket needs is a Claude subscription token, never an API key:

```sh
claude setup-token                       # on any machine with Claude Code; prints a long-lived token
sudo wicket secret set claude-oauth      # paste it: read without echo, never from arguments
```

`claude-oauth` may go only to `api.anthropic.com` unless you say otherwise.
[Store and link secrets](store-and-link-secrets.md) has the alternatives.

## 5. Enrol a passkey for the console

```sh
sudo wicket operator enrol-link --origin http://localhost:8787
```

Open the link in a browser on the host (or through an ssh tunnel to port 8787): passkeys need
`https://` or `localhost`. To reach the console from your phone, [put it on the
internet](put-the-console-on-the-internet.md).

## Then

- Run something: `wicket run examples/hello-github.yaml` from the unpacked archive, as yourself.
  The [first tutorial](../tutorials/first-box.md) walks through what happens.
- Approve from the console, or with `sudo wicket approve ID` on the host (the break-glass, audited
  as such). Operators can't approve without root or a passkey, so an agent session running as your
  own user can't approve anything.
- Commands that need `sudo`: [the daemon](../reference/daemon.md#who-may-run-what).
- `examples/` and the other relative paths in these docs are in the repository, and in the archive
  except `docs/`.
