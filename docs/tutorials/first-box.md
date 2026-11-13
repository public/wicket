# Your first box

In this tutorial you will install wicket on a Linux machine in development mode, give it your Claude
login, run an agent in a gVisor box, and approve its request for a host outside its zone from
wicket's console. It takes about half an hour, most of it builds.

You need an Ubuntu 24.04 machine with a browser, Rust (`rustup`), Claude Code logged in to your
Claude subscription (`claude` works in a terminal), and `sudo`. Ids, times and token counts in the
output below will differ on your machine; `…` marks where.

Development mode runs wicket as you, and anything else running as you could approve its requests.
It is for trying wicket out. [Install on a host](../how-to/install-on-a-host.md) is the real thing.

## 1. Install Docker and gVisor

```sh
sudo apt-get update && sudo apt-get install -y docker.io curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
```

Register gVisor with Docker as `runsc`, allowed to use host unix sockets (that is how a box reaches
wicket), then let yourself use Docker:

```sh
echo '{ "runtimes": { "runsc": { "path": "/usr/bin/runsc", "runtimeArgs": ["--host-uds=open"] } } }' \
    | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
sudo usermod -aG docker $USER && newgrp docker
docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}'
```

```text
io.containerd.runc.v2 runc runsc
```

## 2. Build wicket

```sh
git clone https://github.com/public/wicket.git && cd wicket
cargo build --release -p wicket-cli && export PATH=$PWD/target/release:$PATH
wicket --version
```

```text
wicket 0.0.1
```

## 3. Build the agent image and the identity issuer

```sh
wicket image
```

```text
…
built wicket/claude-code:poc
```

```sh
wicket identity init --trust-domain wicket.example.com
```

```text
issuer ready: spiffe://wicket.example.com (key …)
```

Every box will get an identity under this trust domain.

## 4. Link your Claude login

wicket never puts your credential in the box. It refers to your Claude Code login and reads the
current token at each use:

```sh
wicket secret link claude-oauth --file ~/.claude/.credentials.json \
    --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
```

```text
secret claude-oauth now refers to /home/you/.claude/.credentials.json#/claudeAiOauth/accessToken (read at each use; never copied); sent only to api.anthropic.com
```

Check everything:

```sh
wicket doctor
```

It reports Docker, gVisor, the image, the secret and the ledger, and that this mode is insecure.

## 5. Start the console and enrol a passkey

In a second terminal, in the same directory and with the same `PATH`:

```sh
wicket serve
```

```text
wicket console on http://localhost:8787/  (listening on 127.0.0.1:8787, HTTP, loopback only)
runs can be started from …
no operator passkey yet. Enrol one within 10 minutes (single use):
  http://localhost:8787/enrol?t=…
```

Open the link in a browser on this machine and create a passkey when it asks. Then sign in with
it. The console shows nothing waiting yet. Leave it open.

## 6. Run an agent

Back in the first terminal:

```sh
wicket run examples/hello-github.yaml
```

The manifest asks an agent to read the GitHub repository `octocat/Hello-World`, which its zone
allows, and then `https://example.com/`, which it doesn't. wicket starts the box:

```text
wicket run run_…  tenant t0  zone research  agent explorer (claude-code)
  isolation Gvisor, no network; egress and model calls via wicket only
  identity spiffe://wicket.example.com/t/t0/z/research/a/explorer  (valid 600s, re-issued every 300s)
  acting for you (cli, unix-user) → explorer
  approve escalations from another terminal: wicket pending / wicket approve <id>
  run dir /home/you/.local/share/wicket/runs/run_…
```

Then every model call and every request the box makes, as wicket decides them:

```text
[llm]    #1 claude-… → 200  in … (+… cached) / out …  (…)
[egress] ALLOW   GET api.github.com/repos/octocat/Hello-World  (R1ReadScoped; …)
…
[egress] PENDING GET example.com/  (R1ReadScoped; r-… …)
         → a human decides: wicket approve r-…   or   wicket deny r-…
```

The agent's request for example.com got a 403 that says a human must decide, and a request id. The
agent calls wicket's `await_grant` tool with it and waits.

## 7. Approve it in the console

Look at the console. A card shows the waiting request: `GET example.com/`, its risk, the agent's
reason, and the agent's identity, verified, acting for you.

Tap **Approve**. The console asks the server for exactly that decision and shows it pinned at the
top of the page: this is what your passkey will sign. Confirm it and use your passkey.

In the first terminal, the agent's `await_grant` returns `granted`, it retries once, and the grant
lets it through:

```text
[egress] ALLOW   GET example.com/  (R1ReadScoped; grant g-…)
```

The grant was for one use, for this run only, for 10 minutes.

## 8. See how it ended

When the agent finishes, wicket prints a summary and the result the agent wrote:

```text
[wicket] run run_…: succeeded in …s; … model requests, … in (… of them cached) / … out tokens
[wicket] result.json: {…}
[wicket] transcript /home/you/.local/share/wicket/runs/run_…/transcript.jsonl
```

Every decision is in the audit log, and your passkey's signature with yours:

```sh
wicket audit --tail 20
wicket audit --verify
```

```text
audit chain OK: … records
passkey-signed decisions and console actions: 1 verified offline, 0 failed
agent identities and signed messages: … verified offline, 0 failed
```

You have run an agent with no network and no credentials, watched wicket decide each of its
requests, and approved one with a passkey-signed decision anyone can check offline.

Next: [approvals, children and links](approvals-children-and-links.md). To understand what you
just saw, read [concepts](../explanation/concepts.md).
