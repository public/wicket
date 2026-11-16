---
name: wicket-operator
description: Use when installing, running or looking after wicket as its operator, on the control host or a node - running a manifest, approving or denying requests (console passkey or CLI), storing and linking secrets, enrolling nodes and leases, following a running agent with wicket session, checking a host with wicket doctor, or troubleshooting a run that failed, was killed for memory, can't read its model credential or seems stuck.
---

# Operating wicket

You are the human side of wicket (or helping them): you run `wicket` on the **control host**, the
machine with the ledger, vault and keys, and decide what boxes ask for. Every command and flag is in
the [CLI reference](https://github.com/public/wicket/blob/main/docs/reference/cli.md); the words
wicket uses are in [the nouns](https://github.com/public/wicket/blob/main/docs/explanation/concepts.md#the-nouns).

On an installed host, commands go through the daemon, and those that change authority or secrets
need `sudo`; taking a run's authority away (`grant revoke`, `identity revoke`, `unlink`, `lease release`) doesn't ([who may run what](https://github.com/public/wicket/blob/main/docs/reference/daemon.md#who-may-run-what)).

## Install

- **To try it** as your own user (development mode): [your first box](https://github.com/public/wicket/blob/main/docs/tutorials/first-box.md).
- **To run it for real**: [install on a host](https://github.com/public/wicket/blob/main/docs/how-to/install-on-a-host.md):
  `sudo deploy/install.sh --trust-domain wicket.example.com`, log in again, `wicket doctor`.
- The one secret wicket needs is the model credential, a Claude subscription token from
  `claude setup-token` (never an API key): `sudo wicket secret set claude-oauth`.

## Run a manifest

```sh
wicket zone task.yaml                         # check it first: hosts, splice or inspect, warnings
wicket run task.yaml                          # in the foreground; prints events and how it ended
wicket run task.yaml --workdir .              # copy a directory into /workspace
wicket run task.yaml --workspace-dir ../clone # mount a clone in place, so commits land there
wicket run task.yaml --task "…" --node n1     # another task text, on an enrolled node
```

While it runs: `wicket top` (every node, run, pending request and lease), `wicket agents`
(long-lived agents and their state), and `wicket session <run>` to follow an agent live and type
prompts as its next turns (`wicket session <run> "…" --no-wait` queues one prompt; Ctrl-C leaves and
the agent goes on). The run's files are under `runs/<run>/` in the data directory
([files](https://github.com/public/wicket/blob/main/docs/reference/files.md#a-runs-directory)):
`workspace/`, with the agent's `out/result.json`, and `transcript.jsonl`.

Writing the manifest itself: see the `wicket-manifest` skill.

## Approvals

A box's out-of-reach request waits as a pending request (`r-…`) until you decide it.

- **Console**, with a passkey: enrol one with `sudo wicket operator enrol-link --origin
  http://localhost:8787` and open the link on the host (or over an ssh tunnel). To approve from a
  phone, [put the console on the internet](https://github.com/public/wicket/blob/main/docs/how-to/put-the-console-on-the-internet.md)
  and [get notified](https://github.com/public/wicket/blob/main/docs/how-to/get-notified-of-approvals.md).
- **CLI**: `wicket pending`, then `sudo wicket approve r-… ` (`--uses N`, `--ttl 10m`, `--prefix
  PATH`, `--zone-wide`) or `sudo wicket deny r-…`. On the host this is the audited break-glass path.
- Approve exactly what the work needs. A grant is never wider than the request, and one use for the
  asking run is the default. Turn what you approve every time into reach in the zone instead.
- Live grants: `wicket grant list`, `wicket grant revoke`, `sudo wicket grant renew <run> --ttl`.

An agent session running as your own user can't approve anything: approvals need root or a passkey.

## Secrets

[Store and link secrets](https://github.com/public/wicket/blob/main/docs/how-to/store-and-link-secrets.md)
has every case. Boxes only ever hold placeholders; the proxies put the value into one header toward
the hosts the secret is bound to.

```sh
sudo wicket secret set github-ro --hosts api.github.com    # value from the terminal or stdin, never an argument
sudo wicket secret link claude-oauth --file ~/.claude/.credentials.json \
    --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
wicket secret list                                          # names and hosts, never values
```

- **Bind every secret to its hosts** (`--hosts`). A secret bound to none is sent nowhere.
- **Another user's login file** (an operator's Claude login): use the **secret helper**, not an ACL.
  Claude Code rewrites its credentials file on refresh, which drops an ACL. Run `wicket secret serve`
  as the file's owner (the `deploy/systemd-user/wicket-secret-helper.service` unit), then `sudo wicket
  secret link claude-oauth --via-helper --helper-user "$USER" …`.
- The console shows secrets by name only, with whether the vault has each one and binds it to the
  host a zone injects it toward. Values are set at the host's shell, never in a browser or a chat.

## Nodes and leases

- **Enrol a machine** ([add a remote node](https://github.com/public/wicket/blob/main/docs/how-to/add-a-remote-node.md)):
  `wicket node token --name n1`, `wicket node enrol wicket@host --token … --host-key SHA256:… --hosts
  'api.example.com'`, `wicket node install n1`, then build the agent image there with `wicket image`.
- **Have wicket create one** on a cloud, inside a money envelope, by hand or for agents that ask
  with `request_capacity` (leases), with `wicket node create`: [create nodes on Vultr](https://github.com/public/wicket/blob/main/docs/how-to/create-nodes-on-vultr.md).
  `wicket lease list` and `wicket lease release l-…` manage leases.
- **Watch**: `wicket top` on the control host; `wicket node top` on the node as its `wicket` user.
- **Look after**: `wicket node list`, `wicket node renew-ca n1` (a node that was away until its
  certificate expired), `sudo wicket node revoke n1`.

## Check a host: `wicket doctor`

`wicket doctor` checks Docker, gVisor, the agent image, every secret (linked ones are read the way
a run would read them), the ledger, the placement backend and orphaned boxes. Run it after
installing, after an update, and first when something fails.

## Troubleshooting

- **Model calls fail with 503 `secret "claude-oauth" could not be read`.** The proxy couldn't read
  the credential (it retries for 3 s first). Usually a linked login whose ACL a refresh dropped:
  switch to the secret helper. `wicket doctor` says what's wrong with each linked secret.
- **Boxes on a node get 503 with `Retry-After: 5`.** The node is catching up with its policy feed,
  holds no valid policy yet, or briefly can't reach the control host. Harnesses retry it. If it
  persists, check the node in `wicket top` and `wicket node top` (connected, feed freshness,
  certificate expiry); `wicket node renew-ca` brings back a node whose certificate expired.
- **`failed (exit status: 137; killed: out of memory (limit …, peak …))`.** The box went over
  `limits.memory` and the kernel killed all of it. Raise the limit, or keep it and add
  `limits.memory_advice` (fewer build jobs, one test run at a time), which the agent gets with its
  warning at 90%. The cause is also in the parent's `run_finished` and the audit (`run.exit_cause`).
- **A run that seems stuck.** `wicket session <run>` shows what it is doing, and a prompt can ask it
  to save its work and `finish`. A harness that called `finish` but doesn't exit is stopped after
  `limits.exit_grace`. `wicket hibernate <run>` puts a long-lived agent to sleep at its next quiet
  point. To stop a box and everything it started: `wicket identity revoke <run>`.
- **An agent that won't wake.** It spent its model budget or its `limits.timeout`, or it ended
  rather than hibernated: [when it won't wake](https://github.com/public/wicket/blob/main/docs/how-to/hibernate-and-wake-an-agent.md#when-it-wont-wake).
- **A request nobody can approve.** "Never allowed" comes from a `forbid` rule or `escalation.request:
  false`: change the manifest, not the approval.
