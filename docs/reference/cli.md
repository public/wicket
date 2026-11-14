# Command line

Every `wicket` command and flag, as `wicket <command> --help` prints it. This page is generated
from the code by `ci/gen-cli-reference.sh`, and CI checks that it matches: edit the commands' doc
comments in `crates/wicket-cli/src/main.rs` (and `place.rs`), not this page.

On an installed host most commands go through the daemon, which allows each one for some callers
only: [the daemon](daemon.md#who-may-run-what) lists which commands need `sudo`. Durations are
humantime strings (`90s`, `10m`, `1h`).

- [`wicket run`](#wicket-run)
- [`wicket say`](#wicket-say)
- [`wicket hibernate`](#wicket-hibernate)
- [`wicket wake`](#wicket-wake)
- [`wicket agents`](#wicket-agents)
- [`wicket wrap`](#wicket-wrap)
- [`wicket pending`](#wicket-pending)
- [`wicket approve`](#wicket-approve)
- [`wicket deny`](#wicket-deny)
- [`wicket links`](#wicket-links)
- [`wicket unlink`](#wicket-unlink)
- [`wicket grant`](#wicket-grant)
  - [`wicket grant revoke`](#wicket-grant-revoke)
- [`wicket audit`](#wicket-audit)
  - [`wicket audit export`](#wicket-audit-export)
- [`wicket secret`](#wicket-secret)
  - [`wicket secret set`](#wicket-secret-set)
  - [`wicket secret list`](#wicket-secret-list)
  - [`wicket secret rm`](#wicket-secret-rm)
  - [`wicket secret hosts`](#wicket-secret-hosts)
  - [`wicket secret link`](#wicket-secret-link)
- [`wicket image`](#wicket-image)
  - [`wicket image digest`](#wicket-image-digest)
- [`wicket serve`](#wicket-serve)
- [`wicket program`](#wicket-program)
  - [`wicket program digest`](#wicket-program-digest)
- [`wicket operator`](#wicket-operator)
  - [`wicket operator list`](#wicket-operator-list)
  - [`wicket operator reset`](#wicket-operator-reset)
  - [`wicket operator enrol-link`](#wicket-operator-enrol-link)
  - [`wicket operator sessions`](#wicket-operator-sessions)
  - [`wicket operator revoke-session`](#wicket-operator-revoke-session)
- [`wicket identity`](#wicket-identity)
  - [`wicket identity init`](#wicket-identity-init)
  - [`wicket identity issuer`](#wicket-identity-issuer)
  - [`wicket identity show`](#wicket-identity-show)
  - [`wicket identity list`](#wicket-identity-list)
  - [`wicket identity revoke`](#wicket-identity-revoke)
- [`wicket policy`](#wicket-policy)
  - [`wicket policy show`](#wicket-policy-show)
  - [`wicket policy check`](#wicket-policy-check)
  - [`wicket policy apply`](#wicket-policy-apply)
  - [`wicket policy zone`](#wicket-policy-zone)
- [`wicket state`](#wicket-state)
  - [`wicket state check`](#wicket-state-check)
  - [`wicket state replicate`](#wicket-state-replicate)
  - [`wicket state kit`](#wicket-state-kit)
  - [`wicket state restore`](#wicket-state-restore)
  - [`wicket state snapshots`](#wicket-state-snapshots)
  - [`wicket state snapshot`](#wicket-state-snapshot)
- [`wicket keys`](#wicket-keys)
  - [`wicket keys roots-offline`](#wicket-keys-roots-offline)
  - [`wicket keys certify`](#wicket-keys-certify)
  - [`wicket keys roots-online`](#wicket-keys-roots-online)
- [`wicket reconcile`](#wicket-reconcile)
- [`wicket lease`](#wicket-lease)
  - [`wicket lease list`](#wicket-lease-list)
  - [`wicket lease release`](#wicket-lease-release)
- [`wicket zone`](#wicket-zone)
  - [`wicket zone pin`](#wicket-zone-pin)
- [`wicket doctor`](#wicket-doctor)
- [`wicket node`](#wicket-node)
  - [`wicket node token`](#wicket-node-token)
  - [`wicket node enrol`](#wicket-node-enrol)
  - [`wicket node list`](#wicket-node-list)
  - [`wicket node revoke`](#wicket-node-revoke)
  - [`wicket node install`](#wicket-node-install)
  - [`wicket node serve`](#wicket-node-serve)
  - [`wicket node renew-ca`](#wicket-node-renew-ca)
- [`wicket place`](#wicket-place)
  - [`wicket place plans`](#wicket-place-plans)
  - [`wicket place list`](#wicket-place-list)
  - [`wicket place create`](#wicket-place-create)
  - [`wicket place release`](#wicket-place-release)
- [`wicket dev`](#wicket-dev)
  - [`wicket dev node-feed-probe`](#wicket-dev-node-feed-probe)
  - [`wicket dev mock-llm`](#wicket-dev-mock-llm)
- [`wicket self`](#wicket-self)
  - [`wicket self status`](#wicket-self-status)
  - [`wicket self update`](#wicket-self-update)
  - [`wicket self follow`](#wicket-self-follow)
  - [`wicket self rollback`](#wicket-self-rollback)
  - [`wicket self prune`](#wicket-self-prune)
  - [`wicket self trust-key`](#wicket-self-trust-key)
  - [`wicket self keygen`](#wicket-self-keygen)
  - [`wicket self sign`](#wicket-self-sign)
  - [`wicket self apply-units`](#wicket-self-apply-units)
- [`wicket daemon`](#wicket-daemon)

## `wicket`

```text
Run agents in least-privilege sandboxes (proof of concept)

Usage: wicket <COMMAND>

Commands:
  run        Run a task manifest: one Claude Code agent in one zone
  say        Send a follow-up message to a running agent, as its operator. It arrives as the agent's next turn; the session stays open until the agent finishes or exits. A long-lived agent can be named by its id or any of its runs; a hibernated one is woken
  hibernate  Hibernate a long-lived agent (by run or agent id) at its next quiet point: its turn has ended and nothing but the agent runs in its box. Otherwise it goes on running
  wake       Wake a hibernated agent: rebuild its box, restore its state and resume its session. Runs the woken activation in the foreground, like `wicket run`. Text, if given, is the operator's message to it
  agents     Long-lived agents: state, generation, current run and bundle size
  wrap       Run an agent command line that another program launches, inside a wicket box: e.g. as Claude Code Remote Control's CLAUDE_CODE_PROCESS_WRAPPER. Its stdin and stdout stay connected to the launcher, its credentials become placeholders swapped at the proxy, and wicket logs to a file
  pending    List pending escalation requests
  approve    Approve a pending request. The grant is never wider than the request
  deny       Deny a pending request
  links      Links between boxes (expose/connect/link), newest first
  unlink     Cut a link between boxes: its relay closes it and drops its connections within seconds
  grant      Grants made by approvals
  audit      Show or verify the hash-chained audit log, or export it to the configured sinks
  secret     Manage vault secrets (values are read from the terminal, never from arguments)
  image      Build the agent image (the image directory plus the in-box forwarder's source, compiled in the build). Without --dir, from the copy embedded in this binary, so the image matches it
  serve      Serve the operator console (runs, approvals, activity; start, steer and revoke runs). Plain HTTP on loopback by default; any other address needs HTTPS (--acme-domain, or --tls-cert and --tls-key) or --behind-tls-terminator
  program    Programs: deterministic workloads that run without an agent
  operator   Operator passkeys
  identity   Agent identities (design §3.2): the issuer's public key, and verified identity documents
  policy     The installation's org policy in Cedar (#51): a ceiling and forbids over every zone, compiled into each box's token when it is minted
  state      Control-plane state off this host (#154): the state store, the ledger's stream, the recovery kit and a restore onto a standby
  keys       The installation's root keys (#154)
  reconcile  Make what exists agree with the ledger (#38): end runs whose process is gone, end leases past their end or whose run ended, destroy owned machines no lease needs (checking the owner tag again right before each destroy), adopt or create the ones leases need, and stop boxes whose run has ended, here and on enrolled nodes. Records every change in the audit log
  lease      Capacity leases (#7): nodes agents asked for with request_capacity. Approve or deny the ask with `wicket approve`/`deny` (see `wicket pending`)
  zone       The zone view of a manifest: for each host its reach names, whether the egress proxy inspects it (terminates TLS and decides every request) or splices it through (decides on the hostname, relays the encrypted bytes), and why (#62)
  doctor     Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes
  node       Remote sandbox nodes (#16): one-time join tokens, enrolment with a pinned ssh host key, a node key and a name-constrained node CA; listing, revoking, renewing the CA
  place      Nodes from a provider (#37): Vultr plans, owned nodes, create inside a money envelope with a terminal approval and enrol with the host key pinned at creation, release
  dev        Development helpers
  self       Update this installation to another wicket build (#162): blue/green, with a health gate and automatic rollback, on the control host and then its nodes. Only artifacts signed by a release key this installation trusts, or whose sha256 a human approved (an agent's `request_update`), are accepted. See docs/explanation/updates.md
  daemon     wicketd (#12): run as the wicket system user and serve other users' commands over a unix socket, letting each caller do what the policy grants its uid (from SO_PEERCRED). Approving, denying and other privileged commands need root over the socket, or a passkey in the console. Installed and started by deploy/install.sh
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `wicket run`

```text
Run a task manifest: one Claude Code agent in one zone

Usage: wicket run [OPTIONS] <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
      --workdir <WORKDIR>              Copy this directory into the box's /workspace first
      --workspace-dir <WORKSPACE_DIR>  Mount this directory as the box's /workspace, read-write and in place (local runs only)
      --task <TASK>                    Use this task text instead of the manifest's
      --image <IMAGE>                  Agent image, overriding the manifest's agent.image (default: that, or the installation's agent image)
      --node <NODE>                    Run the box on an enrolled node (its name; its host key is pinned), through its `wicket node serve`. Default: this host's own node, `local`
      --ssh-key <SSH_KEY>              ssh identity for --node (default: the one it was enrolled with)
  -h, --help                           Print help
```

## `wicket say`

```text
Send a follow-up message to a running agent, as its operator. It arrives as the agent's next turn; the session stays open until the agent finishes or exits. A long-lived agent can be named by its id or any of its runs; a hibernated one is woken

Usage: wicket say <RUN> [TEXT]...

Arguments:
  <RUN>      
  [TEXT]...  

Options:
  -h, --help  Print help
```

## `wicket hibernate`

```text
Hibernate a long-lived agent (by run or agent id) at its next quiet point: its turn has ended and nothing but the agent runs in its box. Otherwise it goes on running

Usage: wicket hibernate [OPTIONS] <RUN>

Arguments:
  <RUN>  

Options:
      --wait <WAIT>  How long to wait for the outcome (seconds) [default: 120]
  -h, --help         Print help
```

## `wicket wake`

```text
Wake a hibernated agent: rebuild its box, restore its state and resume its session. Runs the woken activation in the foreground, like `wicket run`. Text, if given, is the operator's message to it

Usage: wicket wake <AGENT> [TEXT]...

Arguments:
  <AGENT>    
  [TEXT]...  

Options:
  -h, --help  Print help
```

## `wicket agents`

```text
Long-lived agents: state, generation, current run and bundle size

Usage: wicket agents [OPTIONS]

Options:
      --json  
  -h, --help  Print help
```

## `wicket wrap`

```text
Run an agent command line that another program launches, inside a wicket box: e.g. as Claude Code Remote Control's CLAUDE_CODE_PROCESS_WRAPPER. Its stdin and stdout stay connected to the launcher, its credentials become placeholders swapped at the proxy, and wicket logs to a file

Usage: wicket wrap [OPTIONS] --manifest <MANIFEST> <ARGV>...

Arguments:
  <ARGV>...  The agent command line, after `--`

Options:
      --manifest <MANIFEST>  
      --image <IMAGE>        Agent image, overriding the manifest's agent.image
  -h, --help                 Print help
```

## `wicket pending`

```text
List pending escalation requests

Usage: wicket pending

Options:
  -h, --help  Print help
```

## `wicket approve`

```text
Approve a pending request. The grant is never wider than the request

Usage: wicket approve [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --uses <USES>      Number of uses (default 1) [default: 1]
      --unlimited        Unlimited uses until expiry
      --ttl <TTL>        Grant lifetime [default: 10m]
      --prefix <PREFIX>  Grant a path prefix of the requested path instead of the exact path
  -y, --yes              Don't ask for confirmation at a terminal (the request is printed either way)
      --zone-wide        Let any run in the request's zone use the grant, until it expires. By default only the run that asked may, and the grant ends with that run
  -h, --help             Print help
```

## `wicket deny`

```text
Deny a pending request

Usage: wicket deny <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket links`

```text
Links between boxes (expose/connect/link), newest first

Usage: wicket links [OPTIONS]

Options:
      --tail <TAIL>  [default: 40]
  -h, --help         Print help
```

## `wicket unlink`

```text
Cut a link between boxes: its relay closes it and drops its connections within seconds

Usage: wicket unlink <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket grant`

```text
Grants made by approvals

Usage: wicket grant <COMMAND>

Commands:
  revoke  Revoke a grant. A grant handed to a node is revoked there through its feed by the run that published it (at once if the node is reachable)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket grant revoke`

```text
Revoke a grant. A grant handed to a node is revoked there through its feed by the run that published it (at once if the node is reachable)

Usage: wicket grant revoke <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket audit`

```text
Show or verify the hash-chained audit log, or export it to the configured sinks

Usage: wicket audit [OPTIONS] [COMMAND]

Commands:
  export  Feed the sinks in the sinks file (`audit-sinks.yaml` in the data dir, or $WICKET_AUDIT_SINKS) until stopped. Runs alongside `wicket run` and `wicket serve`, which feed the sinks too; each sink is fed by one process at a time. The only process that writes to a `path: "-"` (stdout) sink
  help    Print this message or the help of the given subcommand(s)

Options:
      --tail <TAIL>              [default: 40]
      --verify                   
      --against <AGAINST>        With --verify: also check the local chain against exported records and signed checkpoints (JSON lines, or a Collector's OTLP JSON file output). Catches a rewritten or truncated chain. `store:<sink>`: what a `store` sink wrote to the state store
      --issuer-jwk <ISSUER_JWK>  The issuer public key (JWK, as `wicket identity issuer` prints it) checkpoints must be signed with. Default: this installation's issuer key
  -h, --help                     Print help
```

### `wicket audit export`

```text
Feed the sinks in the sinks file (`audit-sinks.yaml` in the data dir, or $WICKET_AUDIT_SINKS) until stopped. Runs alongside `wicket run` and `wicket serve`, which feed the sinks too; each sink is fed by one process at a time. The only process that writes to a `path: "-"` (stdout) sink

Usage: wicket audit export [OPTIONS]

Options:
      --once        One pass, then exit (non-zero if a sink failed)
      --checkpoint  Send every sink a checkpoint now
      --status      Show each sink's position and last error
  -h, --help        Print help
```

## `wicket secret`

```text
Manage vault secrets (values are read from the terminal, never from arguments)

Usage: wicket secret <COMMAND>

Commands:
  set    Store a secret. Prompts without echo, or reads stdin when it isn't a terminal
  list   List secret names and the hosts each may be sent to (never values)
  rm     Remove a secret (a reference: only the reference). Nodes holding a copy delete it when their run's lease next reaches them, within seconds while connected (#152)
  hosts  Bind a secret to the only hosts it may be sent to, replacing its list
  link   Make a secret a reference to a JSON field in another file, re-read on every use (never copied). E.g. the Claude login on this host: wicket secret link claude-oauth --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket secret set`

```text
Store a secret. Prompts without echo, or reads stdin when it isn't a terminal

Usage: wicket secret set [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --hosts <HOSTS>  The only hosts it may be sent to (comma-separated; `*.example.com` for every host under it). Without it, the secret keeps the hosts it had; a secret with none is sent nowhere (claude-oauth defaults to api.anthropic.com)
  -h, --help           Print help
```

### `wicket secret list`

```text
List secret names and the hosts each may be sent to (never values)

Usage: wicket secret list

Options:
  -h, --help  Print help
```

### `wicket secret rm`

```text
Remove a secret (a reference: only the reference). Nodes holding a copy delete it when their run's lease next reaches them, within seconds while connected (#152)

Usage: wicket secret rm <NAME>

Arguments:
  <NAME>  

Options:
  -h, --help  Print help
```

### `wicket secret hosts`

```text
Bind a secret to the only hosts it may be sent to, replacing its list

Usage: wicket secret hosts --hosts <HOSTS> <NAME>

Arguments:
  <NAME>  

Options:
      --hosts <HOSTS>  
  -h, --help           Print help
```

### `wicket secret link`

```text
Make a secret a reference to a JSON field in another file, re-read on every use (never copied). E.g. the Claude login on this host: wicket secret link claude-oauth --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt

Usage: wicket secret link [OPTIONS] --file <FILE> <NAME>

Arguments:
  <NAME>  

Options:
      --file <FILE>
          
      --pointer <POINTER>
          A JSON pointer into the file (e.g. /claudeAiOauth/accessToken). Without one, the whole file is the secret, trimmed (e.g. an API key file)
      --expires-pointer <EXPIRES_POINTER>
          
      --hosts <HOSTS>
          The only hosts it may be sent to (as for `secret set`)
  -h, --help
          Print help
```

## `wicket image`

```text
Build the agent image (the image directory plus the in-box forwarder's source, compiled in the build). Without --dir, from the copy embedded in this binary, so the image matches it

Usage: wicket image [OPTIONS]
       wicket image <COMMAND>

Commands:
  digest  The digest each image is in this installation's Docker (#192): `<ref> sha256:…`, what a zone pins it as (`name@sha256:…`)
  help    Print this message or the help of the given subcommand(s)

Options:
      --tag <TAG>  The tag to build, kept as given [default: this installation's own image: wicket/claude-code:<build id> on an installed version, else wicket/claude-code:poc]
      --dir <DIR>  An image directory to build instead (e.g. images/claude-code, while changing it). If its Dockerfile declares `ARG BASE`, BASE is this installation's own agent image
  -h, --help       Print help
```

### `wicket image digest`

```text
The digest each image is in this installation's Docker (#192): `<ref> sha256:…`, what a zone pins it as (`name@sha256:…`)

Usage: wicket image digest <REFS>...

Arguments:
  <REFS>...  

Options:
  -h, --help  Print help
```

## `wicket serve`

```text
Serve the operator console (runs, approvals, activity; start, steer and revoke runs). Plain HTTP on loopback by default; any other address needs HTTPS (--acme-domain, or --tls-cert and --tls-key) or --behind-tls-terminator

Usage: wicket serve [OPTIONS]

Options:
      --listen <LISTEN>
          [default: 127.0.0.1:8787]
      --origin <ORIGIN>
          Browser origin for WebAuthn (default: http://localhost:PORT; https://DOMAIN with ACME)
      --rp-id <RP_ID>
          WebAuthn relying-party id (default: the origin's host)
      --tls-cert <TLS_CERT>
          Serve HTTPS with this certificate chain (PEM; re-read when it changes)
      --tls-key <TLS_KEY>
          The certificate's private key (PEM)
      --acme-domain <ACME_DOMAIN>
          Serve HTTPS with a certificate from an ACME CA (Let's Encrypt) for this name, validated with TLS-ALPN-01 on this listener (so listen on :443)
      --acme-agree-tos
          Accept the ACME CA's terms of service (required with --acme-domain)
      --acme-contact <ACME_CONTACT>
          Contact for the ACME account (mailto:...; repeatable)
      --acme-staging
          Use Let's Encrypt's staging CA (untrusted certificates; for trying the setup)
      --acme-directory <ACME_DIRECTORY>
          Another ACME directory URL
      --acme-cache <ACME_CACHE>
          Where the ACME account and certificate are kept (default $WICKET_HOME/acme)
      --behind-tls-terminator
          A TLS-terminating proxy in front serves the console's https:// --origin; listen in plain HTTP
      --trusted-proxy <TRUSTED_PROXY>
          The proxy's address or range (repeatable): its X-Forwarded-For names the client
      --max-connections <MAX_CONNECTIONS>
          Most simultaneous connections [default: 256]
      --no-bootstrap-link
          Don't print a passkey enrolment link at start when no passkey is enrolled (a system install's log may be readable by operators; root prints one with `operator enrol-link`)
  -h, --help
          Print help
```

## `wicket program`

```text
Programs: deterministic workloads that run without an agent

Usage: wicket program <COMMAND>

Commands:
  digest  Print a program source directory's digest (what a manifest pins to approve that exact code)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket program digest`

```text
Print a program source directory's digest (what a manifest pins to approve that exact code)

Usage: wicket program digest <DIR>

Arguments:
  <DIR>  

Options:
  -h, --help  Print help
```

## `wicket operator`

```text
Operator passkeys

Usage: wicket operator <COMMAND>

Commands:
  list            List enrolled passkeys
  reset           Host-only break-glass: revoke every passkey (and every console session), so `wicket serve` prints a fresh enrolment link
  enrol-link      Print a fresh single-use link that enrols one passkey in the console (another device, or a replacement after `reset`). The only way to add a passkey: a signed-in console session can't
  sessions        List live console sessions (id, passkey, client address, times)
  revoke-session  End console sessions now: one by its id (or a unique prefix of it), or all with --all
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket operator list`

```text
List enrolled passkeys

Usage: wicket operator list

Options:
  -h, --help  Print help
```

### `wicket operator reset`

```text
Host-only break-glass: revoke every passkey (and every console session), so `wicket serve` prints a fresh enrolment link

Usage: wicket operator reset

Options:
  -h, --help  Print help
```

### `wicket operator enrol-link`

```text
Print a fresh single-use link that enrols one passkey in the console (another device, or a replacement after `reset`). The only way to add a passkey: a signed-in console session can't

Usage: wicket operator enrol-link [OPTIONS]

Options:
      --ttl <TTL>        How long the link stays usable (at most 1h) [default: 10m]
      --origin <ORIGIN>  The console's origin, to print the whole link (otherwise just its path)
  -h, --help             Print help
```

### `wicket operator sessions`

```text
List live console sessions (id, passkey, client address, times)

Usage: wicket operator sessions

Options:
  -h, --help  Print help
```

### `wicket operator revoke-session`

```text
End console sessions now: one by its id (or a unique prefix of it), or all with --all

Usage: wicket operator revoke-session [OPTIONS] [ID]

Arguments:
  [ID]  

Options:
      --all   
  -h, --help  Print help
```

## `wicket identity`

```text
Agent identities (design §3.2): the issuer's public key, and verified identity documents

Usage: wicket identity <COMMAND>

Commands:
  init    Set up this installation's identity issuer: its key and its trust domain, which every agent's SPIFFE ID is under (spiffe://<domain>/t/…). The domain is fixed once set
  issuer  Print the installation issuer's public key (JWK) and trust domain: what verifiers need
  show    Verify and show the identity wicket issued for a run
  list    List every agent identity issued, verified
  revoke  Revoke a run's identity at once (e.g. if its environment may be compromised): its box is stopped, its messages are no longer delivered, and its requests can't be approved
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket identity init`

```text
Set up this installation's identity issuer: its key and its trust domain, which every agent's SPIFFE ID is under (spiffe://<domain>/t/…). The domain is fixed once set

Usage: wicket identity init --trust-domain <TRUST_DOMAIN>

Options:
      --trust-domain <TRUST_DOMAIN>  e.g. wicket.example.com: lowercase letters, digits, '.', '-' and '_'
  -h, --help                         Print help
```

### `wicket identity issuer`

```text
Print the installation issuer's public key (JWK) and trust domain: what verifiers need

Usage: wicket identity issuer

Options:
  -h, --help  Print help
```

### `wicket identity show`

```text
Verify and show the identity wicket issued for a run

Usage: wicket identity show <RUN>

Arguments:
  <RUN>  

Options:
  -h, --help  Print help
```

### `wicket identity list`

```text
List every agent identity issued, verified

Usage: wicket identity list

Options:
  -h, --help  Print help
```

### `wicket identity revoke`

```text
Revoke a run's identity at once (e.g. if its environment may be compromised): its box is stopped, its messages are no longer delivered, and its requests can't be approved

Usage: wicket identity revoke [OPTIONS] <RUN>

Arguments:
  <RUN>  

Options:
      --reason <REASON>  [default: "revoked by the operator"]
  -h, --help             Print help
```

## `wicket policy`

```text
The installation's org policy in Cedar (#51): a ceiling and forbids over every zone, compiled into each box's token when it is minted

Usage: wicket policy <COMMAND>

Commands:
  show   The org policy's version, and the running runs minted under another
  check  Validate and compile an org policy without installing it
  apply  Install an org policy, and revoke the running runs minted under an older version (their boxes stop; new runs get the new policy)
  zone   A zone's policy as Cedar, generated from a manifest (what its boxes' tokens are compiled from)
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket policy show`

```text
The org policy's version, and the running runs minted under another

Usage: wicket policy show

Options:
  -h, --help  Print help
```

### `wicket policy check`

```text
Validate and compile an org policy without installing it

Usage: wicket policy check [OPTIONS] <FILE>

Arguments:
  <FILE>  

Options:
      --entities <ENTITIES>  The groups zones are in (Cedar entities JSON)
  -h, --help                 Print help
```

### `wicket policy apply`

```text
Install an org policy, and revoke the running runs minted under an older version (their boxes stop; new runs get the new policy)

Usage: wicket policy apply [OPTIONS] <FILE>

Arguments:
  <FILE>  

Options:
      --entities <ENTITIES>  
      --keep-runs            Leave running runs on the policy they were minted under until they end
  -h, --help                 Print help
```

### `wicket policy zone`

```text
A zone's policy as Cedar, generated from a manifest (what its boxes' tokens are compiled from)

Usage: wicket policy zone <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
  -h, --help  Print help
```

## `wicket state`

```text
Control-plane state off this host (#154): the state store, the ledger's stream, the recovery kit and a restore onto a standby

Usage: wicket state <COMMAND>

Commands:
  check      Where each kind of control-plane state goes (state-store.yaml)
  replicate  Stream the ledger to the state store until stopped (Litestream): a lost control host loses at most `ledger.sync_interval`. Run it as a service beside wicketd
  kit        Write a recovery kit: what a standby needs besides the state store (keys, state.key, nodes' feed keys and pinned host keys, config files, and the vault's secrets). Keep it offline
  restore    Make this fresh host the control host: the kit's files, then the ledger from the state store (as of now, or of --at), audit records the store has beyond it, agents fenced, and each node feed set to start a new generation
  snapshots  The ledger snapshots `wicket self update` pushed to the state store before each switch (#167): the way back past a contract step after losing the control host
  snapshot   Fetch one of them (unsealed with state.key) into a new file, to restore as docs/how-to/update-and-roll-back.md says
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket state check`

```text
Where each kind of control-plane state goes (state-store.yaml)

Usage: wicket state check [OPTIONS]

Options:
      --probe  Also write, read back and delete a probe object in the store
  -h, --help   Print help
```

### `wicket state replicate`

```text
Stream the ledger to the state store until stopped (Litestream): a lost control host loses at most `ledger.sync_interval`. Run it as a service beside wicketd

Usage: wicket state replicate

Options:
  -h, --help  Print help
```

### `wicket state kit`

```text
Write a recovery kit: what a standby needs besides the state store (keys, state.key, nodes' feed keys and pinned host keys, config files, and the vault's secrets). Keep it offline

Usage: wicket state kit [OPTIONS] --out <OUT>

Options:
      --out <OUT>        
      --without-secrets  Leave the vault's secrets out (set them again on the standby)
      --without-roots    Leave the roots out even if they are on this host
  -h, --help             Print help
```

### `wicket state restore`

```text
Make this fresh host the control host: the kit's files, then the ledger from the state store (as of now, or of --at), audit records the store has beyond it, agents fenced, and each node feed set to start a new generation

Usage: wicket state restore [OPTIONS] --kit <KIT>

Options:
      --kit <KIT>  
      --at <AT>    Restore the ledger as it was at this time (RFC 3339, UTC), discarding what came after
      --force      Replace a ledger this host already has
  -h, --help       Print help
```

### `wicket state snapshots`

```text
The ledger snapshots `wicket self update` pushed to the state store before each switch (#167): the way back past a contract step after losing the control host

Usage: wicket state snapshots

Options:
  -h, --help  Print help
```

### `wicket state snapshot`

```text
Fetch one of them (unsealed with state.key) into a new file, to restore as docs/how-to/update-and-roll-back.md says

Usage: wicket state snapshot --out <OUT> <NAME>

Arguments:
  <NAME>  Its name, as `wicket state snapshots` lists it

Options:
      --out <OUT>  
  -h, --help       Print help
```

## `wicket keys`

```text
The installation's root keys (#154)

Usage: wicket keys <COMMAND>

Commands:
  roots-offline  Move the feed root and the authority root off this host (to removable media, say): boxes' tokens are then minted by a certified issuing key, and certificates the roots issue last --days. Nodes pin the same keys as before
  certify        With the roots' directory (--roots, or WICKET_ROOTS): renew the issuing key's and every node feed's certificate for another --days (as chosen at roots-offline), and start the new generation of any feed a restore left. Installed, the wicket user must be able to read it
  roots-online   Put the roots back on this host
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket keys roots-offline`

```text
Move the feed root and the authority root off this host (to removable media, say): boxes' tokens are then minted by a certified issuing key, and certificates the roots issue last --days. Nodes pin the same keys as before

Usage: wicket keys roots-offline [OPTIONS] --to <TO>

Options:
      --to <TO>      
      --days <DAYS>  [default: 30]
  -h, --help         Print help
```

### `wicket keys certify`

```text
With the roots' directory (--roots, or WICKET_ROOTS): renew the issuing key's and every node feed's certificate for another --days (as chosen at roots-offline), and start the new generation of any feed a restore left. Installed, the wicket user must be able to read it

Usage: wicket keys certify [OPTIONS]

Options:
      --roots <ROOTS>  
  -h, --help           Print help
```

### `wicket keys roots-online`

```text
Put the roots back on this host

Usage: wicket keys roots-online --from <FROM>

Options:
      --from <FROM>  
  -h, --help         Print help
```

## `wicket reconcile`

```text
Make what exists agree with the ledger (#38): end runs whose process is gone, end leases past their end or whose run ended, destroy owned machines no lease needs (checking the owner tag again right before each destroy), adopt or create the ones leases need, and stop boxes whose run has ended, here and on enrolled nodes. Records every change in the audit log

Usage: wicket reconcile [OPTIONS]

Options:
      --dry-run        Only report what would change
      --every <EVERY>  Keep running, one pass per interval (e.g. 30s)
  -h, --help           Print help
```

## `wicket lease`

```text
Capacity leases (#7): nodes agents asked for with request_capacity. Approve or deny the ask with `wicket approve`/`deny` (see `wicket pending`)

Usage: wicket lease <COMMAND>

Commands:
  list     Every lease: status, holder run, node, money reserved, end
  release  End a lease now: what runs on it stops and its node is destroyed (one reconcile pass)
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket lease list`

```text
Every lease: status, holder run, node, money reserved, end

Usage: wicket lease list

Options:
  -h, --help  Print help
```

### `wicket lease release`

```text
End a lease now: what runs on it stops and its node is destroyed (one reconcile pass)

Usage: wicket lease release <ID>

Arguments:
  <ID>  

Options:
  -h, --help  Print help
```

## `wicket zone`

```text
The zone view of a manifest: for each host its reach names, whether the egress proxy inspects it (terminates TLS and decides every request) or splices it through (decides on the hostname, relays the encrypted bytes), and why (#62)

Usage: wicket zone [OPTIONS] [MANIFEST]
       wicket zone <COMMAND>

Commands:
  pin   Rewrite a manifest's image tags (zone.images, agent.image, program.image) to the digests they point to now, in place, keeping the rest of the file (#192)
  help  Print this message or the help of the given subcommand(s)

Arguments:
  [MANIFEST]  The manifest (YAML)

Options:
      --json  JSON instead of text
  -h, --help  Print help
```

### `wicket zone pin`

```text
Rewrite a manifest's image tags (zone.images, agent.image, program.image) to the digests they point to now, in place, keeping the rest of the file (#192)

Usage: wicket zone pin [OPTIONS] <MANIFEST>

Arguments:
  <MANIFEST>  

Options:
      --dry-run  Say what would change; write nothing
  -h, --help     Print help
```

## `wicket doctor`

```text
Check the environment: Docker, gVisor, image, secrets, ledger, orphaned boxes

Usage: wicket doctor [OPTIONS]

Options:
      --image <IMAGE>  [default: wicket/claude-code:poc]
  -h, --help           Print help
```

## `wicket node`

```text
Remote sandbox nodes (#16): one-time join tokens, enrolment with a pinned ssh host key, a node key and a name-constrained node CA; listing, revoking, renewing the CA

Usage: wicket node <COMMAND>

Commands:
  token     Print a one-time join token for a node (stored hashed; single use)
  enrol     Enrol a node over ssh: pin its host key, have it make its node key and CA key, and give it a short-lived identity certificate for its node key, a short-lived CA certificate constrained to --hosts, the feed root key and the issuer key
  list      List enrolled nodes
  revoke    Revoke a node: refuse it from now on (its pinned host key is deleted, its identity certificates are revoked, and runs connected to it drop it) and record its CA serials for the feed's revocation list
  install   Copy this wicket binary to an enrolled node (sha256-checked) and install the `wicket-node` systemd user service that runs `wicket node serve` there
  serve     On the node: run its boxes and decide their egress locally from the signed feed (the `wicket-node` service runs this)
  renew-ca  Issue a node a fresh CA certificate (and CA key, made on the node) and a fresh identity certificate for its node key, over its pinned ssh: also how a node whose identity certificate expired while it was unreachable gets back in
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket node token`

```text
Print a one-time join token for a node (stored hashed; single use)

Usage: wicket node token [OPTIONS]

Options:
      --name <NAME>  The node's name (default: a generated one, printed)
      --ttl <TTL>    [default: 1h]
  -h, --help         Print help
```

### `wicket node enrol`

```text
Enrol a node over ssh: pin its host key, have it make its node key and CA key, and give it a short-lived identity certificate for its node key, a short-lived CA certificate constrained to --hosts, the feed root key and the issuer key

Usage: wicket node enrol [OPTIONS] --token <TOKEN> --hosts <HOSTS> <TARGET>

Arguments:
  <TARGET>  e.g. wicket@203.0.113.7

Options:
      --token <TOKEN>        From `wicket node token`
      --name <NAME>          The node name (must match the token's)
      --ssh-key <SSH_KEY>    ssh identity to log in with (remembered for later runs)
      --host-key <HOST_KEY>  The node's ssh host key (`ssh-ed25519 AAAA…`) or its fingerprint (`SHA256:…`), from the provider's console, cloud-init output or the image: not from the network
      --trust-first-use      No --host-key: pin whatever key the node presents now, and print its fingerprint
      --hosts <HOSTS>        Hosts the node's CA may mint certificates for: `api.example.com`, `*.example.org` (comma-separated)
      --ca-ttl <CA_TTL>      Node CA lifetime [default: 24h]
      --cert-ttl <CERT_TTL>  Node identity certificate lifetime (renewed over the control channel at half-life) [default: 24h]
  -h, --help                 Print help
```

### `wicket node list`

```text
List enrolled nodes

Usage: wicket node list

Options:
  -h, --help  Print help
```

### `wicket node revoke`

```text
Revoke a node: refuse it from now on (its pinned host key is deleted, its identity certificates are revoked, and runs connected to it drop it) and record its CA serials for the feed's revocation list

Usage: wicket node revoke <NAME>

Arguments:
  <NAME>  

Options:
  -h, --help  Print help
```

### `wicket node install`

```text
Copy this wicket binary to an enrolled node (sha256-checked) and install the `wicket-node` systemd user service that runs `wicket node serve` there

Usage: wicket node install [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --ssh-key <SSH_KEY>  ssh identity (default: the one it was enrolled with)
      --no-service         Only copy the binary; don't install or restart the service
  -h, --help               Print help
```

### `wicket node serve`

```text
On the node: run its boxes and decide their egress locally from the signed feed (the `wicket-node` service runs this)

Usage: wicket node serve [OPTIONS]

Options:
      --dir <DIR>  The node's directory (default: $WICKET_NODE_HOME or ~/.local/share/wicket-node)
  -h, --help       Print help
```

### `wicket node renew-ca`

```text
Issue a node a fresh CA certificate (and CA key, made on the node) and a fresh identity certificate for its node key, over its pinned ssh: also how a node whose identity certificate expired while it was unreachable gets back in

Usage: wicket node renew-ca [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --hosts <HOSTS>        Replace the hosts it is constrained to (default: keep them)
      --ca-ttl <CA_TTL>      [default: 24h]
      --cert-ttl <CERT_TTL>  Node identity certificate lifetime [default: 24h]
  -h, --help                 Print help
```

## `wicket place`

```text
Nodes from a provider (#37): Vultr plans, owned nodes, create inside a money envelope with a terminal approval and enrol with the host key pinned at creation, release

Usage: wicket place <COMMAND>

Commands:
  plans    List Vultr plans in a region with their hourly price
  list     List this installation's nodes (by owner tag) with their paid time
  create   Create a Vultr node inside a money envelope, after approval on this terminal, and enrol it with its host key pinned at creation
  release  Destroy an owned node now (refusing anything without the owner tag) and revoke its enrolment
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket place plans`

```text
List Vultr plans in a region with their hourly price

Usage: wicket place plans [OPTIONS]

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
      --region <REGION>
          [default: lhr]
      --plan-type <PLAN_TYPE>
          [default: vc2]
  -h, --help
          Print help
```

### `wicket place list`

```text
List this installation's nodes (by owner tag) with their paid time

Usage: wicket place list [OPTIONS]

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
  -h, --help
          Print help
```

### `wicket place create`

```text
Create a Vultr node inside a money envelope, after approval on this terminal, and enrol it with its host key pinned at creation

Usage: wicket place create [OPTIONS] --name <NAME> --max-hourly <MAX_HOURLY> --max-total <MAX_TOTAL> --ssh-key-id <SSH_KEY_IDS>

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
      --name <NAME>
          Node name (hostname, label and enrolled name)
      --hosts <HOSTS>
          Hosts the node's CA may issue for, as for `wicket node enrol --hosts`
      --region <REGION>
          [default: lhr]
      --plan <PLAN>
          A plan id (e.g. vc2-1c-2gb); otherwise the cheapest that fits --vcpus and --memory-mib
      --vcpus <VCPUS>
          [default: 1]
      --memory-mib <MEMORY_MIB>
          [default: 2048]
      --lifetime <LIFETIME>
          How long the node is needed: its worst-case cost is reserved for this long, and its lease ends at minute 50 of the last hour [default: 1h]
      --max-node-hourly <MAX_NODE_HOURLY>
          Most this node may cost per hour, in dollars
      --max-hourly <MAX_HOURLY>
          Envelope: most all owned nodes together may cost per hour, in dollars
      --max-total <MAX_TOTAL>
          Envelope: most all owned nodes together may cost through their leases, in dollars
      --ssh-key-id <SSH_KEY_IDS>
          Id of an ssh key already in the Vultr account (installed for root, copied to `wicket`)
      --ssh-key <SSH_KEY>
          The private half of that key, on this host
      --os-id <OS_ID>
          Vultr os_id (default: Ubuntu 24.04 x64) [default: 2284]
      --idempotency-key <IDEMPOTENCY_KEY>
          Make a retried create return the same node (default: derived from --name)
      --no-enrol
          Create and wait, but don't enrol
      --ca-ttl <CA_TTL>
          [default: 24h]
  -h, --help
          Print help
```

### `wicket place release`

```text
Destroy an owned node now (refusing anything without the owner tag) and revoke its enrolment

Usage: wicket place release [OPTIONS] <ID>

Arguments:
  <ID>  The Vultr instance id

Options:
      --api-key-secret <API_KEY_SECRET>
          The vault secret holding the Vultr API key [default: vultr-api-key]
      --owner <OWNER>
          The owner tag's installation name (default: this installation's trust domain, else "wicket"). Garbage collection only ever touches instances carrying it, so keep it stable
  -h, --help
          Print help
```

## `wicket dev`

```text
Development helpers

Usage: wicket dev <COMMAND>

Commands:
  node-feed-probe  On a node: send `node serve` its own last freshness statement, tampered and then replayed, and print how each was refused (a check for ci/node-e2e.sh). The control connection stays up
  mock-llm         A scripted stand-in for the Anthropic Messages API: each turn runs one Bash command, then calls wicket's finish tool (or hibernate, or neither, as the command's output asks with a `wicket-mock: hibernate` or `wicket-mock: stay` line). Lets the whole path be tested without an API key
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket dev node-feed-probe`

```text
On a node: send `node serve` its own last freshness statement, tampered and then replayed, and print how each was refused (a check for ci/node-e2e.sh). The control connection stays up

Usage: wicket dev node-feed-probe [OPTIONS]

Options:
      --dir <DIR>  
  -h, --help       Print help
```

### `wicket dev mock-llm`

```text
A scripted stand-in for the Anthropic Messages API: each turn runs one Bash command, then calls wicket's finish tool (or hibernate, or neither, as the command's output asks with a `wicket-mock: hibernate` or `wicket-mock: stay` line). Lets the whole path be tested without an API key

Usage: wicket dev mock-llm [OPTIONS] --command <COMMAND>

Options:
      --listen <LISTEN>    [default: 127.0.0.1:9999]
      --command <COMMAND>  The Bash command the mock model asks the agent to run
  -h, --help               Print help
```

## `wicket self`

```text
Update this installation to another wicket build (#162): blue/green, with a health gate and automatic rollback, on the control host and then its nodes. Only artifacts signed by a release key this installation trusts, or whose sha256 a human approved (an agent's `request_update`), are accepted. See docs/explanation/updates.md

Usage: wicket self <COMMAND>

Commands:
  status       The staged versions, which is current and previous, and the ledger's schema
  update       Stage an artifact (a wicket binary, or a release archive from ci/package.sh), switch the control host to it, hand its processes over, and watch it; then the nodes, a canary first. Any failed health check switches back
  follow       Update to the newest build CI signed for main, if `<data dir>/ci-builds.yaml`'s follow policy lets it now (its window, soak time, only forward along main, never across a schema contract step or a failed build). Run by the wicket-follow timer
  rollback     Switch back to the previous version: the control host (unless --only-nodes) and these nodes
  prune        Remove what no rollback or running box needs: versions other than current and previous that no process runs, their agent images unless a container uses them, and ledger snapshots beyond the newest few (always keeping the newest of the current and previous versions')
  trust-key    Trust a release public key (from `wicket self keygen`) for updates
  keygen       Make a release key pair: KEY (private, keep it offline) and KEY.pub
  sign         Sign an artifact with a release key: writes <artifact>.sig
  apply-units  Install this build's systemd units (#165) where they differ from the installed ones, and reload systemd; restarts nothing. Run as root with the version's own binary, as a refused `self update` says: `sudo <versions>/<id>/wicket self apply-units`
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `wicket self status`

```text
The staged versions, which is current and previous, and the ledger's schema

Usage: wicket self status

Options:
  -h, --help  Print help
```

### `wicket self update`

```text
Stage an artifact (a wicket binary, or a release archive from ci/package.sh), switch the control host to it, hand its processes over, and watch it; then the nodes, a canary first. Any failed health check switches back

Usage: wicket self update [OPTIONS] [ARTIFACT]

Arguments:
  [ARTIFACT]  The artifact: a wicket binary, or a release archive

Options:
      --from-ci <COMMIT|latest>  A build CI signed instead (#190): a commit on main, or `latest`. Downloaded here and taken only if signed in the release environment by a trusted key, for this installation's repository (`<data dir>/ci-builds.yaml`) and that commit, on main
      --sig <SIG>                The detached signature (default: <artifact>.sig)
      --nodes <NODES>            Also update these nodes after the control host: `all`, or names (comma-separated). The first is the canary
      --only-nodes               The control host already runs this build: only the nodes
      --window <WINDOW>          How long each new build is watched after its switch [default: 30s]
      --interval <INTERVAL>      How often within the window [default: 10s]
      --check <CHECK>            A command (sh -c) that must succeed each time; $WICKET is the new build's binary and $WICKET_UPDATE_TARGET `control` or `node:<name>`. Repeatable
      --canary <CANARY>          A task manifest the new build runs once on the control host; it must succeed
      --image <IMAGE>            The canary's image (default: the new build's own, wicket/claude-code:<build id>)
      --no-prune                 Keep what the update leaves unneeded (by default it prunes as `wicket self prune` does, where it updated)
  -h, --help                     Print help
```

### `wicket self follow`

```text
Update to the newest build CI signed for main, if `<data dir>/ci-builds.yaml`'s follow policy lets it now (its window, soak time, only forward along main, never across a schema contract step or a failed build). Run by the wicket-follow timer

Usage: wicket self follow

Options:
  -h, --help  Print help
```

### `wicket self rollback`

```text
Switch back to the previous version: the control host (unless --only-nodes) and these nodes

Usage: wicket self rollback [OPTIONS]

Options:
      --nodes <NODES>  `all`, or node names (comma-separated)
      --only-nodes     
  -h, --help           Print help
```

### `wicket self prune`

```text
Remove what no rollback or running box needs: versions other than current and previous that no process runs, their agent images unless a container uses them, and ledger snapshots beyond the newest few (always keeping the newest of the current and previous versions')

Usage: wicket self prune [OPTIONS]

Options:
      --nodes <NODES>                    Also these nodes: `all`, or names (comma-separated)
      --only-nodes                       
      --keep-snapshots <KEEP_SNAPSHOTS>  How many snapshots to keep [default: 5]
      --dry-run                          Say what would go; remove nothing
  -h, --help                             Print help
```

### `wicket self trust-key`

```text
Trust a release public key (from `wicket self keygen`) for updates

Usage: wicket self trust-key <PUBLIC>

Arguments:
  <PUBLIC>  

Options:
  -h, --help  Print help
```

### `wicket self keygen`

```text
Make a release key pair: KEY (private, keep it offline) and KEY.pub

Usage: wicket self keygen <KEY>

Arguments:
  <KEY>  

Options:
  -h, --help  Print help
```

### `wicket self sign`

```text
Sign an artifact with a release key: writes <artifact>.sig

Usage: wicket self sign --key <KEY> <ARTIFACT>

Arguments:
  <ARTIFACT>  

Options:
      --key <KEY>  
  -h, --help       Print help
```

### `wicket self apply-units`

```text
Install this build's systemd units (#165) where they differ from the installed ones, and reload systemd; restarts nothing. Run as root with the version's own binary, as a refused `self update` says: `sudo <versions>/<id>/wicket self apply-units`

Usage: wicket self apply-units [OPTIONS]

Options:
      --dir <DIR>  Another units directory (default: /etc/systemd/system, which needs root)
  -h, --help       Print help
```

## `wicket daemon`

```text
wicketd (#12): run as the wicket system user and serve other users' commands over a unix socket, letting each caller do what the policy grants its uid (from SO_PEERCRED). Approving, denying and other privileged commands need root over the socket, or a passkey in the console. Installed and started by deploy/install.sh

Usage: wicket daemon [OPTIONS]

Options:
      --socket <SOCKET>  [default: /run/wicket/wicketd.sock]
      --policy <POLICY>  Who may read, run and revoke (YAML; default: the wicket-operators group) [default: /etc/wicket/wicketd.yaml]
  -h, --help             Print help
```
