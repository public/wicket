# Drive a box from the Claude apps

Three ways to chat with an agent in a wicket box from the Claude apps (desktop, web, phone):

- **A remote session** (`agent.remote`, #169): wicket starts the box, and the harness in it
  registers its own session with the vendor. The task is optional, and wicket can't give it one: the
  session starts working when its owner sends the first message from the app.
- **A driven remote session** (`agent.remote.drive`, #285): wicket drives the agent as in any box
  (the manifest's task is its first turn), and its session is also in the app, where you watch it
  and can send it messages.
- **A wrapped session** (`wicket wrap`): Claude Code's Remote Control on your host launches each
  session process, and wicket puts it in a box.

## A remote session

1. Link the account login by reference, bound to the provider's host (on an installed host, with
   `sudo`):

   ```sh
   wicket secret link claude-login --file ~/.claude/.credentials.json \
       --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt --hosts api.anthropic.com
   ```

   For a Claude login, the link also reads the account fields Remote Control checks before it starts
   (organization and account ids, plan, roles; never the holder's name) from the login's Claude
   config, `~/.claude.json` beside `~/.claude/.credentials.json` (or `.claude.json` in a
   `CLAUDE_CONFIG_DIR`), and keeps them with the secret. Box starts use that copy and never read
   `~/.claude.json`, which Claude Code replaces often (dropping any ACL on it). So the user running
   the link must be able to read that file at that moment: on an installed host, grant the `wicket`
   user read just before linking (`setfacl -m u:wicket:r ~/.claude.json`); it doesn't need to keep
   it. If it can't be read, the secret is linked anyway and `wicket secret link` warns that Remote
   Control boxes need a re-link. Re-link to refresh the fields, such as after switching accounts or
   organizations.

2. Start from `examples/remote-control-box.yaml`, a whole zone for it: `agent.remote.name` is the
   session's name in the apps, and `zone.llm.secret` names the login linked above.
3. Run it:

   ```sh
   wicket run examples/remote-control-box.yaml
   ```

   When the session is up, wicket prints `[wicket] remote session: <url>` and records it as
   `run.remote_session`; the session shows up in the Claude apps, and the console links it on the
   run's card.
4. Decide what the zone doesn't allow as usual (`wicket pending`, or the console). Deny what a
   session doesn't need.

This is the harness's remote [mode](../reference/manifest.md#harness-modes). For
`harness: claude-code` it is Remote Control: `claude remote-control --spawn session` in the box.
Harness adapters that have no remote mode refuse the manifest, saying so.

What it protects, and how:

- **The account login never enters the box.** A remote session needs the owner's full login (for
  Claude, the claude.ai OAuth login: it can list and drive the account's sessions), not an inference
  token. The box gets a placeholder login (a credentials file whose access token is a placeholder,
  expiring far ahead, and a refresh token that refreshes nothing). The egress proxy swaps the
  placeholder for the real access token on the hosts the secret is bound to, and only on the paths
  the zone's reach allows. The secret is read at each use, so the host's own Claude Code keeps it
  fresh; the refresh token never leaves the host. The per-session tokens the API hands the box for
  its session go up as the box sent them, since they aren't wicket's to hold. Only the login's
  non-secret account fields reach the box (scopes, plan, and the account and organization ids Claude
  Code checks before it starts Remote Control; not the holder's name).
- **Reach is the authority.** Everything the zone reaches on the provider's host is reached with the
  owner's login, so the example names only what a session needs (registering, reconnecting and
  deregistering its environment, its work and worker channel, creating its session and posting its
  events, reading its own metadata back, model calls, the profile, validating the login's scopes),
  forbids the account's connectors (`mcp-proxy.anthropic.com`, `/v1/mcp_servers` and everything
  under it, a session's remote MCP at `/v2/ccr-sessions/<id>/mcp`) and token refresh outright, and
  leaves everything else (other sessions, triggers, memory) to a human's decision, as in any zone:
  deny those. It also forbids, so that nothing waits for a human at each start, the background
  reads a box has no use for: the consumer-terms notice (`/api/claude_code_grove`), the
  organization's fast mode (`/api/claude_code_penguin_mode`) and guest-pass referral eligibility.
  Claude Code carries on without each. A forbid glob ending `/**` doesn't match the bare path
  before it: forbid both, as the example does for `/v1/mcp_servers`.
- **Inside the box** Claude Code is set up so nothing waits on a terminal that isn't there: the
  workspace is trusted, Remote Control's one-time prompt is answered, wicket's gateway is the only MCP
  server, and the sandbox notice is the user memory.
- **Permission mode.** `agent.remote.permission_mode` is passed to `claude remote-control
  --permission-mode` (`acceptEdits`, `auto`, `bypassPermissions`, `default`, `dontAsk` or `plan`).
  The default, `default`, asks in the app before each action, so a box nobody is watching stalls on
  its first prompt; for an unattended box set `bypassPermissions`:

  ```yaml
  agent:
    name: rc-box
    remote: { name: wicket-box, permission_mode: bypassPermissions }
  ```

  The mode only decides whether Claude Code asks you first. wicket's proxies decide what the box can
  reach whatever the mode: egress outside the zone's reach is still a decision for a human, and the
  login is still only a placeholder in the box. An unknown mode is refused, and a harness with no
  permission modes refuses any but `default`.
- **Nodes.** It runs on any node: the node forwards the provider's host to the control host, where the
  login is swapped in, so the secret stays with the control host.
- **Not with hibernation.** The session lives in the vendor's apps, so the `hibernate` tool is refused;
  the box ends with its session. A supervisor that is handed over (`wicket self update`, #151) rebuilds
  the swap from the manifest.
- **It waits for you.** `claude remote-control` takes its messages from the app only, so the
  manifest's `task` isn't delivered (wicket has no channel into the session): the box idles until
  its owner sends the first message. For a box that starts on its task by itself, use a driven
  remote session.

## A driven remote session

`agent.remote` with `drive: true` is a driven box whose Claude Code session is also a Remote
Control session. wicket gives it the manifest's task, `wicket say` follow-ups, peers' messages and
wakes as turns, as in any driven box; in the app you see the same conversation as it happens, and a
message you send there is the agent's next turn.

1. Link the login as for a remote session (step 1 above).
2. Start from `examples/remote-driven-box.yaml`: it has a `task`, `agent.remote: { name: ...,
   drive: true }`, and a zone whose reach is what a driven session calls.
3. `wicket run examples/remote-driven-box.yaml`. wicket prints `[wicket] remote session: <url>` and
   records it as `run.remote_session` once Remote Control is on; if it can't start (no claude.ai
   subscription, a zone that refuses its calls), wicket prints why, records
   `run.remote_session_failed`, and the agent carries on, driven only.

How it works, and what differs from a remote session:

- **Claude Code** runs as in the driven mode (`claude -p --input-format stream-json`). `claude -p`
  takes no Remote Control flag (`--remote-control` starts an interactive session only, and
  `claude remote-control` takes its messages from the app only); instead its stdin host can turn
  Remote Control on with a `remote_control` control request, which wicket writes before the task.
  Its answer has the session's address.
- **The login** is a placeholder, as for a remote session, and Remote Control runs only against
  `api.anthropic.com` with a claude.ai login: so the model calls go there through the egress proxy
  (with `zone.llm`'s budget and accounting), not to wicket's model proxy with an inference token.
- **Permission mode.** `agent.remote.permission_mode` defaults to `bypassPermissions`, as in any
  driven box. In `claude -p`, an action that needs approval is asked of its stdin host (wicket), not
  the app, and wicket answers no such prompt, so `default` is refused; `acceptEdits`, `auto`,
  `dontAsk` and `plan` are passed to `--permission-mode`. wicket's proxies decide what the box can
  reach whatever the mode.
- **Hibernation.** It hibernates and wakes as a driven agent: a wake resumes the same conversation
  and turns Remote Control on again, which registers a new session in the app (with a new address,
  printed and recorded as before).
- **Reach.** A driven session creates its session with `POST /v1/code/sessions` and gets its worker
  credentials from `/v1/code/sessions/<id>/bridge`, instead of registering an environment and polling
  for work; the example's reach has those, and refuses the account's MCP servers and the settings a
  box doesn't need.

## A wrapped session

`wicket wrap --manifest <m> -- <agent command line>` runs an agent that another program launches
inside a box, with stdio connected through. `examples/remote-control/` uses it as Claude Code's
`CLAUDE_CODE_PROCESS_WRAPPER`, so a session you drive from the Claude app runs in gVisor:

```sh
mkdir -p ~/work/some-folder && cd ~/work/some-folder     # a folder Claude Code trusts
CLAUDE_CODE_PROCESS_WRAPPER=/path/to/wicket/examples/remote-control/wrap.sh \
  claude remote-control --spawn session --name my-sandboxed-session
```

Then open the session in the Claude app. The box holds only placeholder credentials, which the proxy
swaps for the real ones on `api.anthropic.com` alone; see `examples/remote-control/manifest.yaml`
for the reach a session needs, and its README for the details.

- `wicket wrap` mounts its launcher's directory in place, so under the daemon it is root's only
  ([daemon](../reference/daemon.md#who-may-run-what)).
- Wrapped sessions run only on the control host's own node: the box takes over its launcher's stdio
  protocol and its working directory at the same path, and a node's channel may drop output while
  disconnected, which that protocol can't survive.
- A wrapped session can't be taken over by a new supervisor (its launcher was the process that
  died): after a control-host restart it ends as `lost` and its box is stopped.
- Wrapped agents don't hibernate.
