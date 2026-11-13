# Drive a box from the Claude apps

Two ways to chat with an agent in a wicket box from the Claude apps (desktop, web, phone):

- **A remote session** (`agent.remote`, #169): wicket starts the box, and the harness in it
  registers its own session with the vendor. The task is optional: the first message comes from the
  app.
- **A wrapped session** (`wicket wrap`): Claude Code's Remote Control on your host launches each
  session process, and wicket puts it in a box.

## A remote session

1. Link the account login by reference, bound to the provider's host (on an installed host, with
   `sudo`):

   ```sh
   wicket secret link claude-login --file ~/.claude/.credentials.json \
       --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt --hosts api.anthropic.com
   ```

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

For `kind: claude-code` this is Remote Control: `claude remote-control --spawn session` in the box.
Harness adapters that have no such feature refuse the manifest, saying so.

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
  owner's login, so the example names only what a session needs (registering its environment, its
  work and worker channel, model calls, the profile), forbids the account's connectors
  (`mcp-proxy.anthropic.com`, `/v1/mcp_servers`) and token refresh outright, and leaves everything
  else (other sessions, triggers, memory) to a human's decision, as in any zone: deny those.
- **Inside the box** Claude Code is set up so nothing waits on a terminal that isn't there: the
  workspace is trusted, Remote Control's one-time prompt is answered, wicket's gateway is the only MCP
  server, and the sandbox notice is the user memory. Claude Code asks in the app before it acts
  (permission mode `default`); wicket decides what the box can reach either way.
- **Nodes.** It runs on any node: the node forwards the provider's host to the control host, where the
  login is swapped in, so the secret stays with the control host.
- **Not with hibernation.** The session lives in the vendor's apps, so `hibernate_after` is refused;
  the box ends with its session. A supervisor that is handed over (`wicket self update`, #151) rebuilds
  the swap from the manifest.

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
