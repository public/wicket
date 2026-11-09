# Example: a Remote Control session inside wicket

Drive a Claude Code session live from the Claude app (desktop, web or phone) while it runs in a wicket
box: gVisor, no network of its own, everything through wicket's proxy.

```sh
mkdir -p ~/work/some-folder && cd ~/work/some-folder     # a folder Claude Code trusts
CLAUDE_CODE_PROCESS_WRAPPER=/path/to/wicket/examples/remote-control/wrap.sh \
  claude remote-control --spawn session --name my-sandboxed-session
```

Then open the session in the Claude app. `wicket` must be on the PATH, and Docker reachable
(`WICKET_DOCKER` if you use sudo). Remote Control serves one bridge per folder.

- The session's account login and session token never enter the box. The box holds placeholders, and
  wicket's egress proxy swaps them for the real values toward `api.anthropic.com` only.
- Your claude.ai connectors are forbidden in the zone: they would hand the box your account-wide tools.
- Anything outside the zone's reach becomes a wicket request (`wicket pending`, or the console). Claude
  Code's own permission prompt in the app is advisory; only wicket can grant network access.
- wicket logs to `~/.local/share/wicket/wrap-logs/<pid>.log`; the session's stdout belongs to Remote Control.
