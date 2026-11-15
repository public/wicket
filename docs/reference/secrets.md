# Secrets and the vault

The vault is one file per secret under `$HOME/.config/wicket/secrets/` (installed:
`/var/lib/wicket/.config/wicket/secrets/`), mode 0600, or a `<name>.ref` file for a linked secret
(`wicket secret link`), naming a file that is re-read at every use. Each secret's `<name>.hosts`
lists the hosts it may be sent to. A `.ref` may also keep non-secret metadata a harness read when the
secret was linked (below). [Store and link secrets](../how-to/store-and-link-secrets.md)
shows how to use it.

## Who may read a secret's file

wicket refuses a secret file, or a file a secret links to, that someone other than its owner and the
user wicket runs as can read. The error says who else can read it.

- A file whose mode has no group or other bits (0600, 0400) is accepted.
- Otherwise its POSIX access ACL decides. It is accepted only when others, the owning group and
  every named group can't read it, and the only named user who can is the user wicket runs as. The
  ACL mask can only take read away from named users and groups, never give it.
- A file with group or other bits and no ACL (or on a filesystem without ACLs) is refused.

## Let the wicket user read a linked file

On an installed host, wicket reads linked files as the `wicket` user. To link a file another user
owns, such as an operator's Claude login, prefer [the secret helper](#a-link-through-the-secret-helper):
nothing to grant, and a refresh doesn't break it. Otherwise keep it owner-only and grant the `wicket`
user read with an ACL, and let it reach the file through its directories:

```sh
chmod 600 ~/.claude/.credentials.json
setfacl -m u:wicket:r ~/.claude/.credentials.json
setfacl -m u:wicket:x ~ ~/.claude
sudo wicket secret link claude-oauth --file ~/.claude/.credentials.json \
    --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
```

`getfacl ~/.claude/.credentials.json` should show `user:wicket:r--`, `group::---`, `mask::r--` and
`other::---`. `ls -l` shows the mask as the group bits (`-rw-r-----+`): that is expected. A program
that rewrites the file may replace it with one without the ACL (Claude Code refreshing its login, for
one): if wicket then can't read it, grant the ACL again, or set a default ACL on the directory
(`setfacl -d -m u:wicket:r ~/.claude`) so new files there get it.

## A link through the secret helper

A `.ref` made by `wicket secret link --via-helper` names a helper instead of a file wicket reads:
`{"file": …, "helper": {"uid": 1000, "socket": "@wicket-secret.1000"}}` (`file` is only noted). At
every use the vault connects to the socket (`@` is the abstract namespace; otherwise a path), refuses
it unless `SO_PEERCRED` says it is held by `uid`, sends `{"secret": NAME}` and reads one line back:
`{"value": …, "expires_at": MS}` or `{"error": …}`. An expired value is refused. The helper is
`wicket secret serve`, run as the file's owner: it serves only the secrets named on its command
line, only to the uid `--for` names, and only their values and expiries. See
[store and link secrets](../how-to/store-and-link-secrets.md#link-a-login-without-an-acl-the-secret-helper).

## What a link keeps besides the reference

The vault keeps a linked secret's `meta` as the harness adapter hands it over at `wicket secret
link`, without reading it. A re-link replaces it. For a Claude login (a pointer under
`/claudeAiOauth/`), the Claude adapter keeps the login's `oauthAccount` from its Claude config
(`~/.claude.json` beside `~/.claude/.credentials.json`, or `.claude.json` in a `CLAUDE_CONFIG_DIR`):
account and organization ids, plan and roles, without `fullName`. No credential is kept.

A Remote Control box (`agent.remote`) gets those fields from the stored copy and never reads
`~/.claude.json`. Claude Code replaces that file often, so an ACL on it doesn't last: grant the
`wicket` user read on it only for the link (`setfacl -m u:wicket:r ~/.claude.json`, then `sudo wicket
secret link ...`). If the config can't be read, the secret is linked anyway and the link warns that
Remote Control boxes need a re-link once it can be. Re-link after switching accounts or
organizations to refresh the fields.
