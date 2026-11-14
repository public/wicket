# Secrets and the vault

The vault is one file per secret under `$HOME/.config/wicket/secrets/` (installed:
`/var/lib/wicket/.config/wicket/secrets/`), mode 0600, or a `<name>.ref` file for a linked secret
(`wicket secret link`), naming a file that is re-read at every use. Each secret's `<name>.hosts`
lists the hosts it may be sent to. [Store and link secrets](../how-to/store-and-link-secrets.md)
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
owns, such as an operator's Claude login, keep it owner-only and grant the `wicket` user read with
an ACL, and let it reach the file through its directories:

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
