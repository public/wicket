# Store and link secrets

wicket's vault holds the credentials boxes use, so the boxes never do: a box holds placeholders, and
the proxies put the real value into one header, toward the hosts the secret is bound to. On an
installed host every command here that changes a secret needs `sudo`.

## Store a secret

```sh
wicket secret set github-ro --hosts api.github.com
```

The value is read from the terminal without echo, or from stdin when it isn't a terminal (`printf
'%s' "$TOKEN" | wicket secret set …`); never from an argument. Names are letters, digits, `-` and
`_`. It prints where the secret may go:

```text
stored secret github-ro; sent only to api.github.com
```

**Bind every secret to the hosts it is for.** `--hosts` takes a comma-separated list, and
`*.example.com` for every host under `example.com`. A secret bound to no hosts is sent nowhere.
Without `--hosts`, `secret set` keeps the hosts the secret already had. The vault has no defaults of
its own, but a harness's default model secret stored or linked with no binding is bound to its
model host, as the harness's adapter says: `claude-oauth` to `api.anthropic.com`. A `claude-oauth`
stored by an earlier build without `--hosts` has no binding: bind it with `wicket secret hosts
claude-oauth --hosts api.anthropic.com`.

## Link a secret instead of copying it

A linked secret is a reference to a JSON field in a file, re-read at every use and never copied. Use
it for the host's own Claude Code login, which Claude Code keeps fresh:

```sh
wicket secret link claude-oauth --file ~/.claude/.credentials.json \
    --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
```

`--pointer` is a JSON pointer into the file; without it the whole file, trimmed, is the secret (an
API key file, say). `--expires-pointer` names the field that says when the value expires (Unix ms),
so a node holding a copy drops it then. `--hosts` works as for `secret set`. On an installed host
the file is read as the `wicket` user, so it must be readable by it, and by no one else but its
owner. For another user's file, such as an operator's Claude login, use the
[secret helper](#link-a-login-without-an-acl-the-secret-helper); granting the `wicket` user read with
an ACL also works, until a program rewriting the file drops it
([secrets reference](../reference/secrets.md#let-the-wicket-user-read-a-linked-file)).

## Link a login without an ACL: the secret helper

An ACL on another user's login file doesn't last: Claude Code refreshes its login by rewriting
`~/.claude/.credentials.json` at mode 0600, which drops the ACL, and from then on every model call
fails until it is granted again. It is also wider than needed: it lets the `wicket` user read the
whole file, refresh token included. Instead, run the **secret helper** as the file's owner, and link
the secret through it:

1. As the file's owner, install and start the helper as a systemd user service (edit `--secret` in
   the unit if your login is elsewhere, or to serve more than one secret):

   ```sh
   mkdir -p ~/.config/systemd/user
   cp deploy/systemd-user/wicket-secret-helper.service ~/.config/systemd/user/
   systemctl --user daemon-reload && systemctl --user enable --now wicket-secret-helper
   loginctl enable-linger "$USER"    # keep it running while you are logged out
   ```

   It runs `wicket secret serve --for wicket --secret
   claude-oauth=%h/.claude/.credentials.json#/claudeAiOauth/accessToken#/claudeAiOauth/expiresAt`:
   each `--secret` is `NAME=FILE[#POINTER[#EXPIRES_POINTER]]`.

2. Link the secret through it (`--file` and `--pointer` are only noted, and say whose login it is):

   ```sh
   sudo wicket secret link claude-oauth --via-helper --helper-user "$USER" \
       --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken
   ```

   ```text
   secret claude-oauth is now read through the secret helper of uid 1000 at @wicket-secret.1000 (at each use; never copied; wicket reads no file); sent only to api.anthropic.com
   ```

3. Remove the ACLs you had granted (`setfacl -x u:wicket ~/.claude/.credentials.json`), and check:
   `wicket doctor` says `claude-oauth: read through the secret helper of uid 1000 at
   @wicket-secret.1000: reachable, valid for N more minutes`.

What it does:

- At every use, wicketd asks the helper for the secret by name. The helper reads the file itself, as
  its owner, and answers with the pointed-to value and its expiry, nothing else from the file: the
  refresh token never leaves its owner. A refresh is picked up at the next request.
- Each end checks the other by the kernel's word (`SO_PEERCRED`): the helper answers only the
  `wicket` user (`--for`), and wicketd takes an answer only from the uid the link names
  (`--helper-user`, by default you, the caller), so another process that took the socket's name
  can't hand it a token of its own.
- The socket is in the abstract namespace, `@wicket-secret.<uid>`, so there is no directory both
  users need to reach. Boxes have their own network namespace and can't reach it. `--socket` (on
  `serve`) and `--helper-socket` (on `link`) take another name, or a path.

Why a flag, and not a fallback when the file can't be read: a link says where its value comes from,
and that doesn't change behind the operator's back when an ACL comes or goes. A plain link to a file
wicket can't read fails, and the error says to use the helper.

A Remote Control box (`agent.remote`) also uses non-secret fields of the login object (scopes,
plan) that wicket reads from the file when the box starts. Through the helper it can't, so those
boxes start without them; the account fields kept at link time still need `~/.claude.json` readable
for the link ([secrets reference](../reference/secrets.md#what-a-link-keeps-besides-the-reference)).

## When a model call can't read its secret

The model proxy reads its secret again for up to 3 seconds when it can't (the file is being
rewritten, or the helper is restarting). If it still can't, the call gets a `503` naming the secret
and the cause, for example:

```text
secret "claude-oauth" could not be read (16 tries): the secret helper for secret claude-oauth isn't reachable at @wicket-secret.1000 (...)
```

`wicket doctor` checks every linked secret the same way.

## Use it in a zone

```yaml
zone:
  inject:
    - { host: api.github.com, header: Authorization, format: "Bearer {secret}", secret: github-ro }
    - { host: github.com, header: Authorization, format: "Basic {basic:x-access-token}", secret: github-ro }
  llm: { secret: claude-oauth }
```

- The credential goes in exactly the one `header`, toward exactly that `host`, and only over HTTPS:
  plain HTTP to a host with a credential is refused.
- `{basic:USER}` renders an HTTP Basic credential with the secret as password: git over HTTPS with a
  token.
- `optional: true` sends requests without it if the secret isn't set, instead of refusing to start.
- Running boxes follow the vault: a secret set, rotated or removed after a box started is used, or
  left out, from its next request, with no restart (on a remote node within about 2 s). A required
  rule whose secret is removed fails its host's requests until it is set again.
- A manifest that injects a secret toward a host outside its binding, or points `llm.upstream` at
  another host, is refused, and the proxies check again before sending.

The [manifest reference](../reference/manifest.md#inject) has every field.

## See, rebind and remove

```sh
wicket secret list                                  # names and where each may go, never values
wicket secret hosts github-ro --hosts api.github.com,github.com   # replace its hosts
wicket secret remove github-ro
```

`secret remove` of a linked secret removes only the reference. Nodes holding a copy delete it when their
run's lease next reaches them, within seconds while connected.

## From the console

The console's *Secrets* section does the same from a browser or a phone, each change signed with
your passkey ([console reference](../reference/console.md#secrets)):

- **New secret…** (or **Set…** beside a name a manifest uses that isn't stored yet): type the name,
  the value and the hosts, then sign. The value field shows nothing and is cleared when you submit;
  your passkey signs a salted hash of the value, and the value goes to the console only when you
  sign. It is never shown again, anywhere.
- **Replace value…** stores a new value; empty hosts keep the ones it had. Running boxes use the
  new value from their next request.
- **Hosts…** replaces the hosts a secret may be sent to, as `wicket secret hosts`.
- **Delete…** first lists the zones and running runs that use it, then asks you to sign.

Each secret shows its kind, hosts, when it was last set, and where it is used (each injection's
host, header and format). Linking a file (`wicket secret link`) stays on the host, because it names
a path there: the console lists linked secrets and can change their hosts or remove the link.

## On nodes

A node fetches a secret only when one of its runs first needs it, keeps it in memory only, and drops
it when the last run using it ends, when its upstream expiry passes, or when the control host says it
changed, was rebound or was removed. `wicket node list` shows which secrets each node was given for
which run, by name. Root on a node can read what that node holds: see
[limits](../explanation/limits.md#remote-nodes).

## Model credentials

wicket never uses Anthropic API keys: the agent is Claude Code on the owner's subscription. Use a
token from `claude setup-token` (`wicket secret set claude-oauth`) or link the host's login as above.
The node is given the access token only, never the refresh token.
