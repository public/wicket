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
`claude-oauth` defaults to `api.anthropic.com`. Without `--hosts`, `secret set` keeps the hosts the
secret already had.

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
owner: to share an owner-only file with it, grant it read with an ACL
([secrets reference](../reference/secrets.md#let-the-wicket-user-read-a-linked-file)).

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
- A manifest that injects a secret toward a host outside its binding, or points `llm.upstream` at
  another host, is refused, and the proxies check again before sending.

The [manifest reference](../reference/manifest.md#inject) has every field.

## See, rebind and remove

```sh
wicket secret list                                  # names and where each may go, never values
wicket secret hosts github-ro --hosts api.github.com,github.com   # replace its hosts
wicket secret rm github-ro
```

`secret rm` of a linked secret removes only the reference. Nodes holding a copy delete it when their
run's lease next reaches them, within seconds while connected.

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
