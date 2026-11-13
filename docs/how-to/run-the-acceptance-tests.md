# Run the acceptance tests

`ci/acceptance.sh` runs wicket's main flows against the real image, gVisor and Docker, with the
scripted mock model (no model credential), checks each outcome, prints a summary and tears
everything down, on failure too. It covers:

- an agent's egress, over HTTP/1.1 and HTTP/3, in reach and out of it;
- one request approved and one denied;
- `spawn` of a narrower zone, and of a wider one with `ask_human`;
- a `link` between two boxes and a fetch across it;
- revoking the agent and its whole subtree;
- hibernate and wake;
- an orphaned box stopped by `wicket reconcile`;
- `wicket audit --verify`, with an export to a JSON-lines sink checked by `--against`.

```sh
ci/acceptance.sh                    # development mode: this checkout's binary, fresh data, boxes named acc-*
ci/acceptance.sh --nodes local      # and the multi-host flow: a capacity lease on localhost as a node
                                    # (the static backend), a box there, ci/node-e2e.sh, revoke, reconcile
ci/acceptance.sh --installed        # as an operator, against an installed system (wicketd, sudo wicket)
ci/install-acceptance.sh            # --installed against deploy/install.sh in a fresh container
ACC_VULTR=yes ci/acceptance.sh --nodes vultr   # a fresh Vultr node (spends money; see the script's header)
```

The multi-host flow also links the agent's box on the control host to the box on the node and
fetches a page across the link.

You need Linux with Docker and gVisor registered as `runsc` with `--host-uds=open`. Each script's
header lists its environment variables (`WICKET`, `IMAGE` and the like).

Narrower checks:

| script | checks |
|---|---|
| `ci/smoke.sh` | one agent in a gVisor box, end to end, with the mock model (CI runs it) |
| `ci/hibernate.sh [--node]` | hibernate and wake, on this host or an enrolled node |
| `ci/node-e2e.sh --local\|<node>` | a box working on its grants while its node is cut off |
| `ci/update.sh` | `wicket self update`, its health gate and automatic rollback |
| `ci/restore.sh` | the state store and a restore, against a local S3 gateway |
| `examples/links/demo.sh` | links between boxes |
| `ci/check-public.py`, `ci/check-doc-links.sh` | no secrets or machine details; no broken relative links in Markdown |
| `ci/gen-cli-reference.sh --check` | `docs/reference/cli.md` matches the commands' `--help` |
