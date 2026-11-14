# Place nodes on Vultr

Have wicket create nodes on Vultr inside a money envelope, by hand (`wicket place`) or for agents
that ask (`request_capacity` and leases). [Nodes](../reference/nodes.md#provisioning-nodes-wicket-place)
has the rules; this page is the recipe. On an installed control host, run these commands with
`sudo`.

Vultr provisioning has been tested against fakes of the API; the live API, and a child running on a
leased node, haven't been run end to end yet ([limits](../explanation/limits.md#built-not-yet-run-live)).

## 1. Store the API key

```sh
wicket secret set vultr-api-key          # read from the terminal; only ever sent as the API's bearer token
```

You also need an ssh key in the Vultr account (its id) and its private half on the control host.
On an installed control host wicket reaches nodes as the `wicket` user, now and on every later run,
so keep the private half where that user can read it:

```sh
sudo install -d -o wicket -g wicket -m 0700 /var/lib/wicket/ssh
sudo -u wicket ssh-keygen -q -t ed25519 -N '' -C wicket-placement -f /var/lib/wicket/ssh/placement
sudo cat /var/lib/wicket/ssh/placement.pub   # add this public half to the Vultr account, note its id
```

`wicket place create` refuses a key it can't read before it creates anything, and asks for the spend
on the terminal you run it from (`sudo` passes it through wicketd).

## 2. Create a node by hand

```sh
wicket place plans --region lhr                     # plans and their hourly price
wicket place create --name n2 --region lhr --vcpus 1 --memory-mib 2048 --lifetime 1h \
    --max-hourly 0.05 --max-total 0.50 --ssh-key-id <id> --ssh-key /var/lib/wicket/ssh/placement \
    --hosts 'api.example.com'
```

- `--max-hourly` and `--max-total` are the envelope: every owned node's hourly rate together, and
  every owned node's cost through its lease plus the new node's worst case. Anything beyond it is
  refused; anything inside it still waits for `yes` on the terminal, with the plan, rate and worst
  case shown.
- Vultr bills per started hour, so a node's lease ends at minute 50 of its last hour.
- wicket generates the node's ssh host key, installs it through cloud-init as its only host key,
  pins it before the node boots, waits for `node-setup.sh` to finish, enrols the node and removes the
  key from the instance's user data. There is no trust on first use.
- A retried `create` with the same `--idempotency-key` (default: derived from `--name`) finds the
  first instance instead of making a second.

Then install wicket and the agent image on it, as for any node
([add a remote node](add-a-remote-node.md#3-install-wicket-and-the-agent-image-there)):

```sh
wicket node install n2
sudo -u wicket ssh -i /var/lib/wicket/ssh/placement wicket@<its address> '~/.local/bin/wicket image'
wicket run task.yaml --node n2
```

```sh
wicket place list                  # owned nodes, lease end and next paid hour
wicket place release <instance-id> # destroy now and revoke the enrolment
```

Only instances tagged `wicket-owner-<installation>` (`--owner`, default the trust domain) are listed
or destroyed; tag an instance `wicket-protected` to keep wicket's hands off it.

## 3. Leases for agents

An agent can ask for a machine of its own with the `request_capacity` tool. It gets a lease, never a
cloud credential.

1. Copy `examples/placement/placement.yaml` to `<data dir>/placement.yaml` (`/var/lib/wicket/` on an
   installed host) and set `backend: vultr`, the envelope (`max_hourly_usd`, `max_total_usd`), and
   the `vultr:` section (`region`, `ssh_key_ids`, `ssh_key`). `backend: static` uses your own
   enrolled machines instead. Every field is in [configuration](../reference/configuration.md#placementyaml).
2. Run the reconciler. Installed, the `wicket-reconcile` unit already runs `wicket reconcile --every
   1m`. In development mode run `wicket reconcile --every 30s` beside `wicket serve`.
3. Check it: `wicket doctor` reports the placement backend and whether the API key is set.

When an agent asks, the ask becomes a pending lease with its worst case reserved against the
envelope (an ask over budget is refused before you see it):

```sh
wicket pending                     # CAPACITY wicket.internal/capacity/l-…
wicket approve r-…                 # runs one reconcile pass at once: the node is created and enrolled
wicket lease list                  # status, holder run, node, reserved, end, billed
wicket lease release l-…           # end it now
```

The agent waits with `request_capacity {lease}`, then starts children there with `spawn` and
`placement: {"lease": "l-…"}`. At the lease's end, or when its holder run ends, what runs on the
node stops and the node is destroyed, before the next paid hour.

The reconciler installs wicket on a node it creates for a lease, but not the agent image: build it
there as above before boxes are placed on it.

## Afterwards

`wicket reconcile --dry-run` shows what one pass would change. Every change is an audit record
`reconcile.<what>`. Charges are wicket's own arithmetic; nothing compares them with Vultr's invoices
yet.
