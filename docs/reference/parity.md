# Console and CLI parity

Every operator action belongs in both the [console](console.md) and the [CLI](cli.md), unless
there's a stated reason it can't be (#713). This page lists where each action is today. Host-only is
the exception: it's for actions on files or processes on the control host, and for bootstrapping
trust before any passkey exists. A gap that is still to be filled says "none yet" and names its
issue.

Each side applies its own authority check. The console signs a changing action with a passkey. A
decision is checked against that operator's `operators.yaml` authority: for most actions before the
passkey is asked for, and for a capacity grant or its renewal when the signed action is applied
(refused then, and audited). The CLI runs
as a host user: `wicketd` sorts each command into a class (read, run, revoke or privileged; see the
[daemon](daemon.md)), and a decision is also checked against that operator's `operators.yaml`
authority. Both sides go through the same functions and write the same audit records. A
console-signed record also keeps its signature (`wicket audit --verify` checks it).

## Requests, grants and standing reach

| Action | Console | CLI |
| --- | --- | --- |
| List pending requests, standing asks and name asks | `/api/state` (`pending`) | `wicket pending` |
| Approve or deny a request | `decide` | `wicket approve`, `wicket deny` |
| List grants | `/api/state` (`decided`: the last 15 decisions) | `wicket grant list` |
| Renew a grant or a box's authority | none yet (#713) | `wicket grant renew` |
| Revoke a grant | none yet (#713); a capacity grant: `/api/capacity/revoke` | `wicket grant revoke` |
| Issue a capacity grant | `capacity_grant` | `wicket capacity grant` |
| Renew a capacity grant | `capacity_renew` | `wicket capacity renew` (or `wicket grant renew`) |
| Revoke a capacity grant | `/api/capacity/revoke` | `wicket capacity revoke` (or `wicket grant revoke`) |
| List capacity grants | `/api/state` (`capacity`) | `wicket capacity list` |
| Approve, deny or renew standing reach | `standing_approve`, `standing_deny`, `standing_renew` | `wicket standing approve`, `deny`, `renew` |
| Revoke standing reach | `/api/standing/revoke` | `wicket standing revoke` |
| List or show standing reach | `/api/state` (`standing`) | `wicket standing list`, `show` |

## Names

| Action | Console | CLI |
| --- | --- | --- |
| List names, or show one | `/api/names`, `/api/names/<id>` | `wicket names list`, `show` |
| Approve or deny a public name | `name_approve`, `name_deny` | `wicket names approve`, `deny` |
| Renew a standing name | `name_renew` | `wicket names renew` |
| Revoke a name | `name_revoke` | `wicket names revoke` |
| Set a node's public addresses | `node_addresses` | `wicket node set --public-ipv4`, `--public-ipv6` |

## Runs and agents

| Action | Console | CLI |
| --- | --- | --- |
| Start a run from a manifest | `start_run` | `wicket run` |
| Open a run's session | `open_session` (the session page) | `wicket session` |
| Revoke a run's identity | `revoke` | `wicket identity revoke` |
| List runs and agents | `/api/state` (`runs`: the last 15) | `wicket agents`, `wicket top` |
| A run's authority now | `/api/runs/<run>/authority` | `wicket authority` |
| Explain an activity record's decision | `/api/explain/<seq>` | `wicket audit explain` |
| Why a run went where it did | `/api/runs/<run>/placement` | `wicket why-here` |
| Send an agent a message | `send_message` | `wicket message send` |
| Read your inbox, receipts and who you may write to | `/api/messages`, `/api/messages/read` | `wicket message inbox`, `receipts`, `principals` |
| Hibernate an agent | none yet (#713) | `wicket hibernate` (a message, or `wicket session`, wakes it) |
| Create, pause, resume, renew, fire or remove a trigger, or rotate its URL | none yet (#713) | `wicket trigger …` |
| List or show triggers | none yet (#713) | `wicket trigger list`, `show` |
| Cut a link between boxes | none yet (#713) | `wicket unlink` |
| List links | none yet (#713) | `wicket links` |

## Manifests and policy

| Action | Console | CLI |
| --- | --- | --- |
| View a manifest, with its effective values and policy | `/api/manifests/<root>/<name>` | `wicket zone` (its hosts); the rest: none yet (#713) |
| Check an edited manifest against the saved one | `/api/manifests/check` | none yet (#713) |
| Save or restore a manifest version | `save_manifest`, `restore_manifest` | none yet (#713): editing the file on the host keeps no history and isn't audited |
| Pin a manifest's images by digest | none yet (#713) | `wicket zone pin` |
| View the org policy, its versions and the runs under each | `/api/policy` | `wicket policy show` (its version and the runs); the versions' Cedar: none yet (#713) |
| Preview or apply an org policy | `/api/policy/preview`, `policy_apply` | `wicket policy apply --dry-run`, `wicket policy apply` |
| Check an org policy without applying it | `/api/policy/preview` (it validates and compiles it) | `wicket policy check` |
| A manifest's zone policy as Cedar | a running run's: `/api/runs/<run>/authority` (`zone_cedar`); a manifest's: none yet (#713) | `wicket policy zone` |

## Secrets

| Action | Console | CLI |
| --- | --- | --- |
| List secrets by name | `/api/state` (`secrets`) | `wicket secret list` |
| Set a secret | `set_secret` | `wicket secret set` |
| Bind a secret to hosts | `secret_hosts` | `wicket secret hosts` |
| Remove a secret | `delete_secret` | `wicket secret remove` |
| Make a secret a trigger's verify secret | none yet (#713) | `wicket secret verify` |
| Link a secret to a file | host-only: it is a file on the host, which the wicket user reads | `wicket secret link`, `wicket secret serve` |

## Nodes and placement

| Action | Console | CLI |
| --- | --- | --- |
| List nodes | `/api/state` (`placed`: nodes `wicket node create` made); the rest: none yet (#713) | `wicket node list` |
| A node's CA: hosts, policy, wants and widenings | `/api/nodes/<node>/ca` | `wicket node ca` |
| Release a node `wicket node create` made | `node_release` | `wicket node release` |
| Release a run's fence on a lost node | `release_fence` | `wicket node release-fence` (root only) |
| List runs fenced on lost nodes | `/api/state` (`fenced`) | none yet (#713) |
| Create a node from a provider, or list its plans | none yet (#713) | `wicket node create`, `wicket node plans` |
| Make a join token, enrol, revoke or forget a node, or renew its CA | none yet (#713) | `wicket node token`, `enrol`, `revoke`, `forget`, `renew-ca` |
| Set a node's CA hosts, labels or taints | none yet (#713) | `wicket node set` |
| List or release capacity leases | a lease's request in `/api/state` (`pending`); releasing one: none yet (#713) | `wicket lease list`, `wicket lease release` |
| List, add or remove per-node services | none yet (#713) | `wicket service list`, `add`, `remove` |
| Make what exists agree with the ledger now | none yet (#713): the reconciler runs as a service | `wicket reconcile` |
| Install a node, or serve it | host-only: runs on the node, as root over ssh or under systemd | `wicket node install`, `serve`, `intake`, `top` |
| Keep a node feed's checkpoint across a rollback | host-only: part of an update on the host | `wicket node feed-checkpoint` |

## Operators and the console

| Action | Console | CLI |
| --- | --- | --- |
| Enrol another passkey | `enrol_link` | `wicket operator enrol-link` |
| Enrol the first passkey | host-only: no passkey exists yet, so nothing can sign | `wicket serve` prints its link, or `wicket operator enrol-link` |
| List passkeys | `/api/state` (`passkeys`) | `wicket operator list` |
| Revoke every passkey | host-only: the break-glass for a lost or stolen passkey | `wicket operator reset` |
| Sign out | `/api/logout` | not applicable: the CLI has no session |
| List console sessions, or end one | none yet (#713); signing out ends your own | `wicket operator sessions`, `revoke-session` |
| Turn notifications on a device on or off | `push_subscribe`, `/api/push/remove`, `push_details` | not applicable: a browser's push subscription |

## The installation

| Action | Console | CLI |
| --- | --- | --- |
| See the audit log | `/api/state` (`audit`: the last 40 records) | `wicket audit` |
| Verify the audit chain and signatures | none yet (#713) | `wicket audit --verify` |
| Audit retention against its limit | `/api/state` (`audit_retention`) | `wicket top` |
| Compact the ledger, or feed the audit sinks | host-only: compacting needs wicketd stopped; a sink is a process on the host | `wicket audit compact`, `wicket audit export` |
| Health | `/api/state` (`health`) | `wicket top`, `wicket doctor` |
| Set up the identity issuer | host-only: bootstraps trust | `wicket identity init` |
| Show or list identities, or the issuer key | none yet (#713) | `wicket identity show`, `list`, `issuer` |
| Approve an agent's update request | `decide` (installs the build it names) | `wicket approve`, or `wicket self apply-update` |
| Update, roll back, prune, or trust an update key | host-only: installs binaries and units on the host | `wicket self …` |
| State store: replicate, snapshot, restore, recovery kit | host-only: for recovering when the control host is gone | `wicket state …` |
| The authority's root keys | host-only: the offline root stays off the network | `wicket keys …` |
| Build the agent image, or digest an image or program | host-only: the host's Docker and files | `wicket image`, `wicket program digest` |
| Run a command in a box from the host's shell | host-only: wraps a local process | `wicket wrap` |
| Run the console, the daemon or development helpers | host-only: processes on the host | `wicket serve`, `wicket daemon`, `wicket dev` |
