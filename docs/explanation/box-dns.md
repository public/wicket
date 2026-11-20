# Names for boxes: internal and public DNS

Design for [#575](https://github.com/public/wicket/issues/575). Boxes run services (a dev server, a
demo, an API) that other boxes, and sometimes the internet, should reach under a stable name.
wicket manages the names, as Kubernetes does with Service DNS and external-dns. It runs no ingress
and no reverse proxy of its own.

This note is the design only. What is built is listed under [Steps](#steps).

## Rules this keeps

The rules of [one decision path](one-decision-path.md), applied to names:

- **The node decides at the edge.** Whether a name resolves in a box, and whether a connection to a
  published port is taken, is decided on the box's node, from its verified feed replica.
- **The control host only issues authority.** It records asks, takes a human's decision, allocates
  ports, publishes grants on the feed and writes DNS records. It decides no connection.
- **Nothing an agent says widens anything without a human.** An agent can ask for a name. Only a
  human makes a public name, and only within limits the operator set once.
- **Every name has a lifetime,** and a name without a live grant has no records and no open port.
- **Fail narrow.** A record wicket can't prove it owns is never touched. A port it can't prove is
  free is never handed out.

## Two kinds of name

| | internal | public |
|---|---|---|
| example | `api.build.wicket.internal` | `demo.boxes.example.com` |
| who resolves it | other boxes of the tenant, through wicket's in-box resolver | anyone, through public DNS |
| what it points at | a link address inside the resolving box | the public address of the node the box runs on |
| who decides a connection | the node, by links (#6): `accept_from`, children, or a human | the node: the name's grant is live and the box holds authority |
| what it widens | nothing: it is a name for `expose` | inbound reach from the internet, and an outbound channel (below) |
| who approves | nobody: within the operator's limits | a human, always |

### Internal names

An internal name is `<label>.<zone>.wicket.internal`: a label the box chose, under its zone's name
as it is, so only a zone whose name is already in DNS form holds names (`wicket_names::zone_part`;
#668: `Build` and `build`, or `web_api` and `web-api`, are different zones to `accept_from`, so no
zone name is mapped onto another's form).
Links today give `<name>.wicket.internal` (one label), so the two-label form can't collide with them.
Internal names are per tenant: a box never resolves another tenant's.

Registering one is `expose` with a name. It grants nothing, so it needs no approval, only room in
the operator's limit (names per workload). A label is unique within its zone, so a box can't take a
name in another zone.

Resolving it goes through `connect`, as built (step 3):

- **`connect(name: "<label>.<zone>")`** finds the run holding the name in the ledger and decides
  exactly as `connect` to that box decides (`wicket_core::link::connect`): its parent, a box the
  target's `accept_from` lists by zone or principal, or a human approving exactly that link. The
  port defaults to the name's.
- **The link is named after the name,** so the connecting box's hosts file (which wicket owns) maps
  `<label>.<zone>.wicket.internal` to the link's address from its pool (198.18.1.1–32), and the box
  resolves it like any linked name. Its in-box resolver (`wicket-proxy/src/dns.rs`, #92) is
  unchanged: it never answers a `.wicket.internal` name itself.
- **No name, or its holder isn't running:** `connect` says so. A box that never connected doesn't
  resolve the name.

So a name saves an agent finding the box's run id; whether it may connect is the link's decision, as
NetworkPolicy is to Service DNS in Kubernetes. A link across nodes still passes through the control
host as #6's links do.

**Direct, with nothing in between, is for public names.** Internal names are box-to-box traffic, and
box-to-box traffic always goes through a link: the control host decides it, and the box edge enforces
it (the link's listener in the box, the node's relay), whatever name the box used. A public record
is different: it points at the node's own address and the host port the service is published on,
with no proxy and no relay through the control host, only the node copying bytes into the box.

*Changed from the first version of this note:* it had the resolver answer a name, and the first
connection open the link, for a box that may connect by default. But `connect` is decided on the
control host, and a link's address, listener and hosts line are set up when it opens. A lookup that
opened links would put a control-host call, and a box exec, inside a DNS query, and would need the
names on the feed, while `connect` by name needs neither. That lookup can come later, on its own, if
agents need names without calling `connect`. Internal names are also run-scoped only: a box asks
again when it starts. Standing applies to public names, which need a human's approval each time.

A box in `filtered` or `direct` mode (§7.3, not built) would get the same answers from the node's
resolver on its veth. Nothing else changes for it.

### Public names

A public name is `<label>.<boxes domain>`: one label under a domain the operator gave wicket. It
gets an A record for the node's public IPv4 address, an AAAA record for its IPv6 address if it has
one, and an SRV record `_<service>._tcp.<label>.<boxes domain>` naming the published port.

The service is published on the node: a host port on the node's public address, which the node's
`wicket node serve` listens on. Each connection to it is dialed into the box at the box's own port,
as a link's far end is (`BoxOps::dial`), and the node copies bytes between them.

**That is a byte relay on the node, not a proxy.** Boxes have no network device (`--network none`,
and Docker on a node has no bridge), so a socket from outside can reach a box only through
something on the node. wicket doesn't terminate TLS on it, read HTTP, route by host name or pass
anything through the control host. The record points at the node the box runs on, so traffic goes
straight there. This is the one reading of "not proxied" that works with boxes without a network,
and it is the rule step 4c is held to:

- **Layer 4 only.** The node's listener is a pure byte relay into the box (or, for a box with a
  network device, a DNAT rule to it). It never terminates TLS, never parses HTTP or any other
  protocol, never routes by host name or SNI, and never passes a connection through the control
  host. What it decides is only whether to accept a connection (the name live, the box running, a
  connection limit) and whether to keep it.

## Asking and approving

A box asks with one gateway tool, `request_name`:

```json
{ "name": "demo", "kind": "public", "port": 3000, "service": "http", "reason": "the demo for the review" }
```

- `kind`: `internal` or `public`.
- `port`: the box's own port, 1–65535. TCP only at first; UDP (HTTP/3, games) is a later step.
- `service`: the SRV service label (`http`, `https`, …), public names only.
- `scope`: `run` (default: this run only) or `standing` (every later run of the workload, as #572).
  Public names only: an internal name is always the run's.

**Internal names** are registered at once if the label is valid, free in the zone and within the
workload's limit. The answer says the name. Audited `name.registered`.

**Public names** are a pending request of a new reserved kind, `name`, with an effect descriptor
([approvals bound to their effect](approvals-bound-to-effects.md)):

| kind | target (the op's path) | arguments hashed |
|---|---|---|
| `name` | `/names/<tenant>/<fqdn>` | the label, kind, box port, service, the zone digest |

The operator sees, in `wicket names show` and on the console's card:

- the full name, the box port, the asking run, its zone and principal;
- **"Anyone on the internet can connect to this box's port 3000 and read what it serves."** A public
  port is an outbound channel: an agent can serve anything it holds to anyone who connects. So the
  card says what the zone holds that could leak (private repositories, confidential volumes, tenant
  data), as approval cards do for `direct` mode, and a zone the org policy marks confidential can't
  be given a public name at all;
- the nodes the box may run on that can publish (below);
- for a standing ask, the evidence and terms as `wicket standing` shows them.

A human approves with a passkey (console) or `wicket names approve` (`deny`). No agent's `decide`
can approve a public name, as no agent approves standing reach.

**Standing names reuse standing reach (#572)** where it fits. A standing ask is a row with the same
life (pending, approved or denied, revoked, lapsed), bound to the agent's principal or its zone
(`Bound`), and to the zone's digest, so a manifest that reuses the zone's name with other reach
doesn't inherit it. It lasts 30 days by default (`--lasts`), or until revoked. Each later run of
the workload gets the name back when it starts, without asking. What differs from a reach rule: a
name is exclusive. While a standing name is approved, nobody else gets the label, even while no run
holds it.

A run-scoped name ends with the run.

## Name rules

Checked on the control host when asked, and again on the node when it reads the name from the feed.

- **One DNS label:** 1–63 characters of `a-z`, `0-9` and `-`, lowercase, not starting or ending with
  `-`. No dots, so a name can't sit under another name. No `*`, no `_`.
- **No IDNs:** a label starting `xn--` is refused, unless the operator allows them.
- **Reserved:** `wicket`, `console`, `www`, `api`, `admin`, `mail`, `ns`, any label the operator
  lists, the first label of the console's host name, and any label whose ASCII skeleton matches one
  of these. The skeleton folds `0`→`o`, `1`→`l`, `i`→`l`, `5`→`s`, `rn`→`m`, `vv`→`w` and drops `-`,
  so `c0nsole`, `conso1e` and `con-sole` are refused.
- **Unique:** an internal label per zone and tenant; a public label per installation. Two asks for one
  public label: the first approved takes it, and the other is refused with "taken".
- **Limits:** names per workload (default 3 internal, 1 public) and the TTL (default 60 s, operator's
  range 30–3600 s) come from the operator's config. No ask sets a TTL.

## What the operator sets once

A new section of `wicket.yaml`, since these are installation decisions, not a manifest's:

```yaml
names:
  internal:
    per_workload: 3
  public:
    provider: noop               # noop now; vultr and rfc2136 with step 5 (later: cloudflare, route53)
    zone: boxes.example.com      # a delegated subzone is recommended: wicket's credential then touches nothing else
    credential: dns-boxes        # a vault secret's name; never its value
    owner: a1b2c3d4              # this installation's owner id, random, made at install
    ttl: 60
    per_workload: 1
    reserved: [status, docs]
    console_host: console.example.com  # its first label is reserved too
    nodes: { publish: "true" }   # node labels a node needs to publish public ports
    ports: 20000-20999           # the host ports wicket allocates on each node
```

Every part of the section is optional: without `names.public` the installation publishes no names,
and asks for them are refused. The section is checked when a run starts ([configuration
reference](../reference/configuration.md#wicketyaml)); a human's approval is decided under it as it
is then.

Each node that publishes also has its public addresses in the ledger, set by the operator
(new flags: `wicket node set n1 --public-ipv4 … --public-ipv6 …`) or read from the placement provider for a
node it created (Vultr's instance record). **Never from the node itself:** a node that could name
its own address could point a name at someone else's server.

## Host ports

- **Allocated by the control host when a public name is granted,** from the node's range. The ledger
  holds `(node, protocol, port)` unique, so two boxes on one node never get one port. This is
  issuance: the port is part of the grant, published on the feed.
- **Bound by the node,** which refuses a port outside its configured range or one it didn't get from
  the feed. It listens while the name's grant is live and the box holds authority, and checks both
  every 2 s, as a link on one node does (`listen_direct`). Revoke closes the listener and drops its
  connections at once, before DNS catches up.
- **Sticky:** a name keeps its port while it is granted, and a box that moves gets the same port on
  the new node if it is free there. Otherwise a new one, and the SRV record follows.
- **Quarantined after release.** A port a name gave up isn't handed out again on that node until its
  records are gone and twice the TTL has passed. Otherwise a cached record for the old name would
  reach the new box. The reconciler frees it: once the ledger lists none of the name's records, the
  port is free twice the TTL from then.
- **Ports below 1024** (80, 443) only where the operator allows them on a node, for one name each,
  since a node has one port 443. Sharing 443 between boxes needs routing by TLS server name, which
  is ingress: not in this design. See [open questions](#open-questions).

**As built (step 4c).** The run's supervisor allocates a port for each live public name its box
holds that may be published on its node (the same check as the reconciler's: labels, addresses,
domain, label rules), from `names.public.ports`, keeping the port the name had on another node if it
is free here and releasing that one. It puts them in the box's record (`ports`) for a node at
protocol 21. The node publishes from its replica alone, every 2 s, so it works offline and across
restarts: a port in its range (`publish.json` in its directory, written by `wicket node install` for
a node with the `names.public.nodes` labels; without it the node publishes nothing), unexpired,
claimed by one box, whose authority holds on the node. It listens on one IPv6 socket that takes
IPv4 too, and dials each connection into the box (`wicket-fwd`), at most 64 at once per name. A port
that stops being published closes within 2 s of the node's feed saying so, with its connections,
before DNS catches up; a node cut off from its control host can't hear of a revoke, and closes the
port when the box's authority or the name's end passes. **Layer 4
only:** the node never terminates TLS, reads a protocol, or routes by name; nothing passes through
the control host.

## The node firewall

A node's firewall is the operator's. wicket asks it for one thing: admit the node's port range from
anywhere. Inside the
range a port is open only while wicket listens on it, so a revoked name is closed by the node
itself, not by a firewall change that might fail. `node-setup.sh` adds the rule when given the range
(`WICKET_PUBLISH_PORTS=20000-20999`, the same as `names.public.ports`). `wicket node serve` runs unprivileged and changes
no firewall rules.

Each connection to a published port is checked as it is accepted (grant live, box running, the
per-name connection limit not reached) and audited when it ends: the name, the peer address, bytes
each way, and how long it lasted. wicket can't see requests inside it.

## IPv6

Boxes have no network of their own, so IPv6 is the node's alone. The node listens on its IPv6
address too when it has one, on the same port, and the name gets an AAAA record. A node with only
IPv6 gets only AAAA. The internal resolver keeps answering AAAA with no data, as now (#92).

## Nodes behind NAT or a reverse tunnel

- **No public address in the ledger:** the node can't publish. Placement doesn't put a box that holds
  a public name there (the `publish` label), and a standing name waits for a run on a node that can.
- **NAT with a fixed forward:** the operator sets the router's public address as the node's and
  forwards the node's port range one to one. To wicket it is then a node with a public address.
- **A reverse tunnel** (the node dials out to a relay that accepts connections for it) is a relay,
  which this design leaves out. It could be a provider later: the record would be a CNAME to the
  tunnel's host, and the tunnel would be the operator's, not wicket's.

## Records and reconciliation

wicket owns records the way external-dns does: it reconciles the records it owns, and never touches
one it doesn't.

- **The desired state is the ledger's:** for each live public name held by a running box, its A,
  AAAA and SRV records for that box's node, and its owner record. The node must carry the labels
  `names.public.nodes` asks for and have public addresses; until then the name is *waiting*, with
  why, and has no records. So does a name without a host port on that node (step 4c: its run's
  supervisor gives it one, on a node at protocol 21): an address with nothing listening would reach
  nobody, or, once the port is someone else's, the wrong box.
- **What the noop provider does:** it lists an empty zone and applies nothing, so the reconciler
  records nothing in `name_records` (the ledger never claims a record that isn't there), and audits
  each new plan as `name.plan` with `applied: false`. The same plan pass after pass is recorded once.
- **The owner record** is a TXT at `_wicket.<label>.<zone>`:
  `"wicket-owner=<owner id>;name=<grant id>"`. It sits beside the name, not on it, so the name can
  later be a CNAME. The owner id is random, made at install: no host name or other detail in it.
- **A record is wicket's only if both** the ledger lists it as created by this installation
  (`name_records`) and its owner TXT carries this installation's owner id. A record either side
  doesn't vouch for is never changed or deleted.
- **The reconciler** (`wicket reconcile`; `wicket_control::namesync`) lists the zone, compares it
  with the desired state, and applies the difference: create, update or delete owned records. A name
  that exists in the zone without wicket's owner record is a conflict: wicket leaves it, the name's
  grant shows "taken in the zone", and the conflict is audited. It is never adopted on its own.
- **Order:** an owner record is written before the records it owns, and deleted after them, so a
  crash between the two leaves an owner record for nothing (cleaned on the next pass), never an
  unowned A record. The ledger records a plan's new records, and an intent per change, in one write
  before the provider applies it; a provider whose apply isn't atomic says how far it got, and only
  those changes count as made.
- **Every zone with records** (#748): a pass also withdraws the records of a zone that isn't the
  configured one (after a zone change), with the provider that made them. Records another provider
  made (after a provider change, or with `names.public` removed) are *stranded*: the pass says so
  each time until the setting is put back, and never forgets them.
- **Records gone from the zone** (deleted by hand, or never made because of a crash) are forgotten
  once listings by the provider that made them have lacked them for 10 minutes or more (the first
  such listing notes when; one that has them again clears it), so they hold no name's port. A
  listing that lacks every record the provider made in the zone forgets none, and the pass says so.
  A provider's `Ok` listing is the whole zone; its id names its account, and each provider's rows
  are its own: none writes over, plans on or forgets another's.
- **Links by name:** a name that ends closes the links other boxes opened with `connect` by it.
- **One address, one node:** names on two nodes that share a public address wait, since host ports
  are allocated per node.
- **Lifecycle:** a name's records go when its grant ends, is revoked or lapses, or its run stops.
  A standing name's come back when its workload runs again. A box moving to another node has its A
  and AAAA updated to that node's addresses (and its SRV if the port changed).
- **Dangling records.** A node being destroyed (`wicket node release`, a lease's end) first has every
  record pointing at it removed, and placement waits for that before it releases the instance, since
  a cloud reuses its address for someone else's server. If the removal fails, the node is destroyed
  anyway (money first), and the reconciler keeps retrying and reports it.

## Providers

One trait, chosen by `names.public.provider`. The plan is wicket's, so a provider only lists and
applies:

```rust
pub trait DnsProvider: Send + Sync {
    /// What it supports: record types, the lowest TTL, whether `apply` is atomic.
    fn caps(&self) -> Caps;
    /// Every record in the zone, or under one name.
    async fn list(&self, zone: &Zone) -> Result<Vec<Record>>;
    /// Applies a plan wicket computed (creates, updates, deletes of records it owns).
    async fn apply(&self, zone: &Zone, plan: &Plan) -> Result<Applied>;
}
```

`Plan` is computed by one function, from the desired records, the zone's records and the ledger's
owned set, and it is what the property tests check: whatever the zone holds, a plan never updates or
deletes a record wicket doesn't own, and applying it makes the owned records the desired ones.

- **`noop` first:** it lists nothing, applies nothing and reports the plan it was given, audited as
  `name.plan` with `applied: false`. It lets an operator see what wicket would do before giving it a
  credential, and is what tests and the simulation use.
- **Then `vultr`** (its DNS API; most nodes run on Vultr now) **and `rfc2136`** (dynamic update with
  TSIG, for self-hosted servers such as BIND, Knot or PowerDNS, and the static hosts).
- **Later:** Cloudflare and Route 53, each one more implementation of the trait.

A provider runs on the control host, in the reconciler. Nodes never hold a DNS credential.

## Credentials

The provider's credential is a vault secret like any other (`wicket secret set dns-boxes`), its
`.hosts` file limited to the provider's API host. The reconciler fetches it from the vault when it
runs. It never goes to a node or a box, and never on the feed. Use a credential scoped to the
boxes zone where the provider has them (a TSIG key allowed only that zone, a Cloudflare token for
one zone).

## Certificates the box gets itself

A box that wants its own certificate for its public name (it terminates its own TLS, since wicket
doesn't) can get one by DNS-01: a gateway tool, `dns_challenge(name, value)`, makes
`_acme-challenge.<label>.<zone>` TXT with that value, for 10 minutes, removed after.

- Only for a public name the box holds, and only that one TXT name: the value is the only thing the
  box chooses, and it is checked to be an ACME key authorization digest (43 base64url characters).
- No approval beyond the name's: a certificate for a name the box already serves adds no reach.
- Audited `name.challenge`. The box reaches the ACME server through egress as any host, so its zone
  needs it.

## Audit and console

Audit records, as written so far: `name.requested` (an ask), `decision` and `decision.refused` (a
human's approval or denial, or a refused one, as for other asks), `name.registered` (internal),
`name.revoked`, `name.released`, `name.claimed` (a later run took up a standing name),
`node.addresses` (an operator set a node's public addresses), and the reconciler's (step 4b):
`name.lapsed` (a name's lifetime ended), `name.plan` (a reconcile's plans for every zone, applied or
not, with the stranded records and the names waiting, recorded when it differs from the last one),
`name.record` (each create, update or delete a provider is about to make, `state: intended`, and
each record forgotten, `state: forgotten`), `name.applied` (how a provider's apply ended, and how
many changes it made) and `name.conflict`. The node's (step 4c, shipped as node audit records):
`name.port.opened`, `name.port.closed` (with why), `name.port.failed` (a port it couldn't bind, or
one two boxes claim, recorded once), `name.conn` (per connection: the peer, bytes each way, how
long) and `name.conn.refused` (connections over the per-name limit, counted each tick). Still to
come with step 6: `name.challenge`.

`wicket names list` and the console's **Names** card list every name: kind, full name, owner (the
principal, zone and run), target (node, address, host port and box port), state (pending, live,
waiting for a run, taken in the zone, records out of sync) and when it lapses. The card approves or
denies public asks (passkey-signed, bound to the effect), and renews or revokes. `wicket names show`
has a name's records as the zone last listed them, and its last connections.

## Data and protocol

- **Ledger schema 28:** `names` (one row per name through its life: tenant, zone, zone digest,
  principal, run, label, kind, box port, service, status, bound, expiry, effect hash, decided and
  revoked by), `name_records` (the records this installation created: zone, name, type, value,
  provider, created, last seen) and `host_ports` (`node`, protocol, port unique; the name holding it,
  released at).
- **Ledger schema 31** (#668): `name_exposures`, the ports a run's names exposed (not the box
  itself), which a name's move may take away once no other name of the run names the port.
- **Ledger schema 34** (step 4b): `node_addresses`, each node's public addresses as its operator set
  them (`wicket node set --public-ipv4 … --public-ipv6 …`), audited `node.addresses`. They are
  deleted when the node is revoked or enrolled again (its address may be someone else's by then),
  are set only on an active node, and are one node's each, since host ports are allocated per
  node. Also `names.domain`: the boxes domain a public name was approved under, so a change of
  `names.public.zone` doesn't move live names into a zone nobody approved them in.
- **Protocol 18:** `request_name` is a control-host tool (`ControlTool::RequestName`), asked by a
  node only of a control host at 18.
- **Protocol 21** (step 4c): a box's record in the feed carries its public names' host ports
  (`BoxAuthority.ports`: the name, its label, the host port, the box's port, until), omitted when
  there are none, and sent only to a node at 21. A port the node can't bind is a node audit record
  (`name.port.failed`), not a message of its own.
- **Ledger schema 43** (#748): `name_records.missing_since`, when a listing first lacked a record.

## Steps

1. This note.
2. The provider trait, the `noop` provider and the plan function, in their own crate
   (`wicket-names`), with property tests for ownership.
3. Ledger schema 28 (#658); `request_name` for internal names, `connect` by name, protocol 18.
4. Public names, in four parts:
   - 4a: the ask (`request_name` with `kind: public`), the human decision (`wicket names`, the
     operators' `name` kind) and `await_grant` on it;
   - 4b: the installation's `names:` config, node public addresses, and the reconciler with the
     `noop` provider;
   - 4c: host ports, published on the feed, and the node's listener (built: below);
   - 4d: the console's Names card.
5. The `vultr` and `rfc2136` providers.
6. DNS-01 challenges.

Done when (from the issue): a box asks for `demo.<boxes domain>` → its port 3000, the operator
approves once, the public record points at its node and the service answers there directly; another
box resolves its internal name; revoking removes both records.

## Open questions

- **"Not proxied"**: the node's byte relay above is the only way into a box without a network.
  Confirm it is what was meant.
- **Port 443 shared by name:** routing by the TLS server name without terminating would let many
  boxes share 443 on a node. It is ingress in all but name; left out unless the owner wants it.
- **UDP** (HTTP/3 to a box): the node would relay datagrams; a later step.
- **The client's address:** a box sees connections from the node's relay. An opt-in PROXY protocol
  v2 header would pass it on.
