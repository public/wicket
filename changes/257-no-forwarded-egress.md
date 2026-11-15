---
area: Nodes
type: Changed
---
- A node no longer forwards any egress to the control host. This is the third step of
  [#257](https://github.com/public/wicket/issues/257), one decision path. Some hosts are outside
  the node CA's name constraints, for example one approved later under
  `unlisted_hosts: escalate`. There is also every host on a node with no live CA. The node splices
  such a host through when the box's token allows it wholesale, and refuses it otherwise with a
  403: `Blocked by wicket sandbox: host not served on this node`. Before, the node tunnelled such
  hosts to the run's egress proxy on the control host. To serve one, widen the node's CA with
  `wicket node renew-ca <node> --hosts …`. Plain `http://` needs no certificate, so the node now
  decides it whatever its CA covers.
- The control host decides no request. Its run no longer listens on `ctl/egress.sock`, and a
  node's tunnel to `egress` is refused. The ledger records each grant, its renewals and its
  revocation, and every egress grant is published to the box's node, which alone counts its uses.
  Some grants can't be honoured on a node as approved: one with a risk bound that a query could
  exceed (#119), or one the box's token can't carry. Such a grant is not published, so the box's
  request is asked again.
- Egress lines: a refused uncovered host is now a `forbidden` line, `not served on this node
  (<why>)`, where it was a `FORWARD` one. The control host's own `grant …; used by …` details are
  gone with it. A grant use on the node reads `(counted on the node)`, as before. Audit records
  are unchanged.
- Protocol 11. A box goes only to a node talking protocol 11 or later if an older node would
  forward one of its hosts: its zone reaches, injects into or swaps a credential for a host outside
  that node's CA, or the node has no live CA. An older node is refused, with a message saying to
  update it (`wicket node install <node>`).
