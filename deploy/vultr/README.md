# Running wicket boxes on a Vultr node

`node-setup.sh` prepares a fresh Ubuntu 24.04 machine (on Vultr or anywhere else) as a wicket node:
Docker with no bridge or firewall rules of its own, gVisor registered as `runsc`, and an unprivileged
`wicket` user that the control host logs in as, with lingering enabled so its `wicket-node` service
runs without a login.

```sh
ssh root@NODE 'bash -s' < deploy/vultr/node-setup.sh
```

Then enrol the node, install wicket there and run boxes on it:
[add a remote node](../../docs/how-to/add-a-remote-node.md). `wicket place create` does all of it on
Vultr in one step, with the node's host key pinned at creation:
[place nodes on Vultr](../../docs/how-to/place-nodes-on-vultr.md).

A node is trusted with the boxes it serves: it terminates their TLS and holds, in memory only, the
secrets its runs use ([limits](../../docs/explanation/limits.md#remote-nodes)). Before destroying a
node by hand, revoke it (`wicket node revoke NAME`); `wicket place release` does both.
