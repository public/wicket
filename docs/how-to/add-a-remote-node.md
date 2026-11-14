# Add a remote node

Run boxes on another machine. The node runs Docker and gVisor and its own `wicket node serve`, which
runs the boxes and decides their egress from the signed policy feed, so they keep working while the
control host is unreachable ([concepts](../explanation/concepts.md#authority-biscuit-tokens-and-the-feed)).
[Nodes](../reference/nodes.md) has everything the node does. To have wicket create the machine on
Vultr as well, see [place nodes on Vultr](place-nodes-on-vultr.md).

You need a fresh Ubuntu 24.04 machine you can ssh to as root with a key on the control host, and its
ssh host key's fingerprint from somewhere other than the network (the provider's console, cloud-init
output, the image). On an installed control host, run the `wicket node …` commands with `sudo`.

## 1. Prepare the machine

```sh
ssh root@203.0.113.7 'bash -s' < deploy/vultr/node-setup.sh
```

`node-setup.sh` (it works on any Ubuntu 24.04 host, not only Vultr) installs Docker, with no bridge,
iptables or IP forwarding of its own, and gVisor from its signed repository, registered as `runsc`
with `--host-uds=open`. It creates an unprivileged `wicket` user in the `docker` group with root's
authorized keys, and enables lingering so its systemd user services run without a login. It ends
with `node ready`.

## 2. Enrol it

```sh
wicket node token --name n1 --ttl 1h        # prints a one-time join token (stored hashed)
wicket node enrol wicket@203.0.113.7 --token wkt_… --host-key 'SHA256:…' \
    --hosts 'api.example.com,*.example.org'
```

- `--host-key` takes the node's key line or its `SHA256:` fingerprint. Without it `enrol` refuses,
  unless you pass `--trust-first-use`, which pins whatever the node presents and prints its
  fingerprint for you to check.
- `--hosts` is what the node's CA may mint certificates for. Make it as narrow as the boxes you will
  run there need: root on the node can use the CA for these names until it expires (24 h).
- The token is single-use and short-lived. Passed as `--token`, it shows up in `ps` and shell history.

Enrolment pins the host key, has the node make its own node key and CA key (neither leaves it), and
gives it a 24-hour identity certificate and a 24-hour node CA.

## 3. Install wicket and the agent image there

```sh
wicket node install n1                       # copies this wicket binary, starts the wicket-node service
ssh wicket@203.0.113.7 '~/.local/bin/wicket image'   # builds the node's own image, wicket/claude-code:<build id>
```

`node install` checks the binary's sha256 on the node and installs it as a version, with
`~/.local/bin/wicket` a link to it, then installs the `wicket-node` systemd user service. The node's
architecture must match the control host's. `wicket image` builds the image from the copy embedded
in the binary, so it matches the build.

## 4. Run a box there

```sh
wicket run task.yaml --node n1
```

The run's header says where it runs:

```text
  node n1 via wicket node serve (egress decided there from the signed feed; secrets stay here)
```

Approve and deny as usual: an out-of-reach request on the node becomes a pending request on the
control host.

## Look after it

```sh
wicket node list              # each node, and what it holds for this host's runs
wicket node renew-ca n1       # a fresh node CA and identity certificate, over ssh
wicket node revoke n1         # refuse it from now on
```

- The node's certificate and CA are renewed over the control channel at half-life while a run is
  connected. A node that was unreachable until they expired gets back in with `wicket node renew-ca`.
- Update it with the control host: `sudo wicket self update ARTIFACT --nodes n1`
  ([update and roll back](update-and-roll-back.md)).
- After a deliberate clock step on the node, restart `wicket-node` (`systemctl --user restart
  wicket-node`, as `wicket`) so it reads the wall clock again.

## Check it end to end

`ci/node-e2e.sh n1` runs a probe on the node and cuts the control channel twice, to show the box
working on its grants while cut off and stopped when its authority ends. The node must be enrolled
with `--hosts example.com`.
