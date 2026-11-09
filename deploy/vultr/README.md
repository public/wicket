# Running wicket boxes on a Vultr node

The node is a **sandbox node that holds no secrets**: it runs Docker + gVisor only. wicket's proxies, the
Claude subscription token, the per-run CA key and the ledger stay on the control host, and each run's two unix
sockets are forwarded to the node with `ssh -R`. Nothing on the node listens on its public IP.

Create a small Vultr instance (any plan with 2 GB RAM is plenty; Ubuntu 24.04), with an SSH key you hold on the
control host. The PoC doesn't create instances itself yet (design §8, milestone I2).

```sh
IP=<the node's IP>; K=<path to the SSH private key>

ssh -i $K root@$IP 'bash -s' < deploy/vultr/node-setup.sh  # Docker + gVisor + user wicket
tar -C images/claude-code -cf - . | ssh -i $K wicket@$IP \
  'mkdir -p img && tar -C img -xf - && docker build -q --network host -t wicket/claude-code:poc img'

./target/release/wicket run examples/hello-github.yaml --node wicket@$IP --ssh-key $K

# before destroying the node: confirm it holds no secrets (see docs/poc-results.md), then destroy it
```
