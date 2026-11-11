#!/usr/bin/env bash
# Prepare a fresh Ubuntu 24.04 Vultr instance as a wicket sandbox node (proof of concept).
#
# The node gets Docker + gVisor and an unprivileged `wicket` user that wicket's control host logs in as.
# The model key, the installation CA key and the ledger stay on the control host. After enrolment,
# `wicket node install <name>` puts wicket's binary in ~wicket/.local/bin and runs `wicket node serve` as
# a systemd user service (lingering, enabled below, keeps it running without a login). Run as root:
#   ssh root@NODE 'bash -s' < deploy/vultr/node-setup.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Docker never manages the host firewall or a bridge: wicket boxes run with --network none.
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{
  "iptables": false,
  "ip6tables": false,
  "bridge": "none",
  "ip-forward": false,
  "ip-masq": false,
  "log-driver": "local",
  "runtimes": { "runsc": { "path": "/usr/bin/runsc", "runtimeArgs": ["--host-uds=open"] } }
}
JSON
apt-get update -q
apt-get install -y -q docker.io curl gnupg ca-certificates openssl >/dev/null

# gVisor from its signed apt repository.
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
apt-get update -q
apt-get install -y -q runsc >/dev/null
systemctl restart docker

# The login wicket's control host uses: unprivileged, in the docker group, same keys as root.
id wicket >/dev/null 2>&1 || useradd --create-home --shell /bin/bash wicket
usermod -aG docker wicket
install -d -m 700 -o wicket -g wicket /home/wicket/.ssh
install -m 600 -o wicket -g wicket /root/.ssh/authorized_keys /home/wicket/.ssh/authorized_keys
# `wicket node serve` runs as a systemd user service of `wicket`: keep its user manager running.
loginctl enable-linger wicket

docker info --format 'runtimes: {{range $k, $v := .Runtimes}}{{$k}} {{end}}'
runsc --version | head -1
echo "node ready"
