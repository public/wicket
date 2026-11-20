#!/usr/bin/env bash
# Prepare a fresh Ubuntu 24.04 Vultr instance as a wicket node (proof of concept).
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

# Limits for many boxes (#582 step 4; docs/reference/nodes.md#limits). The control host runs each
# box's supervisor over its own ssh session, multiplexed on one shared connection per node: sshd's
# default of 10 sessions a connection would refuse the eleventh box. MaxStartups allows bursts of
# new connections (box starts after a control-host restart) before sshd starts dropping them.
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/60-wicket.conf <<'SSHD'
MaxSessions 512
MaxStartups 64:30:256
SSHD
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
# The wicket user's slice holds `wicket node serve` and every thread it runs: no task limit beyond
# the kernel's.
uid=$(id -u wicket)
install -d -m 755 "/etc/systemd/system/user-$uid.slice.d"
printf '[Slice]\nTasksMax=infinity\n' > "/etc/systemd/system/user-$uid.slice.d/60-wicket.conf"
systemctl daemon-reload

docker info --format 'runtimes: {{range $k, $v := .Runtimes}}{{$k}} {{end}}'
runsc --version | sed -n 1p   # sed reads it all: head would close the pipe early (SIGPIPE under pipefail)
echo "node ready"
