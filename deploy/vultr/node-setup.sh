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

# gVisor from its signed apt repository. Its signing key is accepted only if it is the one key with
# the fingerprint pinned here (#722): a fetched key could be anyone's, and a second key appended to
# it would be trusted too.
fpr=6F1DF85E3A71C24918E727D56FC6D554E32BD943
kd=$(mktemp -d)
key=$kd/archive.key
curl -fsSL --retry 3 -o "$key" https://gvisor.dev/archive.key
got=$(GNUPGHOME=$kd gpg --show-keys --with-colons "$key" | awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; p = 0 }')
[ "$got" = "$fpr" ] || { echo "gVisor's apt key is not the pinned $fpr (got ${got:-nothing})" >&2; exit 1; }
GNUPGHOME=$kd gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg <"$key"
rm -rf "$kd"
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
# default of 10 sessions a connection would refuse the eleventh box (MaxSessions, for the wicket
# login only). MaxStartups allows bursts of new connections (box starts after a control-host
# restart) before sshd starts dropping them; it can't go in a Match block.
# This script sets up a new node: don't re-run it on a live one (it restarts Docker, stopping every
# box, and rewrites wicket's authorized_keys). The docs give each of these steps on its own.
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/60-wicket.conf <<'SSHD'
MaxStartups 64:30:256
Match User wicket
    MaxSessions 512
Match all
SSHD
# `sshd -t` needs its privilege separation directory, which only a running ssh.service makes: from
# cloud-init it may not have started yet (socket activation).
install -d -m 755 /run/sshd
if ! sshd -t; then
  rm -f /etc/ssh/sshd_config.d/60-wicket.conf
  echo "node-setup: sshd refused the wicket settings (above); removed them, so this node keeps sshd's defaults (10 sessions a connection: about 10 boxes)" >&2
fi
ssh_unit=ssh
systemctl cat ssh.service >/dev/null 2>&1 || ssh_unit=sshd
# Reloaded if running; a socket-activated sshd that hasn't started reads them when it does.
if ! systemctl try-reload-or-restart "$ssh_unit"; then
  echo "node-setup: reloading $ssh_unit failed: the wicket settings apply once sshd restarts" >&2
fi
# The wicket user's slice holds `wicket node serve` and every thread it runs: no task limit beyond
# the kernel's. Its user manager (whose limits `wicket node serve` inherits, and can't exceed) gets
# no RLIMIT_NPROC: that counts every thread of the user, and systemd's default would stop the node
# at a few thousand boxes' worth.
uid=$(id -u wicket)
install -d -m 755 "/etc/systemd/system/user-$uid.slice.d" "/etc/systemd/system/user@$uid.service.d"
printf '[Slice]\nTasksMax=infinity\n' > "/etc/systemd/system/user-$uid.slice.d/60-wicket.conf"
printf '[Service]\nLimitNPROC=infinity\n' > "/etc/systemd/system/user@$uid.service.d/60-wicket.conf"
systemctl daemon-reload
# The user manager started by `enable-linger` above reads its new limit when it restarts.
systemctl try-restart "user@$uid.service"

# A node that publishes its boxes' public names (#575 step 4c): its firewall admits the host ports
# wicket hands out, from anywhere. Inside the range a port is open only while `wicket node serve`
# listens on it (`publish.json`, written by `wicket node install`); it changes no firewall rule.
# Opt in with the same range as names.public.ports (e.g. WICKET_PUBLISH_PORTS=20000-20999);
# WICKET_PUBLISH_PORTS=off removes the rule this script added.
# The range is kept in /etc/wicket-publish-ports, so a new one replaces it.
if [ -n "${WICKET_PUBLISH_PORTS:-}" ]; then
  kept=/etc/wicket-publish-ports
  # The new range first: a bad one changes nothing, the old rule included.
  if [ "$WICKET_PUBLISH_PORTS" != off ]; then
    case "$WICKET_PUBLISH_PORTS" in
      *[!0-9-]* | -* | *- | *-*-*) echo "node-setup: WICKET_PUBLISH_PORTS must be low-high (e.g. 20000-20999), or off" >&2; exit 1 ;;
    esac
    lo=${WICKET_PUBLISH_PORTS%-*}
    hi=${WICKET_PUBLISH_PORTS#*-}
    if [ "$lo" -lt 1024 ] || [ "$lo" -gt "$hi" ] || [ "$hi" -gt 65535 ]; then
      echo "node-setup: WICKET_PUBLISH_PORTS $WICKET_PUBLISH_PORTS: ports from 1024 to 65535, low first" >&2
      exit 1
    fi
    # wicket's own ports here, as `wicket_names::own_ports` reads them: the console's --listen in
    # /etc/wicket/console.env (8787 by default) and webhook intake's in its unit (8443 by default).
    listen_port() { grep -o -- '--listen[= ][^ "]*' "$1" 2>/dev/null | head -n 1 | sed 's/.*://'; }
    console_port=$(listen_port /etc/wicket/console.env); console_port=${console_port:-8787}
    intake_port=$(listen_port /etc/systemd/system/wicket-intake.service); intake_port=${intake_port:-8443}
    for own in "$console_port" "$intake_port"; do
      if [ "$own" -ge "$lo" ] && [ "$own" -le "$hi" ]; then
        echo "node-setup: WICKET_PUBLISH_PORTS $WICKET_PUBLISH_PORTS holds port $own, which wicket itself listens on" >&2
        exit 1
      fi
    done
  fi
  have_ufw=0
  if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then have_ufw=1; fi
  old=$(cat "$kept" 2>/dev/null || true)
  if [ -n "$old" ] && [ "$old" != "$WICKET_PUBLISH_PORTS" ] && [ "$have_ufw" = 1 ]; then
    ufw delete allow "${old/-/:}/tcp" >/dev/null 2>&1 || true
    echo "node-setup: the firewall no longer admits host ports $old/tcp"
  fi
  if [ "$WICKET_PUBLISH_PORTS" = off ]; then
    rm -f "$kept"
  else
    if [ "$have_ufw" = 1 ]; then
      ufw allow "${WICKET_PUBLISH_PORTS/-/:}/tcp" >/dev/null
      echo "node-setup: the firewall admits host ports $WICKET_PUBLISH_PORTS/tcp"
    else
      echo "node-setup: no active ufw: admit host ports $WICKET_PUBLISH_PORTS/tcp in this node's firewall yourself"
    fi
    printf '%s\n' "$WICKET_PUBLISH_PORTS" > "$kept"
  fi
fi

docker info --format 'runtimes: {{range $k, $v := .Runtimes}}{{$k}} {{end}}'
runsc --version | sed -n 1p   # sed reads it all: head would close the pipe early (SIGPIPE under pipefail)
echo "node ready"
