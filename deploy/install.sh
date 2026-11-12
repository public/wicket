#!/usr/bin/env bash
# Set up this host as a wicket control host (#40, #12). Ubuntu 24.04 or Debian 12; run as root,
# from a checkout or an unpacked release; safe to run again (it changes only what is missing or
# out of date).
#
#   sudo deploy/install.sh [--binary PATH] [--operator USER]... [--trust-domain NAME]
#                          [--console-origin URL] [--skip-gvisor] [--skip-image] [--no-start]
#
# What it does:
#   - Docker (the distribution's docker.io), and gVisor from its signed apt repository, registered
#     with Docker as `runsc` with --host-uds=open (merged into /etc/docker/daemon.json);
#   - the `wicket` system user and group, alone in the docker group (Docker is root on the host),
#     and the `wicket-operators` group for the people who start runs (--operator, default the
#     user running sudo); operators are taken out of the docker group;
#   - /var/lib/wicket (0700, the wicket user's): ledger, vault, issuer key, runs and their sockets;
#   - /usr/local/bin/wicket, the agent image's directory under /usr/local/share/wicket, and
#     /etc/wicket (the daemon's policy, the console's options);
#   - systemd units for wicketd, the console (wicket serve) and the reconciler, enabled and started;
#   - the identity issuer, and the agent image.
# Then the one secret: sudo wicket secret set claude-oauth (from `claude setup-token`).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
binary=""
operators=()
trust_domain=""
origin=""
skip_gvisor=0
skip_image=0
start=1
while [ $# -gt 0 ]; do
    case "$1" in
        --binary) binary=$2; shift 2 ;;
        --operator) operators+=("$2"); shift 2 ;;
        --trust-domain) trust_domain=$2; shift 2 ;;
        --console-origin) origin=$2; shift 2 ;;
        --skip-gvisor) skip_gvisor=1; shift ;;
        --skip-image) skip_image=1; shift ;;
        --no-start) start=0; shift ;;
        -h | --help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo $0)"

# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:24.04 | debian:12) ;;
    *) say "warning: tested on Ubuntu 24.04 and Debian 12, not ${PRETTY_NAME:-this system}" ;;
esac
if [ ${#operators[@]} -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    operators=("$SUDO_USER")
fi
if [ -z "$binary" ]; then
    for b in "$root/wicket" "$root/target/release/wicket"; do
        [ -x "$b" ] && { binary=$b; break; }
    done
fi
[ -n "$binary" ] && [ -x "$binary" ] || die "no wicket binary: build one (cargo build --release) or pass --binary PATH"
[ -f "$root/images/claude-code/Dockerfile" ] || die "no images/claude-code next to this script"
systemd=0
[ -d /run/systemd/system ] && systemd=1

say "packages"
need=()
for p in docker.io ca-certificates curl gnupg python3 openssh-client; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || need+=("$p")
done
if [ ${#need[@]} -gt 0 ]; then
    apt-get update -q
    apt-get install -y -q "${need[@]}" >/dev/null
fi

if [ "$skip_gvisor" = 0 ]; then
    say "gVisor"
    if ! command -v runsc >/dev/null; then
        arch=$(dpkg --print-architecture)
        curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
        echo "deb [arch=$arch signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
            >/etc/apt/sources.list.d/gvisor.list
        # gVisor's repository is sometimes caught mid-sync ("File has unexpected size"): retry.
        for i in 1 2 3 4; do
            if apt-get update -q && apt-get install -y -q runsc >/dev/null; then break; fi
            [ "$i" = 4 ] && die "installing gVisor failed"
            say "installing gVisor failed (attempt $i), retrying in $((i * 20)) s"
            sleep $((i * 20))
        done
    fi
    # Register runsc with --host-uds=open (boxes reach wicket only through unix sockets), keeping
    # whatever else daemon.json already says.
    mkdir -p /etc/docker
    changed=$(python3 - "$(command -v runsc)" <<'PY'
import json, os, sys
p = "/etc/docker/daemon.json"
try:
    with open(p) as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}
want = {"path": sys.argv[1], "runtimeArgs": ["--host-uds=open"]}
if cfg.setdefault("runtimes", {}).get("runsc") == want:
    print("no")
else:
    cfg["runtimes"]["runsc"] = want
    tmp = p + ".wicket-new"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    os.replace(tmp, p)
    print("yes")
PY
)
    if [ "$changed" = yes ] && [ "$systemd" = 1 ]; then
        systemctl restart docker
    fi
fi
[ "$systemd" = 1 ] && systemctl enable --now docker >/dev/null 2>&1 || true

say "users and groups"
getent group wicket >/dev/null || groupadd --system wicket
id -u wicket >/dev/null 2>&1 || useradd --system --gid wicket --home-dir /var/lib/wicket --no-create-home --shell /usr/sbin/nologin wicket
getent group docker >/dev/null || groupadd --system docker
usermod -aG docker wicket
getent group wicket-operators >/dev/null || groupadd --system wicket-operators
for op in "${operators[@]}"; do
    id -u "$op" >/dev/null 2>&1 || die "no user $op (--operator)"
    usermod -aG wicket-operators "$op"
    if id -nG "$op" | tr ' ' '\n' | grep -qx docker; then
        gpasswd -d "$op" docker >/dev/null
        say "took $op out of the docker group: Docker is root on this host, so only the wicket user has it"
    fi
done

say "directories"
install -d -o wicket -g wicket -m 0700 /var/lib/wicket
install -d -o root -g root -m 0755 /etc/wicket /usr/local/share/wicket
if [ ! -e /etc/wicket/wicketd.yaml ]; then
    cat >/etc/wicket/wicketd.yaml <<'YAML'
# Who may do what through wicketd (wicket daemon). Users by name or uid, groups by name or gid.
# Root may do everything over the socket (the host break-glass); approving, denying, secrets,
# passkey enrolment, nodes and spending are root's alone there, or need a passkey in the console.
read:   { groups: [wicket-operators] }   # pending, links, audit, identities, leases, nodes, doctor
run:    { groups: [wicket-operators] }   # run, wrap, say
revoke: { groups: [wicket-operators] }   # identity revoke, grant revoke, unlink, lease release
YAML
fi
if [ ! -e /etc/wicket/console.env ]; then
    args="--listen 127.0.0.1:8787 --no-bootstrap-link"
    [ -n "$origin" ] && args="$args --origin $origin"
    printf '# wicket serve options (see wicket serve --help). Passkeys need https:// or localhost.\nWICKET_CONSOLE_ARGS="%s"\n' "$args" \
        >/etc/wicket/console.env
fi

say "wicket $("$binary" --version | awk '{print $2}')"
install -m 0755 "$binary" /usr/local/bin/wicket.new
mv -f /usr/local/bin/wicket.new /usr/local/bin/wicket
rm -rf /usr/local/share/wicket/images.new
cp -r "$root/images" /usr/local/share/wicket/images.new
chmod -R u=rwX,go=rX /usr/local/share/wicket/images.new
rm -rf /usr/local/share/wicket/images
mv /usr/local/share/wicket/images.new /usr/local/share/wicket/images

as_wicket() { (cd /var/lib/wicket && runuser -u wicket -- env HOME=/var/lib/wicket WICKET_HOME=/var/lib/wicket /usr/local/bin/wicket "$@"); }

say "identity issuer"
if [ ! -e /var/lib/wicket/identity/issuer.key ]; then
    [ -n "$trust_domain" ] || trust_domain="wicket.$(hostname -s | tr 'A-Z' 'a-z' | tr -c 'a-z0-9.\n-' '-')"
    as_wicket identity init --trust-domain "$trust_domain"
fi

say "systemd units"
units_changed=0
for u in wicketd wicket-console wicket-reconcile; do
    if ! cmp -s "$here/systemd/$u.service" "/etc/systemd/system/$u.service"; then
        install -m 0644 "$here/systemd/$u.service" "/etc/systemd/system/$u.service"
        units_changed=1
    fi
done
if [ "$systemd" = 1 ]; then
    systemctl daemon-reload
    if [ "$start" = 1 ]; then
        systemctl enable wicketd wicket-console wicket-reconcile >/dev/null 2>&1
        # Restarting wicketd stops the runs started through it: only when something changed.
        if [ "$units_changed" = 1 ] || ! systemctl is-active -q wicketd; then
            systemctl restart wicketd
        fi
        systemctl restart wicket-console wicket-reconcile
    fi
else
    say "no systemd here: units installed but not started"
fi

if [ "$skip_image" = 0 ]; then
    say "agent image"
    as_wicket image --dir /usr/local/share/wicket/images/claude-code
fi

cat <<EOF

wicket is installed. Next:
  1. The one secret, your Claude subscription token (from \`claude setup-token\`):
       sudo wicket secret set claude-oauth
  2. Check it all, as an operator${operators:+ (${operators[*]}; log in again first, for the wicket-operators group)}:
       wicket doctor
  3. A passkey for the console (approvals need one, or root on this host):
       sudo wicket operator enrol-link --origin http://localhost:8787
EOF
