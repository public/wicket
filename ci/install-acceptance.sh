#!/usr/bin/env bash
# ci/acceptance.sh --installed against a system that deploy/install.sh set up in a disposable
# container (as ci/install-test.sh does): the operator `alex` drives wicketd, privileged steps go
# through `sudo wicket` (the host break-glass), and the boxes are real gVisor boxes.
#
# The container has no Docker daemon or systemd of its own, and gVisor can't run inside it. So:
#   - its boxes run on the host's Docker, with the host's runsc: the host's socket is relayed into
#     the container's docker group (so only the wicket user reaches it, as install.sh arranges);
#   - Docker resolves a box's bind mounts on the host, so the container's /var/lib/wicket is the
#     host's /var/lib/wicket: made for the test (it must not exist) and removed afterwards;
#   - wicketd is started by hand as the wicket user (no systemd), as ci/install-test.sh does.
# Not covered: systemd starting the units, install.sh building the image (--skip-image: the host's
# image is used), and the gVisor and Docker install.sh puts in the container (the host's run the
# boxes). The multi-host flow is not run here.
#
#   ci/install-acceptance.sh [path/to/wicket] [ubuntu:24.04|debian:12]
# Env: IMAGE (an agent image on the host; default: built from this tree as wicket/claude-code:acc-inst
# and removed afterwards), H3GET (a static ci/h3get; default: built), DOCKER (the host's docker
# command, default "docker").
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=$(realpath "${1:-$repo/target/release/wicket}")
base=${2:-ubuntu:24.04}
docker=${DOCKER:-docker}
name=acc-install-$$
data=/var/lib/wicket
[ ! -e "$data" ] || { echo "$data exists on this host: refusing to share it with the test container" >&2; exit 2; }
sock=$($docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null | sed 's#^unix://##')
sock=${sock:-/var/run/docker.sock}
pkg=$(mktemp -d)
built=
cleanup() {
  set +e
  $docker rm -f "$name" >/dev/null 2>&1
  # Boxes the container's wicketd started, if any outlived it (its runs are under $data).
  for c in $($docker ps -aq --filter label=wicket=1); do
    case "$($docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$c")" in *"$data/runs/"*) $docker rm -f "$c" >/dev/null ;; esac
  done
  [ -n "$built" ] && $docker rmi "$built" >/dev/null 2>&1
  sudo -n rm -rf "$data"
  rm -rf "$pkg"
}
trap cleanup EXIT
sudo -n install -d -m 0700 "$data"

"$repo/ci/package.sh" "$bin" "$pkg" >/dev/null
if [ -n "${H3GET:-}" ]; then
  cp "$H3GET" "$pkg/h3get"
else
  cargo build -q --release --locked --target x86_64-unknown-linux-musl --manifest-path "$repo/ci/h3get/Cargo.toml"
  cp "$repo/ci/h3get/target/x86_64-unknown-linux-musl/release/h3get" "$pkg/h3get"
fi
image=${IMAGE:-}
if [ -z "$image" ]; then
  image=wicket/claude-code:acc-inst
  WICKET_DOCKER=$docker "$bin" image --tag "$image" >"$pkg/image.log" 2>&1 || { tail -30 "$pkg/image.log"; exit 1; }
  built=$image
fi

$docker run --rm --name "$name" --network host \
  -v "$repo:/src:ro" -v "$pkg:/pkg:ro" -v "$sock:/run/host-docker.sock" -v "$data:$data" \
  -e IMAGE="$image" "$base" bash -euo pipefail -c '
apt-get update -q >/dev/null && apt-get install -y -q sudo jq curl socat python3 >/dev/null
useradd --create-home alex
echo "alex ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers.d/alex
mkdir /opt/pkg && tar -C /opt/pkg -xzf /pkg/wicket-*-x86_64-linux.tar.gz
/opt/pkg/wicket-*/deploy/install.sh --operator alex --skip-image --trust-domain acc.wicket.test >/tmp/install.log 2>&1 \
  || { tail -30 /tmp/install.log; exit 1; }
echo "ok: install.sh ran (from the release archive)"
# The host'"'"'s Docker, for the docker group only (where install.sh put the wicket user).
socat UNIX-LISTEN:/var/run/docker.sock,fork,group=docker,mode=660 UNIX-CONNECT:/run/host-docker.sock &
for _ in $(seq 50); do [ -S /var/run/docker.sock ] && break; sleep 0.1; done
runuser -u wicket -- docker info --format "runtimes: {{range \$k, \$v := .Runtimes}}{{\$k}} {{end}}" | grep -q runsc \
  || { echo "FAIL: the host Docker has no runsc runtime"; exit 1; }
# What systemd would do: the runtime directory, then wicketd as wicket.
install -d -o wicket -g wicket -m 0755 /run/wicket
(cd /var/lib/wicket && runuser -u wicket -- env HOME=/var/lib/wicket WICKET_HOME=/var/lib/wicket /usr/local/bin/wicket daemon) 2>/tmp/wicketd.log &
for _ in $(seq 50); do [ -S /run/wicket/wicketd.sock ] && break; sleep 0.1; done
[ -S /run/wicket/wicketd.sock ] || { cat /tmp/wicketd.log; exit 1; }
echo "ok: wicketd is up"
# The operator, in a copy of the checkout it can write to.
mkdir /home/alex/wicket && tar -C /src --exclude=./target --exclude=./ci/h3get/target -cf - . | tar -C /home/alex/wicket -xf - && chown -R alex /home/alex/wicket
cp /pkg/h3get /home/alex/h3get && chown alex /home/alex/h3get
status=0
(cd /home/alex/wicket && runuser -u alex -- env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/alex USER=alex \
  IMAGE="$IMAGE" H3GET=/home/alex/h3get WICKET_DOCKER="sudo -n docker" ACC_AUDIT_SINK=1 ci/acceptance.sh --installed) || status=$?
[ "$status" = 0 ] || { echo "== wicketd log (tail)"; tail -30 /tmp/wicketd.log; }
exit $status
'
