#!/usr/bin/env bash
# deploy/install.sh in a disposable container (#40, #12): a fresh Ubuntu 24.04 (or Debian 12) gets
# the users, groups, directories, policy, units and binary; then wicketd is started by hand (no
# systemd in a container) and real users check #12's acceptance: an operator reads state and starts
# nothing it shouldn't, can't open the data or approve; root can. The script runs twice (idempotent).
#
# It installs from the release archive (ci/package.sh), including gVisor's package and its
# registration in daemon.json, and starts the console's command line as its unit would.
# Not covered here (needs a real VM): running gVisor (runsc can't run inside an unprivileged
# container), the Docker daemon, systemd starting the units, and building the agent image.
#   ci/install-test.sh [path/to/wicket] [ubuntu:24.04|debian:12]
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=$(realpath "${1:-$repo/target/release/wicket}")
image=${2:-ubuntu:24.04}
docker=${DOCKER:-docker}
name=wicket-install-test-$$
pkg=$(mktemp -d)
trap '$docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$pkg"' EXIT
"$repo/ci/package.sh" "$bin" "$pkg" >/dev/null

$docker run --rm --name "$name" --network host \
    -v "$repo:/src:ro" -v "$pkg:/pkg:ro" \
    "$image" bash -euo pipefail -c '
fail() { echo "FAIL: $*"; exit 1; }
useradd --create-home alex
groupadd --system docker
usermod -aG docker alex   # an operator who had Docker: the install takes it away

mkdir -p /etc/docker && echo "{\"log-driver\": \"local\"}" >/etc/docker/daemon.json   # settings of its own
mkdir /opt/pkg && tar -C /opt/pkg -xzf /pkg/wicket-*-x86_64-linux.tar.gz
(cd /pkg && sha256sum -c --quiet wicket-*.tar.gz.sha256) || fail "archive checksum"
inst=$(echo /opt/pkg/wicket-*/deploy/install.sh)
$inst --operator alex --skip-image --trust-domain wicket.example.com >/tmp/install1.log
echo "ok: install.sh ran, from the release archive"
before=$(stat -c %i /usr/local/bin/wicket; sha256sum /etc/docker/daemon.json /etc/wicket/*)
$inst --operator alex --skip-image >/tmp/install2.log
[ "$before" = "$(stat -c %i /usr/local/bin/wicket; sha256sum /etc/docker/daemon.json /etc/wicket/*)" ] || fail "the second run changed the binary or the configuration"
echo "ok: install.sh ran again and changed nothing"
python3 -c "import json; c = json.load(open(\"/etc/docker/daemon.json\")); assert c[\"log-driver\"] == \"local\", c; assert c[\"runtimes\"][\"runsc\"] == {\"path\": \"/usr/bin/runsc\", \"runtimeArgs\": [\"--host-uds=open\"]}, c" \
    || fail "daemon.json: $(cat /etc/docker/daemon.json)"
runsc --version >/dev/null || fail "runsc not installed"
echo "ok: gVisor installed and registered as runsc with --host-uds=open, keeping daemon.json'"'"'s own settings"

[ "$(stat -c "%U %G %a" /var/lib/wicket)" = "wicket wicket 700" ] || fail "data dir: $(stat -c "%U %G %a" /var/lib/wicket)"
id -nG wicket | tr " " "\n" | grep -qx docker || fail "wicket is not in the docker group"
id -nG alex | tr " " "\n" | grep -qx docker && fail "alex is still in the docker group"
id -nG alex | tr " " "\n" | grep -qx wicket-operators || fail "alex is not an operator"
[ "$(getent passwd wicket | cut -d: -f7)" = /usr/sbin/nologin ] || fail "wicket has a login shell"
for u in wicketd wicket-console wicket-reconcile wicket-state; do [ -f /etc/systemd/system/$u.service ] || fail "no $u unit"; done
[ -f /etc/wicket/wicketd.yaml ] && [ -f /etc/wicket/console.env ] || fail "no /etc/wicket config"
[ -f /var/lib/wicket/identity/issuer.key ] || fail "no issuer key"
[ "$(stat -c %U /var/lib/wicket/identity/issuer.key)" = wicket ] || fail "issuer key not the wicket user'"'"'s"
echo "ok: users, groups, data dir, config, units and issuer in place"

# What systemd would do: the runtime directory, then the daemon as wicket.
install -d -o wicket -g wicket -m 0755 /run/wicket
(cd /var/lib/wicket && runuser -u wicket -- env HOME=/var/lib/wicket WICKET_HOME=/var/lib/wicket /usr/local/bin/wicket daemon) 2>/tmp/wicketd.log &
for _ in $(seq 50); do [ -S /run/wicket/wicketd.sock ] && break; sleep 0.1; done
[ -S /run/wicket/wicketd.sock ] || { cat /tmp/wicketd.log; fail "wicketd did not start"; }

# The console, as its unit starts it (on another port: this test may share the host'"'"'s network).
sed -i "s/127.0.0.1:8787/127.0.0.1:18787/" /etc/wicket/console.env
set -a; . /etc/wicket/console.env; set +a
# shellcheck disable=SC2086
(cd /var/lib/wicket && runuser -u wicket -- env HOME=/var/lib/wicket WICKET_HOME=/var/lib/wicket /usr/local/bin/wicket serve $WICKET_CONSOLE_ARGS) >/tmp/console.log 2>&1 &
for _ in $(seq 50); do grep -q "wicket console on" /tmp/console.log && break; sleep 0.1; done
grep -q "wicket console on http://localhost:18787" /tmp/console.log || { cat /tmp/console.log; fail "the console did not start"; }
grep -q "/enrol?t=" /tmp/console.log && fail "the console printed an enrolment link in its log"
grep -q "wicket operator enrol-link" /tmp/console.log || fail "the console did not say how to enrol"
echo "ok: the console starts from its unit'"'"'s options and keeps enrolment links out of its log"

as_alex() { (cd /home/alex && runuser -u alex -- env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/alex USER=alex /usr/local/bin/wicket "$@"); }
out=$(as_alex pending) || fail "alex: pending: $out"
[ "$out" = "no pending requests" ] || fail "alex: pending: $out"
as_alex identity issuer | grep -q wicket.example.com || fail "alex: identity issuer"
echo "ok: alex reads state through wicketd"
runuser -u alex -- ls /var/lib/wicket >/dev/null 2>&1 && fail "alex listed the data dir"
runuser -u alex -- cat /var/lib/wicket/ledger.db >/dev/null 2>&1 && fail "alex read the ledger"
runuser -u alex -- test -r /var/lib/wicket/identity/issuer.key && fail "alex can read the issuer key"
[ -S /var/run/docker.sock ] && runuser -u alex -- test -w /var/run/docker.sock && fail "alex can reach docker"
echo "ok: alex can'"'"'t reach the data dir, the ledger, the issuer key or Docker"
for c in "approve R1" "deny R1" "operator enrol-link" "operator reset" "reconcile --dry-run"; do
    if out=$(as_alex $c 2>&1); then fail "alex: $c succeeded: $out"; fi
    case "$out" in *"needs root on the host"*) ;; *) fail "alex: $c: $out" ;; esac
done
echo "ok: alex can'"'"'t approve, deny, enrol a passkey, reset passkeys or reconcile"
out=$(as_alex run --run-id x /src/examples/demo.yaml 2>&1) && fail "alex passed --run-id"
case "$out" in *"for wicket'"'"'s own use"*) ;; *) fail "alex: --run-id: $out" ;; esac
out=$(as_alex run --workspace-dir /var/lib /src/examples/demo.yaml 2>&1) && fail "alex mounted /var/lib"
case "$out" in *"only root mounts in place"*) ;; *) fail "alex: --workspace-dir /var/lib: $out" ;; esac
echo "ok: alex can'"'"'t pass internal arguments or mount a directory in place"
useradd --create-home eve
out=$(cd /home/eve && runuser -u eve -- /usr/local/bin/wicket pending 2>&1) && fail "eve (no operator) read state"
case "$out" in *"may not read state"*) ;; *) fail "eve: $out" ;; esac
echo "ok: a user outside wicket-operators gets nothing"

out=$(cd / && wicket approve R1 2>&1) && fail "root: approve of a missing request succeeded"
case "$out" in *"needs root"*) fail "root refused: $out" ;; *R1*) ;; *) fail "root: $out" ;; esac
echo token-value | (cd / && wicket secret set claude-oauth) >/dev/null || fail "root: secret set"
[ "$(stat -c "%U %a" /var/lib/wicket/.config/wicket/secrets/claude-oauth)" = "wicket 600" ] || fail "secret file ownership"
echo "ok: root approves and sets the secret, as the wicket user"

out=$(as_alex doctor 2>&1) && fail "doctor passed without Docker"
for want in "mode: system install, through wicketd" "not readable by you (good)" "docker: not reachable by you (good)" \
    "mode: system install, as wicket" "data /var/lib/wicket: ours, mode 0700" "docker group: only us" \
    "policy /etc/wicket/wicketd.yaml: read [group wicket-operators]" "vault: 1 secret(s): claude-oauth" "docker: NOT OK" \
    "listening on 127.0.0.1:18787: up" "no passkey enrolled yet: sudo wicket operator enrol-link"; do
    case "$out" in *"$want"*) ;; *) printf "%s\n" "$out"; fail "doctor did not say: $want" ;; esac
done
echo "ok: doctor reports the install (and the missing Docker daemon)"
n=$(wicket audit --tail 200 | grep -c daemon.refused) || true
[ "$n" -ge 8 ] || fail "only $n refusals audited"
wicket audit --verify >/dev/null || fail "audit chain"
echo "ok: $n refusals audited; the chain verifies"

# #165: an update to a version whose systemd units differ from the installed ones is refused until
# root applies that version'"'"'s own units; then it goes on (here as far as its agent image, which needs
# the Docker daemon this container lacks).
vroot=/var/lib/wicket-versions
a=$(basename "$(readlink $vroot/current)")
(cd /tmp && wicket self keygen /tmp/rk >/dev/null && wicket self trust-key /tmp/rk.pub >/dev/null) || fail "release key"
cp /usr/local/bin/wicket /tmp/wicket-b && printf "build b" >>/tmp/wicket-b && chmod 755 /tmp/wicket-b
(cd /tmp && wicket self sign --key /tmp/rk /tmp/wicket-b >/dev/null) && chmod 644 /tmp/wicket-b.sig || fail "signing b"
b=$(sha256sum /tmp/wicket-b | cut -c1-12)
echo "# edited here" >>/etc/systemd/system/wicketd.service
out=$(cd / && wicket self update /tmp/wicket-b 2>&1) && fail "an update with other units went through: $out"
case "$out" in *"systemd units differ"*wicketd.service*"self apply-units"*) ;; *) fail "update with other units: $out" ;; esac
[ "$(basename "$(readlink $vroot/current)")" = "$a" ] || fail "current moved to $(readlink $vroot/current)"
wicket audit --tail 20 | grep self.update_refused | grep -q "\"units\"" || fail "the units refusal was not audited"
out=$(as_alex self apply-units 2>&1) && fail "alex applied units: $out"
"$vroot/$b/wicket" self apply-units >/tmp/apply.log || { cat /tmp/apply.log; fail "apply-units"; }
grep -q "updated /etc/systemd/system/wicketd.service" /tmp/apply.log || { cat /tmp/apply.log; fail "apply-units said: $(cat /tmp/apply.log)"; }
cmp -s /etc/systemd/system/wicketd.service /opt/pkg/wicket-*/deploy/systemd/wicketd.service || fail "wicketd.service is not the version'"'"'s"
out=$(cd / && wicket self update /tmp/wicket-b 2>&1) || true
case "$out" in *"units differ"*) fail "still refused over units: $out" ;; *"building wicket/claude-code:$b with $b"*) ;; *) fail "the update after apply-units: $out" ;; esac
echo "ok: an update to other systemd units waits for root'"'"'s apply-units, then goes on"
echo "install-test: all checks passed"
'
