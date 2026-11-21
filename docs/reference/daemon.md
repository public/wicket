# The daemon, and who may do what

On an installed control host (`deploy/install.sh`), `wicketd` (`wicket daemon`) runs as the `wicket`
system user, which owns the data in `/var/lib/wicket` and is the only user in the `docker` group.
Operators run the usual `wicket` commands, which send their command line to the daemon over
`/run/wicket/wicketd.sock`. The daemon parses it again with the same clap definition, sorts it into a
class, and allows or refuses it for the caller the kernel names (`SO_PEERCRED`), never for anything
the caller says. The code is `crates/wicket-cli/src/daemon/`.

Without the daemon (development mode, or `WICKET_HOME` set), `wicket` runs in the caller's own
process, as the caller, and every check below is absent: see
[limits](../explanation/limits.md#the-control-host).

## Classes

| class | who | |
|---|---|---|
| read | the policy file's `read` (default: the `wicket-operators` group) | reads state |
| run | the policy file's `run` (default: `wicket-operators`) | starts and steers runs |
| revoke | the policy file's `revoke` (default: `wicket-operators`) | takes authority away |
| privileged | root over the socket (`sudo wicket …`, the host break-glass), and the daemon's own uid | everything else; no policy setting widens it |
| root only | root over the socket, not even the daemon's own uid | changing the code that holds every key |
| local | anyone; runs in the caller's own process | touches no wicket data |
| refused | nobody through the daemon | runs as a systemd unit instead |

Everyone else approves, denies and starts runs in the console, with a passkey.

## Who may run what

| command | class |
|---|---|
| `run`, `wrap`, `session`, `hibernate`, `wake`, `trigger create\|resume\|renew`, `manifest save\|restore` | run |
| `agents`, `pending`, `links`, `audit` (and `audit explain`, `audit export`), `authority`, `capacity list`, `manifest list\|show\|check`, `doctor` | read |
| `secret list`, `identity issuer\|show\|list`, `operator list\|sessions`, `lease list`, `node list` (without `--provider`), `node ca\|fences`, `policy show`, `state check`, `self status`, `trigger list\|show\|fire` | read |
| `unlink`, `grant revoke`, `capacity revoke`, `identity revoke`, `lease release`, `trigger pause\|rm` | revoke |
| `approve`, `deny`, `grant renew`, `capacity grant\|renew` | privileged |
| `secret set\|link\|hosts\|rm` | privileged |
| `image` | privileged |
| `operator enrol-link\|reset\|revoke-session` | privileged |
| `identity init` | privileged |
| `reconcile` | privileged |
| `node token\|enrol\|revoke\|renew-ca\|install\|create\|release\|release-fence\|plans`, `node list --provider` | privileged |
| `state check --probe`, `state kit`, `state restore`, `keys …` | privileged |
| `self update\|rollback\|prune\|trust-key` | root only |
| `program digest`, `zone`, `node serve`, `self keygen\|sign`, `dev …` | local |
| `serve`, `daemon`, `state replicate` | refused: the `wicket-console`, `wicketd` and `wicket-state` units run them |

Arguments only wicket itself passes are refused from any caller: `run --run-id` and `--ssh-key`,
and `wake --by`. (A child run's parent, lease and takeover are no arguments: its supervisor runs
in its parent's process.) Manifests, `--workdir`, a trigger's `--file` and `--event`, `manifest check` and `save`'s `--file`, and `audit --verify`'s `--against` files (a `store:<sink>` names no file) and `--issuer-jwk` are sent to the daemon as
content; mounting a directory in place (`run --workspace-dir`, and `wrap`, which mounts its
launcher's directory) is root's only.

Runs outlive the daemon (#455). `wicket self update` moves `wicketd` to the new build at once: on
SIGHUP it re-executes, handing every running command to the new build, which goes on relaying its
caller's signals and sends its exit code; the caller and the run don't notice. Only commands still
being started (admission, uploads) are waited for, and new ones are refused for those seconds, to
be tried again. A restart by systemd (`deploy/install.sh`, `systemctl restart wicketd`) stops only
the daemon (`KillMode=process`): its runs go on supervising their boxes, and only their callers'
connections end (`wicket session <run>` opens one again). At its start, the new `wicketd` first
re-executes this host's own node's `serve` as its build (SIGHUP, as `wicket self update` does) when
the restart left it on another (#529), then hands each run whose supervisor runs another build to its own (#475): the supervisor is stopped without
its box, and the new build's reconciler starts one that re-attaches, so no run keeps an old build's
supervisor across an install. To end runs too, end them first (`wicket identity revoke <run>`, or `wicket
hibernate` for a long-lived agent).

## The policy file

`/etc/wicket/wicketd.yaml` (`wicket daemon --policy`). Users by name or uid, groups by name or gid.
A class left out defaults to the `wicket-operators` group; a missing or empty file is the default.

```yaml
read:   { groups: [wicket-operators] }   # pending, links, audit, identities, leases, nodes, doctor
run:    { groups: [wicket-operators] }   # run, wrap, say
revoke: { groups: [wicket-operators] }   # identity revoke, grant revoke, unlink, lease release
```

## The systemd units

`deploy/install.sh` installs them from `deploy/systemd/`. Each runs as `wicket`, with
`HOME=/var/lib/wicket WICKET_HOME=/var/lib/wicket`, in the `docker` group.

| unit | runs | |
|---|---|---|
| `wicketd` | `wicket daemon` | the socket in `/run/wicket` |
| `wicket-console` | `wicket serve $WICKET_CONSOLE_ARGS` | options in `/etc/wicket/console.env`; by default `--listen 127.0.0.1:8787 --no-bootstrap-link` |
| `wicket-reconcile` | `wicket reconcile --every 1m` | |
| `wicket-state` | `wicket state replicate` | starts only once `/var/lib/wicket/state-store.yaml` exists |

### Limits

Every run has a supervisor process (`wicket run`, `attach` or `wake`). It lives in the cgroup of
the unit that started it: `wicketd` for runs started on the CLI, `wicket-console` for runs started
from the console, and `wicket-reconcile` for runs it adopts after a crash. So those three units are
sized for many boxes ([#582](https://github.com/public/wicket/issues/582) step 4):

| setting | value | why |
|---|---|---|
| `TasksMax` | 262144 | It counts every thread in the unit's cgroup. systemd's default is 15% of the kernel's pid limit, often 4915, about 800 supervisors. A supervisor has about 6 threads: the main one, its runtime's 2 workers and a few blocking-pool threads (at most 32). So 262144 covers the 10,000 boxes #582's step 4 aims at, with room. |
| `LimitNOFILE` | 1048576 | Per process. A supervisor holds its box's sockets, its logs and the ledger, and wicketd holds its callers' descriptors. The default of 1,024 is the first limit a busy wicketd hits. |
| `LimitNPROC` | infinity | `RLIMIT_NPROC` counts every thread of the `wicket` user, in every unit. systemd's default (about 31,000 on a typical host) would stop about 5,000 supervisors, long before `TasksMax`. A supervisor you start by hand as the wicket user (`sudo -u wicket wicket run`) has your login's limit instead (`ulimit -u`). |

A supervisor's tokio runtime has 2 worker threads, not one per core: on a 32-core host, 100
supervisors used to start 3,200 workers, and now start 200. `WICKET_SUPERVISOR_WORKERS` changes
it, from 1 to 64; another value is refused with a warning and 2 used. Other commands keep tokio's
default.

The units' new limits arrive with the units: `deploy/install.sh` on the control host. The
kernel's limits must also allow as many threads. `kernel.pid_max` defaults vary by distribution
and size: 32768 on many small hosts, 4194304 on Ubuntu 24.04 (check with `sysctl kernel.pid_max
kernel.threads-max`). For thousands of boxes, raise them if they're lower:

```sh
printf 'kernel.pid_max = 4194304\nkernel.threads-max = 4194304\n' | sudo tee /etc/sysctl.d/60-wicket.conf
sudo sysctl --system
```
