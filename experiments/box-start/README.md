# Where a box start's time goes (#287, step 1)

The question: where does the time between `wicket run` and a running box go, on this host's own
node and on an enrolled one? The answer decides #287's later steps: talking to the Docker Engine API
instead of the CLI, then driving runsc directly or restoring pre-booted boxes.

## Method

Every `wicket run` records named spans on one monotonic clock (`wicket_core::timing`: `Instant`s
pushed onto a list, always on, no I/O on the path). They are kept in the run's record,
`<WICKET_HOME>/runs/<run>/ctl/run.json` (`timings`), when the box has started and again when the run
ends, and printed as a table with `WICKET_TIMINGS=1`. Each span has `at_ms` (when it began, from the
supervisor's start) and `ms` (how long it took).

`measure.sh` starts N boxes (plus one warm-up it leaves out) running `sh -c 'echo …'` in a
256 MiB, one-CPU gvisor zone with no reach, and prints the median and p90 of each span:

```sh
experiments/box-start/measure.sh -n 20                       # this host's own node
experiments/box-start/measure.sh -n 20 --node <name>         # an enrolled node
experiments/box-start/measure.sh -n 20 --isolation runc      # the same without gVisor
```

Run it alone on the host: other load shows up in every span. The raw spans of each run go to
`logs/<label>-<time>.jsonl`.

`runsc-trace.sh` looks inside runsc's own start (#287, `box.entry.runtime`). It adds `--debug
--debug-log` to runsc's `runtimeArgs` for a few `measure.sh` starts, then puts `daemon.json` back.
It prints, for the last box, each runsc command's first and last line (create, gofer, boot, start,
…) and the 15 largest gaps between lines, each with the line after it:

```sh
sudo -E experiments/box-start/runsc-trace.sh -n 3 --keep /tmp/runsc-trace
```

It restarts Docker twice, so run it on a node with no boxes. The debug log slows runsc, so read the
gaps, not the totals.

## The spans

On the control host (the supervisor, `wicket run`):

| span | what |
|---|---|
| `manifest` | reading and parsing the manifest |
| `checks` | the vault, the installation's settings, a program's source digest, the images policy |
| `node.resolve` | finding the enrolled node (`--node`) |
| `run.dir` | the run's directory (and a woken agent's restored state, a `--workdir` copy) |
| `ledger` | opening the ledger, `run.start` and its audit records |
| `ca` | the run CA: generated and written |
| `identity` | the agent identity: issued, verified, put in the ledger |
| `policy.org` | the org policy, compiled into the box's layer (#51) |
| `zone.compile` | the zone, compiled for the run's proxies |
| `proxies`, `proxies.sockets` | the run's egress, model and gateway proxies; binding their sockets (each listens before it is served, so there is no wait, #287) |
| `plan` | the harness's or program's plan, the box's spec |
| `record` | `ctl/run.json` written |
| `node.local` | making sure this host's own `wicket node serve` runs |
| `token.keys`, `token.policy`, `token.mint` | the minting keys and the node's feed, opened (its delta log replayed: only the entries still held are compiled, #287); block 0 compiled from Cedar; the box's token minted and published |
| `feed.publish` | the token committed to the node's feed |
| `node.ready` | from starting the node connection until the node is fresh on the feed at the box's epoch, made of `node.dial` (ssh, or the local unix socket), `node.handshake` (hello, authentication, welcome), `feed.catch_up`, `budget.slice` (the budget slice sealed and sent, #152) and `feed.fresh` (a moment) |
| `trees`, `image.deliver` | the box's trees sent to a remote node; a pinned image sent or pulled there |
| `node.start` | the node round trip: `BoxStart` sent until `Started` received |
| `box_start` | all of the node part (`node.ready` to `node.start`) |
| `started` | a moment: the box runs, as the supervisor learns it |
| `box.first_output` | a moment: the box's first stdout or stderr bytes reach the supervisor |
| `agent.first_model_request` | a moment: the box's first model request reached its node's model proxy |

On the node, inside `node.start` (`node.start.*`, measured on the node's own clock from when it took
the start in, and placed from when the control host sent it, so they start up to the channel's
one-way latency late):

| span | what |
|---|---|
| `total` | the node's whole start of the box |
| `checks` | the run's authority in the feed, for its zone |
| `docker.image_inspect`, `docker.image_cached` | `docker image inspect` (twice for a pinned image not found by its reference); or, instead, the node's cached identity, while no image event has come since it was inspected (#287) |
| `layout` | the box's directories, CA bundle, hosts file, workspace archive, state files, volumes |
| `proxies`, `proxies.sockets` | the node's per-box egress, model, HTTP/3 and DNS, gateway proxies; binding their sockets (no wait, #287) |
| `docker.run` | `docker run -d`: through the Engine API (#287), its create and start calls; else the CLI. Then dockerd, containerd, the shim and runsc |
| `docker.run.create` | from the call (or the CLI) starting until Docker had created the container (Docker's `Created`) |
| `docker.run.runtime` | from then until the runtime had started the box's first process (`State.StartedAt`): containerd, the shim, runsc's sandbox and gofer boot |
| `docker.run.return` | from then until the start call (or the CLI) returned |
| `docker.inspect` | the extra `docker inspect` the three spans above are read from (only with `WICKET_TIMINGS=1`) |
| `record`, `wire` | the box's record saved; its stdin socket, and its logs (followed) and wait started |

After `Started`, the box's own start and its end (#287). These are measured by the box and its node,
sent with the box's exit, and placed by the node's wall clock (so another node's spans are only as
good as the two clocks agree):

| span | what |
|---|---|
| `box.started` | a moment: the runtime started the box's first process (Docker's `State.StartedAt`) |
| `box.entry.init` | from then until `wicket-entry` began (docker-init, bash) |
| `box.entry.runtime` | from `box.started` until the sandbox's kernel came up (its uptime's zero, from `wicket-entry`'s `boot` line, up to 10 ms late): what of the runtime's start comes after `State.StartedAt`. gVisor only, and only when the boot is after `box.started` |
| `box.entry.boot` | from the sandbox's kernel up until `wicket-entry` began: docker-init and bash, inside the box |
| `box.entry.addrs` | wicket.internal's, the links' and the synthetic addresses added |
| `box.entry.setup` | wicket-fwd spawned, the CA bundle written |
| `box.entry.fwd` | waiting for wicket-fwd to listen |
| `box.entry.exec` | the agent's directories made and these steps written (one process) |
| `box.exec` | a moment: the program is started (then `box.first_output` is the program's own start) |
| `box.finished` | a moment: the program exited (Docker's `State.FinishedAt`) |
| `node.teardown.wait` | from then until Docker's wait returned to the node |
| `node.teardown.output` | the node reading the last of the box's logs |
| `node.teardown.inspect` | how it ended (`docker inspect`) |
| `node.teardown.rm` | the container removed |
| `node.teardown.release` | the run's leases dropped, its spend sent |
| `node.teardown` | all of the node's part, from Docker's wait returning until `Exited` is sent |
| `box.exited` | a moment: the supervisor has the exit |
| `teardown.output`, `teardown.fetch` | on the control host, from the exit: the box's last output and stderr; its files fetched from a node that kept them |
| `teardown` | the control host's part, from the exit until the timings are saved (the process's own exit after that is in the wall time only) |

The `box.entry.*` steps need an image with this `wicket-entry` (`wicket image`).

So `node.start` − `node.start.total` is the channel (both ways) and the node's own scheduling, and
`docker.run` − `docker.run.runtime` is what the CLI and dockerd add to runsc.

## Caveats

- `docker.run.*` come from Docker's RFC 3339 timestamps, which dockerd takes on the node's wall
  clock; they are placed on the monotonic clock from when `docker run` began. A clock step during
  a start skews them.
- `agent.first_model_request` is the node's wall clock placed on the control host's: on another
  node it is only as good as the two clocks agree (NTP: a few ms). A program makes no model requests,
  so `measure.sh` shows none; run an agent manifest with `WICKET_TIMINGS=1` for it.
- Recording costs a few `Instant::now()` calls and a mutex per span: nanoseconds against
  milliseconds. Only `WICKET_TIMINGS=1` adds work to a start (the one `docker inspect`, after
  `docker run` has returned, so it delays `Started`, not the box).
- A re-attached run keeps its first supervisor's timings; a run taken over from the node that started it (#164) has only the steps of its taking over.

## Results

### wicket's own part, against a stand-in Docker (2026-11-16)

`fake-engine.py` is a Docker Engine API on a unix socket whose containers are created, started and
exit at once, so a start costs Docker (and runsc) nothing. What `measure.sh` reports with it is
wicket's own work, both hosts' parts, and its Engine API round trips. It needs no Docker:

```sh
python3 experiments/box-start/fake-engine.py /tmp/fake/docker.sock &
WICKET_DOCKER="docker -H unix:///tmp/fake/docker.sock" WICKET=target/release/wicket \
  experiments/box-start/measure.sh -n 20 --isolation runc
```

**The machine:** a wicket box (gVisor) on a shared VPS, release build, this host's own node, 20
starts after a warm-up. Medians, in ms. fsync is slow here (3–8 ms per sync), and noisy: the spans
that are writes to disk move most between runs, the others by under 1 ms. Raw spans:
`logs/fake-engine-before.jsonl`, `logs/fake-engine-after.jsonl`.

| span | before | after | what it is |
|---|---:|---:|---|
| `wicket run`, end to end (wall) | 163 | 153 | the process, start to exit |
| `ledger` | 15.9 | 16.2 | opening the ledger, the run's rows and audit records (SQLite commits) |
| `identity` | 9.7 | 9.7 | the agent identity, issued and put in the ledger |
| `quotas` | (untimed) | 9.7 | the run's quota grants recorded (ledger commits); was a gap after `policy.org` |
| `token.keys` + `token.policy` + `token.mint` | 8.2 | 8.7 | the feed opened, block 0 compiled, the token minted |
| `feed.publish` | 3.5 | 3.7 | the token's delta fsynced into the control host's feed |
| `authority.record` | (untimed) | 7.8 | the box's authority and node recorded (a file and a ledger commit); was a gap |
| `node.ready` | **32.1** | **22.4** | the node's channel up and its feed fresh at the box's epoch |
|   `node.handshake` | 7.3 | 7.4 | hello, authentication, welcome |
|   (the feed's catch-up, applied on the node) | 24.5 | 14.6 | the frames the node persists before it says it is fresh (below) |
| `node.start` | 6.2 | 6.2 | the node's whole start of the box; Docker's calls in it: |
|   `node.start.docker.run` | 2.0 | 2.0 | create and start, two Engine API calls |
|   `node.start.proxies` | 2.0 | 2.0 | the node's per-box proxies, their sockets bound |
| **`started`** | **104.8** | **94.1** | when the supervisor learns the box runs |
| `node.teardown` | 6.8 | 6.7 | the node's part after the box exits (inspect, rm, release) |
| `teardown` | 15.1 | 14.8 | the control host's part after the exit (the audit flushed, the record saved) |

**Where the node's wait went.** Each start's catch-up is four frames: the feed key's certificate
(unchanged, not persisted: 0.04 ms), two deltas and a freshness statement. Each delta was appended and fsynced, and then `statements.json` was rewritten
(an atomic replace: fsync the file, rename, fsync the directory), about 8 ms per delta. The rewrite
wrote the same bytes: a delta leaves the newest statement alone, and moves `vouched` only when it
reaches a newer statement's epoch. Now it is skipped when nothing in the file changed: about 3 ms per
delta here, and `node.ready` 32 → 22 ms. The statement itself is still written (2 fsyncs): it carries
the replay floor that must survive a restart.

**What is left of wicket's own ~95 ms**, by kind:

- SQLite commits on the control host, one per write (`ledger`, `identity`, `quotas`,
  `authority.record`, and in `teardown`): these spans add up to about 58 ms here, mostly commits. They are the next cut: the start's writes
  in one transaction (one commit), and the ledger's schema statements run once per process instead
  of on every open.
- fsyncs on the node's feed: ~15 ms (two delta appends, the statement).
- the node's handshake, 7 ms (a fresh connection per run, with its authentication).
- computation (CA, token compile and mint, proxies): about 10 ms.

Docker's two calls took 2 ms against the stand-in. Through real dockerd, containerd and runsc they are
what `docker.run.create`, `.runtime` and `.return` separate, and they need a host with Docker: the
next section.

### On a host with Docker

`measure.sh` with a real Docker hasn't been run on a node yet. What has been measured is Docker and
the runtimes alone, without wicket: `runtime.sh` reads `docker.run.runtime` the way the node does,
from Docker's `Created` and `State.StartedAt`, and also `State.FinishedAt`, for a container
running `true` with no network.

```sh
experiments/box-start/runtime.sh -n 20 --label <host>        # runsc and runc; --runtime NAME for one
```

**2026-11-20, in a cloud sandbox, not a node** (a Firecracker VM, 4 vCPU, 15 GiB, cgroup v1, Docker
29.10.0 with the containerd snapshotter, gVisor release-20261116.0 with `--host-uds=open` as CI
installs it, its default platform; nothing else running). 20 starts per runtime after a warm-up,
`logs/runtime-ccr-firecracker-20261120T160300Z.jsonl`. Median (p90), ms:

| runtime | `docker.run.runtime` (Created → StartedAt) | Created → FinishedAt (`true` has run and exited) | `docker run -d`, the CLI's wall time |
|---|---:|---:|---:|
| runsc | 18.5 (21.1) | 94.8 (109.9) | 124.1 (142.2) |
| runc | 17.9 (20.2) | 102.6 (119.7) | 144.8 (162.6) |

- `docker.run.runtime` is ~18 ms for both. With runsc, `State.StartedAt` comes when `runsc start`
  returns, before the sandboxed process has run: the rest of gVisor's boot is after it, in
  `box.entry.runtime` and `box.entry.init` (148 ms on the control host's node, #287's step-3
  measurement), and here in Created → FinishedAt.
- Created → FinishedAt includes Docker noticing the exit (the shim, containerd, dockerd's event), so
  it is an upper bound on the start: under ~110 ms at p90 for runsc here, no slower than runc.
- This VM isn't a node: no KVM platform, cgroup v1, a different disk. A node's numbers can differ;
  the procedure below is how to get them.

**On a node** (still to do, by the coordinator):
1. On the node, alone: `experiments/box-start/runtime.sh -n 20 --label <node>`.
2. On the control host: `experiments/box-start/measure.sh -n 20 --node <node>`, and again with
   `--isolation runc`. Read `node.start.docker.run.runtime`, `box.entry.runtime` and
   `box.entry.init` from both.
3. For runsc's own settings, change `runtimeArgs` in `/etc/docker/daemon.json` (e.g. `--directfs=false`,
   `--platform=kvm` where `/dev/kvm` exists), restart Docker, and repeat step 1.
4. Add the rows to the table above and to [performance](../../docs/explanation/performance.md#docker-runsc-or-a-restore-287-step-3).
