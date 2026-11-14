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
| `proxies`, `proxies.sockets` | the run's egress, model and gateway proxies; the wait for their sockets (polled every 20 ms) |
| `plan` | the harness's or program's plan, the box's spec |
| `record` | `ctl/run.json` written |
| `node.local` | making sure this host's own `wicket node serve` runs |
| `token.keys`, `token.policy`, `token.mint` | the minting keys; block 0 compiled from Cedar; the box's token minted and published |
| `feed.publish` | the token committed to the node's feed |
| `node.ready` | from starting the node connection until the node is fresh on the feed at the box's epoch, made of `node.dial` (ssh, or the local unix socket), `node.handshake` (hello, authentication, welcome), `feed.catch_up`, `budget.lease` (the budget slice sealed and sent, #152) and `feed.fresh` (a moment) |
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
| `docker.image_inspect` | `docker image inspect` (twice for a pinned image not found by its reference) |
| `layout` | the box's directories, CA bundle, hosts file, workspace archive, state files, volumes |
| `proxies`, `proxies.sockets` | the node's per-box egress, model, HTTP/3 and DNS, gateway proxies; the wait for the egress socket |
| `docker.run` | `docker run -d`: the CLI, dockerd, containerd, the shim and runsc |
| `docker.run.create` | from the CLI starting until Docker had created the container (Docker's `Created`) |
| `docker.run.runtime` | from then until the runtime had started the box's first process (`State.StartedAt`): containerd, the shim, runsc's sandbox and gofer boot |
| `docker.run.return` | from then until the CLI returned |
| `docker.inspect` | the extra `docker inspect` the three spans above are read from (only with `WICKET_TIMINGS=1`) |
| `record`, `wire` | the box's record saved; its stdin socket, and `docker logs --follow` and `docker wait` spawned |

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

Not yet run: the numbers go here and in docs/explanation/performance.md (#287, step 1).
