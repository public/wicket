# What idle supervisors cost (#582 step 5)

Research note 25 (§6) estimates what step 5 saves at 10,000 boxes, from no measurements: a
supervisor's idle CPU, its resident memory, and the writes it makes while nothing happens. §7 asks
for a harness that measures them before anything is built on the estimates. This is that harness,
for today's model: one `wicket run` process per box.

## Method

`scale.sh` starts N `wicket run` processes, each supervising a program box that runs until it is
killed (`sleep 86400`), on this host's own node. Docker is the stand-in from
[box-start](../box-start/README.md) with `--hold`: containers start at once and run until killed,
so the boxes cost nothing, and what is measured is wicket's own per-run work: the supervisor, its
node channel, its timers, its ledger and feed traffic, and the node's side of them.

Once every box runs (the stand-in's `/_stats`), and 5 s more for the starts to settle, it samples
over a window (default 60 s):

| column | what | from |
|---|---|---|
| `start_all_s` | from the first `wicket run` to every box running | the stand-in's count |
| `sup_cpu_ms/s_each` | each supervisor's CPU, idle | `/proc/<pid>/stat` utime + stime, over the window, per supervisor |
| `sup_rss_MiB_each` | each supervisor's resident memory | `VmRSS`, averaged |
| `threads_each` | each supervisor's threads | `Threads`, averaged |
| `node_cpu_ms/s` | the node's CPU (`wicket node serve`), for all N | the same |
| `writes/s`, `write_KiB/s` | write syscalls, and bytes that reached storage, of every supervisor and the node: the ledger, the feed, run files | `/proc/<pid>/io` `syscw`, `write_bytes` |
| `adopt_all_s` | after every supervisor is SIGKILLed: one `wicket reconcile` pass until every run has an attach process that has held for 2 s and every box still runs | process list, the stand-in |

Each N runs with a fresh `WICKET_HOME` (a new ledger), removed after.

## Running it

On **pc5800**, one box, nothing else running there (#582). A release build:

```sh
cargo build --release -p wicket-cli
WICKET=$PWD/target/release/wicket experiments/supervisor-scale/scale.sh -n 100 -n 1000 -n 5000 --window 60 --label pc5800
```

Before 5,000, check the limits that `docs/reference/daemon.md#limits` lists for the user running it
(`ulimit -u`, `ulimit -n`, `kernel.pid_max`): here the supervisors are that user's processes, not
a unit's. One JSON line per N goes to `logs/scale-<label>-<time>.jsonl`.

## What it maps to in note 25 §6

| §6 row | column |
|---|---|
| resident memory (assumed 15–30 MB a process) | `sup_rss_MiB_each` |
| threads (about 6 a supervisor) | `threads_each` |
| a supervisor's idle CPU (7.7 ms/s before step 2, an upper bound) | `sup_cpu_ms/s_each` |
| heartbeat, presence and polling writes | `writes/s`, `write_KiB/s` (a program box has no agent heartbeat; an agent's adds one write every 5 s) |
| adoption after an update | `adopt_all_s` |

## Not measured here, and why

- **Supervisors as threads in a host** (§7's second arm): runs aren't supervised in hosts until
  item 3 of #582's step 5. The same script measures it then, against `supervise.hosts`.
- **Ledger write-lock wait and transactions a second**: SQLite doesn't count either from outside
  the process. `writes/s` is the proxy; counting commits needs a counter in the ledger's writer.
- **Agents.** A program box makes no model requests and no agent heartbeat. An agent manifest
  (with a stub model route) would add those.
- **A remote node.** Everything is on the local node (one unix socket, no ssh), so `MaxSessions`
  and per-session ssh cost aren't in it.

## Results

None yet: to be run on pc5800 (above). A check on a development container, N = 3 and 20 with a
debug build, found the harness working, and one fault in it: the stand-in's listen backlog (Python's
default, 5) refused a burst of 20 starts with EAGAIN. It is 4096 now, as Docker's is the kernel's
`somaxconn`. That run also showed, under 20 concurrent starts, the node refusing feed deltas it
already held ("delta 17 already applied (held 19)") and one run's shipped audit records ("do not
continue the node's chain"). The runs started anyway. These are worth a look at 1,000.
