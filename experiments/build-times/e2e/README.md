# End-to-end scripts: where their time goes (#219, item 4)

`profile.sh` runs a script under `bash -x` with a timestamp on every traced command, written to a
file of its own so the script's output is untouched. `analyze.py` then reports the slowest lines (a
function call or loop counts as the line that called it) and every `sleep` by line:

```sh
experiments/build-times/e2e/profile.sh OUT_DIR ci/node-e2e.sh --local
```

Measured on the shared 4-vCPU development host on 2026-11-13, one run each, with the same debug
binary, the agent image already built (`IMAGE=wicket/claude-code:poc`) and the static HTTP/3 client
prebuilt for `acceptance.sh`. Other sessions shared the host, so the times are ±10%.

## Before

| script | wall | fixed sleeps and polls | where the time went |
|---|---|---|---|
| `smoke.sh` | 56 s | 0 s | building the static HTTP/3 client (31 s; CI and `acceptance.sh` reuse it with `H3GET`), the agent's run (24 s) |
| `hibernate.sh` | 52 s | 17 s, 1 s polls | runs and wakes; polls wait for real work |
| `hibernate.sh --node` | 62 s | similar | as above |
| `restore.sh` | 89 s | 12 s, 6 fixed sleeps | enrolling a node, runs and wakes, the stream catching up |
| `node-e2e.sh --local` | 334 s | **320 s (96%)** | a 165 s cut of the control channel, then waiting for the box's 300 s authority to run out |
| `update.sh` | 926 s | 36 s | **packaging 7 builds (~65 s each: `gzip -9` of a 500 MB debug binary)**, the update to B (155 s) |
| `acceptance.sh` | 183 s | 98 s, mostly 1 s polls on real work | the lead's steps, the control-host restart, the output flood |
| `acceptance.sh --nodes local` | 943 s | 461 s | `node-e2e.sh` again (inside the multi-host flow, 446 s), the offline flow (304 s: fixed waits of 80, 75 and 20 s around a 165 s cut and a 5 min authority) |

The agent image is built once per CI job already (`wicket image` in the smoke job, whose steps all
use it; `acceptance.yml` builds `:acc` once). No script rebuilds it when `IMAGE` is set, except
`update.sh`, whose updates build each version's own image: that is what it tests.

Two checks fail on main, independently of these changes:

- `update.sh`, "a dry run says B would go, keeps its image while a container uses it". The stopped
  box that checked B's image is already gone when the dry run looks, so the image is listed for
  removal instead of kept.
- `acceptance.sh --nodes local`, the offline flow's "after the restart, still cut off" and "the miss
  while cut off is in the node's audit".

## After

| script | before | after | change |
|---|---|---|---|
| `update.sh` | 926 s | 476 s | builds are copies of the binary with its debug info stripped (`objcopy --strip-debug`: 115 MB instead of 500 MB), so packaging, hashing and sending them is 3–4× faster |
| `node-e2e.sh --local` | 334 s | 131 s | #235: a 30 s cut and a 100 s authority by default (the nightly run keeps 165 s and 300 s: 356 s, all checks ok); fixed sleeps replaced by waits on the box's own probe lines |
| `acceptance.sh --nodes local` | 943 s | about 740 s (expected) | runs `node-e2e.sh` inside its multi-host flow, so it saves the same ~200 s |

Evaluated and left as they are:

- `restore.sh`'s fixed sleeps (12 s). Two of them separate the point-in-time restore's timestamps,
  which have one-second resolution, and the rest let the stream catch up. Readiness checks there
  would save under 8 s, and add a way to flake.
- The 1 s polls in `hibernate.sh` and `acceptance.sh`. They wait on real work (runs, wakes, a lead's
  steps), so a shorter interval would save little.
- The offline flow in `acceptance.sh --nodes local` (fixed waits of 80, 75 and 20 s within a 5 min
  authority). Its checks are timed against a 165 s cut, and two of them fail on main. Left until
  that is understood.
