# 22 — Pause, resume and hibernate: what state a box has, and how to keep it

Research date: 2026-11-10. Scope: what it takes to put a wicket agent to sleep and wake it later, on the same host or
another one, under each isolation tier (gVisor now; Firecracker, Virtualization.framework and Kata later) and on
each provider (Vultr, Hetzner, AWS, GCP, Macs). It covers every option, from "mount a cloud block volume" to "copy
files to object storage ourselves", and ends with a recommendation for wicket.

Context: design §7 (sandboxes, parking), §7.2 (tiers), §7.3 (network modes), §8.5 (leases), §13 (long-lived
agents; §13.5 says "rebuild must always work; snapshots are an optimisation"; §13.8 sets the budgets); research 02
(isolation) and 10 (infrastructure); issues #8 (move a running agent), #29 (long-lived agents), #37 (placement),
#48 (macOS VZ), #56 (leases), #61 (OpenSandbox), #64 (Firecracker).

Confidence tags: **[H]** verified against a primary source (official docs, source code at a named commit, a
price list, or this machine). **[M]** secondary source, vendor marketing number, or partly verified. **[L]**
inference, not checked.

---

## 0. Summary

- **There are three levels of "keep the agent", and wicket needs all three, built in reverse order of
  sophistication.**
  - (a) A **live snapshot** (memory and disk) resumes mid-instruction.
  - (b) **Disk plus the agent's own session resume** (`claude --resume`) loses running processes but keeps the
    conversation and the files.
  - (c) A **rebuild** from durable state (manifest, workdir, session, memory versions) is (b) after the node is gone.

  §13.5 is right that (c) must always work. Every memory-snapshot mechanism surveyed refuses to restore across CPU
  feature sets, runtime versions or, on Macs, users and OS updates. So (a) is a cache in front of (c), never a
  replacement.
- **The cheapest durable store is object storage with our own sync, not block volumes.** Per-agent block volumes
  fail on every axis wicket cares about:
  - they're bound to a zone or location [H];
  - Vultr and Hetzner allow 16 per server [H];
  - the minimum size is about 10 GB [M];
  - Hetzner volumes have no snapshots at all [H];
  - none of them crosses providers.

  A content-chunked, encrypted, incremental tree sync to S3-compatible storage costs about $0.015–0.024 per
  GB-month [H]. It works the same on Vultr, Hetzner, AWS, GCP, R2 and a Mac, and fits §13.5's per-agent keys
  wrapped by tenant keys. Block volumes have a place only as node-local cache and, later, as a Firecracker VM's
  own disk within one zone.
- **For Claude Code, level (b) is most of the value.** Its whole conversation is a JSONL file under
  `CLAUDE_CONFIG_DIR/projects/<cwd>/<session>.jsonl` [H]. wicket already puts that dir at `/wicket/state/claude`.
  Resume is `claude -p --resume <id>` with the same cwd.
  - Lost on resume: running shells and dev servers, subagents mid-flight, in-memory MCP state.
  - Not lost: anything the model needs to carry on.
  - A memory snapshot also doesn't save model cost after a long sleep: the prompt cache expires in minutes to an
    hour [M], so the first turn after any long sleep re-reads the context uncached either way.
- **gVisor already has nearly everything needed for level (a):**
  - `runsc checkpoint` / `restore`;
  - background (lazy) restore, on by default [H];
  - an in-sandbox save/restore hook (`--save-restore-exec-argv`) [H];
  - a CPU-feature annotation to make images portable across hosts [H];
  - filesystem-only checkpoints (`runsc fscheckpoint`, `runsc tar rootfs-upper`) [H].

  The constraints:
  - restore needs **the identical runsc build** [H];
  - the CPU features must be a subset of the host's [H];
  - host-UDS connections are cut, and the forwarders must re-dial [H];
  - host bind mounts (workspace, state, volumes) are **not** in the image, are not validated on restore, and must
    be restored bit-identical by wicket [H];
  - Docker's checkpoint path is experimental and same-container only [H].

  So the gVisor level (a) needs wicket to drive `runsc` directly (§8.3's direct launch), not Docker.
- **Firecracker is the best level-(a) substrate when KVM exists:**
  - full and diff snapshots;
  - UFFD lazy memory;
  - vsock and network path overrides on load;
  - VMGenID and VMClock for clone and clock safety [H].

  It doesn't snapshot disks (that's the caller's job), and resumes only on the same CPU model and host kernel [H].
  **Apple VZ save/restore** works only for "Sleeping" on the same Mac: the file is hardware-encrypted to that Mac
  and user, needs the keychain unlocked, and a macOS update can invalidate it [H]. **Kata has no
  checkpoint/restore** [H]. **CRIU** is a poor fit for Node/Bun agents: libuv ≥ 1.50 always opens io_uring,
  which CRIU can't dump [H].
- **The product survey agrees:** E2B, Fly, Modal, CodeSandbox, Daytona, OpenSandbox, Agent Substrate, GKE Pod
  Snapshots, Sprites and Blaxel all keep memory only on matching hardware, and all drop external connections on
  resume. Several (Cloudflare, Vercel, Sprites' checkpoints, Daytona containers) ship disk-only persistence and
  call it enough. Wake-on-request is documented in detail only by OpenSandbox (park up to 5 s, then
  `503 + Retry-After`, with a single-flight resume) and Agent Substrate [H].
- **Resume is a security event, and five rules fall out of it:**
  1. **Restore at most once, verify before restore.** Each image is restored at most once (§7 already says so),
     after its signed manifest and digests have been checked, and only if the agent isn't revoked.
  2. **Keep the in-box crypto stable across a memory restore.** A running Node process has already loaded its CA
     bundle and placeholder tokens. So the per-agent CA and placeholders must survive a memory restore, unchanged,
     and be re-bound to the new socket. That refines §13.2's "new placeholders on every wake", which only holds for
     rebuilds.
  3. **A memory restore keeps the full label.** It keeps all ephemeral context too, so §13.3's "sleep is a
     declassification checkpoint" holds only for (b)/(c).
  4. **Any authority-relevant change forces a rebuild.** If the charter, image, adapter pin or policy epoch
     changed in a way the agent must see, wake by rebuild, not restore.
  5. **Leases keep running on the wall clock while asleep.** Expiry is checked on wake. Nothing authority-bearing
     lives in the box, so there's nothing in it to rotate.
- **The recommendation:**
  - **0.0.1:** level (c)/(b) only. Stop at a quiescent point; push the workspace, the session dir and volumes as
    one encrypted, signed bundle per agent (tar + zstd + XChaCha20-Poly1305) to object storage; rebuild and
    `--resume` on wake. Add `docker pause` for Idle.
  - **Next:** a content-defined chunk store for incremental pushes (the 60 s RPO) and cheap cross-host moves;
    direct `runsc` with local checkpoints for Sleeping; then checkpoints shipped to object storage, for
    hibernation with memory and #8 moves.
  - **Later:** Firecracker diff snapshots with UFFD on KVM pools; VZ save for Sleeping on Macs.
  - **First:** nine experiments (§9.6), starting with a runsc checkpoint of a real Claude Code box and a measured
    rebuild-and-resume.

---

## 1. What state there is

What a wicket box holds today (PoC: Docker with `--runtime runsc`; `crates/wicket-agent/src/lib.rs` and
`crates/wicket-cli/src/run.rs`) [H], and which level keeps each part:

| State | Where it lives now | Typical size | (a) live snapshot | (b) disk + session | (c) rebuild | Notes |
|---|---|---|---|---|---|---|
| Process memory and CPU state (Claude Code, its shells, subagents, dev servers, MCP clients) | gVisor sentry memory | Claude Code alone a few hundred MB [L]; plus whatever the agent runs | yes | **no** | no | The only thing (a) adds |
| Kernel state: fds, timers, pipes, in-box loopback TCP | gVisor sentry | small | yes; loopback TCP survives a gVisor restore [H] | no | no | Host-backed sockets don't survive (below) |
| Root filesystem writes (`/tmp`, `apt install`, `~/.cache` outside the state dir) | gVisor overlay upper layer: memory or a filestore file (`--overlay2=root:self` by default) [H] | MB to GB | yes: it's in the sentry's memory file and saved with the pages [H/M] | only if exported (`runsc tar rootfs-upper`) [H] | no (rebuilt from the image) | Treated as cache by default (§13.4) |
| Workspace `/workspace` | host directory, bind-mounted through the gofer | 10 MB to 10 GB; repos and `node_modules` | **no**: host files aren't in the image [H] | yes | yes | Durable state |
| Agent state dir `/wicket/state` (`claude/` = `CLAUDE_CONFIG_DIR`, `home/`) | host directory, bind-mounted | KB to tens of MB | no | yes | yes | Holds the **session transcript**, `file-history/`, task lists, plus files wicket regenerates (`settings.json`, the placeholder `.credentials.json`) |
| Volumes `/volumes/<name>` | host directory per tenant and zone, on whichever host ran the box | any | no | yes | yes | Lost today when a #37 node is destroyed |
| Sockets to wicket (`/wicket/sock/*`, through in-box forwarders at `wicket.internal`) | host UDS connected via `--host-uds=open` | — | **cut**: the host fd is closed on save and reads return EOF after restore [H] | re-made | re-made | Forwarders must re-dial |
| Upstream connections (model API stream, git fetch) | the proxy, outside the box; the box sees only its connection to the forwarder | — | cut | cut | cut | Park only at a quiescent point (§7 parking) |
| The run CA and placeholders | `/wicket/ca`, env vars, `.credentials.json`; loaded into Node's memory at start | KB | **kept in memory**: must stay valid | regenerated | regenerated | §6.4 |
| Agent's own session (Claude Code) | `state/claude/projects/-workspace/<session>.jsonl`, plus `<session>/subagents/` and `tool-results/` [H] | KB to tens of MB | yes | **yes, resumable with `--resume <id>`** | yes | Plaintext; swept after `cleanupPeriodDays` (default **30 days**) [H] |
| wicket-side: ledger rows, leases, pending requests, subscriptions, identity history, audit | SQLite/Postgres on the control host | — | n/a: never in the box | n/a | n/a | The authority. Never snapshotted with the box |
| wicket-side: identity document and key, socket bindings, proxy state | `wicket run` / wicketd memory | — | n/a | n/a | n/a | Re-issued on every wake (§3.2) |
| Memory stores (facts, skills) | wicket stores, versioned (§13.4) | — | n/a | n/a | n/a | Already durable; an activation starts from a fork |

Three things fall out of the table:
1. **The gVisor checkpoint image doesn't contain the durable state.** Workspace, state and volumes are host
   bind mounts. So every level needs the same "persist these three trees" machinery. (a) adds memory on top, it
   doesn't replace the trees.
2. **wicket-side state is never part of a snapshot,** and doesn't need to be. The box holds no authority, and
   that is exactly what makes restoring it safe.
3. **Claude Code's state dir is half durable state, half regenerated config.** Persist `projects/`,
   `file-history/` and `tasks/`. Overwrite `settings.json` and `.credentials.json` from the LaunchPlan on every
   wake, as §13.4 says.

---

## 2. The three levels

| | (a) Live snapshot | (b) Disk + agent session resume | (c) Rebuild from durable state |
|---|---|---|---|
| What's kept | Memory, CPU state, fds, rootfs writes, plus the trees saved at the same instant | Workspace, state dir (session), volumes; optionally the rootfs upper | Same as (b), but from object storage onto any node, with the current image and adapter |
| What's lost | External connections (all mechanisms) | Running processes: shells, servers, builds, subagents mid-run; in-memory MCP state; anything in `/tmp` | Same as (b) |
| Resume point | Mid-instruction | Between turns: Claude reloads the transcript and continues | Same as (b) |
| Wake latency | Local: tens of ms to ~1 s (gVisor 65–160 ms measured in an unmerged PR [H]; Modal 1.05 s p50 in production [H]; Fly "a few hundred ms" [H, vendor]; E2B ~1 s [H, vendor]). From object storage: plus the download (§5.2) unless lazily paged | Box start (≤ 1 s cold, §7.1) + Claude Code start (1–2 s) + transcript load + tree restore if not local | (b) + pulling the trees: seconds for 100 MB, longer for multi-GB `node_modules` unless chunk-cached or lazily loaded |
| Sleep cost | Image ≈ committed memory (zero pages excluded [H]); hundreds of MB per agent | Size of the trees, incremental | Same |
| Portability | Same runtime build; same or a superset of CPU features; same arch; same VMM version; on VZ, same Mac and user | Any node with the image | Any node, any provider, any tier |
| Fidelity risks | Clock jumps; cloned RNG state if restored twice; stale in-memory config (old charter, old CA) | Agent must tolerate "the shell I started is gone" | Same, plus image or adapter upgrades between sleep and wake |
| Fits budget (§13.8) | Idle ≤ 50 ms (freeze); Sleeping ≤ 2 s (local image) | Hibernated ≤ 10 s | Hibernated ≤ 10 s for small trees |

**The decision rule:**
- wake by (a) when a compatible image exists, nothing authority-relevant changed, and the agent was mid-task
  with live processes worth keeping;
- otherwise wake by (b) on the same node, or (c) anywhere.

The ladder in §13.2 maps onto this:

| §13.2 state | Mechanism |
|---|---|
| Idle | freeze (`cgroup.freeze` / `runsc pause`) |
| Sleeping | (a) image on node disk |
| Hibernated | (a) image and trees in object storage when compatible, else (c) |
| Archived | (c) only |

---

## 3. Memory and process snapshot mechanisms

### 3.1 gVisor `runsc checkpoint` / `restore` (source: google/gvisor master at dd49ce7, 2026-11-10)

**Flags** [H] (`runsc/cmd/checkpoint.go`, `restore.go`; https://gvisor.dev/docs/user_guide/checkpoint_restore/):

| Command | Flags |
|---|---|
| `checkpoint` | `--image-path`, `--leave-running` (checkpoint then immediate restore, so the PID can change), `--compression=none\|flate-best-speed` (default none), `--exclude-committed-zero-pages` (default true), `--direct` (O_DIRECT pages file), `--save-restore-exec-argv`, `--save-restore-exec-timeout` (default 10 min), `--fs-checkpoint-paths` (filesystem-only; accepts `all-tmpfs`), `--state-engine=wire\|graph`, the CUDA flags |
| `restore` | `--image-path`, `--detach`, `--direct-io`, `--background` (**default true**, needs an uncompressed image), `runsc wait --restore` to block until loading finishes |

Top-level flags must be repeated on `restore`. Rootless restore is rejected.

**Background restore** [H]:
- The application starts as soon as kernel state has loaded.
- Memory and file data stream in behind it, pages the app touches first loaded first.
- The image files stay open until loading finishes.

This is gVisor's equivalent of UFFD lazy loading, and the main lever for the ≤ 2 s budget.

**The save/restore hook** [H] (`pkg/sentry/control/state.go`):
- The sentry runs a binary inside the sandbox's mount and PID namespaces, with
  `GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE` set to `save`, `resume` or `restore`.
- A non-zero exit or a timeout fails the save or the restore.
- It can also be set by the annotations `dev.gvisor.internal.checkpoint.save-restore-exec-argv` and `...-timeout`.
- It's skipped while the kernel is paused, which is how Docker calls it.

For wicket this is `wicket-entry --hook`:
- on `save`, veto unless every forwarder is idle;
- on `restore`, re-dial the sockets, reseed the RNGs it controls, and re-read the in-box view of time.

**Image** [H] (`pkg/sentry/state/checkpointfiles`):
- `checkpoint.img` (kernel state and metadata), `pages_meta.img` and `pages.img`.
- `runsc statefile --get cpu_features` reads the CPU set back out.
- No published size figures exist. Expect roughly committed memory [L].

**What it does with each kind of host state** [H unless marked]:

| Host state | Behaviour |
|---|---|
| **`--host-uds=open` connections** (wicket's sockets) | The host fd is closed in `beforeSave`. After restore, reads return EOF. The forwarder must reconnect. (`--host-uds=create` listeners make the save panic, and wicket doesn't use them) |
| **Netstack TCP** | Reset on save, except over links with the SaveRestore capability. Loopback has it, so with `--network=none` all in-box TCP survives (`pkg/tcpip/transport/tcp/endpoint_state.go`). The agent's connection to the forwarder at `198.18.0.1` is loopback and survives. The forwarder's upstream UDS doesn't, so the forwarder must reset its matching client connections, or the agent sees a hang |
| **Gofer (bind-mounted) files** | Re-walked and stat'ed on restore; a missing path fails the restore [M]. Size and mtime checks exist in VFS, but runsc passes empty options, so **contents aren't validated** (`runsc/boot/restore.go`). Restoring against a workspace that changed silently mixes the sentry's cached view with new files. wicket must restore the trees bit-identical, and should record and check digests itself |
| **Deleted-but-open files** | Copied into the image |

**Compatibility** [H]:
- **The runsc version string must match exactly** (`runsc/boot/controller.go`).
- **CPU features:** the saved set must be a subset of the host's, and the amd64 cache line size must match
  (`pkg/cpuid`). The `dev.gvisor.internal.cpufeatures` annotation pins the exposed set at create time, so an
  image can move between hosts. `runsc cpu-features` lists a host's set.
- **Not checked:** the platform (systrap vs KVM) isn't saved, so it isn't blocked either, but it's untested [L].
- **TSC:** on systrap, restoring onto a host whose TSC is behind logs that timestamps will go backwards. Only the
  KVM platform can adjust the TSC (`computeTSCOffset`) [H for the code, L for the impact on cross-host moves].

**Clocks** [H]:
- `CLOCK_MONOTONIC` excludes the time spent checkpointed, so timers keep their remaining time.
- `CLOCK_REALTIME` and `CLOCK_BOOTTIME` jump forward, and BOOTTIME timers that came due fire.

**Latency** [H]: there are no official numbers.
- PR #12810 measured a cold restore of about 144 ms and about 65 ms with a reused ("warm") sentry under
  `--network=none`.
- It was **closed unmerged on 2026-04-03**: a sentry that has run untrusted code can't be trusted with the next
  one. wicket shouldn't want that mode either.

**Filesystem-only checkpoints** [H] (https://gvisor.dev/docs/user_guide/fs_snapshot/,
https://gvisor.dev/docs/user_guide/rootfs_snapshot/):
- `runsc fscheckpoint --image-path --path=/ [--leave-running]` is restored with
  `runsc create --fs-restore-image-path`, and containers can start while it loads. It needs the same runsc
  binary.
- `runsc tar rootfs-upper --file x.tar <id>` writes a plain tar of the overlay upper layer, which can be restored
  through an annotation plus `--allow-rootfs-tar-annotation`. That tar is portable across versions, because it's
  just a tar.
- Both need the default overlay with a disk-backed upper layer.

This is the gVisor way to keep rootfs writes at level (b).

**Docker, containerd and Kubernetes** [H]:

| Path | Status |
|---|---|
| `docker checkpoint` | **Experimental** (needs `experimental: true` on the daemon). Restore must reuse the *same* container. There is no `--checkpoint-dir` on restore (moby #37344) |
| gVisor's containerd shim | The standard `Checkpoint` task API returns `ErrNotImplemented`. Checkpointing goes through gVisor's own `GvisorTaskServer` |
| Kubernetes `ContainerCheckpoint` | Still beta in 1.37 |
| Pod checkpoint/restore (KEP-5823) | Alpha, aimed at 1.38, same node only |
| **GKE Pod Snapshots** | gVisor-based. Saves memory, rootfs, emptyDir and tmpfs, but not PVCs. Restore needs the same machine series, CPU vendor, features, gVisor version and pod-spec hash; connections close and the IP changes (https://docs.cloud.google.com/kubernetes-engine/docs/concepts/pod-snapshots) |

So in wicket, gVisor level (a) means direct `runsc` (§8.3), and on GKE Pod Snapshots are an optional backend.

### 3.2 CRIU (runc and the process tier)

- **CRIU 4.3** (2026-10-19) [H] (https://criu.org/Download/criu/4.3):
  - lz4 page compression, streaming, lazy pages via userfaultfd, page-server over TLS;
  - TCP repair (`--tcp-established`);
  - `criu cpuinfo` checks;
  - ghost files.
- **External named Unix stream sockets can't be dumped** [H] (https://criu.org/External_UNIX_socket). That is
  exactly wicket's socket model.
- **Privileges** [H]: `CAP_CHECKPOINT_RESTORE` (5.9+) plus ptrace. Seccomp-filtered tasks need `CAP_SYS_ADMIN` in
  the init user namespace, which the process tier's design forbids.
- **The killer for agents** [H]:
  - libuv ≥ 1.50 always creates an io_uring ring (`uv__use_io_uring` in `src/unix/linux.c`);
  - CRIU has no io_uring support (PR #1597 closed unmerged, issue #2131 open);
  - the seccomp profile in §7 denies io_uring, which would make libuv fall back [L], but it's still a fragile
    base.
- **Tooling** [H]: podman `checkpoint --export` / `restore --import` moves containers between hosts with the rootfs
  diff. `rust-criu` 0.6.1 drives CRIU over its RPC. youki can checkpoint but has no restore command.

**Verdict:** the process tier parks by **freeze only** (as §7 already says). CRIU isn't worth building on for
Node or Bun agents.

### 3.3 Firecracker (v1.18.0, 2026-11-09)

All [H] from https://github.com/firecracker-microvm/firecracker/tree/main/docs/snapshotting unless marked.

**Snapshot kinds:**
- **Full snapshots** hold all of guest memory plus the vmstate.
- **Diff snapshots** hold the pages dirtied since the last snapshot, as a sparse file. They're still a developer
  preview, and they need `track_dirty_pages` set on every load: it isn't saved.
- `snapshot-editor edit-memory rebase` merges diffs onto a base, applied in creation order.

**Memory backends:**
- `File`: `MAP_PRIVATE`, demand-loaded; the file must stay present and unchanged for the VM's whole life.
- `Uffd`: an external handler serves page faults with `UFFDIO_COPY`. The example is
  `src/firecracker/examples/uffd/on_demand_handler.rs`. The VM hangs if the handler dies. `2M` huge pages need
  Uffd.

**Load options:** `resume_vm`, `network_overrides`, `vsock_override` (a new host UDS path, since 1.16), and
`clock_realtime` (x86_64, 1.16+; the guest wall clock jumps forward; without it the guest must fix its own
clock).

**What a snapshot leaves out:**
- **Disks.** "The separate block device file components of the snapshot have to be handled by the user."
  Firecracker drains and fsyncs them. The vmstate refers to them by path.
- **vsock connections.** `TRANSPORT_RESET` is sent at snapshot *creation*: the guest closes every connection,
  and listeners survive. So the source VM loses its connections too if it keeps running.
- **MMDS data,** logger and metrics config.

**Compatibility:**
- identical software and hardware;
- across host kernels is "unstable";
- not across CPU models unless the guest-visible features are identical (CPU templates mask CPUID, but masked
  instructions still run);
- never Intel↔AMD;
- format version checked on load.

**Uniqueness and clocks:**
- Firecracker changes the **VMGenID** on resume, and Linux ≥ 5.18 reseeds its RNG. There is a race window, so
  the docs also recommend `RNDADDENTROPY` + `RNDRESEEDCRNG`.
- User-space PRNGs have "no generic solution".
- Treat snapshot files as secrets.
- **VMClock** (1.15+) exposes `vm_generation_counter`, which guests can poll. The guest side merged in Linux 7.0
  (https://uapi-group.org/specifications/specs/vmclock/).

**Shrinking snapshots:** balloon free-page hinting and reporting (1.14, developer preview) zero freed pages before
a snapshot. `sync_snapshot_files=false` (1.17) is faster but not crash-safe.

**Latency:** the docs publish no snapshot-load figures [H, negative]. The papers in [10 §4.1] give a VMM load of
about 50 ms plus page faults, and REAP/FaaSnap prefetch cuts the fault cost [H]. Vendor figures: CodeSandbox
200–300 ms resume [M]; Fly "a few hundred ms" [H, vendor].

**Rust:** `fctools` 0.6.0 (0.7.0-alpha.2, May 2026) [H].

### 3.4 Cloud Hypervisor (v54.0, 2026-10-14)

[H] https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/snapshot_restore.md

- **Commands:** `ch-remote pause` + `snapshot file:///dir` writes `config.json`, `state.json` and
  `memory-ranges`. Disks aren't included.
- **Restore:** `--restore source_url=…,resume=true,memory_restore_mode=ondemand|copyonwrite[,prefault=on]`.
- **Version history:**
  - v52: userfaultfd on-demand restore; vsock connections reset;
  - v53: background prefault, and the guest clock advanced on resume;
  - v54: copy-on-write restore, and VMGenID changes on every restore.
- **Live migration:** `send-migration` with precopy or postcopy, compatible with the previous two releases.
  This is a real #8 path, where wicket owns both hosts.
- **Rust:** `cloud-hypervisor-client` 0.6.0 (unofficial) [M].

### 3.5 Kata Containers

- **No checkpoint/restore** [H]: "The runtime does not provide `checkpoint` and `restore` commands"
  (docs/Limitations.md).
- VM templating and VMCache exist for **start-up speed only**, with QEMU only [H].
- So a Kata pool parks by freeze, or by (b)/(c).

### 3.6 Apple Virtualization.framework

**API** [H] (developer.apple.com: `saveMachineStateTo(url:)`, `restoreMachineStateFrom(url:)`,
`validateSaveRestoreSupport()`):
- macOS 14+.
- Save needs a paused VM. Restore needs a stopped VM with the identical configuration, and leaves it paused.
- Custom virtio devices default to `supportsSaveRestore = NO`.

**Tied to one Mac and user** [H] (WWDC23 10007; Apple forums 782007):
- The file is "hardware encrypted… No other Mac or user account can read another's save file".
- It's keychain-protected, so the Mac must be **unlocked**, which matters for headless restores.
- A newer OS rejects older files, and a software update can invalidate them.
- A changed MAC address makes restore fail.
- Disk images must be copied separately.

**Unknowns:**
- Tart's suspendable mode keeps the vsock and directory-sharing devices but drops entropy and audio [M]. Whether
  vsock connections survive is **unverified**; assume they drop [L].
- An Encore post claims saving needs a private entitlement [M]. Tart ships suspend as a third-party app, so this is
  doubtful [L].

**Tooling:**
- `objc2-virtualization` 0.3.2 exposes save and restore [H].
- Apple's `container` CLI has no suspend [H].

**Verdict:** VZ save is a **Sleeping**-tier mechanism (same Mac, minutes to hours). Hibernate on a Mac is (b)/(c).

### 3.7 Mechanisms compared

| | gVisor runsc | CRIU (runc) | Firecracker | Cloud Hypervisor | Kata | Apple VZ |
|---|---|---|---|---|---|---|
| Memory snapshot | yes | yes (fragile for Node) | yes, full + diff | yes | **no** | yes (macOS 14+, arm64) |
| Lazy restore | background restore, default on | lazy-pages (uffd) | UFFD handler / mmap | `ondemand` (uffd), `copyonwrite` | — | no [L] |
| Disk in snapshot | rootfs overlay yes; bind mounts **no** | rootfs diff via podman export | **no** | **no** | — | **no** |
| Connections to host | host UDS cut; in-box loopback TCP kept | external UDS stream not dumpable | vsock reset | vsock reset | — | unverified; assume cut |
| Cross-host | same runsc build; CPU-feature subset (pinnable) | same CPU caps (`cpuinfo`) | same CPU model and host kernel | n-2 for migration; snapshot rules undocumented | — | **same Mac and user only** |
| Clone safety | restore once; host RNG for the sentry | — | VMGenID, VMClock | VMGenID (v54) | — | — |
| Clock | MONOTONIC paused; REALTIME jumps | — | optional `clock_realtime`; VMClock | advanced on resume (v53) | — | — |
| Hook in the guest | `--save-restore-exec-argv` | action scripts | guest agent over vsock (ours) | ours | — | ours |
| Needs | nothing special | CAP_CHECKPOINT_RESTORE / SYS_ADMIN | KVM | KVM | KVM | Mac |
| wicket tier use | Sleeping, Hibernated, #8 moves | none (freeze only) | Sleeping, Hibernated, clones | GPU or migration pools | freeze only | Sleeping only |

---

## 4. How products do it

Detail and sources in the per-product notes below; tags as given.

| Product | Mechanism | Memory kept | Resume (published) | While paused | Cross-host | Auto-pause / wake |
|---|---|---|---|---|---|---|
| **E2B** | Firecracker; memory + disk diff vs template in object storage; UFFD [H] | yes (falls back to filesystem-only if the node refuses for ~2 min) [H] | pause ~4 s/GiB, resume ~1 s [H, vendor] | kept until killed [H] | yes [L] | `onTimeout: "pause"`, `autoResume` [H] |
| **Fly Machines `suspend`** | Firecracker snapshot; ≤ 2 GB RAM, no swap [H] | yes | "a few hundred ms" [H, vendor] | rootfs $0.15/GB-month; snapshot "not guaranteed to persist", dropped on host migration or deploy [H] | **no** | fly-proxy `auto_stop_machines = "suspend"` [H] |
| **Modal Functions** | gVisor checkpoint; one lazily loaded pages file [H] | yes | 1.05 s p50 (2025) [H] | re-taken on platform updates | same CPU flags only [H] | restored automatically on cold start |
| **Modal Sandboxes** | filesystem / directory diff images; memory snapshot (`_experimental_`) [H] | memory: experimental | — | filesystem 30 days; memory 7 days [H] | same instance type [H] | no |
| **CodeSandbox** | Firecracker; mmap then UFFD with lz4 8 KiB chunks [M] (pages 403'd) | yes | 200–300 ms [H, 2022 post] | — | — | timeout 1 min–24 h; any request wakes [M] |
| **Daytona** | containers: stop/archive (disk); VMs: pause, hot snapshot, fork [H] | VMs only | VM "< 1 s" [M] | archive to object storage after 7 days [H] | archive yes | auto-stop 15 min, auto-pause 60 min [M] |
| **OpenSandbox 1.2.0** | Firecracker vmstate + memory + reflinked rootfs to an artifact store [H] | yes | target P95 < 500 ms on the same node; ~16 s to pull 3.5 GiB from the store [H] | — | yes (fast-sandbox PR #59) | `idlePolicy`; ingress parks requests (≤ 1024, 5 s budget, then 503 + `Retry-After: 1`, single-flight resume fenced by checkpoint id, buffered ≤ 1 MiB bodies replayed once) [H] |
| **Agent Substrate** (CNCF Sandbox; GKE) | gVisor `runsc` checkpoint or Cloud Hypervisor; snapshots on local disk + GCS [H] | yes | "< 500 ms", > 500 activations/s [M] | pay while active (GKE) | yes: any free worker | router resumes on request; parks requests when no worker is free (PR #221) [H] |
| **GKE Pod Snapshots** | gVisor, whole pod to GCS [H] | yes | kernel "a few seconds", then memory streams [H] | — | same series, vendor, features [H] | restored when a matching pod starts |
| **Cloudflare Containers / Sandbox** | sleep = stop; filesystem snapshot (beta 2026-09-30) or R2 backup [H] | **no** | cold 1–3 s [H] | snapshot 30 days; backup 3 days [H] | yes | `sleepAfter` (10 min default); the next request starts fresh [H] |
| **Vercel Sandbox** | filesystem snapshot on stop [H] | no | — | 30 days from last use [H] | yes [L] | SDK call auto-resumes [H] |
| **Sprites (Fly)** | warm = suspended VM, cold = stopped; checkpoints are disk overlay only [H] | warm only | warm 100–500 ms, cold 1–2 s [H] | no compute charge | — | idle ~30 s; HTTP wakes [H] |
| **Blaxel** | full-state standby [M] | yes | "< 25 ms" [M] | snapshot storage only [M] | — | standby after ~15 s idle [M] |
| **Morph Cloud** | memory + disk snapshots, branching [H] | yes | "< 250 ms" [M] | storage only [H] | — | — |

**Patterns that matter for wicket:**
1. **Nobody keeps external connections.** Every memory-keeping product drops them or says not to rely on them.
   Clients reconnect. wicket's forwarders must too.
2. **Memory images are hardware-pinned everywhere.** Fly simply discards them on host migration. Products that move
   memory across hosts (E2B, OpenSandbox, Substrate, GKE) restrict the target pool to matching hardware.
3. **Disk-only is a respectable product.** Cloudflare, Vercel, Daytona containers and Sprites' checkpoints all ship
   only (b)/(c), plus a fast cold start.
4. **Wake-on-request is a router feature:** single-flight resume, a bounded parking lot, a time budget, then
   `503 + Retry-After`, with the restore continuing in the background (OpenSandbox's is the clearest spec).
5. **OpenSandbox's cross-host design is wicket's plan in miniature:** reflinked rootfs + vmstate + memory pushed
   to an artifact store, a preference for the node that took the checkpoint, and a pull from the store otherwise.
   Its 16 s for 3.5 GiB is a warning about full-image pulls; lazy paging matters.

---

## 5. Keeping the disk state

The owner's framing: "options ranging from mounting EBS volumes into the container to copying files around to a
blockstore ourselves". In order of how much the provider does for us:

### 5.1 Cloud block volumes

| | $/GB-month | Binding | Max per server | Snapshots | Attach |
|---|---|---|---|---|---|
| **AWS EBS gp3** | $0.08 us-east-1; $0.0928 London [H] | one AZ [H] | most Nitro types: 28 slots shared with ENIs; some up to 128 [H] | incremental, in S3, restorable in any AZ of the region; $0.05/GB-month (London $0.053) [H]. Restored volumes load lazily from S3; Fast Snapshot Restore costs ~$540/month per snapshot per AZ [H] | hot; AWS publishes no latency [L: seconds] |
| **Vultr Block Storage** | NVMe ~$0.10 ("$1 per 10 GB") [M]; HDD $0.025–0.04 (sources conflict) [M] | one location [H] | 16 [H] | documented, but the FAQ answer contradicts it [H, conflicting] | `live: true` attaches without restart; the default restarts the instance [H] |
| **Hetzner Volumes** | ~€0.044 before April 2026, ~30% more since [M] | one location [M] | 16; 10 GB–10 TB [H] | **none** ("we do not provide Backups or Snapshots for Volumes") [H] | hot; a first attach may need a power cycle [H] |
| **GCP PD / Hyperdisk** | pd-balanced ~$0.10; Hyperdisk Balanced ~$0.08 + IOPS [H] | zonal (HA variant: 2 zones) [H] | not on the page [M: 128] | ~$0.05; global snapshots restorable in any region [H] | Hyperdisk multi-writer up to 8 VMs [H] |

**Why this is the wrong home for a hibernated agent's state:**
- **Granularity and limits.** One volume per agent means at most 16 hibernated or running agents per Vultr or
  Hetzner server. With about a 10 GB minimum, each costs $0.25–1/month even when the agent's state is 50 MB [M].
- **It doesn't move.** A volume is bound to one zone or location. Moving an agent to another region or provider,
  as #8 and §8.4 want, means copying the data anyway.
- **It doesn't snapshot portably.** The snapshots that exist are provider-specific and restore only inside that
  provider. Hetzner has none.
- **Attach is slow and stateful.** Attach and detach go through the provisioner (the only holder of cloud
  credentials, §8.5), take seconds [L], and can need a restart (Vultr's default, Hetzner's first attach). That
  doesn't fit a ≤ 2 s wake.
- **There's no local equivalent on a Mac.**

**Where block volumes do fit:**
1. **Per-node disk** for the chunk cache and Sleeping images, sized per node, not per agent.
2. **A Firecracker VM's own virtio-block device** within one AZ. The guest's filesystem is never mounted by the
   host kernel, which keeps §7's rule, and a move within the zone is detach plus attach.
3. **Large per-zone datasets** (hundreds of GB) that are too big to sync, with placement pinned to the volume's
   zone.
4. **EBS snapshots as a lazy-restore trick** inside AWS: a restored volume pages in from S3 on first access [H].
   It's AWS-only, so at most an optimisation for an AWS pool.

### 5.2 Object storage, synced by wicket

| | $/GB-month | Egress | Requests | Notes |
|---|---|---|---|---|
| AWS S3 Standard | $0.023; London $0.024 [H] | $0.09/GB [H] | PUT $0.005/1k, GET $0.0004/1k [H] | |
| **Cloudflare R2** | $0.015 (IA $0.01) [H] | **free** [H] | A $4.50/M, B $0.36/M [H] | Best for cross-provider moves |
| Backblaze B2 | ~$0.007 [H] | free up to 3× stored [H] | free [H] | |
| Hetzner Object Storage | €6.49/month incl. 1 TB + 1 TB egress, then ~€6.35/TB [H] | €1/TB [H] | free [H] | **64 KB minimum billable object**; three German and Finnish locations [H] |
| Vultr Object Storage | Standard $18/month incl. 1 TB + 1 TB transfer [M] | $0.01/GB [M] | — | colocated with Vultr nodes |
| GCS Standard | ~$0.020 [M] | ~$0.12/GB [M] | A $0.005/1k [H] | |
| Self-hosted | MinIO's community repo is **archived** (proprietary AIStor now) [H]; Garage (Rust) v2.5.0 [H]; SeaweedFS 4.53 [H]; RustFS 1.0.5 [H] | | | §13.5's "MinIO locally" should become Garage, SeaweedFS or a plain directory backend |

**Cost of keeping one agent** [L, arithmetic]:
- 500 MB of trees plus 500 MB of compressed memory image costs about $0.015/month on R2 and $0.024 on S3.
- A cross-provider wake that pulls 1 GB costs $0 from R2 and about $0.09 from S3.
- Requests dominate only if small files are stored one per object: 100k `node_modules` files at
  $0.005/1k PUTs is about $0.50 per snapshot [H prices]. **Pack small files** into large objects.

**How to sync the trees:**

| Approach | Incremental | Dedup | Encryption | Restore | Rust | Fit |
|---|---|---|---|---|---|---|
| **tar + zstd per snapshot** | no (or GNU incremental tar) | no | add our own (XChaCha20-Poly1305 / age) | download one object, stream-extract; zstd level 1 ~1.5 GB/s decompression [H] | `tar` 0.4.46, `zstd` 0.14.3, `chacha20poly1305` 0.11, `age` 0.12.1 [H] | **0.0.1**: simple and auditable; fine below a few hundred MB |
| **Content-defined chunks + packs** (restic model) | yes | within a repository | per repository | fetch the index, then the missing packs; a local chunk cache makes moves cheap | `fastcdc` 5.0.0, `rustic_core` 0.13.0 (restic format, "less mature than restic") [H] | **Next**: the 60 s RPO, #8 moves, large `node_modules` |
| casync / desync | yes (index + chunk store) | across anything sharing a store | none | `desync mount-index` mounts lazily over FUSE; reflink seeding [H] | bita is a Rust analogue [H] | Good ideas (seeds, lazy mount); no encryption |
| rclone sync | per file | no | `crypt` remote | per file | Go | Not for small-file trees |
| git (WIP commits to a wicket-held bare repo) | yes | yes | no (encrypt the repo) | `git fetch` | `gix` [L] | Only the repo part of a workspace; ignores `node_modules` and untracked files |

**Dedup and per-agent keys pull against each other** [L]. Convergent encryption across agents leaks "these two
agents have the same file", which is why restic randomises its chunker per repository [H]. The practical split:
- **base content** (image layers, a lockfile-keyed `node_modules`, a git commit) isn't stored per agent at all.
  It's re-derived, or kept under a tenant or base key;
- **each agent's delta** is chunked under the agent's own key, with dedup only within that agent's history.

Crypto-shredding the agent key then kills exactly the agent's own data (§13.6).

### 5.3 Lazily loaded and network filesystems

| | What | First access | Consistency | Licence / maturity | Under gVisor | Fit |
|---|---|---|---|---|---|---|
| JuiceFS | metadata engine (Redis/SQL) + object store | on demand via a local cache [H] | close-to-open; `--writeback` can lose data [H] | Apache-2.0, v1.4.2 [H] | host mount, bind-mounted through the gofer [L] | A metadata database per installation; overkill for per-agent state |
| **ZeroFS** | Rust; NFS/9P/NBD on S3; slatedb LSM; XChaCha20-Poly1305 [H] | memory and disk cache [H] | xfstests and Jepsen tested [H]; single writer [L] | **AGPL-3.0**, v2.3.6 [H] | as NFS or 9P from the host [L] | Interesting for lazy hibernated volumes; AGPL and youth are risks |
| mountpoint-s3, s3fs, gcsfuse | object-per-file FUSE | — | no random writes, no rename [H] | — | — | **Unsuitable** for git and `node_modules` |
| AWS EFS | managed NFS | network | close-to-open | $0.30/GB-month + per-GB I/O [H]; AWS only | host mount [L] | No |
| CephFS / RBD | distributed | — | strong | heavy ops (≥ 3 nodes) [L] | — | No |
| stargz / SOCI / nydus / overlaybd | lazy **image** layers [H] | chunks on demand | read-only (overlaybd: writable block layers) | mature | gVisor needs the image on the host first [L] | For base images (§7.1 technique 1), not agent state |

A FUSE server inside gVisor works (the sentry has its own `/dev/fuse`) [H]. A host-side mount bind-mounted in is
the simpler route [L].

**Verdict:** lazy filesystems are a later optimisation for large hibernated volumes. The baseline is "pull the
chunks you need into the node's cache, then start".

### 5.4 Local copy-on-write snapshots, shipped as diffs

| | Diff | Encrypted send | Fit |
|---|---|---|---|
| btrfs `send -p` | incremental stream between read-only snapshots [H] | no | point-in-time copies on a btrfs node data dir |
| **ZFS `send -i` / `-w`** | incremental; raw send of encrypted datasets without keys [H] | **yes**: an untrusted receiver for free | strongest local option; ZFS on every node is an ops cost |
| LVM thin + `thin_delta` | block mapping diffs [H] | no | block-level, FS-specific; we'd ship blocks ourselves |
| **overlayfs upper dir** | the upper dir *is* the diff (whiteouts 0/0, `trusted.overlay.opaque`) [H] | no | already wicket's workdir model (§7); turn off `redirect_dir` and metacopy for portability [L] |
| XFS/btrfs reflinks | instant local clones [H] | no | **ms-scale point-in-time copies** to upload from |
| APFS `clonefile` | instant local clones [M] | no | the Mac equivalent |

Provider block snapshots aren't diffs wicket can ship elsewhere, and filesystem send streams tie both ends to the
same filesystem. A **reflink copy taken during a freeze, then chunked and uploaded** is portable and only needs
XFS or btrfs on the node's data dir [L]. Vultr's stock image is ext4 [L], so a node would format its data disk as
XFS with `reflink=1` at bootstrap.

### 5.5 Consistency and quiescing

- **Crash-consistent** means "the state a power cut would leave". Git and SQLite recover from that, but a file-by-file copy taken while writes continue can be worse than a crash: torn SQLite, refs pointing at objects not yet copied [H] (https://www.sqlite.org/howtocorrupt.html; git's `core.fsync` default "risks losing recent work").
- **So take a point-in-time copy:** freeze the box (`cgroup.freeze` or `runsc pause`), copy, thaw. The copy is a reflink or overlay snapshot; on ext4 it's a full copy, so the freeze lasts as long as the copy.
- **gVisor caveat** [L, to test]: the sentry may hold dirty file data for gofer mounts in its own page cache. A host-side copy during `runsc pause` can then miss recent writes. Run `sync` inside the box (through the control channel or the save hook) before pausing, or stop the box cleanly. At level (c) the natural quiescent point is "turn ended, no tool running, the stream-json session closed after `idle_timeout`" (PoC §13.5), then a clean stop.
- **Active checkpoints (RPO 60 s)** while the agent runs:
  - session JSONL is append-only, so copying it is safe;
  - the workspace needs a ~10 ms freeze plus a reflink snapshot, then an upload from the snapshot in the background.

### 5.6 Encryption, as §13.5 requires

**Envelope encryption:**
1. A random 256-bit data key per agent.
2. Chunks and packs sealed with XChaCha20-Poly1305 (random nonces are safe at this scale) or AES-256-GCM.
3. The data key wrapped by the tenant key: KMS in production, the vault or `age` X25519 recipients locally.

**KMS pricing:**

| | Per key | Per request |
|---|---|---|
| AWS KMS | $1 per key per month | $0.03 per 10k requests |
| GCP Cloud KMS | $0.06 per software key version per month | $0.03 per 10k operations |

All [H]. So: **one KMS key per tenant, per-agent keys wrapped by it** [L].

**Never trust the store:**
- Object names reveal only `tenant/agent/sequence`; manifests are encrypted too.
- Integrity comes from AEAD tags plus a signed manifest of digests (§6.8).
- A provider-side server-side encryption setting is a second layer, never the first.

---

## 6. Security and correctness of resume

### 6.1 Clones and randomness
- **Restore each image at most once** (§7 already says so) and never resume the source after a snapshot. That
  avoids most clone problems.
- **Warm-pool clones are the exception:** restoring one pristine snapshot many times (§7.1 technique 3). Snapshot
  them *before* anything identity-bearing or random is generated in user space.
  - **Firecracker:** VMGenID plus explicit `RNDRESEEDCRNG` [H].
  - **gVisor:** the sentry takes `getrandom` from the host, so kernel-level randomness is fresh [L]. User-space
    pools (Node's crypto DRBG, V8's `Math.random` state, UUID generators) are duplicated, so the restore hook must
    reseed what wicket controls, and agents must not be cloned after start.
- **Mark every image** `clone_safe: bool` in its manifest. Only pristine images are clone-safe.

### 6.2 Clocks and timers
- **gVisor:** MONOTONIC pauses and REALTIME jumps [H]. Node timers run on the monotonic clock, so a 10-minute
  `setTimeout` keeps its remaining time. Wall-clock logic sees the jump.
- **Firecracker:** without `clock_realtime` the guest wall clock *lags* until something fixes it [H]. The guest
  shim must step the clock from the host on restore. Otherwise a box whose clock lags rejects the proxy's freshly
  minted leaf certificates as not yet valid (`notBefore` in its future), even though it only ever talks TLS to
  wicket's own certificates (§9) [L].
- **What wicket checks:** leases, identities and grant expiry are judged on wicket's clock, never the box's (§3.2
  "trusted time"), so a box with a wrong clock can't extend anything.
- **Fly** documents the same lag until NTP syncs [H].

### 6.3 Connections and sockets
- **Cut on restore:** host UDS in gVisor (EOF) [H], vsock in Firecracker (reset at snapshot creation) [H], and
  vsock in Cloud Hypervisor [H].
- **The in-box forwarders (`wicket-entry`) must:**
  1. re-dial the sockets or vsock ports on restore. Firecracker's `vsock_override` and gVisor's re-bound mounts
     let the *new* host path differ;
  2. reset any agent-side loopback connection whose upstream died, so the agent retries instead of hanging;
  3. refuse to be checkpointed with a request in flight (the save hook veto).
- **A quiescent snapshot means no partial requests,** because wicket parks only after the gateway has answered
  *pending* and the agent has gone quiet (§7 parking step 1).
- **TLS between the agent and the proxy:** session tickets and keys in the box's memory survive a restore. The proxy
  should refuse resumption across activations (new session caches per activation) [L]. That costs one full
  handshake after wake, which is negligible.

### 6.4 In-box material that a memory restore keeps
A memory-restored Node process keeps:
- the environment it started with: `CLAUDE_CODE_OAUTH_TOKEN` placeholder, `WICKET_RUN`;
- the CA bundle it loaded at start (`NODE_EXTRA_CA_CERTS` is read once [L]);
- the system prompt and charter text it was given.

Hence three rules:
- **Placeholders are markers, not secrets.** The proxy authenticates by socket (§3.2). So on a memory restore,
  wicket re-binds the *old* placeholder values to the new socket and activation, instead of minting new ones.
  Per-agent placeholder values (stable across activations) make this trivial. §13.2's "new placeholders on every
  wake" stays true for rebuilds.
- **The per-agent (or per-zone) CA must outlive the snapshot.** The proxy must keep presenting leaf certificates
  chained to the CA the box loaded. Its private key stays outside the box, wrapped by the agent key. Rotating the
  CA forces a rebuild.
- **Stale instructions force a rebuild.** If the charter, adapter pin, image digest or a narrowing policy change
  must reach the agent, wake by rebuild, or deliver a trusted operator message saying so. Enforcement is outside
  the box, so a stale prompt can't *widen* anything. It can only make the agent attempt things that are now
  denied.

### 6.5 Identity, leases and revocation while asleep
- **Nothing to rotate in the box:** identity keys never enter it (§3.2). On wake, wicket issues a fresh 10-minute
  identity document naming the new activation and node, and the ledger records the sleep/wake pair. An identity
  document that expired while asleep is simply history.
- **Leases keep running on the wall clock** (#56). Anything that expired while asleep is denied on the first use
  after wake, and becomes a pending request in the usual way. Work-item grants don't survive sleep at all (§13.4).
  A pending request survives only as a ledger entry, which may itself be a wake trigger.
- **Revocation and the kill switch must cover sleeping agents.** `wicket identity revoke` (or a tenant's "stop
  everything") marks every image and tree of the agent **unrestorable** in the ledger. Restore and rebuild both
  check that flag. Deleting the agent crypto-shreds its key (§13.6). The node-side cache must also honour the flag,
  because a Sleeping image sits on the node's disk.
- **A node lease (§8.5) pins a Sleeping agent's node.** At the paid-hour boundary, the agent goes down a level
  (Sleeping → Hibernated), or the node is kept and billed. Under Vultr's per-started-hour billing that is a real
  per-hour decision.

### 6.6 Labels and taint
- **A snapshot carries the agent's label at the moment it was taken,** and every blob in it carries the zone's
  `conf` label (§7).
- **§13.3 says sleep is a declassification checkpoint,** with the label reset to what the agent *keeps*. That holds
  only for (b)/(c): the session transcript, the workdir and approved memory. **A memory snapshot keeps everything,
  so a level-(a) wake keeps the full floating label.** To shed taint, wake by rebuild, optionally with
  `--resume <id> --fork-session` from a clean transcript entry (Claude Code supports both flags [H]).
- **Volumes and workspaces keep their taint** across any level, as stores do (§12).

### 6.7 What a snapshot contains (no credentials, but plenty of data)
- **A memory image or tree has, by design,** no upstream credentials, no identity keys and no cloud keys. It does
  have:
  - placeholders;
  - the public CA certificate;
  - every file the agent read;
  - every model response and tool output;
  - the transcript (plaintext by Claude Code's design [H]);
  - environment variables;
  - anything upstream sent *back*.
- **Watch the response path.** The proxy injects credentials into requests, never responses. An upstream that
  echoes a token (an OAuth token endpoint, a "create token" API) puts a real secret into the box and then into
  every snapshot. The egress rules should mark such endpoints, and the zone view should say so.
- **Claude Code's `/heapdump`** warns that a heap snapshot holds "the full conversation and any credentials the
  process held" [H]. A gVisor or VM memory image is a superset of that, so it must be protected like the zone's
  most confidential data: encrypted under the agent key, labelled, and never readable by the provider.
- **Apple VZ files** are hardware-encrypted per Mac and user [H], which is good for confidentiality but makes them
  non-portable.
- **Hosted backends** (E2B, Modal, Fly) keep snapshots in *their* storage, under *their* keys. A valuable zone on
  a hosted backend should hibernate by (c) into wicket's store, not by the vendor's pause.

### 6.8 Integrity
- **Every snapshot gets a manifest** (§9.4) listing:
  - each blob's digest, the runtime fingerprint (runsc build, CPU features, platform, VMM version), the image
    digest, the adapter pin, the charter version, the label, the parent snapshot and a sequence number;
  - the manifest is **signed by wicket's issuing key** (§3.2).
- **Restore verifies the signature, every digest and the sequence** (no rollback to an older snapshot unless an
  operator asks) before anything parses the image.
- **Why this matters:**
  - runsc's restore deserialises sentry state, and Firecracker parses vmstate. A tampered image attacks the
    sandbox runtime, **outside** the box's isolation.
  - The trees are verified too, because runsc doesn't validate bind-mounted files on restore (§3.1).
- **Never mount a guest-written disk image with the host kernel** (§7). A Firecracker workdir image is re-attached
  to a VM, never mounted on the host. Extraction goes through the guest agent or a user-space reader.

### 6.9 Garbage collection
- **Restore-once:** after a successful restore *and* the next checkpoint, the older image is deleted. One previous
  tree snapshot is kept as a rollback point.
- **Per tier,** following §13.6:
  - Sleeping images are dropped at the hibernate step, or when the node lease ends;
  - Hibernated images are dropped at archive, which keeps only the trees, the session and memory;
  - delete is crypto-shredding the agent key, then deleting the blobs.
- **The chunk store** needs mark-and-sweep from the live manifests (restic's `prune` model), run per agent.
  Per-agent keys mean an agent's chunks are never shared, so the sweep never needs cross-agent reference counts.
- **Images expire with their runtime.** A runsc or Firecracker upgrade makes every image built on the old version
  unrestorable. Either keep the old runtime binary for a grace period (pinned by digest), or let those agents wake
  by rebuild. Modal re-takes snapshots on platform updates [H], and Fly drops them [H].
- **Session transcripts:** Claude Code deletes transcripts older than `cleanupPeriodDays` (default 30) on start
  [H]. A long-lived agent woken after 31 days would delete its own session on wake. wicket's generated
  `settings.json` must set `cleanupPeriodDays` above the agent's retention.

---

## 7. Wake triggers and budgets

- **Wake sources** (§13.2): operator message, schedule, event subscription, agent message, grant decided. All of
  them already arrive *at wicket*, not at the box. The box has no network and no inbound port, so "wake on
  access" is simpler than OpenSandbox's.
  - Messages are durable ledger entries, so they **queue without a budget** and are delivered after wake, through
    the same stream-json channel `wicket say` uses.
  - Only live HTTP traffic needs parking: previews (#31) and links (#6) into a box, and a vendor Remote Control
    client.
- **Parking for live traffic,** following OpenSandbox's spec [H]:
  - **single-flight wake** per agent, fenced by the snapshot id;
  - a bounded **parking lot** per node;
  - a per-request budget (2 s for Sleeping, 10 s for Hibernated, per §13.8), then `503` + `Retry-After`, while the
    wake carries on;
  - one replay of a buffered small request body.

  The parked request's identity is checked *before* it can trigger a wake, so an unauthenticated preview hit can't
  be used to make wicket spend money restoring agents.
- **Schedules:** a cron wake can pre-warm. It starts pulling trees and images to a likely node a minute early, so
  a scheduled agent wakes from local disk.
- **Budgets vs mechanisms:**

| Transition | Budget (p95, §13.8) | Mechanism that can meet it | Risk |
|---|---|---|---|
| Wake from Idle | ≤ 50 ms | `cgroup.freeze` / `runsc pause`, ~10 ms (§7) | memory stays pinned |
| Wake from Sleeping | ≤ 2 s | gVisor restore from node disk with background restore (65–160 ms measured unofficially [H] up to ~1 s [H]); Firecracker snapshot + UFFD; VZ restore | none measured on wicket's boxes yet: experiment E1 |
| Wake from Hibernated | ≤ 10 s | (a) pull image + trees from object storage (at an assumed 100–200 MB/s [L], 500 MB ≈ 3–5 s; lazy paging or a node cache shortens it), or (c) rebuild: box ≤ 1 s + tree pull + Claude Code start 1–2 s + `--resume` | multi-GB `node_modules` pulls; OpenSandbox's 16 s for 3.5 GiB [H] shows the cost of full pulls |
| Active RPO | 60 s | incremental chunk push from a frozen reflink copy | ext4 nodes need a full copy per freeze |

---

## 8. Provider and tier notes

| | gVisor (any VPS) | Firecracker (KVM) | VZ (Mac) | Kata |
|---|---|---|---|---|
| Idle | `runsc pause` / cgroup freeze | `PATCH /vm Paused` | `pause()` | freeze |
| Sleeping | `runsc checkpoint` to node disk; trees stay in place | full or diff snapshot to node disk; disks reflinked at the same pause | `saveMachineStateTo` (same Mac and user; keychain unlocked) | (b) |
| Hibernated | image (CPU features pinned per pool) + trees to object storage; restore on a matching node, else (c) | memory (diff-merged with `snapshot-editor`) + disk chunks to object storage; UFFD handler pages lazily from the local cache; same-CPU pools only | (b)/(c) only: the state file can't leave the Mac | (b)/(c) |
| Move a running agent (#8) | checkpoint → ship → restore on a matching node; re-dial sockets; new identity | snapshot → ship; or Cloud Hypervisor live migration between wicket hosts | not possible | rebuild |

| Provider | Node state | Durable store | Notes |
|---|---|---|---|
| **Vultr** (no KVM on VPS) | gVisor; node NVMe for Sleeping images and the chunk cache; XFS data dir for reflinks [L] | Vultr Object Storage in the same region, or R2 | Per-started-hour billing: a Sleeping agent keeps its node only while the paid hour lasts, then hibernates (§8.5) |
| **Hetzner** | as Vultr; dedicated servers for KVM | Hetzner Object Storage (cheap; pack to beat the 64 KB minimum) | Volumes have no snapshots: never the durable copy |
| **AWS** | gVisor, or Firecracker on nested-virt C7i/M7i or `.metal` | S3 (London) | EBS as node disk only; EBS snapshot lazy-restore is an AWS-only optimisation |
| **GCP** | gVisor; GKE Pod Snapshots or Agent Substrate as optional backends | GCS | Those backends keep memory in Google's store under Google's keys: not for valuable zones |
| **Mac** | VZ (#48); APFS clones | object storage, or a local directory store | VZ save is Sleeping-only; macOS updates invalidate it |
| **Cross-provider** | — | R2 (no egress fees) or the tenant's residency region | Memory images don't cross CPU vendors; trees do |

---

## 9. Recommendation for wicket

### 9.1 Principles
1. **Level (c) is the product, (a) is a cache.** Build rebuild-and-resume first, and test it on every release:
   wake every agent once by rebuild in CI. Snapshots are tried first, and any failure (version, CPU, digest,
   revoked, changed charter) falls back to rebuild without operator involvement.
2. **One durable format for trees,** shared by every level, tier and provider. Memory images are optional
   attachments to a tree snapshot, taken at the same freeze.
3. **The box holds no authority,** so nothing in it is re-validated on wake except integrity. Identity, leases,
   grants and labels are wicket-side and re-bound on wake.
4. **Object storage for durability, node disk for speed.** Block volumes only as node disks, plus later Firecracker
   VM disks.

### 9.2 Layered plan

| Step | Build | Gets | Where |
|---|---|---|---|
| **H0 (0.0.1)** | (1) Start Claude Code with `--session-id <uuid>` chosen by wicket, and set `cleanupPeriodDays` in the generated settings. (2) A clean stop at a quiescent point, then push **one bundle per agent**: workspace (or its overlay upper dir) + `state/claude/{projects,file-history,tasks}` + volumes. Format: tar, zstd, XChaCha20-Poly1305 under the agent key wrapped by the tenant key, with a signed manifest. (3) Wake = new box on any node, pull, unpack, regenerate config, `claude -p --resume <id> --input-format stream-json`, deliver the wake message. (4) `docker pause` for Idle. (5) Volumes become durable trees with a single-writer lease (#56) instead of host directories | Long-lived agents across #37's ephemeral Vultr nodes; volumes that survive node destruction; the 10 s Hibernated budget for small workspaces | Docker + gVisor, Vultr Object Storage or R2 |
| **H1** | A content-defined chunk store (`fastcdc` + zstd + AEAD packs; or `rustic_core` with one repository per agent, evaluated in E5); a node chunk cache; freeze + reflink active checkpoints for the 60 s RPO; GC by mark-and-sweep | Incremental pushes; cheap moves; dedup within an agent's history | same |
| **H2** | Direct `runsc` launch (§8.3) with `dev.gvisor.internal.cpufeatures` pinned per node pool; `wicket-entry` as the save/restore hook (veto, re-dial, reseed); local `runsc checkpoint` for **Sleeping**; image + trees restored bit-identical, digest-checked | ≤ 2 s Sleeping wakes; processes survive | gVisor nodes |
| **H3** | Ship checkpoint images to object storage (uncompressed pages for background restore; compress in transit); a restore-compatibility check against the target node; #8 moves | Hibernated with memory; moving a live agent | gVisor pools with uniform CPUs |
| **H4** | Firecracker (#64): full + diff snapshots, a UFFD handler fed from the chunk cache, VMGenID + explicit reseed, vsock re-dial, disks as reflinked images; warm-pool clones of pristine images | Fastest wakes; clones | KVM pools (AWS nested, bare metal) |
| **H5** | VZ save for Sleeping on Macs (#48); GKE Pod Snapshots, Agent Substrate or OpenSandbox as optional backends for low-value zones (#61) | Parity on Macs; hosted capacity | Macs, GKE |

### 9.3 What wicket stores where

| What | Where | Why |
|---|---|---|
| Lifecycle state, current snapshot pointer, restorable/consumed/revoked flags, leases, pending requests, subscriptions, identity history | **ledger** (SQLite+litestream / Postgres) | Authority and audit; never in a snapshot |
| Tenant keys | KMS / vault | One KMS key per tenant |
| Wrapped agent data keys, agent CA keys (wrapped), issuing keys | vault | Crypto-shred = destroy the wrapped agent key |
| Snapshot manifests (signed, encrypted) | object storage `t/<tenant>/a/<agent>/m/<seq>` | Small; listed by the ledger pointer, never by listing the bucket |
| Tree packs | object storage `t/<tenant>/a/<agent>/p/<hash>` | Agent key; per-agent GC |
| Base content (image layers, lockfile-keyed dependency trees) | registry, or `t/<tenant>/base/...` under a tenant key | Re-derivable; shared within a tenant only |
| Memory images | node disk (Sleeping); object storage `.../live/<seq>/` (Hibernated) | Pinned to the runtime fingerprint |
| Chunk cache, Sleeping images, reflink snapshots | node data disk (XFS) | Speed; disposable |
| Memory stores (§13.4) | wicket's store, already versioned | Not part of the box's trees |

### 9.4 The minimal durable-state format

```rust
/// One durable snapshot of an agent. Encrypted under the agent key, then signed by wicket's issuing key.
pub struct StateManifest {
    pub agent: AgentId, pub tenant: TenantId,
    pub seq: u64,                          // strictly increasing; restore refuses an older seq unless an operator forces it
    pub parent: Option<Digest>,            // previous manifest, for incrementals and audit
    pub taken_at: Timestamp,               // wicket's clock
    pub activation: ActivationId,          // the activation that produced it
    pub quiescent: bool,                   // taken at a turn boundary with nothing in flight
    pub launch: LaunchFingerprint,         // manifest digest, image digest, adapter pin, charter version, policy epoch
    pub session: AgentSession,             // e.g. ClaudeCode { session_id: Uuid, cwd: "/workspace", config_dir: "/wicket/state/claude" }
    pub trees: Vec<TreeSnapshot>,          // workspace, state, each volume
    pub memory: Vec<MemoryVersionRef>,     // approved memory versions it ran with
    pub live: Option<LiveImage>,           // present only for level (a)
    pub label: Label,                      // join of everything kept; a LiveImage keeps the full floating label
    pub key: WrappedKeyRef,                // which agent key, wrapped by which tenant key
}
pub struct TreeSnapshot {
    pub mount: TreeMount,                  // Workspace | State | Volume(VolumeName) | RootfsUpper
    pub base: Option<BaseRef>,             // git commit, image layer digest or tenant base, never stored per agent
    pub format: TreeFormat,                // TarZstd (H0) | ChunkIndex (H1)
    pub blobs: Vec<BlobRef>,               // digest, size, object key
    pub tree_digest: Digest,               // digest over (path, mode, size, mtime, content digest), checked after unpack
}
pub struct LiveImage {
    pub runtime: RuntimeFingerprint,       // e.g. Gvisor { runsc_build, platform, cpu_features } | Firecracker { version, cpu_template, host_kernel } | Vz { macos_build }
    pub files: Vec<BlobRef>,               // checkpoint.img, pages_meta.img, pages.img | vmstate, memory
    pub restore_once: bool,                // true except for pristine pool images
    pub clone_safe: bool,
    pub ca_ref: CaRef,                     // the CA the box loaded, which must stay presentable
    pub placeholders: PlaceholderSetRef,   // re-bound to the new socket on restore
}
```

**Wake algorithm:**
1. Verify the signature, check the seq, and check the ledger's restorable flag.
2. If `live` is present, compatible with the chosen node, the agent wasn't revoked and `launch` is unchanged where it
   matters, then restore: trees first (digest-checked), then the image.
3. Otherwise, rebuild from `trees` and `session`.
4. Either way, issue a fresh identity, bind the sockets, and mark the snapshot consumed.

### 9.5 What this means for the design doc (to propose, not done here)
- **§13.2:** "new placeholders and a CA from the ceiling on every wake" holds for rebuilds. A memory restore re-binds
  the old placeholders and needs the agent's CA to outlive the snapshot.
- **§13.3:** sleep declassifies only on rebuild or a forked session. A memory restore keeps the full label.
- **§13.5:** "MinIO locally" becomes Garage, SeaweedFS or a directory backend (MinIO's community repo is archived
  [H]). Volumes become durable trees with single-writer leases.
- **§7:** the gVisor checkpoint covers memory and the rootfs overlay only. Bind-mounted trees are restored by
  wicket, bit-identical and digest-checked, because runsc doesn't validate them.

### 9.6 Experiments to run first

| # | Experiment | Measures | Where |
|---|---|---|---|
| **E1** | `runsc checkpoint` / `restore` of a real wicket box (Claude Code mid-session) with direct runsc and the current mounts; with and without `--background` | Image size, checkpoint and restore ms, time to first token after restore; whether the forwarders see EOF and re-dial; whether loopback connections survive | this box ($0) |
| **E2** | Restore E1's image on a second Vultr node of the same plan, then of another plan or CPU, with and without the `cpufeatures` annotation | Which moves work; TSC warnings on systrap | Vultr, ~$0.10 |
| **E3** | Clock and timers: checkpoint for 1 h, restore | Node timers, Claude Code's API retries, TLS to the proxy, certificate `notBefore` | this box |
| **E4** | Level (b): stop the box at a turn boundary, keep `state/` and `/workspace`, start a new box, `claude -p --resume <id>` over stream-json | Wake-to-first-token; what's lost (background shells, task lists, subagents); that the 30-day `cleanupPeriodDays` sweep is disabled; `--fork-session` | this box |
| **E5** | Tree sync: tar+zstd+AEAD vs fastcdc packs vs `rustic_core`, on a typical Node repo with `node_modules` and on a Rust repo; full and incremental after a session | Bytes, PUT counts, upload and download time to Vultr Object Storage and R2 from London; restore throughput | this box + buckets, cents |
| **E6** | Consistency under gVisor: write heavily in the box, `runsc pause`, copy the host dirs, compare with an in-box `sync` first | Whether the sentry holds dirty data for gofer mounts | this box |
| **E7** | Placeholder and CA stability: restore after the per-run CA was rotated (expect failure), then with a per-agent CA and re-bound placeholders | Validates §6.4 | this box |
| **E8** | Firecracker on an AWS nested-virt instance: full vs diff snapshots, UFFD from a local cache, vsock re-dial, VMGenID reseed, two restores of one pristine image produce different random output | The I4 numbers in §8.6 | AWS c7i, ~$1 |
| **E9** | VZ save/restore of a Linux VM with vsock + virtiofs and no network device, headless | Whether those devices block save; vsock behaviour; keychain prompts | a Mac |

---

## 10. Open questions

1. Does gVisor hold dirty gofer-file data in the sentry long enough to matter for host-side copies (E6)? If it
   does, what's the cheapest flush?
2. Should a level-(a) wake be allowed for agents whose zone is valuable at all? It keeps the full label and
   every in-memory secret-adjacent byte. One option is "rebuild only" for zones above a confidentiality level.
3. Per-agent or per-zone CA? Per-agent CAs simplify memory restore and team layouts. Per-zone CAs are fewer keys.
4. `rustic_core` (restic format, existing tooling for audits and restores) or our own small chunk format (fewer
   moving parts, our own key model)? E5 decides.
5. How long do Sleeping images stay restorable across runsc upgrades? Keep old runsc builds pinned by digest, or
   rebuild?
6. Volumes shared by several agents in a team (§13.7) need either a single-writer lease or a merge. Which one first?

---

## Sources

**gVisor:**
- https://gvisor.dev/docs/user_guide/checkpoint_restore/
- https://gvisor.dev/docs/user_guide/fs_snapshot/
- https://gvisor.dev/docs/user_guide/rootfs_snapshot/
- https://gvisor.dev/docs/user_guide/fuse/
- Source at google/gvisor master dd49ce7: `runsc/cmd/checkpoint.go`, `runsc/cmd/restore.go`,
  `runsc/boot/restore.go`, `runsc/boot/controller.go`, `pkg/sentry/control/state.go`,
  `pkg/sentry/state/checkpointfiles/`, `pkg/sentry/socket/unix/transport/host.go`,
  `pkg/tcpip/transport/tcp/endpoint_state.go`, `pkg/cpuid/`, `pkg/shim/v1/runsc/service.go`
- https://github.com/google/gvisor/pull/12810

**Containers and CRIU:**
- https://docs.docker.com/reference/cli/docker/checkpoint/
- https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/
- https://www.kubernetes.dev/resources/keps/5823/
- https://docs.cloud.google.com/kubernetes-engine/docs/concepts/pod-snapshots
- https://criu.org/Download/criu/4.3
- https://criu.org/External_UNIX_socket
- https://github.com/checkpoint-restore/criu/pull/1597
- https://github.com/libuv/libuv/blob/v1.x/src/unix/linux.c
- https://docs.podman.io/en/latest/markdown/podman-container-checkpoint.1.html
- https://github.com/checkpoint-restore/rust-criu

**Firecracker and Cloud Hypervisor:**
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/handling-page-faults-on-snapshot-resume.md
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/random-for-clones.md
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/versioning.md
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-editor.md
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/ballooning.md
- https://uapi-group.org/specifications/specs/vmclock/
- https://arxiv.org/abs/2102.12892
- https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/snapshot_restore.md
- https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/live_migration.md

**Kata:**
- https://github.com/kata-containers/kata-containers/blob/main/docs/Limitations.md

**Apple:**
- https://developer.apple.com/documentation/virtualization/vzvirtualmachine/savemachinestateto(url:completionhandler:)
- https://developer.apple.com/documentation/virtualization/vzvirtualmachine/restoremachinestatefrom(url:completionhandler:)
- https://developer.apple.com/videos/play/wwdc2023/10007/
- https://developer.apple.com/forums/thread/782007
- https://github.com/cirruslabs/tart/blob/main/Sources/tart/VM.swift
- https://docs.rs/objc2-virtualization/latest/objc2_virtualization/struct.VZVirtualMachine.html

**Products:**
- https://docs.e2b.dev/sandbox/persistence
- https://github.com/e2b-dev/infra
- https://docs.fly.io/reference/suspend-resume
- https://docs.fly.io/about/pricing
- https://modal.com/blog/mem-snapshots
- https://modal.com/docs/guide/memory-snapshot
- https://modal.com/docs/guide/sandbox-snapshots
- https://modal.com/docs/guide/sandbox-memory-snapshots
- https://dev.to/codesandboxio/how-we-clone-a-running-vm-in-2-seconds-39m3
- https://www.daytona.io/docs/en/persistence
- https://github.com/opensandbox-group/OpenSandbox
- https://github.com/opensandbox-group/OpenSandbox/pull/2152
- https://github.com/opensandbox-group/OpenSandbox/pull/2156
- https://github.com/opensandbox-group/fast-sandbox/pull/59
- https://github.com/agent-substrate/substrate
- https://github.com/agent-substrate/substrate/pull/221
- https://docs.cloud.google.com/kubernetes-engine/ai-ml/about-agent-substrate
- https://developers.cloudflare.com/sandbox/concepts/sandboxes/
- https://developers.cloudflare.com/sandbox/guides/backup-restore/
- https://developers.cloudflare.com/containers/guides/snapshots/
- https://vercel.com/docs/vercel-sandbox/concepts/persistent-sandboxes
- https://docs.fly.io/sprites/concepts/lifecycle
- https://cloud.morph.so/docs/documentation/instances/pause-resume
- https://docs.blaxel.ai/Sandboxes/Overview

**Storage:**
- AWS Price List CSVs (EBS, S3, KMS; effective 2026-11-01)
- https://docs.aws.amazon.com/ebs/latest/userguide/initalize-volume.html
- https://www.hetzner.com/storage/object-storage/
- https://docs.vultr.com/support/products/storage/pricing-and-billing
- https://developers.cloudflare.com/r2/pricing/
- https://github.com/Barre/ZeroFS
- https://restic.readthedocs.io/en/stable/100_references.html
- https://github.com/folbricht/desync
- https://www.sqlite.org/howtocorrupt.html
- openzfs `zfs-send.8`; kernel `Documentation/filesystems/overlayfs.rst`

**Claude Code:**
- https://code.claude.com/docs/en/claude-directory.md (transcripts, `cleanupPeriodDays`, plaintext storage, heapdump warning)
- `claude --help` (2.1.322: `--resume`, `--session-id`, `--fork-session`, `--no-session-persistence`) [H, this machine]
