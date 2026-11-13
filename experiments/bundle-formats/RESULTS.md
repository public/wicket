# E5: hibernation bundle formats compared (#195)

**Question.** Should a hibernated agent's trees keep wicket's own bundle format (one tar + zstd -3 blob per
tree, sealed with wicket's chunked AES-256-GCM, reused only while a tree is unchanged), move to the restic
repository format through `rustic_core`, or keep tar + zstd and replace the sealing with `age`? Research doc 22
left this to E5 (§9.6, open question 4); #195 asks for it, and #194 (OCI artifacts) and #177 (snapshots, forks)
depend on the answer.

**Answer.** Adopt the **restic repository format, through `rustic_core`, one repository per agent**, under
wicket's own manifest. It is the only option that makes hibernation incremental: after a session it stores
**18 MB instead of 125 MB** for a Rust repository, **0.1 MB instead of 56 MB** for a Node repository and
**1.9 MB instead of 19 MB** for a small-file tree. After 20 sessions the store holds **5–18× less**. Incremental saves are 2–6× faster for the Rust and Node
agents, and slower for the small-file one (3.8 s against 2.5 s). It also brings a documented format with an independent reader (the restic
CLI) and a publicly examined crypto design.

It costs more memory (140–300 MB against 15–40 MB), CPU on many small files (34 s against 3 s for a first save
of 60k files), larger first saves (+15% to +100%) and a 0.x library. It also needs wicket's own restore checks
in front of it: rustic_core's restore follows symlinked parents and makes device nodes. `age` alone is a fair
replacement for wicket's sealing (same size and speed), but it doesn't change what a hibernation costs.
Details, the conditions attached and a migration sketch are in §6.

Run on 2026-11-13 on the shared 4 vCPU Vultr VPS, the same box as the other experiments, so
expect ±30% noise on timings. Single runs: one wall time in a series that is out of line with its neighbours
(node `today` +1 at 14.2 s, small `age` +1 at 8.7 s) is noise from other sessions on the box.

## 1. What was compared

| | format | sealing | dedup | per |
|---|---|---|---|---|
| **today** | `wicket_store::bundle::push`/`pull_tree` unchanged: one tar + zstd -3 blob per tree, content-addressed, reused while the tree's digest is unchanged | `SealedStore` (AES-256-GCM, 64 KiB chunks, AAD binds the object key) | whole unchanged trees only | agent |
| **age** | the same push and pull | `AgeStore` (E5's): age X25519 recipient, STREAM 64 KiB; the object key is the first plaintext line, checked on read | whole unchanged trees only | agent |
| **rustic** | `rustic_core` 0.13: content-defined chunks, packs, index, snapshots; each tree a snapshot (`as_path /<tree>`, host = agent, tag `tree=<name>`) | restic's (AES-256-CTR + Poly1305, master key) | every chunk, within a repository | agent (or zone, §3) |
| **restic CLI** 0.19.1 | the reference implementation of the same format, for comparison | | | |

Stores: a local directory (wicket's `DirStore`; rustic's local backend), and an S3-compatible store, versitygw
(pinned as in `ci/restore.sh`) over host networking. For today and age, wicket's own S3 client is used:
`crates/wicket-cli/src/s3.rs`, included by path, with `If-None-Match` put-if-absent. rustic uses its opendal S3
backend. Request counts come from versitygw's access log.

## 2. Method

- **Datasets** (`src/gen.rs`, deterministic: a seed per dataset and per session, so nothing is checked in):
  - **rust**: a repository with sources and a `target/` of build outputs: 273 MB, 1,283 files;
  - **state**: an agent `$HOME` with Claude Code session logs: 56 MB, 366 files;
  - **node**: a repository with `node_modules`, some packages in two versions: 200 MB, 28,857 files;
  - **small**: 60,000 files under 2 KB: 63 MB.

  The rust agent has two trees (`workspace` = rust, `state` = state), so "restore one tree" restores `state`.
  The node and small agents have one tree each.
- **A session** (`gen::session`):
  - **rust**: edits five sources, rewrites eight build outputs and the binary, and churns an incremental-cache
    directory;
  - **node**: edits ten sources, and every fifth session upgrades, adds and removes packages;
  - **state**: appends to the current session log, starting a new one every fifth session;
  - **small**: edits 1% of the files, adds 0.5% and deletes 0.2%.
- **Series** (`run.py series`):
  - save after session 0 (full) and after every session up to 20 (local) or 5 (S3);
  - restore everything, and one tree, after sessions 0, 1, 5 and 20, each verified against wicket's tree digest
    (type, path, mode, size and content of every entry);
  - on the local store after 20 sessions, a full integrity check that reads every byte, then a prune down to
    the newest state, then a verified restore.

  Each operation is one process: wall time, CPU and peak RSS come from `wait4`.
- **Extras** (`run.py extras`, `run.py kill9`):
  - cross-agent dedup;
  - two concurrent writers;
  - kill -9 at 20, 50 and 80% of a measured run of the same save, full and incremental;
  - one flipped byte in the largest stored object;
  - a tree with a symlink out of it, a dangling symlink and a FIFO.

  Raw records are in `logs/*.jsonl`; `report.py` prints the tables below.
- **Not done**: kopia and borg (optional in the brief), and casync/desync, which are discussed in §5.7, not
  measured. Real Vultr Object Storage and R2 were not used: versitygw on the same host measures bytes and
  requests, not network time.

## 3. Results

Every save, restore, check and prune in the series succeeded, and every restore verified (345 operations).

**fs**: bytes added to the store per save (MB), and in total after 20 sessions

| agent | format | full | +1 session | +5 (each, mean) | +20 (each, mean) | total | objects |
|---|---|---:|---:|---:|---:|---:|---:|
| rust | today | 124.7 | 124.8 | 124.6 | 124.7 | 2,619.3 | 63 |
| rust | age | 124.7 | 124.8 | 124.6 | 124.7 | 2,619.2 | 63 |
| rust | rustic | 144.6 | 17.9 | 18.9 | 19.0 | 524.3 | 173 |
| node | today | 55.8 | 55.8 | 55.8 | 55.8 | 1,172.5 | 42 |
| node | age | 55.8 | 55.8 | 55.8 | 55.8 | 1,172.5 | 42 |
| node | rustic | 64.4 | 0.0 | 0.1 | 0.1 | 66.1 | 88 |
| small | today | 19.2 | 19.3 | 19.4 | 19.9 | 416.3 | 42 |
| small | age | 19.2 | 19.3 | 19.4 | 19.9 | 416.4 | 42 |
| small | rustic | 39.9 | 1.9 | 1.9 | 1.9 | 77.6 | 92 |

**s3**: bytes added to the store per save (MB), and in total after 5 sessions

| agent | format | full | +1 session | +5 (each, mean) | +20 (each, mean) | total | objects |
|---|---|---:|---:|---:|---:|---:|---:|
| rust | today | 124.7 | 124.8 | 124.6 | - | 747.8 | 18 |
| rust | age | 124.7 | 124.8 | 124.6 | - | 747.8 | 18 |
| rust | rustic | 144.6 | 17.9 | 18.9 | - | 239.1 | 53 |
| node | today | 55.8 | 55.8 | 55.8 | - | 334.9 | 12 |
| node | age | 55.8 | 55.8 | 55.8 | - | 334.9 | 12 |
| node | rustic | 64.3 | 0.0 | 0.1 | - | 64.7 | 28 |
| small | today | 19.2 | 19.3 | 19.4 | - | 116.1 | 12 |
| small | age | 19.2 | 19.3 | 19.4 | - | 116.1 | 12 |
| small | rustic | 39.9 | 1.9 | 1.9 | - | 49.2 | 32 |

**fs**: save and restore, wall s / CPU s / peak RSS MB (one process each)

| agent | format | full save | incremental save (+1) | restore (+5) | restore one tree (+5) |
|---|---|---|---|---|---|
| rust | today | 5.8 / 5.3 / 16 | 6.9 / 5.6 / 16 | 4.0 / 4.0 / 15 | 0.9 / 0.9 / 14 |
| rust | age | 7.3 / 6.2 / 16 | 6.7 / 5.9 / 16 | 4.5 / 4.4 / 15 | 0.8 / 0.8 / 14 |
| rust | rustic | 4.9 / 8.0 / 139 | 1.1 / 1.3 / 139 | 1.5 / 2.1 / 236 | 0.8 / 0.8 / 139 |
| node | today | 5.7 / 5.4 / 27 | 14.2 / 7.3 / 28 | 6.1 / 6.0 / 25 | - |
| node | age | 4.9 / 4.6 / 28 | 5.0 / 4.8 / 28 | 6.7 / 6.5 / 25 | - |
| node | rustic | 9.9 / 21.8 / 139 | 2.1 / 2.8 / 139 | 4.7 / 5.9 / 236 | - |
| small | today | 3.4 / 2.9 / 36 | 2.5 / 2.4 / 36 | 7.2 / 7.0 / 34 | - |
| small | age | 3.1 / 2.8 / 36 | 8.7 / 3.8 / 37 | 7.9 / 6.9 / 34 | - |
| small | rustic | 20.6 / 33.5 / 139 | 3.8 / 5.0 / 139 | 8.0 / 7.8 / 139 | - |

**s3**: save and restore, wall s / CPU s / peak RSS MB (one process each)

| agent | format | full save | incremental save (+1) | restore (+5) | restore one tree (+5) |
|---|---|---|---|---|---|
| rust | today | 7.7 / 7.4 / 18 | 7.5 / 7.4 / 18 | 4.5 / 4.4 / 19 | 0.8 / 0.8 / 18 |
| rust | age | 8.0 / 7.6 / 18 | 9.6 / 7.3 / 18 | 4.5 / 4.5 / 18 | 0.9 / 0.9 / 17 |
| rust | rustic | 6.1 / 7.8 / 144 | 1.2 / 1.3 / 143 | 1.5 / 2.0 / 305 | 0.7 / 0.8 / 144 |
| node | today | 6.2 / 5.7 / 30 | 12.0 / 7.1 / 30 | 6.4 / 6.3 / 28 | - |
| node | age | 5.9 / 5.8 / 30 | 5.8 / 5.6 / 30 | 6.8 / 6.5 / 28 | - |
| node | rustic | 13.4 / 22.9 / 144 | 2.2 / 2.7 / 144 | 4.7 / 6.0 / 275 | - |
| small | today | 3.6 / 3.2 / 39 | 10.3 / 4.4 / 39 | 6.8 / 6.7 / 37 | - |
| small | age | 3.4 / 3.2 / 39 | 3.0 / 3.0 / 38 | 7.1 / 6.9 / 38 | - |
| small | rustic | 12.4 / 36.8 / 144 | 3.2 / 4.9 / 143 | 7.6 / 9.4 / 175 | - |

**s3**: requests per operation (versitygw's access log)

| agent | format | full save PUT | incremental save PUT / GET / LIST | restore (+5) GET | restore one tree GET |
|---|---|---:|---|---:|---:|
| rust | today | 3 | 3 / 4 / 2 | 3 | 2 |
| rust | age | 3 | 3 / 1 / 1 | 3 | 2 |
| rust | rustic | 273 | 8 / 2 / 4 | 30 | 8 |
| node | today | 2 | 2 / 3 / 2 | 2 | - |
| node | age | 2 | 2 / 1 / 1 | 2 | - |
| node | rustic | 268 | 4 / 2 / 3 | 10 | - |
| small | today | 2 | 2 / 3 / 2 | 2 | - |
| small | age | 2 | 2 / 1 / 1 | 2 | - |
| small | rustic | 272 | 4 / 2 / 3 | 13 | - |

**fs, after 20 sessions**: integrity check reading every byte, and prune to the newest state

| agent | format | check (wall s / CPU s) | prune (wall s) | store before → after (MB) | restore after prune |
|---|---|---|---:|---|---|
| rust | today | 24.4 / 22.9 | 0.3 | 2,619.3 → 124.8 | verified |
| rust | age | 27.8 / 26.3 | 0.1 | 2,619.2 → 124.8 | verified |
| rust | rustic | 6.3 / 13.5 | 1.9 | 524.3 → 171.7 | verified |
| node | today | 9.5 / 9.4 | 0.2 | 1,172.5 → 55.8 | verified |
| node | age | 11.3 / 10.9 | 0.1 | 1,172.5 → 55.8 | verified |
| node | rustic | 2.0 / 3.9 | 1.4 | 66.1 → 65.7 | verified |
| small | today | 3.7 / 3.5 | 0.1 | 416.3 → 20.5 | verified |
| small | age | 4.0 / 3.9 | 0.1 | 416.4 → 20.5 | verified |
| small | rustic | 6.9 / 8.7 | 2.6 | 77.6 → 49.5 | verified |

**restic CLI 0.19.1 (reference), fs**: MB added, wall s / CPU s / RSS MB

| agent | full | +1 session | +5 | restore (+5) | check --read-data | forget --keep-last 1 --prune |
|---|---|---|---|---|---|---|
| rust | 145.9 (3.9 s) | 18.0 (1.8 s) | 19.6 | 1.2 / 1.0 / 61 | 2.7 / 4.5 / 62 | 2.7 / 2.8 / 77 |
| node | 64.1 (4.9 s) | 0.0 (2.9 s) | 0.3 | 7.2 / 8.9 / 125 | 2.8 / 4.1 / 69 | 2.3 / 2.8 / 81 |
| small | 39.5 (6.9 s) | 1.9 (3.7 s) | 1.8 | 10.7 / 13.5 / 162 | 4.1 / 6.2 / 70 | 3.6 / 4.3 / 125 |

**cross-agent dedup**: a second agent with the same node tree (a fork)

| format | repository | first agent (MB) | second agent adds (MB) |
|---|---|---:|---:|
| rustic | per agent | 64.4 | 64.4 |
| rustic | per zone | 64.4 | 0.0 |
| today | per agent | 55.8 | 55.8 |
| age | per agent | 55.8 | 55.8 |

**kill -9 mid-save** (rust agent; killed at 20, 50 and 80% of a measured run of the same save)

| format | phase | killed | check after | previous state restores | next save + restore |
|---|---|---|---|---|---|
| today | full | 3/3 | 3 clean | n/a (nothing before) | 3/3 |
| today | incremental | 3/3 | 3 clean | 3/3 | 3/3 |
| age | full | 3/3 | 3 clean | n/a (nothing before) | 3/3 |
| age | incremental | 3/3 | 3 clean | 3/3 | 3/3 |
| rustic | full | 3/3 | 1 clean, 2 unreferenced-pack warnings | n/a (nothing before) | 3/3 |
| rustic | incremental | 3/3 | 3 clean | 3/3 | 3/3 |

### Reading the numbers

- **Incremental bytes decide it.** today and age re-upload every tree that changed at all: one edited source
  re-uploads the whole repository, `target/` and `node_modules` included. The restic format uploads the
  changed chunks: build outputs that changed, the edited sources, the appended log. For a Rust agent that
  hibernates after every session, that is 19 MB instead of 125 MB per hibernation; for a Node agent, 0.1 MB
  instead of 56 MB. Over 20 sessions the store holds 524 MB against 2.6 GB, and 66 MB against 1.2 GB.
- **First saves are larger and, with many small files, slower.**
  - rust +16%, node +15%, small 2× (39.9 against 19.2 MB): restic compresses chunk by chunk, not the whole
    tree as one zstd stream, and stores a tree object per directory.
  - On 60k small files a first save takes 34 CPU-seconds against 3. It is multithreaded, so 12–21 s of wall
    time, still several times slower.
  - Incremental saves are 2–6× faster than today's for the rust and node agents (today re-packs every
    changed tree), and slower for small (3.8 s against 2.5 s): rustic still walks and stats 60k files.
- **Memory**: 139–144 MB for any rustic save, and up to 305 MB for a restore. today and age stay at 11–39 MB.
- **S3 requests**:
  - A rustic first save makes about 270 PUTs. 256 of them are the directory markers (`data/00`…`data/ff`)
    that rustic's opendal backend creates once per repository; the rest are packs, index, snapshot, key and
    config. A wicket-owned backend over `ObjectStore` (§6) wouldn't make the markers.
  - Incremental saves: 4–8 PUTs against 2–3. Restores: 10–30 GETs (packs) against 2–3 (one blob per tree).
  - At the prices in research §5.2 (S3 $0.005 per 1k PUT) none of this matters; bytes do.
- **Restore speed**: rustic restores the Rust agent 2.7× faster (1.5 s against 4.0–4.5 s), since it writes
  with several threads and verifies chunks instead of re-hashing the whole tree. For node and small it is about
  equal. One tree out of two: all three under a second.
- **Integrity check**: rustic reads packs without decompressing whole trees, so it is 3–5× faster on the big
  agents and about 2× slower on 60k small files.
- **Prune**:
  - today and age prune instantly: delete manifests and blobs nothing kept refers to. After 20 sessions they
    get back to one full copy, 125 MB for rust.
  - rustic's prune repacks partly used packs (1.4–2.6 s) and keeps some unused data under its default 5%
    `max-unused` threshold. That is 172 MB for rust, against 125 MB for a single today copy, because the
    kept snapshot's chunks are spread over packs written across 20 sessions.
  - Every restore after a prune verified.
- **Cross-agent dedup**: a forked agent with the same node tree adds the whole tree again, unless both
  agents share one repository (per zone), which adds nothing. Per zone means one key and one chunker for every
  agent in the zone, the trade-off in research §5.2: "these two agents have the same file" becomes visible to
  anyone holding the zone key, and crypto-shredding one agent no longer removes its data.
- **Concurrent writers**: two simultaneous saves of one agent succeed in every format.
  - today and age write two manifests with the same sequence number and different generations; the ledger
    picks one, which is wicket's fencing.
  - rustic writes two snapshots; restic repositories are multi-writer by design.
  - Checks were clean, and restores verified.
- **kill -9**: no format lost a committed state.
  - today and age leave at most an orphan blob, which their prune reclaims.
  - rustic killed during a first save leaves unreferenced packs (`check` warns), which prune reclaims, and
    possibly a complete snapshot of a tree that was finished. wicket's manifest is the commit point, so that
    is garbage, not state.
- **Tamper**: one flipped byte is found by every format's check.
  - today: "sealed object fails authentication".
  - age: "decryption error".
  - rustic: an `ErrorCheckingPack` cryptography error.
  - A restore of today or age fails cleanly. **rustic's restore panicked** (exit 101) instead of returning an
    error. It wrote nothing wrong, but wicket would need to catch the panic or run the restore in a child
    process.
- **Odd tree** (a symlink to `/etc`, a dangling symlink, a FIFO):
  - today and age store both links as links, skip the FIFO, and restore the links without following them.
  - rustic stores the FIFO too. E5's listing check (§5.3) refused the restore because of it; wicket would
    rather exclude special files at backup time (rustic's local-source options) and keep the refusal as a
    backstop.

## 5. Assessment (code, docs, and what the probes showed)

### 5.1 Crypto

| | today (`SealedStore`) | restic format (rustic_core) | age |
|---|---|---|---|
| Construction | AES-256-GCM (ring), 64 KiB chunks; nonce = 8 random bytes ‖ chunk index; AAD = object key ‖ index ‖ last-chunk flag | AES-256-CTR + Poly1305-AES MAC (encrypt-then-MAC) per blob and per file; master key in key files under scrypt | X25519 (or scrypt) stanzas wrapping a file key; ChaCha20-Poly1305 STREAM, 64 KiB chunks, last-chunk flag |
| Binds an object to its name | yes (AAD) | no, but every blob is addressed by the SHA-256 of its plaintext and checked on read | no slot for it; E5 puts the key in the first plaintext line and checks it (§2) |
| Truncation, reordering | detected (index, last flag) | blobs are whole; packs hold a signed header | detected (STREAM) |
| Review | none outside wicket | a public, informal look at restic's design (Filippo Valsorda, 29 Aug 2017: "The design might not be perfect, but it's good", explicitly "not an audit"); the format is specified in restic's docs, and rustic implements the same format | a published, versioned spec (C2SP) with several independent implementations; neither the age README nor the spec mentions a third-party audit |
| Key model | one 256-bit key per installation today (§13.5 wants per-agent keys wrapped by the tenant key) | one master key per repository, any number of password- or key-file-wrapped copies | per-file key wrapped to any number of recipients: per-agent identity and tenant recipient fit directly |

### 5.2 Licence, maturity and dependencies

- restic: BSD-2-Clause, 0.19.1, about a decade of production use. rustic_core: Apache-2.0 OR MIT, 0.13.0 (MSRV
  1.91). Its README says it "is in an early development stage and its API is subject to change in the next
  releases", and rustic's README says "The `restic` project is older and more mature than `rustic`". This
  harness hit two signature changes against the README's own examples (`Repository::new` takes the backends by
  reference; `open`/`init` take `Credentials`). age (Rust crate): MIT OR Apache-2.0, 0.11.
- New crates on top of what `wicket-cli` already builds: age +60 (mostly its i18n stack), rustic_core +94,
  rustic_backend with opendal +240 (avoidable: rustic_core's `ReadBackend`/`WriteBackend` traits can sit on
  wicket's own stores, but they need ranged reads, which `ObjectStore` doesn't have).

### 5.3 Safe restore

wicket's rules: never follow symlinks out of a tree, never accept `..` or absolute paths, only files, directories
and symlinks.

- **today and age**: `unpack_tree` enforces them while unpacking (tar entries checked one by one, `unpack_in`).
- **rustic_core**: its restore writes `dest.join(path)` with plain `OpenOptions` (no `O_NOFOLLOW`, no check that
  a parent is a symlink), creates directories with `create_dir_all`, and `mknod`s devices, FIFOs and sockets.
  A crafted snapshot (`a -> /etc`, then `a/passwd`) would write outside the tree. Its path components come from
  node names, so `..` would surface in the listing. wicket must therefore vet the whole listing before
  restoring: E5's `safety::Listing` refuses non-plain paths, duplicate names, anything under a symlink and any
  type but file, dir and symlink, and the odd-tree probe (§3.6) shows rustic storing and restoring a FIFO that
  the listing check then refuses. A check-then-restore over a fresh destination is enough; a restore into a
  tree the box can also write would not be.
- **restic CLI**: the same model (it restores what the snapshot lists, special files included).

### 5.4 Generations, fencing and the ledger (#70, #184)

- wicket's `StateManifest` stays the commit point under every option: the ledger points at it, it names the
  generation that wrote it, and it would reference restic snapshot ids per tree instead of blob keys.
- restic repositories are multi-writer: concurrent backups are safe by construction (content-addressed packs,
  new snapshot files). rustic_core has no locks at all; its prune is two-phase (packs marked, deleted after
  `keep-delete`). A prune that runs with `instant_delete` (as E5 measures it) while a save is in flight can
  delete packs that save is about to reference. wicket would keep prune to one place, the reconciler, and
  only with the default two-phase delete.
- today's prune has the same hazard in a smaller form: a push reuses the previous manifest's blob without
  uploading it, so a concurrent prune that drops that manifest can delete the blob. Fencing makes it safe
  today: one generation holds the agent, and prune runs on the control host.

### 5.5 OCI artifacts (#194)

- today/age: one blob per tree, named by its digest: an OCI manifest whose layers are the tree blobs, the
  `StateManifest` as config, maps one to one, and registries dedupe identical tree blobs.
- restic: a repository is a tree of typed files (config, keys, index, snapshots, packs) that clients list by
  type. A registry has no listing by prefix nor deletion of single blobs by clients, so a repository would sit
  in a registry only as opaque packs plus an index artifact of wicket's own. It is possible, but it is a
  second format on top.

### 5.6 Snapshots and forks (#177)

- today: a fork is a new manifest pointing at the same blobs, but blobs live under `a/<agent>/` and are sealed
  under the installation key; per-agent keys (§13.5) would make a cross-agent fork a re-seal.
- restic per agent: a fork into another agent's repository is `restic copy` (re-chunked, re-encrypted).
  restic per zone: a fork is a new snapshot pointing at the same trees, free, but every agent in the zone
  then shares one key and one chunker, which §5.2 of the research doc says leaks "same file" between them.

### 5.7 casync / desync, kopia, borg

Not measured. casync and desync use the same content-defined chunking, with an index per snapshot and a shared
chunk store. They add seeding from local files and `desync mount-index` (lazy FUSE restore), which fits waking
a large agent before all its chunks arrive. They have no encryption, so wicket would layer its own, and their
chunk store dedups across everything that shares it, which is the per-zone trade-off again. kopia (Go) and
borg (Python, its repository format being redone in borg 2) are further chunked, encrypted formats with no
Rust library to embed; nothing in E5 suggests they would beat restic's format for wicket.

## 6. Recommendation

**Use the restic repository format, through `rustic_core`, for hibernation trees: one repository per agent,
under wicket's manifest, with wicket's restore rules in front of it.** In detail:

1. **Why.**
   - Hibernation is meant to run often: every idle agent, research §9's 60 s RPO, moves between nodes (#8).
     What it costs then is the incremental upload and the store, and the restic format cuts the upload by
     7–500× and the store by 5–18× on E5's agents.
   - The format is documented, has a mature independent implementation (the restic CLI, which can audit and
     restore wicket's bundles without wicket), and a crypto design that has been looked at in public.
   - Our own chunk format (open question 4's alternative) would mean building and reviewing the same thing
     alone.
2. **Per agent, not per zone.** Key separation and crypto-shredding (research §5.2, design §13.6) matter more
   than the cross-agent dedup that a zone repository buys (§3: a fork costs one copy).
   - Base content that many agents share (a lockfile-keyed `node_modules`, a toolchain) should be re-derived,
     or kept in a separate tenant- or base-keyed repository later, never per zone.
   - Forks within a repository (#177) are free: the same agent's snapshots share chunks.
3. **Conditions.**
   - **Pin `rustic_core`.** It describes itself as early-stage with a changing API, and E5 hit two breaking
     signatures. Run the restic CLI in CI as an independent reader of what wicket writes (`restic check
     --read-data`, `restic restore`), so a rustic_core regression can't silently produce bundles nothing
     else reads.
   - **wicket's own backend.** Implement `rustic_core`'s `ReadBackend`/`WriteBackend` over `ObjectStore`
     (`DirStore`, wicket's `S3Store`), which needs ranged reads added to `ObjectStore`. That avoids opendal's
     240 extra crates and its 256 directory markers, and keeps one S3 client for audit segments, the ledger
     stream and bundles.
   - **Keys.** Open each repository with `Credentials::Masterkey`: a per-agent data key wrapped by the tenant
     key, as §13.5 plans. Don't use restic key files with a password and scrypt; the vault holds the key.
   - **Restore.**
     - Always into a fresh directory.
     - First vet the whole listing (E5's `safety::Listing`: plain components only, no duplicate names,
       nothing under a symlink, files, directories and symlinks only).
     - Then check wicket's tree digest after restoring, as today.
     - Exclude special files at backup time.
     - Run the restore where a panic (§3) is caught or kills only a child process, so it is an error, not a
       crash of the supervisor.
   - **Prune** only from the reconciler, with rustic's default two-phase delete (never `instant_delete` while
     a save could be running), and only for agents not mid-hibernate.
   - **Memory.** Budget 150–300 MB per save or restore on the node that runs it. Throttle the number of
     concurrent hibernations per node.
4. **OCI (#194).**
   - today's one-blob-per-tree format maps one to one onto an OCI artifact, and the restic format doesn't: a
     repository is typed files listed by prefix.
   - If #194 still matters, store each agent's packs as artifact layers, with the index, snapshot and key
     files as the config of an artifact wicket writes per hibernation. That is a second format over the
     first, so decide #194 after this.
   - The S3-compatible store (#154) needs nothing new.
5. **age.**
   - If the owner prefers to stay on tar + zstd (smaller memory, one blob per tree, the OCI fit), replace
     `SealedStore` with age as #195 step 3 proposes. E5 shows it costs nothing in size (the same bytes to
     within a few hundred per object) and its times are within the box's noise of today's. It does need wicket to keep binding an object to its key inside the plaintext,
     since age has no associated data.
   - But it leaves hibernation non-incremental, which is the cost that matters.
   - Under the restic format, restic's own encryption replaces both.

### Migration sketch

- **Manifest version 2.** `StateManifest.version = 2`; each `TreeEntry` gains `format`:
  - `tarzstd-sealed` (today's: `blob`, sealed with the installation key);
  - `restic`: the repository location `a/<agent>/r/`, the snapshot id and wicket's `tree_digest`, which is
    still checked after a restore.

  The manifest stays the commit point the ledger points at, named by sequence number and generation, so
  fencing (#70, #184) is unchanged.
- **Reading old bundles.**
  - Version 1 manifests (no `format`) keep restoring through `pull_tree`.
  - The first hibernation after an upgrade writes the restic tree as a full save; later ones are incremental.
  - A version-1 manifest's blobs are pruned once no kept manifest refers to them (the existing prune).
- **One release of both.** Writers produce version 2. Readers accept 1 and 2. Rollback to the previous wicket
  can't read a version-2 bundle, so a downgrade wakes from the last version-1 manifest or refuses; #162's
  schema floor covers it.
- **Tests.**
  - `ci/hibernate.sh` (both modes) and `ci/restore.sh` with the S3 store.
  - A crafted-snapshot test for the listing check (duplicate names, a symlinked parent, `..`, a FIFO), since
    rustic_core won't refuse those itself.
  - The restic CLI reading a wicket repository in CI.

## 7. Files

- `src/gen.rs`: datasets and sessions. `src/formats.rs`: the three formats. `src/store.rs`: stores, `AgeStore`,
  and wicket's S3 client by path. `src/safety.rs`: wicket's restore rules over a restic listing.
  `src/main.rs`: the `bf` binary and its `measure` wrapper.
- `run.py`: the driver (`series`, `extras`, `kill9`, `restic`). `report.py`: the tables above.
- `logs/`: the raw records (`series.jsonl`, `extras.jsonl`, `kill9.jsonl`, `restic.jsonl`) and the drivers'
  console output. `tools/` (the restic binary, checked against its release's SHA256SUMS) and `target/` are
  git-ignored.

To rerun:

```sh
cd experiments/bundle-formats
mkdir -p tools && <download restic 0.19.1 linux_amd64 to tools/restic, check its SHA256SUMS>
cargo build --release
WICKET_DOCKER="sudo -n docker" python3 -I run.py series && python3 -I run.py extras && python3 -I run.py kill9 && python3 -I run.py restic
python3 -I report.py
```

`E5_SCALE` scales every dataset (1.0 here). Scratch data peaks at about 3 GB and is removed as each run ends.
