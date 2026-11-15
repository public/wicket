# One content-addressed store

Design note for #258, step 6 of the simplification in #253. Today wicket keeps five kinds of
immutable state in five formats. This note replaces them with one store of **blobs and trees named
by sha256**, in wicket's own format (#195 decided: our format, few dependencies). It also turns the
question "may this digest run" into a single check: a grant on the digest (#256).

It describes what we'd build, the order to build it in, and what is still open.

## What there is today

| What | Format today | Where | Named by |
|---|---|---|---|
| Hibernation bundles (#70) | one tar + zstd blob per tree, plus a JSON `StateManifest` (`wicket_store::bundle`) | `objects/` or the state store, sealed (`SealedStore`) | `a/<agent>/p/<sha256 of the blob>`, `a/<agent>/m/<seq>.<generation>`, and the ledger's pointer to the head manifest |
| Named snapshots and forks (#177) | not built; planned as frozen bundles | | |
| Volume snapshots (#251) | not built; "sha256 of its tree" | | |
| Pre-update ledger snapshots (#167) | the SQLite file, sealed as a whole | `<data dir>/snapshots/` and `ledger-snapshots/<time>-<build>.db` in the state store | file name |
| Installed versions (#162) | a directory per build id holding `wicket` and `manifest.json` | the versions root, and pushed to nodes over ssh | the first 12 hex digits of the binary's sha256 |
| Program sources | a directory; its own digest `wicket-program-v1` over plain files (`program::digest_dir`) | the manifest's `program.source` | `sha256:` of that digest |
| Images (#191) | OCI image layout | Docker, or an archive sent to a node | the OCI manifest's `sha256:` |

That is three tree digests (the bundle's per-entry lines, the program digest and OCI's manifests),
three naming schemes, and four answers to "may this run": release keys, a human-approved update
sha256, image pins and program pins.

## The store

### Objects

There are two kinds of object, and both are named by the sha256 of their bytes, written
`sha256:<64 hex>`:

- A **blob** is bytes: a file's content, a symlink's target, a ledger snapshot, a wicket binary.
- A **tree** is a blob in the canonical text format below. It lists a directory's entries, and each
  entry names its content by digest.

```
wicket-tree-v1
f 0644 1763150400 1234 sha256:… Cargo.toml
d 0755 1763150400 0 sha256:… src
l 0777 0 9 sha256:… link-to-readme
```

- **Header.** The first line is exactly `wicket-tree-v1`.
- **Entries.** One line per entry: `<kind> <mode> <mtime> <size> <digest> <name>`, with fields separated
  by one space and the line ended by `\n`.
  - **kind:** `f` for a regular file, `d` for a directory or `l` for a symlink.
  - **mode:** four octal digits, `& 0o7777`. A symlink's is always `0777`.
  - **mtime:** Unix seconds, so cargo's fingerprints stay valid after a restore (#177's warm caches).
    A symlink's is `0`.
  - **size:** a file's length, or a symlink target's length. A directory's is `0`.
  - **digest:** the file's blob, the symlink target's blob, or the directory's tree.
- **Names.** A name is UTF-8 with no `/`, NUL or newline, and is not `.` or `..`. Entries are sorted by
  the bytes of the name, and no name appears twice.
- **One encoding per tree.** A reader decodes a tree, encodes it again and refuses it unless the
  bytes are identical.
- **What isn't kept.** Sockets, FIFOs and devices are left out, as bundles leave them out today. So
  are owners: a restore writes everything as its own user.

This is git's model in a form we can read in a few dozen lines. Unchanged files and directories
share their objects across hibernations, snapshots, forks and agents. A tree's digest is a Merkle
root, so a whole workspace is named, checked and granted by one digest.

**Large files** are one blob in v1. Content-defined chunking for files that change a little at a
time (SQLite databases, linked binaries) is an open question below.

### Refs

A digest says what something is. A **ref** is a name that points to a digest: `sha256:…` and a
newline, stored under `r/<name>`.

- **Write-once.** A ref is written put-if-absent, as every object is, and is never rewritten. A name
  that has to move is a sequence of names: hibernation already uses `<seq>.<generation>`.
- **The ledger stays the truth.** A hibernated agent's head, a named snapshot's owner and retention, and
  a volume snapshot's grant are ledger rows that hold a digest.
- **Refs in the store** are for what has to outlive the ledger: the pre-update ledger snapshots, which
  are the way back when the ledger itself is what went wrong. They are also roots for garbage
  collection, below.

### Layout in a backend

The store runs on the existing `ObjectStore` backends: `DirStore` (a directory) and `S3Store` (any
S3-compatible store, with `If-None-Match: *`). It needs nothing from a backend but put-if-absent,
get, has, delete and a prefix listing.

```
o/<hex>               an object: zstd(-3) of its bytes
r/<name>              a ref: "sha256:<hex>\n"
p/<hex>               a pack (later, below)
```

**Every read is verified.** The bytes are decompressed and hashed as they are read, and a reader that
reaches the end of an object whose hash isn't its name gets an error instead of end of file.
Callers already write to a temporary file and move it into place only once it is complete, so
nothing unverified is used.

### Sealing

The store sits on `SealedStore`, unchanged: AES-256-GCM in 64 KiB chunks, with the key's id in the
header and the object's key (`o/<hex>`, `r/<name>`) in each chunk's associated data. Two things change:

- **No plain fallback.** `SealedStore` still reads unsealed objects written before #146. Over the
  content-addressed store that is a hole: anyone who can write the bucket could plant a plain ref
  pointing at a plain object, and it would be read as if wicket had written it. The store opens
  its backend with plain reads off (`SealedStore::sealed_only`). Old prefixes keep the fallback until
  their users move.
- **One key per store, not per agent.** Forks (#177) and shared volume snapshots (#251) only share
  storage if their objects are sealed under the same key. That key is `state.key` today: one
  installation, one tenant. E5 recommended per-agent repositories, for crypto-shredding; with one
  store, shredding is done per tenant (a key per tenant's store) and by deleting objects, not keys.

**What sealing doesn't hide:** object names (the sha256 of the content) and sizes. Someone who can
list the bucket can confirm that a file they already have is stored there. Naming objects by an HMAC
of the digest under the store's key would close that, and is an open question.

## Where it lives

- **Every host has a local store**, `<data dir>/store/`: the control host and each node. It is the
  working store for everything that host makes, and the cache for everything it fetches.
- **The state store** (#154), when one is configured, is the shared store, under the same layout and
  sealed under the same key. What has to survive losing a host goes there: hibernation trees (with
  `bundles: s3`), named snapshots, volume snapshots that are granted across nodes, and ledger
  snapshots.
- **Between nodes**, objects move over the existing authenticated node channel, as `has` and `get` by
  digest. A node asks for what it lacks; whoever answers sends bytes, and the receiver checks them
  against the digest. That needs no trust in the sender beyond "it may have this digest".

## Caching and transfer

These are what the store does, not separate features (closed #139 and #193).

- **Reads** go: the local store, then a peer that is known to have the digest (the owner's node, for a
  volume snapshot or a fork's source), then the state store. Whatever is fetched is written to the
  local store once it has verified.
- **Writes** go to the local store, then to the shared store when the user needs it there. A
  hibernation that must survive the node goes to the state store before the ledger's pointer moves, as
  it does today.
- **Sending a tree** is like git's negotiation. The sender offers a tree's digest. The receiver walks
  it, asks `has` for each child digest it doesn't hold, and fetches only those. An incremental
  hibernation uploads only changed files, against today's whole changed tree. Most of what E5 measured
  for restic (5–18× less stored) comes from exactly this per-file sharing.
- **Packs.** Thousands of small files mean thousands of S3 PUTs. A push to a remote backend packs new
  small objects (under 1 MiB) into one pack object, `p/<hex>`, with an index of digest, offset and
  length. The local store keeps objects loose. A read of a packed object is a ranged GET, which
  `ObjectStore` gains for this. A pack is how objects travel and rest, never what is named: no grant
  or ref ever names a pack.
- **Nothing goes stale.** An object never changes, so a cache needs eviction (least recently used, up
  to a byte cap per host), never invalidation.

### Garbage collection

**Roots** are:

- every ref in the store;
- every digest the ledger holds: hibernation heads, named snapshots before their retention ends,
  volume snapshots with a live grant, and installed versions;
- objects written in the last hour, so a push still in progress isn't swept.

The reconciler marks everything reachable from the roots, then deletes the rest. It runs on the
control host, for the state store, and on each node, where the local store is also cut down to its
cache cap. Until that sweep exists, a user deletes only objects it alone reaches. For ledger
snapshots, that means the blob of a snapshot no other ref points to.

## What each format becomes

| Today | Becomes |
|---|---|
| **Hibernation bundle**: `StateManifest` and tar + zstd per tree | A **bundle tree**. Its entries are `workspace`, `state`, `tmp` and `volume.<name>` (trees), and `meta`, a blob of JSON: agent, generation, seq, session id. The ledger's head pointer holds the bundle tree's digest; fencing by generation is unchanged. The `<seq>.<generation>` names become refs `agents/<agent>/<seq>.<generation>`, so a push still can't overwrite another generation's. Restore keeps today's checks (only the three entry types, fresh directory, never through a symlink) and checks the tree digest it rebuilds. |
| **Named snapshot / fork** (#177) | A ledger row `{name, digest, owner, zone, expires}` holding a bundle tree's digest. `wicket snapshot` hibernates and records the head's digest under the name. `wicket fork` wakes a new agent from that digest, with a fresh id, identity and authority. Forks share every object. "Storage for 3 forks is about one copy plus their changes" follows from the store. |
| **Volume snapshot** (#251) | A tree digest. Freezing a volume puts its tree, and the read-only grant is a grant on that digest (below). A reader's node fetches the tree (from the owner's node or the state store), restores it once into a read-only directory keyed by digest, and bind-mounts it into each box that holds a grant. |
| **Ledger snapshot** (#167) | A blob, plus a ref `ledger-snapshots/<time>-<build id>.db` in the state store. The local copy in `<data dir>/snapshots/` stays a plain file, because the restore procedure opens it with SQLite. **The first PR.** |
| **Installed version** | The artifact is a blob, and the version is a tree `{wicket, manifest.json}`. The versions root stays as it is (a checkout, named by build id, because the binaries are run from there). Nodes fetch the binary by digest through the store instead of having it pushed over ssh. Root's own copies (#261) stay root's: root reads the blob by digest and checks it. |
| **Program source** | Its tree digest replaces `wicket-program-v1`. Symlinks and special files are still refused. Pins change once: `wicket zone pin` rewrites them. |
| **Image** (#191) | Stays OCI: an OCI layout's `blobs/sha256/<hex>` are already blobs named by their sha256. So an image's blobs can be carried and cached by the store, and the pin is still the OCI manifest's digest. The verified import (`oci::unpack_verified`) is unchanged. |

## "May this digest run" is a grant on the digest

With #256's grant record, every artifact is accepted the same way:

- the **resource** is `digest:sha256:<hex>`;
- the **action** is `run`, `install` or `mount`;
- the **scope** is a zone, a node or the installation;
- there is a **lifetime** and a **number of uses**;
- the grant was made by a **principal whose authority covers the scope**.

One function, `may_use(digest, action, scope) -> Grant`, is the only check, and every acceptance is
one audit record that names the grant.

| Today's answer | As a grant |
|---|---|
| Release key / CI signature (#190) | The CI principal holds a standing grant: it may grant `install` on wicket builds that meet `CiExpect` (repository, workflow, `main`, the `release` environment). A signature is that principal's grant on one digest, carried with the artifact and checked against its standing authority. A trusted release key is the same thing, without the claims. |
| Human-approved update sha256 (`request_update`) | A human's grant: `install`, one use, on that digest. It is what the UPDATE request already makes, now held on the digest. |
| Image pin (`name@sha256:…`) | The zone's approver grants `run` on that digest, scoped to the zone, when the manifest is approved. A child's inherited image is still covered by the same grant. |
| Program digest | The same, for a program's source tree. |
| Volume snapshot | The owner grants `mount` (read-only) on the tree's digest to another principal, within the owner's own authority. |
| Fork of a snapshot | The owner grants `run` on the bundle tree to the principal that forks it. The fork's own authority still comes fresh from its zone (#177). |

Done for #258, an update, a program and an image are all accepted through `may_use`. That needs
#256's grant record, so it lands after it.

## Order of the work

1. **The store API and ledger snapshots** (this PR). `wicket_store::cas`: `put`, `get` (verified)
   and `has` by digest; trees (the format, `put_tree`, `get_tree`); write-once refs; `has` on
   `ObjectStore` (a HEAD on S3); `SealedStore::sealed_only`. `snapstore` moves onto it. Snapshots
   that earlier builds pushed stay readable and are pruned the same way.
2. **Trees from directories**: `put_dir` and `checkout`, with bundle restore's checks, and the program
   digest as a tree digest.
3. **Hibernation bundles as bundle trees**, through the local store; push to the state store by
   negotiation; manifest version 2 alongside a reader for version 1 until no agent's head is version 1.
4. **Garbage collection** in the reconciler, and the local store's cache cap.
5. **Named snapshots and forks** (#177) on bundle trees.
6. **Transfer between nodes**: `has` and `get` on the node channel, reads falling through local, peer
   and state store; volume snapshots (#251) on it.
7. **Packs and ranged reads**, for remote backends.
8. **Installed versions** as blobs and trees fetched by nodes; then `may_use` over #256's grants for
   updates, programs and images.

## Open questions

- **Object names leak content hashes.** Name objects by HMAC(store key, digest) instead, or accept it,
  as today's bundle names already do?
- **One key per tenant.** Today there is one tenant and `state.key` is the key. How is a tenant's
  store key derived and rotated, and can a fork or a volume snapshot ever cross tenants (by
  re-sealing)?
- **Chunking large files.** Content-defined chunking (FastCDC is about a hundred lines) for big files
  that change a little at a time, or whole files only?
- **Non-UTF-8 names.** Today's bundles convert them lossily. The tree format refuses them; is that
  right for every user?
- **Copy-on-write restores** (#177's "later"). Objects in the local store are compressed, so a restore
  copies. Would large files be kept uncompressed locally, so a restore can reflink them?
- **Unsealed local caches.** A node's local store is sealed under the store's key, so nodes need the
  key. Or is each node's cache sealed under the node's own key, with plaintext only over the
  authenticated channel?
- **Ledger snapshots locally.** Should `<data dir>/snapshots/` become a local store with refs too, or
  stay plain files that SQLite opens directly?
