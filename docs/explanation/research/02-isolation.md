# 02 — Isolation substrates ("sandbox backends") and the Rust ecosystem

Research date: 2026-11-08. Scope: what wicket's pluggable `Sandbox` trait can sit on, from lightest to strongest. It covers how to force all egress through the harness proxy for each backend, how to give an agent a workdir and get typed output back, and how to snapshot a parked agent.

Confidence tags: **[H]** verified against a primary source (repo, official docs, or this machine), **[M]** secondary source or partly verified, **[L]** inference or memory, not checked.

---

## 0. TL;DR

- **The black-box agent decides the floor.** Claude Code needs a full Linux userland (bash, git, rg, Node or its native binary, package managers). Codemode substrates such as Wasm, V8 isolates, QuickJS and Monty cannot host it. They are for code the *harness* runs (adapter logic, agent-written tool scripts), not for the agent itself.
- **Everyone serious has converged on one pattern**, and it is the brief's pattern. Put the agent in a box with no route out except a host-side proxy. Hold real credentials outside the box. Hand the box sentinels or scoped tokens, which the proxy swaps or validates on egress. Docker Sandboxes, Anthropic's `srt`, Codex's `network-proxy`, microsandbox, Cloudflare Sandbox outbound Workers, E2B BYOP and Northflank all ship a variant of it in 2026. wicket's job is not to invent the box. Its job is to drive several boxes through one trait and point them all at one policy-enforcing proxy and gateway.
- **v1 on Linux:** (1) a native-Rust **process tier**: user, mount, PID and net namespaces, Landlock, seccomp, and a netns whose only exit is a UDS-bridged proxy. This is Codex's and srt's design, done in-process with `landlock`, `seccompiler` and `rustix`/`nix`. (2) A **gVisor (runsc) tier**, the strongest isolation that runs without KVM, and it has checkpoint/restore. (3) A **Firecracker tier** for KVM hosts, the right tool for snapshot-parking. **On macOS:** a Seatbelt process tier, then a Virtualization.framework VM tier (libkrun/microsandbox, or Apple `container`). **Remote:** E2B first, because BYOP forces egress through *our* SOCKS5 proxy on the host side. Cloudflare Sandbox second.
- **This box (the development host, a Vultr VC2) has no KVM.** There is no `/dev/kvm` and the guest CPU has no `vmx` flag. No microVM backend can run here: Firecracker, Cloud Hypervisor, libkrun, Kata, microsandbox and Docker Sandboxes all need KVM. Landlock is ABI 4 (kernel 6.8). Ubuntu 24.04's AppArmor userns restriction blocks unprivileged bubblewrap, but sudo works. The process tier and gVisor can be built and tested here. MicroVM work needs a Vultr bare-metal box (cheapest in `lhr`: `vbm-6c-32gb`, $0.253/h, but billed monthly) or a Mac with an M3 or later chip.

---

## 1. This machine's capabilities (checked read-only, 2026-11-08) [H]

| Probe | Result | Implication |
|---|---|---|
| `uname -r` | `6.8.0-147-generic`, Ubuntu 24.04.5, x86_64, 4 vCPU, 7.9 GiB RAM | Host kernel is older than any Landlock ABI after 4 |
| DMI / dmesg | `Vultr VC2`; `Hypervisor detected: KVM` (`systemd-detect-virt` says `microsoft` because KVM exposes Hyper-V enlightenment CPUID) | Regular cloud compute VM |
| `/dev/kvm` | **absent**; `/proc/cpuinfo` has `hypervisor` but **no `vmx`/`svm`** | **No nested virt.** Firecracker, Cloud Hypervisor, libkrun, Kata, microsandbox and Docker Sandboxes (sbx) cannot run here |
| `/sys/kernel/security/lsm` | `lockdown,capability,landlock,yama,apparmor` | Landlock is enabled |
| `landlock_create_ruleset(NULL,0,VERSION)` | **ABI 4** | FS rights plus TCP bind/connect. No IPC scoping (ABI 6), no UDP rules (ABI 10), no TSYNC (ABI 8) |
| seccomp | `actions_avail: kill_process kill_thread trap errno user_notif trace log allow` | seccomp-bpf, including `SECCOMP_RET_USER_NOTIF`, is available |
| `unshare --user --map-root-user` (as `claude`) | **fails**: `write /proc/self/uid_map: Operation not permitted` | `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 24.04 default). Unprivileged bwrap, srt and Codex's sandbox fail unless an AppArmor profile grants `userns` or the sysctl is turned off |
| `sudo unshare --user --map-root-user --net --mount --pid --fork` | **works** | A small privileged helper (or a per-binary AppArmor profile) unblocks the process tier |
| cgroups | cgroup2 unified | Resource limits via cgroup v2 |
| Kernel config | `USER_NS=y`, `SECCOMP_FILTER=y`, `SECURITY_LANDLOCK=y`, `NF_TABLES=m` (loaded), `VETH=m`, `OVERLAY_FS=m`, `FUSE_FS=y`, `VIRTIO_FS=m`, `KVM=m` (useless here) | netns + veth + nftables + overlayfs all available |
| Devices | `/dev/net/tun`, `/dev/fuse`, `/dev/vhost-vsock` present | TAP/FUSE usable. vhost-vsock is pointless without KVM |
| Installed | no docker, podman, bwrap, nsjail, runsc, nft CLI or passt. Node v18.19.1, Claude Code 2.1.319 | Nothing is installed yet. Per instructions, nothing was installed |

**Vultr and nested virtualization.** No official Vultr document on nested virt turned up. The evidence is a 2019 Vultr staff forum reply ("not supported on VPS, use bare metal") and a 2021 NANOG report of the same [M], and this box confirms it [H]. Vultr bare metal runs on physical hardware, so KVM is native there. The live catalog (Vultr API, 2026-11-08) [H] lists London (`lhr`) bare-metal plans: `vbm-6c-32gb` (E-2286G, 6c/12t, 32 GB) at $0.253/h ($185/mo), `vbm-6c-32gb-amd` (EPYC 4245P) at $0.41/h, and `vbm-8c-64gb-amd` at $0.55/h. All of them say `invoice_type: monthly`, so expect monthly billing rather than hourly [M]. A test box therefore has to justify a month of cost, or the tests run on a Mac or a hosted backend.

Sources: https://discuss.vultr.com/discussion/1957/ask · https://mailman.nanog.org/pipermail/nanog/2021-January/211590.html

---

## 2. Process-level isolation

### 2.1 Linux primitives

**Landlock** [H] (https://docs.kernel.org/userspace-api/landlock.html, built from 7.4.0-rc1, Oct 2026). Unprivileged and stackable (up to 16 layers), and inherited across fork/exec. ABI history:

| ABI | Kernel | Adds |
|---|---|---|
| 1 | 5.13 | FS: execute, read/write file, read dir, make/remove entries |
| 2 | 5.19 | `REFER` (cross-directory rename/link) |
| 3 | 6.2 | `TRUNCATE` |
| 4 | 6.7 | **Network: `BIND_TCP`, `CONNECT_TCP` per port** (ports only, not addresses) |
| 5 | 6.10 | `IOCTL_DEV` |
| 6 | 6.12 | **Scopes: abstract UNIX sockets, signals** (IPC out of the domain) |
| 7 | 6.15 | Audit logging of denials (`LANDLOCK_RESTRICT_SELF_LOG_*`) |
| 8 | 7.0 | `TSYNC`: apply a ruleset to all threads atomically [M: 7.0-rc1 merge, sample bump 2026-03-04] |
| 9 | ? | `RESOLVE_UNIX`: restrict connects to pathname UNIX sockets made outside the domain [M] |
| 10 | ? | UDP: `BIND_UDP`, `CONNECT_SEND_UDP` [M: v5 patch series June 2026; the doc lists it, the merge kernel is unconfirmed] |
| 11 | ? | `RESTRICT_SELF_NO_NEW_PRIVS` [M] |
| 12 | ? | Capability and namespace-use restrictions [M] |

(The kernel versions for ABI 1–7 are from memory and well established [H/M]. For ABI 9–12 the doc page lists the features but not the kernels, so those are [M].)

What Landlock cannot do: TCP rules are by **port**, not destination address, so it cannot express "only the proxy". It cannot restrict `chdir`/`stat`/`chmod`/`chown`/`setxattr`/`fcntl`/`access`, or pre-opened fds. UDP and raw sockets are unrestricted before ABI 10. **Conclusion:** Landlock is a filesystem layer plus belt-and-braces. Network confinement must come from a **network namespace**. On this box (ABI 4), add a seccomp filter for socket families.

Rust: **`landlock` 0.4.7** (2026-07-27, official landlock-lsm crate, 7M recent downloads) [H]. It has a "best effort" compat mode that degrades by ABI, and wicket should *fail closed* rather than degrade silently for anything the policy depends on.

**seccomp-bpf** [H]: `seccompiler` 0.5.0 (rust-vmm, used by Firecracker; pure Rust, compiles a JSON or Rust filter to BPF) and `libseccomp` 0.4.0 (C bindings). Codex's pattern [H]: after the mount view is built, set `PR_SET_NO_NEW_PRIVS` and install a filter that blocks network syscalls (restricted mode) or `AF_VSOCK` (otherwise). **All modes block `io_uring`**, which otherwise bypasses socket-family filters. In proxy mode it also blocks new standalone `AF_UNIX` sockets. srt adds a second filter [H] that refuses `unshare`/`clone` with `CLONE_NEWUSER|CLONE_NEWNS`, `setns`, `mount`, `umount2`, `pivot_root` and the new mount API, and returns `ENOSYS` for `clone3` so libc falls back to `clone`, whose flags BPF can inspect. Without that filter, a sandboxed process can make a nested userns and unmount the read-only binds that enforce write denies. wicket needs both rules. `SECCOMP_RET_USER_NOTIF` (available here) would let the harness supervise specific syscalls, such as `connect` to an unexpected address, but it is TOCTOU-prone for pointer arguments [L].

**Namespaces** via `rustix` 1.1.6 or `nix` 0.31.3 [H]. The minimal set is user + mount + PID + net + IPC + UTS (+ cgroup). A **fresh netns also scopes abstract UNIX sockets**, because they are per-netns, and a PID ns scopes signals. That covers Landlock ABI 6's job on older kernels like this one [M, standard kernel semantics].

### 2.2 Tools and how others use them

- **bubblewrap** 0.13.1 (2026-10-14) [H]. The de facto unprivileged sandbox (Flatpak, Codex, srt). `--disable-userns` needs ≥0.8.0. srt supports ≥0.4.0 (≥0.5.0 for some file binds) [H].
- **nsjail** 3.6 (2026-03-18) [H]. Namespaces, Kafel seccomp policies, cgroups, MACVLAN or **pasta** userland networking. A good config reference. C++, so it is a subprocess, not a library.
- **Anthropic sandbox-runtime (`srt`)** v0.0.81 (2026-10-20, TypeScript, "beta research preview") [H] https://github.com/anthropic-experimental/sandbox-runtime
  - macOS: generated Seatbelt profile that allows network only to the localhost proxy port. Linux: bubblewrap with **netns removed entirely**. The proxies listen on UNIX sockets bind-mounted into the sandbox and bridged with `socat`. Windows (alpha): a dedicated `srt-sandbox` local user plus a WFP egress fence keyed on its SID.
  - HTTP proxy plus SOCKS5 proxy. Domain allow/deny lists, a resolved-address check (blocks names that resolve to private IPs), and an "ask callback" for undecided hosts.
  - **`network.tlsTerminate`** (experimental): in-process MITM with a supplied or ephemeral CA. It sets `SSL_CERT_FILE`, `GIT_SSL_CAINFO` and similar to a bundle of MITM CA plus host roots. `excludeDomains` tunnels pinned or mTLS hosts opaquely, without credential injection.
  - **`credentials`**: env vars and files in `deny` or `mask` mode. `mask` puts a **sentinel** in the sandbox, and the proxy substitutes the real value on egress to `injectHosts` only. Masking requires TLS termination. There is also SigV4 re-signing for AWS.
  - **`--control-fd`**: live policy updates (network lists apply on the next connection; FS rules do not change). This is the dynamic-escalation mechanism in miniature.
  - **`srt proxy`**: the proxy alone, with **an external decider process** speaking a framed-JSON protocol. It terminates every CONNECT and forwards only on an allow verdict, which can set headers. **This is almost exactly wicket's egress-proxy contract.** It is worth reading `docs/srt-proxy.md` before designing wicket's proxy/decider split.
  - Ubuntu 24.04 note: needs `kernel.apparmor_restrict_unprivileged_userns=0` or an AppArmor profile granting `userns`. That is this box.
- **Codex CLI (Rust, Apache-2.0)** [H] https://github.com/openai/codex/tree/main/codex-rs/linux-sandbox — the best Rust reference.
  - Linux: bubblewrap is the default. It prefers system `bwrap` and falls back to a vendored one. The old Landlock-only path is "legacy" and is *rejected* for filesystem-restricted policies "because it cannot isolate app-server Unix sockets".
  - `--ro-bind / /`, then `--bind` for writable roots, then **re-`--ro-bind` protected subpaths inside writable roots (`.git`, resolved `gitdir:`, `.codex`)**. Path-specificity ordering, deny globs expanded with `rg` before launch, symlinks or missing components in protected paths masked with `/dev/null`.
  - `--unshare-user`, `--unshare-pid`, and `--unshare-net` when network is restricted. In **managed proxy mode** it uses `--unshare-net` plus an internal **TCP→UDS→TCP bridge**, so tool traffic reaches only the proxy endpoints, then seccomp blocks new `AF_UNIX`.
  - macOS: Seatbelt `.sbpl` profiles in `codex-rs/sandboxing/src/` (`seatbelt_base_policy.sbpl` starts `(deny default)`, modelled on Chromium's renderer policy), with proxy-specific allow rules injected at runtime.
  - `codex-rs/network-proxy` is a **Rust** HTTP+SOCKS5 policy proxy with MITM (CA key kept in memory, CA bundle env vars set for children), `mitm.hooks` (host + method + path-prefix → actions such as `strip_request_headers`), a `credential_broker` module, `aws_sigv4`, and a "limited" read-only mode. It is a candidate to fork or vendor for wicket's egress proxy.
- **Seatbelt / `sandbox-exec` (macOS)** [M]. The man page has marked it deprecated for years, but it is still the mechanism in Codex, srt/Claude Code and Chromium. It allows path-, network- and mach-service-level rules, cannot change the filesystem view, and inherits across fork/exec. Gotchas: Go binaries need `com.apple.trustd.agent` to verify TLS, which srt flags as a potential exfil vector [H]. Loopback can bypass the proxy unless denied.

### 2.3 Rust crates (versions from crates.io, 2026-11-08) [H]

| Crate | Version / updated | Notes |
|---|---|---|
| `landlock` | 0.4.7 / 2026-07 | Official. Use it |
| `seccompiler` | 0.5.0 / 2025-03 | rust-vmm, pure Rust. Stable, slow-moving |
| `rustix` / `nix` | 1.1.6 / 0.31.3 | Namespaces, mounts, `pivot_root`, `clone3`, pidfd |
| `hakoniwa` | **1.8.1 / 2026-11-08** | Actively maintained: namespaces, pivot_root, **pasta networking**, cgroup v2 via systemd, Landlock, seccomp, TOML profiles. The closest "library bwrap" in Rust. Small community (96★) |
| `birdcage` (Phylum) | 0.8.1 / 2024-04 | Linux namespaces plus macOS `sandbox_init`. FS and network only. Stale |
| `extrasafe` | 0.5.1 / 2024-04 | seccomp + Landlock + userns "Isolate". Self-sandboxing oriented. Stale |
| `gaol` | 0.2.1 / 2019 | Dead |
| `zerobox-linux-sandbox` | 0.3.3 / 2026-05 | "Sandbox any command with file, network, and credential controls". Appears Codex-derived [L]. Worth a look |

**Recommendation:** write wicket's process tier directly on `rustix` + `landlock` + `seccompiler`, borrowing Codex's mount-plan logic and srt's namespace-escape seccomp rules. Shell out to `bwrap` only as a fallback. Treat `hakoniwa` as reading material or an optional dependency rather than a foundation (bus factor).

### 2.4 Security assessment of the process tier
- It shares the host kernel, so a kernel LPE escapes it. That is acceptable for "the agent is mostly benign but its inputs are not". It is not enough for adversarial multi-tenant use. Anthropic's own split [H]: Claude Code uses Seatbelt/bubblewrap, claude.ai code execution uses **gVisor**, and Cowork uses a full VM. https://www.anthropic.com/engineering/how-we-contain-claude (2026-05-25)
- Same-UID processes outside the sandbox are reachable through anything the sandbox can see (UNIX sockets, `/proc`, shared tmp). Use a fresh `/proc`, private `/tmp`, PID ns, and ideally a **dedicated UID per sandbox**, which the privileged helper makes easy.
- Nested sandboxing inside the box breaks: Chromium's sandbox, rootless podman, `unshare -r`. srt documents this cost of blocking nested userns [H]. For Claude Code it matters only if the agent runs browsers or containers.

---

## 3. Containers

- **Rootless Podman 6.1.4 / Docker** [H versions]. Podman's rootless default networking is **pasta** (passt project, user-mode TCP/IP translating guest L2 to host sockets) since Podman 5 [M]. bollard 0.21.1 speaks the Docker Engine API, and Podman serves a compatible API socket [H/M]. A plain runc/crun container is roughly the process tier plus image management. Its isolation is the same shared kernel.
- **youki** 0.7.0 (2026-07) [H]: an OCI runtime in Rust. The `libcontainer` crate (0.7.0) is embeddable, so wicket could build OCI bundles (`oci-spec` 0.10.0) and run them in-process without a daemon. Useful if v1 wants OCI-image rootfs without Docker.
- **gVisor (runsc)** release-20261102.0 [H]. A user-space kernel (Sentry) that intercepts syscalls. The **systrap platform needs no KVM**, so it runs on this box [M]. KVM platform is optional.
  - Networking: `--network=sandbox` (gVisor netstack in the Sentry, attached to a veth in the container netns), `none`, or `host`. Netstack means guest TCP/IP bugs land in a Go user-space stack, not the host kernel.
  - FS: gofer/directfs. Rootfs overlay can be memory- or file-backed [M].
  - **Checkpoint/restore** [H] (https://gvisor.dev/docs/user_guide/checkpoint_restore/): `runsc checkpoint --image-path`, restore into a new container with `runsc create` + `runsc restore`. *Background restore* (lazy page loading) is on by default and needs `--compression=none`. Host-network sockets are not saved, and connected sockets get `ECONNRESET` on restore. Restore needs the same CPU features. `CLOCK_MONOTONIC` pauses while REALTIME/BOOTTIME jump. Rootless checkpointing was unsupported at least in the past [M], so run runsc as root via the helper.
  - Rust: no official client. Drive the `runsc` CLI with OCI bundles from `oci-spec`, or via containerd (`containerd-client` 0.9.0) with the runsc shim.
  - **Best no-KVM strong tier**, and it gives this box a real snapshot/park capability. Anthropic and Modal both run untrusted code on gVisor [H].
- **Kata Containers** 4.3.1 [H]. 4.0 (2026-07-22) made the **Rust runtime-rs** the default, with the built-in **Dragonball** VMM. It also supports Cloud Hypervisor and QEMU [M]. It is an OCI/CRI runtime that gives each pod a VM, which suits Kubernetes-scale fleets. It is heavyweight for a single-host harness and needs KVM.

---

## 4. microVMs

All need **KVM** on Linux (or HVF/WHP elsewhere). None run on this VPS.

### 4.1 Firecracker — v1.17.0 (2026-09-10); 1.18.0 in CHANGELOG [H]
- Spec (enforced in CI) [H] https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md: VMM start ≤ 8 CPU-ms (wall clock ~12 ms typical), **≤125 ms from InstanceStart to guest `/sbin/init`**, **≤5 MiB VMM memory overhead** (1 vCPU / 128 MiB), more than 95% of bare-metal compute.
- Devices: virtio-net (**TAP only**), virtio-block (plus vhost-user-block, discard as of 1.17), **virtio-vsock** (guest AF_VSOCK ↔ host UDS), balloon (with free-page reporting/hinting), **virtio-mem hotplug**, serial, and PCI transport with device hotplug in developer preview. **No virtio-fs, no 9p** [H: absent from the changelog; long-standing project stance]. The workdir has to be a block device or go over vsock.
- **Snapshots** [H]: full and diff (dirty-page) snapshots via `PUT /snapshot/create` / `PUT /snapshot/load`. Format v1.0.0 since 1.7 breaks pre-1.7 snapshots. `snapshot-editor` merges diffs. Memory can be restored lazily via a **UFFD** handler. 1.17 added `sync_snapshot_files=false` for fast creation and `huge_pages` on load. vsock UDS paths can be overridden on restore. The vsock device sends `TRANSPORT_RESET` on restore, so **all vsock connections die**. Guests should not be cloned from one snapshot without regenerating entropy and identity (VMGenID support exists [M]).
- **MMDS** [H]: a metadata service at a link-local IP, served by the VMM from a JSON store and configured over the API. It suits non-secret per-sandbox config (proxy address, task id). Keep long-lived secrets off it. MMDS v2 uses session tokens.
- **Jailer** [H]: chroot, PID/net namespaces, cgroups, a dropped UID, and a seccomp filter per VMM thread. Run each microVM under the jailer.
- Rust control: the API is a REST/OpenAPI server on a UDS. Crates: **`fctools` 0.6.0** (2026-05, "exhaustive, modular host SDK") [H] and `firepilot` 1.2.0 (2023, stale). Writing a thin client from the swagger with `hyper` over a UDS is also trivial.
- Who uses it: AWS Lambda/Fargate, E2B, and Daytona (its v2 docs say Firecracker) [M]. One sandbox vendor (wrenn) **migrated from Firecracker to Cloud Hypervisor** in May 2026 [M], presumably for features.

### 4.2 Cloud Hypervisor — v54.0 (2026-10-14) [H]
- Rust (rust-vmm). virtio-fs (via `virtiofsd` 1.14.0, Rust), vhost-user, VFIO, hotplug, **snapshot/restore and live migration**. v52 (May 2026) added **userfaultfd demand-paged restore**, v53 an offloaded snapshot/restore daemon and mTLS-encrypted migration, v54 migration across the two prior versions [M: Phoronix]. CVE-2026-45782 (virtio-block UAF) was fixed in 51.2 [M].
- REST API over UDS. `cloud-hypervisor-client` 0.6.0 (unofficial, 2026-05) [H].
- Compared with Firecracker: more features (virtiofs is the big one for a live workdir), larger attack surface, slightly heavier. It is a good alternative VM backend, and Kata and Northflank use it.

### 4.3 libkrun / krunkit / muvm / microsandbox
- **libkrun** v1.19.8 (2026-11-06; the crate `libkrun` is the library itself and is Rust; `krun-sys` 1.10.1 bindings are older) [H]. It is a library, not a daemon: the process *becomes* the VMM. It runs on KVM (Linux), **HVF (macOS ARM64)**, and WHP (Windows, upcoming). Devices: virtio-fs (rootfs can be a host directory), vsock, net, gpu (venus). SEV/TDX variants exist.
  - Networking [H]: **TSI (Transparent Socket Impersonation)** hooks guest `AF_INET/INET6/UNIX` socket calls over vsock and performs them **in the VMM's host network context**. Alternatively virtio-net + passt/gvproxy.
  - Its security model doc [H] says plainly: "The VM boundary alone does not restrict the host resources exposed through those devices". Run the VMM itself in namespaces with a restricted netns, and confine the virtio-fs export with a mount ns + `pivot_root`. So a libkrun backend = process-tier jail around the VMM + VM.
  - Upstream libkrun has no snapshot/restore that I found (no mention in the README) [M].
- **muvm**: a libkrun-based tool for running x86 apps on Asahi. Not relevant [L].
- **microsandbox** v0.7.13 (2026-11-01, Rust, Apache-2.0, "beta") [H]. A self-hosted microVM sandbox platform on **libkrun + smoltcp** (user-space network stack). Linux (KVM), macOS (Apple Silicon), Windows. Rust, Python, JS, Go and Ruby SDKs plus an MCP server. Features [H, README/docs]:
  - per-sandbox `network.allow` hosts and ports
  - **`secrets: [{env, value, allowed_host}]`** ("secret keys that never enter the VM"; placeholder substitution at egress [M on the mechanism])
  - **disk and full (memory + process) snapshots, live fork with CoW memory**, nested virt on x86-64/Apple Silicon
  - snapshot limits: host connections are not captured, host mounts are not included, matching CPU and memory are needed, and full snapshots and fork are **local only**
  - It is the closest open-source analogue to a wicket microVM backend, and it is Rust. Two options: use it as a backend through its crate (`microsandbox` 0.7.13), or read it as a design reference. Beta API churn is the risk.

### 4.4 Docker Sandboxes (sbx), 2026 [M]
- Launched around March 2026. Each agent gets its own microVM with its own kernel and Docker daemon. Docker wrote **its own VMM**, not Firecracker: Hypervisor.framework on macOS (Apple Silicon, Sonoma or later), WHP on Windows 11, KVM on Linux ("without KVM sbx won't start").
- Architecture (docs.docker.com/ai/sandboxes/architecture) [H for the doc content]:
  - Workspace via **virtiofs passthrough** with caching on, or a "clone mode" with the host repo read-only at `/run/sandbox/source` and a private clone inside.
  - **All outbound TCP goes through a host-side proxy**: HTTP/HTTPS via a forward proxy, other TCP forwarded transparently, policy enforced on both, deny by default.
  - **Credential injection by sentinel replacement** after the request leaves the VM. Blogs report a per-session CA installed in the VM [M].
  - A host-side **MCP gateway** per sandbox that also governs tool calls.
  - No snapshot feature is documented.
- This is the closest *product* to the brief, and it validates the architecture. wicket differs in being policy- and zone-driven, backend-pluggable, and escalation-centric.

### 4.5 Others
- **crosvm** (Google, Rust, ChromeOS/Android) [M]. Mature and security-focused (per-device sandboxed processes, minijail). It has snapshot support [L]. No published control crate, and the project is oriented to its own ecosystem. Low priority.
- **Unikraft** 0.21.0 (2026-05) [H]. Unikernels with very fast boot. Browser Use runs agents in Unikraft Cloud micro-VMs [M, brief]. A unikernel can't host Claude Code's tooling (bash, git, apt) [L]. Skip.
- **QEMU microvm** machine type [L]. Works, but has a larger TCB. Skip.

### 4.6 macOS
- **Virtualization.framework (VZ)** [H, Apple docs]. Linux guests with virtio-fs, vsock, NAT/bridged/file-handle networking. **Save/restore of machine state from macOS 14** (`saveMachineStateTo`/`restoreMachineState`; arm64 only; `validateSaveRestoreSupport()`). **Nested virtualization on M3 or later with macOS 15** (`VZGenericPlatformConfiguration.isNestedVirtualizationEnabled`), so a Linux VM on a recent Mac can run Firecracker inside it, with a performance cost.
- **Apple `container`** 1.7.1 (2026-11-06; 1.0 shipped 2026-06-09) and the `containerization` Swift package [H/M]. **One lightweight VM per container** on VZ + vmnet, with virtiofs bind mounts. macOS 26 is the practical requirement. A Rust client crate exists (`apple-container` 0.1.0, via XPC, tiny) [H]. `objc2-virtualization` 0.3.2 gives raw VZ bindings [H].
- **HVF via libkrun/krunkit/microsandbox** is the Rust-native path on Mac.
- Anthropic's Cowork uses VZ on macOS and HCS on Windows, and **moved the agent loop to the host**, keeping only code execution in the VM [H, how-we-contain-claude]. That works for Anthropic's own agent. It does not work for wicket's black-box agents, whose whole process must live in the box.

---

## 5. Hosted sandboxes as backends

The key question for each is whether **egress can be forced through *our* proxy, enforced outside the guest**, which keeps credentials out and puts policy in our hands.

| Provider | Isolation | Egress control | Can we force all egress via our proxy? | Credentials kept out? | Snapshots |
|---|---|---|---|---|---|
| **E2B** (SDK py 2.63.0, 2026-11-04) | Firecracker microVMs [M] | `allowOut`/`denyOut` (IP, CIDR, domain; domain filtering needs `ALL_TRAFFIC` denied; allow wins), runtime `updateNetwork` (replaces, not merges) [H] | **Yes, BYOP** [H]: `network.egressProxy {address, username, password}`, a SOCKS5 proxy tunnelled **on the host after filtering**, invisible to guest code, fails closed if the proxy is down. **Caveats:** TCP only. UDP (DNS, QUIC) is not tunnelled. **UDP DNS to 8.8.8.8:53 is allowed automatically and goes direct.** Not available in self-hosted open-source `e2b-dev/runtime` | Yes, if our proxy (reachable from E2B infra) does MITM and injection. The proxy must be internet-reachable with SOCKS5 auth, so the per-sandbox username/password is the only thing in E2B's hands | Pause/resume exists [L] |
| **Cloudflare Sandbox** (`@cloudflare/sandbox` 1.0.3, 2026-10-22) | Each sandbox in its own VM on Cloudflare Containers [H] | **Outbound Workers**: handlers in the Workers runtime intercept outbound HTTP and **HTTPS** (since 2026-04-13: a **per-instance ephemeral CA** trusted in the sandbox, private key stays in the sidecar). `allowedHosts`/`deniedHosts` globs (deny by default once `allowedHosts` is set). Swap handlers live with `setOutboundHandler()` / `setOutboundByHost()` [H] | Effectively yes: the outbound Worker *is* the proxy, and it can forward to wicket's policy service. Non-HTTP TCP coverage not confirmed [M] | **Yes**, a first-class pattern: "the sandbox never sees the real credential" [H] | Backup/restore APIs exist [L] |
| **Modal** | gVisor, or VMs with their own kernel (KVM) [H] | `block_network`, `outbound_cidr_allowlist` (any protocol), `outbound_domain_allowlist` (beta: **TLS/443 only, SNI-matched, not decrypted; domain fronting possible; DNS unrestricted unless all blocked**), runtime policy replace (experimental) [H] | **Partly**: experimental `proxy_traffic_via_sidecar` relays outbound TCP 443 through a Sidecar, with other ports under the CIDR list [H]. We could run our proxy as the sidecar [L] | Only via the sidecar route [M] | Filesystem, directory and memory snapshots exist (`_experimental_enable_snapshot`) [M] |
| **Daytona** (v0.190.0) | Firecracker microVMs (v2 docs) [M] | `networkAllowList` / `networkBlockAll`, domain firewall, tier-gated runtime changes [M] | No forced-proxy feature found [M]. We could only allowlist our proxy's IP and set proxy env vars, which a non-proxy-aware client simply fails against. That is *fail-closed*, but **SNI/MITM only applies to traffic that chooses the proxy** | Only if the allowlist is exactly our proxy | Snapshots/archives exist [L] |
| **Northflank** | Kata + Cloud Hypervisor (gVisor for GPU) [M, vendor] | FQDN/IP network policies, host-enforced egress firewall, "secrets injected at egress", BYOC [M, vendor] | Likely via BYOC network policy [L] | Claimed [M] | ? |

**Hosted ranking for wicket:** **E2B first** (BYOP is the only documented host-side forced proxy; fix the DNS leak by requiring DoH through the proxy or accepting it as a low-bandwidth channel). **Cloudflare second** (strongest credential story, but the policy point is a Worker we write, which is fine as a thin forwarder to wicket). **Modal third** (gVisor plus sidecar). Daytona and Northflank are allowlist-only until verified.

Sources: https://docs.e2b.dev/network/internet-access · https://docs.e2b.dev/network/byop · https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/ · https://developers.cloudflare.com/sandbox/sdk/concepts/security/ · https://modal.com/docs/guide/sandbox-networking · https://www.daytona.io/docs/en/v2/isolation · https://www.daytona.io/docs/network-limits/ · https://northflank.com/product/sandboxes

---

## 6. Codemode / lightweight substrates

**What they are for in wicket:** code the *harness or gateway* executes on the agent's behalf (codemode tool scripts, generated adapter filters if they ever need logic, per-request policy hooks). They are also a possible "env" for agents that are themselves just LLM loops emitting code. **They cannot host Claude Code**, which needs bash, git, ripgrep, a POSIX fs and package managers.

**Security property:** the capability set is exactly the imported functions. There are no ambient syscalls, sockets or fs. That is a much smaller and more analysable boundary than an OS sandbox, and it matches the brief's "capabilities = typed functions" idea. The residual risks are bugs in the engine (V8 JIT bugs are the classic class; interpreters and Wasm are smaller), resource exhaustion (fuel, epochs, memory limits), and **the imported functions themselves**. Each import is a gateway call, so it goes through the same policy engine.

| Option | Version (2026-11) | Notes |
|---|---|---|
| **wasmtime** + `wasmtime-wasi` | 50.0.1 [H] | Component model with WIT-typed imports, which suit typed capabilities. **WASI 0.3.0 released 2026-06-11** (native async, `stream<T>`/`future<T>`). Wasmtime 46 enabled component-model async by default [M: wasi.dev]. Fuel and epoch interruption, memory limits, a pooling allocator (µs instantiation). Languages: Rust/C/Go/JS (via StarlingMonkey/ComponentizeJS), Python (componentize-py). The best substrate for "untrusted code with typed host functions" |
| **V8 via `v8` / `deno_core`** | v8 152.2.0, deno_core 0.413.0 [H] | Real JS/TS with the npm ecosystem minus Node APIs. Isolates are cheap (ms). Larger TCB and JIT risk. Cloudflare's model |
| **QuickJS via `rquickjs`** | 0.14.0 [H] | Small interpreter, easy to embed, no JIT. Good for small agent scripts. Slower |
| **Boa** | 0.22.0 [H] | Pure-Rust JS engine. Less mature |
| **Pydantic Monty** | v1.5.0 (2026-11-05) [H] | Rust bytecode VM for a Python subset (Ruff parser). No fs, env or network. **External functions pause execution and are serviceable by the host. State is serializable and resumable across processes** [M], which fits "park while waiting for approval" nicely. No third-party packages |
| **Cloudflare Code Mode / Dynamic Workers** | Code Mode blog Sept 2025. Dynamic Workers **open beta 2026-03-24** [M] | MCP tool schemas become a generated TS API. The LLM writes code that runs in a fresh isolate with `globalOutbound: null` (no network) and only RPC bindings to MCP servers [M]. A hosted reference design |
| **Anthropic "code execution with MCP"** | 2025-11-04 [H] | Present MCP servers as code APIs (filesystem of tool modules). The example cut 150k→2k tokens. Notes that it "requires a secure execution environment with appropriate sandboxing" |

https://www.anthropic.com/engineering/code-execution-with-mcp · https://blog.cloudflare.com/code-mode/ [L: URL from memory] · https://developers.cloudflare.com/changelog/post/2026-03-24-dynamic-workers-open-beta/ · https://wasi.dev/releases/wasi-p3 · https://pydantic.dev/articles/pydantic-monty

**For wicket:** a `CodeModeSandbox` backend (wasmtime first, Monty second) whose `exec` takes a script and whose "network attachment" is a set of host-function bindings to the MCP gateway. It is cheap, very strong, and snapshotable (Monty natively, Wasm via instance-state serialization, which is not standard [L]). It is the right tier for "readers" zones that only call tools.

---

## 7. Networking: forcing ALL egress through the harness proxy

Principle (the brief's complete mediation): **the sandbox must have no network path except to the harness proxy and gateway, enforced outside the sandbox.** Proxy env vars (`HTTPS_PROXY`) are a *convenience* so clients use the path. Enforcement must hold for clients that ignore them, and they should fail closed.

### 7.1 Per-backend attachment patterns

| Backend | Pattern | Notes |
|---|---|---|
| Process tier (Linux) | **A. No-interface netns + UDS bridge** (srt/Codex): `unshare(CLONE_NEWNET)` with only `lo`. The proxy listens on a UNIX socket bind-mounted in. A tiny in-sandbox forwarder (srt: socat; Codex: built-in TCP→UDS bridge) listens on `127.0.0.1:3128/1080`. `HTTP(S)_PROXY`/`ALL_PROXY` point there | Simplest and strongest: there is no route at all. Non-proxy-aware clients fail. Block new `AF_UNIX` sockets after setup (Codex) so the agent can't reach other host sockets. The forwarder runs inside the sandbox, which is fine because it can only reach the proxy socket anyway |
| | **B. veth + nftables (transparent)**: a veth pair into a per-sandbox netns. On the host side an nftables ruleset DNATs/TPROXYs all TCP to the proxy, allows UDP 53 only to the harness resolver, and drops everything else, including IPv6 RAs and ICMP | Handles non-proxy-aware clients (the transparent proxy reads SNI / Host). Needs root (the helper). Rust: `rtnetlink` 0.24.0, `rustables` 0.9.0 / `nftables` 0.6.3, `netns-rs` 0.2.0 [H]. More moving parts, but it is also the TAP pattern for VMs, so it is shared code |
| | **C. pasta** (rootless user-mode stack) | Gives the netns full host connectivity via user-space sockets. Destination filtering would need pasta options or nftables in front [L]. Not recommended as the enforcement point |
| gVisor | `--network=none` + host-UDS connect for the proxy socket (runsc `--host-uds` options [L]), **or** `--network=sandbox` (netstack) on a veth in a netns with pattern B | Netstack keeps guest TCP/IP parsing out of the host kernel |
| Firecracker / Cloud Hypervisor | **D. vsock-only**: no virtio-net at all. A guest agent (PID 1 or a service) exposes `127.0.0.1:3128` and forwards over AF_VSOCK to the host UDS (Firecracker maps guest→host vsock port N to `<uds_path>_N`) where the proxy listens | Smallest host attack surface (no host network stack exposure, no IP config, no DNS). Pure proxy-mode semantics like pattern A. libkrun's TSI is a generalized version of this |
| | **E. TAP + nftables** (pattern B with a TAP in the jailer's netns) | Needed for transparent interception of arbitrary TCP. Firecracker only supports TAP for net [H] |
| libkrun / microsandbox | TSI performs connects *in the VMM process* → put the VMM in a netns with pattern A or B. microsandbox already does allowlisting in smoltcp [M] | Per libkrun's own security model [H] |
| macOS Seatbelt | Profile allows `network-outbound` only to `localhost:<proxyport>`, and denies other loopback (srt/Codex) | Loopback to other local services must be denied explicitly |
| macOS VZ VM | vsock-only (VZ supports virtio-vsock) or NAT with host pf rules [L] | Prefer vsock |
| E2B | BYOP SOCKS5 to a wicket-run, internet-reachable proxy, plus `denyOut ALL_TRAFFIC` | DNS leak (8.8.8.8:53) |
| Cloudflare | Outbound Worker → wicket policy API | |

**DNS:** never give the sandbox a real resolver. In proxy mode (A or D), the proxy resolves names (CONNECT hostnames / SOCKS5 ATYP=domain), so the sandbox needs no DNS. Glibc may still want `/etc/hosts` / `/etc/resolv.conf`, so point them at nothing. In transparent mode, run a harness resolver that answers only policy-allowed names. Otherwise DNS is an exfil channel [standard; H for E2B/Modal docs calling it out]. Block UDP/QUIC: clients fall back to TCP/TLS.

**SSRF / local network:** the proxy must refuse destinations that resolve to loopback, link-local, RFC1918 or metadata IPs (169.254.169.254, *Vultr's metadata service too*) unless explicitly allowed. srt calls this "the resolved-address check" [H].

### 7.2 TLS: SNI-only filtering vs. interception

| | SNI/CONNECT-host filtering | TLS termination (MITM) with per-sandbox CA |
|---|---|---|
| Sees | hostname only | method, path, headers, body |
| Supports (provider, resource, verb) policy | **No** | Yes. Required by the brief's gateway model |
| Credential injection | **No** (can't add headers to an encrypted stream) | Yes (sentinel → real header on egress) |
| Weaknesses | **Domain fronting** on shared CDNs (Modal docs say so explicitly), ECH hides SNI, can't stop "allowed domain, attacker's account" | Proxy is a high-value TCB. Pinned clients break. CA must be trusted by every client |
| Pinned clients | Work | Must go to `excludeDomains` (opaque tunnel, SNI-only, **never inject credentials there**) |

**Anthropic's lesson** [H, how-we-contain-claude]: Cowork allowlisted `api.anthropic.com`. An injected prompt used an *attacker's* API key to upload workspace files to the attacker's account. "Every function reachable through any domain on an allowlist is now an attack surface." The fix was a MITM that passes only requests carrying the VM's provisioned session token. **For wicket this means MITM is mandatory for any credentialed provider.** The proxy should *replace* auth headers: drop whatever auth the agent sent and inject the real credential only when the request presents the sandbox's sentinel. That blocks bring-your-own-key exfiltration.

**Injecting the CA** (per sandbox, ephemeral, key never in the box; generate with `rcgen` 0.14.10 [H]):
- System store in the rootfs (`/usr/local/share/ca-certificates` + `update-ca-certificates`, or overlay a prebuilt `/etc/ssl/certs/ca-certificates.crt`).
- Env: `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS` (Node, so Claude Code), `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT`, `DENO_CERT`, `CARGO_HTTP_CAINFO` (srt and Codex set a similar list [H]).
- Things that ignore these [M/L]: binaries with **bundled `webpki-roots`** (many Rust CLIs), the **JVM** (own keystore; needs `keytool` import or `-Djavax.net.ssl.trustStore`), **Go on macOS** (uses the system trust service, hence srt's `trustd` caveat), Electron/Chromium (NSS DB), and apps with real **certificate pinning** (some cloud SDKs, mobile-style clients, gRPC with fixed roots). Policy: default-deny pinned destinations, or allow them SNI-only without credentials.
- Rust proxy building blocks: `hudsucker` 0.25.0 (MITM proxy library), `http-mitm-proxy` 0.18.0, `rustls`, `hyper` [H versions]. Codex's `network-proxy` crate (Apache-2.0) is a complete reference implementation [H].

### 7.3 Liveness under snapshot
Snapshots break connections. gVisor: host sockets get `ECONNRESET` [H]. Firecracker: vsock transport reset [H]. microsandbox: "does not capture host-side connections" [H]. So **park only at a quiescent point**: the gateway answers the escalation with "pending, retry with id X", the agent's in-flight requests drain, *then* snapshot. On restore, the agent's next request (a new connection) hits the proxy, which now has a decision. Long-lived streams (Claude Code's API streaming through the proxy) must be idle, or the agent must tolerate a retry. Claude Code retries API errors [L], to be tested.

---

## 8. Filesystem: providing the workdir and getting typed output

### 8.1 Mechanisms

| Mechanism | Backends | Notes |
|---|---|---|
| Bind mounts (ro root, rw workdir, re-ro protected subpaths) | process, gVisor (via gofer), containers | Codex's layering is the reference [H]. Protect `.git/hooks`, `.git/config`, the `gitdir:` target, `.wicket/`, and CI configs (`.github/workflows` is code execution) as read-only. Resolve symlinks before validation (Anthropic incident [H]) |
| **overlayfs** (lowerdir = repo snapshot ro, upperdir = per-sandbox) | process, gVisor (own overlay), containers | The **upperdir *is* the diff**: whiteouts plus changed files. Gives cheap CoW, snapshot = tar the upperdir, discard = delete. Unprivileged overlay inside a userns has been allowed since 5.11 [M] |
| virtio-fs (`virtiofsd` 1.14.0, Rust) | Cloud Hypervisor, libkrun, VZ, Kata, QEMU — **not Firecracker** | Live shared directory. virtiofsd runs sandboxed (its own namespaces/seccomp). Shares inode and disk exhaustion with the host (libkrun model [H]) |
| 9p | gVisor (legacy gofer), QEMU | Slow; legacy |
| Block device image (ext4 built with `mkfs.ext4 -d`, or qcow/raw + overlay) | Firecracker (only option), all VMs | Copy-in = build the image (seconds for a repo). **Copy-out: never mount a guest-written image with the host kernel** (a crafted ext4 is a host-kernel attack). Extract via a guest agent over vsock (tar or `git diff` stream), or parse in user space (`debugfs`/`e2tools` in a sandbox, or a Rust ext4 reader) [L] |
| Copy-in/copy-out over the control channel (tar over vsock/exec) | all, including hosted (E2B/Modal/CF file APIs) | Universal fallback. The only option for hosted backends |
| git worktree | host side | Cheap, but **its `.git` points into the main repo's gitdir**, so hooks, config and refs are shared. Writable gitdir = host code execution the next time a human or the harness runs git. Prefer `git clone --local --no-hardlinks` (or `--reference`), or a worktree with the shared gitdir mounted ro and a sandbox-private index |

### 8.2 Typed output (the brief's "handles, not contents")
Treat the agent's work product as **untrusted data with a type**, extracted by the harness and not by the agent:
- `Patch { base_commit, files: Vec<FileChange>, stats }`: produced by the harness running `git diff --binary base..` (or reading the overlay upperdir) **with hooks and config neutralized** (`-c core.hooksPath=/dev/null -c core.fsmonitor= -c diff.external= --no-ext-diff --no-textconv`, `GIT_CONFIG_NOSYSTEM=1`, `HOME=/nonexistent`), ideally itself inside a throwaway process sandbox. Validate it by applying to a clean checkout. Reject symlinks pointing outside, submodule changes, modes beyond 644/755, and paths outside the task's scope.
- `TestResult { passed: bool, summary_handle }`, `Artifact { handle, label }`. Labels (from the IFC part of the brief) attach here.

### 8.3 Snapshotting state
- Process tier: no memory snapshot. CRIU exists [L] but is fragile for Node and the like, and needs privileges. FS-only "snapshot" = overlay upperdir tar or reflink copy (btrfs/xfs). A parked process-tier agent can only be **frozen** (cgroup `freezer` / `cgroup.freeze`), which still costs RAM.
- gVisor: `runsc checkpoint`, a real memory + kernel-state snapshot, works without KVM [H].
- Firecracker/CH: full or diff memory snapshot + **CoW copies of block devices** (reflink, or overlay/dm-snapshot) taken *at the same pause*. UFFD lazy restore keeps resume fast. Memory file ≈ guest RAM, so balloon down or use free-page reporting before snapshotting to shrink it [M].
- VZ (macOS 14+): `saveMachineStateTo` (VM must be paused; arm64 only) [H].
- microsandbox: `msb snap create --full`, fork with CoW memory (local only) [H].
- Monty: interpreter state dump [M]. Wasm: no standard; custom [L].

---

## 9. Comparison matrix

| Tier | Example | Isolation strength | Start | Overhead | Runs Claude Code | Memory snapshot | Needs | Runs on this box |
|---|---|---|---|---|---|---|---|---|
| 0 codemode | wasmtime, Monty, QuickJS, V8 | very high (capabilities only); engine bugs | µs–ms | KB–MB | **no** | Monty yes; Wasm custom | nothing | yes |
| 1 process | Landlock+seccomp+ns (bwrap-like) | medium (shared kernel) | ~ms | ~0 | yes | no (freeze only) | userns (AppArmor exception on Ubuntu 24.04) or root helper | **yes** (via sudo/helper) |
| 1m macOS process | Seatbelt | medium | ~ms | ~0 | yes | no | macOS | n/a |
| 2 user-space kernel | gVisor runsc (systrap) | high | ~100s ms [L] | tens of MB; syscall-heavy slowdown | yes [M: Node/git run under gVisor at Modal/Anthropic] | **yes** (`runsc checkpoint`) | root (or rootless with limits) | **yes** |
| 3 microVM | Firecracker / Cloud Hypervisor | high (hardware) | ~125 ms boot (+ userland) | ≤5 MiB VMM + guest RAM | yes (needs full rootfs image) | **yes**, fast (UFFD) | **KVM** | **no** |
| 3l microVM lib | libkrun / microsandbox | high (with VMM jailed) | ~100s ms | small | yes | microsandbox yes (local) | KVM or HVF | no |
| 3m macOS VM | VZ / Apple container / libkrun-HVF | high | ~1 s [L] | guest RAM | yes | VZ save/restore (14+) | Apple Silicon | n/a |
| 4 hosted | E2B, Cloudflare, Modal, Daytona, Northflank | high | ~100s ms–s | $ | yes | provider-specific | account, network | yes (as client) |

---

## 10. Recommended backend tiering for v1

**Linux (build first, testable on this box):**
1. **`process` backend (native Rust).** A small privileged helper (`wicket-jail`, setuid-free; started by the harness with `sudo`/capabilities, or with an AppArmor profile granting `userns` to this one binary) that:
   - creates user/mount/PID/IPC/UTS/net namespaces and a **dedicated UID** per sandbox;
   - pivot_roots into an overlay of a read-only base rootfs (host `/usr` or an OCI image unpacked with `oci-spec`) plus a rw workdir overlay;
   - applies protected-path ro rebinds, Landlock (best effort ≥ ABI 1–4; ABI 6+ scopes when present), and seccomp (srt's namespace/mount escape rules plus Codex's socket-family rules, `io_uring` blocked);
   - networks via **pattern A** (no interface, UDS-bridged proxy) by default, with pattern B (veth + nftables transparent) as an option for non-proxy-aware tools;
   - uses a cgroup v2 leaf per sandbox for limits and **freeze** for cheap parking.

   Reference code: Codex `linux-sandbox` + `network-proxy` (Apache-2.0), srt (Apache-2.0), hakoniwa (license not auto-detected by GitHub; check before copying).
2. **`gvisor` backend**: an OCI bundle built from the same spec, run with `runsc --platform=systrap --network=none` (UDS proxy) or `sandbox` + veth/nftables. Provides **checkpoint/restore for parking on non-KVM hosts**. The default "strong" tier on VPSes.
3. **`firecracker` backend** (on KVM hosts: bare metal, or nested-virt clouds such as GCP/Azure [L]): jailer + **vsock-only networking (pattern D)**, an ext4 workdir block device + guest agent for exec, IO and diff extraction, full/diff snapshots with UFFD restore for parking, and MMDS for non-secret config. Use `fctools` or a thin hand-written client. **Cloud Hypervisor** is the second VM backend when a live virtiofs workdir is wanted. Same trait, mostly shared code.

**macOS (dev machines):**
1. **`seatbelt` backend**: generated SBPL (start from Codex's `seatbelt_base_policy.sbpl` and network policy), network only to the proxy port, workdir writable, protected paths denied.
2. **`vz` backend** via libkrun (HVF, Rust, vsock/TSI) or microsandbox. Apple `container` is an alternative where macOS 26 is present. VZ save/restore for parking.

**Remote:** `e2b` backend (BYOP → wicket proxy; deny all otherwise), then `cloudflare` (outbound Worker forwarding to wicket's decider). Modal and Daytona come later.

**Codemode:** `wasm` backend (wasmtime components, imports = gateway functions) for tool-only zones. Add `monty` if Python-subset scripts and resumable state are wanted.

**Defer:** Kata (fleet-scale), crosvm, Unikraft, Docker/Podman-as-backend (pointless beside the process and gVisor tiers, except for image pulling, where `oci-client` or `skopeo` is enough).

---

## 11. Sketch of the Rust `Sandbox` trait

Design notes:
- The policy engine picks a backend by **required properties** (isolation floor, snapshot need, platform), not by name. Backends advertise `Capabilities`.
- Network attachment and mounts are **declarative inputs** compiled by the backend, so the zone/gate view is generated from the same spec that is enforced (the brief's "view must be generated from live enforcement config").
- Exec/IO goes through a control channel the agent cannot impersonate (the parent end of a socketpair, a vsock control port, or a provider API).
- Output extraction is the harness's job and yields typed values.

```rust
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsolationLevel { Capability /*codemode*/, Process, UserspaceKernel, Hardware, Remote }

pub enum SnapshotKind { None, Freeze /*RAM held*/, Filesystem, Full /*memory + fs*/ }

pub struct Capabilities {
    pub isolation: IsolationLevel,
    pub snapshot: SnapshotKind,
    pub runs_posix_userland: bool,          // false for codemode
    pub egress_modes: Vec<EgressMode>,      // what this backend can enforce
    pub mount_kinds: Vec<MountKind>,
    pub requires: Vec<HostRequirement>,     // Kvm, Hvf, UserNs, Root, Account(..)
}

/// How the box reaches the outside world. There is never a "direct" variant.
pub enum EgressMode {
    None,
    /// Only route: harness proxy on a host UDS, bridged to 127.0.0.1:{http,socks} inside.
    ProxyBridge { http_port: u16, socks_port: Option<u16> },
    /// veth/TAP into a netns whose nftables send all TCP to a transparent proxy,
    /// DNS only to the harness resolver, everything else dropped.
    Transparent { dns: bool },
    /// vsock-only VM; guest shim exposes the proxy locally.
    Vsock { guest_port: u32 },
    /// Provider-side forced proxy (E2B BYOP SOCKS5, Cloudflare outbound Worker).
    ProviderProxy,
    /// Codemode: capabilities are host functions bound to the MCP gateway.
    HostFunctions(Vec<CapabilityBinding>),
}

pub struct NetworkAttachment {
    pub mode: EgressMode,
    pub proxy: ProxyEndpoint,               // UDS path / vsock CID:port / URL + per-sandbox auth
    pub ca_bundle: Option<CaBundle>,        // per-sandbox ephemeral CA (public part only)
    pub env: Vec<(String, String)>,         // HTTPS_PROXY, NODE_EXTRA_CA_CERTS, sentinels...
}

pub enum MountKind { Bind, Overlay, VirtioFs, BlockImage, CopyIn }
pub enum Access { ReadOnly, ReadWrite, ReadWriteNoDelete }
pub struct MountSpec {
    pub source: MountSource,                // HostDir, Image(OciRef), Snapshot(SnapshotId), Tmpfs
    pub target: PathBuf,
    pub access: Access,
    pub protected: Vec<PathBuf>,            // forced RO/deny within (e.g. .git/hooks, .github/workflows)
    pub kind_hint: Option<MountKind>,
}

pub struct SandboxSpec {
    pub id: SandboxId,
    pub rootfs: RootfsSpec,                 // host-ro, OCI image, VM image
    pub mounts: Vec<MountSpec>,
    pub network: NetworkAttachment,
    pub limits: Limits,                     // cpu, mem, pids, disk, wall time
    pub uid: Option<u32>,
    pub labels: LabelSet,                   // IFC labels from the zone model
}

pub struct ExecRequest { pub argv: Vec<String>, pub env: Vec<(String,String)>, pub cwd: PathBuf, pub tty: bool }

#[async_trait::async_trait]
pub trait Sandbox: Send + Sync {
    fn capabilities(&self) -> &Capabilities;

    /// Validate spec vs capabilities; build rootfs/overlay/image, netns, CA, cgroup. No guest code runs.
    async fn prepare(&self, spec: &SandboxSpec) -> Result<Prepared>;
    /// Boot VM / create namespaces / create remote sandbox. Returns a handle.
    async fn start(&self, prepared: Prepared) -> Result<Box<dyn Instance>>;
    /// Re-create an instance from a snapshot (possibly on another host for Full-but-portable kinds).
    async fn restore(&self, snap: &SnapshotRef, overrides: RestoreOverrides) -> Result<Box<dyn Instance>>;
}

#[async_trait::async_trait]
pub trait Instance: Send + Sync {
    fn id(&self) -> &SandboxId;
    /// Spawn a process inside (agent itself, or tool commands). Control channel is harness-only.
    async fn exec(&self, req: ExecRequest) -> Result<Process>;
    /// Attach stdio/PTY of a running process (for the agent's TUI or stream-json I/O).
    async fn attach(&self, pid: ProcessId) -> Result<IoStreams>;
    /// Live egress change (escalation grants); FS changes generally require restart.
    async fn update_network(&self, net: &NetworkAttachment) -> Result<()>;
    /// Quiesce (after gateway returned "pending"), then snapshot per capabilities().snapshot.
    async fn snapshot(&self, opts: SnapshotOpts) -> Result<SnapshotRef>;
    async fn pause(&self) -> Result<()>;    // freeze / VM pause
    async fn resume(&self) -> Result<()>;
    /// Harness-side extraction of typed outputs (never trusts guest-produced metadata).
    async fn extract(&self, what: Extract) -> Result<Output>; // Patch{base}, File{path}, Tar{dir}
    async fn status(&self) -> Result<InstanceStatus>;        // incl. exit codes, OOM, violations
    async fn destroy(self: Box<Self>) -> Result<Teardown>;    // also returns violation log
}
```

Backends: `ProcessSandbox` (linux), `SeatbeltSandbox` (macos), `GvisorSandbox`, `FirecrackerSandbox`, `CloudHypervisorSandbox`, `KrunSandbox` (linux+macos), `VzSandbox`, `E2bSandbox`, `CloudflareSandbox`, `WasmSandbox`, `MontySandbox`. Shared crates: `wicket-netns` (veth/nftables/UDS bridge), `wicket-proxy` (MITM + sentinel credential swap + decider protocol, srt-proxy-like), `wicket-fs` (overlay, image build, safe diff extraction), `wicket-guest` (static PID-1/agent for VMs: exec, IO, vsock proxy shim, diff).

---

## 12. Open risks and questions

1. **No KVM here.** MicroVM backends can't be developed or tested on the control host. Options: Vultr bare metal (monthly billing [M]), a Mac with M3 or later, or GCP/Azure nested-virt VMs [L]. Firecracker/CH CI could run on GitHub larger runners with KVM [L, needs checking].
2. **Ubuntu 24.04 AppArmor userns restriction.** The process tier needs either a privileged helper (more TCB, but also enables per-sandbox UIDs, veth and nftables) or an AppArmor profile. I recommend the helper and scrutinizing it hard.
3. **Landlock ABI 4 on this box**: no IPC scoping and no UDP. Rely on netns + PID ns + seccomp. Do not assume newer ABIs without probing.
4. **TLS interception breadth.** Some tools won't trust the injected CA. Need a per-tool compat list and a policy for pinned hosts (SNI-only, no credentials). Test Claude Code itself (Node: `NODE_EXTRA_CA_CERTS`, `HTTPS_PROXY`) early, including its auth: inject the Anthropic credential at the proxy rather than giving the agent a real key [L: verify Claude Code works with a sentinel key + proxy injection].
5. **Snapshot vs. connections.** Every substrate resets connections on restore. The escalation protocol must drive the agent to quiescence first. Measure whether Claude Code survives a reset mid-session.
6. **Guest-written filesystem images** are a host-kernel attack vector. Extraction must be user-space only or go through a guest agent.
7. **The proxy is the crown jewel**: it holds credentials and makes policy decisions. Anthropic's own note: "Be wary of custom components … custom proxies and allowlists were where the flaws appeared" [H]. Keep it small, fuzz it, consider srt-proxy's split (dumb terminating proxy + separate decider), and pin TLS to upstreams.
8. **Hosted backends leak small channels**: E2B's direct DNS, Modal's unrestricted DNS. Document them as covert-channel bandwidth in the zone view.
9. **Version churn**: srt (0.0.x), microsandbox (beta), Dynamic Workers (beta), WASI p3 (new). Pin versions and isolate each behind the trait.
10. **Licenses** [H, GitHub API]: Codex, srt, microsandbox and libkrun are all Apache-2.0. hakoniwa reports `NOASSERTION`, so read its LICENSE before copying code.

---

## Sources (primary unless noted)

- Landlock docs (7.4-rc1): https://docs.kernel.org/userspace-api/landlock.html ; TSYNC in 7.0: https://kernsec.org/pipermail/linux-security-module-archive/2026-March/056546.html ; UDP series: https://kernsec.org/pipermail/linux-security-module-archive/2026-June/058013.html
- Codex Linux sandbox: https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md ; network proxy: https://github.com/openai/codex/tree/main/codex-rs/network-proxy ; seatbelt policies: https://github.com/openai/codex/tree/main/codex-rs/sandboxing/src
- Anthropic sandbox-runtime: https://github.com/anthropic-experimental/sandbox-runtime (v0.0.81, 2026-10-20) ; srt-proxy decider: https://github.com/anthropic-experimental/sandbox-runtime/blob/main/docs/srt-proxy.md
- Anthropic, How we contain Claude across products (2026-05-25): https://www.anthropic.com/engineering/how-we-contain-claude
- Anthropic, Code execution with MCP (2025-11-04): https://www.anthropic.com/engineering/code-execution-with-mcp
- bubblewrap: https://github.com/containers/bubblewrap ; nsjail: https://github.com/google/nsjail ; hakoniwa: https://github.com/souk4711/hakoniwa ; birdcage: https://github.com/phylum-dev/birdcage ; extrasafe: https://github.com/boustrophedon/extrasafe
- Firecracker: https://github.com/firecracker-microvm/firecracker (SPECIFICATION.md, CHANGELOG.md, docs/snapshotting, docs/vsock.md, docs/mmds) ; fctools: https://crates.io/crates/fctools
- Cloud Hypervisor: https://github.com/cloud-hypervisor/cloud-hypervisor ; v53/v54 (secondary): https://www.phoronix.com/news/Cloud-Hypervisor-53 , https://phoronix.com/news/Cloud-Hypervisor-54
- libkrun: https://github.com/containers/libkrun (README, docs/security-model.md, docs/networking.md)
- microsandbox: https://github.com/microsandbox/microsandbox ; https://docs.microsandbox.dev/sandboxes/snapshots
- libkrun vs Firecracker essay (secondary, 2026-05-15): https://iii.dev/blog/why-agent-sandboxes-are-converging-on-libkrun-not-firecracker/
- Docker Sandboxes: https://docs.docker.com/ai/sandboxes/architecture/ ; product: https://www.docker.com/products/docker-sandboxes/ ; (secondary) https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/ , https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/
- gVisor checkpoint/restore: https://gvisor.dev/docs/user_guide/checkpoint_restore/
- Kata 4.0 (2026-07-22): https://katacontainers.io/blog/kata-containers-4-0-0-release-overview/
- Apple VZ nested virt: https://developer.apple.com/documentation/virtualization/vzgenericplatformconfiguration/isnestedvirtualizationsupported ; save/restore: https://developer.apple.com/documentation/virtualization/vzvirtualmachine/restoremachinestatefrom(url:completionhandler:) ; Apple container: https://github.com/apple/container
- E2B: https://docs.e2b.dev/network/internet-access , https://docs.e2b.dev/network/byop
- Cloudflare Sandbox outbound TLS/auth (2026-04-13): https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/ ; security: https://developers.cloudflare.com/sandbox/sdk/concepts/security/ ; Dynamic Workers open beta (2026-03-24): https://developers.cloudflare.com/changelog/post/2026-03-24-dynamic-workers-open-beta/
- Modal networking: https://modal.com/docs/guide/sandbox-networking
- Daytona: https://www.daytona.io/docs/en/v2/isolation , https://www.daytona.io/docs/network-limits/
- Northflank (vendor): https://northflank.com/product/sandboxes
- WASI 0.3: https://wasi.dev/releases/wasi-p3 ; wasmtime: https://github.com/bytecodealliance/wasmtime
- Monty: https://github.com/pydantic/monty ; https://pydantic.dev/articles/pydantic-monty
- passt/pasta: https://passt.top/passt/about/
- Vultr nested virt (secondary, dated): https://discuss.vultr.com/discussion/1957/ask , https://mailman.nanog.org/pipermail/nanog/2021-January/211590.html
- Crate versions: crates.io API, queried 2026-11-08. GitHub release tags via `gh api`, 2026-11-08.
