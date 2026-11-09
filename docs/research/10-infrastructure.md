# 10 — Infrastructure: hosts, capacity, placement, and Kubernetes as the substrate

Research date: 2026-11-08. Scope: how wicket gets compute to run code on, and how it does that safely. That
means requesting hosts, sandboxes and containers; placing agent sandboxes, third-party MCP servers, codemode
runtimes and wicket's own per-host proxies under isolation and separation rules; bootstrapping and trusting
nodes; and treating provisioning as authority, with money as an effect.

Two owner requirements were added while this was being written:
1. **Evaluate Kubernetes as the infrastructure layer in depth**, rather than wicket building its own
   scheduler. That evaluation is §5, and the overall recommendation is §11.
2. **Startup time and resource efficiency** matter as much as isolation level, because wicket starts many
   short-lived sandboxes. See §4.

Out of scope: the source code of sandbox and gateway OSS projects (ToolHive, Docker MCP gateway,
microsandbox, agent-sandbox, E2B). Other agents cover that. Agent-sandbox appears here only as a candidate
backend and API surface.

Confidence tags, as in [02]: **[H]** verified against a primary source (official page, repo, the Vultr
account API, or a measurement on this machine); **[M]** secondary source, search snippet of an official page,
or inference from a primary one; **[L]** unverified. Prices are list prices excluding VAT, with the date they
were read (2026-11-08 unless stated).

---

## 0. TL;DR

- **Recommendation: hybrid. Kubernetes for capacity and services; a wicket node agent for the sandbox hot
  path.** Kubernetes (k3s on one box, VKE or GKE across hosts) owns nodes, node pools and autoscaling. It also
  runs wicket's own components and long-lived services. wicket does **not** write a multi-host scheduler,
  cluster manager or node autoscaler.
  - **The hot path stays with wicket.** A privileged `wicket-node` DaemonSet launches agent sandboxes and
    per-task MCP server instances directly on its node (process jail, `runsc`, later Firecracker), inside
    CPU and memory that reservation pods hold for it.
  - **Why the hot path can't be ordinary pods:**
    - **Latency.** Kubernetes' own SLO is p99 ≤ 5 s *excluding image pull*. Direct jail creation is
      ~3 ms here; Firecracker boots in ≤ 125 ms.
    - **Parking.** gVisor checkpoint/restore isn't reachable through Kubernetes, and pod restore is alpha,
      same-node only (KEP-5823).
    - **Network shape.** wicket's strongest pattern is a netns with *no interface* and a UDS-bridged proxy.
      CNI always gives a pod an interface, which only a correctly configured Cilium policy then closes.
  - **What wicket builds:** a placement compiler (constraint vocabulary → Kubernetes primitives plus a
    post-placement verifier), the node agent, a provisioning/money controller for leases, budgets and
    billing-aligned GC, and a single-host **local mode** (no Kubernetes) for laptops and for this box today.
- **kubernetes-sigs/agent-sandbox** (v1.0.10, 2026-11-06, API still `v1beta1`, breaking changes nearly
  weekly) becomes an **optional `Sandbox` backend**. Its managed NetworkPolicy allows the whole public
  internet by default. wicket must run it with `networkPolicyManagement: Unmanaged` and its own Cilium
  default-deny. It is a good fit for users who already run GKE (GKE Agent Sandbox: 90% of warm-pool claims in
  200 ms, a vendor claim).
- **Providers.** Shortlist:
  - **Vultr cloud compute** for VMs. Hourly, billed per *started* hour with each line rounded up to the cent,
    capped at 672 h/month. Verified on our own pending charges. No KVM. $0.014/h for vc2-1c-2gb in London.
  - **AWS `c7i-flex.large` with nested virtualization** for KVM by the minute. Per-second billing with a
    60 s minimum: $0.085/h in us-east-1, $0.101/h in London.
  - **A Mac with M3 or later** for free local KVM, via Virtualization.framework nested virtualization.
  - **Fly.io Machines** as cheap per-second Firecracker capacity, but without KVM and with weak egress control.
  - **E2B** as hosted capacity.
  - **Hetzner dedicated** (hourly, €0.0945/h for AX41, KVM) is the cheapest hourly bare metal found, but it
    has no UK region.
  - **Vultr bare metal: billing is ambiguous.** The catalog says `invoice_type: monthly` ($185/month for the
    cheapest London box), but Vultr's billing doc (updated 2026-10-26) says everything is hourly, up to
    672 h. Don't spend on it until that is settled.
- **Agents never hold cloud credentials.** A cloud key is an egress bypass (a new VM has unmediated internet),
  a persistence mechanism, and permission management, all at once. Provisioning is an `Op` on provider
  `wicket.infra` with effect `money`. Grants are leases on capacity, never credentials. Budgets are hard
  ledger reservations of the *worst-case billed cost*, using each provider's real billing granule. This
  automates what an in-house provisioning broker script already does by hand (§2).
- **v1 within about $20/month:**
  - Local mode and the placement and explain machinery on this box.
  - k3s with a gVisor RuntimeClass and Cilium, run **on demand** on this box for the Kubernetes backend's
    conformance tests: about 1.6 GB RAM, against about 3 GB free.
  - A `VultrProvider` that goes through provisioning-broker grants.
  - Firecracker work on a Mac, or on AWS nested virtualization at about $0.10/h. AWS needs an account the
    owner decides on.
  - Defer VKE, which is about $10–40 per node-month and would eat the budget, until multi-host is actually
    needed.

---

## 1. Requirements restated

| # | Requirement | Source |
|---|---|---|
| R1 | wicket requests hosts, sandboxes and containers itself, and keeps MCP servers isolated from each other in their own containers | owner, 2026-11-08 |
| R2 | Never keep a box past its paid hour unless it is needed; release to a pool rather than destroy when that is cheaper | owner's Vultr rules |
| R3 | Hard monthly cap, currently **$20/month** for everything the broker creates | broker `BUDGET`, owner |
| R4 | No KVM on the dev box (Vultr VC2) | [02 §1] [H] |
| R5 | Startup latency and density matter as much as isolation | owner, 2026-11-08 |
| R6 | Lean towards Kubernetes rather than a home-grown scheduler | owner, 2026-11-08 |
| R7 | The trust model of design §2 still holds: the box is hostile, no secrets in the box, fail narrow, authority only narrows | design §2 |

R7 has a direct consequence for this layer. **Infrastructure APIs are authority.** Whoever can create a pod in
a wicket namespace, or a VM in wicket's cloud account, can create a box with no wicket proxy in front of it.
The infra layer is therefore part of the TCB, and its credentials sit with the control plane only.

---

## 2. In-house prior art: a provisioning broker script (read 2026-11-08) [H]

The in-house broker script (295 lines of bash) is effectively wicket's infra layer v0.
It is run by hand by a broker session. Its rules were paid for in real money, and they carry over directly:

| Broker mechanism | What it teaches wicket |
|---|---|
| `request CLASS HOURS purpose` → broker `approve`/`deny` → `BB_GRANT=id up` (single use, expires after 6 h, bound to requester and class) | Provisioning is a **typed escalation request**, the grant is single-use and bound to requester and class, and the ledger is the grants directory. Same shape as design §10. |
| `budget_ok`: month-to-date spend + live boxes' billed-so-far + **this box's worst-case life**, compared with `$BUDGET` | **Reserve the worst case before creating**, not the expected cost. |
| `billed_usd`: per started hour, each line rounded **up** to the cent | The billing model is per-provider data and must be exact. Vultr pending charges confirm it (below). |
| `paid_cap`: a box's life is capped at **minute 50** of its last granted hour (the watchdog runs every 5 min, and Vultr's clock starts a few seconds after ours) | Lease expiry snaps to the billing granule minus the GC jitter. |
| `release` → pool if at least 10 min of paid time is left; `up` takes a pooled box only with at least 20 min left; the watchdog destroys pooled boxes | **Warm host pool aligned to paid time.** Paid-but-unused minutes cost nothing to reuse. |
| `mine`: destroy only instances tagged `broker-owned`, and never ones tagged as protected (the control host, the broker itself) | **Tag-scoped ownership.** The GC can only ever touch what wicket created. |
| `watchdog` (systemd timer): destroy past `max_age`, idle past 45 min, or orphans (tagged but with no state file) | **Level-triggered GC** against the provider's list, the provider being the source of truth for what exists. |
| API key read into a curl config on stdin, never in argv, logs, commits or on a box | The provisioner holds the only cloud credential. Nodes hold none. |
| Known gap: "boxes die even if a session forgets them (*not if the control host itself dies*)" | A **dead-man's switch** has to live outside the control plane (§6.5). |

**Measured Vultr facts from this account** (Vultr API `pending_charges`, 2026-11-08) [H]:
- **Billing is per started hour.** Probes that lived 46–137 s are billed `units: 1, unit_type: hours`, and an
  82-minute life is billed 2 units.
- **Each line is rounded up to the cent.** A 1 GB box costs $0.0089/h but is billed $0.01.
- **The monthly cap is 672 h.** A $40/month plan bills at $0.0595/h, which is $40/672 h.
- **Create to SSH-ready plus provision takes 58–82 s** (the broker's event log, vhp/vx1 plans in fra and lhr,
  2026-11-07) [H].

---

## 3. Host and capacity providers

### 3.1 What matters, per provider

For wicket the properties that matter are these, in order:
1. API create and destroy (and whether create is idempotent);
2. billing granule (it drives leases, pools and GC);
3. minimum cost per hour;
4. whether `/dev/kvm` is available (for Firecracker and Kata);
5. boot time;
6. UK/EU regions (data residency, and the owner is in London);
7. identity and attestation (§8);
8. Rust client.

### 3.2 VMs and bare metal

| Provider / SKU | Billing granule | Min $/h | KVM | UK / EU | Create idempotency | Rust | Notes |
|---|---|---|---|---|---|---|---|
| **Vultr cloud compute** vc2-1c-2gb (lhr) | per **started hour**, each line rounded up to the cent, 672 h/mo cap; **stopped servers bill** [H billing doc 2026-10-26, pending charges] | **$0.014** ($10/mo) [H API]; vhp-1c-2gb $0.0179 [H] | **No** (no `vmx`/`svm`) [H, 02 §1] | lhr, man, ams, fra, … [H] | **None** documented; govultr sends a plain POST [M] → tag-and-list pattern | `vultr` 0.4.4 (unofficial, low activity) [H]; plain REST is easier | Create→ready 58–82 s measured [H]. No signed identity document, no confidential VMs [M/L] |
| **Vultr bare metal** vbm-6c-32gb (E-2286G, lhr) | **Ambiguous.** The catalog's `invoice_type: "monthly"` covers every non-GPU vbm plan, while the GPU plans say `"hourly"` [H API]. The billing doc says "all servers … hourly … up to 672 hours", Bare Metal included [H] | $0.253 *or* $185/mo [H] | Yes (bare metal) | lhr + ~24 regions [H] | none [M] | as above | **Settle the billing before buying.** The downside is lopsided: $0.25 versus $185 |
| **Hetzner Cloud** CX23 / CAX11 / CPX22 | hourly, partial hours rounded up, monthly cap; switched-off servers bill [H] | **€0.0096** (CX23, €5.99/mo) [H, post-15-Jun-2026 prices]; every plan showed "currently unavailable" when fetched [H] | **No** (community reports) [M] | FSN1, NBG1, HEL1. **No UK** [H] | none [H] | `hcloud` 0.27.0 (2026-11-05, unofficial, active) [H] | Two price rises in 2026 (April and June) [H]. Supply is tight |
| **Hetzner dedicated / Server Auction** AX41 | hourly pro-rata up to the monthly cap [H matrix page]; Auction has no setup fee [H] | **€0.0945** (AX41, €59/mo, €0 setup; figures may predate June) [H/M] | **Yes** | DE/FI only | Robot webservice (HTTP basic) [M] | none | Cheapest hourly KVM found. Delivery time not documented |
| **OVHcloud Public Cloud** d2-2 | **per second, 1 min minimum**; stopped still bills, "shelving" doesn't [H] | £0.009 [H] | not documented [L] | UK1 (London) [M] | none [M] | none | Metal Instance bm-s1 (4c/32 GB) **£0.435/h**, hourly [H] |
| **Scaleway** Instances / Elastic Metal | Instances: hourly, 60 min minimum, **billing stops when powered off** [H docs repo]; EM hourly, powered-off still bills [H] | DEV1-S ~€0.0088 [M]; EM-A115X **€0.091/h** [M] | EM: yes | PAR, AMS, WAW. No UK [M] | none [M] | none | Mac mini M4 €0.22/h with a **24 h minimum lease** [H/M] |
| **Latitude.sh** m4.metal.small | hourly or monthly (monthly ~50% cheaper) [H] | **$0.41** [H] | Yes | **London** ×2, FRA, AMS [H] | `billing: hourly` on `POST /servers`; no idempotency key [H] | none | An Equinix Metal successor |
| **Equinix Metal** | **EOL 2026-06-30** [M] | — | — | — | — | — | Successors: Latitude, Cherry (~$0.091/h, no UK, ~12 min deploy [H]), phoenixNAP BMC (hourly, partial hours billed full, s0.d1.small ~$0.08/h [M]) |
| **AWS** c7i-flex.large (nested) | **per second, 60 s minimum**; stopped instances don't bill compute [H] | **$0.0848** us-east-1 / **$0.1008** eu-west-2 [H price feed 2026-11-07] | **Yes, via nested virtualization** (since 2026-02-16): M7i, C7i, R7i, M8i, C8i, R8i (and -flex/-d), X8i, I7i/I7ie; **Intel only**; KVM or Hyper-V as L1 [H] | eu-west-2 London [H] | **`ClientToken`** (≤ 64 ASCII characters) [H] | `aws-sdk-ec2` 1.275.0 (official) [H] | Cheapest x86 `.metal` is c5n.metal at $3.89/h. AWS still recommends metal for latency-sensitive nested use [H] |
| **GCP** n4d-standard-2 / n4-standard-2 | per second after a 1 min minimum [H] | $0.0847 (n4d, us-central1) / $0.0965 (London) [M] | Yes, **KVM L1 only**; not E2, Arm, memory-optimized or AMD, **except N4D** [H]; nested CPU-bound workloads lose ≥ 10% [H] | europe-west2 [H] | **`requestId`** UUID [H] | `google-cloud-compute-v1` 4.1.0 (official) [H] | Signed instance-identity JWT [H] |
| **Azure** D2als_v6 | per second [M]; "Stopped (deallocated)" doesn't bill [H] | $0.0804 East US / **$0.0934 UK South** [H retail API] | Yes: Dsv5/6, Dasv5/6, Dalsv6, Fsv2 [H]. A Trusted Launch conflict is reported by the community but not documented [L]: test it | UK South [H] | idempotent PUT on named resources [M] | **no usable official compute crate** (`azure_mgmt_compute` 0.21, 2024) [H] | Attested-data document [H] |

### 3.3 Sandbox-shaped capacity (someone else's hosts)

| Provider | Isolation | Billing | Start | Egress through *our* proxy | Rust | Fit |
|---|---|---|---|---|---|---|
| **Fly.io Machines** | Firecracker microVM [H] | **per second while running**; stopped/suspended machines pay $0.15/GB-month for rootfs only [H] | Start a stopped machine: "well under a second". Create: "low double-digit seconds". Resume from suspend (a Firecracker snapshot, ≤ 2 GB RAM): "a few hundred ms" [H, vendor] | **Weak.** Network policies are allow-only by *port and protocol*, with no CIDR or destination targeting documented, and a restart is needed to apply them [H]. You can block everything except "port P", but not "only host X" | none official; generate from OpenAPI [H] | **Strong hosted backend for third-party MCP servers and agent sandboxes**, provided the egress gap is tested (e.g. allow only 6PN to a wicket proxy machine). shared-cpu-1x 256 MB: $2.19/mo, about $0.003/h [H]. **No nested KVM** [M, 2023 staff post] |
| **E2B** | Firecracker [M] | $0.000014/vCPU-s + $0.0000045/GiB-s, so 2 vCPU + 2 GiB ≈ **$0.133/h** [H] | ~150 ms (vendor talk) [L]; independent burst time-to-interactive median 1.13 s [M] | **Yes, BYOP SOCKS5** host-side, minus direct UDP DNS [02 §5, H] | none official | Hosted `Sandbox` backend [02]. Hobby tier: 1 h max session, one-time $100 credit. Pro: $150/mo, 24 h sessions [H] |
| **Modal Sandboxes** | gVisor (or an experimental VM runtime) [H] | CPU $0.00003942/core-s (1 core = 2 vCPU) + $0.00000667/GiB-s, so 1 core + 2 GiB ≈ **$0.19/h** [H] | sub-second for cached images [M]; memory snapshots [H] | partial (sidecar) [02 §5] | none | Third choice |
| **Daytona** | Firecracker [M] | $0.0504/vCPU-h + $0.0162/GiB-h, per second [H] | "< 90 ms" (vendor) [H]; 595 ms measured independently [M] | no forced proxy [02 §5] | none | Not recommended |

### 3.4 Local capacity

- **This host** (Vultr VC2, 4 vCPU / 7.9 GiB, about 3 GiB available at 12:47Z with other sessions running) [H]:
  - Supports the process jail and gVisor (systrap) only.
  - Shared with other workloads under the host's job-slot limits: one core per slot, `-j1` builds. Any
    resident wicket infrastructure (k3s, Cilium) must be agreed with the host's operator and stopped when idle.
- **A Mac (Apple silicon)**:
  - Seatbelt and `vz` tiers [02 §4.6].
  - **Nested virtualization:** `VZGenericPlatformConfiguration.isNestedVirtualizationEnabled` needs
    macOS 15+ and an **M3 or later** chip [H]. So a Linux guest can have `/dev/kvm` and run Firecracker and
    Kata, given a guest kernel with KVM built in [M].
  - **Apple `container`:** 1.7.1 (2026-11-06) runs one lightweight VM per container, macOS 26 only [H].
  - **Licence:** the macOS licence allows **two extra macOS VMs** per Mac [H]. Linux guests are not
    explicitly limited [M/L].
  - The Mac's model and chip are unknown to this session. It is a free KVM dev host *if* it is an M3 or later.

### 3.5 Shortlist

| Role | Pick | Why | Cost to try |
|---|---|---|---|
| Ephemeral x86 VMs (multi-host tests, the "box for an agent's heavy job") | **Vultr cloud compute** | Already integrated (the broker script), London, hourly, 58–82 s to ready | $0.014–0.02 per box-hour |
| KVM by the minute (Firecracker/Kata backend development and CI) | **AWS c7i-flex.large, nested virtualization**, eu-west-2 | Per-second billing, `ClientToken`, official Rust SDK, London; GCP n4d-standard-2 is equivalent | ~$0.10/h. **Needs an AWS account (owner decision)** |
| Free KVM | **Mac M3 or later, macOS 15+** | No spend | $0 (chip unknown) |
| Long-running KVM bare metal | Hetzner AX41 (hourly, EU) or **Vultr bare metal once billing is confirmed** | Cheapest hourly KVM is Hetzner, but no UK; Vultr has London | €0.0945/h; $0.253/h or $185/mo |
| Hosted microVM capacity | **Fly Machines** (MCP servers, burst), **E2B** (agent sandboxes with forced proxy) | Per-second billing; E2B has the only documented forced proxy | cents |
| Managed Kubernetes | **VKE** (free control plane) when multi-host arrives; **GKE** where Agent Sandbox/gVisor is wanted | §5.5 | VKE: workers only, $10/mo per 1c/2GB node |

---

## 4. Startup and efficiency

wicket starts one agent sandbox per zone and, by default, a **per-task instance of every third-party MCP
server** (§9). Both sit on the agent's critical path:
- The agent waits for its box to boot.
- `tools/list` waits for the MCP servers to start.

Density matters because the agent itself is heavy. **Claude Code 2.1.319 processes on this box use
276–569 MB RSS each** [H, `ps`, 2026-11-08]. A sandbox tier's fixed overhead is a tax on top of that. For an
MCP server the overhead can exceed the server itself.

Tags: **MI** = measured, independent; **MV** = measured by the vendor; **VC** = vendor claim. Confidence as
elsewhere.

### 4.1 Published and measured numbers

| Tier | Cold start | Warm / restore | Per-instance overhead | Source, date, tag |
|---|---|---|---|---|
| **Process jail** (user, mount, pid, net, ipc and uts namespaces) | **~3 ms** (17 ms with `sudo`, against 14 ms for `sudo true`, on this loaded box, load average 2.5) | freeze/thaw (cgroup v2) is effectively instant | ~7 MB peak RSS for `unshare` itself; otherwise zero | **this box, 2026-11-08, MI [H]** |
| bubblewrap | 8 ms for `bwrap … ls`, against 3 ms for bare `ls` | — | — | jvns.ca 2022-06-28, MI [H] |
| runc vs crun (OCI) | 69 ms vs 39 ms per `run true` | — | max RSS 15 MB vs 3.7 MB | Red Hat 2020-08-03, MV [H] |
| `docker run` / `podman run` | 378 / 279 ms | — | — | jvns.ca 2022, MI [H] |
| **gVisor** (runsc) | lifecycle 2.3/s against runc 2.6/s (2019, pre-Systrap) | **restore 144 ms cold / 65 ms warm-Sentry** with `--network=none` (160/79 ms with networking). The PR was **closed unmerged** in 2026-04 over a "Sentry reuse" security concern | idle pod ~31 MiB, Sentry ~12 MiB [L]; "small, mostly fixed" [MV] | HotCloud'19 MI [H]; google/gvisor PR #12810, 2026-03, MI [H]; computingforgeeks [L] |
| gVisor in production (Modal) | `import torch` ~5 s cold | memory-snapshot restore **1.05 s p50**; snapshots tied to CPU features and runtime version | — | modal.com/blog/mem-snapshots 2025-01-28, MV [H] |
| **Kata** (CLH/FC/Dragonball; QEMU) | Kata-CLH: 0.85–0.95 s single pod, 1.6–1.8 s at 50 in parallel | VM templating: up to 39% faster creation | RuntimeClass `podFixed` overhead **130 Mi** (clh/fc/dragonball), **320 Mi** (qemu), **2048 Mi** (SNP/TDX) | Kuasar benchmark MV [M]; kata-deploy chart, main, MV [H] |
| Kata with CNI at concurrency | **CNI setup doubles start time** even for the best CNIs at 400 concurrent; eBPF CNI was 18× slower. Cause: RTNL lock | — | — | 2024 CNI paper, MI [H] |
| RunD (Alibaba Kata variant) | 88 ms to app; 200 containers/s per node | — | < 20 MB/sandbox; 2,500 × 128 MB per 384 GB node | ATC'22, MV [H] |
| **Firecracker** | **≤ 125 ms** InstanceStart → `/sbin/init` (CI-enforced); VMM API-ready in ~12 ms; 150 microVMs/s per host | snapshot: VMM load ~50 ms, then page faults dominate (hello-world 182 ms against 1 ms warm). With **REAP** working-set prefetch 3.7× faster on average; **FaaSnap** up to 3.5× better than REAP | **≤ 5 MiB** VMM overhead (CI-enforced); ~3 MB measured | firecracker SPECIFICATION.md [H]; NSDI'20 MV [H]; ASPLOS'21 MI [H]; EuroSys'22 MI [H] |
| Kata-FC vs Kata-QEMU density | — | — | 94 MB vs 168 MB on a 128 MB container (71/145 MB at 1,000 VMs/node, from shared kernel text) | RunD ATC'22, MI [H] |
| **Cloud Hypervisor** | ≈ Firecracker (NSDI'20 p99 153–158 ms at 50–100 concurrent) | snapshot/restore supported [02] | ~13 MB VMM | NSDI'20 [H] |
| **libkrun / microsandbox** | "< 100 ms" guest boot on an M1 | — | — | microsandbox README, VC [H] |
| **Wasm** (wasmtime, CoW heap, pooling allocator) | **~5 µs** instantiation, down from 2 ms | — | "a few KB" written per instance | Bytecode Alliance 2022-09-06, MV [H] |
| **V8 isolates** | "~5 ms" | — | ~3 MB with a shared runtime | Cloudflare 2018-11-09, VC [H] |
| **Kubernetes pod** | **SLO p99 ≤ 5 s** from creation to containers started, **excluding image pull and init containers**, stateless pods only | — | RuntimeClass `overhead` adds to scheduling accounting | sig-scalability SLO doc [H] |
| **agent-sandbox warm pool (GKE)** | — | **300 sandboxes/s per cluster, 90% of claims in 200 ms**; Pod Snapshots "resume in seconds" (gVisor, same machine series) | — | Google Cloud blog 2026-05-21, VC [H]; InfoQ 2026-09 [M] |
| E2B / Daytona / Modal / Cloudflare / Fly | vendor: 150 ms / 90 ms / sub-second / 1–3 s / start-stopped < 1 s | E2B resume ~1 s, pause ~4 s per GiB [H]; Fly resume "a few hundred ms" [H] | — | vendor docs; ComputeSDK burst time-to-interactive medians 1.13 s / 595 ms / 796 ms / 671 ms (MI [M], undated) |
| **Vultr VM** (a whole host) | **58–82 s** create → SSH → provisioned | pool claim: ~1 s (one SSH check) | — | broker event log, 2026-11-07, MI [H] |

**Caveats:**
- The gVisor startup data is old (2019, Docker 18) or only in charts.
- Nobody publishes a clean per-stage Kubernetes pod-start breakdown.
- Almost every result was measured at low concurrency. At high concurrency, network setup (RTNL, CNI) and
  image pulls dominate (CNI paper, RunD, Slacker).
- Claude Code's own startup is also seconds, not milliseconds. `node -e 0` took 0.6 s on this loaded box [H].

### 4.2 Techniques and what they buy

| Technique | What it does | Numbers | wicket use |
|---|---|---|---|
| **Warm pools, claim-then-bind** | Pre-start sandboxes with **no identity**; on claim, bind the identity: per-sandbox CA, proxy registration, placeholder env, workdir mount | GKE: 200 ms p90 claims (VC). agent-sandbox `SandboxClaim` adopts from a `SandboxWarmPool`, but a claim with `spec.env` set **always cold-starts** [H] | Pool **unbound** jails or gVisor sandboxes per image digest. Binding must not need env injection at start: the agent's env comes through `exec` on the control channel. Identity is the transport (the netns/UDS registered on claim), so binding is a proxy-table insert |
| **Snapshot-clone of pristine state** | Boot an MCP server or agent image, initialize it (imports, JIT, caches), snapshot **before any task data**, then restore a fresh clone per task | Firecracker snapshot restore is tens to hundreds of ms (REAP/FaaSnap). gVisor restore 65–160 ms (unmerged PR) or ~1 s (Modal). Modal: 2.5× faster cold starts overall | The main density and latency lever for per-task MCP servers (§9). Restoring a *pristine* snapshot gives warm-start speed with **no cross-task state**, which a reused warm process cannot |
| **Reseed after restore** | Clones share RNG state, TLS session keys, UUID generators and boot IDs | "Restoring Uniqueness in MicroVM Snapshots" (Brooker et al. 2021); Firecracker supports **VMGenID** (guest Linux ≥ 5.18) [H] | The guest shim must reseed (VMGenID, plus explicit `getrandom` reseeding of the userspace pools wicket controls). Mint per-clone identity *after* restore. Don't snapshot after the CA or credentials are bound |
| **Shared read-only base layers** | One lower layer per image digest, an overlay or CoW upper layer per sandbox | Kata VM templating saved 72% of memory for 100 × 128 MB [MV]. RunD shares kernel text | Design already uses a read-only base plus a writable upper [design §7]. Keep one base per digest per node, and preload it on node join |
| **Lazy image pulling** (stargz/eStargz, SOCI, Nydus) | Fetch image chunks on demand | **Slacker (FAST'16): pulls are 76% of start, but only 6.4% of the data is read** [H]. eStargz ~45 s → < 10 s on one gcc image [M] | Small value for wicket: base images are few and preloaded. Worth it for third-party MCP images pulled per request, but **lazy fetch is a network side channel at run time**, so fetch through wicket's registry mirror only |
| **gVisor rootfs overlay** (tmpfs-backed, default since 2023-05) | Keeps rootfs writes inside the Sentry | fsstress 263 s → 3.2 s [MV, M] | On by default; keep it |
| **Memory dedup** (KSM) / **free page reporting** (virtio-balloon) | Merge identical pages across VMs / return free guest memory to the host | KSM: up to 46.9 MB/s merge rate at ~10% of a core (OLS 2009) [H]. No clean multi-VM savings figure found. Free page reporting: ~1–2% performance cost [M] | KSM across *tenants* is a **side channel** (page-dedup timing attacks are well known [L]). Enable it only within a trust class, never across zones with different labels. Prefer snapshot CoW sharing, which is explicit |
| **Pod overhead accounting** | RuntimeClass `overhead.podFixed` | Kata 130–320 Mi | Do the same in wicket-node: each tier declares its fixed overhead so the placement compiler counts density honestly |

### 4.3 The Kubernetes pod path versus direct launch

A Kubernetes pod start is these steps, in series:
1. API write and admission (validating policies);
2. scheduler binding;
3. kubelet sync;
4. CRI `RunPodSandbox` (pause container, netns, **CNI ADD**: veth, IPAM, Cilium endpoint and policy
   regeneration);
5. image pull or unpack;
6. `CreateContainer` and `StartContainer` (runc, runsc or kata shim);
7. probes.

Steps 1–4 are what the 5 s p99 SLO covers, with pull excluded. At concurrency, CNI alone can double start
time (Kata CNI paper). A **direct launch** from `wicket-node` skips steps 1–4: `clone` into prepared
namespaces, or `runsc create/start` with `--network=none` plus the UDS bridge, or a Firecracker
`InstanceStart`. The image is already unpacked on the node. Expected cost:
- **~3–50 ms** for the process jail;
- **~100–300 ms** for gVisor [L, needs the M7 measurement];
- **≤ 125 ms** boot plus guest init for Firecracker, or **tens of ms plus page faults** from a snapshot.

That is **one to two orders of magnitude** below the pod path, and it keeps the parts Kubernetes can't do
today:
- gVisor checkpoint/restore;
- Firecracker snapshots and UFFD;
- the no-interface netns;
- claim-then-bind without a pod update.

**So:** use Kubernetes for **capacity** (nodes, node pools, the per-node reservation) and for **long-lived
services**. Use **direct launch from wicket-node** for anything on the agent's critical path. wicket-node
asks for its budget as *reservation pods*: pause-image pods requesting the CPU and memory of N sandbox
slots, with the RuntimeClass overhead included. The Kubernetes scheduler and cluster-autoscaler then see the
real load and add nodes. Inside a reservation, wicket-node launches and recycles sandboxes freely.
Cluster-autoscaler and Karpenter scale on pending pods, so wicket scales the cluster by creating more
reservation pods than fit.

### 4.4 Latency and density budget per workload kind

| Workload | Start budget (p95) | Overhead budget on top of the payload | Mechanism | Where |
|---|---|---|---|---|
| **Agent sandbox** (Claude Code, per zone) | **≤ 300 ms** box-ready from a warm pool; ≤ 1 s cold (the agent's own start, ~1–2 s, comes on top) | **≤ 40 MiB** (the agent is 300–600 MB) | process jail, or gVisor direct launch; Firecracker later | wicket-node, direct |
| **Per-task third-party MCP server** | **≤ 250 ms** to `tools/list`-ready, from a pristine snapshot or an unbound warm instance; ≤ 2 s cold | **≤ 30 MiB** + server RSS | gVisor/Firecracker snapshot-clone; jail for wicket-vetted servers | wicket-node, direct |
| **Per-zone or shared MCP service** (stateless, vetted) | n/a (long-lived) | pod overhead acceptable | gVisor RuntimeClass pod | Kubernetes Deployment |
| **Codemode** (Wasm) | **≤ 5 ms** | ≤ 5 MB | wasmtime pooling allocator | in the gateway process |
| **Parked agent resume** | **≤ 2 s** after approval | disk only while parked | cgroup freeze (seconds); runsc checkpoint, Firecracker snapshot (minutes+) | wicket-node, direct |
| **wicket per-node proxies** (egress, LLM, gateway) | n/a | ~100–200 MB per node [L] | inside wicket-node, or a sibling DaemonSet | DaemonSet |
| **A whole host** | ~60–80 s (Vultr); seconds from a paid-time pool | — | warm host pool aligned to the billing hour | provisioner |

**How this changes the Kubernetes recommendation:** it moves Kubernetes *off* the hot path. It would have been
the natural sandbox launcher if per-sandbox latency didn't matter (agent-sandbox's model). With these budgets,
Kubernetes stays the right place for capacity, node lifecycle, autoscaling and services. It is the wrong
place for one-sandbox-per-zone and one-MCP-instance-per-task churn. The exceptions are agent-sandbox warm
pools on GKE, which make the pod path acceptable for *agent* sandboxes (200 ms claims). wicket supports that
through the optional backend.

---

## 5. Kubernetes as the infrastructure layer (in depth)

### 5.1 kubernetes-sigs/agent-sandbox: API surface and maturity

Only the parts that matter for a backend decision:
- **Version and maturity.**
  - **v1.0.10** (2026-11-06), with weekly releases since October.
  - The API groups are still **`agents.x-k8s.io/v1beta1`** and `extensions.agents.x-k8s.io/v1beta1`.
  - Recent releases broke things: v1.0.6 started rejecting names over 63 characters *on existing objects*;
    v1.0.9 left Helm CRDs to be applied manually; v1.0.10 removed a Go API option.
  - **Pin it exactly and treat upgrades as migrations.** [H]
- **CRDs:**
  - `Sandbox` (core: a singleton stateful pod with a stable identity; lifecycle has `shutdownTime` and
    `shutdownPolicy: Delete|Retain`);
  - `SandboxTemplate`;
  - `SandboxClaim`;
  - `SandboxWarmPool`.

  [H]
- **Isolation and runtimes.**
  - **Isolation is delegated to RuntimeClass** (gVisor or Kata). It requires Kubernetes ≥ 1.25 (1.29+
    recommended).
  - An optional Sandbox Router handles runtimes that can't port-forward.
  - Pause/resume and snapshots are not core features; on GKE they come from **Pod Snapshots** (gVisor).
  - [H/M]
- **Egress.**
  - `SandboxTemplate.spec.networkPolicy` creates **one NetworkPolicy shared by every sandbox of the
    template**.
  - The managed default **allows egress to the public internet** (RFC 1918 and metadata blocked).
  - The router's egress was too open until v1.0.10. Even now TCP 443, 6443 and 53 to any destination stay
    open by default.
  - [H]

  **That default contradicts wicket's principle that only the proxy is reachable.** wicket must set
  `networkPolicyManagement: Unmanaged` and enforce its own policy (§5.3).

**Verdict:** an **optional `Sandbox` backend** (`k8s-agent-sandbox`), behind the same trait as the others.
- Use it where a user already runs Kubernetes, especially GKE with Agent Sandbox and Pod Snapshots.
- Don't make it wicket's core model, for four reasons:
  - it is beta and churning;
  - its unit is the pod, so it inherits the pod-start path and has no runsc checkpoint;
  - one NetworkPolicy per template is coarser than wicket's per-zone egress;
  - claims that set env cold-start.

### 5.2 Isolation tiers as RuntimeClasses

| RuntimeClass | Needs | Works on this box? | Notes |
|---|---|---|---|
| `runc` (default) | — | yes | Shares the host kernel. **Never** for hostile code (runc container escapes CVE-2025-31133, -52565 and -52881 in Nov 2025, all high [H]) |
| `gvisor` (runsc, **systrap**) | nothing special | **yes**: systrap is "a better choice when running inside a VM, or on a machine without virtualization support"; ptrace is no longer supported [H] | On k3s, configure it by hand: `containerd-shim-runsc-v1` plus a `config-v3.toml.tmpl` runtime entry (k3s doesn't auto-detect runsc) [H/M]. GKE Sandbox is the managed variant: COS nodes, a separate pool, no hostPath or privileged pods [H] |
| `kata-clh` / `kata-fc` / `kata-qemu` | **KVM** on the node | **no** | Kata 4.3.1 (2026-10-21) is active [H]. Overhead 130–320 Mi. Kata-FC needs the devmapper snapshotter. On EKS it means self-managed Kata on `.metal`, or nested virtualization on C7i/C8i (to be tested) [H/M]. firecracker-containerd is in maintenance (no releases, last commit 2026-07) [H] |

`RuntimeClass.scheduling` (still beta) merges a `nodeSelector` and tolerations into every pod that uses it.
That is how `kata-*` pods land only on KVM node pools [H].

**Container checkpoint/restore in Kubernetes (for parking)** [H]:
- **`ContainerCheckpoint`** is beta and on by default since 1.30 and is **not GA** in 1.37 (latest minor,
  2026-08-26). It writes a checkpoint archive via the kubelet API. Restore is left to the runtime. A node DoS
  went through this API (CVE-2025-0426).
- **Pod checkpoint/restore (KEP-5823)** is **alpha** in 1.37. It adds CRI `CheckpointPod`/`RestorePod` and a
  new pod with `spec.restoreFrom`, **same-node only**, with a new UID.
- **gVisor `runsc checkpoint/restore`** is documented only for raw runsc and partly for Docker. It is not
  reachable through containerd or Kubernetes.

**Conclusion:** parking stays a wicket-node feature, done with direct runsc or Firecracker calls.

### 5.3 Network: making the proxy un-bypassable

wicket's rule: a box's **only** route is wicket's proxy. In a Kubernetes cluster, two shapes are possible:
- **(a) Direct-launched sandboxes (recommended for the hot path).** wicket-node creates the sandbox's netns
  itself, with **no interface** and a UDS-bridged proxy (pattern A, [02 §7]). CNI is never involved, so there
  is nothing to bypass. The node's own egress is restricted by host nftables to wicket's upstream targets.
- **(b) Sandbox or MCP pods (optional backend, long-lived services).** These need **CNI enforcement**.
  Cilium (v1.20.4) [H]:
  - **Default deny.**
    - `policyEnforcementMode=always`, plus a namespace-wide policy selecting all pods.
    - Allow egress **only** to the node-local wicket proxy (by `toEndpoints` on the proxy DaemonSet's labels,
      or a host port) and to wicket's DNS.
    - Allow ingress **only** from wicket-node or the gateway.
    - `toFQDNs` rules are wrong for sandboxes: they would let traffic bypass the TLS-intercepting proxy.
    - [H]
  - **Node-local steering.**
    - `CiliumLocalRedirectPolicy` redirects a ClusterIP or IP:port to a node-local backend, which suits the
      proxy as a DaemonSet.
    - `toPorts.listener` (CiliumEnvoyConfig) can send matched traffic to an Envoy listener.
    - Neither is a general "redirect everything" primitive. Default-deny-except-proxy is the enforceable
      shape, and the box is configured with `HTTPS_PROXY` (pattern A semantics over an interface) [H/M].
  - **Runtime caveats.**
    - gVisor writes packets to the pod's veth through its own netstack, so CNI policy applies on the host
      side [H/M].
    - Kata needs `socketLB.hostNamespaceOnly=true` and has MTU caveats [H].
  - **Policy timing.** Egress Gateway docs note brand-new pods can egress briefly before policy applies [H].
    Treat that as a general CNI race, and start sandbox payloads only after the endpoint's policy revision is
    realised (Cilium exposes this per endpoint) [L, verify].
  - **MCP pods isolated from each other.**
    - Plain NetworkPolicy is a union of allows, and a connection needs both egress at the source and ingress
      at the target [H].
    - Per namespace: a `podSelector: {}` deny for ingress and egress.
    - Then allow MCP ingress from wicket-node or the gateway only, and MCP egress to the proxy only.
    - Server A then can't reach B even inside one namespace.
  - **Don't expose MCP servers as cluster-wide Services.** The gateway reaches them through wicket-node
    (§9.4).

### 5.4 wicket as a Rust operator

- **kube-rs** is mature enough:
  - `kube` 5.0.0 (2026-11-01), a CNCF Sandbox project;
  - `runtime` has Controller, finalizers, reflectors, watchers, events and scheduling;
  - `admission` and `cel` features are available;
  - adopters include the Linkerd policy controller, Kubewarden, Vector, Stackable and mirrord;
  - `k8s-openapi` 0.29.0 covers Kubernetes 1.33–1.37;
  - MSRV trails stable by about two versions.

  [H]
- **Shape:** one `wicket-operator` binary with a controller per CRD (§12). Status subresources carry the
  *explanation* (which rule placed what where). Finalizers make sure leases and money reservations are
  settled before objects disappear.
- **The ledger is not etcd.** Grants, use counts, budgets and the audit log stay in `wicket-store` (SQLite,
  design §13). CRDs hold **desired infrastructure state** only. etcd is readable and writable by anyone with
  cluster RBAC, and it has no notion of wicket's capability algebra.

**Mapping wicket's placement vocabulary (§7) onto Kubernetes:**

| wicket constraint | Kubernetes primitive | Verified by wicket after placement |
|---|---|---|
| `isolation >= UserspaceKernel` | `runtimeClassName: gvisor` (or kata) | pod's runtime handler, from the CRI status |
| `isolation >= Hardware` | `runtimeClassName: kata-*`; RuntimeClass `scheduling.nodeSelector: wicket.dev/kvm=true` | node label set by the provisioner |
| `requires(kvm)`, `arch`, `gpu` | node labels plus `nodeSelector`/`nodeAffinity` | ✓ |
| `region in […]`, `residency(uk)` | `topology.kubernetes.io/region` node affinity | node's provider region, from the provisioner's records, not the kubelet's self-report |
| `separate(A, B, at: Sandbox)` | always true (distinct pods / sandboxes) | — |
| `separate(A, B, at: Kernel)` | true if *either* side runs gVisor or Kata (its own kernel); otherwise `at: Host` | runtime check |
| `separate(A, B, at: Host)` | **required** `podAntiAffinity` on `kubernetes.io/hostname` against B's `wicket.dev/sep-group` label (symmetric: put it on both) | node of each, re-checked on every reschedule |
| `separate(…, at: Provider/Account)` | separate clusters or node pools per account | ✓ |
| `dedicated(tenant T)` | node pool with taint `wicket.dev/tenant=T:NoSchedule` plus toleration and nodeSelector | ✓ |
| `colocate(sandbox, its proxies)` | implicit: wicket-node is per node | ✓ |
| data-class conflict between zones (§7.3) | derived `separate(at: Host)`, expressed as anti-affinity on a `wicket.dev/data-class` label | ✓ |
| `attestation >= ProviderApi/Tpm/SevSnp` | node pool label | from the node's attestation record (§8) |

**Security-relevant node labels must use the `node-restriction.kubernetes.io/` prefix.** NodeRestriction stops
a kubelet setting those on itself [H], so a compromised node can't self-label into a trusted pool. Required
pod anti-affinity is limited to `kubernetes.io/hostname` topology by an admission plugin and is "not
recommended in clusters larger than several hundred nodes" [H]. Fine at wicket's scale.

The Kubernetes scheduler is only a *proposer* here. wicket's verifier re-checks every placement from its own
records, and an admission policy (`ValidatingAdmissionPolicy`, CEL) rejects pods in wicket namespaces that
lack the operator's constraints.

### 5.5 Capacity and money on Kubernetes

| Option | Control plane | Nodes | Scale to zero | KVM nodes | Autoscaling |
|---|---|---|---|---|---|
| **VKE** (Vultr) | **free** [H]; HA control plane price not published ($30–40/mo reported [L]) | normal instance rates (hourly, 672 h cap); smallest 1c/2GB **$10/mo** [H] | **No**: "at least one node is required for a node pool" [H] | VMs have no KVM. Bare-metal workers: the FAQ says no, a 2024 changelog says "Add VKE Baremetal support" [H]. **Treat as unsupported** | built-in per-pool `auto_scaler` with min/max (cluster-autoscaler) [H] |
| **GKE** | $0.10/h; a $74.40/mo credit covers one zonal or Autopilot cluster [M] | per second | Autopilot: yes | Intel/N4D nested virtualization; **GKE Sandbox (gVisor) managed** [H] | Autopilot / cluster-autoscaler |
| **EKS** | $0.10/h standard [H] | per second | via Karpenter | nested virtualization on C7i/C8i; Kata self-managed on `.metal` [H] | **Karpenter** |
| **k3s / k0s self-managed** | your box | any provider | yes (wicket's provisioner) | wherever the host has KVM | wicket's provisioner, or cluster-autoscaler `externalgrpc`/`clusterapi` |

- **Cluster API for Vultr (CAPVULTR)** is pre-1.0 (v0.6.0, 6 stars) [H].
- **Karpenter** has providers for AWS, Azure, GCP, Hetzner (third-party), Linode, OCI, Cluster API, Proxmox
  and others. **There is no Vultr provider** [H].
- **cluster-autoscaler** supports `vultr`, `hetzner`, `clusterapi` and `externalgrpc` [H].

**Node pools are the spend envelope.** A pool's `max_nodes × hourly price × 672` is its worst-case month.
wicket's provisioner sets pool maxima from the ledger budget and never lets the autoscaler own the cap.
Pools that must reach zero, such as KVM and GPU pools, are **not** VKE pools. They are hosts wicket's own
`HostProvider` creates and joins as k3s agents (or Karpenter NodeClaims on EKS), with leases and GC (§6).

### 5.6 Single host and development

- **k3s v1.37.2** (2026-11-03, containerd 2.3.7) [H]:
  - Minimums: server 2 cores / 2 GB.
  - Measured: **~1.6 GB RAM and ~6% of a core** for a single-node server with a workload (k3s resource
    profiling, v1.26) [H].
  - k0s is similar: 1 GB minimum for controller plus worker [H].
- **On this box:** about 3 GB available with roughly 15 sessions running [H]. k3s, gVisor and Cilium fit
  **only as an on-demand test cluster**, started for backend conformance runs through the host's job-slot limits and stopped
  afterwards, and agreed with the host's operator first. A resident cluster would take about half the box's memory
  headroom.
- **Keep a no-Kubernetes local mode** for:
  - laptops (macOS: seatbelt, `vz`);
  - this box today (the M1 milestone);
  - anyone running wicket as a CLI.

  Local mode runs the *same* reconcilers against SQLite instead of CRDs (§12), so it isn't a second
  implementation.

### 5.7 The security cost of Kubernetes for hostile workloads

- **The TCB grows** to include:
  - the API server and etcd;
  - the kubelet;
  - containerd and the shims;
  - the CNI agent (Cilium runs privileged on every node);
  - admission webhooks;
  - wicket's operator RBAC.

  The Kubernetes docs: sandboxing is "often recommended when you are running untrusted code", but "the
  kubelet and … the API service are still shared services" [H]. Recent relevant CVEs:
  - runc escapes (Nov 2025);
  - kubelet checkpoint DoS (CVE-2025-0426);
  - a compromised node bypassing DRA checks (CVE-2025-4563/5187);
  - StatefulSet cross-namespace pod creation (CVE-2026-2270).

  [H]
- **Node compromise exposes every secret referenced by pods on that node** (Node authorizer) [H]. Rules:
  - **No Kubernetes Secrets for sandbox or MCP pods, ever.** Per-task credentials go from the vault to
    wicket-node's in-memory proxies over mTLS (§8).
  - `automountServiceAccountToken: false` on every workload pod.
  - Workload pods get a ServiceAccount with no RBAC.
- **RBAC is authority.** Anyone who can `create pods` in a wicket namespace can start a box with no wicket
  proxy. Rules:
  - Only the operator's ServiceAccount may create pods there, enforced by a `ValidatingAdmissionPolicy` that
    checks `request.userInfo`.
  - Humans get read-only access plus `wicket` CLI verbs.
  - **Cluster-admin is in wicket's TCB.** The zone view must say so: "cluster admins can bypass all gates".
- **Operator RBAC, minimal:**
  - create/delete pods and NetworkPolicies/CiliumNetworkPolicies in wicket namespaces;
  - read nodes;
  - patch its own CRDs' status;
  - **no** cluster-wide Secret read;
  - **no** RBAC write.

  The provisioner (the cloud credential holder) is a separate process and is not in the cluster at all.
- **Multi-tenancy:**
  - Use namespaces per zone class. Use **vCluster** (v0.37.6, Apache-2.0) [H] only if separate *human*
    tenants share a cluster; it adds a whole API server per tenant.
  - For hostile *code*, the boundary is the sandbox (gVisor or Kata) plus node separation, not namespaces.

---

## 6. Control-plane patterns

### 6.1 Declarative desired state with level-triggered reconcilers

Use the Kubernetes controller shape whether or not Kubernetes is underneath:
- desired state in a store (CRDs, or SQLite in local mode);
- observed state read from the *authoritative* source:
  - the provider API for hosts;
  - wicket-node for sandboxes;
  - the provider's billing API for money;
- a pure function `reconcile(desired, observed) -> Vec<Action>`;
- actions applied idempotently, with requeue on error.

It is level-triggered: every pass recomputes from scratch, so a missed event costs latency, not correctness.

Prior art:
- **Kubernetes controllers** (kube-rs `Controller`).
- **Nomad** (BSL 1.1 since 2023-08 [H]: usable internally, but not embeddable in a competing product):
  - constraint operators `distinct_hosts`, `distinct_property`, `set_contains(_any)`, `regexp`, `version`,
    `semver`, `is_set` [H];
  - affinities with weights from −100 to 100;
  - `spread`.
- **Fly's flyd** [H, 2023 blog]:
  - each host's flyd is the source of truth for its machines, as finite-state machines persisted in BoltDB
    as a log;
  - **no central scheduler and no consensus**: requests are *bids*, hosts are suppliers, immediate-or-cancel,
    no pending queue;
  - a stateless proxy (`flaps`) ranks hosts;
  - fleet state is gossiped (Corrosion).
- **Firecracker-containerd**: in maintenance, not a basis [H].

**What wicket takes from each:**
- From flyd, *per-node durable FSMs*: wicket-node persists each sandbox's state machine locally, so a
  wicket-node restart resumes, and the control plane's view is a cache.
- From Kubernetes, *the desired-state API and controllers*.
- From Nomad, *the constraint vocabulary* (§7).

### 6.2 Leases and TTLs

Everything wicket creates carries a **lease**: `holder`, `granted_until`, `renew_by`, `max_until`,
`billing_granule`.
- **Workload leases** are renewed by the task's heartbeat, which the LLM proxy and wicket-node observe. They
  end at task end at the latest (design §10).
- **Host leases are snapped to the billing granule.** For Vultr, Hetzner, Scaleway and phoenixNAP (per
  started hour), `granted_until` = minute 50 of the last paid hour, as in the broker script. For AWS, GCP, OVH and Fly
  (per second or per minute), the lease is the requested duration plus a small grace period.
- **Fly Machines leases** (`POST /machines/{id}/lease` with a TTL and a nonce required on later mutations)
  are an *optimistic lock* for multiple controllers [H]. They are a good model for wicket's own multi-writer
  safety: the operator and the provisioner both act on hosts, so take a lease before mutating.

### 6.3 Warm pools (three levels)

1. **Host pool.** Paid-time-aligned: release goes to the pool if ≥ 10 min are left; a claim needs ≥ 20 min
   left; pooled hosts are destroyed before the next hour starts (the broker script) [H].
   - A pooled host is reused **only within the same trust and data class** (§7.3). After a hostile workload
     the host kernel is suspect.
   - A host that ran a different class is destroyed, not pooled, unless it is reimaged. Reimaging costs
     about the same as a new box on hourly providers.
2. **Sandbox pool.** Unbound, identity-less sandboxes per (image digest, tier), bound on claim (§4.2).
   Pool size comes from recent claim rate × p95 claim-to-release time, bounded by the node reservation.
3. **Snapshot pool.** Pristine snapshots per (MCP server digest, tier), restored per task (§9).

### 6.4 Idempotent creation

A create call that times out may or may not have created a host. The protocol:
1. **Write an intent row first**: `intent_id` (UUIDv7), provider, class, region, worst-case cost reserved
   in the ledger (§10).
2. **Create with the intent attached**:
   - **AWS** `ClientToken = intent_id` (≤ 64 characters) [H];
   - **GCP** `requestId = intent_id` [H];
   - **Azure** a deterministic resource name (idempotent PUT) [M];
   - **Fly** a deterministic Machine `name` [M];
   - **Vultr, Hetzner, OVH, Scaleway, Latitude** have **no idempotency key** [H/M]. Put `wicket-intent=<id>`
     in tags or labels, and on any retry **list by tag before creating again** (the broker script's `mine` and orphan
     logic).
3. **Commit the observed `provider_id` to the intent.** The reconciler adopts or destroys any tagged
   resource whose intent is unknown or already closed (orphan GC).

### 6.5 Garbage collection of leaked hosts

- **The inner loop.** The provisioner's GC pass runs every 5 minutes and lists by owner tag. It destroys
  every resource tagged as wicket's that has:
  - (a) no live lease;
  - (b) an expired lease;
  - (c) a stale heartbeat (45 min idle);
  - (d) an unknown intent.

  It **never** touches untagged resources, or ones tagged as protected (the control host and the broker)
  [H, the broker script].
- **Dead-man's switch** (the broker script's open gap: if the control plane dies, nothing reaps):
  - **Provider-side TTL where it exists.**
    - AWS `InstanceInitiatedShutdownBehavior=terminate` plus a guest `shutdown -h +N` timer that wicket-node
      keeps pushing out while it can reach the control plane [M]. The node then kills itself, and AWS
      terminates it.
    - **On Vultr and Hetzner, a stopped server still bills** [H], so self-poweroff doesn't help. You need an
      **external reaper**: a second, minimal GC running elsewhere (another region's tiny VM, or a scheduled
      Claude Routine) that holds a *destroy-only* view.
    - Vultr API keys aren't scopable [M], so that second key is still a full key. Keep it in a separate
      place with IP-allowlisting, which Vultr supports for API keys [L].
  - **Budget-side cap.** The ledger's worst-case reservation means that even a leaked host can't push the
    month past the cap *as accounted*. The external reaper keeps reality matching the accounts.
- **Reconcile money daily** against the provider's billing API (Vultr `pending_charges` [H]). Alarm on
  drift: actual > reserved, or unknown line items, which mean something exists that wicket doesn't know
  about.

### 6.6 Cost accounting and hard caps

- **Each provider's `BillingModel` is data:**
  - granule (per second, minute or started hour);
  - minimum;
  - per-line rounding (Vultr rounds up to the cent);
  - monthly cap hours (Vultr 672, Hetzner the monthly price);
  - whether stopped resources bill (Vultr and Hetzner yes; AWS and Azure deallocated no);
  - setup fees;
  - minimum lease (Scaleway Mac: 24 h).
- **The worst-case cost of a lease** is `ceil_to_granule(max_until − created) × rate`, rounded up per line,
  plus setup fees, plus storage and IPs. It is reserved at intent time and released or settled at close.
- **Hard monthly cap:** the sum of reservations plus settled spend must be ≤ cap, or the request goes to a
  human, never to auto (§10). the broker script additionally requires the owner's OK above $2 per run [H]. Keep that as
  a per-request `human_above` threshold.

---

## 7. Placement and isolation constraints

### 7.1 What gets placed

| Workload kind | Default isolation floor | Default separation | Notes |
|---|---|---|---|
| `AgentSandbox` (one per zone) | `Process` for wicket-trusted tasks; **`UserspaceKernel`** (gVisor) by default on shared hosts | from other tasks' sandboxes: `Kernel` if they have different principals or labels | runs the inner agent |
| `McpServer` (third-party) | **`UserspaceKernel`** | **`Kernel` from every other MCP server and every agent sandbox** | owner's example: "A and B never share a kernel" |
| `Codemode` | `Capability` (Wasm) | in-process in the gateway | no POSIX |
| `WicketProxy` (egress, LLM, gateway per node) | host process (TCB) | colocated with the sandboxes it serves | DaemonSet / wicketd |
| `Job` (an agent's "GPU box to run tests") | per request; `Hardware` or a dedicated host for GPU | `Host` from other principals | via the escalation flow (§10) |

### 7.2 Vocabulary

Constraints are **data**, compiled to a backend's primitives (Kubernetes §5.4; local mode: the wicket-node
scheduler). Every constraint carries **provenance**: org policy, zone manifest, derived from labels, or a
grant. The zone view explains a placement as a list of `(constraint, provenance, satisfied_by)`.

```text
isolation >= Process | UserspaceKernel | Hardware | Remote        # IsolationLevel from [02 §11]
requires kvm | arch(x86_64|aarch64) | gpu(kind, n) | snapshot(Full|Filesystem|Freeze)
region in {lhr, man, …}        residency(uk | eu | any)
provider in {vultr, aws, fly, local, …}      not provider {…}
separate(A, B, at = Sandbox | Kernel | Host | Provider)      # A, B are selectors: workload kind, zone, server digest, principal
dedicated(tenant = T)          # only workloads of T on these hosts
colocate(A, B, at = Host)      # e.g. an MCP instance with its agent, when allowed
attestation >= None | ProviderApi | InstanceIdentity | Tpm | SevSnp | Tdx
max_cost(usd_per_hour), max_lifetime(dur)
```

Notes:
- **`at = Kernel` is the useful middle level.** Two gVisor sandboxes on one host don't share a guest kernel
  (each has its own Sentry), though they share the host kernel underneath. "Never share a kernel" for
  hostile third-party servers is therefore met by `UserspaceKernel` *on both*. The stricter `Host` exists for
  data-class conflicts and side channels.
- **Separation is symmetric and transitive-free.** `separate(A, B)` doesn't imply anything about C. The
  compiler emits it on both sides (anti-affinity is placed on each pod).
- **Soft preferences** (Nomad-style affinities): `prefer colocate`, `prefer region`, with weights. Only hard
  constraints appear in the "why" view as guarantees. Preferences appear as "chosen because".

### 7.3 Derived constraints from labels

The IFC labels (design §4.2) generate separation automatically:
- **Conflicting data classes never share a host.** Two zones whose confidentiality labels are incomparable
  get `separate(at = Host)`. Examples: `secret:acme-prod` and `secret:globex`, or `secret:*` and
  `untrusted:web` when the policy marks them as conflicting.
- **Hosts carry a history label:** the join of the labels of everything they have run since the last image.
  A host may accept a workload only if the workload's label is compatible with that history. That is why
  pooled hosts are reused only within a class (§6.3).
- **KSM and other cross-workload dedup are allowed only within a class** (§4.2).

### 7.4 Explaining placements in the zone view

```
mcp:github-issues@sha256:9f… (task fix-flaky-sync)
  runs   gVisor sandbox sbx-41 on node lhr-vc2-3 (Vultr, London, attestation: provider-api)
  why    isolation >= UserspaceKernel        org policy P3 "third-party MCP servers never run in a shared kernel"
         separate(at=Kernel) from agent zone writer   derived: label untrusted:web ⋢ secret:acme
         residency(uk)                        zone manifest fix-flaky-sync.yaml:12
  not    colocate with zone reader: preference waived — host lhr-vc2-3 full (soft, weight 30)
```

The same records drive the verifier. If any line becomes false (a node relabelled, a pod rescheduled), the
workload is stopped first and explained second. **Fail narrow.**

Prior art mapped: Kubernetes affinity/anti-affinity, taints, RuntimeClass, topology spread; Nomad
constraints/affinity/spread; **AWS Nitro Enclaves** as the extreme `separate(at = Kernel)` with attestation
(enclave PCRs bind the image, the parent role and the instance) [H].

---

## 8. Node bootstrap and trust

### 8.1 Bootstrap

**Host created by wicket's provisioner (not via managed Kubernetes):**
1. The provisioner creates the host with cloud-init user-data containing:
   - the pinned wicket-node image digest;
   - the control plane's public key and endpoint;
   - a **one-time join token**: 128-bit random, TTL ≤ 15 min, bound to the `intent_id`, and to the provider
     instance ID and IP once known.

   Prior art: kubeadm bootstrap tokens (`[a-z0-9]{6}.[a-z0-9]{16}`, 24 h default TTL; the docs warn against
   sharing one token between clients) [H]; Nomad 1.11 *client introduction tokens* (JWTs scoped by node
   name and pool) [M]; Tailscale **one-off, ephemeral, pre-approved, tagged** auth keys [H].
2. wicket-node generates its key pair **on the host** and presents the join token plus the public key plus
   provider evidence:
   - **AWS:** IMDSv2 signed identity document (PKCS7/RSA-2048) [H].
   - **GCP:** instance identity JWT with `audience = wicket`, `format=full` (instance_id, project, zone) [H].
   - **Azure:** attested data with a nonce [H].
   - **Vultr, Hetzner, Fly:** no signed identity document [M/L]. Use **provider-API attestation**: the
     control plane asks the provider API (with its own key) whether instance X, with this IP, tag
     `wicket-intent=<id>`, was created < 15 min ago and not yet joined. This is the trust-on-first-use
     equivalent, and it is what SPIRE's `join_token` attestor degrades to.
3. The control plane burns the token and issues a short-lived **node certificate**: SPIFFE-style ID
   `spiffe://wicket/node/<provider>/<id>`, 24 h, renewed over mTLS.
   - Optional: run **SPIRE** (v1.16.0; node attestors `aws_iid`, `gcp_iit`, `azure_imds/msi`, `join_token`,
     `tpm_devid`, `k8s_psat`, `x509pop`) [H] instead of a home-grown CA, once there is more than one
     provider.
4. **Transport:** a **WireGuard** mesh between nodes and the control plane, with mTLS inside.
   - Rust: `defguard_wireguard_rs` 0.12.5 (kernel WG), `boringtun` 0.7.1 (userspace) [H].
   - Or **Tailscale/headscale** (headscale v0.29.7 [H]) with tagged ephemeral keys, if a coordination
     server is acceptable in the TCB.
   - Recommendation: plain WireGuard managed by the control plane. It has fewer moving parts and no
     third-party coordination server.

**Hosts joined through managed Kubernetes (VKE, GKE):**
- The provider's bootstrap handles kubelet join.
- **wicket-node still does its own wicket join** (steps 2–3) from the DaemonSet. Kubernetes membership
  doesn't grant wicket trust.

### 8.2 Hardware attestation in 2026

| Provider | Confidential VMs / vTPM |
|---|---|
| **AWS** | **SEV-SNP** only on m6a/c6a/r6a. Shared tenancy only in us-east-2 and eu-west-1, plus 10%; Dedicated Hosts anywhere. **NitroTPM** with attestation documents, "Attestable AMIs". **Nitro Enclaves** (PCR-bound attestation, KMS integration). No TDX found [H/M] |
| **GCP** | SEV (N2D/C2D/C3D/C4D), **SEV-SNP N2D only**, **TDX** (C3, C4, A3). **None of them in europe-west2 (London)**; nearest are europe-west3/4/9 [H] |
| **Azure** | SEV-SNP (DCasv5/v6, ECasv5/v6); TDX (DCesv6, ECesv6); Trusted Launch vTPM by default [H]. Whether UK South has the CVM SKUs: not checked |
| **Vultr / Hetzner / Fly** | none found [L] |

**Implication:** v1 trusts nodes at `ProviderApi`/`InstanceIdentity` level only. Attestation is a
placement constraint (`attestation >= SevSnp`) that high-sensitivity zones can demand later. That pushes
them to Azure, or to AWS outside London. **Measured boot (TPM PCRs) for wicket-node's own image** is the
first attestation worth building, because it is what lets the vault release credentials to a node.

### 8.3 Credentials to nodes

- **Nodes hold no cloud credentials and no long-lived upstream credentials.**
- The vault mints the **narrowest native credential per task** (design §8.4) and delivers it to *that
  task's node* only, over mTLS, audience-bound to the node's SPIFFE ID, with TTL ≤ task lease. It is held in
  wicket-node's proxies' memory, never on disk, never in a Kubernetes Secret.
- The model API key is the exception: it is wicket's own, not per-task. Either:
  - per-node LLM proxies get a *derived* key with a per-node spend limit, where the model provider supports
    it (Anthropic workspaces and keys [L]); or
  - the LLM proxy runs centrally, and nodes reach it over the mesh. That costs one extra hop on the model
    path, but keeps a single key off every node. **Recommended for v1 multi-host.**

### 8.4 The decision engine and ledger across hosts

Every enforcement point embeds the decision engine (design §3). Multi-host changes only *where ledger state
lives*:
- **Tasks have a home node.** A task's zones are placed on one node unless separation forces otherwise. Its
  grants and use counts are **leased to that node's ledger shard**: SQLite on the node, write-ahead-logged
  to the control plane asynchronously.
- **A single-use grant is consumed locally, with no round trip.** Escrow semantics: the control plane hands
  the node `n` uses, and the node returns unused uses at close. This is the standard escrow/quota-lease
  pattern [L].
- **Cross-node counters stay central, with reserve-then-commit.** These are org-wide budgets, money, rate
  limits, and grants shared by zones on different nodes. Enforcement points reserve before acting. If they
  can't reach the control plane, they **deny or pend** (fail narrow).
- **Policy (Cedar) and adapters** are content-addressed bundles pushed to nodes and pinned by hash in each
  decision's audit record.

**When Biscuit becomes worthwhile** [03 §7.2; biscuit-auth 6.0.0, third-party blocks, revocation IDs H]:
- an enforcement point must verify authority **offline**, with no ledger reachable: a remote MCP server we
  don't run, or E2B/Fly capacity calling back;
- delegation crosses **trust domains**: another org's wicket, or a third-party service checking a wicket
  grant;
- attenuation must happen **at the edge**: a node narrowing a grant for a child without asking the control
  plane.

Use counts still need server state (the MCP spec says single-use must be enforced server-side, [03 §2.6]).
The Biscuit revocation guide also says expiry "is not sufficient" and needs a shared, limited revocation feed
[H]. So Biscuit is a *transport* for authority to places the ledger can't reach, not a replacement for the
ledger. **Not v1.** The first use is likely remote MCP servers and hosted backends.

### 8.5 Blast radius of a compromised node

| Attacker gets | Contained by |
|---|---|
| Every sandbox and MCP instance on the node, and their in-memory per-task credentials until expiry | narrow native credentials, TTL ≤ lease; zone view lists "tasks on this node" as one blast-radius unit |
| The node's ledger shard: it can consume its own tasks' escrowed uses | escrow bounded per task; ratchet at the control plane |
| The node's mTLS identity | short-lived certificates; revoke the node, and the control plane refuses its WAL and decisions |
| **Not:** other nodes' credentials, cloud credentials, the money ledger, the ability to create hosts | none are ever on nodes. Provisioning is control-plane-only |
| In Kubernetes mode: the Secrets referenced by pods on that node (Node authorizer) | **no Secrets for workload pods**; kubelet NodeRestriction; `node-restriction.kubernetes.io/` labels |

Placement uses this table. `separate(at = Host)` between data classes means a node compromise exposes at
most one class.

---

## 9. Running MCP servers as isolated services

### 9.1 Instance scope: state is memory, and memory is a smuggling channel

| Scope | When | Risk |
|---|---|---|
| **Per task (default for third-party servers)** | any server with state, any server that has credentials or reaches the network | none across tasks. Cost is start latency, solved by snapshot-clone (§4.2) |
| **Per zone** (one instance serves the zone's sandbox across tasks in a session) | stateless or vetted servers, one principal, same label | carries memory across the zone's tasks. Acceptable only if all of them share label and principal |
| **Shared, long-lived** | wicket's own gateway-native tools (design §8.2, kind 1), or servers vetted as stateless *and* credential-less | a shared instance is a covert channel between every task that uses it: caches, temp files, global variables, background tasks. Third-party servers never qualify |

An MCP server instance's IFC label is the **join of the labels of everything it has seen**. A per-task
instance makes that label exactly the task's label.

### 9.2 MCP protocol facts that force this

- **2026-07-28 removes protocol-level sessions.** There is no `Mcp-Session-Id`; servers SHOULD ignore it.
  Each POST carries the protocol version, and `Mcp-Method`/`Mcp-Name` headers are required. State moves into
  **handles**, and the security guidance on "State Handle Hijacking" says possession of a handle MUST NOT
  count as authentication and state SHOULD be bound to `<user_id>:<handle>` [H].
- **2025-11-25 sessions:** a session ID MUST NOT be used for authentication [H].
- **Neither spec says anything about per-task vs shared instances** [H, not found].

Implication: wicket can't rely on a server to isolate tasks by session. Isolation is **one endpoint per
instance per task**, and the gateway holds the map `task → instance endpoint`. When one instance must serve
several principals (shared scope), the gateway authenticates on the server's behalf and binds handles to the
principal.

### 9.3 stdio servers, secrets and egress

- **stdio servers:**
  - **wicket-node runs the server in its sandbox and bridges its stdio over the sandbox's control channel**
    (UDS or vsock) to the gateway. No HTTP wrapper is needed.
  - Prior art if one is: supergateway v4.2.1 (stateless by default), sparfenyuk/mcp-proxy v0.15.0,
    ToolHive v0.63.0 (stdio in a container behind a streamable-HTTP proxy) [H]. Whether these wrappers share
    one stdio child across HTTP clients isn't documented. **That sharing is exactly the cross-task risk**, so
    don't use them for third-party servers.
- **Secrets:** keep the server **credential-less**.
  - The server gets placeholders, and its egress goes through the **same egress proxy**, under the *server
    instance's own* identity (zone `mcp:<digest>:<task>`). The proxy injects the narrow credential (design
    §8.4).
  - **Exception:** non-HTTP protocols (a database wire protocol, SSH) can't be injected at an HTTP proxy.
    For those, deliver a short-lived scoped credential to a tmpfs file at instance start, and mark it in the
    zone view as **"credential inside box"**.
  - Prefer a wicket-side protocol adapter (e.g. a Postgres proxy that holds the password) when such servers
    matter [L].

### 9.4 How the gateway reaches servers on other nodes

- **Prefer colocation.** `colocate(mcp-instance, its agent, at = Host)` is a soft preference by default. It
  gives a UDS path, with no network.
- **When separation forces another node:** gateway → its wicket-node → **mesh (WireGuard + mTLS, SPIFFE ID of
  the target instance)** → the target wicket-node → the instance's control channel.
- **Never** through a Kubernetes Service or a cluster IP.
- **In pod mode** (§5.3b), MCP pods accept ingress only from their node's wicket-node, by Cilium policy.

---

## 10. Infrastructure as authority

### 10.1 Who asks, and the path a request takes

All three kinds of requester produce the same `Op`:
- **humans** (`wicket infra up`);
- **wicket itself** (the reconciler needs a node for a placement, or a pool refill);
- **agents** ("I need a GPU box to run the test suite").

```rust
Op {
  agent, surface: Surface::Infra, provider: "wicket.infra",
  verb: "host.create" | "host.extend" | "host.release" | "workload.create" | "pool.resize",
  resources: [Resource::Capacity { class, region, provider }],
  effects: {money(usd_max), capacity, egress.new_host?},   // egress.new_host if the host gets any route out
  risk: max(floor(money), floor(capacity)),
  args: { class, hours, region, purpose_ref, max_usd },     // declared args only
  ..
}
```

- **Effect `money(usd_max)`.** `usd_max` is the worst-case billed cost (§6.6), computed by wicket from the
  provider's `BillingModel`, **never** taken from the requester. The risk floor scales with it:
  - ≤ the auto threshold and within budget → R2, which can be auto;
  - > the per-request human threshold (the broker script: $2) → R4, human;
  - would exceed the monthly cap → **Denied**, with a narrower alternative such as a smaller class or fewer
    hours.
- **Budgets** are ledger counters with reserve-then-settle:
  - org month cap ($20 now);
  - per-task budget, from the manifest;
  - per-requester budget;
  - per-class caps (e.g. no GPU without a human).

  The reservation happens at `Granted`. Settlement happens at lease close, and again at the daily provider
  reconciliation.
- **Tiers:**
  - **Auto:** wicket's own reconciler requests (pool refills, placements) within pre-approved envelopes.
    Node-pool maxima are pre-approved by a human once per month, the way the owner pre-approved the broker's
    rules.
  - **Human:** agent-originated requests above the threshold, any new provider or region, any request that
    widens the trust or data class of a host.
  - The **field provenance** rule (design §10) applies: an agent-supplied region or class that appears
    nowhere upstream can't be auto-granted.
- **What a grant gives.** A grant for an agent's request is a **lease on a workload slot**: a new sandbox
  or job on capacity wicket controls, *attached to the agent's zone graph* (a child zone, ⊆ parent
  authority). The agent receives a **handle** to run commands there through wicket (`wicket.exec(handle, …)`
  over its gateway), and artifacts come back as labelled handles. **It never receives SSH keys, IPs it can
  route to directly, or cloud tokens.**

### 10.2 Why agents must never hold cloud credentials

1. **A cloud credential is an egress bypass.** A new VM has its own unmediated internet. Creating one with
   user-data that uploads the workdir is exfiltration in one API call. Snapshots and images can be shared
   publicly, and object storage can be made public.
2. **It is persistence.** Resources outlive the task and the sandbox: a cron VM, an API key, an SSH key
   added to the account.
3. **It is permission management.** It creates sub-users and keys, changes firewall groups, and touches
   *the box wicket itself runs on*. The broker script guards the control host by tag for exactly this reason.
4. **It is money.** It is the one effect with no natural ceiling: GPU bare metal is listed at $68/h in this
   account's catalog [H].
5. **Provider scoping is coarse.** Vultr API keys are account-wide [M]. Fly macaroons can be attenuated
   (`fly tokens attenuate`, app-scoped caveats) [H], and AWS IAM is fine-grained, but even a perfectly
   scoped key still gives effects 1 and 2.

So the cloud credential lives **only in the provisioner** (a separate process, not in the cluster, not on
nodes). It is read the way the broker script reads it (never in argv or logs). Where the provider allows it, the
provisioner holds an attenuated credential: a Fly macaroon caveated to wicket's apps; an AWS role limited to
`RunInstances` with tag conditions plus `TerminateInstances` on `wicket:*`-tagged resources.

### 10.3 Relation to the existing provisioning broker

Until wicket replaces it, **wicket's `VultrProvider` is a client of the provisioning broker**:
1. it calls the broker's `request`;
2. it waits for the broker's grant;
3. it runs `up` with `BB_GRANT`.

That keeps one budget and one GC across all sessions on this box. Later, wicket's ledger *becomes* the
broker. The policy the broker session applies by hand becomes Cedar plus thresholds, and the broker script's watchdog
becomes the GC reconciler.

---

## 11. Recommendation: Kubernetes-native vs own reconciler vs hybrid

| Option | For | Against |
|---|---|---|
| **A. Kubernetes-native** (every sandbox and MCP instance is a pod; agent-sandbox CRDs; Cilium; RuntimeClass) | Least code; standard ops; autoscaling, node pools and multi-tenancy tooling for free; GKE Agent Sandbox gives warm pools and Pod Snapshots | **Hot-path latency** (pod p99 ≤ 5 s excluding pull, against a budget of ≤ 300 ms); **no runsc checkpoint** through Kubernetes, and pod restore is alpha and same-node; network un-bypassability depends on Cilium configuration rather than on the absence of an interface; Kubernetes RBAC becomes authority; ~1.6 GB baseline makes laptops and this box awkward; agent-sandbox is beta and churning |
| **B. Own reconciler and scheduler** (flyd-like per-node FSMs, own placement, own provisioning) | Full control; fastest path; tiny footprint | Rebuilds node lifecycle, autoscaling, scheduling, health and upgrades: the owner explicitly doesn't want this; becomes a second cluster manager to secure |
| **C. Hybrid (recommended)** | Kubernetes for capacity, node pools, autoscaling, wicket's own services and long-lived MCP services. **wicket-node does direct launch** inside reservation pods for agent sandboxes, per-task MCP instances and parking. A small **provisioner** handles what Kubernetes doesn't: money, billing-aligned leases, KVM/GPU hosts that scale to zero, provider-API attestation. **Local mode** reuses the same reconcilers on SQLite | Two placement layers (the Kubernetes scheduler for reservations, wicket-node inside them). The privileged wicket-node DaemonSet is TCB, but `wicket-jail` already is |

**Choose C.**
- **Kubernetes is the default multi-host substrate.** k3s self-managed on providers that have no managed
  Kubernetes, or where pools must reach zero; VKE where its pools fit; GKE/EKS where users already are.
- **Kubernetes is an optional backend, not a requirement.** wicket must still run as one binary on a laptop
  or this box (local mode). The design's M1 doesn't change.
- **agent-sandbox is a `Sandbox` backend** for clusters where pod-path latency is acceptable (GKE warm pools).
- **wicket writes:**
  - the placement compiler and verifier;
  - the operator (kube-rs);
  - wicket-node;
  - the provisioner;
  - the ledger integration.
- **wicket doesn't write:**
  - a cluster scheduler;
  - a node autoscaler (cluster-autoscaler/Karpenter, or its own provisioner for scale-to-zero pools only);
  - a service mesh (WireGuard + mTLS is enough).

---

## 12. Recommended Rust types

Two layers: **CRDs** (kube-rs `CustomResource`, group `wicket.dev/v1alpha1`) for desired infrastructure
state, and **plain traits** shared by the operator, local mode and the provisioner. Everything is in a new
`wicket-infra` crate (types, traits, compiler) plus `wicket-operator`, `wicket-node` and
`wicket-provisioner` binaries. `wicket-core` gets only `Surface::Infra` and the `money` effect.

```rust
// ---------- placement vocabulary (wicket-infra::placement, no I/O) ----------
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum IsolationLevel { Capability, Process, UserspaceKernel, Hardware, Remote }   // from 02 §11

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum SeparationLevel { Sandbox, Kernel, Host, Provider }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum AttestationLevel { None, ProviderApi, InstanceIdentity, Tpm, SevSnp, Tdx }

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub enum PlacementConstraint {
    IsolationAtLeast(IsolationLevel),
    Requires(HostFeature),                       // Kvm, Arch(Arch), Gpu{kind, count}, Snapshot(SnapshotKind)
    Region(BTreeSet<RegionId>), Residency(Jurisdiction),
    Provider { allow: BTreeSet<ProviderId>, deny: BTreeSet<ProviderId> },
    Separate { from: WorkloadSelector, at: SeparationLevel },
    Dedicated { tenant: PrincipalId },
    Colocate { with: WorkloadSelector, at: SeparationLevel, hard: bool },
    AttestationAtLeast(AttestationLevel),
    MaxCostPerHour(Usd), MaxLifetime(Duration),
}
pub struct Constrained { pub c: PlacementConstraint, pub provenance: Provenance /* OrgPolicy|Manifest|DerivedFromLabels|Grant */, pub weight: Option<i8> /* None = hard */ }

/// Compiles to a backend's primitives and explains the result. Pure.
pub trait PlacementCompiler {
    type Plan;                                   // k8s: pod spec fragments (RuntimeClass, affinity, tolerations); local: NodeChoice
    fn compile(&self, w: &WorkloadSpec, cs: &[Constrained], view: &CapacityView) -> Result<(Self::Plan, Explanation), Unsatisfiable>;
    /// Re-check an actual placement from wicket's own records (never the scheduler's say-so).
    fn verify(&self, w: &WorkloadSpec, cs: &[Constrained], actual: &Placement) -> Result<Explanation, Violation>;
}

// ---------- money and leases ----------
pub struct BillingModel {
    pub granule: Granule,                        // PerSecond{min: Duration} | PerStartedHour | PerMinute{min}
    pub line_rounding: Rounding,                 // UpToCent (Vultr) | None
    pub monthly_cap_hours: Option<u32>,          // Vultr 672
    pub stopped_bills: bool,                     // Vultr/Hetzner true; AWS/Azure-deallocated false
    pub setup_fee: Usd, pub min_lease: Duration, // Scaleway Mac: 24h
}
impl BillingModel { pub fn worst_case(&self, rate: UsdPerHour, life: Duration) -> Usd { /* ceil per granule, round per line */ } }

pub struct Lease {
    pub id: LeaseId, pub holder: Holder,         // Task(TaskId) | Pool(PoolId) | Wicket
    pub granted_until: Timestamp,                // snapped to the billing granule (minute 50 rule)
    pub max_until: Timestamp, pub renew_by: Timestamp,
    pub reservation: ReservationId,              // ledger money reservation (worst case)
}

// ---------- providers (wicket-provisioner; the only holder of cloud credentials) ----------
#[async_trait]
pub trait HostProvider: Send + Sync {
    fn id(&self) -> ProviderId;
    fn billing(&self, class: &HostClass) -> BillingModel;
    fn catalog(&self) -> &[HostClass];           // plan, region, rate, features {kvm, arch, gpu}, attestation level
    /// Idempotent by `intent`: ClientToken/requestId where supported, else tag + list-before-create.
    async fn create(&self, intent: &Intent, class: &HostClass, boot: &BootConfig /* cloud-init, join token */) -> Result<HostRef>;
    async fn get(&self, h: &HostRef) -> Result<Option<ObservedHost>>;
    async fn list_owned(&self) -> Result<Vec<ObservedHost>>;          // by owner tag only; never untagged
    async fn destroy(&self, h: &HostRef) -> Result<()>;               // refuses non-owned/protected tags
    async fn attest(&self, h: &HostRef, evidence: &NodeEvidence) -> Result<AttestationLevel>; // IID/JWT/provider-API check
    async fn charges_since(&self, t: Timestamp) -> Result<Vec<ChargeLine>>;                // daily money reconcile
}
// impls: VultrProvider (via the provisioning broker grants first), AwsProvider, GcpProvider, HetznerProvider, FlyProvider (Machines as hosts-of-one), LocalProvider (this host / a Mac)

// ---------- reconcilers (shared by kube-rs operator and local mode) ----------
pub trait Store<T>: Send + Sync { /* get/list/patch_status/finalize — impls: KubeStore (CRDs), SqliteStore (local) */ }

#[async_trait]
pub trait Reconciler: Send + Sync {
    type Desired; type Observed; type Action;
    async fn observe(&self, d: &Self::Desired) -> Result<Self::Observed>;
    fn plan(&self, d: &Self::Desired, o: &Self::Observed, now: Timestamp) -> Vec<Self::Action>;   // pure, property-tested
    async fn apply(&self, a: Self::Action) -> Result<()>;                                          // idempotent
    fn requeue_after(&self, d: &Self::Desired, o: &Self::Observed) -> Duration;
}
// HostReconciler (leases, pool, GC, dead-man), NodePoolReconciler, WorkloadReconciler, WarmPoolReconciler, MoneyReconciler
```

**CRDs** (spec is desired state; status carries observation, the explanation and lease state):

```rust
#[derive(CustomResource, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(group = "wicket.dev", version = "v1alpha1", kind = "NodePool", status = "NodePoolStatus")]
pub struct NodePoolSpec {
    pub provider: ProviderId, pub class: HostClassRef, pub region: RegionId,
    pub min: u32, pub max: u32,                  // max × rate × 672h = this pool's worst-case month; must fit the ledger budget
    pub features: Vec<HostFeature>, pub trust_class: TrustClass, pub data_class: Option<LabelSet>,
    pub mode: PoolMode,                          // ManagedK8s{vke|gke|eks pool id} | Provisioned{k3s agent join}
    pub idle_release: ReleasePolicy,             // pool-to-paid-hour vs destroy
}

#[derive(CustomResource, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(group = "wicket.dev", version = "v1alpha1", kind = "Workload", namespaced, status = "WorkloadStatus")]
pub struct WorkloadSpec {
    pub kind: WorkloadKind,                      // AgentSandbox | McpServer{digest, scope: PerTask|PerZone|Shared} | Codemode | Job
    pub zone: ZoneRef, pub task: Option<TaskRef>,
    pub image: ImageDigest, pub resources: Resources,
    pub constraints: Vec<Constrained>,
    pub launch: LaunchPath,                      // Direct{tier} (wicket-node, hot path) | Pod{runtime_class} | AgentSandbox{template} | Remote{provider}
    pub lease: LeaseRequest,                     // max lifetime; renewal by task heartbeat
}
pub struct WorkloadStatus { pub phase: Phase, pub placement: Option<Placement>, pub explanation: Explanation, pub lease: Option<Lease>, pub violations: Vec<Violation> }

#[derive(CustomResource, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(group = "wicket.dev", version = "v1alpha1", kind = "WarmPool", namespaced)]
pub struct WarmPoolSpec { pub image: ImageDigest, pub tier: IsolationLevel, pub source: WarmSource /* Unbound | PristineSnapshot */, pub target: u32, pub max: u32 }

/// Not a CRD: wicket-node's per-node capacity claim, realised as pause-image reservation pods
/// (CPU/mem incl. tier overhead) so the k8s scheduler/autoscaler see real load.
pub struct NodeReservation { pub node: NodeId, pub slots: Vec<SlotSpec>, pub overhead: Resources }
```

Invariants to property-test in M0-style:
- `plan()` never emits `destroy` for an unowned or protected resource.
- Sum of reservations ≤ the month cap after any action sequence.
- `verify(compile(x)) == Ok` for every satisfiable input.
- `separate` holds under any reschedule the compiler allows.
- Lease `granted_until` ≤ the paid-hour boundary for `PerStartedHour` models.

---

## 13. v1 scope (no KVM here, about $20/month)

| Step | Build | Where | Spend | Done when |
|---|---|---|---|---|
| **I0** | `wicket-infra` types: placement vocabulary, compiler for **local mode**, verifier, `Explanation`; `BillingModel` with Vultr/AWS/Hetzner/Fly data; `Lease`; ledger `money` effect with reservations | this box | $0 | property tests above; `wicket explain` shows a placement with provenance |
| **I1** | `wicket-node` (local): direct launch of process-jail and gVisor sandboxes, unbound warm pool + claim-then-bind, per-task MCP instance with stdio over the control channel, NodeReservation accounting. **Measure startup and RSS for each tier on this box** (replace §4.1's [L] rows) | this box, via the host's job-slot limits | $0 | agent sandbox ≤ 300 ms from the pool; MCP instance ≤ 250 ms to `tools/list` from the pool; numbers recorded |
| **I2** | `VultrProvider` *through provisioning-broker grants*; `HostReconciler` with intent tags, list-before-create, minute-50 leases, pool/release, GC; provider-API attestation; WireGuard + mTLS join of a second node | Vultr vc2/vhp in lhr | **~$1–3/mo** (a few box-hours at $0.014–0.02) | kill the control plane mid-create, and the reconciler adopts or destroys with no leak; the money reconcile matches `pending_charges` to the cent |
| **I3** | Kubernetes backend: `wicket-operator` (kube-rs) for `Workload`/`WarmPool`, reservation pods, Cilium default-deny, gVisor RuntimeClass; the optional `k8s-agent-sandbox` backend (pinned version, `Unmanaged` network policy) | **k3s on this box on demand** (≈ 1.6 GB, stopped when idle; agree with the host's operator first) | $0 | MCP pods A and B can't reach each other or the internet except via the proxy (tested); the operator can't read Secrets cluster-wide |
| **I4** | Firecracker tier and snapshot-clone with RNG reseeding | Mac M3+ (if available) **or** AWS c7i-flex.large nested in eu-west-2 | $0, or **~$0.10/h** (10 h ≈ $1) | snapshot restore of a pristine MCP server < 100 ms + page faults; clones get distinct RNG output |
| later | VKE/GKE multi-node; Fly and E2B capacity providers; SEV-SNP/TDX attestation; Biscuit for remote enforcement points; Hetzner/Latitude bare metal | | | |

**Not in v1:** cluster autoscaling (fixed pools), Karpenter, Cluster API, vCluster, hardware attestation,
Vultr bare metal (billing unresolved), HA control plane.

**Owner decisions this needs:**
1. Is an AWS account (or GCP) acceptable for minute-billed KVM, or is the Mac M3+?
2. May k3s run on the control host on demand (the host's operator)?
3. Should wicket's Vultr usage share the provisioning broker's $20 cap, or have its own line?

---

## 14. Risks and open questions

1. **Vultr bare-metal billing is contradictory** (the API says `invoice_type: monthly`, the docs say
   hourly). Resolve it from Vultr's docs or support before any purchase; buying blind risks $185. [H, both]
2. **Hetzner capacity:** every cloud plan was "currently unavailable" on 2026-11-08, and prices doubled for
   CPX/CCX in June. Don't depend on Hetzner Cloud. [H]
3. **Fly egress control is port-based only.** Whether "only reach a wicket proxy" can be enforced on Fly is
   untested. Until it is, Fly runs only workloads that need no egress at all. [H/M]
4. **No signed identity on Vultr, Hetzner or Fly.** Provider-API attestation is TOFU within a 15-minute
   window. A stolen join token plus a race could enrol a rogue node. Bind tokens to instance ID and IP, make
   them single-use, and alarm on any second attempt. [M]
5. **Kubernetes is a large TCB.** Every CVE in the API server, kubelet, containerd, Cilium or runc is now
   wicket's. Mitigations:
   - direct launch on the hot path;
   - gVisor or Kata everywhere hostile code runs;
   - no Secrets;
   - an admission policy pinning who can create pods. [H]
6. **agent-sandbox churn:** weekly releases with breaking changes on a `v1beta1` API. Pin exactly; run a
   conformance suite on upgrade. [H]
7. **The gVisor checkpoint/restore story is unsettled upstream.** The Sentry-reuse PR was rejected for
   security reasons. Measure runsc checkpoint/restore ourselves (M7), and never restore into a Sentry that
   ran another task. [H]
8. **Snapshot-clone uniqueness:** RNG, TLS state and UUIDs duplicated across clones. Reseed via VMGenID plus
   the guest shim. Never snapshot after binding identity. [H/M]
9. **KSM and dedup side channels across classes.** Keep them off, or within a class only. [L]
10. **The external dead-man reaper needs a second full Vultr key** (keys aren't scopable). Store it apart
    from the main one and IP-restrict it. [M/L]
11. **Startup numbers are mostly vendor claims or old.** I1 and I4 must produce wicket's own measurements
    before the budgets in §4.4 are treated as commitments. [—]
12. **LLM key placement in multi-host mode:** central LLM proxy (one key, extra hop) versus per-node derived
    keys. To be decided when multi-host lands. [L]

---

## Sources

Read 2026-11-08 unless stated otherwise.

**This machine and account [H]**
- Vultr API (read-only): `catalog_metal_plans_list`, `catalog_plans_list`, `account_pending_charges_list`,
  `kubernetes_versions_list`.
- The in-house broker script, its spend log and event logs.
- `ps` and `unshare` timings on the control host.

**Billing and providers**
- Vultr: https://docs.vultr.com/support/platform/billing/how-am-i-billed-for-my-servers (updated 2026-10-26)
- Vultr VKE: https://docs.vultr.com/support/products/vke/how-much-does-the-vultr-kubernetes-engine-cost
  · https://docs.vultr.com/support/products/vke/can-i-deploy-a-bare-metal-server-to-my-kubernetes-cluster
  · https://docs.vultr.com/products/compute/kubernetes/changelog.md
  · https://docs.vultr.com/support/products/vke/how-does-vultr-kubernetes-engine-handle-scaling
- Hetzner:
  - https://docs.hetzner.com/cloud/billing/faq/
  - https://www.hetzner.com/cloud/cost-optimized
  - https://www.hetzner.com/pressroom/standardization-and-price-adjustment-of-our-server-products/
  - https://www.hetzner.com/dedicated-rootserver/matrix-ax/
  - https://www.hetzner.com/sb/
- OVHcloud: https://www.ovhcloud.com/en-gb/public-cloud/prices/
- Scaleway: github.com/scaleway/docs-content (`pages/billing/faq.mdx`, `elastic-metal/faq.mdx`)
- Latitude.sh: https://www.latitude.sh/pricing · https://www.latitude.sh/locations ·
  https://www.latitude.sh/docs/api-reference/create-server
- Cherry Servers: https://www.cherryservers.com/pricing/dedicated-servers
- phoenixNAP: https://phoenixnap.com/kb/phoenixnap-bare-metal-cloud-billing-models
- AWS:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html
  - https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual
  - the AWS public price feed (2026-11-07)
  - API_RunInstances (`ClientToken`)
  - https://aws.amazon.com/eks/pricing/
- GCP:
  - https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview
  - https://cloud.google.com/compute/vm-instance-pricing
  - https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods
- Azure: prices.azure.com retail API · MicrosoftDocs/azure-compute-docs size pages ·
  https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch
- Fly.io:
  - https://docs.fly.io/about/pricing
  - https://docs.fly.io/machines/api/machines-resource
  - https://docs.fly.io/reference/suspend-resume/
  - https://docs.fly.io/machines/guides-examples/network-policies
  - https://docs.fly.io/security/tokens/
  - https://fly.io/blog/carving-the-scheduler-out-of-our-orchestrator/
- E2B / Modal / Daytona: https://e2b.dev/pricing · https://modal.com/pricing · https://www.daytona.io/pricing ·
  https://github.com/e2b-dev/infra
- Apple:
  - https://developer.apple.com/documentation/virtualization/vzgenericplatformconfiguration/isnestedvirtualizationenabled
  - https://github.com/apple/container/releases
  - https://www.apple.com/legal/sla/docs/macOSTahoe.pdf

**Kubernetes and control plane**
- https://github.com/kubernetes-sigs/agent-sandbox (releases; `api/v1beta1`; `extensions/api/v1beta1`)
- https://kubernetes.io/docs/concepts/containers/runtime-class/
- https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/
- https://kubernetes.io/docs/reference/access-authn-authz/node/
- https://kubernetes.io/docs/concepts/security/multi-tenancy/
- https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/
- https://www.kubernetes.dev/resources/keps/2008/ · https://www.kubernetes.dev/resources/keps/5823/
- https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/
- https://github.com/kubernetes/community (sig-scalability `slos/pod_startup_latency.md`)
- https://docs.k3s.io/reference/resource-profiling · https://docs.k3s.io/installation/requirements ·
  https://docs.k0sproject.io/stable/system-requirements/
- https://gvisor.dev/docs/architecture_guide/platforms/ · https://gvisor.dev/docs/user_guide/checkpoint_restore/ ·
  https://gvisor.dev/docs/user_guide/networking/
- Cilium:
  - https://docs.cilium.io/en/stable/security/policy/intro/
  - https://docs.cilium.io/en/stable/security/policy/layer3/
  - https://docs.cilium.io/en/stable/network/kubernetes/local-redirect-policy/
  - https://docs.cilium.io/en/stable/network/kubernetes/kata/
  - https://docs.cilium.io/en/stable/network/egress-gateway/egress-gateway/
- https://kubernetes.io/docs/concepts/services-networking/network-policies/
- https://github.com/kubernetes-sigs/karpenter · https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler/cloudprovider ·
  https://github.com/vultr/cluster-api-provider-vultr
- kube-rs: https://kube.rs/adopters/ · https://docs.rs/kube/latest/kube/runtime/index.html ·
  crates.io API for `kube`, `k8s-openapi`, `hcloud`, `vultr`, `aws-sdk-ec2`, `google-cloud-compute-v1`,
  `azure_mgmt_compute`, `boringtun`, `defguard_wireguard_rs`, `biscuit-auth`
- Nomad: https://developer.hashicorp.com/nomad/docs/job-specification/constraint ·
  https://github.com/hashicorp/nomad/blob/main/LICENSE
- https://github.com/loft-sh/vcluster · https://github.com/opencontainers/runc/security/advisories ·
  https://kubernetes.io/docs/reference/issues-security/official-cve-feed/
- Kata: https://github.com/kata-containers/kata-containers (releases; kata-deploy runtimeclasses) ·
  https://github.com/firecracker-microvm/firecracker-containerd

**Identity, attestation, tokens**
- AWS:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html
  - https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html
- GCP: https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations ·
  https://docs.cloud.google.com/compute/docs/instances/verifying-instance-identity
- Azure: https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-machine-options ·
  https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- SPIFFE/SPIRE: https://github.com/spiffe/spire/releases · https://github.com/spiffe/spire/tree/main/doc
- https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/ · https://tailscale.com/kb/1085/auth-keys ·
  https://github.com/juanfont/headscale/releases
- Biscuit: https://doc.biscuitsec.org/reference/specifications · https://www.biscuitsec.org/docs/guides/revocation/

**MCP**
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://github.com/supercorp-ai/supergateway · https://github.com/sparfenyuk/mcp-proxy ·
  https://docs.stacklok.com/toolhive/guides-cli/run-mcp-servers

**Startup and efficiency**
- Agache et al., "Firecracker", NSDI'20: https://www.usenix.org/system/files/nsdi20-paper-agache.pdf
- Firecracker `SPECIFICATION.md` and `docs/snapshotting/snapshot-support.md` (main)
- Ustiugov et al., REAP, ASPLOS'21: https://arxiv.org/abs/2101.09355
- Ao et al., FaaSnap, EuroSys'22: https://sysnet.ucsd.edu/~voelker/pubs/faasnap-eurosys22.pdf
- Brooker et al., "Restoring Uniqueness in MicroVM Snapshots" (2021): https://arxiv.org/abs/2102.12892
- Young et al., "The True Cost of Containing", HotCloud'19:
  https://www.usenix.org/system/files/hotcloud19-paper-young.pdf
- gVisor PR #12810 (2026-03, closed): https://github.com/google/gvisor/pull/12810
- https://modal.com/blog/mem-snapshots (2025-01-28)
- Li et al., RunD, ATC'22: https://www.usenix.org/system/files/atc22-li-zijun-rund.pdf
- Kuasar benchmark: https://github.com/kuasar-io/kuasar (`tests/benchmark/Benchmark.md`)
- CNI startup paper (2024): https://liu445126256.github.io/files/2024CNICMP.pdf
- Harter et al., Slacker, FAST'16
- https://bytecodealliance.org/articles/wasmtime-10-performance (2022-09-06)
- https://blog.cloudflare.com/cloud-computing-without-containers (2018-11-09)
- https://jvns.ca/blog/2022/06/28/some-notes-on-bubblewrap/ · https://www.redhat.com/en/blog/introduction-crun
- Google Cloud blog, Agent Sandbox on GKE (2026-05-21); InfoQ, GKE Pod Snapshots (2026-09-27)
- https://computesdk.com/benchmarks/sandboxes/burst-tti (undated)
- E2B persistence docs: https://docs.e2b.dev/sandbox/persistence
- https://developers.cloudflare.com/containers/faq
