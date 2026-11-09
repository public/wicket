# 07 — Open-source sandboxes and agent runtimes, read at source level

Research date: 2026-11-08. Scope: the **sandbox / agent-runtime** layer. That means process jails, gVisor, microVMs, hosted-sandbox infrastructure, and agent-runtime orchestrators. Each project is evaluated against `docs/design.md` (§3, §6, §7, §13) at the level of its code, not its README. Gateway, proxy and policy projects (agentgateway, MCP gateways, rama, Cedar) are covered in a separate study. They appear here only where a sandbox project embeds its own proxy.

**Method.**
- Each repo was shallow-cloned (`--depth 1`; `--filter=blob:none --sparse` for Codex, gVisor, Firecracker, OpenHands, cua and Daytona) into `refs/repos/<name>`.
- The repos were read only. Nothing was built, installed or run. `AGENTS.md`/`CLAUDE.md` files inside them were treated as data.
- Stars and releases come from `gh api` on 2026-11-08.
- Three readers split the corpus: srt, Codex, nono and httpjail (Part 1); the Linux jails, gVisor and container/K8s runtimes (Part 2); and the microVM and hosted projects (Part 3).
- Confidence: **H** means the code path was read; **M** means the docs plus key files were read, or the conclusion is inferred from code absence; **L** means it was not checked.
- Citations are `path:function` or `path` (line number) at the recorded commit.

**What changed relative to 01/02** (details in the synthesis):
1. **Codex's fd-passing network bridge** beats srt's in-box `socat` and should be wicket's process-tier attachment.
2. **srt's credential masking reflects secrets.** It substitutes into any header or body bound for an allowed host. Keep §8.1's strip-and-inject.
3. **Mount locking is the real process-tier boundary.** Codex lacks the nested-userns defence that srt and bwrap have, and hakoniwa never drops capabilities.
4. **Codex pins rama `=0.3.0-alpha.4`, not 0.4.**
5. **sandstorm** (Rust, Apache-2.0, gVisor-by-default because its hosts have no KVM) is the code to port for M7 parking.
6. **nono** (Rust, Apache-2.0, ~4.9k★, new in 2026) shows per-tool command sandboxes and runtime fd grants. It also shows why seccomp-notify cannot be the egress fence.
7. Almost every VM project runs its VMM **unjailed**.

## Inventory (commit SHAs and licences)

| name | local path | commit | date | licence |
|---|---|---|---|---|
| sandbox-runtime (srt) | refs/repos/sandbox-runtime | 27fce0dbd58925061c57eb8b38707b9a98349dad | 2026-11-06 | Apache-2.0 |
| codex (sparse) | refs/repos/codex | 748ab55ca7de0b647d9a7a9d9a8e70e00f28666d | 2026-11-08 | Apache-2.0 |
| nono | refs/repos/nono | e9796cca01eb863a9a83e96c18ae6120aa50beb1 | 2026-11-06 | Apache-2.0 |
| httpjail | refs/repos/httpjail | cb4cba2024dee9d8b1dc423eb20592a8f70ad4ae | 2026-11-04 | CC0-1.0 |
| hakoniwa | refs/repos/hakoniwa | d99c8f3a4400a3d196c0dd3d66e3824008274748 | 2026-11-08 | LGPL-3.0-only WITH linking exception (lib) / GPL-3.0 (CLI) |
| birdcage | refs/repos/birdcage | d0c625188385bbdb77bddd1a16408e7c20d22a9f | 2025-11-24 | GPL-3.0 |
| extrasafe | refs/repos/extrasafe | b56d18c8d7b337aa19fe5b14c8af51b68db00c13 | 2024-04-17 | MIT |
| nsjail | refs/repos/nsjail | d8415bc8eea43cdd413daba25af63127019a1189 | 2026-10-28 | Apache-2.0 |
| bubblewrap | refs/repos/bubblewrap | 1fb0aa26d3eb66254f7742e704add7f82f41a582 | 2026-10-14 | LGPL-2.1-or-later |
| rust-landlock | refs/repos/rust-landlock | 6a5413744f746cb471263b39234c06ea1b6cdf1b | 2026-10-21 | Apache-2.0 OR MIT |
| zerobox | refs/repos/zerobox | 9a7affd6c68fb2541c7c709559c40e08ba0a1872 | 2026-05-17 | Apache-2.0 |
| gvisor (sparse) | refs/repos/gvisor | 451b92800b9cb82262dc8a735388f7cf4d17d895 | 2026-11-07 | Apache-2.0 |
| agent-sandbox | refs/repos/agent-sandbox | 993fd4aa9f576b8374b8810ef45e7305ed2dd95d | 2026-11-07 | Apache-2.0 |
| container-use | refs/repos/container-use | 2e43e625e95216b719ec9338f4034fd3a0be2734 | 2026-08-12 | Apache-2.0 |
| toolhive | refs/repos/toolhive | 42cd9b7e497bfc77dc67a1e73037675247d405b1 | 2026-11-07 | Apache-2.0 |
| OpenHands (frontend only now) | refs/repos/OpenHands | cc99322a1efd0f4be8d6934ae93a4d1d4bc33e05 | 2026-11-08 | MIT |
| OpenHands software-agent-sdk (sparse) | refs/repos/openhands-sdk | e6569442a23951f852ead8514ae51dff1b377f37 | 2026-11-08 | MIT |
| SWE-ReX | refs/repos/SWE-ReX | 5c995c365dfb1fd5bc56fda688be5d8538f9931f | 2026-03-02 | MIT |
| microsandbox | refs/repos/microsandbox | 5da702c9ce96240505fca162b9e13a7f595b4f6d | 2026-11-08 | Apache-2.0 |
| microsandbox-mcp | refs/repos/microsandbox-mcp | 7fc2db60612a35eb55f6a9f5438d29f99effb8cd | 2026-11-01 | Apache-2.0 |
| libkrun | refs/repos/libkrun | 2fc56b5b6fcef00fc327768c8bbd692cf90b03df | 2026-11-05 | Apache-2.0 |
| firecracker (sparse) | refs/repos/firecracker | c774bddb8246b64daa7cae6d09d56194a07d7851 | 2026-11-06 | Apache-2.0 |
| fctools | refs/repos/fctools | c9862146c0c8d02903dded6bd14850c2a8727cb6 | 2026-05-11 | MIT |
| sandstorm | refs/repos/sandstorm | d27ab7c452126e3b34987b84d3c72cb41fc3fd16 | 2026-11-02 | Apache-2.0 |
| gondolin | refs/repos/gondolin | 5fec2d0df3e58c801498a8c661b14be76c5d1450 | 2026-11-05 | Apache-2.0 |
| E2B (SDK) | refs/repos/E2B | 2d7eb43dfe09215abbdf611abbdacc0c68998977 | 2026-11-06 | Apache-2.0 |
| e2b-infra (now e2b-dev/runtime) | refs/repos/e2b-infra | 7a1781a632b7711185c67247e20dd64c9641dc0e | 2026-11-08 | Apache-2.0 |
| daytona (tag v0.190.0, sparse) | refs/repos/daytona | 01c502bb1f1ff8f2885d0cd490e043736083dca8 | 2026-06 | AGPL-3.0 |
| pullrun | refs/repos/pullrun | 0b0ce94c5f56ebed8416167e4ca91e62c0eacd74 | 2026-11-07 | Apache-2.0 (workspace says MIT OR Apache-2.0) |
| arrakis | refs/repos/arrakis | 877231496acbf3b3091ab33340d2d126a251c4d5 | 2025-06-02 | AGPL-3.0 |
| cua (sparse: lume) | refs/repos/cua | a90b916a5f136eafdc6cf314326768b1587567c1 | 2026-11-08 | MIT |

Not found or not public: `fctools` exists only as `rust-firecracker/fctools` (above). Daytona's `main` is emptied: core development went private in June 2026, and the last public code is tag v0.190.0. Modal's open parts (`modal-labs/modal-client`) are an SDK with no sandbox internals, so I skipped them.

---

## Part 1 — The two reference implementations (srt, Codex) and the two newest Rust/CC0 entrants (nono, httpjail)

### sandbox-runtime (`srt`) — Anthropic's process sandbox, MITM proxy, credential masking and external-decider proxy (https://github.com/anthropic-experimental/sandbox-runtime, now redirects to `anthropics/sandbox-runtime`; Apache-2.0, commit 27fce0dbd589, v0.0.81 2026-10-20)

- **Basics.** Local path `refs/repos/sandbox-runtime`. TypeScript on Node ≥22.12 or Bun ≥1.4, with C helpers (`vendor/seccomp-src/`) and a Rust Windows helper (`vendor/srt-win-src/`). About 7.0k stars; "beta research preview"; it is the sandbox under Claude Code's `/sandbox`. About 65k lines, most of them in `sandbox-manager.ts` (3.9k), `linux-sandbox-utils.ts` (3.9k), `http-proxy.ts` and `tls-terminate-proxy.ts` (1.5k each).
- **Linux sandbox, as implemented** (`src/sandbox/linux-sandbox-utils.ts:wrapCommandWithSandboxLinux`). It builds one `bwrap` command line:
  - `--new-session --die-with-parent` (TIOCSTI defence; no orphaned jails).
  - Environment: `--unsetenv` for denied credential vars, then `--setenv NAME <sentinel>` for masked ones. bwrap applies env operations in argument order, so the proxy variables set later cannot be clobbered by a caller-chosen name.
  - Network: `--unshare-net` (no interfaces at all). The host HTTP and SOCKS proxies listen on UNIX sockets that are `--bind`-mounted in. `buildSandboxCommand` starts two in-box `socat` listeners on `127.0.0.1:3128` and `:1080` *before* seccomp is applied, and points `HTTP(S)_PROXY`/`ALL_PROXY` at them. A Java agent jar is injected via `JAVA_TOOL_OPTIONS` because JVMs ignore proxy env vars.
  - Filesystem: `generateFilesystemArgs` does `--ro-bind / /`, `--bind` for writable roots, then re-`--ro-bind`s "dangerous" paths. `DANGEROUS_FILES` (`sandbox-utils.ts`) is `.gitconfig .gitmodules .bashrc .bash_profile .zshrc .zprofile .profile .ripgreprc .mcp.json`, plus the dirs `.vscode .idea`, plus `.git/hooks`, `.git/HEAD` and `.git/config`. These are found by running `rg --files --hidden --iglob …` **at launch, to depth 3** (`linuxGetMandatoryDenyPaths`). A symlink or missing component in a protected path gets `/dev/null` mounted on it.
  - `--unshare-pid --proc /proc`, `--unshare-user`, `--cap-drop ALL` (`capabilityArgs`), `--dev /dev`.
  - The command is wrapped in **`apply-seccomp`** (`vendor/seccomp-src/apply-seccomp.c`). That helper creates a *nested* user+PID+mount namespace (so the agent cannot see or ptrace bwrap's init or socat), sets `PR_SET_DUMPABLE=0`, writes `user.max_user_namespaces=0` in its own userns, and installs two stacked BPF filters generated by `seccomp-unix-block.c`:
    - `unix`: `socket(AF_UNIX)` and `socket(AF_VSOCK)` → EPERM (32-bit masked compare, because the kernel ignores the upper half of an int argument); `io_uring_setup/enter/register` → EPERM. Comment: "the network namespace does not fence VM sockets". There is no `socketpair` rule, so related processes can still talk.
    - `namespaces`: `unshare` and `clone` with `CLONE_NEWUSER|CLONE_NEWNS` (and Linux 7.1's `UNSHARE_EMPTY_MNTNS`) → EPERM; **`clone3` → ENOSYS** so libc falls back to `clone`, whose flags BPF can read; `setns mount umount2 pivot_root open_tree move_mount fsopen fsconfig fsmount fspick mount_setattr open_tree_attr` → EPERM. Rules are added with `seccomp_rule_add_exact`, and the generator *fails* rather than silently skipping a syscall libseccomp cannot name.
  - The rationale is spelled out at `NESTED_USERNS_ENV`: a read-only bind protects a path only in its own mount namespace. A fresh user namespace needs no capability, gives full caps over a private copy of the mount tree, and lets the binds be detached together, after which a directory fd opened earlier reaches the denied names.
  - Optional observation (`SRT_OBSERVE_SOCK`): a third filter traps write-intent FS syscalls to `SECCOMP_RET_USER_NOTIF`, and the outer stub answers `FLAG_CONTINUE` and logs paths read with `process_vm_readv`. The code says explicitly that this is fail-open and a hint only, "must never gate a policy decision".
- **Proxy, MITM and credentials.**
  - `tls-terminate-proxy.ts` and `mitm-ca.ts` terminate TLS with a supplied or ephemeral CA. Leaf certificates share one key (a cache of 256 names). `excludeDomains` tunnels pinned hosts opaquely.
  - `resolved-address-guard.ts` resolves each allowed name once, drops loopback, `0.0.0.0/8`, `::`, link-local, multicast, broadcast, the host's own interface addresses and a list of cloud-metadata IPs outside link-local (Azure `168.63.129.16`, Alibaba `100.100.100.200`, AWS `fd00:ec2::/32`, GCP, OCI, Scaleway, Linode), then dials the surviving address. **RFC1918, ULA and CGNAT are *not* denied by default in full-sandbox mode** (opt-in via `network.deniedResolvedAddresses`); proxy-only mode does deny them.
  - **Credential masking** (`credential-sentinel.ts:SentinelRegistry`). The sentinel is `fake_value_<uuid4>`, padded with random characters to the real value's byte length so `Content-Length` stays unchanged. It is minted per credential *name*, so two vars with the same secret get different sentinels, each with its own `injectHosts`. `substituteInHeaders` scans **every header value**, and `body-substitution.ts:createBodySubstitutionTransform` streams sentinel→real replacement through **request bodies** with a hold-back window across chunks, all gated only on "destination host ∈ this credential's injectHosts". There is also JWT-shaped fakes (`credential-decode.ts`), AWS SigV4 re-signing (`aws-sigv4.ts`, `credential-aws-pairs.ts`) and masked *files* (`credential-mask-files.ts`).
  - `--control-fd` gives live policy updates (network lists apply on the next connection).
- **`srt proxy` and the decider protocol** (`docs/srt-proxy.md`, `src/proxy-main.ts`, `src/sandbox/decider-client.ts`, `proxy-only.ts`, `request-filter.ts`):
  - All resources are inherited fds: `--listen-fd`, `--decider-fd` (or an in/out pair), `--lifeline-fd`, `--ca-fd`. Every CONNECT is TLS-terminated; opaque tunnels are refused (`opaque_tunnel`).
  - Frames are a 4-byte BE length plus one strict JSON object. Duplicate keys, nulls, unknown fields, *empty optional fields*, non-lowercase header names and control characters all kill the link.
  - Hello carries the allow/deny domain lists, which the proxy checks before asking. `req` carries `{id, method, host, port, hostHeader, sni, path, query, headers}`, with **`path` and `query` "as the client spelled it"**. Verdicts are `allow{setHeaders, removeHeaders, cred, credential}`, `deny{status, reason}` and `need_body{max ≤32 MiB}` (one per request).
  - `cred` strips every client credential header (`authorization`, `proxy-authorization`, `cookie`, `x-api-key`, with names folded across `-` `_` `.`) before placing the value. Framing headers cannot be set. Header sets on plaintext HTTP are refused unless `--plaintext-header-set`. TRACE/TRACK get 405 because they echo credentials. A body on GET/HEAD/OPTIONS under `need_body` is refused.
  - Fail closed: a 5 s timer per verdict gives 503; any protocol violation kills the link and the proxy exits. Nothing is resolved or dialled before an allow.
  - Refusals carry `X-Deny-Reason` codes (`host_not_allowed`, `decider`, `decider_unavailable`, `misdirected` (Host/SNI ≠ target), `address_not_allowed`, …).
- **How denials surface.** Plain 403 with `X-Deny-Reason`, or the decider's own status and reason. The full sandbox also has an `ask` callback `({host, port}) → true | {allow:false, reason}`; only a literal `true` allows (`sandbox-manager.ts`, around l.840).
- **Bugs, gaps and risks.**
  1. **Reflection leak in credential masking.** Substitution into *any* header and *any* body bound for an injectHost means an agent can put the sentinel into a field the upstream stores or echoes: an issue body or comment, a gist, a commit message via the API, a request-echo or error endpoint. The real secret is then written to the provider or returned into the box. The module's "fail-safe direction" comment only covers *missed* substitutions. This is the exact reason wicket's §8.1 says "strip all client auth, inject only the adapter-declared header". The `srt proxy` decider path (`cred` → one auth header) does not have this problem; the full-sandbox `credentials.mask` path does.
  2. **Fail-open when the seccomp helper is missing.** If `apply-seccomp` cannot be resolved, it logs a warning and continues without the AF_UNIX/vsock/io_uring/namespace filters (`resolveApplySeccompPrefix` branch). A netns does not fence pathname UNIX sockets, so the agent can then connect to any host socket visible in the bound filesystem (`/run/user/<uid>/bus`, a Docker or Podman socket, wicketd's own sockets). Similarly, without the helper and with bwrap < 0.8 there is no `--disable-userns`, and only a warning.
  3. **Launch-time deny scan.** Dangerous paths are found once at launch and to depth 3. A `.git` created later (a fresh `git clone` inside the workdir), or one deeper than 3, is writable, so hooks planted there run the next time a human or the harness runs git on the host. That is TOCTOU by design.
  4. **Same UID as the user**, with no per-sandbox UID. Everything reachable read-only under `--ro-bind / /` (`~/.ssh`, `~/.aws` unless denied) is readable by default.
  5. **RFC1918 allowed by default** in the full sandbox (see above), which matters on a Vultr VPC.
  6. 32-bit `socketcall` is not filtered (documented TODO; x86-32 is unsupported).
- **For wicket.**
  - **REUSE (Apache-2.0):**
    - Run `srt proxy` unmodified as the *differential reference* for `wicket-egress` in tests (design §3.1 already says this), using only the decider path, not `credentials.mask`.
    - Port to Rust (re-implementing, citing the source): `seccomp-unix-block.c:add_namespace_rules` (the rule list and the `clone3→ENOSYS` trick) and `apply-seccomp.c`'s nested PID+mount namespace layout.
  - **BORROW:**
    - The decider protocol's strictness rules verbatim for wicket's proxy↔engine seam (no empty optionals, duplicate keys or nulls; one `need_body`; ids increase; fail closed on any violation).
    - The refusal-code vocabulary.
    - The `cred` semantics (strip every client credential spelling, then place one).
    - `TRACE`/`TRACK` refusal.
    - Bodyless-method-with-body refusal.
    - The plaintext-header-set refusal.
    - The cloud-metadata list in `resolved-address-guard.ts` (add Vultr's `169.254.169.254`, already covered by link-local).
    - Sentinel hygiene: per-name sentinels, length matching.
  - **AVOID:**
    - Body and arbitrary-header substitution.
    - The in-box `socat` (Codex's fd-passing bridge is better, see below).
    - Warn-and-continue on missing hardening.
    - Launch-time-only path scans. Use overlay plus host-side extract-time checks instead (design §7 "Workdir and output").
  - **design.md implications:**
    - §3.1: keep the srt decider seam, but note that `path` arrives *as spelled*. wicket's canonicalize-or-reject must happen inside the decider (or in `wicket-egress` before the frame). Prefix matching on the raw path is the classic bypass.
    - §8.1: add "TRACE/TRACK refused; a body on bodyless methods refused; framing headers immutable".
    - §6.1 conformance check 2 ("no real credential findable") should add a **reflection test**: send the placeholder in a body to an allowed echoing endpoint and assert the real value never leaves the proxy.
- **Confidence:** H (code and protocol doc read; reflection risk is a direct reading of `substituteInHeaders` and `sentinelsForHost`, not tested).

### Codex (`codex-rs`) — linux-sandbox, sandboxing, network-proxy, execpolicy, app-server protocol (https://github.com/openai/codex, Apache-2.0, commit 748ab55ca7de, rust-v0.167.0 2026-11-06)

- **Basics.** Local path `refs/repos/codex`, sparse checkout: `codex-rs/{linux-sandbox,sandboxing,network-proxy,execpolicy,execpolicy-legacy,app-server-protocol,process-hardening,windows-sandbox-rs,arg0,core/src/sandboxing}`. Rust. About 134k stars; releases several times a week.
- **Crates are workspace-internal (`version = "0.0.0"`) and not usable as dependencies.** `codex-linux-sandbox` depends on `codex-protocol`, `codex-network-proxy`, `codex-sandboxing`, `codex-uds`, `codex-process-hardening`, `codex-install-context`, and in tests on `codex-core`. `codex-sandboxing` also pulls in `codex-mxc-sandbox`, `codex-windows-sandbox`, `codex-utils-pty` and `codex-otel`. **Reuse means copying files at a pinned SHA**, which zerobox shows is feasible (Part 2).
- **linux-sandbox, as implemented.**
  - `bwrap.rs:create_bwrap_flags*`: `--new-session --die-with-parent`, `--ro-bind / /` (or a minimal platform set), `--bind` for writable roots, re-`--ro-bind` of protected subpaths (`.git`, the resolved `gitdir:` target, `.codex`), path-specificity ordering for split policies, deny globs expanded with `rg` before launch, `/dev/null` on symlinks or missing components. Then `--unshare-user --unshare-ipc --unshare-pid [--unshare-net] --proc /proc --cap-drop ALL`. `launcher.rs` adds `--as-pid-1` when supported. It prefers the system `bwrap` from `PATH` *outside the cwd* and falls back to a bundled one (`bundled_bwrap.rs`).
  - `seccomp.rs:install_network_seccomp_filter_on_current_thread` (seccompiler, default Allow, match → EPERM, x86_64/aarch64 only), installed *after* the mount view is built, after `PR_SET_NO_NEW_PRIVS`:
    - all modes: `io_uring_setup/enter/register`; non-vsock modes also `ptrace`, `process_vm_readv` and `process_vm_writev`;
    - `Restricted`: `connect accept accept4 bind listen getpeername getsockname shutdown sendto sendmmsg recvmmsg getsockopt setsockopt`, and `socket`/`socketpair` for anything but `AF_UNIX`;
    - **`ProxyRouted`: `socket` allowed only for `AF_INET`/`AF_INET6`** (an allowlist, unlike srt's denylist), and `socketpair` only for `AF_UNIX`;
    - `VmSocketRestricted`: `AF_VSOCK` denied.
  - The legacy Landlock path (`install_filesystem_landlock_rules_on_current_thread`) uses `ABI::V5` with `CompatLevel::BestEffort` and errors only on `NotEnforced`, so it accepts `PartiallyEnforced`. It is rejected for FS-restricted policies "because it cannot isolate app-server Unix sockets". **Neither Codex's nor srt's mainline Linux path uses Landlock**: both rely on the bwrap mount namespace.
  - **`proxy_routing.rs`, the fd-passing bridge (the key find).**
    1. *Outside* the netns, `prepare_host_proxy_route_spec` forks one **host bridge** process per proxy endpoint (`spawn_host_bridge`) and keeps a socketpair control channel above stdio.
    2. *Inside* the new netns, after bringing `lo` up (`ensure_loopback_interface_up`), `activate_proxy_routes_in_netns` binds a TCP listener on `127.0.0.1:0` *in the sandbox netns* and **sends the listening socket fd over the socketpair (SCM_RIGHTS) to the host bridge**. It then rewrites `HTTP(S)_PROXY`, `WS(S)_PROXY`, `ALL_PROXY`, npm, yarn, bundler, pip and docker proxy vars to that port, closes its own copies, and execs the agent.
    3. The host bridge `accept()`s on that listener. "The socket keeps its isolated network namespace even though we accept in the host process; newly opened upstream sockets use our host namespace". It `connect()`s to the real proxy and writes an **attribution frame** first (`write_attribution_frame`), so the proxy knows which exec this is.
    4. No process runs inside the box to forward traffic, no socket file is bind-mounted, and seccomp can then forbid every new `AF_UNIX` socket.
  - `process-hardening/src/lib.rs:pre_main_hardening_linux`: `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, strips `LD_*`. On macOS: `PT_DENY_ATTACH` and strips `DYLD_*`.
- **Seatbelt** (`sandboxing/src/seatbelt_base_policy.sbpl`, `seatbelt_network_policy.sbpl`, `seatbelt.rs`): starts with `(deny default)`, based on Chromium's renderer policy. Proxy allow rules are injected at runtime, and there is a separate read-only platform-defaults file.
- **network-proxy** (`codex-rs/network-proxy`, about 25k lines):
  - **rama pinned at `=0.3.0-alpha.4`** (`rama-core`, `-http`, `-http-backend`, `-net`, `-socks5`, `-tcp`, `-tls-rustls`, `-unix`, `-dns`), not 0.4.
  - HTTP proxy, SOCKS5 (with UDP), and a "limited" mode (GET/HEAD/OPTIONS only, which forces MITM). `x-proxy-error: blocked-by-{allowlist,denylist,method-policy,policy}`.
  - `NetworkPolicyDecider` hook: the embedding app can override *allowlist misses only*; explicit denies still win. OTEL `codex.network_proxy.policy_decision` events.
  - **MITM CA** (`certs.rs:generate_ca`): ECDSA P-256, `BasicConstraints::Unconstrained`, **no name constraints**. The key stays in memory; the cert goes to `$CODEX_HOME/proxy/` for the child CA env vars.
  - **`mitm_hook.rs`**: hooks match `{host, schemes, ports, methods, path_prefixes (literal or glob), query (single value only: "origins disagree on which occurrence wins"), headers, body}`. Actions are `strip_request_headers`, `inject_request_headers{placeholder?, name, secret_env_var | secret_file, prefix}` ("replace exactly this entire guest header value; requires HTTPS on 443"), `body_secret_substitution` and `aws_sigv4`. **`authorization_path.rs:is_safe_for_authorization` rejects any path segment that is `.`/`..` in literal or percent-encoded form, or that contains `\` or `;`, before a hook can match.** That is reject-not-normalise, the same principle as wicket §8.1.
  - **`credential_broker/`**: discovers real credentials in the parent env (`providers/github.rs` knows `GH_TOKEN`/`GITHUB_TOKEN` and the `ghp_ gho_ ghu_ ghs_ ghr_ github_pat_` prefixes; `providers/openai.rs`) and replaces them in the child env with **shape-preserving dummies** (`shaped_dummy_value`: same prefix and length, so client-side validators accept them). `select_credentials` translates only the provider's own auth header for a matching host binding, and drops ambiguous matches. `CredentialMaskingFailureMode::{Warn, Deny, Error}` controls what happens when a raw credential would leak into the child env.
- **execpolicy** (`execpolicy/`, Starlark subset): `prefix_rule(pattern=[…], decision=allow|prompt|forbidden, justification, match=[…], not_match=[…])` plus `host_executable(name, paths)`. **`match`/`not_match` examples are validated at load time as unit tests.** `amend.rs` appends approved rules, which is the learning loop.
- **app-server protocol** (`app-server-protocol/src/protocol/v2/permissions.rs`, `common.rs`): server→client requests `item/commandExecution/requestApproval`, `item/fileChange/requestApproval` and **`item/permissions/requestApproval`**. The last carries `PermissionsRequestApprovalParams {thread_id, turn_id, item_id, environment_id, started_at_ms, cwd, reason, permissions: {network:{enabled}, file_system:{entries}}}` and is answered with `{permissions: GrantedPermissionProfile, scope: Turn|Session, strict_auto_review}`. The grant can be narrower than the request, and `NetworkApprovalContext {host, protocol: http|https|socks5Tcp|socks5Udp}` ties a proxy miss to an approval. It also carries `ExecPolicyAmendment` and `NetworkPolicyAmendment{host, allow|deny}`. JSON Schema and TS types are generated (`export.rs`, `schema_fixtures.rs`).
- **Bugs, gaps and risks.**
  1. **No nested-userns defence.** The checkout has no `max_user_namespaces`, `--disable-userns` or seccomp rule for `unshare`/`setns`/`mount`/`clone3`. The bwrap invocation drops caps but does not stop a sandboxed process creating a fresh user and mount namespace. srt documents exactly that as the way to detach read-only binds and reach `.git/hooks` through a pre-opened fd (`linux-sandbox-utils.ts`, `NESTED_USERNS_ENV`). [M: inferred from code absence plus srt's analysis; not tested. It may be mitigated by host `max_user_namespaces` settings.]
  2. MITM CA without name constraints.
  3. The legacy Landlock path accepts partial enforcement.
  4. The launch-time `rg` scan for protected paths has the same TOCTOU as srt's.
  5. `inject_request_headers` with `placeholder: None` injects whenever the hook matches, whatever the guest sent. That is correct for strip-and-inject but must be paired with `strip_request_headers`.
- **For wicket.**
  - **REUSE (copy at a pinned SHA, Apache-2.0, NOTICE attribution):**
    - `linux-sandbox/src/proxy_routing.rs` (fd-passing bridge);
    - `linux-sandbox/src/seccomp.rs` (`ProxyRouted` allowlist filter);
    - `network-proxy/src/authorization_path.rs`;
    - the mount-ordering logic in `bwrap.rs` (as a spec for wicket-jail's own mount planner, since wicket builds mounts itself);
    - `process-hardening` (small enough to inline).
  - Do **not** take `network-proxy` wholesale: it is 25k lines bound to `codex-core` config types and an older rama.
  - **BORROW:**
    - (a) The listener-fd handoff as **wicket's process-tier network attachment** (see synthesis).
    - (b) The attribution frame (one per host-side bridge), which becomes the transport identity of principle 2.
    - (c) Shape-preserving placeholders (prefix and length), so `gh`, the AWS SDK and the Anthropic SDK don't reject the token locally.
    - (d) Single-valued query constraints.
    - (e) `match`/`not_match` examples-as-tests for **adapter rules** (§9: each endpoint rule carries positive and negative requests checked at load).
    - (f) The app-server `permissions/requestApproval` shape (typed ask, narrower grant, scope) as a model for `wicket.request_access`.
  - **AVOID:** execpolicy as enforcement. It runs inside the agent and is UX, matching principle 1.
  - **design.md implications:**
    - **§8.1 says "`rama` 0.4, pinned exactly as Codex does". Codex pins `=0.3.0-alpha.4`.** Either pin 0.4 on wicket's own judgement or follow Codex; the precedent is not what the text claims. (The gateway/proxy study covers rama itself.)
    - §6 tier table: **Codex should be driven through `codex app-server` (JSON-RPC, generated schema), not only through `codex-acp`.** It has a native held-open `permissions/requestApproval` with a narrower-grant response and a network-approval context fed by its own proxy. That is a T1-grade pending path for Codex in E1.
    - §7 row 1: "Codex `linux-sandbox` and `srt` are the reference code". Correct, but take the namespace-escape filter from srt and bwrap, since Codex lacks it.
- **Confidence:** H for linux-sandbox, seccomp, proxy_routing, mitm_hook, credential broker selection and the protocol types. M for the nested-userns exposure.

### nono — unprivileged Landlock/Seatbelt capability sandbox with an out-of-box supervisor, credential proxy and per-tool command sandboxes (https://github.com/nolabs-ai/nono, Apache-2.0, commit e9796cca01eb, v0.81.0 2026-10-29)

- **Basics.** Local path `refs/repos/nono`. Rust (edition 2024, MSRV 1.95). About 4.9k stars; repo created 2026-01-31; very active, pre-1.0. Built by the Sigstore team. Crates: `nono` (library: sandbox, capability, supervisor, keystore, undo, trust, audit), `nono-proxy` (credential and L7 proxy), `nono-cli` (243k lines in the workspace), plus C bindings. It was not in the earlier research.
- **Architecture as implemented.**
  - **Linux** (`crates/nono/src/sandbox/linux.rs`, 6.9k lines): Landlock is primary.
    - `detect_abi` probes candidates. `apply_with_abi_inner` builds the FS rules from `CapabilitySet` and opens each path rule by fd (`open_path_rule`). It refuses unsupported filesystems (`fs_type_unsupported`), adds `Scope::{AbstractUnixSocket, Signal}` on ABI ≥6, and on ABI ≥4 adds `AccessNet` TCP-port rules.
    - `restrict_execute` requires `FullyEnforced` (`ensure_execute_restriction_fully_enforced`).
    - Seccomp is hand-written BPF with an arch guard. Variants: `block_network` (16 insns), `tcp_only` (29), and a **USER_NOTIF proxy filter** (`build_seccomp_proxy_filter`): `socket` allowed only for AF_UNIX, INET and INET6; `socketpair` only AF_UNIX; `connect`, `bind`, `sendto`, `sendmsg` and `sendmmsg` all go to `SECCOMP_RET_USER_NOTIF`; `io_uring_*` → EPERM.
    - Optional namespaces (`linux_namespace.rs`): user+net(+ipc, uts) with a loopback bridge listener, chosen via `linux.isolate.network`. They are **not the default**: the selling point is "unprivileged, zero setup".
  - **Supervisor** (`nono-cli/src/exec_strategy/supervisor_linux.rs`, 3.5k lines): runs outside the sandbox as the user. `decide_network_notification` reads the sockaddr from the child with `read_notif_sockaddr` (`process_vm_readv`). It allows loopback connects to the proxy port or granted ports, mediates pathname AF_UNIX against a socket allowlist (abstract and unnamed sockets are denied), and asks an approval backend for unlisted sockets. Allowed calls are answered **`continue_notif` (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`)**. Runtime file grants use `inject_fd` (`SECCOMP_IOCTL_NOTIF_ADDFD`): the supervisor opens the approved file itself and installs the fd in the child.
  - **Command mediation / tool sandbox** (`nono-cli/src/tool-sandbox/*`, `docs/cli/internals/security-model.mdx`): shims for chosen commands (`gh`, `git`, `kubectl`, `aws`, `curl`) send the invocation to the supervisor. The supervisor resolves a *command policy* and runs the tool in a **fresh command sandbox** with its own FS, network, env, credential and resource grants. Their example: "the `aws` CLI can use a credential, but `curl` can't". Chained commands cross the broker again.
  - **Proxy** (`crates/nono-proxy`): CONNECT and reverse proxy, TLS interception with an h2 forwarder (`tls_intercept/h2_forward.rs`, 3k lines), routes with method and path rules (`route.rs`), **phantom tokens** (`token.rs`: `nono_<64hex>` nonces resolved per consumer `proxy.<route_id>`, constant-time compare, `Zeroizing`), OAuth capture and rewrite, SPIFFE, AWS, rate limits.
  - **Approval webhook protocol v1** (`docs/protocols/approval-webhook-v1.md`): one blocking POST (unsigned), or submit-then-poll with an enrolled key (signed). Timeouts and errors mean deny. A **Unix-socket transport** exists because "a sandboxed child that may listen on TCP ports … can take a loopback port over … and then answer every approval itself", and nono refuses to launch if the sandbox could write the socket path or any parent directory.
  - Also: Sigstore attestation of skills, hooks and instruction files (`trust/`), a tamper-evident audit log, and FS "undo" snapshots (`undo/snapshot.rs`).
- **Bugs, gaps and risks.**
  1. **USER_NOTIF + CONTINUE is TOCTOU for pointer arguments.** The sockaddr is read from child memory and the original syscall then proceeds with whatever the memory holds at that moment. A second thread can swap a loopback proxy address for an external one between the check and the kernel's own copy. The kernel's `seccomp_unotify(2)` warns that CONTINUE must not be used for security decisions. nono's own comments carry "TOCTOU Warning" blocks (`linux.rs`, l.2577, 2694, 3811), and `notif_id_valid` does not close this hole.
     - In the default (no-netns) mode, the remaining fences against direct egress are Landlock ABI ≥4's `CONNECT_TCP` *port* rule, which cannot restrict the address, plus this racy check. So an agent can probably reach an *external* host on the proxy's port number, and UDP is unrestricted before ABI 10. [M: from reading, not tested.]
     - With `linux.isolate.network` the netns removes the route and the race no longer matters.
  2. The supervisor runs as the invoking user, so it is the same UID as the box. nono documents this as a TCB assumption.
  3. Command mediation relies on shims on `PATH`. A direct exec of the real binary is blocked only if Landlock execute rules forbid it (`restrict_execute`), which is not universal.
- **For wicket.**
  - **REUSE:** read-only for now. Apache-2.0 permits vendoring, but the crates are fast-moving and pre-1.0.
  - **BORROW:**
    - (a) **Tool-scoped credentials.** The narrowest credential holder is *one tool invocation in its own sandbox*, not the agent's box. For wicket this means gateway-native tools that wrap CLIs (`gh pr create`) run in a fresh per-call tool sandbox with the real token injected at *its* egress. The agent's own box holds nothing. That is the same shape as §8.2 kind 2, applied to CLIs.
    - (b) **ADDFD-based runtime FS grants**: on an approved FS escalation, wicket-jail's supervisor opens the file and injects the fd, so the agent never resolves the path itself, with no TOCTOU and no restart. This could become `Instance::grant_fd` in §7.
    - (c) Phantom tokens resolved *per consumer* (route), not per host.
    - (d) The approval-webhook contract (blocking or submit-then-poll; timeout means deny) and, above all, its rule that **no approval or decision socket may be reachable or replaceable from the box**. That rule also belongs in wicket's conformance suite.
    - (e) `ensure_*_fully_enforced`.
  - **AVOID:** seccomp-notify + CONTINUE as an egress control. That backs up design §7's choice of a no-interface netns.
  - **design.md:**
    - §8.2: add a fourth tool kind, **"CLI-wrapping tools"** (per-call tool sandbox).
    - §10 human channel: borrow nono's signed submit-then-poll shape for the later web UI.
- **Confidence:** M-H. I read the sandbox, supervisor-decision, token and protocol code and docs; not the whole CLI.

### httpjail — per-process HTTP(S) filter with JS/shell/external-process rule engines (https://github.com/coder/httpjail, CC0-1.0, commit cb4cba2024de, v0.6.2 2026-09-24)

- **Basics.** Local path `refs/repos/httpjail`. Rust (about 9.5k lines). About 960 stars; Coder; active.
- **Architecture.**
  - "Strong" Linux mode (`src/jail/linux/mod.rs`) requires sudo and refuses to run as real root without `SUDO_UID` ("so the command cannot alter its own network policy"). It creates a named netns and a veth pair with a per-jail /30-style subnet (`compute_subnet_for_jail`) using the `ip` CLI, then applies **two nftables tables via `nft -f -`** (`nftables.rs`):
    - in the netns: `nat output` DNATs TCP 80 and 443 to the host proxy ports; `filter output policy drop` allows established traffic, UDP 53 to the host IP and the proxy ports, drops other UDP and TCP; and an `ip6` table drops everything except `lo`;
    - on the host: masquerade, forward accept for the subnet, and an input accept from the veth.
  - It runs the command with `ip netns exec <ns> unshare --pid --fork --kill-child=SIGKILL --mount-proc setpriv --no-new-privs --reuid --regid --clear-groups`.
  - `seccomp.rs` (hand BPF): kills x32 and wrong-arch calls; `socket` only for INET, INET6 and NETLINK; `socketpair` only `AF_UNIX/SOCK_STREAM`; `io_uring_*` → EPERM.
  - A dummy DNS server on the host IP (`dns.rs`).
  - "Weak" mode just sets proxy env vars, and there is a Docker mode.
- **Rules** (`src/rules/`): a V8 JS predicate (`v8_js.rs`), a shell command, or **`proc`**: a long-running external process speaking line-delimited JSON over stdin/stdout, with `RequestInfo {url, method, scheme, host, path, requester_ip}`, responses capped at 64 KiB and timeouts. The `proc` engine is a simpler sibling of srt's decider.
- **Gaps.**
  1. The jail has **no filesystem isolation**: the jailed command runs as the invoking user and sees their whole home directory.
  2. The **MITM CA key is persisted at `~/.config/httpjail/ca-key.pem`** (0600, same UID), so the jailed process can read the CA private key.
  3. The host input chain accepts everything from the veth, so enforcement depends entirely on the in-netns nftables output chain. That chain is safe only because the payload runs without `CAP_NET_ADMIN` in that netns (it is owned by the init userns). If a future change ran the payload as root in the netns, it would be an open door.
  4. It shells out to `ip`, `nft`, `unshare` and `setpriv` by absolute path, which is a large privileged surface.
  5. Policy sees URL and method only, with no body or headers.
- **For wicket.**
  - **REUSE:** CC0, so anything can be copied with no attribution duty. The hand-written seccomp BPF (`seccomp.rs`) is a compact reference with the x32 kill.
  - **BORROW:** the nftables ruleset as the *starting point* for transparent mode (pattern B in 02 §7.1), with the host input chain narrowed to the proxy ports.
  - **AVOID:** persisting the CA key where the box's UID can read it; network-only jails.
  - **design.md:** none beyond confirming §7's choices. httpjail is a useful *second* differential reference for the egress proxy's allow/deny behaviour (`proc` engine).
- **Confidence:** H.

---

## Part 2 — Linux jail libraries, gVisor, container and Kubernetes agent runtimes

### hakoniwa — Rust "library bwrap": namespaces + pivot_root + Landlock + seccomp + pasta/TUN + cgroups (https://github.com/souk4711/hakoniwa, lib LGPL-3.0-only WITH LGPL-3.0-linking-exception / CLI GPL-3.0-only, commit d99c8f3a4400, v1.8.1 2026-11-08)
- Local path `refs/repos/hakoniwa`; Rust (lib ~5.4k LOC in `hakoniwa/src`); 96 stars, one maintainer, very active (release the day of reading). Deps: `nix`, `libseccomp` (C), `landlock` 0.4, youki's `libcgroups` (systemd driver), `tun-rs`, `caps`, `postcard`.
- **Architecture as implemented.** `Command::spawn` forks; the child runs `runc::exec` (`hakoniwa/src/runc.rs`). Order in `exec_imp`: dup2 stdio → `close_extra_fds_exclude` → `PR_SET_PDEATHSIG(SIGKILL)` → `unshare::newuser` = one `unshare(all CLONE_NEW* flags)` then write `uid_map`/`setgroups=deny`/`gid_map` itself, *or* signal the parent over a pipe (`runc/notify.rs`, bitmask `SETUP_UGIDMAP|SETUP_NETWORK|SETUP_CGROUPS`) so the parent runs `newuidmap`/`newgidmap` (`unshare/newuser.rs:mainp_setup`), `pasta <pid>` (`unshare/newnet/pasta.rs`) and the systemd cgroup (`cgroups/manager.rs`, slice `hakoniwa.slice:hakoniwa:<pid>`) → `unshare::newns` (`runc/unshare.rs:mount`): `mount --make-rprivate /`, self-bind `new_root`, chdir, `initialize_rootfs` (proc held as an rbind of old `/proc` at a temp path; devfs = tmpfs + bind of null/zero/full/random/urandom/tty + private `devpts newinstance`; overlay/tmpfs; bind mounts with mkdir/touch of targets), `pivot_root(".", ".oldrootfs")`, `umount2(MNT_DETACH)`, `remount_rdonly` (retries with CL_UNPRIVILEGED-locked flags, moby's `getUnprivilegedMountFlags`) → **fork** (PID-ns init stays as reaper/ptrace supervisor in `reap`, collecting `/proc/<pid>/status` and `smaps_rollup` on `PTRACE_EVENT_EXIT`) → in grandchild `spawn`: `tidyup` (mount fresh procfs, detach old one, recursive RO remount of `/` unless `RootdirRW`, hostname, `setuser`) → chdir → optional `setsid` + TIOCSCTTY → rlimits → `landlock::load` → `seccomp::load` → `execve`.
- **Security mechanisms.** Landlock (`runc/landlock.rs:handle_access_fs`): FS rights of ABI V1 are `HardRequirement`, V2–V5 rights `BestEffort` — a good fail-closed-for-the-core, degrade-for-extras pattern; net (TCP bind/connect) per rule `Enforce`→Hard / `Relax`→BestEffort. Paths are `canonicalize`d before `path_beneath_rules`. Seccomp via libseccomp (`runc/seccomp.rs`); the CLI ships Podman's default profile (`hakoniwa-cli/src/assets/seccomp/podman.json`: default `ERRNO`, allow-list) and an `audit.json`. Networking: none (empty netns), pasta (forces `--no-map-gw`, `-t/-u/-T/-U none` unless overridden), or **RustSlirp**: creates a TUN/TAP inside the netns and passes the fd back to the caller via `SCM_RIGHTS` (`unshare/newnet/rustslirp.rs`) "to manage packets / do filtering explicitly" — i.e. a hook for a host-side userland stack. Ships an AppArmor profile (`etc/apparmor.d/hakoniwa`: `flags=(unconfined) { userns, }`) — exactly the Ubuntu 24.04 unblock wicket needs.
- **Bugs / gaps.**
  - **No capability dropping at all.** `hakoniwa-cli/src/seccomp.rs:contains_caps` returns `true` "since we donot restrict capabilities"; `runc/unshare.rs:setuser` even re-raises effective = permitted after `setuid`. With the default map (container uid = host uid, non-zero) caps vanish at `execve`, but **when the launcher is root (a privileged helper) the default map is `0 0 1`**, so the sandboxee is root in a userns that *owns* the mount namespace and can `mount -o remount,rw` or `umount` the RO binds it was given (they were created inside that userns, so they are not `MNT_LOCKED`). The Podman profile allows `mount`, `umount2`, `unshare`, `clone`, `clone3`, `pivot_root`, `keyctl`, `ptrace` unconditionally (Podman relies on cap-dropping to make that safe; hakoniwa doesn't drop).
  - Unknown syscall names in a profile are silently skipped (`runc/seccomp.rs:load_imp`): a deny rule for a syscall libseccomp doesn't know becomes a no-op.
  - No `TIOCSTI`/`TIOCLINUX` ioctl filter; `setsid` is opt-in (`Runctl::NewSession`).
  - Mount targets are built with path-based `mkdir_p`/`touch`/`mount` after `chdir(new_root)`, following symlinks; if the rootdir contains attacker-writable content (a workdir from a previous run), a planted symlink can redirect a later bind target. nsjail's new-API code walks with `O_NOFOLLOW` (below).
  - `/dev/core -> /proc/kcore` symlink (copied from bwrap; harmless without caps, noted).
- **For wicket.** REUSE: possible as a crates.io dependency (LGPL with linking exception permits static linking from Apache/MIT code; modifications to hakoniwa itself must stay LGPL) — but bus factor 1 and the cap gap mean **not as the TCB core**. BORROW: the parent/child setup handshake over a pipe (uidmap/net/cgroup done by the privileged parent while the child waits), PID-1 reaper with `PTRACE_O_TRACEEXIT` for exit metrics, the Landlock Hard-for-V1 / BestEffort-above split, RustSlirp's "hand the TUN fd to the host" (pattern for a transparent-mode netns without nftables), the AppArmor `userns` profile for `wicket-jail`. AVOID: running the sandboxee as uid 0 in the mount-owning userns; libseccomp C dependency (use `seccompiler`). design.md §7 row 1: add "drop all caps + bounding set, and exec the agent in a **second, nested userns** (bwrap/birdcage pattern) so mounts are locked"; §3.1: ship an AppArmor profile for `wicket-jail` rather than flipping the sysctl.
- Confidence: H (code read end-to-end for the run path).

### birdcage — Phylum's cross-platform FS/network sandbox (Linux namespaces+seccomp, macOS `sandbox_init`) (https://github.com/phylum-dev/birdcage, GPL-3.0, commit d0c625188385, v0.8.1 crate 2024-04; last commit 2025-11 is a CI bump)
- Local path `refs/repos/birdcage`; Rust ~2.6k LOC; 219 stars; effectively unmaintained.
- **Architecture.** `src/linux/mod.rs:spawn_sandbox_init` asserts single-threaded, then raw `libc::clone(CLONE_NEWIPC|NEWNS|NEWPID|NEWUSER [|NEWNET unless Exception::Networking])` onto an mmap'd stack. In `sandbox_init_inner`: `map_ids(euid→0)` → `namespaces::setup_mount_namespace` (`src/linux/namespaces.rs`): tmpfs at fixed `/tmp/birdcage-root`, bind-mount each exception sorted by path depth (`copy_tree` recreates parents), `mount_setattr(AT_RECURSIVE, RDONLY/NOEXEC + NOSUID)`, bind old `/proc`, `pivot_root(new, new)` + `umount2("/", MNT_DETACH)`, `MS_REC|MS_PRIVATE` → mount fresh `/proc` (nosuid,nodev,noexec) → **`create_user_namespace(parent_euid, parent_egid)`: a second userns mapping root back to the original uid** → seccomp → `NO_NEW_PRIVS` → spawn sandboxee as child of an init that relays exit status.
- **Security mechanisms.** The nested userns is the important idea: the sandboxee's caps live in userns #2, which does not own the mount ns, so it cannot unmount or remount anything set up in #1. Seccomp (`src/linux/seccomp.rs`, `seccompiler`): allow-list, mismatch → `EACCES`; `clone` allowed only if `flags & 0x7E020000 == 0` (no `CLONE_NEW*`); a second filter makes `clone3` return `ENOSYS` so libc falls back to `clone` (the same trick srt uses).
- **Bugs / gaps.** Allow-list includes `ioctl` unrestricted (TIOCSTI) and `setsid` but the sandbox never calls `setsid`; includes `socket` with any family and all three `io_uring_*` syscalls (fine only because NEWNET removes the routes); exceptions that fail `copy_tree` are logged and skipped (fails narrow, OK); fixed host path `/tmp/birdcage-root` (created on the shared `/tmp` before tmpfs is mounted over it — a host-side symlink there redirects the tmpfs mountpoint). With `Exception::Networking` it is host networking, no proxy concept.
- **For wicket.** REUSE: no (GPL-3.0). BORROW (idea only, re-implement): nested userns after mount setup; `mount_setattr(AT_RECURSIVE)` rather than per-mount remounts; `clone3→ENOSYS`. AVOID: fixed paths in shared `/tmp`.
- Confidence: H.

### extrasafe — seccomp + Landlock self-sandboxing builder, plus an experimental "Isolate" namespace runner (https://github.com/boustrophedon/extrasafe, MIT, commit b56d18c8d7b3, 0.5.1 2024-04)
- Local path `refs/repos/extrasafe`; Rust ~2.4k LOC; 265 stars; stale since 2024.
- **Architecture.** `SafetyContext` collects `RuleSet`s (`src/builtins/*.rs`: `BasicCapabilities`, `SystemIO`, `Networking`, `Threads`, `Time`, `danger_zone`) into a `seccompiler` filter (mismatch → `Errno`, match → `Allow`), applied per thread or with TSYNC. `src/isolate/isolate_sys.rs:run_isolate`: `clone(NEWNS|NEWUSER|NEWPID|NEWIPC|NEWUTS [|NEWNET] | CLONE_PIDFD)`, map user to root, tmpfs root, bind mounts (rejects `.`/`..` in dst), `pivot_root(".",".")` + detach, closes fds, runs a function pointer from a memfd copy of `/proc/self/exe`.
- **Bugs (concrete).**
  - **Socket-family filter is wrong**: `builtins/network.rs:allow_start_tcp_servers` uses `arg0 & AF_INET == AF_INET` (masked-equal) as if it were equality. AF_INET=2, so any family with bit 1 set passes: **AF_ALG (38), AF_KEY (15), AF_BLUETOOTH (31)**, AF_INET6 (10), etc.; `arg1 & SOCK_STREAM == SOCK_STREAM` (1) also admits `SOCK_RAW` (3) and `SOCK_SEQPACKET` (5). The UDP variant has the same bug.
  - **Landlock fails open**: `src/lib.rs:apply_landlock_rules` does `let _status = landlock_ruleset.restrict_self();` — the error is discarded. Only ABI V2 rights are handled, so `TRUNCATE` (V3) is never restricted; missing rule paths are silently skipped.
  - Isolate: `//// TODO: if config_data.drop_caps, drop capabilities` — the isolate runs as root in its userns with full caps.
- **For wicket.** REUSE: no (stale, buggy). BORROW: the `RuleSet`/`YesReally<>` API shape (dangerous grants need an explicit type-level acknowledgement) is a nice pattern for wicket's seccomp profile builder. AVOID: masked-equal for enum-valued args; ignoring `restrict_self` status. Lesson for `wicket-jail` tests (§14 M1): **unit-test the BPF filter against a table of (family, type) pairs**, including AF_ALG/AF_KEY/AF_NETLINK/AF_PACKET/AF_VSOCK, rather than trusting the builder.
- Confidence: H (bugs verified by reading the macro expansion in `src/macros.rs`).

### nsjail — Google's process jail: namespaces, Kafel seccomp, cgroups v1/v2, MACVLAN/pasta/**nstun** userland networking, seccomp-unotify tracing (https://github.com/google/nsjail, Apache-2.0, commit d8415bc8eea4, 3.6 2026-03-18; commits to 2026-10-28)
- Local path `refs/repos/nsjail`; C++ ~8.2k LOC core + ~6.9k LOC `nstun/` + `unotify/`; 4.2k stars; mature, actively developed.
- **Architecture as implemented.** `subproc.cc` builds the clone flags (`clone_newnet/user/ns/pid/ipc/uts/cgroup/time` from `config.proto`); the parent writes id maps (`user.cc`: direct write with `setgroups=deny`, or `/usr/bin/newuidmap` for multi-range maps), sets up net/cgroups, then releases the child. Child: `contain.cc:containProc` = `containUserNs` → `containInitPidNs` → `containInitMountNs` (`mnt.cc` legacy, or **`mnt_newapi.cc`** using `open_tree(OPEN_TREE_CLONE)`/`fsopen`/`fsmount`/`move_mount`/`mount_setattr` with **component-wise `openat(..., O_NOFOLLOW|O_DIRECTORY)` walks** so a symlink planted in the new root cannot redirect a mount target; root made RO with `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)`; `pivot_root` or `chroot` fallback) → net → uts → cgroupns → `containDropPrivs` (`PR_SET_NO_NEW_PRIVS`, then `caps::initNs`: clears all caps and the bounding set via `PR_CAPBSET_DROP` unless `keep_caps`) → CPU/core-scheduling/TSC/rlimits → `containPrepareEnv` (re-installs `PDEATHSIG` after uid change and **checks the parent didn't die in the window**: `setupParentDeathSignal` polls the parent pipe / compares `getppid()`; `setsid()` by default, `--skip_setsid` documented as "Dangerous") → `containMakeFdsCOE` (`close_range` or /proc walk) → seccomp last (`sandbox.cc:applyPolicy`).
- **Security mechanisms.**
  - Seccomp: **no built-in default policy** — only what the Kafel file/string says (`preparePolicy` returns early if none). TSYNC is only set when `seccomp_log`. Apply order: optional unotify filter first, then the main filter.
  - **`seccomp_unotify` (new)**: installs a `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter, sends the listener fd to the parent by `SCM_RIGHTS`, and the parent records file and socket syscalls (`unotify/syscall.cc` reads args with `process_vm_readv`) then answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. It is an **observation/learn mode** producing a report (`seccomp_unotify_report`), not an enforcement point, so the pointer-argument TOCTOU doesn't matter. `applyPolicy` now refuses to run when unotify is requested without a supervisor (previously it silently ran with *no* seccomp — a fixed fail-open, see comment in `sandbox.cc`).
  - **nstun (new, default user-net backend)**: a TUN device in the jail netns, fd passed to the parent, a userland TCP/UDP/ICMP stack in the parent (`nstun/tcp.cc`, `udp.cc`, `icmp.cc`) and a rule table (`config.proto: UserNet.NstunRule`, `nstun/policy.cc:evaluate_rules4/6`) with actions **DROP, REJECT, ALLOW, REDIRECT, ENCAP_SOCKS5, ENCAP_CONNECT** matched on direction/proto/CIDR/port ranges. `ENCAP_CONNECT` turns each guest TCP flow into `CONNECT <ip>:<port>` to an HTTP proxy (`nstun/encap.cc`) — **transparent forcing of non-proxy-aware clients through a proxy, rootless, no nftables**. Limitation: only the destination *IP* is known (no SNI/Host peek), so DNS must already have been answered.
  - cgroup v2 (`cgroup2.cc`): mem/pids/cpu per jail.
- **Bugs / gaps.** Policy-file driven: easy to run without seccomp; `mount_proc` is RW-off by default but `/proc` hardening relies on PID ns; legacy `mnt.cc` path still uses path-based mounts (the new API is the safe one); nstun ENCAP_CONNECT with IP-only targets cannot carry hostnames, so a hostname-policy proxy would have to reverse-map IPs (unsafe with shared CDNs).
- **For wicket.** REUSE: as an optional subprocess backend only (C++, not a library); its `configs/` are a good reference corpus. BORROW (strongly): (1) `mnt_newapi.cc` fd-relative, `O_NOFOLLOW` mount construction for `wicket-jail`; (2) the PDEATHSIG race check; (3) full cap + bounding-set drop before exec; (4) **unotify learn mode** for a `wicket observe` run that records which files/sockets an agent touches, feeding manifest proposal (§5.2) — observation only; (5) nstun's ENCAP_CONNECT as the design for an optional transparent mode (pattern B in 02 §7.1) without root nftables — in Rust this is `smoltcp` + a TUN fd, with an SNI/Host peek added so the CONNECT carries the hostname. AVOID: relying on config to remember seccomp; TSYNC off.
- Confidence: H for contain/mnt/sandbox/unotify code paths; M for nstun internals (read headers, policy and encap, not the TCP state machine).

### bubblewrap (brief) — the unprivileged sandbox under Flatpak, Codex and srt (https://github.com/containers/bubblewrap, LGPL-2.1-or-later, commit 1fb0aa26d3eb, v0.13.1 2026-10-14)
- Local path `refs/repos/bubblewrap`; C; 9.4k stars; mature.
- Relevant recent changes (`NEWS.md`): 0.13.0 uses `mount_setattr()` for ro/nodev/nosuid remounts on ≥5.12; rejects empty path args (previously sometimes meant `/`); 0.13.1 opens parent dirs in the new root with `O_PATH` (`safe_openat.c`); multiple `--sync-fd`. Flags wicket would use if it shells out: `--unshare-all --share-net`-less, `--disable-userns`, `--die-with-parent`, `--new-session` (TIOCSTI), `--cap-drop ALL`, `--seccomp FD`/`--add-seccomp-fd`, `--tmp-overlay`/`--overlay`, `--json-status-fd`, `--userns-block-fd` (lets the parent write maps).
- **`--disable-userns` mechanism (`bubblewrap.c` ~L3378)**: inside userns #1 it writes `1` to `/proc/sys/user/max_user_namespaces` (a per-userns limit), then creates userns #2 and re-drops the bounding set; the sandboxee cannot create further user namespaces **by kernel limit, not by seccomp**, and can't undo the sysctl because it lives in the parent userns. This is stronger than srt's clone-flag seccomp filter (which a new syscall or `clone3` variant could bypass) and gives the locked-mounts property for free.
- For wicket: REUSE as the documented fallback subprocess (LGPL is fine for exec). BORROW the max_user_namespaces=1 + nested-userns trick into `wicket-jail` and keep the seccomp clone filter as the second layer. Confidence: H.

### rust-landlock — official Landlock bindings (https://github.com/landlock-lsm/rust-landlock, Apache-2.0 OR MIT, commit 6a5413744f74, v0.4.7 2026-07-27)
- Local path `refs/repos/rust-landlock`; Rust; 337 stars; maintained by the Landlock author.
- **API facts that matter.** `CompatLevel::{BestEffort (default), SoftRequirement, HardRequirement}` (`src/compat.rs`), settable per `handle_access` call, so a ruleset can be Hard for the rights policy depends on and BestEffort for the rest (hakoniwa does this). `restrict_self()` returns `RestrictionStatus { ruleset: FullyEnforced|PartiallyEnforced|NotEnforced, no_new_privs }` — **wicket must check it and fail unless `FullyEnforced` for the declared ABI**. ABI table in code: V8 = Linux 7.0 (`all_threads()` / TSYNC, crate 0.4.6), V9 = 7.1 (`AccessFs::ResolveUnix` — pathname UNIX socket connects, crate 0.4.7), **V10 = 7.2 (`AccessNet::BindUdp`, `ConnectSendUdp`) — on `main`, not in 0.4.7**. `Scope::{AbstractUnixSocket, Signal}` (V6). V7 audit-log knobs `log_same_exec/log_new_exec/log_subdomains`. New `Erratum` API (`src/errata.rs`): erratum 1 (ABI 4 TCP rules wrongly applied to SMC/MPTCP/SCTP), erratum 2 (signal scoping), **erratum 3 (ABI 1: rename/link on disconnected directories under bind mounts could widen access, bypassing `REFER`)** — relevant because wicket combines bind mounts with Landlock; whether Ubuntu's 6.8 kernel carries the fix should be probed with `Erratum::current()` and logged, not used to disable rules (the crate docs say exactly that).
- For wicket: REUSE (depend, pin; consider a git pin to `main` only if UDP rules are wanted on 7.2+ hosts). Implication for §7 row 1: "probe the ABI" → "pin `handle_access(from_all(ABI::V4))` as HardRequirement on this box, BestEffort above, assert `FullyEnforced`, record errata in the sandbox capabilities". Confidence: H.

### zerobox — Codex's sandbox crates extracted, renamed and republished, plus secret placeholders and FS snapshots (https://github.com/afshinm/zerobox, Apache-2.0, commit 9a7affd6c68f, v0.3.3 2026-05-17)
- Local path `refs/repos/zerobox`; Rust ~12.5k LOC of its own + vendored Codex; 728 stars; quiet since May 2026.
- **Architecture.** `scripts/sync.sh` shallow-clones `openai/codex` at the tag in `UPSTREAM_VERSION` (`rust-v0.131.0-alpha.22`, commit 9b8cf56c, synced 2026-05-16), copies `codex-rs/{sandboxing,linux-sandbox,windows-sandbox-rs,process-hardening,network-proxy}` and `utils/{absolute-path,string,pty,rustls-provider}` into `upstream/` (gitignored), **replaces `codex-core` error types with an inlined `error.rs`**, sed-renames crates to `zerobox-*`, and publishes them to crates.io pinned `=0.3.3`. `crates/zerobox-protocol/src/permissions.rs` (3k LOC) is a stand-in for `codex-protocol`'s policy types. Own code: `crates/zerobox/src/secret.rs` (placeholder `ZEROBOX_SECRET_<64 hex>` in env; `substitute_headers` replaces placeholders in **any** request header when the CONNECT host matches the secret's hosts, through Codex's rama MITM), `zerobox-snapshot` (Merkle content store for `--restore`/undo of FS changes).
- **Bugs / gaps.** `SecretEntry::host_matches` returns **true when no `--secret-host` is given** ("No restriction — matches all hosts"): an unscoped secret is substituted toward any allowed host, including an attacker-controlled one. Substitution into arbitrary headers means a reflecting allowed host (echo/debug endpoints, error pages that include headers) leaks the real value back into the box. MITM CA persisted at `~/.zerobox/proxy/ca.pem` (shared across runs). Lags Codex by months.
- **For wicket.** This is **evidence that Codex's `linux-sandbox`/`sandboxing`/`network-proxy` crates are extractable** with a small patch set (error types + protocol types). BORROW the sync-script approach (pinned upstream SHA, scripted patching, renamed crates) if wicket vendors Codex code; do it from Codex directly, not via zerobox. AVOID: default-open secret scoping; header-wide substitution — wicket should inject only into the adapter-declared auth header after stripping client auth (design §8.1 already says so; keep it).
- Confidence: H.

### gVisor (runsc), relevant bits — user-space kernel; checkpoint/restore, network modes, host UDS, new netgofer/network-proxy-path (https://github.com/google/gvisor, Apache-2.0, commit 451b92800b9c, release-20261102.0)
- Local path `refs/repos/gvisor` (sparse: `runsc/{cmd,sandbox,boot,config,container,gofer/net}`, `pkg/sentry/{state,fsimpl/host}`, `pkg/unet`); Go; 19.9k stars; weekly releases.
- **Platform/args.** `runsc/config/flags.go`: `--platform` default **`systrap`** (no KVM; `ptrace`, `kvm`, `auto` also); `--rootless`; `--ignore-cgroups`; `--host-settings=check|ignore|adjust|enforce`; flags are global `runsc` flags before the subcommand and can also be set per container via OCI annotations (see `config.go`). Rust has no client: wicket writes an OCI bundle (`oci-spec`) and execs `runsc create/start/checkpoint/restore/delete`.
- **Networking.** `--network=sandbox|host|none|plugin` (`config.go` `NetworkType`); `none` = netstack loopback only. `--host-uds=none|open|create|all` (default `none`) controls whether the sandbox may connect to (`open`) or create (`create`) host UNIX sockets that are present in its mounts — the knob for **srt-style UDS bridging under gVisor**: bind-mount the proxy socket, `--network=none --host-uds=open`, in-box TCP→UDS forwarder. **New and EXPERIMENTAL in this release:** `--network-proxy-path=<abs path>` attaches the sandbox's primary NIC to an external `SOCK_SEQPACKET` UDS (raw L2 frames to a process of ours) and `--netgofer=proxy`, a sidecar (`runsc/gofer/net/netgofer.go`) that terminates guest TCP in its own netstack (`tcp.NewForwarder`) and `net.Dial`s the host, filtered by `runsc/gofer/net/egressfilter/egressfilter.go:Allows` — which rejects host-local interface addresses, loopback (unless allowed), link-local (so 169.254.169.254), multicast, unspecified, broadcast, but **allows RFC1918**. Both require `--network=sandbox`, and `PauseExternalNetworking` is sandbox-network only (`config.go` validation ~L611–634).
- **Checkpoint/restore.** `runsc checkpoint` (`runsc/cmd/checkpoint.go`): `--image-path`, `--leave-running`, `--compression=none|flate-best-speed`, `--exclude-committed-zero-pages` (default true), `--direct`, **`--save-restore-exec-argv` / `--save-restore-exec-timeout`: a binary run *inside the sandbox* before save and after restore; failure aborts the save/restore**, `--fs-checkpoint-paths` (split filesystem checkpoint, "all-tmpfs"), `--state-engine=wire|graph`. `runsc restore` (`restore.go`): `--image-path`, `--background` (default true: lazy page loading, needs an uncompressed image), `--direct-io=auto|on|off`. Host FDs: `pkg/sentry/fsimpl/host/save_restore.go` — `beforeSave` panics on non-savable host inodes and drains pipe buffers; `afterLoad` requires the restorer to supply a new FD for each `restoreKey` (`host:<fd>` per container) or marks it `-1` if declared non-restorable. So stdio and donated fds must be re-provided on restore; host network connections are not carried (02 §3 notes `ECONNRESET`). `runsc/sandbox/sandbox.go` restore checks host settings and refuses split-FS restore if the sandbox wasn't created with FS-restore support.
- **Bugs / gaps.** netgofer is experimental and its egress filter is not an allowlist (RFC1918 reachable); `--network-proxy-path` gives us L2 frames, meaning wicket would need a userland TCP stack to use it. Connected host-UDS sockets through the gofer are, as far as I could tell, not restorable (M), so the in-box forwarder must reconnect after restore.
- **For wicket.** REUSE: `runsc` as a subprocess (Apache-2.0). BORROW: `--save-restore-exec-argv` as the **parking hook** — before save, the in-box `wicket-guest` helper confirms quiescence (no in-flight proxy streams, agent idle) and fails the checkpoint otherwise; after restore it re-dials the UDS bridges, refreshes the clock-sensitive bits and pokes the agent (design §7 "Parking"). Use `--compression=none` + background restore for fast resume. v1 gVisor egress = `--network=none --host-uds=open` + bind-mounted proxy UDS (same code as the process tier); revisit `--network-proxy-path` (with a smoltcp endpoint) only if transparent mode is needed. design.md §7 row 2 should say `--host-uds=open` explicitly, and §14 M7 should test that restore re-provides stdio fds and that the bridge reconnects.
- Confidence: H for flags/config/host-FD code; M for host-UDS restore behaviour (gofer socket code not checked out).

### agent-sandbox (kubernetes-sigs) — K8s CRDs for singleton, stateful agent pods with warm pools and suspend (https://github.com/kubernetes-sigs/agent-sandbox, Apache-2.0, commit 993fd4aa9f57, v1.0.10 2026-11-06)
- Local path `refs/repos/agent-sandbox`; Go controller + Python/Go SDKs + `sandbox-router` + `packages/sandboxd`; 4.5k stars; very active (SIG Apps).
- **CRDs as implemented.** `api/v1beta1/sandbox_types.go`: `Sandbox{ SandboxBlueprint{PodTemplate, VolumeClaimTemplates, Service, FailedPodPolicy Retain|Recreate}, Lifecycle{ShutdownTime, ShutdownPolicy Delete|Retain}, OperatingMode Running|Suspended }`, conditions `Ready/Suspended/PodScheduled/Finished` with reasons. `extensions/api/v1beta1/`: `SandboxTemplate` (blueprint + `NetworkPolicy{Ingress,Egress}` + `NetworkPolicyManagement Managed|Unmanaged` + `EnvVarsInjectionPolicy Disallowed|Allowed|Overrides` + `VolumeClaimTemplatesPolicy`), `SandboxWarmPool{Replicas, TemplateRef, UpdateStrategy}`, `SandboxClaim{WarmPoolRef, Lifecycle, TTLSecondsAfterFinished, AdditionalPodMetadata, Env, VolumeClaimTemplates}`. Claims adopt a warm pod (label `agents.x-k8s.io/launch-type: warm|cold`); a claim that sets `env` is **forced to cold start** because env can't be injected into a running pod (template doc comment).
- **Security mechanisms.** Default managed NetworkPolicy (`extensions/controllers/sandboxtemplate_controller.go` ~L224): ingress only from the router; egress `0.0.0.0/0` except 10/8, 172.16/12, 192.168/16, 169.254/16 and `::/0` except fc00::/7, fe80::/10 — **blocks cluster DNS on purpose**, but is IP-level only: no proxy, no TLS, no credential handling. Isolation strength is delegated to `runtimeClassName` (gVisor/Kata). `Suspended` = delete the Pod, keep PVCs (`controllers/sandbox_controller.go:computeSuspendedCondition`); memory snapshots are a separate, unmerged "Snapshot Provider" KEP (KEP-694 explicitly excludes it; roadmap lists PodSnapshot CI as in progress). `sandboxd` (in-pod gRPC process service + REST filesystem API, token auth via `X-Sandboxd-Token`, binds 0.0.0.0 by default) is the exec channel.
- **Bugs / gaps.** Template-level shared NetworkPolicy means all claims from one template share one egress set (no per-task policy); the control daemon lives in the box (fine for their threat model, not wicket's principle 1); "Suspend" loses process state.
- **For wicket.** REUSE: none now (K8s). BORROW: the **template / warm-pool / claim** split (a zone's sandbox template is prepared ahead; a claim binds task-specific bits), and the rule that **anything task-specific that must be baked in at start forces a cold start** — for wicket the per-box CA and placeholder env are task-specific, so warm pools need a late-binding path (inject CA/env via the guest helper after claim, never baked). A future `k8s` backend for §7 could target these CRDs with `runtimeClassName: gvisor` and an `Unmanaged` policy plus wicket's proxy as the only egress. Confidence: H (types and controller read), M (snapshot KEP status).

### container-use (dagger) — MCP server giving each agent a Dagger container plus a git branch per environment (https://github.com/dagger/container-use, Apache-2.0, commit 2e43e625e952, v0.4.2 2025-08-19; last commit 2026-08-12)
- Local path `refs/repos/container-use`; Go ~7.9k LOC; 4.1k stars; slowing down.
- **Git-branch-per-env model (`repository/repository.go`, `repository/git.go`).** `ensureFork`: a bare repo per user repo under `~/.config/container-use/repos/…` with `include.path` → the user's `.git/config` and `commit.gpgsign=false` (`setupConfigInclude`); the user repo gets a `container-use` remote pointing at it. `initializeWorktree`: `git -c core.hooksPath=/dev/null push container-use <ref>:refs/heads/<env-id>`, `git worktree add` in the fork, `submodule update --init --recursive` **with host credentials**, `absorbgitdirs`. After each agent action `propagateToWorktree` exports the container's `/workdir` over the worktree with `Wipe:true` (re-writing the `.git` pointer file host-side), `commitWorktreeChanges` (`git add` non-binary files + `commit` with hooks disabled), state in git notes. Humans `cu checkout/merge/apply <env>`.
- **Security mechanisms / gaps.** Container exec uses **`ExperimentalPrivilegedNesting: true`** (`environment/environment.go` ~L273, ~L375), which gives code in the container access to the Dagger engine API of the session [M on exact reach: Dagger's docs describe it as letting nested execs call back into the engine]. Secrets are `WithSecretVariable` env vars inside the container. No egress control. `validateExportFilePath` (`git.go`) is **lexical only**; `exportEnvironmentFile` then `MkdirAll`s and writes through the host filesystem, so a symlink exported earlier into the worktree can redirect a later single-file export outside it (symlink TOCTOU). Host-side `git status/add/commit` run in a tree the agent fully controls (attributes, large files); `Checkout`/`Merge` in the user repo run without `noHooks`. Agent-written `CLAUDE.md`/`.envrc`/`.vscode/tasks.json` land in the user's checkout unflagged.
- **For wicket.** BORROW: branch-per-zone in a **separate bare repo** with `core.hooksPath=/dev/null` on every host git call; git notes for provenance; humans merge, never auto-apply. AVOID: exporting agent trees onto host paths (wicket's `extract(Patch)` parsed host-side is right, design §7); privileged nesting; secrets as env. Confidence: H for git flow, M for privileged-nesting reach.

### toolhive (stacklok) — runs MCP servers in containers with permission profiles, sidecar egress/ingress proxies, DNS sidecar (https://github.com/stacklok/toolhive, Apache-2.0, commit 42cd9b7e497b, v0.63.0 2026-11-06)
- Local path `refs/repos/toolhive`; Go; 2.3k stars; very active (also an operator, vMCP aggregator, LLM gateway).
- **Permission profile schema.** The type lives in the external module `github.com/stacklok/toolhive-core/permissions` (v0.0.58, not vendored here); the operator mirror (`cmd/thv-operator/api/v1beta1/mcpserver_types.go` ~L680–725, now marked *deprecated for MCPServer workloads*) shows it: `{ read: [paths], write: [paths], network: { mode: host|bridge|none, outbound: { insecureAllowAll, allowHost: [], allowPort: [] } } }`, plus builtin profiles `none` and `network`; CapDrop/SecurityOpt/Privileged come from the profile (`pkg/container/docker/client.go` ~L890, L1713).
- **Network isolation as implemented (`pkg/container/docker/client.go` ~L200–300).** When isolation is on and the mode is bridge: create `toolhive-<name>-internal` with Docker `Internal: true` (no route out), attach the MCP container only to it; attach sidecars to both internal and `toolhive-external`: a DNS container (`DnsImage = "dockurr/dnsmasq:latest"`), an egress Squid (`pkg/container/docker/squid.go:createTempEgressSquidConf`: `acl allowed_ports port …`, `acl allowed_dsts dstdomain …`, `http_access allow allowed_dsts allowed_ports`, `http_access deny all`, explicit deny of Docker gateway IPs/hostnames before any allow unless `AllowDockerGateway`), and an ingress Squid reverse proxy for SSE/HTTP transports. Envoy is an alternative (`TOOLHIVE_NETWORK_PROXY=envoy`, `envoy.go`). `addEgressEnvVars` sets `HTTP(S)_PROXY=http://<name>-egress:3128`, `NO_PROXY=localhost,127.0.0.1,::1`. Non-bridge modes silently drop isolation (logged) — `none` is treated as already confined. K8s path uses NetworkPolicies.
- **Bugs / gaps.** Squid matches CONNECT host only, no TLS interception → domain-level policy, domain fronting possible, no credential injection; **the DNS sidecar resolves any name upstream, so DNS is an open exfiltration channel from the "internal" network**; DNS image is an unpinned third-party `:latest`; `SecurityOpt: label:disable` (SELinux off) on workloads; secrets are passed to MCP servers as env vars (the MCP server holds real tokens).
- **For wicket.** REUSE: nothing (Go, Docker-centric). BORROW: the **profile shape** for third-party MCP servers in their own sandbox (design §8.2 kind 2): read/write paths + outbound hosts/ports is the minimum, and wicket's zone compiler can emit it. The internal-network + dual-homed sidecar pattern is the container analogue of the UDS bridge; if wicket ever adds a Docker/Podman backend, use it but **answer DNS only for policy-allowed names (or not at all)** and terminate TLS. Confidence: H for docker/squid code; M for the profile type (read via operator mirror).

### OpenHands runtime (now `software-agent-sdk`) — agent server inside a container, driven over HTTP/WebSocket (https://github.com/OpenHands/software-agent-sdk, MIT, commit e6569442a239, v1.60.1 2026-11-05)
- Local path `refs/repos/openhands-sdk` (sparse: `openhands-workspace`, `openhands-agent-server`). The originally requested `refs/repos/OpenHands` (commit cc99322a1efd) is now the TypeScript frontend; `openhands/runtime` no longer exists there. Python; 1.4k stars (main repo 93k); very active.
- **Architecture.** `openhands-workspace/openhands/workspace/{docker,apptainer,agent_sandbox,cloud,remote_api}`: each starts an **agent-server** (the whole agent loop + tools) in the box and talks to it over HTTP. `docker/workspace.py` runs `docker run -d --rm --ulimit nofile=65536:65536 -p 127.0.0.1:<port>:8000 [-v …] [--network …] -e SESSION_API_KEY…` — default bridge network (full internet), no cap drop, no seccomp beyond Docker's default. `agent_sandbox/` claims a pod from a kubernetes-sigs `SandboxWarmPool` (above) and gets gVisor/Kata via `runtimeClass`.
- **Credentials.** The LLM config including `api_key` and per-conversation secrets are sent **into** the agent server (`agent_server/conversation_router.py` `decrypt_incoming_llm_secrets`, `/{id}/secrets`), i.e. the model key and tool secrets live in the box — the opposite of wicket principle 2.
- **For wicket.** Useful only as a T3-style "agent runs entirely in the box" data point and as proof that agent-sandbox warm pools are being consumed by agent frameworks. AVOID its credential model. Confidence: M (read the workspace launcher and routers, not the full SDK).

### SWE-ReX — remote shell/exec runtime for SWE-agent across Docker, Modal, Fargate, Daytona (https://github.com/SWE-agent/SWE-ReX, MIT, commit 5c995c365dfb, v1.4.0 2025-08-14; last commit 2026-03-02)
- Local path `refs/repos/SWE-ReX`; Python; 638 stars; maintenance mode.
- **Architecture.** `src/swerex/deployment/docker.py` runs `docker run --rm -p <port>:8000 … <image> swerex-remote --auth-token <uuid4>` with a fallback `pip install pipx && pipx run swerex-remote` at container start; `src/swerex/server.py` is FastAPI with an `X-API-Key` check (`!=` compare); `runtime/local.py` keeps bash sessions with `pexpect` and detects command end by a `PS1="SHELLPS1PREFIX"` sentinel.
- **Gaps.** Port published on all host interfaces (`-p <port>:8000`), guarded by a token passed on the command line (visible in host `ps`); runtime install from PyPI inside the box at start (supply chain); sentinel-delimited output means the command output can forge the end-of-command marker; no network or credential controls at all.
- **For wicket.** Nothing to reuse. Lesson for wicket's harness-only control channel (`Instance::exec`, design §7): length-prefixed framed I/O over a private fd/vsock, never PS1 sentinels, never a TCP port on the host. Confidence: H.

---

## Part 3 — microVM, gVisor-driver and hosted-sandbox projects

### microsandbox — self-hosted libkrun microVM runtime with a user-space netstack, TLS MITM and placeholder secrets (https://github.com/superradcompany/microsandbox, Apache-2.0, commit 5da702c9ce96, v0.7.13 2026-11-01)

- **Basics.** Local path `refs/repos/microsandbox`. Written in Rust (edition 2024), with SDKs for TS, Python, Go and Ruby. About 9.0k stars, pushed daily, "beta". The workspace is about 40 crates. The VMM is the **`msb_krun` crate pinned `=0.1.45`**, a fork of libkrun with a pluggable `NetBackend` and checkpointing; the vendored `vendor/libkrunfw` supplies the guest kernel.
- **Architecture as implemented.**
  - The per-sandbox host process is libkrun-in-process. It exposes virtio-console (control), virtio-net, virtio-fs, virtio-blk and virtio-rng (`docs/security/isolation.mdx`).
  - **Network:** `crates/network/lib/engine/netstack/backend.rs:SmoltcpBackend` implements msb_krun's `NetBackend`. Guest Ethernet frames go into lock-free rings, then to a **smoltcp** poll thread on the host, which terminates guest TCP/UDP. It is user-mode NAT, like slirp, with policy in front.
  - TCP goes to `engine/tcp/*`. TLS goes to `engine/tls/proxy.rs:TlsProxy::try_run`, which buffers the ClientHello with a 10 s timeout, takes the SNI, then runs `network_policy.evaluate_egress_with_source(guest_dst, …, HostnameSource::Sni)`. The result is deny, bypass (opaque relay) or `intercept_relay`.
  - Inside `intercept_relay`, the upstream side uses rustls verification against `ServerName::try_from(sni)`. A guest that forges an IP cannot get a valid upstream session.
  - DNS is intercepted host-side (`engine/dns/interceptor.rs`). It records a **pin set** (name→IP observed for *this* sandbox), and domain rules match only IPs in that set (`docs/security/network.mdx` "DNS-to-IP binding (TOCTOU)").
  - Outbound can be chained through one upstream HTTP CONNECT or SOCKS proxy (`crates/network/lib/proxy/*`, `docs/networking/outbound-proxy.mdx`).
- **Credential placeholders (exact code).**
  - `crates/network/lib/engine/secrets/handler.rs` is a 7.3k-line **byte-stream rewriter** over the decrypted guest→server plaintext. It covers HTTP/1 headers, query strings, fixed and chunked bodies, Basic auth (base64-decoded scan), and HTTP/2 with HPACK decode and re-encode (`substitute_http2`, `hpack.rs`).
  - `SecretsHandler::new_inner` splits secrets into *eligible* and *ineligible* for this connection. A secret is eligible only if `secret_host_allowed` holds: the SNI matches `allowed_hosts`, **and** the guest's dst IP is in the DNS pin set for a matching name (`host_pattern_allowed`, l.2703), **and** TLS was intercepted (`require_tls_identity`). For CONNECT-tunnelled traffic the SNI is checked against the CONNECT authority instead (`new_tls_intercepted_via_connect`).
  - Authority alignment: `HttpAuthorityValidator::Sni` requires `Host`/`:authority` to equal the SNI, which closes domain fronting.
  - A placeholder seen going to an ineligible destination triggers `SecretViolationAction::{Block, BlockAndLog, BlockAndTerminate}`. This includes placeholders split across TCP writes (the `prev_tail` sliding window) and opaque streams (`scan_opaque`).
  - The placeholder is `$MSB_<ENV>` by default and is put in the guest env by agentd (`docs/security/secrets.mdx`). Placeholders over `MAX_SECRET_PLACEHOLDER_BYTES` fail closed. Unparseable HTTP-looking bytes fail closed (`opaque_prefix_might_be_http`).
- **Control channel.**
  - CBOR frames over virtio-console (`crates/protocol/lib/lib.rs`, `codec.rs`, `MAX_FRAME_SIZE` = 4 MiB), served by `agentd`, which runs as guest PID 1 as root.
  - The docs say plainly that the channel is unauthenticated and host-driven. A compromised guest can send any frames; the host must treat them as untrusted.
  - The workload runs as root by default. There is an opt-in `SecurityProfile::Restricted` (no_new_privs, nosuid/nodev).
- **Snapshots.**
  - `crates/runtime/lib/checkpoint/*` (15k lines) supports disk snapshots and *full* snapshots (memory plus processes), and `msb fork` with CoW memory. These are local only; cloud does disk only.
  - Restore re-creates host sockets: "a fresh proxy owns fresh host sockets, but must present the same virtual gateway MAC to captured RAM" (`checkpoint/network.rs:captured_gateway_mac`).
  - The docs state that "network connection recovery is not guaranteed".
- **Filesystem.** In-process passthrough virtio-fs (`crates/filesystem/lib/backends/passthroughfs/unix/inode.rs`) uses `openat2(RESOLVE_BENEATH)` with an `O_NOFOLLOW` fallback, and reopens through `/proc/self/fd/N`. The writable root is a per-sandbox layer over a content-addressed image cache.
- **Bugs, gaps and risks.**
  1. **The VMM process is not jailed.** There is no namespace, seccomp or Landlock code in `crates/runtime` (grep found none). The VMM runs as the invoking user with full host network and filesystem. This contradicts libkrun's own `docs/security-model.md` ("run the VMM inside an isolated context… namespaces"). A virtio-device bug, or a passthroughfs path bug, therefore yields that user's full authority.
  2. **One persistent, unconstrained MITM CA** for all sandboxes (`engine/tls/state.rs:load_or_generate_ca` → `~/.microsandbox/tls`, `ca.rs: BasicConstraints::Unconstrained`). There is no per-sandbox CA and no name constraints.
  3. The default policy allows public egress, so deny-by-default must be configured.
  4. Placeholder substitution is fundamentally *pattern matching on bytes the guest controls*. That is a large parser surface (HTTP/1 framing ambiguities, h2, chunked, compression), even with careful fail-closed choices.
  5. Raw secret values supplied via the SDK are persisted in the host catalog (`docs/security/secrets.mdx` "Where the values live").
  6. Fork and multi-restore of full snapshots duplicate entropy and TLS state (the same issue as Firecracker, see below). I found no VMGenID or reseed handling in `checkpoint/restore.rs` (grep for entropy, random or vmgenid returned nothing).
- **For wicket.**
  - **REUSE:**
    - Treat microsandbox as an optional *backend* through its Rust SDK (`sdk/rust`, `microsandbox` crate) on KVM or Apple Silicon hosts. Configure it with `network.policy` deny-all except an `outbound_proxy` (HTTP CONNECT) pointing at wicket-egress, with microsandbox's own TLS intercept *bypassed*, so wicket is the only MITM and the only credential holder.
    - Wrap the msb process in wicket-jail (netns whose only exit is the proxy UDS, mount ns, dedicated UID).
    - Beta API churn means pinning exactly.
    - Do **not** vendor `secrets/handler.rs`.
  - **BORROW:**
    - (a) The *DNS pin set* (a connection's dst IP must have been answered for that name to *this* sandbox), for wicket's transparent-mode (pattern B/E) resolver.
    - (b) The `Host`/`:authority` == SNI == CONNECT-authority triple check.
    - (c) The **placeholder tripwire**: even though wicket strips and injects instead of substituting, scan egress to *other* hosts for any zone placeholder, and deny and alert on a hit. That catches an agent copying its placeholder into an exfil request, a cheap compromise signal for the ledger.
    - (d) The user-space netstack (smoltcp) as the way to give a VM an `eth0` without host-kernel routing. This is the alternative to vsock-only for clients that ignore `HTTPS_PROXY`.
  - **AVOID:**
    - A shared persistent CA.
    - Substituting guest-supplied placeholders in arbitrary positions (body, query). wicket's §8.1 "strip all client auth, inject the real credential" is strictly simpler and stronger, and microsandbox's 7k lines show what the alternative costs.
    - An unjailed VMM.
  - **design.md implications:**
    - §7 table row 4: add a "libkrun/microsandbox (KVM or HVF)" backend under the rule that *every VMM runs inside wicket-jail*.
    - §8.1: add the DNS pin set and the placeholder tripwire.
    - §11: snapshot images contain the zone's plaintext memory, so label them with the zone's `conf` and delete them at task end.
- **Confidence:** H (code read). Fork, entropy and restore internals are M (in msb_krun, not read).

### libkrun — library VMM (KVM/HVF/WHP) with TSI socket impersonation (https://github.com/containers/libkrun → now libkrun/libkrun, Apache-2.0, commit 2fc56b5b6fce, v1.19.8 2026-11-06)

- **Basics.** Local path `refs/repos/libkrun`. Written in Rust, with C bindings. About 2.9k stars, Red Hat maintained, active. `src/libkrun/Cargo.toml` is at **2.0.0-dev**, with a new Rust builder API (`VmmBuilder`, `docs/vm-lifecycle.md`).
- **Architecture.**
  - The calling process *becomes* the VMM.
  - Devices are in `src/devices/src/virtio/{fs,vsock,net,block,console,balloon,rng,gpu}`.
  - Networking is either **TSI** over virtio-vsock (`vsock/tsi_stream/*`, `tsi_dgram/*`) or virtio-net over a Unix stream fd to passt or gvproxy (`NetDevice::new_unixstream_fd`, `docs/networking.md`).
  - With TSI, the libkrunfw guest kernel hooks `socket`/`connect`/`bind`/`listen`/`accept` and the VMM performs them **in its own host network context**.
- **Security mechanisms.**
  - Only those that `docs/security-model.md` delegates to the embedder: put the VMM in user, mount, net, pid and ipc namespaces with a dedicated UID and rlimits. Do not treat the virtio-fs export as a sandbox (use mount ns + `pivot_root`).
  - I found no self-applied seccomp or Landlock in the tree.
  - **No pause or snapshot on Linux**: `docs/vm-lifecycle.md` says pause/resume is macOS-only and "these control methods return `FeatureDisabled` on Linux".
- **Bugs and risks.**
  - **TSI `AF_UNIX` hijack lets the guest unlink host sockets.** `vsock/tsi_stream/unix.rs` bind path: `get_unixsock_path` stats the guest-supplied absolute path. If it is a socket, the VMM calls `fs::remove_file(path)` and then `bind`s its own listener there. It also unlinks on drop. A guest can therefore delete and replace *any host UNIX socket the VMM can reach* (for example a proxy or gateway socket), and connect to any of them.
  - There is a stat→unlink→bind TOCTOU.
  - With `HIJACK_INET`, guest connects run unfiltered in the VMM's netns.
- **For wicket.**
  - **REUSE:** the `krun` crate (Apache-2.0) for a macOS-HVF and Linux-KVM VM tier, *only* with virtio-net to a wicket-owned user-space stack, or with vsock to explicit ports. Never TSI `HIJACK_UNIX`, and never TSI `HIJACK_INET` outside a no-route netns.
  - **BORROW:** `NetDevice::new_unixstream_fd` as the seam where wicket's own netstack or proxy attaches.
  - **AVOID:** relying on libkrun for parking on Linux (no snapshot).
  - **design.md:**
    - §7 row 4 "Mac M3+ vz/libkrun variant": state that libkrun gives *no* snapshot on Linux, so parking there falls back to cgroup freeze.
    - §3.1: the jail helper must also wrap VMMs.
- **Confidence:** H.

### Firecracker (jailer, snapshot, vsock, seccomp) — the reference KVM microVM (https://github.com/firecracker-microvm/firecracker, Apache-2.0, commit c774bddb8246, v1.17.0 2026-09-10)

- **Basics.** Local path `refs/repos/firecracker`, sparse checkout: `src/jailer`, `src/vmm/src/{persist.rs,snapshot,devices/virtio/vsock,mmds}`, `resources/seccomp`, `docs/snapshotting`. Written in Rust. About 37.9k stars, mature.
- **Jailer, as implemented** (`src/jailer/src/env.rs:Env::run`, l.655):
  1. Copy the binary into the chroot (`copy_exec_to_chroot`).
  2. Optionally `setns` into a pre-made netns (`join_netns`).
  3. Install rlimits.
  4. Write cgroup v1/v2 limits.
  5. Chroot (`chroot.rs:chroot`: `unshare(CLONE_NEWNS)`, `MS_SLAVE|MS_REC`, self bind mount, `pivot_root(".", "old_root")`, unmount old root).
  6. `mknod` exactly `/dev/net/tun`, `/dev/kvm`, `/dev/urandom` and optionally `/dev/userfaultfd`, owned by the target UID.
  7. Optionally daemonize.
  8. Optionally `clone(CLONE_NEWPID)`.
  9. `exec_command` with `Command::uid/gid` (std drops supplementary groups).

  Gaps: no user namespace, no IPC or UTS ns, and no `no_new_privs` in the jailer itself. Firecracker installs its own **per-thread seccomp filters** from `resources/seccomp/x86_64-unknown-linux-musl.json` (vmm, api and vcpu threads). The jailer must start as root.
- **Vsock host side** (`devices/virtio/vsock/unix/muxer.rs`):
  - A guest connect to port P makes the host `connect()` to the fixed path **`<uds_path>_P`** (`handle_peer_request_pkt`, l.696).
  - A host connect goes to `uds_path` with a `CONNECT <port>\n` text preamble (`read_local_stream_port`).
  - `MAX_CONNECTIONS` caps the muxer.
  - The guest chooses only a port number, never a path. That makes it a clean explicit-port capability.
- **Snapshots** (`docs/snapshotting/snapshot-support.md`):
  - Full and diff snapshots exist; UFFD handles lazy restore.
  - "Network connectivity not guaranteed". The vsock device sends `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET`, so **all vsock connections close** while listen sockets survive.
  - "Snapshot security and uniqueness": resuming one state more than once is insecure (entropy, tokens). Only *boot A → snapshot → terminate A → resume once in B* is called secure. VMGenID is supported (Linux guest ≥5.18 with ACPI) and documented in `random-for-clones.md`.
- **Bugs and risks.**
  - None found in what I read.
  - Operational risk: most integrators skip the jailer (E2B and sandstorm both do, see below).
- **For wicket.**
  - **REUSE:** run the official jailer binary as-is (do not vendor). Use the API through `fctools` (MIT) or a thin hyper-over-UDS client.
  - **BORROW:**
    - (a) The jailer's step order and its *minimal mknod device set*, as the checklist for `wicket-jail`.
    - (b) **The `<uds>_<port>` vsock convention as wicket's VM attachment.** Port 3128 → `egress.sock_3128`, port N → `gateway.sock_N`. The guest shim forwards `127.0.0.1:3128` → vsock 3128.
    - (c) The parking semantics map exactly onto Firecracker's "secure usage" example: snapshot, kill, then restore once. **Forbid fork-from-park**, and if fork is ever wanted, require VMGenID plus reseeding.
  - **design.md:**
    - §7 Parking: "restore at most once per snapshot; never resume the source", and restore re-issues vsock listeners because of the transport reset.
    - §14 later: Firecracker milestone uses the jailer from day one.
- **Confidence:** H.

### fctools — async Rust host SDK for Firecracker (https://github.com/rust-firecracker/fctools, MIT, commit c9862146c0c8, no GitHub releases; crate 0.7.0-alpha.2, last push 2026-05-11)

- **Basics.** Local path `refs/repos/fctools`. Written in Rust. 19 stars, single maintainer (kanpov).
- **Architecture.**
  - `src/vmm/executor/{unrestricted,jailed}.rs` executes Firecracker directly or through the jailer.
  - `src/vm/{api,snapshot,configuration}.rs` hold typed API models and snapshot create/load.
  - The extensions are `http_vsock` and `grpc_vsock` (host→guest over the vsock `CONNECT` preamble), `snapshot_editor` and `link_local`.
  - It runs on either tokio or smol.
- **Security.** `src/process_spawner.rs` offers `SuProcessSpawner::new(password, …)` and `SudoProcessSpawner::new(Some(password), …)`, which **keep a root password in process memory** and pipe it to su or sudo. `vmm/ownership.rs` shells out to `chown` to upgrade or downgrade ownership.
- **For wicket.**
  - REUSE the API model and snapshot types, or borrow them (MIT; alpha, so pin).
  - AVOID its privilege-escalation spawners. wicket's privileged helper must be a separate, already-privileged binary, not a password-driven sudo wrapper.
  - Relevance is low until the KVM milestone.
- **Confidence:** M (skimmed).

### sandstorm — Rust fleet manager that parks idle sandboxes via cgroup freeze and `runsc checkpoint` (https://github.com/deeplethe/sandstorm, Apache-2.0, commit d27ab7c45212, v0.6.0 2026-11-01)

- **Basics.** Local path `refs/repos/sandstorm`. Written in Rust: one crate, `crates/sandstorm-core`, about 34k lines, with a single `sandstormd` binary. About 5.7k stars, alpha. The ADRs are dated October 2026.
- **Architecture.**
  - Master/node design with an E2B-compatible front door (`master/e2b.rs`).
  - Two backends (`node/backend.rs:Runsc`, `node/firecracker.rs`). **gVisor is the default because none of its dev hosts have KVM** (`docs/adr/0002-gvisor-runtime-no-kvm.md`), which is exactly wicket's situation.
  - The tier machine is `node/runtime.rs`:

    | Transition | Mechanism | Measured cost |
    |---|---|---|
    | hot→frozen | `echo 1 > cgroup.freeze`, then wait for `cgroup.events: frozen 1` (`freeze`, l.1288) | 8–11 ms |
    | hot→snapshot | `runsc checkpoint --image-path=… [--compression=flate-best-speed]` (`Runsc::checkpoint`) | 84 ms; frees RAM |
    | snapshot→hot | `runsc restore --bundle … --image-path=… --detach` (`Runsc::restore`) | 84 ms |
    | hot→detached | tar+zstd the writable layer | 1.7–2.8 s to cold-start back |

  - Every runsc call has a hard deadline because "runsc takes a lock on its state directory, and a wedged container makes even `runsc list` block". Output goes to files, not pipes, because runsc keeps the descriptors open (`Runsc::spawn`, `Runsc::run`).
  - Checkpoints are written to an attempt directory, validated by the `gVisorSF` statefile header (`validate`), **sealed** (file-size map), then renamed atomically (`checkpoint_into`).
  - Freezing also tunes zswap.
- **Networking** (`node/net.rs`).
  - A **netns per sandbox with a /30 veth (no shared bridge)**. iptables `FORWARD`/`INPUT` drops hold "independent of `ip_forward`". A per-sandbox egress exception is CIDR-only.
  - Frozen sandboxes get a `SANDSTORM-COLD` TCP-reset chain, and the gateway wakes the sandbox on traffic.
  - The OCI spec joins a pre-made netns path (`bundle.rs`, l.449).
- **Firecracker backend.**
  - Upstream FC, no jailer. Diff snapshots via soft-dirty bits, reflinked per-sandbox rootfs, fixed guest IP and MACs so restored ARP caches stay valid.
  - "Memory and disk travel together… memory from one moment over the disk from another corrupts the filesystem".
  - The guest agent is a Python HTTP server on TCP 8888.
- **Gaps** (some self-declared in `docs/SECURITY.md`):
  - No domain filtering and no inspection; egress is per address.
  - One unscoped root API token.
  - Node gateways serve plain HTTP.
  - gVisor has no memory cap.
  - Checkpoint size is unbounded.
  - FC runs without the jailer.
  - The key finding, from `may_restore` (l.1445): **restoring a gVisor checkpoint after a host file it had mapped changed** (a library in a bind mount) "succeeded, the program died". The checkpoint depends on host files staying byte-identical.
- **For wicket.**
  - **REUSE:** vendor or port the small, battle-tested pieces of `node/runtime.rs` and `node/backend.rs` (Apache-2.0, attribution in NOTICE): `freeze()` with `cgroup.events` confirmation, `Runsc::{spawn,run}` deadline-and-file-output handling, `checkpoint_into` (attempt dir, validate, seal, rename), and `may_restore` survival tracking. This is the M7 (gVisor parking) code path almost verbatim.
  - **BORROW:** the four-tier ladder, as wicket's parking policy (seconds = freeze, minutes = runsc checkpoint, hours = detach the upper layer only). The /30-per-sandbox veth pattern for wicket's transparent mode. Wake-on-traffic, which for wicket means wake-on-grant.
  - **AVOID:** its egress model and its API-token model.
  - **design.md:**
    - §7 Parking: the **lower layers (repo snapshot, toolchain, Claude Code binary) must be immutable and content-addressed for the life of a checkpoint**. Pin them by digest in the snapshot metadata and refuse to restore on mismatch.
    - §14 M7: budget about 50 MiB of disk per parked agent and enforce a disk-admission limit.
- **Confidence:** H (gVisor path), M (Firecracker path).

### gondolin — QEMU/krun micro-VM with a TypeScript host-side netstack, MITM and programmable VFS (https://github.com/earendil-works/gondolin, Apache-2.0, commit 5fec2d0df3e5, v0.14.0 2026-10-22)

- **Basics.** Local path `refs/repos/gondolin`. Host side in TypeScript/Node, guest daemons in Go/C. About 2.4k stars, "experimental" (Armin Ronacher's org).
- **Architecture** (`docs/architecture.md`, `docs/network.md`).
  - QEMU `-netdev stream` connects to a UDS, and the **host implements Ethernet, ARP, DHCP, IPv4, TCP and UDP in Node**. There is no NAT. Only HTTP/1.x and intercepted TLS are bridged to host-side `fetch`, with optional explicit SSH and mapped-TCP exceptions. Everything else is dropped.
  - Control runs over **four virtio-serial ports** (exec, VFS RPC, SSH, ingress). `docs/qemu.md` explains why vsock is avoided.
  - The guest `sandboxfs` FUSE daemon forwards every file operation to host providers (`MemoryProvider`, `RealFSProvider`, `ReadonlyProvider`, shadow).
  - Disk-only qcow2 checkpoints; there is no memory snapshot (`docs/limitations.md`).
- **Secrets** (`host/src/http/hooks.ts`).
  - `createHttpHooks` makes placeholders: `<random-marker>.<NAME>` in shared mode, or `GONDOLIN_SECRET_<48 hex>` (`makeDefaultSecretPlaceholder`).
  - `assertSecretPlaceholderIsSafe` rejects value==placeholder, duplicates and placeholders that overlap each other.
  - Substitution covers headers (and query strings if enabled) only for the secret's hosts, including decoding and re-encoding Basic auth. A placeholder sent to another host blocks the request.
- **DNS.** The **synthetic mode** (the default) answers every A/AAAA query with a fixed synthetic IP (`192.0.2.1`) and makes no upstream query. Policy is then decided on the Host/SNI seen after MITM, not on DNS, so DNS is neither an exfil channel nor a rebinding vector (`docs/network.md` "DNS and Policy").
- **Gaps.**
  - HTTP/1 only (no h2, h3 or QUIC).
  - QEMU is the boundary and runs unsandboxed as the user. The docs exclude "a malicious local user on the same account".
  - Virtio UDS sit in a temp dir (`docs/security.md`, l.431).
  - The JS netstack and FUSE-RPC are large untrusted-input parsers inside the trusted host process.
- **For wicket.**
  - **BORROW:**
    - (a) **Synthetic DNS**: for wicket's transparent-interception VM mode, answer all names with one sinkhole IP and decide on SNI and Host after MITM. That is simpler than microsandbox's pin set and leaks nothing.
    - (b) Placeholder hygiene rules (high entropy, no overlaps), for wicket's zone-bound placeholder tokens.
    - (c) Host-served VFS as a model for handles. A read-only provider that materialises a handle's content on read, and records the read so the label can be joined, is a neat way to implement §4.3 "dereferencing a handle joins its label".
  - **AVOID:** a JS host netstack in the TCB, and per-request substitution.
- **Confidence:** M (docs plus key files).

### E2B infra (now `e2b-dev/runtime`) + E2B SDK — Firecracker orchestrator, envd guest agent, tcpfirewall (https://github.com/e2b-dev/infra, Apache-2.0, commit 7a1781a632b7, release 2026.30 2026-09-10; SDK https://github.com/e2b-dev/E2B Apache-2.0 commit 2d7eb43dfe09, @e2b/python-sdk 2.63.0 2026-11-04)

- **Basics.** Local paths `refs/repos/e2b-infra` and `refs/repos/E2B`. Written in Go; the SDKs are TS and Python. The runtime has about 1.8k stars and the SDK about 14.8k; both are very active.
- **Egress, as implemented.**
  - `orchestrator/main.go:defaultEgressFactory` wires `pkg/tcpfirewall.Proxy` as the `network.EgressProxy`.
  - nftables in each sandbox netns (`pkg/sandbox/network/firewall.go`, table `slot-firewall`, postures default, rules, byop and isolated) redirect TCP/80 to the HTTP port (`Host` peek), TCP/443 to the TLS port (SNI peek, `inetaf/tcpproxy`), and other ports to a CIDR-only port.
  - `tcpfirewall/handlers.go:domainHandler` checks `isEgressAllowed`. Its order is allow-domain/allow-CIDR first, then deny-CIDR, then **default allow** (l.182–226).
  - On a domain match it **dials the hostname itself**, not the guest's dst IP, to defeat `/etc/hosts` tricks. It then checks the resolved IP against `DeniedSandboxCIDRs` in `Dialer.ControlContext` (`upstreamDialer`).
  - The sandbox is identified by source `ip:port` (`GetByHostPort`), and limiter state is keyed by `LifecycleID` because IPs are reused.
  - **No TLS interception, no BYOP and no header transforms in OSS.** `network/egressproxy.go` defines the `EgressProxy` interface (`SupportsBYOP`, `CABundle`, `HeadFilterRules`) with a `NoopEgressProxy`, and the SDK says BYOP is "rejected as unsupported" on `e2b-dev/runtime` (`js-sdk/src/sandbox/sandboxApi.ts`, l.330ff).
  - BYOP is SOCKS5, now optionally over TLS (`tls: true`), tunnelled host-side after filtering. UDP (DNS, QUIC) is not tunnelled. The SDK now exposes a configurable allowed DNS-server list.
- **Credential transforms** (`shared/pkg/networktransform/placeholders.go`).
  - The **rule** (written by the API caller at sandbox create, `api/internal/handlers/sandbox_create.go`, l.1140) sets header values containing `${e2b.secrets.NAME}` or `${e2b.identity.tokens.NAME}`. The proxy resolves these host-side, with at most 32 names per domain.
  - The guest never carries a placeholder at all. This is the "inject, don't substitute" model, the same as wicket's.
  - The applying proxy is closed-source.
- **Guest agent.**
  - `envd` is an HTTP/connect-rpc server *inside* the VM on port 49983. It authenticates callers with `X-Access-Token` (`envd/internal/api/auth.go`), whose hash it reads from MMDS (`internal/host/mmds.go`). The token protects the guest from other network parties; it is not a boundary for the host.
  - Pause requires guest cooperation: an envd freeze, then a held `/init` re-init after restore for clock sync (`sandbox/envd_reinit.go`). A compromised guest can wedge pause, though not harm the host.
  - Env vars, including any secrets the user passes, go into the guest (`sandbox/envd.go`, l.274).
- **Firecracker launch.** `sandbox/fc/process.go` (l.300) runs `unshare -m -- bash -c <script>`, and `fc/script_builder.go:startScriptV2` does `mount --make-rprivate /`, tmpfs mounts, then `ip netns exec <ns> firecracker --api-sock …`. That is **root, no jailer, no chroot, no UID drop**.
- **Bugs and gaps.**
  1. A Firecracker escape lands as **root on the host** (no jailer).
  2. `DeniedSandboxCIDRs` (`shared/pkg/sandbox-network/firewall.go`, l.22) **omits `0.0.0.0/8`**. A hostname under an allowed wildcard that resolves to `0.0.0.0` is dialled from the host netns, and on Linux that reaches host-loopback listeners. It also omits `198.18.0.0/15` and NAT64 `64:ff9b::/96`. M confidence; I did not test it.
  3. SNI-only matching means domain fronting on shared CDNs and "allowed domain, attacker's account" both work.
  4. Default allow.
  5. Allow-domain takes priority over deny-CIDR.
  6. The UDP/53 bypass is documented.
- **For wicket.**
  - **REUSE:** none (Go).
  - **BORROW:**
    - (a) **Dial the vetted name host-side and check the resolved IP inside the dialer's control hook** (`upstreamDialer`), with Happy Eyeballs preserved. That is exactly §8.1 "resolve once, dial the vetted IP", including the race-free placement.
    - (b) The template-in-rule transform syntax (`${secrets.NAME}`) for adapter-declared credential injection.
    - (c) Lifecycle-ID keyed connection accounting.
  - **AVOID:** a guest-resident agent as a security principal, and default-allow.
  - **design.md:**
    - §7 row 5 (e2b): BYOP is **E2B Cloud/BYOC only**, so a self-hosted E2B backend gets no forced proxy. Use SOCKS5-over-TLS with per-sandbox SOCKS credentials as the transport identity.
    - §8.1 SSRF deny list: include `0.0.0.0/8`, `::/128`, `::ffff:0:0/96` (mapped, normalised before the check), `64:ff9b::/96`, `100.64/10`, `198.18/15`, multicast and broadcast, plus the provider metadata IPs.
- **Confidence:** H for the code read; M for gap 2's reachability.

### Daytona (archived OSS, v0.190.0) — Docker-based sandbox runner (https://github.com/daytonaio/daytona, AGPL-3.0, tag v0.190.0 commit 01c502bb1f1f, v0.190.0 2026-06-23; repo emptied and archived, development moved private June 2026)

- **Basics.** Local path `refs/repos/daytona` (sparse checkout of `apps/{runner,daemon,proxy,snapshot-manager}`). Written in Go. About 71k stars, now dead upstream.
- **Architecture.**
  - The runner creates Docker containers (`apps/runner/pkg/docker/*`).
  - **`HostConfig.Privileged: gpuIndex == nil`**: every non-GPU sandbox is a *privileged* container ("non-GPU sandboxes still need privileged for their current workloads", `pkg/docker/container_configs.go`, l.205). An alternative `Runtime` (presumably sysbox or kata in cloud) is a config knob.
  - Egress: `pkg/netrules/set.go:SetNetworkRules` adds a per-container iptables chain in `DOCKER-USER` that RETURNs allowlisted CIDRs and DROPs the rest. It is keyed on source IP, with no domain or L7 policy.
  - The daemon is a toolbox server *inside* the sandbox.
- **For wicket:** AVOID everything (AGPL plus privileged containers). The only takeaway is negative evidence: a market leader shipped privileged containers with CIDR-only egress.
- **Confidence:** M.

### pullrun — OCI image as container/Firecracker/VZ VM (https://github.com/pullrun/pullrun, Apache-2.0 (workspace says "MIT OR Apache-2.0"), commit 0b0ce94c5f56, v0.7.10 2026-11-07)

- **Basics.** Local path `refs/repos/pullrun`. Written in Rust plus Go. 134 stars, very new.
- **Networking.** `runtime/pullrun-vm/src/network.rs` puts all VMs and containers on a **shared bridge `pullrun-br0` 10.42.0.0/16 with blanket MASQUERADE and FORWARD ACCEPT**. Its own header says "raw TCP from a VM is currently allowed through… v1 will layer… a proxy".
- **Jailer.** `jailer_path` exists in `pullrun-vm/src/lib.rs` but is always `None` (`pullrun-runtime/src/service.rs`, l.465).
- **For wicket:** AVOID. There is nothing to borrow beyond ext4-from-OCI (`pullrun-vm/src/ext4.rs`), which might be worth a glance for the Firecracker workdir image.
- **Confidence:** M.

### arrakis — Cloud Hypervisor sandboxes with snapshot/backtrack for agents (https://github.com/abshkbh/arrakis, AGPL-3.0, commit 877231496acb, release-36 2025-06-02; stale)

- **Basics.** Local path `refs/repos/arrakis`. Written in Go. 894 stars; there has been no push since June 2025.
- **Architecture.** `pkg/server/server.go` uses a shared bridge with `POSTROUTING MASQUERADE` plus `FORWARD -s/-d bridgeSubnet ACCEPT` (l.468–472), so egress is unrestricted. It uses Cloud Hypervisor snapshot and restore for "backtracking", and vsock for the command server.
- **For wicket:** AVOID (AGPL, no egress control). The only idea is "backtrack" (snapshot as an undo point), which wicket could expose as a typed `checkpoint` handle, with the same restore-once caveat.
- **Confidence:** M.

### cua / lume — Apple Virtualization.framework VM manager (https://github.com/trycua/cua, MIT, commit a90b916a5f13, cua-spaces-v0.22.3 2026-11-07; lume only)

- **Basics.** Local path `refs/repos/cua/libs/lume`. Written in Swift. The monorepo has about 32k stars.
- **Relevant code.**
  - `src/Virtualization/GatewayNetwork.swift:attachment` builds a `VZFileHandleNetworkDeviceAttachment` on a **SOCK_DGRAM UNIX socket using the vfkit greeting (`"VFKT"`)** to a user-mode gateway (`cua-netgw`, not in this checkout) "which decides what the guest may reach".
  - `VMVirtualizationService.saveMachineState`/`restoreMachineState` (`VM.swift`, l.816, l.863) give macOS 14+ save and restore.
  - `VZVirtioSocketDevice` is available for vsock.
- **For wicket.** BORROW the exact recipe for the macOS VM tier: VZ with a file-handle network to wicket's user-space gateway (or vsock-only), plus `saveMachineStateTo` for parking. This could be done from Rust via `objc2-virtualization`.
- **Confidence:** M.


---

## Synthesis

### (a.1) Reuse plan (wicket is Apache-2.0/MIT)

**Depend on (crates.io, pinned exactly):**
- `landlock` 0.4.7 (Apache-2.0 OR MIT). Use `HardRequirement` for ABI-4 FS and TCP rights and `BestEffort` above, assert `RestrictionStatus::FullyEnforced`, and record `Erratum::current()` (erratum 3 interacts with bind mounts).
- `seccompiler` 0.5 (Apache-2.0, rust-vmm), as Codex uses it.
- `rustix`/`nix`, `oci-spec`.
- Later: `krun` (libkrun, Apache-2.0), the `microsandbox` SDK (Apache-2.0) as an optional KVM/HVF backend, and fctools API types (MIT, alpha).

**Run as subprocesses (licence is irrelevant across exec):**
- `runsc` (Apache-2.0) for the gVisor tier.
- Firecracker's **official jailer** binary.
- `bwrap` ≥0.8 (LGPL-2.1+) only as a documented fallback.
- `srt proxy` (Apache-2.0) and httpjail's `proc` engine (CC0), as **differential test references** for `wicket-egress`, never in production.

**Vendor (copy at a pinned SHA into `wicket-jail`/`wicket-sandbox`, NOTICE attribution; use zerobox's `scripts/sync.sh` approach, applied to Codex directly):**

| From | Files | Into | Why |
|---|---|---|---|
| Codex `codex-rs/linux-sandbox` | `src/proxy_routing.rs` (listener-fd handoff, attribution frame, env rewrite), `src/seccomp.rs` (`ProxyRouted` filter) | `wicket-jail` | Process-tier network attachment (change 1) |
| Codex `codex-rs/network-proxy` | `src/authorization_path.rs` | `wicket-egress` / `wicket-adapter` canonicaliser | Reject `.`/`..`/`%2e`/`\`/`;` segments before any path match |
| Codex `codex-rs/process-hardening` | `src/lib.rs` (about 190 lines) | `wicket-jail`, `wicketd` | Non-dumpable, `RLIMIT_CORE=0`, strip `LD_*` |
| sandstorm `crates/sandstorm-core/src/node/{runtime,backend}.rs` | `freeze`, `Runsc::{spawn,run,checkpoint,restore,validate}`, `checkpoint_into`, `may_restore` | `wicket-sandbox` (gvisor) | M7 parking, almost verbatim |
| srt `vendor/seccomp-src/` | rule tables of `seccomp-unix-block.c:add_namespace_rules`, `apply-seccomp.c`'s layout (C, so *re-implemented* in Rust with seccompiler) | `wicket-jail` | Namespace-escape filter, `clone3→ENOSYS` |
| httpjail `src/jail/linux/{seccomp,nftables}.rs` | BPF with the x32 kill; the netns nft ruleset | `wicket-jail` (optional transparent mode) | CC0, so no obligations |

**Do not vendor:**
- hakoniwa: LGPL. Linking is fine, but copied code would stay LGPL. It also has a capability gap, so prototype with it at most.
- birdcage: GPL-3.0. Ideas only.
- Daytona and arrakis: AGPL.
- The whole Codex `network-proxy`: 25k lines, tied to `codex-core` config types and rama `=0.3.0-alpha.4`.
- microsandbox `secrets/handler.rs`: 7.3k lines of guest-placeholder rewriting.
- Anything in Go or TypeScript (E2B, toolhive, agent-sandbox, gondolin, srt's TS): ideas only.

### (a.2) Ranked design changes

1. **Process-tier network attachment = Codex's listener-fd handoff, not srt's socat/UDS bind** (§3.1, §7 row 1, §8).
   - `wicket-jail` creates the netns, brings up `lo`, binds `127.0.0.1:0` *inside* it, and passes the listening fd by `SCM_RIGHTS` to `wicketd`.
   - `wicketd` accepts on it directly. *The listener is the transport identity* (principle 2): no bearer token, no attribution header, no socket file in the box, and no in-box forwarder process.
   - Seccomp then allows only `AF_INET`/`AF_INET6` sockets (`socketpair` only `AF_UNIX`) and denies every new `AF_UNIX`, `AF_VSOCK`, `AF_NETLINK`, `AF_PACKET` and `io_uring`.
   - **gVisor cannot take this path**: its sockets are Sentry objects, not host fds. The gvisor tier keeps `--network=none --host-uds=open` with a bind-mounted UDS and an in-box forwarder, which must re-dial after restore.
2. **Lock the mount view; don't just filter it** (§7 row 1, M1 done-when).
   - After building mounts in userns #1: drop all caps and the bounding set (nsjail), write `user.max_user_namespaces=1` (bwrap `--disable-userns`), and exec the agent in a **nested userns #2** with the per-box UID (birdcage, srt's `apply-seccomp`).
   - Then add srt's `namespaces` seccomp filter as a second layer (`unshare`/`clone` with `NEWUSER|NEWNS` → EPERM; `clone3` → ENOSYS; `setns`, `mount*`, `pivot_root`, the new mount API).
   - Build mounts fd-relatively with the new mount API and `O_NOFOLLOW` walks (nsjail `mnt_newapi.cc`), because the workdir upper layer is agent-written.
   - **Codex lacks the userns defence** (M), so the design should cite srt and bwrap for it, not Codex.
3. **Fail closed on every hardening step** (§2 principle 3, §7).
   - srt warns and continues without its seccomp helper; Codex's legacy Landlock accepts `PartiallyEnforced`; extrasafe drops `restrict_self()`'s result; hakoniwa skips unknown syscall names.
   - `wicket-jail` refuses to start unless each declared layer (userns lock, seccomp, Landlock `FullyEnforced`, cgroup, netns) is confirmed. The applied set is reported in `Capabilities` and in the zone view.
   - The seccomp filter is table-tested over (family, type) pairs and clone flags, because of extrasafe's masked-equal bug.
4. **Every VMM and runtime runs inside `wicket-jail`** (§3.1, §7 rows 2/4/5).
   - microsandbox, E2B and sandstorm-FC run VMMs unjailed. libkrun's own security model says the embedder must jail the VMM.
   - Never enable libkrun TSI `HIJACK_UNIX`: guest-chosen host sockets get unlinked and rebound.
   - Ship an **AppArmor profile granting `userns` to `wicket-jail`** (hakoniwa ships one) instead of flipping `kernel.apparmor_restrict_unprivileged_userns`.
5. **Credentials: inject one adapter-declared header, never substitute guest bytes** (§8.1, §8.4, §6.1).
   - srt's `credentials.mask` and zerobox substitute into any header *and* body bound for an allowed host. That **reflects** the real secret into anything the provider stores or echoes.
   - microsandbox needs 7.3k lines to do substitution carefully. E2B's rule-side `${secrets.X}` and srt-proxy's `cred` verdict show the simple form.
   - Keep strip-and-inject, and add:
     - **shape-preserving placeholders** (Codex `shaped_dummy_value`: same prefix and length, so SDKs accept them locally);
     - a **placeholder tripwire**: a zone placeholder seen anywhere except its own injection header is denied and recorded as a ledger anomaly (microsandbox, gondolin);
     - conformance check 2b, a **reflection test**.
6. **Per-box CA: name constraints conflict with runtime host grants** (§8.1).
   - Node reads `NODE_EXTRA_CA_CERTS` once at start, so a CA name-constrained to the zone's *current* hosts cannot cover a host granted by escalation without restarting the agent.
   - Constrain the CA to the zone's **ceiling** (org-allowed hosts), not its reach, or keep it unconstrained but ephemeral, with the key only in `wicketd` memory.
   - Never persist the key where the box UID can read it (httpjail and microsandbox do).
   - Codex's and microsandbox's CAs are unconstrained, so a constraint would still be better than prior art.
7. **Parking = sandstorm's tier ladder plus gVisor's in-box hook** (§7 Parking, M7).
   - Tiers: freeze (`cgroup.freeze`, confirmed via `cgroup.events`, about 10 ms), `runsc checkpoint --compression=none` (about 84 ms), then detach the upper layer for long waits.
   - `--save-restore-exec-argv=/wicket/guest park` lets an in-box helper **veto** a checkpoint that is not quiescent and re-dial bridges after restore.
   - Restore each snapshot **at most once**, and never resume the source (Firecracker).
   - Pin lower layers by digest and refuse restore on mismatch (sandstorm: "succeeded, the program died").
   - Reseed user-space PRNGs after any template restore (sandstorm `WarmSpec`).
   - Label snapshot images with the zone's `conf`, and enforce a disk budget.
8. **Decider seam details** (§3.1).
   - Keep srt's protocol strictness: no nulls, duplicate keys or empty optionals; one `need_body`; ids increase; any violation kills the link; one 5 s timer.
   - `path`/`query` arrive *as spelled*, so canonicalize-or-reject happens before the frame (Codex `authorization_path.rs`). Query constraints are single-valued (Codex).
   - Refuse TRACE/TRACK, bodies on GET/HEAD/OPTIONS, and edits to framing headers (srt).
9. **Drive Codex through `codex app-server`, not only `codex-acp`** (§6 tier table, E1).
   - Its `item/permissions/requestApproval` is a held-open typed ask: `{network, file_system}` plus a reason, answered with a *narrower* `GrantedPermissionProfile` and `scope: Turn|Session`.
   - Its proxy feeds `NetworkApprovalContext{host, protocol}` into it. That is a T1-grade pending path for Codex.
10. **Runtime FS grants without restart via `SECCOMP_IOCTL_NOTIF_ADDFD`** (nono). After an approved FS escalation, the supervisor opens the file and injects the fd, so the agent never resolves the path. Add it as a later `Instance::grant_fd` (§7, §10). Do **not** use seccomp-notify + CONTINUE for any decision (nono's egress fallback is TOCTOU); it is fine for an observation-only `wicket observe` learn mode (nsjail `unotify/`, srt `SRT_OBSERVE_SOCK`) that feeds manifest proposals (§5.2).
11. **DNS and SSRF** (§8.1).
    - In proxy mode the box has no resolver.
    - In transparent and VM modes use **synthetic DNS** (gondolin: every name maps to one sinkhole IP, and the decision is made on SNI/Host after MITM) or a per-sandbox pin set (microsandbox).
    - Dial the vetted *name* host-side and check the resolved IP in the dialer's control hook (E2B `upstreamDialer`).
    - The deny list includes `0.0.0.0/8`, `::`, v4-mapped and NAT64, `100.64/10`, `198.18/15`, RFC1918 and ULA (srt full mode and gVisor netgofer allow RFC1918; E2B misses `0.0.0.0/8`), plus srt's cloud-metadata list.
12. **Adapter rules carry examples-as-tests** (§9). Borrowed from Codex execpolicy's `match`/`not_match`: each endpoint rule ships positive and negative requests that are checked at load time and in CI.
13. **Launch-time path scans are not protection** (§7 Workdir). srt and Codex find `.git`/hooks with `rg` once at launch, to depth 3. wicket's overlay plus host-side `extract(Patch)` with dangerous-path rules is the right model. State that the workdir's `.git` is never host-executed: host git runs with `core.hooksPath=/dev/null`, as container-use does on every call.
14. **CLI-wrapping gateway tools** (§8.2, a new fourth kind, from nono's command sandboxes). `gh pr create` and similar run in a **fresh per-call tool sandbox** holding the real token at *its* egress. The agent's box holds nothing, and each call is a gateway `Op`.

### (a.3) Where this contradicts the current design.md

| design.md says | Code says | Proposed fix |
|---|---|---|
| §8.1 "`rama` 0.4, pinned exactly as Codex does" | Codex pins `rama-* =0.3.0-alpha.4` (`network-proxy/Cargo.toml`) | Choose the rama version on its own merits (the gateway study); drop "as Codex does" |
| §7 row 1 / §2 "netns with no interface + **UDS-bridged** proxy" | Codex's fd handoff removes the UDS file, the in-box forwarder and the AF_UNIX exception; srt's socat bridge has none of those advantages | Process tier uses the listener-fd handoff; the UDS bridge remains for gVisor |
| §7 row 1 "seccomp (srt's and Codex's rules)" | Codex has no namespace-escape rules and no userns limit | "srt's namespace filter + bwrap's `max_user_namespaces=1` + nested userns + Codex's `ProxyRouted` socket allowlist" |
| §8.1 "per-sandbox CA (`rcgen`, name-constrained to the zone's hosts)" | A CA constrained to the current hosts cannot cover a host granted later without restarting Node | Constrain to the zone ceiling, or keep it unconstrained and ephemeral |
| §6 T2 "Codex via `codex-acp`" | `codex app-server` has native typed permission requests with narrower grants | Add a Codex app-server adapter (T1-like) and test both in E1 |
| §7 row 4 "Mac M3+ `vz`/libkrun variant" for snapshot work | libkrun has **no pause or snapshot on Linux** (`docs/vm-lifecycle.md`); microsandbox's checkpointing lives in its `msb_krun` fork | Linux parking needs Firecracker, gVisor or microsandbox; libkrun on Linux parks by freeze only |
| §7 row 5 "e2b — bring-your-own-proxy forces all egress through ours" | BYOP and MITM are **E2B Cloud/BYOC only**; the OSS `e2b-dev/runtime` ships `NoopEgressProxy` and a default-allow SNI/CIDR filter | The e2b backend is cloud-only; self-hosted E2B gets no forced proxy |
| §3.1 jail helper "started with the privileges needed to build namespaces" | Every VM project that skipped jailing ended up with a VMM that has full user or root authority | The helper also wraps VMMs and runsc. Ship an AppArmor `userns` profile; don't flip the sysctl |

### (a.4) Isolating MCP servers and provisioning capacity

This responds to the owner's ask: wicket manages its own infrastructure, including running MCP servers isolated from each other.

**What the projects actually do.**

| Project | Unit of isolation for an MCP server or tool | Secrets | Lifetime and cross-task state | Warm pool / late binding | Placement and bootstrap |
|---|---|---|---|---|---|
| **toolhive** | **One container per MCP server.** Profile `{read[], write[], network:{mode host\|bridge\|none, outbound:{insecure_allow_all, allow_host[], allow_port[]}, inbound}, privileged}`. With `isolate_network` + bridge, each server gets its own `Internal:true` network with its *own* dnsmasq, egress-Squid and ingress-Squid sidecars. Without it, all servers share `toolhive-external` and can reach each other. Workloads get `CapDrop: ALL` but `label:disable` | **Env vars in the server** (keyring/1Password → `EnvVars`; K8s `SecretKeyRef`). The server holds real tokens | Long-lived (`unless-stopped`), shared by every client; RunConfig and write mounts persist, so cross-task memory is the default | none | Local Docker/Podman; K8s operator → StatefulSet per server; no node bootstrap. Gaps: the DNS sidecar resolves any name (exfil channel), unpinned `dnsmasq:latest`, Squid sees CONNECT host only (no TLS) |
| **agent-sandbox** | Pod + `runtimeClassName` (gVisor/Kata) + template-wide IP-level NetworkPolicy (blocks cluster DNS and RFC1918) | Env on the claim only, which **forces a cold start** | A claim never returns a pod to the pool; Suspend deletes the pod and keeps PVCs | `SandboxWarmPool` keeps N Sandboxes; a claim **transfers the controller ownerRef pool→claim and stamps labels**. Labels are the only thing bound late | kube-scheduler. gVisor node install script: pinned tarball + sha512, `gvisor-bin/`, containerd runtime stanza, RuntimeClass, smoke pod |
| **OpenHands sdk** | One hardened container per *conversation* (`--cap-drop ALL`, `no-new-privileges`, pids, mem and cpu limits); **stdio MCP servers run as subprocesses inside it**, so they share files, network and each other | Model key and secrets sent *into* the box | Per conversation, reattachable runtime dirs | Can claim from agent-sandbox warm pools | Docker, or the K8s pools |
| **container-use** | One Dagger container per *environment*; "services" are sibling containers bound by hostname | Secret URIs resolved by the Dagger client into env | Long-lived; layer chain and git notes are cross-task memory | — | Local Dagger engine |
| **microsandbox** (+ `microsandbox-mcp`) | One microVM per sandbox; a natural fit for one server per VM | Env placeholder + egress substitution. **microsandbox-mcp has a confused deputy**: the calling agent picks `secrets[].valueEnv` and `allowedHost` (`src/tools/sandbox.ts`, l.677), so an injected agent can name any host env var and send it to a host of its choice | Named, catalogued; volumes and snapshots persist only if reused | Image-layer cache, full snapshots, `msb fork` | Local binary; needs `/dev/kvm` |
| **E2B infra** | One Firecracker VM per sandbox | Guest env, or rule-side `${e2b.secrets.X}` (cloud proxy) | Per request, with pause/auto-resume, so cross-task memory equals snapshot reuse | **A sandbox is a resumed pre-booted snapshot**. Identity is bound late by a held `POST /init` with a fresh envd token and CA | `BestOfK` scoring after hard filters, including a **`HostIsolation` partition** (artifacts from isolated hosts run only on isolated hosts); Nomad/K8s node pools |
| **sandstorm** | runsc container or FC VM per sandbox, /30 netns each, own cgroup and writable layer | Env only | Long-lived, demoted hot→frozen→snapshot→detached | Checkpointed warm templates with an **`after_restore` reseed** (PRNG, OpenSSL DRBG and hash seeds were identical across children); pre-built netns pool | Fingerprinted pools (runsc version, kernel, CPU flags); nodes self-admit on PSI and free memory; **`install.sh` with a single-use, CA-pinned token; the node dials out over mTLS**; systemd with an explicit `CapabilityBoundingSet`; a restart *adopts* running sandboxes |
| **nono** | **One fresh command sandbox per tool invocation**, with its own FS, network, env and credential grants | Phantom tokens resolved per consumer (route) | Per call | — | Unprivileged binary on the host |

No project combines all of the following: per-server isolation, no secrets in the server, per-task lifetime and no shared DNS. That combination is what wicket should build.

**Design for wicket** (proposed additions to §7 and §8.2, and a new §7.1 "Capacity"):
1. **Third-party MCP server = a zone-less tool sandbox, one per (server, task).**
   - It uses the same `Sandbox` trait and backends as agents: process tier, or gVisor for unvetted code.
   - It gets its own UID, netns (listener-fd handoff, no interface), mount view and cgroup. It never shares a netns, filesystem or UID with another server or with the agent, so servers cannot see each other by construction.
   - Its egress goes through `wicket-egress` under a **toolhive-shaped profile** (`read`, `write`, `outbound.allow_host/port`) compiled from the adapter catalog.
   - It holds **placeholders only**; real credentials are injected at its egress.
   - The gateway reaches it over a wicketd-held stdio or UDS pipe.
2. **Per task by default.** Write mounts are task-scoped and deleted at task end (§11). A long-lived server is allowed only if it is declared stateless and is restored from a clean template per task. Otherwise its state is labelled memory under a `Declassify` gate.
3. **The credential binding never comes from a caller.** The credential→host-template binding comes only from the vault and adapter (microsandbox-mcp lesson). Detectors such as trufflehog (gondolin) may *propose* a binding for human approval.
4. **CLI tools** (`gh`, `aws`) can be run the same way, as per-call tool sandboxes (nono) behind gateway-native tools (change 14).
5. **Warm pools with explicit late binding.**
   - `wicketd` keeps N pre-started, identity-less sandboxes per (image, profile).
   - On claim, `wicket-jail` binds the netns listener, the per-box CA, the placeholder env and the zone label in the proxy's listener→agent map, then runs an `after_restore` reseed.
   - A claimed sandbox is never reused. Anything that cannot be bound late forces a cold start (agent-sandbox).
   - Nothing task-specific is baked into the template, and the guest agent is never the authority for identity (E2B's `/init` is convenience, not security).
6. **Scheduling** (§7 scheduler): hard filters first (isolation floor, snapshot need, KVM present, host fingerprint, E2B-style origin partition so tainted-zone snapshots stay on their host class), then scoring (least loaded, best-of-K). Snapshots carry the host fingerprint and are parked or restored only within that pool. v1 is a single host with cgroup v2 budgets and a slot count.
7. **`wicket-host` bootstrap** (sandstorm's pattern plus agent-sandbox's gVisor install; for extra Vultr boxes via the provisioning broker):
   - cloud-init fetches `wicket-host` with a single-use, CA-pinned token;
   - it installs a pinned runsc with sha512 (including `gvisor-bin/`), the `wicket-jail` AppArmor `userns` profile, a `/etc/subuid` range for per-box UIDs and cgroup v2 delegation;
   - `preflight` records the Landlock ABI and errata, seccomp actions, KVM presence and runsc platform into the host's `Capabilities`, and refuses to register if any declared layer is missing;
   - the node **dials out** to `wicketd` over mTLS (identity = issued cert; no inbound port);
   - systemd runs it with an explicit capability set;
   - desired state lives in wicketd's SQLite, and a restart adopts rather than kills;
   - the broker releases the box at the end of its paid hour only when no task or parked snapshot is pinned to it (migrate within the fingerprint pool, or terminate first).

### (b) Project table

| name | url | licence | lang | local path | what wicket takes | relevance (1–3) |
|---|---|---|---|---|---|---|
| sandbox-runtime (srt) | https://github.com/anthropic-experimental/sandbox-runtime | Apache-2.0 | TypeScript, C | refs/repos/sandbox-runtime | decider protocol and strictness rules; `srt proxy` as differential reference; namespace-escape seccomp rules and nested PID/mount layout (ported); cloud-metadata list; negative lessons: body/header substitution reflects secrets, warn-and-continue, launch-time scans | 3 |
| codex (codex-rs) | https://github.com/openai/codex | Apache-2.0 | Rust | refs/repos/codex | vendor `proxy_routing.rs` (listener-fd handoff), `seccomp.rs` ProxyRouted, `authorization_path.rs`, `process-hardening`; shaped placeholders; execpolicy examples-as-tests; app-server `permissions/requestApproval` as a Codex pending path; rama pin fact | 3 |
| nono | https://github.com/nolabs-ai/nono | Apache-2.0 | Rust | refs/repos/nono | per-tool command sandboxes → CLI-wrapping gateway tools; ADDFD runtime FS grants; per-consumer phantom tokens; approval-webhook contract and "no reachable decision socket" rule; negative: seccomp-notify CONTINUE egress is TOCTOU | 3 |
| httpjail | https://github.com/coder/httpjail | CC0-1.0 | Rust | refs/repos/httpjail | seccomp BPF with x32 kill and netns nftables ruleset (copy freely) for transparent mode; `proc` engine as a second differential reference; negative: persisted CA key, no FS isolation | 2 |
| hakoniwa | https://github.com/souk4711/hakoniwa | LGPL-3.0 w/ linking exc. (lib), GPL-3.0 (CLI) | Rust | refs/repos/hakoniwa | parent/child setup handshake; Landlock Hard/BestEffort split; TUN-fd-to-host idea; AppArmor `userns` profile; cautionary capability gap | 2 |
| birdcage | https://github.com/phylum-dev/birdcage | GPL-3.0 | Rust | refs/repos/birdcage | nested userns after mount setup; `mount_setattr(AT_RECURSIVE)`; clone3→ENOSYS (ideas only) | 2 |
| extrasafe | https://github.com/boustrophedon/extrasafe | MIT | Rust | refs/repos/extrasafe | `YesReally` API shape; negative lessons (masked-equal socket filter, ignored `restrict_self`) → table-tested filters | 1 |
| nsjail | https://github.com/google/nsjail | Apache-2.0 | C++ | refs/repos/nsjail | fd-relative new-mount-API construction; PDEATHSIG race check; cap/bounding-set drop; unotify learn mode; nstun ENCAP_CONNECT design for rootless transparent mode | 3 |
| bubblewrap | https://github.com/containers/bubblewrap | LGPL-2.1+ | C | refs/repos/bubblewrap | `max_user_namespaces=1` + userns #2 trick; fallback subprocess | 2 |
| rust-landlock | https://github.com/landlock-lsm/rust-landlock | Apache-2.0 OR MIT | Rust | refs/repos/rust-landlock | dependency; per-right CompatLevel; `FullyEnforced` check; Erratum probe; V9/V10 rights | 3 |
| zerobox | https://github.com/afshinm/zerobox | Apache-2.0 | Rust | refs/repos/zerobox | proof and script that Codex sandbox crates extract cleanly; negative: unscoped secret matches all hosts | 2 |
| gVisor (runsc) | https://github.com/google/gvisor | Apache-2.0 | Go | refs/repos/gvisor | gvisor backend: `--network=none --host-uds=open`, `checkpoint --save-restore-exec-argv` park hook, background restore; `--network-proxy-path` later | 3 |
| agent-sandbox | https://github.com/kubernetes-sigs/agent-sandbox | Apache-2.0 | Go | refs/repos/agent-sandbox | template/warm-pool/claim split; "task-specific bits force cold start" rule; gVisor node install recipe; future k8s backend | 2 |
| container-use | https://github.com/dagger/container-use | Apache-2.0 | Go | refs/repos/container-use | branch-per-env in a separate bare repo with hooks off; negative: host-side export with lexical path check, privileged nesting | 1 |
| toolhive | https://github.com/stacklok/toolhive | Apache-2.0 | Go | refs/repos/toolhive | permission-profile shape for per-server sandboxes; internal network + per-server sidecars; negative: open DNS sidecar, secrets in env, long-lived shared servers | 2 |
| OpenHands software-agent-sdk | https://github.com/OpenHands/software-agent-sdk | MIT | Python | refs/repos/openhands-sdk (frontend: refs/repos/OpenHands) | data point; negative: model key and MCP servers inside the box | 1 |
| SWE-ReX | https://github.com/SWE-agent/SWE-ReX | MIT | Python | refs/repos/SWE-ReX | negative lesson for exec channel (no PS1 sentinels, no host TCP port) | 1 |
| microsandbox (+ microsandbox-mcp) | https://github.com/superradcompany/microsandbox | Apache-2.0 | Rust | refs/repos/microsandbox, refs/repos/microsandbox-mcp | optional KVM/HVF backend via SDK (jailed, outbound proxy → wicket, its MITM bypassed); DNS pin set; Host==SNI check; placeholder tripwire; negative: shared CA, unjailed VMM, caller-chosen secret binding | 3 |
| libkrun | https://github.com/libkrun/libkrun | Apache-2.0 | Rust | refs/repos/libkrun | `krun` crate with virtio-net-over-UDS; never TSI `HIJACK_UNIX`; no Linux snapshot | 2 |
| firecracker | https://github.com/firecracker-microvm/firecracker | Apache-2.0 | Rust | refs/repos/firecracker | official jailer as-is; `<uds>_<port>` vsock attachment; restore-once parking; VMGenID | 3 |
| fctools | https://github.com/rust-firecracker/fctools | MIT | Rust | refs/repos/fctools | FC API and snapshot models; avoid its sudo-password spawners | 1 |
| sandstorm | https://github.com/deeplethe/sandstorm | Apache-2.0 | Rust | refs/repos/sandstorm | vendor runsc freeze/checkpoint/restore/seal/may_restore; tier ladder; lower-layer immutability; warm-template reseed; host bootstrap and fingerprinted pools | 3 |
| gondolin | https://github.com/earendil-works/gondolin | Apache-2.0 | TypeScript | refs/repos/gondolin | synthetic DNS; placeholder hygiene; host-served VFS as model for handle reads; detector-suggested secret hosts | 2 |
| E2B infra (runtime) | https://github.com/e2b-dev/infra | Apache-2.0 | Go | refs/repos/e2b-infra | dial-name + IP check in dialer control hook; rule-side `${secrets.X}` templates; late identity binding via held `/init`; BestOfK + HostIsolation placement; OSS has no BYOP/MITM | 2 |
| E2B SDK | https://github.com/e2b-dev/E2B | Apache-2.0 | TS, Python | refs/repos/E2B | BYOP API shape (SOCKS5 over TLS, fail closed, cloud-only); DNS server allowlist | 2 |
| daytona (v0.190.0) | https://github.com/daytonaio/daytona | AGPL-3.0 | Go | refs/repos/daytona | nothing; negative evidence (privileged containers, CIDR-only egress); repo now archived and private | 1 |
| pullrun | https://github.com/pullrun/pullrun | Apache-2.0 / MIT | Rust, Go | refs/repos/pullrun | nothing (open bridge + MASQUERADE, jailer unused); maybe ext4-from-OCI | 1 |
| arrakis | https://github.com/abshkbh/arrakis | AGPL-3.0 | Go | refs/repos/arrakis | idea only: snapshot as typed undo point | 1 |
| cua / lume | https://github.com/trycua/cua | MIT | Swift | refs/repos/cua/libs/lume | macOS VZ recipe: file-handle network to a user-mode gateway, `saveMachineState` parking | 2 |
