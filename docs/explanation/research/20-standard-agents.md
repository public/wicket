# 20 — Standard Agents (the Standard Agent Specification and Standard Agents Builder)

Research date: 2026-11-10. Scope: what "Standard Agents" (the owner's "Schroeder's Standard Agents") is,
how its agents are defined, run and secured, how mature it is, and what it means for wicket.

Confidence tags, as in [16] and [17]:
- **[H]** read in the project's primary docs or shipped code in this session;
- **[M]** from a README, a vendor page, a talk listing or a secondary source, not checked in code;
- **[L]** metadata only (stars, licence, download counts), or a guess.

Method: the whole 0.2.0 specification was read as raw markdown from the site's `llms.txt` index, plus the
0.1.0 overview and agents pages. GitHub health came from `gh api`; npm metadata from the registry. The npm
tarballs of `@standardagents/spec`, `@standardagents/builder` and `@standardagents/anthropic` were
downloaded and read as data (minified bundles, so code-level claims about the Builder are grep-level).
Nothing was installed, built or run.

---

## 0. Summary

- **What it is.** "Standard Agents" is two things from one small company, FormKit, Inc. (trading as Standard
  Agents), whose lead is **Justin Schroeder** (creator of FormKit, ArrowJS, AutoAnimate, Tempo and dmux)
  [H: [community](https://standardagentspec.org/community), [GitHub profile](https://github.com/justin-schroeder)]:
  1. the **Standard Agent Specification**: an MIT-licensed, versioned (0.1.0, now 0.2.0) spec for writing an
     agent entirely in TypeScript (model, prompt, tools, hooks, sub-agents, storage) so it can be packed as an
     npm package and run on any runtime that conforms [H: [overview](https://standardagentspec.org/0.2.0/getting-started/overview/)];
  2. **Standard Agents Builder** (AgentBuilder): the only runtime that exists, a proprietary hosted platform
     on Cloudflare Workers and Durable Objects, with a Vite plugin for local development
     [H: [runtimes](https://standardagentspec.org/runtimes), npm `license: UNLICENSED`].
- **It is an agent framework with a spec in front, not a protocol between agents and not a sandbox.** It owns
  the agent loop: the runtime assembles context, calls the model, runs tools in order and stores everything
  per thread. Its pitch is *composition over inheritance*: many small domain-specific agents (a "Gmail agent")
  instead of one general agent loaded with MCP servers and skills [H]. That is the opposite layer from wicket,
  which never runs a loop and boxes agents that already have one.
- **Its security model lives inside the runtime.** It has write-only, origin-scoped **credential grants**
  injected by the runtime on `fetch`; a **`runCode` sandbox** with no ambient globals; closed `uses` lists;
  and **parent hooks** that must be disclosed and fail closed [H]. But tools, hooks and handlers are "trusted
  definition code" that run with the full thread state, can read `secret` environment values, and (on
  Workers) can call `fetch` freely. Several limits are opt-in (`uses`, `maxInstances`, `maxSessionTurns`, no
  wall-clock timeout) [H]. Its approval gate is a child agent whose model presents the request and
  *records* the human's answer [H].
- **Interop.** Models come in through per-vendor provider packages (OpenAI, Anthropic, Google, Groq, xAI,
  OpenRouter, Cerebras, Cloudflare and others) [H]. Agents are reached through the spec's own HTTP and
  WebSocket **Thread Client API** [H]. Skills follow the agentskills.io format [H]. The spec defines no
  MCP, ACP or A2A surface; the Builder reportedly exposes agents as MCP tools [M].
- **Maturity.** Young, single-vendor, moving fast. The types package `@standardagents/spec` has had 199
  versions since 2026-01-09 (0.45.3 published today), with about 1,300 downloads a week [L]. Its document
  model changed shape between spec 0.1.0 and 0.2.0 [H]. The spec repository and the Builder monorepo are not
  public (both 404 through `gh api`) [H]. No other runtime is listed, and no third-party coverage was found
  beyond Schroeder's AI Engineer World's Fair 2026 talk, at which the company called itself "still largely in
  stealth" [M].
- **For wicket.** It doesn't change the architecture. A Standard Agents project could run as a **T3 service
  workload**: Builder's dev server in a gVisor box, driven over its Thread Client API, with model calls routed
  to the LLM proxy by a wicket-generated provider extension. That needs experiments (workerd under gVisor,
  workerd's outbound proxy and CA handling, running without the hosted platform account). It is also blocked
  for Claude models by the owner's no-API-key rule. The better fit is as a **service zone** (§8.2) that has its own
  LLM route: "an agent as a tool" is an MCP-server-shaped workload that also calls a model.
- **Worth borrowing:** the credential-grant record and its rules, closed `uses` lists, "installing is inert;
  composing is the act that gets disclosed", schema-checked spawn arguments with a structured refusal, the
  `runCode` conformance checklist (for the Wasm codemode tier), single-use stream tickets bound to an exact
  path, and the typed `decide()` answers (for wicket's own LLM calls). **Avoid:** approvals recorded by a
  model, secrets readable by packaged code, limits that default to unlimited, and a security boundary that
  exists only inside the runtime.

---

## 1. Establishing what "Standard Agents" is

### 1.1 The match covered

Searching for "Justin Schroeder Standard Agents" finds nothing directly. Searching for "standard agents"
plus "spec" finds the specification site, whose community page names Schroeder as lead maintainer and
co-founder [H]. Evidence that this is the owner's "Schroeder's Standard Agents":

| Claim | Source | Tag |
|---|---|---|
| "Justin Schroeder is the lead maintainer of the specification. He is a co-founder of Standard Agents … He created … ArrowJS, AutoAnimate, dmux, FormKit, and Tempo" | [standardagentspec.org/community](https://standardagentspec.org/community) | [H] |
| "published in 2026 by the FormKit and Standard Agent Builder team and is MIT licensed" | [0.1.0 overview](https://standardagentspec-com.pages.dev/0.1.0/getting-started/overview) | [H] |
| GitHub bio: "Full stack engineer @standardagents, @formkit. Creator of dmux, ArrowJS, FormKit, Tempo, AutoAnimate" | `gh api users/justin-schroeder` | [H] |
| The company operates as FormKit, Inc., doing business as Standard Agents; Andrew Boyd is a founder | [ai.engineer/orgs/standardagents](https://ai.engineer/orgs/standardagents) | [M] |
| npm maintainers of `@standardagents/*`: `justin-schroeder`, `boyd`, `stolinski`, `lnguyen-braid` | npm registry | [L] |
| Talk: "The Future Is Domain-Specific Agents", AI Engineer World's Fair 2026 (30:38) | [ai.engineer talk page](https://ai.engineer/talks/spNAUEgq_A8-future-is-domain-specific-agents) | [M] |

Domains: the spec lives at **standardagentspec.org** (`standardagentspec.com` redirects there; an older copy is
at `standardagentspec-com.pages.dev`). The Builder lives at **standardagents.ai** (`standardagentbuilder.com`
redirects there). `standardagents.com` is a parked Markmonitor page [H, by HTTP probe].

### 1.2 Other things with similar names (not covered)

| Name | What it is | Why it's not the target |
|---|---|---|
| **Open Agent Spec** (`oracle/agent-spec`, Apache-2.0, 449★, pushed 2026-10-28) | Oracle's declarative, framework-agnostic language for agents and workflows; arXiv 2510.04173 | Oracle, not Schroeder [L] |
| **The-Standard-Agent-Specs** (`hassanhabib/…`, 0★, created 2026-07) | "Specs for Creating Standard Compliant AI Agents", tied to Hassan Habib's "The Standard" engineering method | Different author, no adoption [L] |
| **Agents Standard** (`agentsstandard-dot-com.pages.dev`) | A hierarchical `AGENTS.md` configuration convention | Instruction files, not agents [L] |
| **gitagent** (`open-gitagent/gitagent`, MIT, 751★) | A git-native agent definition (identity, rules, memory, tools as files) | Different project; possibly worth its own note [L] |
| **.iblai Agent Standard** ([ibl.ai](https://ibl.ai/developer/agents/standard.md)) | A Markdown agent-definition file format | Vendor format [L] |
| "Standard agent" | A US real-estate agency term | Unrelated |

Schroeder's adjacent projects are summarised in §2.7: **dmux** (agent multiplexer), **ArrowJS**'s
QuickJS/WASM sandbox, and **Standard Code**, the company's hosted coding-session product.

---

## 2. What the specification defines

### 2.1 Shape and principles

The spec's five principles are: agents, not models, are the unit of AI software; agents should be
domain-specific, vendor-agnostic, composable and portable [H: overview]. "Agents are *deterministic* software
that harnesses the non-deterministic results produced by LLMs." It defines the runtime language as well:
"Standard Agents also defines a runtime: TypeScript. There is no need to run a full MCP server just to
implement a custom tool" [H: 0.1.0 overview]. Its FAQ answers "framework or specification?" with "an open
source specification … AgentBuilder is one such implementation" [H].

Spec 0.2.0 sections [H: [llms.txt](https://standardagentspec.org/llms.txt)]: Providers, Models, Tools,
Effects, Prompts, Handlers, Agents, Subagents, Threads (Messages, File System, Code Execution, Runtime
Streams, Execution State, Decisions, Thread Endpoints, Thread Client API), Users, Hooks, Type Registry,
Runtime, Packaging. Normative text uses RFC 2119 words throughout.

### 2.2 The agent model

**Definition format: TypeScript code**, using `defineAgent`, `definePrompt`, `defineTool`, `defineModel`,
`defineHook`, `defineHandler`, `defineEffect` from `@standardagents/spec`, with Zod schemas for arguments
[H: [agents](https://standardagentspec.org/0.2.0/specification/agents),
[tools](https://standardagentspec.org/0.2.0/specification/tools)]. Projects use a conventional `agents/`
directory layout, and a build-time **type registry** gives autocompletion and compile errors for names [H].

**An agent is a conversation between two sides** [H: agents §1]:

| Side backing | Who takes the turn | Declared as |
|---|---|---|
| Human | a person, "via whatever interface the runtime provides" | `{ human: true }` |
| Prompt | a model, driven by a named prompt (system prompt, model, tools, reasoning, hooks) | `{ prompt: 'name', … }` |
| Handler | deterministic code, called once per inbound message | `{ handler: 'name' }` |

Spec 0.1.0 had two fixed types instead (`ai_human`, and `dual_ai` with a `sideA`/`sideB` pair), and
sub-agents were declared inside a prompt's `tools` list. In 0.2.0 sub-agents moved to a `subagents` array on
the side that owns them [H: comparing the 0.1.0 and 0.2.0 agents pages]. A common pattern is
worker/reviewer: side A produces, side B validates before `sessionStop` [H].

**Tools** are of three kinds: function tools (`defineTool`, with `execute(state, args)`), prompt tools (a
sub-prompt run as a tool), and agent tools (hand-off to another agent on the same thread) [H: tools §1].
A tool may declare `uses`, the closed list of tools, prompts or agents it may invoke by name. With a list,
the runtime MUST reject other targets; **without one, there is no restriction** [H: tools §2.1].

**Stopping** is declarative: `sessionStop` and `sessionFail` bind a tool whose arguments become the
result, then `stopTool`, `stopOnResponse`, and the safety caps `maxSteps` and `maxSessionTurns`. The caps are
optional on every agent ("a voluntary safety valve") [H: agents §1.3, §4].

**Sub-agents** are any agent composed as a child, run in its **own thread** (messages, file system, queue,
lifecycle) [H: [subagents](https://standardagentspec.org/0.2.0/specification/subagents)]. Each relationship
sets `blocking`, `immediate` (spawn at thread creation), `maxInstances` (unset = unbounded), `optional` (an env
flag gates it), `hidden` (code can spawn it, the model never sees the tool), `scopedEnv` (values copied into the
child as "runtime-only transfer data", never shown to the model) and `parentCommunication` (`implicit` queues
the child's result to the parent; `explicit` leaves that to code). Spawn arguments are validated against the
child's `requiredSchema`, persisted for the child's whole life, and missing ones are refused with a
structured `subagent_arguments_required` error. Attachments are **copied** across thread boundaries, never
linked [H: runtime §7–8].

**Memory and state, per thread** [H: [threads](https://standardagentspec.org/0.2.0/specification/threads)]:
- message history, with hooks (`filter_messages`, `prefilter_llm_history`, …) that reshape context per request;
- a virtual **file system** per thread (paths relative to the thread root; not POSIX);
- a durable **key-value store**, isolated per thread and never copied to children;
- layered **environment variables**: thread → agent → prompt → user → instance; values typed `text` or
  `secret`; `setEnv` propagates to active descendants; `instanceEnv` reads *only* the runtime instance's value,
  for trust anchors such as a service URL and its credential;
- **skills** in the agentskills.io format, scoped to the thread owner, with administrator-reviewed shared
  skills that tenant code MUST NOT change;
- **effects**: scheduled callbacks (alarms) that start execution later.

**Lifecycle.** Threads are durable and long-lived: a session end (stop, fail, error, turn cap) "MUST NOT
terminate a child thread; only explicit termination destroys an instance". `terminate()` is a soft shutdown
[H: runtime §10]. Runs are triggered by a user message, a queued message, a queued tool or an effect alarm,
and there is one execution at a time per thread [H: runtime §2, §11].

**Decisions** are a separate primitive: `state.decide()` asks a model named, typed questions (`choice`,
`score`, `boolean`) and gets back probabilities, without advancing the conversation [H:
[decisions](https://standardagentspec.org/0.2.0/specification/threads/decisions)].

**Packaging.** An agent packs into a self-contained npm package exporting registries of agents, prompts,
tools, models, hooks and handlers. A packed agent MUST NOT depend on private runtime RPCs or storage schemas.
Tools that touch `_notPackableRuntimeContext` (platform bindings such as a D1 database) can't be packed [H:
[packaging](https://standardagentspec.org/0.2.0/distribution/packaging), threads §10].

### 2.3 How agents are run and hosted

The spec's **runtime** section requires sequential steps per thread (drain queue, assemble context, call the
model, persist, run tool calls in order, persist, evaluate stop), tool errors persisted rather than crashing
the loop, durable FIFO queues ("should survive DO eviction", that is, Durable Object eviction), and no
concurrent execution within a thread [H: [runtime](https://standardagentspec.org/0.2.0/infrastructure/runtime)].
The text assumes a Cloudflare-shaped host in places.

A runtime SHOULD expose the **Thread Client API**: `GET agents`, `POST/GET/PATCH/DELETE threads`, read and
send messages, read thread files, `POST …/stop`, and a WebSocket stream. Every HTTP route takes
`Authorization: Bearer`; the WebSocket upgrade takes a **single-use stream ticket valid only for one exact,
normalised path**; internal failures must be 5xx; the first stream frame is a status snapshot [H:
[client API](https://standardagentspec.org/0.2.0/specification/threads/client-api)].

**Standard Agents Builder**, the one runtime:
- runs on **Cloudflare Workers**; each thread is a Durable Object with its own SQLite database [H: runtimes
  page; M: ai.engineer org page]. The generated config binds `AGENT_BUILDER_THREAD` and `AGENT_BUILDER`
  Durable Object namespaces and a Worker Loader [H: `@standardagents/cli` README];
- is used through a Vite plugin (`builder()`) that injects the Cloudflare Vite plugin, the Worker entry and
  the bindings. Local development is the Vite dev server on `127.0.0.1`, which runs workerd [H: CLI README];
- `npx @standardagents/cli init` **signs in to a Standard Agents account in the browser** ("the account
  supplies inference for your agents"). It clones a platform-owned git repository, writes
  `STANDARD_AGENTS_API_KEY` and the platform endpoints to `.dev.vars`, and installs a repo-local git credential
  helper that mints short-lived tokens from the platform. Deployment is `git push` to that repository [H: CLI
  README]. The bundle defaults its platform origin to `https://api.standardagents.ai` [H: grep of
  `@standardagents/builder` 0.45.3];
- the bundle also has a `SUPER_ADMIN_PASSWORD` + `ENCRYPTION_KEY` bearer path. That suggests a deployment can
  authenticate without the platform, but it is not documented and was not tested [L];
- provider packages read keys from Worker environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `CEREBRAS_API_KEY`, …) [H: builder runtime provider catalogue]. The Anthropic provider wraps
  `@anthropic-ai/sdk` and exposes Anthropic's server-side `web_search` as a provider tool [H: its README];
- the company also offers hosting ("Domain-specific agents deployed to our global edge network") behind a
  waitlist [H: [standardagents.ai](https://standardagents.ai)].

### 2.4 Security, sandboxing, credentials and permissions

What the spec provides [H unless marked]:

| Mechanism | What it guarantees | Limits |
|---|---|---|
| **Credential grants** ([users §6](https://standardagentspec.org/0.2.0/specification/users)) | A named, user-scoped credential `{kind: bearer\|header\|query\|basic\|signing, origins, inject{header,format,query}, allow{tools,endpoints,userEndpoints,userRooms,agents}}`. The secret is write-only (not readable by packaged code, models or clients). The runtime injects it in `user.fetch(grant, …)`, rejects destinations outside `origins` and callers outside `allow` (**absent `allow` denies everyone**), keeps it out of errors, logs and traces, and makes revocation fail distinguishably from a network error. | Opt-in: nothing stops a tool calling plain `fetch` with a key from `state.env`. Origins may be suffix wildcards. |
| **Secret env values** | `type: 'secret'` values "should be encrypted at rest" and "should be redacted from tool output and logs" | **Readable by tools** via `state.env()`. Redaction is advisory. |
| **`instanceEnv`** | A trust anchor that thread or user values can't override | Optional capability |
| **`runCode` sandbox** ([code execution](https://standardagentspec.org/0.2.0/specification/threads/code-execution), runtime §14) | A fresh isolate per call; `globalThis` holds only ECMAScript intrinsics (no `fetch`, `process`, timers, `WebAssembly`, `crypto`); capabilities only through `imports`/`globals`; no `eval`, `new Function`, `SharedArrayBuffer`, `Atomics` or URL imports; structured-clone marshalling; memory cap status; `terminate()` settles within 50 ms | Covers code the model writes, **not tools, hooks or handlers**. No wall-clock timeout ("Runtimes MUST NOT invent one silently"). The Builder creates these isolates with `globalOutbound: null`, so no network [H: grep]. |
| **Closed `uses` lists** | A tool can invoke only declared targets | Only when the list is present |
| **Parent hooks** (agents §6) | A child may require hooks that run on its *parent's* thread. "Downloading or installing a package is inert"; adding the child to a parent is the composition act, and UIs MUST disclose the hook ID, reason and stage first. Missing or unloadable hooks fail composition closed. | A child gets code running on the parent's state by design |
| **Skills** | Owner-scoped; shared library changes need an admin principal | |
| **Human approval gate** (agents §7) | A child agent with a human side parks in `awaiting_human` | Side A is a *prompt* that "renders the request, records the outcome". The spec doesn't say who the human is or how they answer. |
| **Client API auth** | Bearer on HTTP; single-use, exact-path stream tickets | Identity and authentication are runtime-defined |

Handlers "are trusted definition code, like tools" [H: handlers §1]. So the spec's trust model is: the agent
package is trusted, the model's code is sandboxed, and credentials are protected only if authors use grants.
The talk says each agent has "sandboxed code execution" meant to prevent exfiltration and access to the
surrounding OS, and that each specialist starts with "an explicitly approved, smaller set of actions" [M].
There is no process, network or file-system isolation of the runtime itself; on Cloudflare that is the
Workers isolate model.

### 2.5 Interop

- **Model APIs:** first-party provider packages for Anthropic (Messages), OpenAI, Google, Groq, xAI,
  OpenRouter, DeepInfra, Novita, Cerebras, Cloudflare Workers AI, and an LM Studio stub. "Provider extensions"
  give OpenAI-compatible endpoints their own identity, base URL and key. `ProviderFactoryConfig` takes
  `baseUrl`, `defaultHeaders` and a **`fetch` transport override** that providers MUST honour [H:
  [providers](https://standardagentspec.org/0.2.0/specification/providers)]. The base OpenAI slot gives
  `baseUrl` a default but no environment variable, so pointing it elsewhere takes an extension (code) [H].
- **MCP:** absent from the spec except as the thing it argues against ("The answer isn't Model Context
  Protocol (MCP) it's domain specific agents") [H]. The Builder exposes agents as MCP tools [M: ai.engineer
  org page]. The talk calls MCP's practical role "tool distribution" [M].
- **ACP, A2A:** not mentioned anywhere in the spec [H: grep of all pages].
- **Agent-to-agent:** only within one runtime (handoff and sub-agents). Across runtimes, only by packaging
  (npm) [H].
- **Skills:** agentskills.io format [H]. `npx @standardagents/cli skill` installs an `agentbuilder` skill
  into Claude Code, Codex and other coding agents, telling them to read the spec's `llms.txt`. The intended
  author of a Standard Agent is a coding agent [H: CLI README].

### 2.6 Maturity and adoption

| Item | Value | Tag |
|---|---|---|
| Spec versions | 0.1.0, 0.2.0 (current). "Published versions stay available and do not change." | [H] |
| `@standardagents/spec` (types, MIT) | 199 versions since 2026-01-09; 0.11.0 (2026-01-21) → 0.45.3 (2026-11-10); about weekly minor releases; ~1,312 downloads in the week to 2026-11-09 | [L] |
| `@standardagents/builder`, `cli`, `client`, providers | `license: UNLICENSED` (proprietary); builder 226 versions since 2025-12-03, ~800 downloads a week; 61 MB unpacked | [L] |
| Spec repository `standardagents/standardagentspec.com` | **Not public** (404). The runtimes page says a PR "needs access to the repository"; issues link to it. | [H] |
| Builder monorepo `standardagents/standardagents` | Not public (404), though npm metadata points to it | [H] |
| GitHub org `standardagents` | Created 2025-12-02, 20 public repos: ArrowJS (3,784★), dmux (1,819★), composer-api (348★), ssh-clipboard, jevpilot, music and others. None is the spec or runtime. | [L] |
| Runtimes | One (Builder). "A listing is not an endorsement, and it does not certify conformance." There is no conformance suite. | [H] |
| Governance | "No working groups, formal proposal process, or foundation". Discord plus GitHub; intent to "donate the specification once we identify a proper steward" | [H] |
| Product status | Builder behind a waitlist; "still largely in stealth"; "slowly opening access to a small number of users" | [M] |
| Third-party coverage | None found besides the AI Engineer listing and an aggregator write-up of the talk. 2026 surveys of agent standards (CSA, DEV) don't mention it. | [M] |

Talk claims such as "over 80% token efficiency" have no stated baseline or method [M].

### 2.7 Adjacent projects from the same team

- **dmux** (`standardagents/dmux`, MIT, 1,819★, v5.11.1 on 2026-08-16, 16 contributors) [L]: a tmux pane
  manager that gives each coding agent (Claude Code, Codex, Grok, Gemini CLI, …) its own git worktree and
  branch, then merges or opens a PR [M: README]. Isolation is the worktree only. Its launch table maps a
  per-pane `permissionMode` to each agent's flags, up to `--dangerously-skip-permissions` and Codex
  `--dangerously-bypass-approvals-and-sandbox`; the default `''` leaves the agent's own mode. It also has an
  "autopilot" setting [H: `src/utils/agentLaunch.ts`, `src/types.ts`]. That puts it in [16]'s session-manager
  group (worktrees plus the agent's own permission mode), not near wicket.
- **ArrowJS** (`@arrow-js/sandbox`): a "QuickJS/WASM-backed sandbox runtime" for running templates outside
  the host, which is one of the `runCode` approaches the spec lists [L: npm description].
- **Standard Code**: hosted cloud coding sessions with terminal, web, macOS and iOS clients, priced per
  active session line, with plugins that meter "Claude and Codex account quota" [M: ai.engineer org page,
  npm descriptions]. Whether it puts user subscription credentials in its sessions was not established [L].

---

## 3. Overlap with wicket

They sit at different layers. Standard Agents is a loop-owning framework and runtime (de Macedo's loop,
tools and context, plus in-runtime control). wicket supplies only control and containment, from outside,
for agents that already have the rest (design preamble). Where they meet:

| Concern | Standard Agents | wicket | Note |
|---|---|---|---|
| Credentials | Grants injected by the runtime on `user.fetch`; secrets in env readable by tools | No secrets in the box; injection at the proxies; placeholders only (§2 P2, §9) | Same idea; wicket enforces it below the agent rather than relying on authors |
| Sub-agents | Child threads, `maxInstances`, `scopedEnv`, schema-checked spawn args, copied attachments | Child zones; ceiling ⊆ parent (P5); typed fields and handles across gates (P6) | Their isolation is of *state*; wicket's is of *authority* |
| Approvals | Human-backed side; `awaiting_human` | Escalation broker, digest-bound, answered outside the box (§11) | Theirs is answered inside the conversation, recorded by a model |
| Code execution | `runCode`: no ambient globals, capability imports | Wasm codemode tier (§7 backend 6) | Very close in shape |
| Long-lived agents | Durable threads; only explicit termination destroys | Agents long-lived by default (P11, §13) | Theirs keeps memory with no promotion gate |
| Deterministic workers | Handler-backed sides | Programs (§17) | Theirs are trusted code inside the agent |
| Composition disclosure | Parent hooks disclosed before enabling; fail closed | Manifest approval; "the picture is generated from the enforcement config" (P7) | Shared instinct |
| Tool surface | Many small agents instead of many MCP tools | Gateway tools from adapters; service zones (§8.2) | Their "Gmail agent" is a service zone with a model |

Nothing in Standard Agents covers wicket's core: a box with no route out, an `Op` per crossing, labels,
handles, or grants that can't be answered from inside.

---

## 4. Running Standard Agents as wicket inner agents

### 4.1 What exists to run

There is **no agent CLI** in the Claude Code or Codex sense, and no headless "run this prompt" command. The
runnable unit is a Builder project: a Vite app that becomes a Cloudflare Worker, served locally by workerd.
You talk to it over the Thread Client API [H]. The Builder is proprietary, so wicket can't ship it in an
image. The user brings their own project and `node_modules`, and wicket treats all of it as untrusted.

### 4.2 Proposed adapter: T3, `Placement::Whole`, a service process driven over HTTP

```
box (gVisor floor, network: mediated)
  /work            the user's Standard Agents project (read-only lower layer), node_modules prebuilt
  .dev.vars        written by the LaunchPlan: placeholders only; the repo's own copy is ignored
  agents/providers/wicket_*.ts   generated, hash-pinned provider extensions: baseUrl -> LLM route at wicket.internal
  vite dev --host 127.0.0.1 --port <p>   (workerd inside)
host: wicket adapter
  POST {prefix}/threads {agent}  ->  POST {prefix}/threads/{id}/messages  ->  WS stream (ticket)
  typed result = the entry agent's sessionStop/sessionFail payload, schema-validated outside the box
```

- **Start and drive.** The adapter launches the dev server (or a prebuilt workerd config). It waits for
  `GET {prefix}/agents`, creates a thread, posts the task prompt, and follows the WebSocket stream for
  `thread_status`, `message_data` and `event` frames [H: client API]. `POST …/stop` is the interrupt. Thread
  deletion is "abort and discard". The `{runtime_prefix}` the Builder uses was not established [L].
- **Bearer for the client API.** It is held by wicket. The runtime listens on `127.0.0.1` inside the box,
  and wicket reaches it the same way it reaches other in-box servers.
- **Typed output.** Require the entry agent to end through `sessionStop` with an object-form binding.
  wicket validates the mapped payload against the task's output schema outside the box. Free-text results
  become handles (P6).
- **Pending path.** A wicket denial reaches tools as an HTTP error from the egress proxy or LLM route. The
  Builder persists tool errors as results and carries on (runtime §5.2), so a structured 403 with a
  `request_id` reaches the model. Whether models then wait and retry well is wicket's standard experiment
  (§19 M3). A **human-backed side** is a cleaner pending signal: its thread parks in `awaiting_human`.
  wicket could answer it, but only with a typed decision message, never free text from a requester.
- **Model route.** Provider packages call vendor URLs with keys from env. wicket generates a provider
  extension per allowed provider, with `baseUrl` set to the LLM route at `wicket.internal` and `apiKey` a
  zone placeholder. The spec's `fetch` override is an alternative for runtimes that inject it [H: providers
  §1]. The **Builder's own platform inference** (`STANDARD_AGENTS_API_KEY` to `api.standardagents.ai`) would
  be one more credential-bearing host behind the egress proxy, if the operator allows it at all.
- **Owner's credential rule.** Subscription tokens are for the unmodified Claude Code binary only, and there
  is never an Anthropic API key (§6). So **a Standard Agent under wicket can't use Claude models** through
  either route. It needs another provider the owner holds API access to (OpenAI, OpenRouter, Groq, …), with
  that vendor's terms.
- **Network.** workerd's outbound `fetch` may not honour `HTTPS_PROXY`. Open reports describe HTTPS `fetch`
  failing in Vite-plugin local dev [L: workerd issue #6746, workers-sdk #9356, via mirrors]. In `mediated`
  mode the box has no interface, so every vendor call must go to `wicket.internal` explicitly. Generated
  provider extensions cover model calls. Tools that call third-party APIs need either the egress proxy to
  work for workerd, or grants rewritten to go through wicket. workerd's CA trust for wicket's per-box CA is
  unverified.
- **Git and deploy.** Never in the box: no platform credential helper, no `agents deploy`. Output is the
  thread's results and files, extracted host-side.

### 4.3 What needs taint labels and preflight

| Item | Treatment |
|---|---|
| The project's `agents/` tree (prompts, tools, hooks, handlers, effects) and every npm dependency | Untrusted code with full thread state. Prompts and prompt includes are **context files** (taint list). Packed third-party agents from npm are the same. |
| `parentHooks` of composed children | Code from the child's package that runs on the parent's state. List them in the preflight view, as the spec itself requires a UI to. |
| `state.skills` (owner and shared libraries) | Instruction-like memory: §13.4 promotion gate; disabled for a task unless declared |
| Thread KV, thread files, Durable Object SQLite (`.wrangler/state` locally) | Agent memory and session state: labelled zone state, writes staged for promotion (§12, §13.4) |
| `.dev.vars`, `wrangler` and Vite config in the repo | `config_lockdown`: ignored and regenerated. `config_exec_vectors`: Vite plugins run arbitrary code at build time, so the build runs in the box, never on the host. |
| Anthropic `web_search` and other provider server-side tools | `server_side_tools`: taint ingress at the LLM proxy, rewritten or withheld (§6) |
| Effects (scheduled alarms) | `background_traffic`: they wake the thread and call models while "parked". Disable them, or count their traffic as not proving liveness. |
| `immediate` sub-agents | Spawn and call models before the first user turn; budget from launch |
| `scopedEnv`, `setEnv` propagation to descendants | Placeholders only. A value can flow to every active child, so treat the zone's env as shared by the whole thread tree. |
| Builder admin and platform variables (`SUPER_ADMIN_PASSWORD`, `ENCRYPTION_KEY`, `STANDARD_AGENTS_API_KEY`) | Reserved: set by the LaunchPlan as placeholders or local-only values, refused from `agent.env` |

`AgentCaps` sketch: `typed_output: terminating tool` (sessionStop); `steer: yes` (queued messages);
`host_tools: no` (no MCP client in the spec); `model_wire: per provider`; `server_side_tools: yes`;
`config_lockdown: file ownership only`; `session_store: yes` (Durable Object SQLite); `settled_signal:
thread_status idle`; `background_traffic: effects, immediate children`.

### 4.4 Alternative placement: a service zone for agents used as tools

A packed Standard Agent is meant to be used as **a tool by other agents**, and the Builder reportedly exposes
agents as MCP tools [M]. For wicket that is a §8.2 service zone: one sandbox per (agent package, task, zone),
reached only through the gateway, egress only through the proxy, reach equal to the package's declared
needs intersected with the caller's. The difference from an MCP server is that it **also needs an LLM route**
and its results are model output: free text, labelled with the join of its inputs and what it read, and
returned as handles or typed fields.

### 4.5 Experiments before an adapter is worth building

- **E-SA1:** the Builder dev server (workerd) starts under `runsc --network=none`.
- **E-SA2:** the Builder runs with no platform account (`SUPER_ADMIN_PASSWORD` path, no
  `STANDARD_AGENTS_API_KEY`) and makes no calls to `*.standardagents.ai`. Check with the DNS canary.
- **E-SA3:** model calls go only through a generated provider extension to the LLM route; nothing else
  leaves the box.
- **E-SA4:** workerd's outbound `fetch` honours the egress proxy and trusts the per-box CA, or the failure
  is clean.
- **E-SA5:** a 403 with a `request_id` from the egress proxy becomes a tool result, and the thread can be
  resumed after the grant without restarting the process.
- **E-SA6:** effects and `immediate` children produce no model traffic while the zone is parked.

Until E-SA1 to E-SA3 pass, Standard Agents is "any process" under T3, enforced only at the proxies.

---

## 5. What wicket should borrow

Ranked by value to wicket.

1. **The credential-grant record and its rules** (users §6). wicket's vault bindings already work this way.
   Take three rules into §9.4 and §9.5 as test cases: **an absent `allow` denies everyone**; revocation
   fails with an error **distinguishable from a network failure**; injected material never appears in
   errors, logs or traces visible to the box (already conformance item 12, *reflection*).
2. **"Installing is inert; composing is the act that's disclosed and approved"** (agents §6). This is a clean
   rule for wicket's manifests and service zones: pulling an image or package grants nothing. Adding it to a
   zone's topology is the escalation, and the approval card lists everything that comes with it (hooks,
   reach, servers). Missing or unverifiable pieces fail the composition closed.
3. **Closed invocation lists** (`uses`), with an empty list meaning no targets. This matches §17's
   closed-world `reach`. wicket should make the closed form the only form; Standard Agents' "omitted means
   unrestricted" is the part to avoid.
4. **Schema-checked spawn arguments with a structured refusal** (`subagent_arguments_required`). Child zones
   should get typed task inputs validated before launch, with a typed refusal the parent can act on, never a
   half-started child.
5. **The `runCode` conformance checklist** (runtime §14.9) as the starting spec for the Wasm codemode tier:
   a fresh instance per call, capabilities only through imports, no ambient globals, failure to link
   unknown imports, distinct status codes (`memory`, `terminated`, `link_error`, `error`), and terminate
   within a bound. wicket adds the wall-clock deadline the spec leaves out.
6. **Single-use stream tickets bound to one exact normalised path**, `Cache-Control: no-store`, and "first
   frame is a status snapshot" (client API §4). Good patterns for the admin interface's event bus (§14.1.3).
7. **`instanceEnv`**: a read that only the operator's layer can satisfy, for trust anchors. This is the same
   idea as wicket's reserved variables, named well.
8. **`decide()`'s typed answers** (choice, score or boolean with probabilities). That is a low-capacity
   output format that fits P6, for wicket's quarantined readers and the parent-tier re-derivation (§6,
   "wicket's own LLM calls").
9. **Attachments are copied across threads, never linked**, and destination-local paths are rewritten. This
   agrees with wicket's handles; worth stating for outbox extraction.

## 6. What wicket should avoid

1. **Approvals recorded by a model.** The approval-gate child's prompt side "renders the request, records
   the outcome". The human's words pass through a model that writes the decision. wicket's decisions are
   typed, bound to the request digest and recorded by the broker (§11).
2. **Secrets readable by packaged code.** `state.env()` returns `secret` values to any tool; redaction is a
   "should". This is the reason wicket's rule is no secrets in the box at all.
3. **Limits that default to unlimited.** `uses` omitted, `maxInstances` unset, `maxSessionTurns` optional,
   no wall-clock timeout. Each has a reason in their design, but in wicket every budget has a default (P3,
   §13.8).
4. **A boundary that exists only inside the runtime.** Their isolation is between threads in one runtime
   and around `runCode`. Tools, hooks and handlers are trusted. That is fine on Cloudflare's own isolates and
   not enough for third-party npm agent packages on a host.
5. **Automatic downward flow of environment.** `setEnv` propagates to active descendants, and `scopedEnv`
   copies values into children. wicket children start from an explicit LaunchPlan and get only what their
   ceiling allows.
6. **A hosted dependency in the agent's core path.** `init` needs a browser sign-in, writes a platform key,
   and installs a token-minting git helper. Inside wicket none of that belongs in the box.
7. **An "open standard" with one closed runtime and a private spec repository.** Treat it as one vendor's
   framework that may change shape (0.1.0 → 0.2.0 already did). Pin versions per adapter, as §6.1 does
   for Claude Code.

## 7. Does anything change wicket's design?

No change to architecture or principles. Small follow-ups worth recording:

- **§8.2:** allow a service zone to declare an **LLM route**, for "agent as a tool" services (Standard Agents,
  AgentBuilder's MCP exposure, any MCP server that calls a model internally). Its output is model output:
  labelled and returned as handles. Today §8.2 assumes servers don't call models.
- **§6 tier table:** note that **T3 covers HTTP-driven service agents**, using a thread API as its event
  stream (Standard Agents' Thread Client API, and similar ones). This isn't a new tier.
- **§9.4/§9.5 tests:** "absent allow-list denies" and "revocation error is distinguishable from a network
  failure" become conformance cases.
- **Wasm codemode (§7, backend 6):** use the `runCode` checklist (§5 item 5) as its first conformance list.
- **Manifest approvals (§5, §14.2):** state the "installing is inert; composing is the act" rule (§5 item 2).
- **Credential rule reminder:** any non-Claude-Code inner agent that wants Claude models conflicts with the
  owner's no-API-key rule. Standard Agents is one more case; record it once in §6, not per agent.

---

## 8. Sources

Primary (read in this session):
- Specification index: [standardagentspec.org/llms.txt](https://standardagentspec.org/llms.txt) ·
  [overview 0.2.0](https://standardagentspec.org/0.2.0/getting-started/overview/) ·
  [overview 0.1.0](https://standardagentspec-com.pages.dev/0.1.0/getting-started/overview) ·
  [agents 0.1.0](https://standardagentspec-com.pages.dev/0.1.0/specification/agents)
- 0.2.0: [agents](https://standardagentspec.org/0.2.0/specification/agents) ·
  [subagents](https://standardagentspec.org/0.2.0/specification/subagents) ·
  [tools](https://standardagentspec.org/0.2.0/specification/tools) ·
  [providers](https://standardagentspec.org/0.2.0/specification/providers) ·
  [handlers](https://standardagentspec.org/0.2.0/specification/handlers) ·
  [hooks](https://standardagentspec.org/0.2.0/specification/hooks) ·
  [threads](https://standardagentspec.org/0.2.0/specification/threads) ·
  [code execution](https://standardagentspec.org/0.2.0/specification/threads/code-execution) ·
  [decisions](https://standardagentspec.org/0.2.0/specification/threads/decisions) ·
  [client API](https://standardagentspec.org/0.2.0/specification/threads/client-api) ·
  [users](https://standardagentspec.org/0.2.0/specification/users) ·
  [runtime](https://standardagentspec.org/0.2.0/infrastructure/runtime) ·
  [packaging](https://standardagentspec.org/0.2.0/distribution/packaging)
- [Runtimes](https://standardagentspec.org/runtimes) · [Community](https://standardagentspec.org/community) ·
  [standardagents.ai](https://standardagents.ai)
- npm: [@standardagents/spec](https://www.npmjs.com/package/@standardagents/spec) ·
  [@standardagents/builder](https://www.npmjs.com/package/@standardagents/builder) ·
  [@standardagents/cli](https://www.npmjs.com/package/@standardagents/cli) (README) ·
  [@standardagents/anthropic](https://www.npmjs.com/package/@standardagents/anthropic) (README, bundle)
- GitHub: [standardagents org](https://github.com/standardagents) ·
  [justin-schroeder](https://github.com/justin-schroeder) ·
  [dmux](https://github.com/standardagents/dmux) (`src/utils/agentLaunch.ts`, `src/types.ts`)

Secondary:
- [AI Engineer: "The Future Is Domain-Specific Agents"](https://ai.engineer/talks/spNAUEgq_A8-future-is-domain-specific-agents) ·
  [AI Engineer: StandardAgents org page](https://ai.engineer/orgs/standardagents) [M]
- workerd and Wrangler proxy and HTTPS issues: workerd #6746, workers-sdk #9356 (seen through mirrors) [L]
- Similar names: [oracle/agent-spec](https://github.com/oracle/agent-spec) ·
  [hassanhabib/The-Standard-Agent-Specs](https://github.com/hassanhabib/The-Standard-Agent-Specs) ·
  [Agents Standard](https://agentsstandard-dot-com.pages.dev/) ·
  [open-gitagent/gitagent](https://github.com/open-gitagent/gitagent) ·
  [.iblai Agent Standard](https://ibl.ai/developer/agents/standard.md)

Not reached: the talk video itself (only its listing and summary), the private spec and Builder
repositories, the Discord, and a running Builder.
