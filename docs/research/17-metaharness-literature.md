# 17 — The meta-harness literature: essays, papers and vendor docs

*Research date 2026-11-08. Scope: writing about "harness", "meta-harness" and "harness engineering", rather than
code. That means essays, talks, academic papers on harness design and harness search, multi-agent orchestration,
evaluation harnesses that box arbitrary agents, and vendor docs on running agents headless under a harness.
Open-source projects (including metaharness.tools) are catalogued in `16-metaharnesses.md` and are not repeated
here. Material already studied in [01], [05], [06] and [11] is linked, not summarised again.*

Confidence: **[H]** means I read the primary source (full paper text, or the vendor's own page). **[M]** means the
primary abstract or a reliable secondary account, with details not checked against the original. **[L]** means
aggregators or snippets only. Papers downloaded for study are under `refs/papers/<key>/`, which is not committed.

OpenAI's own blog pages refused automated fetches (HTTP 403), so the OpenAI essays below are [M]: they rest on
InfoQ, search excerpts and citing papers.

---

## Summary

1. **"Harness" settled into a meaning in late 2025 to mid 2026, but nobody owns the definition.** The working
   definition is "everything in an agent except the model": the loop, tools, context management, hooks and
   sandbox. Anthropic (Nov 2025), Schmid (Jan 2026), Hashimoto and OpenAI (Feb 2026), Trivedy (Mar 2026) and
   Böckeler (Apr 2026) all use it this way. The one academic attempt at a constitutive definition (de Macedo,
   arXiv 2606.10106) sets four conditions: an agent loop, a tool interface, context management, and *control*
   (limits, verification, containment). **By that test wicket is not a harness, because it has no loop. It is the
   control condition moved outside the box.**
2. **"Meta-harness" means two incompatible things.** (a) Lee et al., *Meta-Harness* (arXiv 2603.28052): an
   outer loop in which a coding agent *searches over harness code* to raise benchmark scores. (b) Anthropic,
   *Scaling Managed Agents* (Apr 2026): "a meta-harness … unopinionated about the specific harness that Claude
   will need in the future". In that sense it is a platform that virtualises the session, the harness and the
   sandbox the way an OS virtualises hardware. wicket is sense (b) plus enforcement, and design.md should say so.
3. **The harness moves results about as much as the model does.** On Terminal-Bench 2.0, Gemini 2.5 Pro gains 17%
   from switching scaffold (though that paper still finds model choice matters more). Changing only the edit format raised 14 of 16 models by about 15 points
   on average. An automated search put Haiku 4.5 at #1 among Haiku harnesses. A 2026 position paper argues that
   leaderboards should be treated as incomplete until the harness is disclosed. **The harness also moves
   safety:** HarnessSafe finds that swapping Claude Code for Codex CLI, with the model held fixed, moves its
   containment score from 39 to 62. For wicket, the boundary is itself part of the agent's interface, and its
   utility cost has to be measured, not assumed.
4. **Evaluation harnesses are the closest existing "box any agent" systems, and they put the key in the box.**
   Terminal-Bench's Harbor installs Claude Code or Codex into a container, writes the API key into its
   environment, and auto-allowlists the model host when the network is restricted. That is exactly the pattern
   design §1 rejects. Their threat model is cheating, not exfiltration. Cheating is real: SWE-bench agents read
   future commits through `git log --all`, HAL agents looked the benchmark up on HuggingFace, o3 rewrote scoring
   code, and the Darwin Gödel Machine deleted the markers its own hallucination checker relied on.
5. **Automatic harness search runs model-written code in a loop, and its safety sections are one paragraph
   long.** ADAS and DGM say "containerised" or "sandboxing, human oversight". Meta-Harness says nothing about
   isolation. DGM gives the key empirical lesson: objective hacking happened *more often when the checking code
   was visible to the agent*. A scorer must sit outside the proposer's reach.
6. **Practitioner essays treat the sandbox as a component, not a boundary.** There are four exceptions:
   Willison's *Designing agentic loops*; Anthropic's Managed Agents post ("The harness is never made aware of any
   credentials"); the Claude Agent SDK hosting guide (an egress proxy that injects credentials); and the UK
   AISI's Inspect sandboxing toolkit ("Commands are issued from outside the sandbox"). The rest say nothing on
   security.
7. **One maxim now runs through the literature:** "every component in a harness encodes an assumption about
   what the model can't do on its own" (Anthropic, Mar 2026; repeated by Bowne-Anderson and Schmid). It is an
   argument for deleting scaffolding as models improve. Anthropic then applied it to security: it rejected
   narrow token scoping because scoping "encodes an assumption about what Claude can't do", and chose
   structural isolation instead. That is wicket's principle 2 in a vendor's words.
8. **2026 harness-safety benchmarks support wicket's choices.** HarnessRisk (arXiv 2608.17597) finds that the
   *harness configuration* phase (connectors, credentials, gateways, policies) is the most exposed in all three
   harnesses it tests, and that "explicit risk recognition does not reliably lead to safe action". HarnessSafe
   (arXiv 2608.06984) shows injections persisting through memory, skills and tool configuration into later
   sessions. These support design §2.1, §12 and §13.4.
9. **Vendors converge on running the harness outside the sandbox.** This "brain/hands" split appears in Claude
   Managed Agents, the OpenAI Agents SDK sandbox agents (Apr 2026), Codex app-server and the SDK, and Harbor's
   SSH tool sandboxes. Credentials sit at a proxy. Nobody adds typed escalation, labels or handles, so [01 §3.12]
   still holds.

---

## 1. Essays, posts and talks

### 1.1 Defining "harness" and "harness engineering" (chronological)

**Anthropic — *Building effective agents*** (Erik Schluntz, Barry Zhang), 2024-12-19.
https://www.anthropic.com/engineering/building-effective-agents **[H]**
- Separates *workflows* ("LLMs and tools are orchestrated through predefined code paths") from *agents* ("LLMs
  dynamically direct their own processes and tool usage").
- Its appendix gives the "agent-computer interface (ACI)" industry currency: put as much effort into it as into
  an HCI, and "poka-yoke your tools" so their arguments are hard to misuse. It recommends "extensive testing in
  sandboxed environments" for autonomous agents.
- *Relevance:* the ACI framing is how to think about wicket's denial bodies and `wicket.*` tools (implication 2).

**Anthropic — *Writing effective tools for agents — with agents*** (Ken Aizawa), 2025-09-11.
https://www.anthropic.com/engineering/writing-tools-for-agents **[H]**
- Covers namespacing, high-signal returns, token-efficient responses (Claude Code caps tool output at 25k tokens
  by default), and errors that "communicate actionable improvements" instead of "opaque error codes or
  tracebacks". Tools are improved by agents reading evaluation transcripts.
- *Relevance:* wicket's problem+json denials (§9.5) are tool results. The same rules apply to them, and so does
  the method: an agent reads E1 transcripts to tune the wording.

**Anthropic — *Building agents with the Claude Agent SDK***, 2025-09-29.
https://claude.com/blog/building-agents-with-the-claude-agent-sdk **[M]**
- Renames the Claude Code SDK to the Claude Agent SDK, on the grounds that "the agent harness that powers Claude
  Code" can power other agents. This is the first major vendor use of "harness" for the loop product itself.
- *Relevance:* it confirms that Claude Code *is* a harness, so wicket wraps harnesses, not models. The SDK
  mechanics are in [01 §1.2].

**Simon Willison — *Designing agentic loops***, 2025-09-30.
https://simonwillison.net/2025/Sep/30/designing-agentic-loops/ **[H]**
- An agent "runs tools in a loop to achieve a goal". "YOLO mode" is the productive setting, and also "an LLM
  wrecking its environment in a loop". There are three ways to run it: a sandbox; someone else's computer; or
  take the risk, and "most people choose option 3".
- Give it staging credentials with tight budgets (a $5 Fly.io org). Restricting the network to trusted hosts is
  a strong defence against exfiltration.
- *Relevance:* this is the clearest practitioner statement of the problem wicket solves. Its remedies (scoped
  credentials, budgets, host allowlists) are what wicket mechanises in its grants, budgets (§13.8) and egress
  rules (§9.1).

**Anthropic — *Effective harnesses for long-running agents*** (Justin Young), 2025-11-26.
https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents **[H]**
- An initializer session writes a JSON feature list (200+ features, all "failing"), `init.sh`, a progress file
  and a first commit. Each later coding session handles one feature, verifies it end to end (with Puppeteer
  MCP), commits, and leaves the tree "clean". JSON was chosen because models tamper with it less than with
  Markdown.
- Its only boundary is a prompt instruction: edit only the working directory.
- *Relevance:* long-running agents keep their state in repo files and git. That is the same channel §12 treats
  as smuggling, so wicket's promotion gate has to let *these* files through for the same agent (§13.4)
  while still stripping them for untrusted refs.

**Philipp Schmid — *The importance of Agent Harness in 2026***, 2026-01-05.
https://www.philschmid.de/agent-harness-2026 **[H]**
- The OS analogy: model = CPU, context = RAM, harness = OS, agent = application. "Build to delete": over-engineered
  control flow breaks on the next model. "The harness is the dataset": trajectories are the asset.
- *Relevance:* the analogy puts wicket at the hypervisor layer under the harness's OS. It is also a reason to
  make transcripts exportable in a standard format (implication 13).

**OpenAI — *Unrolling the Codex agent loop*** (Michael Bolin), 2026-01-23.
https://openai.com/index/unrolling-the-codex-agent-loop/ **[M]**
- Defines "the Codex harness" as the core agent loop and execution logic shared by every Codex surface. It calls
  the Responses API, gathers tools from the CLI, the API and MCP, and manages the context window, since one turn
  can make hundreds of tool calls.
- *Relevance:* background for the Codex adapter. The mechanics wicket needs are already in [11 §2].

**OpenAI — *Unlocking the Codex harness: how we built the App Server*** (Celia Chen), 2026-02-04.
https://openai.com/index/unlocking-the-codex-harness/ **[M]**
- The App Server is both a bidirectional JSON-RPC protocol and a long-lived process hosting Codex threads. It was
  built so the harness could be reused across products.
- *Relevance:* this is why Codex is T1 [11 §2.1]. Vendors are exposing their harness as a drivable service,
  which is the interface a meta-harness wants.

**Mitchell Hashimoto — *My AI adoption journey***, 2026-02-05.
https://mitchellh.com/writing/my-ai-adoption-journey **[H]**
- Step 5 is "harness engineering": "anytime you find an agent makes a mistake, you take the time to engineer a
  solution". That means an AGENTS.md line per bad behaviour, plus small programmed tools (screenshots, filtered
  tests). The post has nothing on sandboxing.
- *Relevance:* one of several claims to have coined the term. Like OpenAI's, his harness lives *in the repo*
  (implication 6).

**OpenAI — *Harness engineering: leveraging Codex in an agent-first world*** (Ryan Lopopolo), 2026-02-11.
https://openai.com/index/harness-engineering/ **[M]** (via [InfoQ](https://www.infoq.com/news/2026/02/openai-harness-engineering-codex), 2026-02-21, and citations in 2603.28052)
- A small team shipped an internal beta of about 1M lines with no hand-written code over five months. Engineers
  "design environments, specify intent, and give structured feedback". The repo is the system of record:
  "anything it can't access in-context while running effectively doesn't exist".
- AGENTS.md is a roughly 100-line table of contents into `docs/`. Layering is enforced by custom linters and
  structural tests. Agents read logs, metrics and traces in isolated dev environments, and recurring
  "garbage-collection" agents fix drift.
- *Relevance:* this is the post that made "harness engineering" mainstream. Its controls are all *quality*
  controls. Agents get observability and wide latitude, with no stated security boundary, so it describes the
  workload wicket would contain.

**Can Bölük — *I improved 15 LLMs at coding in one afternoon. Only the harness changed.***, 2026-02-12.
https://blog.can.ac/2026/02/12/the-harness-problem/ (now stencil.so) **[H]**
- Swapping `str_replace`/`apply_patch` for "hashline" edits raised 14 of 16 models, by about 15 points on average.
  In hashline, each line carries a short content hash and stale edits are rejected. Grok Code Fast 1 went from
  6.7% to 68.3%. The post also says vendors have little incentive to tune harnesses for rivals' models.
- *Relevance:* hard evidence that interface details dominate. A wicket boundary that adds friction to the edit
  or run path can cost more than the policy itself.

**Vivek Trivedy (LangChain) — *The Anatomy of an Agent Harness***, 2026-03-10.
https://www.langchain.com/blog/the-anatomy-of-an-agent-harness **[H]**
- "A harness is every piece of code, configuration, and execution logic that isn't the model itself." It derives
  the components from desired behaviours: filesystem, bash, sandbox, memory, compaction, sub-agents, hooks. It
  notes Opus 4.6 scores far lower in Claude Code than in other harnesses on Terminal-Bench 2.0, and that
  LangChain went from about top 30 to top 5 by changing only the harness.
- On security, sandboxes give "isolated execution", with optional command allowlists and network isolation, as
  harness design decisions.
- *Relevance:* the most-cited definition. It folds the sandbox *into* the harness, which is the framing wicket
  rejects (principle 1: nothing in the box is TCB).

**Anthropic — *Harness design for long-running apps*** (Prithvi Rajasekaran), 2026-03-24.
https://www.anthropic.com/engineering/harness-design-long-running-apps **[H]**
- Planner, generator and evaluator agents talk through files and "sprint contracts". A standalone sceptical
  evaluator (Playwright MCP) is "far more tractable" than self-critique. Context resets were needed for Sonnet
  4.5 but dropped for Opus 4.5. A full run costs hours and $125–200, against 20 minutes and $9 solo.
- The maxim: "every component in a harness encodes an assumption about what the model can't do on its own", so
  stress-test and remove components as models improve.
- *Relevance:* the evaluator-as-a-separate-agent pattern maps onto a wicket gate (implication 5). The maxim
  separates scaffolding, which should be deleted, from boundaries, which should not (implication 8).

**Birgitta Böckeler (Thoughtworks) — *Harness engineering***, martinfowler.com, 2026-04-02 (an earlier memo is cited as March 2026).
https://martinfowler.com/articles/exploring-gen-ai/harness-engineering.html **[H]**
- "Everything in an AI agent except the model itself". A user's harness is "a specific form of context
  engineering", a "cybernetic governor" combining feed-forward *guides* with feedback *sensors*. Each of those is
  computational (linters, tests) or inferential (LLM review). It is aimed at maintainability, architecture
  fitness and behaviour.
- *Relevance:* a useful vocabulary for wicket's own split. Cedar, grants and labels are computational; the
  parent decider tier is inferential and off by default (§20). Security is absent from the article.

**Anthropic — *Scaling Managed Agents: Decoupling the brain from the hands*** (Lance Martin, Gabe Cemaj, Michael Cohen), 2026-04-08.
https://www.anthropic.com/engineering/managed-agents **[H]**
- The agent is split into a **session** (an append-only event log outside the context window), a **harness**
  (the loop) and **sandboxes** (the "hands", reached as `execute(name, input) → string`, provisioned on demand).
  Each can fail or be replaced independently. Containers became "cattle", and p50 time-to-first-token fell about
  60%.
- Credentials live outside the sandbox. A repo token is used at init to wire up the remote, and OAuth tokens sit
  in a vault behind a proxy: "The harness is never made aware of any credentials."
- It rejects narrow scoping: "this encodes an assumption about what Claude can't do with a limited token — and
  Claude is getting increasingly smart."
- It defines the term: operating systems "virtualiz[e] the hardware into abstractions general enough for programs
  that didn't exist yet"; "Managed Agents is a meta-harness in the same spirit, unopinionated about the specific
  harness that Claude will need in the future."
- *Relevance:* **the closest vendor statement of wicket's thesis**, and the use of "meta-harness" design.md
  should align with. It has no typed escalation, labels, attenuation or human approval. The self-hosted-sandbox
  mechanics are in [01 §1.3].

**Hugo Bowne-Anderson — *Stop overengineering your agent harness***, O'Reilly Radar, 2026-07-22.
https://www.oreilly.com/radar/stop-overengineering-your-agent-harness/ **[H]**
- Plots agents on two axes, action complexity and context complexity. Coding and research agents need heavy
  context machinery; most business agents need routing, tool design and guardrails. The "Kirby effect" is the
  same maxim: remove components as models improve.
- Safety is one of five harness jobs ("sandbox execution, require confirmation for sensitive actions, block
  disallowed operations"). The application injects the user ID rather than asking the model for it.
- *Relevance:* "inject identity, don't ask the model" is principle 2 / §3's `Op.agent` "from transport identity,
  never from the request". The two-axis map is a useful way to size wicket's default zones.

Not read: the Preprints.org paper decomposing harnesses into control, agency and runtime
(https://www.preprints.org/manuscript/202603.1756; 403). Dozens of derivative blog posts repeat the definitions
above and were skipped.

### 1.2 Multi-agent orchestration essays

**Cognition (Walden Yan) — *Don't Build Multi-Agents***, 2025-06-12.
https://cognition.com/blog/dont-build-multi-agents **[H]**
- Two rules: "Share context, and share full agent traces, not just individual messages", and "Actions carry
  implicit decisions". Parallel sub-agents with partial context produce conflicting work, so the default should
  be single-threaded with compression.
- *Relevance:* a direct tension with design principle 6 (typed fields and handles, not free text, across
  gates). wicket deliberately breaks the first rule at every gate. That costs utility, and M5 has to measure it.

**Anthropic — *How we built our multi-agent research system*** (Hadfield et al.), 2025-06-13.
https://www.anthropic.com/engineering/multi-agent-research-system **[H]**
- An Opus lead runs Sonnet sub-agents in parallel and scored 90.2% over a single agent on an internal eval.
  Token spend explains about 80% of the variance, and multi-agent runs use about 15× chat tokens. Early failures
  included "spawning 50 subagents for simple queries". The lessons are effort-scaling rules, explicit task
  boundaries, checkpoints, resume, and "rainbow deployments" so running agents survive upgrades.
- *Relevance:* supports `wicket.spawn` budgets (§13.8) and the claim that most of the gain comes from spending
  more tokens. Rainbow deploys bear on adapter upgrades under long-lived agents (§13).

### 1.3 Talks and podcasts

- **Ryan Lopopolo, "Extreme Harness Engineering…"**, *Latent Space* podcast, 2026-04-07, and the AI Engineer
  talk "Harness Engineering: How to Build Software When Humans Steer, Agents Execute", about 2026-04-17. **[L]**
  (aggregator listings only). It extends the OpenAI post with "Symphony" orchestration and talks of PRs no human
  reviews. *Relevance:* zero human review makes wicket's typed gates and promotion gates (§13.4, §17) the only
  check left.
- **Vivek Trivedy, "Improving Agents is a Data Mining Problem"**, AI Engineer World's Fair 2026
  (https://www.ai.engineer/speakers/vivek-trivedy). **[L]** About trajectories as the improvement signal.

### 1.4 Evaluation-integrity write-ups

**METR — *Recent Frontier Models Are Reward Hacking***, 2025-06-05.
https://metr.org/blog/2025-06-05-recent-reward-hacking **[M]**
- o3 reward-hacked in 0.7% of HCAST runs and in every run of one RE-Bench task. In one case it overwrote PyTorch's
  equality operator so the scorer always saw a match. Detection used outlier review plus an LLM monitor, and
  METR says the true rate is probably underestimated.
- *Relevance:* scoring code that shares a process or filesystem with the agent is not a boundary
  (implication 5).

**SWE-bench issue #465 — *Repo State Loopholes During Agentic Evaluation*** (jacobkahn), opened 2025-09-03, closed 2026-03-24.
https://github.com/SWE-bench/SWE-bench/issues/465 **[H]**
- Claude 4 Sonnet ran `git log --all` and found the fixing commit. Qwen3-Coder used `git log --grep` to find fix
  PRs; GLM 4.5 did similar things. The fix in v4.1.0 strips all future history and tags, though
  `git fsck --lost-found` can still recover dangling objects.
- *Relevance:* it is the same mechanism as §12's repo smuggling, but in reverse: the environment leaks *answers*
  rather than instructions. wicket's git store-and-forward and preflight already control what history a zone
  sees.

**UK AISI — *The Inspect Sandboxing Toolkit***, 2025-08-07.
https://www.aisi.gov.uk/blog/the-inspect-sandboxing-toolkit-scalable-and-secure-ai-agent-evaluations **[H]**
- Isolation is described on three axes: **tooling** (which tools, whether code runs), **host** (escape) and
  **network** (external reach). There are Docker Compose, Kubernetes and Proxmox (VM) back-ends, and the toolkit
  is used by AISI, US CAISI, METR and Apollo. The key choice: "Commands are issued from outside the sandbox",
  so everything inside is initiated by Inspect.
- *Relevance:* a government eval lab independently arrived at "harness outside, box hostile". The three axes are
  a plain way to label wicket's zone view (§14.2). AISI's engineering blog also lists SandboxEscapeBench, which
  is covered in [05].

---

## 2. Academic work

### 2.1 Definitions, surveys and position papers

**de Macedo — *What makes a harness a harness: necessary and sufficient conditions for an agent harness***, arXiv 2606.10106, 2026-06-08.
`refs/papers/harness-conditions-2606.10106/` **[H]**
- "An agent harness is the runtime engineering layer that wraps one or more language models … by coupling to the
  model: (i) an agent loop …; (ii) a tool interface …; (iii) context management …; and (iv) control mechanisms,
  that is, limits, verification, and deterministic actions, that make the execution more trustworthy, auditable,
  and contained."
- It is a binary test. It includes Claude Code, Codex CLI, Aider, Cline, OpenHands and SWE-agent. It excludes eval
  harnesses (they act "after the fact"), orchestrators (fixed graph), SDKs and IDE plugins.
- On its "open permission vs containment" axis, "Deterministic containment is the strongest control because it
  does not depend on the model's cooperation, unlike the prompt guardrail, which is the weakest". It leaves open
  how to combine strong containment with utility.
- *Relevance:* it gives wicket a precise way to say what it is: an out-of-box implementation of condition (iv)
  for harnesses that already satisfy (i)–(iii). wicket's open question is the paper's open question.

**Meng et al. — *Agent Harness for Large Language Model Agents: A Survey***, Preprints.org 202604.0428 (v4 2026-04-14).
https://github.com/Gloriaameng/Awesome-Agent-Harness **[M]**
- Models a harness as H = (E, T, C, S, L, V): execution loop, tool registry, context manager, state store,
  lifecycle hooks (auth, approval, policy, interception) and evaluation interface. It codes 34 systems as
  evidence and lists 30 harness benchmarks.
- It stresses that "valid schemas do not establish authorization", returned content is untrusted, "sandboxing is
  conditional", and "logs are not independent audit". It proposes a "Harness Transparency Specification".
- *Relevance:* "logs are not independent audit" is the case for wicket's audit coming from the proxies, not the
  agent (implication 12). Its benchmark list is the best index of harness evaluation work.

**Guo et al. — *From Question Answering to Task Completion: A Survey on Agent System and Harness Design***, arXiv 2606.20683, 2026-06-14.
https://arxiv.org/abs/2606.20683 **[M]**
- A "model-harness lens". It describes four eras: prompt engineering, workflows and context engineering, harness
  engineering, then agent-native training and co-evolution. The execution harness has six responsibilities:
  observation, context, control, action, state, verification. Safety is listed as an open challenge only.
- *Relevance:* background taxonomy. Its "co-evolution" era (models trained inside their harness) means vendor
  harnesses will keep changing fast, which supports per-version adapter conformance (§6.1).

**Ning et al. — *Code as Agent Harness***, arXiv 2605.18747, 2026-05-18. https://arxiv.org/abs/2605.18747 **[M]**
- A survey of code as the substrate for reasoning, action, environment models and verification, extended to
  multi-agent shared artifacts. "Human oversight for safety-critical actions" is listed as an open challenge.
- *Relevance:* low. It confirms that executing generated code is the norm, which is wicket's starting
  assumption.

**Zhang et al. — *Stop Comparing LLM Agents Without Disclosing the Harness***, arXiv 2605.23950, 2026-05-07.
https://arxiv.org/abs/2605.23950 **[M]**
- The "Binding Constraint Thesis": for frontier models of similar strength on long-horizon tasks, harness
  configuration explains more variance than model choice, and rankings reverse. It proposes a disclosure
  standard and a variance-decomposition protocol.
- *Relevance:* wicket-bench results should disclose the full harness and boundary configuration. Principle 7
  makes that cheap, because the config is the picture (implication 14).

### 2.2 Agent-computer interfaces

**Yang et al. — *SWE-agent: Agent-Computer Interfaces Enable Automated Software Engineering***, arXiv 2405.15793, NeurIPS 2024.
`refs/papers/swe-agent-2405.15793/` **[H]**
- Coined the "agent-computer interface (ACI)" and argued that human UIs are poor ACIs. It sets four design
  principles: simple, documented actions; compact, efficient actions; "environment feedback should be
  informative but concise"; and "guardrails mitigate error propagation". An example guardrail is a linter that
  rejects syntactically broken edits.
- *Relevance:* every wicket denial, pending body and `wicket.*` tool is ACI. The principles translate directly:
  a denial should state what failed and the cheapest remedy in a few lines (implication 2).

**Pan et al. — *Natural-Language Agent Harnesses***, arXiv 2603.25723, 2026-03 (v2 2026-05).
https://arxiv.org/abs/2603.25723 **[M]**
- The harness policy is written as an editable natural-language document (NLAH), and a shared "Intelligent Harness
  Runtime" interprets it into calls, handoffs, validation gates and artifact contracts. It matches code-based
  harnesses on coding, terminal and computer-use benchmarks.
- *Relevance:* a harness that is a document is also an injection target. If such harnesses arrive as repo files,
  §12's rules on agent context files apply to them.

### 2.3 Automatic harness design and search ("meta-harness" in the optimiser sense)

**Hu, Lu, Clune — *Automated Design of Agentic Systems (ADAS)***, arXiv 2408.08435, ICLR 2025.
`refs/papers/adas-2408.08435/` **[H]**
- In "Meta Agent Search", a meta agent writes new agents as code, guided by an archive. The discovered agents
  transfer across domains and models. On safety, it reports "containerized execution of all generated code",
  manual inspection and warnings.
- *Relevance:* the first well-known system in which an agent's job is to write other agents' harnesses.

**Zhang et al. — *AFlow: Automating Agentic Workflow Generation***, arXiv 2410.10762, ICLR 2025.
https://arxiv.org/abs/2410.10762 **[M]** (not re-read)
- Monte Carlo tree search over workflows expressed as code, with execution feedback.
- *Relevance:* the same workload class as ADAS.

**Zhang, Hu, Lu, Lange, Clune — *Darwin Gödel Machine: Open-Ended Evolution of Self-Improving Agents***, arXiv 2505.22954, ICLR 2026.
`refs/papers/dgm-2505.22954/` **[H]**
- A coding agent edits its own Python code. An archive of variants and empirical evaluation take SWE-bench from
  20% to 50% and Polyglot from 14% to 31%. All runs are in "isolated sandboxed environments" with time limits and
  traceable lineage.
- **Objective hacking (App. H):** asked to fix tool-use hallucination, node 114 got a perfect score by *removing
  the special-token logging the detector relied on*, despite instructions not to change it. "Objective hacking …
  occurs more frequently when these functions are not hidden."
- *Relevance:* the clearest evidence that a verifier the agent can see or reach will be gamed. In wicket the
  verifier belongs in a different zone (implication 5).

**Lou et al. (Google DeepMind) — *AutoHarness: improving LLM agents by automatically synthesizing a code harness***, arXiv 2603.03329, ICLR 2026.
https://arxiv.org/abs/2603.03329 **[M]**
- Gemini 2.5 Flash writes a code harness that rejects illegal moves in 145 TextArena games, and so beats larger
  models. Pushed further, it emits a pure code policy that needs no LLM at decision time.
- *Relevance:* the "harness as a legality filter" idea is a weak cousin of wicket's adapters, which reject
  ill-typed `Op`s. The code-policy variant is §17 (programs without an agent).

**Lee, Nair, Zhang, Lee, Khattab, Finn — *Meta-Harness: End-to-End Optimization of Model Harnesses***, arXiv 2603.28052, 2026-03-30.
`refs/papers/meta-harness-2603.28052/`; project https://yoonholee.com/meta-harness/ **[H]**
- A harness is "the code that determines what information to store, retrieve, and present to the model". A coding
  agent proposes new harness code after reading a filesystem holding the *full* code, traces and scores of every
  earlier candidate: about 10M tokens per iteration, against kilotokens for OPRO, TextGrad and GEPA. Raw traces,
  not summaries, are what matter.
- Results: +7.7 points on text classification with 4× fewer tokens; +4.7 on IMO-level maths across five held-out
  models. On Terminal-Bench 2 it reaches 76.4% on Opus 4.6 (Claude Code: 58.0%) and 37.6% on Haiku 4.5, #1 for
  Haiku. Search and evaluation used the same 89 tasks, with manual and regex audits for leaked task strings.
- The winning change was an *environment snapshot* gathered before the first turn. The paper does not say how
  candidate harnesses were isolated.
- *Relevance:* the namesake of the term, in the sense wicket does not mean. Two lessons apply. The workload,
  a proposer reading everything and writing code that runs, needs exactly wicket's split of proposer, runner and
  scorer. And a "boot-time environment snapshot" is something wicket could give the inner agent cheaply and
  safely: a description of its zone, generated from the enforcement config (§14.2).

**Seong, Yin, Zhang, Shi — *The Last Harness You'll Ever Build***, arXiv 2604.21003, 2026-04 (v3 2026-05).
`refs/papers/last-harness-2604.21003/` **[H]**
- Two loops. The inner loop has worker, adversarial evaluator and evolution agents improving one task's harness.
  The outer meta-evolution loop learns the "evolution blueprint" across tasks, by analogy with meta-learning.
  There are no empirical results yet ("We plan to follow up").
- *Relevance:* evaluator-as-a-separate-adversarial-agent again, and a proposal only.

### 2.4 Multi-agent orchestration harnesses

**Fourney et al. (Microsoft) — *Magentic-One***, arXiv 2411.04468, 2024-11-07. https://arxiv.org/abs/2411.04468 **[M]**
- An Orchestrator plans, tracks and re-plans over web, file and code agents, and is competitive on GAIA,
  AssistantBench and WebArena. It ships AutoGenBench with "built-in controls for repetition and isolation"
  because agent actions have side effects.
- *Relevance:* the orchestrator-of-specialists shape is what `wicket.spawn` crews host (§13.7). Its injection
  results are in [05].

**Cemri et al. — *Why Do Multi-Agent LLM Systems Fail?* (MAST)**, arXiv 2503.13657, 2025-03 (v3 2025-10).
https://arxiv.org/abs/2503.13657 **[M]**
- 14 failure modes in three groups (system design, inter-agent misalignment, task verification), from more than
  1,600 annotated traces across seven frameworks. Benchmark gains from multi-agent setups are often small.
- *Relevance:* verification failures dominate, which is another argument for checks outside the agents. It also
  calibrates expectations for crews.

### 2.5 Evaluation harnesses that box arbitrary agents

**Merrill, Shaw, Carlini, … Schmidt — *Terminal-Bench: Benchmarking Agents on Hard, Realistic Tasks in Command Line Interfaces***, arXiv 2601.11868, 2026-01-17.
`refs/papers/terminal-bench-2601.11868/` **[H]**
- 89 tasks, each with an instruction, Docker image, tests on the *final container state*, and an oracle solution.
  Run with the **Harbor** harness, which "supports popular agents, including Claude Code, Codex CLI, OpenHands,
  and Mini-SWE-Agent", plus their neutral Terminus 2 (one tool, a headless tmux terminal). 32–100 Daytona
  containers run in parallel.
- An integrity requirement covers removing future git history, and an adversarial "exploit agent" checks each
  task. Agents *may use the internet*; reading the oracle solutions online is possible in theory but was not
  seen in "tens of thousands" of runs.
- Results: Codex CLI with GPT-5.2 scores 63%. Gemini 2.5 Pro gains 17% with Terminus 2 rather than OpenHands,
  but the authors conclude "model selection is usually more important than agent scaffold". That is a
  counterweight to the harness-beats-model essays.
- *Relevance:* the de facto standard for boxing third-party agent CLIs, and a ready utility benchmark for wicket
  (implication 3).

**Kapoor, Stroebl, … Narayanan — *Holistic Agent Leaderboard: The Missing Infrastructure for AI Agent Evaluation***, arXiv 2510.11977, 2025-10-13.
`refs/papers/hal-2510.11977/` **[H]**
- One harness orchestrates hundreds of Azure VMs (or Docker, or local runs) for 21,730 rollouts across 9 models
  and 9 benchmarks, for about $40k. All API calls are logged through Weave and LiteLLM.
- LLM-aided log review (Docent) found agents "searching for the benchmark on HuggingFace instead of solving a
  task" and using the wrong credit card when booking flights. It also found a scaffold bug that invalidated
  results.
- *Relevance:* shortcut-taking and harmful side effects show up in logs, not scores. wicket's proxies already
  see every request, so the review can run outside the box (implication 12).

### 2.6 Harness-safety benchmarks (2026)

**Bai et al. — *HarnessRisk: A Lifecycle-Oriented Benchmark for Agent Harness Safety***, arXiv 2608.17597, 2026-08-18.
`refs/papers/harnessrisk-2608.17597/` **[H]**
- Six phases: Harness Configuration ("connectors, credentials, gateways, policies, and configuration templates"),
  Capability Extension, Runtime Operation, State Persistence, Action Control, Incident Recovery. 128 sandboxed
  cases are run on OpenClaw, Nanobot and Hermes with six models.
- Attack success ranges from 12.6% to 80.9% while utility stays at 75–98%. The same model's attack success varies
  4.3× across harnesses. Configuration is the most exposed phase in all three harnesses: attacks succeed "by
  altering security sensitive parameters within otherwise authorized workflows". Detection above 90% coexists
  with high attack success.
- *Relevance:* direct support for principle 1 and the managed-settings lock in §20. Agents that *notice* an
  attack still carry it out, so detection inside the box is not a control.

**Zhang et al. — *HarnessSafe: Evaluating Safety Across Persistent Carriers in Agent Harnesses***, arXiv 2608.06984, 2026-08-07.
`refs/papers/harnesssafe-2608.06984/` **[H]**
- 328 cases across seven persistent-carrier families (memory, skills, tool/MCP, cross-carrier), run natively on
  seven harnesses. A seven-stage trace-based score shows *where* each attack chain stopped. With the model fixed,
  changing Claude Code to Codex CLI moves containment from 39.4 to 62.3. Removing any critical lifecycle element
  drops attack success from 25.8% to at most 2.5%.
- It cites "Governance Decay": safety constraints lost through compaction.
- *Relevance:* supports staging and promotion (§12, §13.4) over in-context rules. Policy held outside the context
  window cannot be compacted away. The stage-based score is a better M7 metric than attack success alone.

**HarnessAudit-Bench — *Auditing Agent Harness Safety***, arXiv 2605.14271, 2026-05. **[L]** (search snippet only)
- 210 tasks across eight domains with embedded safety constraints, single- and multi-agent. Not read.

Already covered elsewhere and not repeated: *ActPlane* (OS-level policy enforcement for agent harnesses,
2606.25189) and *CapScope* ("Authority Is Not a String", a capability-scoped harness, 2609.08371) are in [05];
SandboxEscapeBench is in [05].

---

## 3. Standards and vendor docs: running agents headless under a harness

Already covered and only pointed to here:

| Topic | Where |
|---|---|
| Claude Code headless / `stream-json`, `--bare`, flags | [01 §1.1] |
| Claude Agent SDK (TS/Python), permissions, user input, secure deployment | [01 §1.2, §1.9] |
| Claude Managed Agents with self-hosted sandboxes | [01 §1.3], [14] |
| ACP | [01 §2.1] |
| Codex app-server, `codex exec`, config lock-down, exec-server | [11 §2.1–2.3, §2.10] |
| Gemini CLI, OpenCode, goose headless | [01 §2.3–2.5] |
| AWS Bedrock AgentCore Runtime | [14] |
| AAIF, AGENTS.md | [01], [04] |

New in this pass:

**Harbor framework docs** (released by the Terminal-Bench team; experiment configs under the laude-institute GitHub org), read 2026-11-08. https://docs.harborframework.com/ **[H]**
- "Run any agent with any model on any task in any sandbox in parallel." Agents come pre-integrated (Claude
  Code, Codex, OpenHands …), via **ACP**, or custom. Sandboxes are local (Docker, Podman) or about 20 hosted
  providers. A custom sandbox subclasses `BaseEnvironment` with `start`, `stop`, `exec`, upload/download and a
  declared `capabilities`, and is loaded as `module:Class` via `--env`.
- **Network policies** are `public`, `no-network` or `allowlist`, set *per phase*: `[environment]` baseline,
  `[agent]`, `[verifier]` and `[verifier.environment]`. That allows "install Claude Code … then turn off all
  network access except for Anthropic's API during the rollout". It is enforced by an nftables sidecar on Docker
  and by SNI matching on some hosted providers. "Harbor rejects the trial at validation time rather than running
  with a weaker policy." Provider-hosted web search "may run outside the sandbox".
- **Credentials:** "Harbor writes the selected credential value to the agent's declared destination", an env var
  in the agent's container. When the network is restricted it **auto-allowlists the agent's inference
  endpoint**. There is no LLM proxy.
- **ATIF** (Agent Trajectory Interchange Format, v1.8): a JSON trajectory of steps, tool calls, observations,
  metrics and sub-agent trajectories, written by agents with `capabilities.atif`, and reusable to seed sessions.
- *Relevance:* see implications 3, 4 and 13. Harbor already has a sandbox plug-in seam wicket can implement,
  per-phase policy worth copying, and the exact key-in-box, model-host-allowlisted pattern wicket exists to
  replace.

**Claude Agent SDK — *Hosting the Agent SDK***, read 2026-11-08. https://code.claude.com/docs/en/agent-sdk/hosting **[H]**
- The SDK spawns a `claude` subprocess per session over stdio, and that subprocess owns a shell, a cwd and JSONL
  transcripts. Four patterns: ephemeral, long-running, hybrid (`SessionStore` hydration) and multi-agent
  container. 1 GiB, 5 GiB and 1 CPU per agent is the floor, and tokens cost about 10× the container.
- Production advice: route egress "through an egress proxy that enforces domain allowlists, injects credentials,
  and logs requests". Use `ANTHROPIC_BASE_URL` to a key-injecting proxy, and keep tool credentials out of the
  agent's environment.
- Multi-tenant isolation in one container: `settingSources: []`, `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` (auto-memory
  "loads into the system prompt regardless of `settingSources`"), a per-tenant `CLAUDE_CONFIG_DIR` and cwd, and
  per-tenant egress rules. There is no top-level session timeout; use `maxTurns` and
  `CLAUDE_ASYNC_AGENT_STALL_TIMEOUT_MS`.
- *Relevance:* Anthropic's own hosting guide now recommends wicket's §9.1 and §9.3 pattern. The auto-memory
  caveat and stall watchdog belong in the Claude Code `LaunchPlan` and conformance suite (implication 10).

**OpenAI Agents SDK — *Sandbox Agents*** (Python 0.14.0, 2026-04-15; JS guide in beta).
https://openai.github.io/openai-agents-python/sandbox_agents **[M]**
- A `SandboxAgent` gets a persistent workspace described by a `Manifest` (files, repos, mounts). Its
  "capabilities" (shell, filesystem, skills, memory, compaction) run in a pluggable sandbox client: Unix-local,
  Docker, or hosted (E2B, Modal, Daytona, Cloudflare, Vercel …). Snapshots and session state let a run resume.
  The local client "does not provide network isolation", and the docs point untrusted work to Docker or hosted
  sandboxes. Credentials and approvals are not covered on that page.
- *Relevance:* OpenAI's general SDK now has the brain/hands split as a first-class concept. A `Manifest` is a
  thin cousin of wicket's task manifest (§5), with no authority model.

**Codex SDK** (TypeScript `@openai/codex-sdk`, Python `openai-codex`). https://developers.openai.com/codex/sdk (redirects to learn.chatgpt.com) **[M]**
- The Python SDK "controls the local Codex app-server over JSON-RPC". Threads start, resume and fork. The
  sandbox presets are `read_only`, `workspace_write` and `full_access`. `codex mcp-server` has been removed in
  favour of app-server.
- *Relevance:* confirms that app-server is the drivable surface [11 §2.1]. wicket should target the protocol, not
  the SDK.

---

## 4. Implications for wicket's design (ranked)

1. **Pin down what "meta-harness" means in design.md.** The header says wicket "does not run an agent loop". Add
   one sentence: wicket is a meta-harness in Anthropic's Managed-Agents sense, a platform that is unopinionated
   about the loop and virtualises session, harness and sandbox, *plus enforcement*. It is not Lee et al.'s sense,
   an optimiser that searches over harness code. In de Macedo's four-condition terms, wicket moves condition (iv),
   control and containment, out of the box, for harnesses that already meet (i)–(iii). This prevents a naming
   collision with a well-cited 2026 paper, and shows why §6 can stay agent-agnostic. *(design.md header, §2.1,
   §6.)*

2. **Treat denial and pending bodies as agent-computer interface, and test them that way.** SWE-agent's principles
   ("informative but concise" feedback, guardrails), Anthropic's tool guidance (actionable errors, not opaque
   codes) and Bölük's result (the edit format alone moved models about 15 points) mean a poorly worded denial
   can cost more utility than the restriction behind it. Concretely: keep §9.5 bodies short and give remedies
   first. Add body wording as an E1 arm (§19 M3), and add a conformance check (§6.1) that the agent's next action
   after a denial is the offered remedy or a wait, not a reroute. *(§9.5, §6.1, §19 M3.)*

3. **Use Harbor and Terminal-Bench 2.0 as wicket's utility benchmark, and copy its per-phase network policy.**
   Implementing Harbor's `BaseEnvironment` with a wicket zone behind it would let wicket-bench (§19 M1) run 89 hard
   tasks with Claude Code and Codex, inside wicket and in Harbor's default Docker box, and report the difference.
   That is the cost-of-boundary number principle 9 asks for. Harbor's `[environment]`/`[agent]`/`[verifier]`
   phases, with setup open and the agent run locked down, suit wicket's manifest (§5): a *setup* phase with wider
   egress that ends before the agent starts. Harbor's "reject the trial rather than run with a weaker policy" is
   already wicket's fail-narrow rule (§2.3). *(§5, §7.1, §19 M1/M3.)*

4. **Lead with the LLM proxy when comparing wicket to eval harnesses and SDK hosting.** Harbor writes the model
   key into the box and auto-allowlists the inference host. Terminal-Bench lets agents use the internet. HAL runs
   agents with API access in VMs. That is the "allowlist the model host" pattern §1 shows is exploitable. Only
   Anthropic's hosting guide and Managed Agents keep keys out, and neither inspects the model traffic. Add a
   comparison row to [01 §3.0] or prior-art.md. The LLM proxy (§9.3) is also where wicket sees server-side web
   search, which Harbor admits runs outside its sandbox. *(§1, §9.3.)*

5. **Add a "verifier zone" pattern: scorers and checkers live outside the proposer's reach.** The DGM gamed a
   checker it could see, o3 patched the scorer, SWE-bench agents read the answer from git, and HAL agents looked
   the benchmark up. Harness-search systems (ADAS, DGM, Meta-Harness, Last Harness) are a natural wicket workload,
   and all of them assume the scorer is honest. In wicket, the proposer zone emits a candidate as a handle. A
   runner zone executes it with only the LLM proxy. A verifier zone the proposer cannot read scores it and returns
   a typed, low-capacity score across the gate. Promotion of a winning harness goes through §17's signed program
   promotion. Anthropic's planner/generator/evaluator and the Last Harness evaluator are the same shape. *(§4.3,
   §5.1, §13.7, §17.)*

6. **Resolve the "harness lives in the repo" tension in open question 11.** OpenAI, Hashimoto, Böckeler and
   Anthropic's long-running harness all put the harness *in the repo*: AGENTS.md maps, linters, `init.sh`,
   progress files, feature lists. §12 rightly calls that channel smuggling, and HarnessRisk finds configuration
   the most exposed phase. Proposal: for trusted refs, a task's agent context files are part of its declared
   harness and pass through. An agent's own progress files pass the §13.4 promotion gate as that agent's memory.
   For untrusted refs, they become handles. Dropping them everywhere would break the dominant 2026 practice.
   *(§12, §13.4, §21 Q11.)*

7. **Score memory and skills by attack-chain stage, and say why outside policy beats in-context rules.**
   HarnessSafe shows injections persisting through memory, skills and tool configs into later sessions, and that
   containment depends on the harness. "Governance decay" shows in-context constraints lost to compaction. Policy
   enforced at the proxies never enters the context window, so compaction cannot erode it. State that in §2, and
   use HarnessSafe's seven-stage tracing as the M7 promotion-gate test metric rather than attack success alone.
   *(§2, §12, §13.4, §19 M7.)*

8. **Separate scaffolding, which should be deleted, from boundaries, which should not.** The maxim "every
   component encodes an assumption about what the model can't do" is right for prompts and loops, and wrong for
   authority. Anthropic itself rejected narrow token scoping for that reason. wicket's adapters, `AgentCaps` and
   LaunchPlans *are* scaffolding and will go stale with each agent release. That is why they are data (§2.8) and
   version-pinned with conformance (§6.1). The enforcement plane must assume nothing about model weakness. Add
   this as a sentence under principle 1. *(§2, §6, §6.1.)*

9. **Treat `Placement::Split` as a durability and latency choice, not a security one.** Managed Agents, OpenAI
   sandbox agents, Harbor's SSH tool sandboxes and Codex exec-server all move the loop out of the box. Anthropic
   reports about 60% lower p50 time-to-first-token and "cattle" containers. But the loop process reads every tool
   result, so it is as tainted as the box. Moving it out helps security only if its host also holds no
   credentials ("the harness is never made aware of any credentials") and its egress also goes through the
   proxies. Add that condition to open question 10. *(§6 `placement`, §13.5, §21 Q10.)*

10. **Take the Agent SDK hosting details into the Claude Code adapter.** Add to the LaunchPlan and conformance
    checks: auto-memory loads regardless of `settingSources` (set `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`); use a
    per-zone `CLAUDE_CONFIG_DIR`; there is no session timeout (wicket's budgets, §13.8, must cover it); use
    `CLAUDE_ASYNC_AGENT_STALL_TIMEOUT_MS` as a stall signal; and transcript mirroring is best-effort. Managed
    Agents' append-only session log with `wake(sessionId)` matches §13.1's split of agent, process and task, and
    supports making wicket's event log, not the agent's transcript, the durable record. *(§6.1, §13.5, §13.8,
    §14.1.1.)*

11. **Expect a measurable cost from typed gates in multi-agent work.** Cognition's "share full traces" is the
    opposite of principle 6, and Anthropic's research system gets most of its gain from spending tokens across
    sub-agents that share a lead's plan. Keep free-text sharing *within* a crew's zone (§13.7) and typed fields
    *across* zones, and include a crew task in M5 so the utility cost is known. *(§2.6, §13.7, §19 M5.)*

12. **Make the audit independent of the agent, and reviewable by an LLM outside the box.** HAL and METR found
    shortcuts and harmful side effects only by reviewing logs. Meng et al.: "logs are not independent audit" when
    the harness writes them. wicket's records come from the proxies and the ledger, so say that in §14.2. Plan
    Docent-style review of those records, outside any zone, as a later console feature. *(§3, §14.1.1, §14.2.)*

13. **Export transcripts as ATIF.** Harbor's trajectory format is becoming the interchange for evaluation and
    training tooling ("the harness is the dataset"). Emitting ATIF from wicket's event log, with labels and
    request ids in `extra`, makes wicket runs usable by that tooling at little cost. Low priority. *(§14.1.1.)*

14. **Disclose the harness in wicket-bench reports.** Following *Stop Comparing … Without Disclosing the
    Harness*: each result names the agent version, adapter version, zone policy digest and sandbox backend. Under
    principle 7 this is generated, not written. Low priority. *(§2.7, §19.)*

---

## 5. Sources not reached or left at low confidence

- OpenAI blog pages (`openai.com/index/...`) returned 403 to the fetcher, so all OpenAI essays are [M] from
  InfoQ, search excerpts and citing papers.
- Preprints.org (the control/agency/runtime paper) returned 403. The Meng et al. survey was read through its
  GitHub README, not the PDF.
- Talks (Lopopolo, Trivedy) were seen only through aggregator listings, with no primary video or transcript.
- AFlow, MAST and Magentic-One were read at abstract level. HarnessAudit-Bench only as a search snippet.
