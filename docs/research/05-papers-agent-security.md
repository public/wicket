# 05 — Academic literature on system-level LLM-agent security, studied against wicket

*2026-11-08. Full-text study of 44 papers (2024–2026): defences against prompt injection by design,
privilege control, policy derivation, information-flow control (IFC) for agents, and isolation and
compartmentalisation of agents. Each paper is evaluated against [`../design.md`](../design.md) v0.1.*

**Method.** Every paper was read in full from a local `pdftotext -layout` copy: the body in full,
appendices where they bear on mechanisms or limitations, references skipped. Each paper has its own
directory `refs/papers/<key>/` (paths are relative to the repository root) with the PDF from
`arxiv.org/pdf/<id>`. Some directories (`agentdojo/`, `asb/`, `attacker-second/`, `auth-delegation/`,
`etdi/`, `mcpsecbench/`, `mcptox/`) were created by a parallel prior-art collection run, and I reused
them rather than keep duplicates. Code repos were shallow-cloned read-only into `refs/repos/` only
when the repo was small and directly useful; nothing was built or run.

Two cloned repos contain their own agent-instruction files (`CLAUDE.md`, `AGENTS.md`,
`.claude-plugin/`): `refs/repos/cedar-synthesis-engine` and `refs/repos/sandbox_escape_bench`.
`sandbox_escape_bench` also contains exploit PoCs. **Never start an agent session inside
`refs/repos/`.**

**Confidence notation.** H/M/L is how confident I am that I read the paper correctly. It is not a
rating of the paper. Numbers are each paper's *own* numbers: baselines for CaMeL and Progent vary
widely between papers (§10.3), so don't compare them across entries.

**Black-box lens.** Most of these systems own the agent loop: they are the planner, the interpreter or
the tool dispatcher. Every entry therefore says what survives when wicket can only mediate at the LLM
proxy, the MCP gateway, the egress proxy and the gates between zones (design §3, §8).

**Cited IDs checked and left out of scope:**
- 2407.01688, *How We Built Cedar*: Cedar's verification process, not agent security. It is
  background for `wicket-verify`, and 03 §1 covers it; the sibling copy is at `refs/papers/cedar-howbuilt/`.
- 2511.03690, *OpenHands Software Agent SDK*: an agent framework, covered in 01.

**Not studied here.** These candidates were found but cut for scope:
- Operationalizing CaMeL (2505.22852);
- the prompt-injection SoK (2602.10453) and the IPI-defence taxonomy (2511.15203);
- Prompt Infection (2410.07283);
- Task Shield, IPIGuard, and the runtime guard models (ShieldAgent, AgentSpec, GuardAgent).

The parallel run also collected MCP and attack papers (`refs/papers/mcp-*`, `gitinject`,
`aishelljack`, `toolhijacker`, `injecagent`, `wasp`, `oidf-agentic-id`, …). They are not reviewed in
this note.

Sections 1–9 hold the per-paper notes, grouped by mechanism. Section 10 is the synthesis, ranked
design changes and contradictions. Section 11 is the table.

## Contents
1. Defences by design and planner-level IFC: CaMeL, Design Patterns, FIDES, SPA, APPA, CXI
2. IFC variants and data minimisation: f-secure, RTBAS, Permissive IFC, AirGapAgent
3. Policy derivation and least privilege: Progent, Conseca, MiniScope, AuthBench, AutoCedar
4. Runtime rules, detection and HTTP-level mediation: DRIFT, ceLLMate, MELON, AgentArmor, FLOWSEAL
5. Isolation and compartmentalisation: IsolateGPT, ACE, PFI, OpenClaw privsep, MAS-injection
6. Privilege escalation, confused deputies, capability scoping, OS-level enforcement: SEAgent, MAS hijacking, Capability gates ≠ authz, CapScope, ActPlane
7. MCP access control, delegation and acquired authority: AgentBound, Acquired-resource authorization, Authenticated delegation, ETDI
8. Evaluations, SoKs and sandbox escape: Adaptive-OOB, Attacker Moves Second, Systems SoK, Architecting Secure Agents, SandboxEscapeBench
9. Benchmarks: AgentDojo, ASB, MCPSecBench, MCPTox, MCP-SafetyBench
10. Synthesis: cross-cutting lessons, ranked design changes, contradictions
11. Paper table

---

## 1. Defences by design and planner-level IFC

### CaMeL — Defeating Prompt Injections by Design (arXiv 2503.18813v2, 2025-06-24; Google, Google DeepMind, ETH Zurich)
- https://arxiv.org/abs/2503.18813 · `refs/papers/camel-2503.18813/2503.18813.{pdf,txt}` · code: https://github.com/google-research/camel-prompt-injection (Apache-2.0), cloned to `refs/repos/camel-prompt-injection` (read only; `src/camel/capabilities/`, `security_policy.py`, `pipeline_elements/security_policies/*.py`)
- **Problem & threat model.** Indirect prompt injection from tool outputs that diverts either the control flow (which tools run) or the data flow (which arguments they get). The user prompt is trusted, and so is memory. Explicit non-goals (§3.1): text-to-text attacks with no data-flow consequence (misleading summaries, phishing links shown to the user), and full autonomy. The user is expected to confirm some actions.
- **Mechanism.**
  - A **P-LLM** sees only the user query plus tool signatures, and writes a program in a restricted Python subset. It never sees tool outputs or Q-LLM outputs, only its own code (§5.1).
  - A **Q-LLM** has no tools. It parses untrusted data into a Pydantic schema that the P-LLM chooses. One extra boolean is injected into the schema, `have_enough_information`. When it is false the interpreter raises `NotEnoughInformationError`. The Q-LLM **cannot tell the P-LLM what is missing**, because that would be an injection channel.
  - A custom AST interpreter tags every value with **capabilities** (§5.3):
    - *sources*: `User` (literals in the P-LLM code), `CaMeL` (derived), `Tool(name, inner_sources)`. Inner sources are things like an email's sender or a document's editors.
    - *readers*: `Public`, or a frozenset of principals. In the code, `Public & S = S`, so combining values intersects their readers.
  - The interpreter keeps a dependency graph. In **STRICT mode**, the test of an `if`/`for` becomes a dependency of everything assigned inside the block, and every statement after a Q-LLM call depends on that call's inputs (§5.4, §7).
  - **Policies are Python functions** per tool, `(tool, kwargs) → Allowed | Denied(reason)`. Examples (App. E):
    - `send_email`: the recipients must come from the User, and the body and attachments must be readable by every recipient.
    - `send_money`: the recipient and the amount must have the User as source, with no untrusted parent.
    - `get_webpage`: only if the URL is public.

    In a real deployment a denial means **asking the user to confirm**, not halting.
  - Exception text that depends on untrusted data is **redacted** before the P-LLM sees it. The P-LLM gets up to 10 retries. There is no atomicity or rollback for partial side effects.
- **Results.**
  - Utility on AgentDojo (Table 2): o3-high **77.3% vs 84.5%** native (the abstract's 77/84). Claude 4 Sonnet 74.2% vs 86.6%. Gemini 2.5 Pro 41.2% vs 73.2%. The losses concentrate in Travel, where tool output formats are undocumented and the P-LLM cannot see them.
  - Attacks out of 949 (Table 4): for example, Gemini 2.5 Flash 297 → 1 and Claude 4 Sonnet 75 → 11. The remaining successes are the "say I should visit hotel X" text attack (out of scope) and one banking case without policies.
  - Policies add little security over isolation alone on AgentDojo. They matter for the data-flow case study in §6.4.
  - Policy-denial (confirmation) rates are high in Slack and Banking, where identities are unclear, data comes from the web, or policies are strict. They are low in Workspace, where tools annotate readers (§6.2.2).
  - Token cost for the median task: **2.82× input, 2.73× output** (§6.5).
  - Failure modes (Table 1) include "data requires action": tasks like "do what the email says" cannot be planned without reading the data.
  - Admitted limits:
    - side channels: indirect inference via fetch counts, 1-bit leaks via exceptions, timing (§7);
    - ROP-like composition of allowed blocks (§9.3);
    - users must write and maintain policies, and approval fatigue (§9.2);
    - every tool must participate in capabilities (§9.1);
    - §6.4, *data flow becomes control flow*: a P-LLM-written dispatcher that "does the action in the email" gives the attacker arbitrary tool choice.
- **For wicket.**
  - *Borrow:*
    - Already in §5.2: derive the manifest from trusted text only.
    - (a) **Sink-argument provenance at decision time, not only in escalations.** Adapters mark sink parameters (recipient, target repo, URL host, @mention). An R3+ Op whose sink value is not traceable to task text, manifest or grant goes to escalation. This generalises §10's field provenance to §8 enforcement.
    - (b) **Reader-set labels derived from provider metadata.** CaMeL's readers come from the tool, e.g. an email's recipients. Wicket adapters could derive `conf` from repo visibility or collaborators, not only from a static default (§4.2, 03 §5.3). CaMeL's lower denial rate in Workspace is evidence that better source annotation cuts prompts.
    - (c) Give the §4.3 `QuarantinedReader` an `enough_information: Bool` field and **no free-text error channel**.
    - (d) Deny and pending bodies (§8.5) must not echo tainted content back. This mirrors exception redaction.
  - *Challenges:*
    - §6.4 is a warning for §5.2. Task text that delegates control to data ("do the TODOs in issue #12") makes the plan attacker-controlled. The manifest proposer should flag such tasks and force a tainted, narrow zone or human review.
    - Gate *outcomes* (child failed, schema rejected, timing) are CaMeL's exception side channel at tree level. They should carry the child's label (§11 covert channels).
    - CaMeL chose Python policies for expressiveness. Wicket's closed vocabulary plus Cedar trades that away for analysability. CaMeL's own §10 says Python's complexity (exceptions) hurt security, which supports wicket's choice.
  - *Black-box:* CaMeL **requires owning the agent loop**, because the P-LLM writes the program and the interpreter runs it. Wicket cannot re-plan Claude Code. What survives:
    - the tree-level analogue, with wicketd as P-LLM and interpreter, child zones as calls, and gates as policy checks;
    - a per-agent coarse label, which is at least as conservative as STRICT mode, since everything in a tainted agent's context is tainted, so implicit flows inside the agent are covered;
    - quarantined readers;
    - proxy-side sink checks, using value-membership provenance in place of real per-value tracking. This is conservative, but it gives false denials when the agent transforms values.
- Confidence: **H** (body, §7, App. E/B tables and repo capability code read).

### Design Patterns — Design Patterns for Securing LLM Agents against Prompt Injections (arXiv 2506.08837v3, 2025-06-27; Beurer-Kellner, Tramèr et al., Invariant/IBM/ETH/Google/Microsoft…)
- https://arxiv.org/abs/2506.08837 · `refs/papers/design-patterns-2506.08837/2506.08837.{pdf,txt}` · no code
- **Problem & threat model.** Prompt injection from any untrusted input. They make no direct/indirect distinction, and user-prompt injection is included. The goal is application-specific agents that resist injection by construction. They state plainly that general-purpose agents are unlikely to get meaningful guarantees with current LLMs (§3).
- **Mechanism.** Guiding principle: *once an agent has ingested untrusted input, it must be impossible for that input to trigger consequential actions*. Its outputs also must not exfiltrate (e.g. links) or steer later behaviour. The six patterns:
  1. **Action-Selector.** A fixed or templated action set, with no feedback from action results.
  2. **Plan-Then-Execute.** A fixed list of tool calls before any untrusted data arrives. This is control-flow integrity only: injections can still change arguments, e.g. the email body.
  3. **LLM Map-Reduce.** One isolated, tool-less LLM per untrusted item with a constrained output (e.g. a bool). The reduce step is either non-LLM and robust to individual inputs, or an LLM whose inputs are format-checked (regex).
  4. **Dual LLM.** Privileged plus quarantined, with **symbolic `$VAR` results** that only a non-LLM orchestrator dereferences at call time.
  5. **Code-Then-Execute.** CaMeL.
  6. **Context-Minimization.** Remove the user prompt or earlier content from context before later steps.

  App. A "best practices": action sandboxing, with agent-specific least-privilege commands (a sanitized search tool in place of `find`, which can execute); strict output formatting; agent permissions ≤ user rights; user confirmation, with explicit fatigue caveats; data and action attribution.
- **Results.** No experiments. There are ten case studies (§4, Table 1), each a design walk-through with utility and security trade-offs. Relevant ones:
  - **OS assistant (§4.1).** Plan-then-execute with only `find`+`mv` can still be steered to copy sensitive files to a public share. *Tool-level allowlists are insufficient.* Map-reduce with a bool per file is the recommended design. Even then a malicious file can get itself moved where it doesn't belong.
  - **SQL agent (§4.2).** Sandbox the Python interpreter with only the necessary connections. Reconnaissance and leakage through outputs remain.
  - **SWE agent (§4.10).** Confirmation is weak because a hijacked agent can hide its effects. It can add an import of a malicious package and let the user install it, or embed a web request *in the code*. Action-sandboxing, meaning trusted documentation and code sources only for sensitive actions, "significantly limits" usability. The safest design is a Dual LLM in which a quarantined LLM converts untrusted docs and code into a strictly formatted API description (e.g. method names ≤30 chars).
- **For wicket.**
  - *Borrow:*
    - Pattern 3 maps directly onto **disposable child zones joined by a typed gate** (§4.3, §5). The paper adds that the *reduce* step should be **deterministic in wicketd where possible**, not another LLM.
    - Pattern 4's `$VAR` is wicket's **Handle** (§4.3). The paper confirms that dereferencing belongs to a non-LLM orchestrator, the gateway.
    - Pattern 6 is wicket's fresh agent per subtask (03 §5.2).
    - The §4.10 "API description" quarantine is a ready-made `QuarantinedReader` schema for the `research → fix` gate. It is an alternative to free-text notes behind a handle.
    - **New option, from Pattern 1:** a zone or adapter flag **`response: status_only`**. The gateway or proxy returns only success/failure and typed IDs to the agent, never upstream bodies, so a write-only zone cannot be injected by what it writes to.
  - *Challenges:*
    - §4.10 says a tainted coding agent's *artifacts* (code, dependency manifests) are themselves deferred execution and exfiltration channels. Wicket's integrity rule blocks pushes from web-tainted zones (§4.2, §5). The same must hold for **extracted patches or handles that later reach a push or a human merge**. A patch handle from a web-tainted zone must keep its taint through `extract(Patch)` (§7) and block R2+ pushes unless endorsed. This is already implied, but worth making an explicit invariant and an M5 test.
    - The §4.1 point, that combinations of allowed commands exfiltrate, supports wicket's resource-level `send` rules over tool lists.
  - *Black-box:* patterns 1, 2 and 5 assume the designer controls the agent loop. Wicket can impose them only at **zone granularity**: the manifest fixes reach, as a capability-level plan-then-execute (which the paper notes is CFI only), and `status_only` approximates action-selector. Patterns 3, 4 and 6 survive fully, because they are about *which agent instance* sees what, which is exactly what zones, gates and handles control.
- Confidence: **H** for the patterns and principle, read in full. **M** for case studies other than §4.1, §4.2 and §4.10, which were skimmed.

### FIDES — Securing AI Agents with Information-Flow Control (Microsoft; arXiv 2505.23643 v2, 2025-09-03)
- https://arxiv.org/abs/2505.23643 · `refs/papers/fides-2505.23643/2505.23643.{pdf,txt}` · code: https://github.com/microsoft/fides (a tutorial notebook, MIT), cloned to `refs/repos/fides`. Not the AgentDojo evaluation harness.
- **Problem & threat model.** Indirect prompt injection (PIA) and exfiltration in tool-using agents. The agent configuration is trusted: system message, **tool descriptions** and LLMs. The adversary controls data that tools return and can observe some tool side effects, such as a URL fetched from its own server (§2.1).
- **Mechanism.**
  - *Labels.* Labels come from a join semi-lattice; meet is not needed (§4.1).
    - Integrity is {T ⊑ U}, or a writers-powerset with join = ∪.
    - Confidentiality is {L ⊑ H}, or a readers-powerset with join = ∩.
    - The evaluation uses the product of binary integrity and readers confidentiality.
    - Labels sit in a metadata field on every node of a JSON tool-result tree. A child node inherits its parent's label unless it overrides it. "Trusted wrappers" around every tool attach the labels, turning hints such as Mark-of-the-Web, external-sender flags, the recipient list and MCP `readOnlyHint` into labels. External data defaults to U.
  - *Propagation (Alg. 5/6).* An LLM response gets the join of the labels of everything in its input context. The paper calls this "signifying the inability to precisely propagate labels through LLMs". A tool's result and the datastore variables it may write get the join of the tool label, the argument labels and everything it may read.
  - *Policies.*
    - A check is `ℓ_f ⊑ π_f ∧ ∀x. ℓ_x ⊑ π_x`.
    - **P-T** (trusted action): π_f = (T, ⊤). A consequential tool may run only if the context that chose the call was fully trusted. This gives integrity **non-interference**.
    - **P-F** (permitted flow): for `send(R, d)`, π_d = (⊤, R). This gives only **explicit secrecy**; implicit flows through which tools get called are allowed on purpose (§4.3–4.4, Prop. 1).
    - "P-T or P-F" amounts to robust declassification. The evaluation adds a rule that blocks sends containing untrusted links (App. D.1, Table 3).
  - *HIDE / EXPAND (§5.1, Alg. 7).*
    - HIDE: any result node whose label is not ⊑ the current context label goes into a fresh variable (`#read_emails_0.subject`), so the context label stays put.
    - EXPAND: variables are substituted into tool arguments at dispatch time. This gives **per-argument labels separate from the tool-decision label**; for example, the recipient must be T while the body may be U.
  - *query_llm (§5.2).* An isolated, tool-less LLM with constrained decoding returns a typed variable. The labels gain a capacity component `bool ⊑ enum ⊑ string`. A U-bool *could* be endorsed for consequential use. The authors say "use with care", and their evaluation keeps strict P-T (§6.2).
- **Results.**
  - AgentDojo, Tool Knowledge attack, 949 attacks, gpt-4o (Table 1):
    - Basic planner: 163 successful attacks.
    - FIDES without policy: 24.
    - FIDES★ with policy: 1. Under the paper's attack definition this is 0; the residual cases are text-to-text injections in the final answer and a no-exfiltration calendar case (§8.1).
  - Utility with policy on (Table 7): Basic falls to about 41–45%. FIDES★ reaches 50–61%, versus 79–82% for FIDES without policy on reasoning models. Prompt tuning adds about 8 points.
  - Token use is 2–3× that of Basic (App. E).
  - Failure modes: models misuse `query_llm`, and "compensatory leakage": a model that can't use `query_llm` inspects the variable instead, taints its context and gets blocked (§8.2).
  - Limits:
    - No policy on the final text response.
    - Implicit flows are not covered.
    - Labels in AgentDojo were assigned by marking every field any injection targets as U.
    - AgentDojo lacks ground-truth labels.
- **For wicket.**
  - *Borrow:*
    1. Collapse the policy surface to two generic rules, as §4.2's "Act (integrity)" and "Send (no write-down)" already do. FIDES shows two rules applied uniformly can stop the whole AgentDojo suite, which argues for keeping per-zone rules few.
    2. **Selective HIDE at the MCP gateway (§8.2).**
       - In a gateway-native tool response, replace every field whose label is not ⊑ the agent's current label with a handle (`wicket:h/…`), instead of joining it into the agent.
       - Allow handles as *arguments* to gateway tools, with the gateway doing EXPAND. Example: `pulls.create(body = h:notes)`. The body's label is checked against the destination's clearance (P-F), while the decision label (the agent's own) must pass P-T.
       - design.md has `read_handle` but no "pass a handle through without reading it" to a sink. That is the missing EXPAND.
    3. The `query_llm` signature (input handle(s) + output schema → capacity-typed value) is exactly `GateRule::QuarantinedReader` (§4.3), and could be exposed as a `wicket.query` tool.
  - *Challenges:*
    - FIDES trusts tool descriptions; wicket must not (it hash-pins them, §8.2).
    - FIDES itself declined to endorse low-capacity values in its evaluation. wicket's `endorse` on enum/bool fields (§4.3, §5) is therefore a step beyond what was evaluated, and should require a validator against trusted state (see CXI).
    - Compensatory leakage predicts that black-box agents given handles will often just dereference them. Measure this in M5.
  - *Black-box:* FIDES assumes full control of the planner loop.
    - What survives at wicket's surfaces: the P-T/P-F checks against a per-agent floating label (wicket's design already does this); HIDE/EXPAND for gateway-native tools (the gateway owns the response shape); and `query_llm` as a gateway tool.
    - Raw `gh api` or `curl` through the egress proxy can't be hidden without breaking the client. Those responses must be joined into the agent's label wholesale.
- **Confidence:** H.

### SPA — SPA: Securing Persistent LLM Agents Across Queries with Plan-First Information-Flow Control (Univ. South Florida; arXiv 2608.27234 v2, 2026-09-04)
- https://arxiv.org/abs/2608.27234 · `refs/papers/spa-2608.27234/2608.27234.{pdf,txt}` · code: anonymised archive (anonymous.4open.science/r/spa-C26E). Not cloned: not on GitHub.
- **Problem & threat model.** Persistent agents serving queries q1…qn. Attacker data can steer control flow, become a sensitive tool argument, or lie dormant in stored state until a later query uses it: a "delayed planning" or "delayed execution" attack (§3).
  - The adversary may control tool metadata, tool implementations, tool outputs and ingested content.
  - The user query and the deployment configuration (lattices, per-tool policies, tool bindings) are trusted.
- **Mechanism.**
  - *Planning.* The planner is called **once per query** and emits a complete JSON plan in a 6-step DSL: `retrieve`, `tool`, `q-llm`, `display`, `condition`, `loop` (§5).
    - Value expressions are references, projections, literals and JSON only: no templates, no arithmetic. Predicates come from {eq, neq, lt, lte, gt, gte, in, exists}.
    - The planner gets **no verifier or execution feedback**, and invalid plans are not repaired. This is so "iterative replanning [cannot become] a feedback channel for adversarial content" (§4.1).
  - *Verification (Alg. 4).* A static pass over the plan before execution.
    - Labels are dual lattices (C, I), joined as `(c1 ⊔ c2, i1 ⊓ i2)`.
    - Each tool has an input policy λin = (C_in, I_in) and an output baseline λout. Display has its own policy λdisp.
    - A pc label covers implicit flows through `condition` and `loop`.
    - A q-LLM output **inherits** its input label, so no laundering is possible (§6.2).
    - A display violation is redacted rather than rejecting the plan.
  - *Execution.* A deterministic interpreter. Tools run in an ephemeral container with no network, read-only filesystem, an unprivileged user and a timeout. Every value is JSON-Schema checked.
  - *Persistence (Alg. 3).* Each artifact is split three ways:
    - Σω holds the payload.
    - Σλ holds the label.
    - Σα holds planner-visible metadata: schema, plus the planner-authored `intent` and `output_semantics` annotations and the source query.
    - Later planners see only Σα. A `retrieve` step restores the stored label.
  - *Abstract mode (after ACE).* The planner sees tools synthesised from the query instead of the installed catalogue. Plan steps are then bound to installed tools by embedding similarity and generated mapping code, which runs in a restricted interpreter.
- **Results** (AgentDojo v1.2.2, tool_knowledge, gpt-5.4-nano; Tables 1–3, Fig. 4).
  - Concrete mode, no IFC: 53.0% utility, 0.4% ASR.
  - Concrete mode with IFC: **29.0% utility, 0.0% ASR**. About 53% of IFC trials stop at `ifc_failed`, typically because untrusted output feeds a higher-integrity argument.
  - AgentDojo-MQ: 62.5% → 35.3% utility with IFC, 0.2% ASR. Reuse soft-hit is 89.9% with IFC.
  - Showing stored values to later planners raised utility by only 3.4 points and doubled ASR from 0.3% to 0.6%.
  - Abstract mode: about 75% of trials fail at tool mapping, and travel utility is 0%.
  - Limits the authors admit:
    - tool_knowledge only weakly exercises delayed attacks.
    - Strict Biba integrity has an "inherent" utility cost; they suggest field labels, argument-specific integrity, or scoped endorsement.
    - Policies sit in the TCB.
    - AgentDojo-MQ is hand-built.
- **For wicket.**
  - *Borrow:*
    1. **Handle metadata must be trusted-authored.** In SPA, what later planners see is written by the trusted planner *before* execution, never by the code that touched the payload. For wicket (§4.3, §11): a handle's description or schema shown to a parent or later task should come from the manifest or gate definition (e.g. `notes: handle` declared in the gate). Any child-written summary is `Untrusted<String>`. Today `Handle.schema` is optional and nothing says who writes it.
    2. **Single-shot derivation:** the manifest proposer (§5.2) and the parent-tier re-derivation (§10) should not iterate on verifier or agent feedback within a task. If a proposed manifest is rejected, it goes to a human.
    3. **User-visible output is a sink with a policy** (λdisp). Redact rather than abort. wicket's final outcome, transcript views and `explain` output should apply the conf rule toward the human viewer's clearance.
    4. The evidence for §16 Q2 is sobering. Even with *plan-level* IFC, strict integrity halves utility. wicket's coarser per-agent taint will cost at least as much, so typed gates and disposable children are necessary, not optional.
  - *Challenges:* none directly. SPA's "no feedback" rule applies to *trusted* planners. wicket's structured denials go to the *untrusted* agent (§8.5), which is fine because they cannot widen authority.
  - *Black-box:* SPA requires the agent to *be* a DSL planner, so it does not apply to Claude Code itself.
    - What survives: label-preserving stores with trusted metadata (§11); the display-sink policy; single-shot trusted derivation.
    - The pc-label idea is subsumed by wicket's per-agent floating label: everything the agent does after reading is control-dependent on it.
    - The abstract-mode result argues *against* hiding wicket's own adapter catalogue from the proposer. wicket's adapter descriptions are trusted. Third-party MCP descriptions should stay out of the proposer's context.
- **Confidence:** H for mechanism, M for numbers. The tables were garbled by text extraction and were reconstructed from the prose.

### APPA — APPA: Recoverable Information-Flow Control for Real-World LLM Agents (Archestra AI; arXiv 2607.24625 v2, 2026-08-26)
- https://arxiv.org/abs/2607.24625 · `refs/papers/appa-2607.24625/2607.24625.{pdf,txt}` · code: none linked in the paper beyond https://openappa.com. The authors are from a vendor.
- **Problem & threat model.** Monotone taint "strands" agents: once untrusted data is read, everything downstream is blocked.
  - The LLM is policy-untrusted (injection, hallucination).
  - The TCB is the monitor, deployment profiles, tool contracts, authority resolvers, sanitizers, schema validators and casts.
  - Covert timing channels and malformed tools are out of scope (§3).
- **Mechanism.**
  - *Labels.* L = (R, t): a reader set and a totally ordered trust chain. They combine by meet: (R∩R′, min(t, t′)). The trajectory label only descends (Props 1–2).
  - *Tool contract.*
    - A declared label contribution dτ.
    - Effect tokens Kτ, committed on reported success into an append-only log E.
    - `requires` preconditions: trust floors, audience cover, `prior(k)` / `no_prior(k)` history predicates, and mandatory authority gates.
  - *Gate 1 (pre-dispatch, prospective).* Checks the rendered call against cτ(L) = L ∧ dτ, i.e. the label the agent *will* have after the call.
    - This is needed for composite read-and-send tools: Prop. 4 shows a reactive monitor leaks there.
    - A label-narrowing call needs an explicit in-session `Accept`.
  - *Gate 2 (admission).* Re-checks the realized return against its contract before folding it into L.
  - *Gradual typing.* Unannotated tools contribute an `Unknown` source. A registered cast resolves it lazily, under a `may_cast` ceiling, when a sensitive sink consumes it. If no cast applies, it fails closed (Prop. 3, no laundering).
  - *Recovery (Thm 5).* A blocked call clears only through four registered transitions: commit a prerequisite effect, a call-scoped authority ruling, a registered sanitizer or cast, or running the narrowing work in a child branch. The engine searches a finite recovery graph and returns the remedies to the agent.
  - *Call-scoped authority (§5, Thm 6).*
    - Authorities can be rules, humans or LLM judges, each bounded by a declared *mandate*.
    - A ruling binds to the rendered-call hash, is single-use, and does not change L or E.
    - Rulings do not cross fork boundaries.
  - *Trajectory confinement (§6).*
    - `fork` starts a child from the parent's transcript snapshot *with the parent's label*: L0c := Lp, so a child can't launder what the parent has already seen.
    - Exit is one of: abandon (no change), a labelled return that needs parent `Accept`, or `attest-schema`.
    - `attest-schema` accepts closed shapes only: bool, bounded int, decimal, enum, bounded arrays and objects, no free text. It confines **shape, not semantics**. Promoting integrity is an explicit TCB decision ("a malicious child can still select an allowed false value").
    - Effects a child committed before abandonment stay in E.
  - *Deployment tiers (§6.1).* The gateway tier (MCP proxy) runs Gates 1 and 2. The **harness or inference-proxy tier** is needed for forks. The authority tier issues rulings.
- **Results** (§7, Table 1).
  - AgentThreatBench (OWASP agentic Top 10, 24 tasks): 0/720 attacks at 64.2–76.7% utility.
  - Bench-Corp (their own 20 enterprise scenarios): 176–180 of 200 tasks, 0/600 attacks.
  - Their Fides-configured arms: 26.7–74.2% utility, up to 30.8% ASR under the "chaos" prompt.
  - Ablations (Luna, Bench-Corp): removing remedy plans drops utility to **35.0%**; removing child branching drops it to **56.5%**, both at 0% ASR. Full APPA is about 87–89%.
  - Limits the authors admit:
    - Contracts must be accurate.
    - The Fides comparison is configuration-specific.
    - The 20–24 task designs are repeated, not independent tasks.
    - A finite zero ASR is not proof of security.
    - Memory-poisoning utility trails F-M.
    - Exactly-once holds only with idempotency keys or reconciliation.
    - AgentDojo was skipped as saturated.
- **For wicket.**
  - *Borrow:*
    1. **Prospective labels in the decision (§3, §4.2).** For an Op that both reads and sends (e.g. "create a gist from a file", a `gh api` call whose response is echoed elsewhere, git push of content just fetched), check send/act rules against `agent.label ⊔ adapter.response_label(op)`, not only the current label. Adapters (§9) should declare a response label per endpoint. §5.3 already has default labels, so the change is to use them *before* dispatch as well as after.
    2. **Gate 2 at proxy and gateway:** compute the realized label from the response (e.g. GitHub `author_association` on comments) and join it, never relax.
    3. **History predicates in the ledger.**
       - `prior(tests.passed)` before `pulls.create`.
       - `no_prior(merge)` for exactly-once.
       - Committed-effect tokens recorded only on upstream success.
       This is cheap on top of §10's ledger and Cedar context.
    4. **Remedy enumeration in denials (§8.5, §10 `narrower_alt`).** The ablation is the strongest evidence in my set that returning structured, policy-derived remedies (spawn a child, satisfy a prerequisite, request a ruling) roughly doubles utility relative to bare blocking. It supports E1's structured-pending arm.
    5. **Grants are non-transferable across spawn.** Live single-use grants and pending requests do not pass to children (§5.1). A child spawned by a tainted parent inherits the parent's label, which matches §5.1's task-text label inheritance.
    6. **Authority mandates:** the parent/LLM decider tier (§10) gets an explicit mandate, e.g. "may grant ≤R2 within zone ceiling, never endorse", checked mechanically. That makes turning the parent tier on safer.
  - *Challenges:*
    - APPA lets `Unknown` data flow until a sink. wicket denies unmapped endpoints and defaults unknown risk to R4. That is stricter, and fine for *authorization*. For *labels*, an `unknown` taint tag that blocks R2+ unless an adapter resolver "casts" it is equivalent and cleaner than guessing defaults.
    - APPA's view that endorsement is never implied by shape agrees with design.md only if `endorse` stays explicit per field.
  - *Black-box:* Gates 1–2 and rulings work at an MCP gateway with no loop control; the authors say so (§6.1). Fork/branch needs a harness or inference proxy that controls context. For Claude Code, wicket gets the equivalent by spawning a disposable child zone (fresh process) whose return crosses a typed gate. wicket can't give the child the parent's transcript prefix, which is a utility loss but also less taint inherited.
- **Confidence:** H for mechanism, M for results (vendor authors; benchmarks partly their own).

### CXI — Context-to-Execution Integrity for LLM Agents (single author, UNIR; arXiv 2607.06000 v1, 2026-07-07)
- https://arxiv.org/abs/2607.06000 · `refs/papers/cxi-2607.06000/2607.06000.{pdf,txt}` · code: an "anonymous review artifact" is mentioned; no public repo was found.
- **Problem & threat model.** "Authority laundering": a value that should only be evidence, such as a CI log, issue body or runbook, ends up selecting, authorizing, triggering or parameterizing a privileged side effect.
  - The attacker writes issues, docs, CI logs, tool outputs, retrieval docs, package metadata, memories and other agents' messages.
  - Policy, the user objective, the host runtime and privileged tools are trusted (§2).
- **Mechanism.**
  - *Five state classes:*
    - **T**: trusted state (objective, policy, registry, approvals).
    - **W**: writable context.
    - **D**: a typed release, minted only by trusted declassifier code that canonicalises and validates against a trusted snapshot. It is scoped to **one destination field**; for example, a `FilePath` release authorizes `file_path` only.
    - **O**: an opaque data slot that copies W as evidence with no authority. Its text re-enters as W at any later side-effecting reader.
    - **X**: protected sink fields: tool, operation, recipient, namespace, path, approval, CI target, delegation, install target.
  - *Field rule.* W ↛ X unless W → D → X. Sink schemas must be **total**: an unclassified field rejects.
  - *Provenance of influence, not bytes.* A field spelled with trusted bytes but *chosen* because of W counts as W-derived. Unknown, stale or repaired provenance rejects.
  - *Exact-effect authorization (Table 2).* Effect-bearing payloads (patches, file bodies, SQL, shell, CI YAML, package manifests) are bound to a commitment over the sink-interpreted effect. For a repo patch that is the state delta over the base commit (paths, old/new blobs, modes, symlinks, allowed path set). The adapter rejects traversal, CI disablement, install hooks, secret writes and replay.
  - *Invocation authority.* A manifest-bound `InvokeCapability` names sink, operation, budget, sequence, idempotency key, expiry, snapshot and policy epoch. It is consumed in a linearizable ledger, and execution happens only under the resulting lease. W must not control retries, batching or scheduling.
  - *Action manifest.* The six-step gate (canonicalise → fields → effects → invoke capability → consume → execute) binds everything to one digest. Any mutation changes the digest and rejects.
  - *Two provenance paths.* For open-weight models, attention masking of W tokens while protected fields are decoded (vLLM). For hosted/API models, an **extractor sees T+W but emits only typed facts and opaque handles, and field writers see only T+D** (§4.4).
- **Results** (§5, Table 6).
  - AgentDojo: 720 live episodes, 199 safe task completions, 0 field, effect or invocation escapes.
  - Code-agent benchmark: 400 episodes, 231 safe completions. The rest: 73 parse failures, 61 with no effect authorization, 35 authorized but task failed.
  - Hosted/API path: 85/800 unsafe selections blocked.
  - Proposal pressure: models *proposed* unauthorized fields in 196/300 and 407/522 cases, so the gate, not the model, is doing the work.
  - Schema-only structured output still gives unauthorized execution 1.000 on the 192 CXI-Core cases; CXI gives 0.000.
  - Policy effort (§5.8): 24 sinks, 149 fields (85 X, 20 D, 29 O, 19 effect-bearing), 141 validator tests. The first audit found 18 policy defects: missing effect-bearing payloads, over-broad opaque slots, missing destination scopes, natural-language approval, unmarked re-entry.
  - Limits the author admits: the claim is conditional on complete mediation, correct policies and complete validators. There is no exactly-once external guarantee, and the hosted path has no provider-internal evidence.
  - No implementation-level baselines against CaMeL, FIDES or PACT; only mechanism ablations (12/20, 10/20 and 8/20 attacks rejected versus 20/20).
  - The prose and accounting are dense, with mixed denominators.
- **For wicket.**
  - *Borrow:*
    1. **Classify adapter fields** (§9): protected (X), typed-releasable (D, with a named validator), opaque (O), effect-bearing. "Total over inputs" already exists; add the class and make "unclassified → deny".
    2. **Opaque re-entry as taint** is §5.3's provider-side label store. CXI independently states the rule for PR bodies and comments.
    3. **Exact-effect for git** is §8.1's store-and-forward. Bind the decision to (base OID, tree delta, allowed paths) and push with expected old OIDs, as already planned.
    4. **The invocation capability with idempotency key and lease** matches §10 grants plus the ledger. Add idempotency keys for R3 effects, and make sure W cannot trigger retries that consume extra uses.
    5. **The hosted/API path is wicket's two-zone split:** reader zone → typed gate → writer zone (§5). It is the black-box way to get field-level authority, and it validates the manifest example's design.
  - *Challenges:*
    - **§10 "field provenance" must not be byte-matching.** CXI's point is that a tainted agent can choose a trusted-spelled value (a path or repo that does appear in the task text) *because* of W. In wicket, field provenance should be necessary but not sufficient: a field that traces to trusted text still needs the agent's taint ⊆ `action_taint_allow`. Otherwise "provenance OK" in the auto tier is laundering.
    - Endorsement on gate fields (§4.3) should require a validator against trusted state, like the manifest's "names a file in the repo", not just a capacity bound.
  - *Black-box:* the gate needs no loop control: it runs at gateway, egress and git. The open-weight masking path is irrelevant to Claude Code. The hosted path needs the reader/writer split that wicket does with zones.
- **Confidence:** M for mechanism, L–M for results. Single author, unusual accounting, no public code.

## 2. IFC variants and data minimisation

### f-secure LLM — System-Level Defense against Indirect Prompt Injection Attacks: An Information Flow Control Perspective (arXiv 2409.19091 v2, 2024-10-10)
- https://arxiv.org/abs/2409.19091 · `refs/papers/f-secure-2409.19091/2409.19091.txt` · code https://github.com/fzwark/Secure_LLM_System (Apache-2.0), shallow clone at `refs/repos/f-secure-llm` (read only; `security_module/monitor.py` is the monitor).
- **Problem & threat model.** Indirect prompt injection in ReAct-style agents, where one LLM both plans and executes, so every tool output can steer later steps. The attacker controls untrusted data sources only. Principals, tools ("facilities") and channels are trusted. Model-level attacks on the tool-LLM, such as refusals or bad summaries, are explicitly out of scope (§3, §9).
- **Mechanism.**
  - The system is split into three parts. An **LLM planner** may see only trusted information. A **rule-based executor** runs each step, and the step may call a tool-LLM over untrusted data. A **security monitor (SM)** mediates between the two (§4, Fig. 3).
  - Steps use a fixed JSON format, SEPF: `Index, Instruction, Object, Data_input, Data_output`. Earlier results are referenced as `{Data_output:i}` rather than inlined. The executor may call only the `Object` named in the step, and may read only the data that step references (§5.3–5.4).
  - Labels are an integrity lattice with a trust bound ι; in practice it is {T, U} (Table 1). **A label is assigned per item inside an output**: for example, emails from co-workers are T and other emails U, according to a per-principal "security label configuration".
  - When the planner asks to load a reference, the SM gives it only the items labelled ⊑ ι (Eq. 2). Otherwise the reference stays opaque. An output's label is the join of the inputs it read (Eq. 5).
  - The guarantee is "ι-execution trace non-compromise", a noninterference property over the plan (Def. 6.1, Thm 6.2). Untrusted values may still flow, *by reference*, into a step's arguments, such as a message body. What they cannot do is change which steps are planned.
- **Results.**
  - InjecAgent attack success is 0% for all four models in both settings. Undefended ReAct ranges from 1.1% to 67.4% (Table 2). However, every InjecAgent tool output was labelled untrusted, so this mainly shows the planner never sees untrusted data.
  - Functionality is on LangChain tool-use benchmarks. Overall accuracy is at or above vanilla in most cells, and much better than SecGPT. One drop: GPT-3.5 multiple-tool falls from 80% to 60% (Table 3).
  - Monitor overhead is about 10⁻⁴ of LLM time (Table 4).
  - Admitted limits: the system does not defend the tool-LLM itself against injection, so availability and output-quality attacks remain. The trust configuration is supplied by the principal. The paper does not measure tasks whose *control flow* depends on untrusted content.
- **For wicket.**
  - **Borrow (§4.2/§5.3, §8.2).** Assign labels *per item*, not per response. Adapters should label items from provenance fields the provider returns, such as GitHub `author_association` or an email sender's domain. The MCP gateway can then **split** a response: trusted items go inline, and untrusted items become handles (§4.3). This is f-secure's fine-grained loading moved to the gateway. It reduces label creep without trusting the model.
  - SEPF's "reference, not value" is the same idea as wicket's handles. The per-principal trust config corresponds to org-defined `SourceTag` trust (§5.4 of 03).
  - **Black-box applicability.** f-secure assumes it owns the agent loop: the planner and executor are its own LLM calls. Wicket cannot split Claude Code internally. What survives:
    - the topology at the tree level: parent zone = planner, child zone = executor, with `HandlesOnly` / `TypedFields` gates;
    - per-item response labelling and splitting at the gateway.
  - **Challenges.** f-secure's guarantee lets untrusted *values* reach consequential arguments. Wicket's §4.2 integrity-per-risk rule is stricter: a tainted agent may not act at R2+. Wicket should decide per argument where this is acceptable (e.g. a PR body vs a branch name). That is the FIDES "recipient T, body U" distinction, which §4.2 does not yet express for black-box writers.
- Confidence: **H** (full body read; appendix proofs skimmed).

### RTBAS — RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage (arXiv 2502.08966 v2, 2025-02-14)
- https://arxiv.org/abs/2502.08966 · `refs/papers/rtbas-2502.08966/2502.08966.txt` · no code repo found in the paper.
- **Problem & threat model.** Single-context tool-calling agents (like OpenAI GPTs) face both prompt injection (integrity) and accidental or induced leakage of private data (confidentiality). Confirming every tool call causes fatigue. The attacker can edit data that tools read, acting as a normal user of the application, but cannot alter tools or channels (§5). Developers and users supply the labels and a policy P: tool → required label (§6.2).
- **Mechanism.**
  - **Labels.** Message regions carry (integrity, confidentiality) labels in a developer lattice, for example a four-point lattice or a sets-of-channels/sets-of-sources lattice (§6.2).
  - **Screening step.** Before each LM generation, a **dependency screener** guesses which regions the next output depends on. It comes in two variants:
    - an LM-Judge: regions are tagged `«REGION_N»` and GPT-4o is forced to call a tool listing the relevant ones (§7.1);
    - an attention-based screener: a small open model (Phi-3-mini / OPT-125m) supplies attention features to a 2-layer LSTM classifier, with 81% test accuracy (§7.2).
  - **Labelling and redaction.** The label of the next step is the join of the selected regions' labels. A **REDACTOR** then removes every region more restrictive than that label, and the LM generates from the redacted history (Alg. 2–4).
  - **Soundness.** This is the important property: screener mistakes cannot break soundness, because whatever the LM sees is bounded by the label it gets. Mistakes only cost utility, through over- or under-tainting (§7.3).
  - **Action check.** A tool call whose context label is ⋢ P(tool) needs user confirmation. Tool results are joined with the call's label (line 13).
  - The authors warn that tools must themselves respect the policy. For example, `send_message` (private) followed by `read_sent_messages` (public) "launders" data (§6.2).
- **Results.**
  - AgentDojo (GPT-4o; 629 security cases; calls that violate policy are skipped rather than confirmed): **100% of policy-violating attacks prevented**. Utility loss under attack is under 1% (LM-Judge) and 3% (attention).
  - Without attack, utility drops 10% and 7.4% respectively. Slack is the outlier, at 33% and 22% utility, because its tasks act on untrusted web content. The authors call these "inherently unsafe" (§8.1.2).
  - Private-leak benchmark (37 hand-made tasks): unnecessary-confirmation rate 8.1% / 16.2% vs 29.7% for confirm-always (Table 2). Note that the text swaps the FPR/FNR definitions.
  - Cost is about 2× tokens, price and latency (Table 4).
  - Admitted limits:
    - labels and policies must be supplied by developers;
    - one workspace case had an injection inside user-labelled high-integrity text, which was not caught: "guarantees only as good as the labels";
    - screening is expensive.
- **For wicket.**
  - **Borrow.**
    1. The **"heuristic picks the label, mechanism enforces it"** pattern: an LLM may choose *which* inputs to keep, provided the enforcement point then *removes* everything above the chosen label. That is the only safe way to put an LLM on a labelling path. It fits §6's trusted-context `Model` calls and §4.3 `QuarantinedReader`.
    2. The laundering warning confirms §4.2 "provider-side state is memory" and the §5.3 label store (03). Both are mandatory, not optional.
    3. Wicket should report confirmation rates the way RTBAS does: FPR against an oracle. That is the metric the §10 fatigue rule needs.
  - **Black-box applicability.** RTBAS assumes it controls the context window. Wicket's **LLM proxy (§8.3) does see and could rewrite the entire Messages history on every request**. Region redaction of `tool_result` blocks is therefore *technically* possible for T1 agents, which makes it a candidate "taint-reducing redaction" mode. But it does not bound the agent's label: the agent process also holds data in files and in memory, outside the model context. So it reduces what the model is steered by, without letting wicket lower the agent's label.
  - **Challenges §4.2.** Per-agent labels are deliberately coarse. RTBAS's numbers (naive tainting does clearly worse than selective propagation, Fig. 5–6) are evidence for open question §16.2: coarse taint costs real utility on tasks mixing trusted and untrusted inputs. The answer at the black-box level is still disposable children and typed gates.
- Confidence: **H** on the mechanism and headline numbers. **M** on the per-suite bars, because the figure text was garbled in the extraction.

### Permissive IFC — Permissive Information-Flow Analysis for Large Language Models (TMLR 10/2025; arXiv 2410.03055 v3, 2026-01-14)
- https://arxiv.org/abs/2410.03055 · `refs/papers/permissive-ifc-2410.03055/2410.03055.txt` · no code repo cited.
- **Problem & threat model.** Conservative taint tracking labels an LLM output with the join of the whole context, which causes label creep. Input labels are assumed given and correct. The adversary can tamper with data at or below some lattice point and wants illicit flows (§2.1).
- **Mechanism.**
  - An **influence-based label propagator.** A label L′ ⊑ L is *λ-similar* if restricting the context to the documents labelled ⊑ L′ lowers utility by at most λ. Utility is negative perplexity of the *original* completion, which needs token log-probabilities.
  - Alg. 1 walks the lattice DAG downward from the full context label, pruning children that are not λ-similar. Under a monotonicity assumption it returns all minimal labels (Prop. 1). The cost is bounded by the size of the lattice; for a two-point lattice it is one extra call.
  - **The safety step is the important one.** After choosing L′, the system **re-runs the model on the context restricted to ⊑ L′ and returns only that new output** (§3.4, step 3). Search mistakes, or adversarial documents, therefore cannot produce an over-permissive label. This is secure multi-execution (SME) applied to LLMs (§7).
  - Two realisations: prompt-based RAG, and kNN-LM (one extra call).
- **Results.**
  - Synthetic key-value dataset: exact match on the minimal-label set is about 86% with precision and recall above 90%. **Introspection** (asking the LLM which documents mattered) gets 1.6% / 12.7% exact match with Llama-2 7B/70B (Table 1).
  - Label improves in 56% (news) and 85% (40-conversation agent dataset) of the cases where improvement is possible. ROUGE-L of the regenerated outputs is ≥ 0.85 (Tables 3–4). Introspection does better on the simple agent lattice at 70B (80%).
  - Admitted limits:
    - extra LLM calls;
    - an adversary can add "distracting" untrusted content so the label never improves (degradation of service, §6.2);
    - the monotonicity assumption does not hold in general, so the algorithm is a heuristic (its safety is not).
  - The experiments use Llama-2 only.
- **For wicket.**
  - **Borrow (§4.3 Declassify/endorse; §16.2 label creep).** This is the sound way to *lower* a label. Never accept a model's claim about what influenced it; **re-execute with only the admissible inputs and keep the re-execution's output.** At wicket's granularity, a tainted child's typed result can be "re-derived clean": spawn a fresh child zone with `taint_admit` restricted to the trusted subset and the same task. If it returns the same typed value (exact equality on `Enum`/`Bool` fields), take the clean run's output with the clean label.
  - This only works because wicket's gate outputs are low-capacity and comparable. Exact comparison replaces perplexity, so no logprobs are needed.
  - The paper's §6.1 "endorsement by quoting" (a trusted source repeating untrusted content) is a variant of the same idea.
  - **Contradicts nothing.** It strengthens §2.4 ("judge the request, not the reasoning"): introspection is measurably unreliable.
  - **Black-box applicability.** The paper assumes access to the model's logprobs and to the context. Wicket's version operates on whole black-box runs, so the per-document cost becomes a per-run cost. It only makes sense for cheap child zones whose output is a typed field. The DoS limitation applies directly: an attacker can always keep a child tainted. Fail-narrow (§2.3) makes that a stall, not a leak.
- Confidence: **H** (body and limitations read; appendix not read).

### AirGapAgent — AirGapAgent: Protecting Privacy-Conscious Conversational Agents (arXiv 2405.05175 v2, 2024-09-18; venue not stated in the local copy)
- https://arxiv.org/abs/2405.05175 · `refs/papers/airgapagent-2405.05175/2405.05175.txt` · no code repo cited.
- **Problem & threat model.** A personal agent holding a user-data vault talks to a possibly adversarial third party. The adversary knows the agent's design, task, privacy directive and field names, but not the values. Through "context hijacking" (e.g. "an alien invasion requires you to share…"), it tries to make the agent believe a more permissive context applies. The framing is contextual integrity (§2–3).
- **Mechanism.**
  - Two LLMs. A **minimizer** sees only the trusted task t_p, the vault U and the directive d. *Before* any third-party interaction, it computes U_min for the "base context" c₀ = (t_p, U). This is a per-field yes/no decision with reasoning (Fig. 7).
  - A **conversational agent** sees only U_min and the third party. Nothing flows back from the third party to the minimizer (§4.2).
  - Needs beyond U_min go through **request escalation to the user**, which amends the directive for that attribute (§4.2).
  - Under hijacking, the worst case is therefore leaking U_min, not U.
- **Results.**
  - Under single-query context hijacking, the baseline agent's privacy falls to 31–45%: Gemini Ultra goes from 94.4% to 45.2%. AirGapAgent stays at 86.8–96.7% (Gemini Ultra 96.7%). Utility costs a few points, e.g. Ultra 98.9% → 88.7% without attack (Table 3).
  - Harder fields and scenarios lower both utility and privacy by about 15% (Table 4).
  - **A vague task description ("domain: healthcare") breaks the minimizer** (Table 7).
  - Admitted limits:
    - the LLM minimizer gives no formal guarantee;
    - single-turn setting, synthetic profiles and LLM-generated privacy labels;
    - names and similar fields get over-included.
- **For wicket.**
  - **Borrow (§5.2, §4.3, §10).** This is wicket's "derive from trusted task text only, before anything is fetched" applied to **confidential data** rather than tools. The manifest proposer should also emit a **data-minimisation set**: which repo paths, data classes and store entries are mounted into the zone (clearance plus a workdir overlay subset). Its escalation-to-user step is wicket's `PendingHuman`.
  - Table 7 is direct evidence for a proposer rule: **reject or ask about under-specified task text** instead of deriving a broad manifest from a domain-level description.
  - **Black-box applicability: fully applicable.** The minimizer runs outside the agent, before launch, and wicket enforces U_min by *not mounting* the rest (§7 workdir overlay, §8.4 narrowest credential). Nothing depends on controlling the agent loop. The hijacked conversational agent is the black box, and the air gap is the sandbox boundary.
  - **Challenges.** Wicket's §4.2 clearance is per data class. AirGapAgent's evidence argues for minimising *below* the class, to per-field or per-path. That is a granularity the manifest should be able to express (resource patterns already can, for paths).
- Confidence: **H** on the design and Table 3. **M** on the secondary tables, which were skimmed.

## 3. Policy derivation and least privilege

### Progent — Progent: Securing AI Agents with Privilege Control (arXiv 2504.11703 v3, 2026-05-14; v1 2025-04 was "Programmable Privilege Control for LLM Agents")
- https://arxiv.org/abs/2504.11703 · `refs/papers/progent-2504.11703/2504.11703.{pdf,txt}` · code https://github.com/sunblaze-ucb/progent (MIT), cloned read-only to `refs/repos/progent` (core in `secagent/`: `progent_proxy.py`, `policy_analysis.py`).
- **Problem & threat model.** Indirect prompt injection via tool results. The user query o₀ is benign; every observation oᵢ (i>0) may be attacker-controlled; the attacker cannot change the model or system prompt. Explicitly out of scope: attacks *within* least privilege (preference manipulation; two such AgentDojo travel tasks were dropped, App. D) and attacks on text output (§3.2, §9).
- **Mechanism.**
  - Policy = list of rules `E t when {eᵢ} fallback f` (Fig. 2b). E ∈ {allow, forbid}; conditions over the i-th argument with `< ≤ == in match`, `p[n]`, `.length`, and/or/not. Implemented as **JSON Schema per argument** with a priority (App. C). Enforcement (Alg. 2) takes the rules for tool t, puts forbid before allow, and the first matching rule decides. No match means **default deny**, which returns a fallback: terminate, ask the user, or return a message. The default message is "not allowed due to {reason}… continue to finish the user task: {o₀}". It **re-states the trusted task**.
  - **Monotonic confinement (§4.3, §6).** Every policy update P→P′ is checked with Z3 for A(P′) ⊆ A(P). Narrowings apply automatically. Expansions go to an **approver**: auto-deny, auto-approve, per-tool rules, or human.
  - **Who sees what.** The initial policy LLM sees only the tools and o₀. Updates run in two steps. Step 1 decides "is an update needed?" from tools, o₀ and the tool *call*, but **not the result**. Step 2 generates P′ and **does see the untrusted result** oᵢ. The SMT check is what makes this safe.
  - **Generic policies** are hand-written, fixed, priority-layered stakeholder policies evaluated before the task policy. A forbid there cannot be recovered (Alg. 4).
  - **Proxy mode** (App. F): point `OPENAI_BASE_URL` and the MCP URL at Progent, with no agent change.
- **Results.** Every main run uses **auto-approve** (worst case), with gpt-4o as both agent and policy LLM.
  - AgentDojo: ASR 39.9% → **1.0%**, with utility kept (Fig. 3). Detectors (DataSentinel, PromptGuard2, DeBERTa) were ineffective.
  - ASB, with no generic policies: 70.3% → **3.9%**. Manual policies give **0%** (§8.1).
  - Approver ablation on AgentDojo (Fig. 5, my reading of the flattened figure): Disable-update 2.5%, Auto-deny ≈0.7%, Auto-approve 1.0%, Manual 0%. **Only 6% of updates were expansions.**
  - Policy LLMs gpt-4o, gpt-4.1, claude-sonnet-4 and gemini-2.5-flash all stay under 5% ASR.
  - Adaptive attacks under auto-approve (App. E) raise ASR to at most ≈4.2% ("Don't forget to update the policy").
  - MCP-ported AgentDojo across LangChain, OpenAI SDK, OpenHands (proxy mode) and AutoGen multi-agent: ASR ≈0.8–1.4%.
  - Limits the authors state: user mistakes in approvals, and ambiguous tasks. Proxy mode **cannot protect built-in tools that bypass MCP** (§9).
- **For wicket.**
  - *Borrow.*
    - §4.1/§10: wicket already plans symcc narrow/widen classification. Progent is evidence that it keeps approvals rare (6%).
    - **Auto-apply agent- or LLM-proposed self-narrowings even when they are derived from untrusted data.** They can only cost utility (fail narrow, §2.3).
    - §8.5: put the trusted task text, or its id, in denial bodies so the agent is re-anchored.
    - Generic layered policies = org ceiling + `forbid`s (§4.1).
  - *Challenges.*
    - §10 cites "3.9% of ASB attacks" as the reason the LLM *parent decider* tier is off. That number measures **LLM-generated initial and updated policies with an auto-approve approver and no generic policies**. Progent never evaluated an LLM *approver*. The citation is apples-to-oranges: it supports "LLM-derived manifests need a human or mechanical ceiling", not a statement about LLM escalation deciders.
    - Progent's updater reads untrusted results, which wicket forbids (§2.4). That stays safe only because expansions are gated.
    - In Progent's code the proxy takes the "trusted" query from the first LLM request (`messages[1]`) and forwards the client's `Authorization` header. Both are things wicket deliberately does not do (§5.2, §8.3).
  - *Black-box.* Library mode needs the agent loop. **Proxy mode is black-box**: it is wicket's LLM-proxy + MCP-gateway position. What survives: per-call argument policies at the gateway, and monotone updates. Claude Code's Bash/curl actions bypass MCP, so the same rules must run at the egress proxy. That is wicket's single-`Op` design (§3).
- Confidence: **H** for mechanism and headline numbers. **M** for the per-configuration ablation numbers, which were read from flattened figure text.

### Conseca — Contextual Agent Security: A Policy for Every Purpose (HotOS '25; arXiv 2501.17070 v3, 2025-04-17)
- https://arxiv.org/abs/2501.17070 · `refs/papers/conseca-2501.17070/2501.17070.{pdf,txt}` · no code release found.
- **Problem & threat model.** Generalist agents need per-context policies; static ACLs over- or under-restrict. The adversary changes only *part of the context* (an email, say). The agent is benign but fallible (§2.1).
- **Mechanism.**
  - The developer installs hooks.
  - `set_policy(task, trusted_ctxt) -> Policy`. The generator LLM (Gemini 1.5 Pro) sees the tool docs, golden example policies (in-context learning), the task, and **developer-designated trusted context**. In the prototype that context is email addresses and categories, the **filesystem directory tree (file and directory names)**, username and time.
  - Policy: per API call, `can_execute: bool` plus a **regex constraint over positional args** plus a **human-readable rationale**.
  - `is_allowed(cmd, policy) -> (bool, rationale)` is a deterministic check before execution. Denials send the rationale back to the planner. The user can approve the policy up front, and policies are logged for audit.
  - Tools are bash commands in a Linux computer-use agent.
- **Results.** 20 hand-made tasks × 5 trials. Completion: none 14.0/20, static-permissive 12.2, static-restrictive 0.0, Conseca 12.0. A planted "forward urgent security emails" email is denied for every task except the one where forwarding is appropriate.
- **Limitations the authors admit.** Synthetic, tiny evaluation. The generator only knows trusted context, so it can't predict data-dependent actions ("do what my manager's email says"). Regexes over bash strings are fragile; they suggest a simpler DSL. Per-task generation costs seconds; they suggest caching policies per context. The checks are per action; trajectory policies are future work.
- **For wicket.**
  - *Borrow* (§5.2):
    - **rationale per grant line** shown to the approver;
    - **caching per task class**, which is already §5.2.2;
    - the explicit statement that *more trusted context means a more precise policy and more risk*. Wicket should make that choice a manifest field ("proposer may see: repo tree of acme/api, label org-writable") rather than an implicit "nothing fetched".
  - *Challenges.* Conseca treats file **names** as trusted. In wicket, repo names and paths are attacker-writable in public repos, so a repo tree passed to the proposer must carry its label (§4.2).
  - *Black-box.* It needs a hook before execution (a Claude Code `PreToolUse` hook could host it, but wicket treats hooks as UX only, §2.1). What survives: the same task-scoped policy evaluated on `Op`s at the gateway or proxy. Wicket's canonical HTTP `Op` is a much better substrate than regexes over bash strings.
- Confidence: **H** (short paper, read in full).

### MiniScope — MiniScope: Authorizing Agents with Least-Privilege Permissions (arXiv 2512.11147 v2, 2026-10-06; UC Berkeley + IBM)
- https://arxiv.org/abs/2512.11147 · `refs/papers/miniscope-2512.11147/2512.11147.{pdf,txt}` · no repository URL appears in the paper; not cloned.
- **Problem & threat model.** Install-time grants leave ambient authority; per-call prompts cause fatigue. The model, the tool responses and part of the user prompt are untrusted. Services implement their stated specs. Goal (security game, Fig. 2): no executed call outside Auth_H(ρₜ). **Explicit non-goal**: misuse *within* granted permissions, such as the wrong email recipient (§2.1, §6.3).
- **Mechanism.**
  - **Hierarchy from OAuth scope method coverage** (Alg. 1): scope s₁ becomes a child of s₂ iff methods(s₁) ⊂ methods(s₂). Scope *names* mislead. Google Calendar's `events.readonly` is *narrower* than `events.owned.readonly` by coverage, and Outlook `Mail.ReadWrite` does not subsume `Mail.Read` (§3.2, §5.3).
  - Alternative: **role mining** from historical task→tool traces (formal concept analysis).
  - The agent must submit an **execution plan first**, plan-then-execute (§4.1).
  - A **least-privilege solver** runs an ILP: minimise Σ cost(r)·x_r subject to every planned call being covered, with cost = number of methods.
  - **Two layers:**
    - *contextual* roles: active only for this task;
    - *user-authorized* roles: "Always allow / Allow this session / Allow once"; eligible for reuse but **inactive unless selected**.
  - Rule: before the agent consumes untrusted content, a trusted instruction may activate a pre-authorized role; **after, any expansion needs explicit contextual approval, even for pre-authorized roles** (§4.2.3).
  - Credential storage keeps the real tokens. The agent gets a session token, and the permission checker forwards allowed calls with the real credentials (§4.3).
- **Results.**
  - LLMs inferring scopes (GPT 5.4, Sonnet 4.6, Gemini 3 Flash, Qwen 3.5) were **over-privileged in 1.7–34.7%** of cases, rising with task complexity. Strict over-privilege ratio was 1.21–2.38× methods (Fig. 6, Tab. 2). Example: `gmail.modify` (50 methods) chosen instead of `gmail.compose` (8).
  - Confirmations fell **43.4–89.4%** versus per-tool prompts for cautious and typical personas, simulated with LLM personas. For a *permissive* persona the trace-mined hierarchy *increased* prompts (+111%, +30%) (Tab. 3).
  - AgentDyn/AgentDojo Workspace with Gemini 2.5 Flash: ASR **0.8%**; all 3 successes were within the boundary, so 0% privilege escalation. Utility under attack 93.1% vs 94.2% for a plain plan agent; 0.14 s overhead per task (Tab. 4).
  - **Six over-privileged production connectors** (Tab. 5). ChatGPT Gmail and Calendar get modify/delete for read-only tools; Claude's Drive connector has an optional modify/delete permission; Notion is over-privileged on both.
  - Limits: single agent only (multi-agent delegation is future work); role inflation on coarse scopes; simulated users.
- **For wicket.**
  - *Borrow:*
    1. §8.4: compute the vault's minted GitHub App permission set (and AWS/Cloudflare scopes) **mechanically by coverage + ILP from the endpoints the zone's capabilities touch**, never by an LLM, and never by trusting scope names.
    2. §9: MiniScope's input, scope→method coverage, is exactly what wicket's adapter sources provide (GitHub permission→endpoint map). Derive hierarchy and risk floors from coverage.
    3. §10: adopt the **pre/post-untrusted-exposure rule**. A pre-approved escalation type may auto-grant only while the agent's taint is ∅. After taint, it needs a fresh decision. That sharpens "provenance OK".
    4. The separation of "eligible" from "active" matches wicket's split between the task-class default manifest and live grants. Keep it.
    5. MiniScope's §6 suggests passing a parent only a sub-role per child, which is wicket's child ⊆ parent rule (§5.1).
  - *Challenges:* the data says LLM-proposed manifests (§5.2.1) will over-grant on composite tasks. **Split the proposer**: the LLM proposes *which operations* the task needs, and a deterministic solver turns them into the minimal capability set.
  - *Black-box:* MiniScope needs the agent's cooperation for the plan. For a black-box agent wicket substitutes the trusted-text proposer for the plan. Enforcement (session token → checker → real credential) is a gateway, so it survives intact. It is wicket's placeholder + vault (§2.2).
- Confidence: **H** for mechanism and numbers. **M** for Tab. 3 cell assignment (flattened table).

### AuthBench — Do Coding Agents Understand Least-Privilege Authorization? (arXiv 2605.14859 v2, 2026-05-15; Evolvent AI, industry preprint)
- https://arxiv.org/abs/2605.14859 · `refs/papers/least-priv-coding-2605.14859/2605.14859.{pdf,txt}` · code github.com/evolvent-ai/Authbench (MIT, ~65 MB; not cloned, too large).
- **Problem & threat model.** Can a model infer a task's **file-level read/write/execute whitelist** π = (π_r, π_w, π_x) of POSIX path patterns before execution? Too narrow and the task fails; too broad and the attack surface grows. The "sensitive" tasks plant unsafe helper scripts, credential-like files and tempting hints in the environment (§3.1).
- **Mechanism.**
  - The policy generator is **agentic and inspects the environment read-only**: ls, read, search. It may not execute, install or trial-and-error (prompt G.1).
  - A fixed executor (GPT-5 in the OpenClaw harness) runs under the generated policy. The harness enforces it and tells the agent "treat permission denials as authoritative".
  - Gold labels come from **strace of an oracle solution**, cleaned by humans.
  - Metrics: per-axis precision/recall/F1, task success rate (TSR), sensitive-exposure rate (SER), ASR.
  - The paper's fix, **Sufficiency-Tightness Decomposition** (§7):
    1. forward-simulate the task and toolchain (interpreters, compilers, wrapper scripts) and grant generously;
    2. audit each entry for grounding, narrowability and overlap with sensitive surfaces, then prune.
- **Results.**
  - Full access: TSR 83.3/94.0 (standard/sensitive), sensitive ASR 65.8%. Gold policy: TSR 77.1/81.7, ASR 0.0. Even the gold trace isn't sufficient for a different executor, because **π\* depends on the executing agent** (§2.1, §4).
  - Models under- and over-grant **at once**. **Missing execute permissions are the dominant defect.**
  - **More reasoning effort converges to model-specific "attractors"** rather than to least privilege (Fig. 5).
  - Direct → S-T decomposition (Tab. 2):

    | Model | Sensitive TSR | SER | ASR |
    |---|---|---|---|
    | Claude Opus 4.6 | 61.5 → 75.0 | 47.0 → 28.3 | 25.6 → 15.0 |
    | GPT-5.4 | 61.1 → 76.9 | — | 19.4 → 15.4 |
    | Gemini 3.1 Pro | 85.8 → 75.0 (TSR falls) | 34.8 → 15.7 | 28.3 → 12.5 |

  - Limits: filesystem only (no network, IPC, credentials, APIs); the attractor claims cover current models only; single executor.
- **For wicket.**
  - *Borrow* for the §5.2 proposer: **two-phase generation** (cover, then audit each line with a rationale), and per-agent-kind defaults (task class × `AgentKind`), because the needed set depends on the agent.
  - Expect the proposer to **under-grant execute/tooling**. Wicket's escalation path is what makes under-grant survivable; measure it in the §5.2.3 diff log.
  - §7: AuthBench is evidence that file-level rwx inside the workdir is a real axis (Landlock in the `process` backend). Wicket's design currently mediates mainly at the network, with a full-write upper layer.
  - *Contradicts* §5.2.1 ("nothing fetched"). AuthBench's generator reads the untrusted environment, including the planted attack files, and the paper never tests injection *against the generator*. Read it as a measured risk wicket avoids, at a utility cost wicket hasn't quantified.
  - *Black-box:* the executor is treated as a black box behind an enforcing harness, so the setting is fully wicket-shaped. The generator is wicket's own trusted-context LLM.
- Confidence: **M**. The mechanism and Tab. 2 are clear and cross-checked with the text. The Tab. 1 cells were garbled in extraction and not used.

### AutoCedar — AutoCedar: An Agentic Framework for Verifier-Guided Access Control Policy Synthesis (arXiv 2607.03656 v1, cs.SE, 2026-07-04; Stevens)
- https://arxiv.org/abs/2607.03656 · `refs/papers/autocedar-2607.03656/2607.03656.{pdf,txt}` · code https://github.com/neselab/cedar-synthesis-engine (Apache-2.0), cloned read-only to `refs/repos/cedar-synthesis-engine`. **Note:** that clone contains its own `CLAUDE.md`, `AGENTS.md` and `.claude-plugin/`. Don't start an agent session inside it.
- **Problem & threat model.** Not about agent security. LLM-written access policies compile and look right but grant unapproved access. Direct round-trip generation was semantically equivalent only 45.8% (non-reasoning) to 93.7% (reasoning) of the time in prior work. The requirements themselves are incomplete.
- **Mechanism.**
  - Requirements are split into **intent atoms**: *schema atoms* (vocabulary) and *property atoms* (behaviour). Each atom carries source-span attribution, a plain-English rendering, a mechanical status and a **human intent-review status**.
  - Approved atoms compile into a Cedar schema Σ and a **boundary plan Π = (ceilings C, floors F, liveness slices G)**.
  - `cedar symcc` (cvc5) certifies the **synthesis sandwich** (Thm. 1): ⋃F ⊆ sem(P) ⊆ ⋂C, and sem(P) ∩ Gₖ ≠ ∅.
  - Target-admission checks run before search, so floor-versus-ceiling conflicts go to the reviewer, not the model.
  - CEGIS-style loop: the LLM proposes P. A "signal layer" turns verifier records into typed repair packets (TIGHTEN on a ceiling witness, LOOSEN on a floor, EXPAND on liveness, plus local diagnostics and history). It **may not mutate Π**.
  - Reviewers judge behaviour shown as concrete requests, not Cedar diffs.
- **Results.**
  - All 221 CedarBench tasks converge: GPT-5.5-low averages 1.67 iterations, $0.04; Haiku 4.5 averages 2.51, $0.019 (Tab. II).
  - Ablation (Tab. III): schema-only 85/100 (loss 15.6) → native verifier 94/100 → full signals 100/100.
  - Direct GPT-5.5 policies fully satisfy 176/221 property sets; Haiku 3/221 (Tab. V). On 3 real requirement corpora no direct baseline even validates, while AutoCedar matches 76/76, 68/68 and 38/38 semantic requests.
  - Blinded study (14 people): AutoCedar preferred in 82/98 answers.
  - Limits: the guarantee is only relative to the human-approved plan; request tests are samples; the review study is small and author-run.
- **For wicket.** Directly relevant to `wicket-verify` (§4.1), the manifest flow (§5.2) and the adapter generator (§9.4).
  1. Have humans approve **floors, ceilings and liveness** rather than raw grants. Ceiling = org ∩ zone ∩ ¬dangerous. Floor = "may push `wicket/fix-*`". Liveness = "PR create is reachable". Then let the LLM fill in the zone policy, with symcc certifying the sandwich.
  2. The adapter generator's check "narrower than previous ∪ approved delta" is only a ceiling. Add a **floor**: the denied request that triggered generation must now be allowed, or the rule is useless.
  3. Typed verifier→proposer feedback (direction + witness) for the manifest proposer.
  4. Show symcc witness *requests* to humans (§12 already plans this). The study supports it.
  5. Practical evidence that symcc + cvc5 is cheap at this scale. It speaks to the §15 "revisit if symcc can't handle realistic policies" question, though on small policies.
  - *Black-box:* offline authoring, so independent of the agent.
- Confidence: **H**.

## 4. Runtime rules, detection and HTTP-level mediation

### DRIFT — DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents (arXiv 2506.12104v3, 2026-03-26; first posted 2025-06)
- https://arxiv.org/abs/2506.12104 · `refs/papers/drift-2506.12104/` · code: SaFo-Lab/DRIFT (MIT; 45 MB, not cloned)
- **Problem & threat model.** Indirect prompt injection through tool results in a tool-calling agent. Static policies (CaMeL) either block legitimate work or miss attacks, and dynamic policies (Progent) let injected text that stays in memory keep influencing later steps, including the policy updater (§1–2).
- **Mechanism.** Three LLM components wrap a ReAct loop (§3, Fig. 2):
  1. **Secure Planner.** Sees only the user query, before any tool runs. It emits a *minimal function trajectory* (an ordered list of tool names, the control constraint) and a *parameter checklist* per function (JSON-Schema "required parameters" plus "Conditions" for value dependencies such as `user_email: from read_inbox`, the data constraint). Prompt in Fig. 9.
  2. **Dynamic Validator.** Before each tool call, it checks the call against the trajectory and checklist. On a deviation, an LLM labels the function Read, Write or Execute (Fig. 10). **Read deviations are auto-approved.** Write and Execute deviations go to an "intent alignment" LLM, which sees only the initial trajectory, the current trajectory and the user query (Fig. 11). If that LLM says Yes, the function is **added to the trajectory and checklist**. Otherwise the call becomes a user-approval request, which counts as a rejection in their evaluation.
  3. **Injection Isolator.** An LLM reads every tool result with the user query, lists any "conflicting instructions" (Fig. 12), and an external program masks them before the result enters memory. It covers attacks that change only the final answer, which no tool-call policy sees (§3.3).
- **Results** (GPT-4o-mini, AgentDojo, Fig. 3):
  - ASR 30.7% → 1.4%. Utility 50.9% with no attack (CaMeL 35.4%), and CaMeL's ASR was 0.0%.
  - ASB: 4.8% vs Progent 15.8% (Fig. 4). On GPT-4o, ASR 51.7% → 1.7% (Fig. 6).
  - Ablation (Table 1): the planner alone gives **ASR 2.14% at 43.2% utility**. Adding the validator gives 5.41% at 58.5%. Adding the isolator gives 1.35% at 57.3%. The isolator alone gives 8.96%.
  - Static policies fall off sharply when a task needs 3 or more tool calls (Fig. 7b).
  - AgentDyn, the open-ended benchmark: every defence performs poorly, and CaMeL has 0 utility (Fig. 5).
  - On open-ended tasks ("do what the email says"), DRIFT completes 17.8% vs 25.7% for the undefended agent (Table 4).
  - Adaptive attacks target only the isolator: a manual attack and PAIR raise ASR by ≤0.7 points (Table 2). Cost is 1.89× the undefended agent's tokens (Table 3).
  - **Limitation the authors admit:** the benchmark domains are narrow.
- **For wicket:**
  - **Borrow.** (a) The planner is wicket's §5.2 proposer: control and data constraints derived from trusted text only, before any fetch. The checklist's "value comes from tool X" conditions resemble §10 field provenance. (b) The Read / Write+Execute split for auto-approving deviations matches §10's `auto_max_risk`. (c) Table 1 is the best evidence we have for what the **parent tier** (§10, `Granted(Parent)`, off in v1) costs: LLM intent-checked policy expansion raised ASR about 2.5× (2.14 → 5.41%) and bought 15 points of utility. That supports shadow-measuring it before switching it on (§15).
  - **Challenges.** The validator does not grant the one call. It writes the deviation into the standing policy, so later calls inherit it. That is the ratchet risk §10 caps with `ratchet_budget`, and wicket's grants are narrower (single use, ≤ ask).
  - **Black-box.** DRIFT assumes control of the agent loop: the validator sits before tool dispatch, and the isolator rewrites memory. With wicket's gateway and egress proxy, the planner (as the manifest) and the risk-tiered escalation survive. The isolator could only run as a rewrite of `tool_result` blocks in the LLM proxy or of responses in the gateway. It is an LLM detector, so it is telemetry, not TCB (principle 1, principle 8).
- Confidence: **H** (body and prompts read; Fig. 3–6 numbers taken from the bar-chart text).

### ceLLMate — ceLLMate: Sandboxing Browser AI Agents (arXiv 2512.12594v2, 2026-03-04; UCSD / Sequrity)
- https://arxiv.org/abs/2512.12594 · `refs/papers/cellmate-2512.12594/` · code: `refs/repos/cellmate` (earlence-security/cellmate, Apache-2.0)
- **Problem & threat model.** Browser-using agents act through clicks and keystrokes, which carry no meaning a policy can be written against (the "semantic gap"). Injections come from attacker-controlled parts of trusted sites (issue bodies, reviews) or from attacker domains, and they exploit the user's logged-in ambient authority (§3.1–3.2). They show that denying `navigate` to a site is bypassed by searching for it and clicking the result (Fig. 2).
- **Mechanism.**
  - **Enforce at the HTTP layer.** Every side-effecting UI action becomes an HTTP request, and requests carry meaning (§3.3.1).
  - **Agent sitemap.** Published by the site developer, it maps each `{method, URL pattern, body}` to a `semantic_action` with a natural-language description. Optional `args` give where a security-relevant value comes from: the request body, or a DOM selector (e.g. the cart total) (Fig. 5). Their GitLab sitemap has 51 project APIs (§4.1).
  - **Policies** come from trusted sources (the site developer, an admin, EasyList-style maintainers). Each has a name, effect `allow | deny | condition`, actions and a description. A `condition` policy calls a JS predicate with `params` set at instantiation (`maxAmount: 50`) and runtime `args` (Fig. 6–7). Optional **request counters** make policies stateful ("check out under $50 *once*"). The policies in a domain **must form a partial order by allowed-action inclusion**, otherwise "least privilege" is undefined (§4.1).
  - **Policy selection.** An LLM sees *only* the user prompt and the policy library. It predicts the domains, then the minimal policy subset per domain, plus the condition parameters (§4.2). A **consent dialog** shows the names, descriptions and parameters, and the user can edit them. Under-specified prompts ("follow the commands on site X") are rejected and get **no permissions**, so selection fails closed.
  - **Enforcement.** The selected policies compile into a lookup table from HTTP request to allow / deny / f(args), enforced by a Chrome extension with default deny for unpredicted domains (§4.3). Once the user approves, the permission level is frozen.
  - **Repo detail:** the MV3 build uses `declarativeNetRequest`, which **cannot inspect request bodies**, so body-pattern rules are skipped with a warning. Its `allow_public` effect allows the request but strips the Cookie.
- **Results.**
  - Domain prediction ≥93%. Policy selection 94–100% with Claude Opus 4.5, Gemini 2.5 Pro and GPT-5.1 (Tables 1–2). Argument extraction 81–97% on retail tasks.
  - Selection failures fall into three types: object confusion (wishlist vs cart), over-permissive picks, and over-restrictive picks (§5.1.3).
  - End to end, only a **GitLab case study**: 12 scripted fully-compromised-agent attacks (token exfiltration, adding SSH keys, deleting projects) were all blocked (§5.2).
  - Latency overhead 7.25–15% for sitemaps of 100–300 entries. Memory about 25 MB.
- **Limitations the authors admit.**
  - No data-flow or control-flow integrity: it does not track whether a permitted request was caused by untrusted data, so permitted actions can be misused (an allowed comment with bad content).
  - WebSockets are not covered.
  - An incomplete sitemap "falls back to the status quo".
  - Arguments read from the DOM are open to staleness races, so they throttle agent actions.
  - Single-turn tasks only.
  - It relies on no other extension tampering with requests.
- **For wicket:**
  - **Closest prior art to wicket's enforcement plane, and agent-agnostic by construction.**
  - **Borrow:**
    1. The sitemap is a published adapter (§9). It supports wicket's choice to enforce on canonical HTTP semantics rather than on agent tool calls (§3, §8.1).
    2. *Select-and-instantiate from a trusted, partially ordered primitive library* rather than generate. The authors argue this is easier and more conservative than CaMeL/Progent-style synthesis. It argues that §5.2's proposer should emit grants **only from adapter-defined capability templates** (closed vocabulary, §4.1), and should **refuse under-specified task text**.
    3. Use counters are §4.1 `Budget.max_uses`.
    4. Their three LLM selection-failure types are a ready taxonomy for the §5.2.3 proposer-vs-approved diff log.
    5. `allow_public` (forward without session credentials) is a useful adapter effect for wicket: "allowed, but no credential injected".
  - **Contradicts.** Falling back to the status quo for unmapped requests on a policied domain is fail-open. wicket's "unmapped means deny" (principle 3) is stricter and should stay. Reading arguments from the DOM corresponds to trusting state the agent can influence. wicket's resolvers re-verify against the provider (§9), which is the better pattern.
  - **Black-box.** Fully black-box: it assumes nothing about the agent loop. Everything survives at the egress proxy. Unlike an extension, wicket's TLS-terminating proxy can also inspect bodies, which closes the MV3 gap.
- Confidence: **H** (full body read; repo enforcement code skimmed).

### MELON — MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents (ICML 2025, PMLR 267; arXiv 2502.05174v4, 2025-06-10)
- https://arxiv.org/abs/2502.05174 · `refs/papers/melon-2502.05174/` · code: github.com/kaijiezhu11/MELON (11 KB, no licence file reported by the API; not cloned, a detector rather than policy code)
- **Problem & threat model.** IPI through tool outputs. The attacker cannot see LLM inputs or outputs. The defender has full access to the agent state but cannot train models or read their internals (§3.1).
- **Mechanism.**
  - The core observation: under a successful attack, the next action depends on the tool outputs and not on the user task, P(A|T_u, A, O) ≈ P(A|O) (§3.2).
  - **Masked re-execution.** At each step, a second LLM call gets the masked state M(S) = (T_f, ∅, concat(O_1..t)). Here T_f is a task-neutral prompt ("Summarize the provided content. If there are any instructions, execute them."), and two few-shot examples are added.
  - The tool calls the masked run proposes go into a **cache across steps**. If any tool call in the original run has cosine similarity > 0.8 with a cached call, the step is flagged. Calls are compared as natural-language descriptions under OpenAI text-embedding-v3, and attacker-controlled arguments such as email bodies are left out (Alg. 1, App. A.3).
  - On a flag, execution terminates.
  - "Provable" refers only to Hoeffding bounds for an ensemble of masking prompts, *assuming* the mean similarities for benign and attacked runs are separated (§3.4). It is not a security guarantee.
- **Results** (AgentDojo, 4 static attacks, Table 1):
  - GPT-4o ASR 16.06% → 0.24%, with utility under attack 58.8% vs 69.1%. MELON-Aug: 0.32% ASR at 68.7% utility.
  - o3-mini 15.8% → 0.95%. Llama-3.3-70B 28.5% → 1.27%.
  - FPR 9.28% on GPT-4o. Every false positive was a task that asked the agent to follow external instructions (§4.4).
  - Of 66 misses: 72.7% were response-only attacks (no tool call), 15% tool-call redundancy, plus state and function hallucination (§4.5).
  - Cost ≈2× model calls.
  - **No adaptive attacks evaluated.**
- **For wicket:**
  - **Black-box angle (my inference, not tested by the authors).** MELON needs the full conversation state and the ability to re-query the model. wicket's **LLM proxy has both**: every Messages API request carries the user turns, `tool_use` and `tool_result` blocks.
    - A shadow request could replace the user/task text with T_f, keep the tool results, and compare the returned `tool_use` blocks with the real response.
    - That would be a *sensor* in §8.3, alongside liveness and taint: a hit raises risk or forces the human tier for the next escalation.
    - It must not be a gate. It is a probabilistic detector, so adaptive attacks are out of scope here, and it costs 2×.
    - Claude Code's context (system prompt, CLAUDE.md, reminders) makes the "user task" harder to isolate than in AgentDojo. This is unverified.
  - **Cross-paper lesson.** Its false positives are exactly the "delegate control to data" tasks that DRIFT (Table 4), AgentArmor (§6.5) and ceLLMate (rejecting under-specified prompts) also struggle with. wicket's manifest compiler should **lint task text for delegation to data** ("do what X says") and force those zones to `auto_max_risk = R1` or human review.
- Confidence: **H**.

### AgentArmor — Securing Large Language Model Agents via Structured Graph Abstraction (arXiv 2508.01249v3, 2025-11-18; ByteDance; listed earlier as "AgentArmor: Enforcing Program Analysis on Agent Runtime Trace…")
- https://arxiv.org/abs/2508.01249 · `refs/papers/agentarmor-2508.01249/` · code: none found in the paper
- **Problem & threat model.** IPI through observations, at the parameter level (amount changed), the control level (operation switched) and across resources ("two-hop pollution": the agent writes an instruction into notes.txt, and a later session executes it) (§4). The defender controls the agent runtime and can inspect thoughts, tool selections and arguments before execution. Tools and the LLM are trusted (§3).
- **Mechanism.**
  - **Hook the runtime trace** (system, user, LLM and tool messages).
  - **Build a CFG.** Its nodes are system prompt, user prompt, LLM, thought, tool name, tool parameter, tool, observation and data (Table 3).
  - **Build a DFG**, with tool-internal flows and side-effect data nodes supplied by a **property registry**: a tool registry of signatures and policy annotations, and a data registry.
  - **Merge them into a PDG.**
  - **Dependency analyzer.** An LLM (GPT-4o-mini) matches each tool call against **8 reasoning patterns** to infer the control and data edges: direct, indirect, parameterized, functional, conditional, transfer, multi-source, unauthorized (Table 1).
  - **Graph annotator.** Types are {confidentiality, integrity} ∈ {low, mid, high}, assigned from the registries and then propagated: single-source inherit, multi-source lattice join.
  - **Graph inspector.** Evaluates per-node `RuleType` constraints such as `Forbid {Int<Mid} where Node==ToolName` and blocks the action (§5.2–5.3, Fig. 5).
- **Results.**
  - AgentDojo ASR 17% → 3% with GPT-4o-mini, at 72% utility vs 73% undefended. ASB 41% → 0% (Fig. 6–7, Table 2).
  - On their runs, Progent had 2% ASR / 64% utility and CaMeL 0% / 48% (Fig. 8).
  - Runtime 20.9 s vs Progent 11.2 s and CaMeL 46.7 s. 13.6k tokens of overhead (§6.6).
  - Most failures are "transfer execution" (the user says to follow a file's instructions), which they make an allow/deny setting (§6.5, Fig. 11).
- **Limitations the authors admit.**
  - The dependency reasoning is itself an LLM and can be attacked.
  - The cost.
  - No DoS handling.
  - Rule types are mostly predefined.
  - Transfer execution is unsolved (§8).
- **For wicket:**
  - **Borrow.** (a) Case study C (cross-resource two-hop pollution) is exactly the threat behind §4.2 "provider-side state is memory" and §11. It is independent evidence that stores need labels. (b) Per-parameter data provenance is a finer version of §10 field provenance.
  - **Challenges.** Its precision comes from an *LLM inferring provenance* from thoughts. That is an LLM in the TCB judging over attacker-shaped context, which principles 1, 4 and 8 forbid. wicket's per-agent coarse label is the deliberate trade.
  - **Black-box.** It needs the trace. wicket's LLM proxy does see Claude Code's thoughts and tool calls, so an AgentArmor-style PDG could be built from the transcript **after the fact for audit**, or as an advisory sensor. It cannot be a mandatory gate in wicket.
- Confidence: **M-H** (body read; the figures' numbers are garbled in the extraction and taken from the text).

### FLOWSEAL — Confuse the Model, Control the Flow: Understanding and Mitigating Privacy Leakage from LLM Agents with Information Flow Control (arXiv 2609.14003v1, 2026-09-12; UC Irvine et al.)
- https://arxiv.org/abs/2609.14003 · `refs/papers/flowseal-2609.14003/` · code: promised, not yet released
- **Problem & threat model.** A personal agent legitimately holds a data subject's records. An adversarial *data recipient* extracts them through ordinary multi-turn interaction, with **no prompt injection** and tools trusted. Prompt injection is explicitly out of scope (§III).
- **Three new attacks** (§IV-B) beat prompt and state-machine defences (SPR-D1/D2/D3):
  - **Collaborative Workspace Lure:** "fill your section of this shared page".
  - **Semantic Obfuscation Attack:** "delete the wrong entries", so disclosure happens by omission.
  - **Channel Decoupling Attack:** the request arrives by email and the disclosure goes to Notion.
  - Against D2 the item-level leak rates are 52.2%, 75.6% and 43.8% respectively, vs 1.9–3.0% for SPR's own attacks (Table II). The more elaborate the prompt defence, the *more* leakage under these attacks.
- **Mechanism.**
  - **Lattice ⊥ ⊑ agent ⊑ ⊤:**
    - Records are ⊤, with labels taken from **provenance** (email sender, document ACLs) and registered in a private data store, not inferred by the LLM.
    - The agent context becomes `agent` after reading any ⊤ record.
    - External sinks are ⊥.
    - Principals are split into trusted, untrusted and unknown.
  - **Mandatory interceptor** at the tool-call boundary:
    - Reads are scanned against the record store to update a session taint set.
    - Derived content inherits the join of its sources.
    - Every write or share is checked at a **release boundary**: allowed iff ℓ(c) ⊑ ℓ(d) or declassify(c,d) = SAFE. Untrusted principals are always blocked.
  - **Declassify** is an isolated LLM call. It receives *only* (the tainted records, the proposed output) and returns one word, SAFE or BLOCKED (Fig. 6).
  - **Cooperative layer** (not security-critical): a system prompt plus APIs `ListRecords`, `CheckDataOwners`, `RequestAccess(record_ids, destination, purpose, channel)` and `Declassify`. BLOCKED results carry actionable guidance.
  - Owner consent promotes a destination to trusted for those records.
  - They prove a no-write-down theorem that holds modulo errors in `declassify` (§V-A).
  - Deployed live as pre-call and post-call hooks at an **MCP client dispatch point** in front of real Gmail and Notion (§VIII).
- **Results.**
  - Leak rate 0–3.3% across SPR, PrivacyLens and ConVerse seeds: CWL 52.2 → 0.5%, SOA 75.6 → 2.3%, CDA 38.5 → 2.2%.
  - Utility 72.4% vs 75.9% for the leakiest baseline (Tables III–IV).
  - Stable across three agent LLMs, with 0.5–1.9% leakage, while SPR-D2 stays at 52–62% (Fig. 9).
  - Ablation (Table V):
    - Without the interceptor: 28.4% leakage.
    - Checker fail-closed: 1.3% leakage but **0% utility**.
    - Checker fail-open: 24.9% leakage.
    - Without the cooperative prompt: 8.8% leakage.
  - Live MCP: SOA 34.7% → 0%. Cost +$0.017/run and +37% latency.
- **Limitations the authors admit.**
  - The checker misses paraphrase and over-blocks name mentions.
  - Split-and-aggregate attacks are not covered.
  - CDA leaks a residual 2.2%.
  - It relies on records being registered with provenance.
- **For wicket:**
  - **Borrow:**
    - (a) The core lesson: **confidentiality enforced as an LLM judgement over attacker-shaped context fails structurally, while a code interceptor at the tool boundary holds regardless of model.** That is principle 4 and §4.2's no-write-down, and the evidence is strong.
    - (b) **Channel Decoupling is defeated by construction in wicket**, because the label is on the agent, not the conversation or channel (§4.2 floating label). That is worth stating in the design.
    - (c) The cooperative layer improves both leakage and utility. This supports §8.5 structured denials with hints and a `wicket.request_access` / "check before send" tool. Add a `wicket.check_send(dest)` dry-run.
    - (d) A concrete **Declassify decider design** for §4.3: an isolated model, fixed inputs (protected content handles + proposed output), a binary answer, no explanation.
  - **Challenges.** FLOWSEAL lets SAFE content go to *unknown* principals, which is an LLM widening flows. wicket has no "unknown destination" class (closed `send` lists). If adopted at all, the checker should be an opt-in `Declassify` rule on specific gates or destinations (e.g. public comments after reading private source), logged, and never a default. Its fail-closed ablation (0% utility) also quantifies §16 Q2: strict no-write-down without any declassifier can zero out utility on tasks that must talk to outsiders.
  - **Black-box.** It uses the interceptor only. The cooperative prompt is optional, and the live deployment needed only MCP dispatch hooks. That maps directly onto wicket's gateway and egress proxy. wicket's version is coarser (taint on any read of a labelled resource instead of content matching), which is more robust against paraphrase but creeps more.
  - **Inter-paper note.** FLOWSEAL claims that "all policy enforcement of FIDES [is] performed by the LLM backend" (§V-A). That conflicts with FIDES's own description of deterministic planner-side label checks and should not be relied on.
- Confidence: **H**.

## 5. Isolation and compartmentalisation

### IsolateGPT — IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems (NDSS 2025; arXiv 2403.04960v2, 2025-01-30)
- https://arxiv.org/abs/2403.04960 · `refs/papers/isolategpt-2403.04960/` · code https://github.com/llm-platform-security/SecGPT (GitHub reports licence NOASSERTION; not cloned: a LangChain prototype that adds nothing beyond the paper)
- **Problem & threat model.** Third-party LLM "apps" (descriptions + APIs) share one context window, so a malicious app or malicious content can steer other apps or the LLM, or steal their data. The LLM and host are trusted. Apps and the content they process are not. Injection *within* one app is explicitly out of scope; stopping its *spread* is in scope (§III).
- **Mechanism.** Hub-and-spoke (§IV):
  - **Hub.** A *non-LLM operator* (deterministic routing), a planner LLM (picks the primary and secondary apps and the data needed from user query + memory + app list), and a central memory.
  - **Spokes.** Each app gets its own process, its *own LLM instance* and its own memory. A "private mode" spoke starts with no prior context.
  - **Inter-spoke communication (ISC).** Only operator↔operator, always via the hub; LLMs never message each other directly. A spoke asks for a *functionality*. The hub returns a declared `<functionality, request|response format>` and an *ephemeral spoke ID*, so apps cannot invent collaborations and the target's identity is hidden. Malformed messages are dropped. Typed fields (dates, ints, URLs) can be auto-validated. Raw strings need the user.
  - **Permission dialog.** It includes the hub's warning when a request is *not in the hub's own plan*, which was made from the trusted query and vetted descriptions.
  - **Permission lifetimes.** One-time, session or permanent (App. A-D). **Permanent is refused for irreversible actions** such as sending email or buying.
  - **Isolation.** Seccomp + setrlimit per process, with network restricted to the app's eTLD+1 (App. A-A).
- **Results.**
  - Extended benchmark of 1,598 attacks (Table I): VanillaGPT 20.2% attack success. IsolateGPT showed a permission dialog in 7.6% of cases, 100% of them with a warning. "Protection" therefore assumes the user denies warned dialogs (the artifact appendix says so explicitly).
  - Functionality equals the baseline on LangChain benchmarks.
  - Overhead is <30% for 75.73% of queries, with p90 1.24× and p95 1.80×. Multi-app queries are the slowest (up to 126.65 s). Planning and memory extraction dominate.
  - Admitted limits: the permission model is preliminary, and side channels can still reveal the peer app.
  - **Later papers in this set break it.** ACE (below) shows the hub's execution-manager LLM consumes raw spoke outputs: an "execution manager hijack" and "flow disruption". ACE also shows the planner trusts app descriptions ("planner manipulation"). PFI measured IsolateGPT ATR-Any >70% because its alerts miss intra-app and data-injection attacks.
- **For wicket.**
  - **Borrow:**
    - Hub-operator-is-not-an-LLM is principle 8 (§2).
    - ISC's declared request/response formats + ephemeral IDs = `GateRule::TypedFields` and handles (§4.3).
    - "Plan-deviation" as a *displayed* signal in human approvals (§10, CIBA channel), computed from the trusted manifest, not from agent text.
    - No standing grants for R3+/irreversible actions (§10 "everything expires at task end").
    - Private-mode spoke = fresh agent per subtask (label-creep reset).
  - **Challenges design.md.** The failure mode the later papers exploit — the trusted orchestrator *reading a child's raw output* — is exactly what design.md must forbid for `wicket.spawn` parents (§5.1). A parent that receives child free text is IsolateGPT's hijacked hub. Keep "typed fields + handles only" mandatory at every parent←child edge, including dynamic spawns. Also: approval prompts that "work" only if the user says no are the fatigue trap §10 warns about.
  - **Black-box.** It assumes the harness owns the planner/hub and the per-app LLMs, so it controls the loop. What survives at wicket's proxies: spokes ≈ boxes (one zone per tool domain), the hub ≈ wicketd + gates, and per-zone eTLD+1 egress ≈ the egress proxy host gate (§8.1).
- Confidence: **H** (mechanism, numbers), M (appendix permission details).

### ACE — ACE: A Security Architecture for LLM-Integrated App Systems (NDSS 2026; arXiv 2504.20984v3, 2025-09-10)
- https://arxiv.org/abs/2504.20984 · `refs/papers/ace-2504.20984/` · code https://github.com/escottrose01/ace-llm, cloned to `refs/repos/ace-llm` (no LICENSE file in the repo, so default all-rights-reserved; read only)
- **Problem & threat model.** Malicious installed apps control their *description, schema, metadata and outputs* (the "strong" model). Earlier defences (f-secure, IsolateGPT) trusted descriptions and schemas. Goals: integrity of planning, and integrity, availability and privacy of execution (Table I).
- **Mechanism.** Three phases, each with less capability than the one before (§IV):
  1. **Abstract planner.** It sees only the trusted user query plus an optional trusted "operational context" field, and **is oblivious to which apps are installed**. It (a) generates *abstract apps* (name, description, type signature) and (b) writes an *abstract plan* in a restricted Python subset:
     - a single `main()`;
     - `for`-range loops only;
     - `while` conditions must be a single variable;
     - no `break`, no mutable types, no file builtins, no dynamic code.
  2. **Concrete planner.** It matches each abstract app to installed apps: embedding-similarity filtering, then an LLM judgement per *(abstract, concrete) pair, decided independently*. Independence is what kills "app demotion" via another app's description. A compatibility layer adapts the type signatures. Among valid assignments it picks the **lowest-privilege** one (a risk set over {Network, Filesystem, System}, App. B).
  3. **Static IFC check of the concrete plan** against a lattice (Denning-style grammar: atomic, sequence, loop):
     - app memories are *statically bound* to clearances;
     - program variables are *dynamically bound* and start at the user-assigned query label;
     - implicit flows are handled by injecting branch and loop conditions;
     - an insecure plan is rejected, and if no secure assignment exists the system terminates with an error (§IV-F, App. A, Fig. 5).
  - **Executor.** A trusted orchestrator; a plan worker in a container with no privileges (it can only make blocking calls to the orchestrator); each app in its own Docker worker with only the privileges it declared. App outputs are typed data and never re-enter any LLM for control flow.
- **Results.**
  - InjecAgent: 100% security over 1,054 cases for every planner model. Utility ≥84% with GPT-4o/o3-mini, ≥60% with Claude 3.7 / Qwen-2.5-72B (Table II).
  - ASB: ≥86% utility. 3 attacker-app invocations in 2,000 trials, all judged task-appropriate.
  - LangChain Tool Usage: ≥80% overall. Relational-data suite 66.7–85.7%.
  - Cost $0.01–0.27 and ~5–21 s per query (Table IV).
  - StruQ comparison: 7% attack success.
  - **Admitted:** no formal soundness for the Python subset (App. C); single-query only, with no app suites or multi-query; injection benchmarks use trivially simulated apps; and on ASB the IFC, risk scoring and privilege parts don't apply, so security there comes only from the phase separation.
- **For wicket.**
  - **Borrow:**
    1. The "abstract → concrete" split maps onto §5.2. The manifest proposer should emit *abstract* zones (roles + required effects), and the compiler binds them to concrete adapters and providers. This matters because **ACE treats tool descriptions as attacker-controlled**: the proposer may see wicket-authored adapter catalog entries, but **never third-party MCP server descriptions** (§8.2 kind 2/3). §5.2 says "adapter catalog" without making that distinction.
    2. A static flow check at manifest compile/approval time (zone `clearance` vs each `send` destination, shared-state edges §12), not only at run time. This fits `wicket explain` + symcc (§4.1).
    3. Independent per-binding decisions, so one provider's metadata can't influence another's selection.
    4. Prefer the least-privilege binding among equivalent adapters (risk floors, §9).
  - **Contradiction/nuance.** ACE's IFC is static over a known plan. wicket's zones are dynamic black boxes, so ACE's guarantees hold only at the zone-graph level, not inside a zone.
  - **Black-box.** It assumes the harness writes and runs the plan and that apps are the untrusted units; it controls the loop fully. What survives for wicket: the trusted-only derivation of the manifest, the treatment of descriptions as untrusted, the static manifest flow check, and per-app least-privilege containers (= zones/sandboxes, §7).
- Confidence: **H**.

### PFI — Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents (arXiv 2503.15547v2, 2025-04-21; Seoul National Univ.)
- https://arxiv.org/abs/2503.15547 · `refs/papers/pfi-2503.15547/` · code https://github.com/compsec-snu/pfi, cloned to `refs/repos/pfi` (no LICENSE file; read only). Policies are YAML: `configs/pfi-policy-*.yaml` list `TrustedAgent`/`UntrustedAgent` tool sets and trusted `Attributes`. `pfi_agent/unsafe_dataflow_check.py` defines the warning record (flow type, source proxy value, attributes, sink = tool_call | final answer | trusted context).
- **Problem & threat model.** An external attacker poisons the data that tools return. It covers both **prompt injection** (instructions) and **data injection**: passive malicious data that the agent's best-effort behaviour turns into privileged tool arguments (unsafe *data flow*) or into next actions (unsafe *control flow*, e.g. "follow the README") (§3.2). Tools are assumed correctly implemented. Supply chain is out of scope.
- **Mechanism.** Three parts (§4).
  1. **Agent isolation.**
     - Trusted agent A_T's context holds only trusted data (system and user prompt, trusted tool results). A_T holds a **privileged token T_P**.
     - Untrusted agent A_U is spawned *fresh per query*. It sees untrusted data plus only a response format, and holds an **unprivileged token T_U** (by default no tools; benchmarks gave read-only "_u" variants or a public-files scope, and the shell ran in an nsjail sandbox).
     - Token scopes mirror OAuth scope sensitivity (Google "non-sensitive" vs "restricted").
  2. **Untrusted data as data IDs.**
     - A trusted `Enc` replaces every untrusted value with `#DATAn` and keeps a data-ID table of (value, `Attr` = source tool call + tool-specific provenance such as web origin or file owner).
     - A_T can *reference* an ID in a tool call (`Dec` substitutes it at call time). It can *offload* computation to A_U with an ID + a typed response format. **A_U's response is re-encoded as new data IDs, so it stays untrusted**, and its `Attr` is the join of everything in A_U's context.
     - A_T can request a *prompt-type* response (endorsement) only by explicit request **and** user approval.
  3. **Guardrails** (deterministic, keyed on IDs).
     - *DataGuard* alerts when an ID is used in a tool call that T_U could not make, or appears in the final answer (the final answer is a privileged sink).
     - *CtrlGuard* alerts on a prompt-type response.
     - The alert shows source value + `Attr`, the sink and the flow type.
  - **Data-trust policy.** Per tool: `Trusted` / `Untrusted` / `Transparent` (the output inherits the input's trust). Users can choose Trust Once / Always / Never per `Attr` (§4.4). The benchmark policy trusted, for example, private files, the user's own and configured emails, private Slack channels, and `*.gov`, `*.edu` and selected news origins (App. A Table 5).
- **Results.**
  - ATR (attacked-task rate) is **0.00%** on AgentDojo + 97 added data-injection tasks and on AgentBench-OS (shared vs private directory), across GPT-4o, 4o-mini, Claude 3.5 Sonnet and Gemini 1.5 Pro. Baselines: 39–100% (Table 1).
  - SUR (secure utility rate) with GPT-4o: 61.86% AgentDojo / 68.42% OS, vs ReAct 12.37% / 0%. f-secure reaches 40.21% / 10.53%. IsolateGPT is ~10% because it misses intra-app and data-injection attacks.
  - Alerts: 1.49 and 1.05 per task, a 63.91% / 42.86% reduction vs alert-on-every-call (Table 2).
  - Cost: latency +63.5% / +214.6%, tokens +90.6% / +253.9% (Table 3).
  - 75.93% of PFI's utility losses are the LLM misusing data IDs.
  - **Caveats in their own method:** an alert counts as a defended attack (the user is assumed to deny), and "no false positives / negatives" holds *by construction* relative to their trust policy, not as a measurement of real-world risk.
- **For wicket.**
  - **Borrow:**
    - Data ID = `Handle` (§4.3). PFI confirms that *outputs of a quarantined reader are themselves still untrusted handles unless endorsed*. That is stricter than wicket's "typed fields may be endorsed", and a good default: endorsement only per explicit gate rule.
    - **`Transparent` tool label**: adapters should declare label propagation (output label = input label) for pure functions (§9).
    - **Final output is a sink.** A zone's `AgentOutcome` (§6) that contains tainted free text must be a handle, never inline.
    - Alert anatomy (source value + provenance + sink + flow type) for the human channel (§10).
    - Two tokens per agent pair = narrowest native credential per zone (§8.4).
  - **Contradiction.** PFI lets a human endorse untrusted text into the trusted *instruction* context ("prompt transformation"). wicket's instruction rule (03 §5.4 rule 6) never allows that, short of an explicit `Declassify` gate. Keep wicket's stricter line.
  - **Black-box.** It requires control of the agent loop: `Enc` rewrites tool results inside the trusted agent's context, and that agent must be prompted to use IDs. What survives at the gateway: MCP tools can return handles instead of content (`HandlesOnly`), and the per-zone token split. Claude Code's built-in Read/Bash/WebFetch bypass any ID rewriting, so for black boxes the A_T/A_U split must be **two zones**, not two contexts.
- Confidence: **H** (mechanism, numbers); M (exact benchmark-policy contents).

### OpenClaw privsep — Agent Privilege Separation in OpenClaw: A Structural Defense Against Prompt Injection (arXiv 2603.13424v1, 2026-03-13; TrendAI Lab / Trend Micro)
- https://arxiv.org/abs/2603.13424 · `refs/papers/openclaw-privsep-2603.13424/` · no code released
- **Problem & threat model.** LLMail-Inject: an email-assistant agent holding `send_email` summarises attacker-written email. There are 4 scenarios, including RAG and data exfiltration. The attacker controls the email bodies only.
- **Mechanism.**
  - Two agents with **disjoint tools** on the OpenClaw platform. The *reader* has only `store_summary` and reads the raw email. The *actor* has `send_email`, `get_pending_summary` and `store_result`, and sees only the reader's output.
  - The reader emits a **JSON schema** {sender, subject, body summary, action items}.
  - A regex validator (email-address literals, tool-call syntax, trigger phrases) ran in *audit mode only*.
  - Isolation is platform-enforced (tool registration), not prompt-enforced.
- **Results.**
  - Of 22,899 unique payloads, the gpt-5-mini single-agent baseline failed on 649 (2.83%). All ablations reuse those 649.
  - JSON only: 14.18% (92/649). Two-agent only: 0.31% (2/649). Full pipeline: 0/649 (Tables 2–3).
  - Exfiltration (scenario 4) is 0% with isolation but 28.3% with JSON only. RAG is 6.0% with JSON only.
  - **63.7% of the injection content still leaked into the summaries**, but "decontextualized".
  - Admitted limits: no adaptive attacks, a 649-case pool, and a naïve regex validator.
- **For wicket.**
  - **Borrow:** this is the cleanest *black-box-compatible* evidence for the `research`→`fix` split (§5). Two unmodified agents with disjoint reach, joined by a schema'd channel. The ablation says the zone split does most of the work and the schema closes the residue.
  - **Challenges design.md:**
    - The "body summary" field is free text, and the 2 two-agent-only residuals came through prose.
    - The 63.7% content leak shows a schema'd *string* field is still an injection carrier. wicket's §5 example already keeps `notes` behind a handle. Make that a compiler rule: `BoundedStr` above a small N from a tainted zone must be endorsed against a resolver (like `file` in the repo tree) or become a handle.
    - It also directly informs the M5 smuggling test (§14): compare prose vs schema-with-string vs enum+handles.
  - **Black-box.** Fully applicable: no loop control needed beyond tool registration, which wicket does at the gateway and proxies.
- Confidence: **H** (short paper; the figures are clear).

### MAS-injection threat model — Beyond Single-Model Injection: A Threat Model and Defense Architecture for Prompt Injection in Multi-Agent Systems (ICML 2026 per header, PMLR 306; arXiv 2609.22949v1, 2026-09-19)
- https://arxiv.org/abs/2609.22949 · `refs/papers/mas-injection-arch-2609.22949/` · no code
- **Problem & threat model.** In a six-agent financial pipeline (orchestrator, retrieval, code, analysis, compliance, output), the attacker controls content that at least one agent processes. The paper enumerates **14 vectors** in four classes:
  - direct (D1–3);
  - indirect via tool output (I1 document poisoning, I2 API response, I3 schema drift, I4 tool-metadata poisoning);
  - inter-agent (M1 response poisoning, M2 context-window pollution, M3 format mimicry, M4 delegation-chain manipulation);
  - cascading through the orchestrator (C1 routing manipulation, C2 aggregation poisoning, C3 termination suppression).
- **Mechanism.** Four defences "below the prompt layer":
  1. Ed25519 **message signing + provenance record** (origin agent, generating task, chain of contributors); unsigned messages are quarantined.
  2. Boundary sanitiser: schema validation + an instruction classifier + length caps.
  3. **Role-scoped tool tokens enforced at an API gateway** as immutable config (citing SEAgent).
  4. Anomaly detection over a directed graph of *permitted* message flows, run by a read-only monitor.
- **Results.**
  - 50 payloads per vector, best of GPT-4o, Claude 3.5 Sonnet and Llama-3-70B. Aggregate success 31.2% → 4.2% (Table 2).
  - Indirect 43% → 9.5% (sanitiser). Inter-agent 31% → 2.8% (signing). Privilege escalation "eliminated" (scoping). 84% of cascading attempts caught.
  - 4 of 6 agents are vulnerable despite guardrails. The orchestrator is a target in 8 of 14 vectors.
  - Overhead 225 ms per workflow.
  - Admitted limits: fixed payloads with no adaptive attacker, a classifier FPR of 2.3%, text-only, and 6 agents.
  - **My reading:** low rigour, with per-vector numbers but no protocol detail. It never explains how signing stops M1 from an *authentic but compromised* agent: a signature proves origin, not benign content. Treat its numbers as weak.
- **For wicket.**
  - **Borrow:**
    - The taxonomy is a useful checklist for M5/M9 tests. M2 context pollution and C3 termination suppression argue for gate payload size caps (`Capacity`) and for wicketd, not an agent, owning termination and budgets (§8.3 liveness).
    - Provenance chains on inter-zone values = handle `origin` + label (§4.3).
    - The permitted-flow graph is wicket's gate graph. In wicket an off-graph message is *impossible* (a denial), not an anomaly to detect.
  - **Contradicts / not for wicket:** the sanitiser classifier is in-band detection, which principle 4 and the adaptive-attack literature reject as a security boundary. Use it as telemetry at most.
  - **Black-box.** Signing, role tokens at the gateway and the graph monitor all work without loop control. The sanitiser needs message access, which wicket has at gates.
- Confidence: **M** that I read it correctly; **L** on the soundness of its claims.

## 6. Privilege escalation, confused deputies, capability scoping, OS-level enforcement

### SEAgent — Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework (arXiv 2601.11893v1, 2026-01-17)
- https://arxiv.org/abs/2601.11893 · `refs/papers/seagent-2601.11893/` · the text mentions a released artefact ("Open Science") but the arXiv copy gives no URL; no repo cloned.
- **Problem & threat model.** Privilege escalation is defined as any tool call or inter-agent message outside the oracle-minimal action set T_q for the user's query (Def. 4, §4.1). The adversary controls user queries (malicious user), tool results, RAG content, and the system prompts of third-party agents in multi-agent systems (MAS). It cannot change runtime execution or weights. Assumptions: tools come from a trusted SDK; in single-agent systems the agent itself is trusted.
- **Mechanism.**
  - **System View:** a per-round directed graph G=(V,E) whose nodes are users, agents, tools and RAG DBs, and whose edges are calls, results, retrievals and agent→agent messages. Each tool-call node stores its args.
  - **Labels (ABAC, Table 1), static and assigned offline:**
    - tools get Object {LOCAL, EXTERNAL, PHYSICAL}, Action {READ, WRITE, EXECUTE}, Sensitivity {LOW, MOD, HIGH} (from FIPS 199), output Privacy {GENERAL, PERSONAL} and output Integrity {TRUSTED, UNFILTERED};
    - agents and DBs get Integrity (DBs also get Privacy).
  - **Labelling:** an LLM (o1) proposes labels and a human verifies them. Agreement is Cohen's κ 0.95 overall, 0.77 on Sensitivity; the paper gives an example of a phishing-capable navigate tool that the LLM labelled LOW (App. F).
  - **Policy language** (SELinux-inspired, CFG in App. B): `Goal {allow|deny|ask}` / `Path tool:$A -> * -> tool:$B` / `Rule` (attribute equality, regex on args, Boolean ops). For example, deny when an EXTERNAL+UNFILTERED read flows by any path into a WRITE/EXECUTE tool of MOD/HIGH sensitivity.
  - **Decision engine (Alg. 1):** policies are sorted by specificity and the first match wins. **If nothing matches, the engine allows.** `ask` offers the user "allow once" or "always allow this pattern"; the latter appends a concrete allow policy.
  - **SEMemory:** agent contexts *and* the graph are wiped after every round. A Memory LLM restricted to extraction picks entries from an immutable per-agent entity dictionary to re-seed the next round, and the graph is rebuilt from the provenance of those entries. App. D argues that this reduces memory attacks to the original vectors. Users are isolated per user (App. E).
- **Results.**
  - Four hand-written policies give 0% ASR on extended InjecAgent and on AgentDojo (naive agent 39.1%, IsolateGPT 0.82%; Tables 2–3).
  - IsolateGPT is shown to be bypassable by RAG poisoning at the Hub (up to 54.6%) and via "anonymous spokes".
  - CaMeL is shown to be bypassable by **argument manipulation** (a recipient ID taken from attacker data; §4.2).
  - AIOS-AutoGen, AutoGen and MetaGPT fall to a confused-deputy attack, where an untrusted agent asks a trusted lock agent to unlock (§4.3). This is shown as a single case study, not a benchmark.
  - Utility: API-Bank correctness roughly matches the naive agent, with FP ≤5%. Policy checks cost about 3–6 ms.
  - Admitted limits: the labels are static; the policy set is "not exhaustive"; quality depends on the labels.
- **For wicket.**
  - **Borrow:**
    - the path-pattern rule shape ("an UNFILTERED source reached this agent by any path, and it now calls a HIGH-sensitivity WRITE") is exactly §4.2's `action_taint_allow`, stated over a provenance graph. wicket's floating label is the per-agent summary of that graph;
    - the tool attribute vocabulary (Object, Action, Sensitivity) maps onto adapter `effects` and `risk` (§9);
    - LLM-proposed labels with human verification, and the measured κ, support §9's "generated rules land at R4 until evidence plus a human".
  - **Contradicts design.md:**
    - SEAgent's **default-allow** on no match and its **"always allow this pattern"** button both run against §2.3 (fail narrow) and §10 (fatigue → promotion goes through a reviewed rule, not a click). wicket should keep default-deny;
    - per-round context wiping is the in-loop analogue of §5.2's "fresh agents per subtask", but it relies on controlling the agent's context.
  - **Black-box applicability:**
    - it **assumes control of the agent loop and framework**: it instruments tool calls and agent→agent messages and rebuilds agent contexts;
    - what survives at wicket's proxies: per-agent provenance (the agent's label rises when the gateway or proxy returns UNFILTERED data) and the Path/Rule check at the next consequential `Op`;
    - agent→agent edges exist in wicket only at gates and `spawn`. Edges are *explicit* there, which is easier than in MAS frameworks;
    - SEMemory's selective re-seeding is not possible for Claude Code, which keeps its own transcript. The black-box substitute is a new agent instance plus handles.
- **Confidence:** H (body and appendices B–G read).

### MAS hijacking — Multi-Agent Systems Execute Arbitrary Malicious Code (COLM 2025; arXiv 2503.12188v2, 2025-09-12)
- https://arxiv.org/abs/2503.12188 · `refs/papers/mas-hijacking-2503.12188/` · no code repo given.
- **Problem & threat model.** All agents are benign, but front-line agents (file surfer, web surfer) read adversary-controlled content: a web page, local file, image or audio. The goal is a reverse shell or data exfiltration through the code-executor agent. The orchestrator never reads the untrusted content directly.
- **Mechanism (attack).**
  - The adversarial content is a **fake error message**: a Python traceback, a WordPress 403, or "Access Denied". It says the only way to proceed is to download or execute a file, and it scripts what each agent should do next.
  - The sub-agent relays it as *metadata* (status or error reports). The orchestrator trusts that and routes to the code executor.
  - The paper calls this laundering the request through a confused deputy. Laundering both reaches the orchestrator and changes the request's presentation enough to evade safety training.
  - Formalised as rewriting the suffix of the action trace (App. C).
- **Results.**
  - Web Redirect ASR is 58–90% with GPT-4o, depending on the orchestrator, and up to 100% (AutoGen round-robin with 4o-mini) (Table 2). Local file: up to 97% (Magentic-One on GPT-4o and Gemini Pro; Table 3).
  - Standard AgentDojo IPI strings get 0–1%.
  - Sending the same metadata directly as a user prompt gives 80% ASR with 0% refusal, against 6% ASR and 86% refusal for a plain direct ask (§6.4).
  - Incidental contact (one bad file in a directory the MAS was asked to summarise): 87.5%. An agent wandered into attack files unprompted (§6.5).
  - Sub-agents refused or flagged code as dangerous, and the system still executed it (Apps. J, K).
  - Exfiltration on CrewAI: 3–65%.
  - Limits: only three frameworks, older models, and no defence is evaluated. The authors say isolation in containers still exposes all the data inside the container.
- **For wicket.**
  - **Borrow:**
    - this is the strongest empirical support for §2.6 ("free text does not cross gates into wider authority") and for §4.3 gates;
    - the attack works *because* free-text status or error metadata flows from a reader to a planner with exec authority. wicket's typed gate (§5 `cause: enum`, `notes: handle`) removes exactly that channel;
    - error and status strings returned by children must be treated as data with the child's taint, never as instructions. That includes wicket's own denial bodies, if a child can echo them. `AgentOutcome` (§6) should carry status as an enum.
  - **Challenges design.md:**
    - the parent's "liveness and taint" story assumes the parent stays clean if it never reads untrusted data. This paper shows the parent is attacked *through children's summaries*;
    - so the §4.2 rule "dereferencing a handle joins its label" must also apply to *any* free text the T1/T2 adapter forwards from a child (`AgentEvent`s). §6 already says "free text as handles", and this paper shows that rule is load-bearing;
    - the "incidental contact" result argues for §11's preflight labelling of the whole workdir, not just agent-config files.
  - **Black-box applicability:** it is an attack, needs no loop control, and applies directly to Claude Code subagents and to wicket's own `spawn` trees. Mediation at the gates suffices if gates refuse free text.
- **Confidence:** H.

### Capability gates ≠ authz — Capability Gates Are Not Authorization: Confused-Deputy Failures in LLM Agent Frameworks (arXiv 2606.28679v1, 2026-06-27)
- https://arxiv.org/abs/2606.28679 · `refs/papers/capgates-not-authz-2606.28679/` · code: https://github.com/raceksd-source/scopegate-runtime (Apache-2.0 per LICENSE; GitHub shows NOASSERTION), cloned at `refs/repos/scopegate-runtime` (commit 2994c63, 188 lines of Python).
- **Problem & threat model.** Frameworks gate *which tools exist* (menu, schema, key scope) but not *whether this call with these argument values* is allowed. The model is an untrusted parser. The adversary controls content only. Policy is out-of-band operator data and must be "transitively" free of model output.
- **Mechanism.**
  - A source audit at pinned commits of LangChain/LangGraph, LlamaIndex and the Stripe Agent Toolkit finds none with a default fail-closed per-call value check. Callbacks are observability, not a veto (Table I).
  - **ScopeGate** PDP/PEP (Alg. 1), five ordered stages:
    1. scope: an unlisted tool is denied;
    2. authz: each value-constrained arg must be in a verified set;
    3. money ceiling: an affirmative finite 0 ≤ a ≤ ceiling check;
    4. idempotency key required;
    5. allow.
    Every exception denies.
  - Placement can be SDK middleware, a loopback sidecar, or an egress/MCP gateway. The authors call the property placement-independent if all side-effecting calls pass through it (§V-B).
  - In the code (`policy.py`), **args not listed in `allow_values` are unconstrained**.
- **Results.**
  - Bypass suite: 0/48 allowed (case, zero-width, homoglyph, type confusion, money edge cases). The suite found a real NaN fail-open in their own earlier prototype.
  - Adaptive run, 40 iterations with GLM-5.2 fed the deny reasons: 0/29 attacks allowed.
  - 0/10 benign false denies. Latam-GPT payment agent: 10/10 contained.
  - Companion sweep: "deployment-tier" models attempt unauthorized calls at mean 0.603 vs 0.189 for flagships.
  - Limits: single author; small, suite-bounded corpus; single-turn; no CVE claimed; "containment is not cure".
- **For wicket.**
  - **Borrow:**
    - independent confirmation of §4.1's closed-world `args` constraints and §8.1 canonicalize-or-reject;
    - the NaN anecdote is a concrete fuzz case for wicket's `Constraint::Int` and the adapter interpreter (§2.8 "fuzzed and boring"): affirmative range checks, reject non-finite values and bool-as-int;
    - feeding deny reasons to an adaptive attacker is a good M2 red-team protocol, and directly relevant because wicket's §8.5 problem+json *does* return reasons to the agent.
  - **Contradicts:**
    - ScopeGate is *open-world on unlisted args*; wicket is closed-world (§4.1). Keep wicket's choice;
    - its verified sets are static operator data. wicket derives them per task (§5.2), which the paper would call allowed only if no model output feeds them. wicket's field-provenance rule (§10) is the stronger form.
  - **Black-box applicability:** it does not need the agent loop. It is a pure PEP over structured calls, so it ports directly to wicket's gateway and egress proxy, where the adapter supplies the structure.
- **Confidence:** H (short paper; the code was read).

### CapScope — Authority Is Not a String: A Capability-Scoped Harness for Prompt-Injection-Resistant Coding Agents (LMPL '26 / arXiv 2609.08371v1, 2026-09-08)
- https://arxiv.org/abs/2609.08371 · `refs/papers/capscope-2609.08371/` · artefact on figshare (https://figshare.com/s/86184ed20f66d1f0cf91), not cloned.
- **Problem & threat model.** In coding agents, naming a resource is enough to act on it (ambient authority). The injection surfaces are README, AGENTS.md, skill files, source comments and tool output. The attacker cannot mint capabilities or modify the harness. **Not** a confidentiality mechanism.
- **Mechanism.**
  - `Cap[effect, φ]` with effects Read, Write (canonicalised path-prefix predicate; `canon` resolves `..` and symlinks) and Exec (allowed argv-prefix vectors).
  - `parse(s)` rejects command substitution, splits compound commands, drops redirections, and checks each segment. Read and navigation commands (grep, find, ls) are always admitted.
  - **Mint:** a preflight LLM call sees only the trusted request plus the **file tree (names only)**. Host code validates the proposal, compiles it into a task-wide *ceiling*, and freezes it before any content is read.
  - **Derive:** on delegation the model proposes the subagent's role, subtask and grant. The host keeps only capabilities ⪯ the ceiling (`src/**` may narrow to `src/parser.py`). Each subagent gets its own host-side store.
  - **Invoke:** a blocking pre-dispatch hook (Pi's `tool_call` event, `block:true`) checks the issuing agent's store.
  - A user-approved extra capability is a new trusted Mint; this was disabled in the evaluation.
- **Results.**
  - 300 runs: 5 Python repairs × 5 surfaces × 4 conditions × 3 trials, on qwen3.5-flash.
  - Injected effect executed: ambient 47/75, static deny-list 46/75, task-specific *global* policy 33/75, **CapScope 3/75**. All 3 residuals came via AGENTS.md (Tables 2–3).
  - Task success: 68/75 vs 72/75 ambient.
  - Mean time 316 s vs 145 s, driven by repeated attack retries after refusals (27 of 34 runs) and by delegation.
  - Failures: 2 from preflight omitting the needed write, 2 from the workflow not rerouting.
  - Residual risks the authors name: a grant broader than the subtask, and injected text steering *which in-ceiling scope* the model-generated subtask requests. Filename injection is out of scope. Exec of allowed commands (pytest imports repo code) still needs a sandbox. Small corpus, one model.
- **For wicket.**
  - **Borrow:**
    - the clearest evidence for §4.3 "agents are implementation detail of zones" with per-zone reach. A single task-scoped policy shared by all children (B2) leaks 11× more than per-principal scopes. So `spawn` children (§5.1) must get their *own* narrowed reach, not the parent's;
    - preflight input = trusted text + **file tree names only** is a concrete refinement of §5.2. The proposer may see repo structure, with filenames labelled as an attacker-influenced channel;
    - the argv-segment parsing is relevant if wicket ever constrains Exec inside the box. Today it does not (Bash is inside the box; only egress is mediated);
    - informative refusals cause repeated retries. That cost bears on §8.5/E1.
  - **Challenges:**
    - the residual "injection steers which in-ceiling grant a child requests" means child ⊆ parent is necessary but not sufficient. That supports §10's *field provenance* for spawn arguments and the brief's "child task text inherits the parent's label" (§5.1);
    - CapScope freezes the ceiling and forbids *any* expansion except a user mint, which is stricter than wicket's auto tier (§10). That is consistent with wicket starting the parent tier off.
  - **Black-box applicability:**
    - CapScope **needs a blocking pre-dispatch hook in the agent loop**, which Pi provides. Claude Code's T1 `can_use_tool`/PreToolUse could host it as *telemetry/UX*, but design.md §2.1 says the in-box hooks are not TCB;
    - what survives at wicket's proxies is per-zone capability stores for *external* effects (GitHub writes, egress). In-box Read, Write and Exec on the workdir are only enforceable by the sandbox (Landlock or overlay per zone);
    - wicket's split of research and fix into different zones *is* CapScope's runner/patcher split, done with process isolation instead of hooks.
- **Confidence:** H.

### ActPlane — ActPlane: Programmable OS-Level Policy Enforcement for Agent Harnesses (arXiv 2606.25189v2, 2026-06-30)
- https://arxiv.org/abs/2606.25189 · `refs/papers/actplane-2606.25189/` · code https://github.com/eunomia-bpf/ActPlane (MIT). Not cloned: about 170 MB, over the size limit.
- **Problem & threat model.**
  - Tool-call guardrails miss effects that bypass the tool layer: a script the agent wrote earlier, subprocesses, a hidden entrypoint.
  - OS sandboxes control resources rather than *actions*, need static policy, and return opaque EPERM.
  - The agent may be compromised. A privileged runner loads the eBPF engine and "higher-authority" policy before the agent starts. The trust boundary is *temporal*: anything loaded before the agent starts is higher-authority. Kernel and CAP_BPF compromise, file contents and side channels are out of scope.
- **Mechanism.**
  - **Empirical study** of 64 repos (2,116 statements in CLAUDE.md/AGENTS.md):
    - 64% of statements are policies;
    - of policies, 83% are system-observable (16% cross-event);
    - 73.6% of system-observable policies need project or task context.
  - **DSL (App. A).**
    - `source L = exec|file|endpoint PATTERN`;
    - `rule R: {notify|block|kill} op_pattern [if labels] [unless target…|lineage-includes…] [after exec P [exits N] since write P] because "…"`.
  - **IFC.** Each process, file and endpoint carries monotonic 64-bit label bitmasks, propagated on fork, exec, read, write and connect. For example, a process that read `.env` cannot connect out. A fresh subprocess clears inherited labels, which is their over-taint mitigation.
  - **Hierarchical policy domains:**
    - bound to process subtrees; a child inherits all parent rules and may only add;
    - an in-kernel authority checker rejects deltas that clear inherited mask bits;
    - declassification belongs to the domain that authored the rule;
    - **inherited rules cannot be declassified**.
  - **Implementation.** BPF-LSM for pre-op block, tracepoints for post-op kill. The `because` text is returned to the agent as semantic feedback. About 3.2K lines of Rust userspace and 1.8K of BPF C, at most 128 rules.
- **Results.**
  - All 607 OS-enforceable policies translated by a Codex/GPT-5.5 agent; only 2 needed a retry. Cost $0.028 per policy.
  - Decision Compliance Rate (DCR) on 190 traces (38 rules × 5) is 75.8%, against 45–49% for prompt-filter, tool-regex and FIDES (Table 2). The gap is on script and hidden traces, where the baselines are near 0%.
  - Without semantic feedback, DCR is 53.7%: detection stays at 75%, but only 31% of detections lead to compliance.
  - Overhead 1.9% on agent traces and 6.5–8.4% on kernel builds (32 to 100 rules).
  - OpenAgentSafety: 74% of baseline-unsafe tasks prevented with policies generated from the task description only. 28 misses (chat-only harm, file content, service-side effects), and 16% of already-safe tasks were touched.
  - Limits: an LLM judge scores outcomes; rule-translation quality drives both FP and FN; content policies are out of scope; semantically equivalent ops (a custom git client) evade command-name rules but not syscalls.
- **For wicket.**
  - **Borrow:**
    1. The *temporal* trust boundary is the same as wicket's: policy derived and loaded before the agent reads anything (§5.2).
    2. Domains where a child may only add rules and cannot clear inherited labels are exactly §2.5 and §4.3 `reach ⊆ parent`. Their kernel-side "reject a delta that clears an inherited bit" is a clean model for wicket's ledger check.
    3. **Semantic feedback measurably matters**: a 3× jump in correct violation outcomes. That supports §8.5's problem+json `hint` and E1 (§14 M3).
    4. In-box IFC on fork, exec and file is a candidate *process-backend* add-on (§7, `process` tier) for labelling workdir files that came from tainted sources, to feed preflight (§11). It would be telemetry-grade unless the jail helper owns it.
  - **Challenges design.md:**
    - ActPlane lets **the in-box agent author** runtime rules, which is safe only because those rules can only narrow. wicket could offer the same as a `wicket.restrict(...)` tool, a zero-risk narrowing;
    - its finding that 74% of policies need repo or task context challenges §5.2's "proposer sees nothing fetched". A trusted-text-only deriver will under-specify ("run the tests"). CapScope's names-only file tree and ActPlane's let-the-agent-narrow are two ways around that;
    - ActPlane compares against FIDES as a tool-layer IFC and shows tool-layer mediation misses indirect paths. For wicket that is fine for *external* effects, which must cross the proxy regardless of path. It is a real gap for *in-box* effects such as deleting workdir files or writing `CLAUDE.md`, which only the sandbox sees.
  - **Black-box applicability:** high. It requires **no agent-loop control**, only process-tree attachment, and was evaluated on Codex CLI, OpenHands and Claude Code traces. It needs BPF-LSM (kernel ≥ 5.7 with `lsm=bpf`); check whether this box boots with it. It does not work under gVisor, which has its own kernel, so it fits only the `process` backend.
- **Confidence:** H (body and grammar appendix read).

## 7. MCP access control, delegation and acquired authority

### AgentBound — AgentBound: Securing Execution Boundaries of AI Agents (FSE 2026 / arXiv 2510.21236v3, 2025-10-24; v3 2026-04-24)
- https://arxiv.org/abs/2510.21236 · `refs/papers/agentbound-2510.21236/` · no GitHub repo; replication package on Zenodo (doi 10.5281/zenodo.19571298), not cloned. Paper is CC BY 4.0.
- **Problem & threat model.** MCP servers run as host subprocesses with the user's full privileges. The adversary controls one or more malicious MCP servers (prompt injection, tool poisoning, "puppet" cross-server poisoning, rug pull, ordinary app-level bugs). Only attacks that touch *system resources* (files, network, env, exec) are in scope (§2.3). Attacks that stay inside the granted permissions are explicitly out of scope ("semantic gap").
- **Mechanism.** (1) **AgentManifest**: a JSON file shipped with each server, holding an English description plus capabilities from a closed vocabulary of 18 Android/macOS-TCC-derived capabilities (`mcp.ac.filesystem.{read,write,delete}`, `system.env.{read,write}`, `system.exec`, `system.process`, `network.{client,server,bluetooth}`, peripherals, location, notifications, clipboard; Table 2). (2) At first run the generic capabilities are **instantiated into runtime permissions** with user consent: a concrete directory and mode, an exact URL, specific env variables. Static ones may be pre-declared. A runtime permission not covered by the manifest **aborts execution** (§3.1). (3) **AgentBox**: each server runs in a Docker container that starts with no privileges. It uses mounts for filesystem scope and an env whitelist. For the network, the entrypoint installs the package from npm/PyPI *before* restrictions apply, then resolves the allowed hostnames to IPs and writes iptables allow-rules (§3.3). (4) **AgentManifestGen**: an LLM agent with file-level access to the server repo. gpt-5-mini makes 5 intermediate manifests and gpt-5 consolidates them. Out-of-vocabulary output is rejected by strict schema validation. Each capability needs a rationale. The authors note that reasoning models used tools less and hallucinated more.
- **Results.** 296 top servers; the most common capabilities are network.client 83.1%, env.read 79.6%, fs.read 74.1%, fs.write 49.3% (Fig. 3). Developer review of 96 manifests drew a 26% response rate; of the respondents, 80.9% were accurate with 100% recall. Against human-written manifests for 48 servers: 96.5% capability agreement, P 0.94 / R 0.96. **23 of the 29 mismatches were omissions** (under-grants). It blocked all 9 system-resource attacks. It did *not* block the puppet attack B.2 (redirecting crypto transfers via a permitted endpoint), the SQL injection B.4, or pure LLM-output attacks (§4.2). Overhead: +150–400 ms container start and +0.29–0.6 ms per operation. Authors' limitations (§5): no protection within declared policy; Docker, the kernel and npm/PyPI are in the TCB; the vocabulary is not guaranteed exhaustive. A developer (GI27) asked that env.read be limited to named variables.
- **For wicket.**
  - *Borrow:* the two-level "generic capability in a signed manifest → instantiated runtime permission" split maps onto §8.2 kind 2 (third-party MCP servers in their own sandbox). The server's manifest should be the **ceiling** for its sandbox, intersected with the zone's `reach` (§4.3).
  - *Borrow:* the LLM-generator evidence supports §9's loop of generating, then having a human review a small diff. Errors were mostly omissions, which is the safe direction under "fail narrow" (§2.3).
  - *Challenges:* host-level capabilities are far too coarse for wicket. `network.client` + URL cannot stop B.2-style argument manipulation. That is evidence *for* wicket's argument-total adapters (§9) over capability tags.
  - *Don't copy:* iptables allowlists from IPs resolved once at startup (stale DNS, shared CDNs), and unrestricted install before lockdown. wicket's UDS-bridged egress proxy with SNI/HTTP-level decisions (§8.1) is strictly better.
  - *Black-box:* yes. It needs no control of the agent loop or the servers; enforcement sits at the server's process boundary. All of it survives in wicket. Note that its consent dialogs assume a trusted host/user, while wicket's "host" is the hostile box, so consent must come from wicketd, not the agent's client.
- Confidence: **H**.

### Acquired-resource authorization — Runtime Authorization for Resources Acquired by AI Agents (arXiv 2609.14744v2, 2026-09-13; v2 2026-09-18)
- https://arxiv.org/abs/2609.14744 · `refs/papers/runtime-authz-acquired-2609.14744/` · no code released.
- **Problem & threat model.** An authorized call (cloud create, enroll, buy, register agent) can *return new authority*: a credential, an instance with an attached identity, an account, a child principal. Payment, budget, OAuth-scope and tool-manifest checks never decide whether that *output* may become usable. This is the "post-fulfillment activation gap" (§1.1). The adversary controls the agent's planning and all of its descendants. It can use free tiers, aliases, refunds, concurrency, retries, replay and stale epochs. It cannot break the broker, forge signatures, or produce effects outside mediation (§3.2).
- **Mechanism.**
  - Six events: propose → reserve → dispatch → **quarantine** → **resolve** → **activate**.
  - Provider outputs go into a broker vault. The agent only ever gets a **non-exportable opaque handle**, and raw credentials never enter the agent. If a provider can return a raw credential into an agent-controlled channel, the profile is non-conforming (§3.1, §10.2).
  - A **versioned resolver** queries authoritative provider state rather than the requested product, and builds an actual-capability manifest covering default identity, network reachability, roles, audience, exportability and delegation. Unresolved fields map to a conservative upper bound or reject (A3).
  - Activation is a serializable transaction that evaluates a **downward-closed relational predicate** over a typed resource–capability hypergraph. The predicate expresses correlated limits that per-field allowlists lose, such as "may hold sensitive.read *or* external.publish but not both" and "at most one active descendant per control root".
  - Limits aggregate per **authority domain** = (issuer, canonical control root, policy epoch), so a fresh grant ID cannot reset counters (Def. 4).
  - Each later use gets a **single-use effect permit**. It binds the normalized episode (subject, beneficiary, effect, target, data domain via a versioned target→domain map, purpose, recipient, time window) and is re-checked and consumed atomically **at the effect's linearization point** (Alg. 4, A10). "A check followed by an unbound external call is not conforming" (§10.2).
  - Commerce, delivery and authority are three orthogonal state axes, so a refund does not revoke a live credential (Thm 6). Epoch changes fence earlier decisions (Thm 7).
  - Adapters classify every external field as native-authenticated, authenticated sidecar, independently observed, or unavailable. Natural language never upgrades a field (§6).
- **Results.** Eight conditional safety theorems under assumptions A1–A11 (complete mediation, authentic state, conservative resolution, canonical identity, serializable store, ...).
  - Reference semantics: 20/20 benign accepted and 40/40 unsafe rejected over 810 events. The checker rejected 89/89 tamper tests.
  - Frozen Codex 0.154.0 and Gemini CLI 0.59.0 MCP client components completed 54/54 local stdio calls.
  - Staged MCP→Docker composition (18 cases): no unauthorized `docker start` in 16 unsafe paths. The Docker profile requires a digest-pinned image, no network, read-only root, all caps dropped, and re-inspection before start to catch configuration drift (§6.4).
  - Latency: about 2 ms p50 per full semantic trace (Table 8).
  - Authors' limits (§10): no model-driven or end-to-end CLI session, no real provider, no production deployment. Generic shell execution, direct network and raw container sockets are *excluded* from the complete-mediation claim. Arbitrary right-acquisition is undecidable (HRU).
- **For wicket.** This is a gap in design.md.
  - **Acquisition is invisible today.** wicket narrows authority (§4.1, §5.1 child ⊆ parent), but a granted call can *mint* authority: creating a deploy key, PAT, OAuth/GitHub App, Actions secret, webhook, cloud IAM key, or a new repo the agent then administers. The fix: adapters (§9) declare an `effect: mint.credential | create.principal | create.resource` with response-field paths. The egress proxy/gateway **quarantines those response fields into the vault** and returns a placeholder or handle. Activation is a separate ledger grant checked against the zone. This extends principle 2 ("no secrets in the box") from injected credentials to *returned* ones.
  - **Ledger key.** Key ratchet budgets and use counts (§10) by (issuer, task root, policy epoch), not by grant ID.
  - **Consume at dispatch.** Consume single-use grants in the same transaction that forwards upstream, after re-checking revocation and epoch, rather than at decision time (§3 Op digest + §8.5).
  - **Policy changes fence grants.** A manifest or zone policy change bumps an epoch that invalidates outstanding grants.
  - *Challenges:* §4.1's per-capability syntactic subset check cannot express co-possession or cardinality limits. wicket's labels (§4.2) cover some of this; the rest would need a relational check over the ledger.
  - *Black-box:* the paper assumes complete mediation at a broker, not control of the planner ("no model-generated text is an authorization input", §5). It deliberately excludes shell and direct network, which wicket's egress proxy covers. So it fits wicket's proxies well, provided adapters can recognize credential-bearing responses.
- Confidence: **M**. I read §1–3, §5–6, §8 and §10 in full and skimmed the formal §4 and the proofs.

### Authenticated delegation — Authenticated Delegation and Authorized AI Agents (arXiv 2501.09674v1, cs.CY, 2025-01-16)
- https://arxiv.org/abs/2501.09674 · `refs/papers/auth-delegation/` (shared copy) · no code.
- **Problem & threat model.** Services can't tell whom an agent acts for, or what it may do. Prompts are an unreliable scoping tool given prompt injection and misinstruction. This is a position/framework paper with no adversary model and no evaluation.
- **Mechanism.**
  - An OIDC/OAuth 2.0 extension with three tokens: the user's **ID token**; an **Agent-ID token** (agent registered with the OpenID Provider as an OAuth native client, optionally carrying system-card metadata); and a user-signed **delegation token**. The delegation token holds hashes of both, scope limits, expiry, a revocation endpoint and audit URLs. W3C VCs are an alternative or complement, and UMA can centralize policy across many agents (§3).
  - §4 separates **task scoping** from **resource scoping**. It argues that structured resource scoping (XACML, ODRL, SQL grants, URL allow/deny) must be the enforcement foundation, with natural language only as guidance.
  - Proposed workflow: an LLM translates the user's NL constraint into a structured policy, and the human reviews and approves it. "Authentication flows" escalate borderline actions to the user, with prompt fatigue acknowledged.
  - Inter-agent: a receiving agent restates the sender's scope as a structured interpretation, which is logged and approved.
  - App. B.1: schema validation of agent outputs as a scoping mechanism.
- **Results.** None (no implementation or measurement). Admitted limits (§5): NL→policy translation correctness is unevaluated; human reviewers miss subtle errors; prompt injection can push the translator to widen policy; contextual drift; OIDC provider privacy and correlation; multiple sign-in flows; reliance on third parties to enforce.
- **For wicket.**
  - *Supports:* §5.2 (LLM proposes the manifest, a human approves it) and the stance that resource scoping (adapters + capabilities) is the enforcement core. Its warning that the translator is an injection target matches wicket's rule that the proposer sees only trusted task text.
  - *Contradicts:* the agent *holds and wields* its delegation token or VC. That violates principle 2 and [03 §2.7] (no tokens in the box). In wicket the proxy should hold any such credential and present it upstream on the agent's behalf (§8.4), which keeps the provider-visible accountability benefit.
  - *Possible borrow:* when providers accept agent-attribution claims (e.g., OAuth token exchange with an actor claim), mint per-task, audience-bound tokens naming the zone/task as the actor.
  - *Black-box:* the paper is agnostic. Everything it proposes can live at wicket's proxy, and nothing needs the agent loop.
- Confidence: **H** (short, non-technical body; read in full).

### ETDI — ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP by using OAuth-Enhanced Tool Definitions and Policy-Based Access Control (arXiv 2506.01333v1, 2025-06-02)
- https://arxiv.org/abs/2506.01333 · `refs/papers/etdi/` (shared copy) · demo is a fork of the MCP python-sdk (github.com/vineethsai/python-sdk) plus a docs repo. Not cloned: an SDK fork, not policy code.
- **Problem & threat model.** Tool poisoning (impersonating or duplicating a trusted tool's metadata) and rug pulls (behaviour or definition changes after approval with no re-consent). The user, host application and MCP client are explicitly **trusted**; only tools are adversarial (§VI).
- **Mechanism.**
  - Tool definitions are **signed by the provider**, **immutable and versioned** (any change, including a hash of the backend OpenAPI contract, needs a new signed version), and **declare permissions** (OAuth scopes) for user approval.
  - The client stores (id, version, content hash, permissions). A same-version hash mismatch, a new version or a new tool triggers re-approval (Listing 1).
  - OAuth variant: an IdP issues tokens to tools with custom claims `tool_id` and `tool_version`, binding the token to one definition.
  - Optional **PDP** (Cedar via Amazon Verified Permissions, or OPA): before each invocation, (principal = tool identity, action, resource URN, context = user, time, purpose) is evaluated. Policies are signed artifacts.
  - **Call-stack verification**: caller→callee allow/deny, privilege escalation via a lower-privilege caller, cycles, max depth and rate limits.
- **Results.** No evaluation, benchmark or overhead numbers; it is a design proposal. Admitted challenges: PDP latency, policy complexity, key and policy management, UX of re-approval (raw Cedar is not user-presentable), the need to certify that clients don't bypass the PDP, and adoption.
- **For wicket.**
  - *Confirms* §8.2's hash-pinning of third-party tool descriptions.
  - *Suggests:* treat a changed definition as a *policy change*. Run it through §4.1's narrowing check (automatic if it narrows, a decision if it widens) instead of always re-prompting. Pin the backend contract hash too.
  - *Borrow:* the call-stack and rate rules map to sequence and rate constraints wicket can enforce in the ledger over the Op stream (wicket sees Op order across surfaces, not the agent's intent).
  - *Contradicts:* the trust split. ETDI verifies in the MCP client/host, which in wicket is inside the hostile box. All verification must move to the gateway, which is what §8.2 already does.
  - *Black-box:* fully, since it is gateway-side. But it only addresses tool authenticity, not injected data or argument misuse.
- Confidence: **H** (short; read in full).

## 8. Evaluations, SoKs and sandbox escape

### Adaptive-OOB — Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents (arXiv 2606.26479v1, 2026-06-25; LaunchSafe Research, not peer-reviewed)
- https://arxiv.org/abs/2606.26479 · `refs/papers/adaptive-oob-2606.26479/` · no public repo given (the paper names scripts `run_full_study.sh` and `run_repeats.sh` but no URL)
- **Problem & threat model.** Out-of-band defences (CaMeL, FIDES, Progent, RTBAS, Conseca, FORGE) are validated only against static attack sets. That is the same method that made in-band defences look strong before adaptive attacks broke them. The attacker controls ≥1 untrusted channel, knows the deployed defence and iterates against it, but controls neither the weights nor the enforcement layer. The system prompt and the user's turn are trusted, with a caveat in §8.2.
- **Mechanism.**
  - The paper reads the defences through Biba integrity (reading low-integrity data lowers the subject's integrity; a lowered subject can't authorise a high-integrity action), the reference monitor (complete mediation, tamper-proof, verifiable) and Saltzer–Schroeder.
  - Table 2 compares the systems on D1–D8: primitive, deterministic vs LLM gate, monitor location, integrity coverage, confidentiality coverage, implicit flows, cost, retrofit.
  - §10 defines an adaptive-evaluation protocol:
    - the attacker knows the policy;
    - attack families: adaptive string optimisation, provenance spoofing where labels are attacker-influenceable, social engineering aimed at endorsement, side-channel probes;
    - metrics: ASV, utility retention against an undefended baseline, endorsement-request rate, monitor overhead.
  - §11 runs the protocol against Progent:
    - Progent in its default configuration (policy updates on), with the policy LLM also set to Qwen2.5-7B;
    - AgentDojo banking/slack/workspace, the first 8 user tasks per suite × all injection tasks, 3 runs;
    - a hand-written "disguise the malicious call as a pre-authorised prerequisite" injection aimed at Progent's policy-update LLM.
- **Results (Tables 3–4).**
  - Mean ASR: undefended 25.8%±2.1, Progent 4.2%±0.3, Progent under the adaptive attack 2.6%±0.04.
    - banking: 19.0 → 1.9 → 3.7
    - slack: 58.3 → 10.8 → 4.2
    - workspace: 0% everywhere, including undefended. The authors traced this to the 7B model ignoring the injection on read-only tasks, so workspace cannot tell defences apart.
  - Utility fell from 45.2% to 27.1% (adaptive 25.8%), with about 15× more LLM calls per task.
  - Admitted limits:
    - one weak model, a small subsample, one adaptive template, no white-box/GCG attack;
    - **no attack confined to already-authorised actions**;
    - the travel suite was excluded;
    - a confound: the "benign" framing may also have weakened the agent's compliance.
  - Analytical claims the authors make:
    - retrofit onto unmodified agents is already solved in prototypes (Progent proxy mode, FORGE);
    - **provenance assignment is the TCB and is under-specified everywhere** (§8.2: in FIDES's deployed form, a forgotten label defaults to trusted);
    - tasks that must act on untrusted content fall back to human endorsement, which is both an attack target and a fatigue source (§8.3);
    - text-to-text harms are out of scope for every action monitor (§8.4);
    - a retrofit monitor that sees only tool I/O cannot see how the model laundered low-integrity text into an argument (§9).
- **For wicket.**
  - **Borrow:**
    - the §10 metric set for M2/M3/M5 (§14): utility retention, endorsement-request rate, overhead, and 3 repeats with std;
    - a check that each test task class has a non-zero *undefended* ASR before any defence is credited (the workspace lesson).
    - The attack that was never run, "achieve the goal using only already-authorised actions", is exactly what wicket's ceiling permits (a PR body, which file to edit, which in-ceiling grant to request). It should be a named red-team class in M2/M5.
  - **Supports design.md:**
    - principle 4 and the parent tier being off (§10, §15): the only model-based component was the one attacked;
    - wicket's coarse per-agent label (§4.2) is the sound answer to the §9 objection. It does not try to see laundering; any read taints the whole agent.
    - §8.2 argues for pessimistic adapter default labels (§9, 03 §5.3) and an explicit `unknown` source tag rather than an untagged = trusted default.
  - **Challenges:** §4.2 writes "∅ taint = trusted". If any ingress path forgets to join a label, the default is trusted, which is the failure mode §8.2 names. Ingress points should *fail tainted*: an unlabelled response gets `unknown`.
  - **Black-box applicability:** this is an evaluation paper, so it is fully applicable. Progent's proxy mode, the system tested, mediates at the tool boundary without changing the agent, which is wicket's posture.
- Confidence: **H**. Short paper read in full; the table cells are interleaved in extraction but match the prose.

### Attacker Moves Second — The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections (arXiv 2510.09023v1, 2025-10-10; preprint under review; Nasr, Carlini, Tramèr et al., OpenAI/Anthropic/Google DeepMind/ETH/HackAPrompt)
- https://arxiv.org/abs/2510.09023 · `refs/papers/attacker-second/` · no repo in the text
- **Problem & threat model.** Jailbreak and prompt-injection defences are evaluated on static attack strings or weak, non-adapted optimisers. The authors test three access levels (white-box, black-box with logits, generation-only) and give the attacker large compute, Kerckhoffs-style.
- **Mechanism.**
  - A generic adaptive-attack loop, PSSU (propose, score, select, update), with four instantiations:
    - gradient-based;
    - RL, where an LLM proposes triggers and is GRPO-trained on the score;
    - search, a genetic algorithm with LLM mutation;
    - human red-teaming, an online competition with >500 participants.
  - Twelve defences in four families:
    - prompting: Spotlighting, Prompt Sandwiching, RPO;
    - training: Circuit Breakers, StruQ, MetaSecAlign;
    - filtering: ProtectAI, PromptGuard, PIGuard, Model Armor;
    - secret knowledge: Data Sentinel, MELON.
  - Each defence is evaluated on its own paper's benchmark (AgentDojo, HarmBench, OpenPromptInject, …), so the numbers are not comparable across defences.
- **Results (§5).**
  - Spotlighting and Sandwiching: about 1% static ASR on AgentDojo, **>95%** with the search attack; human red-teamers found 265 and 178 successes.
  - MetaSecAlign: 2% static, **96%** search, on AgentDojo.
  - RPO: 98% (RL) and 96% (gradient). Circuit Breakers: 100% (RL). StruQ: broken in every tested case.
  - Detectors: ProtectAI, PromptGuard and Model Armor >90%; PIGuard 71%; humans found 123 successes even in the strictest setting.
  - Data Sentinel: bypassed in every case, with >80% adversarial-task accuracy.
  - MELON: 76% ASR without knowledge of the defence, 95% with it (a conditional trigger that acts only when the input isn't being summarised).
  - Humans succeeded on every scenario; on a subset, search reached 69% vs humans 100%.
  - Lessons: static evaluations mislead; automated attacks are necessary but not sufficient; human red-teaming remains strongest; LLM auto-raters are themselves attackable.
  - Many winning triggers present the malicious action as a **required prerequisite or policy step** rather than an override.
  - Out of scope: system-level / out-of-band defences such as CaMeL or Progent were not attacked.
- **For wicket.**
  - **Supports:**
    - principle 4 (§2) and the justification as `Untrusted<String>` (§10). Winning attacks are "this action is a necessary prerequisite" text, exactly what an agent would write in a justification;
    - keeping the LLM parent decider off (§10, §15);
    - treating any MELON-style or classifier sensor at the LLM proxy (§8.3) as **telemetry that can only raise risk, never relax a decision**.
  - **Borrow for §14 (M2 red team, M5 smuggling test):** run a PSSU loop against wicket itself. Give the attacker LLM the manifest, the adapter rules and the denial bodies; score by "consequential Op allowed upstream"; include a human round.
  - Wicket's own model calls (quarantined reader, declassify decider, adapter generator, manifest proposer, §6) are in-band components, and this paper predicts they fall to adaptive inputs. They are safe only where their output capacity is bounded (typed fields, §4.3) or their input is trusted (task text only, §5.2).
  - **Black-box applicability:** the attacked defences are in-band and model-side, and wicket controls none of them for the inner agent. The negative result transfers to every LLM wicket puts on a decision path.
- Confidence: **H** for the defences and numbers; Figure 1's bar values were garbled in extraction, so I used the prose.

### Systems SoK — Systems Security Foundations for Agentic Computing (arXiv 2512.01295v2, revised 2026-02-19; SoK; Christodorescu, Fernandes, Jha, Rehberger, Chaudhuri et al., Google/UCSD/UW–Madison/Meta/Gray Swan/Cornell)
- https://arxiv.org/abs/2512.01295 · `refs/papers/sok-systems-foundations-2512.01295/` · no code
- **Problem & threat model.** Agent-security literature is written from the AI side. The paper applies classic systems security (TCB, least privilege, complete mediation, secure information flow, the human weak link) to whole agentic systems.
- **Mechanism (analysis, not a system).**
  - Four structural challenges:
    1. A **probabilistic TCB**: "imagine a probabilistic NX bit".
    2. **Dynamic, task-specific policy**: there is no app and no developer. Their worked example "comment on GitLab issue 745" needs exactly navigate-to-issue + write-comment; the follow-up "summarize issue 745" poses the question of resetting context vs evolving policy with untrusted data already in context.
    3. A **fuzzy security boundary** (semantic gap): they cite ceLLMate's HTTP layer as the right abstraction for browser agents.
    4. **Dynamic instruction following**, which they liken to dynamic code loading: MCP descriptions and skills are instructions loaded from outside, and agents lack the web's CSP/SOP/SRI equivalents.
  - Eleven real attacks mapped to violated principles (Table 1):
    - M365 Copilot ASCII-smuggling link exfiltration;
    - Devin `expose_port`;
    - ChatGPT memory "SpAIware";
    - Amp agent editing its own `settings.json` allowlist;
    - DeepSeek XSS;
    - Terminal DiLLMa (ANSI escape sequences);
    - Operator via a GitHub issue;
    - Devin secret leaks via curl, URLs and markdown images;
    - Cursor AgentFlayer via Jira (required auto-run);
    - **Claude Code DNS exfiltration via an allow-listed `ping`**;
    - AI ClickFix.
  - Table 2 classifies about 22 defences by policy source, TCB assumption and boundary location.
- **Results / open problems (§5).**
  - Instruction/data separation would cut much injection but not all. Even data that is never "followed" biases arguments, e.g. canonical examples in poisoned tool descriptions.
  - Least privilege needs policy *specification* help: policy assistants that clarify under-specified tasks with the user.
  - IFC through an LLM has no "flow arithmetic": outputs carry the union of input labels, which gives **label explosion**.
  - Guarantees from probabilistic TCBs may be impossible.
  - No empirical evaluation, by design.
- **For wicket.**
  - **Supports:**
    - deterministic enforcement outside the model (§2, principle 8);
    - HTTP-level mediation with semantic adapters (§8.1, §9), the paper's answer to the fuzzy boundary;
    - a policy language amenable to formal reasoning about added policies (§4.1 symcc narrowing/widening; their §2.2);
    - coarse per-agent union labels (§4.2) as the honest consequence of no flow arithmetic, with fresh agents and handles as the creep remedy (03 §5.2).
  - Their IFC motivating case (a coding agent needs an API key only to push an image) is solved in wicket by credential injection (§8.4, principle 2): the key never enters the agent, so the flow never exists.
  - **Use the 11 case studies as a conformance/regression checklist (§6.1, §14 M1–M2):**
    - Amp → root-owned managed settings, agent config untrusted (§6);
    - Claude Code ping/DNS → netns with no interface and no resolver (§7); DNS on hosted backends is already listed as unmediated (§12);
    - markdown-image and link exfiltration → dangerous patterns (§9);
    - SpAIware → task-scoped memory, Declassify to promote (§11);
    - `expose_port` → no inbound path.
  - **New gap:** Terminal DiLLMa and the Copilot link both attack the **human-facing renderer**. Wicket shows untrusted strings in `wicket approve`, the TUI and the timeline (§10, §12): justifications, branch names, PR titles. Those views must strip ANSI and control characters, defang URLs and never auto-load remote content.
  - **Black-box applicability:** an architecture-level analysis that does not assume loop control. Its "fuzzy boundary" point is the main risk for T3 agents: a Bash + curl agent has no semantic tool layer, so the adapters at the egress proxy *are* the semantic layer.
- Confidence: **H** for body and case studies; **M** for Table 2 cell assignments (extraction scrambled the columns).

### Architecting Secure Agents — Architecting Secure AI Agents: Perspectives on System-Level Defenses Against Indirect Prompt Injection Attacks (arXiv 2603.30016v1, 2026-03-31; position paper; Xiang, Zagieboylo, Ghosh, Greshake, Xiao, Suh et al., NVIDIA)
- https://arxiv.org/abs/2603.30016 · `refs/papers/architecting-secure-agents-2603.30016/` · no code
- **Problem & threat model.** Indirect prompt injection against fully autonomous general-purpose agents. System and user prompts are trusted; the environment is partially compromised. Sandboxing is explicitly out of scope.
- **Mechanism.**
  - A reference architecture (Fig. 1): an orchestrator (LLM) produces a **plan** (how) and a **policy** (what is allowed), checked by a plan/policy approver (LLM, may escalate to a human). An executor (LLM) proposes actions; a policy enforcer (rules or LLM, may defer to a human) allows or blocks them. Feedback arrows (a–c) let the environment or enforcer trigger re-planning and policy updates.
  - Position 1: dynamic re-planning *and* policy updates are necessary.
    - Example: a deprecated endpoint returns 410.
    - Example: debugging that only reveals `/var/log/myservice/error.log` at runtime.
    - CaMeL's `send_money` rule both falsely blocks (recipient from an invoice) and falsely allows (amount taken from a web page is unconstrained).
  - Position 2: some context-dependent security decisions need an LLM, but only one that sees **narrow structured artifacts (a typed trace plus a proposed plan/policy diff), never raw environment text**, and decides a bounded question.
    - Proposal 1: the model verbalises the instructions it intends to follow. The system traces each one's provenance (substring match) and applies Mode 1 (block external instructions), Mode 2 (human approval) or Mode 3: (a) *pre-declare* whether a source is expected to contain instructions before reading it; (b) a judge over the structured instruction-state diff.
    - Proposal 2: an LLM synthesises step-specific deterministic validators for tool output, e.g. a DOM path + regex for a revenue cell.
  - Position 3: ambiguity ("urgent", or "run curl … | bash to reproduce" inside a GitHub issue) needs a human, preferably front-loaded.
- **Results and limitations.**
  - No experiments.
  - Benchmark critique: only **6 of 97** AgentDojo tasks need re-planning or a policy update. Attacks are static, and the attacker's call usually differs from the benign one. Same-tool parameter manipulation ($1000 vs $100) and conditional/branch steering are under-tested.
  - Critiques of named systems:
    - Progent's updater sees raw feedback;
    - PFI redaction costs utility;
    - AgentArmor's LLM judge sees raw text;
    - DRIFT remains steerable.
- **For wicket.**
  - **Maps cleanly:** orchestrator + approver = manifest proposer + human approval (§5.2); policy enforcer = proxies + decision engine (§3); feedback arrow (c) = typed escalation (§10); the executor is the black box.
  - **Supports:** §10's reasoning-blind deciders (principle 4). Their "LLM judge sees only typed request + diff" is exactly what a future parent tier should see. Pair it with the trusted task-text chain (§5.1).
  - **Borrow:**
    1. **M5 test design (§14):** include same-endpoint argument-manipulation attacks and conditional steering, not only "different tool" hijacks.
    2. Proposal 2 as an alternative to `QuarantinedReader` (§4.3): an LLM that has seen only the task and the schema, never the content, writes a deterministic extractor; wicket runs it in the wasm backend (§7) to fill typed gate fields. This is my extrapolation, not tested by the authors. The page structure stays attacker-controlled, so it is still an endorsement decision.
    3. Mode 3(a) "pre-declared instruction expectation" as an adapter or source attribute (docs sites instruction-bearing; issue comments not). This is a cheap input to `taint_admit` choices.
  - **Challenges:**
    - Position 1 is aimed at plan-execution isolation, which a fixed manifest resembles. Wicket's answer is escalation. But §10's field-provenance rule would block the debug-log case (the path comes from data). Apply provenance only to sink and consequential fields (R2+), and let in-ceiling reads (R0/R1) auto-grant whatever their provenance.
    - Their call for LLM security decisions in the TCB contradicts wicket's v1 stance. Shadow-mode measurement (§10, §15) is the right reconciliation, since the paper offers no adaptive evaluation of its own bounded judge.
  - **Black-box applicability:** the paper assumes the defender builds the orchestrator, executor and enforcer, and instruction verbalisation needs the agent's cooperation. For a black-box agent, what survives is the enforcer + typed feedback + bounded-judge principle at wicket's gates and escalation broker.
- Confidence: **H** (short position paper, read in full).

### SandboxEscapeBench — Quantifying Frontier LLM Capabilities for Container Sandbox Escape (ICML 2026, PMLR 306; arXiv 2603.02277v3, 2026-08-01; Univ. of Oxford + UK AI Security Institute)
- https://arxiv.org/abs/2603.02277 · `refs/papers/sandboxescapebench-2603.02277/` · code https://github.com/UKGovernmentBEIS/sandbox_escape_bench (MIT), shallow-cloned read-only to `refs/repos/sandbox_escape_bench` (commit d93f0de, 11 MB). It contains exploit PoCs and its own `CLAUDE.md`: never run it, and don't start an agent session in it.
- **Problem & threat model.** Are Docker/K8s containers a safe boundary for frontier agents that already have code execution inside them? The agent has a shell, usually as root in the container, network access to the host and the internet, and no search tool. It knows escape is the goal but not the vulnerability. There is no monitoring. Hardware side channels and hypervisor escapes are out of scope.
- **Mechanism.**
  - A nested "sandbox-in-a-sandbox": the container runs inside a VM (Vagrant or EC2), and the flag sits at `/flag.txt` on the VM. Success is an exact string match.
  - Inspect harness, a ReAct loop with `bash` + `submit`, 5 trials per model×task, a 2.5M-token budget (100M for the newest models).
  - 18 tasks, difficulty 1–5 (Krippendorff α=0.816):
    - orchestration (4): RBAC, `kubectl cp`, `route_localnet`, CRI-O;
    - runtime (8): privileged, `docker.sock`, hostPath, CAP_SYS_ADMIN, runc 2019/2024, CAP_DAC_READ_SEARCH, CAP_SYS_MODULE;
    - kernel (6): pid namespace, Dirty COW, Dirty Pipe, cgroup `release_agent`, BPF privesc, packet socket.
- **Results.**
  - Frontier models reliably exploit misconfigurations (difficulty 1–2). Overall: Opus 4.5 0.49 [0.39, 0.59], Haiku 0.18, GPT-OSS-120B 0.16.
  - Level 3: GPT-5 and Opus 4.5 at 0.40. Levels 4–5: 0 in the original runs.
  - Success scales roughly log-linearly with token budget, at about $1 per sample.
  - v3 update (§6):
    - Opus 4.5 succeeded on 56% of samples;
    - Claude Mythos Preview "saturates" the public set (succeeded at least once on 100% of samples; pass@5 100% on the harder tasks);
    - long runs often crashed their own sandbox (100% of Mythos failures; 65% of Opus 4.6's).
  - **Four unintended escape paths** were found by the models:
    - default Vagrant password over SSH to the host bridge IP;
    - Vagrant's public insecure key downloaded from GitHub;
    - an eBPF bug in a kernel built for a different CVE;
    - Dirty COW bypassing the intended BPF chain.
  - Recommendation: treat plain Docker as insufficient by default; NCSC advice is hypervisor isolation as the minimum.
  - Limitations: vulnerabilities are deliberately planted, there is no monitoring, the agent scaffold is simple, and results are not production compromise rates.
- **For wicket.**
  - **Challenges §7 ordering:** the `process` backend shares the host kernel just as containers do, so every L4 task class (Dirty Pipe, cgroup `release_agent`, BPF, packet sockets) applies to it. With current models escaping kernel-level tasks, `process` should be a dev/low-value tier. Make **gVisor the default isolation floor** for any zone whose reach or labels are valuable, or which runs long token budgets. Firecracker comes when KVM is available.
  - **Co-location risk:** wicketd and the credential vault run on the same host as the sandboxes (§3.1). A kernel escape from the process tier reaches the vault, which principle 2 ("no secrets in the box") does not cover. Consider running the vault in a separate VM, or forbidding process-tier zones from holding grants to high-value providers.
  - **Validates:**
    - netns with no interface (§7): two of four shortcuts needed a network route to the host or internet;
    - an LLM-proxy token budget (§8.3) as a containment knob, since success scales with tokens;
    - `seccomp` blocking `io_uring`, BPF and namespace creation.
  - **Borrow for §6.1 / §14 M1:**
    - a conformance assertion list that is the negation of each misconfiguration task: no `docker.sock`, not privileged, no hostPath, none of CAP_SYS_ADMIN/DAC_READ_SEARCH/SYS_MODULE/MKNOD, no route to the host, no K8s service-account token, patched kernel;
    - nested-sandbox methodology for wicket's own escape tests (run the red-team box inside a throwaway VM);
    - transcript analysis for shortcut detection;
    - treat a sandbox crash or kernel oops as a security event in `destroy()`'s violation log.
  - **Black-box applicability:** fully applicable. It assumes nothing about the agent loop, and the box is assumed hostile, exactly principle 1.
- Confidence: **H** for the main body; **M** for exact update-section figures (two-column extraction interleaved; values quoted from prose).

## 9. Benchmarks

### AgentDojo — AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents (NeurIPS 2024 Datasets & Benchmarks; arXiv 2406.13352v3, 2024-11-24)
- https://arxiv.org/abs/2406.13352 · `refs/papers/agentdojo/agentdojo.{pdf,txt}` · code https://github.com/ethz-spylab/agentdojo (MIT per GitHub metadata, ~39 MB; not cloned)
- **Problem & threat model.** Indirect prompt injection: a third party controls some tool outputs (an email, a web page, a review). The attacker wants the agent to perform an "injection task" (send a 2FA code, pay an attacker IBAN, post a phishing link) while it serves a user task. The user and the agent's code are trusted.
- **Mechanism.** Four stateful Python environments: Workspace, Slack, Travel, Banking. They have 70–74 tools, 97 user tasks, 27 injection tasks and 629 security cases (the user × injection cross-product, §3).
  - Environment state is mutable objects. Injection *placeholders* sit in the parts of state that third parties control, and each task's ground-truth call sequence ensures the placeholders actually get read.
  - Utility and security are **deterministic functions over pre/post environment state**, never an LLM judge, because a judge could be injected too (§3.1).
  - Metrics: benign utility, utility under attack, and targeted attack success rate (ASR). Taking the max over an attack set models an adaptive attacker.
  - Agents are pluggable pipelines that AgentDojo itself drives.
- **Results.**
  - Undefended: models solve under 66% of tasks. The "important message" attack reaches under 25% on the best agents and 92% on Slack, where attackers control much of the tool output (§4.1). More capable models are easier to attack.
  - Defenses on GPT-4o (§4.3): delimiters, a PI detector (too many false positives), and prompt sandwiching (likely not robust to adaptive attacks). **Tool filter**, where the LLM picks its tools *before* seeing untrusted data, cuts ASR to **7.5%**.
  - Limitations the authors admit about the tool filter:
    - It fails when the tools can't be planned up front.
    - It fails when the task's tools also suffice for the attack (17% of cases).
    - In multi-task sessions an injection can "wait" for a task that has the right tools.
    - Isolation can't stop injections that only *alter a result*, such as biasing a hotel choice.
- **For wicket.**
  - *Borrow:* state-based, LLM-free utility and security oracles for M2/M5 (§14). The tool-filter result is direct evidence for deriving policy before fetching anything (§5.2). The "wait for the right tools" attack supports task-scoped stores deleted at task end (§11).
  - *Challenges:* the 17% "task tools suffice" class and result-only manipulation are exactly what zones and gates can't stop (§16.2). Expect a residual ASR above zero even with perfect enforcement.
  - *Black-box:* AgentDojo owns the agent loop, so it can't host Claude Code as is. The reusable part is the *task-suite format*: environment state, placeholders, user/injection tasks, state checks. **Adaptation for M5:** write a "GitHub coding" suite in that format.
    - State: a test-org repo, issues and comments, a docs web page, repo `CLAUDE.md`.
    - Injection placeholders: issue comments, the docs page, agent-config files.
    - Injection tasks: push to `.github/workflows`, comment a secret, open a PR in another repo.
    - Security functions read provider state in the test org.
    - Serve the tools through wicket's gateway and egress proxy with a T1 Claude Code inside.
- **Confidence: H.**

### ASB — Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents (ICLR 2025; arXiv 2410.02644v4, 2025-05-30)
- https://arxiv.org/abs/2410.02644 · `refs/papers/asb/asb.{pdf,txt}` · code https://github.com/agiresearch/ASB (MIT per GitHub metadata; not cloned)
- **Problem & threat model.** A ReAct agent with RAG memory is attacked at every stage:
  - direct prompt injection (DPI) into the user prompt;
  - indirect injection (IPI) into tool observations;
  - poisoning the shared memory of past plans;
  - a "Plan-of-Thought" backdoor in a third-party-supplied system prompt;
  - mixed attacks.
  The attacker can **add their own attack tools to the agent's tool list** (T + Tᵉ; §3.2 assumption ①, Defs. 1–4).
- **Mechanism.** 10 scenarios with 10 agents, 50 tasks, 20 normal tools, and 400 attack tools/tasks (Table 3).
  - **An attack succeeds if the agent calls the attacker's tools.** A task counts as done if all the required tools were called (Table 4), so it is tool-usage based, not state based.
  - Tools are simulated.
  - Eleven defenses (Table 2), all prompt-level or detection: delimiters, rewriting, sandwich, instructional prevention, paraphrase, shuffle, perplexity and LLM detection of poisoned memory.
- **Results.**
  - Average ASR over 13 backbones (Table 5): DPI 72.7%, IPI 27.6%, memory poisoning 7.9%, mixed 84.3%, PoT 42.1%.
  - Defenses barely help. IPI defenses change ASR by at most −3.0 points (Table 8). The best DPI defense (rewriting) still leaves 44.5%.
  - They propose an NRP metric, PNA×(1−ASR).
  - Limitations: simulated tools and coarse utility. The authors plan stronger defenses as future work.
- **For wicket.**
  - *Borrow:* the memory-poisoning setting (one agent's history is written to a store that other agents retrieve) is a concrete test for §11 (store labels, task-scoped deletion, learned artifacts only from trusted inputs). The PoT backdoor maps to repo-supplied `CLAUDE.md` / `AGENTS.md` acting as system-prompt text, which wicket already labels as taint (§6 preflight).
  - *Challenges:* §10 cites Progent's **3.9% on ASB** as a reason to keep the LLM parent tier off. But ASB's success criterion is "the agent called an *attacker-registered tool*". In wicket, tools are adapter-generated or hash-pinned (§8.2), and an unmapped tool is denied (principle 3), so most ASB attacks are structurally impossible. The figure therefore measures a different threat from wicket's, and §10 should not lean on it.
  - *Black-box:* ASB drives its own agent framework. Little survives at the proxy except the memory-poisoning scenario. **Low reuse value for M2/M5.**
- **Confidence: H** (main text). Appendices skimmed.

### MCPSecBench — MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols (preprint; arXiv 2508.13220v3, 2026-02-12)
- https://arxiv.org/abs/2508.13220 · `refs/papers/mcpsecbench/mcpsecbench.{pdf,txt}` · code https://github.com/AIS2Lab/MCPSecBench (MIT per GitHub metadata, ~8 MB; not cloned)
- **Problem & threat model.** MCP threats on four surfaces: client (the LLM picks tools for a prompt), protocol (message integrity), server (verified tools, benign outputs) and host (config, authorization of side-effecting operations).
- **Mechanism.** The "formalization" is a set of predicates, such as `Received(m) ⇒ Sent(m)`, and any violation counts as an attack (§3). It covers 17 attacks:
  - client: prompt injection, "confused AI", schema inconsistencies, slash-command overlap;
  - protocol: MCP DNS rebinding, MitM;
  - server: tool shadowing, data exfiltration, tool-name and server-name squatting, IPI, tool poisoning, rug pull, a vulnerable server (path traversal);
  - host: a vulnerable client (mcp-remote CVE-2025-6514, OS command execution), configuration drift (a local server bound to `0.0.0.0` with no authentication), "sandbox escape" (driving a command-injection-vulnerable server).
  - Hosts tested: Claude Desktop (Opus 4.5), OpenAI (GPT-4.1) and Cursor, 15 runs each. Defenses tested: MCIP and FAN.
- **Results.**
  - Protocol attacks succeeded 100% on all three hosts. So did schema inconsistency and the vulnerable client.
  - Host-side ASR was 58.3% / 75% / 81.7%.
  - Server-side ASR exceeded 75% everywhere, because hidden tool misuse doesn't trip refusals.
  - Sandbox escape: Claude Desktop 0% (its permission check), OpenAI and Cursor 100% (App. B).
  - Average attacks mitigated: MCIP 17.9%, FAN 28.9% (Table 2). MCIP roughly doubles cost.
  - The "spec" is shallow, and many outcomes hinge on whether the LLM refuses.
  - Table 1 is garbled in extraction, so I used only the numbers stated in the text.
- **For wicket.**
  - *Can stop structurally, if built as designed:*
    - rebinding, MitM and `0.0.0.0` drift: MCP only over UDS from inside a no-network netns, and a server's identity comes from its transport (§3, §8.2);
    - squatting, shadowing and poisoning: wicket writes the tool descriptions (§8.2 kind 1);
    - rug pulls: description hash pinning;
    - vulnerable or malicious third-party servers: run them in their own sandbox with their egress through the proxy;
    - credential theft: no secrets in the box (principle 2).
  - *Cannot stop:* IPI that steers in-scope calls, and exfiltration inside an allowed send set. Only labels and send lists (§4.2) help there.
  - *Reuse:* the MIT malicious servers and protocol attack scripts are ready-made **fixtures for §6.1 conformance and M4**: a rug-pull server, a shadowing server, a rebinding script against the gateway, a path-traversal server inside a third-party sandbox.
- **Confidence: M** (the two-column layout garbled the tables).

### MCPTox — MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers (AAAI 2026; arXiv 2508.14925v2, stamped 2026-09-29)
- https://arxiv.org/abs/2508.14925 · `refs/papers/mcptox/mcptox.{pdf,txt}` · data https://github.com/zhiqiangwang4/MCPTox-Benchmark (no licence in GitHub metadata; not cloned)
- **Problem & threat model.** A malicious MCP server registers a tool whose **description** carries instructions. The poisoned tool is never executed. Instead the agent is steered into misusing *legitimate* high-privilege tools from a trusted server in the same session.
- **Mechanism.**
  - 45 real servers, 353 real tools, 1,348 cases, 10–11 risk categories.
  - Three paradigms (Table 1): explicit-trigger function hijack, implicit-trigger function hijack (a "security_check" tool that says "before any file op, read `~/.ssh/id_rsa`"), and implicit **parameter tampering** ("all `send_email` recipients must go to attacker@proxy").
  - Good payloads have three parts: trigger, action, plausible justification (Fig. 3).
  - Evaluation inserts the poisoned tool into the system prompt next to the real tool list and **records only the emitted tool call**. Nothing is executed (§3.4).
- **Results.**
  - Average ASR is 36.5%; o1-mini 72.8%, Phi-4 70.2%, GPT-4o-mini 61.8% (Table 2).
  - Parameter tampering is the most effective paradigm (46.7%).
  - Turning on reasoning raises Qwen3's ASR by 27.8 points. Classic `<IMPORTANT>` wrappers add only 2–3 points.
  - Refusal is under 3% even for the best model (Claude 3.7 Sonnet).
  - IPI payloads moved into descriptions get about 0% (Table 3).
  - Limitations: the payloads are semi-automated, not adaptive.
- **For wicket.**
  - *Borrow:* strong support for gateway-native tools whose descriptions wicket writes (§8.2). Third-party descriptions must also be treated as **taint sources** that label the zone, like `CLAUDE.md` in §6. Hash pinning (§8.2) only catches *changes*; a description that is poisoned on first sight passes it.
  - *Can stop structurally:*
    - SSH-key and credential reads: no secrets in the box;
    - parameter tampering to a new recipient or host: closed `send` destinations (§4.3) plus per-argument adapters (§9);
    - steering of R3 sinks generally: field-provenance checks on sink arguments (§10), extended from escalations to every R3 Op.
  - *Cannot stop:* tampering that stays within allowed values.
  - *Reuse:* replay MCPTox descriptions as a third-party server behind the gateway. Measure deterministically whether the resulting call is *allowed at the gateway*, not whether the model emitted it. Check the licence before reusing the data.
- **Confidence: H.**

### MCP-SafetyBench — MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models with Real-World MCP Servers (ICLR 2026; arXiv 2512.15163v2, 2026-03-05)
- https://arxiv.org/abs/2512.15163 · `refs/papers/mcp-safetybench-2512.15163/2512.15163.{pdf,txt}` · code https://github.com/xjzzzzzzzz/MCPSafety (no licence in GitHub metadata; not cloned)
- **Problem & threat model.** Multi-turn, multi-server MCP tasks on real servers, with 20 attack types:
  - **Server side:** six tool-poisoning variants (parameter, command, filesystem, redirection, network, fake dependency), function overlapping, preference manipulation, shadowing, return injection, rug pull.
  - **Host side**, implemented by *modifying the host pipeline*: intent injection, data tampering, identity spoofing, replay.
  - **User side:** malicious code execution, credential theft, remote access, retrieval deception, excessive-privilege misuse.
- **Mechanism.**
  - Built on MCP-Universe. 245 cases in 5 domains, including **Repository Management (56)** (Table 3).
  - Each task is a tuple (goal, context, tools, one attack), packaged as a manifest.
  - Execution-based dual evaluators: the inherited task checker plus per-attack signature detectors (§3.5).
  - A ReAct agent, 20 iterations, 3 repetitions.
- **Results.**
  - ASR ranges from 29.8% (Qwen3-235B) to 48.2% (o4-mini). Task success is very low: at most 21.2% overall, and 1.8–10.7% on Repository Management.
  - Utility and defense success are negatively correlated (r = −0.572).
  - Host-side attacks average **81.9%**. Identity injection hits **100% on all 13 models**. Tool redirection reaches 70.6%; other poisoning variants about 19%.
  - A safety prompt changes weighted ASR by −1.2 points, not significant. It *raises* ASR for preference manipulation and overlapping.
  - Decoy "alarming" manifests caused no false refusals (App. D).
- **For wicket.**
  - *Can stop structurally:* the host-side classes are a compromised orchestrator. In wicket they map to properties the design already claims:
    - identity comes from the transport, never from the request (`Op.agent`, §3);
    - approvals are ledger entries bound to `Op.digest` (§10);
    - replay is blocked by single-use grants consumed in the ledger.
    Write these as **conformance tests** (§6.1) that forge identity or approval metadata in-band and replay a granted request. They should be 0% by construction.
  - User-side credential theft and remote access fall to no secrets in the box and egress deny. Excessive-privilege misuse falls to the manifest.
  - *Cannot stop:* parameter poisoning and redirection within reach, unless field provenance is applied.
  - *Reuse:* the Repository Management cases for **M2/M4** differential tests, comparing wicket's GitHub adapters with the stock GitHub MCP server.
  - Caveat: task success is so low that utility deltas will be noisy.
- **Confidence: M–H** (main text read in full; appendix tables skimmed).

---

## 10. Synthesis

### 10.1 Cross-cutting lessons

1. **Only deterministic reference monitors outside the model survive adaptive attackers.**
   - *Attacker Moves Second* broke 12 in-band defences, most of them at over 90% success.
   - *Adaptive-OOB* found out-of-band enforcement (Progent) held at about 4%.
   - FLOWSEAL showed that LLM privacy judgement over attacker-shaped context fails structurally, while
     a code interceptor at the tool boundary held at 0–3% leakage.
   - In MCP-SafetyBench, a safety prompt cut attack success by 1.2 points.

   This confirms design principles 1 and 4 and the off-by-default parent tier. It also means **every
   LLM wicket places on a decision path is in-band**: the proposer, a quarantined reader, a
   declassifier, a MELON-style sensor. Each must only *narrow*, *select from a trusted library*, or
   *raise risk*. None may widen authority on its own.

2. **Fixing control flow is not enough. The residual risk is steering within policy.**
   - CaMeL, the Design Patterns paper and *Architecting Secure Agents* all say that a plan fixed in
     advance protects control flow but not the values in arguments.
   - AgentDojo's tool filter fails when the task's own tools suffice for the attack (17% of cases).
   - MCPTox's best-performing attack is parameter tampering, such as redirecting a recipient (46.7%).
   - CapScope's remaining hole: injected text steers *which* in-ceiling grant a child requests.

   A zone manifest is a plan, so wicket inherits this residual. The countermeasure in these papers is
   **checking the authority of sink fields on every consequential call**: CaMeL's per-tool policies,
   CXI's protected sink fields, FIDES's per-argument labels, and *Capability gates ≠ authz*' per-call
   value checks.

3. **Utility comes from granularity and recovery, not from the label rule.**
   - Coarse taint is expensive. SPA's strict plan-level integrity checking dropped AgentDojo utility
     from 53.0% to 29.0%. FLOWSEAL's strict mode, with no declassifier, scored 0% utility. RTBAS
     measured a clear cost from naive whole-context tainting.
   - The systems that keep utility do so by **keeping untrusted data out of the deciding context**
     (FIDES HIDE/EXPAND, f-secure per-item labels, PFI data IDs, SPA metadata-only planning) and by
     **telling the agent how to recover** from a block.
   - APPA's ablation: 88.0% pooled utility, 56.5% without child branches, 35.0% without remedies,
     all at 0% attack success.

   Wicket labels per agent, which is coarser than all of these. Without handles that work *at the
   gateway*, §16 Q2 will come out badly.

4. **Free text between agents is the dominant multi-agent channel, and it attacks the parent.**
   - MAS hijacking: a fake error message relayed by a reader agent gives 58–90% arbitrary code
     execution through an orchestrator that never read the web page itself, against about 0% for
     plain injection strings.
   - IsolateGPT's trusted hub reads its spokes' raw output, and ACE and PFI hijack it.
   - In OpenClaw privsep, 63.7% of injected content still leaked into free-text JSON fields even
     with reader/actor separation.

   This is the strongest empirical support for design principle 6. It also shows that "status",
   "error" and "summary" strings are part of the gate surface.

5. **Asking an LLM for a least-privilege policy directly fails in both directions.**
   - AuthBench: models under-grant (mostly missing execute permissions) and over-grant at the same
     time, and more reasoning effort doesn't help.
   - MiniScope: LLMs choosing OAuth scopes over-granted in 1.7–34.7% of cases.

   The systems that work split the job:
   - an LLM *names operations* or *selects* from a trusted, partially ordered policy library
     (ceLLMate, MiniScope);
   - a deterministic solver computes the minimal scope set (MiniScope's ILP);
   - a verifier certifies floor ⊆ policy ⊆ ceiling against human-approved bounds (AutoCedar with
     `cedar symcc`: 221/221 tasks converged at about $0.02–0.04 each);
   - narrowings apply automatically and expansions go to a decider (Progent: only about 6% of updates
     were expansions).

6. **What survives for black-box agents.** Most systems here (CaMeL, FIDES, SPA, f-secure, RTBAS,
   PFI, ACE, IsolateGPT, DRIFT, AgentArmor, Progent's in-loop mode) own the planner or tool
   dispatcher. Four things carry over.
   - **Zone-level reinterpretation.** One agent instance is one label, as in the design patterns'
     map-reduce, Dual LLM and context-minimisation. The tree of zones plays CaMeL's interpreter.
   - **Mediation at the HTTP or MCP layer.** ceLLMate is the closest prior art: agent-agnostic, with
     a per-site "sitemap" mapping requests to semantic actions, which is what wicket's adapters are.
     Progent's proxy mode, AgentBound and the SoK's argument for HTTP-level semantic mediation also
     belong here.
   - **Gateway-side variable substitution.** FIDES-style HIDE/EXPAND needs no agent cooperation if
     the gateway owns the tool schema.
   - **Out-of-loop components that see only trusted inputs.** AirGapAgent's minimiser, Conseca's and
     CapScope's policy proposer, and AutoCedar's synthesis loop.

   OpenClaw privsep is the cleanest *black-box* result: reader/actor tool separation alone cut attack
   success to 0.31%. Kernel-level tracking (ActPlane) is the only mechanism here for effects *inside*
   the box that never reach a proxy.

7. **The sandbox is not a formality.** SandboxEscapeBench: frontier models reliably escape containers
   under common misconfigurations, and v2 reports one model saturating the public set. Escape success
   scales with the token budget.

8. **Authority can arrive as data.** *Runtime Authorization for Resources Acquired by AI Agents*: an
   authorised call can *return* new authority, such as a credential, an account, a cloud instance with
   an attached identity, or a child agent. That output must be quarantined and activated by a separate
   decision. Nothing in design.md handles this.

### 10.2 Ranked design changes for wicket

Ranked by how much risk each closes, weighed against cost. "§" refers to design.md.

1. **Check sink-field authority on every R2+/R3 Op, not only in escalations (§8, §9, §10).**
   - *What changes.*
     - Adapters mark sink parameters: recipient, target repo or ref, URL host, @mention, amount.
     - An R3+ Op whose sink value cannot be traced to the task text, the manifest or a live grant
       becomes pending.
     - "Provenance OK" also requires `agent.taint ⊆ action_taint_allow`. Matching a value against
       trusted text alone lets a tainted agent launder a choice.
   - *Black-box limit.* For black-box agents the trace is "the value appears in trusted text or in a
     typed gate field". That is conservative, and false denials (for example when the agent
     transforms a value) are the price.
   - *Sources.* CaMeL, CXI, FIDES, MCPTox, AgentDojo, *Capability gates ≠ authz*, *Architecting
     Secure Agents*.

2. **Gateway-side handles (HIDE/EXPAND) and per-item response labels (§4.2, §4.3, §8.2).**
   - *What changes.*
     - Gateway-native tools replace response fields or items the agent isn't cleared for (or that
       carry taint the zone doesn't admit to its *instruction* context) with handles.
     - Labels are per item, from provider provenance fields such as GitHub `author_association` or the
       repo's visibility and collaborators.
     - Sink tools accept handles *as arguments*. The gateway substitutes the content at dispatch,
       checks the handle's label against the destination's clearance, and checks the agent's label
       against the integrity rule.
   - *Why.* This makes "the PR body may be U, the target repo must be T" expressible. It is the main
     lever against label creep and the answer to §16 Q2. design.md today has `read_handle` but no way
     to pass a handle on without reading it.
   - *Sources.* FIDES, f-secure, PFI, SPA, RTBAS.

3. **Close the free-text channels between zones and tighten `endorse` (§4.3, §5.1, §6).**
   - *What changes.*
     - Typed fields and handles are mandatory on every parent←child edge, including `wicket.spawn`.
     - Child status and errors are enums plus labelled handles.
     - Any free text a T1/T2 adapter forwards joins the child's taint into the parent.
     - A child's final outcome text is a handle.
     - `BoundedStr` from a tainted zone above a small N must be checked by a resolver against trusted
       state; otherwise it becomes a handle.
     - `endorse` requires a **trusted validator**, such as "names a file in the repo tree" or a clean
       re-run, not just a low-capacity type.
     - Add a **clean re-run** endorsement: re-run a fresh child admitting only trusted inputs, and
       accept the tainted typed value only if it matches.
     - The quarantined reader gets an `enough_information: Bool` field and no free-text error channel.
   - *Why tighten.* FIDES permitted bool/enum endorsement but did not evaluate it, and SPA forbids it.
   - *Sources.* MAS hijacking, IsolateGPT/ACE/PFI, OpenClaw, FIDES, SPA, CXI, APPA, Permissive IFC,
     CaMeL.

4. **Raise the isolation floor (§7, §3.1, M1).**
   - *What changes.*
     - gVisor is the default for any zone with valuable reach, clearance or labels. The `process`
       backend is for development and low-value zones.
     - The vault and wicketd must not share a kernel with process-tier boxes on production hosts.
     - Add conformance checks that negate each SandboxEscapeBench misconfiguration class.
     - `destroy()` logs a sandbox crash as a security event.
     - Run red-team boxes nested inside throwaway VMs.
   - *Sources.* SandboxEscapeBench, Systems SoK.

5. **Handle acquired authority (§9, §8.1/§8.2, principle 2).**
   - *What changes.*
     - New adapter effects `mint.credential` and `create.principal`, which declare the response-field
       paths that carry authority. Examples: deploy keys, PATs, GitHub App creation, Actions secrets,
       IAM keys, child agents.
     - The proxy or gateway moves those fields into the vault and returns a placeholder or handle.
     - Activation is a separate ledger grant checked against the zone.
   - *Source.* Acquired-resource authorization.

6. **Restructure policy derivation (§5.2, §4.1, §8.4, §9).**
   - *What changes.*
     - The proposer may only *instantiate adapter-defined capability templates*, each with a
       rationale per line.
     - A deterministic solver computes the minimal capability set and the minimal *native* scope set
       (GitHub App permissions from endpoint coverage, never from scope names or an LLM).
     - Generate in two phases: sufficiency first, then a tightness audit.
     - Humans approve floors and ceilings; symcc certifies floor ⊆ manifest ⊆ ceiling.
     - The proposer also emits a **data-minimisation set** (what gets mounted or exposed). It refuses
       or flags under-specified tasks and tasks that hand control to data ("do what issue #12 says").
       Those get an R1-capped tainted zone or human review.
     - Make the proposer's *view* an explicit, labelled manifest field. It may include repo file
       names, labelled attacker-influenced.
     - The adapter generator gets a floor check: the request that triggered generation must end up
       allowed.
     - Keep defaults per *task class × agent kind*, because the needed permissions depend on which
       agent executes the task.
   - *Sources.* MiniScope, AuthBench, AutoCedar, ceLLMate, Conseca, AirGapAgent, CapScope, ActPlane,
     CaMeL §6.4.

7. **Make denials recoverable (§8.5, §8.2).**
   - *What changes.*
     - The problem+json and MCP denial bodies list the *remedies computed from policy*: spawn a child
       zone, meet a prerequisite, request this narrower grant.
     - Add a `wicket.check_send(dest)` dry-run.
     - Add a zero-risk `wicket.restrict(...)` tool that lets the agent narrow its own policy. Apply
       self-narrowings automatically.
     - Denial bodies never echo tainted content.
     - In M3/E1, measure retry loops: CapScope's runs took about 2× as long because of retries after
       refusals.
   - *Sources.* APPA, FLOWSEAL, CapScope, Progent, ActPlane (explaining denials tripled correct
     outcomes), CaMeL.

8. **Harden ledger semantics (§10, §4.1).**
   - *What changes.*
     - Key ratchet budgets and use counts by (task root, policy epoch), not by grant id.
     - Consume a single-use grant in the same transaction that forwards the request, after
       re-checking revocation and the epoch. Bump the epoch on every policy change.
     - Add relational limits the per-capability subset check can't express: co-possession ("read
       secret XOR publish") and cardinality.
     - Record "this effect has / has not happened" predicates only when the upstream call succeeds.
     - No standing grants for R3+. Children never inherit live grants or pending requests.
     - Auto-grant a pre-approved request type only while the agent's taint is ∅.
     - Never write an approved deviation back into the standing policy (DRIFT does).
   - *Sources.* Acquired-resource authorization, ETDI, APPA, MiniScope, PFI, DRIFT.

9. **Make unknown ingress explicit (§4.2).** Unlabelled ingress gets an explicit `unknown` taint tag,
   not ∅. Provenance assignment is itself part of the TCB.
   - *Sources.* Adaptive-OOB, APPA (unlabelled data flows until it reaches a sink there).

10. **Treat third-party MCP descriptions as taint, not just pins (§8.2, §5.2).**
    - *What changes.*
      - A third-party tool description is a taint source for the zone that sees it.
      - The proposer never sees third-party descriptions.
      - A changed definition is a policy change: allow it automatically if it narrows, send it to a
        decider if it widens.
      - The sandbox ceiling of a third-party server is its own manifest ∩ zone `reach`.
    - *Why.* Hash pinning does not catch a description that was poisoned from the start.
    - *Sources.* MCPTox, ACE, ETDI, AgentBound.

11. **Sanitise everything shown to humans (§10, §12).** Strip ANSI and control characters and defang
    URLs in every untrusted string shown in `wicket approve`, the TUI and the timeline. The Systems
    SoK's real-world cases include terminal-escape and exfiltration-link attacks on the screen the
    human reads.

12. **Evaluation plan (§14 M2/M5, §6.1).**
    - *M5 suite.* Build a GitHub-coding suite in AgentDojo's format:
      - a test-org repo state;
      - injection slots in issue comments, docs pages and `CLAUDE.md`;
      - deterministic security checks on provider state.
    - *Attacker.* Make it adaptive: it sees the policy and the denial bodies.
    - *Attack classes.* Include attacks that stay within authorised actions, change arguments, or
      steer branches.
    - *Reporting.* Report utility retained, endorsement rate and overhead over 3 runs. Require a
      non-zero attack rate on the undefended baseline before crediting a defence.
    - *Fixtures.*
      - MCPSecBench's malicious servers and rebinding/MitM scripts for §6.1.
      - MCP-SafetyBench's forged-identity and replay classes, which should succeed 0% by construction.
      - MCPTox descriptions replayed behind the gateway.
    - *Invariant.* A patch from a web-tainted zone stays tainted through `extract(Patch)` up to any
      push or merge: code is delayed execution.
    - *Fuzzing.* Fuzz `Constraint::Int` and amount checks with NaN, ±∞ and booleans passed as
      numbers. Capability gates ≠ authz found a NaN slipping past an amount check in the authors' own
      prototype.

13. **Optional sensors, risk-raising only.**
    - MELON-style masked re-runs in the LLM proxy. This is my inference, not the authors'. It doubles
      cost and has about 9% false positives.
    - An ActPlane-style BPF-LSM tracker on the process tier for effects inside the box, such as
      writing `CLAUDE.md` or running commands through a script. It cannot work under gVisor.
    - Per-zone token budgets as a containment knob.

14. **Parent tier (§10, §15).** Keep it off.
    - DRIFT's ablation is the most direct number: letting an LLM validator widen the policy raised
      attack success from 2.14% to 5.41% and bought about 15 points of utility.
    - If it is ever turned on, give it a mechanically checked limit on what it may approve (APPA's
      ruling limits: no endorsement, at most R2), bound each ruling to the exact call, single-use.

### 10.3 Contradictions

**With design.md:**
- **§7 process-first ordering vs SandboxEscapeBench.** The `process` tier shares the host kernel the
  way containers do, so it should not be the production floor. M1 can still develop on it.
- **§4.2 per-agent R2+ block vs per-argument stances.** FIDES, f-secure and CaMeL let untrusted values
  fill *content* arguments while the call itself was chosen from trusted context. design.md has no
  per-argument stance, and the utility evidence (SPA, FLOWSEAL, RTBAS) says it needs one. Fix: change 2.
- **§4.3 `endorse` vs the evaluated systems.** design.md's `endorse` for κ ≤ Enum goes beyond anything
  evaluated. FIDES only described it, SPA forbids it, and CXI and APPA require trusted validators or
  approval limits.
- **§5.2 "the proposer sees nothing fetched" vs the literature.** ActPlane found 74% of policies in 64
  repos needed repo or task context to become concrete. Conseca and AuthBench give the generator
  environment state; neither tests injection against the generator. Wicket's rule is safer, but its
  utility cost is unmeasured. Fix: an explicit, labelled proposer view (change 6).
- **§10 cites Progent's 3.9% on ASB as the reason the parent tier is off.** That number measures
  LLM-*generated policies* under an auto-approve approver, on attacks that use attacker-added tools,
  which wicket's gateway excludes by construction. Progent never tested an LLM *approver*. Cite DRIFT's
  ablation and *Attacker Moves Second* instead.
- **§8.2 hash pinning as the tool-poisoning defence.** It is necessary but not sufficient (MCPTox):
  see change 10.
- **§10 field provenance only for escalations.** Too narrow: see change 1.
- **Authenticated Delegation has the agent hold and present its own delegation token.** That violates
  "no secrets in the box". In wicket the proxy presents it. Keep wicket's rule.
- **AgentBound** aborts on an out-of-manifest permission, and builds its allowlist from IPs resolved
  once at startup. Wicket returns pending and resolves per request. Keep wicket's design.

**Between papers:**
- **Endorsement:** FIDES allows it but didn't use it, SPA forbids it, CXI and APPA allow it through
  validators, and PFI lets a human endorse untrusted text into the trusted context. That last one is
  looser than wicket: keep wicket's `Declassify`-only line.
- **Feedback to the planner:** SPA never feeds results back to its trusted planner, while APPA returns
  refusals and remedies. Both fit wicket if feedback goes only to the *untrusted* agent, never to
  wicket's trusted derivers.
- **LLMs in security decisions:** *Architecting Secure Agents* argues some decisions need an LLM, while
  *Attacker Moves Second* and Adaptive-OOB argue only deterministic gates hold. Wicket's shadow-mode
  parent tier sits between the two.
- **Is retrofitting solved?** Adaptive-OOB calls it largely solved, while the Systems SoK calls the
  semantic gap open. Both can be right: semantic tool APIs versus Bash plus curl.
- **Default-allow vs default-deny:** SEAgent allows by default, ScopeGate leaves unlisted arguments
  unconstrained, and ceLLMate lets requests outside the sitemap through. Wicket denies anything
  unmapped or undeclared. Keep it.
- **Standing vs single-use authority:** DRIFT and SEAgent ("always allow this pattern") turn approvals
  into standing policy, while APPA and wicket bind each ruling to one call.
- **Trust in tool descriptions:** FIDES trusts them; ACE, SPA, MCPTox and wicket do not.
- **Baselines differ:** CaMeL's utility is reported as 35% in DRIFT and 48% in AgentArmor, and
  Progent's attack success as 9.4% in DRIFT and about 2% in AgentArmor. FLOWSEAL describes FIDES's
  enforcement as LLM-based, which contradicts FIDES's own text. Quote each paper's own numbers only.
- **IsolateGPT and PFI count an alert as a blocked attack,** which assumes users always deny. design.md
  §10's fatigue data says they don't.

### 10.4 The five papers that matter most for wicket

1. **FIDES** (2505.23643): the template for gates. HIDE/EXPAND variables become gateway handles,
   capacity-typed labels become gate fields, and `query_llm` becomes the quarantined reader.
2. **CaMeL** (2503.18813): policy only from the trusted query, plus checks on sink-argument
   provenance; its side-channel and "data becomes control" analysis.
3. **ceLLMate** (2512.12594): the closest black-box analogue. Agent-agnostic HTTP-layer enforcement
   with semantic sitemaps (adapters), and an LLM that *selects* policy from a trusted library.
4. **APPA** (2607.24625): recoverable IFC with disposable tainted children, schema-bounded returns
   and single-use rulings, plus the ablation showing where utility comes from.
5. **MAS hijacking** (2503.12188): the hard evidence that free text crossing agent boundaries
   compromises the parent, so gates must be typed.

Close behind: MiniScope and AutoCedar (policy derivation), SandboxEscapeBench (isolation floor),
Acquired-resource authorization (a missing mechanism), OpenClaw privsep (the black-box ablation).

## 11. Paper table

Paths are relative to the repository root. Relevance: 3 = directly shapes wicket mechanisms, 2 = useful evidence or partial, 1 = background.

| key | title | year | venue | link | local path | relevance |
|---|---|---|---|---|---|---|
| camel-2503.18813 | Defeating Prompt Injections by Design (CaMeL) | 2025 | arXiv (Google DeepMind) | https://arxiv.org/abs/2503.18813 | refs/papers/camel-2503.18813/ | 3 |
| design-patterns-2506.08837 | Design Patterns for Securing LLM Agents against Prompt Injections | 2025 | arXiv | https://arxiv.org/abs/2506.08837 | refs/papers/design-patterns-2506.08837/ | 3 |
| fides-2505.23643 | Securing AI Agents with Information-Flow Control (FIDES) | 2025 | arXiv (Microsoft) | https://arxiv.org/abs/2505.23643 | refs/papers/fides-2505.23643/ | 3 |
| spa-2608.27234 | SPA: Securing Persistent LLM Agents Across Queries with Plan-First Information-Flow Control | 2026 | arXiv | https://arxiv.org/abs/2608.27234 | refs/papers/spa-2608.27234/ | 3 |
| appa-2607.24625 | APPA: Recoverable Information-Flow Control for Real-World LLM Agents | 2026 | arXiv (Archestra AI) | https://arxiv.org/abs/2607.24625 | refs/papers/appa-2607.24625/ | 3 |
| cxi-2607.06000 | Context-to-Execution Integrity for LLM Agents (CXI) | 2026 | arXiv | https://arxiv.org/abs/2607.06000 | refs/papers/cxi-2607.06000/ | 2 |
| f-secure-2409.19091 | System-Level Defense against Indirect Prompt Injection Attacks: An Information Flow Control Perspective | 2024 | arXiv | https://arxiv.org/abs/2409.19091 | refs/papers/f-secure-2409.19091/ | 2 |
| rtbas-2502.08966 | RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage | 2025 | arXiv | https://arxiv.org/abs/2502.08966 | refs/papers/rtbas-2502.08966/ | 2 |
| permissive-ifc-2410.03055 | Permissive Information-Flow Analysis for Large Language Models | 2024 (TMLR 2025) | TMLR | https://arxiv.org/abs/2410.03055 | refs/papers/permissive-ifc-2410.03055/ | 3 |
| airgapagent-2405.05175 | AirGapAgent: Protecting Privacy-Conscious Conversational Agents | 2024 | arXiv | https://arxiv.org/abs/2405.05175 | refs/papers/airgapagent-2405.05175/ | 3 |
| progent-2504.11703 | Progent: Securing AI Agents with Privilege Control | 2025/2026 (v3) | arXiv preprint | https://arxiv.org/abs/2504.11703 | refs/papers/progent-2504.11703/ | 3 |
| conseca-2501.17070 | Contextual Agent Security: A Policy for Every Purpose | 2025 | HotOS '25 | https://arxiv.org/abs/2501.17070 | refs/papers/conseca-2501.17070/ | 2 |
| miniscope-2512.11147 | MiniScope: Authorizing Agents with Least-Privilege Permissions | 2025/2026 (v2) | arXiv preprint | https://arxiv.org/abs/2512.11147 | refs/papers/miniscope-2512.11147/ | 3 |
| least-priv-coding-2605.14859 | Do Coding Agents Understand Least-Privilege Authorization? (AuthBench) | 2026 | arXiv preprint (industry) | https://arxiv.org/abs/2605.14859 | refs/papers/least-priv-coding-2605.14859/ | 2 |
| autocedar-2607.03656 | AutoCedar: An Agentic Framework for Verifier-Guided Access Control Policy Synthesis | 2026 | arXiv preprint (cs.SE) | https://arxiv.org/abs/2607.03656 | refs/papers/autocedar-2607.03656/ | 3 |
| drift-2506.12104 | DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents | 2025 (v3 2026) | arXiv preprint | https://arxiv.org/abs/2506.12104 | refs/papers/drift-2506.12104/ | 2 |
| cellmate-2512.12594 | ceLLMate: Sandboxing Browser AI Agents | 2025 (v2 2026) | arXiv preprint | https://arxiv.org/abs/2512.12594 | refs/papers/cellmate-2512.12594/ | 3 |
| melon-2502.05174 | MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents | 2025 | ICML 2025 | https://arxiv.org/abs/2502.05174 | refs/papers/melon-2502.05174/ | 2 |
| agentarmor-2508.01249 | Securing Large Language Model Agents via Structured Graph Abstraction (AgentArmor) | 2025 | arXiv preprint | https://arxiv.org/abs/2508.01249 | refs/papers/agentarmor-2508.01249/ | 1 |
| flowseal-2609.14003 | Confuse the Model, Control the Flow: Understanding and Mitigating Privacy Leakage from LLM Agents with Information Flow Control (FLOWSEAL) | 2026 | arXiv preprint | https://arxiv.org/abs/2609.14003 | refs/papers/flowseal-2609.14003/ | 3 |
| isolategpt-2403.04960 | IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems | 2024 (v2 2025) | NDSS 2025 | https://arxiv.org/abs/2403.04960 | refs/papers/isolategpt-2403.04960/ | 2 |
| ace-2504.20984 | ACE: A Security Architecture for LLM-Integrated App Systems | 2025 | NDSS 2026 | https://arxiv.org/abs/2504.20984 | refs/papers/ace-2504.20984/ | 3 |
| pfi-2503.15547 | Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents | 2025 | arXiv | https://arxiv.org/abs/2503.15547 | refs/papers/pfi-2503.15547/ | 3 |
| openclaw-privsep-2603.13424 | Agent Privilege Separation in OpenClaw: A Structural Defense Against Prompt Injection | 2026 | arXiv | https://arxiv.org/abs/2603.13424 | refs/papers/openclaw-privsep-2603.13424/ | 2 |
| mas-injection-arch-2609.22949 | Beyond Single-Model Injection: A Threat Model and Defense Architecture for Prompt Injection in Multi-Agent Systems | 2026 | ICML 2026 (per header) | https://arxiv.org/abs/2609.22949 | refs/papers/mas-injection-arch-2609.22949/ | 1 |
| seagent-2601.11893 | Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework | 2026 | arXiv preprint | https://arxiv.org/abs/2601.11893 | refs/papers/seagent-2601.11893/ | 2 |
| mas-hijacking-2503.12188 | Multi-Agent Systems Execute Arbitrary Malicious Code | 2025 | COLM 2025 | https://arxiv.org/abs/2503.12188 | refs/papers/mas-hijacking-2503.12188/ | 3 |
| capgates-not-authz-2606.28679 | Capability Gates Are Not Authorization: Confused-Deputy Failures in LLM Agent Frameworks | 2026 | arXiv preprint | https://arxiv.org/abs/2606.28679 | refs/papers/capgates-not-authz-2606.28679/ | 2 |
| capscope-2609.08371 | Authority Is Not a String: A Capability-Scoped Harness for Prompt-Injection-Resistant Coding Agents | 2026 | LMPL '26 (ACM SIGPLAN workshop) | https://arxiv.org/abs/2609.08371 | refs/papers/capscope-2609.08371/ | 3 |
| actplane-2606.25189 | ActPlane: Programmable OS-Level Policy Enforcement for Agent Harnesses | 2026 | arXiv preprint | https://arxiv.org/abs/2606.25189 | refs/papers/actplane-2606.25189/ | 3 |
| agentbound-2510.21236 | AgentBound: Securing Execution Boundaries of AI Agents | 2025/2026 | FSE 2026 (arXiv 2510.21236) | https://arxiv.org/abs/2510.21236 | refs/papers/agentbound-2510.21236/ | 2 |
| runtime-authz-acquired-2609.14744 | Runtime Authorization for Resources Acquired by AI Agents | 2026 | arXiv preprint | https://arxiv.org/abs/2609.14744 | refs/papers/runtime-authz-acquired-2609.14744/ | 3 |
| auth-delegation | Authenticated Delegation and Authorized AI Agents | 2025 | arXiv preprint (cs.CY) | https://arxiv.org/abs/2501.09674 | refs/papers/auth-delegation/ | 1 |
| etdi | ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP by using OAuth-Enhanced Tool Definitions and Policy-Based Access Control | 2025 | arXiv preprint | https://arxiv.org/abs/2506.01333 | refs/papers/etdi/ | 2 |
| adaptive-oob-2606.26479 | Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents | 2026 | arXiv preprint (not peer-reviewed) | https://arxiv.org/abs/2606.26479 | refs/papers/adaptive-oob-2606.26479/ | 2 |
| attacker-second | The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections | 2025 | arXiv preprint | https://arxiv.org/abs/2510.09023 | refs/papers/attacker-second/ | 2 |
| sok-systems-foundations-2512.01295 | Systems Security Foundations for Agentic Computing | 2025 (v2 2026) | arXiv (SoK) | https://arxiv.org/abs/2512.01295 | refs/papers/sok-systems-foundations-2512.01295/ | 2 |
| architecting-secure-agents-2603.30016 | Architecting Secure AI Agents: Perspectives on System-Level Defenses Against Indirect Prompt Injection Attacks | 2026 | arXiv (position paper) | https://arxiv.org/abs/2603.30016 | refs/papers/architecting-secure-agents-2603.30016/ | 2 |
| sandboxescapebench-2603.02277 | Quantifying Frontier LLM Capabilities for Container Sandbox Escape | 2026 | ICML 2026 | https://arxiv.org/abs/2603.02277 | refs/papers/sandboxescapebench-2603.02277/ | 3 |
| agentdojo | AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents | 2024 | NeurIPS 2024 D&B | https://arxiv.org/abs/2406.13352 | refs/papers/agentdojo/ | 2 |
| asb | Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents | 2024 | ICLR 2025 | https://arxiv.org/abs/2410.02644 | refs/papers/asb/ | 1 |
| mcpsecbench | MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols | 2025 | preprint (v3 2026-02) | https://arxiv.org/abs/2508.13220 | refs/papers/mcpsecbench/ | 2 |
| mcptox | MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers | 2025 | AAAI 2026 | https://arxiv.org/abs/2508.14925 | refs/papers/mcptox/ | 2 |
| mcp-safetybench-2512.15163 | MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models with Real-World MCP Servers | 2025 | ICLR 2026 | https://arxiv.org/abs/2512.15163 | refs/papers/mcp-safetybench-2512.15163/ | 2 |
