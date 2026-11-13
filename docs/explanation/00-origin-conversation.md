# Origin conversation (shared claude.ai conversation, 2026-11-08)

You said: Most agent harnesses are concerned with actually making LLM API calls.

Most agent harnesses are concerned with actually making LLM API calls. I think this thinking too small. I want a sort of meta harness for any agent process.

The purpose of this harness is primarily to construct environments in which other agents can run on focussed tasks, but also securely.

This means that the meta harness has good understanding of the security boundaries needed for each task and can provision each agent with minimal access to what it needs.

These resources might be MCPs, or VM environments etc.

They might even be codemode environments or microvms for speed/lightness.

Does anything like this exist? Is it feasible?

18 minutes ago

Claude responded: The pieces exist, but the integrated version doesn't, as far as I can find (~75% confident there's no mature product).
Searched the web

Searched the web

The pieces exist, but the integrated version doesn't, as far as I can find (~75% confident there's no mature product). It's feasible. The hard part isn't provisioning. It's deciding what the boundary should be.

Assumptions: "any agent process" means you treat the agent as a black box (Claude Code, a custom loop, a script). So you can only control what it can reach, not how it reasons.

The four layers, and what exists for each

Isolation. Solved enough. Docker Sandboxes launched in March 2026 and use per-sandbox microVMs to run autonomous coding agents, and E2B and Northflank offer the same as a service. 
letsdatascience

Capability brokering. Mostly exists. MCP gateways that mint tokens when the agent attempts to access protected resources, scoped to the specific task and the specific tools. The best reference design is Browser Use: agents run in Unikraft micro-VMs without secrets, communicating remotely through a control plane that manages all external interactions and credentials. That pattern is what makes it work for black-box agents, because enforcement lives entirely outside the box: egress proxy, injected credentials, tool endpoints. 
securityboulevard

fooqux

Deriving the policy from the task. Research stage, and this is your bottleneck. Progent has an LLM write least-privilege policies per task. On the ASB benchmark, the fully autonomous version lowers attack success from 70.3% to 7.3%, while manually specified policies provably reduce it to 0%. So LLM-written policies help a lot, but they aren't a guarantee. 
arxiv

The meta-harness that ties 1–3 together. Missing. This is your product.

Where it breaks

Injection moves upstream. If the policy-writer ever reads untrusted data, an attacker can widen the boundary. Fix: derive the policy only from the trusted task text, before any data is fetched. That's the CaMeL idea, which explicitly extracts the control and data flows from the (trusted) query. 
fugumt

Escalation requests become the attack surface. An agent that's boxed too tightly will ask for more access mid-task. Whatever grants that request is your weakest point.
Sub-agents. A child agent must get a strict subset of its parent's capabilities. You want attenuable tokens (macaroon or Biscuit style), not fresh grants.
Allowed channels still leak. Write access to GitHub is enough to exfiltrate data. Network isolation doesn't stop that; per-destination data rules do.

Smallest test

Pick one task class, such as "fix a failing test in repo X." Hand-write capability manifests for 20 real tasks. Then have an LLM generate manifests from the task text alone and diff them against yours. Count the over-grants (security cost) and under-grants (agent stalls). If under-grants run above roughly 20%, the escalation path becomes the core design problem, not the sandbox.


18 minutes ago
You said: Yes I think part of this might need to be good support for dynamic provisioning of access.

Yes I think part of this might need to be good support for dynamic provisioning of access. An agent may want to reach for something at any moment which may require a policy update from a parent agent or human

15 minutes ago

Claude responded: Agreed, and I'd put dynamic escalation at the center of the design rather than treating it as an add-on.

Agreed, and I'd put dynamic escalation at the center of the design rather than treating it as an add-on. Static manifests will always be wrong at the edges, so the escalation path is where most of the security work happens.

The core problem: who wrote the request?

By the time a child agent asks for more access, it has usually read untrusted data. Its justification ("I need write access to infra/ because the test config lives there") may come from an attacker. If the parent agent reads that justification and decides, you've built a confused deputy: an LLM approving based on text an attacker may have shaped.

So the decider should judge the request, not the reasoning:

Requests are typed, not prose: capability, resource, verb, duration. Something like {fs.write, repo:X/infra/ci.yml, 1 use, 10 min}.
The parent checks one question: "Would I have granted this from the original task text alone?" It answers by re-running policy derivation on the trusted task plus the typed request, without the child's context window. If yes, grant. If no, send it up.
A parent can only grant a subset of what it holds. Anything outside its own capabilities goes up the tree, eventually to a human.

Decision tiers

Static policy auto-grants low-risk requests: reads within data the task already touches.
Parent agent handles requests within its own capabilities, using the re-derivation check.
A human handles irreversible or external effects, new data classes, or anything a parent can't cover.

Failure modes to design against

Ratcheting. Twenty small grants can add up to full access. Track the cumulative grant set against the original manifest and force a human review once the difference passes a budget.
Approval fatigue. If humans approve more than about 95% of a request type, the prompt is noise. Turn it into an auto-grant rule or an auto-deny. Each approval should feed back into that task class's default manifest, so escalations become rarer over time.
Grant creep. Grant narrower than the ask: one file rather than the repo, one use rather than standing access. Expire everything at task end.

Mechanics for black-box agents

The harness intercepts at the proxy or tool gateway, so it can't pause the agent's reasoning. Holding the connection open while a human decides will hit timeouts. Better: return a structured error with a request ID that the agent can retry. Most agents handle "permission pending, retry later" fine. For long human waits, snapshot the microVM (Firecracker supports this) so a waiting agent costs nothing.

Prior art worth borrowing (~80% confident these fit; I haven't checked current implementations):

OAuth Rich Authorization Requests (RFC 9396) for typed requests.
OpenID CIBA for asynchronous human approval on another device.
Macaroons or Biscuit tokens for parent-to-child attenuation.

Smallest test

Extend the 20-task experiment. Start each agent with the hand-written manifest minus one capability, then log every escalation request. Check two things: what fraction of requests the re-derivation check decides correctly without a human, and whether any request contains content traceable to fetched data rather than the task. The second number tells you how real the confused-deputy risk is for your workloads.


15 minutes ago
You said: Technically this will also require some sort of MCP gateway which can provide more fine-grained access to tools since providers do not always allow this at the…

Technically this will also require some sort of MCP gateway which can provide more fine-grained access to tools since providers do not always allow this at their API level

14 minutes ago

Claude responded: Yes.

Yes. The gateway becomes the place where coarse provider permissions get narrowed to task-sized ones. It holds a broad credential, and every request goes through a policy check before it reaches the provider.

That makes it a classic reference monitor, which has three requirements:

Complete mediation. The agent must have no other route to the credential. No tokens inside the sandbox, and all egress goes through the gateway.
Tamper-proof. It runs outside the agent's trust domain.
Small enough to verify. This is the hard one, because of the long tail of providers.

Two enforcement surfaces, one policy engine

Agents won't only use MCP. They'll run gh, aws or curl directly. If only MCP is mediated, the agent routes around it. So you need an MCP gateway for tool calls and an HTTP egress proxy that injects credentials for CLIs and SDKs. Both map requests onto the same resource model, (provider, resource path, verb), and query the same policy. Unmapped endpoints are denied by default.

Where narrowing gets hard (GitHub and Slack examples):

Writes with hidden side effects. Writing to .github/workflows/ means running code with the repo's secrets. Pushing to an auto-deploying branch means a production deploy. Path-level rules have to encode provider semantics, not just "write to repo X."
Reads that return too much. Slack search returns everything the token can see. You either rewrite the query (add a channel filter) or filter results afterwards. Filtering afterwards breaks pagination and counts, so rewrite where possible.
Opaque IDs. "Comment on issue 4821" requires resolving which repo it belongs to before deciding. That's an extra call, and a race if the resource changes between check and use.
GraphQL and batch endpoints. One request touches many resources. Parse fully or deny; partial parsing is a bypass waiting to happen.
Provider-side triggers. A comment that @mentions someone sends them an email. The gateway sees a comment, not an outbound message.

Defense in depth

The gateway holds the broadest tokens, so it's the most valuable target. Use the narrowest native credential the provider offers (GitHub App installation tokens scoped to specific repos, for example) and let the gateway narrow further from there. If the gateway's policy has a bug, the native scope still caps the damage.

The scaling cost is adapters

Each provider needs a mapping from endpoints to resources, written with an understanding of side effects. Generating adapters from OpenAPI specs with an LLM gets you about 70% of the way (~60% confident on that figure). The side-effect semantics above are mostly absent from specs, and that's where escapes come from. I'd hand-write adapters for the 5–10 providers that cover most usage and deny everything else.

Smallest test

Build the GitHub adapter for about 15 endpoints. Then give a red-team agent a task scoped to one repo and one directory, with the goal of reading or writing anything outside it using only allowed calls. Every escape it finds is a missing semantic rule. If it finds more than 3, the adapter model needs rethinking before you scale it to other providers.


14 minutes ago
You said: I think the MCP filter adapters may need to support being generated automatically by the harness.

I think the MCP filter adapters may need to support being generated automatically by the harness. It can be self building to some extent

12 minutes ago

Claude responded: Yes, with one rule: the generator gets to make adapters narrower, never wider.

Yes, with one rule: the generator gets to make adapters narrower, never wider. A generated adapter defines the security boundary, so the code writing it is in your trusted base. Design it so that mistakes cost the agent access (it stalls, someone notices, it gets fixed) rather than leaking access (silent, found later or never).

Make adapters data, not code

If the generator writes Python or TypeScript filters, you have to review arbitrary code each time. Instead, generated adapters should be declarations in a small DSL that one interpreter runs:

endpoint pattern
where the resource ID lives (path param, body field, or resolved via a lookup call)
verb
risk class
response filter or query rewrite

You verify the interpreter once. The generator can only produce rules that type-check, and anything it leaves unspecified, such as an unmapped field or an unknown parameter, means deny.

Start conservative

Every newly discovered endpoint starts at the highest risk class: write, irreversible, external side effects. Lowering that classification requires evidence:

Resource extraction can be checked automatically. In a sandbox provider account (say, a GitHub test org), create resources inside and outside the scope, call each endpoint, and confirm the gateway's allow/deny decisions match. I'm ~70% confident this part can be fully automated.
Side effects can only be partly checked. Watching webhook and email sinks in the test account catches some, but testing can't prove a side effect doesn't exist. A human signs off on downgrades below "external effects." That's a small, reviewable diff, not a whole adapter.

Self-building loop

This connects to dynamic provisioning:

An agent hits an unmapped endpoint, and the gateway denies it with a request ID.
The harness generates a rule from the OpenAPI spec, docs and the request shape. It doesn't see the agent's context, for the same confused-deputy reason as before.
The rule runs through the sandbox checks and lands at whatever risk class the evidence supports.
The normal escalation path decides whether this agent gets it now.

Over time the adapter set grows toward what agents actually use, which beats trying to map the whole API up front.

What stays manual

Semantic rules like "writes to .github/workflows/ mean code execution" can't be derived from specs or from black-box testing. Keep a short, hand-maintained list of dangerous patterns per provider. The generator must check its output against that list, and a match forces the high risk class.

Smallest test

Auto-generate the GitHub adapter for the same ~15 endpoints you'd hand-write in the red-team test, then diff the two. Classify each disagreement as either too restrictive (fine) or too permissive (a bug). If any generated rule is too permissive, find out which check should have caught it before you trust the loop with anything else.


12 minutes ago
You said: What about managing memories etc generated by the child agents?

What about managing memories etc generated by the child agents? We need to avoid smuggling between the tree of agents

11 minutes ago

Claude responded: This is an information-flow control problem, not an access-control one.
Searched the web

Searched the web

This is an information-flow control problem, not an access-control one. Capabilities decide what an agent can touch. Smuggling happens through data that legitimately moves between agents. Microsoft's FIDES is the closest prior art: it tracks confidentiality and integrity labels, deterministically enforces security policies, and introduces novel primitives for selectively hiding and revealing information. Your version is harder because your agents are black boxes, so labels have to be per agent, not per token. 
arxiv


Two directions of smuggling

Integrity (child to parent). A child reads a poisoned web page and returns text containing instructions. The parent acts on them using its wider capabilities. Same confused deputy as before, carried in through a return value.
Confidentiality (parent or sibling to child). Sensitive data reaches an agent whose egress allows destinations that data shouldn't go to.

Coarse labels, propagated by the harness

Each agent's output gets a label covering everything it was granted to read, plus a taint flag if it fetched anything untrusted. Any store it writes to inherits that label, and anyone who reads that store inherits it in turn. The rules:

An agent can read data only if its clearance covers the label.
An agent's egress destinations must be cleared for every label it holds. No writing down.
Tainted data is never read as instructions by anything holding wider capabilities.

Memory is any state that outlives a write, not just the obvious memory store:

memory files and vector stores
shared filesystems and repos
caches and logs a later agent reads
provider-side state: a child writes a GitHub comment, a sibling reads it later. The gateway has to remember a label for each resource it allowed a write to, and apply that label on later reads.
the harness's own learned artifacts: generated adapters, manifests, approval history. This is why the adapter generator must not see agent context.

Defaults: memory is scoped to the task and deleted at task end. Promoting it to persistent memory is an explicit declassification step, done by a human or a trusted process, and the label stays attached.

Handles, not contents

Without this, label creep turns everything tainted by the time results reach the root. FIDES's answer: for hiding, tool results are stored in variables in the planner's memory. In your tree, a parent receives an opaque handle to a child's output. It can pass the handle to another child, or to the final output, without ever reading the contents. The parent only reads typed fields with low information content, like tests_passed: bool. Anything free-text stays behind a handle or goes through a quarantined reader that has no capabilities. 
alphaxiv


What you can't fully close

Covert channels: timing, resource exhaustion, file names, error messages, even the size of an escalation request. Eliminating them isn't realistic. Aim to keep bandwidth low and audit for anomalies. ~85% confident the explicit channels above account for nearly all practical risk.

Smallest test

Build a two-level tree: a parent with write access to a repo, and a child with web read access only. Plant an injection on a page the child will fetch, telling it to get the parent to push a specific change. Run it three ways: free-text returns, typed returns, and handles. Count how often the push happens. If typed returns already get it to zero on realistic tasks, handles may be overkill for v1.


10 minutes ago
You said: We need some sort of abstraction to help humans understand the various boundaries this sort of system will enable.

We need some sort of abstraction to help humans understand the various boundaries this sort of system will enable.

I think there are multiple layers to this? For example a swarm of agents may or may not provide uniform access and information flow to all of its subagents.

9 minutes ago

Claude responded: Yes.

Yes. I'd build the abstraction around zones and gates, because humans reason about boundaries far better than about per-agent permission lists. SELinux is the cautionary example: precise per-process rules that almost nobody can read.

The core idea

A zone is a set of agents with free internal flow and a shared ceiling. Every agent inside has at most the zone's capabilities, and data moves freely among them.
A gate is the only place where data or authority crosses a zone boundary. Each gate has an explicit rule: typed fields only, handles only, a declassification step, or human approval.

Humans approve zones and gates. Agents inside a zone are implementation detail. Your swarm question then has a simple answer: a uniform swarm is one zone, and a non-uniform swarm is several zones joined by gates.

The layers

Agent. Capabilities plus a label. Mostly invisible to humans.
Zone. Described by three facts: what it can reach (capabilities), what it can see (data labels), and where it can send (egress).
Delegation tree. Zones nest. An inner zone's ceiling is a subset of its parent's. Authority flows down and narrows at each level. Results flow up through gates.
Organisation. Data classes, provider grants, who can approve what. This sets the ceiling for every task.

Uniform versus split swarms

A uniform swarm is cheap: no gates, no friction. But its blast radius is the union of everything any member needs. Take the earlier example. If web readers and repo writers share a zone, one poisoned page can reach a push to main.

Split them: a "readers" zone with web access and taint, a "writers" zone with repo write and no web, and a typed-results gate between them. Each extra zone adds friction, so the design choice is where the blast-radius reduction justifies a gate.

The question humans actually ask

"If this agent is compromised, what can happen?" The model answers it mechanically. The answer is the zone's reach and send, plus whatever can cross its gates on its behalf. Show that answer directly rather than making people derive it from a diagram.

Two ways the abstraction can lie

Hand-drawn diagrams drift from enforcement. The view must be generated from the live enforcement config, including provider-side state. Two zones that both write to the same GitHub issue are connected, and the diagram must show that edge.
Too many zones becomes SELinux again. Collapse nested zones by default so the top-level view has about 7 zones or fewer, and let people expand on demand.

Dynamic escalation changes zones over time, so the view also needs a timeline of diffs. For example: "writers gained repo:Y write at 14:02, approved by parent, expires 14:12."

Smallest test

Take a 3-zone task. Show three engineers the zone/gate view, and separately the raw policy config. Ask each one the same five blast-radius questions ("can the web reader cause a push to main?"). Compare accuracy and time. If the zone view isn't clearly faster and at least as accurate, the abstraction is wrong.


8 minutes ago
