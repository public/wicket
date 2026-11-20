"use strict";
// Made-up console data for ci/console-preview.sh: the shapes /api/state and its siblings return
// (crates/wicket-cli/src/serve/mod.rs `dashboard`, capacity.rs, standing.rs, secrets.rs), with every
// kind of pending request, long names, and alerts. Nothing here is a real host, run or person.
const T = "acme";
const DOMAIN = "wicket.example";
const agentId = (zone, agent) => `spiffe://${DOMAIN}/t/${T}/z/${zone}/a/${agent}`;
const opId = who => `spiffe://${DOMAIN}/t/${T}/op/${who}`;
const run = n => "run_01JD" + n.padEnd(22, "Q").slice(0, 22);

function verified(zone, agent, actingFor) {
  return { verified: true, id: agentId(zone, agent), agent, zone, acting_for: actingFor || ["passkey:phone"], identity_sha256: "ab12" };
}
const attr1 = (agent, tool, call) => ({ basis: "one", requesters: [{ agent, tool, call }] });

function pending(now) {
  return [
    {
      id: "r-7f3a", tenant: T, run: run("RELEASE"), zone: "release", method: "POST", host: "github.com",
      path: "/acme/storefront.git/git-receive-pack", risk: "R4ExecOrPrivilege", status: "pending",
      reason: "Push the release branch release/2026.11 with the changelog and version bump",
      created_at: now - 40, attribution: [attr1("release-bot", "Bash", "git push origin release/2026.11")], scope_prefix: false,
      identity: verified("release", "release-bot"), once_terms: { uses: null, ttl_secs: 300 },
    },
    {
      id: "r-81c0", tenant: T, run: run("DOCS"), zone: "docs-writer", method: "PUT", host: "api.docs-host.example.com",
      path: "/v2/spaces/engineering-handbook/pages/onboarding-for-new-contributors-and-reviewers-2026", risk: "R3ExternalOrIrreversible",
      status: "pending", reason: "Publish the updated onboarding page", created_at: now - 260,
      attribution: [{ basis: "ambiguous", requesters: [
        { agent: "docs-writer", tool: "WebFetch", call: "PUT https://api.docs-host.example.com/v2/spaces/engineering-handbook/pages/…" },
        { agent: "docs-writer/reviewer", tool: "Bash", call: "curl -X PUT …" }] }],
      scope_prefix: false, identity: verified("docs-writer", "docs-writer"), once_terms: { uses: 1, ttl_secs: 600 },
    },
    {
      id: "r-9a12", tenant: T, run: run("TRIAGE"), zone: "triage", method: "GET", host: "registry.npmjs.org",
      path: "/@acme-internal/", risk: "R1ReadScoped", status: "pending", reason: "Read package metadata for the dependency audit",
      created_at: now - 600, attribution: [attr1("triage", "Bash", "npm view @acme-internal/ui-kit versions")], scope_prefix: true,
      identity: verified("triage", "triage"), once_terms: { uses: 1, ttl_secs: 600 },
    },
    {
      id: "r-a004", tenant: T, run: run("SCALE"), zone: "build-farm", method: "CAPACITY", host: "wicket.internal",
      path: "/capacity/l-17", risk: "R3ExternalOrIrreversible", status: "pending",
      reason: "capacity lease l-17: 2 vCPU, 4096 MiB, isolation Gvisor or stronger, region lhr preferred, for 8h, on vultr, at most $0.036/h, worst case $0.288 (reserved now). Asked by the agent: Lease one more build node for the nightly matrix", created_at: now - 1500, attribution: [], scope_prefix: false,
      identity: verified("build-farm", "scheduler"), once_terms: { uses: 1, ttl_secs: 600 }, args_sha256: "c0ffee",
      // The lease's terms as fields, as the server sends them (#709, #715 review).
      lease: { id: "l-17", provider: "vultr", vcpus: 2, memory_mib: 4096, isolation: "gvisor", region: "lhr", duration_secs: 28800,
        hourly_cap_usd: "$0.0360", reserved_usd: "$0.2880", reason: "Lease one more build node for the nightly matrix" },
    },
    {
      id: "r-a019", tenant: T, run: run("PLANNER"), zone: "planner", method: "SPAWN", host: "wicket.internal",
      path: "/zones/research/literature-reviewer", risk: "R4ExecOrPrivilege", status: "pending",
      reason: "Start a named child to read the papers on rate limiting", created_at: now - 3000, attribution: [],
      scope_prefix: false, identity: verified("planner", "planner"), once_terms: { uses: 1, ttl_secs: 600 }, args_sha256: "beef",
    },
    {
      id: "r-a020", tenant: T, run: run("WEB"), zone: "web", method: "LINK", host: "wicket.internal",
      path: `/links/${run("WEB")}/${run("API")}/8080`, risk: "R2WriteReversible", status: "pending",
      reason: "Let the web build reach the API preview", created_at: now - 4200, attribution: [], scope_prefix: false,
      identity: verified("web", "frontend"), once_terms: { uses: 1, ttl_secs: 600 },
    },
    {
      id: "r-a031", tenant: T, run: run("SELFUP"), zone: "maintenance", method: "UPDATE", host: "wicket.internal",
      path: "/self/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", risk: "R4ExecOrPrivilege", status: "pending",
      reason: "Install the build with the fix for the feed reconnect", created_at: now - 7300, attribution: [], scope_prefix: false,
      identity: verified("maintenance", "updater"), once_terms: { uses: 1, ttl_secs: 600 },
    },
    {
      id: "r-b100", tenant: T, run: run("ROGUE"), zone: "sandbox", method: "POST", host: "hooks.chat.example.com",
      path: "/services/T000/B000/notify", risk: "R2WriteReversible", status: "pending", reason: "Post the summary to the team channel",
      created_at: now - 90, attribution: [], scope_prefix: false,
      identity: { verified: false, run: run("ROGUE"), error: "signature invalid" }, once_terms: { uses: 1, ttl_secs: 600 },
    },
  ];
}

function runs(now) {
  return [
    { id: run("RELEASE"), zone: "release", agent: "release-bot", status: "running", started_at: now - 900, ended_at: null, has_identity: true, revoked: false, acp: true, remote_url: "https://claude.example.com/code/session_0000" },
    { id: run("DOCS"), zone: "docs-writer", agent: "docs-writer", status: "running", started_at: now - 3600, ended_at: null, has_identity: true, revoked: false, acp: true },
    { id: run("TRIAGE"), zone: "triage", agent: "triage", status: "running", started_at: now - 5400, ended_at: null, has_identity: true, revoked: false, acp: false },
    { id: run("SCALE"), zone: "build-farm", agent: "scheduler", status: "running", started_at: now - 12000, ended_at: null, has_identity: true, revoked: false, acp: false },
    { id: run("PLANNER"), zone: "planner", agent: "planner", status: "running", started_at: now - 20000, ended_at: null, has_identity: true, revoked: false, acp: false },
    { id: run("ROGUE"), zone: "sandbox", agent: "experiment-with-a-very-long-agent-name-for-layout", status: "running", started_at: now - 120, ended_at: null, has_identity: true, revoked: true, acp: false },
    { id: run("NIGHTLY"), zone: "build-farm", agent: "nightly", status: "exited", started_at: now - 30000, ended_at: now - 21600, has_identity: true, revoked: false, acp: false },
    { id: run("FAILED"), zone: "triage", agent: "triage", status: "failed", started_at: now - 40000, ended_at: now - 39000, has_identity: true, revoked: false, acp: false },
    { id: run("STOPPED"), zone: "web", agent: "frontend", status: "stopped", started_at: now - 50000, ended_at: now - 48000, has_identity: true, revoked: false, acp: false },
    { id: run("HIBER"), zone: "research", agent: "literature-reviewer", status: "hibernated", started_at: now - 80000, ended_at: null, has_identity: true, revoked: false, acp: false },
    { id: run("PROGRAM"), zone: "maintenance", agent: "", status: "running", started_at: now - 300, ended_at: null, has_identity: false, revoked: false, acp: false },
  ];
}

const decided = now => [
  { id: "r-6e01", run: run("RELEASE"), zone: "release", method: "GET", host: "api.github.com", path: "/repos/acme/storefront/releases", risk: "R1ReadScoped", status: "granted", created_at: now - 1200 },
  { id: "r-6d77", run: run("DOCS"), zone: "docs-writer", method: "DELETE", host: "api.docs-host.example.com", path: "/v2/spaces/engineering-handbook/pages/old-draft", risk: "R3ExternalOrIrreversible", status: "denied", created_at: now - 4000 },
  { id: "r-6c10", run: run("TRIAGE"), zone: "triage", method: "GET", host: "registry.npmjs.org", path: "/left-pad", risk: "R0Read", status: "expired", created_at: now - 9000 },
];

const egress = (seq, ts, r, method, host, path, outcome, risk) => ({ seq, ts, kind: "op", run: r, body: { kind: "egress", method, host, path, outcome, risk } });
function audit(now) {
  const a = [
    { seq: 9001, ts: now - 7200, kind: "run.start", run: run("PLANNER"), body: { zone: "planner", agent: "planner" } },
    egress(9002, now - 7000, run("PLANNER"), "GET", "api.search.example.com", "/v1/search?q=token+bucket", "allow"),
    { seq: 9003, ts: now - 6900, kind: "op", run: run("PLANNER"), body: { kind: "llm", requests: 3, model: "claude-model-x", status: 200, input_tokens: 12345, output_tokens: 567 } },
    egress(9004, now - 6000, run("DOCS"), "DELETE", "api.docs-host.example.com", "/v2/spaces/engineering-handbook/pages/old-draft", "forbidden"),
    { seq: 9005, ts: now - 5000, kind: "decision", run: run("DOCS"), body: { decision: "deny", request: "r-6d77", by: "passkey:phone", signed: true } },
    { seq: 9006, ts: now - 4000, kind: "standing.revoked", run: null, body: { standing: "s-3", by: "passkey:laptop", rule: { host: "deb.example.org", methods: ["GET"], paths: ["/**"] }, bound: "zone" } },
    { seq: 9007, ts: now - 3500, kind: "decision.refused", run: run("TRIAGE"), body: { target: "r-6c10", decision: "approve", by: "passkey:tablet", granter: "human", why: "R4 is above this operator's highest risk (R2)" } },
    { seq: 9008, ts: now - 3000, kind: "capacity.requested", run: run("SCALE"), body: { request: "r-a004", principal: "spiffe://wicket.example/t/acme/op/unix/alex", ask: "1 × vc2-2c-4gb in lhr", backend: "vultr", lifetime_secs: 28800, purpose: "nightly matrix" } },
    { seq: 9009, ts: now - 2500, kind: "node.audit", run: run("SCALE"), body: { node: "node-a", body: JSON.stringify({ kind: "egress", method: "GET", host: "deb.example.org", path: "/dists/stable/InRelease", outcome: "spliced" }) } },
    { seq: 9010, ts: now - 2000, kind: "grant.revoked", run: run("TRIAGE"), body: { grant: "g-41", by: "passkey:phone", node: "local" } },
    { seq: 9011, ts: now - 1500, kind: "session.prompt", run: run("RELEASE"), body: { by: "passkey:phone", chars: 212, via: "console", signed: true } },
    { seq: 9012, ts: now - 1200, kind: "identity.revoked", run: run("ROGUE"), body: { by: "passkey:phone", reason: "posting outside its brief", signed: true } },
    { seq: 9013, ts: now - 900, kind: "run.console_start", run: run("RELEASE"), body: { root: "manifests", manifest: "release.yaml", by: "passkey:phone" } },
    egress(9014, now - 600, run("RELEASE"), "POST", "github.com", "/acme/storefront.git/git-receive-pack", "pending"),
    { seq: 9015, ts: now - 400, kind: "op", run: run("SCALE"), body: { kind: "box", what: "oom", detail: "the box was killed for memory (2 GiB)" } },
    { seq: 9016, ts: now - 300, kind: "run.exit_cause", run: run("FAILED"), body: { code: 137, cause: "killed: out of memory" } },
    { seq: 9017, ts: now - 200, kind: "run.end", run: run("NIGHTLY"), body: { status: "exited", model_requests: 41 } },
    { seq: 9018, ts: now - 100, kind: "lease.requested", run: run("SCALE"), body: { lease: "l-17", request: "r-a004", provider: "vultr", spec: { plan: "vc2-2c-4gb", region: "lhr" }, hourly_cap_usd_micros: 36000, reserved_usd_micros: 288000, duration_secs: 28800 } },
    egress(9019, now - 50, run("TRIAGE"), "GET", "registry.npmjs.org", "/@acme-internal/ui-kit", "allow"),
    { seq: 9020, ts: now - 40, kind: "node.audit", run: run("SCALE"), body: { node: "node-ams-02", body: JSON.stringify({ kind: "box.restart", why: "health gate" }) } },
    { seq: 9021, ts: now - 30, kind: "operator.passkey_added", run: null, body: { name: "tablet", via: "enrol link" } },
  ];
  return a;
}

const manifests = [
  { root: "manifests", name: "release.yaml", agent: "release-bot", program: null, zone: "release", image: "ghcr.io/acme/agent-base:2026.11", image_error: null, valid: true,
    hosts: [{ host: "github.com", mode: "inspected", why: "reach rule" }, { host: "api.github.com", mode: "inspected", why: "reach rule" }] },
  { root: "manifests", name: "docs-writer.yaml", agent: "docs-writer", program: null, zone: "docs-writer", image: "ghcr.io/acme/agent-base:2026.11", image_error: null, valid: true,
    hosts: [{ host: "api.docs-host.example.com", mode: "inspected", why: "reach rule" }, { host: "deb.example.org", mode: "spliced", rule: "apt" }] },
  { root: "manifests", name: "a-manifest-with-a-rather-long-file-name-for-layout-checks.yaml", agent: null, program: "backup", zone: "maintenance", image: null, image_error: "no image is set and the zone has no default", valid: true, hosts: [] },
  { root: "manifests", name: "broken.yaml", agent: null, program: null, zone: null, image: null, image_error: null, valid: false, hosts: null },
  { root: "examples", name: "hello.yaml", agent: "hello", program: null, zone: "hello", image: "ghcr.io/acme/agent-base:2026.11", image_error: null, valid: true, hosts: [] },
];

const secrets = now => ({
  secrets: [
    { name: "ANTHROPIC_API_KEY", kind: "value", hosts: ["api.anthropic.com"], set_at: now - 86400 * 12,
      used_by: [{ zone: "release", root: "manifests", manifest: "release.yaml", use: "llm", provider: "anthropic" }], zones: ["release"], runs: [{ run: run("RELEASE") }] },
    { name: "GITHUB_PUSH_TOKEN", kind: "value", hosts: ["github.com", "api.github.com"], set_at: now - 86400 * 3,
      used_by: [{ zone: "release", root: "manifests", manifest: "release.yaml", use: "inject", host: "github.com", header: "authorization", format: "basic", optional: false }], zones: ["release"], runs: [] },
    { name: "CLAUDE_LOGIN", kind: "reference", hosts: ["api.anthropic.com"], set_at: null, reference: { file: "~/.claude/.credentials.json", pointer: "/claudeAiOauth/accessToken" }, used_by: [], zones: [], runs: [] },
  ],
  missing: [{ name: "DOCS_HOST_TOKEN", zones: ["docs-writer"], used_by: [{ zone: "docs-writer", root: "manifests", manifest: "docs-writer.yaml", use: "inject", host: "api.docs-host.example.com", header: "authorization", format: "bearer", optional: false }] }],
  link_cli_only: "a reference names a file on the host, so it is made on the host: wicket secret link NAME --file PATH [--pointer /json/pointer]",
  max_value: 65536,
});

function health(nowMs) {
  return {
    nodes: [
      { node: "local", received_ms: nowMs - 20000, summary: "disk 41% · memory 38% · 6 boxes", disk_pct: 41, alerts: [] },
      { node: "node-lhr-ci-runner-large-01.nodes.internal.example.net", received_ms: nowMs - 45000, summary: "disk 91% · memory 72% · 3 boxes", disk_pct: 91,
        alerts: ["node-lhr-ci-runner-large-01.nodes.internal.example.net: disk 91% full (alert at 90%)"] },
      { node: "node-ams-02", received_ms: nowMs - 600000, summary: "no report for 10 min", disk_pct: 12, alerts: ["node-ams-02: no health report for 10 min"] },
    ],
    control_disk_pct: 88,
    state_store: {
      stream: { endpoint: "s3.storage.example.com", bucket: "acme-wicket-state", state: "streaming", last_sync_ms: nowMs - 4000, behind_secs: 0, error: null, error_ms: null },
      audit: [
        { sink: "archive", kind: "s3", seq: 8990, head: 9019, behind: 29, behind_secs: 840, manual: false, checkpoint_at: nowMs / 1000 - 900, error: null },
        { sink: "stdout", kind: "jsonl", seq: 0, head: 9019, behind: 9019, behind_secs: 86400, manual: true, checkpoint_at: null, error: null },
      ],
      errors: [], read_ms: nowMs - 3000, stale: false, alerts: ["audit export archive is 29 records behind (oldest 14 min)"],
    },
    alerts: [],
  };
}

const placed = now => [
  { id: "8f2c6d1e-3b4a-4f5e-9a8b-7c6d5e4f3a2b", name: "ci-runner-large-01", backend: "vultr", lease_until: now + 6 * 3600, past_lease: false, held_by: null },
  { id: "1a2b3c4d-5e6f-4a1b-8c9d-0e1f2a3b4c5d", name: "ci-runner-large-02", backend: "vultr", lease_until: now - 7200, past_lease: true, held_by: run("SCALE") },
  { id: "aa11bb22-cc33-4d44-8e55-ff6677889900", name: "scratch", backend: "vultr", lease_until: now - 60, past_lease: true, held_by: null },
];

const capacity = now => [
  { id: "cap-7", principal: opId("unix/alex"), terms: { plans: ["vc2-1c-2gb", "vc2-2c-4gb"], regions: ["lhr"], hourly_micros: 50000, hourly_usd: "$0.0500", daily_micros: 1000000, daily_usd: "$1.0000", nodes: 2 },
    expires_at: now + 8 * 3600, decided_by: "passkey:phone", created_at: now - 3600,
    used: { nodes: 1, hourly_usd: "$0.0140", daily_usd: "$0.2000" }, left: { nodes: 1, hourly_usd: "$0.0360", daily_usd: "$0.8000" } },
  { id: "cap-9", principal: agentId("build-farm", "scheduler"), terms: { plans: ["vc2-4c-8gb"], regions: ["lhr", "ams", "fra"], hourly_micros: 240000, hourly_usd: "$0.2400", daily_micros: 5000000, daily_usd: "$5.0000", nodes: 4 },
    expires_at: now + 1800, decided_by: "passkey:laptop", created_at: now - 80000,
    used: { nodes: 0, hourly_usd: "$0.0000", daily_usd: "$0.0000" }, left: { nodes: 4, hourly_usd: "$0.2400", daily_usd: "$5.0000" } },
];

const standing = now => ({
  asks: [
    { id: "s-12", principal: agentId("triage", "triage"), zone: "triage", zone_digest: "5d41402abc4b2a76b9719d911017c592", run: run("TRIAGE"),
      rule: { host: "registry.npmjs.org", methods: ["GET"], paths: ["/**"] }, reason: "Every triage run reads package metadata; asking each time is noise",
      evidence: { requests: 37, granted: 35, denied: 0, undecided: 2, runs: 9, days: 6, own_asks: 1,
        ops: [{ method: "GET", path: "/@acme-internal/ui-kit", count: 14, granted: 14 }, { method: "GET", path: "/left-pad", count: 9, granted: 8 }, { method: "GET", path: "/@acme-internal/http", count: 7, granted: 7 }] },
      beyond: ["every path on registry.npmjs.org, not only the 3 packages it read"], narrowed: { methods: ["GET"], paths: ["/@acme-internal/**", "/left-pad"] }, created_at: now - 5000 },
    { id: "s-13", principal: agentId("release", "release-bot"), zone: "release", zone_digest: null, run: run("RELEASE"),
      rule: { host: "uploads.github.com", methods: ["POST"], paths: ["/repos/acme/storefront/releases/*/assets"], allow_dangerous: true },
      reason: "Upload release assets", evidence: { requests: 0, granted: 0, denied: 0, undecided: 0, runs: 0, days: 0, own_asks: 0, ops: [] }, beyond: [], narrowed: null, created_at: now - 300 },
  ],
  rules: [
    { id: "s-4", principal: agentId("docs-writer", "docs-writer"), zone: "docs-writer", rule: { host: "api.docs-host.example.com", methods: ["GET"], paths: ["/v2/spaces/**"] }, for: "agent",
      expires_at: now + 86400 * 21, live: true, decided_by: "passkey:phone", decided_at: now - 86400 * 9 },
    { id: "s-7", principal: agentId("build-farm", "scheduler"), zone: "build-farm", rule: { host: "deb.example.org", methods: ["GET"], paths: ["/**"] }, for: "zone",
      expires_at: now - 3600, live: false, decided_by: "passkey:laptop", decided_at: now - 86400 * 31 },
  ],
});

function state(nowMs) {
  const now = Math.floor(nowMs / 1000);
  return {
    now, tenant: T,
    pending: pending(now), decided: decided(now), runs: runs(now), manifests, secrets: secrets(now),
    passkeys: [{ id: "AbCdEfGhIjKlMnOpQrStUvWxYz012345", name: "phone", sign_count: 41 }, { id: "ZyXwVuTsRqPoNmLkJiHgFeDcBa987654", name: "laptop", sign_count: 7 }],
    placed: placed(now), health: health(nowMs), capacity: capacity(now), standing: standing(now), audit: audit(now),
    audit_retention: { line: "audit table: 41 MiB of 512 MiB; pruned up to #8200 (exported to archive) 3 days ago", enabled: true, bytes: 43000000, limit_bytes: 536870912, anchor: null },
  };
}

// Nothing waiting, nothing running: every empty state at once.
function empty(nowMs) {
  const now = Math.floor(nowMs / 1000);
  return {
    now, tenant: T, pending: [], decided: [], runs: [], manifests: [], secrets: { secrets: [], missing: [], link_cli_only: secrets(now).link_cli_only },
    passkeys: [{ id: "AbCdEfGhIjKlMnOpQrStUvWxYz012345", name: "phone", sign_count: 1 }], placed: [],
    health: { nodes: [], control_disk_pct: 20, state_store: null, alerts: [] }, capacity: [], standing: { asks: [], rules: [] }, audit: [], audit_retention: null,
  };
}

const push = { public_key: "BAEC", min_interval_secs: 30, devices: [
  { id: "d1", label: "iPhone · Safari", service: "web.push.apple.com", details: true, last_success: Math.floor(Date.now() / 1000) - 3600 },
  { id: "d2", label: "Mac · Firefox", service: "updates.push.services.mozilla.com", details: false, last_success: null },
] };

const policy = { installed: "v3", current: { matches_applied: true, cedar: "permit(principal, action == Action::\"egress\", resource)\nwhen { resource.host == \"github.com\" && principal.zone == \"release\" };" },
  versions: [{ version: "v3", current: true, applied: [{ at: Math.floor(Date.now() / 1000) - 86400, by: "unix/alex" }] }, { version: "v2", current: false, applied: [] }],
  runs: [{ run: run("RELEASE"), zone: "release", policy: "v3", status: "running" }] };

function authority(id) {
  return { status: "running", node: "local", feed: { epoch: 4 }, policy: { version: "v3", current: true, installed: "v3" },
    deadline: { until_ms: Date.now() + 3600000, stopped: false },
    holdings: { secrets: ["ANTHROPIC_API_KEY"], slice: { requests: 200, output_tokens: 400000, input_tokens: null } },
    token: { held: true, box_path: id, epoch: 4, zone: "release", issued_by: "the authority root", loads: true,
      reach: [{ host: "github.com", methods: ["GET", "POST"], paths: ["/acme/storefront.git/**"], allow_dangerous: false }, { host: "api.github.com", methods: ["GET", "HEAD"], paths: ["/**"], allow_dangerous: false }],
      blocks: [{ index: 0, kind: "zone", source: "check if reach(\"github.com\", \"POST\", $p), $p.starts_with(\"/acme/\");", signed_by: null, revocation_fingerprint: "0123456789abcdef", revoked: false }],
      grants: [{ id: "g-51", method: "GET", host: "api.github.com", path: "/repos/acme/storefront/releases", uses: null, expires_at: Math.floor(Date.now() / 1000) + 3000, approved_by: "passkey:phone", approved_at: Math.floor(Date.now() / 1000) - 600, revoked: false, reached_node: true }],
      zone_cedar: "permit(principal, action, resource) when { resource.host == \"github.com\" };" } };
}

const explain = seq => ({ run: run("DOCS"), policy: "v3", recorded: { method: "DELETE", host: "api.docs-host.example.com", path: "/v2/spaces/engineering-handbook/pages/old-draft", risk: "R3ExternalOrIrreversible", outcome: "forbidden", decided_on: "the box's node", at: Math.floor(Date.now() / 1000) - 6000, detail: "no grant or rule allows DELETE" },
  against_token_now: { available: true, decision: "forbidden", why: "block 0: no check matched", zone_says: "Forbidden" }, seq });

const manifestView = (root, name) => ({ root, name, writable: root === "manifests", valid: true, error: null,
  yaml: "task: Cut the release\nagent: { name: release-bot }\nzone:\n  name: release\n  reach:\n    - { host: github.com, methods: [GET, POST] }\n",
  history: [{ version: 2, saved_before: Math.floor(Date.now() / 1000) - 86400, sha256_prefix: "9f86d081" }],
  fields: [{ path: "zone.name", value: "release" }, { path: "limits.memory", value: "2GiB", default: true }],
  grants: { task: "Cut the release", agent: { name: "release-bot", harness: "claude", max_turns: null, max_children: 0 }, program: null, image: { Ok: "ghcr.io/acme/agent-base:2026.11" },
    isolation: "gvisor", unlisted_hosts: "ask", reach: [{ host: "github.com", methods: ["GET", "POST"], paths: null }], hosts: [{ host: "github.com", mode: "inspected", why: "reach rule" }],
    forbid: [], inject: [], llm: null, volumes: [], limits: { memory: "2GiB", cpus: 2, wall: "1h" }, org_policy: null } });

module.exports = { state, empty, push, policy, authority, explain, manifestView, run };
