//! Enforcement points (design §9). Both proxies listen on unix sockets that are bind-mounted into
//! the sandbox: the socket a request arrives on *is* the sandbox's identity, so no bearer token is
//! ever needed inside the box.

pub mod ca;
pub mod decide;
pub mod delegate;
mod dial;
pub mod dns;
pub mod egress;
pub mod exists;
pub mod gateway;
pub mod h3;
pub mod link;
pub mod llm;
pub mod provider;
pub mod secret_helper;
pub mod sockpath;
mod splice;
pub mod vault;

// The tests' stand-in decision source, shared with the integration tests (which reach it by
// `#[path]`), written against this crate's public items as `wicket_proxy::`.
#[cfg(test)]
extern crate self as wicket_proxy;
#[cfg(test)]
#[path = "../tests/support/zone_decider.rs"]
pub(crate) mod zone_decider;

use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use wicket_core::{CompiledZone, RunId, TenantId};
use wicket_store::Ledger;

/// What a run's enforcement points share.
#[derive(Clone)]
pub struct RunCtx {
    pub tenant: TenantId,
    pub run: RunId,
    /// The run's zone, its globs compiled once (it dereferences to the `ZoneSpec`).
    pub zone: Arc<CompiledZone>,
    /// The installation's org policy, compiled for this box at its start (#51): what the control
    /// host's own proxies check too (hosts it forwards for, injections, spawns, messages), as the
    /// box's token does on its node. None: no org policy.
    pub org: Option<Arc<wicket_authz::OrgLayer>>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub vault: vault::Vault,
    pub events: UnboundedSender<Event>,
    /// The zone's `escalation.request` (false by default for a program, #255): when false,
    /// out-of-reach requests fail without a pending request.
    pub escalate: bool,
    /// Who inside the box is making a request to (host, path), as reported by the agent's event
    /// stream: the attribution as JSON, plus a one-line summary. Untrusted; for humans only.
    pub attribute: Option<Attributor>,
    /// This agent instance's wicket-issued identity (design §3.2), rotated while it runs. None for
    /// programs.
    pub identity: Option<Arc<IdentityCell>>,
    /// Starts a child agent in its own box; None when the agent may not spawn.
    pub spawner: Option<Spawner>,
    /// Placeholders the box holds in place of real credentials, swapped at the egress proxy.
    pub swaps: Vec<CredentialSwap>,
    /// The boxes links reach (`expose`, `connect`, `link`); None where this box can't link.
    pub boxes: Option<Arc<dyn link::BoxOps>>,
    /// Asks for capacity leases (`request_capacity`, #7); None when this run may not.
    pub capacity: Option<CapacityHook>,
    /// Decides descendants' requests within this run's authority (`decide`, #50); None when this
    /// run may not (its zone has `escalation.grant: false`, or it is a program).
    pub decisions: Option<Arc<dyn Decisions>>,
    /// The long-lived agent this run is an activation of, and its generation (#70). Requests are
    /// refused once the agent's generation has moved past this one: a newer activation woke it.
    pub fence: Option<Fence>,
    /// Wakes a hibernated agent (a message just arrived for it). Set by the supervisor.
    pub waker: Option<Waker>,
    /// Where the agent's own lifetime requests go (`finish`, `hibernate`, #249): to its supervisor,
    /// which acts at the end of the agent's turn. None for programs.
    pub lifecycle: Option<Lifecycle>,
}

/// An activation's fencing token: the agent's generation when it was woken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fence {
    pub agent: String,
    pub generation: i64,
}

/// Asks for an agent to be woken, with what woke it.
pub type Waker = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// What an agent asks of its own lifetime (#249). wicket never ends or hibernates a run on a turn
/// boundary by itself: only when the agent (or an operator) asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// Close the session at the end of this turn: the harness exits, and the run ends.
    Finish,
    /// Hibernate at the end of this turn, at a quiet point.
    Hibernate,
}

/// Sends the agent's lifetime requests to its supervisor.
pub type Lifecycle = tokio::sync::mpsc::UnboundedSender<Want>;

/// What an agent asks for with `request_capacity` (#7): a node for a while, at most this price.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CapacityAsk {
    pub vcpus: u32,
    pub memory_mib: u64,
    /// `process`, `gvisor` or `vm`: the weakest isolation the node may offer.
    pub isolation: String,
    pub region: Option<String>,
    pub duration_secs: i64,
    /// The most the node may cost per hour, in dollars (e.g. "0.02").
    pub max_hourly_usd: String,
    pub reason: String,
}

pub enum CapacityCall {
    /// File a request (a pending lease and its approval request).
    Ask(CapacityAsk),
    /// Where a lease is.
    Status(String),
}

pub enum CapacityState {
    /// Still waiting (for a human, or for the node to come up): what to tell the agent.
    Waiting(String),
    /// Decided: usable, refused, or ended.
    Settled(String),
}

/// Ok: what to tell the agent. Err: why not.
pub type CapacityHook = Arc<dyn Fn(CapacityCall) -> std::result::Result<CapacityState, String> + Send + Sync>;

/// The payload kind of a decision envelope (#50): what the gateway signs for `decide`, never a
/// message (`send_message` signs `message`), so a message can't be presented as a decision.
pub const DECISION_KIND: &str = "decision";

/// Decisions an agent makes on its descendants' requests (#50, the `decide` tool). The gateway
/// signs each decision with this run's identity key; the hook verifies the envelope and checks the
/// decision is within the run's own authority before recording it.
pub trait Decisions: Send + Sync {
    /// The pending requests of this run's descendants that it could decide now.
    fn decidable(&self) -> std::result::Result<Vec<wicket_store::Request>, String>;
    /// Records the decision in `signed`, a [`DECISION_KIND`] envelope this run's gateway signed:
    /// what to tell the agent, or why it was refused (the request then stays pending).
    fn decide(&self, signed: &str) -> std::result::Result<String, String>;
}

/// A credential the box only ever sees as a placeholder. When a request to `host` carries exactly
/// `Authorization: Bearer <placeholder>`, the egress proxy sends the real value instead. The
/// placeholder is worthless anywhere else (it's stripped like every client credential), and the real
/// value never enters the box.
#[derive(Clone)]
pub struct CredentialSwap {
    /// For logs: what this credential is (never its value).
    pub name: String,
    pub host: String,
    pub placeholder: String,
    pub real: SwapSource,
    /// Whether, on this host, a bearer the box presents that isn't the placeholder goes upstream as
    /// the box sent it, rather than being dropped: for a harness that holds tokens of its own, which
    /// it got from this host's answers (a remote session's per-session tokens, #169). Never wicket's
    /// secret either way: only the placeholder is swapped.
    pub box_bearers: bool,
}

#[derive(Clone)]
pub enum SwapSource {
    /// A vault secret, read per request (e.g. a reference to the host's login, refreshed there).
    Vault(String),
    /// A value handed to wicket by the process that launched the agent, kept in memory only.
    Value(String),
}

/// An agent instance's identity: the document wicket issued and the key it signs with on the
/// agent's behalf. The key lives here, in the `wicket run` process, never in the box.
pub struct RunIdentity {
    pub jws: String,
    pub claims: wicket_identity::AgentClaims,
    pub key: wicket_identity::AgentKey,
    /// The installation issuer's public key, for verifying other agents' envelopes.
    pub issuer: wicket_identity::VerifyingKey,
}

/// The current identity of a run. The runner swaps in a fresh document and key every few minutes;
/// readers always take the latest.
pub struct IdentityCell(std::sync::RwLock<Arc<RunIdentity>>);

impl IdentityCell {
    pub fn new(i: RunIdentity) -> IdentityCell {
        IdentityCell(std::sync::RwLock::new(Arc::new(i)))
    }
    pub fn current(&self) -> Arc<RunIdentity> {
        self.0.read().expect("identity").clone()
    }
    pub fn replace(&self, i: RunIdentity) {
        *self.0.write().expect("identity") = Arc::new(i);
    }
}

/// A box an agent asks to start (design §5.1): an agent or a program, in a zone the agent writes
/// itself, which must be a subset of its own unless a human approves exactly that zone.
#[derive(Debug, Clone, Default)]
pub struct SpawnRequest {
    pub name: String,
    /// "agent" or "program" (a program can be a long-running service).
    pub kind: String,
    /// An agent's task.
    pub task: Option<String>,
    /// A program's command line.
    pub command: Vec<String>,
    /// Default: the parent's image.
    pub image: Option<String>,
    /// The new zone, in manifest form (JSON). Omitted fields default to the parent's (limits with the
    /// time it has left, isolation, unlisted_hosts) or to nothing (reach, inject, volumes).
    pub zone: Option<serde_json::Value>,
    pub max_children: u32,
    /// If the zone isn't a subset of the parent's, put exactly this zone up for approval instead of refusing.
    pub escalate: bool,
    /// Where to run it: `{"lease": "l-…"}` (a capacity lease this run holds) or `{"node": "<name>"}`.
    /// Default: where the parent runs.
    pub placement: Option<serde_json::Value>,
}

/// Ok: what to tell the agent (started, or waiting for approval). Err: why not.
pub type Spawner = Arc<dyn Fn(SpawnRequest) -> std::result::Result<String, String> + Send + Sync>;

/// Maximum size of a message body, in bytes of JSON.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

pub type Attributor = Arc<dyn Fn(&str, &str) -> Option<(serde_json::Value, String)> + Send + Sync>;

/// One line describing an attribution object, for terminals and logs.
pub fn attribution_line(v: &serde_json::Value) -> String {
    let rs = v.get("requesters").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let one = |r: &serde_json::Value| {
        let g = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_string();
        format!("{} via {}: {}", g("agent"), g("tool"), g("call").chars().take(80).collect::<String>())
    };
    match v.get("basis").and_then(|b| b.as_str()).unwrap_or("none") {
        "none" => "unknown (no tool call in flight)".into(),
        "ambiguous" => format!("one of: {}", rs.iter().map(one).collect::<Vec<_>>().join(" | ")),
        _ => rs.first().map(one).unwrap_or_default(),
    }
}

/// The agents an attribution object names.
pub fn attributed_agents(v: &serde_json::Value) -> Vec<String> {
    wicket_store::requesters(v)
}

/// Live events for the operator's console and the audit log.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Egress {
        method: String,
        host: String,
        path: String,
        risk: String,
        outcome: String,
        detail: String,
    },
    /// One model call. `input_tokens` is the uncached input; `cached_tokens` the cache reads and
    /// cache writes on top of it (all three count toward `max_input_tokens`).
    Llm {
        /// The zone's model provider (`zone.llm.provider`, #368: `gen_ai.provider.name` in OTLP).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        model: Option<String>,
        status: u16,
        input_tokens: u64,
        cached_tokens: u64,
        output_tokens: u64,
        requests: u64,
        outcome: String,
    },
    Tool {
        name: String,
        detail: String,
    },
    /// The box itself (#185): `memory_pressure` near its memory limit (the text for its agent).
    Box {
        what: String,
        detail: String,
    },
}

/// Who a message is for (#250): the sender's parent, or a principal by its identity.
#[derive(Clone, Copy, Debug)]
pub enum Recipient<'a> {
    Parent,
    Principal(&'a str),
}

/// A message sent: its id, the principal it is for, the run it reached (None: held until the
/// principal runs), and whether a hibernated agent is being woken for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub id: String,
    pub to: String,
    pub run: Option<String>,
    pub woke: bool,
}

/// How a message is sent (#252): how soon the sender wants it read, and the message it answers.
/// A reply to a message the recipient sent this principal needs no `accept_from`: the recipient
/// gave its reply address when it wrote.
#[derive(Clone, Copy, Debug, Default)]
pub struct SendOpts<'a> {
    pub priority: wicket_store::Priority,
    pub in_reply_to: Option<&'a str>,
}

/// Why a message wasn't sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// wicket refused it (#252): it has an id and a receipt that says why, and the refusal is on
    /// the record.
    Refused { id: String, to: String, why: String },
    /// It couldn't be sent at all (no such principal, too large, no identity): no receipt.
    Failed(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Refused { why, .. } => f.write_str(why),
            SendError::Failed(e) => f.write_str(e),
        }
    }
}

impl From<String> for SendError {
    fn from(e: String) -> SendError {
        SendError::Failed(e)
    }
}

impl From<&str> for SendError {
    fn from(e: &str) -> SendError {
        SendError::Failed(e.to_string())
    }
}

/// While a run waits (`await_message`, `await_grant`), its presence is `waiting` (#252); then what
/// it was, unless its supervisor has said something newer meanwhile (a node's push stream waits
/// between turns, not in one).
pub(crate) struct Waiting<'a>(&'a RunCtx, Option<String>);

impl<'a> Waiting<'a> {
    pub(crate) fn start(ctx: &'a RunCtx) -> Waiting<'a> {
        let before = ctx.ledger.lock().ok().and_then(|l| {
            let before = l.run_activity(&ctx.run.0).ok().flatten();
            let _ = l.set_run_activity(&ctx.run.0, Some("waiting"));
            before
        });
        Waiting(ctx, before.filter(|b| b != "waiting"))
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Ok(l) = self.0.ledger.lock() {
            let _ = l.restore_run_activity(&self.0.run.0, "waiting", self.1.as_deref());
        }
    }
}

impl RunCtx {
    /// Why this activation may no longer act, if a newer one has superseded it (or its agent is
    /// gone). Checked by every proxy on every request.
    pub fn superseded(&self) -> Option<String> {
        let f = self.fence.as_ref()?;
        let current = self.ledger.lock().ok().map(|l| l.agent_generation(&f.agent));
        match current {
            Some(Ok(Some(g))) if g == f.generation => None,
            Some(Ok(Some(g))) => {
                Some(format!("agent {} was woken again (generation {g}); this activation (generation {}) is stale", f.agent, f.generation))
            }
            Some(Ok(None)) => Some(format!("agent {} no longer exists", f.agent)),
            _ => Some("the ledger can't be read to check this activation's generation".into()),
        }
    }

    /// Sends a signed message from this agent to a principal (#250): its parent, or an agent named by
    /// its identity (`spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>`), never by a run. The sender
    /// is this run's identity, set by wicket; the agent can't choose it. Allowed between parent and
    /// child, or when the recipient's `accept_from` lists this agent or its zone, within one tenant.
    ///
    /// The message goes to the principal's live run. Without one it is held: a hibernated agent is
    /// woken to read it, and otherwise the principal's next run takes it ([`wicket_store::MESSAGE_HOLD_SECS`]).
    /// A message never grants authority: it is data for the recipient.
    pub fn send_message(&self, to: &Recipient, kind: &str, body: serde_json::Value) -> std::result::Result<Sent, String> {
        self.send(to, kind, body, SendOpts::default()).map_err(|e| e.to_string())
    }

    /// [`Self::send_message`], with a priority and the message it answers (#252). A message
    /// `accept_from` doesn't allow is refused on the record, with a receipt that says so.
    pub fn send(&self, to: &Recipient, kind: &str, body: serde_json::Value, opts: SendOpts) -> std::result::Result<Sent, SendError> {
        let me = self.identity.as_ref().ok_or("this run has no wicket identity")?.current();
        let now = wicket_store::now();
        if me.claims.exp <= now {
            return Err("this agent's identity has expired and was not refreshed; it can't send".into());
        }
        let size = body.to_string().len();
        if size > MAX_MESSAGE_BYTES {
            return Err(format!("message body is {size} bytes; the limit is {MAX_MESSAGE_BYTES}").into());
        }
        let mut l = self.ledger.lock().map_err(|_| "ledger lock")?;
        if let Some((r, ..)) = l.revoked_in_chain(&self.run.0).map_err(|e| e.to_string())? {
            return Err(format!("this agent's identity was revoked (revoked: {r})").into());
        }
        // Who it is for, and the run it should reach first (a child's parent is that run).
        let (principal, prefer) = match to {
            Recipient::Parent => {
                let p = me.claims.parent_run.clone().ok_or("this agent has no parent")?;
                match l.identity(&p).map_err(|e| e.to_string())? {
                    Some(r) if r.tenant == self.tenant.0 => (r.spiffe_id, Some(p)),
                    _ => return Err("this agent's parent has no wicket identity".into()),
                }
            }
            Recipient::Principal(id) => match wicket_identity::Principal::parse(id) {
                Some(wicket_identity::Principal::Agent { .. }) => (id.to_string(), None),
                Some(wicket_identity::Principal::Operator { .. }) => {
                    return Err(format!("{id} is an operator: operators don't receive messages from agents yet (#250); write to your result instead").into())
                }
                None => {
                    return Err(format!(
                        "{id:?} is not a principal: name one by its identity (spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>, as whoami and spawn show it), or \"parent\""
                    )
                    .into())
                }
            },
        };
        let rec = match l.principal_identity(&self.tenant.0, &principal).map_err(|e| e.to_string())? {
            Some(r) if r.tenant == self.tenant.0 => r,
            _ => return Err(format!("no agent {principal}: none has run as it in this tenant").into()),
        };
        // The run it is for: the preferred one while it runs, else the principal's live run. A
        // long-lived agent (#70) with none is woken to read it if it is hibernated; any other
        // principal's message is held for its next run.
        let running = |l: &wicket_store::Ledger, r: &str| l.run_status(r).ok().flatten().as_deref() == Some("running");
        let mut to_run = match prefer.clone().filter(|p| running(&l, p)) {
            Some(p) => Some(p),
            None => l.live_run_of(&self.tenant.0, &principal).map_err(|e| e.to_string())?,
        };
        let mut wake: Option<String> = None;
        if to_run.is_none() {
            let agent = match l.agent_of_run(&rec.run).map_err(|e| e.to_string())? {
                Some((id, _)) => l.agent(&id).map_err(|e| e.to_string())?,
                None => None,
            };
            match agent {
                Some(a) if a.restorable && a.state == "hibernated" && self.waker.is_some() => wake = Some(a.id),
                Some(a) if a.restorable && wicket_store::AGENT_HELD.contains(&a.state.as_str()) => to_run = Some(a.run),
                _ => {}
            }
        }
        // A reply (#252): to a message this principal sent us, which gave its reply address.
        let replies = match opts.in_reply_to {
            None => false,
            Some(m) => match l.message_row(m).map_err(|e| e.to_string())? {
                Some(r)
                    if r.tenant == self.tenant.0
                        && r.to_principal.as_deref() == Some(me.claims.sub.as_str())
                        && (r.from_principal.as_deref() == Some(principal.as_str())
                            || (r.from_principal.is_none()
                                && l.identity(&r.from_run).ok().flatten().is_some_and(|i| i.spiffe_id == principal))) =>
                {
                    true
                }
                _ => return Err(format!("in_reply_to {m} is not a message {principal} sent you").into()),
            },
        };
        let id = format!("m-{}", wicket_core::new_ulid().to_string().to_lowercase());
        let relation = if rec.parent_run.as_deref() == Some(&self.run.0) {
            "child"
        } else if prefer.is_some()
            || me.claims.parent_run.as_deref().is_some_and(|p| l.identity(p).ok().flatten().is_some_and(|i| i.spiffe_id == principal))
        {
            "parent"
        } else if wicket_core::manifest::accepts(&rec.accept_from, &self.zone.name, Some(&me.claims.sub)) {
            "peer"
        } else if replies {
            "reply"
        } else {
            // Refused on the record (#252): the sender has a receipt that says so, and nothing
            // reaches the recipient.
            let why = format!(
                "{principal} does not accept messages from you ({}, zone {}): its accept_from lists neither",
                me.claims.sub, self.zone.name
            );
            l.refuse_message(&id, &self.tenant.0, &self.run.0, Some(&me.claims.sub), &principal, &why).map_err(|e| e.to_string())?;
            let audited = l.audit(
                &self.tenant,
                Some(&self.run),
                "message.refused",
                &serde_json::json!({ "id": id, "kind": kind, "from": me.claims.sub, "to": principal, "why": "accept_from", "bytes": size }),
            );
            if let Err(e) = audited {
                return Err(format!("not sent: the audit record could not be written ({e})").into());
            }
            return Err(SendError::Refused { id, to: principal, why });
        };
        let payload = serde_json::json!({
            "jti": id, "iat": now, "kind": kind, "to": principal, "body": body,
            "reply_to": me.claims.sub, "priority": opts.priority.as_str(), "in_reply_to": opts.in_reply_to,
        });
        let env = wicket_identity::sign_envelope(&me.key, &me.jws, &payload);
        let meta =
            wicket_store::MessageMeta { from_principal: Some(&me.claims.sub), priority: opts.priority, in_reply_to: opts.in_reply_to };
        // A wake's claim moves the message to the new run, as the new run's identity does a held one.
        let routed =
            l.post_message(&id, &self.tenant, &self.run.0, &principal, to_run.as_deref(), &env, &meta).map_err(|e| e.to_string())?;
        // A message is delivered only once its audit record is on disk (fail closed).
        let audited = l.audit(
            &self.tenant,
            Some(&self.run),
            "message",
            &serde_json::json!({
                "id": id, "kind": kind, "from": me.claims.sub, "to": principal, "to_run": routed, "relation": relation, "bytes": size,
                "wakes": wake, "held": routed.is_none(), "priority": opts.priority.as_str(), "in_reply_to": opts.in_reply_to,
            }),
        );
        if let Err(e) = audited {
            let _ = l.withdraw_message(&id);
            return Err(format!("not sent: the audit record could not be written ({e})").into());
        }
        drop(l);
        // Wake the recipient only once the message and its audit record are on disk.
        if let (Some(agent), Some(w)) = (&wake, &self.waker) {
            w(agent, &format!("a message from {} ({})", me.claims.agent, self.run.0));
        }
        Ok(Sent { id, to: principal, run: routed, woke: wake.is_some() })
    }

    /// Records an event in the audit log and sends it to the console. A failure to record is
    /// dropped: for events that must be on disk before their request goes ahead, use
    /// [`record`](Self::record), which fails closed.
    pub(crate) fn emit(&self, ev: Event) {
        let _ = self.record(ev);
    }

    /// Records an event in the audit log, then sends it to the console.
    ///
    /// With the batched audit writer (#62), most records are queued and committed within
    /// milliseconds, off the request path. A request allowed by a human's grant waits for its
    /// record's commit ([`must_be_durable`]): the use of an approval is on disk before it takes
    /// effect. If that commit fails, this returns the error (and the event is not shown as
    /// allowed): the caller must refuse the request. The ledger lock is held only to look up the
    /// writer, never across a commit.
    pub(crate) fn record(&self, ev: Event) -> std::result::Result<(), String> {
        let durable = must_be_durable(&ev);
        let v = serde_json::to_value(&ev).map_err(|e| e.to_string())?;
        let writer = match self.ledger.lock() {
            Ok(l) => match l.audit_writer() {
                Some(w) => Some(w),
                None => {
                    let r = l.audit(&self.tenant, Some(&self.run), "op", &v);
                    if durable {
                        r.map_err(|e| e.to_string())?;
                    }
                    None
                }
            },
            Err(_) if durable => return Err("the ledger lock is poisoned".into()),
            Err(_) => None,
        };
        if let Some(w) = writer {
            if durable {
                let t = w.enqueue(&self.tenant, Some(&self.run), "op", &v).map_err(|e| e.to_string())?;
                let mut r = Ok(0);
                wait_blocking(|| r = t.wait());
                r.map_err(|e| e.to_string())?;
            } else {
                let _ = w.submit(&self.tenant, Some(&self.run), "op", &v);
            }
        }
        let _ = self.events.send(ev);
        Ok(())
    }
}

/// Whether an event's audit record must be committed before the request it describes goes ahead:
/// a request allowed by a grant (a human's approval, consumed here or counted on a node). Requests
/// allowed by the zone's reach and refusals are recorded without waiting.
pub fn must_be_durable(ev: &Event) -> bool {
    matches!(ev, Event::Egress { outcome, detail, .. } if outcome == "allow" && detail.starts_with("grant "))
}

/// Runs a blocking wait without stalling other tasks on a multi-threaded tokio runtime.
fn wait_blocking(f: impl FnOnce()) {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

pub(crate) type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) fn full(b: impl Into<bytes::Bytes>) -> BoxBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(b.into()).map_err(|never| match never {}).boxed()
}

/// An RFC 9457 problem+json response that tells the agent what happened and what it can do.
pub(crate) fn problem(status: u16, kind: &str, title: &str, detail: &str, request_id: Option<&str>) -> http::Response<BoxBody> {
    let mut body = serde_json::json!({
        "type": format!("https://wicket.dev/e/{kind}"),
        "title": title,
        "status": status,
        "detail": detail,
    });
    if let Some(id) = request_id {
        body["request_id"] = id.into();
        body["retry_after"] = 30.into();
        body["hint"] = format!("Call the wicket MCP tool await_grant with request_id {id} to wait for the decision, then retry this same request once. Nothing else will reach this destination from the box.").into();
    }
    let mut b = http::Response::builder().status(status).header("content-type", "application/problem+json").header("x-wicket", kind);
    if let Some(id) = request_id {
        b = b.header("x-wicket-request-id", id).header("retry-after", "30");
    }
    let mut resp = b.body(full(serde_json::to_vec_pretty(&body).unwrap_or_default())).expect("valid response");
    // Many tools show only the status line, not the body: make it say what happened.
    let reason: String = match request_id {
        Some(id) => format!("{title} ({id})"),
        None => title.to_string(),
    }
    .chars()
    .filter(|c| c.is_ascii() && !c.is_ascii_control())
    .collect();
    if let Ok(r) = hyper::ext::ReasonPhrase::try_from(reason) {
        resp.extensions_mut().insert(r);
    }
    resp
}

/// Seconds a box is told to wait (`Retry-After`) when its node can't decide right now (#352).
pub(crate) const UNAVAILABLE_RETRY_AFTER: u64 = 5;

/// The answer when this node can't decide a request right now: it is catching up with its policy
/// feed, holds no valid policy, or can't reach the control host (#352). These conditions pass, so
/// the answer is 503 with `Retry-After`, which HTTP clients and model SDKs retry (Claude Code
/// retries every 5xx from the Messages API; a 429 it may read as a usage limit, a 403 as an
/// authentication failure that ends its turn). 403 stays for refusals that retrying doesn't change.
pub(crate) fn unavailable(detail: &str) -> http::Response<BoxBody> {
    let mut body = serde_json::json!({
        "type": "https://wicket.dev/e/unavailable",
        "title": "Blocked by wicket box: control host unreachable",
        "status": 503,
        "detail": detail,
        "retry_after": UNAVAILABLE_RETRY_AFTER,
    });
    body["hint"] = "This is temporary: retry this same request in a few seconds.".into();
    let mut resp = problem(503, "unavailable", "Blocked by wicket box: control host unreachable", detail, None);
    *resp.body_mut() = full(serde_json::to_vec_pretty(&body).unwrap_or_default());
    resp.headers_mut().insert(http::header::RETRY_AFTER, http::HeaderValue::from(UNAVAILABLE_RETRY_AFTER));
    resp
}

/// What every refusal reminds the agent of: where it is, and that there is no other way out.
/// What an agent whose zone may not ask (`escalation.request: false`, #50) is told when it asks.
pub const NEVER_ASKS: &str = "this zone may not ask for anything outside its reach (escalation.request: false), so this will never be allowed from this box; tell the user";

pub(crate) const BOX_FACT: &str = "You are in a wicket box (a gVisor container with no network of its own); wicket's proxy is its only route out, so no other tool, host, mirror or cache will reach this either.";

/// Request headers the egress proxy forwards from a box to any upstream (#130, design §9.0): content
/// negotiation, caching and conditional requests, the body's own description, and git's protocol
/// version. Every other header is dropped; [`provider_request_header`] adds a provider's own.
pub(crate) const FORWARD_REQUEST: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-encoding",
    "content-language",
    "content-type",
    "git-protocol",
    "idempotency-key",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "origin",
    "pragma",
    "range",
    "referer",
    "user-agent",
    "x-request-id",
];

/// A provider's own request headers, forwarded to its hosts only (what an adapter would declare).
pub(crate) fn provider_request_header(host: &str, name: &str) -> bool {
    match host {
        "api.github.com" | "uploads.github.com" => name == "x-github-api-version",
        // A model provider's host: its profile's headers (wrapped sessions' model and remote traffic).
        _ => crate::provider::for_host(host).is_some_and(|p| (p.request_header)(name)),
    }
}

/// Headers that make some servers run a request as another method or on another path than the one
/// decided: a request carrying one is refused outright (#130).
pub(crate) const REFUSE_REQUEST: &[&str] =
    &["x-http-method-override", "x-http-method", "x-method-override", "x-original-method", "x-original-url", "x-rewrite-url"];

/// The methods the egress proxy forwards. TRACE, TRACK, CONNECT inside a tunnel and anything
/// unknown are refused.
pub(crate) const FORWARD_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Hop-by-hop response headers, never passed on.
pub(crate) const HOP_BY_HOP: &[&str] = &["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"];

/// Response headers the LLM proxy drops: hop-by-hop, and the length (it may rewrite the body).
pub(crate) const STRIP_RESPONSE: &[&str] = &["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length"];

#[cfg(test)]
mod fence_tests {
    //! #70: an activation superseded by a newer wake is refused at every enforcement point (the LLM
    //! proxy's test is in llm.rs).
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stale activation's context: its agent has been woken again (generation 2).
    fn stale_ctx() -> RunCtx {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let agent = wicket_store::new_agent_id();
        ledger
            .create_agent(&wicket_store::NewAgent {
                id: &agent,
                tenant: "t0",
                zone: "z",
                name: "a",
                run: "run_old",
                session_id: "s",
                manifest: "m",
                image: "i",
                workspace: None,
                claim_until: 0,
            })
            .unwrap();
        assert!(ledger.commit_agent_push(&agent, 1, 0, 1, "h", 1).unwrap());
        assert_eq!(ledger.claim_wake(&agent, "run_new", 0).unwrap(), Some(2));
        let m = wicket_core::Manifest::from_yaml(
            "task: t\nagent: {name: a}\nzone: {name: z, llm: {}, reach: [{host: example.com, methods: [GET]}]}",
        )
        .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_old".into()),
            zone: Arc::new(CompiledZone::new(m.zone.clone()).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(ledger)),
            vault: vault::Vault::new(std::env::temp_dir().join("wicket-fence-no-vault")),
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            decisions: None,
            fence: Some(Fence { agent, generation: 1 }),
            waker: None,
            lifecycle: None,
        }
    }

    /// Sends one raw HTTP/1.1 request to a unix socket once it exists; returns the response head and body.
    async fn raw(sock: &std::path::Path, req: &str) -> String {
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut s = tokio::net::UnixStream::connect(sock).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = vec![0u8; 16 * 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut out)).await.unwrap().unwrap();
        String::from_utf8_lossy(&out[..n]).into_owned()
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-fence-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn the_egress_proxy_refuses_a_stale_generation() {
        let ctx = stale_ctx();
        let ca = Arc::new(ca::RunCa::generate("run_old").unwrap());
        let egress = egress::Egress::with(ctx, ca, Arc::new(zone_decider::ZoneDecider), None).unwrap();
        let d = dir("egress");
        let sock = d.join("egress.sock");
        let server = tokio::spawn({
            let sock = sock.clone();
            async move { egress.serve(&sock).await }
        });
        // In reach, so only the fence can refuse it: a CONNECT and a plain request.
        let r = raw(&sock, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 403") && r.contains("stale"), "{r}");
        let r = raw(&sock, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 403") && r.contains("stale"), "{r}");
        server.abort();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn the_gateway_refuses_a_stale_generation() {
        let gw = gateway::Gateway::new(stale_ctx());
        for tool in ["links", "await_grant", "send_message"] {
            let (text, is_error) = gw.call_tool(tool, serde_json::json!({})).await;
            assert!(is_error && text.contains("stale"), "{tool}: {text}");
        }
    }
}
