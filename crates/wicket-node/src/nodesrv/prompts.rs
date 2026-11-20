//! A driven harness's tool prompts, answered on its box's node (#257 step 8). The node reads the
//! requests the harness starts from the box's stdout ([`wicket_home::control::Prompts`]) and
//! answers them on its stdin; the control host keeps the requests wicket starts (an interrupt, a
//! mode change). What it decides from, in order:
//!
//! 1. `bypassPermissions` (the manifest's mode, or an operator's `/mode`, [`Msg::PromptMode`]):
//!    allowed at once;
//! 2. a TOOL grant for the call in the box's record in this node's replica
//!    ([`wicket_feed::Replica::decide_tool`]), its use recorded on disk first;
//! 3. a zone that may not ask: refused;
//! 4. a human: [`chan::ControlTool::ToolPrompt`], which raises (or finds) the request on the control
//!    host and answers with its state when it is decided. A granted request is answered from the
//!    replica again, once its grant has reached it.
//!
//! Cut off from the control host, a prompt that needs a human waits for it [`OFFLINE_WAIT`], then is
//! refused: the harness never waits on a node that can't ask. A cancel from the harness ends the
//! wait ([`Step::Withdrawn`]).
//!
//! **Stdin.** An answer goes in the box's stdin feed only at a line boundary of what the control
//! host wrote (else it is held until that line ends), under the box's lock, so neither splits the
//! other's line. The node's answers are counted apart from the control host's bytes
//! (`stdin_answered`), whose offsets they never change. What the node keeps of the box's prompts
//! (the ids answered, the prompts waiting, the mode) is saved in its record before an answer is
//! fed, so none is answered twice after a restart.

use super::*;
use std::time::Duration;
use wicket_home::control::{Prompt, Prompts, Step};

/// How long a prompt that needs a human waits for an unreachable control host before it is refused.
pub(super) const OFFLINE_WAIT: Duration = Duration::from_secs(120);

/// How long a granted request's grant may take to reach this node's replica.
const GRANT_ARRIVES: Duration = Duration::from_secs(15);

/// The refusal while cut off.
const CUT_OFF: &str = "wicket's control host has been unreachable from this node, so nobody could approve this call; retry it later";

/// What a node keeps of a box's prompts in its record.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct Kept {
    /// Bytes of the box's stdin the node wrote itself (its answers), besides the control host's.
    #[serde(default)]
    pub stdin_answered: u64,
    #[serde(default)]
    pub answered: Vec<String>,
    #[serde(default)]
    pub waiting: Vec<String>,
    /// An operator's mode change since the box started (else the manifest's).
    #[serde(default)]
    pub mode: Option<wicket_core::RemotePermissionMode>,
}

/// A box's prompts on this node.
pub(super) struct BoxPrompts {
    pub p: Prompts,
    /// Whether the control host's last stdin bytes ended mid-line, and the answers held until it ends.
    mid_line: bool,
    held: Vec<Vec<u8>>,
    /// The decisions running, by prompt id.
    deciding: HashMap<String, tokio::task::AbortHandle>,
}

impl BoxPrompts {
    /// The box's prompts, if its harness has a control channel, picked up from its record; the
    /// prompts still waiting are raised again (the steps to run once the box is wired).
    pub fn of(bs: &BoxStart, kept: &Kept) -> Option<(BoxPrompts, Vec<Step>)> {
        let edge = bs.edge.as_ref()?.prompts.as_ref()?;
        let control = wicket_agent::harness::adapter(edge.harness).controller()?;
        let mut p = Prompts::new(control, kept.mode.unwrap_or(edge.mode));
        let steps = p.restore(&kept.answered, &kept.waiting);
        Some((BoxPrompts { p, mid_line: false, held: vec![], deciding: HashMap::new() }, steps))
    }
}

/// Feeds the control host's stdin bytes to the box, then any answers held for the end of its line.
pub(super) fn push_host_stdin(b: &mut BoxState, fresh: &[u8]) {
    let Some(s) = &b.stdin else { return };
    s.push(fresh);
    b.record.stdin_received = b.stdin_next;
    if let (Some(bp), Some(last)) = (b.prompts.as_mut(), fresh.last()) {
        bp.mid_line = *last != b'\n';
        if !bp.mid_line {
            for h in std::mem::take(&mut bp.held) {
                s.push(&h);
                b.record.prompts.stdin_answered += h.len() as u64;
            }
        }
    }
    let _ = b.record.save(&b.dir);
}

/// Runs the steps that need the box's lock (its stdin, its record) and returns the rest.
fn apply_locked(b: &mut BoxState, steps: Vec<Step>) -> Vec<Step> {
    let Some(bp) = b.prompts.as_mut() else { return vec![] };
    b.record.prompts.answered = bp.p.answered();
    b.record.prompts.waiting = bp.p.waiting_lines();
    let mut writes = vec![];
    let mut rest = vec![];
    for st in steps {
        match st {
            Step::Write(l) => writes.push(format!("{l}\n").into_bytes()),
            Step::Withdrawn(id) => {
                if let Some(h) = bp.deciding.remove(&id) {
                    h.abort();
                }
            }
            other => rest.push(other),
        }
    }
    // Saved before it is fed: a restart never answers it again.
    let _ = b.record.save(&b.dir);
    for w in writes {
        match (&b.stdin, bp.mid_line) {
            (Some(s), false) => {
                s.push(&w);
                b.record.prompts.stdin_answered += w.len() as u64;
            }
            (Some(_), true) => bp.held.push(w),
            (None, _) => {}
        }
    }
    let _ = b.record.save(&b.dir);
    rest
}

/// Steps from a box's prompts: what needs its lock is run under it; audits, the operator's lines
/// and decisions after.
pub(super) fn apply(n: &Arc<Node>, run: &str, steps: Vec<Step>) {
    if steps.is_empty() {
        return;
    }
    let (rest, tenant) = {
        let mut boxes = n.boxes.lock().expect("boxes");
        let Some(b) = boxes.get_mut(run) else { return };
        (apply_locked(b, steps), b.record.start.tenant.clone())
    };
    after(n, run, &tenant, rest);
}

/// The box's stdout bytes, read under its lock: what its prompts make of them.
pub(super) fn on_stdout(b: &mut BoxState, bytes: &[u8]) -> Vec<Step> {
    match b.prompts.as_mut() {
        Some(bp) => {
            let steps = bp.p.on_bytes(bytes);
            apply_locked(b, steps)
        }
        None => vec![],
    }
}

/// What is left once the box's lock is released.
pub(super) fn after(n: &Arc<Node>, run: &str, tenant: &str, steps: Vec<Step>) {
    for st in steps {
        match st {
            Step::Audit(body) => {
                let _ = n.audit.lock().expect("audit").audit(
                    &wicket_core::TenantId(tenant.into()),
                    Some(&wicket_core::RunId(run.into())),
                    "run.agent_prompt",
                    &body,
                );
            }
            Step::Say(line) => {
                let ev = wicket_proxy::Event::Tool { name: "tool prompt".into(), detail: format!("{line} (on node {})", n.name) };
                if let Ok(event) = serde_json::to_value(&ev) {
                    n.send_run(run, Frame::Msg(Msg::Event { run: run.into(), event }));
                }
            }
            Step::Decide(p) => {
                let (n2, run2, id) = (n.clone(), run.to_string(), p.id.clone());
                let task = tokio::spawn(async move {
                    let (allow, why, request) = decide(&n2, &run2, &p).await;
                    let steps = {
                        let mut boxes = n2.boxes.lock().expect("boxes");
                        match boxes.get_mut(&run2).and_then(|b| b.prompts.as_mut()) {
                            Some(bp) => {
                                bp.deciding.remove(&p.id);
                                bp.p.answer(&p, allow, &why, request.as_deref())
                            }
                            None => vec![],
                        }
                    };
                    apply(&n2, &run2, steps);
                });
                let mut boxes = n.boxes.lock().expect("boxes");
                match boxes.get_mut(run).and_then(|b| b.prompts.as_mut()) {
                    Some(bp) if bp.p.is_waiting(&id) => {
                        bp.deciding.insert(id, task.abort_handle());
                    }
                    _ => task.abort(),
                }
            }
            Step::Write(_) | Step::Withdrawn(_) => {}
        }
    }
}

/// An operator changed the harness's mode ([`Msg::PromptMode`]): kept in the box's record.
pub(super) fn set_mode(b: &mut BoxState, mode: wicket_core::RemotePermissionMode) {
    if let Some(bp) = b.prompts.as_mut() {
        bp.p.set_mode(mode);
        b.record.prompts.mode = Some(mode);
        let _ = b.record.save(&b.dir);
    }
}

/// The prompt's op, for its box.
fn op_of(rec: &BoxRecord, p: &Prompt) -> wicket_core::Op {
    let (tenant, run) = (wicket_core::TenantId(rec.start.tenant.clone()), wicket_core::RunId(rec.start.run.clone()));
    wicket_home::control::op(&tenant, &run, &rec.start.zone, &p.tool, &p.kind, &p.digest)
}

/// The replica's decision on the prompt's op, now.
fn from_replica(n: &Node, op: &wicket_core::Op) -> wicket_feed::Decision {
    let now = (n.clock)();
    n.replica.lock().expect("replica").decide_tool(op, now)
}

/// Decides one prompt: whether to allow it, why, and the human's request it waited on.
async fn decide(n: &Arc<Node>, run: &str, p: &Prompt) -> (bool, String, Option<String>) {
    decide_within(n, run, p, OFFLINE_WAIT, Duration::from_secs(2)).await
}

/// [`decide`], cut off for at most `offline` before it refuses, trying again every `retry`.
async fn decide_within(n: &Arc<Node>, run: &str, p: &Prompt, offline: Duration, retry: Duration) -> (bool, String, Option<String>) {
    use wicket_feed::{Allowed, Decision};
    let Some((op, escalate)) = n.boxes.lock().expect("boxes").get(run).map(|b| (op_of(&b.record, p), b.record.start.escalate)) else {
        return (false, "the box is gone".into(), None);
    };
    match from_replica(n, &op) {
        Decision::Allow(Allowed::Grant(g)) => return (true, format!("approved (grant {g}, counted on the node)"), None),
        Decision::Forbidden(why) => return (false, why, None),
        _ => {}
    }
    if !escalate {
        return (false, "this zone may not ask for approval (escalation.request: false), and the call needs one".into(), None);
    }
    let args = serde_json::json!({ "tool": p.tool, "kind": p.kind, "detail": p.detail, "digest": p.digest, "timeout_seconds": 300 });
    let mut cut_off: Option<Instant> = None;
    loop {
        match n.call_control(run, chan::ControlTool::ToolPrompt, &args).await {
            Ok((text, is_error)) => {
                cut_off = None;
                let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                let request = v.get("request").and_then(|r| r.as_str()).map(String::from);
                let why = v.get("why").and_then(|r| r.as_str()).unwrap_or(&text).to_string();
                match (is_error, v.get("state").and_then(|s| s.as_str())) {
                    (false, Some("pending")) => continue,
                    (false, Some("granted")) => {
                        let r = request.clone().unwrap_or_default();
                        let start = Instant::now();
                        loop {
                            match from_replica(n, &op) {
                                Decision::Allow(Allowed::Grant(g)) => {
                                    return (true, format!("request {r} was approved (grant {g}, counted on the node)"), request)
                                }
                                Decision::Forbidden(why) => return (false, why, request),
                                _ if start.elapsed() > GRANT_ARRIVES => {
                                    return (
                                        false,
                                        format!("request {r} was approved, but no grant on this node covers this call (used, or not here yet): ask again"),
                                        request,
                                    )
                                }
                                _ => tokio::time::sleep(Duration::from_millis(250)).await,
                            }
                        }
                    }
                    _ => return (false, why, request),
                }
            }
            Err(_) => {
                let since = *cut_off.get_or_insert_with(Instant::now);
                if since.elapsed() >= offline {
                    return (false, CUT_OFF.into(), None);
                }
                tokio::time::sleep(retry).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodeauth::testkit::Install;
    use serde_json::json;

    fn can_use_tool(id: &str, tool: &str, input: serde_json::Value) -> String {
        json!({ "type": "control_request", "request_id": id, "request": { "subtype": "can_use_tool", "tool_name": tool, "input": input } })
            .to_string()
            + "\n"
    }

    fn fed(b: &BoxState) -> String {
        let s = b.stdin.as_ref().unwrap();
        let g = s.buf.lock().unwrap();
        String::from_utf8(g.0.since(0).1).unwrap()
    }

    /// (a) of #257 step 8: the node's answer never splits a line the control host is writing, it
    /// is counted apart from the control host's bytes, and it is given once, across a replay of
    /// the box's output and a restart of the node.
    #[tokio::test]
    async fn an_answer_waits_for_the_control_hosts_line_and_is_given_once() {
        let inst = Install::new("prompts-stdin");
        let node = super::super::tests::test_node(&inst);
        let mut rec = super::super::tests::fake_record("run_p");
        rec.start.edge = Some(Box::new(chan::EdgeStart {
            who: json!({}),
            spawn: None,
            push: None,
            ca_widen: None,
            prompts: Some(chan::EdgePrompts {
                harness: wicket_core::Harness::ClaudeCode,
                mode: wicket_core::RemotePermissionMode::Default,
            }),
        }));
        let dir = inst.dir.join("runs/run_p");
        std::fs::create_dir_all(&dir).unwrap();
        let (bp, restored) = BoxPrompts::of(&rec.start, &rec.prompts).unwrap();
        assert!(restored.is_empty());
        let mut b = BoxState {
            streams: [1, 2, 3],
            name: "wicket-run-p".into(),
            dir: dir.clone(),
            stdin: Some(Arc::new(StdinFeed::new(0, false))),
            stdin_next: 0,
            out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
            exited: None,
            ended: false,
            tasks: vec![],
            user: String::new(),
            cpus: 1.0,
            memory_mib: 1,
            listeners: HashMap::new(),
            owner: Some(1),
            prompts: Some(bp),
            record: rec,
        };
        // The control host is mid-line when the harness asks something wicket's rule refuses.
        b.stdin_next = 4;
        push_host_stdin(&mut b, b"{\"ty");
        let ask = can_use_tool("cc-1", "Write", json!({ "file_path": "/workspace/.claude/settings.json" }));
        let rest = on_stdout(&mut b, ask.as_bytes());
        assert!(rest.iter().any(|s| matches!(s, Step::Audit(a) if a["answer"] == "deny")), "{rest:?}");
        assert_eq!(fed(&b), "{\"ty", "held until the control host's line ends");
        b.stdin_next = 11;
        push_host_stdin(&mut b, b"pe\":1}\n");
        let all = fed(&b);
        let (host, answer) = all.split_at("{\"type\":1}\n".len());
        assert_eq!(host, "{\"type\":1}\n");
        let v: serde_json::Value = serde_json::from_str(answer.trim_end()).unwrap();
        assert_eq!((v["response"]["request_id"].as_str(), v["response"]["response"]["behavior"].as_str()), (Some("cc-1"), Some("deny")));
        assert_eq!(b.record.stdin_received, 11, "the control host's count is its own");
        assert_eq!(b.record.prompts.stdin_answered, answer.len() as u64);
        // A replay of the same output answers nothing more.
        assert!(on_stdout(&mut b, ask.as_bytes()).is_empty());
        assert_eq!(fed(&b), all);
        // Nor does a node restarted from the saved record.
        let saved = BoxRecord::load(&dir).unwrap();
        assert_eq!(saved.prompts.answered, ["cc-1"]);
        let (mut again, restored) = BoxPrompts::of(&saved.start, &saved.prompts).unwrap();
        assert!(restored.is_empty());
        assert!(again.p.on_bytes(ask.as_bytes()).is_empty());
        // A prompt for a human waits in the record, and is raised again after a restart.
        let ask2 = can_use_tool("cc-2", "Bash", json!({ "command": "make" }));
        let rest = on_stdout(&mut b, ask2.as_bytes());
        assert!(matches!(&rest[..], [Step::Decide(p)] if p.id == "cc-2"), "{rest:?}");
        let saved = BoxRecord::load(&dir).unwrap();
        let (_, restored) = BoxPrompts::of(&saved.start, &saved.prompts).unwrap();
        assert!(matches!(&restored[..], [Step::Decide(p)] if p.id == "cc-2"), "{restored:?}");
        drop(node);
    }

    /// (c): a prompt that needs a human while its node is cut off is refused after the wait, so
    /// the harness never waits on a node that can't ask; a zone that may not ask is refused at once.
    #[tokio::test]
    async fn cut_off_a_prompt_for_a_human_is_refused_after_a_while() {
        let inst = Install::new("prompts-cut-off");
        let node = super::super::tests::test_node(&inst);
        let rec = super::super::tests::fake_record("run_c");
        let dir = inst.dir.join("runs/run_c");
        std::fs::create_dir_all(&dir).unwrap();
        node.boxes.lock().unwrap().insert(
            "run_c".into(),
            BoxState {
                streams: [1, 2, 3],
                name: "wicket-run-c".into(),
                dir,
                stdin: None,
                stdin_next: 0,
                out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
                exited: None,
                ended: false,
                tasks: vec![],
                user: String::new(),
                cpus: 1.0,
                memory_mib: 1,
                listeners: HashMap::new(),
                owner: None,
                prompts: None,
                record: rec,
            },
        );
        let p = Prompt { id: "cc-1".into(), tool: "Bash".into(), kind: "execute".into(), detail: "make".into(), digest: "ab".into() };
        let t = Instant::now();
        let (allow, why, request) = decide_within(&node, "run_c", &p, Duration::from_millis(300), Duration::from_millis(50)).await;
        assert!(!allow && why == CUT_OFF && request.is_none(), "{why}");
        assert!(t.elapsed() >= Duration::from_millis(300) && t.elapsed() < Duration::from_secs(10));
        node.boxes.lock().unwrap().get_mut("run_c").unwrap().record.start.escalate = false;
        let (allow, why, _) = decide_within(&node, "run_c", &p, Duration::from_secs(60), Duration::from_secs(1)).await;
        assert!(!allow && why.contains("escalation.request: false"), "{why}");
    }

    /// (d): the mode comes from the start and from the control host's PromptMode only.
    #[test]
    fn the_mode_is_the_starts_until_an_operator_changes_it() {
        let mut rec = super::super::tests::fake_record("run_m");
        rec.start.edge = Some(Box::new(chan::EdgeStart {
            who: json!({}),
            spawn: None,
            push: None,
            ca_widen: None,
            prompts: Some(chan::EdgePrompts {
                harness: wicket_core::Harness::ClaudeCode,
                mode: wicket_core::RemotePermissionMode::BypassPermissions,
            }),
        }));
        let (bp, _) = BoxPrompts::of(&rec.start, &rec.prompts).unwrap();
        assert_eq!(bp.p.mode(), wicket_core::RemotePermissionMode::BypassPermissions);
        rec.prompts.mode = Some(wicket_core::RemotePermissionMode::Default);
        let (bp, _) = BoxPrompts::of(&rec.start, &rec.prompts).unwrap();
        assert_eq!(bp.p.mode(), wicket_core::RemotePermissionMode::Default, "an operator's change outlives a restart");
        rec.start.edge = None;
        assert!(BoxPrompts::of(&rec.start, &rec.prompts).is_none(), "no prompts: none answered here");
    }
}
