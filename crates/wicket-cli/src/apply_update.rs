//! An approved `request_update`, applied (#465): approving an agent's update request in the
//! console installs the build it asked for, with no terminal on the control host.
//!
//! - **The artifact** is the file in the requesting run's outbox (`<data dir>/runs/<run>/workspace
//!   /out/`, for a box on this host's own node) whose sha256 is the one the request names, found
//!   without following anything the box put there ([`wicket_node::boxfiles::find_in_outbox`]) and
//!   copied to a private staging file before anything else reads it.
//! - **The update** is `wicket self update <copy> --nodes all`'s ([`crate::update::update`]): the
//!   copy is hashed again and accepted only by the approval of that sha256, which it uses up; then
//!   the blue/green switch, its health gate and rollback, then the nodes, a canary first.
//! - **The outcome** goes back to the requester as a notice from wicket (a turn in its inbox): done,
//!   rolled back, or failed and why. Every step is an audit record (`self.apply_*`).
//!
//! It runs as the `wicket` user, as wicketd runs `sudo wicket self update`'s update; root's own
//! copies and link (#261) are not touched: root never runs what the `wicket` user staged.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wicket_core::TenantId;
use wicket_store::{Ledger, Request};

/// The largest artifact taken from an outbox.
pub const MAX_ARTIFACT: u64 = 1 << 30;

/// The sha256 an update request asks for: `UPDATE wicket.internal/self/<sha256>`, 64 lowercase hex
/// digits (as `request_update` files it). None for any other request.
pub fn requested_sha(req: &Request) -> Option<&str> {
    if req.method != "UPDATE" || req.host != "wicket.internal" {
        return None;
    }
    let sha = req.path.strip_prefix("/self/")?;
    (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then_some(sha)
}

/// The commit the requester says the build is of: `request_update`'s `commit`, which it writes
/// into the reason as `… sha256 <sha> of commit <commit>: …`. The agent's word, never checked.
pub fn commit_said(req: &Request) -> Option<String> {
    let rest = req.reason.split_once(" of commit ")?.1;
    let c: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (7..=40).contains(&c.len()).then_some(c)
}

/// The run directory an outbox is under: `<data>/runs/<run>`.
fn run_root(data: &Path, run: &str) -> Result<PathBuf> {
    let plain = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    if run.is_empty() || run.len() > 128 || !run.chars().all(plain) {
        bail!("{run:?} is not a run id");
    }
    Ok(data.join("runs").join(run))
}

/// What approving an update request would install, shown on its approval card and signed with
/// the decision.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Preview {
    pub sha256: String,
    /// The file in the run's outbox with that sha256.
    pub artifact: Option<String>,
    pub size: Option<u64>,
    /// The commit the agent says it builds ([`commit_said`]).
    pub commit_said: Option<String>,
    /// The nodes it reaches after the control host, canary first.
    pub nodes: Vec<String>,
    /// Whether approving applies it; if not, why (approving then only accepts the sha256 for a
    /// `sudo wicket self update` on the host, as before).
    pub applies: bool,
    pub why_not: Option<String>,
    /// The node the run's box is on, when it isn't this host's own: its outbox is there, and the
    /// artifact is fetched from it (and only then found and hashed) once the request is approved.
    pub node: Option<String>,
}

/// The preview of approving `req` (an update request, [`requested_sha`]), with `data` the data dir.
pub fn preview(l: &Ledger, data: &Path, req: &Request) -> Result<Preview> {
    let sha = requested_sha(req).context("not an update request")?.to_string();
    let nodes = crate::update::node_list(l, "all")?;
    let mut p = Preview {
        sha256: sha.clone(),
        artifact: None,
        size: None,
        commit_said: commit_said(req),
        nodes,
        applies: false,
        why_not: None,
        node: remote_node(l, &req.run),
    };
    if p.node.is_some() {
        // Not fetched to be shown: a fetch is the whole outbox, over the node's connection.
        p.applies = run_root(data, &req.run).is_ok();
        return Ok(p);
    }
    match find(l, data, req, &sha) {
        Ok(f) => {
            p.artifact = Some(f.name);
            p.size = Some(f.size);
            p.applies = true;
        }
        Err(e) => p.why_not = Some(format!("{e:#}")),
    }
    Ok(p)
}

/// The node `run`'s box is on, if it isn't this host's own.
fn remote_node(l: &Ledger, run: &str) -> Option<String> {
    l.run_node(run).ok().flatten().filter(|n| n != crate::localnode::NAME)
}

/// The artifact in `req`'s run's outbox on this host, or why there is none.
fn find(l: &Ledger, data: &Path, req: &Request, sha: &str) -> Result<wicket_node::boxfiles::OutboxFile> {
    let root = run_root(data, &req.run)?;
    if let Some(node) = remote_node(l, &req.run) {
        bail!("{} runs on node {node}, and its outbox is there", req.run);
    }
    found(wicket_node::boxfiles::find_in_outbox(&root, sha, MAX_ARTIFACT)?, &req.run, sha)
}

fn found(f: Option<wicket_node::boxfiles::OutboxFile>, run: &str, sha: &str) -> Result<wicket_node::boxfiles::OutboxFile> {
    f.with_context(|| format!("no file in {run}'s outbox (/workspace/out) has sha256 {sha} (regular files of at most 1 GiB, not links)"))
}

/// How long fetching a remote outbox may take.
const FETCH_WAIT: Duration = Duration::from_secs(600);

/// The artifact in the outbox of `run`'s box on node `node`: the outbox fetched over a control
/// connection of this process's own ([`crate::nodecall::Link`]) into `into` (private), then found
/// there as on this host, never following what the box put there. A node from before the
/// `outbox` tree sends the whole workspace instead.
async fn fetch_remote(node: &str, run: &str, sha: &str, into: &Path) -> Result<wicket_node::boxfiles::OutboxFile> {
    let ledger = std::sync::Arc::new(std::sync::Mutex::new(Ledger::open(&crate::ledger_path())?));
    let link = crate::nodecall::Link::connect(node, &format!("apply-update:{}", std::process::id()), &ledger)
        .await
        .with_context(|| format!("reaching node {node}"))?;
    let get = |tree: &'static str, dest: PathBuf| {
        let calls = link.calls.clone();
        async move {
            tokio::time::timeout(FETCH_WAIT, calls.get_tree(run, tree, &dest))
                .await
                .map_err(|_| anyhow::anyhow!("fetching {run}'s {tree} from node {node} took over {FETCH_WAIT:?}"))?
        }
    };
    match get("outbox", into.join("workspace/out")).await {
        Ok(()) => {}
        Err(e) if format!("{e:#}").contains("no tree") => {
            let _ = std::fs::remove_dir_all(into.join("workspace"));
            get("workspace", into.join("workspace")).await?
        }
        Err(e) => return Err(e.context(format!("fetching {run}'s outbox from node {node}"))),
    }
    found(wicket_node::boxfiles::find_in_outbox(into, sha, MAX_ARTIFACT)?, run, sha)
}

/// How an applied update ended, as the requester is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    RolledBack,
    Failed,
}

/// The outcome of an update that ended with `r`: a failed health gate switches back, and says so.
pub fn outcome(r: &Result<()>) -> Outcome {
    match r {
        Ok(()) => Outcome::Done,
        Err(e) => {
            let why = format!("{e:#}");
            if why.contains("rolled back") || why.contains("switched back") {
                Outcome::RolledBack
            } else {
                Outcome::Failed
            }
        }
    }
}

/// What the requester is told.
pub fn notice(rid: &str, sha: &str, o: Outcome, r: &Result<()>) -> String {
    match (o, r) {
        (Outcome::Done, _) => format!(
            "update {rid} done: wicket now runs the build with sha256 {sha} (its health gate passed). Runs carried on under it; `wicket self rollback` on the host goes back."
        ),
        (Outcome::RolledBack, Err(e)) => {
            format!("update {rid} rolled back: the build with sha256 {sha} failed its health gate, and wicket switched back: {e:#}")
        }
        (_, Err(e)) => format!("update {rid} failed: {e:#}"),
        (_, Ok(())) => unreachable!("an Ok outcome is done"),
    }
}

fn audit(l: &Ledger, run: &str, kind: &str, body: serde_json::Value) {
    let _ = l.audit(&TenantId::single(), Some(&wicket_core::RunId(run.into())), kind, &body);
}

/// `wicket self apply <request>`: applies an approved update request (the module's doc).
pub async fn apply(request: &str) -> Result<()> {
    let data = crate::data_dir();
    let l = Ledger::open(&crate::ledger_path())?;
    let req = l.request(request)?;
    let sha = requested_sha(&req)
        .with_context(|| format!("{request} is not an update request (UPDATE wicket.internal/self/<sha256>)"))?
        .to_string();
    if req.status != "granted" {
        bail!("{request} is {}, not approved (granted)", req.status);
    }
    let told = |l: &Ledger, text: &str| {
        if let Err(e) = l.add_notice(&req.run, text) {
            say_err!("couldn't tell {}: {e:#}", req.run);
        }
    };
    // Into a private copy first: the update reads (and hashes again) only that.
    let stage = data.join(format!("self-apply-{}", std::process::id()));
    let _clean = RemoveDir(stage.clone());
    let made = std::fs::create_dir_all(&stage)
        .and_then(|()| std::fs::set_permissions(&stage, std::os::unix::fs::PermissionsExt::from_mode(0o700)))
        .map_err(anyhow::Error::from);
    let located = match (made, remote_node(&l, &req.run)) {
        (Err(e), _) => Err(e),
        (Ok(()), Some(node)) => {
            say!("fetching {}'s outbox from node {node}", req.run);
            fetch_remote(&node, &req.run, &sha, &stage.join("fetched")).await
        }
        (Ok(()), None) => find(&l, &data, &req, &sha),
    };
    let copied = located.and_then(|mut f| {
        let to = stage.join("artifact");
        let mut out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&to)?;
        std::io::copy(&mut std::io::Read::take(&mut f.file, MAX_ARTIFACT), &mut out)?;
        Ok((f.name, f.size, to))
    });
    let (name, size, artifact) = match copied {
        Ok(x) => x,
        Err(e) => {
            let r = Err(e);
            audit(
                &l,
                &req.run,
                "self.apply_failed",
                serde_json::json!({ "request": request, "artifact_sha256": sha, "why": format!("{:#}", r.as_ref().unwrap_err()) }),
            );
            told(&l, &notice(request, &sha, Outcome::Failed, &r));
            return r;
        }
    };
    let nodes = crate::update::node_list(&l, "all")?;
    audit(
        &l,
        &req.run,
        "self.apply_started",
        serde_json::json!({ "request": request, "artifact": name, "size": size, "artifact_sha256": sha, "nodes": nodes }),
    );
    say!("applying {request}: {name} ({size} bytes, sha256 {sha}) from {}'s outbox, then {} node(s)", req.run, nodes.len());
    drop(l);
    let before = crate::update::Versions::control().pointer("current");
    let r = crate::update::update(crate::update::UpdateOpts {
        artifact: artifact.clone(),
        sig: None,
        nodes: (!nodes.is_empty()).then(|| "all".to_string()),
        only_nodes: false,
        gate: crate::update::Gate {
            window: Duration::from_secs(30),
            interval: Duration::from_secs(10),
            checks: vec![],
            canary: None,
            image: None,
        },
        prune: true,
        ci: None,
    })
    .await;
    let o = outcome(&r);
    let l = Ledger::open(&crate::ledger_path())?;
    audit(
        &l,
        &req.run,
        "self.apply_done",
        serde_json::json!({ "request": request, "artifact_sha256": sha, "outcome": o, "why": r.as_ref().err().map(|e| format!("{e:#}")) }),
    );
    told(&l, &notice(request, &sha, o, &r));
    // The control host moved: root's link follows, through root's own check of the passkey's
    // approval (crate::rootadmit), on an installed host.
    if crate::update::Versions::control().pointer("current") != before && Path::new(crate::rootcopy::COPIES).is_dir() {
        match queue_for_root(&l, &data, request, &sha, &artifact) {
            Ok(m) => say!("{m}"),
            Err(e) => say_err!("root's link stays on its build: {e:#}"),
        }
    }
    r
}

/// Queues the applied artifact and the passkey-signed approval for root ([`crate::rootadmit`]).
fn queue_for_root(l: &Ledger, data: &Path, request: &str, sha: &str, artifact: &Path) -> Result<String> {
    let rec: serde_json::Value = serde_json::from_str(&l.decision_record(request)?.context("no decision record for the request")?)?;
    let Some(signed) = rec.get("signed").filter(|s| s.get("decision_json").is_some()) else {
        bail!("{request} wasn't approved with a passkey (`wicket approve`): for root's copy, sudo wicket self admit <artifact>");
    };
    let e = crate::rootadmit::Entry { v: 1, request: request.into(), sha256: sha.into(), signed: signed.clone() };
    crate::rootadmit::queue(data, &e, artifact)?;
    Ok(format!(
        "queued for root (wicket-admit): root copies the build if it trusts the passkey that approved {request} (sudo wicket self trust-operator <name>), and moves {} to it",
        crate::rootcopy::LINK
    ))
}

struct RemoveDir(PathBuf);
impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, reason: &str) -> Request {
        Request {
            id: "req_1".into(),
            tenant: "t".into(),
            run: "run_a".into(),
            zone: "z".into(),
            method: method.into(),
            host: "wicket.internal".into(),
            path: path.into(),
            risk: "R4".into(),
            reason: reason.into(),
            status: "pending".into(),
            created_at: 0,
            attribution: vec![],
            scope_prefix: false,
            args_sha256: None,
        }
    }

    #[test]
    fn only_an_update_request_names_a_sha256() {
        let sha = "0f".repeat(32);
        assert_eq!(requested_sha(&req("UPDATE", &format!("/self/{sha}"), "")), Some(sha.as_str()));
        assert_eq!(requested_sha(&req("GET", &format!("/self/{sha}"), "")), None);
        assert_eq!(requested_sha(&req("UPDATE", "/self/../../etc", "")), None);
        assert_eq!(requested_sha(&req("UPDATE", &format!("/self/{}", sha.to_uppercase()), "")), None);
        assert_eq!(requested_sha(&req("UPDATE", &format!("/other/{sha}"), "")), None);
    }

    #[test]
    fn the_commit_is_what_the_reason_says() {
        let sha = "0f".repeat(32);
        let r = |reason: &str| commit_said(&req("UPDATE", &format!("/self/{sha}"), reason));
        assert_eq!(r(&format!("update wicket to the build with sha256 {sha} of commit 36c92b5e: main")), Some("36c92b5e".into()));
        assert_eq!(r(&format!("update wicket to the build with sha256 {sha}: main")), None);
        assert_eq!(r("x of commit 36c: y"), None, "too short");
    }

    #[test]
    fn a_failed_gate_is_a_rollback() {
        assert_eq!(outcome(&Ok(())), Outcome::Done);
        let rolled: Result<()> =
            Err(anyhow::anyhow!("the update to b failed its health gate on the control host and was rolled back to a: x"));
        assert_eq!(outcome(&rolled), Outcome::RolledBack);
        assert!(notice("req_1", "ab", Outcome::RolledBack, &rolled).starts_with("update req_1 rolled back"));
        let failed: Result<()> = Err(anyhow::anyhow!("refused: not approved"));
        assert_eq!(outcome(&failed), Outcome::Failed);
        assert_eq!(notice("req_1", "ab", Outcome::Failed, &failed), "update req_1 failed: refused: not approved");
    }

    /// The preview finds the artifact in the run's outbox, and says why not when it can't.
    #[test]
    fn the_preview_shows_the_artifact_or_why_it_doesnt_apply() {
        use sha2::Digest;
        let d = std::env::temp_dir().join(format!("wicket-apply-preview-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("runs/run_a/workspace/out")).unwrap();
        std::fs::write(d.join("runs/run_a/workspace/out/wicket.tar.gz"), b"archive").unwrap();
        let sha = hex::encode(sha2::Sha256::digest(b"archive"));
        let l = Ledger::open(&d.join("ledger.db")).unwrap();
        let p = preview(&l, &d, &req("UPDATE", &format!("/self/{sha}"), &format!("sha256 {sha} of commit abcdef1: x"))).unwrap();
        assert_eq!(
            (p.artifact.as_deref(), p.size, p.applies, p.commit_said.as_deref()),
            (Some("wicket.tar.gz"), Some(7), true, Some("abcdef1"))
        );
        let other = "0f".repeat(32);
        let p = preview(&l, &d, &req("UPDATE", &format!("/self/{other}"), "x")).unwrap();
        assert!(!p.applies && p.why_not.unwrap().contains("no file in run_a's outbox"));
        let mut r = req("UPDATE", &format!("/self/{sha}"), "x");
        r.run = "../x".into();
        assert!(!preview(&l, &d, &r).unwrap().applies);
        // A box on another node: its outbox is fetched from there once approved, not to be shown.
        l.run_started(&TenantId::single(), &wicket_core::RunId("run_n".into()), "z", "lead").unwrap();
        l.set_run_node("run_n", "far").unwrap();
        let mut r = req("UPDATE", &format!("/self/{sha}"), "x");
        r.run = "run_n".into();
        let p = preview(&l, &d, &r).unwrap();
        assert_eq!((p.node.as_deref(), p.applies, p.artifact, p.why_not), (Some("far"), true, None, None));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// #261: what root is handed is the passkey's signed decision from the audit log, with the
    /// artifact; an approval without a passkey (`wicket approve`) hands root nothing.
    #[test]
    fn root_is_queued_the_signed_approval_only() {
        let d = std::env::temp_dir().join(format!("wicket-apply-queue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let l = Ledger::open(&d.join("ledger.db")).unwrap();
        let sha = "ab".repeat(32);
        let signed = serde_json::json!({ "credential": "c", "decision_json": "{}" });
        l.audit(&TenantId::single(), None, "decision", &serde_json::json!({ "request": "req_1", "decision": "approve", "signed": signed }))
            .unwrap();
        l.audit(&TenantId::single(), None, "decision", &serde_json::json!({ "request": "req_2", "decision": "approve", "by": "alex" }))
            .unwrap();
        std::fs::write(d.join("artifact"), b"bytes").unwrap();
        queue_for_root(&l, &d, "req_1", &sha, &d.join("artifact")).unwrap();
        let e: crate::rootadmit::Entry =
            serde_json::from_slice(&std::fs::read(crate::rootadmit::spool(&d).join(format!("{sha}.json"))).unwrap()).unwrap();
        assert_eq!((e.request.as_str(), e.signed), ("req_1", signed));
        assert_eq!(std::fs::read(crate::rootadmit::spool(&d).join(format!("{sha}.artifact"))).unwrap(), b"bytes");
        std::fs::write(d.join("artifact"), b"bytes").unwrap();
        assert!(queue_for_root(&l, &d, "req_2", &sha, &d.join("artifact")).unwrap_err().to_string().contains("passkey"));
        assert!(queue_for_root(&l, &d, "req_3", &sha, &d.join("artifact")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
