//! The control host: the node's feed publisher, the runs' grants and their model budgets.
//!
//! It follows `wicket-cli/src/noderun.rs`:
//! - **Grants** (`sync_grants`): the plan's approvals, renewals and revocations are carried out as
//!   the control host's clock passes them. Each change republishes the box's token from its
//!   unchanged base with the live grants (`Issuer::publish`). A revocation goes in the same delta
//!   as `Change::Revoke { kind: Grant, until: expiry }`. Grants past their expiry drop out of the
//!   token.
//! - **The feed** (`wicket_feed::Publisher`, persisted under its directory): catch-up from the
//!   node's hello on every connection, then deltas as they are committed and a statement at each
//!   refresh.
//! - **Budget slices** (`slice_due`): per connection, the run's [`Llm::next_slice`], renewed by
//!   [`wicket_proxy::llm::Slice::renewed`], sent when it changes. The node's spend reports are
//!   merged into the run's counter (`Msg::Spent`'s handler, with its `spent_base`).
//!
//! What survives a crash ([`Disk`]): the publisher's log, the ledger's grant records and the
//! run's counted spend (`used_*`, restored with `Llm::spent_before`, the re-attach path).

use crate::oracle::Oracle;
use crate::wire::{self, Ctl};
use crate::{true_now, Env, GrantKind, CONTROL_PORT, EPOCH_MS, GRANT_PATHS, HOST, NODE, QUOTA, REFRESH_MS, RUNS, SILENCE_MS, TTL_MS};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use wicket_core::{Op, RunId, TenantId};
use wicket_feed::{BoxAuthority, Change, Frame, LiveGrant, Publisher, PublisherConfig, RevokeKind};
use wicket_proxy::llm::{Llm, Slice, Spent};

/// What the control host has on disk besides the publisher's log: the ledger's part.
#[derive(Default)]
pub struct Disk {
    pub started: bool,
    /// How many of the plan's grant actions are done.
    pub done: usize,
    /// Each run's live grants: id → (which path, expiry in Unix seconds).
    pub live: BTreeMap<String, BTreeMap<String, (usize, u64)>>,
    pub revoked: BTreeSet<String>,
    /// Each run's counted spend (requests, input tokens, output tokens), as the ledger records it.
    pub used: BTreeMap<String, (u64, u64, u64)>,
}

/// What to tell the oracle once the change's epoch is known.
type Note = Box<dyn FnOnce(&mut Oracle, u64)>;

struct Run {
    llm: Arc<Llm>,
    /// `noderun::Shared::spent_base`: for a re-attached run, the node's first report, which later
    /// ones count from.
    spent_base: Option<Option<Spent>>,
}

struct State {
    publisher: Publisher<BoxAuthority>,
    /// The deltas this process committed, in order: each connection sends those after its catch-up.
    deltas: Vec<Frame>,
    runs: BTreeMap<String, Run>,
}

fn cfg() -> PublisherConfig {
    PublisherConfig { ttl_ms: TTL_MS, refresh_ms: REFRESH_MS, retain: 1000 }
}

/// The control host's software: started at the beginning, and again after each crash.
pub async fn run(env: Rc<Env>) -> turmoil::Result {
    env.oracle.borrow_mut().stats.control_starts += 1;
    let publisher = Publisher::open_with(
        &env.dir.join("control").join("feed"),
        NODE,
        &env.feed_root.verifying_key(),
        env.feed_key.clone(),
        &env.cert,
        cfg(),
        env.authz_root.public(),
    )?;
    let mut runs = BTreeMap::new();
    for run in RUNS {
        let llm = Llm::with_quota(crate::run_ctx(run, &env.zone), Some(QUOTA)).map_err(|e| e.to_string())?;
        let spent_base = match env.control_disk.borrow().used.get(run) {
            Some(&(r, i, o)) => {
                llm.spent_before(r, i, o);
                Some(None)
            }
            None => None,
        };
        runs.insert(run.to_string(), Run { llm, spent_base });
    }
    let st = Rc::new(RefCell::new(State { publisher, deltas: vec![], runs }));
    if !env.control_disk.borrow().started {
        let now = true_now();
        let mut s = st.borrow_mut();
        let changes =
            RUNS.iter().map(|r| Change::PutZone { zone: env.issuers[*r].publish(&env.approver, &[]).expect("a record") }).collect();
        let f = s.publisher.commit(changes, now)?;
        s.deltas.push(f);
        env.control_disk.borrow_mut().started = true;
    }
    tokio::task::spawn_local(grants(env.clone(), st.clone()));
    let listener = turmoil::net::TcpListener::bind(("0.0.0.0", CONTROL_PORT)).await?;
    loop {
        let (s, _) = listener.accept().await?;
        env.oracle.borrow_mut().stats.connections += 1;
        tokio::task::spawn_local(serve(env.clone(), st.clone(), s));
    }
}

/// Carries out the plan's grant actions as their time comes, and drops expired grants.
async fn grants(env: Rc<Env>, st: Rc<RefCell<State>>) {
    loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let t = true_now();
        loop {
            let done = env.control_disk.borrow().done;
            let Some(a) = env.plan.grants.get(done) else { break };
            if a.at_ms > t - EPOCH_MS {
                break;
            }
            apply(&env, &mut st.borrow_mut(), a.run, Some((a.path, &a.gid, &a.kind)), t);
            env.control_disk.borrow_mut().done += 1;
        }
        // Expired grants leave the token (noderun's `p.live.retain(not_after > now)`).
        for (run, name) in RUNS.iter().enumerate() {
            let expired = env.control_disk.borrow().live.get(*name).is_some_and(|l| l.values().any(|(_, na)| *na as i64 <= t / 1000));
            if expired {
                apply(&env, &mut st.borrow_mut(), run, None, t);
            }
        }
    }
}

/// One grant change for `run` (or none: a rebuild without the expired ones), published at once.
/// Synchronous, so a crash comes before or after it, never inside.
fn apply(env: &Env, st: &mut State, run_i: usize, action: Option<(usize, &str, &GrantKind)>, t: i64) {
    let run = RUNS[run_i];
    let now_s = (t / 1000) as u64;
    let mut changes = vec![];
    let mut disk = env.control_disk.borrow_mut();
    let Disk { live, revoked, .. } = &mut *disk;
    let live = live.entry(run.to_string()).or_default();
    live.retain(|_, (_, na)| *na > now_s);
    let mut note: Option<Note> = None;
    match action {
        None => {}
        Some((path, gid, GrantKind::Issue { lifetime_s })) => {
            if revoked.contains(gid) {
                return;
            }
            let na = now_s + lifetime_s;
            live.insert(gid.to_string(), (path, na));
            let (gid, run) = (gid.to_string(), run.to_string());
            note = Some(Box::new(move |o, _| o.published(t, &gid, &run, GRANT_PATHS[path], na)));
        }
        Some((path, gid, GrantKind::Renew { lifetime_s })) => {
            // Only a live grant is renewed.
            let Some(g) = live.get_mut(gid) else { return };
            g.1 = now_s + lifetime_s;
            let na = g.1;
            let (gid, run) = (gid.to_string(), run.to_string());
            note = Some(Box::new(move |o, _| o.published(t, &gid, &run, GRANT_PATHS[path], na)));
        }
        Some((_, gid, GrantKind::Revoke)) => {
            let Some((_, na)) = live.remove(gid) else { return };
            revoked.insert(gid.to_string());
            changes.push(Change::Revoke { kind: RevokeKind::Grant, id: gid.to_string(), until: na as i64 * 1000 });
            let gid = gid.to_string();
            note = Some(Box::new(move |o, epoch| o.revoked(t, &gid, epoch)));
        }
    }
    let issuer = &env.issuers[run];
    let tenant = TenantId(crate::TENANT.into());
    let grants: Vec<LiveGrant> = live
        .iter()
        .map(|(gid, (path, na))| {
            let op = Op::egress(&tenant, &RunId(run.into()), &env.zone.name, "POST", HOST, GRANT_PATHS[*path]);
            LiveGrant {
                grant: wicket_authz::Grant {
                    gid: gid.clone(),
                    box_id: issuer.box_path.clone(),
                    epoch: issuer.epoch,
                    host: op.host.clone(),
                    method: op.method.clone(),
                    path: op.path.clone(),
                    not_after: *na,
                    approver: "human:sim".into(),
                    digest: hex::decode(op.digest()).unwrap_or_default(),
                },
                uses: None,
            }
        })
        .collect();
    drop(disk);
    let record = issuer.publish(&env.approver, &grants).expect("the token with its grants");
    changes.push(Change::PutZone { zone: record });
    let f = st.publisher.commit(changes, t).expect("the publisher commits");
    st.deltas.push(f);
    let epoch = st.publisher.epoch();
    let mut o = env.oracle.borrow_mut();
    match note {
        Some(n) => n(&mut o, epoch),
        None => o.note(t, format!("republish {run} without expired grants, epoch {epoch}")),
    }
}

/// One node connection: catch-up, then deltas, statements and slices; spend reports in.
async fn serve(env: Rc<Env>, st: Rc<RefCell<State>>, s: turmoil::net::TcpStream) {
    let (mut rd, mut wr) = s.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let reader = tokio::task::spawn_local(async move {
        while let Ok(Some(f)) = wire::read_frame(&mut rd).await {
            if tx.send(f).is_err() {
                break;
            }
        }
    });
    let _guard = AbortOnDrop(reader);
    // The node's hello first.
    let hello = match tokio::time::timeout(Duration::from_millis(SILENCE_MS), rx.recv()).await {
        Ok(Some((wire::KIND_MSG, b))) => match wire::parse::<Ctl>(&b) {
            Ok(Ctl::Hello { hello }) => hello,
            _ => return,
        },
        _ => return,
    };
    let now = true_now();
    let (frames, mut sent) = {
        let mut s = st.borrow_mut();
        match s.publisher.catch_up(&hello, now) {
            Ok(f) => (f, s.deltas.len()),
            Err(e) => {
                env.oracle.borrow_mut().note(now, format!("catch-up refused: {e}"));
                return;
            }
        }
    };
    env.oracle.borrow_mut().note(now, format!("node connected at epoch {:?}, {} catch-up frames", hello.epoch, frames.len()));
    for f in frames {
        if wire::write_frame(&mut wr, wire::KIND_FEED, f.to_line().as_bytes()).await.is_err() {
            return;
        }
    }
    let mut slices: BTreeMap<String, Slice> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut last_rx = tokio::time::Instant::now();
    loop {
        // `biased`: unbiased, `select!` picks among ready branches with tokio's own RNG, which
        // the seed doesn't reach, so a frame and a tick due at the same simulated instant ran in
        // either order (#324). What has arrived is handled before the tick acts on it.
        tokio::select! {
            biased;
            f = rx.recv() => {
                let Some((kind, body)) = f else { return };
                last_rx = tokio::time::Instant::now();
                if kind == wire::KIND_MSG {
                    if let Ok(Ctl::Spent { run, spent }) = wire::parse::<Ctl>(&body) {
                        spent_in(&env, &mut st.borrow_mut(), &run, spent);
                    }
                }
            }
            _ = tick.tick() => {
                if last_rx.elapsed() > Duration::from_millis(SILENCE_MS) {
                    env.oracle.borrow_mut().note(true_now(), "control host drops a silent node connection");
                    return;
                }
                let now = true_now();
                let mut out: Vec<(u8, Vec<u8>)> = vec![];
                {
                    let mut s = st.borrow_mut();
                    for f in &s.deltas[sent..] {
                        out.push((wire::KIND_FEED, f.to_line().into_bytes()));
                    }
                    sent = s.deltas.len();
                    if let Some(f) = s.publisher.tick(now) {
                        out.push((wire::KIND_FEED, f.to_line().into_bytes()));
                    }
                    for (run, r) in &s.runs {
                        if let Some(sl) = slice_due(&r.llm, slices.get(run).copied()) {
                            slices.insert(run.clone(), sl);
                            env.oracle.borrow_mut().note(now, format!("slice {run} {sl:?}"));
                            let m = Ctl::BudgetSlice { run: run.clone(), slice: sl };
                            out.push((wire::KIND_MSG, serde_json::to_vec(&m).expect("serialises")));
                        }
                    }
                }
                for (k, b) in out {
                    if wire::write_frame(&mut wr, k, &b).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// `noderun::slice_due`: the slice to send, if it differs from the one this connection sent.
fn slice_due(l: &Llm, cur: Option<Slice>) -> Option<Slice> {
    let next = l.next_slice(crate::SLICE_FRACTION)?;
    let slice = Slice::renewed(cur, next, l.spent(), l.input_total());
    (cur != Some(slice)).then_some(slice)
}

/// `Msg::Spent`'s handler: the node is the counter of record; the ledger keeps the run's total.
fn spent_in(env: &Env, st: &mut State, run: &str, spent: Spent) {
    let Some(r) = st.runs.get_mut(run) else { return };
    let base = match &mut r.spent_base {
        Some(slot) => *slot.get_or_insert(spent),
        None => Spent::default(),
    };
    r.llm.merge_spent(spent.since(base));
    env.control_disk.borrow_mut().used.insert(run.to_string(), r.llm.spent_total());
}

/// A task aborted when this is dropped: a connection's reader goes with its connection.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
