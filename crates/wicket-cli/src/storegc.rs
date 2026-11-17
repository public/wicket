//! The content-addressed stores' collection (#258, store.md's step 4): `wicket state gc`, and the
//! reconciler's pass once an hour ([`EVERY_SECS`]).
//!
//! Both stores are collected: the control host's local store (`<data dir>/store`) and, with an
//! `s3:` state store, the shared one (bundles with `bundles: s3`, and ledger snapshots). Their roots
//! are every agent's head the ledger holds and every ref the store keeps, except a bundle's ref
//! (`agents/<agent>/<seq>.<generation>`) once its agent's head has moved past it, which is dropped
//! first. With bundles in the state store, the local store is then cut down to its cache cap
//! (`local_cache:` in `state-store.yaml`), evicting only what the state store holds. Pushes and
//! restores hold a store while they write or read it (`Cas::writing`), and a collection waits for
//! them, or stops for one that begins (see `wicket_store::cas`'s `gc`).
//!
//! What a collection deletes is audited: one `store.gc` record per store and pass, and the
//! digests themselves in `store.deleted` records of up to [`AUDIT_BATCH`].

use anyhow::Result;
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashMap;
use wicket_core::TenantId;
use wicket_store::cas::{Cas, Digest, GcPlan, GcReport};
use wicket_store::Ledger;

/// How often the reconciler collects.
pub const EVERY_SECS: i64 = 3600;
/// Digests per `store.deleted` audit record.
pub const AUDIT_BATCH: usize = 500;

/// One store's pass.
pub struct Pass {
    pub store: &'static str,
    pub report: GcReport,
}

/// Whether a bundle ref `agents/<agent>/<seq>.<generation>` is one nothing names any more: its
/// agent's head is another digest, at or past its sequence number. A ref past the head (a push
/// that lost its fencing, or one not yet committed) and any other ref are kept.
pub fn superseded(heads: &HashMap<String, (String, i64)>, name: &str, target: &Digest) -> bool {
    let Some((agent, rest)) = name.strip_prefix("agents/").and_then(|r| r.split_once('/')) else { return false };
    let Some(seq) = rest.split_once('.').and_then(|(s, _)| s.parse::<i64>().ok()) else { return false };
    match heads.get(agent) {
        Some((head, head_seq)) => *head != target.to_string() && seq <= *head_seq,
        None => false,
    }
}

/// Collects `cas` (`cap`: the local store's cache cap, and the store whose objects it may evict).
fn collect(ledger: &Ledger, cas: &Cas, cap: Option<(&Cas, u64)>, dry_run: bool) -> Result<GcReport> {
    let heads: RefCell<HashMap<String, (String, i64)>> = RefCell::default();
    let roots = || {
        let hs = ledger.agent_heads().map_err(std::io::Error::other)?;
        let digests = hs.iter().filter_map(|(_, h, _)| Digest::parse(h)).collect();
        *heads.borrow_mut() = hs.into_iter().map(|(a, h, s)| (a, (h, s))).collect();
        Ok(digests)
    };
    let drop_ref = |name: &str, target: &Digest| superseded(&heads.borrow(), name, target);
    let by = format!("wicket (pid {})", std::process::id());
    let plan = GcPlan { roots: &roots, drop_ref: &drop_ref, dry_run, by: &by, cap, now: &wicket_store::now };
    Ok(cas.collect(&plan)?)
}

/// Collects the local store and, with an `s3:` state store, the shared one.
pub fn run(ledger: &Ledger, dry_run: bool) -> Result<Vec<Pass>> {
    let mut out = vec![];
    let (local, _) = crate::hibernate::local_store()?;
    let ss = crate::statestore::StateStore::load()?;
    let shared = crate::snapstore::store()?;
    if let Some(sh) = &shared {
        out.push(Pass { store: "state store", report: collect(ledger, sh, None, dry_run)? });
    }
    // The cap only where the state store is the bundles' home: otherwise the local store is it.
    let cap = match (&ss, &shared) {
        (Some(s), Some(sh)) if s.bundles == crate::statestore::Where::S3 => Some((sh, s.local_cache()?)),
        _ => None,
    };
    out.push(Pass { store: "local store", report: collect(ledger, &local, cap, dry_run)? });
    if !dry_run {
        for p in &out {
            audit(ledger, p);
        }
    }
    Ok(out)
}

fn audit(ledger: &Ledger, p: &Pass) {
    let r = &p.report;
    let t = TenantId::single();
    let _ = ledger.audit(
        &t,
        None,
        "store.gc",
        &json!({
            "store": p.store,
            "busy": r.busy,
            "stopped": r.stopped,
            "refs": r.refs,
            "refs_dropped": r.refs_dropped,
            "objects": r.objects,
            "live": r.live,
            "missing": r.missing.len(),
            "deleted": r.deleted.len(),
            "deleted_bytes": r.deleted_bytes,
            "evicted": r.evicted.len(),
            "evicted_bytes": r.evicted_bytes,
            "kept_bytes": r.kept_bytes,
            "over_cap": r.over_cap,
        }),
    );
    for (why, ds) in [("unreachable", &r.deleted), ("evicted", &r.evicted)] {
        for chunk in ds.chunks(AUDIT_BATCH) {
            let digests: Vec<String> = chunk.iter().map(|d| d.to_string()).collect();
            let _ = ledger.audit(&t, None, "store.deleted", &json!({ "store": p.store, "why": why, "digests": digests }));
        }
    }
}

/// What a pass says, one line per store.
pub fn summary(p: &Pass, dry_run: bool) -> String {
    let r = &p.report;
    if let Some(b) = &r.busy {
        return format!("{}: not collected: {b}", p.store);
    }
    let verb = if dry_run { "would delete" } else { "deleted" };
    let mut s = format!(
        "{}: {} object(s), {} reachable; {verb} {} unreachable ({}) and {} superseded ref(s)",
        p.store,
        r.objects,
        r.live,
        r.deleted.len(),
        crate::exitcause::human(r.deleted_bytes),
        r.refs_dropped.len()
    );
    if let Some(kept) = r.kept_bytes {
        let verb = if dry_run { "would evict" } else { "evicted" };
        s += &format!(
            "; {verb} {} the state store holds ({}), keeping {}",
            r.evicted.len(),
            crate::exitcause::human(r.evicted_bytes),
            crate::exitcause::human(kept)
        );
        if r.over_cap {
            s += " (over the cap: the rest only this host holds)";
        }
    }
    if !r.missing.is_empty() && r.kept_bytes.is_none() && p.store != "local store" {
        s += &format!("; {} reachable object(s) missing", r.missing.len());
    }
    if let Some(why) = &r.stopped {
        s += &format!("; stopped early: {why} (the next pass goes on)");
    }
    s
}

/// `wicket state gc [--dry-run]`.
pub fn command(dry_run: bool) -> Result<()> {
    let ledger = Ledger::open(&crate::ledger_path())?;
    for p in run(&ledger, dry_run)? {
        println!("{}", summary(&p, dry_run));
        if dry_run {
            for r in &p.report.refs_dropped {
                println!("  ref {r}");
            }
            for d in &p.report.deleted {
                println!("  unreachable {d}");
            }
            for d in &p.report.evicted {
                println!("  evict {d}");
            }
        }
    }
    Ok(())
}

/// Whether the reconciler's collection is due (none in the last [`EVERY_SECS`]), by the time of the
/// last one's mark, `<data dir>/store-gc.last`, which this then touches.
pub fn due() -> bool {
    let p = crate::data_dir().join("store-gc.last");
    let last = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
    let now = std::time::SystemTime::now();
    if last.is_some_and(|t| now.duration_since(t).map(|d| d.as_secs() < EVERY_SECS as u64).unwrap_or(true)) {
        return false;
    }
    std::fs::write(&p, b"").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_ref_is_dropped_once_its_agents_head_moves_past_it() {
        let d = Digest::of(b"old");
        let head = Digest::of(b"new");
        let heads: HashMap<String, (String, i64)> = [("agt_a".to_string(), (head.to_string(), 3))].into();
        assert!(superseded(&heads, "agents/agt_a/2.1", &d));
        assert!(superseded(&heads, "agents/agt_a/3.1", &d), "another generation's push at the head's seq lost");
        assert!(!superseded(&heads, "agents/agt_a/3.2", &head), "the head's own ref");
        assert!(!superseded(&heads, "agents/agt_a/4.2", &d), "past the head: kept");
        assert!(!superseded(&heads, "agents/agt_b/1.1", &d), "an agent the ledger doesn't hold: kept");
        assert!(!superseded(&heads, "ledger-snapshots/1-a.db", &d));
        assert!(!superseded(&heads, "agents/agt_a/x", &d));
    }
}
