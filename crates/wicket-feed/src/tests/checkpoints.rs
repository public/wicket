//! One node's feed shared by many publishers (#582 step 3): each follows what the others append by
//! applying only their deltas ([`Publisher::refresh`]), opens from a checkpoint instead of
//! replaying the whole log, keeps a bounded tail for catch-up, and signs a statement only when no
//! publisher on the feed has signed one for a refresh.

use super::*;
use crate::publisher::{Refreshed, CHECKPOINT};
use crate::token::COMPILES;

/// The state as a node would get it: compared as a snapshot, so two loads agree on every entry,
/// grant and revocation, at the same epoch and head.
fn snap(p: &mut Publisher<BoxAuthority>, now: i64) -> serde_json::Value {
    let st = p.state();
    serde_json::to_value(st.snapshot(NODE, now)).unwrap()
}

/// Runs `n` boxes through the feed one after another: each puts its token, gets a grant, and
/// every other one is dropped; one revocation in the middle.
fn churn(cp: &mut Cp, from: usize, n: usize) {
    for i in from..from + n {
        let run = format!("run-{i}");
        let t = T0 + i as i64;
        let put = cp.put(&run);
        cp.p.commit(vec![put], t).unwrap();
        let g = cp.grant(&run, token_grant(&format!("g-{i}"), &granted(), T0 + 3_600_000, None));
        cp.p.commit(vec![g, add(grant(&format!("g-{i}"), &granted(), T0 + 3_600_000))], t).unwrap();
        if i % 2 == 0 {
            cp.p.commit(vec![Change::DropZone { name: run }], t).unwrap();
        }
        if i == from + n / 2 && i > 0 {
            cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Grant, id: format!("g-{}", i - 1), until: T0 + 3_600_000 }], t).unwrap();
        }
    }
}

#[test]
fn a_publisher_applies_only_the_deltas_another_appended() {
    let mut cp = Cp::new();
    churn(&mut cp, 0, 4);
    let mut b = cp.open_publisher(cfg());
    assert_eq!(b.refresh().unwrap(), Refreshed::Current);

    // A appends three deltas: B applies those three, compiling only the tokens they put.
    churn(&mut cp, 5, 1);
    COMPILES.with(|c| c.set(0));
    assert_eq!(b.refresh().unwrap(), Refreshed::Applied(3));
    assert_eq!(COMPILES.with(|c| c.get()), 1, "the put that a later delta in the same batch replaces isn't compiled");
    assert_eq!(snap(&mut b, T0), snap(&mut cp.p, T0));
    assert_eq!(b.refresh().unwrap(), Refreshed::Current);

    // B appends, A follows; either serves a node the same catch-up.
    let put = cp.put("from-b");
    b.commit(vec![put], T0 + 50).unwrap();
    assert_eq!(cp.p.refresh().unwrap(), Refreshed::Applied(1));
    assert_eq!((cp.p.epoch(), &cp.p.state().head), (b.epoch(), &b.state().head));
    let mut r = cp.replica();
    let hello = r.hello();
    let from_a = cp.p.catch_up(&hello, T0 + 60).unwrap();
    feed(&mut r, from_a, T0 + 60);
    let mut r2 = cp.replica();
    feed(&mut r2, b.catch_up(&hello, T0 + 60).unwrap(), T0 + 60);
    assert_eq!(r.state().unwrap().head, r2.state().unwrap().head);
    assert_eq!(r.mode(T0 + 60), Mode::Fresh);
}

#[test]
fn a_log_replaced_or_made_under_a_newer_certificate_is_opened_again() {
    let mut cp = Cp::new();
    churn(&mut cp, 0, 2);
    let mut b = cp.open_publisher(cfg());
    // Another process rotates to a new generation and commits under it.
    let cert2 = cert(&cp.root, &cp.feed_key, 2, T0 + 86_400_000);
    cp.p.rotate(&cp.root.verifying_key(), cp.feed_key.clone(), &cert2).unwrap();
    let put = cp.put("after");
    cp.p.commit(vec![put], T0 + 10).unwrap();
    assert_eq!(b.refresh().unwrap(), Refreshed::Reopen);
    assert_eq!(b.epoch(), cp.p.epoch() - 1, "nothing of the newer generation was applied");

    // The log set aside and a new one started (a new generation after a restore).
    let log = cp.p.log_path().to_path_buf();
    std::fs::rename(&log, log.with_extension("jsonl.old")).unwrap();
    let mut c = cp.open_publisher(cfg());
    assert_eq!(c.epoch(), 0);
    assert_eq!(cp.p.refresh().unwrap(), Refreshed::Reopen);
    let put = cp.put("new");
    c.commit(vec![put], T0 + 20).unwrap();
    assert_eq!(cp.p.refresh().unwrap(), Refreshed::Reopen);
}

#[test]
fn a_torn_append_is_dropped_by_the_next_refresh() {
    let mut cp = Cp::new();
    churn(&mut cp, 0, 1);
    let mut b = cp.open_publisher(cfg());
    let put = cp.put("whole");
    cp.p.commit(vec![put], T0 + 10).unwrap();
    // A crash mid-append: half a line, never fsynced in full.
    let log = cp.p.log_path().to_path_buf();
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, b"eyJhbGciOi").unwrap();
    assert_eq!(b.refresh().unwrap(), Refreshed::Applied(1));
    assert_eq!(b.state().head, cp.p.state().head);
    let put = cp.put("next");
    b.commit(vec![put], T0 + 20).unwrap();
    let reopened = cp.open_publisher(cfg());
    assert_eq!((reopened.epoch(), &reopened.state().head), (b.epoch(), &b.state().head), "the torn bytes are gone");
}

#[test]
fn opening_from_a_checkpoint_reaches_the_state_a_full_replay_does() {
    let mut cp = Cp::new();
    cp.p.set_checkpoint_every(8);
    churn(&mut cp, 0, 30);
    let epoch = cp.p.epoch();
    assert!(cp.dir.path().join(CHECKPOINT).exists());
    let want = snap(&mut cp.p, T0 + 100);

    COMPILES.with(|c| c.set(0));
    let mut from_checkpoint = cp.open_publisher(cfg());
    let compiled = COMPILES.with(|c| c.get());
    assert_eq!((from_checkpoint.epoch(), snap(&mut from_checkpoint, T0 + 100)), (epoch, want.clone()));
    // The tokens held at the checkpoint, and at most the puts after it.
    assert!(compiled <= cp.p.state().zones.len() + 8, "{compiled} compiles");

    let viewed = read_state::<BoxAuthority>(cp.dir.path(), NODE, cp.authz_root.public()).unwrap();
    assert_eq!((viewed.epoch, &viewed.head), (epoch, &cp.p.state().head));
    assert!(viewed.zones.values().all(|z| z.compiled.is_ok()));

    std::fs::remove_file(cp.dir.path().join(CHECKPOINT)).unwrap();
    let mut replayed = cp.open_publisher(cfg());
    assert_eq!((replayed.epoch(), snap(&mut replayed, T0 + 100)), (epoch, want));
    assert!(epoch > crate::publisher::CHECKPOINT_EVERY);
    assert!(cp.dir.path().join(CHECKPOINT).exists(), "a long replay leaves a checkpoint for the next open");
}

#[test]
fn a_checkpoint_that_does_not_match_the_log_is_ignored() {
    let mut cp = Cp::new();
    cp.p.set_checkpoint_every(4);
    churn(&mut cp, 0, 6);
    let path = cp.dir.path().join(CHECKPOINT);
    let good = std::fs::read_to_string(&path).unwrap();
    let want = snap(&mut cp.p, T0 + 100);
    let check = |cp: &Cp, what: &str| {
        let mut p = cp.open_publisher(cfg());
        assert_eq!(snap(&mut p, T0 + 100), want, "{what}");
        let viewed = read_state::<BoxAuthority>(cp.dir.path(), NODE, cp.authz_root.public()).unwrap();
        assert_eq!(viewed.head, cp.p.state().head, "{what}");
    };

    // The state inside, edited: (`f` changes the snapshot; `resum` whether its hash follows).
    let edit = |f: &dyn Fn(&mut serde_json::Value), resum: bool| {
        let mut c: serde_json::Value = serde_json::from_str(&good).unwrap();
        let mut snap: serde_json::Value = serde_json::from_str(c["snap"].as_str().unwrap()).unwrap();
        f(&mut snap);
        let text = snap.to_string();
        if resum {
            c["sum"] = serde_json::json!(crate::sha(&text));
        }
        c["snap"] = serde_json::json!(text);
        std::fs::write(&path, c.to_string()).unwrap();
    };
    // Damaged (a box gone) with the right head: its hash no longer matches.
    edit(&|s| s["zones"].as_array_mut().unwrap().clear(), false);
    check(&cp, "a state that doesn't match its hash");
    // Consistent in itself, but at another head than the log's line at its offset.
    edit(&|s| s["head"] = serde_json::json!(GENESIS), true);
    check(&cp, "another head");
    edit(&|s| s["feed"] = serde_json::json!("n2"), true);
    check(&cp, "another node's");
    let offsets = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut c: serde_json::Value = serde_json::from_str(&good).unwrap();
        f(&mut c);
        std::fs::write(&path, c.to_string()).unwrap();
    };
    offsets(&|c| c["end"] = serde_json::json!(c["end"].as_u64().unwrap() - 3));
    check(&cp, "a short offset");
    offsets(&|c| c["end"] = serde_json::json!(c["end"].as_u64().unwrap() * 10));
    check(&cp, "past the log's end");
    // No delta kept to check it against: refused, whatever it holds.
    offsets(&|c| {
        c["tail_from"] = c["end"].clone();
        c["tail_epoch"] = serde_json::json!(cp.p.epoch() + 1);
    });
    check(&cp, "nothing kept to check it against");
    std::fs::write(&path, "{not json").unwrap();
    check(&cp, "unreadable");
}

#[test]
fn a_publisher_keeps_a_bounded_tail_and_serves_older_nodes_a_snapshot() {
    let mut cp = Cp::with(PublisherConfig { retain: 5, ..cfg() }, T0 + 86_400_000);
    cp.p.set_checkpoint_every(4);
    let mut behind = cp.replica();
    churn(&mut cp, 0, 2);
    let frames = cp.p.catch_up(&behind.hello(), T0 + 10).unwrap();
    feed(&mut behind, frames, T0 + 10);
    let mut near = cp.replica();
    churn(&mut cp, 2, 6);
    let frames = cp.p.catch_up(&near.hello(), T0 + 20).unwrap();
    feed(&mut near, frames, T0 + 20);
    let put = cp.put("last");
    cp.p.commit(vec![put], T0 + 30).unwrap();
    let put = cp.put("last2");
    cp.p.commit(vec![put], T0 + 31).unwrap();

    {
        let p = &mut cp.open_publisher(PublisherConfig { retain: 5, ..cfg() });
        // Two behind: deltas. Far behind: a snapshot. Both end fresh at the same head.
        let frames = p.catch_up(&near.hello(), T0 + 40).unwrap();
        let kinds: Vec<FrameKind> = frames.iter().map(|f| f.kind).collect();
        assert_eq!(kinds, [FrameKind::Key, FrameKind::Delta, FrameKind::Delta, FrameKind::Fresh]);
        feed(&mut near, frames, T0 + 40);
        let frames = p.catch_up(&behind.hello(), T0 + 40).unwrap();
        assert_eq!(frames[1].kind, FrameKind::Snap);
        feed(&mut behind, frames, T0 + 40);
        assert_eq!(near.state().unwrap().head, behind.state().unwrap().head);
        assert_eq!(near.mode(T0 + 40), Mode::Fresh);
    }
}

#[test]
fn a_statement_is_due_a_refresh_after_the_last_any_publisher_signed() {
    let (mut cp, mut r) = setup();
    let mut b = cp.open_publisher(cfg());
    // B knows of no statement yet: one is due at once. Told of A's, none is due until a refresh
    // after the newest signed by either, as the shared last statement time says.
    let first = b.tick(T0 + 100).expect("B's first");
    let mut c = cp.open_publisher(cfg());
    c.note_issued(b.last_issued());
    assert!(c.tick(T0 + 150).is_none(), "a publisher opened after B signed");
    r.accept(&first, T0 + 100).unwrap();
    cp.p.note_issued(b.last_issued());
    assert!(cp.p.tick(T0 + 200).is_none(), "B signed one 100 ms ago");
    let from_a = cp.p.tick(T0 + 600).expect("a refresh after B's");
    r.accept(&from_a, T0 + 600).unwrap();
    b.note_issued(cp.p.last_issued());
    assert!(b.tick(T0 + 1000).is_none(), "A signed one 400 ms ago");
    assert!(b.tick(T0 + 1100).is_some());
    assert_eq!(r.mode(T0 + 1100), Mode::Fresh);
}

/// What an open from a checkpoint costs doesn't grow with the log's history: it reads nothing
/// before the deltas kept for catch-up. (Here the history before them is made unreadable: a full
/// replay refuses the log, the open from the checkpoint doesn't see it.)
#[test]
fn an_open_from_a_checkpoint_reads_nothing_before_its_tail() {
    let small = PublisherConfig { retain: 5, ..cfg() };
    let mut cp = Cp::with(small.clone(), T0 + 86_400_000);
    cp.p.set_checkpoint_every(4);
    churn(&mut cp, 0, 12);
    let log = cp.p.log_path().to_path_buf();
    let text = std::fs::read_to_string(&log).unwrap();
    let first = text.find('\n').unwrap();
    let mut spoiled = text.into_bytes();
    spoiled[..first].fill(b'x');
    std::fs::write(&log, &spoiled).unwrap();
    let mut p = cp.open_publisher(small.clone());
    assert_eq!(snap(&mut p, T0 + 100), snap(&mut cp.p, T0 + 100));
    std::fs::remove_file(cp.dir.path().join(CHECKPOINT)).unwrap();
    let replayed = Publisher::<BoxAuthority>::open_with(
        cp.dir.path(),
        NODE,
        &cp.root.verifying_key(),
        cp.feed_key.clone(),
        &cp.cert,
        small,
        cp.authz_root.public(),
    );
    assert!(replayed.is_err_and(|e| e.to_string().contains("unreadable")));
}

/// With `retain` 0, a checkpoint still keeps its own epoch's delta, and is checked against it.
#[test]
fn a_checkpoint_keeps_its_own_delta_with_retain_zero() {
    let none = PublisherConfig { retain: 0, ..cfg() };
    let mut cp = Cp::with(none.clone(), T0 + 86_400_000);
    cp.p.set_checkpoint_every(4);
    churn(&mut cp, 0, 4);
    let c: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(cp.dir.path().join(CHECKPOINT)).unwrap()).unwrap();
    assert!(c["tail_from"].as_u64() < c["end"].as_u64(), "{c}");
    let mut p = cp.open_publisher(none);
    assert_eq!(snap(&mut p, T0 + 100), snap(&mut cp.p, T0 + 100));
}

/// A publisher that missed another's append can't commit on the head it holds: that delta would
/// fork the chain (its epoch and prev stale), and a node holding the other's (a revocation,
/// say) would refuse it, or the other's, as a replay. It fails closed until it refreshes.
#[test]
fn a_publisher_behind_the_log_refuses_to_commit_until_it_refreshes() {
    let mut cp = Cp::new();
    churn(&mut cp, 0, 1);
    let mut b = cp.open_publisher(cfg());
    let before = (b.epoch(), b.state().head.clone());
    cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Run, id: "run-0".into(), until: T0 + 3_600_000 }], T0 + 10).unwrap();
    let put = cp.put("from-b");
    let e = b.commit(vec![put.clone()], T0 + 20).unwrap_err();
    assert!(e.to_string().contains("refresh first"), "{e}");
    assert_eq!((b.epoch(), b.state().head.clone()), before, "nothing applied");
    assert_eq!(b.refresh().unwrap(), Refreshed::Applied(1));
    assert!(b.state().is_revoked(RevokeKind::Run, "run-0"));
    b.commit(vec![put], T0 + 20).unwrap();
    assert_eq!(cp.p.refresh().unwrap(), Refreshed::Applied(1));
    assert_eq!(cp.p.state().head, b.state().head);
}

/// Checkpoints are one per `CHECKPOINT_EVERY` deltas of the feed, however many publishers commit
/// them in turn (each epoch is committed by one of them).
#[test]
fn many_publishers_write_one_checkpoint_per_interval_between_them() {
    let cp = Cp::new();
    let mut ps: Vec<Publisher<BoxAuthority>> = (0..8).map(|_| cp.open_publisher(cfg())).collect();
    for p in &mut ps {
        p.set_checkpoint_every(8);
    }
    for i in 0..200 {
        let p = &mut ps[i % 8];
        p.refresh().unwrap();
        p.commit(vec![Change::Revoke { kind: RevokeKind::Run, id: format!("r{i}"), until: T0 + 3_600_000 }], T0 + i as i64).unwrap();
    }
    let written: u64 = ps.iter().map(|p| p.checkpoints_written()).sum();
    assert_eq!(written, 200 / 8);
    let mut last = cp.open_publisher(cfg());
    assert_eq!(last.epoch(), 200);
    assert_eq!(snap(&mut last, T0 + 300), snap(&mut ps[7], T0 + 300));
}

/// A publisher behind the log serves no catch-up and signs no statement on its tick, as it
/// commits nothing: what it holds may be behind what nodes hold. And one whose log was set aside
/// for a new one (a new generation) can't append to the old file no one reads.
#[test]
fn a_publisher_behind_the_log_serves_nothing_and_a_set_aside_log_takes_nothing() {
    let (mut cp, r) = setup();
    let mut b = cp.open_publisher(cfg());
    let put = cp.put("from-a");
    cp.p.commit(vec![put], T0 + 10).unwrap();
    assert!(b.catch_up(&r.hello(), T0 + 20).unwrap_err().to_string().contains("refresh first"));
    assert!(b.tick(T0 + 10_000).is_none(), "no statement for an epoch the log has moved past");
    assert_eq!(b.refresh().unwrap(), Refreshed::Applied(1));
    assert!(b.catch_up(&r.hello(), T0 + 20).is_ok());
    assert!(b.tick(T0 + 10_000).is_some());

    // The log set aside, as a new generation does, and a new one started by another publisher.
    let log = cp.p.log_path().to_path_buf();
    std::fs::rename(&log, log.with_extension("jsonl.old")).unwrap();
    let put = cp.put("into-the-old-file");
    let e = b.commit(vec![put.clone()], T0 + 30).unwrap_err();
    assert!(e.to_string().contains("replaced") || e.to_string().contains("gone"), "{e}");
    let mut c = cp.open_publisher(cfg());
    c.commit(vec![put.clone()], T0 + 40).unwrap();
    let e = b.commit(vec![put], T0 + 50).unwrap_err();
    assert!(e.to_string().contains("replaced"), "{e}");
    assert_eq!(b.refresh().unwrap(), Refreshed::Reopen);
}
