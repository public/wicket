//! Persistence: the node reloads its verified feed and resumes in the mode the signed deadlines
//! allow; corrupt files are refused; the publisher's log survives restarts and torn writes.

use super::*;

fn open(cp: &Cp, dir: &TempDir) -> Result<Replica<ZoneSpec>, LoadError> {
    Replica::open(dir.path(), NODE, cp.root.verifying_key(), ReplicaConfig::default())
}

/// A persisting node at epoch 3 (snapshot + 2 deltas), with a statement received at T0 + 10.
fn persisted() -> (Cp, TempDir) {
    let mut cp = Cp::new();
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }, add(grant("keep-1", &granted(), T0 + 3_600_000))], T0 - 10).unwrap();
    let dir = TempDir::new();
    let mut r = open(&cp, &dir).unwrap();
    assert_eq!(r.mode(T0), Mode::Closed);
    let frames = cp.p.catch_up(&r.hello(), T0).unwrap();
    feed(&mut r, frames, T0);
    for i in 0..2 {
        let d =
            cp.p.commit(
                vec![add(Grant { uses: Some(3), box_id: Some("r1".into()), ..grant(&format!("g-{i}"), &evil(), T0 + 3_600_000) })],
                T0 + 1 + i,
            )
            .unwrap();
        r.accept(&d, T0 + 5).unwrap();
    }
    r.accept(&cp.p.statement(T0 + 10), T0 + 10).unwrap();
    assert!(allowed(&mut r, &evil(), T0 + 11), "uses g-0 once");
    (cp, dir)
}

#[test]
fn reload_resumes_in_the_mode_the_signed_deadlines_allow() {
    let (cp, dir) = persisted();
    let mut r = open(&cp, &dir).unwrap();
    assert_eq!(r.state().unwrap().epoch, 3);
    assert_eq!(r.deadlines().unwrap(), (T0 + 10 + TTL, T0 + 10 + TTL + WINDOW));
    assert_eq!(r.mode(T0 + 20), Mode::Fresh);
    assert!(allowed(&mut r, &granted(), T0 + 20));
    assert_eq!(r.uses("g-0"), 1, "use counts survive");
    // Rebooted during an outage: narrow, then closed, on the signed schedule.
    let r = open(&cp, &dir).unwrap();
    assert_eq!(r.mode(T0 + 10 + TTL), Mode::Narrow);
    assert_eq!(r.mode(T0 + 10 + TTL + WINDOW), Mode::Closed);
}

#[test]
fn replay_protection_survives_a_reboot() {
    let (mut cp, dir) = persisted();
    let later = cp.p.statement(T0 + 20);
    let mut r = open(&cp, &dir).unwrap();
    let floor = r.last_statement().unwrap().issued_at;
    let replay = Fresh { issued_at: floor, ..r.last_statement().unwrap().clone() };
    let replay = Frame::new(FrameKind::Fresh, sign(&cp.feed_key, TYP_FRESH, &replay));
    assert_eq!(r.accept(&replay, T0 + 20).unwrap_err().kind(), "replay");
    r.accept(&later, T0 + 20).expect("a later statement is fine");
    // The deltas already held are replays, too.
    let log = std::fs::read_to_string(cp.p.log_path()).unwrap();
    let first = Frame::new(FrameKind::Delta, log.lines().next().unwrap().into());
    assert_eq!(r.accept(&first, T0 + 21).unwrap_err().kind(), "replay");
}

#[test]
fn reload_continues_the_chain() {
    let (mut cp, dir) = persisted();
    let mut r = open(&cp, &dir).unwrap();
    let frames = cp.p.catch_up(&r.hello(), T0 + 30).unwrap();
    assert_eq!(frames.iter().map(|f| f.kind).collect::<Vec<_>>(), [FrameKind::Key, FrameKind::Fresh], "on the chain: nothing to send");
    feed(&mut r, frames, T0 + 30);
    let d = cp.p.commit(vec![add(grant("g-new", &read(), T0 + 3_600_000))], T0 + 31).unwrap();
    r.accept(&d, T0 + 31).unwrap();
    // A same-epoch snapshot compacts the persisted deltas.
    r.accept(&cp.p.snapshot(T0 + 32), T0 + 32).unwrap();
    assert_eq!(std::fs::read_to_string(dir.path().join("deltas.jsonl")).unwrap(), "");
    let r = open(&cp, &dir).unwrap();
    assert_eq!(r.state().unwrap().epoch, 4);
    assert_eq!(r.mode(T0 + 33), Mode::Fresh);
}

/// Flips one byte in the middle of `file`.
fn corrupt(dir: &TempDir, file: &str) {
    let p = dir.path().join(file);
    let mut b = std::fs::read(&p).unwrap();
    let i = b.len() / 2;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    std::fs::write(&p, b).unwrap();
}

#[test]
fn corrupt_files_are_refused_not_trusted() {
    for file in ["cert.jws", "snapshot.jws", "deltas.jsonl", "statements.json"] {
        let (cp, dir) = persisted();
        corrupt(&dir, file);
        let err = open(&cp, &dir).err().unwrap_or_else(|| panic!("{file} corrupted, yet loaded"));
        assert!(matches!(err, LoadError::Corrupt { .. }), "{file}: {err}");
        // The node starts again with nothing: closed until a live statement arrives. Use counts stay.
        let mut r = Replica::<ZoneSpec>::reset(dir.path(), NODE, cp.root.verifying_key(), ReplicaConfig::default()).unwrap();
        assert_eq!(r.mode(T0 + 20), Mode::Closed);
        assert_eq!(r.uses("g-0"), 1);
        let mut cp = cp;
        let frames = cp.p.catch_up(&r.hello(), T0 + 20).unwrap();
        feed(&mut r, frames, T0 + 20);
        assert_eq!(r.mode(T0 + 20), Mode::Fresh);
    }
}

#[test]
fn other_bad_states_are_refused() {
    // Files whose content is valid but whose combination isn't.
    let (cp, dir) = persisted();
    std::fs::remove_file(dir.path().join("cert.jws")).unwrap();
    assert!(open(&cp, &dir).is_err(), "feed files without a certificate");
    let (cp, dir) = persisted();
    std::fs::remove_file(dir.path().join("snapshot.jws")).unwrap();
    assert!(open(&cp, &dir).is_err(), "deltas without a snapshot");
    // A different root: nothing verifies.
    let (_cp, dir) = persisted();
    assert!(Replica::<ZoneSpec>::open(dir.path(), NODE, key().verifying_key(), ReplicaConfig::default()).is_err());
    // Another node's files.
    let (cp, dir) = persisted();
    assert!(Replica::<ZoneSpec>::open(dir.path(), "n2", cp.root.verifying_key(), ReplicaConfig::default()).is_err());
    // Deltas reordered.
    let (cp, dir) = persisted();
    let p = dir.path().join("deltas.jsonl");
    let text = std::fs::read_to_string(&p).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.reverse();
    std::fs::write(&p, lines.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    assert!(open(&cp, &dir).is_err());
}

#[test]
fn a_torn_delta_append_is_dropped() {
    let (cp, dir) = persisted();
    let p = dir.path().join("deltas.jsonl");
    let mut text = std::fs::read_to_string(&p).unwrap();
    text.push_str("eyJhbGciOi"); // a crash mid-append: no newline, never fsynced in full
    std::fs::write(&p, text).unwrap();
    let r = open(&cp, &dir).unwrap();
    assert_eq!(r.state().unwrap().epoch, 3);
}

#[test]
fn publisher_log_survives_restarts_and_torn_writes() {
    let mut cp = Cp::new();
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }], T0).unwrap();
    cp.p.commit(vec![add(grant("a", &granted(), T0 + 3_600_000))], T0 + 1).unwrap();
    let head = cp.p.state().head.clone();
    // Every committed delta is on disk (fsynced) by the time commit returns.
    assert_eq!(std::fs::read_to_string(cp.p.log_path()).unwrap().lines().count(), 2);
    let mut torn = std::fs::read_to_string(cp.p.log_path()).unwrap();
    torn.push_str("eyJhbGciOiJFZERTQSIs");
    std::fs::write(cp.p.log_path(), torn).unwrap();
    cp.restart(cfg());
    assert_eq!((cp.p.epoch(), cp.p.state().head.clone()), (2, head));
    let d = cp.p.commit(vec![add(grant("b", &read(), T0 + 3_600_000))], T0 + 2).unwrap();
    assert_eq!(cp.p.epoch(), 3);
    cp.restart(cfg());
    assert_eq!(cp.p.epoch(), 3);
    // A node following along accepts the post-restart delta.
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&Hello { node: NODE.into(), ..Default::default() }, T0 + 3).unwrap();
    feed(&mut r, frames, T0 + 3);
    assert_eq!(r.accept(&d, T0 + 3).unwrap_err().kind(), "replay", "already in the snapshot");
    assert!(r.state().unwrap().grants.contains_key("b"));
    // A log that isn't a chain is refused.
    let log = std::fs::read_to_string(cp.p.log_path()).unwrap();
    let mut lines: Vec<&str> = log.lines().collect();
    lines.swap(0, 1);
    std::fs::write(cp.p.log_path(), lines.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    assert!(Publisher::<ZoneSpec>::open(cp.dir.path(), NODE, &cp.root.verifying_key(), cp.feed_key.clone(), &cp.cert, cfg()).is_err());
}

#[test]
fn publisher_refuses_settings_beyond_its_certificate() {
    let (root, k, dir) = (key(), key(), TempDir::new());
    let c = sign(&root, TYP_KEY, &KeyCert::new(&k.verifying_key(), 1, T0 + 86_400_000, 10_000, 60_000));
    let open = |cfg: PublisherConfig| Publisher::<ZoneSpec>::open(dir.path(), NODE, &root.verifying_key(), k.clone(), &c, cfg);
    assert!(open(PublisherConfig::default()).is_err(), "30 s TTL > certified 10 s");
    assert!(open(PublisherConfig { ttl_ms: 10_000, narrow_ms: 60_000, ..PublisherConfig::default() }).is_ok());
    let other = key();
    assert!(Publisher::<ZoneSpec>::open(dir.path(), NODE, &root.verifying_key(), other, &c, cfg()).is_err(), "certificate for another key");
}

#[test]
fn reload_across_a_regenesis_with_a_new_feed_key() {
    let (mut cp, dir) = persisted();
    let mut r = open(&cp, &dir).unwrap();
    let new_key = key();
    let v2 = cert(&cp.root, &new_key, 2, T0 + 86_400_000);
    cp.p.rotate(&cp.root.verifying_key(), new_key.clone(), &v2).unwrap();
    let frames = cp.p.catch_up(&r.hello(), T0 + 40).unwrap();
    // Only the new certificate arrives before a reboot: the old generation's state is kept on disk
    // but can't vouch for anything, so the node comes back closed, without error.
    r.accept(&frames[0], T0 + 40).unwrap();
    assert_eq!(r.mode(T0 + 40), Mode::Closed);
    drop(r);
    let mut r = open(&cp, &dir).unwrap();
    assert!(r.state().is_none());
    assert_eq!(r.mode(T0 + 41), Mode::Closed);
    feed(&mut r, frames[1..].to_vec(), T0 + 41);
    assert_eq!(r.mode(T0 + 41), Mode::Fresh);
    let r = open(&cp, &dir).unwrap();
    assert_eq!((r.state().unwrap().version, r.state().unwrap().epoch), (2, 3));
    assert_eq!(r.cert().unwrap().kid, kid(&new_key.verifying_key()));
    assert_eq!(r.mode(T0 + 42), Mode::Fresh);
}

#[test]
fn a_crash_while_installing_a_snapshot_loads_closed_not_corrupt() {
    // Snapshot install truncates the deltas, then writes the snapshot. A crash in between leaves the
    // old base without its deltas, while the statements vouched for a later epoch.
    let (mut cp, dir) = persisted();
    std::fs::write(dir.path().join("deltas.jsonl"), "").unwrap();
    let mut r = open(&cp, &dir).unwrap();
    assert_eq!(r.state().unwrap().epoch, 1);
    assert_eq!(r.mode(T0 + 20), Mode::Closed, "lagging, and nothing vouches for epoch 1 any more");
    let frames = cp.p.catch_up(&r.hello(), T0 + 20).unwrap();
    feed(&mut r, frames, T0 + 20);
    assert_eq!((r.state().unwrap().epoch, r.mode(T0 + 20)), (3, Mode::Fresh));
}
