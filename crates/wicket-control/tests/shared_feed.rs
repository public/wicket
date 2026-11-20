//! A node's feed on the control host (#582 step 3): one publisher per node in a process, following
//! what other processes append, and one statement per refresh between them. Its own test binary:
//! it sets the data directory for the whole process.

use std::sync::Arc;
use wicket_control::noderun::{feed_config, open_feed, SharedFeed};
use wicket_feed::{Change, RevokeKind};

fn revoke(id: &str) -> Change<wicket_feed::BoxAuthority> {
    Change::Revoke { kind: RevokeKind::Run, id: id.into(), until: wicket_feed::now_ms() + 3_600_000 }
}

#[test]
fn runs_in_a_process_share_a_publisher_that_follows_other_processes() {
    let home = std::env::temp_dir().join(format!("wicket-shared-feed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    // SAFETY: this test binary's only test, set before anything reads it.
    unsafe { std::env::set_var("WICKET_HOME", &home) };

    let a = SharedFeed::open("n1", feed_config()).unwrap();
    let b = SharedFeed::open("n1", feed_config()).unwrap();
    assert!(Arc::ptr_eq(&a, &b), "two runs on one node in one process share its publisher");
    assert!(!Arc::ptr_eq(&a, &SharedFeed::open("n2", feed_config()).unwrap()));

    // Another process (its own publisher on the same files) appends, under the lock as SharedFeed takes it.
    let mut other = open_feed("n1", feed_config()).unwrap();
    a.lock().unwrap().commit(vec![revoke("run_a")], wicket_feed::now_ms()).unwrap();
    other.refresh().unwrap();
    other.commit(vec![revoke("run_b"), revoke("run_c")], wicket_feed::now_ms()).unwrap();
    {
        let g = b.lock().unwrap();
        assert_eq!((g.epoch(), &g.state().head), (other.epoch(), &other.state().head));
        assert!(g.state().is_revoked(RevokeKind::Run, "run_c"));
    }
    a.lock().unwrap().commit(vec![revoke("run_d")], wicket_feed::now_ms()).unwrap();
    assert_eq!(b.lock().unwrap().epoch(), 3);

    // One statement per refresh, whichever run (or process) signs it: the time is shared on disk.
    let now = wicket_feed::now_ms();
    assert!(a.lock().unwrap().tick(now).is_some());
    assert!(b.lock().unwrap().tick(now + 1).is_none(), "the same process's other run");
    drop((a, b));
    let again = SharedFeed::open("n1", feed_config()).unwrap();
    assert!(again.lock().unwrap().tick(now + 2).is_none(), "a publisher opened afterwards");
    assert!(again.lock().unwrap().tick(now + feed_config().refresh_ms + 1).is_some());

    // A run that panics holding the feed doesn't take the node's other runs down with it: the
    // publisher is opened again from the files.
    let a = again.clone();
    let panicked = std::thread::spawn(move || {
        let _g = a.lock().unwrap();
        panic!("a run's supervisor fails holding the feed");
    })
    .join();
    assert!(panicked.is_err());
    let mut g = again.lock().expect("the feed after a panic");
    assert_eq!(g.epoch(), 3);
    g.commit(vec![revoke("run_e")], wicket_feed::now_ms()).unwrap();
    drop(g);
    assert_eq!(again.lock().unwrap().epoch(), 4);

    // A panic, then a reopen that fails (here the feed key doesn't read, while the log does, so
    // a refresh alone would succeed): the poison stays, so every lock tries the reopen again and
    // none trusts the half-updated publisher; once the key reads, the next one works.
    let feed_dir = home.join("nodes/n1/feed");
    let key = feed_dir.join("feed.key");
    let key_text = std::fs::read(&key).unwrap();
    let a = again.clone();
    let _ = std::thread::spawn(move || {
        let _g = a.lock().unwrap();
        panic!("again");
    })
    .join();
    std::fs::write(&key, "not a key").unwrap();
    assert!(again.lock().is_err());
    assert!(again.lock().is_err(), "still poisoned: the reopen is tried again, the old publisher not trusted");
    std::fs::write(&key, &key_text).unwrap();
    assert_eq!(again.lock().expect("the key reads again").epoch(), 4);

    // A renewal that can't be made (here the feed key doesn't read) keeps the current publisher:
    // the revocation this lock is for still goes out.
    let cert_path = feed_dir.join("cert.jws");
    let cert = std::fs::read(&cert_path).unwrap();
    std::fs::write(&key, "not a key").unwrap();
    std::fs::write(&cert_path, "renewed elsewhere").unwrap();
    {
        let mut g = again.lock().expect("a failed renewal doesn't fail the lock");
        g.commit(vec![revoke("run_f")], wicket_feed::now_ms()).unwrap();
    }
    std::fs::write(&key, &key_text).unwrap();
    std::fs::write(&cert_path, cert).unwrap();
    assert_eq!(again.lock().unwrap().epoch(), 5);
    let _ = std::fs::remove_dir_all(&home);
}
