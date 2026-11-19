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
    let _ = std::fs::remove_dir_all(&home);
}
