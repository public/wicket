//! #258: the control host converts version-1 bundle heads to version 2 when it starts, so a bundle
//! made before the version-1 code goes restores after it. Its own test binary: it points wicket at a
//! data directory of its own (`WICKET_HOME`) for the whole process.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use wicket_store::bundle::{self, PushTo, TreeSrc};
use wicket_store::{new_agent_id, Ledger, NewAgent};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wicket-convert-{tag}-{}", std::process::id()));
    let _ = bundle::make_writable(&d);
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn new_agent(l: &mut Ledger) -> String {
    let id = new_agent_id();
    l.create_agent(&NewAgent {
        id: &id,
        tenant: "t0",
        zone: "z",
        name: "a",
        run: &format!("run_{id}"),
        session_id: "s",
        manifest: "m",
        image: "img",
        workspace: None,
        claim_until: wicket_store::now() + 30,
    })
    .unwrap();
    id
}

/// Hibernates `src` as a version-1 bundle, as builds before version 2 did, and commits it as the
/// agent's head.
fn hibernate_v1(l: &Ledger, id: &str, src: &Path) -> String {
    let store = wicket_control::hibernate::store().unwrap();
    let trees = [TreeSrc { name: "workspace".into(), path: src.to_path_buf(), exclude: &[] }];
    let to = PushTo { agent: id, generation: 1, seq: 1, session_id: "s" };
    let (m, key) = bundle::push(&store, &to, &trees, None, &wicket_home::data_dir().join("objects-scratch")).unwrap();
    assert_eq!(m.version, 1);
    assert!(l.commit_agent_push(id, 1, 0, 1, &key, m.stored_bytes() as i64).unwrap());
    key
}

#[test]
fn version_one_heads_convert_once_and_restore_the_same_trees() {
    let home = tmp("home");
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("WICKET_HOME", &home);
    let src = home.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), "content").unwrap();
    std::os::unix::fs::symlink("sub/f", src.join("link")).unwrap();
    let mut l = Ledger::open(&wicket_home::ledger_path()).unwrap();
    // One hibernated agent, and one woken again since (awake: its own next push is version 2).
    let (asleep, awake) = (new_agent(&mut l), new_agent(&mut l));
    let old = hibernate_v1(&l, &asleep, &src);
    hibernate_v1(&l, &awake, &src);
    assert!(l.claim_wake(&awake, "run_w", wicket_store::now() + 30).unwrap().is_some());
    let ledger = Mutex::new(l);

    let done = wicket_control::hibernate::convert_v1_heads(&ledger).unwrap();
    assert_eq!(done.len(), 2, "{done:?}");
    let conv = done.iter().find(|c| c.agent == asleep).unwrap();
    let head = conv.to.clone().unwrap();
    assert_eq!(conv.from, old);
    assert!(bundle::is_tree_head(&head));
    assert!(done.iter().find(|c| c.agent == awake).unwrap().to.is_err(), "an awake agent is left");
    let l = ledger.lock().unwrap();
    let a = l.agent(&asleep).unwrap().unwrap();
    assert_eq!((a.head.as_deref(), a.head_seq, a.state.as_str(), a.generation), (Some(head.as_str()), 2, "hibernated", 1));
    let kinds: Vec<String> = l.audit_tail(50).unwrap().into_iter().map(|r| r.2).collect();
    assert!(kinds.iter().any(|k| k == "agent.bundle_converted") && kinds.iter().any(|k| k == "agent.bundle_not_converted"), "{kinds:?}");
    drop(l);

    // The converted head restores what was hibernated.
    let m = wicket_control::hibernate::read_head(&head, &asleep).unwrap();
    assert_eq!(m.version, bundle::TREE_VERSION);
    let out = home.join("out");
    wicket_control::hibernate::restore(&m, "workspace", &out).unwrap();
    assert_eq!(std::fs::read_to_string(out.join("sub/f")).unwrap(), "content");
    assert_eq!(std::fs::read_link(out.join("link")).unwrap(), PathBuf::from("sub/f"));

    // A second start finds nothing more to convert of it.
    let again = wicket_control::hibernate::convert_v1_heads(&ledger).unwrap();
    assert!(again.iter().all(|c| c.agent == awake), "{again:?}");
    let _ = bundle::make_writable(&home);
    let _ = std::fs::remove_dir_all(&home);
}
