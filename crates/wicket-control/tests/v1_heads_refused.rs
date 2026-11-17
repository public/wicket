//! #258: this build reads no version-1 hibernation bundles, so the control host refuses to start
//! while an agent's head is one, naming the agents (the build before converted them).

use wicket_store::{new_agent_id, Ledger, NewAgent};

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

#[test]
fn a_version_one_head_refuses_the_start_and_names_its_agent() {
    let mut l = Ledger::open_in_memory().unwrap();
    // No heads, and version-2 heads only: the control host starts.
    wicket_control::hibernate::refuse_v1_heads(&l).unwrap();
    let (new, old) = (new_agent(&mut l), new_agent(&mut l));
    let digest = format!("sha256:{}", "ab".repeat(32));
    assert!(l.commit_agent_push(&new, 1, 0, 1, &digest, 10).unwrap());
    wicket_control::hibernate::refuse_v1_heads(&l).unwrap();
    // A version-1 head (a manifest key): refused, by name.
    assert!(l.commit_agent_push(&old, 1, 0, 1, &format!("a/{old}/m/1.1"), 10).unwrap());
    assert_eq!(wicket_control::hibernate::v1_heads(&l).unwrap(), vec![old.clone()]);
    let e = wicket_control::hibernate::refuse_v1_heads(&l).unwrap_err().to_string();
    assert!(e.contains(&old) && !e.contains(&new) && e.contains("version-1"), "{e}");
}
