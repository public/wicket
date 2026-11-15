//! examples/remote-driven-box.yaml (#285): its zone reaches what a driven Remote Control session was
//! seen to call, refuses the account's MCP servers and the settings a box has no use for outright
//! (no human waits on them), and leaves the rest of the account (other sessions) to a human.

use wicket_core::{CompiledZone, Manifest, Op, RunId, TenantId, Verdict};

fn zone() -> CompiledZone {
    let m = Manifest::from_yaml(include_str!("../../../../examples/remote-driven-box.yaml")).expect("the example parses");
    let r = m.agent.as_ref().and_then(|a| a.remote.as_ref()).expect("a remote agent");
    assert!(r.drive, "the example is driven");
    CompiledZone::new(m.zone).unwrap()
}

fn verdict(z: &CompiledZone, method: &str, path: &str) -> Verdict {
    z.evaluate(&Op::egress(&TenantId::single(), &RunId("run_x".into()), "remote-driven-box", method, "api.anthropic.com", path))
}

#[test]
fn the_driven_remote_example_reaches_its_session_and_refuses_the_account_s_mcp() {
    let z = zone();
    let allowed = [
        ("POST", "/v1/messages"),
        ("POST", "/v1/code/sessions"),
        ("POST", "/v1/code/sessions/cse_01x/bridge"),
        ("GET", "/v1/code/sessions/cse_01x"),
        ("GET", "/v1/code/sessions/cse_01x/worker"),
        ("PUT", "/v1/code/sessions/cse_01x/worker"),
        ("POST", "/v1/code/sessions/cse_01x/worker/events"),
        ("GET", "/v1/code/sessions/cse_01x/worker/events/stream"),
        ("POST", "/v1/code/sessions/cse_01x/worker/heartbeat"),
        ("POST", "/v1/sessions/session_01x/archive"),
        ("GET", "/api/oauth/profile"),
        ("GET", "/api/claude_cli/bootstrap"),
    ];
    for (method, path) in allowed {
        assert!(matches!(verdict(&z, method, path), Verdict::AllowByReach(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
    let refused = [
        ("GET", "/v1/mcp_servers"),
        ("GET", "/v1/mcp_servers/srv_1/tools"),
        ("POST", "/v2/ccr-sessions/cse_01x/mcp"),
        ("GET", "/mcp-registry/v0/servers"),
        ("GET", "/api/claude_code_grove"),
        ("GET", "/api/claude_code_penguin_mode"),
        ("GET", "/api/oauth/organizations/org-1/referral/eligibility"),
    ];
    for (method, path) in refused {
        assert!(matches!(verdict(&z, method, path), Verdict::Forbidden(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
    // The rest of the account is a human's decision.
    for (method, path) in [
        ("GET", "/v1/sessions"),
        ("GET", "/v1/code/sessions"),
        ("DELETE", "/v1/code/sessions/cse_01x"),
        // Only POST unarchives; reading or changing a session through that path is not the resume's.
        ("GET", "/v1/sessions/session_01x/unarchive"),
        ("DELETE", "/v1/sessions/session_01x"),
    ] {
        assert!(matches!(verdict(&z, method, path), Verdict::NeedsGrant(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
}

#[test]
fn a_woken_driven_remote_box_resumes_its_session_with_nothing_pending() {
    // What a resumed Claude Code calls to reattach to its Remote Control session (#330): unarchive the
    // session (the v1 path takes its `session_` id, the v2 one its `cse_` id), fetch its bridge
    // credentials again, then the worker channel as at the start. None of it waits for a human.
    let z = zone();
    let resume = [
        ("POST", "/v1/sessions/session_01x/unarchive"),
        ("POST", "/v1/code/sessions/cse_01x/unarchive"),
        ("POST", "/v1/code/sessions/cse_01x/bridge"),
        ("POST", "/v1/code/sessions/cse_01x/worker/register"),
        ("PUT", "/v1/code/sessions/cse_01x/worker"),
        ("GET", "/v1/code/sessions/cse_01x/worker/events/stream"),
        ("POST", "/v1/code/sessions/cse_01x/worker/events"),
        ("POST", "/v1/code/sessions/cse_01x/worker/heartbeat"),
    ];
    for (method, path) in resume {
        assert!(matches!(verdict(&z, method, path), Verdict::AllowByReach(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
}
