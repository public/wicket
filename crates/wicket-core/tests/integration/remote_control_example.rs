//! examples/remote-control-box.yaml (#169, #298): its zone reaches what a Remote Control session
//! calls, refuses the account's MCP servers (the bare `/v1/mcp_servers` too, which `/**` doesn't
//! match) and the settings a box has no use for outright, so nothing waits for a human at a start,
//! and leaves the rest of the account (other sessions) to a human.

use wicket_core::{CompiledZone, Manifest, Op, RunId, TenantId, Verdict};

fn verdict(z: &CompiledZone, method: &str, path: &str) -> Verdict {
    z.evaluate(&Op::egress(&TenantId::single(), &RunId("run_x".into()), "remote-control-box", method, "api.anthropic.com", path))
}

#[test]
fn the_remote_control_example_refuses_the_mcp_paths_and_reaches_the_session() {
    let m = Manifest::from_yaml(include_str!("../../../../examples/remote-control-box.yaml")).expect("the example parses");
    assert!(m.agent.as_ref().and_then(|a| a.remote.as_ref()).is_some(), "a remote agent");
    let z = CompiledZone::new(m.zone).unwrap();
    let allowed = [
        ("POST", "/v1/messages"),
        ("POST", "/v1/environments/bridge"),
        ("GET", "/v1/environments/env_1/work/poll"),
        ("PUT", "/v1/code/sessions/cse_01x/worker"),
        ("POST", "/v1/code/sessions/cse_01x/worker/events"),
        ("GET", "/v1/code/sessions/cse_01x"),
        ("POST", "/v1/sessions"),
        ("GET", "/v1/sessions/session_01x"),
        ("POST", "/v1/sessions/session_01x/events"),
        ("GET", "/api/oauth/profile"),
        ("POST", "/api/oauth/validate"),
    ];
    for (method, path) in allowed {
        assert!(matches!(verdict(&z, method, path), Verdict::AllowByReach(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
    let refused = [
        ("GET", "/v1/mcp_servers"),
        ("GET", "/v1/mcp_servers/srv_1"),
        ("POST", "/v2/ccr-sessions/cse_01x/mcp"),
        ("GET", "/mcp-registry/v0/servers"),
        ("GET", "/api/claude_code_grove"),
        ("GET", "/api/claude_code_penguin_mode"),
        ("GET", "/api/oauth/organizations/org-1/referral/eligibility"),
    ];
    for (method, path) in refused {
        assert!(matches!(verdict(&z, method, path), Verdict::Forbidden(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
    // Listing or changing the account's other sessions is a human's decision.
    for (method, path) in [("GET", "/v1/sessions"), ("GET", "/v1/code/sessions"), ("PATCH", "/v1/code/sessions/cse_01x")] {
        assert!(matches!(verdict(&z, method, path), Verdict::NeedsGrant(_)), "{method} {path}: {:?}", verdict(&z, method, path));
    }
}
