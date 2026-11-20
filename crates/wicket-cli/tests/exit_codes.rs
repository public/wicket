//! #574: `wicket`'s exit codes, from the binary, as docs/reference/cli.md lists them: 0 done, 1
//! failed, 2 a usage error, 3 refused, 4 not found, 5 an approval nobody has given yet (the last is checked in
//! main.rs's unit test: it needs a terminal or a provider).

use std::process::Command;
use wicket_core::{RunId, TenantId};

struct Home(std::path::PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(tag: &str) -> Home {
    let d = std::env::temp_dir().join(format!("wicket-exit-{tag}-{}", wicket_core::new_ulid()));
    std::fs::create_dir_all(&d).unwrap();
    Home(d)
}

/// `wicket args…` in `h`: its exit code and stderr.
fn wicket(h: &Home, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wicket"))
        .args(args)
        .env("WICKET_HOME", &h.0)
        .env_remove("WICKET_DAEMON_SOCKET")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn every_kind_of_outcome_has_its_code() {
    let h = home("codes");
    // A request, then denied: deciding it again is refused.
    let rid = {
        let l = wicket_store::Ledger::open(&h.0.join("ledger.db")).unwrap();
        let op = wicket_core::Op::egress(&TenantId::single(), &RunId("run_a".into()), "work", "GET", "api.example.com", "/v1");
        let (rid, _) = l.pending_for(&op, "blocked", None).unwrap();
        l.deny(&rid, "op").unwrap();
        rid
    };
    for (args, want) in [
        (&["pending"][..], 0),
        (&["pending", "--bogus"], 2),
        (&["approve", "s-abc"], 2),
        (&["deny", "s-abc"], 2),
        (&["standing", "approve", "s-abc", "--for", "bogus"], 2),
        (&["approve", &rid, "-y"], 3),
        (&["approve", "r-nope", "-y"], 4),
        (&["deny", "r-nope"], 4),
        (&["grant", "revoke", "g-nope"], 4),
        (&["grant", "renew", "g-nope"], 4),
        (&["grant", "renew", "r-nope"], 4),
        (&["operator", "enrol-link", "--ttl", "2h"], 2),
        (&["serve", "--listen", "0.0.0.0:8080"], 2),
        (&["wake", "agent_1", "--wait", "5q"], 2),
        (&["audit", "--json", "export"], 2),
        // Every duration flag is parsed as clap parses the command line: a bad one is a usage error.
        (&["approve", "r-nope", "--ttl", "5q"], 2),
        (&["grant", "renew", "g-nope", "--ttl", "5q"], 2),
        (&["node", "token", "--ttl", "5q"], 2),
        (&["reconcile", "--every", "5q"], 2),
        (&["trigger", "renew", "t-nope", "--lasts", "5q"], 2),
        (&["self", "update", "x", "--window", "5q"], 2),
        (&["trigger", "show", "nope"], 4),
        (&["unlink", "lk-nope"], 4),
        (&["lease", "release", "lease_nope"], 4),
        (&["standing", "show", "s-nope"], 4),
        (&["service", "remove", "nope"], 4),
        (&["why-here", "run_nope"], 4),
        (&["session", "run_nope", "hi"], 4),
        (&["hibernate", "run_nope"], 4),
        (&["node", "set", "nope", "--label", "a=b"], 4),
    ] {
        let (code, err) = wicket(&h, args);
        assert_eq!(code, want, "wicket {}: {err}", args.join(" "));
        if code != 0 && code != 2 {
            assert!(err.starts_with("Error: "), "the error is printed as before: {err}");
        }
    }
}
