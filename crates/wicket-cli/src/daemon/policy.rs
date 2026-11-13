//! Who may do what through `wicketd` (#12): every forwarded command line is parsed again by the
//! daemon with the same `clap` definition as the CLI's, sorted into a [`Class`], and allowed or
//! refused for the caller the kernel names (`SO_PEERCRED`), never for anything the caller says.
//!
//! - **read**, **run** and **revoke** are granted by the policy file (by default to the
//!   `wicket-operators` group).
//! - **privileged** (approving, denying, secrets, passkey enrolment, nodes, spending, image builds)
//!   is root's alone over the socket: the host break-glass. Everyone else approves in the console
//!   with a passkey. No policy setting widens it.
//! - The daemon's own uid (the `wicket` user: the console, the reconciler, runs starting children)
//!   is trusted with everything, since it owns the data anyway.

use super::Peer;
use crate::{
    Cmd, DevCmd, GrantCmd, IdentityCmd, ImageCmd, LeaseCmd, NodeCmd, OperatorCmd, PolicyCmd, ProgramCmd, SecretCmd, SelfCmd, StateCmd,
};
use serde::Deserialize;
use std::path::Path;

/// The default policy file.
pub const POLICY_PATH: &str = "/etc/wicket/wicketd.yaml";
/// The group the install script creates for the host's operators.
pub const OPERATORS_GROUP: &str = "wicket-operators";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Reads state: pending requests, links, audit, identities, leases, nodes, secret names.
    Read,
    /// Starts or steers runs: `run`, `wrap`, `say`.
    Run,
    /// Takes authority away: revoke an identity or a grant, cut a link, end a lease.
    Revoke,
    /// Root (or the daemon's own uid) only.
    Privileged,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::Read => "read",
            Class::Run => "run",
            Class::Revoke => "revoke",
            Class::Privileged => "privileged",
        }
    }
}

/// What the CLI does with a command when a daemon is installed.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Forward it to the daemon, which checks this class.
    Forward(Class),
    /// Run it in the caller's own process: it touches no wicket data.
    Local,
    /// Never through the daemon; the reason says what to do instead.
    Refuse(&'static str),
}

/// Sorts a command. Every variant is listed (no wildcard), so a new command fails to compile until
/// it is classified.
pub fn route(cmd: &Cmd) -> Route {
    use Class::*;
    use Route::*;
    match cmd {
        // Hibernating and waking steer an agent the way `say` does; waking reruns its stored manifest.
        Cmd::Run { .. } | Cmd::Wrap { .. } | Cmd::Say { .. } | Cmd::Hibernate { .. } | Cmd::Wake { .. } => Forward(Run),
        Cmd::Agents { .. } => Forward(Read),
        Cmd::Pending | Cmd::Links { .. } | Cmd::Audit { .. } | Cmd::Doctor { .. } => Forward(Read),
        Cmd::Approve { .. } | Cmd::Deny { .. } => Forward(Privileged),
        Cmd::Unlink { .. } | Cmd::Grant { cmd: GrantCmd::Revoke { .. } } => Forward(Revoke),
        Cmd::Secret { cmd } => match cmd {
            SecretCmd::List => Forward(Read),
            // Setting a secret changes what the proxies present upstream; linking one makes the
            // wicket user read a file the caller names.
            // and binding one to hosts decides where it may go.
            SecretCmd::Set { .. } | SecretCmd::Link { .. } | SecretCmd::Hosts { .. } | SecretCmd::Rm { .. } => Forward(Privileged),
        },
        // Reads a directory the caller names, as the wicket user.
        // Reads Docker, as the wicket user: what `wicket zone pin` resolves tags through.
        Cmd::Image { cmd: Some(ImageCmd::Digest { .. }), .. } => Forward(Read),
        Cmd::Image { .. } => Forward(Privileged),
        Cmd::Serve { .. } => Refuse("the console runs as the wicket user under systemd: systemctl status wicket-console"),
        Cmd::Daemon { .. } => Refuse("the daemon runs as the wicket user under systemd: systemctl status wicketd"),
        Cmd::Program { cmd: ProgramCmd::Digest { .. } } => Local,
        // Reads a manifest the caller names, in the caller's own process.
        Cmd::Zone { .. } => Local,
        Cmd::Operator { cmd } => match cmd {
            OperatorCmd::List | OperatorCmd::Sessions => Forward(Read),
            // A passkey enrolled by the operator's uid could approve in the console.
            OperatorCmd::EnrolLink { .. } | OperatorCmd::Reset | OperatorCmd::RevokeSession { .. } => Forward(Privileged),
        },
        Cmd::Identity { cmd } => match cmd {
            IdentityCmd::Issuer | IdentityCmd::Show { .. } | IdentityCmd::List => Forward(Read),
            IdentityCmd::Revoke { .. } => Forward(Revoke),
            IdentityCmd::Init { .. } => Forward(Privileged),
        },
        // Both stop things, and a reconcile pass can create machines a lease needs.
        Cmd::Reap { .. } | Cmd::Reconcile { .. } | Cmd::Attach { .. } => Forward(Privileged),
        Cmd::Lease { cmd } => match cmd {
            LeaseCmd::List => Forward(Read),
            LeaseCmd::Release { .. } => Forward(Revoke),
        },
        Cmd::Node { cmd } => match cmd {
            NodeCmd::List => Forward(Read),
            NodeCmd::Token { .. } | NodeCmd::Enrol { .. } | NodeCmd::Revoke { .. } | NodeCmd::RenewCa { .. } | NodeCmd::Install { .. } => {
                Forward(Privileged)
            }
            NodeCmd::Serve { .. } | NodeCmd::Attach { .. } => Local,
        },
        // Spends money after a terminal prompt.
        Cmd::Place { .. } => Forward(Privileged),
        // Applying an org policy changes what every box may do, and revokes runs.
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => Forward(Read),
            PolicyCmd::Apply { .. } => Forward(Privileged),
            // Read files the caller names, in the caller's own process.
            PolicyCmd::Check { .. } | PolicyCmd::Zone { .. } => Local,
        },
        // The kit holds every key and secret; a restore replaces the ledger; the roots are the roots.
        Cmd::State { cmd } => match cmd {
            StateCmd::Check { probe: false } => Forward(Read),
            // Writes (and deletes) an object in the store.
            StateCmd::Check { probe: true } => Forward(Privileged),
            StateCmd::Replicate => Refuse("the ledger's stream runs as the wicket user under systemd: systemctl status wicket-state"),
            StateCmd::Kit { .. } | StateCmd::Restore { .. } => Forward(Privileged),
        },
        Cmd::Keys { .. } => Forward(Privileged),
        Cmd::Itself { cmd } => match cmd {
            SelfCmd::Status => Forward(Read),
            // Changes the code that holds every key: root's alone, and never the daemon's own uid
            // (`root_only`).
            SelfCmd::Update { .. }
            | SelfCmd::Follow
            | SelfCmd::Rollback { .. }
            | SelfCmd::Prune { .. }
            | SelfCmd::TrustKey { .. }
            | SelfCmd::Health { .. } => Forward(Privileged),
            // Touch no wicket data.
            SelfCmd::Keygen { .. } | SelfCmd::Sign { .. } | SelfCmd::Describe => Local,
        },
        Cmd::Dev { cmd } => match cmd {
            DevCmd::MockLlm { .. } => Local,
            DevCmd::NodeFeedProbe { .. } => Local,
        },
    }
}

/// Commands only root may run through the daemon: not even the daemon's own uid, which runs runs'
/// supervisors, gateways and proxies (#162). Updating wicket, or changing which keys may sign an
/// update, is a human's act on the host; an agent can only ask (`request_update`).
pub fn root_only(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Itself {
            cmd: SelfCmd::Update { .. } | SelfCmd::Follow | SelfCmd::Rollback { .. } | SelfCmd::Prune { .. } | SelfCmd::TrustKey { .. }
        }
    )
}

/// Arguments only wicket itself passes (a parent starting a child, the console starting a run): a
/// caller of the socket could otherwise claim to be a child of another run, or of a lease.
pub fn internal_args(cmd: &Cmd) -> Option<&'static str> {
    match cmd {
        Cmd::Run { run_id: Some(_), .. } => Some("--run-id"),
        Cmd::Run { parent_run: Some(_), .. } => Some("--parent-run"),
        Cmd::Run { lease: Some(_), .. } => Some("--lease"),
        // ssh keys for nodes belong to the wicket user, not to the caller.
        Cmd::Run { ssh_key: Some(_), .. } => Some("--ssh-key"),
        // What woke an agent is recorded as fact: a message's arrival, set by wicket.
        Cmd::Wake { by: Some(_), .. } => Some("--by"),
        _ => None,
    }
}

/// Who is granted a class: user names or uids, and groups by name or gid.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grantees {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// The policy file. Missing classes default to the `wicket-operators` group.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "operators")]
    pub read: Grantees,
    #[serde(default = "operators")]
    pub run: Grantees,
    #[serde(default = "operators")]
    pub revoke: Grantees,
}

fn operators() -> Grantees {
    Grantees { users: vec![], groups: vec![OPERATORS_GROUP.into()] }
}

impl Default for Policy {
    fn default() -> Self {
        Policy { read: operators(), run: operators(), revoke: operators() }
    }
}

impl Policy {
    pub fn parse(s: &str) -> anyhow::Result<Policy> {
        if s.trim().is_empty() {
            return Ok(Policy::default());
        }
        Ok(serde_yaml::from_str(s)?)
    }

    /// The policy at `path`, or the default when there is none.
    pub fn load(path: &Path) -> anyhow::Result<Policy> {
        match std::fs::read_to_string(path) {
            Ok(s) => Policy::parse(&s).map_err(|e| anyhow::anyhow!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
            Err(e) => Err(anyhow::anyhow!("{}: {e}", path.display())),
        }
    }

    fn grantees(&self, c: Class) -> Option<&Grantees> {
        match c {
            Class::Read => Some(&self.read),
            Class::Run => Some(&self.run),
            Class::Revoke => Some(&self.revoke),
            Class::Privileged => None,
        }
    }
}

/// How the caller was let in, recorded with what it does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Basis {
    /// uid 0 over the socket: the host break-glass.
    Root,
    /// The daemon's own uid.
    Daemon,
    /// Granted by the policy file.
    Policy,
}

/// Whether `peer` may do `class`. `daemon_uid` is the uid the daemon runs as.
pub fn authorize(peer: &Peer, class: Class, policy: &Policy, daemon_uid: u32) -> Result<Basis, String> {
    if peer.uid == 0 {
        return Ok(Basis::Root);
    }
    if peer.uid == daemon_uid {
        return Ok(Basis::Daemon);
    }
    let Some(g) = policy.grantees(class) else {
        return Err(format!(
            "{} (uid {}) may not do this through wicketd: it needs root on the host (sudo wicket …) or a passkey in the console",
            peer.user, peer.uid
        ));
    };
    let user_ok = g.users.iter().any(|u| *u == peer.user || u.parse::<u32>().ok() == Some(peer.uid));
    let group_ok = g.groups.iter().any(|want| peer.groups.iter().any(|(gid, name)| want == name || want.parse::<u32>().ok() == Some(*gid)));
    if user_ok || group_ok {
        Ok(Basis::Policy)
    } else {
        Err(format!(
            "{} (uid {}) may not {} through wicketd: the policy ({POLICY_PATH}) grants it to users [{}] and groups [{}]",
            peer.user,
            peer.uid,
            match class {
                Class::Read => "read state",
                Class::Run => "start or steer runs",
                Class::Revoke => "revoke",
                Class::Privileged => unreachable!(),
            },
            g.users.join(", "),
            g.groups.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cmd(args: &[&str]) -> Cmd {
        let mut v = vec!["wicket"];
        v.extend_from_slice(args);
        crate::Cli::try_parse_from(v).expect("parses").cmd
    }

    fn peer(uid: u32, user: &str, groups: &[(u32, &str)]) -> Peer {
        Peer { uid, gid: uid, pid: 1, user: user.into(), groups: groups.iter().map(|(g, n)| (*g, n.to_string())).collect() }
    }

    const DAEMON: u32 = 990;

    #[test]
    fn every_command_line_is_routed_as_documented() {
        use Class::*;
        let cases: &[(&[&str], Route)] = &[
            (&["run", "m.yaml"], Route::Forward(Run)),
            (&["wrap", "--manifest", "m.yaml", "--", "claude"], Route::Forward(Run)),
            (&["say", "r1", "hello"], Route::Forward(Run)),
            (&["hibernate", "r1"], Route::Forward(Run)),
            (&["wake", "a1", "hello"], Route::Forward(Run)),
            (&["agents"], Route::Forward(Read)),
            (&["pending"], Route::Forward(Read)),
            (&["links"], Route::Forward(Read)),
            (&["audit", "--verify"], Route::Forward(Read)),
            (&["doctor"], Route::Forward(Read)),
            (&["approve", "R1"], Route::Forward(Privileged)),
            (&["approve", "R1", "--unlimited", "--ttl", "1h"], Route::Forward(Privileged)),
            (&["deny", "R1"], Route::Forward(Privileged)),
            (&["unlink", "L1"], Route::Forward(Revoke)),
            (&["grant", "revoke", "G1"], Route::Forward(Revoke)),
            (&["secret", "list"], Route::Forward(Read)),
            (&["secret", "set", "claude-oauth"], Route::Forward(Privileged)),
            (&["secret", "set", "gh", "--hosts", "api.github.com"], Route::Forward(Privileged)),
            (&["secret", "hosts", "gh", "--hosts", "*.attacker.example"], Route::Forward(Privileged)),
            (&["secret", "link", "x", "--file", "/etc/shadow"], Route::Forward(Privileged)),
            (&["image"], Route::Forward(Privileged)),
            (&["program", "digest", "."], Route::Local),
            (&["operator", "list"], Route::Forward(Read)),
            (&["operator", "sessions"], Route::Forward(Read)),
            (&["operator", "enrol-link"], Route::Forward(Privileged)),
            (&["operator", "reset"], Route::Forward(Privileged)),
            (&["operator", "revoke-session", "--all"], Route::Forward(Privileged)),
            (&["identity", "issuer"], Route::Forward(Read)),
            (&["identity", "show", "r1"], Route::Forward(Read)),
            (&["identity", "list"], Route::Forward(Read)),
            (&["identity", "revoke", "r1"], Route::Forward(Revoke)),
            (&["identity", "init", "--trust-domain", "wicket.example.com"], Route::Forward(Privileged)),
            (&["reap"], Route::Forward(Privileged)),
            (&["reconcile", "--dry-run"], Route::Forward(Privileged)),
            (&["lease", "list"], Route::Forward(Read)),
            (&["lease", "release", "l1"], Route::Forward(Revoke)),
            (&["node", "list"], Route::Forward(Read)),
            (&["node", "token"], Route::Forward(Privileged)),
            (&["node", "revoke", "n1"], Route::Forward(Privileged)),
            (&["node", "serve"], Route::Local),
            (&["node", "attach"], Route::Local),
            (&["place", "plans"], Route::Forward(Privileged)),
            (&["self", "status"], Route::Forward(Read)),
            (&["self", "update", "/tmp/w.tar.gz"], Route::Forward(Privileged)),
            (&["self", "update", "/tmp/w", "--nodes", "all"], Route::Forward(Privileged)),
            (&["self", "rollback"], Route::Forward(Privileged)),
            (&["self", "prune", "--dry-run"], Route::Forward(Privileged)),
            (&["self", "trust-key", "/tmp/k.pub"], Route::Forward(Privileged)),
            (&["self", "keygen", "/tmp/k"], Route::Local),
            (&["self", "sign", "--key", "/tmp/k", "/tmp/w"], Route::Local),
            (&["dev", "mock-llm", "--command", "true"], Route::Local),
        ];
        for (args, want) in cases {
            assert_eq!(&route(&cmd(args)), want, "{args:?}");
        }
        assert!(matches!(route(&cmd(&["serve"])), Route::Refuse(_)));
        assert!(matches!(route(&cmd(&["daemon"])), Route::Refuse(_)));
    }

    #[test]
    fn internal_arguments_are_refused_from_callers() {
        assert_eq!(internal_args(&cmd(&["run", "m.yaml"])), None);
        assert_eq!(internal_args(&cmd(&["run", "--run-id", "r1", "m.yaml"])), Some("--run-id"));
        assert_eq!(internal_args(&cmd(&["run", "--parent-run", "r0", "m.yaml"])), Some("--parent-run"));
        assert_eq!(internal_args(&cmd(&["run", "--lease", "l1", "m.yaml"])), Some("--lease"));
        assert_eq!(internal_args(&cmd(&["run", "--node", "n1", "--ssh-key", "/k", "m.yaml"])), Some("--ssh-key"));
        assert_eq!(internal_args(&cmd(&["run", "--node", "n1", "m.yaml"])), None);
        assert_eq!(internal_args(&cmd(&["wake", "--by", "message", "a1"])), Some("--by"));
        assert_eq!(internal_args(&cmd(&["wake", "a1"])), None);
    }

    #[test]
    fn the_operators_uid_can_run_and_read_but_never_approve() {
        let p = Policy::default();
        let alex = peer(1000, "alex", &[(1000, "alex"), (1001, OPERATORS_GROUP)]);
        for c in [Class::Read, Class::Run, Class::Revoke] {
            assert_eq!(authorize(&alex, c, &p, DAEMON), Ok(Basis::Policy), "{c:?}");
        }
        let e = authorize(&alex, Class::Privileged, &p, DAEMON).unwrap_err();
        assert!(e.contains("root") && e.contains("passkey"), "{e}");
        // A policy can't grant the privileged class: there is no key for it.
        assert!(Policy::parse("privileged: {users: [alex]}").is_err());
    }

    #[test]
    fn root_and_the_daemon_uid_may_do_everything() {
        let p = Policy::parse("read: {users: []}\nrun: {users: []}\nrevoke: {users: []}").unwrap();
        for c in [Class::Read, Class::Run, Class::Revoke, Class::Privileged] {
            assert_eq!(authorize(&peer(0, "root", &[(0, "root")]), c, &p, DAEMON), Ok(Basis::Root));
            assert_eq!(authorize(&peer(DAEMON, "wicket", &[]), c, &p, DAEMON), Ok(Basis::Daemon));
        }
    }

    #[test]
    fn users_outside_the_policy_get_nothing() {
        let p = Policy::default();
        let eve = peer(1002, "eve", &[(1002, "eve"), (27, "sudo")]);
        for c in [Class::Read, Class::Run, Class::Revoke, Class::Privileged] {
            assert!(authorize(&eve, c, &p, DAEMON).is_err(), "{c:?}");
        }
    }

    #[test]
    fn policy_names_users_groups_and_ids() {
        let p = Policy::parse("read: {users: [bob, '1003'], groups: ['2000']}\nrun: {groups: [builders]}\n").unwrap();
        assert_eq!(p.revoke, operators(), "unlisted classes keep the default");
        let bob = peer(1004, "bob", &[]);
        assert_eq!(authorize(&bob, Class::Read, &p, DAEMON), Ok(Basis::Policy));
        assert!(authorize(&bob, Class::Run, &p, DAEMON).is_err());
        assert_eq!(authorize(&peer(1003, "carol", &[]), Class::Read, &p, DAEMON), Ok(Basis::Policy));
        assert_eq!(authorize(&peer(1005, "dan", &[(2000, "x")]), Class::Read, &p, DAEMON), Ok(Basis::Policy));
        assert_eq!(authorize(&peer(1006, "erin", &[(3000, "builders")]), Class::Run, &p, DAEMON), Ok(Basis::Policy));
        assert!(Policy::parse("read: {users: [a], extra: 1}").is_err());
        assert_eq!(Policy::parse("").unwrap(), Policy::default());
    }
}
