//! The daemon end to end over a real socket, as a second uid would see it: the daemon is told it
//! runs as another uid, so this test's own uid is an operator the policy names, not the owner. The
//! command it runs is a script that reports what it was given.

use super::*;
use std::io::Read;
use std::os::fd::AsRawFd;

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp() -> Tmp {
    let mut n = [0u8; 6];
    getrandom::fill(&mut n).unwrap();
    let d = std::env::temp_dir().join(format!("wicketd-test-{}", hex::encode(n)));
    std::fs::create_dir_all(&d).unwrap();
    Tmp(d)
}

const FAKE: &str = r#"#!/bin/sh
echo "argv: $*"
echo "cwd: $(pwd)"
echo "home: $WICKET_HOME"
echo "operator: $WICKET_OPERATOR"
echo "principal: $WICKET_PRINCIPAL"
case "$1" in
  run) echo "manifest: $(head -c 200 "$2" | tr '\n' ' ')"; [ "$3" = --workdir ] && echo "workdir: $(ls -A "$4" | tr '\n' ' ')";
       src=$(dirname "$2")/../programs/repo-stats; [ -d "$src" ] && echo "program: $(ls "$src" | tr '\n' ' ')";;
  session) echo "stdin: $(cat)";;
  links) exit "$3";;
esac
exit 0
"#;

struct Fixture {
    dir: Tmp,
    sock: PathBuf,
}

/// A daemon that believes it runs as another uid, granting this test's uid read, run and revoke.
fn daemon() -> Fixture {
    let dir = tmp();
    let data = dir.0.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let exe = dir.0.join("fake-wicket");
    std::fs::write(&exe, FAKE).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    // SAFETY: a plain getter.
    let me = unsafe { libc::geteuid() };
    let policy = dir.0.join("policy.yaml");
    std::fs::write(&policy, format!("read: {{users: ['{me}']}}\nrun: {{users: ['{me}']}}\nrevoke: {{users: ['{me}']}}\n")).unwrap();
    let vault = wicket_proxy::vault::Vault::new(dir.0.join("vault"));
    vault.set("gh", "the-real-token").unwrap();
    vault.set_hosts("gh", &["api.github.com".into()]).unwrap();
    vault.set("claude-oauth", "the-login").unwrap();
    // As `wicket secret set` binds it: the harness's default model secret, to its model host.
    crate::cmd::secret::bind(&vault, "claude-oauth", &[]).unwrap();
    let d = Arc::new(Daemon {
        data_dir: data,
        policy_path: policy,
        uid: me.wrapping_add(4242),
        user: "wicket".into(),
        exe,
        vault_dir: dir.0.join("vault"),
    });
    let sock = dir.0.join("wicketd.sock");
    let l = listen(&sock).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let d = d.clone();
            let c = c.unwrap();
            std::thread::spawn(move || d.handle(c).unwrap());
        }
    });
    Fixture { dir, sock }
}

/// Runs a command line through the daemon; its exit status, stdout and stderr.
async fn call(f: &Fixture, args: &[&str], stdin: Option<&str>) -> Result<(i32, String, String)> {
    use clap::Parser;
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let cmd = crate::Cli::try_parse_from(std::iter::once("wicket".to_string()).chain(argv.clone()))?.cmd;
    let (mut or, ow) = std::io::pipe()?;
    let (mut er, ew) = std::io::pipe()?;
    let (ir, mut iw) = std::io::pipe()?;
    if let Some(s) = stdin {
        iw.write_all(s.as_bytes())?;
    }
    drop(iw);
    let code = client::forward_with(&f.sock, &cmd, argv, [ir.as_raw_fd(), ow.as_raw_fd(), ew.as_raw_fd()]).await;
    drop((ow, ew, ir));
    let code = code?;
    let (mut o, mut e) = (String::new(), String::new());
    or.read_to_string(&mut o)?;
    er.read_to_string(&mut e)?;
    Ok((code, o, e))
}

#[tokio::test]
async fn an_operator_reads_state_as_itself_through_the_daemon() {
    let f = daemon();
    let (code, out, _) = call(&f, &["pending"], None).await.unwrap();
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("argv: pending\n"), "{out}");
    assert!(out.contains(&format!("home: {}", f.dir.0.join("data").display())), "{out}");
    // Who it is comes from the kernel, not from the caller's environment.
    let user = proto::user_name(unsafe { libc::geteuid() }).unwrap();
    assert!(out.contains(&format!("operator: {user}@cli (uid ")), "{out}");
    assert!(out.contains(r#""assurance":"unix-peercred""#) && out.contains(&format!(r#""id":"{user}""#)), "{out}");
    // Exit statuses come back.
    let (code, ..) = call(&f, &["links", "--tail", "5"], None).await.unwrap();
    assert_eq!(code, 5);
    // stdin is the caller's.
    let (_, out, _) = call(&f, &["session", "r1"], Some("from the caller")).await.unwrap();
    assert!(out.contains("stdin: from the caller"), "{out}");
}

#[tokio::test]
async fn an_operator_cannot_approve_deny_or_enrol_a_passkey() {
    let f = daemon();
    for args in [
        &["approve", "R1"][..],
        &["deny", "R1"],
        &["operator", "enrol-link"],
        &["operator", "reset"],
        &["secret", "link", "x", "--file", "/etc/hostname"],
        &["image"],
        &["reconcile"],
    ] {
        let err = call(&f, args, None).await.unwrap_err();
        // The policy's refusal: exit 3 (#574).
        assert_eq!(wicket_home::exit::code_of(&err), Some(wicket_home::exit::Code::Refused), "{args:?}: {err}");
        let e = err.to_string();
        assert!(e.contains("needs root") && e.contains("passkey"), "{args:?}: {e}");
    }
    // Refusals are in the audit log.
    let l = wicket_store::Ledger::open(&f.dir.0.join("data/ledger.db")).unwrap();
    let refused: Vec<_> = l.audit_tail(50).unwrap().into_iter().filter(|r| r.2 == "daemon.refused").collect();
    assert_eq!(refused.len(), 7);
    assert!(refused.iter().any(|r| r.4.contains("approve")));
    l.verify_audit().unwrap();
}

#[tokio::test]
async fn internal_arguments_and_foreign_directories_are_refused() {
    let f = daemon();
    let m = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/demo.yaml");
    let e = call(&f, &["run", "--run-id", "x", m], None).await.unwrap_err().to_string();
    assert!(e.contains("--run-id is for wicket's own use"), "{e}");
    let e = call(&f, &["run", "--parent-run", "x", m], None).await.unwrap_err().to_string();
    assert!(e.contains("--parent-run"), "{e}");
    // Nothing is mounted in place for an operator: the path could be swapped for a link into the
    // data after any check. Not even the caller's own directory, nor through wrap.
    let own = f.dir.0.join("project");
    std::fs::create_dir_all(&own).unwrap();
    for d in ["/usr", f.dir.0.to_str().unwrap(), own.to_str().unwrap()] {
        let e = call(&f, &["run", "--workspace-dir", d, m], None).await.unwrap_err().to_string();
        assert!(e.contains("only root mounts in place"), "{d}: {e}");
    }
    let e = call(&f, &["wrap", "--manifest", m, "--", "claude"], None).await.unwrap_err().to_string();
    assert!(e.contains("only root can"), "{e}");
    // The console and the daemon aren't started through the daemon.
    assert!(call(&f, &["serve"], None).await.unwrap_err().to_string().contains("systemd"));
}

#[tokio::test]
async fn a_run_gets_its_manifest_program_and_workdir_as_content() {
    let f = daemon();
    let m = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/program-repo-stats.yaml");
    let wd = f.dir.0.join("wd");
    std::fs::create_dir_all(wd.join("sub")).unwrap();
    std::fs::write(wd.join("sub/a.txt"), "a").unwrap();
    std::fs::write(wd.join(".hidden"), "h").unwrap();
    let (code, out, err) = call(&f, &["run", "--workdir", wd.to_str().unwrap(), "--task", "count", m], None).await.unwrap();
    assert_eq!(code, 0, "{out}{err}");
    let stage = f.dir.0.join("data/daemon/stage");
    assert!(out.contains(&format!("argv: run {}", stage.display())), "staged, not the caller's path: {out}");
    assert!(out.contains("--task count\n") && !out.contains("--image"), "no --image unless one is named (#171): {out}");
    assert!(out.contains("manifest: # A deterministic program"), "{out}");
    assert!(out.contains("workdir: .hidden sub"), "{out}");
    assert!(out.contains("program: stats.sh"), "the program's source sits where the manifest says: {out}");
    assert!(out.contains(&format!("cwd: {}", f.dir.0.join("data").display())), "{out}");
    assert_eq!(std::fs::read_dir(&stage).unwrap().count(), 0, "the stage is removed afterwards");
}

#[tokio::test]
async fn a_caller_that_lies_about_its_program_source_is_refused() {
    // The client announces no program source but sends a manifest with one that climbs out of the
    // stage (towards the data directory): the daemon checks the manifest that arrived.
    let f = daemon();
    let s = UnixStream::connect(&f.sock).unwrap();
    proto::send_fds(&s, &[0, 1, 2]).unwrap();
    let mut w = s.try_clone().unwrap();
    let mut r = s.try_clone().unwrap();
    let hello = Hello {
        version: "0".into(),
        argv: vec!["run".into(), "m.yaml".into()],
        cwd: "/".into(),
        log: None,
        dir_fd: false,
        manifest_name: Some("m.yaml".into()),
        program_source: None,
    };
    proto::write_json(&mut w, kind::HELLO, &hello).unwrap();
    assert_eq!(proto::read_frame(&mut r).unwrap().unwrap().0, kind::WELCOME);
    let yaml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/program-repo-stats.yaml"))
        .unwrap()
        .replace("../programs/repo-stats", "../../../../.config/wicket/secrets");
    let e = proto::Entry { role: "manifest".into(), path: "".into(), kind: "file".into(), mode: 0o644, target: None, append: false };
    proto::write_frame(&mut w, kind::UPLOAD, &proto::upload_frame(&e, yaml.as_bytes()).unwrap()).unwrap();
    proto::write_frame(&mut w, kind::GO, b"").unwrap();
    let (k, p) = proto::read_frame(&mut r).unwrap().unwrap();
    assert_eq!(k, kind::ERROR);
    assert!(String::from_utf8_lossy(&p).contains("program source differs"));
}

#[tokio::test]
async fn an_operator_manifest_cannot_send_a_secret_anywhere_root_did_not_bind_it() {
    let f = daemon();
    let write = |name: &str, zone: &str| {
        let p = f.dir.0.join(name);
        let llm = if zone.contains("llm:") { "" } else { ", llm: {secret: claude-oauth}" };
        std::fs::write(&p, format!("task: t\nagent: {{name: a}}\nzone: {{name: z, {zone}{llm}}}\n")).unwrap();
        p.display().to_string()
    };
    // Injecting the GitHub token into requests to the operator's own host.
    let evil = write("evil.yaml", "inject: [{host: attacker.example, header: Authorization, format: 'Bearer {secret}', secret: gh}]");
    let e = call(&f, &["run", &evil], None).await.map(|_| ()).map_err(|e| format!("{e:#}")).unwrap_err();
    assert!(e.contains("may be sent only to api.github.com, not to attacker.example"), "{e}");
    // Or under a wildcard that covers more than the binding.
    let wide = write("wide.yaml", "inject: [{host: '*.github.com', header: Authorization, secret: gh}]");
    assert!(call(&f, &["run", &wide], None).await.map(|_| ()).map_err(|e| format!("{e:#}")).unwrap_err().contains("not to *.github.com"));
    // Pointing the model route, with the login, at another host.
    let llm = write("llm.yaml", "llm: {secret: claude-oauth, upstream: 'https://attacker.example'}");
    let e = call(&f, &["run", &llm], None).await.map(|_| ()).map_err(|e| format!("{e:#}")).unwrap_err();
    assert!(e.contains("may be sent only to api.anthropic.com, not to attacker.example"), "{e}");
    // A secret bound to nothing goes nowhere.
    wicket_proxy::vault::Vault::new(f.dir.0.join("vault")).set("loose", "x").unwrap();
    let loose = write("loose.yaml", "inject: [{host: api.github.com, header: Authorization, secret: loose}]");
    assert!(call(&f, &["run", &loose], None).await.map(|_| ()).map_err(|e| format!("{e:#}")).unwrap_err().contains("bound to no hosts"));
    // The hosts root bound it to are fine.
    let ok = write(
        "ok.yaml",
        "inject: [{host: api.github.com, header: Authorization, format: 'Bearer {secret}', secret: gh}], llm: {secret: claude-oauth}",
    );
    let (code, out, err) = call(&f, &["run", &ok], None).await.unwrap();
    assert_eq!(code, 0, "{out}{err}");
    // Every refusal is audited.
    let l = wicket_store::Ledger::open(&f.dir.0.join("data/ledger.db")).unwrap();
    let refused = l.audit_tail(50).unwrap().into_iter().filter(|r| r.2 == "daemon.refused").count();
    assert_eq!(refused, 4);
}

/// Plans `args` as root would have them run through the daemon, sends the files the client sends
/// for them (as content, in frames), and stages them as the daemon does. The child's argv, what
/// the stage holds, and `check_staged`'s verdict.
fn staged(args: &[&str], cwd: &Path) -> (Vec<String>, PathBuf, Result<()>, (upload::Stage, Tmp)) {
    use clap::Parser;
    let dir = tmp();
    let data = dir.0.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let d = Daemon {
        data_dir: data,
        policy_path: dir.0.join("policy.yaml"),
        uid: 4242,
        user: "wicket".into(),
        exe: "/bin/false".into(),
        vault_dir: dir.0.join("vault"),
    };
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let cmd = crate::Cli::try_parse_from(std::iter::once("wicket".to_string()).chain(argv.clone())).unwrap().cmd;
    let hello = Hello {
        version: "0".into(),
        argv,
        cwd: cwd.display().to_string(),
        log: None,
        dir_fd: false,
        manifest_name: None,
        program_source: None,
    };
    let peer = proto::Peer { pid: 1, uid: 0, gid: 0, user: "root".into(), groups: vec![] };
    let mut plan = d.plan(&peer, &Basis::Root, &cmd, &hello, None).unwrap();
    let mut frames = vec![];
    for (role, path) in client::self_uploads(&cmd) {
        upload::send(&mut frames, role, &path).unwrap();
    }
    let mut st = plan.stage.take().expect("staged");
    let mut r = &frames[..];
    while let Some((k, p)) = proto::read_frame(&mut r).unwrap() {
        assert_eq!(k, kind::UPLOAD);
        let (e, data) = proto::parse_upload(&p).unwrap();
        st.add(&e, data).unwrap();
    }
    st.finish().unwrap();
    let checked = check_staged(&cmd, &hello, &st, &d.vault_dir);
    let at = st.dir.clone();
    // The stage before the directory it lives in.
    (plan.argv, at, checked, (st, dir))
}

/// #564: `self trust-key` and `self update` name files that may be root's alone (`/root/k.pub`),
/// which wicketd, as the wicket user, can't read. They go as content, as a run's manifest does,
/// and the command runs on the staged copies.
#[test]
fn a_trusted_key_and_an_update_build_go_to_the_daemon_as_content() {
    let src = tmp();
    std::fs::write(src.0.join("k.pub"), "the key").unwrap();
    let (argv, stage, checked, _st) = staged(&["self", "trust-key", src.0.join("k.pub").to_str().unwrap()], &src.0);
    checked.unwrap();
    assert_eq!(argv, ["self", "trust-key", stage.join("key.pub").to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(stage.join("key.pub")).unwrap(), "the key");

    // A build and the signature beside it; every option carried over, the paths staged.
    std::fs::write(src.0.join("wicket"), "the build").unwrap();
    std::fs::write(src.0.join("wicket.sig"), "its signature").unwrap();
    let a = src.0.join("wicket");
    let args = [
        "self",
        "update",
        a.to_str().unwrap(),
        "--nodes",
        "all",
        "--window",
        "5s",
        "--interval",
        "2s",
        "--check",
        "true",
        "--image",
        "i",
        "--no-prune",
    ];
    let (argv, stage, checked, _st) = staged(&args, &src.0);
    checked.unwrap();
    let built = stage.join("build/artifact");
    assert_eq!(
        argv,
        [
            "self",
            "update",
            built.to_str().unwrap(),
            "--nodes",
            "all",
            "--window",
            "5s",
            "--interval",
            "2s",
            "--check",
            "true",
            "--image",
            "i",
            "--no-prune",
        ]
    );
    assert_eq!(std::fs::read_to_string(&built).unwrap(), "the build");
    assert_eq!(std::fs::read_to_string(stage.join("build/artifact.sig")).unwrap(), "its signature");
    // The re-made command line means what the caller's did.
    use clap::Parser;
    assert!(crate::Cli::try_parse_from(std::iter::once("wicket".to_string()).chain(argv)).is_ok());

    // `--sig` elsewhere lands beside the build too; none at all sends none (an approval of its
    // sha256 may stand in).
    std::fs::write(src.0.join("other.sig"), "elsewhere").unwrap();
    let (_, stage, checked, _st) =
        staged(&["self", "update", a.to_str().unwrap(), "--sig", src.0.join("other.sig").to_str().unwrap()], &src.0);
    checked.unwrap();
    assert_eq!(std::fs::read_to_string(stage.join("build/artifact.sig")).unwrap(), "elsewhere");
    std::fs::remove_file(src.0.join("wicket.sig")).unwrap();
    let (_, stage, checked, _st) = staged(&["self", "update", a.to_str().unwrap()], &src.0);
    checked.unwrap();
    assert!(!stage.join("build/artifact.sig").exists());

    // A directory where the build should be is refused before anything runs.
    std::fs::create_dir(src.0.join("adir")).unwrap();
    let (_, _, checked, _st) = staged(&["self", "update", src.0.join("adir").to_str().unwrap()], &src.0);
    assert!(checked.unwrap_err().to_string().contains("did not arrive as a file"));
}

/// #487: on SIGHUP, with commands running (long-lived runs), the daemon writes their handoff and
/// moves on at once. It once deadlocked here, asking the registry it held how many it handed over,
/// and refused every command until it was restarted.
#[test]
fn moving_to_a_new_build_with_running_commands_does_not_hang() {
    use std::os::unix::process::CommandExt;
    static DRAINING_HERE: AtomicBool = AtomicBool::new(false);
    static IN_FLIGHT_HERE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let t = tmp();
    let path = t.0.join(handoff::FILE);
    let pid = std::process::Command::new("sh").args(["-c", "sleep 30"]).process_group(0).spawn().unwrap().id() as i32;
    let (daemon, client) = UnixStream::pair().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let follower = std::thread::spawn(move || handoff::follow(pid, &daemon, None, move || tx.send(()).unwrap()).unwrap());
    rx.recv().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let p = path.clone();
    std::thread::spawn(move || {
        let held = drain(&p, &DRAINING_HERE, &IN_FLIGHT_HERE);
        done_tx.send(held.0.as_ref().map(|h| h.handed())).unwrap();
        // Held until the test has looked (as across an exec), then dropped: the exec failed.
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(held);
    });
    let handed = done_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the handoff is written at once, not hung");
    assert!(handed.is_some_and(|n| n >= 1), "{handed:?}");
    assert!(DRAINING_HERE.load(Ordering::SeqCst), "new commands are refused meanwhile");
    let h: handoff::Handoff = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(h.children.iter().any(|c| c.pid == pid));
    std::thread::sleep(std::time::Duration::from_millis(600));
    assert!(!DRAINING_HERE.load(Ordering::SeqCst), "a failed exec takes commands again");
    drop(client);
    assert_eq!(follower.join().unwrap(), 128 + libc::SIGTERM);
}

/// #487's deadlock class, over orders (#326): a handover with N followed commands that exit in any
/// order and at any time (before the drain, while the handoff holds the registry, after it), and
/// with commands still being started. In every round the drain returns within a bound, the daemon
/// takes commands again once the handoff is dropped (an exec that failed), and every follower ends
/// with its child's own exit code. Each wait is guarded by a timeout, so a deadlock fails the test
/// instead of hanging it.
#[test]
fn a_handover_ends_within_a_bound_whatever_order_the_commands_exit_in() {
    use std::os::unix::process::CommandExt;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut below = move |n: u64| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s % n
    };
    let within = |what: &str, limit: Duration, mut done: Box<dyn FnMut() -> bool>| {
        let t0 = Instant::now();
        while !done() {
            assert!(t0.elapsed() < limit, "{what}: not within {limit:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    for round in 0..12u64 {
        let draining: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let in_flight: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
        let t = tmp();
        let path = t.0.join(handoff::FILE);
        let mut followers = vec![];
        let mut clients = vec![];
        for i in 0..(1 + round % 5) {
            let (ms, code) = (below(500), 10 + i as i32);
            let script = format!("sleep {}.{:03}; exit {code}", ms / 1000, ms % 1000);
            let pid = std::process::Command::new("sh").args(["-c", &script]).process_group(0).spawn().unwrap().id() as i32;
            let (daemon, client) = UnixStream::pair().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let f = std::thread::spawn(move || handoff::follow(pid, &daemon, None, move || tx.send(()).unwrap()).unwrap());
            rx.recv_timeout(Duration::from_secs(5)).expect("followed");
            followers.push((code, f));
            clients.push(client);
        }
        // Commands still being started, each done at its own time.
        for _ in 0..below(3) {
            in_flight.fetch_add(1, Ordering::SeqCst);
            let ms = below(300);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(ms));
                in_flight.fetch_sub(1, Ordering::SeqCst);
            });
        }
        std::thread::sleep(Duration::from_millis(below(300)));
        let (dtx, drx) = std::sync::mpsc::channel();
        let (p, hold) = (path.clone(), 100 + below(300));
        std::thread::spawn(move || {
            let held = drain(&p, draining, in_flight);
            dtx.send(held.0.as_ref().map(|h| h.handed())).unwrap();
            // Held as across an exec, then dropped: the exec failed.
            std::thread::sleep(Duration::from_millis(hold));
            drop(held);
        });
        let handed = drx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| panic!("round {round}: the drain hung"));
        assert!(handed.is_some(), "round {round}: the handoff is written");
        assert!(draining.load(Ordering::SeqCst), "round {round}: new commands are refused while it is held");
        assert_eq!(in_flight.load(Ordering::SeqCst), 0, "round {round}: it waited for the commands being started");
        within(&format!("round {round}: commands are taken again"), Duration::from_secs(5), Box::new(|| !draining.load(Ordering::SeqCst)));
        for (code, f) in followers {
            let t0 = Instant::now();
            while !f.is_finished() {
                assert!(t0.elapsed() < Duration::from_secs(10), "round {round}: a follower didn't end");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(f.join().unwrap(), code, "round {round}: its child's exit code");
        }
        drop(clients);
    }
}

/// #477 within #487's handover (#326): supervisors the daemon is following, on another build, are
/// stopped (`stop_stale_supervisors`, SIGKILL) while a handover holds the registry. Stopping them
/// returns within its bound with every run, the drain returns, and each follower ends with the
/// kill's code once the handoff is dropped.
#[test]
fn stopping_followed_supervisors_during_a_handover_ends_within_a_bound() {
    use std::os::unix::process::CommandExt;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};
    for n in 1..=4u32 {
        let draining: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let in_flight: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
        let t = tmp();
        let ledger = wicket_store::Ledger::open(&t.0.join("ledger.db")).unwrap();
        let mut followers = vec![];
        let mut clients = vec![];
        let mut runs = vec![];
        for i in 0..n {
            let pid = std::process::Command::new("sh").args(["-c", "sleep 30"]).process_group(0).spawn().unwrap().id();
            let run = format!("run_{n}_{i}");
            ledger.run_started(&wicket_core::TenantId::single(), &wicket_core::RunId(run.clone()), "z", "a").unwrap();
            ledger.set_run_owner(&run, &crate::owner::owner_label_of(pid).unwrap()).unwrap();
            runs.push(run);
            let (daemon, client) = UnixStream::pair().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let f = std::thread::spawn(move || handoff::follow(pid as i32, &daemon, None, move || tx.send(()).unwrap()).unwrap());
            rx.recv_timeout(Duration::from_secs(5)).expect("followed");
            followers.push(f);
            clients.push(client);
        }
        // The handover holds the registry for a while (as across an exec).
        let (dtx, drx) = std::sync::mpsc::channel();
        let p = t.0.join(handoff::FILE);
        std::thread::spawn(move || {
            let held = drain(&p, draining, in_flight);
            dtx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(500));
            drop(held);
        });
        drx.recv_timeout(Duration::from_secs(10)).expect("the drain hung");
        // Meanwhile the new build stops the old supervisors (`sh` is another binary than this one).
        let t0 = Instant::now();
        let mut stopped = crate::update::stop_stale_supervisors(&ledger, &std::env::current_exe().unwrap()).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(10), "n {n}: stopping took {:?}", t0.elapsed());
        stopped.sort();
        assert_eq!(stopped, runs, "n {n}: every stale supervisor is stopped");
        for f in followers {
            let t0 = Instant::now();
            while !f.is_finished() {
                assert!(t0.elapsed() < Duration::from_secs(10), "n {n}: a follower didn't end");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(f.join().unwrap(), 128 + libc::SIGKILL, "n {n}: ended by the kill");
        }
        let t0 = Instant::now();
        while draining.load(Ordering::SeqCst) {
            assert!(t0.elapsed() < Duration::from_secs(5), "n {n}: commands are taken again");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(clients);
    }
}
