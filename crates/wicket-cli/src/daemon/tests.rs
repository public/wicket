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
    getrandom::getrandom(&mut n).unwrap();
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
  say) echo "stdin: $(cat)";;
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
    let d = Arc::new(Daemon { data_dir: data, policy_path: policy, uid: me.wrapping_add(4242), user: "wicket".into(), exe });
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
    let (_, out, _) = call(&f, &["say", "r1", "hi"], Some("from the caller")).await.unwrap();
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
        let e = call(&f, args, None).await.unwrap_err().to_string();
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
    assert!(out.contains("--task count --image wicket/claude-code:poc"), "{out}");
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
