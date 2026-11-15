//! `images/claude-code/wicket-entry` against this wicket-fwd (#287): the script runs with stand-ins
//! for `setpriv` (checks its flags, then runs the rest) and `ip` (records its batch), and a wrapper
//! that runs the real forwarder with the box's paths and addresses moved under a test directory and
//! onto 127.0.0.1. Skipped where the script isn't next to the crate (the image's build context).

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../images/claude-code/wicket-entry");

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("wentry-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/bash\nset -eu\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A box's root under a test directory, with the stand-ins on PATH.
fn the_box() -> PathBuf {
    let root = tmpdir();
    let bin = root.join("bin");
    for d in ["bin", "wicket/sock", "wicket/ca", "home"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("roots.pem"), "ROOTS\n").unwrap();
    std::fs::write(root.join("wicket/ca/ca.pem"), "RUN CA\n").unwrap();
    script(
        &bin.join("setpriv"),
        r#"for f in --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --bounding-set=-all; do
  case " $* " in *" $f "*) ;; *) echo "setpriv: missing $f" >&2; exit 99 ;; esac
done
while [ "$1" != -- ]; do shift; done; shift
exec "$@""#,
    );
    script(
        &bin.join("ip"),
        r#"[ "$*" = "-batch -" ] || exit 98
cat > "$ROOT/ip.batch"
exit "${IP_FAIL:-0}""#,
    );
    script(
        &bin.join("wicket-fwd"),
        r#"args=()
for a in "$@"; do
  # Paths already under the test's root (its home) stay as they are: the root's own path may contain
  # /wicket/ (a checkout named wicket).
  case $a in "$ROOT"*) args+=("$a"); continue ;; esac
  a=${a//198.18.0.1:8080/127.0.0.1:${FWD_BUSY:-0}}
  a=${a//198.18.0.1:[0-9]*=/127.0.0.1:0=}
  a=${a//0.0.0.0:443/127.0.0.1:0}
  a=${a//\/wicket\//$ROOT/wicket/}
  a=${a//\/tmp\/ca-bundle.pem/$ROOT/ca-bundle.pem}
  a=${a//\/etc\/ssl\/certs\/ca-certificates.crt/$ROOT/roots.pem}
  a=${a//\/workspace\/out/$ROOT/out}
  args+=("$a")
done
echo $$ > "$ROOT/fwd.pid"
readlink /proc/$$/fd/0 /proc/$$/fd/1 > "$ROOT/fwd.pipes"
exec "$REAL_FWD" "${args[@]}""#,
    );
    // The program: what it was started with, and what its descriptors are.
    script(
        &bin.join("prog"),
        r#"readlink /proc/$$/fd/* > "$ROOT/prog.fds" || :
printf 'args %s\ncert %s\n' "$*" "$SSL_CERT_FILE" > "$ROOT/prog.out""#,
    );
    root
}

/// Runs the script (its output to files: the forwarder it leaves running, as a box's would, holds
/// them), then stops that forwarder.
fn run(root: &Path, env: &[(&str, &str)]) -> (Output, Duration) {
    let path = format!("{}:{}", root.join("bin").display(), std::env::var("PATH").unwrap_or_default());
    let file = |n: &str| std::fs::File::create(root.join(n)).unwrap();
    let t = Instant::now();
    let status = Command::new("bash")
        .args([SCRIPT, "prog", "a b", "c"])
        .env_clear()
        .env("PATH", path)
        .env("ROOT", root)
        .env("REAL_FWD", env!("CARGO_BIN_EXE_wicket-fwd"))
        .env("HOME", root.join("home"))
        .env("WICKET_AS_USER", "1000:1000")
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(file("stdout"))
        .stderr(file("stderr"))
        .status()
        .unwrap();
    let took = t.elapsed();
    if let Ok(pid) = std::fs::read_to_string(root.join("fwd.pid")) {
        let _ = Command::new("kill").arg(pid.trim()).status();
    }
    let read = |n: &str| std::fs::read(root.join(n)).unwrap();
    (Output { status, stdout: read("stdout"), stderr: read("stderr") }, took)
}

fn present() -> bool {
    Path::new(SCRIPT).is_file() && Command::new("bash").arg("-c").arg("true").status().is_ok_and(|s| s.success())
}

#[test]
fn starts_the_program_once_the_forwarder_listens_and_records_each_step() {
    if !present() {
        return;
    }
    let root = the_box();
    let (out, took) = run(&root, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("wicket-fwd: listening tcp 127.0.0.1:"), "{stderr}");
    // No waiting out a timeout anywhere (a forwarder never told its stdin ended waits 5 s for it).
    assert!(took < Duration::from_secs(4), "took {took:?}");
    let batch = std::fs::read_to_string(root.join("ip.batch")).unwrap();
    assert_eq!(batch.lines().count(), 34, "{batch}");
    for l in [
        "addr replace 198.18.1.1/32 dev lo",
        "addr replace 198.18.1.32/32 dev lo",
        "addr replace 198.18.0.1/32 dev lo",
        "addr replace 198.19.0.1/16 dev lo",
    ] {
        assert!(batch.lines().any(|b| b == l), "{l} in {batch}");
    }
    assert!(root.join("home/.claude").is_dir());
    assert!(root.join("out").is_dir());
    assert_eq!(std::fs::read_to_string(root.join("ca-bundle.pem")).unwrap(), "ROOTS\nRUN CA\n");
    let prog = std::fs::read_to_string(root.join("prog.out")).unwrap();
    assert_eq!(prog, "args a b c\ncert /tmp/ca-bundle.pem\n");
    let pipes = std::fs::read_to_string(root.join("fwd.pipes")).unwrap();
    let fds = std::fs::read_to_string(root.join("prog.fds")).unwrap();
    assert_eq!(pipes.lines().filter(|p| p.starts_with("pipe:")).count(), 2, "{pipes}");
    assert!(pipes.lines().all(|p| !fds.lines().any(|f| f == p)), "the program inherits none of the forwarder's pipes: {fds} / {pipes}");
    let times = std::fs::read_to_string(root.join("wicket/sock/entry.times")).unwrap();
    let steps: Vec<&str> = times.lines().map(|l| l.split(' ').next().unwrap()).collect();
    assert_eq!(steps, ["start", "addrs", "setup", "fwd", "exec"], "{times}");
    let at: Vec<f64> = times.lines().map(|l| l.split(' ').nth(1).unwrap().replace(',', ".").parse().unwrap()).collect();
    assert!(at.windows(2).all(|w| w[0] <= w[1]), "{times}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn never_starts_the_program_if_the_forwarder_or_the_addresses_fail() {
    if !present() {
        return;
    }
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port().to_string();
    let cases = [
        // A listener that can't bind (its port taken).
        ("busy port", vec![("FWD_BUSY", port.as_str())], ""),
        // The run's CA missing: no bundle, so no `prepared`.
        ("no CA", vec![], "wicket/ca/ca.pem"),
        // A home that can't be made (a file where it would be).
        ("no home", vec![], "home"),
        ("ip fails", vec![("IP_FAIL", "1")], ""),
    ];
    for (name, env, remove) in cases {
        let root = the_box();
        match remove {
            "" => {}
            "home" => {
                std::fs::remove_dir(root.join("home")).unwrap();
                std::fs::write(root.join("home"), "").unwrap();
            }
            f => std::fs::remove_file(root.join(f)).unwrap(),
        }
        let (out, took) = run(&root, &env);
        assert!(!out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(!root.join("prog.out").exists(), "{name}: the program never starts");
        assert!(took < Duration::from_secs(4), "{name}: fails at once, took {took:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
