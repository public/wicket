//! #582 step 5: wicketd's host manager against real `wicket supervise` processes. It starts every
//! shard's host, hears their heartbeats, fences one that dies (a higher epoch) and starts a fresh
//! one, and a host stopped with SIGTERM frees its shard with the clean-stop marker.

use std::time::{Duration, Instant};
use wicket_control::supervise::{HostIo, Manager, ProcIo};

struct Home(std::path::PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The real host processes, every one SIGKILLed when the test ends, pass or fail: a leftover
/// would hold the test's output open, and take a shard in a fresh ledger once the home is gone.
struct Io(ProcIo);

impl Drop for Io {
    fn drop(&mut self) {
        for o in self.0.spawned.clone() {
            let p = pid(&o);
            if wicket_home::owner::owner_label_of(p as u32).as_deref() == Some(o.as_str()) {
                unsafe { libc::kill(p, libc::SIGKILL) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(p, &mut st, 0) };
        }
    }
}

fn wait_for<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn pid(owner: &str) -> i32 {
    owner.split(':').nth(1).unwrap().parse().unwrap()
}

#[test]
fn the_manager_starts_hosts_fences_a_dead_one_and_starts_it_again() {
    // Short: the hosts' sockets live under it.
    let h = Home(std::env::temp_dir().join(format!("wsh-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&h.0);
    std::fs::create_dir_all(&h.0).unwrap();
    let ledger = wicket_store::Ledger::open(&h.0.join("ledger.db")).unwrap();
    // A second node, so shard 1 (of 2) has one: n2's shard is 1 (FNV-1a, pinned in supervise's tests).
    ledger
        .enrol_builtin_node(&wicket_store::NodeRow {
            name: "n2".into(),
            tenant: "t0".into(),
            target: "local".into(),
            host_key: String::new(),
            host_key_fp: String::new(),
            node_key: "00".into(),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: 0,
            status: "active".into(),
            revoked_at: None,
        })
        .unwrap();
    let mut guard = Io(ProcIo {
        exe: env!("CARGO_BIN_EXE_wicket").into(),
        data_dir: h.0.clone(),
        env: vec![("WICKET_HOME".into(), h.0.display().to_string()), ("WICKET_DAEMON_SOCKET".into(), "/nonexistent".into())],
        spawned: Vec::new(),
    });
    let io = &mut guard.0;
    let mut m = Manager::new(2);
    let t = m.tick(&ledger, io, wicket_store::now());
    assert_eq!(t.started, ["0", "1"], "{t:?}");
    let beats = wait_for("both hosts answer", || Some((io.heartbeat("0")?, io.heartbeat("1")?)));
    assert_eq!((beats.0.epoch, beats.1.epoch), (1, 1));
    // Healthy: nothing to do.
    let t = m.tick(&ledger, io, wicket_store::now());
    assert!(t.started.is_empty() && t.fenced.is_empty() && t.errors.is_empty(), "{t:?}");

    // Host 0 dies hard.
    unsafe { libc::kill(pid(&beats.0.owner), libc::SIGKILL) };
    wait_for("host 0 fenced", || {
        let t = m.tick(&ledger, io, wicket_store::now());
        (t.fenced == ["0"]).then_some(())
    });
    assert_eq!(ledger.supervisor_host("0").unwrap().unwrap().epoch, 2, "fenced at a higher epoch");
    // A fresh host takes it at the next epoch.
    let fresh = wait_for("a fresh host 0", || {
        m.tick(&ledger, io, wicket_store::now());
        io.heartbeat("0").filter(|b| b.owner != beats.0.owner)
    });
    assert_eq!(fresh.epoch, 3);
    assert_eq!(io.heartbeat("1").unwrap().owner, beats.1.owner, "host 1 untouched");

    // A planned stop: SIGTERM writes the clean-stop marker, and the shard is free.
    for owner in [&fresh.owner, &beats.1.owner] {
        unsafe { libc::kill(pid(owner), libc::SIGTERM) };
    }
    wait_for("both stopped", || (io.gone(&fresh.owner) && io.gone(&beats.1.owner)).then_some(()));
    for s in ["0", "1"] {
        assert!(ledger.supervisor_host(s).unwrap().unwrap().stopping, "shard {s}'s clean-stop marker");
    }
}
