//! Where a run supervisor's own output goes. A run started by the operator prints to this
//! process's stdout and stderr; a spawned child's supervisor runs in its parent's process (#257
//! slice 4c), on a thread of its own, and prints to its log in the parent's `children/` instead.
//! [`say!`] and [`say_err!`] are `println!` and `eprintln!` that follow that thread's log, and
//! never panic: a supervisor whose stdout is gone (a closed pipe, a full disk) carries on
//! supervising its box, and loses only what it would have printed.

use std::cell::RefCell;
use std::io::Write;

thread_local! {
    static LOG: RefCell<Option<std::fs::File>> = const { RefCell::new(None) };
}

/// Sends what this thread's supervisor prints to `log` from now on.
pub fn to(log: std::fs::File) {
    LOG.with(|l| *l.borrow_mut() = Some(log));
}

#[doc(hidden)]
pub fn line(err: bool, a: std::fmt::Arguments<'_>) {
    LOG.with(|l| match &mut *l.borrow_mut() {
        Some(f) => {
            let _ = writeln!(f, "{a}");
        }
        None if err => {
            let _ = writeln!(std::io::stderr().lock(), "{a}");
        }
        None => {
            let _ = writeln!(std::io::stdout().lock(), "{a}");
        }
    })
}

/// `println!`, to this thread's supervisor log if it has one.
macro_rules! say {
    () => { $crate::out::line(false, format_args!("")) };
    ($($t:tt)*) => { $crate::out::line(false, format_args!($($t)*)) };
}

/// `eprintln!`, to this thread's supervisor log if it has one.
macro_rules! say_err {
    ($($t:tt)*) => { $crate::out::line(true, format_args!($($t)*)) };
}

#[cfg(test)]
mod tests {
    /// #422: `println!` and `eprintln!` panic when stdout or stderr is closed (a journal that went
    /// away, a pipe whose reader ended). The long-running processes (`node serve`, `wicketd`, the
    /// console, the reconciler, run supervisors) and what they call print with [`say!`] and
    /// [`say_err!`] instead, outside their tests.
    #[test]
    fn long_running_processes_print_without_panicking() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![];
        for f in [
            "nodesrv.rs",
            "nodeauth.rs",
            "nodeca.rs",
            "noderun.rs",
            "nodegw.rs",
            "run.rs",
            "spawn.rs",
            "reconcile.rs",
            "localnode.rs",
            "enrol.rs",
            "nodecreate.rs",
            "daemon/mod.rs",
        ] {
            files.push(src.join(f));
        }
        for d in ["nodesrv", "serve"] {
            for e in std::fs::read_dir(src.join(d)).unwrap() {
                let p = e.unwrap().path();
                if p.extension().is_some_and(|x| x == "rs") {
                    files.push(p);
                }
            }
        }
        let mut found = vec![];
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            for (n, line) in text.lines().enumerate() {
                if line.starts_with("mod tests") || line.trim_end() == "#[cfg(test)]" {
                    break;
                }
                let code = line.split("//").next().unwrap_or("");
                if ["println!", "print!", "eprintln!", "eprint!"].iter().any(|m| code.contains(m)) {
                    found.push(format!("{}:{}: {}", f.display(), n + 1, line.trim()));
                }
            }
        }
        assert!(found.is_empty(), "use say!/say_err! (or a write whose error is ignored):\n{}", found.join("\n"));
    }
}
