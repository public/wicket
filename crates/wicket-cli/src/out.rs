//! Where a run supervisor's own output goes: wicket-home's [`wicket_home::out`] (#219), whose
//! [`say!`] and [`say_err!`] are `println!` and `eprintln!` that follow a supervisor thread's log
//! and never panic. main.rs imports the macros for every module here.

pub use wicket_home::out::to;

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
            // Moved to wicket-node (#219): node serve, its gateway, and what moved with them.
            "../../wicket-node/src/nodesrv.rs",
            "../../wicket-node/src/nodegw.rs",
            "../../wicket-node/src/controlca.rs",
            "../../wicket-node/src/childplan.rs",
            "../../wicket-node/src/status.rs",
            // Moved to wicket-home (#219); node serve calls it.
            "../../wicket-home/src/nodeauth.rs",
            "nodeca.rs",
            "noderun.rs",
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
        for d in ["../../wicket-node/src/nodesrv", "serve"] {
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
