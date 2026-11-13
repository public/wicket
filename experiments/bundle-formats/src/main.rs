//! E5 (#195): wicket's hibernation bundle format compared with the restic format (rustic_core) and
//! with tar+zstd+age. `run.py` drives it; each operation is one process, so `measure` can report its
//! wall time, CPU and peak memory (wait4).
//!
//!   bf gen <rust|node|home|small> <dir> [scale]
//!   bf session <dataset> <dir> <n> [scale]
//!   bf save <today|age|rustic> <store> <agent> <repo-key> <tree>=<dir>...
//!   bf restore <format> <store> <agent> <repo-key> <dest> [tree]
//!   bf prune <format> <store> <agent> <repo-key> <keep>
//!   bf check <format> <store> <agent> <repo-key> [read]
//!   bf digest <dir>
//!   bf measure -- <command...>
//!
//! `<store>`: `fs:<dir>` or `s3:<endpoint>|<bucket>|<prefix>`. `<repo-key>`: `agent` (a repository
//! per agent) or a zone name (rustic only: one repository shared by the zone's agents).

mod formats;
mod gen;
mod safety;
mod store;

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

fn scratch() -> PathBuf {
    std::env::var_os("E5_SCRATCH").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("scratch/tmp"))
}

fn main() {
    if let Err(e) = run() {
        println!("{}", serde_json::json!({ "error": format!("{e:#}") }));
        eprintln!("bf: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| a.get(i).cloned().with_context(|| format!("missing argument {i}"));
    let scale = |i: usize| gen::Scale(a.get(i).and_then(|s| s.parse().ok()).unwrap_or(1.0));
    let fmt = |sp: &store::Spec| formats::open(&a[1], sp, &scratch(), &a[4]);
    match a.first().map(String::as_str) {
        Some("gen") => gen::generate(&arg(1)?, Path::new(&arg(2)?), &scale(3)),
        Some("session") => gen::session(&arg(1)?, Path::new(&arg(2)?), arg(3)?.parse()?, &scale(4)),
        Some("save") => {
            let sp = store::Spec::parse(&arg(2)?)?;
            let trees: Vec<(String, PathBuf)> = a[5..]
                .iter()
                .map(|t| t.split_once('=').map(|(n, p)| (n.to_string(), PathBuf::from(p))).context("tree: name=dir"))
                .collect::<Result<_>>()?;
            let out = fmt(&sp)?.save(&arg(3)?, &trees)?;
            println!("{out}");
        }
        Some("restore") => {
            let sp = store::Spec::parse(&arg(2)?)?;
            let out = fmt(&sp)?.restore(&arg(3)?, a.get(6).map(String::as_str), Path::new(&arg(5)?))?;
            println!("{out}");
        }
        Some("prune") => {
            let sp = store::Spec::parse(&arg(2)?)?;
            println!("{}", fmt(&sp)?.prune(&arg(3)?, arg(5)?.parse()?)?);
        }
        Some("check") => {
            let sp = store::Spec::parse(&arg(2)?)?;
            println!("{}", fmt(&sp)?.check(&arg(3)?, a.get(5).is_some_and(|s| s == "read"))?);
        }
        Some("digest") => println!("{}", wicket_store::bundle::tree_digest(Path::new(&arg(1)?), &[])?),
        Some("measure") => measure(&a[2..])?,
        _ => bail!("usage: see src/main.rs"),
    }
    Ok(())
}

/// Runs a command, and prints its last stdout line (JSON) merged with its wall time, CPU and peak RSS.
fn measure(cmd: &[String]) -> Result<()> {
    let t0 = std::time::Instant::now();
    let child = std::process::Command::new(&cmd[0]).args(&cmd[1..]).stdout(std::process::Stdio::piped()).spawn()?;
    let pid = child.id() as libc::pid_t;
    let mut out = child.stdout.context("stdout")?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut out, &mut text)?;
    let mut status = 0;
    // SAFETY: an all-zero rusage is valid, and wait4 fills it for our own child.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: waits for the child spawned above.
    unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
    let wall = t0.elapsed().as_secs_f64();
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    let last = text.lines().last().unwrap_or("{}");
    let mut v: serde_json::Value = serde_json::from_str(last).unwrap_or_else(|_| serde_json::json!({ "stdout": last }));
    let m = serde_json::json!({
        "wall_s": wall, "user_s": tv(ru.ru_utime), "sys_s": tv(ru.ru_stime), "maxrss_mb": ru.ru_maxrss as f64 / 1024.0,
        "exit": if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 }
    });
    if let (Some(o), Some(mm)) = (v.as_object_mut(), m.as_object()) {
        o.extend(mm.clone());
    }
    println!("{v}");
    Ok(())
}
