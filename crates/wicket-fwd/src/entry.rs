//! `wicket-fwd --control` (#287): the forwarder's part of `wicket-entry`'s start, so that the box's
//! start spawns no process per step and waits on signals instead of polling.
//!
//! `wicket-entry` starts the forwarder as the agent's user (as a bash coprocess: its stdin and
//! stdout are pipes to the script) before it adds wicket.internal's addresses, so the forwarder's
//! own start (setpriv, exec) overlaps with that. Then, over those pipes, one line each:
//!
//! 1. The forwarder does the agent user's setup: the `--mkdir` directories (an error is fatal), the
//!    `--try-mkdir` ones (best effort), and each `--bundle OUT=IN,IN...` (the inputs concatenated
//!    into OUT, as `cat IN... > OUT` did: an error is fatal). Then it writes `prepared`.
//! 2. It waits for `listen` on stdin: the script has added the addresses. Anything else, or the end
//!    of stdin, and it exits non-zero without listening.
//! 3. It binds every listener (an error is fatal, as without `--control`) and writes `ready`.
//!    The script starts the program only after this line: every listener is bound by then.
//! 4. The rest of stdin, up to its end (at most 4 KiB), is the start's step times: written to
//!    `--times-to PATH` if given (best effort: an older node's socket directory may not take them),
//!    then `done` is written, so the script knows they are on disk before it execs the program.
//!
//! The forwarder then runs as it would without `--control`. Its stdout is never written again.

use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use crate::{Config, Forwarder};

/// What the forwarder does as the agent's user before it listens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prepare {
    /// Directories made with their parents; failing to is fatal.
    pub mkdirs: Vec<PathBuf>,
    /// Directories made with their parents if they can be (`/workspace/out` is absent when the
    /// workspace is mounted elsewhere).
    pub try_mkdirs: Vec<PathBuf>,
    /// Files written as the concatenation of others (the CA bundle: the system roots and the run's CA).
    pub bundles: Vec<(PathBuf, Vec<PathBuf>)>,
    /// Where the start's step times go (`/wicket/sock/entry.times`).
    pub times_to: Option<PathBuf>,
}

/// Parses `--bundle OUT=IN,IN...`: absolute paths, at least one input.
pub fn parse_bundle(s: &str) -> Result<(PathBuf, Vec<PathBuf>), String> {
    let (out, ins) = s.split_once('=').ok_or_else(|| format!("--bundle {s:?}: expected OUT=IN[,IN...]"))?;
    let ins: Vec<PathBuf> = ins.split(',').filter(|p| !p.is_empty()).map(PathBuf::from).collect();
    let out = PathBuf::from(out);
    if ins.is_empty() || !out.is_absolute() || ins.iter().any(|p| !p.is_absolute()) {
        return Err(format!("--bundle {s:?}: expected absolute paths, OUT=IN[,IN...]"));
    }
    Ok((out, ins))
}

impl Prepare {
    /// Makes the directories and writes the bundles.
    pub fn run(&self) -> io::Result<()> {
        for d in &self.mkdirs {
            fs::create_dir_all(d).map_err(|e| io::Error::new(e.kind(), format!("mkdir {}: {e}", d.display())))?;
        }
        for d in &self.try_mkdirs {
            let _ = fs::create_dir_all(d);
        }
        for (out, ins) in &self.bundles {
            bundle(out, ins).map_err(|e| io::Error::new(e.kind(), format!("bundle {}: {e}", out.display())))?;
        }
        Ok(())
    }
}

fn bundle(out: &Path, ins: &[PathBuf]) -> io::Result<()> {
    let mut all = Vec::new();
    for i in ins {
        fs::File::open(i)
            .and_then(|mut f| f.read_to_end(&mut all))
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", i.display())))?;
    }
    // Truncated and rewritten in place, with the umask's mode, as the shell's `>` did.
    fs::write(out, all)
}

/// The step times' limit (the node reads at most 4 KiB of them).
const TIMES_MAX: u64 = 4096;

/// Runs the `--control` exchange over `input` and `output` (the process's stdin and stdout) and
/// returns the running forwarder. An error means nothing listens: the caller exits non-zero.
pub fn control(
    cfg: Config,
    prep: &Prepare,
    input: impl Read + Send + 'static,
    mut output: impl Write + Send + 'static,
) -> io::Result<Forwarder> {
    prep.run()?;
    say(&mut output, "prepared")?;
    let mut input = io::BufReader::new(input);
    let mut line = String::new();
    input.by_ref().take(64).read_line(&mut line)?;
    if line.trim_end() != "listen" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("--control: expected `listen`, got {:?}", line.trim_end())));
    }
    let f = Forwarder::start(cfg)?;
    say(&mut output, "ready")?;
    let times_to = prep.times_to.clone();
    std::thread::Builder::new().name("entry times".into()).spawn(move || {
        let mut times = Vec::new();
        if input.take(TIMES_MAX).read_to_end(&mut times).is_ok() && !times.is_empty() {
            if let Some(p) = times_to {
                let _ = fs::write(p, &times);
            }
        }
        let _ = say(&mut output, "done");
    })?;
    Ok(f)
}

fn say(out: &mut impl Write, line: &str) -> io::Result<()> {
    out.write_all(format!("{line}\n").as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Write};
    use std::net::TcpStream;
    use std::os::unix::net::{UnixListener, UnixStream};

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wfwd-entry-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(sock: &Path) -> Config {
        Config {
            listens: vec![crate::spec::parse(crate::Kind::Tcp, &format!("127.0.0.1:0={}", sock.display())).unwrap()],
            watch_every: std::time::Duration::ZERO,
            ..Config::default()
        }
    }

    #[test]
    fn parses_bundles() {
        assert_eq!(parse_bundle("/o=/a,/b").unwrap(), (PathBuf::from("/o"), vec![PathBuf::from("/a"), PathBuf::from("/b")]));
        for bad in ["/o", "/o=", "o=/a", "/o=a", "/o=/a,b"] {
            assert!(parse_bundle(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn prepares_then_listens_on_its_signal_then_writes_the_times() {
        let d = tmpdir("ok");
        let sock = d.join("s.sock");
        let _server = UnixListener::bind(&sock).unwrap();
        fs::write(d.join("a"), "A\n").unwrap();
        fs::write(d.join("b"), "B\n").unwrap();
        let prep = Prepare {
            mkdirs: vec![d.join("home/.claude")],
            try_mkdirs: vec![PathBuf::from("/proc/no/such/dir")],
            bundles: vec![(d.join("bundle.pem"), vec![d.join("a"), d.join("b")])],
            times_to: Some(d.join("entry.times")),
        };
        let (mut to_fwd, fwd_in) = UnixStream::pair().unwrap();
        let (fwd_out, from_fwd) = UnixStream::pair().unwrap();
        let mut from_fwd = BufReader::new(from_fwd);
        let (c, p) = (cfg(&sock), prep.clone());
        let t = std::thread::spawn(move || control(c, &p, fwd_in, fwd_out).map(|f| f.addrs));
        let mut line = String::new();
        from_fwd.read_line(&mut line).unwrap();
        assert_eq!(line, "prepared\n");
        // Prepared, and nothing listens yet.
        assert!(d.join("home/.claude").is_dir());
        assert_eq!(fs::read_to_string(d.join("bundle.pem")).unwrap(), "A\nB\n");
        assert!(!t.is_finished(), "waits for `listen`");
        to_fwd.write_all(b"listen\n").unwrap();
        line.clear();
        from_fwd.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let addrs = t.join().unwrap().unwrap();
        TcpStream::connect(addrs[0]).expect("listening once ready");
        to_fwd.write_all(b"start 1.0\nexec 2.0\n").unwrap();
        to_fwd.shutdown(std::net::Shutdown::Write).unwrap();
        line.clear();
        from_fwd.read_line(&mut line).unwrap();
        assert_eq!(line, "done\n");
        assert_eq!(fs::read_to_string(d.join("entry.times")).unwrap(), "start 1.0\nexec 2.0\n");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn listens_on_nothing_without_its_signal_or_its_setup() {
        let d = tmpdir("bad");
        let sock = d.join("s.sock");
        // The end of stdin, or another line, instead of `listen`.
        for input in [&b""[..], b"go\n"] {
            let r = control(cfg(&sock), &Prepare::default(), io::Cursor::new(input.to_vec()), io::sink());
            assert!(r.is_err(), "{input:?}");
        }
        // A bundle input that can't be read: nothing is said, nothing listens.
        let prep = Prepare { bundles: vec![(d.join("o"), vec![d.join("missing")])], ..Prepare::default() };
        let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct W(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for W {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let r = control(cfg(&sock), &prep, io::Cursor::new(b"listen\n".to_vec()), W(out.clone()));
        assert!(r.is_err_and(|e| e.to_string().contains("missing")));
        assert!(out.lock().unwrap().is_empty(), "not prepared");
        // A directory that can't be made.
        let prep = Prepare { mkdirs: vec![PathBuf::from("/proc/no/such/dir")], ..Prepare::default() };
        assert!(control(cfg(&sock), &prep, io::Cursor::new(b"listen\n".to_vec()), io::sink()).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
