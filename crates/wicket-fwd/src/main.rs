//! `wicket-fwd`: see the library docs (`src/lib.rs`).

use std::process::ExitCode;
use std::time::Duration;

use wicket_fwd::entry::{self, Prepare};
use wicket_fwd::{spec, Config, Forwarder, Kind};

const USAGE: &str = "\
usage: wicket-fwd --listen IP:PORT=/path/to/unix.sock [--listen ...] [--udp IP:PORT=/path/to/unix.sock ...]
                  [--max-conns N] [--copy rw|splice] [--buf BYTES] [--bind-timeout SECS] [--verbose]
                  [--control [--mkdir DIR ...] [--try-mkdir DIR ...] [--bundle OUT=IN,IN... ...] [--times-to PATH]]
       wicket-fwd --dial IP:PORT [--copy rw|splice] [--buf BYTES] [--idle-secs SECS] [--after-close-secs SECS]
       wicket-fwd --stdin-from /path/to/unix.sock -- CMD [ARGS...]

Relays each TCP connection accepted on IP:PORT to a new connection on the unix socket.
  --listen        a TCP listener and the unix socket it relays to (repeatable)
  --udp           a UDP listener (0.0.0.0:PORT: every local address, by IP_PKTINFO) and the unix socket
                  its datagrams are relayed to, in frames, over one connection (repeatable)
  --max-conns     connections relaying at once, over all listeners (default 256)
  --copy          rw: read/write through a buffer; splice: splice(2), falling back to rw (default splice)
  --buf           buffer or pipe size per direction, in bytes (default 262144)
  --bind-timeout  how long to wait at start for a listen address to appear (default 5)
  --verbose       one log line per connection (peer, byte counts, duration; never contents)
  --control       wicket-entry's start, over stdin and stdout (src/entry.rs): makes the directories and
                  bundles below, says `prepared`, listens once stdin says `listen`, then says `ready`;
                  the rest of stdin is the start's step times, for --times-to, then it says `done`
  --mkdir         (--control) a directory made with its parents before listening; failing is fatal
  --try-mkdir     (--control) the same, best effort
  --bundle        (--control) OUT written as the concatenation of the INs (absolute paths); fatal
  --times-to      (--control) where the step times are written (best effort)
  --dial          instead: one TCP connection to IP:PORT, relayed to stdin/stdout (links between boxes)
  --idle-secs     (--dial) exit once no bytes have moved either way for this long (default: never)
  --after-close-secs
                  (--dial) exit this long after stdin's end of file, even if IP:PORT keeps its side
                  open (default: never; a node's host ports give both, #796 re-review)
  --stdin-from    instead: runs CMD with its stdin fed from wicket's node over the unix socket,
                  reconnecting if the node restarts; exits with CMD's exit code";

/// The environment's `--idle-secs` for a `--dial` (see `parse`).
const IDLE_ENV: &str = "WICKET_FWD_IDLE_SECS";
/// The environment's `--after-close-secs` for a `--dial`.
const AFTER_CLOSE_ENV: &str = "WICKET_FWD_AFTER_CLOSE_SECS";

fn parse(args: impl IntoIterator<Item = String>) -> Result<(Config, Option<Prepare>), String> {
    let mut cfg = Config::default();
    let (mut control, mut prep) = (false, Prepare::default());
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = || inline.clone().or_else(|| args.next()).ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => cfg.listens.push(spec::parse(Kind::Tcp, &value()?)?),
            "--udp" => cfg.listens.push(spec::parse(Kind::Udp, &value()?)?),
            "--max-conns" => cfg.max_conns = number(&flag, &value()?)?,
            "--copy" => cfg.copy = value()?.parse()?,
            "--buf" => cfg.buf_size = number(&flag, &value()?)?,
            "--bind-timeout" => cfg.bind_timeout = Duration::from_secs_f64(number::<f64>(&flag, &value()?)?.clamp(0.0, 3600.0)),
            "--verbose" => cfg.verbose = true,
            "--control" => control = true,
            "--mkdir" => prep.mkdirs.push(absolute(&flag, value()?)?),
            "--try-mkdir" => prep.try_mkdirs.push(absolute(&flag, value()?)?),
            "--bundle" => prep.bundles.push(entry::parse_bundle(&value()?)?),
            "--times-to" => prep.times_to = Some(absolute(&flag, value()?)?),
            "--idle-secs" => cfg.dial_limits.idle = Some(secs(&flag, &value()?)?),
            "--after-close-secs" => cfg.dial_limits.after_close = Some(secs(&flag, &value()?)?),
            "--dial" => {
                let v = value()?;
                cfg.dial = Some(v.trim().parse().map_err(|_| format!("--dial {v:?}: not an IP:PORT (names aren't resolved)"))?);
            }
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown argument {a:?}")),
        }
    }
    if cfg.dial.is_some() == !cfg.listens.is_empty() {
        return Err("give at least one --listen or --udp, or one --dial".into());
    }
    if cfg.max_conns == 0 || !(4096..=64 << 20).contains(&cfg.buf_size) {
        return Err("--max-conns must be at least 1 and --buf between 4096 and 64 MiB".into());
    }
    spec::check_distinct(&cfg.listens)?;
    if cfg.dial.is_none() && cfg.dial_limits != wicket_fwd::DialLimits::default() {
        return Err("--idle-secs and --after-close-secs are for --dial".into());
    }
    // The same limits from the environment, for a --dial not given the flags (#796 re-review): a
    // node passes them so (`docker exec -e`), which an older wicket-fwd in an older box image
    // ignores and still relays, where it would refuse a flag it doesn't know.
    if cfg.dial.is_some() {
        for (var, slot) in [(IDLE_ENV, &mut cfg.dial_limits.idle), (AFTER_CLOSE_ENV, &mut cfg.dial_limits.after_close)] {
            if slot.is_none() {
                if let Ok(v) = std::env::var(var) {
                    *slot = Some(secs(var, &v)?);
                }
            }
        }
    }
    if control && cfg.dial.is_some() {
        return Err("--control is for listeners, not --dial".into());
    }
    if !control && prep != Prepare::default() {
        return Err("--mkdir, --try-mkdir, --bundle and --times-to need --control".into());
    }
    Ok((cfg, control.then_some(prep)))
}

fn absolute(flag: &str, v: String) -> Result<std::path::PathBuf, String> {
    let p = std::path::PathBuf::from(&v);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(format!("{flag} {v:?}: not an absolute path"))
    }
}

/// A positive number of seconds, at most a day.
fn secs(flag: &str, v: &str) -> Result<Duration, String> {
    let n: f64 = number(flag, v)?;
    if !(n > 0.0 && n <= 86_400.0) {
        return Err(format!("{flag} {v:?}: not between 0 and 86400 seconds"));
    }
    Ok(Duration::from_secs_f64(n))
}

fn number<T: std::str::FromStr>(flag: &str, v: &str) -> Result<T, String> {
    v.parse().map_err(|_| format!("{flag} {v:?}: not a number"))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--stdin-from") {
        let (Some(sock), Some("--")) = (argv.get(1), argv.get(2).map(String::as_str)) else {
            eprintln!("wicket-fwd: --stdin-from SOCK -- CMD [ARGS...]\n\n{USAGE}");
            return ExitCode::from(2);
        };
        return match wicket_fwd::stdin::run(std::path::Path::new(sock), &argv[3..]) {
            Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
            Err(e) => {
                wicket_fwd::log(format_args!("--stdin-from: {e}"));
                ExitCode::from(127)
            }
        };
    }
    let (cfg, control) = match parse(argv) {
        Ok(c) => c,
        Err(e) if e.is_empty() => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("wicket-fwd: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if let Some(addr) = cfg.dial {
        return match wicket_fwd::dial_bounded(addr, cfg.copy, cfg.buf_size, cfg.dial_limits) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                wicket_fwd::log(format_args!("dial {addr}: {e}"));
                ExitCode::FAILURE
            }
        };
    }
    let started = match control {
        // Unbuffered handles on fds 0 and 1: the exchange is a line at a time.
        Some(prep) => stdio().and_then(|(i, o)| entry::control(cfg, &prep, i, o)),
        None => Forwarder::start(cfg),
    };
    match started {
        Ok(f) => {
            f.wait();
            ExitCode::SUCCESS
        }
        Err(e) => {
            wicket_fwd::log(format_args!("{e}"));
            ExitCode::FAILURE
        }
    }
}

fn stdio() -> std::io::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::AsFd;
    Ok((
        std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned()?),
        std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_the_entry_command_line() {
        let (u, _) = parse(args("--udp 0.0.0.0:443=/wicket/sock/udp.sock --udp 198.18.0.1:53=/wicket/sock/udp.sock")).unwrap();
        assert!(u.listens.iter().all(|l| l.kind == Kind::Udp));
        let (c, _) = parse(args("--listen 198.18.0.1:3128=/wicket/sock/egress.sock --listen 198.18.0.1:8080=/wicket/sock/llm.sock --copy splice --max-conns=8 --verbose")).unwrap();
        assert_eq!(c.listens.len(), 2);
        assert_eq!(c.copy, wicket_fwd::CopyMode::Splice);
        assert_eq!(c.max_conns, 8);
        assert!(c.verbose);
        let (_, p) = parse(args(
            "--control --listen 198.18.0.1:8080=/wicket/sock/llm.sock --mkdir /home/a --try-mkdir /workspace/out \
             --bundle /tmp/ca-bundle.pem=/etc/ssl/certs/ca-certificates.crt,/wicket/ca/ca.pem --times-to /wicket/sock/entry.times",
        ))
        .unwrap();
        let p = p.expect("--control");
        assert_eq!(p.mkdirs, [std::path::PathBuf::from("/home/a")]);
        assert_eq!(p.bundles[0].1.len(), 2);
        assert!(parse(args("--listen 127.0.0.1:1=/s")).unwrap().1.is_none());
        let (d, _) = parse(args("--dial 127.0.0.1:9222 --copy rw")).unwrap();
        assert_eq!(d.dial, Some("127.0.0.1:9222".parse().unwrap()));
        assert_eq!(d.dial_limits, wicket_fwd::DialLimits::default(), "no limits unless given (links)");
        let (d, _) = parse(args("--dial 127.0.0.1:9222 --idle-secs 300 --after-close-secs=0.5")).unwrap();
        assert_eq!(d.dial_limits.idle, Some(Duration::from_secs(300)));
        assert_eq!(d.dial_limits.after_close, Some(Duration::from_millis(500)));
    }

    #[test]
    fn refuses_bad_command_lines() {
        for bad in [
            "",
            "--listen",
            "--listen 198.18.0.1:3128",
            "--listen localhost:3128=/s",
            "--listen 198.18.0.1:3128=/a --listen 198.18.0.1:3128=/b",
            "--listen 127.0.0.1:1=/s --copy zero",
            "--listen 127.0.0.1:1=/s --max-conns 0",
            "--listen 127.0.0.1:1=/s --buf 1",
            "--dial localhost:80",
            "--dial 127.0.0.1:80 --listen 127.0.0.1:1=/s",
            "--dial 127.0.0.1:80 --control",
            "--listen 127.0.0.1:1=/s --idle-secs 5",
            "--listen 127.0.0.1:1=/s --after-close-secs 5",
            "--dial 127.0.0.1:80 --idle-secs 0",
            "--dial 127.0.0.1:80 --idle-secs x",
            "--dial 127.0.0.1:80 --after-close-secs -1",
            "--listen 127.0.0.1:1=/s --mkdir /a",
            "--listen 127.0.0.1:1=/s --control --mkdir a",
            "--listen 127.0.0.1:1=/s --control --bundle /o",
        ] {
            assert!(parse(args(bad)).is_err_and(|e| !e.is_empty()), "{bad:?} should be refused");
        }
    }
}
