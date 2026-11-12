//! `wicket-fwd`: see the library docs (`src/lib.rs`).

use std::process::ExitCode;
use std::time::Duration;

use wicket_fwd::{spec, Config, Forwarder, Kind};

const USAGE: &str = "\
usage: wicket-fwd --listen IP:PORT=/path/to/unix.sock [--listen ...] [--udp IP:PORT=/path/to/unix.sock ...]
                  [--max-conns N] [--copy rw|splice] [--buf BYTES] [--bind-timeout SECS] [--verbose]
       wicket-fwd --dial IP:PORT [--copy rw|splice] [--buf BYTES]
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
  --dial          instead: one TCP connection to IP:PORT, relayed to stdin/stdout (links between boxes)
  --stdin-from    instead: runs CMD with its stdin fed from wicket's node over the unix socket,
                  reconnecting if the node restarts; exits with CMD's exit code";

fn parse(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
    let mut cfg = Config::default();
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
    Ok(cfg)
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
    let cfg = match parse(argv) {
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
        return match wicket_fwd::dial(addr, cfg.copy, cfg.buf_size) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                wicket_fwd::log(format_args!("dial {addr}: {e}"));
                ExitCode::FAILURE
            }
        };
    }
    match Forwarder::start(cfg) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_the_entry_command_line() {
        let u = parse(args("--udp 0.0.0.0:443=/wicket/sock/udp.sock --udp 198.18.0.1:53=/wicket/sock/udp.sock")).unwrap();
        assert!(u.listens.iter().all(|l| l.kind == Kind::Udp));
        let c = parse(args("--listen 198.18.0.1:3128=/wicket/sock/egress.sock --listen 198.18.0.1:8080=/wicket/sock/llm.sock --copy splice --max-conns=8 --verbose")).unwrap();
        assert_eq!(c.listens.len(), 2);
        assert_eq!(c.copy, wicket_fwd::CopyMode::Splice);
        assert_eq!(c.max_conns, 8);
        assert!(c.verbose);
        let d = parse(args("--dial 127.0.0.1:9222 --copy rw")).unwrap();
        assert_eq!(d.dial, Some("127.0.0.1:9222".parse().unwrap()));
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
        ] {
            assert!(parse(args(bad)).is_err_and(|e| !e.is_empty()), "{bad:?} should be refused");
        }
    }
}
