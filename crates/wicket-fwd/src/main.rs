//! `wicket-fwd`: see the library docs (`src/lib.rs`).

use std::process::ExitCode;
use std::time::Duration;

use wicket_fwd::{spec, Config, Forwarder, Kind};

const USAGE: &str = "\
usage: wicket-fwd --listen IP:PORT=/path/to/unix.sock [--listen ...]
                  [--max-conns N] [--copy rw|splice] [--buf BYTES] [--bind-timeout SECS] [--verbose]

Relays each TCP connection accepted on IP:PORT to a new connection on the unix socket.
  --listen        a TCP listener and the unix socket it relays to (repeatable, at least one)
  --max-conns     connections relaying at once, over all listeners (default 256)
  --copy          rw: read/write through a buffer; splice: splice(2), falling back to rw (default splice)
  --buf           buffer or pipe size per direction, in bytes (default 262144)
  --bind-timeout  how long to wait at start for a listen address to appear (default 5)
  --verbose       one log line per connection (peer, byte counts, duration; never contents)";

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
            "--max-conns" => cfg.max_conns = number(&flag, &value()?)?,
            "--copy" => cfg.copy = value()?.parse()?,
            "--buf" => cfg.buf_size = number(&flag, &value()?)?,
            "--bind-timeout" => cfg.bind_timeout = Duration::from_secs_f64(number::<f64>(&flag, &value()?)?.clamp(0.0, 3600.0)),
            "--verbose" => cfg.verbose = true,
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown argument {a:?}")),
        }
    }
    if cfg.listens.is_empty() {
        return Err("at least one --listen is needed".into());
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
    let cfg = match parse(std::env::args().skip(1)) {
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
        let c = parse(args("--listen 198.18.0.1:3128=/wicket/sock/egress.sock --listen 198.18.0.1:8080=/wicket/sock/llm.sock --copy splice --max-conns=8 --verbose")).unwrap();
        assert_eq!(c.listens.len(), 2);
        assert_eq!(c.copy, wicket_fwd::CopyMode::Splice);
        assert_eq!(c.max_conns, 8);
        assert!(c.verbose);
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
            "--listen 127.0.0.1:1=/s --udp 127.0.0.1:443=/u",
        ] {
            assert!(parse(args(bad)).is_err_and(|e| !e.is_empty()), "{bad:?} should be refused");
        }
    }
}
