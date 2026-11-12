//! Listener specs: `ADDR:PORT=/path/to/host.sock`, one per `--listen`.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The transport a listener accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A TCP listener; each accepted connection is relayed to a new connection on a unix stream socket.
    Tcp,
    /// A UDP listener (`--udp`); datagrams are relayed in [`crate::frame`]s over one unix connection.
    Udp,
}

/// One listener: where it listens in the box and the host's unix socket it relays to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    pub kind: Kind,
    pub addr: SocketAddr,
    pub path: PathBuf,
}

impl fmt::Display for Listen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let k = match self.kind {
            Kind::Tcp => "tcp",
            Kind::Udp => "udp",
        };
        write!(f, "{k} {} -> {}", self.addr, self.path.display())
    }
}

/// Parses `IP:PORT=PATH`. The address is an IP literal (`198.18.0.1:3128`, `[::1]:8080`), never a
/// name: the forwarder resolves nothing. The path is absolute, and at most 107 bytes (a unix socket
/// address's limit). Port 0 asks the kernel for a free port (tests use it).
pub fn parse(kind: Kind, s: &str) -> Result<Listen, String> {
    let (addr, path) = s.split_once('=').ok_or_else(|| format!("{s:?}: expected ADDR:PORT=/path/to/socket"))?;
    let addr: SocketAddr = addr.trim().parse().map_err(|_| format!("{s:?}: {addr:?} is not an IP:PORT (names aren't resolved)"))?;
    let path = PathBuf::from(path.trim());
    if !path.is_absolute() {
        return Err(format!("{s:?}: the socket path must be absolute"));
    }
    if path.as_os_str().len() > 107 {
        return Err(format!("{s:?}: the socket path is longer than a unix socket address allows (107 bytes)"));
    }
    Ok(Listen { kind, addr, path })
}

/// Refuses two listeners on the same address and port.
pub fn check_distinct(listens: &[Listen]) -> Result<(), String> {
    for (i, a) in listens.iter().enumerate() {
        if a.addr.port() != 0 && listens[..i].iter().any(|b| b.kind == a.kind && b.addr == a.addr) {
            return Err(format!("{} is listed twice", a.addr));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_box_specs() {
        let l = parse(Kind::Tcp, "198.18.0.1:3128=/wicket/sock/egress.sock").unwrap();
        assert_eq!(l.addr, "198.18.0.1:3128".parse().unwrap());
        assert_eq!(l.path, PathBuf::from("/wicket/sock/egress.sock"));
        assert_eq!(l.to_string(), "tcp 198.18.0.1:3128 -> /wicket/sock/egress.sock");
        assert_eq!(parse(Kind::Tcp, "[::1]:0=/s").unwrap().addr, "[::1]:0".parse().unwrap());
    }

    #[test]
    fn refuses_what_does_not_match() {
        for bad in [
            "198.18.0.1:3128",                    // no socket
            "=/wicket/sock/egress.sock",          // no address
            "198.18.0.1=/s",                      // no port
            "wicket.internal:3128=/s",            // a name
            "198.18.0.1:99999=/s",                // port out of range
            "198.18.0.1:3128=wicket/sock/x.sock", // relative
            "198.18.0.1:3128=",                   // empty path
            "tcp://198.18.0.1:3128=/s",           // a URL
        ] {
            assert!(parse(Kind::Tcp, bad).is_err(), "{bad} should be refused");
        }
        let long = format!("127.0.0.1:1=/{}", "a".repeat(120));
        assert!(parse(Kind::Tcp, &long).is_err());
    }

    #[test]
    fn refuses_duplicates() {
        let a = parse(Kind::Tcp, "198.18.0.1:3128=/a").unwrap();
        let b = parse(Kind::Tcp, "198.18.0.1:3128=/b").unwrap();
        let c = parse(Kind::Tcp, "198.18.0.1:8080=/b").unwrap();
        assert!(check_distinct(&[a.clone(), b]).is_err());
        assert!(check_distinct(&[a.clone(), c]).is_ok());
        // TCP and UDP on one address and port are different listeners.
        let u = parse(Kind::Udp, "198.18.0.1:3128=/b").unwrap();
        assert!(check_distinct(&[a, u.clone()]).is_ok());
        assert_eq!(parse(Kind::Udp, "0.0.0.0:443=/wicket/sock/udp.sock").unwrap().to_string(), "udp 0.0.0.0:443 -> /wicket/sock/udp.sock");
    }
}
