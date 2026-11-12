//! Sign-in throttling and lockout, the client address behind a trusted proxy, and the bounds on the
//! console's per-request resources.
//!
//! Policy (constants below), applied to the pre-auth endpoints (passkey sign-in, enrolment link):
//! - **per client address** (IPv4 address, or IPv6 /64): at most [`IP_ATTEMPTS`] attempts a minute;
//!   [`FAILURES_TO_LOCK`] failures in a row lock the address out for [`LOCKOUT`], doubling with each
//!   further lockout up to [`MAX_LOCKOUT`];
//! - **per credential** (the passkey id an assertion names): the same failure count and lockout,
//!   whatever address the attempts come from. Credential ids are not disclosed before sign-in
//!   (sign-in offers no `allowCredentials`), which keeps this from being a cheap way to lock the
//!   operator out.
//!
//! The tables are bounded ([`MAX_ENTRIES`]); when full, the stalest unlocked entry is dropped, and if
//! every entry is a live lockout, the oldest lockout is (#123: refusing every new client instead let
//! a table full of lockouts shut everyone out).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(60);
pub const IP_ATTEMPTS: u32 = 20;
pub const FAILURES_TO_LOCK: u32 = 5;
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);
pub const MAX_LOCKOUT: Duration = Duration::from_secs(24 * 3600);
pub const MAX_ENTRIES: usize = 4096;

#[derive(Default)]
struct Entry {
    window_start: Option<Instant>,
    attempts: u32,
    failures: u32,
    lockouts: u32,
    locked_until: Option<Instant>,
    last: Option<Instant>,
}

impl Entry {
    fn locked(&self, now: Instant) -> Option<Duration> {
        self.locked_until.filter(|u| *u > now).map(|u| u - now)
    }
}

#[derive(Default)]
struct Table(HashMap<String, Entry>);

impl Table {
    /// The entry for `key`, making room if needed: the stalest unlocked entry goes, or, when every
    /// entry is a live lockout, the one locked longest ago.
    fn entry(&mut self, key: &str, now: Instant) -> Option<&mut Entry> {
        if !self.0.contains_key(key) && self.0.len() >= MAX_ENTRIES {
            self.0.retain(|_, e| e.locked(now).is_some() || e.last.is_some_and(|l| now.duration_since(l) < LOCKOUT));
            if self.0.len() >= MAX_ENTRIES {
                let stalest = self.0.iter().filter(|(_, e)| e.locked(now).is_none()).min_by_key(|(_, e)| e.last).map(|(k, _)| k.clone());
                let victim = stalest.or_else(|| self.0.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| k.clone()));
                self.0.remove(&victim?);
            }
        }
        let e = self.0.entry(key.to_string()).or_default();
        e.last = Some(now);
        Some(e)
    }

    /// Records a failure; returns the lockout it started, if it started one.
    fn fail(&mut self, key: &str, now: Instant) -> Option<Duration> {
        let e = self.entry(key, now)?;
        e.failures += 1;
        if e.failures < FAILURES_TO_LOCK {
            return None;
        }
        e.failures = 0;
        e.lockouts += 1;
        let d = LOCKOUT.saturating_mul(1u32 << (e.lockouts - 1).min(16)).min(MAX_LOCKOUT);
        e.locked_until = Some(now + d);
        Some(d)
    }
}

/// Why an attempt is refused before it is looked at.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Too many attempts this minute (not a lockout).
    Throttled(Duration),
    /// Locked out after repeated failures.
    Locked(Duration),
}

impl Refusal {
    pub fn retry_after(&self) -> Duration {
        match self {
            Refusal::Throttled(d) | Refusal::Locked(d) => *d,
        }
    }
}

/// A lockout that a failure just started: audited.
#[derive(Debug, PartialEq, Eq)]
pub struct Lockout {
    pub scope: &'static str,
    pub key: String,
    pub duration: Duration,
}

#[derive(Default)]
pub struct Limiter {
    ips: Mutex<Table>,
    creds: Mutex<Table>,
}

impl Limiter {
    /// Counts an attempt from `ip`, or refuses it (throttled or locked out).
    pub fn attempt(&self, ip: IpAddr, now: Instant) -> Result<(), Refusal> {
        let mut t = self.ips.lock().expect("lock");
        let Some(e) = t.entry(&ip_key(ip), now) else { return Err(Refusal::Locked(LOCKOUT)) };
        if let Some(d) = e.locked(now) {
            return Err(Refusal::Locked(d));
        }
        match e.window_start {
            Some(s) if now.duration_since(s) < WINDOW => {
                if e.attempts >= IP_ATTEMPTS {
                    return Err(Refusal::Throttled(WINDOW - now.duration_since(s)));
                }
                e.attempts += 1;
            }
            _ => {
                e.window_start = Some(now);
                e.attempts = 1;
            }
        }
        Ok(())
    }

    /// Whether a credential is locked out.
    pub fn credential_locked(&self, cred: &str, now: Instant) -> Option<Duration> {
        self.creds.lock().expect("lock").0.get(cred).and_then(|e| e.locked(now))
    }

    /// Records a failed attempt from `ip` (naming `cred`, if it named one); returns the lockouts it
    /// started.
    pub fn fail(&self, ip: IpAddr, cred: Option<&str>, now: Instant) -> Vec<Lockout> {
        let mut out = Vec::new();
        let key = ip_key(ip);
        if let Some(duration) = self.ips.lock().expect("lock").fail(&key, now) {
            out.push(Lockout { scope: "client", key, duration });
        }
        if let Some(c) = cred {
            if let Some(duration) = self.creds.lock().expect("lock").fail(c, now) {
                out.push(Lockout { scope: "credential", key: c.to_string(), duration });
            }
        }
        out
    }

    /// A successful sign-in clears the failure counts (not the lockout history, which keeps
    /// doubling the next lockout).
    pub fn succeed(&self, ip: IpAddr, cred: &str, now: Instant) {
        if let Some(e) = self.ips.lock().expect("lock").entry(&ip_key(ip), now) {
            e.failures = 0;
        }
        if let Some(e) = self.creds.lock().expect("lock").entry(cred, now) {
            e.failures = 0;
        }
    }
}

/// The key a client address is limited under: IPv4 as is, IPv6 by its /64 (one host usually has a
/// whole /64 to pick addresses from).
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// The address block a client is in: its IPv4 /24 or IPv6 /48 (a site's usual allocation).
pub fn block_key(ip: IpAddr) -> String {
    let v4 = |v4: std::net::Ipv4Addr| {
        let o = v4.octets();
        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
    };
    match ip {
        IpAddr::V4(a) => v4(a),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(a) => v4(a),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        },
    }
}

/// An address range: `192.0.2.10`, `192.0.2.0/24`, `2001:db8::/32`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl std::str::FromStr for Cidr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Cidr> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, len)) => (ip.parse::<IpAddr>()?, Some(len.parse::<u8>()?)),
            None => (s.parse::<IpAddr>()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = len.unwrap_or(max);
        anyhow::ensure!(len <= max, "{s}: prefix length over {max}");
        Ok(Cidr { net: ip, len })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        let (a, b, bits) = match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => (u32::from(n) as u128, u32::from(i) as u128, 32),
            (IpAddr::V6(n), IpAddr::V6(i)) => (u128::from(n), u128::from(i), 128),
            _ => return false,
        };
        if self.len == 0 {
            return true;
        }
        let shift = bits - self.len as u32;
        (a >> shift) == (b >> shift)
    }
}

/// The client's address: the peer's, unless the peer is a trusted proxy, in which case it is the
/// right-most `X-Forwarded-For` entry that isn't itself a trusted proxy. Every header line counts,
/// in order (`lines`): a proxy that adds its own line rather than appending to the client's would
/// otherwise leave the client's forged line as the one read (#123). An entry that isn't an address
/// (or a line that isn't text, passed as None) stops the walk at the last good hop.
pub fn client_ip(peer: IpAddr, lines: &[Option<&str>], trusted: &[Cidr]) -> IpAddr {
    if trusted.is_empty() || !trusted.iter().any(|c| c.contains(peer)) {
        return peer;
    }
    let mut last = peer;
    for line in lines.iter().rev() {
        let Some(line) = line else { return last };
        for part in line.rsplit(',') {
            let Ok(ip) = part.trim().parse::<IpAddr>() else { return last };
            if !trusted.iter().any(|c| c.contains(ip)) {
                return ip;
            }
            last = ip;
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn attempts_are_throttled_per_address_and_window() {
        let l = Limiter::default();
        let t0 = Instant::now();
        for _ in 0..IP_ATTEMPTS {
            l.attempt(ip("192.0.2.1"), t0).unwrap();
        }
        assert!(matches!(l.attempt(ip("192.0.2.1"), t0), Err(Refusal::Throttled(_))));
        // Another address is unaffected; the same /64 is the same client.
        l.attempt(ip("192.0.2.2"), t0).unwrap();
        for _ in 0..IP_ATTEMPTS {
            l.attempt(ip("2001:db8:1:2::1"), t0).unwrap();
        }
        assert!(l.attempt(ip("2001:db8:1:2:ffff::9"), t0).is_err());
        // The next window starts afresh.
        l.attempt(ip("192.0.2.1"), t0 + WINDOW).unwrap();
    }

    #[test]
    fn failures_lock_out_the_address_and_the_credential_with_growing_lockouts() {
        let l = Limiter::default();
        let t0 = Instant::now();
        let a = ip("198.51.100.7");
        for i in 1..FAILURES_TO_LOCK {
            assert!(l.fail(a, Some("cred"), t0).is_empty(), "failure {i}");
        }
        let locks = l.fail(a, Some("cred"), t0);
        assert_eq!(
            locks,
            vec![
                Lockout { scope: "client", key: "198.51.100.7".into(), duration: LOCKOUT },
                Lockout { scope: "credential", key: "cred".into(), duration: LOCKOUT }
            ]
        );
        assert_eq!(l.attempt(a, t0), Err(Refusal::Locked(LOCKOUT)));
        assert_eq!(l.credential_locked("cred", t0), Some(LOCKOUT));
        // The credential stays locked from any address; other credentials don't.
        assert!(l.credential_locked("other", t0).is_none());
        // After the lockout, the next one is twice as long.
        let t1 = t0 + LOCKOUT;
        assert!(l.attempt(a, t1).is_ok());
        assert!(l.credential_locked("cred", t1).is_none());
        for _ in 1..FAILURES_TO_LOCK {
            l.fail(a, None, t1);
        }
        assert_eq!(l.fail(a, None, t1)[0].duration, LOCKOUT * 2);
        // Success resets the count of failures in a row.
        let b = ip("203.0.113.9");
        for _ in 1..FAILURES_TO_LOCK {
            l.fail(b, None, t0);
        }
        l.succeed(b, "cred2", t0);
        assert!(l.fail(b, None, t0).is_empty());
    }

    #[test]
    fn the_tables_are_bounded_and_keep_live_lockouts() {
        let l = Limiter::default();
        let t0 = Instant::now();
        let locked = ip("192.0.2.200");
        for _ in 0..FAILURES_TO_LOCK {
            l.fail(locked, None, t0);
        }
        for i in 0..(MAX_ENTRIES as u32 + 100) {
            let a = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            l.attempt(a, t0 + Duration::from_millis(i as u64)).unwrap();
        }
        assert!(l.ips.lock().unwrap().0.len() <= MAX_ENTRIES);
        assert!(matches!(l.attempt(locked, t0 + Duration::from_secs(60)), Err(Refusal::Locked(_))), "flooding doesn't clear a lockout");
    }

    /// #123: a table full of live lockouts drops the oldest for a new client, rather than refusing
    /// every new client (the operator included).
    #[test]
    fn a_table_full_of_lockouts_still_admits_new_clients() {
        let l = Limiter::default();
        let t0 = Instant::now();
        let ips: Vec<IpAddr> = (0..MAX_ENTRIES as u32).map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i))).collect();
        for (i, a) in ips.iter().enumerate() {
            for _ in 0..FAILURES_TO_LOCK {
                l.fail(*a, None, t0 + Duration::from_millis(i as u64));
            }
        }
        let later = t0 + Duration::from_secs(10);
        assert_eq!(l.attempt(ip("192.0.2.1"), later), Ok(()), "a new client gets in");
        assert!(l.ips.lock().unwrap().0.len() <= MAX_ENTRIES);
        assert_eq!(l.attempt(ips[0], later), Ok(()), "the oldest lockout made room");
        assert!(matches!(l.attempt(ips[MAX_ENTRIES - 1], later), Err(Refusal::Locked(_))), "newer lockouts stay");
    }

    #[test]
    fn forwarded_for_is_believed_only_from_trusted_proxies() {
        let trusted: Vec<Cidr> = vec!["10.0.0.0/8".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let proxy = ip("10.1.2.3");
        // No trusted proxies, or a peer that isn't one: the header is ignored.
        assert_eq!(client_ip(proxy, &[Some("192.0.2.5")], &[]), proxy);
        assert_eq!(client_ip(ip("192.0.2.9"), &[Some("192.0.2.5")], &trusted), ip("192.0.2.9"));
        // From a trusted proxy: the right-most untrusted entry, not what the client prepended.
        assert_eq!(client_ip(proxy, &[Some("203.0.113.66, 192.0.2.5")], &trusted), ip("192.0.2.5"));
        assert_eq!(client_ip(proxy, &[Some("192.0.2.5, 10.9.9.9")], &trusted), ip("192.0.2.5"));
        assert_eq!(client_ip(ip("2001:db8::1"), &[Some("2001:db8:aa::5")], &trusted), ip("2001:db8:aa::5"));
        // Garbage stops the walk at the last good hop.
        assert_eq!(client_ip(proxy, &[Some("evil, 10.9.9.9")], &trusted), ip("10.9.9.9"));
        assert_eq!(client_ip(proxy, &[], &trusted), proxy);
        // #123: every header line, in order. A proxy that adds its own line after the client's: the
        // proxy's line names the client, whatever the client wrote in its own.
        assert_eq!(client_ip(proxy, &[Some("203.0.113.66"), Some("192.0.2.5")], &trusted), ip("192.0.2.5"));
        assert_eq!(client_ip(proxy, &[Some("203.0.113.66, 10.2.2.2"), Some("192.0.2.5, 10.9.9.9")], &trusted), ip("192.0.2.5"));
        // Past trusted hops into an earlier line, and an unreadable line stops the walk.
        assert_eq!(client_ip(proxy, &[Some("192.0.2.7"), Some("10.9.9.9")], &trusted), ip("192.0.2.7"));
        assert_eq!(client_ip(proxy, &[Some("192.0.2.7"), None, Some("10.9.9.9")], &trusted), ip("10.9.9.9"));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("0.0.0.0/0".parse::<Cidr>().unwrap().contains(ip("192.0.2.1")));
        assert!(!"0.0.0.0/0".parse::<Cidr>().unwrap().contains(ip("2001:db8::5")));
    }
}
