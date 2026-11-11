//! The control plane's side of the feed: one feed (one node audience) per process in this prototype.
//! It keeps a persistent signed delta log, pushes every delta and freshness statement to
//! subscribers, answers polls, serves catch-up from retained deltas or a snapshot, and takes
//! changes on an admin socket.

use crate::feed::{now_ms, sha, sign, Change, Delta, Fresh, Grant, KeyCert, State, GENESIS, TYP_DELTA, TYP_FRESH, TYP_KEY, TYP_SNAP};
use crate::node::log;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct CpCfg {
    pub dir: PathBuf,
    pub feed: String,
    pub feed_port: u16,
    pub admin_port: u16,
    pub ttl_ms: i64,
    pub refresh_ms: u64,
    pub grace_ms: i64,
    /// Catch-up from deltas only if the node is at most this many epochs behind; else a snapshot.
    pub retain: u64,
}

struct Cp {
    cfg: CpCfg,
    key: SigningKey,
    cert: String,
    state: State,
    heads: Vec<String>,
    log: Vec<String>,
    file: File,
    subs: Vec<TcpStream>,
    fresh: String,
    fresh_epoch: u64,
    last_issued: i64,
    frames: BTreeMap<String, u64>,
    bytes: BTreeMap<String, u64>,
    churn_n: u64,
}

pub fn load_key(path: &Path) -> std::io::Result<SigningKey> {
    match std::fs::read_to_string(path) {
        Ok(s) => crate::feed::key_from_hex(&s).ok_or_else(|| std::io::Error::other("bad key file")),
        Err(_) => {
            let k = SigningKey::generate(&mut rand_core::OsRng);
            std::fs::write(path, hex::encode(k.to_bytes()))?;
            Ok(k)
        }
    }
}

impl Cp {
    fn open(cfg: CpCfg) -> std::io::Result<Cp> {
        std::fs::create_dir_all(&cfg.dir)?;
        let root = load_key(&cfg.dir.join("root.key"))?;
        std::fs::write(cfg.dir.join("root.pub"), hex::encode(root.verifying_key().as_bytes()))?;
        let key = load_key(&cfg.dir.join("feed.key"))?;
        // In production the root is offline and certifies the online key ahead of time.
        let cert = sign(&root, TYP_KEY, &KeyCert::new(&key.verifying_key(), 1, now_ms() + 7 * 86_400_000, cfg.ttl_ms.max(30_000), cfg.grace_ms.max(300_000)));
        let path = cfg.dir.join("deltas.jsonl");
        let mut state = State::genesis();
        let mut heads = vec![GENESIS.to_string()];
        let mut entries = vec![];
        if let Ok(f) = File::open(&path) {
            for line in BufReader::new(f).lines() {
                let jws = line?;
                let d: Delta = crate::feed::open(&jws, TYP_DELTA, &crate::feed::kid(&key.verifying_key()), &key.verifying_key()).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
                if d.epoch != state.epoch + 1 || d.prev != state.head {
                    return Err(std::io::Error::other("delta log is not a chain"));
                }
                state.apply(&d, sha(&jws));
                heads.push(state.head.clone());
                entries.push(jws);
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        log(json!({"ev": "cp_open", "epoch": state.epoch, "grants": state.grants.len()}));
        let mut cp = Cp { cfg, key, cert, state, heads, log: entries, file, subs: vec![], fresh: String::new(), fresh_epoch: 0, last_issued: 0, frames: BTreeMap::new(), bytes: BTreeMap::new(), churn_n: 0 };
        cp.tick();
        Ok(cp)
    }

    fn send(&mut self, s: &mut TcpStream, t: &str, jws: &str) -> std::io::Result<()> {
        let line = format!("{{\"t\":\"{t}\",\"jws\":\"{jws}\"}}\n");
        *self.frames.entry(t.into()).or_default() += 1;
        *self.bytes.entry(t.into()).or_default() += line.len() as u64;
        s.write_all(line.as_bytes())
    }

    fn broadcast(&mut self, t: &str, jws: &str) {
        let mut subs = std::mem::take(&mut self.subs);
        subs.retain_mut(|s| self.send(s, t, jws).is_ok());
        self.subs = subs;
    }

    fn commit(&mut self, changes: Vec<Change>) -> std::io::Result<u64> {
        let d = Delta { feed: self.cfg.feed.clone(), epoch: self.state.epoch + 1, prev: self.state.head.clone(), issued_at: now_ms(), changes };
        let jws = sign(&self.key, TYP_DELTA, &d);
        writeln!(self.file, "{jws}")?;
        self.state.apply(&d, sha(&jws));
        self.heads.push(self.state.head.clone());
        self.log.push(jws.clone());
        self.broadcast("delta", &jws);
        Ok(self.state.epoch)
    }

    fn tick(&mut self) {
        let issued_at = now_ms().max(self.last_issued + 1);
        self.last_issued = issued_at;
        let f = Fresh {
            feed: self.cfg.feed.clone(),
            epoch: self.state.epoch,
            head: self.state.head.clone(),
            issued_at,
            fresh_until: issued_at + self.cfg.ttl_ms,
            narrow_until: issued_at + self.cfg.ttl_ms + self.cfg.grace_ms,
        };
        self.fresh = sign(&self.key, TYP_FRESH, &f);
        self.fresh_epoch = f.epoch;
        let j = self.fresh.clone();
        self.broadcast("fresh", &j);
    }

    /// Catch-up for a node at (epoch, head): retained deltas if it is on our chain and close
    /// enough, else a snapshot. Then the current freshness statement.
    fn serve(&mut self, mut s: TcpStream, hello: &Value) -> std::io::Result<()> {
        let cert = self.cert.clone();
        self.send(&mut s, "key", &cert)?;
        let epoch = hello["epoch"].as_u64();
        let on_chain = epoch.is_some_and(|e| e <= self.state.epoch && self.state.epoch - e <= self.cfg.retain && hello["head"].as_str() == Some(self.heads[e as usize].as_str()));
        let (kind, n) = if on_chain {
            let e = epoch.unwrap() as usize;
            for i in e..self.log.len() {
                let j = self.log[i].clone();
                self.send(&mut s, "delta", &j)?;
            }
            ("deltas", self.log.len() - e)
        } else {
            let snap = sign(&self.key, TYP_SNAP, &self.state.snapshot(&self.cfg.feed, now_ms()));
            self.send(&mut s, "snap", &snap)?;
            ("snapshot", snap.len())
        };
        if self.fresh_epoch != self.state.epoch {
            self.tick(); // a statement naming the epoch just served, so the node is fresh at once
        }
        let f = self.fresh.clone();
        self.send(&mut s, "fresh", &f)?;
        log(json!({"ev": "served", "sub": hello["sub"], "node_epoch": epoch, "epoch": self.state.epoch, "catchup": kind, "n": n}));
        if hello["sub"].as_bool() == Some(true) {
            s.set_write_timeout(Some(Duration::from_secs(1)))?;
            self.subs.push(s);
        } else {
            s.write_all(b"{\"t\":\"end\"}\n")?;
        }
        Ok(())
    }

    fn admin(&mut self, cmd: &Value) -> std::io::Result<Value> {
        let changes: Vec<Change> = match cmd["cmd"].as_str().unwrap_or("") {
            "batch" => serde_json::from_value(cmd["changes"].clone()).map_err(std::io::Error::other)?,
            "grant" => vec![Change::AddGrant { grant: serde_json::from_value(cmd["grant"].clone()).map_err(std::io::Error::other)? }],
            "revoke" => vec![Change::Revoke { id: cmd["id"].as_str().unwrap_or("").into(), until: cmd["until"].as_i64().unwrap_or(now_ms() + 86_400_000) }],
            "stats" => {
                return Ok(json!({"epoch": self.state.epoch, "grants": self.state.grants.len(), "zones": self.state.zones.len(),
                    "subs": self.subs.len(), "frames": self.frames, "bytes": self.bytes}))
            }
            "snapshot" => {
                let snap = sign(&self.key, TYP_SNAP, &self.state.snapshot(&self.cfg.feed, now_ms()));
                return Ok(json!({"epoch": self.state.epoch, "jws": snap}));
            }
            other => return Ok(json!({"error": format!("unknown cmd {other}")})),
        };
        Ok(json!({"ok": true, "epoch": self.commit(changes)?}))
    }

    /// One churn step: add a grant, or revoke one, alternately (keeps the grant count steady).
    fn churn(&mut self) -> std::io::Result<()> {
        self.churn_n += 1;
        let n = self.churn_n;
        let change = if n % 2 == 1 {
            let zone = format!("z{}", n % self.state.zones.len().max(1) as u64);
            let op = wicket_core::Op::egress(&wicket_core::TenantId::single(), &wicket_core::RunId(String::new()), &zone, "POST", "api.github.com", &format!("/repos/acme/churn/issues/{n}/comments"));
            Change::AddGrant { grant: Grant { id: format!("c-{n}"), zone, op: op.digest(), what: format!("POST api.github.com{}", op.path), not_after: now_ms() + 3_600_000, uses: None } }
        } else {
            match self.state.grants.keys().find(|k| k.starts_with("s-") || k.starts_with("c-")).cloned() {
                Some(id) => Change::Revoke { id, until: now_ms() + 3_600_000 },
                None => return Ok(()),
            }
        };
        self.commit(vec![change]).map(|_| ())
    }
}

pub fn run(cfg: CpCfg) -> std::io::Result<()> {
    let feed = TcpListener::bind(("127.0.0.1", cfg.feed_port))?;
    let admin = TcpListener::bind(("127.0.0.1", cfg.admin_port))?;
    let refresh = cfg.refresh_ms;
    let cp = Arc::new(Mutex::new(Cp::open(cfg)?));
    let c = cp.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(refresh));
        c.lock().unwrap().tick();
    });
    let c = cp.clone();
    std::thread::spawn(move || {
        for s in admin.incoming().flatten() {
            let c = c.clone();
            std::thread::spawn(move || -> std::io::Result<()> {
                let mut w = s.try_clone()?;
                for line in BufReader::new(s).lines() {
                    let cmd: Value = serde_json::from_str(&line?).unwrap_or(Value::Null);
                    if cmd["cmd"] == "churn" {
                        let rate = cmd["rate"].as_f64().unwrap_or(10.0);
                        let c = c.clone();
                        std::thread::spawn(move || loop {
                            std::thread::sleep(Duration::from_secs_f64(1.0 / rate));
                            if c.lock().unwrap().churn().is_err() {
                                return;
                            }
                        });
                        w.write_all(format!("{}\n", json!({"ok": true})).as_bytes())?;
                        continue;
                    }
                    let out = c.lock().unwrap().admin(&cmd).unwrap_or_else(|e| json!({"error": e.to_string()}));
                    w.write_all(format!("{out}\n").as_bytes())?;
                }
                Ok(())
            });
        }
    });
    log(json!({"ev": "listening", "feed": feed.local_addr()?.port()}));
    for s in feed.incoming().flatten() {
        let c = cp.clone();
        std::thread::spawn(move || -> std::io::Result<()> {
            s.set_nodelay(true)?;
            s.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut line = String::new();
            BufReader::new(s.try_clone()?).read_line(&mut line)?;
            let hello: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            c.lock().unwrap().serve(s, &hello)
        });
    }
    Ok(())
}
