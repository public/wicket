//! Times one node's feed as its runs share it (#582 step 3): every run's supervisor is its own
//! publisher on the node's delta log, and after any run appends, each of the others brings its
//! publisher up to date before its next commit or statement.
//!
//! ```text
//! cargo run --release -p wicket-feed --example feed_scale -- <boxes per node> <history deltas> <measured deltas> [reopen]
//! ```
//!
//! The node holds `boxes` live tokens. First `history` deltas of churn are written (each run: its
//! token, then three grant syncs re-publishing it with one more grant, then its drop), then
//! `measured` more, each committed by the next of `boxes` publishers in turn (each run commits its
//! own changes), after each of which every other publisher catches up, as
//! `noderun::SharedFeed::lock` does: [`Publisher::refresh`], applying only the appended deltas, or
//! with `reopen`, opening the feed again as it did before #582 step 3 (on this build that open
//! starts from the checkpoint; the numbers before are in docs/explanation/feed-publisher.md).
//! Printed: the time to open the feed; one publisher's catch-up after an append, an append's cost to
//! the node's publishers (every other one catching up), and the commit itself, each as median, p99
//! and maximum (a commit at a multiple of `CHECKPOINT_EVERY` writes the checkpoint); and how many
//! checkpoints the publishers wrote between them.
//!
//! The numbers before #582 step 3 in docs/explanation/feed-publisher.md were measured with this
//! harness's `reopen` path (a publisher opened again whenever the log's length moved, as
//! `SharedFeed::lock` did), built against main's `publisher.rs`, which replays the whole log on
//! open: on main, the `refresh` path and the `Refreshed` and `checkpoints_written` uses must first
//! be removed for it to build.

use ed25519_dalek::SigningKey as FeedKey;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wicket_authz::{Grant as AuthzGrant, SigningKey};
use wicket_core::ZoneSpec;
use wicket_feed::*;

const T0: i64 = 1_800_000_000_000;
const NODE: &str = "n1";
const GRANTS: usize = 3;

struct Env {
    dir: PathBuf,
    root: FeedKey,
    key: FeedKey,
    cert: String,
    authz: SigningKey,
    approver: SigningKey,
    zone: ZoneSpec,
}

impl Env {
    fn open(&self) -> Publisher<BoxAuthority> {
        let cfg = PublisherConfig::default();
        Publisher::open_with(&self.dir, NODE, &self.root.verifying_key(), self.key.clone(), &self.cert, cfg, self.authz.public()).unwrap()
    }

    /// Run `i`'s token with `grants` grants.
    fn token(&self, i: usize, grants: usize) -> BoxAuthority {
        let run = format!("run_{i:07}");
        let issuer = Issuer::root(
            &self.authz,
            "t",
            "trigger:t",
            &run,
            0,
            &self.zone,
            &[],
            (T0 / 1000) as u64 + 86_400,
            vec![self.approver.public()],
        )
        .unwrap();
        let live: Vec<LiveGrant> = (0..grants)
            .map(|g| LiveGrant {
                grant: AuthzGrant {
                    gid: format!("g_{i}_{g}"),
                    box_id: String::new(),
                    epoch: 0,
                    host: "api.github.com".into(),
                    method: "GET".into(),
                    path: format!("/repos/o/r/issues/{g}"),
                    not_after: (T0 / 1000) as u64 + 3600,
                    approver: "human:test".into(),
                    digest: vec![1, 2, 3],
                },
                uses: None,
                prefix: false,
                standing: None,
            })
            .collect();
        issuer.publish(&self.approver, &live).unwrap()
    }
}

/// The churn: run `i`'s events in order, `2 + GRANTS` of them per run, interleaved so that about
/// `boxes` runs are live at once.
struct Churn {
    boxes: usize,
    step: usize,
}

impl Churn {
    fn next(&mut self, env: &Env) -> Change<BoxAuthority> {
        let per = 2 + GRANTS;
        let s = self.step;
        self.step += 1;
        // A round robin over `boxes` slots, each running one run after another, out of phase.
        let slot = s % self.boxes;
        let round = s / self.boxes + slot;
        let event = round % per;
        let run = slot + self.boxes * (round / per);
        match event {
            0 => Change::PutZone { zone: env.token(run, 0) },
            e if e <= GRANTS => Change::PutZone { zone: env.token(run, e) },
            _ => Change::DropZone { name: format!("run_{run:07}") },
        }
    }
}

/// Median, 99th percentile and maximum.
fn stats(mut v: Vec<Duration>) -> String {
    v.sort();
    let at = |q: f64| v.get(((v.len() as f64 - 1.0) * q).round() as usize).copied().unwrap_or_default();
    format!("median {:.1?}, p99 {:.1?}, max {:.1?}", at(0.5), at(0.99), at(1.0))
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let reopen = args.last().is_some_and(|a| a == "reopen");
    if reopen {
        args.pop();
    }
    let args: Vec<usize> = args.iter().map(|a| a.parse().expect("a number")).collect();
    let [boxes, history, measured] = args[..] else {
        eprintln!("usage: feed_scale <boxes per node> <history deltas> <measured deltas>");
        std::process::exit(2)
    };
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let (root, key) = (FeedKey::generate(&mut rng), FeedKey::generate(&mut rng));
    let cert = sign(&root, TYP_KEY, &KeyCert::new(&key.verifying_key(), 1, T0 + 7 * 86_400_000, 30_000));
    let dir = std::env::temp_dir().join(format!("wicket-feed-scale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let zone: ZoneSpec = serde_json::from_value(serde_json::json!({
        "name": "z",
        "reach": [{"host": "api.github.com", "methods": ["GET", "POST"], "paths": ["/repos/o/r/**"]}],
        "forbid": [{"host": "evil.example.com"}],
    }))
    .unwrap();
    let env = Env { dir: dir.clone(), root, key, cert, authz: SigningKey::generate(), approver: SigningKey::generate(), zone };
    let mut writer = env.open();
    let mut churn = Churn { boxes, step: 0 };
    let mut now = T0;
    let t = Instant::now();
    for _ in 0..history {
        now += 10;
        let c = churn.next(&env);
        writer.commit(vec![c], now).unwrap();
    }
    println!("history: {history} deltas in {:.1?}; log {} KB", t.elapsed(), size(&dir) / 1024);
    let t = Instant::now();
    let opened = env.open();
    println!("open: {:.1?} (epoch {}, {} live tokens)", t.elapsed(), opened.epoch(), opened.state().zones.len());
    drop(opened);

    // Every run commits its own changes: the writer goes round the publishers, each catching up
    // first (as under the lock), then the others catch up after its append.
    drop(writer);
    let mut pubs: Vec<Follower> = (0..boxes.max(1)).map(|_| Follower::new(&env)).collect();
    let (mut one, mut all, mut commits) = (vec![], vec![], vec![]);
    for step in 0..measured {
        now += 10;
        let c = churn.next(&env);
        let w = step % pubs.len();
        pubs[w].catch_up(&env, reopen);
        let t = Instant::now();
        pubs[w].p.commit(vec![c], now).unwrap();
        commits.push(t.elapsed());
        let t = Instant::now();
        for (i, f) in pubs.iter_mut().enumerate() {
            if i != w {
                let t1 = Instant::now();
                f.catch_up(&env, reopen);
                one.push(t1.elapsed());
            }
        }
        all.push(t.elapsed());
    }
    let checkpoints: u64 = pubs.iter().map(|f| f.written + f.p.checkpoints_written()).sum();
    println!("boxes {boxes}, {measured} appends by {} publishers in turn{}:", pubs.len(), if reopen { " (reopening)" } else { "" });
    println!("  one publisher's catch-up after an append: {}", stats(one));
    println!("  one append, every other publisher catching up: {}", stats(all));
    println!("  the commit itself (checkpoints included): {}", stats(commits));
    println!("  checkpoints written: {checkpoints} (one per {CHECKPOINT_EVERY} deltas: {})", measured as u64 / CHECKPOINT_EVERY);
    let _ = std::fs::remove_dir_all(&dir);
}

fn size(dir: &Path) -> u64 {
    std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()?.metadata().ok()).map(|m| m.len()).sum()
}

/// Another run's publisher on the same feed.
struct Follower {
    p: Publisher<BoxAuthority>,
    len: u64,
    /// Checkpoints written by the publishers this one replaced (reopening).
    written: u64,
}

impl Follower {
    fn new(env: &Env) -> Follower {
        let p = env.open();
        Follower { len: len(&p), p, written: 0 }
    }

    /// What `SharedFeed::lock` does before each use.
    fn catch_up(&mut self, env: &Env, reopen: bool) {
        if !reopen {
            if self.p.refresh().unwrap() == Refreshed::Reopen {
                self.written += self.p.checkpoints_written();
                self.p = env.open();
            }
            return;
        }
        let l = len(&self.p);
        if l != self.len {
            self.written += self.p.checkpoints_written();
            self.p = env.open();
            self.len = l;
        }
    }
}

fn len(p: &Publisher<BoxAuthority>) -> u64 {
    std::fs::metadata(p.log_path()).map(|m| m.len()).unwrap_or(0)
}
