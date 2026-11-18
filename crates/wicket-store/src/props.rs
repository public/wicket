//! Properties of the security-critical grant code written for #258 and #256 (#326), checked over
//! seeded random sequences of operations against a small model of what each should do:
//!
//! - [`Ledger::may_use`]: a use is accepted only by a live, unrevoked digest grant whose action and
//!   scope cover it, the oldest such one, never past its uses, and every acceptance writes exactly
//!   one `digest.accepted` audit record (a refusal none). Racing users of one counted grant, each on
//!   its own connection, never use it more often than it allows.
//! - [`crate::money::check`] (through [`Ledger::reserve_money`]): the live money quota grants equal
//!   the model's reservations after every step; a reservation is recorded only if, with every live
//!   one, it fits the limit it was checked against, and a refused one records nothing.
//!
//! No property-testing crate: a small seeded generator, so a failure names its seed and step.

use crate::lease::{BudgetRefusal, LeaseBudget};
use crate::*;
use wicket_core::TenantId;

/// xorshift64*: enough to drive the sequences, and reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

const SEEDS: u64 = 200;
const STEPS: usize = 60;

fn digests() -> Vec<String> {
    ["aa", "bb", "cc"].iter().map(|c| format!("sha256:{}", c.repeat(32))).collect()
}

fn scopes() -> Vec<DigestScope> {
    vec![DigestScope::Installation, DigestScope::Zone("a".into()), DigestScope::Zone("b".into()), DigestScope::Node("n".into())]
}

const ACTIONS: [DigestAction; 3] = [DigestAction::Run, DigestAction::Install, DigestAction::Mount];

/// The model's grant: what was recorded, and whether it is still live (not revoked or expired).
struct ModelGrant {
    id: String,
    digest: String,
    action: DigestAction,
    scope: DigestScope,
    uses: Option<u32>,
    live: bool,
}

impl ModelGrant {
    fn covers(&self, digest: &str, action: DigestAction, scope: &DigestScope) -> bool {
        self.live
            && self.digest == digest
            && self.action == action
            && (self.scope == DigestScope::Installation || &self.scope == scope)
            && self.uses.is_none_or(|n| n > 0)
    }
}

fn accepted(l: &Ledger) -> usize {
    l.audit_of_kind("digest.accepted").unwrap().len()
}

/// #258: over random grants, revocations, expiries and uses, `may_use` answers as the model does
/// (the oldest live grant covering the digest, action and scope, with a use left), takes a counted
/// grant's use, and audits exactly the acceptances.
#[test]
fn may_use_accepts_only_by_a_live_covering_grant_with_a_use_left() {
    let (ds, ss) = (digests(), scopes());
    let t = TenantId::single();
    for seed in 0..SEEDS {
        let mut rng = Rng::new(seed);
        let l = Ledger::open_in_memory().unwrap();
        let mut model: Vec<ModelGrant> = vec![];
        let mut audits = 0;
        for step in 0..STEPS {
            match rng.below(10) {
                // Grant (the most common, so uses find something).
                0..=3 => {
                    let (digest, action, scope) = (rng.pick(&ds).clone(), *rng.pick(&ACTIONS), rng.pick(&ss).clone());
                    let uses = match rng.below(3) {
                        0 => None,
                        _ => Some(1 + rng.below(3) as u32),
                    };
                    let id = l
                        .grant_digest(&NewDigestGrant {
                            tenant: &t,
                            digest: &digest,
                            action,
                            scope: scope.clone(),
                            uses,
                            expires_at: now() + 3600,
                            decided_by: "operator:test",
                        })
                        .unwrap();
                    model.push(ModelGrant { id, digest, action, scope, uses, live: true });
                }
                // Revoke one.
                4 if !model.is_empty() => {
                    let i = rng.below(model.len() as u64) as usize;
                    l.revoke_grant(&model[i].id).unwrap();
                    model[i].live = false;
                }
                // Expire one (its lifetime ends: past, as time passing would make it).
                5 if !model.is_empty() => {
                    let i = rng.below(model.len() as u64) as usize;
                    l.conn.execute("UPDATE grants SET expires_at = ?2 WHERE id = ?1", rusqlite::params![model[i].id, now() - 1]).unwrap();
                    model[i].live = false;
                }
                // Use.
                _ => {
                    let (digest, action, scope) = (rng.pick(&ds).clone(), *rng.pick(&ACTIONS), rng.pick(&ss).clone());
                    let want = model.iter().position(|g| g.covers(&digest, action, &scope));
                    let got = l.may_use(&t, &digest, action, &scope, "prop").unwrap();
                    match (want, &got) {
                        (Some(i), Some(u)) => {
                            assert_eq!(u.grant, model[i].id, "seed {seed} step {step}: the oldest covering grant");
                            assert_eq!(u.scope, model[i].scope, "seed {seed} step {step}");
                            if let Some(n) = &mut model[i].uses {
                                *n -= 1;
                            }
                            audits += 1;
                        }
                        (None, None) => {}
                        _ => panic!("seed {seed} step {step}: {digest} {action:?} {scope:?}: model {want:?}, ledger {got:?}"),
                    }
                    assert_eq!(accepted(&l), audits, "seed {seed} step {step}: one audit record per acceptance, none per refusal");
                }
            }
        }
        // What the ledger holds agrees with the model: no counted grant was used past its uses.
        for g in &model {
            let left: Option<i64> =
                l.conn.query_row("SELECT uses_left FROM grants WHERE id = ?1", rusqlite::params![g.id], |r| r.get(0)).unwrap();
            assert_eq!(left, g.uses.map(i64::from), "seed {seed}: grant {}'s uses", g.id);
        }
    }
}

/// #258: users racing for one counted grant, each on its own connection to one ledger file, never
/// use it more often than it allows; each acceptance is one audit record. (SQLite's locks, not
/// atomics, are what races here, so real threads and connections rather than loom.)
#[test]
fn racing_users_never_use_a_counted_grant_past_its_uses() {
    let t = TenantId::single();
    let digest = digests()[0].clone();
    for round in 0..20u32 {
        let path = std::env::temp_dir().join(format!("wicket-race-{}-{round}.db", wicket_core::new_ulid()));
        let uses = 1 + round % 4;
        {
            let l = Ledger::open(&path).unwrap();
            l.grant_digest(&NewDigestGrant {
                tenant: &t,
                digest: &digest,
                action: DigestAction::Install,
                scope: DigestScope::Installation,
                uses: Some(uses),
                expires_at: now() + 3600,
                decided_by: "operator:test",
            })
            .unwrap();
        }
        // Opened before the race (opening migrates), then each thread uses its own.
        let ledgers: Vec<Ledger> = (0..6).map(|_| Ledger::open(&path).unwrap()).collect();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(ledgers.len()));
        let handles: Vec<_> = ledgers
            .into_iter()
            .map(|l| {
                let (t, digest, barrier) = (t.clone(), digest.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut ok = 0;
                    for _ in 0..3 {
                        // An error is a lost race (the database was busy): not an acceptance.
                        if let Ok(Some(_)) = l.may_use(&t, &digest, DigestAction::Install, &DigestScope::Installation, "racer") {
                            ok += 1;
                        }
                    }
                    ok
                })
            })
            .collect();
        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        let l = Ledger::open(&path).unwrap();
        assert!(total <= uses, "round {round}: {total} acceptances of a grant with {uses} uses");
        assert!(total >= 1, "round {round}: some racer is accepted (the race isn't vacuous)");
        assert_eq!(accepted(&l), total as usize, "round {round}: one audit record per acceptance");
        let left: i64 = l.conn.query_row("SELECT uses_left FROM grants LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(left, i64::from(uses - total), "round {round}: the uses taken are the acceptances");
        drop(l);
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }
}

/// #256: over random reservations, releases, expiries and limit changes, the live money quota
/// grants are the model's reservations; a reservation is recorded only if it fits, with every live
/// one, the limit it is checked against (the hourly limit first), and a refused one records nothing.
#[test]
fn money_reservations_never_exceed_the_limit_they_were_checked_against() {
    let tenant = "t";
    for seed in 0..SEEDS {
        let mut rng = Rng::new(seed);
        let mut l = Ledger::open_in_memory().unwrap();
        let mut limit = LeaseBudget { max_hourly: 100_000, max_total: 1_000_000 };
        // key -> (hourly, reserved), as recorded (a part of 0 is not recorded).
        let mut model: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
        let sums = |m: &std::collections::BTreeMap<String, (i64, i64)>| m.values().fold((0, 0), |(h, r), (a, b)| (h + a, r + b));
        for step in 0..STEPS {
            let key = format!("node-{}", rng.below(6));
            match rng.below(8) {
                0..=3 => {
                    let (h, r) = (rng.below(60_001) as i64, rng.below(600_001) as i64);
                    let got = l.reserve_money(tenant, &key, h, r, 3600, limit, "prop").unwrap();
                    let (sh, sr) = sums(&model);
                    let want = if model.contains_key(&key) {
                        Ok(())
                    } else if sh + h > limit.max_hourly {
                        Err(BudgetRefusal::Hourly { reserved: sh, new: h, max: limit.max_hourly })
                    } else if sr + r > limit.max_total {
                        Err(BudgetRefusal::Total { reserved: sr, new: r, max: limit.max_total })
                    } else {
                        Ok(())
                    };
                    assert_eq!(got, want, "seed {seed} step {step}: reserve {key} {h}/h {r}");
                    if got.is_ok() && !model.contains_key(&key) && (h > 0 || r > 0) {
                        model.insert(key.clone(), (h, r));
                        let (sh, sr) = sums(&model);
                        assert!(
                            sh <= limit.max_hourly && sr <= limit.max_total,
                            "seed {seed} step {step}: over the limit it was checked against"
                        );
                    }
                    assert_eq!(l.money_limit(tenant).unwrap(), Some(limit), "seed {seed} step {step}: the limit grant follows the limits");
                }
                4 => {
                    l.release_money(&key).unwrap();
                    model.remove(&key);
                }
                5 => {
                    // Its lifetime ends.
                    let [hp, rp] = crate::quota::lease_quota_paths(&key);
                    l.conn
                        .execute("UPDATE grants SET expires_at = ?3 WHERE path IN (?1, ?2)", rusqlite::params![hp, rp, now() - 1])
                        .unwrap();
                    model.remove(&key);
                }
                // The configured limits change (lowered or raised); what is reserved stays.
                _ => {
                    limit =
                        LeaseBudget { max_hourly: 20_000 + rng.below(200_000) as i64, max_total: 200_000 + rng.below(2_000_000) as i64 };
                }
            }
            assert_eq!(l.money_reserved(tenant).unwrap(), sums(&model), "seed {seed} step {step}: the live grants are the model's");
        }
    }
}
