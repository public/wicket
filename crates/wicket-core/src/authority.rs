//! What an agent may decide (#50, #291): the parts of `wicket-cli`'s `grant::within_authority`,
//! `agent_terms` and `agent_renews` that don't need the ledger, over its identities' parent links
//! and bare times. Kani checks them (#325, `proofs/authority.rs`) against Wicket/Grant.lean.

/// How far up a spawn chain a request is routed to a granter.
pub const MAX_CHAIN: usize = 64;

/// The chain from `run` up to `target` (`run` first), if `run` is a strict descendant of `target`
/// by `parent_of` (the ledger's `parent_run`): `Ok(None)` if not, and never for `target` itself,
/// even if the parent links had a cycle through it.
pub fn descendant_chain<T: PartialEq + Clone, E>(
    mut parent_of: impl FnMut(&T) -> Result<Option<T>, E>,
    target: &T,
    run: &T,
) -> Result<Option<Vec<T>>, E> {
    // An agent never decides its own request: not even round a cycle of parent links (#325).
    if run == target {
        return Ok(None);
    }
    let mut chain = vec![run.clone()];
    let mut at = parent_of(run)?;
    loop {
        match at {
            Some(p) if &p == target => {
                chain.push(p);
                return Ok(Some(chain));
            }
            Some(p) if chain.len() < MAX_CHAIN && !chain.contains(&p) => {
                at = parent_of(&p)?;
                chain.push(p);
            }
            _ => return Ok(None),
        }
    }
}

/// Why an end is past an agent's own authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outlasts {
    /// Its authority has ended already.
    Ended,
    /// The end is after its authority's.
    Later,
}

/// Whether something an agent grants or renews, ending `ttl_secs` from `now`, ends no later than the
/// agent's own authority (`until`; all Unix seconds). An end past `i64::MAX` is past every authority.
pub fn ends_within(now: i64, ttl_secs: u64, until: i64) -> Result<(), Outlasts> {
    ends_by(now, i64::try_from(ttl_secs).ok().and_then(|t| now.checked_add(t)), until)
}

/// As [`ends_within`], for an end already computed (`None`: past `i64::MAX`).
pub fn ends_by(now: i64, end: Option<i64>, until: i64) -> Result<(), Outlasts> {
    if until <= now {
        return Err(Outlasts::Ended);
    }
    match end {
        Some(end) if end <= until => Ok(()),
        _ => Err(Outlasts::Later),
    }
}

#[cfg(kani)]
#[path = "proofs/authority.rs"]
mod proofs;
