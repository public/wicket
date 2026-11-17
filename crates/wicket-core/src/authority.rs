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
    ends_by(now, end_of(now, ttl_secs), until)
}

/// `ttl_secs` from `now`, if that is an `i64` (computed in `i128`, so exact).
pub fn end_of(now: i64, ttl_secs: u64) -> Option<i64> {
    i64::try_from(i128::from(now) + i128::from(ttl_secs)).ok()
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

/// The rules at their boundaries, as the Kani proofs state them for every value (#326: the proofs
/// don't run under `cargo test`, so mutation testing needs these).
#[cfg(test)]
mod tests {
    use super::*;

    /// Parent links over numbers: `i`'s parent is `i + 1`, up to `top` (which has none).
    fn line(top: u32) -> impl FnMut(&u32) -> Result<Option<u32>, String> {
        move |r: &u32| Ok((*r < top).then_some(r + 1))
    }

    #[test]
    fn a_chain_runs_from_the_run_up_to_its_ancestor() {
        assert_eq!(descendant_chain(line(10), &1, &0), Ok(Some(vec![0, 1])), "a child");
        assert_eq!(descendant_chain(line(10), &3, &0), Ok(Some(vec![0, 1, 2, 3])), "a grandchild's grandchild");
        assert_eq!(descendant_chain(line(10), &0, &0), Ok(None), "never the target itself");
        assert_eq!(descendant_chain(line(10), &0, &3), Ok(None), "an ancestor is no descendant");
        assert_eq!(descendant_chain(line(10), &20, &0), Ok(None), "the chain ends without the target");
        // Errors from the parent lookup are the caller's.
        let failing = |_: &u32| -> Result<Option<u32>, String> { Err("ledger".into()) };
        assert_eq!(descendant_chain(failing, &1, &0), Err("ledger".into()));
    }

    #[test]
    fn a_chain_is_at_most_max_chain_runs_below_its_target_and_never_loops() {
        let max = MAX_CHAIN as u32;
        let found = descendant_chain(line(1000), &max, &0).unwrap().expect("MAX_CHAIN runs below");
        assert_eq!(found.len(), MAX_CHAIN + 1);
        assert_eq!(descendant_chain(line(1000), &(max + 1), &0), Ok(None), "one more is too far");
        // A cycle of parent links (0 → 1 → 2 → 0) that doesn't pass the target ends.
        let cycle = |r: &u32| -> Result<Option<u32>, String> { Ok(Some((r + 1) % 3)) };
        assert_eq!(descendant_chain(cycle, &7, &0), Ok(None));
        assert_eq!(descendant_chain(cycle, &2, &0), Ok(Some(vec![0, 1, 2])));
    }

    #[test]
    fn an_end_is_within_an_authority_up_to_its_last_second() {
        assert_eq!(end_of(10, 5), Some(15));
        assert_eq!(end_of(-10, 5), Some(-5));
        assert_eq!(end_of(i64::MAX - 1, 2), None, "past i64::MAX");
        assert_eq!(end_of(i64::MAX, 0), Some(i64::MAX));
        assert_eq!(ends_within(100, 50, 150), Ok(()), "ending exactly with the authority");
        assert_eq!(ends_within(100, 51, 150), Err(Outlasts::Later));
        assert_eq!(ends_within(100, 1, 100), Err(Outlasts::Ended), "an authority ending now has ended");
        assert_eq!(ends_within(100, 0, 99), Err(Outlasts::Ended));
        assert_eq!(ends_within(100, u64::MAX, i64::MAX), Err(Outlasts::Later), "an end past i64::MAX outlasts all");
        assert_eq!(ends_by(100, Some(120), 150), Ok(()));
        assert_eq!(ends_by(100, None, 150), Err(Outlasts::Later));
        assert_eq!(ends_by(100, Some(120), 101), Err(Outlasts::Later));
    }
}
