//! Version skew (#162, #207): which peers may talk, at which protocol version, and which builds may
//! open a ledger. The rules over bare numbers, so they are one function each: the node protocol
//! (`wicket-cli`'s `chan::negotiate`, the update's jump check) and the ledger's schema floor
//! (`wicket-store`'s `check_schema`, the update's rollback check) call these. Kani checks them
//! (#325, `proofs/version.rs`).

/// The protocol version two peers talk at: the lower of the two, if `theirs` has one at all (0 is a
/// peer from before protocol versions) and the two are at most `skew` apart.
pub fn talk_at(ours: u32, theirs: u32, skew: u32) -> Option<u32> {
    (theirs != 0 && !is_jump(ours, theirs, skew)).then_some(ours.min(theirs))
}

/// Whether going from protocol `from` to `to` is a jump: more than `skew` apart, so a peer left on
/// `from` can't talk to one on `to` (#207: the control host and its nodes then switch together).
pub fn is_jump(from: u32, to: u32, skew: u32) -> bool {
    from.abs_diff(to) > skew
}

/// Whether a build of schema `version` may open a ledger whose floor is `floor`: one that has been
/// through a contract step past the build can't be opened by it (its tables changed under it).
pub fn schema_opens(version: u32, floor: u32) -> bool {
    version >= floor
}

/// What a ledger records once a build of schema `(version, floor)` opens one at `(at, at_floor)`:
/// never lower than either, so a later, older build can't lower the floor and open it.
pub fn schema_recorded((at, at_floor): (u32, u32), (version, floor): (u32, u32)) -> (u32, u32) {
    (at.max(version), at_floor.max(floor))
}

#[cfg(kani)]
#[path = "proofs/version.rs"]
mod proofs;

/// The rules at their boundaries, as the Kani proofs state them for every value (#326: the proofs
/// don't run under `cargo test`, so mutation testing needs these).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_talk_at_the_lower_version_within_the_skew() {
        assert_eq!(talk_at(15, 14, 1), Some(14));
        assert_eq!(talk_at(15, 16, 1), Some(15));
        assert_eq!(talk_at(15, 15, 1), Some(15));
        assert_eq!(talk_at(15, 13, 1), None, "two apart");
        assert_eq!(talk_at(15, 17, 1), None);
        assert_eq!(talk_at(1, 0, 1), None, "a peer from before protocol versions, even within the skew");
        assert_eq!(talk_at(3, 5, 2), Some(3));
    }

    #[test]
    fn a_jump_is_more_than_the_skew_either_way() {
        assert!(!is_jump(15, 15, 1));
        assert!(!is_jump(15, 16, 1) && !is_jump(16, 15, 1), "exactly the skew apart is no jump");
        assert!(is_jump(15, 17, 1) && is_jump(17, 15, 1));
        assert!(is_jump(1, 1 + 3, 2) && !is_jump(1, 1, 0));
    }

    #[test]
    fn a_build_opens_a_ledger_up_to_its_own_version_as_floor() {
        assert!(schema_opens(17, 1) && schema_opens(17, 17));
        assert!(!schema_opens(16, 17), "a contract step past the build");
    }

    #[test]
    fn what_a_ledger_records_never_goes_down() {
        assert_eq!(schema_recorded((16, 1), (17, 1)), (17, 1), "a newer build raises the version");
        assert_eq!(schema_recorded((17, 3), (16, 2)), (17, 3), "an older one lowers neither");
        assert_eq!(schema_recorded((17, 2), (17, 5)), (17, 5), "a contract step raises the floor");
    }
}
