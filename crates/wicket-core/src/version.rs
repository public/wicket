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
