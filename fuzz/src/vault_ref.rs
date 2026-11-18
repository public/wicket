//! Target 11: a linked secret's `<name>.ref` (#499, `wicket_proxy::vault`). A link is JSON the vault
//! reads at every use of the secret, and its file is the operator's (`wicket secret link`), kept
//! across builds: links any earlier build wrote (every field present, `null` for none) must read as
//! they did, and nothing in one may panic the proxy that reads it.
//!
//! The oracle, besides panics: a link that reads writes (as `write_ref` does) as a link that reads
//! back, and writes the same again: what the vault accepts, it keeps.

use wicket_proxy::vault::ref_file_round_trip;

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Some(written) = ref_file_round_trip(text) else { return };
    let again = ref_file_round_trip(&written).unwrap_or_else(|| panic!("{text:?} reads, but what it writes doesn't: {written}"));
    assert_eq!(again, written, "{text:?}: what it writes doesn't write back the same");
}
