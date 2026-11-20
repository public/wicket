//! The rules for a box name's label (design: "Name rules").
//!
//! A label is one DNS label: 1–63 characters of `a-z`, `0-9` and `-`, not starting or ending with
//! `-`. No dots (a name can't sit under another name), no `*`, no `_` (those are wicket's own owner
//! and service records). A label starting `xn--` (an IDN) is refused unless the operator allows
//! them. A reserved label, or one whose ASCII skeleton is a reserved label's, is refused, so
//! `c0nsole`, `conso1e` and `con-sole` are as reserved as `console`.

use std::fmt;

/// Labels every installation reserves, besides the operator's own.
pub const RESERVED: &[&str] = &["wicket", "console", "www", "api", "admin", "mail", "ns"];

/// The longest DNS label.
pub const MAX_LABEL: usize = 63;

/// What the operator adds to the rules.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    /// Labels reserved besides [`RESERVED`]: the operator's list, and the first label of the
    /// console's host name.
    pub reserved: Vec<String>,
    /// Whether `xn--` labels are allowed.
    pub allow_idn: bool,
}

/// Why a label was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelError {
    Empty,
    TooLong(usize),
    /// A character outside `a-z`, `0-9` and `-` (an upper-case letter included: labels are asked
    /// for in lower case, not folded).
    Character(char),
    /// Starts or ends with `-`.
    Hyphen,
    Idn,
    /// Reserved, or a lookalike of the reserved label named.
    Reserved(String),
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelError::Empty => write!(f, "a name can't be empty"),
            LabelError::TooLong(n) => write!(f, "a name is at most {MAX_LABEL} characters (this is {n})"),
            LabelError::Character('.') => write!(f, "a name is one label: no dots"),
            LabelError::Character(c) => write!(f, "a name has only a-z, 0-9 and '-', not {c:?}"),
            LabelError::Hyphen => write!(f, "a name can't start or end with '-'"),
            LabelError::Idn => write!(f, "internationalized names (xn--) aren't allowed here"),
            LabelError::Reserved(r) if r.is_empty() => write!(f, "that name is reserved"),
            LabelError::Reserved(r) => write!(f, "that name is reserved (it looks like {r:?})"),
        }
    }
}

impl std::error::Error for LabelError {}

/// Checks `label` against the rules: its shape ([`check_shape`]), then the reserved labels and
/// their lookalikes. For public names.
pub fn check_label(label: &str, rules: &Rules) -> Result<(), LabelError> {
    check_shape(label, rules.allow_idn)?;
    let s = skeleton(label);
    let reserved = RESERVED.iter().map(|r| r.to_string()).chain(rules.reserved.iter().map(|r| r.to_ascii_lowercase()));
    for r in reserved {
        if r == label {
            return Err(LabelError::Reserved(String::new()));
        }
        if !r.is_empty() && skeleton(&r) == s {
            return Err(LabelError::Reserved(r));
        }
    }
    Ok(())
}

/// Checks only that `label` is one DNS label wicket accepts (no reserved names): for internal
/// names, which live under their zone's name, where no lookalike of the console's can be.
pub fn check_shape(label: &str, allow_idn: bool) -> Result<(), LabelError> {
    if label.is_empty() {
        return Err(LabelError::Empty);
    }
    if label.len() > MAX_LABEL {
        return Err(LabelError::TooLong(label.len()));
    }
    if let Some(c) = label.chars().find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-')) {
        return Err(LabelError::Character(c));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(LabelError::Hyphen);
    }
    if label.starts_with("xn--") && !allow_idn {
        return Err(LabelError::Idn);
    }
    Ok(())
}

/// The domain internal names live under (`wicket_core::link::DOMAIN`, which a test holds this to).
pub const INTERNAL_DOMAIN: &str = "wicket.internal";

/// The longest zone part of an internal name: with a 63-character label, a dot and
/// `.wicket.internal`, the whole name stays within DNS's 253.
pub const MAX_ZONE_PART: usize = 170;

/// A zone's name as it appears in internal names (`<label>.<zone>.wicket.internal`, #575): only
/// a zone whose name is already in DNS form, each dot-separated part one label ([`check_shape`]:
/// lower case, digits and `-`), may hold names, and its name is used as it is. No other zone name
/// is mapped to one (#668): `Build` and `build`, or `web_api` and `web-api`, are different zones to
/// `accept_from`, so one DNS form for both would let one zone's box take the other's names. A
/// spawned zone (`<parent>.<agent>.<run id without run_>`) is in DNS form when its parent's and
/// agent's names are, since run ids are lower case and digits.
pub fn zone_part(zone: &str) -> Result<String, LabelError> {
    if zone.len() > MAX_ZONE_PART {
        return Err(LabelError::TooLong(zone.len()));
    }
    // A zone named like wicket's own domain would make `<label>.<zone>.wicket.internal` read as a
    // name of another zone once a lookup strips the suffix (#668 review).
    // Compared in any case and without a trailing dot, so the refusal doesn't rest on the shape
    // check below.
    let folded = zone.trim_end_matches('.').to_ascii_lowercase();
    if folded == INTERNAL_DOMAIN || folded.ends_with(&format!(".{INTERNAL_DOMAIN}")) {
        return Err(LabelError::Reserved(INTERNAL_DOMAIN.to_string()));
    }
    for part in zone.split('.') {
        check_shape(part, false)?;
    }
    Ok(zone.to_string())
}

/// The label with lookalikes folded: `0`→`o`, `1` and `i`→`l`, `5`→`s`, `rn`→`m`, `vv`→`w`, and
/// `-` dropped. Two labels with one skeleton are refused as the same name where one is reserved.
pub fn skeleton(label: &str) -> String {
    let folded: String = label
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' => 'l',
            '5' => 's',
            c => c,
        })
        .collect();
    folded.replace("rn", "m").replace("vv", "w")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(l: &str) -> Result<(), LabelError> {
        check_label(l, &Rules::default())
    }

    #[test]
    fn plain_labels_pass() {
        for l in ["demo", "a", "my-api-2", "x".repeat(63).as_str()] {
            assert_eq!(ok(l), Ok(()), "{l}");
        }
    }

    #[test]
    fn shapes_are_refused() {
        assert_eq!(ok(""), Err(LabelError::Empty));
        assert_eq!(ok(&"x".repeat(64)), Err(LabelError::TooLong(64)));
        assert_eq!(ok("a.b"), Err(LabelError::Character('.')));
        assert_eq!(ok("Demo"), Err(LabelError::Character('D')));
        assert_eq!(ok("_wicket"), Err(LabelError::Character('_')));
        assert_eq!(ok("*"), Err(LabelError::Character('*')));
        assert_eq!(ok("-demo"), Err(LabelError::Hyphen));
        assert_eq!(ok("demo-"), Err(LabelError::Hyphen));
        assert_eq!(ok("xn--bcher-kva"), Err(LabelError::Idn));
        assert_eq!(check_label("xn--bcher-kva", &Rules { allow_idn: true, ..Rules::default() }), Ok(()));
    }

    #[test]
    fn reserved_and_lookalikes_are_refused() {
        assert_eq!(ok("console"), Err(LabelError::Reserved(String::new())));
        for l in ["c0nsole", "conso1e", "consoie", "con-sole", "wlcket", "vvww", "adrnin"] {
            assert!(matches!(ok(l), Err(LabelError::Reserved(_))), "{l} should be refused");
        }
        let rules = Rules { reserved: vec!["Status".into(), "ops".into()], allow_idn: false };
        assert!(check_label("status", &rules).is_err());
        assert!(check_label("5tatus", &rules).is_err());
        assert!(check_label("0ps", &rules).is_err());
        assert_eq!(check_label("demo", &rules), Ok(()));
    }

    #[test]
    fn only_zones_already_in_dns_form_hold_names() {
        assert_eq!(zone_part("build").unwrap(), "build");
        assert_eq!(zone_part("lead.fetcher.01jabcd0123456789abcdefghj").unwrap(), "lead.fetcher.01jabcd0123456789abcdefghj");
        // Not mapped (#668): each of these is a zone apart from its look-alike.
        assert!(zone_part("Build").is_err());
        assert!(zone_part("web_api").is_err());
        assert!(zone_part("lead.fetch_er.01jabcd").is_err());
        assert!(zone_part("a..b").is_err());
        assert!(zone_part("-x").is_err());
        assert!(zone_part("caf\u{e9}").is_err());
        assert!(zone_part(&"a.".repeat(100)).is_err());
        // Nor a zone named like wicket's own domain (#668 review).
        assert!(zone_part("wicket.internal").is_err());
        assert!(zone_part("build.wicket.internal").is_err());
        assert!(zone_part("wicket.internals").is_ok());
        // In any case, or with a trailing dot, refused as wicket's domain, not only by its shape.
        for z in ["Build.Wicket.Internal", "build.wicket.internal.", "build.WICKET.INTERNAL", "BUILD.wicket.internal", "wicket.internal."] {
            assert_eq!(zone_part(z), Err(LabelError::Reserved(INTERNAL_DOMAIN.into())), "{z}");
        }
    }

    #[test]
    fn shapes_alone_allow_reserved_labels() {
        assert_eq!(check_shape("api", false), Ok(()));
        assert_eq!(check_shape("console", false), Ok(()));
        assert_eq!(check_shape("a.b", false), Err(LabelError::Character('.')));
        assert_eq!(check_shape("xn--bcher-kva", false), Err(LabelError::Idn));
    }
}
