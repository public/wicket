//! Alternative path model: the path as up to `MAX_DEPTH` segment attributes (`s0`..`s7`) plus a
//! `depth`, instead of one string. Cedar can't say "one segment" on a string, but it can on a
//! segment attribute, so every glob without `?`/`[...]` compiles exactly — for paths of at most
//! `MAX_DEPTH` segments (deeper requests would have to be refused by the proxy, or matched
//! by a `rest` attribute this experiment doesn't model).

use crate::glob::{cedar_str, expand_braces, Mode};
use std::sync::atomic::{AtomicBool, Ordering};

pub const MAX_DEPTH: usize = 8;

static ON: AtomicBool = AtomicBool::new(false);

pub fn enable() {
    ON.store(true, Ordering::SeqCst);
}

pub fn on() -> bool {
    ON.load(Ordering::SeqCst)
}

pub fn url_entity_decl() -> String {
    if on() {
        let segs: Vec<String> = (0..MAX_DEPTH).map(|i| format!("s{i}: String")).collect();
        format!("entity Url {{ host: String, depth: Long, {} }};", segs.join(", "))
    } else {
        "entity Url { host: String, path: String };".into()
    }
}

/// "/a/b/" -> ["a", "b", ""]; "/" -> [""].
pub fn split(path: &str) -> Vec<String> {
    path.strip_prefix('/').unwrap_or(path).split('/').map(String::from).collect()
}

#[derive(Clone)]
enum Comp {
    /// A segment pattern; `exact` is false if it had `?` or `[...]`.
    Seg { like: String, wild: bool, approx: bool },
    DStar,
}

fn comps(glob: &str) -> Vec<Comp> {
    let body = glob.strip_prefix('/').unwrap_or(glob);
    body.split('/')
        .map(|c| {
            if c == "**" {
                return Comp::DStar;
            }
            let mut like = String::new();
            let mut wild = false;
            let mut approx = false;
            let mut chars = c.chars().peekable();
            while let Some(ch) = chars.next() {
                match ch {
                    '*' => {
                        while chars.peek() == Some(&'*') {
                            chars.next();
                        }
                        like.push('*');
                        wild = true;
                    }
                    '?' | '[' => {
                        if ch == '[' {
                            for d in chars.by_ref() {
                                if d == ']' {
                                    break;
                                }
                            }
                        }
                        like.push('*');
                        wild = true;
                        approx = true;
                    }
                    '\\' => {
                        if let Some(d) = chars.next() {
                            like.push(d);
                        }
                    }
                    '"' => like.push_str("\\\""),
                    c => like.push(c),
                }
            }
            Comp::Seg { like, wild, approx }
        })
        .collect()
}

/// All ways `cs` can cover segments `at..n`: a list of conjunctions of per-segment conditions.
fn align(cs: &[Comp], at: usize, n: usize, mode: Mode, exact: &mut bool) -> Vec<Vec<String>> {
    let Some((first, rest)) = cs.split_first() else {
        return if at == n { vec![vec![]] } else { vec![] };
    };
    match first {
        Comp::DStar if rest.is_empty() => {
            // Trailing "/**": one or more remaining segments, anything (globset: "/x/**" matches "/x/", not "/x").
            if n > at {
                vec![vec![]]
            } else {
                vec![]
            }
        }
        Comp::DStar => (at..=n).flat_map(|k| align(rest, k, n, mode, exact)).collect(),
        Comp::Seg { like, wild, approx } => {
            if at >= n {
                return vec![];
            }
            let cond = if *approx {
                *exact = false;
                if mode == Mode::Under {
                    return vec![];
                }
                format!("resource.s{at} like \"{like}\"")
            } else if *wild {
                if like == "*" {
                    String::new()
                } else {
                    format!("resource.s{at} like \"{like}\"")
                }
            } else {
                format!("resource.s{at} == \"{like}\"")
            };
            align(rest, at + 1, n, mode, exact)
                .into_iter()
                .map(|mut v| {
                    if !cond.is_empty() {
                        v.insert(0, cond.clone());
                    }
                    v
                })
                .collect()
        }
    }
}

pub fn glob_expr(glob: &str, mode: Mode, exact: &mut bool) -> String {
    // depth -> condition on the segments; depths with the same condition are merged.
    let mut groups: Vec<(String, Vec<usize>)> = vec![];
    for n in 1..=MAX_DEPTH {
        let mut alts: Vec<String> = vec![];
        for g in expand_braces(glob) {
            for conj in align(&comps(&g), 0, n, mode, exact) {
                let c = if conj.is_empty() { "true".to_string() } else { conj.join(" && ") };
                if !alts.contains(&c) {
                    alts.push(c);
                }
            }
        }
        if alts.is_empty() {
            continue;
        }
        let body = if alts.iter().any(|a| a == "true") { "true".to_string() } else { alts.join(" || ") };
        match groups.iter_mut().find(|(b, _)| *b == body) {
            Some((_, ds)) => ds.push(n),
            None => groups.push((body, vec![n])),
        }
    }
    let parts: Vec<String> = groups
        .into_iter()
        .map(|(body, ds)| {
            let lo = ds[0];
            let contiguous_to_max = ds.iter().copied().eq(lo..=MAX_DEPTH);
            let d = if ds.len() == 1 {
                format!("resource.depth == {lo}")
            } else if contiguous_to_max {
                format!("resource.depth >= {lo}")
            } else {
                format!("({})", ds.iter().map(|n| format!("resource.depth == {n}")).collect::<Vec<_>>().join(" || "))
            };
            if body == "true" {
                d
            } else {
                format!("({d} && ({body}))")
            }
        })
        .collect();
    if parts.is_empty() {
        "false".into()
    } else if parts.len() == 1 {
        parts.into_iter().next().unwrap()
    } else {
        format!("({})", parts.join(" || "))
    }
}

/// Non-canonical paths in the segment model.
pub fn envelope_conditions() -> Vec<String> {
    let mut v = vec![format!("resource.depth < 1"), format!("resource.depth > {MAX_DEPTH}")];
    for i in 0..MAX_DEPTH {
        let s = format!("resource.s{i}");
        let live = format!("resource.depth > {i}");
        let inner = format!("resource.depth > {}", i + 1);
        v.push(format!("({inner} && {s} == \"\")"));
        let bad = ["*/*", ".", "..", "*?*", "*%2f*", "*%2F*", "*%5c*", "*%5C*", "*%2e*", "*%2E*", "*%00*", "*%25*", "*\\\\*"]
            .iter()
            .map(|p| if p.contains('*') { format!("{s} like \"{p}\"") } else { format!("{s} == {}", cedar_str(p)) })
            .collect::<Vec<_>>()
            .join(" || ");
        v.push(format!("({live} && ({bad}))"));
    }
    v
}
