//! Path globs (wicket's globset syntax, `literal_separator(true)`) to Cedar boolean expressions.
//!
//! Cedar's `like` has one wildcard, `*`, and it matches any characters *including* `/`. wicket's
//! `*` stays inside one path segment. So a glob can only sometimes be written exactly:
//!
//! - no single-segment `*`: exact (`**` really is "anything");
//! - single-segment `*`s but no `**`: exact, by also requiring the path to have exactly as many `/`
//!   as the glob's literal text (`!(p like "*/*/*/*")` with one more `/`);
//! - single-segment `*` together with `**` (e.g. `/v1/code/sessions/*/worker/**`): not expressible
//!   exactly with `like` and boolean connectives as far as we found. We then emit an
//!   over-approximation (drop the segment constraint) or an under-approximation (forbid each `*`
//!   from holding a `/` under *any* split), and the caller uses the sound direction: child over,
//!   parent under. A "not contained" answer is then re-checked concretely.
//! - `?` and `[...]`: Cedar has no single-character wildcard and no classes. Over-approximated by
//!   `*`; under-approximated by `false`.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Over,
    Under,
}

impl Mode {
    pub fn flip(self) -> Mode {
        match self {
            Mode::Over => Mode::Under,
            Mode::Under => Mode::Over,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Lit(String),
    /// One-segment `*`.
    Star,
    /// From `**`: anything, slashes included.
    Any,
    /// `?` or a `[...]` class.
    Single,
}

/// How the glob `/x/**` treats `/x` itself. Set from the probe (see `probe` in main.rs):
/// globset's `/x/**` does not match `/x`, but does match `/x/`.
pub const TRAILING_DSTAR_MATCHES_BASE: bool = false;

pub fn expand_braces(g: &str) -> Vec<String> {
    let bytes: Vec<char> = g.chars().collect();
    let Some(open) = bytes.iter().position(|&c| c == '{') else { return vec![g.to_string()] };
    let mut depth = 0;
    let mut close = None;
    let mut commas = vec![];
    for (i, &c) in bytes.iter().enumerate().skip(open) {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            ',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let Some(close) = close else { return vec![g.to_string()] };
    let pre: String = bytes[..open].iter().collect();
    let post: String = bytes[close + 1..].iter().collect();
    let mut cuts = vec![open];
    cuts.extend(&commas);
    cuts.push(close);
    let mut out = vec![];
    for w in cuts.windows(2) {
        let alt: String = bytes[w[0] + 1..w[1]].iter().collect();
        out.extend(expand_braces(&format!("{pre}{alt}{post}")));
    }
    out
}

/// Token sequences for one brace-free glob. `/**/` in the middle yields two variants.
fn tokenise(g: &str) -> Vec<Vec<Tok>> {
    let comps: Vec<&str> = g.split('/').collect();
    let mut seqs: Vec<Vec<Tok>> = vec![vec![]];
    let n = comps.len();
    for (k, comp) in comps.iter().enumerate() {
        let last = k + 1 == n;
        if *comp == "**" {
            if last {
                // ".../**": the separator before it is already emitted.
                for s in &mut seqs {
                    s.push(Tok::Any);
                }
            } else if k == 0 {
                // "**/x": zero or more leading segments.
                let mut next = vec![];
                for s in &seqs {
                    next.push(s.clone());
                    let mut b = s.clone();
                    b.push(Tok::Any);
                    b.push(Tok::Lit("/".into()));
                    next.push(b);
                }
                seqs = next;
            } else {
                // "/a/**/b": "/a/b" or "/a/<anything>/b". The separator before is emitted already.
                let mut next = vec![];
                for s in &seqs {
                    next.push(s.clone());
                    let mut b = s.clone();
                    b.push(Tok::Any);
                    b.push(Tok::Lit("/".into()));
                    next.push(b);
                }
                seqs = next;
            }
            continue;
        }
        let mut toks = vec![];
        let mut lit = String::new();
        let mut chars = comp.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '*' => {
                    while chars.peek() == Some(&'*') {
                        chars.next();
                    }
                    if !lit.is_empty() {
                        toks.push(Tok::Lit(std::mem::take(&mut lit)));
                    }
                    toks.push(Tok::Star);
                }
                '?' => {
                    if !lit.is_empty() {
                        toks.push(Tok::Lit(std::mem::take(&mut lit)));
                    }
                    toks.push(Tok::Single);
                }
                '[' => {
                    for d in chars.by_ref() {
                        if d == ']' {
                            break;
                        }
                    }
                    if !lit.is_empty() {
                        toks.push(Tok::Lit(std::mem::take(&mut lit)));
                    }
                    toks.push(Tok::Single);
                }
                '\\' => {
                    if let Some(d) = chars.next() {
                        lit.push(d);
                    }
                }
                _ => lit.push(c),
            }
        }
        if !lit.is_empty() {
            toks.push(Tok::Lit(lit));
        }
        if !last {
            toks.push(Tok::Lit("/".into()));
        }
        for s in &mut seqs {
            s.extend(toks.iter().cloned());
        }
    }
    // A trailing "/**" also matching the base path, if globset did that.
    if TRAILING_DSTAR_MATCHES_BASE {
        let mut extra = vec![];
        for s in &seqs {
            if s.last() == Some(&Tok::Any) {
                let mut b = s.clone();
                b.pop();
                if let Some(Tok::Lit(l)) = b.last_mut() {
                    if l.ends_with('/') {
                        l.pop();
                    }
                }
                extra.push(b);
            }
        }
        seqs.extend(extra);
    }
    seqs.into_iter().map(merge_lits).collect()
}

fn merge_lits(s: Vec<Tok>) -> Vec<Tok> {
    let mut out: Vec<Tok> = vec![];
    for t in s {
        if let Tok::Lit(b) = &t {
            if b.is_empty() {
                continue;
            }
            if let Some(Tok::Lit(a)) = out.last_mut() {
                a.push_str(b);
                continue;
            }
        }
        out.push(t);
    }
    out
}

/// A Cedar string literal for a `like` pattern (escapes `*`, `\`, `"`).
fn pat(toks: &[Tok]) -> String {
    let mut s = String::new();
    for t in toks {
        match t {
            Tok::Lit(l) => {
                for c in l.chars() {
                    match c {
                        '*' => s.push_str("\\*"),
                        '\\' => s.push_str("\\\\"),
                        '"' => s.push_str("\\\""),
                        c => s.push(c),
                    }
                }
            }
            _ => s.push('*'),
        }
    }
    format!("\"{s}\"")
}

pub fn cedar_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub struct GlobExpr {
    pub expr: String,
    /// Whether `expr` is exactly the glob's language (in this mode).
    pub exact: bool,
}

/// One glob (may contain braces) as a Cedar condition on `var`.
pub fn glob_expr(var: &str, glob: &str, mode: Mode) -> GlobExpr {
    let mut alts = vec![];
    let mut exact = true;
    for g in expand_braces(glob) {
        for toks in tokenise(&g) {
            let (e, ex) = seq_expr(var, &toks, mode);
            exact &= ex;
            alts.push(e);
        }
    }
    let expr = if alts.len() == 1 { alts.pop().unwrap() } else { format!("({})", alts.join(" || ")) };
    GlobExpr { expr, exact }
}

fn seq_expr(var: &str, toks: &[Tok], mode: Mode) -> (String, bool) {
    let stars = toks.iter().filter(|t| **t == Tok::Star).count();
    let anys = toks.iter().filter(|t| **t == Tok::Any).count();
    let singles = toks.iter().filter(|t| **t == Tok::Single).count();
    if singles > 0 && mode == Mode::Under {
        return ("false".into(), false);
    }
    let base = if stars + anys + singles == 0 {
        // A literal: equality is cheaper for the solver than `like`.
        let lit: String = toks.iter().map(|t| if let Tok::Lit(l) = t { l.as_str() } else { "" }).collect();
        format!("{var} == {}", cedar_str(&lit))
    } else {
        format!("{var} like {}", pat(toks))
    };
    if stars == 0 {
        return (base, singles == 0);
    }
    if anys == 0 && singles == 0 {
        // Exact: exactly as many '/' as the literal text has.
        let slashes: usize = toks.iter().map(|t| if let Tok::Lit(l) = t { l.matches('/').count() } else { 0 }).sum();
        let too_many = format!("\"{}\"", "*/".repeat(slashes + 1) + "*");
        return (format!("({base} && !({var} like {too_many}))"), true);
    }
    match mode {
        Mode::Over => (base, false),
        Mode::Under => {
            let mut parts = vec![base];
            let mut idx = 0;
            for (i, t) in toks.iter().enumerate() {
                if *t == Tok::Star {
                    let mut v = toks[..i].to_vec();
                    v.push(Tok::Star);
                    v.push(Tok::Lit("/".into()));
                    v.push(Tok::Star);
                    v.extend(toks[i + 1..].iter().cloned());
                    parts.push(format!("!({var} like {})", pat(&merge_lits(v))));
                    idx += 1;
                }
            }
            let _ = idx;
            (format!("({})", parts.join(" && ")), false)
        }
    }
}
