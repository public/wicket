//! Untrusted text on an operator's screen. Anything an agent, a node or a web page wrote (a request's
//! reason, method, host or path, a box's name) is printed only through [`strip`] or [`clip`]: no
//! terminal escapes, no characters that reorder or hide what follows.
//! The console's `strip()` (console.js) removes the same set.

/// Whether `c` must never reach an operator's terminal or card as is: C0 and C1 controls (ESC starts
/// every ANSI and OSC sequence; U+009B is a one-character CSI), DEL, the bidi marks, embeddings,
/// overrides and isolates, zero-width characters, and the line and paragraph separators (#128).
pub fn is_unsafe(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'
        | '\u{61c}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{2069}'
        | '\u{feff}')
}

/// `s` with every [`is_unsafe`] character replaced by a space.
pub fn strip(s: &str) -> String {
    s.chars().map(|c| if is_unsafe(c) { ' ' } else { c }).collect()
}

/// As [`strip`], with newlines shown as ` ⏎ ` and at most `n` characters (then `…`).
pub fn clip(s: &str, n: usize) -> String {
    let clean: String = s.chars().map(|c| if c != '\n' && is_unsafe(c) { ' ' } else { c }).collect();
    let clean = clean.replace('\n', " ⏎ ");
    if clean.chars().count() > n {
        format!("{}…", clean.chars().take(n).collect::<String>())
    } else {
        clean
    }
}

/// A value someone other than wicket chose (an agent's zone's host, glob, method, name), for a
/// sentence wicket writes (#731): [`clip`]ped to `n`, and shown as is when it is one plain token,
/// quoted (`{:?}`) when it has anything that could read as wicket's own words (spaces, commas,
/// semicolons, quotes), so no value passes for the sentence's terms. Quoted, it is escaped as
/// [`char::escape_default`] does: quotes, backslashes and every character outside printable ASCII.
pub fn shown(s: &str, n: usize) -> String {
    let c = clip(s, n);
    if !c.is_empty() && c.chars().all(|ch| ch.is_ascii_alphanumeric() || "-._/*:@{}[]?=+~%!$&()#^|<>".contains(ch)) {
        c
    } else {
        // Every character that isn't plain ASCII escaped, as `\u{…}`: a look-alike of a quote
        // (” ″ « ») can't seem to end the value early (#731 review).
        format!("\"{}\"", c.escape_default())
    }
}

/// Values someone other than wicket chose, as a list in a sentence wicket writes (#731 review): each
/// [`shown`] within `each`, at most `max` of them, then how many more.
pub fn shown_list<'a>(items: impl IntoIterator<Item = &'a String>, each: usize, max: usize) -> String {
    let all: Vec<&String> = items.into_iter().collect();
    let mut v: Vec<String> = all.iter().take(max).map(|s| shown(s, each)).collect();
    if all.len() > max {
        v.push(format!("and {} more", all.len() - max));
    }
    v.join(", ")
}

/// `s` with every URL in it cut to its scheme, host, port and path: user info (`user:pass@`), the
/// query and the fragment dropped, as tokens and signed parameters travel there. A URL that doesn't
/// parse, or where more than one '@' could end the user info, is cut to its scheme (`https://…`).
/// For error text that is stored and shown (an exporter's or Litestream's last error).
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        // The scheme: the ASCII letters, digits, '+', '-' and '.' just before `://` (whatever comes
        // before them, non-ASCII included, is text).
        let start = rest[..i]
            .char_indices()
            .rev()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(j, c)| j + c.len_utf8());
        let mut end =
            rest[i + 3..].find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`')).map_or(rest.len(), |j| i + 3 + j);
        // A closing bracket or quote the URL didn't open is the text's: `(see https://h/x)`. Each
        // kind is counted once, then as it is trimmed (linear in the token).
        let token = &rest[start..end];
        let mut balance = [('(', ')'), ('[', ']'), ('{', '}')].map(|(o, c)| (c, token.matches(o).count(), token.matches(c).count()));
        while let Some(c) = rest[i + 3..end].chars().last() {
            match balance.iter_mut().find(|(close, ..)| *close == c) {
                Some((_, opens, closes)) if *opens < *closes => *closes -= 1,
                Some(_) => break,
                None if matches!(c, '\u{201d}' | '\u{2019}' | '\u{bb}' | '\u{203a}') => {}
                None => break,
            }
            end -= c.len_utf8();
        }
        out.push_str(&rest[..start]);
        // A letter or digit outside ASCII right before the scheme (or in place of one: fullwidth
        // `ｈｔｔｐｓ://`) makes the scheme unclear: what follows is cut, not shown.
        if rest[..start].chars().last().is_some_and(|c| !c.is_ascii() && c.is_alphanumeric()) {
            out.push_str(&rest[start..i]);
            out.push_str("://…");
            rest = &rest[end..];
            continue;
        }
        if start == i {
            // No scheme: not a URL, nothing to redact.
            out.push_str(&rest[i..i + 3]);
            rest = &rest[i + 3..];
            continue;
        }
        out.push_str(&redact_one(&rest[start..i], &rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// One URL token, `scheme` its scheme.
fn redact_one(scheme: &str, token: &str) -> String {
    let opaque = format!("{scheme}://…");
    let Ok(u) = url::Url::parse(token) else { return opaque };
    // The user info ends at an '@' in the authority (up to the first '/', '\\', '?' or '#', as the
    // url crate splits it; '\\' is '/' for http(s)). Any other '@' anywhere, or more than one, and
    // which part is a secret can't be told: nothing past the scheme is shown. An npm scoped path
    // (`/@types/node`) is cut too; for error text, redacting more is the right mistake.
    let after = &token[scheme.len() + 3..];
    let auth = &after[..after.find(['/', '\\', '?', '#']).unwrap_or(after.len())];
    match (after.matches('@').count(), auth.contains('@')) {
        (0, _) | (1, true) => {}
        _ => return opaque,
    }
    let Some(host) = u.host_str() else { return opaque };
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    let mut shown = format!("{scheme}://{host}{port}{}", u.path());
    if u.query().is_some() || u.fragment().is_some() {
        shown.push_str("?…");
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #731: a plain token reads as is; anything that could read as words is quoted, its own quotes
    /// escaped, so it ends where it says.
    #[test]
    fn an_others_value_is_shown_bare_only_as_one_plain_token() {
        for plain in ["api.example.com", "/repos/acme/**", "GET", "*.example.com", "img@sha256:ab", "1g", "us-east-1"] {
            assert_eq!(shown(plain, 200), plain);
        }
        assert_eq!(shown("GET; no other reach", 200), r#""GET; no other reach""#);
        assert_eq!(shown("a, b", 200), r#""a, b""#);
        assert_eq!(shown(r#"x" and "y"#, 200), r#""x\" and \"y""#);
        assert_eq!(shown("", 200), r#""""#);
        // Look-alikes of a quote, and anything else outside printable ASCII, are escaped.
        assert_eq!(shown("x” and “y", 200), r#""x\u{201d} and \u{201c}y""#);
        for lookalike in ['\u{201d}', '\u{2033}', '\u{ab}', '\u{bb}', '\u{ff02}'] {
            let s = shown(&format!("a{lookalike}b"), 200);
            assert!(s.is_ascii() && s.starts_with('"') && s.ends_with('"') && s.matches('"').count() == 2, "{s}");
        }
    }

    /// #731 review: a list of others' values (a parent zone's images, models, forbid paths) is
    /// bounded in number, each value shown, never joined raw.
    #[test]
    fn an_others_list_is_bounded_and_each_value_shown() {
        let v: Vec<String> = ["a", "b, c", "d"].iter().map(|s| s.to_string()).collect();
        assert_eq!(shown_list(&v, 10, 8), r#"a, "b, c", d"#);
        assert_eq!(shown_list(&v, 10, 2), r#"a, "b, c", and 1 more"#);
        let many: Vec<String> = (0..1000).map(|i| format!("image-{i}")).collect();
        let s = shown_list(&many, 120, 8);
        assert!(s.ends_with("image-7, and 992 more") && s.len() < 200, "{s}");
        assert_eq!(shown_list(&[], 10, 8), "");
    }

    #[test]
    fn urls_lose_their_user_info_and_query() {
        assert_eq!(
            redact_urls("POST https://u:tok@collector.example:4318/v1/logs?key=s3cr3t#x: 401: nope"),
            "POST https://collector.example:4318/v1/logs?… 401: nope"
        );
        assert_eq!(redact_urls("get \"http://h/a?X-Amz-Signature=abc\": refused"), "get \"http://h/a?…\": refused");
        assert_eq!(redact_urls("no url here"), "no url here");
        for (url, shown) in [
            ("https://AKIA:wJal/K7x@host/x", "https://…"),
            ("https://AKIA:wJal/K7?x#y@host/x", "https://…"),
            ("https://AKIA:wJal/K7x@host/x?token=sec@ret", "https://…"),
            ("https://u:1234/56@host/x", "https://…"),
            ("s3://bucket:prefix/obj@v2", "s3://…"),
            ("https://u:p@host:9000/b/k?X-Amz-Signature=s", "https://host:9000/b/k?…"),
            ("https://h/p?token=sec@ret", "https://…"),
            ("https://h/p?sig=AbC/dEf@x.y&q=1", "https://…"),
            ("https://registry.npmjs.org/@types/node", "https://…"),
            ("https://tokn?k/@host/", "https://…"),
            ("https://ghp_tokn/en/@github.com/x", "https://…"),
            ("https://u:1234/56/@host/x", "https://…"),
            ("https://h/x?email=a@b.com", "https://…"),
            ("s3://bucket/key@v1", "s3://…"),
            ("http://localhost:7070/list", "http://localhost:7070/list"),
            ("http://[::1]/x", "http://[::1]/x"),
            ("http://[::1]/p?token=sec@ret", "http://…"),
            ("http://[2001:db8::1]/a?x=sec@ret", "http://…"),
            ("https://to?ken@host/", "https://…"),
            ("https://u:1234?56@host/x", "https://…"),
            ("https://u:1234#56@host/x", "https://…"),
            ("https://AKIA:1234\\56@host/x", "https://…"),
            ("https://u:p@host/@scope/pkg", "https://…"),
            ("https://h/p?q=1", "https://h/p?…"),
            ("https://a@b@host/x", "https://…"),
            ("https://", "https://…"),
        ] {
            assert_eq!(redact_urls(url), shown, "{url}");
        }
        // Text before the scheme, non-ASCII included, stays text; a bracket the URL didn't open is
        // the text's.
        assert_eq!(redact_urls("éhttps://us:pw@host/"), "éhttps://…", "a letter outside ASCII before it: unclear");
        assert_eq!(redact_urls("\u{201c}https://us:pw@host/\u{201d}"), "\u{201c}https://host/\u{201d}");
        assert_eq!(redact_urls("错误https://us:pw@host/"), "错误https://…");
        assert_eq!(
            redact_urls("x \u{ff48}\u{ff54}\u{ff54}\u{ff50}://us:pw@host/ y"),
            "x \u{ff48}\u{ff54}\u{ff54}\u{ff50}://… y",
            "fullwidth"
        );
        assert_eq!(redact_urls("错误: https://us:pw@host/"), "错误: https://host/", "text, then a space");
        assert_eq!(redact_urls("→ws://us:pw@host/"), "→ws://host/");
        assert_eq!(redact_urls("(see https://usr:pwd@host)"), "(see https://host/)");
        assert_eq!(redact_urls("[https://h/a_(b)]"), "[https://h/a_(b)]");
        assert_eq!(redact_urls("dial tcp 10.0.0.1:443: refused; s3://b/k"), "dial tcp 10.0.0.1:443: refused; s3://b/k");
    }

    #[test]
    fn escapes_and_bidi_never_survive() {
        let hostile = "ok\u{1b}[2K\u{1b}[1A\u{1b}]0;title\u{7}\u{9b}31m\u{202e}4R\u{2066}x\u{2069}\u{200b}\u{feff}\u{2028}\u{61c}\r";
        let s = strip(hostile);
        assert!(s.chars().all(|c| !is_unsafe(c)), "{s:?}");
        assert!(s.starts_with("ok "));
        assert_eq!(s.chars().count(), hostile.chars().count(), "one space per character removed");
        assert_eq!(clip("a\nb\u{1b}c", 100), "a ⏎ b c");
        assert_eq!(clip("abcdef", 3), "abc…");
        // Ordinary text, accents and other scripts are kept.
        assert_eq!(strip("café 東京 — ok"), "café 東京 — ok");
    }

    /// A megabyte body (what Litestream's reply is read up to) is redacted in linear time: closing
    /// brackets aren't recounted for each one trimmed.
    #[test]
    fn a_large_body_is_redacted_in_linear_time() {
        let body = format!("(https://u:p@h/{}", ")".repeat(1 << 20));
        let t = std::time::Instant::now();
        let out = redact_urls(&body);
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "took {:?}", t.elapsed());
        assert!(out.starts_with("(https://h/") && !out.contains("u:p"));
    }

    /// A small deterministic generator (xorshift): the crate has no property-test framework, and
    /// the same seeds run everywhere.
    struct Gen(u64);
    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        /// A character from all over Unicode, weighted towards the ones URLs and their parsing
        /// care about.
        fn char(&mut self) -> char {
            const SPECIAL: &[char] = &[
                ':',
                '/',
                '\\',
                '@',
                '?',
                '#',
                '(',
                ')',
                '[',
                ']',
                '{',
                '}',
                '"',
                '\'',
                '<',
                '>',
                '`',
                '%',
                '.',
                '+',
                '-',
                ' ',
                '\n',
                'é',
                '错',
                '→',
                '\u{201c}',
                '\u{201d}',
                '\u{200b}',
                '\u{202e}',
                '\u{1f600}',
            ];
            match self.below(4) {
                0 => SPECIAL[self.below(SPECIAL.len())],
                1 => (b'a' + self.below(26) as u8) as char,
                2 => char::from_u32(self.below(0x11_0000) as u32).unwrap_or('x'),
                _ => (b'0' + self.below(10) as u8) as char,
            }
        }
        fn text(&mut self, max: usize) -> String {
            (0..self.below(max + 1)).map(|_| self.char()).collect()
        }
        /// A secret-looking word: at least 4 characters, the URL's own delimiters (`/ ? # \\ @`)
        /// included, none that ends the URL token (whitespace, quotes).
        fn word(&mut self) -> String {
            const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/?#\\@";
            (0..4 + self.below(12)).map(|_| A[self.below(A.len())] as char).collect()
        }
    }

    /// On arbitrary text, redact_urls never panics; and a `scheme://USER:PASS@HOST/...` URL put
    /// anywhere in it never comes out with its user or password in it.
    #[test]
    fn redact_urls_never_panics_and_never_shows_user_info() {
        let mut g = Gen(0x9e37_79b9_7f4a_7c15);
        for _ in 0..20_000 {
            let s = g.text(40);
            let _ = redact_urls(&s);
            let _ = redact_urls(&format!("{s}https://{s}"));
        }
        for _ in 0..20_000 {
            let (user, pass) = (format!("U{}", g.word()), format!("P{}", g.word()));
            let scheme = ["https", "http", "s3", "ws", "git+ssh"][g.below(5)];
            let tail = g.text(12);
            let url = format!("{scheme}://{user}:{pass}@host{}.example/{tail}", g.below(100));
            let text = format!("{}{url}{}", g.text(10), g.text(10));
            let out = redact_urls(&text);
            assert!(!out.contains(&user) && !out.contains(&pass), "{text:?} came out as {out:?}");
        }
    }
}
