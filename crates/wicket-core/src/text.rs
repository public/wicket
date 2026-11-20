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

/// `s` with every URL in it cut to its scheme, host, port and path: user info (`user:pass@`), the
/// query and the fragment dropped, as tokens and signed parameters travel there. A URL that doesn't
/// parse, or where more than one '@' could end the user info, is cut to its scheme (`https://…`).
/// For error text that is stored and shown (an exporter's or Litestream's last error).
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let start = rest[..i].rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))).map_or(0, |j| j + 1);
        let end =
            rest[i + 3..].find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`')).map_or(rest.len(), |j| i + 3 + j);
        out.push_str(&rest[..start]);
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
    let after = &token[scheme.len() + 3..];
    let before_query = &after[..after.find(['?', '#']).unwrap_or(after.len())];
    let auth_end = before_query.find('/').unwrap_or(before_query.len());
    let (auth, path) = before_query.split_at(auth_end);
    // More than one '@' that could end the user info, or user info (a ':') with an '@' only later
    // in the path (`u:1234/56@host`): which part is the secret can't be told.
    if before_query.matches('@').count() > 1 || (!auth.contains('@') && auth.contains(':') && path.contains('@')) {
        return opaque;
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
            ("https://h/p?token=sec@ret", "https://h/p?…"),
            ("https://h/p?sig=AbC/dEf@x.y&q=1", "https://h/p?…"),
            ("https://registry.npmjs.org/@types/node", "https://registry.npmjs.org/@types/node"),
            ("https://h/x?email=a@b.com", "https://h/x?…"),
            ("s3://bucket/key@v1", "s3://bucket/key@v1"),
            ("http://localhost:7070/list", "http://localhost:7070/list"),
            ("http://[::1]/x", "http://[::1]/x"),
            ("http://[::1]/p?token=sec@ret", "http://[::1]/p?…"),
            ("http://[2001:db8::1]/a?x=sec@ret", "http://[2001:db8::1]/a?…"),
            ("https://a@b@host/x", "https://…"),
            ("https://", "https://…"),
        ] {
            assert_eq!(redact_urls(url), shown, "{url}");
        }
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
}
