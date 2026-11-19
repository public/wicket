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
/// query and the fragment dropped, as tokens and signed parameters travel there. For error text
/// that is stored and shown (an exporter's or Litestream's last error).
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let end =
            rest[i + 3..].find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`')).map_or(rest.len(), |j| i + 3 + j);
        out.push_str(&rest[..i + 3]);
        // User info ends at the last '@' (a secret can hold '/', '?' or '#'), so the host starts
        // after it; with none, at once. Over-redacting a path that holds '@' is the safe mistake.
        let url = &rest[i + 3..end];
        let url = url.rsplit_once('@').map_or(url, |(_, after)| after);
        let auth_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        out.push_str(&url[..auth_end]);
        let tail = &url[auth_end..];
        let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
        out.push_str(&tail[..path_end]);
        if path_end < tail.len() {
            out.push_str("?…");
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
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
        assert_eq!(redact_urls("PUT https://AKIA:wJal/K7?x#y@host/x failed"), "PUT https://host/x failed", "a secret holding '/'");
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
