//! Writes the seed corpora (`corpus/<target>/`), taken from the crates' tests: `cargo run --example
//! seeds` in `fuzz/`. Deterministic where the inputs are (the feed's frames are signed with the
//! harness's fixed keys); rerun it when a format changes.

use std::path::Path;
use wicket_fuzz::chan::{Frame, Msg, CONTROL_TUNNEL_BIT, PROTOCOL, TUNNEL_BIT};

fn write(target: &str, name: &str, data: &[u8]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), data).unwrap();
}

fn main() {
    egress();
    gateway();
    chan();
    feed();
    token();
    manifest();
    store();
    git();
    canon();
    time();
}

const OLD: &str = "0000000000000000000000000000000000000000";
const NEW: &str = "1111111111111111111111111111111111111111";

fn pkt(s: &str) -> Vec<u8> {
    let mut v = format!("{:04x}", s.len() + 4).into_bytes();
    v.extend_from_slice(s.as_bytes());
    v
}

fn egress() {
    let t = |name: &str, head: &str| {
        let mut v = vec![1u8];
        v.extend_from_slice(head.as_bytes());
        write("egress", name, &v);
    };
    let p = |name: &str, head: &str| {
        let mut v = vec![0u8];
        v.extend_from_slice(head.as_bytes());
        write("egress", name, &v);
    };
    t("get", "GET /repos/acme/app/issues?state=open HTTP/1.1\r\nhost: fuzz.example\r\naccept: */*\r\n\r\n");
    t(
        "pipelined",
        "GET /a HTTP/1.1\r\nhost: fuzz.example\r\n\r\nGET /b/../c HTTP/1.1\r\nhost: fuzz.example\r\n\r\nHEAD /d HTTP/1.1\r\n\r\n",
    );
    t(
        "post-length",
        "POST /v1/messages HTTP/1.1\r\nhost: fuzz.example\r\ncontent-type: application/json\r\ncontent-length: 13\r\n\r\n{\"a\":[1,2,3]}",
    );
    t("post-chunked", "POST /upload HTTP/1.1\r\nhost: fuzz.example\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nx-trailer: t\r\n\r\nGET /after HTTP/1.1\r\nhost: fuzz.example\r\n\r\n");
    t("cl-te", "POST /a HTTP/1.1\r\nhost: fuzz.example\r\ncontent-length: 44\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nhost: fuzz.example\r\n\r\n");
    t("te-cl", "POST /a HTTP/1.1\r\nhost: fuzz.example\r\ntransfer-encoding: chunked\r\ncontent-length: 4\r\n\r\n2c\r\nGET /smuggled HTTP/1.1\r\nhost: fuzz.example\r\n\r\n\r\n0\r\n\r\n");
    t(
        "te-obfuscated",
        "POST /a HTTP/1.1\r\nhost: fuzz.example\r\ntransfer-encoding: xchunked\r\ntransfer-encoding : chunked\r\n\r\n0\r\n\r\n",
    );
    t("two-lengths", "POST /a HTTP/1.1\r\nhost: fuzz.example\r\ncontent-length: 3\r\ncontent-length: 30\r\n\r\nabcGET /x HTTP/1.1\r\n\r\n");
    t("get-with-body", "GET /a HTTP/1.1\r\nhost: fuzz.example\r\ncontent-length: 5\r\n\r\nhello");
    t("host-mismatch", "GET /a HTTP/1.1\r\nhost: other.example\r\n\r\n");
    t("absolute-in-tunnel", "GET http://other.example/x HTTP/1.1\r\nhost: fuzz.example\r\n\r\n");
    t("encoded-path", "GET /a/%2e%2e/%2Fb//c/./d%00 HTTP/1.1\r\nhost: fuzz.example\r\n\r\n");
    t("override", "POST /a HTTP/1.1\r\nhost: fuzz.example\r\nx-http-method-override: DELETE\r\ncontent-length: 0\r\n\r\n");
    t("trace", "TRACE / HTTP/1.1\r\nhost: fuzz.example\r\n\r\n");
    t("http10", "GET /a HTTP/1.0\r\n\r\n");
    t("expect", "PUT /a HTTP/1.1\r\nhost: fuzz.example\r\nexpect: 100-continue\r\ncontent-length: 3\r\n\r\nabc");
    t("upgrade", "GET /ws HTTP/1.1\r\nhost: fuzz.example\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n");
    // A git push: discovery, then the upload with its pkt-lines (crates/wicket-proxy/tests/git_push.rs).
    let mut body = Vec::new();
    body.extend(pkt(&format!("{OLD} {NEW} refs/heads/main\0report-status side-band-64k\n")));
    body.extend(pkt(&format!("{OLD} {NEW} refs/heads/other\n")));
    body.extend(b"0000PACK\0\0\0\x02\0\0\0\0");
    let mut push = format!(
        "GET /acme/app.git/info/refs?service=git-receive-pack HTTP/1.1\r\nhost: fuzz.example\r\n\r\nPOST /acme/app.git/git-receive-pack HTTP/1.1\r\nhost: fuzz.example\r\ncontent-type: application/x-git-receive-pack-request\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    push.extend(&body);
    let mut v = vec![1u8];
    v.extend(&push);
    write("egress", "git-push", &v);
    p("plain-get", "GET http://plain.example/a?b=c HTTP/1.1\r\nhost: plain.example\r\n\r\n");
    p("plain-post", "POST http://plain.example/form HTTP/1.1\r\nhost: plain.example\r\ncontent-length: 3\r\n\r\nabcGET http://plain.example/next HTTP/1.1\r\n\r\n");
    p("plain-port", "GET http://plain.example:8080/a HTTP/1.1\r\n\r\n");
    p("plain-ip", "GET http://127.0.0.1/a HTTP/1.1\r\n\r\n");
    p("plain-userinfo", "GET http://user@plain.example/a HTTP/1.1\r\n\r\n");
    p("connect", "CONNECT fuzz.example:443 HTTP/1.1\r\nhost: fuzz.example:443\r\n\r\n\x16\x03\x01\x00\x05hello");
    p("connect-other", "CONNECT other.example:443 HTTP/1.1\r\n\r\n");
    p("connect-port", "CONNECT fuzz.example:22 HTTP/1.1\r\n\r\n");
    p("origin-form", "GET /a HTTP/1.1\r\nhost: plain.example\r\n\r\n");
}

fn gateway() {
    let w = |name: &str, s: &str| write("gateway", name, s.as_bytes());
    w("initialize", r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#);
    w("list", r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#);
    w("ping", r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#);
    w("notification", r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    w("batch", r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
    w("nested", &format!("{}{}", "[".repeat(200), "]".repeat(200)));
    let calls: &[(&str, &str)] = &[
        ("await_grant", r#"{"request_id":"r-1","timeout_seconds":5}"#),
        ("pending_requests", "{}"),
        ("whoami", "{}"),
        ("send_message", r#"{"to":"parent","kind":"note","body":{"text":"hi"}}"#),
        ("await_message", r#"{"timeout_seconds":1}"#),
        ("spawn", r#"{"zone":{"name":"c","reach":[]},"image":"img:a","task":"t"}"#),
        ("spawn_agent", r#"{"name":"x","task":"t"}"#),
        ("request_access", r#"{"url":"https://api.example.com/v1/x","scope":"prefix","reason":"needed"}"#),
        ("decide", r#"{"request_id":"r-1","approve":true,"uses":3,"ttl_seconds":60}"#),
        ("expose", r#"{"port":8080,"name":"web"}"#),
        ("connect", r#"{"box":"b1","port":80}"#),
        ("link", r#"{"from":"a","to":"b","port":443}"#),
        ("unlink", r#"{"link":"l-1"}"#),
        ("links", "{}"),
        ("request_capacity", r#"{"vcpus":2,"memory_mib":1024,"reason":"build"}"#),
        ("request_update", r#"{"reason":"x"}"#),
        ("finish", "{}"),
        ("hibernate", "{}"),
        ("nope", "[]"),
    ];
    for (name, args) in calls {
        w(
            &format!("call-{name}"),
            &format!(r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#),
        );
    }
    let mut raw = vec![0u8];
    raw.extend_from_slice(
        b"POST /mcp HTTP/1.1\r\ncontent-length: 46\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}GET / HTTP/1.1\r\n\r\n",
    );
    write("gateway", "raw-pipelined", &raw);
}

fn chan() {
    let op =
        wicket_core::Op::egress(&wicket_core::TenantId::single(), &wicket_core::RunId("run_a".into()), "z", "GET", "api.example.com", "/x");
    let a64 = "a".repeat(64);
    let mut frames = vec![
        Frame::Msg(Msg::Hello {
            node: "n1".into(),
            version: "0.0.1".into(),
            build: "ab".repeat(32),
            proto: PROTOCOL,
            observer: false,
            nonce: "A".repeat(43),
            scope: "run_a".into(),
        }),
        Frame::Msg(Msg::Ask {
            id: 7,
            run: "run_a".into(),
            op: Box::new(op),
            why: "out of reach".into(),
            who: None,
            queued: Some(("q-1".into(), 5)),
            prefix: true,
        }),
        Frame::Msg(Msg::ImageHave { id: 3, digest: format!("sha256:{a64}") }),
        Frame::Msg(Msg::PutImage {
            stream: TUNNEL_BIT | CONTROL_TUNNEL_BIT | 5,
            digest: format!("sha256:{a64}"),
            name: Some(format!("docker.io/library/x@sha256:{a64}")),
        }),
        Frame::Msg(Msg::ImagePut { stream: TUNNEL_BIT | CONTROL_TUNNEL_BIT | 5, error: Some("tampered".into()) }),
        Frame::Msg(Msg::ImagePulled { id: 9, error: None }),
        Frame::Data { stream: TUNNEL_BIT | 4, offset: 1 << 40, bytes: b"hello\0world".to_vec() },
        Frame::Data { stream: 2, offset: 0, bytes: vec![] },
        Frame::Feed(br#"{"t":"fresh","jws":"a.b.c"}"#.to_vec()),
    ];
    // Messages of the later protocol versions, from their JSON (what a peer actually sends).
    for j in [
        r#"{"m":"budget_slice","run":"run_a","slice":{"requests":3,"output_tokens":100,"input_tokens":7}}"#,
        r#"{"m":"secret_fetch","id":1,"run":"run_a","name":"gh"}"#,
        r#"{"m":"spent","run":"run_a","spent":{"requests":1,"output_tokens":2}}"#,
        r#"{"m":"close","stream":9223372036854775813}"#,
        r#"{"m":"kill","run":"run_a"}"#,
        r#"{"m":"ack","stream":2,"upto":10}"#,
    ] {
        if let Ok(m) = serde_json::from_str::<Msg>(j) {
            frames.push(Frame::Msg(m));
        }
        let mut body = vec![1u8];
        body.extend_from_slice(j.as_bytes());
        write("chan", &format!("body-{}", &j[6..j[6..].find('"').unwrap() + 6]), &body);
    }
    for (i, f) in frames.iter().enumerate() {
        write("chan", &format!("frame-{i:02}"), &f.encode());
    }
    let all: Vec<u8> = frames.iter().flat_map(Frame::encode).collect();
    write("chan", "stream", &all);
}

fn feed() {
    use wicket_fuzz::feed::*;
    let dir = std::env::temp_dir().join(format!("wicket-fuzz-seeds-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (mut p, frames) = publisher(&dir);
    let line = |f: &wicket_feed::Frame| format!("R{}", f.to_line());
    let catch: String = frames.iter().map(line).collect();
    write("feed", "catch-up-again", catch.as_bytes());
    // Frames the node hasn't seen: raw, and as payloads to sign.
    let fresh = p.statement(T0 + 2);
    let snap = p.snapshot(T0 + 3);
    let mut signed = String::new();
    for (tag, f) in [("F", &fresh), ("S", &snap), ("K", &frames[0])] {
        let v: serde_json::Value = wicket_feed::jws::payload_unverified(&f.jws).unwrap();
        signed.push_str(&format!("{tag}{v}\nT1000\n"));
    }
    write("feed", "signed", signed.as_bytes());
    write("feed", "raw-new", format!("{}T5000\n{}", line(&fresh), line(&snap)).as_bytes());
    write("feed", "garbage", b"R{\"t\":\"key\",\"jws\":\"..\"}\nR{}\nT-99999999\nF{\"x\":1}\n");
    let _ = std::fs::remove_dir_all(&dir);
}

fn token() {
    let w = |name: &str, s: &str| write("token", name, s.as_bytes());
    // From crates/wicket-authz/tests/hostile.rs.
    w(
        "tp-ok",
        r#"Tapproved("g", "h", "GET", "/") <- time($t), $t <= 2030-01-01T00:00:00Z, box("b0/b1/b2"), epoch(3), uses_left("g", $n), $n > 0;"#,
    );
    w("check-host", "Acheck if host(\"api.github.com\");");
    w("check-path", "Acheck if path($p), $p.matches(\"^/repos/acme/.*$\");");
    w("rule", "Aok($x) <- host($x);");
    w("check-all", "Acheck all host($h), $h == \"a\";");
    w("two", "Acheck if host(\"a\") or host(\"b\");\n%%\nAcheck if method(\"GET\");");
    w("time", "Acheck if time($t), $t <= 2030-01-01T00:00:00Z;");
    w("fact", "Atenant(\"other\");");
    w("raw", "B\x00\x01\x02");
}

fn manifest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for f in [
        "demo.yaml",
        "hello-github.yaml",
        "mock-github.yaml",
        "program-repo-stats.yaml",
        "remote-control-box.yaml",
        "remote-driven-box.yaml",
        "links/demo.yaml",
        "acp-claude/manifest.yaml",
    ] {
        if let Ok(s) = std::fs::read_to_string(root.join("examples").join(f)) {
            write("manifest", &f.replace('/', "-"), s.as_bytes());
        }
    }
    let parent = "task: t\nagent: { name: a }\nzone:\n  name: p\n  llm: {}\n  reach:\n    - { host: api.github.com, methods: [GET, POST], paths: [\"/repos/acme/**\"] }\n    - { host: \"*.example.com\", methods: [GET], paths: [\"/v1/*\"] }\n  forbid:\n    - { host: api.github.com, paths: [\"/repos/acme/*/hooks\"] }\n";
    let child = "task: t\nagent: { name: a }\nzone:\n  name: c\n  llm: {}\n  reach:\n    - { host: api.github.com, methods: [GET], paths: [\"/repos/acme/app/**\"] }\n";
    let wider = "task: t\nagent: { name: a }\nzone:\n  name: c\n  llm: {}\n  reach:\n    - { host: api.github.com, methods: [GET], paths: [\"/repos/**\"] }\n";
    write("manifest", "pair-within", format!("{parent}{}{child}", wicket_fuzz::manifest::SEPARATOR).as_bytes());
    write("manifest", "pair-wider", format!("{parent}{}{wider}", wicket_fuzz::manifest::SEPARATOR).as_bytes());
}

fn store() {
    let w = |name: &str, s: &str| write("store", name, s.as_bytes());
    w("tree", "bhello\nb#!/bin/sh\nb/etc/passwd\nt\nf 0644 1700000000 = 0 a.txt;f 0750 0 = 1 run.sh;l 0777 0 = 2 out\nt\nd 0755 1600000000 0 3 sub;f 0644 0 = 0 top\n");
    w("readonly", "bx\nt\nf 0444 0 = 0 x\nt\nd 0555 0 0 1 ro;d 0000 0 0 1 none\n");
    w("tampered", "bhello\nt\nf 0644 0 = 0 a\nx0\n");
    w("escape-link", "b../outside\nbpwned\nt\nl 0777 0 = 0 link;f 0644 0 = 1 link2\nt\nd 0755 0 0 2 sub;l 0777 0 = 0 sub2\n");
    w("bad-names", "bx\nt\nf 0644 0 = 0 ..;f 0644 0 = 0 .;f 0644 0 = 0 a/b\n");
    w("wrong-size", "bhello\nt\nf 0644 0 3 0 a;f 0644 0 9 0 b\n");
    w("times", "bx\nt\nf 0644 -1 = 0 a;f 0644 99999999999 = 0 b\n");
    w("decode", "Dwicket-tree-v1\nf 0644 0 5 sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 a\n");
}

fn git() {
    let w = |name: &str, s: &str| write("git", name, s.as_bytes());
    w("discovery", "GET /acme/app.git/info/refs?service=git-receive-pack");
    w("upload", "POST /acme/app.git/git-receive-pack");
    w("fetch", "GET /acme/app.git/info/refs?service=git-upload-pack");
    w("upper", "POST /ACME/App.Git/Git-Receive-Pack");
    w("root", "POST /git-receive-pack");
    w("encoded", "POST /a/%67it-receive-pack");
}

/// Hosts and paths from the conformance pack (#361) and canon.rs's own tests.
fn canon() {
    let w = |name: &str, s: &str| write("canon", name, s.as_bytes());
    for (name, s) in [
        ("host", "api.github.com"),
        ("host-upper-dot", "API.GitHub.com."),
        ("ip-decimal", "2130706433"),
        ("ip-octal", "0177.0.0.1"),
        ("ip-hex", "0x7f.1"),
        ("ip-mapped", "[::ffff:127.0.0.1]"),
        ("host-escape", "exa%6dple.com"),
        ("host-idn", "b\u{fc}cher.example"),
        ("path", "/repos/acme/app/issues?state=open"),
        ("path-dots", "/a/%2e%2e/b"),
        ("path-encoded-slash", "/a%2Fb"),
        ("path-matrix", "/a;x/b"),
        ("path-encoded-slash", "/@scope%2fname"),
        ("path-escape-lower", "/a%7bb"),
        ("path-unreserved-escape", "/%41"),
        ("path-trailing", "/a/b/"),
    ] {
        w(name, s);
    }
}

/// Durations as manifests, operator files and flags write them, and times as `--at` and wicket
/// print them (`wicket_core::time`'s tests, #437).
fn time() {
    let w = |name: &str, s: &str| write("time", name, s.as_bytes());
    for (name, s) in [
        ("zero", "0"),
        ("timeout", "30m"),
        ("ttl", "24h"),
        ("terms", "1h 30m"),
        ("terms-unspaced", "1d2h3m4s"),
        ("fraction", "1.5h"),
        ("words", "5 minutes"),
        ("small", "1ms 2us 3ns"),
        ("micro-sign", "1\u{b5}s"),
        ("months-years", "1M 2years"),
        ("largest", "18446744073709551615s"),
        ("carry", "18446744073709551615s 500ms 500ms"),
        ("bad-unit", "1x"),
        ("no-unit", "3600"),
        ("time", "2026-11-12T19:05:05Z"),
        ("time-space", "2026-11-12 19:05:05"),
        ("time-offset", "2026-11-12T19:05:05.123456789+00:00"),
        ("time-leap", "2024-02-29T23:59:60Z"),
        ("time-last", "9999-12-31T23:59:59Z"),
        ("time-zz", "2026-11-12T19:05:05ZZ"),
    ] {
        w(name, s);
    }
}
