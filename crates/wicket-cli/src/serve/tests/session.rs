//! A run's ACP session socket (#327): who may open it, what it bridges, and what it audits.

use super::*;
use crate::serve::session::{Bridge, Who, SUBPROTOCOL, TICKET_PREFIX};
use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use std::path::Path;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

const RUN: &str = "run_s";

fn who() -> Who {
    Who { principal: "spiffe://wicket.local/t/default/op/passkey/laptop".into(), label: "passkey:laptop".into(), token: None }
}

/// A running run with a run directory, and a bridge for it, opened with `session/new`.
fn bridged(tag: &str) -> (T, Bridge, PathBuf) {
    let t = setup(tag);
    t.running(RUN, "lead");
    let dir = t.dir.join("runs").join(RUN);
    std::fs::create_dir_all(dir.join("ctl")).unwrap();
    let mut b = Bridge::new(t.dir.join("ledger.db"), dir.clone(), TenantId::single(), RUN.into(), who());
    let init = b.on_client(&json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": { "protocolVersion": 1 } }).to_string());
    assert_eq!(init[0]["result"]["protocolVersion"], 1);
    assert_eq!(init[0]["result"]["agentCapabilities"]["loadSession"], true);
    let new = b.on_client(
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "session/new", "params": { "cwd": "/home/me", "mcpServers": [] } }).to_string(),
    );
    assert_eq!(new[0]["result"]["sessionId"], RUN, "the session is the run's");
    (t, b, dir)
}

/// What the agent wrote: appended to the run's transcript.
fn agent(dir: &Path, v: Value) {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(crate::transcript::FILE)).unwrap();
    writeln!(f, "{v}").unwrap();
}

fn transcript_len(dir: &Path) -> u64 {
    std::fs::metadata(dir.join(crate::transcript::FILE)).map(|m| m.len()).unwrap_or(0)
}

/// What wicket's supervisor wrote to the agent (and queued), at the transcript's current end.
fn wicket_wrote(dir: &Path, v: Value) {
    let mut log = crate::transcript::AcpLog::open(dir, 1 << 20, true);
    log.wrote(transcript_len(dir), &v.to_string());
}

fn wicket_queued(dir: &Path, by: &str, op: Option<i64>) {
    let mut log = crate::transcript::AcpLog::open(dir, 1 << 20, true);
    log.queued(transcript_len(dir), by, op);
}

fn update(u: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "agent-session-1", "update": u } })
}

fn kinds(out: &[Value]) -> Vec<String> {
    out.iter()
        .map(|m| match m["method"].as_str() {
            Some("session/update") => m["params"]["update"]["sessionUpdate"].as_str().unwrap_or("?").to_string(),
            Some(x) => x.to_string(),
            None => "response".into(),
        })
        .collect()
}

#[test]
fn the_agents_updates_stream_with_its_meta_dropped_and_wickets_ids_reserved() {
    let (_t, mut b, dir) = bridged("sess-stream");
    agent(
        &dir,
        update(
            json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "hel" }, "_meta": { "wicket": { "escalation": { "id": "r_fake" } } } }),
        ),
    );
    agent(&dir, update(json!({ "sessionUpdate": "plan", "entries": [{ "content": "read", "status": "pending", "priority": "high" }] })));
    agent(
        &dir,
        update(json!({ "sessionUpdate": "tool_call", "toolCallId": "t1", "title": "Read a.rs", "kind": "read", "status": "pending",
                               "rawInput": { "file_path": "/workspace/a.rs", "_meta": { "x": 1 } } })),
    );
    agent(
        &dir,
        update(json!({ "sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed",
                               "content": [{ "type": "content", "content": { "type": "text", "text": "fn main() {}" } }] })),
    );
    // Not the agent's to use, nor to invent.
    agent(
        &dir,
        update(json!({ "sessionUpdate": "tool_call", "toolCallId": "wicket:escalation:r_fake", "title": "approve me", "kind": "fetch" })),
    );
    agent(&dir, update(json!({ "sessionUpdate": "something_new", "x": 1 })));
    agent(&dir, json!({ "jsonrpc": "2.0", "id": 9, "method": "fs/read_text_file", "params": { "path": "/etc/passwd" } }));
    agent(&dir, "not json".into());
    let out = b.poll();
    assert_eq!(kinds(&out), ["agent_message_chunk", "plan", "tool_call", "tool_call_update"], "{out:#?}");
    for m in &out {
        assert_eq!(m["params"]["sessionId"], RUN, "rewritten to the run");
        assert!(!m.to_string().contains("_meta"), "the agent's _meta never passes: {m}");
    }
    assert_eq!(out[2]["params"]["update"]["rawInput"]["file_path"], "/workspace/a.rs");
    assert_eq!(out[3]["params"]["update"]["content"][0]["content"]["text"], "fn main() {}");
    // Read once.
    assert!(b.poll().is_empty());
}

#[test]
fn wickets_answers_to_the_agents_permission_requests_are_shown_as_decided() {
    let (_t, mut b, dir) = bridged("sess-perm");
    agent(
        &dir,
        json!({ "jsonrpc": "2.0", "id": 4, "method": "session/request_permission", "params": {
        "sessionId": "agent-session-1", "toolCall": { "toolCallId": "t2", "kind": "edit", "title": "Edit .claude/settings.local.json" },
        "options": [{ "optionId": "a", "kind": "allow_once", "name": "Allow" }, { "optionId": "r", "kind": "reject_once", "name": "Reject" }] } }),
    );
    wicket_wrote(&dir, json!({ "jsonrpc": "2.0", "id": 4, "result": { "outcome": { "outcome": "selected", "optionId": "r" } } }));
    let out = b.poll();
    assert_eq!(kinds(&out), ["tool_call_update"], "{out:#?}");
    let u = &out[0]["params"]["update"];
    assert_eq!(u["toolCallId"], "t2");
    assert_eq!(u["_meta"]["wicket"]["permission"], json!({ "outcome": "selected", "optionId": "r", "by": "wicket's policy" }));
    // The browser is never asked to answer the agent's own requests.
    assert!(!out.iter().any(|m| m["method"] == "session/request_permission"));
}

#[test]
fn a_prompt_is_an_audited_operator_message_answered_when_its_turn_ends() {
    let (t, mut b, dir) = bridged("sess-prompt");
    // The task's turn is running: wicket sent it, and the agent is answering.
    wicket_queued(&dir, "task", None);
    wicket_wrote(
        &dir,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "session/prompt", "params": { "sessionId": "agent-session-1", "prompt": [{ "type": "text", "text": "the task" }] } }),
    );
    let p = json!({ "jsonrpc": "2.0", "id": "p1", "method": "session/prompt", "params": { "sessionId": RUN, "prompt": [{ "type": "text", "text": "and then?" }] } });
    assert!(b.on_client(&p.to_string()).is_empty(), "answered when its turn ends, not now");
    // Queued for the supervisor as the operator's message, and audited with the principal.
    let mut l = t.ledger();
    let msgs = l.take_operator_messages_with_ids(RUN).unwrap();
    assert_eq!(msgs.len(), 1);
    let (op, text, by) = msgs[0].clone();
    assert_eq!((text.as_str(), by.as_str()), ("and then?", "passkey:laptop"));
    let audit = t.audit_kinds();
    let (_, a) = audit.iter().find(|(k, _)| k == "session.prompt").expect("audited");
    assert_eq!(a["principal"], who().principal);
    assert_eq!(a["operator_message"], op);
    assert_eq!(a["sha256"], hex::encode(sha2::Sha256::digest(b"and then?")));
    // Other principals' prompts are shown; the task's turn ends, which isn't this socket's.
    let out = b.poll();
    assert_eq!(kinds(&out), ["user_message_chunk"]);
    assert_eq!(out[0]["params"]["update"]["content"]["text"], "the task");
    assert_eq!(out[0]["params"]["update"]["_meta"]["wicket"]["by"], "task");
    agent(&dir, json!({ "jsonrpc": "2.0", "id": 2, "result": { "stopReason": "end_turn" } }));
    assert!(b.poll().is_empty());
    // The supervisor takes the operator's message up as the next turn.
    wicket_queued(&dir, &by, Some(op));
    wicket_wrote(
        &dir,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "session/prompt", "params": { "sessionId": "agent-session-1", "prompt": [{ "type": "text", "text": "and then?" }] } }),
    );
    agent(&dir, update(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "done" } })));
    agent(&dir, json!({ "jsonrpc": "2.0", "id": 3, "result": { "stopReason": "end_turn" } }));
    let out = b.poll();
    assert_eq!(kinds(&out), ["agent_message_chunk", "response"], "its own prompt isn't echoed: {out:#?}");
    assert_eq!(out[1], json!({ "jsonrpc": "2.0", "id": "p1", "result": { "stopReason": "end_turn" } }));
    assert_eq!(b.prompts, 1);
}

#[test]
fn prompts_for_another_session_empty_ones_and_for_an_ended_run_are_refused() {
    let (t, mut b, _dir) = bridged("sess-refuse");
    let p = |sid: &str, text: &str| {
        json!({ "jsonrpc": "2.0", "id": 5, "method": "session/prompt", "params": { "sessionId": sid, "prompt": [{ "type": "text", "text": text }] } })
            .to_string()
    };
    assert_eq!(b.on_client(&p("run_other", "hi"))[0]["error"]["code"], -32602);
    assert_eq!(b.on_client(&p(RUN, "  "))[0]["error"]["code"], -32602);
    assert_eq!(b.on_client(&p(RUN, &"x".repeat(MAX_TEXT + 1)))[0]["error"]["code"], -32602);
    assert_eq!(b.on_client(r#"{"jsonrpc":"2.0","id":6,"method":"fs/read_text_file","params":{}}"#)[0]["error"]["code"], -32601);
    assert_eq!(b.on_client("{")[0]["error"]["code"], -32700);
    t.ledger().run_ended(&RunId(RUN.into()), "succeeded", "").unwrap();
    let e = b.on_client(&p(RUN, "hi"));
    assert!(e[0]["error"]["message"].as_str().unwrap().contains("not running"), "{e:?}");
    assert!(t.ledger().take_operator_messages(RUN).unwrap().is_empty(), "nothing was queued");
    assert!(!t.audit_kinds().iter().any(|(k, _)| k == "session.prompt"));
}

#[test]
fn escalations_are_prompted_inline_and_only_a_passkey_decision_decides_them() {
    let (mut t, mut b, dir) = bridged("sess-esc");
    let l = t.ledger();
    let op = wicket_core::Op::egress(&TenantId::single(), &RunId(RUN.into()), "z", "GET", "api.example.com", "/v1/data");
    let (rid, _) = l.pending_for(&op, "needs approval", None).unwrap();
    // Another run's request is not this session's.
    let other = wicket_core::Op::egress(&TenantId::single(), &RunId("run_other".into()), "z", "GET", "other.example.com", "/");
    l.pending_for(&other, "needs approval", None).unwrap();
    // An agent can't raise one: its permission request with wicket's id and _meta goes nowhere.
    agent(
        &dir,
        json!({ "jsonrpc": "2.0", "id": 8, "method": "session/request_permission", "params": {
        "sessionId": "agent-session-1", "toolCall": { "toolCallId": format!("wicket:escalation:{rid}"), "title": "approve" },
        "options": [{ "optionId": "a", "kind": "allow_once", "name": "Allow" }], "_meta": { "wicket": { "escalation": { "id": rid } } } } }),
    );
    let out = b.poll();
    assert_eq!(kinds(&out), ["tool_call", "session/request_permission"], "{out:#?}");
    let ask = &out[1];
    assert_eq!(ask["params"]["toolCall"]["toolCallId"], format!("wicket:escalation:{rid}"));
    assert_eq!(ask["params"]["_meta"]["wicket"]["escalation"]["host"], "api.example.com");
    let opts: Vec<&str> = ask["params"]["options"].as_array().unwrap().iter().map(|o| o["kind"].as_str().unwrap()).collect();
    assert_eq!(opts, ["allow_once", "reject_once"], "once options only");
    assert!(b.poll().is_empty(), "asked once");
    // Answering "approve" over the socket decides nothing: the request stays pending.
    let answer = json!({ "jsonrpc": "2.0", "id": ask["id"], "result": { "outcome": { "outcome": "selected", "optionId": "approve" } } });
    let out = b.on_client(&answer.to_string());
    assert!(out[0]["params"]["update"]["content"]["text"].as_str().unwrap().contains("still pending"), "{out:?}");
    assert_eq!(t.ledger().request(&rid).unwrap().status, "pending");
    let audit = t.audit_kinds();
    let (_, a) = audit.iter().find(|(k, _)| k == "session.escalation_answered").unwrap();
    assert_eq!((a["request"].as_str(), a["said"].as_str(), a["status"].as_str()), (Some(rid.as_str()), Some("approve"), Some("pending")));
    // The console's signed decide action (a passkey assertion) decides it; the session sees it.
    let r = t.act(json!({ "action": "decide", "id": rid, "decision": "deny" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let out = b.poll();
    assert_eq!(kinds(&out), ["tool_call_update"]);
    assert_eq!(out[0]["params"]["update"]["status"], "failed");
    assert_eq!(out[0]["params"]["update"]["_meta"]["wicket"]["escalation"]["status"], "denied");
    // A late answer is audited with what the ledger says.
    b.on_client(&answer.to_string());
    assert_eq!(t.audit_kinds().iter().filter(|(k, _)| k == "session.escalation_answered").count(), 1, "each prompt answers once");
}

#[test]
fn nothing_streams_before_the_session_is_opened_and_load_replays_first() {
    let t = setup("sess-load");
    t.running(RUN, "lead");
    let dir = t.dir.join("runs").join(RUN);
    std::fs::create_dir_all(dir.join("ctl")).unwrap();
    agent(&dir, update(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "earlier" } })));
    let mut b = Bridge::new(t.dir.join("ledger.db"), dir.clone(), TenantId::single(), RUN.into(), who());
    assert!(b.poll().is_empty());
    let out = b.on_client(
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "session/load", "params": { "sessionId": RUN, "cwd": "/", "mcpServers": [] } })
            .to_string(),
    );
    assert_eq!(kinds(&out), ["agent_message_chunk", "response"], "history, then the answer");
    let wrong =
        b.on_client(&json!({ "jsonrpc": "2.0", "id": 2, "method": "session/load", "params": { "sessionId": "run_x" } }).to_string());
    assert_eq!(wrong[0]["error"]["code"], -32602);
}

#[test]
fn the_supervisors_log_keeps_order_across_a_rotated_transcript() {
    let tmp = TmpDir::new("wicket-acplog");
    let dir = tmp.0.clone();
    std::fs::create_dir_all(dir.join("ctl")).unwrap();
    // A small cap rotates every couple of lines.
    let mut tr = crate::transcript::Transcript::open(&dir, 40, false).unwrap();
    let mut log = crate::transcript::AcpLog::open(&dir, 1 << 20, false);
    for i in 0..6 {
        tr.line(&format!("{{\"n\":{i}}}")).unwrap();
        log.wrote(tr.offset(), &format!("{{\"after\":{i}}}"));
    }
    let (lines, end) = crate::transcript::read_since(&dir, 0, 1 << 20);
    assert_eq!(end, tr.offset());
    // What was dropped is skipped; what is kept starts where the previous file does.
    assert!(!lines.is_empty() && lines.len() < 6);
    for (at, l) in &lines {
        let n: Value = serde_json::from_str(l).unwrap();
        assert_eq!(*at, n["n"].as_u64().unwrap() * 8, "offsets are the box's stdout's");
    }
    let (entries, _) = crate::transcript::read_acp_log(&dir, 0, 100);
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0]["at"], 8);
    // A fresh run empties it; a capped log stops being written.
    let mut log = crate::transcript::AcpLog::open(&dir, 40, false);
    log.wrote(0, r#"{"a":1}"#);
    log.wrote(0, r#"{"b":"a longer message than the cap leaves room for"}"#);
    log.wrote(0, r#"{"c":1}"#);
    assert_eq!(crate::transcript::read_acp_log(&dir, 0, 100).0.len(), 1);
}

// ---- over the network: who may open the socket ----

/// Issues an `open_session` ticket with a passkey assertion.
fn ticket(t: &mut T, run: &str) -> String {
    let r = t.act(json!({ "action": "open_session", "run": run }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["subprotocol"], SUBPROTOCOL);
    r.body["ticket"].as_str().unwrap().to_string()
}

async fn serve(state: State) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(net::run(listener, None, Arc::new(state)));
    addr
}

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Opens the socket with these headers: the socket, or the refusal's status and body.
async fn connect(addr: SocketAddr, run: &str, headers: &[(&'static str, String)]) -> Result<Ws, (u16, String)> {
    let mut req = format!("ws://{addr}/api/runs/{run}/acp").into_client_request().unwrap();
    req.headers_mut().insert("host", "localhost:8787".parse().unwrap());
    for (k, v) in headers {
        req.headers_mut().insert(*k, v.parse().unwrap());
    }
    let s = tokio::net::TcpStream::connect(addr).await.unwrap();
    match tokio_tungstenite::client_async(req, s).await {
        Ok((ws, resp)) => {
            assert_eq!(resp.headers()["sec-websocket-protocol"], SUBPROTOCOL);
            assert!(resp.headers().contains_key("content-security-policy"));
            Ok(ws)
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
            let body = r.body().as_ref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
            Err((r.status().as_u16(), body))
        }
        Err(e) => panic!("{e}"),
    }
}

fn browser(cookie: &str, ticket: &str) -> Vec<(&'static str, String)> {
    vec![
        ("cookie", format!("__Host-wicket_sid={cookie}")),
        ("origin", ORIGIN.into()),
        ("sec-websocket-protocol", format!("{SUBPROTOCOL}, {TICKET_PREFIX}{ticket}")),
    ]
}

async fn recv(ws: &mut Ws) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a message in time") {
            Some(Ok(Message::Text(t))) => return serde_json::from_str(t.as_str()).unwrap(),
            Some(Ok(Message::Close(c))) => return json!({ "closed": c.map(|c| u16::from(c.code)) }),
            Some(Ok(_)) => continue,
            other => return json!({ "closed": format!("{other:?}") }),
        }
    }
}

#[tokio::test]
async fn the_socket_needs_a_session_the_consoles_origin_and_a_fresh_passkey_ticket() {
    let mut t = setup("sess-auth");
    t.running(RUN, "lead");
    t.running("run_two", "other");
    std::fs::create_dir_all(t.dir.join("runs").join(RUN).join("ctl")).unwrap();
    let cookie = t.sid.clone().unwrap();
    // Not for a run that isn't running: refused before the passkey is asked for.
    assert_eq!(t.begin(json!({ "action": "open_session", "run": "run_none" })).status, StatusCode::NOT_FOUND);
    let good = ticket(&mut t, RUN);
    let other_run = ticket(&mut t, "run_two");
    let cross = ticket(&mut t, RUN);
    let no_origin = ticket(&mut t, RUN);
    // Another signed-in session of the same operator can't use this session's ticket.
    let other_cookie = token_of(&set_session(&t.state, SessionKind::Operator { cred: t.cred.clone() }, LOCAL).unwrap());
    let other_session = ticket(&mut t, RUN);
    let opened = t.audit_kinds().into_iter().filter(|(k, _)| k == "session.opened").collect::<Vec<_>>();
    assert_eq!(opened.len(), 5);
    assert!(opened[0].1["signed"]["signature"].is_string(), "the open is signed");
    assert!(opened[0].1["principal"].as_str().unwrap().contains("/op/passkey/laptop"));
    let ledger = t.dir.join("ledger.db");
    let addr = serve(t.state).await;

    // No cookie: the same 401 as any unauthenticated request.
    let no_cookie: Vec<_> = browser(&cookie, &good).into_iter().filter(|(k, _)| *k != "cookie").collect();
    assert_eq!(connect(addr, RUN, &no_cookie).await.unwrap_err(), (401, DENIED.to_string()));
    // Another origin (a cross-site page with the operator's cookie).
    let mut h = browser(&cookie, &cross);
    h[1].1 = "https://evil.example".into();
    assert_eq!(connect(addr, RUN, &h).await.unwrap_err().0, 403);
    let h: Vec<_> = browser(&cookie, &no_origin).into_iter().filter(|(k, _)| *k != "origin").collect();
    assert_eq!(connect(addr, RUN, &h).await.unwrap_err().0, 403);
    // No ticket: the cookie alone opens nothing.
    let h =
        vec![("cookie", format!("__Host-wicket_sid={cookie}")), ("origin", ORIGIN.into()), ("sec-websocket-protocol", SUBPROTOCOL.into())];
    assert!(connect(addr, RUN, &h).await.unwrap_err().1.contains("passkey"));
    // A ticket for another run, or from another console session.
    assert!(connect(addr, RUN, &browser(&cookie, &other_run)).await.unwrap_err().1.contains("something else"));
    assert!(connect(addr, RUN, &browser(&other_cookie, &other_session)).await.unwrap_err().1.contains("something else"));
    // The good one, once.
    let mut ws = connect(addr, RUN, &browser(&cookie, &good)).await.expect("opens");
    assert_eq!(connect(addr, RUN, &browser(&cookie, &good)).await.unwrap_err().1, r#"{"error":"unknown, used or expired ticket"}"#);
    // A ticket refused for naming something else is used up too.
    assert!(connect(addr, "run_two", &browser(&cookie, &other_run)).await.unwrap_err().1.contains("unknown, used or expired"));

    ws.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": { "protocolVersion": 1 } }).to_string().into(),
    ))
    .await
    .unwrap();
    assert_eq!(recv(&mut ws).await["result"]["agentInfo"]["name"], "wicket");
    ws.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "session/new", "params": { "cwd": "/", "mcpServers": [] } }).to_string().into(),
    ))
    .await
    .unwrap();
    assert_eq!(recv(&mut ws).await["result"]["sessionId"], RUN);
    // Streams what the agent says, as it says it.
    agent(
        &ledger.parent().unwrap().join("runs").join(RUN),
        update(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "hi" } })),
    );
    assert_eq!(recv(&mut ws).await["params"]["update"]["content"]["text"], "hi");
    let l = Ledger::open(&ledger).unwrap();
    let attached: Vec<Value> =
        l.audit_tail(100).unwrap().into_iter().filter(|r| r.2 == "session.attached").map(|r| serde_json::from_str(&r.4).unwrap()).collect();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0]["by"], "passkey:laptop");

    // Signing out ends the socket: the next message finds no session.
    l.end_console_session(&session_id(&cookie), "sign-out").unwrap();
    ws.send(Message::Text(json!({ "jsonrpc": "2.0", "id": 2, "method": "session/prompt", "params": { "sessionId": RUN, "prompt": [{ "type": "text", "text": "x" }] } }).to_string().into()))
        .await
        .unwrap();
    let end = recv(&mut ws).await;
    assert!(end.get("closed").is_some(), "{end}");
    let mut l = Ledger::open(&ledger).unwrap();
    assert!(l.take_operator_messages(RUN).unwrap().is_empty(), "no prompt after the session ended");
    // Closed, and audited.
    for _ in 0..50 {
        if l.audit_tail(100).unwrap().iter().any(|r| r.2 == "session.closed") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("session.closed was not audited");
}
