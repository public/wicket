use super::*;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn trig(kind: &str, token: &str) -> IntakeTrigger {
    IntakeTrigger {
        trigger: "trg_1".into(),
        kind: kind.into(),
        token_sha256: ik::token_sha256(token),
        secret: "s3cret-s3cret-s3cret".into(),
        repo: (kind == "github").then(|| "acme/app".to_string()),
        events: if kind == "github" { vec!["check_suite".into()] } else { vec![] },
        unavailable: false,
    }
}

fn github_sig(body: &[u8]) -> String {
    format!("sha256={}", hex::encode(ik::hmac_sha256(b"s3cret-s3cret-s3cret", body)))
}

fn headers(h: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
    let h: Vec<(String, String)> = h.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    move |n: &str| h.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone())
}

fn generic(ts: i64, id: &str, body: &[u8]) -> impl Fn(&str) -> Option<String> {
    headers(&[
        (ik::GENERIC_SIGNATURE, ik::generic_signature(b"s3cret-s3cret-s3cret", ts, id, body)),
        (ik::GENERIC_TIMESTAMP, ts.to_string()),
        (ik::GENERIC_DELIVERY, id.to_string()),
    ])
}

fn ready(t: Vec<IntakeTrigger>) -> Intake {
    let i = Intake::default();
    i.set_table(t, true);
    i
}

/// A generic delivery: the path and token before the body, then the signature (with its time and
/// id), and each refusal counted by why.
#[test]
fn a_generic_delivery_is_checked_in_order() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("webhook", &token)]);
    let body = br#"{"status":"failed","n":3}"#;
    let at = Instant::now();
    let path = format!("/hook/trg_1/{token}");
    let t = i.admit(&path, IP, at).unwrap();
    let Outcome::Spool(e) = i.verify(&t, &generic(1000, "d-1", body), body, 1000, at) else { panic!("refused") };
    assert_eq!((e.trigger.as_str(), e.delivery.as_str(), e.kind.as_str()), ("trg_1", "d-1", "webhook"));
    assert_eq!(e.fields, serde_json::json!({ "status": "failed", "n": 3 }));
    let other = ik::new_token().unwrap();
    assert_eq!(i.admit(&format!("/hook/trg_1/{other}"), IP, at), Err(Outcome::Answer(StatusCode::NOT_FOUND, "not found")));
    assert_eq!(i.admit(&format!("/hook/trg_2/{token}"), IP, at), Err(Outcome::Answer(StatusCode::NOT_FOUND, "not found")));
    assert_eq!(i.admit("/hook/trg_1", IP, at), Err(Outcome::Answer(StatusCode::NOT_FOUND, "not found")));
    let forged =
        headers(&[(ik::GENERIC_SIGNATURE, ik::generic_signature(b"other", 1000, "d-1", body)), (ik::GENERIC_TIMESTAMP, "1000".into())]);
    assert_eq!(i.verify(&t, &forged, body, 1000, at), Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"));
    let r = i.take_refused();
    assert_eq!((r.token, r.signature), (3, 1));
    assert_eq!(i.take_refused().total(), 0, "reported once");
}

/// #714 review H2: a captured generic delivery can't be sent again under a new delivery id, or
/// after its window.
#[test]
fn a_captured_generic_delivery_cant_be_replayed() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("webhook", &token)]);
    let t = i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()).unwrap();
    let body = br#"{"a":1}"#;
    let sig = ik::generic_signature(b"s3cret-s3cret-s3cret", 1000, "d-1", body);
    let replay = |id: &str, now: i64| {
        let h = headers(&[(ik::GENERIC_SIGNATURE, sig.clone()), (ik::GENERIC_TIMESTAMP, "1000".into()), (ik::GENERIC_DELIVERY, id.into())]);
        i.verify(&t, &h, body, now, Instant::now())
    };
    assert!(matches!(replay("d-1", 1000), Outcome::Spool(_)));
    assert_eq!(replay("d-2", 1000), Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"), "a new id");
    assert_eq!(replay("d-1", 1000 + ik::GENERIC_WINDOW_SECS + 1), Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"), "later");
}

/// #714 fifth review: a delivery's reservation is given back if its hand-over to the node is
/// dropped (the sender hung up), so the retry is taken; one the node took stays; one slowed down by
/// the trigger's rate doesn't keep it either.
#[test]
fn a_dropped_hand_over_gives_its_delivery_back() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("webhook", &token)]);
    let t = i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()).unwrap();
    let at = Instant::now();
    let Outcome::Spool(e) = i.verify(&t, &generic(1, "d-1", b"{}"), b"{}", 1, at) else { panic!("refused") };
    assert_eq!(i.verify(&t, &generic(1, "d-1", b"{}"), b"{}", 1, at), Outcome::Answer(StatusCode::ACCEPTED, "already had it"));
    drop(super::Handing { i: &i, e: &e, taken: false });
    let Outcome::Spool(e) = i.verify(&t, &generic(1, "d-1", b"{}"), b"{}", 1, at) else { panic!("the retry is taken") };
    drop(super::Handing { i: &i, e: &e, taken: true });
    assert_eq!(i.verify(&t, &generic(1, "d-1", b"{}"), b"{}", 1, at), Outcome::Answer(StatusCode::ACCEPTED, "already had it"));
    // Past the burst: a slowed-down delivery isn't reserved, so it can come again.
    let mut slowed = None;
    for n in 0..40 {
        let id = format!("r-{n}");
        if let Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, _) = i.verify(&t, &generic(1, &id, b"{}"), b"{}", 1, at) {
            slowed = Some(id);
            break;
        }
    }
    let id = slowed.expect("slowed down");
    assert_eq!(i.verify(&t, &generic(1, &id, b"{}"), b"{}", 1, at), Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, "slow down"), "not had");
}

/// #714 fifth review: concurrent copies of one delivery spool once.
#[test]
fn concurrent_copies_spool_once() {
    let token = ik::new_token().unwrap();
    let i = std::sync::Arc::new(ready(vec![trig("webhook", &token)]));
    let t = i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()).unwrap();
    let body = vec![b' '; 400 * 1024];
    let spooled = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..16)
            .map(|_| sc.spawn(|| matches!(i.verify(&t, &generic(1, "d-1", &body), &body, 1, Instant::now()), Outcome::Spool(_))))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap() as u32).sum::<u32>()
    });
    assert_eq!(spooled, 1);
}

/// #714 fifth review: one trigger's full share doesn't stop another trigger's body (from another
/// address); a second address to the full trigger is refused.
#[tokio::test]
async fn one_triggers_full_share_leaves_the_others_room() {
    let i = Intake::default();
    let room = |t: &str, a: &str| super::Room { i: &i, trigger: format!("t:{t}"), address: format!("a:{a}"), kib: 0, permits: vec![] };
    let mut full = room("trg_1", "1.2.3.4");
    assert!(full.grow(super::BODY_SHARE_KIB as u32).await);
    let mut other = room("trg_2", "5.6.7.8");
    assert!(other.grow(1024).await, "another trigger gets through");
    let mut more = room("trg_1", "5.6.7.8");
    assert!(!more.grow(1).await, "the full trigger's share");
    drop(full);
    assert!(more.grow(1).await, "given back when dropped");
}

/// #714 fifth review: an address whose bodies to a trigger keep failing is refused before its body
/// is read, for that trigger only; others' addresses and triggers aren't.
#[test]
fn a_slow_address_is_refused_before_its_body() {
    let i = Intake::default();
    let (a, b): (std::net::IpAddr, std::net::IpAddr) = ("1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap());
    let at = Instant::now();
    for _ in 0..super::SLOW_BURST as usize {
        assert!(i.may_send("trg_1", a, at));
        i.charge_slow("trg_1", a, at);
    }
    assert!(!i.may_send("trg_1", a, at));
    assert!(i.may_send("trg_2", a, at), "another trigger");
    assert!(i.may_send("trg_1", b, at), "another address");
    assert!(i.may_send("trg_1", a, at + Duration::from_secs(31)), "refilled");
}

/// GitHub: its own signature header; events and repositories it doesn't listen to are 202 and
/// dropped; repository names ignore case; the fields are the normalised ones.
#[test]
fn a_github_delivery_keeps_its_fields() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("github", &token)]);
    let path = format!("/hook/trg_1/{token}");
    let body = serde_json::to_vec(&serde_json::json!({
        "action": "completed",
        "check_suite": { "conclusion": "failure", "head_branch": "fix", "pull_requests": [{ "number": 9 }] },
        "repository": { "full_name": "Acme/App" }
    }))
    .unwrap();
    let h = |event: &str, body: &[u8]| {
        headers(&[
            (ik::GITHUB_SIGNATURE, github_sig(body)),
            (ik::GITHUB_EVENT, event.into()),
            (ik::GITHUB_DELIVERY, format!("{event}-{}", ik::body_sha256(body))),
        ])
    };
    let at = Instant::now();
    let t = i.admit(&path, IP, at).unwrap();
    let Outcome::Spool(e) = i.verify(&t, &h("check_suite", &body), &body, 5, at) else { panic!("refused") };
    assert_eq!((e.kind.as_str(), e.fields["pr"]["number"].as_i64()), ("check_suite", Some(9)));
    // The same body again is a duplicate (#714 fourth review R2: reserved when it verified).
    assert_eq!(i.verify(&t, &h("check_suite", &body), &body, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "already had it"));
    let pushed =
        serde_json::to_vec(&serde_json::json!({ "after": "abc", "commits": [], "repository": { "full_name": "Acme/App" } })).unwrap();
    assert_eq!(i.verify(&t, &h("push", &pushed), &pushed, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "not listened to"));
    // Forgotten when the node refuses it, so GitHub's redelivery is taken.
    i.forget(&e);
    assert!(matches!(i.verify(&t, &h("check_suite", &body), &body, 5, at), Outcome::Spool(_)), "after forget");
    let elsewhere = serde_json::to_vec(&serde_json::json!({ "check_suite": {}, "repository": { "full_name": "evil/app" } })).unwrap();
    assert_eq!(i.verify(&t, &h("check_suite", &elsewhere), &elsewhere, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "another repository"));
    // The generic header doesn't sign a GitHub delivery.
    let generic = headers(&[(ik::GENERIC_SIGNATURE, github_sig(&body)), (ik::GITHUB_EVENT, "check_suite".into())]);
    assert_eq!(i.verify(&t, &generic, &body, 5, at), Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"));
}

/// #714 reviews M1 and F3: only verified deliveries count against a trigger, so a leaked URL can't
/// starve it; bad tokens are charged to their address (an IPv6 address by its /64) and slow down
/// only its bad-token requests, never a delivery with a trigger's token; bad signatures are charged
/// to their trigger and slow down only bad signatures.
#[test]
fn rates_count_what_they_should() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("webhook", &token)]);
    let path = format!("/hook/trg_1/{token}");
    let at = Instant::now();
    let shared: IpAddr = "2001:db8:1:2::7".parse().unwrap();
    let neighbour: IpAddr = "2001:db8:1:2::9".parse().unwrap();
    let bad = format!("/hook/trg_1/{}", ik::new_token().unwrap());
    for _ in 0..30 {
        let _ = i.admit(&bad, shared, at);
    }
    assert_eq!(i.admit(&bad, neighbour, at), Err(Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, "slow down")), "the same /64");
    let t = i.admit(&path, shared, at).expect("a delivery with the token isn't slowed down by its address's bad tokens");
    // Bad signatures: charged to the trigger, past its burst answered 429, but a signed one goes on.
    for _ in 0..30 {
        let _ = i.verify(&t, &headers(&[]), b"{}", 1, at);
    }
    assert_eq!(i.verify(&t, &headers(&[]), b"{}", 1, at), Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, "slow down"));
    let mut ok = 0;
    for n in 0..30 {
        let id = format!("d-{n}");
        if let Outcome::Spool(_) = i.verify(&t, &generic(1, &id, b"{}"), b"{}", 1, at) {
            ok += 1;
        }
    }
    assert_eq!(ok, PER_TRIGGER_BURST as usize, "the sender still gets its burst");
    assert!(
        matches!(i.verify(&t, &generic(1, "late", b"{}"), b"{}", 1, at + Duration::from_secs(2)), Outcome::Spool(_)),
        "a token a second comes back"
    );
    // A trigger no longer served loses its bucket, and its deliveries are not found.
    i.set_table(vec![], true);
    assert_eq!(i.admit(&path, IP, at), Err(Outcome::Answer(StatusCode::NOT_FOUND, "not found")));
}

/// #714 review F2: a captured GitHub body sent again under new delivery ids is answered 202 and
/// neither spooled nor charged, so the real deliveries still go through.
#[test]
fn a_replayed_body_doesnt_use_up_the_trigger() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("github", &token)]);
    let t = i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()).unwrap();
    let at = Instant::now();
    let body =
        |n: u32| serde_json::to_vec(&serde_json::json!({ "n": n, "check_suite": {}, "repository": { "full_name": "acme/app" } })).unwrap();
    let h = |b: &[u8], id: &str| {
        headers(&[(ik::GITHUB_SIGNATURE, github_sig(b)), (ik::GITHUB_EVENT, "check_suite".into()), (ik::GITHUB_DELIVERY, id.into())])
    };
    let captured = body(0);
    assert!(matches!(i.verify(&t, &h(&captured, "g-0"), &captured, 5, at), Outcome::Spool(_)), "refused");
    for n in 1..50 {
        assert_eq!(
            i.verify(&t, &h(&captured, &format!("replay-{n}")), &captured, 5, at),
            Outcome::Answer(StatusCode::ACCEPTED, "already had it")
        );
    }
    let real = body(1);
    assert!(matches!(i.verify(&t, &h(&real, "g-1"), &real, 5, at), Outcome::Spool(_)), "the real delivery still goes through");
}

/// #714 review N1: a delivery of an event the trigger doesn't listen to (or of another repository,
/// or a body that isn't the event it says), replayed, never uses up the trigger: it is answered 202
/// and remembered before the rate, so the real delivery after it goes through.
#[test]
fn unlistened_replays_dont_starve_the_trigger() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("github", &token)]);
    let t = i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()).unwrap();
    let at = Instant::now();
    let star = serde_json::to_vec(&serde_json::json!({ "action": "created", "repository": { "full_name": "acme/app" } })).unwrap();
    let h = |b: &[u8], event: &str, id: &str| {
        headers(&[(ik::GITHUB_SIGNATURE, github_sig(b)), (ik::GITHUB_EVENT, event.into()), (ik::GITHUB_DELIVERY, id.into())])
    };
    assert_eq!(i.verify(&t, &h(&star, "star", "s-0"), &star, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "not listened to"));
    for n in 1..40 {
        let o = i.verify(&t, &h(&star, "star", &format!("s-{n}")), &star, 5, at);
        assert_eq!(o, Outcome::Answer(StatusCode::ACCEPTED, "already had it"), "replay {n}");
    }
    // The same body claimed as a check suite: not that event.
    assert_eq!(i.verify(&t, &h(&star, "check_suite", "s-x"), &star, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "already had it"));
    let other = serde_json::to_vec(&serde_json::json!({ "issue": { "number": 1 }, "repository": { "full_name": "acme/app" } })).unwrap();
    assert_eq!(i.verify(&t, &h(&other, "check_suite", "i-1"), &other, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "not that event"));
    let real =
        serde_json::to_vec(&serde_json::json!({ "check_suite": { "conclusion": "failure" }, "repository": { "full_name": "acme/app" } }))
            .unwrap();
    assert!(matches!(i.verify(&t, &h(&real, "check_suite", "g-1"), &real, 5, at), Outcome::Spool(_)), "the real delivery goes through");
}

/// #714 review C: a generic delivery with no id is named by its signed message, time included, so
/// the same body sent again later is a new delivery, not "already had it".
#[test]
fn the_same_generic_body_later_is_a_new_delivery() {
    let token = ik::new_token().unwrap();
    let i = ready(vec![trig("webhook", &token)]);
    let t = i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()).unwrap();
    let at = Instant::now();
    let send = |ts: i64| {
        let h = headers(&[
            (ik::GENERIC_SIGNATURE, ik::generic_signature(b"s3cret-s3cret-s3cret", ts, "", b"{}")),
            (ik::GENERIC_TIMESTAMP, ts.to_string()),
        ]);
        i.verify(&t, &h, b"{}", ts, at)
    };
    let Outcome::Spool(a) = send(1000) else { panic!("refused") };
    assert_eq!(send(1000), Outcome::Answer(StatusCode::ACCEPTED, "already had it"), "the same send again");
    let Outcome::Spool(b) = send(1060) else { panic!("a minute later: a new delivery") };
    assert_ne!(a.delivery, b.delivery);
}

/// #714 review E: a trigger whose key is too short to verify with is answered 503, not served.
#[test]
fn a_short_key_isnt_served() {
    let token = ik::new_token().unwrap();
    let mut t = trig("webhook", &token);
    t.secret = "k".into();
    let i = ready(vec![t]);
    assert_eq!(
        i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()),
        Err(Outcome::Answer(StatusCode::SERVICE_UNAVAILABLE, "try later"))
    );
}

/// #714 review F5: a trigger whose secret didn't read is answered 503, and counts as nobody's failure.
#[test]
fn an_unavailable_trigger_says_try_later() {
    let token = ik::new_token().unwrap();
    let mut t = trig("webhook", &token);
    t.unavailable = true;
    t.secret = String::new();
    let i = ready(vec![t]);
    for _ in 0..30 {
        assert_eq!(
            i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()),
            Err(Outcome::Answer(StatusCode::SERVICE_UNAVAILABLE, "try later"))
        );
    }
    assert_eq!(i.take_refused().total(), 0);
}

/// #714 review M4: until `node serve` has the control host's table, deliveries are answered 503
/// (try later), not 404.
#[test]
fn a_node_without_its_table_says_try_later() {
    let token = ik::new_token().unwrap();
    let i = Intake::default();
    i.set_table(vec![trig("webhook", &token)], false);
    assert_eq!(
        i.admit(&format!("/hook/trg_1/{token}"), IP, Instant::now()),
        Err(Outcome::Answer(StatusCode::SERVICE_UNAVAILABLE, "try later"))
    );
}

/// A stand-in `node serve`: answers the table (ready) and records deliveries.
fn fake_node(sock: PathBuf, table: Vec<IntakeTrigger>) -> Arc<Mutex<Vec<serde_json::Value>>> {
    let delivered = Arc::new(Mutex::new(vec![]));
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let d = delivered.clone();
    tokio::spawn(async move {
        loop {
            let Ok((c, _)) = listener.accept().await else { return };
            let (rd, mut wr) = c.into_split();
            let mut line = String::new();
            let _ = tokio::io::BufReader::new(rd).read_line(&mut line).await;
            let req: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            let answer = match req["op"].as_str() {
                Some("table") => serde_json::json!({ "triggers": table, "ready": true }),
                Some("deliver") => {
                    d.lock().unwrap().push(req["event"].clone());
                    serde_json::json!({ "ok": true })
                }
                _ => serde_json::json!({ "ok": true }),
            };
            let mut out = serde_json::to_vec(&answer).unwrap();
            out.push(b'\n');
            let _ = wr.write_all(&out).await;
        }
    });
    delivered
}

struct Served {
    addr: std::net::SocketAddr,
    delivered: Arc<Mutex<Vec<serde_json::Value>>>,
    dir: PathBuf,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The service on a free port, its node a stand-in, with `lim`, its table fetched.
async fn served(name: &str, token: &str, lim: crate::serve::net::Limits) -> Served {
    let dir = std::env::temp_dir().join(format!("wi-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("intake.sock");
    let delivered = fake_node(sock.clone(), vec![trig("webhook", token)]);
    let intake = Arc::new(Intake::default());
    let v = ask(&sock, &serde_json::json!({ "op": "table" })).await.unwrap();
    intake.set_table(serde_json::from_value(v["triggers"].clone()).unwrap(), true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept(listener, None, intake, sock, lim, Arc::new(vec![])));
    Served { addr, delivered, dir }
}

async fn send(addr: std::net::SocketAddr, raw: &[u8]) -> String {
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(raw).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_string(&mut out)).await;
    out
}

fn post(path: &str, h: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut req = format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\nconnection: close\r\n", body.len());
    for (k, v) in h {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    out
}

/// The service end to end, over TCP and a stand-in node: a signed delivery reaches the node and
/// is answered 202 with nothing of it echoed; a forged one is 401 and doesn't; a GET is 405.
#[tokio::test]
async fn the_service_hands_verified_deliveries_to_its_node() {
    let token = ik::new_token().unwrap();
    let s = served("e2e", &token, limits()).await;
    let body = br#"{"status":"failed"}"#;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let h = |id: &str, body: &[u8]| {
        vec![
            (ik::GENERIC_SIGNATURE, ik::generic_signature(b"s3cret-s3cret-s3cret", now, id, body)),
            (ik::GENERIC_TIMESTAMP, now.to_string()),
            (ik::GENERIC_DELIVERY, id.to_string()),
        ]
    };
    let path = format!("/hook/trg_1/{token}");
    let ok = send(s.addr, &post(&path, &h("d-1", body), body)).await;
    assert!(ok.starts_with("HTTP/1.1 202"), "{ok}");
    assert!(!ok.contains("failed"), "the payload isn't echoed: {ok}");
    let mut forged = h("d-1", body);
    forged[0].1 = ik::generic_signature(b"other", now, "d-1", body);
    assert!(send(s.addr, &post(&path, &forged, body)).await.starts_with("HTTP/1.1 401"));
    let get = send(s.addr, format!("GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").as_bytes()).await;
    assert!(get.starts_with("HTTP/1.1 405"), "{get}");
    let d = s.delivered.lock().unwrap().clone();
    assert_eq!(d.len(), 1, "only the verified one reached the node");
    assert_eq!(
        (d[0]["trigger"].as_str(), d[0]["delivery"].as_str(), d[0]["fields"]["status"].as_str()),
        (Some("trg_1"), Some("d-1"), Some("failed"))
    );
}

/// #714 review H1: the server's bounds. A body announced over the cap is 413 before it is read; an
/// unknown token is 404 before the body is read; slow headers and a slow body are cut off; past
/// the connection cap, a connection is closed at once.
#[tokio::test]
async fn the_server_is_bounded() {
    let token = ik::new_token().unwrap();
    let lim = crate::serve::net::Limits {
        header_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(300),
        max_connections: 2,
        per_ip_connections: 2,
        ..limits()
    };
    let s = served("bounds", &token, lim).await;
    let path = format!("/hook/trg_1/{token}");
    // 413 from the announced length alone: no body sent.
    let big = format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", ik::MAX_BODY + 1);
    assert!(send(s.addr, big.as_bytes()).await.starts_with("HTTP/1.1 413"));
    // 404 for another token without waiting for the (never sent) body.
    let other = ik::new_token().unwrap();
    let head = format!("POST /hook/trg_1/{other} HTTP/1.1\r\nhost: x\r\ncontent-length: 1000\r\n\r\n");
    let started = Instant::now();
    assert!(send(s.addr, head.as_bytes()).await.starts_with("HTTP/1.1 404"));
    assert!(started.elapsed() < Duration::from_millis(250), "answered before any body");
    // Slow headers: cut off by the header timeout, no answer.
    let started = Instant::now();
    let slow = send(s.addr, b"POST /hook/x HTTP/1.1\r\nhost: x\r\n").await;
    assert!(!slow.starts_with("HTTP/1.1 2"), "{slow}");
    assert!(started.elapsed() < Duration::from_secs(3), "cut off");
    // A slow body: its headers whole, then too little: 408.
    let slow_body = format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\nconnection: close\r\n\r\n{{");
    assert!(send(s.addr, slow_body.as_bytes()).await.starts_with("HTTP/1.1 408"));
    // #714 fourth review R1: room is taken as bytes arrive. Bodies announced at 1 MiB that send a
    // byte hold almost nothing, so a signed delivery still goes through; one address past its share
    // (8 MiB of bodies it is actually sending) gets 503 for the next.
    drop(s);
    let lim = crate::serve::net::Limits { max_connections: 64, per_ip_connections: 64, body_timeout: Duration::from_secs(10), ..limits() };
    let s = served("budget", &token, lim).await;
    let mut holding = vec![];
    for _ in 0..32 {
        let mut c = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        c.write_all(format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n{{", ik::MAX_BODY).as_bytes()).await.unwrap();
        holding.push(c);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let body: &[u8] = b"{}";
    let signed = vec![
        (ik::GENERIC_SIGNATURE, ik::generic_signature(b"s3cret-s3cret-s3cret", now, "d-r1", body)),
        (ik::GENERIC_TIMESTAMP, now.to_string()),
        (ik::GENERIC_DELIVERY, "d-r1".to_string()),
    ];
    let ok = send(s.addr, &post(&path, &signed, body)).await;
    assert!(ok.starts_with("HTTP/1.1 202"), "held 1-byte bodies don't take the room: {ok}");
    drop(holding);
    let mut sending = vec![];
    let chunk = vec![b'x'; ik::MAX_BODY - 1];
    for _ in 0..8 {
        let mut c = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        c.write_all(format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n", ik::MAX_BODY).as_bytes()).await.unwrap();
        c.write_all(&chunk).await.unwrap();
        sending.push(c);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut ninth = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    ninth
        .write_all(format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", ik::MAX_BODY).as_bytes())
        .await
        .unwrap();
    ninth.write_all(&chunk[..64 * 1024]).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), ninth.read_to_string(&mut out)).await;
    // 503 past the share; or 429 before the body, since the dropped half-sent bodies above were
    // charged to this address (#714 fifth review).
    assert!(out.starts_with("HTTP/1.1 503") || out.starts_with("HTTP/1.1 429"), "past the address's share: {out}");
    drop(sending);
    let lim = crate::serve::net::Limits {
        header_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(300),
        max_connections: 2,
        per_ip_connections: 2,
        ..limits()
    };
    let s = served("bounds2", &token, lim).await;
    // The connection cap: two held open, a third is closed at once.
    let mut held = vec![];
    for _ in 0..2 {
        let mut c = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        c.write_all(b"POST /hook/x HTTP/1.1\r\n").await.unwrap();
        held.push(c);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut third = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf)).await.expect("closed, not left waiting").unwrap_or(0);
    assert_eq!(n, 0, "closed without an answer");
    drop(held);
}
