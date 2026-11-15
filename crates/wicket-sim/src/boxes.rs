//! A box stub: it stands in for a box and its agent. Over the box's connection to its node (the
//! stand-in for its proxies' sockets), it makes egress requests and model calls, chosen from its
//! seed, for [`DURATION_MS`]. It doesn't crash. A box outlives `wicket node serve`'s restarts
//! (the node adopts it), so it just redials.

use crate::rng::Rng;
use crate::wire::{self, BoxReq};
use crate::{Env, DURATION_MS, FORBIDDEN_HOST, GRANT_PATHS, HOST, NEVER_PATH, NODE_PORT, READ_PATH, RUNS};
use std::rc::Rc;
use std::time::Duration;

pub async fn run(env: Rc<Env>, i: usize, mut rng: Rng) -> turmoil::Result {
    let run = RUNS[i];
    let _ = env;
    let start = tokio::time::Instant::now();
    let mut conn = None;
    while start.elapsed() < Duration::from_millis(DURATION_MS as u64) {
        tokio::time::sleep(Duration::from_millis(rng.range(20, 300))).await;
        if conn.is_none() {
            let Ok(s) = turmoil::net::TcpStream::connect(("node", NODE_PORT)).await else {
                continue;
            };
            let (rd, mut wr) = s.into_split();
            if wire::write_json(&mut wr, &BoxReq::Hello { run: run.into() }).await.is_err() {
                continue;
            }
            conn = Some((rd, wr));
        }
        let req = match rng.range(0, 9) {
            0 => BoxReq::Egress { method: "GET".into(), host: HOST.into(), path: READ_PATH.into() },
            1..=4 => BoxReq::Egress { method: "POST".into(), host: HOST.into(), path: GRANT_PATHS[rng.range(0, 2) as usize].into() },
            5 => BoxReq::Egress { method: "POST".into(), host: HOST.into(), path: NEVER_PATH.into() },
            6 => BoxReq::Egress { method: "GET".into(), host: FORBIDDEN_HOST.into(), path: "/".into() },
            _ => BoxReq::Model { max_tokens: rng.range(50, 1_500) },
        };
        let (rd, wr) = conn.as_mut().expect("connected");
        let ok = wire::write_json(wr, &req).await.is_ok()
            && matches!(tokio::time::timeout(Duration::from_secs(3), wire::read_frame(rd)).await, Ok(Ok(Some(_))));
        if !ok {
            conn = None;
        }
    }
    Ok(())
}
