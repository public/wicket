//! Times what every run's supervisor and every node's feed status ask of the ledger (#582), on a
//! ledger file: a copy of a real one, or one this fills with history first.
//!
//! ```text
//! cargo run --release -p wicket-store --example ledger_scale -- fill <ledger.db> <runs>
//! cargo run --release -p wicket-store --example ledger_scale -- measure <copy-of-ledger.db>
//! cargo run --release -p wicket-store --example ledger_scale -- maintain <copy-of-ledger.db> <days-from-now>
//! cargo run --release -p wicket-store --example ledger_scale -- sql <copy-of-ledger.db> "<SELECT … ?1>" <value>
//! ```
//!
//! `fill` adds `runs` runs (a tenth still running, spread over 3 nodes), each with a request and
//! its grant, and every node's shipped audit. `measure` opens the ledger with this build (which
//! migrates it) and prints the median time of each call, over runs and nodes it finds in it.
//! Measure a copy: opening migrates the file.

use std::time::{Duration, Instant};
use wicket_core::{Op, RunId, TenantId};
use wicket_store::{Approval, Ledger};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["fill", path, runs] => fill(path, runs.parse().expect("runs")),
        ["measure", path] => measure(path),
        ["sql", path, sql, arg] => time_sql(path, sql, arg),
        ["maintain", path, days] => {
            // As if `days` had passed: what a reconcile pass's upkeep then does, and how long it takes.
            let l = Ledger::open(std::path::Path::new(path)).expect("open");
            let t = Instant::now();
            let m = l.maintain(wicket_store::now() + days.parse::<i64>().expect("days") * 86400).unwrap();
            println!("maintain: {m:?} in {:.1?}", t.elapsed());
        }
        _ => {
            eprintln!("usage: ledger_scale fill <ledger.db> <runs> | measure <ledger.db> | maintain <ledger.db> <days> | sql <ledger.db> <sql> <value>");
            std::process::exit(2)
        }
    }
}

fn fill(path: &str, runs: usize) {
    let mut l = Ledger::open(std::path::Path::new(path)).expect("open");
    let t = TenantId::single();
    let node = Ledger::open_in_memory().unwrap();
    let t0 = Instant::now();
    for i in 0..runs {
        let run = RunId(format!("run_{i:07}"));
        let n = format!("n{}", i % 3);
        l.run_started(&t, &run, "z", "a").unwrap();
        l.set_run_node(&run.0, &n).unwrap();
        let op = Op::egress(&t, &run, "z", "GET", &format!("h{}.example.com", i % 50), &format!("/p/{i}"));
        let (rid, _) = l.pending_for(&op, "out of reach", None).unwrap();
        let a = Approval { uses: Some(1), ttl: Duration::from_secs(3600), path_prefix: None, decided_by: "t".into() };
        let gid = l.approve(&rid, &a).unwrap();
        l.hand_grant_to_node(&gid, &n).unwrap();
        l.grants_published(&[gid], i as i64).unwrap();
        if i % 10 != 0 {
            l.run_ended(&run, "done", "").unwrap();
        }
        node.audit(&t, Some(&run), "op", &serde_json::json!({ "i": i })).unwrap();
        if i % 1000 == 999 {
            eprintln!("{} runs, {:.0?}", i + 1, t0.elapsed());
        }
    }
    let recs = node.audit_records_after(0, runs).unwrap();
    for n in ["n0", "n1", "n2"] {
        for c in recs.chunks(500) {
            l.append_node_audit(n, &t, c).unwrap();
        }
    }
    eprintln!("filled {path}: {runs} runs in {:.0?}", t0.elapsed());
}

/// One statement's plan and median time with this build's SQLite (one text parameter), prepared
/// once and prepared each call: what a statement's preparing costs is often most of a hot call.
fn time_sql(path: &str, sql: &str, arg: &str) {
    let c = rusqlite::Connection::open(path).expect("open");
    let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    for d in st.query_map([arg], |r| r.get::<_, String>(3)).unwrap() {
        println!("  {}", d.unwrap());
    }
    let run = |st: &mut rusqlite::Statement<'_>| {
        let rows = st.query_map([arg], |r| {
            for i in 0..r.as_ref().column_count() {
                let _: rusqlite::types::Value = r.get(i)?;
            }
            Ok(())
        });
        std::hint::black_box(rows.unwrap().count());
    };
    let mut once = c.prepare(sql).unwrap();
    let mut xs = vec![];
    let mut each = vec![];
    for _ in 0..300 {
        let t = Instant::now();
        run(&mut once);
        xs.push(t.elapsed());
        let t = Instant::now();
        run(&mut c.prepare(sql).unwrap());
        each.push(t.elapsed());
    }
    println!("prepared once {:.1?}, prepared each call {:.1?}", median(xs), median(each));
}

fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

fn measure(path: &str) {
    let t0 = Instant::now();
    let mut l = Ledger::open(std::path::Path::new(path)).expect("open");
    println!("open (and migrate): {:.1?}", t0.elapsed());
    let running = l.running_runs().unwrap();
    let runs: Vec<String> = running.iter().map(|(r, _)| r.clone()).take(50).collect();
    let nodes: Vec<String> = l.nodes().unwrap().into_iter().map(|n| n.name).chain(["n0", "n1", "n2"].map(String::from)).take(3).collect();
    println!("{} running runs; timing over {} of them and nodes {}", running.len(), runs.len(), nodes.join(", "));
    let time = |name: &str, f: &mut dyn FnMut(usize)| {
        let mut xs = vec![];
        for i in 0..200 {
            let t = Instant::now();
            f(i);
            xs.push(t.elapsed());
        }
        println!("{name:<28} {:>10.1?}", median(xs));
    };
    let pick = |i: usize| runs[i % runs.len().max(1)].clone();
    time("grants_for_run", &mut |i| {
        let _ = l.grants_for_run(&pick(i)).unwrap();
    });
    time("node_feed_at", &mut |i| l.node_feed_at(&nodes[i % nodes.len()], 1).unwrap());
    time("take_turn_cancels", &mut |i| {
        let _ = l.take_turn_cancels(&pick(i), 30).unwrap();
    });
    time("take_mode_changes", &mut |i| {
        let _ = l.take_mode_changes(&pick(i), 30).unwrap();
    });
    time("node_audit_head", &mut |i| {
        let _ = l.node_audit_head(&nodes[i % nodes.len()]).unwrap();
    });
    time("running_runs_on_node", &mut |i| {
        let _ = l.running_runs_on_node(&nodes[i % nodes.len()]).unwrap();
    });
    let rids: Vec<String> = runs.iter().filter_map(|r| l.grants_for_run(r).ok()?.first()?.request_id.clone()).collect();
    if !rids.is_empty() {
        time("grant_in_flight", &mut |i| {
            let _ = l.grant_in_flight(&rids[i % rids.len()]).unwrap();
        });
    }
}
