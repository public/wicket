//! `wicket why-here <run>` (#579 step 2): why a run's box went where it did, or why it went nowhere,
//! from the decision placement recorded when it chose (`placement_decisions`).

use crate::ledger_path;
use anyhow::Result;
use wicket_store::Ledger;

/// The decision recorded for `run`, as text (or the record itself with `json`).
pub fn why_here(run: &str, json: bool) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let Some((at_ms, record)) = l.placement_decision(run)? else {
        return Err(wicket_home::exit::not_found(format!(
            "no placement decision is recorded for {run}: it ran on this host's own node, on a node named for it whose room \
             wasn't known from a report, or its decision is over a week old"
        )));
    };
    if json {
        let mut v: serde_json::Value = serde_json::from_str(&record)?;
        v["run"] = serde_json::json!(run);
        v["at_ms"] = serde_json::json!(at_ms);
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    print!("{}", explain(run, at_ms, &record, wicket_feed::now_ms())?);
    Ok(())
}

/// The text `why_here` prints.
pub fn explain(run: &str, at_ms: i64, record: &str, now_ms: i64) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(record)?;
    let list = |k: &str| -> Vec<String> {
        v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    let ago = (now_ms - at_ms).max(0) / 1000;
    let mut out = String::new();
    let ranked = list("ranked");
    let more = |k: &str| v[k].as_u64().filter(|n| *n > 0).map(|n| format!(" and {n} more")).unwrap_or_default();
    match (v["node"].as_str(), v["behind"].as_str()) {
        (Some(n), _) => out.push_str(&format!(
            "{run}: on node {n}, the best fit of {} it may go on (of {} candidates), decided {ago} s ago\n",
            ranked.len() + v["ranked_more"].as_u64().unwrap_or(0) as usize,
            v["candidates"].as_u64().unwrap_or(0)
        )),
        (None, Some(b)) => out.push_str(&format!("{run}: waiting behind {b}, which waited first and fits a node now ({ago} s ago)\n")),
        (None, None) => out.push_str(&format!(
            "{run}: no node may take it (of {} candidates), decided {ago} s ago\n",
            v["candidates"].as_u64().unwrap_or(0)
        )),
    }
    let r = &v["request"];
    let mut asked = format!("  asked for: {} vCPU, {} MiB", r["vcpus"].as_f64().unwrap_or(0.0), r["memory_mib"].as_u64().unwrap_or(0));
    if let Some(sel) = r["node_selector"].as_object().filter(|m| !m.is_empty()) {
        let s: Vec<String> = sel.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect();
        asked.push_str(&format!("; labels {}", s.join(", ")));
    }
    if let Some(t) = r["tolerations"].as_array().filter(|a| !a.is_empty()) {
        let s: Vec<String> = t
            .iter()
            .map(|x| match x["value"].as_str() {
                Some(v) => format!("{}={v}", x["key"].as_str().unwrap_or("")),
                None => x["key"].as_str().unwrap_or("").to_string(),
            })
            .collect();
        asked.push_str(&format!("; tolerates {}", s.join(", ")));
    }
    let hosts = list("ca_hosts");
    if !hosts.is_empty() {
        asked.push_str(&format!("; its node's CA must cover {}", hosts.join(", ")));
    }
    out.push_str(&asked);
    out.push('\n');
    if !ranked.is_empty() {
        out.push_str(&format!("  ranked (bin-packed, best first): {}{}\n", ranked.join(", "), more("ranked_more")));
    }
    if let Some(refused) = v["refused"].as_array().filter(|a| !a.is_empty()) {
        out.push_str(&format!("  refused{}:\n", more("refused_more")));
        for x in refused {
            let why: Vec<&str> = x["why"].as_array().map(|a| a.iter().filter_map(|w| w.as_str()).collect()).unwrap_or_default();
            out.push_str(&format!("    {}: {}\n", x["node"].as_str().unwrap_or("?"), why.join("; ")));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibernate::{decision_record, Bound, Waiting};
    use wicket_placement::schedule::{Decision, Refusal, Request};

    #[test]
    fn a_decision_reads_as_where_why_and_why_not() {
        let mut req = Request { vcpus: 1.0, memory_mib: 2048, ..Request::default() };
        req.node_selector.insert("gpu".into(), "a100".into());
        req.tolerations.push(wicket_core::placement::Taint::parse("dedicated").unwrap());
        let ask = Waiting { req, need: vec!["api.example.com".into()] };
        let d = Decision {
            node: Some("n1".into()),
            ranked: vec!["n1".into(), "n3".into()],
            refused: vec![
                ("n2".into(), vec![Refusal::NoRoom { free_vcpus: 0.5, free_mib: 512 }]),
                ("n4".into(), vec![Refusal::Label { key: "gpu".into(), want: "a100".into(), has: None }, Refusal::Full]),
            ],
        };
        let rec = decision_record(&ask, &Bound { decision: d, behind: None }, 4);
        let t = explain("run_x", 1_000, &rec, 31_000).unwrap();
        assert!(t.starts_with("run_x: on node n1, the best fit of 2 it may go on (of 4 candidates), decided 30 s ago\n"), "{t}");
        assert!(
            t.contains("asked for: 1 vCPU, 2048 MiB; labels gpu=a100; tolerates dedicated; its node's CA must cover api.example.com"),
            "{t}"
        );
        assert!(t.contains("ranked (bin-packed, best first): n1, n3"), "{t}");
        assert!(t.contains("    n2: 0.5 vCPU, 512 MiB free\n"), "{t}");
        assert!(t.contains("    n4: no label gpu (wanted gpu=a100); its disk is below the floor\n"), "{t}");
        let waiting = decision_record(&ask, &Bound { decision: Decision::default(), behind: Some("run_old".into()) }, 4);
        assert!(explain("run_y", 0, &waiting, 0).unwrap().starts_with("run_y: waiting behind run_old"));
        let none = decision_record(&ask, &Bound::default(), 0);
        assert!(explain("run_z", 0, &none, 0).unwrap().starts_with("run_z: no node may take it (of 0 candidates)"));
        // Bounded: a large installation's record names at most DECISION_NODES of each.
        let many = Decision { node: None, ranked: vec![], refused: (0..25).map(|i| (format!("n{i}"), vec![Refusal::Full])).collect() };
        let rec = decision_record(&ask, &Bound { decision: many, behind: None }, 25);
        let v: serde_json::Value = serde_json::from_str(&rec).unwrap();
        assert_eq!((v["refused"].as_array().unwrap().len(), v["refused_more"].as_u64()), (crate::hibernate::DECISION_NODES, Some(15)));
        assert!(explain("run_m", 0, &rec, 0).unwrap().contains("refused and 15 more:"));
    }
}
