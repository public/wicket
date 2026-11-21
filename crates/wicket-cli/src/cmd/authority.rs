//! `wicket authority <run>` and `wicket audit explain <seq>` (#713): the console's read-only views
//! of authority (#173) from the host. Both print the console's own view ([`views`]), so the two
//! surfaces show the same thing; `--json` prints it whole.

use crate::serve::authority::{self as views, Views};
use crate::*;
use serde_json::Value;

fn with_views<T>(f: impl FnOnce(&Views) -> Result<T>) -> Result<T> {
    let (ledger, data, tenant) = (ledger_path(), wicket_home::data_dir(), TenantId::single());
    let root = crate::roots::authz_root_public().ok();
    f(&Views { ledger: &ledger, data: &data, tenant: &tenant, authz_root: root.as_ref() })
}

/// Text from a view: a string, or `-` for none.
fn s(v: &Value) -> String {
    match v {
        Value::String(s) => wicket_agent::clip(s, 300),
        Value::Null => "-".into(),
        v => v.to_string(),
    }
}

fn when_ms(v: &Value) -> String {
    v.as_i64().map_or("-".into(), |ms| wicket_core::time::unix_rfc3339(ms / 1000))
}

/// What `wicket authority` prints without --json.
pub(crate) fn authority_text(v: &Value) -> String {
    let mut out = format!("run {}  {}  on node {}\n", s(&v["run"]), s(&v["status"]), s(&v["node"]));
    let p = &v["policy"];
    out.push_str(&format!(
        "  org policy: minted under {}; installed {}{}\n",
        s(&p["version"]),
        s(&p["installed"]),
        if p["current"] == true { " (current)" } else { "" }
    ));
    if let Some(r) = v["revoked"].as_object() {
        out.push_str(&format!("  revoked by {} at {}: {}\n", s(&r["by"]), s(&r["at"]), s(&r["reason"])));
    }
    if let Some(d) = v["deadline"].as_object() {
        out.push_str(&format!("  deadline {}{}\n", when_ms(&d["until_ms"]), if d["stopped"] == true { " (stopped)" } else { "" }));
    }
    if let Some(h) = v["holdings"].as_object() {
        let secrets: Vec<String> = h["secrets"].as_array().into_iter().flatten().map(s).collect();
        out.push_str(&format!("  its node holds secrets: {}\n", if secrets.is_empty() { "none".into() } else { secrets.join(", ") }));
    }
    let t = &v["token"];
    if t["held"] != true {
        out.push_str(&format!("  token: not held: {}\n", s(&t["why"])));
        return out;
    }
    out.push_str(&format!("  token: zone {}, epoch {}, issued by {}", s(&t["zone"]), s(&t["epoch"]), s(&t["issued_by"])));
    if t["loads"] != true {
        out.push_str(&format!(", does NOT load: {}", s(&t["loads"]["error"])));
    }
    out.push('\n');
    out.push_str(&format!("  reach: {}\n", serde_json::to_string(&t["reach"]).unwrap_or_default()));
    out.push_str(&format!("  forbid: {}\n", serde_json::to_string(&t["forbid"]).unwrap_or_default()));
    for b in t["blocks"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  block {} ({}){}{}  [{}]\n",
            s(&b["index"]),
            s(&b["kind"]),
            b["signed_by"].as_str().map(|k| format!(", signed by {}", wicket_agent::clip(k, 200))).unwrap_or_default(),
            if b["revoked"] == true { ", REVOKED" } else { "" },
            s(&b["revocation_fingerprint"]),
        ));
        // A block's source names the hosts and paths agents asked for (#731): cleaned, as every other field.
        for l in b["source"].as_str().unwrap_or("").lines() {
            out.push_str(&format!("      {}\n", wicket_agent::clip(l, 400)));
        }
    }
    for g in t["grants"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  grant {}  {} {}{}{}  approved by {}{}\n",
            s(&g["id"]),
            s(&g["method"]),
            s(&g["host"]),
            s(&g["path"]),
            if g["prefix"] == true { "*" } else { "" },
            s(&g["approved_by"]),
            if g["revoked"] == true { ", REVOKED" } else { "" },
        ));
    }
    out
}

/// What `wicket audit explain` prints without --json.
pub(crate) fn explain_text(v: &Value) -> String {
    let r = &v["recorded"];
    let mut out = format!(
        "record {}: {} {}{} for run {}\n  recorded: {} on {} ({})\n",
        s(&v["seq"]),
        s(&r["method"]),
        s(&r["host"]),
        s(&r["path"]),
        s(&v["run"]),
        s(&r["outcome"]),
        s(&r["decided_on"]),
        s(&r["detail"]),
    );
    let n = &v["against_token_now"];
    if n["available"] == true {
        out.push_str(&format!(
            "  against its token now: {}: {}\n  its zone alone says {}\n",
            s(&n["decision"]),
            s(&n["why"]),
            s(&n["zone_says"])
        ));
    } else {
        out.push_str(&format!("  against its token now: can't say: {}\n", s(&n["why"])));
    }
    out
}

/// `wicket authority <run>`.
pub fn run(run: &str, json: bool) -> Result<()> {
    let v = with_views(|x| views::run_authority(x, run))?;
    if json {
        return super::print_json(&v);
    }
    print!("{}", authority_text(&v));
    Ok(())
}

/// `wicket audit explain <seq>`.
pub fn explain(seq: i64, json: bool) -> Result<()> {
    let v = with_views(|x| views::explain(x, seq))?;
    if json {
        return super::print_json(&v);
    }
    print!("{}", explain_text(&v));
    Ok(())
}
