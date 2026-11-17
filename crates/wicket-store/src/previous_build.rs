//! A ledger this build writes, read with the previous build's queries (#475).
//!
//! An expand step must leave what an older build reads unchanged: a build that rolls back, or a
//! supervisor that still runs the old build for the seconds of a handover, reads the tables this
//! build writes. A step that puts rows an older query would mishandle into a table it reads (#463's
//! prompts, in the `messages` an older `await_message` took from) is not an expand step, whatever
//! its DDL.
//!
//! [`PREVIOUS`] is the previous build's queries over the tables whose rows have more than one
//! meaning, copied from its source (schema 17, before 8e1a9af), each with the kinds of row it can
//! handle. When a change gives one of those tables a new kind of row, or a release moves the floor,
//! copy the queries of the build before it here first, then make the change: this test then says
//! whether the old queries still see only what they understand.

use crate::*;

/// One query of the previous build's, and the `messages.kind`s of the rows it handles.
struct Query {
    what: &'static str,
    sql: &'static str,
    handles: &'static [&'static str],
}

/// Schema 17's readers of `messages` (`?1` a run; `?2`, where it is used, a stdin offset).
const PREVIOUS: &[Query] = &[
    Query {
        what: "take_prompts",
        sql:
            "SELECT id FROM messages WHERE to_run = ?1 AND kind IN ('prompt', 'notice') AND delivered_at IS NULL ORDER BY created_at, rowid",
        handles: &[KIND_PROMPT, KIND_NOTICE],
    },
    Query {
        what: "requeue_prompts",
        sql: "SELECT id FROM messages WHERE to_run = ?1 AND kind IN ('prompt', 'notice') AND delivered_at IS NOT NULL
                AND (stdin_start IS NULL OR stdin_start >= ?2) ORDER BY created_at, rowid",
        handles: &[KIND_PROMPT, KIND_NOTICE],
    },
    Query {
        what: "take_message",
        sql: "SELECT id FROM messages WHERE to_run = ?1 AND kind = 'message' AND delivered_at IS NULL
                ORDER BY CASE priority WHEN 'now' THEN 0 WHEN 'later' THEN 2 ELSE 1 END, created_at, rowid LIMIT 1",
        handles: &[KIND_MESSAGE],
    },
    Query {
        what: "take_message_in_flight",
        sql: "SELECT id FROM messages WHERE to_run = ?1 AND kind = 'message' AND delivered_at IS NULL AND taken_at IS NULL
                ORDER BY CASE priority WHEN 'now' THEN 0 WHEN 'later' THEN 2 ELSE 1 END, created_at, rowid LIMIT 1",
        handles: &[KIND_MESSAGE],
    },
    Query { what: "envelopes", sql: "SELECT id FROM messages WHERE kind = 'message' ORDER BY created_at", handles: &[KIND_MESSAGE] },
];

/// Schema 16's `take_message_in_flight`, from before #463: it takes any row of `messages`.
const SCHEMA_16_TAKE: &str = "SELECT id FROM messages WHERE to_run = ?1 AND delivered_at IS NULL AND taken_at IS NULL
    ORDER BY CASE priority WHEN 'now' THEN 0 WHEN 'later' THEN 2 ELSE 1 END, created_at, rowid LIMIT 1";

/// Every kind of row this build writes to `messages`, for one run: (id, kind).
fn written(l: &Ledger, run: &str) -> Vec<(String, &'static str)> {
    let notice = l.add_notice(run, "near its memory limit").unwrap();
    let prompt = l.add_prompt(run, "do the thing", "alex", "spiffe://t/op/alex").unwrap();
    l.add_message("m-1", &TenantId::single(), "run_from", run, "e.n.v").unwrap();
    vec![(notice, KIND_NOTICE), (prompt, KIND_PROMPT), ("m-1".into(), KIND_MESSAGE)]
}

/// What `sql` returns for `run`, read until it returns nothing new (a `LIMIT 1` take, marking each
/// taken as the build does).
fn read(l: &Ledger, sql: &str, run: &str) -> Vec<String> {
    let mut seen = vec![];
    loop {
        let mut st = l.conn.prepare(sql).unwrap();
        let n = st.parameter_count();
        let ids: Vec<String> = match n {
            0 => st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect(),
            1 => st.query_map(rusqlite::params![run], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect(),
            _ => st.query_map(rusqlite::params![run, 0i64], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect(),
        };
        let new: Vec<String> = ids.into_iter().filter(|i| !seen.contains(i)).collect();
        if new.is_empty() || !sql.contains("LIMIT 1") {
            seen.extend(new);
            return seen;
        }
        for id in &new {
            l.conn.execute("UPDATE messages SET taken_at = 1 WHERE id = ?1 AND taken_at IS NULL", rusqlite::params![id]).unwrap();
        }
        seen.extend(new);
    }
}

/// #475: each of the previous build's queries, over a ledger this build wrote, sees only rows of
/// the kinds it handles.
#[test]
fn the_previous_builds_queries_see_only_rows_they_handle() {
    for q in PREVIOUS {
        let l = Ledger::open_in_memory().unwrap();
        let rows = written(&l, "run_1");
        // `requeue_prompts` reads what was handed out: every row, delivered.
        l.conn.execute("UPDATE messages SET delivered_at = 1 WHERE ?1 = 'requeue_prompts'", rusqlite::params![q.what]).unwrap();
        for id in read(&l, q.sql, "run_1") {
            let kind = rows.iter().find(|(i, _)| *i == id).map(|(_, k)| *k).unwrap_or("?");
            assert!(q.handles.contains(&kind), "the previous build's {} reads {id}, a {kind}: not an expand step (#475)", q.what);
        }
    }
}

/// #475's failure, as this test would have caught it: schema 16's `await_message` took schema 17's
/// prompts and notices as peers' messages, and dropped them, unsigned.
#[test]
fn schema_16s_take_would_have_taken_a_prompt() {
    let l = Ledger::open_in_memory().unwrap();
    let rows = written(&l, "run_1");
    let taken = read(&l, SCHEMA_16_TAKE, "run_1");
    assert!(taken.iter().any(|id| rows.iter().any(|(i, k)| i == id && *k != KIND_MESSAGE)));
}
