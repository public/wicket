//! `wicket capacity` (#713): standing capacity grants (#256) from the host, as the console's
//! Capacity card has them. A grant lets a principal lease nodes up to its terms without asking.
//!
//! - **The same paths as the card.** Issuing and renewing go through [`grant::issue_capacity_grant`]
//!   and [`grant::decide`], which check the operator's authority (`operators.yaml`, kind
//!   `capacity`) and audit the decision. Revoking goes through [`grant::revoke_capacity_grant`].
//!   Their terms, lifetimes and principals are read by the card's own checks
//!   ([`capacity::principal`], [`capacity::check_ttl`], [`capacity::live_grant`]).
//! - **One shape.** `list --json` prints the card's grants ([`capacity::view_of`]).

use crate::serve::capacity;
use crate::*;
use wicket_placement::MicroUsd;
use wicket_store::CapacityTerms;

#[derive(Subcommand)]
pub enum CapacityCmd {
    /// Capacity grants, newest first, with what their uses take and leave. Only live ones unless --all.
    List {
        /// Also revoked and expired grants.
        #[arg(long)]
        all: bool,
        /// Print JSON (docs/reference/cli.md, "Output for scripts"), as the console's Capacity card has them.
        #[arg(long)]
        json: bool,
    },
    /// Issue a capacity grant: the principal may lease nodes within these terms without asking, until
    /// it lapses (at most 24h; renew it for longer). Audited as a decision, like the console's.
    Grant {
        /// Who may use it: an identity (`spiffe://…`), or an operator as `unix/<user>` or `passkey/<name>`.
        principal: String,
        /// How many nodes it covers at once.
        #[arg(long)]
        nodes: u32,
        /// The most its nodes may cost an hour together, in dollars (e.g. 0.05).
        #[arg(long)]
        max_hourly_usd: String,
        /// The most its nodes may cost a day together, in dollars.
        #[arg(long)]
        max_daily_usd: String,
        /// The provider plans it covers (comma-separated, e.g. vc2-1c-2gb).
        #[arg(long, value_delimiter = ',', required = true)]
        plans: Vec<String>,
        /// The regions it covers (comma-separated, e.g. lhr).
        #[arg(long, value_delimiter = ',', required = true)]
        regions: Vec<String>,
        /// How long it lasts.
        #[arg(long, default_value = "8h", value_parser = wicket_core::time::duration_arg)]
        ttl: Duration,
    },
    /// Renew a live capacity grant: it lasts --ttl from now (at most 24h).
    Renew {
        id: String,
        #[arg(long, default_value = "8h", value_parser = wicket_core::time::duration_arg)]
        ttl: Duration,
    },
    /// Revoke a capacity grant: nothing more is approved under it. Nodes already made under it keep
    /// their own leases.
    Revoke { id: String },
}

fn dollars(flag: &str, s: &str) -> Result<i64> {
    let m = MicroUsd::parse_dollars(s).ok_or_else(|| wicket_home::exit::usage(format!("--{flag}: {s:?} is not a dollar amount")))?;
    i64::try_from(m.0).map_err(|_| wicket_home::exit::usage(format!("--{flag}: too large")))
}

fn ttl_secs(ttl: Duration) -> Result<u64> {
    capacity::check_ttl(ttl.as_secs()).map_err(wicket_home::exit::usage)
}

/// A grant that isn't live, as the exit kinds say it.
fn not_live((status, m): (http::StatusCode, String)) -> anyhow::Error {
    match status {
        http::StatusCode::NOT_FOUND => wicket_home::exit::not_found(m),
        http::StatusCode::CONFLICT => wicket_home::exit::refused(m),
        _ => anyhow::anyhow!(m),
    }
}

/// One line for `wicket capacity list`.
pub(super) fn line(v: &serde_json::Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let t = &v["terms"];
    let any = |k: &str| t[k].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(",");
    format!(
        "{}  {:<7}  {}  {} node(s) at once (left {}), {}/h (left {}), {} a day (left {}), plans {}, regions {}, until {}",
        s("id"),
        s("state"),
        s("principal"),
        t["nodes"],
        v["left"]["nodes"],
        t["hourly_usd"].as_str().unwrap_or(""),
        v["left"]["hourly_usd"].as_str().unwrap_or(""),
        t["daily_usd"].as_str().unwrap_or(""),
        v["left"]["daily_usd"].as_str().unwrap_or(""),
        any("plans"),
        any("regions"),
        wicket_core::time::unix_rfc3339(v["expires_at"].as_i64().unwrap_or(0)),
    )
}

pub async fn dispatch(c: CapacityCmd) -> Result<()> {
    let t = TenantId::single();
    let human = || -> Result<grant::Granter> { Ok(grant::Granter::Human(crate::operators::Operator::cli(&t.0)?)) };
    match c {
        CapacityCmd::List { all, json } => {
            let l = Ledger::open(&ledger_path())?;
            let rows = capacity::view_of(&l, &t.0, all)?;
            if json {
                return crate::cmd::print_json(&rows.into());
            }
            if rows.is_empty() {
                println!("no capacity grants");
            }
            for r in &rows {
                println!("{}", line(r));
            }
            Ok(())
        }
        CapacityCmd::Grant { principal, nodes, max_hourly_usd, max_daily_usd, plans, regions, ttl } => {
            let p = capacity::principal(&t.0, &principal).map_err(wicket_home::exit::usage)?;
            let clean = |v: Vec<String>| v.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            let terms = CapacityTerms {
                plans: clean(plans),
                regions: clean(regions),
                hourly: dollars("max-hourly-usd", &max_hourly_usd)?,
                daily: dollars("max-daily-usd", &max_daily_usd)?,
                nodes,
            };
            terms.check().map_err(wicket_home::exit::usage)?;
            let secs = ttl_secs(ttl)?;
            let mut l = Ledger::open(&ledger_path())?;
            let id = grant::issue_capacity_grant(
                &mut l,
                &human()?,
                &t,
                &p,
                &terms,
                Duration::from_secs(secs),
                serde_json::json!({ "via": "cli" }),
            )?;
            let g = l.capacity_grant(&id)?.context("the grant just issued")?;
            println!(
                "capacity grant {id} to {p}: {} node(s) at once, {}/h, {} a day, until {}",
                terms.nodes,
                capacity::usd(terms.hourly),
                capacity::usd(terms.daily),
                wicket_core::time::unix_rfc3339(g.expires_at)
            );
            Ok(())
        }
        CapacityCmd::Renew { id, ttl } => {
            let secs = ttl_secs(ttl)?;
            let mut l = Ledger::open(&ledger_path())?;
            let g = capacity::live_grant(&l, &t.0, &id).map_err(not_live)?;
            let grant::Decided::Renewed { until, .. } = grant::decide(
                &mut l,
                &human()?,
                &g.id,
                &grant::Verdict::Renew(Duration::from_secs(secs)),
                serde_json::json!({ "via": "cli", "previous_until": g.expires_at }),
            )?
            else {
                unreachable!("a renewal renews")
            };
            println!("renewed capacity grant {id} until {}", wicket_core::time::unix_rfc3339(until));
            Ok(())
        }
        CapacityCmd::Revoke { id } => {
            let l = Ledger::open(&ledger_path())?;
            grant::revoke_capacity_grant(&l, &operator(), &t, &id, serde_json::json!({ "via": "cli" }))?;
            println!("revoked capacity grant {id}: nothing more is approved under it");
            Ok(())
        }
    }
}
