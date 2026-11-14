//! `wicket run`, `wrap`, `attach`, `say`, `hibernate`, `wake` and `agents`: starting and steering runs.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Run { manifest, workdir, workspace_dir, task, image, node, ssh_key, run_id, parent_run, lease, adopt } => {
            let adopt = match adopt {
                Some(a) => {
                    let (at, session) = a.split_once(':').context("--adopt <started ms>:<session id>")?;
                    Some((at.parse::<i64>().context("--adopt: started ms")?, session.to_string()))
                }
                None => None,
            };
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: workdir.as_deref(),
                workspace_dir: workspace_dir.as_deref(),
                task,
                image: image.as_deref(),
                node: node.as_deref(),
                ssh_key: ssh_key.as_deref(),
                run_id,
                parent_run,
                lease,
                wrap: None,
                wake: None,
                attach: false,
                adopt,
            })
            .await
        }
        Cmd::Wrap { manifest, image, argv } => {
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: None,
                workspace_dir: None,
                task: None,
                image: image.as_deref(),
                node: None,
                ssh_key: None,
                run_id: None,
                parent_run: None,
                lease: None,
                wrap: Some(argv),
                wake: None,
                attach: false,
                adopt: None,
            })
            .await
        }
        Cmd::Attach { run } => run::run(run::RunOpts {
            manifest: std::path::Path::new("(the run's record)"),
            workdir: None,
            workspace_dir: None,
            task: None,
            image: None,
            node: None,
            ssh_key: None,
            run_id: Some(run.clone()),
            parent_run: None,
            lease: None,
            wrap: None,
            wake: None,
            attach: true,
            adopt: None,
        })
        .await
        .inspect_err(|e| run::attach_failed(&run, e)),
        Cmd::Say { run, text } => {
            let text = text.join(" ");
            if text.trim().is_empty() {
                bail!("nothing to say");
            }
            let l = Ledger::open(&ledger_path())?;
            // A long-lived agent is reached through its current run; a hibernated one is woken, and
            // the message is its first turn.
            let mut run = run;
            if l.run_status(&run)?.as_deref() != Some("running") {
                if let Ok(a) = hibernate::resolve(&l, &run) {
                    match a.state.as_str() {
                        "hibernated" if a.restorable => {
                            if let Some(why) = hibernate::exhausted(&a) {
                                bail!("agent {} is hibernated and can't be woken: {why}", a.id);
                            }
                            l.add_operator_message(&a.id, &text, &operator())?;
                            l.audit(
                                &TenantId::single(),
                                None,
                                "operator.message",
                                &serde_json::json!({ "by": operator(), "chars": text.len(), "agent": a.id, "wakes": true }),
                            )?;
                            hibernate::trigger_wake(&a.id, &format!("wicket say by {}", operator()));
                            println!(
                                "agent {} is hibernated: waking it; the message is its first turn (log: {})",
                                a.id,
                                hibernate::agent_dir(&a.id).join("wake.log").display()
                            );
                            return Ok(());
                        }
                        "active" | "waking" | "hibernating" => run = a.run,
                        s => bail!("agent {} is {s}", a.id),
                    }
                }
            }
            match l.run_status(&run)?.as_deref() {
                Some("running") => {}
                Some(s) => bail!("{run} is {s}, not running"),
                None => bail!("no run {run}"),
            }
            l.add_operator_message(&run, &text, &operator())?;
            l.audit(
                &TenantId::single(),
                Some(&wicket_core::RunId(run.clone())),
                "operator.message",
                &serde_json::json!({ "by": operator(), "chars": text.len() }),
            )?;
            println!("queued for {run}: the agent gets it within a second (as its next turn, or queued behind the current one)");
            Ok(())
        }
        Cmd::Hibernate { run, wait } => hibernate::hibernate(&run, wait).await,
        Cmd::Wake { agent, text, by } => {
            let text = text.join(" ");
            hibernate::wake(&agent, (!text.trim().is_empty()).then_some(text), by).await
        }
        Cmd::Agents { json } => hibernate::list(json),
        _ => unreachable!("dispatched to the wrong command group"),
    }
}
