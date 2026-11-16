//! `wicket run`, `wrap`, `attach`, `session`, `hibernate`, `wake` and `agents`: starting and steering runs.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Run { manifest, workdir, workspace_dir, task, image, node, ssh_key, run_id } => {
            run::run(run::RunOpts {
                manifest: &manifest,
                workdir: workdir.as_deref(),
                workspace_dir: workspace_dir.as_deref(),
                task,
                image: image.as_deref(),
                node: node.as_deref(),
                ssh_key: ssh_key.as_deref(),
                run_id,
                parent_run: None,
                lease: None,
                wrap: None,
                wake: None,
                attach: false,
                adopt: None,
                stop: None,
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
                stop: None,
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
            stop: None,
        })
        .await
        .inspect_err(|e| run::attach_failed(&run, e)),
        Cmd::Session { run, text, no_wait, timeout } => {
            let text = text.join(" ");
            let text = (!text.trim().is_empty()).then_some(text);
            if no_wait && text.is_none() {
                bail!("--no-wait needs a prompt to send");
            }
            session::open(session::Opts { run, text, wait: !no_wait, timeout: timeout.map(std::time::Duration::from_secs) }).await
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
