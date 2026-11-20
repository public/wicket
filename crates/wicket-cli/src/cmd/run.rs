//! `wicket run`, `wrap`, `attach`, `session`, `hibernate`, `wake`, `agents` and `why-here`: starting and steering runs.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Run { manifest, workdir, workspace_dir, task, image, node, ssh_key, run_id } => ended(
            run::run_to_end(run::RunOpts {
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
            .await,
            false,
        ),
        Cmd::Wrap { manifest, image, argv } => ended(
            run::run_to_end(run::RunOpts {
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
            .await,
            true,
        ),
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
                return Err(wicket_home::exit::usage("--no-wait needs a prompt to send"));
            }
            session::open(session::Opts { run, text, wait: !no_wait, timeout }).await
        }
        // Whole seconds, rounded up: a wait under a second is still a wait.
        Cmd::Hibernate { run, wait } => hibernate::hibernate(&run, wait.as_millis().div_ceil(1000) as u64).await,
        Cmd::Wake { agent, text, by, wait } => {
            let text = text.join(" ");
            hibernate::wake(&agent, (!text.trim().is_empty()).then_some(text), by, wait).await
        }
        Cmd::Agents { json } => hibernate::list(json),
        Cmd::WhyHere { run, json } => wicket_control::whyhere::why_here(&run, json),
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

/// How `wicket run` and `wicket wrap` end (#574; docs/reference/cli.md): 0 if the box succeeded
/// (or hibernated); 1 if it failed (a non-zero exit, out of memory, over a cap) or timed out; 6 if
/// it was revoked; 128 + the signal if the run was interrupted (130 for Ctrl-C, 143 for SIGTERM).
/// `wicket wrap` exits with the wrapped program's own code when it failed by exiting with one. The
/// run's status line is printed already.
fn ended(r: Result<run::RunEnd>, wrap: bool) -> Result<()> {
    exit_for(&r?, wrap)
}

fn exit_for(end: &run::RunEnd, wrap: bool) -> Result<()> {
    use wicket_home::exit::{Code, Exit, Status};
    if let Some(sig) = end.signal {
        return Err(Status(128 + sig).into());
    }
    if end.status == "revoked" {
        return Err(Exit { code: Code::Revoked, msg: "the run was revoked".into() }.into());
    }
    // The wrapped program's own code, when it exited by itself with one: not a box wicket stopped
    // (timeout, hibernate, superseded, or its node: authority, backstop, out of memory), whose code
    // is the stop's.
    if wrap && exited_by_itself(&end.status) {
        if let Some(c) = end.code.filter(|c| *c != 0) {
            return Err(Status(c).into());
        }
    }
    match run::box_failed(&end.status) {
        true => bail!("the run ended: {}", end.status),
        false => Ok(()),
    }
}

/// Whether a failed run's box exited by itself: `failed (exit status: N)`, or with a cause that
/// isn't wicket's (a crash, a signal from elsewhere). Not when its node stopped it (`stopped by
/// wicket: …`), the kernel killed it for memory (`killed: …`), or the runtime failed: those codes
/// are the stop's, not the program's.
fn exited_by_itself(status: &str) -> bool {
    let Some(rest) = status.strip_prefix("failed (exit status") else { return false };
    match rest.split_once("; ") {
        None => true,
        Some((_, cause)) => !["stopped by wicket", "killed:", "the container runtime failed"].iter().any(|p| cause.starts_with(p)),
    }
}

#[cfg(test)]
mod tests {
    use super::exit_for;
    use wicket_control::run::RunEnd;

    /// #574: what `wicket run` and `wicket wrap` exit with, by how the run ended.
    #[test]
    fn a_run_exits_by_how_its_box_ended() {
        let end = |status: &str, signal: Option<i32>, code: Option<i32>| RunEnd { status: status.into(), signal, code };
        let exit = |e: &RunEnd, wrap: bool| exit_for(e, wrap).map_or_else(|e| wicket_home::exit::status_of(&e), |_| 0);
        let failed = end("failed (exit status: 3)", None, Some(3));
        assert_eq!(exit(&end("succeeded", None, Some(0)), false), 0);
        assert_eq!(exit(&end("hibernated", None, Some(0)), false), 0);
        assert_eq!(exit(&failed, false), 1);
        assert_eq!(exit(&end("failed (exit status: 137; out of memory)", None, Some(137)), false), 1);
        // A box wicket stopped has the stop's code (the node always reports one: 255 if it never did).
        assert_eq!(exit(&end("timeout", None, Some(137)), false), 1);
        assert_eq!(exit(&end("revoked", None, Some(137)), false), 6);
        assert_eq!(exit(&end("interrupted", Some(libc::SIGINT), Some(130)), false), 130);
        assert_eq!(exit(&end("interrupted", Some(libc::SIGTERM), Some(143)), false), 143);
        // wrap passes the program's own code on, only when it exited by itself with one.
        assert_eq!(exit(&failed, true), 3);
        assert_eq!(exit(&end("succeeded", None, Some(0)), true), 0);
        assert_eq!(exit(&end("timeout", None, Some(143)), true), 1);
        assert_eq!(exit(&end("hibernated", None, Some(137)), true), 0);
        assert_eq!(exit(&end("superseded", None, Some(255)), true), 0);
        assert_eq!(exit(&end("failed (/tmp over its cap)", None, Some(137)), true), 1);
        // A box its node stopped, or the kernel killed for memory: wicket's stop, 1.
        assert_eq!(exit(&end("failed (exit status: 137; stopped by wicket: past its timeout (30m))", None, Some(137)), true), 1);
        assert_eq!(exit(&end("failed (exit status: 137; stopped by wicket: its authority expired)", None, Some(137)), true), 1);
        assert_eq!(exit(&end("failed (exit status: 137; killed: out of memory (limit 512 MiB))", None, Some(137)), true), 1);
        assert_eq!(exit(&end("failed (exit status: 125; the container runtime failed: x)", None, Some(125)), true), 1);
        // A crash or a signal from elsewhere is the program's own end: its code.
        assert_eq!(exit(&end("failed (exit status: 139; crashed: signal 11 (SIGSEGV))", None, Some(139)), true), 139);
    }
}
