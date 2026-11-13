//! `wicket dev`: development helpers.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Dev { cmd: DevCmd::MockLlm { listen, command } } => mock::serve(&listen, &command).await,
        Cmd::Dev { cmd: DevCmd::NodeFeedProbe { dir } } => {
            for r in nodesrv::probe_tamper(dir).await? {
                println!("{r}");
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum DevCmd {
    /// On a node: send `node serve` its own last freshness statement, tampered and then replayed, and
    /// print how each was refused (a check for ci/node-e2e.sh). The control connection stays up.
    NodeFeedProbe {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// A scripted stand-in for the Anthropic Messages API: the first turn runs one Bash command,
    /// the second ends the conversation. Lets the whole path be tested without an API key.
    MockLlm {
        #[arg(long, default_value = "127.0.0.1:9999")]
        listen: String,
        /// The Bash command the mock model asks the agent to run.
        #[arg(long)]
        command: String,
    },
}
