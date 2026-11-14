//! `wicket policy`, `state` and `keys`: the org policy, the state store and the roots.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => policy::show(),
            PolicyCmd::Check { file, entities } => {
                policy::sanity(&file)?;
                policy::check(&file, entities.as_deref())
            }
            PolicyCmd::Apply { file, entities, keep_runs } => {
                policy::sanity(&file)?;
                policy::apply(&file, entities.as_deref(), keep_runs).await
            }
            PolicyCmd::Zone { manifest } => policy::zone(&manifest),
        },
        Cmd::State { cmd } => {
            // Litestream and the store client block: off the async runtime.
            std::thread::spawn(move || match cmd {
                StateCmd::Check { probe } => state::check(probe),
                StateCmd::Replicate => state::replicate(),
                StateCmd::Kit { out, without_secrets, without_roots } => state::kit(&out, !without_secrets, !without_roots),
                StateCmd::Restore { kit, at, force } => state::restore(&kit, at.as_deref(), force),
                StateCmd::Snapshots => snapstore::print_list(),
                StateCmd::Snapshot { name, out } => snapstore::get(&name, &out),
            })
            .join()
            .map_err(|_| anyhow::anyhow!("wicket state panicked"))?
        }
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::RootsOffline { to, days } => roots::roots_offline(&to, days).await,
            KeysCmd::Certify { roots: dir } => {
                if let Some(d) = dir {
                    std::env::set_var("WICKET_ROOTS", d);
                }
                roots::certify()
            }
            KeysCmd::RootsOnline { from } => roots::roots_online(&from),
        },
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum PolicyCmd {
    /// The org policy's version, and the running runs minted under another.
    Show,
    /// Validate and compile an org policy without installing it.
    Check {
        file: PathBuf,
        /// The groups zones are in (Cedar entities JSON).
        #[arg(long)]
        entities: Option<PathBuf>,
    },
    /// Install an org policy, and revoke the running runs minted under an older version (their boxes
    /// stop; new runs get the new policy).
    Apply {
        file: PathBuf,
        #[arg(long)]
        entities: Option<PathBuf>,
        /// Leave running runs on the policy they were minted under until they end.
        #[arg(long)]
        keep_runs: bool,
    },
    /// A zone's policy as Cedar, generated from a manifest (what its boxes' tokens are compiled from).
    Zone { manifest: PathBuf },
}

#[derive(Subcommand)]
pub enum StateCmd {
    /// Where each kind of control-plane state goes (state-store.yaml).
    Check {
        /// Also write, read back and delete a probe object in the store.
        #[arg(long)]
        probe: bool,
    },
    /// Stream the ledger to the state store until stopped (Litestream): a lost control host loses
    /// at most `ledger.sync_interval`. Run it as a service beside wicketd.
    Replicate,
    /// Write a recovery kit: what a standby needs besides the state store (keys, state.key, nodes'
    /// feed keys and pinned host keys, config files, and the vault's secrets). Keep it offline.
    Kit {
        #[arg(long)]
        out: PathBuf,
        /// Leave the vault's secrets out (set them again on the standby).
        #[arg(long)]
        without_secrets: bool,
        /// Leave the roots out even if they are on this host.
        #[arg(long)]
        without_roots: bool,
    },
    /// Make this fresh host the control host: the kit's files, then the ledger from the state store
    /// (as of now, or of --at), audit records the store has beyond it, agents fenced, and each node
    /// feed set to start a new generation.
    Restore {
        #[arg(long)]
        kit: PathBuf,
        /// Restore the ledger as it was at this time (RFC 3339, UTC), discarding what came after.
        #[arg(long)]
        at: Option<String>,
        /// Replace a ledger this host already has.
        #[arg(long)]
        force: bool,
    },
    /// The ledger snapshots `wicket self update` pushed to the state store before each switch
    /// (#167): the way back past a contract step after losing the control host.
    Snapshots,
    /// Fetch one of them (unsealed with state.key) into a new file, to restore as
    /// docs/how-to/update-and-roll-back.md says.
    Snapshot {
        /// Its name, as `wicket state snapshots` lists it.
        name: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum KeysCmd {
    /// Move the feed root and the authority root off this host (to removable media, say): boxes'
    /// tokens are then minted by a certified issuing key, and certificates the roots issue last
    /// --days. Nodes pin the same keys as before.
    RootsOffline {
        #[arg(long)]
        to: PathBuf,
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
    /// With the roots' directory (--roots, or WICKET_ROOTS): renew the issuing key's and every node
    /// feed's certificate for another --days (as chosen at roots-offline), and start the new
    /// generation of any feed a restore left. Installed, the wicket user must be able to read it.
    Certify {
        #[arg(long)]
        roots: Option<PathBuf>,
    },
    /// Put the roots back on this host.
    RootsOnline {
        #[arg(long)]
        from: PathBuf,
    },
}
