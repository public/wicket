//! `wicket self`: updates, rollbacks, versions and release keys.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Itself { cmd } => match cmd {
            SelfCmd::Status => update::status(),
            SelfCmd::Follow => ci_update::follow().await,
            SelfCmd::Update { artifact, from_ci, sig, nodes, only_nodes, window, interval, check, canary, image, no_prune } => {
                let gate = update::Gate {
                    window: humantime::parse_duration(&window).context("bad --window")?,
                    interval: humantime::parse_duration(&interval).context("bad --interval")?.max(Duration::from_secs(1)),
                    checks: check,
                    canary,
                    image,
                };
                match (from_ci, artifact) {
                    (Some(target), _) => ci_update::update_from_ci(&target, nodes, only_nodes, gate, !no_prune).await,
                    (None, Some(artifact)) => {
                        update::update(update::UpdateOpts { artifact, sig, nodes, only_nodes, gate, prune: !no_prune, ci: None }).await
                    }
                    (None, None) => unreachable!("clap requires one"),
                }
            }
            SelfCmd::Rollback { nodes, only_nodes } => update::rollback(nodes, only_nodes).await,
            SelfCmd::Prune { nodes, only_nodes, keep_snapshots, dry_run } => {
                update::prune(nodes, only_nodes, keep_snapshots, dry_run).await
            }
            SelfCmd::TrustKey { public } => update::trust_key(&public),
            SelfCmd::Keygen { key } => update::keygen(&key),
            SelfCmd::Sign { key, artifact } => update::sign(&key, &artifact),
            SelfCmd::Describe => {
                #[allow(unused_mut)]
                let mut d = update::describe()?;
                // Tests only (debug builds): the protocol this build reports when staged, so
                // ci/update.sh can stage a "jump" (#207) with two builds of the same code.
                #[cfg(debug_assertions)]
                if let Some(p) = std::env::var("WICKET_TEST_DESCRIBE_PROTOCOL").ok().and_then(|p| p.parse().ok()) {
                    d.protocol = p;
                }
                println!("{}", serde_json::to_string(&d)?);
                Ok(())
            }
            SelfCmd::Health { node, canary, image } => update::health(node, canary, image).await,
            SelfCmd::Units => units::print(),
            SelfCmd::ApplyUnits { dir } => units::apply(dir),
        },
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum SelfCmd {
    /// The staged versions, which is current and previous, and the ledger's schema.
    Status,
    /// Stage an artifact (a wicket binary, or a release archive from ci/package.sh), switch the
    /// control host to it, hand its processes over, and watch it; then the nodes, a canary first.
    /// Any failed health check switches back.
    Update {
        /// The artifact: a wicket binary, or a release archive.
        #[arg(required_unless_present = "from_ci", conflicts_with = "from_ci")]
        artifact: Option<PathBuf>,
        /// A build CI signed instead (#190): a commit on main, or `latest`. Downloaded here and
        /// taken only if signed in the release environment by a trusted key, for this
        /// installation's repository (`<data dir>/ci-builds.yaml`) and that commit, on main.
        #[arg(long, value_name = "COMMIT|latest")]
        from_ci: Option<String>,
        /// The detached signature (default: <artifact>.sig).
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Also update these nodes after the control host: `all`, or names (comma-separated). The
        /// first is the canary.
        #[arg(long)]
        nodes: Option<String>,
        /// The control host already runs this build: only the nodes.
        #[arg(long, requires = "nodes")]
        only_nodes: bool,
        /// How long each new build is watched after its switch.
        #[arg(long, default_value = "30s")]
        window: String,
        /// How often within the window.
        #[arg(long, default_value = "10s")]
        interval: String,
        /// A command (sh -c) that must succeed each time; $WICKET is the new build's binary and
        /// $WICKET_UPDATE_TARGET `control` or `node:<name>`. Repeatable.
        #[arg(long)]
        check: Vec<String>,
        /// A task manifest the new build runs once on the control host; it must succeed.
        #[arg(long)]
        canary: Option<PathBuf>,
        /// The canary's image (default: the new build's own, wicket/claude-code:<build id>).
        #[arg(long)]
        image: Option<String>,
        /// Keep what the update leaves unneeded (by default it prunes as `wicket self prune` does,
        /// where it updated).
        #[arg(long)]
        no_prune: bool,
    },
    /// Update to the newest build CI signed for main, if `<data dir>/ci-builds.yaml`'s follow
    /// policy lets it now (its window, soak time, only forward along main, never across a schema
    /// contract step or a failed build). Run by the wicket-follow timer.
    Follow,
    /// Switch back to the previous version: the control host (unless --only-nodes) and these nodes.
    Rollback {
        /// `all`, or node names (comma-separated).
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long, requires = "nodes")]
        only_nodes: bool,
    },
    /// Remove what no rollback or running box needs: versions other than current and previous that
    /// no process runs, their agent images unless a container uses them, and ledger snapshots
    /// beyond the newest few (always keeping the newest of the current and previous versions').
    Prune {
        /// Also these nodes: `all`, or names (comma-separated).
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long, requires = "nodes")]
        only_nodes: bool,
        /// How many snapshots to keep.
        #[arg(long, default_value_t = update::KEEP_SNAPSHOTS)]
        keep_snapshots: usize,
        /// Say what would go; remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Trust a release public key (from `wicket self keygen`) for updates.
    TrustKey { public: PathBuf },
    /// Make a release key pair: KEY (private, keep it offline) and KEY.pub.
    Keygen { key: PathBuf },
    /// Sign an artifact with a release key: writes <artifact>.sig.
    Sign {
        #[arg(long)]
        key: PathBuf,
        artifact: PathBuf,
    },
    /// Install this build's systemd units (#165) where they differ from the installed ones, and
    /// reload systemd; restarts nothing. Run as root with the version's own binary, as a refused
    /// `self update` says: `sudo <versions>/<id>/wicket self apply-units`.
    ApplyUnits {
        /// Another units directory (default: /etc/systemd/system, which needs root).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// This build's systemd units (JSON: name to contents).
    #[command(hide = true)]
    Units,
    /// This build's version, protocol and schema (JSON).
    #[command(hide = true)]
    Describe,
    /// The health check a new build runs on itself during an update.
    #[command(hide = true)]
    Health {
        #[arg(long)]
        node: Vec<String>,
        #[arg(long)]
        canary: Option<PathBuf>,
        #[arg(long, default_value = crate::image::DEFAULT)]
        image: String,
    },
}
