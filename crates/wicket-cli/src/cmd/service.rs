//! `wicket service`: per-node services (#579 step 3), installed by an operator and kept running by
//! `wicket reconcile` on every node whose boxes use them (`zone.uses`).
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    let Cmd::Service { cmd } = c else { unreachable!("dispatched to the wrong command group") };
    let l = Ledger::open(&ledger_path())?;
    match cmd {
        ServiceCmd::Add { manifest } => {
            // A snapshot wicket owns: what starts from now on, whatever happens to `manifest`.
            let snap = wicket_control::services::snapshot(&manifest, &data_dir())?;
            let m = &snap.manifest;
            let s = m.service.as_ref().expect("a snapshot is a service");
            let name = &m.program.as_ref().expect("a service is a program").name;
            let by = operator();
            // The row and its audit record in one transaction: both, or neither.
            l.immediate::<_, anyhow::Error>(|l| {
                let replaced = l.add_service(name, &snap.path.display().to_string(), &snap.sha256, &m.tenant.0, &by)?;
                l.audit(
                    &m.tenant,
                    None,
                    "service.added",
                    &serde_json::json!({
                        "name": name, "from": manifest.display().to_string(), "snapshot": snap.path.display().to_string(),
                        "sha256": snap.sha256, "replaced": replaced, "tenancy": s.tenancy, "public_only": s.public_only,
                        "port": s.port, "reach": m.zone.reach, "env": s.env, "by": by,
                    }),
                )?;
                Ok(())
            })?;
            println!(
                "service {name} installed from a snapshot ({}, sha256 {}): one instance {} on each node whose boxes use it \
                 (zone.uses: [{name}]), started by wicket reconcile. Changing it takes another wicket service add.",
                snap.path.display(),
                &snap.sha256[..12],
                if s.tenancy == wicket_core::service::Tenancy::Shared { "shared by every tenant" } else { "per tenant" }
            );
            Ok(())
        }
        ServiceCmd::Remove { name } => {
            let n = wicket_control::services::remove(&l, &name, &operator())?;
            println!("service {name} removed: {n} instance(s) stopped, and no new one starts");
            Ok(())
        }
        ServiceCmd::List => {
            let services = l.services()?;
            if services.is_empty() {
                println!("no services installed (wicket service add <manifest>)");
            }
            for s in services {
                println!("{}  sha256 {}  {}  (added by {})", s.name, &s.sha256[..s.sha256.len().min(12)], s.manifest, s.added_by);
            }
            Ok(())
        }
    }
}

#[derive(Subcommand)]
pub enum ServiceCmd {
    /// Install a per-node service: a program manifest with a `service:` section. Its manifest and
    /// source are copied into wicket's data directory and pinned: what was there when it was added
    /// is what runs. Adding again replaces it (audited).
    Add { manifest: PathBuf },
    /// Uninstall one: its instances stop, and no new one starts.
    Remove { name: String },
    /// The installed services.
    List,
}
