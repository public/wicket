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
            let path = std::fs::canonicalize(&manifest).with_context(|| format!("reading {}", manifest.display()))?;
            let m = wicket_core::Manifest::from_yaml(&std::fs::read_to_string(&path)?)?;
            let s = m.service.as_ref().context("this manifest has no service: section: it is not a per-node service")?;
            let name = &m.program.as_ref().context("a service is a program")?.name;
            wicket_core::service::check_name(name).map_err(anyhow::Error::msg)?;
            l.add_service(name, &path.display().to_string(), &operator())?;
            l.audit(
                &m.tenant,
                None,
                "service.added",
                &serde_json::json!({ "name": name, "manifest": path.display().to_string(), "tenancy": s.tenancy, "port": s.port, "by": operator() }),
            )?;
            println!(
                "service {name} installed: one instance {} on each node whose boxes use it (zone.uses: [{name}]), started by wicket reconcile",
                if s.tenancy == wicket_core::service::Tenancy::Shared { "shared by every tenant" } else { "per tenant" }
            );
            Ok(())
        }
        ServiceCmd::Remove { name } => {
            anyhow::ensure!(l.remove_service(&name)?, "no service {name} is installed");
            l.audit(&wicket_core::TenantId::single(), None, "service.removed", &serde_json::json!({ "name": name, "by": operator() }))?;
            println!("service {name} removed: no new instance starts; running ones end with their runs");
            Ok(())
        }
        ServiceCmd::List => {
            let services = l.services()?;
            if services.is_empty() {
                println!("no services installed (wicket service add <manifest>)");
            }
            for s in services {
                println!("{}  {}  (added by {})", s.name, s.manifest, s.added_by);
            }
            Ok(())
        }
    }
}

#[derive(Subcommand)]
pub enum ServiceCmd {
    /// Install a per-node service: a program manifest with a `service:` section. Its manifest is
    /// read where it is, at each start: keep it there.
    Add { manifest: PathBuf },
    /// Uninstall one: no new instance starts.
    Remove { name: String },
    /// The installed services.
    List,
}
