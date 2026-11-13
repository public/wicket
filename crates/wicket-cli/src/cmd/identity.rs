//! `wicket identity`: the installation's issuer and runs' identities.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Identity { cmd } => {
            let l = Ledger::open(&ledger_path())?;
            match cmd {
                IdentityCmd::Init { trust_domain } => {
                    let i = wicket_identity::Issuer::load(&issuer_key_path(), Some(&trust_domain))?;
                    println!("issuer ready: {} (key {})", i.issuer_id(), wicket_identity::key_id(&i.verifying_key()));
                }
                IdentityCmd::Issuer => {
                    let i = issuer()?;
                    let mut jwk = i.public_jwk();
                    jwk["trust_domain"] = i.trust_domain.clone().into();
                    println!("{}", serde_json::to_string_pretty(&jwk)?);
                }
                IdentityCmd::Show { run } => println!("{}", serde_json::to_string_pretty(&verified_identity(&l, &run, None))?),
                IdentityCmd::Revoke { run, reason } => {
                    if l.identity(&run)?.is_none() {
                        bail!("no identity was issued for {run}");
                    }
                    let fresh = l.revoke(&run, &operator(), &reason)?;
                    l.audit(
                        &TenantId::single(),
                        Some(&wicket_core::RunId(run.clone())),
                        "identity.revoked",
                        &serde_json::json!({ "run": run, "by": operator(), "reason": reason }),
                    )?;
                    println!(
                        "{} {run}: its runner stops the box within seconds; its messages and approvals are refused",
                        if fresh { "revoked" } else { "already revoked" }
                    );
                }
                IdentityCmd::List => {
                    for row in l.identities()? {
                        let status = l.run_status(&row.run)?.unwrap_or_default();
                        println!("{}  {:<10} {}", row.run, status, identity_line(&verified_identity(&l, &row.run, None)));
                    }
                }
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Set up this installation's identity issuer: its key and its trust domain, which every agent's
    /// SPIFFE ID is under (spiffe://<domain>/t/…). The domain is fixed once set.
    Init {
        /// e.g. wicket.example.com: lowercase letters, digits, '.', '-' and '_'.
        #[arg(long)]
        trust_domain: String,
    },
    /// Print the installation issuer's public key (JWK) and trust domain: what verifiers need.
    Issuer,
    /// Verify and show the identity wicket issued for a run.
    Show { run: String },
    /// List every agent identity issued, verified.
    List,
    /// Revoke a run's identity at once (e.g. if its environment may be compromised): its box is
    /// stopped, its messages are no longer delivered, and its requests can't be approved.
    Revoke {
        run: String,
        #[arg(long, default_value = "revoked by the operator")]
        reason: String,
    },
}
