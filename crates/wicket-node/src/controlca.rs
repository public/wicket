//! Renewing a node's CA over its control channel (#416), the control host's side. The node's side
//! is `nodesrv/nodeca.rs`.
//!
//! The node CA (an intermediate under the installation CA, name-constrained to the node's hosts,
//! `enrol.rs`) is short-lived. Like the node's identity certificate (`nodeauth.rs`), it is renewed
//! by whichever of its runs is connected, once past half its life, on the same once-a-second check:
//!
//! 1. the control host asks for a new key ([`Msg::CaRenew`]); the node makes one and answers with
//!    its signing request ([`Msg::CaCsr`]);
//! 2. the control host signs it with the installation CA, for the hosts and lifetime of the CA it
//!    replaces ([`Msg::NodeCa`]);
//! 3. the node checks it (its own key, this installation's root, unexpired), installs it and swaps
//!    it in for every box it runs, running ones included ([`Msg::NodeCaInstalled`]);
//! 4. then the ledger records it, revoking the CA it replaced early (`node.ca_renewed`).
//!
//! A node that was unreachable until its CA expired is renewed the same way once a run connects to
//! it; a box start waits for that (a box on an expired CA is refused by the node). A node on
//! protocol 13 isn't asked: `wicket node renew-ca` renews it over ssh, as before. The control host's
//! own node renews its CA itself (`localnode.rs`).

use crate::chan::{Msg, CA_RENEWAL};
use anyhow::Context;
use std::sync::Mutex;
use wicket_core::TenantId;
use wicket_proxy::ca::{InstallationCa, NodeCaCert};
use wicket_store::{Ledger, NodeCaRow};

/// An unanswered step is given up after this long (s), and a failed one retried after this.
const STEP_SECS: i64 = 60;

/// A renewal is due once the active CA is past half its life (or has expired).
pub fn due(ca: &NodeCaRow, now: i64) -> bool {
    now >= ca.issued_at + (ca.not_after - ca.issued_at) / 2
}

/// The node's active CA in the ledger.
pub fn active(ledger: &Ledger, node: &str) -> Option<NodeCaRow> {
    ledger.node_cas(node).ok()?.into_iter().find(|c| c.status == "active")
}

enum Step {
    Asked { at: i64 },
    Sent { at: i64, cert: NodeCaCert },
}

/// One connection's renewal of its node's CA.
#[derive(Default)]
pub struct CaRenewal {
    step: Option<Step>,
    after: i64,
}

impl CaRenewal {
    /// A new connection: nothing under way on it.
    pub fn reset(&mut self) {
        self.step = None;
    }

    /// Checked every second: the request to send, if a renewal is due and none is under way.
    pub fn tick(&mut self, ledger: &Mutex<Ledger>, node: &str, proto: u32, now: i64) -> Option<Msg> {
        if proto < CA_RENEWAL || node == crate::LOCAL_NODE {
            return None;
        }
        match &self.step {
            Some(Step::Asked { at } | Step::Sent { at, .. }) if now - at < STEP_SECS => return None,
            Some(_) => {
                say!("[wicket] node {node} did not answer its CA renewal; trying again");
                self.step = None;
                self.after = now;
            }
            None => {}
        }
        if now < self.after || !active(&ledger.lock().expect("ledger"), node).is_some_and(|c| due(&c, now)) {
            return None;
        }
        self.step = Some(Step::Asked { at: now });
        Some(Msg::CaRenew {})
    }

    /// The node's signing request: its certificate to send, signed by `ca` (the installation CA).
    pub fn on_csr(
        &mut self,
        ledger: &Mutex<Ledger>,
        ca: Option<&InstallationCa>,
        node: &str,
        csr: Option<String>,
        error: Option<String>,
        now: i64,
    ) -> Option<Msg> {
        if !matches!(self.step, Some(Step::Asked { .. })) {
            return None;
        }
        let signed = (|| {
            let csr = csr.with_context(|| error.unwrap_or_else(|| "no signing request".into()))?;
            let ca = ca.context("this control host has no installation CA")?;
            let current = active(&ledger.lock().expect("ledger"), node).context("the node has no active CA in the ledger")?;
            // The same name constraints as the CA it replaces (stored as subtrees: `.d` is `*.d`),
            // and the same lifetime.
            let hosts: Vec<String> =
                current.hosts.iter().map(|h| h.strip_prefix('.').map(|d| format!("*.{d}")).unwrap_or_else(|| h.clone())).collect();
            let ttl = time::Duration::seconds((current.not_after - current.issued_at).clamp(300, 30 * 86_400));
            ca.issue_node_ca(&csr, node, &hosts, ttl)
        })();
        match signed {
            Ok(cert) => {
                let pem = cert.pem.clone();
                self.step = Some(Step::Sent { at: now, cert });
                Some(Msg::NodeCa { pem })
            }
            Err(e) => {
                say!("[wicket] could not renew node {node}'s CA: {e:#}; retrying in a minute");
                self.step = None;
                self.after = now + STEP_SECS;
                None
            }
        }
    }

    /// The node's answer to the certificate: recorded (and audited) once it is the node's CA.
    /// Returns the new CA's row.
    pub fn on_installed(&mut self, ledger: &Mutex<Ledger>, node: &str, serial: &str, error: Option<String>, now: i64) -> Option<NodeCaRow> {
        let Some(Step::Sent { cert, .. }) = self.step.take() else { return None };
        if let Some(e) = error.or_else(|| (serial != cert.serial).then(|| format!("it installed {serial}, not {}", cert.serial))) {
            say!("[wicket] node {node} did not take its renewed CA ({e}); retrying in a minute");
            self.after = now + STEP_SECS;
            return None;
        }
        let row = NodeCaRow {
            serial: cert.serial.clone(),
            node: node.into(),
            issued_at: now,
            not_after: cert.not_after,
            hosts: cert.permitted.clone(),
            status: "active".into(),
        };
        let mut l = ledger.lock().expect("ledger");
        let recorded = l.replace_node_ca(&row).map_err(anyhow::Error::from).and_then(|revoked| {
            l.audit(
                &TenantId::single(),
                None,
                "node.ca_renewed",
                &serde_json::json!({ "name": node, "ca_serial": cert.serial, "ca_not_after": cert.not_after, "hosts": cert.permitted,
                                     "revoked": revoked, "via": "channel" }),
            )?;
            Ok(())
        });
        match recorded {
            Ok(()) => {
                say!("[wicket] node {node}'s CA renewed over the channel: serial {} until {}", cert.serial, cert.not_after);
                Some(row)
            }
            Err(e) => {
                // The node has the CA; the ledger doesn't say so. Renewed again in a minute, so it does.
                say!("[wicket] node {node} took its renewed CA {}, but recording it failed: {e:#}", cert.serial);
                self.after = now + STEP_SECS;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodeauth::testkit::Install;

    fn ca_of(l: &Mutex<Ledger>) -> NodeCaRow {
        active(&l.lock().unwrap(), "n1").unwrap()
    }

    #[test]
    fn a_ca_is_renewed_once_past_half_its_life_and_recorded_once_installed() {
        let i = Install::new("ca-renew");
        let root = InstallationCa::generate().unwrap();
        let mut r = CaRenewal::default();
        // The CA a node enrolled with `--hosts api.example.com,*.example.org` has: issued now, for an hour.
        let t0 = wicket_store::now();
        let enrolled = NodeCaRow {
            serial: "ca2".into(),
            node: "n1".into(),
            issued_at: t0,
            not_after: t0 + 3600,
            hosts: vec!["api.example.com".into(), ".example.org".into()],
            status: "active".into(),
        };
        i.ledger.lock().unwrap().renew_node_ca(&enrolled).unwrap();
        let c = ca_of(&i.ledger);
        let now = c.issued_at;
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + 1799).is_none());
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL - 1, now + 1800).is_none(), "a node at 13 isn't asked");
        assert!(r.tick(&i.ledger, crate::LOCAL_NODE, CA_RENEWAL, now + 7200).is_none(), "the local node renews itself");
        assert_eq!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + 1800), Some(Msg::CaRenew {}));
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + 1801).is_none(), "one at a time");
        // The node refused (another renewal under way): retried a minute later.
        assert!(r.on_csr(&i.ledger, Some(&root), "n1", None, Some("busy".into()), now + 1802).is_none());
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + 1803).is_none());
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + 1802 + STEP_SECS).is_some());
        let t = now + 1900;
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let Some(Msg::NodeCa { pem }) = r.on_csr(&i.ledger, Some(&root), "n1", Some(csr), None, t) else { panic!("no certificate") };
        let ca = wicket_proxy::ca::NodeCa::load_any(&pem, &key.serialize_pem()).unwrap();
        // The node refused it: nothing recorded.
        assert!(r.on_installed(&i.ledger, "n1", "", Some("no".into()), t).is_none());
        assert_eq!(ca_of(&i.ledger).serial, c.serial);
        // Again, and taken.
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, t + STEP_SECS).is_some());
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let Some(Msg::NodeCa { pem }) = r.on_csr(&i.ledger, Some(&root), "n1", Some(csr), None, t + STEP_SECS) else { panic!() };
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let serial = hex::encode(p.parse_x509().unwrap().raw_serial());
        assert!(r.on_installed(&i.ledger, "n1", "someone-else", None, t + STEP_SECS).is_none(), "not the one sent");
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, t + 2 * STEP_SECS).is_some());
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let Some(Msg::NodeCa { pem }) = r.on_csr(&i.ledger, Some(&root), "n1", Some(csr), None, t + 2 * STEP_SECS) else { panic!() };
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let serial2 = hex::encode(p.parse_x509().unwrap().raw_serial());
        assert_ne!(serial, serial2);
        let row = r.on_installed(&i.ledger, "n1", &serial2, None, t + 2 * STEP_SECS).unwrap();
        // The same lifetime (an hour) and constraints, recorded active; the old one revoked early.
        assert_eq!(ca_of(&i.ledger).serial, serial2);
        assert!((3590..=3600).contains(&(row.not_after - wicket_store::now())), "{row:?}");
        assert_eq!(ca.permitted, [".example.org", "api.example.com"], "the constraints it had");
        assert_eq!(row.hosts, ca.permitted);
        let l = i.ledger.lock().unwrap();
        assert_eq!(l.revoked_node_cas(t).unwrap().iter().map(|c| c.serial.clone()).collect::<Vec<_>>(), std::slice::from_ref(&c.serial));
        drop(l);
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, t + 3 * STEP_SECS).is_none(), "renewed: not due");
    }

    #[test]
    fn an_unanswered_renewal_is_given_up_and_asked_again() {
        let i = Install::new("ca-renew-lost");
        let mut r = CaRenewal::default();
        let now = ca_of(&i.ledger).not_after; // expired: due at once (a node back after its CA's end)
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now).is_some());
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + STEP_SECS - 1).is_none());
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + STEP_SECS).is_some());
        // A reconnect forgets what was asked on the old connection.
        r.reset();
        assert!(r.tick(&i.ledger, "n1", CA_RENEWAL, now + STEP_SECS + 1).is_some());
        // An answer nothing asked for is ignored.
        let mut fresh = CaRenewal::default();
        assert!(fresh.on_csr(&i.ledger, None, "n1", Some("x".into()), None, now).is_none());
        assert!(fresh.on_installed(&i.ledger, "n1", "x", None, now).is_none());
    }
}
