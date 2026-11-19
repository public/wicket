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
//! it; a box start waits for that (a box on an expired CA is refused by the node). `wicket node
//! renew-ca` renews it over ssh instead, for a node unreachable meanwhile. The control host's own
//! node renews its CA itself (`localnode.rs`).

use crate::chan::Msg;
use anyhow::Context;
use std::sync::Mutex;
use wicket_core::TenantId;
use wicket_proxy::ca::{InstallationCa, NodeCaCert};
use wicket_store::{Ledger, NodeCaRow};

/// An unanswered step is given up after this long (s), and a failed one retried after this.
const STEP_SECS: i64 = 60;

/// The most name constraints a widened node CA carries (#573): certificate size, and what
/// verifiers take.
pub const MAX_CA_HOSTS: usize = 64;

/// What `node`'s CA should cover (#573): the hosts its operator set (`nodes.hosts`, from enrolment
/// or `wicket node renew-ca`) and the live wants its node CA policy allows, oldest first, without
/// entries another covers, at most [`MAX_CA_HOSTS`]. None: the policy is `fixed`, so the CA keeps
/// its hosts.
pub fn target(ledger: &Ledger, node: &str) -> Option<Vec<String>> {
    let policy = ledger.node_ca_policy(node).ok()?;
    if policy == wicket_store::CaHosts::Fixed {
        return None;
    }
    let base = ledger.node(node).ok()??.hosts;
    let wants = ledger.node_ca_wants(node).ok()?;
    let mut all = base;
    all.extend(wants.into_iter().map(|w| w.host).filter(|h| policy.allows(h)));
    let mut merged = wicket_core::splice::merge_subtrees(&all);
    if merged.len() > MAX_CA_HOSTS {
        say!("[wicket] node {node}'s CA would need {} name constraints; it is widened to the first {MAX_CA_HOSTS}", merged.len());
        merged.truncate(MAX_CA_HOSTS);
    }
    Some(merged)
}

/// Whether `node`'s CA leaves out a host its target has: a renewal widens it now, not at half its
/// life.
fn wants_widening(ledger: &Ledger, node: &str, ca: &NodeCaRow) -> bool {
    target(ledger, node).is_some_and(|t| !wicket_core::splice::uncovered(&ca.hosts, &t).is_empty())
}

/// A renewal is due once the active CA is past half its life (or has expired).
pub fn due(ca: &NodeCaRow, now: i64) -> bool {
    now >= ca.issued_at + (ca.not_after - ca.issued_at) / 2
}

/// The node's active CA in the ledger.
pub fn active(ledger: &Ledger, node: &str) -> Option<NodeCaRow> {
    ledger.node_cas(node).ok()?.into_iter().find(|c| c.status == "active")
}

enum Step {
    Asked {
        at: i64,
    },
    /// `before`: the hosts of the CA it replaces, for the audit of a widening.
    Sent {
        at: i64,
        cert: NodeCaCert,
        before: Vec<String>,
    },
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
        // 0: the connection hasn't negotiated a version yet. Every version it can talk renews.
        if proto == 0 || node == crate::LOCAL_NODE {
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
        let renew = {
            let l = ledger.lock().expect("ledger");
            active(&l, node).is_some_and(|c| due(&c, now) || wants_widening(&l, node, &c))
        };
        if now < self.after || !renew {
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
            let l = ledger.lock().expect("ledger");
            let current = active(&l, node).context("the node has no active CA in the ledger")?;
            // The name constraints of the CA it replaces; with #573's policy, its target: widened by
            // what its boxes want, and pruned to the target only at a due renewal (a box ending
            // doesn't renew the CA early). Stored as subtrees: `.d` is `*.d`. The same lifetime.
            let wanted = match target(&l, node) {
                None => current.hosts.clone(),
                Some(t) if due(&current, now) => t,
                Some(t) => wicket_core::splice::merge_subtrees(&[current.hosts.clone(), t].concat()),
            };
            drop(l);
            let hosts: Vec<String> =
                wanted.iter().map(|h| h.strip_prefix('.').map(|d| format!("*.{d}")).unwrap_or_else(|| h.clone())).collect();
            let ttl = time::Duration::seconds((current.not_after - current.issued_at).clamp(300, 30 * 86_400));
            ca.issue_node_ca(&csr, node, &hosts, ttl).map(|c| (c, current.hosts))
        })();
        match signed {
            Ok((cert, before)) => {
                let pem = cert.pem.clone();
                self.step = Some(Step::Sent { at: now, cert, before });
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
        let Some(Step::Sent { cert, before, .. }) = self.step.take() else { return None };
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
            // #573: what changed, and who wanted the hosts added.
            let added: Vec<&String> = cert.permitted.iter().filter(|h| !before.contains(h)).collect();
            let removed: Vec<&String> = before.iter().filter(|h| !cert.permitted.contains(h)).collect();
            if !added.is_empty() || !removed.is_empty() {
                let wants = l.node_ca_wants(node).unwrap_or_default();
                let by: Vec<_> = wants
                    .iter()
                    .filter(|w| added.iter().any(|a| **a == w.host))
                    .map(|w| serde_json::json!({ "host": w.host, "run": w.run, "why": w.why }))
                    .collect();
                l.audit(
                    &TenantId::single(),
                    None,
                    "node.ca_widened",
                    &serde_json::json!({ "name": node, "ca_serial": cert.serial, "added": added, "removed": removed, "wanted_by": by }),
                )?;
            }
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
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + 1799).is_none());
        assert!(r.tick(&i.ledger, "n1", 0, now + 1800).is_none(), "not asked before the connection talks a version");
        assert!(r.tick(&i.ledger, crate::LOCAL_NODE, crate::chan::PROTOCOL, now + 7200).is_none(), "the local node renews itself");
        assert_eq!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL - 1, now + 1800), Some(Msg::CaRenew {}), "a node at 14 is asked too");
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + 1801).is_none(), "one at a time");
        // The node refused (another renewal under way): retried a minute later.
        assert!(r.on_csr(&i.ledger, Some(&root), "n1", None, Some("busy".into()), now + 1802).is_none());
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + 1803).is_none());
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + 1802 + STEP_SECS).is_some());
        let t = now + 1900;
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let Some(Msg::NodeCa { pem }) = r.on_csr(&i.ledger, Some(&root), "n1", Some(csr), None, t) else { panic!("no certificate") };
        let ca = wicket_proxy::ca::NodeCa::load_any(&pem, &key.serialize_pem()).unwrap();
        // The node refused it: nothing recorded.
        assert!(r.on_installed(&i.ledger, "n1", "", Some("no".into()), t).is_none());
        assert_eq!(ca_of(&i.ledger).serial, c.serial);
        // Again, and taken.
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, t + STEP_SECS).is_some());
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let Some(Msg::NodeCa { pem }) = r.on_csr(&i.ledger, Some(&root), "n1", Some(csr), None, t + STEP_SECS) else { panic!() };
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let serial = hex::encode(p.parse_x509().unwrap().raw_serial());
        assert!(r.on_installed(&i.ledger, "n1", "someone-else", None, t + STEP_SECS).is_none(), "not the one sent");
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, t + 2 * STEP_SECS).is_some());
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
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, t + 3 * STEP_SECS).is_none(), "renewed: not due");
    }

    #[test]
    fn an_unanswered_renewal_is_given_up_and_asked_again() {
        let i = Install::new("ca-renew-lost");
        let mut r = CaRenewal::default();
        let now = ca_of(&i.ledger).not_after; // expired: due at once (a node back after its CA's end)
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now).is_some());
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + STEP_SECS - 1).is_none());
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + STEP_SECS).is_some());
        // A reconnect forgets what was asked on the old connection.
        r.reset();
        assert!(r.tick(&i.ledger, "n1", crate::chan::PROTOCOL, now + STEP_SECS + 1).is_some());
        // An answer nothing asked for is ignored.
        let mut fresh = CaRenewal::default();
        assert!(fresh.on_csr(&i.ledger, None, "n1", Some("x".into()), None, now).is_none());
        assert!(fresh.on_installed(&i.ledger, "n1", "x", None, now).is_none());
    }

    /// #573: a host a box wants of its node's CA widens it at once (no waiting for half its life),
    /// within the node's policy, audited with who wanted it; a due renewal prunes what no box wants.
    #[test]
    fn a_want_widens_the_ca_within_its_policy_and_a_due_renewal_prunes_it() {
        let i = Install::new("ca-widen");
        let root = InstallationCa::generate().unwrap();
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
        let p = crate::chan::PROTOCOL;
        let renew = |r: &mut CaRenewal, at: i64| -> (NodeCaRow, Vec<String>) {
            assert_eq!(r.tick(&i.ledger, "n1", p, at), Some(Msg::CaRenew {}));
            let key = rcgen::KeyPair::generate().unwrap();
            let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
            let Some(Msg::NodeCa { pem }) = r.on_csr(&i.ledger, Some(&root), "n1", Some(csr), None, at) else { panic!("no certificate") };
            let ca = wicket_proxy::ca::NodeCa::load_any(&pem, &key.serialize_pem()).unwrap();
            let (_, x) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
            let serial = hex::encode(x.parse_x509().unwrap().raw_serial());
            (r.on_installed(&i.ledger, "n1", &serial, None, at).unwrap(), ca.permitted)
        };
        let kinds = || {
            i.ledger
                .lock()
                .unwrap()
                .audit_tail(50)
                .unwrap()
                .into_iter()
                .filter(|a| a.2 == "node.ca_widened")
                .map(|a| a.4)
                .collect::<Vec<_>>()
        };
        let mut r = CaRenewal::default();
        let want = |host: &str, run: &str| {
            i.ledger.lock().unwrap().want_node_ca_hosts("n1", &[host.to_string()], run, "the box's reach", t0).unwrap()
        };
        // Fixed (no policy recorded): a want changes nothing.
        want("late.test", "run_a");
        assert!(r.tick(&i.ledger, "n1", p, t0 + 10).is_none());
        // Auto: renewed now, for the union.
        i.ledger.lock().unwrap().set_node_ca_policy("n1", &wicket_store::CaHosts::Auto).unwrap();
        let (row, permitted) = renew(&mut r, t0 + 20);
        assert_eq!(permitted, [".example.org", "api.example.com", "late.test"]);
        assert_eq!(row.hosts, permitted);
        assert_eq!(
            i.ledger.lock().unwrap().node("n1").unwrap().unwrap().hosts,
            ["api.example.com", ".example.org"],
            "the operator's hosts are kept apart"
        );
        let w = kinds();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("\"added\":[\"late.test\"]") && w[0].contains("run_a"), "{}", w[0]);
        assert!(r.tick(&i.ledger, "n1", p, t0 + 30).is_none(), "covered now");
        // An allowed list that doesn't name a want: no renewal for it.
        i.ledger.lock().unwrap().set_node_ca_policy("n1", &wicket_store::CaHosts::parse("late.test,*.example.org").unwrap()).unwrap();
        want("other.test", "run_b");
        assert!(r.tick(&i.ledger, "n1", p, t0 + 40).is_none());
        // run_a ended: at the next due renewal, late.test is pruned (other.test still kept out).
        i.ledger.lock().unwrap().drop_node_ca_wants("run_a").unwrap();
        let due = row.issued_at + (row.not_after - row.issued_at) / 2;
        let (_, permitted) = renew(&mut r, due);
        assert_eq!(permitted, [".example.org", "api.example.com"]);
        assert!(kinds().last().unwrap().contains("\"removed\":[\"late.test\"]"));
    }
}
