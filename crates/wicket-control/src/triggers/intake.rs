//! Webhook intake on the control host (#578 step 4; docs/explanation/trigger-intake.md).
//!
//! The control host never terminates a webhook: `wicket node intake` on an intake node does, and its
//! `node serve` spools what it verified. This side assigns a webhook trigger to an intake node
//! (minting its URL's token), tells each intake node which triggers it serves (protocol 21's
//! `IntakeSync`), and records and fires what the nodes hand back, each event only for the trigger
//! its URL named, with that trigger's owner's authority and limits.

use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wicket_core::intake::{IntakeEvent, IntakeRefused, IntakeTrigger};

/// The node label that makes a node an intake node (`wicket node set <n> --label wicket.intake=true`).
pub const INTAKE_LABEL: &str = "wicket.intake";
/// The most events one pass takes from one node (a backlog goes over several passes) …
pub const PASS_MAX_EVENTS: usize = 2000;
/// … in at most this many syncs, and this long: a slow or hostile node can't stall the pass.
pub const PASS_MAX_ROUNDS: usize = 10;
pub const PASS_NODE_SECS: u64 = 20;
/// A node's refusals are audited at most this often (s), counted.
pub const REFUSED_AUDIT_SECS: i64 = 3600;

/// Whether `s` is a source intake serves.
pub fn is_hook(s: &Source) -> bool {
    matches!(s, Source::Webhook { .. } | Source::Github { .. })
}

/// Whether node `node` is labelled for intake.
fn labelled(l: &Ledger, node: &str) -> Result<bool> {
    Ok(l.node_labels(node)?.get(INTAKE_LABEL).map(String::as_str) == Some("true"))
}

/// The intake node for a new webhook trigger of tenant `tenant`: `wanted` if it is one, else the
/// only one there is. An intake node is labelled [`INTAKE_LABEL`]`=true`, active, of the tenant,
/// and was last noted at protocol [`wicket_chan::chan::INTAKE`] or later. The local node (the
/// control host's own machine) only with `allow_local`: intake there puts internet traffic on the
/// machine with the ledger and the vault (#714 review H4).
pub fn intake_node(l: &Ledger, tenant: &str, wanted: Option<&str>, allow_local: bool) -> Result<String> {
    let mut ok = vec![];
    let mut why = vec![];
    for n in l.nodes()? {
        if n.tenant != tenant || n.status != "active" {
            continue;
        }
        if !labelled(l, &n.name)? {
            continue;
        }
        if n.name == crate::localnode::NAME && !allow_local {
            why.push(format!("{} (the control host's own machine: only with --allow-local-intake)", n.name));
            continue;
        }
        match crate::noderun::known_protocol(&n.name) {
            Some(p) if p >= wicket_chan::chan::INTAKE => ok.push(n.name),
            p => why.push(format!(
                "{} ({}; intake needs protocol {})",
                n.name,
                p.map_or("its protocol isn't known yet".to_string(), |p| format!("talks protocol {p}")),
                wicket_chan::chan::INTAKE
            )),
        }
    }
    match wanted {
        Some(w) if ok.iter().any(|n| n == w) => Ok(w.to_string()),
        Some(w) => bail!("node {w} isn't an intake node it can use{}", if why.is_empty() { String::new() } else { format!(": {}", why.join(", ")) }),
        None => match ok.as_slice() {
            [one] => Ok(one.clone()),
            [] if why.is_empty() => bail!(
                "no intake node: label one for webhook intake (wicket node set <node> --label {INTAKE_LABEL}=true) and run `wicket node intake` there"
            ),
            [] => bail!("no intake node it can use: {}", why.join(", ")),
            many => bail!("several intake nodes ({}): name one with --intake-node", many.join(", ")),
        },
    }
}

/// Gives trigger `id` a new URL token on `node`: kept as its sha256 only. The token, which goes in
/// the URL `/hook/<id>/<token>`, shown once.
pub fn assign(l: &Ledger, id: &str, node: &str) -> Result<String> {
    let token = wicket_core::intake::new_token().map_err(anyhow::Error::msg)?;
    l.set_trigger_intake(id, node, &wicket_core::intake::token_sha256(&token))?;
    Ok(token)
}

/// A new URL for trigger `id` (its old token stops working at the intake node's next sync), by its
/// owner or root: audited as `trigger.url_rotated`. The new token.
pub fn rotate_url(l: &Ledger, by: &Operator, root: bool, id: &str) -> Result<(Trigger, String, String)> {
    let t = get(l, id)?;
    owner_or_root(&t, by, root)?;
    let Some((node, _)) = l.trigger_intake(id)? else { bail!("trigger {id} has no webhook URL (its source is {})", source_text(&t.spec)) };
    let token = assign(l, id, &node)?;
    audit(
        l,
        "trigger.url_rotated",
        &json!({ "trigger": id, "name": t.name, "owner": t.owner, "by": by.label, "principal": by.id, "node": node }),
    )?;
    Ok((t, node, token))
}

/// The verify secret a hook trigger names.
fn verify_secret(s: &TriggerSpec) -> Option<&str> {
    match &s.source {
        Source::Webhook { verify } | Source::Github { verify, .. } => Some(&verify.hmac_sha256),
        _ => None,
    }
}

/// Refuses a hook trigger whose verify secret isn't one (`wicket secret verify`).
pub fn check_verify(s: &TriggerSpec, vault: &wicket_proxy::vault::Vault) -> Result<()> {
    if let Some(name) = verify_secret(s) {
        if !vault.has(name) {
            bail!("no secret {name} (store the webhook's key: wicket secret set {name}, then wicket secret verify {name})");
        }
        if !vault.is_verify(name) {
            bail!("secret {name} isn't a verify secret, so a trigger can't check deliveries with it (wicket secret verify {name})");
        }
    }
    Ok(())
}

/// The table node `node`'s intake serves: each of its triggers that isn't deleted, with its
/// token's sha256 and verify secret. A trigger whose secret doesn't read now is left out, and said.
pub fn table(l: &Ledger, node: &str, vault: &wicket_proxy::vault::Vault) -> Result<(Vec<IntakeTrigger>, Vec<String>)> {
    let mut out = vec![];
    let mut problems = vec![];
    for (id, token_sha256) in l.intake_triggers(node)? {
        let Some(t) = l.trigger(&id)? else { continue };
        let Some(name) = verify_secret(&t.spec) else { continue };
        let secret = match vault.get_verify(name) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("trigger {} ({id}): {e:#}", t.name));
                continue;
            }
        };
        let (kind, repo, events) = match &t.spec.source {
            Source::Github { repo, events, .. } => ("github", Some(repo.clone()), events.clone()),
            _ => ("webhook", None, vec![]),
        };
        out.push(IntakeTrigger { trigger: id, kind: kind.into(), token_sha256, secret, repo, events });
    }
    Ok((out, problems))
}

/// Records and fires the events node `node` handed over, at `now`. What fired (or was skipped or
/// failed), and the events to ack: every one recorded or dropped, but not one whose owner couldn't
/// be checked (it stays in the node's spool for the next pass).
pub fn ingest(
    l: &Ledger,
    node: &str,
    events: &[IntakeEvent],
    now: i64,
    wake: Waker<'_>,
    owner: OwnerCheck<'_>,
) -> Result<(Vec<Fired>, Vec<String>)> {
    ingest_checked(l, node, events, now, wake, owner, &mut HashMap::new())
}

/// [`ingest`], with the owners checked so far this pass (`checked`, by trigger): a trigger's owner
/// is checked once a pass, however many syncs the node's events take; one that couldn't be is
/// held for the rest of the pass, its events skipped (not acked) without blocking the others'.
pub(super) fn ingest_checked(
    l: &Ledger,
    node: &str,
    events: &[IntakeEvent],
    now: i64,
    wake: Waker<'_>,
    owner: OwnerCheck<'_>,
    checked: &mut HashMap<String, bool>,
) -> Result<(Vec<Fired>, Vec<String>)> {
    let mut out = vec![];
    let mut ack = vec![];
    for e in events {
        // Only a trigger this node serves, and only fields within what intake makes: a node is
        // trusted as far as its own triggers, no further.
        let t = match (l.trigger(&e.trigger)?, l.trigger_intake(&e.trigger)?) {
            (Some(t), Some((n, _))) if n == node && is_hook(&t.spec.source) && t.status != "deleted" => t,
            _ => {
                ack.push(e.id.clone());
                continue;
            }
        };
        let source = match t.spec.source {
            Source::Github { .. } => "github",
            _ => "webhook",
        };
        let kind_ok = match &t.spec.source {
            Source::Github { events, .. } => events.contains(&e.kind),
            _ => e.kind == "webhook",
        };
        if !kind_ok
            || !wicket_core::intake::fields_within(&e.fields)
            || e.delivery.is_empty()
            || e.delivery.len() > wicket_core::intake::MAX_DELIVERY
        {
            // Counted, and audited with the node's refusals (#714 review M6).
            note_dropped(node);
            ack.push(e.id.clone());
            continue;
        }
        // The node's clock isn't the control host's: a time from the future is now. The rate
        // window and the staleness below use the control host's now (#714 review H3).
        let received_at = e.received_at.min(now);
        // The dedup key is the trigger's own: one URL, one trigger.
        let dedup = format!("hook:{}", t.id);
        let raw = &e.raw_sha256;
        // A signed body replayed under a new delivery id is the same delivery (#714 review H2).
        if !l.trigger_event_known(&t.tenant, &dedup, &e.delivery)? && l.trigger_event_body_known(&t.tenant, &dedup, raw)? {
            ack.push(e.id.clone());
            continue;
        }
        // Paused, lapsed, or waiting for a human: recorded, not fired.
        if !t.live(now) {
            l.record_trigger_event(&t.tenant, &dedup, &e.kind, &e.delivery, &e.fields, raw, &format!("intake:{node}"))?;
            ack.push(e.id.clone());
            continue;
        }
        // Too old when read (the reconciler or the link was down): recorded once and passed over.
        if received_at < now - EVENT_STALE_SECS {
            let r = l.immediate(|l| -> Result<Option<Fired>> {
                let (event, fresh) =
                    l.record_trigger_event(&t.tenant, &dedup, &e.kind, &e.delivery, &e.fields, raw, &format!("intake:{node}"))?;
                if !fresh {
                    return Ok(None);
                }
                let why = format!("delivered {} s before it was read: passed over", now - received_at);
                l.record_firing(&t.id, &event, "skipped", Some(&why))?;
                Ok(Some(Fired { trigger: t.id.clone(), name: t.name.clone(), status: "skipped".into(), detail: why }))
            })?;
            out.extend(r);
            ack.push(e.id.clone());
            continue;
        }
        if !checked.contains_key(&t.id) {
            let ok = match owner(&t) {
                Ok(()) => true,
                Err(NotOwner::Unknown(why)) => {
                    // Held in the node's spool, and tried again next pass.
                    out.push(Fired {
                        trigger: t.id.clone(),
                        name: t.name.clone(),
                        status: "skipped".into(),
                        detail: format!("its owner can't be checked now ({why}): held"),
                    });
                    checked.insert(t.id.clone(), false);
                    continue;
                }
                Err(err) => {
                    match owner_failed(l, &t, err) {
                        Ok(f) => out.push(f),
                        Err(e) => out.push(failed(&t, &e)),
                    }
                    false
                }
            };
            checked.insert(t.id.clone(), ok);
        }
        match checked.get(&t.id) {
            Some(true) => {}
            // Its owner couldn't be checked: held. Paused for its owner: recorded, not fired.
            Some(false) if l.trigger(&t.id)?.is_some_and(|x| x.status == "active") => continue,
            _ => {
                l.record_trigger_event(&t.tenant, &dedup, &e.kind, &e.delivery, &e.fields, raw, &format!("intake:{node}"))?;
                ack.push(e.id.clone());
                continue;
            }
        }
        // wicket's own fields win over a body's of the same name.
        let mut fields = e.fields.clone();
        if let Some(m) = fields.as_object_mut() {
            m.insert("delivery".into(), Value::String(e.delivery.clone()));
            m.insert("at".into(), Value::from(received_at));
        }
        let r = l.immediate(|l| -> Result<(Option<Fired>, Option<String>)> {
            let (event, fresh) = l.record_trigger_event(&t.tenant, &dedup, &e.kind, &e.delivery, &fields, raw, &format!("intake:{node}"))?;
            if !fresh {
                // A redelivery: fired once already.
                return Ok((None, None));
            }
            // The firing's time is the control host's: what the hourly limit counts back from.
            let ev = Ev { id: event, source, at: now, fields: fields.clone(), chain: Default::default() };
            match l.savepoint(|l| fire_event(l, &t, &ev)) {
                Ok(x) => Ok(x),
                Err(err) => {
                    let why = format!("{err:#}");
                    let _ = l.savepoint(|l| -> Result<()> {
                        let (f, _) = l.record_firing(&t.id, &ev.id, "failed", Some(&why))?;
                        let body = json!({ "trigger": t.id, "name": t.name, "owner": t.owner, "event": ev.id, "firing": f, "source": source, "status": "failed", "detail": why });
                        audit(l, "trigger.failed", &body)
                    });
                    Ok((Some(failed(&t, &err)), None))
                }
            }
        });
        match r {
            Ok((f, w)) => {
                if let Some(agent) = w {
                    wake(&agent, &format!("trigger {}", t.name));
                }
                if let Some(f) = f {
                    let was_failed = f.status == "failed";
                    out.push(f);
                    if was_failed {
                        if let Err(e) = pause_if_failing(l, &t) {
                            out.push(failed(&t, &e));
                        }
                    }
                }
                ack.push(e.id.clone());
            }
            // A store error: not acked, so it comes again next pass.
            Err(err) => out.push(failed(&t, &err)),
        }
    }
    Ok((out, ack))
}

/// When each node's refusals were last audited, and what it refused (and what the control host
/// dropped of what it sent) since. In this process's memory: a reconciler is long-lived, and one
/// that restarts audits its first refusals at once.
static REFUSED_AT: std::sync::LazyLock<Mutex<HashMap<String, (i64, IntakeRefused, u64)>>> = std::sync::LazyLock::new(Default::default);

/// Counts an event from `node` the control host dropped (fields outside intake's shape, another
/// trigger's kind): audited with the node's refusals.
fn note_dropped(node: &str) {
    let mut m = REFUSED_AT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    m.entry(node.to_string()).or_insert((0, IntakeRefused::default(), 0)).2 += 1;
}

/// Counts node `node`'s refusals, and audits them (`trigger.intake_refused`) at most once every
/// [`REFUSED_AUDIT_SECS`].
pub fn note_refused(l: &Ledger, node: &str, r: &IntakeRefused, now: i64) -> Result<()> {
    let mut m = REFUSED_AT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let e = m.entry(node.to_string()).or_insert((0, IntakeRefused::default(), 0));
    e.1.token += r.token;
    e.1.signature += r.signature;
    e.1.rate += r.rate;
    e.1.other += r.other;
    if (e.1.total() > 0 || e.2 > 0) && now - e.0 >= REFUSED_AUDIT_SECS {
        audit(
            l,
            "trigger.intake_refused",
            &json!({ "node": node, "token": e.1.token, "signature": e.1.signature, "rate": e.1.rate, "other": e.1.other, "dropped": e.2, "since": e.0 }),
        )?;
        *e = (now, IntakeRefused::default(), 0);
    }
    Ok(())
}

/// One pass over every intake node, from the reconciler: each is sent the triggers it serves and
/// the events recorded since, and what it hands back is recorded and fired, until its spool is
/// empty, or [`PASS_MAX_EVENTS`], [`PASS_MAX_ROUNDS`] syncs or [`PASS_NODE_SECS`] are reached. One
/// node's failure is its own: the others are still synced. `ledger` is the pass's own connection;
/// `link_ledger` is a second one for the links' handshakes.
pub async fn pass(
    ledger: &Ledger,
    link_ledger: &Arc<Mutex<Ledger>>,
    now: i64,
    wake: Waker<'_>,
    owner: OwnerCheck<'_>,
) -> Result<Vec<Fired>> {
    let vault = wicket_proxy::vault::Vault::new(wicket_proxy::vault::Vault::default_dir());
    let mut out = vec![];
    for node in ledger.intake_nodes()? {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(PASS_NODE_SECS);
        if let Err(e) = tokio::time::timeout_at(deadline, sync_node(ledger, link_ledger, &vault, &node, now, wake, owner, &mut out))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("node {node} took more than {PASS_NODE_SECS} s: the rest waits for the next pass")))
        {
            out.push(Fired {
                trigger: String::new(),
                name: format!("intake on {node}"),
                status: "failed".into(),
                detail: format!("{e:#}"),
            });
        }
    }
    Ok(out)
}

/// One intake node's sync, for [`pass`].
#[allow(clippy::too_many_arguments)]
async fn sync_node(
    ledger: &Ledger,
    link_ledger: &Arc<Mutex<Ledger>>,
    vault: &wicket_proxy::vault::Vault,
    node: &str,
    now: i64,
    wake: Waker<'_>,
    owner: OwnerCheck<'_>,
    out: &mut Vec<Fired>,
) -> Result<()> {
    if crate::noderun::known_protocol(node).is_none_or(|p| p < wicket_chan::chan::INTAKE) {
        bail!("node {node} isn't known to talk protocol {} (intake): not synced", wicket_chan::chan::INTAKE);
    }
    // A node no longer labelled for intake is sent an empty table: its secrets go from its memory,
    // and its spool keeps what it holds until it is labelled again or the triggers move.
    let (triggers, problems) = if labelled(ledger, node)? { table(ledger, node, vault)? } else { (vec![], vec![]) };
    let serving: Vec<String> = ledger.intake_triggers(node)?.into_iter().map(|(id, _)| id).collect();
    for p in problems {
        out.push(Fired { trigger: String::new(), name: format!("intake on {node}"), status: "failed".into(), detail: p });
    }
    let link = crate::nodecall::Link::connect(node, &format!("intake:{}", std::process::id()), link_ledger).await?;
    if link.proto < wicket_chan::chan::INTAKE {
        bail!("node {node} talks protocol {} now: intake needs {}", link.proto, wicket_chan::chan::INTAKE);
    }
    let (mut ack, mut read) = (vec![], 0usize);
    let mut checked: HashMap<String, bool> = HashMap::new();
    for round in 0..PASS_MAX_ROUNDS {
        let hold: Vec<String> = checked.iter().filter(|(_, ok)| !**ok).map(|(id, _)| id.clone()).collect();
        let (events, refused) = link.calls.intake_sync(triggers.clone(), std::mem::take(&mut ack), serving.clone(), hold).await?;
        if let Err(e) = note_refused(ledger, node, &refused, now) {
            out.push(Fired {
                trigger: String::new(),
                name: format!("intake on {node}"),
                status: "failed".into(),
                detail: format!("{e:#}"),
            });
        }
        if events.is_empty() {
            break;
        }
        read += events.len();
        let (fired, acked) = ingest_checked(ledger, node, &events, now, wake, owner, &mut checked)?;
        out.extend(fired);
        ack = acked;
        // Every event of this batch was held (owners that can't be checked): the next sync would
        // hand the same ones over again.
        let progressed = !ack.is_empty();
        if read >= PASS_MAX_EVENTS || round + 1 == PASS_MAX_ROUNDS || !progressed {
            if !ack.is_empty() {
                link.calls.intake_sync(triggers.clone(), std::mem::take(&mut ack), serving.clone(), vec![]).await?;
            }
            break;
        }
    }
    Ok(())
}
