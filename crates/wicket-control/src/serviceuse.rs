//! A box using per-node services (#579 step 3): the environment its zone's `uses` gives it at its
//! start, its wants (which the reconciler acts on), and its link to each service's instance on its
//! node once that runs. And a service's own instance offering its port to them.

use crate::services::{installed, Installed};
use std::time::Duration;
use wicket_gateway::link::{use_service, ServiceRef, UseOutcome};
use wicket_store::Ledger;

/// How long a box waits for its node's instance to run and link (a reconcile pass starts one within
/// 30 s, and its start takes a few more).
pub const LINK_WAIT_SECS: u64 = 120;

/// How often a link waiting for a human's decision looks at it.
const APPROVAL_POLL: Duration = Duration::from_secs(5);

/// The environment a box whose zone uses `uses` gets from them (each installed service's `env`,
/// `{host}` and `{port}` filled in), at its start. A service not installed gives nothing (its link
/// says why).
///
/// It also gets `WICKET_WAIT_LINKS`: the box's program starts once those links are up
/// (`wicket-entry`), not before, so its first request finds the service.
pub fn user_env(l: &Ledger, uses: &[String]) -> Vec<(String, String)> {
    let Ok(all) = installed(l) else { return vec![] };
    let used: Vec<&String> = uses.iter().filter(|u| all.contains_key(*u)).collect();
    let mut env: Vec<(String, String)> = used.iter().flat_map(|u| all[*u].spec.user_env(u).into_iter()).collect();
    if !used.is_empty() {
        let names: Vec<String> = used.iter().map(|u| format!("{u}.{}", wicket_core::link::DOMAIN)).collect();
        env.push(("WICKET_WAIT_LINKS".into(), names.join(",")));
    }
    env
}

/// Whether `run`, whose zone is `zone`, may run in it (#579): an installed service's zone is its
/// instances' alone, since any other run in it would share the service's kept volumes (a cache's
/// storage) and could rewrite what it serves. Err says whose zone it is.
pub fn check_zone(l: &Ledger, zone: &str, run: &str) -> anyhow::Result<()> {
    for (name, svc) in installed(l)? {
        let ours = l.service_instance_of(run)?.is_some_and(|i| i.service == name);
        if svc.zone == zone && !ours {
            anyhow::bail!("zone {zone} is service {name}'s: only the instances wicket starts for it run in it");
        }
    }
    Ok(())
}

fn service_ref<'a>(name: &'a str, s: &'a Installed, zone: &'a str, program: &'a str) -> ServiceRef<'a> {
    ServiceRef { name, port: s.spec.port, shared: s.spec.tenancy == wicket_core::service::Tenancy::Shared, zone, program }
}

/// After a box started:
/// - a per-node service's instance (one wicket recorded starting) exposes its port, under its
///   name, to the boxes that use it; a run that merely says `service:` exposes nothing;
/// - a box whose zone uses services records that, and is linked to each one's instance on its node
///   once it runs, as `<name>.wicket.internal`. A link that needs a human waits for the decision
///   and is opened once it's granted.
pub fn after_start(ctx: &wicket_proxy::RunCtx, m: &wicket_core::Manifest, node: &str) {
    if let (Some(s), Some(p)) = (&m.service, &m.program) {
        let l = ctx.ledger.lock().expect("ledger");
        let ours = l.service_instance_of(&ctx.run.0).ok().flatten().is_some_and(|i| i.service == p.name);
        if ours {
            let zone = serde_json::to_string(&m.zone).unwrap_or_default();
            // The audit first: an expose with no record isn't made.
            let body = serde_json::json!({ "port": s.port, "name": p.name, "service": true });
            match l
                .audit(&ctx.tenant, Some(&ctx.run), "link.expose", &body)
                .and_then(|_| l.expose(&ctx.tenant, &ctx.run.0, s.port, Some(&p.name), &zone))
            {
                Ok(_) => say!("[wicket] service {} offers port {} on node {node} to the boxes there that use it", p.name, s.port),
                Err(e) => say_err!("[wicket] service {}: could not expose port {}: {e}", p.name, s.port),
            }
        } else {
            say!("[wicket] this run says service: but isn't an instance wicket started (wicket service add): it offers nothing");
        }
    }
    if m.zone.uses.is_empty() {
        return;
    }
    let all = ctx.ledger.lock().map(|l| installed(&l).unwrap_or_default()).unwrap_or_default();
    for u in &m.zone.uses {
        if let Err(e) = ctx.ledger.lock().expect("ledger").want_service(u, node, &ctx.tenant.0, &ctx.run.0) {
            say_err!("[wicket] could not record that this box uses {u}: {e}");
        }
        let Some(svc) = all.get(u).cloned() else {
            say!("[wicket] this box's zone uses {u}, which isn't installed (wicket service add): not linked");
            continue;
        };
        let (zone, program) = (svc.zone.clone(), svc.program.clone());
        let (ctx, u, node) = (ctx.clone(), u.clone(), node.to_string());
        tokio::spawn(async move {
            let t0 = std::time::Instant::now();
            loop {
                let outcome = use_service(&ctx, &service_ref(&u, &svc, &zone, &program)).await;
                match outcome {
                    UseOutcome::Linked(t) => return say!("[wicket] {u} on node {node}: {t}"),
                    UseOutcome::Refused(t) => return say!("[wicket] {u} on node {node}: not linked: {t}"),
                    UseOutcome::Waiting(t) if t0.elapsed().as_secs() >= LINK_WAIT_SECS => {
                        return say!("[wicket] {u} on node {node}: not linked: {t} (gave up after {LINK_WAIT_SECS} s)")
                    }
                    UseOutcome::Waiting(_) => tokio::time::sleep(Duration::from_secs(5)).await,
                    UseOutcome::Approval { request, text } => {
                        say!("[wicket] {u} on node {node}: {text}");
                        // Until a human decides: then the same link again (granted), or nothing.
                        loop {
                            tokio::time::sleep(APPROVAL_POLL).await;
                            let status = ctx.ledger.lock().ok().and_then(|l| l.request(&request).ok()).map(|r| r.status);
                            match status.as_deref() {
                                Some("pending") => continue,
                                Some("granted") => break,
                                other => {
                                    return say!(
                                        "[wicket] {u} on node {node}: not linked: request {request} is {}",
                                        other.unwrap_or("gone")
                                    )
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_services_zone_is_its_instances_alone() {
        let root = std::env::temp_dir().join(format!("wicket-svc-zone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("m.yaml");
        std::fs::write(&path, "task: c\nprogram: { name: npm-cache, command: [x] }\nservice: { port: 4873 }\nzone: { name: npm-cache }\n")
            .unwrap();
        let snap = crate::services::snapshot(&path, &root.join("data")).unwrap();
        let l = Ledger::open_in_memory().unwrap();
        assert!(check_zone(&l, "npm-cache", "run_x").is_ok(), "nothing installed yet");
        l.add_service("npm-cache", &snap.path.display().to_string(), &snap.sha256, "t0", "alex").unwrap();
        assert!(check_zone(&l, "npm-cache", "run_x").unwrap_err().to_string().contains("is service npm-cache's"));
        assert!(check_zone(&l, "build", "run_x").is_ok(), "another zone");
        l.record_service_instance("run_svc", "npm-cache", "n1", "t0", &snap.sha256, wicket_store::now()).unwrap();
        assert!(check_zone(&l, "npm-cache", "run_svc").is_ok(), "the instance wicket started");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_box_gets_the_environment_of_the_installed_services_it_uses() {
        let root = std::env::temp_dir().join(format!("wicket-svc-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("npm-cache.yaml");
        std::fs::write(
            &path,
            concat!(
                "task: cache\nprogram: { name: npm-cache, command: [verdaccio] }\n",
                "service: { port: 4873, env: { npm_config_registry: 'http://{host}:{port}/' } }\n",
                "zone: { name: npm-cache }\n"
            ),
        )
        .unwrap();
        let snap = crate::services::snapshot(&path, &root.join("data")).unwrap();
        let l = Ledger::open_in_memory().unwrap();
        l.add_service("npm-cache", &snap.path.display().to_string(), &snap.sha256, "t0", "alex").unwrap();
        let uses = vec!["npm-cache".to_string(), "not-installed".to_string()];
        assert_eq!(
            user_env(&l, &uses),
            vec![
                ("npm_config_registry".to_string(), "http://npm-cache.wicket.internal:4873/".to_string()),
                ("WICKET_WAIT_LINKS".to_string(), "npm-cache.wicket.internal".to_string()),
            ],
            "and the box waits for its link before its program starts"
        );
        // The file it was installed from changes: nothing installed does.
        std::fs::write(&path, "task: x\nprogram: { name: npm-cache, command: [x] }\nservice: { port: 1, env: { npm_config_registry: 'http://evil/' } }\nzone: { name: npm-cache }\n").unwrap();
        assert_eq!(user_env(&l, &uses)[0].1, "http://npm-cache.wicket.internal:4873/");
        assert!(user_env(&l, &[]).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
