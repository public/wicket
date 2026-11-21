//! The trigger engine (#578 step 5): starts the runs that `start` triggers queued.
//!
//! Each reconcile pass, after the scheduler's and intake's, [`pass`] looks at every live trigger
//! with a `start` action and a firing waiting, and starts its oldest:
//! - **Within its concurrency.** A run it started that is still running holds a place, and so does
//!   one launched less than [`LAUNCH_GRACE_SECS`] ago that isn't in the ledger yet (a run writes
//!   its own row once it is under way).
//! - **As its owner, now.** The trigger must still be live (not paused, lapsed or waiting for an
//!   approval) and its owner may still have it fire ([`OwnerCheck`]). Both are checked when the
//!   run starts, not when the firing was queued. The run's principal is the owner's
//!   ([`principal_of`]), so it has the owner's authority and never more.
//! - **The bytes the trigger pins.** The manifest is read once ([`Engine::read`]). If its sha256
//!   isn't the trigger's pin, the firing is refused: it fails, audited `trigger.refused` with both
//!   digests, and nothing starts. Editing the file (in the console, or with `wicket manifest
//!   save`) never changes what an approved trigger runs. The verified bytes are written into the
//!   run's directory ([`MANIFEST_COPY`]) and the run starts from that copy, so a change between
//!   the check and the start doesn't count either.
//! - **One transaction, then the launch.** The firing becomes `started` with its run, audited
//!   `trigger.fired`, and then the run is launched ([`Engine::launch`]), as a wake follows its
//!   firing. A launch that fails marks the firing failed (`trigger.failed`).
//! - **The chain.** The started run carries the triggers that led to its firing (recorded when it
//!   was queued, as `firing:<id>`), so what it does can't fire them again.
//!
//! A firing that fails counts toward [`FAILURES_TO_PAUSE`], as any other does.

use super::*;
use std::path::{Path, PathBuf};

/// How long a run the engine launched may take to appear in the ledger before its place in the
/// trigger's concurrency is given up (the launch died before the run started).
pub const LAUNCH_GRACE_SECS: i64 = 10 * 60;

/// The verified copy of a trigger's manifest, in the run's directory: what the run starts from.
pub const MANIFEST_COPY: &str = "trigger-manifest.yaml";

/// The run's log, in its directory: what `wicket run` prints.
pub const LOG: &str = "trigger.log";

/// A run for the engine's launcher to start: `wicket run --run-id <run> [--task <task>]
/// <manifest>`, with `principal` as its `WICKET_PRINCIPAL`, logging to `log`.
#[derive(Clone, Debug, PartialEq)]
pub struct Launch {
    pub run: String,
    /// The verified copy of the manifest ([`MANIFEST_COPY`]).
    pub manifest: PathBuf,
    pub task: Option<String>,
    pub principal: Value,
    pub log: PathBuf,
}

/// What the engine needs from its host: how a trigger's manifest is read (`<root>/<name>`, or a
/// name in the `manifests` root, as the console resolves it), where run directories are, and how a
/// run is launched.
pub struct Engine<'a> {
    pub read: &'a dyn Fn(&str) -> Result<Vec<u8>>,
    pub runs: &'a Path,
    pub launch: &'a dyn Fn(&Launch) -> Result<()>,
}

/// One engine pass at `now`: each live `start` trigger's oldest waiting firing, started if the
/// trigger has room. A dry run reports what would start and changes nothing. One trigger's failure
/// is its result, not the pass's.
pub fn pass(l: &Ledger, now: i64, dry_run: bool, eng: &Engine<'_>, owner: OwnerCheck<'_>) -> Result<Vec<Fired>> {
    let tenant = TenantId::single();
    let mut out = vec![];
    for t in l.triggers(&tenant.0, None)? {
        if t.spec.action.start.is_none() || !t.live(now) {
            continue;
        }
        match one(l, &t, now, dry_run, eng, owner) {
            Ok(f) => out.extend(f),
            Err(e) => out.push(failed(&t, &e)),
        }
    }
    Ok(out)
}

fn one(l: &Ledger, t: &Trigger, now: i64, dry_run: bool, eng: &Engine<'_>, owner: OwnerCheck<'_>) -> Result<Option<Fired>> {
    let Some(f) = l.firings(&t.id, Some("queued"))?.into_iter().next() else { return Ok(None) };
    if l.firings_in_flight(&t.id, now - LAUNCH_GRACE_SECS)? >= t.spec.limits.concurrency as i64 {
        return Ok(None);
    }
    let done = |status: &str, detail: String| Fired { trigger: t.id.clone(), name: t.name.clone(), status: status.into(), detail };
    if dry_run {
        return Ok(Some(done("due", format!("{}, for firing {} (dry run)", action_text(&t.spec), f.id))));
    }
    if let Err(e) = owner(t) {
        return owner_failed(l, t, e).map(Some);
    }
    let fired = match prepare(l, t, &f, eng) {
        Ok(p) => start(l, t, &f, p, eng)?,
        Err(NotStarted::Refused { why, found }) => {
            let st = t.spec.action.start.as_ref().expect("a start trigger");
            l.update_firing(&f.id, "failed", Some(&why), None)?;
            let mut r = record(t, &f, "failed", &why);
            r["manifest"] = json!(st.manifest);
            r["pinned_sha256"] = json!(st.sha256);
            r["found_sha256"] = json!(found);
            audit(l, "trigger.refused", &r)?;
            done("failed", why)
        }
        Err(NotStarted::Failed(why)) => {
            l.update_firing(&f.id, "failed", Some(&why), None)?;
            audit(l, "trigger.failed", &record(t, &f, "failed", &why))?;
            done("failed", why)
        }
    };
    if fired.status == "failed" {
        pause_if_failing(l, t)?;
    }
    Ok(Some(fired))
}

/// Why a firing wasn't started: refused (the manifest isn't the one the trigger pins: its sha256
/// found), or failed.
enum NotStarted {
    Refused { why: String, found: String },
    Failed(String),
}

/// A firing ready to start: its verified manifest bytes, its task, and its run's principal.
struct Prepared {
    bytes: Vec<u8>,
    task: Option<String>,
    principal: Value,
}

/// Everything about firing `f` that is checked before anything is recorded or started.
fn prepare(l: &Ledger, t: &Trigger, f: &wicket_store::TriggerFiring, eng: &Engine<'_>) -> std::result::Result<Prepared, NotStarted> {
    let fail = |s: String| NotStarted::Failed(s);
    let st = t.spec.action.start.as_ref().expect("a start trigger");
    let event = l
        .trigger_event(&f.event)
        .map_err(|e| fail(format!("reading its event: {e}")))?
        .ok_or_else(|| fail(format!("its event {} is no longer kept", f.event)))?;
    let bytes = (eng.read)(&st.manifest).map_err(|e| fail(format!("reading manifest {}: {e:#}", st.manifest)))?;
    let found = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
    if found != st.sha256 {
        return Err(NotStarted::Refused {
            why: format!(
                "manifest {} has changed since the trigger pinned it (sha256 {}…, now {}…): nothing was started; \
                 restore that version, or make the trigger again with the new sha256",
                st.manifest,
                &st.sha256[..12],
                &found[..12]
            ),
            found,
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| fail(format!("manifest {} is not UTF-8", st.manifest)))?;
    let m = wicket_agent::load(text).map_err(|e| fail(format!("manifest {}: {e}", st.manifest)))?;
    if m.tenant.0 != t.tenant {
        return Err(fail(format!("manifest {} is for tenant {}, not the trigger's ({})", st.manifest, m.tenant.0, t.tenant)));
    }
    if st.task.is_some() && m.agent.is_none() {
        return Err(fail(format!("start.task applies to agent manifests only, and {} is a program's", st.manifest)));
    }
    // A program's source is found next to its manifest file, and the run starts from a copy
    // elsewhere: only a source given as an absolute path is still the same directory.
    if let Some(src) = m.program.as_ref().and_then(|p| p.source.as_deref()).filter(|s| !Path::new(s).is_absolute()) {
        return Err(fail(format!(
            "manifest {}'s program source {src:?} is relative to the manifest file, which a trigger doesn't start from: give it as an absolute path",
            st.manifest
        )));
    }
    let principal = principal_of(t).map_err(|e| fail(format!("{e:#}")))?;
    let task = st.task.as_deref().map(|task| start_task(t, &event.fields, task));
    Ok(Prepared { bytes, task, principal })
}

/// The principal a run started for `t` acts as (its `WICKET_PRINCIPAL`): the trigger's owner, an
/// operator, as wicket would know them from the CLI (`unix`) or the console (`passkey`), and
/// naming the trigger. Refused unless the operator id a run computes from it
/// ([`crate::operators::with_identity`]) is the owner's, under this installation's trust domain.
pub fn principal_of(t: &Trigger) -> Result<Value> {
    let Some(wicket_identity::Principal::Operator { tenant, via, name, .. }) = wicket_identity::Principal::parse(&t.owner) else {
        bail!("{} is not an operator: only an operator's trigger starts a run", t.owner);
    };
    let mut p = match via.as_str() {
        "unix" => json!({ "type": "human", "id": name, "via": "cli" }),
        "passkey" => json!({ "type": "human", "id": format!("passkey:{name}"), "via": "console" }),
        v => bail!("{} is an operator known {v:?}, which a run can't be started as", t.owner),
    };
    p["assurance"] = json!("trigger");
    p["trigger"] = json!(t.id);
    let sub = crate::operators::with_identity(p.clone(), &tenant);
    if sub["sub"].as_str() != Some(t.owner.as_str()) {
        bail!("a run started for {} would act as {}, not as its owner {}", t.id, sub["sub"].as_str().unwrap_or("no operator"), t.owner);
    }
    Ok(p)
}

/// A firing's audit record, as the scheduler's are.
fn record(t: &Trigger, f: &wicket_store::TriggerFiring, status: &str, detail: &str) -> Value {
    json!({ "trigger": t.id, "name": t.name, "owner": t.owner, "event": f.event, "firing": f.id, "status": status, "detail": detail })
}

/// Starts firing `f`: the verified manifest into a new run's directory, the firing `started` and
/// audited in one transaction, then the launch.
fn start(l: &Ledger, t: &Trigger, f: &wicket_store::TriggerFiring, p: Prepared, eng: &Engine<'_>) -> Result<Fired> {
    let st = t.spec.action.start.as_ref().expect("a start trigger");
    let done = |status: &str, detail: String| Fired { trigger: t.id.clone(), name: t.name.clone(), status: status.into(), detail };
    let run = wicket_core::RunId::new().0;
    let dir = eng.runs.join(&run);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let manifest = dir.join(MANIFEST_COPY);
    std::fs::write(&manifest, &p.bytes).with_context(|| format!("writing {}", manifest.display()))?;
    let detail = format!("started run {run} from {} as {}", st.manifest, t.owner);
    let claimed = l.immediate(|l| -> Result<bool> {
        // Another pass may have taken it meanwhile (the reconciler's lock makes this unlikely).
        if !l.firings(&t.id, Some("queued"))?.iter().any(|q| q.id == f.id) {
            return Ok(false);
        }
        l.update_firing(&f.id, "started", Some(&detail), Some(&run))?;
        let mut r = record(t, f, "started", &detail);
        r["run"] = json!(run);
        r["manifest"] = json!(st.manifest);
        r["manifest_sha256"] = json!(st.sha256);
        if let Some(task) = &p.task {
            r["task_sha256"] = json!(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(task.as_bytes())));
            r["task_bytes"] = json!(task.len());
        }
        audit(l, "trigger.fired", &r)?;
        Ok(true)
    })?;
    if !claimed {
        let _ = std::fs::remove_dir_all(&dir);
        return Ok(done("skipped", format!("firing {} was taken by another pass", f.id)));
    }
    let launch = Launch { run: run.clone(), manifest, task: p.task, principal: p.principal, log: dir.join(LOG) };
    match (eng.launch)(&launch) {
        Ok(()) => Ok(done("started", detail)),
        Err(e) => {
            let why = format!("launching run {run}: {e:#}");
            l.update_firing(&f.id, "failed", Some(&why), None)?;
            let mut r = record(t, f, "failed", &why);
            r["run"] = json!(run);
            audit(l, "trigger.failed", &r)?;
            Ok(done("failed", why))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn spec(y: &str) -> TriggerSpec {
        wicket_core::yaml::from_str(y).unwrap()
    }

    /// An operator under this installation's trust domain, as a run started for it would compute.
    fn alex() -> Operator {
        let id = wicket_identity::operator_id(&crate::operators::trust_domain(), "t0", "unix", "alex");
        Operator { id, label: "unix:alex".into(), authority: Authority::Anything }
    }

    fn anyone(_: &Trigger) -> std::result::Result<(), NotOwner> {
        Ok(())
    }

    fn no_wake(_: &str, _: &str) {}

    const MANIFEST: &str = "agent:\n  name: triage\ntask: look\nzone:\n  name: rel\n  llm: { secret: model-key }\n  limits: { memory: 1g, cpus: 1, timeout: 1h }\n";

    fn sha(b: &[u8]) -> String {
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b))
    }

    /// A host for the engine: manifests by name, run directories in a temporary directory, and
    /// the launches it was asked for.
    struct Host {
        files: RefCell<std::collections::HashMap<String, Vec<u8>>>,
        runs: Runs,
        launched: RefCell<Vec<Launch>>,
        fail_launch: bool,
    }

    impl Host {
        fn new() -> Host {
            let files = RefCell::new([("triage.yaml".to_string(), MANIFEST.as_bytes().to_vec())].into());
            Host { files, runs: Runs::new(), launched: RefCell::new(vec![]), fail_launch: false }
        }

        fn pass(&self, l: &Ledger, now: i64, dry_run: bool) -> Vec<Fired> {
            let read = |name: &str| self.files.borrow().get(name).cloned().with_context(|| format!("no {name}"));
            let launch = |x: &Launch| {
                if self.fail_launch {
                    bail!("no wicket here");
                }
                self.launched.borrow_mut().push(x.clone());
                Ok(())
            };
            let eng = Engine { read: &read, runs: self.runs.path(), launch: &launch };
            pass(l, now, dry_run, &eng, &anyone).unwrap()
        }
    }

    /// A run directory of the test's own, removed when it ends.
    struct Runs(PathBuf);

    impl Runs {
        fn new() -> Runs {
            let d = std::env::temp_dir().join(format!("wicket-engine-{}", wicket_core::new_ulid().to_string().to_lowercase()));
            std::fs::create_dir_all(&d).unwrap();
            Runs(d)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Runs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A `start` trigger on every minute's schedule, pinning `MANIFEST`.
    fn every_minute(l: &Ledger, extra: &str) -> String {
        let y = format!(
            "trigger: build\nsource: {{ schedule: {{ cron: '* * * * *' }} }}\naction: {{ start: {{ manifest: triage.yaml, sha256: {}{extra} }} }}\nlimits: {{ per_hour: 60 }}\n",
            sha(MANIFEST.as_bytes())
        );
        create(l, &alex(), &spec(&y), None, "t").unwrap().0
    }

    /// Fires the scheduler at minute `n` after `base`: one firing queued.
    fn tick(l: &Ledger, base: i64, n: i64) {
        let got = crate::triggers::pass(l, base + n * 60, false, &no_wake, &anyone).unwrap();
        assert!(got.iter().any(|f| f.status == "queued"), "{got:?}");
    }

    fn base() -> i64 {
        (wicket_store::now().div_euclid(60) + 1) * 60
    }

    /// #578 step 5: a schedule's queued `start` is started as the trigger's owner, from the pinned
    /// bytes copied into its run's directory, with its task filled in; one at a time (concurrency
    /// 1) until its run ends; audited, and the dry run changes nothing.
    #[test]
    fn a_queued_start_runs_as_its_owner_one_at_a_time() {
        let l = Ledger::open_in_memory().unwrap();
        let h = Host::new();
        let t = every_minute(&l, ", task: 'Triage at {{ event.at }}'");
        let b = base();
        tick(&l, b, 0);
        tick(&l, b, 1);
        let due = h.pass(&l, b + 61, true);
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].status, "due");
        assert!(h.launched.borrow().is_empty() && l.firings(&t, Some("queued")).unwrap().len() == 2, "a dry run changes nothing");

        let got = h.pass(&l, b + 61, false);
        assert_eq!(got.iter().map(|f| f.status.as_str()).collect::<Vec<_>>(), ["started"], "{got:?}");
        let x = h.launched.borrow()[0].clone();
        assert_eq!(std::fs::read(&x.manifest).unwrap(), MANIFEST.as_bytes(), "the verified bytes");
        assert!(x.manifest.starts_with(h.runs.path().join(&x.run)));
        assert_eq!(x.principal["id"], "alex");
        assert_eq!(x.principal["via"], "cli");
        assert_eq!(x.principal["trigger"], json!(t));
        assert_eq!(crate::operators::with_identity(x.principal.clone(), "t0")["sub"], json!(alex().id), "the owner's authority");
        assert!(x.task.as_deref().unwrap().starts_with("Triage at "), "{:?}", x.task);
        let started = l.firings(&t, Some("started")).unwrap();
        assert_eq!(started[0].run.as_deref(), Some(x.run.as_str()));
        let rec = l.audit_of_kind("trigger.fired").unwrap();
        let body: Value = serde_json::from_str(&rec.last().unwrap().body).unwrap();
        assert_eq!((body["status"].as_str(), body["run"].as_str()), (Some("started"), Some(x.run.as_str())), "{body}");
        assert_eq!(body["manifest_sha256"], json!(sha(MANIFEST.as_bytes())));

        // Launched, not yet in the ledger: it holds the trigger's one place.
        assert!(h.pass(&l, b + 62, false).is_empty());
        // Running, then ended: the next waits, then starts.
        l.run_started(&TenantId::single(), &wicket_core::RunId(x.run.clone()), "rel", "triage").unwrap();
        assert!(h.pass(&l, b + 63, false).is_empty());
        l.run_ended(&wicket_core::RunId(x.run.clone()), "succeeded", "").unwrap();
        assert_eq!(h.pass(&l, b + 64, false)[0].status, "started");
        assert_eq!(h.launched.borrow().len(), 2);
        // A launch that never reached the ledger gives its place up after the grace.
        tick(&l, b, 2);
        assert!(h.pass(&l, b + 180, false).is_empty());
        assert_eq!(h.pass(&l, wicket_store::now() + LAUNCH_GRACE_SECS + 1, false)[0].status, "started");
    }

    /// The coordinator's #823 note: a manifest edited after the trigger pinned it is refused, not
    /// started: the firing fails, audited `trigger.refused` with both digests, and nothing is
    /// launched; the version it pinned, restored, starts again.
    #[test]
    fn a_manifest_that_changed_is_refused_and_audited() {
        let l = Ledger::open_in_memory().unwrap();
        let h = Host::new();
        let t = every_minute(&l, "");
        let b = base();
        tick(&l, b, 0);
        let edited = MANIFEST.replace("look", "look, and push to main");
        h.files.borrow_mut().insert("triage.yaml".into(), edited.clone().into_bytes());
        let got = h.pass(&l, b + 1, false);
        assert_eq!(got[0].status, "failed");
        assert!(got[0].detail.contains("has changed since the trigger pinned it"), "{got:?}");
        assert!(h.launched.borrow().is_empty(), "nothing started");
        assert!(std::fs::read_dir(h.runs.path()).unwrap().next().is_none(), "no run directory");
        let rec = l.audit_of_kind("trigger.refused").unwrap();
        assert_eq!(rec.len(), 1);
        let body: Value = serde_json::from_str(&rec[0].body).unwrap();
        assert_eq!(body["pinned_sha256"], json!(sha(MANIFEST.as_bytes())));
        assert_eq!(body["found_sha256"], json!(sha(edited.as_bytes())));
        assert_eq!(body["manifest"], "triage.yaml");
        assert_eq!(l.firings(&t, Some("failed")).unwrap().len(), 1);

        h.files.borrow_mut().insert("triage.yaml".into(), MANIFEST.as_bytes().to_vec());
        tick(&l, b, 1);
        assert_eq!(h.pass(&l, b + 61, false)[0].status, "started");
    }

    /// The kill switch holds at start, not only when a firing is queued: a paused trigger's
    /// waiting firing isn't started, and is once it is resumed. An owner who may no longer have it
    /// fire has it paused instead.
    #[test]
    fn a_paused_trigger_or_a_gone_owner_starts_nothing() {
        let l = Ledger::open_in_memory().unwrap();
        let h = Host::new();
        let t = every_minute(&l, "");
        let b = base();
        tick(&l, b, 0);
        set_status(&l, &alex(), &t, "paused").unwrap();
        assert!(h.pass(&l, b + 1, false).is_empty());
        resume(&l, &alex(), false, &t).unwrap();
        let read = |name: &str| h.files.borrow().get(name).cloned().context("none");
        let launch = |_: &Launch| -> Result<()> { panic!("not started") };
        let eng = Engine { read: &read, runs: h.runs.path(), launch: &launch };
        let gone = |_: &Trigger| Err(NotOwner::No("alex is no longer an operator".into()));
        let got = pass(&l, b + 2, false, &eng, &gone).unwrap();
        assert_eq!(got[0].status, "paused", "{got:?}");
        assert_eq!(l.firings(&t, Some("queued")).unwrap().len(), 1, "still waiting, for a resume");
    }

    /// What a firing can't start with fails, audited, and five in a row pause the trigger: a
    /// launch that fails, a manifest gone, a task for a program, a program whose source is
    /// relative to the file.
    #[test]
    fn what_cant_start_fails_and_pauses() {
        let l = Ledger::open_in_memory().unwrap();
        let mut h = Host::new();
        h.fail_launch = true;
        let t = every_minute(&l, "");
        let b = base();
        tick(&l, b, 0);
        let got = h.pass(&l, b + 1, false);
        assert!(got[0].status == "failed" && got[0].detail.contains("no wicket here"), "{got:?}");
        h.fail_launch = false;
        h.files.borrow_mut().clear();
        for n in 1..5 {
            tick(&l, b, n);
            let got = h.pass(&l, b + n * 60 + 1, false);
            assert!(got[0].detail.contains("no triage.yaml"), "{got:?}");
        }
        assert_eq!(l.trigger(&t).unwrap().unwrap().status, "paused", "five failures in a row");
        assert_eq!(l.audit_of_kind("trigger.failed").unwrap().len(), 5);

        let program = "program:\n  name: p\n  image: i\n  command: [run]\n  source: src\nzone:\n  name: rel\n";
        h.files.borrow_mut().insert("p.yaml".into(), program.as_bytes().to_vec());
        for (extra, why) in [(", task: go", "agent manifests only"), ("", "relative to the manifest file")] {
            let y = format!(
                "trigger: prog{}\nsource: {{ schedule: {{ cron: '* * * * *' }} }}\naction: {{ start: {{ manifest: p.yaml, sha256: {}{extra} }} }}\n",
                why.len(),
                sha(program.as_bytes())
            );
            let id = create(&l, &alex(), &spec(&y), None, "t").unwrap().0;
            let got = crate::triggers::pass(&l, b + 600, false, &no_wake, &anyone).unwrap();
            assert!(got.iter().any(|f| f.trigger == id && f.status == "queued"), "{got:?}");
            let got = h.pass(&l, b + 601, false);
            let mine: Vec<_> = got.iter().filter(|f| f.trigger == id).collect();
            assert!(mine[0].status == "failed" && mine[0].detail.contains(why), "{why}: {got:?}");
        }
    }

    /// A run a `start` trigger started carries the trigger's chain: its end, a `run.end` the same
    /// trigger listens for, doesn't start it again (a loop), while another trigger hears it.
    #[test]
    fn a_started_run_doesnt_start_its_trigger_again() {
        let l = Ledger::open_in_memory().unwrap();
        let h = Host::new();
        let t0 = TenantId::single();
        assert!(crate::triggers::pass(&l, wicket_store::now(), false, &no_wake, &anyone).unwrap().is_empty(), "from the chain's head");
        let y = format!(
            "trigger: again\nsource: {{ wicket: {{ kinds: [run.end] }} }}\naction: {{ start: {{ manifest: triage.yaml, sha256: {} }} }}\n",
            sha(MANIFEST.as_bytes())
        );
        let t = create(&l, &alex(), &spec(&y), None, "t").unwrap().0;
        let other = create(&l, &alex(), &spec(&y.replace("trigger: again", "trigger: other")), None, "t").unwrap().0;
        // Some other run ends: both triggers queue a start.
        l.run_started(&t0, &wicket_core::RunId("run_first".into()), "rel", "triage").unwrap();
        l.audit(&t0, Some(&wicket_core::RunId("run_first".into())), "run.end", &json!({ "status": "succeeded" })).unwrap();
        let got = crate::triggers::pass(&l, wicket_store::now(), false, &no_wake, &anyone).unwrap();
        assert_eq!(got.iter().filter(|f| f.status == "queued").count(), 2, "{got:?}");
        let got = h.pass(&l, wicket_store::now(), false);
        assert_eq!(got.iter().filter(|f| f.status == "started").count(), 2, "{got:?}");
        // The run `again` started ends.
        let run = l.firings(&t, Some("started")).unwrap()[0].run.clone().unwrap();
        let rid = wicket_core::RunId(run.clone());
        l.run_started(&t0, &rid, "rel", "triage").unwrap();
        l.audit(&t0, Some(&rid), "run.end", &json!({ "status": "succeeded" })).unwrap();
        let got = crate::triggers::pass(&l, wicket_store::now() + 1, false, &no_wake, &anyone).unwrap();
        let by = |id: &str| got.iter().filter(|f| f.trigger == id).map(|f| f.status.as_str()).collect::<Vec<_>>();
        assert_eq!(by(&t), ["skipped"], "its own run's end: a loop: {got:?}");
        assert!(got.iter().any(|f| f.trigger == t && f.detail.contains("a loop")), "{got:?}");
        assert_eq!(by(&other), ["queued"], "another trigger's run, so it fires once: {got:?}");
    }

    /// A trigger's run acts as its owner: an operator from the CLI or the console, never an
    /// agent's principal, and never one whose id doesn't come back as the owner's.
    #[test]
    fn a_run_acts_as_the_triggers_owner() {
        let l = Ledger::open_in_memory().unwrap();
        let t = every_minute(&l, "");
        let mut tr = l.trigger(&t).unwrap().unwrap();
        assert_eq!(principal_of(&tr).unwrap()["id"], "alex");
        tr.owner = wicket_identity::operator_id(&crate::operators::trust_domain(), "t0", "passkey", "laptop");
        let p = principal_of(&tr).unwrap();
        assert_eq!((p["id"].as_str(), p["via"].as_str()), (Some("passkey:laptop"), Some("console")));
        tr.owner = "spiffe://elsewhere.example/t/t0/op/unix/alex".into();
        assert!(principal_of(&tr).unwrap_err().to_string().contains("not as its owner"));
        tr.owner = "spiffe://local/t/t0/z/rel/a/captain".into();
        assert!(principal_of(&tr).unwrap_err().to_string().contains("not an operator"));
    }
}
