//! Updating to builds CI signed (#190): `wicket self update --from-ci <commit|latest>` and
//! `wicket self follow`.
//!
//! The trust anchor is the reviewed merge. A human reviews and merges a pull request; CI builds the
//! merge commit on `main` (`.github/workflows/build.yml`, the `build` job); a reviewer approves the
//! `sign` job in the repository's `release` environment, which only then gets the release key and
//! signs the archive's sha256 together with claims about where it came from (commit, ref,
//! repository, workflow, run, environment: [`crate::update::CiClaims`]). An installation trusts that
//! key (`wicket self trust-key`) and the repository it is configured with, and takes a build only:
//! - signed by a trusted key, with claims for this repository, this workflow, `refs/heads/main`, the
//!   `release` environment and the commit asked for (`update::accept`);
//! - whose commit is on `main` now, by GitHub's compare API (an ancestor of, or, `main`'s head);
//! - downloaded here, on the control host, never in a box, with a token from the vault (read-only on
//!   the repository's Actions), which is never sent anywhere but the API host.
//!
//! Then the usual blue/green update runs, with its health gate and rollback, and the audit records
//! the commit, the run, the environment and the signing key (`self.staged`'s `source.ci`).
//!
//! `self follow` (the `wicket-follow` timer) does the same for the newest signed build of `main`,
//! within a policy: an allowed window, a minimum soak since it was signed, only forward along
//! `main` from the running build's commit, never across a schema contract step or more than one
//! protocol version (those need an operator), and never again to a build whose gate failed here.

use crate::update::{self, CiClaims, CiExpect, Gate};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The installation's CI builds (`<data dir>/ci-builds.yaml`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiConfig {
    /// `owner/name` of the repository whose `main` this installation follows.
    pub repo: String,
    /// The workflow that builds and signs (default `.github/workflows/build.yml`).
    #[serde(default = "default_workflow")]
    pub workflow: String,
    /// The vault secret holding a GitHub token that can read the repository's Actions artifacts
    /// (a fine-grained token, read-only, this repository only).
    pub token_secret: String,
    /// The API (default `https://api.github.com`).
    #[serde(default = "default_api")]
    pub api: String,
    /// `self follow`'s policy: absent, it updates nothing.
    #[serde(default)]
    pub follow: Option<FollowPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FollowPolicy {
    /// When it may update, UTC (`HH:MM-HH:MM`, may wrap past midnight). Absent: any time.
    #[serde(default)]
    pub window: Option<String>,
    /// How long a build must have been signed before it is taken (default 1h).
    #[serde(default = "default_soak")]
    pub soak: String,
    /// Nodes to update after the control host (`all`, or names), as `self update --nodes`.
    #[serde(default)]
    pub nodes: Option<String>,
    /// The health gate's window (default 2m).
    #[serde(default = "default_gate")]
    pub gate_window: String,
}

fn default_workflow() -> String {
    ".github/workflows/build.yml".into()
}
fn default_api() -> String {
    "https://api.github.com".into()
}
fn default_soak() -> String {
    "1h".into()
}
fn default_gate() -> String {
    "2m".into()
}

pub fn config_path() -> PathBuf {
    crate::data_dir().join("ci-builds.yaml")
}

pub fn load() -> Result<CiConfig> {
    let p = config_path();
    let text = std::fs::read_to_string(&p).with_context(|| format!("{} (see docs/how-to/update-from-ci.md)", p.display()))?;
    let c: CiConfig = serde_yaml::from_str(&text).with_context(|| p.display().to_string())?;
    let ok = |s: &str| !s.is_empty() && s.chars().all(|ch| ch.is_ascii_alphanumeric() || "-_.".contains(ch));
    match c.repo.split_once('/') {
        Some((o, n)) if ok(o) && ok(n) => {}
        _ => bail!("{}: repo must be owner/name", p.display()),
    }
    if !c.workflow.starts_with(".github/workflows/") || c.workflow.contains("..") {
        bail!("{}: workflow must be a path under .github/workflows/", p.display());
    }
    Ok(c)
}

// ---- the API ----

/// GitHub's REST API, with the installation's token. The token goes to the API host only:
/// redirects (to the artifact store) are followed without it.
pub struct Gh {
    client: reqwest::Client,
    api: String,
    repo: String,
    token: String,
}

/// The most an artifact may be: the archive, and its signature.
const MAX_ARCHIVE: usize = 512 << 20;
const MAX_SIG: usize = 64 << 10;

impl Gh {
    pub fn new(c: &CiConfig, token: String) -> Result<Gh> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("wicket-self-update")
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(Gh { client, api: c.api.trim_end_matches('/').to_string(), repo: c.repo.clone(), token })
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}/repos/{}{path}", self.api, self.repo);
        let r = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .send()
            .await
            .with_context(|| format!("GitHub API {path}"))?;
        let status = r.status();
        if !status.is_success() {
            bail!("GitHub API {path}: {status}");
        }
        Ok(r.json().await?)
    }

    /// An artifact's bytes (uploaded unarchived), at most `max`.
    async fn download(&self, artifact_id: u64, max: usize) -> Result<Vec<u8>> {
        let url = format!("{}/repos/{}/actions/artifacts/{artifact_id}/zip", self.api, self.repo);
        let mut r = self.client.get(&url).bearer_auth(&self.token).header("accept", "application/vnd.github+json").send().await?;
        if r.status().is_redirection() {
            let to = r.headers().get("location").and_then(|l| l.to_str().ok()).context("a redirect without a location")?.to_string();
            if !to.starts_with("https://") && !self.api.starts_with("http://") {
                bail!("the artifact store isn't https");
            }
            // Without the token: it is the API's, not the store's.
            r = self.client.get(&to).send().await?;
        }
        if !r.status().is_success() {
            bail!("downloading artifact {artifact_id}: {}", r.status());
        }
        if r.content_length().is_some_and(|n| n as usize > max) {
            bail!("artifact {artifact_id} is larger than {max} bytes");
        }
        let mut out = Vec::new();
        let mut r = r;
        while let Some(chunk) = r.chunk().await? {
            out.extend_from_slice(&chunk);
            if out.len() > max {
                bail!("artifact {artifact_id} is larger than {max} bytes");
            }
        }
        Ok(out)
    }

    /// How `commit` stands to `main`: commits behind its head if it is on `main` (0: the head),
    /// None if it isn't (a branch's, or unknown).
    pub async fn behind_main(&self, commit: &str) -> Result<Option<u64>> {
        let v = self.get(&format!("/compare/main...{commit}")).await?;
        Ok(match v["status"].as_str() {
            Some("identical") => Some(0),
            Some("behind") => v["behind_by"].as_u64(),
            _ => None,
        })
    }

    /// Whether `head` descends from (or is) `base`.
    pub async fn descends(&self, base: &str, head: &str) -> Result<bool> {
        let v = self.get(&format!("/compare/{base}...{head}")).await?;
        Ok(matches!(v["status"].as_str(), Some("identical" | "ahead")))
    }

    async fn full_sha(&self, commit: &str) -> Result<String> {
        let v = self.get(&format!("/commits/{commit}")).await?;
        let sha = v["sha"].as_str().context("no such commit")?;
        if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("a malformed commit id from the API");
        }
        Ok(sha.to_ascii_lowercase())
    }
}

/// A signed build CI published: its commit, run, and the archive's and signature's artifacts.
#[derive(Clone, Debug, PartialEq)]
pub struct Build {
    pub commit: String,
    pub run_id: u64,
    pub archive: u64,
    pub sig: u64,
    /// Commits behind `main`'s head.
    pub behind: u64,
}

/// The successful push runs of the workflow on `main` (newest first) that published a signed build.
async fn published(gh: &Gh, c: &CiConfig, commit: Option<&str>) -> Result<Vec<(String, u64, u64, u64)>> {
    let file = c.workflow.rsplit('/').next().unwrap_or(&c.workflow);
    let filter = commit.map(|s| format!("&head_sha={s}")).unwrap_or_default();
    let runs = gh.get(&format!("/actions/workflows/{file}/runs?branch=main&event=push&status=success&per_page=30{filter}")).await?;
    let mut out = vec![];
    for r in runs["workflow_runs"].as_array().cloned().unwrap_or_default() {
        let (Some(id), Some(sha)) = (r["id"].as_u64(), r["head_sha"].as_str()) else { continue };
        if r["path"].as_str() != Some(c.workflow.as_str())
            || r["head_branch"].as_str() != Some("main")
            || r["event"].as_str() != Some("push")
        {
            continue;
        }
        let arts = gh.get(&format!("/actions/runs/{id}/artifacts?per_page=100")).await?;
        let list = arts["artifacts"].as_array().cloned().unwrap_or_default();
        let find = |pred: &dyn Fn(&str) -> bool| {
            list.iter()
                .find(|a| a["expired"].as_bool() != Some(true) && a["name"].as_str().is_some_and(pred))
                .and_then(|a| a["id"].as_u64())
        };
        let short = &sha[..sha.len().min(12)];
        let archive = find(&|n| n.ends_with("-x86_64-linux.tar.gz") && n.contains(short));
        let sig = find(&|n| n.ends_with("-x86_64-linux.tar.gz.sig") && n.contains(short));
        if let (Some(a), Some(s)) = (archive, sig) {
            out.push((sha.to_ascii_lowercase(), id, a, s));
        }
    }
    Ok(out)
}

/// The newest signed build of `main` by its history, not by when it ran (a re-run of an old run
/// signs an old commit again): the one fewest commits behind `main`'s head. Ties: the newest run.
pub fn newest(builds: &[Build]) -> Option<&Build> {
    builds.iter().min_by_key(|b| (b.behind, std::cmp::Reverse(b.run_id)))
}

/// Finds the signed build for `target` (a commit, or `latest`): on `main`, or refused.
pub async fn resolve(gh: &Gh, c: &CiConfig, target: &str) -> Result<Build> {
    if target == "latest" {
        let mut builds = vec![];
        for (commit, run_id, archive, sig) in published(gh, c, None).await? {
            if let Some(behind) = gh.behind_main(&commit).await? {
                builds.push(Build { commit, run_id, archive, sig, behind });
            }
        }
        return newest(&builds).cloned().context("no signed build of main (has the release environment approved one?)");
    }
    if !(7..=40).contains(&target.len()) || !target.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("{target:?}: a commit id (7 to 40 hex digits) or `latest`");
    }
    let commit = gh.full_sha(target).await?;
    let behind = gh.behind_main(&commit).await?.with_context(|| format!("commit {commit} is not on main"))?;
    let (_, run_id, archive, sig) = published(gh, c, Some(&commit))
        .await?
        .into_iter()
        .find(|b| b.0 == commit)
        .with_context(|| format!("no signed build of commit {commit} (not built yet, its signing not approved, or expired)"))?;
    Ok(Build { commit, run_id, archive, sig, behind })
}

/// Downloads a build's archive and signature into `dir` (private), under fixed names.
pub async fn fetch(gh: &Gh, b: &Build, dir: &Path) -> Result<(PathBuf, PathBuf)> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let (archive, sig) = (dir.join("build.tar.gz"), dir.join("build.tar.gz.sig"));
    std::fs::write(&archive, gh.download(b.archive, MAX_ARCHIVE).await?)?;
    std::fs::write(&sig, gh.download(b.sig, MAX_SIG).await?)?;
    Ok((archive, sig))
}

fn connect(c: &CiConfig) -> Result<Gh> {
    let token = wicket_proxy::vault::Vault::new(wicket_proxy::vault::Vault::default_dir())
        .get(&c.token_secret)
        .with_context(|| format!("the GitHub token (vault secret {})", c.token_secret))?;
    Gh::new(c, token.trim().to_string())
}

/// `wicket self update --from-ci <commit|latest>`.
pub async fn update_from_ci(target: &str, nodes: Option<String>, only_nodes: bool, gate: Gate, prune: bool) -> Result<()> {
    let c = load()?;
    let gh = connect(&c)?;
    let b = resolve(&gh, &c, target).await?;
    println!("[wicket] CI build of {} (run {}), {} commit(s) behind main", b.commit, b.run_id, b.behind);
    take(&gh, &c, &b, nodes, only_nodes, gate, prune).await
}

async fn take(gh: &Gh, c: &CiConfig, b: &Build, nodes: Option<String>, only_nodes: bool, gate: Gate, prune: bool) -> Result<()> {
    let dir = crate::data_dir().join(format!("ci-download-{}", std::process::id()));
    let _clean = Remove(dir.clone());
    let (archive, sig) = fetch(gh, b, &dir).await?;
    let ci = CiExpect { repo: c.repo.clone(), workflow: c.workflow.clone(), commit: b.commit.clone() };
    update::update(update::UpdateOpts { artifact: archive, sig: Some(sig), nodes, only_nodes, gate, prune, ci: Some(ci) }).await
}

struct Remove(PathBuf);
impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- following main ----

/// What `self follow` remembers between runs (`<data dir>/follow.json`).
#[derive(Default, Serialize, Deserialize)]
struct FollowState {
    /// Builds whose update failed here (its gate, or a refusal): not tried again.
    #[serde(default)]
    failed: Vec<String>,
    /// Why the last run didn't update, if it didn't: audited when it changes, not every run.
    #[serde(default)]
    last: Option<String>,
}

fn state_path() -> PathBuf {
    crate::data_dir().join("follow.json")
}

fn load_state() -> FollowState {
    std::fs::read(state_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_state(s: &FollowState) {
    let _ = crate::nodesecrets::write_atomic(&state_path(), &serde_json::to_vec(s).unwrap_or_default());
}

/// Whether `minute` (minutes past midnight, UTC) is in `window` (`HH:MM-HH:MM`, may wrap).
pub fn in_window(window: &str, minute: u32) -> Result<bool> {
    let parse = |t: &str| -> Result<u32> {
        let (h, m) = t.trim().split_once(':').context("HH:MM")?;
        let (h, m): (u32, u32) = (h.parse()?, m.parse()?);
        if h > 23 || m > 59 {
            bail!("HH:MM");
        }
        Ok(h * 60 + m)
    };
    let (a, b) = window.split_once('-').context("window: HH:MM-HH:MM")?;
    let (a, b) = (parse(a).context("window: HH:MM-HH:MM")?, parse(b).context("window: HH:MM-HH:MM")?);
    Ok(if a <= b { (a..b).contains(&minute) } else { minute >= a || minute < b })
}

/// Why a build may not be taken unattended, from what the running build and it are: None, it may.
pub fn contract_step(here: &update::Describe, new: &update::Describe) -> Option<String> {
    if new.schema_floor > here.schema_floor {
        return Some(format!(
            "it raises the ledger's schema floor from {} to {} (a contract step: an operator updates across it)",
            here.schema_floor, new.schema_floor
        ));
    }
    if new.protocol.abs_diff(here.protocol) > here.protocol_skew {
        return Some(format!("it speaks protocol {}, this build {} (one version at a time, by an operator)", new.protocol, here.protocol));
    }
    None
}

/// `wicket self follow`: one look at `main`, updating to its newest signed build if the policy lets
/// it. Run by the `wicket-follow` timer.
pub async fn follow() -> Result<()> {
    let c = load()?;
    let Some(p) = c.follow.clone() else {
        println!("[wicket] follow: no follow policy in {}; nothing to do", config_path().display());
        return Ok(());
    };
    let mut st = load_state();
    let ledger = wicket_store::Ledger::open(&crate::ledger_path())?;
    // Audited once per reason, not on every run.
    let skip = |st: &mut FollowState, key: String, why: String| -> Result<()> {
        println!("[wicket] follow: not updating: {why}");
        if st.last.as_deref() != Some(key.as_str()) {
            ledger.audit(&wicket_core::TenantId::single(), None, "self.follow_skipped", &serde_json::json!({ "why": why }))?;
            st.last = Some(key);
            save_state(st);
        }
        Ok(())
    };
    let now = wicket_store::now();
    if let Some(w) = &p.window {
        let minute = u32::try_from(now.rem_euclid(86_400) / 60).unwrap_or(0);
        if !in_window(w, minute)? {
            println!("[wicket] follow: outside the window {w} (UTC)");
            return Ok(());
        }
    }
    let v = update::Versions::control();
    let running = v.pointer("current").and_then(|id| v.manifest(&id).ok());
    let Some(running_commit) = running.as_ref().and_then(|m| m.source["ci"]["commit"].as_str().map(String::from)) else {
        return skip(
            &mut st,
            "not-ci".into(),
            "the running build isn't a CI build: update to one with `wicket self update --from-ci latest` first".into(),
        );
    };
    let gh = connect(&c)?;
    let b = resolve(&gh, &c, "latest").await?;
    if b.commit == running_commit {
        println!("[wicket] follow: up to date ({})", b.commit);
        return Ok(());
    }
    if st.failed.contains(&b.commit) {
        return skip(
            &mut st,
            format!("failed:{}", b.commit),
            format!("the update to {} failed here before; waiting for a newer build", b.commit),
        );
    }
    if !gh.descends(&running_commit, &b.commit).await? {
        return skip(
            &mut st,
            format!("behind:{}", b.commit),
            format!("{} isn't ahead of the running build's commit {running_commit} on main", b.commit),
        );
    }
    let dir = crate::data_dir().join(format!("ci-download-{}", std::process::id()));
    let _clean = Remove(dir.clone());
    let (archive, sig) = fetch(&gh, &b, &dir).await?;
    let ci = CiExpect { repo: c.repo.clone(), workflow: c.workflow.clone(), commit: b.commit.clone() };
    let claims: CiClaims = match update::verify_ci_files(&archive, &sig, &ci) {
        Ok((_, claims)) => claims,
        Err(e) => {
            st.failed.push(b.commit.clone());
            return skip(&mut st, format!("unsigned:{}", b.commit), format!("the build of {} isn't signed as it must be: {e:#}", b.commit));
        }
    };
    let soak = humantime::parse_duration(&p.soak).context("follow.soak")?.as_secs() as i64;
    if now - claims.signed_at < soak {
        return skip(
            &mut st,
            format!("soak:{}", b.commit),
            format!("{} was signed {}s ago; it soaks for {}", b.commit, now - claims.signed_at, p.soak),
        );
    }
    let new = update::describe_archive(&archive, &dir.join("describe"))?;
    if let Some(why) = contract_step(&update::describe()?, &new) {
        return skip(&mut st, format!("contract:{}", b.commit), format!("{}: {why}", b.commit));
    }
    ledger.audit(
        &wicket_core::TenantId::single(),
        None,
        "self.follow_update",
        &serde_json::json!({ "from": running_commit, "to": b.commit, "run": b.run_id, "signed_at": claims.signed_at }),
    )?;
    drop(ledger);
    let gate = Gate {
        window: humantime::parse_duration(&p.gate_window).context("follow.gate_window")?,
        interval: Duration::from_secs(10),
        checks: vec![],
        canary: None,
        image: None,
    };
    let r = update::update(update::UpdateOpts {
        artifact: archive,
        sig: Some(sig),
        nodes: p.nodes.clone(),
        only_nodes: false,
        gate,
        prune: true,
        ci: Some(ci),
    })
    .await;
    match r {
        Ok(()) => {
            st.last = None;
            save_state(&st);
            Ok(())
        }
        Err(e) => {
            st.failed.push(b.commit.clone());
            st.last = Some(format!("failed:{}", b.commit));
            save_state(&st);
            let l = wicket_store::Ledger::open(&crate::ledger_path())?;
            l.audit(
                &wicket_core::TenantId::single(),
                None,
                "self.follow_failed",
                &serde_json::json!({ "to": b.commit, "why": format!("{e:#}") }),
            )?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_wrap_past_midnight() {
        assert!(in_window("02:00-05:00", 3 * 60).unwrap());
        assert!(!in_window("02:00-05:00", 5 * 60).unwrap());
        assert!(in_window("22:00-02:00", 23 * 60).unwrap() && in_window("22:00-02:00", 60).unwrap());
        assert!(!in_window("22:00-02:00", 12 * 60).unwrap());
        assert!(in_window("25:00-02:00", 0).is_err());
    }

    #[test]
    fn newest_is_by_main_s_history_not_by_run() {
        let b = |commit: &str, run_id, behind| Build { commit: commit.into(), run_id, archive: 1, sig: 2, behind };
        // A re-run (newer run id) of an old commit doesn't win over main's head.
        let builds = vec![b("old", 99, 5), b("head", 10, 0), b("mid", 50, 2)];
        assert_eq!(newest(&builds).unwrap().commit, "head");
        assert!(newest(&[]).is_none());
    }

    #[test]
    fn a_contract_step_or_a_protocol_jump_needs_an_operator() {
        let here = update::Describe { version: "0".into(), build: "a".into(), protocol: 5, protocol_skew: 1, schema: 3, schema_floor: 1 };
        let mut new = here.clone();
        assert!(contract_step(&here, &new).is_none());
        new.schema = 4;
        assert!(contract_step(&here, &new).is_none(), "an expand step is fine");
        new.schema_floor = 2;
        assert!(contract_step(&here, &new).unwrap().contains("contract step"));
        let mut new = here.clone();
        new.protocol = 7;
        assert!(contract_step(&here, &new).unwrap().contains("protocol"));
    }

    /// A fake GitHub API on localhost: the routes `route` answers (status, extra headers, body),
    /// and every request's path and whether it carried the token.
    async fn fake_api(
        route: impl Fn(&str) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync + 'static,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let (route, seen2) = (std::sync::Arc::new(route), seen.clone());
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let (route, seen) = (route.clone(), seen2.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                    let authed = req.lines().any(|l| l.to_ascii_lowercase().starts_with("authorization: bearer tok"));
                    seen.lock().unwrap().push((path.clone(), authed));
                    let (status, headers, body) = route(&path);
                    let mut head = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n", body.len());
                    for (k, v) in headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = c.write_all(head.as_bytes()).await;
                    let _ = c.write_all(&body).await;
                });
            }
        });
        (base, seen)
    }

    fn sha(c: char) -> String {
        std::iter::repeat_n(c, 40).collect()
    }

    /// #190: `latest` is the newest signed build by main's history (a re-run of an old commit
    /// doesn't win, a branch's build is never taken); a commit is taken only on main; artifacts are
    /// fetched with the token from the API and without it from the store it redirects to.
    #[tokio::test]
    async fn builds_are_resolved_by_main_s_history_and_fetched_without_leaking_the_token() {
        let (head, old, branch) = (sha('a'), sha('b'), sha('c'));
        let (h2, o2, b2) = (head.clone(), old.clone(), branch.clone());
        let base = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let base2 = base.clone();
        let (api, seen) = fake_api(move |path| {
            let json = |v: serde_json::Value| (200, vec![("content-type".into(), "application/json".into())], v.to_string().into_bytes());
            let run = |id: u64, sha: &str| serde_json::json!({ "id": id, "head_sha": sha, "head_branch": "main", "event": "push", "path": ".github/workflows/build.yml" });
            let arts = |sha: &str, a: u64| {
                let name = format!("wicket-0.0.1-{}-x86_64-linux.tar.gz", &sha[..12]);
                serde_json::json!({ "artifacts": [{ "id": a, "name": name, "expired": false }, { "id": a + 1, "name": format!("{name}.sig"), "expired": false }] })
            };
            let p = path.split('?').next().unwrap_or("");
            match p {
                "/repos/acme/wicket/actions/workflows/build.yml/runs" => {
                    // Newest run first: an old commit's re-run, a branch build, then main's head.
                    let all = vec![run(99, &o2), run(50, &b2), run(10, &h2)];
                    let want = path.split("head_sha=").nth(1).map(|s| s.split('&').next().unwrap_or("").to_string());
                    let runs: Vec<_> = all.into_iter().filter(|r| want.as_deref().is_none_or(|w| r["head_sha"] == w)).collect();
                    json(serde_json::json!({ "workflow_runs": runs }))
                }
                "/repos/acme/wicket/actions/runs/99/artifacts" => json(arts(&o2, 990)),
                "/repos/acme/wicket/actions/runs/50/artifacts" => json(arts(&b2, 500)),
                "/repos/acme/wicket/actions/runs/10/artifacts" => json(arts(&h2, 100)),
                p if p.starts_with("/repos/acme/wicket/compare/main...") => {
                    let c = p.rsplit("...").next().unwrap_or("");
                    let v = if c == h2 {
                        serde_json::json!({ "status": "identical", "behind_by": 0 })
                    } else if c == o2 {
                        serde_json::json!({ "status": "behind", "behind_by": 7 })
                    } else {
                        serde_json::json!({ "status": "diverged", "behind_by": 3, "ahead_by": 1 })
                    };
                    json(v)
                }
                p if p.starts_with("/repos/acme/wicket/commits/") => {
                    let short = p.rsplit('/').next().unwrap_or("");
                    let full = [&h2, &o2, &b2].into_iter().find(|s| s.starts_with(short)).cloned().unwrap_or_default();
                    json(serde_json::json!({ "sha": full }))
                }
                "/repos/acme/wicket/actions/artifacts/100/zip" | "/repos/acme/wicket/actions/artifacts/101/zip" => {
                    let id = p.split('/').nth(6).unwrap_or("");
                    (302, vec![("location".into(), format!("{}/store/{id}", base2.lock().unwrap()))], vec![])
                }
                "/store/100" => (200, vec![], b"the archive".to_vec()),
                "/store/101" => (200, vec![], b"{\"sig\":1}".to_vec()),
                "/repos/acme/wicket/actions/artifacts/990/zip" => (200, vec![], vec![0u8; MAX_SIG + 1]),
                _ => (404, vec![], b"{}".to_vec()),
            }
        })
        .await;
        *base.lock().unwrap() = api.clone();
        let c =
            CiConfig { repo: "acme/wicket".into(), workflow: default_workflow(), token_secret: "t".into(), api: api.clone(), follow: None };
        let gh = Gh::new(&c, "tok".into()).unwrap();
        let b = resolve(&gh, &c, "latest").await.unwrap();
        assert_eq!((b.commit.as_str(), b.run_id, b.behind), (head.as_str(), 10, 0), "main's head, not the newest run");
        let o = resolve(&gh, &c, &old[..9]).await.unwrap();
        assert_eq!((o.commit.as_str(), o.behind), (old.as_str(), 7), "an older commit on main, by its short id");
        let e = resolve(&gh, &c, &branch).await.unwrap_err().to_string();
        assert!(e.contains("is not on main"), "{e}");
        assert!(resolve(&gh, &c, "../etc").await.is_err());
        let d = std::env::temp_dir().join(format!("wicket-ci-fetch-{}", std::process::id()));
        let (archive, sig) = fetch(&gh, &b, &d).await.unwrap();
        assert_eq!(std::fs::read(&archive).unwrap(), b"the archive");
        assert_eq!(std::fs::read(&sig).unwrap(), b"{\"sig\":1}");
        let seen = seen.lock().unwrap().clone();
        assert!(seen.iter().filter(|(p, _)| p.starts_with("/repos/")).all(|(_, a)| *a), "the API is asked with the token");
        assert!(seen.iter().filter(|(p, _)| p.starts_with("/store/")).all(|(_, a)| !*a), "the store never gets it: {seen:?}");
        // An oversized signature is refused, not written.
        assert!(gh.download(990, MAX_SIG).await.unwrap_err().to_string().contains("larger than"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
