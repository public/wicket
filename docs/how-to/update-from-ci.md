# Update from CI-signed builds

Every merge to `main` is built and tested in CI. A reviewer then approves its signing in the
repository's `release` environment, and installations update to that signed build: by hand with
`wicket self update --from-ci`, or on their own with the `wicket-follow` timer. Nothing reaches an
installation without that approval. [How updates work](../explanation/updates.md#builds-ci-signed)
explains the trust model.

There are no tags and no GitHub Releases: a build is an artifact of the workflow run that made it,
named by its commit, kept for 90 days.

## Once: the repository (the owner)

Do these in this order. GitHub creates an environment named in a workflow, unprotected, the first
time a run reaches it, so protect it before the secret exists. The `sign` job also refuses to sign
unless the environment has required reviewers and a branch rule.

1. **Settings → Environments → New environment**, name `release`.
2. **Required reviewers:** add the people who may approve a build (up to 6), and tick **Prevent
   self-review**, so whoever merged a pull request can't approve its build alone.
3. **Deployment branches and tags:** **Selected branches and tags**, add the rule `main`.
4. Optional: a **Wait timer**, so an approval takes effect only after that many minutes.
5. Leave **Allow administrators to bypass configured protection rules** unticked.
6. **The signing key**, on your own machine, never on an installation or in a box:

   ```
   openssl genpkey -algorithm ed25519 -out wicket-release.pem
   openssl pkey -in wicket-release.pem -pubout -out wicket-release.pub.pem
   ```

   Add the contents of `wicket-release.pem` as the environment's secret `WICKET_RELEASE_KEY`
   (**Environment secrets**, not repository secrets). Keep the private key offline, or delete it: a
   new one only needs trusting again. `wicket-release.pub.pem` goes to each installation.

The workflow is `.github/workflows/build.yml`. Its `build` job builds the archive (`ci/package.sh`,
reproducible) and runs the gates on every push to `main`. Its `sign` job waits for a reviewer, who sees
the commit, the gates and the archive's sha256 (in the `build` job's log). Approving gives the job the
key; it signs the archive's sha256 together with the commit, `refs/heads/main`, the repository, the
workflow, the run and the environment, using openssl only. Nothing from the repository or the build
runs while the key is there.

## Once: each installation (root)

1. Trust the key:

   ```
   sudo wicket self trust-key wicket-release.pub.pem
   ```

2. A GitHub token that can read the repository's Actions artifacts: a fine-grained token for this
   repository only, with **Actions: read** and nothing else. Store it in the vault:

   ```
   sudo wicket secret set github-ci-read --hosts api.github.com
   ```

   It is used on the control host only, sent only to the API (downloads are redirected to GitHub's
   artifact store, which gets no token), and never reaches a box.

3. `<data dir>/ci-builds.yaml` (`/var/lib/wicket/ci-builds.yaml` installed):

   ```yaml
   repo: owner/wicket            # the repository whose main this installation follows
   token_secret: github-ci-read
   # workflow: .github/workflows/build.yml   (the default)
   # follow:                                 (only for the timer, below)
   #   window: "02:00-05:00"                 UTC; absent: any time
   #   soak: 2h                              how long since it was signed (default 1h)
   #   nodes: all                            also update the nodes, as --nodes
   #   gate_window: 2m                       the health gate's window (default 2m)
   ```

   The repository is the installation's: a build signed for any other repository is refused,
   whatever its signature.

## Update by hand

```
sudo wicket self update --from-ci latest
sudo wicket self update --from-ci 1a2b3c4d5e6f
```

`latest` is the newest signed build by `main`'s history, not the newest run: a re-run of an old run
signs an old commit again, and isn't newer. A commit must be on `main` now, by GitHub's compare API.
The build is downloaded on the control host and taken only if all of these hold:

- it is signed by a trusted key;
- its claims name this repository, the workflow, that commit, `refs/heads/main` and the `release`
  environment;
- it was signed in the past.

Then the usual update runs: staged, switched, handed over, gated, rolled back on a failed gate. Every
flag of `self update` applies (`--nodes`, `--window`, `--check`, …). Root's own copy of the build,
which `sudo wicket` runs, isn't made: see [following](#follow-main-on-its-own) below.

The audit records the commit, the run, the environment and the signing key (`self.staged`'s
`source.ci`). A signature without the claims (from `wicket self sign`) doesn't do for `--from-ci`, and
no human approval of a sha256 stands in for one.

## Follow main on its own

With a `follow:` section in `ci-builds.yaml`, and the installation already on a CI build (one update
with `--from-ci` first):

```
sudo systemctl enable --now wicket-follow.timer
```

Every 15 minutes, `wicket self follow` looks for the newest signed build of `main` and updates to it,
with no one's approval, if:

- it is inside the window;
- it was signed at least `soak` ago, by its signed time;
- it is ahead of the running build's commit on `main` (never sideways, never back);
- it doesn't raise the ledger's schema floor (a contract step) or jump more than one protocol version:
  those wait for an operator's `--from-ci`;
- its update hasn't already failed here. A build whose gate failed is rolled back and not tried
  again; the next newer build is.

Each reason it doesn't update is audited once when it changes (`self.follow_skipped`). An update is
`self.follow_update`, then the usual `self.*` records; a failure is `self.follow_failed`.
`journalctl -u wicket-follow` shows every run. To stop following:
`sudo systemctl disable --now wicket-follow.timer`.

The build is downloaded as the `wicket` user, so root has no copy of it: wicket's services run it,
but `/usr/local/bin/wicket` (what `sudo wicket` and the timer itself run) stays on the build root
last copied, since root runs only its own copies (#261). To move root to it, download the archive
yourself and `sudo wicket self admit wicket-….tar.gz` ([update and roll back](update-and-roll-back.md#a-build-that-came-another-way)).

## What is refused

| what | why |
|---|---|
| a build not signed, or signed by a key the installation doesn't trust | `self.update_refused` |
| a signature without CI claims, for `--from-ci` | a hand-signed build isn't a CI build |
| claims for another repository, workflow, commit or ref, or not the `release` environment | the claims are what was asked for, or nothing |
| a commit not on `main` | GitHub's compare API: an ancestor of `main`'s head, or that head |
| a build edited after signing | the signature covers the claims' bytes and the archive's sha256 |
