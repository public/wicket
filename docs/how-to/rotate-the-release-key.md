# Rotate the release signing key

wicket's CI-signed builds ([update from CI-signed builds](update-from-ci.md)) are signed with one
Ed25519 key, the release key. This page says where each half of it lives, who can use it, and how to
replace it: on a schedule, or at once if it may have leaked.

## Where the key lives

| What | Where | Who can use it |
|---|---|---|
| The private key | The `release` environment's secret `WICKET_RELEASE_KEY` (Settings → Environments → `release` → Environment secrets) | Only the `sign` job of `.github/workflows/build.yml`, and only after a required reviewer approves that run. The job refuses to start unless the environment has required reviewers and is restricted to `main`. It holds the key for one `openssl` call, and runs nothing from the repository or the build while it has it. |
| A copy of the private key | Offline, if you kept one (removable media, a password manager), or nowhere | Whoever holds that copy. You don't need one: a lost key is replaced, not recovered. |
| The public key | `<data dir>/release-keys/<key id>.pub` on each installation (`/var/lib/wicket/release-keys/` installed), and a standing grant in its ledger for the principal `release-key:<key id>` | Each installation, to check a build before it takes it. |

The **key id** is the first 16 hex digits of the sha256 of the 32-byte public key. The `sign` job
prints it in its log (`signed wicket-… (sha256) at <commit>, key <key id>`), `wicket self trust-key`
prints it, and it names the file in `release-keys/`. Compare them when you rotate.

GitHub never shows a secret again once it is saved, and nobody can read it from a workflow run's
log or artifacts: the job writes it to a 0600 file under the runner's temporary directory and
deletes it straight after signing.

## Who can produce a signed build

Only a run of `build.yml` on `main` that a required reviewer of the `release` environment approves.
Check the environment ([update from CI-signed builds](update-from-ci.md#once-the-repository-the-owner)):

- **Required reviewers:** the people who may approve a build, with **Prevent self-review** ticked.
- **Deployment branches and tags:** the single rule `main`.
- **Allow administrators to bypass configured protection rules:** unticked.

The reviewer sees the run's commit, its gates and the archive's sha256 (in the `build` job's log)
before approving. An approval signs exactly that archive, for that commit, `refs/heads/main`, this
repository, this workflow, this run and the `release` environment. An installation checks each of
these claims before it takes the build.

## Rotate it on a schedule

Trust the new key everywhere before CI signs with it, so no installation sees a build it can't
check. Builds already signed with the old key stay valid until you stop trusting it.

1. **Make the new key**, on your own machine, never on an installation or in a box:

   ```
   openssl genpkey -algorithm ed25519 -out wicket-release-2.pem
   openssl pkey -in wicket-release-2.pem -pubout -out wicket-release-2.pub.pem
   ```

2. **Trust it on every installation** (root), alongside the old one:

   ```
   sudo wicket self trust-key wicket-release-2.pub.pem
   ```

   It prints the new key id and its standing grant. Both keys are now accepted.

3. **Give CI the new key:** Settings → Environments → `release` → Environment secrets →
   `WICKET_RELEASE_KEY` → update it with the contents of `wicket-release-2.pem`. Keep the private
   key offline, or delete it.

4. **Check the next signed build** uses it: its `sign` job's log shows the new key id. An
   installation takes it with `sudo wicket self update --from-ci latest` (or its `wicket-follow`
   timer), and the audit's `self.staged` record names the key.

5. **Stop trusting the old key** on every installation, once each has taken a build signed with the new
   one (or once you no longer want old builds to install):

   ```
   sudo rm /var/lib/wicket/release-keys/<old key id>.pub
   ```

   The reconciler then revokes the old key's standing grant (`self.key_untrusted` in the audit), at
   most a day later. To stop it at once, also revoke the grant itself: `wicket audit` shows it in the
   old key's `self.key_trusted` record, and `sudo wicket grant revoke <grant>` revokes it.

From then on, a build signed with the old key is refused (`self.update_refused`), wherever it comes
from.

## If the key may have leaked

Someone with the private key can sign an archive that installations would take, if it also
carries claims for this repository, `main` and the `release` environment. So stop trusting the old
key first, then replace it.

1. **On every installation, stop trusting the old key now**, as in step 5 above: delete its file and
   revoke its grant. Stop the follow timer until you are done:
   `sudo systemctl disable --now wicket-follow.timer`.
2. **Delete the secret** in the `release` environment, so no approval can sign with it again.
3. **Look for builds it signed** that you didn't approve: each installation's audit
   (`wicket audit`, `self.staged` and `self.update_refused`, by key id), and the repository's
   Actions runs of `build.yml` and the `release` environment's deployment history.
4. **Rotate** as above (steps 1 to 4), then re-enable the timer.

An installation already running a build is not changed by any of this. If it took a build you don't
trust, `sudo wicket self rollback` returns it to the previous build
([update and roll back](update-and-roll-back.md)).

## Keys for your own builds

`wicket self keygen` and `wicket self sign` sign builds you make yourself, outside CI. They are
checked against the same `release-keys/`, and rotate the same way: trust the new key, sign with it,
remove the old one ([update and roll back](update-and-roll-back.md)).
