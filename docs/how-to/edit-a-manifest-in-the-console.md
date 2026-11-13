# Edit a manifest in the console

Read what a manifest grants, change it, and see what the change does to its authority before you
sign it. [The console reference](../reference/console.md#manifests) has the details.

1. Sign in to the console with your passkey and find **Manifests**.
2. Follow **view / edit** on one of the installation's manifests (those under `examples/` are
   read-only), or **new manifest** to write one.
3. Read it first:
   - **valid**, or the error `wicket run` would give;
   - what it grants: reach, the hosts the proxy splices (not inspected) or inspects, forbids,
     injections (a secret marked NOT SET is missing from the vault: `sudo wicket secret set NAME`),
     the model route and budgets, limits, and the org policy's verdict;
   - every field, with `(default)` beside the ones the file doesn't set.
4. Edit the YAML. Below it, as you type:
   - **valid** or the error;
   - **WIDENS authority**, with each way it does (a new host or method, a bigger budget, a removed
     forbid, a new injection), or **does not widen authority**;
   - the list of changes, `+` added, `-` removed, `~` before → after.
5. **Save…** shows exactly what your passkey signs: the new version's hash, the one it replaces, and
   whether it widens. Sign it. If someone changed the file since you opened it, the save is refused:
   open it again.
6. To go back, follow **restore…** beside a saved version, and sign that.

Runs already started keep the manifest they started with; the next run uses the saved one.
