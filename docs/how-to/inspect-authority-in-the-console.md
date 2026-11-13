# Inspect a run's authority in the console

Find out what a run may do, why a request was allowed or refused, and which policy it runs under,
from the console. Everything here is read-only. [The console reference](../reference/console.md#authority-views)
says what each view shows and never shows.

## A run's authority

1. Sign in to the console with your passkey.
2. In **Runs**, follow the run's **authority** link.
3. Read the card from the top:
   - **policy**: the org policy version the token was minted under. "not the installed …" means a
     later `wicket policy apply` changed it; such a run is revoked unless it was applied with
     `--keep-runs`.
   - **authority until**: when its authority ends (its deadline), and whether its box has stopped.
   - **secrets on its node** and **budget slice**: what its node holds for it, secrets by name.
   - **token**: whether it loads, then each block. Block 0 is the zone's ceiling; spawn blocks narrow
     it for a child run; grant blocks carry what a human approved. A block marked REVOKED takes the
     whole token (and every run below it) with it.
   - **grants**: each with its uses, expiry, approver, and "not yet on its node" while the feed delta
     carrying it hasn't reached the node.
   - **zone policy**: the zone's rules as Cedar, generated from its manifest.

## Why a request was allowed or refused

1. In **Activity**, find the request's row (decisions made on a node are marked "(node)").
2. Follow **explain**.
3. **recorded** is what was decided then; **token now** is the run's token's decision today, naming
   the block and check that decided (`block 0: check if …` for a forbid or reach rule in the zone's
   ceiling, `grant g-…` for an approval). If the two differ, a grant or the policy changed since.

To change any of it, use the signed actions (approve, deny, revoke) or `wicket policy apply`; these
views never change authority.

## The org policy

**Policy** shows the applied Cedar, every kept version with when and by whom it was applied, and the
running runs by the version they were minted under. A warning that `org.cedar` was changed by hand
means every new run is refused until you apply it: `sudo wicket policy apply <file>`.
