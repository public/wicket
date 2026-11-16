---
area: Long-lived agents
type: Changed
---
- Hibernation is incremental ([#365](https://github.com/public/wicket/issues/365)). An agent's
  state goes into the content-addressed store as a bundle tree (`<data dir>/store`), file by file,
  so a hibernation writes only the files that changed since an earlier one. With `bundles: s3` it
  sends the state store only what it lacks, before the agent counts as hibernated, and a wake
  fetches what the local store lacks. Agents hibernated before this still wake. One whose files have
  names that aren't UTF-8 is kept as before, as a full copy, and the log says so. `wicket agents`
  shows a bundle's restored size, since its objects are shared with other bundles.
