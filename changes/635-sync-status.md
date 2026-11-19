---
area: Operations and audit
type: Added
---
- `wicket state check` says where the ledger's stream to the state store is: streaming, lagging or
  stopped, when Litestream last brought the store up to date, and its last error. `wicket state
  replicate` turns on Litestream's control socket (`<data dir>/litestream.sock`) and keeps
  Litestream's last error in `<data dir>/state-stream.json`; the position is Litestream's own. It
  also shows each `store` audit sink's progress
  ([#635](https://github.com/public/wicket/issues/635)).
- `wicket audit export --status` shows how many records each sink is behind the chain head, how long
  the oldest of them has waited, and how long ago its last signed checkpoint was. The console's
  `/api/state` carries both under `health.state_store`.
- An audit sink's stored error (`wicket audit export --status`, the console) and Litestream's no longer
  keep a URL's user info, query or fragment, where tokens travel.
- `state-store.yaml` refuses an `s3.endpoint` with user info in it (`https://key:secret@…`): the
  secret access key goes in `secret:`. Its errors no longer repeat the endpoint.
