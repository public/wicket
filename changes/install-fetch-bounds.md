---
area: Updates
type: Changed
---
- `install.sh` gives up on a package mirror or gVisor's repository that stops answering, instead
  of waiting for as long as it stalls. apt drops a connection after 30 s without an answer and
  retries it, and the gVisor key download is limited to a minute and retried. Each step it
  announces now starts with its time (UTC), so a slow install shows which step it is in.
