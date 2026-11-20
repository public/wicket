---
area: Install and privilege separation
type: Changed
---
- Limits for many boxes ([#582](https://github.com/public/wicket/issues/582) step 4):
  - **Control-host units:** `wicketd`, `wicket-console` and `wicket-reconcile` set
    `LimitNOFILE=1048576`, `LimitNPROC=infinity` and `TasksMax=262144`, because every supervisor
    they start counts against them.
  - **Supervisors:** a supervisor (`wicket run`, `attach`, `wrap`, `wake`) runs a two-worker tokio
    runtime instead of one worker per core (`WICKET_SUPERVISOR_WORKERS` changes it, 1 to 64).
  - **Node unit:** `LimitNOFILE=524288` and `TasksMax=infinity`.
  - **Node setup:** `deploy/vultr/node-setup.sh` sets sshd's `MaxSessions 512` (for the wicket
    login) and `MaxStartups 64:30:256`, and lifts the wicket user's slice task limit and its user
    manager's process limit. For a live node, the docs give each setting on its own (don't re-run
    the script there: it restarts Docker), and the kernel's `pid_max` for thousands of boxes.
  [Daemon limits](../docs/reference/daemon.md#limits), [node limits](../docs/reference/nodes.md#limits).
