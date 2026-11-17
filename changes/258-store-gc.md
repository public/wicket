---
area: Long-lived agents
type: Added
---
- The content-addressed stores are collected ([#258](https://github.com/public/wicket/issues/258), store.md step 4): a mark-and-sweep from the live roots (every agent's head and the write-once refs) deletes unreachable objects, local and in the shared state store, with push locks so a push in flight never loses what it just wrote. A local cache cap evicts objects the shared store already holds, least recently used first, never one only the local store has. The reconciler collects hourly, and `wicket state gc [--dry-run]` runs it by hand (a collection is privileged, a dry run reads). Deletions are audited.
