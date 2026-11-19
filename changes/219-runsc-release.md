---
area: Development
type: Changed
---
- CI's gVisor jobs install runsc from gVisor's release binary, pinned by version and checksum,
  instead of from its apt repository (#219). That repository's mid-sync retries had made the
  setup step 255-359 s on some runs, against about 90 s.
