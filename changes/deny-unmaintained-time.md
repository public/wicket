---
area: Build and CI
type: Changed
---
- cargo deny accepts two advisories published on 2026-11-17, with their reasons in deny.toml: chrono is unmaintained (RUSTSEC-2026-0543; wicket only reaches it through cedar-policy-core) and humantime is unmaintained (RUSTSEC-2026-0542; wicket uses it directly, and replacing it is tracked separately).
