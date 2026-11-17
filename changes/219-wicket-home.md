---
area: Development
type: Changed
---
- The installation's paths, identity issuer and caller are a library crate of their own,
  `wicket-home`, with the wicket-cli modules that needed nothing else of the CLI's (node
  authentication, the state store and audit export, the image policy, program digests, box owners
  and exit causes, a harness's control channel): they build and test without the rest of
  wicket-cli ([#219](https://github.com/public/wicket/issues/219)).
