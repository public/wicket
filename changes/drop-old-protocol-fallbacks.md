---
area: Remote nodes and capacity
type: Removed
---
- The fallbacks for control/node protocols 1 to 4 are gone (relaying model calls and injected hosts
  to a control host that kept the credential, the per-run lease message, the version checks before
  minting issuing-key and org-policy tokens): a peer more than one version behind is refused at the
  handshake anyway ([#254](https://github.com/public/wicket/issues/254)).
