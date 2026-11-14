---
area: Identity, spawn and links
type: Changed
---
- One compact-JWS implementation signs and checks identity documents, envelopes, node certificates,
  audit checkpoints and the policy feed. Identity documents and envelopes are now checked with
  strict Ed25519 too, as the feed already was ([#254](https://github.com/public/wicket/issues/254)).
