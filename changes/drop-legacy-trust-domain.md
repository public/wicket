---
area: Identity, spawn and links
type: Removed
---
- An issuer key without a recorded trust domain is refused rather than given the old default
  `wicket.local`: such keys come only from development builds before trust domains were recorded
  ([#254](https://github.com/public/wicket/issues/254)).
