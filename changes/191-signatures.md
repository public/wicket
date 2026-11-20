---
area: Images
type: Added
---
- `images.yaml` takes a `trust` policy: which keys must have signed which images, by repository and
  zone. A run whose image, or any of its zone's `images`, a rule requires signed starts only if one of
  the rule's keys signed exactly its digest (cosign signatures made with a key, ECDSA P-256 or
  Ed25519), checked on the control host before the box starts. Each check is audited as
  `image.signature` with the key's fingerprint and the signature's digest, and `run.image` records
  the run's signature ([#191](https://github.com/public/wicket/issues/191)).
