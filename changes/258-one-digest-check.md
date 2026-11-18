---
area: Updates
type: Removed
---
- "May this digest run" has one answer, a grant on the digest (#258). The separate checks are
  gone: a key file in `release-keys/` only keeps its CI principal's standing grant renewed; a
  program pin is no gate of its own (the pin records a grant on the pinned digest, and a source
  that isn't it has none, so the one check refuses it); `images.yaml`'s `require_digests` is read
  and ignored (its `registries` stay); and an update approval is accepted only through the
  operator's grant on the build's digest. A pin by the digest from before #258 still runs, with its
  warning ([#258](https://github.com/public/wicket/issues/258)).
