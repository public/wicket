---
area: Updates
type: Changed
---
- A trusted release key is a CI principal holding a standing grant to install what it signs
  (#258). The grant lasts a day and the reconciler renews it while the key file is still in
  `release-keys/`; revoking it (`wicket grant revoke`) or removing the key file stops the key
  within a day. A verified signature is accepted as that principal's one-use grant on the build's
  digest, through the one "may this digest run" check. An installed host moves over by itself: its
  first reconcile pass or update imports each key file as its grant
  ([#258](https://github.com/public/wicket/issues/258)).
