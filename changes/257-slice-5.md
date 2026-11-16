---
area: Boxes and the egress path
type: Removed
---
- A run has no CA of its own on the control host (`ctl/run-ca.key`, `ctl/run-ca.pem`): the control
  host has terminated no TLS since its egress proxy went (#257), so the CA signed nothing, but every
  box still trusted it. A box trusts the installation root alone, which signs its node CA's leaves.
  `BoxStart.ca_pem` is sent empty, for nodes at protocol 13 that read it
  ([#257](https://github.com/public/wicket/issues/257)).
