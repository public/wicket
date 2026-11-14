---
area: Images
type: Added
---
- Nodes pull a box's pinned image themselves, by digest, from a registry `images.yaml` lists
  (`registries`), host-side and never from inside a box: only the registry's own hosts are
  reached, every blob is checked against its digest, and the registry's credential is a vault
  secret the node fetches for that pull only. If the pull fails, the control host sends the image.
  Protocol 8 ([#191](https://github.com/public/wicket/issues/191)).
