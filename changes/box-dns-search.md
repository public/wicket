---
area: Boxes and the egress path
type: Security
---
- A box's `/etc/resolv.conf` has no search domain. Docker copied the host's, so on a cloud host every
  name a box looked up reached wicket's DNS with the host's region appended
  (`<name>.us-west-2.compute.internal`), and the box's own hostname resolved under it. The escape
  box in the acceptance suite now checks for it.
