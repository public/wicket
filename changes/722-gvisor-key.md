---
area: Install and privilege separation
type: Security
---
- `deploy/install.sh` and the Vultr node setup accept gVisor's apt signing key only if it is the one
  key with the fingerprint pinned in the script, so a key served from a compromised or spoofed
  gvisor.dev, or a second key appended to it, stops the install
  ([#722](https://github.com/public/wicket/issues/722)).
