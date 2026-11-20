---
area: Images
type: Security
---
- The agent image installs Claude Code from its registry tarballs, each checked against a sha512
  recorded in the Dockerfile, and runs no package's install script
  ([#721](https://github.com/public/wicket/issues/721)). The ACP example's adapter and its
  dependencies install with `npm ci --ignore-scripts` from a committed lockfile.
