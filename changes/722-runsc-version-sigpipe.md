---
area: Development
type: Fixed
---
- CI's gVisor setup no longer fails now and then with exit code 141: it printed `runsc --version`
  through `head -1`, and under `pipefail` runsc could die of SIGPIPE after `head` exited. It reads
  the whole output now ([#722](https://github.com/public/wicket/issues/722)).
