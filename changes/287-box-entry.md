---
area: Images
type: Changed
---
- A box starts its program sooner (#287). `wicket-entry` now starts the forwarder first, while it
  adds wicket.internal's addresses, and the forwarder (`wicket-fwd --control`) makes the agent's
  directories, the CA bundle and the start's step times itself, as the agent's user. Before, each of
  those steps ran in a process of its own. The script waits for the forwarder to say its listeners
  are bound instead of polling every 100 ms, and builds its single `ip -batch` without `seq` or
  `sed`. The program still never starts before every TCP and UDP listener is bound. A forwarder that
  fails, or never answers, now ends the box instead of starting the program without its proxies. The
  privilege drop (`setpriv`, no capabilities, an empty bounding set) is unchanged. Images built by an
  older `wicket image` keep the old start until they're rebuilt.
