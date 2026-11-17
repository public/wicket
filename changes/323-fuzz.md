---
area: Boxes and the egress path
type: Added
---
- Fuzz targets for everything a box can send: the egress proxy (with a no-smuggling oracle: what is
  decided is what goes upstream), the MCP gateway, the control/node channel, the feed, Biscuit box
  tokens, manifests, the store's trees and checkout, and git push decisions (`fuzz/`, see its
  README). Pull requests fuzz the targets their change selects for 60 s each (`ci/fuzz.sh`,
  `ci/determinator/suites.toml`); every target runs for 20 minutes nightly, and findings are filed
  ([#323](https://github.com/public/wicket/issues/323)).
