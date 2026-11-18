---
area: Programs
type: Changed
---
- A pinned program's source is accepted by a grant on its digest, the one "may this digest run"
  check (#258). Running a manifest that pins it records the operator's grant (`run`, in the run's
  zone, for a day, audited as `digest.granted`), and every run is accepted by a live grant
  (`digest.accepted`, naming the grant). A pin that doesn't match the source is still refused,
  and an unpinned program is still a development run ([#258](https://github.com/public/wicket/issues/258)).
