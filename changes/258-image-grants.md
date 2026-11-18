---
area: Images
type: Changed
---
- A run's pinned image is accepted by a grant on its digest, the one "may this digest run" check
  (#258), as a pinned program's source is. Running a manifest with a pinned image records the
  operator's grant (`run`, in the run's zone, for a day; `digest.granted`), and each run is
  accepted by a live grant (`digest.accepted`). `images.yaml`'s `require_digests` still decides
  whether tags may run ([#258](https://github.com/public/wicket/issues/258)).
