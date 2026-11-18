---
area: Development
type: Fixed
---
- Kani's image-pin harness took 28 minutes of a CI shard, because `image::repository`'s char search
  is costly to unwind. `repository` now searches bytes, which gives the same result, and
  `patterns_overlap`'s harness (98 s) is split in three
  ([#325](https://github.com/public/wicket/issues/325)).
