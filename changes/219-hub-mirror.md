---
area: Build and CI
type: Fixed
---
- The gVisor CI jobs pull Docker Hub images through `mirror.gcr.io` first
  ([#219](https://github.com/public/wicket/issues/219)). The setup action adds it to Docker's
  `registry-mirrors` beside runsc, so the runsc self-test's `busybox` and the agent image's base
  images no longer hit Docker Hub's anonymous pull rate limit ("toomanyrequests"), which once failed
  a run in setup. Docker falls back to Hub itself if the mirror lacks an image.
