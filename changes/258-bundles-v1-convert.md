---
area: Long-lived agents
type: Changed
---
- When the control host starts, it converts every agent's version-1 hibernation bundle (tar and
  zstd per tree) to a version-2 bundle tree in the content-addressed store. Each conversion is
  audited (`agent.bundle_converted`). An awake agent's head is left for its own next hibernation,
  which is version 2 ([#258](https://github.com/public/wicket/issues/258)).
- An agent whose workspace holds a file name that isn't UTF-8 is no longer hibernated as a
  version-1 bundle. The hibernation fails with an error naming the file, audited as
  `agent.hibernate_failed`, and the agent stays as it was. Rename the file to hibernate it.
