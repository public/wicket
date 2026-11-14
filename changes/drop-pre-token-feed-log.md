---
area: Remote nodes and capacity
type: Removed
---
- A node feed's delta log from before boxes' authority moved to tokens is no longer set aside and
  replaced at start: a log that doesn't read is an error
  ([#254](https://github.com/public/wicket/issues/254)).
