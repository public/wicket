---
area: Images
type: Added
---
- A node removes the images it was sent or pulled once none has been used for 7 days of it serving
  (`image_keep_days` in its `node.json`, `0` to keep them all). Removal is never forced: an image a
  container was made from, a box is starting from, or a live box or its zone's `images` may start
  from is kept. Each removal is audited as `image.removed`, and a kept or failed one as `image.kept`
  or `image.remove_failed`. A start whose image is on neither the node, the control host nor a
  listed registry now fails saying so ([#191](https://github.com/public/wicket/issues/191)).
