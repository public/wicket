---
area: Images
type: Added
---
- A node removes the images it was sent or pulled once no box has started from them for 7 days
  (`image_keep_days` in its `node.json`, `0` to keep them all), never forced: an image a container
  was made from, or that a live box or its zone's `images` may start from, is kept. Each removal is
  audited as `image.removed` ([#191](https://github.com/public/wicket/issues/191)).
