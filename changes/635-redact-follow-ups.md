---
area: Approvals and the console
type: Fixed
---
- A stored error cuts a URL to its scheme (`https://…`) when a letter or digit outside ASCII stands
  right before it, or in place of its scheme (`ｈｔｔｐｓ://`), and redacting a large error body no
  longer takes time quadratic in its closing brackets
  ([#635](https://github.com/public/wicket/issues/635)).
