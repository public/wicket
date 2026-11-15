---
area: Boxes and the egress path
type: Fixed
---
- A request path with a character a URL parser percent-encodes (space, `"`, `<`, `>`, `` ` ``, `{`,
  `}`, or anything non-ASCII), sent raw, is refused as ambiguous. It used to be decided as written
  and sent upstream encoded (`/a{b` decided, `/a%7Bb` sent). Percent-encoded, it is accepted as
  before. Found by fuzzing ([#323](https://github.com/public/wicket/issues/323)).
