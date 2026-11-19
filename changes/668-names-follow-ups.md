---
area: Identity, spawn and links
type: Fixed
---
- Internal names ([#668](https://github.com/public/wicket/issues/668), follow-ups to
  [#575](https://github.com/public/wicket/issues/575)):
  - Only a zone whose name is already in DNS form (lower case, digits and `-` in each part) can hold
    names. A zone such as `Build` or `web_api` was given the same form as `build` or `web-api`,
    which are other zones, so one zone's box could take the other's names.
  - A run-scoped ask can't be approved once its run has ended. Asks of runs that ended without
    `run_ended` are withdrawn, and names such runs held are let go with a `name.released` record.
  - A box can link to another port of a box it already links to under a different name.
  - A failed `request_name` leaves a port the box exposed itself as it was.
  - `connect` by name against a control host at protocol 17 is refused with a clear message, instead
    of being read as `connect` with no box.
