---
area: Long-lived agents
type: Fixed
---
- Triggers ([#578](https://github.com/public/wicket/issues/578)): a schedule with fixed hours fires
  once a day across a daylight-saving change, as cron does. It fires the first time a repeated
  wall-clock time comes round, and just after a skipped hour. A timer that has fired, or whose
  time passed, is marked `done` (audited as `trigger.done`). It stays listed until removed, and a
  new trigger of its name replaces it.
