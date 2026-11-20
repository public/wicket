---
area: Remote nodes and capacity
type: Fixed
---
- Placement ([#579](https://github.com/public/wicket/issues/579)): a placed (paid) node that has
  ended counts as past its lease, by its latest record, so a node whose enrolment outlived it is no
  candidate for a fresh run or a wake. Before, only active placed nodes were checked, and an ended
  one whose node row was still active counted as never placed.
