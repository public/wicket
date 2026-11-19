---
area: Development
type: Added
---
- A new library crate, `wicket-names`, holds the first part of DNS names for boxes
  ([#575](https://github.com/public/wicket/issues/575)): the rules for a name's label, DNS records
  and their owner records, the reconcile plan, the DNS provider trait, and a no-op provider that
  applies nothing and reports what it would do. The plan never updates or deletes a record wicket
  doesn't own, and property tests check that over random zones. Nothing uses the crate yet.
