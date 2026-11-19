---
area: Manifests
type: Added
---
- A program's manifest may say it is a per-node service (`service:`: port, the environment its
  users get, tenancy, drain), and a zone may name the services its boxes use (`zone.uses`)
  ([#579](https://github.com/public/wicket/issues/579), step 3). Using a service is having its
  reach: a spawned zone may use only services its parent uses, and no approval widens that. A
  service is per tenant unless its manifest declares `public_only: true` for `tenancy: shared`.
  Nothing starts services or links boxes to them yet: that comes in the next changes.
