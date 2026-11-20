---
area: Identity, spawn and links
type: Added
---
- Public names ([#575](https://github.com/public/wicket/issues/575), step 5a): the `vultr` DNS
  provider. With `names.public.provider: vultr` and `names.public.credential` naming the vault
  secret that holds a Vultr API key, `wicket reconcile` publishes the boxes zone's records through
  Vultr's DNS API: owner TXT, A, AAAA and SRV records are created, updated when a box moves, and
  deleted, owner record last, when a name ends. Each change is one request, in the plan's order; a
  pass that stops part way counts only what it made. A zone the account doesn't serve, or a listing
  that couldn't be read whole, is an error and nothing is forgotten. The provider is named
  `vultr:<key fingerprint>` in the ledger, never by the key. `wicket reconcile --dry-run` lists and
  plans without writing. See [box DNS](../docs/explanation/box-dns.md#trying-the-vultr-provider-against-a-test-zone) for an opt-in manual
  check against a real test zone.
