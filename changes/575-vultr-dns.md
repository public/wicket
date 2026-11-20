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
  that couldn't be read whole (a page failing, a page without its records or paging data, or a
  count other than the total Vultr gives), is an error and nothing is forgotten; placement's
  listing of its Vultr machines is held to the same, so a short listing no longer reads as
  machines gone. Duplicates of a record are all deleted, or on an update reduced to the one
  updated; SRV targets are sent fully qualified; the key is sent only to `https://api.vultr.com`. The provider is named
  `vultr:<key fingerprint>` in the ledger, never by the key. `wicket reconcile --dry-run` lists and
  plans without writing. See [box DNS](../docs/explanation/box-dns.md#trying-the-vultr-provider-against-a-test-zone) for an opt-in manual
  check against a real test zone. Its TTL is at least 60 (`names.public.ttl`), since Vultr raises a lower one to 60.
