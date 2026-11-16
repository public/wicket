---
area: Boxes and the egress path
type: Security
---
- Credential placeholders are canaries (#362): a run's placeholder seen anywhere but
  `Authorization: Bearer <placeholder>` to its own host (another host, the URL, a request body,
  another header), or another run's placeholder seen at all, refuses the request with a `403`,
  is audited as an `anomaly` (`placeholder.moved`) and counts as a strike. A streamed body is cut
  off before the placeholder's first byte goes upstream. A model call's body (the conversation)
  isn't scanned. A bearer on a placeholder's host that isn't the placeholder is still dropped, and
  now audited (`placeholder.unknown`, once per host per run).
- Responses from a host wicket attached a credential to can no longer reflect it into the box:
  wicket asks for them unencoded and refuses (`502`) a compressed reply, and masks the credential
  in the body as it streams, raw or in base64 or hex (an `anomaly`, `secret.reflected`, is audited).
