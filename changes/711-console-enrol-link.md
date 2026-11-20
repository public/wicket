---
area: Approvals and the console
type: Added
---
- A signed-in operator can enrol another device from the console (`enrol_link`), not only with
  `wicket operator enrol-link` on the host, which stays for the first passkey and for recovery. The link
  is signed for with the operator's passkey, single use, 5 minutes by default (at most 10), shown once and
  audited. The passkey it enrols takes its maker's name, so it has the same `operators.yaml` authority and
  never more; a link whose maker was revoked before it was used enrols nothing
  ([#711](https://github.com/public/wicket/issues/711)).
- Every signed console action must be signed by the passkey the session signed in with: the challenge
  offers only it, and another enrolled passkey's signature is refused and audited
  (`operator.action_refused`). The passkeys card has **Add a device**, which makes the link and shows it
  until it expires ([#711](https://github.com/public/wicket/issues/711)).
