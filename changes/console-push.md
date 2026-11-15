---
area: Approvals and the console
type: Added
---
- The console notifies your devices when a request is waiting (Web Push: RFC 8030, RFC 8291
  encryption, RFC 8292 VAPID). This covers egress asks and wicket's capacity, update, spawn and link
  asks, in desktop browsers and in the iOS home-screen app. **Enable notifications** in the new
  *Notifications* section registers a device, signed with your passkey (`push_subscribe`), so a stolen
  session cookie alone can't add a device. Devices are listed per passkey with a **Remove** button,
  and each change is audited; unsigned attempts to register a device or to turn its details on are
  refused and audited as `operator.push_refused`. Pushes go only to known push services
  (FCM, Apple, Mozilla, WNS), at most one per device every 30 seconds with new requests coalesced,
  with a TTL of an hour, high urgency and a collapsing `Topic`. By default a push says only how many
  requests are waiting; each device can opt in to the agent and what it asks for (signed,
  `push_details`; opting out needs only the session). Push services answering 404 or 410 drop the
  device. When a browser replaces a subscription (`pushsubscriptionchange`), the service worker says
  so and the console offers a signed re-registration the next time it is open. The VAPID key is made once in `$WICKET_HOME/console/vapid.key`
  (0600). See [notifications](../docs/reference/console.md#notifications) and [get notified of
  approvals](../docs/how-to/get-notified-of-approvals.md).
