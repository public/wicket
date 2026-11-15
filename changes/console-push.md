---
area: Approvals and the console
type: Added
---
- The console notifies your devices when a request is waiting (Web Push: RFC 8030, RFC 8291
  encryption, RFC 8292 VAPID). This covers egress asks and wicket's capacity, update, spawn and link
  asks, in desktop browsers and in the iOS home-screen app. **Enable notifications** in the new
  *Notifications* section subscribes a device from a signed-in session. Devices are listed per passkey
  with a **Remove** button, and each change is audited. Pushes go only to known push services
  (FCM, Apple, Mozilla, WNS), at most one per device every 30 seconds with new requests coalesced,
  with a TTL of an hour, high urgency and a collapsing `Topic`. By default a push says only how many
  requests are waiting; each device can opt in to the agent and what it asks for. Push services
  answering 404 or 410 drop the device. The VAPID key is made once in `$WICKET_HOME/console/vapid.key`
  (0600). See [notifications](../docs/reference/console.md#notifications) and [get notified of
  approvals](../docs/how-to/get-notified-of-approvals.md).
