# Get notified of approvals

Have the console notify your phone or desktop when an agent is waiting for you. [The console
reference](../reference/console.md#notifications) says what a notification contains, when it is sent
and where it can go.

## Before you start

- The console must be on an `https://` origin. iOS and most browsers refuse push on plain HTTP, and
  a phone can't use `http://localhost` anyway. See [put the console on the
  internet](put-the-console-on-the-internet.md).
- The console host needs outbound HTTPS to the push services: `fcm.googleapis.com`,
  `*.push.apple.com`, `updates.push.services.mozilla.com` and `*.notify.windows.com`. Behind an
  egress firewall, allow the ones your devices use.

## On an iPhone or iPad

1. Open the console in Safari, tap **Share**, then **Add to Home Screen**. Notifications work only
   in the home-screen app (iOS 16.4 or later), not in a Safari tab.
2. Open the console from the home screen and sign in with your passkey.
3. In **Notifications**, tap **Enable notifications** and allow them when iOS asks. Check the
   device the console names, then tap **Sign with passkey**. The device is listed as
   *iPhone · Safari (this device)*.

## In a desktop browser

1. Sign in to the console.
2. In **Notifications**, click **Enable notifications** and allow them when the browser asks. If
   it says notifications are blocked, allow them for the console's site in the browser's settings
   and click again. Then sign the registration with your passkey.

Registering a device is signed, like an approval, so someone holding only your session cookie can't
add a device of theirs.

## Choose what the lock screen shows

By default a notification says only how many requests are waiting. To also see which agent is
asking and for what (`lead asks POST api.github.com/repos/acme/app/pulls`), tick *Show the agent and
what it asks for* next to that device and sign with your passkey. Unticking it needs no
signature. Leave it off on a phone whose lock screen others can see.

Tapping a notification opens the console on the waiting list, with that request marked. You still
approve or deny with your passkey.

## Remove a device

Click **Remove** next to it in **Notifications**. On the device itself this also unsubscribes the
browser. A device whose browser dropped the subscription (site data cleared, app removed) is removed
the next time a push to it fails. A device stops getting pushes as soon as its passkey is revoked
(`wicket operator reset`).

## If nothing arrives

- **Notifications** shows each device's last delivery. "nothing delivered yet" after a request
  arrived means the push service didn't accept it: the console's log says why (by device id).
- A device gets at most one push every 30 seconds. Requests that arrive in between are in its next
  push.
- Requests already waiting when the console started are not announced. Only new ones are.
- On iOS, check **Settings → Notifications → wicket**, and that Focus modes allow it.
- A desktop browser sometimes replaces a device's subscription. The device then shows "Notifications
  on this device need renewing": open the console and click **Re-register this device** in
  **Notifications**, then sign.
