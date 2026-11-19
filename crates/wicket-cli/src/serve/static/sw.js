"use strict";
// The console's service worker: shows the notifications the console pushes when a request is waiting
// (Web Push), and a tap on one focuses the console (or opens it) on the pending list. It fetches
// nothing and caches nothing. The payload is the console's own JSON (decrypted by the browser); its
// text is shown as notification text only, never as markup.
//
// When the browser replaces the subscription (pushsubscriptionchange), the worker can't register the
// new one itself: registering a device is signed with the operator's passkey, which only the page can
// ask for. So it subscribes again with the same server key (if it can), tells any open console, and
// shows one notification saying so; the console then offers a signed re-registration.
const TAG = "wicket-pending";
const RESUB_TAG = "wicket-resubscribe";
const HEALTH_TAG = "wicket-health";
const ID = /^[A-Za-z0-9_-]{1,64}$/;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = {}; }
  const body = typeof d.body === "string" && d.body ? d.body.slice(0, 300) : "A request is waiting for you.";
  const id = typeof d.id === "string" && ID.test(d.id) ? d.id : "";
  // Node health alerts (#377) have their own tag, so they and the pending one don't replace each other.
  const health = d.kind === "health";
  // One notification at a time (the tag), replaced by the next and announced again (renotify).
  e.waitUntil(self.registration.showNotification("wicket", {
    body, tag: health ? HEALTH_TAG : TAG, renotify: true, requireInteraction: health,
    icon: "/static/icon-192.png", badge: "/static/icon-192.png", data: health ? { health: true } : { id },
  }));
});

self.addEventListener("pushsubscriptionchange", e => {
  e.waitUntil((async () => {
    const key = e.oldSubscription && e.oldSubscription.options && e.oldSubscription.options.applicationServerKey;
    if (!e.newSubscription && key) {
      try { await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key }); } catch (_) { /* the page subscribes */ }
    }
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of wins) if (new URL(c.url).origin === self.location.origin) c.postMessage({ resubscribe: true });
    await self.registration.showNotification("wicket", {
      body: "Notifications on this device need renewing: open the console and sign to keep them.",
      tag: RESUB_TAG, icon: "/static/icon-192.png", badge: "/static/icon-192.png", data: { resubscribe: true },
    });
  })());
});

self.addEventListener("notificationclick", e => {
  e.notification.close();
  const resub = !!(e.notification.data && e.notification.data.resubscribe === true);
  const id = (e.notification.data && ID.test(e.notification.data.id || "")) ? e.notification.data.id : "";
  const health = !!(e.notification.data && e.notification.data.health === true);
  const url = new URL(resub ? "/#notifications" : health ? "/#health" : "/#pending" + (id ? "/" + id : ""), self.location.origin).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of wins) {
      if (new URL(c.url).origin !== self.location.origin) continue;
      c.postMessage(resub ? { resubscribe: true } : health ? { health: true } : { open: id });
      return c.focus();
    }
    return self.clients.openWindow(url);
  })());
});
