"use strict";
// The console's service worker: shows the notifications the console pushes when a request is waiting
// (Web Push), and a tap on one focuses the console (or opens it) on the pending list. It fetches
// nothing and caches nothing. The payload is the console's own JSON (decrypted by the browser); its
// text is shown as notification text only, never as markup.
const TAG = "wicket-pending";
const ID = /^[A-Za-z0-9_-]{1,64}$/;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = {}; }
  const body = typeof d.body === "string" && d.body ? d.body.slice(0, 300) : "A request is waiting for you.";
  const id = typeof d.id === "string" && ID.test(d.id) ? d.id : "";
  // One notification at a time (the tag), replaced by the next and announced again (renotify).
  e.waitUntil(self.registration.showNotification("wicket", {
    body, tag: TAG, renotify: true, requireInteraction: false,
    icon: "/static/icon-192.png", badge: "/static/icon-192.png", data: { id },
  }));
});

self.addEventListener("notificationclick", e => {
  e.notification.close();
  const id = (e.notification.data && ID.test(e.notification.data.id || "")) ? e.notification.data.id : "";
  const url = new URL("/#pending" + (id ? "/" + id : ""), self.location.origin).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of wins) {
      if (new URL(c.url).origin !== self.location.origin) continue;
      c.postMessage({ open: id });
      return c.focus();
    }
    return self.clients.openWindow(url);
  })());
});
