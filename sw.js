// Network-first for the app shell; API calls are never cached. Also shows outage push alerts.
const CACHE = 'nawec-alerts-v3';
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/', '/nawec-logo.png', '/nawec-icon.png', '/manifest.json']))); self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))); self.clients.claim(); });
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.pathname.startsWith('/api') || url.origin !== location.origin) return;
  e.respondWith(fetch(e.request).then((r) => { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); return r; }).catch(() => caches.match(e.request).then((r) => r || caches.match('/'))));
});

/* ---------- Push alerts (Android, and iPhone when added to the Home Screen) ---------- */
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data && e.data.text() }; }
  const title = d.title || 'NAWEC Alerts';
  const opts = {
    body: d.body || 'There is a power outage update for your area.',
    icon: '/nawec-icon.png',
    badge: '/nawec-icon.png',
    tag: d.tag || undefined,
    renotify: !!d.tag,
    requireInteraction: !!d.urgent,
    vibrate: d.urgent ? [300, 120, 300, 120, 300] : [200, 100, 200],
    data: { url: d.url || '/' },
  };
  e.waitUntil(Promise.all([
    // iPhone requires every push to show a notification, so always show one.
    self.registration.showNotification(title, opts),
    // Tell the server the phone showed it, so the backup email isn't sent.
    d.r ? fetch('/api/push/seen', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ r: d.r }) }).catch(() => {}) : null,
    // Refresh any open app window.
    self.clients.matchAll({ type: 'window' }).then((cs) => cs.forEach((c) => c.postMessage({ type: 'alert' }))),
  ]));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = new URL((e.notification.data && e.notification.data.url) || '/', self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cs) => {
    for (const c of cs) {
      if (new URL(c.url).origin === self.location.origin && 'focus' in c) { c.postMessage({ type: 'open', url: target }); return c.focus(); }
    }
    return self.clients.openWindow(target);
  }));
});
