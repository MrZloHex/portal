// The app shell, kept so the app opens even when the bubble is out of
// reach. The bus (/bus) is a live socket and is never cached.
const CACHE = 'monoweb-v1'

self.addEventListener('install', () => self.skipWaiting())

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))),
  )
  self.clients.claim()
})

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url)
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname === '/bus') return

  const keep = (res) => {
    if (res.ok) {
      const copy = res.clone()
      caches.open(CACHE).then((c) => c.put(e.request, copy))
    }
    return res
  }

  if (url.pathname.startsWith('/assets/')) {
    // Hashed names: a file here never changes, so the cache is enough.
    e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request).then(keep)))
    return
  }
  // Everything else from the network first, so an update arrives; the cache
  // when there is no network.
  e.respondWith(
    fetch(e.request)
      .then(keep)
      .catch(() => caches.match(e.request).then((hit) => hit || caches.match('/'))),
  )
})

// A push from vestnik: shown whether the app is open or not. It names no one
// and says nothing of what was written — a lock screen shows it; the app,
// opened, shows the rest.
self.addEventListener('push', (e) => {
  let n = { title: 'MONOLITH', body: 'something new', tag: 'monolith' }
  try {
    n = { ...n, ...e.data.json() }
  } catch {
    // shown as it is
  }
  e.waitUntil(self.registration.showNotification(n.title, { body: n.body, tag: n.tag, icon: '/icon-192.png', badge: '/icon-192.png' }))
})

// Tapped: to the app, already open or not.
self.addEventListener('notificationclick', (e) => {
  e.notification.close()
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((open) => {
      const app = open.find((c) => new URL(c.url).origin === location.origin)
      return app ? app.focus() : self.clients.openWindow('/')
    }),
  )
})
