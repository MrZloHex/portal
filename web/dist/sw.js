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
