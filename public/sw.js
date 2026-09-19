/*
 * TrustVision service worker.
 *
 * Purpose: make the console installable and let its shell open offline. It is deliberately
 * conservative about what it caches, because this is an assurance tool:
 *
 *  - /api/* is NEVER cached. Every verdict, ledger entry and health check must be live;
 *    a stale assurance result is worse than an error. These go network-only.
 *  - Navigations are network-first, falling back to the cached shell only when offline.
 *  - Immutable build assets (/assets, /fonts, icons) are cache-first for instant loads.
 *  - Dev-server and HMR paths are passed straight through so `npm run dev` still works.
 *
 * Nothing here reaches an external origin; it only ever touches this same-origin node,
 * which keeps the air-gap intact.
 */

const VERSION = 'tv-v1';
const SHELL_CACHE = `${VERSION}-shell`;
const ASSET_CACHE = `${VERSION}-assets`;

const SHELL_URLS = [
  '/',
  '/manifest.webmanifest',
  '/favicon.svg',
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => cache.addAll(SHELL_URLS).catch(() => undefined))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => !key.startsWith(VERSION)).map((key) => caches.delete(key)))
      )
      .then(() => self.clients.claim())
  );
});

function isDevPath(url) {
  return (
    url.pathname.startsWith('/@') ||
    url.pathname.startsWith('/src/') ||
    url.pathname.startsWith('/node_modules/') ||
    url.pathname.includes('hot-update') ||
    url.searchParams.has('t')
  );
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Live data and the dev server are never intercepted.
  if (url.pathname.startsWith('/api') || isDevPath(url)) return;

  // App navigations: try the network, fall back to the cached shell when offline.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/', { ignoreSearch: true }).then((hit) => hit || caches.match(request)))
    );
    return;
  }

  // Static assets: serve from cache immediately, refresh in the background.
  if (/\/(assets|fonts)\//.test(url.pathname) || /\.(?:png|svg|css|js|woff2?|ico|webmanifest)$/.test(url.pathname)) {
    event.respondWith(
      caches.open(ASSET_CACHE).then(async (cache) => {
        const cached = await cache.match(request);
        const network = fetch(request)
          .then((response) => {
            if (response && response.ok) cache.put(request, response.clone());
            return response;
          })
          .catch(() => cached);
        return cached || network;
      })
    );
  }
});
