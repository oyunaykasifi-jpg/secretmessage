// SecretMessage - Service Worker (Offline Cache)
// HTML pages: network-first (so updates arrive faster)
// Other assets: cache-first (better offline stability)

const CACHE_NAME = "secretmessage-v1";

const ASSETS = [
  "./",
  "./index.html",
  "./guide.html",
  "./privacy.html",
  "./why-use-secretmessage.html",
  "./app.js",
  "./manifest.json",
  "./icon-192.png",
  "./icon-512.png"
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((c) => c.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((k) => (k === CACHE_NAME ? null : caches.delete(k)))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const accept = req.headers.get("accept") || "";

  // HTML pages: network first, fallback to cache
  if (req.method === "GET" && accept.includes("text/html")) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() =>
          caches.match(req).then((r) => r || caches.match("./index.html"))
        )
    );
    return;
  }

  // Other files: cache first
  e.respondWith(
    caches.match(req).then((cached) => cached || fetch(req))
  );
});