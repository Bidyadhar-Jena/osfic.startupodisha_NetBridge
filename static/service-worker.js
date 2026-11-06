'use strict';

const CACHE_NAME = 'netbridge-shell-v27';

const APP_SHELL = [
    '/',
    '/merchant',
    '/far-wallet/customer2',
    '/static/style.css',
    '/static/merchant.css',
    '/static/script.js',
    '/static/merchant.js',
    '/static/offline_totp.js',
    '/static/offline_store.js',
    '/static/payment_feedback.js',
    '/static/far_wallet.js',
    '/static/offline_receipt_code.js',
    '/static/vendor/jsQR.js',
    '/static/vendor/qrcode.min.js',
    '/static/manifest.webmanifest',
    '/static/merchant.webmanifest',
    '/static/icons/icon-192.png',
    '/static/icons/icon-512.png'
];

/* INSTALL */
self.addEventListener('install', event => {
    event.waitUntil((async () => {
        const cache = await caches.open(CACHE_NAME);
        await cache.addAll(APP_SHELL);
        await self.skipWaiting();
    })());
});

/* ACTIVATE */
self.addEventListener('activate', event => {
    event.waitUntil((async () => {
        const names = await caches.keys();

        await Promise.all(
            names
                .filter(name =>
                    name.startsWith('netbridge-shell-') &&
                    name !== CACHE_NAME
                )
                .map(name => caches.delete(name))
        );

        await self.clients.claim();
    })());
});

/* FETCH */
self.addEventListener('fetch', event => {
    const request = event.request;
    const url = new URL(request.url);

    /*
     * Never cache API responses, PIN/OTP traffic,
     * or payment operations.
     */
    if (
        request.method !== 'GET' ||
        url.pathname.startsWith('/api/')
    ) {
        return;
    }

    /* Prefer current server files so phone browsers do not keep stale app
     * code after a VS Code update. Use cached shell files only offline. */
    if (url.origin === self.location.origin) {
        event.respondWith((async () => {
            const cache = await caches.open(CACHE_NAME);
            try {
                const fresh = await fetch(request);
                if (fresh && fresh.ok && fresh.type === 'basic') {
                    cache.put(request, fresh.clone());
                }
                if (fresh) return fresh;
            } catch (_) {
                // Fall back to the cached shell while offline.
            }

            const cached = await cache.match(request, { ignoreSearch: true });
            if (cached) return cached;

            /*
             * Offline navigation fallback.
             */
            if (request.mode === 'navigate') {
                return (
                    await cache.match('/')
                ) || new Response(
                    '<!doctype html>' +
                    '<title>NetBridge offline</title>' +
                    '<h1>NetBridge</h1>' +
                    '<p>The app shell is unavailable. ' +
                    'Reconnect once to load it.</p>',
                    {
                        headers: {
                            'Content-Type':
                                'text/html; charset=utf-8'
                        },
                        status: 200
                    }
                );
            }

            return new Response(
                'Offline resource unavailable',
                { status: 503 }
            );
        })());

        return;
    }

    /*
     * Cache CDN libraries after successful loading.
     * This supports repeat visits after the first
     * successful online load.
     */
    if (url.hostname === 'cdn.jsdelivr.net') {
        event.respondWith((async () => {
            const cache = await caches.open(CACHE_NAME);
            const cached = await cache.match(request, { ignoreSearch: true });

            try {
                const response = await fetch(request);

                // Classic cross-origin scripts are returned as opaque
                // responses. They can still be cached for offline use.
                if (response && (response.ok || response.type === 'opaque')) {
                    cache.put(request, response.clone());
                }

                return response;

            } catch (error) {
                if (cached) {
                    return cached;
                }

                throw error;
            }
        })());
    }
});
