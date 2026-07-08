/// <reference lib="webworker" />
// Must be first: installs Buffer/process on globalThis before @enbox/browser
// (and its DWN/crypto deps) are evaluated. See sw-polyfills.ts.
import "./sw-polyfills";

//@ts-expect-error - WorkBox disable dev logs
self.__WB_DISABLE_DEV_LOGS = true;
import { activatePolyfills } from "@enbox/browser";

import {
  cleanupOutdatedCaches,
  createHandlerBoundToURL,
  precacheAndRoute,
} from "workbox-precaching";
import { NavigationRoute, registerRoute } from "workbox-routing";

declare let self: ServiceWorkerGlobalScope;

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") self.skipWaiting();
});

// self.__WB_MANIFEST is the default injection point
precacheAndRoute(self.__WB_MANIFEST);

// clean old assets
cleanupOutdatedCaches();

/** @type {RegExp[] | undefined} */
let allowlist: RegExp[] | undefined;
// in dev mode, we disable precaching to avoid caching issues
if (import.meta.env.DEV) allowlist = [/^\/$/];

// to allow work offline (SPA navigation fallback)
registerRoute(
  new NavigationRoute(createHandlerBoundToURL("index.html"), { allowlist })
);

// Activate the Enbox service-worker polyfills: DRL/DWeb URL resolution against
// DWNs, DID resolution, and the resolution cache (30s TTL).
activatePolyfills({
  onCacheCheck() {
    return {
      ttl: 30000,
    };
  },
});
