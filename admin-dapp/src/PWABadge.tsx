import { useRegisterSW } from "virtual:pwa-register/react";

/**
 * Minimal PWA update prompt. The service worker (src/sw.ts) registers with the
 * "prompt" strategy, so a new build installs but waits; this badge surfaces the
 * update and lets the user reload into it. It also re-checks for a new SW once
 * an hour.
 */
export function PWABadge() {
  const period = 60 * 60 * 1000; // 1 hour

  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker
  } = useRegisterSW({
    onRegisteredSW(swUrl, registration) {
      if (period <= 0 || !registration) return;
      if (registration.active?.state === "activated") {
        schedulePeriodicUpdate(period, swUrl, registration);
      } else if (registration.installing) {
        registration.installing.addEventListener("statechange", (event) => {
          const sw = event.target as ServiceWorker;
          if (sw.state === "activated") schedulePeriodicUpdate(period, swUrl, registration);
        });
      }
    }
  });

  if (!needRefresh) return null;

  return (
    <div
      role="alert"
      style={{
        position: "fixed",
        right: 16,
        bottom: 16,
        zIndex: 50,
        maxWidth: 320,
        padding: "12px 16px",
        borderRadius: 8,
        background: "#101820",
        color: "#e6edf3",
        border: "1px solid #2b3a44",
        boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
        fontSize: 14
      }}
    >
      <div>A new version is available.</div>
      <div style={{ marginTop: 12, display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <button
          onClick={() => setNeedRefresh(false)}
          style={{
            padding: "4px 10px",
            borderRadius: 6,
            background: "transparent",
            color: "#e6edf3",
            border: "1px solid #2b3a44",
            cursor: "pointer"
          }}
        >
          Dismiss
        </button>
        <button
          onClick={() => void updateServiceWorker(true)}
          style={{
            padding: "4px 10px",
            borderRadius: 6,
            background: "#66c2ff",
            color: "#08131a",
            border: "none",
            cursor: "pointer",
            fontWeight: 600
          }}
        >
          Reload
        </button>
      </div>
    </div>
  );
}

/** Re-check for an updated service worker on an interval. */
function schedulePeriodicUpdate(period: number, swUrl: string, registration: ServiceWorkerRegistration) {
  setInterval(async () => {
    if ("onLine" in navigator && !navigator.onLine) return;
    try {
      const resp = await fetch(swUrl, { cache: "no-store", headers: { cache: "no-store" } });
      if (resp.status === 200) await registration.update();
    } catch {
      // Offline or transient network error — retry on the next tick.
    }
  }, period);
}

export default PWABadge;
