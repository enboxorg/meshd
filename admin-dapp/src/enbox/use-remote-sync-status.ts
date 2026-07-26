import { useCallback, useEffect, useRef, useState } from "react";

import type { RemoteSyncStatus } from "@enbox/browser";

import { useEnbox } from "./use-enbox";

/** Slow safety poll while the panel is rendered; skipped when the tab is hidden. */
const POLL_INTERVAL_MS = 30_000;

/** Trailing throttle for the (potentially chatty) sync-event driven refresh. */
const EVENT_THROTTLE_MS = 400;

export type RemoteSyncStatusView = {
  /** Per-`(tenant, remote)` health rows for the connected owner identity. */
  remotes: RemoteSyncStatus[];
  /** True until the first read resolves. */
  loading: boolean;
  /** Set when a status read throws (kept distinct from an empty result). */
  error?: string;
  /** Endpoints with a "Retry now" call currently in flight, keyed by endpoint. */
  retrying: Record<string, boolean>;
  /** Force a re-read (also runs on sync events and on a slow interval). */
  refresh: () => void;
  /** Immediately re-probe a blocked remote, then re-read. */
  retry: (remoteEndpoint: string) => Promise<void>;
};

/**
 * Reactive view over the SyncEngine's per-remote status
 * (`agent.sync.getRemoteSyncStatus`), refreshed on every sync event
 * (throttled) plus a slow visibility-gated poll, with a per-remote
 * "Retry now" bound to `retryRemoteNow`. Modeled on notesd's
 * use-remote-sync-status.
 */
export function useRemoteSyncStatus(): RemoteSyncStatusView {
  const { enbox, did } = useEnbox();
  const sync = enbox?.agent.sync;
  const tenantDid = did;

  const [remotes, setRemotes] = useState<RemoteSyncStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | undefined>();
  const [retrying, setRetrying] = useState<Record<string, boolean>>({});

  // Guard against setState after unmount (reads and retries are async).
  const activeRef = useRef(true);
  useEffect(() => {
    activeRef.current = true;
    return () => {
      activeRef.current = false;
    };
  }, []);

  const refresh = useCallback(() => {
    if (!sync) {
      setRemotes([]);
      setLoading(false);
      setError(undefined);
      return;
    }
    void sync
      .getRemoteSyncStatus(tenantDid)
      .then((rows) => {
        if (!activeRef.current) return;
        setRemotes(rows);
        setError(undefined);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (!activeRef.current) return;
        setError(err instanceof Error ? err.message : "Failed to read sync status");
        setLoading(false);
      });
  }, [sync, tenantDid]);

  // Initial read + refresh on every sync event (throttled) + a slow poll.
  useEffect(() => {
    if (!sync) {
      setRemotes([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    refresh();

    let throttleTimer: number | undefined;
    const onSyncEvent = (): void => {
      if (throttleTimer !== undefined) return;
      throttleTimer = window.setTimeout(() => {
        throttleTimer = undefined;
        refresh();
      }, EVENT_THROTTLE_MS);
    };
    const off = sync.on(onSyncEvent);
    const poll = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      refresh();
    }, POLL_INTERVAL_MS);

    return () => {
      off();
      window.clearInterval(poll);
      if (throttleTimer !== undefined) window.clearTimeout(throttleTimer);
    };
  }, [sync, refresh]);

  const retry = useCallback(
    async (remoteEndpoint: string) => {
      if (!sync || !tenantDid) return;
      setRetrying((prev) => ({ ...prev, [remoteEndpoint]: true }));
      try {
        await sync.retryRemoteNow(tenantDid, remoteEndpoint);
        refresh();
      } catch (err) {
        if (activeRef.current) {
          setError(err instanceof Error ? err.message : "Retry failed");
        }
      } finally {
        if (activeRef.current) {
          setRetrying((prev) => {
            const next = { ...prev };
            delete next[remoteEndpoint];
            return next;
          });
        }
      }
    },
    [sync, tenantDid, refresh]
  );

  return { remotes, loading, error, retrying, refresh, retry };
}
