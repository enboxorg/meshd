import { Loader2Icon, RefreshCwIcon } from "lucide-react";

import type { RemoteSyncState, RemoteSyncStatus } from "@enbox/browser";

import { useRemoteSyncStatus } from "./enbox/use-remote-sync-status";

/**
 * State badge vocabulary. Precedence is decided by the SDK
 * (`offline > quota-blocked > degraded > healthy`); this only renders it.
 * Quota-blocked is spelled out — a full remote silently deferring pushes
 * otherwise just looks like a node that never appears.
 */
export const REMOTE_SYNC_STATE_META: Record<RemoteSyncState, { label: string; tone: "ok" | "warn" | "off" }> = {
  healthy: { label: "Healthy", tone: "ok" },
  "quota-blocked": { label: "Storage full — pushes deferred", tone: "warn" },
  degraded: { label: "Degraded", tone: "warn" },
  offline: { label: "Offline", tone: "off" }
};

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export function formatAgo(iso?: string, now = Date.now()): string | undefined {
  if (!iso) return undefined;
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return undefined;
  const secs = Math.round((now - time) / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function formatIn(iso?: string, now = Date.now()): string | undefined {
  if (!iso) return undefined;
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return undefined;
  const secs = Math.round((time - now) / 1000);
  if (secs <= 0) return "now";
  if (secs < 60) return `${secs}s`;
  return `${Math.round(secs / 60)}m`;
}

/** One detail line per remote: state, counts, recency, next probe. */
export function describeRemoteSyncRow(remote: RemoteSyncStatus, now = Date.now()): string {
  const parts = [REMOTE_SYNC_STATE_META[remote.state].label];
  if (remote.quotaBlockedMessageCount > 0) parts.push(`${remote.quotaBlockedMessageCount} waiting`);
  if (remote.failedMessageCount > 0) parts.push(`${remote.failedMessageCount} failed`);
  const lastActivity = formatAgo(remote.lastActivityAt, now);
  if (lastActivity) parts.push(lastActivity);
  const nextProbe = formatIn(remote.nextProbeAt, now);
  if (nextProbe) parts.push(`retry in ${nextProbe}`);
  return parts.join(" · ");
}

/**
 * Compact per-remote DWN sync-health surface for the sidebar: one row per
 * `(tenant, remote)` from `getRemoteSyncStatus`, with a state dot, blocked and
 * dead-lettered message counts, and a per-remote "Retry" bound to
 * `retryRemoteNow`. Modeled on notesd's remote-sync-panel.
 */
export function SyncHealthPanel() {
  const { remotes, loading, error, retrying, refresh, retry } = useRemoteSyncStatus();

  return (
    <div className="sync-health" data-testid="sync-health-panel">
      <div className="section-heading">
        <span>Sync</span>
        <button
          className="icon-button small"
          type="button"
          aria-label="Refresh sync status"
          title="Refresh sync status"
          onClick={refresh}
        >
          <RefreshCwIcon size={14} />
        </button>
      </div>

      {error ? (
        <p className="sync-health-note error" role="alert">Couldn&apos;t read sync status: {error}</p>
      ) : loading && remotes.length === 0 ? (
        <p className="sync-health-note"><Loader2Icon className="spin" size={13} /> Checking sync…</p>
      ) : remotes.length === 0 ? (
        <p className="sync-health-note">No sync remotes registered for this identity.</p>
      ) : (
        <ul className="sync-remote-list">
          {remotes.map((remote) => {
            const meta = REMOTE_SYNC_STATE_META[remote.state];
            const busy = retrying[remote.remoteEndpoint] === true;
            const canRetry = remote.state !== "healthy" || remote.quotaBlockedMessageCount > 0;
            return (
              <li
                key={`${remote.tenantDid}:${remote.remoteEndpoint}`}
                className="sync-remote-row"
                data-state={remote.state}
              >
                <div className="sync-remote-main">
                  <span className="sync-remote-host">
                    <span aria-hidden className={`sync-dot ${meta.tone}`} />
                    <strong title={remote.remoteEndpoint}>{hostOf(remote.remoteEndpoint)}</strong>
                  </span>
                  <small>{describeRemoteSyncRow(remote)}</small>
                  {remote.lastError ? (
                    <small className="sync-remote-error" title={remote.lastError}>{remote.lastError}</small>
                  ) : null}
                </div>
                {canRetry ? (
                  <button
                    className="text-button"
                    type="button"
                    disabled={busy}
                    onClick={() => void retry(remote.remoteEndpoint)}
                  >
                    {busy ? "Retrying…" : "Retry"}
                  </button>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
