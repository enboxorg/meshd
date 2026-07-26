import type { SyncEvent } from "@enbox/browser";

/**
 * Trailing debounce for sync-event-driven topology refreshes: one refresh at
 * most per window, so a burst of applied messages (an approval writes member +
 * node + approval records back-to-back) coalesces into a single refetch.
 */
export const MESH_SYNC_REFRESH_DEBOUNCE_MS = 500;

export type MeshSyncRefreshScheduler = {
  /** Feed every sync event here (pass to `agent.sync.on`). */
  listener: (event: SyncEvent) => void;
  /** Cancel any pending refresh (call on unmount/disconnect). */
  dispose: () => void;
};

/**
 * Builds the sync-event listener that drives event-driven topology refreshes.
 *
 * Only `delivery:applied` events whose descriptor belongs to `protocol`
 * schedule a refresh — the engine emits these once per FRESHLY applied remote
 * message, so this fires exactly when the local replica gained mesh records
 * worth re-reading. Other event types (checkpoints, connectivity, quota) are
 * health signals, not data changes, and are ignored here.
 */
export function createMeshSyncRefreshScheduler(options: {
  protocol: string;
  onRefresh: () => void;
  debounceMs?: number;
}): MeshSyncRefreshScheduler {
  const debounceMs = options.debounceMs ?? MESH_SYNC_REFRESH_DEBOUNCE_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const listener = (event: SyncEvent) => {
    if (event.type !== "delivery:applied") return;
    if (event.descriptor.protocol !== options.protocol) return;
    if (timer !== undefined) return;
    timer = setTimeout(() => {
      timer = undefined;
      options.onRefresh();
    }, debounceMs);
  };

  const dispose = () => {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
  };

  return { listener, dispose };
}
