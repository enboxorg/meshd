import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SyncEvent } from "@enbox/browser";

import { MESHD_PROTOCOL_URI } from "@/enbox/config";

import { createMeshSyncRefreshScheduler, MESH_SYNC_REFRESH_DEBOUNCE_MS } from "./topology-refresh";

function deliveryApplied(overrides: Partial<{ protocol: string; protocolPath: string }> = {}): SyncEvent {
  return {
    type: "delivery:applied",
    tenantDid: "did:example:owner",
    remoteEndpoint: "https://dwn.example",
    scope: "protocol-set",
    protocols: [MESHD_PROTOCOL_URI],
    messageCid: "cid-1",
    descriptor: {
      interface: "Records",
      method: "Write",
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network/nodeRequest",
      ...overrides
    }
  } as unknown as SyncEvent;
}

describe("createMeshSyncRefreshScheduler", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("refreshes once after the debounce window for a mesh delivery", () => {
    const onRefresh = vi.fn();
    const { listener } = createMeshSyncRefreshScheduler({ protocol: MESHD_PROTOCOL_URI, onRefresh });

    listener(deliveryApplied());
    expect(onRefresh).not.toHaveBeenCalled();

    vi.advanceTimersByTime(MESH_SYNC_REFRESH_DEBOUNCE_MS);
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });

  it("coalesces a burst of deliveries into a single refresh", () => {
    // An approval applies member + node + approval records back-to-back; the
    // dashboard must refetch once, not once per record.
    const onRefresh = vi.fn();
    const { listener } = createMeshSyncRefreshScheduler({ protocol: MESHD_PROTOCOL_URI, onRefresh });

    listener(deliveryApplied({ protocolPath: "network/member" }));
    listener(deliveryApplied({ protocolPath: "network/member/node" }));
    listener(deliveryApplied({ protocolPath: "nodeApproval" }));

    vi.advanceTimersByTime(MESH_SYNC_REFRESH_DEBOUNCE_MS);
    expect(onRefresh).toHaveBeenCalledTimes(1);

    // A delivery after the window fires a fresh refresh.
    listener(deliveryApplied());
    vi.advanceTimersByTime(MESH_SYNC_REFRESH_DEBOUNCE_MS);
    expect(onRefresh).toHaveBeenCalledTimes(2);
  });

  it("ignores deliveries for other protocols", () => {
    const onRefresh = vi.fn();
    const { listener } = createMeshSyncRefreshScheduler({ protocol: MESHD_PROTOCOL_URI, onRefresh });

    listener(deliveryApplied({ protocol: "https://enbox.id/protocols/notebook" }));
    vi.advanceTimersByTime(MESH_SYNC_REFRESH_DEBOUNCE_MS * 4);
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it("ignores non-delivery sync events (health signals are not data changes)", () => {
    const onRefresh = vi.fn();
    const { listener } = createMeshSyncRefreshScheduler({ protocol: MESHD_PROTOCOL_URI, onRefresh });

    listener({
      type: "link:connectivity-change",
      tenantDid: "did:example:owner",
      remoteEndpoint: "https://dwn.example",
      scope: "protocol-set",
      protocols: [MESHD_PROTOCOL_URI],
      from: "online",
      to: "offline"
    } as unknown as SyncEvent);
    listener({
      type: "push:quota-blocked",
      tenantDid: "did:example:owner",
      remoteEndpoint: "https://dwn.example",
      scope: "protocol-set",
      protocols: [MESHD_PROTOCOL_URI],
      messageCid: "cid-9",
      nextProbeAt: "2026-07-26T00:00:00Z"
    } as unknown as SyncEvent);

    vi.advanceTimersByTime(MESH_SYNC_REFRESH_DEBOUNCE_MS * 4);
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it("dispose cancels a pending refresh", () => {
    const onRefresh = vi.fn();
    const { listener, dispose } = createMeshSyncRefreshScheduler({ protocol: MESHD_PROTOCOL_URI, onRefresh });

    listener(deliveryApplied());
    dispose();
    vi.advanceTimersByTime(MESH_SYNC_REFRESH_DEBOUNCE_MS * 4);
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it("honors a custom debounce window", () => {
    const onRefresh = vi.fn();
    const { listener } = createMeshSyncRefreshScheduler({
      protocol: MESHD_PROTOCOL_URI,
      onRefresh,
      debounceMs: 50
    });

    listener(deliveryApplied());
    vi.advanceTimersByTime(49);
    expect(onRefresh).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });
});
