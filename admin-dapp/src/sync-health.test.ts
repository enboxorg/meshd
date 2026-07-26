import { describe, expect, it } from "vitest";

import type { RemoteSyncStatus } from "@enbox/browser";

import { describeRemoteSyncRow, formatAgo, formatIn, hostOf, REMOTE_SYNC_STATE_META } from "./sync-health";

const NOW = Date.parse("2026-07-26T12:00:00Z");

function remote(overrides: Partial<RemoteSyncStatus> = {}): RemoteSyncStatus {
  return {
    tenantDid: "did:example:owner",
    remoteEndpoint: "https://dev.aws.dwn.enbox.id",
    state: "healthy",
    connectivity: "online",
    quotaBlockedMessageCount: 0,
    failedMessageCount: 0,
    ...overrides
  };
}

describe("sync health surface", () => {
  it("spells out quota-blocked so a full remote is not mistaken for a healthy one", () => {
    // A quota-blocked remote silently defers pushes; without explicit copy it
    // just looks like a node that never appears.
    expect(REMOTE_SYNC_STATE_META["quota-blocked"].label).toBe("Storage full — pushes deferred");
    expect(REMOTE_SYNC_STATE_META["quota-blocked"].tone).toBe("warn");
    expect(REMOTE_SYNC_STATE_META.healthy.tone).toBe("ok");
    expect(REMOTE_SYNC_STATE_META.offline.tone).toBe("off");
  });

  it("describes a healthy remote with recency only", () => {
    const line = describeRemoteSyncRow(
      remote({ lastActivityAt: "2026-07-26T11:58:00Z" }),
      NOW
    );
    expect(line).toBe("Healthy · 2m ago");
  });

  it("describes a blocked remote with counts and the next probe", () => {
    const line = describeRemoteSyncRow(
      remote({
        state: "quota-blocked",
        quotaBlockedMessageCount: 4,
        failedMessageCount: 1,
        lastActivityAt: "2026-07-26T10:00:00Z",
        nextProbeAt: "2026-07-26T12:05:00Z"
      }),
      NOW
    );
    expect(line).toBe("Storage full — pushes deferred · 4 waiting · 1 failed · 2h ago · retry in 5m");
  });

  it("formats relative times on both sides of now", () => {
    expect(formatAgo("2026-07-26T11:59:59Z", NOW)).toBe("just now");
    expect(formatAgo("2026-07-26T11:59:20Z", NOW)).toBe("40s ago");
    expect(formatAgo("2026-07-25T12:00:00Z", NOW)).toBe("1d ago");
    expect(formatAgo("not-a-date", NOW)).toBeUndefined();
    expect(formatAgo(undefined, NOW)).toBeUndefined();

    expect(formatIn("2026-07-26T12:00:30Z", NOW)).toBe("30s");
    expect(formatIn("2026-07-26T12:10:00Z", NOW)).toBe("10m");
    expect(formatIn("2026-07-26T11:00:00Z", NOW)).toBe("now");
    expect(formatIn(undefined, NOW)).toBeUndefined();
  });

  it("reduces endpoints to their host for the row title", () => {
    expect(hostOf("https://dev.aws.dwn.enbox.id/")).toBe("dev.aws.dwn.enbox.id");
    expect(hostOf("not a url")).toBe("not a url");
  });
});
