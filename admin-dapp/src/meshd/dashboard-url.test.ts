import { describe, expect, it } from "vitest";

import { dashboardContextFromSearch, ownerMatchesDashboardContext } from "./dashboard-url";

describe("meshd admin dashboard URL context", () => {
  it("reads owner and network hints from query params", () => {
    expect(dashboardContextFromSearch("?owner=did%3Aexample%3Aowner&network=network-record")).toEqual({
      ownerDID: "did:example:owner",
      networkRecordID: "network-record"
    });
  });

  it("ignores empty hints", () => {
    expect(dashboardContextFromSearch("?owner=+&network=")).toEqual({});
  });

  it("checks connected wallet owner against URL owner hint", () => {
    expect(ownerMatchesDashboardContext({ ownerDID: "did:example:owner" }, "did:example:owner")).toBe(true);
    expect(ownerMatchesDashboardContext({ ownerDID: "did:example:owner" }, "did:example:other")).toBe(false);
    expect(ownerMatchesDashboardContext({}, "did:example:other")).toBe(true);
  });
});
