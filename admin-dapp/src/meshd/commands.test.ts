import { describe, expect, it } from "vitest";

import { ownerSetupCommand, shellQuote } from "./commands";

describe("meshd admin command helpers", () => {
  it("builds the owner setup command", () => {
    expect(ownerSetupCommand("did:example:owner")).toBe("meshd up 'did:example:owner'");
  });

  it("trims the owner DID before building commands", () => {
    expect(ownerSetupCommand("  did:example:owner  ")).toBe("meshd up 'did:example:owner'");
  });

  it("shell-quotes single quotes defensively", () => {
    expect(shellQuote("did:example:o'wner")).toBe("'did:example:o'\\''wner'");
  });

  it("rejects empty owner DIDs", () => {
    expect(() => ownerSetupCommand("   ")).toThrow("Owner DID is required.");
  });
});
