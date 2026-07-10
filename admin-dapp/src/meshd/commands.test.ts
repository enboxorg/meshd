import { describe, expect, it } from "vitest";

import { installAndUpCommand, shellQuote } from "./commands";

describe("meshd admin command helpers", () => {
  it("shell-quotes single quotes defensively", () => {
    expect(shellQuote("did:example:o'wner")).toBe("'did:example:o'\\''wner'");
  });

  it("builds the install+up one-liner for an invite URL", () => {
    expect(installAndUpCommand("meshd://invite/abc123", "https://meshd.sh/install")).toBe(
      "curl -fsSL https://meshd.sh/install | bash -s -- up 'meshd://invite/abc123'"
    );
  });

  it("builds the install+up one-liner for an owner DID", () => {
    expect(installAndUpCommand(" did:example:owner ", "https://meshd.sh/install")).toBe(
      "curl -fsSL https://meshd.sh/install | bash -s -- up 'did:example:owner'"
    );
  });

  it("rejects empty install+up targets", () => {
    expect(() => installAndUpCommand("   ")).toThrow("An invite URL or owner DID is required.");
  });
});
