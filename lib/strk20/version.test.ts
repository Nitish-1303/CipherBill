import { describe, expect, it } from "vitest";

import { compareSemanticVersions, supportsStrk20WalletApi } from "./version";

describe("Wallet API semantic version checks", () => {
  it("accepts 0.10.3 and newer semantic versions", () => {
    expect(supportsStrk20WalletApi("0.10.3")).toBe(true);
    expect(supportsStrk20WalletApi("0.10.4-rc.1")).toBe(true);
    expect(supportsStrk20WalletApi("0.10.10")).toBe(true);
    expect(supportsStrk20WalletApi("1.0.0")).toBe(true);
  });

  it("rejects older, prerelease, and malformed versions", () => {
    expect(supportsStrk20WalletApi("0.10.2")).toBe(false);
    expect(supportsStrk20WalletApi("0.10.3-rc.1")).toBe(false);
    expect(supportsStrk20WalletApi("not-a-version")).toBe(false);
  });

  it("compares numeric segments rather than lexicographic strings", () => {
    expect(compareSemanticVersions("0.10.10", "0.10.3")).toBe(1);
    expect(compareSemanticVersions("0.9.99", "0.10.3")).toBe(-1);
  });
});
