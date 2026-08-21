import { afterEach, describe, expect, it, vi } from "vitest";

import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "./transaction";

afterEach(() => vi.useRealTimers());

describe("STRK20 submission lifecycle", () => {
  it("retains the submitted hash when RPC confirmation times out", async () => {
    vi.useFakeTimers();
    const confirmation = awaitSubmittedTransaction({
      action: "private_transfer",
      hash: "0xsubmitted",
      timeoutMs: 1_000,
      waitForReceipt: () => new Promise<never>(() => undefined),
      isReverted: () => false,
    });

    await vi.advanceTimersByTimeAsync(1_000);

    await expect(confirmation).resolves.toMatchObject({
      hash: "0xsubmitted",
      status: "submitted",
    });
  });

  it("prevents a duplicate submission until the active call finishes", () => {
    const lock = { current: false };

    expect(acquireSubmission(lock)).toBe(true);
    expect(acquireSubmission(lock)).toBe(false);
    releaseSubmission(lock);
    expect(acquireSubmission(lock)).toBe(true);
  });
});
