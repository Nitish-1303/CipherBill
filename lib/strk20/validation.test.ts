import { describe, expect, it } from "vitest";

import { decimalToBaseUnits, isValidAmount, isValidStarknetAddress, normalizeStarknetAddress, validatePaymentInput } from "./validation";

describe("STRK20 input validation", () => {
  it("accepts canonical-looking Starknet addresses", () => {
    expect(isValidStarknetAddress("0x1234")).toBe(true);
    expect(isValidStarknetAddress("1234")).toBe(false);
    expect(normalizeStarknetAddress("0x1234")).toMatch(/^0x0+1234$/);
  });

  it("accepts positive amounts with at most 18 decimals", () => {
    expect(isValidAmount("1")).toBe(true);
    expect(isValidAmount("0.000000000000000001")).toBe(true);
    expect(isValidAmount("0")).toBe(false);
    expect(isValidAmount("1.0000000000000000001")).toBe(false);
  });

  it("converts STRK amounts to base units", () => {
    expect(decimalToBaseUnits("1.5")).toBe("1500000000000000000");
    expect(decimalToBaseUnits("0.000000000000000001")).toBe("1");
  });

  it("returns a safe validation message for invalid payment input", () => {
    expect(validatePaymentInput("0x1234", "2")).toBeNull();
    expect(validatePaymentInput("not-an-address", "2")).toContain("recipient");
    expect(validatePaymentInput("0x1234", "0")).toContain("positive");
  });
});
