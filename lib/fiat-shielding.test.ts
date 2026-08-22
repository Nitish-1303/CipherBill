import { describe, expect, it } from "vitest";

import {
  assertFiatQuoteActive,
  buildFiatShieldActions,
  buildPrivateFiatSettlementActions,
  calculateFiatConversion,
  createFiatShieldingPlan,
  decryptFiatShieldingPlan,
  encryptFiatShieldingPlan,
  FIAT_SHIELDING_POOL_ADDRESS,
  formatFiatMinorUnits,
  getFiatVisibilityModel,
  parseEncryptedFiatShieldingPlan,
  serializeEncryptedFiatShieldingPlan,
  verifyFiatShieldingPlan,
  type CreateFiatShieldingPlanInput,
  type EncryptedFiatShieldingPlan,
  type FiatShieldingPlan,
} from "./fiat-shielding";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const CREATED_AT = new Date("2026-08-22T08:00:00.000Z");
const EXPIRES_AT = "2026-08-23T08:00:00.000Z";
const TOKEN = "0x0000000000000000000000000000000000000000000000000000000000001111";
const RECIPIENT = "0x0000000000000000000000000000000000000000000000000000000000002222";

const input: CreateFiatShieldingPlanInput = {
  invoiceId: "invoice_global_1042",
  merchantName: "Cipher Export Studio",
  invoiceCurrency: "EUR",
  invoiceAmount: "12500.37",
  recipientAddress: RECIPIENT,
  settlementAsset: {
    symbol: "USDC",
    tokenAddress: TOKEN,
    decimals: 6,
    pegCurrency: "USD",
  },
  rateLock: {
    rate: "1.07654321",
    source: "Merchant treasury rate lock",
    asOf: CREATED_AT.toISOString(),
    expiresAt: EXPIRES_AT,
  },
  shieldBufferBps: 500,
  memo: "Private cross-border settlement",
};

function plan(): FiatShieldingPlan {
  return createFiatShieldingPlan(input, CREATED_AT, { createId: () => "fiat_global_1042" });
}

function deterministicBytes(target: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return target.fill(target.length === 32 ? 5 : 9);
}

function decodeBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

describe("fiat-pegged STRK20 shielding", () => {
  it("converts values above Number.MAX_SAFE_INTEGER with exact bigint arithmetic", () => {
    const result = calculateFiatConversion({
      invoiceCurrency: "EUR",
      invoiceAmount: "9007199254740993.01",
      settlementDecimals: 6,
      rate: "1.07654321",
      shieldBufferBps: 0,
    });
    const invoiceMinor = 900719925474099301n;
    const numerator = invoiceMinor * 107654321n * 1_000_000n;
    const denominator = 100n * 100_000_000n;
    const expected = (numerator + denominator - 1n) / denominator;

    expect(result.invoiceMinorUnits).toBe(invoiceMinor.toString());
    expect(result.settlementBaseUnits).toBe(expected.toString());
    expect(result.shieldBaseUnits).toBe(expected.toString());
    expect(formatFiatMinorUnits(result.invoiceMinorUnits, "EUR")).toBe("9007199254740993.01");
    expect(String(Number(result.invoiceMinorUnits))).not.toBe(result.invoiceMinorUnits);
  });

  it("rounds settlement up by one base unit and calculates an exact shield buffer", () => {
    const rounded = calculateFiatConversion({ invoiceCurrency: "JPY", invoiceAmount: "1", settlementDecimals: 6, rate: "0.0066661", shieldBufferBps: 0 });
    const buffered = calculateFiatConversion({ invoiceCurrency: "EUR", invoiceAmount: "100", settlementDecimals: 6, rate: "1.1", shieldBufferBps: 500 });

    expect(rounded).toMatchObject({ settlementBaseUnits: "6667", settlementDisplayAmount: "0.006667", rounding: "ceil" });
    expect(BigInt(rounded.roundingDeltaNumerator)).toBeGreaterThan(0n);
    expect(buffered).toMatchObject({
      settlementBaseUnits: "110000000",
      shieldBufferBaseUnits: "5500000",
      shieldBaseUnits: "115500000",
      shieldDisplayAmount: "115.5",
    });
  });

  it("commits every material invoice, rate, asset, and conversion field", () => {
    const quote = plan();

    expect(FIAT_SHIELDING_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(quote.poolAddress).toBe("0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a");
    expect(quote.rateLock.direction).toBe("1 EUR = 1.07654321 USD");
    expect(verifyFiatShieldingPlan(quote)).toBe(true);
    expect(verifyFiatShieldingPlan({ ...quote, merchantName: "Altered Merchant" })).toBe(false);
    expect(verifyFiatShieldingPlan({ ...quote, conversion: { ...quote.conversion, settlementBaseUnits: "1" } })).toBe(false);
  });

  it("encrypts invoice metadata and FX terms into an opaque portable quote", async () => {
    const quote = plan();
    const bundle = await encryptFiatShieldingPlan(quote, { randomBytes: deterministicBytes });
    const serialized = serializeEncryptedFiatShieldingPlan(bundle.envelope);
    const rawCiphertext = new TextDecoder("latin1").decode(decodeBase64Url(bundle.envelope.ciphertext));

    expect(Object.keys(bundle.envelope).sort()).toEqual(["algorithm", "ciphertext", "ciphertextDigest", "iv", "kind", "network", "notice", "poolAddress", "version"]);
    for (const secret of [input.invoiceId, input.merchantName, input.invoiceCurrency, input.invoiceAmount, input.rateLock.rate, input.rateLock.source, RECIPIENT, TOKEN]) {
      expect(serialized).not.toContain(secret);
      expect(rawCiphertext).not.toContain(secret);
    }
    expect(() => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(bundle.envelope.ciphertext)))).toThrow();
    expect(parseEncryptedFiatShieldingPlan(serialized)).toEqual(bundle.envelope);
    await expect(decryptFiatShieldingPlan(bundle.envelope, bundle.accessKey)).resolves.toEqual(quote);
  });

  it("fails closed for a wrong access key or modified authenticated data", async () => {
    const bundle = await encryptFiatShieldingPlan(plan(), { randomBytes: deterministicBytes });
    const wrongKey = "A".repeat(bundle.accessKey.length);
    const alteredCiphertext: EncryptedFiatShieldingPlan = {
      ...bundle.envelope,
      ciphertext: `${bundle.envelope.ciphertext[0] === "A" ? "B" : "A"}${bundle.envelope.ciphertext.slice(1)}`,
    };
    const alteredNotice: EncryptedFiatShieldingPlan = {
      ...bundle.envelope,
      notice: "Safe to publish invoice metadata." as EncryptedFiatShieldingPlan["notice"],
    };

    await expect(decryptFiatShieldingPlan(bundle.envelope, wrongKey)).rejects.toThrow("could not be decrypted");
    await expect(decryptFiatShieldingPlan(alteredCiphertext, bundle.accessKey)).rejects.toThrow("digest");
    await expect(decryptFiatShieldingPlan(alteredNotice, bundle.accessKey)).rejects.toThrow("header");
  });

  it("keeps invoice metadata out of both public shielding and private payment actions", () => {
    const quote = plan();
    const shieldActions = buildFiatShieldActions(quote, CREATED_AT);
    const settlementActions = buildPrivateFiatSettlementActions(quote, CREATED_AT);
    const serializedActions = JSON.stringify([shieldActions, settlementActions]);

    expect(shieldActions).toEqual([{ type: "deposit", token: TOKEN, amount: quote.conversion.shieldBaseUnits }]);
    expect(settlementActions).toEqual([{ type: "transfer", token: TOKEN, amount: quote.conversion.settlementBaseUnits, recipient: RECIPIENT }]);
    for (const metadata of [input.invoiceId, input.merchantName, "EUR", input.rateLock.rate, input.rateLock.source, input.memo ?? ""]) {
      expect(serializedActions).not.toContain(metadata);
    }
    expect(getFiatVisibilityModel(quote).publicShieldEdge).toContain(`${quote.conversion.shieldDisplayAmount} shield amount`);
    expect(getFiatVisibilityModel(quote).hiddenPrivatePayment).toContain("exact settlement amount");
  });

  it("rejects expired quotes before constructing wallet actions", () => {
    const quote = plan();

    expect(() => assertFiatQuoteActive(quote, new Date(EXPIRES_AT))).not.toThrow();
    expect(() => buildFiatShieldActions(quote, new Date("2026-08-23T08:00:00.001Z"))).toThrow("expired");
    expect(() => buildPrivateFiatSettlementActions(quote, new Date("2026-08-24T00:00:00.000Z"))).toThrow("expired");
  });

  it("rejects precision loss, unsafe buffers, invalid assets, and excessive values", () => {
    expect(() => calculateFiatConversion({ invoiceCurrency: "USD", invoiceAmount: "1.001", settlementDecimals: 6, rate: "1", shieldBufferBps: 0 })).toThrow("2 decimal");
    expect(() => calculateFiatConversion({ invoiceCurrency: "USD", invoiceAmount: "1", settlementDecimals: 6, rate: "1", shieldBufferBps: 5_001 })).toThrow("basis points");
    expect(() => createFiatShieldingPlan({ ...input, settlementAsset: { ...input.settlementAsset, tokenAddress: "invalid" } }, CREATED_AT)).toThrow();
    expect(() => createFiatShieldingPlan({ ...input, rateLock: { ...input.rateLock, expiresAt: CREATED_AT.toISOString() } }, CREATED_AT)).toThrow("future");
    expect(() => calculateFiatConversion({ invoiceCurrency: "USD", invoiceAmount: "99999999999999999999999999999999999999", settlementDecimals: 18, rate: "999999999999999999", shieldBufferBps: 0 })).toThrow("u128");
  });
});
