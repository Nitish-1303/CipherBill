import { describe, expect, it } from "vitest";

import {
  buildFxQuoteDigest,
  buildFxRateAuthorization,
  buildFxSettlementReceipt,
  buildSettlementActions,
  checkSettlementWithinBand,
  createFxQuote,
  formatFxBaseUnits,
  FX_POOL_ADDRESS,
  getFxVisibilityModel,
  openFxQuote,
  parseFxQuote,
  parseFxQuoteDigest,
  parseFxSettlementReceipt,
  previewFxConversion,
  registerFxRateAuthority,
  serializeFxQuote,
  serializeFxQuoteDigest,
  serializeFxSettlementReceipt,
  summarizeFxTrust,
  verifyFxQuote,
  verifyFxQuoteDisclosure,
  verifyFxRateAuthorization,
  verifyFxSettlementReceipt,
  type CreateFxQuoteInput,
  type FxEntropy,
  type FxRateAuthorityEntropy,
} from "./fx-engine";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const NOW = new Date("2026-08-23T08:00:00.000Z");
const USDC = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const MERCHANT = "0x0712345678901234567890123456789012345678901234567890123456789012";
const TX = "0x02c1f6f9e7b1a4c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8fabc1234";
const MINUTE = 60_000;
const DAY = 86_400_000;

const QUOTE_INPUT: CreateFxQuoteInput = {
  invoiceId: "inv_fx_001",
  merchant: MERCHANT,
  denomination: { currency: "USD", decimals: 2, amount: "100.00" },
  rails: [
    { symbol: "USDC", tokenAddress: USDC, decimals: 6, rate: "1", rateSource: "Treasury desk" },
    { symbol: "STRK", tokenAddress: STRK, decimals: 18, rate: "2.5", rateSource: "Treasury desk" },
  ],
  slippageBps: 100,
  payerLabel: "Acme Corp",
  memo: "q3 retainer",
};

function entropy(seed: number): FxEntropy {
  return {
    createId: () => `fxq_test_${seed.toString().padStart(4, "0")}`,
    randomBytes: (target) => {
      for (let i = 0; i < target.length; i += 1) target[i] = (seed * 31 + i * 7 + 1) & 0xff;
      return target;
    },
  };
}

function authorityEntropy(seed: number): FxRateAuthorityEntropy {
  return { authoritySecret: BigInt(seed) * 6_700_417n + 8191n, nonce: BigInt(seed) * 2_147_483_647n + 524_287n };
}

function makeQuote(overrides: Partial<CreateFxQuoteInput> = {}, seed = 1) {
  return createFxQuote({ ...QUOTE_INPUT, ...overrides }, NOW, entropy(seed));
}

const iso = (offsetMs: number) => new Date(NOW.getTime() + offsetMs).toISOString();

describe("createFxQuote", () => {
  it("records pool provenance, converts each rail, and commits the quote", () => {
    const quote = makeQuote();
    expect(quote.poolAddress).toBe(FX_POOL_ADDRESS);
    expect(quote.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(quote.quoteId).toBe("fxq_test_0001");
    expect(quote.denomination.amountMinorUnits).toBe("10000");
    expect(quote.denomination.amountDisplay).toBe("100");
    expect(quote.rails[0].settlementBaseUnits).toBe("100000000");
    expect(quote.rails[0].settlementDisplay).toBe("100");
    expect(quote.rails[1].settlementBaseUnits).toBe("250000000000000000000");
    expect(quote.rails[1].settlementDisplay).toBe("250");
    expect(quote.quoteCommitment).toMatch(/^0x[0-9a-f]+$/);
    expect(verifyFxQuote(quote)).toBe(true);
  });

  it("ceiling-rounds a settlement so the payer never underpays", () => {
    const quote = makeQuote({
      denomination: { currency: "USD", decimals: 2, amount: "1.00" },
      rails: [{ symbol: "USDC", tokenAddress: USDC, decimals: 6, rate: "0.3333335", rateSource: "desk" }],
      slippageBps: 0,
    });
    expect(quote.rails[0].settlementBaseUnits).toBe("333334");
    expect(quote.rails[0].settlementDisplay).toBe("0.333334");
    expect(quote.rails[0].minBaseUnits).toBe("333334");
    expect(quote.rails[0].maxBaseUnits).toBe("333334");
  });

  it("derives a slippage band around each rail", () => {
    const quote = makeQuote();
    expect(quote.rails[0].minBaseUnits).toBe("99000000");
    expect(quote.rails[0].maxBaseUnits).toBe("101000000");
    expect(quote.rails[1].minBaseUnits).toBe("247500000000000000000");
    expect(quote.rails[1].maxBaseUnits).toBe("252500000000000000000");
  });

  it("sets an expiry after the quote time", () => {
    const quote = makeQuote({ validForMinutes: 30 });
    expect(quote.quotedAt).toBe(NOW.toISOString());
    expect(quote.expiresAt).toBe(iso(30 * MINUTE));
  });

  it("gives independent quotes distinct salts and commitments", () => {
    const a = makeQuote({}, 1);
    const b = makeQuote({}, 2);
    expect(a.quoteSalt).not.toBe(b.quoteSalt);
    expect(a.quoteCommitment).not.toBe(b.quoteCommitment);
    expect(a.rails[0].settlementBaseUnits).toBe(b.rails[0].settlementBaseUnits);
  });

  it("rejects malformed inputs", () => {
    expect(() => makeQuote({ denomination: { currency: "USD", decimals: 2, amount: "0" } })).toThrow(/greater than zero/i);
    expect(() => makeQuote({ slippageBps: 20_000 })).toThrow(/basis points/i);
    expect(() => makeQuote({ rails: [] })).toThrow(/between 1 and 8/i);
    expect(() => makeQuote({
      rails: [{ symbol: "USDC", tokenAddress: USDC, decimals: 6, rate: "1", rateSource: "d" },
        { symbol: "usdc", tokenAddress: STRK, decimals: 18, rate: "1", rateSource: "d" }],
    })).toThrow(/symbols must be unique/i);
    expect(() => makeQuote({
      rails: [{ symbol: "USDC", tokenAddress: USDC, decimals: 6, rate: "1", rateSource: "d" },
        { symbol: "USDT", tokenAddress: USDC, decimals: 6, rate: "1", rateSource: "d" }],
    })).toThrow(/token addresses must be unique/i);
    expect(() => makeQuote({
      rails: [{ symbol: "USDC", tokenAddress: USDC, decimals: 6, rate: "abc", rateSource: "d" }],
    })).toThrow(/positive decimal/i);
  });

  it("refuses a settlement amount that overflows a u128", () => {
    expect(() => makeQuote({
      denomination: { currency: "USD", decimals: 0, amount: "1000000000000000000000" },
      rails: [{ symbol: "STRK", tokenAddress: STRK, decimals: 18, rate: "1", rateSource: "d" }],
    })).toThrow(/u128/i);
  });
});

describe("settlement actions", () => {
  it("builds exactly one in-pool transfer for a chosen rail, with no relayer-fee leg", () => {
    const quote = makeQuote();
    const bySymbol = buildSettlementActions(quote, "STRK");
    expect(bySymbol).toHaveLength(1);
    expect(bySymbol[0]).toEqual({
      type: "transfer",
      token: quote.rails[1].tokenAddress,
      amount: "250000000000000000000",
      recipient: quote.merchant,
    });
    const byAddress = buildSettlementActions(quote, USDC);
    expect(byAddress[0]).toMatchObject({ token: quote.rails[0].tokenAddress, amount: "100000000" });
  });

  it("refuses an unknown rail selector", () => {
    expect(() => buildSettlementActions(makeQuote(), "DAI")).toThrow(/no settlement rail/i);
    expect(() => buildSettlementActions(makeQuote(), "")).toThrow(/selector is required/i);
  });
});

describe("slippage band checks", () => {
  it("accepts an amount inside the band and rejects one outside", () => {
    const quote = makeQuote();
    expect(checkSettlementWithinBand(quote, "USDC", "100000000").withinBand).toBe(true);
    expect(checkSettlementWithinBand(quote, "USDC", "99000000").withinBand).toBe(true);
    expect(checkSettlementWithinBand(quote, "USDC", "101000000").withinBand).toBe(true);
    expect(checkSettlementWithinBand(quote, "USDC", "98999999").withinBand).toBe(false);
    expect(checkSettlementWithinBand(quote, "USDC", "101000001").withinBand).toBe(false);
  });

  it("reports the band bounds it checked against", () => {
    const check = checkSettlementWithinBand(makeQuote(), "USDC", "100000000");
    expect(check.minBaseUnits).toBe("99000000");
    expect(check.maxBaseUnits).toBe("101000000");
    expect(check.quotedBaseUnits).toBe("100000000");
  });
});

describe("conversion preview", () => {
  it("previews every rail without building a committed quote", () => {
    const preview = previewFxConversion({
      denomination: { currency: "USD", decimals: 2, amount: "100.00" },
      rails: QUOTE_INPUT.rails,
      slippageBps: 100,
    });
    expect(preview.denominationDisplay).toBe("100");
    expect(preview.rails).toHaveLength(2);
    expect(preview.rails[0]).toEqual({ symbol: "USDC", rate: "1", settlementDisplay: "100", minDisplay: "99", maxDisplay: "101" });
    expect(preview.rails[1].settlementDisplay).toBe("250");
  });
});

describe("quote digest and disclosure", () => {
  it("omits amounts, rates, addresses, payer, salt, and memo from the digest", () => {
    const quote = makeQuote();
    const digest = buildFxQuoteDigest(quote);
    const json = JSON.stringify(digest);
    expect(json).not.toContain(quote.merchant);
    expect(json).not.toContain(quote.quoteSalt);
    expect(json).not.toContain("Acme Corp");
    expect(json).not.toContain("q3 retainer");
    expect(json).not.toContain("250000000000000000000");
    expect("rails" in digest).toBe(false);
    expect(digest.hasPayer).toBe(true);
    expect(digest.railCount).toBe(2);
    expect(digest.denominationCurrency).toBe("USD");
    expect(digest.railsHash).toMatch(/^0x[0-9a-f]+$/);
    expect(digest.quoteCommitment).toBe(quote.quoteCommitment);
  });

  it("verifies a faithful disclosure and rejects a doctored one", () => {
    const quote = makeQuote();
    const digest = buildFxQuoteDigest(quote);
    const opening = openFxQuote(quote);
    expect(verifyFxQuoteDisclosure(digest, opening)).toBe(true);
    expect(verifyFxQuoteDisclosure(digest, { ...opening, quote: { ...opening.quote, invoiceId: "inv_other" } })).toBe(false);
    expect(verifyFxQuoteDisclosure(digest, { ...opening, quoteCommitment: "0x1" })).toBe(false);
  });

  it("detects a swapped rail rate that no longer matches its settlement", () => {
    const quote = makeQuote();
    const digest = buildFxQuoteDigest(quote);
    const opening = openFxQuote(quote);
    const tamperedRail = { ...quote.rails[0], rate: "2", rateScaled: "2", rateDecimals: 0 };
    const bad = { ...opening, quote: { ...quote, rails: [tamperedRail, quote.rails[1]] } };
    expect(verifyFxQuoteDisclosure(digest, bad)).toBe(false);
  });

  it("round-trips the digest through serialization", () => {
    const digest = buildFxQuoteDigest(makeQuote());
    expect(parseFxQuoteDigest(serializeFxQuoteDigest(digest))).toEqual(digest);
  });
});

describe("settlement receipts", () => {
  it("builds and verifies a receipt bound to the quote and rail", () => {
    const quote = makeQuote();
    const receipt = buildFxSettlementReceipt(quote, {
      railSelector: "USDC",
      settledBaseUnits: "100000000",
      settledAt: iso(2 * MINUTE),
      transactionHash: TX,
    });
    expect(receipt.railTokenAddress).toBe(quote.rails[0].tokenAddress);
    expect(receipt.quotedBaseUnits).toBe("100000000");
    expect(receipt.withinBand).toBe(true);
    expect(verifyFxSettlementReceipt(receipt, quote)).toBe(true);
    expect(verifyFxSettlementReceipt(receipt, makeQuote({}, 2))).toBe(false);
  });

  it("records an out-of-band settlement honestly", () => {
    const quote = makeQuote();
    const receipt = buildFxSettlementReceipt(quote, {
      railSelector: "USDC",
      settledBaseUnits: "98000000",
      settledAt: iso(2 * MINUTE),
      transactionHash: TX,
    });
    expect(receipt.withinBand).toBe(false);
    expect(verifyFxSettlementReceipt(receipt, quote)).toBe(true);
  });

  it("refuses a settlement time before the quote", () => {
    const quote = makeQuote();
    expect(() => buildFxSettlementReceipt(quote, {
      railSelector: "USDC",
      settledBaseUnits: "100000000",
      settledAt: iso(-DAY),
      transactionHash: TX,
    })).toThrow(/before the quote time/i);
  });

  it("round-trips a receipt through serialization", () => {
    const quote = makeQuote();
    const receipt = buildFxSettlementReceipt(quote, {
      railSelector: "STRK",
      settledBaseUnits: "250000000000000000000",
      settledAt: iso(2 * MINUTE),
      transactionHash: TX,
    });
    expect(parseFxSettlementReceipt(serializeFxSettlementReceipt(receipt))).toEqual(receipt);
  });
});

describe("rate authorization", () => {
  it("verifies a valid proof against the expected authority key", () => {
    const quote = makeQuote();
    const authority = registerFxRateAuthority(authorityEntropy(1));
    const auth = buildFxRateAuthorization(quote, "USDC", authority.authoritySecret, authorityEntropy(1));
    expect(verifyFxRateAuthorization(auth, quote, authority.authorityPublicKey)).toBe(true);
  });

  it("rejects a wrong key, a tampered rail, and a wrong quote", () => {
    const quote = makeQuote();
    const authority = registerFxRateAuthority(authorityEntropy(1));
    const other = registerFxRateAuthority(authorityEntropy(2));
    const auth = buildFxRateAuthorization(quote, "USDC", authority.authoritySecret, authorityEntropy(1));
    expect(verifyFxRateAuthorization(auth, quote, other.authorityPublicKey)).toBe(false);
    expect(verifyFxRateAuthorization({ ...auth, railSymbol: "STRK", railTokenAddress: quote.rails[1].tokenAddress }, quote, authority.authorityPublicKey)).toBe(false);
    expect(verifyFxRateAuthorization(auth, makeQuote({}, 2), authority.authorityPublicKey)).toBe(false);
  });

  it("produces a deterministic proof for a fixed nonce", () => {
    const quote = makeQuote();
    const authority = registerFxRateAuthority(authorityEntropy(1));
    const a = buildFxRateAuthorization(quote, "USDC", authority.authoritySecret, authorityEntropy(1));
    const b = buildFxRateAuthorization(quote, "USDC", authority.authoritySecret, authorityEntropy(1));
    expect(a.proof).toEqual(b.proof);
  });

  it("never exposes the authority secret in the authorization", () => {
    const quote = makeQuote();
    const authority = registerFxRateAuthority(authorityEntropy(1));
    const auth = buildFxRateAuthorization(quote, "USDC", authority.authoritySecret, authorityEntropy(1));
    expect(JSON.stringify(auth)).not.toContain(authority.authoritySecret);
  });
});

describe("visibility, trust, and serialization", () => {
  it("states an honest visibility model", () => {
    const model = getFxVisibilityModel(makeQuote());
    expect(model.walletRequest.some((e) => /exact base-unit settlement amount/.test(e))).toBe(true);
    expect(model.hiddenInPool.some((e) => /which encrypted notes were spent/.test(e))).toBe(true);
    expect(model.publicOrObservable.some((e) => /nullifiers/.test(e))).toBe(true);
    expect(model.limitation).toMatch(/no oracle, swap, or price proof/i);
  });

  it("summarizes trust without overclaiming", () => {
    const trust = summarizeFxTrust(makeQuote());
    expect(trust).toMatchObject({ isDecentralized: false, isOracle: false, isSwap: false, provesRate: false, provesPayment: false });
    expect(trust.trustedParties).toHaveLength(2);
    expect(trust.statement).toMatch(/nothing is decentralized, swapped, or oracle-backed/i);
    expect(trust.zeroKnowledgeElement).toMatch(/only the optional rate authorization/i);
  });

  it("detects tampering when verifying a quote", () => {
    const quote = makeQuote();
    expect(verifyFxQuote({ ...quote, quoteSalt: "0x1" })).toBe(false);
    expect(verifyFxQuote({ ...quote, slippageBps: 250 })).toBe(false);
    expect(verifyFxQuote({
      ...quote,
      rails: [{ ...quote.rails[0], settlementDisplay: "999" }, quote.rails[1]],
    })).toBe(false);
  });

  it("round-trips a quote and rejects malformed encodings", () => {
    const quote = makeQuote();
    expect(parseFxQuote(serializeFxQuote(quote))).toEqual(quote);
    expect(() => parseFxQuote("!!not valid!!")).toThrow(/encoding is invalid/i);
  });

  it("formats base units and guards decimals", () => {
    expect(formatFxBaseUnits("100000000", 6)).toBe("100");
    expect(formatFxBaseUnits(1_000_002n, 6)).toBe("1.000002");
    expect(formatFxBaseUnits("0", 0)).toBe("0");
    expect(() => formatFxBaseUnits("1", 19)).toThrow(/between 0 and 18/i);
  });
});






