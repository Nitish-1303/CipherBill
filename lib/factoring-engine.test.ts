import { describe, expect, it } from "vitest";

import {
  buildAdvanceActions,
  buildInvoiceListingDigest,
  buildRepaymentActions,
  createFactorQuote,
  createInvoiceListing,
  FACTORING_POOL_ADDRESS,
  formatFactoringBaseUnits,
  getFactoringVisibilityModel,
  matchInvoiceFactoring,
  openInvoiceListing,
  parseFactoringAgreement,
  parseFactorQuote,
  parseInvoiceListing,
  parseInvoiceListingDigest,
  serializeFactoringAgreement,
  serializeFactorQuote,
  serializeInvoiceListing,
  serializeInvoiceListingDigest,
  summarizeFactoringRisk,
  verifyFactoringAgreement,
  verifyFactorQuote,
  verifyInvoiceListing,
  verifyListingDisclosure,
  type CreateFactorQuoteInput,
  type CreateInvoiceListingInput,
  type FactoringEntropy,
} from "./factoring-engine";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const NOW = new Date("2026-08-22T08:00:00.000Z");
const DUE = "2026-09-21T08:00:00.000Z"; // 30 days out
const OFFER_EXPIRY = "2026-09-05T08:00:00.000Z";
const QUOTE_EXPIRY = "2026-09-01T08:00:00.000Z";
const USDC = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const MERCHANT = "0x0712345678901234567890123456789012345678901234567890123456789012";
const LP = "0x0698765432109876543210987654321098765432109876543210987654321098";

/** Deterministic salts and ids, so every commitment in this file is reproducible. */
function entropy(seed: number): FactoringEntropy {
  return {
    createId: (kind) => `${kind === "listing" ? "list" : kind === "quote" ? "quote" : "agr"}_test_${seed}`,
    randomBytes: (target) => {
      for (let index = 0; index < target.length; index += 1) target[index] = ((index + seed) % 251) + 1;
      return target;
    },
  };
}

const LISTING_INPUT: CreateInvoiceListingInput = {
  invoiceId: "inv_factor_001",
  asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
  faceValue: "1000",
  dueDate: DUE,
  offerExpiry: OFFER_EXPIRY,
  merchantRecipient: MERCHANT,
  debtorLabel: "Acme Corp ****4321",
  memo: "Q3 services",
};

function makeListing(seed = 1) {
  return createInvoiceListing(LISTING_INPUT, NOW, entropy(seed));
}

function makeQuote(listingCommitment: string, overrides: Partial<CreateFactorQuoteInput> = {}, seed = 1) {
  const input: CreateFactorQuoteInput = {
    invoiceId: "inv_factor_001",
    listingCommitment,
    liquidityProviderRecipient: LP,
    pricing: { mode: "flat_discount", discountBps: 250 },
    quoteExpiry: QUOTE_EXPIRY,
    note: "Funds available now",
    ...overrides,
  };
  return createFactorQuote(input, NOW, entropy(seed));
}

function makeAgreement(overrides: Partial<CreateFactorQuoteInput> = {}, seed = 1) {
  const listing = makeListing(seed);
  const quote = makeQuote(listing.listingCommitment, overrides, seed);
  return { listing, quote, agreement: matchInvoiceFactoring(listing, quote, NOW, entropy(seed)) };
}

describe("createInvoiceListing", () => {
  it("records the pool as provenance and solves the tenor from the dates", () => {
    const listing = makeListing();

    expect(listing.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(FACTORING_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(listing.network).toBe("SN_MAIN");
    expect(listing.faceBaseUnits).toBe("1000000000");
    expect(listing.faceDisplay).toBe("1000");
    expect(listing.tenorDays).toBe(30);
    expect(verifyInvoiceListing(listing)).toBe(true);
  });

  it("rejects due dates that are past or beyond the tenor limit, and expired offers", () => {
    expect(() => createInvoiceListing({ ...LISTING_INPUT, dueDate: "2026-08-21T08:00:00.000Z" }, NOW, entropy(1))).toThrow(/due date must be in the future/i);
    expect(() => createInvoiceListing({ ...LISTING_INPUT, dueDate: "2027-09-21T08:00:00.000Z" }, NOW, entropy(1))).toThrow(/due within 365 days/i);
    expect(() => createInvoiceListing({ ...LISTING_INPUT, offerExpiry: "2026-08-21T08:00:00.000Z" }, NOW, entropy(1))).toThrow(/offer expiry must be in the future/i);
    expect(() => createInvoiceListing({ ...LISTING_INPUT, offerExpiry: "2026-09-22T08:00:00.000Z" }, NOW, entropy(1))).toThrow(/offer expiry cannot be later than the invoice due date/i);
  });

  it("rejects a face value finer than the token or not positive", () => {
    expect(() => createInvoiceListing({ ...LISTING_INPUT, faceValue: "1.0000001" }, NOW, entropy(1))).toThrow(/more precision than the token's 6 decimals/i);
    expect(() => createInvoiceListing({ ...LISTING_INPUT, faceValue: "0" }, NOW, entropy(1))).toThrow(/greater than zero/i);
  });
});

describe("factoring economics", () => {
  it("solves a flat discount up and funds the advance that remains", () => {
    const { agreement } = makeAgreement();

    expect(agreement.faceBaseUnits).toBe("1000000000");
    expect(agreement.discountBaseUnits).toBe("25000000");
    expect(agreement.advanceBaseUnits).toBe("975000000");
    expect(agreement.advanceDisplay).toBe("975");
    expect(agreement.repaymentBaseUnits).toBe("1000000000");
    expect(agreement.platformFeeBaseUnits).toBe("0");
    expect(agreement.totalCostBaseUnits).toBe("25000000");
    expect(agreement.effectiveDiscountBps).toBe(250);
    expect(agreement.impliedAprBps).toBe(3119);
    expect(agreement.advanceDeadline).toBe(QUOTE_EXPIRY);
    expect(verifyFactoringAgreement(agreement)).toBe(true);
  });

  it("annualizes a rate across the tenor and charges a flat platform fee on top", () => {
    const { agreement } = makeAgreement({ pricing: { mode: "annualized", aprBps: 1200, platformFeeBaseUnits: "500000" } });

    expect(agreement.discountBaseUnits).toBe("9863014");
    expect(agreement.platformFeeBaseUnits).toBe("500000");
    expect(agreement.totalCostBaseUnits).toBe("10363014");
    expect(agreement.advanceBaseUnits).toBe("989636986");
    expect(agreement.effectiveDiscountBps).toBe(103);
    expect(agreement.pricing.mode).toBe("annualized");
    expect(verifyFactoringAgreement(agreement)).toBe(true);
  });

  it("refuses a discount that would consume the whole face value", () => {
    const listing = makeListing();
    const quote = makeQuote(listing.listingCommitment, { pricing: { mode: "flat_discount", discountBps: 250, platformFeeBaseUnits: "1000000000" } });
    expect(() => matchInvoiceFactoring(listing, quote, NOW, entropy(1))).toThrow(/no advance would remain/i);
  });

  it("rejects rates and fees outside their caps", () => {
    const listing = makeListing();
    expect(() => makeQuote(listing.listingCommitment, { pricing: { mode: "flat_discount", discountBps: 5001 } })).toThrow(/between 1 and 5000 basis points/i);
    expect(() => makeQuote(listing.listingCommitment, { pricing: { mode: "annualized", aprBps: 100001 } })).toThrow(/between 1 and 100000 basis points/i);
  });
});

describe("matching and binding", () => {
  it("binds a quote to the listing it answers and refuses a mismatched pair", () => {
    const listing = makeListing();
    const otherListing = createInvoiceListing({ ...LISTING_INPUT, invoiceId: "inv_factor_999" }, NOW, entropy(3));
    const wrongInvoice = makeQuote(listing.listingCommitment, { invoiceId: "inv_factor_999" });
    const wrongCommitment = makeQuote(otherListing.listingCommitment);

    expect(() => matchInvoiceFactoring(listing, wrongInvoice, NOW, entropy(1))).toThrow(/different invoice/i);
    expect(() => matchInvoiceFactoring(listing, wrongCommitment, NOW, entropy(1))).toThrow(/not bound to this listing/i);
  });

  it("refuses to match once both the offer and the quote have expired", () => {
    const { listing, quote } = makeAgreement();
    expect(() => matchInvoiceFactoring(listing, quote, new Date("2026-09-02T00:00:00.000Z"), entropy(1))).toThrow(/already expired/i);
  });
});

describe("settlement actions", () => {
  it("builds one in-pool advance transfer to the merchant with no extra relayer-fee action", () => {
    const { agreement } = makeAgreement();
    const actions = buildAdvanceActions(agreement, NOW);

    expect(actions).toEqual([{ type: "transfer", token: USDC, amount: "975000000", recipient: agreement.merchantRecipient }]);
    expect(actions.filter((action) => action.type === "withdraw")).toHaveLength(0);
  });

  it("builds one in-pool repayment transfer of the full face to the provider", () => {
    const { agreement } = makeAgreement();
    const actions = buildRepaymentActions(agreement);

    expect(actions).toEqual([{ type: "transfer", token: USDC, amount: "1000000000", recipient: agreement.liquidityProviderRecipient }]);
  });

  it("refuses to build the advance once the offer deadline has passed", () => {
    const { agreement } = makeAgreement();
    expect(() => buildAdvanceActions(agreement, new Date("2026-09-02T00:00:00.000Z"))).toThrow(/expired/i);
  });
});

describe("commitments and selective disclosure", () => {
  it("detects a tampered amount, salt, or bound listing", () => {
    const { listing, quote, agreement } = makeAgreement();

    expect(verifyInvoiceListing({ ...listing, listingSalt: "0x2" })).toBe(false);
    expect(verifyInvoiceListing({ ...listing, memo: "different memo" })).toBe(false);
    expect(verifyFactorQuote({ ...quote, note: "changed note" })).toBe(false);
    expect(verifyFactorQuote({ ...quote, quoteSalt: "0x3" })).toBe(false);
    expect(verifyFactoringAgreement({ ...agreement, advanceBaseUnits: "1" })).toBe(false);
    expect(verifyFactoringAgreement({ ...agreement, agreementSalt: "0x9" })).toBe(false);
  });

  it("publishes a digest that carries no face value, debtor, address, salt, or memo", () => {
    const listing = makeListing();
    const digest = buildInvoiceListingDigest(listing);
    const encoded = JSON.stringify(digest);

    expect(digest.listingCommitment).toBe(listing.listingCommitment);
    expect(encoded).not.toContain(listing.faceBaseUnits);
    expect(encoded).not.toContain(listing.listingSalt);
    expect(encoded).not.toContain(listing.merchantRecipient);
    expect(encoded).not.toContain("Acme Corp");
    expect(encoded).not.toContain("Q3 services");
    expect(parseInvoiceListingDigest(serializeInvoiceListingDigest(digest))).toEqual(digest);
  });

  it("opens a listing against its digest and rejects a doctored opening", () => {
    const listing = makeListing();
    const digest = buildInvoiceListingDigest(listing);
    const opening = openInvoiceListing(listing);

    expect(verifyListingDisclosure(digest, opening)).toBe(true);
    expect(verifyListingDisclosure(digest, { ...opening, listing: { ...opening.listing, debtorLabel: "Someone else" } })).toBe(false);
    expect(verifyListingDisclosure(digest, { ...opening, listingCommitment: "0x5" })).toBe(false);
  });

  it("survives serialize and parse round trips and gives independent objects independent commitments", () => {
    const { listing, quote, agreement } = makeAgreement();
    const twin = makeAgreement({}, 2);

    expect(parseInvoiceListing(serializeInvoiceListing(listing))).toEqual(listing);
    expect(parseFactorQuote(serializeFactorQuote(quote))).toEqual(quote);
    expect(parseFactoringAgreement(serializeFactoringAgreement(agreement))).toEqual(agreement);
    expect(twin.agreement.advanceBaseUnits).toBe(agreement.advanceBaseUnits);
    expect(twin.agreement.agreementSalt).not.toBe(agreement.agreementSalt);
    expect(twin.agreement.agreementCommitment).not.toBe(agreement.agreementCommitment);
    expect(() => parseInvoiceListing("not base64url!!")).toThrow(/encoding is invalid/i);
  });
});

describe("visibility and risk", () => {
  it("says plainly what is in-browser only, what the wallet sees, and what stays public", () => {
    const { agreement } = makeAgreement();
    const model = getFactoringVisibilityModel(agreement);

    expect(model.applicationOnly).toContain("debtor label");
    expect(model.walletRequest).toContain("exact advance and repayment base-unit amounts");
    expect(model.hiddenInPool).toContain("which encrypted notes were spent");
    expect(model.publicOrObservable.some((entry) => /timing/.test(entry))).toBe(true);
    expect(model.limitation).toMatch(/link the provider and the merchant by timing and value/i);
  });

  it("names who bears non-payment risk and refuses to call the deal escrowed or proven", () => {
    const { agreement } = makeAgreement();
    const risk = summarizeFactoringRisk(agreement);

    expect(risk).toMatchObject({ nonPaymentBearer: "liquidity provider", isEscrowed: false, isProven: false });
    expect(risk.trustedParties).toHaveLength(2);
    expect(risk.statement).toMatch(/nothing is escrowed and no proof is generated/i);
  });

  it("formats base units for display", () => {
    expect(formatFactoringBaseUnits("975000000", 6)).toBe("975");
    expect(formatFactoringBaseUnits(1000000000n, 6)).toBe("1000");
    expect(formatFactoringBaseUnits("0", 18)).toBe("0");
    expect(() => formatFactoringBaseUnits("1", 19)).toThrow(/between 0 and 18/i);
  });

  it("keeps in-pool transfers on a real pool token", () => {
    const { agreement } = makeAgreement();
    expect(agreement.asset.tokenAddress).not.toBe(STRK);
    expect(agreement.asset.tokenAddress).toBe(USDC);
  });
});
