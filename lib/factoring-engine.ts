/**
 * Invoice factoring and liquidity-matching engine for CipherBill.
 *
 * This module holds two independent layers. Read the boundary before writing copy:
 *
 *   1. The PLAN layer (`createInvoiceListing` .. `summarizeFactoringRisk`) — exact-integer
 *      discounting plus salted Poseidon commitments. It is NOT zero-knowledge.
 *   2. The VAULT layer (`issueFactoringVaultCertificate` .. `verifyFactoringVaultDisclosure`)
 *      — Pedersen commitments with bit-decomposition range proofs. It IS zero-knowledge, but
 *      only about arithmetic relations between numbers the issuer typed in. See the
 *      "RECEIVABLES COLLATERALIZATION VAULT" banner further down for its exact claim set.
 *
 * WHAT THIS IS
 * - An exact-integer discounting engine: a merchant lists an unpaid invoice (face value,
 *   due date) and a liquidity provider quotes a discount rate or an annualized APR. The
 *   engine solves the advance the merchant receives now and the repayment owed at maturity,
 *   in bigint arithmetic with a stated rounding direction that favours the party taking risk.
 * - A client-side matching step that binds one listing to one quote and produces a factoring
 *   agreement both sides can check, without an on-chain order book or a coordinator.
 * - A salted Poseidon commitment scheme so a merchant can publish a listing digest that hides
 *   the face value, the debtor's identity, and the settlement address, then disclose the full
 *   listing to a chosen liquidity provider who verifies it against the published commitment.
 * - A builder for the two STRK20 settlement legs: a private in-pool `transfer` of the advance
 *   from the provider to the merchant now, and a private in-pool `transfer` of the repayment
 *   from the merchant to the provider once the invoice is collected.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - The plan layer is not zero-knowledge and it proves nothing about an invoice. Its commitments
 *   are salted Poseidon hashes: they bind and hide the terms, but they do not attest that an
 *   invoice, a debtor, or a due date is real. The vault layer adds real range proofs, but they
 *   too are statements about typed-in numbers, never about the receivables behind them.
 *   Legitimacy here is a legal and commercial fact, not a mathematical one.
 * - Neither layer is verified on-chain. CipherBill generates no proof the pool consumes: the
 *   wallet proves the settlement transfer and the pool verifies that transfer onchain, and
 *   `wallet_strk20InvokeTransaction` returns only `{ transaction_hash }`. No Starknet contract
 *   reads, stores, or checks a listing, an agreement, or a vault certificate.
 * - Not a decentralized marketplace or exchange. Matching is a local computation in one party's
 *   browser. There is no on-chain listing registry, escrow contract, or atomic swap. The STRK20
 *   Wallet API is three methods over four Starknet-only action types (`deposit`, `withdraw`,
 *   `transfer`, `invoke`); none of them lists, matches, or tokenizes an invoice.
 * - Not tokenization. The invoice is never minted as an NFT or a transferable token. The listing
 *   is a JSON commitment held in a browser, not an asset that changes hands onchain.
 * - Not escrow or a guarantee. Nothing holds the advance or enforces repayment. If the debtor
 *   never pays, the provider's recourse is legal, not on-chain. Non-payment risk sits entirely
 *   with the party who advanced the funds.
 * - Not anonymous end to end. In-pool transfers hide the sender, recipient, token, and amount,
 *   but registration, timing, and any withdrawal stay public, and the debtor label and face
 *   value live only in the merchant's browser. A "shielded" provider is shielded in-pool only.
 * - Not a price, rate, or credit oracle. Discounts, APRs, and fees are caller-supplied and
 *   committed as given. The engine checks arithmetic, never whether a rate is fair or a debtor
 *   is creditworthy. `STRK20_POOL_ADDRESS` is recorded as provenance for the settlement legs,
 *   not as a contract that sees, stores, or validates a listing.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const FACTORING_ENGINE_VERSION = 1 as const;
export const FACTORING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const FEE_BPS_DENOMINATOR = 10_000n;
export const DAY_COUNT_BASIS = 365n;
export const DAY_MS = 86_400_000;
export const MAX_DISCOUNT_BPS = 5_000;
export const MAX_APR_BPS = 100_000;
export const MAX_ASSET_DECIMALS = 18;
export const MAX_TENOR_DAYS = 365;
export const MAX_OFFER_LIFETIME_MS = 30 * DAY_MS;
export const FACTORING_SALT_BYTES = 31;

const LISTING_KIND = "cipherbill.invoice-listing" as const;
const LISTING_DIGEST_KIND = "cipherbill.invoice-listing-digest" as const;
const QUOTE_KIND = "cipherbill.factor-quote" as const;
const AGREEMENT_KIND = "cipherbill.factoring-agreement" as const;

const LISTING_DOMAIN = hash.starknetKeccak("CipherBill invoice listing v1");
const QUOTE_DOMAIN = hash.starknetKeccak("CipherBill factor quote v1");
const AGREEMENT_DOMAIN = hash.starknetKeccak("CipherBill factoring agreement v1");
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 200_000;

const FACTORING_NOTICE = "Client-side invoice-discounting plan. The advance and the repayment are private in-pool STRK20 transfers between registered pool users; everything else here is computation held in one browser. No proof, escrow, or on-chain marketplace is involved, and non-payment risk stays with the party that advances the funds.";

const FACTORING_LIMITATIONS = [
  "No invoice is tokenized, listed, or matched on-chain. Matching is a local computation, and only the advance and repayment transfers touch the STRK20 pool.",
  "Commitments are salted Poseidon hashes. They are not zero-knowledge proofs, no contract verifies them, and they attest nothing about whether the invoice, debtor, or due date is real.",
  "Nothing is held in escrow. If the debtor never pays, the provider's only recourse is legal or commercial. Repayment is not enforced on-chain.",
  "Discount rates, APRs, and platform fees are caller-supplied and committed as given. Fairness, creditworthiness, and solvency are never checked.",
  "In-pool transfers hide sender, recipient, token, and amount, but a distinctive advance amount followed by a matching repayment can link the two parties by timing and value.",
  "The face value, the debtor's identity, and the settlement addresses live only in this browser until the merchant discloses them to a chosen provider.",
] as const;

export type FactorPricingMode = "flat_discount" | "annualized";

/** The settlement token. Both legs are in-pool transfers of it, so it must be a pool token. */
export interface FactoringAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface FactorPricingInput {
  mode: FactorPricingMode;
  /** Required for `flat_discount`: discount taken from the face value, in basis points. */
  discountBps?: number;
  /** Required for `annualized`: annual rate applied across the tenor, in basis points. */
  aprBps?: number;
  /** Optional flat platform fee in the asset's base units. Defaults to "0". */
  platformFeeBaseUnits?: string;
}

export interface FactorPricing {
  mode: FactorPricingMode;
  discountBps: number;
  aprBps: number;
  platformFeeBaseUnits: string;
}

export interface CreateInvoiceListingInput {
  invoiceId: string;
  asset: { symbol: string; tokenAddress: string; decimals: number };
  faceValue: string;
  dueDate: string;
  offerExpiry: string;
  merchantRecipient: string;
  debtorLabel?: string;
  memo?: string;
}

export interface InvoiceListing {
  kind: typeof LISTING_KIND;
  version: typeof FACTORING_ENGINE_VERSION;
  listingId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  asset: FactoringAsset;
  faceBaseUnits: string;
  faceDisplay: string;
  dueDate: string;
  offerExpiry: string;
  createdAt: string;
  tenorDays: number;
  merchantRecipient: string;
  /** Trade secret. Bound by the commitment, published only as a keccak hash in the digest. */
  debtorLabel: string;
  memo: string;
  /** Secret listing-level blinding factor. Never publish a listing; publish its digest. */
  listingSalt: string;
  listingCommitment: string;
  notice: typeof FACTORING_NOTICE;
  limitations: string[];
}

/** Listing fields safe to publish to providers: no face value, address, debtor, or salt. */
export interface InvoiceListingDigest {
  kind: typeof LISTING_DIGEST_KIND;
  version: typeof FACTORING_ENGINE_VERSION;
  listingId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  assetSymbol: string;
  assetDecimals: number;
  dueDate: string;
  offerExpiry: string;
  createdAt: string;
  tenorDays: number;
  debtorLabelHash: string;
  listingCommitment: string;
  notice: typeof FACTORING_NOTICE;
  limitations: string[];
}

/** One listing disclosed against a published digest, for a chosen provider or an auditor. */
export interface InvoiceListingOpening {
  listingId: string;
  listingCommitment: string;
  listing: InvoiceListing;
}

export interface CreateFactorQuoteInput {
  invoiceId: string;
  listingCommitment: string;
  liquidityProviderRecipient: string;
  pricing: FactorPricingInput;
  quoteExpiry: string;
  note?: string;
}

export interface FactorQuote {
  kind: typeof QUOTE_KIND;
  version: typeof FACTORING_ENGINE_VERSION;
  quoteId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  listingCommitment: string;
  liquidityProviderRecipient: string;
  pricing: FactorPricing;
  quoteExpiry: string;
  createdAt: string;
  note: string;
  quoteSalt: string;
  quoteCommitment: string;
  notice: typeof FACTORING_NOTICE;
  limitations: string[];
}

export interface FactoringAgreement {
  kind: typeof AGREEMENT_KIND;
  version: typeof FACTORING_ENGINE_VERSION;
  agreementId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  asset: FactoringAsset;
  faceBaseUnits: string;
  faceDisplay: string;
  advanceBaseUnits: string;
  advanceDisplay: string;
  repaymentBaseUnits: string;
  repaymentDisplay: string;
  discountBaseUnits: string;
  discountDisplay: string;
  platformFeeBaseUnits: string;
  platformFeeDisplay: string;
  totalCostBaseUnits: string;
  totalCostDisplay: string;
  pricing: FactorPricing;
  effectiveDiscountBps: number;
  impliedAprBps: number;
  tenorDays: number;
  merchantRecipient: string;
  liquidityProviderRecipient: string;
  dueDate: string;
  advanceDeadline: string;
  createdAt: string;
  listingCommitment: string;
  quoteCommitment: string;
  agreementSalt: string;
  agreementCommitment: string;
  notice: typeof FACTORING_NOTICE;
  limitations: string[];
}

export interface FactoringVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface FactoringRiskSummary {
  nonPaymentBearer: string;
  isEscrowed: boolean;
  isProven: boolean;
  trustedParties: string[];
  statement: string;
}

export interface FactoringEntropy {
  createId?: (kind: "listing" | "quote" | "agreement") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

/**
 * Builds a merchant's invoice listing: the private object that holds the face value, the
 * debtor label, and the settlement address, bound by a salted Poseidon commitment. Share the
 * digest from `buildInvoiceListingDigest`, never this object.
 */
export function createInvoiceListing(
  input: CreateInvoiceListingInput,
  now = new Date(),
  entropy: FactoringEntropy = {},
): InvoiceListing {
  const createdAt = requireIsoTimestamp(now.toISOString(), "Listing creation time");
  const dueDate = requireIsoTimestamp(input.dueDate, "Invoice due date");
  const offerExpiry = requireIsoTimestamp(input.offerExpiry, "Offer expiry");
  const createdMs = Date.parse(createdAt);
  const dueMs = Date.parse(dueDate);
  const offerMs = Date.parse(offerExpiry);
  if (dueMs <= createdMs) throw new Error("The invoice due date must be in the future.");
  if (dueMs - createdMs > MAX_TENOR_DAYS * DAY_MS) throw new Error(`The invoice must be due within ${MAX_TENOR_DAYS} days.`);
  if (offerMs <= createdMs) throw new Error("The offer expiry must be in the future.");
  if (offerMs > dueMs) throw new Error("The offer expiry cannot be later than the invoice due date.");
  if (offerMs - createdMs > MAX_OFFER_LIFETIME_MS) throw new Error(`The offer expiry must be within ${MAX_OFFER_LIFETIME_MS / DAY_MS} days.`);

  const asset = normalizeAsset(input.asset, "Invoice asset");
  const faceBaseUnits = parseDecimalToBaseUnits(input.faceValue, asset.decimals, "Face value");
  requireU128(faceBaseUnits, "Face value");
  const tenorDays = tenorDaysBetween(createdMs, dueMs);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<InvoiceListing, "listingCommitment"> = {
    kind: LISTING_KIND,
    version: FACTORING_ENGINE_VERSION,
    listingId: makeId(entropy.createId?.("listing"), "list"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    asset,
    faceBaseUnits: faceBaseUnits.toString(),
    faceDisplay: formatBaseUnits(faceBaseUnits, asset.decimals),
    dueDate,
    offerExpiry,
    createdAt,
    tenorDays,
    merchantRecipient: normalizeStarknetAddress(requireText(input.merchantRecipient, "Merchant recipient", 66)),
    debtorLabel: requireOptionalText(input.debtorLabel ?? "", "Debtor label", 96),
    memo: requireOptionalText(input.memo ?? "", "Listing memo", 160),
    listingSalt: toHex(randomFelt(random)),
    notice: FACTORING_NOTICE,
    limitations: [...FACTORING_LIMITATIONS],
  };
  const listing: InvoiceListing = { ...draft, listingCommitment: toHex(computeListingCommitment(draft)) };
  assertInvoiceListing(listing);
  return listing;
}

export function verifyInvoiceListing(listing: InvoiceListing): boolean {
  try {
    assertInvoiceListing(listing);
    return true;
  } catch {
    return false;
  }
}

/** The only listing object safe to publish. Carries the due date and a debtor hash, no amount. */
export function buildInvoiceListingDigest(listing: InvoiceListing): InvoiceListingDigest {
  assertInvoiceListing(listing);
  return {
    kind: LISTING_DIGEST_KIND,
    version: FACTORING_ENGINE_VERSION,
    listingId: listing.listingId,
    network: listing.network,
    poolAddress: listing.poolAddress,
    invoiceId: listing.invoiceId,
    assetSymbol: listing.asset.symbol,
    assetDecimals: listing.asset.decimals,
    dueDate: listing.dueDate,
    offerExpiry: listing.offerExpiry,
    createdAt: listing.createdAt,
    tenorDays: listing.tenorDays,
    debtorLabelHash: toHex(BigInt(hash.starknetKeccak(listing.debtorLabel || "undisclosed"))),
    listingCommitment: listing.listingCommitment,
    notice: FACTORING_NOTICE,
    limitations: [...FACTORING_LIMITATIONS],
  };
}

/** Discloses the full listing so a chosen provider can check it against a published digest. */
export function openInvoiceListing(listing: InvoiceListing): InvoiceListingOpening {
  assertInvoiceListing(listing);
  return { listingId: listing.listingId, listingCommitment: listing.listingCommitment, listing };
}

export function verifyListingDisclosure(digest: InvoiceListingDigest, opening: InvoiceListingOpening): boolean {
  try {
    assertInvoiceListingDigest(digest);
    assertInvoiceListing(opening.listing);
    if (digest.listingId !== opening.listingId || digest.listingCommitment !== opening.listingCommitment) return false;
    if (digest.listingCommitment !== opening.listing.listingCommitment) return false;
    return digest.invoiceId === opening.listing.invoiceId
      && digest.assetSymbol === opening.listing.asset.symbol
      && digest.assetDecimals === opening.listing.asset.decimals
      && digest.dueDate === opening.listing.dueDate
      && digest.offerExpiry === opening.listing.offerExpiry
      && digest.tenorDays === opening.listing.tenorDays
      && digest.debtorLabelHash === toHex(BigInt(hash.starknetKeccak(opening.listing.debtorLabel || "undisclosed")));
  } catch {
    return false;
  }
}

/**
 * Builds a provider's quote against a listing commitment. The quote fixes the pricing and the
 * repayment address, and binds itself to the listing it answers so neither side can later swap
 * in a different listing.
 */
export function createFactorQuote(
  input: CreateFactorQuoteInput,
  now = new Date(),
  entropy: FactoringEntropy = {},
): FactorQuote {
  const createdAt = requireIsoTimestamp(now.toISOString(), "Quote creation time");
  const quoteExpiry = requireIsoTimestamp(input.quoteExpiry, "Quote expiry");
  if (Date.parse(quoteExpiry) <= Date.parse(createdAt)) throw new Error("The quote expiry must be in the future.");
  if (Date.parse(quoteExpiry) - Date.parse(createdAt) > MAX_OFFER_LIFETIME_MS) throw new Error(`The quote expiry must be within ${MAX_OFFER_LIFETIME_MS / DAY_MS} days.`);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<FactorQuote, "quoteCommitment"> = {
    kind: QUOTE_KIND,
    version: FACTORING_ENGINE_VERSION,
    quoteId: makeId(entropy.createId?.("quote"), "quote"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    listingCommitment: toHex(requireFelt(input.listingCommitment, "Listing commitment")),
    liquidityProviderRecipient: normalizeStarknetAddress(requireText(input.liquidityProviderRecipient, "Provider recipient", 66)),
    pricing: normalizePricing(input.pricing),
    quoteExpiry,
    createdAt,
    note: requireOptionalText(input.note ?? "", "Quote note", 160),
    quoteSalt: toHex(randomFelt(random)),
    notice: FACTORING_NOTICE,
    limitations: [...FACTORING_LIMITATIONS],
  };
  const quote: FactorQuote = { ...draft, quoteCommitment: toHex(computeQuoteCommitment(draft)) };
  assertFactorQuote(quote);
  return quote;
}

export function verifyFactorQuote(quote: FactorQuote): boolean {
  try {
    assertFactorQuote(quote);
    return true;
  } catch {
    return false;
  }
}

/**
 * Matches one listing to one quote and solves the settlement in exact integers. The discount
 * rounds up (against the merchant, in favour of the provider taking the non-payment risk); the
 * platform fee is exact. The provider advances `advanceBaseUnits` now and is repaid the full
 * face at collection.
 */
export function matchInvoiceFactoring(
  listing: InvoiceListing,
  quote: FactorQuote,
  now = new Date(),
  entropy: FactoringEntropy = {},
): FactoringAgreement {
  assertInvoiceListing(listing);
  assertFactorQuote(quote);
  if (quote.invoiceId !== listing.invoiceId) throw new Error("The quote answers a different invoice than the listing.");
  if (quote.listingCommitment !== listing.listingCommitment) throw new Error("The quote is not bound to this listing.");

  const createdAt = requireIsoTimestamp(now.toISOString(), "Agreement time");
  const advanceDeadline = earlierIso(listing.offerExpiry, quote.quoteExpiry);
  if (Date.parse(advanceDeadline) <= Date.parse(createdAt)) throw new Error("The listing offer or the quote has already expired.");

  const face = BigInt(listing.faceBaseUnits);
  const economics = solveFactoring(face, quote.pricing, listing.tenorDays);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<FactoringAgreement, "agreementCommitment"> = {
    kind: AGREEMENT_KIND,
    version: FACTORING_ENGINE_VERSION,
    agreementId: makeId(entropy.createId?.("agreement"), "agr"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: listing.invoiceId,
    asset: listing.asset,
    faceBaseUnits: face.toString(),
    faceDisplay: formatBaseUnits(face, listing.asset.decimals),
    advanceBaseUnits: economics.advance.toString(),
    advanceDisplay: formatBaseUnits(economics.advance, listing.asset.decimals),
    repaymentBaseUnits: face.toString(),
    repaymentDisplay: formatBaseUnits(face, listing.asset.decimals),
    discountBaseUnits: economics.discount.toString(),
    discountDisplay: formatBaseUnits(economics.discount, listing.asset.decimals),
    platformFeeBaseUnits: economics.platformFee.toString(),
    platformFeeDisplay: formatBaseUnits(economics.platformFee, listing.asset.decimals),
    totalCostBaseUnits: economics.totalCost.toString(),
    totalCostDisplay: formatBaseUnits(economics.totalCost, listing.asset.decimals),
    pricing: quote.pricing,
    effectiveDiscountBps: economics.effectiveDiscountBps,
    impliedAprBps: economics.impliedAprBps,
    tenorDays: listing.tenorDays,
    merchantRecipient: listing.merchantRecipient,
    liquidityProviderRecipient: quote.liquidityProviderRecipient,
    dueDate: listing.dueDate,
    advanceDeadline,
    createdAt,
    listingCommitment: listing.listingCommitment,
    quoteCommitment: quote.quoteCommitment,
    agreementSalt: toHex(randomFelt(random)),
    notice: FACTORING_NOTICE,
    limitations: [...FACTORING_LIMITATIONS],
  };
  const agreement: FactoringAgreement = { ...draft, agreementCommitment: toHex(computeAgreementCommitment(draft)) };
  assertFactoringAgreement(agreement);
  return agreement;
}

export function verifyFactoringAgreement(agreement: FactoringAgreement): boolean {
  try {
    assertFactoringAgreement(agreement);
    return true;
  } catch {
    return false;
  }
}

export function assertAdvanceOpen(agreement: FactoringAgreement, now = new Date()): void {
  assertFactoringAgreement(agreement);
  if (now.getTime() > Date.parse(agreement.advanceDeadline)) {
    throw new Error("This factoring offer has expired. Re-quote the listing against a current rate before advancing.");
  }
}

/**
 * The advance leg: a private in-pool `transfer` of the advance from the provider to the
 * merchant. The connected wallet here is the provider's. No relayer-fee action is added:
 * `wallet_strk20InvokeTransaction` appends its own, and a second one would double-charge.
 */
export function buildAdvanceActions(agreement: FactoringAgreement, now = new Date()): STRK20_ACTION[] {
  assertAdvanceOpen(agreement, now);
  return [{ type: "transfer", token: agreement.asset.tokenAddress, amount: agreement.advanceBaseUnits, recipient: agreement.merchantRecipient }];
}

/**
 * The repayment leg: a private in-pool `transfer` of the collected face value from the
 * merchant to the provider, executed once the debtor has paid. Not gated on a deadline, since
 * collection timing varies. No relayer-fee action is added, for the same reason as the advance.
 */
export function buildRepaymentActions(agreement: FactoringAgreement): STRK20_ACTION[] {
  assertFactoringAgreement(agreement);
  return [{ type: "transfer", token: agreement.asset.tokenAddress, amount: agreement.repaymentBaseUnits, recipient: agreement.liquidityProviderRecipient }];
}

export function getFactoringVisibilityModel(agreement: FactoringAgreement): FactoringVisibilityModel {
  assertFactoringAgreement(agreement);
  return {
    applicationOnly: ["invoice ID", "face value and advance amount", "debtor label", "listing, quote, and agreement salts", "pricing assumptions", "listing memo"],
    walletRequest: ["settlement token address", "exact advance and repayment base-unit amounts", "in-pool merchant and provider recipients"],
    hiddenInPool: ["in-pool sender and recipient of both transfers", "token and amount of both transfers", "which encrypted notes were spent"],
    publicOrObservable: ["published nullifiers, unlinkable without a viewing key", "transaction timing and fees for each transfer"],
    limitation: "The advance and the repayment are two transfers of related amounts between the same pair. A distinctive advance amount followed by a matching repayment can link the provider and the merchant by timing and value. Vary timing and avoid distinctive amounts.",
  };
}

export function summarizeFactoringRisk(agreement: FactoringAgreement): FactoringRiskSummary {
  assertFactoringAgreement(agreement);
  return {
    nonPaymentBearer: "liquidity provider",
    isEscrowed: false,
    isProven: false,
    trustedParties: ["the merchant to remit the collected invoice", "the debtor to pay the invoice at maturity"],
    statement: `The provider advances ${agreement.advanceDisplay} ${agreement.asset.symbol} now against a ${agreement.faceDisplay} ${agreement.asset.symbol} face value due in ${agreement.tenorDays} day${agreement.tenorDays === 1 ? "" : "s"}. Nothing is escrowed and no proof is generated. If the debtor never pays or the merchant never remits, the provider's loss is a commercial dispute, not something this application or the pool enforces.`,
  };
}

export function serializeInvoiceListing(listing: InvoiceListing): string {
  assertInvoiceListing(listing);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(listing)));
}

export function parseInvoiceListing(encoded: string): InvoiceListing {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Invoice listing");
  assertInvoiceListing(parsed);
  return parsed;
}

export function serializeInvoiceListingDigest(digest: InvoiceListingDigest): string {
  assertInvoiceListingDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseInvoiceListingDigest(encoded: string): InvoiceListingDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Listing digest");
  assertInvoiceListingDigest(parsed);
  return parsed;
}

export function serializeFactorQuote(quote: FactorQuote): string {
  assertFactorQuote(quote);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(quote)));
}

export function parseFactorQuote(encoded: string): FactorQuote {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Factor quote");
  assertFactorQuote(parsed);
  return parsed;
}

export function serializeFactoringAgreement(agreement: FactoringAgreement): string {
  assertFactoringAgreement(agreement);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(agreement)));
}

export function parseFactoringAgreement(encoded: string): FactoringAgreement {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Factoring agreement");
  assertFactoringAgreement(parsed);
  return parsed;
}

export function formatFactoringBaseUnits(value: string | bigint, decimals: number): string {
  const amount = typeof value === "bigint" ? value : BigInt(value);
  return formatBaseUnits(amount, requireDecimals(decimals, "Asset decimals"));
}

interface FactoringEconomics {
  discount: bigint;
  platformFee: bigint;
  totalCost: bigint;
  advance: bigint;
  effectiveDiscountBps: number;
  impliedAprBps: number;
}

/** Discount rounds up (in the provider's favour); the flat fee is exact. Advance must stay positive. */
function solveFactoring(face: bigint, pricing: FactorPricing, tenorDays: number): FactoringEconomics {
  requireU128(face, "Face value");
  const platformFee = requireBaseUnitString(pricing.platformFeeBaseUnits, "Platform fee");
  requireU128(platformFee, "Platform fee");
  const discount = pricing.mode === "annualized"
    ? divideCeil(face * BigInt(pricing.aprBps) * BigInt(tenorDays), FEE_BPS_DENOMINATOR * DAY_COUNT_BASIS)
    : divideCeil(face * BigInt(pricing.discountBps), FEE_BPS_DENOMINATOR);
  const totalCost = discount + platformFee;
  if (totalCost >= face) throw new Error("The discount and fee consume the entire face value; no advance would remain.");
  const advance = face - totalCost;
  requireU128(advance, "Advance amount");
  const effectiveDiscountBps = Number((totalCost * FEE_BPS_DENOMINATOR) / face);
  const impliedAprBps = Number((totalCost * FEE_BPS_DENOMINATOR * DAY_COUNT_BASIS) / (advance * BigInt(tenorDays)));
  return { discount, platformFee, totalCost, advance, effectiveDiscountBps, impliedAprBps };
}

function normalizePricing(input: FactorPricingInput): FactorPricing {
  if (!input || (input.mode !== "flat_discount" && input.mode !== "annualized")) {
    throw new Error("Pricing mode must be 'flat_discount' or 'annualized'.");
  }
  const platformFee = requireBaseUnitString(input.platformFeeBaseUnits ?? "0", "Platform fee");
  requireU128(platformFee, "Platform fee");
  if (input.mode === "flat_discount") {
    const discountBps = input.discountBps ?? 0;
    if (!Number.isInteger(discountBps) || discountBps < 1 || discountBps > MAX_DISCOUNT_BPS) {
      throw new Error(`A flat discount must be between 1 and ${MAX_DISCOUNT_BPS} basis points.`);
    }
    return { mode: "flat_discount", discountBps, aprBps: 0, platformFeeBaseUnits: platformFee.toString() };
  }
  const aprBps = input.aprBps ?? 0;
  if (!Number.isInteger(aprBps) || aprBps < 1 || aprBps > MAX_APR_BPS) {
    throw new Error(`An annualized rate must be between 1 and ${MAX_APR_BPS} basis points.`);
  }
  return { mode: "annualized", discountBps: 0, aprBps, platformFeeBaseUnits: platformFee.toString() };
}

function normalizeAsset(asset: { symbol: string; tokenAddress: string; decimals: number } | undefined, label: string): FactoringAsset {
  if (!asset || !asset.tokenAddress) throw new Error(`${label} needs a Starknet token contract address.`);
  return {
    symbol: requireSymbol(asset.symbol, `${label} symbol`),
    tokenAddress: normalizeStarknetAddress(asset.tokenAddress),
    decimals: requireDecimals(asset.decimals, `${label} decimals`),
  };
}

function tenorDaysBetween(createdMs: number, dueMs: number): number {
  const days = Math.ceil((dueMs - createdMs) / DAY_MS);
  if (days < 1 || days > MAX_TENOR_DAYS) throw new Error(`The invoice tenor must be between 1 and ${MAX_TENOR_DAYS} days.`);
  return days;
}

function earlierIso(left: string, right: string): string {
  return Date.parse(left) <= Date.parse(right) ? left : right;
}

function makeId(provided: string | undefined, prefix: string): string {
  const id = provided ?? `${prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!new RegExp(`^${prefix}_[A-Za-z0-9_-]{1,48}$`).test(id)) throw new Error(`A ${prefix} identifier is invalid.`);
  return id;
}

function secondsOf(iso: string): bigint {
  return BigInt(Math.floor(Date.parse(iso) / 1_000));
}

function computeListingCommitment(listing: Omit<InvoiceListing, "listingCommitment">): bigint {
  return hashElements([
    LISTING_DOMAIN,
    BigInt(listing.version),
    requireFelt(listing.listingSalt, "Listing salt"),
    BigInt(hash.starknetKeccak(listing.listingId)),
    BigInt(hash.starknetKeccak(listing.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(hash.starknetKeccak(listing.asset.symbol)),
    BigInt(listing.asset.tokenAddress),
    BigInt(listing.asset.decimals),
    BigInt(listing.faceBaseUnits),
    secondsOf(listing.dueDate),
    secondsOf(listing.offerExpiry),
    secondsOf(listing.createdAt),
    BigInt(listing.tenorDays),
    BigInt(listing.merchantRecipient),
    BigInt(hash.starknetKeccak(listing.debtorLabel || "undisclosed")),
    BigInt(hash.starknetKeccak(listing.memo || "empty")),
  ]);
}

function computeQuoteCommitment(quote: Omit<FactorQuote, "quoteCommitment">): bigint {
  return hashElements([
    QUOTE_DOMAIN,
    BigInt(quote.version),
    requireFelt(quote.quoteSalt, "Quote salt"),
    BigInt(hash.starknetKeccak(quote.quoteId)),
    BigInt(hash.starknetKeccak(quote.invoiceId)),
    requireFelt(quote.listingCommitment, "Listing commitment"),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(quote.liquidityProviderRecipient),
    BigInt(hash.starknetKeccak(quote.pricing.mode)),
    BigInt(quote.pricing.discountBps),
    BigInt(quote.pricing.aprBps),
    BigInt(quote.pricing.platformFeeBaseUnits),
    secondsOf(quote.quoteExpiry),
    secondsOf(quote.createdAt),
    BigInt(hash.starknetKeccak(quote.note || "empty")),
  ]);
}

function computeAgreementCommitment(agreement: Omit<FactoringAgreement, "agreementCommitment">): bigint {
  return hashElements([
    AGREEMENT_DOMAIN,
    BigInt(agreement.version),
    requireFelt(agreement.agreementSalt, "Agreement salt"),
    BigInt(hash.starknetKeccak(agreement.agreementId)),
    BigInt(hash.starknetKeccak(agreement.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    requireFelt(agreement.listingCommitment, "Listing commitment"),
    requireFelt(agreement.quoteCommitment, "Quote commitment"),
    BigInt(agreement.asset.tokenAddress),
    BigInt(agreement.asset.decimals),
    BigInt(agreement.faceBaseUnits),
    BigInt(agreement.advanceBaseUnits),
    BigInt(agreement.repaymentBaseUnits),
    BigInt(agreement.discountBaseUnits),
    BigInt(agreement.platformFeeBaseUnits),
    BigInt(agreement.merchantRecipient),
    BigInt(agreement.liquidityProviderRecipient),
    secondsOf(agreement.dueDate),
    secondsOf(agreement.advanceDeadline),
    secondsOf(agreement.createdAt),
    BigInt(agreement.tenorDays),
    BigInt(hash.starknetKeccak(agreement.pricing.mode)),
    BigInt(agreement.pricing.discountBps),
    BigInt(agreement.pricing.aprBps),
  ]);
}
/** Draws a non-zero field element from the injected entropy source. */
function randomFelt(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const bytes = random(new Uint8Array(FACTORING_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== FACTORING_SALT_BYTES) throw new Error("The entropy source returned the wrong number of bytes.");
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n && value < FIELD_PRIME) return value;
  }
  throw new Error("Could not draw a usable salt.");
}

function hashElements(values: bigint[]): bigint {
  for (const value of values) {
    if (value < 0n || value >= FIELD_PRIME) throw new Error("A commitment input is outside the STARK field.");
  }
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function divideCeil(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) throw new Error("Factoring arithmetic hit a non-positive denominator.");
  if (numerator <= 0n) return 0n;
  return (numerator + denominator - 1n) / denominator;
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Factoring amounts cannot be negative.");
  if (decimals === 0) return value.toString();
  const divisor = 10n ** BigInt(decimals);
  const fraction = (value % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  const whole = (value / divisor).toString();
  return fraction ? `${whole}.${fraction}` : whole;
}

function parseDecimalToBaseUnits(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a positive decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  const units = BigInt(`${whole}${fraction.padEnd(decimals, "0")}`);
  if (units <= 0n) throw new Error(`${label} must be greater than zero.`);
  return units;
}
function requireBaseUnitString(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} is outside the u128 range the privacy pool accepts.`);
  return value;
}

function requireSymbol(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9.-]{2,12}$/.test(value)) throw new Error(`${label} must be 2 to 12 letters, digits, dots, or dashes.`);
  return value;
}

function requireDecimals(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_ASSET_DECIMALS) {
    throw new Error(`${label} must be a whole number between 0 and ${MAX_ASSET_DECIMALS}.`);
  }
  return value;
}

function requireText(value: unknown, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) throw new Error(`${label} must be between 1 and ${maxLength} characters.`);
  if (pattern && !pattern.test(trimmed)) throw new Error(`${label} has an unsupported format.`);
  return trimmed;
}

function requireOptionalText(value: unknown, label: string, maxLength: number): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  const trimmed = value.trim();
  if (trimmed.length > maxLength) throw new Error(`${label} must be ${maxLength} characters or fewer.`);
  return trimmed;
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 UTC timestamp.`);
  }
  return value;
}
function requireFelt(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,63}$/.test(value)) throw new Error(`${label} must be a lowercase hexadecimal field element.`);
  const parsed = BigInt(value);
  if (parsed >= FIELD_PRIME) throw new Error(`${label} is outside the STARK field.`);
  return parsed;
}

function toHex(value: bigint): string {
  if (value < 0n || value >= FIELD_PRIME) throw new Error("A field element is outside the STARK field.");
  return `0x${value.toString(16)}`;
}

function parseEncodedJson(encoded: string, maxLength: number, label: string): unknown {
  if (typeof encoded !== "string" || !encoded || encoded.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} encoding is invalid.`);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded)));
  } catch {
    throw new Error(`${label} could not be decoded.`);
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url value.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

const ASSET_KEYS = ["symbol", "tokenAddress", "decimals"];
const PRICING_KEYS = ["mode", "discountBps", "aprBps", "platformFeeBaseUnits"];
const LISTING_KEYS = ["kind", "version", "listingId", "network", "poolAddress", "invoiceId", "asset", "faceBaseUnits", "faceDisplay", "dueDate", "offerExpiry", "createdAt", "tenorDays", "merchantRecipient", "debtorLabel", "memo", "listingSalt", "listingCommitment", "notice", "limitations"];
const DIGEST_KEYS = ["kind", "version", "listingId", "network", "poolAddress", "invoiceId", "assetSymbol", "assetDecimals", "dueDate", "offerExpiry", "createdAt", "tenorDays", "debtorLabelHash", "listingCommitment", "notice", "limitations"];
const QUOTE_KEYS = ["kind", "version", "quoteId", "network", "poolAddress", "invoiceId", "listingCommitment", "liquidityProviderRecipient", "pricing", "quoteExpiry", "createdAt", "note", "quoteSalt", "quoteCommitment", "notice", "limitations"];
const AGREEMENT_KEYS = ["kind", "version", "agreementId", "network", "poolAddress", "invoiceId", "asset", "faceBaseUnits", "faceDisplay", "advanceBaseUnits", "advanceDisplay", "repaymentBaseUnits", "repaymentDisplay", "discountBaseUnits", "discountDisplay", "platformFeeBaseUnits", "platformFeeDisplay", "totalCostBaseUnits", "totalCostDisplay", "pricing", "effectiveDiscountBps", "impliedAprBps", "tenorDays", "merchantRecipient", "liquidityProviderRecipient", "dueDate", "advanceDeadline", "createdAt", "listingCommitment", "quoteCommitment", "agreementSalt", "agreementCommitment", "notice", "limitations"];
function hasOnlyKeys(value: object, allowed: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every((key) => allowed.includes(key));
}

function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== FACTORING_LIMITATIONS.length || value.some((entry, index) => entry !== FACTORING_LIMITATIONS[index])) {
    throw new Error("The factoring limitations were altered.");
  }
}

function assertAsset(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ASSET_KEYS)) throw new Error(`${label} is invalid.`);
  const asset = value as FactoringAsset;
  requireSymbol(asset.symbol, `${label} symbol`);
  requireDecimals(asset.decimals, `${label} decimals`);
  if (!asset.tokenAddress || asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) throw new Error(`${label} token address is not canonical.`);
}

function assertPricing(value: unknown): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PRICING_KEYS)) throw new Error("Pricing terms are invalid.");
  const pricing = value as FactorPricing;
  if (pricing.mode !== "flat_discount" && pricing.mode !== "annualized") throw new Error("Pricing mode is invalid.");
  if (!Number.isInteger(pricing.discountBps) || pricing.discountBps < 0 || pricing.discountBps > MAX_DISCOUNT_BPS) throw new Error("The discount rate is out of range.");
  if (!Number.isInteger(pricing.aprBps) || pricing.aprBps < 0 || pricing.aprBps > MAX_APR_BPS) throw new Error("The annualized rate is out of range.");
  requireU128(requireBaseUnitString(pricing.platformFeeBaseUnits, "Platform fee"), "Platform fee");
  if (pricing.mode === "flat_discount" && (pricing.discountBps < 1 || pricing.aprBps !== 0)) throw new Error("A flat-discount quote must set only a discount rate.");
  if (pricing.mode === "annualized" && (pricing.aprBps < 1 || pricing.discountBps !== 0)) throw new Error("An annualized quote must set only an APR.");
}
function assertInvoiceListing(value: unknown): asserts value is InvoiceListing {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, LISTING_KEYS)) throw new Error("Invoice listing is invalid.");
  const listing = value as InvoiceListing;
  if (listing.kind !== LISTING_KIND || listing.version !== FACTORING_ENGINE_VERSION || listing.network !== MAINNET_CHAIN_ID
    || listing.poolAddress !== STRK20_POOL_ADDRESS || listing.notice !== FACTORING_NOTICE
    || !/^list_[A-Za-z0-9_-]{1,48}$/.test(listing.listingId)) throw new Error("Invoice listing header is invalid.");
  assertLimitations(listing.limitations);
  requireText(listing.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  assertAsset(listing.asset, "Invoice asset");
  const face = requireU128(requireBaseUnitString(listing.faceBaseUnits, "Face value"), "Face value");
  if (listing.faceDisplay !== formatBaseUnits(face, listing.asset.decimals)) throw new Error("The listing face display is inconsistent.");
  requireIsoTimestamp(listing.dueDate, "Invoice due date");
  requireIsoTimestamp(listing.offerExpiry, "Offer expiry");
  requireIsoTimestamp(listing.createdAt, "Listing creation time");
  if (listing.tenorDays !== tenorDaysBetween(Date.parse(listing.createdAt), Date.parse(listing.dueDate))) throw new Error("The listing tenor is inconsistent with its dates.");
  if (listing.merchantRecipient !== normalizeStarknetAddress(listing.merchantRecipient)) throw new Error("The merchant recipient is not canonical.");
  if (typeof listing.debtorLabel !== "string" || listing.debtorLabel.length > 96) throw new Error("The debtor label is invalid.");
  if (typeof listing.memo !== "string" || listing.memo.length > 160) throw new Error("The listing memo is invalid.");
  requireFelt(listing.listingSalt, "Listing salt");
  if (requireFelt(listing.listingCommitment, "Listing commitment") !== computeListingCommitment(listing)) throw new Error("The listing commitment does not match its contents.");
}

function assertInvoiceListingDigest(value: unknown): asserts value is InvoiceListingDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, DIGEST_KEYS)) throw new Error("Listing digest is invalid.");
  const digest = value as InvoiceListingDigest;
  if (digest.kind !== LISTING_DIGEST_KIND || digest.version !== FACTORING_ENGINE_VERSION || digest.network !== MAINNET_CHAIN_ID
    || digest.poolAddress !== STRK20_POOL_ADDRESS || digest.notice !== FACTORING_NOTICE
    || !/^list_[A-Za-z0-9_-]{1,48}$/.test(digest.listingId)) throw new Error("Listing digest header is invalid.");
  assertLimitations(digest.limitations);
  requireText(digest.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireSymbol(digest.assetSymbol, "Digest asset symbol");
  requireDecimals(digest.assetDecimals, "Digest asset decimals");
  requireIsoTimestamp(digest.dueDate, "Invoice due date");
  requireIsoTimestamp(digest.offerExpiry, "Offer expiry");
  requireIsoTimestamp(digest.createdAt, "Listing creation time");
  if (!Number.isInteger(digest.tenorDays) || digest.tenorDays < 1 || digest.tenorDays > MAX_TENOR_DAYS) throw new Error("The digest tenor is invalid.");
  requireFelt(digest.debtorLabelHash, "Debtor label hash");
  requireFelt(digest.listingCommitment, "Listing commitment");
}
function assertFactorQuote(value: unknown): asserts value is FactorQuote {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, QUOTE_KEYS)) throw new Error("Factor quote is invalid.");
  const quote = value as FactorQuote;
  if (quote.kind !== QUOTE_KIND || quote.version !== FACTORING_ENGINE_VERSION || quote.network !== MAINNET_CHAIN_ID
    || quote.poolAddress !== STRK20_POOL_ADDRESS || quote.notice !== FACTORING_NOTICE
    || !/^quote_[A-Za-z0-9_-]{1,48}$/.test(quote.quoteId)) throw new Error("Factor quote header is invalid.");
  assertLimitations(quote.limitations);
  requireText(quote.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireFelt(quote.listingCommitment, "Listing commitment");
  if (quote.liquidityProviderRecipient !== normalizeStarknetAddress(quote.liquidityProviderRecipient)) throw new Error("The provider recipient is not canonical.");
  assertPricing(quote.pricing);
  requireIsoTimestamp(quote.quoteExpiry, "Quote expiry");
  requireIsoTimestamp(quote.createdAt, "Quote creation time");
  if (typeof quote.note !== "string" || quote.note.length > 160) throw new Error("The quote note is invalid.");
  requireFelt(quote.quoteSalt, "Quote salt");
  if (requireFelt(quote.quoteCommitment, "Quote commitment") !== computeQuoteCommitment(quote)) throw new Error("The quote commitment does not match its contents.");
}

function assertFactoringAgreement(value: unknown): asserts value is FactoringAgreement {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, AGREEMENT_KEYS)) throw new Error("Factoring agreement is invalid.");
  const agreement = value as FactoringAgreement;
  if (agreement.kind !== AGREEMENT_KIND || agreement.version !== FACTORING_ENGINE_VERSION || agreement.network !== MAINNET_CHAIN_ID
    || agreement.poolAddress !== STRK20_POOL_ADDRESS || agreement.notice !== FACTORING_NOTICE
    || !/^agr_[A-Za-z0-9_-]{1,48}$/.test(agreement.agreementId)) throw new Error("Factoring agreement header is invalid.");
  assertLimitations(agreement.limitations);
  requireText(agreement.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  assertAsset(agreement.asset, "Settlement asset");
  const face = requireU128(requireBaseUnitString(agreement.faceBaseUnits, "Face value"), "Face value");
  const advance = requireU128(requireBaseUnitString(agreement.advanceBaseUnits, "Advance amount"), "Advance amount");
  const repayment = requireU128(requireBaseUnitString(agreement.repaymentBaseUnits, "Repayment amount"), "Repayment amount");
  const discount = requireBaseUnitString(agreement.discountBaseUnits, "Discount amount");
  const platformFee = requireBaseUnitString(agreement.platformFeeBaseUnits, "Platform fee");
  const totalCost = requireBaseUnitString(agreement.totalCostBaseUnits, "Total cost");
  assertPricing(agreement.pricing);
  if (agreement.platformFeeBaseUnits !== agreement.pricing.platformFeeBaseUnits) throw new Error("The agreement fee does not match its pricing.");
  if (!Number.isInteger(agreement.tenorDays) || agreement.tenorDays < 1 || agreement.tenorDays > MAX_TENOR_DAYS) throw new Error("The agreement tenor is invalid.");
  if (agreement.merchantRecipient !== normalizeStarknetAddress(agreement.merchantRecipient)) throw new Error("The merchant recipient is not canonical.");
  if (agreement.liquidityProviderRecipient !== normalizeStarknetAddress(agreement.liquidityProviderRecipient)) throw new Error("The provider recipient is not canonical.");
  requireIsoTimestamp(agreement.dueDate, "Invoice due date");
  requireIsoTimestamp(agreement.advanceDeadline, "Advance deadline");
  requireIsoTimestamp(agreement.createdAt, "Agreement time");
  requireFelt(agreement.listingCommitment, "Listing commitment");
  requireFelt(agreement.quoteCommitment, "Quote commitment");
  requireFelt(agreement.agreementSalt, "Agreement salt");
  const economics = solveFactoring(face, agreement.pricing, agreement.tenorDays);
  if (repayment !== face || discount !== economics.discount || platformFee !== economics.platformFee || totalCost !== economics.totalCost || advance !== economics.advance) {
    throw new Error("The agreement economics do not reconcile.");
  }
  if (agreement.effectiveDiscountBps !== economics.effectiveDiscountBps || agreement.impliedAprBps !== economics.impliedAprBps) throw new Error("The agreement rate metrics do not reconcile.");
  if (agreement.faceDisplay !== formatBaseUnits(face, agreement.asset.decimals)
    || agreement.advanceDisplay !== formatBaseUnits(advance, agreement.asset.decimals)
    || agreement.repaymentDisplay !== formatBaseUnits(repayment, agreement.asset.decimals)
    || agreement.discountDisplay !== formatBaseUnits(discount, agreement.asset.decimals)
    || agreement.platformFeeDisplay !== formatBaseUnits(platformFee, agreement.asset.decimals)
    || agreement.totalCostDisplay !== formatBaseUnits(totalCost, agreement.asset.decimals)) throw new Error("An agreement display value is inconsistent.");
  if (requireFelt(agreement.agreementCommitment, "Agreement commitment") !== computeAgreementCommitment(agreement)) throw new Error("The agreement commitment does not match its contents.");
}

/* ============================================================================================
 * RECEIVABLES COLLATERALIZATION VAULT — zero-knowledge layer
 *
 * The plan layer above hides terms behind salted hashes. This layer proves arithmetic about
 * hidden numbers instead. A merchant commits to an aged receivables schedule and a requested
 * draw with Pedersen commitments `C = v·G + r·H` on the STARK curve, then proves, in zero
 * knowledge, that the committed figures satisfy an underwriter's covenants.
 *
 * WHAT A VAULT CERTIFICATE PROVES (each statement is a checked range proof, not a promise)
 * - Every aging bucket, the eligible collateral, the requested advance, the discount charge and
 *   the largest-debtor exposure are non-negative and inside the declared bit band.
 * - The committed face value is exactly the sum of the four committed aging buckets.
 * - `eligible · 10000 ≤ Σ (10000 − haircutBps[i]) · bucket[i]` — the eligible base respects the
 *   per-bucket haircuts the underwriter set.
 * - `advance · 10000 ≤ eligible · advanceRateBps` — the draw respects the advance rate.
 * - `eligible · 10000 ≥ advance · minCoverageRatioBps` — the coverage covenant holds.
 * - `eligible − advance ≥ holdbackBaseUnits` — the public holdback floor is intact.
 * - `discountCharge = ceil(advance · discountRateBps · tenorDays / (10000 · 365))` — pinned
 *   exactly, both bounds, not merely bounded above.
 * - `advance ≥ discountCharge + platformFeeBaseUnits` — the fee stack does not exceed the draw.
 * - `concentration · 10000 ≤ face · maxConcentrationBps` — single-debtor concentration cap.
 * - `bucket[3] · 10000 ≤ face · maxStaleBps` — the 90+ day bucket stays within its cap.
 * - The whole certificate is Schnorr-signed over a Poseidon binding hash by the issuer's key.
 *
 * WHAT IT DOES NOT PROVE
 * - That any receivable exists, that a debtor is solvent, or that a due date is real. Every
 *   committed figure is typed in by the issuer. A merchant who lies about their book produces a
 *   certificate that is cryptographically valid and factually false.
 * - Nothing is tokenized, pledged, locked, escrowed, or seizable. No collateral changes hands
 *   and no lien is created. The vault is a claim about numbers, not a security interest.
 * - No stablecoin is delivered and no liquidity moves. This module builds no transfer for the
 *   vault layer at all; funding is arranged out of band, or through the plan layer's own
 *   `buildAdvanceActions`, which moves whatever asset the two parties already hold in the pool.
 * - Nothing is decentralized: issuing and verifying both run in one browser. `poolAddress` is
 *   recorded as provenance for the deployment this build targets, and no call is made to it.
 * - It reads no on-chain state and no accounting system. It cannot detect a receivable that was
 *   already factored somewhere else.
 * ============================================================================================ */

export const FACTORING_VAULT_VERSION = 1 as const;
/** Aging buckets, in days outstanding. Fixed: the count is baked into every binding hash. */
export const FACTORING_VAULT_BUCKET_LABELS = ["0-30 days", "31-60 days", "61-90 days", "90+ days"] as const;
export const FACTORING_VAULT_BUCKET_COUNT = FACTORING_VAULT_BUCKET_LABELS.length;
/** Legal band for the hidden base-unit figures. Wider bands cost proving time linearly. */
export const FACTORING_VAULT_MIN_BIT_LENGTH = 8;
export const FACTORING_VAULT_MAX_BIT_LENGTH = 128;
export const FACTORING_VAULT_DEFAULT_BIT_LENGTH = 48;
/**
 * Headroom added to a surplus leg's band. A surplus is a basis-point-weighted difference, so it
 * can carry up to `log2(4 · 100000)` ≈ 19 bits more than the figures it is built from; 18 bits
 * of headroom plus the `<= 128` bit cap on the figures themselves keeps every leg inside the
 * curve order with room to spare (worst case ≈ 2^150 against an order near 2^251).
 */
export const FACTORING_VAULT_SURPLUS_HEADROOM_BITS = 18;
/**
 * Band for the two legs that pin the ceiling division. The remainder is strictly below
 * `10000 · 365 = 3_650_000 < 2^22`, so 24 bits is a canonical, comfortably tight band.
 */
export const FACTORING_VAULT_REMAINDER_BITS = 24;
export const FACTORING_VAULT_MAX_COVERAGE_RATIO_BPS = 100_000;
export const FACTORING_VAULT_MAX_HAIRCUT_BPS = 10_000;

const VAULT_KIND = "cipherbill.factoring-vault-certificate" as const;
const VAULT_SECRET_KIND = "cipherbill.factoring-vault-secret" as const;
const VAULT_DISCLOSURE_KIND = "cipherbill.factoring-vault-disclosure" as const;

const VAULT_DOMAIN = hash.starknetKeccak("CipherBill factoring vault binding v1");
const VAULT_CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill factoring vault context v1");
const VAULT_CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill factoring vault bit challenge v1");
const VAULT_SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill factoring vault signature v1");
const VAULT_REF_DOMAIN = hash.starknetKeccak("CipherBill factoring vault reference v1");
const VAULT_GENERATOR_SEED = hash.starknetKeccak("CipherBill factoring vault second generator v1");

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const CURVE_FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

/** Vault certificates carry ~1000 bit proofs, so they need a much larger envelope than a plan. */
const MAX_VAULT_ENCODED_LENGTH = 4_000_000;

/** Leg identifiers. Folded into every bit challenge so proofs cannot be moved between legs. */
const LEG_BUCKET_BASE = 10;
const LEG_ELIGIBLE = 20;
const LEG_ADVANCE = 21;
const LEG_CHARGE = 22;
const LEG_CONCENTRATION = 23;
const LEG_HOLDBACK_SURPLUS = 30;
const LEG_NET_PROCEEDS = 31;
const LEG_ELIGIBILITY_HEADROOM = 40;
const LEG_ADVANCE_CAP = 41;
const LEG_COVERAGE = 42;
const LEG_CONCENTRATION_CAP = 43;
const LEG_STALE_CAP = 44;
const LEG_CHARGE_REMAINDER = 50;
const LEG_CHARGE_REMAINDER_COMPLEMENT = 51;

const FACTORING_VAULT_NOTICE = "Client-side zero-knowledge collateralization certificate. The range proofs below are real and check out in this browser, and they prove only that the numbers the issuer committed to satisfy the stated covenants. They do not prove that any receivable, debtor, or due date exists, nothing is tokenized or pledged, no collateral is locked or seizable, no stablecoin is delivered, and no Starknet contract sees or verifies this certificate. The pool address is recorded as provenance for this deployment, not as a counterparty.";

const FACTORING_VAULT_LIMITATIONS = [
  "Every hidden figure is typed in by the issuer. A merchant who misstates their receivables book produces a certificate that verifies cryptographically and is false in fact.",
  "Nothing is tokenized, pledged, locked, escrowed, or seizable. No lien or security interest is created, and no collateral changes hands at any point.",
  "No stablecoin is delivered and no liquidity moves. This layer builds no transfer at all; funding is arranged out of band between the two parties.",
  "Nothing is decentralized. Issuing and verifying both run in one browser, there is no registry, no coordinator, and no on-chain verifier for this certificate.",
  "The engine reads no on-chain state and no accounting system. It cannot detect a receivable that has already been pledged or factored elsewhere.",
  "Range proofs bound the hidden figures to the declared bit band only. A figure at the top of the band is indistinguishable from any other figure in the band.",
  "The public covenant parameters, the asset symbol, the bit band, the timestamps, and the number of proofs are all visible in plaintext on the certificate.",
  "Disclosing one committed figure reveals that figure exactly, forever. Selective disclosure is a one-way door, not a revocable grant.",
] as const;

export type FactoringVaultFigure = "face" | "eligible" | "advance" | "discountCharge" | "concentration" | "bucket0" | "bucket1" | "bucket2" | "bucket3";

export interface FactoringVaultPoint {
  x: string;
  y: string;
}

export interface FactoringVaultBitProof {
  commitment: FactoringVaultPoint;
  announcement0: FactoringVaultPoint;
  announcement1: FactoringVaultPoint;
  challenge0: string;
  response0: string;
  response1: string;
}

export interface FactoringVaultSignature {
  challenge: string;
  response: string;
}

export interface FactoringVaultIssuerKey {
  /** Schnorr signing scalar. Sensitive: never place this on a certificate. */
  secretScalar: string;
  publicKey: FactoringVaultPoint;
}

/** Underwriting covenants. Every entry is public and is compared literally at verify time. */
export interface FactoringVaultCovenants {
  haircutBps: number[];
  advanceRateBps: number;
  minCoverageRatioBps: number;
  maxConcentrationBps: number;
  maxStaleBps: number;
  discountRateBps: number;
  tenorDays: number;
  holdbackBaseUnits: string;
  platformFeeBaseUnits: string;
}

export interface IssueFactoringVaultInput {
  vaultId?: string;
  facilityLabel: string;
  merchantAlias: string;
  underwriterAlias: string;
  assetSymbol: string;
  assetDecimals: number;
  amountBitLength?: number;
  /** Aged receivables, in base units, one entry per `FACTORING_VAULT_BUCKET_LABELS` entry. */
  bucketBaseUnits: string[];
  eligibleBaseUnits: string;
  advanceBaseUnits: string;
  /** Largest single-debtor exposure across the whole book, in base units. */
  concentrationBaseUnits: string;
  covenants: FactoringVaultCovenants;
  asOf?: string;
  maturity: string;
  createdAt?: string;
  memo?: string;
  issuerKey: FactoringVaultIssuerKey;
}

export interface FactoringVaultCertificate {
  kind: typeof VAULT_KIND;
  version: typeof FACTORING_VAULT_VERSION;
  vaultId: string;
  network: string;
  poolAddress: string;
  facilityRef: string;
  merchantRef: string;
  underwriterRef: string;
  assetSymbol: string;
  assetDecimals: number;
  amountBitLength: number;
  surplusBitLength: number;
  remainderBitLength: number;
  bucketLabels: string[];
  covenants: FactoringVaultCovenants;
  asOf: string;
  maturity: string;
  createdAt: string;
  memo: string;
  bucketCommitments: FactoringVaultPoint[];
  eligibleCommitment: FactoringVaultPoint;
  advanceCommitment: FactoringVaultPoint;
  discountChargeCommitment: FactoringVaultPoint;
  concentrationCommitment: FactoringVaultPoint;
  /** Second generator, derived by a nothing-up-my-sleeve hash. Recomputed by every verifier. */
  generatorH: FactoringVaultPoint;
  bucketProofs: FactoringVaultBitProof[][];
  eligibleProof: FactoringVaultBitProof[];
  advanceProof: FactoringVaultBitProof[];
  discountChargeProof: FactoringVaultBitProof[];
  concentrationProof: FactoringVaultBitProof[];
  holdbackSurplusProof: FactoringVaultBitProof[];
  netProceedsProof: FactoringVaultBitProof[];
  eligibilityHeadroomProof: FactoringVaultBitProof[];
  advanceCapProof: FactoringVaultBitProof[];
  coverageProof: FactoringVaultBitProof[];
  concentrationCapProof: FactoringVaultBitProof[];
  staleCapProof: FactoringVaultBitProof[];
  chargeRemainderProof: FactoringVaultBitProof[];
  chargeRemainderComplementProof: FactoringVaultBitProof[];
  bindingHash: string;
  issuerPublicKey: FactoringVaultPoint;
  signature: FactoringVaultSignature;
  notice: string;
  limitations: readonly string[];
}

/**
 * Openings for every committed figure. Holding this file is equivalent to knowing the merchant's
 * receivables book: it is a local backup, never something to publish alongside a certificate.
 */
export interface FactoringVaultSecret {
  kind: typeof VAULT_SECRET_KIND;
  version: typeof FACTORING_VAULT_VERSION;
  vaultId: string;
  bindingHash: string;
  buckets: { value: string; blinding: string }[];
  face: { value: string; blinding: string };
  eligible: { value: string; blinding: string };
  advance: { value: string; blinding: string };
  discountCharge: { value: string; blinding: string };
  concentration: { value: string; blinding: string };
}

/** Reveals exactly one committed figure, checkable against the certificate's commitment. */
export interface FactoringVaultDisclosure {
  kind: typeof VAULT_DISCLOSURE_KIND;
  version: typeof FACTORING_VAULT_VERSION;
  vaultId: string;
  bindingHash: string;
  figure: FactoringVaultFigure;
  valueBaseUnits: string;
  valueDisplay: string;
  blinding: string;
}

export interface FactoringVaultCheck {
  label: string;
  detail: string;
  passed: boolean;
}

export interface FactoringVaultAudit {
  ok: boolean;
  checks: FactoringVaultCheck[];
}

export interface FactoringVaultBadge {
  headline: string;
  claim: string;
  facilityRef: string;
  merchantRef: string;
  underwriterRef: string;
  assetSymbol: string;
  band: string;
  covenantSummary: string[];
  proofCount: number;
  maturity: string;
  createdAt: string;
  notice: string;
}

export interface FactoringVaultTrustModel {
  proven: string[];
  hidden: string[];
  visible: string[];
  limitations: readonly string[];
}

export interface FactoringVaultEntropy {
  random?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

/**
 * Number of one-of-two bit proofs a certificate at this band carries. Each costs one Poseidon
 * hash and a handful of curve multiplications, so this is the honest unit of proving cost.
 */
export function estimateFactoringVaultProofCount(amountBitLength: number): number {
  const amount = requireVaultBitLength(amountBitLength);
  const surplus = amount + FACTORING_VAULT_SURPLUS_HEADROOM_BITS;
  // 4 buckets + eligible + advance + charge + concentration + holdback surplus + net proceeds.
  const amountLegs = (FACTORING_VAULT_BUCKET_COUNT + 6) * amount;
  // Eligibility headroom, advance cap, coverage, concentration cap, stale cap.
  const surplusLegs = 5 * surplus;
  const remainderLegs = 2 * FACTORING_VAULT_REMAINDER_BITS;
  return amountLegs + surplusLegs + remainderLegs;
}

/** Draws a fresh Schnorr issuer key. The secret scalar stays in the caller's hands. */
export function generateFactoringVaultIssuerKey(entropy: FactoringVaultEntropy = {}): FactoringVaultIssuerKey {
  const random = entropy.random ?? ((target) => crypto.getRandomValues(target));
  const secret = nonZeroScalar(() => randomScalar(random));
  return { secretScalar: toHex(secret), publicKey: pointToFelts(scalePoint(G, secret)) };
}

/**
 * Builds a vault certificate: commits every figure, proves every covenant, signs the binding
 * hash. Returns the public certificate and the secret openings separately so a caller cannot
 * publish the openings by accident.
 */
export function issueFactoringVaultCertificate(
  input: IssueFactoringVaultInput,
  entropy: FactoringVaultEntropy = {},
): { certificate: FactoringVaultCertificate; secret: FactoringVaultSecret } {
  const random = entropy.random ?? ((target) => crypto.getRandomValues(target));
  const nextScalar = () => nonZeroScalar(() => randomScalar(random));

  const amountBitLength = requireVaultBitLength(input.amountBitLength ?? FACTORING_VAULT_DEFAULT_BIT_LENGTH);
  const surplusBitLength = amountBitLength + FACTORING_VAULT_SURPLUS_HEADROOM_BITS;
  const band = 1n << BigInt(amountBitLength);

  const vaultId = makeId(input.vaultId, "vault");
  const assetSymbol = requireSymbol(input.assetSymbol, "Asset symbol");
  const assetDecimals = requireDecimals(input.assetDecimals, "Asset decimals");
  const facilityLabel = requireText(input.facilityLabel, "Facility label", 96);
  const merchantAlias = requireText(input.merchantAlias, "Merchant alias", 96);
  const underwriterAlias = requireText(input.underwriterAlias, "Underwriter alias", 96);
  const memo = requireOptionalText(input.memo, "Memo", 240);
  const createdAt = requireIsoTimestamp(input.createdAt ?? new Date().toISOString(), "Certificate time");
  const asOf = requireIsoTimestamp(input.asOf ?? createdAt, "Ledger as-of time");
  const maturity = requireIsoTimestamp(input.maturity, "Facility maturity");
  if (Date.parse(maturity) <= Date.parse(createdAt)) throw new Error("The facility maturity must be after the certificate time.");
  if (Date.parse(asOf) > Date.parse(createdAt)) throw new Error("The ledger as-of time cannot be in the certificate's future.");

  const covenants = normalizeVaultCovenants(input.covenants, assetDecimals, amountBitLength);
  const holdback = BigInt(covenants.holdbackBaseUnits);
  const platformFee = BigInt(covenants.platformFeeBaseUnits);

  if (!Array.isArray(input.bucketBaseUnits) || input.bucketBaseUnits.length !== FACTORING_VAULT_BUCKET_COUNT) {
    throw new Error(`Provide exactly ${FACTORING_VAULT_BUCKET_COUNT} aging buckets.`);
  }
  const buckets = input.bucketBaseUnits.map((value, index) => {
    const parsed = requireBaseUnitString(value, `${FACTORING_VAULT_BUCKET_LABELS[index]} bucket`);
    if (parsed >= band) throw new Error(`The ${FACTORING_VAULT_BUCKET_LABELS[index]} bucket exceeds the ${amountBitLength}-bit band.`);
    return parsed;
  });
  const face = buckets.reduce((total, value) => total + value, 0n);
  const eligible = requireBaseUnitString(input.eligibleBaseUnits, "Eligible collateral");
  const advance = requireBaseUnitString(input.advanceBaseUnits, "Requested advance");
  const concentration = requireBaseUnitString(input.concentrationBaseUnits, "Largest debtor exposure");
  if (eligible >= band) throw new Error(`The eligible collateral exceeds the ${amountBitLength}-bit band.`);
  if (advance >= band) throw new Error(`The requested advance exceeds the ${amountBitLength}-bit band.`);
  if (concentration >= band) throw new Error(`The largest debtor exposure exceeds the ${amountBitLength}-bit band.`);

  // Every covenant is checked in the clear first, so a merchant gets a plain-language failure
  // instead of a range-proof exception from deep inside the prover.
  const weights = covenants.haircutBps.map((haircut) => FEE_BPS_DENOMINATOR - BigInt(haircut));
  const weightedBase = buckets.reduce((total, value, index) => total + weights[index] * value, 0n);
  const eligibilityHeadroom = weightedBase - FEE_BPS_DENOMINATOR * eligible;
  if (eligibilityHeadroom < 0n) throw new Error("The eligible collateral exceeds what the aging buckets support after haircuts.");
  const advanceHeadroom = BigInt(covenants.advanceRateBps) * eligible - FEE_BPS_DENOMINATOR * advance;
  if (advanceHeadroom < 0n) throw new Error("The requested advance exceeds the advance rate against eligible collateral.");
  const coverageSurplus = FEE_BPS_DENOMINATOR * eligible - BigInt(covenants.minCoverageRatioBps) * advance;
  if (coverageSurplus < 0n) throw new Error("The requested advance breaches the minimum coverage ratio.");
  const holdbackSurplus = eligible - advance - holdback;
  if (holdbackSurplus < 0n) throw new Error("The requested advance would eat into the holdback reserve.");

  const chargeMultiplier = BigInt(covenants.discountRateBps) * BigInt(covenants.tenorDays);
  const chargeDenominator = FEE_BPS_DENOMINATOR * DAY_COUNT_BASIS;
  const discountCharge = divideCeil(advance * chargeMultiplier, chargeDenominator);
  if (discountCharge >= band) throw new Error(`The discount charge exceeds the ${amountBitLength}-bit band.`);
  const chargeRemainder = discountCharge * chargeDenominator - advance * chargeMultiplier;
  const chargeRemainderComplement = chargeDenominator - 1n - chargeRemainder;
  const netProceeds = advance - discountCharge - platformFee;
  if (netProceeds < 0n) throw new Error("The discount charge and platform fee exceed the requested advance.");

  const concentrationSurplus = BigInt(covenants.maxConcentrationBps) * face - FEE_BPS_DENOMINATOR * concentration;
  if (concentrationSurplus < 0n) throw new Error("The largest debtor exposure breaches the concentration cap.");
  const staleSurplus = BigInt(covenants.maxStaleBps) * face - FEE_BPS_DENOMINATOR * buckets[FACTORING_VAULT_BUCKET_COUNT - 1];
  if (staleSurplus < 0n) throw new Error("The 90+ day bucket breaches the stale-receivables cap.");
  if (concentration > face) throw new Error("The largest debtor exposure cannot exceed the total receivables book.");

  const h = deriveVaultGenerator();
  const bucketBlindings = buckets.map(() => nextScalar());
  // Forced: the face blinding is the bucket sum, so `C_face` is literally `Σ C_bucket`. That
  // point equality is what proves the schedule adds up to the face value.
  const faceBlinding = mod(bucketBlindings.reduce((total, value) => total + value, 0n), CURVE_ORDER);
  const eligibleBlinding = nextScalar();
  const advanceBlinding = nextScalar();
  const chargeBlinding = nextScalar();
  const concentrationBlinding = nextScalar();

  const bucketCommitments = buckets.map((value, index) => pedersenCommit(value, bucketBlindings[index], h));
  const eligibleCommitment = pedersenCommit(eligible, eligibleBlinding, h);
  const advanceCommitment = pedersenCommit(advance, advanceBlinding, h);
  const chargeCommitment = pedersenCommit(discountCharge, chargeBlinding, h);
  const concentrationCommitment = pedersenCommit(concentration, concentrationBlinding, h);

  const header = {
    vaultId,
    facilityRef: toHex(commitVaultRef(facilityLabel, nextScalar())),
    merchantRef: toHex(commitVaultRef(merchantAlias, nextScalar())),
    underwriterRef: toHex(commitVaultRef(underwriterAlias, nextScalar())),
    assetSymbol,
    assetDecimals,
    amountBitLength,
    surplusBitLength,
    asOf,
    maturity,
    createdAt,
    memo,
    covenants,
  };
  const bindingHash = computeVaultBindingHash({
    ...header,
    bucketCommitments,
    eligibleCommitment,
    advanceCommitment,
    chargeCommitment,
    concentrationCommitment,
    generatorH: h,
    issuerPublicKey: pointFromFelts(input.issuerKey.publicKey),
  });
  const ctx = vaultStatementContext(bindingHash);

  const bucketProofs = buckets.map((value, index) =>
    proveRange(value, bucketBlindings[index], amountBitLength, ctx, LEG_BUCKET_BASE + index, h, nextScalar));
  const eligibleProof = proveRange(eligible, eligibleBlinding, amountBitLength, ctx, LEG_ELIGIBLE, h, nextScalar);
  const advanceProof = proveRange(advance, advanceBlinding, amountBitLength, ctx, LEG_ADVANCE, h, nextScalar);
  const discountChargeProof = proveRange(discountCharge, chargeBlinding, amountBitLength, ctx, LEG_CHARGE, h, nextScalar);
  const concentrationProof = proveRange(concentration, concentrationBlinding, amountBitLength, ctx, LEG_CONCENTRATION, h, nextScalar);

  // Surplus legs. Each blinding is forced to the same linear combination as its value, so the
  // recomputed bit sum lands exactly on the homomorphic target the verifier builds from the
  // published commitments. A prover who picks any other blinding cannot make the leg close.
  const holdbackSurplusProof = proveRange(holdbackSurplus, mod(eligibleBlinding - advanceBlinding, CURVE_ORDER),
    amountBitLength, ctx, LEG_HOLDBACK_SURPLUS, h, nextScalar);
  const netProceedsProof = proveRange(netProceeds, mod(advanceBlinding - chargeBlinding, CURVE_ORDER),
    amountBitLength, ctx, LEG_NET_PROCEEDS, h, nextScalar);
  const headroomBlinding = mod(
    bucketBlindings.reduce((total, blinding, index) => total + weights[index] * blinding, 0n) - FEE_BPS_DENOMINATOR * eligibleBlinding,
    CURVE_ORDER,
  );
  const eligibilityHeadroomProof = proveRange(eligibilityHeadroom, headroomBlinding, surplusBitLength, ctx, LEG_ELIGIBILITY_HEADROOM, h, nextScalar);
  const advanceCapProof = proveRange(advanceHeadroom,
    mod(BigInt(covenants.advanceRateBps) * eligibleBlinding - FEE_BPS_DENOMINATOR * advanceBlinding, CURVE_ORDER),
    surplusBitLength, ctx, LEG_ADVANCE_CAP, h, nextScalar);
  const coverageProof = proveRange(coverageSurplus,
    mod(FEE_BPS_DENOMINATOR * eligibleBlinding - BigInt(covenants.minCoverageRatioBps) * advanceBlinding, CURVE_ORDER),
    surplusBitLength, ctx, LEG_COVERAGE, h, nextScalar);
  const concentrationCapProof = proveRange(concentrationSurplus,
    mod(BigInt(covenants.maxConcentrationBps) * faceBlinding - FEE_BPS_DENOMINATOR * concentrationBlinding, CURVE_ORDER),
    surplusBitLength, ctx, LEG_CONCENTRATION_CAP, h, nextScalar);
  const staleCapProof = proveRange(staleSurplus,
    mod(BigInt(covenants.maxStaleBps) * faceBlinding - FEE_BPS_DENOMINATOR * bucketBlindings[FACTORING_VAULT_BUCKET_COUNT - 1], CURVE_ORDER),
    surplusBitLength, ctx, LEG_STALE_CAP, h, nextScalar);

  // The two legs that pin the ceiling division exactly: `0 <= charge·D − advance·k <= D − 1`.
  const remainderBlinding = mod(chargeBlinding * chargeDenominator - advanceBlinding * chargeMultiplier, CURVE_ORDER);
  const chargeRemainderProof = proveRange(chargeRemainder, remainderBlinding,
    FACTORING_VAULT_REMAINDER_BITS, ctx, LEG_CHARGE_REMAINDER, h, nextScalar);
  const chargeRemainderComplementProof = proveRange(chargeRemainderComplement, mod(-remainderBlinding, CURVE_ORDER),
    FACTORING_VAULT_REMAINDER_BITS, ctx, LEG_CHARGE_REMAINDER_COMPLEMENT, h, nextScalar);

  const signature = signVaultBinding(bindingHash, requireScalar(input.issuerKey.secretScalar, "Issuer secret scalar", false), nextScalar);

  const certificate: FactoringVaultCertificate = {
    kind: VAULT_KIND,
    version: FACTORING_VAULT_VERSION,
    vaultId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    facilityRef: header.facilityRef,
    merchantRef: header.merchantRef,
    underwriterRef: header.underwriterRef,
    assetSymbol,
    assetDecimals,
    amountBitLength,
    surplusBitLength,
    remainderBitLength: FACTORING_VAULT_REMAINDER_BITS,
    bucketLabels: [...FACTORING_VAULT_BUCKET_LABELS],
    covenants,
    asOf,
    maturity,
    createdAt,
    memo,
    bucketCommitments: bucketCommitments.map(pointToFelts),
    eligibleCommitment: pointToFelts(eligibleCommitment),
    advanceCommitment: pointToFelts(advanceCommitment),
    discountChargeCommitment: pointToFelts(chargeCommitment),
    concentrationCommitment: pointToFelts(concentrationCommitment),
    generatorH: pointToFelts(h),
    bucketProofs,
    eligibleProof,
    advanceProof,
    discountChargeProof,
    concentrationProof,
    holdbackSurplusProof,
    netProceedsProof,
    eligibilityHeadroomProof,
    advanceCapProof,
    coverageProof,
    concentrationCapProof,
    staleCapProof,
    chargeRemainderProof,
    chargeRemainderComplementProof,
    bindingHash: toHex(bindingHash),
    issuerPublicKey: pointToFelts(pointFromFelts(input.issuerKey.publicKey)),
    signature,
    notice: FACTORING_VAULT_NOTICE,
    limitations: FACTORING_VAULT_LIMITATIONS,
  };

  const secret: FactoringVaultSecret = {
    kind: VAULT_SECRET_KIND,
    version: FACTORING_VAULT_VERSION,
    vaultId,
    bindingHash: toHex(bindingHash),
    buckets: buckets.map((value, index) => ({ value: value.toString(), blinding: toHex(bucketBlindings[index]) })),
    face: { value: face.toString(), blinding: toHex(faceBlinding) },
    eligible: { value: eligible.toString(), blinding: toHex(eligibleBlinding) },
    advance: { value: advance.toString(), blinding: toHex(advanceBlinding) },
    discountCharge: { value: discountCharge.toString(), blinding: toHex(chargeBlinding) },
    concentration: { value: concentration.toString(), blinding: toHex(concentrationBlinding) },
  };

  return { certificate, secret };
}

/**
 * Re-derives the second generator, recomputes the binding hash, checks the issuer signature, then
 * replays every range proof and every homomorphic tie-back. Returns false on any failure, never
 * throws, so a portal can feed it untrusted paste-in without a try/catch around the call site.
 */
export function verifyFactoringVaultCertificate(certificate: FactoringVaultCertificate): boolean {
  try {
    return auditFactoringVaultCertificate(certificate).ok;
  } catch {
    return false;
  }
}
/** Row-by-row verification, for a UI that shows which covenant failed rather than a bare false. */
export function auditFactoringVaultCertificate(certificate: FactoringVaultCertificate): FactoringVaultAudit {
  const checks: FactoringVaultCheck[] = [];
  const push = (label: string, detail: string, passed: boolean) => {
    checks.push({ label, detail, passed });
    return passed;
  };
  try {
    assertFactoringVaultCertificate(certificate);
  } catch (error) {
    return { ok: false, checks: [{ label: "Certificate structure", detail: error instanceof Error ? error.message : "The certificate is malformed.", passed: false }] };
  }
  push("Certificate structure", `Header, covenants, and ${estimateFactoringVaultProofCount(certificate.amountBitLength)} bit proofs are well formed and inside their declared bands.`, true);

  const h = deriveVaultGenerator();
  if (!push("Second generator", "Recomputed by nothing-up-my-sleeve hash and matched against the certificate.", pointToFelts(h).x === certificate.generatorH.x && pointToFelts(h).y === certificate.generatorH.y)) {
    return { ok: false, checks };
  }

  const bucketCommitments = certificate.bucketCommitments.map(pointFromFelts);
  const eligibleCommitment = pointFromFelts(certificate.eligibleCommitment);
  const advanceCommitment = pointFromFelts(certificate.advanceCommitment);
  const chargeCommitment = pointFromFelts(certificate.discountChargeCommitment);
  const concentrationCommitment = pointFromFelts(certificate.concentrationCommitment);
  const issuerPublicKey = pointFromFelts(certificate.issuerPublicKey);
  // Face value is not committed separately: it is the sum of the bucket commitments, so the
  // schedule and the face value cannot disagree. There is no second number to reconcile.
  const faceCommitment = bucketCommitments.reduce<CurvePoint>((total, point) => total.add(point), ZERO);

  const expectedBinding = computeVaultBindingHash({
    vaultId: certificate.vaultId,
    facilityRef: certificate.facilityRef,
    merchantRef: certificate.merchantRef,
    underwriterRef: certificate.underwriterRef,
    assetSymbol: certificate.assetSymbol,
    assetDecimals: certificate.assetDecimals,
    amountBitLength: certificate.amountBitLength,
    surplusBitLength: certificate.surplusBitLength,
    asOf: certificate.asOf,
    maturity: certificate.maturity,
    createdAt: certificate.createdAt,
    memo: certificate.memo,
    covenants: certificate.covenants,
    bucketCommitments,
    eligibleCommitment,
    advanceCommitment,
    chargeCommitment,
    concentrationCommitment,
    generatorH: h,
    issuerPublicKey,
  });
  if (!push("Binding hash", "Every public field and every commitment rehashes to the published binding hash.", toHex(expectedBinding) === certificate.bindingHash)) {
    return { ok: false, checks };
  }
  if (!push("Issuer signature", "Schnorr signature over the binding hash verifies against the issuer's public key.", verifyVaultSignature(expectedBinding, certificate.signature, issuerPublicKey))) {
    return { ok: false, checks };
  }

  const ctx = vaultStatementContext(expectedBinding);
  const amountBits = certificate.amountBitLength;
  const surplusBits = certificate.surplusBitLength;
  const E = FEE_BPS_DENOMINATOR;

  const bucketSums = certificate.bucketProofs.map((proofs, index) => verifyRange(proofs, amountBits, ctx, LEG_BUCKET_BASE + index, h));
  const bucketsClosed = bucketSums.every((sum, index) => sum !== null && sum.equals(bucketCommitments[index]));
  if (!push("Aging buckets in band", `All ${FACTORING_VAULT_BUCKET_COUNT} bucket commitments open to values in [0, 2^${amountBits}).`, bucketsClosed)) {
    return { ok: false, checks };
  }
  push("Face value binding", `Face value is the sum of the ${FACTORING_VAULT_BUCKET_COUNT} bucket commitments by construction, bounded by ${FACTORING_VAULT_BUCKET_COUNT}·2^${amountBits}.`, true);

  const eligibleSum = verifyRange(certificate.eligibleProof, amountBits, ctx, LEG_ELIGIBLE, h);
  if (!push("Eligible collateral in band", `The eligible collateral commitment opens to a value in [0, 2^${amountBits}).`, eligibleSum !== null && eligibleSum.equals(eligibleCommitment))) {
    return { ok: false, checks };
  }
  const advanceSum = verifyRange(certificate.advanceProof, amountBits, ctx, LEG_ADVANCE, h);
  if (!push("Requested advance in band", `The advance commitment opens to a value in [0, 2^${amountBits}).`, advanceSum !== null && advanceSum.equals(advanceCommitment))) {
    return { ok: false, checks };
  }
  const chargeSum = verifyRange(certificate.discountChargeProof, amountBits, ctx, LEG_CHARGE, h);
  if (!push("Discount charge in band", `The discount charge commitment opens to a value in [0, 2^${amountBits}).`, chargeSum !== null && chargeSum.equals(chargeCommitment))) {
    return { ok: false, checks };
  }
  const concentrationSum = verifyRange(certificate.concentrationProof, amountBits, ctx, LEG_CONCENTRATION, h);
  if (!push("Debtor concentration in band", `The largest-debtor commitment opens to a value in [0, 2^${amountBits}).`, concentrationSum !== null && concentrationSum.equals(concentrationCommitment))) {
    return { ok: false, checks };
  }

  const weights = certificate.covenants.haircutBps.map((haircut) => E - BigInt(haircut));
  const headroomTarget = bucketCommitments
    .reduce<CurvePoint>((total, point, index) => total.add(scalePoint(point, weights[index])), ZERO)
    .add(scalePoint(eligibleCommitment, E).negate());
  const headroomSum = verifyRange(certificate.eligibilityHeadroomProof, surplusBits, ctx, LEG_ELIGIBILITY_HEADROOM, h);
  if (!push("Haircut eligibility headroom", "eligible · 10000 ≤ Σ (10000 − haircut[i]) · bucket[i], proved as a non-negative surplus.", headroomSum !== null && headroomSum.equals(headroomTarget))) {
    return { ok: false, checks };
  }

  const advanceCapTarget = scalePoint(eligibleCommitment, BigInt(certificate.covenants.advanceRateBps)).add(scalePoint(advanceCommitment, E).negate());
  const advanceCapSum = verifyRange(certificate.advanceCapProof, surplusBits, ctx, LEG_ADVANCE_CAP, h);
  if (!push("Advance rate cap", `advance · 10000 ≤ eligible · ${certificate.covenants.advanceRateBps}, proved as a non-negative surplus.`, advanceCapSum !== null && advanceCapSum.equals(advanceCapTarget))) {
    return { ok: false, checks };
  }

  const coverageTarget = scalePoint(eligibleCommitment, E).add(scalePoint(advanceCommitment, BigInt(certificate.covenants.minCoverageRatioBps)).negate());
  const coverageSum = verifyRange(certificate.coverageProof, surplusBits, ctx, LEG_COVERAGE, h);
  if (!push("Minimum coverage ratio", `eligible · 10000 ≥ advance · ${certificate.covenants.minCoverageRatioBps}, proved as a non-negative surplus.`, coverageSum !== null && coverageSum.equals(coverageTarget))) {
    return { ok: false, checks };
  }
  const holdback = BigInt(certificate.covenants.holdbackBaseUnits);
  const holdbackTarget = eligibleCommitment.add(advanceCommitment.negate()).add(scalePoint(G, holdback).negate());
  const holdbackSum = verifyRange(certificate.holdbackSurplusProof, amountBits, ctx, LEG_HOLDBACK_SURPLUS, h);
  if (!push("Holdback floor", `eligible − advance ≥ ${certificate.covenants.holdbackBaseUnits} base units, proved as a non-negative surplus.`, holdbackSum !== null && holdbackSum.equals(holdbackTarget))) {
    return { ok: false, checks };
  }

  const platformFee = BigInt(certificate.covenants.platformFeeBaseUnits);
  const netTarget = advanceCommitment.add(chargeCommitment.negate()).add(scalePoint(G, platformFee).negate());
  const netSum = verifyRange(certificate.netProceedsProof, amountBits, ctx, LEG_NET_PROCEEDS, h);
  if (!push("Net proceeds solvency", `advance − discount charge − ${certificate.covenants.platformFeeBaseUnits} base units of fee is non-negative.`, netSum !== null && netSum.equals(netTarget))) {
    return { ok: false, checks };
  }

  const concentrationCapTarget = scalePoint(faceCommitment, BigInt(certificate.covenants.maxConcentrationBps)).add(scalePoint(concentrationCommitment, E).negate());
  const concentrationCapSum = verifyRange(certificate.concentrationCapProof, surplusBits, ctx, LEG_CONCENTRATION_CAP, h);
  if (!push("Concentration cap", `largest debtor · 10000 ≤ face · ${certificate.covenants.maxConcentrationBps}, proved against the summed bucket commitments.`, concentrationCapSum !== null && concentrationCapSum.equals(concentrationCapTarget))) {
    return { ok: false, checks };
  }

  const staleCapTarget = scalePoint(faceCommitment, BigInt(certificate.covenants.maxStaleBps))
    .add(scalePoint(bucketCommitments[FACTORING_VAULT_BUCKET_COUNT - 1], E).negate());
  const staleCapSum = verifyRange(certificate.staleCapProof, surplusBits, ctx, LEG_STALE_CAP, h);
  if (!push("Stale receivables cap", `90+ day bucket · 10000 ≤ face · ${certificate.covenants.maxStaleBps}, proved as a non-negative surplus.`, staleCapSum !== null && staleCapSum.equals(staleCapTarget))) {
    return { ok: false, checks };
  }

  // Exact ceiling division. Leg one shows `charge·D − advance·k >= 0`; leg two shows the same
  // quantity is at most `D − 1`. Together they pin `charge = ceil(advance·k / D)` — a single
  // lower bound would let an issuer overstate the charge without limit.
  const chargeMultiplier = BigInt(certificate.covenants.discountRateBps) * BigInt(certificate.covenants.tenorDays);
  const chargeDenominator = E * DAY_COUNT_BASIS;
  const remainderTarget = scalePoint(chargeCommitment, chargeDenominator).add(scalePoint(advanceCommitment, chargeMultiplier).negate());
  const remainderSum = verifyRange(certificate.chargeRemainderProof, certificate.remainderBitLength, ctx, LEG_CHARGE_REMAINDER, h);
  const complementTarget = scalePoint(G, chargeDenominator - 1n).add(remainderTarget.negate());
  const complementSum = verifyRange(certificate.chargeRemainderComplementProof, certificate.remainderBitLength, ctx, LEG_CHARGE_REMAINDER_COMPLEMENT, h);
  const pinned = remainderSum !== null && remainderSum.equals(remainderTarget) && complementSum !== null && complementSum.equals(complementTarget);
  if (!push("Discount charge pinned", `discount charge = ceil(advance · ${certificate.covenants.discountRateBps} · ${certificate.covenants.tenorDays} / 3650000), both bounds proved.`, pinned)) {
    return { ok: false, checks };
  }

  return { ok: checks.every((check) => check.passed), checks };
}

/** Reveals one committed figure. Irreversible: the recipient learns the exact number. */
export function discloseFactoringVaultFigure(
  certificate: FactoringVaultCertificate,
  secret: FactoringVaultSecret,
  figure: FactoringVaultFigure,
): FactoringVaultDisclosure {
  assertFactoringVaultCertificate(certificate);
  assertFactoringVaultSecret(secret);
  if (secret.vaultId !== certificate.vaultId || secret.bindingHash !== certificate.bindingHash) {
    throw new Error("The openings belong to a different vault certificate.");
  }
  const opening = vaultOpeningFor(secret, figure);
  return {
    kind: VAULT_DISCLOSURE_KIND,
    version: FACTORING_VAULT_VERSION,
    vaultId: certificate.vaultId,
    bindingHash: certificate.bindingHash,
    figure,
    valueBaseUnits: opening.value,
    valueDisplay: formatBaseUnits(BigInt(opening.value), certificate.assetDecimals),
    blinding: opening.blinding,
  };
}

/**
 * Checks a disclosed figure against the certificate. Rejects a value outside its canonical band:
 * a Pedersen opening is only unique modulo the curve order, so without an explicit bound a holder
 * could re-open the same commitment at `value + k·n` and quote any number they liked.
 */
export function verifyFactoringVaultDisclosure(
  certificate: FactoringVaultCertificate,
  disclosure: FactoringVaultDisclosure,
): boolean {
  try {
    assertFactoringVaultCertificate(certificate);
    assertFactoringVaultDisclosure(disclosure);
    if (disclosure.vaultId !== certificate.vaultId || disclosure.bindingHash !== certificate.bindingHash) return false;
    const value = BigInt(disclosure.valueBaseUnits);
    const band = 1n << BigInt(certificate.amountBitLength);
    const limit = disclosure.figure === "face" ? BigInt(FACTORING_VAULT_BUCKET_COUNT) * band : band;
    if (value < 0n || value >= limit) return false;
    if (disclosure.valueDisplay !== formatBaseUnits(value, certificate.assetDecimals)) return false;
    const blinding = requireScalar(disclosure.blinding, "Disclosed blinding", true);
    const h = deriveVaultGenerator();
    const target = vaultCommitmentFor(certificate, disclosure.figure);
    return pedersenCommit(value, blinding, h).equals(target);
  } catch {
    return false;
  }
}

/** Display-ready summary. Every string here is derived from the certificate, nothing is asserted. */
export function buildFactoringVaultBadge(certificate: FactoringVaultCertificate): FactoringVaultBadge {
  assertFactoringVaultCertificate(certificate);
  const covenants = certificate.covenants;
  return {
    headline: `Receivables facility ${certificate.vaultId}`,
    claim: `Advance drawn under a ${covenants.advanceRateBps / 100}% advance rate with ${covenants.minCoverageRatioBps / 100}% minimum coverage, all figures hidden.`,
    facilityRef: certificate.facilityRef,
    merchantRef: certificate.merchantRef,
    underwriterRef: certificate.underwriterRef,
    assetSymbol: certificate.assetSymbol,
    band: `[0, 2^${certificate.amountBitLength}) base units`,
    covenantSummary: [
      `Haircuts ${covenants.haircutBps.map((bps) => `${bps / 100}%`).join(" / ")} across ${certificate.bucketLabels.join(", ")}`,
      `Advance rate ${covenants.advanceRateBps / 100}% of eligible collateral`,
      `Minimum coverage ${covenants.minCoverageRatioBps / 100}%`,
      `Concentration cap ${covenants.maxConcentrationBps / 100}% of face, stale cap ${covenants.maxStaleBps / 100}%`,
      `Discount ${covenants.discountRateBps / 100}% per annum over ${covenants.tenorDays} days, 365-day basis`,
      `Holdback ${formatBaseUnits(BigInt(covenants.holdbackBaseUnits), certificate.assetDecimals)} ${certificate.assetSymbol}, platform fee ${formatBaseUnits(BigInt(covenants.platformFeeBaseUnits), certificate.assetDecimals)} ${certificate.assetSymbol}`,
    ],
    proofCount: estimateFactoringVaultProofCount(certificate.amountBitLength),
    maturity: certificate.maturity,
    createdAt: certificate.createdAt,
    notice: certificate.notice,
  };
}

/** The full trust boundary, for the portal to render verbatim. */
export function getFactoringVaultTrustModel(): FactoringVaultTrustModel {
  return {
    proven: [
      "Each aging bucket, the eligible collateral, the advance, the discount charge, and the largest debtor exposure are non-negative and inside the declared bit band.",
      "The face value is exactly the sum of the four aging buckets — there is no independent face commitment that could disagree.",
      "The eligible collateral respects every per-bucket haircut, and the advance respects both the advance rate and the minimum coverage ratio.",
      "The holdback floor survives the draw, and the discount charge plus the platform fee never exceed the advance.",
      "The discount charge equals ceil(advance · rate · tenor / (10000 · 365)) exactly, upper bound included.",
      "Single-debtor concentration and the 90+ day bucket both sit inside their caps, measured against the same committed face value.",
      "The whole certificate is Schnorr-signed over a Poseidon binding hash that covers every public field and every commitment.",
    ],
    hidden: [
      "Every figure above: bucket balances, face value, eligible collateral, the advance, the discount charge, net proceeds, and the largest debtor exposure.",
      "Client identities and invoice-level detail. The facility, merchant, and underwriter labels appear only as salted Poseidon references.",
    ],
    visible: [
      "All covenant parameters: haircuts, advance rate, coverage ratio, concentration and stale caps, discount rate, tenor, holdback, and platform fee.",
      "The asset symbol and decimals, the bit band, the proof count, the as-of and maturity timestamps, and the memo.",
      "The issuer's public key and signature, and the commitment points themselves.",
    ],
    limitations: FACTORING_VAULT_LIMITATIONS,
  };
}

export function serializeFactoringVaultCertificate(certificate: FactoringVaultCertificate): string {
  assertFactoringVaultCertificate(certificate);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(certificate)));
}

export function parseFactoringVaultCertificate(encoded: string): FactoringVaultCertificate {
  const value = parseEncodedJson(encoded, MAX_VAULT_ENCODED_LENGTH, "Vault certificate");
  assertFactoringVaultCertificate(value);
  return value;
}

/** Sensitive. This encodes every hidden figure in the clear; treat it like the ledger itself. */
export function serializeFactoringVaultSecret(secret: FactoringVaultSecret): string {
  assertFactoringVaultSecret(secret);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(secret)));
}

export function parseFactoringVaultSecret(encoded: string): FactoringVaultSecret {
  const value = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Vault openings");
  assertFactoringVaultSecret(value);
  return value;
}

export function serializeFactoringVaultDisclosure(disclosure: FactoringVaultDisclosure): string {
  assertFactoringVaultDisclosure(disclosure);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(disclosure)));
}

export function parseFactoringVaultDisclosure(encoded: string): FactoringVaultDisclosure {
  const value = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Vault disclosure");
  assertFactoringVaultDisclosure(value);
  return value;
}

/* ---------------------------------- vault internals ---------------------------------------- */

let cachedVaultGenerator: CurvePoint | null = null;

/**
 * Second Pedersen generator. Derived by hashing a fixed domain string to a curve point, so nobody
 * — including whoever wrote this file — knows a discrete log relating it to `G`. That is what makes
 * the commitments binding: knowing `log_G(H)` would let an issuer re-open any commitment.
 */
function deriveVaultGenerator(): CurvePoint {
  if (!cachedVaultGenerator) cachedVaultGenerator = hashToVaultPoint(VAULT_GENERATOR_SEED);
  return cachedVaultGenerator;
}

function hashToVaultPoint(seed: bigint): CurvePoint {
  for (let counter = 0n; counter < 1000n; counter += 1n) {
    const x = hashElements([seed, counter]);
    const rhs = CURVE_FIELD.add(CURVE_FIELD.add(CURVE_FIELD.mul(CURVE_FIELD.mul(x, x), x), CURVE_FIELD.mul(CURVE_A, x)), CURVE_B);
    let y: bigint;
    try {
      y = CURVE_FIELD.sqrt(rhs);
    } catch {
      continue;
    }
    const even = y % 2n === 0n ? y : FIELD_PRIME - y;
    try {
      const point = ec.starkCurve.ProjectivePoint.fromAffine({ x, y: even });
      point.assertValidity();
      if (point.equals(G) || point.equals(ZERO)) continue;
      return point;
    } catch {
      continue;
    }
  }
  throw new Error("Failed to derive an independent factoring vault generator.");
}

function scalePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const reduced = mod(scalar, CURVE_ORDER);
  return reduced === 0n ? ZERO : point.multiply(reduced);
}

function pedersenCommit(value: bigint, blinding: bigint, h: CurvePoint): CurvePoint {
  return scalePoint(G, value).add(scalePoint(h, blinding));
}

function pointToFelts(point: CurvePoint): FactoringVaultPoint {
  const affine = point.toAffine();
  return { x: toHex(affine.x), y: toHex(affine.y) };
}

function pointFromFelts(point: FactoringVaultPoint): CurvePoint {
  const x = requireFelt(point.x, "Commitment x coordinate");
  const y = requireFelt(point.y, "Commitment y coordinate");
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x, y });
  parsed.assertValidity();
  return parsed;
}

function mod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder < 0n ? remainder + modulus : remainder;
}

/** Extended Euclid. Throws rather than returning a wrong inverse for a non-invertible input. */
function modInverse(value: bigint, modulus: bigint): bigint {
  let [old, current] = [mod(value, modulus), modulus];
  let [oldCoefficient, coefficient] = [1n, 0n];
  while (current !== 0n) {
    const quotient = old / current;
    [old, current] = [current, old - quotient * current];
    [oldCoefficient, coefficient] = [coefficient, oldCoefficient - quotient * coefficient];
  }
  if (old !== 1n) throw new Error("A vault scalar was not invertible modulo the curve order.");
  return mod(oldCoefficient, modulus);
}
function randomScalar(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  const bytes = random(new Uint8Array(32));
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error("The entropy source returned the wrong number of bytes.");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return mod(value, CURVE_ORDER);
}

function nonZeroScalar(draw: () => bigint): bigint {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const value = draw();
    if (value !== 0n) return value;
  }
  throw new Error("Could not draw a usable vault scalar.");
}

function requireScalar(value: unknown, label: string, allowZero: boolean): bigint {
  const parsed = requireFelt(value, label);
  if (parsed >= CURVE_ORDER) throw new Error(`${label} is outside the curve order.`);
  if (!allowZero && parsed === 0n) throw new Error(`${label} cannot be zero.`);
  return parsed;
}

function requireVaultBitLength(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < FACTORING_VAULT_MIN_BIT_LENGTH || value > FACTORING_VAULT_MAX_BIT_LENGTH) {
    throw new Error(`The amount bit length must be a whole number between ${FACTORING_VAULT_MIN_BIT_LENGTH} and ${FACTORING_VAULT_MAX_BIT_LENGTH}.`);
  }
  return value;
}

function requireBps(value: unknown, label: string, maximum: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} must be a whole number of basis points between 0 and ${maximum}.`);
  }
  return value;
}

/** Salted Poseidon reference to a plaintext label, so the label never leaves the browser. */
function commitVaultRef(value: string, salt: bigint): bigint {
  return hashElements([VAULT_REF_DOMAIN, hash.starknetKeccak(value), mod(salt, FIELD_PRIME)]);
}

function vaultStatementContext(bindingHash: bigint): bigint {
  return hashElements([VAULT_CONTEXT_DOMAIN, bindingHash]);
}

function vaultBitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  const c = commitment.toAffine();
  const p0 = a0.toAffine();
  const p1 = a1.toAffine();
  return mod(hashElements([VAULT_CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), c.x, c.y, p0.x, p0.y, p1.x, p1.y]), CURVE_ORDER);
}
/**
 * One bit, proved as a Schnorr one-of-two: either the commitment opens to 0 or, after subtracting
 * `G`, it opens to 0. The false branch is simulated from a freely chosen challenge, so the pair of
 * transcripts reveals which branch is real to nobody.
 */
function proveVaultBit(
  bit: number,
  commitment: CurvePoint,
  blinding: bigint,
  ctx: bigint,
  leg: number,
  index: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): FactoringVaultBitProof {
  const p0 = commitment;
  const p1 = commitment.add(G.negate());
  let announcement0: CurvePoint;
  let announcement1: CurvePoint;
  let challenge0: bigint;
  let response0: bigint;
  let response1: bigint;

  if (bit === 0) {
    const k0 = nextScalar();
    announcement0 = scalePoint(h, k0);
    const simulatedChallenge = nextScalar();
    const simulatedResponse = nextScalar();
    announcement1 = scalePoint(h, simulatedResponse).add(scalePoint(p1, simulatedChallenge).negate());
    const e = vaultBitChallenge(ctx, leg, index, commitment, announcement0, announcement1);
    challenge0 = mod(e - simulatedChallenge, CURVE_ORDER);
    response0 = mod(k0 + challenge0 * blinding, CURVE_ORDER);
    response1 = simulatedResponse;
  } else {
    const k1 = nextScalar();
    announcement1 = scalePoint(h, k1);
    challenge0 = nextScalar();
    response0 = nextScalar();
    announcement0 = scalePoint(h, response0).add(scalePoint(p0, challenge0).negate());
    const e = vaultBitChallenge(ctx, leg, index, commitment, announcement0, announcement1);
    const challenge1 = mod(e - challenge0, CURVE_ORDER);
    response1 = mod(k1 + challenge1 * blinding, CURVE_ORDER);
  }

  return {
    commitment: pointToFelts(commitment),
    announcement0: pointToFelts(announcement0),
    announcement1: pointToFelts(announcement1),
    challenge0: toHex(challenge0),
    response0: toHex(response0),
    response1: toHex(response1),
  };
}
function verifyVaultBit(proof: FactoringVaultBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
  let commitment: CurvePoint;
  let announcement0: CurvePoint;
  let announcement1: CurvePoint;
  let challenge0: bigint;
  let response0: bigint;
  let response1: bigint;
  try {
    commitment = pointFromFelts(proof.commitment);
    announcement0 = pointFromFelts(proof.announcement0);
    announcement1 = pointFromFelts(proof.announcement1);
    challenge0 = requireScalar(proof.challenge0, "Bit challenge", true);
    response0 = requireScalar(proof.response0, "Bit response", true);
    response1 = requireScalar(proof.response1, "Bit response", true);
  } catch {
    return null;
  }
  const e = vaultBitChallenge(ctx, leg, index, commitment, announcement0, announcement1);
  const challenge1 = mod(e - challenge0, CURVE_ORDER);
  const ok0 = scalePoint(h, response0).equals(announcement0.add(scalePoint(commitment, challenge0)));
  const ok1 = scalePoint(h, response1).equals(announcement1.add(scalePoint(commitment.add(G.negate()), challenge1)));
  return ok0 && ok1 ? commitment : null;
}

/**
 * Bit-decomposition range proof. The top bit's blinding is forced so that `Σ 2^i·r_i` lands on the
 * caller's blinding exactly; that is what lets the verifier fold the per-bit commitments back into
 * a homomorphic target it built from the published commitments.
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): FactoringVaultBitProof[] {
  if (value < 0n) throw new Error("Cannot range-prove a negative value.");
  if (value >= 1n << BigInt(bitLength)) throw new Error(`A vault figure exceeds its ${bitLength}-bit band.`);
  const blindings: bigint[] = [];
  let partial = 0n;
  for (let index = 0; index < bitLength - 1; index += 1) {
    const r = nextScalar();
    blindings.push(r);
    partial = mod(partial + (1n << BigInt(index)) * r, CURVE_ORDER);
  }
  const topWeight = modInverse(1n << BigInt(bitLength - 1), CURVE_ORDER);
  const lastBlinding = mod((blinding - partial) * topWeight, CURVE_ORDER);
  if (lastBlinding === 0n) throw new Error("Degenerate range-proof blinding; retry with fresh entropy.");
  blindings.push(lastBlinding);
  const proofs: FactoringVaultBitProof[] = [];
  for (let index = 0; index < bitLength; index += 1) {
    const bit = Number((value >> BigInt(index)) & 1n);
    const commitment = pedersenCommit(BigInt(bit), blindings[index], h);
    proofs.push(proveVaultBit(bit, commitment, blindings[index], ctx, leg, index, h, nextScalar));
  }
  return proofs;
}

function verifyRange(proofs: FactoringVaultBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return null;
  let accumulator: CurvePoint = ZERO;
  for (let index = 0; index < bitLength; index += 1) {
    const commitment = verifyVaultBit(proofs[index], ctx, leg, index, h);
    if (!commitment) return null;
    accumulator = accumulator.add(scalePoint(commitment, 1n << BigInt(index)));
  }
  return accumulator;
}

function signVaultBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): FactoringVaultSignature {
  const nonce = nextScalar();
  const commitment = scalePoint(G, nonce);
  const affine = commitment.toAffine();
  const challenge = mod(hashElements([VAULT_SIGNATURE_DOMAIN, affine.x, affine.y, bindingHash]), CURVE_ORDER);
  const response = mod(nonce + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

function verifyVaultSignature(bindingHash: bigint, signature: FactoringVaultSignature, publicKey: CurvePoint): boolean {
  let challenge: bigint;
  let response: bigint;
  try {
    challenge = requireScalar(signature.challenge, "Signature challenge", true);
    response = requireScalar(signature.response, "Signature response", true);
  } catch {
    return false;
  }
  const commitment = scalePoint(G, response).add(scalePoint(publicKey, challenge).negate());
  // The identity has no usable affine coordinates and would let a forger fix the challenge input.
  if (commitment.equals(ZERO)) return false;
  const affine = commitment.toAffine();
  return mod(hashElements([VAULT_SIGNATURE_DOMAIN, affine.x, affine.y, bindingHash]), CURVE_ORDER) === challenge;
}

interface VaultBindingFields {
  vaultId: string;
  facilityRef: string;
  merchantRef: string;
  underwriterRef: string;
  assetSymbol: string;
  assetDecimals: number;
  amountBitLength: number;
  surplusBitLength: number;
  asOf: string;
  maturity: string;
  createdAt: string;
  memo: string;
  covenants: FactoringVaultCovenants;
  bucketCommitments: CurvePoint[];
  eligibleCommitment: CurvePoint;
  advanceCommitment: CurvePoint;
  chargeCommitment: CurvePoint;
  concentrationCommitment: CurvePoint;
  generatorH: CurvePoint;
  issuerPublicKey: CurvePoint;
}

/**
 * Poseidon hash over every public field and every commitment. Domain constants such as the kind,
 * the version, the chain id, and the pool address are folded in from the module rather than the
 * certificate, so a verifier must also compare those literally — see `assertFactoringVault*`.
 */
function computeVaultBindingHash(fields: VaultBindingFields): bigint {
  const points = [
    ...fields.bucketCommitments,
    fields.eligibleCommitment,
    fields.advanceCommitment,
    fields.chargeCommitment,
    fields.concentrationCommitment,
    fields.generatorH,
    fields.issuerPublicKey,
  ];
  const coordinates: bigint[] = [];
  for (const point of points) {
    const affine = point.toAffine();
    coordinates.push(affine.x, affine.y);
  }
  return hashElements([
    VAULT_DOMAIN,
    BigInt(FACTORING_VAULT_VERSION),
    hash.starknetKeccak(VAULT_KIND),
    hash.starknetKeccak(MAINNET_CHAIN_ID),
    BigInt(STRK20_POOL_ADDRESS),
    hash.starknetKeccak(fields.vaultId),
    requireFelt(fields.facilityRef, "Facility reference"),
    requireFelt(fields.merchantRef, "Merchant reference"),
    requireFelt(fields.underwriterRef, "Underwriter reference"),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.assetDecimals),
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    BigInt(FACTORING_VAULT_REMAINDER_BITS),
    BigInt(FACTORING_VAULT_BUCKET_COUNT),
    hash.starknetKeccak(FACTORING_VAULT_BUCKET_LABELS.join("|")),
    ...fields.covenants.haircutBps.map((bps) => BigInt(bps)),
    BigInt(fields.covenants.advanceRateBps),
    BigInt(fields.covenants.minCoverageRatioBps),
    BigInt(fields.covenants.maxConcentrationBps),
    BigInt(fields.covenants.maxStaleBps),
    BigInt(fields.covenants.discountRateBps),
    BigInt(fields.covenants.tenorDays),
    BigInt(fields.covenants.holdbackBaseUnits),
    BigInt(fields.covenants.platformFeeBaseUnits),
    secondsOf(fields.asOf),
    secondsOf(fields.maturity),
    secondsOf(fields.createdAt),
    // Hashed verbatim with a separate presence flag. Substituting a placeholder for an empty memo
    // would let "" and that placeholder collide, so an empty-memo certificate could be relabelled
    // without breaking this hash.
    fields.memo ? 1n : 0n,
    hash.starknetKeccak(fields.memo),
    hash.starknetKeccak(FACTORING_VAULT_NOTICE),
    hash.starknetKeccak(FACTORING_VAULT_LIMITATIONS.join("|")),
    ...coordinates,
  ]);
}

function normalizeVaultCovenants(value: unknown, assetDecimals: number, amountBitLength: number): FactoringVaultCovenants {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("The underwriting covenants are invalid.");
  const covenants = value as FactoringVaultCovenants;
  if (!Array.isArray(covenants.haircutBps) || covenants.haircutBps.length !== FACTORING_VAULT_BUCKET_COUNT) {
    throw new Error(`Provide exactly ${FACTORING_VAULT_BUCKET_COUNT} haircut rates.`);
  }
  const haircutBps = covenants.haircutBps.map((bps, index) => requireBps(bps, `${FACTORING_VAULT_BUCKET_LABELS[index]} haircut`, FACTORING_VAULT_MAX_HAIRCUT_BPS));
  const advanceRateBps = requireBps(covenants.advanceRateBps, "Advance rate", Number(FEE_BPS_DENOMINATOR));
  const minCoverageRatioBps = requireBps(covenants.minCoverageRatioBps, "Minimum coverage ratio", FACTORING_VAULT_MAX_COVERAGE_RATIO_BPS);
  if (minCoverageRatioBps < Number(FEE_BPS_DENOMINATOR)) throw new Error("The minimum coverage ratio cannot be below 100%.");
  const maxConcentrationBps = requireBps(covenants.maxConcentrationBps, "Concentration cap", Number(FEE_BPS_DENOMINATOR));
  const maxStaleBps = requireBps(covenants.maxStaleBps, "Stale receivables cap", Number(FEE_BPS_DENOMINATOR));
  const discountRateBps = requireBps(covenants.discountRateBps, "Discount rate", MAX_APR_BPS);
  if (!Number.isInteger(covenants.tenorDays) || covenants.tenorDays < 1 || covenants.tenorDays > MAX_TENOR_DAYS) {
    throw new Error(`The facility tenor must be between 1 and ${MAX_TENOR_DAYS} days.`);
  }
  // Canonical bounds. Both of these reach the verifier as `scalar·G` inside a homomorphic leg, so
  // an unbounded value could be shifted by a multiple of FIELD_PRIME·CURVE_ORDER: congruent under
  // the Poseidon field and under the curve order at once, leaving the binding hash, the signature,
  // and the leg all intact while the certificate advertises an arbitrary number.
  const band = 1n << BigInt(amountBitLength);
  const holdback = requireBaseUnitString(covenants.holdbackBaseUnits, "Holdback reserve");
  if (holdback >= band) throw new Error(`The holdback reserve exceeds the ${amountBitLength}-bit band.`);
  const platformFee = requireBaseUnitString(covenants.platformFeeBaseUnits, "Platform fee");
  if (platformFee >= band) throw new Error(`The platform fee exceeds the ${amountBitLength}-bit band.`);
  requireDecimals(assetDecimals, "Asset decimals");
  return {
    haircutBps,
    advanceRateBps,
    minCoverageRatioBps,
    maxConcentrationBps,
    maxStaleBps,
    discountRateBps,
    tenorDays: covenants.tenorDays,
    holdbackBaseUnits: holdback.toString(),
    platformFeeBaseUnits: platformFee.toString(),
  };
}

function vaultOpeningFor(secret: FactoringVaultSecret, figure: FactoringVaultFigure): { value: string; blinding: string } {
  switch (figure) {
    case "face": return secret.face;
    case "eligible": return secret.eligible;
    case "advance": return secret.advance;
    case "discountCharge": return secret.discountCharge;
    case "concentration": return secret.concentration;
    case "bucket0": return secret.buckets[0];
    case "bucket1": return secret.buckets[1];
    case "bucket2": return secret.buckets[2];
    case "bucket3": return secret.buckets[3];
    default: throw new Error("That figure is not part of the vault certificate.");
  }
}

function vaultCommitmentFor(certificate: FactoringVaultCertificate, figure: FactoringVaultFigure): CurvePoint {
  switch (figure) {
    case "face":
      return certificate.bucketCommitments.reduce<CurvePoint>((total, point) => total.add(pointFromFelts(point)), ZERO);
    case "eligible": return pointFromFelts(certificate.eligibleCommitment);
    case "advance": return pointFromFelts(certificate.advanceCommitment);
    case "discountCharge": return pointFromFelts(certificate.discountChargeCommitment);
    case "concentration": return pointFromFelts(certificate.concentrationCommitment);
    case "bucket0": return pointFromFelts(certificate.bucketCommitments[0]);
    case "bucket1": return pointFromFelts(certificate.bucketCommitments[1]);
    case "bucket2": return pointFromFelts(certificate.bucketCommitments[2]);
    case "bucket3": return pointFromFelts(certificate.bucketCommitments[3]);
    default: throw new Error("That figure is not part of the vault certificate.");
  }
}

const VAULT_POINT_KEYS = ["x", "y"];
const VAULT_BIT_PROOF_KEYS = ["commitment", "announcement0", "announcement1", "challenge0", "response0", "response1"];
const VAULT_SIGNATURE_KEYS = ["challenge", "response"];
const VAULT_OPENING_KEYS = ["value", "blinding"];
const VAULT_COVENANT_KEYS = ["haircutBps", "advanceRateBps", "minCoverageRatioBps", "maxConcentrationBps", "maxStaleBps", "discountRateBps", "tenorDays", "holdbackBaseUnits", "platformFeeBaseUnits"];
const VAULT_CERTIFICATE_KEYS = ["kind", "version", "vaultId", "network", "poolAddress", "facilityRef", "merchantRef", "underwriterRef", "assetSymbol", "assetDecimals", "amountBitLength", "surplusBitLength", "remainderBitLength", "bucketLabels", "covenants", "asOf", "maturity", "createdAt", "memo", "bucketCommitments", "eligibleCommitment", "advanceCommitment", "discountChargeCommitment", "concentrationCommitment", "generatorH", "bucketProofs", "eligibleProof", "advanceProof", "discountChargeProof", "concentrationProof", "holdbackSurplusProof", "netProceedsProof", "eligibilityHeadroomProof", "advanceCapProof", "coverageProof", "concentrationCapProof", "staleCapProof", "chargeRemainderProof", "chargeRemainderComplementProof", "bindingHash", "issuerPublicKey", "signature", "notice", "limitations"];
const VAULT_SECRET_KEYS = ["kind", "version", "vaultId", "bindingHash", "buckets", "face", "eligible", "advance", "discountCharge", "concentration"];
const VAULT_DISCLOSURE_KEYS = ["kind", "version", "vaultId", "bindingHash", "figure", "valueBaseUnits", "valueDisplay", "blinding"];
const VAULT_FIGURES: FactoringVaultFigure[] = ["face", "eligible", "advance", "discountCharge", "concentration", "bucket0", "bucket1", "bucket2", "bucket3"];
function assertVaultPoint(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, VAULT_POINT_KEYS)) throw new Error(`${label} is not a curve point.`);
  const point = value as FactoringVaultPoint;
  requireFelt(point.x, `${label} x coordinate`);
  requireFelt(point.y, `${label} y coordinate`);
}

function assertVaultBitProofs(value: unknown, expectedLength: number, label: string): void {
  if (!Array.isArray(value) || value.length !== expectedLength) throw new Error(`${label} must carry exactly ${expectedLength} bit proofs.`);
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || !hasOnlyKeys(entry, VAULT_BIT_PROOF_KEYS)) throw new Error(`${label} contains a malformed bit proof.`);
    const proof = entry as FactoringVaultBitProof;
    assertVaultPoint(proof.commitment, `${label} bit commitment`);
    assertVaultPoint(proof.announcement0, `${label} first announcement`);
    assertVaultPoint(proof.announcement1, `${label} second announcement`);
    requireScalar(proof.challenge0, `${label} bit challenge`, true);
    requireScalar(proof.response0, `${label} first response`, true);
    requireScalar(proof.response1, `${label} second response`, true);
  }
}

function assertVaultLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== FACTORING_VAULT_LIMITATIONS.length
    || value.some((entry, index) => entry !== FACTORING_VAULT_LIMITATIONS[index])) {
    throw new Error("The vault limitations were altered.");
  }
}

function assertFactoringVaultCertificate(value: unknown): asserts value is FactoringVaultCertificate {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, VAULT_CERTIFICATE_KEYS)) throw new Error("Vault certificate is invalid.");
  const certificate = value as FactoringVaultCertificate;
  // Header constants are compared literally against the module, not read from the certificate: the
  // binding hash folds in the module's copies, so a rewritten header would otherwise pass unnoticed.
  if (certificate.kind !== VAULT_KIND || certificate.version !== FACTORING_VAULT_VERSION
    || certificate.network !== MAINNET_CHAIN_ID || certificate.poolAddress !== STRK20_POOL_ADDRESS
    || certificate.notice !== FACTORING_VAULT_NOTICE
    || !/^vault_[A-Za-z0-9_-]{1,48}$/.test(certificate.vaultId)) throw new Error("Vault certificate header is invalid.");
  assertVaultLimitations(certificate.limitations);
  if (!Array.isArray(certificate.bucketLabels) || certificate.bucketLabels.length !== FACTORING_VAULT_BUCKET_COUNT
    || certificate.bucketLabels.some((label, index) => label !== FACTORING_VAULT_BUCKET_LABELS[index])) {
    throw new Error("The vault aging buckets were altered.");
  }
  requireFelt(certificate.facilityRef, "Facility reference");
  requireFelt(certificate.merchantRef, "Merchant reference");
  requireFelt(certificate.underwriterRef, "Underwriter reference");
  requireSymbol(certificate.assetSymbol, "Asset symbol");
  // Re-validated here and not merely trusted: the decimals drive every display string a reader
  // sees, so an out-of-range value would let a certificate render a misleading magnitude.
  const assetDecimals = requireDecimals(certificate.assetDecimals, "Asset decimals");
  const amountBitLength = requireVaultBitLength(certificate.amountBitLength);
  if (certificate.surplusBitLength !== amountBitLength + FACTORING_VAULT_SURPLUS_HEADROOM_BITS) throw new Error("The surplus band does not match the amount band.");
  if (certificate.remainderBitLength !== FACTORING_VAULT_REMAINDER_BITS) throw new Error("The remainder band was altered.");
  if (!certificate.covenants || typeof certificate.covenants !== "object" || Array.isArray(certificate.covenants)
    || !hasOnlyKeys(certificate.covenants, VAULT_COVENANT_KEYS)) throw new Error("The vault covenants are invalid.");
  const covenants = normalizeVaultCovenants(certificate.covenants, assetDecimals, amountBitLength);
  const declared = certificate.covenants;
  const covenantsMatch = covenants.haircutBps.every((bps, index) => bps === declared.haircutBps[index])
    && covenants.advanceRateBps === declared.advanceRateBps
    && covenants.minCoverageRatioBps === declared.minCoverageRatioBps
    && covenants.maxConcentrationBps === declared.maxConcentrationBps
    && covenants.maxStaleBps === declared.maxStaleBps
    && covenants.discountRateBps === declared.discountRateBps
    && covenants.tenorDays === declared.tenorDays
    // String comparison, not bigint: a leading zero or a `+` would survive a numeric check and
    // change the bytes the binding hash was computed over.
    && covenants.holdbackBaseUnits === declared.holdbackBaseUnits
    && covenants.platformFeeBaseUnits === declared.platformFeeBaseUnits;
  if (!covenantsMatch) throw new Error("The vault covenants are not in canonical form.");
  requireIsoTimestamp(certificate.asOf, "Ledger as-of time");
  requireIsoTimestamp(certificate.maturity, "Facility maturity");
  requireIsoTimestamp(certificate.createdAt, "Certificate time");
  if (Date.parse(certificate.maturity) <= Date.parse(certificate.createdAt)) throw new Error("The facility maturity must be after the certificate time.");
  if (Date.parse(certificate.asOf) > Date.parse(certificate.createdAt)) throw new Error("The ledger as-of time cannot be in the certificate's future.");
  requireOptionalText(certificate.memo, "Memo", 240);

  if (!Array.isArray(certificate.bucketCommitments) || certificate.bucketCommitments.length !== FACTORING_VAULT_BUCKET_COUNT) {
    throw new Error(`The certificate must carry exactly ${FACTORING_VAULT_BUCKET_COUNT} bucket commitments.`);
  }
  certificate.bucketCommitments.forEach((point, index) => assertVaultPoint(point, `${FACTORING_VAULT_BUCKET_LABELS[index]} commitment`));
  assertVaultPoint(certificate.eligibleCommitment, "Eligible collateral commitment");
  assertVaultPoint(certificate.advanceCommitment, "Advance commitment");
  assertVaultPoint(certificate.discountChargeCommitment, "Discount charge commitment");
  assertVaultPoint(certificate.concentrationCommitment, "Concentration commitment");
  assertVaultPoint(certificate.generatorH, "Second generator");
  assertVaultPoint(certificate.issuerPublicKey, "Issuer public key");

  if (!Array.isArray(certificate.bucketProofs) || certificate.bucketProofs.length !== FACTORING_VAULT_BUCKET_COUNT) {
    throw new Error(`The certificate must carry exactly ${FACTORING_VAULT_BUCKET_COUNT} bucket range proofs.`);
  }
  certificate.bucketProofs.forEach((proofs, index) => assertVaultBitProofs(proofs, amountBitLength, `${FACTORING_VAULT_BUCKET_LABELS[index]} range proof`));
  assertVaultBitProofs(certificate.eligibleProof, amountBitLength, "Eligible collateral range proof");
  assertVaultBitProofs(certificate.advanceProof, amountBitLength, "Advance range proof");
  assertVaultBitProofs(certificate.discountChargeProof, amountBitLength, "Discount charge range proof");
  assertVaultBitProofs(certificate.concentrationProof, amountBitLength, "Concentration range proof");
  assertVaultBitProofs(certificate.holdbackSurplusProof, amountBitLength, "Holdback surplus proof");
  assertVaultBitProofs(certificate.netProceedsProof, amountBitLength, "Net proceeds proof");
  assertVaultBitProofs(certificate.eligibilityHeadroomProof, certificate.surplusBitLength, "Eligibility headroom proof");
  assertVaultBitProofs(certificate.advanceCapProof, certificate.surplusBitLength, "Advance cap proof");
  assertVaultBitProofs(certificate.coverageProof, certificate.surplusBitLength, "Coverage proof");
  assertVaultBitProofs(certificate.concentrationCapProof, certificate.surplusBitLength, "Concentration cap proof");
  assertVaultBitProofs(certificate.staleCapProof, certificate.surplusBitLength, "Stale receivables cap proof");
  assertVaultBitProofs(certificate.chargeRemainderProof, FACTORING_VAULT_REMAINDER_BITS, "Discount remainder proof");
  assertVaultBitProofs(certificate.chargeRemainderComplementProof, FACTORING_VAULT_REMAINDER_BITS, "Discount remainder complement proof");

  requireFelt(certificate.bindingHash, "Binding hash");
  if (!certificate.signature || typeof certificate.signature !== "object" || Array.isArray(certificate.signature)
    || !hasOnlyKeys(certificate.signature, VAULT_SIGNATURE_KEYS)) throw new Error("The issuer signature is malformed.");
  requireScalar(certificate.signature.challenge, "Signature challenge", true);
  requireScalar(certificate.signature.response, "Signature response", true);
}

function assertVaultOpening(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, VAULT_OPENING_KEYS)) throw new Error(`${label} opening is invalid.`);
  const opening = value as { value: string; blinding: string };
  requireBaseUnitString(opening.value, `${label} value`);
  requireScalar(opening.blinding, `${label} blinding`, true);
}
function assertFactoringVaultSecret(value: unknown): asserts value is FactoringVaultSecret {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, VAULT_SECRET_KEYS)) throw new Error("Vault openings are invalid.");
  const secret = value as FactoringVaultSecret;
  if (secret.kind !== VAULT_SECRET_KIND || secret.version !== FACTORING_VAULT_VERSION
    || !/^vault_[A-Za-z0-9_-]{1,48}$/.test(secret.vaultId)) throw new Error("Vault openings header is invalid.");
  requireFelt(secret.bindingHash, "Binding hash");
  if (!Array.isArray(secret.buckets) || secret.buckets.length !== FACTORING_VAULT_BUCKET_COUNT) {
    throw new Error(`Vault openings must cover exactly ${FACTORING_VAULT_BUCKET_COUNT} buckets.`);
  }
  secret.buckets.forEach((opening, index) => assertVaultOpening(opening, FACTORING_VAULT_BUCKET_LABELS[index]));
  assertVaultOpening(secret.face, "Face value");
  assertVaultOpening(secret.eligible, "Eligible collateral");
  assertVaultOpening(secret.advance, "Advance");
  assertVaultOpening(secret.discountCharge, "Discount charge");
  assertVaultOpening(secret.concentration, "Concentration");
}

function assertFactoringVaultDisclosure(value: unknown): asserts value is FactoringVaultDisclosure {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, VAULT_DISCLOSURE_KEYS)) throw new Error("Vault disclosure is invalid.");
  const disclosure = value as FactoringVaultDisclosure;
  if (disclosure.kind !== VAULT_DISCLOSURE_KIND || disclosure.version !== FACTORING_VAULT_VERSION
    || !/^vault_[A-Za-z0-9_-]{1,48}$/.test(disclosure.vaultId)) throw new Error("Vault disclosure header is invalid.");
  requireFelt(disclosure.bindingHash, "Binding hash");
  if (!VAULT_FIGURES.includes(disclosure.figure)) throw new Error("That figure is not part of the vault certificate.");
  requireBaseUnitString(disclosure.valueBaseUnits, "Disclosed value");
  requireText(disclosure.valueDisplay, "Disclosed display value", 80);
  requireScalar(disclosure.blinding, "Disclosed blinding", true);
}
