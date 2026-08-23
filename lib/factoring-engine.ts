/**
 * Invoice factoring and liquidity-matching engine for CipherBill.
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
 * - Not zero-knowledge, and it proves nothing about an invoice. CipherBill generates no proof
 *   of any kind: the wallet proves the settlement transfer and the pool verifies it onchain,
 *   and `wallet_strk20InvokeTransaction` returns only `{ transaction_hash }`. The commitments
 *   below are salted Poseidon hashes. They bind and hide the terms, but they do not attest that
 *   an invoice, a debtor, or a due date is real. Legitimacy here is a legal and commercial fact,
 *   not a mathematical one.
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
