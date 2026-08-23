/**
 * Multi-currency invoice denomination and FX conversion planner for CipherBill.
 *
 * WHAT THIS IS
 * - A client-side FX quote: a merchant denominates an invoice in a display currency (a fiat peg such as
 *   USD/EUR, or an alternative token) and this engine converts it, with exact integer math, into a
 *   settlement amount for one or more candidate pool tokens ("rails"). Each rail carries its own quoted
 *   rate, a ceiling-rounded settlement amount (never underpay), and a slippage band from a tolerance.
 * - A single-token settlement builder: for a chosen rail it composes one private in-pool STRK20 `transfer`
 *   of that rail's settlement amount from the customer to the merchant, which the customer's wallet signs.
 *   There is no swap: the customer settles directly in the chosen token at the quoted rate.
 * - A salted Poseidon commitment scheme: the merchant commits to the full quote (denomination, every rail's
 *   token, rate and amount, the slippage band) and publishes a digest carrying no amounts, rates,
 *   addresses, pricing tiers, payer, or memo, then discloses the quote to the customer to verify against it.
 * - Disclosable settlement receipts binding the quote commitment, the chosen rail, an observed settlement
 *   amount, whether it fell inside the slippage band, a claimed settlement time, and the transaction hash.
 * - An optional Schnorr zero-knowledge proof of knowledge — the "rate authorization" — by which a rate
 *   authority proves knowledge of a private key bound to a quote and rail without revealing it. This is the
 *   ONLY zero-knowledge element here; it attests a rate was authorized, it does not price or pay.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not decentralized. The denomination, rates, conversions, and slippage band are local computations in
 *   one browser. There is no on-chain oracle, AMM, price feed, or FX contract; `STRK20_POOL_ADDRESS` is
 *   recorded as provenance for the settlement leg, not a contract that quotes or converts anything.
 * - Not an on-chain swap or DEX. CipherBill performs no token conversion, routing, or liquidity provision.
 *   The "conversion" is arithmetic on a rate the merchant or a rate authority supplies; the customer pays
 *   the quoted amount directly in the chosen pool token. Nothing bridges or swaps one asset for another.
 * - Not an oracle, and it does not validate that a rate is fair or live. The rate is an input, quoted by
 *   whoever runs the desk. The engine checks its arithmetic and commits it; it cannot vouch for the price.
 * - Not zero-knowledge as a system, and it hides no trade amount from the public. In-pool transfers hide
 *   amounts, but that is the pool's property, not this module's. The quote commitment and receipts are
 *   salted Poseidon hashes, not zero-knowledge proofs; only the optional rate authorization is a
 *   zero-knowledge proof, and it proves knowledge of a key, never a price or a payment.
 * - Not anonymous end to end. A distinctive settlement amount, a rate tied to a known invoice, or a deposit
 *   or withdrawal edge stays public, and timing, fees, and nullifiers are observable.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";
export const FX_ENGINE_VERSION = 1 as const;
export const FX_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const FX_RATE_PROOF_SYSTEM = "stark-schnorr-fx-rate-v1" as const;
export const MAX_ASSET_DECIMALS = 18;
export const MAX_RATE_DECIMALS = 18;
export const MIN_RAILS = 1;
export const MAX_RAILS = 8;
export const MIN_SLIPPAGE_BPS = 0;
export const MAX_SLIPPAGE_BPS = 5_000; // 50%, the widest band the composer offers
export const BPS_DENOMINATOR = 10_000;
export const FX_SALT_BYTES = 31;
export const DEFAULT_QUOTE_TTL_MINUTES = 15;
export const MAX_QUOTE_TTL_MINUTES = 43_200; // 30 days
export const MINUTE_MS = 60_000;

export const FX_NOTICE =
  "Client-side multi-currency FX quote and single-token settlement plan. A merchant denominates an invoice " +
  "in a display currency, and this browser converts it with exact integer math into a settlement amount for " +
  "one or more pool tokens using a quoted rate. There is no oracle, swap, or price feed; the customer settles " +
  "by voluntarily signing one private in-pool transfer in the token they choose. The quote commitment and " +
  "receipts are salted Poseidon hashes rather than proofs, and only the optional rate authorization is a " +
  "zero-knowledge proof.";

export const FX_LIMITATIONS: readonly string[] = [
  "Nothing here is decentralized. The denomination, rates, conversions, and slippage band are local " +
    "computations in one browser; no oracle, AMM, or FX contract quotes or converts anything.",
  "There is no swap. CipherBill converts a rate into an amount and the customer pays that amount directly in " +
    "the chosen pool token; no asset is exchanged for another on-chain.",
  "The rate is an input, not a fact. It is quoted by the merchant or a rate authority; the engine validates " +
    "its arithmetic and commits it, but cannot vouch that the price is fair or current.",
  "The quote commitment, digest, and receipts are salted Poseidon hashes, not zero-knowledge proofs, and no " +
    "contract verifies them. Only the optional rate authorization is a zero-knowledge proof, and it proves " +
    "knowledge of a key, not a price or a payment.",
  "A settlement receipt records a claimed settlement and whether the observed amount fell inside the slippage " +
    "band; a self-issued receipt is internally consistent but is not independent proof the transfer settled. " +
    "Confirm the transaction hash on-chain.",
  "In-pool transfers hide the settlement's sender, recipient, token, and amount, but a distinctive amount or a " +
    "rate tied to a known invoice is a correlation signal, and timing, fees, nullifiers, and any deposit or " +
    "withdrawal edge stay public.",
];

const QUOTE_KIND = "cipherbill.fx-quote";
const QUOTE_DIGEST_KIND = "cipherbill.fx-quote-digest";
const RECEIPT_KIND = "cipherbill.fx-settlement-receipt";
const RATE_AUTH_KIND = "cipherbill.fx-rate-authorization";
const QUOTE_DOMAIN = BigInt(hash.starknetKeccak("CipherBill fx quote v1"));
const RAIL_DOMAIN = BigInt(hash.starknetKeccak("CipherBill fx rail v1"));
const RECEIPT_DOMAIN = BigInt(hash.starknetKeccak("CipherBill fx settlement receipt v1"));
const RATE_DOMAIN = BigInt(hash.starknetKeccak("CipherBill fx rate authorization v1"));

const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const BASE = ec.starkCurve.ProjectivePoint.BASE;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 200_000;

const QUOTE_KEYS = [
  "kind", "version", "quoteId", "network", "poolAddress", "invoiceId", "merchant", "denomination", "rails",
  "slippageBps", "payerLabel", "memo", "quotedAt", "expiresAt", "quoteSalt", "quoteCommitment", "notice",
  "limitations",
] as const;
const DENOMINATION_KEYS = ["currency", "decimals", "amountDisplay", "amountMinorUnits"] as const;
const RAIL_KEYS = [
  "symbol", "tokenAddress", "decimals", "rate", "rateScaled", "rateDecimals", "rateSource",
  "settlementBaseUnits", "settlementDisplay", "minBaseUnits", "maxBaseUnits",
] as const;
const DIGEST_KEYS = [
  "kind", "version", "quoteId", "network", "poolAddress", "invoiceId", "denominationCurrency",
  "denominationDecimals", "railCount", "railsHash", "slippageBps", "hasPayer", "quotedAt", "expiresAt",
  "memoHash", "quoteCommitment", "notice", "limitations",
] as const;
const RECEIPT_KEYS = [
  "kind", "version", "quoteId", "network", "poolAddress", "invoiceId", "railSymbol", "railTokenAddress",
  "quotedBaseUnits", "settledBaseUnits", "withinBand", "minBaseUnits", "maxBaseUnits", "settledAt",
  "transactionHash", "quoteCommitment", "receiptCommitment", "notice", "limitations",
] as const;
const RATE_AUTH_KEYS = [
  "kind", "version", "proofSystem", "quoteId", "quoteCommitment", "railSymbol", "railTokenAddress",
  "authorityPublicKey", "proof", "notice",
] as const;
const POINT_KEYS = ["x", "y"] as const;
const PROOF_KEYS = ["nonceCommitment", "response"] as const;

export interface FxCurvePoint {
  x: string;
  y: string;
}

export interface FxSchnorrProof {
  nonceCommitment: FxCurvePoint;
  response: string;
}
export interface FxDenominationInput {
  currency: string;
  decimals: number;
  amount: string;
}

export interface FxRailInput {
  symbol: string;
  tokenAddress: string;
  decimals: number;
  rate: string;
  rateSource: string;
}

export interface CreateFxQuoteInput {
  invoiceId: string;
  merchant: string;
  denomination: FxDenominationInput;
  rails: FxRailInput[];
  slippageBps?: number;
  validForMinutes?: number;
  payerLabel?: string;
  memo?: string;
}

export interface FxDenomination {
  currency: string;
  decimals: number;
  amountDisplay: string;
  amountMinorUnits: string;
}

export interface FxRail {
  symbol: string;
  tokenAddress: string;
  decimals: number;
  rate: string;
  rateScaled: string;
  rateDecimals: number;
  rateSource: string;
  settlementBaseUnits: string;
  settlementDisplay: string;
  minBaseUnits: string;
  maxBaseUnits: string;
}
export interface FxQuote {
  kind: typeof QUOTE_KIND;
  version: typeof FX_ENGINE_VERSION;
  quoteId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  merchant: string;
  denomination: FxDenomination;
  rails: FxRail[];
  slippageBps: number;
  payerLabel: string;
  memo: string;
  quotedAt: string;
  expiresAt: string;
  quoteSalt: string;
  quoteCommitment: string;
  notice: typeof FX_NOTICE;
  limitations: string[];
}

export interface FxQuoteDigest {
  kind: typeof QUOTE_DIGEST_KIND;
  version: typeof FX_ENGINE_VERSION;
  quoteId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  denominationCurrency: string;
  denominationDecimals: number;
  railCount: number;
  railsHash: string;
  slippageBps: number;
  hasPayer: boolean;
  quotedAt: string;
  expiresAt: string;
  memoHash: string;
  quoteCommitment: string;
  notice: typeof FX_NOTICE;
  limitations: string[];
}

export interface FxQuoteOpening {
  quoteId: string;
  quoteCommitment: string;
  quote: FxQuote;
}
export interface FxSettlementReceipt {
  kind: typeof RECEIPT_KIND;
  version: typeof FX_ENGINE_VERSION;
  quoteId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  railSymbol: string;
  railTokenAddress: string;
  quotedBaseUnits: string;
  settledBaseUnits: string;
  withinBand: boolean;
  minBaseUnits: string;
  maxBaseUnits: string;
  settledAt: string;
  transactionHash: string;
  quoteCommitment: string;
  receiptCommitment: string;
  notice: typeof FX_NOTICE;
  limitations: string[];
}

export interface FxRateAuthority {
  authoritySecret: string;
  authorityPublicKey: FxCurvePoint;
}

export interface FxRateAuthorization {
  kind: typeof RATE_AUTH_KIND;
  version: typeof FX_ENGINE_VERSION;
  proofSystem: typeof FX_RATE_PROOF_SYSTEM;
  quoteId: string;
  quoteCommitment: string;
  railSymbol: string;
  railTokenAddress: string;
  authorityPublicKey: FxCurvePoint;
  proof: FxSchnorrProof;
  notice: string;
}

export interface FxRailPreview {
  symbol: string;
  rate: string;
  settlementDisplay: string;
  minDisplay: string;
  maxDisplay: string;
}
export interface FxConversionPreview {
  denominationCurrency: string;
  denominationDisplay: string;
  slippageBps: number;
  rails: FxRailPreview[];
}

export interface FxBandCheck {
  railSymbol: string;
  railTokenAddress: string;
  quotedBaseUnits: string;
  minBaseUnits: string;
  maxBaseUnits: string;
  observedBaseUnits: string;
  withinBand: boolean;
}

export interface FxVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface FxTrustSummary {
  fundHolder: string;
  isDecentralized: boolean;
  isOracle: boolean;
  isSwap: boolean;
  provesRate: boolean;
  provesPayment: boolean;
  rateSource: string;
  zeroKnowledgeElement: string;
  trustedParties: string[];
  statement: string;
}

export interface FxEntropy {
  createId?: (kind: "quote") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export interface FxRateAuthorityEntropy {
  authoritySecret?: bigint;
  nonce?: bigint;
}
export function createFxQuote(input: CreateFxQuoteInput, now: Date = new Date(), entropy: FxEntropy = {}): FxQuote {
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 96);
  const merchant = normalizeStarknetAddress(input.merchant);
  const denomination = normalizeDenomination(input.denomination);
  const slippageBps = requireBps(input.slippageBps, "Slippage tolerance");
  const validForMinutes = requireMinutes(input.validForMinutes, "Quote validity");
  const payerLabel = requireOptionalText(input.payerLabel, "Payer label", 64);
  const memo = requireOptionalText(input.memo, "Quote memo", 280);

  if (!Array.isArray(input.rails)) throw new Error("At least one settlement rail is required.");
  requireCount(input.rails.length, "Rail count", MIN_RAILS, MAX_RAILS);
  const denomMinorUnits = BigInt(denomination.amountMinorUnits);
  const rails = input.rails.map((rail) => computeRail(rail, denomMinorUnits, denomination.decimals, slippageBps));
  assertUniqueRails(rails);

  const quotedMs = requireInstant(now, "Quote time");
  const quotedAt = new Date(quotedMs).toISOString();
  const expiresAt = new Date(quotedMs + validForMinutes * MINUTE_MS).toISOString();
  const quoteId = makeId(entropy.createId?.("quote"), "fxq");
  const quoteSalt = toHex(randomFelt(entropy.randomBytes));

  const quote: FxQuote = {
    kind: QUOTE_KIND,
    version: FX_ENGINE_VERSION,
    quoteId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId,
    merchant,
    denomination,
    rails,
    slippageBps,
    payerLabel,
    memo,
    quotedAt,
    expiresAt,
    quoteSalt,
    quoteCommitment: "0x0",
    notice: FX_NOTICE,
    limitations: [...FX_LIMITATIONS],
  };
  quote.quoteCommitment = toHex(computeQuoteCommitment(quote));
  return quote;
}
export function verifyFxQuote(quote: FxQuote): boolean {
  try {
    assertFxQuote(quote);
    return true;
  } catch {
    return false;
  }
}

export function buildSettlementActions(quote: FxQuote, railSelector: string): STRK20_ACTION[] {
  assertFxQuote(quote);
  const rail = resolveRail(quote, railSelector);
  const amount = requireU128(BigInt(rail.settlementBaseUnits), "Settlement amount");
  if (amount <= 0n) throw new Error("This rail has nothing to settle.");
  // Exactly one in-pool transfer at the quoted amount. No swap, and no second relayer-fee leg:
  // wallet_strk20InvokeTransaction is already gasless and the wallet withdraws the relayer fee itself.
  return [{ type: "transfer", token: rail.tokenAddress, amount: amount.toString(), recipient: quote.merchant }];
}

export function checkSettlementWithinBand(
  quote: FxQuote,
  railSelector: string,
  observedBaseUnits: string | bigint,
): FxBandCheck {
  assertFxQuote(quote);
  const rail = resolveRail(quote, railSelector);
  const observed = requireU128(coerceBaseUnits(observedBaseUnits, "Observed settlement"), "Observed settlement");
  const min = BigInt(rail.minBaseUnits);
  const max = BigInt(rail.maxBaseUnits);
  return {
    railSymbol: rail.symbol,
    railTokenAddress: rail.tokenAddress,
    quotedBaseUnits: rail.settlementBaseUnits,
    minBaseUnits: rail.minBaseUnits,
    maxBaseUnits: rail.maxBaseUnits,
    observedBaseUnits: observed.toString(),
    withinBand: observed >= min && observed <= max,
  };
}

export function previewFxConversion(input: {
  denomination: FxDenominationInput;
  rails: FxRailInput[];
  slippageBps?: number;
}): FxConversionPreview {
  const denomination = normalizeDenomination(input.denomination);
  const slippageBps = requireBps(input.slippageBps, "Slippage tolerance");
  if (!Array.isArray(input.rails)) throw new Error("At least one settlement rail is required.");
  requireCount(input.rails.length, "Rail count", MIN_RAILS, MAX_RAILS);
  const denomMinorUnits = BigInt(denomination.amountMinorUnits);
  const rails = input.rails.map((rail) => computeRail(rail, denomMinorUnits, denomination.decimals, slippageBps));
  assertUniqueRails(rails);
  return {
    denominationCurrency: denomination.currency,
    denominationDisplay: denomination.amountDisplay,
    slippageBps,
    rails: rails.map((rail) => ({
      symbol: rail.symbol,
      rate: rail.rate,
      settlementDisplay: rail.settlementDisplay,
      minDisplay: formatBaseUnits(BigInt(rail.minBaseUnits), rail.decimals),
      maxDisplay: formatBaseUnits(BigInt(rail.maxBaseUnits), rail.decimals),
    })),
  };
}
export function buildFxQuoteDigest(quote: FxQuote): FxQuoteDigest {
  assertFxQuote(quote);
  return {
    kind: QUOTE_DIGEST_KIND,
    version: FX_ENGINE_VERSION,
    quoteId: quote.quoteId,
    network: quote.network,
    poolAddress: quote.poolAddress,
    invoiceId: quote.invoiceId,
    denominationCurrency: quote.denomination.currency,
    denominationDecimals: quote.denomination.decimals,
    railCount: quote.rails.length,
    railsHash: toHex(computeRailsHash(quote.rails)),
    slippageBps: quote.slippageBps,
    hasPayer: quote.payerLabel.length > 0,
    quotedAt: quote.quotedAt,
    expiresAt: quote.expiresAt,
    memoHash: toHex(BigInt(hash.starknetKeccak(quote.memo.length > 0 ? quote.memo : "cipherbill.fx-empty-memo"))),
    quoteCommitment: quote.quoteCommitment,
    notice: FX_NOTICE,
    limitations: [...FX_LIMITATIONS],
  };
}

export function openFxQuote(quote: FxQuote): FxQuoteOpening {
  assertFxQuote(quote);
  return { quoteId: quote.quoteId, quoteCommitment: quote.quoteCommitment, quote };
}

export function verifyFxQuoteDisclosure(digest: FxQuoteDigest, opening: FxQuoteOpening): boolean {
  try {
    assertFxQuoteDigest(digest);
    if (!opening || typeof opening !== "object") return false;
    const quote = opening.quote;
    assertFxQuote(quote);
    if (opening.quoteId !== quote.quoteId || opening.quoteCommitment !== quote.quoteCommitment) return false;
    if (digest.quoteId !== quote.quoteId) return false;
    if (digest.quoteCommitment !== quote.quoteCommitment) return false;
    if (digest.invoiceId !== quote.invoiceId) return false;
    if (digest.denominationCurrency !== quote.denomination.currency) return false;
    if (digest.denominationDecimals !== quote.denomination.decimals) return false;
    if (digest.railCount !== quote.rails.length) return false;
    if (digest.railsHash !== toHex(computeRailsHash(quote.rails))) return false;
    if (digest.slippageBps !== quote.slippageBps) return false;
    if (digest.hasPayer !== (quote.payerLabel.length > 0)) return false;
    if (digest.quotedAt !== quote.quotedAt || digest.expiresAt !== quote.expiresAt) return false;
    const expectedMemoHash = toHex(
      BigInt(hash.starknetKeccak(quote.memo.length > 0 ? quote.memo : "cipherbill.fx-empty-memo")),
    );
    if (digest.memoHash !== expectedMemoHash) return false;
    return true;
  } catch {
    return false;
  }
}
export function buildFxSettlementReceipt(
  quote: FxQuote,
  input: { railSelector: string; settledBaseUnits: string | bigint; settledAt: string; transactionHash: string },
): FxSettlementReceipt {
  assertFxQuote(quote);
  const rail = resolveRail(quote, input.railSelector);
  const settled = requireU128(coerceBaseUnits(input.settledBaseUnits, "Settled amount"), "Settled amount");
  const settledAt = requireIsoTimestamp(input.settledAt, "Settlement time");
  if (Date.parse(settledAt) < Date.parse(quote.quotedAt)) {
    throw new Error("The settlement time cannot be before the quote time.");
  }
  const transactionHash = toHex(requireTransactionHash(input.transactionHash));
  const min = BigInt(rail.minBaseUnits);
  const max = BigInt(rail.maxBaseUnits);
  const withinBand = settled >= min && settled <= max;
  const draft: Omit<FxSettlementReceipt, "receiptCommitment"> = {
    kind: RECEIPT_KIND,
    version: FX_ENGINE_VERSION,
    quoteId: quote.quoteId,
    network: quote.network,
    poolAddress: quote.poolAddress,
    invoiceId: quote.invoiceId,
    railSymbol: rail.symbol,
    railTokenAddress: rail.tokenAddress,
    quotedBaseUnits: rail.settlementBaseUnits,
    settledBaseUnits: settled.toString(),
    withinBand,
    minBaseUnits: rail.minBaseUnits,
    maxBaseUnits: rail.maxBaseUnits,
    settledAt,
    transactionHash,
    quoteCommitment: quote.quoteCommitment,
    notice: FX_NOTICE,
    limitations: [...FX_LIMITATIONS],
  };
  return { ...draft, receiptCommitment: toHex(computeReceiptCommitment(draft)) };
}

export function verifyFxSettlementReceipt(receipt: FxSettlementReceipt, quote: FxQuote): boolean {
  try {
    assertFxSettlementReceipt(receipt);
    assertFxQuote(quote);
    if (receipt.quoteId !== quote.quoteId || receipt.quoteCommitment !== quote.quoteCommitment) return false;
    if (receipt.invoiceId !== quote.invoiceId) return false;
    const rail = quote.rails.find(
      (candidate) =>
        candidate.symbol === receipt.railSymbol &&
        BigInt(candidate.tokenAddress) === BigInt(receipt.railTokenAddress),
    );
    if (!rail) return false;
    if (receipt.quotedBaseUnits !== rail.settlementBaseUnits) return false;
    if (receipt.minBaseUnits !== rail.minBaseUnits || receipt.maxBaseUnits !== rail.maxBaseUnits) return false;
    const settled = BigInt(receipt.settledBaseUnits);
    const expectWithin = settled >= BigInt(rail.minBaseUnits) && settled <= BigInt(rail.maxBaseUnits);
    return receipt.withinBand === expectWithin;
  } catch {
    return false;
  }
}
export function registerFxRateAuthority(entropy: FxRateAuthorityEntropy = {}): FxRateAuthority {
  const secret = entropy.authoritySecret === undefined
    ? randomScalar()
    : requireSecretScalar(entropy.authoritySecret, "Rate authority secret");
  const publicKey = multiplyPoint(BASE, secret);
  return { authoritySecret: toHex(secret), authorityPublicKey: pointToFelts(publicKey) };
}

export function buildFxRateAuthorization(
  quote: FxQuote,
  railSelector: string,
  authoritySecret: string | bigint,
  entropy: FxRateAuthorityEntropy = {},
): FxRateAuthorization {
  assertFxQuote(quote);
  const rail = resolveRail(quote, railSelector);
  const secret = requireCurveScalar(authoritySecret, false, "Rate authority secret");
  const publicKey = multiplyPoint(BASE, secret);
  const proof = createSchnorrProof(RATE_DOMAIN, secret, rateTranscript(quote, rail), entropy.nonce);
  return {
    kind: RATE_AUTH_KIND,
    version: FX_ENGINE_VERSION,
    proofSystem: FX_RATE_PROOF_SYSTEM,
    quoteId: quote.quoteId,
    quoteCommitment: quote.quoteCommitment,
    railSymbol: rail.symbol,
    railTokenAddress: rail.tokenAddress,
    authorityPublicKey: pointToFelts(publicKey),
    proof,
    notice:
      "Zero-knowledge proof of knowledge of the rate-authority key, bound to this quote and settlement rail. " +
      "It attests the rate was authorized and reveals nothing about the key; it does not prove the price is " +
      "fair or that any settlement was made.",
  };
}

export function verifyFxRateAuthorization(
  auth: FxRateAuthorization,
  quote: FxQuote,
  expectedAuthorityPublicKey: FxCurvePoint,
): boolean {
  try {
    assertRateAuthorization(auth);
    assertFxQuote(quote);
    if (auth.quoteId !== quote.quoteId || auth.quoteCommitment !== quote.quoteCommitment) return false;
    const rail = quote.rails.find(
      (candidate) =>
        candidate.symbol === auth.railSymbol &&
        BigInt(candidate.tokenAddress) === BigInt(auth.railTokenAddress),
    );
    if (!rail) return false;
    const expected = pointFromFelts(expectedAuthorityPublicKey, "Expected rate authority public key");
    const presented = pointFromFelts(auth.authorityPublicKey, "Rate authority public key");
    if (!presented.equals(expected)) return false;
    return verifySchnorrProof(RATE_DOMAIN, presented, auth.proof, rateTranscript(quote, rail));
  } catch {
    return false;
  }
}
export function getFxVisibilityModel(quote: FxQuote): FxVisibilityModel {
  assertFxQuote(quote);
  return {
    applicationOnly: [
      "the invoice ID and the denominated amount in the display currency",
      "every rail's quoted rate, settlement amount, and slippage band",
      "the merchant recipient, the payer label, the quote memo, and the quote salt",
      "which rail the customer chose to settle in",
    ],
    walletRequest: [
      "the chosen settlement token address",
      "the exact base-unit settlement amount",
      "the in-pool merchant recipient",
    ],
    hiddenInPool: [
      "the settlement's in-pool sender and recipient",
      "the settlement token and amount",
      "which encrypted notes were spent and their linkage",
    ],
    publicOrObservable: [
      "published nullifiers, which are unlinkable without a viewing key",
      "the settlement transaction's timing and fees",
      "any shielding deposit or withdrawal edge, including its token, amount, and public address",
    ],
    limitation:
      "A distinctive settlement amount, or a rate tied to a known invoice or merchant, is a correlation " +
      "signal even though the transfer's parties and amount are hidden inside the pool. There is no oracle, " +
      "swap, or price proof: the rate is quoted off-chain and the conversion is local arithmetic.",
  };
}

export function summarizeFxTrust(quote: FxQuote): FxTrustSummary {
  assertFxQuote(quote);
  const payer = quote.payerLabel.length > 0 ? quote.payerLabel : "the customer";
  const railWord = quote.rails.length === 1 ? "rail" : "rails";
  return {
    fundHolder: "the customer, who keeps custody of their funds and voluntarily signs the settlement transfer",
    isDecentralized: false,
    isOracle: false,
    isSwap: false,
    provesRate: false,
    provesPayment: false,
    rateSource: "quoted by the merchant or a rate authority off-chain; CipherBill checks the arithmetic, never the price",
    zeroKnowledgeElement:
      "Only the optional rate authorization is a zero-knowledge proof, and it proves knowledge of a " +
      "rate-authority key bound to the quote, never that a rate is fair or that a payment was made.",
    trustedParties: [`the rate authority to quote ${quote.denomination.currency} honestly`, `${payer} to settle at the quoted rate`],
    statement:
      `The quote denominates ${quote.denomination.amountDisplay} ${quote.denomination.currency} across ` +
      `${quote.rails.length} settlement ${railWord}. Nothing is decentralized, swapped, or oracle-backed, and no ` +
      `rate or payment is proven: ${payer} signs a single private in-pool transfer in the chosen token, at the ` +
      `quoted rate, and can decline.`,
  };
}
export function serializeFxQuote(quote: FxQuote): string {
  assertFxQuote(quote);
  return toBase64Url(JSON.stringify(quote));
}

export function parseFxQuote(encoded: string): FxQuote {
  const value = parseEncodedJson(encoded);
  assertFxQuote(value);
  return value;
}

export function serializeFxQuoteDigest(digest: FxQuoteDigest): string {
  assertFxQuoteDigest(digest);
  return toBase64Url(JSON.stringify(digest));
}

export function parseFxQuoteDigest(encoded: string): FxQuoteDigest {
  const value = parseEncodedJson(encoded);
  assertFxQuoteDigest(value);
  return value;
}

export function serializeFxSettlementReceipt(receipt: FxSettlementReceipt): string {
  assertFxSettlementReceipt(receipt);
  return toBase64Url(JSON.stringify(receipt));
}

export function parseFxSettlementReceipt(encoded: string): FxSettlementReceipt {
  const value = parseEncodedJson(encoded);
  assertFxSettlementReceipt(value);
  return value;
}

export function formatFxBaseUnits(value: string | bigint, decimals: number): string {
  return formatBaseUnits(coerceBaseUnits(value, "Amount"), requireDecimals(decimals, "Decimals"));
}
function normalizeDenomination(input: FxDenominationInput | undefined): FxDenomination {
  if (!input || typeof input !== "object") throw new Error("A denomination is required.");
  const currency = requireSymbol(input.currency, "Denomination currency");
  const decimals = requireDecimals(input.decimals, "Denomination decimals");
  const amountMinorUnits = parseDecimalToBaseUnits(input.amount, decimals, "Denominated amount");
  if (amountMinorUnits <= 0n) throw new Error("The denominated amount must be greater than zero.");
  return {
    currency,
    decimals,
    amountDisplay: formatBaseUnits(amountMinorUnits, decimals),
    amountMinorUnits: amountMinorUnits.toString(),
  };
}

function computeRail(
  input: FxRailInput,
  denomMinorUnits: bigint,
  denomDecimals: number,
  slippageBps: number,
): FxRail {
  if (!input || typeof input !== "object") throw new Error("Each settlement rail must be an object.");
  const symbol = requireSymbol(input.symbol, "Rail symbol");
  const tokenAddress = normalizeStarknetAddress(input.tokenAddress);
  const decimals = requireDecimals(input.decimals, "Rail decimals");
  const rate = parseRate(input.rate, "Rail rate");
  const rateSource = requireText(input.rateSource, "Rate source", 96);

  // settlement = ceil( amount * rate * 10^tokenDecimals ), with amount and rate carried as scaled integers.
  const numerator = denomMinorUnits * rate.scaled * 10n ** BigInt(decimals);
  const denominator = 10n ** BigInt(denomDecimals + rate.decimals);
  const settlement = ceilDiv(numerator, denominator);
  requireU128(settlement, "Rail settlement amount");
  const min = (settlement * BigInt(BPS_DENOMINATOR - slippageBps)) / BigInt(BPS_DENOMINATOR);
  const max = ceilDiv(settlement * BigInt(BPS_DENOMINATOR + slippageBps), BigInt(BPS_DENOMINATOR));
  requireU128(min, "Rail slippage floor");
  requireU128(max, "Rail slippage ceiling");

  return {
    symbol,
    tokenAddress,
    decimals,
    rate: rate.normalized,
    rateScaled: rate.scaled.toString(),
    rateDecimals: rate.decimals,
    rateSource,
    settlementBaseUnits: settlement.toString(),
    settlementDisplay: formatBaseUnits(settlement, decimals),
    minBaseUnits: min.toString(),
    maxBaseUnits: max.toString(),
  };
}
function resolveRail(quote: FxQuote, selector: string): FxRail {
  if (typeof selector !== "string" || selector.trim().length === 0) {
    throw new Error("A settlement rail selector is required.");
  }
  const trimmed = selector.trim();
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    const target = BigInt(normalizeStarknetAddress(trimmed));
    const rail = quote.rails.find((candidate) => BigInt(candidate.tokenAddress) === target);
    if (!rail) throw new Error("No settlement rail matches the token address.");
    return rail;
  }
  const lowered = trimmed.toLowerCase();
  const rail = quote.rails.find((candidate) => candidate.symbol.toLowerCase() === lowered);
  if (!rail) throw new Error("No settlement rail matches the symbol.");
  return rail;
}

function assertUniqueRails(rails: FxRail[]): void {
  const symbols = new Set<string>();
  const tokens = new Set<string>();
  for (const rail of rails) {
    const symbolKey = rail.symbol.toLowerCase();
    if (symbols.has(symbolKey)) throw new Error("Rail symbols must be unique within a quote.");
    symbols.add(symbolKey);
    const tokenKey = BigInt(rail.tokenAddress).toString();
    if (tokens.has(tokenKey)) throw new Error("Rail token addresses must be unique within a quote.");
    tokens.add(tokenKey);
  }
}

function ceilDiv(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) throw new Error("Division by a non-positive denominator.");
  if (numerator <= 0n) return 0n;
  return (numerator + denominator - 1n) / denominator;
}

function parseRate(value: unknown, label: string): { scaled: bigint; decimals: number; normalized: string } {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,18})?$/.test(value.trim())) {
    throw new Error(`${label} must be a positive decimal number with up to ${MAX_RATE_DECIMALS} decimals.`);
  }
  const [wholeRaw, fractionRaw = ""] = value.trim().split(".");
  const fraction = fractionRaw.replace(/0+$/, "");
  const whole = BigInt(wholeRaw).toString();
  const scaled = BigInt(`${whole}${fraction}`);
  if (scaled <= 0n) throw new Error(`${label} must be greater than zero.`);
  const normalized = fraction.length > 0 ? `${whole}.${fraction}` : whole;
  return { scaled, decimals: fraction.length, normalized };
}
function hashElements(elements: bigint[]): bigint {
  for (const element of elements) {
    if (element < 0n || element >= FIELD_PRIME) throw new Error("A commitment field element is out of range.");
  }
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

function railFelts(rail: FxRail): bigint[] {
  return [
    BigInt(hash.starknetKeccak(rail.symbol)),
    BigInt(rail.tokenAddress),
    BigInt(rail.decimals),
    BigInt(rail.rateScaled),
    BigInt(rail.rateDecimals),
    BigInt(hash.starknetKeccak(rail.rateSource.length > 0 ? rail.rateSource : "none")),
    BigInt(rail.settlementBaseUnits),
    BigInt(rail.minBaseUnits),
    BigInt(rail.maxBaseUnits),
  ];
}

function computeRailsHash(rails: FxRail[]): bigint {
  const elements: bigint[] = [RAIL_DOMAIN, BigInt(rails.length)];
  for (const rail of rails) elements.push(...railFelts(rail));
  return hashElements(elements);
}

function computeQuoteCommitment(quote: FxQuote): bigint {
  return hashElements([
    QUOTE_DOMAIN,
    BigInt(quote.version),
    BigInt(quote.quoteSalt),
    BigInt(hash.starknetKeccak(quote.quoteId)),
    BigInt(hash.starknetKeccak(quote.invoiceId)),
    BigInt(quote.poolAddress),
    BigInt(quote.merchant),
    BigInt(hash.starknetKeccak(quote.denomination.currency)),
    BigInt(quote.denomination.decimals),
    BigInt(quote.denomination.amountMinorUnits),
    BigInt(quote.slippageBps),
    BigInt(hash.starknetKeccak(quote.payerLabel.length > 0 ? quote.payerLabel : "none")),
    BigInt(hash.starknetKeccak(quote.memo.length > 0 ? quote.memo : "cipherbill.fx-empty-memo")),
    secondsOf(quote.quotedAt),
    secondsOf(quote.expiresAt),
    BigInt(quote.rails.length),
    computeRailsHash(quote.rails),
  ]);
}
function computeReceiptCommitment(receipt: Omit<FxSettlementReceipt, "receiptCommitment">): bigint {
  return hashElements([
    RECEIPT_DOMAIN,
    BigInt(receipt.version),
    BigInt(hash.starknetKeccak(receipt.quoteId)),
    BigInt(hash.starknetKeccak(receipt.invoiceId)),
    BigInt(receipt.poolAddress),
    BigInt(receipt.quoteCommitment),
    BigInt(hash.starknetKeccak(receipt.railSymbol)),
    BigInt(receipt.railTokenAddress),
    BigInt(receipt.quotedBaseUnits),
    BigInt(receipt.settledBaseUnits),
    receipt.withinBand ? 1n : 0n,
    BigInt(receipt.minBaseUnits),
    BigInt(receipt.maxBaseUnits),
    secondsOf(receipt.settledAt),
    BigInt(receipt.transactionHash),
  ]);
}

function rateTranscript(quote: FxQuote, rail: FxRail): bigint[] {
  return [
    BigInt(quote.quoteCommitment),
    BigInt(rail.tokenAddress),
    BigInt(rail.settlementBaseUnits),
    secondsOf(quote.expiresAt),
  ];
}

function secondsOf(iso: string): bigint {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) throw new Error("An invalid timestamp reached the commitment.");
  return BigInt(Math.floor(ms / 1000));
}

function makeId(provided: string | undefined, prefix: string): string {
  if (provided === undefined) {
    let random = "";
    const bytes = randomFillBytes(new Uint8Array(9));
    for (const byte of bytes) random += byte.toString(16).padStart(2, "0");
    return `${prefix}_${random}`;
  }
  const trimmed = provided.trim();
  if (!/^[A-Za-z0-9_-]{1,48}$/.test(trimmed)) throw new Error("A supplied identifier is malformed.");
  return trimmed.startsWith(`${prefix}_`) ? trimmed : `${prefix}_${trimmed}`;
}
function randomFillBytes(target: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const source = globalThis.crypto;
  if (!source || typeof source.getRandomValues !== "function") {
    throw new Error("A secure random source is unavailable in this environment.");
  }
  source.getRandomValues(target);
  return target;
}

function randomFelt(supplied?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  const bytes = (supplied ?? randomFillBytes)(new Uint8Array(FX_SALT_BYTES));
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  value %= FIELD_PRIME;
  return value === 0n ? 1n : value;
}

function randomScalar(): bigint {
  const bytes = randomFillBytes(new Uint8Array(32));
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  value %= CURVE_ORDER;
  return value === 0n ? 1n : value;
}

type CurvePoint = InstanceType<typeof ec.starkCurve.ProjectivePoint>;

function multiplyPoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const k = mod(scalar, CURVE_ORDER);
  if (k === 0n) return ec.starkCurve.ProjectivePoint.ZERO;
  return point.multiply(k);
}

function pointToFelts(point: CurvePoint): FxCurvePoint {
  const affine = point.toAffine();
  return { x: toHex(affine.x), y: toHex(affine.y) };
}

function pointFromFelts(value: unknown, label: string): CurvePoint {
  assertPoint(value, label);
  const point = ec.starkCurve.ProjectivePoint.fromAffine({
    x: BigInt((value as FxCurvePoint).x),
    y: BigInt((value as FxCurvePoint).y),
  });
  point.assertValidity();
  return point;
}

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}
function createSchnorrProof(
  domain: bigint,
  secret: bigint,
  transcript: bigint[],
  suppliedNonce?: bigint,
): FxSchnorrProof {
  const nonce = suppliedNonce === undefined
    ? randomScalar()
    : requireCurveScalar(suppliedNonce, false, "Proof nonce");
  const commitment = multiplyPoint(BASE, nonce);
  const publicKey = multiplyPoint(BASE, secret);
  const challenge = schnorrChallenge(domain, publicKey, commitment, transcript);
  const response = mod(nonce + challenge * secret, CURVE_ORDER);
  return { nonceCommitment: pointToFelts(commitment), response: toHex(response) };
}

function verifySchnorrProof(
  domain: bigint,
  publicKey: CurvePoint,
  proof: FxSchnorrProof,
  transcript: bigint[],
): boolean {
  const commitment = pointFromFelts(proof.nonceCommitment, "Proof nonce commitment");
  const response = requireCurveScalar(proof.response, true, "Proof response");
  const challenge = schnorrChallenge(domain, publicKey, commitment, transcript);
  const lhs = multiplyPoint(BASE, response);
  const rhs = commitment.add(multiplyPoint(publicKey, challenge));
  return lhs.equals(rhs);
}

function schnorrChallenge(
  domain: bigint,
  publicKey: CurvePoint,
  commitment: CurvePoint,
  transcript: bigint[],
): bigint {
  const pk = publicKey.toAffine();
  const r = commitment.toAffine();
  const elements = [domain, pk.x, pk.y, r.x, r.y, ...transcript];
  return mod(hashElements(elements), CURVE_ORDER);
}
function toHex(value: bigint): string {
  if (value < 0n || value >= FIELD_PRIME) throw new Error("A field element is out of range.");
  return `0x${value.toString(16)}`;
}

function coerceBaseUnits(value: string | bigint, label: string): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(`${label} must not be negative.`);
    return value;
  }
  if (typeof value !== "string" || !/^\d+$/.test(value.trim())) {
    throw new Error(`${label} must be a base-unit integer string.`);
  }
  return BigInt(value.trim());
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} does not fit in a u128 base-unit amount.`);
  return value;
}

function requireCount(value: number, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function requireBps(value: number | undefined, label: string): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < MIN_SLIPPAGE_BPS || value > MAX_SLIPPAGE_BPS) {
    throw new Error(`${label} must be an integer between ${MIN_SLIPPAGE_BPS} and ${MAX_SLIPPAGE_BPS} basis points.`);
  }
  return value;
}

function requireMinutes(value: number | undefined, label: string): number {
  if (value === undefined || value === null) return DEFAULT_QUOTE_TTL_MINUTES;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_QUOTE_TTL_MINUTES) {
    throw new Error(`${label} must be an integer between 1 and ${MAX_QUOTE_TTL_MINUTES} minutes.`);
  }
  return value;
}
function requireSymbol(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (!/^[A-Za-z0-9.\-/]{1,16}$/.test(trimmed)) {
    throw new Error(`${label} must be 1 to 16 letters, digits, or the symbols . - /.`);
  }
  return trimmed;
}

function requireDecimals(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_ASSET_DECIMALS) {
    throw new Error(`${label} must be an integer between 0 and ${MAX_ASSET_DECIMALS}.`);
  }
  return value;
}

function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new Error(`${label} is required.`);
  if (trimmed.length > maxLength) throw new Error(`${label} must be at most ${maxLength} characters.`);
  return trimmed;
}

function requireOptionalText(value: unknown, label: string, maxLength: number): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  const trimmed = value.trim();
  if (trimmed.length > maxLength) throw new Error(`${label} must be at most ${maxLength} characters.`);
  return trimmed;
}

function requireInstant(value: Date, label: string): number {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new Error(`${label} must be a valid date.`);
  return value.getTime();
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error(`${label} must be an ISO-8601 UTC timestamp.`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) throw new Error(`${label} is not a real instant.`);
  return value;
}
function requireFelt(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new Error(`${label} must be a hex field element.`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error(`${label} is out of the field range.`);
  return parsed;
}

function requireCurveScalar(value: string | bigint, allowZero: boolean, label: string): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) {
    parsed = BigInt(value);
  } else {
    throw new Error(`${label} must be a scalar.`);
  }
  if (parsed < 0n || parsed >= CURVE_ORDER) throw new Error(`${label} is out of the curve order.`);
  if (!allowZero && parsed === 0n) throw new Error(`${label} must be non-zero.`);
  return parsed;
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (typeof value !== "bigint") throw new Error(`${label} must be a bigint.`);
  if (value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is out of the curve order.`);
  return value;
}

function requireTransactionHash(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value.trim())) {
    throw new Error("A transaction hash must be a hex string.");
  }
  const parsed = BigInt(value.trim());
  if (parsed <= 0n || parsed >= FIELD_PRIME) throw new Error("A transaction hash is out of range.");
  return parsed;
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (decimals < 0 || decimals > MAX_ASSET_DECIMALS) throw new Error(`Decimals must be between 0 and ${MAX_ASSET_DECIMALS}.`);
  if (value < 0n) throw new Error("A base-unit amount must not be negative.");
  if (decimals === 0) return value.toString();
  const scale = 10n ** BigInt(decimals);
  const whole = value / scale;
  const fraction = (value % scale).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction.length > 0 ? `${whole}.${fraction}` : whole.toString();
}
function parseDecimalToBaseUnits(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) {
    throw new Error(`${label} must be a non-negative decimal number.`);
  }
  const [wholeRaw, fractionRaw = ""] = value.trim().split(".");
  if (fractionRaw.length > decimals) throw new Error(`${label} has more precision than the currency allows.`);
  const padded = fractionRaw.padEnd(decimals, "0");
  return BigInt(wholeRaw) * 10n ** BigInt(decimals) + (padded.length > 0 ? BigInt(padded) : 0n);
}

function toBase64Url(value: string): string {
  const base64 = typeof btoa === "function"
    ? btoa(unescape(encodeURIComponent(value)))
    : Buffer.from(value, "utf-8").toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  if (typeof atob === "function") return decodeURIComponent(escape(atob(padded)));
  return Buffer.from(padded, "base64").toString("utf-8");
}

function parseEncodedJson(encoded: string): unknown {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > MAX_ENCODED_LENGTH) {
    throw new Error("The encoding is invalid.");
  }
  let decoded: string;
  try {
    decoded = fromBase64Url(encoded);
  } catch {
    throw new Error("The encoding is invalid.");
  }
  try {
    return JSON.parse(decoded);
  } catch {
    throw new Error("The encoding is invalid.");
  }
}

function hasOnlyKeys(value: unknown, keys: readonly string[]): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  if (actual.length !== keys.length) return false;
  return actual.every((key) => keys.includes(key));
}
function assertPoint(value: unknown, label: string): asserts value is FxCurvePoint {
  if (!hasOnlyKeys(value, POINT_KEYS)) throw new Error(`${label} is malformed.`);
  requireFelt((value as FxCurvePoint).x, `${label} x`);
  requireFelt((value as FxCurvePoint).y, `${label} y`);
}

function assertProof(value: unknown, label: string): asserts value is FxSchnorrProof {
  if (!hasOnlyKeys(value, PROOF_KEYS)) throw new Error(`${label} is malformed.`);
  assertPoint((value as FxSchnorrProof).nonceCommitment, `${label} nonce commitment`);
  requireCurveScalar((value as FxSchnorrProof).response, true, `${label} response`);
}

function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== FX_LIMITATIONS.length) throw new Error("The limitations are malformed.");
  for (let index = 0; index < FX_LIMITATIONS.length; index += 1) {
    if (value[index] !== FX_LIMITATIONS[index]) throw new Error("The limitations were altered.");
  }
}

function assertDenomination(value: unknown): asserts value is FxDenomination {
  if (!hasOnlyKeys(value, DENOMINATION_KEYS)) throw new Error("The denomination is malformed.");
  const denomination = value as FxDenomination;
  const currency = requireSymbol(denomination.currency, "Denomination currency");
  const decimals = requireDecimals(denomination.decimals, "Denomination decimals");
  const minor = coerceBaseUnits(denomination.amountMinorUnits, "Denominated amount");
  if (minor <= 0n) throw new Error("The denominated amount must be greater than zero.");
  if (denomination.currency !== currency) throw new Error("The denomination currency is not normalized.");
  if (denomination.amountDisplay !== formatBaseUnits(minor, decimals)) {
    throw new Error("The denomination display does not match its minor units.");
  }
}
function assertRail(value: unknown, label: string): asserts value is FxRail {
  if (!hasOnlyKeys(value, RAIL_KEYS)) throw new Error(`${label} is malformed.`);
  const rail = value as FxRail;
  const symbol = requireSymbol(rail.symbol, `${label} symbol`);
  if (rail.symbol !== symbol) throw new Error(`${label} symbol is not normalized.`);
  if (rail.tokenAddress !== normalizeStarknetAddress(rail.tokenAddress)) {
    throw new Error(`${label} token address is not normalized.`);
  }
  const decimals = requireDecimals(rail.decimals, `${label} decimals`);
  const parsedRate = parseRate(rail.rate, `${label} rate`);
  if (
    parsedRate.normalized !== rail.rate ||
    parsedRate.scaled.toString() !== rail.rateScaled ||
    parsedRate.decimals !== rail.rateDecimals
  ) {
    throw new Error(`${label} rate is inconsistent with its scaled form.`);
  }
  requireText(rail.rateSource, `${label} rate source`, 96);
  const settlement = requireU128(coerceBaseUnits(rail.settlementBaseUnits, `${label} settlement`), `${label} settlement`);
  if (rail.settlementDisplay !== formatBaseUnits(settlement, decimals)) {
    throw new Error(`${label} settlement display does not match its base units.`);
  }
  const min = requireU128(coerceBaseUnits(rail.minBaseUnits, `${label} floor`), `${label} floor`);
  const max = requireU128(coerceBaseUnits(rail.maxBaseUnits, `${label} ceiling`), `${label} ceiling`);
  if (min > settlement || max < settlement) throw new Error(`${label} slippage band does not contain the quote.`);
}
function assertFxQuote(value: unknown): asserts value is FxQuote {
  if (!hasOnlyKeys(value, QUOTE_KEYS)) throw new Error("The FX quote is malformed.");
  const quote = value as FxQuote;
  if (quote.kind !== QUOTE_KIND) throw new Error("The FX quote kind is wrong.");
  if (quote.version !== FX_ENGINE_VERSION) throw new Error("The FX quote version is unsupported.");
  if (quote.network !== MAINNET_CHAIN_ID) throw new Error("The FX quote network is wrong.");
  if (quote.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("The FX quote pool address is wrong.");
  if (quote.notice !== FX_NOTICE) throw new Error("The FX quote notice was altered.");
  if (typeof quote.quoteId !== "string" || !/^fxq_[A-Za-z0-9_-]{1,48}$/.test(quote.quoteId)) {
    throw new Error("The FX quote ID is malformed.");
  }
  requireText(quote.invoiceId, "Invoice ID", 96);
  if (quote.merchant !== normalizeStarknetAddress(quote.merchant)) throw new Error("The merchant address is not normalized.");
  assertDenomination(quote.denomination);
  if (!Array.isArray(quote.rails)) throw new Error("The settlement rails are malformed.");
  requireCount(quote.rails.length, "Rail count", MIN_RAILS, MAX_RAILS);
  quote.rails.forEach((rail, index) => assertRail(rail, `Rail ${index + 1}`));
  assertUniqueRails(quote.rails);
  requireBps(quote.slippageBps, "Slippage tolerance");
  requireOptionalText(quote.payerLabel, "Payer label", 64);
  requireOptionalText(quote.memo, "Quote memo", 280);
  requireIsoTimestamp(quote.quotedAt, "Quote time");
  requireIsoTimestamp(quote.expiresAt, "Expiry time");
  if (Date.parse(quote.expiresAt) <= Date.parse(quote.quotedAt)) throw new Error("The expiry must be after the quote time.");
  requireFelt(quote.quoteSalt, "Quote salt");
  assertLimitations(quote.limitations);

  // Revalidate the exchange-rate arithmetic: recompute every rail from its own rate and confirm it matches.
  const denomMinorUnits = BigInt(quote.denomination.amountMinorUnits);
  quote.rails.forEach((rail, index) => {
    const recomputed = computeRail(
      { symbol: rail.symbol, tokenAddress: rail.tokenAddress, decimals: rail.decimals, rate: rail.rate, rateSource: rail.rateSource },
      denomMinorUnits,
      quote.denomination.decimals,
      quote.slippageBps,
    );
    if (
      recomputed.settlementBaseUnits !== rail.settlementBaseUnits ||
      recomputed.minBaseUnits !== rail.minBaseUnits ||
      recomputed.maxBaseUnits !== rail.maxBaseUnits ||
      recomputed.rateScaled !== rail.rateScaled
    ) {
      throw new Error(`Rail ${index + 1} settlement does not match its rate.`);
    }
  });

  if (requireFelt(quote.quoteCommitment, "Quote commitment") !== computeQuoteCommitment(quote)) {
    throw new Error("The FX quote commitment does not match its contents.");
  }
}
function assertFxQuoteDigest(value: unknown): asserts value is FxQuoteDigest {
  if (!hasOnlyKeys(value, DIGEST_KEYS)) throw new Error("The FX quote digest is malformed.");
  const digest = value as FxQuoteDigest;
  if (digest.kind !== QUOTE_DIGEST_KIND) throw new Error("The digest kind is wrong.");
  if (digest.version !== FX_ENGINE_VERSION) throw new Error("The digest version is unsupported.");
  if (digest.network !== MAINNET_CHAIN_ID) throw new Error("The digest network is wrong.");
  if (digest.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("The digest pool address is wrong.");
  if (digest.notice !== FX_NOTICE) throw new Error("The digest notice was altered.");
  if (typeof digest.quoteId !== "string" || !/^fxq_[A-Za-z0-9_-]{1,48}$/.test(digest.quoteId)) {
    throw new Error("The digest quote ID is malformed.");
  }
  requireText(digest.invoiceId, "Invoice ID", 96);
  requireSymbol(digest.denominationCurrency, "Denomination currency");
  requireDecimals(digest.denominationDecimals, "Denomination decimals");
  requireCount(digest.railCount, "Rail count", MIN_RAILS, MAX_RAILS);
  requireFelt(digest.railsHash, "Rails hash");
  requireBps(digest.slippageBps, "Slippage tolerance");
  if (typeof digest.hasPayer !== "boolean") throw new Error("The digest payer flag is malformed.");
  requireIsoTimestamp(digest.quotedAt, "Quote time");
  requireIsoTimestamp(digest.expiresAt, "Expiry time");
  requireFelt(digest.memoHash, "Memo hash");
  requireFelt(digest.quoteCommitment, "Quote commitment");
  assertLimitations(digest.limitations);
}

function assertFxSettlementReceipt(value: unknown): asserts value is FxSettlementReceipt {
  if (!hasOnlyKeys(value, RECEIPT_KEYS)) throw new Error("The settlement receipt is malformed.");
  const receipt = value as FxSettlementReceipt;
  if (receipt.kind !== RECEIPT_KIND) throw new Error("The receipt kind is wrong.");
  if (receipt.version !== FX_ENGINE_VERSION) throw new Error("The receipt version is unsupported.");
  if (receipt.network !== MAINNET_CHAIN_ID) throw new Error("The receipt network is wrong.");
  if (receipt.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("The receipt pool address is wrong.");
  if (receipt.notice !== FX_NOTICE) throw new Error("The receipt notice was altered.");
  if (typeof receipt.quoteId !== "string" || !/^fxq_[A-Za-z0-9_-]{1,48}$/.test(receipt.quoteId)) {
    throw new Error("The receipt quote ID is malformed.");
  }
  requireText(receipt.invoiceId, "Invoice ID", 96);
  requireSymbol(receipt.railSymbol, "Rail symbol");
  if (receipt.railTokenAddress !== normalizeStarknetAddress(receipt.railTokenAddress)) {
    throw new Error("The receipt rail token is not normalized.");
  }
  const settlement = requireU128(coerceBaseUnits(receipt.quotedBaseUnits, "Quoted amount"), "Quoted amount");
  const settled = requireU128(coerceBaseUnits(receipt.settledBaseUnits, "Settled amount"), "Settled amount");
  const min = requireU128(coerceBaseUnits(receipt.minBaseUnits, "Floor"), "Floor");
  const max = requireU128(coerceBaseUnits(receipt.maxBaseUnits, "Ceiling"), "Ceiling");
  if (min > settlement || max < settlement) throw new Error("The receipt band does not contain the quote.");
  if (typeof receipt.withinBand !== "boolean") throw new Error("The receipt band flag is malformed.");
  if (receipt.withinBand !== (settled >= min && settled <= max)) throw new Error("The receipt band flag is inconsistent.");
  requireIsoTimestamp(receipt.settledAt, "Settlement time");
  requireTransactionHash(receipt.transactionHash);
  requireFelt(receipt.quoteCommitment, "Quote commitment");
  assertLimitations(receipt.limitations);
  const { receiptCommitment, ...rest } = receipt;
  if (requireFelt(receiptCommitment, "Receipt commitment") !== computeReceiptCommitment(rest)) {
    throw new Error("The receipt commitment does not match its contents.");
  }
}
function assertRateAuthorization(value: unknown): asserts value is FxRateAuthorization {
  if (!hasOnlyKeys(value, RATE_AUTH_KEYS)) throw new Error("The rate authorization is malformed.");
  const auth = value as FxRateAuthorization;
  if (auth.kind !== RATE_AUTH_KIND) throw new Error("The authorization kind is wrong.");
  if (auth.version !== FX_ENGINE_VERSION) throw new Error("The authorization version is unsupported.");
  if (auth.proofSystem !== FX_RATE_PROOF_SYSTEM) throw new Error("The authorization proof system is wrong.");
  if (typeof auth.quoteId !== "string" || !/^fxq_[A-Za-z0-9_-]{1,48}$/.test(auth.quoteId)) {
    throw new Error("The authorization quote ID is malformed.");
  }
  requireFelt(auth.quoteCommitment, "Quote commitment");
  requireSymbol(auth.railSymbol, "Rail symbol");
  if (auth.railTokenAddress !== normalizeStarknetAddress(auth.railTokenAddress)) {
    throw new Error("The authorization rail token is not normalized.");
  }
  assertPoint(auth.authorityPublicKey, "Rate authority public key");
  assertProof(auth.proof, "Rate authorization proof");
  if (typeof auth.notice !== "string" || !/knowledge of the rate-authority key/i.test(auth.notice)) {
    throw new Error("The authorization notice was altered.");
  }
}




























