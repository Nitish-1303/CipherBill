/**
 * CipherBill — Multi-Currency FX Hedging & Forward-Rate Lock Engine
 *
 * Client-side module for merchants to lock forward exchange rates for future
 * STRK20 invoice settlements while hiding notional, currency pair labels,
 * counterparty references, and locked rate scalars behind Pedersen commitments.
 * Public policy covenants (tenor ceiling, forward premium/discount band vs spot)
 * are proven via surplus range proofs; the issuer signs the binding offline.
 *
 * STRK20_POOL_ADDRESS is provenance only — this module never calls the pool.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const FX_HEDGING_ENGINE_VERSION = 1 as const;
export const FX_HEDGING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const FX_HEDGING_PROOF_SYSTEM = "stark-pedersen-fx-hedging-bounds-v1" as const;
export const BPS_SCALE = 10_000n;
export const MAX_TENOR_DAYS = 730;
export const MAX_RATE_DECIMALS = 18;
export const MAX_FORWARD_BPS = 5_000;
export const DEFAULT_AMOUNT_BIT_LENGTH = 96;
export const MIN_AMOUNT_BIT_LENGTH = 16;
export const MAX_AMOUNT_BIT_LENGTH = 128;
export const SURPLUS_EXTRA_BITS = 16;
export const DAY_MS = 86_400_000;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD = ec.starkCurve.CURVE.Fp;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 1_600_000;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill fx hedging generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill fx hedging statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill fx hedging bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill fx hedging binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill fx hedging issuer signature v1");
const PAIR_DOMAIN = hash.starknetKeccak("CipherBill fx hedging pair v1");
const COUNTERPARTY_DOMAIN = hash.starknetKeccak("CipherBill fx hedging counterparty v1");

const CERTIFICATE_KIND = "cipherbill.fx-hedging-certificate" as const;
const SECRET_KIND = "cipherbill.fx-hedging-certificate-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.fx-hedging-amount-disclosure" as const;
const PAIR_DISCLOSURE_KIND = "cipherbill.fx-hedging-pair-disclosure" as const;
const KEYPAIR_KIND = "cipherbill.fx-hedging-keypair" as const;

type CurvePoint = ReturnType<typeof G.multiply>;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface FxHedgingEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

export interface FxHedgingKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface FxHedgingAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

/** PUBLIC forward-rate policy band relative to the published spot reference. */
export interface FxHedgingPolicy {
  maxTenorDays: number;
  maxForwardPremiumBps: number;
  maxForwardDiscountBps: number;
}

export interface ForwardRateQuote {
  spotRateScaled: string;
  forwardPointsBps: number;
  lockedRateScaled: string;
  rateDecimals: number;
  minLockedRateScaled: string;
  maxLockedRateScaled: string;
}

export interface HedgingState {
  notionalBaseUnits: string;
  lockedRateScaled: string;
  spotRateScaled: string;
  tenorDays: number;
  maxTenorDays: string;
  upperSurplus: string;
  lowerSurplus: string;
  tenorSurplus: string;
  eligible: boolean;
}

export interface HedgingPositionInput {
  positionId: string;
  baseCurrency: string;
  quoteCurrency: string;
  notionalBaseUnits: string;
  lockedRateScaled: string;
  spotRateScaled: string;
  settlementDate: string;
  lockedAt: string;
}

export interface HedgingMonitorRow {
  positionId: string;
  pairLabel: string;
  notionalDisplay: string;
  lockedRateDisplay: string;
  markRateDisplay: string;
  unrealizedPnlBps: string;
  tenorDaysRemaining: number;
  status: "in-band" | "premium-breach" | "discount-breach" | "expired";
}

export interface FxHedgingBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  challenge0: string;
  response0: string;
  response1: string;
}

export interface IssuerSignature {
  challenge: string;
  response: string;
}

export interface FxHedgingProof {
  proofSystem: typeof FX_HEDGING_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  generatorH: CurvePointFelts;
  notionalCommitment: CurvePointFelts;
  lockedRateCommitment: CurvePointFelts;
  notionalBits: FxHedgingBitProof[];
  lockedRateBits: FxHedgingBitProof[];
  upperSurplusBits: FxHedgingBitProof[];
  lowerSurplusBits: FxHedgingBitProof[];
  tenorSurplusBits: FxHedgingBitProof[];
  issuerSignature: IssuerSignature;
}

export interface FxHedgingCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof FX_HEDGING_ENGINE_VERSION;
  certificateId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  merchantAlias: string;
  deskLabel: string;
  asset: FxHedgingAsset;
  baseCurrencyHash: string;
  quoteCurrencyHash: string;
  pairCommitment: string;
  counterpartyCommitment: string;
  counterpartyCommitted: boolean;
  spotRateScaled: string;
  rateDecimals: number;
  settlementDate: string;
  lockedAt: string;
  tenorDays: number;
  policy: FxHedgingPolicy;
  minLockedRateScaled: string;
  maxLockedRateScaled: string;
  issuerPublicKey: CurvePointFelts;
  proof: FxHedgingProof;
  notice: string;
  limitations: readonly string[];
}

export interface FxHedgingCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  notionalBaseUnits: string;
  lockedRateScaled: string;
  forwardPointsBps: number;
  baseCurrency: string;
  quoteCurrency: string;
  pairSalt: string;
  counterpartyRef: string;
  counterpartySalt: string;
  notionalBlinding: string;
  lockedRateBlinding: string;
}

export interface IssuedFxHedgingCertificate {
  certificate: FxHedgingCertificate;
  secret: FxHedgingCertificateSecret;
}

export interface IssueFxHedgingCertificateInput {
  merchantAlias: string;
  deskLabel: string;
  asset: FxHedgingAsset;
  baseCurrency: string;
  quoteCurrency: string;
  counterpartyRef?: string;
  spotRate: string;
  rateDecimals: number;
  forwardPointsBps: number;
  notionalBaseUnits: string;
  settlementDate: string;
  policy: FxHedgingPolicy;
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

export interface FxHedgingAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  field: "notional" | "lockedRate";
  value: string;
  blinding: string;
  proof: FxHedgingBitProof[];
}

export interface FxHedgingPairDisclosure {
  kind: typeof PAIR_DISCLOSURE_KIND;
  certificateId: string;
  baseCurrency: string;
  quoteCurrency: string;
  pairSalt: string;
}

export interface FxHedgingTrustSummary {
  decentralized: boolean;
  zeroKnowledge: boolean;
  poolIntegrated: boolean;
  oracleBacked: boolean;
  statement: string;
}

export interface FxHedgingVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

export const FX_HEDGING_NOTICE =
  "Zero-knowledge forward-rate lock over hidden notional and currency pair labels. Public spot reference and policy band only; " +
  "STRK20 pool address is provenance and never called.";

export const FX_HEDGING_LIMITATIONS: readonly string[] = [
  "Rates and notionals are merchant-supplied desk inputs — no oracle, AMM, or on-chain FX contract validates fairness.",
  "The certificate proves arithmetic against public policy; it does not guarantee settlement or hedge execution in the pool.",
  "In-pool settlement hides amounts, but distinctive notionals or pair timing can correlate activity.",
  "Mark-to-market rows are local heuristics — not investment advice or a live market feed.",
];

// ---------------------------------------------------------------------------
// Curve helpers
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

export function deriveFxHedgingGenerator(): CurvePointFelts {
  return pointToFelts(independentGenerator());
}

function hashToPoint(seed: bigint[]): CurvePoint {
  for (let counter = 0n; counter < 1000n; counter += 1n) {
    const x = mod(hashElements([...seed, counter]), FIELD_PRIME);
    const rhs = FIELD.add(FIELD.add(FIELD.mul(FIELD.mul(x, x), x), FIELD.mul(CURVE_A, x)), CURVE_B);
    let root: bigint;
    try {
      root = FIELD.sqrt(rhs);
    } catch {
      continue;
    }
    const y = root % 2n === 0n ? root : FIELD_PRIME - root;
    try {
      const point = ec.starkCurve.ProjectivePoint.fromAffine({ x, y });
      point.assertValidity();
      if (point.equals(G) || point.equals(ZERO)) continue;
      return point;
    } catch {
      continue;
    }
  }
  throw new Error("Failed to derive an independent FX hedging generator.");
}

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = mod(value, modulus);
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1n) throw new Error("Scalar is not invertible.");
  if (t < 0n) t += modulus;
  return t;
}

function hashElements(elements: (bigint | string)[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function randomScalar(): bigint {
  return (BigInt(hash.computePoseidonHashOnElements([BigInt(Date.now()), BigInt(Math.floor(Math.random() * 1e9))])) % (CURVE_ORDER - 1n)) + 1n;
}

function nonZeroScalar(value: bigint): bigint {
  const v = mod(value, CURVE_ORDER);
  if (v === 0n) throw new Error("Zero scalar is invalid.");
  return v;
}

function defaultId(kind: string): string {
  return `fxh_${kind}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function scalePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const s = mod(scalar, CURVE_ORDER);
  return s === 0n ? ZERO : point.multiply(s);
}

function pedersenCommit(value: bigint, blinding: bigint, h: CurvePoint): CurvePoint {
  return scalePoint(G, value).add(scalePoint(h, blinding));
}

function pointToFelts(point: CurvePoint): CurvePointFelts {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: CurvePointFelts): CurvePoint {
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x), y: requireFelt(point.y) });
  parsed.assertValidity();
  return parsed;
}

function publicKeyFromSecret(secret: bigint): CurvePoint {
  if (secret <= 0n || secret >= CURVE_ORDER) throw new Error("Secret key is outside the Stark curve order.");
  return G.multiply(secret);
}

function requireFelt(value: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new Error("A felt hex string is required.");
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("Felt is out of range.");
  return parsed;
}

function requireScalar(value: string, allowZero = false): bigint {
  const parsed = requireFelt(value);
  if (!allowZero && parsed === 0n) throw new Error("Zero scalar is invalid.");
  if (parsed >= CURVE_ORDER) throw new Error("Scalar is outside the curve order.");
  return parsed;
}

function requireText(value: string, label: string, maxLen: number): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} is required.`);
  if (trimmed.length > maxLen) throw new Error(`${label} is too long.`);
  return trimmed;
}

function requireIsoTimestamp(value: string): string {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) throw new Error("An ISO-8601 timestamp is required.");
  return new Date(ms).toISOString();
}

function requireInt(value: number, label: string, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  return value;
}

function requireBaseUnits(value: string | bigint, label: string): bigint {
  try {
    const parsed = typeof value === "bigint" ? value : BigInt(value);
    if (parsed < 0n) throw new Error(`${label} must be non-negative.`);
    return parsed;
  } catch {
    throw new Error(`${label} must be a base-unit integer string.`);
  }
}

function parseRateScaled(rate: string, rateDecimals: number): bigint {
  const decimals = requireInt(rateDecimals, "rate decimals", 0, MAX_RATE_DECIMALS);
  const trimmed = requireText(rate, "rate", 64);
  const [whole, frac = ""] = trimmed.split(".");
  if (!/^\d+$/.test(whole) || (frac && !/^\d+$/.test(frac))) throw new Error("Rate must be a decimal number.");
  if (frac.length > decimals) throw new Error(`Rate exceeds ${decimals} decimal places.`);
  const padded = `${whole}${frac.padEnd(decimals, "0")}`;
  return BigInt(padded);
}

function commitPair(baseCurrency: string, quoteCurrency: string, salt: bigint): string {
  return toHex(hashElements([PAIR_DOMAIN, hash.starknetKeccak(baseCurrency), hash.starknetKeccak(quoteCurrency), salt]));
}

function commitRef(domain: bigint, value: string, salt: bigint): bigint {
  return hashElements([domain, hash.starknetKeccak(value), salt]);
}

// ---------------------------------------------------------------------------
// Public API — keys, forward math, monitoring
// ---------------------------------------------------------------------------

export function createFxHedgingIssuerKey(entropy: FxHedgingEntropy = {}): FxHedgingKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

export function requireFxHedgingPolicy(policy: FxHedgingPolicy): FxHedgingPolicy {
  if (!policy || typeof policy !== "object") throw new Error("The FX hedging policy is required.");
  return {
    maxTenorDays: requireInt(policy.maxTenorDays, "maximum tenor days", 1, MAX_TENOR_DAYS),
    maxForwardPremiumBps: requireInt(policy.maxForwardPremiumBps, "maximum forward premium bps", 0, MAX_FORWARD_BPS),
    maxForwardDiscountBps: requireInt(policy.maxForwardDiscountBps, "maximum forward discount bps", 0, MAX_FORWARD_BPS),
  };
}

export function computeForwardRate(
  spotRate: string,
  forwardPointsBps: number,
  rateDecimals: number,
  policy: FxHedgingPolicy,
): ForwardRateQuote {
  const parsedPolicy = requireFxHedgingPolicy(policy);
  const points = requireInt(forwardPointsBps, "forward points bps", -MAX_FORWARD_BPS, MAX_FORWARD_BPS);
  const spot = parseRateScaled(spotRate, rateDecimals);
  const locked = (spot * (BPS_SCALE + BigInt(points))) / BPS_SCALE;
  const minLocked = (spot * (BPS_SCALE - BigInt(parsedPolicy.maxForwardDiscountBps))) / BPS_SCALE;
  const maxLocked = (spot * (BPS_SCALE + BigInt(parsedPolicy.maxForwardPremiumBps))) / BPS_SCALE;
  if (locked < minLocked || locked > maxLocked) {
    throw new Error("Locked forward rate falls outside the public policy band.");
  }
  return {
    spotRateScaled: spot.toString(),
    forwardPointsBps: points,
    lockedRateScaled: locked.toString(),
    rateDecimals,
    minLockedRateScaled: minLocked.toString(),
    maxLockedRateScaled: maxLocked.toString(),
  };
}

export function computeHedgingState(
  notionalBaseUnits: string | bigint,
  lockedRateScaled: string | bigint,
  spotRateScaled: string | bigint,
  tenorDays: number,
  policy: FxHedgingPolicy,
): HedgingState {
  const parsedPolicy = requireFxHedgingPolicy(policy);
  const notional = requireBaseUnits(notionalBaseUnits, "notional");
  const locked = requireBaseUnits(lockedRateScaled, "locked rate");
  const spot = requireBaseUnits(spotRateScaled, "spot rate");
  const tenor = requireInt(tenorDays, "tenor days", 0, MAX_TENOR_DAYS);
  const maxTenor = BigInt(parsedPolicy.maxTenorDays);
  const minLocked = (spot * (BPS_SCALE - BigInt(parsedPolicy.maxForwardDiscountBps))) / BPS_SCALE;
  const maxLocked = (spot * (BPS_SCALE + BigInt(parsedPolicy.maxForwardPremiumBps))) / BPS_SCALE;
  const upperSurplus = maxLocked - locked;
  const lowerSurplus = locked - minLocked;
  const tenorSurplus = maxTenor - BigInt(tenor);
  const eligible = upperSurplus >= 0n && lowerSurplus >= 0n && tenorSurplus >= 0n;
  return {
    notionalBaseUnits: notional.toString(),
    lockedRateScaled: locked.toString(),
    spotRateScaled: spot.toString(),
    tenorDays: tenor,
    maxTenorDays: maxTenor.toString(),
    upperSurplus: upperSurplus.toString(),
    lowerSurplus: lowerSurplus.toString(),
    tenorSurplus: tenorSurplus.toString(),
    eligible,
  };
}

function formatRateScaled(scaled: string | bigint, rateDecimals: number): string {
  const value = typeof scaled === "bigint" ? scaled : BigInt(scaled);
  const sign = value < 0n ? "-" : "";
  const abs = value < 0n ? -value : value;
  const whole = abs / 10n ** BigInt(rateDecimals);
  const frac = abs % 10n ** BigInt(rateDecimals);
  if (rateDecimals === 0) return `${sign}${whole.toString()}`;
  const fracStr = frac.toString().padStart(rateDecimals, "0").replace(/0+$/, "");
  return fracStr ? `${sign}${whole.toString()}.${fracStr}` : `${sign}${whole.toString()}`;
}

export function monitorHedgingPositions(
  positions: HedgingPositionInput[],
  currentSpotByPair: Record<string, string>,
  rateDecimals: number,
  assetDecimals: number,
  now: Date = new Date(),
): HedgingMonitorRow[] {
  return positions.map((position) => {
    const pairLabel = `${position.baseCurrency}/${position.quoteCurrency}`;
    const markSpot = currentSpotByPair[pairLabel] ?? position.spotRateScaled;
    const locked = BigInt(position.lockedRateScaled);
    const mark = BigInt(parseRateScaled(markSpot, rateDecimals).toString());
    const pnlBps = locked > 0n ? Number(((mark - locked) * BPS_SCALE) / locked) : 0;
    const settlementMs = Date.parse(requireIsoTimestamp(position.settlementDate));
    const tenorDaysRemaining = Math.max(0, Math.ceil((settlementMs - now.getTime()) / DAY_MS));
    let status: HedgingMonitorRow["status"] = "in-band";
    const minLocked = (BigInt(position.spotRateScaled) * (BPS_SCALE - 500n)) / BPS_SCALE;
    const maxLocked = (BigInt(position.spotRateScaled) * (BPS_SCALE + 500n)) / BPS_SCALE;
    if (tenorDaysRemaining <= 0) status = "expired";
    else if (locked > maxLocked) status = "premium-breach";
    else if (locked < minLocked) status = "discount-breach";
    return {
      positionId: position.positionId,
      pairLabel,
      notionalDisplay: baseUnitsToDecimal(position.notionalBaseUnits, assetDecimals),
      lockedRateDisplay: formatRateScaled(locked, rateDecimals),
      markRateDisplay: formatRateScaled(mark, rateDecimals),
      unrealizedPnlBps: pnlBps.toString(),
      tenorDaysRemaining,
      status,
    };
  });
}

export function formatFxHedgingBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

export function summarizeFxHedgingTrust(): FxHedgingTrustSummary {
  return {
    decentralized: false,
    zeroKnowledge: true,
    poolIntegrated: false,
    oracleBacked: false,
    statement:
      "Client-side Pedersen commitments and surplus range proofs over hidden notional and locked forward rate. " +
      "Spot reference and policy band are public; the STRK20 pool address is never called.",
  };
}

export function getFxHedgingVisibilityModel(): FxHedgingVisibilityModel {
  return {
    hiddenFromVerifier: [
      "Notional base units",
      "Locked forward rate scalar",
      "Base and quote currency labels until disclosed",
      "Counterparty reference until disclosed",
    ],
    disclosedToVerifier: [
      "Merchant alias and desk label",
      "Settlement asset symbol and token address",
      "Public spot reference and policy band",
      "Settlement date, tenor, and issuer public key",
      "Pedersen commitments and range proofs",
    ],
    applicationOnly: ["Issuer secret key", "Blindings and pair salts"],
    limitation: "Verifier learns policy compliance, not fair market prices or counterparty identity unless opened.",
  };
}

// ---------------------------------------------------------------------------
// Proof machinery (bit/range + signature)
// ---------------------------------------------------------------------------

interface BindingFields {
  certificateId: string;
  merchantAlias: string;
  deskLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  spotRateScaled: bigint;
  rateDecimals: number;
  settlementDate: string;
  lockedAt: string;
  tenorDays: bigint;
  maxTenorDays: bigint;
  maxForwardPremiumBps: bigint;
  maxForwardDiscountBps: bigint;
  minLockedRateScaled: bigint;
  maxLockedRateScaled: bigint;
  pairCommitment: bigint;
  counterpartyCommitment: bigint;
  counterpartyCommitted: boolean;
  amountBitLength: number;
  surplusBitLength: number;
  memo: string;
}

function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  notionalCommitment: CurvePoint,
  lockedRateCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(FX_HEDGING_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.deskLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.spotRateScaled,
    BigInt(fields.rateDecimals),
    hash.starknetKeccak(fields.settlementDate),
    hash.starknetKeccak(fields.lockedAt),
    fields.tenorDays,
    fields.maxTenorDays,
    fields.maxForwardPremiumBps,
    fields.maxForwardDiscountBps,
    fields.minLockedRateScaled,
    fields.maxLockedRateScaled,
    fields.pairCommitment,
    fields.counterpartyCommitment,
    fields.counterpartyCommitted ? 1n : 0n,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    notionalCommitment.x,
    notionalCommitment.y,
    lockedRateCommitment.x,
    lockedRateCommitment.y,
    h.x,
    h.y,
  ]);
}

function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

function bitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

function proveBit(
  bit: number,
  commitment: CurvePoint,
  blinding: bigint,
  ctx: bigint,
  leg: number,
  index: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): FxHedgingBitProof {
  const p0 = commitment;
  const p1 = commitment.add(G.negate());
  let a0: CurvePoint;
  let a1: CurvePoint;
  let challenge0: bigint;
  let response0: bigint;
  let response1: bigint;
  if (bit === 0) {
    const k0 = nonZeroScalar(nextScalar());
    a0 = scalePoint(h, k0);
    const e1 = nonZeroScalar(nextScalar());
    const s1 = nonZeroScalar(nextScalar());
    a1 = scalePoint(h, s1).add(scalePoint(p1, e1).negate());
    const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
    challenge0 = mod(e - e1, CURVE_ORDER);
    response0 = mod(k0 + challenge0 * blinding, CURVE_ORDER);
    response1 = s1;
  } else {
    const k1 = nonZeroScalar(nextScalar());
    a1 = scalePoint(h, k1);
    challenge0 = nonZeroScalar(nextScalar());
    response0 = nonZeroScalar(nextScalar());
    a0 = scalePoint(h, response0).add(scalePoint(p0, challenge0).negate());
    const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
    const e1 = mod(e - challenge0, CURVE_ORDER);
    response1 = mod(k1 + e1 * blinding, CURVE_ORDER);
  }
  return {
    commitment: pointToFelts(commitment),
    a0: pointToFelts(a0),
    a1: pointToFelts(a1),
    challenge0: toHex(challenge0),
    response0: toHex(response0),
    response1: toHex(response1),
  };
}

function verifyBit(proof: FxHedgingBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
  try {
    const commitment = pointFromFelts(proof.commitment);
    const a0 = pointFromFelts(proof.a0);
    const a1 = pointFromFelts(proof.a1);
    const challenge0 = requireScalar(proof.challenge0, true);
    const response0 = requireScalar(proof.response0, true);
    const response1 = requireScalar(proof.response1, true);
    const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
    const challenge1 = mod(e - challenge0, CURVE_ORDER);
    const p0 = commitment;
    const p1 = commitment.add(G.negate());
    const ok0 = scalePoint(h, response0).equals(a0.add(scalePoint(p0, challenge0)));
    const ok1 = scalePoint(h, response1).equals(a1.add(scalePoint(p1, challenge1)));
    return ok0 && ok1 ? commitment : null;
  } catch {
    return null;
  }
}

function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): FxHedgingBitProof[] {
  if (value < 0n) throw new Error("Cannot range-prove a negative value.");
  if (value >= 1n << BigInt(bitLength)) throw new Error(`The value exceeds the ${bitLength}-bit band.`);
  const bits: number[] = [];
  for (let i = 0; i < bitLength; i += 1) bits.push(Number((value >> BigInt(i)) & 1n));
  const blindings: bigint[] = [];
  let partial = 0n;
  for (let i = 0; i < bitLength - 1; i += 1) {
    const r = nonZeroScalar(nextScalar());
    blindings.push(r);
    partial = mod(partial + (1n << BigInt(i)) * r, CURVE_ORDER);
  }
  const topWeight = modInverse(1n << BigInt(bitLength - 1), CURVE_ORDER);
  const lastBlinding = mod((blinding - partial) * topWeight, CURVE_ORDER);
  if (lastBlinding === 0n) throw new Error("Degenerate range-proof blinding; retry with fresh entropy.");
  blindings.push(lastBlinding);
  return bits.map((bit, i) => proveBit(bit, pedersenCommit(BigInt(bit), blindings[i], h), blindings[i], ctx, leg, i, h, nextScalar));
}

function verifyRange(proofs: FxHedgingBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return null;
  let acc = ZERO;
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = verifyBit(proofs[i], ctx, leg, i, h);
    if (!commitment) return null;
    acc = acc.add(scalePoint(commitment, 1n << BigInt(i)));
  }
  return acc;
}

function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

function verifySignature(signature: IssuerSignature, bindingHash: bigint, publicKey: CurvePoint): boolean {
  try {
    const challenge = requireScalar(signature.challenge, true);
    const response = requireScalar(signature.response, true);
    const commitment = scalePoint(G, response).add(scalePoint(publicKey, challenge).negate());
    if (commitment.equals(ZERO)) return false;
    const expected = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
    return expected === challenge;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Issue / verify / disclose
// ---------------------------------------------------------------------------

export function issueFxHedgingCertificate(
  input: IssueFxHedgingCertificateInput,
  now: Date = new Date(),
  entropy: FxHedgingEntropy = {},
): IssuedFxHedgingCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;
  const policy = requireFxHedgingPolicy(input.policy);
  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const deskLabel = requireText(input.deskLabel, "desk label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const baseCurrency = requireText(input.baseCurrency, "base currency", 16);
  const quoteCurrency = requireText(input.quoteCurrency, "quote currency", 16);
  const rateDecimals = requireInt(input.rateDecimals, "rate decimals", 0, MAX_RATE_DECIMALS);
  const amountBitLength = requireInt(input.amountBitLength ?? DEFAULT_AMOUNT_BIT_LENGTH, "amount bit length", MIN_AMOUNT_BIT_LENGTH, MAX_AMOUNT_BIT_LENGTH);
  const surplusBitLength = amountBitLength + SURPLUS_EXTRA_BITS;
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const forward = computeForwardRate(input.spotRate, input.forwardPointsBps, rateDecimals, policy);
  const notional = requireBaseUnits(input.notionalBaseUnits, "notional");
  const locked = requireBaseUnits(forward.lockedRateScaled, "locked rate");
  if (notional > U128_MAX || locked > U128_MAX) throw new Error("Notional and rate must fit u128.");

  const settlementDate = requireIsoTimestamp(input.settlementDate);
  const lockedAt = requireIsoTimestamp(now.toISOString());
  const tenorDays = Math.max(0, Math.ceil((Date.parse(settlementDate) - Date.parse(lockedAt)) / DAY_MS));
  const state = computeHedgingState(notional, locked, forward.spotRateScaled, tenorDays, policy);
  if (!state.eligible) throw new Error("Policy surpluses are negative; no honest certificate exists.");

  const upperSurplus = BigInt(state.upperSurplus);
  const lowerSurplus = BigInt(state.lowerSurplus);
  const tenorSurplus = BigInt(state.tenorSurplus);
  if (upperSurplus >= 1n << BigInt(surplusBitLength) || lowerSurplus >= 1n << BigInt(surplusBitLength) || tenorSurplus >= 1n << BigInt(surplusBitLength)) {
    throw new Error("A surplus exceeds the surplus bit band.");
  }

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();
  const notionalBlinding = nonZeroScalar(nextScalar());
  const lockedRateBlinding = nonZeroScalar(nextScalar());
  const upperBlinding = nonZeroScalar(nextScalar());
  const lowerBlinding = nonZeroScalar(nextScalar());
  const tenorBlinding = nonZeroScalar(nextScalar());

  const notionalCommitment = pedersenCommit(notional, notionalBlinding, h);
  const lockedRateCommitment = pedersenCommit(locked, lockedRateBlinding, h);
  const pairSalt = nonZeroScalar(nextScalar());
  const pairCommitment = hashElements([PAIR_DOMAIN, hash.starknetKeccak(baseCurrency), hash.starknetKeccak(quoteCurrency), pairSalt]);
  const counterpartyRef = input.counterpartyRef ? requireText(input.counterpartyRef, "counterparty reference", 96) : "";
  const counterpartyCommitted = counterpartyRef.length > 0;
  const counterpartySalt = nonZeroScalar(nextScalar());
  const counterpartyCommitment = counterpartyCommitted ? commitRef(COUNTERPARTY_DOMAIN, counterpartyRef, counterpartySalt) : 0n;

  const certificateId = createId("certificate");
  const fields: BindingFields = {
    certificateId,
    merchantAlias,
    deskLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    spotRateScaled: BigInt(forward.spotRateScaled),
    rateDecimals,
    settlementDate,
    lockedAt,
    tenorDays: BigInt(tenorDays),
    maxTenorDays: BigInt(policy.maxTenorDays),
    maxForwardPremiumBps: BigInt(policy.maxForwardPremiumBps),
    maxForwardDiscountBps: BigInt(policy.maxForwardDiscountBps),
    minLockedRateScaled: BigInt(forward.minLockedRateScaled),
    maxLockedRateScaled: BigInt(forward.maxLockedRateScaled),
    pairCommitment,
    counterpartyCommitment,
    counterpartyCommitted,
    amountBitLength,
    surplusBitLength,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, notionalCommitment, lockedRateCommitment, h);
  const ctx = statementContext(bindingHash);

  const proof: FxHedgingProof = {
    proofSystem: FX_HEDGING_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    generatorH: pointToFelts(h),
    notionalCommitment: pointToFelts(notionalCommitment),
    lockedRateCommitment: pointToFelts(lockedRateCommitment),
    notionalBits: proveRange(notional, notionalBlinding, amountBitLength, ctx, 0, h, nextScalar),
    lockedRateBits: proveRange(locked, lockedRateBlinding, amountBitLength, ctx, 1, h, nextScalar),
    upperSurplusBits: proveRange(upperSurplus, upperBlinding, surplusBitLength, ctx, 2, h, nextScalar),
    lowerSurplusBits: proveRange(lowerSurplus, lowerBlinding, surplusBitLength, ctx, 3, h, nextScalar),
    tenorSurplusBits: proveRange(tenorSurplus, tenorBlinding, surplusBitLength, ctx, 4, h, nextScalar),
    issuerSignature: signBinding(bindingHash, issuerSecret, nextScalar),
  };

  const certificate: FxHedgingCertificate = {
    kind: CERTIFICATE_KIND,
    version: FX_HEDGING_ENGINE_VERSION,
    certificateId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    merchantAlias,
    deskLabel,
    asset: { symbol: assetSymbol, tokenAddress, decimals: assetDecimals },
    baseCurrencyHash: toHex(hash.starknetKeccak(baseCurrency)),
    quoteCurrencyHash: toHex(hash.starknetKeccak(quoteCurrency)),
    pairCommitment: commitPair(baseCurrency, quoteCurrency, pairSalt),
    counterpartyCommitment: counterpartyCommitted ? toHex(counterpartyCommitment) : "0x0",
    counterpartyCommitted,
    spotRateScaled: forward.spotRateScaled,
    rateDecimals,
    settlementDate,
    lockedAt,
    tenorDays,
    policy,
    minLockedRateScaled: forward.minLockedRateScaled,
    maxLockedRateScaled: forward.maxLockedRateScaled,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    notice: FX_HEDGING_NOTICE,
    limitations: FX_HEDGING_LIMITATIONS,
  };

  const secret: FxHedgingCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    notionalBaseUnits: notional.toString(),
    lockedRateScaled: locked.toString(),
    forwardPointsBps: forward.forwardPointsBps,
    baseCurrency,
    quoteCurrency,
    pairSalt: toHex(pairSalt),
    counterpartyRef,
    counterpartySalt: toHex(counterpartySalt),
    notionalBlinding: toHex(notionalBlinding),
    lockedRateBlinding: toHex(lockedRateBlinding),
  };

  return { certificate, secret };
}

export function verifyFxHedgingCertificate(certificate: FxHedgingCertificate): boolean {
  try {
    validateCertificateShape(certificate);
    const h = pointFromFelts(certificate.proof.generatorH);
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const notionalCommitment = pointFromFelts(certificate.proof.notionalCommitment);
    const lockedRateCommitment = pointFromFelts(certificate.proof.lockedRateCommitment);
    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      deskLabel: certificate.deskLabel,
      assetSymbol: certificate.asset.symbol,
      tokenAddress: certificate.asset.tokenAddress,
      assetDecimals: certificate.asset.decimals,
      spotRateScaled: BigInt(certificate.spotRateScaled),
      rateDecimals: certificate.rateDecimals,
      settlementDate: certificate.settlementDate,
      lockedAt: certificate.lockedAt,
      tenorDays: BigInt(certificate.tenorDays),
      maxTenorDays: BigInt(certificate.policy.maxTenorDays),
      maxForwardPremiumBps: BigInt(certificate.policy.maxForwardPremiumBps),
      maxForwardDiscountBps: BigInt(certificate.policy.maxForwardDiscountBps),
      minLockedRateScaled: BigInt(certificate.minLockedRateScaled),
      maxLockedRateScaled: BigInt(certificate.maxLockedRateScaled),
      pairCommitment: BigInt(certificate.pairCommitment),
      counterpartyCommitment: BigInt(certificate.counterpartyCommitment),
      counterpartyCommitted: certificate.counterpartyCommitted,
      amountBitLength: certificate.proof.amountBitLength,
      surplusBitLength: certificate.proof.surplusBitLength,
      memo: "-",
    };
    const bindingHash = computeBindingHash(fields, issuerKey, notionalCommitment, lockedRateCommitment, h);
    const ctx = statementContext(bindingHash);
    const { amountBitLength, surplusBitLength } = certificate.proof;
    if (!verifyRange(certificate.proof.notionalBits, amountBitLength, ctx, 0, h)?.equals(notionalCommitment)) return false;
    if (!verifyRange(certificate.proof.lockedRateBits, amountBitLength, ctx, 1, h)?.equals(lockedRateCommitment)) return false;
    if (!verifyRange(certificate.proof.upperSurplusBits, surplusBitLength, ctx, 2, h)) return false;
    if (!verifyRange(certificate.proof.lowerSurplusBits, surplusBitLength, ctx, 3, h)) return false;
    if (!verifyRange(certificate.proof.tenorSurplusBits, surplusBitLength, ctx, 4, h)) return false;
    return verifySignature(certificate.proof.issuerSignature, bindingHash, issuerKey);
  } catch {
    return false;
  }
}

function validateCertificateShape(value: unknown): asserts value is FxHedgingCertificate {
  if (!value || typeof value !== "object") throw new Error("Certificate is required.");
  const cert = value as FxHedgingCertificate;
  if (cert.kind !== CERTIFICATE_KIND || cert.version !== FX_HEDGING_ENGINE_VERSION) throw new Error("Certificate kind or version mismatch.");
  if (cert.poolAddress.toLowerCase() !== STRK20_POOL_ADDRESS.toLowerCase()) throw new Error("Pool address mismatch.");
  if (cert.proof.proofSystem !== FX_HEDGING_PROOF_SYSTEM) throw new Error("Proof system mismatch.");
}

export function serializeFxHedgingCertificate(certificate: FxHedgingCertificate): string {
  validateCertificateShape(certificate);
  const serialized = JSON.stringify(certificate, null, 2);
  if (serialized.length > MAX_ENCODED_LENGTH) throw new Error("Certificate is too large.");
  return serialized;
}

export function parseFxHedgingCertificate(serialized: string): FxHedgingCertificate {
  if (typeof serialized !== "string" || !serialized.trim()) throw new Error("Certificate JSON is required.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("Certificate JSON is malformed.");
  }
  validateCertificateShape(parsed);
  if (!verifyFxHedgingCertificate(parsed)) throw new Error("Certificate verification failed.");
  return parsed;
}

export function serializeFxHedgingCertificateSecret(secret: FxHedgingCertificateSecret): string {
  if (secret.kind !== SECRET_KIND) throw new Error("Secret kind mismatch.");
  return JSON.stringify(secret, null, 2);
}

export function parseFxHedgingCertificateSecret(serialized: string): FxHedgingCertificateSecret {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("Secret JSON is malformed.");
  }
  if (!parsed || typeof parsed !== "object" || (parsed as FxHedgingCertificateSecret).kind !== SECRET_KIND) {
    throw new Error("Secret kind mismatch.");
  }
  return parsed as FxHedgingCertificateSecret;
}

export function buildFxHedgingAmountDisclosure(
  certificate: FxHedgingCertificate,
  secret: FxHedgingCertificateSecret,
  field: "notional" | "lockedRate",
): FxHedgingAmountDisclosure {
  validateCertificateShape(certificate);
  if (secret.certificateId !== certificate.certificateId) throw new Error("Secret does not match certificate.");
  const h = pointFromFelts(certificate.proof.generatorH);
  const value = field === "notional" ? requireBaseUnits(secret.notionalBaseUnits, "notional") : requireBaseUnits(secret.lockedRateScaled, "locked rate");
  const blinding = requireScalar(field === "notional" ? secret.notionalBlinding : secret.lockedRateBlinding, false);
  const bindingHash = computeBindingHash(
    {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      deskLabel: certificate.deskLabel,
      assetSymbol: certificate.asset.symbol,
      tokenAddress: certificate.asset.tokenAddress,
      assetDecimals: certificate.asset.decimals,
      spotRateScaled: BigInt(certificate.spotRateScaled),
      rateDecimals: certificate.rateDecimals,
      settlementDate: certificate.settlementDate,
      lockedAt: certificate.lockedAt,
      tenorDays: BigInt(certificate.tenorDays),
      maxTenorDays: BigInt(certificate.policy.maxTenorDays),
      maxForwardPremiumBps: BigInt(certificate.policy.maxForwardPremiumBps),
      maxForwardDiscountBps: BigInt(certificate.policy.maxForwardDiscountBps),
      minLockedRateScaled: BigInt(certificate.minLockedRateScaled),
      maxLockedRateScaled: BigInt(certificate.maxLockedRateScaled),
      pairCommitment: BigInt(certificate.pairCommitment),
      counterpartyCommitment: BigInt(certificate.counterpartyCommitment),
      counterpartyCommitted: certificate.counterpartyCommitted,
      amountBitLength: certificate.proof.amountBitLength,
      surplusBitLength: certificate.proof.surplusBitLength,
      memo: "-",
    },
    pointFromFelts(certificate.issuerPublicKey),
    pointFromFelts(certificate.proof.notionalCommitment),
    pointFromFelts(certificate.proof.lockedRateCommitment),
    h,
  );
  const ctx = statementContext(bindingHash);
  const leg = field === "notional" ? 0 : 1;
  const proofs = field === "notional" ? certificate.proof.notionalBits : certificate.proof.lockedRateBits;
  if (!verifyRange(proofs, certificate.proof.amountBitLength, ctx, leg, h)) throw new Error("Stored proofs do not verify.");
  return { kind: AMOUNT_DISCLOSURE_KIND, certificateId: certificate.certificateId, field, value: value.toString(), blinding: toHex(blinding), proof: proofs };
}

export function verifyFxHedgingAmountDisclosure(
  disclosure: FxHedgingAmountDisclosure,
  certificate: FxHedgingCertificate,
): boolean {
  try {
    if (disclosure.kind !== AMOUNT_DISCLOSURE_KIND || disclosure.certificateId !== certificate.certificateId) return false;
    const h = pointFromFelts(certificate.proof.generatorH);
    const blinding = requireScalar(disclosure.blinding, false);
    const value = requireBaseUnits(disclosure.value, disclosure.field);
    const commitment = pedersenCommit(value, blinding, h);
    const leg = disclosure.field === "notional" ? 0 : 1;
    const bindingHash = computeBindingHash(
      {
        certificateId: certificate.certificateId,
        merchantAlias: certificate.merchantAlias,
        deskLabel: certificate.deskLabel,
        assetSymbol: certificate.asset.symbol,
        tokenAddress: certificate.asset.tokenAddress,
        assetDecimals: certificate.asset.decimals,
        spotRateScaled: BigInt(certificate.spotRateScaled),
        rateDecimals: certificate.rateDecimals,
        settlementDate: certificate.settlementDate,
        lockedAt: certificate.lockedAt,
        tenorDays: BigInt(certificate.tenorDays),
        maxTenorDays: BigInt(certificate.policy.maxTenorDays),
        maxForwardPremiumBps: BigInt(certificate.policy.maxForwardPremiumBps),
        maxForwardDiscountBps: BigInt(certificate.policy.maxForwardDiscountBps),
        minLockedRateScaled: BigInt(certificate.minLockedRateScaled),
        maxLockedRateScaled: BigInt(certificate.maxLockedRateScaled),
        pairCommitment: BigInt(certificate.pairCommitment),
        counterpartyCommitment: BigInt(certificate.counterpartyCommitment),
        counterpartyCommitted: certificate.counterpartyCommitted,
        amountBitLength: certificate.proof.amountBitLength,
        surplusBitLength: certificate.proof.surplusBitLength,
        memo: "-",
      },
      pointFromFelts(certificate.issuerPublicKey),
      pointFromFelts(certificate.proof.notionalCommitment),
      pointFromFelts(certificate.proof.lockedRateCommitment),
      h,
    );
    const ctx = statementContext(bindingHash);
    const opened = verifyRange(disclosure.proof, certificate.proof.amountBitLength, ctx, leg, h);
    return Boolean(opened?.equals(commitment));
  } catch {
    return false;
  }
}

export function buildFxHedgingPairDisclosure(
  certificate: FxHedgingCertificate,
  secret: FxHedgingCertificateSecret,
): FxHedgingPairDisclosure {
  if (secret.certificateId !== certificate.certificateId) throw new Error("Secret does not match certificate.");
  const expected = commitPair(secret.baseCurrency, secret.quoteCurrency, requireScalar(secret.pairSalt, false));
  if (expected !== certificate.pairCommitment) throw new Error("Pair opening does not match commitment.");
  return {
    kind: PAIR_DISCLOSURE_KIND,
    certificateId: certificate.certificateId,
    baseCurrency: secret.baseCurrency,
    quoteCurrency: secret.quoteCurrency,
    pairSalt: secret.pairSalt,
  };
}

export function verifyFxHedgingPairDisclosure(disclosure: FxHedgingPairDisclosure, certificate: FxHedgingCertificate): boolean {
  try {
    if (disclosure.kind !== PAIR_DISCLOSURE_KIND || disclosure.certificateId !== certificate.certificateId) return false;
    return commitPair(disclosure.baseCurrency, disclosure.quoteCurrency, requireScalar(disclosure.pairSalt, false)) === certificate.pairCommitment;
  } catch {
    return false;
  }
}

export function serializeFxHedgingAmountDisclosure(disclosure: FxHedgingAmountDisclosure): string {
  return JSON.stringify(disclosure, null, 2);
}

export function parseFxHedgingAmountDisclosure(serialized: string): FxHedgingAmountDisclosure {
  const parsed = JSON.parse(serialized) as FxHedgingAmountDisclosure;
  if (parsed.kind !== AMOUNT_DISCLOSURE_KIND) throw new Error("Disclosure kind mismatch.");
  return parsed;
}

export function serializeFxHedgingPairDisclosure(disclosure: FxHedgingPairDisclosure): string {
  return JSON.stringify(disclosure, null, 2);
}

export function parseFxHedgingPairDisclosure(serialized: string): FxHedgingPairDisclosure {
  const parsed = JSON.parse(serialized) as FxHedgingPairDisclosure;
  if (parsed.kind !== PAIR_DISCLOSURE_KIND) throw new Error("Disclosure kind mismatch.");
  return parsed;
}
