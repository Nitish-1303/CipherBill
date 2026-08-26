/**
 * CipherBill — Merchant Volume Loyalty & Dynamic Fee-Tier Proof Engine
 * ====================================================================
 *
 * A client-side module that lets a merchant prove, in zero knowledge, a PUBLIC
 * loyalty tier — and the dynamic protocol-fee discount and tokenized cashback
 * rate that tier carries — over their PRIVATE monthly settlement volumes,
 * WITHOUT revealing any single month, the aggregate volume, or the cashback
 * amount. Each monthly volume is hidden inside a Pedersen commitment over the
 * STARK curve; the commitments sum homomorphically to a hidden aggregate; a
 * bit-decomposition range proof binds every month and the aggregate to a
 * non-negative band; two coverage range proofs attest the aggregate clears the
 * proven tier's public floor and stays below the next tier's floor; and a pair
 * of remainder range proofs on a homomorphic point attest the hidden cashback
 * commitment is EXACTLY floor(cashbackBps · volume / 10000) — all without
 * opening a single figure. The merchant signs the binding so anyone can
 * authenticate the attestation offline, and any figure can be selectively
 * disclosed later (the cashback opening doubles as a rebate-claim voucher a
 * counterparty settles out of band). Fiat–Shamir makes every proof
 * non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that a merchant's hidden monthly volumes aggregate into a
 *   total that sits in a PUBLIC tier band, and that the hidden cashback
 *   commitment is the exact floor of the tier's public cashback rate applied to
 *   that hidden total. A verifier learns the tier, the fee-discount rate, the
 *   cashback rate, and the tier floors — never a month, the total, the cashback
 *   amount, the blindings, or any customer.
 * - Issuer-authenticated with a Schnorr signature anyone can check offline.
 * - Selectively disclosable per figure, and fully openable to a counterparty.
 * - Self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It does NOT reduce, refund, or apply any protocol fee, and does NOT pay,
 *   mint, transfer, or settle any cashback or rebate. The fee discount and
 *   cashback are rates and amounts a counterparty applies out of band in its own
 *   systems; nothing here moves funds or lowers on-chain gas.
 * - It does NOT read from or write to the STRK20 pool contract; the pool
 *   address below is provenance only.
 * - It does NOT verify that the committed volumes are real. It binds
 *   merchant-supplied figures; it cannot confirm any payment ever settled.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   attestations and no contract, oracle, scheduler, or consensus vouches for
 *   the inputs. It is not a loyalty-program guarantee and not financial advice.
 *   `summarizeLoyaltyTrust()` and `getLoyaltyVisibilityModel()` state these limits.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const LOYALTY_ENGINE_VERSION = 1 as const;
export const LOYALTY_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const LOYALTY_PROOF_SYSTEM = "stark-pedersen-loyalty-rebate-v1" as const;

/** Basis-point denominator for the fee-discount and cashback rates (100% = 10000 bps). */
export const LOYALTY_BPS_DENOMINATOR = 10_000n;
/** Ceiling on any tier's PUBLIC protocol-fee discount rate (≤ 50%). */
export const MAX_LOYALTY_FEE_DISCOUNT_BPS = 5_000;
/** Ceiling on any tier's PUBLIC cashback rate (≤ 25%). */
export const MAX_LOYALTY_CASHBACK_BPS = 2_500;
/** Number of tiers the public ladder may define. */
export const MIN_LOYALTY_TIERS = 1;
export const MAX_LOYALTY_TIERS = 8;
/** Number of monthly volumes a single attestation may aggregate. */
export const MIN_LOYALTY_MONTHS = 1;
export const MAX_LOYALTY_MONTHS = 24;
/** Bit band for the hidden monthly volumes, the aggregate, and the coverage gaps. */
export const DEFAULT_LOYALTY_AMOUNT_BIT_LENGTH = 96;
export const MIN_LOYALTY_AMOUNT_BIT_LENGTH = 8;
export const MAX_LOYALTY_AMOUNT_BIT_LENGTH = 128;
/**
 * Fixed bit band for the cashback remainder legs. The remainder of
 * cashbackBps·volume modulo 10000 lies in [0, 9999], so 14 bits (< 16384) is the
 * tightest power-of-two band that contains it; the two-sided remainder proof
 * then pins it to [0, 9999] and forces the cashback to the exact floor.
 */
export const LOYALTY_REMAINDER_BIT_LENGTH = 14;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;
const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill loyalty generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill loyalty statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill loyalty bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill loyalty binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill loyalty issuer signature v1");
const TIER_DOMAIN = hash.starknetKeccak("CipherBill loyalty tier ladder v1");
const ACCOUNT_DOMAIN = hash.starknetKeccak("CipherBill loyalty account ref v1");
const CERTIFICATE_KIND = "cipherbill.loyalty-certificate" as const;
const SECRET_KIND = "cipherbill.loyalty-certificate-secret" as const;
const METRIC_DISCLOSURE_KIND = "cipherbill.loyalty-metric-disclosure" as const;
const MONTH_DISCLOSURE_KIND = "cipherbill.loyalty-month-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.loyalty-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.loyalty-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.loyalty-keypair" as const;
const MAX_ENCODED_LENGTH = 1_400_000;

/** Proof-leg identifiers, kept distinct from the monthly leg indices (0 … monthCount − 1). */
const LEG_TOTAL = 900;
const LEG_TIER_LOWER = 901;
const LEG_TIER_UPPER = 902;
const LEG_CASHBACK = 903;
const LEG_REMAINDER_LOWER = 904;
const LEG_REMAINDER_UPPER = 905;

/** A selectively disclosable aggregate figure. */
export type LoyaltyMetric = "total" | "cashback";

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface LoyaltyAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface LoyaltyKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface LoyaltyEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}
/**
 * One rung of the PUBLIC loyalty ladder. The verifier sees every field: the
 * floor fixes the aggregate-volume band the tier covers, and the two rates fix
 * the dynamic fee discount and cashback that tier carries. None of this reveals
 * any hidden volume.
 */
export interface LoyaltyTier {
  /** PUBLIC human-readable tier name (e.g. "Silver"). */
  name: string;
  /** PUBLIC inclusive aggregate-volume floor for this tier, in base units. Tier 0 must be 0. */
  floorBaseUnits: string;
  /** PUBLIC protocol-fee discount rate carried by this tier, in basis points. */
  feeDiscountBps: number;
  /** PUBLIC cashback rate carried by this tier, in basis points. */
  cashbackBps: number;
}

/**
 * A public loyalty policy: the strictly ascending tier ladder. The verifier
 * sees every rung. `tiers[0].floorBaseUnits` must be "0" so every merchant
 * qualifies for the base tier.
 */
export interface LoyaltyPolicy {
  tiers: LoyaltyTier[];
}

/** The private monthly figures a merchant commits to. None are ever published in the clear. */
export interface LoyaltyMetrics {
  /** SECRET per-month settled volumes in base units. Their hidden sum sets the tier. */
  monthlyVolumesBaseUnits: string[];
}

/** The pure, proof-free breakdown of a loyalty assessment. Computed locally; never fully published. */
export interface LoyaltyState {
  monthlyVolumesBaseUnits: string[];
  monthCount: number;
  /** The hidden aggregate volume (sum of the months). Never published in the clear. */
  totalVolumeBaseUnits: string;
  /** Index of the highest tier whose floor the aggregate clears. */
  tierIndex: number;
  tierName: string;
  /** PUBLIC fee-discount rate of the assigned tier, in basis points. */
  feeDiscountBps: number;
  /** PUBLIC cashback rate of the assigned tier, in basis points. */
  cashbackBps: number;
  /** floor(cashbackBps · total / 10000), in base units. Hidden; proven exact. */
  cashbackBaseUnits: string;
  /** PUBLIC floor of the assigned tier, in base units. */
  tierFloorBaseUnits: string;
  /** PUBLIC floor of the next tier, in base units, or null at the top tier. */
  nextTierFloorBaseUnits: string | null;
  /** Aggregate still needed to reach the next tier, in base units, or null at the top. Application-only. */
  volumeToNextTierBaseUnits: string | null;
  /** Progress through the current tier band toward the next floor, in bps. Application-only. */
  tierProgressBps: string;
  isTopTier: boolean;
}
export interface IssueLoyaltyCertificateInput {
  merchantAlias: string;
  asset: LoyaltyAsset;
  /** PUBLIC label of the aggregation period this attestation covers (e.g. "FY26 H1"). */
  periodLabel: string;
  /** PUBLIC human-readable loyalty-program label. */
  programLabel: string;
  /** PUBLIC loyalty policy: the ascending tier ladder. */
  policy: LoyaltyPolicy;
  /** SECRET private monthly volumes being committed and aggregated. */
  metrics: LoyaltyMetrics;
  /** SECRET opaque account/loyalty-member reference; only a salted commitment is published. */
  accountRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface LoyaltyBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

/** Schnorr signature (challenge, response) over the binding by the issuer key. */
export interface LoyaltyIssuerSignature {
  challenge: string;
  response: string;
}
/**
 * Zero-knowledge proof bundle. Range legs bound the hidden figures and derived
 * homomorphic points enforce the tier band and the exact cashback:
 *   monthly[i]     v_i ∈ [0, 2^amountBits)             (tied to C_i);
 *   total          V   ∈ [0, 2^amountBits)             (tied to ΣC_i ⇒ V bounded);
 *   tierLower      V − tierFloor       ∈ [0, 2^amountBits) (tied to ΣC_i − floor·G ⇒ V ≥ floor);
 *   tierUpper      (nextFloor−1) − V   ∈ [0, 2^amountBits) (tied to (nextFloor−1)·G − ΣC_i ⇒ V < nextFloor);
 *                  omitted at the top tier, which has no upper floor;
 *   cashback       c   ∈ [0, 2^amountBits)             (tied to C_cash);
 *   remainderLower rem ∈ [0, 2^remBits)                (tied to D = cashbackBps·ΣC_i − 10000·C_cash);
 *   remainderUpper (9999 − rem) ∈ [0, 2^remBits)       (tied to 9999·G − D);
 * the two remainder legs pin rem ∈ [0, 9999], forcing c = floor(cashbackBps·V / 10000).
 */
export interface LoyaltyProof {
  proofSystem: typeof LOYALTY_PROOF_SYSTEM;
  amountBitLength: number;
  remainderBitLength: number;
  generatorH: CurvePointFelts;
  monthlyCommitments: CurvePointFelts[];
  cashbackCommitment: CurvePointFelts;
  monthlyBits: LoyaltyBitProof[][];
  totalBits: LoyaltyBitProof[];
  tierLowerBits: LoyaltyBitProof[];
  /** Empty at the top tier (no next floor to bound against). */
  tierUpperBits: LoyaltyBitProof[];
  cashbackBits: LoyaltyBitProof[];
  remainderLowerBits: LoyaltyBitProof[];
  remainderUpperBits: LoyaltyBitProof[];
}
export interface LoyaltyCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof LOYALTY_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  merchantAlias: string;
  periodLabel: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC tier ladder the aggregate was measured against. */
  tiers: LoyaltyTier[];
  /** PUBLIC number of monthly volumes aggregated (a count, never an amount). */
  monthCount: number;
  /** PUBLIC index of the proven tier within the ladder. */
  tierIndex: number;
  /** PUBLIC name of the proven tier. */
  tierName: string;
  /** PUBLIC fee-discount rate of the proven tier, in basis points. */
  feeDiscountBps: string;
  /** PUBLIC cashback rate of the proven tier, in basis points. */
  cashbackBps: string;
  /** PUBLIC floor of the proven tier, in base units (proven cleared). */
  tierFloorBaseUnits: string;
  /** PUBLIC floor of the next tier, in base units, or "" at the top tier (proven not reached). */
  nextTierFloorBaseUnits: string;
  /** Salted Poseidon commitment to the account reference; hides the value. */
  accountCommitment: string;
  accountCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: LoyaltyProof;
  issuerSignature: LoyaltyIssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}
/** SECRET issuer record of a freshly issued attestation. Never publish it. */
export interface LoyaltyCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  monthlyVolumesBaseUnits: string[];
  monthlyBlindings: string[];
  totalVolumeBaseUnits: string;
  /** Aggregate blinding r_total = Σ r_i (mod n), backing the ΣC_i commitment. */
  totalBlinding: string;
  cashbackBaseUnits: string;
  cashbackBlinding: string;
  accountRef: string;
  accountSalt: string;
  accountCommitted: boolean;
}

export interface IssuedLoyaltyCertificate {
  certificate: LoyaltyCertificate;
  secret: LoyaltyCertificateSecret;
}

/** A full opening the merchant can hand a counterparty to disclose every committed figure. */
export interface LoyaltyCertificateOpening {
  monthlyVolumesBaseUnits: string[];
  monthlyBlindings: string[];
  totalVolumeBaseUnits: string;
  totalBlinding: string;
  cashbackBaseUnits: string;
  cashbackBlinding: string;
}

/** Selective disclosure of a single aggregate figure (the total, or the cashback). */
export interface LoyaltyMetricDisclosure {
  kind: typeof METRIC_DISCLOSURE_KIND;
  certificateId: string;
  metric: LoyaltyMetric;
  valueBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of one hidden month. */
export interface LoyaltyMonthDisclosure {
  kind: typeof MONTH_DISCLOSURE_KIND;
  certificateId: string;
  monthIndex: number;
  valueBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of the committed account reference. */
export interface LoyaltyRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: "account";
  value: string;
  salt: string;
}
export interface LoyaltyCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  merchantAlias: string;
  periodLabel: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  tierName: string;
  tierIndex: number;
  monthCount: number;
  feeDiscountDisplay: string;
  cashbackDisplay: string;
  tierFloorDisplay: string;
  nextTierFloorDisplay: string;
  accountCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface LoyaltyTrustModel {
  isZeroKnowledge: boolean;
  provesAggregateInTierBand: boolean;
  provesCashbackIsExactFloorOfRate: boolean;
  provesEveryMonthNonNegative: boolean;
  hidesMonthlyVolumes: boolean;
  hidesAggregateVolume: boolean;
  hidesCashbackAmount: boolean;
  hidesCustomerLists: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  appliesOrReducesProtocolFee: boolean;
  paysOrSettlesCashback: boolean;
  reducesGas: boolean;
  movesPoolFunds: boolean;
  verifiesVolumesAreReal: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  isLoyaltyProgramGuaranteeOrFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface LoyaltyVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}
const LOYALTY_NOTICE =
  "Zero-knowledge proof that a merchant's hidden monthly settlement volumes aggregate into a total that lies in a public loyalty tier band, and that a hidden cashback commitment equals exactly floor(cashbackBps · total / 10000) for that tier's public rate — hiding every month, the aggregate, the cashback amount, the blindings, and the customer list. It authenticates the issuer and supports selective disclosure; it does not apply, reduce, or refund any protocol fee, does not pay, mint, or settle any cashback, does not reduce gas, does not verify that the committed volumes are real, is neither decentralized nor automatic, is not a loyalty-program guarantee or financial advice, and never reads from or writes to the STRK20 pool contract.";
// ---------------------------------------------------------------------------
// Curve primitives
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

/**
 * A second Pedersen generator H with no known discrete log relative to G.
 * Derived by hash-and-increment from a fixed domain seed (nothing-up-my-sleeve):
 * hash a counter to a field element, keep it when it is a valid x-coordinate,
 * and canonicalize to the even-y point. The STARK curve has prime order and
 * cofactor 1, so any on-curve point is a full-order generator.
 */
function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

/** Returns the canonical H as serializable felts (for embedding in a certificate). */
export function deriveLoyaltyGenerator(): CurvePointFelts {
  return pointToFelts(independentGenerator());
}

/**
 * Deterministically hashes a seed to an independent curve point by
 * hash-and-increment, so its discrete log relative to G is unknown by construction.
 */
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
  throw new Error("Failed to derive an independent loyalty generator.");
}
/** scalar·point, tolerating a zero scalar (noble rejects multiply(0)). */
function scalePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const s = mod(scalar, CURVE_ORDER);
  return s === 0n ? ZERO : point.multiply(s);
}

/** Pedersen commitment value·G + blinding·H. */
function pedersenCommit(value: bigint, blinding: bigint, h: CurvePoint): CurvePoint {
  return scalePoint(G, value).add(scalePoint(h, blinding));
}

function pointToFelts(point: CurvePoint): CurvePointFelts {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: CurvePointFelts): CurvePoint {
  if (!point || typeof point !== "object") throw new Error("Curve point is missing.");
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x), y: requireFelt(point.y) });
  parsed.assertValidity();
  return parsed;
}

function publicKeyFromSecret(secret: bigint): CurvePoint {
  if (secret <= 0n || secret >= CURVE_ORDER) throw new Error("Secret key is outside the Stark curve order.");
  return G.multiply(secret);
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/** A merchant issuing keypair. The secret signs attestations; the public key authenticates them. */
export function createLoyaltyIssuerKey(entropy: LoyaltyEntropy = {}): LoyaltyKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}
// ---------------------------------------------------------------------------
// Tier ladder, aggregate, cashback, and state (pure)
// ---------------------------------------------------------------------------

interface NormalizedLoyaltyTier {
  name: string;
  floor: bigint;
  feeDiscountBps: number;
  cashbackBps: number;
}

/** Validates and normalizes a public tier ladder: ascending floors, tier 0 at floor 0, bounded rates. */
export function requireLoyaltyPolicy(policy: LoyaltyPolicy): NormalizedLoyaltyTier[] {
  if (!policy || typeof policy !== "object" || !Array.isArray(policy.tiers)) {
    throw new Error("The loyalty policy must define a tier ladder.");
  }
  const count = policy.tiers.length;
  if (count < MIN_LOYALTY_TIERS || count > MAX_LOYALTY_TIERS) {
    throw new Error(`The tier ladder must define between ${MIN_LOYALTY_TIERS} and ${MAX_LOYALTY_TIERS} tiers.`);
  }
  const tiers: NormalizedLoyaltyTier[] = [];
  let previousFloor = -1n;
  for (let i = 0; i < count; i += 1) {
    const raw = policy.tiers[i];
    if (!raw || typeof raw !== "object") throw new Error(`Tier ${i} is malformed.`);
    const name = requireText(raw.name, `tier ${i} name`, 48);
    const floor = requireBaseUnits(raw.floorBaseUnits, `tier ${i} floor`);
    const feeDiscountBps = requireInt(raw.feeDiscountBps, `tier ${i} fee-discount bps`, 0, MAX_LOYALTY_FEE_DISCOUNT_BPS);
    const cashbackBps = requireInt(raw.cashbackBps, `tier ${i} cashback bps`, 0, MAX_LOYALTY_CASHBACK_BPS);
    if (i === 0 && floor !== 0n) throw new Error("The base tier (tier 0) must have a floor of 0.");
    if (floor <= previousFloor) throw new Error("Tier floors must be strictly ascending.");
    previousFloor = floor;
    tiers.push({ name, floor, feeDiscountBps, cashbackBps });
  }
  return tiers;
}

/** The index of the highest tier whose floor the aggregate volume clears. */
export function tierIndexForVolume(total: bigint, tiers: NormalizedLoyaltyTier[]): number {
  let index = 0;
  for (let i = 0; i < tiers.length; i += 1) {
    if (total >= tiers[i].floor) index = i;
    else break;
  }
  return index;
}

/** floor(cashbackBps · total / 10000): the exact tokenized cashback the proof pins down. */
export function computeCashback(cashbackBps: number, total: bigint): bigint {
  return (BigInt(cashbackBps) * total) / LOYALTY_BPS_DENOMINATOR;
}
/** Parses and bounds the SECRET monthly volumes, returning the values and their sum. */
function requireMonthlyVolumes(metrics: LoyaltyMetrics): { months: bigint[]; total: bigint } {
  if (!metrics || !Array.isArray(metrics.monthlyVolumesBaseUnits)) {
    throw new Error("The monthly volumes are required.");
  }
  const raw = metrics.monthlyVolumesBaseUnits;
  if (raw.length < MIN_LOYALTY_MONTHS || raw.length > MAX_LOYALTY_MONTHS) {
    throw new Error(`The attestation must aggregate between ${MIN_LOYALTY_MONTHS} and ${MAX_LOYALTY_MONTHS} months.`);
  }
  const months: bigint[] = [];
  let total = 0n;
  for (let i = 0; i < raw.length; i += 1) {
    const value = requireBaseUnits(raw[i], `month ${i + 1} volume`);
    if (value > U128_MAX) throw new Error(`Month ${i + 1} volume must fit within the u128 range.`);
    months.push(value);
    total += value;
  }
  return { months, total };
}

/**
 * Computes the pure loyalty state: the aggregate volume, the tier it lands in,
 * that tier's public fee-discount and cashback rates, the exact cashback amount,
 * and the progress toward the next tier. This is the same relation the
 * zero-knowledge proof attests.
 */
export function computeLoyaltyState(metrics: LoyaltyMetrics, policy: LoyaltyPolicy): LoyaltyState {
  const tiers = requireLoyaltyPolicy(policy);
  const { months, total } = requireMonthlyVolumes(metrics);
  const tierIndex = tierIndexForVolume(total, tiers);
  const tier = tiers[tierIndex];
  const isTopTier = tierIndex === tiers.length - 1;
  const nextFloor = isTopTier ? null : tiers[tierIndex + 1].floor;
  const cashback = computeCashback(tier.cashbackBps, total);
  const volumeToNext = nextFloor === null ? null : nextFloor - total;
  let tierProgressBps = "10000";
  if (nextFloor !== null) {
    const span = nextFloor - tier.floor;
    tierProgressBps = span > 0n ? (((total - tier.floor) * LOYALTY_BPS_DENOMINATOR) / span).toString() : "0";
  }
  return {
    monthlyVolumesBaseUnits: months.map((m) => m.toString()),
    monthCount: months.length,
    totalVolumeBaseUnits: total.toString(),
    tierIndex,
    tierName: tier.name,
    feeDiscountBps: tier.feeDiscountBps,
    cashbackBps: tier.cashbackBps,
    cashbackBaseUnits: cashback.toString(),
    tierFloorBaseUnits: tier.floor.toString(),
    nextTierFloorBaseUnits: nextFloor === null ? null : nextFloor.toString(),
    volumeToNextTierBaseUnits: volumeToNext === null ? null : volumeToNext.toString(),
    tierProgressBps,
    isTopTier,
  };
}
export function formatLoyaltyBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

/** Formats a rate expressed in basis points, e.g. 250 → "2.5%", 500 → "5%". */
export function formatLoyaltyBps(bps: string | number | bigint): string {
  const n = Number(bps);
  return `${(n / 100).toString()}%`;
}

// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  certificateId: string;
  merchantAlias: string;
  periodLabel: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  tiers: NormalizedLoyaltyTier[];
  monthCount: number;
  tierIndex: number;
  amountBitLength: number;
  remainderBitLength: number;
  accountCommitment: bigint;
  accountCommitted: boolean;
  createdAt: string;
  memo: string;
}

/** Flattens the public tier ladder into field elements so it can be bound into the hash. */
function tierLadderElements(tiers: NormalizedLoyaltyTier[]): bigint[] {
  const elements: bigint[] = [TIER_DOMAIN, BigInt(tiers.length)];
  for (const tier of tiers) {
    elements.push(hash.starknetKeccak(tier.name), tier.floor, BigInt(tier.feeDiscountBps), BigInt(tier.cashbackBps));
  }
  return elements;
}
/**
 * The certificate binding hash: a Poseidon digest over every public,
 * proof-independent field plus the full tier ladder, every monthly commitment,
 * the cashback commitment, and the generator H. Every range-proof challenge and
 * the issuer signature are bound to it, so no field can be altered without
 * invalidating the certificate.
 */
function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  monthlyCommitments: CurvePoint[],
  cashbackCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  const elements: bigint[] = [
    BINDING_DOMAIN,
    BigInt(LOYALTY_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.periodLabel),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    ...tierLadderElements(fields.tiers),
    BigInt(fields.monthCount),
    BigInt(fields.tierIndex),
    BigInt(fields.amountBitLength),
    BigInt(fields.remainderBitLength),
    fields.accountCommitment,
    fields.accountCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    cashbackCommitment.x,
    cashbackCommitment.y,
    h.x,
    h.y,
  ];
  for (const commitment of monthlyCommitments) {
    elements.push(commitment.x, commitment.y);
  }
  return hashElements(elements);
}

/** Context digest that seeds every range-proof challenge, bound to the certificate. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/** Per-bit Fiat–Shamir challenge, bound to the context, the proof leg, the bit index, and both nonces. */
function bitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

/** Salted Poseidon commitment to a reference string; hiding and binding. */
function commitRef(domain: bigint, value: string, salt: bigint): bigint {
  return hashElements([domain, hash.starknetKeccak(value), salt]);
}
// ---------------------------------------------------------------------------
// Per-bit one-of-two (OR) proof
// ---------------------------------------------------------------------------

/**
 * Proves the commitment C = bit·G + r·H opens to 0 OR to 1, in zero knowledge.
 * Branch 0 witness proves C = r·H; branch 1 witness proves C − G = r·H. The
 * false branch is simulated (pick its challenge/response, back out its nonce);
 * the real branch is completed after the Fiat–Shamir challenge is fixed.
 */
function proveBit(
  bit: number,
  commitment: CurvePoint,
  blinding: bigint,
  ctx: bigint,
  leg: number,
  index: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): LoyaltyBitProof {
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
function verifyBit(proof: LoyaltyBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
  let commitment: CurvePoint;
  let a0: CurvePoint;
  let a1: CurvePoint;
  let challenge0: bigint;
  let response0: bigint;
  let response1: bigint;
  try {
    commitment = pointFromFelts(proof.commitment);
    a0 = pointFromFelts(proof.a0);
    a1 = pointFromFelts(proof.a1);
    challenge0 = requireScalar(proof.challenge0, true);
    response0 = requireScalar(proof.response0, true);
    response1 = requireScalar(proof.response1, true);
  } catch {
    return null;
  }
  const p0 = commitment;
  const p1 = commitment.add(G.negate());
  const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
  const challenge1 = mod(e - challenge0, CURVE_ORDER);
  const ok0 = scalePoint(h, response0).equals(a0.add(scalePoint(p0, challenge0)));
  const ok1 = scalePoint(h, response1).equals(a1.add(scalePoint(p1, challenge1)));
  return ok0 && ok1 ? commitment : null;
}

// ---------------------------------------------------------------------------
// Bit-decomposition range proof (a leg of the certificate)
// ---------------------------------------------------------------------------

/**
 * Proves `value ∈ [0, 2^bitLength)` by committing each bit and proving each is
 * 0 or 1. The per-bit blindings are chosen so that `Σ 2^i·r_i ≡ blinding (mod n)`,
 * so the homomorphic sum `Σ 2^i·C_i` reconstructs the target commitment exactly —
 * tying the range proof to that commitment (or derived homomorphic point).
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): LoyaltyBitProof[] {
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
  const proofs: LoyaltyBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies every bit and returns the reconstructed commitment `Σ 2^i·C_i`, or null. */
function verifyRange(proofs: LoyaltyBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return null;
  let acc = ZERO;
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = verifyBit(proofs[i], ctx, leg, i, h);
    if (!commitment) return null;
    acc = acc.add(scalePoint(commitment, 1n << BigInt(i)));
  }
  return acc;
}
// ---------------------------------------------------------------------------
// Issuer Schnorr signature over the binding hash
// ---------------------------------------------------------------------------

/** Signs the binding hash with the issuer scalar so anyone can authenticate it offline. */
function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): LoyaltyIssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

/** Verifies the issuer Schnorr signature against the published public key. */
function verifySignature(signature: LoyaltyIssuerSignature, bindingHash: bigint, publicKey: CurvePoint): boolean {
  let challenge: bigint;
  let response: bigint;
  try {
    challenge = requireScalar(signature.challenge, true);
    response = requireScalar(signature.response, true);
  } catch {
    return false;
  }
  const commitment = scalePoint(G, response).add(scalePoint(publicKey, challenge).negate());
  if (commitment.equals(ZERO)) return false;
  const expected = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  return expected === challenge;
}
// ---------------------------------------------------------------------------
// Issue and verify a loyalty certificate
// ---------------------------------------------------------------------------

/**
 * Issues a zero-knowledge merchant loyalty certificate. It commits every hidden
 * monthly volume, proves each is a bounded non-negative integer, proves their
 * hidden aggregate lands in the proven tier's public band (≥ this floor, and —
 * below the top tier — < the next floor), and proves a hidden cashback
 * commitment equals exactly floor(cashbackBps · aggregate / 10000) for the
 * tier's public rate — all without revealing any figure. Throws when the inputs
 * exceed the proven bit band, because no honest proof exists in that case.
 */
export function issueLoyaltyCertificate(
  input: IssueLoyaltyCertificateInput,
  now: Date = new Date(),
  entropy: LoyaltyEntropy = {},
): IssuedLoyaltyCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const periodLabel = requireText(input.periodLabel, "period label", 96);
  const programLabel = requireText(input.programLabel, "program label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const tiers = requireLoyaltyPolicy(input.policy);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_LOYALTY_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_LOYALTY_AMOUNT_BIT_LENGTH,
    MAX_LOYALTY_AMOUNT_BIT_LENGTH,
  );
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";
  const { months, total } = requireMonthlyVolumes(input.metrics);

  const amountCeiling = 1n << BigInt(amountBitLength);
  for (let i = 0; i < months.length; i += 1) {
    if (months[i] >= amountCeiling) throw new Error(`Month ${i + 1} volume exceeds the ${amountBitLength}-bit band.`);
  }
  if (total >= amountCeiling) throw new Error(`The aggregate volume exceeds the ${amountBitLength}-bit band.`);
  for (let i = 0; i < tiers.length; i += 1) {
    if (tiers[i].floor >= amountCeiling) throw new Error(`Tier ${i} floor exceeds the ${amountBitLength}-bit band.`);
  }

  const tierIndex = tierIndexForVolume(total, tiers);
  const tier = tiers[tierIndex];
  const isTopTier = tierIndex === tiers.length - 1;
  const nextFloor = isTopTier ? null : tiers[tierIndex + 1].floor;
  const cashbackBps = BigInt(tier.cashbackBps);
  const cashback = computeCashback(tier.cashbackBps, total);
  const remainder = cashbackBps * total - LOYALTY_BPS_DENOMINATOR * cashback;
  // __CBT_ISSUE__
  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();

  const monthlyBlindings: bigint[] = [];
  const monthlyCommitments: CurvePoint[] = [];
  let totalBlinding = 0n;
  for (let i = 0; i < months.length; i += 1) {
    const r = nonZeroScalar(nextScalar());
    monthlyBlindings.push(r);
    monthlyCommitments.push(pedersenCommit(months[i], r, h));
    totalBlinding = mod(totalBlinding + r, CURVE_ORDER);
  }
  const cashbackBlinding = nonZeroScalar(nextScalar());
  const cashbackCommitment = pedersenCommit(cashback, cashbackBlinding, h);

  const accountRef = input.accountRef ? requireText(input.accountRef, "account reference", 128) : "";
  const accountCommitted = accountRef.length > 0;
  const accountSalt = nonZeroScalar(nextScalar());
  const accountCommitment = accountCommitted ? commitRef(ACCOUNT_DOMAIN, accountRef, accountSalt) : 0n;

  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());
  const fields: BindingFields = {
    certificateId,
    merchantAlias,
    periodLabel,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    tiers,
    monthCount: months.length,
    tierIndex,
    amountBitLength,
    remainderBitLength: LOYALTY_REMAINDER_BIT_LENGTH,
    accountCommitment,
    accountCommitted,
    createdAt,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, monthlyCommitments, cashbackCommitment, h);
  const ctx = statementContext(bindingHash);
  // __CBT_ISSUE2__
  // Range legs. Each hidden month is a bounded non-negative integer; the
  // aggregate leg (forced blinding r_total = Σ r_i) bounds the sum ΣC_i.
  const monthlyBits: LoyaltyBitProof[][] = [];
  for (let i = 0; i < months.length; i += 1) {
    monthlyBits.push(proveRange(months[i], monthlyBlindings[i], amountBitLength, ctx, i, h, nextScalar));
  }
  const totalBits = proveRange(total, totalBlinding, amountBitLength, ctx, LEG_TOTAL, h, nextScalar);

  // Tier lower: (total − floor) tied to ΣC_i − floor·G (the floor·G term has no H part).
  const tierLowerBits = proveRange(total - tier.floor, totalBlinding, amountBitLength, ctx, LEG_TIER_LOWER, h, nextScalar);
  // Tier upper: (nextFloor − 1 − total) tied to (nextFloor − 1)·G − ΣC_i, under −r_total. Omitted at the top tier.
  const tierUpperBits =
    nextFloor === null
      ? []
      : proveRange(nextFloor - 1n - total, mod(-totalBlinding, CURVE_ORDER), amountBitLength, ctx, LEG_TIER_UPPER, h, nextScalar);

  // Cashback commitment holds c = floor(cashbackBps·total / 10000); prove it is a bounded non-negative integer.
  const cashbackBits = proveRange(cashback, cashbackBlinding, amountBitLength, ctx, LEG_CASHBACK, h, nextScalar);

  // Remainder legs on D = cashbackBps·ΣC_i − 10000·C_cash = rem·G + r_D·H, with
  // r_D = cashbackBps·r_total − 10000·r_cash. Pinning rem ∈ [0, 9999] forces c to the exact floor.
  const remainderBlinding = mod(cashbackBps * totalBlinding - LOYALTY_BPS_DENOMINATOR * cashbackBlinding, CURVE_ORDER);
  const remainderLowerBits = proveRange(remainder, remainderBlinding, LOYALTY_REMAINDER_BIT_LENGTH, ctx, LEG_REMAINDER_LOWER, h, nextScalar);
  const remainderUpperBits = proveRange(
    LOYALTY_BPS_DENOMINATOR - 1n - remainder,
    mod(-remainderBlinding, CURVE_ORDER),
    LOYALTY_REMAINDER_BIT_LENGTH,
    ctx,
    LEG_REMAINDER_UPPER,
    h,
    nextScalar,
  );

  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);
  // __CBT_ISSUE3__
  const proof: LoyaltyProof = {
    proofSystem: LOYALTY_PROOF_SYSTEM,
    amountBitLength,
    remainderBitLength: LOYALTY_REMAINDER_BIT_LENGTH,
    generatorH: pointToFelts(h),
    monthlyCommitments: monthlyCommitments.map(pointToFelts),
    cashbackCommitment: pointToFelts(cashbackCommitment),
    monthlyBits,
    totalBits,
    tierLowerBits,
    tierUpperBits,
    cashbackBits,
    remainderLowerBits,
    remainderUpperBits,
  };

  const publicTiers: LoyaltyTier[] = tiers.map((t) => ({
    name: t.name,
    floorBaseUnits: t.floor.toString(),
    feeDiscountBps: t.feeDiscountBps,
    cashbackBps: t.cashbackBps,
  }));

  const certificate: LoyaltyCertificate = {
    kind: CERTIFICATE_KIND,
    version: LOYALTY_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    merchantAlias,
    periodLabel,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    tiers: publicTiers,
    monthCount: months.length,
    tierIndex,
    tierName: tier.name,
    feeDiscountBps: tier.feeDiscountBps.toString(),
    cashbackBps: tier.cashbackBps.toString(),
    tierFloorBaseUnits: tier.floor.toString(),
    nextTierFloorBaseUnits: nextFloor === null ? "" : nextFloor.toString(),
    accountCommitment: toHex(accountCommitment),
    accountCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: LOYALTY_NOTICE,
  };

  const secret: LoyaltyCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    monthlyVolumesBaseUnits: months.map((m) => m.toString()),
    monthlyBlindings: monthlyBlindings.map(toHex),
    totalVolumeBaseUnits: total.toString(),
    totalBlinding: toHex(totalBlinding),
    cashbackBaseUnits: cashback.toString(),
    cashbackBlinding: toHex(cashbackBlinding),
    accountRef,
    accountSalt: toHex(accountSalt),
    accountCommitted,
  };

  return { certificate, secret };
}

/**
 * Verifies a loyalty certificate end to end: the binding hash, the issuer
 * signature, that the published tier data matches the bound public ladder at the
 * proven index, every monthly range leg tied to its commitment, the aggregate
 * leg tied to ΣC_i, the tier band (lower always; upper below the top tier), the
 * cashback range leg, and the two remainder legs that force the cashback to the
 * exact floor of the tier's public rate. A passing verdict reveals no figure —
 * only that the aggregate sits in the tier band and the cashback is exact.
 */
export function verifyLoyaltyCertificate(certificate: LoyaltyCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== LOYALTY_PROOF_SYSTEM) return false;
    const amountBitLength = proof.amountBitLength;
    const remainderBitLength = proof.remainderBitLength;
    if (!Number.isInteger(amountBitLength) || amountBitLength < MIN_LOYALTY_AMOUNT_BIT_LENGTH || amountBitLength > MAX_LOYALTY_AMOUNT_BIT_LENGTH)
      return false;
    if (remainderBitLength !== LOYALTY_REMAINDER_BIT_LENGTH) return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);

    // Re-normalize the PUBLIC ladder and derive the proven tier's data from the
    // bound (ladder, tierIndex) pair — never from the certificate's display fields.
    const tiers = requireLoyaltyPolicy({ tiers: certificate.tiers });
    const tierIndex = certificate.tierIndex;
    if (!Number.isInteger(tierIndex) || tierIndex < 0 || tierIndex >= tiers.length) return false;
    const tier = tiers[tierIndex];
    const isTopTier = tierIndex === tiers.length - 1;
    const nextFloor = isTopTier ? null : tiers[tierIndex + 1].floor;
    if (certificate.tierName !== tier.name) return false;
    if (certificate.feeDiscountBps !== tier.feeDiscountBps.toString()) return false;
    if (certificate.cashbackBps !== tier.cashbackBps.toString()) return false;
    if (certificate.tierFloorBaseUnits !== tier.floor.toString()) return false;
    if (certificate.nextTierFloorBaseUnits !== (nextFloor === null ? "" : nextFloor.toString())) return false;

    const monthCount = certificate.monthCount;
    if (!Number.isInteger(monthCount) || monthCount < MIN_LOYALTY_MONTHS || monthCount > MAX_LOYALTY_MONTHS) return false;
    if (!Array.isArray(proof.monthlyCommitments) || proof.monthlyCommitments.length !== monthCount) return false;
    if (!Array.isArray(proof.monthlyBits) || proof.monthlyBits.length !== monthCount) return false;
    const monthlyCommitments = proof.monthlyCommitments.map(pointFromFelts);
    const cashbackCommitment = pointFromFelts(proof.cashbackCommitment);
    // __CBT_VERIFY__
    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      periodLabel: certificate.periodLabel,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: certificate.assetDecimals,
      tiers,
      monthCount,
      tierIndex,
      amountBitLength,
      remainderBitLength,
      accountCommitment: requireFelt(certificate.accountCommitment),
      accountCommitted: certificate.accountCommitted,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };
    const bindingHash = computeBindingHash(fields, issuerKey, monthlyCommitments, cashbackCommitment, h);
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);

    // Monthly legs: each hidden month is a bounded non-negative integer, and the
    // homomorphic sum of the committed months is the aggregate commitment ΣC_i.
    let totalCommitment = ZERO;
    for (let i = 0; i < monthCount; i += 1) {
      const monthSum = verifyRange(proof.monthlyBits[i], amountBitLength, ctx, i, h);
      if (!monthSum || !monthSum.equals(monthlyCommitments[i])) return false;
      totalCommitment = totalCommitment.add(monthlyCommitments[i]);
    }

    // Aggregate leg: V ∈ [0, 2^amountBits) tied to ΣC_i (bounds the aggregate).
    const totalSum = verifyRange(proof.totalBits, amountBitLength, ctx, LEG_TOTAL, h);
    if (!totalSum || !totalSum.equals(totalCommitment)) return false;

    // Tier lower: ΣC_i − floor·G ∈ [0, 2^amountBits) ⇒ aggregate ≥ tier floor.
    const tierLowerSum = verifyRange(proof.tierLowerBits, amountBitLength, ctx, LEG_TIER_LOWER, h);
    if (!tierLowerSum || !tierLowerSum.equals(totalCommitment.add(scalePoint(G, tier.floor).negate()))) return false;
    // __CBT_VERIFY2__
    // Tier upper: below the top tier, (nextFloor − 1)·G − ΣC_i ∈ [0, 2^amountBits)
    // ⇒ aggregate ≤ nextFloor − 1 < nextFloor. At the top tier there is no upper leg.
    if (nextFloor === null) {
      if (Array.isArray(proof.tierUpperBits) && proof.tierUpperBits.length !== 0) return false;
    } else {
      const target = scalePoint(G, nextFloor - 1n).add(totalCommitment.negate());
      const tierUpperSum = verifyRange(proof.tierUpperBits, amountBitLength, ctx, LEG_TIER_UPPER, h);
      if (!tierUpperSum || !tierUpperSum.equals(target)) return false;
    }

    // Cashback leg: c ∈ [0, 2^amountBits) tied to C_cash.
    const cashbackSum = verifyRange(proof.cashbackBits, amountBitLength, ctx, LEG_CASHBACK, h);
    if (!cashbackSum || !cashbackSum.equals(cashbackCommitment)) return false;

    // Remainder legs on D = cashbackBps·ΣC_i − 10000·C_cash. Pinning rem ∈ [0, 9999]
    // forces c = floor(cashbackBps · aggregate / 10000) for the tier's public rate.
    const cashbackBps = BigInt(tier.cashbackBps);
    const derived = scalePoint(totalCommitment, cashbackBps).add(scalePoint(cashbackCommitment, LOYALTY_BPS_DENOMINATOR).negate());
    const remainderLowerSum = verifyRange(proof.remainderLowerBits, remainderBitLength, ctx, LEG_REMAINDER_LOWER, h);
    if (!remainderLowerSum || !remainderLowerSum.equals(derived)) return false;
    const remainderUpperSum = verifyRange(proof.remainderUpperBits, remainderBitLength, ctx, LEG_REMAINDER_UPPER, h);
    if (!remainderUpperSum || !remainderUpperSum.equals(scalePoint(G, LOYALTY_BPS_DENOMINATOR - 1n).add(derived.negate()))) return false;

    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure and full opening
// ---------------------------------------------------------------------------

/** The committed aggregate figure and its blinding, from the secret. */
function aggregateSecret(secret: LoyaltyCertificateSecret, metric: LoyaltyMetric): { value: string; blinding: string } {
  switch (metric) {
    case "total":
      return { value: secret.totalVolumeBaseUnits, blinding: secret.totalBlinding };
    case "cashback":
      return { value: secret.cashbackBaseUnits, blinding: secret.cashbackBlinding };
    default:
      throw new Error("The loyalty metric is unknown.");
  }
}

/** The published commitment backing a disclosable aggregate — ΣC_i for the total, C_cash for the cashback. */
function aggregateCommitment(certificate: LoyaltyCertificate, metric: LoyaltyMetric): CurvePoint {
  if (metric === "cashback") return pointFromFelts(certificate.proof.cashbackCommitment);
  if (metric === "total") {
    let acc = ZERO;
    for (const felts of certificate.proof.monthlyCommitments) acc = acc.add(pointFromFelts(felts));
    return acc;
  }
  throw new Error("The loyalty metric is unknown.");
}

/** Builds a disclosure that opens exactly one aggregate figure (total or cashback), leaving the rest hidden. */
export function buildLoyaltyMetricDisclosure(secret: LoyaltyCertificateSecret, metric: LoyaltyMetric): LoyaltyMetricDisclosure {
  const { value, blinding } = aggregateSecret(secret, metric);
  return { kind: METRIC_DISCLOSURE_KIND, certificateId: secret.certificateId, metric, valueBaseUnits: value, blinding };
}

/**
 * The cashback opening doubles as a rebate-claim voucher: it opens the cashback
 * commitment so a counterparty can verify the exact amount and settle it out of
 * band. Issuing this voucher does not itself move any funds.
 */
export function buildLoyaltyRebateClaim(secret: LoyaltyCertificateSecret): LoyaltyMetricDisclosure {
  return buildLoyaltyMetricDisclosure(secret, "cashback");
}

/** Verifies a single aggregate disclosure against the matching commitment in the certificate. */
export function verifyLoyaltyMetricDisclosure(certificate: LoyaltyCertificate, disclosure: LoyaltyMetricDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== METRIC_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const h = independentGenerator();
    const value = requireBaseUnits(disclosure.valueBaseUnits, "disclosed value");
    const blinding = requireScalar(disclosure.blinding, true);
    return pedersenCommit(value, blinding, h).equals(aggregateCommitment(certificate, disclosure.metric));
  } catch {
    return false;
  }
}
/** Builds a disclosure that opens exactly one hidden month, leaving the others hidden. */
export function buildLoyaltyMonthDisclosure(secret: LoyaltyCertificateSecret, monthIndex: number): LoyaltyMonthDisclosure {
  if (!Number.isInteger(monthIndex) || monthIndex < 0 || monthIndex >= secret.monthlyVolumesBaseUnits.length) {
    throw new Error("The month index is out of range.");
  }
  return {
    kind: MONTH_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    monthIndex,
    valueBaseUnits: secret.monthlyVolumesBaseUnits[monthIndex],
    blinding: secret.monthlyBlindings[monthIndex],
  };
}

/** Verifies a single-month disclosure against that month's published commitment. */
export function verifyLoyaltyMonthDisclosure(certificate: LoyaltyCertificate, disclosure: LoyaltyMonthDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== MONTH_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const commitments = certificate.proof.monthlyCommitments;
    const monthIndex = disclosure.monthIndex;
    if (!Number.isInteger(monthIndex) || monthIndex < 0 || monthIndex >= commitments.length) return false;
    const h = independentGenerator();
    const value = requireBaseUnits(disclosure.valueBaseUnits, "disclosed month volume");
    const blinding = requireScalar(disclosure.blinding, true);
    return pedersenCommit(value, blinding, h).equals(pointFromFelts(commitments[monthIndex]));
  } catch {
    return false;
  }
}

/** Reveals the committed account reference (salt + value) so a verifier can re-derive the commitment. */
export function buildLoyaltyAccountDisclosure(secret: LoyaltyCertificateSecret): LoyaltyRefDisclosure {
  if (!secret.accountCommitted) throw new Error("This certificate carries no account commitment to disclose.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "account",
    value: secret.accountRef,
    salt: secret.accountSalt,
  };
}

/** Verifies an account-reference disclosure against the published salted commitment. */
export function verifyLoyaltyRefDisclosure(certificate: LoyaltyCertificate, disclosure: LoyaltyRefDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND || disclosure.field !== "account") return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    if (!certificate.accountCommitted) return false;
    const value = requireText(disclosure.value, "account reference", 128);
    const salt = requireScalar(disclosure.salt, true);
    return toHex(commitRef(ACCOUNT_DOMAIN, value, salt)) === certificate.accountCommitment;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Full opening
// ---------------------------------------------------------------------------

/** A full opening the merchant hands a counterparty to reveal every committed figure at once. */
export function buildLoyaltyCertificateOpening(secret: LoyaltyCertificateSecret): LoyaltyCertificateOpening {
  return {
    monthlyVolumesBaseUnits: [...secret.monthlyVolumesBaseUnits],
    monthlyBlindings: [...secret.monthlyBlindings],
    totalVolumeBaseUnits: secret.totalVolumeBaseUnits,
    totalBlinding: secret.totalBlinding,
    cashbackBaseUnits: secret.cashbackBaseUnits,
    cashbackBlinding: secret.cashbackBlinding,
  };
}

/**
 * Verifies a full opening: every month opens its commitment, the disclosed
 * months sum to the disclosed aggregate, the aggregate opens ΣC_i, the cashback
 * opens C_cash, and the disclosed cashback equals floor(cashbackBps · total /
 * 10000) for the certificate's proven tier rate. Reveals every figure — use it
 * only with a trusted counterparty.
 */
export function verifyLoyaltyCertificateOpening(certificate: LoyaltyCertificate, opening: LoyaltyCertificateOpening): boolean {
  try {
    if (!opening || typeof opening !== "object") return false;
    const commitments = certificate.proof.monthlyCommitments;
    if (!Array.isArray(opening.monthlyVolumesBaseUnits) || opening.monthlyVolumesBaseUnits.length !== commitments.length) return false;
    if (!Array.isArray(opening.monthlyBlindings) || opening.monthlyBlindings.length !== commitments.length) return false;
    const h = independentGenerator();

    let total = 0n;
    let aggregateCommit = ZERO;
    for (let i = 0; i < commitments.length; i += 1) {
      const value = requireBaseUnits(opening.monthlyVolumesBaseUnits[i], `month ${i + 1} volume`);
      const blinding = requireScalar(opening.monthlyBlindings[i], true);
      if (!pedersenCommit(value, blinding, h).equals(pointFromFelts(commitments[i]))) return false;
      total += value;
      aggregateCommit = aggregateCommit.add(pointFromFelts(commitments[i]));
    }

    const disclosedTotal = requireBaseUnits(opening.totalVolumeBaseUnits, "aggregate volume");
    if (disclosedTotal !== total) return false;
    const totalBlinding = requireScalar(opening.totalBlinding, true);
    if (!pedersenCommit(total, totalBlinding, h).equals(aggregateCommit)) return false;

    const cashback = requireBaseUnits(opening.cashbackBaseUnits, "cashback amount");
    const cashbackBlinding = requireScalar(opening.cashbackBlinding, true);
    if (!pedersenCommit(cashback, cashbackBlinding, h).equals(pointFromFelts(certificate.proof.cashbackCommitment))) return false;

    const cashbackBps = requireInt(Number(certificate.cashbackBps), "cashback bps", 0, MAX_LOYALTY_CASHBACK_BPS);
    if (cashback !== computeCashback(cashbackBps, total)) return false;
    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Presentation helpers: badge, trust model, visibility model
// ---------------------------------------------------------------------------

/** A compact, display-only summary card of a certificate's public claims. */
export function buildLoyaltyCertificateBadge(certificate: LoyaltyCertificate): LoyaltyCertificateBadge {
  const decimals = certificate.assetDecimals;
  const nextFloorDisplay =
    certificate.nextTierFloorBaseUnits === ""
      ? "—"
      : `${formatLoyaltyBaseUnits(certificate.nextTierFloorBaseUnits, decimals)} ${certificate.assetSymbol}`;
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    periodLabel: certificate.periodLabel,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    tierName: certificate.tierName,
    tierIndex: certificate.tierIndex,
    monthCount: certificate.monthCount,
    feeDiscountDisplay: formatLoyaltyBps(certificate.feeDiscountBps),
    cashbackDisplay: formatLoyaltyBps(certificate.cashbackBps),
    tierFloorDisplay: `${formatLoyaltyBaseUnits(certificate.tierFloorBaseUnits, decimals)} ${certificate.assetSymbol}`,
    nextTierFloorDisplay: nextFloorDisplay,
    accountCommitted: certificate.accountCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}

/** An honest, machine-readable statement of exactly what a passing verdict does and does not establish. */
export function summarizeLoyaltyTrust(): LoyaltyTrustModel {
  return {
    isZeroKnowledge: true,
    provesAggregateInTierBand: true,
    provesCashbackIsExactFloorOfRate: true,
    provesEveryMonthNonNegative: true,
    hidesMonthlyVolumes: true,
    hidesAggregateVolume: true,
    hidesCashbackAmount: true,
    hidesCustomerLists: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    appliesOrReducesProtocolFee: false,
    paysOrSettlesCashback: false,
    reducesGas: false,
    movesPoolFunds: false,
    verifiesVolumesAreReal: false,
    isDecentralized: false,
    isAutomatic: false,
    isLoyaltyProgramGuaranteeOrFinancialAdvice: false,
    zeroKnowledgeElement:
      "Per-bit Schnorr one-of-two proofs with Fiat–Shamir over Pedersen commitments on the Stark curve. The homomorphic sum of the monthly commitments is range-bound and compared to derived points, so the tier band and the exact cashback floor are proven without opening any month, the aggregate, or the cashback amount.",
    statement:
      "A passing verdict proves an issuer-signed claim that hidden monthly volumes aggregate into a total within a public tier band, and that a hidden cashback commitment equals exactly floor(cashbackBps · total / 10000) for that tier's public rate. It does NOT move funds, apply or reduce any protocol fee, pay or settle any cashback, reduce gas, or read or write the STRK20 pool, and it cannot confirm the committed volumes reflect real settlements. It is neither decentralized nor automatic, and is not a loyalty-program guarantee or financial advice.",
  };
}

/** The hidden / disclosed / application-only split, for honest UI copy. */
export function getLoyaltyVisibilityModel(): LoyaltyVisibilityModel {
  return {
    hiddenFromVerifier: [
      "Each individual monthly settlement volume",
      "The aggregate settlement volume across the period",
      "The exact cashback amount (revealed only by the rebate-claim voucher)",
      "Every Pedersen blinding factor",
      "The account / loyalty-member reference (only a salted commitment is published)",
      "The merchant's customer list and any per-payment detail",
    ],
    disclosedToVerifier: [
      "The public tier ladder (names, floors, fee-discount and cashback rates)",
      "The proven tier index and its name",
      "The proven tier's fee-discount and cashback rates, and its floors",
      "The number of months aggregated (a count, never an amount)",
      "The issuer public key, the binding hash, and the proof bundle",
    ],
    applicationOnly: [
      "Volume still needed to reach the next tier, and progress through the current band",
      "Any decimal formatting or fiat estimate rendered in the interface",
    ],
    limitation:
      "The edges are trust assumptions, not proofs: the certificate binds merchant-supplied figures and cannot confirm any payment settled on-chain, nothing here moves funds or changes an on-chain fee, and a single issuer key vouches for the inputs. Distinctive tier ladders or timing can still correlate a merchant with public activity.",
  };
}
// ---------------------------------------------------------------------------
// Serialization (base64url-wrapped JSON)
// ---------------------------------------------------------------------------

/** Serializes a public certificate to a portable base64url token. */
export function serializeLoyaltyCertificate(certificate: LoyaltyCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

/** Parses a certificate token, checking its kind. Throws on a malformed or foreign token. */
export function parseLoyaltyCertificate(encoded: string): LoyaltyCertificate {
  const parsed = decodeJson(fromBase64Url(encoded)) as LoyaltyCertificate;
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("The encoded value is not a loyalty certificate.");
  return parsed;
}

/** Serializes the SECRET issuer record. Never publish the result. */
export function serializeLoyaltyCertificateSecret(secret: LoyaltyCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseLoyaltyCertificateSecret(encoded: string): LoyaltyCertificateSecret {
  const parsed = decodeJson(fromBase64Url(encoded)) as LoyaltyCertificateSecret;
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("The encoded value is not a loyalty certificate secret.");
  return parsed;
}

export function serializeLoyaltyMetricDisclosure(disclosure: LoyaltyMetricDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseLoyaltyMetricDisclosure(encoded: string): LoyaltyMetricDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as LoyaltyMetricDisclosure;
  if (!parsed || parsed.kind !== METRIC_DISCLOSURE_KIND) throw new Error("The encoded value is not a loyalty metric disclosure.");
  return parsed;
}

export function serializeLoyaltyMonthDisclosure(disclosure: LoyaltyMonthDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseLoyaltyMonthDisclosure(encoded: string): LoyaltyMonthDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as LoyaltyMonthDisclosure;
  if (!parsed || parsed.kind !== MONTH_DISCLOSURE_KIND) throw new Error("The encoded value is not a loyalty month disclosure.");
  return parsed;
}

export function serializeLoyaltyRefDisclosure(disclosure: LoyaltyRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseLoyaltyRefDisclosure(encoded: string): LoyaltyRefDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as LoyaltyRefDisclosure;
  if (!parsed || parsed.kind !== REF_DISCLOSURE_KIND) throw new Error("The encoded value is not a loyalty reference disclosure.");
  return parsed;
}
// ---------------------------------------------------------------------------
// Arithmetic helpers
// ---------------------------------------------------------------------------

/** Non-negative representative of `value` modulo `modulus`. */
function mod(value: bigint, modulus: bigint): bigint {
  const r = value % modulus;
  return r < 0n ? r + modulus : r;
}

/** Modular inverse of `value` modulo `modulus` via the extended Euclidean algorithm. */
function modInverse(value: bigint, modulus: bigint): bigint {
  let [old_r, r] = [mod(value, modulus), modulus];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("The value is not invertible modulo the curve order.");
  return mod(old_s, modulus);
}

/** Canonical lowercase hex encoding of a field element or scalar. */
function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

/** Poseidon hash over field elements, returned as a bigint. */
function hashElements(elements: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

/** A uniformly random non-zero scalar in [1, n). */
function randomScalar(): bigint {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return nonZeroScalar(acc);
}

/** Reduces a scalar into [1, n), mapping 0 to 1 so no proof nonce or blinding degenerates. */
function nonZeroScalar(value: bigint): bigint {
  const s = mod(value, CURVE_ORDER);
  return s === 0n ? 1n : s;
}
// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/** Requires a non-empty, length-bounded string, returning it trimmed. */
function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`The ${label} is required.`);
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new Error(`The ${label} is required.`);
  if (trimmed.length > maxLength) throw new Error(`The ${label} must be at most ${maxLength} characters.`);
  return trimmed;
}

/** Requires an integer within an inclusive range. */
function requireInt(value: unknown, label: string, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n)) throw new Error(`The ${label} must be an integer.`);
  if (n < min || n > max) throw new Error(`The ${label} must be between ${min} and ${max}.`);
  return n;
}

/** Requires a non-negative base-unit integer (as a decimal string or bigint). */
function requireBaseUnits(value: unknown, label: string): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "string" && /^\d+$/.test(value.trim())) parsed = BigInt(value.trim());
  else throw new Error(`The ${label} must be a base-unit integer.`);
  if (parsed < 0n) throw new Error(`The ${label} must not be negative.`);
  return parsed;
}

/** Requires a field element (hex or decimal string) in [0, p). */
function requireFelt(value: unknown): bigint {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error("A field element is required.");
  let parsed: bigint;
  try {
    parsed = BigInt(value.trim());
  } catch {
    throw new Error("The field element is malformed.");
  }
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("The field element is out of range.");
  return parsed;
}

/** Requires a curve scalar (hex or decimal string). Rejects zero unless allowed, and anything ≥ n. */
function requireScalar(value: unknown, allowZero: boolean): bigint {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error("A scalar is required.");
  let parsed: bigint;
  try {
    parsed = BigInt(value.trim());
  } catch {
    throw new Error("The scalar is malformed.");
  }
  if (parsed < 0n || parsed >= CURVE_ORDER) throw new Error("The scalar is out of range.");
  if (!allowZero && parsed === 0n) throw new Error("The scalar must be non-zero.");
  return parsed;
}

/** Requires a valid ISO-8601 timestamp, returning its canonical form. */
function requireIsoTimestamp(value: unknown): string {
  if (typeof value !== "string") throw new Error("A timestamp is required.");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("The timestamp is not a valid ISO-8601 value.");
  return date.toISOString();
}
// ---------------------------------------------------------------------------
// Identifiers and codecs
// ---------------------------------------------------------------------------

/** A collision-resistant local identifier for a freshly issued certificate. */
function defaultId(kind: "certificate"): string {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return `loyal_${kind}_${acc.toString(16).slice(0, 24)}`;
}

/** Serializes a value to a JSON string. */
function encodeJson(value: unknown): string {
  return JSON.stringify(value);
}

/** Parses a JSON string, normalizing any failure to a single opaque message. */
function decodeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The encoding is invalid.");
  }
}

/** UTF-8 → base64url (no padding). */
function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url → UTF-8, rejecting malformed or oversized input with a single opaque message. */
function fromBase64Url(encoded: string): string {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > MAX_ENCODED_LENGTH) {
    throw new Error("The encoding is invalid.");
  }
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    throw new Error("The encoding is invalid.");
  }
}
