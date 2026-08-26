/**
 * CipherBill — Merchant Credit Scoring & Risk Underwriting Proof Engine
 * =====================================================================
 *
 * A client-side module that lets a merchant prove, in zero knowledge, a PUBLIC
 * underwriting index and a set of hard liquidity/volume covenants over their
 * PRIVATE settlement history — the number of fulfilled invoices, on-time
 * settlements, and disputes, plus the settled cash-flow volume and the
 * liquidity reserve — WITHOUT revealing any of those figures or the customer
 * list. Each metric is hidden inside a Pedersen commitment over the STARK
 * curve. A homomorphic Schnorr proof reconciles the published index
 * `index = base + wF·fulfilled + wO·onTime − wD·disputed` against the hidden
 * count commitments; bit-decomposition range proofs bind every hidden count
 * and cash-flow figure to a non-negative band; and three coverage range proofs
 * attest that on-time ≤ fulfilled, that the reserve clears a public liquidity
 * floor, and that the settled volume clears a public floor — all without
 * opening a single figure. The merchant signs the binding so anyone can
 * authenticate the attestation offline, and any metric can be selectively
 * disclosed later. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that a published underwriting index is the exact public
 *   weighting of the merchant's hidden fulfilled/on-time/disputed counts, and
 *   that the hidden liquidity reserve and settled volume each clear a public
 *   floor. A verifier learns the index, the tier, the weights, and the floors —
 *   never the counts, the volume, the reserve, the blindings, or the customers.
 * - Issuer-authenticated with a Schnorr signature anyone can check offline.
 * - Selectively disclosable per metric, and fully openable to a counterparty.
 * - Self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It is NOT a credit-bureau score, a predictive model, or financial advice.
 *   The index, tier, and standing are deterministic heuristics over the exact
 *   figures the merchant supplies.
 * - It does NOT extend, disburse, settle, or move any funds, and does NOT move
 *   funds in the STRK20 pool. It attests a relation over merchant-supplied
 *   figures; any lending happens out of band in a counterparty's own systems.
 * - It does NOT verify that the committed history is real. It binds
 *   merchant-supplied figures; it cannot confirm invoices settled or reserves exist.
 * - It does NOT read from or write to the STRK20 pool contract; the pool
 *   address below is provenance only.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   attestations and no contract, oracle, scheduler, or consensus vouches for
 *   the inputs. `summarizeCreditTrust()` and `getCreditVisibilityModel()` state these limits.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const CREDIT_ENGINE_VERSION = 1 as const;
export const CREDIT_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const CREDIT_PROOF_SYSTEM = "stark-pedersen-credit-underwriting-v1" as const;

/** Ceiling on any public underwriting weight (fulfilled/on-time/dispute), kept far below the curve order. */
export const MAX_CREDIT_WEIGHT = 100_000;
/** Ceiling on the public base index the weighting starts from. */
export const MAX_CREDIT_BASE_INDEX = 1_000_000;
/** Anchor points the deterministic risk heuristic normalizes the public index against. */
export const CREDIT_INDEX_RISK_FLOOR = 500;
export const CREDIT_INDEX_RISK_CEILING = 900;

/** Bit band for the hidden counts (fulfilled, on-time, disputed). 2^32 covers any realistic invoice history. */
export const DEFAULT_CREDIT_COUNT_BIT_LENGTH = 16;
export const MIN_CREDIT_COUNT_BIT_LENGTH = 4;
export const MAX_CREDIT_COUNT_BIT_LENGTH = 32;
/** Bit band for the hidden cash-flow figures (settled volume, liquidity reserve) and their coverage gaps. */
export const DEFAULT_CREDIT_AMOUNT_BIT_LENGTH = 128;
export const MIN_CREDIT_AMOUNT_BIT_LENGTH = 8;
export const MAX_CREDIT_AMOUNT_BIT_LENGTH = 128;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;
const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill credit generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill credit statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill credit bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill credit binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill credit issuer signature v1");
const INDEX_DOMAIN = hash.starknetKeccak("CipherBill credit index reconciliation v1");
const UNDERWRITER_DOMAIN = hash.starknetKeccak("CipherBill credit underwriter ref v1");
const BOOK_DOMAIN = hash.starknetKeccak("CipherBill credit book ref v1");
const CERTIFICATE_KIND = "cipherbill.credit-certificate" as const;
const SECRET_KIND = "cipherbill.credit-certificate-secret" as const;
const METRIC_DISCLOSURE_KIND = "cipherbill.credit-metric-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.credit-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.credit-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.credit-keypair" as const;
const MAX_ENCODED_LENGTH = 1_400_000;

/** The five hidden metrics, in a fixed order used for proof legs and disclosures. */
export type CreditMetric = "fulfilled" | "onTime" | "disputed" | "volume" | "reserve";
export type CreditTier = "prime" | "preferred" | "standard" | "watch" | "substandard";
export type CreditRiskBand = "low" | "elevated" | "high" | "critical";

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface CreditAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface CreditKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface CreditEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}
/**
 * A public underwriting policy. The verifier sees every field here: the base
 * index and the three count weights fix how the published index is derived from
 * the hidden counts, and the two floors fix the covenants the hidden cash-flow
 * figures are proven to clear. None of this reveals the hidden metrics.
 */
export interface CreditPolicy {
  /** PUBLIC base the weighted index starts from. */
  baseIndex: number;
  /** PUBLIC weight applied to the hidden fulfilled-invoice count (added). */
  fulfilledWeight: number;
  /** PUBLIC weight applied to the hidden on-time-settlement count (added). */
  onTimeWeight: number;
  /** PUBLIC weight applied to the hidden disputed-invoice count (subtracted). */
  disputeWeight: number;
  /** PUBLIC liquidity-reserve floor, in base units. Proven: hidden reserve ≥ this floor. */
  reserveFloorBaseUnits: string;
  /** PUBLIC settled-volume floor, in base units. Proven: hidden settled volume ≥ this floor. */
  volumeFloorBaseUnits: string;
}

/** The private figures a merchant commits to. None are ever published in the clear. */
export interface CreditMetrics {
  /** SECRET count of fulfilled (successfully settled) invoices. */
  fulfilledInvoices: string;
  /** SECRET count of on-time settlements. Proven ≤ fulfilled. */
  onTimeSettlements: string;
  /** SECRET count of disputed invoices. */
  disputedInvoices: string;
  /** SECRET settled cash-flow volume in base units. Proven ≥ the public floor. */
  settledVolumeBaseUnits: string;
  /** SECRET liquidity reserve in base units. Proven ≥ the public floor. */
  liquidityReserveBaseUnits: string;
}

/** The pure, proof-free breakdown of a credit assessment. Computed locally; never published. */
export interface CreditState {
  fulfilledInvoices: string;
  onTimeSettlements: string;
  disputedInvoices: string;
  settledVolumeBaseUnits: string;
  liquidityReserveBaseUnits: string;
  /** The public underwriting index: base + wF·fulfilled + wO·onTime − wD·disputed. */
  index: string;
  tier: CreditTier;
  /** on-time / fulfilled, in bps (application-only; never proven or published). */
  onTimeRateBps: string;
  /** disputed / (fulfilled + disputed), in bps (application-only; never proven or published). */
  disputeRateBps: string;
  reserveFloorBaseUnits: string;
  volumeFloorBaseUnits: string;
  clearsReserveFloor: boolean;
  clearsVolumeFloor: boolean;
  punctualityConsistent: boolean;
  /** True when every covenant holds and the index is non-negative — the relation the proof attests. */
  eligible: boolean;
}
/** A deterministic risk heuristic over the public index — not a credit score or model. */
export interface CreditRiskAssessment {
  band: CreditRiskBand;
  score: number;
  tier: CreditTier;
  index: number;
  eligible: boolean;
  rationale: string;
}

export interface IssueCreditCertificateInput {
  merchantAlias: string;
  asset: CreditAsset;
  /** PUBLIC free-form reference to the assessment this attestation covers. */
  assessmentRef: string;
  /** PUBLIC human-readable underwriting-program label. */
  programLabel: string;
  /** PUBLIC underwriting policy: base index, count weights, and covenant floors. */
  policy: CreditPolicy;
  /** SECRET private metrics being committed and proven. */
  metrics: CreditMetrics;
  /** SECRET underwriter/counterparty reference; only a salted commitment is published. */
  underwriterRef?: string;
  /** SECRET opaque loan-book/account reference; only a salted commitment is published. */
  bookRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  countBitLength?: number;
  amountBitLength?: number;
  memo?: string;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface CreditBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

/** A linear Schnorr proof that a statement point equals witness·H (its G-component is zero). */
export interface CreditLinearProof {
  nonceCommitment: CurvePointFelts;
  response: string;
}

/** Schnorr signature (challenge, response) over the binding by the issuer key. */
export interface CreditIssuerSignature {
  challenge: string;
  response: string;
}
/**
 * Zero-knowledge proof bundle. Six range legs bound the hidden figures, and one
 * linear leg reconciles the published index against the count commitments:
 *   leg 0 fulfilled ∈ [0, 2^countBits);
 *   leg 1 onTime    ∈ [0, 2^countBits);
 *   leg 2 disputed  ∈ [0, 2^countBits);
 *   leg 3 fulfilled − onTime ∈ [0, 2^countBits)     (tied to C_f − C_o ⇒ onTime ≤ fulfilled);
 *   leg 4 reserve − reserveFloor ∈ [0, 2^amountBits) (tied to C_r − floor·G ⇒ reserve ≥ floor);
 *   leg 5 volume − volumeFloor  ∈ [0, 2^amountBits)  (tied to C_v − floor·G ⇒ volume ≥ floor);
 * plus indexReconciliation: wF·C_f + wO·C_o − wD·C_d − (index − base)·G = r·H.
 */
export interface CreditProof {
  proofSystem: typeof CREDIT_PROOF_SYSTEM;
  countBitLength: number;
  amountBitLength: number;
  generatorH: CurvePointFelts;
  fulfilledCommitment: CurvePointFelts;
  onTimeCommitment: CurvePointFelts;
  disputedCommitment: CurvePointFelts;
  volumeCommitment: CurvePointFelts;
  reserveCommitment: CurvePointFelts;
  fulfilledBits: CreditBitProof[];
  onTimeBits: CreditBitProof[];
  disputedBits: CreditBitProof[];
  punctualityBits: CreditBitProof[];
  reserveCoverageBits: CreditBitProof[];
  volumeCoverageBits: CreditBitProof[];
  indexReconciliation: CreditLinearProof;
}

export interface CreditCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof CREDIT_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  merchantAlias: string;
  assessmentRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC base index the weighting starts from. */
  baseIndex: string;
  /** PUBLIC weight on the hidden fulfilled count (added). */
  fulfilledWeight: string;
  /** PUBLIC weight on the hidden on-time count (added). */
  onTimeWeight: string;
  /** PUBLIC weight on the hidden disputed count (subtracted). */
  disputeWeight: string;
  /** PUBLIC liquidity-reserve floor in base units (proven cleared). */
  reserveFloorBaseUnits: string;
  /** PUBLIC settled-volume floor in base units (proven cleared). */
  volumeFloorBaseUnits: string;
  /** PUBLIC underwriting index, cryptographically bound to the hidden counts. */
  index: string;
  /** PUBLIC underwriting tier derived deterministically from the index. */
  tier: CreditTier;
  /** Salted Poseidon commitment to the underwriter reference; hides the value. */
  underwriterCommitment: string;
  underwriterCommitted: boolean;
  /** Salted Poseidon commitment to the loan-book reference; hides the value. */
  bookCommitment: string;
  bookCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: CreditProof;
  issuerSignature: CreditIssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}
/** SECRET issuer record of a freshly issued attestation. Never publish it. */
export interface CreditCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  fulfilledInvoices: string;
  onTimeSettlements: string;
  disputedInvoices: string;
  settledVolumeBaseUnits: string;
  liquidityReserveBaseUnits: string;
  fulfilledBlinding: string;
  onTimeBlinding: string;
  disputedBlinding: string;
  volumeBlinding: string;
  reserveBlinding: string;
  underwriterRef: string;
  underwriterSalt: string;
  underwriterCommitted: boolean;
  bookRef: string;
  bookSalt: string;
  bookCommitted: boolean;
}

export interface IssuedCreditCertificate {
  certificate: CreditCertificate;
  secret: CreditCertificateSecret;
}

/** A full opening the merchant can hand a counterparty to disclose every committed figure. */
export interface CreditCertificateOpening {
  fulfilledInvoices: string;
  fulfilledBlinding: string;
  onTimeSettlements: string;
  onTimeBlinding: string;
  disputedInvoices: string;
  disputedBlinding: string;
  settledVolumeBaseUnits: string;
  volumeBlinding: string;
  liquidityReserveBaseUnits: string;
  reserveBlinding: string;
}

/** Selective disclosure of a single committed metric. */
export interface CreditMetricDisclosure {
  kind: typeof METRIC_DISCLOSURE_KIND;
  certificateId: string;
  metric: CreditMetric;
  valueBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of a committed reference (underwriter or loan book). */
export interface CreditRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: "underwriter" | "book";
  value: string;
  salt: string;
}
export interface CreditCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  merchantAlias: string;
  assessmentRef: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  index: string;
  tier: CreditTier;
  weightingDisplay: string;
  reserveFloorDisplay: string;
  volumeFloorDisplay: string;
  underwriterCommitted: boolean;
  bookCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface CreditTrustModel {
  isZeroKnowledge: boolean;
  provesIndexIsExactWeightingOfHiddenCounts: boolean;
  provesOnTimeAtMostFulfilled: boolean;
  provesReserveClearsFloor: boolean;
  provesVolumeClearsFloor: boolean;
  hidesCounts: boolean;
  hidesCashFlowFigures: boolean;
  hidesCustomerLists: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  extendsOrDisbursesFunds: boolean;
  settlesOnChain: boolean;
  movesPoolFunds: boolean;
  verifiesHistoryIsReal: boolean;
  isCreditBureauScoreOrModel: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  isFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface CreditVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const CREDIT_NOTICE =
  "Zero-knowledge proof that a published underwriting index is the exact public weighting of a merchant's hidden fulfilled, on-time, and disputed invoice counts, that on-time settlements never exceed fulfilled invoices, and that the hidden liquidity reserve and settled volume each clear a public floor — hiding every count, both cash-flow figures, the blindings, and the customer list. It authenticates the issuer and supports selective disclosure; it does not extend, disburse, or settle any funds, does not verify that the committed history is real, is neither a credit-bureau score nor financial advice, is neither decentralized nor automatic, and never reads from or writes to the STRK20 pool contract.";
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
export function deriveCreditGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent credit generator.");
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
export function createCreditIssuerKey(entropy: CreditEntropy = {}): CreditKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}
// ---------------------------------------------------------------------------
// Underwriting index, tier, state, and risk heuristic (pure)
// ---------------------------------------------------------------------------

interface NormalizedCreditPolicy {
  baseIndex: number;
  fulfilledWeight: number;
  onTimeWeight: number;
  disputeWeight: number;
  reserveFloor: bigint;
  volumeFloor: bigint;
}

/** Validates and normalizes a public underwriting policy. */
export function requireCreditPolicy(policy: CreditPolicy): NormalizedCreditPolicy {
  if (!policy || typeof policy !== "object") throw new Error("The credit policy is required.");
  const baseIndex = requireInt(policy.baseIndex, "base index", 0, MAX_CREDIT_BASE_INDEX);
  const fulfilledWeight = requireInt(policy.fulfilledWeight, "fulfilled weight", 0, MAX_CREDIT_WEIGHT);
  const onTimeWeight = requireInt(policy.onTimeWeight, "on-time weight", 0, MAX_CREDIT_WEIGHT);
  const disputeWeight = requireInt(policy.disputeWeight, "dispute weight", 0, MAX_CREDIT_WEIGHT);
  const reserveFloor = requireBaseUnits(policy.reserveFloorBaseUnits, "reserve floor");
  const volumeFloor = requireBaseUnits(policy.volumeFloorBaseUnits, "volume floor");
  return { baseIndex, fulfilledWeight, onTimeWeight, disputeWeight, reserveFloor, volumeFloor };
}

/** The public underwriting index: base + wF·fulfilled + wO·onTime − wD·disputed (may be negative). */
export function computeCreditIndex(
  fulfilled: bigint,
  onTime: bigint,
  disputed: bigint,
  policy: NormalizedCreditPolicy,
): bigint {
  return (
    BigInt(policy.baseIndex) +
    BigInt(policy.fulfilledWeight) * fulfilled +
    BigInt(policy.onTimeWeight) * onTime -
    BigInt(policy.disputeWeight) * disputed
  );
}

/** Deterministic underwriting tier from the public index. Not a credit-bureau grade. */
export function tierForCreditIndex(index: number | bigint): CreditTier {
  const n = typeof index === "bigint" ? Number(index) : index;
  if (n >= 800) return "prime";
  if (n >= 720) return "preferred";
  if (n >= 620) return "standard";
  if (n >= 540) return "watch";
  return "substandard";
}
/**
 * Computes the pure credit state: the underwriting index and tier, the on-time
 * and dispute rates, whether each covenant holds, and overall eligibility. This
 * is the same relation the zero-knowledge proof attests when `eligible`.
 */
export function computeCreditState(metrics: CreditMetrics, policy: CreditPolicy): CreditState {
  const normalized = requireCreditPolicy(policy);
  const fulfilled = requireBaseUnits(metrics.fulfilledInvoices, "fulfilled invoices");
  const onTime = requireBaseUnits(metrics.onTimeSettlements, "on-time settlements");
  const disputed = requireBaseUnits(metrics.disputedInvoices, "disputed invoices");
  const volume = requireBaseUnits(metrics.settledVolumeBaseUnits, "settled volume");
  const reserve = requireBaseUnits(metrics.liquidityReserveBaseUnits, "liquidity reserve");
  if (volume > U128_MAX) throw new Error("The settled volume must fit within the u128 range.");
  if (reserve > U128_MAX) throw new Error("The liquidity reserve must fit within the u128 range.");
  const index = computeCreditIndex(fulfilled, onTime, disputed, normalized);
  const punctualityConsistent = onTime <= fulfilled;
  const clearsReserveFloor = reserve >= normalized.reserveFloor;
  const clearsVolumeFloor = volume >= normalized.volumeFloor;
  const onTimeRateBps = fulfilled > 0n ? (onTime * 10_000n) / fulfilled : 0n;
  const disputeDenom = fulfilled + disputed;
  const disputeRateBps = disputeDenom > 0n ? (disputed * 10_000n) / disputeDenom : 0n;
  const eligible = punctualityConsistent && clearsReserveFloor && clearsVolumeFloor && index >= 0n;
  return {
    fulfilledInvoices: fulfilled.toString(),
    onTimeSettlements: onTime.toString(),
    disputedInvoices: disputed.toString(),
    settledVolumeBaseUnits: volume.toString(),
    liquidityReserveBaseUnits: reserve.toString(),
    index: index.toString(),
    tier: tierForCreditIndex(index),
    onTimeRateBps: onTimeRateBps.toString(),
    disputeRateBps: disputeRateBps.toString(),
    reserveFloorBaseUnits: normalized.reserveFloor.toString(),
    volumeFloorBaseUnits: normalized.volumeFloor.toString(),
    clearsReserveFloor,
    clearsVolumeFloor,
    punctualityConsistent,
    eligible,
  };
}

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}
/**
 * A deterministic underwriting-risk band over the public index — a transparent
 * heuristic that maps a higher index to lower risk, NOT a credit-bureau score,
 * NOT a predictive model, and NOT financial advice. An ineligible assessment
 * (a broken covenant) is always critical.
 */
export function assessCreditRisk(state: CreditState): CreditRiskAssessment {
  const index = Number(state.index);
  const tier = state.tier;
  const span = CREDIT_INDEX_RISK_CEILING - CREDIT_INDEX_RISK_FLOOR;
  const normalized = clamp01((index - CREDIT_INDEX_RISK_FLOOR) / span);
  const score = Math.round(100 * clamp01(1 - normalized));
  let band: CreditRiskBand;
  if (!state.eligible) band = "critical";
  else if (index >= 720) band = "low";
  else if (index >= 620) band = "elevated";
  else if (index >= 540) band = "high";
  else band = "critical";
  return {
    band,
    score,
    tier,
    index,
    eligible: state.eligible,
    rationale: state.eligible
      ? `Heuristic: an underwriting index of ${index} places the merchant in the ${tier} tier (higher index → lower risk).`
      : "A covenant does not hold (on-time exceeds fulfilled, a floor is unmet, or the index is negative); no honest proof exists.",
  };
}

export function formatCreditBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

/** Formats the public weighting, e.g. "base 500 + 3·fulfilled + 2·on-time − 15·disputed". */
export function formatCreditWeighting(certificate: CreditCertificate): string {
  return `base ${certificate.baseIndex} + ${certificate.fulfilledWeight}·fulfilled + ${certificate.onTimeWeight}·on-time − ${certificate.disputeWeight}·disputed`;
}

/** Formats a rate expressed in basis points, e.g. 9000 → "90%", 9050 → "90.5%". */
export function formatCreditRateBps(bps: string | number | bigint): string {
  const n = Number(bps);
  return `${(n / 100).toString()}%`;
}
// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  certificateId: string;
  merchantAlias: string;
  assessmentRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  baseIndex: bigint;
  fulfilledWeight: bigint;
  onTimeWeight: bigint;
  disputeWeight: bigint;
  reserveFloor: bigint;
  volumeFloor: bigint;
  index: bigint;
  tier: CreditTier;
  countBitLength: number;
  amountBitLength: number;
  underwriterCommitment: bigint;
  underwriterCommitted: boolean;
  bookCommitment: bigint;
  bookCommitted: boolean;
  createdAt: string;
  memo: string;
}

interface CommitmentBundle {
  fulfilled: CurvePoint;
  onTime: CurvePoint;
  disputed: CurvePoint;
  volume: CurvePoint;
  reserve: CurvePoint;
}
/** Maps an underwriting tier to a small field code so it can be bound into the hash. */
function tierCode(tier: CreditTier): bigint {
  const index = ["substandard", "watch", "standard", "preferred", "prime"].indexOf(tier);
  if (index < 0) throw new Error("The underwriting tier is invalid.");
  return BigInt(index + 1);
}

/**
 * The certificate binding hash: a Poseidon digest over every public,
 * proof-independent field plus the five metric commitments and the generator H.
 * Every range-proof and index-reconciliation challenge and the issuer signature
 * are bound to it, so no field can be altered without invalidating the certificate.
 */
function computeBindingHash(fields: BindingFields, issuerKey: CurvePoint, commitments: CommitmentBundle, h: CurvePoint): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(CREDIT_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.assessmentRef),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.baseIndex,
    fields.fulfilledWeight,
    fields.onTimeWeight,
    fields.disputeWeight,
    fields.reserveFloor,
    fields.volumeFloor,
    fields.index,
    tierCode(fields.tier),
    BigInt(fields.countBitLength),
    BigInt(fields.amountBitLength),
    fields.underwriterCommitment,
    fields.underwriterCommitted ? 1n : 0n,
    fields.bookCommitment,
    fields.bookCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    commitments.fulfilled.x, commitments.fulfilled.y,
    commitments.onTime.x, commitments.onTime.y,
    commitments.disputed.x, commitments.disputed.y,
    commitments.volume.x, commitments.volume.y,
    commitments.reserve.x, commitments.reserve.y,
    h.x, h.y,
  ]);
}
/** Context digest that seeds every range-proof and reconciliation challenge, bound to the certificate. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/**
 * Per-bit Fiat–Shamir challenge, bound to the context, the proof leg
 * (0 fulfilled, 1 on-time, 2 disputed, 3 punctuality, 4 reserve coverage,
 * 5 volume coverage), the index, and both proof nonces.
 */
function bitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

/** Fiat–Shamir challenge for a linear proof: binds the domain, context, statement, and nonce point. */
function linearChallenge(domain: bigint, ctx: bigint, statement: CurvePoint, noncePoint: CurvePoint): bigint {
  return mod(hashElements([domain, ctx, statement.x, statement.y, noncePoint.x, noncePoint.y]), CURVE_ORDER);
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
): CreditBitProof {
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
function verifyBit(
  proof: CreditBitProof,
  ctx: bigint,
  leg: number,
  index: number,
  h: CurvePoint,
): CurvePoint | null {
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
 * so the homomorphic sum `Σ 2^i·C_i` reconstructs the value commitment exactly —
 * tying the range proof to that commitment. The final blinding closes the sum.
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): CreditBitProof[] {
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
  const proofs: CreditBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies every bit and returns the reconstructed commitment `Σ 2^i·C_i`, or null. */
function verifyRange(proofs: CreditBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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
// Linear Schnorr proof over H (index reconciliation)
// ---------------------------------------------------------------------------

/**
 * Proves the statement point equals `witness·H` — i.e. that its G-component is
 * zero. Used to show `wF·C_f + wO·C_o − wD·C_d − (index − base)·G = r·H`, which
 * holds exactly when the published index is the claimed public weighting of the
 * hidden counts (the `value·G` terms cancel), leaving only a multiple of H.
 */
function proveLinear(
  statement: CurvePoint,
  witness: bigint,
  ctx: bigint,
  h: CurvePoint,
  nextScalar: () => bigint,
): CreditLinearProof {
  const nonce = nonZeroScalar(nextScalar());
  const noncePoint = scalePoint(h, nonce);
  const challenge = linearChallenge(INDEX_DOMAIN, ctx, statement, noncePoint);
  const response = mod(nonce + challenge * witness, CURVE_ORDER);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(response) };
}

function verifyLinear(proof: CreditLinearProof, statement: CurvePoint, ctx: bigint, h: CurvePoint): boolean {
  let noncePoint: CurvePoint;
  let response: bigint;
  try {
    noncePoint = pointFromFelts(proof.nonceCommitment);
    response = requireScalar(proof.response, true);
  } catch {
    return false;
  }
  const challenge = linearChallenge(INDEX_DOMAIN, ctx, statement, noncePoint);
  return scalePoint(h, response).equals(noncePoint.add(scalePoint(statement, challenge)));
}
// ---------------------------------------------------------------------------
// Issuer Schnorr signature over the binding hash
// ---------------------------------------------------------------------------

/** Signs the binding hash with the issuer scalar so anyone can authenticate it offline. */
function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): CreditIssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

/** Verifies the issuer Schnorr signature against the published public key. */
function verifySignature(signature: CreditIssuerSignature, bindingHash: bigint, publicKey: CurvePoint): boolean {
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
// Issue and verify a credit certificate
// ---------------------------------------------------------------------------

/**
 * Issues a zero-knowledge merchant credit certificate. It commits the hidden
 * fulfilled / on-time / disputed counts and the hidden settled-volume and
 * liquidity-reserve figures, proves each is a bounded non-negative integer,
 * proves on-time ≤ fulfilled and that both cash-flow figures clear their public
 * floors, and proves the published index is the exact public weighting of the
 * hidden counts — all without revealing any figure. Throws when a covenant is
 * broken, because no honest proof exists in that case.
 */
export function issueCreditCertificate(
  input: IssueCreditCertificateInput,
  now: Date = new Date(),
  entropy: CreditEntropy = {},
): IssuedCreditCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const assessmentRef = requireText(input.assessmentRef, "assessment reference", 96);
  const programLabel = requireText(input.programLabel, "program label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const policy = requireCreditPolicy(input.policy);
  const countBitLength = requireInt(
    input.countBitLength ?? DEFAULT_CREDIT_COUNT_BIT_LENGTH,
    "count bit length",
    MIN_CREDIT_COUNT_BIT_LENGTH,
    MAX_CREDIT_COUNT_BIT_LENGTH,
  );
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_CREDIT_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_CREDIT_AMOUNT_BIT_LENGTH,
    MAX_CREDIT_AMOUNT_BIT_LENGTH,
  );
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const fulfilled = requireBaseUnits(input.metrics?.fulfilledInvoices, "fulfilled invoices");
  const onTime = requireBaseUnits(input.metrics?.onTimeSettlements, "on-time settlements");
  const disputed = requireBaseUnits(input.metrics?.disputedInvoices, "disputed invoices");
  const volume = requireBaseUnits(input.metrics?.settledVolumeBaseUnits, "settled volume");
  const reserve = requireBaseUnits(input.metrics?.liquidityReserveBaseUnits, "liquidity reserve");

  const countCeiling = 1n << BigInt(countBitLength);
  if (fulfilled >= countCeiling) throw new Error(`The fulfilled count exceeds the ${countBitLength}-bit band.`);
  if (onTime >= countCeiling) throw new Error(`The on-time count exceeds the ${countBitLength}-bit band.`);
  if (disputed >= countCeiling) throw new Error(`The disputed count exceeds the ${countBitLength}-bit band.`);

  // Covenants that must hold for an honest proof to exist.
  const punctualityGap = fulfilled - onTime;
  if (punctualityGap < 0n) throw new Error("On-time settlements exceed fulfilled invoices; no honest proof exists.");

  const amountCeiling = 1n << BigInt(amountBitLength);
  const reserveCoverage = reserve - policy.reserveFloor;
  const volumeCoverage = volume - policy.volumeFloor;
  if (reserveCoverage < 0n) throw new Error("The liquidity reserve does not clear the public floor; no honest proof exists.");
  if (volumeCoverage < 0n) throw new Error("The settled volume does not clear the public floor; no honest proof exists.");
  if (reserve >= amountCeiling) throw new Error(`The liquidity reserve exceeds the ${amountBitLength}-bit band.`);
  if (volume >= amountCeiling) throw new Error(`The settled volume exceeds the ${amountBitLength}-bit band.`);
  if (reserveCoverage >= amountCeiling) throw new Error(`The reserve coverage exceeds the ${amountBitLength}-bit band.`);
  if (volumeCoverage >= amountCeiling) throw new Error(`The volume coverage exceeds the ${amountBitLength}-bit band.`);

  const index = computeCreditIndex(fulfilled, onTime, disputed, policy);
  if (index < 0n) throw new Error("The underwriting index is negative; no honest proof exists.");
  const tier = tierForCreditIndex(index);

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();

  const fulfilledBlinding = nonZeroScalar(nextScalar());
  const onTimeBlinding = nonZeroScalar(nextScalar());
  const disputedBlinding = nonZeroScalar(nextScalar());
  const volumeBlinding = nonZeroScalar(nextScalar());
  const reserveBlinding = nonZeroScalar(nextScalar());
  const fulfilledCommitment = pedersenCommit(fulfilled, fulfilledBlinding, h);
  const onTimeCommitment = pedersenCommit(onTime, onTimeBlinding, h);
  const disputedCommitment = pedersenCommit(disputed, disputedBlinding, h);
  const volumeCommitment = pedersenCommit(volume, volumeBlinding, h);
  const reserveCommitment = pedersenCommit(reserve, reserveBlinding, h);

  // Derived blindings tie each homomorphic leg to the published commitments:
  //   C_f − C_o        opens the punctuality gap under (r_f − r_o);
  //   C_r − floor·G     opens the reserve coverage under r_r (the floor·G term has no H part);
  //   C_v − floor·G     opens the volume coverage under r_v.
  const punctualityBlinding = mod(fulfilledBlinding - onTimeBlinding, CURVE_ORDER);

  const underwriterRef = input.underwriterRef ? requireText(input.underwriterRef, "underwriter reference", 96) : "";
  const bookRef = input.bookRef ? requireText(input.bookRef, "loan-book reference", 128) : "";
  const underwriterCommitted = underwriterRef.length > 0;
  const bookCommitted = bookRef.length > 0;
  const underwriterSalt = nonZeroScalar(nextScalar());
  const bookSalt = nonZeroScalar(nextScalar());
  const underwriterCommitment = underwriterCommitted ? commitRef(UNDERWRITER_DOMAIN, underwriterRef, underwriterSalt) : 0n;
  const bookCommitment = bookCommitted ? commitRef(BOOK_DOMAIN, bookRef, bookSalt) : 0n;

  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());
  const commitments: CommitmentBundle = {
    fulfilled: fulfilledCommitment,
    onTime: onTimeCommitment,
    disputed: disputedCommitment,
    volume: volumeCommitment,
    reserve: reserveCommitment,
  };
  const fields: BindingFields = {
    certificateId,
    merchantAlias,
    assessmentRef,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    baseIndex: BigInt(policy.baseIndex),
    fulfilledWeight: BigInt(policy.fulfilledWeight),
    onTimeWeight: BigInt(policy.onTimeWeight),
    disputeWeight: BigInt(policy.disputeWeight),
    reserveFloor: policy.reserveFloor,
    volumeFloor: policy.volumeFloor,
    index,
    tier,
    countBitLength,
    amountBitLength,
    underwriterCommitment,
    underwriterCommitted,
    bookCommitment,
    bookCommitted,
    createdAt,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, commitments, h);
  const ctx = statementContext(bindingHash);

  const fulfilledBits = proveRange(fulfilled, fulfilledBlinding, countBitLength, ctx, 0, h, nextScalar);
  const onTimeBits = proveRange(onTime, onTimeBlinding, countBitLength, ctx, 1, h, nextScalar);
  const disputedBits = proveRange(disputed, disputedBlinding, countBitLength, ctx, 2, h, nextScalar);
  const punctualityBits = proveRange(punctualityGap, punctualityBlinding, countBitLength, ctx, 3, h, nextScalar);
  const reserveCoverageBits = proveRange(reserveCoverage, reserveBlinding, amountBitLength, ctx, 4, h, nextScalar);
  const volumeCoverageBits = proveRange(volumeCoverage, volumeBlinding, amountBitLength, ctx, 5, h, nextScalar);

  // Index reconciliation statement: wF·C_f + wO·C_o − wD·C_d − (index − base)·G.
  // The value parts cancel to leave r_index·H exactly when the published index is
  // the claimed public weighting of the hidden counts.
  const wF = BigInt(policy.fulfilledWeight);
  const wO = BigInt(policy.onTimeWeight);
  const wD = BigInt(policy.disputeWeight);
  const indexOffset = index - BigInt(policy.baseIndex);
  const statement = scalePoint(fulfilledCommitment, wF)
    .add(scalePoint(onTimeCommitment, wO))
    .add(scalePoint(disputedCommitment, wD).negate())
    .add(scalePoint(G, mod(indexOffset, CURVE_ORDER)).negate());
  const indexWitness = mod(wF * fulfilledBlinding + wO * onTimeBlinding - wD * disputedBlinding, CURVE_ORDER);
  const indexReconciliation = proveLinear(statement, indexWitness, ctx, h, nextScalar);

  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);

  const proof: CreditProof = {
    proofSystem: CREDIT_PROOF_SYSTEM,
    countBitLength,
    amountBitLength,
    generatorH: pointToFelts(h),
    fulfilledCommitment: pointToFelts(fulfilledCommitment),
    onTimeCommitment: pointToFelts(onTimeCommitment),
    disputedCommitment: pointToFelts(disputedCommitment),
    volumeCommitment: pointToFelts(volumeCommitment),
    reserveCommitment: pointToFelts(reserveCommitment),
    fulfilledBits,
    onTimeBits,
    disputedBits,
    punctualityBits,
    reserveCoverageBits,
    volumeCoverageBits,
    indexReconciliation,
  };

  const certificate: CreditCertificate = {
    kind: CERTIFICATE_KIND,
    version: CREDIT_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    merchantAlias,
    assessmentRef,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    baseIndex: policy.baseIndex.toString(),
    fulfilledWeight: policy.fulfilledWeight.toString(),
    onTimeWeight: policy.onTimeWeight.toString(),
    disputeWeight: policy.disputeWeight.toString(),
    reserveFloorBaseUnits: policy.reserveFloor.toString(),
    volumeFloorBaseUnits: policy.volumeFloor.toString(),
    index: index.toString(),
    tier,
    underwriterCommitment: toHex(underwriterCommitment),
    underwriterCommitted,
    bookCommitment: toHex(bookCommitment),
    bookCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: CREDIT_NOTICE,
  };

  const secret: CreditCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    fulfilledInvoices: fulfilled.toString(),
    onTimeSettlements: onTime.toString(),
    disputedInvoices: disputed.toString(),
    settledVolumeBaseUnits: volume.toString(),
    liquidityReserveBaseUnits: reserve.toString(),
    fulfilledBlinding: toHex(fulfilledBlinding),
    onTimeBlinding: toHex(onTimeBlinding),
    disputedBlinding: toHex(disputedBlinding),
    volumeBlinding: toHex(volumeBlinding),
    reserveBlinding: toHex(reserveBlinding),
    underwriterRef,
    underwriterSalt: toHex(underwriterSalt),
    underwriterCommitted,
    bookRef,
    bookSalt: toHex(bookSalt),
    bookCommitted,
  };
  return { certificate, secret };
}
/**
 * Verifies a credit certificate end to end: the binding hash, the issuer
 * signature, the six range legs tied to their commitments (counts, the
 * punctuality gap C_f − C_o, and the reserve/volume coverages C_r − floor·G and
 * C_v − floor·G), and the linear reconciliation proving the published index is
 * the exact public weighting of the hidden counts. A passing verdict reveals no
 * figure — only that every covenant holds and the index is consistent.
 */
export function verifyCreditCertificate(certificate: CreditCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== CREDIT_PROOF_SYSTEM) return false;
    const countBitLength = proof.countBitLength;
    const amountBitLength = proof.amountBitLength;
    if (!Number.isInteger(countBitLength) || countBitLength < MIN_CREDIT_COUNT_BIT_LENGTH || countBitLength > MAX_CREDIT_COUNT_BIT_LENGTH)
      return false;
    if (!Number.isInteger(amountBitLength) || amountBitLength < MIN_CREDIT_AMOUNT_BIT_LENGTH || amountBitLength > MAX_CREDIT_AMOUNT_BIT_LENGTH)
      return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const fulfilledCommitment = pointFromFelts(proof.fulfilledCommitment);
    const onTimeCommitment = pointFromFelts(proof.onTimeCommitment);
    const disputedCommitment = pointFromFelts(proof.disputedCommitment);
    const volumeCommitment = pointFromFelts(proof.volumeCommitment);
    const reserveCommitment = pointFromFelts(proof.reserveCommitment);

    const baseIndex = requireBaseUnits(certificate.baseIndex, "base index");
    const index = requireBaseUnits(certificate.index, "index");
    const reserveFloor = requireBaseUnits(certificate.reserveFloorBaseUnits, "reserve floor");
    const volumeFloor = requireBaseUnits(certificate.volumeFloorBaseUnits, "volume floor");
    if (tierForCreditIndex(index) !== certificate.tier) return false;

    const commitments: CommitmentBundle = {
      fulfilled: fulfilledCommitment,
      onTime: onTimeCommitment,
      disputed: disputedCommitment,
      volume: volumeCommitment,
      reserve: reserveCommitment,
    };
    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      assessmentRef: certificate.assessmentRef,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: certificate.assetDecimals,
      baseIndex,
      fulfilledWeight: BigInt(certificate.fulfilledWeight),
      onTimeWeight: BigInt(certificate.onTimeWeight),
      disputeWeight: BigInt(certificate.disputeWeight),
      reserveFloor,
      volumeFloor,
      index,
      tier: certificate.tier,
      countBitLength,
      amountBitLength,
      underwriterCommitment: requireFelt(certificate.underwriterCommitment),
      underwriterCommitted: certificate.underwriterCommitted,
      bookCommitment: requireFelt(certificate.bookCommitment),
      bookCommitted: certificate.bookCommitted,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };
    const bindingHash = computeBindingHash(fields, issuerKey, commitments, h);
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);

    // Legs 0–2: each hidden count is a bounded non-negative integer.
    const fulfilledSum = verifyRange(proof.fulfilledBits, countBitLength, ctx, 0, h);
    if (!fulfilledSum || !fulfilledSum.equals(fulfilledCommitment)) return false;
    const onTimeSum = verifyRange(proof.onTimeBits, countBitLength, ctx, 1, h);
    if (!onTimeSum || !onTimeSum.equals(onTimeCommitment)) return false;
    const disputedSum = verifyRange(proof.disputedBits, countBitLength, ctx, 2, h);
    if (!disputedSum || !disputedSum.equals(disputedCommitment)) return false;

    // Leg 3: C_f − C_o ∈ [0, 2^countBits) ⇒ on-time ≤ fulfilled.
    const punctualitySum = verifyRange(proof.punctualityBits, countBitLength, ctx, 3, h);
    if (!punctualitySum || !punctualitySum.equals(fulfilledCommitment.add(onTimeCommitment.negate()))) return false;

    // Leg 4: C_r − reserveFloor·G ∈ [0, 2^amountBits) ⇒ reserve ≥ floor (and < floor + 2^amountBits).
    const reserveCoverageSum = verifyRange(proof.reserveCoverageBits, amountBitLength, ctx, 4, h);
    if (!reserveCoverageSum || !reserveCoverageSum.equals(reserveCommitment.add(scalePoint(G, reserveFloor).negate()))) return false;

    // Leg 5: C_v − volumeFloor·G ∈ [0, 2^amountBits) ⇒ volume ≥ floor.
    const volumeCoverageSum = verifyRange(proof.volumeCoverageBits, amountBitLength, ctx, 5, h);
    if (!volumeCoverageSum || !volumeCoverageSum.equals(volumeCommitment.add(scalePoint(G, volumeFloor).negate()))) return false;

    // Index reconciliation: wF·C_f + wO·C_o − wD·C_d − (index − base)·G = r·H.
    const wF = BigInt(certificate.fulfilledWeight);
    const wO = BigInt(certificate.onTimeWeight);
    const wD = BigInt(certificate.disputeWeight);
    const indexOffset = index - baseIndex;
    const statement = scalePoint(fulfilledCommitment, wF)
      .add(scalePoint(onTimeCommitment, wO))
      .add(scalePoint(disputedCommitment, wD).negate())
      .add(scalePoint(G, mod(indexOffset, CURVE_ORDER)).negate());
    if (!verifyLinear(proof.indexReconciliation, statement, ctx, h)) return false;
    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure and full opening
// ---------------------------------------------------------------------------

/** The committed value and blinding backing each disclosable metric, from the secret. */
function metricSecret(secret: CreditCertificateSecret, metric: CreditMetric): { value: string; blinding: string } {
  switch (metric) {
    case "fulfilled":
      return { value: secret.fulfilledInvoices, blinding: secret.fulfilledBlinding };
    case "onTime":
      return { value: secret.onTimeSettlements, blinding: secret.onTimeBlinding };
    case "disputed":
      return { value: secret.disputedInvoices, blinding: secret.disputedBlinding };
    case "volume":
      return { value: secret.settledVolumeBaseUnits, blinding: secret.volumeBlinding };
    case "reserve":
      return { value: secret.liquidityReserveBaseUnits, blinding: secret.reserveBlinding };
    default:
      throw new Error("The credit metric is unknown.");
  }
}

/** The published commitment backing each disclosable metric, from the certificate. */
function metricCommitment(certificate: CreditCertificate, metric: CreditMetric): CurvePointFelts {
  switch (metric) {
    case "fulfilled":
      return certificate.proof.fulfilledCommitment;
    case "onTime":
      return certificate.proof.onTimeCommitment;
    case "disputed":
      return certificate.proof.disputedCommitment;
    case "volume":
      return certificate.proof.volumeCommitment;
    case "reserve":
      return certificate.proof.reserveCommitment;
    default:
      throw new Error("The credit metric is unknown.");
  }
}

/** Builds a disclosure that opens exactly one committed metric, leaving the rest hidden. */
export function buildCreditMetricDisclosure(secret: CreditCertificateSecret, metric: CreditMetric): CreditMetricDisclosure {
  const { value, blinding } = metricSecret(secret, metric);
  return { kind: METRIC_DISCLOSURE_KIND, certificateId: secret.certificateId, metric, valueBaseUnits: value, blinding };
}
/** Verifies a single-metric disclosure against the matching commitment in the certificate. */
export function verifyCreditMetricDisclosure(certificate: CreditCertificate, disclosure: CreditMetricDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== METRIC_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const h = independentGenerator();
    const value = requireBaseUnits(disclosure.valueBaseUnits, "disclosed value");
    const blinding = requireScalar(disclosure.blinding, true);
    const recomputed = pedersenCommit(value, blinding, h);
    const target = pointFromFelts(metricCommitment(certificate, disclosure.metric));
    return recomputed.equals(target);
  } catch {
    return false;
  }
}

/** Builds a disclosure that opens the committed underwriter reference, if one was committed. */
export function buildCreditUnderwriterDisclosure(secret: CreditCertificateSecret): CreditRefDisclosure {
  if (!secret.underwriterCommitted) throw new Error("This certificate has no committed underwriter reference to disclose.");
  return { kind: REF_DISCLOSURE_KIND, certificateId: secret.certificateId, field: "underwriter", value: secret.underwriterRef, salt: secret.underwriterSalt };
}

/** Builds a disclosure that opens the committed loan-book reference, if one was committed. */
export function buildCreditBookDisclosure(secret: CreditCertificateSecret): CreditRefDisclosure {
  if (!secret.bookCommitted) throw new Error("This certificate has no committed loan-book reference to disclose.");
  return { kind: REF_DISCLOSURE_KIND, certificateId: secret.certificateId, field: "book", value: secret.bookRef, salt: secret.bookSalt };
}

/** Verifies a reference disclosure against the salted commitment published in the certificate. */
export function verifyCreditRefDisclosure(certificate: CreditCertificate, disclosure: CreditRefDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const salt = requireScalar(disclosure.salt, true);
    if (disclosure.field === "underwriter") {
      if (!certificate.underwriterCommitted) return false;
      const value = requireText(disclosure.value, "underwriter reference", 96);
      return toHex(commitRef(UNDERWRITER_DOMAIN, value, salt)) === certificate.underwriterCommitment;
    }
    if (disclosure.field === "book") {
      if (!certificate.bookCommitted) return false;
      const value = requireText(disclosure.value, "loan-book reference", 128);
      return toHex(commitRef(BOOK_DOMAIN, value, salt)) === certificate.bookCommitment;
    }
    return false;
  } catch {
    return false;
  }
}
/** Builds a full opening that reveals every committed figure and its blinding. */
export function buildCreditCertificateOpening(secret: CreditCertificateSecret): CreditCertificateOpening {
  return {
    fulfilledInvoices: secret.fulfilledInvoices,
    fulfilledBlinding: secret.fulfilledBlinding,
    onTimeSettlements: secret.onTimeSettlements,
    onTimeBlinding: secret.onTimeBlinding,
    disputedInvoices: secret.disputedInvoices,
    disputedBlinding: secret.disputedBlinding,
    settledVolumeBaseUnits: secret.settledVolumeBaseUnits,
    volumeBlinding: secret.volumeBlinding,
    liquidityReserveBaseUnits: secret.liquidityReserveBaseUnits,
    reserveBlinding: secret.reserveBlinding,
  };
}

/**
 * Verifies a full opening: every recomputed commitment must match the published
 * one, and the counts must reproduce the published index under the public
 * weighting. This confirms the certificate's hidden figures without trusting the
 * issuer's claims about them.
 */
export function verifyCreditCertificateOpening(certificate: CreditCertificate, opening: CreditCertificateOpening): boolean {
  try {
    if (!opening || typeof opening !== "object") return false;
    const h = independentGenerator();
    const fulfilled = requireBaseUnits(opening.fulfilledInvoices, "fulfilled invoices");
    const onTime = requireBaseUnits(opening.onTimeSettlements, "on-time settlements");
    const disputed = requireBaseUnits(opening.disputedInvoices, "disputed invoices");
    const volume = requireBaseUnits(opening.settledVolumeBaseUnits, "settled volume");
    const reserve = requireBaseUnits(opening.liquidityReserveBaseUnits, "liquidity reserve");
    const checks: Array<[bigint, string, CurvePointFelts]> = [
      [fulfilled, opening.fulfilledBlinding, certificate.proof.fulfilledCommitment],
      [onTime, opening.onTimeBlinding, certificate.proof.onTimeCommitment],
      [disputed, opening.disputedBlinding, certificate.proof.disputedCommitment],
      [volume, opening.volumeBlinding, certificate.proof.volumeCommitment],
      [reserve, opening.reserveBlinding, certificate.proof.reserveCommitment],
    ];
    for (const [value, blindingHex, commitment] of checks) {
      const blinding = requireScalar(blindingHex, true);
      if (!pedersenCommit(value, blinding, h).equals(pointFromFelts(commitment))) return false;
    }
    const policy: NormalizedCreditPolicy = {
      baseIndex: Number(certificate.baseIndex),
      fulfilledWeight: Number(certificate.fulfilledWeight),
      onTimeWeight: Number(certificate.onTimeWeight),
      disputeWeight: Number(certificate.disputeWeight),
      reserveFloor: requireBaseUnits(certificate.reserveFloorBaseUnits, "reserve floor"),
      volumeFloor: requireBaseUnits(certificate.volumeFloorBaseUnits, "volume floor"),
    };
    const index = computeCreditIndex(fulfilled, onTime, disputed, policy);
    return index.toString() === certificate.index;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Badge, trust model, and visibility model
// ---------------------------------------------------------------------------

/** A compact, shareable public summary of a certificate — no hidden figure appears. */
export function buildCreditCertificateBadge(certificate: CreditCertificate): CreditCertificateBadge {
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    assessmentRef: certificate.assessmentRef,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    index: certificate.index,
    tier: certificate.tier,
    weightingDisplay: formatCreditWeighting(certificate),
    reserveFloorDisplay: `≥ ${formatCreditBaseUnits(certificate.reserveFloorBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    volumeFloorDisplay: `≥ ${formatCreditBaseUnits(certificate.volumeFloorBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    underwriterCommitted: certificate.underwriterCommitted,
    bookCommitted: certificate.bookCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}
/** An honest, machine-readable statement of exactly what this engine proves — and what it does not. */
export function summarizeCreditTrust(): CreditTrustModel {
  return {
    isZeroKnowledge: true,
    provesIndexIsExactWeightingOfHiddenCounts: true,
    provesOnTimeAtMostFulfilled: true,
    provesReserveClearsFloor: true,
    provesVolumeClearsFloor: true,
    hidesCounts: true,
    hidesCashFlowFigures: true,
    hidesCustomerLists: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    extendsOrDisbursesFunds: false,
    settlesOnChain: false,
    movesPoolFunds: false,
    verifiesHistoryIsReal: false,
    isCreditBureauScoreOrModel: false,
    isDecentralized: false,
    isAutomatic: false,
    isFinancialAdvice: false,
    zeroKnowledgeElement:
      "A verifier learns only that the published index is the exact public weighting of the merchant's hidden fulfilled, on-time, and disputed counts, that on-time settlements never exceed fulfilled invoices, and that the hidden liquidity reserve and settled volume each clear a public floor; every count, both cash-flow figures, the blindings, and the customer list stay hidden.",
    statement:
      "This engine proves a merchant's published underwriting index is the exact public weighting of its hidden invoice-fulfilment counts and that its hidden cash-flow figures clear public covenants, and it authenticates the merchant that issued the attestation. It is neither decentralized nor automatic: one merchant key issues attestations, and no contract, oracle, scheduler, or consensus vouches for the inputs. It does not extend, disburse, or settle any funds and does not move funds in the STRK20 pool; it does not verify that the committed history is real; and it never reads from or writes to the STRK20 pool contract — the pool address is provenance only. Its index, tier, and risk band are deterministic heuristics, not a credit-bureau score, a predictive model, or financial advice.",
  };
}
/** What a verifier does and does not learn from a certificate, stated plainly. */
export function getCreditVisibilityModel(): CreditVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The fulfilled, on-time, and disputed invoice counts.",
      "The settled cash-flow volume and the liquidity reserve figures.",
      "All Pedersen blindings and the index-reconciliation witness.",
      "The customer list and every individual invoice amount.",
      "The underwriter and loan-book references, until selectively disclosed.",
    ],
    disclosedToVerifier: [
      "That the published index is the exact public weighting of the hidden counts.",
      "That on-time settlements never exceed fulfilled invoices.",
      "That the hidden reserve and settled volume each clear their public floor.",
      "That every count and coverage is a non-negative integer within the proven bit band.",
      "The public base index, weights, and covenant floors; the merchant alias, assessment reference, program label, and asset.",
      "The issuer public key and Schnorr signature; salted commitments to the underwriter and loan-book references.",
    ],
    applicationOnly: [
      "The certificate id, creation timestamp, and memo.",
      "The deterministic risk band and score heuristics (not proven, not a credit-bureau score).",
      "The on-time and dispute rate figures shown in the dashboard (never proven or published).",
    ],
    limitation:
      "This is an off-chain attestation over merchant-supplied figures. It never reads from or writes to the STRK20 pool contract, does not extend or settle funds, and cannot confirm that the committed history reflects real invoices or settlements. The pool address is recorded for provenance only.",
  };
}
// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** Encodes a certificate as a compact base64url string for sharing. */
export function serializeCreditCertificate(certificate: CreditCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

/** Decodes and shallow-validates a certificate; does NOT re-verify the proof. */
export function parseCreditCertificate(encoded: string): CreditCertificate {
  const parsed = decodeJson(fromBase64Url(encoded)) as CreditCertificate;
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("The encoded credit certificate is invalid.");
  return parsed;
}

/** Encodes the SECRET issuer record. Never publish this. */
export function serializeCreditCertificateSecret(secret: CreditCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseCreditCertificateSecret(encoded: string): CreditCertificateSecret {
  const parsed = decodeJson(fromBase64Url(encoded)) as CreditCertificateSecret;
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("The encoded credit secret is invalid.");
  return parsed;
}

export function serializeCreditMetricDisclosure(disclosure: CreditMetricDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseCreditMetricDisclosure(encoded: string): CreditMetricDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as CreditMetricDisclosure;
  if (!parsed || parsed.kind !== METRIC_DISCLOSURE_KIND) throw new Error("The encoded metric disclosure is invalid.");
  return parsed;
}

export function serializeCreditRefDisclosure(disclosure: CreditRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseCreditRefDisclosure(encoded: string): CreditRefDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as CreditRefDisclosure;
  if (!parsed || parsed.kind !== REF_DISCLOSURE_KIND) throw new Error("The encoded reference disclosure is invalid.");
  return parsed;
}
// ---------------------------------------------------------------------------
// Arithmetic and encoding helpers
// ---------------------------------------------------------------------------

/** Least non-negative residue of value mod modulus. */
function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

/** Modular inverse via the extended Euclidean algorithm. */
function modInverse(value: bigint, modulus: bigint): bigint {
  let oldR = mod(value, modulus);
  let r = modulus;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error("The value is not invertible modulo the curve order.");
  return mod(oldS, modulus);
}

/** Hex-encodes a non-negative bigint as a felt string. */
function toHex(value: bigint): string {
  if (value < 0n) throw new Error("Cannot hex-encode a negative value.");
  return `0x${value.toString(16)}`;
}

/** Poseidon hash over a list of field elements, returned as a bigint. */
function hashElements(elements: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

/** A cryptographically random scalar in [1, n). Only used when no entropy is injected. */
function randomScalar(): bigint {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return nonZeroScalar(mod(value, CURVE_ORDER));
}

/** Reduces a scalar mod n and maps 0 → 1 so it is safe as a nonce or blinding. */
function nonZeroScalar(value: bigint): bigint {
  const s = mod(value, CURVE_ORDER);
  return s === 0n ? 1n : s;
}
// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`The ${label} is required.`);
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new Error(`The ${label} is required.`);
  if (trimmed.length > maxLength) throw new Error(`The ${label} must be at most ${maxLength} characters.`);
  return trimmed;
}

function requireInt(value: unknown, label: string, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n)) throw new Error(`The ${label} must be an integer.`);
  if (n < min || n > max) throw new Error(`The ${label} must be between ${min} and ${max}.`);
  return n;
}

function requireBaseUnits(value: unknown, label: string): bigint {
  let parsed: bigint;
  try {
    parsed = typeof value === "bigint" ? value : BigInt(String(value).trim());
  } catch {
    throw new Error(`The ${label} must be an integer number of base units.`);
  }
  if (parsed < 0n) throw new Error(`The ${label} must not be negative.`);
  return parsed;
}

function requireFelt(value: string): bigint {
  if (typeof value !== "string") throw new Error("A field element is required.");
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error("The field element is malformed.");
  }
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("The field element is out of range.");
  return parsed;
}

function requireScalar(value: string, allowZero: boolean): bigint {
  if (typeof value !== "string") throw new Error("A scalar is required.");
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error("The scalar is malformed.");
  }
  if (parsed < 0n || parsed >= CURVE_ORDER) throw new Error("The scalar is outside the Stark curve order.");
  if (!allowZero && parsed === 0n) throw new Error("The scalar must be non-zero.");
  return parsed;
}

function requireIsoTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("The timestamp is not a valid ISO-8601 value.");
  return date.toISOString();
}
// ---------------------------------------------------------------------------
// Identifiers and base64url codec
// ---------------------------------------------------------------------------

let idCounter = 0;

/** A default, collision-resistant certificate id (prefix `cred_`). */
function defaultId(kind: "certificate"): string {
  idCounter += 1;
  const rand = toHex(randomScalar()).slice(2, 12);
  return `cred_${kind}_${Date.now().toString(36)}_${idCounter}_${rand}`;
}

function encodeJson(value: unknown): string {
  return JSON.stringify(value);
}

function decodeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The encoding is invalid.");
  }
}

function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(encoded: string): string {
  if (typeof encoded !== "string" || encoded.length === 0) throw new Error("The encoding is invalid.");
  if (encoded.length > MAX_ENCODED_LENGTH) throw new Error("The encoded payload is too large.");
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const binary = typeof atob === "function" ? atob(base64) : Buffer.from(base64, "base64").toString("binary");
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    throw new Error("The encoding is invalid.");
  }
}
