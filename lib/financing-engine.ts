/**
 * CipherBill — Merchant Cash Advance & Revenue-Based Financing Proof Engine
 * =========================================================================
 *
 * A client-side module that lets a merchant prove, in zero knowledge, that a
 * requested capital advance is within a PUBLIC advance factor of their committed
 * historical settlement revenue — that `advance ≤ advanceFactor · revenue` —
 * WITHOUT revealing the revenue figure, the requested advance, the customer
 * list, or any individual invoice amount. It also binds a financier reference
 * and an opaque payout-account reference under salted commitments so the
 * attestation is tied to a specific counterparty and destination without
 * disclosing them.
 *
 * The zero-knowledge core combines Pedersen commitments over the STARK curve
 * with bit-decomposition range proofs. Revenue R and advance A are each proven
 * to be bounded non-negative integers. The eligibility surplus
 * `S = factor·R − 10000·A` is committed by the homomorphic relation
 * `C_S = factor·C_R − 10000·C_A` and proven to be a bounded non-negative
 * integer; because S is non-negative exactly when `10000·A ≤ factor·R`, a valid
 * surplus range proof forces `A ≤ factor/10000 · R`. Only an advance that
 * genuinely fits the public factor of the committed revenue can be attested —
 * if the advance is too large the surplus is negative, its residue modulo the
 * curve order is astronomically large, and no honest bounded range proof exists.
 * The merchant signs the binding so anyone can authenticate the issuer offline,
 * and the revenue, advance, financier, or payout-account references can be
 * selectively disclosed later. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that a requested advance is within a public factor of the
 *   merchant's committed revenue. A verifier learns only that the committed
 *   advance is ≤ the public factor times the committed revenue — nothing about
 *   the revenue, the advance, the blindings, the customers, or the invoices.
 * - Issuer-authenticated. A Schnorr signature over the binding proves a specific
 *   merchant public key issued it; anyone can check it offline.
 * - Selectively disclosable. The merchant can later open the revenue, the
 *   advance, the financier reference, or the payout-account reference.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It does NOT advance, disburse, or settle any funds, and does NOT move funds
 *   in the STRK20 pool. It attests an eligibility relation over merchant-supplied
 *   figures; the financier's own systems disburse capital out of band.
 * - It does NOT verify that the committed revenue is real. It binds a
 *   merchant-supplied revenue figure; it cannot confirm invoices settled.
 * - It does NOT store or encrypt a reusable payout credential. The payout-account
 *   reference is bound under a one-way salted commitment and cannot be replayed.
 * - It does NOT settle on-chain or read from or write to the STRK20 pool
 *   contract; the pool address below is provenance only.
 * - Its credit limit and risk band are deterministic heuristics over the same
 *   figures, NOT a credit score, NOT a predictive model, and NOT financial advice.
 * - The repayment schedule it computes is a PLAN only — the financier's own
 *   systems must execute it; the engine never collects or moves a repayment.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   attestations and no contract, oracle, scheduler, or consensus vouches for the
 *   inputs. `summarizeFinancingTrust()` and `getFinancingVisibilityModel()` state these limits.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const FINANCING_ENGINE_VERSION = 1 as const;
export const FINANCING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const FINANCING_PROOF_SYSTEM = "stark-pedersen-financing-bounds-v1" as const;
/** Basis-point denominator: an advance factor and fee are expressed in 1/10000ths. */
export const ADVANCE_FACTOR_SCALE = 10_000n;
/** Floor on the public advance factor (basis points). 1 bps = 0.01%. */
export const MIN_ADVANCE_FACTOR_BPS = 1;
/** Ceiling on the public advance factor (basis points): 10000 = 100% of committed revenue. */
export const MAX_ADVANCE_FACTOR_BPS = 10_000;
/** Ceiling on the public financing fee (basis points): schedule metadata, never proven. */
export const MAX_FINANCING_FEE_BPS = 10_000;
/** Ceiling on the public installment count of a repayment plan. */
export const MAX_FINANCING_INSTALLMENTS = 60;
/** Ceiling on the public spacing (days) between repayment installments. */
export const MAX_FINANCING_INTERVAL_DAYS = 365;
export const DEFAULT_FINANCING_AMOUNT_BIT_LENGTH = 128;
export const MIN_FINANCING_AMOUNT_BIT_LENGTH = 8;
export const MAX_FINANCING_AMOUNT_BIT_LENGTH = 128;
/**
 * Extra bits the surplus range needs beyond the amount range. Both the advance
 * factor and the basis-point scale are < 2^14, so `factor·R` and `10000·A` — and
 * therefore the surplus `factor·R − 10000·A` — fit in `amountBitLength + 14` bits.
 */
export const FINANCING_SURPLUS_EXTRA_BITS = 14;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill financing generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill financing statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill financing bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill financing binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill financing issuer signature v1");
const FINANCIER_DOMAIN = hash.starknetKeccak("CipherBill financing counterparty ref v1");
const PAYOUT_DOMAIN = hash.starknetKeccak("CipherBill financing payout account ref v1");
const CERTIFICATE_KIND = "cipherbill.financing-certificate" as const;
const SECRET_KIND = "cipherbill.financing-certificate-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.financing-amount-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.financing-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.financing-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.financing-keypair" as const;
const MAX_ENCODED_LENGTH = 1_400_000;
export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface FinancingAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface FinancingKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface FinancingEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

/** A public financing program: the advance factor (proven) plus repayment metadata. */
export interface FinancingPolicy {
  /** PUBLIC max advance as a fraction of committed revenue, in bps. Proven: advance ≤ factor·revenue. */
  advanceFactorBps: number;
  /** PUBLIC financing fee in bps, applied to the advance for the repayment plan (metadata; not proven). */
  feeBps: number;
  /** PUBLIC number of repayment installments (metadata; not proven). */
  installments: number;
  /** PUBLIC spacing in days between repayment installments (metadata; not proven). */
  intervalDays: number;
}

/** One planned repayment installment: purely a schedule the financier's own system may execute. */
export interface RepaymentScheduleEntry {
  installment: number;
  dayOffset: number;
  amountBaseUnits: string;
  cumulativeBaseUnits: string;
  remainingBaseUnits: string;
}

/** The pure, proof-free breakdown of a financing request. */
export interface FinancingState {
  revenueBaseUnits: string;
  requestedAdvanceBaseUnits: string;
  advanceFactorBps: string;
  creditLimitBaseUnits: string;
  headroomBaseUnits: string;
  /** factor·revenue − 10000·advance, as a signed decimal string; ≥ 0 exactly when eligible. */
  eligibilitySurplus: string;
  utilizationBps: string;
  overLimit: boolean;
  eligible: boolean;
}
export type FinancingRiskBand = "low" | "elevated" | "high" | "critical";

/** A deterministic financing-risk heuristic over the figures — not a credit score or model. */
export interface FinancingRiskAssessment {
  band: FinancingRiskBand;
  score: number;
  utilizationRatio: number;
  factorRatio: number;
  eligible: boolean;
  rationale: string;
}
export interface IssueFinancingCertificateInput {
  merchantAlias: string;
  asset: FinancingAsset;
  /** PUBLIC free-form reference to the advance request this attestation covers. */
  advanceRef: string;
  /** PUBLIC human-readable financing-program label. */
  programLabel: string;
  /** PUBLIC financing program: advance factor (proven) plus repayment metadata. */
  policy: FinancingPolicy;
  /** SECRET committed historical settlement revenue in integer base units. */
  revenueBaseUnits: string;
  /** SECRET requested advance in integer base units. Proven ≤ factor·revenue. */
  requestedAdvanceBaseUnits: string;
  /** SECRET financier/counterparty reference; only a salted commitment is published. */
  financierRef?: string;
  /** SECRET opaque payout-account reference; only a salted commitment is published. */
  payoutAccountRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface FinancingBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

/** Schnorr signature (challenge, response) over the binding by the issuer key. */
export interface IssuerSignature {
  challenge: string;
  response: string;
}
/**
 * Zero-knowledge proof bundle. `revenue ∈ [0, 2^amountBitLength)` (leg 0);
 * `advance ∈ [0, 2^amountBitLength)` (leg 1); the eligibility surplus
 * `factor·revenue − 10000·advance ∈ [0, 2^surplusBitLength)` (leg 2), tied to
 * `factor·C_revenue − 10000·C_advance`, which forces `advance ≤ factor/10000 · revenue`.
 */
export interface FinancingProof {
  proofSystem: typeof FINANCING_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  generatorH: CurvePointFelts;
  revenueCommitment: CurvePointFelts;
  advanceCommitment: CurvePointFelts;
  revenueBits: FinancingBitProof[];
  advanceBits: FinancingBitProof[];
  surplusBits: FinancingBitProof[];
}
export interface FinancingCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof FINANCING_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  merchantAlias: string;
  advanceRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC advance factor in bps: the advance is proven to be ≤ this fraction of revenue. */
  advanceFactorBps: string;
  /** PUBLIC financing fee in bps (repayment metadata; not proven). */
  feeBps: string;
  /** PUBLIC installment count (repayment metadata; not proven). */
  installments: string;
  /** PUBLIC installment spacing in days (repayment metadata; not proven). */
  intervalDays: string;
  /** Salted Poseidon commitment to the financier reference; hides the value. */
  financierCommitment: string;
  financierCommitted: boolean;
  /** Salted Poseidon commitment to the payout-account reference; hides the value. */
  payoutAccountCommitment: string;
  payoutAccountCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: FinancingProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}
/** SECRET issuer record of a freshly issued attestation. Never publish it. */
export interface FinancingCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  revenueBaseUnits: string;
  requestedAdvanceBaseUnits: string;
  advanceFactorBps: string;
  revenueBlinding: string;
  advanceBlinding: string;
  surplusBlinding: string;
  financierRef: string;
  financierSalt: string;
  financierCommitted: boolean;
  payoutAccountRef: string;
  payoutAccountSalt: string;
  payoutAccountCommitted: boolean;
}

export interface IssuedFinancingCertificate {
  certificate: FinancingCertificate;
  secret: FinancingCertificateSecret;
}

/** A full opening the merchant can hand a financier to disclose the underlying figures. */
export interface FinancingCertificateOpening {
  revenueBaseUnits: string;
  revenueBlinding: string;
  requestedAdvanceBaseUnits: string;
  advanceBlinding: string;
}

/** Selective disclosure of a single committed amount (revenue or advance). */
export interface FinancingAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  field: "revenue" | "advance";
  amountBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of a committed reference (financier or payout account). */
export interface FinancingRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: "financier" | "payoutAccount";
  value: string;
  salt: string;
}
export interface FinancingCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  merchantAlias: string;
  advanceRef: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  advanceFactorDisplay: string;
  feeDisplay: string;
  installmentsDisplay: string;
  financierCommitted: boolean;
  payoutAccountCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface FinancingTrustModel {
  isZeroKnowledge: boolean;
  provesAdvanceWithinFactorOfRevenue: boolean;
  hidesRevenue: boolean;
  hidesRequestedAdvance: boolean;
  hidesCustomerLists: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  advancesOrDisbursesFunds: boolean;
  settlesOnChain: boolean;
  movesPoolFunds: boolean;
  verifiesRevenueIsReal: boolean;
  isCreditScoreOrModel: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  isFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface FinancingVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const FINANCING_NOTICE =
  "Zero-knowledge proof that a requested capital advance is within a public advance factor of a merchant's committed historical settlement revenue — advance ≤ factor · revenue — hiding the revenue, the advance, the customer list, and individual invoice amounts. It authenticates the issuer and supports selective disclosure; it does not advance, disburse, or settle any funds, does not verify that the revenue is real, does not store a reusable payout credential, is neither decentralized nor automatic, and never reads from or writes to the STRK20 pool contract.";
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
export function deriveFinancingGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent financing generator.");
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
export function createFinancingIssuerKey(entropy: FinancingEntropy = {}): FinancingKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}
// ---------------------------------------------------------------------------
// Financing arithmetic, credit limit, repayment plan, and risk heuristic (pure)
// ---------------------------------------------------------------------------

/** Validates and normalizes a public financing policy. */
export function requireFinancingPolicy(policy: FinancingPolicy): {
  advanceFactorBps: number;
  feeBps: number;
  installments: number;
  intervalDays: number;
} {
  if (!policy || typeof policy !== "object") throw new Error("The financing policy is required.");
  const advanceFactorBps = requireInt(policy.advanceFactorBps, "advance factor bps", MIN_ADVANCE_FACTOR_BPS, MAX_ADVANCE_FACTOR_BPS);
  const feeBps = requireInt(policy.feeBps, "fee bps", 0, MAX_FINANCING_FEE_BPS);
  const installments = requireInt(policy.installments, "installments", 1, MAX_FINANCING_INSTALLMENTS);
  const intervalDays = requireInt(policy.intervalDays, "interval days", 1, MAX_FINANCING_INTERVAL_DAYS);
  return { advanceFactorBps, feeBps, installments, intervalDays };
}

/** The deterministic credit limit: floor(factor · revenue / 10000), in base units. */
export function computeCreditLimit(revenueBaseUnits: string | bigint, advanceFactorBps: number): string {
  const revenue = requireBaseUnits(revenueBaseUnits, "revenue");
  const factor = BigInt(requireInt(advanceFactorBps, "advance factor bps", MIN_ADVANCE_FACTOR_BPS, MAX_ADVANCE_FACTOR_BPS));
  return ((factor * revenue) / ADVANCE_FACTOR_SCALE).toString();
}

/**
 * Computes the pure financing state: the credit limit, remaining headroom, the
 * eligibility surplus, utilization, and whether the requested advance is
 * eligible. This is the same relation the zero-knowledge proof attests when `eligible`.
 */
export function computeFinancingState(
  revenueBaseUnits: string,
  requestedAdvanceBaseUnits: string,
  policy: FinancingPolicy,
): FinancingState {
  const { advanceFactorBps } = requireFinancingPolicy(policy);
  const revenue = requireBaseUnits(revenueBaseUnits, "revenue");
  const advance = requireBaseUnits(requestedAdvanceBaseUnits, "requested advance");
  if (revenue > U128_MAX) throw new Error("The revenue must fit within the u128 range.");
  if (advance > U128_MAX) throw new Error("The requested advance must fit within the u128 range.");
  const factor = BigInt(advanceFactorBps);
  const creditLimit = (factor * revenue) / ADVANCE_FACTOR_SCALE;
  const surplus = factor * revenue - ADVANCE_FACTOR_SCALE * advance;
  const overLimit = advance > creditLimit;
  const headroom = overLimit ? 0n : creditLimit - advance;
  const utilizationBps = creditLimit > 0n ? (advance * ADVANCE_FACTOR_SCALE) / creditLimit : advance > 0n ? ADVANCE_FACTOR_SCALE + 1n : 0n;
  return {
    revenueBaseUnits: revenue.toString(),
    requestedAdvanceBaseUnits: advance.toString(),
    advanceFactorBps: advanceFactorBps.toString(),
    creditLimitBaseUnits: creditLimit.toString(),
    headroomBaseUnits: headroom.toString(),
    eligibilitySurplus: surplus.toString(),
    utilizationBps: utilizationBps.toString(),
    overLimit,
    eligible: !overLimit,
  };
}
/**
 * Computes the planned repayment schedule for a given advance. This is a PLAN
 * only — the engine never executes it; the financier's own systems must. The
 * total repayment is `advance · (10000 + feeBps) / 10000`, split into equal
 * installments with any rounding remainder folded into the final installment.
 */
export function computeRepaymentSchedule(advanceBaseUnits: string | bigint, policy: FinancingPolicy): RepaymentScheduleEntry[] {
  const { feeBps, installments, intervalDays } = requireFinancingPolicy(policy);
  const advance = requireBaseUnits(advanceBaseUnits, "advance");
  const total = (advance * (ADVANCE_FACTOR_SCALE + BigInt(feeBps))) / ADVANCE_FACTOR_SCALE;
  const per = total / BigInt(installments);
  const entries: RepaymentScheduleEntry[] = [];
  let cumulative = 0n;
  for (let i = 1; i <= installments; i += 1) {
    const amount = i === installments ? total - cumulative : per;
    cumulative += amount;
    entries.push({
      installment: i,
      dayOffset: i * intervalDays,
      amountBaseUnits: amount.toString(),
      cumulativeBaseUnits: cumulative.toString(),
      remainingBaseUnits: (total - cumulative).toString(),
    });
  }
  return entries;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}

/**
 * A deterministic financing-risk band over the same figures — a transparent
 * heuristic (a blend of credit-limit utilization and the requested advance
 * factor), NOT a credit score, NOT a predictive model, and NOT financial advice.
 */
export function assessFinancingRisk(state: FinancingState): FinancingRiskAssessment {
  const advance = Number(state.requestedAdvanceBaseUnits);
  const creditLimit = Number(state.creditLimitBaseUnits);
  const utilizationRatio = creditLimit > 0 ? clamp01(advance / creditLimit) : advance > 0 ? 1 : 0;
  const factorRatio = clamp01(Number(state.advanceFactorBps) / MAX_ADVANCE_FACTOR_BPS);
  const score = Math.round(100 * clamp01(0.7 * utilizationRatio + 0.3 * factorRatio));
  let band: FinancingRiskBand;
  if (!state.eligible || score >= 75) band = "critical";
  else if (score >= 50) band = "high";
  else if (score >= 25) band = "elevated";
  else band = "low";
  return {
    band,
    score,
    utilizationRatio,
    factorRatio,
    eligible: state.eligible,
    rationale: state.eligible
      ? `Heuristic blend: ${(utilizationRatio * 100).toFixed(1)}% of the credit limit requested at a ${(factorRatio * 100).toFixed(0)}% advance factor.`
      : "Over the credit limit: the requested advance exceeds the public advance factor of the committed revenue.",
  };
}
export function formatFinancingBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

/** Formats an advance factor, e.g. 8000 → "80%", 8050 → "80.5%". */
export function formatAdvanceFactor(bps: string | number | bigint): string {
  const n = typeof bps === "bigint" ? Number(bps) : Number(bps);
  return `${(n / 100).toString()}%`;
}

/** Formats a financing fee, e.g. 1200 → "12% fee", 0 → "0% fee". */
export function formatFeeRate(bps: string | number | bigint): string {
  const n = typeof bps === "bigint" ? Number(bps) : Number(bps);
  return `${(n / 100).toString()}% fee`;
}

/** Formats an installment plan, e.g. (12, 30) → "12 × every 30 days". */
export function formatInstallments(installments: string | number, intervalDays: string | number): string {
  return `${installments} × every ${intervalDays} days`;
}
// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  certificateId: string;
  merchantAlias: string;
  advanceRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  advanceFactorBps: bigint;
  feeBps: bigint;
  installments: bigint;
  intervalDays: bigint;
  amountBitLength: number;
  surplusBitLength: number;
  financierCommitment: bigint;
  financierCommitted: boolean;
  payoutAccountCommitment: bigint;
  payoutAccountCommitted: boolean;
  createdAt: string;
  memo: string;
}

/**
 * The certificate binding hash: a Poseidon digest over every public,
 * proof-independent field plus the two commitments and the generator H. The
 * range-proof challenges and the issuer signature are all bound to it, so no
 * field can be altered without invalidating the certificate.
 */
function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  revenueCommitment: CurvePoint,
  advanceCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(FINANCING_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.advanceRef),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.advanceFactorBps,
    fields.feeBps,
    fields.installments,
    fields.intervalDays,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    fields.financierCommitment,
    fields.financierCommitted ? 1n : 0n,
    fields.payoutAccountCommitment,
    fields.payoutAccountCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    revenueCommitment.x,
    revenueCommitment.y,
    advanceCommitment.x,
    advanceCommitment.y,
    h.x,
    h.y,
  ]);
}
/** Context digest that seeds every range-proof challenge, bound to the certificate binding. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/**
 * Per-bit Fiat–Shamir challenge, bound to the context, the proof leg
 * (0 = revenue, 1 = advance, 2 = surplus), the index, and both proof nonces.
 */
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
): FinancingBitProof {
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
function verifyBit(proof: FinancingBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
): FinancingBitProof[] {
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
  const proofs: FinancingBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies every bit and returns the reconstructed commitment `Σ 2^i·C_i`, or null. */
function verifyRange(proofs: FinancingBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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
function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

/** Verifies the issuer Schnorr signature against the published public key. */
function verifySignature(signature: IssuerSignature, bindingHash: bigint, publicKey: CurvePoint): boolean {
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
// Issue and verify a financing certificate
// ---------------------------------------------------------------------------

/**
 * Issues a zero-knowledge financing eligibility certificate. Proves the
 * committed advance is within the public advance factor of the committed
 * revenue (advance ≤ factor · revenue), hiding both figures, and signs the
 * binding with the issuer key. Throws if the advance exceeds the credit limit,
 * since no honest proof of eligibility exists in that case.
 */
export function issueFinancingCertificate(
  input: IssueFinancingCertificateInput,
  now: Date = new Date(),
  entropy: FinancingEntropy = {},
): IssuedFinancingCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const advanceRef = requireText(input.advanceRef, "advance reference", 96);
  const programLabel = requireText(input.programLabel, "program label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const policy = requireFinancingPolicy(input.policy);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_FINANCING_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_FINANCING_AMOUNT_BIT_LENGTH,
    MAX_FINANCING_AMOUNT_BIT_LENGTH,
  );
  const surplusBitLength = amountBitLength + FINANCING_SURPLUS_EXTRA_BITS;
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const revenue = requireBaseUnits(input.revenueBaseUnits, "revenue");
  const advance = requireBaseUnits(input.requestedAdvanceBaseUnits, "requested advance");
  if (revenue >= 1n << BigInt(amountBitLength)) throw new Error(`The revenue exceeds the ${amountBitLength}-bit band.`);
  if (advance >= 1n << BigInt(amountBitLength)) throw new Error(`The requested advance exceeds the ${amountBitLength}-bit band.`);

  const factor = BigInt(policy.advanceFactorBps);
  const surplus = factor * revenue - ADVANCE_FACTOR_SCALE * advance;
  if (surplus < 0n)
    throw new Error("The requested advance exceeds the eligible credit limit for the committed revenue; no honest proof exists.");
  if (surplus >= 1n << BigInt(surplusBitLength)) throw new Error(`The eligibility surplus exceeds the ${surplusBitLength}-bit band.`);
  // __FE_ISSUE_2__
  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();

  const revenueBlinding = nonZeroScalar(nextScalar());
  const advanceBlinding = nonZeroScalar(nextScalar());
  const surplusBlinding = mod(factor * revenueBlinding - ADVANCE_FACTOR_SCALE * advanceBlinding, CURVE_ORDER);
  const revenueCommitment = pedersenCommit(revenue, revenueBlinding, h);
  const advanceCommitment = pedersenCommit(advance, advanceBlinding, h);

  const financierRef = input.financierRef ? requireText(input.financierRef, "financier reference", 96) : "";
  const payoutAccountRef = input.payoutAccountRef ? requireText(input.payoutAccountRef, "payout account reference", 128) : "";
  const financierCommitted = financierRef.length > 0;
  const payoutAccountCommitted = payoutAccountRef.length > 0;
  const financierSalt = nonZeroScalar(nextScalar());
  const payoutAccountSalt = nonZeroScalar(nextScalar());
  const financierCommitment = financierCommitted ? commitRef(FINANCIER_DOMAIN, financierRef, financierSalt) : 0n;
  const payoutAccountCommitment = payoutAccountCommitted ? commitRef(PAYOUT_DOMAIN, payoutAccountRef, payoutAccountSalt) : 0n;

  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());
  const fields: BindingFields = {
    certificateId, merchantAlias, advanceRef, programLabel, assetSymbol, tokenAddress, assetDecimals,
    advanceFactorBps: factor, feeBps: BigInt(policy.feeBps), installments: BigInt(policy.installments),
    intervalDays: BigInt(policy.intervalDays), amountBitLength, surplusBitLength,
    financierCommitment, financierCommitted, payoutAccountCommitment, payoutAccountCommitted, createdAt, memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, revenueCommitment, advanceCommitment, h);
  const ctx = statementContext(bindingHash);

  const revenueBits = proveRange(revenue, revenueBlinding, amountBitLength, ctx, 0, h, nextScalar);
  const advanceBits = proveRange(advance, advanceBlinding, amountBitLength, ctx, 1, h, nextScalar);
  const surplusBits = proveRange(surplus, surplusBlinding, surplusBitLength, ctx, 2, h, nextScalar);
  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);
  // __FE_ISSUE_3__
  const proof: FinancingProof = {
    proofSystem: FINANCING_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    generatorH: pointToFelts(h),
    revenueCommitment: pointToFelts(revenueCommitment),
    advanceCommitment: pointToFelts(advanceCommitment),
    revenueBits, advanceBits, surplusBits,
  };
  const certificate: FinancingCertificate = {
    kind: CERTIFICATE_KIND,
    version: FINANCING_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId, merchantAlias, advanceRef, programLabel, assetSymbol, tokenAddress, assetDecimals,
    advanceFactorBps: factor.toString(),
    feeBps: policy.feeBps.toString(),
    installments: policy.installments.toString(),
    intervalDays: policy.intervalDays.toString(),
    financierCommitment: toHex(financierCommitment),
    financierCommitted,
    payoutAccountCommitment: toHex(payoutAccountCommitment),
    payoutAccountCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof, issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt, memo,
    notice: FINANCING_NOTICE,
  };
  const secret: FinancingCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    revenueBaseUnits: revenue.toString(),
    requestedAdvanceBaseUnits: advance.toString(),
    advanceFactorBps: factor.toString(),
    revenueBlinding: toHex(revenueBlinding),
    advanceBlinding: toHex(advanceBlinding),
    surplusBlinding: toHex(surplusBlinding),
    financierRef, financierSalt: toHex(financierSalt), financierCommitted,
    payoutAccountRef, payoutAccountSalt: toHex(payoutAccountSalt), payoutAccountCommitted,
  };
  return { certificate, secret };
}
/**
 * Verifies a financing certificate end to end: the binding hash, the issuer
 * signature, both amount range proofs tied to their commitments, and the
 * eligibility-surplus range proof tied homomorphically to
 * `factor·C_revenue − 10000·C_advance`. A passing verdict means the committed
 * advance is a non-negative integer ≤ the public factor times the committed
 * (non-negative) revenue — nothing about the underlying figures is revealed.
 */
export function verifyFinancingCertificate(certificate: FinancingCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== FINANCING_PROOF_SYSTEM) return false;
    const amountBitLength = proof.amountBitLength;
    const surplusBitLength = proof.surplusBitLength;
    if (!Number.isInteger(amountBitLength) || amountBitLength < MIN_FINANCING_AMOUNT_BIT_LENGTH || amountBitLength > MAX_FINANCING_AMOUNT_BIT_LENGTH)
      return false;
    if (surplusBitLength !== amountBitLength + FINANCING_SURPLUS_EXTRA_BITS) return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const revenueCommitment = pointFromFelts(proof.revenueCommitment);
    const advanceCommitment = pointFromFelts(proof.advanceCommitment);
    // __FE_VERIFY_2__
    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      advanceRef: certificate.advanceRef,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: certificate.assetDecimals,
      advanceFactorBps: BigInt(certificate.advanceFactorBps),
      feeBps: BigInt(certificate.feeBps),
      installments: BigInt(certificate.installments),
      intervalDays: BigInt(certificate.intervalDays),
      amountBitLength,
      surplusBitLength,
      financierCommitment: requireFelt(certificate.financierCommitment),
      financierCommitted: certificate.financierCommitted,
      payoutAccountCommitment: requireFelt(certificate.payoutAccountCommitment),
      payoutAccountCommitted: certificate.payoutAccountCommitted,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };
    const bindingHash = computeBindingHash(fields, issuerKey, revenueCommitment, advanceCommitment, h);
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);
    const revenueSum = verifyRange(proof.revenueBits, amountBitLength, ctx, 0, h);
    if (!revenueSum || !revenueSum.equals(revenueCommitment)) return false;
    const advanceSum = verifyRange(proof.advanceBits, amountBitLength, ctx, 1, h);
    if (!advanceSum || !advanceSum.equals(advanceCommitment)) return false;
    const surplusSum = verifyRange(proof.surplusBits, surplusBitLength, ctx, 2, h);
    if (!surplusSum) return false;
    const expectedSurplus = scalePoint(revenueCommitment, BigInt(certificate.advanceFactorBps)).add(
      scalePoint(advanceCommitment, ADVANCE_FACTOR_SCALE).negate(),
    );
    if (!surplusSum.equals(expectedSurplus)) return false;
    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure and full opening
// ---------------------------------------------------------------------------

/** Builds a disclosure that opens the committed revenue figure alone. */
export function buildFinancingRevenueDisclosure(secret: FinancingCertificateSecret): FinancingAmountDisclosure {
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "revenue",
    amountBaseUnits: secret.revenueBaseUnits,
    blinding: secret.revenueBlinding,
  };
}

/** Builds a disclosure that opens the committed requested-advance figure alone. */
export function buildFinancingAdvanceDisclosure(secret: FinancingCertificateSecret): FinancingAmountDisclosure {
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "advance",
    amountBaseUnits: secret.requestedAdvanceBaseUnits,
    blinding: secret.advanceBlinding,
  };
}

/** Verifies a single-amount disclosure against the matching commitment in the certificate. */
export function verifyFinancingAmountDisclosure(certificate: FinancingCertificate, disclosure: FinancingAmountDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== AMOUNT_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const h = independentGenerator();
    const amount = requireBaseUnits(disclosure.amountBaseUnits, "disclosed amount");
    const blinding = requireScalar(disclosure.blinding, true);
    const recomputed = pedersenCommit(amount, blinding, h);
    const target =
      disclosure.field === "revenue"
        ? pointFromFelts(certificate.proof.revenueCommitment)
        : disclosure.field === "advance"
          ? pointFromFelts(certificate.proof.advanceCommitment)
          : null;
    return target ? recomputed.equals(target) : false;
  } catch {
    return false;
  }
}
/** Builds a disclosure that opens the committed financier reference, if one was committed. */
export function buildFinancingFinancierDisclosure(secret: FinancingCertificateSecret): FinancingRefDisclosure {
  if (!secret.financierCommitted) throw new Error("This certificate has no committed financier reference to disclose.");
  return { kind: REF_DISCLOSURE_KIND, certificateId: secret.certificateId, field: "financier", value: secret.financierRef, salt: secret.financierSalt };
}

/** Builds a disclosure that opens the committed payout-account reference, if one was committed. */
export function buildFinancingPayoutAccountDisclosure(secret: FinancingCertificateSecret): FinancingRefDisclosure {
  if (!secret.payoutAccountCommitted) throw new Error("This certificate has no committed payout-account reference to disclose.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "payoutAccount",
    value: secret.payoutAccountRef,
    salt: secret.payoutAccountSalt,
  };
}

/** Verifies a reference disclosure against the salted commitment in the certificate. */
export function verifyFinancingRefDisclosure(certificate: FinancingCertificate, disclosure: FinancingRefDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const salt = requireScalar(disclosure.salt, true);
    if (disclosure.field === "financier") {
      if (!certificate.financierCommitted) return false;
      return toHex(commitRef(FINANCIER_DOMAIN, disclosure.value, salt)) === certificate.financierCommitment;
    }
    if (disclosure.field === "payoutAccount") {
      if (!certificate.payoutAccountCommitted) return false;
      return toHex(commitRef(PAYOUT_DOMAIN, disclosure.value, salt)) === certificate.payoutAccountCommitment;
    }
    return false;
  } catch {
    return false;
  }
}

/** Verifies a full opening: both amount commitments open to the disclosed figures and blindings. */
export function verifyFinancingCertificateOpening(certificate: FinancingCertificate, opening: FinancingCertificateOpening): boolean {
  try {
    const h = independentGenerator();
    const revenue = requireBaseUnits(opening.revenueBaseUnits, "revenue");
    const advance = requireBaseUnits(opening.requestedAdvanceBaseUnits, "requested advance");
    const revenueBlinding = requireScalar(opening.revenueBlinding, true);
    const advanceBlinding = requireScalar(opening.advanceBlinding, true);
    const revenueOk = pedersenCommit(revenue, revenueBlinding, h).equals(pointFromFelts(certificate.proof.revenueCommitment));
    const advanceOk = pedersenCommit(advance, advanceBlinding, h).equals(pointFromFelts(certificate.proof.advanceCommitment));
    return revenueOk && advanceOk;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Badge, trust model, and visibility model
// ---------------------------------------------------------------------------

/** A compact, shareable summary of a certificate with only public display fields — no secret figures. */
export function buildFinancingCertificateBadge(certificate: FinancingCertificate): FinancingCertificateBadge {
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    advanceRef: certificate.advanceRef,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    advanceFactorDisplay: `≤ ${formatAdvanceFactor(certificate.advanceFactorBps)} of revenue`,
    feeDisplay: formatFeeRate(certificate.feeBps),
    installmentsDisplay: formatInstallments(certificate.installments, certificate.intervalDays),
    financierCommitted: certificate.financierCommitted,
    payoutAccountCommitted: certificate.payoutAccountCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}
/** An honest, machine-readable statement of exactly what this engine proves — and what it does not. */
export function summarizeFinancingTrust(): FinancingTrustModel {
  return {
    isZeroKnowledge: true,
    provesAdvanceWithinFactorOfRevenue: true,
    hidesRevenue: true,
    hidesRequestedAdvance: true,
    hidesCustomerLists: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    advancesOrDisbursesFunds: false,
    settlesOnChain: false,
    movesPoolFunds: false,
    verifiesRevenueIsReal: false,
    isCreditScoreOrModel: false,
    isDecentralized: false,
    isAutomatic: false,
    isFinancialAdvice: false,
    zeroKnowledgeElement:
      "A verifier learns only that the committed advance is a non-negative integer within the public advance factor of the committed (non-negative) revenue; the revenue, the advance, the blindings, the customer list, and the individual invoice amounts stay hidden.",
    statement:
      "This engine proves a requested capital advance is within a public advance factor of a merchant's committed historical settlement revenue, and authenticates the merchant that issued it. It is neither decentralized nor automatic: one merchant key issues attestations, and no contract, oracle, scheduler, or consensus vouches for the inputs. It does not advance, disburse, or settle any funds and does not move funds in the STRK20 pool; it does not verify that the committed revenue is real; and it never reads from or writes to the STRK20 pool contract — the pool address is provenance only. Its credit limit and risk band are deterministic heuristics, not a credit score, a predictive model, or financial advice, and any repayment schedule it computes is a plan that the financier's own systems must execute.",
  };
}
/** What a verifier does and does not learn from a certificate, stated plainly. */
export function getFinancingVisibilityModel(): FinancingVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The committed historical settlement revenue figure.",
      "The requested capital advance figure.",
      "The Pedersen blindings and the eligibility-surplus blinding.",
      "The customer list and every individual invoice amount.",
      "The financier and payout-account references, until selectively disclosed.",
    ],
    disclosedToVerifier: [
      "That the committed advance is ≤ the public advance factor of the committed revenue.",
      "That the revenue and advance are non-negative integers within the proven bit band.",
      "The public advance factor, fee, and repayment-plan metadata.",
      "The merchant alias, advance reference, program label, and asset.",
      "The issuer public key and Schnorr signature authenticating the attestation.",
      "Salted commitments to the financier and payout-account references.",
    ],
    applicationOnly: [
      "The certificate id, creation timestamp, and memo.",
      "The deterministic credit-limit and risk-band heuristics (not proven, not a credit score).",
      "The computed repayment schedule (a plan only; never executed by this engine).",
    ],
    limitation:
      "This is an off-chain attestation over merchant-supplied figures. It never reads from or writes to the STRK20 pool contract, does not advance or settle funds, and cannot confirm that the committed revenue reflects real settlements. The pool address is recorded for provenance only.",
  };
}
// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** Encodes a certificate as a compact base64url string for sharing. */
export function serializeFinancingCertificate(certificate: FinancingCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

/** Decodes and shallow-validates a certificate; does NOT re-verify the proof. */
export function parseFinancingCertificate(encoded: string): FinancingCertificate {
  const parsed = decodeJson(fromBase64Url(encoded)) as FinancingCertificate;
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("The encoded financing certificate is invalid.");
  return parsed;
}

/** Encodes the SECRET issuer record. Never publish this. */
export function serializeFinancingCertificateSecret(secret: FinancingCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseFinancingCertificateSecret(encoded: string): FinancingCertificateSecret {
  const parsed = decodeJson(fromBase64Url(encoded)) as FinancingCertificateSecret;
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("The encoded financing secret is invalid.");
  return parsed;
}

export function serializeFinancingAmountDisclosure(disclosure: FinancingAmountDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseFinancingAmountDisclosure(encoded: string): FinancingAmountDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as FinancingAmountDisclosure;
  if (!parsed || parsed.kind !== AMOUNT_DISCLOSURE_KIND) throw new Error("The encoded amount disclosure is invalid.");
  return parsed;
}

export function serializeFinancingRefDisclosure(disclosure: FinancingRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseFinancingRefDisclosure(encoded: string): FinancingRefDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as FinancingRefDisclosure;
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

function requireBaseUnits(value: string | bigint, label: string): bigint {
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

/** A default, collision-resistant certificate id (prefix `fin_`). */
function defaultId(kind: "certificate"): string {
  idCounter += 1;
  const rand = toHex(randomScalar()).slice(2, 12);
  return `fin_${kind}_${Date.now().toString(36)}_${idCounter}_${rand}`;
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
