/**
 * CipherBill — Subscription Dunning & Recovery Proof Engine
 * =========================================================
 *
 * A client-side module that, when a recurring subscription invoice fails to
 * settle, produces a zero-knowledge attestation that the delinquent
 * subscription is STILL RECOVERABLE under a PUBLIC dunning policy — that its
 * failed-retry count is at most a public maximum AND its delinquency age is
 * below a public grace period — WITHOUT revealing the outstanding balance, the
 * exact number of failed retries, the delinquency age, or the subscriber's
 * identity. It also binds a payment-token reference under a salted commitment so
 * the attestation is tied to a specific stored token without disclosing it.
 *
 * The zero-knowledge core combines Pedersen commitments over the STARK curve
 * with bit-decomposition range proofs. Each policy bound is enforced by a pair
 * of range legs (lower and upper): proving both `v` and `bound − v` are
 * non-negative bounded integers forces `0 ≤ v ≤ bound` with no separate linear
 * proof, exactly as a two-sided bound. Only a genuinely recoverable
 * subscription can be attested — if retries are exhausted or the grace period
 * has lapsed, the complement value is negative and no honest proof exists. The
 * merchant signs the binding so anyone can authenticate the issuer offline, and
 * the outstanding balance, subscriber reference, or payment-token reference can
 * be selectively disclosed later. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that a subscription is recoverable within a public policy.
 *   A verifier learns only that the committed attempt count is ≤ the public
 *   maximum and the committed delinquency age is < the public grace period —
 *   nothing about the balance, the exact counts, the blindings, or the subscriber.
 * - Issuer-authenticated. A Schnorr signature over the binding proves a specific
 *   merchant public key issued it; anyone can check it offline.
 * - Selectively disclosable. The merchant can later open the outstanding balance,
 *   the subscriber reference, or the payment-token reference against the commitments.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It does NOT charge, retry, or settle any payment. It attests a state the
 *   merchant supplied; the merchant's own billing scheduler executes retries
 *   out of band. The retry cadence it computes is a plan, not executed automation.
 * - It does NOT store or encrypt a reusable payment credential. The payment-token
 *   reference is bound under a one-way salted commitment and cannot be recovered
 *   or replayed to charge anyone.
 * - It does NOT validate that a subscriber, plan, or token is real or active. It
 *   only binds merchant-supplied values under salted commitments.
 * - It does NOT settle on-chain or move funds in the STRK20 pool, and never reads
 *   from or writes to the pool contract; the pool address below is provenance only.
 * - Its churn-risk band is a deterministic heuristic over the same figures, NOT a
 *   predictive model and NOT financial advice.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   attestations and no contract, oracle, scheduler, or consensus vouches for the
 *   inputs. `summarizeDunningTrust()` and `getDunningVisibilityModel()` state these limits.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const DUNNING_ENGINE_VERSION = 1 as const;
export const DUNNING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const DUNNING_PROOF_SYSTEM = "stark-pedersen-dunning-bounds-v1" as const;
/** Ceiling on the public retry maximum a policy may declare. */
export const MAX_DUNNING_ATTEMPTS = 32;
/** Ceiling on the public grace-period length (days) a policy may declare. */
export const MAX_DUNNING_GRACE_DAYS = 365;
/** Ceiling on the public retry spacing (hours) a policy may declare. */
export const MAX_DUNNING_INTERVAL_HOURS = 24 * 90;
/** 2^8 = 256 > MAX_DUNNING_ATTEMPTS, so attempts and (max − attempts) fit. */
export const DUNNING_ATTEMPTS_BIT_LENGTH = 8;
/** 2^9 = 512 > MAX_DUNNING_GRACE_DAYS, so elapsed and (grace − 1 − elapsed) fit. */
export const DUNNING_GRACE_BIT_LENGTH = 9;
export const DEFAULT_DUNNING_AMOUNT_BIT_LENGTH = 128;
export const MIN_DUNNING_AMOUNT_BIT_LENGTH = 8;
export const MAX_DUNNING_AMOUNT_BIT_LENGTH = 128;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill dunning generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill dunning statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill dunning bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill dunning binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill dunning issuer signature v1");
const SUBSCRIBER_DOMAIN = hash.starknetKeccak("CipherBill dunning subscriber ref v1");
const PAYMENT_TOKEN_DOMAIN = hash.starknetKeccak("CipherBill dunning payment token ref v1");
const VOUCHER_KIND = "cipherbill.dunning-voucher" as const;
const SECRET_KIND = "cipherbill.dunning-voucher-secret" as const;
const BALANCE_DISCLOSURE_KIND = "cipherbill.dunning-balance-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.dunning-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.dunning-voucher-badge" as const;
const KEYPAIR_KIND = "cipherbill.dunning-keypair" as const;
const MAX_ENCODED_LENGTH = 800_000;
export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface DunningAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface DunningKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface DunningEntropy {
  createId?: (kind: "voucher") => string;
  randomScalar?: () => bigint;
}

export type DunningCadence = "fixed" | "exponential";

/** A public recovery policy: how many retries, how far apart, and the grace window. */
export interface DunningPolicy {
  /** PUBLIC maximum number of failed retries tolerated, 1..MAX_DUNNING_ATTEMPTS. */
  maxAttempts: number;
  /** PUBLIC grace-period length in days, 1..MAX_DUNNING_GRACE_DAYS. */
  gracePeriodDays: number;
  /** PUBLIC base spacing between retries in hours, 1..MAX_DUNNING_INTERVAL_HOURS. */
  retryIntervalHours: number;
  /** PUBLIC cadence shape: fixed spacing or exponential backoff. */
  cadence: DunningCadence;
}

/** One planned retry attempt: purely a schedule the merchant's own system may execute. */
export interface RetryScheduleEntry {
  attempt: number;
  hourOffset: number;
  dayOffset: number;
  withinGrace: boolean;
}

/** The pure, proof-free breakdown of a subscription's dunning state. */
export interface DunningState {
  outstandingBaseUnits: string;
  attemptsMade: string;
  maxAttempts: string;
  remainingAttempts: string;
  elapsedDays: string;
  gracePeriodDays: string;
  remainingGraceDays: string;
  attemptsExhausted: boolean;
  graceExpired: boolean;
  recoverable: boolean;
}
export type ChurnRiskBand = "low" | "elevated" | "high" | "critical";

/** A deterministic churn-risk heuristic over the dunning figures — not a model. */
export interface ChurnRiskAssessment {
  band: ChurnRiskBand;
  score: number;
  attemptsRatio: number;
  graceRatio: number;
  recoverable: boolean;
  rationale: string;
}

export interface IssueDunningVoucherInput {
  merchantAlias: string;
  asset: DunningAsset;
  /** PUBLIC free-form reference to the subscription this attestation covers. */
  subscriptionRef: string;
  /** PUBLIC human-readable plan label. */
  planLabel: string;
  /** PUBLIC recovery policy. */
  policy: DunningPolicy;
  /** SECRET outstanding (delinquent) balance in integer base units. */
  outstandingBaseUnits: string;
  /** SECRET count of failed retries so far. Proven ≤ policy.maxAttempts. */
  attemptsMade: number;
  /** SECRET days since the first failed settlement. Proven < policy.gracePeriodDays. */
  elapsedDays: number;
  /** SECRET pseudonymous subscriber reference; only a salted commitment is published. */
  subscriberRef?: string;
  /** SECRET opaque payment-token reference; only a salted commitment is published. */
  paymentTokenRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface DunningBitProof {
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
 * Zero-knowledge proof bundle. `outstanding ∈ [0, 2^amountBitLength)` (leg 0);
 * `attemptsMade ∈ [0, maxAttempts]` via a lower leg (leg 1) tied to C_attempts
 * and an upper leg (leg 2) tied to `maxAttempts·G − C_attempts`; `elapsedDays ∈
 * [0, gracePeriodDays − 1]` via a lower leg (leg 3) tied to C_elapsed and an
 * upper leg (leg 4) tied to `(gracePeriodDays − 1)·G − C_elapsed`.
 */
export interface DunningProof {
  proofSystem: typeof DUNNING_PROOF_SYSTEM;
  amountBitLength: number;
  attemptsBitLength: number;
  graceBitLength: number;
  generatorH: CurvePointFelts;
  outstandingCommitment: CurvePointFelts;
  attemptsCommitment: CurvePointFelts;
  elapsedCommitment: CurvePointFelts;
  outstandingBits: DunningBitProof[];
  attemptsLowerBits: DunningBitProof[];
  attemptsUpperBits: DunningBitProof[];
  elapsedLowerBits: DunningBitProof[];
  elapsedUpperBits: DunningBitProof[];
}

export interface DunningVoucher {
  kind: typeof VOUCHER_KIND;
  version: typeof DUNNING_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  voucherId: string;
  merchantAlias: string;
  subscriptionRef: string;
  planLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC policy: retries are proven to be ≤ this maximum. */
  maxAttempts: string;
  /** PUBLIC policy: delinquency age is proven to be < this many days. */
  gracePeriodDays: string;
  /** PUBLIC cadence spacing in hours (schedule metadata; not proven). */
  retryIntervalHours: string;
  /** PUBLIC cadence shape (schedule metadata; not proven). */
  cadence: DunningCadence;
  /** Salted Poseidon commitment to the subscriber reference; hides the value. */
  subscriberCommitment: string;
  subscriberCommitted: boolean;
  /** Salted Poseidon commitment to the payment-token reference; hides the value. */
  paymentTokenCommitment: string;
  paymentTokenCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: DunningProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}
/** SECRET issuer record of a freshly issued attestation. Never publish it. */
export interface DunningVoucherSecret {
  kind: typeof SECRET_KIND;
  voucherId: string;
  outstandingBaseUnits: string;
  attemptsMade: string;
  elapsedDays: string;
  maxAttempts: string;
  gracePeriodDays: string;
  outstandingBlinding: string;
  attemptsBlinding: string;
  elapsedBlinding: string;
  subscriberRef: string;
  subscriberSalt: string;
  subscriberCommitted: boolean;
  paymentTokenRef: string;
  paymentTokenSalt: string;
  paymentTokenCommitted: boolean;
}

export interface IssuedDunningVoucher {
  voucher: DunningVoucher;
  secret: DunningVoucherSecret;
}

/** A full opening the merchant can hand an auditor to disclose every figure. */
export interface DunningVoucherOpening {
  outstandingBaseUnits: string;
  outstandingBlinding: string;
  attemptsMade: string;
  attemptsBlinding: string;
  elapsedDays: string;
  elapsedBlinding: string;
}

/** Selective disclosure of the outstanding balance alone. */
export interface DunningBalanceDisclosure {
  kind: typeof BALANCE_DISCLOSURE_KIND;
  voucherId: string;
  outstandingBaseUnits: string;
  outstandingBlinding: string;
}

/** Selective disclosure of a committed reference (subscriber or payment token). */
export interface DunningRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  voucherId: string;
  field: "subscriber" | "paymentToken";
  value: string;
  salt: string;
}
export interface DunningVoucherBadge {
  kind: typeof BADGE_KIND;
  voucherId: string;
  merchantAlias: string;
  subscriptionRef: string;
  planLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  maxAttemptsDisplay: string;
  gracePeriodDisplay: string;
  cadenceDisplay: string;
  subscriberCommitted: boolean;
  paymentTokenCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface DunningTrustModel {
  isZeroKnowledge: boolean;
  provesRecoverabilityWithinPolicy: boolean;
  hidesOutstandingBalance: boolean;
  hidesAttemptCount: boolean;
  hidesDelinquencyAge: boolean;
  hidesSubscriberIdentity: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  chargesOrRetriesPayments: boolean;
  settlesOnChain: boolean;
  bindsToRealFunds: boolean;
  storesReusablePaymentCredentials: boolean;
  predictsChurnWithModel: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  isFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface DunningVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const DUNNING_NOTICE =
  "Zero-knowledge proof that a delinquent subscription is recoverable under a public dunning policy — failed retries ≤ a public maximum and delinquency age < a public grace period — hiding the balance, exact counts, and subscriber. It authenticates the issuer and supports selective disclosure; it does not charge, retry, or settle any payment, does not store a reusable payment credential, is neither decentralized nor automatic, and never reads from or writes to the STRK20 pool contract.";
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

/** Returns the canonical H as serializable felts (for embedding in a voucher). */
export function deriveDunningGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent dunning generator.");
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
export function createDunningIssuerKey(entropy: DunningEntropy = {}): DunningKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}
// ---------------------------------------------------------------------------
// Dunning arithmetic, cadence, and churn heuristic (pure — proof-free)
// ---------------------------------------------------------------------------

/** Validates and normalizes a public dunning policy. */
export function requireDunningPolicy(policy: DunningPolicy): {
  maxAttempts: number;
  gracePeriodDays: number;
  retryIntervalHours: number;
  cadence: DunningCadence;
} {
  if (!policy || typeof policy !== "object") throw new Error("The dunning policy is required.");
  const maxAttempts = requireInt(policy.maxAttempts, "max attempts", 1, MAX_DUNNING_ATTEMPTS);
  const gracePeriodDays = requireInt(policy.gracePeriodDays, "grace period days", 1, MAX_DUNNING_GRACE_DAYS);
  const retryIntervalHours = requireInt(policy.retryIntervalHours, "retry interval hours", 1, MAX_DUNNING_INTERVAL_HOURS);
  const cadence: DunningCadence = policy.cadence === "exponential" ? "exponential" : "fixed";
  return { maxAttempts, gracePeriodDays, retryIntervalHours, cadence };
}

/**
 * Computes the pure dunning state: remaining retries and grace days, whether the
 * subscription is exhausted or lapsed, and whether it is still recoverable. This
 * is the same relation the zero-knowledge proof attests when `recoverable`.
 */
export function computeDunningState(
  outstandingBaseUnits: string,
  attemptsMade: number,
  elapsedDays: number,
  policy: DunningPolicy,
): DunningState {
  const { maxAttempts, gracePeriodDays } = requireDunningPolicy(policy);
  const outstanding = requireBaseUnits(outstandingBaseUnits, "outstanding balance");
  if (outstanding > U128_MAX) throw new Error("The outstanding balance must fit within the u128 range.");
  const attempts = requireInt(attemptsMade, "attempts made", 0, MAX_DUNNING_ATTEMPTS);
  const elapsed = requireInt(elapsedDays, "elapsed days", 0, MAX_DUNNING_GRACE_DAYS);
  const attemptsExhausted = attempts > maxAttempts;
  const graceExpired = elapsed >= gracePeriodDays;
  return {
    outstandingBaseUnits: outstanding.toString(),
    attemptsMade: attempts.toString(),
    maxAttempts: maxAttempts.toString(),
    remainingAttempts: (attemptsExhausted ? 0 : maxAttempts - attempts).toString(),
    elapsedDays: elapsed.toString(),
    gracePeriodDays: gracePeriodDays.toString(),
    remainingGraceDays: (graceExpired ? 0 : gracePeriodDays - elapsed).toString(),
    attemptsExhausted,
    graceExpired,
    recoverable: !attemptsExhausted && !graceExpired,
  };
}
/**
 * Computes the planned retry schedule from a policy. This is a PLAN only — the
 * engine never executes it; the merchant's own billing scheduler must. Fixed
 * cadence spaces attempts evenly; exponential doubles the spacing each attempt.
 */
export function computeRetrySchedule(policy: DunningPolicy): RetryScheduleEntry[] {
  const { maxAttempts, gracePeriodDays, retryIntervalHours, cadence } = requireDunningPolicy(policy);
  const entries: RetryScheduleEntry[] = [];
  for (let i = 1; i <= maxAttempts; i += 1) {
    const hourOffset = cadence === "exponential" ? retryIntervalHours * 2 ** (i - 1) : retryIntervalHours * i;
    const dayOffset = Math.floor(hourOffset / 24);
    entries.push({ attempt: i, hourOffset, dayOffset, withinGrace: dayOffset < gracePeriodDays });
  }
  return entries;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}

/**
 * A deterministic churn-risk band over the same figures — a transparent
 * heuristic (a 50/50 blend of retry pressure and grace-window pressure), NOT a
 * predictive model and NOT financial advice.
 */
export function assessChurnRisk(state: DunningState): ChurnRiskAssessment {
  const attempts = Number(state.attemptsMade);
  const maxAttempts = Number(state.maxAttempts);
  const elapsed = Number(state.elapsedDays);
  const grace = Number(state.gracePeriodDays);
  const attemptsRatio = maxAttempts > 0 ? clamp01(attempts / maxAttempts) : 0;
  const graceRatio = grace > 0 ? clamp01(elapsed / grace) : 0;
  const score = Math.round(100 * clamp01(0.5 * attemptsRatio + 0.5 * graceRatio));
  let band: ChurnRiskBand;
  if (!state.recoverable || score >= 75) band = "critical";
  else if (score >= 50) band = "high";
  else if (score >= 25) band = "elevated";
  else band = "low";
  return {
    band,
    score,
    attemptsRatio,
    graceRatio,
    recoverable: state.recoverable,
    rationale: state.recoverable
      ? `Heuristic blend: ${attempts}/${maxAttempts} retries used and ${elapsed}/${grace} grace days elapsed.`
      : "Outside the recovery policy: retries exhausted or the grace period has lapsed.",
  };
}
export function formatDunningBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

/** Formats a grace window, e.g. 14 → "14 days", 1 → "1 day". */
export function formatGraceWindow(days: string | number | bigint): string {
  const n = typeof days === "bigint" ? days : BigInt(days);
  return `${n} ${n === 1n ? "day" : "days"}`;
}

/** Formats a retry cadence, e.g. (24, "fixed") → "every 24h (fixed)". */
export function formatRetryCadence(retryIntervalHours: string | number, cadence: DunningCadence): string {
  const shape = cadence === "exponential" ? "exponential backoff" : "fixed";
  return `every ${retryIntervalHours}h (${shape})`;
}
// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  voucherId: string;
  merchantAlias: string;
  subscriptionRef: string;
  planLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  maxAttempts: bigint;
  gracePeriodDays: bigint;
  retryIntervalHours: bigint;
  cadence: DunningCadence;
  amountBitLength: number;
  subscriberCommitment: bigint;
  subscriberCommitted: boolean;
  paymentTokenCommitment: bigint;
  paymentTokenCommitted: boolean;
  createdAt: string;
  memo: string;
}

/**
 * The voucher binding hash: a Poseidon digest over every public,
 * proof-independent field plus the three commitments and the generator H. The
 * range-proof challenges and the issuer signature are all bound to it, so no
 * field can be altered without invalidating the voucher.
 */
function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  outstandingCommitment: CurvePoint,
  attemptsCommitment: CurvePoint,
  elapsedCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(DUNNING_ENGINE_VERSION),
    hash.starknetKeccak(fields.voucherId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.subscriptionRef),
    hash.starknetKeccak(fields.planLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.maxAttempts,
    fields.gracePeriodDays,
    fields.retryIntervalHours,
    hash.starknetKeccak(fields.cadence),
    BigInt(fields.amountBitLength),
    BigInt(DUNNING_ATTEMPTS_BIT_LENGTH),
    BigInt(DUNNING_GRACE_BIT_LENGTH),
    fields.subscriberCommitment,
    fields.subscriberCommitted ? 1n : 0n,
    fields.paymentTokenCommitment,
    fields.paymentTokenCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    outstandingCommitment.x,
    outstandingCommitment.y,
    attemptsCommitment.x,
    attemptsCommitment.y,
    elapsedCommitment.x,
    elapsedCommitment.y,
    h.x,
    h.y,
  ]);
}
/** Context digest that seeds every range-proof challenge, bound to the voucher binding. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/**
 * Per-bit Fiat–Shamir challenge, bound to the context, the proof leg
 * (0 = outstanding, 1 = attempts lower, 2 = attempts upper, 3 = elapsed lower,
 * 4 = elapsed upper), the index, and both proof nonces.
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
): DunningBitProof {
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
function verifyBit(proof: DunningBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
// Range-proof legs
// ---------------------------------------------------------------------------

/**
 * Builds one range-proof leg: bit-commits `value ∈ [0, 2^bitLength)` with fresh
 * per-bit blindings constrained so Σ 2^i·r_i ≡ `blinding` (mod n), then proves
 * each bit is 0/1. The homomorphic sum of the bit commitments therefore equals
 * `value·G + blinding·H`, which the verifier ties back to the target commitment.
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): DunningBitProof[] {
  const bitBlindings: bigint[] = [];
  let partial = 0n;
  for (let i = 0; i < bitLength - 1; i += 1) {
    const ri = nonZeroScalar(nextScalar());
    bitBlindings.push(ri);
    partial = mod(partial + (ri % CURVE_ORDER) * mod(1n << BigInt(i), CURVE_ORDER), CURVE_ORDER);
  }
  const topWeight = modInverse(mod(1n << BigInt(bitLength - 1), CURVE_ORDER), CURVE_ORDER);
  const lastBlinding = mod((blinding - partial) * topWeight, CURVE_ORDER);
  if (lastBlinding === 0n) {
    throw new Error("Entropy produced a degenerate bit blinding; retry with fresh randomness.");
  }
  bitBlindings.push(lastBlinding);

  const proofs: DunningBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const bit = Number((value >> BigInt(i)) & 1n);
    const commitment = pedersenCommit(BigInt(bit), bitBlindings[i], h);
    proofs.push(proveBit(bit, commitment, bitBlindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies one range-proof leg and returns Σ 2^i·C_i, or null if any bit proof fails. */
function verifyRange(proofs: DunningBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return null;
  let sum = ZERO;
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = verifyBit(proofs[i], ctx, leg, i, h);
    if (!commitment) return null;
    sum = sum.add(scalePoint(commitment, 1n << BigInt(i)));
  }
  return sum;
}
// ---------------------------------------------------------------------------
// Issuer signature
// ---------------------------------------------------------------------------

/** Schnorr signature over the binding hash by the issuer key. */
function signBinding(bindingHash: bigint, issuerSecret: bigint, issuerKey: CurvePoint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const r = scalePoint(G, k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, issuerKey.x, issuerKey.y, r.x, r.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * issuerSecret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

function verifySignature(bindingHash: bigint, issuerKey: CurvePoint, signature: IssuerSignature): boolean {
  const challenge = requireScalar(signature.challenge, true);
  const response = requireScalar(signature.response, true);
  const r = scalePoint(G, response).add(scalePoint(issuerKey, challenge).negate());
  const recomputed = mod(hashElements([SIGNATURE_DOMAIN, issuerKey.x, issuerKey.y, r.x, r.y, bindingHash]), CURVE_ORDER);
  return recomputed === challenge;
}

// ---------------------------------------------------------------------------
// Issue and verify
// ---------------------------------------------------------------------------

/** Recomputes the binding hash from a voucher's public fields (used by verify). */
function bindingHashForVoucher(voucher: DunningVoucher, h: CurvePoint): bigint {
  const fields: BindingFields = {
    voucherId: voucher.voucherId,
    merchantAlias: voucher.merchantAlias,
    subscriptionRef: voucher.subscriptionRef,
    planLabel: voucher.planLabel,
    assetSymbol: voucher.assetSymbol,
    tokenAddress: voucher.tokenAddress,
    assetDecimals: voucher.assetDecimals,
    maxAttempts: requireCount(voucher.maxAttempts, "max attempts", 1, MAX_DUNNING_ATTEMPTS),
    gracePeriodDays: requireCount(voucher.gracePeriodDays, "grace period days", 1, MAX_DUNNING_GRACE_DAYS),
    retryIntervalHours: requireCount(voucher.retryIntervalHours, "retry interval hours", 1, MAX_DUNNING_INTERVAL_HOURS),
    cadence: voucher.cadence === "exponential" ? "exponential" : "fixed",
    amountBitLength: voucher.proof.amountBitLength,
    subscriberCommitment: requireFelt(voucher.subscriberCommitment, "subscriber commitment"),
    subscriberCommitted: voucher.subscriberCommitted === true,
    paymentTokenCommitment: requireFelt(voucher.paymentTokenCommitment, "payment token commitment"),
    paymentTokenCommitted: voucher.paymentTokenCommitted === true,
    createdAt: voucher.createdAt,
    memo: voucher.memo,
  };
  return computeBindingHash(
    fields,
    pointFromFelts(voucher.issuerPublicKey),
    pointFromFelts(voucher.proof.outstandingCommitment),
    pointFromFelts(voucher.proof.attemptsCommitment),
    pointFromFelts(voucher.proof.elapsedCommitment),
    h,
  );
}
/**
 * Issues a dunning attestation: commits the outstanding balance, the failed-retry
 * count, and the delinquency age; proves in zero knowledge that the balance is a
 * bounded non-negative integer, the retry count is ≤ the public maximum, and the
 * delinquency age is below the public grace period; binds salted commitments to
 * the subscriber and payment-token references; and signs the binding as the
 * merchant. Throws if the subscription is not recoverable — no honest proof
 * exists once retries are exhausted or the grace period has lapsed. Returns the
 * publishable voucher and the secret opening the issuer retains (never publish it).
 */
export function issueDunningVoucher(
  input: IssueDunningVoucherInput,
  now: Date = new Date(),
  entropy: DunningEntropy = {},
): IssuedDunningVoucher {
  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 80);
  const subscriptionRef = requireText(input.subscriptionRef, "subscription reference", 120);
  const planLabel = requireText(input.planLabel, "plan label", 80);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress ?? "");
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 18);
  const memo = typeof input.memo === "string" && input.memo.trim() ? requireText(input.memo, "memo", 200) : "";
  const { maxAttempts, gracePeriodDays, retryIntervalHours, cadence } = requireDunningPolicy(input.policy);
  const amountBitLength =
    input.amountBitLength === undefined
      ? DEFAULT_DUNNING_AMOUNT_BIT_LENGTH
      : requireInt(input.amountBitLength, "amount bit length", MIN_DUNNING_AMOUNT_BIT_LENGTH, MAX_DUNNING_AMOUNT_BIT_LENGTH);

  const outstanding = requireBaseUnits(input.outstandingBaseUnits, "outstanding balance");
  if (outstanding > U128_MAX) throw new Error("The outstanding balance must fit within the u128 range.");
  if (outstanding >= 1n << BigInt(amountBitLength)) {
    throw new Error(`The outstanding balance exceeds the provable ${amountBitLength}-bit band.`);
  }

  const attempts = requireInt(input.attemptsMade, "attempts made", 0, MAX_DUNNING_ATTEMPTS);
  const elapsed = requireInt(input.elapsedDays, "elapsed days", 0, MAX_DUNNING_GRACE_DAYS);
  if (attempts > maxAttempts) {
    throw new Error("The subscription has exhausted its retries; it is outside the recovery policy and cannot be attested.");
  }
  if (elapsed >= gracePeriodDays) {
    throw new Error("The subscription's grace period has lapsed; it is outside the recovery policy and cannot be attested.");
  }

  const subscriberRef = typeof input.subscriberRef === "string" ? input.subscriberRef.trim() : "";
  if (subscriberRef.length > 96) throw new Error("The subscriber reference is too long (max 96 characters).");
  const subscriberCommitted = subscriberRef.length > 0;
  const paymentTokenRef = typeof input.paymentTokenRef === "string" ? input.paymentTokenRef.trim() : "";
  if (paymentTokenRef.length > 128) throw new Error("The payment token reference is too long (max 128 characters).");
  const paymentTokenCommitted = paymentTokenRef.length > 0;

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);

  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? ((kind: "voucher") => defaultId(kind));
  const h = independentGenerator();

  const outstandingBlinding = nonZeroScalar(nextScalar());
  const attemptsBlinding = nonZeroScalar(nextScalar());
  const elapsedBlinding = nonZeroScalar(nextScalar());
  const outstandingCommitment = pedersenCommit(outstanding, outstandingBlinding, h);
  const attemptsCommitment = pedersenCommit(BigInt(attempts), attemptsBlinding, h);
  const elapsedCommitment = pedersenCommit(BigInt(elapsed), elapsedBlinding, h);

  const subscriberSalt = subscriberCommitted ? nonZeroScalar(nextScalar()) : 0n;
  const subscriberCommitment = subscriberCommitted ? commitRef(SUBSCRIBER_DOMAIN, subscriberRef, subscriberSalt) : 0n;
  const paymentTokenSalt = paymentTokenCommitted ? nonZeroScalar(nextScalar()) : 0n;
  const paymentTokenCommitment = paymentTokenCommitted
    ? commitRef(PAYMENT_TOKEN_DOMAIN, paymentTokenRef, paymentTokenSalt)
    : 0n;

  const voucherId = requireText(createId("voucher"), "voucher id", 80);
  const createdAt = now.toISOString();
  const bindingHash = computeBindingHash(
    {
      voucherId,
      merchantAlias,
      subscriptionRef,
      planLabel,
      assetSymbol,
      tokenAddress,
      assetDecimals,
      maxAttempts: BigInt(maxAttempts),
      gracePeriodDays: BigInt(gracePeriodDays),
      retryIntervalHours: BigInt(retryIntervalHours),
      cadence,
      amountBitLength,
      subscriberCommitment,
      subscriberCommitted,
      paymentTokenCommitment,
      paymentTokenCommitted,
      createdAt,
      memo,
    },
    issuerKey,
    outstandingCommitment,
    attemptsCommitment,
    elapsedCommitment,
    h,
  );
  const ctx = statementContext(bindingHash);

  // Leg 0: outstanding ∈ [0, 2^amountBitLength). Legs 1/2 pin attempts ∈ [0, maxAttempts]
  // (lower tied to C_attempts, upper — value maxAttempts−attempts, blinding −attemptsBlinding —
  // tied to maxAttempts·G − C_attempts). Legs 3/4 pin elapsed ∈ [0, gracePeriodDays−1] the same way.
  const outstandingBits = proveRange(outstanding, outstandingBlinding, amountBitLength, ctx, 0, h, nextScalar);
  const attemptsLowerBits = proveRange(BigInt(attempts), attemptsBlinding, DUNNING_ATTEMPTS_BIT_LENGTH, ctx, 1, h, nextScalar);
  const attemptsUpperBits = proveRange(
    BigInt(maxAttempts - attempts),
    mod(-attemptsBlinding, CURVE_ORDER),
    DUNNING_ATTEMPTS_BIT_LENGTH,
    ctx,
    2,
    h,
    nextScalar,
  );
  const elapsedLowerBits = proveRange(BigInt(elapsed), elapsedBlinding, DUNNING_GRACE_BIT_LENGTH, ctx, 3, h, nextScalar);
  const elapsedUpperBits = proveRange(
    BigInt(gracePeriodDays - 1 - elapsed),
    mod(-elapsedBlinding, CURVE_ORDER),
    DUNNING_GRACE_BIT_LENGTH,
    ctx,
    4,
    h,
    nextScalar,
  );

  const issuerSignature = signBinding(bindingHash, issuerSecret, issuerKey, nextScalar);

  const proof: DunningProof = {
    proofSystem: DUNNING_PROOF_SYSTEM,
    amountBitLength,
    attemptsBitLength: DUNNING_ATTEMPTS_BIT_LENGTH,
    graceBitLength: DUNNING_GRACE_BIT_LENGTH,
    generatorH: pointToFelts(h),
    outstandingCommitment: pointToFelts(outstandingCommitment),
    attemptsCommitment: pointToFelts(attemptsCommitment),
    elapsedCommitment: pointToFelts(elapsedCommitment),
    outstandingBits,
    attemptsLowerBits,
    attemptsUpperBits,
    elapsedLowerBits,
    elapsedUpperBits,
  };
  const voucher: DunningVoucher = {
    kind: VOUCHER_KIND,
    version: DUNNING_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    voucherId,
    merchantAlias,
    subscriptionRef,
    planLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    maxAttempts: maxAttempts.toString(),
    gracePeriodDays: gracePeriodDays.toString(),
    retryIntervalHours: retryIntervalHours.toString(),
    cadence,
    subscriberCommitment: toHex(subscriberCommitment),
    subscriberCommitted,
    paymentTokenCommitment: toHex(paymentTokenCommitment),
    paymentTokenCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: DUNNING_NOTICE,
  };

  const secret: DunningVoucherSecret = {
    kind: SECRET_KIND,
    voucherId,
    outstandingBaseUnits: outstanding.toString(),
    attemptsMade: attempts.toString(),
    elapsedDays: elapsed.toString(),
    maxAttempts: maxAttempts.toString(),
    gracePeriodDays: gracePeriodDays.toString(),
    outstandingBlinding: toHex(outstandingBlinding),
    attemptsBlinding: toHex(attemptsBlinding),
    elapsedBlinding: toHex(elapsedBlinding),
    subscriberRef,
    subscriberSalt: toHex(subscriberSalt),
    subscriberCommitted,
    paymentTokenRef,
    paymentTokenSalt: toHex(paymentTokenSalt),
    paymentTokenCommitted,
  };

  return { voucher, secret };
}
/**
 * Verifies a dunning attestation with no secret material: checks the envelope,
 * that H is the canonical generator, that the binding hash matches every public
 * field, that the issuer signature is valid, and that all five range legs hold —
 * proving the committed outstanding balance is a bounded non-negative integer,
 * the committed retry count is ≤ the public maximum, and the committed
 * delinquency age is < the public grace period. Returns true only if all pass.
 */
export function verifyDunningVoucher(voucher: DunningVoucher): boolean {
  try {
    if (!voucher || typeof voucher !== "object") return false;
    if (voucher.kind !== VOUCHER_KIND) return false;
    if (voucher.version !== DUNNING_ENGINE_VERSION) return false;
    if (voucher.network !== MAINNET_CHAIN_ID) return false;
    const proof = voucher.proof;
    if (!proof || proof.proofSystem !== DUNNING_PROOF_SYSTEM) return false;
    if (proof.attemptsBitLength !== DUNNING_ATTEMPTS_BIT_LENGTH) return false;
    if (proof.graceBitLength !== DUNNING_GRACE_BIT_LENGTH) return false;
    if (
      !Number.isInteger(proof.amountBitLength) ||
      proof.amountBitLength < MIN_DUNNING_AMOUNT_BIT_LENGTH ||
      proof.amountBitLength > MAX_DUNNING_AMOUNT_BIT_LENGTH
    ) {
      return false;
    }

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;

    const bindingHash = bindingHashForVoucher(voucher, h);
    if (bindingHash !== requireFelt(voucher.bindingHash, "binding hash")) return false;

    const issuerKey = pointFromFelts(voucher.issuerPublicKey);
    if (!verifySignature(bindingHash, issuerKey, voucher.issuerSignature)) return false;

    const maxAttempts = requireCount(voucher.maxAttempts, "max attempts", 1, MAX_DUNNING_ATTEMPTS);
    const gracePeriodDays = requireCount(voucher.gracePeriodDays, "grace period days", 1, MAX_DUNNING_GRACE_DAYS);

    const outstandingCommitment = pointFromFelts(proof.outstandingCommitment);
    const attemptsCommitment = pointFromFelts(proof.attemptsCommitment);
    const elapsedCommitment = pointFromFelts(proof.elapsedCommitment);
    const ctx = statementContext(bindingHash);

    const sum0 = verifyRange(proof.outstandingBits, proof.amountBitLength, ctx, 0, h);
    if (!sum0 || !sum0.equals(outstandingCommitment)) return false;

    const sum1 = verifyRange(proof.attemptsLowerBits, DUNNING_ATTEMPTS_BIT_LENGTH, ctx, 1, h);
    if (!sum1 || !sum1.equals(attemptsCommitment)) return false;

    const sum2 = verifyRange(proof.attemptsUpperBits, DUNNING_ATTEMPTS_BIT_LENGTH, ctx, 2, h);
    if (!sum2 || !sum2.equals(scalePoint(G, maxAttempts).add(attemptsCommitment.negate()))) return false;

    const sum3 = verifyRange(proof.elapsedLowerBits, DUNNING_GRACE_BIT_LENGTH, ctx, 3, h);
    if (!sum3 || !sum3.equals(elapsedCommitment)) return false;

    const sum4 = verifyRange(proof.elapsedUpperBits, DUNNING_GRACE_BIT_LENGTH, ctx, 4, h);
    if (!sum4 || !sum4.equals(scalePoint(G, gracePeriodDays - 1n).add(elapsedCommitment.negate()))) return false;

    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure
// ---------------------------------------------------------------------------

/** Builds a disclosure that opens the outstanding balance against its commitment. */
export function buildDunningBalanceDisclosure(secret: DunningVoucherSecret): DunningBalanceDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("A dunning voucher secret is required.");
  return {
    kind: BALANCE_DISCLOSURE_KIND,
    voucherId: secret.voucherId,
    outstandingBaseUnits: secret.outstandingBaseUnits,
    outstandingBlinding: secret.outstandingBlinding,
  };
}

/** Verifies a balance disclosure against the voucher's outstanding commitment. */
export function verifyDunningBalanceDisclosure(voucher: DunningVoucher, disclosure: DunningBalanceDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== BALANCE_DISCLOSURE_KIND) return false;
    if (disclosure.voucherId !== voucher.voucherId) return false;
    const outstanding = requireBaseUnits(disclosure.outstandingBaseUnits, "outstanding balance");
    if (outstanding > U128_MAX) return false;
    const blinding = requireScalar(disclosure.outstandingBlinding, true);
    const recomputed = pedersenCommit(outstanding, blinding, independentGenerator());
    return recomputed.equals(pointFromFelts(voucher.proof.outstandingCommitment));
  } catch {
    return false;
  }
}

/** Builds a disclosure that opens the subscriber reference against its commitment. */
export function buildDunningSubscriberDisclosure(secret: DunningVoucherSecret): DunningRefDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("A dunning voucher secret is required.");
  if (!secret.subscriberCommitted) throw new Error("This voucher does not commit to a subscriber reference.");
  return { kind: REF_DISCLOSURE_KIND, voucherId: secret.voucherId, field: "subscriber", value: secret.subscriberRef, salt: secret.subscriberSalt };
}

/** Builds a disclosure that opens the payment-token reference against its commitment. */
export function buildDunningPaymentTokenDisclosure(secret: DunningVoucherSecret): DunningRefDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("A dunning voucher secret is required.");
  if (!secret.paymentTokenCommitted) throw new Error("This voucher does not commit to a payment-token reference.");
  return { kind: REF_DISCLOSURE_KIND, voucherId: secret.voucherId, field: "paymentToken", value: secret.paymentTokenRef, salt: secret.paymentTokenSalt };
}

/** Verifies a reference disclosure (subscriber or payment token) against its commitment. */
export function verifyDunningRefDisclosure(voucher: DunningVoucher, disclosure: DunningRefDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND) return false;
    if (disclosure.voucherId !== voucher.voucherId) return false;
    const salt = requireScalar(disclosure.salt, true);
    if (disclosure.field === "subscriber") {
      if (!voucher.subscriberCommitted) return false;
      const recomputed = commitRef(SUBSCRIBER_DOMAIN, disclosure.value, salt);
      return recomputed === requireFelt(voucher.subscriberCommitment, "subscriber commitment");
    }
    if (disclosure.field === "paymentToken") {
      if (!voucher.paymentTokenCommitted) return false;
      const recomputed = commitRef(PAYMENT_TOKEN_DOMAIN, disclosure.value, salt);
      return recomputed === requireFelt(voucher.paymentTokenCommitment, "payment token commitment");
    }
    return false;
  } catch {
    return false;
  }
}
/**
 * Verifies a full opening of all three commitments against the voucher and
 * re-checks the recovery relation in the clear: outstanding fits the provable
 * band, the attempt count is ≤ the public maximum, and the delinquency age is
 * below the public grace period. This is what an auditor runs after the merchant
 * hands over the complete opening.
 */
export function verifyDunningVoucherOpening(voucher: DunningVoucher, opening: DunningVoucherOpening): boolean {
  try {
    if (!opening || typeof opening !== "object") return false;
    const h = independentGenerator();
    const maxAttempts = requireCount(voucher.maxAttempts, "max attempts", 1, MAX_DUNNING_ATTEMPTS);
    const gracePeriodDays = requireCount(voucher.gracePeriodDays, "grace period days", 1, MAX_DUNNING_GRACE_DAYS);
    const amountBitLength = voucher.proof.amountBitLength;

    const outstanding = requireBaseUnits(opening.outstandingBaseUnits, "outstanding balance");
    if (outstanding > U128_MAX || outstanding >= 1n << BigInt(amountBitLength)) return false;
    const attempts = requireCount(opening.attemptsMade, "attempts made", 0, MAX_DUNNING_ATTEMPTS);
    const elapsed = requireCount(opening.elapsedDays, "elapsed days", 0, MAX_DUNNING_GRACE_DAYS);
    if (attempts > maxAttempts) return false;
    if (elapsed >= gracePeriodDays) return false;

    const outstandingBlinding = requireScalar(opening.outstandingBlinding, true);
    const attemptsBlinding = requireScalar(opening.attemptsBlinding, true);
    const elapsedBlinding = requireScalar(opening.elapsedBlinding, true);
    if (!pedersenCommit(outstanding, outstandingBlinding, h).equals(pointFromFelts(voucher.proof.outstandingCommitment))) return false;
    if (!pedersenCommit(attempts, attemptsBlinding, h).equals(pointFromFelts(voucher.proof.attemptsCommitment))) return false;
    if (!pedersenCommit(elapsed, elapsedBlinding, h).equals(pointFromFelts(voucher.proof.elapsedCommitment))) return false;
    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Badge, trust, and visibility summaries
// ---------------------------------------------------------------------------

/** A compact, display-only badge of a voucher's public fields (no proof payload). */
export function buildDunningVoucherBadge(voucher: DunningVoucher): DunningVoucherBadge {
  return {
    kind: BADGE_KIND,
    voucherId: voucher.voucherId,
    merchantAlias: voucher.merchantAlias,
    subscriptionRef: voucher.subscriptionRef,
    planLabel: voucher.planLabel,
    assetSymbol: voucher.assetSymbol,
    network: voucher.network,
    maxAttemptsDisplay: `≤ ${voucher.maxAttempts} retries`,
    gracePeriodDisplay: `< ${formatGraceWindow(voucher.gracePeriodDays)}`,
    cadenceDisplay: formatRetryCadence(voucher.retryIntervalHours, voucher.cadence),
    subscriberCommitted: voucher.subscriberCommitted,
    paymentTokenCommitted: voucher.paymentTokenCommitted,
    createdAt: voucher.createdAt,
    bindingHash: voucher.bindingHash,
    issuerPublicKey: voucher.issuerPublicKey,
  };
}

/** An explicit, honest statement of exactly what a dunning voucher does and does not prove. */
export function summarizeDunningTrust(): DunningTrustModel {
  return {
    isZeroKnowledge: true,
    provesRecoverabilityWithinPolicy: true,
    hidesOutstandingBalance: true,
    hidesAttemptCount: true,
    hidesDelinquencyAge: true,
    hidesSubscriberIdentity: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    chargesOrRetriesPayments: false,
    settlesOnChain: false,
    bindsToRealFunds: false,
    storesReusablePaymentCredentials: false,
    predictsChurnWithModel: false,
    isDecentralized: false,
    isAutomatic: false,
    isFinancialAdvice: false,
    zeroKnowledgeElement:
      "The verifier learns only that the committed retry count is ≤ the public maximum and the committed delinquency age is < the public grace period. The outstanding balance, exact retry count, delinquency age, blindings, and subscriber and payment-token references stay hidden unless the merchant selectively discloses them.",
    statement:
      "This voucher is a genuine zero-knowledge proof that a delinquent subscription is recoverable under a public dunning policy, authenticated by the issuer's signature. It is neither decentralized nor automatic: a single merchant key issues it and no contract, oracle, scheduler, or consensus vouches for the inputs. It does not charge, retry, or settle any payment — the retry cadence is a plan the merchant's own scheduler must execute — and it does not store a reusable payment credential; the payment-token reference is a one-way salted commitment. The churn-risk band is a deterministic heuristic, not a predictive model and not financial advice. It never reads from or writes to the STRK20 pool contract; the pool address is provenance only.",
  };
}
/** What a verifier can and cannot see from a published voucher. */
export function getDunningVisibilityModel(): DunningVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The outstanding (delinquent) balance.",
      "The exact number of failed retries so far.",
      "The delinquency age in days.",
      "All Pedersen blindings and Poseidon salts.",
      "The subscriber reference (only a salted commitment is published).",
      "The payment-token reference (only a salted commitment is published).",
    ],
    disclosedToVerifier: [
      "That the committed retry count is ≤ the public maximum.",
      "That the committed delinquency age is < the public grace period.",
      "That the committed outstanding balance is a bounded non-negative integer.",
      "The public policy: max retries, grace-period length, and retry cadence.",
      "The merchant alias, subscription reference, plan label, and asset.",
      "The issuer public key and a valid signature over the binding.",
    ],
    applicationOnly: [
      "Whether the subscriber or payment-token references correspond to real, active records — the engine only binds merchant-supplied values.",
      "Executing the retry cadence — the engine computes a plan; the merchant's own billing scheduler must run it.",
      "Any actual settlement of the outstanding balance.",
    ],
    limitation:
      "The proof attests merchant-supplied figures under a public policy; it does not verify that the subscription, subscriber, or payment token is real or active, does not charge, retry, or settle any payment, and never reads from or writes to the STRK20 pool contract.",
  };
}
// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** Encodes a voucher as a compact, URL-safe base64 string for transport. */
export function serializeDunningVoucher(voucher: DunningVoucher): string {
  return toBase64Url(encodeJson(voucher));
}

/** Encodes a voucher secret as a URL-safe base64 string. NEVER share this. */
export function serializeDunningVoucherSecret(secret: DunningVoucherSecret): string {
  return toBase64Url(encodeJson(secret));
}

/** Encodes a balance disclosure as a URL-safe base64 string. */
export function serializeDunningBalanceDisclosure(disclosure: DunningBalanceDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

/** Encodes a reference disclosure as a URL-safe base64 string. */
export function serializeDunningRefDisclosure(disclosure: DunningRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

function parsePoint(value: unknown): CurvePointFelts {
  if (!value || typeof value !== "object") throw new Error("A curve point is missing.");
  const point = value as { x?: unknown; y?: unknown };
  return pointToFelts(pointFromFelts({ x: toHex(requireFelt(point.x, "point x")), y: toHex(requireFelt(point.y, "point y")) }));
}

function parseBitProof(value: unknown): DunningBitProof {
  if (!value || typeof value !== "object") throw new Error("A bit proof is malformed.");
  const p = value as Record<string, unknown>;
  return {
    commitment: parsePoint(p.commitment),
    a0: parsePoint(p.a0),
    a1: parsePoint(p.a1),
    challenge0: toHex(requireScalar(p.challenge0, true)),
    response0: toHex(requireScalar(p.response0, true)),
    response1: toHex(requireScalar(p.response1, true)),
  };
}

function parseBitProofArray(value: unknown, expected: number, label: string): DunningBitProof[] {
  if (!Array.isArray(value) || value.length !== expected) throw new Error(`The ${label} proof is malformed.`);
  return value.map(parseBitProof);
}
function parseProof(value: unknown): DunningProof {
  if (!value || typeof value !== "object") throw new Error("The proof is missing.");
  const p = value as Record<string, unknown>;
  if (p.proofSystem !== DUNNING_PROOF_SYSTEM) throw new Error("Unsupported dunning proof system.");
  const amountBitLength = requireInt(p.amountBitLength, "amount bit length", MIN_DUNNING_AMOUNT_BIT_LENGTH, MAX_DUNNING_AMOUNT_BIT_LENGTH);
  if (p.attemptsBitLength !== DUNNING_ATTEMPTS_BIT_LENGTH) throw new Error("Unexpected attempts bit length.");
  if (p.graceBitLength !== DUNNING_GRACE_BIT_LENGTH) throw new Error("Unexpected grace bit length.");
  return {
    proofSystem: DUNNING_PROOF_SYSTEM,
    amountBitLength,
    attemptsBitLength: DUNNING_ATTEMPTS_BIT_LENGTH,
    graceBitLength: DUNNING_GRACE_BIT_LENGTH,
    generatorH: parsePoint(p.generatorH),
    outstandingCommitment: parsePoint(p.outstandingCommitment),
    attemptsCommitment: parsePoint(p.attemptsCommitment),
    elapsedCommitment: parsePoint(p.elapsedCommitment),
    outstandingBits: parseBitProofArray(p.outstandingBits, amountBitLength, "outstanding range"),
    attemptsLowerBits: parseBitProofArray(p.attemptsLowerBits, DUNNING_ATTEMPTS_BIT_LENGTH, "attempts lower range"),
    attemptsUpperBits: parseBitProofArray(p.attemptsUpperBits, DUNNING_ATTEMPTS_BIT_LENGTH, "attempts upper range"),
    elapsedLowerBits: parseBitProofArray(p.elapsedLowerBits, DUNNING_GRACE_BIT_LENGTH, "elapsed lower range"),
    elapsedUpperBits: parseBitProofArray(p.elapsedUpperBits, DUNNING_GRACE_BIT_LENGTH, "elapsed upper range"),
  };
}
/** Decodes and structurally validates a serialized voucher. Throws on malformed input. */
export function parseDunningVoucher(encoded: string): DunningVoucher {
  const raw = decodeJson(fromBase64Url(encoded)) as Record<string, unknown>;
  if (!raw || typeof raw !== "object") throw new Error("The dunning voucher is malformed.");
  if (raw.kind !== VOUCHER_KIND) throw new Error("This is not a dunning voucher.");
  if (raw.version !== DUNNING_ENGINE_VERSION) throw new Error("Unsupported dunning voucher version.");
  if (raw.network !== MAINNET_CHAIN_ID) throw new Error("Unexpected network.");
  const memoRaw = typeof raw.memo === "string" && raw.memo.trim() ? requireText(raw.memo, "memo", 200) : "";
  const maxAttempts = requireCount(raw.maxAttempts, "max attempts", 1, MAX_DUNNING_ATTEMPTS);
  const gracePeriodDays = requireCount(raw.gracePeriodDays, "grace period days", 1, MAX_DUNNING_GRACE_DAYS);
  const retryIntervalHours = requireCount(raw.retryIntervalHours, "retry interval hours", 1, MAX_DUNNING_INTERVAL_HOURS);
  const sig = raw.issuerSignature as Record<string, unknown> | undefined;
  if (!sig || typeof sig !== "object") throw new Error("The issuer signature is missing.");
  return {
    kind: VOUCHER_KIND,
    version: DUNNING_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    voucherId: requireText(raw.voucherId, "voucher id", 80),
    merchantAlias: requireText(raw.merchantAlias, "merchant alias", 80),
    subscriptionRef: requireText(raw.subscriptionRef, "subscription reference", 120),
    planLabel: requireText(raw.planLabel, "plan label", 80),
    assetSymbol: requireText(raw.assetSymbol, "asset symbol", 16),
    tokenAddress: normalizeStarknetAddress(String(raw.tokenAddress ?? "")),
    assetDecimals: requireInt(raw.assetDecimals, "asset decimals", 0, 18),
    maxAttempts: maxAttempts.toString(),
    gracePeriodDays: gracePeriodDays.toString(),
    retryIntervalHours: retryIntervalHours.toString(),
    cadence: raw.cadence === "exponential" ? "exponential" : "fixed",
    subscriberCommitment: toHex(requireFelt(raw.subscriberCommitment, "subscriber commitment")),
    subscriberCommitted: raw.subscriberCommitted === true,
    paymentTokenCommitment: toHex(requireFelt(raw.paymentTokenCommitment, "payment token commitment")),
    paymentTokenCommitted: raw.paymentTokenCommitted === true,
    issuerPublicKey: parsePoint(raw.issuerPublicKey),
    proof: parseProof(raw.proof),
    issuerSignature: { challenge: toHex(requireScalar(sig.challenge, true)), response: toHex(requireScalar(sig.response, true)) },
    bindingHash: toHex(requireFelt(raw.bindingHash, "binding hash")),
    createdAt: requireIsoTimestamp(raw.createdAt, "created at"),
    memo: memoRaw,
    notice: typeof raw.notice === "string" && raw.notice.trim() ? raw.notice : DUNNING_NOTICE,
  };
}
/** Decodes and validates a serialized voucher secret. Throws on malformed input. */
export function parseDunningVoucherSecret(encoded: string): DunningVoucherSecret {
  const raw = decodeJson(fromBase64Url(encoded)) as Record<string, unknown>;
  if (!raw || raw.kind !== SECRET_KIND) throw new Error("This is not a dunning voucher secret.");
  const subscriberRef = typeof raw.subscriberRef === "string" ? raw.subscriberRef : "";
  if (subscriberRef.length > 96) throw new Error("The subscriber reference is too long.");
  const paymentTokenRef = typeof raw.paymentTokenRef === "string" ? raw.paymentTokenRef : "";
  if (paymentTokenRef.length > 128) throw new Error("The payment token reference is too long.");
  return {
    kind: SECRET_KIND,
    voucherId: requireText(raw.voucherId, "voucher id", 80),
    outstandingBaseUnits: requireBaseUnits(raw.outstandingBaseUnits, "outstanding balance").toString(),
    attemptsMade: requireCount(raw.attemptsMade, "attempts made", 0, MAX_DUNNING_ATTEMPTS).toString(),
    elapsedDays: requireCount(raw.elapsedDays, "elapsed days", 0, MAX_DUNNING_GRACE_DAYS).toString(),
    maxAttempts: requireCount(raw.maxAttempts, "max attempts", 1, MAX_DUNNING_ATTEMPTS).toString(),
    gracePeriodDays: requireCount(raw.gracePeriodDays, "grace period days", 1, MAX_DUNNING_GRACE_DAYS).toString(),
    outstandingBlinding: toHex(requireScalar(raw.outstandingBlinding, true)),
    attemptsBlinding: toHex(requireScalar(raw.attemptsBlinding, true)),
    elapsedBlinding: toHex(requireScalar(raw.elapsedBlinding, true)),
    subscriberRef,
    subscriberSalt: toHex(requireScalar(raw.subscriberSalt, true)),
    subscriberCommitted: raw.subscriberCommitted === true,
    paymentTokenRef,
    paymentTokenSalt: toHex(requireScalar(raw.paymentTokenSalt, true)),
    paymentTokenCommitted: raw.paymentTokenCommitted === true,
  };
}

/** Decodes and validates a serialized balance disclosure. Throws on malformed input. */
export function parseDunningBalanceDisclosure(encoded: string): DunningBalanceDisclosure {
  const raw = decodeJson(fromBase64Url(encoded)) as Record<string, unknown>;
  if (!raw || raw.kind !== BALANCE_DISCLOSURE_KIND) throw new Error("This is not a dunning balance disclosure.");
  return {
    kind: BALANCE_DISCLOSURE_KIND,
    voucherId: requireText(raw.voucherId, "voucher id", 80),
    outstandingBaseUnits: requireBaseUnits(raw.outstandingBaseUnits, "outstanding balance").toString(),
    outstandingBlinding: toHex(requireScalar(raw.outstandingBlinding, true)),
  };
}

/** Decodes and validates a serialized reference disclosure. Throws on malformed input. */
export function parseDunningRefDisclosure(encoded: string): DunningRefDisclosure {
  const raw = decodeJson(fromBase64Url(encoded)) as Record<string, unknown>;
  if (!raw || raw.kind !== REF_DISCLOSURE_KIND) throw new Error("This is not a dunning reference disclosure.");
  const field = raw.field === "paymentToken" ? "paymentToken" : raw.field === "subscriber" ? "subscriber" : null;
  if (!field) throw new Error("The disclosure field is invalid.");
  const value = typeof raw.value === "string" ? raw.value : "";
  if (value.length > 128) throw new Error("The disclosed reference is too long.");
  return { kind: REF_DISCLOSURE_KIND, voucherId: requireText(raw.voucherId, "voucher id", 80), field, value, salt: toHex(requireScalar(raw.salt, true)) };
}
// ---------------------------------------------------------------------------
// Field, encoding, and validation helpers
// ---------------------------------------------------------------------------

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}

/** Modular inverse via the extended Euclidean algorithm. */
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

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

/** Poseidon hash over field elements, returned as a bigint. */
function hashElements(items: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(items));
}

/** A uniform scalar in [0, n) drawn from the platform CSPRNG. */
function randomScalar(): bigint {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return mod(acc, CURVE_ORDER);
}

/** Reduces a scalar mod n and maps 0 to 1, so blindings and nonces are never zero. */
function nonZeroScalar(value: bigint): bigint {
  const s = mod(value, CURVE_ORDER);
  return s === 0n ? 1n : s;
}
function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`The ${label} must be a string.`);
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`The ${label} is required.`);
  if (trimmed.length > maxLength) throw new Error(`The ${label} is too long (max ${maxLength} characters).`);
  return trimmed;
}

function requireInt(value: unknown, label: string, min: number, max: number): number {
  const n = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
  if (!Number.isInteger(n)) throw new Error(`The ${label} must be an integer.`);
  if (n < min || n > max) throw new Error(`The ${label} must be between ${min} and ${max}.`);
  return n;
}

/** Parses a non-negative integer amount in base units (string, number, or bigint). */
function requireBaseUnits(value: unknown, label: string): bigint {
  let parsed: bigint;
  try {
    if (typeof value === "bigint") parsed = value;
    else if (typeof value === "number" && Number.isInteger(value)) parsed = BigInt(value);
    else if (typeof value === "string" && /^\d+$/.test(value.trim())) parsed = BigInt(value.trim());
    else throw new Error("bad");
  } catch {
    throw new Error(`The ${label} must be a non-negative integer in base units.`);
  }
  if (parsed < 0n) throw new Error(`The ${label} must be non-negative.`);
  return parsed;
}

/** Parses an integer count (string, number, or bigint) bounded to [min, max]; returns a bigint. */
function requireCount(value: unknown, label: string, min: number, max: number): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "number" && Number.isInteger(value)) parsed = BigInt(value);
  else if (typeof value === "string" && /^-?\d+$/.test(value.trim())) parsed = BigInt(value.trim());
  else throw new Error(`The ${label} must be an integer.`);
  if (parsed < BigInt(min) || parsed > BigInt(max)) throw new Error(`The ${label} must be between ${min} and ${max}.`);
  return parsed;
}
/** Parses a field element in [0, p) from a hex/decimal string, number, or bigint. */
function requireFelt(value: unknown, label = "field element"): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "number" && Number.isInteger(value)) parsed = BigInt(value);
  else if (typeof value === "string" && value.trim()) {
    try {
      parsed = BigInt(value.trim());
    } catch {
      throw new Error(`The ${label} is not a valid field element.`);
    }
  } else throw new Error(`The ${label} is not a valid field element.`);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error(`The ${label} is out of field range.`);
  return parsed;
}

/** Parses a curve scalar in [0, n) (or (0, n) when zero is disallowed). */
function requireScalar(value: unknown, allowZero: boolean): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "number" && Number.isInteger(value)) parsed = BigInt(value);
  else if (typeof value === "string" && value.trim()) {
    try {
      parsed = BigInt(value.trim());
    } catch {
      throw new Error("The scalar is not a valid integer.");
    }
  } else throw new Error("The scalar is not a valid integer.");
  if (parsed < 0n || parsed >= CURVE_ORDER) throw new Error("The scalar is outside the curve order.");
  if (!allowZero && parsed === 0n) throw new Error("The scalar must be non-zero.");
  return parsed;
}

/** Validates an ISO-8601 timestamp and returns it normalized. */
function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`The ${label} must be an ISO-8601 timestamp.`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`The ${label} must be an ISO-8601 timestamp.`);
  return date.toISOString();
}

/** A default identifier for a voucher, prefixed `dun_`. */
function defaultId(kind: string): string {
  return `dun_${kind}_${toHex(randomScalar()).slice(2, 16)}`;
}
function encodeJson(value: unknown): string {
  return JSON.stringify(value);
}

function decodeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The dunning voucher encoding is invalid.");
  }
}

/** Encodes a UTF-8 string as URL-safe base64 (works in Node and the browser). */
function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(text, "utf8").toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes URL-safe base64 back to a UTF-8 string; throws on malformed input. */
function fromBase64Url(encoded: string): string {
  if (typeof encoded !== "string" || !encoded.trim()) throw new Error("The dunning voucher encoding is invalid.");
  if (encoded.length > MAX_ENCODED_LENGTH) throw new Error("The dunning voucher encoding is invalid.");
  const normalized = encoded.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  try {
    if (typeof atob === "function") {
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder().decode(bytes);
    }
    return Buffer.from(padded, "base64").toString("utf8");
  } catch {
    throw new Error("The dunning voucher encoding is invalid.");
  }
}
