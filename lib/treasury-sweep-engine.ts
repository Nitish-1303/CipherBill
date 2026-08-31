/**
 * CipherBill — Treasury Yield & Idle Capital Sweep Attestation Engine
 * ==================================================================
 *
 * A client-side module that lets a merchant prove, in zero knowledge, that a
 * proposed sweep of idle treasury capital into a yield venue satisfies four
 * PUBLIC treasury covenants — a minimum retained reserve, a sweep sourced only
 * from capital that has actually gone idle, a maximum share of the treasury
 * committed to yield, and a minimum projected yield rate — WITHOUT revealing the
 * tier balances, the total idle capital, the sweep size, the projected yield,
 * the per-account balance rows, or the yield venue. Four idle-age tier balances
 * are proven to conserve the committed total idle capital; the sweep, the yield,
 * and every tier are range-bounded; and four homomorphic surplus range proofs
 * attest the covenants. The merchant signs the binding so anyone can
 * authenticate the issuer offline, and any amount or reference can be
 * selectively disclosed later. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that four hidden idle-age tiers conserve a committed total
 *   and that the hidden sweep amount and hidden projected yield clear four
 *   public treasury covenants. A verifier learns only the policy and that the
 *   relations hold — nothing about balances, the sweep size, the yield figure,
 *   the account rows, or the venue until selectively disclosed.
 * - Issuer-authenticated. A Schnorr signature over the binding proves a specific
 *   merchant public key issued it; anyone can check it offline.
 * - Selectively disclosable. The merchant can later open the total idle capital,
 *   the sweep amount, the projected yield, any tier, or the salted mandate and
 *   venue references.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It sweeps NOTHING. There is no vault, no venue, no counterparty, and no
 *   integration: this module never moves, transfers, deposits, withdraws,
 *   stakes, lends, or invests any value, shielded or public. "Sweep" names a
 *   number the operator types in and the covenants proven about that number.
 * - It earns NO interest. The projected yield is a figure the operator supplies,
 *   and the accrual schedule is deterministic integer arithmetic at a rate the
 *   operator types in — not an offered rate, not an achievable rate, and not a
 *   guarantee of any return.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   attestations, and no contract, oracle, scheduler, or consensus vouches for
 *   the inputs or fires a sweep. `summarizeTreasurySweepTrust()` and
 *   `getTreasurySweepVisibilityModel()` state these limits.
 * - It does NOT read the merchant's real shielded balance or any on-chain state,
 *   and does NOT verify that the committed treasury figures are real.
 * - It never reads from or writes to the STRK20 pool contract at
 *   `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`
 *   (`STRK20_POOL_ADDRESS` in `./strk20/config.ts`, re-exported here as
 *   `TREASURY_SWEEP_POOL_ADDRESS`); that address is recorded as provenance only
 *   and is never called.
 * - Its efficiency band and yield schedule are deterministic heuristics over the
 *   same figures, NOT a forecast, NOT a recommendation, and NOT financial advice.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const TREASURY_SWEEP_ENGINE_VERSION = 1 as const;
export const TREASURY_SWEEP_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const TREASURY_SWEEP_PROOF_SYSTEM = "stark-pedersen-treasury-sweep-bounds-v1" as const;
/** Basis-point denominator for share and rate covenants: 10000 = 100%. */
export const BPS_SCALE = 10_000n;
/** Ceiling on the public maximum sweep share covenant (bps). */
export const MAX_SWEEP_SHARE_BPS = 10_000;
/** Ceiling on the public minimum projected-yield covenant (bps of the sweep). */
export const MAX_YIELD_BPS = 10_000;
/** Ceiling on how long a balance row may be reported idle (days). */
export const MAX_IDLE_DAYS = 3650;
/** Ceiling on periods a yield accrual schedule may project. */
export const MAX_YIELD_PERIODS = 120;
/** Upper bound on asset decimals, matching what `baseUnitsToDecimal` can format. */
export const MAX_ASSET_DECIMALS = 18;
export const DEFAULT_TREASURY_AMOUNT_BIT_LENGTH = 128;
export const MIN_TREASURY_AMOUNT_BIT_LENGTH = 8;
export const MAX_TREASURY_AMOUNT_BIT_LENGTH = 128;
/**
 * Extra bits the surplus range proofs need beyond the amount range. Policy
 * scalars (share bps, yield bps, the bps scale) are < 2^14 and the total idle
 * capital is a sum of four tiers, so every homomorphic product below fits in
 * `amountBitLength + 18` bits with margin.
 */
export const TREASURY_SURPLUS_EXTRA_BITS = 18;

/**
 * Fixed idle-age tiers, youngest first. Tier 0 is working capital that has moved
 * recently and is NOT sweep-eligible; tiers 1–3 are the eligible idle band.
 */
export const DEFAULT_IDLE_TIERS = [
  { label: "Active", minIdleDays: 0, maxIdleDays: 6, sweepEligible: false },
  { label: "Idle 7-30", minIdleDays: 7, maxIdleDays: 30, sweepEligible: true },
  { label: "Idle 31-90", minIdleDays: 31, maxIdleDays: 90, sweepEligible: true },
  { label: "Idle 90+", minIdleDays: 91, maxIdleDays: null as number | null, sweepEligible: true },
] as const;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
const MS_PER_DAY = 86_400_000;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep issuer signature v1");
const BALANCE_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep balance record v1");
const MANDATE_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep mandate ref v1");
const VENUE_DOMAIN = hash.starknetKeccak("CipherBill treasury sweep venue ref v1");

const CERTIFICATE_KIND = "cipherbill.treasury-sweep-certificate" as const;
const SECRET_KIND = "cipherbill.treasury-sweep-certificate-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.treasury-sweep-amount-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.treasury-sweep-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.treasury-sweep-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.treasury-sweep-keypair" as const;
const MAX_ENCODED_LENGTH = 1_600_000;
/** Number of fixed idle-age tiers. Tier 0 is ineligible working capital. */
export const IDLE_TIER_COUNT = 4;
/** Proof leg indices. Legs 0–3 pin the tiers; 4–5 the sweep and yield; 6–9 the covenants. */
const LEG_SWEEP = 4;
const LEG_YIELD = 5;
const LEG_RESERVE_SURPLUS = 6;
const LEG_ELIGIBILITY_SURPLUS = 7;
const LEG_SHARE_SURPLUS = 8;
const LEG_YIELD_SURPLUS = 9;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface TreasurySweepAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface TreasurySweepKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface TreasurySweepEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

/** PUBLIC treasury covenants the hidden figures are proven to satisfy. */
export interface TreasurySweepPolicy {
  /** PUBLIC retained-reserve floor in base units. Proven: totalIdle − sweep ≥ this. */
  minReserveBaseUnits: string;
  /** PUBLIC cap on the swept share in bps. Proven: 10000 · sweep ≤ maxShare · totalIdle. */
  maxSweepShareBps: number;
  /** PUBLIC yield hurdle in bps of the sweep. Proven: 10000 · yield ≥ minYieldBps · sweep. */
  minYieldBps: number;
}

/** One merchant-supplied treasury balance row. Never published in the clear. */
export interface TreasuryBalanceRow {
  alias: string;
  /** ISO-8601 timestamp of the last movement on this balance. */
  lastMovedAt: string;
  balanceBaseUnits: string;
}

export interface IdleTierSummary {
  label: string;
  balanceBaseUnits: string;
  accountCount: number;
  sweepEligible: boolean;
}

/** Pure idle-age breakdown aggregated from balance rows (no proof). */
export interface IdleLedger {
  asOf: string;
  tiers: IdleTierSummary[];
  totalIdleBaseUnits: string;
  eligibleIdleBaseUnits: string;
  /** Σ(balance · idleDays) across every row; a drag figure, never proven. */
  weightedIdleDays: string;
  averageIdleDays: string;
  eligibleShareBps: string;
}

/** Pure sweep state against a policy (no proof). Mirrors the proven relations. */
export interface TreasurySweepState {
  tierBalancesBaseUnits: string[];
  totalIdleBaseUnits: string;
  eligibleIdleBaseUnits: string;
  sweepBaseUnits: string;
  projectedYieldBaseUnits: string;
  retainedBaseUnits: string;
  minReserveBaseUnits: string;
  maxSweepShareBps: string;
  minYieldBps: string;
  sweepShareBps: string;
  impliedYieldBps: string;
  /** totalIdle − sweep − minReserve; ≥ 0 exactly when the reserve covenant holds. */
  reserveSurplus: string;
  /** eligibleIdle − sweep; ≥ 0 exactly when the sourcing covenant holds. */
  eligibilitySurplus: string;
  /** maxShare · totalIdle − 10000 · sweep; ≥ 0 exactly when the share cap holds. */
  shareSurplus: string;
  /** 10000 · yield − minYieldBps · sweep; ≥ 0 exactly when the hurdle holds. */
  yieldSurplus: string;
  eligible: boolean;
}

/** One period of a deterministic accrual schedule. Arithmetic only — no venue exists. */
export interface SweepYieldPeriod {
  periodIndex: number;
  openingBalanceBaseUnits: string;
  accruedBaseUnits: string;
  closingBalanceBaseUnits: string;
  cumulativeAccruedBaseUnits: string;
}

export interface SweepYieldSchedule {
  principalBaseUnits: string;
  annualRateBps: string;
  periodsPerYear: number;
  periods: SweepYieldPeriod[];
  totalAccruedBaseUnits: string;
  endingBalanceBaseUnits: string;
  compounding: boolean;
  /** Always true: this schedule is arithmetic over operator-supplied inputs. */
  isProjectionOnly: true;
}

export type SweepEfficiencyBand = "optimal" | "adequate" | "lagging" | "idle-heavy";

export interface SweepEfficiencyAssessment {
  band: SweepEfficiencyBand;
  score: number;
  deploymentRatio: number;
  eligibleUseRatio: number;
  yieldHeadroomRatio: number;
  eligible: boolean;
  rationale: string;
}

export interface IssueTreasurySweepCertificateInput {
  merchantAlias: string;
  asset: TreasurySweepAsset;
  /** PUBLIC reference to the treasury mandate this attestation is issued under. */
  mandateRef: string;
  /** PUBLIC human-readable program label. */
  programLabel: string;
  /** PUBLIC treasury covenants. */
  policy: TreasurySweepPolicy;
  /**
   * SECRET four idle-age tier balances in base units, youngest first
   * (Active, Idle 7-30, Idle 31-90, Idle 90+). They define the committed total.
   */
  tierBalancesBaseUnits: [string, string, string, string];
  /** SECRET sweep amount in base units. Never published in the clear. */
  sweepBaseUnits: string;
  /** SECRET projected yield on the sweep, in base units. Operator-supplied. */
  projectedYieldBaseUnits: string;
  /** SECRET yield venue or strategy label; only a salted commitment is published. */
  venueRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

export interface TreasurySweepBitProof {
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

/**
 * Zero-knowledge proof bundle. Legs 0–3 pin each idle-age tier, leg 4 the sweep,
 * leg 5 the projected yield, and legs 6–9 are the four covenant surplus range
 * proofs. The total idle capital is the homomorphic sum of the four tier
 * commitments; the eligible idle band is the sum of tiers 1–3.
 */
export interface TreasurySweepProof {
  proofSystem: typeof TREASURY_SWEEP_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  generatorH: CurvePointFelts;
  tierCommitments: CurvePointFelts[];
  totalIdleCommitment: CurvePointFelts;
  eligibleIdleCommitment: CurvePointFelts;
  sweepCommitment: CurvePointFelts;
  yieldCommitment: CurvePointFelts;
  tierBits: TreasurySweepBitProof[][];
  sweepBits: TreasurySweepBitProof[];
  yieldBits: TreasurySweepBitProof[];
  reserveSurplusBits: TreasurySweepBitProof[];
  eligibilitySurplusBits: TreasurySweepBitProof[];
  shareSurplusBits: TreasurySweepBitProof[];
  yieldSurplusBits: TreasurySweepBitProof[];
}

export interface TreasurySweepCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof TREASURY_SWEEP_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  merchantAlias: string;
  mandateRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  minReserveBaseUnits: string;
  maxSweepShareBps: string;
  minYieldBps: string;
  mandateCommitment: string;
  mandateCommitted: boolean;
  venueCommitment: string;
  venueCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: TreasurySweepProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}

export interface TreasurySweepCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  tierBalancesBaseUnits: [string, string, string, string];
  totalIdleBaseUnits: string;
  eligibleIdleBaseUnits: string;
  sweepBaseUnits: string;
  projectedYieldBaseUnits: string;
  minReserveBaseUnits: string;
  maxSweepShareBps: string;
  minYieldBps: string;
  tierBlindings: string[];
  totalIdleBlinding: string;
  eligibleIdleBlinding: string;
  sweepBlinding: string;
  yieldBlinding: string;
  reserveSurplusBlinding: string;
  eligibilitySurplusBlinding: string;
  shareSurplusBlinding: string;
  yieldSurplusBlinding: string;
  mandateRef: string;
  mandateSalt: string;
  venueRef: string;
  venueSalt: string;
  venueCommitted: boolean;
}

export interface IssuedTreasurySweepCertificate {
  certificate: TreasurySweepCertificate;
  secret: TreasurySweepCertificateSecret;
}

export type TreasurySweepAmountField =
  | "totalIdle"
  | "eligibleIdle"
  | "sweep"
  | "yield"
  | `tier${0 | 1 | 2 | 3}`;

export interface TreasurySweepAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  field: TreasurySweepAmountField;
  amountBaseUnits: string;
  blinding: string;
}

export type TreasurySweepRefField = "mandateRef" | "venueRef";

export interface TreasurySweepRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: TreasurySweepRefField;
  value: string;
  salt: string;
}

export interface TreasurySweepCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  merchantAlias: string;
  mandateRef: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  minReserveDisplay: string;
  maxShareDisplay: string;
  minYieldDisplay: string;
  venueCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface TreasurySweepTrustModel {
  isZeroKnowledge: boolean;
  provesTierConservation: boolean;
  provesReserveCovenant: boolean;
  provesEligibleSourcing: boolean;
  provesShareCapCovenant: boolean;
  provesYieldHurdleCovenant: boolean;
  hidesTierBalances: boolean;
  hidesSweepAmount: boolean;
  hidesProjectedYield: boolean;
  hidesBalanceRows: boolean;
  hidesYieldVenue: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  sweepsOrMovesFunds: boolean;
  depositsIntoAnyVault: boolean;
  earnsInterest: boolean;
  readsShieldedBalances: boolean;
  settlesOnChain: boolean;
  movesPoolFunds: boolean;
  callsPoolContract: boolean;
  verifiesFiguresAreReal: boolean;
  guaranteesYield: boolean;
  isFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface TreasurySweepVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const TREASURY_SWEEP_NOTICE =
  "Zero-knowledge proof that four hidden idle-age treasury tiers conserve a committed total, that a hidden sweep amount is sourced only from the eligible idle band, leaves a public retained reserve, and stays under a public share cap, and that a hidden projected yield clears a public hurdle rate — hiding every balance, the sweep size, the yield figure, and the venue. It authenticates the issuer and supports selective disclosure; it is neither decentralized nor automatic, sweeps nothing, deposits into no vault, earns no interest, does not read shielded balances, does not verify that the figures are real, and never reads from or writes to the STRK20 pool contract.";

// ---------------------------------------------------------------------------
// Curve primitives
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

export function deriveTreasurySweepGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent treasury sweep generator.");
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

export function createTreasurySweepIssuerKey(entropy: TreasurySweepEntropy = {}): TreasurySweepKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return {
    kind: KEYPAIR_KIND,
    role: "issuer",
    secretKey: toHex(secret),
    publicKey: pointToFelts(publicKeyFromSecret(secret)),
  };
}

// ---------------------------------------------------------------------------
// Balance commitment and idle-age aggregation (pure)
// ---------------------------------------------------------------------------

/** Salted Poseidon commitment to one treasury balance row; hiding and binding. */
export function commitTreasuryBalanceRecord(
  alias: string,
  lastMovedAt: string,
  balanceBaseUnits: string | bigint,
  salt?: bigint,
): string {
  const trimmedAlias = requireText(alias, "balance alias", 96);
  const isoMoved = requireIsoTimestamp(lastMovedAt);
  const balance = requireBaseUnits(balanceBaseUnits, "balance");
  const s = salt !== undefined ? nonZeroScalar(salt) : nonZeroScalar(randomScalar());
  return toHex(
    hashElements([BALANCE_DOMAIN, hash.starknetKeccak(trimmedAlias), hash.starknetKeccak(isoMoved), balance, s]),
  );
}

function idleDaysFor(lastMovedAt: string, asOf: Date): number {
  const moved = new Date(requireIsoTimestamp(lastMovedAt)).getTime();
  const days = Math.floor((asOf.getTime() - moved) / MS_PER_DAY);
  return days < 0 ? 0 : days > MAX_IDLE_DAYS ? MAX_IDLE_DAYS : days;
}

function tierIndexForIdleDays(days: number): number {
  if (days <= 6) return 0;
  if (days <= 30) return 1;
  if (days <= 90) return 2;
  return 3;
}

/** Aggregates balance rows into the four fixed idle-age tiers as of a date. */
export function aggregateIdleLedger(rows: TreasuryBalanceRow[], asOf: Date = new Date()): IdleLedger {
  if (!Array.isArray(rows)) throw new Error("Treasury balance rows are required.");
  const balances = [0n, 0n, 0n, 0n];
  const counts = [0, 0, 0, 0];
  let weighted = 0n;

  for (const row of rows) {
    const balance = requireBaseUnits(row.balanceBaseUnits, "balance");
    void requireText(row.alias, "balance alias", 96);
    const days = idleDaysFor(row.lastMovedAt, asOf);
    balances[tierIndexForIdleDays(days)] += balance;
    counts[tierIndexForIdleDays(days)] += 1;
    weighted += balance * BigInt(days);
  }

  const totalIdle = balances.reduce((acc, v) => acc + v, 0n);
  const eligibleIdle = balances[1] + balances[2] + balances[3];
  const averageIdleDays = totalIdle > 0n ? weighted / totalIdle : 0n;
  const eligibleShareBps = totalIdle > 0n ? (eligibleIdle * BPS_SCALE) / totalIdle : 0n;

  return {
    asOf: asOf.toISOString(),
    tiers: DEFAULT_IDLE_TIERS.map((tier, i) => ({
      label: tier.label,
      balanceBaseUnits: balances[i].toString(),
      accountCount: counts[i],
      sweepEligible: tier.sweepEligible,
    })),
    totalIdleBaseUnits: totalIdle.toString(),
    eligibleIdleBaseUnits: eligibleIdle.toString(),
    weightedIdleDays: weighted.toString(),
    averageIdleDays: averageIdleDays.toString(),
    eligibleShareBps: eligibleShareBps.toString(),
  };
}

export function requireTreasurySweepPolicy(policy: TreasurySweepPolicy): {
  minReserve: bigint;
  maxSweepShareBps: number;
  minYieldBps: number;
} {
  if (!policy || typeof policy !== "object") throw new Error("The treasury sweep policy is required.");
  const minReserve = requireBaseUnits(policy.minReserveBaseUnits, "minimum reserve");
  const maxSweepShareBps = requireInt(policy.maxSweepShareBps, "maximum sweep share bps", 0, MAX_SWEEP_SHARE_BPS);
  const minYieldBps = requireInt(policy.minYieldBps, "minimum yield bps", 0, MAX_YIELD_BPS);
  return { minReserve, maxSweepShareBps, minYieldBps };
}

function parseTierBalances(balances: [string, string, string, string]): bigint[] {
  if (!Array.isArray(balances) || balances.length !== IDLE_TIER_COUNT) {
    throw new Error(`Exactly ${IDLE_TIER_COUNT} idle-age tier balances are required.`);
  }
  return balances.map((b, i) => requireBaseUnits(b, `tier ${i} balance`));
}

/** Computes the pure sweep state and covenant surpluses (the same relations the ZK proof attests). */
export function computeTreasurySweepState(
  tierBalancesBaseUnits: [string, string, string, string],
  sweepBaseUnits: string | bigint,
  projectedYieldBaseUnits: string | bigint,
  policy: TreasurySweepPolicy,
): TreasurySweepState {
  const { minReserve, maxSweepShareBps, minYieldBps } = requireTreasurySweepPolicy(policy);
  const tiers = parseTierBalances(tierBalancesBaseUnits);
  const sweep = requireBaseUnits(sweepBaseUnits, "sweep amount");
  const projectedYield = requireBaseUnits(projectedYieldBaseUnits, "projected yield");

  const totalIdle = tiers.reduce((acc, v) => acc + v, 0n);
  const eligibleIdle = tiers[1] + tiers[2] + tiers[3];
  const maxShare = BigInt(maxSweepShareBps);
  const minYield = BigInt(minYieldBps);

  const reserveSurplus = totalIdle - sweep - minReserve;
  const eligibilitySurplus = eligibleIdle - sweep;
  const shareSurplus = maxShare * totalIdle - BPS_SCALE * sweep;
  const yieldSurplus = BPS_SCALE * projectedYield - minYield * sweep;
  const eligible = reserveSurplus >= 0n && eligibilitySurplus >= 0n && shareSurplus >= 0n && yieldSurplus >= 0n;

  return {
    tierBalancesBaseUnits: tiers.map((t) => t.toString()),
    totalIdleBaseUnits: totalIdle.toString(),
    eligibleIdleBaseUnits: eligibleIdle.toString(),
    sweepBaseUnits: sweep.toString(),
    projectedYieldBaseUnits: projectedYield.toString(),
    retainedBaseUnits: (totalIdle >= sweep ? totalIdle - sweep : 0n).toString(),
    minReserveBaseUnits: minReserve.toString(),
    maxSweepShareBps: maxShare.toString(),
    minYieldBps: minYield.toString(),
    sweepShareBps: (totalIdle > 0n ? (sweep * BPS_SCALE) / totalIdle : 0n).toString(),
    impliedYieldBps: (sweep > 0n ? (projectedYield * BPS_SCALE) / sweep : 0n).toString(),
    reserveSurplus: reserveSurplus.toString(),
    eligibilitySurplus: eligibilitySurplus.toString(),
    shareSurplus: shareSurplus.toString(),
    yieldSurplus: yieldSurplus.toString(),
    eligible,
  };
}

/**
 * Deterministic integer accrual schedule over operator-supplied inputs. There is
 * no venue, no counterparty, and no offered rate — this is arithmetic, not a
 * forecast, an offer, or financial advice.
 */
export function projectSweepYieldSchedule(
  principalBaseUnits: string | bigint,
  annualRateBps: number,
  periodsPerYear: number,
  periods: number,
  compounding = true,
): SweepYieldSchedule {
  const principal = requireBaseUnits(principalBaseUnits, "principal");
  const rateBps = BigInt(requireInt(annualRateBps, "annual rate bps", 0, MAX_YIELD_BPS));
  const perYear = requireInt(periodsPerYear, "periods per year", 1, 365);
  const count = requireInt(periods, "periods", 1, MAX_YIELD_PERIODS);

  const denominator = BPS_SCALE * BigInt(perYear);
  const rows: SweepYieldPeriod[] = [];
  let balance = principal;
  let cumulative = 0n;

  for (let i = 0; i < count; i += 1) {
    const opening = balance;
    // Floor division keeps every figure an exact integer of base units.
    // Compounding accrues on the running balance; simple accrues on the principal.
    const base = compounding ? opening : principal;
    const accrued = (base * rateBps) / denominator;
    cumulative += accrued;
    balance = opening + accrued;
    rows.push({
      periodIndex: i,
      openingBalanceBaseUnits: opening.toString(),
      accruedBaseUnits: accrued.toString(),
      closingBalanceBaseUnits: balance.toString(),
      cumulativeAccruedBaseUnits: cumulative.toString(),
    });
  }

  return {
    principalBaseUnits: principal.toString(),
    annualRateBps: rateBps.toString(),
    periodsPerYear: perYear,
    periods: rows,
    totalAccruedBaseUnits: cumulative.toString(),
    endingBalanceBaseUnits: balance.toString(),
    compounding,
    isProjectionOnly: true,
  };
}

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}

/** Deterministic idle-capital efficiency heuristic — not a forecast, recommendation, or financial advice. */
export function assessSweepEfficiency(state: TreasurySweepState): SweepEfficiencyAssessment {
  const totalIdle = Number(state.totalIdleBaseUnits);
  const eligibleIdle = Number(state.eligibleIdleBaseUnits);
  const sweep = Number(state.sweepBaseUnits);
  const maxShare = Number(state.maxSweepShareBps);
  const shareBps = Number(state.sweepShareBps);
  const impliedYieldBps = Number(state.impliedYieldBps);
  const minYieldBps = Number(state.minYieldBps);

  const deploymentRatio = totalIdle > 0 ? clamp01(sweep / totalIdle) : 0;
  const eligibleUseRatio = eligibleIdle > 0 ? clamp01(sweep / eligibleIdle) : 0;
  const yieldHeadroomRatio = minYieldBps > 0 ? clamp01(impliedYieldBps / minYieldBps) : 1;
  const capUseRatio = maxShare > 0 ? clamp01(shareBps / maxShare) : 0;
  const score = Math.round(
    100 * clamp01(0.4 * eligibleUseRatio + 0.25 * capUseRatio + 0.2 * yieldHeadroomRatio + 0.15 * deploymentRatio),
  );

  let band: SweepEfficiencyBand;
  if (!state.eligible) band = "idle-heavy";
  else if (score >= 70) band = "optimal";
  else if (score >= 45) band = "adequate";
  else if (score >= 20) band = "lagging";
  else band = "idle-heavy";

  return {
    band,
    score,
    deploymentRatio,
    eligibleUseRatio,
    yieldHeadroomRatio,
    eligible: state.eligible,
    rationale: state.eligible
      ? `Heuristic blend: ${formatBpsShare(state.sweepShareBps)} of the treasury swept against a ${formatBpsShare(state.maxSweepShareBps)} cap, using ${(eligibleUseRatio * 100).toFixed(0)}% of the eligible idle band at an implied ${formatBpsShare(state.impliedYieldBps)} versus a ${formatBpsShare(state.minYieldBps)} hurdle.`
      : "One or more covenants fail: the reserve, eligible-sourcing, share-cap, or yield-hurdle surplus is negative.",
  };
}

/**
 * Reports whether the configured trigger would arm. It NEVER fires a sweep, moves
 * value, or contacts any venue — the caller decides what to do out of band.
 */
export function evaluateSweepTrigger(
  state: TreasurySweepState,
  triggerBaseUnits: string | bigint,
): { armed: boolean; eligibleIdleBaseUnits: string; triggerBaseUnits: string; shortfallBaseUnits: string; executesAnything: false } {
  const trigger = requireBaseUnits(triggerBaseUnits, "sweep trigger threshold");
  const eligibleIdle = requireBaseUnits(state.eligibleIdleBaseUnits, "eligible idle capital");
  const armed = eligibleIdle >= trigger;
  return {
    armed,
    eligibleIdleBaseUnits: eligibleIdle.toString(),
    triggerBaseUnits: trigger.toString(),
    shortfallBaseUnits: (armed ? 0n : trigger - eligibleIdle).toString(),
    executesAnything: false,
  };
}

export function formatTreasuryBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

export function formatIdleDays(days: string | number | bigint): string {
  const n = typeof days === "bigint" ? days : BigInt(days);
  if (n > BigInt(MAX_IDLE_DAYS)) return `${MAX_IDLE_DAYS}+ days`;
  return `${n.toString()} ${n === 1n ? "day" : "days"}`;
}

export function formatBpsShare(bps: string | number | bigint): string {
  const value = typeof bps === "bigint" ? bps : BigInt(bps);
  const whole = value / 100n;
  const frac = value % 100n;
  if (frac === 0n) return `${whole}%`;
  const fracStr = frac.toString().padStart(2, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}%`;
}

// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  certificateId: string;
  merchantAlias: string;
  mandateRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  minReserve: bigint;
  maxSweepShareBps: bigint;
  minYieldBps: bigint;
  amountBitLength: number;
  surplusBitLength: number;
  mandateCommitment: bigint;
  mandateCommitted: boolean;
  venueCommitment: bigint;
  venueCommitted: boolean;
  createdAt: string;
  memo: string;
}

function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  tierCommitments: CurvePoint[],
  totalIdleCommitment: CurvePoint,
  eligibleIdleCommitment: CurvePoint,
  sweepCommitment: CurvePoint,
  yieldCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  const tierElements: bigint[] = [];
  for (const c of tierCommitments) {
    tierElements.push(c.x, c.y);
  }
  return hashElements([
    BINDING_DOMAIN,
    BigInt(TREASURY_SWEEP_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.mandateRef),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.minReserve,
    fields.maxSweepShareBps,
    fields.minYieldBps,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    fields.mandateCommitment,
    fields.mandateCommitted ? 1n : 0n,
    fields.venueCommitment,
    fields.venueCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    // Hashed verbatim, with a separate presence flag: substituting a placeholder
    // for an empty memo would let "" and that placeholder collide, so an
    // empty-memo certificate could be relabelled without breaking this hash.
    fields.memo ? 1n : 0n,
    hash.starknetKeccak(fields.memo),
    issuerKey.x,
    issuerKey.y,
    ...tierElements,
    totalIdleCommitment.x,
    totalIdleCommitment.y,
    eligibleIdleCommitment.x,
    eligibleIdleCommitment.y,
    sweepCommitment.x,
    sweepCommitment.y,
    yieldCommitment.x,
    yieldCommitment.y,
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

function commitRef(domain: bigint, value: string, salt: bigint): bigint {
  return hashElements([domain, hash.starknetKeccak(value), salt]);
}

// ---------------------------------------------------------------------------
// Per-bit OR proof and range proof
// ---------------------------------------------------------------------------

function proveBit(
  bit: number,
  commitment: CurvePoint,
  blinding: bigint,
  ctx: bigint,
  leg: number,
  index: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): TreasurySweepBitProof {
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

function verifyBit(proof: TreasurySweepBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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

function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): TreasurySweepBitProof[] {
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
  const proofs: TreasurySweepBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

function verifyRange(
  proofs: TreasurySweepBitProof[],
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
): CurvePoint | null {
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

function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

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
// Issue and verify
// ---------------------------------------------------------------------------

export function issueTreasurySweepCertificate(
  input: IssueTreasurySweepCertificateInput,
  now: Date = new Date(),
  entropy: TreasurySweepEntropy = {},
): IssuedTreasurySweepCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const mandateRef = requireText(input.mandateRef, "mandate reference", 96);
  const programLabel = requireText(input.programLabel, "program label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, MAX_ASSET_DECIMALS);
  const { minReserve, maxSweepShareBps, minYieldBps } = requireTreasurySweepPolicy(input.policy);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_TREASURY_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_TREASURY_AMOUNT_BIT_LENGTH,
    MAX_TREASURY_AMOUNT_BIT_LENGTH,
  );
  const surplusBitLength = amountBitLength + TREASURY_SURPLUS_EXTRA_BITS;
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const tiers = parseTierBalances(input.tierBalancesBaseUnits);
  const sweep = requireBaseUnits(input.sweepBaseUnits, "sweep amount");
  const projectedYield = requireBaseUnits(input.projectedYieldBaseUnits, "projected yield");
  const totalIdle = tiers.reduce((acc, v) => acc + v, 0n);
  const eligibleIdle = tiers[1] + tiers[2] + tiers[3];

  if (totalIdle > U128_MAX) throw new Error("The total idle capital must fit within the u128 range.");
  if (sweep > U128_MAX) throw new Error("The sweep amount must fit within the u128 range.");
  if (projectedYield > U128_MAX) throw new Error("The projected yield must fit within the u128 range.");

  const band = 1n << BigInt(amountBitLength);
  for (let i = 0; i < IDLE_TIER_COUNT; i += 1) {
    if (tiers[i] >= band) throw new Error(`Tier ${i} exceeds the ${amountBitLength}-bit band.`);
  }
  if (sweep >= band) throw new Error(`The sweep amount exceeds the ${amountBitLength}-bit band.`);
  if (projectedYield >= band) throw new Error(`The projected yield exceeds the ${amountBitLength}-bit band.`);

  const maxShare = BigInt(maxSweepShareBps);
  const minYield = BigInt(minYieldBps);

  const reserveSurplus = totalIdle - sweep - minReserve;
  const eligibilitySurplus = eligibleIdle - sweep;
  const shareSurplus = maxShare * totalIdle - BPS_SCALE * sweep;
  const yieldSurplus = BPS_SCALE * projectedYield - minYield * sweep;

  if (reserveSurplus < 0n || eligibilitySurplus < 0n || shareSurplus < 0n || yieldSurplus < 0n) {
    throw new Error("One or more covenant surpluses is negative; no honest eligibility proof exists.");
  }
  const surplusBand = 1n << BigInt(surplusBitLength);
  if (reserveSurplus >= surplusBand) throw new Error(`The reserve surplus exceeds the ${surplusBitLength}-bit band.`);
  if (eligibilitySurplus >= surplusBand) throw new Error(`The eligibility surplus exceeds the ${surplusBitLength}-bit band.`);
  if (shareSurplus >= surplusBand) throw new Error(`The share surplus exceeds the ${surplusBitLength}-bit band.`);
  if (yieldSurplus >= surplusBand) throw new Error(`The yield surplus exceeds the ${surplusBitLength}-bit band.`);

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();

  const tierBlindings = tiers.map(() => nonZeroScalar(nextScalar()));
  const totalIdleBlinding = tierBlindings.reduce((acc, r) => mod(acc + r, CURVE_ORDER), 0n);
  const eligibleIdleBlinding = mod(tierBlindings[1] + tierBlindings[2] + tierBlindings[3], CURVE_ORDER);
  const sweepBlinding = nonZeroScalar(nextScalar());
  const yieldBlinding = nonZeroScalar(nextScalar());
  // Forced blindings: each surplus commitment must equal the homomorphic target
  // point exactly, so its blinding is derived, never sampled.
  const reserveSurplusBlinding = mod(totalIdleBlinding - sweepBlinding, CURVE_ORDER);
  const eligibilitySurplusBlinding = mod(eligibleIdleBlinding - sweepBlinding, CURVE_ORDER);
  const shareSurplusBlinding = mod(maxShare * totalIdleBlinding - BPS_SCALE * sweepBlinding, CURVE_ORDER);
  const yieldSurplusBlinding = mod(BPS_SCALE * yieldBlinding - minYield * sweepBlinding, CURVE_ORDER);

  const tierCommitments = tiers.map((amount, i) => pedersenCommit(amount, tierBlindings[i], h));
  const totalIdleCommitment = tierCommitments.reduce((acc, point) => acc.add(point), ZERO);
  const eligibleIdleCommitment = tierCommitments[1].add(tierCommitments[2]).add(tierCommitments[3]);
  const sweepCommitment = pedersenCommit(sweep, sweepBlinding, h);
  const yieldCommitment = pedersenCommit(projectedYield, yieldBlinding, h);

  const venueRef = input.venueRef ? requireText(input.venueRef, "venue reference", 96) : "";
  const venueCommitted = venueRef.length > 0;
  const venueSalt = nonZeroScalar(nextScalar());
  const mandateSalt = nonZeroScalar(nextScalar());
  const mandateCommitment = commitRef(MANDATE_DOMAIN, mandateRef, mandateSalt);
  const venueCommitment = venueCommitted ? commitRef(VENUE_DOMAIN, venueRef, venueSalt) : 0n;

  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());
  const fields: BindingFields = {
    certificateId,
    merchantAlias,
    mandateRef,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    minReserve,
    maxSweepShareBps: maxShare,
    minYieldBps: minYield,
    amountBitLength,
    surplusBitLength,
    mandateCommitment,
    mandateCommitted: true,
    venueCommitment,
    venueCommitted,
    createdAt,
    memo,
  };
  const bindingHash = computeBindingHash(
    fields,
    issuerKey,
    tierCommitments,
    totalIdleCommitment,
    eligibleIdleCommitment,
    sweepCommitment,
    yieldCommitment,
    h,
  );
  const ctx = statementContext(bindingHash);

  const tierBits = tierCommitments.map((_, i) => proveRange(tiers[i], tierBlindings[i], amountBitLength, ctx, i, h, nextScalar));
  const sweepBits = proveRange(sweep, sweepBlinding, amountBitLength, ctx, LEG_SWEEP, h, nextScalar);
  const yieldBits = proveRange(projectedYield, yieldBlinding, amountBitLength, ctx, LEG_YIELD, h, nextScalar);
  const reserveSurplusBits = proveRange(reserveSurplus, reserveSurplusBlinding, surplusBitLength, ctx, LEG_RESERVE_SURPLUS, h, nextScalar);
  const eligibilitySurplusBits = proveRange(
    eligibilitySurplus,
    eligibilitySurplusBlinding,
    surplusBitLength,
    ctx,
    LEG_ELIGIBILITY_SURPLUS,
    h,
    nextScalar,
  );
  const shareSurplusBits = proveRange(shareSurplus, shareSurplusBlinding, surplusBitLength, ctx, LEG_SHARE_SURPLUS, h, nextScalar);
  const yieldSurplusBits = proveRange(yieldSurplus, yieldSurplusBlinding, surplusBitLength, ctx, LEG_YIELD_SURPLUS, h, nextScalar);

  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);

  const proof: TreasurySweepProof = {
    proofSystem: TREASURY_SWEEP_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    generatorH: pointToFelts(h),
    tierCommitments: tierCommitments.map(pointToFelts),
    totalIdleCommitment: pointToFelts(totalIdleCommitment),
    eligibleIdleCommitment: pointToFelts(eligibleIdleCommitment),
    sweepCommitment: pointToFelts(sweepCommitment),
    yieldCommitment: pointToFelts(yieldCommitment),
    tierBits,
    sweepBits,
    yieldBits,
    reserveSurplusBits,
    eligibilitySurplusBits,
    shareSurplusBits,
    yieldSurplusBits,
  };

  const certificate: TreasurySweepCertificate = {
    kind: CERTIFICATE_KIND,
    version: TREASURY_SWEEP_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    merchantAlias,
    mandateRef,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    minReserveBaseUnits: minReserve.toString(),
    maxSweepShareBps: maxShare.toString(),
    minYieldBps: minYield.toString(),
    mandateCommitment: toHex(mandateCommitment),
    mandateCommitted: true,
    venueCommitment: toHex(venueCommitment),
    venueCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: TREASURY_SWEEP_NOTICE,
  };

  const secret: TreasurySweepCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    tierBalancesBaseUnits: [
      tiers[0].toString(),
      tiers[1].toString(),
      tiers[2].toString(),
      tiers[3].toString(),
    ],
    totalIdleBaseUnits: totalIdle.toString(),
    eligibleIdleBaseUnits: eligibleIdle.toString(),
    sweepBaseUnits: sweep.toString(),
    projectedYieldBaseUnits: projectedYield.toString(),
    minReserveBaseUnits: minReserve.toString(),
    maxSweepShareBps: maxShare.toString(),
    minYieldBps: minYield.toString(),
    tierBlindings: tierBlindings.map(toHex),
    totalIdleBlinding: toHex(totalIdleBlinding),
    eligibleIdleBlinding: toHex(eligibleIdleBlinding),
    sweepBlinding: toHex(sweepBlinding),
    yieldBlinding: toHex(yieldBlinding),
    reserveSurplusBlinding: toHex(reserveSurplusBlinding),
    eligibilitySurplusBlinding: toHex(eligibilitySurplusBlinding),
    shareSurplusBlinding: toHex(shareSurplusBlinding),
    yieldSurplusBlinding: toHex(yieldSurplusBlinding),
    mandateRef,
    mandateSalt: toHex(mandateSalt),
    venueRef,
    venueSalt: toHex(venueSalt),
    venueCommitted,
  };

  return { certificate, secret };
}

/**
 * Verifies a treasury sweep certificate end to end: the binding hash, the
 * issuer signature, every bit-decomposition range proof, tier conservation, and
 * the four covenant surplus legs against their homomorphic target points.
 *
 * A `true` result means the arithmetic is sound. It does NOT mean the committed
 * treasury figures are real, that any capital was swept, that any vault or
 * venue exists, or that any yield was earned. Nothing here touches the STRK20
 * pool contract or any on-chain state.
 */
export function verifyTreasurySweepCertificate(certificate: TreasurySweepCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    // The engine version, chain id, pool provenance, and limitation notice are
    // constants of this engine rather than per-certificate data, and the binding
    // hash commits to the version constant instead of the field. Checking them
    // literally is what stops a holder from rewriting the notice — or the
    // network — on an otherwise valid, signed certificate.
    if (certificate.version !== TREASURY_SWEEP_ENGINE_VERSION) return false;
    if (certificate.network !== MAINNET_CHAIN_ID) return false;
    if (normalizeStarknetAddress(certificate.poolAddress) !== normalizeStarknetAddress(STRK20_POOL_ADDRESS)) return false;
    if (certificate.notice !== TREASURY_SWEEP_NOTICE) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== TREASURY_SWEEP_PROOF_SYSTEM) return false;

    const amountBitLength = proof.amountBitLength;
    const surplusBitLength = proof.surplusBitLength;
    if (
      !Number.isInteger(amountBitLength) ||
      amountBitLength < MIN_TREASURY_AMOUNT_BIT_LENGTH ||
      amountBitLength > MAX_TREASURY_AMOUNT_BIT_LENGTH
    ) {
      return false;
    }
    if (surplusBitLength !== amountBitLength + TREASURY_SURPLUS_EXTRA_BITS) return false;
    if (!Array.isArray(proof.tierCommitments) || proof.tierCommitments.length !== IDLE_TIER_COUNT) return false;
    if (!Array.isArray(proof.tierBits) || proof.tierBits.length !== IDLE_TIER_COUNT) return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;

    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const tierCommitments = proof.tierCommitments.map(pointFromFelts);
    const totalIdleCommitment = pointFromFelts(proof.totalIdleCommitment);
    const eligibleIdleCommitment = pointFromFelts(proof.eligibleIdleCommitment);
    const sweepCommitment = pointFromFelts(proof.sweepCommitment);
    const yieldCommitment = pointFromFelts(proof.yieldCommitment);

    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      mandateRef: certificate.mandateRef,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: requireInt(certificate.assetDecimals, "asset decimals", 0, MAX_ASSET_DECIMALS),
      minReserve: requireBaseUnits(certificate.minReserveBaseUnits, "reserve floor"),
      maxSweepShareBps: BigInt(certificate.maxSweepShareBps),
      minYieldBps: BigInt(certificate.minYieldBps),
      amountBitLength,
      surplusBitLength,
      mandateCommitment: requireFelt(certificate.mandateCommitment),
      mandateCommitted: certificate.mandateCommitted,
      venueCommitment: requireFelt(certificate.venueCommitment),
      venueCommitted: certificate.venueCommitted,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };

    const bindingHash = computeBindingHash(
      fields,
      issuerKey,
      tierCommitments,
      totalIdleCommitment,
      eligibleIdleCommitment,
      sweepCommitment,
      yieldCommitment,
      h,
    );
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);
    const minReserve = fields.minReserve;
    const maxShare = fields.maxSweepShareBps;
    const minYield = fields.minYieldBps;
    if (maxShare < 0n || maxShare > BigInt(MAX_SWEEP_SHARE_BPS)) return false;
    if (minYield < 0n || minYield > BigInt(MAX_YIELD_BPS)) return false;
    // The reserve floor is a PUBLIC scalar that leg 6 subtracts as minReserve·G,
    // and scalar multiplication reduces it modulo the curve order. Without this
    // bound a certificate could advertise a floor of, say, exactly the curve
    // order — which subtracts the identity — and still verify while proving only
    // totalIdle − sweep ≥ 0. Every honest floor is below the amount band, since
    // an honest issuer needs totalIdle − sweep − minReserve ≥ 0.
    if (minReserve >= 1n << BigInt(amountBitLength)) return false;

    // Legs 0–3: every idle-age tier is a non-negative amount inside the band,
    // and the four tier commitments must sum to the committed total idle capital.
    let tierSumPoint = ZERO;
    let eligibleSumPoint = ZERO;
    for (let i = 0; i < IDLE_TIER_COUNT; i += 1) {
      const tierSum = verifyRange(proof.tierBits[i], amountBitLength, ctx, i, h);
      if (!tierSum || !tierSum.equals(tierCommitments[i])) return false;
      tierSumPoint = tierSumPoint.add(tierSum);
      if (i > 0) eligibleSumPoint = eligibleSumPoint.add(tierSum);
    }
    if (!tierSumPoint.equals(totalIdleCommitment)) return false;
    // The eligible idle band is exactly tiers 1–3 (everything past the active tier).
    if (!eligibleSumPoint.equals(eligibleIdleCommitment)) return false;

    // Legs 4–5: the sweep amount and the projected yield are in-band non-negatives.
    const sweepSum = verifyRange(proof.sweepBits, amountBitLength, ctx, LEG_SWEEP, h);
    if (!sweepSum || !sweepSum.equals(sweepCommitment)) return false;
    const yieldSum = verifyRange(proof.yieldBits, amountBitLength, ctx, LEG_YIELD, h);
    if (!yieldSum || !yieldSum.equals(yieldCommitment)) return false;

    // Leg 6 — reserve covenant: totalIdle − sweep − minReserve ≥ 0.
    const reserveSurplusSum = verifyRange(proof.reserveSurplusBits, surplusBitLength, ctx, LEG_RESERVE_SURPLUS, h);
    if (!reserveSurplusSum) return false;
    const expectedReserve = totalIdleCommitment.add(sweepCommitment.negate()).add(scalePoint(G, minReserve).negate());
    if (!reserveSurplusSum.equals(expectedReserve)) return false;

    // Leg 7 — sourcing covenant: eligibleIdle − sweep ≥ 0.
    const eligibilitySurplusSum = verifyRange(proof.eligibilitySurplusBits, surplusBitLength, ctx, LEG_ELIGIBILITY_SURPLUS, h);
    if (!eligibilitySurplusSum) return false;
    const expectedEligibility = eligibleIdleCommitment.add(sweepCommitment.negate());
    if (!eligibilitySurplusSum.equals(expectedEligibility)) return false;

    // Leg 8 — share cap: maxShare · totalIdle − 10000 · sweep ≥ 0.
    const shareSurplusSum = verifyRange(proof.shareSurplusBits, surplusBitLength, ctx, LEG_SHARE_SURPLUS, h);
    if (!shareSurplusSum) return false;
    const expectedShare = scalePoint(totalIdleCommitment, maxShare).add(scalePoint(sweepCommitment, BPS_SCALE).negate());
    if (!shareSurplusSum.equals(expectedShare)) return false;

    // Leg 9 — yield hurdle: 10000 · yield − minYield · sweep ≥ 0.
    const yieldSurplusSum = verifyRange(proof.yieldSurplusBits, surplusBitLength, ctx, LEG_YIELD_SURPLUS, h);
    if (!yieldSurplusSum) return false;
    const expectedYield = scalePoint(yieldCommitment, BPS_SCALE).add(scalePoint(sweepCommitment, minYield).negate());
    if (!yieldSurplusSum.equals(expectedYield)) return false;

    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Selective disclosure
// ---------------------------------------------------------------------------

function amountFieldCommitment(certificate: TreasurySweepCertificate, field: TreasurySweepAmountField): CurvePointFelts | null {
  const proof = certificate.proof;
  if (field === "totalIdle") return proof.totalIdleCommitment;
  if (field === "eligibleIdle") return proof.eligibleIdleCommitment;
  if (field === "sweep") return proof.sweepCommitment;
  if (field === "yield") return proof.yieldCommitment;
  const match = /^tier([0-3])$/.exec(field);
  if (match) return proof.tierCommitments[Number(match[1])] ?? null;
  return null;
}

function amountFieldFromSecret(
  secret: TreasurySweepCertificateSecret,
  field: TreasurySweepAmountField,
): { amount: string; blinding: string } {
  if (field === "totalIdle") return { amount: secret.totalIdleBaseUnits, blinding: secret.totalIdleBlinding };
  if (field === "eligibleIdle") return { amount: secret.eligibleIdleBaseUnits, blinding: secret.eligibleIdleBlinding };
  if (field === "sweep") return { amount: secret.sweepBaseUnits, blinding: secret.sweepBlinding };
  if (field === "yield") return { amount: secret.projectedYieldBaseUnits, blinding: secret.yieldBlinding };
  const match = /^tier([0-3])$/.exec(field);
  if (match) {
    const idx = Number(match[1]);
    return { amount: secret.tierBalancesBaseUnits[idx], blinding: secret.tierBlindings[idx] };
  }
  throw new Error("Unknown treasury sweep amount field.");
}

/** Opens one committed treasury figure to a verifier without touching the rest. */
export function buildTreasurySweepAmountDisclosure(
  secret: TreasurySweepCertificateSecret,
  field: TreasurySweepAmountField,
): TreasurySweepAmountDisclosure {
  const { amount, blinding } = amountFieldFromSecret(secret, field);
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field,
    amountBaseUnits: requireBaseUnits(amount, "disclosed amount").toString(),
    blinding: toHex(requireScalar(blinding, true)),
  };
}

export function verifyTreasurySweepAmountDisclosure(
  certificate: TreasurySweepCertificate,
  disclosure: TreasurySweepAmountDisclosure,
): boolean {
  try {
    if (!disclosure || disclosure.kind !== AMOUNT_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const targetFelts = amountFieldCommitment(certificate, disclosure.field);
    if (!targetFelts) return false;
    const amount = requireBaseUnits(disclosure.amountBaseUnits, "disclosed amount");
    // Re-committing reduces the amount modulo the curve order, so amount + n
    // opens the same point as amount. Every committed figure in this scheme is
    // either a single in-band amount or the sum of the four in-band tiers, so
    // anything at or above four bands is a mod-n forgery, not a real opening.
    const amountBitLength = requireInt(
      certificate.proof?.amountBitLength,
      "amount bit length",
      MIN_TREASURY_AMOUNT_BIT_LENGTH,
      MAX_TREASURY_AMOUNT_BIT_LENGTH,
    );
    if (amount >= BigInt(IDLE_TIER_COUNT) << BigInt(amountBitLength)) return false;
    const blinding = requireScalar(disclosure.blinding, true);
    return pedersenCommit(amount, blinding, independentGenerator()).equals(pointFromFelts(targetFelts));
  } catch {
    return false;
  }
}

/** The PUBLIC mandate reference, opened against its salted commitment. */
export function buildTreasurySweepMandateDisclosure(secret: TreasurySweepCertificateSecret): TreasurySweepRefDisclosure {
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "mandateRef",
    value: secret.mandateRef,
    salt: secret.mandateSalt,
  };
}

/**
 * The SECRET venue or strategy label, opened only when the merchant chooses to.
 * Until then the certificate carries a salted commitment and nothing else, which
 * is the one sense in which the strategy label stays hidden from observers.
 */
export function buildTreasurySweepVenueDisclosure(secret: TreasurySweepCertificateSecret): TreasurySweepRefDisclosure {
  if (!secret.venueCommitted) throw new Error("This certificate has no committed venue reference to disclose.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "venueRef",
    value: secret.venueRef,
    salt: secret.venueSalt,
  };
}

export function verifyTreasurySweepRefDisclosure(
  certificate: TreasurySweepCertificate,
  disclosure: TreasurySweepRefDisclosure,
): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const salt = requireScalar(disclosure.salt, true);
    if (disclosure.field === "mandateRef") {
      if (!certificate.mandateCommitted) return false;
      return toHex(commitRef(MANDATE_DOMAIN, disclosure.value, salt)) === certificate.mandateCommitment;
    }
    if (disclosure.field === "venueRef") {
      if (!certificate.venueCommitted) return false;
      return toHex(commitRef(VENUE_DOMAIN, disclosure.value, salt)) === certificate.venueCommitment;
    }
    return false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Badge, trust model, visibility model
// ---------------------------------------------------------------------------

export function buildTreasurySweepCertificateBadge(certificate: TreasurySweepCertificate): TreasurySweepCertificateBadge {
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    mandateRef: certificate.mandateRef,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    minReserveDisplay: `reserve ≥ ${formatTreasuryBaseUnits(certificate.minReserveBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    maxShareDisplay: `sweep ≤ ${formatBpsShare(certificate.maxSweepShareBps)} of idle`,
    minYieldDisplay: `hurdle ≥ ${formatBpsShare(certificate.minYieldBps)} (operator-typed, not offered)`,
    venueCommitted: certificate.venueCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}

export function summarizeTreasurySweepTrust(): TreasurySweepTrustModel {
  return {
    isZeroKnowledge: true,
    provesTierConservation: true,
    provesReserveCovenant: true,
    provesEligibleSourcing: true,
    provesShareCapCovenant: true,
    provesYieldHurdleCovenant: true,
    hidesTierBalances: true,
    hidesSweepAmount: true,
    hidesProjectedYield: true,
    hidesBalanceRows: true,
    hidesYieldVenue: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    isDecentralized: false,
    isAutomatic: false,
    sweepsOrMovesFunds: false,
    depositsIntoAnyVault: false,
    earnsInterest: false,
    readsShieldedBalances: false,
    settlesOnChain: false,
    movesPoolFunds: false,
    callsPoolContract: false,
    verifiesFiguresAreReal: false,
    guaranteesYield: false,
    isFinancialAdvice: false,
    zeroKnowledgeElement:
      "A verifier learns only that four hidden idle-age tiers conserve a committed total, that a hidden sweep amount is drawn from the eligible idle band, leaves the public reserve floor intact, and stays under the public share cap, and that a hidden projected yield clears the public hurdle — every tier balance, the sweep size, the yield figure, the balance rows, and the venue label stay hidden until the merchant discloses them.",
    statement:
      "This engine proves idle-tier conservation and four public treasury covenants over merchant-supplied commitments, and authenticates the merchant that issued the attestation. It is neither decentralized nor automatic: one merchant key issues attestations, and no contract, oracle, vault, or consensus vouches for the inputs. It does NOT sweep, move, transfer, deposit, withdraw, stake, lend, or invest any value; there is no vault, venue, or counterparty, so nothing earns interest. It does NOT read the merchant's shielded balance or any on-chain state, and it never reads from or writes to the STRK20 pool contract at 0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a — that address is provenance only. It does NOT verify that the committed treasury figures are real; accrual schedules are deterministic integer arithmetic at an operator-typed rate, which is not an offered rate, not achievable, not a guarantee, and not financial advice.",
  };
}

export function getTreasurySweepVisibilityModel(): TreasurySweepVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The four idle-age tier balances and the committed total idle capital.",
      "The eligible idle band total and the sweep amount.",
      "The projected yield figure and every underlying balance row.",
      "The Pedersen blindings and the four derived surplus blindings.",
      "The yield venue or strategy label until selectively disclosed.",
    ],
    disclosedToVerifier: [
      "That the four idle tiers conserve the committed total idle capital.",
      "That the eligible band is exactly tiers 1–3 and that sweep ≤ eligible idle.",
      "That totalIdle − sweep ≥ minReserve, 10000 · sweep ≤ maxSweepShareBps · totalIdle, and 10000 · yield ≥ minYieldBps · sweep.",
      "The public reserve floor, share cap, hurdle rate, mandate reference, program label, and asset.",
      "The issuer public key and Schnorr signature, plus salted commitments to the mandate and any venue reference.",
    ],
    applicationOnly: [
      "The certificate id, creation timestamp, and memo.",
      "The idle ledger, efficiency band, accrual schedule, and sweep-trigger readout (none of which are proven).",
      "The plaintext mandate reference (also bound under a salted commitment).",
    ],
    limitation:
      "This is an off-chain attestation over merchant-supplied figures. It sweeps nothing, deposits into no vault, earns no interest, never reads from or writes to the STRK20 pool contract, and cannot confirm that the committed balances, the sweep, or the projected yield reflect anything real. Accrual schedules are deterministic integer arithmetic at an operator-typed rate, not an offered or achievable return. The pool address is recorded for provenance only.",
  };
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

export function serializeTreasurySweepCertificate(certificate: TreasurySweepCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

export function parseTreasurySweepCertificate(encoded: string): TreasurySweepCertificate {
  const parsed = decodeJson<TreasurySweepCertificate>(fromBase64Url(encoded));
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("This is not a treasury sweep certificate.");
  return parsed;
}

export function serializeTreasurySweepCertificateSecret(secret: TreasurySweepCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseTreasurySweepCertificateSecret(encoded: string): TreasurySweepCertificateSecret {
  const parsed = decodeJson<TreasurySweepCertificateSecret>(fromBase64Url(encoded));
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("This is not a treasury sweep certificate secret.");
  return parsed;
}

export function serializeTreasurySweepAmountDisclosure(disclosure: TreasurySweepAmountDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseTreasurySweepAmountDisclosure(encoded: string): TreasurySweepAmountDisclosure {
  const parsed = decodeJson<TreasurySweepAmountDisclosure>(fromBase64Url(encoded));
  if (!parsed || parsed.kind !== AMOUNT_DISCLOSURE_KIND) throw new Error("This is not a treasury sweep amount disclosure.");
  return parsed;
}

export function serializeTreasurySweepRefDisclosure(disclosure: TreasurySweepRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseTreasurySweepRefDisclosure(encoded: string): TreasurySweepRefDisclosure {
  const parsed = decodeJson<TreasurySweepRefDisclosure>(fromBase64Url(encoded));
  if (!parsed || parsed.kind !== REF_DISCLOSURE_KIND) throw new Error("This is not a treasury sweep reference disclosure.");
  return parsed;
}

export function serializeTreasurySweepCertificateBadge(badge: TreasurySweepCertificateBadge): string {
  return toBase64Url(encodeJson(badge));
}

export function parseTreasurySweepCertificateBadge(encoded: string): TreasurySweepCertificateBadge {
  const parsed = decodeJson<TreasurySweepCertificateBadge>(fromBase64Url(encoded));
  if (!parsed || parsed.kind !== BADGE_KIND) throw new Error("This is not a treasury sweep certificate badge.");
  return parsed;
}

// ---------------------------------------------------------------------------
// Arithmetic and encoding helpers
// ---------------------------------------------------------------------------

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

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

function toHex(value: bigint): string {
  if (value < 0n) throw new Error("Cannot hex-encode a negative value.");
  return `0x${value.toString(16)}`;
}

function hashElements(elements: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

function randomScalar(): bigint {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return nonZeroScalar(mod(value, CURVE_ORDER));
}

function nonZeroScalar(value: bigint): bigint {
  const s = mod(value, CURVE_ORDER);
  return s === 0n ? 1n : s;
}

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

let idCounter = 0;

function defaultId(kind: "certificate"): string {
  idCounter += 1;
  const rand = toHex(randomScalar()).slice(2, 12);
  return `tsw_${kind}_${Date.now().toString(36)}_${idCounter}_${rand}`;
}

function encodeJson(value: unknown): string {
  return JSON.stringify(value);
}

function decodeJson<T>(text: string): T {
  try {
    return JSON.parse(text) as T;
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
