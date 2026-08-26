/**
 * CipherBill — Cash-Flow & AR Aging Attestation Engine
 * =====================================================
 *
 * A client-side module that lets a merchant prove, in zero knowledge, that their
 * committed accounts-receivable aging schedule, liquidity reserve, and daily
 * burn rate satisfy three PUBLIC policy covenants — a minimum cash runway, a
 * maximum days-sales-outstanding (DSO), and a maximum 90+-day concentration
 * share — WITHOUT revealing the bucket amounts, total AR, liquidity, burn,
 * weighted settlement figure, invoice list, or counterparty identities. Five
 * aging-bucket allocations are proven to conserve the committed total AR; each
 * amount leg is range-bounded; and three homomorphic surplus range proofs
 * attest runway ≥ minRunwayDays, DSO ≤ maxDsoDays, and 90+ share ≤
 * maxPastDueShareBps. The merchant signs the binding so anyone can authenticate
 * the issuer offline, and any amount or reference can be selectively disclosed
 * later. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that five hidden aging buckets sum to a committed total AR
 *   and that committed liquidity, burn, and weighted settlement clear three
 *   public policy thresholds. A verifier learns only the policy and that the
 *   relations hold — nothing about the bucket amounts, liquidity, burn, invoices,
 *   or counterparty references until selectively disclosed.
 * - Issuer-authenticated. A Schnorr signature over the binding proves a specific
 *   merchant public key issued it; anyone can check it offline.
 * - Selectively disclosable. The merchant can later open liquidity, burn, any
 *   bucket, the weighted settlement figure, or salted book/counterparty references.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   attestations and no contract, oracle, scheduler, or consensus vouches for
 *   the inputs. `summarizeCashflowTrust()` and `getCashflowVisibilityModel()`
 *   state these limits.
 * - It does NOT collect receivables, advance funds, or settle invoices, and does
 *   NOT move funds in the STRK20 pool. It attests arithmetic over
 *   merchant-supplied figures; any financing happens out of band.
 * - It does NOT verify that the committed AR schedule is real. It binds
 *   merchant-supplied figures; it cannot confirm invoices exist or will pay.
 * - It never reads from or writes to the STRK20 pool contract at
 *   `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`
 *   (`STRK20_POOL_ADDRESS` in `./strk20/config.ts`); that address is recorded as
 *   provenance only and this module never calls it as `CASHFLOW_POOL_ADDRESS`.
 * - Its risk band and rolling runway projection are deterministic heuristics
 *   over the same figures, NOT a credit score, NOT a predictive model, and NOT
 *   financial advice.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const CASHFLOW_ENGINE_VERSION = 1 as const;
export const CASHFLOW_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const CASHFLOW_PROOF_SYSTEM = "stark-pedersen-cashflow-bounds-v1" as const;
/** Basis-point denominator for concentration shares: 10000 = 100%. */
export const BPS_SCALE = 10_000n;
/** Ceiling on the public minimum runway covenant (days). */
export const MAX_MIN_RUNWAY_DAYS = 3650;
/** Ceiling on the public maximum DSO covenant (days). */
export const MAX_DSO_DAYS = 365;
/** Ceiling on the public maximum 90+-day concentration covenant (bps). */
export const MAX_PAST_DUE_SHARE_BPS = 10_000;
export const DEFAULT_CASHFLOW_AMOUNT_BIT_LENGTH = 128;
export const MIN_CASHFLOW_AMOUNT_BIT_LENGTH = 8;
export const MAX_CASHFLOW_AMOUNT_BIT_LENGTH = 128;
/**
 * Extra bits surplus range proofs need beyond the amount range. Policy scalars
 * (runway days, DSO days, bps scale) are < 2^14, so homomorphic products fit in
 * `amountBitLength + 14` bits.
 */
export const CASHFLOW_SURPLUS_EXTRA_BITS = 14;

export const DEFAULT_AGING_BUCKETS = [
  { label: "Current", minDaysPastDue: null as number | null, maxDaysPastDue: 0 },
  { label: "1-30", minDaysPastDue: 1, maxDaysPastDue: 30 },
  { label: "31-60", minDaysPastDue: 31, maxDaysPastDue: 60 },
  { label: "61-90", minDaysPastDue: 61, maxDaysPastDue: 90 },
  { label: "90+", minDaysPastDue: 91, maxDaysPastDue: null as number | null },
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

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill cashflow generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill cashflow statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill cashflow bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill cashflow binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill cashflow issuer signature v1");
const INVOICE_DOMAIN = hash.starknetKeccak("CipherBill cashflow invoice record v1");
const BOOK_DOMAIN = hash.starknetKeccak("CipherBill cashflow book ref v1");
const COUNTERPARTY_DOMAIN = hash.starknetKeccak("CipherBill cashflow counterparty ref v1");

const CERTIFICATE_KIND = "cipherbill.cashflow-certificate" as const;
const SECRET_KIND = "cipherbill.cashflow-certificate-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.cashflow-amount-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.cashflow-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.cashflow-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.cashflow-keypair" as const;
const MAX_ENCODED_LENGTH = 1_600_000;
const BUCKET_COUNT = 5;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface CashflowAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface CashflowKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface CashflowEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

/** PUBLIC cash-flow policy covenants the hidden figures are proven to satisfy. */
export interface CashflowPolicy {
  /** PUBLIC minimum runway in days. Proven: liquidity ≥ minRunwayDays · burn. */
  minRunwayDays: number;
  /** PUBLIC maximum DSO in days. Proven: weighted ≤ maxDsoDays · totalAR. */
  maxDsoDays: number;
  /** PUBLIC maximum 90+-day share in bps. Proven: 90+ ≤ maxShare · totalAR / 10000. */
  maxPastDueShareBps: number;
}

export interface CashflowInvoiceRow {
  alias: string;
  /** ISO-8601 due date. */
  dueDate: string;
  amountBaseUnits: string;
  settlementDays: number;
}

export interface AgingBucketSummary {
  label: string;
  amountBaseUnits: string;
  invoiceCount: number;
}

/** Pure AR aging breakdown aggregated from invoice rows (no proof). */
export interface AgingSchedule {
  asOf: string;
  buckets: AgingBucketSummary[];
  totalArBaseUnits: string;
  weightedSettlementDays: string;
  dsoDays: string;
  pastDueShareBps: string;
  ninetyPlusShareBps: string;
}

/** Pure cash-flow state against a policy (no proof). */
export interface CashflowState {
  liquidityBaseUnits: string;
  burnRateBaseUnits: string;
  totalArBaseUnits: string;
  weightedSettlementDays: string;
  runwayDays: string;
  dsoDays: string;
  pastDueShareBps: string;
  ninetyPlusShareBps: string;
  minRunwayDays: string;
  maxDsoDays: string;
  maxPastDueShareBps: string;
  /** liquidity − minRunwayDays · burn; ≥ 0 exactly when the runway covenant holds. */
  runwaySurplus: string;
  /** maxDsoDays · totalAR − weighted; ≥ 0 exactly when the DSO covenant holds. */
  dsoSurplus: string;
  /** maxPastDueShareBps · totalAR − 10000 · ninetyPlus; ≥ 0 when concentration holds. */
  concentrationSurplus: string;
  eligible: boolean;
}

export interface RollingRunwayWeek {
  weekIndex: number;
  weekStart: string;
  weekEnd: string;
  openingLiquidityBaseUnits: string;
  collectionsBaseUnits: string;
  weeklyBurnBaseUnits: string;
  closingLiquidityBaseUnits: string;
  runwayDays: string;
}

export type CashflowRiskBand = "low" | "elevated" | "high" | "critical";

export interface CashflowRiskAssessment {
  band: CashflowRiskBand;
  score: number;
  runwayRatio: number;
  dsoRatio: number;
  concentrationRatio: number;
  eligible: boolean;
  rationale: string;
}

export interface IssueCashflowCertificateInput {
  merchantAlias: string;
  asset: CashflowAsset;
  /** PUBLIC free-form reference to the AR book this attestation covers. */
  bookRef: string;
  /** PUBLIC human-readable program label. */
  programLabel: string;
  /** PUBLIC cash-flow policy covenants. */
  policy: CashflowPolicy;
  /** SECRET liquidity reserve in integer base units. */
  liquidityBaseUnits: string;
  /** SECRET daily burn rate in integer base units. */
  burnRateBaseUnits: string;
  /**
   * SECRET five aging-bucket amounts in base units (Current, 1-30, 31-60, 61-90, 90+).
   * Must sum to the committed total AR.
   */
  bucketAmountsBaseUnits: [string, string, string, string, string];
  /** SECRET Σ(amount · settlementDays) across the book; never published in the clear. */
  weightedSettlementDays: string;
  /** SECRET counterparty reference; only a salted commitment is published. */
  counterpartyRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

export interface CashflowBitProof {
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
 * Zero-knowledge proof bundle. Legs 0–4 pin each aging bucket; leg 5 liquidity;
 * leg 6 burn; leg 7 weighted settlement; legs 8–10 are the three policy surplus
 * range proofs. Total AR is the homomorphic sum of the five bucket commitments.
 */
export interface CashflowProof {
  proofSystem: typeof CASHFLOW_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  generatorH: CurvePointFelts;
  bucketCommitments: CurvePointFelts[];
  totalArCommitment: CurvePointFelts;
  liquidityCommitment: CurvePointFelts;
  burnCommitment: CurvePointFelts;
  weightedCommitment: CurvePointFelts;
  bucketBits: CashflowBitProof[][];
  liquidityBits: CashflowBitProof[];
  burnBits: CashflowBitProof[];
  weightedBits: CashflowBitProof[];
  runwaySurplusBits: CashflowBitProof[];
  dsoSurplusBits: CashflowBitProof[];
  concentrationSurplusBits: CashflowBitProof[];
}

export interface CashflowCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof CASHFLOW_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  merchantAlias: string;
  bookRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  minRunwayDays: string;
  maxDsoDays: string;
  maxPastDueShareBps: string;
  bookCommitment: string;
  bookCommitted: boolean;
  counterpartyCommitment: string;
  counterpartyCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: CashflowProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}

export interface CashflowCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  liquidityBaseUnits: string;
  burnRateBaseUnits: string;
  bucketAmountsBaseUnits: [string, string, string, string, string];
  totalArBaseUnits: string;
  weightedSettlementDays: string;
  minRunwayDays: string;
  maxDsoDays: string;
  maxPastDueShareBps: string;
  liquidityBlinding: string;
  burnBlinding: string;
  bucketBlindings: string[];
  totalArBlinding: string;
  weightedBlinding: string;
  runwaySurplusBlinding: string;
  dsoSurplusBlinding: string;
  concentrationSurplusBlinding: string;
  bookRef: string;
  bookSalt: string;
  counterpartyRef: string;
  counterpartySalt: string;
  counterpartyCommitted: boolean;
}

export interface IssuedCashflowCertificate {
  certificate: CashflowCertificate;
  secret: CashflowCertificateSecret;
}

export type CashflowAmountField = "liquidity" | "burn" | "weighted" | `bucket${0 | 1 | 2 | 3 | 4}`;

export interface CashflowAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  field: CashflowAmountField;
  amountBaseUnits: string;
  blinding: string;
}

export type CashflowRefField = "bookRef" | "counterpartyRef";

export interface CashflowRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: CashflowRefField;
  value: string;
  salt: string;
}

export interface CashflowCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  merchantAlias: string;
  bookRef: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  minRunwayDisplay: string;
  maxDsoDisplay: string;
  maxConcentrationDisplay: string;
  counterpartyCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface CashflowTrustModel {
  isZeroKnowledge: boolean;
  provesAgingConservation: boolean;
  provesRunwayCovenant: boolean;
  provesDsoCovenant: boolean;
  provesConcentrationCovenant: boolean;
  hidesBucketAmounts: boolean;
  hidesLiquidityAndBurn: boolean;
  hidesInvoiceList: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  collectsOrAdvancesFunds: boolean;
  settlesOnChain: boolean;
  movesPoolFunds: boolean;
  callsPoolContract: boolean;
  verifiesArIsReal: boolean;
  isCreditScoreOrModel: boolean;
  isFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface CashflowVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const CASHFLOW_NOTICE =
  "Zero-knowledge proof that five hidden AR aging buckets conserve a committed total, and that committed liquidity, burn, and weighted settlement satisfy public runway, DSO, and 90+-day concentration covenants — hiding every amount, invoice, and counterparty reference. It authenticates the issuer and supports selective disclosure; it is neither decentralized nor automatic, does not collect or advance funds, does not verify that the AR book is real, and never reads from or writes to the STRK20 pool contract.";

// ---------------------------------------------------------------------------
// Curve primitives
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

export function deriveCashflowGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent cashflow generator.");
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

export function createCashflowIssuerKey(entropy: CashflowEntropy = {}): CashflowKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

// ---------------------------------------------------------------------------
// Invoice commitment and AR aging (pure)
// ---------------------------------------------------------------------------

/** Salted Poseidon commitment to one invoice row; hiding and binding. */
export function commitInvoiceRecord(
  alias: string,
  dueDate: string,
  amountBaseUnits: string | bigint,
  settlementDays: number,
  salt?: bigint,
): string {
  const trimmedAlias = requireText(alias, "invoice alias", 96);
  const isoDue = requireIsoTimestamp(dueDate);
  const amount = requireBaseUnits(amountBaseUnits, "invoice amount");
  const days = requireInt(settlementDays, "settlement days", 0, MAX_DSO_DAYS);
  const s = salt !== undefined ? nonZeroScalar(salt) : nonZeroScalar(randomScalar());
  return toHex(hashElements([INVOICE_DOMAIN, hash.starknetKeccak(trimmedAlias), hash.starknetKeccak(isoDue), amount, BigInt(days), s]));
}

function daysPastDue(dueDate: string, asOf: Date): number {
  const due = new Date(requireIsoTimestamp(dueDate)).getTime();
  return Math.floor((asOf.getTime() - due) / MS_PER_DAY);
}

function bucketIndexForDaysPastDue(days: number): number {
  if (days <= 0) return 0;
  if (days <= 30) return 1;
  if (days <= 60) return 2;
  if (days <= 90) return 3;
  return 4;
}

/** Aggregates invoice rows into a five-bucket AR aging schedule as of a date. */
export function aggregateAgingSchedule(rows: CashflowInvoiceRow[], asOf: Date = new Date()): AgingSchedule {
  if (!Array.isArray(rows)) throw new Error("Invoice rows are required.");
  const asOfIso = asOf.toISOString();
  const amounts = [0n, 0n, 0n, 0n, 0n];
  const counts = [0, 0, 0, 0, 0];
  let weighted = 0n;

  for (const row of rows) {
    const amount = requireBaseUnits(row.amountBaseUnits, "invoice amount");
    const days = requireInt(row.settlementDays, "settlement days", 0, MAX_DSO_DAYS);
    void requireText(row.alias, "invoice alias", 96);
    void requireIsoTimestamp(row.dueDate);
    const idx = bucketIndexForDaysPastDue(daysPastDue(row.dueDate, asOf));
    amounts[idx] += amount;
    counts[idx] += 1;
    weighted += amount * BigInt(days);
  }

  const totalAr = amounts.reduce((acc, v) => acc + v, 0n);
  const pastDue = totalAr - amounts[0];
  const dsoDays = totalAr > 0n ? weighted / totalAr : 0n;
  const pastDueShareBps = totalAr > 0n ? (pastDue * BPS_SCALE) / totalAr : 0n;
  const ninetyPlusShareBps = totalAr > 0n ? (amounts[4] * BPS_SCALE) / totalAr : 0n;

  return {
    asOf: asOfIso,
    buckets: DEFAULT_AGING_BUCKETS.map((bucket, i) => ({
      label: bucket.label,
      amountBaseUnits: amounts[i].toString(),
      invoiceCount: counts[i],
    })),
    totalArBaseUnits: totalAr.toString(),
    weightedSettlementDays: weighted.toString(),
    dsoDays: dsoDays.toString(),
    pastDueShareBps: pastDueShareBps.toString(),
    ninetyPlusShareBps: ninetyPlusShareBps.toString(),
  };
}

export function requireCashflowPolicy(policy: CashflowPolicy): {
  minRunwayDays: number;
  maxDsoDays: number;
  maxPastDueShareBps: number;
} {
  if (!policy || typeof policy !== "object") throw new Error("The cashflow policy is required.");
  const minRunwayDays = requireInt(policy.minRunwayDays, "minimum runway days", 0, MAX_MIN_RUNWAY_DAYS);
  const maxDsoDays = requireInt(policy.maxDsoDays, "maximum DSO days", 0, MAX_DSO_DAYS);
  const maxPastDueShareBps = requireInt(policy.maxPastDueShareBps, "maximum past-due share bps", 0, MAX_PAST_DUE_SHARE_BPS);
  return { minRunwayDays, maxDsoDays, maxPastDueShareBps };
}

/** Computes the pure cash-flow state and policy surpluses (same relations the ZK proof attests). */
export function computeCashflowState(
  liquidityBaseUnits: string | bigint,
  burnRateBaseUnits: string | bigint,
  aging: AgingSchedule,
  policy: CashflowPolicy,
): CashflowState {
  const { minRunwayDays, maxDsoDays, maxPastDueShareBps } = requireCashflowPolicy(policy);
  const liquidity = requireBaseUnits(liquidityBaseUnits, "liquidity");
  const burn = requireBaseUnits(burnRateBaseUnits, "burn rate");
  const totalAr = requireBaseUnits(aging.totalArBaseUnits, "total AR");
  const weighted = requireBaseUnits(aging.weightedSettlementDays, "weighted settlement days");
  const ninetyPlus = requireBaseUnits(aging.buckets[4]?.amountBaseUnits ?? "0", "90+ bucket");

  const runwayDays = burn > 0n ? liquidity / burn : liquidity > 0n ? BigInt(MAX_MIN_RUNWAY_DAYS) + 1n : 0n;
  const minRunway = BigInt(minRunwayDays);
  const maxDso = BigInt(maxDsoDays);
  const maxShare = BigInt(maxPastDueShareBps);

  const runwaySurplus = liquidity - minRunway * burn;
  const dsoSurplus = maxDso * totalAr - weighted;
  const concentrationSurplus = maxShare * totalAr - BPS_SCALE * ninetyPlus;
  const eligible = runwaySurplus >= 0n && dsoSurplus >= 0n && concentrationSurplus >= 0n;

  return {
    liquidityBaseUnits: liquidity.toString(),
    burnRateBaseUnits: burn.toString(),
    totalArBaseUnits: totalAr.toString(),
    weightedSettlementDays: weighted.toString(),
    runwayDays: runwayDays.toString(),
    dsoDays: aging.dsoDays,
    pastDueShareBps: aging.pastDueShareBps,
    ninetyPlusShareBps: aging.ninetyPlusShareBps,
    minRunwayDays: minRunway.toString(),
    maxDsoDays: maxDso.toString(),
    maxPastDueShareBps: maxShare.toString(),
    runwaySurplus: runwaySurplus.toString(),
    dsoSurplus: dsoSurplus.toString(),
    concentrationSurplus: concentrationSurplus.toString(),
    eligible,
  };
}

/** Week-by-week liquidity projection using burn·7 and collections when dueDate+settlementDays falls in the week. */
export function projectRollingRunway(
  rows: CashflowInvoiceRow[],
  liquidityBaseUnits: string | bigint,
  burnRateBaseUnits: string | bigint,
  weeks: number,
  asOf: Date = new Date(),
): RollingRunwayWeek[] {
  const weekCount = requireInt(weeks, "weeks", 1, 104);
  let liquidity = requireBaseUnits(liquidityBaseUnits, "liquidity");
  const dailyBurn = requireBaseUnits(burnRateBaseUnits, "burn rate");
  const weeklyBurn = dailyBurn * 7n;

  const collectionsByWeek = new Array<bigint>(weekCount).fill(0n);
  const startMs = asOf.getTime();

  for (const row of rows) {
    const amount = requireBaseUnits(row.amountBaseUnits, "invoice amount");
    const settlement = requireInt(row.settlementDays, "settlement days", 0, MAX_DSO_DAYS);
    const collectionMs = new Date(requireIsoTimestamp(row.dueDate)).getTime() + settlement * MS_PER_DAY;
    const weekIndex = Math.floor((collectionMs - startMs) / (7 * MS_PER_DAY));
    if (weekIndex >= 0 && weekIndex < weekCount) collectionsByWeek[weekIndex] += amount;
  }

  const projection: RollingRunwayWeek[] = [];
  for (let w = 0; w < weekCount; w += 1) {
    const weekStart = new Date(startMs + w * 7 * MS_PER_DAY);
    const weekEnd = new Date(startMs + (w + 1) * 7 * MS_PER_DAY - 1);
    const opening = liquidity;
    const collections = collectionsByWeek[w];
    liquidity = opening + collections - weeklyBurn;
    const runwayDays = dailyBurn > 0n && liquidity > 0n ? liquidity / dailyBurn : liquidity > 0n ? BigInt(MAX_MIN_RUNWAY_DAYS) + 1n : 0n;
    projection.push({
      weekIndex: w,
      weekStart: weekStart.toISOString(),
      weekEnd: weekEnd.toISOString(),
      openingLiquidityBaseUnits: opening.toString(),
      collectionsBaseUnits: collections.toString(),
      weeklyBurnBaseUnits: weeklyBurn.toString(),
      closingLiquidityBaseUnits: liquidity.toString(),
      runwayDays: runwayDays.toString(),
    });
  }
  return projection;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}

/** Deterministic cash-flow risk heuristic — not a credit score, model, or financial advice. */
export function assessCashflowRisk(state: CashflowState): CashflowRiskAssessment {
  const minRunway = Number(state.minRunwayDays);
  const runway = Number(state.runwayDays);
  const maxDso = Number(state.maxDsoDays);
  const dso = Number(state.dsoDays);
  const maxShare = Number(state.maxPastDueShareBps);
  const ninetyShare = Number(state.ninetyPlusShareBps);

  const runwayRatio = minRunway > 0 ? clamp01(minRunway / Math.max(runway, 1)) : 0;
  const dsoRatio = maxDso > 0 ? clamp01(dso / maxDso) : 0;
  const concentrationRatio = maxShare > 0 ? clamp01(ninetyShare / maxShare) : 0;
  const score = Math.round(100 * clamp01(0.4 * runwayRatio + 0.35 * dsoRatio + 0.25 * concentrationRatio));

  let band: CashflowRiskBand;
  if (!state.eligible || score >= 75) band = "critical";
  else if (score >= 50) band = "high";
  else if (score >= 25) band = "elevated";
  else band = "low";

  return {
    band,
    score,
    runwayRatio,
    dsoRatio,
    concentrationRatio,
    eligible: state.eligible,
    rationale: state.eligible
      ? `Heuristic blend: runway ${runway.toFixed(0)}d vs ${minRunway}d floor, DSO ${dso.toFixed(0)}d vs ${maxDso}d cap, 90+ at ${formatShareBps(state.ninetyPlusShareBps)} vs ${formatShareBps(state.maxPastDueShareBps)} cap.`
      : "One or more policy covenants fail: runway, DSO, or 90+-day concentration surplus is negative.",
  };
}

export function formatCashflowBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

export function formatRunwayDays(days: string | number | bigint): string {
  const n = typeof days === "bigint" ? days : BigInt(days);
  if (n > BigInt(MAX_MIN_RUNWAY_DAYS)) return `${MAX_MIN_RUNWAY_DAYS}+ days`;
  return `${n.toString()} days`;
}

export function formatDsoDays(days: string | number | bigint): string {
  const n = typeof days === "bigint" ? days : BigInt(days);
  return `${n.toString()} days`;
}

export function formatShareBps(bps: string | number | bigint): string {
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
  bookRef: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  minRunwayDays: bigint;
  maxDsoDays: bigint;
  maxPastDueShareBps: bigint;
  amountBitLength: number;
  surplusBitLength: number;
  bookCommitment: bigint;
  bookCommitted: boolean;
  counterpartyCommitment: bigint;
  counterpartyCommitted: boolean;
  createdAt: string;
  memo: string;
}

function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  bucketCommitments: CurvePoint[],
  totalArCommitment: CurvePoint,
  liquidityCommitment: CurvePoint,
  burnCommitment: CurvePoint,
  weightedCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  const bucketElements: bigint[] = [];
  for (const c of bucketCommitments) {
    bucketElements.push(c.x, c.y);
  }
  return hashElements([
    BINDING_DOMAIN,
    BigInt(CASHFLOW_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.bookRef),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.minRunwayDays,
    fields.maxDsoDays,
    fields.maxPastDueShareBps,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    fields.bookCommitment,
    fields.bookCommitted ? 1n : 0n,
    fields.counterpartyCommitment,
    fields.counterpartyCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    ...bucketElements,
    totalArCommitment.x,
    totalArCommitment.y,
    liquidityCommitment.x,
    liquidityCommitment.y,
    burnCommitment.x,
    burnCommitment.y,
    weightedCommitment.x,
    weightedCommitment.y,
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
): CashflowBitProof {
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

function verifyBit(proof: CashflowBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
): CashflowBitProof[] {
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
  const proofs: CashflowBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

function verifyRange(proofs: CashflowBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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

function parseBucketAmounts(amounts: [string, string, string, string, string]): bigint[] {
  return amounts.map((a, i) => requireBaseUnits(a, `bucket ${i} amount`));
}

// ---------------------------------------------------------------------------
// Issue and verify
// ---------------------------------------------------------------------------

export function issueCashflowCertificate(
  input: IssueCashflowCertificateInput,
  now: Date = new Date(),
  entropy: CashflowEntropy = {},
): IssuedCashflowCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const bookRef = requireText(input.bookRef, "book reference", 96);
  const programLabel = requireText(input.programLabel, "program label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const policy = requireCashflowPolicy(input.policy);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_CASHFLOW_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_CASHFLOW_AMOUNT_BIT_LENGTH,
    MAX_CASHFLOW_AMOUNT_BIT_LENGTH,
  );
  const surplusBitLength = amountBitLength + CASHFLOW_SURPLUS_EXTRA_BITS;
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const liquidity = requireBaseUnits(input.liquidityBaseUnits, "liquidity");
  const burn = requireBaseUnits(input.burnRateBaseUnits, "burn rate");
  const buckets = parseBucketAmounts(input.bucketAmountsBaseUnits);
  const totalAr = buckets.reduce((acc, v) => acc + v, 0n);
  const weighted = requireBaseUnits(input.weightedSettlementDays, "weighted settlement days");

  if (liquidity > U128_MAX) throw new Error("The liquidity must fit within the u128 range.");
  if (burn > U128_MAX) throw new Error("The burn rate must fit within the u128 range.");
  if (totalAr > U128_MAX) throw new Error("The total AR must fit within the u128 range.");
  if (weighted > U128_MAX * BigInt(MAX_DSO_DAYS)) throw new Error("The weighted settlement figure is out of range.");

  const band = 1n << BigInt(amountBitLength);
  if (weighted >= band) throw new Error(`The weighted settlement figure exceeds the ${amountBitLength}-bit band.`);

  for (let i = 0; i < BUCKET_COUNT; i += 1) {
    if (buckets[i] >= band) throw new Error(`Bucket ${i} exceeds the ${amountBitLength}-bit band.`);
  }
  if (liquidity >= band) throw new Error(`Liquidity exceeds the ${amountBitLength}-bit band.`);
  if (burn >= band) throw new Error(`Burn rate exceeds the ${amountBitLength}-bit band.`);

  const minRunway = BigInt(policy.minRunwayDays);
  const maxDso = BigInt(policy.maxDsoDays);
  const maxShare = BigInt(policy.maxPastDueShareBps);
  const ninetyPlus = buckets[4];

  const runwaySurplus = liquidity - minRunway * burn;
  const dsoSurplus = maxDso * totalAr - weighted;
  const concentrationSurplus = maxShare * totalAr - BPS_SCALE * ninetyPlus;

  if (runwaySurplus < 0n || dsoSurplus < 0n || concentrationSurplus < 0n) {
    throw new Error("One or more policy surpluses is negative; no honest eligibility proof exists.");
  }
  if (runwaySurplus >= 1n << BigInt(surplusBitLength)) throw new Error(`The runway surplus exceeds the ${surplusBitLength}-bit band.`);
  if (dsoSurplus >= 1n << BigInt(surplusBitLength)) throw new Error(`The DSO surplus exceeds the ${surplusBitLength}-bit band.`);
  if (concentrationSurplus >= 1n << BigInt(surplusBitLength)) {
    throw new Error(`The concentration surplus exceeds the ${surplusBitLength}-bit band.`);
  }

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();

  const bucketBlindings = buckets.map(() => nonZeroScalar(nextScalar()));
  const totalArBlinding = bucketBlindings.reduce((acc, r) => mod(acc + r, CURVE_ORDER), 0n);
  const liquidityBlinding = nonZeroScalar(nextScalar());
  const burnBlinding = nonZeroScalar(nextScalar());
  const weightedBlinding = nonZeroScalar(nextScalar());
  const runwaySurplusBlinding = mod(liquidityBlinding - minRunway * burnBlinding, CURVE_ORDER);
  const dsoSurplusBlinding = mod(maxDso * totalArBlinding - weightedBlinding, CURVE_ORDER);
  const concentrationSurplusBlinding = mod(maxShare * totalArBlinding - BPS_SCALE * bucketBlindings[4], CURVE_ORDER);

  const bucketCommitments = buckets.map((amount, i) => pedersenCommit(amount, bucketBlindings[i], h));
  const totalArCommitment = bucketCommitments.reduce((acc, point) => acc.add(point), ZERO);
  const liquidityCommitment = pedersenCommit(liquidity, liquidityBlinding, h);
  const burnCommitment = pedersenCommit(burn, burnBlinding, h);
  const weightedCommitment = pedersenCommit(weighted, weightedBlinding, h);

  const counterpartyRef = input.counterpartyRef ? requireText(input.counterpartyRef, "counterparty reference", 96) : "";
  const counterpartyCommitted = counterpartyRef.length > 0;
  const counterpartySalt = nonZeroScalar(nextScalar());
  const bookSalt = nonZeroScalar(nextScalar());
  const bookCommitment = commitRef(BOOK_DOMAIN, bookRef, bookSalt);
  const counterpartyCommitment = counterpartyCommitted ? commitRef(COUNTERPARTY_DOMAIN, counterpartyRef, counterpartySalt) : 0n;

  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());
  const fields: BindingFields = {
    certificateId,
    merchantAlias,
    bookRef,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    minRunwayDays: minRunway,
    maxDsoDays: maxDso,
    maxPastDueShareBps: maxShare,
    amountBitLength,
    surplusBitLength,
    bookCommitment,
    bookCommitted: true,
    counterpartyCommitment,
    counterpartyCommitted,
    createdAt,
    memo,
  };
  const bindingHash = computeBindingHash(
    fields,
    issuerKey,
    bucketCommitments,
    totalArCommitment,
    liquidityCommitment,
    burnCommitment,
    weightedCommitment,
    h,
  );
  const ctx = statementContext(bindingHash);

  const bucketBits = bucketCommitments.map((_, i) => proveRange(buckets[i], bucketBlindings[i], amountBitLength, ctx, i, h, nextScalar));
  const liquidityBits = proveRange(liquidity, liquidityBlinding, amountBitLength, ctx, 5, h, nextScalar);
  const burnBits = proveRange(burn, burnBlinding, amountBitLength, ctx, 6, h, nextScalar);
  const weightedBits = proveRange(weighted, weightedBlinding, amountBitLength, ctx, 7, h, nextScalar);
  const runwaySurplusBits = proveRange(runwaySurplus, runwaySurplusBlinding, surplusBitLength, ctx, 8, h, nextScalar);
  const dsoSurplusBits = proveRange(dsoSurplus, dsoSurplusBlinding, surplusBitLength, ctx, 9, h, nextScalar);
  const concentrationSurplusBits = proveRange(concentrationSurplus, concentrationSurplusBlinding, surplusBitLength, ctx, 10, h, nextScalar);

  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);

  const proof: CashflowProof = {
    proofSystem: CASHFLOW_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    generatorH: pointToFelts(h),
    bucketCommitments: bucketCommitments.map(pointToFelts),
    totalArCommitment: pointToFelts(totalArCommitment),
    liquidityCommitment: pointToFelts(liquidityCommitment),
    burnCommitment: pointToFelts(burnCommitment),
    weightedCommitment: pointToFelts(weightedCommitment),
    bucketBits,
    liquidityBits,
    burnBits,
    weightedBits,
    runwaySurplusBits,
    dsoSurplusBits,
    concentrationSurplusBits,
  };

  const certificate: CashflowCertificate = {
    kind: CERTIFICATE_KIND,
    version: CASHFLOW_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    merchantAlias,
    bookRef,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    minRunwayDays: minRunway.toString(),
    maxDsoDays: maxDso.toString(),
    maxPastDueShareBps: maxShare.toString(),
    bookCommitment: toHex(bookCommitment),
    bookCommitted: true,
    counterpartyCommitment: toHex(counterpartyCommitment),
    counterpartyCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: CASHFLOW_NOTICE,
  };

  const secret: CashflowCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    liquidityBaseUnits: liquidity.toString(),
    burnRateBaseUnits: burn.toString(),
    bucketAmountsBaseUnits: buckets.map((b) => b.toString()) as [string, string, string, string, string],
    totalArBaseUnits: totalAr.toString(),
    weightedSettlementDays: weighted.toString(),
    minRunwayDays: minRunway.toString(),
    maxDsoDays: maxDso.toString(),
    maxPastDueShareBps: maxShare.toString(),
    liquidityBlinding: toHex(liquidityBlinding),
    burnBlinding: toHex(burnBlinding),
    bucketBlindings: bucketBlindings.map(toHex),
    totalArBlinding: toHex(totalArBlinding),
    weightedBlinding: toHex(weightedBlinding),
    runwaySurplusBlinding: toHex(runwaySurplusBlinding),
    dsoSurplusBlinding: toHex(dsoSurplusBlinding),
    concentrationSurplusBlinding: toHex(concentrationSurplusBlinding),
    bookRef,
    bookSalt: toHex(bookSalt),
    counterpartyRef,
    counterpartySalt: toHex(counterpartySalt),
    counterpartyCommitted,
  };

  return { certificate, secret };
}

export function verifyCashflowCertificate(certificate: CashflowCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== CASHFLOW_PROOF_SYSTEM) return false;

    const amountBitLength = proof.amountBitLength;
    const surplusBitLength = proof.surplusBitLength;
    if (!Number.isInteger(amountBitLength) || amountBitLength < MIN_CASHFLOW_AMOUNT_BIT_LENGTH || amountBitLength > MAX_CASHFLOW_AMOUNT_BIT_LENGTH) {
      return false;
    }
    if (surplusBitLength !== amountBitLength + CASHFLOW_SURPLUS_EXTRA_BITS) return false;
    if (!Array.isArray(proof.bucketCommitments) || proof.bucketCommitments.length !== BUCKET_COUNT) return false;
    if (!Array.isArray(proof.bucketBits) || proof.bucketBits.length !== BUCKET_COUNT) return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;

    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const bucketCommitments = proof.bucketCommitments.map(pointFromFelts);
    const totalArCommitment = pointFromFelts(proof.totalArCommitment);
    const liquidityCommitment = pointFromFelts(proof.liquidityCommitment);
    const burnCommitment = pointFromFelts(proof.burnCommitment);
    const weightedCommitment = pointFromFelts(proof.weightedCommitment);

    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      bookRef: certificate.bookRef,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: certificate.assetDecimals,
      minRunwayDays: BigInt(certificate.minRunwayDays),
      maxDsoDays: BigInt(certificate.maxDsoDays),
      maxPastDueShareBps: BigInt(certificate.maxPastDueShareBps),
      amountBitLength,
      surplusBitLength,
      bookCommitment: requireFelt(certificate.bookCommitment),
      bookCommitted: certificate.bookCommitted,
      counterpartyCommitment: requireFelt(certificate.counterpartyCommitment),
      counterpartyCommitted: certificate.counterpartyCommitted,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };

    const bindingHash = computeBindingHash(
      fields,
      issuerKey,
      bucketCommitments,
      totalArCommitment,
      liquidityCommitment,
      burnCommitment,
      weightedCommitment,
      h,
    );
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);
    const minRunway = BigInt(certificate.minRunwayDays);
    const maxDso = BigInt(certificate.maxDsoDays);
    const maxShare = BigInt(certificate.maxPastDueShareBps);

    let bucketSumPoint = ZERO;
    for (let i = 0; i < BUCKET_COUNT; i += 1) {
      const bucketSum = verifyRange(proof.bucketBits[i], amountBitLength, ctx, i, h);
      if (!bucketSum || !bucketSum.equals(bucketCommitments[i])) return false;
      bucketSumPoint = bucketSumPoint.add(bucketSum);
    }
    if (!bucketSumPoint.equals(totalArCommitment)) return false;

    const liquiditySum = verifyRange(proof.liquidityBits, amountBitLength, ctx, 5, h);
    if (!liquiditySum || !liquiditySum.equals(liquidityCommitment)) return false;
    const burnSum = verifyRange(proof.burnBits, amountBitLength, ctx, 6, h);
    if (!burnSum || !burnSum.equals(burnCommitment)) return false;
    const weightedSum = verifyRange(proof.weightedBits, amountBitLength, ctx, 7, h);
    if (!weightedSum || !weightedSum.equals(weightedCommitment)) return false;

    const runwaySurplusSum = verifyRange(proof.runwaySurplusBits, surplusBitLength, ctx, 8, h);
    if (!runwaySurplusSum) return false;
    const expectedRunway = liquidityCommitment.add(scalePoint(burnCommitment, minRunway).negate());
    if (!runwaySurplusSum.equals(expectedRunway)) return false;

    const dsoSurplusSum = verifyRange(proof.dsoSurplusBits, surplusBitLength, ctx, 9, h);
    if (!dsoSurplusSum) return false;
    const expectedDso = scalePoint(totalArCommitment, maxDso).add(weightedCommitment.negate());
    if (!dsoSurplusSum.equals(expectedDso)) return false;

    const concentrationSurplusSum = verifyRange(proof.concentrationSurplusBits, surplusBitLength, ctx, 10, h);
    if (!concentrationSurplusSum) return false;
    const expectedConcentration = scalePoint(totalArCommitment, maxShare).add(scalePoint(bucketCommitments[4], BPS_SCALE).negate());
    if (!concentrationSurplusSum.equals(expectedConcentration)) return false;

    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Selective disclosure
// ---------------------------------------------------------------------------

function amountFieldCommitment(certificate: CashflowCertificate, field: CashflowAmountField): CurvePointFelts | null {
  const proof = certificate.proof;
  if (field === "liquidity") return proof.liquidityCommitment;
  if (field === "burn") return proof.burnCommitment;
  if (field === "weighted") return proof.weightedCommitment;
  const match = /^bucket([0-4])$/.exec(field);
  if (match) return proof.bucketCommitments[Number(match[1])] ?? null;
  return null;
}

function amountFieldFromSecret(secret: CashflowCertificateSecret, field: CashflowAmountField): { amount: string; blinding: string } {
  if (field === "liquidity") return { amount: secret.liquidityBaseUnits, blinding: secret.liquidityBlinding };
  if (field === "burn") return { amount: secret.burnRateBaseUnits, blinding: secret.burnBlinding };
  if (field === "weighted") return { amount: secret.weightedSettlementDays, blinding: secret.weightedBlinding };
  const match = /^bucket([0-4])$/.exec(field);
  if (match) {
    const idx = Number(match[1]);
    return { amount: secret.bucketAmountsBaseUnits[idx], blinding: secret.bucketBlindings[idx] };
  }
  throw new Error("Unknown cashflow amount field.");
}

export function buildCashflowAmountDisclosure(
  secret: CashflowCertificateSecret,
  field: CashflowAmountField,
): CashflowAmountDisclosure {
  const { amount, blinding } = amountFieldFromSecret(secret, field);
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field,
    amountBaseUnits: requireBaseUnits(amount, "disclosed amount").toString(),
    blinding: toHex(requireScalar(blinding, true)),
  };
}

export function verifyCashflowAmountDisclosure(certificate: CashflowCertificate, disclosure: CashflowAmountDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== AMOUNT_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const targetFelts = amountFieldCommitment(certificate, disclosure.field);
    if (!targetFelts) return false;
    const amount = requireBaseUnits(disclosure.amountBaseUnits, "disclosed amount");
    const blinding = requireScalar(disclosure.blinding, true);
    return pedersenCommit(amount, blinding, independentGenerator()).equals(pointFromFelts(targetFelts));
  } catch {
    return false;
  }
}

export function buildCashflowBookRefDisclosure(secret: CashflowCertificateSecret): CashflowRefDisclosure {
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "bookRef",
    value: secret.bookRef,
    salt: secret.bookSalt,
  };
}

export function buildCashflowCounterpartyDisclosure(secret: CashflowCertificateSecret): CashflowRefDisclosure {
  if (!secret.counterpartyCommitted) throw new Error("This certificate has no committed counterparty reference to disclose.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "counterpartyRef",
    value: secret.counterpartyRef,
    salt: secret.counterpartySalt,
  };
}

export function verifyCashflowRefDisclosure(certificate: CashflowCertificate, disclosure: CashflowRefDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const salt = requireScalar(disclosure.salt, true);
    if (disclosure.field === "bookRef") {
      if (!certificate.bookCommitted) return false;
      return toHex(commitRef(BOOK_DOMAIN, disclosure.value, salt)) === certificate.bookCommitment;
    }
    if (disclosure.field === "counterpartyRef") {
      if (!certificate.counterpartyCommitted) return false;
      return toHex(commitRef(COUNTERPARTY_DOMAIN, disclosure.value, salt)) === certificate.counterpartyCommitment;
    }
    return false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Badge, trust model, visibility model
// ---------------------------------------------------------------------------

export function buildCashflowCertificateBadge(certificate: CashflowCertificate): CashflowCertificateBadge {
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    bookRef: certificate.bookRef,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    minRunwayDisplay: `≥ ${formatRunwayDays(certificate.minRunwayDays)} runway`,
    maxDsoDisplay: `≤ ${formatDsoDays(certificate.maxDsoDays)}`,
    maxConcentrationDisplay: `≤ ${formatShareBps(certificate.maxPastDueShareBps)} in 90+`,
    counterpartyCommitted: certificate.counterpartyCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}

export function summarizeCashflowTrust(): CashflowTrustModel {
  return {
    isZeroKnowledge: true,
    provesAgingConservation: true,
    provesRunwayCovenant: true,
    provesDsoCovenant: true,
    provesConcentrationCovenant: true,
    hidesBucketAmounts: true,
    hidesLiquidityAndBurn: true,
    hidesInvoiceList: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    isDecentralized: false,
    isAutomatic: false,
    collectsOrAdvancesFunds: false,
    settlesOnChain: false,
    movesPoolFunds: false,
    callsPoolContract: false,
    verifiesArIsReal: false,
    isCreditScoreOrModel: false,
    isFinancialAdvice: false,
    zeroKnowledgeElement:
      "A verifier learns only that five hidden aging buckets conserve a committed total AR and that committed liquidity, burn, and weighted settlement satisfy the public runway, DSO, and 90+-day concentration covenants — every amount, invoice, and counterparty reference stays hidden until disclosed.",
    statement:
      "This engine proves AR aging conservation and three public cash-flow policy covenants over merchant-supplied commitments, and authenticates the merchant that issued the attestation. It is neither decentralized nor automatic: one merchant key issues attestations, and no contract, oracle, or consensus vouches for the inputs. It does not collect receivables, advance funds, or move funds in the STRK20 pool; it never reads from or writes to the STRK20 pool contract at 0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a — that address is provenance only. It does not verify that the AR book is real; risk bands and runway projections are deterministic heuristics, not a credit score, a predictive model, or financial advice.",
  };
}

export function getCashflowVisibilityModel(): CashflowVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The five aging-bucket amounts and the committed total AR.",
      "The committed liquidity reserve and daily burn rate.",
      "The weighted settlement figure and every invoice row.",
      "The Pedersen blindings and surplus blindings.",
      "The counterparty reference until selectively disclosed.",
    ],
    disclosedToVerifier: [
      "That the five buckets conserve the committed total AR.",
      "That liquidity ≥ minRunwayDays · burn, weighted ≤ maxDsoDays · totalAR, and 90+ ≤ maxPastDueShareBps · totalAR / 10000.",
      "The public policy thresholds, book reference, program label, and asset.",
      "The issuer public key and Schnorr signature authenticating the attestation.",
      "Salted commitments to the book and any counterparty reference.",
    ],
    applicationOnly: [
      "The certificate id, creation timestamp, and memo.",
      "The deterministic risk band and rolling runway projection (not proven).",
      "The plaintext book reference (also bound under a salted commitment).",
    ],
    limitation:
      "This is an off-chain attestation over merchant-supplied figures. It never reads from or writes to the STRK20 pool contract, does not collect or advance funds, and cannot confirm that the AR schedule reflects real invoices. The pool address is recorded for provenance only.",
  };
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

export function serializeCashflowCertificate(certificate: CashflowCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

export function parseCashflowCertificate(encoded: string): CashflowCertificate {
  const parsed = decodeJson(fromBase64Url(encoded)) as CashflowCertificate;
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("The encoded cashflow certificate is invalid.");
  return parsed;
}

export function serializeCashflowCertificateSecret(secret: CashflowCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseCashflowCertificateSecret(encoded: string): CashflowCertificateSecret {
  const parsed = decodeJson(fromBase64Url(encoded)) as CashflowCertificateSecret;
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("The encoded cashflow secret is invalid.");
  return parsed;
}

export function serializeCashflowAmountDisclosure(disclosure: CashflowAmountDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseCashflowAmountDisclosure(encoded: string): CashflowAmountDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as CashflowAmountDisclosure;
  if (!parsed || parsed.kind !== AMOUNT_DISCLOSURE_KIND) throw new Error("The encoded amount disclosure is invalid.");
  return parsed;
}

export function serializeCashflowRefDisclosure(disclosure: CashflowRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseCashflowRefDisclosure(encoded: string): CashflowRefDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as CashflowRefDisclosure;
  if (!parsed || parsed.kind !== REF_DISCLOSURE_KIND) throw new Error("The encoded reference disclosure is invalid.");
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
  return `cf_${kind}_${Date.now().toString(36)}_${idCounter}_${rand}`;
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
