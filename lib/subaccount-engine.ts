/**
 * CipherBill — Merchant Expense Sub-Account & Departmental Budget Allocation Proof Engine
 * =======================================================================================
 *
 * A client-side module that lets an enterprise prove, in zero knowledge, a PUBLIC
 * budget-governance claim over PRIVATE departmental sub-accounts: that its hidden
 * per-department allocations sum to a total that does NOT exceed a public budget
 * cap, and that every department's hidden spend does NOT exceed its own hidden
 * allocation (no cost centre overspends) — WITHOUT revealing any department's
 * allocation, its spend, its cost-centre label, or any aggregate. Each department's
 * allocation and spend are hidden inside Pedersen commitments over the STARK curve;
 * the allocation commitments sum homomorphically to a hidden aggregate; a
 * bit-decomposition range proof binds every allocation, every spend, the aggregate,
 * and each derived gap to a non-negative band; a per-department "headroom" range
 * proof on the homomorphic point A_i − S_i attests spend ≤ allocation; and an
 * aggregate "budget headroom" range proof on B_cap·G − ΣA_i attests the allocations
 * fit under the public cap — all without opening a single figure. The enterprise
 * signs the binding so anyone can authenticate the attestation offline, and any
 * figure (a department allocation, a department spend, a cost-centre label, the
 * aggregate allocated, or the aggregate spent) can be selectively disclosed later.
 * Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that hidden departmental allocations aggregate to a total
 *   within a PUBLIC budget cap, and that each department's hidden spend is at most
 *   its hidden allocation. A verifier learns the department count and the public
 *   cap — never a department's allocation, its spend, its label, or any aggregate.
 * - Issuer-authenticated with a Schnorr signature anyone can check offline.
 * - Selectively disclosable per figure, and fully openable to a counterparty.
 * - Self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It does NOT move, allocate, partition, disburse, escrow, or settle any funds,
 *   and does NOT create, fund, or debit any sub-account, balance, or budget on any
 *   ledger. Allocations and spends are merchant-supplied figures the proof binds;
 *   nothing here transfers value or lowers on-chain gas.
 * - It does NOT enforce a spending constraint anywhere: it proves a relation over
 *   figures already chosen, it cannot stop a department from spending.
 * - It does NOT read from or write to the STRK20 pool contract; the pool address
 *   below is provenance only.
 * - It does NOT verify that the committed allocations or spends are real. It binds
 *   merchant-supplied figures; it cannot confirm any balance or payment exists.
 * - It is neither decentralized nor automatic: a single enterprise key issues
 *   attestations and no contract, oracle, scheduler, or consensus vouches for the
 *   inputs. It is not a budgeting guarantee and not financial advice.
 *   `summarizeSubaccountTrust()` and `getSubaccountVisibilityModel()` state these limits.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const SUBACCOUNT_ENGINE_VERSION = 1 as const;
export const SUBACCOUNT_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const SUBACCOUNT_PROOF_SYSTEM = "stark-pedersen-expense-subaccount-v1" as const;

/** Number of departmental sub-accounts a single attestation may partition. */
export const MIN_SUBACCOUNT_DEPARTMENTS = 1;
export const MAX_SUBACCOUNT_DEPARTMENTS = 16;
/** Bit band for the hidden allocations, spends, the aggregate, and every derived gap. */
export const DEFAULT_SUBACCOUNT_AMOUNT_BIT_LENGTH = 96;
export const MIN_SUBACCOUNT_AMOUNT_BIT_LENGTH = 8;
export const MAX_SUBACCOUNT_AMOUNT_BIT_LENGTH = 128;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;
const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill subaccount generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill subaccount statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill subaccount bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill subaccount binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill subaccount issuer signature v1");
const LABEL_DOMAIN = hash.starknetKeccak("CipherBill subaccount department label v1");
const ENTERPRISE_DOMAIN = hash.starknetKeccak("CipherBill subaccount enterprise ref v1");
const CERTIFICATE_KIND = "cipherbill.subaccount-certificate" as const;
const SECRET_KIND = "cipherbill.subaccount-certificate-secret" as const;
const METRIC_DISCLOSURE_KIND = "cipherbill.subaccount-metric-disclosure" as const;
const DEPARTMENT_DISCLOSURE_KIND = "cipherbill.subaccount-department-disclosure" as const;
const LABEL_DISCLOSURE_KIND = "cipherbill.subaccount-label-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.subaccount-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.subaccount-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.subaccount-keypair" as const;
const MAX_ENCODED_LENGTH = 1_400_000;

/**
 * Proof-leg identifiers. The aggregate legs sit at 900–901; the per-department
 * legs sit in well-separated bands so each department's three legs never collide
 * with another's, giving every range proof its own Fiat–Shamir domain.
 */
const LEG_TOTAL_ALLOC = 900;
const LEG_BUDGET_HEADROOM = 901;
const ALLOC_LEG_BASE = 1_000;
const SPEND_LEG_BASE = 2_000;
const HEADROOM_LEG_BASE = 3_000;

/** A selectively disclosable aggregate figure. */
export type SubaccountMetric = "allocated" | "spent";

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface SubaccountAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface SubaccountKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing enterprise keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface SubaccountEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

/**
 * One departmental sub-account's PRIVATE figures. None are ever published in the
 * clear: the allocation and spend are hidden behind Pedersen commitments and the
 * cost-centre label behind a salted commitment.
 */
export interface SubaccountDepartmentInput {
  /** SECRET cost-centre label; only a salted commitment is published. Optional. */
  label?: string;
  /** SECRET budget allocated to this department, in base units. */
  allocationBaseUnits: string;
  /** SECRET amount spent by this department, in base units. Must not exceed the allocation. */
  spendBaseUnits: string;
}

/** The private departmental ledger a single attestation partitions and proves. */
export interface SubaccountLedger {
  departments: SubaccountDepartmentInput[];
}

export interface IssueSubaccountCertificateInput {
  enterpriseAlias: string;
  asset: SubaccountAsset;
  /** PUBLIC label of the governance period this attestation covers (e.g. "FY26 Q3"). */
  periodLabel: string;
  /** PUBLIC human-readable budget-framework label. */
  programLabel: string;
  /** PUBLIC budget cap the hidden allocations must fit under, in base units. */
  budgetCapBaseUnits: string;
  /** SECRET departmental ledger being committed and aggregated. */
  ledger: SubaccountLedger;
  /** SECRET opaque enterprise/entity reference; only a salted commitment is published. */
  enterpriseRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface SubaccountBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

/** Schnorr signature (challenge, response) over the binding by the issuer key. */
export interface SubaccountIssuerSignature {
  challenge: string;
  response: string;
}

/** The published per-department commitments (allocation, spend, and salted cost-centre label). */
export interface SubaccountDepartmentCommitments {
  allocationCommitment: CurvePointFelts;
  spendCommitment: CurvePointFelts;
  /** Salted Poseidon commitment to the cost-centre label; "0x0" when no label was committed. */
  labelCommitment: string;
  labelCommitted: boolean;
}

/**
 * Zero-knowledge proof bundle. Range legs bound the hidden figures and derived
 * homomorphic points enforce no-overspend and the budget cap:
 *   allocation[i]  a_i ∈ [0, 2^amountBits)          (tied to A_i);
 *   spend[i]       s_i ∈ [0, 2^amountBits)           (tied to S_i);
 *   headroom[i]    a_i − s_i ∈ [0, 2^amountBits)     (tied to A_i − S_i ⇒ s_i ≤ a_i);
 *   totalAlloc     Σa_i ∈ [0, 2^amountBits)          (tied to ΣA_i ⇒ aggregate bounded);
 *   budgetHeadroom B_cap − Σa_i ∈ [0, 2^amountBits)  (tied to B_cap·G − ΣA_i ⇒ Σa_i ≤ B_cap).
 */
export interface SubaccountProof {
  proofSystem: typeof SUBACCOUNT_PROOF_SYSTEM;
  amountBitLength: number;
  generatorH: CurvePointFelts;
  departments: SubaccountDepartmentCommitments[];
  allocationBits: SubaccountBitProof[][];
  spendBits: SubaccountBitProof[][];
  headroomBits: SubaccountBitProof[][];
  totalAllocBits: SubaccountBitProof[];
  budgetHeadroomBits: SubaccountBitProof[];
}

export interface SubaccountCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof SUBACCOUNT_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  enterpriseAlias: string;
  periodLabel: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC budget cap the aggregate allocation was proven to fit under, in base units. */
  budgetCapBaseUnits: string;
  /** PUBLIC number of departments partitioned (a count, never an amount). */
  departmentCount: number;
  /** Salted Poseidon commitment to the enterprise reference; hides the value. */
  enterpriseCommitment: string;
  enterpriseCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: SubaccountProof;
  issuerSignature: SubaccountIssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}

/** SECRET issuer record of a freshly issued attestation. Never publish it. */
export interface SubaccountCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  labels: string[];
  labelSalts: string[];
  labelsCommitted: boolean[];
  allocationsBaseUnits: string[];
  allocationBlindings: string[];
  spendsBaseUnits: string[];
  spendBlindings: string[];
  totalAllocatedBaseUnits: string;
  /** Aggregate allocation blinding R = Σ r_i (mod n), backing the ΣA_i commitment. */
  totalAllocatedBlinding: string;
  totalSpentBaseUnits: string;
  /** Aggregate spend blinding T = Σ t_i (mod n), backing the ΣS_i commitment. */
  totalSpentBlinding: string;
  enterpriseRef: string;
  enterpriseSalt: string;
  enterpriseCommitted: boolean;
}

export interface IssuedSubaccountCertificate {
  certificate: SubaccountCertificate;
  secret: SubaccountCertificateSecret;
}

/** A full opening the enterprise can hand a counterparty to disclose every committed figure. */
export interface SubaccountCertificateOpening {
  allocationsBaseUnits: string[];
  allocationBlindings: string[];
  spendsBaseUnits: string[];
  spendBlindings: string[];
  totalAllocatedBaseUnits: string;
  totalAllocatedBlinding: string;
  totalSpentBaseUnits: string;
  totalSpentBlinding: string;
}

/** Selective disclosure of a single aggregate figure (total allocated, or total spent). */
export interface SubaccountMetricDisclosure {
  kind: typeof METRIC_DISCLOSURE_KIND;
  certificateId: string;
  metric: SubaccountMetric;
  valueBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of one hidden department figure (its allocation or its spend). */
export interface SubaccountDepartmentDisclosure {
  kind: typeof DEPARTMENT_DISCLOSURE_KIND;
  certificateId: string;
  departmentIndex: number;
  field: SubaccountMetric;
  valueBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of one department's committed cost-centre label. */
export interface SubaccountLabelDisclosure {
  kind: typeof LABEL_DISCLOSURE_KIND;
  certificateId: string;
  departmentIndex: number;
  value: string;
  salt: string;
}

/** Selective disclosure of the committed enterprise reference. */
export interface SubaccountRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: "enterprise";
  value: string;
  salt: string;
}

export interface SubaccountCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  enterpriseAlias: string;
  periodLabel: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  departmentCount: number;
  budgetCapDisplay: string;
  enterpriseCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface SubaccountTrustModel {
  isZeroKnowledge: boolean;
  provesAllocationsFitBudgetCap: boolean;
  provesNoDepartmentOverspends: boolean;
  provesEveryFigureNonNegative: boolean;
  hidesDepartmentAllocations: boolean;
  hidesDepartmentSpends: boolean;
  hidesAggregateAllocated: boolean;
  hidesAggregateSpent: boolean;
  hidesCostCentreLabels: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  movesOrAllocatesFunds: boolean;
  createsOrFundsSubAccounts: boolean;
  enforcesSpendingConstraints: boolean;
  reducesGas: boolean;
  movesPoolFunds: boolean;
  verifiesFiguresAreReal: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  isBudgetGuaranteeOrFinancialAdvice: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface SubaccountVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const SUBACCOUNT_NOTICE =
  "Zero-knowledge proof that an enterprise's hidden departmental allocations aggregate into a total that does not exceed a public budget cap, and that every department's hidden spend is at most its own hidden allocation (no cost centre overspends) — hiding every allocation, every spend, every cost-centre label, and both aggregates. It authenticates the issuer and supports selective disclosure; it does not move, allocate, partition, disburse, escrow, or settle any funds, does not create, fund, or debit any sub-account or balance, does not enforce any spending constraint, does not reduce gas, does not verify that the committed figures are real, is neither decentralized nor automatic, is not a budgeting guarantee or financial advice, and never reads from or writes to the STRK20 pool contract.";
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
export function deriveSubaccountGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent subaccount generator.");
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

/** An enterprise issuing keypair. The secret signs attestations; the public key authenticates them. */
export function createSubaccountIssuerKey(entropy: SubaccountEntropy = {}): SubaccountKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}
// ---------------------------------------------------------------------------
// Departmental ledger, aggregates, and state (pure)
// ---------------------------------------------------------------------------

/** Basis-point denominator for the display-only utilization percentages (100% = 10000 bps). */
const SUBACCOUNT_BPS_DENOMINATOR = 10_000n;

interface NormalizedDepartment {
  label: string;
  allocation: bigint;
  spend: bigint;
}

interface NormalizedLedger {
  departments: NormalizedDepartment[];
  totalAllocated: bigint;
  totalSpent: bigint;
}

/**
 * Parses and bounds the SECRET departmental ledger: each allocation and spend is a
 * non-negative u128 base-unit integer, and every department's spend must not exceed
 * its allocation (no honest no-overspend proof exists otherwise).
 */
function requireLedger(ledger: SubaccountLedger): NormalizedLedger {
  if (!ledger || typeof ledger !== "object" || !Array.isArray(ledger.departments)) {
    throw new Error("The departmental ledger is required.");
  }
  const raw = ledger.departments;
  if (raw.length < MIN_SUBACCOUNT_DEPARTMENTS || raw.length > MAX_SUBACCOUNT_DEPARTMENTS) {
    throw new Error(`The attestation must partition between ${MIN_SUBACCOUNT_DEPARTMENTS} and ${MAX_SUBACCOUNT_DEPARTMENTS} departments.`);
  }
  const departments: NormalizedDepartment[] = [];
  let totalAllocated = 0n;
  let totalSpent = 0n;
  for (let i = 0; i < raw.length; i += 1) {
    const entry = raw[i];
    if (!entry || typeof entry !== "object") throw new Error(`Department ${i + 1} is malformed.`);
    const label = entry.label && entry.label.trim().length > 0 ? requireText(entry.label, `department ${i + 1} label`, 64) : "";
    const allocation = requireBaseUnits(entry.allocationBaseUnits, `department ${i + 1} allocation`);
    const spend = requireBaseUnits(entry.spendBaseUnits, `department ${i + 1} spend`);
    if (allocation > U128_MAX) throw new Error(`Department ${i + 1} allocation must fit within the u128 range.`);
    if (spend > U128_MAX) throw new Error(`Department ${i + 1} spend must fit within the u128 range.`);
    if (spend > allocation) throw new Error(`Department ${i + 1} spend exceeds its allocation.`);
    departments.push({ label, allocation, spend });
    totalAllocated += allocation;
    totalSpent += spend;
  }
  return { departments, totalAllocated, totalSpent };
}

/** Parses the PUBLIC budget cap as a non-negative base-unit integer. */
function requireBudgetCap(value: unknown): bigint {
  return requireBaseUnits(value, "budget cap");
}

/** floor(part · 10000 / whole): a display-only utilization figure, 0 when the denominator is 0. */
function utilizationBps(part: bigint, whole: bigint): string {
  if (whole <= 0n) return "0";
  return ((part * SUBACCOUNT_BPS_DENOMINATOR) / whole).toString();
}

export interface SubaccountDepartmentState {
  index: number;
  label: string;
  allocationBaseUnits: string;
  spendBaseUnits: string;
  /** allocation − spend: the department's remaining headroom, in base units. */
  headroomBaseUnits: string;
  /** floor(spend · 10000 / allocation), display-only. */
  utilizationBps: string;
}

/** The pure, proof-free breakdown of a departmental partition. Computed locally; never fully published. */
export interface SubaccountState {
  departmentCount: number;
  budgetCapBaseUnits: string;
  /** The hidden aggregate allocation (sum of the departments). Never published in the clear. */
  totalAllocatedBaseUnits: string;
  /** The hidden aggregate spend (sum of the departments). Never published in the clear. */
  totalSpentBaseUnits: string;
  /** budgetCap − totalAllocated: the unallocated budget headroom, in base units. */
  unallocatedBaseUnits: string;
  /** totalAllocated − totalSpent: aggregate remaining headroom, in base units. */
  totalHeadroomBaseUnits: string;
  /** floor(totalAllocated · 10000 / budgetCap), display-only. */
  budgetUtilizationBps: string;
  /** Whether the aggregate allocation fits under the public cap (a passing proof requires this). */
  fitsBudget: boolean;
  departments: SubaccountDepartmentState[];
}

/**
 * Computes the pure partition state: each department's headroom and utilization,
 * the hidden aggregates, and whether the allocations fit under the public cap.
 * This is the same relation the zero-knowledge proof attests. Throws when the
 * ledger overspends a department or breaches the cap, because no honest proof
 * exists in that case.
 */
export function computeSubaccountState(ledger: SubaccountLedger, budgetCapBaseUnits: string): SubaccountState {
  const { departments, totalAllocated, totalSpent } = requireLedger(ledger);
  const budgetCap = requireBudgetCap(budgetCapBaseUnits);
  if (totalAllocated > budgetCap) throw new Error("The total allocation exceeds the budget cap.");
  return {
    departmentCount: departments.length,
    budgetCapBaseUnits: budgetCap.toString(),
    totalAllocatedBaseUnits: totalAllocated.toString(),
    totalSpentBaseUnits: totalSpent.toString(),
    unallocatedBaseUnits: (budgetCap - totalAllocated).toString(),
    totalHeadroomBaseUnits: (totalAllocated - totalSpent).toString(),
    budgetUtilizationBps: utilizationBps(totalAllocated, budgetCap),
    fitsBudget: totalAllocated <= budgetCap,
    departments: departments.map((d, i) => ({
      index: i,
      label: d.label,
      allocationBaseUnits: d.allocation.toString(),
      spendBaseUnits: d.spend.toString(),
      headroomBaseUnits: (d.allocation - d.spend).toString(),
      utilizationBps: utilizationBps(d.spend, d.allocation),
    })),
  };
}

export function formatSubaccountBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

/** Formats a rate expressed in basis points, e.g. 250 → "2.5%", 5000 → "50%". */
export function formatSubaccountBps(bps: string | number | bigint): string {
  const n = Number(bps);
  return `${(n / 100).toString()}%`;
}
// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface DepartmentLabelField {
  commitment: bigint;
  committed: boolean;
}

interface BindingFields {
  certificateId: string;
  enterpriseAlias: string;
  periodLabel: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  budgetCap: bigint;
  departmentCount: number;
  amountBitLength: number;
  enterpriseCommitment: bigint;
  enterpriseCommitted: boolean;
  createdAt: string;
  memo: string;
}

/**
 * The certificate binding hash: a Poseidon digest over every public,
 * proof-independent field plus the budget cap, every department's allocation,
 * spend, and label commitments, and the generator H. Every range-proof challenge
 * and the issuer signature are bound to it, so no field can be altered without
 * invalidating the certificate.
 */
function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  allocationCommitments: CurvePoint[],
  spendCommitments: CurvePoint[],
  labels: DepartmentLabelField[],
  h: CurvePoint,
): bigint {
  const elements: bigint[] = [
    BINDING_DOMAIN,
    BigInt(SUBACCOUNT_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.enterpriseAlias),
    hash.starknetKeccak(fields.periodLabel),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.budgetCap,
    BigInt(fields.departmentCount),
    BigInt(fields.amountBitLength),
    fields.enterpriseCommitment,
    fields.enterpriseCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    h.x,
    h.y,
  ];
  for (let i = 0; i < allocationCommitments.length; i += 1) {
    elements.push(
      allocationCommitments[i].x,
      allocationCommitments[i].y,
      spendCommitments[i].x,
      spendCommitments[i].y,
      labels[i].commitment,
      labels[i].committed ? 1n : 0n,
    );
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
): SubaccountBitProof {
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

function verifyBit(proof: SubaccountBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
): SubaccountBitProof[] {
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
  const proofs: SubaccountBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies every bit and returns the reconstructed commitment `Σ 2^i·C_i`, or null. */
function verifyRange(proofs: SubaccountBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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
function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): SubaccountIssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

/** Verifies the issuer Schnorr signature against the published public key. */
function verifySignature(signature: SubaccountIssuerSignature, bindingHash: bigint, publicKey: CurvePoint): boolean {
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
// Issue and verify a subaccount certificate
// ---------------------------------------------------------------------------

/**
 * Issues a zero-knowledge departmental budget-partition certificate. It commits
 * every hidden allocation and spend, proves each is a bounded non-negative
 * integer, proves each department's spend is at most its allocation (no
 * overspend) via the homomorphic point A_i − S_i, and proves the hidden
 * aggregate allocation fits under the public budget cap via B_cap·G − ΣA_i — all
 * without revealing any figure. Throws when the inputs overspend a department,
 * breach the cap, or exceed the proven bit band, because no honest proof exists
 * in those cases.
 */
export function issueSubaccountCertificate(
  input: IssueSubaccountCertificateInput,
  now: Date = new Date(),
  entropy: SubaccountEntropy = {},
): IssuedSubaccountCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const enterpriseAlias = requireText(input.enterpriseAlias, "enterprise alias", 96);
  const periodLabel = requireText(input.periodLabel, "period label", 96);
  const programLabel = requireText(input.programLabel, "program label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 18);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_SUBACCOUNT_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_SUBACCOUNT_AMOUNT_BIT_LENGTH,
    MAX_SUBACCOUNT_AMOUNT_BIT_LENGTH,
  );
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";
  const budgetCap = requireBudgetCap(input.budgetCapBaseUnits);
  const { departments, totalAllocated, totalSpent } = requireLedger(input.ledger);

  const amountCeiling = 1n << BigInt(amountBitLength);
  for (let i = 0; i < departments.length; i += 1) {
    if (departments[i].allocation >= amountCeiling) throw new Error(`Department ${i + 1} allocation exceeds the ${amountBitLength}-bit band.`);
    if (departments[i].spend >= amountCeiling) throw new Error(`Department ${i + 1} spend exceeds the ${amountBitLength}-bit band.`);
  }
  if (totalAllocated >= amountCeiling) throw new Error(`The aggregate allocation exceeds the ${amountBitLength}-bit band.`);
  if (budgetCap >= amountCeiling) throw new Error(`The budget cap exceeds the ${amountBitLength}-bit band.`);
  if (totalAllocated > budgetCap) throw new Error("The total allocation exceeds the budget cap.");

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();

  const allocationBlindings: bigint[] = [];
  const spendBlindings: bigint[] = [];
  const allocationCommitments: CurvePoint[] = [];
  const spendCommitments: CurvePoint[] = [];
  const labelSalts: bigint[] = [];
  const labelFields: DepartmentLabelField[] = [];
  let totalAllocatedBlinding = 0n;
  let totalSpentBlinding = 0n;
  for (let i = 0; i < departments.length; i += 1) {
    const r = nonZeroScalar(nextScalar());
    const t = nonZeroScalar(nextScalar());
    allocationBlindings.push(r);
    spendBlindings.push(t);
    allocationCommitments.push(pedersenCommit(departments[i].allocation, r, h));
    spendCommitments.push(pedersenCommit(departments[i].spend, t, h));
    totalAllocatedBlinding = mod(totalAllocatedBlinding + r, CURVE_ORDER);
    totalSpentBlinding = mod(totalSpentBlinding + t, CURVE_ORDER);
    const committed = departments[i].label.length > 0;
    const salt = nonZeroScalar(nextScalar());
    labelSalts.push(salt);
    labelFields.push({ commitment: committed ? commitRef(LABEL_DOMAIN, departments[i].label, salt) : 0n, committed });
  }

  const enterpriseRef = input.enterpriseRef ? requireText(input.enterpriseRef, "enterprise reference", 128) : "";
  const enterpriseCommitted = enterpriseRef.length > 0;
  const enterpriseSalt = nonZeroScalar(nextScalar());
  const enterpriseCommitment = enterpriseCommitted ? commitRef(ENTERPRISE_DOMAIN, enterpriseRef, enterpriseSalt) : 0n;

  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());
  const fields: BindingFields = {
    certificateId,
    enterpriseAlias,
    periodLabel,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    budgetCap,
    departmentCount: departments.length,
    amountBitLength,
    enterpriseCommitment,
    enterpriseCommitted,
    createdAt,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, allocationCommitments, spendCommitments, labelFields, h);
  const ctx = statementContext(bindingHash);
  // Range legs. Each hidden allocation and spend is a bounded non-negative
  // integer; the headroom leg (forced blinding r_i − t_i) bounds A_i − S_i so
  // spend ≤ allocation; the aggregate leg (forced blinding Σ r_i) bounds ΣA_i.
  const allocationBits: SubaccountBitProof[][] = [];
  const spendBits: SubaccountBitProof[][] = [];
  const headroomBits: SubaccountBitProof[][] = [];
  for (let i = 0; i < departments.length; i += 1) {
    allocationBits.push(proveRange(departments[i].allocation, allocationBlindings[i], amountBitLength, ctx, ALLOC_LEG_BASE + i, h, nextScalar));
    spendBits.push(proveRange(departments[i].spend, spendBlindings[i], amountBitLength, ctx, SPEND_LEG_BASE + i, h, nextScalar));
    const headroom = departments[i].allocation - departments[i].spend;
    const headroomBlinding = mod(allocationBlindings[i] - spendBlindings[i], CURVE_ORDER);
    headroomBits.push(proveRange(headroom, headroomBlinding, amountBitLength, ctx, HEADROOM_LEG_BASE + i, h, nextScalar));
  }
  const totalAllocBits = proveRange(totalAllocated, totalAllocatedBlinding, amountBitLength, ctx, LEG_TOTAL_ALLOC, h, nextScalar);
  // Budget headroom: (B_cap − Σa_i) tied to B_cap·G − ΣA_i, under −Σr_i ⇒ Σa_i ≤ B_cap.
  const budgetHeadroomBits = proveRange(
    budgetCap - totalAllocated,
    mod(-totalAllocatedBlinding, CURVE_ORDER),
    amountBitLength,
    ctx,
    LEG_BUDGET_HEADROOM,
    h,
    nextScalar,
  );

  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);

  const proof: SubaccountProof = {
    proofSystem: SUBACCOUNT_PROOF_SYSTEM,
    amountBitLength,
    generatorH: pointToFelts(h),
    departments: departments.map((_, i) => ({
      allocationCommitment: pointToFelts(allocationCommitments[i]),
      spendCommitment: pointToFelts(spendCommitments[i]),
      labelCommitment: toHex(labelFields[i].commitment),
      labelCommitted: labelFields[i].committed,
    })),
    allocationBits,
    spendBits,
    headroomBits,
    totalAllocBits,
    budgetHeadroomBits,
  };

  const certificate: SubaccountCertificate = {
    kind: CERTIFICATE_KIND,
    version: SUBACCOUNT_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    enterpriseAlias,
    periodLabel,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    budgetCapBaseUnits: budgetCap.toString(),
    departmentCount: departments.length,
    enterpriseCommitment: toHex(enterpriseCommitment),
    enterpriseCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: SUBACCOUNT_NOTICE,
  };

  const secret: SubaccountCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    labels: departments.map((d) => d.label),
    labelSalts: labelSalts.map(toHex),
    labelsCommitted: labelFields.map((l) => l.committed),
    allocationsBaseUnits: departments.map((d) => d.allocation.toString()),
    allocationBlindings: allocationBlindings.map(toHex),
    spendsBaseUnits: departments.map((d) => d.spend.toString()),
    spendBlindings: spendBlindings.map(toHex),
    totalAllocatedBaseUnits: totalAllocated.toString(),
    totalAllocatedBlinding: toHex(totalAllocatedBlinding),
    totalSpentBaseUnits: totalSpent.toString(),
    totalSpentBlinding: toHex(totalSpentBlinding),
    enterpriseRef,
    enterpriseSalt: toHex(enterpriseSalt),
    enterpriseCommitted,
  };

  return { certificate, secret };
}
/**
 * Verifies a subaccount certificate end to end: the binding hash, the issuer
 * signature, every per-department allocation and spend range leg tied to its
 * commitment, every headroom leg tied to A_i − S_i (so spend ≤ allocation), the
 * aggregate leg tied to ΣA_i, and the budget-headroom leg tied to B_cap·G − ΣA_i
 * (so the allocations fit the public cap). A passing verdict reveals no figure —
 * only that no department overspends and the allocations fit the cap.
 */
export function verifySubaccountCertificate(certificate: SubaccountCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== SUBACCOUNT_PROOF_SYSTEM) return false;
    const amountBitLength = proof.amountBitLength;
    if (
      !Number.isInteger(amountBitLength) ||
      amountBitLength < MIN_SUBACCOUNT_AMOUNT_BIT_LENGTH ||
      amountBitLength > MAX_SUBACCOUNT_AMOUNT_BIT_LENGTH
    )
      return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);

    const departmentCount = certificate.departmentCount;
    if (!Number.isInteger(departmentCount) || departmentCount < MIN_SUBACCOUNT_DEPARTMENTS || departmentCount > MAX_SUBACCOUNT_DEPARTMENTS)
      return false;
    if (!Array.isArray(proof.departments) || proof.departments.length !== departmentCount) return false;
    if (!Array.isArray(proof.allocationBits) || proof.allocationBits.length !== departmentCount) return false;
    if (!Array.isArray(proof.spendBits) || proof.spendBits.length !== departmentCount) return false;
    if (!Array.isArray(proof.headroomBits) || proof.headroomBits.length !== departmentCount) return false;

    const budgetCap = requireBaseUnits(certificate.budgetCapBaseUnits, "budget cap");
    const allocationCommitments = proof.departments.map((d) => pointFromFelts(d.allocationCommitment));
    const spendCommitments = proof.departments.map((d) => pointFromFelts(d.spendCommitment));
    const labelFields: DepartmentLabelField[] = proof.departments.map((d) => ({
      commitment: requireFelt(d.labelCommitment),
      committed: d.labelCommitted === true,
    }));
    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      enterpriseAlias: certificate.enterpriseAlias,
      periodLabel: certificate.periodLabel,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: certificate.assetDecimals,
      budgetCap,
      departmentCount,
      amountBitLength,
      enterpriseCommitment: requireFelt(certificate.enterpriseCommitment),
      enterpriseCommitted: certificate.enterpriseCommitted,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };
    const bindingHash = computeBindingHash(fields, issuerKey, allocationCommitments, spendCommitments, labelFields, h);
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);

    // Per-department legs: each allocation and spend is a bounded non-negative
    // integer, and A_i − S_i is non-negative (spend ≤ allocation). Accumulate ΣA_i.
    let totalCommitment = ZERO;
    for (let i = 0; i < departmentCount; i += 1) {
      const allocSum = verifyRange(proof.allocationBits[i], amountBitLength, ctx, ALLOC_LEG_BASE + i, h);
      if (!allocSum || !allocSum.equals(allocationCommitments[i])) return false;
      const spendSum = verifyRange(proof.spendBits[i], amountBitLength, ctx, SPEND_LEG_BASE + i, h);
      if (!spendSum || !spendSum.equals(spendCommitments[i])) return false;
      const headroomTarget = allocationCommitments[i].add(spendCommitments[i].negate());
      const headroomSum = verifyRange(proof.headroomBits[i], amountBitLength, ctx, HEADROOM_LEG_BASE + i, h);
      if (!headroomSum || !headroomSum.equals(headroomTarget)) return false;
      totalCommitment = totalCommitment.add(allocationCommitments[i]);
    }
    // Aggregate leg: Σa_i ∈ [0, 2^amountBits) tied to ΣA_i (bounds the aggregate).
    const totalSum = verifyRange(proof.totalAllocBits, amountBitLength, ctx, LEG_TOTAL_ALLOC, h);
    if (!totalSum || !totalSum.equals(totalCommitment)) return false;

    // Budget headroom leg: B_cap·G − ΣA_i ∈ [0, 2^amountBits) ⇒ Σa_i ≤ B_cap.
    const budgetTarget = scalePoint(G, budgetCap).add(totalCommitment.negate());
    const budgetSum = verifyRange(proof.budgetHeadroomBits, amountBitLength, ctx, LEG_BUDGET_HEADROOM, h);
    if (!budgetSum || !budgetSum.equals(budgetTarget)) return false;

    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure and full opening
// ---------------------------------------------------------------------------

/** The committed aggregate figure and its blinding, from the secret. */
function aggregateSecret(secret: SubaccountCertificateSecret, metric: SubaccountMetric): { value: string; blinding: string } {
  switch (metric) {
    case "allocated":
      return { value: secret.totalAllocatedBaseUnits, blinding: secret.totalAllocatedBlinding };
    case "spent":
      return { value: secret.totalSpentBaseUnits, blinding: secret.totalSpentBlinding };
    default:
      throw new Error("The subaccount metric is unknown.");
  }
}

/** The published commitment backing a disclosable aggregate — ΣA_i for allocated, ΣS_i for spent. */
function aggregateCommitment(certificate: SubaccountCertificate, metric: SubaccountMetric): CurvePoint {
  const departments = certificate.proof.departments;
  let acc = ZERO;
  if (metric === "allocated") {
    for (const d of departments) acc = acc.add(pointFromFelts(d.allocationCommitment));
    return acc;
  }
  if (metric === "spent") {
    for (const d of departments) acc = acc.add(pointFromFelts(d.spendCommitment));
    return acc;
  }
  throw new Error("The subaccount metric is unknown.");
}

/** Builds a disclosure that opens exactly one aggregate figure (allocated or spent), leaving the rest hidden. */
export function buildSubaccountMetricDisclosure(secret: SubaccountCertificateSecret, metric: SubaccountMetric): SubaccountMetricDisclosure {
  const { value, blinding } = aggregateSecret(secret, metric);
  return { kind: METRIC_DISCLOSURE_KIND, certificateId: secret.certificateId, metric, valueBaseUnits: value, blinding };
}

/** Verifies a single aggregate disclosure against the matching summed commitment in the certificate. */
export function verifySubaccountMetricDisclosure(certificate: SubaccountCertificate, disclosure: SubaccountMetricDisclosure): boolean {
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
/** Builds a disclosure that opens one department's allocation or spend, leaving the rest hidden. */
export function buildSubaccountDepartmentDisclosure(
  secret: SubaccountCertificateSecret,
  departmentIndex: number,
  field: SubaccountMetric,
): SubaccountDepartmentDisclosure {
  if (!Number.isInteger(departmentIndex) || departmentIndex < 0 || departmentIndex >= secret.allocationsBaseUnits.length) {
    throw new Error("The department index is out of range.");
  }
  const value = field === "allocated" ? secret.allocationsBaseUnits[departmentIndex] : field === "spent" ? secret.spendsBaseUnits[departmentIndex] : null;
  const blinding = field === "allocated" ? secret.allocationBlindings[departmentIndex] : field === "spent" ? secret.spendBlindings[departmentIndex] : null;
  if (value === null || blinding === null) throw new Error("The subaccount metric is unknown.");
  return { kind: DEPARTMENT_DISCLOSURE_KIND, certificateId: secret.certificateId, departmentIndex, field, valueBaseUnits: value, blinding };
}

/** Verifies a single-department disclosure against that department's published commitment. */
export function verifySubaccountDepartmentDisclosure(certificate: SubaccountCertificate, disclosure: SubaccountDepartmentDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== DEPARTMENT_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const departments = certificate.proof.departments;
    const index = disclosure.departmentIndex;
    if (!Number.isInteger(index) || index < 0 || index >= departments.length) return false;
    const feltsSource =
      disclosure.field === "allocated"
        ? departments[index].allocationCommitment
        : disclosure.field === "spent"
          ? departments[index].spendCommitment
          : null;
    if (!feltsSource) return false;
    const h = independentGenerator();
    const value = requireBaseUnits(disclosure.valueBaseUnits, "disclosed department figure");
    const blinding = requireScalar(disclosure.blinding, true);
    return pedersenCommit(value, blinding, h).equals(pointFromFelts(feltsSource));
  } catch {
    return false;
  }
}

/** Reveals one department's committed cost-centre label (salt + value) so a verifier can re-derive the commitment. */
export function buildSubaccountLabelDisclosure(secret: SubaccountCertificateSecret, departmentIndex: number): SubaccountLabelDisclosure {
  if (!Number.isInteger(departmentIndex) || departmentIndex < 0 || departmentIndex >= secret.labels.length) {
    throw new Error("The department index is out of range.");
  }
  if (!secret.labelsCommitted[departmentIndex]) throw new Error("This department carries no label commitment to disclose.");
  return {
    kind: LABEL_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    departmentIndex,
    value: secret.labels[departmentIndex],
    salt: secret.labelSalts[departmentIndex],
  };
}

/** Verifies a department-label disclosure against the published salted commitment. */
export function verifySubaccountLabelDisclosure(certificate: SubaccountCertificate, disclosure: SubaccountLabelDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== LABEL_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const departments = certificate.proof.departments;
    const index = disclosure.departmentIndex;
    if (!Number.isInteger(index) || index < 0 || index >= departments.length) return false;
    if (!departments[index].labelCommitted) return false;
    const value = requireText(disclosure.value, "department label", 64);
    const salt = requireScalar(disclosure.salt, true);
    return toHex(commitRef(LABEL_DOMAIN, value, salt)) === departments[index].labelCommitment;
  } catch {
    return false;
  }
}
/** Reveals the committed enterprise reference (salt + value) so a verifier can re-derive the commitment. */
export function buildSubaccountEnterpriseDisclosure(secret: SubaccountCertificateSecret): SubaccountRefDisclosure {
  if (!secret.enterpriseCommitted) throw new Error("This certificate carries no enterprise commitment to disclose.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "enterprise",
    value: secret.enterpriseRef,
    salt: secret.enterpriseSalt,
  };
}

/** Verifies an enterprise-reference disclosure against the published salted commitment. */
export function verifySubaccountRefDisclosure(certificate: SubaccountCertificate, disclosure: SubaccountRefDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND || disclosure.field !== "enterprise") return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    if (!certificate.enterpriseCommitted) return false;
    const value = requireText(disclosure.value, "enterprise reference", 128);
    const salt = requireScalar(disclosure.salt, true);
    return toHex(commitRef(ENTERPRISE_DOMAIN, value, salt)) === certificate.enterpriseCommitment;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Full opening
// ---------------------------------------------------------------------------

/** A full opening the enterprise hands a counterparty to reveal every committed figure at once. */
export function buildSubaccountCertificateOpening(secret: SubaccountCertificateSecret): SubaccountCertificateOpening {
  return {
    allocationsBaseUnits: [...secret.allocationsBaseUnits],
    allocationBlindings: [...secret.allocationBlindings],
    spendsBaseUnits: [...secret.spendsBaseUnits],
    spendBlindings: [...secret.spendBlindings],
    totalAllocatedBaseUnits: secret.totalAllocatedBaseUnits,
    totalAllocatedBlinding: secret.totalAllocatedBlinding,
    totalSpentBaseUnits: secret.totalSpentBaseUnits,
    totalSpentBlinding: secret.totalSpentBlinding,
  };
}

/**
 * Verifies a full opening: every allocation opens A_i, every spend opens S_i,
 * each department's disclosed spend is at most its disclosed allocation, the
 * disclosed figures sum to the disclosed aggregates, the aggregates open ΣA_i and
 * ΣS_i, and the aggregate allocation is at most the certificate's public budget
 * cap. Reveals every figure — use it only with a trusted counterparty.
 */
export function verifySubaccountCertificateOpening(certificate: SubaccountCertificate, opening: SubaccountCertificateOpening): boolean {
  try {
    if (!opening || typeof opening !== "object") return false;
    const departments = certificate.proof.departments;
    const count = departments.length;
    if (!Array.isArray(opening.allocationsBaseUnits) || opening.allocationsBaseUnits.length !== count) return false;
    if (!Array.isArray(opening.allocationBlindings) || opening.allocationBlindings.length !== count) return false;
    if (!Array.isArray(opening.spendsBaseUnits) || opening.spendsBaseUnits.length !== count) return false;
    if (!Array.isArray(opening.spendBlindings) || opening.spendBlindings.length !== count) return false;
    const h = independentGenerator();

    let totalAllocated = 0n;
    let totalSpent = 0n;
    let allocAcc = ZERO;
    let spendAcc = ZERO;
    for (let i = 0; i < count; i += 1) {
      const allocation = requireBaseUnits(opening.allocationsBaseUnits[i], `department ${i + 1} allocation`);
      const allocationBlinding = requireScalar(opening.allocationBlindings[i], true);
      if (!pedersenCommit(allocation, allocationBlinding, h).equals(pointFromFelts(departments[i].allocationCommitment))) return false;
      const spend = requireBaseUnits(opening.spendsBaseUnits[i], `department ${i + 1} spend`);
      const spendBlinding = requireScalar(opening.spendBlindings[i], true);
      if (!pedersenCommit(spend, spendBlinding, h).equals(pointFromFelts(departments[i].spendCommitment))) return false;
      if (spend > allocation) return false;
      totalAllocated += allocation;
      totalSpent += spend;
      allocAcc = allocAcc.add(pointFromFelts(departments[i].allocationCommitment));
      spendAcc = spendAcc.add(pointFromFelts(departments[i].spendCommitment));
    }

    const disclosedAllocated = requireBaseUnits(opening.totalAllocatedBaseUnits, "aggregate allocation");
    if (disclosedAllocated !== totalAllocated) return false;
    const totalAllocatedBlinding = requireScalar(opening.totalAllocatedBlinding, true);
    if (!pedersenCommit(totalAllocated, totalAllocatedBlinding, h).equals(allocAcc)) return false;

    const disclosedSpent = requireBaseUnits(opening.totalSpentBaseUnits, "aggregate spend");
    if (disclosedSpent !== totalSpent) return false;
    const totalSpentBlinding = requireScalar(opening.totalSpentBlinding, true);
    if (!pedersenCommit(totalSpent, totalSpentBlinding, h).equals(spendAcc)) return false;

    const budgetCap = requireBaseUnits(certificate.budgetCapBaseUnits, "budget cap");
    if (totalAllocated > budgetCap) return false;
    return true;
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Presentation helpers: badge, trust model, visibility model
// ---------------------------------------------------------------------------

/** A compact, display-only summary card of a certificate's public claims. */
export function buildSubaccountCertificateBadge(certificate: SubaccountCertificate): SubaccountCertificateBadge {
  const decimals = certificate.assetDecimals;
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    enterpriseAlias: certificate.enterpriseAlias,
    periodLabel: certificate.periodLabel,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    departmentCount: certificate.departmentCount,
    budgetCapDisplay: `${formatSubaccountBaseUnits(certificate.budgetCapBaseUnits, decimals)} ${certificate.assetSymbol}`,
    enterpriseCommitted: certificate.enterpriseCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}

/** An honest, machine-readable statement of exactly what a passing verdict does and does not establish. */
export function summarizeSubaccountTrust(): SubaccountTrustModel {
  return {
    isZeroKnowledge: true,
    provesAllocationsFitBudgetCap: true,
    provesNoDepartmentOverspends: true,
    provesEveryFigureNonNegative: true,
    hidesDepartmentAllocations: true,
    hidesDepartmentSpends: true,
    hidesAggregateAllocated: true,
    hidesAggregateSpent: true,
    hidesCostCentreLabels: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    movesOrAllocatesFunds: false,
    createsOrFundsSubAccounts: false,
    enforcesSpendingConstraints: false,
    reducesGas: false,
    movesPoolFunds: false,
    verifiesFiguresAreReal: false,
    isDecentralized: false,
    isAutomatic: false,
    isBudgetGuaranteeOrFinancialAdvice: false,
    zeroKnowledgeElement:
      "Per-bit Schnorr one-of-two proofs with Fiat–Shamir over Pedersen commitments on the Stark curve. Each department's headroom is proven from the homomorphic point A_i − S_i, and the homomorphic sum of the allocation commitments is compared to B_cap·G, so no-overspend and the budget cap are proven without opening any allocation, spend, label, or aggregate.",
    statement:
      "A passing verdict proves an issuer-signed claim that hidden departmental allocations aggregate into a total that does not exceed a public budget cap, and that every department's hidden spend is at most its own hidden allocation. It does NOT move, allocate, disburse, or settle any funds, create or fund any sub-account or balance, enforce any spending constraint, reduce gas, or read or write the STRK20 pool, and it cannot confirm the committed figures reflect real balances or payments. It is neither decentralized nor automatic, and is not a budgeting guarantee or financial advice.",
  };
}

/** The hidden / disclosed / application-only split, for honest UI copy. */
export function getSubaccountVisibilityModel(): SubaccountVisibilityModel {
  return {
    hiddenFromVerifier: [
      "Each department's budget allocation",
      "Each department's spend to date",
      "The aggregate allocated and the aggregate spent across all departments",
      "Every cost-centre label (only a salted commitment is published)",
      "Every Pedersen blinding factor",
      "The enterprise / entity reference (only a salted commitment is published)",
    ],
    disclosedToVerifier: [
      "The public budget cap the allocations were proven to fit under",
      "The number of departments partitioned (a count, never an amount)",
      "That no department overspends its allocation, and the allocations fit the cap",
      "The issuer public key, the binding hash, and the proof bundle",
    ],
    applicationOnly: [
      "Per-department headroom and utilization, and the unallocated budget headroom",
      "Any decimal formatting or fiat estimate rendered in the interface",
    ],
    limitation:
      "The edges are trust assumptions, not proofs: the certificate binds enterprise-supplied figures and cannot confirm any balance or payment exists on-chain, nothing here moves funds, creates a sub-account, or enforces a spend limit, and a single issuer key vouches for the inputs. Distinctive budget caps or timing can still correlate an enterprise with public activity.",
  };
}
// ---------------------------------------------------------------------------
// Serialization (base64url-wrapped JSON)
// ---------------------------------------------------------------------------

/** Serializes a public certificate to a portable base64url token. */
export function serializeSubaccountCertificate(certificate: SubaccountCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

/** Parses a certificate token, checking its kind. Throws on a malformed or foreign token. */
export function parseSubaccountCertificate(encoded: string): SubaccountCertificate {
  const parsed = decodeJson(fromBase64Url(encoded)) as SubaccountCertificate;
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("The encoded value is not a subaccount certificate.");
  return parsed;
}

/** Serializes the SECRET issuer record. Never publish the result. */
export function serializeSubaccountCertificateSecret(secret: SubaccountCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseSubaccountCertificateSecret(encoded: string): SubaccountCertificateSecret {
  const parsed = decodeJson(fromBase64Url(encoded)) as SubaccountCertificateSecret;
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("The encoded value is not a subaccount certificate secret.");
  return parsed;
}

export function serializeSubaccountMetricDisclosure(disclosure: SubaccountMetricDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseSubaccountMetricDisclosure(encoded: string): SubaccountMetricDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as SubaccountMetricDisclosure;
  if (!parsed || parsed.kind !== METRIC_DISCLOSURE_KIND) throw new Error("The encoded value is not a subaccount metric disclosure.");
  return parsed;
}

export function serializeSubaccountDepartmentDisclosure(disclosure: SubaccountDepartmentDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseSubaccountDepartmentDisclosure(encoded: string): SubaccountDepartmentDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as SubaccountDepartmentDisclosure;
  if (!parsed || parsed.kind !== DEPARTMENT_DISCLOSURE_KIND) throw new Error("The encoded value is not a subaccount department disclosure.");
  return parsed;
}

export function serializeSubaccountLabelDisclosure(disclosure: SubaccountLabelDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseSubaccountLabelDisclosure(encoded: string): SubaccountLabelDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as SubaccountLabelDisclosure;
  if (!parsed || parsed.kind !== LABEL_DISCLOSURE_KIND) throw new Error("The encoded value is not a subaccount label disclosure.");
  return parsed;
}

export function serializeSubaccountRefDisclosure(disclosure: SubaccountRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseSubaccountRefDisclosure(encoded: string): SubaccountRefDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as SubaccountRefDisclosure;
  if (!parsed || parsed.kind !== REF_DISCLOSURE_KIND) throw new Error("The encoded value is not a subaccount reference disclosure.");
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
  return `subacct_${kind}_${acc.toString(16).slice(0, 24)}`;
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


















