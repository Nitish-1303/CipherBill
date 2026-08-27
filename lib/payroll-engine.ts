/**
 * CipherBill — Zero-Knowledge Batch Payroll & Contractor Payout Engine
 *
 * Client-side module for enterprises to attest encrypted salary and milestone
 * batches with Pedersen commitments and range proofs while hiding payee identities,
 * line amounts, and departmental totals from public observers.
 *
 * STRK20_POOL_ADDRESS is provenance only — this module never calls the pool.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const PAYROLL_ENGINE_VERSION = 1 as const;
export const PAYROLL_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const PAYROLL_PROOF_SYSTEM = "stark-pedersen-payroll-batch-v1" as const;
export const BPS_SCALE = 10_000n;
export const MAX_PAYEE_COUNT = 4;
export const MIN_PAYEE_COUNT = 1;
export const DEFAULT_AMOUNT_BIT_LENGTH = 96;
export const MIN_AMOUNT_BIT_LENGTH = 16;
export const MAX_AMOUNT_BIT_LENGTH = 128;
export const SURPLUS_EXTRA_BITS = 16;
export const MAX_CONTRACTOR_SHARE_BPS = 10_000;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD = ec.starkCurve.CURVE.Fp;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
const MAX_ENCODED_LENGTH = 1_600_000;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill payroll generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill payroll statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill payroll bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill payroll binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill payroll issuer signature v1");
const EMPLOYEE_DOMAIN = hash.starknetKeccak("CipherBill payroll employee ref v1");
const DEPARTMENT_DOMAIN = hash.starknetKeccak("CipherBill payroll department v1");

const CERTIFICATE_KIND = "cipherbill.payroll-batch-certificate" as const;
const SECRET_KIND = "cipherbill.payroll-batch-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.payroll-amount-disclosure" as const;
const EMPLOYEE_DISCLOSURE_KIND = "cipherbill.payroll-employee-disclosure" as const;
const KEYPAIR_KIND = "cipherbill.payroll-keypair" as const;

type CurvePoint = ReturnType<typeof G.multiply>;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface PayrollEntropy {
  createId?: (kind: "batch") => string;
  randomScalar?: () => bigint;
}

export interface PayrollKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface PayrollAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

/** PUBLIC payroll policy caps — amounts are base units of the asset. */
export interface PayrollPolicy {
  maxPayeeAmountBaseUnits: string;
  maxBatchTotalBaseUnits: string;
  maxContractorShareBps: number;
}

export interface PayrollSchedule {
  payPeriodLabel: string;
  disbursementDate: string;
}

export type PayeeKind = "employee" | "contractor";

export interface PayrollPayeeInput {
  employeeRef: string;
  amountBaseUnits: string | bigint;
  payeeKind: PayeeKind;
}

export interface PayrollBatchState {
  payeeCount: number;
  totalBaseUnits: string;
  contractorTotalBaseUnits: string;
  contractorShareBps: string;
  batchSurplus: string;
  contractorSurplus: string;
  eligible: boolean;
}

export interface PayrollCommitmentBundle {
  lineCommitments: CurvePointFelts[];
  totalBatchCommitment: CurvePointFelts;
  payeeCount: number;
}

export interface PayrollBitProof {
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

export interface PayrollProof {
  proofSystem: typeof PAYROLL_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  generatorH: CurvePointFelts;
  lineCommitments: CurvePointFelts[];
  totalBatchCommitment: CurvePointFelts;
  lineBits: PayrollBitProof[][];
  totalBits: PayrollBitProof[];
  batchSurplusBits: PayrollBitProof[];
  contractorSurplusBits: PayrollBitProof[];
  issuerSignature: IssuerSignature;
}

export interface PayrollBatchCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof PAYROLL_ENGINE_VERSION;
  certificateId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  organizationAlias: string;
  departmentLabel: string;
  departmentCommitment: string;
  asset: PayrollAsset;
  schedule: PayrollSchedule;
  payeeCount: number;
  policy: PayrollPolicy;
  employeeCommitments: string[];
  issuerPublicKey: CurvePointFelts;
  proof: PayrollProof;
  notice: string;
  limitations: readonly string[];
}

export interface PayrollPayeeSecret {
  employeeRef: string;
  payeeKind: PayeeKind;
  amountBaseUnits: string;
  employeeSalt: string;
  amountBlinding: string;
}

export interface PayrollBatchSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  payees: PayrollPayeeSecret[];
  totalBaseUnits: string;
  totalBlinding: string;
  departmentRef: string;
  departmentSalt: string;
  batchSurplusBlinding: string;
  contractorSurplusBlinding: string;
}

export interface IssuedPayrollBatchCertificate {
  certificate: PayrollBatchCertificate;
  secret: PayrollBatchSecret;
}

export interface IssuePayrollBatchCertificateInput {
  organizationAlias: string;
  departmentLabel: string;
  departmentRef?: string;
  asset: PayrollAsset;
  schedule: PayrollSchedule;
  policy: PayrollPolicy;
  payees: PayrollPayeeInput[];
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

export interface PayrollAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  payeeIndex: number;
  value: string;
  blinding: string;
  proof: PayrollBitProof[];
}

export interface PayrollEmployeeDisclosure {
  kind: typeof EMPLOYEE_DISCLOSURE_KIND;
  certificateId: string;
  payeeIndex: number;
  employeeRef: string;
  payeeKind: PayeeKind;
  employeeSalt: string;
}

export interface PayrollMonitorRow {
  payeeIndex: number;
  employeeLabel: string;
  payeeKind: PayeeKind;
  amountDisplay: string;
  disbursementDate: string;
  status: "scheduled" | "ready" | "over-cap";
}

export interface PayrollTrustSummary {
  decentralized: boolean;
  zeroKnowledge: boolean;
  poolIntegrated: boolean;
  automated: boolean;
  statement: string;
}

export interface PayrollVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

export const PAYROLL_NOTICE =
  "Zero-knowledge batch payroll attestation over hidden payee lines and salted employee references. " +
  "Public schedule, policy caps, and payee count only — STRK20 pool address is provenance and never called.";

export const PAYROLL_LIMITATIONS: readonly string[] = [
  "Payroll lines and amounts are enterprise-supplied inputs — no bank feed, tax authority, or on-chain payroll contract validates them.",
  "The certificate proves arithmetic against public policy; it does not execute transfers in the STRK20 pool.",
  "Disbursement monitor rows are local schedule heuristics — not payroll advice or a live banking integration.",
  "Distinctive batch timing or round amounts can correlate activity despite hidden line values.",
];

let cachedGenerator: CurvePoint | null = null;

function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

export function derivePayrollGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent payroll generator.");
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
  return `pay_${kind}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
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

function commitEmployee(ref: string, salt: bigint): bigint {
  return hashElements([EMPLOYEE_DOMAIN, hash.starknetKeccak(ref), salt]);
}

function commitDepartment(label: string, ref: string, salt: bigint): bigint {
  return hashElements([DEPARTMENT_DOMAIN, hash.starknetKeccak(label), hash.starknetKeccak(ref), salt]);
}

function padPayees(payees: PayrollPayeeInput[]): PayrollPayeeInput[] {
  if (payees.length < MIN_PAYEE_COUNT || payees.length > MAX_PAYEE_COUNT) {
    throw new Error(`Payee count must be between ${MIN_PAYEE_COUNT} and ${MAX_PAYEE_COUNT}.`);
  }
  const padded = [...payees];
  while (padded.length < MAX_PAYEE_COUNT) {
    padded.push({ employeeRef: "", amountBaseUnits: 0n, payeeKind: "employee" });
  }
  return padded;
}

export function createPayrollIssuerKey(entropy: PayrollEntropy = {}): PayrollKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

export function requirePayrollPolicy(policy: PayrollPolicy): PayrollPolicy {
  if (!policy || typeof policy !== "object") throw new Error("The payroll policy is required.");
  const maxPayeeAmountBaseUnits = requireBaseUnits(policy.maxPayeeAmountBaseUnits, "maximum payee amount").toString();
  const maxBatchTotalBaseUnits = requireBaseUnits(policy.maxBatchTotalBaseUnits, "maximum batch total").toString();
  const maxContractorShareBps = requireInt(policy.maxContractorShareBps, "maximum contractor share bps", 0, MAX_CONTRACTOR_SHARE_BPS);
  return { maxPayeeAmountBaseUnits, maxBatchTotalBaseUnits, maxContractorShareBps };
}

export function computePayrollBatchState(payees: PayrollPayeeInput[], policy: PayrollPolicy): PayrollBatchState {
  const parsedPolicy = requirePayrollPolicy(policy);
  const maxPayee = requireBaseUnits(parsedPolicy.maxPayeeAmountBaseUnits, "maximum payee amount");
  const maxBatch = requireBaseUnits(parsedPolicy.maxBatchTotalBaseUnits, "maximum batch total");
  const maxContractorShare = BigInt(parsedPolicy.maxContractorShareBps);
  if (payees.length < MIN_PAYEE_COUNT || payees.length > MAX_PAYEE_COUNT) {
    throw new Error(`Payee count must be between ${MIN_PAYEE_COUNT} and ${MAX_PAYEE_COUNT}.`);
  }

  let total = 0n;
  let contractorTotal = 0n;
  for (const payee of payees) {
    const amount = requireBaseUnits(payee.amountBaseUnits, "payee amount");
    requireText(payee.employeeRef, "employee reference", 96);
    if (amount > maxPayee) throw new Error("A payee amount exceeds the public per-line cap.");
    total += amount;
    if (payee.payeeKind === "contractor") contractorTotal += amount;
  }

  const contractorShareBps = total === 0n ? 0n : (contractorTotal * BPS_SCALE) / total;
  const batchSurplus = maxBatch - total;
  const contractorSurplus = maxContractorShare * total - BPS_SCALE * contractorTotal;
  const eligible = batchSurplus >= 0n && contractorSurplus >= 0n;

  return {
    payeeCount: payees.length,
    totalBaseUnits: total.toString(),
    contractorTotalBaseUnits: contractorTotal.toString(),
    contractorShareBps: contractorShareBps.toString(),
    batchSurplus: batchSurplus.toString(),
    contractorSurplus: contractorSurplus.toString(),
    eligible,
  };
}

export function buildPayrollBatchCommitments(
  payees: PayrollPayeeInput[],
  h: CurvePoint,
  blindings: bigint[],
): PayrollCommitmentBundle {
  const padded = padPayees(payees);
  const lineCommitments = padded.map((payee, i) => {
    const amount = requireBaseUnits(payee.amountBaseUnits, "payee amount");
    return pointToFelts(pedersenCommit(amount, blindings[i], h));
  });
  const totalPoint = lineCommitments.reduce((acc, _, i) => acc.add(pointFromFelts(lineCommitments[i])), ZERO);
  return { lineCommitments, totalBatchCommitment: pointToFelts(totalPoint), payeeCount: payees.length };
}

export function computePayoutSchedule(
  payees: PayrollPayeeInput[],
  schedule: PayrollSchedule,
  assetDecimals: number,
  now: Date = new Date(),
): PayrollMonitorRow[] {
  const disbursementDate = requireIsoTimestamp(schedule.disbursementDate);
  const ready = Date.parse(disbursementDate) <= now.getTime();
  return payees.map((payee, payeeIndex) => ({
    payeeIndex,
    employeeLabel: payee.employeeRef ? `${payee.employeeRef.slice(0, 2)}***` : "hidden",
    payeeKind: payee.payeeKind,
    amountDisplay: formatPayrollBaseUnits(payee.amountBaseUnits, assetDecimals),
    disbursementDate,
    status: ready ? "ready" : "scheduled",
  }));
}

export function formatPayrollBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(typeof baseUnits === "bigint" ? baseUnits.toString() : baseUnits, decimals);
}

export function summarizePayrollTrust(): PayrollTrustSummary {
  return {
    decentralized: false,
    zeroKnowledge: true,
    poolIntegrated: false,
    automated: false,
    statement:
      "Client-side Pedersen batch commitments and range proofs over merchant-supplied payroll lines. " +
      "No pool contract integration or autonomous disbursement.",
  };
}

export function getPayrollVisibilityModel(): PayrollVisibilityModel {
  return {
    hiddenFromVerifier: [
      "Individual payee amounts and salted employee references",
      "Departmental payroll total and contractor line split",
      "Plaintext employee aliases until selectively disclosed",
    ],
    disclosedToVerifier: [
      "Organization alias, pay period label, and disbursement date",
      "Public policy caps (max payee amount, max batch total, max contractor share bps)",
      "Payee count and issuer public key",
    ],
    applicationOnly: ["Issuer secret key and blinding factors", "Full payee roster with amounts"],
    limitation: PAYROLL_LIMITATIONS.join(" "),
  };
}

interface BindingFields {
  certificateId: string;
  organizationAlias: string;
  departmentLabel: string;
  departmentCommitment: bigint;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  payPeriodLabel: string;
  disbursementDate: string;
  payeeCount: bigint;
  maxPayeeAmount: bigint;
  maxBatchTotal: bigint;
  maxContractorShareBps: bigint;
  amountBitLength: number;
  surplusBitLength: number;
  memo: string;
}

function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  lineCommitments: CurvePoint[],
  totalBatchCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(PAYROLL_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.organizationAlias),
    hash.starknetKeccak(fields.departmentLabel),
    fields.departmentCommitment,
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    hash.starknetKeccak(fields.payPeriodLabel),
    hash.starknetKeccak(fields.disbursementDate),
    fields.payeeCount,
    fields.maxPayeeAmount,
    fields.maxBatchTotal,
    fields.maxContractorShareBps,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    ...lineCommitments.flatMap((p) => [p.x, p.y]),
    totalBatchCommitment.x,
    totalBatchCommitment.y,
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
): PayrollBitProof {
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

function verifyBit(proof: PayrollBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
): PayrollBitProof[] {
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

function verifyRange(proofs: PayrollBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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

export function issuePayrollBatchCertificate(
  input: IssuePayrollBatchCertificateInput,
  now: Date = new Date(),
  entropy: PayrollEntropy = {},
): IssuedPayrollBatchCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;
  const policy = requirePayrollPolicy(input.policy);
  const organizationAlias = requireText(input.organizationAlias, "organization alias", 96);
  const departmentLabel = requireText(input.departmentLabel, "department label", 96);
  const departmentRef = input.departmentRef ? requireText(input.departmentRef, "department reference", 96) : departmentLabel;
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const payPeriodLabel = requireText(input.schedule?.payPeriodLabel, "pay period label", 32);
  const disbursementDate = requireIsoTimestamp(input.schedule?.disbursementDate);
  const amountBitLength = requireInt(input.amountBitLength ?? DEFAULT_AMOUNT_BIT_LENGTH, "amount bit length", MIN_AMOUNT_BIT_LENGTH, MAX_AMOUNT_BIT_LENGTH);
  const surplusBitLength = amountBitLength + SURPLUS_EXTRA_BITS;
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const state = computePayrollBatchState(input.payees, policy);
  if (!state.eligible) throw new Error("Policy surpluses are negative; no honest certificate exists.");

  const padded = padPayees(input.payees);
  const amounts = padded.map((p) => requireBaseUnits(p.amountBaseUnits, "payee amount"));
  const total = amounts.reduce((acc, v) => acc + v, 0n);
  const band = 1n << BigInt(amountBitLength);
  if (total >= band) throw new Error(`Batch total exceeds the ${amountBitLength}-bit band.`);
  for (const amount of amounts) {
    if (amount >= band) throw new Error(`A payee amount exceeds the ${amountBitLength}-bit band.`);
  }

  const batchSurplus = BigInt(state.batchSurplus);
  const contractorSurplus = BigInt(state.contractorSurplus);
  if (batchSurplus >= 1n << BigInt(surplusBitLength) || contractorSurplus >= 1n << BigInt(surplusBitLength)) {
    throw new Error("A surplus exceeds the surplus bit band.");
  }

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();
  const amountBlindings = amounts.map(() => nonZeroScalar(nextScalar()));
  const totalBlinding = amountBlindings.reduce((acc, r) => mod(acc + r, CURVE_ORDER), 0n);
  const batchSurplusBlinding = nonZeroScalar(nextScalar());
  const contractorSurplusBlinding = nonZeroScalar(nextScalar());

  const bundle = buildPayrollBatchCommitments(input.payees, h, amountBlindings);
  const linePoints = bundle.lineCommitments.map(pointFromFelts);
  const totalPoint = pointFromFelts(bundle.totalBatchCommitment);
  const totalCommitment = pedersenCommit(total, totalBlinding, h);
  if (!totalPoint.equals(totalCommitment)) throw new Error("Batch total commitment mismatch.");

  const departmentSalt = nonZeroScalar(nextScalar());
  const departmentCommitment = commitDepartment(departmentLabel, departmentRef, departmentSalt);
  const employeeSalts = padded.map((payee) => (payee.employeeRef ? nonZeroScalar(nextScalar()) : 0n));
  const employeeCommitments = padded.map((payee, i) => (payee.employeeRef ? commitEmployee(payee.employeeRef, employeeSalts[i]) : 0n));

  const certificateId = createId("batch");
  const fields: BindingFields = {
    certificateId,
    organizationAlias,
    departmentLabel,
    departmentCommitment,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    payPeriodLabel,
    disbursementDate,
    payeeCount: BigInt(state.payeeCount),
    maxPayeeAmount: requireBaseUnits(policy.maxPayeeAmountBaseUnits, "maximum payee amount"),
    maxBatchTotal: requireBaseUnits(policy.maxBatchTotalBaseUnits, "maximum batch total"),
    maxContractorShareBps: BigInt(policy.maxContractorShareBps),
    amountBitLength,
    surplusBitLength,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, linePoints, totalPoint, h);
  const ctx = statementContext(bindingHash);

  const lineBits = amounts.map((amount, i) => proveRange(amount, amountBlindings[i], amountBitLength, ctx, i, h, nextScalar));
  const totalBits = proveRange(total, totalBlinding, amountBitLength, ctx, MAX_PAYEE_COUNT, h, nextScalar);
  const batchSurplusBits = proveRange(batchSurplus, batchSurplusBlinding, surplusBitLength, ctx, MAX_PAYEE_COUNT + 1, h, nextScalar);
  const contractorSurplusBits = proveRange(contractorSurplus, contractorSurplusBlinding, surplusBitLength, ctx, MAX_PAYEE_COUNT + 2, h, nextScalar);

  const proof: PayrollProof = {
    proofSystem: PAYROLL_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    generatorH: pointToFelts(h),
    lineCommitments: bundle.lineCommitments,
    totalBatchCommitment: bundle.totalBatchCommitment,
    lineBits,
    totalBits,
    batchSurplusBits,
    contractorSurplusBits,
    issuerSignature: signBinding(bindingHash, issuerSecret, nextScalar),
  };

  const certificate: PayrollBatchCertificate = {
    kind: CERTIFICATE_KIND,
    version: PAYROLL_ENGINE_VERSION,
    certificateId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    organizationAlias,
    departmentLabel,
    departmentCommitment: toHex(departmentCommitment),
    asset: { symbol: assetSymbol, tokenAddress, decimals: assetDecimals },
    schedule: { payPeriodLabel, disbursementDate },
    payeeCount: state.payeeCount,
    policy,
    employeeCommitments: employeeCommitments.map(toHex),
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    notice: PAYROLL_NOTICE,
    limitations: PAYROLL_LIMITATIONS,
  };

  const secret: PayrollBatchSecret = {
    kind: SECRET_KIND,
    certificateId,
    payees: input.payees.map((payee, i) => ({
      employeeRef: payee.employeeRef,
      payeeKind: payee.payeeKind,
      amountBaseUnits: requireBaseUnits(payee.amountBaseUnits, "payee amount").toString(),
      employeeSalt: toHex(employeeSalts[i]),
      amountBlinding: toHex(amountBlindings[i]),
    })),
    totalBaseUnits: total.toString(),
    totalBlinding: toHex(totalBlinding),
    departmentRef,
    departmentSalt: toHex(departmentSalt),
    batchSurplusBlinding: toHex(batchSurplusBlinding),
    contractorSurplusBlinding: toHex(contractorSurplusBlinding),
  };

  void now;
  return { certificate, secret };
}

export function verifyPayrollBatchCertificate(certificate: PayrollBatchCertificate): boolean {
  try {
    validateCertificateShape(certificate);
    const h = pointFromFelts(certificate.proof.generatorH);
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const linePoints = certificate.proof.lineCommitments.map(pointFromFelts);
    const totalPoint = pointFromFelts(certificate.proof.totalBatchCommitment);
    const recomputedTotal = linePoints.reduce((acc, point) => acc.add(point), ZERO);
    if (!recomputedTotal.equals(totalPoint)) return false;

    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      organizationAlias: certificate.organizationAlias,
      departmentLabel: certificate.departmentLabel,
      departmentCommitment: BigInt(certificate.departmentCommitment),
      assetSymbol: certificate.asset.symbol,
      tokenAddress: certificate.asset.tokenAddress,
      assetDecimals: certificate.asset.decimals,
      payPeriodLabel: certificate.schedule.payPeriodLabel,
      disbursementDate: certificate.schedule.disbursementDate,
      payeeCount: BigInt(certificate.payeeCount),
      maxPayeeAmount: requireBaseUnits(certificate.policy.maxPayeeAmountBaseUnits, "maximum payee amount"),
      maxBatchTotal: requireBaseUnits(certificate.policy.maxBatchTotalBaseUnits, "maximum batch total"),
      maxContractorShareBps: BigInt(certificate.policy.maxContractorShareBps),
      amountBitLength: certificate.proof.amountBitLength,
      surplusBitLength: certificate.proof.surplusBitLength,
      memo: "-",
    };
    const bindingHash = computeBindingHash(fields, issuerKey, linePoints, totalPoint, h);
    const ctx = statementContext(bindingHash);
    const { amountBitLength, surplusBitLength } = certificate.proof;

    for (let i = 0; i < MAX_PAYEE_COUNT; i += 1) {
      const opened = verifyRange(certificate.proof.lineBits[i], amountBitLength, ctx, i, h);
      if (!opened?.equals(linePoints[i])) return false;
    }
    if (!verifyRange(certificate.proof.totalBits, amountBitLength, ctx, MAX_PAYEE_COUNT, h)?.equals(totalPoint)) return false;
    if (!verifyRange(certificate.proof.batchSurplusBits, surplusBitLength, ctx, MAX_PAYEE_COUNT + 1, h)) return false;
    if (!verifyRange(certificate.proof.contractorSurplusBits, surplusBitLength, ctx, MAX_PAYEE_COUNT + 2, h)) return false;
    return verifySignature(certificate.proof.issuerSignature, bindingHash, issuerKey);
  } catch {
    return false;
  }
}

function validateCertificateShape(value: unknown): asserts value is PayrollBatchCertificate {
  if (!value || typeof value !== "object") throw new Error("Certificate is required.");
  const cert = value as PayrollBatchCertificate;
  if (cert.kind !== CERTIFICATE_KIND || cert.version !== PAYROLL_ENGINE_VERSION) throw new Error("Certificate kind or version mismatch.");
  if (cert.poolAddress.toLowerCase() !== STRK20_POOL_ADDRESS.toLowerCase()) throw new Error("Pool address mismatch.");
  if (cert.proof.proofSystem !== PAYROLL_PROOF_SYSTEM) throw new Error("Proof system mismatch.");
}

export function serializePayrollBatchCertificate(certificate: PayrollBatchCertificate): string {
  const json = JSON.stringify(certificate);
  if (json.length > MAX_ENCODED_LENGTH) throw new Error("Certificate exceeds maximum encoded length.");
  return json;
}

export function parsePayrollBatchCertificate(serialized: string): PayrollBatchCertificate {
  if (serialized.length > MAX_ENCODED_LENGTH) throw new Error("Certificate exceeds maximum encoded length.");
  const parsed = JSON.parse(serialized) as PayrollBatchCertificate;
  validateCertificateShape(parsed);
  return parsed;
}

export function serializePayrollBatchSecret(secret: PayrollBatchSecret): string {
  return JSON.stringify(secret);
}

export function buildPayrollAmountDisclosure(
  certificate: PayrollBatchCertificate,
  secret: PayrollBatchSecret,
  payeeIndex: number,
): PayrollAmountDisclosure {
  if (payeeIndex < 0 || payeeIndex >= secret.payees.length) throw new Error("Payee index is out of range.");
  const payee = secret.payees[payeeIndex];
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: certificate.certificateId,
    payeeIndex,
    value: payee.amountBaseUnits,
    blinding: payee.amountBlinding,
    proof: certificate.proof.lineBits[payeeIndex],
  };
}

export function verifyPayrollAmountDisclosure(disclosure: PayrollAmountDisclosure, certificate: PayrollBatchCertificate): boolean {
  try {
    if (disclosure.kind !== AMOUNT_DISCLOSURE_KIND || disclosure.certificateId !== certificate.certificateId) return false;
    const h = pointFromFelts(certificate.proof.generatorH);
    const bindingHash = computeBindingHashFromCertificate(certificate);
    const ctx = statementContext(bindingHash);
    const opened = verifyRange(disclosure.proof, certificate.proof.amountBitLength, ctx, disclosure.payeeIndex, h);
    return opened?.equals(pointFromFelts(certificate.proof.lineCommitments[disclosure.payeeIndex])) ?? false;
  } catch {
    return false;
  }
}

export function buildPayrollEmployeeDisclosure(
  certificate: PayrollBatchCertificate,
  secret: PayrollBatchSecret,
  payeeIndex: number,
): PayrollEmployeeDisclosure {
  if (payeeIndex < 0 || payeeIndex >= secret.payees.length) throw new Error("Payee index is out of range.");
  const payee = secret.payees[payeeIndex];
  return {
    kind: EMPLOYEE_DISCLOSURE_KIND,
    certificateId: certificate.certificateId,
    payeeIndex,
    employeeRef: payee.employeeRef,
    payeeKind: payee.payeeKind,
    employeeSalt: payee.employeeSalt,
  };
}

export function verifyPayrollEmployeeDisclosure(disclosure: PayrollEmployeeDisclosure, certificate: PayrollBatchCertificate): boolean {
  if (disclosure.kind !== EMPLOYEE_DISCLOSURE_KIND || disclosure.certificateId !== certificate.certificateId) return false;
  const expected = commitEmployee(disclosure.employeeRef, requireScalar(disclosure.employeeSalt, false));
  return toHex(expected) === certificate.employeeCommitments[disclosure.payeeIndex];
}

function computeBindingHashFromCertificate(certificate: PayrollBatchCertificate): bigint {
  const h = pointFromFelts(certificate.proof.generatorH);
  const issuerKey = pointFromFelts(certificate.issuerPublicKey);
  const linePoints = certificate.proof.lineCommitments.map(pointFromFelts);
  const totalPoint = pointFromFelts(certificate.proof.totalBatchCommitment);
  const fields: BindingFields = {
    certificateId: certificate.certificateId,
    organizationAlias: certificate.organizationAlias,
    departmentLabel: certificate.departmentLabel,
    departmentCommitment: BigInt(certificate.departmentCommitment),
    assetSymbol: certificate.asset.symbol,
    tokenAddress: certificate.asset.tokenAddress,
    assetDecimals: certificate.asset.decimals,
    payPeriodLabel: certificate.schedule.payPeriodLabel,
    disbursementDate: certificate.schedule.disbursementDate,
    payeeCount: BigInt(certificate.payeeCount),
    maxPayeeAmount: requireBaseUnits(certificate.policy.maxPayeeAmountBaseUnits, "maximum payee amount"),
    maxBatchTotal: requireBaseUnits(certificate.policy.maxBatchTotalBaseUnits, "maximum batch total"),
    maxContractorShareBps: BigInt(certificate.policy.maxContractorShareBps),
    amountBitLength: certificate.proof.amountBitLength,
    surplusBitLength: certificate.proof.surplusBitLength,
    memo: "-",
  };
  return computeBindingHash(fields, issuerKey, linePoints, totalPoint, h);
}

export function monitorPayrollBatch(
  certificate: PayrollBatchCertificate,
  secret: PayrollBatchSecret,
  now: Date = new Date(),
): PayrollMonitorRow[] {
  const payees: PayrollPayeeInput[] = secret.payees.map((p) => ({
    employeeRef: p.employeeRef,
    amountBaseUnits: p.amountBaseUnits,
    payeeKind: p.payeeKind,
  }));
  const rows = computePayoutSchedule(payees, certificate.schedule, certificate.asset.decimals, now);
  const maxPayee = requireBaseUnits(certificate.policy.maxPayeeAmountBaseUnits, "maximum payee amount");
  return rows.map((row, i) => ({
    ...row,
    status: BigInt(secret.payees[i].amountBaseUnits) > maxPayee ? "over-cap" : row.status,
  }));
}
