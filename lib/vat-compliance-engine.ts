/**
 * CipherBill — Multi-Jurisdiction VAT/GST Compliance Auditor
 *
 * Client-side batch attestation over encrypted invoice streams: jurisdiction
 * net buckets, tax obligations, and customer region references stay hidden
 * behind Pedersen commitments while public filing period, policy caps, and
 * statutory rates per slot are disclosed for regulatory readiness.
 *
 * STRK20_POOL_ADDRESS is provenance only — this module never calls the pool.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";
import { computeVat, getVatJurisdictions, type VatJurisdiction } from "./vat-engine";

export const VAT_COMPLIANCE_ENGINE_VERSION = 1 as const;
export const VAT_COMPLIANCE_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const VAT_COMPLIANCE_PROOF_SYSTEM = "stark-pedersen-vat-compliance-batch-v1" as const;
export const VAT_RATE_DENOMINATOR = 10_000n;
export const MAX_JURISDICTION_LINES = 4;
export const MIN_JURISDICTION_LINES = 1;
export const DEFAULT_AMOUNT_BIT_LENGTH = 96;
export const MIN_AMOUNT_BIT_LENGTH = 16;
export const MAX_AMOUNT_BIT_LENGTH = 128;
export const SURPLUS_EXTRA_BITS = 16;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD = ec.starkCurve.CURVE.Fp;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
const MAX_ENCODED_LENGTH = 1_600_000;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill vat compliance generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill vat compliance statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill vat compliance bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill vat compliance binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill vat compliance issuer signature v1");
const JURISDICTION_DOMAIN = hash.starknetKeccak("CipherBill vat compliance jurisdiction v1");
const REGION_DOMAIN = hash.starknetKeccak("CipherBill vat compliance customer region v1");
const MEMBERSHIP_DOMAIN = hash.starknetKeccak("CipherBill vat compliance membership v1");

const CERTIFICATE_KIND = "cipherbill.vat-compliance-certificate" as const;
const SECRET_KIND = "cipherbill.vat-compliance-secret" as const;
const NET_DISCLOSURE_KIND = "cipherbill.vat-compliance-net-disclosure" as const;
const JURISDICTION_DISCLOSURE_KIND = "cipherbill.vat-compliance-jurisdiction-disclosure" as const;
const KEYPAIR_KIND = "cipherbill.vat-compliance-keypair" as const;

type CurvePoint = ReturnType<typeof G.multiply>;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface VatComplianceEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

export interface VatComplianceKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface VatComplianceAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface VatCompliancePolicy {
  maxNetPerLineBaseUnits: string;
  maxTotalTaxBaseUnits: string;
}

export interface VatComplianceFiling {
  filingPeriodLabel: string;
  filingDueDate: string;
}

export interface ComplianceLineInput {
  jurisdictionCode: string;
  netBaseUnits: string | bigint;
  customerRegionRef?: string;
}

export interface ComplianceLineComputation {
  jurisdictionCode: string;
  jurisdictionLabel: string;
  taxKind: string;
  rateBasisPoints: string;
  netBaseUnits: string;
  taxBaseUnits: string;
  grossBaseUnits: string;
}

export interface ComplianceBatchState {
  lineCount: number;
  totalNetBaseUnits: string;
  totalTaxBaseUnits: string;
  totalGrossBaseUnits: string;
  taxSurplus: string;
  eligible: boolean;
}

export interface ComplianceCommitmentBundle {
  netLineCommitments: CurvePointFelts[];
  taxLineCommitments: CurvePointFelts[];
  totalNetCommitment: CurvePointFelts;
  totalTaxCommitment: CurvePointFelts;
  lineCount: number;
}

export interface ComplianceBitProof {
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

export interface VatComplianceProof {
  proofSystem: typeof VAT_COMPLIANCE_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  generatorH: CurvePointFelts;
  netLineCommitments: CurvePointFelts[];
  taxLineCommitments: CurvePointFelts[];
  totalNetCommitment: CurvePointFelts;
  totalTaxCommitment: CurvePointFelts;
  membershipRoot: string;
  netLineBits: ComplianceBitProof[][];
  taxLineBits: ComplianceBitProof[][];
  totalTaxBits: ComplianceBitProof[];
  taxSurplusBits: ComplianceBitProof[];
  issuerSignature: IssuerSignature;
}

export interface VatComplianceCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof VAT_COMPLIANCE_ENGINE_VERSION;
  certificateId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  merchantAlias: string;
  asset: VatComplianceAsset;
  filing: VatComplianceFiling;
  lineCount: number;
  policy: VatCompliancePolicy;
  slotRateBasisPoints: string[];
  slotTaxKinds: string[];
  jurisdictionCommitments: string[];
  regionCommitments: string[];
  membershipRoot: string;
  issuerPublicKey: CurvePointFelts;
  proof: VatComplianceProof;
  notice: string;
  limitations: readonly string[];
}

export interface ComplianceLineSecret {
  jurisdictionCode: string;
  jurisdictionLabel: string;
  taxKind: string;
  rateBasisPoints: string;
  customerRegionRef: string;
  netBaseUnits: string;
  taxBaseUnits: string;
  grossBaseUnits: string;
  jurisdictionSalt: string;
  regionSalt: string;
  netBlinding: string;
  taxBlinding: string;
}

export interface VatComplianceSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  lines: ComplianceLineSecret[];
  totalNetBaseUnits: string;
  totalTaxBaseUnits: string;
  totalNetBlinding: string;
  totalTaxBlinding: string;
  taxSurplusBlinding: string;
}

export interface IssuedVatComplianceCertificate {
  certificate: VatComplianceCertificate;
  secret: VatComplianceSecret;
}

export interface IssueVatComplianceCertificateInput {
  merchantAlias: string;
  asset: VatComplianceAsset;
  filing: VatComplianceFiling;
  policy: VatCompliancePolicy;
  lines: ComplianceLineInput[];
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

export interface ComplianceNetDisclosure {
  kind: typeof NET_DISCLOSURE_KIND;
  certificateId: string;
  lineIndex: number;
  value: string;
  blinding: string;
  proof: ComplianceBitProof[];
}

export interface ComplianceJurisdictionDisclosure {
  kind: typeof JURISDICTION_DISCLOSURE_KIND;
  certificateId: string;
  lineIndex: number;
  jurisdictionCode: string;
  jurisdictionSalt: string;
  customerRegionRef: string;
  regionSalt: string;
}

export interface ComplianceBreakdownRow {
  lineIndex: number;
  jurisdictionLabel: string;
  taxKind: string;
  rateDisplay: string;
  netDisplay: string;
  taxDisplay: string;
  grossDisplay: string;
  membershipOk: boolean;
}

export interface VatComplianceTrustSummary {
  zeroKnowledge: boolean;
  filesWithAuthority: boolean;
  poolIntegrated: boolean;
  automatedFiling: boolean;
  statement: string;
}

export interface VatComplianceVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

export const VAT_COMPLIANCE_NOTICE =
  "Zero-knowledge batch VAT/GST compliance attestation over hidden jurisdiction nets and customer region references. " +
  "Public filing period, statutory rates per slot, and policy caps only — STRK20 pool address is provenance and never called.";

export const VAT_COMPLIANCE_LIMITATIONS: readonly string[] = [
  "Jurisdiction rates are illustrative presets — verify current statute before filing; not tax advice.",
  "Membership checks bind committed codes to the bundled catalog at issue time; no authority validates registration.",
  "The certificate proves arithmetic against public policy; it does not file, remit, or settle tax with any regulator.",
  "This module never reads from or writes to the STRK20 pool contract.",
];

let cachedGenerator: CurvePoint | null = null;

function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

export function deriveVatComplianceGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent VAT compliance generator.");
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
  return `vcomp_${kind}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
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

function padLines(lines: ComplianceLineInput[]): ComplianceLineInput[] {
  if (lines.length < MIN_JURISDICTION_LINES || lines.length > MAX_JURISDICTION_LINES) {
    throw new Error(`Line count must be between ${MIN_JURISDICTION_LINES} and ${MAX_JURISDICTION_LINES}.`);
  }
  const padded = [...lines];
  while (padded.length < MAX_JURISDICTION_LINES) {
    padded.push({ jurisdictionCode: "", netBaseUnits: 0n, customerRegionRef: "" });
  }
  return padded;
}

function commitJurisdiction(code: string, salt: bigint): bigint {
  return hashElements([JURISDICTION_DOMAIN, hash.starknetKeccak(code), salt]);
}

function commitRegion(ref: string, salt: bigint): bigint {
  return hashElements([REGION_DOMAIN, hash.starknetKeccak(ref), salt]);
}

export function getComplianceJurisdictions(): VatJurisdiction[] {
  return getVatJurisdictions().filter((entry) => entry.code !== "CUSTOM");
}

export function resolveComplianceJurisdiction(code: string): VatJurisdiction {
  const normalized = requireText(code, "jurisdiction code", 16).toUpperCase();
  const match = getComplianceJurisdictions().find((entry) => entry.code === normalized);
  if (!match) throw new Error(`Unknown jurisdiction code: ${normalized}.`);
  return match;
}

export function verifyJurisdictionMembership(code: string): boolean {
  try {
    resolveComplianceJurisdiction(code);
    return true;
  } catch {
    return false;
  }
}

export function computeJurisdictionVat(netBaseUnits: string | bigint, rateBasisPoints: number): ComplianceLineComputation {
  const net = requireBaseUnits(netBaseUnits, "net amount").toString();
  const jurisdiction = { code: "NA", label: "Computed", taxKind: "VAT", standardRateBasisPoints: rateBasisPoints, note: "" };
  const result = computeVat(net, rateBasisPoints);
  return {
    jurisdictionCode: jurisdiction.code,
    jurisdictionLabel: jurisdiction.label,
    taxKind: jurisdiction.taxKind,
    rateBasisPoints: result.rateBasisPoints,
    netBaseUnits: result.netBaseUnits,
    taxBaseUnits: result.taxBaseUnits,
    grossBaseUnits: result.grossBaseUnits,
  };
}

export function computeComplianceLine(
  line: ComplianceLineInput,
): ComplianceLineComputation & { jurisdiction: VatJurisdiction } {
  if (!verifyJurisdictionMembership(line.jurisdictionCode)) {
    throw new Error(`Jurisdiction ${line.jurisdictionCode} is not in the compliance catalog.`);
  }
  const jurisdiction = resolveComplianceJurisdiction(line.jurisdictionCode);
  const result = computeVat(requireBaseUnits(line.netBaseUnits, "net amount").toString(), jurisdiction.standardRateBasisPoints);
  return {
    jurisdiction,
    jurisdictionCode: jurisdiction.code,
    jurisdictionLabel: jurisdiction.label,
    taxKind: jurisdiction.taxKind,
    rateBasisPoints: result.rateBasisPoints,
    netBaseUnits: result.netBaseUnits,
    taxBaseUnits: result.taxBaseUnits,
    grossBaseUnits: result.grossBaseUnits,
  };
}

export function computeMembershipRoot(codes: readonly string[]): string {
  const allowed = getComplianceJurisdictions().map((entry) => hash.starknetKeccak(entry.code));
  const leaves = codes.map((code) => hashElements([MEMBERSHIP_DOMAIN, hash.starknetKeccak(code.toUpperCase())]));
  return toHex(hashElements([MEMBERSHIP_DOMAIN, ...allowed, ...leaves]));
}

export function createVatComplianceIssuerKey(entropy: VatComplianceEntropy = {}): VatComplianceKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

export function requireVatCompliancePolicy(policy: VatCompliancePolicy): VatCompliancePolicy {
  if (!policy || typeof policy !== "object") throw new Error("The compliance policy is required.");
  return {
    maxNetPerLineBaseUnits: requireBaseUnits(policy.maxNetPerLineBaseUnits, "maximum net per line").toString(),
    maxTotalTaxBaseUnits: requireBaseUnits(policy.maxTotalTaxBaseUnits, "maximum total tax").toString(),
  };
}

export function computeComplianceBatchState(lines: ComplianceLineInput[], policy: VatCompliancePolicy): ComplianceBatchState {
  const parsedPolicy = requireVatCompliancePolicy(policy);
  const maxNetPerLine = requireBaseUnits(parsedPolicy.maxNetPerLineBaseUnits, "maximum net per line");
  const maxTotalTax = requireBaseUnits(parsedPolicy.maxTotalTaxBaseUnits, "maximum total tax");
  if (lines.length < MIN_JURISDICTION_LINES || lines.length > MAX_JURISDICTION_LINES) {
    throw new Error(`Line count must be between ${MIN_JURISDICTION_LINES} and ${MAX_JURISDICTION_LINES}.`);
  }

  let totalNet = 0n;
  let totalTax = 0n;
  for (const line of lines) {
    const computed = computeComplianceLine(line);
    const net = requireBaseUnits(computed.netBaseUnits, "net amount");
    const tax = requireBaseUnits(computed.taxBaseUnits, "tax amount");
    if (net > maxNetPerLine) throw new Error("A jurisdiction net exceeds the public per-line cap.");
    totalNet += net;
    totalTax += tax;
  }

  const taxSurplus = maxTotalTax - totalTax;
  return {
    lineCount: lines.length,
    totalNetBaseUnits: totalNet.toString(),
    totalTaxBaseUnits: totalTax.toString(),
    totalGrossBaseUnits: (totalNet + totalTax).toString(),
    taxSurplus: taxSurplus.toString(),
    eligible: taxSurplus >= 0n,
  };
}

export function buildComplianceCommitments(
  lines: ComplianceLineInput[],
  h: CurvePoint,
  netBlindings: bigint[],
  taxBlindings: bigint[],
): ComplianceCommitmentBundle {
  const padded = padLines(lines);
  const computed = padded.map((line) =>
    line.jurisdictionCode ? computeComplianceLine(line) : { netBaseUnits: "0", taxBaseUnits: "0", grossBaseUnits: "0" },
  );
  const netLineCommitments = computed.map((row, i) =>
    pointToFelts(pedersenCommit(requireBaseUnits(row.netBaseUnits, "net amount"), netBlindings[i], h)),
  );
  const taxLineCommitments = computed.map((row, i) =>
    pointToFelts(pedersenCommit(requireBaseUnits(row.taxBaseUnits, "tax amount"), taxBlindings[i], h)),
  );
  const totalNetPoint = netLineCommitments.reduce((acc, _, i) => acc.add(pointFromFelts(netLineCommitments[i])), ZERO);
  const totalTaxPoint = taxLineCommitments.reduce((acc, _, i) => acc.add(pointFromFelts(taxLineCommitments[i])), ZERO);
  return {
    netLineCommitments,
    taxLineCommitments,
    totalNetCommitment: pointToFelts(totalNetPoint),
    totalTaxCommitment: pointToFelts(totalTaxPoint),
    lineCount: lines.length,
  };
}

export function aggregateJurisdictionBreakdown(
  certificate: VatComplianceCertificate,
  secret: VatComplianceSecret,
): ComplianceBreakdownRow[] {
  return secret.lines.map((line, lineIndex) => ({
    lineIndex,
    jurisdictionLabel: line.jurisdictionLabel,
    taxKind: line.taxKind,
    rateDisplay: `${(Number(line.rateBasisPoints) / 100).toFixed(2)}%`,
    netDisplay: formatComplianceBaseUnits(line.netBaseUnits, certificate.asset.decimals),
    taxDisplay: formatComplianceBaseUnits(line.taxBaseUnits, certificate.asset.decimals),
    grossDisplay: formatComplianceBaseUnits(line.grossBaseUnits, certificate.asset.decimals),
    membershipOk: verifyJurisdictionMembership(line.jurisdictionCode),
  }));
}

export function formatComplianceBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(typeof baseUnits === "bigint" ? baseUnits.toString() : baseUnits, decimals);
}

export function summarizeVatComplianceTrust(): VatComplianceTrustSummary {
  return {
    zeroKnowledge: true,
    filesWithAuthority: false,
    poolIntegrated: false,
    automatedFiling: false,
    statement:
      "Client-side Pedersen batch commitments and range proofs over hidden jurisdiction nets and tax lines. " +
      "No regulator filing integration or pool contract calls.",
  };
}

export function getVatComplianceVisibilityModel(): VatComplianceVisibilityModel {
  return {
    hiddenFromVerifier: [
      "Per-jurisdiction net, tax, and gross amounts",
      "Customer region references and exact geographical distribution",
      "Plaintext jurisdiction codes until selectively disclosed",
    ],
    disclosedToVerifier: [
      "Filing period label and due date",
      "Public statutory rate basis points bound to each slot",
      "Policy caps and membership catalog root",
    ],
    applicationOnly: ["Issuer secret key, blinding factors, and full invoice stream"],
    limitation: VAT_COMPLIANCE_LIMITATIONS.join(" "),
  };
}

interface BindingFields {
  certificateId: string;
  merchantAlias: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  filingPeriodLabel: string;
  filingDueDate: string;
  lineCount: bigint;
  maxNetPerLine: bigint;
  maxTotalTax: bigint;
  membershipRoot: bigint;
  amountBitLength: number;
  surplusBitLength: number;
  memo: string;
}

function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  netLineCommitments: CurvePoint[],
  taxLineCommitments: CurvePoint[],
  totalNetCommitment: CurvePoint,
  totalTaxCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(VAT_COMPLIANCE_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    hash.starknetKeccak(fields.filingPeriodLabel),
    hash.starknetKeccak(fields.filingDueDate),
    fields.lineCount,
    fields.maxNetPerLine,
    fields.maxTotalTax,
    fields.membershipRoot,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    ...netLineCommitments.flatMap((p) => [p.x, p.y]),
    ...taxLineCommitments.flatMap((p) => [p.x, p.y]),
    totalNetCommitment.x,
    totalNetCommitment.y,
    totalTaxCommitment.x,
    totalTaxCommitment.y,
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
): ComplianceBitProof {
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

function verifyBit(proof: ComplianceBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
): ComplianceBitProof[] {
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

function verifyRange(proofs: ComplianceBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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

export function issueVatComplianceCertificate(
  input: IssueVatComplianceCertificateInput,
  now: Date = new Date(),
  entropy: VatComplianceEntropy = {},
): IssuedVatComplianceCertificate {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;
  const policy = requireVatCompliancePolicy(input.policy);
  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const filingPeriodLabel = requireText(input.filing?.filingPeriodLabel, "filing period label", 32);
  const filingDueDate = requireIsoTimestamp(input.filing?.filingDueDate);
  const amountBitLength = requireInt(input.amountBitLength ?? DEFAULT_AMOUNT_BIT_LENGTH, "amount bit length", MIN_AMOUNT_BIT_LENGTH, MAX_AMOUNT_BIT_LENGTH);
  const surplusBitLength = amountBitLength + SURPLUS_EXTRA_BITS;
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const state = computeComplianceBatchState(input.lines, policy);
  if (!state.eligible) throw new Error("Policy surpluses are negative; no honest certificate exists.");

  const padded = padLines(input.lines);
  const computedLines = padded.map((line) => (line.jurisdictionCode ? computeComplianceLine(line) : null));
  const nets = computedLines.map((row) => (row ? requireBaseUnits(row.netBaseUnits, "net amount") : 0n));
  const taxes = computedLines.map((row) => (row ? requireBaseUnits(row.taxBaseUnits, "tax amount") : 0n));
  const totalNet = nets.reduce((acc, v) => acc + v, 0n);
  const totalTax = taxes.reduce((acc, v) => acc + v, 0n);
  const band = 1n << BigInt(amountBitLength);
  if (totalNet >= band || totalTax >= band) throw new Error(`Totals exceed the ${amountBitLength}-bit band.`);
  for (let i = 0; i < nets.length; i += 1) {
    if (nets[i] >= band || taxes[i] >= band) throw new Error(`Line ${i} exceeds the ${amountBitLength}-bit band.`);
  }

  const taxSurplus = BigInt(state.taxSurplus);
  if (taxSurplus >= 1n << BigInt(surplusBitLength)) throw new Error("Tax surplus exceeds the surplus bit band.");

  const membershipRoot = BigInt(computeMembershipRoot(input.lines.map((line) => line.jurisdictionCode)));
  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();
  const netBlindings = nets.map(() => nonZeroScalar(nextScalar()));
  const taxBlindings = taxes.map(() => nonZeroScalar(nextScalar()));
  const totalNetBlinding = netBlindings.reduce((acc, r) => mod(acc + r, CURVE_ORDER), 0n);
  const totalTaxBlinding = taxBlindings.reduce((acc, r) => mod(acc + r, CURVE_ORDER), 0n);
  const taxSurplusBlinding = nonZeroScalar(nextScalar());

  const bundle = buildComplianceCommitments(input.lines, h, netBlindings, taxBlindings);
  const netPoints = bundle.netLineCommitments.map(pointFromFelts);
  const taxPoints = bundle.taxLineCommitments.map(pointFromFelts);
  const totalNetPoint = pointFromFelts(bundle.totalNetCommitment);
  const totalTaxPoint = pointFromFelts(bundle.totalTaxCommitment);
  if (!totalNetPoint.equals(pedersenCommit(totalNet, totalNetBlinding, h))) throw new Error("Total net commitment mismatch.");
  if (!totalTaxPoint.equals(pedersenCommit(totalTax, totalTaxBlinding, h))) throw new Error("Total tax commitment mismatch.");

  const jurisdictionSalts = padded.map((line) => (line.jurisdictionCode ? nonZeroScalar(nextScalar()) : 0n));
  const regionSalts = padded.map((line) => (line.customerRegionRef ? nonZeroScalar(nextScalar()) : 0n));
  const jurisdictionCommitments = padded.map((line, i) => (line.jurisdictionCode ? commitJurisdiction(line.jurisdictionCode, jurisdictionSalts[i]) : 0n));
  const regionCommitments = padded.map((line, i) =>
    line.customerRegionRef ? commitRegion(line.customerRegionRef, regionSalts[i]) : 0n,
  );

  const certificateId = createId("certificate");
  const fields: BindingFields = {
    certificateId,
    merchantAlias,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    filingPeriodLabel,
    filingDueDate,
    lineCount: BigInt(state.lineCount),
    maxNetPerLine: requireBaseUnits(policy.maxNetPerLineBaseUnits, "maximum net per line"),
    maxTotalTax: requireBaseUnits(policy.maxTotalTaxBaseUnits, "maximum total tax"),
    membershipRoot,
    amountBitLength,
    surplusBitLength,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, netPoints, taxPoints, totalNetPoint, totalTaxPoint, h);
  const ctx = statementContext(bindingHash);

  const netLineBits = nets.map((net, i) => proveRange(net, netBlindings[i], amountBitLength, ctx, i, h, nextScalar));
  const taxLineBits = taxes.map((tax, i) => proveRange(tax, taxBlindings[i], amountBitLength, ctx, MAX_JURISDICTION_LINES + i, h, nextScalar));
  const totalTaxBits = proveRange(totalTax, totalTaxBlinding, amountBitLength, ctx, MAX_JURISDICTION_LINES * 2, h, nextScalar);
  const taxSurplusBits = proveRange(taxSurplus, taxSurplusBlinding, surplusBitLength, ctx, MAX_JURISDICTION_LINES * 2 + 1, h, nextScalar);

  const proof: VatComplianceProof = {
    proofSystem: VAT_COMPLIANCE_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    generatorH: pointToFelts(h),
    netLineCommitments: bundle.netLineCommitments,
    taxLineCommitments: bundle.taxLineCommitments,
    totalNetCommitment: bundle.totalNetCommitment,
    totalTaxCommitment: bundle.totalTaxCommitment,
    membershipRoot: toHex(membershipRoot),
    netLineBits,
    taxLineBits,
    totalTaxBits,
    taxSurplusBits,
    issuerSignature: signBinding(bindingHash, issuerSecret, nextScalar),
  };

  const slotRateBasisPoints = computedLines.map((row) => row?.rateBasisPoints ?? "0");
  const slotTaxKinds = computedLines.map((row) => row?.taxKind ?? "-");

  const certificate: VatComplianceCertificate = {
    kind: CERTIFICATE_KIND,
    version: VAT_COMPLIANCE_ENGINE_VERSION,
    certificateId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    merchantAlias,
    asset: { symbol: assetSymbol, tokenAddress, decimals: assetDecimals },
    filing: { filingPeriodLabel, filingDueDate },
    lineCount: state.lineCount,
    policy,
    slotRateBasisPoints,
    slotTaxKinds,
    jurisdictionCommitments: jurisdictionCommitments.map(toHex),
    regionCommitments: regionCommitments.map(toHex),
    membershipRoot: toHex(membershipRoot),
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    notice: VAT_COMPLIANCE_NOTICE,
    limitations: VAT_COMPLIANCE_LIMITATIONS,
  };

  const secret: VatComplianceSecret = {
    kind: SECRET_KIND,
    certificateId,
    lines: input.lines.map((line, i) => {
      const computed = computeComplianceLine(line);
      return {
        jurisdictionCode: computed.jurisdictionCode,
        jurisdictionLabel: computed.jurisdictionLabel,
        taxKind: computed.taxKind,
        rateBasisPoints: computed.rateBasisPoints,
        customerRegionRef: line.customerRegionRef?.trim() ?? "",
        netBaseUnits: computed.netBaseUnits,
        taxBaseUnits: computed.taxBaseUnits,
        grossBaseUnits: computed.grossBaseUnits,
        jurisdictionSalt: toHex(jurisdictionSalts[i]),
        regionSalt: toHex(regionSalts[i]),
        netBlinding: toHex(netBlindings[i]),
        taxBlinding: toHex(taxBlindings[i]),
      };
    }),
    totalNetBaseUnits: totalNet.toString(),
    totalTaxBaseUnits: totalTax.toString(),
    totalNetBlinding: toHex(totalNetBlinding),
    totalTaxBlinding: toHex(totalTaxBlinding),
    taxSurplusBlinding: toHex(taxSurplusBlinding),
  };

  void now;
  return { certificate, secret };
}

export function verifyVatComplianceCertificate(certificate: VatComplianceCertificate): boolean {
  try {
    validateCertificateShape(certificate);
    const h = pointFromFelts(certificate.proof.generatorH);
    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const netPoints = certificate.proof.netLineCommitments.map(pointFromFelts);
    const taxPoints = certificate.proof.taxLineCommitments.map(pointFromFelts);
    const totalNetPoint = pointFromFelts(certificate.proof.totalNetCommitment);
    const totalTaxPoint = pointFromFelts(certificate.proof.totalTaxCommitment);
    if (!netPoints.reduce((acc, point) => acc.add(point), ZERO).equals(totalNetPoint)) return false;
    if (!taxPoints.reduce((acc, point) => acc.add(point), ZERO).equals(totalTaxPoint)) return false;

    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      merchantAlias: certificate.merchantAlias,
      assetSymbol: certificate.asset.symbol,
      tokenAddress: certificate.asset.tokenAddress,
      assetDecimals: certificate.asset.decimals,
      filingPeriodLabel: certificate.filing.filingPeriodLabel,
      filingDueDate: certificate.filing.filingDueDate,
      lineCount: BigInt(certificate.lineCount),
      maxNetPerLine: requireBaseUnits(certificate.policy.maxNetPerLineBaseUnits, "maximum net per line"),
      maxTotalTax: requireBaseUnits(certificate.policy.maxTotalTaxBaseUnits, "maximum total tax"),
      membershipRoot: BigInt(certificate.membershipRoot),
      amountBitLength: certificate.proof.amountBitLength,
      surplusBitLength: certificate.proof.surplusBitLength,
      memo: "-",
    };
    const bindingHash = computeBindingHash(fields, issuerKey, netPoints, taxPoints, totalNetPoint, totalTaxPoint, h);
    const ctx = statementContext(bindingHash);
    const { amountBitLength, surplusBitLength } = certificate.proof;

    for (let i = 0; i < MAX_JURISDICTION_LINES; i += 1) {
      const netOpened = verifyRange(certificate.proof.netLineBits[i], amountBitLength, ctx, i, h);
      if (!netOpened?.equals(netPoints[i])) return false;
      const taxOpened = verifyRange(certificate.proof.taxLineBits[i], amountBitLength, ctx, MAX_JURISDICTION_LINES + i, h);
      if (!taxOpened?.equals(taxPoints[i])) return false;
    }
    if (!verifyRange(certificate.proof.totalTaxBits, amountBitLength, ctx, MAX_JURISDICTION_LINES * 2, h)?.equals(totalTaxPoint)) return false;
    if (!verifyRange(certificate.proof.taxSurplusBits, surplusBitLength, ctx, MAX_JURISDICTION_LINES * 2 + 1, h)) return false;
    return verifySignature(certificate.proof.issuerSignature, bindingHash, issuerKey);
  } catch {
    return false;
  }
}

function validateCertificateShape(value: unknown): asserts value is VatComplianceCertificate {
  if (!value || typeof value !== "object") throw new Error("Certificate is required.");
  const cert = value as VatComplianceCertificate;
  if (cert.kind !== CERTIFICATE_KIND || cert.version !== VAT_COMPLIANCE_ENGINE_VERSION) throw new Error("Certificate kind or version mismatch.");
  if (cert.poolAddress.toLowerCase() !== STRK20_POOL_ADDRESS.toLowerCase()) throw new Error("Pool address mismatch.");
  if (cert.proof.proofSystem !== VAT_COMPLIANCE_PROOF_SYSTEM) throw new Error("Proof system mismatch.");
}

export function serializeVatComplianceCertificate(certificate: VatComplianceCertificate): string {
  const json = JSON.stringify(certificate);
  if (json.length > MAX_ENCODED_LENGTH) throw new Error("Certificate exceeds maximum encoded length.");
  return json;
}

export function parseVatComplianceCertificate(serialized: string): VatComplianceCertificate {
  if (serialized.length > MAX_ENCODED_LENGTH) throw new Error("Certificate exceeds maximum encoded length.");
  const parsed = JSON.parse(serialized) as VatComplianceCertificate;
  validateCertificateShape(parsed);
  return parsed;
}

export function serializeVatComplianceSecret(secret: VatComplianceSecret): string {
  return JSON.stringify(secret);
}

export function buildComplianceNetDisclosure(
  certificate: VatComplianceCertificate,
  secret: VatComplianceSecret,
  lineIndex: number,
): ComplianceNetDisclosure {
  if (lineIndex < 0 || lineIndex >= secret.lines.length) throw new Error("Line index is out of range.");
  const line = secret.lines[lineIndex];
  return {
    kind: NET_DISCLOSURE_KIND,
    certificateId: certificate.certificateId,
    lineIndex,
    value: line.netBaseUnits,
    blinding: line.netBlinding,
    proof: certificate.proof.netLineBits[lineIndex],
  };
}

export function verifyComplianceNetDisclosure(disclosure: ComplianceNetDisclosure, certificate: VatComplianceCertificate): boolean {
  try {
    if (disclosure.kind !== NET_DISCLOSURE_KIND || disclosure.certificateId !== certificate.certificateId) return false;
    const h = pointFromFelts(certificate.proof.generatorH);
    const bindingHash = computeBindingHashFromCertificate(certificate);
    const ctx = statementContext(bindingHash);
    const opened = verifyRange(disclosure.proof, certificate.proof.amountBitLength, ctx, disclosure.lineIndex, h);
    return opened?.equals(pointFromFelts(certificate.proof.netLineCommitments[disclosure.lineIndex])) ?? false;
  } catch {
    return false;
  }
}

export function buildComplianceJurisdictionDisclosure(
  certificate: VatComplianceCertificate,
  secret: VatComplianceSecret,
  lineIndex: number,
): ComplianceJurisdictionDisclosure {
  if (lineIndex < 0 || lineIndex >= secret.lines.length) throw new Error("Line index is out of range.");
  const line = secret.lines[lineIndex];
  return {
    kind: JURISDICTION_DISCLOSURE_KIND,
    certificateId: certificate.certificateId,
    lineIndex,
    jurisdictionCode: line.jurisdictionCode,
    jurisdictionSalt: line.jurisdictionSalt,
    customerRegionRef: line.customerRegionRef,
    regionSalt: line.regionSalt,
  };
}

export function verifyComplianceJurisdictionDisclosure(
  disclosure: ComplianceJurisdictionDisclosure,
  certificate: VatComplianceCertificate,
): boolean {
  if (disclosure.kind !== JURISDICTION_DISCLOSURE_KIND || disclosure.certificateId !== certificate.certificateId) return false;
  if (!verifyJurisdictionMembership(disclosure.jurisdictionCode)) return false;
  const jurisdictionOk = toHex(commitJurisdiction(disclosure.jurisdictionCode, requireScalar(disclosure.jurisdictionSalt, false))) === certificate.jurisdictionCommitments[disclosure.lineIndex];
  const regionOk = disclosure.customerRegionRef
    ? toHex(commitRegion(disclosure.customerRegionRef, requireScalar(disclosure.regionSalt, false))) === certificate.regionCommitments[disclosure.lineIndex]
    : certificate.regionCommitments[disclosure.lineIndex] === "0x0";
  return jurisdictionOk && regionOk;
}

function computeBindingHashFromCertificate(certificate: VatComplianceCertificate): bigint {
  const h = pointFromFelts(certificate.proof.generatorH);
  const issuerKey = pointFromFelts(certificate.issuerPublicKey);
  const netPoints = certificate.proof.netLineCommitments.map(pointFromFelts);
  const taxPoints = certificate.proof.taxLineCommitments.map(pointFromFelts);
  const totalNetPoint = pointFromFelts(certificate.proof.totalNetCommitment);
  const totalTaxPoint = pointFromFelts(certificate.proof.totalTaxCommitment);
  const fields: BindingFields = {
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    assetSymbol: certificate.asset.symbol,
    tokenAddress: certificate.asset.tokenAddress,
    assetDecimals: certificate.asset.decimals,
    filingPeriodLabel: certificate.filing.filingPeriodLabel,
    filingDueDate: certificate.filing.filingDueDate,
    lineCount: BigInt(certificate.lineCount),
    maxNetPerLine: requireBaseUnits(certificate.policy.maxNetPerLineBaseUnits, "maximum net per line"),
    maxTotalTax: requireBaseUnits(certificate.policy.maxTotalTaxBaseUnits, "maximum total tax"),
    membershipRoot: BigInt(certificate.membershipRoot),
    amountBitLength: certificate.proof.amountBitLength,
    surplusBitLength: certificate.proof.surplusBitLength,
    memo: "-",
  };
  return computeBindingHash(fields, issuerKey, netPoints, taxPoints, totalNetPoint, totalTaxPoint, h);
}
