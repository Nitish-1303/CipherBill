import { ec, hash, type STRK20_ACTION } from "starknet";

import type { InvoiceRebatePolicy, ShareableInvoice } from "./invoices";
import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { decimalToBaseUnits, normalizeStarknetAddress } from "./strk20/validation";

export const REBATE_ENGINE_VERSION = 1 as const;
export const REBATE_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const REBATE_BPS_DENOMINATOR = 10_000n;
export const MAX_REBATE_BPS = 2_500;
export const REBATE_QUOTE_TTL_MS = 5 * 60 * 1_000;

const PROOF_KIND = "salted-poseidon-commitment" as const;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const INVOICE_DOMAIN = hash.starknetKeccak("CipherBill private rebate invoice v1");
const POLICY_DOMAIN = hash.starknetKeccak("CipherBill vendor rebate policy v1");
const ADJUSTMENT_DOMAIN = hash.starknetKeccak("CipherBill private rebate adjustment v1");

export interface RebateCalculation {
  principalBaseUnits: bigint;
  rebateBaseUnits: bigint;
  settlementBaseUnits: bigint;
  selectedRebateBps: number;
  eligibleRebateBps: number;
  leadTimeSeconds: number;
}

export interface RebateCommitmentProof {
  version: typeof REBATE_ENGINE_VERSION;
  proofKind: typeof PROOF_KIND;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceCommitment: string;
  policyCommitment: string;
  adjustmentCommitment: string;
  issuedAt: string;
  validUntil: string;
  notice: string;
}

export interface RebateCommitmentOpening {
  principalBaseUnits: string;
  rebateBaseUnits: string;
  settlementBaseUnits: string;
  selectedRebateBps: number;
  eligibleRebateBps: number;
  leadTimeSeconds: number;
  invoiceSalt: string;
  policySalt: string;
  adjustmentSalt: string;
}

export interface RebateClaim {
  proof: RebateCommitmentProof;
  opening: RebateCommitmentOpening;
}

export interface RebateEntropy {
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export interface RebateSecurityModel {
  provenLocally: string[];
  hiddenByCommitment: string[];
  hiddenByStrk20: string[];
  limitations: string[];
}

export function calculateEligibleRebateBps(
  policy: InvoiceRebatePolicy,
  expiresAt: string,
  settlementAt = new Date(),
): { eligibleRebateBps: number; leadTimeSeconds: number } {
  validateRebatePolicy(policy);
  const expiryMs = requireTimestamp(expiresAt, "Invoice expiration");
  const settlementMs = settlementAt.getTime();
  if (!Number.isFinite(settlementMs)) throw new Error("Settlement time is invalid.");
  const leadTimeSeconds = Math.max(0, Math.floor((expiryMs - settlementMs) / 1_000));
  if (leadTimeSeconds <= policy.minimumLeadTimeSeconds) return { eligibleRebateBps: 0, leadTimeSeconds };
  if (leadTimeSeconds >= policy.fullRebateLeadTimeSeconds) {
    return { eligibleRebateBps: policy.maximumRebateBps, leadTimeSeconds };
  }

  const eligibleWindow = BigInt(leadTimeSeconds - policy.minimumLeadTimeSeconds);
  const fullWindow = BigInt(policy.fullRebateLeadTimeSeconds - policy.minimumLeadTimeSeconds);
  const eligibleRebateBps = Number(BigInt(policy.maximumRebateBps) * eligibleWindow / fullWindow);
  return { eligibleRebateBps, leadTimeSeconds };
}

export function calculateRebate(
  principalBaseUnits: bigint | string,
  policy: InvoiceRebatePolicy,
  expiresAt: string,
  selectedRebateBps: number,
  settlementAt = new Date(),
): RebateCalculation {
  const principal = typeof principalBaseUnits === "bigint" ? principalBaseUnits : requireBaseUnits(principalBaseUnits, "Invoice principal");
  if (principal <= 0n) throw new Error("Invoice principal must be positive.");
  if (!Number.isInteger(selectedRebateBps) || selectedRebateBps <= 0) throw new Error("Selected rebate must be a positive whole number of basis points.");
  const eligibility = calculateEligibleRebateBps(policy, expiresAt, settlementAt);
  if (selectedRebateBps > eligibility.eligibleRebateBps) {
    throw new Error(`Selected rebate exceeds the currently eligible ${eligibility.eligibleRebateBps} basis points.`);
  }
  const rebateBaseUnits = principal * BigInt(selectedRebateBps) / REBATE_BPS_DENOMINATOR;
  if (rebateBaseUnits <= 0n) throw new Error("Invoice principal is too small to produce a rebate at this rate.");
  const settlementBaseUnits = principal - rebateBaseUnits;
  if (settlementBaseUnits <= 0n) throw new Error("Rebate must leave a positive settlement amount.");
  return {
    principalBaseUnits: principal,
    rebateBaseUnits,
    settlementBaseUnits,
    selectedRebateBps,
    eligibleRebateBps: eligibility.eligibleRebateBps,
    leadTimeSeconds: eligibility.leadTimeSeconds,
  };
}

export function createRebateCommitment(
  invoice: ShareableInvoice,
  selectedRebateBps: number,
  issuedAt = new Date(),
  entropy: RebateEntropy = {},
): RebateClaim {
  const policy = requireEligibleInvoice(invoice);
  const issuedAtMs = issuedAt.getTime();
  if (!Number.isFinite(issuedAtMs)) throw new Error("Rebate quote time is invalid.");
  if (issuedAtMs < Date.parse(invoice.createdAt)) throw new Error("Rebate quote cannot predate the invoice.");
  if (issuedAtMs >= Date.parse(invoice.expiresAt)) throw new Error("Expired invoices cannot claim a rebate.");
  const principalBaseUnits = BigInt(decimalToBaseUnits(invoice.amount, invoice.tokenDecimals));
  const calculation = calculateRebate(principalBaseUnits, policy, invoice.expiresAt, selectedRebateBps, issuedAt);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const invoiceSalt = randomScalar(random);
  const policySalt = randomScalar(random);
  const adjustmentSalt = randomScalar(random);
  const invoiceCommitment = computeInvoiceCommitment(invoice, calculation.principalBaseUnits, invoiceSalt);
  const policyCommitment = computePolicyCommitment(invoice, policy, policySalt);
  const adjustmentCommitment = computeAdjustmentCommitment(
    invoiceCommitment,
    policyCommitment,
    calculation,
    issuedAt,
    adjustmentSalt,
  );
  const validUntilMs = Math.min(issuedAtMs + REBATE_QUOTE_TTL_MS, Date.parse(invoice.expiresAt));

  return {
    proof: {
      version: REBATE_ENGINE_VERSION,
      proofKind: PROOF_KIND,
      network: MAINNET_CHAIN_ID,
      poolAddress: STRK20_POOL_ADDRESS,
      invoiceCommitment: toHex(invoiceCommitment),
      policyCommitment: toHex(policyCommitment),
      adjustmentCommitment: toHex(adjustmentCommitment),
      issuedAt: issuedAt.toISOString(),
      validUntil: new Date(validUntilMs).toISOString(),
      notice: "Salted Poseidon commit-reveal proof for local rebate arithmetic. It is not a zk-SNARK, a merchant signature, or an onchain enforcement mechanism; only the resulting transfer is submitted through STRK20.",
    },
    opening: {
      principalBaseUnits: calculation.principalBaseUnits.toString(),
      rebateBaseUnits: calculation.rebateBaseUnits.toString(),
      settlementBaseUnits: calculation.settlementBaseUnits.toString(),
      selectedRebateBps: calculation.selectedRebateBps,
      eligibleRebateBps: calculation.eligibleRebateBps,
      leadTimeSeconds: calculation.leadTimeSeconds,
      invoiceSalt: toHex(invoiceSalt),
      policySalt: toHex(policySalt),
      adjustmentSalt: toHex(adjustmentSalt),
    },
  };
}

export function verifyRebateCommitment(invoice: ShareableInvoice, claim: RebateClaim, verifiedAt = new Date()): RebateCalculation {
  const policy = requireEligibleInvoice(invoice);
  validateProofShape(claim);
  const verifiedAtMs = verifiedAt.getTime();
  if (!Number.isFinite(verifiedAtMs)) throw new Error("Rebate verification time is invalid.");
  const issuedAtMs = requireTimestamp(claim.proof.issuedAt, "Rebate issue time");
  const validUntilMs = requireTimestamp(claim.proof.validUntil, "Rebate validity time");
  if (issuedAtMs < Date.parse(invoice.createdAt) || issuedAtMs >= Date.parse(invoice.expiresAt)) throw new Error("Rebate issue time is outside the invoice lifetime.");
  if (validUntilMs !== Math.min(issuedAtMs + REBATE_QUOTE_TTL_MS, Date.parse(invoice.expiresAt))) throw new Error("Rebate validity window is invalid.");
  if (verifiedAtMs < issuedAtMs || verifiedAtMs > validUntilMs) throw new Error("Rebate quote is not currently valid.");

  const principal = requireBaseUnits(claim.opening.principalBaseUnits, "Invoice principal");
  const expectedPrincipal = BigInt(decimalToBaseUnits(invoice.amount, invoice.tokenDecimals));
  if (principal !== expectedPrincipal) throw new Error("Rebate opening does not match the invoice principal.");
  const calculation = calculateRebate(principal, policy, invoice.expiresAt, claim.opening.selectedRebateBps, new Date(issuedAtMs));
  if (
    claim.opening.rebateBaseUnits !== calculation.rebateBaseUnits.toString()
    || claim.opening.settlementBaseUnits !== calculation.settlementBaseUnits.toString()
    || claim.opening.eligibleRebateBps !== calculation.eligibleRebateBps
    || claim.opening.leadTimeSeconds !== calculation.leadTimeSeconds
  ) throw new Error("Rebate opening arithmetic is invalid.");

  const invoiceCommitment = computeInvoiceCommitment(invoice, principal, requireScalar(claim.opening.invoiceSalt, "Invoice salt"));
  const policyCommitment = computePolicyCommitment(invoice, policy, requireScalar(claim.opening.policySalt, "Policy salt"));
  const adjustmentCommitment = computeAdjustmentCommitment(
    invoiceCommitment,
    policyCommitment,
    calculation,
    new Date(issuedAtMs),
    requireScalar(claim.opening.adjustmentSalt, "Adjustment salt"),
  );
  if (claim.proof.invoiceCommitment !== toHex(invoiceCommitment)) throw new Error("Invoice commitment does not match its opening.");
  if (claim.proof.policyCommitment !== toHex(policyCommitment)) throw new Error("Policy commitment does not match its opening.");
  if (claim.proof.adjustmentCommitment !== toHex(adjustmentCommitment)) throw new Error("Rebate adjustment commitment does not match its opening.");
  return calculation;
}

export function buildRebateSettlementActions(
  invoice: ShareableInvoice,
  claim: RebateClaim,
  verifiedAt = new Date(),
): STRK20_ACTION[] {
  const calculation = verifyRebateCommitment(invoice, claim, verifiedAt);
  return [{
    type: "transfer",
    token: normalizeStarknetAddress(invoice.tokenAddress),
    amount: calculation.settlementBaseUnits.toString(),
    recipient: normalizeStarknetAddress(invoice.recipientAddress),
  }];
}

export function serializeRebateProof(proof: RebateCommitmentProof): string {
  validatePublicProof(proof);
  return JSON.stringify(proof, null, 2);
}

export function getRebateSecurityModel(): RebateSecurityModel {
  return {
    provenLocally: [
      "The opened principal, policy, rate, rebate, and net settlement reproduce the three Poseidon commitments.",
      "Bigint arithmetic satisfies principal minus rebate equals the exact STRK20 transfer amount.",
      "The selected basis-point rate was within the invoice policy at quote time.",
    ],
    hiddenByCommitment: ["Invoice identifier and addresses", "Principal and rebate amounts", "Vendor schedule and selected rate"],
    hiddenByStrk20: ["In-pool sender and recipient", "Transferred token and amount", "Spent-note linkage and encrypted note values"],
    limitations: [
      "The public commitment is not submitted onchain and is not a zk-SNARK or merchant signature.",
      "The invoice checksum detects link edits but does not authenticate the vendor; verify the merchant address out of band.",
      "A client-only policy cannot force a modified wallet or contract to honor the rebate; enforcement requires a signed policy or helper contract.",
      "Deposits, withdrawals, timing, fees, nullifiers, open-note values, and correlation remain public or observable.",
    ],
  };
}

export function validateRebatePolicy(policy: InvoiceRebatePolicy): void {
  if (!policy || policy.version !== REBATE_ENGINE_VERSION) throw new Error("Rebate policy version is unsupported.");
  if (!Number.isInteger(policy.maximumRebateBps) || policy.maximumRebateBps <= 0 || policy.maximumRebateBps > MAX_REBATE_BPS) {
    throw new Error(`Maximum rebate must be between 1 and ${MAX_REBATE_BPS} basis points.`);
  }
  if (!Number.isInteger(policy.minimumLeadTimeSeconds) || policy.minimumLeadTimeSeconds < 0) {
    throw new Error("Minimum rebate lead time must be a non-negative whole number of seconds.");
  }
  if (
    !Number.isInteger(policy.fullRebateLeadTimeSeconds)
    || policy.fullRebateLeadTimeSeconds <= policy.minimumLeadTimeSeconds
    || policy.fullRebateLeadTimeSeconds > 365 * 24 * 60 * 60
  ) throw new Error("Full-rebate lead time must exceed the minimum lead time and fit within one year.");
}

function requireEligibleInvoice(invoice: ShareableInvoice): InvoiceRebatePolicy {
  if (!invoice.rebatePolicy) throw new Error("This invoice does not offer an early-settlement rebate.");
  if (invoice.allowPartialPayments || invoice.milestones?.length) throw new Error("Rebates require a single exact invoice settlement.");
  validateRebatePolicy(invoice.rebatePolicy);
  return invoice.rebatePolicy;
}

function computeInvoiceCommitment(invoice: ShareableInvoice, principal: bigint, salt: bigint): bigint {
  return hashElements([
    INVOICE_DOMAIN,
    hash.starknetKeccak(invoice.invoiceId),
    BigInt(normalizeStarknetAddress(invoice.recipientAddress)),
    BigInt(normalizeStarknetAddress(invoice.tokenAddress)),
    principal,
    salt,
  ]);
}

function computePolicyCommitment(invoice: ShareableInvoice, policy: InvoiceRebatePolicy, salt: bigint): bigint {
  return hashElements([
    POLICY_DOMAIN,
    hash.starknetKeccak(invoice.invoiceId),
    BigInt(policy.maximumRebateBps),
    BigInt(policy.minimumLeadTimeSeconds),
    BigInt(policy.fullRebateLeadTimeSeconds),
    timestampSeconds(invoice.expiresAt),
    salt,
  ]);
}

function computeAdjustmentCommitment(
  invoiceCommitment: bigint,
  policyCommitment: bigint,
  calculation: RebateCalculation,
  issuedAt: Date,
  salt: bigint,
): bigint {
  return hashElements([
    ADJUSTMENT_DOMAIN,
    invoiceCommitment,
    policyCommitment,
    calculation.principalBaseUnits,
    calculation.rebateBaseUnits,
    calculation.settlementBaseUnits,
    BigInt(calculation.selectedRebateBps),
    BigInt(calculation.eligibleRebateBps),
    BigInt(calculation.leadTimeSeconds),
    BigInt(Math.floor(issuedAt.getTime() / 1_000)),
    salt,
  ]);
}

function validateProofShape(claim: RebateClaim): void {
  if (!claim || typeof claim !== "object" || !claim.proof || !claim.opening) throw new Error("Rebate claim is incomplete.");
  validatePublicProof(claim.proof);
  requireBaseUnits(claim.opening.principalBaseUnits, "Invoice principal");
  requireBaseUnits(claim.opening.rebateBaseUnits, "Rebate amount");
  requireBaseUnits(claim.opening.settlementBaseUnits, "Settlement amount");
  if (!Number.isInteger(claim.opening.selectedRebateBps) || !Number.isInteger(claim.opening.eligibleRebateBps)) throw new Error("Rebate basis points are invalid.");
  if (!Number.isInteger(claim.opening.leadTimeSeconds) || claim.opening.leadTimeSeconds < 0) throw new Error("Rebate lead time is invalid.");
}

function validatePublicProof(proof: RebateCommitmentProof): void {
  if (
    !proof
    || proof.version !== REBATE_ENGINE_VERSION
    || proof.proofKind !== PROOF_KIND
    || proof.network !== MAINNET_CHAIN_ID
    || proof.poolAddress !== STRK20_POOL_ADDRESS
  ) throw new Error("Rebate proof context is invalid.");
  requireCommitment(proof.invoiceCommitment, "Invoice commitment");
  requireCommitment(proof.policyCommitment, "Policy commitment");
  requireCommitment(proof.adjustmentCommitment, "Adjustment commitment");
  requireTimestamp(proof.issuedAt, "Rebate issue time");
  requireTimestamp(proof.validUntil, "Rebate validity time");
}

function randomScalar(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  const bytes = random(new Uint8Array(32));
  if (bytes.length !== 32) throw new Error("Rebate entropy returned an invalid byte length.");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value % (FIELD_PRIME - 1n) + 1n;
}

function requireScalar(value: string, label: string): bigint {
  if (!/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is invalid.`);
  const scalar = BigInt(value);
  if (scalar <= 0n || scalar >= FIELD_PRIME) throw new Error(`${label} is outside the Stark field.`);
  return scalar;
}

function requireCommitment(value: string, label: string): bigint {
  if (!/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is invalid.`);
  const commitment = BigInt(value);
  if (commitment < 0n || commitment >= FIELD_PRIME) throw new Error(`${label} is outside the Stark field.`);
  return commitment;
}

function requireBaseUnits(value: string, label: string): bigint {
  if (!/^\d+$/.test(value)) throw new Error(`${label} must use an unsigned base-unit integer.`);
  return BigInt(value);
}

function requireTimestamp(value: string, label: string): number {
  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) throw new Error(`${label} is invalid.`);
  return date.getTime();
}

function timestampSeconds(value: string): bigint {
  return BigInt(Math.floor(requireTimestamp(value, "Timestamp") / 1_000));
}

function hashElements(values: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}
