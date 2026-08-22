import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const INSURANCE_ENGINE_VERSION = 1 as const;
export const INSURANCE_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const MAX_DEFAULT_PROBABILITY_BPS = 5_000;
export const MAX_CLAIM_EVIDENCE_DIGESTS = 16;

const BPS_DENOMINATOR = 10_000n;
const U128_MAX = (1n << 128n) - 1n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const RISK_DOMAIN = hash.starknetKeccak("CipherBill private invoice risk v1");
const COVERAGE_DOMAIN = hash.starknetKeccak("CipherBill private insurance coverage v1");
const PREMIUM_DOMAIN = hash.starknetKeccak("CipherBill private insurance premium v1");
const POLICY_DOMAIN = hash.starknetKeccak("CipherBill private insurance policy v1");
const CLAIM_DOMAIN = hash.starknetKeccak("CipherBill private insurance claim v1");
const APPROVAL_DOMAIN = hash.starknetKeccak("CipherBill insurance claim approval v1");

export type InsuranceRiskGrade = "A" | "B" | "C" | "D" | "E";
export type InsuranceClaimReason = "nonpayment" | "counterparty_insolvency" | "arbitration_award";
export type InsuranceClaimDecision = "approved" | "denied";

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface InsuranceAuthorityKeypair {
  privateKey: string;
  publicKey: CurvePointFelts;
}

export interface InvoiceRiskInput {
  invoiceId: string;
  invoicePrincipalBaseUnits: string;
  dueAt: string;
  counterpartyTenureDays: number;
  successfulSettlements: number;
  lateSettlements: number;
  disputedSettlements: number;
  concentrationBps: number;
  collateralBps: number;
}

export interface RiskScoreComponents {
  baselineBps: number;
  sparseHistoryBps: number;
  lateHistoryBps: number;
  disputeHistoryBps: number;
  tenureAdjustmentBps: number;
  termRiskBps: number;
  concentrationRiskBps: number;
  collateralCreditBps: number;
}

export interface InsuranceRiskAssessment {
  defaultProbabilityBps: number;
  grade: InsuranceRiskGrade;
  observationCount: number;
  termDays: number;
  components: RiskScoreComponents;
}

export interface InsurancePricingInput {
  coverageBps: number;
  deductibleBps: number;
  reserveLoadingBps: number;
  protocolFeeBps: number;
  capitalReserveBaseUnits: string;
  existingPoolExposureBaseUnits: string;
  minimumSolvencyBps: number;
  claimGracePeriodDays: number;
  claimWindowDays: number;
}

export interface InsuranceCoverageCalculation {
  coverageLimitBaseUnits: bigint;
  deductibleBaseUnits: bigint;
  maximumPayoutBaseUnits: bigint;
  expectedLossBaseUnits: bigint;
  reserveLoadingBaseUnits: bigint;
  protocolFeeBaseUnits: bigint;
  premiumBaseUnits: bigint;
  postBindExposureBaseUnits: bigint;
  capitalRequirementBaseUnits: bigint;
  remainingCapitalBufferBaseUnits: bigint;
  postBindUtilizationBps: number;
}

export interface CreateInsurancePolicyInput {
  risk: InvoiceRiskInput;
  pricing: InsurancePricingInput;
  tokenAddress: string;
  merchantPayoutAddress: string;
  insurerReserveAddress: string;
  claimsPublicKey: CurvePointFelts;
}

export interface InsurancePolicy {
  version: typeof INSURANCE_ENGINE_VERSION;
  policyId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  tokenAddress: string;
  merchantPayoutAddress: string;
  insurerReserveAddress: string;
  claimsPublicKey: CurvePointFelts;
  risk: InvoiceRiskInput;
  assessment: InsuranceRiskAssessment;
  pricing: InsurancePricingInput;
  coverageLimitBaseUnits: string;
  deductibleBaseUnits: string;
  maximumPayoutBaseUnits: string;
  expectedLossBaseUnits: string;
  reserveLoadingBaseUnits: string;
  protocolFeeBaseUnits: string;
  premiumBaseUnits: string;
  postBindExposureBaseUnits: string;
  capitalRequirementBaseUnits: string;
  remainingCapitalBufferBaseUnits: string;
  postBindUtilizationBps: number;
  coverageStartsAt: string;
  defaultEligibleAt: string;
  claimDeadline: string;
  riskCommitment: string;
  coverageCommitment: string;
  premiumCommitment: string;
  policyCommitment: string;
  notice: string;
}

export interface InsurancePolicyOpening {
  riskSalt: string;
  coverageSalt: string;
  premiumSalt: string;
  policySalt: string;
}

export interface InsurancePolicyBundle {
  policy: InsurancePolicy;
  opening: InsurancePolicyOpening;
}

export interface PublicInsuranceCommitment {
  version: typeof INSURANCE_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  riskCommitment: string;
  coverageCommitment: string;
  premiumCommitment: string;
  policyCommitment: string;
  coverageStartsAt: string;
  claimDeadline: string;
  notice: string;
}

export interface InsuranceClaimCommitment {
  version: typeof INSURANCE_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  policyCommitment: string;
  claimCommitment: string;
  filedAt: string;
  notice: string;
}

export interface InsuranceClaimOpening {
  policyId: string;
  defaultLossBaseUnits: string;
  payoutBaseUnits: string;
  reason: InsuranceClaimReason;
  evidenceDigests: string[];
  claimSalt: string;
}

export interface InsuranceClaimBundle {
  commitment: InsuranceClaimCommitment;
  opening: InsuranceClaimOpening;
}

export interface InsuranceClaimAuthorization {
  version: typeof INSURANCE_ENGINE_VERSION;
  policyCommitment: string;
  claimCommitment: string;
  decision: InsuranceClaimDecision;
  payoutBaseUnits: string;
  decidedAt: string;
  nonceCommitment: CurvePointFelts;
  response: string;
}

export interface InsuranceHelperEncoder {
  contractAddress: string;
  encodePremiumEscrow(input: {
    policyCommitment: string;
    tokenAddress: string;
    premiumBaseUnits: string;
    maximumPayoutBaseUnits: string;
    claimDeadlineSeconds: string;
    claimsPublicKey: CurvePointFelts;
    poolAddress: "${poolAddress}";
  }): string[];
  encodeClaimPayout(input: {
    policyCommitment: string;
    claimCommitment: string;
    payoutBaseUnits: string;
    authorization: InsuranceClaimAuthorization;
    openNoteId: "${openNoteIds[0]}";
    poolAddress: "${poolAddress}";
  }): string[];
}

export interface InsuranceEntropy {
  createId?: () => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
  privateKey?: bigint;
  signatureNonce?: bigint;
}

export interface InsuranceSecurityModel {
  provenLocally: string[];
  hiddenByCommitments: string[];
  hiddenByStrk20: string[];
  limitations: string[];
}

export function generateInsuranceAuthorityKeypair(entropy: Pick<InsuranceEntropy, "privateKey"> = {}): InsuranceAuthorityKeypair {
  const privateKey = requireSecretScalar(entropy.privateKey ?? randomCurveScalar(), "Claims authority private key");
  return { privateKey: toHex(privateKey), publicKey: pointToFelts(ec.starkCurve.ProjectivePoint.BASE.multiply(privateKey)) };
}

export function assessInvoiceRisk(input: InvoiceRiskInput, assessedAt = new Date()): InsuranceRiskAssessment {
  const normalized = normalizeRiskInput(input, assessedAt);
  const observationCount = normalized.successfulSettlements + normalized.lateSettlements + normalized.disputedSettlements;
  const sparseHistoryBps = observationCount === 0 ? 600 : observationCount < 5 ? 300 : 0;
  const lateHistoryBps = observationCount ? Math.floor(normalized.lateSettlements * 2_500 / observationCount) : 0;
  const disputeHistoryBps = observationCount ? Math.floor(normalized.disputedSettlements * 3_500 / observationCount) : 0;
  const tenureAdjustmentBps = normalized.counterpartyTenureDays < 90 ? 500 : normalized.counterpartyTenureDays < 365 ? 250 : normalized.counterpartyTenureDays >= 1_095 ? -100 : 0;
  const termDays = Math.max(1, Math.ceil((Date.parse(normalized.dueAt) - assessedAt.getTime()) / 86_400_000));
  const termRiskBps = Math.min(600, termDays * 4);
  const concentrationRiskBps = Math.floor(normalized.concentrationBps / 10);
  const collateralCreditBps = Math.floor(normalized.collateralBps / 10);
  const components: RiskScoreComponents = {
    baselineBps: 75,
    sparseHistoryBps,
    lateHistoryBps,
    disputeHistoryBps,
    tenureAdjustmentBps,
    termRiskBps,
    concentrationRiskBps,
    collateralCreditBps,
  };
  const raw = components.baselineBps + sparseHistoryBps + lateHistoryBps + disputeHistoryBps + tenureAdjustmentBps + termRiskBps + concentrationRiskBps - collateralCreditBps;
  const defaultProbabilityBps = Math.max(25, Math.min(MAX_DEFAULT_PROBABILITY_BPS, raw));
  return { defaultProbabilityBps, grade: riskGrade(defaultProbabilityBps), observationCount, termDays, components };
}

export function calculateInsuranceCoverage(
  risk: InvoiceRiskInput,
  assessment: InsuranceRiskAssessment,
  pricing: InsurancePricingInput,
): InsuranceCoverageCalculation {
  validateAssessment(risk, assessment);
  const normalizedPricing = normalizePricing(pricing);
  const principal = requireBaseUnits(risk.invoicePrincipalBaseUnits, "Invoice principal");
  const coverageLimitBaseUnits = principal * BigInt(normalizedPricing.coverageBps) / BPS_DENOMINATOR;
  const deductibleBaseUnits = principal * BigInt(normalizedPricing.deductibleBps) / BPS_DENOMINATOR;
  if (coverageLimitBaseUnits <= deductibleBaseUnits) throw new Error("Coverage must exceed the deductible.");
  const maximumPayoutBaseUnits = coverageLimitBaseUnits - deductibleBaseUnits;
  const expectedLossBaseUnits = mulDivCeil(maximumPayoutBaseUnits, BigInt(assessment.defaultProbabilityBps), BPS_DENOMINATOR);
  const reserveLoadingBaseUnits = mulDivCeil(expectedLossBaseUnits, BigInt(normalizedPricing.reserveLoadingBps), BPS_DENOMINATOR);
  const protocolFeeBaseUnits = mulDivCeil(maximumPayoutBaseUnits, BigInt(normalizedPricing.protocolFeeBps), BPS_DENOMINATOR);
  const premiumBaseUnits = expectedLossBaseUnits + reserveLoadingBaseUnits + protocolFeeBaseUnits;
  if (premiumBaseUnits <= 0n || premiumBaseUnits >= principal || premiumBaseUnits > U128_MAX) throw new Error("Calculated premium is outside the supported STRK20 range.");
  const capitalReserve = requireBaseUnits(normalizedPricing.capitalReserveBaseUnits, "Capital reserve");
  const existingExposure = requireUnsignedBaseUnits(normalizedPricing.existingPoolExposureBaseUnits, "Existing pool exposure");
  const postBindExposureBaseUnits = existingExposure + maximumPayoutBaseUnits;
  if (postBindExposureBaseUnits > U128_MAX) throw new Error("Post-bind exposure exceeds the STRK20 u128 range.");
  const capitalRequirementBaseUnits = mulDivCeil(postBindExposureBaseUnits, BigInt(normalizedPricing.minimumSolvencyBps), BPS_DENOMINATOR);
  if (capitalReserve < capitalRequirementBaseUnits) throw new Error("Insurance reserve fails the configured post-bind solvency requirement.");
  const remainingCapitalBufferBaseUnits = capitalReserve - capitalRequirementBaseUnits;
  const postBindUtilizationBps = Number(postBindExposureBaseUnits * BPS_DENOMINATOR / capitalReserve);
  return {
    coverageLimitBaseUnits,
    deductibleBaseUnits,
    maximumPayoutBaseUnits,
    expectedLossBaseUnits,
    reserveLoadingBaseUnits,
    protocolFeeBaseUnits,
    premiumBaseUnits,
    postBindExposureBaseUnits,
    capitalRequirementBaseUnits,
    remainingCapitalBufferBaseUnits,
    postBindUtilizationBps,
  };
}

export function createInsurancePolicy(
  input: CreateInsurancePolicyInput,
  now = new Date(),
  entropy: InsuranceEntropy = {},
): InsurancePolicyBundle {
  const risk = normalizeRiskInput(input.risk, now);
  const pricing = normalizePricing(input.pricing);
  const assessment = assessInvoiceRisk(risk, now);
  const calculation = calculateInsuranceCoverage(risk, assessment, pricing);
  const tokenAddress = normalizeStarknetAddress(input.tokenAddress);
  const merchantPayoutAddress = normalizeStarknetAddress(input.merchantPayoutAddress);
  const insurerReserveAddress = normalizeStarknetAddress(input.insurerReserveAddress);
  if (merchantPayoutAddress === insurerReserveAddress) throw new Error("Merchant payout and insurer reserve addresses must differ.");
  const claimsPublicKey = pointToFelts(pointFromFelts(input.claimsPublicKey));
  const policyId = entropy.createId?.() ?? `ins_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!/^ins_[A-Za-z0-9_-]{1,48}$/.test(policyId)) throw new Error("Insurance policy ID is invalid.");
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const opening: InsurancePolicyOpening = {
    riskSalt: toHex(randomFieldScalar(random)),
    coverageSalt: toHex(randomFieldScalar(random)),
    premiumSalt: toHex(randomFieldScalar(random)),
    policySalt: toHex(randomFieldScalar(random)),
  };
  const coverageStartsAt = now.toISOString();
  const defaultEligibleAt = new Date(Date.parse(risk.dueAt) + pricing.claimGracePeriodDays * 86_400_000).toISOString();
  const claimDeadline = new Date(Date.parse(defaultEligibleAt) + pricing.claimWindowDays * 86_400_000).toISOString();
  const riskCommitment = computeRiskCommitment(risk, assessment, requireFieldScalar(opening.riskSalt, "Risk salt"));
  const coverageCommitment = computeCoverageCommitment(risk, pricing, calculation, requireFieldScalar(opening.coverageSalt, "Coverage salt"));
  const premiumCommitment = computePremiumCommitment(risk, calculation, insurerReserveAddress, requireFieldScalar(opening.premiumSalt, "Premium salt"));
  const core = {
    version: INSURANCE_ENGINE_VERSION,
    policyId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    tokenAddress,
    merchantPayoutAddress,
    insurerReserveAddress,
    claimsPublicKey,
    risk,
    assessment,
    pricing,
    coverageLimitBaseUnits: calculation.coverageLimitBaseUnits.toString(),
    deductibleBaseUnits: calculation.deductibleBaseUnits.toString(),
    maximumPayoutBaseUnits: calculation.maximumPayoutBaseUnits.toString(),
    expectedLossBaseUnits: calculation.expectedLossBaseUnits.toString(),
    reserveLoadingBaseUnits: calculation.reserveLoadingBaseUnits.toString(),
    protocolFeeBaseUnits: calculation.protocolFeeBaseUnits.toString(),
    premiumBaseUnits: calculation.premiumBaseUnits.toString(),
    postBindExposureBaseUnits: calculation.postBindExposureBaseUnits.toString(),
    capitalRequirementBaseUnits: calculation.capitalRequirementBaseUnits.toString(),
    remainingCapitalBufferBaseUnits: calculation.remainingCapitalBufferBaseUnits.toString(),
    postBindUtilizationBps: calculation.postBindUtilizationBps,
    coverageStartsAt,
    defaultEligibleAt,
    claimDeadline,
    riskCommitment: toHex(riskCommitment),
    coverageCommitment: toHex(coverageCommitment),
    premiumCommitment: toHex(premiumCommitment),
  } as const;
  const policyCommitment = computePolicyCommitment(core, requireFieldScalar(opening.policySalt, "Policy salt"));
  const policy: InsurancePolicy = {
    ...core,
    policyCommitment: toHex(policyCommitment),
    notice: "Client-side actuarial proposal with salted Poseidon commitments. It is not a zk-SNARK or a guarantee of coverage. Unavoidable premium custody and claims enforcement require an audited stateful STRK20 privacy_invoke helper with independent reserve and oracle governance.",
  };
  verifyInsurancePolicy({ policy, opening });
  return { policy, opening };
}

export function verifyInsurancePolicy(bundle: InsurancePolicyBundle): InsuranceCoverageCalculation {
  const { policy, opening } = bundle;
  validatePolicyHeader(policy);
  const assessment = assessInvoiceRisk(policy.risk, new Date(policy.coverageStartsAt));
  if (JSON.stringify(assessment) !== JSON.stringify(policy.assessment)) throw new Error("Insurance risk assessment does not reproduce.");
  const calculation = calculateInsuranceCoverage(policy.risk, assessment, policy.pricing);
  assertCalculationMatches(policy, calculation);
  const expectedEligibleAt = new Date(Date.parse(policy.risk.dueAt) + policy.pricing.claimGracePeriodDays * 86_400_000).toISOString();
  const expectedDeadline = new Date(Date.parse(expectedEligibleAt) + policy.pricing.claimWindowDays * 86_400_000).toISOString();
  if (policy.defaultEligibleAt !== expectedEligibleAt || policy.claimDeadline !== expectedDeadline) throw new Error("Insurance claim window is invalid.");
  const riskCommitment = computeRiskCommitment(policy.risk, assessment, requireFieldScalar(opening.riskSalt, "Risk salt"));
  const coverageCommitment = computeCoverageCommitment(policy.risk, policy.pricing, calculation, requireFieldScalar(opening.coverageSalt, "Coverage salt"));
  const premiumCommitment = computePremiumCommitment(policy.risk, calculation, policy.insurerReserveAddress, requireFieldScalar(opening.premiumSalt, "Premium salt"));
  if (policy.riskCommitment !== toHex(riskCommitment) || policy.coverageCommitment !== toHex(coverageCommitment) || policy.premiumCommitment !== toHex(premiumCommitment)) {
    throw new Error("Insurance policy opening does not match its component commitments.");
  }
  const policyCommitment = computePolicyCommitment(policy, requireFieldScalar(opening.policySalt, "Policy salt"));
  if (policy.policyCommitment !== toHex(policyCommitment)) throw new Error("Insurance policy commitment does not match its opening.");
  return calculation;
}

export function getPublicInsuranceCommitment(bundle: InsurancePolicyBundle): PublicInsuranceCommitment {
  verifyInsurancePolicy(bundle);
  const { policy } = bundle;
  return {
    version: policy.version,
    network: policy.network,
    poolAddress: policy.poolAddress,
    riskCommitment: policy.riskCommitment,
    coverageCommitment: policy.coverageCommitment,
    premiumCommitment: policy.premiumCommitment,
    policyCommitment: policy.policyCommitment,
    coverageStartsAt: policy.coverageStartsAt,
    claimDeadline: policy.claimDeadline,
    notice: "Opaque insurance commitments only. Risk factors, invoice identity, premium, coverage, addresses, and claim facts require the private opening.",
  };
}

export function serializePublicInsuranceCommitment(bundle: InsurancePolicyBundle): string {
  return JSON.stringify(getPublicInsuranceCommitment(bundle), null, 2);
}

/** Private funding transfer for prototypes. This pays a reserve address but is not non-custodial escrow. */
export function buildDirectPremiumFundingActions(bundle: InsurancePolicyBundle): STRK20_ACTION[] {
  verifyInsurancePolicy(bundle);
  return [{
    type: "transfer",
    token: bundle.policy.tokenAddress,
    amount: bundle.policy.premiumBaseUnits,
    recipient: bundle.policy.insurerReserveAddress,
  }];
}

/** Exact audited helper ABI stays caller-supplied; the deposit leg must return an empty OpenNoteDeposit span. */
export function buildInsuranceHelperPremiumActions(bundle: InsurancePolicyBundle, encoder: InsuranceHelperEncoder): STRK20_ACTION[] {
  verifyInsurancePolicy(bundle);
  const contractAddress = normalizeStarknetAddress(encoder.contractAddress);
  const calldata = encoder.encodePremiumEscrow({
    policyCommitment: bundle.policy.policyCommitment,
    tokenAddress: bundle.policy.tokenAddress,
    premiumBaseUnits: bundle.policy.premiumBaseUnits,
    maximumPayoutBaseUnits: bundle.policy.maximumPayoutBaseUnits,
    claimDeadlineSeconds: toHex(BigInt(Math.floor(Date.parse(bundle.policy.claimDeadline) / 1_000))),
    claimsPublicKey: bundle.policy.claimsPublicKey,
    poolAddress: "${poolAddress}",
  });
  validateCalldata(calldata, "Insurance premium helper");
  return [{ type: "invoke", contract: contractAddress, calldata }];
}

export function createDefaultClaim(
  policyBundle: InsurancePolicyBundle,
  input: { defaultLossBaseUnits: string; reason: InsuranceClaimReason; evidenceDigests: string[] },
  now = new Date(),
  entropy: Pick<InsuranceEntropy, "randomBytes"> = {},
): InsuranceClaimBundle {
  verifyInsurancePolicy(policyBundle);
  const policy = policyBundle.policy;
  const nowMs = now.getTime();
  if (nowMs < Date.parse(policy.defaultEligibleAt) || nowMs > Date.parse(policy.claimDeadline)) throw new Error("Insurance claim window is not active.");
  const defaultLoss = requireBaseUnits(input.defaultLossBaseUnits, "Default loss");
  const reason = requireClaimReason(input.reason);
  const evidenceDigests = normalizeEvidenceDigests(input.evidenceDigests);
  const coveredLoss = defaultLoss < BigInt(policy.coverageLimitBaseUnits) ? defaultLoss : BigInt(policy.coverageLimitBaseUnits);
  const deductible = BigInt(policy.deductibleBaseUnits);
  if (coveredLoss <= deductible) throw new Error("Covered loss does not exceed the policy deductible.");
  const payout = coveredLoss - deductible;
  if (payout > BigInt(policy.maximumPayoutBaseUnits)) throw new Error("Claim payout exceeds the policy maximum.");
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const claimSalt = randomFieldScalar(random);
  const filedAt = now.toISOString();
  const claimCommitment = computeClaimCommitment(policy, defaultLoss, payout, reason, evidenceDigests, filedAt, claimSalt);
  return {
    commitment: {
      version: INSURANCE_ENGINE_VERSION,
      network: MAINNET_CHAIN_ID,
      poolAddress: STRK20_POOL_ADDRESS,
      policyCommitment: policy.policyCommitment,
      claimCommitment: toHex(claimCommitment),
      filedAt,
      notice: "Hiding claim commitment. The public object omits loss amount, payout, reason, evidence digests, invoice identity, and addresses; it is not an oracle attestation or zk-SNARK.",
    },
    opening: {
      policyId: policy.policyId,
      defaultLossBaseUnits: defaultLoss.toString(),
      payoutBaseUnits: payout.toString(),
      reason,
      evidenceDigests,
      claimSalt: toHex(claimSalt),
    },
  };
}

export function verifyDefaultClaim(policyBundle: InsurancePolicyBundle, claim: InsuranceClaimBundle): bigint {
  verifyInsurancePolicy(policyBundle);
  const policy = policyBundle.policy;
  if (!claim || claim.commitment.version !== INSURANCE_ENGINE_VERSION || claim.commitment.network !== MAINNET_CHAIN_ID || claim.commitment.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("Insurance claim header is invalid.");
  if (claim.commitment.policyCommitment !== policy.policyCommitment || claim.opening.policyId !== policy.policyId) throw new Error("Insurance claim does not match this policy.");
  const filedAt = requireIsoTimestamp(claim.commitment.filedAt, "Claim filing time");
  if (Date.parse(filedAt) < Date.parse(policy.defaultEligibleAt) || Date.parse(filedAt) > Date.parse(policy.claimDeadline)) throw new Error("Insurance claim was filed outside its claim window.");
  const defaultLoss = requireBaseUnits(claim.opening.defaultLossBaseUnits, "Default loss");
  const payout = requireBaseUnits(claim.opening.payoutBaseUnits, "Claim payout");
  const coveredLoss = defaultLoss < BigInt(policy.coverageLimitBaseUnits) ? defaultLoss : BigInt(policy.coverageLimitBaseUnits);
  const expectedPayout = coveredLoss - BigInt(policy.deductibleBaseUnits);
  if (expectedPayout <= 0n || payout !== expectedPayout || payout > BigInt(policy.maximumPayoutBaseUnits)) throw new Error("Insurance claim payout arithmetic is invalid.");
  const reason = requireClaimReason(claim.opening.reason);
  const evidenceDigests = normalizeEvidenceDigests(claim.opening.evidenceDigests);
  const expected = computeClaimCommitment(policy, defaultLoss, payout, reason, evidenceDigests, filedAt, requireFieldScalar(claim.opening.claimSalt, "Claim salt"));
  if (claim.commitment.claimCommitment !== toHex(expected)) throw new Error("Insurance claim commitment does not match its opening.");
  return payout;
}

export function authorizeInsuranceClaim(
  policyBundle: InsurancePolicyBundle,
  claim: InsuranceClaimBundle,
  decision: InsuranceClaimDecision,
  claimsPrivateKey: string,
  now = new Date(),
  entropy: Pick<InsuranceEntropy, "signatureNonce"> = {},
): InsuranceClaimAuthorization {
  const payout = verifyDefaultClaim(policyBundle, claim);
  if (decision !== "approved" && decision !== "denied") throw new Error("Insurance claim decision is invalid.");
  const privateKey = requireCurveScalar(claimsPrivateKey, false, "Claims authority private key");
  const publicKey = ec.starkCurve.ProjectivePoint.BASE.multiply(privateKey);
  if (!publicKey.equals(pointFromFelts(policyBundle.policy.claimsPublicKey))) throw new Error("Claims private key does not match the policy authority.");
  const nonce = requireSecretScalar(entropy.signatureNonce ?? randomCurveScalar(), "Claim authorization nonce");
  const noncePoint = ec.starkCurve.ProjectivePoint.BASE.multiply(nonce);
  const decidedAt = now.toISOString();
  const authorizedPayout = decision === "approved" ? payout : 0n;
  const challenge = approvalChallenge(policyBundle.policy, claim, decision, authorizedPayout, decidedAt, publicKey, noncePoint);
  const response = mod(nonce + challenge * privateKey, CURVE_ORDER);
  return {
    version: INSURANCE_ENGINE_VERSION,
    policyCommitment: policyBundle.policy.policyCommitment,
    claimCommitment: claim.commitment.claimCommitment,
    decision,
    payoutBaseUnits: authorizedPayout.toString(),
    decidedAt,
    nonceCommitment: pointToFelts(noncePoint),
    response: toHex(response),
  };
}

export function verifyInsuranceClaimAuthorization(
  policyBundle: InsurancePolicyBundle,
  claim: InsuranceClaimBundle,
  authorization: InsuranceClaimAuthorization,
): boolean {
  try {
    const payout = verifyDefaultClaim(policyBundle, claim);
    if (authorization.version !== INSURANCE_ENGINE_VERSION || authorization.policyCommitment !== policyBundle.policy.policyCommitment || authorization.claimCommitment !== claim.commitment.claimCommitment) return false;
    if (authorization.decision !== "approved" && authorization.decision !== "denied") return false;
    const expectedPayout = authorization.decision === "approved" ? payout : 0n;
    if (authorization.payoutBaseUnits !== expectedPayout.toString()) return false;
    const decidedAt = requireIsoTimestamp(authorization.decidedAt, "Claim decision time");
    if (Date.parse(decidedAt) < Date.parse(claim.commitment.filedAt) || Date.parse(decidedAt) > Date.parse(policyBundle.policy.claimDeadline)) return false;
    const publicKey = pointFromFelts(policyBundle.policy.claimsPublicKey);
    const noncePoint = pointFromFelts(authorization.nonceCommitment);
    const response = requireCurveScalar(authorization.response, true, "Claim authorization response");
    const challenge = approvalChallenge(policyBundle.policy, claim, authorization.decision, expectedPayout, decidedAt, publicKey, noncePoint);
    return ec.starkCurve.ProjectivePoint.BASE.multiply(response).equals(noncePoint.add(publicKey.multiply(challenge)));
  } catch { return false; }
}

/** Requires a valid independent authority signature. The connected wallet must control the insurer reserve. */
export function buildDirectClaimPayoutActions(
  policyBundle: InsurancePolicyBundle,
  claim: InsuranceClaimBundle,
  authorization: InsuranceClaimAuthorization,
): STRK20_ACTION[] {
  if (!verifyInsuranceClaimAuthorization(policyBundle, claim, authorization) || authorization.decision !== "approved") throw new Error("Approved insurance claim authorization is invalid.");
  return [{
    type: "transfer",
    token: policyBundle.policy.tokenAddress,
    amount: authorization.payoutBaseUnits,
    recipient: policyBundle.policy.merchantPayoutAddress,
  }];
}

/** Open-note payout amount is public. The audited helper must pin the pool and prevent double claims. */
export function buildInsuranceHelperClaimActions(
  policyBundle: InsurancePolicyBundle,
  claim: InsuranceClaimBundle,
  authorization: InsuranceClaimAuthorization,
  encoder: InsuranceHelperEncoder,
): STRK20_ACTION[] {
  if (!verifyInsuranceClaimAuthorization(policyBundle, claim, authorization) || authorization.decision !== "approved") throw new Error("Approved insurance claim authorization is invalid.");
  const contractAddress = normalizeStarknetAddress(encoder.contractAddress);
  const calldata = encoder.encodeClaimPayout({
    policyCommitment: policyBundle.policy.policyCommitment,
    claimCommitment: claim.commitment.claimCommitment,
    payoutBaseUnits: authorization.payoutBaseUnits,
    authorization,
    openNoteId: "${openNoteIds[0]}",
    poolAddress: "${poolAddress}",
  });
  validateCalldata(calldata, "Insurance claim helper");
  return [
    { type: "transfer", token: policyBundle.policy.tokenAddress, amount: "OPEN", recipient: contractAddress },
    { type: "invoke", contract: contractAddress, calldata },
  ];
}

export function getInsuranceSecurityModel(): InsuranceSecurityModel {
  return {
    provenLocally: [
      "The deterministic risk score and bigint coverage arithmetic reproduce from the private opening.",
      "Premium components conserve expected loss, reserve loading, and protocol fee exactly.",
      "An approved payout is capped by coverage minus deductible and carries a Stark-curve authority signature.",
    ],
    hiddenByCommitments: ["Invoice identity and risk history", "Coverage, deductible, premium, and reserve inputs", "Claim reason, loss, payout, and evidence digests"],
    hiddenByStrk20: ["Ordinary in-pool premium sender, reserve recipient, token, and amount", "Ordinary in-pool payout sender, merchant recipient, token, and amount", "Spent-note linkage and encrypted note values"],
    limitations: [
      "Salted Poseidon commitments are commit-reveal proofs, not zk-SNARKs and not oracle attestations.",
      "Direct premium funding transfers custody to the reserve; it is not non-custodial escrow.",
      "Unavoidable reserve custody, policy activation, solvency, claim windows, and double-claim prevention require an independently audited stateful privacy_invoke helper.",
      "Helper claim outputs use open notes, whose token and amount are public. Deposits, withdrawals, timing, fees, nullifiers, and correlation also remain observable.",
    ],
  };
}

function normalizeRiskInput(input: InvoiceRiskInput, assessedAt: Date): InvoiceRiskInput {
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  const invoicePrincipalBaseUnits = requireBaseUnits(input.invoicePrincipalBaseUnits, "Invoice principal").toString();
  const dueAt = requireIsoTimestamp(input.dueAt, "Invoice due time");
  if (!Number.isFinite(assessedAt.getTime()) || Date.parse(dueAt) <= assessedAt.getTime() || Date.parse(dueAt) - assessedAt.getTime() > 365 * 86_400_000) throw new Error("Insurance assessment requires a future due date within one year.");
  return {
    invoiceId,
    invoicePrincipalBaseUnits,
    dueAt,
    counterpartyTenureDays: requireBoundedInteger(input.counterpartyTenureDays, "Counterparty tenure", 0, 36_500),
    successfulSettlements: requireBoundedInteger(input.successfulSettlements, "Successful settlements", 0, 100_000),
    lateSettlements: requireBoundedInteger(input.lateSettlements, "Late settlements", 0, 100_000),
    disputedSettlements: requireBoundedInteger(input.disputedSettlements, "Disputed settlements", 0, 100_000),
    concentrationBps: requireBps(input.concentrationBps, "Portfolio concentration"),
    collateralBps: requireBps(input.collateralBps, "Collateral coverage"),
  };
}

function normalizePricing(input: InsurancePricingInput): InsurancePricingInput {
  const coverageBps = requireBoundedInteger(input.coverageBps, "Coverage", 1_000, 10_000);
  const deductibleBps = requireBoundedInteger(input.deductibleBps, "Deductible", 0, 9_000);
  if (deductibleBps >= coverageBps) throw new Error("Deductible must be below coverage.");
  return {
    coverageBps,
    deductibleBps,
    reserveLoadingBps: requireBoundedInteger(input.reserveLoadingBps, "Reserve loading", 0, 10_000),
    protocolFeeBps: requireBoundedInteger(input.protocolFeeBps, "Protocol fee", 0, 2_000),
    capitalReserveBaseUnits: requireBaseUnits(input.capitalReserveBaseUnits, "Capital reserve").toString(),
    existingPoolExposureBaseUnits: requireUnsignedBaseUnits(input.existingPoolExposureBaseUnits, "Existing pool exposure").toString(),
    minimumSolvencyBps: requireBoundedInteger(input.minimumSolvencyBps, "Minimum solvency", 10_000, 30_000),
    claimGracePeriodDays: requireBoundedInteger(input.claimGracePeriodDays, "Claim grace period", 0, 90),
    claimWindowDays: requireBoundedInteger(input.claimWindowDays, "Claim window", 1, 180),
  };
}

function validateAssessment(risk: InvoiceRiskInput, assessment: InsuranceRiskAssessment): void {
  if (!assessment || !Number.isInteger(assessment.defaultProbabilityBps) || assessment.defaultProbabilityBps < 25 || assessment.defaultProbabilityBps > MAX_DEFAULT_PROBABILITY_BPS) throw new Error("Insurance risk assessment is invalid.");
  if (riskGrade(assessment.defaultProbabilityBps) !== assessment.grade) throw new Error("Insurance risk grade does not match its probability.");
}

function validatePolicyHeader(policy: InsurancePolicy): void {
  if (!policy || policy.version !== INSURANCE_ENGINE_VERSION || policy.network !== MAINNET_CHAIN_ID || policy.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("Insurance policy header is invalid.");
  if (!/^ins_[A-Za-z0-9_-]{1,48}$/.test(policy.policyId)) throw new Error("Insurance policy ID is invalid.");
  normalizeStarknetAddress(policy.tokenAddress);
  normalizeStarknetAddress(policy.merchantPayoutAddress);
  normalizeStarknetAddress(policy.insurerReserveAddress);
  pointFromFelts(policy.claimsPublicKey);
  requireIsoTimestamp(policy.coverageStartsAt, "Coverage start");
  requireIsoTimestamp(policy.defaultEligibleAt, "Default eligibility time");
  requireIsoTimestamp(policy.claimDeadline, "Claim deadline");
  for (const [value, label] of [[policy.riskCommitment, "Risk commitment"], [policy.coverageCommitment, "Coverage commitment"], [policy.premiumCommitment, "Premium commitment"], [policy.policyCommitment, "Policy commitment"]] as const) requireFelt(value, label);
}

function assertCalculationMatches(policy: InsurancePolicy, calculation: InsuranceCoverageCalculation): void {
  const fields: Array<[keyof InsurancePolicy, bigint]> = [
    ["coverageLimitBaseUnits", calculation.coverageLimitBaseUnits],
    ["deductibleBaseUnits", calculation.deductibleBaseUnits],
    ["maximumPayoutBaseUnits", calculation.maximumPayoutBaseUnits],
    ["expectedLossBaseUnits", calculation.expectedLossBaseUnits],
    ["reserveLoadingBaseUnits", calculation.reserveLoadingBaseUnits],
    ["protocolFeeBaseUnits", calculation.protocolFeeBaseUnits],
    ["premiumBaseUnits", calculation.premiumBaseUnits],
    ["postBindExposureBaseUnits", calculation.postBindExposureBaseUnits],
    ["capitalRequirementBaseUnits", calculation.capitalRequirementBaseUnits],
    ["remainingCapitalBufferBaseUnits", calculation.remainingCapitalBufferBaseUnits],
  ];
  if (fields.some(([field, expected]) => policy[field] !== expected.toString()) || policy.postBindUtilizationBps !== calculation.postBindUtilizationBps) throw new Error("Insurance coverage calculation does not reproduce.");
}

function computeRiskCommitment(risk: InvoiceRiskInput, assessment: InsuranceRiskAssessment, salt: bigint): bigint {
  return hashElements([
    RISK_DOMAIN, hash.starknetKeccak(risk.invoiceId), BigInt(risk.invoicePrincipalBaseUnits), timestampMs(risk.dueAt),
    BigInt(risk.counterpartyTenureDays), BigInt(risk.successfulSettlements), BigInt(risk.lateSettlements), BigInt(risk.disputedSettlements),
    BigInt(risk.concentrationBps), BigInt(risk.collateralBps), BigInt(assessment.defaultProbabilityBps), gradeCode(assessment.grade), salt,
  ]);
}

function computeCoverageCommitment(risk: InvoiceRiskInput, pricing: InsurancePricingInput, calculation: InsuranceCoverageCalculation, salt: bigint): bigint {
  return hashElements([
    COVERAGE_DOMAIN, hash.starknetKeccak(risk.invoiceId), BigInt(pricing.coverageBps), BigInt(pricing.deductibleBps),
    calculation.coverageLimitBaseUnits, calculation.deductibleBaseUnits, calculation.maximumPayoutBaseUnits,
    calculation.postBindExposureBaseUnits, calculation.capitalRequirementBaseUnits, BigInt(calculation.postBindUtilizationBps), salt,
  ]);
}

function computePremiumCommitment(risk: InvoiceRiskInput, calculation: InsuranceCoverageCalculation, reserveAddress: string, salt: bigint): bigint {
  return hashElements([
    PREMIUM_DOMAIN, hash.starknetKeccak(risk.invoiceId), calculation.expectedLossBaseUnits, calculation.reserveLoadingBaseUnits,
    calculation.protocolFeeBaseUnits, calculation.premiumBaseUnits, BigInt(reserveAddress), salt,
  ]);
}

function computePolicyCommitment(policy: Omit<InsurancePolicy, "policyCommitment" | "notice"> | InsurancePolicy, salt: bigint): bigint {
  return hashElements([
    POLICY_DOMAIN, hash.starknetKeccak(policy.policyId), BigInt(policy.tokenAddress), BigInt(policy.merchantPayoutAddress), BigInt(policy.insurerReserveAddress),
    BigInt(policy.claimsPublicKey.x), BigInt(policy.claimsPublicKey.y), BigInt(policy.riskCommitment), BigInt(policy.coverageCommitment), BigInt(policy.premiumCommitment),
    timestampMs(policy.coverageStartsAt), timestampMs(policy.defaultEligibleAt), timestampMs(policy.claimDeadline), salt,
  ]);
}

function computeClaimCommitment(
  policy: InsurancePolicy,
  defaultLoss: bigint,
  payout: bigint,
  reason: InsuranceClaimReason,
  evidenceDigests: string[],
  filedAt: string,
  salt: bigint,
): bigint {
  return hashElements([
    CLAIM_DOMAIN, BigInt(policy.policyCommitment), defaultLoss, payout, claimReasonCode(reason),
    ...evidenceDigests.map((digest) => hash.starknetKeccak(digest)), timestampMs(filedAt), salt,
  ]);
}

function approvalChallenge(
  policy: InsurancePolicy,
  claim: InsuranceClaimBundle,
  decision: InsuranceClaimDecision,
  payout: bigint,
  decidedAt: string,
  publicKey: ReturnType<typeof pointFromFelts>,
  noncePoint: ReturnType<typeof pointFromFelts>,
): bigint {
  return mod(hashElements([
    APPROVAL_DOMAIN, BigInt(policy.policyCommitment), BigInt(claim.commitment.claimCommitment), decision === "approved" ? 1n : 0n,
    payout, timestampMs(decidedAt), publicKey.x, publicKey.y, noncePoint.x, noncePoint.y,
  ]), CURVE_ORDER);
}

function normalizeEvidenceDigests(values: string[]): string[] {
  if (!Array.isArray(values) || !values.length || values.length > MAX_CLAIM_EVIDENCE_DIGESTS) throw new Error(`Claim requires 1 to ${MAX_CLAIM_EVIDENCE_DIGESTS} evidence digests.`);
  const normalized = values.map((value) => requireText(value, "Evidence digest", 100, /^(sha256:)?[A-Za-z0-9_-]{20,}$/));
  if (new Set(normalized).size !== normalized.length) throw new Error("Claim evidence digests must be unique.");
  return normalized;
}

function validateCalldata(calldata: string[], label: string): void {
  if (!Array.isArray(calldata) || !calldata.length || calldata.some((item) => typeof item !== "string" || !item)) throw new Error(`${label} encoder returned invalid calldata.`);
}

function riskGrade(bps: number): InsuranceRiskGrade {
  return bps <= 100 ? "A" : bps <= 250 ? "B" : bps <= 600 ? "C" : bps <= 1_200 ? "D" : "E";
}

function gradeCode(grade: InsuranceRiskGrade): bigint { return BigInt(["A", "B", "C", "D", "E"].indexOf(grade) + 1); }
function claimReasonCode(reason: InsuranceClaimReason): bigint { return reason === "nonpayment" ? 1n : reason === "counterparty_insolvency" ? 2n : 3n; }

function requireClaimReason(value: InsuranceClaimReason): InsuranceClaimReason {
  if (value !== "nonpayment" && value !== "counterparty_insolvency" && value !== "arbitration_award") throw new Error("Insurance claim reason is invalid.");
  return value;
}

function requireText(value: string, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireBaseUnits(value: string, label: string): bigint {
  const parsed = requireUnsignedBaseUnits(value, label);
  if (parsed <= 0n) throw new Error(`${label} must be positive.`);
  return parsed;
}

function requireUnsignedBaseUnits(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an unsigned base-unit integer.`);
  const parsed = BigInt(value);
  if (parsed > U128_MAX) throw new Error(`${label} exceeds the STRK20 u128 range.`);
  return parsed;
}

function requireBps(value: number, label: string): number { return requireBoundedInteger(value, label, 0, 10_000); }

function requireBoundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${label} must be a whole number from ${minimum} to ${maximum}.`);
  return value;
}

function requireFelt(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is not a felt.`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error(`${label} is outside the Stark field.`);
  return parsed;
}

function requireFieldScalar(value: string, label: string): bigint {
  const parsed = requireFelt(value, label);
  if (parsed === 0n) throw new Error(`${label} must be non-zero.`);
  return parsed;
}

function requireCurveScalar(value: string, allowZero: boolean, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is invalid.`);
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return parsed;
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return value;
}

function pointToFelts(point: ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>): CurvePointFelts { return { x: toHex(point.x), y: toHex(point.y) }; }

function pointFromFelts(point: CurvePointFelts) {
  if (!point || typeof point !== "object") throw new Error("Insurance claims public key is invalid.");
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, "Claims public key"), y: requireFelt(point.y, "Claims public key") });
  parsed.assertValidity();
  return parsed;
}

function randomCurveScalar(): bigint { return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey()); }

function randomFieldScalar(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  const bytes = random(new Uint8Array(32));
  if (bytes.length !== 32) throw new Error("Insurance entropy returned an invalid byte length.");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value % (FIELD_PRIME - 1n) + 1n;
}

function timestampMs(value: string): bigint { return BigInt(Date.parse(requireIsoTimestamp(value, "Timestamp"))); }
function mulDivCeil(value: bigint, numerator: bigint, denominator: bigint): bigint { return (value * numerator + denominator - 1n) / denominator; }
function hashElements(values: bigint[]): bigint { return BigInt(hash.computePoseidonHashOnElements(values)); }
function mod(value: bigint, modulus: bigint): bigint { const remainder = value % modulus; return remainder >= 0n ? remainder : remainder + modulus; }
function toHex(value: bigint): string { return `0x${value.toString(16)}`; }
