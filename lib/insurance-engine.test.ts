import { describe, expect, it } from "vitest";

import {
  assessInvoiceRisk,
  authorizeInsuranceClaim,
  buildDirectClaimPayoutActions,
  buildDirectPremiumFundingActions,
  buildInsuranceHelperClaimActions,
  buildInsuranceHelperPremiumActions,
  calculateInsuranceCoverage,
  createDefaultClaim,
  createInsurancePolicy,
  generateInsuranceAuthorityKeypair,
  getInsuranceSecurityModel,
  INSURANCE_POOL_ADDRESS,
  serializePublicInsuranceCommitment,
  verifyDefaultClaim,
  verifyInsuranceClaimAuthorization,
  verifyInsurancePolicy,
  type CreateInsurancePolicyInput,
  type InsuranceHelperEncoder,
} from "./insurance-engine";

const now = new Date("2026-08-22T00:00:00.000Z");
const authority = generateInsuranceAuthorityKeypair({ privateKey: 123456789n });
const input: CreateInsurancePolicyInput = {
  risk: {
    invoiceId: "inv_insurance_001",
    invoicePrincipalBaseUnits: "10000000000000000000000",
    dueAt: "2026-09-01T00:00:00.000Z",
    counterpartyTenureDays: 400,
    successfulSettlements: 20,
    lateSettlements: 3,
    disputedSettlements: 2,
    concentrationBps: 4_000,
    collateralBps: 5_000,
  },
  pricing: {
    coverageBps: 8_000,
    deductibleBps: 1_000,
    reserveLoadingBps: 2_500,
    protocolFeeBps: 50,
    capitalReserveBaseUnits: "100000000000000000000000",
    existingPoolExposureBaseUnits: "20000000000000000000000",
    minimumSolvencyBps: 15_000,
    claimGracePeriodDays: 7,
    claimWindowDays: 30,
  },
  tokenAddress: "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  merchantPayoutAddress: "0x1234",
  insurerReserveAddress: "0x5678",
  claimsPublicKey: authority.publicKey,
};

const deterministicEntropy = {
  createId: () => "ins_test_policy",
  randomBytes: (target: Uint8Array<ArrayBuffer>) => target.fill(7),
};

function policy() {
  return createInsurancePolicy(input, now, deterministicEntropy);
}

function helperEncoder(): InsuranceHelperEncoder {
  return {
    contractAddress: "0x9999",
    encodePremiumEscrow: (value) => ["0x1", value.policyCommitment, value.premiumBaseUnits, value.poolAddress],
    encodeClaimPayout: (value) => ["0x2", value.claimCommitment, value.payoutBaseUnits, value.openNoteId, value.poolAddress],
  };
}

describe("anonymous invoice insurance engine", () => {
  it("produces a transparent bounded actuarial score", () => {
    const assessment = assessInvoiceRisk(input.risk, now);
    expect(assessment).toMatchObject({ defaultProbabilityBps: 595, grade: "C", observationCount: 25, termDays: 10 });
    expect(assessment.components).toMatchObject({ lateHistoryBps: 300, disputeHistoryBps: 280, concentrationRiskBps: 400, collateralCreditBps: 500 });
  });

  it("calculates bigint-exact premium, payout, and solvency values", () => {
    const assessment = assessInvoiceRisk(input.risk, now);
    const calculation = calculateInsuranceCoverage(input.risk, assessment, input.pricing);
    expect(calculation.coverageLimitBaseUnits).toBe(8000000000000000000000n);
    expect(calculation.deductibleBaseUnits).toBe(1000000000000000000000n);
    expect(calculation.maximumPayoutBaseUnits).toBe(7000000000000000000000n);
    expect(calculation.expectedLossBaseUnits).toBe(416500000000000000000n);
    expect(calculation.reserveLoadingBaseUnits).toBe(104125000000000000000n);
    expect(calculation.protocolFeeBaseUnits).toBe(35000000000000000000n);
    expect(calculation.premiumBaseUnits).toBe(555625000000000000000n);
    expect(calculation.capitalRequirementBaseUnits).toBe(40500000000000000000000n);
  });

  it("rejects a pool that fails its post-bind capital requirement", () => {
    const assessment = assessInvoiceRisk(input.risk, now);
    expect(() => calculateInsuranceCoverage(input.risk, assessment, { ...input.pricing, capitalReserveBaseUnits: "40000000000000000000000" })).toThrow(/solvency/i);
  });

  it("creates hiding component commitments and verifies their openings", () => {
    const bundle = policy();
    expect(verifyInsurancePolicy(bundle).premiumBaseUnits.toString()).toBe(bundle.policy.premiumBaseUnits);
    expect(bundle.policy).toMatchObject({
      policyId: "ins_test_policy",
      poolAddress: INSURANCE_POOL_ADDRESS,
      riskCommitment: expect.stringMatching(/^0x/),
      defaultEligibleAt: "2026-09-08T00:00:00.000Z",
      claimDeadline: "2026-10-08T00:00:00.000Z",
    });
    const publicJson = serializePublicInsuranceCommitment(bundle);
    expect(publicJson).not.toContain(input.risk.invoiceId);
    expect(publicJson).not.toContain(input.risk.invoicePrincipalBaseUnits);
    expect(publicJson).not.toContain(input.merchantPayoutAddress);
    expect(publicJson).not.toContain(bundle.policy.premiumBaseUnits);
  });

  it("detects policy tampering", () => {
    const tampered = structuredClone(policy());
    tampered.policy.premiumBaseUnits = (BigInt(tampered.policy.premiumBaseUnits) + 1n).toString();
    expect(() => verifyInsurancePolicy(tampered)).toThrow(/does not reproduce/i);
  });

  it("builds private direct funding and strict helper escrow plans", () => {
    const bundle = policy();
    expect(buildDirectPremiumFundingActions(bundle)).toEqual([{
      type: "transfer",
      token: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
      amount: bundle.policy.premiumBaseUnits,
      recipient: "0x0000000000000000000000000000000000000000000000000000000000005678",
    }]);
    expect(buildInsuranceHelperPremiumActions(bundle, helperEncoder())).toEqual([{
      type: "invoke",
      contract: "0x0000000000000000000000000000000000000000000000000000000000009999",
      calldata: ["0x1", bundle.policy.policyCommitment, bundle.policy.premiumBaseUnits, "${poolAddress}"],
    }]);
  });

  it("enforces claim timing, deductible, and evidence commitments", () => {
    const bundle = policy();
    expect(() => createDefaultClaim(bundle, {
      defaultLossBaseUnits: input.risk.invoicePrincipalBaseUnits,
      reason: "nonpayment",
      evidenceDigests: ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    }, new Date("2026-09-07T23:59:59.000Z"), deterministicEntropy)).toThrow(/not active/i);

    const claim = createDefaultClaim(bundle, {
      defaultLossBaseUnits: input.risk.invoicePrincipalBaseUnits,
      reason: "nonpayment",
      evidenceDigests: ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    }, new Date("2026-09-09T00:00:00.000Z"), deterministicEntropy);
    expect(verifyDefaultClaim(bundle, claim)).toBe(7000000000000000000000n);
    const tampered = structuredClone(claim);
    tampered.opening.reason = "counterparty_insolvency";
    expect(() => verifyDefaultClaim(bundle, tampered)).toThrow(/does not match/i);
  });

  it("requires a valid independent authority signature before payout", () => {
    const bundle = policy();
    const claim = createDefaultClaim(bundle, {
      defaultLossBaseUnits: input.risk.invoicePrincipalBaseUnits,
      reason: "nonpayment",
      evidenceDigests: ["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    }, new Date("2026-09-09T00:00:00.000Z"), deterministicEntropy);
    const authorization = authorizeInsuranceClaim(bundle, claim, "approved", authority.privateKey, new Date("2026-09-10T00:00:00.000Z"), { signatureNonce: 987654321n });
    expect(verifyInsuranceClaimAuthorization(bundle, claim, authorization)).toBe(true);
    expect(buildDirectClaimPayoutActions(bundle, claim, authorization)).toEqual([{
      type: "transfer",
      token: bundle.policy.tokenAddress,
      amount: "7000000000000000000000",
      recipient: bundle.policy.merchantPayoutAddress,
    }]);
    const helperActions = buildInsuranceHelperClaimActions(bundle, claim, authorization, helperEncoder());
    expect(helperActions[0]).toMatchObject({ type: "transfer", amount: "OPEN" });
    expect(helperActions[1]).toMatchObject({ type: "invoke", calldata: expect.arrayContaining(["${openNoteIds[0]}", "${poolAddress}"]) });

    const modified = { ...authorization, payoutBaseUnits: "1" };
    expect(verifyInsuranceClaimAuthorization(bundle, claim, modified)).toBe(false);
    expect(() => buildDirectClaimPayoutActions(bundle, claim, modified)).toThrow(/invalid/i);
  });

  it("refuses claim authorization from a mismatched key", () => {
    const bundle = policy();
    const claim = createDefaultClaim(bundle, {
      defaultLossBaseUnits: input.risk.invoicePrincipalBaseUnits,
      reason: "arbitration_award",
      evidenceDigests: ["sha256:ccccccccccccccccccccccccccccccccccccccccccc"],
    }, new Date("2026-09-09T00:00:00.000Z"), deterministicEntropy);
    const wrong = generateInsuranceAuthorityKeypair({ privateKey: 456789n });
    expect(() => authorizeInsuranceClaim(bundle, claim, "approved", wrong.privateKey, new Date("2026-09-10T00:00:00.000Z"))).toThrow(/does not match/i);
  });

  it("states direct custody, helper, open-note, and zk boundaries", () => {
    const model = getInsuranceSecurityModel();
    expect(model.limitations.join(" ")).toMatch(/not zk-SNARKs/i);
    expect(model.limitations.join(" ")).toMatch(/not non-custodial escrow/i);
    expect(model.limitations.join(" ")).toMatch(/open notes/i);
    expect(model.hiddenByStrk20.join(" ")).toMatch(/amount/i);
  });
});
