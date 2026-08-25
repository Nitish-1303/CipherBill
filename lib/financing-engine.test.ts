import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  assessFinancingRisk,
  buildFinancingAdvanceDisclosure,
  buildFinancingCertificateBadge,
  buildFinancingFinancierDisclosure,
  buildFinancingPayoutAccountDisclosure,
  buildFinancingRevenueDisclosure,
  computeCreditLimit,
  computeFinancingState,
  computeRepaymentSchedule,
  createFinancingIssuerKey,
  deriveFinancingGenerator,
  FINANCING_PROOF_SYSTEM,
  FINANCING_SURPLUS_EXTRA_BITS,
  formatAdvanceFactor,
  formatFeeRate,
  formatFinancingBaseUnits,
  formatInstallments,
  getFinancingVisibilityModel,
  issueFinancingCertificate,
  MAX_ADVANCE_FACTOR_BPS,
  parseFinancingAmountDisclosure,
  parseFinancingCertificate,
  parseFinancingCertificateSecret,
  parseFinancingRefDisclosure,
  requireFinancingPolicy,
  serializeFinancingAmountDisclosure,
  serializeFinancingCertificate,
  serializeFinancingCertificateSecret,
  serializeFinancingRefDisclosure,
  summarizeFinancingTrust,
  verifyFinancingAmountDisclosure,
  verifyFinancingCertificate,
  verifyFinancingCertificateOpening,
  verifyFinancingRefDisclosure,
  type FinancingCertificate,
  type FinancingCertificateOpening,
  type FinancingCertificateSecret,
  type FinancingPolicy,
  type IssueFinancingCertificateInput,
} from "./financing-engine";
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T00:00:00.000Z");
const PROOF_TIMEOUT = 60_000;

/** Deterministic, collision-free entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `fin_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createFinancingIssuerKey(makeEntropy(seed));
}
// A public 80% advance factor, 12% fee, 12 monthly installments.
const BASE_POLICY: FinancingPolicy = { advanceFactorBps: 8000, feeBps: 1200, installments: 12, intervalDays: 30 };

function baseInput(overrides: Partial<IssueFinancingCertificateInput> = {}): IssueFinancingCertificateInput {
  return {
    merchantAlias: "Aurora Studio",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    advanceRef: "ADV-2026-0007",
    programLabel: "Growth Advance",
    policy: BASE_POLICY,
    revenueBaseUnits: "1000000",
    requestedAdvanceBaseUnits: "500000",
    financierRef: "fin_acme_v1",
    payoutAccountRef: "payout_ledger_9",
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 32,
    ...overrides,
  };
}

function openingFromSecret(secret: FinancingCertificateSecret): FinancingCertificateOpening {
  return {
    revenueBaseUnits: secret.revenueBaseUnits,
    revenueBlinding: secret.revenueBlinding,
    requestedAdvanceBaseUnits: secret.requestedAdvanceBaseUnits,
    advanceBlinding: secret.advanceBlinding,
  };
}

function clone(certificate: FinancingCertificate): FinancingCertificate {
  return JSON.parse(JSON.stringify(certificate)) as FinancingCertificate;
}
describe("financing arithmetic, credit limit, repayment plan, and risk", () => {
  it("computes an eligible financing state with headroom and surplus", () => {
    const state = computeFinancingState("1000000", "500000", BASE_POLICY);
    expect(state).toMatchObject({
      revenueBaseUnits: "1000000",
      requestedAdvanceBaseUnits: "500000",
      advanceFactorBps: "8000",
      creditLimitBaseUnits: "800000",
      headroomBaseUnits: "300000",
      eligibilitySurplus: "3000000000",
      utilizationBps: "6250",
      overLimit: false,
      eligible: true,
    });
  });

  it("flags an advance over the credit limit as ineligible with a negative surplus", () => {
    const state = computeFinancingState("1000000", "900000", BASE_POLICY);
    expect(state).toMatchObject({
      creditLimitBaseUnits: "800000",
      headroomBaseUnits: "0",
      eligibilitySurplus: "-1000000000",
      overLimit: true,
      eligible: false,
    });
  });

  it("computes the credit limit as floor(factor · revenue / 10000)", () => {
    expect(computeCreditLimit("1000000", 8000)).toBe("800000");
    expect(computeCreditLimit("1", 8000)).toBe("0");
  });

  it("plans a repayment schedule that folds rounding into the final installment", () => {
    const schedule = computeRepaymentSchedule("500000", BASE_POLICY);
    expect(schedule).toHaveLength(12);
    expect(schedule[0]).toMatchObject({ installment: 1, dayOffset: 30, amountBaseUnits: "46666" });
    expect(schedule[11]).toMatchObject({ installment: 12, dayOffset: 360, cumulativeBaseUnits: "560000", remainingBaseUnits: "0" });
  });

  it("bands financing risk deterministically and calls an over-limit request critical", () => {
    const eligible = assessFinancingRisk(computeFinancingState("1000000", "500000", BASE_POLICY));
    expect(eligible.band).toBe("high");
    expect(eligible.score).toBe(68);
    expect(assessFinancingRisk(computeFinancingState("1000000", "900000", BASE_POLICY)).band).toBe("critical");
  });

  it("validates the public policy bounds", () => {
    expect(() => requireFinancingPolicy({ ...BASE_POLICY, advanceFactorBps: 0 })).toThrow(/advance factor/i);
    expect(() => requireFinancingPolicy({ ...BASE_POLICY, advanceFactorBps: MAX_ADVANCE_FACTOR_BPS + 1 })).toThrow(/advance factor/i);
    expect(() => requireFinancingPolicy({ ...BASE_POLICY, feeBps: -1 })).toThrow(/fee/i);
    expect(() => requireFinancingPolicy({ ...BASE_POLICY, installments: 0 })).toThrow(/installments/i);
    expect(() => requireFinancingPolicy({ ...BASE_POLICY, intervalDays: 0 })).toThrow(/interval/i);
  });
});
describe("certificate lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a certificate", () => {
    const { certificate, secret } = issueFinancingCertificate(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(certificate.proof.proofSystem).toBe(FINANCING_PROOF_SYSTEM);
    expect(certificate.proof.surplusBitLength).toBe(32 + FINANCING_SURPLUS_EXTRA_BITS);
    expect(verifyFinancingCertificate(certificate)).toBe(true);

    const round = parseFinancingCertificate(serializeFinancingCertificate(certificate));
    expect(round.bindingHash).toBe(certificate.bindingHash);
    expect(verifyFinancingCertificate(round)).toBe(true);

    expect(secret.revenueBaseUnits).toBe("1000000");
    expect(secret.requestedAdvanceBaseUnits).toBe("500000");

    const secretRound = parseFinancingCertificateSecret(serializeFinancingCertificateSecret(secret));
    expect(secretRound).toMatchObject({ revenueBaseUnits: secret.revenueBaseUnits, advanceBlinding: secret.advanceBlinding });
  });

  it("verifies a request sitting right at the credit limit (zero surplus)", () => {
    const { certificate } = issueFinancingCertificate(baseInput({ requestedAdvanceBaseUnits: "800000" }), NOW, makeEntropy("edge"));
    expect(verifyFinancingCertificate(certificate)).toBe(true);
  });

  it("verifies a full 128-bit institutional-scale request", { timeout: 120_000 }, () => {
    const { certificate } = issueFinancingCertificate(
      baseInput({ amountBitLength: 128, revenueBaseUnits: "1000000000000000000000", requestedAdvanceBaseUnits: "500000000000000000000" }),
      NOW,
      makeEntropy("big"),
    );
    expect(verifyFinancingCertificate(certificate)).toBe(true);
  });

  it("builds a badge with public display and no secret figures", () => {
    const { certificate, secret } = issueFinancingCertificate(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildFinancingCertificateBadge(certificate);
    expect(badge.advanceFactorDisplay).toBe("≤ 80% of revenue");
    expect(badge.feeDisplay).toBe("12% fee");
    expect(badge.installmentsDisplay).toBe("12 × every 30 days");
    expect(badge.financierCommitted).toBe(true);
    expect(badge.payoutAccountCommitted).toBe(true);
    const json = JSON.stringify(badge);
    expect(json).not.toContain(secret.financierRef);
    expect(json).not.toContain(secret.payoutAccountRef);
  });

  it("marks a certificate without financier or payout refs as uncommitted", () => {
    const { certificate } = issueFinancingCertificate(baseInput({ financierRef: "", payoutAccountRef: "" }), NOW, makeEntropy("bare"));
    expect(certificate.financierCommitted).toBe(false);
    expect(certificate.payoutAccountCommitted).toBe(false);
    expect(verifyFinancingCertificate(certificate)).toBe(true);
  });
});
describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest an advance over the eligible credit limit", () => {
    expect(() => issueFinancingCertificate(baseInput({ requestedAdvanceBaseUnits: "800001" }), NOW, makeEntropy("g1"))).toThrow(
      /exceeds the eligible credit limit/i,
    );
  });

  it("rejects a revenue outside the provable bit band", () => {
    expect(() => issueFinancingCertificate(baseInput({ revenueBaseUnits: (1n << 32n).toString() }), NOW, makeEntropy("g2"))).toThrow(
      /32-bit band/i,
    );
  });

  it("rejects a missing merchant alias and a malformed token address", () => {
    expect(() => issueFinancingCertificate(baseInput({ merchantAlias: "   " }), NOW, makeEntropy("g3"))).toThrow(/merchant alias/i);
    expect(() =>
      issueFinancingCertificate(baseInput({ asset: { symbol: "STRK", tokenAddress: "not-an-address", decimals: 18 } }), NOW, makeEntropy("g4")),
    ).toThrow(/0x prefix/i);
  });

  it("rejects over-long financier and payout-account references", () => {
    expect(() => issueFinancingCertificate(baseInput({ financierRef: "X".repeat(97) }), NOW, makeEntropy("g5"))).toThrow(
      /financier reference/i,
    );
    expect(() => issueFinancingCertificate(baseInput({ payoutAccountRef: "Y".repeat(129) }), NOW, makeEntropy("g6"))).toThrow(
      /payout account reference/i,
    );
  });

  it("rejects a malformed issuer secret key", () => {
    expect(() => issueFinancingCertificate(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("g7"))).toThrow(/scalar/i);
  });
});

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueFinancingCertificate(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyFinancingCertificate(issued.certificate)).toBe(true);
  });

  it("rejects a changed public advance factor", () => {
    const v = clone(issued.certificate);
    v.advanceFactorBps = "9000";
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects a changed public fee", () => {
    const v = clone(issued.certificate);
    v.feeBps = "3000";
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const v = clone(issued.certificate);
    v.bindingHash = v.bindingHash === "0x0" ? "0x1" : `${v.bindingHash}0`;
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const v = clone(issued.certificate);
    v.issuerSignature = { ...v.issuerSignature, response: "0x1" };
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects a tampered revenue range-proof bit", () => {
    const v = clone(issued.certificate);
    v.proof.revenueBits[0] = { ...v.proof.revenueBits[0], response0: "0x1" };
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects a tampered surplus range-proof bit", () => {
    const v = clone(issued.certificate);
    v.proof.surplusBits[0] = { ...v.proof.surplusBits[0], response1: "0x1" };
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const v = clone(issued.certificate);
    v.proof.generatorH = { ...v.issuerPublicKey };
    expect(verifyFinancingCertificate(v)).toBe(false);
  });

  it("rejects a corrupted advance commitment", () => {
    const v = clone(issued.certificate);
    v.proof.advanceCommitment = { x: "0x1", y: "0x1" };
    expect(verifyFinancingCertificate(v)).toBe(false);
  });
});
describe("selective disclosure and openings", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueFinancingCertificate(baseInput(), NOW, makeEntropy("disc"));

  it("discloses the revenue alone and verifies it", () => {
    const disclosure = buildFinancingRevenueDisclosure(issued.secret);
    expect(disclosure.amountBaseUnits).toBe(issued.secret.revenueBaseUnits);
    expect(verifyFinancingAmountDisclosure(issued.certificate, disclosure)).toBe(true);

    const round = parseFinancingAmountDisclosure(serializeFinancingAmountDisclosure(disclosure));
    expect(verifyFinancingAmountDisclosure(issued.certificate, round)).toBe(true);
    expect(verifyFinancingAmountDisclosure(issued.certificate, { ...disclosure, amountBaseUnits: "1" })).toBe(false);
    expect(verifyFinancingAmountDisclosure(issued.certificate, { ...disclosure, certificateId: "fin_other" })).toBe(false);
  });

  it("discloses the advance alone and verifies it", () => {
    const disclosure = buildFinancingAdvanceDisclosure(issued.secret);
    expect(disclosure.amountBaseUnits).toBe(issued.secret.requestedAdvanceBaseUnits);
    expect(verifyFinancingAmountDisclosure(issued.certificate, disclosure)).toBe(true);
    expect(verifyFinancingAmountDisclosure(issued.certificate, { ...disclosure, amountBaseUnits: "1" })).toBe(false);
  });

  it("discloses the committed financier and payout-account refs and verifies them", () => {
    const fin = buildFinancingFinancierDisclosure(issued.secret);
    expect(fin.value).toBe("fin_acme_v1");
    expect(verifyFinancingRefDisclosure(issued.certificate, fin)).toBe(true);
    const finRound = parseFinancingRefDisclosure(serializeFinancingRefDisclosure(fin));
    expect(verifyFinancingRefDisclosure(issued.certificate, finRound)).toBe(true);
    expect(verifyFinancingRefDisclosure(issued.certificate, { ...fin, value: "fin_other" })).toBe(false);

    const payout = buildFinancingPayoutAccountDisclosure(issued.secret);
    expect(payout.value).toBe("payout_ledger_9");
    expect(verifyFinancingRefDisclosure(issued.certificate, payout)).toBe(true);
  });

  it("verifies a full financier opening and rejects a wrong figure", () => {
    const opening = openingFromSecret(issued.secret);
    expect(verifyFinancingCertificateOpening(issued.certificate, opening)).toBe(true);
    expect(verifyFinancingCertificateOpening(issued.certificate, { ...opening, requestedAdvanceBaseUnits: "1" })).toBe(false);
    expect(verifyFinancingCertificateOpening(issued.certificate, { ...opening, revenueBaseUnits: "1" })).toBe(false);
  });
});

describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds the revenue, advance, blindings, salts, or references in the certificate", () => {
    const { certificate, secret } = issueFinancingCertificate(
      baseInput({ revenueBaseUnits: "999999", requestedAdvanceBaseUnits: "333333", financierRef: "SECRET-FIN-ZZZ", payoutAccountRef: "SECRET-PAYOUT-ZZZ" }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyFinancingCertificate(certificate)).toBe(true);

    const structured = JSON.stringify(certificate);
    const serialized = serializeFinancingCertificate(certificate);
    for (const surface of [structured, serialized]) {
      expect(surface).not.toContain(secret.revenueBaseUnits);
      expect(surface).not.toContain(secret.requestedAdvanceBaseUnits);
      expect(surface).not.toContain(secret.revenueBlinding);
      expect(surface).not.toContain(secret.advanceBlinding);
      expect(surface).not.toContain(secret.surplusBlinding);
      expect(surface).not.toContain(secret.financierSalt);
      expect(surface).not.toContain(secret.payoutAccountSalt);
      expect(surface).not.toContain("SECRET-FIN-ZZZ");
      expect(surface).not.toContain("SECRET-PAYOUT-ZZZ");
    }
    // The public advance reference and program label, by contrast, are deliberately disclosed.
    expect(structured).toContain("ADV-2026-0007");
  });

  it("keeps identical requests unlinkable by producing distinct commitments", () => {
    const a = issueFinancingCertificate(baseInput(), NOW, makeEntropy("ua"));
    const b = issueFinancingCertificate(baseInput(), NOW, makeEntropy("ub"));
    expect(a.certificate.proof.revenueCommitment.x).not.toBe(b.certificate.proof.revenueCommitment.x);
    expect(verifyFinancingCertificate(a.certificate)).toBe(true);
    expect(verifyFinancingCertificate(b.certificate)).toBe(true);
  });
});
describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeFinancingTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesAdvanceWithinFactorOfRevenue).toBe(true);
    expect(trust.hidesRevenue).toBe(true);
    expect(trust.hidesRequestedAdvance).toBe(true);
    expect(trust.hidesCustomerLists).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.supportsSelectiveDisclosure).toBe(true);
    expect(trust.advancesOrDisbursesFunds).toBe(false);
    expect(trust.settlesOnChain).toBe(false);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.verifiesRevenueIsReal).toBe(false);
    expect(trust.isCreditScoreOrModel).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isFinancialAdvice).toBe(false);
    expect(trust.statement).toContain("neither decentralized nor automatic");
    expect(trust.statement).toContain("does not advance, disburse, or settle any funds");
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getFinancingVisibilityModel();
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
  });
});

describe("generator and formatting helpers", () => {
  it("derives a stable, canonical generator H", () => {
    const a = deriveFinancingGenerator();
    const b = deriveFinancingGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
  });

  it("formats advance factors, fees, installments, and base-unit amounts for display", () => {
    expect(formatAdvanceFactor(8000)).toBe("80%");
    expect(formatAdvanceFactor(8050)).toBe("80.5%");
    expect(formatFeeRate(1200)).toBe("12% fee");
    expect(formatInstallments(12, 30)).toBe("12 × every 30 days");
    expect(formatFinancingBaseUnits("200000000000000000000", 18)).toBe("200");
    expect(formatFinancingBaseUnits("1500", 0)).toBe("1500");
  });

  it("rejects a malformed encoded certificate", () => {
    expect(() => parseFinancingCertificate("!!not base64!!")).toThrow(/encoding is invalid/i);
  });
});
