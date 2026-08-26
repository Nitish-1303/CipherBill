import { describe, expect, it } from "vitest";

import {
  LOYALTY_PROOF_SYSTEM,
  MAX_LOYALTY_CASHBACK_BPS,
  MAX_LOYALTY_FEE_DISCOUNT_BPS,
  buildLoyaltyAccountDisclosure,
  buildLoyaltyCertificateBadge,
  buildLoyaltyCertificateOpening,
  buildLoyaltyMetricDisclosure,
  buildLoyaltyMonthDisclosure,
  buildLoyaltyRebateClaim,
  computeCashback,
  computeLoyaltyState,
  createLoyaltyIssuerKey,
  deriveLoyaltyGenerator,
  formatLoyaltyBps,
  getLoyaltyVisibilityModel,
  issueLoyaltyCertificate,
  parseLoyaltyCertificate,
  parseLoyaltyCertificateSecret,
  parseLoyaltyMetricDisclosure,
  parseLoyaltyMonthDisclosure,
  parseLoyaltyRefDisclosure,
  requireLoyaltyPolicy,
  serializeLoyaltyCertificate,
  serializeLoyaltyCertificateSecret,
  serializeLoyaltyMetricDisclosure,
  serializeLoyaltyMonthDisclosure,
  serializeLoyaltyRefDisclosure,
  summarizeLoyaltyTrust,
  tierIndexForVolume,
  verifyLoyaltyCertificate,
  verifyLoyaltyCertificateOpening,
  verifyLoyaltyMetricDisclosure,
  verifyLoyaltyMonthDisclosure,
  verifyLoyaltyRefDisclosure,
  type IssueLoyaltyCertificateInput,
  type LoyaltyPolicy,
} from "./loyalty-rebate-engine";

const PROVE_TIMEOUT = { timeout: 120_000 };

const POLICY: LoyaltyPolicy = {
  tiers: [
    { name: "Bronze", floorBaseUnits: "0", feeDiscountBps: 0, cashbackBps: 0 },
    { name: "Silver", floorBaseUnits: "1000", feeDiscountBps: 500, cashbackBps: 100 },
    { name: "Gold", floorBaseUnits: "5000", feeDiscountBps: 1500, cashbackBps: 250 },
    { name: "Platinum", floorBaseUnits: "20000", feeDiscountBps: 3000, cashbackBps: 500 },
  ],
};

const ISSUER = createLoyaltyIssuerKey();

function baseInput(overrides: Partial<IssueLoyaltyCertificateInput> = {}): IssueLoyaltyCertificateInput {
  return {
    merchantAlias: "Northwind Studio",
    asset: { symbol: "STRK", tokenAddress: "0x1", decimals: 18 },
    periodLabel: "FY26 H1",
    programLabel: "Merchant Volume Loyalty",
    policy: POLICY,
    metrics: { monthlyVolumesBaseUnits: ["2500", "3100", "1800"] }, // total 7400 → Gold
    issuerSecretKey: ISSUER.secretKey,
    accountRef: "member:northwind-0xabc",
    amountBitLength: 20,
    memo: "H1 aggregate",
    ...overrides,
  };
}

describe("computeLoyaltyState", () => {
  it("assigns the highest tier the aggregate clears and computes the exact cashback", () => {
    const state = computeLoyaltyState({ monthlyVolumesBaseUnits: ["2500", "3100", "1800"] }, POLICY);
    expect(state.totalVolumeBaseUnits).toBe("7400");
    expect(state.monthCount).toBe(3);
    expect(state.tierIndex).toBe(2);
    expect(state.tierName).toBe("Gold");
    expect(state.feeDiscountBps).toBe(1500);
    expect(state.cashbackBps).toBe(250);
    // floor(250 * 7400 / 10000) = floor(185) = 185
    expect(state.cashbackBaseUnits).toBe("185");
    expect(state.tierFloorBaseUnits).toBe("5000");
    expect(state.nextTierFloorBaseUnits).toBe("20000");
    expect(state.isTopTier).toBe(false);
    expect(state.volumeToNextTierBaseUnits).toBe("12600");
  });

  it("lands on the base tier when volume clears no floor", () => {
    const state = computeLoyaltyState({ monthlyVolumesBaseUnits: ["100", "200"] }, POLICY);
    expect(state.tierIndex).toBe(0);
    expect(state.tierName).toBe("Bronze");
    expect(state.cashbackBaseUnits).toBe("0");
    expect(state.isTopTier).toBe(false);
  });

  it("marks the top tier and reports full progress with no next floor", () => {
    const state = computeLoyaltyState({ monthlyVolumesBaseUnits: ["25000" ] }, POLICY);
    expect(state.tierName).toBe("Platinum");
    expect(state.isTopTier).toBe(true);
    expect(state.nextTierFloorBaseUnits).toBeNull();
    expect(state.volumeToNextTierBaseUnits).toBeNull();
    expect(state.tierProgressBps).toBe("10000");
  });

  it("reports mid-band progress in basis points", () => {
    // total 10000, Gold band [5000, 20000): (10000-5000)/(20000-5000) = 5000/15000 = 3333 bps
    const state = computeLoyaltyState({ monthlyVolumesBaseUnits: ["10000"] }, POLICY);
    expect(state.tierProgressBps).toBe("3333");
  });

  it("rejects an empty or oversized month set", () => {
    expect(() => computeLoyaltyState({ monthlyVolumesBaseUnits: [] }, POLICY)).toThrow();
    const tooMany = Array.from({ length: 25 }, () => "1");
    expect(() => computeLoyaltyState({ monthlyVolumesBaseUnits: tooMany }, POLICY)).toThrow();
  });

  it("rejects malformed month volumes", () => {
    expect(() => computeLoyaltyState({ monthlyVolumesBaseUnits: ["-5"] }, POLICY)).toThrow();
    expect(() => computeLoyaltyState({ monthlyVolumesBaseUnits: ["12.5"] }, POLICY)).toThrow();
    expect(() => computeLoyaltyState({ monthlyVolumesBaseUnits: ["abc"] }, POLICY)).toThrow();
  });
});

describe("policy validation", () => {
  it("requires the base tier floor to be 0 and floors to ascend", () => {
    expect(() => requireLoyaltyPolicy({ tiers: [{ name: "A", floorBaseUnits: "5", feeDiscountBps: 0, cashbackBps: 0 }] })).toThrow();
    expect(() =>
      requireLoyaltyPolicy({
        tiers: [
          { name: "A", floorBaseUnits: "0", feeDiscountBps: 0, cashbackBps: 0 },
          { name: "B", floorBaseUnits: "0", feeDiscountBps: 0, cashbackBps: 0 },
        ],
      }),
    ).toThrow();
  });

  it("rejects rates above the published ceilings", () => {
    expect(() =>
      requireLoyaltyPolicy({ tiers: [{ name: "A", floorBaseUnits: "0", feeDiscountBps: MAX_LOYALTY_FEE_DISCOUNT_BPS + 1, cashbackBps: 0 }] }),
    ).toThrow();
    expect(() =>
      requireLoyaltyPolicy({ tiers: [{ name: "A", floorBaseUnits: "0", feeDiscountBps: 0, cashbackBps: MAX_LOYALTY_CASHBACK_BPS + 1 }] }),
    ).toThrow();
  });
});

describe("pure primitives", () => {
  it("tierIndexForVolume picks the highest cleared floor", () => {
    const tiers = requireLoyaltyPolicy(POLICY);
    expect(tierIndexForVolume(0n, tiers)).toBe(0);
    expect(tierIndexForVolume(4999n, tiers)).toBe(1);
    expect(tierIndexForVolume(5000n, tiers)).toBe(2);
    expect(tierIndexForVolume(999999n, tiers)).toBe(3);
  });

  it("computeCashback floors the basis-point product", () => {
    expect(computeCashback(250, 7400n)).toBe(185n);
    expect(computeCashback(0, 7400n)).toBe(0n);
    expect(computeCashback(500, 999n)).toBe(49n); // floor(499.5) = 49... floor(500*999/10000)=floor(49.95)=49
  });

  it("formatLoyaltyBps renders a percentage", () => {
    expect(formatLoyaltyBps(250)).toBe("2.5%");
    expect(formatLoyaltyBps(500)).toBe("5%");
    expect(formatLoyaltyBps(0)).toBe("0%");
  });

  it("deriveLoyaltyGenerator is deterministic", () => {
    expect(deriveLoyaltyGenerator()).toEqual(deriveLoyaltyGenerator());
  });
});
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

let goldIssued: ReturnType<typeof issueLoyaltyCertificate> | null = null;
function gold(): ReturnType<typeof issueLoyaltyCertificate> {
  if (!goldIssued) goldIssued = issueLoyaltyCertificate(baseInput());
  return goldIssued;
}

let topIssued: ReturnType<typeof issueLoyaltyCertificate> | null = null;
function top(): ReturnType<typeof issueLoyaltyCertificate> {
  if (!topIssued) topIssued = issueLoyaltyCertificate(baseInput({ metrics: { monthlyVolumesBaseUnits: ["25000"] } }));
  return topIssued;
}

describe("issueLoyaltyCertificate / verifyLoyaltyCertificate", () => {
  it("issues a certificate that verifies and publishes only the tier band", PROVE_TIMEOUT, () => {
    const { certificate } = gold();
    expect(certificate.proof.proofSystem).toBe(LOYALTY_PROOF_SYSTEM);
    expect(certificate.tierName).toBe("Gold");
    expect(certificate.feeDiscountBps).toBe("1500");
    expect(certificate.cashbackBps).toBe("250");
    expect(certificate.tierFloorBaseUnits).toBe("5000");
    expect(certificate.nextTierFloorBaseUnits).toBe("20000");
    expect(certificate.monthCount).toBe(3);
    expect(verifyLoyaltyCertificate(certificate)).toBe(true);
  });

  it("verifies a top-tier certificate that omits the upper coverage leg", PROVE_TIMEOUT, () => {
    const { certificate } = top();
    expect(certificate.tierName).toBe("Platinum");
    expect(certificate.nextTierFloorBaseUnits).toBe("");
    expect(certificate.proof.tierUpperBits).toEqual([]);
    expect(verifyLoyaltyCertificate(certificate)).toBe(true);
  });

  it("rejects a certificate whose top tier smuggles an upper leg", PROVE_TIMEOUT, () => {
    const tampered = clone(top().certificate);
    tampered.proof.tierUpperBits = clone(gold().certificate.proof.tierLowerBits);
    expect(verifyLoyaltyCertificate(tampered)).toBe(false);
  });

  it("rejects a tampered tier index", PROVE_TIMEOUT, () => {
    const tampered = clone(gold().certificate);
    tampered.tierIndex = 3;
    expect(verifyLoyaltyCertificate(tampered)).toBe(false);
  });

  it("rejects an inflated published fee-discount rate", PROVE_TIMEOUT, () => {
    const tampered = clone(gold().certificate);
    tampered.feeDiscountBps = "3000";
    expect(verifyLoyaltyCertificate(tampered)).toBe(false);
  });

  it("rejects a tampered tier name", PROVE_TIMEOUT, () => {
    const tampered = clone(gold().certificate);
    tampered.tierName = "Platinum";
    expect(verifyLoyaltyCertificate(tampered)).toBe(false);
  });

  it("rejects a mutated monthly commitment", PROVE_TIMEOUT, () => {
    const tampered = clone(gold().certificate);
    tampered.proof.monthlyCommitments[0] = clone(gold().certificate.proof.cashbackCommitment);
    expect(verifyLoyaltyCertificate(tampered)).toBe(false);
  });

  it("rejects a forged issuer signature", PROVE_TIMEOUT, () => {
    const tampered = clone(gold().certificate);
    tampered.issuerSignature.response = "0x2";
    expect(verifyLoyaltyCertificate(tampered)).toBe(false);
  });

  it("throws when a month exceeds the proven bit band", () => {
    expect(() =>
      issueLoyaltyCertificate(baseInput({ metrics: { monthlyVolumesBaseUnits: ["2000000"] }, amountBitLength: 20 })),
    ).toThrow();
  });
});
describe("zero-knowledge hiding", () => {
  it("reveals only the public tier: different hidden splits yield identical public claims but distinct commitments", PROVE_TIMEOUT, () => {
    const a = issueLoyaltyCertificate(baseInput({ metrics: { monthlyVolumesBaseUnits: ["6000", "6000", "4321"] } }));
    const b = issueLoyaltyCertificate(baseInput({ metrics: { monthlyVolumesBaseUnits: ["1000", "9000", "6321"] } }));
    // Same aggregate (16321 → Gold), so the same public claim.
    expect(a.certificate.tierName).toBe("Gold");
    expect(b.certificate.tierName).toBe("Gold");
    expect(a.certificate.feeDiscountBps).toBe(b.certificate.feeDiscountBps);
    expect(a.certificate.cashbackBps).toBe(b.certificate.cashbackBps);
    expect(a.certificate.monthCount).toBe(b.certificate.monthCount);
    // But the commitments (and binding) differ — the months are hidden.
    expect(a.certificate.proof.monthlyCommitments).not.toEqual(b.certificate.proof.monthlyCommitments);
    expect(a.certificate.bindingHash).not.toBe(b.certificate.bindingHash);
    expect(verifyLoyaltyCertificate(a.certificate)).toBe(true);
    expect(verifyLoyaltyCertificate(b.certificate)).toBe(true);
  });

  it("keeps the plaintext aggregate and cashback out of the public certificate object", PROVE_TIMEOUT, () => {
    const { certificate, secret } = gold();
    // No top-level public field carries the hidden figures.
    const publicValues = Object.values(certificate).filter((v) => typeof v === "string");
    expect(publicValues).not.toContain(secret.totalVolumeBaseUnits);
    expect(publicValues).not.toContain(secret.cashbackBaseUnits);
    expect(secret.totalVolumeBaseUnits).toBe("7400");
    expect(secret.cashbackBaseUnits).toBe("185");
  });
});

describe("selective disclosure", () => {
  it("opens the aggregate volume against the summed commitments", PROVE_TIMEOUT, () => {
    const { certificate, secret } = gold();
    const disclosure = buildLoyaltyMetricDisclosure(secret, "total");
    expect(disclosure.valueBaseUnits).toBe("7400");
    expect(verifyLoyaltyMetricDisclosure(certificate, disclosure)).toBe(true);
    const forged = { ...disclosure, valueBaseUnits: "7401" };
    expect(verifyLoyaltyMetricDisclosure(certificate, forged)).toBe(false);
  });

  it("opens the cashback as a rebate-claim voucher", PROVE_TIMEOUT, () => {
    const { certificate, secret } = gold();
    const claim = buildLoyaltyRebateClaim(secret);
    expect(claim.metric).toBe("cashback");
    expect(claim.valueBaseUnits).toBe("185");
    expect(verifyLoyaltyMetricDisclosure(certificate, claim)).toBe(true);
  });

  it("opens a single month against its commitment", PROVE_TIMEOUT, () => {
    const { certificate, secret } = gold();
    const disclosure = buildLoyaltyMonthDisclosure(secret, 1);
    expect(disclosure.valueBaseUnits).toBe("3100");
    expect(verifyLoyaltyMonthDisclosure(certificate, disclosure)).toBe(true);
    const forged = { ...disclosure, valueBaseUnits: "9999" };
    expect(verifyLoyaltyMonthDisclosure(certificate, forged)).toBe(false);
  });

  it("opens the committed account reference", PROVE_TIMEOUT, () => {
    const { certificate, secret } = gold();
    const disclosure = buildLoyaltyAccountDisclosure(secret);
    expect(verifyLoyaltyRefDisclosure(certificate, disclosure)).toBe(true);
    const forged = { ...disclosure, value: "member:someone-else" };
    expect(verifyLoyaltyRefDisclosure(certificate, forged)).toBe(false);
  });

  it("rejects a disclosure aimed at a different certificate", PROVE_TIMEOUT, () => {
    const { secret } = gold();
    const other = issueLoyaltyCertificate(baseInput({ metrics: { monthlyVolumesBaseUnits: ["1000", "1000", "1000"] } }));
    const disclosure = buildLoyaltyMetricDisclosure(secret, "total");
    expect(verifyLoyaltyMetricDisclosure(other.certificate, disclosure)).toBe(false);
  });

  it("verifies a full opening and rejects a tampered one", PROVE_TIMEOUT, () => {
    const { certificate, secret } = gold();
    const opening = buildLoyaltyCertificateOpening(secret);
    expect(verifyLoyaltyCertificateOpening(certificate, opening)).toBe(true);
    const tampered = clone(opening);
    tampered.monthlyVolumesBaseUnits[0] = "9999";
    expect(verifyLoyaltyCertificateOpening(certificate, tampered)).toBe(false);
  });
});
describe("serialization", () => {
  it("round-trips a certificate and it still verifies", PROVE_TIMEOUT, () => {
    const { certificate } = gold();
    const restored = parseLoyaltyCertificate(serializeLoyaltyCertificate(certificate));
    expect(restored).toEqual(certificate);
    expect(verifyLoyaltyCertificate(restored)).toBe(true);
  });

  it("round-trips the secret and every disclosure kind", PROVE_TIMEOUT, () => {
    const { secret } = gold();
    expect(parseLoyaltyCertificateSecret(serializeLoyaltyCertificateSecret(secret))).toEqual(secret);
    const metric = buildLoyaltyMetricDisclosure(secret, "total");
    expect(parseLoyaltyMetricDisclosure(serializeLoyaltyMetricDisclosure(metric))).toEqual(metric);
    const month = buildLoyaltyMonthDisclosure(secret, 0);
    expect(parseLoyaltyMonthDisclosure(serializeLoyaltyMonthDisclosure(month))).toEqual(month);
    const ref = buildLoyaltyAccountDisclosure(secret);
    expect(parseLoyaltyRefDisclosure(serializeLoyaltyRefDisclosure(ref))).toEqual(ref);
  });

  it("rejects a foreign or malformed token", PROVE_TIMEOUT, () => {
    const { secret } = gold();
    const secretToken = serializeLoyaltyCertificateSecret(secret);
    expect(() => parseLoyaltyCertificate(secretToken)).toThrow();
    expect(() => parseLoyaltyCertificate("!!!not-base64!!!")).toThrow("The encoding is invalid.");
  });
});

describe("presentation and honesty", () => {
  it("builds a display badge from the public claims", PROVE_TIMEOUT, () => {
    const badge = buildLoyaltyCertificateBadge(gold().certificate);
    expect(badge.tierName).toBe("Gold");
    expect(badge.feeDiscountDisplay).toBe("15%");
    expect(badge.cashbackDisplay).toBe("2.5%");
    expect(badge.monthCount).toBe(3);
    expect(badge.accountCommitted).toBe(true);
  });

  it("states an honest trust model", () => {
    const trust = summarizeLoyaltyTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesAggregateInTierBand).toBe(true);
    expect(trust.provesCashbackIsExactFloorOfRate).toBe(true);
    expect(trust.hidesMonthlyVolumes).toBe(true);
    expect(trust.hidesAggregateVolume).toBe(true);
    expect(trust.hidesCashbackAmount).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    // The load-bearing honesty: it does none of the on-chain / financial things.
    expect(trust.appliesOrReducesProtocolFee).toBe(false);
    expect(trust.paysOrSettlesCashback).toBe(false);
    expect(trust.reducesGas).toBe(false);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.verifiesVolumesAreReal).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isLoyaltyProgramGuaranteeOrFinancialAdvice).toBe(false);
  });

  it("describes a visibility model with real limitations", () => {
    const model = getLoyaltyVisibilityModel();
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
    expect(model.limitation.length).toBeGreaterThan(0);
  });
});
