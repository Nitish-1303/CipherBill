import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  assessChurnRisk,
  buildDunningBalanceDisclosure,
  buildDunningPaymentTokenDisclosure,
  buildDunningSubscriberDisclosure,
  buildDunningVoucherBadge,
  computeDunningState,
  computeRetrySchedule,
  createDunningIssuerKey,
  deriveDunningGenerator,
  DUNNING_PROOF_SYSTEM,
  formatDunningBaseUnits,
  formatGraceWindow,
  formatRetryCadence,
  getDunningVisibilityModel,
  issueDunningVoucher,
  MAX_DUNNING_ATTEMPTS,
  parseDunningBalanceDisclosure,
  parseDunningRefDisclosure,
  parseDunningVoucher,
  parseDunningVoucherSecret,
  requireDunningPolicy,
  serializeDunningBalanceDisclosure,
  serializeDunningRefDisclosure,
  serializeDunningVoucher,
  serializeDunningVoucherSecret,
  summarizeDunningTrust,
  verifyDunningBalanceDisclosure,
  verifyDunningRefDisclosure,
  verifyDunningVoucher,
  verifyDunningVoucherOpening,
  type DunningPolicy,
  type DunningVoucher,
  type DunningVoucherOpening,
  type DunningVoucherSecret,
  type IssueDunningVoucherInput,
} from "./dunning-engine";
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-23T00:00:00.000Z");
const PROOF_TIMEOUT = 60_000;

/** Deterministic, collision-free entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `dun_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createDunningIssuerKey(makeEntropy(seed));
}

const BASE_POLICY: DunningPolicy = { maxAttempts: 5, gracePeriodDays: 14, retryIntervalHours: 24, cadence: "fixed" };

function baseInput(overrides: Partial<IssueDunningVoucherInput> = {}): IssueDunningVoucherInput {
  return {
    merchantAlias: "Aurora Studio",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    subscriptionRef: "SUB-2026-0007",
    planLabel: "Pro Monthly",
    policy: BASE_POLICY,
    outstandingBaseUnits: "1000000000000000000000",
    attemptsMade: 2,
    elapsedDays: 5,
    subscriberRef: "sub_9f3ac41",
    paymentTokenRef: "ptok_7b2e19aa",
    issuerSecretKey: issuerKey().secretKey,
    ...overrides,
  };
}
describe("dunning state and cadence arithmetic", () => {
  it("computes remaining retries and grace for a recoverable subscription", () => {
    const s = computeDunningState("1000", 2, 5, BASE_POLICY);
    expect(s).toMatchObject({
      attemptsMade: "2",
      maxAttempts: "5",
      remainingAttempts: "3",
      elapsedDays: "5",
      gracePeriodDays: "14",
      remainingGraceDays: "9",
      attemptsExhausted: false,
      graceExpired: false,
      recoverable: true,
    });
  });

  it("flags an exhausted subscription and a lapsed grace window as not recoverable", () => {
    expect(computeDunningState("1000", 6, 1, BASE_POLICY)).toMatchObject({ attemptsExhausted: true, recoverable: false });
    expect(computeDunningState("1000", 1, 14, BASE_POLICY)).toMatchObject({ graceExpired: true, recoverable: false });
  });

  it("plans a fixed cadence that fits the grace window", () => {
    const schedule = computeRetrySchedule(BASE_POLICY);
    expect(schedule).toHaveLength(5);
    expect(schedule[0]).toMatchObject({ attempt: 1, hourOffset: 24, dayOffset: 1, withinGrace: true });
    expect(schedule[4]).toMatchObject({ attempt: 5, hourOffset: 120, dayOffset: 5, withinGrace: true });
  });

  it("plans an exponential cadence that eventually exceeds the grace window", () => {
    const schedule = computeRetrySchedule({ ...BASE_POLICY, cadence: "exponential" });
    expect(schedule.map((e) => e.hourOffset)).toEqual([24, 48, 96, 192, 384]);
    expect(schedule[4]).toMatchObject({ dayOffset: 16, withinGrace: false });
  });

  it("bands churn risk deterministically and calls an unrecoverable state critical", () => {
    const recoverable = assessChurnRisk(computeDunningState("1000", 2, 5, BASE_POLICY));
    expect(recoverable.band).toBe("elevated");
    expect(recoverable.score).toBe(38);
    expect(assessChurnRisk(computeDunningState("1000", 6, 1, BASE_POLICY)).band).toBe("critical");
  });

  it("validates the public policy bounds", () => {
    expect(() => requireDunningPolicy({ ...BASE_POLICY, maxAttempts: 0 })).toThrow(/max attempts/i);
    expect(() => requireDunningPolicy({ ...BASE_POLICY, gracePeriodDays: 0 })).toThrow(/grace period/i);
    expect(() => requireDunningPolicy({ ...BASE_POLICY, retryIntervalHours: 0 })).toThrow(/retry interval/i);
    expect(() => requireDunningPolicy({ ...BASE_POLICY, maxAttempts: MAX_DUNNING_ATTEMPTS + 1 })).toThrow(/max attempts/i);
  });
});
describe("voucher lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a voucher", () => {
    const { voucher, secret } = issueDunningVoucher(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(voucher.proof.proofSystem).toBe(DUNNING_PROOF_SYSTEM);
    expect(verifyDunningVoucher(voucher)).toBe(true);

    const round = parseDunningVoucher(serializeDunningVoucher(voucher));
    expect(round.bindingHash).toBe(voucher.bindingHash);
    expect(verifyDunningVoucher(round)).toBe(true);

    // The secret records the inputs the merchant supplied.
    expect(secret.outstandingBaseUnits).toBe("1000000000000000000000");
    expect(secret.attemptsMade).toBe("2");
    expect(secret.elapsedDays).toBe("5");

    const secretRound = parseDunningVoucherSecret(serializeDunningVoucherSecret(secret));
    expect(secretRound).toMatchObject({ outstandingBaseUnits: secret.outstandingBaseUnits, attemptsMade: secret.attemptsMade });
  });

  it("verifies a subscription sitting right at the policy edges", () => {
    const { voucher } = issueDunningVoucher(baseInput({ attemptsMade: 5, elapsedDays: 13 }), NOW, makeEntropy("edge"));
    expect(verifyDunningVoucher(voucher)).toBe(true);
  });

  it("builds a badge with public policy display and no secret figures", () => {
    const { voucher, secret } = issueDunningVoucher(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildDunningVoucherBadge(voucher);
    expect(badge.maxAttemptsDisplay).toBe("≤ 5 retries");
    expect(badge.gracePeriodDisplay).toBe("< 14 days");
    expect(badge.cadenceDisplay).toBe("every 24h (fixed)");
    expect(badge.subscriberCommitted).toBe(true);
    expect(badge.paymentTokenCommitted).toBe(true);
    const json = JSON.stringify(badge);
    expect(json).not.toContain(secret.outstandingBaseUnits);
    expect(json).not.toContain(secret.subscriberRef);
    expect(json).not.toContain(secret.paymentTokenRef);
  });

  it("marks a voucher without subscriber or payment-token refs as uncommitted", () => {
    const { voucher } = issueDunningVoucher(baseInput({ subscriberRef: "", paymentTokenRef: "" }), NOW, makeEntropy("bare"));
    expect(voucher.subscriberCommitted).toBe(false);
    expect(voucher.paymentTokenCommitted).toBe(false);
    expect(verifyDunningVoucher(voucher)).toBe(true);
  });
});
describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest a subscription that has exhausted its retries", () => {
    expect(() => issueDunningVoucher(baseInput({ attemptsMade: 6 }), NOW, makeEntropy("x1"))).toThrow(/exhausted/i);
  });

  it("refuses to attest a subscription whose grace period has lapsed", () => {
    expect(() => issueDunningVoucher(baseInput({ elapsedDays: 14 }), NOW, makeEntropy("x2"))).toThrow(/grace period/i);
  });

  it("rejects a missing merchant alias and a malformed token address", () => {
    expect(() => issueDunningVoucher(baseInput({ merchantAlias: "   " }), NOW, makeEntropy("x3"))).toThrow(/merchant alias/i);
    expect(() =>
      issueDunningVoucher(baseInput({ asset: { symbol: "STRK", tokenAddress: "not-an-address", decimals: 18 } }), NOW, makeEntropy("x4")),
    ).toThrow(/0x prefix/i);
  });

  it("rejects over-long subscriber and payment-token references", () => {
    expect(() => issueDunningVoucher(baseInput({ subscriberRef: "X".repeat(97) }), NOW, makeEntropy("x5"))).toThrow(/subscriber reference/i);
    expect(() => issueDunningVoucher(baseInput({ paymentTokenRef: "Y".repeat(129) }), NOW, makeEntropy("x6"))).toThrow(/payment token reference/i);
  });

  it("rejects an outstanding balance that exceeds the provable bit band", () => {
    expect(() =>
      issueDunningVoucher(baseInput({ outstandingBaseUnits: (1n << 16n).toString(), amountBitLength: 16 }), NOW, makeEntropy("x7")),
    ).toThrow(/16-bit band/i);
  });

  it("rejects a malformed issuer secret key", () => {
    expect(() => issueDunningVoucher(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("x8"))).toThrow(/scalar/i);
  });
});
function clone(voucher: DunningVoucher): DunningVoucher {
  return JSON.parse(JSON.stringify(voucher)) as DunningVoucher;
}

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueDunningVoucher(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyDunningVoucher(issued.voucher)).toBe(true);
  });

  it("rejects a changed public max-attempts policy", () => {
    const v = clone(issued.voucher);
    v.maxAttempts = "10";
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects a changed public grace period", () => {
    const v = clone(issued.voucher);
    v.gracePeriodDays = "30";
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const v = clone(issued.voucher);
    v.bindingHash = v.bindingHash === "0x0" ? "0x1" : `${v.bindingHash}0`;
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const v = clone(issued.voucher);
    v.issuerSignature = { ...v.issuerSignature, response: "0x1" };
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects a tampered outstanding range-proof bit", () => {
    const v = clone(issued.voucher);
    v.proof.outstandingBits[0] = { ...v.proof.outstandingBits[0], response0: "0x1" };
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects a tampered upper attempts-bound bit", () => {
    const v = clone(issued.voucher);
    v.proof.attemptsUpperBits[0] = { ...v.proof.attemptsUpperBits[0], response1: "0x1" };
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const v = clone(issued.voucher);
    v.proof.generatorH = { ...v.issuerPublicKey };
    expect(verifyDunningVoucher(v)).toBe(false);
  });

  it("rejects a corrupted commitment point", () => {
    const v = clone(issued.voucher);
    v.proof.elapsedCommitment = { x: "0x1", y: "0x1" };
    expect(verifyDunningVoucher(v)).toBe(false);
  });
});
function openingFromSecret(secret: DunningVoucherSecret): DunningVoucherOpening {
  return {
    outstandingBaseUnits: secret.outstandingBaseUnits,
    outstandingBlinding: secret.outstandingBlinding,
    attemptsMade: secret.attemptsMade,
    attemptsBlinding: secret.attemptsBlinding,
    elapsedDays: secret.elapsedDays,
    elapsedBlinding: secret.elapsedBlinding,
  };
}

describe("selective disclosure and openings", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueDunningVoucher(baseInput(), NOW, makeEntropy("disc"));

  it("discloses the outstanding balance alone and verifies it", () => {
    const disclosure = buildDunningBalanceDisclosure(issued.secret);
    expect(disclosure.outstandingBaseUnits).toBe(issued.secret.outstandingBaseUnits);
    expect(verifyDunningBalanceDisclosure(issued.voucher, disclosure)).toBe(true);

    const round = parseDunningBalanceDisclosure(serializeDunningBalanceDisclosure(disclosure));
    expect(verifyDunningBalanceDisclosure(issued.voucher, round)).toBe(true);
    expect(verifyDunningBalanceDisclosure(issued.voucher, { ...disclosure, outstandingBaseUnits: "1" })).toBe(false);
    expect(verifyDunningBalanceDisclosure(issued.voucher, { ...disclosure, voucherId: "dun_other" })).toBe(false);
  });

  it("discloses the committed subscriber and payment-token refs and verifies them", () => {
    const sub = buildDunningSubscriberDisclosure(issued.secret);
    expect(sub.value).toBe("sub_9f3ac41");
    expect(verifyDunningRefDisclosure(issued.voucher, sub)).toBe(true);
    const subRound = parseDunningRefDisclosure(serializeDunningRefDisclosure(sub));
    expect(verifyDunningRefDisclosure(issued.voucher, subRound)).toBe(true);
    expect(verifyDunningRefDisclosure(issued.voucher, { ...sub, value: "sub_other" })).toBe(false);

    const tok = buildDunningPaymentTokenDisclosure(issued.secret);
    expect(tok.value).toBe("ptok_7b2e19aa");
    expect(verifyDunningRefDisclosure(issued.voucher, tok)).toBe(true);
  });

  it("verifies a full auditor opening and rejects a wrong figure", () => {
    const opening = openingFromSecret(issued.secret);
    expect(verifyDunningVoucherOpening(issued.voucher, opening)).toBe(true);
    expect(verifyDunningVoucherOpening(issued.voucher, { ...opening, attemptsMade: "1" })).toBe(false);
    expect(verifyDunningVoucherOpening(issued.voucher, { ...opening, outstandingBaseUnits: "1" })).toBe(false);
  });
});
describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds the balance, blindings, salts, or references in the voucher", () => {
    const { voucher, secret } = issueDunningVoucher(
      baseInput({ outstandingBaseUnits: "999999999999999999", subscriberRef: "SECRET-SUB-ZZZ", paymentTokenRef: "SECRET-PTOK-ZZZ" }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyDunningVoucher(voucher)).toBe(true);

    const structured = JSON.stringify(voucher);
    const serialized = serializeDunningVoucher(voucher);
    for (const surface of [structured, serialized]) {
      expect(surface).not.toContain(secret.outstandingBaseUnits);
      expect(surface).not.toContain(secret.outstandingBlinding);
      expect(surface).not.toContain(secret.attemptsBlinding);
      expect(surface).not.toContain(secret.elapsedBlinding);
      expect(surface).not.toContain(secret.subscriberSalt);
      expect(surface).not.toContain(secret.paymentTokenSalt);
      expect(surface).not.toContain("SECRET-SUB-ZZZ");
      expect(surface).not.toContain("SECRET-PTOK-ZZZ");
    }
    // The public subscription reference and policy, by contrast, are deliberately disclosed.
    expect(structured).toContain("SUB-2026-0007");
  });

  it("keeps identical states unlinkable by producing distinct commitments", () => {
    const a = issueDunningVoucher(baseInput(), NOW, makeEntropy("za"));
    const b = issueDunningVoucher(baseInput(), NOW, makeEntropy("zb"));
    expect(a.voucher.proof.outstandingCommitment.x).not.toBe(b.voucher.proof.outstandingCommitment.x);
    expect(verifyDunningVoucher(a.voucher)).toBe(true);
    expect(verifyDunningVoucher(b.voucher)).toBe(true);
  });
});

describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeDunningTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesRecoverabilityWithinPolicy).toBe(true);
    expect(trust.hidesOutstandingBalance).toBe(true);
    expect(trust.hidesAttemptCount).toBe(true);
    expect(trust.hidesDelinquencyAge).toBe(true);
    expect(trust.hidesSubscriberIdentity).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.supportsSelectiveDisclosure).toBe(true);
    expect(trust.chargesOrRetriesPayments).toBe(false);
    expect(trust.settlesOnChain).toBe(false);
    expect(trust.bindsToRealFunds).toBe(false);
    expect(trust.storesReusablePaymentCredentials).toBe(false);
    expect(trust.predictsChurnWithModel).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isFinancialAdvice).toBe(false);
    expect(trust.statement).toContain("neither decentralized nor automatic");
    expect(trust.statement).toContain("does not charge, retry, or settle any payment");
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getDunningVisibilityModel();
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
  });
});
describe("generator and formatting helpers", () => {
  it("derives a stable, canonical generator H", () => {
    const a = deriveDunningGenerator();
    const b = deriveDunningGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
  });

  it("formats grace windows, cadences, and base-unit amounts for display", () => {
    expect(formatGraceWindow(14)).toBe("14 days");
    expect(formatGraceWindow(1)).toBe("1 day");
    expect(formatRetryCadence(24, "fixed")).toBe("every 24h (fixed)");
    expect(formatRetryCadence(24, "exponential")).toBe("every 24h (exponential backoff)");
    expect(formatDunningBaseUnits("200000000000000000000", 18)).toBe("200");
    expect(formatDunningBaseUnits("1500", 0)).toBe("1500");
  });

  it("rejects a malformed encoded voucher", () => {
    expect(() => parseDunningVoucher("!!not base64!!")).toThrow(/encoding is invalid/i);
  });
});
