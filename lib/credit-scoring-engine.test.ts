import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  assessCreditRisk,
  buildCreditBookDisclosure,
  buildCreditCertificateBadge,
  buildCreditCertificateOpening,
  buildCreditMetricDisclosure,
  buildCreditUnderwriterDisclosure,
  computeCreditIndex,
  computeCreditState,
  createCreditIssuerKey,
  CREDIT_PROOF_SYSTEM,
  deriveCreditGenerator,
  formatCreditBaseUnits,
  formatCreditRateBps,
  getCreditVisibilityModel,
  issueCreditCertificate,
  MAX_CREDIT_WEIGHT,
  parseCreditCertificate,
  parseCreditCertificateSecret,
  parseCreditMetricDisclosure,
  parseCreditRefDisclosure,
  requireCreditPolicy,
  serializeCreditCertificate,
  serializeCreditCertificateSecret,
  serializeCreditMetricDisclosure,
  serializeCreditRefDisclosure,
  summarizeCreditTrust,
  tierForCreditIndex,
  verifyCreditCertificate,
  verifyCreditCertificateOpening,
  verifyCreditMetricDisclosure,
  verifyCreditRefDisclosure,
  type CreditCertificate,
  type CreditMetrics,
  type CreditPolicy,
  type IssueCreditCertificateInput,
} from "./credit-scoring-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T00:00:00.000Z");
const PROOF_TIMEOUT = 60_000;

/** Deterministic, collision-free entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `cred_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createCreditIssuerKey(makeEntropy(seed));
}

// A public underwriting policy: base 500, +3 per fulfilled, +2 per on-time, −15 per dispute,
// with a 100-base-unit reserve floor and a 1000-base-unit settled-volume floor.
const BASE_POLICY: CreditPolicy = {
  baseIndex: 500,
  fulfilledWeight: 3,
  onTimeWeight: 2,
  disputeWeight: 15,
  reserveFloorBaseUnits: "100",
  volumeFloorBaseUnits: "1000",
};

// Small, provable metrics: index = 500 + 3·40 + 2·35 − 15·4 = 630 (standard tier).
const BASE_METRICS: CreditMetrics = {
  fulfilledInvoices: "40",
  onTimeSettlements: "35",
  disputedInvoices: "4",
  settledVolumeBaseUnits: "5000",
  liquidityReserveBaseUnits: "250",
};

function baseInput(overrides: Partial<IssueCreditCertificateInput> = {}): IssueCreditCertificateInput {
  return {
    merchantAlias: "Aurora Studio",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    assessmentRef: "ASSESS-2026-0007",
    programLabel: "Merchant Underwriting",
    policy: BASE_POLICY,
    metrics: BASE_METRICS,
    underwriterRef: "uw_acme_v1",
    bookRef: "book_ledger_9",
    issuerSecretKey: issuerKey().secretKey,
    countBitLength: 12,
    amountBitLength: 16,
    ...overrides,
  };
}

function clone(certificate: CreditCertificate): CreditCertificate {
  return JSON.parse(JSON.stringify(certificate)) as CreditCertificate;
}

describe("credit index, tier, state, and risk", () => {
  it("computes an eligible credit state with the expected index, tier, and rates", () => {
    const state = computeCreditState(BASE_METRICS, BASE_POLICY);
    expect(state).toMatchObject({
      fulfilledInvoices: "40",
      onTimeSettlements: "35",
      disputedInvoices: "4",
      index: "630",
      tier: "standard",
      onTimeRateBps: "8750",
      disputeRateBps: "909",
      clearsReserveFloor: true,
      clearsVolumeFloor: true,
      punctualityConsistent: true,
      eligible: true,
    });
  });

  it("computes the public index as base + wF·fulfilled + wO·onTime − wD·disputed", () => {
    const policy = requireCreditPolicy(BASE_POLICY);
    expect(computeCreditIndex(40n, 35n, 4n, policy)).toBe(630n);
    // Disputes can drive the raw index below zero.
    expect(computeCreditIndex(0n, 0n, 40n, policy)).toBe(-100n);
  });

  it("maps indices to underwriting tiers deterministically", () => {
    expect(tierForCreditIndex(820)).toBe("prime");
    expect(tierForCreditIndex(720)).toBe("preferred");
    expect(tierForCreditIndex(630)).toBe("standard");
    expect(tierForCreditIndex(540)).toBe("watch");
    expect(tierForCreditIndex(400)).toBe("substandard");
  });

  it("flags a broken punctuality covenant as ineligible", () => {
    const state = computeCreditState({ ...BASE_METRICS, onTimeSettlements: "50" }, BASE_POLICY);
    expect(state.punctualityConsistent).toBe(false);
    expect(state.eligible).toBe(false);
  });

  it("flags an unmet floor as ineligible", () => {
    const state = computeCreditState({ ...BASE_METRICS, liquidityReserveBaseUnits: "50" }, BASE_POLICY);
    expect(state.clearsReserveFloor).toBe(false);
    expect(state.eligible).toBe(false);
  });

  it("bands credit risk deterministically and calls an ineligible assessment critical", () => {
    const eligible = assessCreditRisk(computeCreditState(BASE_METRICS, BASE_POLICY));
    expect(eligible.band).toBe("elevated");
    expect(eligible.score).toBe(68);
    const broken = assessCreditRisk(computeCreditState({ ...BASE_METRICS, onTimeSettlements: "50" }, BASE_POLICY));
    expect(broken.band).toBe("critical");
  });

  it("validates the public policy bounds", () => {
    expect(() => requireCreditPolicy({ ...BASE_POLICY, baseIndex: -1 })).toThrow(/base index/i);
    expect(() => requireCreditPolicy({ ...BASE_POLICY, fulfilledWeight: MAX_CREDIT_WEIGHT + 1 })).toThrow(/fulfilled weight/i);
    expect(() => requireCreditPolicy({ ...BASE_POLICY, disputeWeight: -1 })).toThrow(/dispute weight/i);
    expect(() => requireCreditPolicy({ ...BASE_POLICY, reserveFloorBaseUnits: "-1" })).toThrow(/reserve floor/i);
  });
});

describe("certificate lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a certificate", () => {
    const { certificate, secret } = issueCreditCertificate(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(certificate.proof.proofSystem).toBe(CREDIT_PROOF_SYSTEM);
    expect(certificate.index).toBe("630");
    expect(certificate.tier).toBe("standard");
    expect(verifyCreditCertificate(certificate)).toBe(true);

    const round = parseCreditCertificate(serializeCreditCertificate(certificate));
    expect(round.bindingHash).toBe(certificate.bindingHash);
    expect(verifyCreditCertificate(round)).toBe(true);

    expect(secret.fulfilledInvoices).toBe("40");
    expect(secret.disputedInvoices).toBe("4");
    const secretRound = parseCreditCertificateSecret(serializeCreditCertificateSecret(secret));
    expect(secretRound).toMatchObject({ fulfilledInvoices: secret.fulfilledInvoices, reserveBlinding: secret.reserveBlinding });
  });

  it("verifies a merchant sitting exactly on both floors (zero coverage)", () => {
    const { certificate } = issueCreditCertificate(
      baseInput({ metrics: { ...BASE_METRICS, liquidityReserveBaseUnits: "100", settledVolumeBaseUnits: "1000" } }),
      NOW,
      makeEntropy("edge"),
    );
    expect(verifyCreditCertificate(certificate)).toBe(true);
  });

  it("verifies a full 128-bit institutional-scale assessment", { timeout: 180_000 }, () => {
    const { certificate } = issueCreditCertificate(
      baseInput({
        amountBitLength: 128,
        metrics: {
          ...BASE_METRICS,
          settledVolumeBaseUnits: "5000000000000000000000",
          liquidityReserveBaseUnits: "250000000000000000000",
        },
        policy: { ...BASE_POLICY, reserveFloorBaseUnits: "100000000000000000000", volumeFloorBaseUnits: "1000000000000000000000" },
      }),
      NOW,
      makeEntropy("big"),
    );
    expect(verifyCreditCertificate(certificate)).toBe(true);
  });

  it("builds a badge with public display and no secret figures", () => {
    const { certificate, secret } = issueCreditCertificate(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildCreditCertificateBadge(certificate);
    expect(badge.index).toBe("630");
    expect(badge.tier).toBe("standard");
    expect(badge.weightingDisplay).toBe("base 500 + 3·fulfilled + 2·on-time − 15·disputed");
    expect(badge.underwriterCommitted).toBe(true);
    expect(badge.bookCommitted).toBe(true);
    const json = JSON.stringify(badge);
    expect(json).not.toContain(secret.underwriterRef);
    expect(json).not.toContain(secret.bookRef);
    expect(json).not.toContain(secret.fulfilledInvoices);
  });

  it("marks a certificate without underwriter or book refs as uncommitted", () => {
    const { certificate } = issueCreditCertificate(baseInput({ underwriterRef: "", bookRef: "" }), NOW, makeEntropy("bare"));
    expect(certificate.underwriterCommitted).toBe(false);
    expect(certificate.bookCommitted).toBe(false);
    expect(verifyCreditCertificate(certificate)).toBe(true);
  });
});

describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest when on-time settlements exceed fulfilled invoices", () => {
    expect(() =>
      issueCreditCertificate(baseInput({ metrics: { ...BASE_METRICS, onTimeSettlements: "50" } }), NOW, makeEntropy("g1")),
    ).toThrow(/on-time settlements exceed fulfilled/i);
  });

  it("refuses to attest when a cash-flow floor is not cleared", () => {
    expect(() =>
      issueCreditCertificate(baseInput({ metrics: { ...BASE_METRICS, liquidityReserveBaseUnits: "50" } }), NOW, makeEntropy("g2")),
    ).toThrow(/liquidity reserve does not clear/i);
    expect(() =>
      issueCreditCertificate(baseInput({ metrics: { ...BASE_METRICS, settledVolumeBaseUnits: "500" } }), NOW, makeEntropy("g3")),
    ).toThrow(/settled volume does not clear/i);
  });

  it("refuses to attest a negative underwriting index", () => {
    expect(() =>
      issueCreditCertificate(
        baseInput({ metrics: { fulfilledInvoices: "0", onTimeSettlements: "0", disputedInvoices: "40", settledVolumeBaseUnits: "5000", liquidityReserveBaseUnits: "250" } }),
        NOW,
        makeEntropy("g4"),
      ),
    ).toThrow(/index is negative/i);
  });

  it("rejects a count outside the provable bit band", () => {
    expect(() =>
      issueCreditCertificate(baseInput({ metrics: { ...BASE_METRICS, fulfilledInvoices: (1n << 12n).toString() } }), NOW, makeEntropy("g5")),
    ).toThrow(/12-bit band/i);
  });

  it("rejects a missing merchant alias and a malformed token address", () => {
    expect(() => issueCreditCertificate(baseInput({ merchantAlias: "   " }), NOW, makeEntropy("g6"))).toThrow(/merchant alias/i);
    expect(() =>
      issueCreditCertificate(baseInput({ asset: { symbol: "STRK", tokenAddress: "not-an-address", decimals: 18 } }), NOW, makeEntropy("g7")),
    ).toThrow(/0x prefix/i);
  });

  it("rejects over-long underwriter and loan-book references", () => {
    expect(() => issueCreditCertificate(baseInput({ underwriterRef: "X".repeat(97) }), NOW, makeEntropy("g8"))).toThrow(/underwriter reference/i);
    expect(() => issueCreditCertificate(baseInput({ bookRef: "Y".repeat(129) }), NOW, makeEntropy("g9"))).toThrow(/loan-book reference/i);
  });

  it("rejects a malformed issuer secret key", () => {
    expect(() => issueCreditCertificate(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("g10"))).toThrow(/scalar/i);
  });
});
describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueCreditCertificate(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyCreditCertificate(issued.certificate)).toBe(true);
  });

  it("rejects a changed public weight", () => {
    const v = clone(issued.certificate);
    v.fulfilledWeight = "9";
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a changed published index", () => {
    const v = clone(issued.certificate);
    v.index = "700";
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a tier that no longer matches the index", () => {
    const v = clone(issued.certificate);
    v.tier = "prime";
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const v = clone(issued.certificate);
    v.bindingHash = v.bindingHash === "0x0" ? "0x1" : `${v.bindingHash}0`;
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const v = clone(issued.certificate);
    v.issuerSignature = { ...v.issuerSignature, response: "0x1" };
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a tampered count range-proof bit", () => {
    const v = clone(issued.certificate);
    v.proof.fulfilledBits[0] = { ...v.proof.fulfilledBits[0], response0: "0x1" };
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a tampered coverage range-proof bit", () => {
    const v = clone(issued.certificate);
    v.proof.reserveCoverageBits[0] = { ...v.proof.reserveCoverageBits[0], response1: "0x1" };
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a tampered index-reconciliation response", () => {
    const v = clone(issued.certificate);
    v.proof.indexReconciliation = { ...v.proof.indexReconciliation, response: "0x1" };
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const v = clone(issued.certificate);
    v.proof.generatorH = { ...v.issuerPublicKey };
    expect(verifyCreditCertificate(v)).toBe(false);
  });

  it("rejects a corrupted count commitment", () => {
    const v = clone(issued.certificate);
    v.proof.fulfilledCommitment = { x: "0x1", y: "0x1" };
    expect(verifyCreditCertificate(v)).toBe(false);
  });
});
describe("selective disclosure and openings", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueCreditCertificate(baseInput(), NOW, makeEntropy("disc"));

  it("discloses each committed metric and verifies it against its commitment", () => {
    const cases: Array<[Parameters<typeof buildCreditMetricDisclosure>[1], string]> = [
      ["fulfilled", "40"],
      ["onTime", "35"],
      ["disputed", "4"],
      ["volume", "5000"],
      ["reserve", "250"],
    ];
    for (const [metric, value] of cases) {
      const disclosure = buildCreditMetricDisclosure(issued.secret, metric);
      expect(disclosure.valueBaseUnits).toBe(value);
      expect(verifyCreditMetricDisclosure(issued.certificate, disclosure)).toBe(true);

      const round = parseCreditMetricDisclosure(serializeCreditMetricDisclosure(disclosure));
      expect(verifyCreditMetricDisclosure(issued.certificate, round)).toBe(true);
      expect(verifyCreditMetricDisclosure(issued.certificate, { ...disclosure, valueBaseUnits: "1" })).toBe(false);
    }
    const first = buildCreditMetricDisclosure(issued.secret, "fulfilled");
    expect(verifyCreditMetricDisclosure(issued.certificate, { ...first, certificateId: "cred_other" })).toBe(false);
  });

  it("discloses the committed underwriter and loan-book refs and verifies them", () => {
    const uw = buildCreditUnderwriterDisclosure(issued.secret);
    expect(uw.value).toBe("uw_acme_v1");
    expect(verifyCreditRefDisclosure(issued.certificate, uw)).toBe(true);
    const uwRound = parseCreditRefDisclosure(serializeCreditRefDisclosure(uw));
    expect(verifyCreditRefDisclosure(issued.certificate, uwRound)).toBe(true);
    expect(verifyCreditRefDisclosure(issued.certificate, { ...uw, value: "uw_other" })).toBe(false);

    const book = buildCreditBookDisclosure(issued.secret);
    expect(book.value).toBe("book_ledger_9");
    expect(verifyCreditRefDisclosure(issued.certificate, book)).toBe(true);
  });

  it("verifies a full opening and rejects a wrong figure or blinding", () => {
    const opening = buildCreditCertificateOpening(issued.secret);
    expect(verifyCreditCertificateOpening(issued.certificate, opening)).toBe(true);
    expect(verifyCreditCertificateOpening(issued.certificate, { ...opening, fulfilledInvoices: "41" })).toBe(false);
    expect(verifyCreditCertificateOpening(issued.certificate, { ...opening, reserveBlinding: "0x1" })).toBe(false);
  });
});
describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds the cash-flow figures, blindings, salts, or references in the certificate", () => {
    const { certificate, secret } = issueCreditCertificate(
      baseInput({
        amountBitLength: 64,
        metrics: {
          fulfilledInvoices: "40",
          onTimeSettlements: "35",
          disputedInvoices: "4",
          settledVolumeBaseUnits: "918273645981",
          liquidityReserveBaseUnits: "827364591237",
        },
        underwriterRef: "SECRET-UW-ZZZ",
        bookRef: "SECRET-BOOK-ZZZ",
      }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyCreditCertificate(certificate)).toBe(true);

    const structured = JSON.stringify(certificate);
    const serialized = serializeCreditCertificate(certificate);
    for (const surface of [structured, serialized]) {
      // The two cash-flow figures are large and distinctive; the blindings, salts, and
      // references are full-width secrets. None may appear on any published surface.
      expect(surface).not.toContain(secret.settledVolumeBaseUnits);
      expect(surface).not.toContain(secret.liquidityReserveBaseUnits);
      expect(surface).not.toContain(secret.fulfilledBlinding);
      expect(surface).not.toContain(secret.onTimeBlinding);
      expect(surface).not.toContain(secret.disputedBlinding);
      expect(surface).not.toContain(secret.volumeBlinding);
      expect(surface).not.toContain(secret.reserveBlinding);
      expect(surface).not.toContain(secret.underwriterSalt);
      expect(surface).not.toContain(secret.bookSalt);
      expect(surface).not.toContain("SECRET-UW-ZZZ");
      expect(surface).not.toContain("SECRET-BOOK-ZZZ");
    }
    // The public assessment reference and program label, by contrast, are deliberately disclosed.
    expect(structured).toContain("ASSESS-2026-0007");
  });

  it("keeps identical assessments unlinkable by producing distinct commitments", () => {
    const a = issueCreditCertificate(baseInput(), NOW, makeEntropy("ua"));
    const b = issueCreditCertificate(baseInput(), NOW, makeEntropy("ub"));
    expect(a.certificate.proof.fulfilledCommitment.x).not.toBe(b.certificate.proof.fulfilledCommitment.x);
    expect(verifyCreditCertificate(a.certificate)).toBe(true);
    expect(verifyCreditCertificate(b.certificate)).toBe(true);
  });
});
describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeCreditTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesIndexIsExactWeightingOfHiddenCounts).toBe(true);
    expect(trust.provesOnTimeAtMostFulfilled).toBe(true);
    expect(trust.provesReserveClearsFloor).toBe(true);
    expect(trust.provesVolumeClearsFloor).toBe(true);
    expect(trust.hidesCounts).toBe(true);
    expect(trust.hidesCashFlowFigures).toBe(true);
    expect(trust.hidesCustomerLists).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.supportsSelectiveDisclosure).toBe(true);
    expect(trust.extendsOrDisbursesFunds).toBe(false);
    expect(trust.settlesOnChain).toBe(false);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.verifiesHistoryIsReal).toBe(false);
    expect(trust.isCreditBureauScoreOrModel).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isFinancialAdvice).toBe(false);
    expect(trust.statement).toContain("neither decentralized nor automatic");
    expect(trust.statement).toContain("does not extend, disburse, or settle any funds");
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getCreditVisibilityModel();
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
  });
});

describe("generator and formatting helpers", () => {
  it("derives a stable, canonical generator H", () => {
    const a = deriveCreditGenerator();
    const b = deriveCreditGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
  });

  it("formats rates and base-unit amounts for display", () => {
    expect(formatCreditRateBps(8750)).toBe("87.5%");
    expect(formatCreditRateBps(909)).toBe("9.09%");
    expect(formatCreditBaseUnits("200000000000000000000", 18)).toBe("200");
    expect(formatCreditBaseUnits("1500", 0)).toBe("1500");
  });

  it("rejects a malformed encoded certificate", () => {
    expect(() => parseCreditCertificate("!!not base64!!")).toThrow(/encoding is invalid/i);
  });
});
