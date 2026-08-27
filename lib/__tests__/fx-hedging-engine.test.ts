import { describe, expect, it } from "vitest";
import { ec as starkEc, hash as starkHash } from "starknet";

import { STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "../strk20/config";
import {
  FX_HEDGING_POOL_ADDRESS,
  FX_HEDGING_PROOF_SYSTEM,
  buildFxHedgingAmountDisclosure,
  buildFxHedgingPairDisclosure,
  computeForwardRate,
  computeHedgingState,
  createFxHedgingIssuerKey,
  deriveFxHedgingGenerator,
  getFxHedgingVisibilityModel,
  issueFxHedgingCertificate,
  monitorHedgingPositions,
  parseFxHedgingCertificate,
  requireFxHedgingPolicy,
  serializeFxHedgingCertificate,
  summarizeFxHedgingTrust,
  verifyFxHedgingAmountDisclosure,
  verifyFxHedgingCertificate,
  verifyFxHedgingPairDisclosure,
  type IssueFxHedgingCertificateInput,
} from "../fx-hedging-engine";

const CURVE_ORDER = starkEc.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T12:00:00.000Z");
const PROOF_TIMEOUT = 120_000;

function makeEntropy(seed: string) {
  const seedFelt = starkHash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `fxh_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(starkHash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createFxHedgingIssuerKey(makeEntropy(seed));
}

const BASE_POLICY = { maxTenorDays: 90, maxForwardPremiumBps: 250, maxForwardDiscountBps: 150 };

function baseInput(overrides: Partial<IssueFxHedgingCertificateInput> = {}): IssueFxHedgingCertificateInput {
  return {
    merchantAlias: "Aurora Desk",
    deskLabel: "Treasury FX",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    baseCurrency: "USD",
    quoteCurrency: "STRK",
    counterpartyRef: "counterparty_alpha",
    spotRate: "2.50",
    rateDecimals: 2,
    forwardPointsBps: 120,
    notionalBaseUnits: "5000",
    settlementDate: "2026-11-01T00:00:00.000Z",
    policy: BASE_POLICY,
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 32,
    ...overrides,
  };
}

describe("fx-hedging-engine", () => {
  it("records STRK20 pool provenance only", () => {
    expect(FX_HEDGING_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
  });

  it("derives an independent generator", () => {
    const point = deriveFxHedgingGenerator();
    expect(point.x).toMatch(/^0x/);
    expect(point.y).toMatch(/^0x/);
  });

  it("computes forward rate inside policy band", () => {
    const quote = computeForwardRate("2.50", 120, 2, BASE_POLICY);
    expect(quote.lockedRateScaled).toBe("253");
    expect(BigInt(quote.lockedRateScaled)).toBeLessThanOrEqual(BigInt(quote.maxLockedRateScaled));
    expect(BigInt(quote.lockedRateScaled)).toBeGreaterThanOrEqual(BigInt(quote.minLockedRateScaled));
  });

  it("rejects forward points outside policy band", () => {
    expect(() => computeForwardRate("2.50", 300, 2, BASE_POLICY)).toThrow(/outside the public policy band/);
  });

  it("computes hedging state surpluses", () => {
    const forward = computeForwardRate("2.50", 120, 2, BASE_POLICY);
    const state = computeHedgingState("5000", forward.lockedRateScaled, forward.spotRateScaled, 45, BASE_POLICY);
    expect(state.eligible).toBe(true);
    expect(BigInt(state.upperSurplus)).toBeGreaterThanOrEqual(0n);
    expect(BigInt(state.lowerSurplus)).toBeGreaterThanOrEqual(0n);
    expect(BigInt(state.tenorSurplus)).toBeGreaterThanOrEqual(0n);
  });

  it(
    "issues and verifies a hedging certificate",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("issue"));
      expect(issued.certificate.proof.proofSystem).toBe(FX_HEDGING_PROOF_SYSTEM);
      expect(verifyFxHedgingCertificate(issued.certificate)).toBe(true);
      expect(JSON.parse(serializeFxHedgingCertificate(issued.certificate)).certificateId).toBe(issued.certificate.certificateId);
      expect(parseFxHedgingCertificate(serializeFxHedgingCertificate(issued.certificate)).certificateId).toBe(
        issued.certificate.certificateId,
      );
    },
    PROOF_TIMEOUT,
  );

  it(
    "rejects ineligible policy surpluses at issue time",
    () => {
      expect(() =>
        issueFxHedgingCertificate(
          baseInput({ forwardPointsBps: 9000, policy: { maxTenorDays: 90, maxForwardPremiumBps: 100, maxForwardDiscountBps: 100 } }),
          NOW,
          makeEntropy("bad-rate"),
        ),
      ).toThrow();
    },
    PROOF_TIMEOUT,
  );

  it(
    "detects tampered notional commitment",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("tamper"));
      const tampered = structuredClone(issued.certificate);
      tampered.proof.notionalCommitment.x = "0x1";
      expect(verifyFxHedgingCertificate(tampered)).toBe(false);
    },
    PROOF_TIMEOUT,
  );

  it(
    "detects tampered issuer signature",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("sig"));
      const tampered = structuredClone(issued.certificate);
      tampered.proof.issuerSignature.response = "0x2";
      expect(verifyFxHedgingCertificate(tampered)).toBe(false);
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies notional disclosure",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("notional"));
      const disclosure = buildFxHedgingAmountDisclosure(issued.certificate, issued.secret, "notional");
      expect(verifyFxHedgingAmountDisclosure(disclosure, issued.certificate)).toBe(true);
      expect(disclosure.value).toBe(issued.secret.notionalBaseUnits);
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies locked-rate disclosure",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("rate"));
      const disclosure = buildFxHedgingAmountDisclosure(issued.certificate, issued.secret, "lockedRate");
      expect(verifyFxHedgingAmountDisclosure(disclosure, issued.certificate)).toBe(true);
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies pair disclosure",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("pair"));
      const disclosure = buildFxHedgingPairDisclosure(issued.certificate, issued.secret);
      expect(verifyFxHedgingPairDisclosure(disclosure, issued.certificate)).toBe(true);
      expect(disclosure.baseCurrency).toBe("USD");
    },
    PROOF_TIMEOUT,
  );

  it(
    "monitors hedging positions against mark spot",
    () => {
      const issued = issueFxHedgingCertificate(baseInput(), NOW, makeEntropy("monitor"));
      const rows = monitorHedgingPositions(
        [
          {
            positionId: issued.certificate.certificateId,
            baseCurrency: "USD",
            quoteCurrency: "STRK",
            notionalBaseUnits: issued.secret.notionalBaseUnits,
            lockedRateScaled: issued.secret.lockedRateScaled,
            spotRateScaled: issued.certificate.spotRateScaled,
            settlementDate: issued.certificate.settlementDate,
            lockedAt: issued.certificate.lockedAt,
          },
        ],
        { "USD/STRK": "2.60" },
        2,
        18,
        NOW,
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].pairLabel).toBe("USD/STRK");
      expect(Number(rows[0].unrealizedPnlBps)).toBeGreaterThan(0);
    },
    PROOF_TIMEOUT,
  );

  it("summarizes trust boundaries honestly", () => {
    const trust = summarizeFxHedgingTrust();
    expect(trust.zeroKnowledge).toBe(true);
    expect(trust.poolIntegrated).toBe(false);
    expect(trust.oracleBacked).toBe(false);
  });

  it("documents visibility model", () => {
    const model = getFxHedgingVisibilityModel();
    expect(model.hiddenFromVerifier.some((line) => line.includes("Notional"))).toBe(true);
    expect(model.disclosedToVerifier.some((line) => line.includes("spot"))).toBe(true);
  });

  it("validates policy bounds", () => {
    expect(requireFxHedgingPolicy(BASE_POLICY).maxTenorDays).toBe(90);
    expect(() => requireFxHedgingPolicy({ ...BASE_POLICY, maxTenorDays: 0 })).toThrow();
  });
});
