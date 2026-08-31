import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "../strk20/config";
import {
  aggregateIdleLedger,
  assessSweepEfficiency,
  buildTreasurySweepAmountDisclosure,
  buildTreasurySweepCertificateBadge,
  buildTreasurySweepMandateDisclosure,
  buildTreasurySweepVenueDisclosure,
  commitTreasuryBalanceRecord,
  computeTreasurySweepState,
  createTreasurySweepIssuerKey,
  deriveTreasurySweepGenerator,
  evaluateSweepTrigger,
  formatBpsShare,
  formatIdleDays,
  formatTreasuryBaseUnits,
  getTreasurySweepVisibilityModel,
  IDLE_TIER_COUNT,
  issueTreasurySweepCertificate,
  MAX_SWEEP_SHARE_BPS,
  parseTreasurySweepAmountDisclosure,
  parseTreasurySweepCertificate,
  parseTreasurySweepCertificateBadge,
  parseTreasurySweepCertificateSecret,
  parseTreasurySweepRefDisclosure,
  projectSweepYieldSchedule,
  requireTreasurySweepPolicy,
  serializeTreasurySweepAmountDisclosure,
  serializeTreasurySweepCertificate,
  serializeTreasurySweepCertificateBadge,
  serializeTreasurySweepCertificateSecret,
  serializeTreasurySweepRefDisclosure,
  summarizeTreasurySweepTrust,
  TREASURY_SWEEP_POOL_ADDRESS,
  TREASURY_SWEEP_PROOF_SYSTEM,
  TREASURY_SURPLUS_EXTRA_BITS,
  verifyTreasurySweepAmountDisclosure,
  verifyTreasurySweepCertificate,
  verifyTreasurySweepRefDisclosure,
  type IssueTreasurySweepCertificateInput,
  type TreasurySweepAmountField,
  type TreasurySweepPolicy,
} from "../treasury-sweep-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-31T00:00:00.000Z");
const PROOF_TIMEOUT = 120_000;

/** Deterministic, collision-free entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `tsw_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createTreasurySweepIssuerKey(makeEntropy(seed));
}

const BASE_POLICY: TreasurySweepPolicy = {
  minReserveBaseUnits: "4000",
  maxSweepShareBps: 6000,
  minYieldBps: 400,
};

const BASE_TIERS: [string, string, string, string] = ["1000", "2000", "3000", "4000"];

function baseInput(overrides: Partial<IssueTreasurySweepCertificateInput> = {}): IssueTreasurySweepCertificateInput {
  return {
    merchantAlias: "Aurora Studio",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 0 },
    mandateRef: "TREAS-2026-0007",
    programLabel: "Idle Capital Sweep",
    policy: BASE_POLICY,
    tierBalancesBaseUnits: BASE_TIERS,
    sweepBaseUnits: "5000",
    projectedYieldBaseUnits: "250",
    venueRef: "vault_alpha_strategy",
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 16,
    ...overrides,
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe("idle-age ledger aggregation", () => {
  const rows = [
    { alias: "ops-hot", lastMovedAt: "2026-08-29T00:00:00.000Z", balanceBaseUnits: "1000" },
    { alias: "ops-warm", lastMovedAt: "2026-08-11T00:00:00.000Z", balanceBaseUnits: "2000" },
    { alias: "reserve-q3", lastMovedAt: "2026-07-01T00:00:00.000Z", balanceBaseUnits: "3000" },
    { alias: "reserve-cold", lastMovedAt: "2026-01-01T00:00:00.000Z", balanceBaseUnits: "4000" },
  ];

  it("buckets each balance row into its idle-age tier as of a date", () => {
    const ledger = aggregateIdleLedger(rows, NOW);
    expect(ledger.tiers).toHaveLength(IDLE_TIER_COUNT);
    expect(ledger.tiers.map((t) => t.balanceBaseUnits)).toEqual(["1000", "2000", "3000", "4000"]);
    expect(ledger.tiers.map((t) => t.accountCount)).toEqual([1, 1, 1, 1]);
    expect(ledger.tiers.map((t) => t.sweepEligible)).toEqual([false, true, true, true]);
    expect(ledger.totalIdleBaseUnits).toBe("10000");
    expect(ledger.eligibleIdleBaseUnits).toBe("9000");
    expect(ledger.weightedIdleDays).toBe("1193000");
    expect(ledger.averageIdleDays).toBe("119");
    expect(ledger.eligibleShareBps).toBe("9000");
    expect(ledger.asOf).toBe(NOW.toISOString());
  });

  it("treats a future timestamp as zero idle days and returns an empty ledger for no rows", () => {
    const future = aggregateIdleLedger(
      [{ alias: "just-moved", lastMovedAt: "2026-09-30T00:00:00.000Z", balanceBaseUnits: "500" }],
      NOW,
    );
    expect(future.tiers[0].balanceBaseUnits).toBe("500");
    expect(future.eligibleIdleBaseUnits).toBe("0");
    expect(future.weightedIdleDays).toBe("0");

    const empty = aggregateIdleLedger([], NOW);
    expect(empty.totalIdleBaseUnits).toBe("0");
    expect(empty.averageIdleDays).toBe("0");
    expect(empty.eligibleShareBps).toBe("0");
  });

  it("rejects malformed balance rows", () => {
    expect(() => aggregateIdleLedger([{ alias: "  ", lastMovedAt: NOW.toISOString(), balanceBaseUnits: "1" }], NOW)).toThrow(
      /balance alias/i,
    );
    expect(() => aggregateIdleLedger([{ alias: "x", lastMovedAt: "not-a-date", balanceBaseUnits: "1" }], NOW)).toThrow(
      /ISO-8601/i,
    );
    expect(() => aggregateIdleLedger([{ alias: "x", lastMovedAt: NOW.toISOString(), balanceBaseUnits: "-1" }], NOW)).toThrow(
      /must not be negative/i,
    );
  });
});
describe("sweep state and covenant surpluses", () => {
  it("computes every covenant surplus the proof attests", () => {
    const state = computeTreasurySweepState(BASE_TIERS, "5000", "250", BASE_POLICY);
    expect(state).toMatchObject({
      totalIdleBaseUnits: "10000",
      eligibleIdleBaseUnits: "9000",
      sweepBaseUnits: "5000",
      projectedYieldBaseUnits: "250",
      retainedBaseUnits: "5000",
      sweepShareBps: "5000",
      impliedYieldBps: "500",
      // 10000 − 5000 − 4000
      reserveSurplus: "1000",
      // 9000 − 5000
      eligibilitySurplus: "4000",
      // 6000·10000 − 10000·5000
      shareSurplus: "10000000",
      // 10000·250 − 400·5000
      yieldSurplus: "500000",
      eligible: true,
    });
  });

  it("sits at zero surplus when the sweep is exactly at every covenant edge", () => {
    const state = computeTreasurySweepState(BASE_TIERS, "5000", "200", {
      minReserveBaseUnits: "5000",
      maxSweepShareBps: 5000,
      minYieldBps: 400,
    });
    expect(state.reserveSurplus).toBe("0");
    expect(state.shareSurplus).toBe("0");
    expect(state.yieldSurplus).toBe("0");
    expect(state.eligible).toBe(true);
  });

  it("marks each individual covenant breach as ineligible", () => {
    // Reserve floor broken: 10000 − 9000 < 4000.
    expect(computeTreasurySweepState(BASE_TIERS, "9000", "500", BASE_POLICY).eligible).toBe(false);
    // Sourced from the active tier: sweep 9500 > eligible 9000.
    expect(computeTreasurySweepState(BASE_TIERS, "9500", "500", { ...BASE_POLICY, minReserveBaseUnits: "0" })).toMatchObject({
      eligibilitySurplus: "-500",
      eligible: false,
    });
    // Share cap broken: 10000·5000 > 1000·10000.
    expect(
      computeTreasurySweepState(BASE_TIERS, "5000", "500", { ...BASE_POLICY, maxSweepShareBps: 1000 }),
    ).toMatchObject({ shareSurplus: "-40000000", eligible: false });
    // Hurdle missed: 10000·10 < 400·5000.
    expect(computeTreasurySweepState(BASE_TIERS, "5000", "10", BASE_POLICY)).toMatchObject({
      yieldSurplus: "-1900000",
      eligible: false,
    });
  });
});
describe("yield accrual calculations", () => {
  it("accrues compounding periods with exact integer floor arithmetic", () => {
    const schedule = projectSweepYieldSchedule("1000000", 500, 12, 3, true);
    expect(schedule.compounding).toBe(true);
    expect(schedule.isProjectionOnly).toBe(true);
    expect(schedule.principalBaseUnits).toBe("1000000");
    expect(schedule.annualRateBps).toBe("500");
    expect(schedule.periodsPerYear).toBe(12);
    expect(schedule.periods.map((p) => p.accruedBaseUnits)).toEqual(["4166", "4184", "4201"]);
    expect(schedule.periods.map((p) => p.openingBalanceBaseUnits)).toEqual(["1000000", "1004166", "1008350"]);
    expect(schedule.periods.map((p) => p.closingBalanceBaseUnits)).toEqual(["1004166", "1008350", "1012551"]);
    expect(schedule.periods.map((p) => p.cumulativeAccruedBaseUnits)).toEqual(["4166", "8350", "12551"]);
    expect(schedule.totalAccruedBaseUnits).toBe("12551");
    expect(schedule.endingBalanceBaseUnits).toBe("1012551");
  });

  it("accrues simple interest on the principal only, so it trails compounding", () => {
    const simple = projectSweepYieldSchedule("1000000", 500, 12, 3, false);
    expect(simple.compounding).toBe(false);
    expect(simple.periods.map((p) => p.accruedBaseUnits)).toEqual(["4166", "4166", "4166"]);
    expect(simple.totalAccruedBaseUnits).toBe("12498");
    expect(simple.endingBalanceBaseUnits).toBe("1012498");
    expect(BigInt(simple.totalAccruedBaseUnits)).toBeLessThan(
      BigInt(projectSweepYieldSchedule("1000000", 500, 12, 3, true).totalAccruedBaseUnits),
    );
  });

  it("accrues nothing at a zero rate or on a zero principal", () => {
    expect(projectSweepYieldSchedule("1000000", 0, 12, 4).totalAccruedBaseUnits).toBe("0");
    expect(projectSweepYieldSchedule("0", 500, 12, 4).endingBalanceBaseUnits).toBe("0");
  });

  it("floors sub-unit accrual to zero rather than inventing a fraction", () => {
    // 100 · 500 / (10000 · 12) = 0.4166… → 0 base units.
    expect(projectSweepYieldSchedule("100", 500, 12, 2).periods.map((p) => p.accruedBaseUnits)).toEqual(["0", "0"]);
  });

  it("validates the schedule inputs", () => {
    expect(() => projectSweepYieldSchedule("1000", 10_001, 12, 3)).toThrow(/annual rate bps/i);
    expect(() => projectSweepYieldSchedule("1000", 500, 0, 3)).toThrow(/periods per year/i);
    expect(() => projectSweepYieldSchedule("1000", 500, 12, 0)).toThrow(/periods/i);
    expect(() => projectSweepYieldSchedule("1000", 500, 12, 121)).toThrow(/periods/i);
    expect(() => projectSweepYieldSchedule("-1", 500, 12, 3)).toThrow(/principal/i);
  });
});
describe("sweep threshold triggers", () => {
  const state = computeTreasurySweepState(BASE_TIERS, "5000", "250", BASE_POLICY);

  it("arms when the eligible idle band reaches the threshold and executes nothing", () => {
    const armed = evaluateSweepTrigger(state, "9000");
    expect(armed).toMatchObject({
      armed: true,
      eligibleIdleBaseUnits: "9000",
      triggerBaseUnits: "9000",
      shortfallBaseUnits: "0",
      executesAnything: false,
    });
  });

  it("stays disarmed below the threshold and reports the exact shortfall", () => {
    const idle = evaluateSweepTrigger(state, "12500");
    expect(idle.armed).toBe(false);
    expect(idle.shortfallBaseUnits).toBe("3500");
    expect(idle.executesAnything).toBe(false);
  });

  it("arms on a zero threshold and rejects a malformed one", () => {
    expect(evaluateSweepTrigger(state, "0").armed).toBe(true);
    expect(() => evaluateSweepTrigger(state, "-1")).toThrow(/sweep trigger threshold/i);
    expect(() => evaluateSweepTrigger(state, "12.5")).toThrow(/sweep trigger threshold/i);
  });
});

describe("efficiency banding and policy validation", () => {
  it("bands a well-deployed treasury above a stalled one", () => {
    const deployed = assessSweepEfficiency(computeTreasurySweepState(BASE_TIERS, "5000", "250", BASE_POLICY));
    const stalled = assessSweepEfficiency(computeTreasurySweepState(BASE_TIERS, "100", "10", BASE_POLICY));
    expect(deployed.eligible).toBe(true);
    expect(deployed.score).toBeGreaterThan(stalled.score);
    expect(deployed.rationale).toContain("Heuristic blend");
    expect(["optimal", "adequate", "lagging", "idle-heavy"]).toContain(deployed.band);
  });

  it("calls any covenant breach idle-heavy and says which surpluses can fail", () => {
    const breached = assessSweepEfficiency(computeTreasurySweepState(BASE_TIERS, "9000", "500", BASE_POLICY));
    expect(breached.eligible).toBe(false);
    expect(breached.band).toBe("idle-heavy");
    expect(breached.rationale).toContain("covenants fail");
  });

  it("validates the public policy bounds", () => {
    expect(requireTreasurySweepPolicy(BASE_POLICY)).toEqual({ minReserve: 4000n, maxSweepShareBps: 6000, minYieldBps: 400 });
    expect(() => requireTreasurySweepPolicy({ ...BASE_POLICY, minReserveBaseUnits: "-1" })).toThrow(/minimum reserve/i);
    expect(() =>
      requireTreasurySweepPolicy({ ...BASE_POLICY, maxSweepShareBps: MAX_SWEEP_SHARE_BPS + 1 }),
    ).toThrow(/maximum sweep share/i);
    expect(() => requireTreasurySweepPolicy({ ...BASE_POLICY, minYieldBps: -1 })).toThrow(/minimum yield/i);
  });
});
describe("certificate lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a certificate", () => {
    const { certificate, secret } = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(certificate.proof.proofSystem).toBe(TREASURY_SWEEP_PROOF_SYSTEM);
    expect(certificate.proof.amountBitLength).toBe(16);
    expect(certificate.proof.surplusBitLength).toBe(16 + TREASURY_SURPLUS_EXTRA_BITS);
    expect(certificate.proof.tierCommitments).toHaveLength(IDLE_TIER_COUNT);
    expect(certificate.poolAddress).toBe(TREASURY_SWEEP_POOL_ADDRESS);
    expect(verifyTreasurySweepCertificate(certificate)).toBe(true);

    const round = parseTreasurySweepCertificate(serializeTreasurySweepCertificate(certificate));
    expect(round.bindingHash).toBe(certificate.bindingHash);
    expect(verifyTreasurySweepCertificate(round)).toBe(true);

    expect(secret.totalIdleBaseUnits).toBe("10000");
    expect(secret.eligibleIdleBaseUnits).toBe("9000");
    expect(secret.sweepBaseUnits).toBe("5000");
    expect(secret.projectedYieldBaseUnits).toBe("250");
    expect(secret.tierBalancesBaseUnits).toEqual(BASE_TIERS);
    const secretRound = parseTreasurySweepCertificateSecret(serializeTreasurySweepCertificateSecret(secret));
    expect(secretRound).toMatchObject({ sweepBaseUnits: "5000", venueRef: "vault_alpha_strategy" });
  });

  it("verifies a sweep sitting exactly on the reserve, share-cap, and hurdle edges", () => {
    const { certificate } = issueTreasurySweepCertificate(
      baseInput({
        policy: { minReserveBaseUnits: "5000", maxSweepShareBps: 5000, minYieldBps: 400 },
        projectedYieldBaseUnits: "200",
      }),
      NOW,
      makeEntropy("edge"),
    );
    expect(verifyTreasurySweepCertificate(certificate)).toBe(true);
  });

  it("marks a certificate issued without a venue reference as uncommitted", () => {
    const { certificate, secret } = issueTreasurySweepCertificate(baseInput({ venueRef: "" }), NOW, makeEntropy("bare"));
    expect(certificate.venueCommitted).toBe(false);
    expect(certificate.venueCommitment).toBe("0x0");
    expect(certificate.mandateCommitted).toBe(true);
    expect(verifyTreasurySweepCertificate(certificate)).toBe(true);
    expect(() => buildTreasurySweepVenueDisclosure(secret)).toThrow(/no committed venue reference/i);
  });
});
describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest a sweep that breaks the reserve floor", () => {
    expect(() => issueTreasurySweepCertificate(baseInput({ sweepBaseUnits: "9000" }), NOW, makeEntropy("g1"))).toThrow(
      /covenant surpluses is negative/i,
    );
  });

  it("refuses to attest a sweep sourced from the active tier", () => {
    expect(() =>
      issueTreasurySweepCertificate(
        baseInput({ sweepBaseUnits: "9500", policy: { ...BASE_POLICY, minReserveBaseUnits: "0", maxSweepShareBps: 10_000 } }),
        NOW,
        makeEntropy("g2"),
      ),
    ).toThrow(/covenant surpluses is negative/i);
  });

  it("refuses to attest a projected yield below the public hurdle", () => {
    expect(() =>
      issueTreasurySweepCertificate(baseInput({ projectedYieldBaseUnits: "10" }), NOW, makeEntropy("g3")),
    ).toThrow(/covenant surpluses is negative/i);
  });

  it("rejects a missing merchant alias and a malformed token address", () => {
    expect(() => issueTreasurySweepCertificate(baseInput({ merchantAlias: "   " }), NOW, makeEntropy("g4"))).toThrow(
      /merchant alias/i,
    );
    expect(() =>
      issueTreasurySweepCertificate(
        baseInput({ asset: { symbol: "STRK", tokenAddress: "not-an-address", decimals: 0 } }),
        NOW,
        makeEntropy("g5"),
      ),
    ).toThrow(/0x prefix/i);
  });

  it("rejects over-long mandate and venue references and unsupported asset decimals", () => {
    expect(() => issueTreasurySweepCertificate(baseInput({ mandateRef: "M".repeat(97) }), NOW, makeEntropy("g6"))).toThrow(
      /mandate reference/i,
    );
    expect(() => issueTreasurySweepCertificate(baseInput({ venueRef: "V".repeat(97) }), NOW, makeEntropy("g7"))).toThrow(
      /venue reference/i,
    );
    expect(() =>
      issueTreasurySweepCertificate(
        baseInput({ asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 19 } }),
        NOW,
        makeEntropy("g8"),
      ),
    ).toThrow(/asset decimals/i);
  });
  it("rejects a tier balance that exceeds the provable bit band", () => {
    expect(() =>
      issueTreasurySweepCertificate(
        baseInput({ tierBalancesBaseUnits: ["1000", "2000", "3000", (1n << 16n).toString()] }),
        NOW,
        makeEntropy("g9"),
      ),
    ).toThrow(/16-bit band/i);
  });

  it("rejects a wrong number of idle tiers and a negative tier balance", () => {
    expect(() =>
      issueTreasurySweepCertificate(
        baseInput({ tierBalancesBaseUnits: ["1000", "2000", "3000"] as unknown as [string, string, string, string] }),
        NOW,
        makeEntropy("g10"),
      ),
    ).toThrow(/idle-age tier balances are required/i);
    expect(() =>
      issueTreasurySweepCertificate(baseInput({ tierBalancesBaseUnits: ["-1", "2000", "3000", "4000"] }), NOW, makeEntropy("g11")),
    ).toThrow(/tier 0 balance/i);
  });

  it("rejects a malformed issuer secret key and an out-of-range bit length", () => {
    expect(() => issueTreasurySweepCertificate(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("g12"))).toThrow(
      /scalar/i,
    );
    expect(() => issueTreasurySweepCertificate(baseInput({ amountBitLength: 4 }), NOW, makeEntropy("g13"))).toThrow(
      /amount bit length/i,
    );
    expect(() => issueTreasurySweepCertificate(baseInput({ amountBitLength: 256 }), NOW, makeEntropy("g14"))).toThrow(
      /amount bit length/i,
    );
  });
});

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyTreasurySweepCertificate(issued.certificate)).toBe(true);
  });

  it("rejects a loosened public reserve floor", () => {
    const c = clone(issued.certificate);
    c.minReserveBaseUnits = "0";
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a widened public share cap", () => {
    const c = clone(issued.certificate);
    c.maxSweepShareBps = "10000";
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });
  it("rejects a lowered public yield hurdle", () => {
    const c = clone(issued.certificate);
    c.minYieldBps = "0";
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const c = clone(issued.certificate);
    c.bindingHash = c.bindingHash === "0x0" ? "0x1" : `${c.bindingHash}0`;
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const c = clone(issued.certificate);
    c.issuerSignature = { ...c.issuerSignature, response: "0x1" };
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a tampered tier range-proof bit", () => {
    const c = clone(issued.certificate);
    c.proof.tierBits[2][0] = { ...c.proof.tierBits[2][0], response0: "0x1" };
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a tampered reserve-surplus bit", () => {
    const c = clone(issued.certificate);
    c.proof.reserveSurplusBits[0] = { ...c.proof.reserveSurplusBits[0], response1: "0x1" };
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a swapped eligible-idle commitment that drops the active tier constraint", () => {
    const c = clone(issued.certificate);
    c.proof.eligibleIdleCommitment = { ...c.proof.totalIdleCommitment };
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const c = clone(issued.certificate);
    c.proof.generatorH = { ...c.issuerPublicKey };
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a corrupted commitment point and a mismatched surplus bit length", () => {
    const bad = clone(issued.certificate);
    bad.proof.sweepCommitment = { x: "0x1", y: "0x1" };
    expect(verifyTreasurySweepCertificate(bad)).toBe(false);

    const shrunk = clone(issued.certificate);
    shrunk.proof.surplusBitLength = shrunk.proof.amountBitLength;
    expect(verifyTreasurySweepCertificate(shrunk)).toBe(false);
  });
});
describe("selective disclosure", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("disc"));

  it("opens every committed amount field against its own commitment", () => {
    const expected: Record<TreasurySweepAmountField, string> = {
      totalIdle: "10000",
      eligibleIdle: "9000",
      sweep: "5000",
      yield: "250",
      tier0: "1000",
      tier1: "2000",
      tier2: "3000",
      tier3: "4000",
    };
    for (const field of Object.keys(expected) as TreasurySweepAmountField[]) {
      const disclosure = buildTreasurySweepAmountDisclosure(issued.secret, field);
      expect(disclosure.amountBaseUnits).toBe(expected[field]);
      expect(verifyTreasurySweepAmountDisclosure(issued.certificate, disclosure)).toBe(true);

      const round = parseTreasurySweepAmountDisclosure(serializeTreasurySweepAmountDisclosure(disclosure));
      expect(verifyTreasurySweepAmountDisclosure(issued.certificate, round)).toBe(true);
      expect(verifyTreasurySweepAmountDisclosure(issued.certificate, { ...disclosure, amountBaseUnits: "1" })).toBe(false);
      expect(verifyTreasurySweepAmountDisclosure(issued.certificate, { ...disclosure, certificateId: "tsw_other" })).toBe(false);
    }
  });

  it("rejects an unknown amount field on both build and verify", () => {
    expect(() => buildTreasurySweepAmountDisclosure(issued.secret, "tier9" as TreasurySweepAmountField)).toThrow(
      /unknown treasury sweep amount field/i,
    );
    const disclosure = buildTreasurySweepAmountDisclosure(issued.secret, "sweep");
    expect(
      verifyTreasurySweepAmountDisclosure(issued.certificate, { ...disclosure, field: "tier9" as TreasurySweepAmountField }),
    ).toBe(false);
  });

  it("opens the public mandate and the secret venue reference", () => {
    const mandate = buildTreasurySweepMandateDisclosure(issued.secret);
    expect(mandate.value).toBe("TREAS-2026-0007");
    expect(verifyTreasurySweepRefDisclosure(issued.certificate, mandate)).toBe(true);
    const mandateRound = parseTreasurySweepRefDisclosure(serializeTreasurySweepRefDisclosure(mandate));
    expect(verifyTreasurySweepRefDisclosure(issued.certificate, mandateRound)).toBe(true);
    expect(verifyTreasurySweepRefDisclosure(issued.certificate, { ...mandate, value: "TREAS-OTHER" })).toBe(false);

    const venue = buildTreasurySweepVenueDisclosure(issued.secret);
    expect(venue.value).toBe("vault_alpha_strategy");
    expect(verifyTreasurySweepRefDisclosure(issued.certificate, venue)).toBe(true);
    expect(verifyTreasurySweepRefDisclosure(issued.certificate, { ...venue, salt: "0x1" })).toBe(false);
  });
});
describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds the tier balances, sweep, yield, blindings, salts, or venue in the certificate", () => {
    const { certificate, secret } = issueTreasurySweepCertificate(
      baseInput({
        tierBalancesBaseUnits: ["1111", "2222", "3333", "4444"],
        sweepBaseUnits: "6666",
        projectedYieldBaseUnits: "999",
        policy: { minReserveBaseUnits: "1000", maxSweepShareBps: 7000, minYieldBps: 400 },
        venueRef: "SECRET-VENUE-ZZZ",
      }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyTreasurySweepCertificate(certificate)).toBe(true);

    const structured = JSON.stringify(certificate);
    const serialized = serializeTreasurySweepCertificate(certificate);
    for (const surface of [structured, serialized]) {
      expect(surface).not.toContain("SECRET-VENUE-ZZZ");
      expect(surface).not.toContain(secret.totalIdleBlinding);
      expect(surface).not.toContain(secret.sweepBlinding);
      expect(surface).not.toContain(secret.yieldBlinding);
      expect(surface).not.toContain(secret.reserveSurplusBlinding);
      expect(surface).not.toContain(secret.shareSurplusBlinding);
      expect(surface).not.toContain(secret.venueSalt);
      expect(surface).not.toContain(secret.mandateSalt);
      for (const blinding of secret.tierBlindings) expect(surface).not.toContain(blinding);
    }
    // Secret figures are absent from the structured certificate; public policy is present.
    for (const figure of ["1111", "2222", "3333", "4444", "6666", "999"]) {
      expect(structured).not.toContain(`"${figure}"`);
    }
    expect(structured).toContain('"minReserveBaseUnits":"1000"');
    expect(structured).toContain('"maxSweepShareBps":"7000"');
    expect(structured).toContain('"minYieldBps":"400"');
    expect(structured).toContain("TREAS-2026-0007");
  });

  it("keeps identical treasuries unlinkable by producing distinct commitments", () => {
    const a = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("za"));
    const b = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("zb"));
    expect(a.certificate.proof.totalIdleCommitment.x).not.toBe(b.certificate.proof.totalIdleCommitment.x);
    expect(a.certificate.proof.sweepCommitment.x).not.toBe(b.certificate.proof.sweepCommitment.x);
    expect(a.certificate.bindingHash).not.toBe(b.certificate.bindingHash);
    expect(verifyTreasurySweepCertificate(a.certificate)).toBe(true);
    expect(verifyTreasurySweepCertificate(b.certificate)).toBe(true);
  });
});
describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeTreasurySweepTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesTierConservation).toBe(true);
    expect(trust.provesReserveCovenant).toBe(true);
    expect(trust.provesEligibleSourcing).toBe(true);
    expect(trust.provesShareCapCovenant).toBe(true);
    expect(trust.provesYieldHurdleCovenant).toBe(true);
    expect(trust.hidesTierBalances).toBe(true);
    expect(trust.hidesSweepAmount).toBe(true);
    expect(trust.hidesProjectedYield).toBe(true);
    expect(trust.hidesBalanceRows).toBe(true);
    expect(trust.hidesYieldVenue).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.supportsSelectiveDisclosure).toBe(true);

    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.sweepsOrMovesFunds).toBe(false);
    expect(trust.depositsIntoAnyVault).toBe(false);
    expect(trust.earnsInterest).toBe(false);
    expect(trust.readsShieldedBalances).toBe(false);
    expect(trust.settlesOnChain).toBe(false);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.callsPoolContract).toBe(false);
    expect(trust.verifiesFiguresAreReal).toBe(false);
    expect(trust.guaranteesYield).toBe(false);
    expect(trust.isFinancialAdvice).toBe(false);

    expect(trust.statement).toContain("neither decentralized nor automatic");
    expect(trust.statement).toContain("does NOT sweep, move, transfer, deposit, withdraw, stake, lend, or invest any value");
    expect(trust.statement).toContain("nothing earns interest");
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
    expect(trust.statement).toContain(TREASURY_SWEEP_POOL_ADDRESS);
    expect(trust.statement).toContain("not financial advice");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getTreasurySweepVisibilityModel();
    expect(model.limitation).toContain("cannot confirm");
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.limitation).toContain("provenance only");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
    expect(model.applicationOnly.length).toBeGreaterThan(0);
  });
});
describe("badge, commitments, and formatting helpers", { timeout: PROOF_TIMEOUT }, () => {
  it("builds a badge that displays only the public covenants", () => {
    const { certificate, secret } = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildTreasurySweepCertificateBadge(certificate);
    expect(badge.minReserveDisplay).toBe("reserve ≥ 4000 STRK");
    expect(badge.maxShareDisplay).toBe("sweep ≤ 60% of idle");
    expect(badge.minYieldDisplay).toBe("hurdle ≥ 4% (operator-typed, not offered)");
    expect(badge.venueCommitted).toBe(true);
    expect(badge.mandateRef).toBe("TREAS-2026-0007");

    const json = JSON.stringify(badge);
    expect(json).not.toContain(secret.venueRef);
    expect(json).not.toContain(secret.venueSalt);
    expect(json).not.toContain(secret.sweepBlinding);
    for (const figure of [...secret.tierBalancesBaseUnits, secret.sweepBaseUnits, secret.projectedYieldBaseUnits]) {
      expect(json).not.toContain(`"${figure}"`);
    }

    const round = parseTreasurySweepCertificateBadge(serializeTreasurySweepCertificateBadge(badge));
    expect(round).toEqual(badge);
  });

  it("derives a stable, canonical generator H", () => {
    const a = deriveTreasurySweepGenerator();
    const b = deriveTreasurySweepGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
  });

  it("commits a balance row deterministically under a fixed salt and diverges otherwise", () => {
    const first = commitTreasuryBalanceRecord("ops-warm", "2026-08-11T00:00:00.000Z", "2000", 77n);
    const again = commitTreasuryBalanceRecord("ops-warm", "2026-08-11T00:00:00.000Z", "2000", 77n);
    expect(first).toBe(again);
    expect(first).toMatch(/^0x[0-9a-f]+$/);
    expect(commitTreasuryBalanceRecord("ops-warm", "2026-08-11T00:00:00.000Z", "2001", 77n)).not.toBe(first);
    expect(commitTreasuryBalanceRecord("ops-warm", "2026-08-11T00:00:00.000Z", "2000", 78n)).not.toBe(first);
    expect(() => commitTreasuryBalanceRecord("   ", "2026-08-11T00:00:00.000Z", "2000", 77n)).toThrow(/balance alias/i);
  });

  it("formats base units, idle windows, and basis-point shares for display", () => {
    expect(formatTreasuryBaseUnits("1000000000000000000", 18)).toBe("1");
    expect(formatTreasuryBaseUnits("4000", 0)).toBe("4000");
    expect(formatIdleDays(0)).toBe("0 days");
    expect(formatIdleDays(1)).toBe("1 day");
    expect(formatIdleDays(31)).toBe("31 days");
    expect(formatIdleDays(4000)).toBe("3650+ days");
    expect(formatBpsShare("6000")).toBe("60%");
    expect(formatBpsShare("1250")).toBe("12.5%");
    expect(formatBpsShare(MAX_SWEEP_SHARE_BPS)).toBe("100%");
    expect(formatBpsShare(7n)).toBe("0.07%");
  });

  it("rejects a malformed encoded certificate", () => {
    expect(() => parseTreasurySweepCertificate("!!not base64!!")).toThrow(/encoding is invalid/i);
    expect(() => parseTreasurySweepCertificate("")).toThrow(/encoding is invalid/i);
  });
});

/**
 * Regressions for an adversarial review of the verifier. Each case below was a
 * working forgery at one point: a holder could rewrite part of a signed
 * certificate, or open a commitment to a false value, and still get `true`.
 */
describe("forgery regressions", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueTreasurySweepCertificate(baseInput(), NOW, makeEntropy("forgery"));

  it("baseline verifies", () => {
    expect(verifyTreasurySweepCertificate(issued.certificate)).toBe(true);
  });

  it("rejects an amount disclosure inflated by the curve order", () => {
    // Re-committing reduces the amount mod n, so amount + n opens the same
    // point. Without a canonical bound this passed as a valid opening.
    const disclosure = buildTreasurySweepAmountDisclosure(issued.secret, "totalIdle");
    expect(verifyTreasurySweepAmountDisclosure(issued.certificate, disclosure)).toBe(true);
    const inflated = { ...disclosure, amountBaseUnits: (BigInt(disclosure.amountBaseUnits) + CURVE_ORDER).toString() };
    expect(verifyTreasurySweepAmountDisclosure(issued.certificate, inflated)).toBe(false);
    const wrapped = { ...disclosure, amountBaseUnits: (BigInt(disclosure.amountBaseUnits) + CURVE_ORDER * 2n).toString() };
    expect(verifyTreasurySweepAmountDisclosure(issued.certificate, wrapped)).toBe(false);
  });

  it("rejects an empty memo relabelled to the placeholder character", () => {
    // The binding hash once substituted "-" for an absent memo, so "" and "-"
    // collided and an empty-memo certificate could be relabelled in place.
    const blank = issueTreasurySweepCertificate(baseInput({ memo: undefined }), NOW, makeEntropy("forgery-memo"));
    expect(blank.certificate.memo).toBe("");
    expect(verifyTreasurySweepCertificate(blank.certificate)).toBe(true);

    const relabelled = clone(blank.certificate);
    relabelled.memo = "-";
    expect(verifyTreasurySweepCertificate(relabelled)).toBe(false);
  });

  it("rejects rewritten engine constants, including the limitation notice", () => {
    // These four are engine constants rather than per-certificate data, and the
    // binding hash commits to the version constant instead of the field, so the
    // verifier has to check them literally.
    const version = clone(issued.certificate);
    (version as { version: number }).version = 99;
    expect(verifyTreasurySweepCertificate(version)).toBe(false);

    const network = clone(issued.certificate);
    (network as { network: string }).network = "0x534e5f5345504f4c4941";
    expect(verifyTreasurySweepCertificate(network)).toBe(false);

    const pool = clone(issued.certificate);
    (pool as { poolAddress: string }).poolAddress = "0x1";
    expect(verifyTreasurySweepCertificate(pool)).toBe(false);

    const notice = clone(issued.certificate);
    notice.notice = "No covenant limitations apply.";
    expect(verifyTreasurySweepCertificate(notice)).toBe(false);
  });

  it("rejects asset decimals outside the displayable range", () => {
    // buildTreasurySweepCertificateBadge throws above 18 decimals, so a verifier
    // that accepted them handed a crash to whatever rendered the result.
    const c = clone(issued.certificate);
    c.assetDecimals = 100;
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
    expect(() => buildTreasurySweepCertificateBadge(c)).toThrow();
  });

  it("rejects a public reserve floor shifted by the curve order", () => {
    const c = clone(issued.certificate);
    c.minReserveBaseUnits = (BigInt(c.minReserveBaseUnits) + CURVE_ORDER).toString();
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });

  it("rejects a reserve floor that is congruent in both the field and the curve order", () => {
    // The sharpest form of the same attack, and the reason the verifier needs an
    // explicit canonical bound rather than relying on its other checks: adding
    // FIELD_PRIME · CURVE_ORDER leaves the binding hash untouched (Poseidon
    // reduces mod the field prime) AND leaves leg 6 untouched (scalar
    // multiplication reduces mod the curve order). Every other check still
    // passes, so the certificate would advertise an astronomical reserve floor
    // while proving only totalIdle − sweep ≥ 0.
    const FIELD_PRIME = 2n ** 251n + 17n * 2n ** 192n + 1n;
    const c = clone(issued.certificate);
    const honestFloor = BigInt(c.minReserveBaseUnits);
    c.minReserveBaseUnits = (honestFloor + FIELD_PRIME * CURVE_ORDER).toString();
    expect(BigInt(c.minReserveBaseUnits) % FIELD_PRIME).toBe(honestFloor);
    expect(BigInt(c.minReserveBaseUnits) % CURVE_ORDER).toBe(honestFloor);
    expect(verifyTreasurySweepCertificate(c)).toBe(false);
  });
});
