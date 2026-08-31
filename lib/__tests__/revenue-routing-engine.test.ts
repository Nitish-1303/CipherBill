import { describe, expect, it } from "vitest";

import {
  AFFILIATE_SLOT_INDEX,
  BPS_SCALE,
  MAX_POSSIBLE_ROUTING_DUST,
  MAX_ROUTING_DUST_BASE_UNITS,
  REVENUE_ROUTING_CHECK_COUNT,
  REVENUE_ROUTING_ENGINE_VERSION,
  REVENUE_ROUTING_LIMITATIONS,
  REVENUE_ROUTING_POOL_ADDRESS,
  REVENUE_ROUTING_PROOF_SYSTEM,
  REVENUE_ROUTING_SLOTS,
  ROUTING_DUST_BIT_LENGTH,
  ROUTING_SLOT_COUNT,
  ROUTING_SURPLUS_EXTRA_BITS,
  TAX_RESERVE_SLOT_INDEX,
  aggregateCorridorLedger,
  assessRoutingConcentration,
  assessRoutingPolicy,
  auditRevenueRoutingCertificate,
  buildRevenueRoutingAgreementDisclosure,
  buildRevenueRoutingAmountDisclosure,
  buildRevenueRoutingCertificateBadge,
  buildRevenueRoutingPayerDisclosure,
  buildRevenueRoutingRecipientDisclosure,
  buildRoutingWaterfall,
  commitSettlementRow,
  computeRevenueRoutingPlan,
  createRevenueRoutingIssuerKey,
  deriveRevenueRoutingGenerator,
  estimateRevenueRoutingProofCount,
  evaluateRoutingRelease,
  formatRoutingBaseUnits,
  formatRoutingBps,
  formatSettlementAgeDays,
  getRevenueRoutingTrustModel,
  getRevenueRoutingVisibilityModel,
  issueRevenueRoutingCertificate,
  normalizeRoutingSplit,
  parseRevenueRoutingAmountDisclosure,
  parseRevenueRoutingCertificate,
  parseRevenueRoutingCertificateBadge,
  parseRevenueRoutingCertificateSecret,
  parseRevenueRoutingKeypair,
  parseRevenueRoutingRefDisclosure,
  requireRevenueRoutingPolicy,
  serializeRevenueRoutingAmountDisclosure,
  serializeRevenueRoutingCertificate,
  serializeRevenueRoutingCertificateBadge,
  serializeRevenueRoutingCertificateSecret,
  serializeRevenueRoutingKeypair,
  serializeRevenueRoutingRefDisclosure,
  verifyRevenueRoutingAmountDisclosure,
  verifyRevenueRoutingCertificate,
  verifyRevenueRoutingRefDisclosure,
} from "../revenue-routing-engine";
import type {
  IssueRevenueRoutingCertificateInput,
  IssuedRevenueRoutingCertificate,
  RevenueRoutingCertificate,
  RoutingJurisdictions,
  RoutingRecipientRefs,
  RoutingSplitBps,
} from "../revenue-routing-engine";
/** Stark field prime and curve order; `n < p`, so `p·n` is congruent to 0 mod both. */
const FIELD_PRIME = 2n ** 251n + 17n * 2n ** 192n + 1n;
const CURVE_ORDER = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2fn;
const CRT_SHIFT = FIELD_PRIME * CURVE_ORDER;

/** An 8-bit amount band keeps the 334 proof legs well inside the per-test timeout. */
const BITS = 8;
const SPLIT: RoutingSplitBps = [3000, 2500, 1500, 1000, 1000, 1000];
const JURISDICTIONS: RoutingJurisdictions = ["DE", "SG", "US", "BR", "GB", "NL"];
const RECIPIENTS: RoutingRecipientRefs = [
  "stakeholder-a@treasury",
  "stakeholder-b@treasury",
  "stakeholder-c@treasury",
  "stakeholder-d@treasury",
  "affiliate-pool@partners",
  "tax-reserve@custodian",
];
const ISSUED_AT = new Date("2026-08-31T12:00:00.000Z");

const ASSET = { symbol: "USDC", tokenAddress: "0x53c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8", decimals: 6 };

function baseInput(overrides: Partial<IssueRevenueRoutingCertificateInput> = {}): IssueRevenueRoutingCertificateInput {
  return {
    merchantAlias: "atlas-commerce",
    asset: ASSET,
    agreementRef: "rev-share-agreement-2026-08",
    programLabel: "Cross-border partner programme",
    splitBps: SPLIT,
    jurisdictions: JURISDICTIONS,
    policy: {
      minGrossBaseUnits: "100",
      maxAffiliatePayoutBaseUnits: "40",
      minTaxReserveBaseUnits: "10",
      maxDustBaseUnits: "5",
    },
    grossBaseUnits: "199",
    recipientRefs: RECIPIENTS,
    payerRef: "payer-consolidated-ledger",
    issuerSecretKey: "0x2f1a4c",
    amountBitLength: BITS,
    memo: "Nothing here moves value.",
    ...overrides,
  };
}

function issueFixture(
  overrides: Partial<IssueRevenueRoutingCertificateInput> = {},
): IssuedRevenueRoutingCertificate {
  return issueRevenueRoutingCertificate(baseInput(overrides), ISSUED_AT);
}
/** One shared certificate: issuing is the expensive step, so tests clone instead. */
let cached: IssuedRevenueRoutingCertificate | undefined;

function shared(): IssuedRevenueRoutingCertificate {
  if (!cached) cached = issueFixture();
  return cached;
}

function clone(certificate: RevenueRoutingCertificate): RevenueRoutingCertificate {
  return JSON.parse(JSON.stringify(certificate)) as RevenueRoutingCertificate;
}

describe("entitlement schedule", () => {
  it("accepts a schedule that totals exactly 10000 bps", () => {
    expect(normalizeRoutingSplit(SPLIT)).toEqual([3000n, 2500n, 1500n, 1000n, 1000n, 1000n]);
  });

  it("accepts decimal-string shares and a zero share", () => {
    expect(normalizeRoutingSplit(["10000", "0", "0", "0", "0", "0"])).toEqual([10000n, 0n, 0n, 0n, 0n, 0n]);
  });

  it("rejects a schedule that does not total 10000 bps", () => {
    expect(() => normalizeRoutingSplit([3000, 2500, 1500, 1000, 1000, 999])).toThrow(/totals 9999/);
  });

  it("rejects the wrong number of shares", () => {
    expect(() => normalizeRoutingSplit([5000, 5000])).toThrow(/Exactly 6 entitlement shares/);
  });

  it("rejects a share above 10000 bps", () => {
    expect(() => normalizeRoutingSplit([10001, 0, 0, 0, 0, -1])).toThrow(/must be between 0 and 10000/);
  });

  it("exposes six slots with the affiliate and tax indices pinned", () => {
    expect(ROUTING_SLOT_COUNT).toBe(6);
    expect(REVENUE_ROUTING_SLOTS[AFFILIATE_SLOT_INDEX].kind).toBe("affiliate");
    expect(REVENUE_ROUTING_SLOTS[TAX_RESERVE_SLOT_INDEX].kind).toBe("tax");
    expect(REVENUE_ROUTING_SLOTS.filter((slot) => slot.kind === "stakeholder")).toHaveLength(4);
  });
});
describe("split ratio calculations", () => {
  it("splits an exactly divisible gross with no remainder", () => {
    const plan = computeRevenueRoutingPlan("200", SPLIT);
    expect(plan.slots.map((slot) => slot.payoutBaseUnits)).toEqual(["60", "50", "30", "20", "20", "20"]);
    expect(plan.allocatedBaseUnits).toBe("200");
    expect(plan.dustBaseUnits).toBe("0");
    expect(plan.isExactSplit).toBe(true);
  });

  it("floors every share and reports the discarded numerator", () => {
    const plan = computeRevenueRoutingPlan("199", SPLIT);
    expect(plan.slots.map((slot) => slot.payoutBaseUnits)).toEqual(["59", "49", "29", "19", "19", "19"]);
    expect(plan.slots.map((slot) => slot.roundingRemainder)).toEqual(["7000", "7500", "8500", "9000", "9000", "9000"]);
    expect(plan.dustBaseUnits).toBe("5");
    expect(plan.isExactSplit).toBe(false);
  });

  it("reports the share actually realized after flooring", () => {
    const plan = computeRevenueRoutingPlan("199", SPLIT);
    expect(plan.slots[0].realizedShareBps).toBe("2964");
    expect(plan.slots[0].entitlementBps).toBe("3000");
  });

  it("conserves the gross exactly for every gross and schedule it is given", () => {
    const schedules: RoutingSplitBps[] = [
      SPLIT,
      [10000, 0, 0, 0, 0, 0],
      [1667, 1667, 1666, 1667, 1667, 1666],
      [9995, 1, 1, 1, 1, 1],
      [0, 0, 0, 0, 5000, 5000],
    ];
    for (const schedule of schedules) {
      for (let gross = 0n; gross <= 400n; gross += 7n) {
        const plan = computeRevenueRoutingPlan(gross, schedule);
        const payouts = plan.slots.reduce((acc, slot) => acc + BigInt(slot.payoutBaseUnits), 0n);
        expect(payouts + BigInt(plan.dustBaseUnits)).toBe(gross);
        expect(BigInt(plan.dustBaseUnits) >= 0n).toBe(true);
        expect(BigInt(plan.dustBaseUnits) <= MAX_POSSIBLE_ROUTING_DUST).toBe(true);
      }
    }
  });
  it("handles a zero gross without dividing by zero", () => {
    const plan = computeRevenueRoutingPlan("0", SPLIT);
    expect(plan.slots.every((slot) => slot.payoutBaseUnits === "0" && slot.realizedShareBps === "0")).toBe(true);
    expect(plan.dustBaseUnits).toBe("0");
    expect(plan.isExactSplit).toBe(true);
  });

  it("leaves a single base unit entirely as remainder", () => {
    const plan = computeRevenueRoutingPlan("1", SPLIT);
    expect(plan.allocatedBaseUnits).toBe("0");
    expect(plan.dustBaseUnits).toBe("1");
  });

  it("rejects a negative gross", () => {
    expect(() => computeRevenueRoutingPlan("-1", SPLIT)).toThrow(/gross settlement/);
  });

  it("draws the waterfall down to exactly zero", () => {
    const plan = computeRevenueRoutingPlan("199", SPLIT);
    const steps = buildRoutingWaterfall(plan);
    expect(steps).toHaveLength(ROUTING_SLOT_COUNT + 1);
    expect(steps[0].openingBalanceBaseUnits).toBe("199");
    expect(steps[steps.length - 1].closingBalanceBaseUnits).toBe("0");
    expect(steps[steps.length - 1].cumulativeBaseUnits).toBe("199");
    expect(steps[steps.length - 1].kind).toBe("remainder");
    for (let index = 1; index < steps.length; index += 1) {
      expect(steps[index].openingBalanceBaseUnits).toBe(steps[index - 1].closingBalanceBaseUnits);
    }
  });
});

describe("corridor ledger", () => {
  const rows = [
    { reference: "wire-de-1", jurisdiction: "DE", receivedAt: "2026-08-01T00:00:00.000Z", amountBaseUnits: "90" },
    { reference: "wire-sg-1", jurisdiction: "SG", receivedAt: "2026-08-21T00:00:00.000Z", amountBaseUnits: "70" },
    { reference: "wire-de-2", jurisdiction: "DE", receivedAt: "2026-08-26T00:00:00.000Z", amountBaseUnits: "39" },
  ];

  it("aggregates per jurisdiction, ordered by amount descending", () => {
    const ledger = aggregateCorridorLedger(rows, ISSUED_AT);
    expect(ledger.grossBaseUnits).toBe("199");
    expect(ledger.rowCount).toBe(3);
    expect(ledger.corridorCount).toBe(2);
    expect(ledger.corridors.map((corridor) => corridor.jurisdiction)).toEqual(["DE", "SG"]);
    expect(ledger.corridors[0].amountBaseUnits).toBe("129");
    expect(ledger.corridors[0].rowCount).toBe(2);
    expect(ledger.largestCorridorShareBps).toBe("6482");
  });
  it("ages every row from the as-of date", () => {
    const ledger = aggregateCorridorLedger(rows, ISSUED_AT);
    expect(ledger.corridors[0].oldestAgeDays).toBe("30");
    expect(ledger.corridors[1].oldestAgeDays).toBe("10");
    expect(ledger.weightedAgeDays).toBe("3595");
    expect(ledger.averageAgeDays).toBe("18");
    expect(ledger.asOf).toBe(ISSUED_AT.toISOString());
  });

  it("clamps a future settlement to zero days rather than going negative", () => {
    const ledger = aggregateCorridorLedger(
      [{ reference: "future", jurisdiction: "JP", receivedAt: "2027-01-01T00:00:00.000Z", amountBaseUnits: "5" }],
      ISSUED_AT,
    );
    expect(ledger.corridors[0].oldestAgeDays).toBe("0");
    expect(ledger.weightedAgeDays).toBe("0");
  });

  it("returns an empty ledger for no rows", () => {
    const ledger = aggregateCorridorLedger([], ISSUED_AT);
    expect(ledger.grossBaseUnits).toBe("0");
    expect(ledger.corridors).toEqual([]);
    expect(ledger.largestCorridorShareBps).toBe("0");
    expect(ledger.averageAgeDays).toBe("0");
  });

  it("commits a settlement row deterministically under a fixed salt", () => {
    const first = commitSettlementRow("wire-de-1", "DE", "2026-08-01T00:00:00.000Z", "90", 7n);
    const second = commitSettlementRow("wire-de-1", "DE", "2026-08-01T00:00:00.000Z", "90", 7n);
    const other = commitSettlementRow("wire-de-1", "DE", "2026-08-01T00:00:00.000Z", "91", 7n);
    expect(first).toBe(second);
    expect(first).not.toBe(other);
    expect(first.startsWith("0x")).toBe(true);
  });

  it("hides the row behind a random salt when none is supplied", () => {
    const first = commitSettlementRow("wire-de-1", "DE", "2026-08-01T00:00:00.000Z", "90");
    const second = commitSettlementRow("wire-de-1", "DE", "2026-08-01T00:00:00.000Z", "90");
    expect(first).not.toBe(second);
  });
});
describe("covenant assessment", () => {
  const plan = computeRevenueRoutingPlan("199", SPLIT);
  const policy = {
    minGrossBaseUnits: "100",
    maxAffiliatePayoutBaseUnits: "40",
    minTaxReserveBaseUnits: "10",
    maxDustBaseUnits: "5",
  };

  it("reports the four surpluses the proof legs carry", () => {
    const assessment = assessRoutingPolicy(plan, policy);
    expect(assessment.grossFloorSurplus).toBe("99");
    expect(assessment.affiliateCapSurplus).toBe("21");
    expect(assessment.taxFloorSurplus).toBe("9");
    expect(assessment.dustCeilingSurplus).toBe("0");
    expect(assessment.eligible).toBe(true);
    expect(assessment.blockers).toEqual([]);
  });

  it("blocks a gross below the settlement floor", () => {
    const assessment = assessRoutingPolicy(plan, { ...policy, minGrossBaseUnits: "200" });
    expect(assessment.eligible).toBe(false);
    expect(assessment.blockers).toEqual(["The gross settlement is below the published minimum settlement floor."]);
  });

  it("blocks an affiliate payout above the cap", () => {
    const assessment = assessRoutingPolicy(plan, { ...policy, maxAffiliatePayoutBaseUnits: "18" });
    expect(assessment.blockers).toEqual(["The affiliate payout exceeds the published affiliate cap."]);
  });

  it("blocks a tax reserve below its floor", () => {
    const assessment = assessRoutingPolicy(plan, { ...policy, minTaxReserveBaseUnits: "20" });
    expect(assessment.blockers).toEqual(["The tax reserve is below the published minimum tax reserve."]);
  });

  it("blocks a remainder above the rounding tolerance", () => {
    const assessment = assessRoutingPolicy(plan, { ...policy, maxDustBaseUnits: "4" });
    expect(assessment.blockers).toEqual(["The rounding remainder exceeds the published rounding tolerance."]);
  });

  it("lists every failing covenant at once", () => {
    const assessment = assessRoutingPolicy(plan, {
      minGrossBaseUnits: "200",
      maxAffiliatePayoutBaseUnits: "18",
      minTaxReserveBaseUnits: "20",
      maxDustBaseUnits: "4",
    });
    expect(assessment.blockers).toHaveLength(4);
  });

  it("rejects a rounding tolerance outside the rounding range", () => {
    expect(() =>
      requireRevenueRoutingPolicy({ ...policy, maxDustBaseUnits: (MAX_ROUTING_DUST_BASE_UNITS + 1n).toString() }),
    ).toThrow(/rounding tolerance must be at most/);
  });
});
describe("concentration heuristic", () => {
  it("calls a broadly spread schedule balanced", () => {
    const assessment = assessRoutingConcentration(computeRevenueRoutingPlan("199", SPLIT));
    expect(assessment.band).toBe("balanced");
    expect(assessment.largestShareBps).toBe("2964");
    expect(assessment.herfindahlIndex).toBe("1969");
    expect(assessment.stakeholderShareBps).toBe("7837");
    expect(assessment.affiliateShareBps).toBe("954");
    expect(assessment.reserveShareBps).toBe("954");
    expect(assessment.rationale).toContain("spreads entitlement broadly");
  });

  it("calls an uneven schedule tilted", () => {
    const plan = computeRevenueRoutingPlan("10000", [4000, 2000, 2000, 1000, 500, 500]);
    expect(assessRoutingConcentration(plan).band).toBe("tilted");
  });

  it("calls a dominant-slot schedule concentrated", () => {
    const plan = computeRevenueRoutingPlan("10000", [7000, 1000, 1000, 500, 300, 200]);
    const assessment = assessRoutingConcentration(plan);
    expect(assessment.band).toBe("concentrated");
    expect(assessment.score).toBeGreaterThanOrEqual(45);
  });

  it("calls a winner-takes-all schedule single-party", () => {
    const plan = computeRevenueRoutingPlan("200", [10000, 0, 0, 0, 0, 0]);
    const assessment = assessRoutingConcentration(plan);
    expect(assessment.band).toBe("single-party");
    expect(assessment.largestShareBps).toBe("10000");
    expect(assessment.rationale).toContain("nearly the gross");
  });

  it("never claims to execute anything", () => {
    const release = evaluateRoutingRelease(computeRevenueRoutingPlan("199", SPLIT), 24);
    expect(release.executesAnything).toBe(false);
    expect(release.withinThreshold).toBe(true);
    expect(release.band).toBe("balanced");
    expect(evaluateRoutingRelease(computeRevenueRoutingPlan("199", SPLIT), 10).withinThreshold).toBe(false);
  });
});
describe("formatters and proof sizing", () => {
  it("formats base units at the asset's decimals", () => {
    expect(formatRoutingBaseUnits("199", 6)).toBe("0.000199");
    expect(formatRoutingBaseUnits("1000000", 6)).toBe("1");
    expect(formatRoutingBaseUnits("0", 6)).toBe("0");
  });

  it("formats basis points as percentages", () => {
    expect(formatRoutingBps(10000)).toBe("100%");
    expect(formatRoutingBps(3000)).toBe("30%");
    expect(formatRoutingBps(2462)).toBe("24.62%");
    expect(formatRoutingBps(5)).toBe("0.05%");
    expect(formatRoutingBps(0)).toBe("0%");
  });

  it("formats settlement ages with a human scale", () => {
    expect(formatSettlementAgeDays(12)).toBe("12d");
    expect(formatSettlementAgeDays("30")).toBe("30d · 1.0mo");
    expect(formatSettlementAgeDays(45)).toBe("45d · 1.5mo");
    expect(formatSettlementAgeDays(400)).toBe("400d · 1.1y");
    expect(formatSettlementAgeDays("not a number")).toBe("0d");
  });

  it("sizes the proof bundle exactly", () => {
    expect(estimateRevenueRoutingProofCount(BITS)).toBe(
      7 * BITS + 2 * ROUTING_DUST_BIT_LENGTH + 12 * 14 + 3 * (BITS + ROUTING_SURPLUS_EXTRA_BITS),
    );
    expect(estimateRevenueRoutingProofCount(BITS)).toBe(334);
    expect(estimateRevenueRoutingProofCount(64)).toBe(894);
  });

  it("derives a generator independent of G, stable across calls", () => {
    const first = deriveRevenueRoutingGenerator();
    expect(deriveRevenueRoutingGenerator()).toEqual(first);
    expect(BigInt(first.x)).toBeGreaterThan(0n);
    expect(BigInt(first.y)).toBeGreaterThan(0n);
  });

  it("mints an issuer keypair whose public key round-trips through an envelope", () => {
    const keypair = createRevenueRoutingIssuerKey();
    expect(keypair.role).toBe("issuer");
    expect(parseRevenueRoutingKeypair(serializeRevenueRoutingKeypair(keypair))).toEqual(keypair);
  });
});
describe("certificate issuance", () => {
  it("issues a certificate that verifies and passes every audit row", () => {
    const { certificate } = shared();
    expect(verifyRevenueRoutingCertificate(certificate)).toBe(true);
    const checks = auditRevenueRoutingCertificate(certificate);
    expect(checks).toHaveLength(REVENUE_ROUTING_CHECK_COUNT);
    expect(checks.every((check) => check.passed)).toBe(true);
    expect(checks.map((check) => check.label)).toContain("Split conservation");
    expect(checks.map((check) => check.label)).toContain("Covenant scalar bounds");
  });

  it("publishes the schedule, jurisdictions, and covenants but no hidden figure", () => {
    const { certificate } = shared();
    expect(certificate.version).toBe(REVENUE_ROUTING_ENGINE_VERSION);
    expect(certificate.poolAddress).toBe(REVENUE_ROUTING_POOL_ADDRESS);
    expect(certificate.proof.proofSystem).toBe(REVENUE_ROUTING_PROOF_SYSTEM);
    expect(certificate.splitBps).toEqual(["3000", "2500", "1500", "1000", "1000", "1000"]);
    expect(certificate.jurisdictions).toEqual([...JURISDICTIONS]);
    expect(certificate.minGrossBaseUnits).toBe("100");
    const serialized = JSON.stringify(certificate);
    expect(certificate).not.toHaveProperty("grossBaseUnits");
    expect(certificate).not.toHaveProperty("slotPayoutsBaseUnits");
    expect(serialized).not.toContain(RECIPIENTS[0]);
    expect(serialized).not.toContain("payer-consolidated-ledger");
    expect(serialized).not.toContain("rev-share-agreement-2026-08");
  });

  it("carries one proof leg per bit of every committed quantity", () => {
    const { certificate } = shared();
    const proof = certificate.proof;
    expect(proof.amountBitLength).toBe(BITS);
    expect(proof.surplusBitLength).toBe(BITS + ROUTING_SURPLUS_EXTRA_BITS);
    expect(proof.grossBits).toHaveLength(BITS);
    expect(proof.slotBits).toHaveLength(ROUTING_SLOT_COUNT);
    expect(proof.slotBits.every((bits) => bits.length === BITS)).toBe(true);
    expect(proof.dustBits).toHaveLength(proof.dustBitLength);
    expect(proof.floorLowerBits.every((bits) => bits.length === proof.floorBitLength)).toBe(true);
    expect(proof.floorUpperBits.every((bits) => bits.length === proof.floorBitLength)).toBe(true);
    expect(proof.grossFloorSurplusBits).toHaveLength(proof.surplusBitLength);
    expect(proof.dustCeilingSurplusBits).toHaveLength(proof.dustBitLength);
    expect(proof.slotCommitments).toHaveLength(ROUTING_SLOT_COUNT);
  });
  it("rejects a gross that does not fit the requested band", () => {
    expect(() => issueFixture({ grossBaseUnits: "256" })).toThrow(/does not fit 8 bits/);
  });

  it("rejects a covenant scalar outside the amount band", () => {
    expect(() =>
      issueFixture({
        policy: {
          minGrossBaseUnits: "256",
          maxAffiliatePayoutBaseUnits: "40",
          minTaxReserveBaseUnits: "10",
          maxDustBaseUnits: "5",
        },
      }),
    ).toThrow(/minimum gross settlement does not fit the requested amount range/);
  });

  it("refuses to issue when a covenant is already breached", () => {
    expect(() =>
      issueFixture({
        policy: {
          minGrossBaseUnits: "200",
          maxAffiliatePayoutBaseUnits: "40",
          minTaxReserveBaseUnits: "10",
          maxDustBaseUnits: "5",
        },
      }),
    ).toThrow("The gross settlement is below the published minimum settlement floor.");
  });

  it("omits the payer commitment when no payer reference is supplied", () => {
    const { certificate, secret } = issueFixture({ payerRef: undefined, amountBitLength: BITS });
    expect(certificate.payerCommitted).toBe(false);
    expect(secret.payerCommitted).toBe(false);
    expect(verifyRevenueRoutingCertificate(certificate)).toBe(true);
  });

  it("keeps the merchant-held secret consistent with the published plan", () => {
    const { secret } = shared();
    expect(secret.grossBaseUnits).toBe("199");
    expect(secret.slotPayoutsBaseUnits).toEqual(["59", "49", "29", "19", "19", "19"]);
    expect(secret.dustBaseUnits).toBe("5");
    const total = secret.slotPayoutsBaseUnits.reduce((acc, value) => acc + BigInt(value), 0n);
    expect(total + BigInt(secret.dustBaseUnits)).toBe(BigInt(secret.grossBaseUnits));
  });
});
describe("tamper resistance", () => {
  it("rejects a rewritten entitlement schedule", () => {
    const tampered = clone(shared().certificate);
    tampered.splitBps = ["2000", "3500", "1500", "1000", "1000", "1000"];
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a rewritten jurisdiction tag", () => {
    const tampered = clone(shared().certificate);
    tampered.jurisdictions = ["KY", "SG", "US", "BR", "GB", "NL"];
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a rewritten limitation notice", () => {
    const tampered = clone(shared().certificate);
    tampered.notice = "This protocol automatically routes funds to every stakeholder.";
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Limitation notice");
  });

  it("rejects a rewritten pool address", () => {
    const tampered = clone(shared().certificate);
    tampered.poolAddress = "0x1" as typeof tampered.poolAddress;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Pool provenance");
  });

  it("rejects a foreign network", () => {
    const tampered = clone(shared().certificate);
    tampered.network = "SN_SEPOLIA" as typeof tampered.network;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a bumped engine version", () => {
    const tampered = clone(shared().certificate);
    tampered.version = 2 as typeof tampered.version;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a loosened covenant", () => {
    const tampered = clone(shared().certificate);
    tampered.maxDustBaseUnits = "6";
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });
  it("rejects a mutated gross commitment", () => {
    const tampered = clone(shared().certificate);
    tampered.proof.grossCommitment = tampered.proof.slotCommitments[0];
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects two swapped slot commitments", () => {
    const tampered = clone(shared().certificate);
    const [first, second] = [tampered.proof.slotCommitments[0], tampered.proof.slotCommitments[1]];
    tampered.proof.slotCommitments[0] = second;
    tampered.proof.slotCommitments[1] = first;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const tampered = clone(shared().certificate);
    tampered.issuerSignature = { challenge: "0x1", response: "0x2" };
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Issuer signature");
  });

  it("rejects a substituted issuer public key", () => {
    const tampered = clone(shared().certificate);
    tampered.issuerPublicKey = createRevenueRoutingIssuerKey().publicKey;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a rewritten binding hash", () => {
    const tampered = clone(shared().certificate);
    tampered.bindingHash = "0x2a";
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Binding hash");
  });

  it("rejects a widened amount band", () => {
    const tampered = clone(shared().certificate);
    tampered.proof.amountBitLength = BITS + 1;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });

  it("rejects a substituted independent generator", () => {
    const tampered = clone(shared().certificate);
    tampered.proof.generatorH = tampered.proof.grossCommitment;
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Independent generator");
  });

  it("rejects a dropped proof leg", () => {
    const tampered = clone(shared().certificate);
    tampered.proof.grossBits = tampered.proof.grossBits.slice(1);
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
  });
});
describe("selective disclosure", () => {
  it("opens the gross and nothing else", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "gross");
    expect(disclosure.amountBaseUnits).toBe("199");
    expect(verifyRevenueRoutingAmountDisclosure(certificate, disclosure)).toBe(true);
  });

  it("opens one slot payout and the rounding remainder", () => {
    const { certificate, secret } = shared();
    const affiliate = buildRevenueRoutingAmountDisclosure(secret, "slot4");
    expect(affiliate.amountBaseUnits).toBe("19");
    expect(verifyRevenueRoutingAmountDisclosure(certificate, affiliate)).toBe(true);
    const dust = buildRevenueRoutingAmountDisclosure(secret, "dust");
    expect(dust.amountBaseUnits).toBe("5");
    expect(verifyRevenueRoutingAmountDisclosure(certificate, dust)).toBe(true);
  });

  it("rejects an opening whose amount was rewritten", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "gross");
    expect(
      verifyRevenueRoutingAmountDisclosure(certificate, { ...disclosure, amountBaseUnits: "200" }),
    ).toBe(false);
  });

  it("rejects an opening replayed against another field", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "slot0");
    expect(verifyRevenueRoutingAmountDisclosure(certificate, { ...disclosure, field: "slot1" })).toBe(false);
  });

  it("rejects an opening bound to another certificate", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "gross");
    expect(
      verifyRevenueRoutingAmountDisclosure(certificate, { ...disclosure, certificateId: "rrt_certificate_other" }),
    ).toBe(false);
  });

  it("opens the agreement, payer, and recipient references", () => {
    const { certificate, secret } = shared();
    const agreement = buildRevenueRoutingAgreementDisclosure(secret);
    expect(agreement.value).toBe("rev-share-agreement-2026-08");
    expect(verifyRevenueRoutingRefDisclosure(certificate, agreement)).toBe(true);
    const payer = buildRevenueRoutingPayerDisclosure(secret);
    expect(verifyRevenueRoutingRefDisclosure(certificate, payer)).toBe(true);
    const recipient = buildRevenueRoutingRecipientDisclosure(secret, TAX_RESERVE_SLOT_INDEX);
    expect(recipient.value).toBe(RECIPIENTS[TAX_RESERVE_SLOT_INDEX]);
    expect(verifyRevenueRoutingRefDisclosure(certificate, recipient)).toBe(true);
  });
  it("refuses to replay one slot's recipient opening as another slot's", () => {
    const { certificate, secret } = shared();
    const recipient = buildRevenueRoutingRecipientDisclosure(secret, 0);
    expect(verifyRevenueRoutingRefDisclosure(certificate, { ...recipient, field: "recipient1" })).toBe(false);
  });

  it("rejects a reference opening whose value was rewritten", () => {
    const { certificate, secret } = shared();
    const recipient = buildRevenueRoutingRecipientDisclosure(secret, 0);
    expect(verifyRevenueRoutingRefDisclosure(certificate, { ...recipient, value: "attacker@elsewhere" })).toBe(false);
  });

  it("refuses to open a payer reference that was never committed", () => {
    const { secret } = issueFixture({ payerRef: undefined });
    expect(() => buildRevenueRoutingPayerDisclosure(secret)).toThrow(/committed no payer reference/);
  });

  it("refuses to open an agreement reference that was never committed", () => {
    const { secret } = issueFixture({ agreementRef: undefined });
    expect(() => buildRevenueRoutingAgreementDisclosure(secret)).toThrow(/committed no agreement reference/);
  });

  it("rejects a slot index outside the schedule", () => {
    const { secret } = shared();
    expect(() => buildRevenueRoutingRecipientDisclosure(secret, ROUTING_SLOT_COUNT)).toThrow(
      /routing slot index must be between 0 and 5/,
    );
  });

  it("will not let a disclosure lend credibility to a broken certificate", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "gross");
    const tampered = clone(certificate);
    tampered.memo = "Rewritten after issuance.";
    expect(verifyRevenueRoutingAmountDisclosure(tampered, disclosure)).toBe(false);
  });
});

describe("envelopes", () => {
  it("round-trips the certificate, secret, badge, and both disclosure kinds", () => {
    const { certificate, secret } = shared();
    expect(parseRevenueRoutingCertificate(serializeRevenueRoutingCertificate(certificate))).toEqual(certificate);
    expect(parseRevenueRoutingCertificateSecret(serializeRevenueRoutingCertificateSecret(secret))).toEqual(secret);
    const amount = buildRevenueRoutingAmountDisclosure(secret, "slot2");
    expect(parseRevenueRoutingAmountDisclosure(serializeRevenueRoutingAmountDisclosure(amount))).toEqual(amount);
    const ref = buildRevenueRoutingRecipientDisclosure(secret, 3);
    expect(parseRevenueRoutingRefDisclosure(serializeRevenueRoutingRefDisclosure(ref))).toEqual(ref);
    const badge = buildRevenueRoutingCertificateBadge(certificate);
    expect(parseRevenueRoutingCertificateBadge(serializeRevenueRoutingCertificateBadge(badge))).toEqual(badge);
  });
  it("survives a serialized certificate round trip and still verifies", () => {
    const { certificate } = shared();
    const restored = parseRevenueRoutingCertificate(serializeRevenueRoutingCertificate(certificate));
    expect(verifyRevenueRoutingCertificate(restored)).toBe(true);
  });

  it("emits url-safe text with no padding", () => {
    const encoded = serializeRevenueRoutingCertificate(shared().certificate);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("refuses an envelope of the wrong kind", () => {
    const { certificate, secret } = shared();
    expect(() => parseRevenueRoutingCertificateSecret(serializeRevenueRoutingCertificate(certificate))).toThrow();
    expect(() => parseRevenueRoutingCertificate(serializeRevenueRoutingCertificateSecret(secret))).toThrow();
  });

  it("refuses empty and non-base64url text", () => {
    expect(() => parseRevenueRoutingCertificate("")).toThrow(/envelope is missing/);
    expect(() => parseRevenueRoutingCertificate("not valid!!")).toThrow(/not valid base64url/);
  });
});

describe("badge, trust model, and visibility model", () => {
  it("summarizes a verifying certificate honestly", () => {
    const badge = buildRevenueRoutingCertificateBadge(shared().certificate);
    expect(badge.proofCount).toBe(estimateRevenueRoutingProofCount(BITS));
    expect(badge.scheduleSummary).toHaveLength(ROUTING_SLOT_COUNT);
    expect(badge.scheduleSummary[0]).toBe("Stakeholder A · 30% · DE");
    expect(badge.covenantSummary).toHaveLength(4);
    expect(badge.jurisdictionSummary).toContain("6 corridors");
    expect(badge.claim).toContain("routes nothing");
    expect(badge.payerCommitted).toBe(true);
  });

  it("refuses to summarize a certificate that does not verify", () => {
    const tampered = clone(shared().certificate);
    tampered.merchantAlias = "someone-else";
    expect(() => buildRevenueRoutingCertificateBadge(tampered)).toThrow(
      "Only a verifying revenue routing certificate can be summarized.",
    );
  });

  it("claims nothing it does not do", () => {
    const model = getRevenueRoutingTrustModel();
    expect(model.isZeroKnowledge).toBe(true);
    expect(model.provesGrossConservation).toBe(true);
    expect(model.provesExactFloorSplits).toBe(true);
    expect(model.authenticatesIssuer).toBe(true);
    expect(model.supportsSelectiveDisclosure).toBe(true);
    expect(model.publishesEntitlementSchedule).toBe(true);
    expect(model.publishesJurisdictions).toBe(true);
  });
  it("disclaims every capability it does not have", () => {
    const model = getRevenueRoutingTrustModel();
    expect(model.isDecentralized).toBe(false);
    expect(model.isAutomatic).toBe(false);
    expect(model.routesOrMovesFunds).toBe(false);
    expect(model.paysAnyStakeholder).toBe(false);
    expect(model.withholdsAnyTax).toBe(false);
    expect(model.observesIncomingPayments).toBe(false);
    expect(model.readsShieldedBalances).toBe(false);
    expect(model.settlesOnChain).toBe(false);
    expect(model.movesPoolFunds).toBe(false);
    expect(model.callsPoolContract).toBe(false);
    expect(model.verifiesFiguresAreReal).toBe(false);
    expect(model.verifiesRecipientsExist).toBe(false);
    expect(model.isTaxAdvice).toBe(false);
    expect(model.isFinancialAdvice).toBe(false);
    expect(model.limitations).toEqual(REVENUE_ROUTING_LIMITATIONS);
  });

  it("keeps the schedule on the visible side of the ledger", () => {
    const visibility = getRevenueRoutingVisibilityModel();
    expect(visibility.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(visibility.disclosedToVerifier.join(" ")).toContain("schedule");
    expect(visibility.limitation.length).toBeGreaterThan(0);
  });

  it("states the schedule-derivation limitation in plain language", () => {
    expect(REVENUE_ROUTING_LIMITATIONS.join(" ")).toContain("derive the gross and every other payout");
    expect(REVENUE_ROUTING_LIMITATIONS.join(" ")).toContain("routes nothing");
  });
});
/**
 * Permanent regression guard. `n < p`, so adding `p·n` to a public scalar leaves it
 * congruent mod p (Poseidon, and therefore the binding hash and issuer signature)
 * AND mod n (`scalePoint`, and therefore every homomorphic target). Only an
 * explicit canonical bound on each scalar rejects the shift.
 */
describe("forgery regressions", () => {
  const shift = (value: string): string => (BigInt(value) + CRT_SHIFT).toString();

  it("keeps the shift congruent under both moduli, so the bound is the only defence", () => {
    expect(CRT_SHIFT % FIELD_PRIME).toBe(0n);
    expect(CRT_SHIFT % CURVE_ORDER).toBe(0n);
    expect(CURVE_ORDER).toBeLessThan(FIELD_PRIME);
  });

  it("rejects a settlement floor shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const tampered = clone(shared().certificate);
    tampered.minGrossBaseUnits = shift(tampered.minGrossBaseUnits);
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Covenant scalar bounds");
  });

  it("rejects an affiliate cap shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const tampered = clone(shared().certificate);
    tampered.maxAffiliatePayoutBaseUnits = shift(tampered.maxAffiliatePayoutBaseUnits);
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Covenant scalar bounds");
  });

  it("rejects a tax reserve floor shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const tampered = clone(shared().certificate);
    tampered.minTaxReserveBaseUnits = shift(tampered.minTaxReserveBaseUnits);
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Covenant scalar bounds");
  });

  it("rejects a rounding tolerance shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const tampered = clone(shared().certificate);
    tampered.maxDustBaseUnits = shift(tampered.maxDustBaseUnits);
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Covenant scalar bounds");
  });
  it("rejects an entitlement share shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const tampered = clone(shared().certificate);
    tampered.splitBps = [shift(tampered.splitBps[0]), ...tampered.splitBps.slice(1)];
    expect(verifyRevenueRoutingCertificate(tampered)).toBe(false);
    const failed = auditRevenueRoutingCertificate(tampered).find((check) => !check.passed);
    expect(failed?.label).toBe("Entitlement schedule");
  });

  it("rejects a disclosed amount shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "gross");
    expect(verifyRevenueRoutingAmountDisclosure(certificate, disclosure)).toBe(true);
    expect(
      verifyRevenueRoutingAmountDisclosure(certificate, {
        ...disclosure,
        amountBaseUnits: shift(disclosure.amountBaseUnits),
      }),
    ).toBe(false);
  });

  it("rejects a disclosed remainder shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingAmountDisclosure(secret, "dust");
    expect(
      verifyRevenueRoutingAmountDisclosure(certificate, {
        ...disclosure,
        amountBaseUnits: shift(disclosure.amountBaseUnits),
      }),
    ).toBe(false);
  });

  it("rejects a disclosure salt shifted past the curve order", () => {
    const { certificate, secret } = shared();
    const disclosure = buildRevenueRoutingRecipientDisclosure(secret, 0);
    expect(verifyRevenueRoutingRefDisclosure(certificate, disclosure)).toBe(true);
    expect(
      verifyRevenueRoutingRefDisclosure(certificate, {
        ...disclosure,
        salt: (BigInt(disclosure.salt) + CURVE_ORDER).toString(),
      }),
    ).toBe(false);
  });

  it("bounds the schedule total exactly, so no share can absorb the shift", () => {
    expect(() => normalizeRoutingSplit([shift("3000"), "2500", "1500", "1000", "1000", "1000"])).toThrow();
    expect(BPS_SCALE).toBe(10000n);
  });
});

