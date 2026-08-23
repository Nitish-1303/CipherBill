import { describe, expect, it } from "vitest";

import {
  buildContingencyActions,
  buildDeadmanAttestation,
  buildDeadmanPlanDigest,
  buildReminderSchedule,
  canTriggerContingency,
  createDeadmanPlan,
  DEADMAN_POOL_ADDRESS,
  evaluateLiveness,
  formatDeadmanBaseUnits,
  getDeadmanVisibilityModel,
  openDeadmanPlan,
  parseDeadmanAttestation,
  parseDeadmanPlan,
  parseDeadmanPlanDigest,
  serializeDeadmanAttestation,
  serializeDeadmanPlan,
  serializeDeadmanPlanDigest,
  summarizeDeadmanTrust,
  verifyDeadmanAttestation,
  verifyDeadmanPlan,
  verifyDeadmanPlanDisclosure,
  type CreateDeadmanPlanInput,
  type DeadmanEntropy,
} from "./deadman-engine";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const NOW = new Date("2026-08-23T08:00:00.000Z");
const USDC = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const BENE_A = "0x0712345678901234567890123456789012345678901234567890123456789012";
const BENE_B = "0x0698765432109876543210987654321098765432109876543210987654321098";
const BENE_C = "0x0333333333333333333333333333333333333333333333333333333333333333";

const HOUR = 3_600_000;

/** Deterministic ids and salts, so every commitment in this file is reproducible. */
function entropy(seed: number): DeadmanEntropy {
  return {
    createId: () => `dms_test_${seed}`,
    randomBytes: (target) => {
      for (let index = 0; index < target.length; index += 1) target[index] = ((index + seed) % 251) + 1;
      return target;
    },
  };
}

const PLAN_INPUT: CreateDeadmanPlanInput = {
  invoiceId: "inv_deadman_001",
  asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
  switchValue: "1000",
  beneficiaries: [
    { recipient: BENE_A, shareBps: 6000, label: "Estate" },
    { recipient: BENE_B, shareBps: 4000, label: "Partner" },
  ],
  checkInIntervalHours: 24,
  graceHours: 48,
  executorLabel: "Trusted Executor",
  memo: "batch 7",
};

function makePlan(overrides: Partial<CreateDeadmanPlanInput> = {}, seed = 1) {
  return createDeadmanPlan({ ...PLAN_INPUT, ...overrides }, NOW, entropy(seed));
}

/** An ISO timestamp offset from NOW by a whole number of hours. */
function hoursFromNow(hours: number): string {
  return new Date(NOW.getTime() + hours * HOUR).toISOString();
}

describe("createDeadmanPlan", () => {
  it("records the pool as provenance and holds the amounts privately", () => {
    const plan = makePlan();

    expect(plan.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(DEADMAN_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(plan.network).toBe("SN_MAIN");
    expect(plan.switchValueBaseUnits).toBe("1000000000");
    expect(plan.switchValueDisplay).toBe("1000");
    expect(plan.checkInIntervalMs).toBe(24 * HOUR);
    expect(plan.graceMs).toBe(48 * HOUR);
    expect(plan.beneficiaries.map((b) => b.amountBaseUnits)).toEqual(["600000000", "400000000"]);
    expect(verifyDeadmanPlan(plan)).toBe(true);
  });

  it("defaults the grace to zero and rejects bad cadence, shares, or parties", () => {
    const noGrace = makePlan({ graceHours: undefined });
    expect(noGrace.graceMs).toBe(0);

    expect(() => makePlan({ switchValue: "0" })).toThrow(/greater than zero/i);
    expect(() => makePlan({ checkInIntervalHours: 0.5 })).toThrow(/between 1 and/i);
    expect(() => makePlan({ graceHours: 4344 })).toThrow(/between 0 and 4320 hours/i);
    expect(() => makePlan({ beneficiaries: [{ recipient: BENE_A, shareBps: 5000 }, { recipient: BENE_B, shareBps: 4000 }] })).toThrow(/sum to exactly 10000/i);
    expect(() => makePlan({ beneficiaries: [{ recipient: BENE_A, shareBps: 5000 }, { recipient: BENE_A, shareBps: 5000 }] })).toThrow(/distinct recipient/i);
  });
});

describe("beneficiary allocation economics", () => {
  it("floors each share and hands the last beneficiary the exact remainder", () => {
    const plan = makePlan({
      switchValue: "1.000001",
      beneficiaries: [
        { recipient: BENE_A, shareBps: 5000, label: "A" },
        { recipient: BENE_B, shareBps: 5000, label: "B" },
      ],
    });

    expect(plan.beneficiaries[0].amountBaseUnits).toBe("500000");
    expect(plan.beneficiaries[1].amountBaseUnits).toBe("500001");
    expect(plan.beneficiaries[0].amountDisplay).toBe("0.5");
    expect(plan.beneficiaries[1].amountDisplay).toBe("0.500001");
    const total = plan.beneficiaries.reduce((sum, b) => sum + BigInt(b.amountBaseUnits), 0n);
    expect(total).toBe(BigInt(plan.switchValueBaseUnits));
  });

  it("spreads three uneven shares and conserves every base unit", () => {
    const plan = makePlan({
      switchValue: "1000",
      beneficiaries: [
        { recipient: BENE_A, shareBps: 3333 },
        { recipient: BENE_B, shareBps: 3333 },
        { recipient: BENE_C, shareBps: 3334 },
      ],
    });

    const total = plan.beneficiaries.reduce((sum, b) => sum + BigInt(b.amountBaseUnits), 0n);
    expect(total).toBe(1_000_000_000n);
    expect(plan.beneficiaries[2].amountBaseUnits).toBe("333400000");
  });
});

describe("contingency actions", () => {
  it("merges the payout into one in-pool transfer per beneficiary with no relayer-fee action", () => {
    const plan = makePlan();
    const actions = buildContingencyActions(plan);

    expect(actions).toEqual([
      { type: "transfer", token: USDC, amount: "600000000", recipient: BENE_A },
      { type: "transfer", token: USDC, amount: "400000000", recipient: BENE_B },
    ]);
    expect(actions.filter((action) => action.type === "withdraw")).toHaveLength(0);
  });

  it("drops a zero leg so a dust plan pays only the remainder beneficiary", () => {
    const plan = makePlan({
      switchValue: "0.000001",
      beneficiaries: [
        { recipient: BENE_A, shareBps: 5000 },
        { recipient: BENE_B, shareBps: 5000 },
      ],
    });
    expect(plan.beneficiaries[0].amountBaseUnits).toBe("0");
    expect(buildContingencyActions(plan)).toEqual([{ type: "transfer", token: USDC, amount: "1", recipient: BENE_B }]);
  });

  it("keeps the payout on a real pool token", () => {
    const plan = makePlan();
    expect(plan.asset.tokenAddress).not.toBe(STRK);
    expect(plan.asset.tokenAddress).toBe(USDC);
  });
});

describe("commitments and selective disclosure", () => {
  it("detects a tampered amount, salt, display, or cadence", () => {
    const plan = makePlan();

    expect(verifyDeadmanPlan({ ...plan, planSalt: "0x2" })).toBe(false);
    expect(verifyDeadmanPlan({ ...plan, switchValueDisplay: "999" })).toBe(false);
    expect(verifyDeadmanPlan({ ...plan, checkInIntervalMs: plan.checkInIntervalMs + 1 })).toBe(false);
    expect(verifyDeadmanPlan({ ...plan, beneficiaries: [{ ...plan.beneficiaries[0], amountBaseUnits: "1" }, plan.beneficiaries[1]] })).toBe(false);
  });

  it("publishes a digest that carries no amount, address, executor, salt, or memo", () => {
    const plan = makePlan();
    const digest = buildDeadmanPlanDigest(plan);
    const encoded = JSON.stringify(digest);

    expect(digest.planCommitment).toBe(plan.planCommitment);
    expect(digest.beneficiaryCount).toBe(2);
    expect(digest.hasExecutor).toBe(true);
    expect(encoded).not.toContain(plan.switchValueBaseUnits);
    expect(encoded).not.toContain("600000000");
    expect(encoded).not.toContain(plan.planSalt);
    expect(encoded).not.toContain(BENE_A);
    expect(encoded).not.toContain("Trusted Executor");
    expect(encoded).not.toContain("batch 7");
    expect(parseDeadmanPlanDigest(serializeDeadmanPlanDigest(digest))).toEqual(digest);
  });

  it("opens a plan against its digest and rejects a doctored opening", () => {
    const plan = makePlan();
    const digest = buildDeadmanPlanDigest(plan);
    const opening = openDeadmanPlan(plan);

    expect(verifyDeadmanPlanDisclosure(digest, opening)).toBe(true);
    expect(verifyDeadmanPlanDisclosure(digest, { ...opening, plan: { ...opening.plan, invoiceId: "inv_other" } })).toBe(false);
    expect(verifyDeadmanPlanDisclosure(digest, { ...opening, planCommitment: "0x5" })).toBe(false);
  });
});

describe("liveness evaluation", () => {
  it("reads active, then grace, then lapsed as the clock advances", () => {
    const plan = makePlan();

    const active = evaluateLiveness(plan, hoursFromNow(0), NOW);
    expect(active.state).toBe("active");
    expect(active.triggerable).toBe(false);
    expect(active.msUntilCheckIn).toBe(24 * HOUR);

    const grace = evaluateLiveness(plan, hoursFromNow(-30), NOW);
    expect(grace.state).toBe("grace");
    expect(grace.triggerable).toBe(false);
    expect(grace.msUntilCheckIn).toBe(0);
    expect(grace.msUntilLapse).toBe(42 * HOUR);

    const lapsed = evaluateLiveness(plan, hoursFromNow(-80), NOW);
    expect(lapsed.state).toBe("lapsed");
    expect(lapsed.triggerable).toBe(true);
    expect(lapsed.msUntilLapse).toBe(0);
    expect(canTriggerContingency(plan, hoursFromNow(-80), NOW)).toBe(true);
    expect(canTriggerContingency(plan, hoursFromNow(0), NOW)).toBe(false);
  });

  it("schedules evenly spaced reminders, a final notice, and the lapse", () => {
    const plan = makePlan();
    const reminders = buildReminderSchedule(plan, hoursFromNow(0), 3);

    expect(reminders).toHaveLength(5);
    expect(reminders.filter((r) => r.kind === "check_in")).toHaveLength(3);
    expect(reminders.at(-2)?.kind).toBe("final_notice");
    expect(reminders.at(-2)?.at).toBe(hoursFromNow(24));
    expect(reminders.at(-1)?.kind).toBe("lapse");
    expect(reminders.at(-1)?.at).toBe(hoursFromNow(72));
  });
});

describe("outcome attestation", () => {
  it("binds the plan and refuses to attest a trigger before the lapse", () => {
    const plan = makePlan();
    const other = makePlan({ invoiceId: "inv_deadman_002" }, 2);
    const attestation = buildDeadmanAttestation(plan, { lastCheckInAt: hoursFromNow(-80), triggeredAt: hoursFromNow(0) });

    expect(attestation.planCommitment).toBe(plan.planCommitment);
    expect(attestation.lapseAt).toBe(hoursFromNow(-8));
    expect(verifyDeadmanAttestation(attestation, plan)).toBe(true);
    expect(verifyDeadmanAttestation(attestation, other)).toBe(false);
    expect(() => buildDeadmanAttestation(plan, { lastCheckInAt: hoursFromNow(-80), triggeredAt: hoursFromNow(-20) })).toThrow(/before the plan lapses/i);
    expect(parseDeadmanAttestation(serializeDeadmanAttestation(attestation))).toEqual(attestation);
  });
});

describe("visibility, trust, and formatting", () => {
  it("says plainly what is in-browser only, what the wallet sees, and what stays public", () => {
    const model = getDeadmanVisibilityModel(makePlan());

    expect(model.walletRequest).toContain("exact per-beneficiary base-unit amounts");
    expect(model.hiddenInPool.some((entry) => /which encrypted notes were spent/.test(entry))).toBe(true);
    expect(model.publicOrObservable.some((entry) => /timing/.test(entry))).toBe(true);
    expect(model.limitation).toMatch(/correlate the beneficiaries/i);
  });

  it("refuses to call the plan autonomous, time-locked, escrowed, or proven", () => {
    const trust = summarizeDeadmanTrust(makePlan());

    expect(trust).toMatchObject({ isAutonomous: false, isTimeLocked: false, isEscrowed: false, isProven: false });
    expect(trust.trustedParties).toHaveLength(2);
    expect(trust.statement).toMatch(/nothing fires on its own/i);
  });

  it("formats base units for display", () => {
    expect(formatDeadmanBaseUnits("600000000", 6)).toBe("600");
    expect(formatDeadmanBaseUnits(1000002n, 6)).toBe("1.000002");
    expect(formatDeadmanBaseUnits("0", 18)).toBe("0");
    expect(() => formatDeadmanBaseUnits("1", 19)).toThrow(/between 0 and 18/i);
  });
});

describe("serialization", () => {
  it("survives round trips and gives independent plans independent commitments", () => {
    const plan = makePlan();
    const twin = makePlan({}, 2);

    expect(parseDeadmanPlan(serializeDeadmanPlan(plan))).toEqual(plan);
    expect(twin.switchValueBaseUnits).toBe(plan.switchValueBaseUnits);
    expect(twin.planSalt).not.toBe(plan.planSalt);
    expect(twin.planCommitment).not.toBe(plan.planCommitment);
    expect(() => parseDeadmanPlan("not base64url!!")).toThrow(/encoding is invalid/i);
  });
});
