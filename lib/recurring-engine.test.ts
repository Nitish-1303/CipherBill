import { describe, expect, it } from "vitest";

import {
  buildBillingSchedule,
  buildCycleDrawActions,
  buildCycleReceiptAttestation,
  buildCycleReminders,
  buildMandateAuthorization,
  buildRecurringPlanDigest,
  createRecurringPlan,
  evaluateBillingCycle,
  evaluateBillingStatus,
  formatRecurringBaseUnits,
  getRecurringVisibilityModel,
  openRecurringPlan,
  parseRecurringCycleReceipt,
  parseRecurringPlan,
  parseRecurringPlanDigest,
  RECURRING_POOL_ADDRESS,
  registerBillingMandate,
  serializeRecurringCycleReceipt,
  serializeRecurringPlan,
  serializeRecurringPlanDigest,
  summarizeRecurringTrust,
  verifyCycleReceiptAttestation,
  verifyMandateAuthorization,
  verifyRecurringPlan,
  verifyRecurringPlanDisclosure,
  type CreateRecurringPlanInput,
  type RecurringEntropy,
  type RecurringMandateEntropy,
} from "./recurring-engine";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const NOW = new Date("2026-08-23T08:00:00.000Z");
const USDC = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const MERCHANT = "0x0712345678901234567890123456789012345678901234567890123456789012";
const TX = "0x02c1f6f9e7b1a4c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8fabc1234";
const DAY = 86_400_000;

const PLAN_INPUT: CreateRecurringPlanInput = {
  invoiceId: "inv_recurring_001",
  merchant: MERCHANT,
  asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
  totalValue: "1200",
  cycleCount: 12,
  cadenceDays: 30,
  graceDays: 7,
  payerLabel: "Acme Corp",
  memo: "annual plan",
};

function entropy(seed: number): RecurringEntropy {
  return {
    createId: () => `rcb_test_${seed.toString().padStart(4, "0")}`,
    randomBytes: (target) => {
      for (let i = 0; i < target.length; i += 1) target[i] = (seed * 31 + i * 7 + 1) & 0xff;
      return target;
    },
  };
}

function mandateEntropy(seed: number): RecurringMandateEntropy {
  return { mandateSecret: BigInt(seed) * 6_700_417n + 8191n, nonce: BigInt(seed) * 2_147_483_647n + 524_287n };
}

function makePlan(overrides: Partial<CreateRecurringPlanInput> = {}, seed = 1) {
  return createRecurringPlan({ ...PLAN_INPUT, ...overrides }, NOW, entropy(seed));
}

const iso = (offsetMs: number) => new Date(NOW.getTime() + offsetMs).toISOString();

describe("createRecurringPlan", () => {
  it("records pool provenance, commits the plan, and keeps amounts local", () => {
    const plan = makePlan();
    expect(plan.poolAddress).toBe(RECURRING_POOL_ADDRESS);
    expect(plan.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(plan.planId).toBe("rcb_test_0001");
    expect(plan.totalValueBaseUnits).toBe("1200000000");
    expect(plan.totalValueDisplay).toBe("1200");
    expect(plan.planCommitment).toMatch(/^0x[0-9a-f]+$/);
    expect(verifyRecurringPlan(plan)).toBe(true);
  });

  it("normalizes an 18-decimal asset and its display", () => {
    const plan = makePlan({ asset: { symbol: "STRK", tokenAddress: STRK, decimals: 18 }, totalValue: "9" });
    expect(plan.asset.decimals).toBe(18);
    expect(plan.totalValueBaseUnits).toBe("9000000000000000000");
    expect(plan.totalValueDisplay).toBe("9");
    expect(verifyRecurringPlan(plan)).toBe(true);
  });

  it("gives independent plans distinct salts and commitments", () => {
    const a = makePlan({}, 1);
    const b = makePlan({}, 2);
    expect(a.planSalt).not.toBe(b.planSalt);
    expect(a.planCommitment).not.toBe(b.planCommitment);
    expect(a.totalValueBaseUnits).toBe(b.totalValueBaseUnits);
  });

  it("rejects malformed inputs", () => {
    expect(() => makePlan({ totalValue: "0" })).toThrow(/greater than zero/i);
    expect(() => makePlan({ cycleCount: 0 })).toThrow(/between 1 and 60/i);
    expect(() => makePlan({ cycleCount: 61 })).toThrow(/between 1 and 60/i);
    expect(() => makePlan({ cadenceDays: 0 })).toThrow(/positive whole number of days/i);
    expect(() => makePlan({ cadenceDays: 400 })).toThrow(/between 1 and 365 days/i);
    expect(() => makePlan({ graceDays: 100 })).toThrow(/between 0 and 90 days/i);
  });
});

describe("installment schedule", () => {
  it("splits evenly and conserves the total", () => {
    const schedule = buildBillingSchedule(makePlan());
    expect(schedule).toHaveLength(12);
    const sum = schedule.reduce((acc, c) => acc + BigInt(c.amountBaseUnits), 0n);
    expect(sum.toString()).toBe("1200000000");
    expect(schedule.every((c) => c.amountDisplay === "100")).toBe(true);
  });

  it("floors each share and loads the remainder onto the last cycle", () => {
    const schedule = buildBillingSchedule(makePlan({ totalValue: "100", cycleCount: 3 }));
    expect(schedule.map((c) => c.amountBaseUnits)).toEqual(["33333333", "33333333", "33333334"]);
    const sum = schedule.reduce((acc, c) => acc + BigInt(c.amountBaseUnits), 0n);
    expect(sum.toString()).toBe("100000000");
  });

  it("handles a total smaller than the cycle count", () => {
    const schedule = buildBillingSchedule(makePlan({ totalValue: "0.000005", cycleCount: 12 }));
    expect(schedule[0].amountBaseUnits).toBe("0");
    expect(schedule[11].amountBaseUnits).toBe("5");
    expect(schedule.reduce((a, c) => a + BigInt(c.amountBaseUnits), 0n).toString()).toBe("5");
  });

  it("spaces due dates by the cadence and adds the grace window", () => {
    const schedule = buildBillingSchedule(makePlan());
    expect(schedule[0].dueAt).toBe(NOW.toISOString());
    expect(schedule[1].dueAt).toBe(iso(30 * DAY));
    expect(schedule[0].graceEndsAt).toBe(iso(7 * DAY));
  });
});

describe("cycle draw actions", () => {
  it("builds exactly one in-pool transfer with no relayer-fee leg", () => {
    const plan = makePlan();
    const actions = buildCycleDrawActions(plan, 1);
    expect(actions).toHaveLength(1);
    expect(actions[0]).toEqual({ type: "transfer", token: plan.asset.tokenAddress, amount: "100000000", recipient: plan.merchant });
  });

  it("refuses an out-of-range or empty cycle", () => {
    expect(() => buildCycleDrawActions(makePlan(), 0)).toThrow(/out of range/i);
    expect(() => buildCycleDrawActions(makePlan(), 13)).toThrow(/out of range/i);
    expect(() => buildCycleDrawActions(makePlan({ totalValue: "0.000005", cycleCount: 12 }), 1)).toThrow(/nothing to draw/i);
  });
});

describe("cycle reminders", () => {
  it("emits count nudges plus a due and overdue notice", () => {
    const reminders = buildCycleReminders(makePlan(), 2);
    expect(reminders).toHaveLength(5);
    expect(reminders.slice(0, 3).every((r) => r.kind === "cycle_nudge")).toBe(true);
    expect(reminders[3].kind).toBe("due_notice");
    expect(reminders[3].at).toBe(iso(30 * DAY));
    expect(reminders[4].kind).toBe("overdue_notice");
    expect(reminders[4].at).toBe(iso(37 * DAY));
  });

  it("honors the reminder count and its bounds", () => {
    expect(buildCycleReminders(makePlan(), 1, 1)).toHaveLength(3);
    expect(() => buildCycleReminders(makePlan(), 1, 0)).toThrow(/between 1 and 8/i);
    expect(() => buildCycleReminders(makePlan(), 1, 9)).toThrow(/between 1 and 8/i);
  });
});

describe("cycle evaluation", () => {
  it("moves from upcoming to due to overdue and reflects settlement", () => {
    const plan = makePlan();
    expect(evaluateBillingCycle(plan, 2, [], NOW).state).toBe("upcoming");
    expect(evaluateBillingCycle(plan, 1, [], NOW).state).toBe("due");
    expect(evaluateBillingCycle(plan, 1, [], new Date(NOW.getTime() + 8 * DAY)).state).toBe("overdue");
    expect(evaluateBillingCycle(plan, 1, [1], NOW).state).toBe("settled");
  });

  it("reports the time remaining to due and overdue", () => {
    const upcoming = evaluateBillingCycle(makePlan(), 2, [], NOW);
    expect(upcoming.msUntilDue).toBe(30 * DAY);
    expect(upcoming.msUntilOverdue).toBe(37 * DAY);
    const due = evaluateBillingCycle(makePlan(), 1, [], NOW);
    expect(due.msUntilDue).toBe(0);
    expect(due.msUntilOverdue).toBe(7 * DAY);
  });

  it("rejects an out-of-range cycle index", () => {
    expect(() => evaluateBillingCycle(makePlan(), 99, [], NOW)).toThrow(/out of range/i);
    expect(() => evaluateBillingCycle(makePlan(), 1, [99], NOW)).toThrow(/out of range/i);
  });
});

describe("billing status", () => {
  const settledAll = Array.from({ length: 12 }, (_, i) => i + 1);

  it("summarizes the plan-level state across the clock", () => {
    const plan = makePlan();
    expect(evaluateBillingStatus(plan, [], new Date(NOW.getTime() - DAY)).state).toBe("scheduled");
    expect(evaluateBillingStatus(plan, [], NOW).state).toBe("active");
    expect(evaluateBillingStatus(plan, [], new Date(NOW.getTime() + 8 * DAY)).state).toBe("in_arrears");
    expect(evaluateBillingStatus(plan, settledAll, NOW).state).toBe("completed");
  });

  it("tracks settled value and outstanding balance", () => {
    const status = evaluateBillingStatus(makePlan(), [1], NOW);
    expect(status.settledCount).toBe(1);
    expect(status.remainingCount).toBe(11);
    expect(status.nextUnsettledIndex).toBe(2);
    expect(status.settledValueBaseUnits).toBe("100000000");
    expect(status.outstandingValueBaseUnits).toBe("1100000000");
  });

  it("marks a fully settled plan complete with zero outstanding", () => {
    const status = evaluateBillingStatus(makePlan(), settledAll, NOW);
    expect(status.remainingCount).toBe(0);
    expect(status.outstandingValueBaseUnits).toBe("0");
    expect(status.settledValueBaseUnits).toBe("1200000000");
  });
});

describe("plan digest and disclosure", () => {
  it("omits amounts, addresses, payer, salt, and memo from the digest", () => {
    const plan = makePlan();
    const digest = buildRecurringPlanDigest(plan);
    const json = JSON.stringify(digest);
    expect(json).not.toContain("1200000000");
    expect(json).not.toContain(plan.merchant);
    expect(json).not.toContain(plan.planSalt);
    expect(json).not.toContain("Acme Corp");
    expect(json).not.toContain("annual plan");
    expect(digest.hasPayer).toBe(true);
    expect(digest.cycleCount).toBe(12);
    expect(digest.planCommitment).toBe(plan.planCommitment);
  });

  it("verifies a faithful disclosure and rejects a doctored one", () => {
    const plan = makePlan();
    const digest = buildRecurringPlanDigest(plan);
    const opening = openRecurringPlan(plan);
    expect(verifyRecurringPlanDisclosure(digest, opening)).toBe(true);
    expect(verifyRecurringPlanDisclosure(digest, { ...opening, plan: { ...opening.plan, invoiceId: "inv_other" } })).toBe(false);
    expect(verifyRecurringPlanDisclosure(digest, { ...opening, planCommitment: "0x1" })).toBe(false);
  });

  it("round-trips the digest through serialization", () => {
    const digest = buildRecurringPlanDigest(makePlan());
    expect(parseRecurringPlanDigest(serializeRecurringPlanDigest(digest))).toEqual(digest);
  });
});

describe("cycle receipts", () => {
  it("builds and verifies a receipt bound to the plan and cycle", () => {
    const plan = makePlan();
    const receipt = buildCycleReceiptAttestation(plan, { cycleIndex: 2, settledAt: iso(31 * DAY), transactionHash: TX });
    expect(receipt.amountBaseUnits).toBe("100000000");
    expect(receipt.dueAt).toBe(iso(30 * DAY));
    expect(verifyCycleReceiptAttestation(receipt, plan)).toBe(true);
    expect(verifyCycleReceiptAttestation(receipt, makePlan({}, 2))).toBe(false);
  });

  it("refuses a settlement time before the plan anchor", () => {
    const plan = makePlan();
    expect(() => buildCycleReceiptAttestation(plan, { cycleIndex: 1, settledAt: iso(-DAY), transactionHash: TX })).toThrow(/before the plan anchor/i);
  });

  it("round-trips a receipt through serialization", () => {
    const plan = makePlan();
    const receipt = buildCycleReceiptAttestation(plan, { cycleIndex: 2, settledAt: iso(31 * DAY), transactionHash: TX });
    expect(parseRecurringCycleReceipt(serializeRecurringCycleReceipt(receipt))).toEqual(receipt);
  });
});

describe("mandate authorization", () => {
  it("verifies a valid proof against the expected mandate key", () => {
    const plan = makePlan();
    const mandate = registerBillingMandate(mandateEntropy(1));
    const auth = buildMandateAuthorization(plan, 2, mandate.mandateSecret, mandateEntropy(1));
    expect(verifyMandateAuthorization(auth, plan, mandate.mandatePublicKey)).toBe(true);
  });

  it("rejects a wrong expected key, a tampered cycle, and a wrong plan", () => {
    const plan = makePlan();
    const mandate = registerBillingMandate(mandateEntropy(1));
    const other = registerBillingMandate(mandateEntropy(2));
    const auth = buildMandateAuthorization(plan, 2, mandate.mandateSecret, mandateEntropy(1));
    expect(verifyMandateAuthorization(auth, plan, other.mandatePublicKey)).toBe(false);
    expect(verifyMandateAuthorization({ ...auth, cycleIndex: 3 }, plan, mandate.mandatePublicKey)).toBe(false);
    expect(verifyMandateAuthorization(auth, makePlan({}, 2), mandate.mandatePublicKey)).toBe(false);
  });

  it("produces a deterministic proof for a fixed nonce", () => {
    const plan = makePlan();
    const mandate = registerBillingMandate(mandateEntropy(1));
    const a = buildMandateAuthorization(plan, 2, mandate.mandateSecret, mandateEntropy(1));
    const b = buildMandateAuthorization(plan, 2, mandate.mandateSecret, mandateEntropy(1));
    expect(a.proof).toEqual(b.proof);
  });
});

describe("visibility, trust, and serialization", () => {
  it("states an honest visibility model", () => {
    const model = getRecurringVisibilityModel(makePlan());
    expect(model.walletRequest.some((e) => /exact base-unit amount/.test(e))).toBe(true);
    expect(model.hiddenInPool.some((e) => /encrypted notes were spent/.test(e))).toBe(true);
    expect(model.publicOrObservable.some((e) => /timing/.test(e))).toBe(true);
    expect(model.limitation).toMatch(/correlation signal/i);
  });

  it("summarizes trust without overclaiming", () => {
    const trust = summarizeRecurringTrust(makePlan());
    expect(trust).toMatchObject({ isAutomated: false, isDecentralized: false, isEscrowed: false, isOnChainMandate: false, provesPayment: false });
    expect(trust.trustedParties).toHaveLength(2);
    expect(trust.statement).toMatch(/nothing is automated, decentralized, or escrowed/i);
    expect(trust.zeroKnowledgeElement).toMatch(/only the optional mandate authorization/i);
  });

  it("detects tampering when verifying a plan", () => {
    const plan = makePlan();
    expect(verifyRecurringPlan({ ...plan, planSalt: "0x1" })).toBe(false);
    expect(verifyRecurringPlan({ ...plan, totalValueDisplay: "999" })).toBe(false);
    expect(verifyRecurringPlan({ ...plan, cadenceMs: plan.cadenceMs + 1 })).toBe(false);
  });

  it("round-trips a plan and rejects malformed encodings", () => {
    const plan = makePlan();
    expect(parseRecurringPlan(serializeRecurringPlan(plan))).toEqual(plan);
    expect(() => parseRecurringPlan("!!not valid!!")).toThrow(/encoding is invalid/i);
  });

  it("formats base units and guards decimals", () => {
    expect(formatRecurringBaseUnits("100000000", 6)).toBe("100");
    expect(formatRecurringBaseUnits(1_000_002n, 6)).toBe("1.000002");
    expect(formatRecurringBaseUnits("0", 0)).toBe("0");
    expect(() => formatRecurringBaseUnits("1", 19)).toThrow(/between 0 and 18/i);
  });
});
