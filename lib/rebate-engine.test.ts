import { describe, expect, it } from "vitest";

import type { ShareableInvoice } from "./invoices";
import {
  buildRebateSettlementActions,
  calculateEligibleRebateBps,
  calculateRebate,
  createRebateCommitment,
  getRebateSecurityModel,
  REBATE_POOL_ADDRESS,
  serializeRebateProof,
  verifyRebateCommitment,
} from "./rebate-engine";

const invoice: ShareableInvoice = {
  version: 2,
  invoiceId: "inv_rebate_001",
  merchantName: "Cipher Studio",
  recipientAddress: "0x1234",
  tokenAddress: "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  amount: "9007199254740993.000000000000000001",
  description: "Private settlement",
  createdAt: "2026-08-01T00:00:00.000Z",
  expiresAt: "2026-09-01T00:00:00.000Z",
  network: "SN_MAIN",
  allowPartialPayments: false,
  rebatePolicy: {
    version: 1,
    maximumRebateBps: 1_000,
    minimumLeadTimeSeconds: 3_600,
    fullRebateLeadTimeSeconds: 10 * 24 * 60 * 60,
  },
};

const deterministicEntropy = { randomBytes: (target: Uint8Array<ArrayBuffer>) => target.fill(7) };
const issuedAt = new Date("2026-08-22T00:00:00.000Z");

describe("early-settlement rebate engine", () => {
  it("decays the vendor ceiling with lead time and respects the cutoff", () => {
    expect(calculateEligibleRebateBps(invoice.rebatePolicy!, invoice.expiresAt, issuedAt)).toEqual({
      eligibleRebateBps: 1_000,
      leadTimeSeconds: 10 * 24 * 60 * 60,
    });
    const midpoint = calculateEligibleRebateBps(invoice.rebatePolicy!, invoice.expiresAt, new Date("2026-08-27T00:00:00.000Z"));
    expect(midpoint.eligibleRebateBps).toBe(Number(1_000n * BigInt(5 * 24 * 60 * 60 - 3_600) / BigInt(10 * 24 * 60 * 60 - 3_600)));
    expect(calculateEligibleRebateBps(invoice.rebatePolicy!, invoice.expiresAt, new Date("2026-08-31T23:30:00.000Z")).eligibleRebateBps).toBe(0);
  });

  it("uses bigint-exact floor arithmetic beyond Number.MAX_SAFE_INTEGER", () => {
    const principal = 9007199254740993000000000000000001n;
    const calculation = calculateRebate(principal, invoice.rebatePolicy!, invoice.expiresAt, 999, issuedAt);
    expect(calculation.rebateBaseUnits).toBe(principal * 999n / 10_000n);
    expect(calculation.settlementBaseUnits + calculation.rebateBaseUnits).toBe(principal);
    expect(() => calculateRebate(principal, invoice.rebatePolicy!, invoice.expiresAt, 1_001, issuedAt)).toThrow(/exceeds/i);
  });

  it("creates an invoice-bound hiding commitment and verifies its opening", () => {
    const claim = createRebateCommitment(invoice, 750, issuedAt, deterministicEntropy);
    const verified = verifyRebateCommitment(invoice, claim, new Date("2026-08-22T00:04:59.000Z"));
    expect(verified.selectedRebateBps).toBe(750);
    expect(verified.settlementBaseUnits + verified.rebateBaseUnits).toBe(verified.principalBaseUnits);
    expect(claim.proof).toMatchObject({
      proofKind: "salted-poseidon-commitment",
      poolAddress: REBATE_POOL_ADDRESS,
      network: "SN_MAIN",
      validUntil: "2026-08-22T00:05:00.000Z",
    });
  });

  it("exports only opaque commitments and rejects a modified opening", () => {
    const claim = createRebateCommitment(invoice, 750, issuedAt, deterministicEntropy);
    const publicProof = serializeRebateProof(claim.proof);
    expect(publicProof).not.toContain(invoice.invoiceId);
    expect(publicProof).not.toContain(invoice.amount);
    expect(publicProof).not.toContain(invoice.recipientAddress);
    expect(publicProof).not.toContain(claim.opening.rebateBaseUnits);

    const tampered = structuredClone(claim);
    tampered.opening.rebateBaseUnits = (BigInt(tampered.opening.rebateBaseUnits) + 1n).toString();
    expect(() => verifyRebateCommitment(invoice, tampered, issuedAt)).toThrow(/arithmetic/i);
  });

  it("maps the verified net amount to one exact STRK20 private transfer", () => {
    const claim = createRebateCommitment(invoice, 750, issuedAt, deterministicEntropy);
    const actions = buildRebateSettlementActions(invoice, claim, issuedAt);
    expect(actions).toEqual([{
      type: "transfer",
      token: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
      amount: claim.opening.settlementBaseUnits,
      recipient: "0x0000000000000000000000000000000000000000000000000000000000001234",
    }]);
  });

  it("expires short-lived quotes and refuses unsupported invoice structures", () => {
    const claim = createRebateCommitment(invoice, 750, issuedAt, deterministicEntropy);
    expect(() => verifyRebateCommitment(invoice, claim, new Date("2026-08-22T00:05:00.001Z"))).toThrow(/not currently valid/i);
    expect(() => createRebateCommitment({ ...invoice, allowPartialPayments: true }, 750, issuedAt, deterministicEntropy)).toThrow(/single exact/i);
    expect(() => createRebateCommitment({ ...invoice, rebatePolicy: undefined }, 750, issuedAt, deterministicEntropy)).toThrow(/does not offer/i);
  });

  it("states the cryptographic and STRK20 enforcement boundaries", () => {
    const model = getRebateSecurityModel();
    expect(model.hiddenByStrk20.join(" ")).toMatch(/amount/i);
    expect(model.limitations.join(" ")).toMatch(/not a zk-SNARK/i);
    expect(model.limitations.join(" ")).toMatch(/helper contract/i);
  });
});
