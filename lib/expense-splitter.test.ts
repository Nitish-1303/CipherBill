import { describe, expect, it } from "vitest";

import {
  buildOptimizedExpenseCalldata,
  calculateExactExpenseConversion,
  createExpenseSettlementPlan,
  estimateExpenseBatchSavings,
  EXPENSE_SPLITTER_POOL_ADDRESS,
  getExpenseVisibilityModel,
  verifyExpenseSettlementPlan,
  type PendingExpenseInput,
} from "./expense-splitter";

const now = new Date("2026-08-22T12:00:00.000Z");
const usdc = { tokenAddress: "0x111", symbol: "USDC", decimals: 6 };
const eurc = { tokenAddress: "0x222", symbol: "EURC", decimals: 6 };

const expenses: PendingExpenseInput[] = [
  expense("inv_us_001", "Cloud vendor", "Platform", "0xabc", "USD", "10.00", usdc, "1"),
  expense("inv_eu_002", "Design vendor", "Creative", "0xabc", "EUR", "20.00", usdc, "1.1"),
  expense("inv_jp_003", "Research vendor", "R&D", "0xdef", "JPY", "1000", usdc, "0.0067"),
  expense("inv_uk_004", "Legal vendor", "Legal", "0x456", "GBP", "8.50", eurc, "1.17"),
];

function plan() {
  return createExpenseSettlementPlan(expenses, now, { createId: () => "split_team_august" });
}

describe("autonomous multi-currency expense splitting", () => {
  it("converts source currencies with bigint-exact ceiling arithmetic", () => {
    expect(calculateExactExpenseConversion({ invoiceCurrency: "EUR", invoiceAmount: "20", settlementDecimals: 6, rate: "1.1" })).toMatchObject({
      invoiceMinorUnits: "2000",
      normalizedInvoiceAmount: "20",
      settlementBaseUnits: "22000000",
      settlementDisplayAmount: "22",
      rounding: "ceil",
    });
    expect(calculateExactExpenseConversion({ invoiceCurrency: "USD", invoiceAmount: "0.01", settlementDecimals: 0, rate: "0.1" })).toMatchObject({
      settlementBaseUnits: "1",
      roundingDeltaNumerator: "999",
      roundingDenominator: "1000",
    });
  });

  it("groups matching token-recipient transfers and conserves every invoice", () => {
    const created = plan();
    expect(created.poolAddress).toBe(EXPENSE_SPLITTER_POOL_ADDRESS);
    expect(created.optimization).toEqual({ pendingInvoiceCount: 4, optimizedTransferCount: 3, duplicateTransfersMerged: 1, walletRequestsAvoided: 3 });
    expect(created.transfers[0]).toMatchObject({
      tokenAddress: expect.stringMatching(/^0x0+111$/),
      recipientAddress: expect.stringMatching(/^0x0+abc$/),
      amountBaseUnits: "32000000",
      displayAmount: "32",
      invoiceIds: ["inv_eu_002", "inv_us_001"],
    });
    const inputTotal = created.expenses.filter((item) => BigInt(item.settlementAsset.tokenAddress) === 0x111n).reduce((sum, item) => sum + BigInt(item.conversion.settlementBaseUnits), 0n);
    expect(created.tokenTotals.find((item) => BigInt(item.tokenAddress) === 0x111n)?.amountBaseUnits).toBe(inputTotal.toString());
  });

  it("constructs one canonical Wallet API batch with no invoice metadata", () => {
    const actions = buildOptimizedExpenseCalldata(plan(), now);
    expect(actions).toHaveLength(3);
    expect(actions.every((action) => action.type === "transfer")).toBe(true);
    expect(Object.keys(actions[0]).sort()).toEqual(["amount", "recipient", "token", "type"]);
    const serialized = JSON.stringify(actions);
    expect(serialized).not.toContain("inv_");
    expect(serialized).not.toContain("Cloud vendor");
    expect(serialized).not.toContain("USD");
  });

  it("detects any plan, conversion, or aggregation tampering", () => {
    const created = plan();
    expect(verifyExpenseSettlementPlan(created)).toBe(true);
    const tamperedAmount = structuredClone(created);
    tamperedAmount.expenses[0].conversion.settlementBaseUnits = "999";
    expect(verifyExpenseSettlementPlan(tamperedAmount)).toBe(false);
    const tamperedTransfer = structuredClone(created);
    tamperedTransfer.transfers[0].amountBaseUnits = "999";
    expect(verifyExpenseSettlementPlan(tamperedTransfer)).toBe(false);
    const extension = structuredClone(created) as typeof created & { privateKey?: string };
    extension.privateKey = "never";
    expect(verifyExpenseSettlementPlan(extension)).toBe(false);
  });

  it("uses bigint-safe fee estimation without claiming guaranteed savings", () => {
    const estimate = estimateExpenseBatchSavings(plan(), "4000000000000000000");
    expect(estimate).toMatchObject({
      individualWalletInvocations: 4,
      batchedWalletInvocations: 1,
      walletInvocationsAvoided: 3,
      estimatedPoolFeeSavingsBaseUnits: "12000000000000000000",
      transferActionsEliminated: 1,
    });
    expect(estimate.notice).toMatch(/estimate|change/i);
    expect(estimateExpenseBatchSavings(plan(), "0x10").estimatedPoolFeeSavingsBaseUnits).toBe("48");
  });

  it("rejects duplicate invoices, invalid quotes, and conflicting token metadata", () => {
    expect(() => createExpenseSettlementPlan([expenses[0], expenses[0]], now)).toThrow(/unique/i);
    const expired = { ...expenses[1], rate: { ...expenses[1].rate, expiresAt: "2026-08-22T11:59:59.000Z" } };
    expect(() => createExpenseSettlementPlan([expenses[0], expired], now)).toThrow(/expiry/i);
    const future = { ...expenses[1], rate: { ...expenses[1].rate, quotedAt: "2026-08-22T13:00:00.000Z" } };
    expect(() => createExpenseSettlementPlan([expenses[0], future], now)).toThrow(/future/i);
    const conflict = { ...expenses[1], settlementAsset: { ...usdc, symbol: "FAKE", decimals: 18 } };
    expect(() => createExpenseSettlementPlan([expenses[0], conflict], now)).toThrow(/conflicting/i);
  });

  it("blocks settlement after the earliest quote expires", () => {
    expect(() => buildOptimizedExpenseCalldata(plan(), new Date("2026-08-23T12:00:01.000Z"))).toThrow(/expired/i);
  });

  it("states the wallet, privacy, and multi-party execution boundaries", () => {
    const visibility = getExpenseVisibilityModel(plan());
    expect(visibility.applicationOnly.join(" ")).toMatch(/cost centers/i);
    expect(visibility.walletRequest.join(" ")).toMatch(/recipients/i);
    expect(visibility.hiddenInPool.join(" ")).toMatch(/amounts/i);
    expect(visibility.publicOrObservable.join(" ")).toMatch(/timing/i);
    expect(visibility.limitation).toMatch(/wallet|registered/i);
    expect(plan().executionNotice).toMatch(/Independent wallets cannot pool/i);
  });
});

function expense(
  invoiceId: string,
  vendorLabel: string,
  costCenter: string,
  recipientAddress: string,
  invoiceCurrency: PendingExpenseInput["invoiceCurrency"],
  invoiceAmount: string,
  settlementAsset: PendingExpenseInput["settlementAsset"],
  rate: string,
): PendingExpenseInput {
  return {
    invoiceId,
    vendorLabel,
    costCenter,
    recipientAddress,
    invoiceCurrency,
    invoiceAmount,
    settlementAsset,
    rate: {
      rate,
      source: "Treasury rate desk",
      quotedAt: "2026-08-22T11:55:00.000Z",
      expiresAt: "2026-08-23T12:00:00.000Z",
    },
  };
}
