import { describe, expect, it } from "vitest";

import {
  activateInvoice,
  confirmInvoicePayment,
  createInvoiceLifecycle,
  deriveInvoiceStatus,
  failInvoicePayment,
  getInvoiceAccounting,
  getMilestoneAccounting,
  normalizeInvoiceLifecycle,
  readPayerInvoiceLifecycle,
  submitInvoicePayment,
  validateInvoicePayment,
  writePayerInvoiceLifecycle,
} from "./invoice-lifecycle";
import type { ShareableInvoice } from "./invoices";

const invoice: ShareableInvoice = {
  version: 2,
  invoiceId: "inv_lifecycle",
  merchantName: "Cipher Studio",
  recipientAddress: "0x0000000000000000000000000000000000000000000000000000000000001234",
  tokenAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  amount: "10",
  description: "Delivery",
  createdAt: "2099-08-21T00:00:00.000Z",
  expiresAt: "2099-08-31T00:00:00.000Z",
  network: "SN_MAIN",
  allowPartialPayments: true,
};

describe("invoice lifecycle", () => {
  it("moves from draft to active, confirming, partial, and paid", () => {
    let lifecycle = activateInvoice(createInvoiceLifecycle("draft", new Date("2026-08-21T01:00:00.000Z")));
    lifecycle = submitInvoicePayment(invoice, lifecycle, {
      hash: "0xabc",
      amountBaseUnits: "4000000000000000000",
      submittedAt: "2026-08-21T02:00:00.000Z",
    });
    expect(lifecycle.status).toBe("confirming");
    lifecycle = confirmInvoicePayment(invoice, lifecycle, "0xabc", "2026-08-21T02:01:00.000Z");
    expect(lifecycle.status).toBe("partially_paid");
    expect(getInvoiceAccounting(invoice, lifecycle).remainingBaseUnits).toBe(6000000000000000000n);

    lifecycle = submitInvoicePayment(invoice, lifecycle, {
      hash: "0xdef",
      amountBaseUnits: "6000000000000000000",
      submittedAt: "2026-08-21T03:00:00.000Z",
    });
    lifecycle = confirmInvoicePayment(invoice, lifecycle, "0xdef", "2026-08-21T03:01:00.000Z");
    expect(lifecycle.status).toBe("paid");
  });

  it("prevents overpayments and duplicate transaction hashes", () => {
    const active = createInvoiceLifecycle("active");
    const submitted = submitInvoicePayment(invoice, active, {
      hash: "0xabc",
      amountBaseUnits: "6000000000000000000",
      submittedAt: "2026-08-21T02:00:00.000Z",
    });
    expect(() => submitInvoicePayment(invoice, submitted, {
      hash: "0xabc",
      amountBaseUnits: "1000000000000000000",
      submittedAt: "2026-08-21T02:01:00.000Z",
    })).toThrow(/not accepting|already recorded/i);
    const partial = confirmInvoicePayment(invoice, submitted, "0xabc");
    expect(() => submitInvoicePayment(invoice, partial, {
      hash: "0xdef",
      amountBaseUnits: "5000000000000000000",
      submittedAt: "2026-08-21T03:00:00.000Z",
    })).toThrow(/exceeds/i);
  });

  it("returns to active after a failed first submission and retains its hash", () => {
    const submitted = submitInvoicePayment(invoice, createInvoiceLifecycle("active"), {
      hash: "0xabc",
      amountBaseUnits: "10000000000000000000",
      submittedAt: "2026-08-21T02:00:00.000Z",
    });
    const failed = failInvoicePayment(invoice, submitted, "0xabc");
    expect(failed.status).toBe("active");
    expect(failed.payments[0]).toMatchObject({ hash: "0xabc", status: "failed" });
  });

  it("derives expiration without overriding terminal states", () => {
    expect(deriveInvoiceStatus(invoice, createInvoiceLifecycle("active"), Date.parse("2099-09-01T00:00:00.000Z"))).toBe("expired");
  });

  it("allows exact milestone installments without enabling free-form partial payments", () => {
    const milestoneInvoice: ShareableInvoice = {
      ...invoice,
      allowPartialPayments: false,
      milestones: [
        { id: "design", label: "Design", amount: "4" },
        { id: "delivery", label: "Delivery", amount: "6" },
      ],
    };
    let lifecycle = submitInvoicePayment(milestoneInvoice, createInvoiceLifecycle("active"), {
      hash: "0x111",
      amountBaseUnits: "4000000000000000000",
      milestoneId: "design",
      submittedAt: "2026-08-21T02:00:00.000Z",
    });
    lifecycle = confirmInvoicePayment(milestoneInvoice, lifecycle, "0x111", "2026-08-21T02:01:00.000Z");
    expect(lifecycle.status).toBe("partially_paid");
    expect(getMilestoneAccounting(milestoneInvoice, lifecycle, "design").remainingBaseUnits).toBe(0n);
    expect(() => validateInvoicePayment(milestoneInvoice, lifecycle, {
      amountBaseUnits: "1000000000000000000",
      milestoneId: "delivery",
    })).toThrow(/exact remaining/i);
  });

  it("allows split milestone payments only when partial payments are enabled", () => {
    const milestoneInvoice: ShareableInvoice = {
      ...invoice,
      milestones: [{ id: "all", label: "All work", amount: "10" }],
    };
    expect(() => validateInvoicePayment(milestoneInvoice, createInvoiceLifecycle("active"), {
      amountBaseUnits: "2500000000000000000",
      milestoneId: "all",
    })).not.toThrow();
  });

  it("persists valid payer state and rejects corrupt local lifecycle data", () => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => { values.set(key, value); },
    };
    const lifecycle = createInvoiceLifecycle("active", new Date("2026-08-21T01:00:00.000Z"));
    expect(writePayerInvoiceLifecycle(invoice.invoiceId, lifecycle, storage)).toBe(true);
    expect(readPayerInvoiceLifecycle(invoice.invoiceId, storage)).toEqual(lifecycle);

    values.set("cipherbill.payment-lifecycle.v1", JSON.stringify({ [invoice.invoiceId]: { status: "paid", payments: [{ hash: "bad" }] } }));
    expect(readPayerInvoiceLifecycle(invoice.invoiceId, storage).status).toBe("active");
  });

  it("migrates the partial lifecycle status used by the unfinished engine", () => {
    expect(normalizeInvoiceLifecycle({
      status: "partially_submitted",
      payments: [],
      updatedAt: "2026-08-21T01:00:00.000Z",
    }).status).toBe("partially_paid");
  });

  it("accounts for a verified rebate as settled value without inflating the transfer", () => {
    const rebateInvoice: ShareableInvoice = {
      ...invoice,
      allowPartialPayments: false,
      createdAt: "2026-08-01T00:00:00.000Z",
      expiresAt: "2026-09-01T00:00:00.000Z",
      rebatePolicy: { version: 1, maximumRebateBps: 1_000, minimumLeadTimeSeconds: 3_600, fullRebateLeadTimeSeconds: 864_000 },
    };
    const submitted = submitInvoicePayment(rebateInvoice, createInvoiceLifecycle("active"), {
      hash: "0x8eb8",
      amountBaseUnits: "9250000000000000000",
      rebateBaseUnits: "750000000000000000",
      rebateBps: 750,
      rebateCommitment: "0x123",
      rebateIssuedAt: "2026-08-22T00:00:00.000Z",
      rebateValidUntil: "2026-08-22T00:05:00.000Z",
      submittedAt: "2026-08-22T00:01:00.000Z",
    });
    expect(getInvoiceAccounting(rebateInvoice, submitted)).toMatchObject({
      pendingBaseUnits: 9250000000000000000n,
      pendingRebateBaseUnits: 750000000000000000n,
      remainingBaseUnits: 10000000000000000000n,
    });
    const confirmed = confirmInvoicePayment(rebateInvoice, submitted, "0x8eb8", "2026-08-22T00:02:00.000Z");
    expect(confirmed.status).toBe("paid");
    expect(getInvoiceAccounting(rebateInvoice, confirmed)).toMatchObject({
      confirmedBaseUnits: 9250000000000000000n,
      confirmedRebateBaseUnits: 750000000000000000n,
      remainingBaseUnits: 0n,
    });
  });

  it("rejects incomplete, excessive, and arithmetically invalid rebate records", () => {
    const rebateInvoice: ShareableInvoice = {
      ...invoice,
      allowPartialPayments: false,
      createdAt: "2026-08-01T00:00:00.000Z",
      expiresAt: "2026-09-01T00:00:00.000Z",
      rebatePolicy: { version: 1, maximumRebateBps: 1_000, minimumLeadTimeSeconds: 3_600, fullRebateLeadTimeSeconds: 864_000 },
    };
    const base = {
      amountBaseUnits: "9250000000000000000",
      rebateBaseUnits: "750000000000000000",
      rebateBps: 750,
      rebateCommitment: "0x123",
      rebateIssuedAt: "2026-08-22T00:00:00.000Z",
      rebateValidUntil: "2026-08-22T00:05:00.000Z",
    };
    expect(() => validateInvoicePayment(rebateInvoice, createInvoiceLifecycle("active"), { ...base, rebateBps: 1_001 })).toThrow(/exceeds/i);
    expect(() => validateInvoicePayment(rebateInvoice, createInvoiceLifecycle("active"), { ...base, rebateBaseUnits: "1" })).toThrow(/does not match/i);
    expect(() => validateInvoicePayment(rebateInvoice, createInvoiceLifecycle("active"), { amountBaseUnits: base.amountBaseUnits, rebateBaseUnits: base.rebateBaseUnits })).toThrow(/incomplete/i);
  });
});
