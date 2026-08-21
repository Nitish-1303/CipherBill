import { describe, expect, it } from "vitest";

import type { InvoicePaymentRecord } from "./invoice-lifecycle";
import type { ShareableInvoice } from "./invoices";
import {
  createSelectiveReceipt,
  DEFAULT_RECEIPT_SELECTION,
  serializeSelectiveReceipt,
} from "./selective-receipts";

const invoice: ShareableInvoice = {
  version: 2,
  invoiceId: "inv_receipt",
  merchantName: "Cipher Studio",
  recipientAddress: "0x0000000000000000000000000000000000000000000000000000000000001234",
  tokenAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  amount: "10",
  description: "Private delivery",
  referenceNumber: "PO-1042",
  createdAt: "2026-08-21T00:00:00.000Z",
  expiresAt: "2026-08-31T00:00:00.000Z",
  network: "SN_MAIN",
  allowPartialPayments: true,
  milestones: [{ id: "delivery", label: "Delivery", amount: "10" }],
};

const payment: InvoicePaymentRecord = {
  hash: "0xabc",
  amountBaseUnits: "2500000000000000000",
  milestoneId: "delivery",
  status: "confirmed",
  submittedAt: "2026-08-21T02:00:00.000Z",
  confirmedAt: "2026-08-21T02:01:00.000Z",
};

describe("selective receipts", () => {
  it("exports only the fields selected by the payer", () => {
    const receipt = createSelectiveReceipt(invoice, payment, {
      ...DEFAULT_RECEIPT_SELECTION,
      recipientAddress: false,
      description: false,
      referenceNumber: false,
    }, new Date("2026-08-21T03:00:00.000Z"));

    expect(receipt.disclosed).toMatchObject({
      merchantName: "Cipher Studio",
      amount: "2.5",
      tokenSymbol: "STRK",
      milestoneId: "delivery",
      transactionHash: "0xabc",
    });
    expect(receipt.disclosed).not.toHaveProperty("recipientAddress");
    expect(receipt.disclosed).not.toHaveProperty("description");
    expect(receipt.disclosed).not.toHaveProperty("referenceNumber");
  });

  it("supports a minimal receipt without transaction or commercial metadata", () => {
    const receipt = createSelectiveReceipt(invoice, payment, {
      merchantName: false,
      recipientAddress: false,
      amount: false,
      milestone: false,
      description: false,
      referenceNumber: false,
      transactionHash: false,
      timestamps: false,
    }, new Date("2026-08-21T03:00:00.000Z"));

    expect(receipt.disclosed).toEqual({});
    expect(receipt).toMatchObject({ invoiceId: "inv_receipt", network: "SN_MAIN", paymentStatus: "confirmed" });
    expect(serializeSelectiveReceipt(receipt)).not.toContain(invoice.recipientAddress);
    expect(serializeSelectiveReceipt(receipt)).not.toContain(payment.hash);
  });
});
