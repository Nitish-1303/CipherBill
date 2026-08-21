import { describe, expect, it } from "vitest";

import { createInvoice, paymentLink, selectiveReceipt } from "./invoices";

describe("local invoice metadata", () => {
  it("creates a non-sensitive invoice and shareable link", () => {
    const invoice = createInvoice({
      recipient: "0x1234",
      amount: "2.5",
      token: "STRK",
      description: "Design work",
      dueDate: "2030-01-01",
    });

    expect(invoice.id).toMatch(/^inv_/);
    expect(paymentLink(invoice, "https://shadowpay.example")).toContain(invoice.id);
    expect(selectiveReceipt({ ...invoice, status: "paid", transactionHash: "0xconfirmed" })).toEqual({
      invoiceId: invoice.id,
      status: "paid",
      amount: "2.5",
      token: "STRK",
      dueDate: "2030-01-01",
      transactionHash: "0xconfirmed",
    });
  });
});