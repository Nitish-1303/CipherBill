import { describe, expect, it } from "vitest";

import {
  createShareableBatchInvoice,
  encodeBatchPayload,
  decodeBatchPayload,
  deriveBatchStatus,
  createBatchLifecycle,
  type CreateBatchInput,
} from "./batch-payroll";

const batchInput: CreateBatchInput = {
  organizationName: "Cipher Corp",
  tokenAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  expiresAt: "2099-08-31T00:00:00.000Z",
  recipients: [
    {
      recipientAddress: "0x0000000000000000000000000000000000000000000000000000000000001111",
      amount: "10.5",
      name: "Alice",
      description: "August Payout",
    },
    {
      recipientAddress: "0x0000000000000000000000000000000000000000000000000000000000002222",
      amount: "20.25",
      name: "Bob",
      description: "Consulting Fee",
    },
  ],
};

describe("batch payroll dispersal", () => {
  it("computes total amount and validates individual payouts", () => {
    const invoice = createShareableBatchInvoice(batchInput);
    expect(invoice.totalAmount).toBe("30.75");
    expect(invoice.recipients).toHaveLength(2);
    expect(invoice.recipients[0].id).toBe("rec_1");
  });

  it("encodes and decodes the batch payload securely", async () => {
    const invoice = createShareableBatchInvoice(batchInput);
    const encoded = await encodeBatchPayload(invoice);
    const decoded = await decodeBatchPayload(encoded);

    expect(decoded.status).toBe("valid");
    if (decoded.status === "valid") {
      expect(decoded.invoice.batchId).toBe(invoice.batchId);
      expect(decoded.invoice.totalAmount).toBe("30.75");
    }
  });

  it("rejects invalid address, amount and expiration", () => {
    expect(() => {
      createShareableBatchInvoice({
        ...batchInput,
        expiresAt: "2020-01-01T00:00:00.000Z", // Past date
      });
    }).toThrow();

    expect(() => {
      createShareableBatchInvoice({
        ...batchInput,
        tokenAddress: "invalid-addr",
      });
    }).toThrow();

    expect(() => {
      createShareableBatchInvoice({
        ...batchInput,
        recipients: [
          {
            recipientAddress: "invalid-addr",
            amount: "10",
            name: "Alice",
            description: "August Payout",
          },
        ],
      });
    }).toThrow();
  });

  it("derives batch status correctly", () => {
    const invoice = createShareableBatchInvoice(batchInput);
    const lifecycle = createBatchLifecycle();

    expect(deriveBatchStatus(invoice, lifecycle)).toBe("batch_pending");

    lifecycle.payments.push({
      recipientId: "rec_1",
      hash: "0x123",
      status: "confirmed",
      submittedAt: new Date().toISOString(),
    });

    expect(deriveBatchStatus(invoice, lifecycle)).toBe("partially_distributed");

    lifecycle.payments.push({
      recipientId: "rec_2",
      hash: "0x456",
      status: "confirmed",
      submittedAt: new Date().toISOString(),
    });

    expect(deriveBatchStatus(invoice, lifecycle)).toBe("batch_settled");
  });
});
