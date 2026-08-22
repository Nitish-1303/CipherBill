import { describe, expect, it } from "vitest";

import {
  decodeInvoicePayload,
  encodeInvoicePayload,
  invoicePaymentUrl,
  MAX_ENCODED_INVOICE_LENGTH,
  readInvoices,
  type ShareableInvoice,
} from "./invoices";
import { decimalToBaseUnits } from "./strk20/validation";

const invoice: ShareableInvoice = {
  version: 2,
  invoiceId: "inv_test_001",
  merchantName: "Cipher Studio",
  recipientAddress: "0x1234",
  tokenAddress: "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  amount: "9007199254740993.000000000000000001",
  description: "Privacy consulting",
  referenceNumber: "PO-1042",
  createdAt: "2028-01-01T00:00:00.000Z",
  expiresAt: "2028-02-01T00:00:00.000Z",
  network: "SN_MAIN",
  allowPartialPayments: true,
  milestones: [
    { id: "discovery", label: "Discovery", amount: "4503599627370496.500000000000000000" },
    { id: "delivery", label: "Delivery", amount: "4503599627370496.500000000000000001" },
  ],
};

describe("shareable invoice payloads", () => {
  it("encodes deterministically and decodes a valid invoice", async () => {
    const first = await encodeInvoicePayload(invoice);
    const second = await encodeInvoicePayload(invoice);
    expect(first).toBe(second);

    const decoded = await decodeInvoicePayload(first, Date.parse("2028-01-15T00:00:00.000Z"));
    expect(decoded.status).toBe("valid");
    if (decoded.status === "valid") {
      expect(decoded.invoice.invoiceId).toBe(invoice.invoiceId);
      expect(decoded.invoice.recipientAddress).toMatch(/^0x0+1234$/);
    }
  });

  it("round-trips through a URL-safe path segment", async () => {
    const encoded = await encodeInvoicePayload(invoice);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(encoded).not.toMatch(/[+/=]/);
    const url = invoicePaymentUrl(encoded, "https://cipherbill.example/");
    expect(new URL(url).pathname).toBe(`/pay/${encoded}`);
  });

  it("rejects checksum corruption", async () => {
    const encoded = await encodeInvoicePayload(invoice);
    const corrupted = `${encoded[0] === "A" ? "B" : "A"}${encoded.slice(1)}`;
    await expect(decodeInvoicePayload(corrupted)).resolves.toMatchObject({ status: "invalid", code: "checksum" });
  });

  it("rejects unsupported versions and missing required fields", async () => {
    await expect(decodeInvoicePayload(await signRaw({ ...invoice, version: 3 }))).resolves.toMatchObject({ status: "invalid", code: "unsupported_version" });
    const missingMerchant: Partial<ShareableInvoice> = { ...invoice };
    delete missingMerchant.merchantName;
    await expect(decodeInvoicePayload(await signRaw(missingMerchant))).resolves.toMatchObject({ status: "invalid", code: "incomplete" });
  });

  it("keeps schema v1 payment links portable after the v2 upgrade", async () => {
    const legacy = { ...invoice, version: 1 } as Record<string, unknown>;
    delete legacy.allowPartialPayments;
    delete legacy.milestones;
    const decoded = await decodeInvoicePayload(await signRaw(legacy), Date.parse("2028-01-15T00:00:00.000Z"));
    expect(decoded.status).toBe("valid");
    if (decoded.status === "valid") {
      expect(decoded.invoice).toMatchObject({ version: 2, allowPartialPayments: false });
    }
  });

  it("rejects malformed and oversized payloads", async () => {
    await expect(decodeInvoicePayload("not-an-envelope")).resolves.toMatchObject({ status: "invalid", code: "malformed" });
    await expect(decodeInvoicePayload("x".repeat(MAX_ENCODED_INVOICE_LENGTH + 1))).resolves.toMatchObject({ status: "invalid", code: "oversized" });
  });

  it("returns an expired state without making the invoice payable", async () => {
    const encoded = await encodeInvoicePayload(invoice);
    await expect(decodeInvoicePayload(encoded, Date.parse("2028-03-01T00:00:00.000Z"))).resolves.toMatchObject({ status: "expired" });
  });

  it("rejects invalid addresses, unsafe decimals, and invalid amounts", async () => {
    await expect(decodeInvoicePayload(await signRaw({ ...invoice, recipientAddress: "not-an-address" }))).resolves.toMatchObject({ status: "invalid", code: "invalid_address" });
    await expect(decodeInvoicePayload(await signRaw({ ...invoice, tokenDecimals: 255 }))).resolves.toMatchObject({ status: "invalid", code: "invalid_decimals" });
    await expect(decodeInvoicePayload(await signRaw({ ...invoice, amount: "1.0000000000000000001" }))).resolves.toMatchObject({ status: "invalid", code: "invalid_amount" });
  });

  it("preserves bigint-safe amount conversion", () => {
    expect(decimalToBaseUnits(invoice.amount, invoice.tokenDecimals)).toBe("9007199254740993000000000000000001");
  });

  it("rejects secret-like and all unknown schema fields", async () => {
    const unsafe = { ...invoice, privateKey: "do-not-accept-this" };
    await expect(decodeInvoicePayload(await signRaw(unsafe))).resolves.toMatchObject({ status: "invalid", code: "unsafe_field" });
  });

  it("requires milestone totals to equal the invoice total", async () => {
    const invalid = { ...invoice, milestones: [{ id: "only", label: "Only", amount: "1" }] };
    await expect(decodeInvoicePayload(await signRaw(invalid))).resolves.toMatchObject({ status: "invalid", code: "invalid_amount" });
  });

  it("rejects too many milestones and secret-like nested fields", async () => {
    const tooMany = { ...invoice, milestones: Array.from({ length: 9 }, (_, index) => ({ id: `m${index}`, label: `Part ${index}`, amount: "1" })) };
    await expect(decodeInvoicePayload(await signRaw(tooMany))).resolves.toMatchObject({ status: "invalid", code: "incomplete" });
    const unsafe = { ...invoice, milestones: [{ id: "m1", label: "Seed phrase", amount: invoice.amount }] };
    await expect(decodeInvoicePayload(await signRaw(unsafe))).resolves.toMatchObject({ status: "invalid", code: "unsafe_field" });
  });

  it("round-trips a bounded early-rebate policy and rejects incompatible payment modes", async () => {
    const rebateInvoice = {
      ...invoice,
      allowPartialPayments: false,
      milestones: undefined,
      rebatePolicy: { version: 1 as const, maximumRebateBps: 750, minimumLeadTimeSeconds: 3_600, fullRebateLeadTimeSeconds: 604_800 },
    };
    const decoded = await decodeInvoicePayload(await encodeInvoicePayload(rebateInvoice), Date.parse("2028-01-15T00:00:00.000Z"));
    expect(decoded).toMatchObject({ status: "valid", invoice: { rebatePolicy: { maximumRebateBps: 750 } } });
    await expect(decodeInvoicePayload(await signRaw({ ...rebateInvoice, allowPartialPayments: true }))).resolves.toMatchObject({ status: "invalid", code: "incomplete" });
    await expect(decodeInvoicePayload(await signRaw({ ...rebateInvoice, rebatePolicy: { ...rebateInvoice.rebatePolicy, maximumRebateBps: 2_501 } }))).resolves.toMatchObject({ status: "invalid", code: "incomplete" });
    await expect(decodeInvoicePayload(await signRaw({ ...rebateInvoice, rebatePolicy: { ...rebateInvoice.rebatePolicy, privateKey: "nope" } }))).resolves.toMatchObject({ status: "invalid", code: "unsafe_field" });
  });

  it("handles corrupt local history safely", () => {
    expect(readInvoices({ getItem: () => "{broken" })).toEqual([]);
    expect(readInvoices({ getItem: () => JSON.stringify([{ invoice: null }]) })).toEqual([]);
  });

  it("migrates legacy local history with a safe active lifecycle", async () => {
    const legacy = { ...invoice, version: 1 } as Record<string, unknown>;
    delete legacy.allowPartialPayments;
    delete legacy.milestones;
    const encodedPayload = await signRaw(legacy);
    const stored = JSON.stringify([{ invoice: legacy, encodedPayload, savedAt: "2028-01-01T00:00:00.000Z" }]);
    const records = readInvoices({ getItem: (key) => key.endsWith(".v1") ? stored : null });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ invoice: { version: 2 }, lifecycle: { status: "active", payments: [] } });
  });
});

async function signRaw(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const data = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data)));
  let checksumBinary = "";
  for (const byte of digest.slice(0, 16)) checksumBinary += String.fromCharCode(byte);
  const checksum = btoa(checksumBinary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  return `${data}.${checksum}`;
}
