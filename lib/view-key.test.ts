import { describe, expect, it } from "vitest";

import type { InvoiceLifecycle } from "./invoice-lifecycle";
import type { ShareableInvoice } from "./invoices";
import { DEFAULT_RECEIPT_SELECTION, type ReceiptDisclosureSelection } from "./selective-receipts";
import { STRK20_POOL_ADDRESS } from "./strk20/config";
import {
  AUDIT_DISCLOSURE_VERSION,
  AUDIT_KEY_BYTES,
  auditDisclosureFileName,
  AuditDisclosureError,
  auditKeyCheckValue,
  buildAuditDisclosureBundle,
  computePayloadDigest,
  decodeAuditDisclosurePayload,
  decryptAuditDisclosure,
  encodeAuditDisclosurePayload,
  encryptAuditDisclosure,
  formatAuditKeyForTransfer,
  generateAuditDisclosureKey,
  MAX_ENCODED_DISCLOSURE_LENGTH,
  serializeEncryptedAuditDisclosure,
  type AuditDisclosureBundle,
  type EncryptedAuditDisclosure,
} from "./view-key";

const invoice: ShareableInvoice = {
  version: 2,
  invoiceId: "inv_audit_001",
  merchantName: "Cipher Studio",
  recipientAddress: "0x1234",
  tokenAddress: "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  amount: "9007199254740993.000000000000000001",
  description: "Privacy consulting retainer",
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

const lifecycle: InvoiceLifecycle = {
  status: "partially_paid",
  updatedAt: "2028-01-20T00:00:00.000Z",
  payments: [
    {
      hash: "0xaaa1",
      amountBaseUnits: "4503599627370496500000000000000000",
      milestoneId: "discovery",
      status: "confirmed",
      submittedAt: "2028-01-10T00:00:00.000Z",
      confirmedAt: "2028-01-10T00:04:00.000Z",
    },
    {
      hash: "0xbbb2",
      amountBaseUnits: "4503599627370496500000000000000001",
      milestoneId: "delivery",
      status: "submitted",
      submittedAt: "2028-01-19T00:00:00.000Z",
    },
    {
      hash: "0xccc3",
      amountBaseUnits: "1",
      status: "failed",
      submittedAt: "2028-01-18T00:00:00.000Z",
    },
  ],
};

const generatedAt = new Date("2028-01-20T12:00:00.000Z");
const everything: ReceiptDisclosureSelection = {
  merchantName: true,
  recipientAddress: true,
  amount: true,
  milestone: true,
  description: true,
  referenceNumber: true,
  transactionHash: true,
  timestamps: true,
};

/** Deterministic byte source so key and nonce generation are reproducible without mocking globals. */
function sequentialBytes(seed: number) {
  let counter = seed;
  return (target: Uint8Array<ArrayBuffer>) => {
    for (let index = 0; index < target.length; index += 1) {
      counter = (counter * 1103515245 + 12345) % 2147483648;
      target[index] = counter % 256;
    }
    return target;
  };
}

async function fixture(selection: ReceiptDisclosureSelection = everything) {
  const { key, checkValue } = await generateAuditDisclosureKey(sequentialBytes(7));
  const bundle = await buildAuditDisclosureBundle(invoice, lifecycle, selection, {
    generatedAt,
    encodedPayload: "encoded-invoice-link.checksum",
  });
  const envelope = await encryptAuditDisclosure(bundle, key, sequentialBytes(19));
  return { key, checkValue, bundle, envelope };
}

function decodeBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encodeBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Byte-for-byte view of raw bytes as characters, so a plaintext substring cannot hide behind base64. */
function asCharacters(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}

describe("audit disclosure view-keys", () => {
  it("round-trips a bundle through real AES-GCM encryption", async () => {
    const { key, bundle, envelope } = await fixture();

    expect(envelope.algorithm).toBe("AES-GCM-256");
    expect(envelope.version).toBe(AUDIT_DISCLOSURE_VERSION);
    expect(envelope.poolAddress).toBe(STRK20_POOL_ADDRESS);

    const decrypted = await decryptAuditDisclosure(envelope, key);
    expect(decrypted).toEqual(bundle);
    expect(decrypted.invoiceId).toBe("inv_audit_001");
  });

  it("generates a 256-bit key whose check value is reproducible from the key alone", async () => {
    const { key, checkValue } = await generateAuditDisclosureKey(sequentialBytes(7));
    const decodedLength = Math.floor((key.length * 3) / 4);
    expect(decodedLength).toBe(AUDIT_KEY_BYTES);
    await expect(auditKeyCheckValue(key)).resolves.toBe(checkValue);

    const other = await generateAuditDisclosureKey(sequentialBytes(8));
    expect(other.key).not.toBe(key);
    expect(other.checkValue).not.toBe(checkValue);
  });

  it("leaks no invoice data in the envelope itself", async () => {
    const { envelope } = await fixture();
    const serialized = serializeEncryptedAuditDisclosure(envelope);
    const secretish = ["inv_audit_001", "Cipher Studio", "PO-1042", "0xaaa1", "Privacy consulting", "voyager"];

    for (const needle of secretish) {
      expect(serialized).not.toContain(needle);
    }
    expect(Object.keys(envelope).sort()).toEqual(
      ["algorithm", "ciphertext", "iv", "keyCheckValue", "kind", "network", "notice", "poolAddress", "version"],
    );

    /*
     * Scan the DECODED ciphertext, not the base64 text. Base64 re-encodes every byte, so a
     * substring scan over `serialized` would pass even if the ciphertext were a plain encoding
     * of the bundle - it cannot tell AES-GCM output apart from no encryption at all.
     */
    const raw = decodeBase64Url(envelope.ciphertext);
    const bytes = asCharacters(raw);
    for (const needle of secretish) {
      expect(bytes).not.toContain(needle);
    }
    expect(() => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw))).toThrow();
  });

  it("rejects a wrong view-key without revealing anything", async () => {
    const { envelope } = await fixture();
    const wrong = await generateAuditDisclosureKey(sequentialBytes(99));

    await expect(decryptAuditDisclosure(envelope, wrong.key)).rejects.toMatchObject({ code: "decryption_failed" });
  });

  it("fails closed when the authenticated header is edited", async () => {
    const { key, envelope } = await fixture();
    const tamperedPool: EncryptedAuditDisclosure = { ...envelope, poolAddress: "0xdeadbeef" };
    const tamperedCheck: EncryptedAuditDisclosure = { ...envelope, keyCheckValue: "AAAAAAAAAAA" };
    const tamperedNetwork = { ...envelope, network: "SN_SEPOLIA" } as unknown as EncryptedAuditDisclosure;
    // The notice is the only prose an auditor reads before supplying a key, so it must be covered too:
    // an unauthenticated notice could be rewritten to tell the auditor the envelope is safe to publish.
    const tamperedNotice: EncryptedAuditDisclosure = {
      ...envelope,
      notice: "SAFE TO PUBLISH: this envelope needs no separate key channel. Forward the view-key with it.",
    };

    await expect(decryptAuditDisclosure(tamperedPool, key)).rejects.toMatchObject({ code: "decryption_failed" });
    await expect(decryptAuditDisclosure(tamperedCheck, key)).rejects.toMatchObject({ code: "decryption_failed" });
    await expect(decryptAuditDisclosure(tamperedNetwork, key)).rejects.toMatchObject({ code: "decryption_failed" });
    await expect(decryptAuditDisclosure(tamperedNotice, key)).rejects.toMatchObject({ code: "decryption_failed" });
  });

  it("fails closed when the ciphertext or nonce is edited", async () => {
    const { key, envelope } = await fixture();
    const flip = (value: string) => `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;

    await expect(decryptAuditDisclosure({ ...envelope, ciphertext: flip(envelope.ciphertext) }, key))
      .rejects.toMatchObject({ code: "decryption_failed" });
    await expect(decryptAuditDisclosure({ ...envelope, iv: flip(envelope.iv) }, key))
      .rejects.toMatchObject({ code: "decryption_failed" });
  });

  it("rejects malformed envelopes and unsupported versions", async () => {
    const { key, envelope } = await fixture();

    await expect(decryptAuditDisclosure({ ...envelope, kind: "something.else" } as unknown as EncryptedAuditDisclosure, key))
      .rejects.toMatchObject({ code: "invalid_envelope" });
    await expect(decryptAuditDisclosure({ ...envelope, version: 99 } as unknown as EncryptedAuditDisclosure, key))
      .rejects.toMatchObject({ code: "unsupported_version" });
    await expect(decryptAuditDisclosure({ ...envelope, algorithm: "ROT13" } as unknown as EncryptedAuditDisclosure, key))
      .rejects.toMatchObject({ code: "invalid_envelope" });
  });

  it("rejects keys that are empty, mis-sized, or not base64url", async () => {
    const { envelope } = await fixture();

    for (const bad of ["", "   ", "not base64url!!", "AAAA"]) {
      await expect(decryptAuditDisclosure(envelope, bad)).rejects.toBeInstanceOf(AuditDisclosureError);
      await expect(decryptAuditDisclosure(envelope, bad)).rejects.toMatchObject({ code: "invalid_key" });
    }
  });

  it("accepts a key pasted back in its human-readable grouped form", async () => {
    const { key, bundle, envelope } = await fixture();
    const grouped = formatAuditKeyForTransfer(key);

    expect(grouped).toContain(" ");
    await expect(decryptAuditDisclosure(envelope, grouped)).resolves.toEqual(bundle);
  });

  it("preserves bigint-exact amounts with no float drift", async () => {
    const { key, envelope } = await fixture();
    const decrypted = await decryptAuditDisclosure(envelope, key);

    expect(decrypted.totals.totalBaseUnits).toBe("9007199254740993000000000000000001");
    expect(decrypted.totals.total).toBe("9007199254740993.000000000000000001");
    expect(decrypted.totals.confirmedBaseUnits).toBe("4503599627370496500000000000000000");
    expect(decrypted.totals.pendingBaseUnits).toBe("4503599627370496500000000000000001");
    expect(decrypted.totals.remainingBaseUnits).toBe("4503599627370496500000000000000001");

    const delivery = decrypted.payments.find((payment) => payment.hash === "0xbbb2");
    expect(delivery?.amountBaseUnits).toBe("4503599627370496500000000000000001");
    expect(delivery?.amount).toBe("4503599627370496.500000000000000001");

    /*
     * The two milestone payments differ by exactly one base unit, and Number() collapses both onto
     * the same double. Keeping them distinct end to end is therefore only possible if no step -
     * accounting, encryption, JSON round-trip, formatting - ever routed the value through a float.
     */
    const discovery = decrypted.payments.find((payment) => payment.hash === "0xaaa1");
    expect(BigInt(delivery?.amountBaseUnits ?? "0") - BigInt(discovery?.amountBaseUnits ?? "0")).toBe(1n);
    expect(Number(delivery?.amountBaseUnits)).toBe(Number(discovery?.amountBaseUnits));
    expect(delivery?.amount).not.toBe(discovery?.amount);
  });

  it("discloses only the selected fields", async () => {
    const { key, envelope } = await fixture(DEFAULT_RECEIPT_SELECTION);
    const decrypted = await decryptAuditDisclosure(envelope, key);

    expect(decrypted.disclosed.merchantName).toBe("Cipher Studio");
    expect(decrypted.disclosed.recipientAddress).toBeUndefined();
    expect(decrypted.disclosed.description).toBeUndefined();
    expect(decrypted.disclosed.referenceNumber).toBeUndefined();
    expect(decrypted.disclosedFields).not.toContain("recipientAddress");
    expect(decrypted.disclosedFields).toContain("invoiceAmount");
  });

  it("scopes an export to one milestone and to confirmed payments only", async () => {
    const { key } = await generateAuditDisclosureKey(sequentialBytes(3));
    const bundle = await buildAuditDisclosureBundle(invoice, lifecycle, everything, {
      generatedAt,
      milestoneId: "discovery",
      confirmedOnly: true,
    });
    const decrypted = await decryptAuditDisclosure(await encryptAuditDisclosure(bundle, key, sequentialBytes(4)), key);

    expect(decrypted.payments).toHaveLength(1);
    expect(decrypted.payments[0]).toMatchObject({ hash: "0xaaa1", milestoneId: "discovery", milestoneLabel: "Discovery" });
    expect(decrypted.disclosed.milestoneLabel).toBe("Discovery");
    expect(decrypted.payments[0].explorerUrl).toContain("0xaaa1");
  });

  it("withholds settlement hashes when the merchant unchecks that field", async () => {
    const { key, envelope, bundle } = await fixture({ ...everything, transactionHash: false });
    const decrypted = await decryptAuditDisclosure(envelope, key);

    expect(decrypted.payments).toHaveLength(3);
    for (const payment of decrypted.payments) {
      expect(payment.hash).toBeUndefined();
      expect(payment.explorerUrl).toBeUndefined();
    }
    // The whole bundle, not just the payment records: no hash and no explorer link may survive anywhere.
    const serialized = JSON.stringify(decrypted);
    for (const needle of ["0xaaa1", "0xbbb2", "0xccc3", "voyager"]) {
      expect(serialized).not.toContain(needle);
    }
    expect(decrypted.disclosedFields).not.toContain("settlementHashes");

    // Unchecking hashes narrows the disclosure without emptying it - amounts and statuses still travel.
    expect(decrypted.payments[0]).toMatchObject({ status: "confirmed", milestoneId: "discovery" });
    expect(bundle.totals.confirmedBaseUnits).toBe("4503599627370496500000000000000000");
  });

  it("declares settlement hashes as a disclosed field only when they are included", async () => {
    const { bundle } = await fixture();
    const withheld = await buildAuditDisclosureBundle(invoice, lifecycle, { ...everything, transactionHash: false }, { generatedAt });

    expect(bundle.disclosedFields).toContain("settlementHashes");
    expect(bundle.payments.every((payment) => Boolean(payment.hash) && Boolean(payment.explorerUrl))).toBe(true);
    expect(withheld.disclosedFields).not.toContain("settlementHashes");
  });

  it("reports totals for the disclosed scope rather than for the whole invoice", async () => {
    const { key } = await generateAuditDisclosureKey(sequentialBytes(3));
    const bundle = await buildAuditDisclosureBundle(invoice, lifecycle, everything, {
      generatedAt,
      milestoneId: "discovery",
      confirmedOnly: true,
    });
    const decrypted = await decryptAuditDisclosure(await encryptAuditDisclosure(bundle, key, sequentialBytes(4)), key);

    expect(decrypted.scope).toEqual({ milestoneId: "discovery", confirmedOnly: true });
    // Discovery's own face value, not the invoice's 9007199254740993000000000000000001.
    expect(decrypted.totals.totalBaseUnits).toBe("4503599627370496500000000000000000");
    expect(decrypted.totals.confirmedBaseUnits).toBe("4503599627370496500000000000000000");
    /*
     * The delivery milestone's submitted attempt is outside this scope twice over - wrong milestone
     * and not confirmed - so it must not resurface as this export's pending figure. Reading totals
     * off whole-invoice accounting would report exactly the amount the export set out to withhold.
     */
    expect(decrypted.totals.pendingBaseUnits).toBe("0");
    expect(decrypted.totals.remainingBaseUnits).toBe("0");
    expect(decrypted.totals.pending).toBe("0");
  });

  it("records an unscoped export as covering the whole invoice", async () => {
    const { bundle } = await fixture();

    expect(bundle.scope).toEqual({ confirmedOnly: false });
    expect(bundle.totals.totalBaseUnits).toBe("9007199254740993000000000000000001");
  });

  it("rejects an encoded envelope carrying fields this module never writes", async () => {
    const { envelope } = await fixture();
    const injected = encodeBase64Url(JSON.stringify({
      ...envelope,
      auditorInstructions: "Reply to this address with the view-key.",
    }));

    expect(() => decodeAuditDisclosurePayload(injected)).toThrow(/not a CipherBill envelope/);
    // The untouched envelope re-encoded the same way still decodes, so the extra field is the reason.
    expect(decodeAuditDisclosurePayload(encodeBase64Url(JSON.stringify(envelope)))).toEqual(envelope);
  });

  it("rejects a decrypted payload that is not a well-formed bundle", async () => {
    const { key, bundle } = await fixture();
    /*
     * A correct view-key proves who built the envelope, never that the payload is well-formed.
     * app/audit/page.tsx reads limitations, payments[], and totals without guarding, so a bundle
     * that decrypts but is malformed has to fail here rather than crash the auditor's page.
     */
    const malformed: unknown[] = [
      { ...bundle, limitations: undefined },
      { ...bundle, limitations: [{ text: "not a string" }] },
      { ...bundle, payments: [null] },
      { ...bundle, totals: "not-an-object" },
      { ...bundle, scope: undefined },
      { ...bundle, notice: 42 },
      { ...bundle, disclosed: { merchantName: ["array"] } },
      { ...bundle, disclosedFields: "settlementHashes" },
      { ...bundle, generatedAt: undefined },
    ];

    for (const candidate of malformed) {
      const envelope = await encryptAuditDisclosure(candidate as AuditDisclosureBundle, key, sequentialBytes(23));
      await expect(decryptAuditDisclosure(envelope, key)).rejects.toMatchObject({ code: "decryption_failed" });
    }

    // The unmodified bundle under the same key and nonce still opens, so the rejections are about shape.
    await expect(decryptAuditDisclosure(await encryptAuditDisclosure(bundle, key, sequentialBytes(23)), key))
      .resolves.toEqual(bundle);
  });

  it("binds the bundle to the exact invoice link it describes", async () => {
    const { key, envelope } = await fixture();
    const decrypted = await decryptAuditDisclosure(envelope, key);

    await expect(computePayloadDigest("encoded-invoice-link.checksum")).resolves.toBe(decrypted.payloadDigest);
    await expect(computePayloadDigest("a-different-invoice-link.checksum")).resolves.not.toBe(decrypted.payloadDigest);

    const unbound = await buildAuditDisclosureBundle(invoice, lifecycle, everything, { generatedAt });
    expect(unbound.payloadDigest).toBeUndefined();
  });

  it("states its own limits truthfully in the bundle", async () => {
    const { bundle } = await fixture();
    const text = `${bundle.notice} ${bundle.limitations.join(" ")}`;

    expect(bundle.notice).toContain("NOT a STRK20 protocol viewing key");
    expect(bundle.notice).toContain("NOT part of the STRK20 auditor key escrow");
    expect(text).toContain("cannot decrypt STRK20 pool notes");
    expect(text).toContain("already public on Starknet");
    expect(text).toContain("not a zero-knowledge proof");
    expect(text).toContain("registered once per account and is immutable");
    expect(text).toContain("Totals cover only the disclosed scope");

    /*
     * STRK20 publishes only an unlinkable nullifier for in-pool movement (compliance.md's visibility
     * table), so telling an auditor to verify the disclosed figures on Starknet would promise a
     * corroboration path the protocol precludes. The copy must describe what a hash actually proves.
     */
    expect(text).toContain("unlinkable without");
    expect(bundle.notice).toContain("cannot derive the amount, the counterparties, or the");
    expect(text).not.toMatch(/verif\w* (?:every )?(?:disclosed )?hash\w* independently/i);
    expect(text).not.toMatch(/must be verified independently on Starknet/i);
  });

  it("round-trips a URL-safe encoded envelope", async () => {
    const { key, bundle, envelope } = await fixture();
    const encoded = encodeAuditDisclosurePayload(envelope);

    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(decodeAuditDisclosurePayload(encoded)).toEqual(envelope);
    await expect(decryptAuditDisclosure(decodeAuditDisclosurePayload(encoded), key)).resolves.toEqual(bundle);
  });

  it("rejects malformed and oversized encoded envelopes", () => {
    expect(() => decodeAuditDisclosurePayload("")).toThrow(AuditDisclosureError);
    expect(() => decodeAuditDisclosurePayload("not valid base64url!")).toThrow(AuditDisclosureError);
    expect(() => decodeAuditDisclosurePayload("AAAA")).toThrow(AuditDisclosureError);
    expect(() => decodeAuditDisclosurePayload("x".repeat(MAX_ENCODED_DISCLOSURE_LENGTH + 1)))
      .toThrow(/too large/);
  });

  it("names export files without colons so every filesystem accepts them", () => {
    const name = auditDisclosureFileName("inv_audit_001", generatedAt);
    expect(name).toBe("cipherbill-audit-inv_audit_001-2028-01-20T12-00-00-000Z.json");
    expect(name).not.toMatch(/[:]/);
  });
});
