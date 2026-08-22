import { describe, expect, it } from "vitest";

import {
  buildEphemeralSettlementActions,
  burnEphemeralAfterSettlement,
  claimEphemeralInvoice,
  createEphemeralInvoice,
  createEphemeralInvoiceState,
  createEphemeralPaymentLink,
  decodeEphemeralCapability,
  encodeEphemeralCapability,
  EPHEMERAL_INVOICE_POOL_ADDRESS,
  expireEphemeralInvoice,
  failEphemeralSubmission,
  getEphemeralSecurityModel,
  getEphemeralStatus,
  parseEphemeralEnvelope,
  readEphemeralState,
  recordEphemeralSubmission,
  serializeEphemeralEnvelope,
  verifyEphemeralState,
  writeEphemeralState,
  type EphemeralInvoiceBundle,
  type EphemeralInvoiceState,
} from "./ephemeral-engine";
import type { ShareableInvoice } from "./invoices";
import { STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";

const CREATED_AT = new Date("2026-08-22T09:00:00.000Z");
const OPENED_AT = new Date("2026-08-22T09:10:00.000Z");
const SUBMITTED_AT = new Date("2026-08-22T09:12:00.000Z");
const CONFIRMED_AT = new Date("2026-08-22T09:13:00.000Z");
const EXPIRES_AT = "2026-08-22T10:00:00.000Z";
const RECIPIENT = "0x0000000000000000000000000000000000000000000000000000000000001234";
const TX_HASH = "0xabc123";

const invoice: ShareableInvoice = {
  version: 2,
  invoiceId: "inv_ephemeral_secret_1042",
  merchantName: "Cipher Studio Private",
  recipientAddress: RECIPIENT,
  tokenAddress: STRK_TOKEN_ADDRESS,
  tokenSymbol: "STRK",
  tokenDecimals: 18,
  amount: "9007199254740993.000000000000000001",
  description: "Confidential single-use research engagement",
  referenceNumber: "SECRET-PO-1042",
  createdAt: CREATED_AT.toISOString(),
  expiresAt: EXPIRES_AT,
  network: "SN_MAIN",
  allowPartialPayments: false,
};

async function bundle(): Promise<EphemeralInvoiceBundle> {
  return createEphemeralInvoice(invoice, CREATED_AT, {
    randomBytes: (target) => target.fill(target.length === 32 ? 7 : 9),
  });
}

describe("ephemeral one-time invoices", () => {
  it("encrypts all invoice metadata and pins the verified STRK20 pool", async () => {
    const created = await bundle();
    const serialized = serializeEphemeralEnvelope(created.envelope);
    const rawCiphertext = new TextDecoder("latin1").decode(decodeBase64Url(created.envelope.ciphertext));

    expect(EPHEMERAL_INVOICE_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(created.envelope).toMatchObject({
      poolAddress: "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
      algorithm: "AES-GCM-256",
      expiresAt: EXPIRES_AT,
    });
    for (const secret of [invoice.invoiceId, invoice.merchantName, invoice.recipientAddress, invoice.amount, invoice.description, invoice.referenceNumber!]) {
      expect(serialized).not.toContain(secret);
      expect(rawCiphertext).not.toContain(secret);
    }
    expect(parseEphemeralEnvelope(serialized)).toEqual(created.envelope);
  });

  it("places the bearer key in the URL fragment, never its path or query", async () => {
    const created = await bundle();
    const capability = encodeEphemeralCapability(created);
    const link = createEphemeralPaymentLink("https://cipherbill.example/create?unsafe=1", created);
    const parsedUrl = new URL(link);

    expect(parsedUrl.pathname).toBe("/pay/ephemeral");
    expect(parsedUrl.search).toBe("");
    expect(parsedUrl.hash).toBe(`#${capability}`);
    expect(parsedUrl.pathname).not.toContain(created.viewingKey);
    expect(parsedUrl.search).not.toContain(created.viewingKey);
    expect(decodeEphemeralCapability(parsedUrl.hash.slice(1))).toEqual(created);
    expect(() => createEphemeralPaymentLink("http://cipherbill.example", created)).toThrow("HTTPS");
    expect(createEphemeralPaymentLink("http://localhost:3000", created)).toContain("http://localhost:3000/pay/ephemeral#");
  });

  it("permits exactly one claim against an intact local state registry", async () => {
    const created = await bundle();
    const sealed = createEphemeralInvoiceState(created.envelope, CREATED_AT);
    const claimed = await claimEphemeralInvoice(created.envelope, created.viewingKey, sealed, OPENED_AT);

    expect(claimed.session.invoice).toEqual(invoice);
    expect(claimed.state).toMatchObject({ status: "opened", openedAt: OPENED_AT.toISOString() });
    expect(verifyEphemeralState(created.envelope, claimed.state)).toBe(true);
    await expect(claimEphemeralInvoice(created.envelope, created.viewingKey, claimed.state, OPENED_AT)).rejects.toThrow("already claimed");
    expect(verifyEphemeralState(created.envelope, { ...claimed.state, status: "sealed" })).toBe(false);
  });

  it("builds one exact bigint-safe private transfer and burns after confirmation", async () => {
    const created = await bundle();
    const claimed = await claimEphemeralInvoice(created.envelope, created.viewingKey, createEphemeralInvoiceState(created.envelope, CREATED_AT), OPENED_AT);
    const actions = buildEphemeralSettlementActions(created.envelope, claimed.session, claimed.state, SUBMITTED_AT);
    const pending = recordEphemeralSubmission(created.envelope, claimed.session, claimed.state, TX_HASH, SUBMITTED_AT);
    const keyReference = claimed.session.viewingKey;
    const result = burnEphemeralAfterSettlement(created.envelope, claimed.session, pending, TX_HASH, CONFIRMED_AT);

    expect(actions).toEqual([{
      type: "transfer",
      token: STRK_TOKEN_ADDRESS,
      amount: "9007199254740993000000000000000001",
      recipient: RECIPIENT,
    }]);
    expect(pending).toMatchObject({ status: "settlement_pending", transactionHash: TX_HASH });
    expect(result.state).toMatchObject({ status: "burned", burnReason: "settlement", transactionHash: TX_HASH, destroyedAt: CONFIRMED_AT.toISOString() });
    expect(result.receipt.erasureAttestation).toContain("not physical erasure");
    expect(claimed.session).toMatchObject({ status: "destroyed", invoice: null });
    expect([...keyReference].every((byte) => byte === 0)).toBe(true);
    expect(() => buildEphemeralSettlementActions(created.envelope, claimed.session, result.state, CONFIRMED_AT)).toThrow(/opened|destroyed/);
  });

  it("allows an in-memory retry after a reverted settlement without accepting duplicates", async () => {
    const created = await bundle();
    const claimed = await claimEphemeralInvoice(created.envelope, created.viewingKey, createEphemeralInvoiceState(created.envelope, CREATED_AT), OPENED_AT);
    const pending = recordEphemeralSubmission(created.envelope, claimed.session, claimed.state, TX_HASH, SUBMITTED_AT);
    const reopened = failEphemeralSubmission(created.envelope, claimed.session, pending, TX_HASH, CONFIRMED_AT);

    expect(reopened).toMatchObject({ status: "opened", openedAt: OPENED_AT.toISOString() });
    expect(reopened).not.toHaveProperty("transactionHash");
    expect(buildEphemeralSettlementActions(created.envelope, claimed.session, reopened, CONFIRMED_AT)).toHaveLength(1);
    expect(() => failEphemeralSubmission(created.envelope, claimed.session, pending, "0x999", CONFIRMED_AT)).toThrow("does not match");
  });

  it("expires into an irreversible local terminal state and zeroizes an open session", async () => {
    const created = await bundle();
    const claimed = await claimEphemeralInvoice(created.envelope, created.viewingKey, createEphemeralInvoiceState(created.envelope, CREATED_AT), OPENED_AT);
    const expiredAt = new Date("2026-08-22T10:00:01.000Z");
    const result = expireEphemeralInvoice(created.envelope, claimed.state, claimed.session, expiredAt);

    expect(getEphemeralStatus(created.envelope, claimed.state, expiredAt)).toBe("expired");
    expect(result.state).toMatchObject({ status: "expired", burnReason: "expiration", destroyedAt: expiredAt.toISOString() });
    expect(result.receipt).toMatchObject({ reason: "expiration", transactionHash: undefined });
    expect(claimed.session.status).toBe("destroyed");
    expect(() => expireEphemeralInvoice(created.envelope, result.state, null, expiredAt)).toThrow("terminal");
  });

  it("rejects wrong keys, altered ciphertext, unsafe TTLs, and multi-payment policies", async () => {
    const created = await bundle();
    const sealed = createEphemeralInvoiceState(created.envelope, CREATED_AT);
    const wrongKey = encodeBase64Url(new Uint8Array(32).fill(8));
    const altered = { ...created.envelope, ciphertext: `${created.envelope.ciphertext[0] === "A" ? "B" : "A"}${created.envelope.ciphertext.slice(1)}` };

    await expect(claimEphemeralInvoice(created.envelope, wrongKey, sealed, OPENED_AT)).rejects.toThrow("does not match");
    await expect(claimEphemeralInvoice(altered, created.viewingKey, sealed, OPENED_AT)).rejects.toThrow("link commitment");
    await expect(createEphemeralInvoice({ ...invoice, allowPartialPayments: true }, CREATED_AT)).rejects.toThrow("exact settlement");
    await expect(createEphemeralInvoice({ ...invoice, milestones: [{ id: "only", label: "Only", amount: invoice.amount }] }, CREATED_AT)).rejects.toThrow("partial payments or milestones");
    await expect(createEphemeralInvoice({ ...invoice, expiresAt: new Date(CREATED_AT.getTime() + 40 * 24 * 60 * 60 * 1_000).toISOString() }, CREATED_AT)).rejects.toThrow("30 days");
  });

  it("persists tamper-evident state and refuses terminal overwrite", async () => {
    const created = await bundle();
    const storage = memoryStorage();
    const sealed = readEphemeralState(created.envelope, storage, CREATED_AT);
    const claimed = await claimEphemeralInvoice(created.envelope, created.viewingKey, sealed, OPENED_AT);
    const pending = recordEphemeralSubmission(created.envelope, claimed.session, claimed.state, TX_HASH, SUBMITTED_AT);
    const burned = burnEphemeralAfterSettlement(created.envelope, claimed.session, pending, TX_HASH, CONFIRMED_AT).state;

    expect(writeEphemeralState(created.envelope, burned, storage)).toBe(true);
    expect(readEphemeralState(created.envelope, storage, CONFIRMED_AT)).toEqual(burned);
    expect(() => writeEphemeralState(created.envelope, sealed, storage)).toThrow("cannot be overwritten");

    const raw = JSON.parse(storage.getItem("cipherbill.ephemeral-state.v1") ?? "{}") as Record<string, EphemeralInvoiceState>;
    raw[created.envelope.linkCommitment] = { ...burned, transactionHash: "0x999" };
    storage.setItem("cipherbill.ephemeral-state.v1", JSON.stringify(raw));
    expect(() => readEphemeralState(created.envelope, storage, CONFIRMED_AT)).toThrow("fails closed");
  });

  it("states the boundary between local destruction and global revocation", () => {
    const model = getEphemeralSecurityModel();
    expect(model.enforcedHere).toContain("Best-effort zeroization of the mutable in-memory viewing-key buffer");
    expect(model.cannotGuarantee).toContain("Global single use without an onchain or shared revocation registry");
    expect(model.hiddenInPool).toContain("amount");
    expect(model.publicOrObservable).toContain("transaction timing");
  });
});

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() { return data.size; },
    clear: () => data.clear(),
    getItem: (key) => data.get(key) ?? null,
    key: (index) => [...data.keys()][index] ?? null,
    removeItem: (key) => { data.delete(key); },
    setItem: (key, value) => { data.set(key, value); },
  };
}

function decodeBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
