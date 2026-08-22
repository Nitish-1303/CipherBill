import { describe, expect, it } from "vitest";

import { STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  buildPrivateDirectoryPaymentActions,
  createStealthBillingProfile,
  createStealthDirectory,
  decryptStealthDirectory,
  deriveDirectoryChannelTag,
  encryptStealthDirectory,
  generateDirectoryViewingKeypair,
  parseEncryptedStealthDirectory,
  parseStealthBillingProfile,
  removeDirectoryContact,
  resolveDirectoryAlias,
  resolvePrivateDirectoryPayment,
  searchDirectoryContacts,
  serializeEncryptedStealthDirectory,
  serializeStealthBillingProfile,
  STEALTH_DIRECTORY_POOL_ADDRESS,
  upsertDirectoryContact,
  verifyStealthBillingProfile,
  type EncryptedStealthDirectory,
  type StealthBillingProfile,
} from "./stealth-directory";

const CREATED_AT = new Date("2026-08-22T08:00:00.000Z");
const UPDATED_AT = new Date("2026-08-22T09:00:00.000Z");
const ACME_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000001234";
const ORBIT_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000005678";
const PASSPHRASE = "correct horse battery staple";

const acmeKeys = generateDirectoryViewingKeypair({ privateScalar: 123_456n });
const orbitKeys = generateDirectoryViewingKeypair({ privateScalar: 987_654n });

function acmeProfile(): StealthBillingProfile {
  return createStealthBillingProfile({
    alias: "acme.ops",
    merchantName: "Acme Confidential Logistics",
    stealthAddress: ACME_ADDRESS,
    directoryViewingPublicKey: acmeKeys.publicKey,
    tags: ["Logistics", "Priority"],
    note: "Net-30 procurement desk",
  }, CREATED_AT, { createId: () => "profile_acme" });
}

function orbitProfile(): StealthBillingProfile {
  return createStealthBillingProfile({
    alias: "orbit.design",
    merchantName: "Orbit Design Cooperative",
    stealthAddress: ORBIT_ADDRESS,
    directoryViewingPublicKey: orbitKeys.publicKey,
    tags: ["design", "contractor"],
    note: "Product design retainer",
  }, CREATED_AT, { createId: () => "profile_orbit" });
}

function directory() {
  return createStealthDirectory({
    directoryName: "Treasury payees",
    ownerAlias: "Cipher Industrial AP",
    contacts: [orbitProfile(), acmeProfile()],
  }, CREATED_AT, { createId: () => "directory_treasury" });
}

function deterministicBytes(target: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return target.fill(target.length === 16 ? 7 : 11);
}

function decodeBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

describe("stealth recipient directory", () => {
  it("creates committed billing profiles without retaining directory private keys", () => {
    const profile = acmeProfile();
    const encoded = serializeStealthBillingProfile(profile);

    expect(STEALTH_DIRECTORY_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(profile).toMatchObject({
      alias: "acme.ops",
      canonicalAlias: "acme.ops",
      stealthAddress: ACME_ADDRESS,
      poolAddress: "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
    });
    expect(profile).not.toHaveProperty("privateKey");
    expect(encoded).not.toContain(acmeKeys.privateKey);
    expect(parseStealthBillingProfile(encoded)).toEqual(profile);
    expect(verifyStealthBillingProfile({ ...profile, merchantName: "Impostor Merchant" })).toBe(false);
  });

  it("derives symmetric directory-only ECDH channel tags", () => {
    const left = deriveDirectoryChannelTag(acmeKeys.privateKey, orbitKeys.publicKey, "invoice-channel-1042");
    const right = deriveDirectoryChannelTag(orbitKeys.privateKey, acmeKeys.publicKey, "invoice-channel-1042");
    const anotherContext = deriveDirectoryChannelTag(orbitKeys.privateKey, acmeKeys.publicKey, "invoice-channel-1043");

    expect(left).toBe(right);
    expect(left).not.toBe(anotherContext);
    expect(acmeKeys.notice).toContain("Never substitute");
  });

  it("canonically orders contacts and resolves aliases without address leakage", () => {
    const book = directory();

    expect(book.contacts.map((contact) => contact.alias)).toEqual(["acme.ops", "orbit.design"]);
    expect(resolveDirectoryAlias(book, "  ACME.OPS ").stealthAddress).toBe(ACME_ADDRESS);
    expect(searchDirectoryContacts(book, "priority logistics").map((contact) => contact.alias)).toEqual(["acme.ops"]);
    expect(searchDirectoryContacts(book, "design retainer").map((contact) => contact.alias)).toEqual(["orbit.design"]);
    expect(() => resolveDirectoryAlias(book, "unknown.payee")).toThrow("not found");
  });

  it("upserts and removes contacts while recomputing the directory commitment", () => {
    const original = createStealthDirectory({ directoryName: "Payees", ownerAlias: "AP" }, CREATED_AT, { createId: () => "directory_empty" });
    const withAcme = upsertDirectoryContact(original, acmeProfile(), UPDATED_AT);
    const replacement = createStealthBillingProfile({
      ...acmeProfile(),
      merchantName: "Acme Logistics Group",
    }, UPDATED_AT, { createId: () => "profile_acme_v2" });
    const replaced = upsertDirectoryContact(withAcme, replacement, new Date("2026-08-22T10:00:00.000Z"));
    const emptied = removeDirectoryContact(replaced, replacement.profileId, new Date("2026-08-22T11:00:00.000Z"));

    expect(withAcme.contacts).toHaveLength(1);
    expect(withAcme.directoryCommitment).not.toBe(original.directoryCommitment);
    expect(replaced.contacts).toHaveLength(1);
    expect(replaced.contacts[0].merchantName).toBe("Acme Logistics Group");
    expect(emptied.contacts).toEqual([]);
    expect(emptied.directoryCommitment).not.toBe(replaced.directoryCommitment);
  });

  it("encrypts every alias, address, note, and public key with authenticated metadata", async () => {
    const book = directory();
    const envelope = await encryptStealthDirectory(book, PASSPHRASE, {
      randomBytes: deterministicBytes,
      kdfIterations: 100_000,
    });
    const serialized = serializeEncryptedStealthDirectory(envelope);
    const rawCiphertext = new TextDecoder("latin1").decode(decodeBase64Url(envelope.ciphertext));

    expect(envelope).toMatchObject({
      algorithm: "PBKDF2-SHA256/AES-GCM-256",
      contactCount: 2,
      poolAddress: STRK20_POOL_ADDRESS,
    });
    for (const secret of ["acme.ops", "Acme Confidential Logistics", ACME_ADDRESS, "Net-30 procurement desk", acmeKeys.publicKey.x]) {
      expect(serialized).not.toContain(secret);
      expect(rawCiphertext).not.toContain(secret);
    }
    expect(() => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(envelope.ciphertext)))).toThrow();
    expect(parseEncryptedStealthDirectory(serialized)).toEqual(envelope);
    await expect(decryptStealthDirectory(envelope, PASSPHRASE)).resolves.toEqual(book);
  });

  it("fails closed for a wrong passphrase or altered ciphertext and header", async () => {
    const book = directory();
    const envelope = await encryptStealthDirectory(book, PASSPHRASE, {
      randomBytes: deterministicBytes,
      kdfIterations: 100_000,
    });
    const alteredCiphertext: EncryptedStealthDirectory = {
      ...envelope,
      ciphertext: `${envelope.ciphertext[0] === "A" ? "B" : "A"}${envelope.ciphertext.slice(1)}`,
    };
    const alteredHeader: EncryptedStealthDirectory = { ...envelope, contactCount: 1 };

    await expect(decryptStealthDirectory(envelope, "incorrect passphrase value")).rejects.toThrow("could not be unlocked");
    await expect(decryptStealthDirectory(alteredCiphertext, PASSPHRASE)).rejects.toThrow("digest");
    await expect(decryptStealthDirectory(alteredHeader, PASSPHRASE)).rejects.toThrow("could not be unlocked");
  });

  it("resolves an alias to the native private STRK20 Wallet API transfer", () => {
    const book = directory();
    const resolution = resolvePrivateDirectoryPayment(book, "acme.ops", "25000000000000000000");

    expect(resolution.actions).toEqual([{
      type: "transfer",
      token: STRK_TOKEN_ADDRESS,
      amount: "25000000000000000000",
      recipient: ACME_ADDRESS,
    }]);
    expect(buildPrivateDirectoryPaymentActions(acmeProfile(), "1")).toEqual([{
      type: "transfer",
      token: STRK_TOKEN_ADDRESS,
      amount: "1",
      recipient: ACME_ADDRESS,
    }]);
    expect(resolution.privacyNotice).toContain("alias is resolved locally");
  });

  it("rejects malformed profiles, weak encryption, and unsafe payment amounts", async () => {
    const profile = acmeProfile();
    expect(() => createStealthBillingProfile({ ...profile, stealthAddress: "not-an-address" }, CREATED_AT)).toThrow();
    expect(() => createStealthDirectory({ directoryName: "Payees", ownerAlias: "AP", contacts: [profile, profile] }, CREATED_AT)).toThrow("IDs");
    expect(() => buildPrivateDirectoryPaymentActions(profile, "0")).toThrow("u128");
    expect(() => parseStealthBillingProfile("not+base64")).toThrow("invalid");
    await expect(encryptStealthDirectory(directory(), "short", { randomBytes: deterministicBytes, kdfIterations: 100_000 })).rejects.toThrow("12 to 1024");
  });
});
