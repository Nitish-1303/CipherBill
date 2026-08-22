import { describe, expect, it } from "vitest";

import {
  buildSubscriptionPaymentActions,
  createSubscriptionMembership,
  deriveSubscriptionStatus,
  generateSubscriptionIssuerKeypair,
  getSubscriptionCountdown,
  getSubscriptionSecurityModel,
  parseSubscriptionCredential,
  renewSubscriptionMembership,
  serializeSubscriptionCredential,
  SUBSCRIPTION_POOL_ADDRESS,
  SUBSCRIPTION_TIERS,
  verifySubscriptionCredential,
  verifySubscriptionOpening,
  verifySubscriptionRotation,
  type SubscriptionEntropy,
} from "./subscription-engine";

const activatedAt = new Date("2026-01-31T12:00:00.000Z");
const issuer = generateSubscriptionIssuerKeypair(123456789n);
const serviceRecipient = "0xabc";

const firstEntropy: SubscriptionEntropy = {
  membershipId: "member_abcdefghijklmnop",
  membershipSecret: 101n,
  serviceViewingKey: bytes(11),
  accessToken: bytes(12),
  paymentSalt: 102n,
  possessionNonce: 103n,
  issuerNonce: 104n,
};

const renewalEntropy: SubscriptionEntropy = {
  membershipId: "member_qrstuvwxyzABCDEF",
  membershipSecret: 201n,
  serviceViewingKey: bytes(21),
  accessToken: bytes(22),
  paymentSalt: 202n,
  possessionNonce: 203n,
  rotationNonce: 204n,
  issuerNonce: 205n,
};

function membership() {
  return createSubscriptionMembership({
    tier: "professional",
    serviceRecipient,
    paymentTransactionHash: "0x12345",
    issuerId: "cipherbill.test-issuer",
    issuerPrivateKey: issuer.privateKey,
  }, activatedAt, firstEntropy);
}

describe("anonymous subscription tier membership", () => {
  it("builds an exact private STRK renewal action without membership metadata", () => {
    const actions = buildSubscriptionPaymentActions("professional", serviceRecipient);
    expect(actions).toEqual([{
      type: "transfer",
      token: expect.stringMatching(/^0x0*4718/),
      amount: "12000000000000000000",
      recipient: expect.stringMatching(/^0x0+abc$/),
    }]);
    expect(JSON.stringify(actions)).not.toContain("professional");
    expect(SUBSCRIPTION_POOL_ADDRESS).toBe("0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a");
  });

  it("creates a signed zero-knowledge possession credential and valid private opening", () => {
    const created = membership();
    expect(verifySubscriptionOpening(created)).toBe(true);
    expect(verifySubscriptionCredential(created.credential, { trustedIssuer: issuer.publicKey, now: activatedAt })).toMatchObject({
      cryptographicallyValid: true,
      issuerTrusted: true,
      current: true,
      status: "active",
      tier: "professional",
    });
    expect(created.credential.periodEnd).toBe("2026-02-28T12:00:00.000Z");
  });

  it("serializes only the public credential, never bearer or payment secrets", () => {
    const created = membership();
    const serialized = serializeSubscriptionCredential(created.credential);
    expect(parseSubscriptionCredential(serialized)).toEqual(created.credential);
    expect(serialized).not.toContain(created.secrets.accessToken);
    expect(serialized).not.toContain(created.secrets.serviceViewingKey);
    expect(serialized).not.toContain(created.secrets.paymentTransactionHash);
    expect(serialized).not.toContain(created.secrets.membershipSecret);
  });

  it("derives active, renewal, grace, and expired states with a bounded countdown", () => {
    const credential = membership().credential;
    expect(deriveSubscriptionStatus(credential, new Date("2026-02-01T00:00:00.000Z"))).toBe("active");
    expect(deriveSubscriptionStatus(credential, new Date("2026-02-22T12:00:00.000Z"))).toBe("renewal_due");
    expect(deriveSubscriptionStatus(credential, new Date("2026-03-01T00:00:00.000Z"))).toBe("grace");
    expect(deriveSubscriptionStatus(credential, new Date("2026-03-07T12:00:00.000Z"))).toBe("expired");
    expect(getSubscriptionCountdown(credential, new Date("2026-02-28T11:59:00.000Z"))).toMatchObject({ status: "renewal_due", remainingSeconds: 60, renewalOpen: true });
  });

  it("rotates every service-scoped secret and proves continuity with the old secret", () => {
    const previous = membership();
    const renewed = renewSubscriptionMembership(previous, {
      paymentTransactionHash: "0x67890",
      issuerId: "cipherbill.test-issuer",
      issuerPrivateKey: issuer.privateKey,
    }, new Date("2026-02-24T12:00:00.000Z"), renewalEntropy);
    expect(renewed.credential.epoch).toBe(2);
    expect(renewed.credential.periodStart).toBe(previous.credential.periodEnd);
    expect(renewed.credential.previousCredentialCommitment).toBe(previous.credential.stateCommitment);
    expect(renewed.secrets.membershipSecret).not.toBe(previous.secrets.membershipSecret);
    expect(renewed.secrets.serviceViewingKey).not.toBe(previous.secrets.serviceViewingKey);
    expect(renewed.secrets.accessToken).not.toBe(previous.secrets.accessToken);
    expect(verifySubscriptionOpening(renewed)).toBe(true);
    expect(verifySubscriptionRotation(previous.credential, renewed.credential)).toBe(true);
  });

  it("supports immediate tier upgrades but prevents premature same-tier renewal", () => {
    const previous = membership();
    expect(() => renewSubscriptionMembership(previous, {
      paymentTransactionHash: "0x67890",
      issuerId: "cipherbill.test-issuer",
      issuerPrivateKey: issuer.privateKey,
    }, new Date("2026-02-01T12:00:00.000Z"), renewalEntropy)).toThrow(/opens/i);
    const upgraded = renewSubscriptionMembership(previous, {
      tier: "enterprise",
      paymentTransactionHash: "0x67890",
      issuerId: "cipherbill.test-issuer",
      issuerPrivateKey: issuer.privateKey,
    }, new Date("2026-02-01T12:00:00.000Z"), renewalEntropy);
    expect(upgraded.credential).toMatchObject({ tier: "enterprise", priceBaseUnits: "30000000000000000000", periodStart: "2026-02-01T12:00:00.000Z" });
  });

  it("rejects proof, issuer, opening, and rotation tampering", () => {
    const created = membership();
    const proofTamper = structuredClone(created.credential);
    proofTamper.possessionProof.response = "0x1";
    expect(verifySubscriptionCredential(proofTamper).cryptographicallyValid).toBe(false);
    const issuerTamper = structuredClone(created.credential);
    issuerTamper.issuerSignature.response = "0x2";
    expect(verifySubscriptionCredential(issuerTamper).cryptographicallyValid).toBe(false);
    const openingTamper = structuredClone(created);
    openingTamper.secrets.accessToken = "sub_tampered";
    expect(verifySubscriptionOpening(openingTamper)).toBe(false);
    const renewed = renewSubscriptionMembership(created, { paymentTransactionHash: "0x67890", issuerId: "cipherbill.test-issuer", issuerPrivateKey: issuer.privateKey }, new Date("2026-02-24T12:00:00.000Z"), renewalEntropy);
    renewed.credential.previousCredentialCommitment = "0x1";
    expect(verifySubscriptionRotation(created.credential, renewed.credential)).toBe(false);
  });

  it("separates issuer trust from cryptographic validity", () => {
    const credential = membership().credential;
    expect(verifySubscriptionCredential(credential, { now: activatedAt })).toMatchObject({ cryptographicallyValid: true, issuerTrusted: false });
    const otherIssuer = generateSubscriptionIssuerKeypair(999n);
    expect(verifySubscriptionCredential(credential, { trustedIssuer: otherIssuer.publicKey, now: activatedAt })).toMatchObject({ cryptographicallyValid: true, issuerTrusted: false });
  });

  it("documents immutable pool viewing keys and honest enforcement limits", () => {
    const model = getSubscriptionSecurityModel();
    expect(model.rotated.join(" ")).toMatch(/service.*viewing/i);
    expect(model.hidden.join(" ")).toMatch(/STRK20.*viewing key/i);
    expect(model.limitations.join(" ")).toMatch(/immutable/i);
    expect(model.issuerGuarantees.join(" ")).toMatch(/settlement/i);
    expect(SUBSCRIPTION_TIERS.enterprise.features).toContain("Issuer allow-listing");
  });
});

function bytes(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (seed + index) % 256);
}
