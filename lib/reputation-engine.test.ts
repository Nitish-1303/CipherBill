import { describe, expect, it } from "vitest";

import {
  aggregatePrivateSettlements,
  createReputationProof,
  credentialFromSettlement,
  generateReputationAttestorKeypair,
  getReputationSecurityModel,
  parseReputationAttestation,
  readReputationAttestation,
  serializeReputationAttestation,
  verifyReputationOpening,
  verifyReputationProof,
  writeReputationAttestation,
  type PrivateSettlementCredential,
  type ReputationEntropy,
} from "./reputation-engine";

const issuedAt = new Date("2026-08-22T00:00:00.000Z");
const merchantAddress = "0x1234";
const authority = generateReputationAttestorKeypair({ privateKey: 123456789n });

const credentials: PrivateSettlementCredential[] = [
  settled("cred_01", "0x101", "2026-08-01T00:00:00.000Z", "2026-07-30T00:00:00.000Z"),
  settled("cred_02", "0x102", "2026-08-03T00:00:00.000Z", "2026-08-03T00:00:00.000Z"),
  settled("cred_03", "0x103", "2026-08-05T00:00:00.000Z", "2026-08-04T00:00:00.000Z"),
  settled("cred_04", "0x104", "2026-08-07T00:00:00.000Z", "2026-08-06T00:00:00.000Z"),
  settled("cred_05", "0x105", "2026-08-09T00:00:00.000Z", "2026-08-08T00:00:00.000Z"),
  settled("cred_06", "0x106", "2026-08-11T00:00:00.000Z", "2026-08-10T00:00:00.000Z"),
  settled("cred_07", "0x107", "2026-08-13T00:00:00.000Z", "2026-08-15T00:00:00.000Z"),
  disputed("cred_08", "0x108", "2026-08-17T00:00:00.000Z"),
];

const entropy: ReputationEntropy = {
  blindings: { total: 101n, successful: 102n, onTime: 103n, late: 104n, disputed: 105n, score: 106n },
  proofNonces: [201n, 202n, 203n, 204n],
  signatureNonce: 301n,
};

function bundle() {
  return createReputationProof({
    merchantAddress,
    credentials,
    attestorId: "cipherbill.test-attestor",
    attestorPrivateKey: authority.privateKey,
    validityDays: 30,
  }, issuedAt, entropy);
}

describe("zero-knowledge vendor reputation engine", () => {
  it("aggregates private settlement credentials into a deterministic score", () => {
    expect(aggregatePrivateSettlements(credentials, issuedAt)).toMatchObject({
      total: 8,
      successful: 7,
      onTime: 6,
      late: 1,
      disputed: 1,
      score: 629,
      tier: "established",
      historyRoot: expect.stringMatching(/^0x/),
    });
  });

  it("creates genuine Pedersen-Schnorr relation proofs and a signed attestation", () => {
    const created = bundle();
    const verification = verifyReputationProof(created.attestation, { trustedAttestor: authority.publicKey, now: issuedAt });
    expect(verification).toMatchObject({
      cryptographicallyValid: true,
      attestorTrusted: true,
      current: true,
      score: 629,
      tier: "established",
    });
    expect(created.attestation.proofSystem).toBe("pedersen-schnorr-linear-v1");
    expect(created.attestation.proof.scoreRelation.response).toMatch(/^0x/);
  });

  it("verifies the optional private opening without publishing it", () => {
    const created = bundle();
    expect(verifyReputationOpening(created)).toBe(true);
    const modified = structuredClone(created);
    modified.opening.blindings.onTime = "0x999";
    expect(verifyReputationOpening(modified)).toBe(false);
  });

  it("rejects modified scores, commitments, and signatures", () => {
    const scoreTamper = structuredClone(bundle().attestation);
    scoreTamper.score = 630;
    expect(verifyReputationProof(scoreTamper, { now: issuedAt }).cryptographicallyValid).toBe(false);

    const commitmentTamper = structuredClone(bundle().attestation);
    commitmentTamper.commitments.successful = commitmentTamper.commitments.total;
    expect(verifyReputationProof(commitmentTamper, { now: issuedAt }).cryptographicallyValid).toBe(false);

    const signatureTamper = structuredClone(bundle().attestation);
    signatureTamper.signature.response = "0x1";
    expect(verifyReputationProof(signatureTamper, { now: issuedAt }).cryptographicallyValid).toBe(false);
  });

  it("separates cryptographic validity from issuer trust and freshness", () => {
    const attestation = bundle().attestation;
    const untrusted = verifyReputationProof(attestation, { now: issuedAt });
    expect(untrusted).toMatchObject({ cryptographicallyValid: true, attestorTrusted: false, current: true });
    const expired = verifyReputationProof(attestation, { trustedAttestor: authority.publicKey, now: new Date("2026-10-01T00:00:00.000Z") });
    expect(expired).toMatchObject({ cryptographicallyValid: true, attestorTrusted: true, current: false });
  });

  it("serializes only public proof material, never credentials or private history", () => {
    const created = bundle();
    const serialized = serializeReputationAttestation(created.attestation);
    expect(parseReputationAttestation(serialized)).toEqual(created.attestation);
    expect(serialized).not.toContain("cred_01");
    expect(serialized).not.toContain(credentials[0].invoiceCommitment);
    expect(serialized).not.toContain("settledAt");
    expect(serialized).not.toContain("dueAt");
    expect(serialized).not.toContain("credentials");
  });

  it("rejects extension fields at every proof layer", () => {
    const withHiddenTopLevel = structuredClone(bundle().attestation) as typeof bundle extends () => { attestation: infer T } ? T & { credentials?: unknown[] } : never;
    withHiddenTopLevel.credentials = [];
    expect(() => parseReputationAttestation(JSON.stringify(withHiddenTopLevel))).toThrow(/unsupported/i);

    const withHiddenPoint = structuredClone(bundle().attestation) as typeof bundle extends () => { attestation: infer T } ? T : never;
    (withHiddenPoint.commitments.total as typeof withHiddenPoint.commitments.total & { amount?: string }).amount = "private";
    expect(() => parseReputationAttestation(JSON.stringify(withHiddenPoint))).toThrow(/unsupported/i);
  });

  it("persists only the public attestation and clears corrupt storage", () => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    };
    const attestation = bundle().attestation;
    expect(writeReputationAttestation(attestation, storage)).toBe(true);
    expect(readReputationAttestation(storage)).toEqual(attestation);
    expect([...values.values()][0]).not.toContain("cred_01");
    values.set("cipherbill.reputation.attestation.v1", "not-json");
    expect(readReputationAttestation(storage)).toBeNull();
    expect(values.size).toBe(0);
  });

  it("constructs credentials from commitments without accepting amounts or counterparties", () => {
    const credential = credentialFromSettlement({
      credentialId: "cred_helper",
      invoiceId: "inv_private_001",
      transactionHash: "0xabc",
      dueAt: "2026-08-20T00:00:00.000Z",
      settledAt: "2026-08-19T00:00:00.000Z",
      outcome: "settled",
    });
    expect(credential).not.toHaveProperty("amount");
    expect(credential).not.toHaveProperty("counterparty");
    expect(credential.invoiceCommitment).toMatch(/^0x/);
  });

  it("enforces credential bounds, uniqueness, and successful history", () => {
    expect(() => aggregatePrivateSettlements([credentials[0], credentials[0]], issuedAt)).toThrow(/unique/i);
    expect(() => aggregatePrivateSettlements([disputed("only_dispute", "0x999", "2026-08-01T00:00:00.000Z")], issuedAt)).toThrow(/successfully settled/i);
    expect(() => aggregatePrivateSettlements(Array.from({ length: 33 }, (_, index) => settled(`cred_${index}`, `0x${(index + 1).toString(16)}`, "2026-08-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z")), issuedAt)).toThrow(/1 to 32/i);
  });

  it("documents exactly what the ZK proof and attestor each guarantee", () => {
    const model = getReputationSecurityModel();
    expect(model.zeroKnowledgeProofs.join(" ")).toMatch(/hidden/i);
    expect(model.attestorGuarantees.join(" ")).toMatch(/bounds/i);
    expect(model.hidden.join(" ")).toMatch(/amount/i);
    expect(model.limitations.join(" ")).toMatch(/not the STRK20/i);
  });
});

function settled(id: string, hashValue: string, dueAt: string, settledAt: string): PrivateSettlementCredential {
  return {
    credentialId: id,
    invoiceCommitment: hashValue,
    settlementCommitment: `0x${(BigInt(hashValue) + 0x1000n).toString(16)}`,
    dueAt,
    settledAt,
    outcome: "settled",
  };
}

function disputed(id: string, hashValue: string, dueAt: string): PrivateSettlementCredential {
  return {
    credentialId: id,
    invoiceCommitment: hashValue,
    settlementCommitment: `0x${(BigInt(hashValue) + 0x1000n).toString(16)}`,
    dueAt,
    outcome: "disputed",
  };
}
