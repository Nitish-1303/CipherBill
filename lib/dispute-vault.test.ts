import { describe, expect, it } from "vitest";

import { STRK20_POOL_ADDRESS } from "./strk20/config";
import {
  buildDirectDisputeReleaseActions,
  buildDisputeHelperReleaseActions,
  commitArbitrationVote,
  createDisputeVault,
  decryptDisputeEvidence,
  DISPUTE_VAULT_POOL_ADDRESS,
  encryptDisputeEvidence,
  generateArbitratorKeypair,
  parseEncryptedEvidence,
  resolveDisputeVault,
  revealArbitrationVote,
  serializeEncryptedEvidence,
  verifyDisputeResolution,
  verifyVoteCommitment,
  verifyVoteReveal,
  type ArbitrationChoice,
  type CreateDisputeVaultInput,
  type DisputeVault,
  type VoteCommitmentBundle,
  type VoteReveal,
} from "./dispute-vault";

const CREATED_AT = new Date("2026-08-22T09:00:00.000Z");
const COMMIT_AT = new Date("2026-08-22T09:30:00.000Z");
const COMMIT_DEADLINE = "2026-08-22T10:00:00.000Z";
const REVEAL_AT = new Date("2026-08-22T10:30:00.000Z");
const REVEAL_DEADLINE = "2026-08-22T11:00:00.000Z";
const RESOLVE_AT = new Date("2026-08-22T11:00:01.000Z");
const TOKEN = "0x0000000000000000000000000000000000000000000000000000000000001111";
const CLAIMANT = "0x0000000000000000000000000000000000000000000000000000000000002222";
const RESPONDENT = "0x0000000000000000000000000000000000000000000000000000000000003333";
const TREASURY = "0x0000000000000000000000000000000000000000000000000000000000004444";
const HELPER = "0x0000000000000000000000000000000000000000000000000000000000005555";
const ARBITRATOR_ADDRESSES = [
  "0x0000000000000000000000000000000000000000000000000000000000006001",
  "0x0000000000000000000000000000000000000000000000000000000000006002",
  "0x0000000000000000000000000000000000000000000000000000000000006003",
];

const keys = [11n, 22n, 33n].map((privateKey) => generateArbitratorKeypair({ privateKey }));

function input(): CreateDisputeVaultInput {
  return {
    invoiceId: "invoice_secret_1042",
    tokenAddress: TOKEN,
    invoicePrincipalBaseUnits: "1000",
    claimant: { displayAlias: "Private supplier", payoutAddress: CLAIMANT, collateralBaseUnits: "200" },
    respondent: { displayAlias: "Private buyer", payoutAddress: RESPONDENT, collateralBaseUnits: "300" },
    arbitrators: keys.map((key, index) => ({
      arbitratorId: `arb_${index + 1}`,
      displayAlias: `Panel member ${index + 1}`,
      payoutAddress: ARBITRATOR_ADDRESSES[index],
      bondBaseUnits: "100",
      votingPublicKey: key.publicKey,
    })),
    quorum: 2,
    commitDeadline: COMMIT_DEADLINE,
    revealDeadline: REVEAL_DEADLINE,
    evidenceCommitment: "0x123456789",
    treasuryAddress: TREASURY,
    loserCollateralSlashBps: 2_500,
    nonRevealBondSlashBps: 10_000,
  };
}

function vault(overrides: Partial<CreateDisputeVaultInput> = {}): DisputeVault {
  return createDisputeVault({ ...input(), ...overrides }, CREATED_AT, { createId: () => "dsv_enterprise_1042" });
}

function commit(caseVault: DisputeVault, index: number, choice: ArbitrationChoice, salt = 100n + BigInt(index)): VoteCommitmentBundle {
  return commitArbitrationVote(caseVault, `arb_${index + 1}`, choice, keys[index].privateKey, COMMIT_AT, {
    voteSalt: salt,
    signatureNonce: 500n + BigInt(index),
  });
}

function reveal(caseVault: DisputeVault, bundle: VoteCommitmentBundle): VoteReveal {
  return revealArbitrationVote(caseVault, bundle.commitment, bundle.opening, REVEAL_AT);
}

describe("anonymous invoice arbitration and slashing vault", () => {
  it("binds every stake and deadline to the configured STRK20 pool", () => {
    const caseVault = vault();

    expect(DISPUTE_VAULT_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(caseVault).toMatchObject({
      poolAddress: "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
      totalVaultBaseUnits: "1800",
      quorum: 2,
      evidenceCommitment: "0x123456789",
    });
    expect(caseVault.vaultCommitment).toMatch(/^0x[0-9a-f]+$/);
    expect(() => createDisputeVault({ ...input(), claimant: { ...input().claimant, collateralBaseUnits: "0" } }, CREATED_AT)).toThrow("u128");
  });

  it("encrypts evidence locally without publishing invoice or evidence metadata", async () => {
    const payload = {
      disputeReference: "invoice_secret_1042",
      submittedBy: "claimant" as const,
      statement: "Signed delivery record and private counter-party correspondence.",
      attachments: [{ name: "private-delivery.pdf", mediaType: "application/pdf", size: 4200, digest: `sha256:${"a".repeat(64)}` }],
      submittedAt: CREATED_AT.toISOString(),
    };
    const bundle = await encryptDisputeEvidence(payload, { randomBytes: (target) => target.fill(target.length === 32 ? 7 : 9) });
    const serialized = serializeEncryptedEvidence(bundle.envelope);
    const ciphertextBytes = decodeBase64Url(bundle.envelope.ciphertext);
    const rawCiphertext = new TextDecoder("latin1").decode(ciphertextBytes);

    expect(Object.keys(bundle.envelope).sort()).toEqual(["algorithm", "ciphertext", "ciphertextDigest", "evidenceCommitment", "iv", "kind", "network", "notice", "poolAddress", "version"]);
    for (const secret of [payload.disputeReference, payload.statement, payload.attachments[0].name]) {
      expect(serialized).not.toContain(secret);
      expect(rawCiphertext).not.toContain(secret);
    }
    expect(parseEncryptedEvidence(serialized)).toEqual(bundle.envelope);
    await expect(decryptDisputeEvidence(bundle.envelope, bundle.accessKey)).resolves.toEqual(payload);

    const altered = { ...bundle.envelope, ciphertext: `${bundle.envelope.ciphertext[0] === "A" ? "B" : "A"}${bundle.envelope.ciphertext.slice(1)}` };
    await expect(decryptDisputeEvidence(altered, bundle.accessKey)).rejects.toThrow(/digest|commitment/);
    await expect(decryptDisputeEvidence(bundle.envelope, encodeBase64Url(new Uint8Array(32).fill(8)))).rejects.toThrow("decryption failed");
  });

  it("creates hiding, authenticated commitments and rejects forged or early openings", () => {
    const caseVault = vault();
    const first = commit(caseVault, 0, "claimant", 101n);
    const saltedAgain = commit(caseVault, 0, "claimant", 999n);
    const publicRecord = JSON.stringify(first.commitment);

    expect(first.commitment.commitment).not.toBe(saltedAgain.commitment.commitment);
    expect(publicRecord).not.toContain("claimant");
    expect(publicRecord).not.toContain(first.opening.salt);
    expect(verifyVoteCommitment(caseVault, first.commitment)).toBe(true);
    expect(verifyVoteCommitment(caseVault, { ...first.commitment, authorization: { ...first.commitment.authorization, response: "0x1" } })).toBe(false);
    expect(() => commitArbitrationVote(caseVault, "arb_1", "claimant", keys[1].privateKey, COMMIT_AT)).toThrow("does not match");
    expect(() => revealArbitrationVote(caseVault, first.commitment, first.opening, COMMIT_AT)).toThrow("not active");

    const opened = reveal(caseVault, first);
    expect(verifyVoteReveal(caseVault, first.commitment, opened)).toBe(true);
    expect(verifyVoteReveal(caseVault, first.commitment, { ...opened, choice: "respondent" })).toBe(false);
  });

  it("resolves a quorum, slashes the losing collateral, and rewards valid revealers exactly", () => {
    const caseVault = vault();
    const votes = [commit(caseVault, 0, "claimant"), commit(caseVault, 1, "claimant"), commit(caseVault, 2, "respondent")];
    const reveals = votes.slice(0, 2).map((bundle) => reveal(caseVault, bundle));
    const resolution = resolveDisputeVault(caseVault, votes.map((item) => item.commitment), reveals, RESOLVE_AT);

    expect(resolution).toMatchObject({ outcome: "claimant", validRevealCount: 2, tallies: { claimant: 2, respondent: 0, split: 0 }, totalVaultBaseUnits: "1800" });
    expect(resolution.slashingEvents).toEqual(expect.arrayContaining([
      { source: "respondent_collateral", subjectId: "respondent", amountBaseUnits: "75", reason: "losing_party" },
      { source: "arbitrator_bond", subjectId: "arb_3", amountBaseUnits: "100", reason: "missing_or_invalid_reveal" },
    ]));
    expect(sumAllocations(resolution.allocations)).toBe(1800n);
    expect(sumFor(resolution.allocations, CLAIMANT)).toBe(1275n);
    expect(sumFor(resolution.allocations, RESPONDENT)).toBe(225n);
    expect(sumFor(resolution.allocations, ARBITRATOR_ADDRESSES[0])).toBe(150n);
    expect(sumFor(resolution.allocations, ARBITRATOR_ADDRESSES[1])).toBe(150n);
    expect(sumFor(resolution.allocations, ARBITRATOR_ADDRESSES[2])).toBe(0n);
    expect(verifyDisputeResolution(caseVault, resolution, votes.map((item) => item.commitment), reveals)).toBe(true);
    expect(verifyDisputeResolution(caseVault, { ...resolution, outcome: "respondent" }, votes.map((item) => item.commitment), reveals)).toBe(false);
  });

  it("never slashes an honest minority voter and handles split and no-quorum outcomes", () => {
    const caseVault = vault({ quorum: 3 });
    const majority = [commit(caseVault, 0, "respondent"), commit(caseVault, 1, "respondent"), commit(caseVault, 2, "claimant")];
    const allReveals = majority.map((bundle) => reveal(caseVault, bundle));
    const resolved = resolveDisputeVault(caseVault, majority.map((item) => item.commitment), allReveals, RESOLVE_AT);

    expect(resolved.outcome).toBe("respondent");
    expect(resolved.slashingEvents.filter((event) => event.source === "arbitrator_bond")).toHaveLength(0);
    expect(sumFor(resolved.allocations, ARBITRATOR_ADDRESSES[2])).toBe(100n);

    const splitVotes = [commit(caseVault, 0, "claimant"), commit(caseVault, 1, "respondent"), commit(caseVault, 2, "split")];
    const split = resolveDisputeVault(caseVault, splitVotes.map((item) => item.commitment), splitVotes.map((item) => reveal(caseVault, item)), RESOLVE_AT);
    expect(split.outcome).toBe("split");
    expect(sumAllocations(split.allocations)).toBe(1800n);

    const noQuorum = resolveDisputeVault(caseVault, [], [], RESOLVE_AT);
    expect(noQuorum.outcome).toBe("no_quorum");
    expect(sumFor(noQuorum.allocations, TREASURY)).toBe(300n);
    expect(sumAllocations(noQuorum.allocations)).toBe(1800n);
  });

  it("rejects duplicate ballots and resolution before the timelock", () => {
    const caseVault = vault();
    const vote = commit(caseVault, 0, "claimant");
    const opened = reveal(caseVault, vote);

    expect(() => resolveDisputeVault(caseVault, [vote.commitment], [opened], REVEAL_AT)).toThrow("not closed");
    expect(() => resolveDisputeVault(caseVault, [vote.commitment, vote.commitment], [opened], RESOLVE_AT)).toThrow("Duplicate vote commitments");
    expect(() => resolveDisputeVault(caseVault, [vote.commitment], [opened, opened], RESOLVE_AT)).toThrow("Duplicate vote reveals");
  });

  it("builds metadata-minimal direct transfers and exact audited-helper placeholders", () => {
    const caseVault = vault();
    const votes = [commit(caseVault, 0, "claimant"), commit(caseVault, 1, "claimant")];
    const reveals = votes.map((item) => reveal(caseVault, item));
    const resolution = resolveDisputeVault(caseVault, votes.map((item) => item.commitment), reveals, RESOLVE_AT);
    const direct = buildDirectDisputeReleaseActions(caseVault, resolution);
    let encoderInput: Parameters<Parameters<typeof buildDisputeHelperReleaseActions>[2]["encodeResolution"]>[0] | undefined;
    const helper = buildDisputeHelperReleaseActions(caseVault, resolution, {
      contractAddress: HELPER,
      encodeResolution: (details) => {
        encoderInput = details;
        return [details.vaultCommitment, details.resolutionCommitment, ...details.allocations.flatMap((item) => [item.amountBaseUnits, item.openNoteId]), details.poolAddress];
      },
    });

    expect(direct).toHaveLength(resolution.allocations.length);
    expect(direct.every((action) => action.type === "transfer" && action.token === TOKEN && action.amount !== "OPEN")).toBe(true);
    expect(JSON.stringify(direct)).not.toContain(input().invoiceId);
    expect(JSON.stringify(direct)).not.toContain("evidence");
    expect(helper).toHaveLength(resolution.allocations.length + 1);
    expect(helper.slice(0, -1).every((action) => action.type === "transfer" && action.amount === "OPEN" && action.recipient === HELPER)).toBe(true);
    expect(encoderInput?.poolAddress).toBe("${poolAddress}");
    expect(encoderInput?.allocations.map((item) => item.openNoteId)).toEqual(resolution.allocations.map((_, index) => `\${openNoteIds[${index}]}`));
  });
});

function decodeBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function sumAllocations(allocations: Array<{ amountBaseUnits: string }>): bigint {
  return allocations.reduce((sum, item) => sum + BigInt(item.amountBaseUnits), 0n);
}

function sumFor(allocations: Array<{ recipientAddress: string; amountBaseUnits: string }>, address: string): bigint {
  return allocations.filter((item) => item.recipientAddress === address).reduce((sum, item) => sum + BigInt(item.amountBaseUnits), 0n);
}
