import { describe, expect, it } from "vitest";

import { STRK20_POOL_ADDRESS } from "./strk20/config";
import {
  buildDirectEscrowReleaseActions,
  buildEscrowHelperClaimActions,
  countValidEscrowApprovals,
  createEscrowApproval,
  createMultiPartyEscrow,
  getEscrowMilestoneStatus,
  MULTISIG_ESCROW_POOL_ADDRESS,
  parseEscrowShare,
  serializeEscrowShare,
  unlockEscrowMilestone,
  verifyEscrowApproval,
  verifyEscrowShare,
  type CreateMultiPartyEscrowInput,
  type EscrowApproval,
  type EscrowKeyShare,
  type MultiPartyEscrowBundle,
} from "./multisig-escrow";

const CREATED_AT = new Date("2026-08-22T09:00:00.000Z");
const UNLOCK_AT = "2026-08-23T09:00:00.000Z";
const RELEASED_AT = new Date("2026-08-23T09:00:01.000Z");
const RECIPIENT = "0x0000000000000000000000000000000000000000000000000000000000001234";
const HELPER = "0x0000000000000000000000000000000000000000000000000000000000004567";

const input: CreateMultiPartyEscrowInput = {
  invoiceId: "inv_secret_1042",
  organizationName: "Cipher Industrial",
  threshold: 2,
  participants: [
    { participantId: "guardian_buyer", displayAlias: "Buyer controller" },
    { participantId: "guardian_supplier", displayAlias: "Supplier controller" },
    { participantId: "guardian_auditor", displayAlias: "Independent auditor" },
  ],
  milestones: [{
    milestoneId: "delivery_acceptance",
    title: "Private equipment delivery",
    recipientAddress: RECIPIENT,
    amountBaseUnits: "10000000000000000000",
    unlockAt: UNLOCK_AT,
  }],
};

async function createFixture(): Promise<MultiPartyEscrowBundle> {
  return createMultiPartyEscrow(input, CREATED_AT, {
    secret: 123_456_789n,
    polynomialCoefficients: [987_654_321n],
    createId: () => "esc_enterprise_1042",
    randomBytes: (target) => target.fill(7),
  });
}

function approve(bundle: MultiPartyEscrowBundle, shareIndex: number, nonce: bigint): EscrowApproval {
  return createEscrowApproval(
    bundle.envelope,
    "delivery_acceptance",
    bundle.shares[shareIndex],
    new Date(`2026-08-22T1${shareIndex}:00:00.000Z`),
    { approvalNonce: nonce },
  );
}

describe("encrypted multi-party escrow", () => {
  it("creates a private public envelope and Feldman-verifiable bearer shares", async () => {
    const bundle = await createFixture();
    const serializedEnvelope = JSON.stringify(bundle.envelope);

    expect(MULTISIG_ESCROW_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(bundle.envelope).toMatchObject({
      poolAddress: "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
      threshold: 2,
      algorithm: "AES-GCM-256",
    });
    expect(serializedEnvelope).not.toContain(input.invoiceId);
    expect(serializedEnvelope).not.toContain(input.milestones[0].title);
    expect(serializedEnvelope).not.toContain(RECIPIENT);
    expect(serializedEnvelope).not.toContain(input.milestones[0].amountBaseUnits);
    expect(bundle.shares).toHaveLength(3);
    expect(bundle.shares.every((share) => verifyEscrowShare(bundle.envelope, share))).toBe(true);

    const restored = parseEscrowShare(serializeEscrowShare(bundle.shares[1]));
    expect(restored).toEqual(bundle.shares[1]);
  });

  it("rejects altered or cross-guardian key shares", async () => {
    const bundle = await createFixture();
    const alteredValue: EscrowKeyShare = { ...bundle.shares[0], shareValue: "0x123" };
    const alteredIdentity: EscrowKeyShare = { ...bundle.shares[0], participantId: "guardian_supplier" };

    expect(verifyEscrowShare(bundle.envelope, alteredValue)).toBe(false);
    expect(verifyEscrowShare(bundle.envelope, alteredIdentity)).toBe(false);
    expect(() => parseEscrowShare("not+base64")).toThrow("invalid");
  });

  it("uses non-replayable Schnorr approvals and counts each guardian once", async () => {
    const bundle = await createFixture();
    const buyerApproval = approve(bundle, 0, 111n);
    const supplierApproval = approve(bundle, 1, 222n);
    const alteredResponse = { ...buyerApproval, response: "0x1" };
    const replayedMilestone = { ...buyerApproval, milestoneId: "another_milestone" };

    expect(verifyEscrowApproval(bundle.envelope, buyerApproval)).toBe(true);
    expect(verifyEscrowApproval(bundle.envelope, alteredResponse)).toBe(false);
    expect(verifyEscrowApproval(bundle.envelope, replayedMilestone)).toBe(false);
    expect(countValidEscrowApprovals(bundle.envelope, "delivery_acceptance", [buyerApproval, buyerApproval])).toBe(1);
    expect(countValidEscrowApprovals(bundle.envelope, "delivery_acceptance", [buyerApproval, supplierApproval])).toBe(2);
  });

  it("requires both the timelock and a matching threshold of approvals and shares", async () => {
    const bundle = await createFixture();
    const approvals = [approve(bundle, 0, 111n), approve(bundle, 1, 222n)];

    expect(getEscrowMilestoneStatus(bundle.envelope, "delivery_acceptance", approvals, CREATED_AT)).toMatchObject({
      unlockedByTime: false,
      thresholdMet: true,
      releasable: false,
    });
    expect(getEscrowMilestoneStatus(bundle.envelope, "delivery_acceptance", approvals, RELEASED_AT)).toMatchObject({
      unlockedByTime: true,
      thresholdMet: true,
      releasable: true,
    });

    await expect(unlockEscrowMilestone(bundle.envelope, "delivery_acceptance", bundle.shares.slice(0, 2), approvals, {
      source: "local_clock",
      timestamp: CREATED_AT.toISOString(),
    })).rejects.toThrow("timelock");
    await expect(unlockEscrowMilestone(bundle.envelope, "delivery_acceptance", bundle.shares.slice(0, 1), approvals, {
      source: "local_clock",
      timestamp: RELEASED_AT.toISOString(),
    })).rejects.toThrow("shares");
    await expect(unlockEscrowMilestone(bundle.envelope, "delivery_acceptance", bundle.shares.slice(0, 2), approvals.slice(0, 1), {
      source: "local_clock",
      timestamp: RELEASED_AT.toISOString(),
    })).rejects.toThrow("approval threshold");
  });

  it("reconstructs the same encrypted release from any valid two-of-three quorum", async () => {
    const first = await createFixture();
    const approvals = [approve(first, 0, 111n), approve(first, 1, 222n), approve(first, 2, 333n)];
    const evidence = {
      source: "starknet_block" as const,
      timestamp: RELEASED_AT.toISOString(),
      chainId: "SN_MAIN" as const,
      blockNumber: 2_345_678,
      blockHash: "0xabc123",
    };
    const buyerSupplier = await unlockEscrowMilestone(first.envelope, "delivery_acceptance", [first.shares[0], first.shares[1]], approvals, evidence);
    const buyerAuditor = await unlockEscrowMilestone(first.envelope, "delivery_acceptance", [first.shares[0], first.shares[2]], approvals, evidence);

    expect(buyerSupplier.releaseSecret).toBe(buyerAuditor.releaseSecret);
    expect(buyerSupplier.payload).toEqual({
      version: 1,
      escrowId: "esc_enterprise_1042",
      invoiceId: input.invoiceId,
      milestoneId: "delivery_acceptance",
      title: input.milestones[0].title,
      recipientAddress: RECIPIENT,
      tokenAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
      amountBaseUnits: input.milestones[0].amountBaseUnits,
      unlockAt: UNLOCK_AT,
    });
  });

  it("detects ciphertext tampering before decryption", async () => {
    const bundle = await createFixture();
    const approvals = [approve(bundle, 0, 111n), approve(bundle, 1, 222n)];
    const alteredEnvelope = structuredClone(bundle.envelope);
    alteredEnvelope.milestones[0].ciphertext = `${alteredEnvelope.milestones[0].ciphertext.slice(0, -1)}A`;

    await expect(unlockEscrowMilestone(alteredEnvelope, "delivery_acceptance", bundle.shares.slice(0, 2), approvals, {
      source: "local_clock",
      timestamp: RELEASED_AT.toISOString(),
    })).rejects.toThrow("digest");
  });

  it("builds private transfer and audited helper claim action plans", async () => {
    const bundle = await createFixture();
    const approvals = [approve(bundle, 0, 111n), approve(bundle, 1, 222n)];
    const unlocked = await unlockEscrowMilestone(bundle.envelope, "delivery_acceptance", bundle.shares.slice(0, 2), approvals, {
      source: "local_clock",
      timestamp: RELEASED_AT.toISOString(),
    });
    const direct = buildDirectEscrowReleaseActions(unlocked);
    let encoderInput: unknown;
    const helper = buildEscrowHelperClaimActions(unlocked, {
      contractAddress: HELPER,
      encodeClaim: (claim) => {
        encoderInput = claim;
        return [claim.claimCommitment, claim.releaseSecret, claim.unlockAtSeconds, claim.openNoteId, claim.poolAddress];
      },
    });

    expect(direct).toEqual([{
      type: "transfer",
      token: bundle.envelope.tokenAddress,
      amount: input.milestones[0].amountBaseUnits,
      recipient: RECIPIENT,
    }]);
    expect(helper).toEqual([
      { type: "transfer", token: bundle.envelope.tokenAddress, amount: "OPEN", recipient: HELPER },
      { type: "invoke", contract: HELPER, calldata: expect.any(Array) },
    ]);
    expect(encoderInput).toMatchObject({ openNoteId: "${openNoteIds[0]}", poolAddress: "${poolAddress}" });
  });

  it("rejects unsafe threshold and timelock configurations", async () => {
    await expect(createMultiPartyEscrow({ ...input, threshold: 1 }, CREATED_AT)).rejects.toThrow("threshold");
    await expect(createMultiPartyEscrow({
      ...input,
      milestones: [{ ...input.milestones[0], unlockAt: CREATED_AT.toISOString() }],
    }, CREATED_AT)).rejects.toThrow("future");
  });
});
