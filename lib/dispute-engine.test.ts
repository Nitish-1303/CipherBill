import { describe, expect, it } from "vitest";

import {
  buildDisputeCaseDigest,
  buildDisputeOutcomeAttestation,
  buildEvidenceDigest,
  buildResolutionActions,
  createDisputeCase,
  createDisputeResolution,
  createEvidence,
  DISPUTE_POOL_ADDRESS,
  formatDisputeBaseUnits,
  getDisputeVisibilityModel,
  openDisputeCase,
  openEvidence,
  parseDisputeCase,
  parseDisputeCaseDigest,
  parseDisputeOutcome,
  parseDisputeResolution,
  parseEvidenceBundle,
  parseEvidenceDigest,
  serializeDisputeCase,
  serializeDisputeCaseDigest,
  serializeDisputeOutcome,
  serializeDisputeResolution,
  serializeEvidenceBundle,
  serializeEvidenceDigest,
  summarizeDisputeTrust,
  verifyDisputeCase,
  verifyDisputeCaseDisclosure,
  verifyDisputeOutcome,
  verifyDisputeResolution,
  verifyEvidence,
  verifyEvidenceDisclosure,
  type CreateDisputeCaseInput,
  type CreateDisputeResolutionInput,
  type CreateEvidenceInput,
  type DisputeEntropy,
} from "./dispute-engine";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const NOW = new Date("2026-08-22T08:00:00.000Z");
const RESPOND_BY = "2026-09-21T08:00:00.000Z"; // 30 days out, inside the 90-day cap
const USDC = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const BUYER = "0x0712345678901234567890123456789012345678901234567890123456789012";
const VENDOR = "0x0698765432109876543210987654321098765432109876543210987654321098";
const ARBITER = "0x0333333333333333333333333333333333333333333333333333333333333333";

/** Deterministic salts and ids, so every commitment in this file is reproducible. */
function entropy(seed: number): DisputeEntropy {
  return {
    createId: (kind) => `${kind === "case" ? "case" : kind === "evidence" ? "evid" : "res"}_test_${seed}`,
    randomBytes: (target) => {
      for (let index = 0; index < target.length; index += 1) target[index] = ((index + seed) % 251) + 1;
      return target;
    },
  };
}

const CASE_INPUT: CreateDisputeCaseInput = {
  invoiceId: "inv_dispute_001",
  asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
  escrowValue: "1000",
  collateralValue: "200",
  buyerRecipient: BUYER,
  vendorRecipient: VENDOR,
  arbiterRecipient: ARBITER,
  arbiterLabel: "Neutral Arbiter",
  claimSummary: "Delivered goods did not match the agreed specification.",
  respondBy: RESPOND_BY,
  memo: "batch 7",
};

const RESOLUTION_INPUT: CreateDisputeResolutionInput = {
  faultAssessment: "vendor_at_fault",
  buyerRefundBps: 4000,
  arbiterFeeBps: 500,
  penaltyBps: 2500,
  resolvedBy: "Neutral Arbiter",
  note: "Vendor shipped the wrong grade.",
};

function makeCase(overrides: Partial<CreateDisputeCaseInput> = {}, seed = 1) {
  return createDisputeCase({ ...CASE_INPUT, ...overrides }, NOW, entropy(seed));
}

function makeResolution(overrides: Partial<CreateDisputeResolutionInput> = {}, caseOverrides: Partial<CreateDisputeCaseInput> = {}, seed = 1) {
  const disputeCase = makeCase(caseOverrides, seed);
  const resolution = createDisputeResolution(disputeCase, { ...RESOLUTION_INPUT, ...overrides }, NOW, entropy(seed));
  return { disputeCase, resolution };
}

function makeEvidence(overrides: Partial<CreateEvidenceInput> = {}, seed = 1) {
  const disputeCase = makeCase({}, seed);
  const input: CreateEvidenceInput = {
    caseCommitment: disputeCase.caseCommitment,
    submittedBy: "buyer",
    items: ["ipfs://bafyEvidencePhoto", "sha256:9f2c...delivery-note"],
    note: "photos and the signed delivery note",
    ...overrides,
  };
  return { disputeCase, evidence: createEvidence(input, NOW, entropy(seed)) };
}

describe("createDisputeCase", () => {
  it("records the pool as provenance and holds the amounts privately", () => {
    const disputeCase = makeCase();

    expect(disputeCase.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(DISPUTE_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(disputeCase.network).toBe("SN_MAIN");
    expect(disputeCase.escrowBaseUnits).toBe("1000000000");
    expect(disputeCase.escrowDisplay).toBe("1000");
    expect(disputeCase.collateralBaseUnits).toBe("200000000");
    expect(verifyDisputeCase(disputeCase)).toBe(true);
  });

  it("defaults the collateral to zero and rejects bad deadlines or parties", () => {
    const noCollateral = makeCase({ collateralValue: undefined });
    expect(noCollateral.collateralBaseUnits).toBe("0");

    expect(() => makeCase({ respondBy: "2026-08-21T08:00:00.000Z" })).toThrow(/deadline must be in the future/i);
    expect(() => makeCase({ respondBy: "2027-08-22T08:00:00.000Z" })).toThrow(/within 90 days/i);
    expect(() => makeCase({ vendorRecipient: BUYER })).toThrow(/buyer and the vendor must be different/i);
  });
});

describe("dispute allocation economics", () => {
  it("solves refund, release, fee, and penalty and conserves every base unit", () => {
    const { resolution } = makeResolution();

    expect(resolution.buyerRefundBaseUnits).toBe("400000000");
    expect(resolution.vendorReleaseBaseUnits).toBe("550000000");
    expect(resolution.arbiterFeeBaseUnits).toBe("50000000");
    expect(resolution.penaltyBaseUnits).toBe("50000000");
    expect(resolution.collateralReturnBaseUnits).toBe("150000000");
    expect(resolution.buyerTotalBaseUnits).toBe("450000000");
    expect(resolution.vendorTotalBaseUnits).toBe("700000000");
    const totalOut = BigInt(resolution.buyerTotalBaseUnits) + BigInt(resolution.vendorTotalBaseUnits) + BigInt(resolution.arbiterFeeBaseUnits);
    expect(totalOut).toBe(BigInt(resolution.escrowBaseUnits) + BigInt(resolution.collateralBaseUnits));
    expect(verifyDisputeResolution(resolution)).toBe(true);
  });

  it("floors each share and hands the vendor the exact remainder", () => {
    const { resolution } = makeResolution(
      { faultAssessment: "shared", buyerRefundBps: 5000, arbiterFeeBps: 0, penaltyBps: 5000 },
      { escrowValue: "1.000001", collateralValue: "1.000001" },
    );

    expect(resolution.buyerRefundBaseUnits).toBe("500000");
    expect(resolution.vendorReleaseBaseUnits).toBe("500001");
    expect(resolution.penaltyBaseUnits).toBe("500000");
    expect(resolution.collateralReturnBaseUnits).toBe("500001");
    expect(resolution.vendorTotalDisplay).toBe("1.000002");
    const totalOut = BigInt(resolution.buyerTotalBaseUnits) + BigInt(resolution.vendorTotalBaseUnits);
    expect(totalOut).toBe(BigInt(resolution.escrowBaseUnits) + BigInt(resolution.collateralBaseUnits));
  });

  it("enforces the guards around penalties, splits, and the arbiter fee", () => {
    expect(() => makeResolution({ faultAssessment: "buyer_at_fault", penaltyBps: 1000 })).toThrow(/vendor-at-fault or shared/i);
    expect(() => makeResolution({ penaltyBps: 1000 }, { collateralValue: undefined })).toThrow(/needs posted collateral/i);
    expect(() => makeResolution({ buyerRefundBps: 9000, arbiterFeeBps: 2000 })).toThrow(/cannot exceed the escrow/i);
    expect(() => makeResolution({ arbiterFeeBps: 2001 })).toThrow(/between 0 and 2000 basis points/i);
    expect(() => makeResolution({ arbiterFeeBps: 500 }, { arbiterRecipient: undefined })).toThrow(/needs an arbiter recipient/i);
    expect(() => makeResolution({ arbiterFeeBps: 500 }, { arbiterRecipient: BUYER })).toThrow(/different recipient/i);
  });
});

describe("settlement actions", () => {
  it("merges the split into one in-pool transfer per recipient with no relayer-fee action", () => {
    const { resolution } = makeResolution();
    const actions = buildResolutionActions(resolution);

    expect(actions).toEqual([
      { type: "transfer", token: USDC, amount: "450000000", recipient: BUYER },
      { type: "transfer", token: USDC, amount: "700000000", recipient: VENDOR },
      { type: "transfer", token: USDC, amount: "50000000", recipient: ARBITER },
    ]);
    expect(actions.filter((action) => action.type === "withdraw")).toHaveLength(0);
  });

  it("drops zero legs so a no-fault release pays only the vendor", () => {
    const { resolution } = makeResolution({ faultAssessment: "no_fault", buyerRefundBps: 0, arbiterFeeBps: 0, penaltyBps: 0 });
    const actions = buildResolutionActions(resolution);

    expect(actions).toEqual([{ type: "transfer", token: USDC, amount: "1200000000", recipient: VENDOR }]);
  });
});

describe("commitments and selective disclosure", () => {
  it("detects a tampered amount, salt, or claim", () => {
    const { disputeCase, resolution } = makeResolution();

    expect(verifyDisputeCase({ ...disputeCase, caseSalt: "0x2" })).toBe(false);
    expect(verifyDisputeCase({ ...disputeCase, claimSummary: "A different claim." })).toBe(false);
    expect(verifyDisputeResolution({ ...resolution, buyerRefundBaseUnits: "1" })).toBe(false);
    expect(verifyDisputeResolution({ ...resolution, resolutionSalt: "0x9" })).toBe(false);
    expect(verifyDisputeResolution({ ...resolution, faultAssessment: "no_fault" })).toBe(false);
  });

  it("publishes a case digest that carries no amount, address, claim, salt, or memo", () => {
    const disputeCase = makeCase();
    const digest = buildDisputeCaseDigest(disputeCase);
    const encoded = JSON.stringify(digest);

    expect(digest.caseCommitment).toBe(disputeCase.caseCommitment);
    expect(digest.hasCollateral).toBe(true);
    expect(encoded).not.toContain(disputeCase.escrowBaseUnits);
    expect(encoded).not.toContain(disputeCase.caseSalt);
    expect(encoded).not.toContain(BUYER);
    expect(encoded).not.toContain("Delivered goods");
    expect(encoded).not.toContain("batch 7");
    expect(parseDisputeCaseDigest(serializeDisputeCaseDigest(digest))).toEqual(digest);
  });

  it("opens a case against its digest and rejects a doctored opening", () => {
    const disputeCase = makeCase();
    const digest = buildDisputeCaseDigest(disputeCase);
    const opening = openDisputeCase(disputeCase);

    expect(verifyDisputeCaseDisclosure(digest, opening)).toBe(true);
    expect(verifyDisputeCaseDisclosure(digest, { ...opening, disputeCase: { ...opening.disputeCase, claimSummary: "Something else." } })).toBe(false);
    expect(verifyDisputeCaseDisclosure(digest, { ...opening, caseCommitment: "0x5" })).toBe(false);
  });
});

describe("evidence commitments", () => {
  it("hashes each item and publishes a digest without the item content", () => {
    const { evidence } = makeEvidence();
    const digest = buildEvidenceDigest(evidence);
    const encoded = JSON.stringify(digest);

    expect(digest.itemCount).toBe(2);
    expect(digest.itemHashes).toHaveLength(2);
    expect(digest.evidenceCommitment).toBe(evidence.evidenceCommitment);
    expect(encoded).not.toContain("ipfs://bafyEvidencePhoto");
    expect(encoded).not.toContain("delivery-note");
    expect(verifyEvidence(evidence)).toBe(true);
    expect(parseEvidenceDigest(serializeEvidenceDigest(digest))).toEqual(digest);
  });

  it("opens evidence against its digest and rejects tampering", () => {
    const { evidence } = makeEvidence();
    const digest = buildEvidenceDigest(evidence);
    const opening = openEvidence(evidence);

    expect(verifyEvidenceDisclosure(digest, opening)).toBe(true);
    expect(verifyEvidenceDisclosure(digest, { ...opening, evidence: { ...opening.evidence, items: ["ipfs://forged", "sha256:9f2c...delivery-note"] } })).toBe(false);
    expect(verifyEvidence({ ...evidence, note: "changed" })).toBe(false);
    expect(verifyEvidence({ ...evidence, evidenceSalt: "0x2" })).toBe(false);
    expect(() => createEvidence({ caseCommitment: evidence.caseCommitment, submittedBy: "buyer", items: [] })).toThrow(/between 1 and 32 items/i);
  });
});

describe("outcome attestation", () => {
  it("binds the case and resolution and verifies only against its own resolution", () => {
    const { resolution } = makeResolution();
    const { resolution: other } = makeResolution({}, {}, 2);
    const attestation = buildDisputeOutcomeAttestation(resolution);

    expect(attestation.faultAssessment).toBe("vendor_at_fault");
    expect(attestation.resolutionCommitment).toBe(resolution.resolutionCommitment);
    expect(verifyDisputeOutcome(attestation, resolution)).toBe(true);
    expect(verifyDisputeOutcome(attestation, other)).toBe(false);
    expect(verifyDisputeOutcome({ ...attestation, faultAssessment: "no_fault" }, resolution)).toBe(false);
    expect(parseDisputeOutcome(serializeDisputeOutcome(attestation))).toEqual(attestation);
  });
});

describe("visibility, trust, and formatting", () => {
  it("says plainly what is in-browser only, what the wallet sees, and what stays public", () => {
    const { resolution } = makeResolution();
    const model = getDisputeVisibilityModel(resolution);

    expect(model.walletRequest).toContain("exact per-recipient base-unit amounts");
    expect(model.hiddenInPool).toContain("which encrypted notes were spent");
    expect(model.publicOrObservable.some((entry) => /timing/.test(entry))).toBe(true);
    expect(model.limitation).toMatch(/correlate the parties/i);
  });

  it("refuses to call the settlement escrowed, proven, or an on-chain reputation record", () => {
    const { resolution } = makeResolution();
    const trust = summarizeDisputeTrust(resolution);

    expect(trust).toMatchObject({ isEscrowed: false, isProven: false, isOnChainReputation: false, faultAssessment: "vendor_at_fault" });
    expect(trust.trustedParties).toHaveLength(2);
    expect(trust.statement).toMatch(/nothing is escrowed or slashed and no proof is generated/i);
  });

  it("formats base units for display", () => {
    expect(formatDisputeBaseUnits("450000000", 6)).toBe("450");
    expect(formatDisputeBaseUnits(1000002n, 6)).toBe("1.000002");
    expect(formatDisputeBaseUnits("0", 18)).toBe("0");
    expect(() => formatDisputeBaseUnits("1", 19)).toThrow(/between 0 and 18/i);
  });

  it("keeps the settlement on a real pool token", () => {
    const { resolution } = makeResolution();
    expect(resolution.asset.tokenAddress).not.toBe(STRK);
    expect(resolution.asset.tokenAddress).toBe(USDC);
  });
});

describe("serialization", () => {
  it("survives round trips and gives independent objects independent commitments", () => {
    const { disputeCase, resolution } = makeResolution();
    const { evidence } = makeEvidence();
    const twin = makeResolution({}, {}, 2);

    expect(parseDisputeCase(serializeDisputeCase(disputeCase))).toEqual(disputeCase);
    expect(parseDisputeResolution(serializeDisputeResolution(resolution))).toEqual(resolution);
    expect(parseEvidenceBundle(serializeEvidenceBundle(evidence))).toEqual(evidence);
    expect(twin.resolution.buyerTotalBaseUnits).toBe(resolution.buyerTotalBaseUnits);
    expect(twin.resolution.resolutionSalt).not.toBe(resolution.resolutionSalt);
    expect(twin.resolution.resolutionCommitment).not.toBe(resolution.resolutionCommitment);
    expect(() => parseDisputeCase("not base64url!!")).toThrow(/encoding is invalid/i);
  });
});
