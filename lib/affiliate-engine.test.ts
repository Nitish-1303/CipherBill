import { describe, expect, it } from "vitest";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  buildAffiliateClaimAuthorization,
  buildAffiliatePayoutReceipt,
  buildAffiliateProgramDigest,
  buildPayoutActions,
  buildReferralLink,
  computeAffiliateReward,
  createAffiliateProgram,
  formatAffiliateBaseUnits,
  getAffiliateVisibilityModel,
  openAffiliateProgram,
  parseAffiliateAccount,
  parseAffiliateClaimAuthorization,
  parseAffiliatePayoutReceipt,
  parseAffiliateProgram,
  parseAffiliateProgramDigest,
  parseAffiliateReferral,
  previewAffiliateReward,
  recordReferral,
  registerAffiliate,
  registerAffiliateClaimKey,
  serializeAffiliateAccount,
  serializeAffiliateClaimAuthorization,
  serializeAffiliatePayoutReceipt,
  serializeAffiliateProgram,
  serializeAffiliateProgramDigest,
  serializeAffiliateReferral,
  summarizeAffiliateTrust,
  verifyAffiliateAccount,
  verifyAffiliateClaimAuthorization,
  verifyAffiliatePayoutReceipt,
  verifyAffiliateProgram,
  verifyAffiliateProgramDisclosure,
  verifyAffiliateReferral,
  type AffiliateTierInput,
  type CreateAffiliateProgramInput,
} from "./affiliate-engine";

const MERCHANT = "0x0111";
const PAYOUT = "0x0222";
const NOW = new Date("2026-08-01T00:00:00.000Z");

const TIERS: AffiliateTierInput[] = [
  { name: "Bronze", minVolume: "0", rateBps: 200 },
  { name: "Silver", minVolume: "1000", rateBps: 500 },
  { name: "Gold", minVolume: "10000", rateBps: 1000 },
];

/** Deterministic entropy: incrementing ids and a fixed non-zero salt so every run is reproducible. */
function makeEntropy() {
  let counter = 0;
  return {
    createId: (kind: "program" | "account" | "referral") => {
      const prefix = kind === "program" ? "afp" : kind === "account" ? "afa" : "afr";
      counter += 1;
      return `${prefix}_t${counter}`;
    },
    randomBytes: (target: Uint8Array<ArrayBuffer>) => {
      target.fill(7);
      return target;
    },
  };
}

function makeProgram(overrides: Partial<CreateAffiliateProgramInput> = {}) {
  const input: CreateAffiliateProgramInput = {
    merchant: MERCHANT,
    asset: { symbol: "USDC", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 6 },
    tiers: TIERS,
    memo: "Q3 partner program",
    ...overrides,
  };
  return createAffiliateProgram(input, NOW, makeEntropy());
}

function makeAccount(program = makeProgram()) {
  const claimKey = registerAffiliateClaimKey({ claimSecret: 12_345n });
  const account = registerAffiliate(
    program,
    { label: "Partner A", payoutAddress: PAYOUT, claimPublicKey: claimKey.claimPublicKey },
    makeEntropy(),
  );
  return { program, account, claimKey };
}

describe("affiliate program", () => {
  it("creates a program that verifies and round-trips through serialization", () => {
    const program = makeProgram();
    expect(program.kind).toBe("cipherbill.affiliate-program");
    expect(program.programId).toMatch(/^afp_/);
    expect(program.merchant).not.toBe(MERCHANT); // normalized/padded
    expect(verifyAffiliateProgram(program)).toBe(true);
    expect(parseAffiliateProgram(serializeAffiliateProgram(program))).toEqual(program);
  });

  it("normalizes tiers to base units and keeps the first tier at zero", () => {
    const program = makeProgram();
    expect(program.tiers.map((t) => t.minVolumeBaseUnits)).toEqual(["0", "1000000000", "10000000000"]);
    expect(program.tiers[0].minVolumeDisplay).toBe("0");
  });

  it("rejects a first tier that does not start at zero volume", () => {
    expect(() => makeProgram({ tiers: [{ name: "Bronze", minVolume: "100", rateBps: 200 }] })).toThrow(/first commission tier/i);
  });

  it("rejects non-ascending tier minimum volumes", () => {
    const tiers: AffiliateTierInput[] = [
      { name: "Bronze", minVolume: "0", rateBps: 200 },
      { name: "Silver", minVolume: "1000", rateBps: 500 },
      { name: "Gold", minVolume: "1000", rateBps: 1000 },
    ];
    expect(() => makeProgram({ tiers })).toThrow(/strictly ascend/i);
  });

  it("rejects duplicate tier names", () => {
    const tiers: AffiliateTierInput[] = [
      { name: "Tier", minVolume: "0", rateBps: 200 },
      { name: "tier", minVolume: "1000", rateBps: 500 },
    ];
    expect(() => makeProgram({ tiers })).toThrow(/unique/i);
  });

  it("rejects out-of-range commission rates", () => {
    expect(() => makeProgram({ tiers: [{ name: "Bronze", minVolume: "0", rateBps: 0 }] })).toThrow(/basis points/i);
    expect(() => makeProgram({ tiers: [{ name: "Bronze", minVolume: "0", rateBps: 10_001 }] })).toThrow(/basis points/i);
  });

  it("rejects a tampered commitment", () => {
    const program = makeProgram();
    const tampered = { ...program, memo: "a different memo" };
    expect(verifyAffiliateProgram(tampered)).toBe(false);
  });
});
describe("affiliate accounts and referrals", () => {
  it("registers an account with an opaque referral code and shareable link", () => {
    const { program, account } = makeAccount();
    expect(account.affiliateId).toMatch(/^afa_/);
    expect(account.referralCode).toMatch(/^af-[0-9a-f]{20}$/);
    expect(account.referralCode).not.toContain(PAYOUT);
    expect(verifyAffiliateAccount(account, program)).toBe(true);
    expect(buildReferralLink(account)).toBe(`https://cipherbill.app/r?ref=${account.referralCode}`);
    expect(parseAffiliateAccount(serializeAffiliateAccount(account))).toEqual(account);
  });

  it("does not carry the claim secret anywhere in the account", () => {
    const { account, claimKey } = makeAccount();
    expect(JSON.stringify(account)).not.toContain(claimKey.claimSecret.slice(2));
  });

  it("rejects a non-https referral link base", () => {
    const { account } = makeAccount();
    expect(() => buildReferralLink(account, "http://cipherbill.app/r")).toThrow(/https/i);
  });

  it("records a referral that verifies and round-trips", () => {
    const { program, account } = makeAccount();
    const referral = recordReferral(program, account, { invoiceId: "inv-1", volume: "5000" }, NOW, makeEntropy());
    expect(referral.referralId).toMatch(/^afr_/);
    expect(referral.volumeBaseUnits).toBe("5000000000");
    expect(verifyAffiliateReferral(referral, program, account)).toBe(true);
    expect(parseAffiliateReferral(serializeAffiliateReferral(referral))).toEqual(referral);
  });

  it("rejects a non-positive referral volume", () => {
    const { program, account } = makeAccount();
    expect(() => recordReferral(program, account, { invoiceId: "inv-1", volume: "0" }, NOW, makeEntropy())).toThrow(/greater than zero/i);
  });

  it("rejects a referral dated before the program was created", () => {
    const { program, account } = makeAccount();
    const before = new Date("2026-07-31T00:00:00.000Z");
    expect(() => recordReferral(program, account, { invoiceId: "inv-1", volume: "10" }, before, makeEntropy())).toThrow(/before the program/i);
  });

  it("rejects an account bound to a different program", () => {
    const programA = makeProgram();
    const { account } = makeAccount(programA);
    const programB = makeProgram({ memo: "another program" });
    expect(verifyAffiliateAccount(account, programB)).toBe(false);
  });
});
describe("commission math", () => {
  function rewardFor(volume: string) {
    const { program, account } = makeAccount();
    const referral = recordReferral(program, account, { invoiceId: "inv-1", volume }, NOW, makeEntropy());
    return { program, account, statement: computeAffiliateReward(program, [referral]) };
  }

  it("resolves the Silver tier and floors the commission", () => {
    const { statement } = rewardFor("5000");
    expect(statement.tierName).toBe("Silver");
    expect(statement.tierRateBps).toBe(500);
    expect(statement.commissionBaseUnits).toBe("250000000");
    expect(statement.commissionDisplay).toBe("250");
  });

  it("resolves the Gold tier at the threshold", () => {
    const { statement } = rewardFor("10000");
    expect(statement.tierName).toBe("Gold");
    expect(statement.commissionBaseUnits).toBe("1000000000");
    expect(statement.commissionDisplay).toBe("1000");
  });

  it("resolves the Bronze tier below the first threshold", () => {
    const { statement } = rewardFor("500");
    expect(statement.tierName).toBe("Bronze");
    expect(statement.commissionBaseUnits).toBe("10000000");
    expect(statement.commissionDisplay).toBe("10");
  });

  it("floors fractional commissions so the merchant never overpays", () => {
    // 333 base units at Bronze's 200 bps = 6.66 -> 6.
    const { statement } = rewardFor("0.000333");
    expect(statement.totalVolumeBaseUnits).toBe("333");
    expect(statement.tierName).toBe("Bronze");
    expect(statement.commissionBaseUnits).toBe("6");
  });

  it("sums multiple referrals for one affiliate", () => {
    const { program, account } = makeAccount();
    const r1 = recordReferral(program, account, { invoiceId: "inv-1", volume: "600" }, NOW, makeEntropy());
    const r2 = recordReferral(program, account, { invoiceId: "inv-2", volume: "600" }, NOW, makeEntropy());
    const statement = computeAffiliateReward(program, [r1, r2]);
    expect(statement.referralCount).toBe(2);
    expect(statement.totalVolumeBaseUnits).toBe("1200000000"); // 1200 USDC -> Silver
    expect(statement.tierName).toBe("Silver");
  });

  it("refuses to mix affiliates in one reward", () => {
    const program = makeProgram();
    const a = makeAccount(program).account;
    const claimKeyB = registerAffiliateClaimKey({ claimSecret: 99n });
    const b = registerAffiliate(
      program,
      { payoutAddress: "0x0333", claimPublicKey: claimKeyB.claimPublicKey },
      { createId: () => "afa_partnerb", randomBytes: (target) => { target.fill(9); return target; } },
    );
    const rA = recordReferral(program, a, { invoiceId: "inv-a", volume: "10" }, NOW, makeEntropy());
    const rB = recordReferral(program, b, { invoiceId: "inv-b", volume: "10" }, NOW, makeEntropy());
    expect(() => computeAffiliateReward(program, [rA, rB])).toThrow(/one affiliate/i);
  });

  it("previews tiers and commission without an account", () => {
    const preview = previewAffiliateReward({ asset: { symbol: "USDC", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 6 }, tiers: TIERS, volume: "5000" });
    expect(preview.tierName).toBe("Silver");
    expect(preview.commissionDisplay).toBe("250");
    expect(preview.tiers).toHaveLength(3);
  });

  it("rejects a commission that overflows the pool's u128 range", () => {
    const { program, account } = makeAccount();
    const overflow = (2n ** 128n).toString();
    expect(() => buildPayoutActions(program, account, overflow)).toThrow(/u128/i);
  });
});
const TX_HASH = "0x02f6a8b9c0d1e2f3040506070809111213141516171819202122232425262728";
const PAID_AT = "2026-08-05T12:00:00.000Z";

describe("payout builder and receipts", () => {
  it("builds exactly one in-pool transfer with no relayer-fee leg", () => {
    const { program, account } = makeAccount();
    const referral = recordReferral(program, account, { invoiceId: "inv-1", volume: "5000" }, NOW, makeEntropy());
    const statement = computeAffiliateReward(program, [referral]);
    const actions = buildPayoutActions(program, account, statement.commissionBaseUnits);
    expect(actions).toHaveLength(1);
    expect(actions[0]).toMatchObject({
      type: "transfer",
      token: program.asset.tokenAddress,
      recipient: account.payoutAddress,
      amount: "250000000",
    });
  });

  it("refuses a zero-commission payout", () => {
    const { program, account } = makeAccount();
    expect(() => buildPayoutActions(program, account, "0")).toThrow(/no commission/i);
  });

  it("builds and verifies a payout receipt that round-trips", () => {
    const { program, account } = makeAccount();
    const receipt = buildAffiliatePayoutReceipt(program, account, {
      totalVolumeBaseUnits: "5000000000",
      tierName: "Silver",
      tierRateBps: 500,
      commissionBaseUnits: "250000000",
      paidAt: PAID_AT,
      transactionHash: TX_HASH,
    });
    expect(verifyAffiliatePayoutReceipt(receipt, program, account)).toBe(true);
    expect(parseAffiliatePayoutReceipt(serializeAffiliatePayoutReceipt(receipt))).toEqual(receipt);
  });

  it("rejects a receipt whose commission contradicts the tier rate", () => {
    const { program, account } = makeAccount();
    expect(() => buildAffiliatePayoutReceipt(program, account, {
      totalVolumeBaseUnits: "5000000000",
      tierName: "Silver",
      tierRateBps: 500,
      commissionBaseUnits: "250000001",
      paidAt: PAID_AT,
      transactionHash: TX_HASH,
    })).toThrow(/does not match/i);
  });
});
describe("claim authorization (zero-knowledge)", () => {
  function buildAuth() {
    const { program, account, claimKey } = makeAccount();
    const authorization = buildAffiliateClaimAuthorization(
      program,
      account,
      claimKey,
      { commissionBaseUnits: "250000000", period: "2026-Q3" },
      { nonce: 424242n },
    );
    return { program, account, claimKey, authorization };
  }

  it("proves knowledge of the claim key and round-trips", () => {
    const { program, account, authorization } = buildAuth();
    expect(authorization.proofSystem).toBe("stark-schnorr-affiliate-claim-v1");
    expect(verifyAffiliateClaimAuthorization(authorization, program, account)).toBe(true);
    expect(parseAffiliateClaimAuthorization(serializeAffiliateClaimAuthorization(authorization))).toEqual(authorization);
  });

  it("never carries the claim secret", () => {
    const { authorization, claimKey } = buildAuth();
    expect(JSON.stringify(authorization)).not.toContain(claimKey.claimSecret.slice(2));
  });

  it("rejects a claim key that does not match the account", () => {
    const { program, account } = makeAccount();
    const wrongKey = registerAffiliateClaimKey({ claimSecret: 777n });
    expect(() => buildAffiliateClaimAuthorization(program, account, wrongKey, { commissionBaseUnits: "1", period: "2026-Q3" })).toThrow(/registered affiliate account/i);
  });

  it("rejects a tampered commission in the authorization", () => {
    const { program, account, authorization } = buildAuth();
    expect(verifyAffiliateClaimAuthorization({ ...authorization, commissionBaseUnits: "1" }, program, account)).toBe(false);
  });

  it("rejects an authorization checked against a different program", () => {
    const { authorization } = buildAuth();
    const otherProgram = makeProgram({ memo: "different" });
    const otherAccount = makeAccount(otherProgram).account;
    expect(verifyAffiliateClaimAuthorization(authorization, otherProgram, otherAccount)).toBe(false);
  });

  it("refuses a zero-commission claim", () => {
    const { program, account, claimKey } = makeAccount();
    expect(() => buildAffiliateClaimAuthorization(program, account, claimKey, { commissionBaseUnits: "0", period: "2026-Q3" })).toThrow(/non-zero/i);
  });
});
describe("program digest and disclosure", () => {
  it("omits tier economics, the memo, and the merchant address", () => {
    const program = makeProgram();
    const digest = buildAffiliateProgramDigest(program);
    const json = JSON.stringify(digest);
    expect(json).not.toContain("Silver");
    expect(json).not.toContain("Q3 partner program");
    expect(json).not.toContain('"rateBps"');
    expect(digest).not.toHaveProperty("merchant");
    expect(digest.tierCount).toBe(3);
    expect(digest.hasMemo).toBe(true);
    expect(parseAffiliateProgramDigest(serializeAffiliateProgramDigest(digest))).toEqual(digest);
  });

  it("verifies a genuine opening against its digest", () => {
    const program = makeProgram();
    const digest = buildAffiliateProgramDigest(program);
    expect(verifyAffiliateProgramDisclosure(openAffiliateProgram(program), digest)).toBe(true);
  });

  it("rejects an opening whose program was altered", () => {
    const digest = buildAffiliateProgramDigest(makeProgram());
    const opening = openAffiliateProgram(makeProgram({ memo: "different program" }));
    expect(verifyAffiliateProgramDisclosure(opening, digest)).toBe(false);
  });
});

describe("honest disclosures", () => {
  it("summarizes trust without overstating the design", () => {
    const trust = summarizeAffiliateTrust();
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.provesReferral).toBe(false);
    expect(trust.provesPayment).toBe(false);
    expect(trust.fundHolder).toMatch(/merchant/i);
  });

  it("describes what the pool hides and what stays public", () => {
    const model = getAffiliateVisibilityModel();
    expect(model.hiddenInPool.length).toBeGreaterThan(0);
    expect(model.publicOrObservable.length).toBeGreaterThan(0);
    expect(model.limitation).toMatch(/public/i);
  });
});

describe("formatAffiliateBaseUnits", () => {
  it("renders decimal strings, hex FELT strings, and bigints", () => {
    expect(formatAffiliateBaseUnits("250000000", 6)).toBe("250");
    expect(formatAffiliateBaseUnits(250000000n, 6)).toBe("250");
    // A wallet FELT balance arrives as hex; 0x3e8 = 1000 base units at 6 decimals = 0.001.
    expect(formatAffiliateBaseUnits("0x3e8", 6)).toBe("0.001");
  });
});
