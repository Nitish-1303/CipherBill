import { describe, expect, it } from "vitest";

import {
  BRIDGE_OPERATORS,
  buildRouteDigest,
  buildStarknetLegActions,
  CROSS_CHAIN_ROUTER_POOL_ADDRESS,
  formatRouteBaseUnits,
  getRouteExecutionBoundary,
  getRouteVisibilityModel,
  openRouteLeg,
  parseCrossChainRoute,
  parseRouteDigest,
  planCrossChainRoute,
  serializeCrossChainRoute,
  serializeRouteDigest,
  summarizeRouteTrust,
  verifyCrossChainRoute,
  verifyRouteLegOpening,
  type PlanCrossChainRouteInput,
} from "./cross-chain-router";
import { STRK20_POOL_ADDRESS } from "./strk20/config";

const NOW = new Date("2026-08-22T08:00:00.000Z");
const DEADLINE = "2026-08-24T08:00:00.000Z";
const USDC = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const PAYEE = "0x0712345678901234567890123456789012345678901234567890123456789012";
const BRIDGE_DEPOSIT = "0x06f1b4a5c2d3e4f50123456789abcdef0123456789abcdef0123456789abcdef";

/** Deterministic salts, so every commitment in this file is reproducible. */
function entropy(seed: number) {
  return {
    createId: () => `route_test_${seed}`,
    randomBytes: (target: Uint8Array<ArrayBuffer>) => {
      for (let index = 0; index < target.length; index += 1) target[index] = ((index + seed) % 251) + 1;
      return target;
    },
  };
}

const POOL_ONLY: PlanCrossChainRouteInput = {
  invoiceId: "inv_route_001",
  sourceAsset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
  deliveryAmount: "100",
  deadline: DEADLINE,
  legs: [{ kind: "pool_private_transfer", toVenue: "strk20_pool", asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 }, recipient: PAYEE }],
};

const CROSS_CHAIN: PlanCrossChainRouteInput = {
  invoiceId: "inv_route_002",
  sourceAsset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
  deliveryAmount: "90",
  deadline: DEADLINE,
  memo: "Contractor payout August",
  legs: [
    { kind: "pool_withdraw", toVenue: "starknet_public", asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 }, recipient: BRIDGE_DEPOSIT },
    {
      kind: "external_bridge",
      toVenue: "base",
      asset: { symbol: "USDC", decimals: 6 },
      operator: "circle_cctp",
      recipientLabel: "Base treasury 0xabc…def",
      feeBps: 10,
      fixedFeeBaseUnits: "100000",
    },
    {
      kind: "external_payout",
      toVenue: "base",
      asset: { symbol: "EUR", decimals: 2 },
      recipientLabel: "Contractor IBAN ****1234",
      rate: "0.9",
    },
  ],
};

function plan(input: PlanCrossChainRouteInput, seed = 1) {
  return planCrossChainRoute(input, NOW, entropy(seed));
}

describe("planCrossChainRoute", () => {
  it("funds a single in-pool leg with exactly the delivered amount when no fee is charged", () => {
    const route = plan(POOL_ONLY);

    expect(route.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(CROSS_CHAIN_ROUTER_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(route.network).toBe("SN_MAIN");
    expect(route.fundingBaseUnits).toBe("100000000");
    expect(route.fundingDisplay).toBe("100");
    expect(route.deliveryBaseUnits).toBe("100000000");
    expect(route.legs[0].surplusOutBaseUnits).toBe("0");
    expect(route.legs[0].provenance).toBe("starknet_proof_by_wallet");
    expect(route.executableLegCount).toBe(1);
    expect(verifyCrossChainRoute(route)).toBe(true);
  });

  it("rounds a proportional fee up and funds the smallest amount that still delivers", () => {
    const route = plan({
      ...POOL_ONLY,
      legs: [{ ...POOL_ONLY.legs[0], feeBps: 50 }],
    });
    const leg = route.legs[0];

    expect(route.fundingBaseUnits).toBe("100502513");
    expect(leg.proportionalFeeBaseUnits).toBe("502513");
    expect(leg.netInBaseUnits).toBe("100000000");
    expect(leg.deliveredOutBaseUnits).toBe("100000000");
    expect(leg.surplusOutBaseUnits).toBe("0");
    expect(leg.totalFeeDisplay).toBe("0.502513");
    expect(route.feeTotals).toEqual([{ symbol: "USDC", tokenAddress: USDC, decimals: 6, feeBaseUnits: "502513", feeDisplay: "0.502513" }]);
  });

  it("solves a pool exit, a bridge, and an off-chain payout backwards in exact integers", () => {
    const route = plan(CROSS_CHAIN);

    expect(route.fundingBaseUnits).toBe("100200201");
    expect(route.fundingDisplay).toBe("100.200201");
    expect(route.deliveryBaseUnits).toBe("9000");
    expect(route.deliveryDisplay).toBe("90");
    expect(route.legs.map((leg) => leg.grossInBaseUnits)).toEqual(["100200201", "100200201", "100000000"]);
    expect(route.legs.map((leg) => leg.deliveredOutBaseUnits)).toEqual(["100200201", "100000000", "9000"]);
    expect(route.legs[1].proportionalFeeBaseUnits).toBe("100201");
    expect(route.legs[1].fixedFeeBaseUnits).toBe("100000");
    expect(route.legs[2].normalizedRate).toBe("0.9");
    expect(route.legs[2].rateNumerator).toBe("9");
    expect(route.legs[2].rateScale).toBe("10");
    expect(route.executableLegCount).toBe(1);
    expect(route.estimatedTotalSeconds).toBe(90 + 900 + 300);
    expect(route.feeTotals).toEqual([
      { symbol: "USDC", tokenAddress: USDC, decimals: 6, feeBaseUnits: "200201", feeDisplay: "0.200201" },
      { symbol: "USDC", tokenAddress: null, decimals: 6, feeBaseUnits: "0", feeDisplay: "0" },
    ]);
    expect(verifyCrossChainRoute(route)).toBe(true);
  });

  it("reports the dust a floor-rounded conversion leaves behind instead of silently keeping it", () => {
    const route = plan({
      invoiceId: "inv_route_dust",
      sourceAsset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 },
      deliveryAmount: "0.000001",
      deadline: DEADLINE,
      legs: [
        { kind: "pool_withdraw", toVenue: "starknet_public", asset: { symbol: "USDC", tokenAddress: USDC, decimals: 6 }, recipient: BRIDGE_DEPOSIT },
        { kind: "external_payout", toVenue: "base", asset: { symbol: "XTKN", decimals: 6 }, recipientLabel: "Venue account", rate: "3" },
      ],
    });

    expect(route.fundingBaseUnits).toBe("1");
    expect(route.legs[1].requiredOutBaseUnits).toBe("1");
    expect(route.legs[1].deliveredOutBaseUnits).toBe("3");
    expect(route.legs[1].surplusOutBaseUnits).toBe("2");
  });

  it("rejects deadlines that are past, or further out than the route lifetime", () => {
    expect(() => plan({ ...POOL_ONLY, deadline: "2026-08-22T07:00:00.000Z" })).toThrow(/deadline must be in the future/i);
    expect(() => plan({ ...POOL_ONLY, deadline: "2026-09-30T08:00:00.000Z" })).toThrow(/within 7 days/i);
  });

  it("rejects delivery amounts that are zero or finer than the destination asset", () => {
    expect(() => plan({ ...POOL_ONLY, deliveryAmount: "0" })).toThrow(/greater than zero/i);
    expect(() => plan({ ...POOL_ONLY, deliveryAmount: "1.0000001" })).toThrow(/more precision than the token's 6 decimals/i);
    expect(() => plan({ ...POOL_ONLY, deliveryAmount: "-5" })).toThrow(/positive decimal/i);
  });

  it("rejects an empty leg list and routes longer than the leg limit", () => {
    expect(() => plan({ ...POOL_ONLY, legs: [] })).toThrow(/between 1 and 6 legs/i);
    expect(() => plan({ ...POOL_ONLY, legs: new Array(7).fill(POOL_ONLY.legs[0]) })).toThrow(/between 1 and 6 legs/i);
  });
});

describe("route legality", () => {
  it("requires a route to be funded from the shielded balance", () => {
    expect(() => plan({
      ...CROSS_CHAIN,
      legs: [CROSS_CHAIN.legs[1]],
      deliveryAmount: "90",
    })).toThrow(/must be preceded by a pool withdrawal/i);
  });

  it("requires a bridge leg to name an operator and to change network", () => {
    expect(() => plan({ ...CROSS_CHAIN, legs: [CROSS_CHAIN.legs[0], { ...CROSS_CHAIN.legs[1], operator: undefined }] })).toThrow(/must name the operator/i);
    expect(() => plan({ ...CROSS_CHAIN, legs: [CROSS_CHAIN.legs[0], { ...CROSS_CHAIN.legs[1], toVenue: "starknet_public" }] })).toThrow(/does not change network/i);
  });

  it("allows the pool to be exited only once", () => {
    expect(() => plan({
      ...CROSS_CHAIN,
      deliveryAmount: "100",
      legs: [CROSS_CHAIN.legs[0], { ...CROSS_CHAIN.legs[0], recipient: PAYEE }],
    })).toThrow(/acts on the pool but does not start there/i);
  });

  it("keeps in-pool legs on the same token and refuses a venue rate inside the pool", () => {
    expect(() => plan({
      ...POOL_ONLY,
      legs: [{ ...POOL_ONLY.legs[0], asset: { symbol: "STRK", tokenAddress: STRK, decimals: 18 } }],
    })).toThrow(/cannot change the token/i);
    expect(() => plan({ ...POOL_ONLY, legs: [{ ...POOL_ONLY.legs[0], rate: "1.05" }] })).toThrow(/cannot apply a venue rate/i);
  });

  it("requires a recipient on Starknet legs and a reconciliation label on external legs", () => {
    expect(() => plan({ ...POOL_ONLY, legs: [{ ...POOL_ONLY.legs[0], recipient: undefined }] })).toThrow(/recipient must be between/i);
    expect(() => plan({ ...CROSS_CHAIN, legs: [CROSS_CHAIN.legs[0], { ...CROSS_CHAIN.legs[1], recipientLabel: undefined }] })).toThrow(/needs a recipient label/i);
  });

  it("refuses an operator on a pool leg and a fee above the leg cap", () => {
    expect(() => plan({ ...POOL_ONLY, legs: [{ ...POOL_ONLY.legs[0], operator: "starkgate" }] })).toThrow(/must not name an external operator/i);
    expect(() => plan({ ...POOL_ONLY, legs: [{ ...POOL_ONLY.legs[0], feeBps: 2_001 }] })).toThrow(/between 0 and 2000 basis points/i);
  });
});

describe("commitments and selective disclosure", () => {
  it("detects a tampered amount and a tampered route salt", () => {
    const route = plan(CROSS_CHAIN);

    expect(verifyCrossChainRoute({ ...route, fundingBaseUnits: "1" })).toBe(false);
    expect(verifyCrossChainRoute({ ...route, routeSalt: "0x2" })).toBe(false);
    expect(verifyCrossChainRoute({ ...route, memo: "different memo" })).toBe(false);
    expect(verifyCrossChainRoute({ ...route, legs: [{ ...route.legs[0], recipient: PAYEE }, route.legs[1], route.legs[2]] })).toBe(false);
  });

  it("publishes a digest that carries no amount, address, salt, or memo", () => {
    const route = plan(CROSS_CHAIN);
    const digest = buildRouteDigest(route);
    const encoded = JSON.stringify(digest);

    expect(digest.legs.map((leg) => leg.legCommitment)).toEqual(route.legs.map((leg) => leg.legCommitment));
    expect(encoded).not.toContain(route.routeSalt);
    expect(encoded).not.toContain(route.legs[0].salt);
    expect(encoded).not.toContain(route.fundingBaseUnits);
    expect(encoded).not.toContain(BRIDGE_DEPOSIT);
    expect(encoded).not.toContain("Contractor IBAN");
    expect(encoded).not.toContain("Contractor payout August");
    expect(parseRouteDigest(serializeRouteDigest(digest))).toEqual(digest);
  });

  it("opens one leg against a published digest and rejects a doctored opening", () => {
    const route = plan(CROSS_CHAIN);
    const digest = buildRouteDigest(route);
    const opening = openRouteLeg(route, 1);

    expect(verifyRouteLegOpening(digest, opening)).toBe(true);
    expect(verifyRouteLegOpening(digest, { ...opening, leg: { ...opening.leg, grossInBaseUnits: "1" } })).toBe(false);
    expect(verifyRouteLegOpening(digest, { ...opening, leg: { ...opening.leg, recipientLabel: "Someone else" } })).toBe(false);
    expect(verifyRouteLegOpening(digest, { ...opening, routeCommitment: "0x5" })).toBe(false);
    expect(() => openRouteLeg(route, 9)).toThrow(/does not exist/i);
  });

  it("survives a serialize and parse round trip, and gives independent routes independent commitments", () => {
    const route = plan(CROSS_CHAIN);
    const twin = plan(CROSS_CHAIN, 2);

    expect(parseCrossChainRoute(serializeCrossChainRoute(route))).toEqual(route);
    expect(twin.fundingBaseUnits).toBe(route.fundingBaseUnits);
    expect(twin.routeSalt).not.toBe(route.routeSalt);
    expect(twin.routeCommitment).not.toBe(route.routeCommitment);
    expect(() => parseCrossChainRoute("not base64url!!")).toThrow(/encoding is invalid/i);
  });
});

describe("execution boundary", () => {
  it("builds one withdraw action for the Starknet part and stops at the first external leg", () => {
    const actions = buildStarknetLegActions(plan(CROSS_CHAIN), NOW);

    expect(actions).toEqual([{ type: "withdraw", token: USDC, amount: "100200201", recipient: BRIDGE_DEPOSIT }]);
  });

  it("builds an in-pool transfer without adding a second relayer-fee withdrawal", () => {
    const actions = buildStarknetLegActions(plan(POOL_ONLY), NOW);

    expect(actions).toEqual([{ type: "transfer", token: USDC, amount: "100000000", recipient: PAYEE }]);
    expect(actions.filter((action) => action.type === "withdraw")).toHaveLength(0);
  });

  it("refuses to build actions once the route deadline has passed", () => {
    expect(() => buildStarknetLegActions(plan(POOL_ONLY), new Date("2026-08-25T00:00:00.000Z"))).toThrow(/passed its deadline/i);
  });

  it("names the leg where this application stops and the amount it hands off", () => {
    const boundary = getRouteExecutionBoundary(plan(CROSS_CHAIN));

    expect(boundary).toMatchObject({
      executableLegCount: 1,
      executableLegs: [0],
      firstExternalLegIndex: 1,
      firstExternalLegSummary: "Leg 2: Starknet mainnet to Base via Circle CCTP.",
      handoffAmountBaseUnits: "100200201",
      handoffAssetSymbol: "USDC",
      publicWithdrawalCount: 1,
    });
    expect(boundary.statement).toContain("CipherBill can execute 1 of 3 legs");
    expect(getRouteExecutionBoundary(plan(POOL_ONLY)).statement).toContain("All 1 legs stay on Starknet");
  });
});

describe("visibility and trust", () => {
  it("says plainly that the pool exit publishes recipient, token, and exact amount", () => {
    const model = getRouteVisibilityModel(plan(CROSS_CHAIN));

    expect(model.publicOrObservable[0]).toBe("1 pool withdrawal with recipient, token, and exact amount");
    expect(model.hiddenInPool).toEqual(["nothing: this route contains no in-pool transfer"]);
    expect(model.applicationOnly).toContain("route salt");
    expect(model.outsideThisApplication[0]).toContain("Leg 2 on Base");
    expect(model.limitation).toMatch(/links the shielded balance to the destination address/i);
  });

  it("keeps an all-Starknet route's in-pool details hidden", () => {
    const model = getRouteVisibilityModel(plan(POOL_ONLY));

    expect(model.hiddenInPool).toContain("in-pool sender and recipient");
    expect(model.outsideThisApplication).toEqual(["none: every leg stays on Starknet"]);
  });

  it("enumerates the parties an external leg trusts and refuses to call the route trustless", () => {
    const summary = summarizeRouteTrust(plan(CROSS_CHAIN));

    expect(summary.starknetLegs).toBe(1);
    expect(summary.externalLegs).toBe(2);
    expect(summary.isFullyExecutableHere).toBe(false);
    expect(summary.trustedParties).toEqual([...BRIDGE_OPERATORS.circle_cctp.trustedParties]);
    expect(summary.statement).toContain("neither proven nor enforced");
    expect(summary.operators[0].note).toContain("CipherBill never calls it");
  });

  it("reports an all-Starknet route as verified onchain with no third party", () => {
    const summary = summarizeRouteTrust(plan(POOL_ONLY));

    expect(summary).toMatchObject({ starknetLegs: 1, externalLegs: 0, operators: [], trustedParties: [], isFullyExecutableHere: true });
    expect(summary.statement).toContain("No third party is trusted");
  });

  it("formats base units for display", () => {
    expect(formatRouteBaseUnits("100200201", 6)).toBe("100.200201");
    expect(formatRouteBaseUnits(9000n, 2)).toBe("90");
    expect(formatRouteBaseUnits("0", 18)).toBe("0");
    expect(() => formatRouteBaseUnits("1", 19)).toThrow(/between 0 and 18/i);
  });
});
