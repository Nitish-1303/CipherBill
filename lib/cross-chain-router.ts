/**
 * Cross-chain settlement route planner for CipherBill.
 *
 * WHAT THIS IS
 * - An exact-integer planner for a multi-hop invoice settlement that starts inside the
 *   STRK20 privacy pool on Starknet mainnet and may end on another network.
 * - A solver that works backwards from the amount the payee must receive to the amount
 *   that must leave the shielded balance, charging every declared leg fee and venue rate
 *   in bigint arithmetic with a stated rounding direction and a minimality guarantee.
 * - A builder for the Wallet API actions of the leading Starknet legs only (`transfer`
 *   inside the pool, `withdraw` to a public Starknet address), plus an explicit
 *   execution boundary naming the first leg this application cannot perform.
 * - A salted Poseidon commitment scheme so a merchant and a payer can agree on a route,
 *   share a digest that hides amounts and addresses, and later open one leg for an auditor.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not a bridge, swap, or liquidity router that moves value. It moves nothing off
 *   Starknet. The STRK20 Wallet API is exactly three methods -- `wallet_strk20InvokeTransaction`,
 *   `wallet_strk20PrepareInvoke`, `wallet_strk20Balances` -- over four action types
 *   (`deposit`, `withdraw`, `transfer`, `invoke`), all of which act on the single Starknet
 *   pool contract. No cross-chain, bridge, swap, or multi-hop method exists in that surface.
 * - Not zero-knowledge. CipherBill generates no proof of any kind: the wallet proves the
 *   transaction and the pool verifies it onchain, and `wallet_strk20InvokeTransaction`
 *   returns only `{ transaction_hash }`. The commitments below are salted Poseidon hashes.
 *   They hide and bind, but they are not zk-SNARKs and no contract ever verifies them.
 * - Not untraceable. Every hop that leaves Starknet must first exit the pool through a
 *   `withdraw`, which publishes recipient, token, and amount at the pool edge. A
 *   cross-chain route is the most publicly visible settlement CipherBill can plan, and
 *   the per-leg visibility model says exactly that.
 * - Not trustless. External legs depend on a bridge operator, its relayer or attestation
 *   set, and destination liquidity. Those trusted parties are enumerated per operator.
 * - Not a price oracle. Venue rates are caller-supplied and committed as given. This
 *   module checks arithmetic, never whether a rate is fair or a venue is solvent.
 * - Planning writes nothing anywhere. `STRK20_POOL_ADDRESS` is recorded as provenance for
 *   the Starknet legs, not as a contract that sees, stores, or validates a route.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const CROSS_CHAIN_ROUTER_VERSION = 1 as const;
export const CROSS_CHAIN_ROUTER_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const FEE_BPS_DENOMINATOR = 10_000n;
export const MAX_ROUTE_LEGS = 6;
export const MAX_LEG_FEE_BPS = 2_000;
export const MAX_ASSET_DECIMALS = 18;
export const MAX_RATE_DECIMALS = 18;
export const MAX_ROUTE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;
export const ROUTE_SALT_BYTES = 31;

/**
 * Settlement venues a route may traverse. `execution` is the load-bearing field:
 * `starknet_wallet_api` legs are the only ones this application can build actions for.
 */
export const SETTLEMENT_VENUES = {
  strk20_pool: { label: "STRK20 privacy pool", network: "Starknet mainnet", family: "starknet", execution: "starknet_wallet_api", confidentiality: "shielded" },
  starknet_public: { label: "Starknet public account", network: "Starknet mainnet", family: "starknet", execution: "starknet_wallet_api", confidentiality: "public" },
  ethereum: { label: "Ethereum account", network: "Ethereum mainnet", family: "ethereum_l1", execution: "external_operator", confidentiality: "public" },
  base: { label: "Base account", network: "Base", family: "ethereum_l2", execution: "external_operator", confidentiality: "public" },
  arbitrum: { label: "Arbitrum account", network: "Arbitrum One", family: "ethereum_l2", execution: "external_operator", confidentiality: "public" },
  optimism: { label: "Optimism account", network: "OP Mainnet", family: "ethereum_l2", execution: "external_operator", confidentiality: "public" },
  polygon: { label: "Polygon account", network: "Polygon PoS", family: "sidechain", execution: "external_operator", confidentiality: "public" },
  avalanche: { label: "Avalanche account", network: "Avalanche C-Chain", family: "sidechain", execution: "external_operator", confidentiality: "public" },
} as const;

export type SettlementVenueId = keyof typeof SETTLEMENT_VENUES;
export type LegExecution = (typeof SETTLEMENT_VENUES)[SettlementVenueId]["execution"];

/**
 * Operators an external leg would have to rely on. `trustedParties` is deliberately
 * verbose: the point of this registry is that a route out of Starknet is not trustless.
 */
export const BRIDGE_OPERATORS = {
  circle_cctp: {
    label: "Circle CCTP",
    trustedParties: ["Circle attestation service", "destination-chain message transmitter", "USDC issuer"],
    note: "The STRK20 Privacy Bridge (starkware-libs/privacy-bridge) moves EVM USDC over CCTP and its own documentation calls it early. CipherBill never calls it; this leg is a plan for a human or another tool to carry out.",
  },
  starkgate: {
    label: "StarkGate canonical bridge",
    trustedParties: ["StarkGate L1 and L2 bridge contracts", "Starknet proof settlement on Ethereum"],
    note: "Canonical Starknet withdrawals settle on Ethereum only after Starknet proves the block on L1, so this leg is slow and its timing is public.",
  },
  third_party_bridge: {
    label: "Third-party bridge or liquidity venue",
    trustedParties: ["bridge operator", "relayer or validator set", "destination liquidity provider"],
    note: "Custody, censorship, and solvency risk sit entirely with the chosen venue. CipherBill neither integrates nor audits it.",
  },
  manual_transfer: {
    label: "Manual or OTC transfer",
    trustedParties: ["counterparty performing the transfer"],
    note: "A human step. Nothing is enforced, proven, or observed by this application.",
  },
} as const;

export type BridgeOperatorId = keyof typeof BRIDGE_OPERATORS;

const ROUTE_KIND = "cipherbill.cross-chain-route" as const;
const DIGEST_KIND = "cipherbill.cross-chain-route-digest" as const;
const ROUTE_DOMAIN = hash.starknetKeccak("CipherBill cross-chain route v1");
const LEG_DOMAIN = hash.starknetKeccak("CipherBill cross-chain route leg v1");
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_ROUTE_LENGTH = 200_000;

const ROUTE_NOTICE = "Client-side settlement plan. Starknet legs are executable through the STRK20 Wallet API; every other leg is a plan for a human or an external tool. Withdrawing from the pool publishes recipient, token, and amount onchain.";

const ROUTE_LIMITATIONS = [
  "No value is bridged, swapped, or routed by this application. Only the leading Starknet legs become Wallet API actions.",
  "Route commitments are salted Poseidon hashes. They are not zero-knowledge proofs and no contract verifies them.",
  "Any leg that leaves Starknet begins with a public pool withdrawal that reveals the recipient address, token, and exact amount.",
  "External legs are only as trustworthy as the operator named on them; CipherBill does not integrate, monitor, or audit any of them.",
  "Venue rates and fees are caller-supplied. Arithmetic is checked exactly; fairness, liquidity, and solvency are not.",
  "A cross-chain route makes timing correlation easy. Splitting the pool exit from the bridge step in time reduces, but never removes, that linkage.",
] as const;

/** Leg kinds. `pool_*` legs are executable here; `external_*` legs never are. */
export type RouteLegKind = "pool_private_transfer" | "pool_withdraw" | "external_bridge" | "external_payout";

export type RouteProvenance = "starknet_proof_by_wallet" | "not_proven_by_this_application";

export interface RouteAsset {
  symbol: string;
  tokenAddress: string | null;
  decimals: number;
}

export interface RouteLegInput {
  kind: RouteLegKind;
  toVenue: SettlementVenueId;
  asset: { symbol: string; tokenAddress?: string; decimals: number };
  recipient?: string;
  recipientLabel?: string;
  operator?: BridgeOperatorId;
  feeBps?: number;
  fixedFeeBaseUnits?: string;
  /** Units of this leg's output asset per unit of its input asset. Defaults to "1". */
  rate?: string;
  estimatedSeconds?: number;
}

export interface PlanCrossChainRouteInput {
  invoiceId: string;
  sourceAsset: { symbol: string; tokenAddress: string; decimals: number };
  /** Decimal amount the final payee must receive, in the last leg's asset. */
  deliveryAmount: string;
  legs: RouteLegInput[];
  deadline: string;
  memo?: string;
}

export interface RouteLegVisibility {
  hidden: string[];
  publicOrObservable: string[];
}

export interface RouteLeg {
  index: number;
  kind: RouteLegKind;
  execution: LegExecution;
  fromVenue: SettlementVenueId;
  toVenue: SettlementVenueId;
  inputAsset: RouteAsset;
  outputAsset: RouteAsset;
  recipient: string | null;
  recipientLabel: string;
  operator: BridgeOperatorId | null;
  feeBps: number;
  fixedFeeBaseUnits: string;
  rateNumerator: string;
  rateScale: string;
  normalizedRate: string;
  grossInBaseUnits: string;
  proportionalFeeBaseUnits: string;
  netInBaseUnits: string;
  deliveredOutBaseUnits: string;
  requiredOutBaseUnits: string;
  surplusOutBaseUnits: string;
  grossInDisplay: string;
  deliveredOutDisplay: string;
  totalFeeDisplay: string;
  estimatedSeconds: number;
  provenance: RouteProvenance;
  trustedParties: string[];
  visibility: RouteLegVisibility;
  /** Secret per-leg blinding factor. Never share a route object; share `buildRouteDigest` output. */
  salt: string;
  legCommitment: string;
}

export interface RouteFeeTotal {
  symbol: string;
  tokenAddress: string | null;
  decimals: number;
  feeBaseUnits: string;
  feeDisplay: string;
}

export interface CrossChainRoute {
  kind: typeof ROUTE_KIND;
  version: typeof CROSS_CHAIN_ROUTER_VERSION;
  routeId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  sourceAsset: RouteAsset;
  /** Secret route-level blinding factor. Excluded from `buildRouteDigest` output. */
  routeSalt: string;
  fundingBaseUnits: string;
  fundingDisplay: string;
  deliveryBaseUnits: string;
  deliveryDisplay: string;
  legs: RouteLeg[];
  feeTotals: RouteFeeTotal[];
  executableLegCount: number;
  estimatedTotalSeconds: number;
  deadline: string;
  createdAt: string;
  memo: string;
  routeCommitment: string;
  notice: typeof ROUTE_NOTICE;
  limitations: string[];
}

/** Leg fields safe to publish: no amount, no fee, no address, no salt. */
export interface RouteDigestLeg {
  index: number;
  kind: RouteLegKind;
  execution: LegExecution;
  fromVenue: SettlementVenueId;
  toVenue: SettlementVenueId;
  assetSymbol: string;
  operator: BridgeOperatorId | null;
  provenance: RouteProvenance;
  legCommitment: string;
}

export interface CrossChainRouteDigest {
  kind: typeof DIGEST_KIND;
  version: typeof CROSS_CHAIN_ROUTER_VERSION;
  routeId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  legs: RouteDigestLeg[];
  executableLegCount: number;
  deadline: string;
  createdAt: string;
  routeCommitment: string;
  notice: typeof ROUTE_NOTICE;
  limitations: string[];
}

/** One leg disclosed against a published digest, for an auditor or a counterparty. */
export interface RouteLegOpening {
  routeId: string;
  routeCommitment: string;
  leg: RouteLeg;
}

export interface RouteExecutionBoundary {
  executableLegCount: number;
  executableLegs: number[];
  firstExternalLegIndex: number | null;
  firstExternalLegSummary: string | null;
  handoffAmountBaseUnits: string | null;
  handoffAssetSymbol: string | null;
  publicWithdrawalCount: number;
  statement: string;
}

export interface RouteVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  outsideThisApplication: string[];
  limitation: string;
}

export interface RouteTrustSummary {
  starknetLegs: number;
  externalLegs: number;
  operators: Array<{ operator: BridgeOperatorId; label: string; trustedParties: string[]; note: string }>;
  trustedParties: string[];
  isFullyExecutableHere: boolean;
  statement: string;
}

interface RouteEntropy {
  createId?: () => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

interface ParsedRate {
  numerator: bigint;
  scale: bigint;
  normalized: string;
}

interface LegEconomics {
  feeBps: number;
  fixedFee: bigint;
  rate: ParsedRate;
  inDecimals: number;
  outDecimals: number;
}

/**
 * Solves a settlement route backwards from the amount the payee must receive.
 *
 * Rounding is fixed and adversarial to the sender: proportional fees round up, venue
 * conversions round down, and the funding amount is the *smallest* input for which every
 * leg still delivers at least what the next leg needs. `surplusOutBaseUnits` reports the
 * dust that rounding leaves behind on each leg; this planner never tries to reclaim it.
 */
export function planCrossChainRoute(
  input: PlanCrossChainRouteInput,
  now = new Date(),
  entropy: RouteEntropy = {},
): CrossChainRoute {
  const createdAt = requireIsoTimestamp(now.toISOString(), "Route creation time");
  const deadline = requireIsoTimestamp(input.deadline, "Route deadline");
  if (Date.parse(deadline) <= now.getTime()) throw new Error("Route deadline must be in the future.");
  if (Date.parse(deadline) - now.getTime() > MAX_ROUTE_LIFETIME_MS) throw new Error("Route deadline must be within 7 days.");
  if (!Array.isArray(input.legs) || input.legs.length < 1 || input.legs.length > MAX_ROUTE_LEGS) {
    throw new Error(`A route needs between 1 and ${MAX_ROUTE_LEGS} legs.`);
  }

  const sourceAsset: RouteAsset = {
    symbol: requireSymbol(input.sourceAsset?.symbol, "Source token symbol"),
    tokenAddress: normalizeStarknetAddress(input.sourceAsset?.tokenAddress ?? ""),
    decimals: requireDecimals(input.sourceAsset?.decimals, "Source token decimals"),
  };
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const prepared = input.legs.map((leg, index) => prepareLeg(
    leg,
    index,
    index === 0 ? sourceAsset : normalizeLegAsset(input.legs[index - 1], index - 1),
    index === 0 ? "strk20_pool" : input.legs[index - 1].toVenue,
  ));
  assertRouteShape(prepared);

  const finalLeg = prepared[prepared.length - 1];
  const deliveryBaseUnits = parseDecimalToBaseUnits(input.deliveryAmount, finalLeg.outputAsset.decimals, "Delivery amount");
  requireU128(deliveryBaseUnits, "Delivery amount");

  const requiredOut: bigint[] = new Array(prepared.length);
  const grossIn: bigint[] = new Array(prepared.length);
  let carried = deliveryBaseUnits;
  for (let index = prepared.length - 1; index >= 0; index -= 1) {
    requiredOut[index] = carried;
    const gross = solveLegGrossInput(prepared[index].economics, carried);
    requireU128(gross, `Leg ${index + 1} input amount`);
    grossIn[index] = gross;
    carried = gross;
  }

  const legs: RouteLeg[] = prepared.map((leg, index) => {
    const forward = applyLegForward(leg.economics, grossIn[index]);
    const target = index === prepared.length - 1 ? deliveryBaseUnits : grossIn[index + 1];
    if (forward.out < target) throw new Error(`Leg ${index + 1} cannot deliver the amount the next step requires.`);
    if (grossIn[index] > 1n && applyLegForward(leg.economics, grossIn[index] - 1n, true).out >= requiredOut[index]) {
      throw new Error(`Leg ${index + 1} input amount is not minimal.`);
    }
    const salt = toHex(randomFelt(random));
    const draft: Omit<RouteLeg, "legCommitment"> = {
      index,
      kind: leg.kind,
      execution: leg.execution,
      fromVenue: leg.fromVenue,
      toVenue: leg.toVenue,
      inputAsset: leg.inputAsset,
      outputAsset: leg.outputAsset,
      recipient: leg.recipient,
      recipientLabel: leg.recipientLabel,
      operator: leg.operator,
      feeBps: leg.economics.feeBps,
      fixedFeeBaseUnits: leg.economics.fixedFee.toString(),
      rateNumerator: leg.economics.rate.numerator.toString(),
      rateScale: leg.economics.rate.scale.toString(),
      normalizedRate: leg.economics.rate.normalized,
      grossInBaseUnits: grossIn[index].toString(),
      proportionalFeeBaseUnits: forward.proportionalFee.toString(),
      netInBaseUnits: forward.net.toString(),
      deliveredOutBaseUnits: forward.out.toString(),
      requiredOutBaseUnits: target.toString(),
      surplusOutBaseUnits: (forward.out - target).toString(),
      grossInDisplay: formatBaseUnits(grossIn[index], leg.inputAsset.decimals),
      deliveredOutDisplay: formatBaseUnits(forward.out, leg.outputAsset.decimals),
      totalFeeDisplay: formatBaseUnits(forward.proportionalFee + leg.economics.fixedFee, leg.inputAsset.decimals),
      estimatedSeconds: leg.estimatedSeconds,
      provenance: leg.provenance,
      trustedParties: leg.trustedParties,
      visibility: leg.visibility,
      salt,
    };
    return { ...draft, legCommitment: toHex(computeLegCommitment(draft)) };
  });

  const routeSalt = toHex(randomFelt(random));
  const header: Omit<CrossChainRoute, "routeCommitment"> = {
    kind: ROUTE_KIND,
    version: CROSS_CHAIN_ROUTER_VERSION,
    routeId: entropy.createId?.() ?? `route_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    sourceAsset,
    routeSalt,
    fundingBaseUnits: grossIn[0].toString(),
    fundingDisplay: formatBaseUnits(grossIn[0], sourceAsset.decimals),
    deliveryBaseUnits: deliveryBaseUnits.toString(),
    deliveryDisplay: formatBaseUnits(deliveryBaseUnits, finalLeg.outputAsset.decimals),
    legs,
    feeTotals: summarizeFeeTotals(legs),
    executableLegCount: legs.filter((leg) => leg.execution === "starknet_wallet_api").length,
    estimatedTotalSeconds: legs.reduce((total, leg) => total + leg.estimatedSeconds, 0),
    deadline,
    createdAt,
    memo: requireOptionalText(input.memo ?? "", "Route memo", 160),
    notice: ROUTE_NOTICE,
    limitations: [...ROUTE_LIMITATIONS],
  };
  if (!/^route_[A-Za-z0-9_-]{1,48}$/.test(header.routeId)) throw new Error("Route ID is invalid.");
  const route: CrossChainRoute = { ...header, routeCommitment: toHex(computeRouteCommitment(header)) };
  assertCrossChainRoute(route);
  return route;
}

export function verifyCrossChainRoute(route: CrossChainRoute): boolean {
  try {
    assertCrossChainRoute(route);
    return true;
  } catch {
    return false;
  }
}

export function assertRouteOpen(route: CrossChainRoute, now = new Date()): void {
  assertCrossChainRoute(route);
  if (now.getTime() > Date.parse(route.deadline)) throw new Error("This settlement route has passed its deadline. Re-plan it against current venue quotes.");
}

/**
 * The only object safe to hand to a counterparty. Carries leg structure, venue labels, and
 * the commitments, and omits every amount, fee, address, memo, and salt.
 */
export function buildRouteDigest(route: CrossChainRoute): CrossChainRouteDigest {
  assertCrossChainRoute(route);
  return {
    kind: DIGEST_KIND,
    version: CROSS_CHAIN_ROUTER_VERSION,
    routeId: route.routeId,
    network: route.network,
    poolAddress: route.poolAddress,
    invoiceId: route.invoiceId,
    legs: route.legs.map((leg) => ({
      index: leg.index,
      kind: leg.kind,
      execution: leg.execution,
      fromVenue: leg.fromVenue,
      toVenue: leg.toVenue,
      assetSymbol: leg.outputAsset.symbol,
      operator: leg.operator,
      provenance: leg.provenance,
      legCommitment: leg.legCommitment,
    })),
    executableLegCount: route.executableLegCount,
    deadline: route.deadline,
    createdAt: route.createdAt,
    routeCommitment: route.routeCommitment,
    notice: ROUTE_NOTICE,
    limitations: [...ROUTE_LIMITATIONS],
  };
}

/** Discloses one leg in full so a counterparty can check it against a published digest. */
export function openRouteLeg(route: CrossChainRoute, index: number): RouteLegOpening {
  assertCrossChainRoute(route);
  const leg = route.legs[index];
  if (!leg) throw new Error("That route leg does not exist.");
  return { routeId: route.routeId, routeCommitment: route.routeCommitment, leg };
}

export function verifyRouteLegOpening(digest: CrossChainRouteDigest, opening: RouteLegOpening): boolean {
  try {
    assertRouteDigest(digest);
    if (digest.routeId !== opening.routeId || digest.routeCommitment !== opening.routeCommitment) return false;
    const published = digest.legs.find((leg) => leg.index === opening.leg.index);
    if (!published) return false;
    const { legCommitment, ...draft } = opening.leg;
    if (published.legCommitment !== legCommitment
      || published.kind !== draft.kind
      || published.execution !== draft.execution
      || published.fromVenue !== draft.fromVenue
      || published.toVenue !== draft.toVenue
      || published.assetSymbol !== draft.outputAsset.symbol
      || published.operator !== draft.operator
      || published.provenance !== draft.provenance) return false;
    return BigInt(legCommitment) === computeLegCommitment(draft);
  } catch {
    return false;
  }
}

/**
 * Builds Wallet API actions for the leading Starknet legs and nothing else.
 *
 * A `pool_private_transfer` becomes a `transfer` inside the pool; a `pool_withdraw`
 * becomes a public `withdraw`. The array stops at the first leg this application cannot
 * perform. No relayer-fee withdrawal is added: `wallet_strk20InvokeTransaction` appends
 * its own, and a second one would double-charge the payer.
 */
export function buildStarknetLegActions(route: CrossChainRoute, now = new Date()): STRK20_ACTION[] {
  assertRouteOpen(route, now);
  const actions: STRK20_ACTION[] = [];
  for (const leg of route.legs) {
    if (leg.execution !== "starknet_wallet_api") break;
    const token = leg.inputAsset.tokenAddress;
    const recipient = leg.recipient;
    if (!token || !recipient) throw new Error(`Leg ${leg.index + 1} is missing the Starknet token or recipient it needs.`);
    actions.push(leg.kind === "pool_withdraw"
      ? { type: "withdraw", token, amount: leg.grossInBaseUnits, recipient }
      : { type: "transfer", token, amount: leg.grossInBaseUnits, recipient });
  }
  if (!actions.length) throw new Error("This route has no leg that CipherBill can execute.");
  return actions;
}

export function getRouteExecutionBoundary(route: CrossChainRoute): RouteExecutionBoundary {
  assertCrossChainRoute(route);
  const executable = route.legs.filter((leg) => leg.execution === "starknet_wallet_api");
  const external = route.legs.find((leg) => leg.execution !== "starknet_wallet_api") ?? null;
  const publicWithdrawalCount = route.legs.filter((leg) => leg.kind === "pool_withdraw").length;
  const operatorLabel = external?.operator ? BRIDGE_OPERATORS[external.operator].label : "an external venue";
  return {
    executableLegCount: executable.length,
    executableLegs: executable.map((leg) => leg.index),
    firstExternalLegIndex: external ? external.index : null,
    firstExternalLegSummary: external
      ? `Leg ${external.index + 1}: ${SETTLEMENT_VENUES[external.fromVenue].network} to ${SETTLEMENT_VENUES[external.toVenue].network} via ${operatorLabel}.`
      : null,
    handoffAmountBaseUnits: external ? external.grossInBaseUnits : null,
    handoffAssetSymbol: external ? external.inputAsset.symbol : null,
    publicWithdrawalCount,
    statement: external
      ? `CipherBill can execute ${executable.length} of ${route.legs.length} legs. Leg ${external.index + 1} onward must be carried out in ${operatorLabel}, outside this application, and CipherBill cannot observe, prove, or enforce it.`
      : `All ${route.legs.length} legs stay on Starknet and are executable through the STRK20 Wallet API.`,
  };
}

export function getRouteVisibilityModel(route: CrossChainRoute): RouteVisibilityModel {
  assertCrossChainRoute(route);
  const exits = route.legs.filter((leg) => leg.kind === "pool_withdraw");
  const external = route.legs.filter((leg) => leg.execution !== "starknet_wallet_api");
  return {
    applicationOnly: ["invoice ID", "route memo", "per-leg salts", "route salt", "fee and rate assumptions", "external recipient labels"],
    walletRequest: ["token addresses of the Starknet legs", "exact base-unit amounts of those legs", "in-pool recipients", "public withdrawal recipients"],
    hiddenInPool: route.legs.some((leg) => leg.kind === "pool_private_transfer")
      ? ["in-pool sender and recipient", "token and amount of in-pool transfers", "which encrypted notes were spent"]
      : ["nothing: this route contains no in-pool transfer"],
    publicOrObservable: exits.length
      ? [`${exits.length} pool withdrawal${exits.length === 1 ? "" : "s"} with recipient, token, and exact amount`, "withdrawal timing", "published nullifiers, unlinkable without a viewing key"]
      : ["published nullifiers, unlinkable without a viewing key", "transaction timing and fees"],
    outsideThisApplication: external.length
      ? external.map((leg) => `Leg ${leg.index + 1} on ${SETTLEMENT_VENUES[leg.toVenue].network}: fully public to that network and to ${leg.operator ? BRIDGE_OPERATORS[leg.operator].label : "the venue"}.`)
      : ["none: every leg stays on Starknet"],
    limitation: "A pool exit followed closely by a bridge deposit of the same amount links the shielded balance to the destination address by timing and value. Separate the two steps in time and avoid distinctive amounts.",
  };
}

export function summarizeRouteTrust(route: CrossChainRoute): RouteTrustSummary {
  assertCrossChainRoute(route);
  const starknetLegs = route.legs.filter((leg) => leg.execution === "starknet_wallet_api").length;
  const externalLegs = route.legs.length - starknetLegs;
  const operatorIds = [...new Set(route.legs.flatMap((leg) => leg.operator ? [leg.operator] : []))];
  const operators = operatorIds.map((operator) => ({ operator, ...BRIDGE_OPERATORS[operator], trustedParties: [...BRIDGE_OPERATORS[operator].trustedParties] }));
  const trustedParties = [...new Set(operators.flatMap((entry) => entry.trustedParties))];
  return {
    starknetLegs,
    externalLegs,
    operators,
    trustedParties,
    isFullyExecutableHere: externalLegs === 0,
    statement: externalLegs === 0
      ? "Every leg is verified onchain by the STRK20 pool after the wallet proves the transaction. No third party is trusted."
      : `${externalLegs} leg${externalLegs === 1 ? "" : "s"} depend on ${trustedParties.length} party or parties outside Starknet. Those legs are neither proven nor enforced, by this application or by the pool.`,
  };
}

export function serializeCrossChainRoute(route: CrossChainRoute): string {
  assertCrossChainRoute(route);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(route)));
}

export function parseCrossChainRoute(encoded: string): CrossChainRoute {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_ROUTE_LENGTH, "Settlement route");
  assertCrossChainRoute(parsed);
  return parsed;
}

export function serializeRouteDigest(digest: CrossChainRouteDigest): string {
  assertRouteDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseRouteDigest(encoded: string): CrossChainRouteDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_ROUTE_LENGTH, "Route digest");
  assertRouteDigest(parsed);
  return parsed;
}

export function formatRouteBaseUnits(value: string | bigint, decimals: number): string {
  const amount = typeof value === "bigint" ? value : BigInt(value);
  return formatBaseUnits(amount, requireDecimals(decimals, "Asset decimals"));
}

interface PreparedLeg {
  kind: RouteLegKind;
  execution: LegExecution;
  fromVenue: SettlementVenueId;
  toVenue: SettlementVenueId;
  inputAsset: RouteAsset;
  outputAsset: RouteAsset;
  recipient: string | null;
  recipientLabel: string;
  operator: BridgeOperatorId | null;
  estimatedSeconds: number;
  provenance: RouteProvenance;
  trustedParties: string[];
  visibility: RouteLegVisibility;
  economics: LegEconomics;
}

const DEFAULT_LEG_SECONDS: Record<RouteLegKind, number> = {
  pool_private_transfer: 60,
  pool_withdraw: 90,
  external_bridge: 900,
  external_payout: 300,
};

function normalizeLegAsset(leg: RouteLegInput, index: number): RouteAsset {
  const isPoolLeg = leg?.kind === "pool_private_transfer" || leg?.kind === "pool_withdraw";
  if (isPoolLeg && !leg.asset?.tokenAddress) throw new Error(`Leg ${index + 1} settles on Starknet and needs its token contract address.`);
  return {
    symbol: requireSymbol(leg?.asset?.symbol, "Leg token symbol"),
    tokenAddress: leg?.asset?.tokenAddress ? normalizeStarknetAddress(leg.asset.tokenAddress) : null,
    decimals: requireDecimals(leg?.asset?.decimals, "Leg token decimals"),
  };
}

function prepareLeg(leg: RouteLegInput, index: number, inputAsset: RouteAsset, fromVenue: SettlementVenueId): PreparedLeg {
  const kind = leg?.kind;
  if (!kind || !(kind in DEFAULT_LEG_SECONDS)) throw new Error(`Leg ${index + 1} has an unsupported kind.`);
  const isPoolLeg = kind === "pool_private_transfer" || kind === "pool_withdraw";
  const toVenue = leg.toVenue;
  if (!toVenue || !(toVenue in SETTLEMENT_VENUES)) throw new Error(`Leg ${index + 1} has an unsupported destination venue.`);
  const outputAsset = normalizeLegAsset(leg, index);
  const execution: LegExecution = isPoolLeg ? "starknet_wallet_api" : "external_operator";
  const operator = leg.operator ?? null;
  if (operator !== null && !(operator in BRIDGE_OPERATORS)) throw new Error(`Leg ${index + 1} names an unknown operator.`);
  if (isPoolLeg && operator) throw new Error(`Leg ${index + 1} runs inside Starknet and must not name an external operator.`);
  if (kind === "external_bridge" && !operator) throw new Error(`Leg ${index + 1} crosses networks and must name the operator it relies on.`);

  if (isPoolLeg) {
    if (fromVenue !== "strk20_pool") throw new Error(`Leg ${index + 1} acts on the pool but does not start there.`);
    if (kind === "pool_private_transfer" && toVenue !== "strk20_pool") throw new Error(`Leg ${index + 1} is an in-pool transfer, so it must end inside the pool.`);
    if (kind === "pool_withdraw" && toVenue !== "starknet_public") throw new Error(`Leg ${index + 1} is a pool withdrawal, so it must end at a public Starknet address.`);
    if (outputAsset.tokenAddress !== inputAsset.tokenAddress || outputAsset.decimals !== inputAsset.decimals) {
      throw new Error(`Leg ${index + 1} runs inside the pool, which cannot change the token or its decimals.`);
    }
    if (leg.rate !== undefined && leg.rate !== "1") throw new Error(`Leg ${index + 1} runs inside the pool and cannot apply a venue rate.`);
  } else if (fromVenue === "strk20_pool") {
    throw new Error(`Leg ${index + 1} leaves Starknet, so it must be preceded by a pool withdrawal.`);
  }
  if (kind === "external_bridge" && fromVenue === toVenue) throw new Error(`Leg ${index + 1} is a bridge but does not change network.`);

  const recipient = isPoolLeg ? normalizeStarknetAddress(requireText(leg.recipient ?? "", `Leg ${index + 1} recipient`, 66)) : null;
  const recipientLabel = requireOptionalText(leg.recipientLabel ?? "", `Leg ${index + 1} recipient label`, 80);
  if (!isPoolLeg && !recipientLabel) throw new Error(`Leg ${index + 1} happens outside this application, so it needs a recipient label for reconciliation.`);
  const estimatedSeconds = leg.estimatedSeconds ?? DEFAULT_LEG_SECONDS[kind];
  if (!Number.isInteger(estimatedSeconds) || estimatedSeconds < 0 || estimatedSeconds > 2_592_000) {
    throw new Error(`Leg ${index + 1} duration estimate must be between 0 and 2592000 seconds.`);
  }
  const feeBps = leg.feeBps ?? 0;
  if (!Number.isInteger(feeBps) || feeBps < 0 || feeBps > MAX_LEG_FEE_BPS) throw new Error(`Leg ${index + 1} fee must be between 0 and ${MAX_LEG_FEE_BPS} basis points.`);
  const fixedFee = leg.fixedFeeBaseUnits === undefined ? 0n : requireBaseUnitString(leg.fixedFeeBaseUnits, `Leg ${index + 1} fixed fee`);
  if (fixedFee > U128_MAX) throw new Error(`Leg ${index + 1} fixed fee is outside the u128 range.`);

  return {
    kind,
    execution,
    fromVenue,
    toVenue,
    inputAsset,
    outputAsset,
    recipient,
    recipientLabel,
    operator,
    estimatedSeconds,
    provenance: isPoolLeg ? "starknet_proof_by_wallet" : "not_proven_by_this_application",
    trustedParties: operator ? [...BRIDGE_OPERATORS[operator].trustedParties] : [],
    visibility: legVisibility(kind, toVenue, operator),
    economics: {
      feeBps,
      fixedFee,
      rate: parsePositiveDecimal(leg.rate ?? "1", MAX_RATE_DECIMALS, `Leg ${index + 1} venue rate`),
      inDecimals: inputAsset.decimals,
      outDecimals: outputAsset.decimals,
    },
  };
}

function legVisibility(kind: RouteLegKind, toVenue: SettlementVenueId, operator: BridgeOperatorId | null): RouteLegVisibility {
  if (kind === "pool_private_transfer") {
    return {
      hidden: ["sender", "recipient", "token", "exact amount", "spent-note linkage"],
      publicOrObservable: ["a published nullifier, unlinkable without a viewing key", "transaction timing and fees"],
    };
  }
  if (kind === "pool_withdraw") {
    return {
      hidden: ["which encrypted notes funded the exit", "the payer's remaining shielded balance"],
      publicOrObservable: ["recipient address", "token address", "exact withdrawn amount", "timing"],
    };
  }
  const venue = SETTLEMENT_VENUES[toVenue];
  return {
    hidden: ["nothing: this leg happens outside the privacy pool"],
    publicOrObservable: [`${venue.network} sender and recipient`, "exact amount and fees", "timing", operator ? `full visibility for ${BRIDGE_OPERATORS[operator].label}` : "full visibility for the venue"],
  };
}

function assertRouteShape(legs: PreparedLeg[]): void {
  if (legs[0].fromVenue !== "strk20_pool") throw new Error("A route must be funded from the STRK20 shielded balance.");
  let leftStarknet = false;
  for (const [index, leg] of legs.entries()) {
    if (index > 0 && leg.fromVenue !== legs[index - 1].toVenue) throw new Error(`Leg ${index + 1} does not start where leg ${index} ended.`);
    if (leftStarknet && leg.execution === "starknet_wallet_api") {
      throw new Error("Once a route leaves Starknet, CipherBill cannot observe it returning, so no later leg may be marked executable here.");
    }
    if (leg.execution !== "starknet_wallet_api") leftStarknet = true;
  }
  if (legs.filter((leg) => leg.kind === "pool_withdraw").length > 1) {
    throw new Error("A route may exit the pool only once. A second withdrawal would publish a second linkable amount.");
  }
}

/** Fee rounds up, so `net` is what the venue actually forwards. */
function applyLegForward(economics: LegEconomics, gross: bigint, tolerant = false): { proportionalFee: bigint; net: bigint; out: bigint } {
  const proportionalFee = divideCeil(gross * BigInt(economics.feeBps), FEE_BPS_DENOMINATOR);
  const net = gross - proportionalFee - economics.fixedFee;
  if (net <= 0n) {
    if (tolerant) return { proportionalFee, net, out: 0n };
    throw new Error("A route leg's fees consume its entire input amount.");
  }
  const numerator = net * economics.rate.numerator * 10n ** BigInt(economics.outDecimals);
  const denominator = economics.rate.scale * 10n ** BigInt(economics.inDecimals);
  return { proportionalFee, net, out: numerator / denominator };
}

/** Smallest input for which `applyLegForward(...).out >= requiredOut`. */
function solveLegGrossInput(economics: LegEconomics, requiredOut: bigint): bigint {
  if (requiredOut <= 0n) throw new Error("A route leg must deliver a positive amount.");
  const netNumerator = requiredOut * economics.rate.scale * 10n ** BigInt(economics.inDecimals);
  const netDenominator = economics.rate.numerator * 10n ** BigInt(economics.outDecimals);
  const netRequired = divideCeil(netNumerator, netDenominator);
  const bps = BigInt(economics.feeBps);
  const netOf = (value: bigint) => value - divideCeil(value * bps, FEE_BPS_DENOMINATOR) - economics.fixedFee;
  let gross = bps === 0n
    ? netRequired + economics.fixedFee
    : divideCeil((netRequired + economics.fixedFee) * FEE_BPS_DENOMINATOR, FEE_BPS_DENOMINATOR - bps);
  for (let guard = 0; netOf(gross) < netRequired; guard += 1) {
    if (guard > 64) throw new Error("A route leg's fee schedule has no solution for the requested amount.");
    gross += 1n;
  }
  for (let guard = 0; gross > 1n && netOf(gross - 1n) >= netRequired; guard += 1) {
    if (guard > 64) throw new Error("A route leg's fee schedule has no minimal solution.");
    gross -= 1n;
  }
  return gross;
}

function summarizeFeeTotals(legs: RouteLeg[]): RouteFeeTotal[] {
  const totals = new Map<string, RouteFeeTotal & { raw: bigint }>();
  for (const leg of legs) {
    const key = `${leg.inputAsset.symbol}|${leg.inputAsset.tokenAddress ?? "external"}|${leg.inputAsset.decimals}`;
    const fee = BigInt(leg.proportionalFeeBaseUnits) + BigInt(leg.fixedFeeBaseUnits);
    const existing = totals.get(key);
    const raw = (existing?.raw ?? 0n) + fee;
    totals.set(key, {
      raw,
      symbol: leg.inputAsset.symbol,
      tokenAddress: leg.inputAsset.tokenAddress,
      decimals: leg.inputAsset.decimals,
      feeBaseUnits: raw.toString(),
      feeDisplay: formatBaseUnits(raw, leg.inputAsset.decimals),
    });
  }
  return [...totals.values()].map((total) => ({
    symbol: total.symbol,
    tokenAddress: total.tokenAddress,
    decimals: total.decimals,
    feeBaseUnits: total.feeBaseUnits,
    feeDisplay: total.feeDisplay,
  }));
}

function computeLegCommitment(leg: Omit<RouteLeg, "legCommitment">): bigint {
  return hashElements([
    LEG_DOMAIN,
    BigInt(leg.index),
    requireFelt(leg.salt, "Leg salt"),
    hash.starknetKeccak(leg.kind),
    hash.starknetKeccak(leg.execution),
    hash.starknetKeccak(leg.fromVenue),
    hash.starknetKeccak(leg.toVenue),
    hash.starknetKeccak(leg.inputAsset.symbol),
    leg.inputAsset.tokenAddress ? BigInt(leg.inputAsset.tokenAddress) : 0n,
    BigInt(leg.inputAsset.decimals),
    hash.starknetKeccak(leg.outputAsset.symbol),
    leg.outputAsset.tokenAddress ? BigInt(leg.outputAsset.tokenAddress) : 0n,
    BigInt(leg.outputAsset.decimals),
    leg.recipient ? BigInt(leg.recipient) : 0n,
    hash.starknetKeccak(leg.recipientLabel || "none"),
    leg.operator ? hash.starknetKeccak(leg.operator) : 0n,
    BigInt(leg.feeBps),
    BigInt(leg.fixedFeeBaseUnits),
    BigInt(leg.rateNumerator),
    BigInt(leg.rateScale),
    BigInt(leg.grossInBaseUnits),
    BigInt(leg.proportionalFeeBaseUnits),
    BigInt(leg.netInBaseUnits),
    BigInt(leg.deliveredOutBaseUnits),
    BigInt(leg.requiredOutBaseUnits),
    BigInt(leg.estimatedSeconds),
    hash.starknetKeccak(leg.provenance),
    BigInt(STRK20_POOL_ADDRESS),
  ]);
}

function computeRouteCommitment(route: Omit<CrossChainRoute, "routeCommitment">): bigint {
  return hashElements([
    ROUTE_DOMAIN,
    BigInt(route.version),
    requireFelt(route.routeSalt, "Route salt"),
    hash.starknetKeccak(route.routeId),
    hash.starknetKeccak(route.invoiceId),
    BigInt(STRK20_POOL_ADDRESS),
    hash.starknetKeccak(route.sourceAsset.symbol),
    BigInt(route.sourceAsset.tokenAddress ?? "0x0"),
    BigInt(route.sourceAsset.decimals),
    BigInt(route.fundingBaseUnits),
    BigInt(route.deliveryBaseUnits),
    BigInt(route.legs.length),
    ...route.legs.map((leg) => requireFelt(leg.legCommitment, "Leg commitment")),
    BigInt(Math.floor(Date.parse(route.deadline) / 1_000)),
    BigInt(Math.floor(Date.parse(route.createdAt) / 1_000)),
    hash.starknetKeccak(route.memo || "empty"),
  ]);
}

const ROUTE_KEYS = ["kind", "version", "routeId", "network", "poolAddress", "invoiceId", "sourceAsset", "routeSalt", "fundingBaseUnits", "fundingDisplay", "deliveryBaseUnits", "deliveryDisplay", "legs", "feeTotals", "executableLegCount", "estimatedTotalSeconds", "deadline", "createdAt", "memo", "routeCommitment", "notice", "limitations"];
const LEG_KEYS = ["index", "kind", "execution", "fromVenue", "toVenue", "inputAsset", "outputAsset", "recipient", "recipientLabel", "operator", "feeBps", "fixedFeeBaseUnits", "rateNumerator", "rateScale", "normalizedRate", "grossInBaseUnits", "proportionalFeeBaseUnits", "netInBaseUnits", "deliveredOutBaseUnits", "requiredOutBaseUnits", "surplusOutBaseUnits", "grossInDisplay", "deliveredOutDisplay", "totalFeeDisplay", "estimatedSeconds", "provenance", "trustedParties", "visibility", "salt", "legCommitment"];
const DIGEST_KEYS = ["kind", "version", "routeId", "network", "poolAddress", "invoiceId", "legs", "executableLegCount", "deadline", "createdAt", "routeCommitment", "notice", "limitations"];
const DIGEST_LEG_KEYS = ["index", "kind", "execution", "fromVenue", "toVenue", "assetSymbol", "operator", "provenance", "legCommitment"];
const ASSET_KEYS = ["symbol", "tokenAddress", "decimals"];

function assertCrossChainRoute(value: unknown): asserts value is CrossChainRoute {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Settlement route is invalid.");
  const route = value as CrossChainRoute;
  if (Object.keys(route).some((key) => !ROUTE_KEYS.includes(key))
    || route.kind !== ROUTE_KIND
    || route.version !== CROSS_CHAIN_ROUTER_VERSION
    || route.network !== MAINNET_CHAIN_ID
    || route.poolAddress !== STRK20_POOL_ADDRESS
    || route.notice !== ROUTE_NOTICE
    || !/^route_[A-Za-z0-9_-]{1,48}$/.test(route.routeId)) throw new Error("Settlement route header is invalid.");
  if (!Array.isArray(route.limitations) || route.limitations.length !== ROUTE_LIMITATIONS.length || route.limitations.some((entry, index) => entry !== ROUTE_LIMITATIONS[index])) {
    throw new Error("Settlement route limitations were altered.");
  }
  requireText(route.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireOptionalText(route.memo, "Route memo", 160);
  requireFelt(route.routeSalt, "Route salt");
  requireFelt(route.routeCommitment, "Route commitment");
  requireIsoTimestamp(route.createdAt, "Route creation time");
  requireIsoTimestamp(route.deadline, "Route deadline");
  if (Date.parse(route.deadline) <= Date.parse(route.createdAt) || Date.parse(route.deadline) - Date.parse(route.createdAt) > MAX_ROUTE_LIFETIME_MS) {
    throw new Error("Settlement route deadline is invalid.");
  }
  assertCanonicalAsset(route.sourceAsset, true, "Source asset");
  if (!Array.isArray(route.legs) || route.legs.length < 1 || route.legs.length > MAX_ROUTE_LEGS) throw new Error("Settlement route leg count is invalid.");

  const delivery = requireBaseUnitString(route.deliveryBaseUnits, "Delivery amount");
  requireU128(delivery, "Delivery amount");
  let expectedInput: RouteAsset = route.sourceAsset;
  let expectedFromVenue: SettlementVenueId = "strk20_pool";
  const grossIn: bigint[] = [];
  for (const [index, leg] of route.legs.entries()) {
    if (!leg || typeof leg !== "object" || Array.isArray(leg) || Object.keys(leg).some((key) => !LEG_KEYS.includes(key))) throw new Error(`Leg ${index + 1} is invalid.`);
    if (leg.index !== index) throw new Error(`Leg ${index + 1} is out of order.`);
    if (leg.fromVenue !== expectedFromVenue) throw new Error(`Leg ${index + 1} does not start where the previous leg ended.`);
    if (JSON.stringify(leg.inputAsset) !== JSON.stringify(expectedInput)) throw new Error(`Leg ${index + 1} input asset does not match the previous leg output.`);
    const rebuilt = prepareLeg(toLegInput(leg), index, expectedInput, expectedFromVenue);
    assertLegMatchesDeclaration(leg, rebuilt, index);
    grossIn.push(requireBaseUnitString(leg.grossInBaseUnits, `Leg ${index + 1} input amount`));
    expectedInput = leg.outputAsset;
    expectedFromVenue = leg.toVenue;
  }
  assertRouteShape(route.legs.map((leg, index) => prepareLeg(toLegInput(leg), index, leg.inputAsset, leg.fromVenue)));
  assertRouteEconomics(route, grossIn, delivery);
  if (BigInt(route.routeCommitment) !== computeRouteCommitment(route)) throw new Error("Settlement route commitment does not match its contents.");
}

function toLegInput(leg: RouteLeg): RouteLegInput {
  return {
    kind: leg.kind,
    toVenue: leg.toVenue,
    asset: { symbol: leg.outputAsset?.symbol, tokenAddress: leg.outputAsset?.tokenAddress ?? undefined, decimals: leg.outputAsset?.decimals },
    recipient: leg.recipient ?? undefined,
    recipientLabel: leg.recipientLabel,
    operator: leg.operator ?? undefined,
    feeBps: leg.feeBps,
    fixedFeeBaseUnits: leg.fixedFeeBaseUnits,
    rate: leg.normalizedRate,
    estimatedSeconds: leg.estimatedSeconds,
  };
}

function legEconomicsOf(leg: RouteLeg): LegEconomics {
  const rate = parsePositiveDecimal(leg.normalizedRate, MAX_RATE_DECIMALS, "Venue rate");
  if (rate.numerator.toString() !== leg.rateNumerator || rate.scale.toString() !== leg.rateScale) throw new Error(`Leg ${leg.index + 1} rate is not canonical.`);
  return {
    feeBps: leg.feeBps,
    fixedFee: BigInt(leg.fixedFeeBaseUnits),
    rate,
    inDecimals: leg.inputAsset.decimals,
    outDecimals: leg.outputAsset.decimals,
  };
}

function assertLegMatchesDeclaration(leg: RouteLeg, rebuilt: PreparedLeg, index: number): void {
  const declared = { execution: leg.execution, provenance: leg.provenance, trustedParties: leg.trustedParties, visibility: leg.visibility, recipient: leg.recipient, recipientLabel: leg.recipientLabel, operator: leg.operator, feeBps: leg.feeBps, outputAsset: leg.outputAsset, estimatedSeconds: leg.estimatedSeconds };
  const expected = { execution: rebuilt.execution, provenance: rebuilt.provenance, trustedParties: rebuilt.trustedParties, visibility: rebuilt.visibility, recipient: rebuilt.recipient, recipientLabel: rebuilt.recipientLabel, operator: rebuilt.operator, feeBps: rebuilt.economics.feeBps, outputAsset: rebuilt.outputAsset, estimatedSeconds: rebuilt.estimatedSeconds };
  if (JSON.stringify(declared) !== JSON.stringify(expected)) throw new Error(`Leg ${index + 1} labelling does not match its own declared parameters.`);
  assertCanonicalAsset(leg.outputAsset, leg.execution === "starknet_wallet_api", `Leg ${index + 1} asset`);
  requireFelt(leg.salt, `Leg ${index + 1} salt`);
  requireFelt(leg.legCommitment, `Leg ${index + 1} commitment`);
}

function assertRouteEconomics(route: CrossChainRoute, grossIn: bigint[], delivery: bigint): void {
  if (route.fundingBaseUnits !== grossIn[0].toString()) throw new Error("Settlement route funding amount does not match its first leg.");
  if (route.fundingDisplay !== formatBaseUnits(grossIn[0], route.sourceAsset.decimals)) throw new Error("Settlement route funding display amount is inconsistent.");
  const finalLeg = route.legs[route.legs.length - 1];
  if (route.deliveryDisplay !== formatBaseUnits(delivery, finalLeg.outputAsset.decimals)) throw new Error("Settlement route delivery display amount is inconsistent.");
  for (const [index, leg] of route.legs.entries()) {
    const economics = legEconomicsOf(leg);
    const requiredOut = index === route.legs.length - 1 ? delivery : grossIn[index + 1];
    requireU128(grossIn[index], `Leg ${index + 1} input amount`);
    const forward = applyLegForward(economics, grossIn[index]);
    const surplus = forward.out - requiredOut;
    if (surplus < 0n) throw new Error(`Leg ${index + 1} does not deliver what the next step requires.`);
    if (grossIn[index] > 1n && applyLegForward(economics, grossIn[index] - 1n, true).out >= requiredOut) throw new Error(`Leg ${index + 1} input amount is not minimal.`);
    if (leg.proportionalFeeBaseUnits !== forward.proportionalFee.toString()
      || leg.netInBaseUnits !== forward.net.toString()
      || leg.deliveredOutBaseUnits !== forward.out.toString()
      || leg.requiredOutBaseUnits !== requiredOut.toString()
      || leg.surplusOutBaseUnits !== surplus.toString()
      || leg.grossInDisplay !== formatBaseUnits(grossIn[index], leg.inputAsset.decimals)
      || leg.deliveredOutDisplay !== formatBaseUnits(forward.out, leg.outputAsset.decimals)
      || leg.totalFeeDisplay !== formatBaseUnits(forward.proportionalFee + economics.fixedFee, leg.inputAsset.decimals)) {
      throw new Error(`Leg ${index + 1} amounts do not match its own fee schedule.`);
    }
    if (BigInt(leg.legCommitment) !== computeLegCommitment(leg)) throw new Error(`Leg ${index + 1} commitment does not match its contents.`);
  }
  if (JSON.stringify(route.feeTotals) !== JSON.stringify(summarizeFeeTotals(route.legs))) throw new Error("Settlement route fee totals are inconsistent.");
  if (route.executableLegCount !== route.legs.filter((leg) => leg.execution === "starknet_wallet_api").length) throw new Error("Settlement route executable leg count is inconsistent.");
  if (route.estimatedTotalSeconds !== route.legs.reduce((total, leg) => total + leg.estimatedSeconds, 0)) throw new Error("Settlement route duration estimate is inconsistent.");
}

function assertRouteDigest(value: unknown): asserts value is CrossChainRouteDigest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Route digest is invalid.");
  const digest = value as CrossChainRouteDigest;
  if (Object.keys(digest).some((key) => !DIGEST_KEYS.includes(key))
    || digest.kind !== DIGEST_KIND
    || digest.version !== CROSS_CHAIN_ROUTER_VERSION
    || digest.network !== MAINNET_CHAIN_ID
    || digest.poolAddress !== STRK20_POOL_ADDRESS
    || digest.notice !== ROUTE_NOTICE
    || !/^route_[A-Za-z0-9_-]{1,48}$/.test(digest.routeId)) throw new Error("Route digest header is invalid.");
  if (!Array.isArray(digest.limitations) || digest.limitations.length !== ROUTE_LIMITATIONS.length || digest.limitations.some((entry, index) => entry !== ROUTE_LIMITATIONS[index])) {
    throw new Error("Route digest limitations were altered.");
  }
  requireText(digest.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireFelt(digest.routeCommitment, "Route commitment");
  requireIsoTimestamp(digest.createdAt, "Route creation time");
  requireIsoTimestamp(digest.deadline, "Route deadline");
  if (!Array.isArray(digest.legs) || digest.legs.length < 1 || digest.legs.length > MAX_ROUTE_LEGS) throw new Error("Route digest leg count is invalid.");
  digest.legs.forEach((leg, index) => {
    if (!leg || typeof leg !== "object" || Array.isArray(leg) || Object.keys(leg).some((key) => !DIGEST_LEG_KEYS.includes(key))) throw new Error(`Digest leg ${index + 1} is invalid.`);
    if (leg.index !== index) throw new Error(`Digest leg ${index + 1} is out of order.`);
    if (!(leg.kind in DEFAULT_LEG_SECONDS) || !(leg.fromVenue in SETTLEMENT_VENUES) || !(leg.toVenue in SETTLEMENT_VENUES)) throw new Error(`Digest leg ${index + 1} names an unknown kind or venue.`);
    if (leg.operator !== null && !(leg.operator in BRIDGE_OPERATORS)) throw new Error(`Digest leg ${index + 1} names an unknown operator.`);
    requireSymbol(leg.assetSymbol, `Digest leg ${index + 1} token symbol`);
    requireFelt(leg.legCommitment, `Digest leg ${index + 1} commitment`);
  });
  if (digest.executableLegCount !== digest.legs.filter((leg) => leg.execution === "starknet_wallet_api").length) {
    throw new Error("Route digest executable leg count is inconsistent.");
  }
}

function assertCanonicalAsset(asset: RouteAsset, requireStarknetToken: boolean, label: string): void {
  if (!asset || typeof asset !== "object" || Array.isArray(asset)) throw new Error(`${label} is invalid.`);
  const keys = Object.keys(asset);
  if (keys.length !== 3 || keys.some((key) => !ASSET_KEYS.includes(key))) throw new Error(`${label} has unexpected fields.`);
  if (asset.symbol !== requireSymbol(asset.symbol, `${label} symbol`)) throw new Error(`${label} symbol is not canonical.`);
  requireDecimals(asset.decimals, `${label} decimals`);
  if (requireStarknetToken) {
    if (!asset.tokenAddress || asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) throw new Error(`${label} token address is not canonical.`);
  } else if (asset.tokenAddress !== null && asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) {
    throw new Error(`${label} token address is not canonical.`);
  }
}

/** Draws a non-zero field element from the injected entropy source. */
function randomFelt(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const bytes = random(new Uint8Array(ROUTE_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== ROUTE_SALT_BYTES) throw new Error("The route entropy source returned the wrong number of bytes.");
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n && value < FIELD_PRIME) return value;
  }
  throw new Error("Could not draw a usable route salt.");
}

function hashElements(values: bigint[]): bigint {
  for (const value of values) {
    if (value < 0n || value >= FIELD_PRIME) throw new Error("A commitment input is outside the STARK field.");
  }
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function divideCeil(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) throw new Error("Route arithmetic hit a non-positive denominator.");
  if (numerator <= 0n) return 0n;
  return (numerator + denominator - 1n) / denominator;
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Route amounts cannot be negative.");
  if (decimals === 0) return value.toString();
  const divisor = 10n ** BigInt(decimals);
  const fraction = (value % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  const whole = (value / divisor).toString();
  return fraction ? `${whole}.${fraction}` : whole;
}

/** Parses a positive decimal into an exact numerator/scale rational plus its canonical text. */
function parsePositiveDecimal(value: unknown, maxDecimals: number, label: string): ParsedRate {
  if (typeof value !== "string" || !/^\d{1,20}(\.\d{1,20})?$/.test(value)) throw new Error(`${label} must be a positive decimal number.`);
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > maxDecimals) throw new Error(`${label} supports at most ${maxDecimals} decimal places.`);
  const trimmed = fraction.replace(/0+$/, "");
  const canonicalWhole = BigInt(whole).toString();
  const numerator = BigInt(`${canonicalWhole}${trimmed}`);
  if (numerator <= 0n) throw new Error(`${label} must be greater than zero.`);
  return { numerator, scale: 10n ** BigInt(trimmed.length), normalized: trimmed ? `${canonicalWhole}.${trimmed}` : canonicalWhole };
}

function parseDecimalToBaseUnits(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a positive decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  const units = BigInt(`${whole}${fraction.padEnd(decimals, "0")}`);
  if (units <= 0n) throw new Error(`${label} must be greater than zero.`);
  return units;
}

function requireBaseUnitString(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} is outside the u128 range the privacy pool accepts.`);
  return value;
}

function requireSymbol(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9.-]{2,12}$/.test(value)) throw new Error(`${label} must be 2 to 12 letters, digits, dots, or dashes.`);
  return value;
}

function requireDecimals(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_ASSET_DECIMALS) {
    throw new Error(`${label} must be a whole number between 0 and ${MAX_ASSET_DECIMALS}.`);
  }
  return value;
}

function requireText(value: unknown, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) throw new Error(`${label} must be between 1 and ${maxLength} characters.`);
  if (pattern && !pattern.test(trimmed)) throw new Error(`${label} has an unsupported format.`);
  return trimmed;
}

function requireOptionalText(value: unknown, label: string, maxLength: number): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  const trimmed = value.trim();
  if (trimmed.length > maxLength) throw new Error(`${label} must be ${maxLength} characters or fewer.`);
  return trimmed;
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 UTC timestamp.`);
  }
  return value;
}

function requireFelt(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,63}$/.test(value)) throw new Error(`${label} must be a lowercase hexadecimal field element.`);
  const parsed = BigInt(value);
  if (parsed >= FIELD_PRIME) throw new Error(`${label} is outside the STARK field.`);
  return parsed;
}

function toHex(value: bigint): string {
  if (value < 0n || value >= FIELD_PRIME) throw new Error("A route field element is outside the STARK field.");
  return `0x${value.toString(16)}`;
}

function parseEncodedJson(encoded: string, maxLength: number, label: string): unknown {
  if (typeof encoded !== "string" || !encoded || encoded.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} encoding is invalid.`);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded)));
  } catch {
    throw new Error(`${label} could not be decoded.`);
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url value.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
