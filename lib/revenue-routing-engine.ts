/**
 * CipherBill — Cross-Border Multi-Party Split Payment & Revenue Routing Engine
 * ===========================================================================
 *
 * A client-side module that lets a merchant prove, in zero knowledge, that a
 * hidden gross settlement was split across six routing slots — four stakeholder
 * routes, an affiliate pool, and a cross-border tax reserve — EXACTLY according
 * to a published basis-point schedule, that the split conserves the gross to the
 * last base unit, and that four public routing covenants hold, WITHOUT revealing
 * the gross amount, any per-slot payout, the recipient references, or the payer.
 * Every payout is pinned to `floor(gross · entitlementBps / 10000)` by a pair of
 * homomorphic surplus range proofs, so the split ratios are proven to be applied
 * exactly rather than merely asserted, and the unallocated rounding remainder is
 * committed, range-bounded, and proven to sit under a published tolerance. The
 * merchant signs the binding so anyone can authenticate the issuer offline, and
 * any amount or reference can be selectively disclosed later. Fiat–Shamir makes
 * every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that six hidden payouts plus a hidden rounding remainder
 *   conserve a hidden gross, that each payout equals the exact integer floor of
 *   its published share of that gross, and that four public covenants hold. A
 *   verifier learns the published schedule and that the relations hold — nothing
 *   about the gross, the payouts, the remainder, the recipients, or the payer
 *   until selectively disclosed.
 * - Issuer-authenticated. A Schnorr signature over the binding proves a specific
 *   merchant public key issued it; anyone can check it offline.
 * - Selectively disclosable. The merchant can later open the gross, any slot
 *   payout, the remainder, or the salted agreement, payer, and recipient
 *   references.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It routes NOTHING. There are no stakeholder wallets, no affiliate ledger, no
 *   tax authority, and no integration: this module never moves, transfers,
 *   splits, pays out, escrows, or withholds any value, shielded or public.
 *   "Routing" names numbers the operator types in and the relations proven about
 *   them.
 * - It is NOT automatic and NOT decentralized: a single merchant key issues
 *   attestations, and no contract, oracle, scheduler, relayer, or consensus
 *   vouches for the inputs or releases a payout.
 * - It does NOT observe incoming payments. It never reads the merchant's
 *   shielded balance, note set, or any on-chain state, and it cannot confirm
 *   that the committed gross, payouts, or recipients correspond to anything real.
 * - It never reads from or writes to the STRK20 pool contract at
 *   `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`
 *   (`STRK20_POOL_ADDRESS` in `./strk20/config.ts`, re-exported here as
 *   `REVENUE_ROUTING_POOL_ADDRESS`); that address is recorded as provenance only
 *   and is never called. There is no `privacy_invoke`, no anonymizer contract,
 *   and no transaction of any kind.
 * - It does NOT verify that the committed gross, the payouts, or the recipient
 *   references correspond to anything real, and it is NOT tax advice or
 *   financial advice. The corridor ledger, waterfall, and concentration band are
 *   deterministic arithmetic and heuristics over operator-supplied figures.
 * - Publishing the schedule is a deliberate trade-off: the entitlement basis
 *   points and the per-slot jurisdiction tags are PUBLIC, so a verifier who
 *   learns one payout can derive the gross and every other payout from it.
 *   `getRevenueRoutingVisibilityModel()` states this outright.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const REVENUE_ROUTING_ENGINE_VERSION = 1 as const;
export const REVENUE_ROUTING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const REVENUE_ROUTING_PROOF_SYSTEM = "stark-pedersen-revenue-routing-splits-v1" as const;
/** Basis-point denominator for the entitlement schedule: 10000 = 100%. */
export const BPS_SCALE = 10_000n;
/** Upper bound on asset decimals, matching what `baseUnitsToDecimal` can format. */
export const MAX_ASSET_DECIMALS = 18;
export const DEFAULT_ROUTING_AMOUNT_BIT_LENGTH = 128;
export const MIN_ROUTING_AMOUNT_BIT_LENGTH = 8;
export const MAX_ROUTING_AMOUNT_BIT_LENGTH = 128;
/**
 * Extra bits the three amount-scale covenant surplus proofs get beyond the amount
 * range. Every one of those surpluses is a difference of two values below
 * `2^amountBitLength`, so the band is already generous; the margin keeps the
 * soundness argument (band + largest possible homomorphic difference stays far
 * below the curve order) obvious rather than tight.
 */
export const ROUTING_SURPLUS_EXTRA_BITS = 18;
/**
 * Band for the twelve exact-floor legs. Each of those legs commits to
 * `entitlementBps · gross mod 10000` or its complement `9999 −` that, so the
 * value never exceeds 9999 and 14 bits (16384) covers it. The two legs of a slot
 * sum to exactly `9999 · G`, so proving both inside this band forces the payout to
 * be the exact integer floor — see `proveFloorPair` below.
 */
export const ROUTING_FLOOR_BIT_LENGTH = 14;
/** Largest value either exact-floor leg can hold: `10000 − 1`. */
export const MAX_FLOOR_LEG_VALUE = BPS_SCALE - 1n;
/**
 * Band for the unallocated rounding remainder and for the published tolerance.
 * Six floor divisions can drop at most five base units in total, so 16 bits is a
 * generous ceiling that still keeps the two remainder legs cheap.
 */
export const ROUTING_DUST_BIT_LENGTH = 16;
/** Ceiling on the published rounding tolerance, in base units. */
export const MAX_ROUTING_DUST_BASE_UNITS = (1n << BigInt(ROUTING_DUST_BIT_LENGTH)) - 1n;
/** Ceiling on how many days a settlement row may be reported as aged. */
export const MAX_SETTLEMENT_AGE_DAYS = 3650;
/** Ceiling on the jurisdiction tag length for a routing slot. */
export const MAX_JURISDICTION_LENGTH = 32;

/**
 * The six fixed routing slots, in waterfall order. Slots 0–3 are stakeholder
 * routes, slot 4 is the affiliate pool, and slot 5 is the cross-border tax
 * reserve. The set is fixed so that the proof shape — and therefore every leg
 * index in the Fiat–Shamir transcript — is identical for every certificate.
 */
export const REVENUE_ROUTING_SLOTS = [
  { key: "stakeholderA", label: "Stakeholder A", kind: "stakeholder" },
  { key: "stakeholderB", label: "Stakeholder B", kind: "stakeholder" },
  { key: "stakeholderC", label: "Stakeholder C", kind: "stakeholder" },
  { key: "stakeholderD", label: "Stakeholder D", kind: "stakeholder" },
  { key: "affiliatePool", label: "Affiliate pool", kind: "affiliate" },
  { key: "taxReserve", label: "Tax reserve", kind: "tax" },
] as const;

export type RoutingSlotKey = (typeof REVENUE_ROUTING_SLOTS)[number]["key"];
export type RoutingSlotKind = (typeof REVENUE_ROUTING_SLOTS)[number]["kind"];

/** Number of routing slots every certificate commits to. */
export const ROUTING_SLOT_COUNT = REVENUE_ROUTING_SLOTS.length;
export const AFFILIATE_SLOT_INDEX = 4;
export const TAX_RESERVE_SLOT_INDEX = 5;
export const REVENUE_ROUTING_SLOT_LABELS = REVENUE_ROUTING_SLOTS.map((slot) => slot.label);
/**
 * Six floor divisions each drop strictly less than one base unit, so an honest
 * split over a schedule totalling exactly 10000 bps can never leave more than
 * five base units unallocated. The published tolerance may be larger; this is
 * the arithmetic maximum the remainder can actually reach.
 */
export const MAX_POSSIBLE_ROUTING_DUST = BigInt(ROUTING_SLOT_COUNT - 1);

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
const MS_PER_DAY = 86_400_000;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill revenue routing generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill revenue routing statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill revenue routing bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill revenue routing binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill revenue routing issuer signature v1");
const SETTLEMENT_DOMAIN = hash.starknetKeccak("CipherBill revenue routing settlement row v1");
const AGREEMENT_DOMAIN = hash.starknetKeccak("CipherBill revenue routing agreement ref v1");
const PAYER_DOMAIN = hash.starknetKeccak("CipherBill revenue routing payer ref v1");
const RECIPIENT_DOMAIN = hash.starknetKeccak("CipherBill revenue routing recipient ref v1");

const CERTIFICATE_KIND = "cipherbill.revenue-routing-certificate" as const;
const SECRET_KIND = "cipherbill.revenue-routing-certificate-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.revenue-routing-amount-disclosure" as const;
const REF_DISCLOSURE_KIND = "cipherbill.revenue-routing-ref-disclosure" as const;
const BADGE_KIND = "cipherbill.revenue-routing-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.revenue-routing-keypair" as const;
const MAX_ENCODED_LENGTH = 12_000_000;

/**
 * Proof leg indices. Legs 0–5 pin each slot payout, leg 6 the gross, leg 7 the
 * rounding remainder, legs 8–13 the lower floor bound per slot, legs 14–19 the
 * upper floor bound per slot, and legs 20–23 the four public covenants. Every
 * leg has its own index so a bit proof can never be replayed into another leg.
 */
const LEG_GROSS = 6;
const LEG_DUST = 7;
const LEG_FLOOR_LOWER_BASE = 8;
const LEG_FLOOR_UPPER_BASE = 14;
const LEG_GROSS_FLOOR_SURPLUS = 20;
const LEG_AFFILIATE_CAP_SURPLUS = 21;
const LEG_TAX_FLOOR_SURPLUS = 22;
const LEG_DUST_CEILING_SURPLUS = 23;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface RevenueRoutingAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface RevenueRoutingKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign attestations. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface RevenueRoutingEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

/** PUBLIC entitlement schedule: one basis-point share per routing slot. */
export type RoutingSplitBps = [number, number, number, number, number, number];

/** PUBLIC jurisdiction tag per routing slot, in slot order. */
export type RoutingJurisdictions = [string, string, string, string, string, string];

/** SECRET recipient reference per routing slot, in slot order. */
export type RoutingRecipientRefs = [string, string, string, string, string, string];

/** PUBLIC covenants the hidden routing figures are proven to satisfy. */
export interface RevenueRoutingPolicy {
  /** PUBLIC minimum gross settlement in base units. Proven: gross ≥ this. */
  minGrossBaseUnits: string;
  /** PUBLIC absolute cap on the affiliate payout. Proven: affiliate ≤ this. */
  maxAffiliatePayoutBaseUnits: string;
  /** PUBLIC absolute floor on the tax reserve. Proven: taxReserve ≥ this. */
  minTaxReserveBaseUnits: string;
  /** PUBLIC rounding tolerance in base units. Proven: remainder ≤ this. */
  maxDustBaseUnits: string;
}

/** One merchant-supplied incoming settlement row. Never published in the clear. */
export interface SettlementRow {
  reference: string;
  /** Jurisdiction tag for the paying corridor (e.g. "DE", "SG"). */
  jurisdiction: string;
  /** ISO-8601 timestamp the settlement was received. */
  receivedAt: string;
  amountBaseUnits: string;
}

export interface CorridorSummary {
  jurisdiction: string;
  amountBaseUnits: string;
  rowCount: number;
  shareBps: string;
  oldestAgeDays: string;
}

/** Pure cross-border corridor breakdown aggregated from settlement rows (no proof). */
export interface CorridorLedger {
  asOf: string;
  corridors: CorridorSummary[];
  grossBaseUnits: string;
  rowCount: number;
  corridorCount: number;
  largestCorridorShareBps: string;
  /** Σ(amount · ageDays) across every row; an ageing figure, never proven. */
  weightedAgeDays: string;
  averageAgeDays: string;
}

export interface RoutingSlotPlan {
  index: number;
  key: RoutingSlotKey;
  label: string;
  kind: RoutingSlotKind;
  entitlementBps: string;
  payoutBaseUnits: string;
  /** `gross · entitlementBps mod 10000` — the numerator the floor discards. */
  roundingRemainder: string;
  /** `payout · 10000 / gross` — the share actually realized after flooring. */
  realizedShareBps: string;
}

/** Pure integer split of a gross settlement across the six slots (no proof). */
export interface RevenueRoutingPlan {
  grossBaseUnits: string;
  slots: RoutingSlotPlan[];
  allocatedBaseUnits: string;
  /** gross − Σ payouts; the unallocated rounding remainder. */
  dustBaseUnits: string;
  totalEntitlementBps: string;
  isExactSplit: boolean;
  maxPossibleDustBaseUnits: string;
}

export type WaterfallStepKind = RoutingSlotKind | "remainder";

export interface RoutingWaterfallStep {
  index: number;
  label: string;
  kind: WaterfallStepKind;
  openingBalanceBaseUnits: string;
  deductionBaseUnits: string;
  closingBalanceBaseUnits: string;
  cumulativeBaseUnits: string;
  shareBps: string;
}

export interface RoutingPolicyAssessment {
  /** gross − minGross; ≥ 0 exactly when the settlement floor holds. */
  grossFloorSurplus: string;
  /** maxAffiliatePayout − affiliate; ≥ 0 exactly when the affiliate cap holds. */
  affiliateCapSurplus: string;
  /** taxReserve − minTaxReserve; ≥ 0 exactly when the reserve floor holds. */
  taxFloorSurplus: string;
  /** maxDust − remainder; ≥ 0 exactly when the rounding tolerance holds. */
  dustCeilingSurplus: string;
  eligible: boolean;
  /** Clear-text blockers, verbatim the errors `issue…()` would throw. */
  blockers: string[];
}

export type RoutingConcentrationBand = "balanced" | "tilted" | "concentrated" | "single-party";

export interface RoutingConcentrationAssessment {
  band: RoutingConcentrationBand;
  score: number;
  largestShareBps: string;
  /** Herfindahl index over the realized slot shares, scaled to 10000. */
  herfindahlIndex: string;
  stakeholderShareBps: string;
  affiliateShareBps: string;
  reserveShareBps: string;
  rationale: string;
}

export interface IssueRevenueRoutingCertificateInput {
  merchantAlias: string;
  asset: RevenueRoutingAsset;
  /**
   * SECRET reference to the revenue-share agreement this attestation is issued
   * under. Only a salted commitment is published; omit it to publish none.
   */
  agreementRef?: string;
  /** PUBLIC human-readable programme label. */
  programLabel: string;
  /** PUBLIC entitlement schedule in bps; must total exactly 10000. */
  splitBps: RoutingSplitBps;
  /** PUBLIC jurisdiction tag per slot, in slot order. */
  jurisdictions: RoutingJurisdictions;
  /** PUBLIC routing covenants. */
  policy: RevenueRoutingPolicy;
  /**
   * SECRET gross settlement amount in base units. Never published in the clear.
   * The six payouts are DERIVED from it by exact floor division, never supplied,
   * so the split relations the proof attests cannot be sidestepped by an input.
   */
  grossBaseUnits: string;
  /** SECRET recipient references per slot; only salted commitments are published. */
  recipientRefs: RoutingRecipientRefs;
  /** SECRET payer reference; only a salted commitment is published. */
  payerRef?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

export interface RevenueRoutingBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  challenge0: string;
  response0: string;
  response1: string;
}

export interface IssuerSignature {
  challenge: string;
  response: string;
}

/**
 * Zero-knowledge proof bundle. Legs 0–5 pin each slot payout inside the amount
 * band, leg 6 the gross, and leg 7 the rounding remainder inside the dust band.
 * Conservation is a point identity — the six slot commitments plus the remainder
 * commitment equal the gross commitment exactly — so no separate leg is needed.
 * Legs 8–19 pin every payout to the exact floor of its published share, and legs
 * 20–23 carry the four public covenant surpluses.
 */
export interface RevenueRoutingProof {
  proofSystem: typeof REVENUE_ROUTING_PROOF_SYSTEM;
  amountBitLength: number;
  surplusBitLength: number;
  floorBitLength: number;
  dustBitLength: number;
  generatorH: CurvePointFelts;
  grossCommitment: CurvePointFelts;
  slotCommitments: CurvePointFelts[];
  dustCommitment: CurvePointFelts;
  grossBits: RevenueRoutingBitProof[];
  slotBits: RevenueRoutingBitProof[][];
  dustBits: RevenueRoutingBitProof[];
  /** Per slot: `entitlementBps · gross − 10000 · payout ≥ 0`. */
  floorLowerBits: RevenueRoutingBitProof[][];
  /** Per slot: `10000 · payout + 9999 − entitlementBps · gross ≥ 0`. */
  floorUpperBits: RevenueRoutingBitProof[][];
  grossFloorSurplusBits: RevenueRoutingBitProof[];
  affiliateCapSurplusBits: RevenueRoutingBitProof[];
  taxFloorSurplusBits: RevenueRoutingBitProof[];
  dustCeilingSurplusBits: RevenueRoutingBitProof[];
}

export interface RevenueRoutingCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof REVENUE_ROUTING_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  merchantAlias: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  splitBps: string[];
  jurisdictions: string[];
  minGrossBaseUnits: string;
  maxAffiliatePayoutBaseUnits: string;
  minTaxReserveBaseUnits: string;
  maxDustBaseUnits: string;
  agreementCommitment: string;
  agreementCommitted: boolean;
  payerCommitment: string;
  payerCommitted: boolean;
  recipientCommitments: string[];
  issuerPublicKey: CurvePointFelts;
  proof: RevenueRoutingProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}

/**
 * The merchant-held opening material. It contains every hidden figure and every
 * blinding, so it is a SECRET: publishing it opens the whole certificate. Use the
 * selective-disclosure builders to open one field at a time instead.
 */
export interface RevenueRoutingCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  grossBaseUnits: string;
  slotPayoutsBaseUnits: string[];
  dustBaseUnits: string;
  splitBps: string[];
  minGrossBaseUnits: string;
  maxAffiliatePayoutBaseUnits: string;
  minTaxReserveBaseUnits: string;
  maxDustBaseUnits: string;
  grossBlinding: string;
  slotBlindings: string[];
  dustBlinding: string;
  floorLowerBlindings: string[];
  floorUpperBlindings: string[];
  grossFloorSurplusBlinding: string;
  affiliateCapSurplusBlinding: string;
  taxFloorSurplusBlinding: string;
  dustCeilingSurplusBlinding: string;
  agreementRef: string;
  agreementSalt: string;
  payerRef: string;
  payerSalt: string;
  payerCommitted: boolean;
  recipientRefs: string[];
  recipientSalts: string[];
}

export interface IssuedRevenueRoutingCertificate {
  certificate: RevenueRoutingCertificate;
  secret: RevenueRoutingCertificateSecret;
}

export type RevenueRoutingAmountField = "gross" | "dust" | `slot${0 | 1 | 2 | 3 | 4 | 5}`;

export interface RevenueRoutingAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  field: RevenueRoutingAmountField;
  amountBaseUnits: string;
  blinding: string;
}

export type RevenueRoutingRefField = "agreementRef" | "payerRef" | `recipient${0 | 1 | 2 | 3 | 4 | 5}`;

export interface RevenueRoutingRefDisclosure {
  kind: typeof REF_DISCLOSURE_KIND;
  certificateId: string;
  field: RevenueRoutingRefField;
  value: string;
  salt: string;
}

/** One row of the audit readout: what was checked, what it means, and the verdict. */
export interface RevenueRoutingCheck {
  label: string;
  detail: string;
  passed: boolean;
}

export interface RevenueRoutingCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  merchantAlias: string;
  programLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  headline: string;
  claim: string;
  scheduleSummary: string[];
  covenantSummary: string[];
  jurisdictionSummary: string;
  proofCount: number;
  payerCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
  notice: string;
}

export interface RevenueRoutingTrustModel {
  isZeroKnowledge: boolean;
  provesGrossConservation: boolean;
  provesExactFloorSplits: boolean;
  provesRoundingTolerance: boolean;
  provesSettlementFloor: boolean;
  provesAffiliateCap: boolean;
  provesTaxReserveFloor: boolean;
  hidesGrossAmount: boolean;
  hidesSlotPayouts: boolean;
  hidesRecipientReferences: boolean;
  hidesPayerReference: boolean;
  hidesSettlementRows: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  publishesEntitlementSchedule: boolean;
  publishesJurisdictions: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  routesOrMovesFunds: boolean;
  paysAnyStakeholder: boolean;
  withholdsAnyTax: boolean;
  observesIncomingPayments: boolean;
  readsShieldedBalances: boolean;
  settlesOnChain: boolean;
  movesPoolFunds: boolean;
  callsPoolContract: boolean;
  verifiesFiguresAreReal: boolean;
  verifiesRecipientsExist: boolean;
  isTaxAdvice: boolean;
  isFinancialAdvice: boolean;
  proven: string[];
  hidden: string[];
  visible: string[];
  limitations: readonly string[];
  zeroKnowledgeElement: string;
  statement: string;
}

export interface RevenueRoutingVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

/** Plain-language limits, surfaced verbatim in the portal so the UI cannot drift. */
export const REVENUE_ROUTING_LIMITATIONS = [
  "It routes nothing. No value moves, no stakeholder is paid, no affiliate is credited, and no tax is withheld — the payouts are integers derived from an operator-typed gross.",
  "It is neither decentralized nor automatic. One merchant key issues attestations; no contract, oracle, scheduler, relayer, or consensus vouches for the inputs or releases a payout.",
  "It never observes an incoming payment. It reads no shielded balance, no note set, and no on-chain state, so it cannot know a settlement arrived.",
  "It never reads from or writes to the STRK20 pool contract. The pool address is recorded for provenance only and is never called.",
  "It proves arithmetic consistency between committed numbers, never their truthfulness. A certificate over invented figures verifies exactly as well as one over real figures.",
  "The entitlement schedule and the jurisdiction tags are PUBLIC. A verifier who learns any one payout can derive the gross and every other payout from the schedule.",
  "Recipient references are salted commitments, not addresses. Nothing here checks that a recipient exists, is reachable, or consents to the share.",
  "The corridor ledger, waterfall, and concentration band are deterministic arithmetic and heuristics over operator-supplied rows — not tax advice and not financial advice.",
] as const;

const REVENUE_ROUTING_NOTICE =
  "Zero-knowledge proof that a hidden gross settlement splits across six routing slots exactly at a published basis-point schedule, that the six hidden payouts plus a hidden rounding remainder conserve that gross to the last base unit, and that four public covenants hold — hiding the gross, every payout, the remainder, the payer, and every recipient reference. It authenticates the issuer and supports selective disclosure; it is neither decentralized nor automatic, routes nothing, pays nobody, withholds no tax, observes no incoming payment, does not read shielded balances, does not verify that the figures or recipients are real, and never reads from or writes to the STRK20 pool contract.";

// ---------------------------------------------------------------------------
// Curve primitives
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

export function deriveRevenueRoutingGenerator(): CurvePointFelts {
  return pointToFelts(independentGenerator());
}

function hashToPoint(seed: bigint[]): CurvePoint {
  for (let counter = 0n; counter < 1000n; counter += 1n) {
    const x = mod(hashElements([...seed, counter]), FIELD_PRIME);
    const rhs = FIELD.add(FIELD.add(FIELD.mul(FIELD.mul(x, x), x), FIELD.mul(CURVE_A, x)), CURVE_B);
    let root: bigint;
    try {
      root = FIELD.sqrt(rhs);
    } catch {
      continue;
    }
    const y = root % 2n === 0n ? root : FIELD_PRIME - root;
    try {
      const point = ec.starkCurve.ProjectivePoint.fromAffine({ x, y });
      point.assertValidity();
      if (point.equals(G) || point.equals(ZERO)) continue;
      return point;
    } catch {
      continue;
    }
  }
  throw new Error("Failed to derive an independent revenue routing generator.");
}

function scalePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const s = mod(scalar, CURVE_ORDER);
  return s === 0n ? ZERO : point.multiply(s);
}

function pedersenCommit(value: bigint, blinding: bigint, h: CurvePoint): CurvePoint {
  return scalePoint(G, value).add(scalePoint(h, blinding));
}

function pointToFelts(point: CurvePoint): CurvePointFelts {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: CurvePointFelts): CurvePoint {
  if (!point || typeof point !== "object") throw new Error("Curve point is missing.");
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x), y: requireFelt(point.y) });
  parsed.assertValidity();
  return parsed;
}

function publicKeyFromSecret(secret: bigint): CurvePoint {
  if (secret <= 0n || secret >= CURVE_ORDER) throw new Error("Secret key is outside the Stark curve order.");
  return G.multiply(secret);
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

export function createRevenueRoutingIssuerKey(entropy: RevenueRoutingEntropy = {}): RevenueRoutingKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return {
    kind: KEYPAIR_KIND,
    role: "issuer",
    secretKey: toHex(secret),
    publicKey: pointToFelts(publicKeyFromSecret(secret)),
  };
}

// ---------------------------------------------------------------------------
// Settlement rows, corridor ledger, and the pure split (no proofs)
// ---------------------------------------------------------------------------

/** Salted Poseidon commitment to one settlement row; hiding and binding. */
export function commitSettlementRow(
  reference: string,
  jurisdiction: string,
  receivedAt: string,
  amountBaseUnits: string | bigint,
  salt?: bigint,
): string {
  const trimmedRef = requireText(reference, "settlement reference", 96);
  const trimmedJurisdiction = requireText(jurisdiction, "jurisdiction", MAX_JURISDICTION_LENGTH);
  const isoReceived = requireIsoTimestamp(receivedAt);
  const amount = requireBaseUnits(amountBaseUnits, "settlement amount");
  const s = salt !== undefined ? nonZeroScalar(salt) : nonZeroScalar(randomScalar());
  return toHex(
    hashElements([
      SETTLEMENT_DOMAIN,
      hash.starknetKeccak(trimmedRef),
      hash.starknetKeccak(trimmedJurisdiction),
      hash.starknetKeccak(isoReceived),
      amount,
      s,
    ]),
  );
}

function ageDaysFor(receivedAt: string, asOf: Date): number {
  const received = new Date(requireIsoTimestamp(receivedAt)).getTime();
  const days = Math.floor((asOf.getTime() - received) / MS_PER_DAY);
  return days < 0 ? 0 : days > MAX_SETTLEMENT_AGE_DAYS ? MAX_SETTLEMENT_AGE_DAYS : days;
}

/**
 * Aggregates settlement rows into per-jurisdiction corridors as of a date. Pure
 * arithmetic over operator-supplied rows: it reads no chain state and proves
 * nothing. Corridors are ordered by amount descending, then jurisdiction
 * ascending, so the readout is deterministic.
 */
export function aggregateCorridorLedger(rows: SettlementRow[], asOf: Date = new Date()): CorridorLedger {
  if (!Array.isArray(rows)) throw new Error("Settlement rows are required.");
  const totals = new Map<string, { amount: bigint; rowCount: number; oldestAgeDays: number }>();
  let gross = 0n;
  let weighted = 0n;

  for (const row of rows) {
    const amount = requireBaseUnits(row.amountBaseUnits, "settlement amount");
    void requireText(row.reference, "settlement reference", 96);
    const jurisdiction = requireText(row.jurisdiction, "jurisdiction", MAX_JURISDICTION_LENGTH);
    const days = ageDaysFor(row.receivedAt, asOf);
    const bucket = totals.get(jurisdiction) ?? { amount: 0n, rowCount: 0, oldestAgeDays: 0 };
    bucket.amount += amount;
    bucket.rowCount += 1;
    if (days > bucket.oldestAgeDays) bucket.oldestAgeDays = days;
    totals.set(jurisdiction, bucket);
    gross += amount;
    weighted += amount * BigInt(days);
  }

  const corridors: CorridorSummary[] = [...totals.entries()]
    .map(([jurisdiction, bucket]) => ({
      jurisdiction,
      amountBaseUnits: bucket.amount.toString(),
      rowCount: bucket.rowCount,
      shareBps: (gross > 0n ? (bucket.amount * BPS_SCALE) / gross : 0n).toString(),
      oldestAgeDays: bucket.oldestAgeDays.toString(),
    }))
    .sort((a, b) => {
      const left = BigInt(a.amountBaseUnits);
      const right = BigInt(b.amountBaseUnits);
      if (left !== right) return left > right ? -1 : 1;
      return a.jurisdiction.localeCompare(b.jurisdiction);
    });

  return {
    asOf: asOf.toISOString(),
    corridors,
    grossBaseUnits: gross.toString(),
    rowCount: rows.length,
    corridorCount: corridors.length,
    largestCorridorShareBps: corridors.length > 0 ? corridors[0].shareBps : "0",
    weightedAgeDays: weighted.toString(),
    averageAgeDays: (gross > 0n ? weighted / gross : 0n).toString(),
  };
}

/**
 * Validates the PUBLIC entitlement schedule. Six shares, each within 0…10000
 * bps, totalling exactly 10000. The exact total is what makes the rounding
 * remainder a bounded quantity: with Σ bps = 10000 and every payout an exact
 * floor, the six discarded fractions sum to strictly less than six base units.
 */
export function normalizeRoutingSplit(splitBps: RoutingSplitBps | number[] | string[]): bigint[] {
  if (!Array.isArray(splitBps) || splitBps.length !== ROUTING_SLOT_COUNT) {
    throw new Error(`Exactly ${ROUTING_SLOT_COUNT} entitlement shares are required.`);
  }
  const shares = splitBps.map((bps, index) =>
    BigInt(requireInt(bps, `${REVENUE_ROUTING_SLOTS[index].label} entitlement bps`, 0, Number(BPS_SCALE))),
  );
  const total = shares.reduce((acc, v) => acc + v, 0n);
  if (total !== BPS_SCALE) {
    throw new Error(`The entitlement schedule must total exactly ${BPS_SCALE} basis points; this one totals ${total}.`);
  }
  return shares;
}

/**
 * Splits a gross settlement across the six slots by exact integer floor
 * division, exactly as the ZK proof attests. `dustBaseUnits` is the remainder
 * the floors leave behind; with a schedule totalling 10000 bps it is always
 * between 0 and 5 base units inclusive.
 */
export function computeRevenueRoutingPlan(
  grossBaseUnits: string | bigint,
  splitBps: RoutingSplitBps | number[] | string[],
): RevenueRoutingPlan {
  const gross = requireBaseUnits(grossBaseUnits, "gross settlement");
  const shares = normalizeRoutingSplit(splitBps);

  let allocated = 0n;
  const slots: RoutingSlotPlan[] = REVENUE_ROUTING_SLOTS.map((slot, index) => {
    const numerator = gross * shares[index];
    const payout = numerator / BPS_SCALE;
    allocated += payout;
    return {
      index,
      key: slot.key,
      label: slot.label,
      kind: slot.kind,
      entitlementBps: shares[index].toString(),
      payoutBaseUnits: payout.toString(),
      roundingRemainder: (numerator % BPS_SCALE).toString(),
      realizedShareBps: (gross > 0n ? (payout * BPS_SCALE) / gross : 0n).toString(),
    };
  });

  const dust = gross - allocated;
  return {
    grossBaseUnits: gross.toString(),
    slots,
    allocatedBaseUnits: allocated.toString(),
    dustBaseUnits: dust.toString(),
    totalEntitlementBps: BPS_SCALE.toString(),
    isExactSplit: dust === 0n,
    maxPossibleDustBaseUnits: MAX_POSSIBLE_ROUTING_DUST.toString(),
  };
}

/**
 * Turns a plan into a running-balance waterfall: seven steps that draw the gross
 * down to exactly zero. Presentation arithmetic for the distribution visualizer,
 * not part of the proof.
 */
export function buildRoutingWaterfall(plan: RevenueRoutingPlan): RoutingWaterfallStep[] {
  const gross = requireBaseUnits(plan.grossBaseUnits, "gross settlement");
  const steps: RoutingWaterfallStep[] = [];
  let balance = gross;
  let cumulative = 0n;

  const push = (label: string, kind: WaterfallStepKind, deduction: bigint) => {
    const opening = balance;
    cumulative += deduction;
    balance = opening - deduction;
    steps.push({
      index: steps.length,
      label,
      kind,
      openingBalanceBaseUnits: opening.toString(),
      deductionBaseUnits: deduction.toString(),
      closingBalanceBaseUnits: balance.toString(),
      cumulativeBaseUnits: cumulative.toString(),
      shareBps: (gross > 0n ? (deduction * BPS_SCALE) / gross : 0n).toString(),
    });
  };

  for (const slot of plan.slots) {
    push(slot.label, slot.kind, requireBaseUnits(slot.payoutBaseUnits, `${slot.label} payout`));
  }
  push("Rounding remainder", "remainder", requireBaseUnits(plan.dustBaseUnits, "rounding remainder"));
  return steps;
}

export function requireRevenueRoutingPolicy(policy: RevenueRoutingPolicy): {
  minGross: bigint;
  maxAffiliatePayout: bigint;
  minTaxReserve: bigint;
  maxDust: bigint;
} {
  if (!policy || typeof policy !== "object") throw new Error("The revenue routing policy is required.");
  const minGross = requireBaseUnits(policy.minGrossBaseUnits, "minimum gross settlement");
  const maxAffiliatePayout = requireBaseUnits(policy.maxAffiliatePayoutBaseUnits, "maximum affiliate payout");
  const minTaxReserve = requireBaseUnits(policy.minTaxReserveBaseUnits, "minimum tax reserve");
  const maxDust = requireBaseUnits(policy.maxDustBaseUnits, "rounding tolerance");
  if (maxDust > MAX_ROUTING_DUST_BASE_UNITS) {
    throw new Error(`The rounding tolerance must be at most ${MAX_ROUTING_DUST_BASE_UNITS} base units.`);
  }
  return { minGross, maxAffiliatePayout, minTaxReserve, maxDust };
}

/**
 * Evaluates the four public covenants against a plan. The surpluses are the same
 * quantities legs 20–23 range-prove, and the blockers are verbatim the errors
 * `issueRevenueRoutingCertificate` throws, so a portal can preview a rejection
 * without calling the prover.
 */
export function assessRoutingPolicy(plan: RevenueRoutingPlan, policy: RevenueRoutingPolicy): RoutingPolicyAssessment {
  const { minGross, maxAffiliatePayout, minTaxReserve, maxDust } = requireRevenueRoutingPolicy(policy);
  const gross = requireBaseUnits(plan.grossBaseUnits, "gross settlement");
  const affiliate = requireBaseUnits(plan.slots[AFFILIATE_SLOT_INDEX].payoutBaseUnits, "affiliate payout");
  const taxReserve = requireBaseUnits(plan.slots[TAX_RESERVE_SLOT_INDEX].payoutBaseUnits, "tax reserve");
  const dust = requireBaseUnits(plan.dustBaseUnits, "rounding remainder");

  const grossFloorSurplus = gross - minGross;
  const affiliateCapSurplus = maxAffiliatePayout - affiliate;
  const taxFloorSurplus = taxReserve - minTaxReserve;
  const dustCeilingSurplus = maxDust - dust;

  const blockers: string[] = [];
  if (grossFloorSurplus < 0n) blockers.push(BLOCKER_GROSS_FLOOR);
  if (affiliateCapSurplus < 0n) blockers.push(BLOCKER_AFFILIATE_CAP);
  if (taxFloorSurplus < 0n) blockers.push(BLOCKER_TAX_FLOOR);
  if (dustCeilingSurplus < 0n) blockers.push(BLOCKER_DUST_TOLERANCE);

  return {
    grossFloorSurplus: grossFloorSurplus.toString(),
    affiliateCapSurplus: affiliateCapSurplus.toString(),
    taxFloorSurplus: taxFloorSurplus.toString(),
    dustCeilingSurplus: dustCeilingSurplus.toString(),
    eligible: blockers.length === 0,
    blockers,
  };
}

const BLOCKER_GROSS_FLOOR = "The gross settlement is below the published minimum settlement floor.";
const BLOCKER_AFFILIATE_CAP = "The affiliate payout exceeds the published affiliate cap.";
const BLOCKER_TAX_FLOOR = "The tax reserve is below the published minimum tax reserve.";
const BLOCKER_DUST_TOLERANCE = "The rounding remainder exceeds the published rounding tolerance.";

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}

/**
 * Deterministic concentration heuristic over the realized slot shares. It is a
 * readout, not a forecast, a recommendation, tax advice, or financial advice.
 */
export function assessRoutingConcentration(plan: RevenueRoutingPlan): RoutingConcentrationAssessment {
  const shares = plan.slots.map((slot) => BigInt(slot.realizedShareBps));
  const largest = shares.reduce((acc, v) => (v > acc ? v : acc), 0n);
  const stakeholderShare = shares.slice(0, AFFILIATE_SLOT_INDEX).reduce((acc, v) => acc + v, 0n);
  const affiliateShare = shares[AFFILIATE_SLOT_INDEX];
  const reserveShare = shares[TAX_RESERVE_SLOT_INDEX];
  // Herfindahl over bps shares: Σ share², rescaled back to a 10000 basis.
  const herfindahl = shares.reduce((acc, v) => acc + v * v, 0n) / BPS_SCALE;

  const largestRatio = clamp01(Number(largest) / Number(BPS_SCALE));
  const herfindahlRatio = clamp01(Number(herfindahl) / Number(BPS_SCALE));
  const score = Math.round(100 * clamp01(0.6 * herfindahlRatio + 0.4 * largestRatio));

  let band: RoutingConcentrationBand;
  if (largestRatio >= 0.9) band = "single-party";
  else if (score >= 45) band = "concentrated";
  else if (score >= 25) band = "tilted";
  else band = "balanced";

  const rationale =
    band === "single-party"
      ? "One slot takes at least 90% of the schedule, so a single disclosed payout is nearly the gross."
      : band === "concentrated"
        ? "The schedule leans heavily on one slot; a disclosed payout narrows the gross sharply."
        : band === "tilted"
          ? "The schedule is uneven but no single slot dominates it."
          : "The schedule spreads entitlement broadly across the six slots.";

  return {
    band,
    score,
    largestShareBps: largest.toString(),
    herfindahlIndex: herfindahl.toString(),
    stakeholderShareBps: stakeholderShare.toString(),
    affiliateShareBps: affiliateShare.toString(),
    reserveShareBps: reserveShare.toString(),
    rationale,
  };
}

/**
 * Reports whether the plan clears a caller-supplied concentration score
 * threshold. It executes nothing: `executesAnything` is always false because
 * this module never moves value.
 */
export function evaluateRoutingRelease(
  plan: RevenueRoutingPlan,
  concentrationThreshold: number,
): { concentrationScore: number; band: RoutingConcentrationBand; withinThreshold: boolean; executesAnything: false } {
  const threshold = requireInt(concentrationThreshold, "concentration threshold", 0, 100);
  const assessment = assessRoutingConcentration(plan);
  return {
    concentrationScore: assessment.score,
    band: assessment.band,
    withinThreshold: assessment.score <= threshold,
    executesAnything: false,
  };
}

export function formatRoutingBaseUnits(baseUnits: string, decimals: number): string {
  return baseUnitsToDecimal(requireBaseUnits(baseUnits, "amount").toString(), requireInt(decimals, "decimals", 0, MAX_ASSET_DECIMALS));
}

export function formatRoutingBps(bps: number): string {
  const value = requireInt(bps, "basis points", 0, Number(BPS_SCALE));
  const whole = Math.trunc(value / 100);
  const frac = value % 100;
  return frac === 0 ? `${whole}%` : `${whole}.${frac.toString().padStart(2, "0")}%`;
}
export function formatSettlementAgeDays(days: string | number): string {
  const value = typeof days === "number" ? days : Number.parseInt(days, 10);
  if (!Number.isFinite(value)) return "0d";
  const whole = Math.max(0, Math.trunc(value));
  if (whole < 30) return `${whole}d`;
  if (whole < 365) return `${whole}d · ${(whole / 30).toFixed(1)}mo`;
  return `${whole}d · ${(whole / 365).toFixed(1)}y`;
}

/**
 * Exact number of Chaum–Pedersen OR proofs a certificate carries at a given
 * amount band: `7·b` for the gross and the six payouts, `2·dustBitLength` for the
 * remainder and its ceiling surplus, `12·floorBitLength` for the twelve
 * exact-floor legs, and `3·(b + extra)` for the three amount-scale covenants.
 */
export function estimateRevenueRoutingProofCount(amountBitLength: number): number {
  const bits = requireInt(
    amountBitLength,
    "amount bit length",
    MIN_ROUTING_AMOUNT_BIT_LENGTH,
    MAX_ROUTING_AMOUNT_BIT_LENGTH,
  );
  const surplusBits = bits + ROUTING_SURPLUS_EXTRA_BITS;
  return (
    (ROUTING_SLOT_COUNT + 1) * bits +
    2 * ROUTING_DUST_BIT_LENGTH +
    2 * ROUTING_SLOT_COUNT * ROUTING_FLOOR_BIT_LENGTH +
    3 * surplusBits
  );
}

// ---------------------------------------------------------------------------
// Fiat–Shamir binding
// ---------------------------------------------------------------------------

interface BindingFields {
  merchantAlias: string;
  programLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  splitBps: bigint[];
  jurisdictions: string[];
  minGross: bigint;
  maxAffiliatePayout: bigint;
  minTaxReserve: bigint;
  maxDust: bigint;
  amountBitLength: number;
  surplusBitLength: number;
  floorBitLength: number;
  dustBitLength: number;
  agreementCommitment: bigint;
  agreementCommitted: boolean;
  payerCommitment: bigint;
  payerCommitted: boolean;
  recipientCommitments: bigint[];
  certificateId: string;
  createdAt: string;
  memo: string;
  issuerPublicKey: CurvePoint;
  grossCommitment: CurvePoint;
  slotCommitments: CurvePoint[];
  dustCommitment: CurvePoint;
  h: CurvePoint;
}
/**
 * One Poseidon hash over every public field and every commitment. Both the
 * per-bit Fiat–Shamir challenges and the issuer signature are derived from it, so
 * changing any published byte invalidates the whole certificate. Strings enter as
 * `starknetKeccak` digests; the empty-memo case is disambiguated by an explicit
 * presence flag so that an absent memo and a memo that happens to keccak to the
 * same felt as the empty string cannot be swapped for one another.
 */
function computeBindingHash(fields: BindingFields): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(REVENUE_ROUTING_ENGINE_VERSION),
    hash.starknetKeccak(MAINNET_CHAIN_ID),
    BigInt(normalizeStarknetAddress(STRK20_POOL_ADDRESS)),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.programLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    ...fields.splitBps,
    ...fields.jurisdictions.map((value) => hash.starknetKeccak(value)),
    fields.minGross,
    fields.maxAffiliatePayout,
    fields.minTaxReserve,
    fields.maxDust,
    BigInt(fields.amountBitLength),
    BigInt(fields.surplusBitLength),
    BigInt(fields.floorBitLength),
    BigInt(fields.dustBitLength),
    fields.agreementCommitment,
    fields.agreementCommitted ? 1n : 0n,
    fields.payerCommitment,
    fields.payerCommitted ? 1n : 0n,
    ...fields.recipientCommitments,
    hash.starknetKeccak(fields.createdAt),
    fields.memo ? 1n : 0n,
    hash.starknetKeccak(fields.memo),
    fields.issuerPublicKey.x,
    fields.issuerPublicKey.y,
    fields.grossCommitment.x,
    fields.grossCommitment.y,
    ...fields.slotCommitments.flatMap((point) => [point.x, point.y]),
    fields.dustCommitment.x,
    fields.dustCommitment.y,
    fields.h.x,
    fields.h.y,
    hash.starknetKeccak(REVENUE_ROUTING_PROOF_SYSTEM),
    hash.starknetKeccak(REVENUE_ROUTING_NOTICE),
  ]);
}
/** Per-leg statement context: binds every bit challenge to one leg of one certificate. */
function statementContext(bindingHash: bigint, leg: number): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash, BigInt(leg)]);
}

/** Non-interactive challenge for one bit of one leg. */
function bitChallenge(context: bigint, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, context, BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

/** Salted Poseidon commitment to a reference string; hiding and binding. */
function commitRef(domain: bigint, value: string, salt: bigint): bigint {
  return hashElements([domain, hash.starknetKeccak(value), salt]);
}

// ---------------------------------------------------------------------------
// Chaum–Pedersen OR proof of a bit, and the bit-decomposition range proof
// ---------------------------------------------------------------------------

/**
 * Proves a Pedersen commitment `bit·G + blinding·H` opens to 0 or 1 without
 * revealing which. The honest branch runs a real Schnorr proof of knowledge of
 * the blinding; the other branch is simulated from a sampled response and its
 * challenge is fixed by the Fiat–Shamir split `challenge1 = e − challenge0`.
 */
function proveBit(
  bit: bigint,
  blinding: bigint,
  h: CurvePoint,
  context: bigint,
  index: number,
  nextScalar: () => bigint,
): RevenueRoutingBitProof {
  const commitment = pedersenCommit(bit, blinding, h);
  const k = nonZeroScalar(nextScalar());
  const simulatedResponse = nonZeroScalar(nextScalar());
  const simulatedChallenge = nonZeroScalar(nextScalar());

  let a0: CurvePoint;
  let a1: CurvePoint;
  if (bit === 0n) {
    a0 = scalePoint(h, k);
    a1 = scalePoint(h, simulatedResponse).add(scalePoint(commitment.add(G.negate()), simulatedChallenge).negate());
  } else {
    a0 = scalePoint(h, simulatedResponse).add(scalePoint(commitment, simulatedChallenge).negate());
    a1 = scalePoint(h, k);
  }

  const e = bitChallenge(context, index, commitment, a0, a1);
  const challenge0 = bit === 0n ? mod(e - simulatedChallenge, CURVE_ORDER) : simulatedChallenge;
  const challenge1 = mod(e - challenge0, CURVE_ORDER);
  const response0 = bit === 0n ? mod(k + challenge0 * blinding, CURVE_ORDER) : simulatedResponse;
  const response1 = bit === 0n ? simulatedResponse : mod(k + challenge1 * blinding, CURVE_ORDER);

  return {
    commitment: pointToFelts(commitment),
    a0: pointToFelts(a0),
    a1: pointToFelts(a1),
    challenge0: toHex(challenge0),
    response0: toHex(response0),
    response1: toHex(response1),
  };
}
function verifyBit(proof: RevenueRoutingBitProof, h: CurvePoint, context: bigint, index: number): boolean {
  const commitment = pointFromFelts(proof.commitment);
  const a0 = pointFromFelts(proof.a0);
  const a1 = pointFromFelts(proof.a1);
  const challenge0 = requireScalar(proof.challenge0, true);
  const response0 = requireScalar(proof.response0, true);
  const response1 = requireScalar(proof.response1, true);

  const e = bitChallenge(context, index, commitment, a0, a1);
  const challenge1 = mod(e - challenge0, CURVE_ORDER);

  const left0 = scalePoint(h, response0);
  const right0 = a0.add(scalePoint(commitment, challenge0));
  if (!left0.equals(right0)) return false;

  const left1 = scalePoint(h, response1);
  const right1 = a1.add(scalePoint(commitment.add(G.negate()), challenge1));
  return left1.equals(right1);
}

/**
 * Range proof by bit decomposition. Each bit gets its own commitment and OR
 * proof, and the per-bit blindings are forced to sum — weighted by `2^i` — to the
 * parent blinding, so `Σ 2^i · C_i` equals the parent commitment exactly. That
 * identity plus `bitLength` valid bit proofs is what bounds the hidden value to
 * `[0, 2^bitLength)`.
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  h: CurvePoint,
  context: bigint,
  nextScalar: () => bigint,
): RevenueRoutingBitProof[] {
  const blindings: bigint[] = [];
  for (let i = 0; i < bitLength - 1; i += 1) blindings.push(nonZeroScalar(nextScalar()));
  let partial = 0n;
  for (let i = 0; i < bitLength - 1; i += 1) partial = mod(partial + blindings[i] * (1n << BigInt(i)), CURVE_ORDER);
  const topWeight = modInverse(1n << BigInt(bitLength - 1), CURVE_ORDER);
  const lastBlinding = mod((blinding - partial) * topWeight, CURVE_ORDER);
  if (lastBlinding === 0n) throw new Error("Degenerate range-proof blinding; retry with fresh entropy.");
  blindings.push(lastBlinding);

  const proofs: RevenueRoutingBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const bit = (value >> BigInt(i)) & 1n;
    proofs.push(proveBit(bit, blindings[i], h, context, i, nextScalar));
  }
  return proofs;
}
/**
 * Verifies a range proof against the point it is supposed to open: every bit
 * proof must check, and the weighted sum of the per-bit commitments must equal
 * `target` exactly.
 */
function verifyRange(
  proofs: RevenueRoutingBitProof[],
  target: CurvePoint,
  bitLength: number,
  h: CurvePoint,
  context: bigint,
): boolean {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return false;
  let acc = ZERO;
  for (let i = 0; i < bitLength; i += 1) {
    if (!verifyBit(proofs[i], h, context, i)) return false;
    acc = acc.add(scalePoint(pointFromFelts(proofs[i].commitment), 1n << BigInt(i)));
  }
  return acc.equals(target);
}

// ---------------------------------------------------------------------------
// Issuer signature (Schnorr over the binding hash)
// ---------------------------------------------------------------------------

function signBinding(secret: bigint, bindingHash: bigint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(
    hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]),
    CURVE_ORDER,
  );
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

function verifySignature(signature: IssuerSignature, publicKey: CurvePoint, bindingHash: bigint): boolean {
  const challenge = requireScalar(signature.challenge, true);
  const response = requireScalar(signature.response, true);
  const recovered = scalePoint(G, response).add(scalePoint(publicKey, challenge).negate());
  if (recovered.equals(ZERO)) return false;
  const expected = mod(hashElements([SIGNATURE_DOMAIN, recovered.x, recovered.y, bindingHash]), CURVE_ORDER);
  return expected === challenge;
}
// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

/**
 * Builds a revenue routing certificate plus the merchant-held opening material.
 *
 * The six slot payouts are DERIVED here by exact floor division from the hidden
 * gross and the published schedule — they are never accepted as input — so a
 * caller cannot smuggle in payouts that contradict the schedule they publish.
 * Nothing is transmitted, no wallet signs anything, and no value moves.
 */
export function issueRevenueRoutingCertificate(
  input: IssueRevenueRoutingCertificateInput,
  now: Date = new Date(),
  entropy: RevenueRoutingEntropy = {},
): IssuedRevenueRoutingCertificate {
  if (!input || typeof input !== "object") throw new Error("Revenue routing certificate input is required.");
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? ((kind: "certificate") => defaultId(kind));

  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 96);
  const programLabel = requireText(input.programLabel, "programme label", 96);
  if (!input.asset || typeof input.asset !== "object") throw new Error("The settlement asset is required.");
  const assetSymbol = requireText(input.asset.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset.tokenAddress);
  const assetDecimals = requireInt(input.asset.decimals, "asset decimals", 0, MAX_ASSET_DECIMALS);
  const memo = input.memo ? requireText(input.memo, "memo", 240) : "";

  const shares = normalizeRoutingSplit(input.splitBps);
  if (!Array.isArray(input.jurisdictions) || input.jurisdictions.length !== ROUTING_SLOT_COUNT) {
    throw new Error(`Exactly ${ROUTING_SLOT_COUNT} jurisdiction tags are required.`);
  }
  const jurisdictions = input.jurisdictions.map((value, index) =>
    requireText(value, `${REVENUE_ROUTING_SLOTS[index].label} jurisdiction`, MAX_JURISDICTION_LENGTH),
  );
  if (!Array.isArray(input.recipientRefs) || input.recipientRefs.length !== ROUTING_SLOT_COUNT) {
    throw new Error(`Exactly ${ROUTING_SLOT_COUNT} recipient references are required.`);
  }
  const recipientRefs = input.recipientRefs.map((value, index) =>
    requireText(value, `${REVENUE_ROUTING_SLOTS[index].label} recipient reference`, 96),
  );
  const agreementRef = input.agreementRef ? requireText(input.agreementRef, "agreement reference", 96) : "";
  const payerRef = input.payerRef ? requireText(input.payerRef, "payer reference", 96) : "";

  const { minGross, maxAffiliatePayout, minTaxReserve, maxDust } = requireRevenueRoutingPolicy(input.policy);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_ROUTING_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_ROUTING_AMOUNT_BIT_LENGTH,
    MAX_ROUTING_AMOUNT_BIT_LENGTH,
  );
  const surplusBitLength = amountBitLength + ROUTING_SURPLUS_EXTRA_BITS;
  const amountBand = 1n << BigInt(amountBitLength);
  const surplusBand = 1n << BigInt(surplusBitLength);
  const floorBand = 1n << BigInt(ROUTING_FLOOR_BIT_LENGTH);
  const dustBand = 1n << BigInt(ROUTING_DUST_BIT_LENGTH);

  // Every public scalar the verifier later folds in as `scalar·G` needs an
  // explicit canonical bound. Without one, a holder could add
  // FIELD_PRIME·CURVE_ORDER to it: that leaves the value congruent under BOTH the
  // Poseidon field (so the binding hash and the issuer signature still close) and
  // the curve order (so the homomorphic leg still closes), while the range proof
  // only ever covered the unshifted value. The bounds below close that gap.
  if (minGross >= amountBand) throw new Error("The minimum gross settlement does not fit the requested amount range.");
  if (maxAffiliatePayout >= amountBand) throw new Error("The affiliate cap does not fit the requested amount range.");
  if (minTaxReserve >= amountBand) throw new Error("The minimum tax reserve does not fit the requested amount range.");
  if (maxDust >= dustBand) throw new Error("The rounding tolerance does not fit the rounding range.");

  const gross = requireBaseUnits(input.grossBaseUnits, "gross settlement");
  if (gross > U128_MAX) throw new Error("The gross settlement exceeds the u128 range STRK20 notes use.");
  if (gross >= amountBand) throw new Error(`The gross settlement does not fit ${amountBitLength} bits.`);

  const plan = computeRevenueRoutingPlan(gross, shares.map((share) => Number(share)));
  const payouts = plan.slots.map((slot) => BigInt(slot.payoutBaseUnits));
  const dust = BigInt(plan.dustBaseUnits);

  const assessment = assessRoutingPolicy(plan, input.policy);
  if (!assessment.eligible) throw new Error(assessment.blockers[0]);

  const grossFloorSurplus = gross - minGross;
  const affiliateCapSurplus = maxAffiliatePayout - payouts[AFFILIATE_SLOT_INDEX];
  const taxFloorSurplus = payouts[TAX_RESERVE_SLOT_INDEX] - minTaxReserve;
  const dustCeilingSurplus = maxDust - dust;
  if (grossFloorSurplus >= surplusBand || affiliateCapSurplus >= surplusBand || taxFloorSurplus >= surplusBand) {
    throw new Error("A covenant surplus does not fit the surplus range; widen the amount range.");
  }
  if (dustCeilingSurplus >= dustBand) {
    throw new Error("The rounding tolerance surplus does not fit the rounding range.");
  }
  // The two exact-floor legs per slot. Their values are `bps·gross mod 10000` and
  // its complement `9999 −` that, so an honest split always lands both inside the
  // 14-bit floor band; proving both non-negative is what pins the payout to the
  // exact integer floor rather than merely to something near it.
  const floorLowerValues = shares.map((bps, index) => bps * gross - BPS_SCALE * payouts[index]);
  const floorUpperValues = shares.map((bps, index) => BPS_SCALE * payouts[index] + MAX_FLOOR_LEG_VALUE - bps * gross);
  for (let index = 0; index < ROUTING_SLOT_COUNT; index += 1) {
    const label = REVENUE_ROUTING_SLOTS[index].label;
    if (floorLowerValues[index] < 0n || floorLowerValues[index] >= floorBand) {
      throw new Error(`The ${label} payout is not the exact floor of its published share.`);
    }
    if (floorUpperValues[index] < 0n || floorUpperValues[index] >= floorBand) {
      throw new Error(`The ${label} payout is not the exact floor of its published share.`);
    }
  }

  const h = independentGenerator();
  const grossBlinding = nonZeroScalar(nextScalar());
  const slotBlindings: bigint[] = [];
  for (let index = 0; index < ROUTING_SLOT_COUNT; index += 1) slotBlindings.push(nonZeroScalar(nextScalar()));

  // Conservation is a POINT IDENTITY, not an extra leg: forcing the remainder
  // blinding to `grossBlinding − Σ slotBlindings` makes
  // `Σ slotCommitments + dustCommitment` equal `grossCommitment` exactly when
  // `Σ payouts + remainder ≡ gross (mod n)`. Seven addends each below 2^128 sum to
  // under 2^131, far below the curve order, so that congruence forces integer
  // equality. Every blinding below is derived the same way: each derived
  // commitment has to land on the verifier's homomorphic target point exactly, so
  // its blinding is computed, never sampled.
  const dustBlinding = mod(grossBlinding - slotBlindings.reduce((acc, value) => acc + value, 0n), CURVE_ORDER);
  const floorLowerBlindings = shares.map((bps, index) =>
    mod(bps * grossBlinding - BPS_SCALE * slotBlindings[index], CURVE_ORDER),
  );
  const floorUpperBlindings = shares.map((bps, index) =>
    mod(BPS_SCALE * slotBlindings[index] - bps * grossBlinding, CURVE_ORDER),
  );
  const grossFloorSurplusBlinding = grossBlinding;
  const affiliateCapSurplusBlinding = mod(-slotBlindings[AFFILIATE_SLOT_INDEX], CURVE_ORDER);
  const taxFloorSurplusBlinding = slotBlindings[TAX_RESERVE_SLOT_INDEX];
  const dustCeilingSurplusBlinding = mod(-dustBlinding, CURVE_ORDER);

  const grossCommitment = pedersenCommit(gross, grossBlinding, h);
  const slotCommitments = payouts.map((payout, index) => pedersenCommit(payout, slotBlindings[index], h));
  const dustCommitment = pedersenCommit(dust, dustBlinding, h);
  const agreementSalt = nonZeroScalar(nextScalar());
  const payerSalt = nonZeroScalar(nextScalar());
  const recipientSalts = recipientRefs.map(() => nonZeroScalar(nextScalar()));
  const agreementCommitment = commitRef(AGREEMENT_DOMAIN, agreementRef, agreementSalt);
  const payerCommitment = commitRef(PAYER_DOMAIN, payerRef, payerSalt);
  // Recipient commitments bind the slot index as well as the reference, so a
  // disclosure opened for one slot cannot be replayed as another slot's recipient.
  const recipientCommitments = recipientRefs.map((ref, index) =>
    commitRecipientRef(ref, recipientSalts[index], index),
  );

  const createdAt = requireIsoTimestamp(now.toISOString());
  const certificateId = requireText(createId("certificate"), "certificate id", 96);
  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerPublicKey = publicKeyFromSecret(issuerSecret);

  const bindingHash = computeBindingHash({
    merchantAlias,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    splitBps: shares,
    jurisdictions,
    minGross,
    maxAffiliatePayout,
    minTaxReserve,
    maxDust,
    amountBitLength,
    surplusBitLength,
    floorBitLength: ROUTING_FLOOR_BIT_LENGTH,
    dustBitLength: ROUTING_DUST_BIT_LENGTH,
    agreementCommitment,
    agreementCommitted: agreementRef !== "",
    payerCommitment,
    payerCommitted: payerRef !== "",
    recipientCommitments,
    certificateId,
    createdAt,
    memo,
    issuerPublicKey,
    grossCommitment,
    slotCommitments,
    dustCommitment,
    h,
  });
  const grossBits = proveRange(
    gross,
    grossBlinding,
    amountBitLength,
    h,
    statementContext(bindingHash, LEG_GROSS),
    nextScalar,
  );
  const slotBits = payouts.map((payout, index) =>
    proveRange(payout, slotBlindings[index], amountBitLength, h, statementContext(bindingHash, index), nextScalar),
  );
  const dustBits = proveRange(
    dust,
    dustBlinding,
    ROUTING_DUST_BIT_LENGTH,
    h,
    statementContext(bindingHash, LEG_DUST),
    nextScalar,
  );
  const floorLowerBits = floorLowerValues.map((value, index) =>
    proveRange(
      value,
      floorLowerBlindings[index],
      ROUTING_FLOOR_BIT_LENGTH,
      h,
      statementContext(bindingHash, LEG_FLOOR_LOWER_BASE + index),
      nextScalar,
    ),
  );
  const floorUpperBits = floorUpperValues.map((value, index) =>
    proveRange(
      value,
      floorUpperBlindings[index],
      ROUTING_FLOOR_BIT_LENGTH,
      h,
      statementContext(bindingHash, LEG_FLOOR_UPPER_BASE + index),
      nextScalar,
    ),
  );
  const grossFloorSurplusBits = proveRange(
    grossFloorSurplus,
    grossFloorSurplusBlinding,
    surplusBitLength,
    h,
    statementContext(bindingHash, LEG_GROSS_FLOOR_SURPLUS),
    nextScalar,
  );
  const affiliateCapSurplusBits = proveRange(
    affiliateCapSurplus,
    affiliateCapSurplusBlinding,
    surplusBitLength,
    h,
    statementContext(bindingHash, LEG_AFFILIATE_CAP_SURPLUS),
    nextScalar,
  );
  const taxFloorSurplusBits = proveRange(
    taxFloorSurplus,
    taxFloorSurplusBlinding,
    surplusBitLength,
    h,
    statementContext(bindingHash, LEG_TAX_FLOOR_SURPLUS),
    nextScalar,
  );
  const dustCeilingSurplusBits = proveRange(
    dustCeilingSurplus,
    dustCeilingSurplusBlinding,
    ROUTING_DUST_BIT_LENGTH,
    h,
    statementContext(bindingHash, LEG_DUST_CEILING_SURPLUS),
    nextScalar,
  );

  const proof: RevenueRoutingProof = {
    proofSystem: REVENUE_ROUTING_PROOF_SYSTEM,
    amountBitLength,
    surplusBitLength,
    floorBitLength: ROUTING_FLOOR_BIT_LENGTH,
    dustBitLength: ROUTING_DUST_BIT_LENGTH,
    generatorH: pointToFelts(h),
    grossCommitment: pointToFelts(grossCommitment),
    slotCommitments: slotCommitments.map((point) => pointToFelts(point)),
    dustCommitment: pointToFelts(dustCommitment),
    grossBits,
    slotBits,
    dustBits,
    floorLowerBits,
    floorUpperBits,
    grossFloorSurplusBits,
    affiliateCapSurplusBits,
    taxFloorSurplusBits,
    dustCeilingSurplusBits,
  };
  const certificate: RevenueRoutingCertificate = {
    kind: CERTIFICATE_KIND,
    version: REVENUE_ROUTING_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    merchantAlias,
    programLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    splitBps: shares.map((share) => share.toString()),
    jurisdictions,
    minGrossBaseUnits: minGross.toString(),
    maxAffiliatePayoutBaseUnits: maxAffiliatePayout.toString(),
    minTaxReserveBaseUnits: minTaxReserve.toString(),
    maxDustBaseUnits: maxDust.toString(),
    agreementCommitment: toHex(agreementCommitment),
    agreementCommitted: agreementRef !== "",
    payerCommitment: toHex(payerCommitment),
    payerCommitted: payerRef !== "",
    recipientCommitments: recipientCommitments.map((value) => toHex(value)),
    issuerPublicKey: pointToFelts(issuerPublicKey),
    proof,
    issuerSignature: signBinding(issuerSecret, bindingHash, nextScalar),
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: REVENUE_ROUTING_NOTICE,
  };
  const secret: RevenueRoutingCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    grossBaseUnits: gross.toString(),
    slotPayoutsBaseUnits: payouts.map((payout) => payout.toString()),
    dustBaseUnits: dust.toString(),
    splitBps: shares.map((share) => share.toString()),
    minGrossBaseUnits: minGross.toString(),
    maxAffiliatePayoutBaseUnits: maxAffiliatePayout.toString(),
    minTaxReserveBaseUnits: minTaxReserve.toString(),
    maxDustBaseUnits: maxDust.toString(),
    grossBlinding: toHex(grossBlinding),
    slotBlindings: slotBlindings.map((value) => toHex(value)),
    dustBlinding: toHex(dustBlinding),
    floorLowerBlindings: floorLowerBlindings.map((value) => toHex(value)),
    floorUpperBlindings: floorUpperBlindings.map((value) => toHex(value)),
    grossFloorSurplusBlinding: toHex(grossFloorSurplusBlinding),
    affiliateCapSurplusBlinding: toHex(affiliateCapSurplusBlinding),
    taxFloorSurplusBlinding: toHex(taxFloorSurplusBlinding),
    dustCeilingSurplusBlinding: toHex(dustCeilingSurplusBlinding),
    agreementRef,
    agreementSalt: toHex(agreementSalt),
    payerRef,
    payerSalt: toHex(payerSalt),
    payerCommitted: payerRef !== "",
    recipientRefs,
    recipientSalts: recipientSalts.map((value) => toHex(value)),
  };

  return { certificate, secret };
}
// ---------------------------------------------------------------------------
// Audit and verify
// ---------------------------------------------------------------------------

/**
 * Ordered audit rows. The order is fixed so a portal can render a stable table
 * and so a certificate that bails early still reports every row.
 */
const CHECK_LABELS = [
  "Envelope kind",
  "Engine version",
  "Network",
  "Pool provenance",
  "Limitation notice",
  "Proof system",
  "Range bands",
  "Independent generator",
  "Entitlement schedule",
  "Jurisdiction tags",
  "Covenant scalar bounds",
  "Binding hash",
  "Issuer signature",
  "Gross range proof",
  "Slot payout range proofs",
  "Rounding remainder range proof",
  "Split conservation",
  "Exact-floor lower bounds",
  "Exact-floor upper bounds",
  "Settlement floor covenant",
  "Affiliate cap covenant",
  "Tax reserve floor covenant",
  "Rounding tolerance covenant",
] as const;

export const REVENUE_ROUTING_CHECK_COUNT = CHECK_LABELS.length;
/**
 * Re-derives every relation a revenue routing certificate claims and reports one
 * row per check. It needs nothing but the certificate: no secret, no network, no
 * chain state. A row that reads "Not evaluated" means an earlier row failed and
 * the rest of the transcript could not be reached.
 */
export function auditRevenueRoutingCertificate(certificate: RevenueRoutingCertificate): RevenueRoutingCheck[] {
  const rows: RevenueRoutingCheck[] = [];
  const push = (detail: string, passed: boolean): boolean => {
    rows.push({ label: CHECK_LABELS[rows.length], detail, passed });
    return passed;
  };
  const pad = (): RevenueRoutingCheck[] => {
    while (rows.length < CHECK_LABELS.length) {
      rows.push({
        label: CHECK_LABELS[rows.length],
        detail: "Not evaluated because an earlier check failed.",
        passed: false,
      });
    }
    return rows;
  };

  try {
    if (!certificate || typeof certificate !== "object") {
      push("The certificate is missing or is not an object.", false);
      return pad();
    }
    if (!push(`Envelope declares ${CERTIFICATE_KIND}.`, certificate.kind === CERTIFICATE_KIND)) return pad();
    if (!push(`Engine version is ${REVENUE_ROUTING_ENGINE_VERSION}.`, certificate.version === REVENUE_ROUTING_ENGINE_VERSION)) {
      return pad();
    }
    if (!push(`Network is ${MAINNET_CHAIN_ID}.`, certificate.network === MAINNET_CHAIN_ID)) return pad();
    // The binding hash commits to the MODULE's pool address, notice, and proof
    // system rather than to the certificate's copies, so each copy is compared
    // literally here. Without this row a holder could rewrite the notice — the
    // one place the certificate states what it does not do — and still present a
    // certificate whose hash and signature verify.
    if (
      !push(
        "Pool address matches the recorded STRK20 pool (provenance only; never called).",
        safeNormalizeAddress(certificate.poolAddress) === safeNormalizeAddress(STRK20_POOL_ADDRESS),
      )
    ) {
      return pad();
    }
    if (!push("Limitation notice is unmodified.", certificate.notice === REVENUE_ROUTING_NOTICE)) return pad();
    const proof = certificate.proof;
    if (!proof || typeof proof !== "object") {
      push("The proof bundle is missing.", false);
      return pad();
    }
    if (!push(`Proof system is ${REVENUE_ROUTING_PROOF_SYSTEM}.`, proof.proofSystem === REVENUE_ROUTING_PROOF_SYSTEM)) {
      return pad();
    }

    const amountBitLength = proof.amountBitLength;
    const bandsOk =
      Number.isInteger(amountBitLength) &&
      amountBitLength >= MIN_ROUTING_AMOUNT_BIT_LENGTH &&
      amountBitLength <= MAX_ROUTING_AMOUNT_BIT_LENGTH &&
      proof.surplusBitLength === amountBitLength + ROUTING_SURPLUS_EXTRA_BITS &&
      proof.floorBitLength === ROUTING_FLOOR_BIT_LENGTH &&
      proof.dustBitLength === ROUTING_DUST_BIT_LENGTH &&
      Array.isArray(proof.slotCommitments) &&
      proof.slotCommitments.length === ROUTING_SLOT_COUNT &&
      Array.isArray(proof.slotBits) &&
      proof.slotBits.length === ROUTING_SLOT_COUNT &&
      Array.isArray(proof.floorLowerBits) &&
      proof.floorLowerBits.length === ROUTING_SLOT_COUNT &&
      Array.isArray(proof.floorUpperBits) &&
      proof.floorUpperBits.length === ROUTING_SLOT_COUNT &&
      Array.isArray(certificate.recipientCommitments) &&
      certificate.recipientCommitments.length === ROUTING_SLOT_COUNT;
    if (
      !push(
        `Amount band ${amountBitLength} bits, surplus band ${proof.surplusBitLength}, floor band ${proof.floorBitLength}, remainder band ${proof.dustBitLength}, over ${ROUTING_SLOT_COUNT} slots.`,
        bandsOk,
      )
    ) {
      return pad();
    }

    const h = pointFromFelts(proof.generatorH);
    if (!push("Blinding generator H is this module's hash-to-curve generator.", h.equals(independentGenerator()))) {
      return pad();
    }

    if (!Array.isArray(certificate.splitBps) || certificate.splitBps.length !== ROUTING_SLOT_COUNT) {
      push(`The entitlement schedule must publish ${ROUTING_SLOT_COUNT} shares.`, false);
      return pad();
    }
    const shares = certificate.splitBps.map((value) => requireBaseUnits(value, "entitlement basis points"));
    const scheduleTotal = shares.reduce((acc, value) => acc + value, 0n);
    const scheduleOk = shares.every((value) => value <= BPS_SCALE) && scheduleTotal === BPS_SCALE;
    if (!push(`Six published shares total ${scheduleTotal} of ${BPS_SCALE} basis points.`, scheduleOk)) return pad();
    const jurisdictionsOk =
      Array.isArray(certificate.jurisdictions) &&
      certificate.jurisdictions.length === ROUTING_SLOT_COUNT &&
      certificate.jurisdictions.every(
        (tag) => typeof tag === "string" && tag.length > 0 && tag.length <= MAX_JURISDICTION_LENGTH,
      );
    if (
      !push(
        `Six jurisdiction tags published, each at most ${MAX_JURISDICTION_LENGTH} characters.`,
        jurisdictionsOk,
      )
    ) {
      return pad();
    }

    const minGross = requireBaseUnits(certificate.minGrossBaseUnits, "minimum gross settlement");
    const maxAffiliatePayout = requireBaseUnits(certificate.maxAffiliatePayoutBaseUnits, "maximum affiliate payout");
    const minTaxReserve = requireBaseUnits(certificate.minTaxReserveBaseUnits, "minimum tax reserve");
    const maxDust = requireBaseUnits(certificate.maxDustBaseUnits, "rounding tolerance");
    const amountBand = 1n << BigInt(amountBitLength);
    const dustBand = 1n << BigInt(ROUTING_DUST_BIT_LENGTH);
    // CANONICAL BOUNDS. Each of these four scalars is folded into a homomorphic
    // target as `scalar·G`, so each needs an explicit upper bound. Poseidon reduces
    // mod FIELD_PRIME p, `scalePoint` reduces mod CURVE_ORDER n, and adding p·n to
    // a scalar leaves it congruent under BOTH: the binding hash still matches, the
    // issuer signature still verifies, and the target point is unchanged — while
    // the range proof only ever covered the unshifted value. A holder could then
    // advertise an astronomical settlement floor or reserve floor with a proof that
    // says nothing about it. Bounding each scalar below its own proof band is what
    // makes the covenant legs mean what they claim.
    const boundsOk =
      minGross < amountBand && maxAffiliatePayout < amountBand && minTaxReserve < amountBand && maxDust < dustBand;
    if (
      !push(
        "Published covenant scalars are canonically bounded by the bands their proofs cover.",
        boundsOk,
      )
    ) {
      return pad();
    }

    const issuerPublicKey = pointFromFelts(certificate.issuerPublicKey);
    const grossCommitment = pointFromFelts(proof.grossCommitment);
    const slotCommitments = proof.slotCommitments.map((point) => pointFromFelts(point));
    const dustCommitment = pointFromFelts(proof.dustCommitment);
    const bindingHash = computeBindingHash({
      merchantAlias: certificate.merchantAlias,
      programLabel: certificate.programLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: normalizeStarknetAddress(certificate.tokenAddress),
      assetDecimals: requireInt(certificate.assetDecimals, "asset decimals", 0, MAX_ASSET_DECIMALS),
      splitBps: shares,
      jurisdictions: certificate.jurisdictions,
      minGross,
      maxAffiliatePayout,
      minTaxReserve,
      maxDust,
      amountBitLength,
      surplusBitLength: proof.surplusBitLength,
      floorBitLength: proof.floorBitLength,
      dustBitLength: proof.dustBitLength,
      agreementCommitment: requireFelt(certificate.agreementCommitment),
      agreementCommitted: certificate.agreementCommitted === true,
      payerCommitment: requireFelt(certificate.payerCommitment),
      payerCommitted: certificate.payerCommitted === true,
      recipientCommitments: certificate.recipientCommitments.map((value) => requireFelt(value)),
      certificateId: requireText(certificate.certificateId, "certificate id", 96),
      createdAt: requireIsoTimestamp(certificate.createdAt),
      memo: typeof certificate.memo === "string" ? certificate.memo : "",
      issuerPublicKey,
      grossCommitment,
      slotCommitments,
      dustCommitment,
      h,
    });
    if (
      !push(
        "Binding hash reproduces from every published field and commitment.",
        toHex(bindingHash) === certificate.bindingHash,
      )
    ) {
      return pad();
    }
    if (
      !push(
        "Issuer signature verifies against the embedded public key.",
        verifySignature(certificate.issuerSignature, issuerPublicKey, bindingHash),
      )
    ) {
      return pad();
    }
    if (
      !push(
        `Gross settlement is committed inside [0, 2^${amountBitLength}).`,
        verifyRange(proof.grossBits, grossCommitment, amountBitLength, h, statementContext(bindingHash, LEG_GROSS)),
      )
    ) {
      return pad();
    }

    let slotRangesOk = true;
    for (let index = 0; index < ROUTING_SLOT_COUNT; index += 1) {
      const ok = verifyRange(
        proof.slotBits[index],
        slotCommitments[index],
        amountBitLength,
        h,
        statementContext(bindingHash, index),
      );
      if (!ok) {
        slotRangesOk = false;
        break;
      }
    }
    if (!push(`All ${ROUTING_SLOT_COUNT} slot payouts are committed inside [0, 2^${amountBitLength}).`, slotRangesOk)) {
      return pad();
    }

    if (
      !push(
        `Rounding remainder is committed inside [0, 2^${proof.dustBitLength}).`,
        verifyRange(proof.dustBits, dustCommitment, proof.dustBitLength, h, statementContext(bindingHash, LEG_DUST)),
      )
    ) {
      return pad();
    }

    // Conservation needs no proof leg of its own: the commitments are additively
    // homomorphic, so this single point identity says the six hidden payouts plus
    // the hidden remainder sum to the hidden gross, to the last base unit.
    const conserved = slotCommitments.reduce((acc, point) => acc.add(point), ZERO).add(dustCommitment);
    if (
      !push(
        "Six payouts plus the rounding remainder conserve the gross exactly.",
        conserved.equals(grossCommitment),
      )
    ) {
      return pad();
    }
    // The two floor legs together are what make the split ratios PROVEN rather
    // than asserted. The lower leg forces `10000·payout ≤ bps·gross` and the upper
    // forces `bps·gross − 10000·payout ≤ 9999`, and the only integer satisfying
    // both is `payout = floor(bps·gross / 10000)`.
    let lowerOk = true;
    for (let index = 0; index < ROUTING_SLOT_COUNT; index += 1) {
      const target = scalePoint(grossCommitment, shares[index]).add(
        scalePoint(slotCommitments[index], BPS_SCALE).negate(),
      );
      const ok = verifyRange(
        proof.floorLowerBits[index],
        target,
        proof.floorBitLength,
        h,
        statementContext(bindingHash, LEG_FLOOR_LOWER_BASE + index),
      );
      if (!ok) {
        lowerOk = false;
        break;
      }
    }
    if (!push("Every payout is at most its published share of the gross.", lowerOk)) return pad();

    let upperOk = true;
    for (let index = 0; index < ROUTING_SLOT_COUNT; index += 1) {
      const target = scalePoint(slotCommitments[index], BPS_SCALE)
        .add(scalePoint(G, MAX_FLOOR_LEG_VALUE))
        .add(scalePoint(grossCommitment, shares[index]).negate());
      const ok = verifyRange(
        proof.floorUpperBits[index],
        target,
        proof.floorBitLength,
        h,
        statementContext(bindingHash, LEG_FLOOR_UPPER_BASE + index),
      );
      if (!ok) {
        upperOk = false;
        break;
      }
    }
    if (
      !push(
        "Every payout is the exact integer floor of its published share, never rounded up or shaved.",
        upperOk,
      )
    ) {
      return pad();
    }
    const settlementFloorTarget = grossCommitment.add(scalePoint(G, minGross).negate());
    if (
      !push(
        `Gross settlement is at least the published floor of ${minGross} base units.`,
        verifyRange(
          proof.grossFloorSurplusBits,
          settlementFloorTarget,
          proof.surplusBitLength,
          h,
          statementContext(bindingHash, LEG_GROSS_FLOOR_SURPLUS),
        ),
      )
    ) {
      return pad();
    }

    const affiliateCapTarget = scalePoint(G, maxAffiliatePayout).add(slotCommitments[AFFILIATE_SLOT_INDEX].negate());
    if (
      !push(
        `Affiliate payout is at most the published cap of ${maxAffiliatePayout} base units.`,
        verifyRange(
          proof.affiliateCapSurplusBits,
          affiliateCapTarget,
          proof.surplusBitLength,
          h,
          statementContext(bindingHash, LEG_AFFILIATE_CAP_SURPLUS),
        ),
      )
    ) {
      return pad();
    }

    const taxFloorTarget = slotCommitments[TAX_RESERVE_SLOT_INDEX].add(scalePoint(G, minTaxReserve).negate());
    if (
      !push(
        `Tax reserve is at least the published floor of ${minTaxReserve} base units.`,
        verifyRange(
          proof.taxFloorSurplusBits,
          taxFloorTarget,
          proof.surplusBitLength,
          h,
          statementContext(bindingHash, LEG_TAX_FLOOR_SURPLUS),
        ),
      )
    ) {
      return pad();
    }
    const dustCeilingTarget = scalePoint(G, maxDust).add(dustCommitment.negate());
    push(
      `Rounding remainder is at most the published tolerance of ${maxDust} base units.`,
      verifyRange(
        proof.dustCeilingSurplusBits,
        dustCeilingTarget,
        proof.dustBitLength,
        h,
        statementContext(bindingHash, LEG_DUST_CEILING_SURPLUS),
      ),
    );
    return pad();
  } catch (error) {
    const message = error instanceof Error ? error.message : "the certificate is malformed";
    if (rows.length < CHECK_LABELS.length) {
      rows.push({ label: CHECK_LABELS[rows.length], detail: `Rejected: ${message}`, passed: false });
    }
    return pad();
  }
}

/**
 * True only when every audit row passes. Any malformed field, tampered scalar, or
 * failed proof leg returns false rather than throwing, so a portal can hand this
 * an arbitrary pasted envelope.
 */
export function verifyRevenueRoutingCertificate(certificate: RevenueRoutingCertificate): boolean {
  try {
    const rows = auditRevenueRoutingCertificate(certificate);
    return rows.length === CHECK_LABELS.length && rows.every((row) => row.passed);
  } catch {
    return false;
  }
}

function safeNormalizeAddress(value: string): string {
  try {
    return normalizeStarknetAddress(value);
  } catch {
    return "";
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure
// ---------------------------------------------------------------------------

function commitRecipientRef(value: string, salt: bigint, slotIndex: number): bigint {
  return hashElements([RECIPIENT_DOMAIN, BigInt(slotIndex), hash.starknetKeccak(value), salt]);
}

function routingSlotIndexFromField(field: string): number {
  const match = /^(?:slot|recipient)([0-5])$/.exec(field);
  if (!match) throw new Error("Unknown revenue routing disclosure field.");
  return Number.parseInt(match[1], 10);
}

function selectAmountField(
  secret: RevenueRoutingCertificateSecret,
  field: RevenueRoutingAmountField,
): { amount: string; blinding: string } {
  if (field === "gross") return { amount: secret.grossBaseUnits, blinding: secret.grossBlinding };
  if (field === "dust") return { amount: secret.dustBaseUnits, blinding: secret.dustBlinding };
  const index = routingSlotIndexFromField(field);
  return { amount: secret.slotPayoutsBaseUnits[index], blinding: secret.slotBlindings[index] };
}

/**
 * Opens exactly one committed amount — the gross, one slot payout, or the
 * rounding remainder — and nothing else. Publishing an opening reveals that one
 * figure; because the entitlement schedule is public, any single opening also
 * lets the holder derive the gross and every other payout, so open deliberately.
 */
export function buildRevenueRoutingAmountDisclosure(
  secret: RevenueRoutingCertificateSecret,
  field: RevenueRoutingAmountField,
): RevenueRoutingAmountDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("The revenue routing certificate secret is required.");
  const { amount, blinding } = selectAmountField(secret, field);
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field,
    amountBaseUnits: requireBaseUnits(amount, "disclosed amount").toString(),
    blinding: toHex(requireScalar(blinding, true)),
  };
}
/**
 * Checks an amount opening against the certificate it claims to belong to. It
 * re-verifies the whole certificate first, so a disclosure can never lend
 * credibility to a certificate that does not itself verify.
 */
export function verifyRevenueRoutingAmountDisclosure(
  certificate: RevenueRoutingCertificate,
  disclosure: RevenueRoutingAmountDisclosure,
): boolean {
  try {
    if (!disclosure || disclosure.kind !== AMOUNT_DISCLOSURE_KIND) return false;
    if (!certificate || disclosure.certificateId !== certificate.certificateId) return false;
    if (!verifyRevenueRoutingCertificate(certificate)) return false;

    const proof = certificate.proof;
    const h = pointFromFelts(proof.generatorH);
    const amount = requireBaseUnits(disclosure.amountBaseUnits, "disclosed amount");
    const blinding = requireScalar(disclosure.blinding, true);

    // The disclosed amount is folded in as `amount·G`, so it needs the same
    // canonical bound as the covenant scalars: a value shifted by
    // FIELD_PRIME·CURVE_ORDER would still reproduce the commitment while claiming
    // an astronomical figure. Bounding it to the band its range proof covers is
    // what makes the opening mean the number it prints.
    const band =
      disclosure.field === "dust" ? 1n << BigInt(proof.dustBitLength) : 1n << BigInt(proof.amountBitLength);
    if (amount >= band) return false;

    const target =
      disclosure.field === "gross"
        ? pointFromFelts(proof.grossCommitment)
        : disclosure.field === "dust"
          ? pointFromFelts(proof.dustCommitment)
          : pointFromFelts(proof.slotCommitments[routingSlotIndexFromField(disclosure.field)]);
    return pedersenCommit(amount, blinding, h).equals(target);
  } catch {
    return false;
  }
}
/** Opens the salted agreement reference. Throws when none was committed. */
export function buildRevenueRoutingAgreementDisclosure(
  secret: RevenueRoutingCertificateSecret,
): RevenueRoutingRefDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("The revenue routing certificate secret is required.");
  if (!secret.agreementRef) throw new Error("This certificate committed no agreement reference.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "agreementRef",
    value: secret.agreementRef,
    salt: toHex(requireScalar(secret.agreementSalt, false)),
  };
}

/** Opens the salted payer reference. Throws when none was committed. */
export function buildRevenueRoutingPayerDisclosure(
  secret: RevenueRoutingCertificateSecret,
): RevenueRoutingRefDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("The revenue routing certificate secret is required.");
  if (!secret.payerCommitted || !secret.payerRef) throw new Error("This certificate committed no payer reference.");
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: "payerRef",
    value: secret.payerRef,
    salt: toHex(requireScalar(secret.payerSalt, false)),
  };
}

/** Opens one slot's salted recipient reference, and only that slot's. */
export function buildRevenueRoutingRecipientDisclosure(
  secret: RevenueRoutingCertificateSecret,
  slotIndex: number,
): RevenueRoutingRefDisclosure {
  if (!secret || secret.kind !== SECRET_KIND) throw new Error("The revenue routing certificate secret is required.");
  const index = requireInt(slotIndex, "routing slot index", 0, ROUTING_SLOT_COUNT - 1);
  return {
    kind: REF_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    field: `recipient${index as 0 | 1 | 2 | 3 | 4 | 5}`,
    value: requireText(secret.recipientRefs[index], "recipient reference", 96),
    salt: toHex(requireScalar(secret.recipientSalts[index], false)),
  };
}
/**
 * Checks a reference opening against the salted commitment the certificate
 * published. Recipient commitments bind the slot index too, so an opening for one
 * slot cannot be replayed as another slot's recipient.
 */
export function verifyRevenueRoutingRefDisclosure(
  certificate: RevenueRoutingCertificate,
  disclosure: RevenueRoutingRefDisclosure,
): boolean {
  try {
    if (!disclosure || disclosure.kind !== REF_DISCLOSURE_KIND) return false;
    if (!certificate || disclosure.certificateId !== certificate.certificateId) return false;
    if (!verifyRevenueRoutingCertificate(certificate)) return false;

    const value = requireText(disclosure.value, "disclosed reference", 96);
    const salt = requireScalar(disclosure.salt, false);

    if (disclosure.field === "agreementRef") {
      if (!certificate.agreementCommitted) return false;
      return toHex(commitRef(AGREEMENT_DOMAIN, value, salt)) === certificate.agreementCommitment;
    }
    if (disclosure.field === "payerRef") {
      if (!certificate.payerCommitted) return false;
      return toHex(commitRef(PAYER_DOMAIN, value, salt)) === certificate.payerCommitment;
    }
    const index = routingSlotIndexFromField(disclosure.field);
    return toHex(commitRecipientRef(value, salt, index)) === certificate.recipientCommitments[index];
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Badge, trust model, and visibility model
// ---------------------------------------------------------------------------

/**
 * A compact, shareable summary of a certificate. It carries no secret and no
 * opening: everything in it is already public in the certificate itself.
 */
export function buildRevenueRoutingCertificateBadge(
  certificate: RevenueRoutingCertificate,
): RevenueRoutingCertificateBadge {
  if (!verifyRevenueRoutingCertificate(certificate)) {
    throw new Error("Only a verifying revenue routing certificate can be summarized.");
  }
  const scheduleSummary = certificate.splitBps.map(
    (bps, index) =>
      `${REVENUE_ROUTING_SLOT_LABELS[index]} · ${formatRoutingBps(Number(bps))} · ${certificate.jurisdictions[index]}`,
  );
  const covenantSummary = [
    `Gross settlement at least ${formatRoutingBaseUnits(certificate.minGrossBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    `Affiliate payout at most ${formatRoutingBaseUnits(certificate.maxAffiliatePayoutBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    `Tax reserve at least ${formatRoutingBaseUnits(certificate.minTaxReserveBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    `Rounding remainder at most ${certificate.maxDustBaseUnits} base units`,
  ];
  const uniqueJurisdictions = [...new Set(certificate.jurisdictions)].sort((a, b) => a.localeCompare(b));

  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    merchantAlias: certificate.merchantAlias,
    programLabel: certificate.programLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    headline: `Split proven exactly at a published ${ROUTING_SLOT_COUNT}-way schedule`,
    claim:
      "Zero-knowledge proof that six hidden payouts plus a hidden rounding remainder conserve a hidden gross settlement, that each payout is the exact integer floor of its published share, and that four public covenants hold. It routes nothing and moves no value.",
    scheduleSummary,
    covenantSummary,
    jurisdictionSummary: `${uniqueJurisdictions.length} corridor${uniqueJurisdictions.length === 1 ? "" : "s"}: ${uniqueJurisdictions.join(", ")}`,
    proofCount: estimateRevenueRoutingProofCount(certificate.proof.amountBitLength),
    payerCommitted: certificate.payerCommitted,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
    notice: certificate.notice,
  };
}
/**
 * The trust model as explicit booleans, so a UI cannot quietly overstate what a
 * certificate means. Every "false" below is a real limitation, not a placeholder.
 */
export function getRevenueRoutingTrustModel(): RevenueRoutingTrustModel {
  return {
    isZeroKnowledge: true,
    provesGrossConservation: true,
    provesExactFloorSplits: true,
    provesRoundingTolerance: true,
    provesSettlementFloor: true,
    provesAffiliateCap: true,
    provesTaxReserveFloor: true,
    hidesGrossAmount: true,
    hidesSlotPayouts: true,
    hidesRecipientReferences: true,
    hidesPayerReference: true,
    hidesSettlementRows: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    publishesEntitlementSchedule: true,
    publishesJurisdictions: true,
    isDecentralized: false,
    isAutomatic: false,
    routesOrMovesFunds: false,
    paysAnyStakeholder: false,
    withholdsAnyTax: false,
    observesIncomingPayments: false,
    readsShieldedBalances: false,
    settlesOnChain: false,
    movesPoolFunds: false,
    callsPoolContract: false,
    verifiesFiguresAreReal: false,
    verifiesRecipientsExist: false,
    isTaxAdvice: false,
    isFinancialAdvice: false,
    proven: [
      "The six hidden payouts plus the hidden rounding remainder sum to the hidden gross settlement exactly.",
      "Each payout equals the exact integer floor of its published basis-point share of that gross.",
      "The gross settlement is at least the published minimum settlement floor.",
      "The affiliate payout is at most the published affiliate cap.",
      "The tax reserve is at least the published minimum reserve.",
      "The unallocated rounding remainder is at most the published tolerance.",
      "A specific merchant public key issued the certificate, checkable offline.",
    ],
    hidden: [
      "The gross settlement amount.",
      "Every per-slot payout, including the affiliate share and the tax reserve.",
      "The unallocated rounding remainder.",
      "The payer reference and every recipient reference (salted commitments only).",
      "The underlying settlement rows and the corridor ledger built from them.",
    ],
    visible: [
      "The entitlement schedule in basis points, slot by slot.",
      "The per-slot jurisdiction tags.",
      "The four covenant scalars: settlement floor, affiliate cap, reserve floor, rounding tolerance.",
      "The asset, its decimals, the proof bands, the issuer public key, and the issue timestamp.",
      "The merchant alias, the programme label, and any memo.",
    ],
    limitations: REVENUE_ROUTING_LIMITATIONS,
    zeroKnowledgeElement:
      "Pedersen commitments over the STARK curve with Chaum-Pedersen OR proofs per bit, made non-interactive by Fiat-Shamir. Conservation and the exact-floor bounds are homomorphic point identities, so no hidden figure is ever transmitted.",
    statement:
      "For a published schedule (b0..b5) totalling 10000 basis points and public covenant scalars, there exist a hidden gross g, hidden payouts x0..x5, and a hidden remainder d such that x_k = floor(b_k·g / 10000) for every k, x0 + ... + x5 + d = g, g >= minGross, x4 <= maxAffiliatePayout, x5 >= minTaxReserve, and d <= maxDust.",
  };
}

/** What a verifier does and does not learn, stated plainly for the portal. */
export function getRevenueRoutingVisibilityModel(): RevenueRoutingVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The gross settlement amount.",
      "Every per-slot payout and the unallocated rounding remainder.",
      "The payer reference and every recipient reference.",
      "The settlement rows, their corridors, and their ageing.",
    ],
    disclosedToVerifier: [
      "The entitlement schedule and the per-slot jurisdiction tags.",
      "The four covenant scalars and the proof bands they are checked against.",
      "The issuer public key, the binding hash, and the issue timestamp.",
    ],
    applicationOnly: [
      "The corridor ledger, the distribution waterfall, and the concentration band.",
      "Any memo, alias, or programme label the merchant chooses to publish.",
    ],
    limitation:
      "The schedule is public by design, so a verifier who learns any single payout can derive the gross and every other payout from it. Nothing here routes, pays, or withholds value, observes an incoming payment, or calls the STRK20 pool contract.",
  };
}
// ---------------------------------------------------------------------------
// Transport envelopes (base64url JSON; no secret is ever included by accident)
// ---------------------------------------------------------------------------

export function serializeRevenueRoutingCertificate(certificate: RevenueRoutingCertificate): string {
  return toBase64Url(encodeJson(certificate));
}

export function parseRevenueRoutingCertificate(encoded: string): RevenueRoutingCertificate {
  const parsed = decodeJson(fromBase64Url(encoded)) as RevenueRoutingCertificate;
  if (!parsed || parsed.kind !== CERTIFICATE_KIND) throw new Error("This is not a revenue routing certificate.");
  return parsed;
}

/** SECRET. Sharing this opens every hidden figure at once; prefer a disclosure. */
export function serializeRevenueRoutingCertificateSecret(secret: RevenueRoutingCertificateSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function parseRevenueRoutingCertificateSecret(encoded: string): RevenueRoutingCertificateSecret {
  const parsed = decodeJson(fromBase64Url(encoded)) as RevenueRoutingCertificateSecret;
  if (!parsed || parsed.kind !== SECRET_KIND) throw new Error("This is not a revenue routing certificate secret.");
  return parsed;
}

export function serializeRevenueRoutingAmountDisclosure(disclosure: RevenueRoutingAmountDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseRevenueRoutingAmountDisclosure(encoded: string): RevenueRoutingAmountDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as RevenueRoutingAmountDisclosure;
  if (!parsed || parsed.kind !== AMOUNT_DISCLOSURE_KIND) {
    throw new Error("This is not a revenue routing amount disclosure.");
  }
  return parsed;
}

export function serializeRevenueRoutingRefDisclosure(disclosure: RevenueRoutingRefDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function parseRevenueRoutingRefDisclosure(encoded: string): RevenueRoutingRefDisclosure {
  const parsed = decodeJson(fromBase64Url(encoded)) as RevenueRoutingRefDisclosure;
  if (!parsed || parsed.kind !== REF_DISCLOSURE_KIND) {
    throw new Error("This is not a revenue routing reference disclosure.");
  }
  return parsed;
}
export function serializeRevenueRoutingCertificateBadge(badge: RevenueRoutingCertificateBadge): string {
  return toBase64Url(encodeJson(badge));
}

export function parseRevenueRoutingCertificateBadge(encoded: string): RevenueRoutingCertificateBadge {
  const parsed = decodeJson(fromBase64Url(encoded)) as RevenueRoutingCertificateBadge;
  if (!parsed || parsed.kind !== BADGE_KIND) throw new Error("This is not a revenue routing certificate badge.");
  return parsed;
}

/** SECRET. The envelope carries the issuer signing scalar; keep it local. */
export function serializeRevenueRoutingKeypair(keypair: RevenueRoutingKeypair): string {
  return toBase64Url(encodeJson(keypair));
}

export function parseRevenueRoutingKeypair(encoded: string): RevenueRoutingKeypair {
  const parsed = decodeJson(fromBase64Url(encoded)) as RevenueRoutingKeypair;
  if (!parsed || parsed.kind !== KEYPAIR_KIND) throw new Error("This is not a revenue routing keypair.");
  return parsed;
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let [old, current] = [mod(value, modulus), modulus];
  let [oldCoefficient, coefficient] = [1n, 0n];
  while (current !== 0n) {
    const quotient = old / current;
    [old, current] = [current, old - quotient * current];
    [oldCoefficient, coefficient] = [coefficient, oldCoefficient - quotient * coefficient];
  }
  if (old !== 1n) throw new Error("The value is not invertible modulo the curve order.");
  return mod(oldCoefficient, modulus);
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function hashElements(elements: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

/** Browser-safe: no Buffer, because this module also runs inside the portal. */
function randomScalar(): bigint {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let value = 0n;
  for (let index = 0; index < bytes.length; index += 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return mod(value, CURVE_ORDER);
}

function nonZeroScalar(value: bigint): bigint {
  const scalar = mod(value, CURVE_ORDER);
  return scalar === 0n ? 1n : scalar;
}

function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`The ${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`The ${label} is required.`);
  if (trimmed.length > maxLength) throw new Error(`The ${label} must be at most ${maxLength} characters.`);
  return trimmed;
}

function requireInt(value: unknown, label: string, min: number, max: number): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed)) throw new Error(`The ${label} must be a whole number.`);
  if (parsed < min || parsed > max) throw new Error(`The ${label} must be between ${min} and ${max}.`);
  return parsed;
}

function requireBaseUnits(value: unknown, label: string): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(`The ${label} cannot be negative.`);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) throw new Error(`The ${label} must be a whole number of base units.`);
    return BigInt(value);
  }
  if (typeof value !== "string" || !/^\d+$/.test(value.trim())) {
    throw new Error(`The ${label} must be a whole number of base units.`);
  }
  return BigInt(value.trim());
}

/** Bounded by FIELD_PRIME: every published felt must be canonical. */
function requireFelt(value: unknown): bigint {
  if (typeof value !== "string" && typeof value !== "bigint") throw new Error("A field element is missing.");
  const parsed = typeof value === "bigint" ? value : BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("A field element is outside the Stark field.");
  return parsed;
}
/** Bounded by CURVE_ORDER: a felt-only check would NOT bound a scalar canonically. */
function requireScalar(value: unknown, allowZero: boolean): bigint {
  if (typeof value !== "string" && typeof value !== "bigint") throw new Error("A scalar is missing.");
  const parsed = typeof value === "bigint" ? value : BigInt(value);
  if (parsed < 0n || parsed >= CURVE_ORDER) throw new Error("A scalar is outside the Stark curve order.");
  if (!allowZero && parsed === 0n) throw new Error("A scalar must be non-zero.");
  return parsed;
}

function requireIsoTimestamp(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new Error("An ISO-8601 timestamp is required.");
  const parsed = new Date(value.trim());
  if (Number.isNaN(parsed.getTime())) throw new Error("An ISO-8601 timestamp is required.");
  return parsed.toISOString();
}

let idCounter = 0;

function defaultId(kind: string): string {
  idCounter += 1;
  const random = Math.floor(Math.random() * 0xffffff).toString(36);
  return `rrt_${kind}_${Date.now().toString(36)}_${idCounter}_${random}`;
}

function encodeJson(value: unknown): string {
  return JSON.stringify(value);
}

function decodeJson(text: string): unknown {
  return JSON.parse(text);
}
function bytesToBinary(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let binary = "";
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return binary;
}

function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  return btoa(bytesToBinary(bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(encoded: unknown): string {
  if (typeof encoded !== "string") throw new Error("The envelope is missing.");
  const trimmed = encoded.trim();
  if (!trimmed) throw new Error("The envelope is missing.");
  if (trimmed.length > MAX_ENCODED_LENGTH) throw new Error("The envelope is too large to decode.");
  if (!/^[A-Za-z0-9_-]+$/.test(trimmed)) throw new Error("The envelope is not valid base64url text.");
  const base64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return new TextDecoder().decode(bytes);
}
