/**
 * Escrow dispute-resolution and outcome-attestation engine for CipherBill.
 *
 * WHAT THIS IS
 * - An exact-integer arbitration engine: two parties open a dispute over an escrowed invoice
 *   (a principal held in a shielded balance) with optional vendor collateral, and an arbiter
 *   resolves it into an allocation — a buyer refund, a vendor release, an optional arbiter fee,
 *   and an optional penalty carved out of the collateral — solved in bigint arithmetic that
 *   conserves every base unit (the escrow and the collateral are fully accounted for).
 * - A salted Poseidon commitment scheme for selective evidence disclosure: a party commits to a
 *   bundle of evidence item hashes, publishes a digest that carries no item content, and later
 *   discloses the bundle to a chosen arbiter who verifies it against the published commitment.
 * - A builder for the settlement legs: private in-pool STRK20 `transfer` actions, batched by
 *   recipient, that move the agreed amounts from the fund-holder's shielded balance to the buyer,
 *   the vendor, and the arbiter.
 * - A disclosable outcome attestation: a digest binding a case to its resolution and the arbiter's
 *   fault finding, which a vindicated party can share and later prove against the full resolution.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not zero-knowledge, and it proves nothing. CipherBill generates no proof of any kind: the
 *   wallet proves the settlement transfer and the pool verifies it onchain, and
 *   `wallet_strk20InvokeTransaction` returns only `{ transaction_hash }`. The commitments below
 *   are salted Poseidon hashes. They bind and hide terms; they attest nothing about whether an
 *   invoice, a delivery, or a piece of evidence is real or truthful.
 * - Not escrow and not slashing. Nothing holds the disputed funds or the collateral, and nothing
 *   is seized. The "escrow" and "collateral" sit in one party's ordinary shielded balance, and the
 *   resolution is a set of transfers that the fund-holder must voluntarily sign. A refusal to sign
 *   is a commercial or legal dispute, not something this application or the pool can enforce.
 * - Not a decentralized marketplace, court, or arbitration contract. Resolution is a local
 *   computation in one browser. There is no on-chain case registry, no verdict contract, and no
 *   atomic swap. The STRK20 Wallet API is three methods over four Starknet-only action types.
 * - Not a reputation system. The outcome attestation is a hash a party may choose to disclose. It
 *   is not on-chain, not portable without the holder's cooperation, not trustless, and not a score.
 *   The arbiter is a trusted third party whose honesty this engine cannot check.
 * - Not anonymous end to end. In-pool transfers hide sender, recipient, token, and amount, but
 *   registration, timing, and any withdrawal stay public, and a distinctive settlement amount can
 *   be correlated. Claim text, evidence content, and amounts live only in the parties' browsers.
 * - Not a fairness, evidence, or creditworthiness oracle. Fault findings, splits, and fees are
 *   caller-supplied and committed as given; the engine checks arithmetic and conservation, never
 *   whether a verdict is just. `STRK20_POOL_ADDRESS` is recorded as provenance for the settlement
 *   legs, not as a contract that sees, stores, or validates a dispute.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const DISPUTE_ENGINE_VERSION = 1 as const;
export const DISPUTE_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const FEE_BPS_DENOMINATOR = 10_000n;
export const BPS_DENOMINATOR = 10_000;
export const DAY_MS = 86_400_000;
export const MAX_ASSET_DECIMALS = 18;
export const MAX_ARBITER_FEE_BPS = 2_000;
export const MAX_PENALTY_BPS = 10_000;
export const MAX_RESPONSE_WINDOW_MS = 90 * DAY_MS;
export const MAX_EVIDENCE_ITEMS = 32;
export const DISPUTE_SALT_BYTES = 31;

const CASE_KIND = "cipherbill.dispute-case" as const;
const CASE_DIGEST_KIND = "cipherbill.dispute-case-digest" as const;
const EVIDENCE_KIND = "cipherbill.dispute-evidence" as const;
const EVIDENCE_DIGEST_KIND = "cipherbill.dispute-evidence-digest" as const;
const RESOLUTION_KIND = "cipherbill.dispute-resolution" as const;
const OUTCOME_KIND = "cipherbill.dispute-outcome" as const;

const CASE_DOMAIN = hash.starknetKeccak("CipherBill dispute case v1");
const EVIDENCE_DOMAIN = hash.starknetKeccak("CipherBill dispute evidence v1");
const EVIDENCE_ITEMS_DOMAIN = hash.starknetKeccak("CipherBill dispute evidence items v1");
const RESOLUTION_DOMAIN = hash.starknetKeccak("CipherBill dispute resolution v1");
const OUTCOME_DOMAIN = hash.starknetKeccak("CipherBill dispute outcome v1");
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 200_000;

const DISPUTE_NOTICE = "Client-side escrow dispute-resolution plan. The refund, release, penalty, and fee are private in-pool STRK20 transfers signed by the party that holds the shielded funds; everything else here is computation held in one browser. No proof, escrow contract, slashing, or on-chain court is involved, and nothing forces the fund-holder to sign or the arbiter to judge honestly.";

const DISPUTE_LIMITATIONS = [
  "No case, verdict, or evidence is stored, judged, or enforced on-chain. Resolution is a local computation, and only the settlement transfers touch the STRK20 pool.",
  "Commitments are salted Poseidon hashes. They are not zero-knowledge proofs, no contract verifies them, and they attest nothing about whether the invoice, delivery, or evidence is real.",
  "Nothing is escrowed or slashed. The disputed funds and collateral sit in the fund-holder's ordinary shielded balance, and the resolution transfers only execute if that party signs them.",
  "The arbiter is a trusted third party. This engine cannot check that a fault finding or an allocation is fair, and the parties must agree out of band to be bound by it.",
  "Evidence items are hashed, not encrypted. A low-entropy item can be guessed from its published hash, so commit hashes of documents or high-entropy references, not short guessable strings.",
  "In-pool transfers hide sender, recipient, token, and amount, but a distinctive settlement amount close in time to the dispute can correlate the parties. Vary timing and avoid round figures.",
] as const;

export type DisputeFault = "buyer_at_fault" | "vendor_at_fault" | "shared" | "no_fault";
export type EvidenceParty = "buyer" | "vendor";

/** The settlement token. Every leg is an in-pool transfer of it, so it must be a pool token. */
export interface DisputeAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface CreateDisputeCaseInput {
  invoiceId: string;
  asset: { symbol: string; tokenAddress: string; decimals: number };
  /** Disputed principal held in the fund-holder's shielded balance. Must be positive. */
  escrowValue: string;
  /** Optional vendor collateral, also shielded. Defaults to "0" when omitted or blank. */
  collateralValue?: string;
  buyerRecipient: string;
  vendorRecipient: string;
  arbiterRecipient?: string;
  arbiterLabel?: string;
  claimSummary: string;
  respondBy: string;
  memo?: string;
}

export interface DisputeCase {
  kind: typeof CASE_KIND;
  version: typeof DISPUTE_ENGINE_VERSION;
  caseId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  asset: DisputeAsset;
  escrowBaseUnits: string;
  escrowDisplay: string;
  collateralBaseUnits: string;
  collateralDisplay: string;
  buyerRecipient: string;
  vendorRecipient: string;
  /** Empty string when no fee-bearing arbiter was named at case creation. */
  arbiterRecipient: string;
  arbiterLabel: string;
  /** Trade secret. Bound by the commitment, published only as a keccak hash in the digest. */
  claimSummary: string;
  memo: string;
  respondBy: string;
  createdAt: string;
  /** Secret case-level blinding factor. Never publish a case; publish its digest. */
  caseSalt: string;
  caseCommitment: string;
  notice: typeof DISPUTE_NOTICE;
  limitations: string[];
}

/** Case fields safe to publish: no amounts, addresses, arbiter, or claim text. */
export interface DisputeCaseDigest {
  kind: typeof CASE_DIGEST_KIND;
  version: typeof DISPUTE_ENGINE_VERSION;
  caseId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  assetSymbol: string;
  assetDecimals: number;
  hasCollateral: boolean;
  respondBy: string;
  createdAt: string;
  claimSummaryHash: string;
  caseCommitment: string;
  notice: typeof DISPUTE_NOTICE;
  limitations: string[];
}

/** One case disclosed against its published digest, for a chosen arbiter or counterparty. */
export interface DisputeCaseOpening {
  caseId: string;
  caseCommitment: string;
  disputeCase: DisputeCase;
}

export interface CreateEvidenceInput {
  caseCommitment: string;
  submittedBy: EvidenceParty;
  /** Evidence references or document hashes. Hashed, never stored in plaintext in the digest. */
  items: string[];
  note?: string;
}

export interface EvidenceBundle {
  kind: typeof EVIDENCE_KIND;
  version: typeof DISPUTE_ENGINE_VERSION;
  evidenceId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  caseCommitment: string;
  submittedBy: EvidenceParty;
  /** Secret. The full evidence references. Disclose to the arbiter, never publish. */
  items: string[];
  itemHashes: string[];
  itemsRoot: string;
  note: string;
  createdAt: string;
  evidenceSalt: string;
  evidenceCommitment: string;
  notice: typeof DISPUTE_NOTICE;
  limitations: string[];
}

/** Evidence fields safe to publish: item hashes and a root, but no item content. */
export interface EvidenceDigest {
  kind: typeof EVIDENCE_DIGEST_KIND;
  version: typeof DISPUTE_ENGINE_VERSION;
  evidenceId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  caseCommitment: string;
  submittedBy: EvidenceParty;
  itemCount: number;
  itemHashes: string[];
  itemsRoot: string;
  createdAt: string;
  evidenceCommitment: string;
  notice: typeof DISPUTE_NOTICE;
  limitations: string[];
}

/** One evidence bundle disclosed against its digest, for the arbiter to verify. */
export interface EvidenceOpening {
  evidenceId: string;
  evidenceCommitment: string;
  evidence: EvidenceBundle;
}

export interface CreateDisputeResolutionInput {
  faultAssessment: DisputeFault;
  /** Share of the escrow refunded to the buyer, in basis points. */
  buyerRefundBps: number;
  /** Optional arbiter fee, a share of the escrow, in basis points. Defaults to 0. */
  arbiterFeeBps?: number;
  /** Optional penalty carved from the vendor's collateral to the buyer, in basis points. */
  penaltyBps?: number;
  /** Optional evidence commitments the arbiter reviewed, bound into the resolution. */
  buyerEvidenceCommitment?: string;
  vendorEvidenceCommitment?: string;
  resolvedBy: string;
  note?: string;
}

export interface DisputeResolution {
  kind: typeof RESOLUTION_KIND;
  version: typeof DISPUTE_ENGINE_VERSION;
  resolutionId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  asset: DisputeAsset;
  escrowBaseUnits: string;
  collateralBaseUnits: string;
  faultAssessment: DisputeFault;
  buyerRefundBps: number;
  arbiterFeeBps: number;
  penaltyBps: number;
  buyerRefundBaseUnits: string;
  buyerRefundDisplay: string;
  vendorReleaseBaseUnits: string;
  vendorReleaseDisplay: string;
  arbiterFeeBaseUnits: string;
  arbiterFeeDisplay: string;
  penaltyBaseUnits: string;
  penaltyDisplay: string;
  collateralReturnBaseUnits: string;
  collateralReturnDisplay: string;
  buyerTotalBaseUnits: string;
  buyerTotalDisplay: string;
  vendorTotalBaseUnits: string;
  vendorTotalDisplay: string;
  buyerRecipient: string;
  vendorRecipient: string;
  arbiterRecipient: string;
  buyerEvidenceCommitment: string;
  vendorEvidenceCommitment: string;
  resolvedBy: string;
  resolvedAt: string;
  caseCommitment: string;
  resolutionSalt: string;
  resolutionCommitment: string;
  notice: typeof DISPUTE_NOTICE;
  limitations: string[];
}

/** A disclosable record of an outcome. Not a reputation score; a hash a party may choose to share. */
export interface DisputeOutcomeAttestation {
  kind: typeof OUTCOME_KIND;
  version: typeof DISPUTE_ENGINE_VERSION;
  resolutionId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  faultAssessment: DisputeFault;
  resolvedBy: string;
  resolvedAt: string;
  caseCommitment: string;
  resolutionCommitment: string;
  outcomeCommitment: string;
  notice: typeof DISPUTE_NOTICE;
  limitations: string[];
}

export interface DisputeVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface DisputeTrustSummary {
  fundHolder: string;
  isEscrowed: boolean;
  isProven: boolean;
  isOnChainReputation: boolean;
  faultAssessment: DisputeFault;
  trustedParties: string[];
  statement: string;
}

export interface DisputeEntropy {
  createId?: (kind: "case" | "evidence" | "resolution") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

/**
 * Builds a dispute case: the private object holding the disputed amount, the collateral, the
 * parties, and the claim, bound by a salted Poseidon commitment. Share the digest from
 * `buildDisputeCaseDigest`, never this object.
 */
export function createDisputeCase(
  input: CreateDisputeCaseInput,
  now = new Date(),
  entropy: DisputeEntropy = {},
): DisputeCase {
  const createdAt = requireIsoTimestamp(now.toISOString(), "Case creation time");
  const respondBy = requireIsoTimestamp(input.respondBy, "Response deadline");
  const createdMs = Date.parse(createdAt);
  const respondMs = Date.parse(respondBy);
  if (respondMs <= createdMs) throw new Error("The response deadline must be in the future.");
  if (respondMs - createdMs > MAX_RESPONSE_WINDOW_MS) throw new Error(`The response deadline must be within ${MAX_RESPONSE_WINDOW_MS / DAY_MS} days.`);

  const asset = normalizeAsset(input.asset, "Dispute asset");
  const escrow = parseDecimalToBaseUnits(input.escrowValue, asset.decimals, "Escrow value");
  requireU128(escrow, "Escrow value");
  const collateral = parseOptionalBaseUnits(input.collateralValue, asset.decimals, "Collateral value");
  requireU128(collateral, "Collateral value");
  const buyerRecipient = normalizeStarknetAddress(requireText(input.buyerRecipient, "Buyer recipient", 66));
  const vendorRecipient = normalizeStarknetAddress(requireText(input.vendorRecipient, "Vendor recipient", 66));
  if (buyerRecipient === vendorRecipient) throw new Error("The buyer and the vendor must be different recipients.");
  const arbiterRecipient = input.arbiterRecipient ? normalizeStarknetAddress(requireText(input.arbiterRecipient, "Arbiter recipient", 66)) : "";
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<DisputeCase, "caseCommitment"> = {
    kind: CASE_KIND,
    version: DISPUTE_ENGINE_VERSION,
    caseId: makeId(entropy.createId?.("case"), "case"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    asset,
    escrowBaseUnits: escrow.toString(),
    escrowDisplay: formatBaseUnits(escrow, asset.decimals),
    collateralBaseUnits: collateral.toString(),
    collateralDisplay: formatBaseUnits(collateral, asset.decimals),
    buyerRecipient,
    vendorRecipient,
    arbiterRecipient,
    arbiterLabel: requireOptionalText(input.arbiterLabel ?? "", "Arbiter label", 96),
    claimSummary: requireText(input.claimSummary, "Claim summary", 240),
    memo: requireOptionalText(input.memo ?? "", "Case memo", 160),
    respondBy,
    createdAt,
    caseSalt: toHex(randomFelt(random)),
    notice: DISPUTE_NOTICE,
    limitations: [...DISPUTE_LIMITATIONS],
  };
  const disputeCase: DisputeCase = { ...draft, caseCommitment: toHex(computeCaseCommitment(draft)) };
  assertDisputeCase(disputeCase);
  return disputeCase;
}

export function verifyDisputeCase(disputeCase: DisputeCase): boolean {
  try {
    assertDisputeCase(disputeCase);
    return true;
  } catch {
    return false;
  }
}

/** The only case object safe to publish. Carries the deadline and a claim hash, no amounts. */
export function buildDisputeCaseDigest(disputeCase: DisputeCase): DisputeCaseDigest {
  assertDisputeCase(disputeCase);
  return {
    kind: CASE_DIGEST_KIND,
    version: DISPUTE_ENGINE_VERSION,
    caseId: disputeCase.caseId,
    network: disputeCase.network,
    poolAddress: disputeCase.poolAddress,
    invoiceId: disputeCase.invoiceId,
    assetSymbol: disputeCase.asset.symbol,
    assetDecimals: disputeCase.asset.decimals,
    hasCollateral: disputeCase.collateralBaseUnits !== "0",
    respondBy: disputeCase.respondBy,
    createdAt: disputeCase.createdAt,
    claimSummaryHash: toHex(BigInt(hash.starknetKeccak(disputeCase.claimSummary))),
    caseCommitment: disputeCase.caseCommitment,
    notice: DISPUTE_NOTICE,
    limitations: [...DISPUTE_LIMITATIONS],
  };
}

/** Discloses the full case so a chosen arbiter can check it against a published digest. */
export function openDisputeCase(disputeCase: DisputeCase): DisputeCaseOpening {
  assertDisputeCase(disputeCase);
  return { caseId: disputeCase.caseId, caseCommitment: disputeCase.caseCommitment, disputeCase };
}

export function verifyDisputeCaseDisclosure(digest: DisputeCaseDigest, opening: DisputeCaseOpening): boolean {
  try {
    assertDisputeCaseDigest(digest);
    assertDisputeCase(opening.disputeCase);
    if (digest.caseId !== opening.caseId || digest.caseCommitment !== opening.caseCommitment) return false;
    if (digest.caseCommitment !== opening.disputeCase.caseCommitment) return false;
    return digest.invoiceId === opening.disputeCase.invoiceId
      && digest.assetSymbol === opening.disputeCase.asset.symbol
      && digest.assetDecimals === opening.disputeCase.asset.decimals
      && digest.hasCollateral === (opening.disputeCase.collateralBaseUnits !== "0")
      && digest.respondBy === opening.disputeCase.respondBy
      && digest.claimSummaryHash === toHex(BigInt(hash.starknetKeccak(opening.disputeCase.claimSummary)));
  } catch {
    return false;
  }
}

/**
 * Commits a party's evidence bundle against a case commitment. Each item is hashed and folded
 * into a root, so the digest can prove which items were included without revealing their content.
 * Share the digest from `buildEvidenceDigest`; disclose the full bundle only to the arbiter.
 */
export function createEvidence(
  input: CreateEvidenceInput,
  now = new Date(),
  entropy: DisputeEntropy = {},
): EvidenceBundle {
  const createdAt = requireIsoTimestamp(now.toISOString(), "Evidence creation time");
  if (input.submittedBy !== "buyer" && input.submittedBy !== "vendor") throw new Error("Evidence must be submitted by the buyer or the vendor.");
  if (!Array.isArray(input.items) || input.items.length < 1 || input.items.length > MAX_EVIDENCE_ITEMS) {
    throw new Error(`Evidence must carry between 1 and ${MAX_EVIDENCE_ITEMS} items.`);
  }
  const items = input.items.map((item, index) => requireText(item, `Evidence item ${index + 1}`, 200));
  const itemHashes = items.map((item) => toHex(BigInt(hash.starknetKeccak(item))));
  const itemsRoot = toHex(computeItemsRoot(itemHashes));
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<EvidenceBundle, "evidenceCommitment"> = {
    kind: EVIDENCE_KIND,
    version: DISPUTE_ENGINE_VERSION,
    evidenceId: makeId(entropy.createId?.("evidence"), "evid"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    caseCommitment: toHex(requireFelt(input.caseCommitment, "Case commitment")),
    submittedBy: input.submittedBy,
    items,
    itemHashes,
    itemsRoot,
    note: requireOptionalText(input.note ?? "", "Evidence note", 160),
    createdAt,
    evidenceSalt: toHex(randomFelt(random)),
    notice: DISPUTE_NOTICE,
    limitations: [...DISPUTE_LIMITATIONS],
  };
  const evidence: EvidenceBundle = { ...draft, evidenceCommitment: toHex(computeEvidenceCommitment(draft)) };
  assertEvidenceBundle(evidence);
  return evidence;
}

export function verifyEvidence(evidence: EvidenceBundle): boolean {
  try {
    assertEvidenceBundle(evidence);
    return true;
  } catch {
    return false;
  }
}

/** The only evidence object safe to publish. Carries item hashes and a root, no item content. */
export function buildEvidenceDigest(evidence: EvidenceBundle): EvidenceDigest {
  assertEvidenceBundle(evidence);
  return {
    kind: EVIDENCE_DIGEST_KIND,
    version: DISPUTE_ENGINE_VERSION,
    evidenceId: evidence.evidenceId,
    network: evidence.network,
    poolAddress: evidence.poolAddress,
    caseCommitment: evidence.caseCommitment,
    submittedBy: evidence.submittedBy,
    itemCount: evidence.items.length,
    itemHashes: [...evidence.itemHashes],
    itemsRoot: evidence.itemsRoot,
    createdAt: evidence.createdAt,
    evidenceCommitment: evidence.evidenceCommitment,
    notice: DISPUTE_NOTICE,
    limitations: [...DISPUTE_LIMITATIONS],
  };
}

export function openEvidence(evidence: EvidenceBundle): EvidenceOpening {
  assertEvidenceBundle(evidence);
  return { evidenceId: evidence.evidenceId, evidenceCommitment: evidence.evidenceCommitment, evidence };
}

export function verifyEvidenceDisclosure(digest: EvidenceDigest, opening: EvidenceOpening): boolean {
  try {
    assertEvidenceDigest(digest);
    assertEvidenceBundle(opening.evidence);
    if (digest.evidenceId !== opening.evidenceId || digest.evidenceCommitment !== opening.evidenceCommitment) return false;
    if (digest.evidenceCommitment !== opening.evidence.evidenceCommitment) return false;
    const recomputed = opening.evidence.items.map((item) => toHex(BigInt(hash.starknetKeccak(item))));
    if (recomputed.length !== digest.itemHashes.length || recomputed.some((value, index) => value !== digest.itemHashes[index])) return false;
    return digest.caseCommitment === opening.evidence.caseCommitment
      && digest.submittedBy === opening.evidence.submittedBy
      && digest.itemCount === opening.evidence.items.length
      && digest.itemsRoot === opening.evidence.itemsRoot;
  } catch {
    return false;
  }
}

/**
 * Resolves a case into an allocation and solves it in exact integers. The buyer refund and the
 * arbiter fee are floored shares of the escrow; the vendor receives the exact remainder, so no
 * base unit of the escrow is lost. The penalty is a floored share of the collateral to the buyer;
 * the vendor keeps the exact remainder. The connected wallet that signs the transfers must hold
 * the escrow and the collateral in its shielded balance.
 */
export function createDisputeResolution(
  disputeCase: DisputeCase,
  input: CreateDisputeResolutionInput,
  now = new Date(),
  entropy: DisputeEntropy = {},
): DisputeResolution {
  assertDisputeCase(disputeCase);
  const resolvedAt = requireIsoTimestamp(now.toISOString(), "Resolution time");
  const fault = requireFault(input.faultAssessment);
  const escrow = BigInt(disputeCase.escrowBaseUnits);
  const collateral = BigInt(disputeCase.collateralBaseUnits);
  const allocation = solveDisputeAllocation(escrow, collateral, {
    faultAssessment: fault,
    buyerRefundBps: input.buyerRefundBps,
    arbiterFeeBps: input.arbiterFeeBps ?? 0,
    penaltyBps: input.penaltyBps ?? 0,
  });
  if (allocation.arbiterFee > 0n && !disputeCase.arbiterRecipient) throw new Error("An arbiter fee needs an arbiter recipient on the case.");
  if (allocation.arbiterFee > 0n && (disputeCase.arbiterRecipient === disputeCase.buyerRecipient || disputeCase.arbiterRecipient === disputeCase.vendorRecipient)) {
    throw new Error("A fee-bearing arbiter must be a different recipient from the buyer and the vendor.");
  }
  const decimals = disputeCase.asset.decimals;
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<DisputeResolution, "resolutionCommitment"> = {
    kind: RESOLUTION_KIND,
    version: DISPUTE_ENGINE_VERSION,
    resolutionId: makeId(entropy.createId?.("resolution"), "res"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: disputeCase.invoiceId,
    asset: disputeCase.asset,
    escrowBaseUnits: escrow.toString(),
    collateralBaseUnits: collateral.toString(),
    faultAssessment: fault,
    buyerRefundBps: allocation.buyerRefundBps,
    arbiterFeeBps: allocation.arbiterFeeBps,
    penaltyBps: allocation.penaltyBps,
    buyerRefundBaseUnits: allocation.buyerRefund.toString(),
    buyerRefundDisplay: formatBaseUnits(allocation.buyerRefund, decimals),
    vendorReleaseBaseUnits: allocation.vendorRelease.toString(),
    vendorReleaseDisplay: formatBaseUnits(allocation.vendorRelease, decimals),
    arbiterFeeBaseUnits: allocation.arbiterFee.toString(),
    arbiterFeeDisplay: formatBaseUnits(allocation.arbiterFee, decimals),
    penaltyBaseUnits: allocation.penalty.toString(),
    penaltyDisplay: formatBaseUnits(allocation.penalty, decimals),
    collateralReturnBaseUnits: allocation.collateralReturn.toString(),
    collateralReturnDisplay: formatBaseUnits(allocation.collateralReturn, decimals),
    buyerTotalBaseUnits: allocation.buyerTotal.toString(),
    buyerTotalDisplay: formatBaseUnits(allocation.buyerTotal, decimals),
    vendorTotalBaseUnits: allocation.vendorTotal.toString(),
    vendorTotalDisplay: formatBaseUnits(allocation.vendorTotal, decimals),
    buyerRecipient: disputeCase.buyerRecipient,
    vendorRecipient: disputeCase.vendorRecipient,
    arbiterRecipient: disputeCase.arbiterRecipient,
    buyerEvidenceCommitment: input.buyerEvidenceCommitment ? toHex(requireFelt(input.buyerEvidenceCommitment, "Buyer evidence commitment")) : "",
    vendorEvidenceCommitment: input.vendorEvidenceCommitment ? toHex(requireFelt(input.vendorEvidenceCommitment, "Vendor evidence commitment")) : "",
    resolvedBy: requireText(input.resolvedBy, "Resolved by", 96),
    resolvedAt,
    caseCommitment: disputeCase.caseCommitment,
    resolutionSalt: toHex(randomFelt(random)),
    notice: DISPUTE_NOTICE,
    limitations: [...DISPUTE_LIMITATIONS],
  };
  const resolution: DisputeResolution = { ...draft, resolutionCommitment: toHex(computeResolutionCommitment(draft)) };
  assertDisputeResolution(resolution);
  return resolution;
}

export function verifyDisputeResolution(resolution: DisputeResolution): boolean {
  try {
    assertDisputeResolution(resolution);
    return true;
  } catch {
    return false;
  }
}

interface DisputeAllocation {
  buyerRefundBps: number;
  arbiterFeeBps: number;
  penaltyBps: number;
  buyerRefund: bigint;
  vendorRelease: bigint;
  arbiterFee: bigint;
  penalty: bigint;
  collateralReturn: bigint;
  buyerTotal: bigint;
  vendorTotal: bigint;
}

/**
 * Solves the split in exact integers. The buyer refund and the arbiter fee are floored shares of
 * the escrow; the vendor takes the exact remainder, so the escrow is conserved to the base unit.
 * The penalty is a floored share of the collateral to the buyer; the vendor keeps the remainder.
 */
function solveDisputeAllocation(
  escrow: bigint,
  collateral: bigint,
  input: { faultAssessment: DisputeFault; buyerRefundBps: number; arbiterFeeBps: number; penaltyBps: number },
): DisputeAllocation {
  requireU128(escrow, "Escrow value");
  requireU128(collateral, "Collateral value");
  if (escrow <= 0n) throw new Error("The escrow value must be positive.");
  const buyerRefundBps = requireBps(input.buyerRefundBps, "Buyer refund", 0, BPS_DENOMINATOR);
  const arbiterFeeBps = requireBps(input.arbiterFeeBps, "Arbiter fee", 0, MAX_ARBITER_FEE_BPS);
  const penaltyBps = requireBps(input.penaltyBps, "Penalty", 0, MAX_PENALTY_BPS);
  if (buyerRefundBps + arbiterFeeBps > BPS_DENOMINATOR) throw new Error("The buyer refund and the arbiter fee cannot exceed the escrow.");
  if (penaltyBps > 0 && input.faultAssessment !== "vendor_at_fault" && input.faultAssessment !== "shared") throw new Error("A collateral penalty needs a vendor-at-fault or shared finding.");
  if (penaltyBps > 0 && collateral <= 0n) throw new Error("A collateral penalty needs posted collateral.");
  const arbiterFee = (escrow * BigInt(arbiterFeeBps)) / FEE_BPS_DENOMINATOR;
  const buyerRefund = (escrow * BigInt(buyerRefundBps)) / FEE_BPS_DENOMINATOR;
  const vendorRelease = escrow - arbiterFee - buyerRefund;
  requireU128(vendorRelease, "Vendor release");
  const penalty = (collateral * BigInt(penaltyBps)) / FEE_BPS_DENOMINATOR;
  const collateralReturn = collateral - penalty;
  const buyerTotal = buyerRefund + penalty;
  const vendorTotal = vendorRelease + collateralReturn;
  requireU128(buyerTotal, "Buyer settlement");
  requireU128(vendorTotal, "Vendor settlement");
  if (buyerTotal + vendorTotal + arbiterFee !== escrow + collateral) throw new Error("The dispute allocation does not conserve funds.");
  return { buyerRefundBps, arbiterFeeBps, penaltyBps, buyerRefund, vendorRelease, arbiterFee, penalty, collateralReturn, buyerTotal, vendorTotal };
}

/**
 * Builds the settlement legs: private in-pool `transfer` actions batched by recipient, moving the
 * agreed amounts from the fund-holder's shielded balance to the buyer, the vendor, and the
 * arbiter. Zero legs are dropped. The connected wallet here is the fund-holder's. No relayer-fee
 * action is added: `wallet_strk20InvokeTransaction` appends its own, and a second would double-charge.
 */
export function buildResolutionActions(resolution: DisputeResolution): STRK20_ACTION[] {
  assertDisputeResolution(resolution);
  const token = resolution.asset.tokenAddress;
  const legs: Array<{ recipient: string; amount: bigint }> = [
    { recipient: resolution.buyerRecipient, amount: BigInt(resolution.buyerTotalBaseUnits) },
    { recipient: resolution.vendorRecipient, amount: BigInt(resolution.vendorTotalBaseUnits) },
  ];
  if (resolution.arbiterRecipient) legs.push({ recipient: resolution.arbiterRecipient, amount: BigInt(resolution.arbiterFeeBaseUnits) });
  const order: string[] = [];
  const merged = new Map<string, bigint>();
  for (const leg of legs) {
    if (leg.amount <= 0n) continue;
    if (!merged.has(leg.recipient)) order.push(leg.recipient);
    merged.set(leg.recipient, (merged.get(leg.recipient) ?? 0n) + leg.amount);
  }
  if (order.length === 0) throw new Error("The resolution has nothing to settle.");
  return order.map((recipient) => {
    const amount = requireU128(merged.get(recipient) as bigint, "Settlement leg");
    return { type: "transfer", token, amount: amount.toString(), recipient };
  });
}

export function getDisputeVisibilityModel(resolution: DisputeResolution): DisputeVisibilityModel {
  assertDisputeResolution(resolution);
  return {
    applicationOnly: ["invoice ID", "escrow, collateral, refund, penalty, and fee amounts", "the claim summary and evidence item content", "case, evidence, and resolution salts", "the arbiter's fault finding rationale"],
    walletRequest: ["settlement token address", "exact per-recipient base-unit amounts", "in-pool buyer, vendor, and arbiter recipients"],
    hiddenInPool: ["in-pool sender and recipients of the settlement transfers", "token and amount of each transfer", "which encrypted notes were spent"],
    publicOrObservable: ["published nullifiers, unlinkable without a viewing key", "transaction timing and fees for the settlement"],
    limitation: "The settlement moves related amounts from one payer to the buyer, the vendor, and any arbiter close in time. Distinctive amounts settled together can correlate the parties. Vary timing and avoid round figures.",
  };
}

export function summarizeDisputeTrust(resolution: DisputeResolution): DisputeTrustSummary {
  assertDisputeResolution(resolution);
  const symbol = resolution.asset.symbol;
  return {
    fundHolder: "the party that holds the escrow and any collateral in its shielded balance",
    isEscrowed: false,
    isProven: false,
    isOnChainReputation: false,
    faultAssessment: resolution.faultAssessment,
    trustedParties: ["the arbiter to have judged the fault finding honestly", "the fund-holder to sign the settlement transfers"],
    statement: `The arbiter found "${resolution.faultAssessment.replaceAll("_", " ")}" and set the buyer to receive ${resolution.buyerTotalDisplay} ${symbol}, the vendor ${resolution.vendorTotalDisplay} ${symbol}, and any arbiter ${resolution.arbiterFeeDisplay} ${symbol}. Nothing is escrowed or slashed and no proof is generated: the split only takes effect if the fund-holder signs the transfers, and this engine cannot check that the fault finding is fair.`,
  };
}

/**
 * Builds a disclosable outcome attestation: a digest binding the case and the resolution to the
 * arbiter's fault finding. A vindicated party may share it, and a counterparty can later verify it
 * against the full resolution. It is not on-chain, not a portable score, and not a reputation system.
 */
export function buildDisputeOutcomeAttestation(resolution: DisputeResolution): DisputeOutcomeAttestation {
  assertDisputeResolution(resolution);
  const draft: Omit<DisputeOutcomeAttestation, "outcomeCommitment"> = {
    kind: OUTCOME_KIND,
    version: DISPUTE_ENGINE_VERSION,
    resolutionId: resolution.resolutionId,
    network: resolution.network,
    poolAddress: resolution.poolAddress,
    invoiceId: resolution.invoiceId,
    faultAssessment: resolution.faultAssessment,
    resolvedBy: resolution.resolvedBy,
    resolvedAt: resolution.resolvedAt,
    caseCommitment: resolution.caseCommitment,
    resolutionCommitment: resolution.resolutionCommitment,
    notice: DISPUTE_NOTICE,
    limitations: [...DISPUTE_LIMITATIONS],
  };
  return { ...draft, outcomeCommitment: toHex(computeOutcomeCommitment(draft)) };
}

export function verifyDisputeOutcome(attestation: DisputeOutcomeAttestation, resolution: DisputeResolution): boolean {
  try {
    assertDisputeOutcome(attestation);
    assertDisputeResolution(resolution);
    if (attestation.resolutionId !== resolution.resolutionId || attestation.resolutionCommitment !== resolution.resolutionCommitment) return false;
    if (attestation.caseCommitment !== resolution.caseCommitment) return false;
    return attestation.invoiceId === resolution.invoiceId
      && attestation.faultAssessment === resolution.faultAssessment
      && attestation.resolvedBy === resolution.resolvedBy
      && attestation.resolvedAt === resolution.resolvedAt;
  } catch {
    return false;
  }
}

export function serializeDisputeCase(disputeCase: DisputeCase): string {
  assertDisputeCase(disputeCase);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(disputeCase)));
}

export function parseDisputeCase(encoded: string): DisputeCase {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Dispute case");
  assertDisputeCase(parsed);
  return parsed;
}

export function serializeDisputeCaseDigest(digest: DisputeCaseDigest): string {
  assertDisputeCaseDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseDisputeCaseDigest(encoded: string): DisputeCaseDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Case digest");
  assertDisputeCaseDigest(parsed);
  return parsed;
}

export function serializeEvidenceBundle(evidence: EvidenceBundle): string {
  assertEvidenceBundle(evidence);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(evidence)));
}

export function parseEvidenceBundle(encoded: string): EvidenceBundle {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Evidence bundle");
  assertEvidenceBundle(parsed);
  return parsed;
}

export function serializeEvidenceDigest(digest: EvidenceDigest): string {
  assertEvidenceDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseEvidenceDigest(encoded: string): EvidenceDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Evidence digest");
  assertEvidenceDigest(parsed);
  return parsed;
}

export function serializeDisputeResolution(resolution: DisputeResolution): string {
  assertDisputeResolution(resolution);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(resolution)));
}

export function parseDisputeResolution(encoded: string): DisputeResolution {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Dispute resolution");
  assertDisputeResolution(parsed);
  return parsed;
}

export function serializeDisputeOutcome(attestation: DisputeOutcomeAttestation): string {
  assertDisputeOutcome(attestation);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(attestation)));
}

export function parseDisputeOutcome(encoded: string): DisputeOutcomeAttestation {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Dispute outcome");
  assertDisputeOutcome(parsed);
  return parsed;
}

export function formatDisputeBaseUnits(value: string | bigint, decimals: number): string {
  const amount = typeof value === "bigint" ? value : BigInt(value);
  return formatBaseUnits(amount, requireDecimals(decimals, "Asset decimals"));
}

function makeId(provided: string | undefined, prefix: string): string {
  const id = provided ?? `${prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!new RegExp(`^${prefix}_[A-Za-z0-9_-]{1,48}$`).test(id)) throw new Error(`A ${prefix} identifier is invalid.`);
  return id;
}

function secondsOf(iso: string): bigint {
  return BigInt(Math.floor(Date.parse(iso) / 1_000));
}

/** Draws a non-zero field element from the injected entropy source. */
function randomFelt(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const bytes = random(new Uint8Array(DISPUTE_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== DISPUTE_SALT_BYTES) throw new Error("The entropy source returned the wrong number of bytes.");
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n && value < FIELD_PRIME) return value;
  }
  throw new Error("Could not draw a usable salt.");
}

function hashElements(values: bigint[]): bigint {
  for (const value of values) {
    if (value < 0n || value >= FIELD_PRIME) throw new Error("A commitment input is outside the STARK field.");
  }
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function computeCaseCommitment(c: Omit<DisputeCase, "caseCommitment">): bigint {
  return hashElements([
    CASE_DOMAIN,
    BigInt(c.version),
    requireFelt(c.caseSalt, "Case salt"),
    BigInt(hash.starknetKeccak(c.caseId)),
    BigInt(hash.starknetKeccak(c.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(hash.starknetKeccak(c.asset.symbol)),
    BigInt(c.asset.tokenAddress),
    BigInt(c.asset.decimals),
    BigInt(c.escrowBaseUnits),
    BigInt(c.collateralBaseUnits),
    BigInt(c.buyerRecipient),
    BigInt(c.vendorRecipient),
    c.arbiterRecipient ? BigInt(c.arbiterRecipient) : 0n,
    BigInt(hash.starknetKeccak(c.arbiterLabel || "none")),
    BigInt(hash.starknetKeccak(c.claimSummary)),
    BigInt(hash.starknetKeccak(c.memo || "empty")),
    secondsOf(c.respondBy),
    secondsOf(c.createdAt),
  ]);
}

function computeItemsRoot(itemHashes: string[]): bigint {
  return hashElements([EVIDENCE_ITEMS_DOMAIN, BigInt(itemHashes.length), ...itemHashes.map((entry) => requireFelt(entry, "Evidence item hash"))]);
}

function computeEvidenceCommitment(e: Omit<EvidenceBundle, "evidenceCommitment">): bigint {
  return hashElements([
    EVIDENCE_DOMAIN,
    BigInt(e.version),
    requireFelt(e.evidenceSalt, "Evidence salt"),
    BigInt(hash.starknetKeccak(e.evidenceId)),
    requireFelt(e.caseCommitment, "Case commitment"),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(hash.starknetKeccak(e.submittedBy)),
    BigInt(e.itemHashes.length),
    requireFelt(e.itemsRoot, "Evidence items root"),
    BigInt(hash.starknetKeccak(e.note || "empty")),
    secondsOf(e.createdAt),
  ]);
}

function computeResolutionCommitment(r: Omit<DisputeResolution, "resolutionCommitment">): bigint {
  return hashElements([
    RESOLUTION_DOMAIN,
    BigInt(r.version),
    requireFelt(r.resolutionSalt, "Resolution salt"),
    BigInt(hash.starknetKeccak(r.resolutionId)),
    BigInt(hash.starknetKeccak(r.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    requireFelt(r.caseCommitment, "Case commitment"),
    BigInt(r.asset.tokenAddress),
    BigInt(r.asset.decimals),
    BigInt(r.escrowBaseUnits),
    BigInt(r.collateralBaseUnits),
    BigInt(hash.starknetKeccak(r.faultAssessment)),
    BigInt(r.buyerRefundBps),
    BigInt(r.arbiterFeeBps),
    BigInt(r.penaltyBps),
    BigInt(r.buyerRefundBaseUnits),
    BigInt(r.vendorReleaseBaseUnits),
    BigInt(r.arbiterFeeBaseUnits),
    BigInt(r.penaltyBaseUnits),
    BigInt(r.collateralReturnBaseUnits),
    BigInt(r.buyerRecipient),
    BigInt(r.vendorRecipient),
    r.arbiterRecipient ? BigInt(r.arbiterRecipient) : 0n,
    r.buyerEvidenceCommitment ? requireFelt(r.buyerEvidenceCommitment, "Buyer evidence commitment") : 0n,
    r.vendorEvidenceCommitment ? requireFelt(r.vendorEvidenceCommitment, "Vendor evidence commitment") : 0n,
    BigInt(hash.starknetKeccak(r.resolvedBy)),
    secondsOf(r.resolvedAt),
  ]);
}

function computeOutcomeCommitment(o: Omit<DisputeOutcomeAttestation, "outcomeCommitment">): bigint {
  return hashElements([
    OUTCOME_DOMAIN,
    BigInt(o.version),
    BigInt(hash.starknetKeccak(o.resolutionId)),
    BigInt(hash.starknetKeccak(o.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    requireFelt(o.caseCommitment, "Case commitment"),
    requireFelt(o.resolutionCommitment, "Resolution commitment"),
    BigInt(hash.starknetKeccak(o.faultAssessment)),
    BigInt(hash.starknetKeccak(o.resolvedBy)),
    secondsOf(o.resolvedAt),
  ]);
}

function normalizeAsset(asset: { symbol: string; tokenAddress: string; decimals: number } | undefined, label: string): DisputeAsset {
  if (!asset || !asset.tokenAddress) throw new Error(`${label} needs a Starknet token contract address.`);
  return {
    symbol: requireSymbol(asset.symbol, `${label} symbol`),
    tokenAddress: normalizeStarknetAddress(asset.tokenAddress),
    decimals: requireDecimals(asset.decimals, `${label} decimals`),
  };
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Dispute amounts cannot be negative.");
  if (decimals === 0) return value.toString();
  const divisor = 10n ** BigInt(decimals);
  const fraction = (value % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  const whole = (value / divisor).toString();
  return fraction ? `${whole}.${fraction}` : whole;
}

function parseDecimalToBaseUnits(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a positive decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  const units = BigInt(`${whole}${fraction.padEnd(decimals, "0")}`);
  if (units <= 0n) throw new Error(`${label} must be greater than zero.`);
  return units;
}

/** Like parseDecimalToBaseUnits but permits an absent or blank value, treated as zero. */
function parseOptionalBaseUnits(value: unknown, decimals: number, label: string): bigint {
  if (value === undefined || value === null || (typeof value === "string" && value.trim() === "")) return 0n;
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a non-negative decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  return BigInt(`${whole}${fraction.padEnd(decimals, "0")}`);
}

function requireBaseUnitString(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} is outside the u128 range the privacy pool accepts.`);
  return value;
}

function requireBps(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) throw new Error(`${label} must be an integer between ${min} and ${max} basis points.`);
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

function requireFault(value: unknown): DisputeFault {
  if (value !== "buyer_at_fault" && value !== "vendor_at_fault" && value !== "shared" && value !== "no_fault") throw new Error("The fault assessment is invalid.");
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
  if (value < 0n || value >= FIELD_PRIME) throw new Error("A field element is outside the STARK field.");
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

const ASSET_KEYS = ["symbol", "tokenAddress", "decimals"];
const CASE_KEYS = ["kind", "version", "caseId", "network", "poolAddress", "invoiceId", "asset", "escrowBaseUnits", "escrowDisplay", "collateralBaseUnits", "collateralDisplay", "buyerRecipient", "vendorRecipient", "arbiterRecipient", "arbiterLabel", "claimSummary", "memo", "respondBy", "createdAt", "caseSalt", "caseCommitment", "notice", "limitations"];
const CASE_DIGEST_KEYS = ["kind", "version", "caseId", "network", "poolAddress", "invoiceId", "assetSymbol", "assetDecimals", "hasCollateral", "respondBy", "createdAt", "claimSummaryHash", "caseCommitment", "notice", "limitations"];
const EVIDENCE_KEYS = ["kind", "version", "evidenceId", "network", "poolAddress", "caseCommitment", "submittedBy", "items", "itemHashes", "itemsRoot", "note", "createdAt", "evidenceSalt", "evidenceCommitment", "notice", "limitations"];
const EVIDENCE_DIGEST_KEYS = ["kind", "version", "evidenceId", "network", "poolAddress", "caseCommitment", "submittedBy", "itemCount", "itemHashes", "itemsRoot", "createdAt", "evidenceCommitment", "notice", "limitations"];
const RESOLUTION_KEYS = ["kind", "version", "resolutionId", "network", "poolAddress", "invoiceId", "asset", "escrowBaseUnits", "collateralBaseUnits", "faultAssessment", "buyerRefundBps", "arbiterFeeBps", "penaltyBps", "buyerRefundBaseUnits", "buyerRefundDisplay", "vendorReleaseBaseUnits", "vendorReleaseDisplay", "arbiterFeeBaseUnits", "arbiterFeeDisplay", "penaltyBaseUnits", "penaltyDisplay", "collateralReturnBaseUnits", "collateralReturnDisplay", "buyerTotalBaseUnits", "buyerTotalDisplay", "vendorTotalBaseUnits", "vendorTotalDisplay", "buyerRecipient", "vendorRecipient", "arbiterRecipient", "buyerEvidenceCommitment", "vendorEvidenceCommitment", "resolvedBy", "resolvedAt", "caseCommitment", "resolutionSalt", "resolutionCommitment", "notice", "limitations"];
const OUTCOME_KEYS = ["kind", "version", "resolutionId", "network", "poolAddress", "invoiceId", "faultAssessment", "resolvedBy", "resolvedAt", "caseCommitment", "resolutionCommitment", "outcomeCommitment", "notice", "limitations"];

function hasOnlyKeys(value: object, allowed: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every((key) => allowed.includes(key));
}

function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== DISPUTE_LIMITATIONS.length || value.some((entry, index) => entry !== DISPUTE_LIMITATIONS[index])) {
    throw new Error("The dispute limitations were altered.");
  }
}

function assertAsset(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ASSET_KEYS)) throw new Error(`${label} is invalid.`);
  const asset = value as DisputeAsset;
  requireSymbol(asset.symbol, `${label} symbol`);
  requireDecimals(asset.decimals, `${label} decimals`);
  if (!asset.tokenAddress || asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) throw new Error(`${label} token address is not canonical.`);
}

function assertDisputeCase(value: unknown): asserts value is DisputeCase {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, CASE_KEYS)) throw new Error("Dispute case is invalid.");
  const c = value as DisputeCase;
  if (c.kind !== CASE_KIND || c.version !== DISPUTE_ENGINE_VERSION || c.network !== MAINNET_CHAIN_ID
    || c.poolAddress !== STRK20_POOL_ADDRESS || c.notice !== DISPUTE_NOTICE
    || !/^case_[A-Za-z0-9_-]{1,48}$/.test(c.caseId)) throw new Error("Dispute case header is invalid.");
  assertLimitations(c.limitations);
  requireText(c.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  assertAsset(c.asset, "Dispute asset");
  const escrow = requireU128(requireBaseUnitString(c.escrowBaseUnits, "Escrow value"), "Escrow value");
  if (escrow <= 0n) throw new Error("The escrow value must be positive.");
  const collateral = requireU128(requireBaseUnitString(c.collateralBaseUnits, "Collateral value"), "Collateral value");
  if (c.escrowDisplay !== formatBaseUnits(escrow, c.asset.decimals)) throw new Error("The escrow display is inconsistent.");
  if (c.collateralDisplay !== formatBaseUnits(collateral, c.asset.decimals)) throw new Error("The collateral display is inconsistent.");
  if (c.buyerRecipient !== normalizeStarknetAddress(c.buyerRecipient)) throw new Error("The buyer recipient is not canonical.");
  if (c.vendorRecipient !== normalizeStarknetAddress(c.vendorRecipient)) throw new Error("The vendor recipient is not canonical.");
  if (c.buyerRecipient === c.vendorRecipient) throw new Error("The buyer and the vendor must differ.");
  if (c.arbiterRecipient !== "" && c.arbiterRecipient !== normalizeStarknetAddress(c.arbiterRecipient)) throw new Error("The arbiter recipient is not canonical.");
  if (typeof c.arbiterLabel !== "string" || c.arbiterLabel.length > 96) throw new Error("The arbiter label is invalid.");
  requireText(c.claimSummary, "Claim summary", 240);
  if (typeof c.memo !== "string" || c.memo.length > 160) throw new Error("The case memo is invalid.");
  requireIsoTimestamp(c.respondBy, "Response deadline");
  requireIsoTimestamp(c.createdAt, "Case creation time");
  requireFelt(c.caseSalt, "Case salt");
  if (requireFelt(c.caseCommitment, "Case commitment") !== computeCaseCommitment(c)) throw new Error("The case commitment does not match its contents.");
}

function assertDisputeCaseDigest(value: unknown): asserts value is DisputeCaseDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, CASE_DIGEST_KEYS)) throw new Error("Dispute case digest is invalid.");
  const d = value as DisputeCaseDigest;
  if (d.kind !== CASE_DIGEST_KIND || d.version !== DISPUTE_ENGINE_VERSION || d.network !== MAINNET_CHAIN_ID
    || d.poolAddress !== STRK20_POOL_ADDRESS || d.notice !== DISPUTE_NOTICE
    || !/^case_[A-Za-z0-9_-]{1,48}$/.test(d.caseId)) throw new Error("Dispute case digest header is invalid.");
  assertLimitations(d.limitations);
  requireText(d.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireSymbol(d.assetSymbol, "Digest asset symbol");
  requireDecimals(d.assetDecimals, "Digest asset decimals");
  if (typeof d.hasCollateral !== "boolean") throw new Error("The digest collateral flag is invalid.");
  requireIsoTimestamp(d.respondBy, "Response deadline");
  requireIsoTimestamp(d.createdAt, "Case creation time");
  requireFelt(d.claimSummaryHash, "Claim summary hash");
  requireFelt(d.caseCommitment, "Case commitment");
}

function assertEvidenceBundle(value: unknown): asserts value is EvidenceBundle {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, EVIDENCE_KEYS)) throw new Error("Evidence bundle is invalid.");
  const e = value as EvidenceBundle;
  if (e.kind !== EVIDENCE_KIND || e.version !== DISPUTE_ENGINE_VERSION || e.network !== MAINNET_CHAIN_ID
    || e.poolAddress !== STRK20_POOL_ADDRESS || e.notice !== DISPUTE_NOTICE
    || !/^evid_[A-Za-z0-9_-]{1,48}$/.test(e.evidenceId)) throw new Error("Evidence bundle header is invalid.");
  assertLimitations(e.limitations);
  requireFelt(e.caseCommitment, "Case commitment");
  if (e.submittedBy !== "buyer" && e.submittedBy !== "vendor") throw new Error("The evidence submitter is invalid.");
  if (!Array.isArray(e.items) || e.items.length < 1 || e.items.length > MAX_EVIDENCE_ITEMS) throw new Error("The evidence item list is invalid.");
  const items = e.items.map((item, index) => requireText(item, `Evidence item ${index + 1}`, 200));
  if (!Array.isArray(e.itemHashes) || e.itemHashes.length !== items.length) throw new Error("The evidence hash list is inconsistent.");
  const recomputed = items.map((item) => toHex(BigInt(hash.starknetKeccak(item))));
  if (recomputed.some((entry, index) => entry !== e.itemHashes[index])) throw new Error("An evidence item hash does not match its item.");
  if (e.itemsRoot !== toHex(computeItemsRoot(e.itemHashes))) throw new Error("The evidence items root is inconsistent.");
  if (typeof e.note !== "string" || e.note.length > 160) throw new Error("The evidence note is invalid.");
  requireIsoTimestamp(e.createdAt, "Evidence creation time");
  requireFelt(e.evidenceSalt, "Evidence salt");
  if (requireFelt(e.evidenceCommitment, "Evidence commitment") !== computeEvidenceCommitment(e)) throw new Error("The evidence commitment does not match its contents.");
}

function assertEvidenceDigest(value: unknown): asserts value is EvidenceDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, EVIDENCE_DIGEST_KEYS)) throw new Error("Evidence digest is invalid.");
  const d = value as EvidenceDigest;
  if (d.kind !== EVIDENCE_DIGEST_KIND || d.version !== DISPUTE_ENGINE_VERSION || d.network !== MAINNET_CHAIN_ID
    || d.poolAddress !== STRK20_POOL_ADDRESS || d.notice !== DISPUTE_NOTICE
    || !/^evid_[A-Za-z0-9_-]{1,48}$/.test(d.evidenceId)) throw new Error("Evidence digest header is invalid.");
  assertLimitations(d.limitations);
  requireFelt(d.caseCommitment, "Case commitment");
  if (d.submittedBy !== "buyer" && d.submittedBy !== "vendor") throw new Error("The evidence submitter is invalid.");
  if (!Number.isInteger(d.itemCount) || d.itemCount < 1 || d.itemCount > MAX_EVIDENCE_ITEMS) throw new Error("The digest item count is invalid.");
  if (!Array.isArray(d.itemHashes) || d.itemHashes.length !== d.itemCount) throw new Error("The digest hash list is inconsistent.");
  d.itemHashes.forEach((entry) => requireFelt(entry, "Evidence item hash"));
  if (d.itemsRoot !== toHex(computeItemsRoot(d.itemHashes))) throw new Error("The digest items root is inconsistent.");
  requireIsoTimestamp(d.createdAt, "Evidence creation time");
  requireFelt(d.evidenceCommitment, "Evidence commitment");
}

function assertDisputeResolution(value: unknown): asserts value is DisputeResolution {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, RESOLUTION_KEYS)) throw new Error("Dispute resolution is invalid.");
  const r = value as DisputeResolution;
  if (r.kind !== RESOLUTION_KIND || r.version !== DISPUTE_ENGINE_VERSION || r.network !== MAINNET_CHAIN_ID
    || r.poolAddress !== STRK20_POOL_ADDRESS || r.notice !== DISPUTE_NOTICE
    || !/^res_[A-Za-z0-9_-]{1,48}$/.test(r.resolutionId)) throw new Error("Dispute resolution header is invalid.");
  assertLimitations(r.limitations);
  requireText(r.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  assertAsset(r.asset, "Settlement asset");
  const escrow = requireU128(requireBaseUnitString(r.escrowBaseUnits, "Escrow value"), "Escrow value");
  if (escrow <= 0n) throw new Error("The escrow value must be positive.");
  const collateral = requireU128(requireBaseUnitString(r.collateralBaseUnits, "Collateral value"), "Collateral value");
  const fault = requireFault(r.faultAssessment);
  if (r.buyerRecipient !== normalizeStarknetAddress(r.buyerRecipient)) throw new Error("The buyer recipient is not canonical.");
  if (r.vendorRecipient !== normalizeStarknetAddress(r.vendorRecipient)) throw new Error("The vendor recipient is not canonical.");
  if (r.buyerRecipient === r.vendorRecipient) throw new Error("The buyer and the vendor must differ.");
  if (r.arbiterRecipient !== "" && r.arbiterRecipient !== normalizeStarknetAddress(r.arbiterRecipient)) throw new Error("The arbiter recipient is not canonical.");
  if (r.buyerEvidenceCommitment !== "") requireFelt(r.buyerEvidenceCommitment, "Buyer evidence commitment");
  if (r.vendorEvidenceCommitment !== "") requireFelt(r.vendorEvidenceCommitment, "Vendor evidence commitment");
  requireText(r.resolvedBy, "Resolved by", 96);
  requireIsoTimestamp(r.resolvedAt, "Resolution time");
  requireFelt(r.caseCommitment, "Case commitment");
  requireFelt(r.resolutionSalt, "Resolution salt");
  const allocation = solveDisputeAllocation(escrow, collateral, { faultAssessment: fault, buyerRefundBps: r.buyerRefundBps, arbiterFeeBps: r.arbiterFeeBps, penaltyBps: r.penaltyBps });
  if (allocation.arbiterFee > 0n && r.arbiterRecipient === "") throw new Error("An arbiter fee needs an arbiter recipient.");
  if (allocation.arbiterFee > 0n && (r.arbiterRecipient === r.buyerRecipient || r.arbiterRecipient === r.vendorRecipient)) throw new Error("A fee-bearing arbiter must differ from the buyer and the vendor.");
  if (requireBaseUnitString(r.buyerRefundBaseUnits, "Buyer refund") !== allocation.buyerRefund
    || requireBaseUnitString(r.vendorReleaseBaseUnits, "Vendor release") !== allocation.vendorRelease
    || requireBaseUnitString(r.arbiterFeeBaseUnits, "Arbiter fee") !== allocation.arbiterFee
    || requireBaseUnitString(r.penaltyBaseUnits, "Penalty") !== allocation.penalty
    || requireBaseUnitString(r.collateralReturnBaseUnits, "Collateral return") !== allocation.collateralReturn
    || requireBaseUnitString(r.buyerTotalBaseUnits, "Buyer total") !== allocation.buyerTotal
    || requireBaseUnitString(r.vendorTotalBaseUnits, "Vendor total") !== allocation.vendorTotal) throw new Error("The resolution economics do not reconcile.");
  const d = r.asset.decimals;
  if (r.buyerRefundDisplay !== formatBaseUnits(allocation.buyerRefund, d)
    || r.vendorReleaseDisplay !== formatBaseUnits(allocation.vendorRelease, d)
    || r.arbiterFeeDisplay !== formatBaseUnits(allocation.arbiterFee, d)
    || r.penaltyDisplay !== formatBaseUnits(allocation.penalty, d)
    || r.collateralReturnDisplay !== formatBaseUnits(allocation.collateralReturn, d)
    || r.buyerTotalDisplay !== formatBaseUnits(allocation.buyerTotal, d)
    || r.vendorTotalDisplay !== formatBaseUnits(allocation.vendorTotal, d)) throw new Error("A resolution display value is inconsistent.");
  if (requireFelt(r.resolutionCommitment, "Resolution commitment") !== computeResolutionCommitment(r)) throw new Error("The resolution commitment does not match its contents.");
}

function assertDisputeOutcome(value: unknown): asserts value is DisputeOutcomeAttestation {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, OUTCOME_KEYS)) throw new Error("Dispute outcome is invalid.");
  const o = value as DisputeOutcomeAttestation;
  if (o.kind !== OUTCOME_KIND || o.version !== DISPUTE_ENGINE_VERSION || o.network !== MAINNET_CHAIN_ID
    || o.poolAddress !== STRK20_POOL_ADDRESS || o.notice !== DISPUTE_NOTICE
    || !/^res_[A-Za-z0-9_-]{1,48}$/.test(o.resolutionId)) throw new Error("Dispute outcome header is invalid.");
  assertLimitations(o.limitations);
  requireText(o.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireFault(o.faultAssessment);
  requireText(o.resolvedBy, "Resolved by", 96);
  requireIsoTimestamp(o.resolvedAt, "Resolution time");
  requireFelt(o.caseCommitment, "Case commitment");
  requireFelt(o.resolutionCommitment, "Resolution commitment");
  if (requireFelt(o.outcomeCommitment, "Outcome commitment") !== computeOutcomeCommitment(o)) throw new Error("The outcome commitment does not match its contents.");
}
