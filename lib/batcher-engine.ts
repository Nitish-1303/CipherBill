/**
 * CipherBill — Multi-Merchant Invoice Settlement Reconciliation & Batcher Engine
 * ==============================================================================
 *
 * A client-side module that aggregates many per-invoice amounts — grouped by a
 * public merchant label — into a single signed "batch root", and proves in zero
 * knowledge that (a) every invoice amount is a bounded non-negative integer and
 * (b) the hidden amounts sum to exactly one PUBLIC declared batch total, WITHOUT
 * revealing any individual invoice amount or recipient address. Each invoice's
 * amount is a Pedersen commitment C_i = a_i·G + r_i·H with a bit-decomposition
 * range proof; the commitments are folded into a Poseidon Merkle "batch root"
 * that the issuer signs, so the whole batch is authenticated by one signature
 * and any single invoice can later be proven a member of the batch.
 *
 * The homomorphic sum-reconciliation leg is the heart of the reconciliation
 * claim: the verifier recomputes C_total = ΣC_i, forms P = C_total − T·G for the
 * PUBLIC declared total T, and checks a Schnorr proof that P = r_total·H. Because
 * H is a nothing-up-my-sleeve generator whose discrete log relative to G is
 * unknown, such a proof can only exist when the G-component of P is zero — i.e.
 * when the hidden amounts sum to T. The per-invoice range proofs bound that sum
 * below the curve order, so the modular equality is an honest integer equality.
 * Fiat–Shamir makes every proof non-interactive, and the issuer's Schnorr
 * signature over a Poseidon binding of every public field authenticates it offline.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof that a batch of hidden invoice amounts are each bounded
 *   non-negative integers and together sum to one public declared total. A
 *   verifier learns the batch total and invoice count — never any individual
 *   amount, recipient, blinding, or the Merkle openings.
 * - A single signed batch root over all invoice commitments, so one issuer
 *   Schnorr signature authenticates the whole batch and any one invoice can be
 *   proven a member with a compact Merkle inclusion proof.
 * - Selectively disclosable: the operator can later open any single invoice
 *   amount, any recipient reference, prove membership, or open the whole batch.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It is NOT decentralized: a single operator key issues attestations and no
 *   contract, oracle, scheduler, or consensus vouches for the inputs.
 * - It does NOT settle, disburse, net, or move any funds, atomically or
 *   otherwise, and does NOT move funds in the STRK20 pool. It reconciles
 *   operator-supplied figures; any real settlement happens out of band.
 * - It does NOT reduce on-chain gas, because it never builds or submits a
 *   transaction. Any throughput or "gas saved" figure in the dashboard is an
 *   illustrative deterministic estimate, never a measured on-chain cost.
 * - It does NOT read from or write to the STRK20 pool contract; the pool
 *   address below is provenance only.
 * - It does NOT verify that any invoice is real or was actually settled, and it
 *   does NOT observe real payment streams: "multi-merchant" means invoices are
 *   grouped by a public, operator-supplied merchant label.
 * - `summarizeBatchTrust()` and `getBatchVisibilityModel()` state these limits.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const BATCH_ENGINE_VERSION = 1 as const;
export const BATCH_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const BATCH_PROOF_SYSTEM = "stark-pedersen-batch-reconciliation-v1" as const;
/** Basis-point denominator for share/concentration figures (1/10000ths). */
export const BATCH_SHARE_SCALE = 10_000n;
export const DEFAULT_BATCH_AMOUNT_BIT_LENGTH = 64;
export const MIN_BATCH_AMOUNT_BIT_LENGTH = 8;
export const MAX_BATCH_AMOUNT_BIT_LENGTH = 128;
/** Minimum invoices in a batch (a batch of one is valid, if trivial). */
export const MIN_BATCH_INVOICES = 1;
/** Maximum invoices in a batch, bounding proof size and the amount sum below the curve order. */
export const MAX_BATCH_INVOICES = 64;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill batcher generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill batcher statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill batcher bit challenge v1");
const SUM_DOMAIN = hash.starknetKeccak("CipherBill batcher sum reconciliation v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill batcher binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill batcher issuer signature v1");
const RECIPIENT_DOMAIN = hash.starknetKeccak("CipherBill batcher recipient ref v1");
const LEAF_DOMAIN = hash.starknetKeccak("CipherBill batcher merkle leaf v1");
const NODE_DOMAIN = hash.starknetKeccak("CipherBill batcher merkle node v1");

const CERTIFICATE_KIND = "cipherbill.batch-certificate" as const;
const SECRET_KIND = "cipherbill.batch-certificate-secret" as const;
const AMOUNT_DISCLOSURE_KIND = "cipherbill.batch-amount-disclosure" as const;
const RECIPIENT_DISCLOSURE_KIND = "cipherbill.batch-recipient-disclosure" as const;
const INCLUSION_KIND = "cipherbill.batch-inclusion-proof" as const;
const BADGE_KIND = "cipherbill.batch-certificate-badge" as const;
const KEYPAIR_KIND = "cipherbill.batch-keypair" as const;
const MAX_ENCODED_LENGTH = 4_000_000;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface BatchAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface BatchKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing operator keeps it to sign batch roots. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface BatchEntropy {
  createId?: (kind: "certificate") => string;
  randomScalar?: () => bigint;
}

/** One invoice to reconcile into the batch. The amount and recipient are SECRET. */
export interface BatchInvoiceInput {
  /** PUBLIC merchant/counterparty grouping label. */
  merchantLabel: string;
  /** PUBLIC free-form invoice reference for this line. */
  invoiceRef: string;
  /** SECRET invoice amount in integer base units; hidden behind a Pedersen commitment. */
  amountBaseUnits: string;
  /** SECRET recipient reference/address; only a salted commitment is published. */
  recipientRef?: string;
}

/** A single reconciled line in the pure batch state. */
export interface BatchLineState {
  index: number;
  merchantLabel: string;
  invoiceRef: string;
  amountBaseUnits: string;
  /** Share of the batch total in basis points. */
  shareBps: string;
}

/** A per-merchant subtotal in the pure batch state. */
export interface MerchantSubtotalState {
  merchantLabel: string;
  invoiceCount: number;
  subtotalBaseUnits: string;
  /** Share of the batch total in basis points. */
  shareBps: string;
}

/** The pure, proof-free reconciliation of a batch (operator-side; all figures known). */
export interface BatchState {
  invoiceCount: number;
  merchantCount: number;
  totalBaseUnits: string;
  largestInvoiceBaseUnits: string;
  /** Largest single-merchant share in basis points (a concentration measure). */
  concentrationBps: string;
  lines: BatchLineState[];
  merchants: MerchantSubtotalState[];
}

export type BatchConcentrationBand = "low" | "elevated" | "high" | "critical";

/** A deterministic concentration heuristic over the batch — not a risk score or model. */
export interface BatchConcentrationAssessment {
  band: BatchConcentrationBand;
  concentrationRatio: number;
  merchantCount: number;
  rationale: string;
}

/**
 * A deterministic, illustrative aggregation estimate — NOT a measured on-chain
 * gas figure. It counts proof elements the batch folds under one signed root.
 */
export interface BatchEfficiencyEstimate {
  illustrative: true;
  invoiceCount: number;
  perInvoiceProofElements: number;
  batchedProofElements: number;
  signaturesForBatch: number;
  signaturesIfSeparate: number;
  aggregationNote: string;
}

/** The input to issue a batch reconciliation certificate. */
export interface IssueBatchCertificateInput {
  operatorAlias: string;
  asset: BatchAsset;
  /** PUBLIC reference for the batch as a whole. */
  batchRef: string;
  /** PUBLIC human-readable batch label. */
  batchLabel: string;
  /** SECRET per-invoice lines; amounts and recipients are hidden. */
  invoices: BatchInvoiceInput[];
  /** PUBLIC declared batch total in integer base units. Proven: Σ amounts = this. */
  declaredBatchTotalBaseUnits: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  amountBitLength?: number;
  memo?: string;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface BatchBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  challenge0: string;
  response0: string;
  response1: string;
}

/** Schnorr proof on base H that C_total − T·G is a pure H-multiple, i.e. Σ amounts = T. */
export interface SumReconciliationProof {
  commitment: CurvePointFelts;
  challenge: string;
  response: string;
}

/** Schnorr signature (challenge, response) over the binding by the issuer key. */
export interface IssuerSignature {
  challenge: string;
  response: string;
}

/** The public, proven record of one invoice: its commitment, range proof, and leaf metadata. */
export interface BatchInvoiceProof {
  index: number;
  merchantLabel: string;
  invoiceRef: string;
  /** Salted Poseidon commitment to the recipient reference; hides the value. */
  recipientCommitment: string;
  recipientCommitted: boolean;
  /** Poseidon Merkle leaf hash over the commitment and leaf metadata. */
  leafHash: string;
  /** Pedersen commitment C_i = amount·G + blinding·H. */
  commitment: CurvePointFelts;
  /** Bit-decomposition range proof that the committed amount ∈ [0, 2^amountBitLength). */
  bits: BatchBitProof[];
}

/** The zero-knowledge proof bundle for a batch. */
export interface BatchProof {
  proofSystem: typeof BATCH_PROOF_SYSTEM;
  amountBitLength: number;
  generatorH: CurvePointFelts;
  /** Poseidon Merkle root over every invoice leaf hash. */
  batchRoot: string;
  invoices: BatchInvoiceProof[];
  /** Homomorphic proof that Σ committed amounts equals the public declared total. */
  sumReconciliation: SumReconciliationProof;
}

/** A verifiable, publicly shareable batch reconciliation certificate. */
export interface BatchCertificate {
  kind: typeof CERTIFICATE_KIND;
  version: typeof BATCH_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  certificateId: string;
  operatorAlias: string;
  batchRef: string;
  batchLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC declared batch total in base units; the hidden amounts are proven to sum to it. */
  declaredBatchTotalBaseUnits: string;
  /** PUBLIC number of invoices in the batch. */
  invoiceCount: number;
  /** PUBLIC number of distinct merchant labels in the batch. */
  merchantCount: number;
  issuerPublicKey: CurvePointFelts;
  proof: BatchProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}

/** SECRET per-invoice opening the operator keeps. Never publish it. */
export interface BatchInvoiceSecret {
  index: number;
  amountBaseUnits: string;
  blinding: string;
  recipientRef: string;
  recipientSalt: string;
  recipientCommitted: boolean;
}

/** SECRET issuer record of a freshly issued batch. Never publish it. */
export interface BatchCertificateSecret {
  kind: typeof SECRET_KIND;
  certificateId: string;
  declaredBatchTotalBaseUnits: string;
  invoices: BatchInvoiceSecret[];
}

/** A full opening the operator can hand a counterparty to reveal every invoice figure. */
export interface BatchCertificateOpening {
  invoices: { amountBaseUnits: string; blinding: string }[];
}

/** Selective disclosure of a single committed invoice amount. */
export interface BatchAmountDisclosure {
  kind: typeof AMOUNT_DISCLOSURE_KIND;
  certificateId: string;
  index: number;
  amountBaseUnits: string;
  blinding: string;
}

/** Selective disclosure of a single committed recipient reference. */
export interface BatchRecipientDisclosure {
  kind: typeof RECIPIENT_DISCLOSURE_KIND;
  certificateId: string;
  index: number;
  value: string;
  salt: string;
}

/** One step in a Merkle inclusion path. */
export interface MerklePathStep {
  sibling: string;
  siblingIsLeft: boolean;
}

/** A compact proof that one invoice is a member of the signed batch root. */
export interface BatchInclusionProof {
  kind: typeof INCLUSION_KIND;
  certificateId: string;
  index: number;
  merchantLabel: string;
  invoiceRef: string;
  recipientCommitment: string;
  recipientCommitted: boolean;
  commitment: CurvePointFelts;
  leafHash: string;
  path: MerklePathStep[];
}

/** A compact, shareable summary of a batch with only public display fields. */
export interface BatchCertificateBadge {
  kind: typeof BADGE_KIND;
  certificateId: string;
  operatorAlias: string;
  batchRef: string;
  batchLabel: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  invoiceCountDisplay: string;
  merchantCountDisplay: string;
  batchTotalDisplay: string;
  batchRoot: string;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

/** An honest, machine-readable statement of what the engine proves — and what it does not. */
export interface BatchTrustModel {
  isZeroKnowledge: boolean;
  provesInvoiceAmountsAreBoundedNonNegative: boolean;
  provesBatchSumEqualsDeclaredTotal: boolean;
  bindsAllInvoicesUnderOneSignedRoot: boolean;
  hidesIndividualInvoiceAmounts: boolean;
  hidesRecipientAddresses: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  settlesOrDisbursesFunds: boolean;
  settlesOnChain: boolean;
  movesPoolFunds: boolean;
  reducesOnChainGas: boolean;
  callsPoolContract: boolean;
  verifiesInvoicesAreRealOrSettled: boolean;
  observesRealPaymentStreams: boolean;
  metricsAreMeasuredOnChain: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

/** What a verifier does and does not learn from a batch certificate. */
export interface BatchVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const BATCH_NOTICE =
  "Zero-knowledge proof that a batch of hidden per-invoice amounts are each bounded non-negative integers and together sum to one public declared batch total, folded under a single issuer-signed Merkle root that hides individual amounts and recipient addresses. It authenticates the issuer and supports selective disclosure and Merkle inclusion proofs. It is neither decentralized nor automatic; it does not settle, disburse, net, or move any funds, does not reduce on-chain gas (it submits no transaction), does not verify that any invoice is real or settled, does not observe real payment streams (invoices are grouped by a public merchant label), and never reads from or writes to the STRK20 pool contract — the pool address is provenance only.";

// ---------------------------------------------------------------------------
// Curve primitives
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

/**
 * A second Pedersen generator H with no known discrete log relative to G,
 * derived by hash-and-increment from a fixed domain seed (nothing-up-my-sleeve).
 * The STARK curve has prime order and cofactor 1, so any on-curve point is a
 * full-order generator.
 */
function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

/** Returns the canonical generator H as serializable felts. */
export function deriveBatchGenerator(): CurvePointFelts {
  return pointToFelts(independentGenerator());
}

/**
 * Deterministically hashes a seed to an independent curve point by
 * hash-and-increment, so its discrete log relative to G is unknown by construction.
 */
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
  throw new Error("Failed to derive an independent batcher generator.");
}

/** scalar·point, tolerating a zero scalar or the identity base (noble rejects both). */
function scalePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const s = mod(scalar, CURVE_ORDER);
  if (s === 0n) return ZERO;
  return point.equals(ZERO) ? ZERO : point.multiply(s);
}

/** Pedersen commitment value·G + blinding·H. */
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

/** An operator issuing keypair. The secret signs batch roots; the public key authenticates them. */
export function createBatchIssuerKey(entropy: BatchEntropy = {}): BatchKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

// ---------------------------------------------------------------------------
// Pure batch reconciliation, concentration, and illustrative efficiency
// ---------------------------------------------------------------------------

/** Validates and normalizes a list of invoice inputs (amounts, labels, references). */
function requireInvoiceInputs(
  invoices: BatchInvoiceInput[],
): { merchantLabel: string; invoiceRef: string; amount: bigint; recipientRef: string }[] {
  if (!Array.isArray(invoices)) throw new Error("The batch invoices are required.");
  if (invoices.length < MIN_BATCH_INVOICES) throw new Error(`A batch needs at least ${MIN_BATCH_INVOICES} invoice.`);
  if (invoices.length > MAX_BATCH_INVOICES) throw new Error(`A batch may hold at most ${MAX_BATCH_INVOICES} invoices.`);
  return invoices.map((invoice, index) => {
    if (!invoice || typeof invoice !== "object") throw new Error(`Invoice ${index + 1} is malformed.`);
    const amount = requireBaseUnits(invoice.amountBaseUnits, `invoice ${index + 1} amount`);
    if (amount > U128_MAX) throw new Error(`Invoice ${index + 1} amount must fit within the u128 range.`);
    return {
      merchantLabel: requireText(invoice.merchantLabel, `invoice ${index + 1} merchant label`, 64),
      invoiceRef: requireText(invoice.invoiceRef, `invoice ${index + 1} reference`, 96),
      amount,
      recipientRef: invoice.recipientRef ? requireText(invoice.recipientRef, `invoice ${index + 1} recipient reference`, 128) : "",
    };
  });
}

/**
 * Computes the pure batch reconciliation: the total, per-merchant subtotals,
 * per-line shares, and the single-merchant concentration. This is the same total
 * the zero-knowledge proof reconciles the hidden amounts to.
 */
export function computeBatchState(invoices: BatchInvoiceInput[]): BatchState {
  const parsed = requireInvoiceInputs(invoices);
  const total = parsed.reduce((sum, invoice) => sum + invoice.amount, 0n);
  const subtotals = new Map<string, { count: number; subtotal: bigint }>();
  let largest = 0n;
  for (const invoice of parsed) {
    if (invoice.amount > largest) largest = invoice.amount;
    const existing = subtotals.get(invoice.merchantLabel) ?? { count: 0, subtotal: 0n };
    existing.count += 1;
    existing.subtotal += invoice.amount;
    subtotals.set(invoice.merchantLabel, existing);
  }
  const shareBps = (value: bigint): string => (total > 0n ? ((value * BATCH_SHARE_SCALE) / total).toString() : "0");
  const lines: BatchLineState[] = parsed.map((invoice, index) => ({
    index,
    merchantLabel: invoice.merchantLabel,
    invoiceRef: invoice.invoiceRef,
    amountBaseUnits: invoice.amount.toString(),
    shareBps: shareBps(invoice.amount),
  }));
  const merchants: MerchantSubtotalState[] = [...subtotals.entries()].map(([merchantLabel, { count, subtotal }]) => ({
    merchantLabel,
    invoiceCount: count,
    subtotalBaseUnits: subtotal.toString(),
    shareBps: shareBps(subtotal),
  }));
  let concentration = 0n;
  for (const merchant of merchants) {
    const share = BigInt(merchant.shareBps);
    if (share > concentration) concentration = share;
  }
  return {
    invoiceCount: parsed.length,
    merchantCount: subtotals.size,
    totalBaseUnits: total.toString(),
    largestInvoiceBaseUnits: largest.toString(),
    concentrationBps: concentration.toString(),
    lines,
    merchants,
  };
}

function clamp01(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return value > 1 ? 1 : value;
}

/**
 * A deterministic single-merchant concentration band over the batch — a
 * transparent heuristic on the largest merchant's share, NOT a risk score or model.
 */
export function assessBatchConcentration(state: BatchState): BatchConcentrationAssessment {
  const concentrationRatio = clamp01(Number(state.concentrationBps) / Number(BATCH_SHARE_SCALE));
  let band: BatchConcentrationBand;
  if (concentrationRatio >= 0.75 || state.merchantCount <= 1) band = "critical";
  else if (concentrationRatio >= 0.5) band = "high";
  else if (concentrationRatio >= 0.25) band = "elevated";
  else band = "low";
  return {
    band,
    concentrationRatio,
    merchantCount: state.merchantCount,
    rationale:
      state.merchantCount <= 1
        ? "The entire batch settles to a single merchant label; there is no cross-merchant diversification."
        : `The largest merchant accounts for ${(concentrationRatio * 100).toFixed(1)}% of the declared batch total across ${state.merchantCount} merchants.`,
  };
}

/**
 * An illustrative, deterministic aggregation estimate. It counts how many proof
 * elements the batch folds under one signed root — NOT a measured on-chain gas
 * figure, because this engine never builds or submits a transaction.
 */
export function estimateBatchEfficiency(
  state: BatchState,
  amountBitLength: number = DEFAULT_BATCH_AMOUNT_BIT_LENGTH,
): BatchEfficiencyEstimate {
  const bitLength = requireInt(amountBitLength, "amount bit length", MIN_BATCH_AMOUNT_BIT_LENGTH, MAX_BATCH_AMOUNT_BIT_LENGTH);
  return {
    illustrative: true,
    invoiceCount: state.invoiceCount,
    perInvoiceProofElements: bitLength,
    batchedProofElements: state.invoiceCount * bitLength,
    signaturesForBatch: 1,
    signaturesIfSeparate: state.invoiceCount,
    aggregationNote:
      "Illustrative deterministic estimate: the batch folds all invoice commitments under one issuer-signed Merkle root, so one signature authenticates the whole batch instead of one per invoice. This is not a measured on-chain gas cost; the engine submits no transaction.",
  };
}

export function formatBatchBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

/** Formats a basis-point share, e.g. 6250 → "62.5%". */
export function formatShare(bps: string | number | bigint): string {
  const n = Number(bps);
  return `${n / 100}%`;
}

/** Formats an invoice count, e.g. 12 → "12 invoices", 1 → "1 invoice". */
export function formatInvoiceCount(count: string | number): string {
  const n = Number(count);
  return `${n} ${n === 1 ? "invoice" : "invoices"}`;
}

/** Formats a merchant count, e.g. 3 → "3 merchants", 1 → "1 merchant". */
export function formatMerchantCount(count: string | number): string {
  const n = Number(count);
  return `${n} ${n === 1 ? "merchant" : "merchants"}`;
}

// ---------------------------------------------------------------------------
// Poseidon Merkle batch root and inclusion paths
// ---------------------------------------------------------------------------

/** The Poseidon leaf hash for one invoice: its commitment plus public leaf metadata. */
function computeLeafHash(
  index: number,
  commitment: CurvePoint,
  merchantLabel: string,
  invoiceRef: string,
  recipientCommitment: bigint,
  recipientCommitted: boolean,
): bigint {
  return hashElements([
    LEAF_DOMAIN,
    BigInt(index),
    commitment.x,
    commitment.y,
    hash.starknetKeccak(merchantLabel),
    hash.starknetKeccak(invoiceRef),
    recipientCommitment,
    recipientCommitted ? 1n : 0n,
  ]);
}

/** Builds every level of the Merkle tree, duplicating the last node when a level is odd. */
function buildMerkleLevels(leaves: bigint[]): bigint[][] {
  if (leaves.length === 0) throw new Error("A batch root needs at least one leaf.");
  const levels: bigint[][] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(hashElements([NODE_DOMAIN, left, right]));
    }
    levels.push(next);
    current = next;
  }
  return levels;
}

/** The Poseidon Merkle root over a list of leaf hashes. */
function merkleRoot(leaves: bigint[]): bigint {
  const levels = buildMerkleLevels(leaves);
  return levels[levels.length - 1][0];
}

/** The inclusion path (sibling hashes and their side) from a leaf up to the root. */
function merklePath(leaves: bigint[], index: number): MerklePathStep[] {
  const levels = buildMerkleLevels(leaves);
  const path: MerklePathStep[] = [];
  let idx = index;
  for (let level = 0; level < levels.length - 1; level += 1) {
    const nodes = levels[level];
    const isRight = idx % 2 === 1;
    const siblingIndex = isRight ? idx - 1 : idx + 1 < nodes.length ? idx + 1 : idx;
    path.push({ sibling: toHex(nodes[siblingIndex]), siblingIsLeft: isRight });
    idx = Math.floor(idx / 2);
  }
  return path;
}

/** Folds a leaf hash up an inclusion path to a reconstructed root. */
function foldMerklePath(leafHash: bigint, path: MerklePathStep[]): bigint {
  let acc = leafHash;
  for (const step of path) {
    const sibling = requireFelt(step.sibling);
    acc = step.siblingIsLeft ? hashElements([NODE_DOMAIN, sibling, acc]) : hashElements([NODE_DOMAIN, acc, sibling]);
  }
  return acc;
}

// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  certificateId: string;
  operatorAlias: string;
  batchRef: string;
  batchLabel: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  declaredBatchTotal: bigint;
  invoiceCount: number;
  merchantCount: number;
  amountBitLength: number;
  batchRoot: bigint;
  createdAt: string;
  memo: string;
}

/**
 * The certificate binding hash: a Poseidon digest over every public,
 * proof-independent field plus the batch root, the declared total, the issuer
 * key, and the generator H. Every range-proof and reconciliation challenge and
 * the issuer signature are bound to it, so no field can change without invalidating it.
 */
function computeBindingHash(fields: BindingFields, issuerKey: CurvePoint, h: CurvePoint): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(BATCH_ENGINE_VERSION),
    hash.starknetKeccak(fields.certificateId),
    hash.starknetKeccak(fields.operatorAlias),
    hash.starknetKeccak(fields.batchRef),
    hash.starknetKeccak(fields.batchLabel),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.declaredBatchTotal,
    BigInt(fields.invoiceCount),
    BigInt(fields.merchantCount),
    BigInt(fields.amountBitLength),
    fields.batchRoot,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    h.x,
    h.y,
  ]);
}

/** Context digest that seeds every proof challenge, bound to the certificate binding. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/**
 * Per-bit Fiat–Shamir challenge, bound to the context, the invoice leg index,
 * the bit index, and both proof nonces.
 */
function bitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

/** Salted Poseidon commitment to a reference string; hiding and binding. */
function commitRef(domain: bigint, value: string, salt: bigint): bigint {
  return hashElements([domain, hash.starknetKeccak(value), salt]);
}

// ---------------------------------------------------------------------------
// Per-bit one-of-two (OR) proof
// ---------------------------------------------------------------------------

/**
 * Proves the commitment C = bit·G + r·H opens to 0 OR to 1, in zero knowledge.
 * Branch 0 proves C = r·H; branch 1 proves C − G = r·H. The false branch is
 * simulated; the real branch is completed after the Fiat–Shamir challenge is fixed.
 */
function proveBit(
  bit: number,
  commitment: CurvePoint,
  blinding: bigint,
  ctx: bigint,
  leg: number,
  index: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): BatchBitProof {
  const p0 = commitment;
  const p1 = commitment.add(G.negate());
  let a0: CurvePoint;
  let a1: CurvePoint;
  let challenge0: bigint;
  let response0: bigint;
  let response1: bigint;

  if (bit === 0) {
    const k0 = nonZeroScalar(nextScalar());
    a0 = scalePoint(h, k0);
    const e1 = nonZeroScalar(nextScalar());
    const s1 = nonZeroScalar(nextScalar());
    a1 = scalePoint(h, s1).add(scalePoint(p1, e1).negate());
    const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
    challenge0 = mod(e - e1, CURVE_ORDER);
    response0 = mod(k0 + challenge0 * blinding, CURVE_ORDER);
    response1 = s1;
  } else {
    const k1 = nonZeroScalar(nextScalar());
    a1 = scalePoint(h, k1);
    challenge0 = nonZeroScalar(nextScalar());
    response0 = nonZeroScalar(nextScalar());
    a0 = scalePoint(h, response0).add(scalePoint(p0, challenge0).negate());
    const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
    const e1 = mod(e - challenge0, CURVE_ORDER);
    response1 = mod(k1 + e1 * blinding, CURVE_ORDER);
  }

  return {
    commitment: pointToFelts(commitment),
    a0: pointToFelts(a0),
    a1: pointToFelts(a1),
    challenge0: toHex(challenge0),
    response0: toHex(response0),
    response1: toHex(response1),
  };
}

/** Verifies a bit proof and returns the underlying commitment on success, or null. */
function verifyBit(proof: BatchBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
  const commitment = pointFromFelts(proof.commitment);
  const a0 = pointFromFelts(proof.a0);
  const a1 = pointFromFelts(proof.a1);
  const challenge0 = requireScalar(proof.challenge0, true);
  const response0 = requireScalar(proof.response0, true);
  const response1 = requireScalar(proof.response1, true);
  const e = bitChallenge(ctx, leg, index, commitment, a0, a1);
  const challenge1 = mod(e - challenge0, CURVE_ORDER);
  const p0 = commitment;
  const p1 = commitment.add(G.negate());
  const ok0 = scalePoint(h, response0).equals(a0.add(scalePoint(p0, challenge0)));
  const ok1 = scalePoint(h, response1).equals(a1.add(scalePoint(p1, challenge1)));
  return ok0 && ok1 ? commitment : null;
}

// ---------------------------------------------------------------------------
// Bit-decomposition range proof (one per invoice amount)
// ---------------------------------------------------------------------------

/**
 * Proves `value ∈ [0, 2^bitLength)` by committing each bit and proving each is 0
 * or 1. The per-bit blindings are chosen so `Σ 2^i·r_i ≡ blinding (mod n)`, so the
 * homomorphic sum `Σ 2^i·C_i` reconstructs the amount commitment exactly.
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): BatchBitProof[] {
  if (value < 0n) throw new Error("Cannot range-prove a negative value.");
  if (value >= 1n << BigInt(bitLength)) throw new Error(`The value exceeds the ${bitLength}-bit band.`);
  const bits: number[] = [];
  for (let i = 0; i < bitLength; i += 1) bits.push(Number((value >> BigInt(i)) & 1n));
  const blindings: bigint[] = [];
  let partial = 0n;
  for (let i = 0; i < bitLength - 1; i += 1) {
    const r = nonZeroScalar(nextScalar());
    blindings.push(r);
    partial = mod(partial + (1n << BigInt(i)) * r, CURVE_ORDER);
  }
  const topWeight = modInverse(1n << BigInt(bitLength - 1), CURVE_ORDER);
  const lastBlinding = mod((blinding - partial) * topWeight, CURVE_ORDER);
  if (lastBlinding === 0n) throw new Error("Degenerate range-proof blinding; retry with fresh entropy.");
  blindings.push(lastBlinding);
  const proofs: BatchBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = pedersenCommit(BigInt(bits[i]), blindings[i], h);
    proofs.push(proveBit(bits[i], commitment, blindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies every bit and returns the reconstructed commitment `Σ 2^i·C_i`, or null. */
function verifyRange(proofs: BatchBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return null;
  let acc = ZERO;
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = verifyBit(proofs[i], ctx, leg, i, h);
    if (!commitment) return null;
    acc = acc.add(scalePoint(commitment, 1n << BigInt(i)));
  }
  return acc;
}

// ---------------------------------------------------------------------------
// Homomorphic sum-reconciliation proof (Schnorr on base H)
// ---------------------------------------------------------------------------

/**
 * Proves knowledge of r such that P = r·H, where P = C_total − T·G. Because H's
 * discrete log relative to G is unknown, a valid proof exists only when P has no
 * G-component — i.e. when the committed amounts sum to the public total T.
 */
function proveSumReconciliation(rTotal: bigint, ctx: bigint, h: CurvePoint, nextScalar: () => bigint): SumReconciliationProof {
  const k = nonZeroScalar(nextScalar());
  const commitment = scalePoint(h, k);
  const challenge = mod(hashElements([SUM_DOMAIN, ctx, commitment.x, commitment.y]), CURVE_ORDER);
  const response = mod(k + challenge * rTotal, CURVE_ORDER);
  return { commitment: pointToFelts(commitment), challenge: toHex(challenge), response: toHex(response) };
}

/** Verifies the sum-reconciliation proof against P = C_total − T·G. */
function verifySumReconciliation(proof: SumReconciliationProof, expectedPoint: CurvePoint, ctx: bigint, h: CurvePoint): boolean {
  let challenge: bigint;
  let response: bigint;
  try {
    challenge = requireScalar(proof.challenge, true);
    response = requireScalar(proof.response, true);
  } catch {
    return false;
  }
  const commitment = pointFromFelts(proof.commitment);
  const expectedChallenge = mod(hashElements([SUM_DOMAIN, ctx, commitment.x, commitment.y]), CURVE_ORDER);
  if (expectedChallenge !== challenge) return false;
  return scalePoint(h, response).equals(commitment.add(scalePoint(expectedPoint, challenge)));
}

// ---------------------------------------------------------------------------
// Issuer Schnorr signature over the binding hash
// ---------------------------------------------------------------------------

/** Signs the binding hash with the issuer scalar so anyone can authenticate it offline. */
function signBinding(bindingHash: bigint, secret: bigint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const commitment = G.multiply(k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * secret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

/** Verifies the issuer Schnorr signature against the published public key. */
function verifySignature(signature: IssuerSignature, bindingHash: bigint, publicKey: CurvePoint): boolean {
  let challenge: bigint;
  let response: bigint;
  try {
    challenge = requireScalar(signature.challenge, true);
    response = requireScalar(signature.response, true);
  } catch {
    return false;
  }
  const commitment = scalePoint(G, response).add(scalePoint(publicKey, challenge).negate());
  if (commitment.equals(ZERO)) return false;
  const expected = mod(hashElements([SIGNATURE_DOMAIN, commitment.x, commitment.y, bindingHash]), CURVE_ORDER);
  return expected === challenge;
}

// ---------------------------------------------------------------------------
// Issue and verify a batch certificate
// ---------------------------------------------------------------------------

/**
 * Issues a zero-knowledge batch reconciliation certificate. Proves every hidden
 * invoice amount is a bounded non-negative integer and that they sum to the
 * PUBLIC declared batch total, folds all invoice commitments under a single
 * Merkle root, and signs the binding with the issuer key. Throws if the declared
 * total does not equal the sum of the supplied amounts, since no honest proof exists then.
 */
export function issueBatchCertificate(
  input: IssueBatchCertificateInput,
  now: Date = new Date(),
  entropy: BatchEntropy = {},
): { certificate: BatchCertificate; secret: BatchCertificateSecret } {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;

  const operatorAlias = requireText(input.operatorAlias, "operator alias", 96);
  const batchRef = requireText(input.batchRef, "batch reference", 96);
  const batchLabel = requireText(input.batchLabel, "batch label", 96);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress);
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 36);
  const amountBitLength = requireInt(
    input.amountBitLength ?? DEFAULT_BATCH_AMOUNT_BIT_LENGTH,
    "amount bit length",
    MIN_BATCH_AMOUNT_BIT_LENGTH,
    MAX_BATCH_AMOUNT_BIT_LENGTH,
  );
  const memo = input.memo ? requireText(input.memo, "memo", 160) : "";

  const parsed = requireInvoiceInputs(input.invoices);
  const bound = 1n << BigInt(amountBitLength);
  // Guard the honest integer sum against modular wraparound below the curve order.
  if (BigInt(parsed.length) * bound >= CURVE_ORDER) throw new Error("The batch is too large for the amount bit length; reduce either.");
  for (let i = 0; i < parsed.length; i += 1) {
    if (parsed[i].amount >= bound) throw new Error(`Invoice ${i + 1} amount exceeds the ${amountBitLength}-bit band.`);
  }
  const declaredTotal = requireBaseUnits(input.declaredBatchTotalBaseUnits, "declared batch total");
  const actualTotal = parsed.reduce((sum, invoice) => sum + invoice.amount, 0n);
  if (declaredTotal !== actualTotal)
    throw new Error("The declared batch total does not equal the sum of the invoice amounts; no honest reconciliation proof exists.");

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);
  const h = independentGenerator();
  const merchantLabels = new Set(parsed.map((invoice) => invoice.merchantLabel));
  const certificateId = createId("certificate");
  const createdAt = requireIsoTimestamp(now.toISOString());

  const blindings: bigint[] = [];
  const leafHashes: bigint[] = [];
  const invoiceSecrets: BatchInvoiceSecret[] = [];
  const invoiceMeta: {
    index: number;
    merchantLabel: string;
    invoiceRef: string;
    recipientCommitment: bigint;
    recipientCommitted: boolean;
    leafHash: bigint;
    commitment: CurvePoint;
  }[] = [];
  for (let i = 0; i < parsed.length; i += 1) {
    const blinding = nonZeroScalar(nextScalar());
    const commitment = pedersenCommit(parsed[i].amount, blinding, h);
    const recipientCommitted = parsed[i].recipientRef.length > 0;
    const recipientSalt = nonZeroScalar(nextScalar());
    const recipientCommitment = recipientCommitted ? commitRef(RECIPIENT_DOMAIN, parsed[i].recipientRef, recipientSalt) : 0n;
    const leafHash = computeLeafHash(i, commitment, parsed[i].merchantLabel, parsed[i].invoiceRef, recipientCommitment, recipientCommitted);
    blindings.push(blinding);
    leafHashes.push(leafHash);
    invoiceMeta.push({
      index: i,
      merchantLabel: parsed[i].merchantLabel,
      invoiceRef: parsed[i].invoiceRef,
      recipientCommitment,
      recipientCommitted,
      leafHash,
      commitment,
    });
    invoiceSecrets.push({
      index: i,
      amountBaseUnits: parsed[i].amount.toString(),
      blinding: toHex(blinding),
      recipientRef: parsed[i].recipientRef,
      recipientSalt: toHex(recipientSalt),
      recipientCommitted,
    });
  }

  const batchRoot = merkleRoot(leafHashes);
  const fields: BindingFields = {
    certificateId,
    operatorAlias,
    batchRef,
    batchLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    declaredBatchTotal: declaredTotal,
    invoiceCount: parsed.length,
    merchantCount: merchantLabels.size,
    amountBitLength,
    batchRoot,
    createdAt,
    memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, h);
  const ctx = statementContext(bindingHash);

  // Prove each invoice amount is in range, tied to its commitment (leg = invoice index).
  const invoiceProofs: BatchInvoiceProof[] = invoiceMeta.map((meta, i) => ({
    index: meta.index,
    merchantLabel: meta.merchantLabel,
    invoiceRef: meta.invoiceRef,
    recipientCommitment: toHex(meta.recipientCommitment),
    recipientCommitted: meta.recipientCommitted,
    leafHash: toHex(meta.leafHash),
    commitment: pointToFelts(meta.commitment),
    bits: proveRange(parsed[i].amount, blindings[i], amountBitLength, ctx, i, h, nextScalar),
  }));

  // Prove Σ amounts = declared total: C_total − T·G must be a pure H-multiple.
  const rTotal = mod(
    blindings.reduce((sum, r) => sum + r, 0n),
    CURVE_ORDER,
  );
  const sumReconciliation = proveSumReconciliation(rTotal, ctx, h, nextScalar);
  const issuerSignature = signBinding(bindingHash, issuerSecret, nextScalar);

  const proof: BatchProof = {
    proofSystem: BATCH_PROOF_SYSTEM,
    amountBitLength,
    generatorH: pointToFelts(h),
    batchRoot: toHex(batchRoot),
    invoices: invoiceProofs,
    sumReconciliation,
  };

  const certificate: BatchCertificate = {
    kind: CERTIFICATE_KIND,
    version: BATCH_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    certificateId,
    operatorAlias,
    batchRef,
    batchLabel,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    declaredBatchTotalBaseUnits: declaredTotal.toString(),
    invoiceCount: parsed.length,
    merchantCount: merchantLabels.size,
    issuerPublicKey: pointToFelts(issuerKey),
    proof,
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: BATCH_NOTICE,
  };
  const secret: BatchCertificateSecret = {
    kind: SECRET_KIND,
    certificateId,
    declaredBatchTotalBaseUnits: declaredTotal.toString(),
    invoices: invoiceSecrets,
  };
  return { certificate, secret };
}

/**
 * Verifies a batch certificate end to end: the binding hash, the issuer
 * signature, every invoice's leaf hash and range proof tied to its commitment,
 * the Merkle batch root, and the homomorphic sum-reconciliation proof tying
 * ΣC_i − T·G to a pure H-multiple. A passing verdict means every committed
 * invoice amount is a non-negative integer in band and the amounts sum to exactly
 * the public declared total — nothing about any individual amount is revealed.
 */
export function verifyBatchCertificate(certificate: BatchCertificate): boolean {
  try {
    if (!certificate || certificate.kind !== CERTIFICATE_KIND) return false;
    const proof = certificate.proof;
    if (!proof || proof.proofSystem !== BATCH_PROOF_SYSTEM) return false;
    const amountBitLength = proof.amountBitLength;
    if (!Number.isInteger(amountBitLength) || amountBitLength < MIN_BATCH_AMOUNT_BIT_LENGTH || amountBitLength > MAX_BATCH_AMOUNT_BIT_LENGTH)
      return false;
    if (!Array.isArray(proof.invoices) || proof.invoices.length < MIN_BATCH_INVOICES || proof.invoices.length > MAX_BATCH_INVOICES)
      return false;
    if (proof.invoices.length !== certificate.invoiceCount) return false;

    const h = pointFromFelts(proof.generatorH);
    if (!h.equals(independentGenerator())) return false;
    const bound = 1n << BigInt(amountBitLength);
    if (BigInt(proof.invoices.length) * bound >= CURVE_ORDER) return false;

    const issuerKey = pointFromFelts(certificate.issuerPublicKey);
    const commitments: CurvePoint[] = [];
    const leafHashes: bigint[] = [];
    const merchantLabels = new Set<string>();
    for (let i = 0; i < proof.invoices.length; i += 1) {
      const invoice = proof.invoices[i];
      if (invoice.index !== i) return false;
      const commitment = pointFromFelts(invoice.commitment);
      const recipientCommitment = requireFelt(invoice.recipientCommitment);
      const leafHash = computeLeafHash(i, commitment, invoice.merchantLabel, invoice.invoiceRef, recipientCommitment, invoice.recipientCommitted);
      if (toHex(leafHash) !== invoice.leafHash) return false;
      commitments.push(commitment);
      leafHashes.push(leafHash);
      merchantLabels.add(invoice.merchantLabel);
    }
    if (merchantLabels.size !== certificate.merchantCount) return false;
    const batchRoot = merkleRoot(leafHashes);
    if (toHex(batchRoot) !== proof.batchRoot) return false;

    const declaredTotal = requireBaseUnits(certificate.declaredBatchTotalBaseUnits, "declared batch total");
    const fields: BindingFields = {
      certificateId: certificate.certificateId,
      operatorAlias: certificate.operatorAlias,
      batchRef: certificate.batchRef,
      batchLabel: certificate.batchLabel,
      assetSymbol: certificate.assetSymbol,
      tokenAddress: certificate.tokenAddress,
      assetDecimals: certificate.assetDecimals,
      declaredBatchTotal: declaredTotal,
      invoiceCount: certificate.invoiceCount,
      merchantCount: certificate.merchantCount,
      amountBitLength,
      batchRoot,
      createdAt: certificate.createdAt,
      memo: certificate.memo,
    };
    const bindingHash = computeBindingHash(fields, issuerKey, h);
    if (toHex(bindingHash) !== certificate.bindingHash) return false;
    if (!verifySignature(certificate.issuerSignature, bindingHash, issuerKey)) return false;

    const ctx = statementContext(bindingHash);
    // Each invoice's range proof must reconstruct exactly its published commitment.
    let commitmentTotal = ZERO;
    for (let i = 0; i < proof.invoices.length; i += 1) {
      const reconstructed = verifyRange(proof.invoices[i].bits, amountBitLength, ctx, i, h);
      if (!reconstructed || !reconstructed.equals(commitments[i])) return false;
      commitmentTotal = commitmentTotal.add(commitments[i]);
    }
    // Σ amounts = declared total ⇔ C_total − T·G is a pure H-multiple.
    const expectedPoint = commitmentTotal.add(scalePoint(G, declaredTotal).negate());
    return verifySumReconciliation(proof.sumReconciliation, expectedPoint, ctx, h);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Selective disclosure, openings, and Merkle inclusion
// ---------------------------------------------------------------------------

/** Builds a single-invoice amount disclosure from the operator secret. */
export function buildBatchAmountDisclosure(secret: BatchCertificateSecret, index: number): BatchAmountDisclosure {
  const invoice = requireInvoiceSecret(secret, index);
  return {
    kind: AMOUNT_DISCLOSURE_KIND,
    certificateId: secret.certificateId,
    index,
    amountBaseUnits: invoice.amountBaseUnits,
    blinding: invoice.blinding,
  };
}

/** Verifies a disclosed invoice amount against its published Pedersen commitment. */
export function verifyBatchAmountDisclosure(certificate: BatchCertificate, disclosure: BatchAmountDisclosure): boolean {
  try {
    if (disclosure.kind !== AMOUNT_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const invoice = certificate.proof.invoices[disclosure.index];
    if (!invoice) return false;
    const amount = requireBaseUnits(disclosure.amountBaseUnits, "disclosed amount");
    const blinding = requireScalar(disclosure.blinding, true);
    const h = pointFromFelts(certificate.proof.generatorH);
    const expected = pedersenCommit(amount, blinding, h);
    return expected.equals(pointFromFelts(invoice.commitment));
  } catch {
    return false;
  }
}

/** Builds a single-invoice recipient-reference disclosure from the operator secret. */
export function buildBatchRecipientDisclosure(secret: BatchCertificateSecret, index: number): BatchRecipientDisclosure {
  const invoice = requireInvoiceSecret(secret, index);
  if (!invoice.recipientCommitted) throw new Error("This invoice has no committed recipient reference to disclose.");
  return { kind: RECIPIENT_DISCLOSURE_KIND, certificateId: secret.certificateId, index, value: invoice.recipientRef, salt: invoice.recipientSalt };
}

/** Verifies a disclosed recipient reference against its published salted commitment. */
export function verifyBatchRecipientDisclosure(certificate: BatchCertificate, disclosure: BatchRecipientDisclosure): boolean {
  try {
    if (disclosure.kind !== RECIPIENT_DISCLOSURE_KIND) return false;
    if (disclosure.certificateId !== certificate.certificateId) return false;
    const invoice = certificate.proof.invoices[disclosure.index];
    if (!invoice || !invoice.recipientCommitted) return false;
    const value = requireText(disclosure.value, "disclosed recipient reference", 128);
    const salt = requireScalar(disclosure.salt, true);
    return toHex(commitRef(RECIPIENT_DOMAIN, value, salt)) === invoice.recipientCommitment;
  } catch {
    return false;
  }
}

/** Builds a full opening (every amount and blinding) for a counterparty to re-derive the batch. */
export function buildBatchOpening(secret: BatchCertificateSecret): BatchCertificateOpening {
  return { invoices: secret.invoices.map((invoice) => ({ amountBaseUnits: invoice.amountBaseUnits, blinding: invoice.blinding })) };
}

/** Verifies a full opening: every amount+blinding must reproduce every published commitment. */
export function verifyBatchOpening(certificate: BatchCertificate, opening: BatchCertificateOpening): boolean {
  try {
    if (!opening || !Array.isArray(opening.invoices)) return false;
    if (opening.invoices.length !== certificate.proof.invoices.length) return false;
    const h = pointFromFelts(certificate.proof.generatorH);
    let total = 0n;
    for (let i = 0; i < opening.invoices.length; i += 1) {
      const amount = requireBaseUnits(opening.invoices[i].amountBaseUnits, `opening ${i + 1} amount`);
      const blinding = requireScalar(opening.invoices[i].blinding, true);
      const expected = pedersenCommit(amount, blinding, h);
      if (!expected.equals(pointFromFelts(certificate.proof.invoices[i].commitment))) return false;
      total += amount;
    }
    return total === requireBaseUnits(certificate.declaredBatchTotalBaseUnits, "declared batch total");
  } catch {
    return false;
  }
}

/** Builds a compact Merkle inclusion proof that one invoice belongs to the signed batch root. */
export function buildBatchInclusionProof(certificate: BatchCertificate, index: number): BatchInclusionProof {
  const invoice = certificate.proof.invoices[index];
  if (!invoice) throw new Error("Invoice index is out of range for this batch.");
  const leaves = certificate.proof.invoices.map((entry) => requireFelt(entry.leafHash));
  return {
    kind: INCLUSION_KIND,
    certificateId: certificate.certificateId,
    index,
    merchantLabel: invoice.merchantLabel,
    invoiceRef: invoice.invoiceRef,
    recipientCommitment: invoice.recipientCommitment,
    recipientCommitted: invoice.recipientCommitted,
    commitment: invoice.commitment,
    leafHash: invoice.leafHash,
    path: merklePath(leaves, index),
  };
}

/** Verifies a Merkle inclusion proof against just the certificate's signed batch root. */
export function verifyBatchInclusionProof(certificate: BatchCertificate, inclusion: BatchInclusionProof): boolean {
  try {
    if (inclusion.kind !== INCLUSION_KIND) return false;
    if (inclusion.certificateId !== certificate.certificateId) return false;
    const commitment = pointFromFelts(inclusion.commitment);
    const recipientCommitment = requireFelt(inclusion.recipientCommitment);
    const leafHash = computeLeafHash(inclusion.index, commitment, inclusion.merchantLabel, inclusion.invoiceRef, recipientCommitment, inclusion.recipientCommitted);
    if (toHex(leafHash) !== inclusion.leafHash) return false;
    const root = foldMerklePath(leafHash, inclusion.path);
    return toHex(root) === certificate.proof.batchRoot;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Badge, trust model, and visibility model
// ---------------------------------------------------------------------------

/** Builds a compact, shareable badge with only public display fields — no secret figures. */
export function buildBatchCertificateBadge(certificate: BatchCertificate): BatchCertificateBadge {
  return {
    kind: BADGE_KIND,
    certificateId: certificate.certificateId,
    operatorAlias: certificate.operatorAlias,
    batchRef: certificate.batchRef,
    batchLabel: certificate.batchLabel,
    assetSymbol: certificate.assetSymbol,
    network: certificate.network,
    invoiceCountDisplay: formatInvoiceCount(certificate.invoiceCount),
    merchantCountDisplay: formatMerchantCount(certificate.merchantCount),
    batchTotalDisplay: `${formatBatchBaseUnits(certificate.declaredBatchTotalBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    batchRoot: certificate.proof.batchRoot,
    createdAt: certificate.createdAt,
    bindingHash: certificate.bindingHash,
    issuerPublicKey: certificate.issuerPublicKey,
  };
}

/** An honest machine-readable statement of what the engine proves — and what it does not. */
export function summarizeBatchTrust(): BatchTrustModel {
  return {
    isZeroKnowledge: true,
    provesInvoiceAmountsAreBoundedNonNegative: true,
    provesBatchSumEqualsDeclaredTotal: true,
    bindsAllInvoicesUnderOneSignedRoot: true,
    hidesIndividualInvoiceAmounts: true,
    hidesRecipientAddresses: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    isDecentralized: false,
    isAutomatic: false,
    settlesOrDisbursesFunds: false,
    settlesOnChain: false,
    movesPoolFunds: false,
    reducesOnChainGas: false,
    callsPoolContract: false,
    verifiesInvoicesAreRealOrSettled: false,
    observesRealPaymentStreams: false,
    metricsAreMeasuredOnChain: false,
    zeroKnowledgeElement:
      "A Schnorr proof on the independent generator H that C_total − T·G is a pure H-multiple proves the hidden amounts sum to the public total T without revealing any amount; per-invoice bit-decomposition range proofs bound each amount so the modular equality is an honest integer equality.",
    statement:
      "This engine issues a zero-knowledge proof that a batch of hidden per-invoice amounts are each bounded non-negative integers and together sum to one public declared batch total, folded under a single issuer-signed Merkle root. It is neither decentralized nor automatic; it does not settle, disburse, net, or move any funds; it does not reduce on-chain gas because it submits no transaction; it does not verify that any invoice is real or was settled; it does not observe real payment streams (invoices are grouped by a public merchant label); and it never reads from or writes to the STRK20 pool contract — the pool address is provenance only.",
  };
}

/** What a verifier does and does not learn from a batch certificate. */
export function getBatchVisibilityModel(): BatchVisibilityModel {
  return {
    hiddenFromVerifier: [
      "Each individual invoice amount (only a Pedersen commitment is published)",
      "Each recipient address or reference (only a salted commitment is published)",
      "The per-invoice blindings, recipient salts, and full openings",
      "Any per-merchant subtotal beyond what the operator chooses to disclose",
    ],
    disclosedToVerifier: [
      "The public declared batch total the hidden amounts are proven to sum to",
      "The invoice count and the distinct merchant count",
      "The public merchant labels and invoice references per line",
      "The issuer public key, batch root, binding hash, and creation time",
    ],
    applicationOnly: [
      "Which real-world invoices, if any, the amounts correspond to",
      "Whether any invoice was actually settled or the funds actually moved",
      "Any correlation from distinctive labels, references, or timing",
    ],
    limitation:
      "The engine never reads from or writes to the STRK20 pool contract, settles nothing, and cannot attest that any invoice is real or was settled; it reconciles operator-supplied figures and the pool address is provenance only.",
  };
}

// ---------------------------------------------------------------------------
// Serialization (compact, URL-safe base64 of canonical JSON)
// ---------------------------------------------------------------------------

/** Serializes a batch certificate to a compact, URL-safe string. */
export function serializeBatchCertificate(certificate: BatchCertificate): string {
  return encodeJson(certificate);
}

/** Parses a serialized batch certificate, validating its kind. */
export function parseBatchCertificate(encoded: string): BatchCertificate {
  const value = decodeJson<BatchCertificate>(encoded);
  if (!value || value.kind !== CERTIFICATE_KIND) throw new Error("This is not a batch certificate.");
  return value;
}

/** Serializes the SECRET issuer record. Never publish the result. */
export function serializeBatchCertificateSecret(secret: BatchCertificateSecret): string {
  return encodeJson(secret);
}

/** Parses a serialized SECRET issuer record, validating its kind. */
export function parseBatchCertificateSecret(encoded: string): BatchCertificateSecret {
  const value = decodeJson<BatchCertificateSecret>(encoded);
  if (!value || value.kind !== SECRET_KIND) throw new Error("This is not a batch certificate secret.");
  return value;
}

/** Serializes a single-invoice amount disclosure. */
export function serializeBatchAmountDisclosure(disclosure: BatchAmountDisclosure): string {
  return encodeJson(disclosure);
}

/** Parses a single-invoice amount disclosure, validating its kind. */
export function parseBatchAmountDisclosure(encoded: string): BatchAmountDisclosure {
  const value = decodeJson<BatchAmountDisclosure>(encoded);
  if (!value || value.kind !== AMOUNT_DISCLOSURE_KIND) throw new Error("This is not a batch amount disclosure.");
  return value;
}

/** Serializes a single-invoice recipient disclosure. */
export function serializeBatchRecipientDisclosure(disclosure: BatchRecipientDisclosure): string {
  return encodeJson(disclosure);
}

/** Parses a single-invoice recipient disclosure, validating its kind. */
export function parseBatchRecipientDisclosure(encoded: string): BatchRecipientDisclosure {
  const value = decodeJson<BatchRecipientDisclosure>(encoded);
  if (!value || value.kind !== RECIPIENT_DISCLOSURE_KIND) throw new Error("This is not a batch recipient disclosure.");
  return value;
}

/** Serializes a Merkle inclusion proof. */
export function serializeBatchInclusionProof(inclusion: BatchInclusionProof): string {
  return encodeJson(inclusion);
}

/** Parses a Merkle inclusion proof, validating its kind. */
export function parseBatchInclusionProof(encoded: string): BatchInclusionProof {
  const value = decodeJson<BatchInclusionProof>(encoded);
  if (!value || value.kind !== INCLUSION_KIND) throw new Error("This is not a batch inclusion proof.");
  return value;
}

// ---------------------------------------------------------------------------
// Arithmetic, hashing, and entropy helpers
// ---------------------------------------------------------------------------

/** Least non-negative residue of value modulo modulus. */
function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}

/** Modular inverse via the extended Euclidean algorithm. */
function modInverse(value: bigint, modulus: bigint): bigint {
  let [old_r, r] = [mod(value, modulus), modulus];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  if (old_r !== 1n) throw new Error("The value is not invertible modulo the curve order.");
  return mod(old_s, modulus);
}

/** Poseidon hash over a list of field elements, reduced into the field. */
function hashElements(elements: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements.map((element) => mod(element, FIELD_PRIME))));
}

/** Lowercase 0x-prefixed hex of a bigint. */
function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

/** A cryptographically random scalar in [1, n). Only used when no entropy is injected. */
function randomScalar(): bigint {
  const bytes = ec.starkCurve.utils.randomPrivateKey();
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return nonZeroScalar(mod(value, CURVE_ORDER));
}

/** Coerces a scalar into the non-zero range [1, n). */
function nonZeroScalar(value: bigint): bigint {
  const reduced = mod(value, CURVE_ORDER);
  return reduced === 0n ? 1n : reduced;
}

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`The ${label} is required.`);
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new Error(`The ${label} is required.`);
  if (trimmed.length > maxLength) throw new Error(`The ${label} must be at most ${maxLength} characters.`);
  return trimmed;
}

function requireInt(value: unknown, label: string, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n)) throw new Error(`The ${label} must be an integer.`);
  if (n < min || n > max) throw new Error(`The ${label} must be between ${min} and ${max}.`);
  return n;
}

function requireBaseUnits(value: string | bigint, label: string): bigint {
  let parsed: bigint;
  try {
    parsed = typeof value === "bigint" ? value : BigInt(String(value).trim());
  } catch {
    throw new Error(`The ${label} must be an integer number of base units.`);
  }
  if (parsed < 0n) throw new Error(`The ${label} must not be negative.`);
  return parsed;
}

function requireFelt(value: string): bigint {
  if (typeof value !== "string") throw new Error("A field element is required.");
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error("The field element is malformed.");
  }
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("The field element is out of range.");
  return parsed;
}

function requireScalar(value: string, allowZero: boolean): bigint {
  if (typeof value !== "string") throw new Error("A scalar is required.");
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error("The scalar is malformed.");
  }
  if (parsed < 0n || parsed >= CURVE_ORDER) throw new Error("The scalar is outside the Stark curve order.");
  if (!allowZero && parsed === 0n) throw new Error("The scalar must be non-zero.");
  return parsed;
}

function requireIsoTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("The timestamp is not a valid ISO-8601 value.");
  return date.toISOString();
}

/** Fetches and validates one invoice's secret opening by index. */
function requireInvoiceSecret(secret: BatchCertificateSecret, index: number): BatchInvoiceSecret {
  if (!secret || secret.kind !== SECRET_KIND || !Array.isArray(secret.invoices)) throw new Error("The batch secret is malformed.");
  const invoice = secret.invoices[index];
  if (!invoice) throw new Error("Invoice index is out of range for this batch secret.");
  return invoice;
}
// ---------------------------------------------------------------------------
// Identifiers and base64url codec
// ---------------------------------------------------------------------------

let idCounter = 0;

/** A default, collision-resistant certificate id (prefix `batch_`). */
function defaultId(kind: "certificate"): string {
  idCounter += 1;
  const rand = toHex(randomScalar()).slice(2, 12);
  return `batch_${kind}_${Date.now().toString(36)}_${idCounter}_${rand}`;
}

/** Serializes a value to a compact, URL-safe base64 string of its canonical JSON. */
function encodeJson(value: unknown): string {
  return toBase64Url(JSON.stringify(value));
}

/** Parses a base64url-encoded JSON payload, throwing a uniform error on any failure. */
function decodeJson<T>(encoded: string): T {
  try {
    return JSON.parse(fromBase64Url(encoded)) as T;
  } catch {
    throw new Error("The encoding is invalid.");
  }
}

function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(encoded: string): string {
  if (typeof encoded !== "string" || encoded.length === 0) throw new Error("The encoding is invalid.");
  if (encoded.length > MAX_ENCODED_LENGTH) throw new Error("The encoded payload is too large.");
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = typeof atob === "function" ? atob(base64) : Buffer.from(base64, "base64").toString("binary");
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
