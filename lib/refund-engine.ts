/**
 * CipherBill — Private Refund & Credit-Note Settlement Engine
 * ===========================================================
 *
 * A client-side module that lets a merchant issue a commitment-bound credit
 * note against a previously settled invoice and prove, in zero knowledge, that
 * the private refund amount `a` lies within the original invoice total `L`
 * (0 ≤ a ≤ L) WITHOUT revealing `a`. The note is sealed to a per-note claim
 * key so only the intended customer can recover the exact figure, is signed by
 * the merchant so anyone can authenticate the issuer offline, and yields a
 * per-note claim nullifier so a settlement ledger could enforce single use.
 *
 * The zero-knowledge core is a bit-decomposition range proof over Pedersen
 * commitments: each bit of `a` and of `L − a` is committed and proven to be 0
 * or 1 with a Schnorr one-of-two (OR) proof, and homomorphic sums tie the bits
 * back to the amount commitment. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK bounded-range proof. A verifier learns only "the committed
 *   refund is in [0, L]" — nothing about its value, the blinding, the customer,
 *   or the original payment path.
 * - Issuer-authenticated. A Schnorr signature over the note binding proves a
 *   specific merchant public key issued the note; anyone can check it offline.
 * - Recipient-sealed. The exact refund and blinding are masked to the note's
 *   claim key over ECDH, so only the holder of the claim secret can open them.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It does NOT settle on-chain or move any funds in the STRK20 pool. The
 *   refund and invoice figures are values the merchant supplies; the proof
 *   attests a relation over the COMMITTED refund, not custody of real notes.
 * - It does NOT read from or write to the STRK20 pool contract. The pool
 *   address below is recorded as provenance only; the engine never calls it.
 * - It does NOT itself enforce single redemption. The claim nullifier is the
 *   value a shared ledger would track; this client module keeps no ledger.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   notes and no contract or oracle vouches for the figures. `summarizeRefundTrust()`
 *   and `getRefundVisibilityModel()` state these limits verbatim.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const REFUND_ENGINE_VERSION = 1 as const;
export const REFUND_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const REFUND_PROOF_SYSTEM = "stark-pedersen-bounded-credit-v1" as const;
export const DEFAULT_REFUND_BIT_LENGTH = 128;
export const MIN_REFUND_BIT_LENGTH = 8;
export const MAX_REFUND_BIT_LENGTH = 128;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill refund generator H v1");
const NULLIFIER_DOMAIN = hash.starknetKeccak("CipherBill refund nullifier base v1");
const SEAL_DOMAIN = hash.starknetKeccak("CipherBill refund seal v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill refund statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill refund bit challenge v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill refund binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill refund issuer signature v1");
const CLAIM_DOMAIN = hash.starknetKeccak("CipherBill refund claim receipt v1");
const NOTE_KIND = "cipherbill.credit-note" as const;
const SECRET_KIND = "cipherbill.credit-note-opening" as const;
const RECEIPT_KIND = "cipherbill.credit-note-receipt" as const;
const BADGE_KIND = "cipherbill.credit-note-badge" as const;
const KEYPAIR_KIND = "cipherbill.refund-keypair" as const;
const MAX_ENCODED_LENGTH = 800_000;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface RefundAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface RefundKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer" | "claim";
  /** SECRET scalar (hex). The issuer keeps it to sign; the customer keeps it to claim. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface IssueCreditNoteInput {
  merchantAlias: string;
  asset: RefundAsset;
  /** PUBLIC free-form reference to the settled invoice this note credits. */
  invoiceRef: string;
  /** SECRET. The refund amount in integer base units. Never serialized in the note. */
  refundBaseUnits: string;
  /** PUBLIC. The original invoice total; the proof shows the refund does not exceed it. */
  invoiceCeilingBaseUnits: string;
  /** The customer's per-note claim public key (P = x·G). The note is sealed to it. */
  claimPublicKey: CurvePointFelts;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  bitLength?: number;
  memo?: string;
}

export interface RefundEntropy {
  createId?: (kind: "note") => string;
  randomScalar?: () => bigint;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface RefundBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

/** Schnorr signature (challenge, response) over the note binding by the issuer key. */
export interface IssuerSignature {
  challenge: string;
  response: string;
}

/**
 * Bounded-range proof that the committed refund `a` satisfies 0 ≤ a ≤ L.
 * `lowerBits` decompose `a` (tied to the amount commitment C); `upperBits`
 * decompose `L − a` (tied to L·G − C). Both use the canonical generator H.
 */
export interface CreditNoteProof {
  proofSystem: typeof REFUND_PROOF_SYSTEM;
  bitLength: number;
  generatorH: CurvePointFelts;
  amountCommitment: CurvePointFelts;
  lowerBits: RefundBitProof[];
  upperBits: RefundBitProof[];
}

/** A per-note DLEQ claim receipt: proves the holder owns the claim key and derives the nullifier. */
export interface ClaimReceipt {
  kind: typeof RECEIPT_KIND;
  noteId: string;
  bindingHash: string;
  nullifier: CurvePointFelts;
  commitmentG: CurvePointFelts;
  commitmentH: CurvePointFelts;
  response: string;
}

export interface CreditNote {
  kind: typeof NOTE_KIND;
  version: typeof REFUND_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  noteId: string;
  merchantAlias: string;
  invoiceRef: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** PUBLIC invoice ceiling L (base units). The refund is proven to be at most this. */
  invoiceCeilingBaseUnits: string;
  claimPublicKey: CurvePointFelts;
  issuerPublicKey: CurvePointFelts;
  /** Ephemeral ECDH public key E; the customer recovers the seal via x·E. */
  ephemeralPublicKey: CurvePointFelts;
  /** Refund and blinding masked by an ECDH-derived pad (scalar field). Not the plaintext. */
  sealedRefund: string;
  sealedBlinding: string;
  proof: CreditNoteProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}

/** SECRET issuer record of a freshly issued note. Never publish it. */
export interface CreditNoteSecret {
  kind: typeof SECRET_KIND;
  noteId: string;
  refundBaseUnits: string;
  blinding: string;
}

export interface IssuedCreditNote {
  note: CreditNote;
  secret: CreditNoteSecret;
}

/** The plaintext a customer recovers by opening a note with their claim secret. */
export interface CreditNoteOpening {
  refundBaseUnits: string;
  blinding: string;
}

export interface CreditNoteBadge {
  kind: typeof BADGE_KIND;
  noteId: string;
  merchantAlias: string;
  invoiceRef: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  invoiceCeilingDisplay: string;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface RefundTrustModel {
  isZeroKnowledge: boolean;
  provesRefundWithinInvoice: boolean;
  authenticatesIssuer: boolean;
  sealsRefundToClaimant: boolean;
  provesOnChainSettlement: boolean;
  bindsToRealFunds: boolean;
  enforcesSingleRedemption: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface RefundVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const REFUND_NOTICE =
  "Zero-knowledge bounded-range proof over a merchant-supplied refund commitment. It proves the committed refund lies in [0, invoice total] and authenticates the issuer; it does not settle on-chain, move pool funds, or enforce single redemption, and never calls the STRK20 pool contract.";

// ---------------------------------------------------------------------------
// Curve primitives
// ---------------------------------------------------------------------------

let cachedGenerator: CurvePoint | null = null;

/**
 * A second Pedersen generator H with no known discrete log relative to G.
 * Derived by hash-and-increment from a fixed domain seed (nothing-up-my-sleeve):
 * hash a counter to a field element, keep it when it is a valid x-coordinate,
 * and canonicalize to the even-y point. The STARK curve has prime order and
 * cofactor 1, so any on-curve point is a full-order generator.
 */
function independentGenerator(): CurvePoint {
  if (cachedGenerator) return cachedGenerator;
  cachedGenerator = hashToPoint([GENERATOR_DOMAIN]);
  return cachedGenerator;
}

/** Returns the canonical H as serializable felts (for embedding in a note). */
export function deriveRefundGenerator(): CurvePointFelts {
  return pointToFelts(independentGenerator());
}

/**
 * Deterministically hashes a seed to an independent curve point by
 * hash-and-increment. Used for H and for per-note nullifier bases, so the
 * discrete log relative to G is unknown by construction.
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
  throw new Error("Failed to derive an independent refund generator.");
}

/** Per-note nullifier base H_note, bound to the note's binding hash. */
function nullifierBase(bindingHash: bigint): CurvePoint {
  return hashToPoint([NULLIFIER_DOMAIN, bindingHash]);
}

/** scalar·point, tolerating a zero scalar (noble rejects multiply(0)). */
function scalePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const s = mod(scalar, CURVE_ORDER);
  return s === 0n ? ZERO : point.multiply(s);
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

function createKeypair(role: "issuer" | "claim", entropy: RefundEntropy = {}): RefundKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role, secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

/** A merchant issuing keypair. The secret signs credit notes; the public key authenticates them. */
export function createRefundIssuerKey(entropy: RefundEntropy = {}): RefundKeypair {
  return createKeypair("issuer", entropy);
}

/** A customer per-note claim keypair. Share the public key with the merchant; keep the secret to claim. */
export function createRefundClaimKey(entropy: RefundEntropy = {}): RefundKeypair {
  return createKeypair("claim", entropy);
}

// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  noteId: string;
  merchantAlias: string;
  invoiceRef: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  ceiling: bigint;
  bitLength: number;
  createdAt: string;
  memo: string;
}

/**
 * The note binding hash: a Poseidon digest over every public, proof-independent
 * field of the note. Both the range-proof challenges and the issuer signature
 * are bound to it, and the customer's claim receipt is anchored to it, so no
 * field can be altered without invalidating the note.
 */
function computeBindingHash(
  fields: BindingFields,
  claimKey: CurvePoint,
  issuerKey: CurvePoint,
  ephemeralKey: CurvePoint,
  amountCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(REFUND_ENGINE_VERSION),
    hash.starknetKeccak(fields.noteId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.invoiceRef),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    fields.ceiling,
    BigInt(fields.bitLength),
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    claimKey.x,
    claimKey.y,
    issuerKey.x,
    issuerKey.y,
    ephemeralKey.x,
    ephemeralKey.y,
    amountCommitment.x,
    amountCommitment.y,
    h.x,
    h.y,
  ]);
}

/** Context digest that seeds every range-proof challenge, bound to the note binding. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/**
 * Per-bit Fiat–Shamir challenge, bound to the context, the proof leg (0 = lower
 * decomposition of `a`, 1 = upper decomposition of `L − a`), the index, and
 * both proof nonces.
 */
function bitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

// ---------------------------------------------------------------------------
// Per-bit one-of-two (OR) proof
// ---------------------------------------------------------------------------

/**
 * Proves the commitment C = bit·G + r·H opens to 0 OR to 1, in zero knowledge.
 * Branch 0 witness proves C = r·H; branch 1 witness proves C − G = r·H. The
 * false branch is simulated (pick its challenge/response, back out its nonce);
 * the real branch is completed after the Fiat–Shamir challenge is fixed.
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
): RefundBitProof {
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

function verifyBit(proof: RefundBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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

/**
 * Builds one range-proof leg: bit-commits `value ∈ [0, 2^bitLength)` with fresh
 * per-bit blindings constrained so Σ 2^i·r_i ≡ `blinding` (mod n), then proves
 * each bit is 0/1. The homomorphic sum of the bit commitments therefore equals
 * `value·G + blinding·H`, which the verifier ties back to the target commitment.
 */
function proveRange(
  value: bigint,
  blinding: bigint,
  bitLength: number,
  ctx: bigint,
  leg: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): RefundBitProof[] {
  const bitBlindings: bigint[] = [];
  let partial = 0n;
  for (let i = 0; i < bitLength - 1; i += 1) {
    const ri = nonZeroScalar(nextScalar());
    bitBlindings.push(ri);
    partial = mod(partial + (ri % CURVE_ORDER) * mod(1n << BigInt(i), CURVE_ORDER), CURVE_ORDER);
  }
  const topWeight = modInverse(mod(1n << BigInt(bitLength - 1), CURVE_ORDER), CURVE_ORDER);
  const lastBlinding = mod((blinding - partial) * topWeight, CURVE_ORDER);
  if (lastBlinding === 0n) {
    throw new Error("Entropy produced a degenerate bit blinding; retry with fresh randomness.");
  }
  bitBlindings.push(lastBlinding);

  const proofs: RefundBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const bit = Number((value >> BigInt(i)) & 1n);
    const commitment = pedersenCommit(BigInt(bit), bitBlindings[i], h);
    proofs.push(proveBit(bit, commitment, bitBlindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies one range-proof leg and returns Σ 2^i·C_i, or null if any bit proof fails. */
function verifyRange(proofs: RefundBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
  if (!Array.isArray(proofs) || proofs.length !== bitLength) return null;
  let sum = ZERO;
  for (let i = 0; i < bitLength; i += 1) {
    const commitment = verifyBit(proofs[i], ctx, leg, i, h);
    if (!commitment) return null;
    sum = sum.add(scalePoint(commitment, 1n << BigInt(i)));
  }
  return sum;
}

// ---------------------------------------------------------------------------
// ECDH seal, issuer signature, DLEQ claim receipt
// ---------------------------------------------------------------------------

/** Derives the two ECDH pad scalars from a shared point (one for refund, one for blinding). */
function sealPads(shared: CurvePoint): { padRefund: bigint; padBlinding: bigint } {
  return {
    padRefund: mod(hashElements([SEAL_DOMAIN, shared.x, shared.y, 0n]), CURVE_ORDER),
    padBlinding: mod(hashElements([SEAL_DOMAIN, shared.x, shared.y, 1n]), CURVE_ORDER),
  };
}

/** Masks (refund, blinding) additively over the scalar field with an ECDH-derived pad. */
function sealOpening(refund: bigint, blinding: bigint, ephemeralSecret: bigint, claimKey: CurvePoint): { sealedRefund: string; sealedBlinding: string } {
  const shared = scalePoint(claimKey, ephemeralSecret);
  if (shared.equals(ZERO)) throw new Error("Degenerate ECDH shared secret; retry with fresh randomness.");
  const { padRefund, padBlinding } = sealPads(shared);
  return { sealedRefund: toHex(mod(refund + padRefund, CURVE_ORDER)), sealedBlinding: toHex(mod(blinding + padBlinding, CURVE_ORDER)) };
}

/** Recovers (refund, blinding) from a sealed note using the claim secret; null if it does not open. */
function openSeal(note: CreditNote, claimSecret: bigint, h: CurvePoint): CreditNoteOpening | null {
  const shared = scalePoint(pointFromFelts(note.ephemeralPublicKey), claimSecret);
  if (shared.equals(ZERO)) return null;
  const { padRefund, padBlinding } = sealPads(shared);
  const refund = mod(requireScalar(note.sealedRefund, true) - padRefund, CURVE_ORDER);
  const blinding = mod(requireScalar(note.sealedBlinding, true) - padBlinding, CURVE_ORDER);
  if (refund > U128_MAX) return null;
  if (blinding === 0n) return null;
  if (!pedersenCommit(refund, blinding, h).equals(pointFromFelts(note.proof.amountCommitment))) return null;
  return { refundBaseUnits: refund.toString(), blinding: toHex(blinding) };
}

/** Schnorr signature over the binding hash by the issuer key. */
function signBinding(bindingHash: bigint, issuerSecret: bigint, issuerKey: CurvePoint, nextScalar: () => bigint): IssuerSignature {
  const k = nonZeroScalar(nextScalar());
  const r = scalePoint(G, k);
  const challenge = mod(hashElements([SIGNATURE_DOMAIN, issuerKey.x, issuerKey.y, r.x, r.y, bindingHash]), CURVE_ORDER);
  const response = mod(k + challenge * issuerSecret, CURVE_ORDER);
  return { challenge: toHex(challenge), response: toHex(response) };
}

function verifySignature(bindingHash: bigint, issuerKey: CurvePoint, signature: IssuerSignature): boolean {
  const challenge = requireScalar(signature.challenge, true);
  const response = requireScalar(signature.response, true);
  const r = scalePoint(G, response).add(scalePoint(issuerKey, challenge).negate());
  const recomputed = mod(hashElements([SIGNATURE_DOMAIN, issuerKey.x, issuerKey.y, r.x, r.y, bindingHash]), CURVE_ORDER);
  return recomputed === challenge;
}

/**
 * Builds a claim receipt: a Chaum–Pedersen proof that the holder knows the
 * claim secret x (with P = x·G) and that the nullifier N = x·H_note is derived
 * from the same x. Reveals N (unlinkable to P without this proof) so a ledger
 * could mark the note redeemed, without exposing x.
 */
export function buildClaimReceipt(note: CreditNote, claimSecretKey: string, entropy: RefundEntropy = {}): ClaimReceipt {
  const claimSecret = requireScalar(claimSecretKey, false);
  const h = independentGenerator();
  const bindingHash = bindingHashForNote(note, h);
  const claimKey = pointFromFelts(note.claimPublicKey);
  if (!publicKeyFromSecret(claimSecret).equals(claimKey)) {
    throw new Error("Claim secret does not match the note's claim key.");
  }
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const hNote = nullifierBase(bindingHash);
  const nullifier = scalePoint(hNote, claimSecret);
  const k = nonZeroScalar(nextScalar());
  const t1 = scalePoint(G, k);
  const t2 = scalePoint(hNote, k);
  const challenge = mod(
    hashElements([CLAIM_DOMAIN, bindingHash, claimKey.x, claimKey.y, nullifier.x, nullifier.y, t1.x, t1.y, t2.x, t2.y]),
    CURVE_ORDER,
  );
  const response = mod(k + challenge * claimSecret, CURVE_ORDER);
  return {
    kind: RECEIPT_KIND,
    noteId: note.noteId,
    bindingHash: toHex(bindingHash),
    nullifier: pointToFelts(nullifier),
    commitmentG: pointToFelts(t1),
    commitmentH: pointToFelts(t2),
    response: toHex(response),
  };
}

export function verifyClaimReceipt(note: CreditNote, receipt: ClaimReceipt): boolean {
  try {
    if (!receipt || receipt.kind !== RECEIPT_KIND || receipt.noteId !== note.noteId) return false;
    const h = independentGenerator();
    const bindingHash = bindingHashForNote(note, h);
    if (receipt.bindingHash !== toHex(bindingHash)) return false;
    const claimKey = pointFromFelts(note.claimPublicKey);
    const nullifier = pointFromFelts(receipt.nullifier);
    const t1 = pointFromFelts(receipt.commitmentG);
    const t2 = pointFromFelts(receipt.commitmentH);
    const response = requireScalar(receipt.response, true);
    const hNote = nullifierBase(bindingHash);
    const challenge = mod(
      hashElements([CLAIM_DOMAIN, bindingHash, claimKey.x, claimKey.y, nullifier.x, nullifier.y, t1.x, t1.y, t2.x, t2.y]),
      CURVE_ORDER,
    );
    const okG = scalePoint(G, response).equals(t1.add(scalePoint(claimKey, challenge)));
    const okH = scalePoint(hNote, response).equals(t2.add(scalePoint(nullifier, challenge)));
    return okG && okH;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Issue, verify, open
// ---------------------------------------------------------------------------

/** Recomputes the binding hash from a note's public fields (used by verify and claim). */
function bindingHashForNote(note: CreditNote, h: CurvePoint): bigint {
  const fields: BindingFields = {
    noteId: note.noteId,
    merchantAlias: note.merchantAlias,
    invoiceRef: note.invoiceRef,
    assetSymbol: note.assetSymbol,
    tokenAddress: note.tokenAddress,
    assetDecimals: note.assetDecimals,
    ceiling: requireBaseUnits(note.invoiceCeilingBaseUnits, "invoice ceiling"),
    bitLength: note.proof.bitLength,
    createdAt: note.createdAt,
    memo: note.memo,
  };
  return computeBindingHash(
    fields,
    pointFromFelts(note.claimPublicKey),
    pointFromFelts(note.issuerPublicKey),
    pointFromFelts(note.ephemeralPublicKey),
    pointFromFelts(note.proof.amountCommitment),
    h,
  );
}

/**
 * Issues a credit note: commits the private refund, seals the opening to the
 * customer's claim key, proves 0 ≤ refund ≤ invoice total in zero knowledge,
 * and signs the binding as the merchant. Returns the publishable note and the
 * secret opening the issuer retains (never publish the secret).
 */
export function issueCreditNote(
  input: IssueCreditNoteInput,
  now: Date = new Date(),
  entropy: RefundEntropy = {},
): IssuedCreditNote {
  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 80);
  const invoiceRef = requireText(input.invoiceRef, "invoice reference", 120);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress ?? "");
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 18);
  const memo = typeof input.memo === "string" && input.memo.trim() ? requireText(input.memo, "memo", 200) : "";
  const bitLength =
    input.bitLength === undefined
      ? DEFAULT_REFUND_BIT_LENGTH
      : requireInt(input.bitLength, "bit length", MIN_REFUND_BIT_LENGTH, MAX_REFUND_BIT_LENGTH);

  const refund = requireBaseUnits(input.refundBaseUnits, "refund amount");
  const ceiling = requireBaseUnits(input.invoiceCeilingBaseUnits, "invoice ceiling");
  if (refund > U128_MAX || ceiling > U128_MAX) throw new Error("Amounts must fit within the u128 range.");
  if (refund > ceiling) throw new Error("The refund exceeds the invoice total it credits.");
  if (ceiling >= 1n << BigInt(bitLength)) throw new Error(`The invoice total exceeds the provable ${bitLength}-bit band.`);

  const claimKey = pointFromFelts(input.claimPublicKey);
  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);

  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;
  const noteId = requireText(createId("note"), "note id", 120);
  const createdAt = now.toISOString();

  const h = independentGenerator();
  const blinding = nonZeroScalar(nextScalar());
  const amountCommitment = pedersenCommit(refund, blinding, h);

  // Ephemeral ECDH keypair; seal the exact opening to the customer's claim key.
  const ephemeralSecret = nonZeroScalar(nextScalar());
  const ephemeralKey = publicKeyFromSecret(ephemeralSecret);
  const sealed = sealOpening(refund, blinding, ephemeralSecret, claimKey);

  const fields: BindingFields = { noteId, merchantAlias, invoiceRef, assetSymbol, tokenAddress, assetDecimals, ceiling, bitLength, createdAt, memo };
  const bindingHash = computeBindingHash(fields, claimKey, issuerKey, ephemeralKey, amountCommitment, h);
  const ctx = statementContext(bindingHash);

  // Lower leg: decompose the refund; its bit blindings sum to `blinding`, so
  // Σ 2^i·C_i == amountCommitment. Upper leg: decompose (ceiling − refund) with
  // blindings summing to −blinding, so Σ 2^i·C_i == ceiling·G − amountCommitment.
  const lowerBits = proveRange(refund, blinding, bitLength, ctx, 0, h, nextScalar);
  const upperBits = proveRange(ceiling - refund, mod(-blinding, CURVE_ORDER), bitLength, ctx, 1, h, nextScalar);
  const issuerSignature = signBinding(bindingHash, issuerSecret, issuerKey, nextScalar);

  const note: CreditNote = {
    kind: NOTE_KIND,
    version: REFUND_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    noteId,
    merchantAlias,
    invoiceRef,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    invoiceCeilingBaseUnits: ceiling.toString(),
    claimPublicKey: pointToFelts(claimKey),
    issuerPublicKey: pointToFelts(issuerKey),
    ephemeralPublicKey: pointToFelts(ephemeralKey),
    sealedRefund: sealed.sealedRefund,
    sealedBlinding: sealed.sealedBlinding,
    proof: {
      proofSystem: REFUND_PROOF_SYSTEM,
      bitLength,
      generatorH: pointToFelts(h),
      amountCommitment: pointToFelts(amountCommitment),
      lowerBits,
      upperBits,
    },
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: REFUND_NOTICE,
  };
  const secret: CreditNoteSecret = { kind: SECRET_KIND, noteId, refundBaseUnits: refund.toString(), blinding: toHex(blinding) };
  return { note, secret };
}

/** Verifies a credit note offline: canonical H, binding, issuer signature, and both range legs. */
export function verifyCreditNote(note: CreditNote): boolean {
  try {
    if (!note || note.kind !== NOTE_KIND || note.version !== REFUND_ENGINE_VERSION) return false;
    if (note.proof?.proofSystem !== REFUND_PROOF_SYSTEM) return false;
    const bitLength = note.proof.bitLength;
    if (!Number.isInteger(bitLength) || bitLength < MIN_REFUND_BIT_LENGTH || bitLength > MAX_REFUND_BIT_LENGTH) return false;

    // Recompute the canonical generator; reject a prover-substituted H.
    const h = independentGenerator();
    if (note.proof.generatorH.x !== toHex(h.x) || note.proof.generatorH.y !== toHex(h.y)) return false;

    const ceiling = requireBaseUnits(note.invoiceCeilingBaseUnits, "invoice ceiling");
    if (ceiling > U128_MAX || ceiling >= 1n << BigInt(bitLength)) return false;

    const amountCommitment = pointFromFelts(note.proof.amountCommitment);

    // Recompute and match the binding over every public field.
    const bindingHash = bindingHashForNote(note, h);
    if (note.bindingHash !== toHex(bindingHash)) return false;

    // Authenticate the issuer over that binding.
    if (!verifySignature(bindingHash, pointFromFelts(note.issuerPublicKey), note.issuerSignature)) return false;

    const ctx = statementContext(bindingHash);
    // Lower leg ties to the amount commitment; upper leg to ceiling·G − commitment.
    const lowerSum = verifyRange(note.proof.lowerBits, bitLength, ctx, 0, h);
    if (!lowerSum || !lowerSum.equals(amountCommitment)) return false;
    const upperSum = verifyRange(note.proof.upperBits, bitLength, ctx, 1, h);
    if (!upperSum) return false;
    return upperSum.equals(scalePoint(G, ceiling).add(amountCommitment.negate()));
  } catch {
    return false;
  }
}

/** Recovers the exact refund and blinding with the customer's claim secret; null if it does not open. */
export function openCreditNote(note: CreditNote, claimSecretKey: string): CreditNoteOpening | null {
  try {
    const claimSecret = requireScalar(claimSecretKey, false);
    return openSeal(note, claimSecret, independentGenerator());
  } catch {
    return null;
  }
}

/** Confirms a claimed (refund, blinding) opens the note's amount commitment. */
export function verifyCreditNoteOpening(note: CreditNote, opening: CreditNoteOpening): boolean {
  try {
    const refund = requireBaseUnits(opening.refundBaseUnits, "refund amount");
    const blinding = requireScalar(opening.blinding, false);
    if (refund > U128_MAX) return false;
    return pedersenCommit(refund, blinding, independentGenerator()).equals(pointFromFelts(note.proof.amountCommitment));
  } catch {
    return false;
  }
}

/** Condenses a note into a shareable, verifier-facing badge (no secret material). */
export function buildCreditNoteBadge(note: CreditNote): CreditNoteBadge {
  return {
    kind: BADGE_KIND,
    noteId: note.noteId,
    merchantAlias: note.merchantAlias,
    invoiceRef: note.invoiceRef,
    assetSymbol: note.assetSymbol,
    network: note.network,
    invoiceCeilingDisplay: formatRefundBaseUnits(note.invoiceCeilingBaseUnits, note.assetDecimals),
    createdAt: note.createdAt,
    bindingHash: note.bindingHash,
    issuerPublicKey: note.issuerPublicKey,
  };
}

// ---------------------------------------------------------------------------
// Honest trust & visibility model
// ---------------------------------------------------------------------------

export function formatRefundBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}

export function summarizeRefundTrust(): RefundTrustModel {
  return {
    isZeroKnowledge: true,
    provesRefundWithinInvoice: true,
    authenticatesIssuer: true,
    sealsRefundToClaimant: true,
    provesOnChainSettlement: false,
    bindsToRealFunds: false,
    enforcesSingleRedemption: false,
    isDecentralized: false,
    isAutomatic: false,
    zeroKnowledgeElement:
      "The refund amount and its blinding — proven to lie in [0, invoice total] without disclosure.",
    statement:
      "This engine produces a genuine zero-knowledge proof that a committed refund does not exceed the invoice it credits, and authenticates the issuing merchant. It is neither decentralized nor automatic: a single merchant key issues notes, with no contract or oracle vouching for the figures. It does not settle on-chain, does not move or bind to real pool funds, and does not itself enforce single redemption — the claim nullifier is the value an external ledger would track. It never reads from or writes to the STRK20 pool contract.",
  };
}

export function getRefundVisibilityModel(): RefundVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The exact refund amount and its Pedersen blinding.",
      "The customer's identity and the original private payment path.",
      "Any link between this note and other refunds the merchant has issued.",
    ],
    disclosedToVerifier: [
      "The public invoice ceiling the refund is proven not to exceed.",
      "The merchant's issuing public key and a signature authenticating the note.",
      "The proof system, bit range, commitments, and the note binding hash.",
    ],
    applicationOnly: [
      "Merchant alias, invoice reference, asset, and optional memo carried as plaintext metadata.",
      "Timing of issuance and correlation risk from distinctive invoice references or amounts.",
    ],
    limitation:
      "The engine never reads from or writes to the STRK20 pool contract. It proves a relation over a merchant-supplied commitment, not custody of real funds, and does not settle on-chain or enforce single redemption on its own.",
  };
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

export function serializeCreditNote(note: CreditNote): string {
  return toBase64Url(encodeJson(note));
}

export function serializeCreditNoteSecret(secret: CreditNoteSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function serializeClaimReceipt(receipt: ClaimReceipt): string {
  return toBase64Url(encodeJson(receipt));
}

function parsePoint(value: unknown): CurvePointFelts {
  if (!value || typeof value !== "object") throw new Error("A curve point is malformed.");
  const point = value as { x?: unknown; y?: unknown };
  if (typeof point.x !== "string" || typeof point.y !== "string") throw new Error("A curve point is malformed.");
  return pointToFelts(pointFromFelts({ x: point.x, y: point.y }));
}

function parseBitProof(value: unknown): RefundBitProof {
  if (!value || typeof value !== "object") throw new Error("A bit proof is malformed.");
  const b = value as Record<string, unknown>;
  return {
    commitment: parsePoint(b.commitment),
    a0: parsePoint(b.a0),
    a1: parsePoint(b.a1),
    challenge0: toHex(requireScalar(b.challenge0, true)),
    response0: toHex(requireScalar(b.response0, true)),
    response1: toHex(requireScalar(b.response1, true)),
  };
}

function parseSignature(value: unknown): IssuerSignature {
  if (!value || typeof value !== "object") throw new Error("The issuer signature is malformed.");
  const s = value as Record<string, unknown>;
  return { challenge: toHex(requireScalar(s.challenge, true)), response: toHex(requireScalar(s.response, true)) };
}

function parseProof(value: unknown): CreditNoteProof {
  if (!value || typeof value !== "object") throw new Error("The proof is malformed.");
  const p = value as Record<string, unknown>;
  if (p.proofSystem !== REFUND_PROOF_SYSTEM) throw new Error("Unsupported refund proof system.");
  const bitLength = requireInt(p.bitLength, "bit length", MIN_REFUND_BIT_LENGTH, MAX_REFUND_BIT_LENGTH);
  if (!Array.isArray(p.lowerBits) || !Array.isArray(p.upperBits)) throw new Error("The proof legs are malformed.");
  return {
    proofSystem: REFUND_PROOF_SYSTEM,
    bitLength,
    generatorH: parsePoint(p.generatorH),
    amountCommitment: parsePoint(p.amountCommitment),
    lowerBits: p.lowerBits.map(parseBitProof),
    upperBits: p.upperBits.map(parseBitProof),
  };
}

export function parseCreditNote(encoded: string): CreditNote {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object") throw new Error("The credit note is malformed.");
  if (raw.kind !== NOTE_KIND) throw new Error("This is not a CipherBill credit note.");
  if (raw.version !== REFUND_ENGINE_VERSION) throw new Error("Unsupported credit note version.");
  return {
    kind: NOTE_KIND,
    version: REFUND_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    noteId: requireText(raw.noteId, "note id", 120),
    merchantAlias: requireText(raw.merchantAlias, "merchant alias", 80),
    invoiceRef: requireText(raw.invoiceRef, "invoice reference", 120),
    assetSymbol: requireText(raw.assetSymbol, "asset symbol", 16),
    tokenAddress: normalizeStarknetAddress(typeof raw.tokenAddress === "string" ? raw.tokenAddress : ""),
    assetDecimals: requireInt(raw.assetDecimals, "asset decimals", 0, 18),
    invoiceCeilingBaseUnits: requireBaseUnits(raw.invoiceCeilingBaseUnits, "invoice ceiling").toString(),
    claimPublicKey: parsePoint(raw.claimPublicKey),
    issuerPublicKey: parsePoint(raw.issuerPublicKey),
    ephemeralPublicKey: parsePoint(raw.ephemeralPublicKey),
    sealedRefund: toHex(requireScalar(raw.sealedRefund, true)),
    sealedBlinding: toHex(requireScalar(raw.sealedBlinding, true)),
    proof: parseProof(raw.proof),
    issuerSignature: parseSignature(raw.issuerSignature),
    bindingHash: toHex(requireFelt(raw.bindingHash, "binding hash")),
    createdAt: requireIsoTimestamp(raw.createdAt),
    memo: typeof raw.memo === "string" ? raw.memo : "",
    notice: typeof raw.notice === "string" ? raw.notice : REFUND_NOTICE,
  };
}

export function parseCreditNoteSecret(encoded: string): CreditNoteSecret {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object" || raw.kind !== SECRET_KIND) throw new Error("This is not a credit-note opening.");
  return {
    kind: SECRET_KIND,
    noteId: requireText(raw.noteId, "note id", 120),
    refundBaseUnits: requireBaseUnits(raw.refundBaseUnits, "refund amount").toString(),
    blinding: toHex(requireScalar(raw.blinding, false)),
  };
}

export function parseClaimReceipt(encoded: string): ClaimReceipt {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object" || raw.kind !== RECEIPT_KIND) throw new Error("This is not a claim receipt.");
  return {
    kind: RECEIPT_KIND,
    noteId: requireText(raw.noteId, "note id", 120),
    bindingHash: toHex(requireFelt(raw.bindingHash, "binding hash")),
    nullifier: parsePoint(raw.nullifier),
    commitmentG: parsePoint(raw.commitmentG),
    commitmentH: parsePoint(raw.commitmentH),
    response: toHex(requireScalar(raw.response, true)),
  };
}

// ---------------------------------------------------------------------------
// Field arithmetic, hashing, entropy, validators, encoding
// ---------------------------------------------------------------------------

function mod(value: bigint, modulus: bigint): bigint {
  const r = value % modulus;
  return r < 0n ? r + modulus : r;
}

/** Extended-Euclid modular inverse; throws if `value` is not invertible mod `modulus`. */
function modInverse(value: bigint, modulus: bigint): bigint {
  let [oldR, r] = [mod(value, modulus), modulus];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error("Value is not invertible modulo the group order.");
  return mod(oldS, modulus);
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function hashElements(elements: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(elements));
}

/** A uniformly random scalar in [0, n) drawn from the curve's CSPRNG. */
function randomScalar(): bigint {
  let acc = 0n;
  for (const byte of ec.starkCurve.utils.randomPrivateKey()) acc = (acc << 8n) | BigInt(byte);
  return mod(acc, CURVE_ORDER);
}

/** Maps any scalar into [1, n) so it is safe as a blinding, nonce, or key. */
function nonZeroScalar(value: bigint): bigint {
  return mod(value, CURVE_ORDER - 1n) + 1n;
}

function requireText(value: unknown, label: string, max: number): string {
  if (typeof value !== "string") throw new Error(`The ${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`The ${label} is required.`);
  if (trimmed.length > max) throw new Error(`The ${label} is too long (max ${max} characters).`);
  return trimmed;
}

function requireInt(value: unknown, label: string, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`The ${label} must be an integer in [${min}, ${max}].`);
  return n;
}

function requireBaseUnits(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw new Error(`The ${label} must be an integer number of base units.`);
  }
  return BigInt(value);
}

function requireFelt(value: unknown, label = "curve coordinate"): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new Error(`The ${label} is malformed.`);
  const n = BigInt(value);
  if (n < 0n || n >= FIELD_PRIME) throw new Error(`The ${label} is out of range.`);
  return n;
}

function requireScalar(value: unknown, allowZero: boolean): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new Error("A scalar value is malformed.");
  const n = BigInt(value);
  if (n < 0n || n >= CURVE_ORDER) throw new Error("A scalar value is out of range.");
  if (!allowZero && n === 0n) throw new Error("A scalar value must be non-zero.");
  return n;
}

function requireIsoTimestamp(value: unknown): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) throw new Error("The timestamp is malformed.");
  return value;
}
/** A collision-resistant default note id; deterministic ids can be injected via entropy.createId. */
function defaultId(): string {
  const rand =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID().replace(/-/g, "").slice(0, 20)
      : `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 12)}`;
  return `cn_${rand}`;
}

function encodeJson(value: unknown): string {
  return JSON.stringify(value);
}

function decodeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The payload is not valid JSON.");
  }
}

function toBase64Url(text: string): string {
  const base64 =
    typeof Buffer !== "undefined"
      ? Buffer.from(text, "utf8").toString("base64")
      : btoa(String.fromCharCode(...new TextEncoder().encode(text)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(encoded: string): string {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error("The credit note encoding is invalid.");
  }
  if (encoded.length > MAX_ENCODED_LENGTH) throw new Error("The credit note payload is too large to decode.");
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  return typeof Buffer !== "undefined"
    ? Buffer.from(base64, "base64").toString("utf8")
    : new TextDecoder().decode(Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)));
}
