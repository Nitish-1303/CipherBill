/**
 * CipherBill — Merchant Proof-of-Reserves Attestation Engine
 * ==========================================================
 *
 * A client-side module that produces a genuine non-interactive zero-knowledge
 * range proof over a Pedersen commitment: it proves that a committed reserve
 * figure R satisfies  T ≤ R < T + 2^bitLength  for a public threshold T,
 * WITHOUT revealing R. The construction is a bit-decomposition range proof —
 * each bit of (R − T) is committed and proven to be 0 or 1 with a Schnorr
 * one-of-two (OR) proof, and a homomorphic sum ties the bits back to the
 * reserve commitment. Fiat–Shamir makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK range proof. A verifier learns only "R is in the band
 *   [T, T + 2^bitLength)" and nothing else about R, the blinding, or any
 *   underlying transaction history.
 * - Fully self-contained and offline. Anyone can verify an attestation with
 *   this module and the public statement; no wallet, RPC, or contract call.
 * - Binding: once published, the reserve commitment fixes R (the second
 *   generator H is a nothing-up-my-sleeve point with no known discrete log
 *   relative to the base point G, so the commitment cannot be reopened).
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It is NOT proof of on-chain custody. The reserve figure R is a value the
 *   merchant supplies. The proof attests a relation over that COMMITTED number;
 *   it does not, and cannot, demonstrate that the merchant actually holds R in
 *   the STRK20 pool. Proving ownership of specific unspent notes would require
 *   the merchant's viewing key and live pool state — deliberately out of scope
 *   for a client module that touches no keys.
 * - It does NOT read from or write to the STRK20 pool contract. The pool
 *   address below is recorded as provenance only; the engine never calls it.
 * - It is neither decentralized nor automatic. No contract verifies it and no
 *   oracle vouches for the input figure. `summarizeReservesTrust()` and
 *   `getReservesVisibilityModel()` state these limits verbatim.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const RESERVES_ENGINE_VERSION = 1 as const;
export const RESERVES_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const RESERVES_PROOF_SYSTEM = "stark-pedersen-bit-range-v1" as const;
export const DEFAULT_RESERVES_BIT_LENGTH = 128;
export const MIN_RESERVES_BIT_LENGTH = 8;
export const MAX_RESERVES_BIT_LENGTH = 128;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill reserves generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill reserves statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill reserves bit challenge v1");
const STATEMENT_DOMAIN = hash.starknetKeccak("CipherBill reserves commitment v1");
const ATTESTATION_KIND = "cipherbill.reserves-attestation" as const;
const OPENING_KIND = "cipherbill.reserves-opening" as const;
const BADGE_KIND = "cipherbill.reserves-badge" as const;
const MAX_ENCODED_LENGTH = 400_000;

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface ReservesAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface ReservesLiability {
  label: string;
  amountBaseUnits: string;
}

export interface BuildReservesAttestationInput {
  merchantAlias: string;
  asset: ReservesAsset;
  /** SECRET. The merchant's asserted reserve total in integer base units. Never serialized. */
  reserveBaseUnits: string;
  /** PUBLIC. The minimum the proof attests the reserve meets, in integer base units. */
  thresholdBaseUnits: string;
  /** Optional public liability breakdown; when present its sum must equal the threshold. */
  liabilities?: ReservesLiability[];
  bitLength?: number;
  memo?: string;
}

export interface ReservesEntropy {
  createId?: (kind: "attestation") => string;
  randomScalar?: () => bigint;
}

/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface ReservesBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

export interface ReservesRangeProof {
  proofSystem: typeof RESERVES_PROOF_SYSTEM;
  bitLength: number;
  generatorH: CurvePointFelts;
  reserveCommitment: CurvePointFelts;
  bitProofs: ReservesBitProof[];
}

export interface ReservesAttestation {
  kind: typeof ATTESTATION_KIND;
  version: typeof RESERVES_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  attestationId: string;
  merchantAlias: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  /** Public threshold T (base units). The proof shows the committed reserve is at least this. */
  thresholdBaseUnits: string;
  /** Exact upper edge proven: T + 2^bitLength (base units). */
  bandExclusiveMaxBaseUnits: string;
  liabilities: ReservesLiability[];
  memo: string;
  createdAt: string;
  proof: ReservesRangeProof;
  statementCommitment: string;
  notice: string;
}

/** SECRET bearer material returned with a freshly built attestation. Never publish it. */
export interface ReservesSecret {
  kind: typeof OPENING_KIND;
  attestationId: string;
  reserveBaseUnits: string;
  blinding: string;
}

export interface BuiltReservesAttestation {
  attestation: ReservesAttestation;
  secret: ReservesSecret;
}

export interface ReservesBadge {
  kind: typeof BADGE_KIND;
  attestationId: string;
  merchantAlias: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  thresholdDisplay: string;
  bandExclusiveMaxDisplay: string;
  createdAt: string;
  statementCommitment: string;
}

export interface ReservesTrustModel {
  isZeroKnowledge: boolean;
  provesThresholdRelation: boolean;
  provesReserveBand: boolean;
  provesOnChainCustody: boolean;
  bindsToRealFunds: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface ReservesVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const RESERVES_NOTICE =
  "Zero-knowledge range proof over a merchant-supplied reserve commitment. It proves the committed figure lies in the stated band; it does not prove on-chain custody and never calls the STRK20 pool contract.";

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
  for (let counter = 0n; counter < 1000n; counter += 1n) {
    const x = mod(hashElements([GENERATOR_DOMAIN, counter]), FIELD_PRIME);
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
      cachedGenerator = point;
      return point;
    } catch {
      continue;
    }
  }
  throw new Error("Failed to derive an independent reserves generator.");
}

/** Returns the canonical H as serializable felts (for embedding in an attestation). */
export function deriveReservesGenerator(): CurvePointFelts {
  return pointToFelts(independentGenerator());
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

// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface StatementFields {
  tokenAddress: string;
  assetDecimals: number;
  assetSymbol: string;
  merchantAlias: string;
  attestationId: string;
  bitLength: number;
  threshold: bigint;
}

/** Context digest binding the statement (asset, parties, threshold, H, C_R) into every challenge. */
function statementContext(fields: StatementFields, h: CurvePoint, reserveCommitment: CurvePoint): bigint {
  return hashElements([
    CONTEXT_DOMAIN,
    BigInt(RESERVES_ENGINE_VERSION),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    hash.starknetKeccak(fields.assetSymbol),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.attestationId),
    BigInt(fields.bitLength),
    fields.threshold,
    h.x,
    h.y,
    reserveCommitment.x,
    reserveCommitment.y,
  ]);
}

/** Per-bit Fiat–Shamir challenge, bound to the context and both proof nonces. */
function bitChallenge(ctx: bigint, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

/** Integrity digest over the whole attestation; recomputed on verify to catch tampering. */
function computeStatementCommitment(attestation: ReservesAttestation, ctx: bigint): string {
  const proofFelts: bigint[] = [];
  for (const bit of attestation.proof.bitProofs) {
    proofFelts.push(
      requireFelt(bit.commitment.x),
      requireFelt(bit.commitment.y),
      requireFelt(bit.a0.x),
      requireFelt(bit.a0.y),
      requireFelt(bit.a1.x),
      requireFelt(bit.a1.y),
      requireScalar(bit.challenge0, true),
      requireScalar(bit.response0, true),
      requireScalar(bit.response1, true),
    );
  }
  const liabilityFelts: bigint[] = [];
  for (const item of attestation.liabilities) {
    liabilityFelts.push(hash.starknetKeccak(item.label), BigInt(item.amountBaseUnits));
  }
  return toHex(
    hashElements([
      STATEMENT_DOMAIN,
      ctx,
      BigInt(attestation.bandExclusiveMaxBaseUnits),
      hash.starknetKeccak(attestation.createdAt),
      hash.starknetKeccak(attestation.memo || "-"),
      BigInt(attestation.liabilities.length),
      hashElements(liabilityFelts.length ? liabilityFelts : [0n]),
      hashElements(proofFelts),
    ]),
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
  index: number,
  h: CurvePoint,
  nextScalar: () => bigint,
): ReservesBitProof {
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
    const e = bitChallenge(ctx, index, commitment, a0, a1);
    challenge0 = mod(e - e1, CURVE_ORDER);
    response0 = mod(k0 + challenge0 * blinding, CURVE_ORDER);
    response1 = s1;
  } else {
    const k1 = nonZeroScalar(nextScalar());
    a1 = scalePoint(h, k1);
    challenge0 = nonZeroScalar(nextScalar());
    response0 = nonZeroScalar(nextScalar());
    a0 = scalePoint(h, response0).add(scalePoint(p0, challenge0).negate());
    const e = bitChallenge(ctx, index, commitment, a0, a1);
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

function verifyBit(proof: ReservesBitProof, ctx: bigint, index: number, h: CurvePoint): CurvePoint | null {
  const commitment = pointFromFelts(proof.commitment);
  const a0 = pointFromFelts(proof.a0);
  const a1 = pointFromFelts(proof.a1);
  const challenge0 = requireScalar(proof.challenge0, true);
  const response0 = requireScalar(proof.response0, true);
  const response1 = requireScalar(proof.response1, true);
  const e = bitChallenge(ctx, index, commitment, a0, a1);
  const challenge1 = mod(e - challenge0, CURVE_ORDER);
  const p0 = commitment;
  const p1 = commitment.add(G.negate());
  const ok0 = scalePoint(h, response0).equals(a0.add(scalePoint(p0, challenge0)));
  const ok1 = scalePoint(h, response1).equals(a1.add(scalePoint(p1, challenge1)));
  return ok0 && ok1 ? commitment : null;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

export function buildReservesAttestation(
  input: BuildReservesAttestationInput,
  now: Date = new Date(),
  entropy: ReservesEntropy = {},
): BuiltReservesAttestation {
  const merchantAlias = requireText(input.merchantAlias, "Merchant alias", 80);
  const asset = normalizeAsset(input.asset);
  const bitLength = normalizeBitLength(input.bitLength);
  const memo = input.memo === undefined ? "" : requireText(input.memo, "Memo", 200);
  const reserve = requireBaseUnits(input.reserveBaseUnits, "Reserve total");
  const threshold = requireBaseUnits(input.thresholdBaseUnits, "Threshold");
  const liabilities = normalizeLiabilities(input.liabilities, threshold);
  const createdAt = requireIsoTimestamp(now.toISOString(), "Attestation timestamp");

  const band = 1n << BigInt(bitLength);
  const delta = reserve - threshold;
  if (delta < 0n) {
    throw new Error("Reserve total is below the threshold; no proof-of-reserves attestation can be produced.");
  }
  if (delta >= band) {
    throw new Error("Reserve exceeds the provable band for the chosen bit length.");
  }

  const nextScalar = entropy.randomScalar ?? randomScalar;
  const attestationId = requireText(entropy.createId?.("attestation") ?? defaultId(), "Attestation id", 64);
  const h = independentGenerator();

  const blinding = nonZeroScalar(nextScalar());
  const reserveCommitment = pedersenCommit(reserve, blinding, h);

  // Per-bit blindings constrained so Σ 2^i·r_i ≡ blinding (mod n): the last is solved for.
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

  const ctxFields: StatementFields = {
    tokenAddress: asset.tokenAddress,
    assetDecimals: asset.decimals,
    assetSymbol: asset.symbol,
    merchantAlias,
    attestationId,
    bitLength,
    threshold,
  };
  const ctx = statementContext(ctxFields, h, reserveCommitment);

  const bitProofs: ReservesBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const bit = Number((delta >> BigInt(i)) & 1n);
    const commitment = pedersenCommit(BigInt(bit), bitBlindings[i], h);
    bitProofs.push(proveBit(bit, commitment, bitBlindings[i], ctx, i, h, nextScalar));
  }

  const attestation: ReservesAttestation = {
    kind: ATTESTATION_KIND,
    version: RESERVES_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    attestationId,
    merchantAlias,
    assetSymbol: asset.symbol,
    tokenAddress: asset.tokenAddress,
    assetDecimals: asset.decimals,
    thresholdBaseUnits: threshold.toString(),
    bandExclusiveMaxBaseUnits: (threshold + band).toString(),
    liabilities,
    memo,
    createdAt,
    proof: {
      proofSystem: RESERVES_PROOF_SYSTEM,
      bitLength,
      generatorH: pointToFelts(h),
      reserveCommitment: pointToFelts(reserveCommitment),
      bitProofs,
    },
    statementCommitment: "0x0",
    notice: RESERVES_NOTICE,
  };
  attestation.statementCommitment = computeStatementCommitment(attestation, ctx);

  const secret: ReservesSecret = {
    kind: OPENING_KIND,
    attestationId,
    reserveBaseUnits: reserve.toString(),
    blinding: toHex(blinding),
  };

  return { attestation, secret };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export function verifyReservesAttestation(attestation: ReservesAttestation): boolean {
  try {
    if (
      !attestation ||
      attestation.kind !== ATTESTATION_KIND ||
      attestation.version !== RESERVES_ENGINE_VERSION ||
      attestation.network !== MAINNET_CHAIN_ID ||
      attestation.poolAddress !== STRK20_POOL_ADDRESS
    ) {
      return false;
    }
    const proof = attestation.proof;
    if (!proof || proof.proofSystem !== RESERVES_PROOF_SYSTEM) return false;
    const bitLength = proof.bitLength;
    if (!isValidBitLength(bitLength) || !Array.isArray(proof.bitProofs) || proof.bitProofs.length !== bitLength) {
      return false;
    }

    // The verifier must use the canonical H, never a prover-chosen one.
    const h = independentGenerator();
    if (!pointFromFelts(proof.generatorH).equals(h)) return false;
    const reserveCommitment = pointFromFelts(proof.reserveCommitment);

    const threshold = requireBaseUnits(attestation.thresholdBaseUnits, "Threshold");
    const band = 1n << BigInt(bitLength);
    if (BigInt(attestation.bandExclusiveMaxBaseUnits) !== threshold + band) return false;

    const asset = normalizeAsset({
      symbol: attestation.assetSymbol,
      tokenAddress: attestation.tokenAddress,
      decimals: attestation.assetDecimals,
    });
    if (asset.symbol !== attestation.assetSymbol || asset.tokenAddress !== attestation.tokenAddress) return false;
    normalizeLiabilities(attestation.liabilities, threshold);

    const ctx = statementContext(
      {
        tokenAddress: asset.tokenAddress,
        assetDecimals: asset.decimals,
        assetSymbol: asset.symbol,
        merchantAlias: attestation.merchantAlias,
        attestationId: attestation.attestationId,
        bitLength,
        threshold,
      },
      h,
      reserveCommitment,
    );

    let sum = ZERO;
    for (let i = 0; i < bitLength; i += 1) {
      const commitment = verifyBit(proof.bitProofs[i], ctx, i, h);
      if (!commitment) return false;
      sum = sum.add(scalePoint(commitment, 1n << BigInt(i)));
    }
    // Homomorphic tie-back: Σ 2^i·C_i must equal C_R − T·G, i.e. a commitment to (R − T).
    const target = reserveCommitment.add(scalePoint(G, threshold).negate());
    if (!sum.equals(target)) return false;

    if (computeStatementCommitment(attestation, ctx) !== attestation.statementCommitment) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Full disclosure path: the merchant reveals the exact reserve and blinding to
 * a chosen auditor, who confirms it matches the published commitment (binding)
 * and clears the threshold. This intentionally reveals R — use it only with a
 * counterparty entitled to the exact figure.
 */
export function verifyReservesOpening(attestation: ReservesAttestation, secret: ReservesSecret): boolean {
  try {
    if (!secret || secret.kind !== OPENING_KIND || secret.attestationId !== attestation.attestationId) return false;
    const reserve = requireBaseUnits(secret.reserveBaseUnits, "Reserve total");
    const blinding = requireScalar(secret.blinding, false);
    const h = independentGenerator();
    const reserveCommitment = pointFromFelts(attestation.proof.reserveCommitment);
    if (!pedersenCommit(reserve, blinding, h).equals(reserveCommitment)) return false;
    return reserve >= requireBaseUnits(attestation.thresholdBaseUnits, "Threshold");
  } catch {
    return false;
  }
}

export function buildReservesBadge(attestation: ReservesAttestation): ReservesBadge {
  return {
    kind: BADGE_KIND,
    attestationId: attestation.attestationId,
    merchantAlias: attestation.merchantAlias,
    assetSymbol: attestation.assetSymbol,
    network: attestation.network,
    thresholdDisplay: formatReservesBaseUnits(attestation.thresholdBaseUnits, attestation.assetDecimals),
    bandExclusiveMaxDisplay: formatReservesBaseUnits(attestation.bandExclusiveMaxBaseUnits, attestation.assetDecimals),
    createdAt: attestation.createdAt,
    statementCommitment: attestation.statementCommitment,
  };
}

// ---------------------------------------------------------------------------
// Serialization (base64url-encoded JSON)
// ---------------------------------------------------------------------------

export function serializeReservesAttestation(attestation: ReservesAttestation): string {
  return encodeJson(attestation);
}

export function parseReservesAttestation(encoded: string): ReservesAttestation {
  const raw = decodeJson(encoded, "Attestation") as Record<string, unknown>;
  const proofRaw = raw.proof as Record<string, unknown> | undefined;
  if (!proofRaw || !Array.isArray(proofRaw.bitProofs)) throw new Error("Attestation proof is missing.");
  const bitLength = requireInt(proofRaw.bitLength, "Bit length");
  const bitProofs = (proofRaw.bitProofs as unknown[]).map(parseBitProof);
  const attestation: ReservesAttestation = {
    kind: ATTESTATION_KIND,
    version: RESERVES_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    attestationId: requireText(raw.attestationId, "Attestation id", 64),
    merchantAlias: requireText(raw.merchantAlias, "Merchant alias", 80),
    assetSymbol: requireText(raw.assetSymbol, "Asset symbol", 16),
    tokenAddress: normalizeStarknetAddress(requireText(raw.tokenAddress, "Token address", 66)),
    assetDecimals: requireInt(raw.assetDecimals, "Asset decimals"),
    thresholdBaseUnits: requireDigits(raw.thresholdBaseUnits, "Threshold"),
    bandExclusiveMaxBaseUnits: requireDigits(raw.bandExclusiveMaxBaseUnits, "Band maximum"),
    liabilities: parseLiabilities(raw.liabilities),
    memo: typeof raw.memo === "string" ? raw.memo : "",
    createdAt: requireIsoTimestamp(raw.createdAt, "Attestation timestamp"),
    proof: {
      proofSystem: RESERVES_PROOF_SYSTEM,
      bitLength,
      generatorH: parsePoint(proofRaw.generatorH),
      reserveCommitment: parsePoint(proofRaw.reserveCommitment),
      bitProofs,
    },
    statementCommitment: requireHex(raw.statementCommitment, "Statement commitment"),
    notice: typeof raw.notice === "string" ? raw.notice : RESERVES_NOTICE,
  };
  if (raw.kind !== ATTESTATION_KIND || raw.version !== RESERVES_ENGINE_VERSION) {
    throw new Error("Attestation kind or version is unsupported.");
  }
  if (proofRaw.proofSystem !== RESERVES_PROOF_SYSTEM) throw new Error("Unsupported proof system.");
  if (bitProofs.length !== bitLength) throw new Error("Bit-proof count does not match the declared length.");
  return attestation;
}

export function serializeReservesSecret(secret: ReservesSecret): string {
  return encodeJson(secret);
}

export function parseReservesSecret(encoded: string): ReservesSecret {
  const raw = decodeJson(encoded, "Reserve opening") as Record<string, unknown>;
  if (raw.kind !== OPENING_KIND) throw new Error("Unsupported opening kind.");
  return {
    kind: OPENING_KIND,
    attestationId: requireText(raw.attestationId, "Attestation id", 64),
    reserveBaseUnits: requireDigits(raw.reserveBaseUnits, "Reserve total"),
    blinding: requireHex(raw.blinding, "Blinding"),
  };
}

function parseBitProof(value: unknown): ReservesBitProof {
  const raw = value as Record<string, unknown>;
  if (!raw || typeof raw !== "object") throw new Error("Bit proof is malformed.");
  return {
    commitment: parsePoint(raw.commitment),
    a0: parsePoint(raw.a0),
    a1: parsePoint(raw.a1),
    challenge0: requireHex(raw.challenge0, "Challenge"),
    response0: requireHex(raw.response0, "Response"),
    response1: requireHex(raw.response1, "Response"),
  };
}

function parsePoint(value: unknown): CurvePointFelts {
  const raw = value as Record<string, unknown>;
  if (!raw || typeof raw !== "object") throw new Error("Curve point is malformed.");
  return { x: requireHex(raw.x, "Point coordinate"), y: requireHex(raw.y, "Point coordinate") };
}

function parseLiabilities(value: unknown): ReservesLiability[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error("Liabilities must be a list.");
  return value.map((item) => {
    const raw = item as Record<string, unknown>;
    return { label: requireText(raw.label, "Liability label", 60), amountBaseUnits: requireDigits(raw.amountBaseUnits, "Liability amount") };
  });
}

// ---------------------------------------------------------------------------
// Honest disclosure model
// ---------------------------------------------------------------------------

export function summarizeReservesTrust(): ReservesTrustModel {
  return {
    isZeroKnowledge: true,
    provesThresholdRelation: true,
    provesReserveBand: true,
    provesOnChainCustody: false,
    bindsToRealFunds: false,
    isDecentralized: false,
    isAutomatic: false,
    zeroKnowledgeElement:
      "The bit-decomposition range proof and its per-bit Schnorr OR proofs. A verifier learns only that the committed reserve lies in the stated band.",
    statement:
      "This is neither decentralized nor automatic. It proves a zero-knowledge range relation over a merchant-supplied reserve commitment; it does not prove on-chain custody and never reads from or writes to the pool contract.",
  };
}

export function getReservesVisibilityModel(): ReservesVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The exact reserve total R.",
      "The commitment blinding factor.",
      "Any underlying balances, notes, or transaction history.",
    ],
    disclosedToVerifier: [
      "The public threshold T and the proven band [T, T + 2^bitLength).",
      "The asset, merchant alias, and any liability breakdown the merchant chose to attach.",
      "The reserve commitment and the range proof (which reveal nothing about R beyond the band).",
    ],
    applicationOnly: [
      "The reserve figure is asserted by the merchant, not measured from the pool.",
      "The engine runs entirely client-side and touches no keys.",
    ],
    limitation:
      "The engine never reads from or writes to the pool contract. It proves a relation over a committed number, not that the merchant custodies that amount on-chain.",
  };
}

export function formatReservesBaseUnits(value: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(value, decimals);
}

// ---------------------------------------------------------------------------
// Validation & encoding helpers
// ---------------------------------------------------------------------------

function normalizeAsset(asset: ReservesAsset): ReservesAsset {
  if (!asset || typeof asset !== "object") throw new Error("Asset is required.");
  const symbol = requireText(asset.symbol, "Asset symbol", 16);
  const decimals = requireInt(asset.decimals, "Asset decimals");
  if (decimals < 0 || decimals > 18) throw new Error("Asset decimals must be between 0 and 18.");
  return { symbol, tokenAddress: normalizeStarknetAddress(asset.tokenAddress), decimals };
}

function normalizeBitLength(value: number | undefined): number {
  if (value === undefined) return DEFAULT_RESERVES_BIT_LENGTH;
  if (!isValidBitLength(value)) throw new Error("Bit length must be an integer in the supported range.");
  return value;
}

function isValidBitLength(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= MIN_RESERVES_BIT_LENGTH && value <= MAX_RESERVES_BIT_LENGTH;
}

function normalizeLiabilities(liabilities: ReservesLiability[] | undefined, threshold: bigint): ReservesLiability[] {
  if (liabilities === undefined || liabilities === null) return [];
  if (!Array.isArray(liabilities)) throw new Error("Liabilities must be a list.");
  if (liabilities.length > 32) throw new Error("Too many liability line items.");
  let sum = 0n;
  const normalized = liabilities.map((item) => {
    const label = requireText(item.label, "Liability label", 60);
    const amount = requireBaseUnits(item.amountBaseUnits, "Liability amount");
    sum += amount;
    return { label, amountBaseUnits: amount.toString() };
  });
  if (normalized.length > 0 && sum !== threshold) {
    throw new Error("Liability line items must sum to the threshold.");
  }
  return normalized;
}

function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireInt(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(`${label} must be an integer.`);
  return value;
}

function requireDigits(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an integer in base units.`);
  return BigInt(value).toString();
}

function requireBaseUnits(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an integer in base units.`);
  const amount = BigInt(value);
  if (amount <= 0n || amount > U128_MAX) throw new Error(`${label} is outside the STRK20 u128 range.`);
  return amount;
}

function requireHex(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} must be a hex value.`);
  return toHex(BigInt(value));
}

function requireFelt(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Value is not a felt.");
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("Felt is outside the Stark field.");
  return parsed;
}

function requireScalar(value: unknown, allowZero: boolean): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Value is not a scalar.");
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error("Scalar is outside the Stark curve order.");
  return parsed;
}

function randomScalar(): bigint {
  return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey());
}

function nonZeroScalar(value: bigint): bigint {
  return mod(value, CURVE_ORDER - 1n) + 1n;
}

function hashElements(values: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function mod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder >= 0n ? remainder : remainder + modulus;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let low = mod(value, modulus);
  let high = modulus;
  let resultLow = 1n;
  let resultHigh = 0n;
  while (low > 1n) {
    const quotient = high / low;
    [low, high] = [high - quotient * low, low];
    [resultLow, resultHigh] = [resultHigh - quotient * resultLow, resultLow];
  }
  if (low === 0n) throw new Error("Value is not invertible modulo the curve order.");
  return mod(resultLow, modulus);
}

function toHex(value: bigint): string {
  if (value < 0n) throw new Error("Cannot encode a negative value as hex.");
  return `0x${value.toString(16)}`;
}

function defaultId(): string {
  return `res_${randomScalar().toString(16).slice(0, 24)}`;
}

function encodeJson(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeJson(encoded: string, label: string): unknown {
  if (typeof encoded !== "string" || !encoded || encoded.length > MAX_ENCODED_LENGTH || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error(`${label} encoding is invalid.`);
  }
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

