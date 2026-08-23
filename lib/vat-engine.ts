/**
 * CipherBill — Cross-Border VAT & Indirect-Tax Proof Engine
 * =========================================================
 *
 * A client-side module that, upon invoice generation, computes a
 * jurisdiction-specific indirect tax (VAT / GST / sales / consumption tax) at a
 * PUBLIC statutory rate and proves, in zero knowledge, that the committed tax
 * is the exact integer computation over a committed net amount —
 * `tax = floor(net × rate ÷ 10000)` — WITHOUT revealing the net, gross, or tax
 * figures, and while binding the customer's tax identifier under a salted
 * commitment so buyer–seller confidentiality is preserved.
 *
 * The zero-knowledge core combines Pedersen commitments over the STARK curve
 * with (a) bit-decomposition range proofs that pin `net`, `tax`, and the
 * division remainder into non-negative, bounded bands, and (b) a homomorphic
 * linear-relation Schnorr proof that `rate·C_net − 10000·C_tax − C_rem` carries
 * no G-component, i.e. `net·rate = tax·10000 + rem` with `0 ≤ rem < 10000`.
 * Together these force `tax = floor(net·rate/10000)` unconditionally. The
 * merchant signs the binding so anyone can authenticate the issuer offline, and
 * the tax figure or tax ID can be selectively disclosed later. Fiat–Shamir
 * makes every proof non-interactive.
 *
 * WHAT THIS IS
 * ------------
 * - A real ZK proof of correct tax arithmetic. A verifier learns only that the
 *   committed tax equals the exact floor-division of the committed net at the
 *   stated public rate — nothing about the net, gross, tax, blindings, or the
 *   customer's tax ID.
 * - Issuer-authenticated. A Schnorr signature over the voucher binding proves a
 *   specific merchant public key issued it; anyone can check it offline.
 * - Selectively disclosable. The merchant can later open the tax figure alone
 *   (for authority reporting) or reveal the committed customer tax ID, each
 *   verifiable against the published commitments.
 * - Fully self-contained and offline. No wallet, RPC, or contract call.
 *
 * WHAT THIS IS NOT
 * ----------------
 * - It does NOT file, remit, or settle any tax with any authority. It produces
 *   a proof and voucher; remittance and filing happen out of band.
 * - It does NOT validate that a customer tax ID is real or government-registered.
 *   It only binds the merchant-supplied value under a salted commitment.
 * - It does NOT settle on-chain or move funds in the STRK20 pool, and never
 *   reads from or writes to the pool contract; the pool address below is
 *   recorded as provenance only.
 * - It does NOT itself harmonize any tax law, and is NOT tax advice. Bundled
 *   jurisdiction rates are illustrative and must be verified against current
 *   statute.
 * - It is neither decentralized nor automatic: a single merchant key issues
 *   vouchers and no contract, oracle, or consensus vouches for the inputs.
 *   `summarizeVatTrust()` and `getVatVisibilityModel()` state these limits verbatim.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

export const VAT_ENGINE_VERSION = 1 as const;
export const VAT_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const VAT_PROOF_SYSTEM = "stark-pedersen-vat-linear-v1" as const;
/** Basis-point denominator: rate is expressed in hundredths of a percent, so 10000 = 100%. */
export const VAT_RATE_DENOMINATOR = 10000n;
export const MAX_VAT_RATE_BASIS_POINTS = 10000;
/** ceil(log2(10000)) — the remainder rem ∈ [0, 9999] and 9999 − rem both fit in 14 bits. */
export const VAT_REMAINDER_BIT_LENGTH = 14;
export const DEFAULT_VAT_NET_BIT_LENGTH = 128;
export const MIN_VAT_NET_BIT_LENGTH = 8;
export const MAX_VAT_NET_BIT_LENGTH = 128;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const FIELD = ec.starkCurve.CURVE.Fp;
const CURVE_A = ec.starkCurve.CURVE.a;
const CURVE_B = ec.starkCurve.CURVE.b;
const U128_MAX = (1n << 128n) - 1n;
const G = ec.starkCurve.ProjectivePoint.BASE;
const ZERO = ec.starkCurve.ProjectivePoint.ZERO;
type CurvePoint = ReturnType<typeof G.multiply>;

const GENERATOR_DOMAIN = hash.starknetKeccak("CipherBill vat generator H v1");
const CONTEXT_DOMAIN = hash.starknetKeccak("CipherBill vat statement v1");
const CHALLENGE_DOMAIN = hash.starknetKeccak("CipherBill vat bit challenge v1");
const LINK_DOMAIN = hash.starknetKeccak("CipherBill vat linear link v1");
const BINDING_DOMAIN = hash.starknetKeccak("CipherBill vat binding v1");
const SIGNATURE_DOMAIN = hash.starknetKeccak("CipherBill vat issuer signature v1");
const TAXID_DOMAIN = hash.starknetKeccak("CipherBill vat customer tax id v1");
const VOUCHER_KIND = "cipherbill.vat-voucher" as const;
const SECRET_KIND = "cipherbill.vat-voucher-secret" as const;
const TAX_DISCLOSURE_KIND = "cipherbill.vat-tax-disclosure" as const;
const TAXID_DISCLOSURE_KIND = "cipherbill.vat-taxid-disclosure" as const;
const BADGE_KIND = "cipherbill.vat-voucher-badge" as const;
const KEYPAIR_KIND = "cipherbill.vat-keypair" as const;
const MAX_ENCODED_LENGTH = 800_000;
export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface VatAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface VatKeypair {
  kind: typeof KEYPAIR_KIND;
  role: "issuer";
  /** SECRET scalar (hex). The issuing merchant keeps it to sign vouchers. */
  secretKey: string;
  publicKey: CurvePointFelts;
}

export interface VatEntropy {
  createId?: (kind: "voucher") => string;
  randomScalar?: () => bigint;
}

/** A single jurisdiction rate preset. Illustrative only — not tax advice. */
export interface VatJurisdiction {
  code: string;
  label: string;
  taxKind: "VAT" | "GST" | "Sales Tax" | "Consumption Tax";
  standardRateBasisPoints: number;
  note: string;
}

/** The pure arithmetic breakdown of an indirect-tax computation (no proof). */
export interface VatComputation {
  netBaseUnits: string;
  rateBasisPoints: string;
  taxBaseUnits: string;
  grossBaseUnits: string;
  remainderBaseUnits: string;
}

export interface IssueVatVoucherInput {
  merchantAlias: string;
  asset: VatAsset;
  /** PUBLIC free-form reference to the invoice this voucher covers. */
  invoiceRef: string;
  /** PUBLIC jurisdiction code, e.g. "GB" or "EU-DE". */
  jurisdictionCode: string;
  /** PUBLIC human-readable jurisdiction label. */
  jurisdictionLabel: string;
  /** PUBLIC tax kind label, e.g. "VAT" or "GST". */
  taxKind: string;
  /** PUBLIC statutory rate in basis points, 0..10000 (10000 = 100%). */
  rateBasisPoints: number;
  /** SECRET net (pre-tax) amount in integer base units. Never serialized in the voucher. */
  netBaseUnits: string;
  /** SECRET customer tax identifier; only a salted commitment is published. */
  customerTaxId?: string;
  /** SECRET issuer signing scalar (hex). Its public key is embedded and published. */
  issuerSecretKey: string;
  netBitLength?: number;
  memo?: string;
}
/** One bit's Schnorr one-of-two proof: the commitment opens to 0 or to 1. */
export interface VatBitProof {
  commitment: CurvePointFelts;
  a0: CurvePointFelts;
  a1: CurvePointFelts;
  /** Challenge share for branch 0 in [0, n); branch 1's share is (challenge − challenge0). */
  challenge0: string;
  response0: string;
  response1: string;
}

/** Schnorr signature (challenge, response) over the voucher binding by the issuer key. */
export interface IssuerSignature {
  challenge: string;
  response: string;
}

/**
 * Homomorphic linear-relation proof that `rate·C_net − D·C_tax − C_rem` is a
 * pure H-multiple (its G-coefficient is zero), i.e. `net·rate = tax·D + rem`.
 * A Schnorr proof of knowledge of that H-exponent w.r.t. the canonical H.
 */
export interface VatLinkProof {
  commitment: CurvePointFelts;
  response: string;
}

/**
 * Zero-knowledge proof bundle. Range legs pin `net ∈ [0, 2^netBitLength)`,
 * `tax ∈ [0, 2^netBitLength)`, and `rem ∈ [0, D−1]` (a two-leg bound); the link
 * proof ties the three commitments through the exact division relation, forcing
 * `tax = floor(net·rate/D)`.
 */
export interface VatProof {
  proofSystem: typeof VAT_PROOF_SYSTEM;
  netBitLength: number;
  remainderBitLength: number;
  generatorH: CurvePointFelts;
  netCommitment: CurvePointFelts;
  taxCommitment: CurvePointFelts;
  remainderCommitment: CurvePointFelts;
  netBits: VatBitProof[];
  taxBits: VatBitProof[];
  remainderLowerBits: VatBitProof[];
  remainderUpperBits: VatBitProof[];
  link: VatLinkProof;
}

export interface VatVoucher {
  kind: typeof VOUCHER_KIND;
  version: typeof VAT_ENGINE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  voucherId: string;
  merchantAlias: string;
  invoiceRef: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  jurisdictionCode: string;
  jurisdictionLabel: string;
  taxKind: string;
  /** PUBLIC rate ρ in basis points; the tax is proven to apply this exact rate. */
  rateBasisPoints: string;
  /** PUBLIC denominator D (10000); recorded for verifier clarity. */
  rateDenominator: string;
  /** Salted Poseidon commitment to the customer tax ID; hides the ID itself. */
  taxIdCommitment: string;
  /** Whether the merchant asserts a non-empty tax ID is bound (false = B2C / none). */
  taxIdCommitted: boolean;
  issuerPublicKey: CurvePointFelts;
  proof: VatProof;
  issuerSignature: IssuerSignature;
  bindingHash: string;
  createdAt: string;
  memo: string;
  notice: string;
}
/** SECRET issuer record of a freshly issued voucher. Never publish it. */
export interface VatVoucherSecret {
  kind: typeof SECRET_KIND;
  voucherId: string;
  netBaseUnits: string;
  taxBaseUnits: string;
  grossBaseUnits: string;
  remainderBaseUnits: string;
  netBlinding: string;
  taxBlinding: string;
  remainderBlinding: string;
  rateBasisPoints: string;
  customerTaxId: string;
  taxIdSalt: string;
  taxIdCommitted: boolean;
}

export interface IssuedVatVoucher {
  voucher: VatVoucher;
  secret: VatVoucherSecret;
}

/** A full opening the merchant can hand an auditor to disclose every figure. */
export interface VatVoucherOpening {
  netBaseUnits: string;
  netBlinding: string;
  taxBaseUnits: string;
  taxBlinding: string;
  remainderBaseUnits: string;
  remainderBlinding: string;
}

/** Selective disclosure of the tax figure alone (net and gross stay hidden). */
export interface VatTaxDisclosure {
  kind: typeof TAX_DISCLOSURE_KIND;
  voucherId: string;
  taxBaseUnits: string;
  taxBlinding: string;
}

/** Selective disclosure of the committed customer tax ID. */
export interface VatTaxIdDisclosure {
  kind: typeof TAXID_DISCLOSURE_KIND;
  voucherId: string;
  customerTaxId: string;
  taxIdSalt: string;
}

export interface VatVoucherBadge {
  kind: typeof BADGE_KIND;
  voucherId: string;
  merchantAlias: string;
  invoiceRef: string;
  assetSymbol: string;
  network: typeof MAINNET_CHAIN_ID;
  jurisdictionLabel: string;
  taxKind: string;
  rateDisplay: string;
  taxIdCommitted: boolean;
  createdAt: string;
  bindingHash: string;
  issuerPublicKey: CurvePointFelts;
}

export interface VatTrustModel {
  isZeroKnowledge: boolean;
  provesCorrectTaxComputation: boolean;
  hidesNetAndGross: boolean;
  hidesCustomerTaxId: boolean;
  authenticatesIssuer: boolean;
  supportsSelectiveDisclosure: boolean;
  filesOrRemitsTax: boolean;
  validatesTaxIdRegistration: boolean;
  provesOnChainSettlement: boolean;
  bindsToRealFunds: boolean;
  isDecentralized: boolean;
  isAutomatic: boolean;
  isTaxAdvice: boolean;
  harmonizesTaxLaw: boolean;
  zeroKnowledgeElement: string;
  statement: string;
}

export interface VatVisibilityModel {
  hiddenFromVerifier: string[];
  disclosedToVerifier: string[];
  applicationOnly: string[];
  limitation: string;
}

const VAT_NOTICE =
  "Zero-knowledge proof that a committed tax equals floor(net × rate ÷ 10000) at a public jurisdiction rate, hiding net, gross, tax, and the customer tax ID. It authenticates the issuer and supports selective disclosure; it does not file, remit, or settle any tax, is not tax advice, is neither decentralized nor automatic, and never reads from or writes to the STRK20 pool contract.";
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

/** Returns the canonical H as serializable felts (for embedding in a voucher). */
export function deriveVatGenerator(): CurvePointFelts {
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
  throw new Error("Failed to derive an independent VAT generator.");
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

/** A merchant issuing keypair. The secret signs vouchers; the public key authenticates them. */
export function createVatIssuerKey(entropy: VatEntropy = {}): VatKeypair {
  const nextScalar = entropy.randomScalar ?? randomScalar;
  const secret = nonZeroScalar(nextScalar());
  return { kind: KEYPAIR_KIND, role: "issuer", secretKey: toHex(secret), publicKey: pointToFelts(publicKeyFromSecret(secret)) };
}

// ---------------------------------------------------------------------------
// Indirect-tax arithmetic
// ---------------------------------------------------------------------------

/**
 * Computes the exact integer indirect tax at a basis-point rate:
 * `tax = floor(net·rate/10000)`, `rem = net·rate mod 10000`, `gross = net + tax`.
 * Pure arithmetic — the same relation the zero-knowledge proof attests.
 */
export function computeVat(netBaseUnits: string, rateBasisPoints: number): VatComputation {
  const net = requireBaseUnits(netBaseUnits, "net amount");
  const rate = BigInt(requireInt(rateBasisPoints, "rate basis points", 0, MAX_VAT_RATE_BASIS_POINTS));
  if (net > U128_MAX) throw new Error("The net amount must fit within the u128 range.");
  const scaled = net * rate;
  const tax = scaled / VAT_RATE_DENOMINATOR;
  const remainder = scaled % VAT_RATE_DENOMINATOR;
  return {
    netBaseUnits: net.toString(),
    rateBasisPoints: rate.toString(),
    taxBaseUnits: tax.toString(),
    grossBaseUnits: (net + tax).toString(),
    remainderBaseUnits: remainder.toString(),
  };
}

/** Formats a basis-point rate as a percentage string, e.g. 1900 → "19.00%". */
export function formatVatRate(rateBasisPoints: string | number | bigint): string {
  const bp = typeof rateBasisPoints === "bigint" ? rateBasisPoints : BigInt(rateBasisPoints);
  const whole = bp / 100n;
  const frac = (bp % 100n).toString().padStart(2, "0");
  return `${whole}.${frac}%`;
}

export function formatVatBaseUnits(baseUnits: string | bigint, decimals: number): string {
  return baseUnitsToDecimal(baseUnits, decimals);
}
// ---------------------------------------------------------------------------
// Fiat–Shamir transcript
// ---------------------------------------------------------------------------

interface BindingFields {
  voucherId: string;
  merchantAlias: string;
  invoiceRef: string;
  assetSymbol: string;
  tokenAddress: string;
  assetDecimals: number;
  jurisdictionCode: string;
  jurisdictionLabel: string;
  taxKind: string;
  rateBasisPoints: bigint;
  netBitLength: number;
  taxIdCommitment: bigint;
  taxIdCommitted: boolean;
  createdAt: string;
  memo: string;
}

/**
 * The voucher binding hash: a Poseidon digest over every public,
 * proof-independent field plus the three commitments and the generator H. The
 * range-proof challenges, the link proof, and the issuer signature are all
 * bound to it, so no field can be altered without invalidating the voucher.
 */
function computeBindingHash(
  fields: BindingFields,
  issuerKey: CurvePoint,
  netCommitment: CurvePoint,
  taxCommitment: CurvePoint,
  remainderCommitment: CurvePoint,
  h: CurvePoint,
): bigint {
  return hashElements([
    BINDING_DOMAIN,
    BigInt(VAT_ENGINE_VERSION),
    hash.starknetKeccak(fields.voucherId),
    hash.starknetKeccak(fields.merchantAlias),
    hash.starknetKeccak(fields.invoiceRef),
    hash.starknetKeccak(fields.assetSymbol),
    BigInt(fields.tokenAddress),
    BigInt(fields.assetDecimals),
    hash.starknetKeccak(fields.jurisdictionCode),
    hash.starknetKeccak(fields.jurisdictionLabel),
    hash.starknetKeccak(fields.taxKind),
    fields.rateBasisPoints,
    VAT_RATE_DENOMINATOR,
    BigInt(fields.netBitLength),
    BigInt(VAT_REMAINDER_BIT_LENGTH),
    fields.taxIdCommitment,
    fields.taxIdCommitted ? 1n : 0n,
    hash.starknetKeccak(fields.createdAt),
    hash.starknetKeccak(fields.memo || "-"),
    issuerKey.x,
    issuerKey.y,
    netCommitment.x,
    netCommitment.y,
    taxCommitment.x,
    taxCommitment.y,
    remainderCommitment.x,
    remainderCommitment.y,
    h.x,
    h.y,
  ]);
}

/** Context digest that seeds every range-proof challenge, bound to the voucher binding. */
function statementContext(bindingHash: bigint): bigint {
  return hashElements([CONTEXT_DOMAIN, bindingHash]);
}

/**
 * Per-bit Fiat–Shamir challenge, bound to the context, the proof leg
 * (0 = net, 1 = remainder lower, 2 = remainder upper, 3 = tax), the index, and
 * both proof nonces.
 */
function bitChallenge(ctx: bigint, leg: number, index: number, commitment: CurvePoint, a0: CurvePoint, a1: CurvePoint): bigint {
  return mod(
    hashElements([CHALLENGE_DOMAIN, ctx, BigInt(leg), BigInt(index), commitment.x, commitment.y, a0.x, a0.y, a1.x, a1.y]),
    CURVE_ORDER,
  );
}

/** Salted Poseidon commitment to a customer tax identifier; hiding and binding. */
function commitTaxId(customerTaxId: string, salt: bigint): bigint {
  return hashElements([TAXID_DOMAIN, hash.starknetKeccak(customerTaxId), salt]);
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
): VatBitProof {
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

function verifyBit(proof: VatBitProof, ctx: bigint, leg: number, index: number, h: CurvePoint): CurvePoint | null {
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
): VatBitProof[] {
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

  const proofs: VatBitProof[] = [];
  for (let i = 0; i < bitLength; i += 1) {
    const bit = Number((value >> BigInt(i)) & 1n);
    const commitment = pedersenCommit(BigInt(bit), bitBlindings[i], h);
    proofs.push(proveBit(bit, commitment, bitBlindings[i], ctx, leg, i, h, nextScalar));
  }
  return proofs;
}

/** Verifies one range-proof leg and returns Σ 2^i·C_i, or null if any bit proof fails. */
function verifyRange(proofs: VatBitProof[], bitLength: number, ctx: bigint, leg: number, h: CurvePoint): CurvePoint | null {
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
// Linear-relation link proof and issuer signature
// ---------------------------------------------------------------------------

/**
 * The residual point P = rate·C_net − D·C_tax − C_rem. If the division relation
 * `net·rate = tax·D + rem` holds, P's G-component cancels and P = z·H for
 * z = rate·r_net − D·r_tax − r_rem, so a Schnorr proof of knowledge of that
 * H-exponent certifies the relation (H's DL w.r.t. G is unknown).
 */
function linkResidual(netC: CurvePoint, taxC: CurvePoint, remC: CurvePoint, rate: bigint): CurvePoint {
  return scalePoint(netC, rate).add(scalePoint(taxC, VAT_RATE_DENOMINATOR).negate()).add(remC.negate());
}

function linkChallenge(ctx: bigint, residual: CurvePoint, commitment: CurvePoint): bigint {
  return mod(hashElements([LINK_DOMAIN, ctx, residual.x, residual.y, commitment.x, commitment.y]), CURVE_ORDER);
}

function proveLink(
  netBlinding: bigint,
  taxBlinding: bigint,
  remainderBlinding: bigint,
  rate: bigint,
  residual: CurvePoint,
  ctx: bigint,
  h: CurvePoint,
  nextScalar: () => bigint,
): VatLinkProof {
  const z = mod(rate * netBlinding - VAT_RATE_DENOMINATOR * taxBlinding - remainderBlinding, CURVE_ORDER);
  const k = nonZeroScalar(nextScalar());
  const commitment = scalePoint(h, k);
  const challenge = linkChallenge(ctx, residual, commitment);
  const response = mod(k + challenge * z, CURVE_ORDER);
  return { commitment: pointToFelts(commitment), response: toHex(response) };
}

function verifyLink(proof: VatLinkProof, residual: CurvePoint, ctx: bigint, h: CurvePoint): boolean {
  const commitment = pointFromFelts(proof.commitment);
  const response = requireScalar(proof.response, true);
  const challenge = linkChallenge(ctx, residual, commitment);
  return scalePoint(h, response).equals(commitment.add(scalePoint(residual, challenge)));
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
// ---------------------------------------------------------------------------
// Issue and verify
// ---------------------------------------------------------------------------

/** Recomputes the binding hash from a voucher's public fields (used by verify). */
function bindingHashForVoucher(voucher: VatVoucher, h: CurvePoint): bigint {
  const fields: BindingFields = {
    voucherId: voucher.voucherId,
    merchantAlias: voucher.merchantAlias,
    invoiceRef: voucher.invoiceRef,
    assetSymbol: voucher.assetSymbol,
    tokenAddress: voucher.tokenAddress,
    assetDecimals: voucher.assetDecimals,
    jurisdictionCode: voucher.jurisdictionCode,
    jurisdictionLabel: voucher.jurisdictionLabel,
    taxKind: voucher.taxKind,
    rateBasisPoints: requireRate(voucher.rateBasisPoints),
    netBitLength: voucher.proof.netBitLength,
    taxIdCommitment: requireFelt(voucher.taxIdCommitment, "tax id commitment"),
    taxIdCommitted: voucher.taxIdCommitted === true,
    createdAt: voucher.createdAt,
    memo: voucher.memo,
  };
  return computeBindingHash(
    fields,
    pointFromFelts(voucher.issuerPublicKey),
    pointFromFelts(voucher.proof.netCommitment),
    pointFromFelts(voucher.proof.taxCommitment),
    pointFromFelts(voucher.proof.remainderCommitment),
    h,
  );
}

/**
 * Issues a VAT voucher: computes the exact tax, commits net/tax/remainder,
 * proves the division relation and the range bounds in zero knowledge, binds a
 * salted commitment to the customer tax ID, and signs the binding as the
 * merchant. Returns the publishable voucher and the secret opening the issuer
 * retains (never publish the secret).
 */
export function issueVatVoucher(
  input: IssueVatVoucherInput,
  now: Date = new Date(),
  entropy: VatEntropy = {},
): IssuedVatVoucher {
  const merchantAlias = requireText(input.merchantAlias, "merchant alias", 80);
  const invoiceRef = requireText(input.invoiceRef, "invoice reference", 120);
  const assetSymbol = requireText(input.asset?.symbol, "asset symbol", 16);
  const tokenAddress = normalizeStarknetAddress(input.asset?.tokenAddress ?? "");
  const assetDecimals = requireInt(input.asset?.decimals, "asset decimals", 0, 18);
  const jurisdictionCode = requireText(input.jurisdictionCode, "jurisdiction code", 24);
  const jurisdictionLabel = requireText(input.jurisdictionLabel, "jurisdiction label", 80);
  const taxKind = requireText(input.taxKind, "tax kind", 32);
  const memo = typeof input.memo === "string" && input.memo.trim() ? requireText(input.memo, "memo", 200) : "";
  const netBitLength =
    input.netBitLength === undefined
      ? DEFAULT_VAT_NET_BIT_LENGTH
      : requireInt(input.netBitLength, "net bit length", MIN_VAT_NET_BIT_LENGTH, MAX_VAT_NET_BIT_LENGTH);
  const rate = BigInt(requireInt(input.rateBasisPoints, "rate basis points", 0, MAX_VAT_RATE_BASIS_POINTS));

  const net = requireBaseUnits(input.netBaseUnits, "net amount");
  if (net > U128_MAX) throw new Error("The net amount must fit within the u128 range.");
  if (net >= 1n << BigInt(netBitLength)) throw new Error(`The net amount exceeds the provable ${netBitLength}-bit band.`);

  const scaled = net * rate;
  const tax = scaled / VAT_RATE_DENOMINATOR;
  const remainder = scaled % VAT_RATE_DENOMINATOR;
  // rate ≤ 10000 = D ⟹ tax = floor(net·rate/D) ≤ net < 2^netBitLength, so tax shares the band.

  const customerTaxId = typeof input.customerTaxId === "string" ? input.customerTaxId.trim() : "";
  if (customerTaxId.length > 64) throw new Error("The customer tax id is too long (max 64 characters).");
  const taxIdCommitted = customerTaxId.length > 0;

  const issuerSecret = requireScalar(input.issuerSecretKey, false);
  const issuerKey = publicKeyFromSecret(issuerSecret);

  const nextScalar = entropy.randomScalar ?? randomScalar;
  const createId = entropy.createId ?? defaultId;
  const voucherId = requireText(createId("voucher"), "voucher id", 120);
  const createdAt = now.toISOString();

  const h = independentGenerator();
  const netBlinding = nonZeroScalar(nextScalar());
  const taxBlinding = nonZeroScalar(nextScalar());
  const remainderBlinding = nonZeroScalar(nextScalar());
  const taxIdSalt = nonZeroScalar(nextScalar());

  const netCommitment = pedersenCommit(net, netBlinding, h);
  const taxCommitment = pedersenCommit(tax, taxBlinding, h);
  const remainderCommitment = pedersenCommit(remainder, remainderBlinding, h);
  const taxIdCommitment = commitTaxId(customerTaxId, taxIdSalt);

  const fields: BindingFields = {
    voucherId, merchantAlias, invoiceRef, assetSymbol, tokenAddress, assetDecimals,
    jurisdictionCode, jurisdictionLabel, taxKind, rateBasisPoints: rate, netBitLength,
    taxIdCommitment, taxIdCommitted, createdAt, memo,
  };
  const bindingHash = computeBindingHash(fields, issuerKey, netCommitment, taxCommitment, remainderCommitment, h);
  const ctx = statementContext(bindingHash);

  // Range legs: net (leg 0) and tax (leg 3) into [0, 2^netBitLength); remainder
  // into [0, D−1] via a two-leg bound — lower (leg 1) decomposes rem tied to
  // C_rem, upper (leg 2) decomposes (D−1 − rem) tied to (D−1)·G − C_rem.
  const netBits = proveRange(net, netBlinding, netBitLength, ctx, 0, h, nextScalar);
  const taxBits = proveRange(tax, taxBlinding, netBitLength, ctx, 3, h, nextScalar);
  const remainderLowerBits = proveRange(remainder, remainderBlinding, VAT_REMAINDER_BIT_LENGTH, ctx, 1, h, nextScalar);
  const remainderUpperBits = proveRange(
    VAT_RATE_DENOMINATOR - 1n - remainder,
    mod(-remainderBlinding, CURVE_ORDER),
    VAT_REMAINDER_BIT_LENGTH,
    ctx,
    2,
    h,
    nextScalar,
  );

  const residual = linkResidual(netCommitment, taxCommitment, remainderCommitment, rate);
  const link = proveLink(netBlinding, taxBlinding, remainderBlinding, rate, residual, ctx, h, nextScalar);
  const issuerSignature = signBinding(bindingHash, issuerSecret, issuerKey, nextScalar);

  const voucher: VatVoucher = {
    kind: VOUCHER_KIND,
    version: VAT_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    voucherId,
    merchantAlias,
    invoiceRef,
    assetSymbol,
    tokenAddress,
    assetDecimals,
    jurisdictionCode,
    jurisdictionLabel,
    taxKind,
    rateBasisPoints: rate.toString(),
    rateDenominator: VAT_RATE_DENOMINATOR.toString(),
    taxIdCommitment: toHex(taxIdCommitment),
    taxIdCommitted,
    issuerPublicKey: pointToFelts(issuerKey),
    proof: {
      proofSystem: VAT_PROOF_SYSTEM,
      netBitLength,
      remainderBitLength: VAT_REMAINDER_BIT_LENGTH,
      generatorH: pointToFelts(h),
      netCommitment: pointToFelts(netCommitment),
      taxCommitment: pointToFelts(taxCommitment),
      remainderCommitment: pointToFelts(remainderCommitment),
      netBits,
      taxBits,
      remainderLowerBits,
      remainderUpperBits,
      link,
    },
    issuerSignature,
    bindingHash: toHex(bindingHash),
    createdAt,
    memo,
    notice: VAT_NOTICE,
  };
  const secret: VatVoucherSecret = {
    kind: SECRET_KIND,
    voucherId,
    netBaseUnits: net.toString(),
    taxBaseUnits: tax.toString(),
    grossBaseUnits: (net + tax).toString(),
    remainderBaseUnits: remainder.toString(),
    netBlinding: toHex(netBlinding),
    taxBlinding: toHex(taxBlinding),
    remainderBlinding: toHex(remainderBlinding),
    rateBasisPoints: rate.toString(),
    customerTaxId,
    taxIdSalt: toHex(taxIdSalt),
    taxIdCommitted,
  };
  return { voucher, secret };
}
/**
 * Verifies a VAT voucher offline: canonical H, public rate bounds, binding,
 * issuer signature, all four range legs, and the linear division relation.
 * A pass means the committed tax equals floor(committed net × rate ÷ 10000).
 */
export function verifyVatVoucher(voucher: VatVoucher): boolean {
  try {
    if (!voucher || voucher.kind !== VOUCHER_KIND || voucher.version !== VAT_ENGINE_VERSION) return false;
    if (voucher.proof?.proofSystem !== VAT_PROOF_SYSTEM) return false;
    const netBitLength = voucher.proof.netBitLength;
    if (!Number.isInteger(netBitLength) || netBitLength < MIN_VAT_NET_BIT_LENGTH || netBitLength > MAX_VAT_NET_BIT_LENGTH) return false;
    if (voucher.proof.remainderBitLength !== VAT_REMAINDER_BIT_LENGTH) return false;

    // Public rate must be in range and the denominator canonical.
    if (voucher.rateDenominator !== VAT_RATE_DENOMINATOR.toString()) return false;
    const rate = requireRate(voucher.rateBasisPoints);

    // Recompute the canonical generator; reject a prover-substituted H.
    const h = independentGenerator();
    if (voucher.proof.generatorH.x !== toHex(h.x) || voucher.proof.generatorH.y !== toHex(h.y)) return false;

    const netCommitment = pointFromFelts(voucher.proof.netCommitment);
    const taxCommitment = pointFromFelts(voucher.proof.taxCommitment);
    const remainderCommitment = pointFromFelts(voucher.proof.remainderCommitment);

    // Recompute and match the binding over every public field and commitment.
    const bindingHash = bindingHashForVoucher(voucher, h);
    if (voucher.bindingHash !== toHex(bindingHash)) return false;

    // Authenticate the issuer over that binding.
    if (!verifySignature(bindingHash, pointFromFelts(voucher.issuerPublicKey), voucher.issuerSignature)) return false;

    const ctx = statementContext(bindingHash);

    // net ∈ [0, 2^netBitLength) tied to C_net.
    const netSum = verifyRange(voucher.proof.netBits, netBitLength, ctx, 0, h);
    if (!netSum || !netSum.equals(netCommitment)) return false;
    // tax ∈ [0, 2^netBitLength) tied to C_tax.
    const taxSum = verifyRange(voucher.proof.taxBits, netBitLength, ctx, 3, h);
    if (!taxSum || !taxSum.equals(taxCommitment)) return false;
    // rem ∈ [0, D−1]: lower leg ties to C_rem, upper leg to (D−1)·G − C_rem.
    const remLowerSum = verifyRange(voucher.proof.remainderLowerBits, VAT_REMAINDER_BIT_LENGTH, ctx, 1, h);
    if (!remLowerSum || !remLowerSum.equals(remainderCommitment)) return false;
    const remUpperSum = verifyRange(voucher.proof.remainderUpperBits, VAT_REMAINDER_BIT_LENGTH, ctx, 2, h);
    if (!remUpperSum) return false;
    if (!remUpperSum.equals(scalePoint(G, VAT_RATE_DENOMINATOR - 1n).add(remainderCommitment.negate()))) return false;

    // Division relation net·rate = tax·D + rem via the homomorphic link proof.
    const residual = linkResidual(netCommitment, taxCommitment, remainderCommitment, rate);
    return verifyLink(voucher.proof.link, residual, ctx, h);
  } catch {
    return false;
  }
}
// ---------------------------------------------------------------------------
// Selective disclosure and openings
// ---------------------------------------------------------------------------

/** Builds a disclosure of the tax figure alone (net and gross remain hidden). */
export function buildVatTaxDisclosure(secret: VatVoucherSecret): VatTaxDisclosure {
  return {
    kind: TAX_DISCLOSURE_KIND,
    voucherId: requireText(secret.voucherId, "voucher id", 120),
    taxBaseUnits: requireBaseUnits(secret.taxBaseUnits, "tax amount").toString(),
    taxBlinding: toHex(requireScalar(secret.taxBlinding, false)),
  };
}

/** Confirms a tax disclosure opens the voucher's tax commitment to a u128 figure. */
export function verifyVatTaxDisclosure(voucher: VatVoucher, disclosure: VatTaxDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== TAX_DISCLOSURE_KIND || disclosure.voucherId !== voucher.voucherId) return false;
    const tax = requireBaseUnits(disclosure.taxBaseUnits, "tax amount");
    const blinding = requireScalar(disclosure.taxBlinding, false);
    if (tax > U128_MAX) return false;
    return pedersenCommit(tax, blinding, independentGenerator()).equals(pointFromFelts(voucher.proof.taxCommitment));
  } catch {
    return false;
  }
}

/** Builds a disclosure that reveals the committed customer tax ID. */
export function buildVatTaxIdDisclosure(secret: VatVoucherSecret): VatTaxIdDisclosure {
  return {
    kind: TAXID_DISCLOSURE_KIND,
    voucherId: requireText(secret.voucherId, "voucher id", 120),
    customerTaxId: typeof secret.customerTaxId === "string" ? secret.customerTaxId : "",
    taxIdSalt: toHex(requireScalar(secret.taxIdSalt, false)),
  };
}

/** Confirms a tax-ID disclosure opens the voucher's salted tax-ID commitment. */
export function verifyVatTaxIdDisclosure(voucher: VatVoucher, disclosure: VatTaxIdDisclosure): boolean {
  try {
    if (!disclosure || disclosure.kind !== TAXID_DISCLOSURE_KIND || disclosure.voucherId !== voucher.voucherId) return false;
    const salt = requireScalar(disclosure.taxIdSalt, false);
    const taxId = typeof disclosure.customerTaxId === "string" ? disclosure.customerTaxId : "";
    if (taxId.length > 64) return false;
    return toHex(commitTaxId(taxId, salt)) === voucher.taxIdCommitment;
  } catch {
    return false;
  }
}

/**
 * Confirms a full opening reproduces all three commitments AND satisfies the
 * exact division relation — the auditor-facing total-disclosure check.
 */
export function verifyVatVoucherOpening(voucher: VatVoucher, opening: VatVoucherOpening): boolean {
  try {
    const h = independentGenerator();
    const rate = requireRate(voucher.rateBasisPoints);
    const net = requireBaseUnits(opening.netBaseUnits, "net amount");
    const tax = requireBaseUnits(opening.taxBaseUnits, "tax amount");
    const remainder = requireBaseUnits(opening.remainderBaseUnits, "remainder");
    if (net > U128_MAX || tax > U128_MAX) return false;
    if (remainder >= VAT_RATE_DENOMINATOR) return false;
    if (net * rate !== tax * VAT_RATE_DENOMINATOR + remainder) return false;
    const netBlinding = requireScalar(opening.netBlinding, false);
    const taxBlinding = requireScalar(opening.taxBlinding, false);
    const remainderBlinding = requireScalar(opening.remainderBlinding, false);
    if (!pedersenCommit(net, netBlinding, h).equals(pointFromFelts(voucher.proof.netCommitment))) return false;
    if (!pedersenCommit(tax, taxBlinding, h).equals(pointFromFelts(voucher.proof.taxCommitment))) return false;
    return pedersenCommit(remainder, remainderBlinding, h).equals(pointFromFelts(voucher.proof.remainderCommitment));
  } catch {
    return false;
  }
}

/** Condenses a voucher into a shareable, verifier-facing badge (no secret material). */
export function buildVatVoucherBadge(voucher: VatVoucher): VatVoucherBadge {
  return {
    kind: BADGE_KIND,
    voucherId: voucher.voucherId,
    merchantAlias: voucher.merchantAlias,
    invoiceRef: voucher.invoiceRef,
    assetSymbol: voucher.assetSymbol,
    network: voucher.network,
    jurisdictionLabel: voucher.jurisdictionLabel,
    taxKind: voucher.taxKind,
    rateDisplay: formatVatRate(voucher.rateBasisPoints),
    taxIdCommitted: voucher.taxIdCommitted,
    createdAt: voucher.createdAt,
    bindingHash: voucher.bindingHash,
    issuerPublicKey: voucher.issuerPublicKey,
  };
}
// ---------------------------------------------------------------------------
// Jurisdiction presets (illustrative — NOT tax advice)
// ---------------------------------------------------------------------------

/**
 * Illustrative standard indirect-tax rates for common jurisdictions, provided
 * only as convenient presets for the rate selector. These are NOT tax advice
 * and may be out of date; reduced rates, exemptions, and reverse-charge rules
 * are not modelled. Verify the current statutory rate before issuing.
 */
export function getVatJurisdictions(): VatJurisdiction[] {
  return [
    { code: "EU-DE", label: "Germany — VAT", taxKind: "VAT", standardRateBasisPoints: 1900, note: "Standard rate; reduced 7% not modelled." },
    { code: "EU-FR", label: "France — TVA", taxKind: "VAT", standardRateBasisPoints: 2000, note: "Standard rate; reduced rates not modelled." },
    { code: "EU-IE", label: "Ireland — VAT", taxKind: "VAT", standardRateBasisPoints: 2300, note: "Standard rate." },
    { code: "GB", label: "United Kingdom — VAT", taxKind: "VAT", standardRateBasisPoints: 2000, note: "Standard rate; 5% and 0% not modelled." },
    { code: "CH", label: "Switzerland — VAT", taxKind: "VAT", standardRateBasisPoints: 810, note: "Standard rate." },
    { code: "AE", label: "United Arab Emirates — VAT", taxKind: "VAT", standardRateBasisPoints: 500, note: "Standard rate." },
    { code: "AU", label: "Australia — GST", taxKind: "GST", standardRateBasisPoints: 1000, note: "Standard GST." },
    { code: "NZ", label: "New Zealand — GST", taxKind: "GST", standardRateBasisPoints: 1500, note: "Standard GST." },
    { code: "SG", label: "Singapore — GST", taxKind: "GST", standardRateBasisPoints: 900, note: "Standard GST." },
    { code: "IN", label: "India — GST", taxKind: "GST", standardRateBasisPoints: 1800, note: "One common slab; multiple slabs exist." },
    { code: "CA-GST", label: "Canada — federal GST", taxKind: "GST", standardRateBasisPoints: 500, note: "Federal GST only; provincial PST/HST not modelled." },
    { code: "JP", label: "Japan — consumption tax", taxKind: "Consumption Tax", standardRateBasisPoints: 1000, note: "Standard rate; 8% reduced not modelled." },
    { code: "CUSTOM", label: "Custom rate", taxKind: "VAT", standardRateBasisPoints: 0, note: "Enter any rate in basis points (0–10000)." },
  ];
}

// ---------------------------------------------------------------------------
// Honest trust & visibility model
// ---------------------------------------------------------------------------

export function summarizeVatTrust(): VatTrustModel {
  return {
    isZeroKnowledge: true,
    provesCorrectTaxComputation: true,
    hidesNetAndGross: true,
    hidesCustomerTaxId: true,
    authenticatesIssuer: true,
    supportsSelectiveDisclosure: true,
    filesOrRemitsTax: false,
    validatesTaxIdRegistration: false,
    provesOnChainSettlement: false,
    bindsToRealFunds: false,
    isDecentralized: false,
    isAutomatic: false,
    isTaxAdvice: false,
    harmonizesTaxLaw: false,
    zeroKnowledgeElement:
      "The net, tax, and gross amounts — the proof shows tax = floor(net × rate ÷ 10000) at a public rate without disclosing any of them.",
    statement:
      "This engine produces a genuine zero-knowledge proof that a committed tax figure is the exact jurisdiction-rate computation over a committed net amount — tax = floor(net × rate ÷ 10000) — while hiding the net, gross, and tax and binding the customer tax ID under a salted commitment. It authenticates the issuing merchant and supports selective disclosure of the tax figure or the tax ID. It is neither decentralized nor automatic: a single merchant key issues vouchers, with no contract, oracle, or consensus vouching for the inputs. It does not file, remit, or settle any tax with any authority, does not validate that a customer tax ID is real or government-registered, does not settle on-chain or move pool funds, does not itself harmonize any tax law, and is not tax advice. It never reads from or writes to the STRK20 pool contract; the pool address is recorded as provenance only.",
  };
}

export function getVatVisibilityModel(): VatVisibilityModel {
  return {
    hiddenFromVerifier: [
      "The net (pre-tax) amount, the computed tax, and the gross total.",
      "The customer's tax identifier — only a salted commitment is published.",
      "Any link between this voucher and other invoices the merchant has issued.",
    ],
    disclosedToVerifier: [
      "The public jurisdiction rate (basis points) the tax is proven to apply.",
      "The merchant's issuing public key and a signature authenticating the voucher.",
      "The proof system, bit ranges, commitments, and the voucher binding hash.",
    ],
    applicationOnly: [
      "Merchant alias, invoice reference, jurisdiction labels, asset, and optional memo carried as plaintext metadata.",
      "Timing of issuance and correlation risk from distinctive invoice references or rates.",
    ],
    limitation:
      "The engine never reads from or writes to the STRK20 pool contract. It proves correct tax arithmetic over merchant-supplied commitments; it does not file, remit, or settle tax, does not validate that a tax ID is government-registered, and does not settle on-chain.",
  };
}
// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

export function serializeVatVoucher(voucher: VatVoucher): string {
  return toBase64Url(encodeJson(voucher));
}

export function serializeVatVoucherSecret(secret: VatVoucherSecret): string {
  return toBase64Url(encodeJson(secret));
}

export function serializeVatTaxDisclosure(disclosure: VatTaxDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

export function serializeVatTaxIdDisclosure(disclosure: VatTaxIdDisclosure): string {
  return toBase64Url(encodeJson(disclosure));
}

function parsePoint(value: unknown): CurvePointFelts {
  if (!value || typeof value !== "object") throw new Error("A curve point is malformed.");
  const point = value as { x?: unknown; y?: unknown };
  if (typeof point.x !== "string" || typeof point.y !== "string") throw new Error("A curve point is malformed.");
  return pointToFelts(pointFromFelts({ x: point.x, y: point.y }));
}

function parseBitProof(value: unknown): VatBitProof {
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

function parseLink(value: unknown): VatLinkProof {
  if (!value || typeof value !== "object") throw new Error("The link proof is malformed.");
  const l = value as Record<string, unknown>;
  return { commitment: parsePoint(l.commitment), response: toHex(requireScalar(l.response, true)) };
}

function parseSignature(value: unknown): IssuerSignature {
  if (!value || typeof value !== "object") throw new Error("The issuer signature is malformed.");
  const s = value as Record<string, unknown>;
  return { challenge: toHex(requireScalar(s.challenge, true)), response: toHex(requireScalar(s.response, true)) };
}

function parseProof(value: unknown): VatProof {
  if (!value || typeof value !== "object") throw new Error("The proof is malformed.");
  const p = value as Record<string, unknown>;
  if (p.proofSystem !== VAT_PROOF_SYSTEM) throw new Error("Unsupported VAT proof system.");
  const netBitLength = requireInt(p.netBitLength, "net bit length", MIN_VAT_NET_BIT_LENGTH, MAX_VAT_NET_BIT_LENGTH);
  const remainderBitLength = requireInt(p.remainderBitLength, "remainder bit length", VAT_REMAINDER_BIT_LENGTH, VAT_REMAINDER_BIT_LENGTH);
  if (
    !Array.isArray(p.netBits) || !Array.isArray(p.taxBits)
    || !Array.isArray(p.remainderLowerBits) || !Array.isArray(p.remainderUpperBits)
  ) throw new Error("The proof legs are malformed.");
  return {
    proofSystem: VAT_PROOF_SYSTEM,
    netBitLength,
    remainderBitLength,
    generatorH: parsePoint(p.generatorH),
    netCommitment: parsePoint(p.netCommitment),
    taxCommitment: parsePoint(p.taxCommitment),
    remainderCommitment: parsePoint(p.remainderCommitment),
    netBits: p.netBits.map(parseBitProof),
    taxBits: p.taxBits.map(parseBitProof),
    remainderLowerBits: p.remainderLowerBits.map(parseBitProof),
    remainderUpperBits: p.remainderUpperBits.map(parseBitProof),
    link: parseLink(p.link),
  };
}
export function parseVatVoucher(encoded: string): VatVoucher {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object") throw new Error("The VAT voucher is malformed.");
  if (raw.kind !== VOUCHER_KIND) throw new Error("This is not a CipherBill VAT voucher.");
  if (raw.version !== VAT_ENGINE_VERSION) throw new Error("Unsupported VAT voucher version.");
  return {
    kind: VOUCHER_KIND,
    version: VAT_ENGINE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    voucherId: requireText(raw.voucherId, "voucher id", 120),
    merchantAlias: requireText(raw.merchantAlias, "merchant alias", 80),
    invoiceRef: requireText(raw.invoiceRef, "invoice reference", 120),
    assetSymbol: requireText(raw.assetSymbol, "asset symbol", 16),
    tokenAddress: normalizeStarknetAddress(typeof raw.tokenAddress === "string" ? raw.tokenAddress : ""),
    assetDecimals: requireInt(raw.assetDecimals, "asset decimals", 0, 18),
    jurisdictionCode: requireText(raw.jurisdictionCode, "jurisdiction code", 24),
    jurisdictionLabel: requireText(raw.jurisdictionLabel, "jurisdiction label", 80),
    taxKind: requireText(raw.taxKind, "tax kind", 32),
    rateBasisPoints: requireRate(raw.rateBasisPoints).toString(),
    rateDenominator: VAT_RATE_DENOMINATOR.toString(),
    taxIdCommitment: toHex(requireFelt(raw.taxIdCommitment, "tax id commitment")),
    taxIdCommitted: raw.taxIdCommitted === true,
    issuerPublicKey: parsePoint(raw.issuerPublicKey),
    proof: parseProof(raw.proof),
    issuerSignature: parseSignature(raw.issuerSignature),
    bindingHash: toHex(requireFelt(raw.bindingHash, "binding hash")),
    createdAt: requireIsoTimestamp(raw.createdAt),
    memo: typeof raw.memo === "string" ? raw.memo : "",
    notice: typeof raw.notice === "string" ? raw.notice : VAT_NOTICE,
  };
}

export function parseVatVoucherSecret(encoded: string): VatVoucherSecret {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object" || raw.kind !== SECRET_KIND) throw new Error("This is not a VAT voucher secret.");
  return {
    kind: SECRET_KIND,
    voucherId: requireText(raw.voucherId, "voucher id", 120),
    netBaseUnits: requireBaseUnits(raw.netBaseUnits, "net amount").toString(),
    taxBaseUnits: requireBaseUnits(raw.taxBaseUnits, "tax amount").toString(),
    grossBaseUnits: requireBaseUnits(raw.grossBaseUnits, "gross amount").toString(),
    remainderBaseUnits: requireBaseUnits(raw.remainderBaseUnits, "remainder").toString(),
    netBlinding: toHex(requireScalar(raw.netBlinding, false)),
    taxBlinding: toHex(requireScalar(raw.taxBlinding, false)),
    remainderBlinding: toHex(requireScalar(raw.remainderBlinding, false)),
    rateBasisPoints: requireRate(raw.rateBasisPoints).toString(),
    customerTaxId: typeof raw.customerTaxId === "string" ? raw.customerTaxId : "",
    taxIdSalt: toHex(requireScalar(raw.taxIdSalt, false)),
    taxIdCommitted: raw.taxIdCommitted === true,
  };
}

export function parseVatTaxDisclosure(encoded: string): VatTaxDisclosure {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object" || raw.kind !== TAX_DISCLOSURE_KIND) throw new Error("This is not a VAT tax disclosure.");
  return {
    kind: TAX_DISCLOSURE_KIND,
    voucherId: requireText(raw.voucherId, "voucher id", 120),
    taxBaseUnits: requireBaseUnits(raw.taxBaseUnits, "tax amount").toString(),
    taxBlinding: toHex(requireScalar(raw.taxBlinding, false)),
  };
}

export function parseVatTaxIdDisclosure(encoded: string): VatTaxIdDisclosure {
  const raw = decodeJson(fromBase64Url(encoded.trim())) as Record<string, unknown>;
  if (!raw || typeof raw !== "object" || raw.kind !== TAXID_DISCLOSURE_KIND) throw new Error("This is not a VAT tax-ID disclosure.");
  const customerTaxId = typeof raw.customerTaxId === "string" ? raw.customerTaxId : "";
  if (customerTaxId.length > 64) throw new Error("The customer tax id is too long (max 64 characters).");
  return {
    kind: TAXID_DISCLOSURE_KIND,
    voucherId: requireText(raw.voucherId, "voucher id", 120),
    customerTaxId,
    taxIdSalt: toHex(requireScalar(raw.taxIdSalt, false)),
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

/** Parses a basis-point rate (string or number) and bounds it to [0, 10000]. */
function requireRate(value: unknown): bigint {
  if (typeof value === "string" && !/^\d+$/.test(value)) throw new Error("The rate basis points are malformed.");
  const n = requireInt(typeof value === "string" ? Number(value) : value, "rate basis points", 0, MAX_VAT_RATE_BASIS_POINTS);
  return BigInt(n);
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

/** A collision-resistant default voucher id; deterministic ids can be injected via entropy.createId. */
function defaultId(): string {
  const rand =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID().replace(/-/g, "").slice(0, 20)
      : `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 12)}`;
  return `vat_${rand}`;
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
    throw new Error("The VAT voucher encoding is invalid.");
  }
  if (encoded.length > MAX_ENCODED_LENGTH) throw new Error("The VAT voucher payload is too large to decode.");
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  return typeof Buffer !== "undefined"
    ? Buffer.from(base64, "base64").toString("utf8")
    : new TextDecoder().decode(Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)));
}
