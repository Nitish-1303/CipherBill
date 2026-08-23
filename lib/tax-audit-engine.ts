/**
 * Merchant tax & compliance audit export builder for CipherBill.
 *
 * WHAT THIS IS
 * - A client-side export module: a merchant records settled invoices (an invoice id, the settlement
 *   transaction hash, the asset, a gross amount, an optional fee disclosure, a tax category, a settlement
 *   time, and optional private references) as salted Poseidon commitments in one browser.
 * - A tamper-evident bundle: for a chosen date range the module filters the recorded entries, sums per-asset
 *   and per-category totals with exact integer math, builds a Merkle root over the entry commitments, and
 *   binds the root, the period, and the totals under one bundle commitment. Recomputing the commitments and
 *   the root detects any later alteration of an entry, a total, or the set.
 * - Selective disclosure: a shareable bundle digest carries the Merkle root, the per-asset and per-category
 *   totals, the entry count, and the period — never the per-entry invoice ids, transaction hashes,
 *   counterparty references, or memos. An opening (the full bundle) verifies against the digest, and a
 *   Merkle inclusion proof discloses a single entry and proves it belongs to the committed bundle without
 *   revealing the others.
 * - An optional Schnorr zero-knowledge proof of knowledge — the "export authorization" — by which the holder
 *   of an exporter key proves they assembled a specific bundle without revealing the key. This is the ONLY
 *   zero-knowledge element here; it attests who exported the bundle, it does not vouch for its contents.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not decentralized. The profile, the entries, the bundle, and every total are local computations in one
 *   browser. There is no on-chain registry, oracle, or audit contract; `STRK20_POOL_ADDRESS` is recorded as
 *   provenance for the settlement edges the entries reference, not a contract this module reads or writes.
 * - Not automatic. Nothing assembles or files a bundle on its own. A merchant records entries and builds an
 *   export by hand; the module commits and totals what it is given.
 * - Not zero-knowledge as a system. The profile, entry, and bundle commitments and the Merkle root are
 *   salted Poseidon hashes, not zero-knowledge proofs, and the inclusion proof reveals the disclosed entry
 *   in full. Only the optional export authorization is a zero-knowledge proof, and it proves knowledge of an
 *   exporter key, never that an invoice is real, complete, or truthfully categorized.
 * - Not an assurance of completeness or truth. The engine proves internal consistency and tamper-evidence:
 *   that the bundle was not altered after it was built. It cannot prove the merchant recorded every settled
 *   invoice, that a referenced transaction paid this invoice, or that a category is correct.
 * - Not anonymous. The settlement transaction hashes, deposits, withdrawals, and timing the entries point to
 *   are already-public pool edges; only movement inside the pool is encrypted.
 */
import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";
export const TAX_AUDIT_ENGINE_VERSION = 1 as const;
export const TAX_AUDIT_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const TAX_AUDIT_PROOF_SYSTEM = "stark-schnorr-tax-audit-v1" as const;
export const MAX_ASSET_DECIMALS = 18;
export const MAX_ENTRIES_PER_BUNDLE = 4_096;
export const TAX_AUDIT_SALT_BYTES = 31;

export const TAX_AUDIT_NOTICE =
  "Client-side merchant tax and compliance export. A merchant records settled invoices as salted Poseidon " +
  "commitments in this browser, and for a date range this module sums per-asset and per-category totals with " +
  "exact integer math, builds a Merkle root over the entries, and binds the root, period, and totals under " +
  "one commitment. There is no on-chain registry, oracle, or audit contract; the settlement transaction " +
  "hashes it references are already-public pool edges. It proves the bundle was not altered after it was " +
  "built — not that the invoices are complete or truthful. Only the optional export authorization is a " +
  "zero-knowledge proof.";

export const TAX_AUDIT_LIMITATIONS: readonly string[] = [
  "Nothing here is decentralized. The profile, entries, bundle, and every total are local computations in " +
    "one browser; no contract records invoices, aggregates totals, or files anything.",
  "Nothing is automatic. A merchant records each settled invoice and builds an export by hand; the module " +
    "commits and totals what it is given and cannot fetch settlements on its own.",
  "The engine proves tamper-evidence, not completeness or truth. Recomputing the commitments and the Merkle " +
    "root detects any later alteration, but cannot prove the merchant recorded every settlement, that a " +
    "referenced transaction paid this invoice, or that a category is correct.",
  "The profile, entry, and bundle commitments and the Merkle root are salted Poseidon hashes, not " +
    "zero-knowledge proofs. The inclusion proof reveals the disclosed entry in full. Only the optional " +
    "export authorization is a zero-knowledge proof, and it proves knowledge of an exporter key, nothing more.",
  "A bundle digest shares totals and the Merkle root without the per-entry data; on its own it is only " +
    "internally consistent. Full trust needs the opening, which recomputes the commitment from the entries.",
  "The settlement transaction hashes, deposits, withdrawals, and timing the entries reference are " +
    "already-public pool edges. Only movement inside the pool is encrypted; this module reveals nothing new " +
    "on-chain, and it never reads from or writes to the pool contract.",
];

const PROFILE_KIND = "cipherbill.tax-audit-profile";
const ENTRY_KIND = "cipherbill.tax-audit-entry";
const BUNDLE_KIND = "cipherbill.tax-audit-bundle";
const BUNDLE_DIGEST_KIND = "cipherbill.tax-audit-bundle-digest";
const INCLUSION_KIND = "cipherbill.tax-audit-inclusion-proof";
const AUTH_KIND = "cipherbill.tax-audit-authorization";
const PROFILE_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit profile v1"));
const ENTRY_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit entry v1"));
const BUNDLE_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit bundle v1"));
const MERKLE_NODE_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit merkle node v1"));
const ASSET_TOTALS_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit asset totals v1"));
const CATEGORY_TOTALS_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit category totals v1"));
const TOTALS_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit totals v1"));
const AUTH_DOMAIN = BigInt(hash.starknetKeccak("CipherBill tax audit authorization v1"));

const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const BASE = ec.starkCurve.ProjectivePoint.BASE;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 4_000_000;

const PROFILE_KEYS = [
  "kind", "version", "profileId", "network", "poolAddress", "merchant", "jurisdiction", "memo", "createdAt",
  "profileSalt", "profileCommitment", "notice", "limitations",
] as const;
const ENTRY_KEYS = [
  "kind", "version", "entryId", "network", "poolAddress", "profileCommitment", "invoiceId", "transactionHash",
  "assetSymbol", "assetTokenAddress", "assetDecimals", "grossBaseUnits", "feeBaseUnits", "netBaseUnits",
  "category", "settledAt", "counterpartyRef", "memo", "entrySalt", "entryCommitment", "notice",
] as const;
const ASSET_TOTAL_KEYS = [
  "assetSymbol", "assetTokenAddress", "assetDecimals", "entryCount", "grossBaseUnits", "feeBaseUnits",
  "netBaseUnits", "grossDisplay", "feeDisplay", "netDisplay",
] as const;
const CATEGORY_TOTAL_KEYS = [
  "category", "assetSymbol", "assetTokenAddress", "assetDecimals", "entryCount", "grossBaseUnits",
  "netBaseUnits", "grossDisplay", "netDisplay",
] as const;
const BUNDLE_KEYS = [
  "kind", "version", "bundleId", "network", "poolAddress", "profileCommitment", "periodStart", "periodEnd",
  "generatedAt", "entries", "assetTotals", "categoryTotals", "entryCount", "merkleRoot", "bundleSalt",
  "bundleCommitment", "notice", "limitations",
] as const;
const BUNDLE_DIGEST_KEYS = [
  "kind", "version", "bundleId", "network", "poolAddress", "profileCommitment", "periodStart", "periodEnd",
  "entryCount", "merkleRoot", "assetTotals", "categoryTotals", "bundleCommitment", "notice", "limitations",
] as const;
const INCLUSION_KEYS = [
  "kind", "version", "bundleId", "profileCommitment", "merkleRoot", "entry", "path", "notice",
] as const;
const PATH_STEP_KEYS = ["sibling", "position"] as const;
const AUTH_KEYS = [
  "kind", "version", "proofSystem", "bundleId", "profileCommitment", "merkleRoot", "periodStart", "periodEnd",
  "totalsHash", "exporterPublicKey", "proof", "notice",
] as const;
const POINT_KEYS = ["x", "y"] as const;
const PROOF_KEYS = ["nonceCommitment", "response"] as const;
export interface TaxAuditCurvePoint {
  x: string;
  y: string;
}

export interface TaxAuditSchnorrProof {
  nonceCommitment: TaxAuditCurvePoint;
  response: string;
}

export interface TaxAuditAssetInput {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface TaxAuditAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface CreateTaxAuditProfileInput {
  profileId?: string;
  merchant: string;
  jurisdiction?: string;
  memo?: string;
}

export interface TaxAuditProfile {
  kind: typeof PROFILE_KIND;
  version: typeof TAX_AUDIT_ENGINE_VERSION;
  profileId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  merchant: string;
  jurisdiction: string;
  memo: string;
  createdAt: string;
  profileSalt: string;
  profileCommitment: string;
  notice: typeof TAX_AUDIT_NOTICE;
  limitations: string[];
}

export interface RecordSettledInvoiceInput {
  entryId?: string;
  invoiceId: string;
  transactionHash: string;
  asset: TaxAuditAssetInput;
  gross: string;
  fee?: string;
  category: string;
  settledAt: string;
  counterpartyRef?: string;
  memo?: string;
}
export interface TaxAuditEntry {
  kind: typeof ENTRY_KIND;
  version: typeof TAX_AUDIT_ENGINE_VERSION;
  entryId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  profileCommitment: string;
  invoiceId: string;
  transactionHash: string;
  assetSymbol: string;
  assetTokenAddress: string;
  assetDecimals: number;
  grossBaseUnits: string;
  feeBaseUnits: string;
  netBaseUnits: string;
  category: string;
  settledAt: string;
  counterpartyRef: string;
  memo: string;
  entrySalt: string;
  entryCommitment: string;
  notice: string;
}

export interface TaxAuditAssetTotal {
  assetSymbol: string;
  assetTokenAddress: string;
  assetDecimals: number;
  entryCount: number;
  grossBaseUnits: string;
  feeBaseUnits: string;
  netBaseUnits: string;
  grossDisplay: string;
  feeDisplay: string;
  netDisplay: string;
}

export interface TaxAuditCategoryTotal {
  category: string;
  assetSymbol: string;
  assetTokenAddress: string;
  assetDecimals: number;
  entryCount: number;
  grossBaseUnits: string;
  netBaseUnits: string;
  grossDisplay: string;
  netDisplay: string;
}

export interface BuildTaxAuditBundleInput {
  bundleId?: string;
  periodStart: string;
  periodEnd: string;
}
export interface TaxAuditBundle {
  kind: typeof BUNDLE_KIND;
  version: typeof TAX_AUDIT_ENGINE_VERSION;
  bundleId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  profileCommitment: string;
  periodStart: string;
  periodEnd: string;
  generatedAt: string;
  entries: TaxAuditEntry[];
  assetTotals: TaxAuditAssetTotal[];
  categoryTotals: TaxAuditCategoryTotal[];
  entryCount: number;
  merkleRoot: string;
  bundleSalt: string;
  bundleCommitment: string;
  notice: typeof TAX_AUDIT_NOTICE;
  limitations: string[];
}

export interface TaxAuditBundleDigest {
  kind: typeof BUNDLE_DIGEST_KIND;
  version: typeof TAX_AUDIT_ENGINE_VERSION;
  bundleId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  profileCommitment: string;
  periodStart: string;
  periodEnd: string;
  entryCount: number;
  merkleRoot: string;
  assetTotals: TaxAuditAssetTotal[];
  categoryTotals: TaxAuditCategoryTotal[];
  bundleCommitment: string;
  notice: typeof TAX_AUDIT_NOTICE;
  limitations: string[];
}

export interface TaxAuditBundleOpening {
  bundleId: string;
  bundleCommitment: string;
  bundle: TaxAuditBundle;
}

export interface TaxAuditInclusionStep {
  sibling: string;
  position: "left" | "right";
}

export interface TaxAuditInclusionProof {
  kind: typeof INCLUSION_KIND;
  version: typeof TAX_AUDIT_ENGINE_VERSION;
  bundleId: string;
  profileCommitment: string;
  merkleRoot: string;
  entry: TaxAuditEntry;
  path: TaxAuditInclusionStep[];
  notice: string;
}
export interface TaxAuditExporterKey {
  exporterSecret: string;
  exporterPublicKey: TaxAuditCurvePoint;
}

export interface TaxAuditAuthorization {
  kind: typeof AUTH_KIND;
  version: typeof TAX_AUDIT_ENGINE_VERSION;
  proofSystem: typeof TAX_AUDIT_PROOF_SYSTEM;
  bundleId: string;
  profileCommitment: string;
  merkleRoot: string;
  periodStart: string;
  periodEnd: string;
  totalsHash: string;
  exporterPublicKey: TaxAuditCurvePoint;
  proof: TaxAuditSchnorrProof;
  notice: string;
}

export interface TaxAuditTotalsPreview {
  entryCount: number;
  assetTotals: TaxAuditAssetTotal[];
  categoryTotals: TaxAuditCategoryTotal[];
}

export interface TaxAuditVisibilityModel {
  applicationOnly: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface TaxAuditTrustSummary {
  dataSource: string;
  isDecentralized: boolean;
  isAutomatic: boolean;
  provesTamperEvidence: boolean;
  provesCompleteness: boolean;
  provesTruthfulness: boolean;
  zeroKnowledgeElement: string;
  trustedParties: string[];
  statement: string;
}

export interface TaxAuditEntropy {
  createId?: (kind: "profile" | "entry" | "bundle") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export interface TaxAuditKeyEntropy {
  exporterSecret?: bigint;
  nonce?: bigint;
}
export function createTaxAuditProfile(
  input: CreateTaxAuditProfileInput,
  now: Date = new Date(),
  entropy: TaxAuditEntropy = {},
): TaxAuditProfile {
  const merchant = normalizeStarknetAddress(input.merchant);
  const jurisdiction = requireOptionalText(input.jurisdiction, "Jurisdiction", 64);
  const memo = requireOptionalText(input.memo, "Profile memo", 280);
  const createdMs = requireInstant(now, "Profile time");
  const createdAt = new Date(createdMs).toISOString();
  const profileId = makeId(entropy.createId?.("profile"), "tap");
  const profileSalt = toHex(randomFelt(entropy.randomBytes));

  const profile: TaxAuditProfile = {
    kind: PROFILE_KIND,
    version: TAX_AUDIT_ENGINE_VERSION,
    profileId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    merchant,
    jurisdiction,
    memo,
    createdAt,
    profileSalt,
    profileCommitment: "0x0",
    notice: TAX_AUDIT_NOTICE,
    limitations: [...TAX_AUDIT_LIMITATIONS],
  };
  profile.profileCommitment = toHex(computeProfileCommitment(profile));
  return profile;
}

export function verifyTaxAuditProfile(profile: TaxAuditProfile): boolean {
  try {
    assertTaxAuditProfile(profile);
    return true;
  } catch {
    return false;
  }
}
export function recordSettledInvoice(
  profile: TaxAuditProfile,
  input: RecordSettledInvoiceInput,
  now: Date = new Date(),
  entropy: TaxAuditEntropy = {},
): TaxAuditEntry {
  assertTaxAuditProfile(profile);
  const entryId = makeId(entropy.createId?.("entry"), "tae");
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 96);
  const transactionHash = toHex(requireTransactionHash(input.transactionHash));
  const asset = normalizeAsset(input.asset);
  const gross = parseDecimalToBaseUnits(input.gross, asset.decimals, "Gross amount");
  requireU128(gross, "Gross amount");
  const fee = input.fee === undefined || input.fee === null
    ? 0n
    : parseNonNegativeDecimal(input.fee, asset.decimals, "Fee amount");
  if (fee > gross) throw new Error("The fee disclosure cannot exceed the gross amount.");
  const net = gross - fee;
  const category = requireText(input.category, "Tax category", 48);
  const settledAt = requireIsoTimestamp(input.settledAt, "Settlement time");
  const nowMs = requireInstant(now, "Recording time");
  if (Date.parse(settledAt) > nowMs) throw new Error("A settled invoice cannot settle in the future.");
  const counterpartyRef = requireOptionalText(input.counterpartyRef, "Counterparty reference", 96);
  const memo = requireOptionalText(input.memo, "Entry memo", 200);

  const draft: Omit<TaxAuditEntry, "entryCommitment"> = {
    kind: ENTRY_KIND,
    version: TAX_AUDIT_ENGINE_VERSION,
    entryId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    profileCommitment: profile.profileCommitment,
    invoiceId,
    transactionHash,
    assetSymbol: asset.symbol,
    assetTokenAddress: asset.tokenAddress,
    assetDecimals: asset.decimals,
    grossBaseUnits: gross.toString(),
    feeBaseUnits: fee.toString(),
    netBaseUnits: net.toString(),
    category,
    settledAt,
    counterpartyRef,
    memo,
    entrySalt: toHex(randomFelt(entropy.randomBytes)),
    notice:
      "Client-side settled-invoice record. The merchant asserts these figures and this settlement; the " +
      "commitment binds them but does not prove them, and nothing here is on-chain. The transaction hash " +
      "points to an already-public pool edge.",
  };
  return { ...draft, entryCommitment: toHex(computeEntryCommitment(draft)) };
}

export function verifyTaxAuditEntry(entry: TaxAuditEntry, profile: TaxAuditProfile): boolean {
  try {
    assertTaxAuditEntry(entry);
    assertTaxAuditProfile(profile);
    return entry.profileCommitment === profile.profileCommitment;
  } catch {
    return false;
  }
}
export function buildTaxAuditBundle(
  profile: TaxAuditProfile,
  entries: TaxAuditEntry[],
  input: BuildTaxAuditBundleInput,
  now: Date = new Date(),
  entropy: TaxAuditEntropy = {},
): TaxAuditBundle {
  assertTaxAuditProfile(profile);
  if (!Array.isArray(entries)) throw new Error("A settled-invoice entry list is required.");
  const periodStartMs = parsePeriodBound(input.periodStart, "Period start", false);
  const periodEndMs = parsePeriodBound(input.periodEnd, "Period end", true);
  if (periodEndMs < periodStartMs) throw new Error("The period end cannot precede the period start.");
  const periodStart = new Date(periodStartMs).toISOString();
  const periodEnd = new Date(periodEndMs).toISOString();

  const selected: TaxAuditEntry[] = [];
  for (const entry of entries) {
    assertTaxAuditEntry(entry);
    if (entry.profileCommitment !== profile.profileCommitment) {
      throw new Error("An entry belongs to a different tax-audit profile.");
    }
    const settledMs = Date.parse(entry.settledAt);
    if (settledMs >= periodStartMs && settledMs <= periodEndMs) selected.push(entry);
  }
  if (selected.length === 0) throw new Error("No settled invoices fall within the selected period.");
  if (selected.length > MAX_ENTRIES_PER_BUNDLE) {
    throw new Error(`A bundle covers at most ${MAX_ENTRIES_PER_BUNDLE} settled invoices.`);
  }
  // Reject a duplicate entry id or commitment so the Merkle set is well-defined.
  const seenIds = new Set<string>();
  const seenCommitments = new Set<string>();
  for (const entry of selected) {
    if (seenIds.has(entry.entryId) || seenCommitments.has(entry.entryCommitment)) {
      throw new Error("The bundle contains a duplicate settled-invoice entry.");
    }
    seenIds.add(entry.entryId);
    seenCommitments.add(entry.entryCommitment);
  }

  const assetTotals = buildAssetTotals(selected);
  const categoryTotals = buildCategoryTotals(selected);
  const merkleRoot = toHex(computeMerkleRoot(selected.map((entry) => requireFelt(entry.entryCommitment, "Entry commitment"))));
  const generatedAt = new Date(requireInstant(now, "Generation time")).toISOString();

  const draft: Omit<TaxAuditBundle, "bundleCommitment"> = {
    kind: BUNDLE_KIND,
    version: TAX_AUDIT_ENGINE_VERSION,
    bundleId: makeId(entropy.createId?.("bundle"), "tab"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    profileCommitment: profile.profileCommitment,
    periodStart,
    periodEnd,
    generatedAt,
    entries: selected,
    assetTotals,
    categoryTotals,
    entryCount: selected.length,
    merkleRoot,
    bundleSalt: toHex(randomFelt(entropy.randomBytes)),
    notice: TAX_AUDIT_NOTICE,
    limitations: [...TAX_AUDIT_LIMITATIONS],
  };
  return { ...draft, bundleCommitment: toHex(computeBundleCommitment(draft)) };
}

export function verifyTaxAuditBundle(bundle: TaxAuditBundle): boolean {
  try {
    assertTaxAuditBundle(bundle);
    return true;
  } catch {
    return false;
  }
}
export function previewTaxAuditTotals(entries: TaxAuditEntry[]): TaxAuditTotalsPreview {
  if (!Array.isArray(entries)) throw new Error("A settled-invoice entry list is required.");
  for (const entry of entries) assertTaxAuditEntry(entry);
  return {
    entryCount: entries.length,
    assetTotals: buildAssetTotals(entries),
    categoryTotals: buildCategoryTotals(entries),
  };
}

export function buildTaxAuditBundleDigest(bundle: TaxAuditBundle): TaxAuditBundleDigest {
  assertTaxAuditBundle(bundle);
  return {
    kind: BUNDLE_DIGEST_KIND,
    version: TAX_AUDIT_ENGINE_VERSION,
    bundleId: bundle.bundleId,
    network: bundle.network,
    poolAddress: bundle.poolAddress,
    profileCommitment: bundle.profileCommitment,
    periodStart: bundle.periodStart,
    periodEnd: bundle.periodEnd,
    entryCount: bundle.entryCount,
    merkleRoot: bundle.merkleRoot,
    // Aggregates only — never the per-entry invoice ids, transaction hashes, counterparty references, or memos.
    assetTotals: bundle.assetTotals.map((total) => ({ ...total })),
    categoryTotals: bundle.categoryTotals.map((total) => ({ ...total })),
    bundleCommitment: bundle.bundleCommitment,
    notice: TAX_AUDIT_NOTICE,
    limitations: [...TAX_AUDIT_LIMITATIONS],
  };
}

export function openTaxAuditBundle(bundle: TaxAuditBundle): TaxAuditBundleOpening {
  assertTaxAuditBundle(bundle);
  return { bundleId: bundle.bundleId, bundleCommitment: bundle.bundleCommitment, bundle };
}

export function verifyTaxAuditBundleDisclosure(
  opening: TaxAuditBundleOpening,
  digest: TaxAuditBundleDigest,
): boolean {
  try {
    if (!opening || typeof opening !== "object") return false;
    assertTaxAuditBundle(opening.bundle);
    assertTaxAuditBundleDigest(digest);
    if (opening.bundleCommitment !== opening.bundle.bundleCommitment) return false;
    if (digest.bundleCommitment !== opening.bundle.bundleCommitment) return false;
    if (digest.bundleId !== opening.bundle.bundleId) return false;
    if (digest.profileCommitment !== opening.bundle.profileCommitment) return false;
    if (digest.periodStart !== opening.bundle.periodStart || digest.periodEnd !== opening.bundle.periodEnd) return false;
    if (digest.entryCount !== opening.bundle.entryCount) return false;
    if (digest.merkleRoot !== opening.bundle.merkleRoot) return false;
    // The digest's aggregates must be exactly the bundle's; the bundle commitment already binds them.
    return canonical(digest.assetTotals) === canonical(opening.bundle.assetTotals)
      && canonical(digest.categoryTotals) === canonical(opening.bundle.categoryTotals);
  } catch {
    return false;
  }
}
export function proveEntryInclusion(bundle: TaxAuditBundle, entryId: string): TaxAuditInclusionProof {
  assertTaxAuditBundle(bundle);
  const index = bundle.entries.findIndex((entry) => entry.entryId === entryId);
  if (index < 0) throw new Error("The entry is not part of this bundle.");
  const leaves = bundle.entries.map((entry) => requireFelt(entry.entryCommitment, "Entry commitment"));
  const path = computeMerklePath(leaves, index);
  return {
    kind: INCLUSION_KIND,
    version: TAX_AUDIT_ENGINE_VERSION,
    bundleId: bundle.bundleId,
    profileCommitment: bundle.profileCommitment,
    merkleRoot: bundle.merkleRoot,
    entry: bundle.entries[index],
    path,
    notice:
      "Merkle inclusion proof. It discloses this single entry in full and proves it belongs to the committed " +
      "bundle without revealing the others. It is not a zero-knowledge proof and does not prove the entry is truthful.",
  };
}

export function verifyEntryInclusion(proof: TaxAuditInclusionProof, profile?: TaxAuditProfile): boolean {
  try {
    assertTaxAuditInclusionProof(proof);
    if (profile) {
      assertTaxAuditProfile(profile);
      if (proof.profileCommitment !== profile.profileCommitment) return false;
      if (proof.entry.profileCommitment !== profile.profileCommitment) return false;
    }
    if (proof.entry.profileCommitment !== proof.profileCommitment) return false;
    const leaf = requireFelt(proof.entry.entryCommitment, "Entry commitment");
    return verifyMerklePath(leaf, proof.path, requireFelt(proof.merkleRoot, "Merkle root"));
  } catch {
    return false;
  }
}
export function registerTaxAuditExporterKey(entropy: TaxAuditKeyEntropy = {}): TaxAuditExporterKey {
  const secret = entropy.exporterSecret === undefined
    ? randomScalar()
    : requireSecretScalar(entropy.exporterSecret, "Exporter secret");
  const publicKey = multiplyPoint(BASE, secret);
  return { exporterSecret: toHex(secret), exporterPublicKey: pointToFelts(publicKey) };
}

export function buildTaxAuditAuthorization(
  bundle: TaxAuditBundle,
  exporterKey: TaxAuditExporterKey,
  entropy: TaxAuditKeyEntropy = {},
): TaxAuditAuthorization {
  assertTaxAuditBundle(bundle);
  const secret = requireSecretScalar(exporterKey?.exporterSecret, "Exporter secret");
  const publicKey = normalizePoint(exporterKey.exporterPublicKey, "Exporter public key");
  const derived = pointToFelts(multiplyPoint(BASE, secret));
  if (derived.x !== publicKey.x || derived.y !== publicKey.y) {
    throw new Error("The exporter secret does not match the exporter public key.");
  }
  const totalsHash = toHex(computeTotalsHash(bundle.assetTotals, bundle.categoryTotals, bundle.entryCount));
  const transcript = authTranscript({
    bundleId: bundle.bundleId,
    profileCommitment: bundle.profileCommitment,
    merkleRoot: bundle.merkleRoot,
    periodStart: bundle.periodStart,
    periodEnd: bundle.periodEnd,
    totalsHash,
  });
  const proof = createSchnorrProof(AUTH_DOMAIN, secret, transcript, entropy.nonce);
  return {
    kind: AUTH_KIND,
    version: TAX_AUDIT_ENGINE_VERSION,
    proofSystem: TAX_AUDIT_PROOF_SYSTEM,
    bundleId: bundle.bundleId,
    profileCommitment: bundle.profileCommitment,
    merkleRoot: bundle.merkleRoot,
    periodStart: bundle.periodStart,
    periodEnd: bundle.periodEnd,
    totalsHash,
    exporterPublicKey: publicKey,
    proof,
    notice:
      "Zero-knowledge export authorization. It proves the holder knows the exporter key bound to this bundle's " +
      "root, period, and totals; it does not vouch that the invoices are complete, real, or truthfully categorized.",
  };
}

export function verifyTaxAuditAuthorization(authorization: TaxAuditAuthorization, bundle: TaxAuditBundle): boolean {
  try {
    assertTaxAuditAuthorization(authorization);
    assertTaxAuditBundle(bundle);
    if (authorization.bundleId !== bundle.bundleId) return false;
    if (authorization.profileCommitment !== bundle.profileCommitment) return false;
    if (authorization.merkleRoot !== bundle.merkleRoot) return false;
    if (authorization.periodStart !== bundle.periodStart || authorization.periodEnd !== bundle.periodEnd) return false;
    if (authorization.totalsHash !== toHex(computeTotalsHash(bundle.assetTotals, bundle.categoryTotals, bundle.entryCount))) return false;
    const publicKey = pointFromFelts(authorization.exporterPublicKey);
    const transcript = authTranscript({
      bundleId: authorization.bundleId,
      profileCommitment: authorization.profileCommitment,
      merkleRoot: authorization.merkleRoot,
      periodStart: authorization.periodStart,
      periodEnd: authorization.periodEnd,
      totalsHash: authorization.totalsHash,
    });
    return verifySchnorrProof(AUTH_DOMAIN, publicKey, authorization.proof, transcript);
  } catch {
    return false;
  }
}
export function getTaxAuditVisibilityModel(): TaxAuditVisibilityModel {
  return {
    applicationOnly: [
      "The tax-audit profile, every settled-invoice entry, the bundle, and all totals — they live in this browser and are never sent on-chain.",
      "The per-entry invoice ids, counterparty references, and memos, which stay out of the shareable digest entirely.",
    ],
    hiddenInPool: [
      "For the settlements the entries reference, the in-pool sender, recipient, token, and amount are hidden from public observers.",
    ],
    publicOrObservable: [
      "The settlement transaction hashes the entries cite are already-public pool edges; this module reveals nothing new by referencing them.",
      "Any deposit that funded a settlement or withdrawal that cashed it out, with its public address and amount, plus timing, fees, and published nullifiers (unlinkable without a viewing key).",
      "A shared bundle digest exposes the period, entry count, Merkle root, and per-asset and per-category totals — aggregates the merchant chooses to disclose.",
    ],
    limitation:
      "Only movement inside the pool is encrypted. The bundle is a local record, not an on-chain fact; the " +
      "settlement edges it points to stay public, and the engine never reads from or writes to the pool contract.",
  };
}

export function summarizeTaxAuditTrust(): TaxAuditTrustSummary {
  return {
    dataSource: "A local set of settled-invoice records the merchant keeps; the engine commits and totals them but cannot vouch that they are complete or real.",
    isDecentralized: false,
    isAutomatic: false,
    provesTamperEvidence: true,
    provesCompleteness: false,
    provesTruthfulness: false,
    zeroKnowledgeElement:
      "Only the optional export authorization — a Schnorr proof of knowledge of an exporter key bound to a bundle's root, period, and totals. It proves who exported the bundle, never that its invoices are complete or truthful.",
    trustedParties: [
      "The merchant, who records the invoices, categorizes them, and assembles the export.",
      "Whoever receives a bundle, digest, or inclusion proof and must still confirm the cited transactions on-chain.",
      "The STRK20 deposit-screening service and the auditor-key escrow that govern the underlying pool settlements.",
    ],
    statement:
      "CipherBill's tax-audit export aggregates a merchant's settled-invoice records locally with exact integer " +
      "math into a tamper-evident bundle. It is neither decentralized nor automatic, it proves the bundle was " +
      "not altered after it was built — not that the invoices are complete or truthful — and only the export " +
      "authorization is a zero-knowledge proof.",
  };
}
export function serializeTaxAuditProfile(profile: TaxAuditProfile): string {
  assertTaxAuditProfile(profile);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(profile)));
}

export function parseTaxAuditProfile(encoded: string): TaxAuditProfile {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Tax-audit profile");
  assertTaxAuditProfile(parsed);
  return parsed;
}

export function serializeTaxAuditEntry(entry: TaxAuditEntry): string {
  assertTaxAuditEntry(entry);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(entry)));
}

export function parseTaxAuditEntry(encoded: string): TaxAuditEntry {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Tax-audit entry");
  assertTaxAuditEntry(parsed);
  return parsed;
}

export function serializeTaxAuditBundle(bundle: TaxAuditBundle): string {
  assertTaxAuditBundle(bundle);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(bundle)));
}

export function parseTaxAuditBundle(encoded: string): TaxAuditBundle {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Tax-audit bundle");
  assertTaxAuditBundle(parsed);
  return parsed;
}

export function serializeTaxAuditBundleDigest(digest: TaxAuditBundleDigest): string {
  assertTaxAuditBundleDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseTaxAuditBundleDigest(encoded: string): TaxAuditBundleDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Bundle digest");
  assertTaxAuditBundleDigest(parsed);
  return parsed;
}

export function serializeTaxAuditInclusionProof(proof: TaxAuditInclusionProof): string {
  assertTaxAuditInclusionProof(proof);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(proof)));
}

export function parseTaxAuditInclusionProof(encoded: string): TaxAuditInclusionProof {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Inclusion proof");
  assertTaxAuditInclusionProof(parsed);
  return parsed;
}

export function serializeTaxAuditAuthorization(authorization: TaxAuditAuthorization): string {
  assertTaxAuditAuthorization(authorization);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(authorization)));
}

export function parseTaxAuditAuthorization(encoded: string): TaxAuditAuthorization {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Export authorization");
  assertTaxAuditAuthorization(parsed);
  return parsed;
}

export function formatTaxAuditBaseUnits(value: string | bigint, decimals: number): string {
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

function randomFillBytes(target: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(target);
}

/** Draws a non-zero field element from the injected entropy source (defaults to the platform CSPRNG). */
function randomFelt(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer> = randomFillBytes): bigint {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const bytes = random(new Uint8Array(TAX_AUDIT_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== TAX_AUDIT_SALT_BYTES) throw new Error("The entropy source returned the wrong number of bytes.");
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n && value < FIELD_PRIME) return value;
  }
  throw new Error("Could not draw a usable salt.");
}

function randomScalar(): bigint {
  return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey());
}

function hashElements(values: bigint[]): bigint {
  for (const value of values) {
    if (value < 0n || value >= FIELD_PRIME) throw new Error("A commitment input is outside the STARK field.");
  }
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function mod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder >= 0n ? remainder : remainder + modulus;
}
type CurvePoint = ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>;
function multiplyPoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const normalized = mod(scalar, CURVE_ORDER);
  return normalized === 0n ? ec.starkCurve.ProjectivePoint.ZERO : point.multiply(normalized);
}

function pointToFelts(point: CurvePoint): TaxAuditCurvePoint {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: TaxAuditCurvePoint, label = "Curve point"): CurvePoint {
  if (!point || typeof point !== "object") throw new Error(`${label} is invalid.`);
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, label), y: requireFelt(point.y, label) });
  parsed.assertValidity();
  return parsed;
}

function normalizePoint(value: unknown, label: string): TaxAuditCurvePoint {
  assertPoint(value, label);
  return pointToFelts(pointFromFelts(value, label));
}

function createSchnorrProof(domain: bigint, secret: bigint, transcript: bigint[], suppliedNonce?: bigint): TaxAuditSchnorrProof {
  const nonce = requireSecretScalar(suppliedNonce ?? randomScalar(), "Schnorr nonce");
  const publicKey = multiplyPoint(BASE, secret);
  const noncePoint = multiplyPoint(BASE, nonce);
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(mod(nonce + challenge * secret, CURVE_ORDER)) };
}

function verifySchnorrProof(domain: bigint, publicKey: CurvePoint, proof: TaxAuditSchnorrProof, transcript: bigint[]): boolean {
  const noncePoint = pointFromFelts(proof.nonceCommitment, "Schnorr nonce commitment");
  const response = requireCurveScalar(proof.response, true, "Schnorr response");
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return multiplyPoint(BASE, response).equals(noncePoint.add(multiplyPoint(publicKey, challenge)));
}

function schnorrChallenge(domain: bigint, publicKey: CurvePoint, noncePoint: CurvePoint, transcript: bigint[]): bigint {
  return mod(hashElements([domain, publicKey.x, publicKey.y, noncePoint.x, noncePoint.y, ...transcript]), CURVE_ORDER);
}
function normalizeAsset(asset: TaxAuditAssetInput | undefined, label = "Settlement asset"): TaxAuditAsset {
  if (!asset || !asset.tokenAddress) throw new Error(`${label} needs a Starknet token contract address.`);
  return {
    symbol: requireSymbol(asset.symbol, `${label} symbol`),
    tokenAddress: normalizeStarknetAddress(asset.tokenAddress),
    decimals: requireDecimals(asset.decimals, `${label} decimals`),
  };
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Tax-audit amounts cannot be negative.");
  if (decimals === 0) return value.toString();
  const divisor = 10n ** BigInt(decimals);
  const fraction = (value % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  const whole = (value / divisor).toString();
  return fraction ? `${whole}.${fraction}` : whole;
}

/** Parses a positive decimal amount into base units; rejects zero and negatives. */
function parseDecimalToBaseUnits(value: unknown, decimals: number, label: string): bigint {
  const units = parseNonNegativeDecimal(value, decimals, label);
  if (units <= 0n) throw new Error(`${label} must be greater than zero.`);
  return units;
}

/** Parses a non-negative decimal amount into base units; permits zero (fee disclosures). */
function parseNonNegativeDecimal(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a non-negative decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  return requireU128(BigInt(`${whole}${fraction.padEnd(decimals, "0")}`), label);
}

/**
 * Parses a period bound. Accepts a bare calendar date (`YYYY-MM-DD`), snapping the start to 00:00:00.000Z
 * and the end to 23:59:59.999Z of that UTC day, or a full ISO-8601 UTC timestamp used verbatim.
 */
function parsePeriodBound(value: unknown, label: string, isEnd: boolean): number {
  if (typeof value !== "string") throw new Error(`${label} must be a date.`);
  const trimmed = value.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    const ms = Date.parse(`${trimmed}T${isEnd ? "23:59:59.999" : "00:00:00.000"}Z`);
    if (Number.isNaN(ms)) throw new Error(`${label} is not a valid calendar date.`);
    return ms;
  }
  const iso = requireIsoTimestamp(trimmed, label);
  return Date.parse(iso);
}
function requireBaseUnitString(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} is outside the u128 range the privacy pool accepts.`);
  return value;
}

function requireInstant(value: unknown, label: string): number {
  if (!(value instanceof Date)) throw new Error(`${label} must be a Date.`);
  const ms = value.getTime();
  if (!Number.isFinite(ms)) throw new Error(`${label} is not a valid instant.`);
  return ms;
}

function requireSymbol(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9.\-/]{1,16}$/.test(value)) throw new Error(`${label} must be 1 to 16 letters, digits, dots, dashes, or slashes.`);
  return value;
}

function requireDecimals(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_ASSET_DECIMALS) {
    throw new Error(`${label} must be a whole number between 0 and ${MAX_ASSET_DECIMALS}.`);
  }
  return value;
}

function requireText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) throw new Error(`${label} must be between 1 and ${maxLength} characters.`);
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

function requireCurveScalar(value: unknown, allowZero: boolean, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/.test(value)) throw new Error(`${label} is invalid.`);
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error(`${label} is outside the STARK curve order.`);
  return parsed;
}

function requireSecretScalar(value: unknown, label: string): bigint {
  if (typeof value === "string") return requireCurveScalar(value, false, label);
  if (typeof value !== "bigint" || value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the STARK curve order.`);
  return value;
}

function requireTransactionHash(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) throw new Error("The transaction hash is invalid.");
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed >= FIELD_PRIME) throw new Error("The transaction hash is outside the STARK field.");
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

function hasOnlyKeys(value: object, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every((key) => allowed.includes(key));
}

/** A stable, order-preserving JSON string for deep-comparing the aggregate arrays. */
function canonical(value: unknown): string {
  return JSON.stringify(value);
}
/** One interior Merkle node: a domain-separated Poseidon hash of its ordered children. */
function hashMerkleNode(left: bigint, right: bigint): bigint {
  return hashElements([MERKLE_NODE_DOMAIN, left, right]);
}

/**
 * A binary Merkle root over the entry commitments. A single leaf is its own root; an odd level duplicates
 * its last node before pairing. The domain separator keeps a leaf value from ever colliding with a node.
 */
function computeMerkleRoot(leaves: bigint[]): bigint {
  if (leaves.length === 0) throw new Error("A Merkle tree needs at least one leaf.");
  let level = leaves.slice();
  while (level.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(hashMerkleNode(level[i], right));
    }
    level = next;
  }
  return level[0];
}

/** The inclusion path for one leaf: each step names the sibling and the side the sibling sits on. */
function computeMerklePath(leaves: bigint[], index: number): TaxAuditInclusionStep[] {
  if (index < 0 || index >= leaves.length) throw new Error("The Merkle leaf index is out of range.");
  const path: TaxAuditInclusionStep[] = [];
  let level = leaves.slice();
  let idx = index;
  while (level.length > 1) {
    const isRightNode = idx % 2 === 1;
    const siblingIndex = isRightNode ? idx - 1 : idx + 1;
    const sibling = siblingIndex < level.length ? level[siblingIndex] : level[idx];
    path.push({ sibling: toHex(sibling), position: isRightNode ? "left" : "right" });
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(hashMerkleNode(level[i], right));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return path;
}

function verifyMerklePath(leaf: bigint, path: TaxAuditInclusionStep[], root: bigint): boolean {
  let node = leaf;
  for (const step of path) {
    const sibling = requireFelt(step.sibling, "Merkle sibling");
    if (step.position === "left") node = hashMerkleNode(sibling, node);
    else if (step.position === "right") node = hashMerkleNode(node, sibling);
    else return false;
  }
  return node === root;
}
interface AssetBucket {
  assetSymbol: string;
  assetTokenAddress: string;
  assetDecimals: number;
  entryCount: number;
  gross: bigint;
  fee: bigint;
  net: bigint;
}

/** Per-asset gross/fee/net totals, grouped by token address in first-appearance order with exact integer sums. */
function buildAssetTotals(entries: TaxAuditEntry[]): TaxAuditAssetTotal[] {
  const order: string[] = [];
  const buckets = new Map<string, AssetBucket>();
  for (const entry of entries) {
    const key = entry.assetTokenAddress;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { assetSymbol: entry.assetSymbol, assetTokenAddress: entry.assetTokenAddress, assetDecimals: entry.assetDecimals, entryCount: 0, gross: 0n, fee: 0n, net: 0n };
      buckets.set(key, bucket);
      order.push(key);
    } else if (bucket.assetSymbol !== entry.assetSymbol || bucket.assetDecimals !== entry.assetDecimals) {
      throw new Error("The same asset appears with an inconsistent symbol or decimals.");
    }
    bucket.entryCount += 1;
    bucket.gross += BigInt(entry.grossBaseUnits);
    bucket.fee += BigInt(entry.feeBaseUnits);
    bucket.net += BigInt(entry.netBaseUnits);
  }
  return order.map((key) => {
    const b = buckets.get(key) as AssetBucket;
    requireU128(b.gross, "Asset gross total");
    requireU128(b.fee, "Asset fee total");
    requireU128(b.net, "Asset net total");
    return {
      assetSymbol: b.assetSymbol,
      assetTokenAddress: b.assetTokenAddress,
      assetDecimals: b.assetDecimals,
      entryCount: b.entryCount,
      grossBaseUnits: b.gross.toString(),
      feeBaseUnits: b.fee.toString(),
      netBaseUnits: b.net.toString(),
      grossDisplay: formatBaseUnits(b.gross, b.assetDecimals),
      feeDisplay: formatBaseUnits(b.fee, b.assetDecimals),
      netDisplay: formatBaseUnits(b.net, b.assetDecimals),
    };
  });
}
interface CategoryBucket {
  category: string;
  assetSymbol: string;
  assetTokenAddress: string;
  assetDecimals: number;
  entryCount: number;
  gross: bigint;
  net: bigint;
}

/** Per-category, per-asset gross/net totals, grouped by (category, token address) in first-appearance order. */
function buildCategoryTotals(entries: TaxAuditEntry[]): TaxAuditCategoryTotal[] {
  const order: string[] = [];
  const buckets = new Map<string, CategoryBucket>();
  for (const entry of entries) {
    const key = `${entry.category} ${entry.assetTokenAddress}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { category: entry.category, assetSymbol: entry.assetSymbol, assetTokenAddress: entry.assetTokenAddress, assetDecimals: entry.assetDecimals, entryCount: 0, gross: 0n, net: 0n };
      buckets.set(key, bucket);
      order.push(key);
    } else if (bucket.assetSymbol !== entry.assetSymbol || bucket.assetDecimals !== entry.assetDecimals) {
      throw new Error("The same asset appears with an inconsistent symbol or decimals.");
    }
    bucket.entryCount += 1;
    bucket.gross += BigInt(entry.grossBaseUnits);
    bucket.net += BigInt(entry.netBaseUnits);
  }
  return order.map((key) => {
    const b = buckets.get(key) as CategoryBucket;
    requireU128(b.gross, "Category gross total");
    requireU128(b.net, "Category net total");
    return {
      category: b.category,
      assetSymbol: b.assetSymbol,
      assetTokenAddress: b.assetTokenAddress,
      assetDecimals: b.assetDecimals,
      entryCount: b.entryCount,
      grossBaseUnits: b.gross.toString(),
      netBaseUnits: b.net.toString(),
      grossDisplay: formatBaseUnits(b.gross, b.assetDecimals),
      netDisplay: formatBaseUnits(b.net, b.assetDecimals),
    };
  });
}
function computeProfileCommitment(p: Omit<TaxAuditProfile, "profileCommitment">): bigint {
  return hashElements([
    PROFILE_DOMAIN,
    BigInt(p.version),
    requireFelt(p.profileSalt, "Profile salt"),
    BigInt(hash.starknetKeccak(p.profileId)),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(p.merchant),
    BigInt(hash.starknetKeccak(p.jurisdiction || "none")),
    BigInt(hash.starknetKeccak(p.memo || "empty")),
    secondsOf(p.createdAt),
  ]);
}

function computeEntryCommitment(e: Omit<TaxAuditEntry, "entryCommitment">): bigint {
  return hashElements([
    ENTRY_DOMAIN,
    BigInt(e.version),
    requireFelt(e.entrySalt, "Entry salt"),
    BigInt(hash.starknetKeccak(e.entryId)),
    requireFelt(e.profileCommitment, "Profile commitment"),
    BigInt(hash.starknetKeccak(e.invoiceId)),
    requireFelt(e.transactionHash, "Transaction hash"),
    BigInt(hash.starknetKeccak(e.assetSymbol)),
    BigInt(e.assetTokenAddress),
    BigInt(e.assetDecimals),
    BigInt(e.grossBaseUnits),
    BigInt(e.feeBaseUnits),
    BigInt(e.netBaseUnits),
    BigInt(hash.starknetKeccak(e.category)),
    secondsOf(e.settledAt),
    BigInt(hash.starknetKeccak(e.counterpartyRef || "none")),
    BigInt(hash.starknetKeccak(e.memo || "empty")),
  ]);
}
function computeAssetTotalsHash(totals: TaxAuditAssetTotal[]): bigint {
  const elements: bigint[] = [ASSET_TOTALS_DOMAIN, BigInt(totals.length)];
  for (const t of totals) {
    elements.push(
      BigInt(hash.starknetKeccak(t.assetSymbol)),
      BigInt(t.assetTokenAddress),
      BigInt(t.assetDecimals),
      BigInt(t.entryCount),
      BigInt(t.grossBaseUnits),
      BigInt(t.feeBaseUnits),
      BigInt(t.netBaseUnits),
    );
  }
  return hashElements(elements);
}

function computeCategoryTotalsHash(totals: TaxAuditCategoryTotal[]): bigint {
  const elements: bigint[] = [CATEGORY_TOTALS_DOMAIN, BigInt(totals.length)];
  for (const t of totals) {
    elements.push(
      BigInt(hash.starknetKeccak(t.category)),
      BigInt(hash.starknetKeccak(t.assetSymbol)),
      BigInt(t.assetTokenAddress),
      BigInt(t.assetDecimals),
      BigInt(t.entryCount),
      BigInt(t.grossBaseUnits),
      BigInt(t.netBaseUnits),
    );
  }
  return hashElements(elements);
}

function computeTotalsHash(
  assetTotals: TaxAuditAssetTotal[],
  categoryTotals: TaxAuditCategoryTotal[],
  entryCount: number,
): bigint {
  return hashElements([
    TOTALS_DOMAIN,
    BigInt(entryCount),
    computeAssetTotalsHash(assetTotals),
    computeCategoryTotalsHash(categoryTotals),
  ]);
}
function computeBundleCommitment(b: Omit<TaxAuditBundle, "bundleCommitment">): bigint {
  return hashElements([
    BUNDLE_DOMAIN,
    BigInt(b.version),
    requireFelt(b.bundleSalt, "Bundle salt"),
    BigInt(hash.starknetKeccak(b.bundleId)),
    requireFelt(b.profileCommitment, "Profile commitment"),
    secondsOf(b.periodStart),
    secondsOf(b.periodEnd),
    secondsOf(b.generatedAt),
    BigInt(b.entryCount),
    requireFelt(b.merkleRoot, "Merkle root"),
    computeTotalsHash(b.assetTotals, b.categoryTotals, b.entryCount),
  ]);
}

/** The transcript the export authorization is bound to: the bundle, its root, period, and totals hash. */
function authTranscript(input: {
  bundleId: string;
  profileCommitment: string;
  merkleRoot: string;
  periodStart: string;
  periodEnd: string;
  totalsHash: string;
}): bigint[] {
  return [
    BigInt(hash.starknetKeccak(input.bundleId)),
    requireFelt(input.profileCommitment, "Profile commitment"),
    requireFelt(input.merkleRoot, "Merkle root"),
    secondsOf(input.periodStart),
    secondsOf(input.periodEnd),
    requireFelt(input.totalsHash, "Totals hash"),
  ];
}
function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== TAX_AUDIT_LIMITATIONS.length || value.some((entry, index) => entry !== TAX_AUDIT_LIMITATIONS[index])) {
    throw new Error("The tax-audit limitations were altered.");
  }
}

function assertPoint(value: unknown, label: string): asserts value is TaxAuditCurvePoint {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, POINT_KEYS)) throw new Error(`${label} is invalid.`);
  pointFromFelts(value as TaxAuditCurvePoint, label);
}

function assertProof(value: unknown, label: string): asserts value is TaxAuditSchnorrProof {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PROOF_KEYS)) throw new Error(`${label} is invalid.`);
  const proof = value as TaxAuditSchnorrProof;
  assertPoint(proof.nonceCommitment, `${label} nonce`);
  requireCurveScalar(proof.response, true, `${label} response`);
}

function assertTaxAuditAsset(symbol: string, tokenAddress: string, decimals: number, label: string): void {
  requireSymbol(symbol, `${label} symbol`);
  requireDecimals(decimals, `${label} decimals`);
  if (!tokenAddress || tokenAddress !== normalizeStarknetAddress(tokenAddress)) throw new Error(`${label} token address is not canonical.`);
}

function assertPathStep(value: unknown): asserts value is TaxAuditInclusionStep {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PATH_STEP_KEYS)) throw new Error("A Merkle path step is invalid.");
  const step = value as TaxAuditInclusionStep;
  requireFelt(step.sibling, "Merkle sibling");
  if (step.position !== "left" && step.position !== "right") throw new Error("A Merkle path step side is invalid.");
}
function requireEntryCount(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_ENTRIES_PER_BUNDLE) {
    throw new Error(`${label} must be an integer between 1 and ${MAX_ENTRIES_PER_BUNDLE}.`);
  }
  return value;
}

function assertAssetTotal(value: unknown): asserts value is TaxAuditAssetTotal {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ASSET_TOTAL_KEYS)) throw new Error("An asset total is invalid.");
  const t = value as TaxAuditAssetTotal;
  assertTaxAuditAsset(t.assetSymbol, t.assetTokenAddress, t.assetDecimals, "Asset total");
  requireEntryCount(t.entryCount, "Asset total entry count");
  const gross = requireU128(requireBaseUnitString(t.grossBaseUnits, "Asset gross total"), "Asset gross total");
  const fee = requireU128(requireBaseUnitString(t.feeBaseUnits, "Asset fee total"), "Asset fee total");
  const net = requireU128(requireBaseUnitString(t.netBaseUnits, "Asset net total"), "Asset net total");
  if (fee + net !== gross) throw new Error("An asset total's fee and net do not sum to its gross.");
  if (t.grossDisplay !== formatBaseUnits(gross, t.assetDecimals)
    || t.feeDisplay !== formatBaseUnits(fee, t.assetDecimals)
    || t.netDisplay !== formatBaseUnits(net, t.assetDecimals)) throw new Error("An asset total display is inconsistent.");
}

function assertCategoryTotal(value: unknown): asserts value is TaxAuditCategoryTotal {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, CATEGORY_TOTAL_KEYS)) throw new Error("A category total is invalid.");
  const t = value as TaxAuditCategoryTotal;
  requireText(t.category, "Category", 48);
  assertTaxAuditAsset(t.assetSymbol, t.assetTokenAddress, t.assetDecimals, "Category total");
  requireEntryCount(t.entryCount, "Category total entry count");
  const gross = requireU128(requireBaseUnitString(t.grossBaseUnits, "Category gross total"), "Category gross total");
  const net = requireU128(requireBaseUnitString(t.netBaseUnits, "Category net total"), "Category net total");
  if (net > gross) throw new Error("A category total's net exceeds its gross.");
  if (t.grossDisplay !== formatBaseUnits(gross, t.assetDecimals)
    || t.netDisplay !== formatBaseUnits(net, t.assetDecimals)) throw new Error("A category total display is inconsistent.");
}
function assertTaxAuditProfile(value: unknown): asserts value is TaxAuditProfile {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PROFILE_KEYS)) throw new Error("Tax-audit profile is invalid.");
  const p = value as TaxAuditProfile;
  if (p.kind !== PROFILE_KIND || p.version !== TAX_AUDIT_ENGINE_VERSION || p.network !== MAINNET_CHAIN_ID
    || p.poolAddress !== STRK20_POOL_ADDRESS || p.notice !== TAX_AUDIT_NOTICE
    || !/^tap_[A-Za-z0-9_-]{1,48}$/.test(p.profileId)) throw new Error("Tax-audit profile header is invalid.");
  assertLimitations(p.limitations);
  if (!p.merchant || p.merchant !== normalizeStarknetAddress(p.merchant)) throw new Error("The merchant address is not canonical.");
  if (typeof p.jurisdiction !== "string" || p.jurisdiction.length > 64) throw new Error("The jurisdiction is invalid.");
  if (typeof p.memo !== "string" || p.memo.length > 280) throw new Error("The profile memo is invalid.");
  requireIsoTimestamp(p.createdAt, "Profile creation time");
  requireFelt(p.profileSalt, "Profile salt");
  if (requireFelt(p.profileCommitment, "Profile commitment") !== computeProfileCommitment(p)) throw new Error("The profile commitment does not match its contents.");
}

function assertTaxAuditEntry(value: unknown): asserts value is TaxAuditEntry {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ENTRY_KEYS)) throw new Error("Tax-audit entry is invalid.");
  const e = value as TaxAuditEntry;
  if (e.kind !== ENTRY_KIND || e.version !== TAX_AUDIT_ENGINE_VERSION || e.network !== MAINNET_CHAIN_ID
    || e.poolAddress !== STRK20_POOL_ADDRESS || typeof e.notice !== "string"
    || !/^tae_[A-Za-z0-9_-]{1,48}$/.test(e.entryId)) throw new Error("Tax-audit entry header is invalid.");
  requireFelt(e.profileCommitment, "Profile commitment");
  requireText(e.invoiceId, "Invoice ID", 96);
  requireFelt(e.transactionHash, "Transaction hash");
  assertTaxAuditAsset(e.assetSymbol, e.assetTokenAddress, e.assetDecimals, "Settlement asset");
  const gross = requireU128(requireBaseUnitString(e.grossBaseUnits, "Gross amount"), "Gross amount");
  const fee = requireU128(requireBaseUnitString(e.feeBaseUnits, "Fee amount"), "Fee amount");
  const net = requireU128(requireBaseUnitString(e.netBaseUnits, "Net amount"), "Net amount");
  if (gross <= 0n) throw new Error("The gross amount must be positive.");
  if (fee > gross) throw new Error("The fee cannot exceed the gross amount.");
  if (net !== gross - fee) throw new Error("The net amount does not equal gross minus fee.");
  requireText(e.category, "Tax category", 48);
  requireIsoTimestamp(e.settledAt, "Settlement time");
  if (typeof e.counterpartyRef !== "string" || e.counterpartyRef.length > 96) throw new Error("The counterparty reference is invalid.");
  if (typeof e.memo !== "string" || e.memo.length > 200) throw new Error("The entry memo is invalid.");
  requireFelt(e.entrySalt, "Entry salt");
  if (requireFelt(e.entryCommitment, "Entry commitment") !== computeEntryCommitment(e)) throw new Error("The entry commitment does not match its contents.");
}
function assertTaxAuditBundle(value: unknown): asserts value is TaxAuditBundle {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, BUNDLE_KEYS)) throw new Error("Tax-audit bundle is invalid.");
  const b = value as TaxAuditBundle;
  if (b.kind !== BUNDLE_KIND || b.version !== TAX_AUDIT_ENGINE_VERSION || b.network !== MAINNET_CHAIN_ID
    || b.poolAddress !== STRK20_POOL_ADDRESS || b.notice !== TAX_AUDIT_NOTICE
    || !/^tab_[A-Za-z0-9_-]{1,48}$/.test(b.bundleId)) throw new Error("Tax-audit bundle header is invalid.");
  assertLimitations(b.limitations);
  requireFelt(b.profileCommitment, "Profile commitment");
  requireIsoTimestamp(b.periodStart, "Period start");
  requireIsoTimestamp(b.periodEnd, "Period end");
  if (Date.parse(b.periodEnd) < Date.parse(b.periodStart)) throw new Error("The period end cannot precede the period start.");
  requireIsoTimestamp(b.generatedAt, "Generation time");
  if (!Array.isArray(b.entries)) throw new Error("The bundle entries are invalid.");
  requireEntryCount(b.entries.length, "Bundle entry count");
  if (b.entryCount !== b.entries.length) throw new Error("The bundle entry count is inconsistent.");
  const seenIds = new Set<string>();
  const seenCommitments = new Set<string>();
  for (const entry of b.entries) {
    assertTaxAuditEntry(entry);
    if (entry.profileCommitment !== b.profileCommitment) throw new Error("A bundle entry belongs to a different profile.");
    const settledMs = Date.parse(entry.settledAt);
    if (settledMs < Date.parse(b.periodStart) || settledMs > Date.parse(b.periodEnd)) throw new Error("A bundle entry settled outside the period.");
    if (seenIds.has(entry.entryId) || seenCommitments.has(entry.entryCommitment)) throw new Error("The bundle contains a duplicate entry.");
    seenIds.add(entry.entryId);
    seenCommitments.add(entry.entryCommitment);
  }
  if (!Array.isArray(b.assetTotals) || !Array.isArray(b.categoryTotals)) throw new Error("The bundle totals are invalid.");
  for (const total of b.assetTotals) assertAssetTotal(total);
  for (const total of b.categoryTotals) assertCategoryTotal(total);
  if (canonical(b.assetTotals) !== canonical(buildAssetTotals(b.entries))) throw new Error("The bundle asset totals do not match its entries.");
  if (canonical(b.categoryTotals) !== canonical(buildCategoryTotals(b.entries))) throw new Error("The bundle category totals do not match its entries.");
  const root = computeMerkleRoot(b.entries.map((entry) => requireFelt(entry.entryCommitment, "Entry commitment")));
  if (requireFelt(b.merkleRoot, "Merkle root") !== root) throw new Error("The bundle Merkle root does not match its entries.");
  requireFelt(b.bundleSalt, "Bundle salt");
  if (requireFelt(b.bundleCommitment, "Bundle commitment") !== computeBundleCommitment(b)) throw new Error("The bundle commitment does not match its contents.");
}
function assertTaxAuditBundleDigest(value: unknown): asserts value is TaxAuditBundleDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, BUNDLE_DIGEST_KEYS)) throw new Error("Tax-audit bundle digest is invalid.");
  const d = value as TaxAuditBundleDigest;
  if (d.kind !== BUNDLE_DIGEST_KIND || d.version !== TAX_AUDIT_ENGINE_VERSION || d.network !== MAINNET_CHAIN_ID
    || d.poolAddress !== STRK20_POOL_ADDRESS || d.notice !== TAX_AUDIT_NOTICE
    || !/^tab_[A-Za-z0-9_-]{1,48}$/.test(d.bundleId)) throw new Error("Tax-audit bundle digest header is invalid.");
  assertLimitations(d.limitations);
  requireFelt(d.profileCommitment, "Profile commitment");
  requireIsoTimestamp(d.periodStart, "Period start");
  requireIsoTimestamp(d.periodEnd, "Period end");
  if (Date.parse(d.periodEnd) < Date.parse(d.periodStart)) throw new Error("The period end cannot precede the period start.");
  requireEntryCount(d.entryCount, "Digest entry count");
  requireFelt(d.merkleRoot, "Merkle root");
  if (!Array.isArray(d.assetTotals) || d.assetTotals.length === 0 || !Array.isArray(d.categoryTotals)) throw new Error("The digest totals are invalid.");
  for (const total of d.assetTotals) assertAssetTotal(total);
  for (const total of d.categoryTotals) assertCategoryTotal(total);
  requireFelt(d.bundleCommitment, "Bundle commitment");
}

function assertTaxAuditInclusionProof(value: unknown): asserts value is TaxAuditInclusionProof {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, INCLUSION_KEYS)) throw new Error("Tax-audit inclusion proof is invalid.");
  const p = value as TaxAuditInclusionProof;
  if (p.kind !== INCLUSION_KIND || p.version !== TAX_AUDIT_ENGINE_VERSION || typeof p.notice !== "string"
    || !/^tab_[A-Za-z0-9_-]{1,48}$/.test(p.bundleId)) throw new Error("Tax-audit inclusion proof header is invalid.");
  requireFelt(p.profileCommitment, "Profile commitment");
  requireFelt(p.merkleRoot, "Merkle root");
  assertTaxAuditEntry(p.entry);
  if (p.entry.profileCommitment !== p.profileCommitment) throw new Error("The disclosed entry belongs to a different profile.");
  if (!Array.isArray(p.path) || p.path.length > 64) throw new Error("The inclusion path is invalid.");
  for (const step of p.path) assertPathStep(step);
}

function assertTaxAuditAuthorization(value: unknown): asserts value is TaxAuditAuthorization {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, AUTH_KEYS)) throw new Error("The export authorization is invalid.");
  const a = value as TaxAuditAuthorization;
  if (a.kind !== AUTH_KIND || a.version !== TAX_AUDIT_ENGINE_VERSION || a.proofSystem !== TAX_AUDIT_PROOF_SYSTEM
    || typeof a.notice !== "string" || !a.notice.includes("exporter key")
    || !/^tab_[A-Za-z0-9_-]{1,48}$/.test(a.bundleId)) throw new Error("The export authorization header is invalid.");
  requireFelt(a.profileCommitment, "Profile commitment");
  requireFelt(a.merkleRoot, "Merkle root");
  requireIsoTimestamp(a.periodStart, "Period start");
  requireIsoTimestamp(a.periodEnd, "Period end");
  requireFelt(a.totalsHash, "Totals hash");
  assertPoint(a.exporterPublicKey, "Exporter public key");
  assertProof(a.proof, "Export proof");
}
