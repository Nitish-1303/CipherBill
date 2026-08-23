/**
 * Merchant affiliate & referral reward planner for CipherBill.
 *
 * WHAT THIS IS
 * - A client-side affiliate program: a merchant commits to a payout asset and a ladder of commission
 *   tiers (a tier is a cumulative-volume threshold and a basis-point rate). Everything is computed with
 *   exact integer math in one browser.
 * - Referral accounts and links: an affiliate is recorded by their in-pool payout address and a claim
 *   public key they hold the secret for. Each account derives an opaque, salted referral code that leaks
 *   no address, and a shareable link built from it.
 * - A local attribution ledger: the merchant records referrals (an invoice attributed to an affiliate for
 *   a commissionable volume) as salted Poseidon commitments, then sums an affiliate's volume, resolves the
 *   tier it lands in, and floor-rounds the commission so the merchant never overpays.
 * - A single-token payout builder: for a computed commission it composes exactly one private in-pool STRK20
 *   `transfer` of the payout asset from the merchant to the affiliate, which the merchant's wallet signs.
 * - Disclosable payout receipts binding the program commitment, the affiliate, the resolved tier, the
 *   commission, a claimed payout time, and the transaction hash.
 * - An optional Schnorr zero-knowledge proof of knowledge — the "claim authorization" — by which an
 *   affiliate proves knowledge of their claim key bound to a specific payout without revealing it. This is
 *   the ONLY zero-knowledge element here; it attests who is claiming, it does not price or pay.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not decentralized. The program, tiers, attributions, and commissions are local computations in one
 *   browser. There is no on-chain registry, oracle, or affiliate contract; `STRK20_POOL_ADDRESS` is
 *   recorded as provenance for the payout leg, not a contract that tracks referrals or computes rewards.
 * - Not automatic. Nothing pays an affiliate on its own. A commission is arithmetic on a ledger the
 *   merchant keeps; the payout happens only when the merchant voluntarily signs one in-pool transfer.
 * - Not zero-knowledge as a system, and it does not privately verify referrals. The program commitment,
 *   account and referral commitments, and receipts are salted Poseidon hashes, not zero-knowledge proofs;
 *   only the optional claim authorization is a zero-knowledge proof, and it proves knowledge of a key,
 *   never a volume, a commission, or a payment.
 * - Not anonymous end to end. In-pool transfers hide the payout's parties, token, and amount, but a
 *   distinctive commission amount, a payout tied to a known program, or a deposit or withdrawal edge stays
 *   public, and timing, fees, and nullifiers are observable.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";
export const AFFILIATE_ENGINE_VERSION = 1 as const;
export const AFFILIATE_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const AFFILIATE_CLAIM_PROOF_SYSTEM = "stark-schnorr-affiliate-claim-v1" as const;
export const MAX_ASSET_DECIMALS = 18;
export const MIN_TIERS = 1;
export const MAX_TIERS = 8;
export const MIN_RATE_BPS = 1;
export const MAX_RATE_BPS = 10_000; // 100%, the widest commission the composer offers
export const BPS_DENOMINATOR = 10_000;
export const AFFILIATE_SALT_BYTES = 31;
export const DEFAULT_PROGRAM_TTL_DAYS = 90;
export const MAX_PROGRAM_TTL_DAYS = 3_650; // 10 years
export const DAY_MS = 86_400_000;
export const MAX_REFERRALS_PER_REWARD = 4_096;

export const AFFILIATE_NOTICE =
  "Client-side merchant affiliate program and single-token payout plan. A merchant commits to a payout " +
  "asset and commission tiers, records referral attributions as salted Poseidon hashes, and this browser " +
  "sums an affiliate's volume, resolves the tier, and floor-rounds the commission with exact integer math. " +
  "There is no on-chain registry, oracle, or automatic payout; the merchant pays by voluntarily signing one " +
  "private in-pool transfer. The commitments and receipts are hashes rather than proofs, and only the " +
  "optional claim authorization is a zero-knowledge proof.";

export const AFFILIATE_LIMITATIONS: readonly string[] = [
  "Nothing here is decentralized. The program, tiers, attributions, and commissions are local computations " +
    "in one browser; no contract tracks referrals, resolves tiers, or pays anyone.",
  "Nothing is automatic. A commission is arithmetic over a ledger the merchant keeps; an affiliate is paid " +
    "only when the merchant voluntarily signs one in-pool transfer of the payout asset.",
  "The referral attribution is asserted, not proven. The merchant decides which invoice volume counts; the " +
    "engine validates the arithmetic and commits the ledger, but cannot vouch that an attribution is real.",
  "The program, account, and referral commitments and the payout receipt are salted Poseidon hashes, not " +
    "zero-knowledge proofs, and no contract verifies them. Only the optional claim authorization is a " +
    "zero-knowledge proof, and it proves knowledge of a claim key, not a volume, a commission, or a payment.",
  "A payout receipt records a claimed payout and its resolved tier; a self-issued receipt is internally " +
    "consistent but is not independent proof the transfer settled. Confirm the transaction hash on-chain.",
  "In-pool transfers hide the payout's sender, recipient, token, and amount, but a distinctive commission " +
    "amount or a payout tied to a known program is a correlation signal, and timing, fees, nullifiers, and " +
    "any deposit or withdrawal edge stay public.",
];

const PROGRAM_KIND = "cipherbill.affiliate-program";
const ACCOUNT_KIND = "cipherbill.affiliate-account";
const REFERRAL_KIND = "cipherbill.affiliate-referral";
const PROGRAM_DIGEST_KIND = "cipherbill.affiliate-program-digest";
const PAYOUT_RECEIPT_KIND = "cipherbill.affiliate-payout-receipt";
const CLAIM_AUTH_KIND = "cipherbill.affiliate-claim-authorization";
const PROGRAM_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate program v1"));
const TIER_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate tier v1"));
const ACCOUNT_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate account v1"));
const REFERRAL_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate referral v1"));
const REFERRAL_CODE_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate referral code v1"));
const RECEIPT_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate payout receipt v1"));
const CLAIM_DOMAIN = BigInt(hash.starknetKeccak("CipherBill affiliate claim authorization v1"));
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const BASE = ec.starkCurve.ProjectivePoint.BASE;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 200_000;

const PROGRAM_KEYS = [
  "kind", "version", "programId", "network", "poolAddress", "merchant", "asset", "tiers", "createdAt",
  "expiresAt", "memo", "programSalt", "programCommitment", "notice", "limitations",
] as const;
const ASSET_KEYS = ["symbol", "tokenAddress", "decimals"] as const;
const TIER_KEYS = ["name", "minVolumeBaseUnits", "minVolumeDisplay", "rateBps"] as const;
const ACCOUNT_KEYS = [
  "kind", "version", "affiliateId", "network", "poolAddress", "programCommitment", "label", "payoutAddress",
  "claimPublicKey", "referralCode", "accountSalt", "accountCommitment", "notice",
] as const;
const REFERRAL_KEYS = [
  "kind", "version", "referralId", "network", "poolAddress", "programCommitment", "affiliateId", "invoiceId",
  "volumeBaseUnits", "volumeDisplay", "occurredAt", "referralSalt", "referralCommitment", "notice",
] as const;
const PROGRAM_DIGEST_KEYS = [
  "kind", "version", "programId", "network", "poolAddress", "assetSymbol", "assetDecimals", "tierCount",
  "tiersHash", "hasMemo", "createdAt", "expiresAt", "memoHash", "programCommitment", "notice", "limitations",
] as const;
const PAYOUT_RECEIPT_KEYS = [
  "kind", "version", "programId", "network", "poolAddress", "programCommitment", "affiliateId", "assetSymbol",
  "assetTokenAddress", "totalVolumeBaseUnits", "tierName", "tierRateBps", "commissionBaseUnits", "paidAt",
  "transactionHash", "receiptCommitment", "notice", "limitations",
] as const;
const CLAIM_AUTH_KEYS = [
  "kind", "version", "proofSystem", "programCommitment", "affiliateId", "assetTokenAddress",
  "commissionBaseUnits", "period", "claimPublicKey", "proof", "notice",
] as const;
const POINT_KEYS = ["x", "y"] as const;
const PROOF_KEYS = ["nonceCommitment", "response"] as const;
export interface AffiliateCurvePoint {
  x: string;
  y: string;
}

export interface AffiliateSchnorrProof {
  nonceCommitment: AffiliateCurvePoint;
  response: string;
}

export interface AffiliateAssetInput {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface AffiliateTierInput {
  name: string;
  minVolume: string;
  rateBps: number;
}

export interface CreateAffiliateProgramInput {
  programId?: string;
  merchant: string;
  asset: AffiliateAssetInput;
  tiers: AffiliateTierInput[];
  validForDays?: number;
  memo?: string;
}

export interface AffiliateAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface CommissionTier {
  name: string;
  minVolumeBaseUnits: string;
  minVolumeDisplay: string;
  rateBps: number;
}

export interface AffiliateProgram {
  kind: typeof PROGRAM_KIND;
  version: typeof AFFILIATE_ENGINE_VERSION;
  programId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  merchant: string;
  asset: AffiliateAsset;
  tiers: CommissionTier[];
  createdAt: string;
  expiresAt: string;
  memo: string;
  programSalt: string;
  programCommitment: string;
  notice: typeof AFFILIATE_NOTICE;
  limitations: string[];
}
export interface RegisterAffiliateInput {
  affiliateId?: string;
  label?: string;
  payoutAddress: string;
  claimPublicKey: AffiliateCurvePoint;
}

export interface AffiliateAccount {
  kind: typeof ACCOUNT_KIND;
  version: typeof AFFILIATE_ENGINE_VERSION;
  affiliateId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  programCommitment: string;
  label: string;
  payoutAddress: string;
  claimPublicKey: AffiliateCurvePoint;
  referralCode: string;
  accountSalt: string;
  accountCommitment: string;
  notice: string;
}

export interface AffiliateClaimKey {
  claimSecret: string;
  claimPublicKey: AffiliateCurvePoint;
}

export interface RecordReferralInput {
  referralId?: string;
  invoiceId: string;
  volume: string;
}

export interface AffiliateReferral {
  kind: typeof REFERRAL_KIND;
  version: typeof AFFILIATE_ENGINE_VERSION;
  referralId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  programCommitment: string;
  affiliateId: string;
  invoiceId: string;
  volumeBaseUnits: string;
  volumeDisplay: string;
  occurredAt: string;
  referralSalt: string;
  referralCommitment: string;
  notice: string;
}

export interface RewardStatement {
  affiliateId: string;
  referralCount: number;
  totalVolumeBaseUnits: string;
  totalVolumeDisplay: string;
  tierName: string;
  tierRateBps: number;
  commissionBaseUnits: string;
  commissionDisplay: string;
}
export interface AffiliatePayoutInput {
  totalVolumeBaseUnits: string | bigint;
  tierName: string;
  tierRateBps: number;
  commissionBaseUnits: string | bigint;
  paidAt: string;
  transactionHash: string;
}

export interface AffiliatePayoutReceipt {
  kind: typeof PAYOUT_RECEIPT_KIND;
  version: typeof AFFILIATE_ENGINE_VERSION;
  programId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  programCommitment: string;
  affiliateId: string;
  assetSymbol: string;
  assetTokenAddress: string;
  totalVolumeBaseUnits: string;
  tierName: string;
  tierRateBps: number;
  commissionBaseUnits: string;
  paidAt: string;
  transactionHash: string;
  receiptCommitment: string;
  notice: typeof AFFILIATE_NOTICE;
  limitations: string[];
}

export interface AffiliateClaimInput {
  commissionBaseUnits: string | bigint;
  period: string;
}

export interface AffiliateClaimAuthorization {
  kind: typeof CLAIM_AUTH_KIND;
  version: typeof AFFILIATE_ENGINE_VERSION;
  proofSystem: typeof AFFILIATE_CLAIM_PROOF_SYSTEM;
  programCommitment: string;
  affiliateId: string;
  assetTokenAddress: string;
  commissionBaseUnits: string;
  period: string;
  claimPublicKey: AffiliateCurvePoint;
  proof: AffiliateSchnorrProof;
  notice: string;
}

export interface AffiliateProgramDigest {
  kind: typeof PROGRAM_DIGEST_KIND;
  version: typeof AFFILIATE_ENGINE_VERSION;
  programId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  assetSymbol: string;
  assetDecimals: number;
  tierCount: number;
  tiersHash: string;
  hasMemo: boolean;
  createdAt: string;
  expiresAt: string;
  memoHash: string;
  programCommitment: string;
  notice: typeof AFFILIATE_NOTICE;
  limitations: string[];
}

export interface AffiliateProgramOpening {
  programId: string;
  programCommitment: string;
  program: AffiliateProgram;
}
export interface TierPreview {
  name: string;
  minVolumeDisplay: string;
  rateBps: number;
}

export interface AffiliateRewardPreview {
  assetSymbol: string;
  totalVolumeDisplay: string;
  tierName: string;
  tierRateBps: number;
  commissionDisplay: string;
  tiers: TierPreview[];
}

export interface AffiliateVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface AffiliateTrustSummary {
  fundHolder: string;
  isDecentralized: boolean;
  isAutomatic: boolean;
  provesReferral: boolean;
  provesPayment: boolean;
  ledgerSource: string;
  zeroKnowledgeElement: string;
  trustedParties: string[];
  statement: string;
}

export interface AffiliateEntropy {
  createId?: (kind: "program" | "account" | "referral") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export interface AffiliateClaimKeyEntropy {
  claimSecret?: bigint;
  nonce?: bigint;
}
export function createAffiliateProgram(
  input: CreateAffiliateProgramInput,
  now: Date = new Date(),
  entropy: AffiliateEntropy = {},
): AffiliateProgram {
  const merchant = normalizeStarknetAddress(input.merchant);
  const asset = normalizeAsset(input.asset);
  const tiers = normalizeTiers(input.tiers, asset.decimals);
  const validForDays = requireDays(input.validForDays, "Program validity");
  const memo = requireOptionalText(input.memo, "Program memo", 280);

  const createdMs = requireInstant(now, "Program time");
  const createdAt = new Date(createdMs).toISOString();
  const expiresAt = new Date(createdMs + validForDays * DAY_MS).toISOString();
  const programId = makeId(entropy.createId?.("program"), "afp");
  const programSalt = toHex(randomFelt(entropy.randomBytes));

  const program: AffiliateProgram = {
    kind: PROGRAM_KIND,
    version: AFFILIATE_ENGINE_VERSION,
    programId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    merchant,
    asset,
    tiers,
    createdAt,
    expiresAt,
    memo,
    programSalt,
    programCommitment: "0x0",
    notice: AFFILIATE_NOTICE,
    limitations: [...AFFILIATE_LIMITATIONS],
  };
  program.programCommitment = toHex(computeProgramCommitment(program));
  return program;
}

export function verifyAffiliateProgram(program: AffiliateProgram): boolean {
  try {
    assertAffiliateProgram(program);
    return true;
  } catch {
    return false;
  }
}
export function registerAffiliateClaimKey(entropy: AffiliateClaimKeyEntropy = {}): AffiliateClaimKey {
  const secret = entropy.claimSecret === undefined
    ? randomScalar()
    : requireSecretScalar(entropy.claimSecret, "Affiliate claim secret");
  const publicKey = multiplyPoint(BASE, secret);
  return { claimSecret: toHex(secret), claimPublicKey: pointToFelts(publicKey) };
}

export function registerAffiliate(
  program: AffiliateProgram,
  input: RegisterAffiliateInput,
  entropy: AffiliateEntropy = {},
): AffiliateAccount {
  assertAffiliateProgram(program);
  const affiliateId = makeId(entropy.createId?.("account"), "afa");
  const label = requireOptionalText(input.label, "Affiliate label", 64);
  const payoutAddress = normalizeStarknetAddress(input.payoutAddress);
  const claimPublicKey = normalizePoint(input.claimPublicKey, "Affiliate claim public key");
  const accountSalt = toHex(randomFelt(entropy.randomBytes));

  const draft: Omit<AffiliateAccount, "accountCommitment" | "referralCode"> = {
    kind: ACCOUNT_KIND,
    version: AFFILIATE_ENGINE_VERSION,
    affiliateId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    programCommitment: program.programCommitment,
    label,
    payoutAddress,
    claimPublicKey,
    accountSalt,
    notice:
      "Client-side affiliate account. It records the payout address and the claim public key; the claim " +
      "secret is never held here. The referral code is derived from a salted commitment and leaks no address.",
  };
  const accountCommitment = toHex(computeAccountCommitment(draft));
  return { ...draft, referralCode: deriveReferralCode(accountCommitment), accountCommitment };
}

export function verifyAffiliateAccount(account: AffiliateAccount, program: AffiliateProgram): boolean {
  try {
    assertAffiliateAccount(account);
    assertAffiliateProgram(program);
    return account.programCommitment === program.programCommitment;
  } catch {
    return false;
  }
}

export function buildReferralLink(account: AffiliateAccount, baseUrl = "https://cipherbill.app/r"): string {
  assertAffiliateAccount(account);
  if (typeof baseUrl !== "string" || !/^https:\/\/[\w.-]+(?::\d+)?(?:\/[\w\-./]*)?$/.test(baseUrl.trim())) {
    throw new Error("A referral link base must be an https URL.");
  }
  const trimmed = baseUrl.trim().replace(/\/+$/, "");
  return `${trimmed}?ref=${account.referralCode}`;
}
export function recordReferral(
  program: AffiliateProgram,
  account: AffiliateAccount,
  input: RecordReferralInput,
  now: Date = new Date(),
  entropy: AffiliateEntropy = {},
): AffiliateReferral {
  assertAffiliateProgram(program);
  assertAffiliateAccount(account);
  if (account.programCommitment !== program.programCommitment) {
    throw new Error("The affiliate account belongs to a different program.");
  }
  const referralId = makeId(entropy.createId?.("referral"), "afr");
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 96);
  const volumeBaseUnits = parseDecimalToBaseUnits(input.volume, program.asset.decimals, "Referral volume");
  if (volumeBaseUnits <= 0n) throw new Error("The referral volume must be greater than zero.");
  requireU128(volumeBaseUnits, "Referral volume");
  const occurredMs = requireInstant(now, "Referral time");
  const occurredAt = new Date(occurredMs).toISOString();
  if (occurredMs < Date.parse(program.createdAt)) {
    throw new Error("A referral cannot occur before the program was created.");
  }

  const draft: Omit<AffiliateReferral, "referralCommitment"> = {
    kind: REFERRAL_KIND,
    version: AFFILIATE_ENGINE_VERSION,
    referralId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    programCommitment: program.programCommitment,
    affiliateId: account.affiliateId,
    invoiceId,
    volumeBaseUnits: volumeBaseUnits.toString(),
    volumeDisplay: formatBaseUnits(volumeBaseUnits, program.asset.decimals),
    occurredAt,
    referralSalt: toHex(randomFelt(entropy.randomBytes)),
    notice:
      "Client-side referral attribution. The merchant asserts this invoice volume counts for the affiliate; " +
      "the commitment binds it but does not prove it, and nothing here is on-chain.",
  };
  return { ...draft, referralCommitment: toHex(computeReferralCommitment(draft)) };
}

export function verifyAffiliateReferral(
  referral: AffiliateReferral,
  program: AffiliateProgram,
  account: AffiliateAccount,
): boolean {
  try {
    assertAffiliateReferral(referral);
    assertAffiliateProgram(program);
    assertAffiliateAccount(account);
    if (account.programCommitment !== program.programCommitment) return false;
    if (referral.programCommitment !== program.programCommitment) return false;
    return referral.affiliateId === account.affiliateId;
  } catch {
    return false;
  }
}
export function computeAffiliateReward(program: AffiliateProgram, referrals: AffiliateReferral[]): RewardStatement {
  assertAffiliateProgram(program);
  if (!Array.isArray(referrals)) throw new Error("A referral list is required.");
  if (referrals.length > MAX_REFERRALS_PER_REWARD) {
    throw new Error(`A reward covers at most ${MAX_REFERRALS_PER_REWARD} referrals.`);
  }
  let affiliateId: string | null = null;
  let total = 0n;
  for (const referral of referrals) {
    assertAffiliateReferral(referral);
    if (referral.programCommitment !== program.programCommitment) {
      throw new Error("A referral belongs to a different program.");
    }
    if (affiliateId === null) affiliateId = referral.affiliateId;
    else if (referral.affiliateId !== affiliateId) {
      throw new Error("A reward covers exactly one affiliate; the referrals mix affiliates.");
    }
    total += BigInt(referral.volumeBaseUnits);
  }
  requireU128(total, "Total attributed volume");
  const tier = resolveTier(program.tiers, total);
  // Commission floor-rounds so the merchant never overpays: commission = floor(volume * rateBps / 10000).
  const commission = (total * BigInt(tier.rateBps)) / BigInt(BPS_DENOMINATOR);
  requireU128(commission, "Commission amount");
  return {
    affiliateId: affiliateId ?? "",
    referralCount: referrals.length,
    totalVolumeBaseUnits: total.toString(),
    totalVolumeDisplay: formatBaseUnits(total, program.asset.decimals),
    tierName: tier.name,
    tierRateBps: tier.rateBps,
    commissionBaseUnits: commission.toString(),
    commissionDisplay: formatBaseUnits(commission, program.asset.decimals),
  };
}

export function previewAffiliateReward(input: {
  asset: AffiliateAssetInput;
  tiers: AffiliateTierInput[];
  volume: string;
}): AffiliateRewardPreview {
  const asset = normalizeAsset(input.asset);
  const tiers = normalizeTiers(input.tiers, asset.decimals);
  const total = parseDecimalToBaseUnits(input.volume, asset.decimals, "Volume");
  requireU128(total, "Volume");
  const tier = resolveTier(tiers, total);
  const commission = (total * BigInt(tier.rateBps)) / BigInt(BPS_DENOMINATOR);
  return {
    assetSymbol: asset.symbol,
    totalVolumeDisplay: formatBaseUnits(total, asset.decimals),
    tierName: tier.name,
    tierRateBps: tier.rateBps,
    commissionDisplay: formatBaseUnits(commission, asset.decimals),
    tiers: tiers.map((entry) => ({ name: entry.name, minVolumeDisplay: entry.minVolumeDisplay, rateBps: entry.rateBps })),
  };
}

function resolveTier(tiers: CommissionTier[], totalVolume: bigint): CommissionTier {
  let resolved = tiers[0];
  for (const tier of tiers) {
    if (totalVolume >= BigInt(tier.minVolumeBaseUnits)) resolved = tier;
  }
  return resolved;
}
export function buildPayoutActions(
  program: AffiliateProgram,
  account: AffiliateAccount,
  commissionBaseUnits: string | bigint,
): STRK20_ACTION[] {
  assertAffiliateProgram(program);
  assertAffiliateAccount(account);
  if (account.programCommitment !== program.programCommitment) {
    throw new Error("The affiliate account belongs to a different program.");
  }
  const amount = requireU128(coerceBaseUnits(commissionBaseUnits, "Commission amount"), "Commission amount");
  if (amount <= 0n) throw new Error("There is no commission to pay.");
  // Exactly one in-pool transfer of the commission. No second relayer-fee leg:
  // wallet_strk20InvokeTransaction is already gasless and the wallet withdraws the relayer fee itself.
  return [{ type: "transfer", token: program.asset.tokenAddress, amount: amount.toString(), recipient: account.payoutAddress }];
}

export function buildAffiliatePayoutReceipt(
  program: AffiliateProgram,
  account: AffiliateAccount,
  input: AffiliatePayoutInput,
): AffiliatePayoutReceipt {
  assertAffiliateProgram(program);
  assertAffiliateAccount(account);
  if (account.programCommitment !== program.programCommitment) {
    throw new Error("The affiliate account belongs to a different program.");
  }
  const tier = resolveTierByName(program.tiers, input.tierName, input.tierRateBps);
  const totalVolume = requireU128(coerceBaseUnits(input.totalVolumeBaseUnits, "Total volume"), "Total volume");
  const commission = requireU128(coerceBaseUnits(input.commissionBaseUnits, "Commission amount"), "Commission amount");
  const expected = (totalVolume * BigInt(tier.rateBps)) / BigInt(BPS_DENOMINATOR);
  if (commission !== expected) throw new Error("The commission does not match the tier rate and volume.");
  const paidAt = requireIsoTimestamp(input.paidAt, "Payout time");
  if (Date.parse(paidAt) < Date.parse(program.createdAt)) {
    throw new Error("The payout time cannot be before the program was created.");
  }
  const transactionHash = toHex(requireTransactionHash(input.transactionHash));
  const draft: Omit<AffiliatePayoutReceipt, "receiptCommitment"> = {
    kind: PAYOUT_RECEIPT_KIND,
    version: AFFILIATE_ENGINE_VERSION,
    programId: program.programId,
    network: program.network,
    poolAddress: program.poolAddress,
    programCommitment: program.programCommitment,
    affiliateId: account.affiliateId,
    assetSymbol: program.asset.symbol,
    assetTokenAddress: program.asset.tokenAddress,
    totalVolumeBaseUnits: totalVolume.toString(),
    tierName: tier.name,
    tierRateBps: tier.rateBps,
    commissionBaseUnits: commission.toString(),
    paidAt,
    transactionHash,
    notice: AFFILIATE_NOTICE,
    limitations: [...AFFILIATE_LIMITATIONS],
  };
  return { ...draft, receiptCommitment: toHex(computeReceiptCommitment(draft)) };
}

export function verifyAffiliatePayoutReceipt(
  receipt: AffiliatePayoutReceipt,
  program: AffiliateProgram,
  account: AffiliateAccount,
): boolean {
  try {
    assertAffiliatePayoutReceipt(receipt);
    assertAffiliateProgram(program);
    assertAffiliateAccount(account);
    if (account.programCommitment !== program.programCommitment) return false;
    if (receipt.programCommitment !== program.programCommitment) return false;
    if (receipt.affiliateId !== account.affiliateId) return false;
    if (receipt.assetTokenAddress !== program.asset.tokenAddress) return false;
    const tier = program.tiers.find((entry) => entry.name === receipt.tierName && entry.rateBps === receipt.tierRateBps);
    if (!tier) return false;
    const expected = (BigInt(receipt.totalVolumeBaseUnits) * BigInt(tier.rateBps)) / BigInt(BPS_DENOMINATOR);
    return BigInt(receipt.commissionBaseUnits) === expected;
  } catch {
    return false;
  }
}
export function buildAffiliateClaimAuthorization(
  program: AffiliateProgram,
  account: AffiliateAccount,
  claimKey: AffiliateClaimKey,
  input: AffiliateClaimInput,
  entropy: AffiliateClaimKeyEntropy = {},
): AffiliateClaimAuthorization {
  assertAffiliateProgram(program);
  assertAffiliateAccount(account);
  if (account.programCommitment !== program.programCommitment) {
    throw new Error("The affiliate account belongs to a different program.");
  }
  const secret = requireSecretScalar(claimKey?.claimSecret, "Affiliate claim secret");
  const publicKey = normalizePoint(claimKey.claimPublicKey, "Affiliate claim public key");
  const derived = pointToFelts(multiplyPoint(BASE, secret));
  if (derived.x !== publicKey.x || derived.y !== publicKey.y) {
    throw new Error("The claim secret does not match the claim public key.");
  }
  if (publicKey.x !== account.claimPublicKey.x || publicKey.y !== account.claimPublicKey.y) {
    throw new Error("The claim key does not match the registered affiliate account.");
  }
  const commission = requireU128(coerceBaseUnits(input.commissionBaseUnits, "Commission amount"), "Commission amount");
  if (commission <= 0n) throw new Error("A claim authorizes a non-zero commission.");
  const period = requireText(input.period, "Claim period", 64);
  const transcript = claimTranscript({
    programCommitment: program.programCommitment,
    affiliateId: account.affiliateId,
    assetTokenAddress: program.asset.tokenAddress,
    commissionBaseUnits: commission.toString(),
    period,
  });
  const proof = createSchnorrProof(CLAIM_DOMAIN, secret, transcript, entropy.nonce);
  return {
    kind: CLAIM_AUTH_KIND,
    version: AFFILIATE_ENGINE_VERSION,
    proofSystem: AFFILIATE_CLAIM_PROOF_SYSTEM,
    programCommitment: program.programCommitment,
    affiliateId: account.affiliateId,
    assetTokenAddress: program.asset.tokenAddress,
    commissionBaseUnits: commission.toString(),
    period,
    claimPublicKey: publicKey,
    proof,
    notice:
      "Zero-knowledge claim authorization. It proves the holder knows the affiliate's claim secret bound to " +
      "this payout; it does not prove the volume, the commission, or that any transfer settled.",
  };
}

export function verifyAffiliateClaimAuthorization(
  authorization: AffiliateClaimAuthorization,
  program: AffiliateProgram,
  account: AffiliateAccount,
): boolean {
  try {
    assertClaimAuthorization(authorization);
    assertAffiliateProgram(program);
    assertAffiliateAccount(account);
    if (account.programCommitment !== program.programCommitment) return false;
    if (authorization.programCommitment !== program.programCommitment) return false;
    if (authorization.affiliateId !== account.affiliateId) return false;
    if (authorization.assetTokenAddress !== program.asset.tokenAddress) return false;
    if (authorization.claimPublicKey.x !== account.claimPublicKey.x) return false;
    if (authorization.claimPublicKey.y !== account.claimPublicKey.y) return false;
    const publicKey = pointFromFelts(authorization.claimPublicKey);
    const transcript = claimTranscript({
      programCommitment: authorization.programCommitment,
      affiliateId: authorization.affiliateId,
      assetTokenAddress: authorization.assetTokenAddress,
      commissionBaseUnits: authorization.commissionBaseUnits,
      period: authorization.period,
    });
    return verifySchnorrProof(CLAIM_DOMAIN, publicKey, authorization.proof, transcript);
  } catch {
    return false;
  }
}
export function buildAffiliateProgramDigest(program: AffiliateProgram): AffiliateProgramDigest {
  assertAffiliateProgram(program);
  const hasMemo = program.memo.length > 0;
  const digest: AffiliateProgramDigest = {
    kind: PROGRAM_DIGEST_KIND,
    version: AFFILIATE_ENGINE_VERSION,
    programId: program.programId,
    network: program.network,
    poolAddress: program.poolAddress,
    assetSymbol: program.asset.symbol,
    assetDecimals: program.asset.decimals,
    tierCount: program.tiers.length,
    tiersHash: toHex(computeTiersHash(program.tiers)),
    hasMemo,
    createdAt: program.createdAt,
    expiresAt: program.expiresAt,
    // A salted commitment to the memo, so the digest reveals whether one exists without exposing it. The
    // salt is never published, so the digest holder cannot recompute this until the program is disclosed.
    memoHash: toHex(computeMemoHash(program.programSalt, program.memo)),
    programCommitment: program.programCommitment,
    notice: AFFILIATE_NOTICE,
    limitations: [...AFFILIATE_LIMITATIONS],
  };
  return digest;
}

export function openAffiliateProgram(program: AffiliateProgram): AffiliateProgramOpening {
  assertAffiliateProgram(program);
  return { programId: program.programId, programCommitment: program.programCommitment, program };
}

export function verifyAffiliateProgramDisclosure(
  opening: AffiliateProgramOpening,
  digest: AffiliateProgramDigest,
): boolean {
  try {
    if (!opening || typeof opening !== "object") return false;
    assertAffiliateProgram(opening.program);
    assertAffiliateProgramDigest(digest);
    if (opening.programCommitment !== opening.program.programCommitment) return false;
    if (digest.programCommitment !== opening.program.programCommitment) return false;
    // Recompute the commitment from the revealed program and compare it to the digest's binding.
    const recomputed = toHex(computeProgramCommitment(opening.program));
    if (recomputed !== digest.programCommitment) return false;
    if (digest.tiersHash !== toHex(computeTiersHash(opening.program.tiers))) return false;
    if (digest.tierCount !== opening.program.tiers.length) return false;
    if (digest.hasMemo !== (opening.program.memo.length > 0)) return false;
    if (digest.memoHash !== toHex(computeMemoHash(opening.program.programSalt, opening.program.memo))) return false;
    return digest.assetSymbol === opening.program.asset.symbol
      && digest.assetDecimals === opening.program.asset.decimals
      && digest.createdAt === opening.program.createdAt
      && digest.expiresAt === opening.program.expiresAt;
  } catch {
    return false;
  }
}

export function getAffiliateVisibilityModel(): AffiliateVisibilityModel {
  return {
    applicationOnly: [
      "The affiliate program, its commission tiers, and the referral attribution ledger — they live in this browser and are never sent on-chain.",
      "Which affiliate a referral is attributed to, and the running volume that resolves a tier.",
    ],
    walletRequest: [
      "When the merchant pays, the wallet sees one in-pool STRK20 transfer of the payout asset: recipient, token, and amount.",
    ],
    hiddenInPool: [
      "The payout transfer's in-pool sender, recipient, token, and amount are hidden from public observers.",
    ],
    publicOrObservable: [
      "That a transfer occurred, its timing, fees, and published nullifiers (unlinkable without a viewing key).",
      "A distinctive commission amount, or a payout tied to a known program, is a correlation signal.",
      "Any deposit that funds the payout or withdrawal that cashes it out, with its public address and amount.",
    ],
    limitation:
      "Only movement inside the pool is encrypted. The program, tiers, and attributions are local assertions, " +
      "not on-chain facts, and the deposit and withdrawal edges around a payout stay public.",
  };
}

export function summarizeAffiliateTrust(): AffiliateTrustSummary {
  return {
    fundHolder: "The merchant. Funds move only when the merchant voluntarily signs one in-pool transfer.",
    isDecentralized: false,
    isAutomatic: false,
    provesReferral: false,
    provesPayment: false,
    ledgerSource: "A local attribution ledger the merchant keeps; the engine commits and totals it but cannot vouch that an attribution is real.",
    zeroKnowledgeElement:
      "Only the optional claim authorization — a Schnorr proof of knowledge of an affiliate's claim key bound to a payout. It proves who is claiming, never a volume, a commission, or a payment.",
    trustedParties: [
      "The merchant, who defines the program, keeps the ledger, and signs payouts.",
      "The merchant's wallet, RPC, relayer, and prover, which submit the in-pool transfer.",
      "The STRK20 deposit-screening service, which signs every deposit that funds a payout.",
    ],
    statement:
      "CipherBill's affiliate planner computes commissions locally with exact integer math and helps the " +
      "merchant pay one private in-pool transfer. It is neither decentralized nor automatic, it does not " +
      "prove referrals or payments, and only the claim authorization is a zero-knowledge proof.",
  };
}
export function serializeAffiliateProgram(program: AffiliateProgram): string {
  assertAffiliateProgram(program);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(program)));
}

export function parseAffiliateProgram(encoded: string): AffiliateProgram {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Affiliate program");
  assertAffiliateProgram(parsed);
  return parsed;
}

export function serializeAffiliateAccount(account: AffiliateAccount): string {
  assertAffiliateAccount(account);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(account)));
}

export function parseAffiliateAccount(encoded: string): AffiliateAccount {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Affiliate account");
  assertAffiliateAccount(parsed);
  return parsed;
}

export function serializeAffiliateReferral(referral: AffiliateReferral): string {
  assertAffiliateReferral(referral);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(referral)));
}

export function parseAffiliateReferral(encoded: string): AffiliateReferral {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Affiliate referral");
  assertAffiliateReferral(parsed);
  return parsed;
}

export function serializeAffiliateProgramDigest(digest: AffiliateProgramDigest): string {
  assertAffiliateProgramDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseAffiliateProgramDigest(encoded: string): AffiliateProgramDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Program digest");
  assertAffiliateProgramDigest(parsed);
  return parsed;
}

export function serializeAffiliatePayoutReceipt(receipt: AffiliatePayoutReceipt): string {
  assertAffiliatePayoutReceipt(receipt);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(receipt)));
}

export function parseAffiliatePayoutReceipt(encoded: string): AffiliatePayoutReceipt {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Payout receipt");
  assertAffiliatePayoutReceipt(parsed);
  return parsed;
}

export function serializeAffiliateClaimAuthorization(authorization: AffiliateClaimAuthorization): string {
  assertClaimAuthorization(authorization);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(authorization)));
}

export function parseAffiliateClaimAuthorization(encoded: string): AffiliateClaimAuthorization {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Claim authorization");
  assertClaimAuthorization(parsed);
  return parsed;
}

export function formatAffiliateBaseUnits(value: string | bigint, decimals: number): string {
  // Hex-tolerant: a wallet FELT balance arrives as a hex string, and BigInt() reads both hex and decimal.
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
    const bytes = random(new Uint8Array(AFFILIATE_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== AFFILIATE_SALT_BYTES) throw new Error("The entropy source returned the wrong number of bytes.");
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

function pointToFelts(point: CurvePoint): AffiliateCurvePoint {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: AffiliateCurvePoint, label = "Curve point"): CurvePoint {
  if (!point || typeof point !== "object") throw new Error(`${label} is invalid.`);
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, label), y: requireFelt(point.y, label) });
  parsed.assertValidity();
  return parsed;
}

function normalizePoint(value: unknown, label: string): AffiliateCurvePoint {
  assertPoint(value, label);
  return pointToFelts(pointFromFelts(value, label));
}

function createSchnorrProof(domain: bigint, secret: bigint, transcript: bigint[], suppliedNonce?: bigint): AffiliateSchnorrProof {
  const nonce = requireSecretScalar(suppliedNonce ?? randomScalar(), "Schnorr nonce");
  const publicKey = multiplyPoint(BASE, secret);
  const noncePoint = multiplyPoint(BASE, nonce);
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(mod(nonce + challenge * secret, CURVE_ORDER)) };
}

function verifySchnorrProof(domain: bigint, publicKey: CurvePoint, proof: AffiliateSchnorrProof, transcript: bigint[]): boolean {
  const noncePoint = pointFromFelts(proof.nonceCommitment, "Schnorr nonce commitment");
  const response = requireCurveScalar(proof.response, true, "Schnorr response");
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return multiplyPoint(BASE, response).equals(noncePoint.add(multiplyPoint(publicKey, challenge)));
}

function schnorrChallenge(domain: bigint, publicKey: CurvePoint, noncePoint: CurvePoint, transcript: bigint[]): bigint {
  return mod(hashElements([domain, publicKey.x, publicKey.y, noncePoint.x, noncePoint.y, ...transcript]), CURVE_ORDER);
}
function normalizeAsset(asset: AffiliateAssetInput | undefined, label = "Payout asset"): AffiliateAsset {
  if (!asset || !asset.tokenAddress) throw new Error(`${label} needs a Starknet token contract address.`);
  return {
    symbol: requireSymbol(asset.symbol, `${label} symbol`),
    tokenAddress: normalizeStarknetAddress(asset.tokenAddress),
    decimals: requireDecimals(asset.decimals, `${label} decimals`),
  };
}

/**
 * Normalizes the commission ladder: at least one tier, unique names, the first tier open at zero volume,
 * strictly ascending minimum volumes, and each rate within the basis-point bounds.
 */
function normalizeTiers(tiers: AffiliateTierInput[], decimals: number): CommissionTier[] {
  if (!Array.isArray(tiers)) throw new Error("A commission tier ladder is required.");
  requireCount(tiers.length, "Tier count", MIN_TIERS, MAX_TIERS);
  const names = new Set<string>();
  let previousMin = -1n;
  return tiers.map((tier, index) => {
    const name = requireText(tier?.name, "Tier name", 40);
    const key = name.toLowerCase();
    if (names.has(key)) throw new Error("Commission tier names must be unique.");
    names.add(key);
    const minVolume = parseNonNegativeDecimal(tier?.minVolume, decimals, `Tier ${name} minimum volume`);
    if (index === 0 && minVolume !== 0n) throw new Error("The first commission tier must start at zero volume.");
    if (minVolume <= previousMin) throw new Error("Commission tier minimum volumes must strictly ascend.");
    previousMin = minVolume;
    return {
      name,
      minVolumeBaseUnits: minVolume.toString(),
      minVolumeDisplay: formatBaseUnits(minVolume, decimals),
      rateBps: requireBps(tier?.rateBps, `Tier ${name} rate`),
    };
  });
}

/** Picks the highest tier whose cumulative minimum volume the total meets. */
function resolveTierByName(tiers: CommissionTier[], name: unknown, rateBps: unknown): CommissionTier {
  const tier = tiers.find((entry) => entry.name === name && entry.rateBps === rateBps);
  if (!tier) throw new Error("The named tier is not part of the program.");
  return tier;
}

/** An opaque, salted referral code derived from the account commitment; it leaks no address. */
function deriveReferralCode(accountCommitment: string): string {
  const digest = hashElements([REFERRAL_CODE_DOMAIN, requireFelt(accountCommitment, "Account commitment")]);
  return `af-${digest.toString(16).padStart(64, "0").slice(0, 20)}`;
}

function computeMemoHash(programSalt: string, memo: string): bigint {
  return hashElements([
    BigInt(hash.starknetKeccak(PROGRAM_DIGEST_KIND)),
    requireFelt(programSalt, "Program salt"),
    BigInt(hash.starknetKeccak(memo || "empty")),
  ]);
}
function computeTiersHash(tiers: CommissionTier[]): bigint {
  const elements: bigint[] = [TIER_DOMAIN, BigInt(tiers.length)];
  for (const tier of tiers) {
    elements.push(BigInt(hash.starknetKeccak(tier.name)), BigInt(tier.minVolumeBaseUnits), BigInt(tier.rateBps));
  }
  return hashElements(elements);
}

function computeProgramCommitment(p: Omit<AffiliateProgram, "programCommitment">): bigint {
  return hashElements([
    PROGRAM_DOMAIN,
    BigInt(p.version),
    requireFelt(p.programSalt, "Program salt"),
    BigInt(hash.starknetKeccak(p.programId)),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(p.merchant),
    BigInt(hash.starknetKeccak(p.asset.symbol)),
    BigInt(p.asset.tokenAddress),
    BigInt(p.asset.decimals),
    computeTiersHash(p.tiers),
    BigInt(hash.starknetKeccak(p.memo || "empty")),
    secondsOf(p.createdAt),
    secondsOf(p.expiresAt),
  ]);
}

function computeAccountCommitment(a: Omit<AffiliateAccount, "accountCommitment" | "referralCode">): bigint {
  return hashElements([
    ACCOUNT_DOMAIN,
    BigInt(a.version),
    requireFelt(a.accountSalt, "Account salt"),
    BigInt(hash.starknetKeccak(a.affiliateId)),
    requireFelt(a.programCommitment, "Program commitment"),
    BigInt(a.payoutAddress),
    requireFelt(a.claimPublicKey.x, "Claim public key x"),
    requireFelt(a.claimPublicKey.y, "Claim public key y"),
    BigInt(hash.starknetKeccak(a.label || "none")),
  ]);
}

function computeReferralCommitment(r: Omit<AffiliateReferral, "referralCommitment">): bigint {
  return hashElements([
    REFERRAL_DOMAIN,
    BigInt(r.version),
    requireFelt(r.referralSalt, "Referral salt"),
    BigInt(hash.starknetKeccak(r.referralId)),
    requireFelt(r.programCommitment, "Program commitment"),
    BigInt(hash.starknetKeccak(r.affiliateId)),
    BigInt(hash.starknetKeccak(r.invoiceId)),
    BigInt(r.volumeBaseUnits),
    secondsOf(r.occurredAt),
  ]);
}

function computeReceiptCommitment(r: Omit<AffiliatePayoutReceipt, "receiptCommitment">): bigint {
  return hashElements([
    RECEIPT_DOMAIN,
    BigInt(r.version),
    BigInt(hash.starknetKeccak(r.programId)),
    requireFelt(r.programCommitment, "Program commitment"),
    BigInt(hash.starknetKeccak(r.affiliateId)),
    BigInt(r.assetTokenAddress),
    BigInt(r.totalVolumeBaseUnits),
    BigInt(hash.starknetKeccak(r.tierName)),
    BigInt(r.tierRateBps),
    BigInt(r.commissionBaseUnits),
    secondsOf(r.paidAt),
    requireFelt(r.transactionHash, "Transaction hash"),
  ]);
}

/** The transcript the claim proof is bound to: the program, affiliate, asset, commission, and period. */
function claimTranscript(input: {
  programCommitment: string;
  affiliateId: string;
  assetTokenAddress: string;
  commissionBaseUnits: string;
  period: string;
}): bigint[] {
  return [
    requireFelt(input.programCommitment, "Program commitment"),
    BigInt(hash.starknetKeccak(input.affiliateId)),
    BigInt(input.assetTokenAddress),
    BigInt(input.commissionBaseUnits),
    BigInt(hash.starknetKeccak(input.period)),
  ];
}
function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Affiliate amounts cannot be negative.");
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

/** Parses a non-negative decimal amount into base units; permits zero (tier thresholds). */
function parseNonNegativeDecimal(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a non-negative decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  return requireU128(BigInt(`${whole}${fraction.padEnd(decimals, "0")}`), label);
}

/** Coerces a base-unit amount supplied as a decimal integer string or a bigint. Strict: no hex, no fraction. */
function coerceBaseUnits(value: string | bigint, label: string): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(`${label} must not be negative.`);
    return value;
  }
  if (typeof value !== "string" || !/^\d+$/.test(value.trim())) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value.trim());
}

function requireBaseUnitString(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} is outside the u128 range the privacy pool accepts.`);
  return value;
}

function requireCount(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  return value;
}

function requireBps(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < MIN_RATE_BPS || value > MAX_RATE_BPS) {
    throw new Error(`${label} must be an integer between ${MIN_RATE_BPS} and ${MAX_RATE_BPS} basis points.`);
  }
  return value;
}

function requireDays(value: unknown, label: string): number {
  if (value === undefined || value === null) return DEFAULT_PROGRAM_TTL_DAYS;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_PROGRAM_TTL_DAYS) {
    throw new Error(`${label} must be a whole number of days between 1 and ${MAX_PROGRAM_TTL_DAYS}.`);
  }
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

function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== AFFILIATE_LIMITATIONS.length || value.some((entry, index) => entry !== AFFILIATE_LIMITATIONS[index])) {
    throw new Error("The affiliate limitations were altered.");
  }
}

function assertAffiliateAsset(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ASSET_KEYS)) throw new Error(`${label} is invalid.`);
  const asset = value as AffiliateAsset;
  requireSymbol(asset.symbol, `${label} symbol`);
  requireDecimals(asset.decimals, `${label} decimals`);
  if (!asset.tokenAddress || asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) throw new Error(`${label} token address is not canonical.`);
}

function assertPoint(value: unknown, label: string): asserts value is AffiliateCurvePoint {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, POINT_KEYS)) throw new Error(`${label} is invalid.`);
  pointFromFelts(value as AffiliateCurvePoint, label);
}

function assertProof(value: unknown, label: string): asserts value is AffiliateSchnorrProof {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PROOF_KEYS)) throw new Error(`${label} is invalid.`);
  const proof = value as AffiliateSchnorrProof;
  assertPoint(proof.nonceCommitment, `${label} nonce`);
  requireCurveScalar(proof.response, true, `${label} response`);
}

function assertTier(value: unknown, decimals: number): asserts value is CommissionTier {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, TIER_KEYS)) throw new Error("A commission tier is invalid.");
  const tier = value as CommissionTier;
  requireText(tier.name, "Tier name", 40);
  const min = requireU128(requireBaseUnitString(tier.minVolumeBaseUnits, "Tier minimum volume"), "Tier minimum volume");
  if (tier.minVolumeDisplay !== formatBaseUnits(min, decimals)) throw new Error("A tier minimum volume display is inconsistent.");
  requireBps(tier.rateBps, "Tier rate");
}
function assertAffiliateProgram(value: unknown): asserts value is AffiliateProgram {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PROGRAM_KEYS)) throw new Error("Affiliate program is invalid.");
  const p = value as AffiliateProgram;
  if (p.kind !== PROGRAM_KIND || p.version !== AFFILIATE_ENGINE_VERSION || p.network !== MAINNET_CHAIN_ID
    || p.poolAddress !== STRK20_POOL_ADDRESS || p.notice !== AFFILIATE_NOTICE
    || !/^afp_[A-Za-z0-9_-]{1,48}$/.test(p.programId)) throw new Error("Affiliate program header is invalid.");
  assertLimitations(p.limitations);
  if (!p.merchant || p.merchant !== normalizeStarknetAddress(p.merchant)) throw new Error("The merchant address is not canonical.");
  assertAffiliateAsset(p.asset, "Payout asset");
  if (!Array.isArray(p.tiers)) throw new Error("The commission tiers are invalid.");
  requireCount(p.tiers.length, "Tier count", MIN_TIERS, MAX_TIERS);
  const names = new Set<string>();
  let previousMin = -1n;
  p.tiers.forEach((tier, index) => {
    assertTier(tier, p.asset.decimals);
    const key = tier.name.toLowerCase();
    if (names.has(key)) throw new Error("Commission tier names must be unique.");
    names.add(key);
    const min = BigInt(tier.minVolumeBaseUnits);
    if (index === 0 && min !== 0n) throw new Error("The first commission tier must start at zero volume.");
    if (min <= previousMin) throw new Error("Commission tier minimum volumes must strictly ascend.");
    previousMin = min;
  });
  if (typeof p.memo !== "string" || p.memo.length > 280) throw new Error("The program memo is invalid.");
  requireIsoTimestamp(p.createdAt, "Program creation time");
  requireIsoTimestamp(p.expiresAt, "Program expiry time");
  if (Date.parse(p.expiresAt) <= Date.parse(p.createdAt)) throw new Error("The program expiry must be after its creation.");
  requireFelt(p.programSalt, "Program salt");
  if (requireFelt(p.programCommitment, "Program commitment") !== computeProgramCommitment(p)) throw new Error("The program commitment does not match its contents.");
}

function assertAffiliateAccount(value: unknown): asserts value is AffiliateAccount {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ACCOUNT_KEYS)) throw new Error("Affiliate account is invalid.");
  const a = value as AffiliateAccount;
  if (a.kind !== ACCOUNT_KIND || a.version !== AFFILIATE_ENGINE_VERSION || a.network !== MAINNET_CHAIN_ID
    || a.poolAddress !== STRK20_POOL_ADDRESS || typeof a.notice !== "string"
    || !/^afa_[A-Za-z0-9_-]{1,48}$/.test(a.affiliateId)) throw new Error("Affiliate account header is invalid.");
  if (typeof a.label !== "string" || a.label.length > 64) throw new Error("The affiliate label is invalid.");
  if (!a.payoutAddress || a.payoutAddress !== normalizeStarknetAddress(a.payoutAddress)) throw new Error("The payout address is not canonical.");
  assertPoint(a.claimPublicKey, "Affiliate claim public key");
  requireFelt(a.programCommitment, "Program commitment");
  requireFelt(a.accountSalt, "Account salt");
  if (!/^af-[0-9a-f]{20}$/.test(a.referralCode)) throw new Error("The referral code is invalid.");
  const commitment = requireFelt(a.accountCommitment, "Account commitment");
  if (commitment !== computeAccountCommitment(a)) throw new Error("The account commitment does not match its contents.");
  if (a.referralCode !== deriveReferralCode(a.accountCommitment)) throw new Error("The referral code does not match the account commitment.");
}

function assertAffiliateReferral(value: unknown): asserts value is AffiliateReferral {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, REFERRAL_KEYS)) throw new Error("Affiliate referral is invalid.");
  const r = value as AffiliateReferral;
  if (r.kind !== REFERRAL_KIND || r.version !== AFFILIATE_ENGINE_VERSION || r.network !== MAINNET_CHAIN_ID
    || r.poolAddress !== STRK20_POOL_ADDRESS || typeof r.notice !== "string"
    || !/^afr_[A-Za-z0-9_-]{1,48}$/.test(r.referralId)
    || !/^afa_[A-Za-z0-9_-]{1,48}$/.test(r.affiliateId)) throw new Error("Affiliate referral header is invalid.");
  requireText(r.invoiceId, "Invoice ID", 96);
  requireFelt(r.programCommitment, "Program commitment");
  const volume = requireU128(requireBaseUnitString(r.volumeBaseUnits, "Referral volume"), "Referral volume");
  if (volume <= 0n) throw new Error("The referral volume must be positive.");
  requireIsoTimestamp(r.occurredAt, "Referral time");
  requireFelt(r.referralSalt, "Referral salt");
  if (requireFelt(r.referralCommitment, "Referral commitment") !== computeReferralCommitment(r)) throw new Error("The referral commitment does not match its contents.");
}
function assertAffiliateProgramDigest(value: unknown): asserts value is AffiliateProgramDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PROGRAM_DIGEST_KEYS)) throw new Error("Affiliate program digest is invalid.");
  const d = value as AffiliateProgramDigest;
  if (d.kind !== PROGRAM_DIGEST_KIND || d.version !== AFFILIATE_ENGINE_VERSION || d.network !== MAINNET_CHAIN_ID
    || d.poolAddress !== STRK20_POOL_ADDRESS || d.notice !== AFFILIATE_NOTICE
    || !/^afp_[A-Za-z0-9_-]{1,48}$/.test(d.programId)) throw new Error("Affiliate program digest header is invalid.");
  assertLimitations(d.limitations);
  requireSymbol(d.assetSymbol, "Digest asset symbol");
  requireDecimals(d.assetDecimals, "Digest asset decimals");
  requireCount(d.tierCount, "Digest tier count", MIN_TIERS, MAX_TIERS);
  requireFelt(d.tiersHash, "Tiers hash");
  if (typeof d.hasMemo !== "boolean") throw new Error("The digest memo flag is invalid.");
  requireIsoTimestamp(d.createdAt, "Program creation time");
  requireIsoTimestamp(d.expiresAt, "Program expiry time");
  requireFelt(d.memoHash, "Memo hash");
  requireFelt(d.programCommitment, "Program commitment");
}

function assertAffiliatePayoutReceipt(value: unknown): asserts value is AffiliatePayoutReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PAYOUT_RECEIPT_KEYS)) throw new Error("Affiliate payout receipt is invalid.");
  const r = value as AffiliatePayoutReceipt;
  if (r.kind !== PAYOUT_RECEIPT_KIND || r.version !== AFFILIATE_ENGINE_VERSION || r.network !== MAINNET_CHAIN_ID
    || r.poolAddress !== STRK20_POOL_ADDRESS || r.notice !== AFFILIATE_NOTICE
    || !/^afp_[A-Za-z0-9_-]{1,48}$/.test(r.programId)
    || !/^afa_[A-Za-z0-9_-]{1,48}$/.test(r.affiliateId)) throw new Error("Affiliate payout receipt header is invalid.");
  assertLimitations(r.limitations);
  requireFelt(r.programCommitment, "Program commitment");
  requireSymbol(r.assetSymbol, "Receipt asset symbol");
  if (!r.assetTokenAddress || r.assetTokenAddress !== normalizeStarknetAddress(r.assetTokenAddress)) throw new Error("The receipt asset address is not canonical.");
  const total = requireU128(requireBaseUnitString(r.totalVolumeBaseUnits, "Total volume"), "Total volume");
  requireText(r.tierName, "Tier name", 40);
  const rate = requireBps(r.tierRateBps, "Tier rate");
  const commission = requireU128(requireBaseUnitString(r.commissionBaseUnits, "Commission amount"), "Commission amount");
  if (commission !== (total * BigInt(rate)) / BigInt(BPS_DENOMINATOR)) throw new Error("The receipt commission does not match the tier rate and volume.");
  requireIsoTimestamp(r.paidAt, "Payout time");
  requireFelt(r.transactionHash, "Transaction hash");
  if (requireFelt(r.receiptCommitment, "Receipt commitment") !== computeReceiptCommitment(r)) throw new Error("The receipt commitment does not match its contents.");
}

function assertClaimAuthorization(value: unknown): asserts value is AffiliateClaimAuthorization {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, CLAIM_AUTH_KEYS)) throw new Error("The claim authorization is invalid.");
  const a = value as AffiliateClaimAuthorization;
  if (a.kind !== CLAIM_AUTH_KIND || a.version !== AFFILIATE_ENGINE_VERSION || a.proofSystem !== AFFILIATE_CLAIM_PROOF_SYSTEM
    || typeof a.notice !== "string" || !a.notice.includes("claim secret")
    || !/^afa_[A-Za-z0-9_-]{1,48}$/.test(a.affiliateId)) throw new Error("The claim authorization header is invalid.");
  requireFelt(a.programCommitment, "Program commitment");
  if (!a.assetTokenAddress || a.assetTokenAddress !== normalizeStarknetAddress(a.assetTokenAddress)) throw new Error("The claim asset address is not canonical.");
  const commission = requireU128(requireBaseUnitString(a.commissionBaseUnits, "Commission amount"), "Commission amount");
  if (commission <= 0n) throw new Error("A claim authorizes a non-zero commission.");
  requireText(a.period, "Claim period", 64);
  assertPoint(a.claimPublicKey, "Affiliate claim public key");
  assertProof(a.proof, "Claim proof");
}
