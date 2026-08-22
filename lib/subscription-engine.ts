import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";
import { decimalToBaseUnits, normalizeStarknetAddress } from "./strk20/validation";

export const SUBSCRIPTION_ENGINE_VERSION = 1 as const;
export const SUBSCRIPTION_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const SUBSCRIPTION_TOKEN_ADDRESS = STRK_TOKEN_ADDRESS;
export const SUBSCRIPTION_PROOF_SYSTEM = "stark-schnorr-membership-v1" as const;
export const RENEWAL_WINDOW_DAYS = 7;
export const GRACE_PERIOD_DAYS = 7;

const CREDENTIAL_KIND = "cipherbill.subscription-membership" as const;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const DAY_MS = 86_400_000;
const MEMBERSHIP_DOMAIN = hash.starknetKeccak("CipherBill anonymous membership v1");
const POSSESSION_DOMAIN = hash.starknetKeccak("CipherBill membership possession proof v1");
const ROTATION_DOMAIN = hash.starknetKeccak("CipherBill membership rotation proof v1");
const ISSUER_DOMAIN = hash.starknetKeccak("CipherBill membership issuer signature v1");
const PAYMENT_DOMAIN = hash.starknetKeccak("CipherBill hidden subscription payment v1");
const VIEW_KEY_DOMAIN = hash.starknetKeccak("CipherBill service viewing key v1");
const ACCESS_TOKEN_DOMAIN = hash.starknetKeccak("CipherBill rotating access token v1");

export const SUBSCRIPTION_TIERS = {
  starter: {
    name: "Starter",
    monthlyPrice: "4",
    description: "Private recurring billing for solo operators.",
    features: ["5 active private invoices", "Selective receipts", "Monthly key rotation"],
  },
  professional: {
    name: "Professional",
    monthlyPrice: "12",
    description: "Automation and settlement controls for growing teams.",
    features: ["Unlimited private invoices", "Batch settlement", "Encrypted audit exports", "Monthly key rotation"],
  },
  enterprise: {
    name: "Enterprise",
    monthlyPrice: "30",
    description: "Policy-grade private commerce for treasury operations.",
    features: ["Threshold approvals", "Arbitration and escrow", "Issuer allow-listing", "Priority proof workflows"],
  },
} as const;

export type SubscriptionTier = keyof typeof SUBSCRIPTION_TIERS;
export type SubscriptionStatus = "active" | "renewal_due" | "grace" | "expired";

export interface SubscriptionCurvePoint {
  x: string;
  y: string;
}

export interface SubscriptionSchnorrProof {
  nonceCommitment: SubscriptionCurvePoint;
  response: string;
}

export interface SubscriptionIssuerKeypair {
  privateKey: string;
  publicKey: SubscriptionCurvePoint;
}

export interface SubscriptionCredential {
  kind: typeof CREDENTIAL_KIND;
  version: typeof SUBSCRIPTION_ENGINE_VERSION;
  proofSystem: typeof SUBSCRIPTION_PROOF_SYSTEM;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  tokenAddress: typeof STRK_TOKEN_ADDRESS;
  membershipId: string;
  tier: SubscriptionTier;
  epoch: number;
  serviceRecipient: string;
  periodStart: string;
  periodEnd: string;
  graceEndsAt: string;
  priceBaseUnits: string;
  membershipPublicKey: SubscriptionCurvePoint;
  serviceViewingKeyCommitment: string;
  accessTokenCommitment: string;
  paymentCommitment: string;
  previousCredentialCommitment?: string;
  stateCommitment: string;
  possessionProof: SubscriptionSchnorrProof;
  rotationProof?: SubscriptionSchnorrProof;
  issuerId: string;
  issuerPublicKey: SubscriptionCurvePoint;
  issuerSignature: SubscriptionSchnorrProof;
  notice: string;
}

export interface SubscriptionSecrets {
  membershipSecret: string;
  serviceViewingKey: string;
  accessToken: string;
  paymentSalt: string;
  paymentTransactionHash: string;
}

export interface SubscriptionMembershipBundle {
  credential: SubscriptionCredential;
  secrets: SubscriptionSecrets;
}

export interface CreateSubscriptionInput {
  tier: SubscriptionTier;
  serviceRecipient: string;
  paymentTransactionHash: string;
  issuerId: string;
  issuerPrivateKey: string;
}

export interface RenewSubscriptionInput {
  tier?: SubscriptionTier;
  paymentTransactionHash: string;
  issuerId: string;
  issuerPrivateKey: string;
}

export interface SubscriptionEntropy {
  membershipId?: string;
  membershipSecret?: bigint;
  serviceViewingKey?: Uint8Array;
  accessToken?: Uint8Array;
  paymentSalt?: bigint;
  possessionNonce?: bigint;
  rotationNonce?: bigint;
  issuerNonce?: bigint;
}

export interface SubscriptionVerification {
  cryptographicallyValid: boolean;
  issuerTrusted: boolean;
  current: boolean;
  status: SubscriptionStatus | null;
  tier: SubscriptionTier | null;
  reason: string;
}

export interface SubscriptionCountdown {
  status: SubscriptionStatus;
  target: string;
  remainingSeconds: number;
  renewalOpen: boolean;
}

export interface SubscriptionSecurityModel {
  proven: string[];
  issuerGuarantees: string[];
  rotated: string[];
  hidden: string[];
  publicOrObservable: string[];
  limitations: string[];
}

interface CredentialCore {
  kind: typeof CREDENTIAL_KIND;
  version: typeof SUBSCRIPTION_ENGINE_VERSION;
  proofSystem: typeof SUBSCRIPTION_PROOF_SYSTEM;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  tokenAddress: typeof STRK_TOKEN_ADDRESS;
  membershipId: string;
  tier: SubscriptionTier;
  epoch: number;
  serviceRecipient: string;
  periodStart: string;
  periodEnd: string;
  graceEndsAt: string;
  priceBaseUnits: string;
  membershipPublicKey: SubscriptionCurvePoint;
  serviceViewingKeyCommitment: string;
  accessTokenCommitment: string;
  paymentCommitment: string;
  previousCredentialCommitment?: string;
  issuerId: string;
  issuerPublicKey: SubscriptionCurvePoint;
}

export function generateSubscriptionIssuerKeypair(privateKey?: bigint): SubscriptionIssuerKeypair {
  const scalar = requireSecretScalar(privateKey ?? randomScalar(), "Issuer private key");
  return { privateKey: toHex(scalar), publicKey: pointToFelts(multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, scalar)) };
}

export function buildSubscriptionPaymentActions(tier: SubscriptionTier, serviceRecipient: string): STRK20_ACTION[] {
  const definition = requireTier(tier);
  return [{
    type: "transfer",
    token: STRK_TOKEN_ADDRESS,
    amount: decimalToBaseUnits(definition.monthlyPrice, 18),
    recipient: normalizeStarknetAddress(serviceRecipient),
  }];
}

export function createSubscriptionMembership(
  input: CreateSubscriptionInput,
  now = new Date(),
  entropy: SubscriptionEntropy = {},
): SubscriptionMembershipBundle {
  requireValidDate(now, "Membership activation time");
  return issueMembership({
    tier: input.tier,
    epoch: 1,
    serviceRecipient: input.serviceRecipient,
    paymentTransactionHash: input.paymentTransactionHash,
    issuerId: input.issuerId,
    issuerPrivateKey: input.issuerPrivateKey,
    periodStart: now,
  }, entropy);
}

export function renewSubscriptionMembership(
  previous: SubscriptionMembershipBundle,
  input: RenewSubscriptionInput,
  now = new Date(),
  entropy: SubscriptionEntropy = {},
): SubscriptionMembershipBundle {
  requireValidDate(now, "Membership renewal time");
  if (!verifySubscriptionOpening(previous)) throw new Error("Previous membership opening is invalid or altered.");
  const previousCredential = previous.credential;
  const nextTier = input.tier ?? previousCredential.tier;
  requireTier(nextTier);
  const status = deriveSubscriptionStatus(previousCredential, now);
  const tierChange = nextTier !== previousCredential.tier;
  const renewalOpensAt = Date.parse(previousCredential.periodEnd) - RENEWAL_WINDOW_DAYS * DAY_MS;
  if (!tierChange && now.getTime() < renewalOpensAt) throw new Error(`Renewal opens ${RENEWAL_WINDOW_DAYS} days before the current period ends.`);
  if (status === "expired") throw new Error("The membership grace period ended. Create a new membership instead of rotating an expired credential.");

  const periodStart = tierChange ? now : new Date(previousCredential.periodEnd);
  const next = issueMembership({
    tier: nextTier,
    epoch: previousCredential.epoch + 1,
    serviceRecipient: previousCredential.serviceRecipient,
    paymentTransactionHash: input.paymentTransactionHash,
    issuerId: input.issuerId,
    issuerPrivateKey: input.issuerPrivateKey,
    periodStart,
    previousCredential,
    previousMembershipSecret: previous.secrets.membershipSecret,
  }, entropy);
  if (
    next.secrets.membershipSecret === previous.secrets.membershipSecret
    || next.secrets.serviceViewingKey === previous.secrets.serviceViewingKey
    || next.secrets.accessToken === previous.secrets.accessToken
  ) throw new Error("Renewal entropy did not rotate every service-scoped membership secret.");
  return next;
}

export function verifySubscriptionCredential(
  credential: SubscriptionCredential,
  options: { trustedIssuer?: SubscriptionCurvePoint; now?: Date } = {},
): SubscriptionVerification {
  try {
    validateCredentialShape(credential);
    const stateCommitment = computeStateCommitment(credential);
    if (toHex(stateCommitment) !== credential.stateCommitment) throw new Error("Membership state commitment does not match.");
    const membershipPublicKey = pointFromFelts(credential.membershipPublicKey, "Membership public key");
    if (!verifySchnorrProof(POSSESSION_DOMAIN, membershipPublicKey, credential.possessionProof, possessionTranscript(credential))) throw new Error("Membership possession proof is invalid.");
    if (credential.epoch === 1) {
      if (credential.previousCredentialCommitment || credential.rotationProof) throw new Error("Initial membership cannot contain a rotation proof.");
    } else {
      if (!credential.previousCredentialCommitment || !credential.rotationProof) throw new Error("Rotated membership is missing its continuity proof.");
    }
    const issuerPublicKey = pointFromFelts(credential.issuerPublicKey, "Issuer public key");
    if (!verifySchnorrProof(ISSUER_DOMAIN, issuerPublicKey, credential.issuerSignature, issuerTranscript(credential))) throw new Error("Membership issuer signature is invalid.");
    const now = options.now ?? new Date();
    requireValidDate(now, "Membership verification time");
    const status = deriveSubscriptionStatus(credential, now);
    const issuerTrusted = options.trustedIssuer ? issuerPublicKey.equals(pointFromFelts(options.trustedIssuer, "Trusted issuer")) : false;
    return {
      cryptographicallyValid: true,
      issuerTrusted,
      current: status !== "expired",
      status,
      tier: credential.tier,
      reason: status === "expired"
        ? "Credential proofs are valid, but the membership grace period ended."
        : issuerTrusted
          ? "Membership possession, issuer, rotation state, and validity window verified."
          : "Membership proofs are valid, but this verifier has not allow-listed the issuer.",
    };
  } catch (error) {
    return { cryptographicallyValid: false, issuerTrusted: false, current: false, status: null, tier: null, reason: error instanceof Error ? error.message : "Membership credential is invalid." };
  }
}

export function verifySubscriptionRotation(previous: SubscriptionCredential, next: SubscriptionCredential): boolean {
  try {
    const previousVerification = verifySubscriptionCredential(previous, { now: new Date(previous.periodStart) });
    const nextVerification = verifySubscriptionCredential(next, { now: new Date(next.periodStart) });
    if (!previousVerification.cryptographicallyValid || !nextVerification.cryptographicallyValid) return false;
    if (next.epoch !== previous.epoch + 1 || next.previousCredentialCommitment !== previous.stateCommitment || !next.rotationProof) return false;
    if (next.serviceRecipient !== previous.serviceRecipient || next.membershipPublicKey.x === previous.membershipPublicKey.x && next.membershipPublicKey.y === previous.membershipPublicKey.y) return false;
    const previousPublicKey = pointFromFelts(previous.membershipPublicKey, "Previous membership public key");
    return verifySchnorrProof(ROTATION_DOMAIN, previousPublicKey, next.rotationProof, rotationTranscript(previous, next));
  } catch {
    return false;
  }
}

export function verifySubscriptionOpening(bundle: SubscriptionMembershipBundle): boolean {
  try {
    const { credential, secrets } = bundle;
    if (!verifySubscriptionCredential(credential, { now: new Date(credential.periodStart) }).cryptographicallyValid) return false;
    const secret = requireCurveScalar(secrets.membershipSecret, false, "Membership secret");
    if (!multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, secret).equals(pointFromFelts(credential.membershipPublicKey, "Membership public key"))) return false;
    if (commitText(VIEW_KEY_DOMAIN, secrets.serviceViewingKey) !== credential.serviceViewingKeyCommitment) return false;
    if (commitText(ACCESS_TOKEN_DOMAIN, secrets.accessToken) !== credential.accessTokenCommitment) return false;
    const paymentHash = requireTransactionHash(secrets.paymentTransactionHash);
    const paymentSalt = requireCurveScalar(secrets.paymentSalt, false, "Payment salt");
    return toHex(hashElements([PAYMENT_DOMAIN, paymentHash, paymentSalt])) === credential.paymentCommitment;
  } catch {
    return false;
  }
}

export function deriveSubscriptionStatus(credential: SubscriptionCredential, now = new Date()): SubscriptionStatus {
  requireValidDate(now, "Membership status time");
  const time = now.getTime();
  const periodEnd = Date.parse(credential.periodEnd);
  const graceEnd = Date.parse(credential.graceEndsAt);
  if (time >= graceEnd) return "expired";
  if (time >= periodEnd) return "grace";
  if (time >= periodEnd - RENEWAL_WINDOW_DAYS * DAY_MS) return "renewal_due";
  return "active";
}

export function getSubscriptionCountdown(credential: SubscriptionCredential, now = new Date()): SubscriptionCountdown {
  const status = deriveSubscriptionStatus(credential, now);
  const target = status === "grace" ? credential.graceEndsAt : credential.periodEnd;
  return {
    status,
    target,
    remainingSeconds: Math.max(0, Math.ceil((Date.parse(target) - now.getTime()) / 1_000)),
    renewalOpen: status === "renewal_due" || status === "grace",
  };
}

export function serializeSubscriptionCredential(credential: SubscriptionCredential): string {
  validateCredentialShape(credential);
  if (!verifySubscriptionCredential(credential, { now: new Date(credential.periodStart) }).cryptographicallyValid) throw new Error("Membership credential is invalid.");
  return JSON.stringify(credential, null, 2);
}

export function parseSubscriptionCredential(serialized: string): SubscriptionCredential {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch { throw new Error("Membership credential JSON is malformed."); }
  validateCredentialShape(parsed);
  const verification = verifySubscriptionCredential(parsed, { now: new Date(parsed.periodStart) });
  if (!verification.cryptographicallyValid) throw new Error(verification.reason);
  return parsed;
}

export function getSubscriptionSecurityModel(): SubscriptionSecurityModel {
  return {
    proven: ["Knowledge of the current anonymous membership secret", "Credential integrity across tier, epoch, service, validity, and rotating commitments", "Possession continuity from the previous membership secret during renewal"],
    issuerGuarantees: ["A trusted issuer attests that it observed the required private settlement before signing", "The issuer binds the hidden payment commitment to the tier, price, period, and service recipient"],
    rotated: ["Service-scoped membership secret", "Service metadata viewing/decryption key", "Bearer access token", "Hidden payment commitment salt"],
    hidden: ["Wallet address and user identity", "Private payment transaction hash and origin", "Bearer access token", "Service viewing/decryption key", "STRK20 notes and pool viewing key"],
    publicOrObservable: ["Membership tier and validity window when the credential is presented", "Opaque membership and credential commitments", "Issuer identity and public key", "Pool transaction timing, fees, nullifiers, and separate deposit or withdrawal edges"],
    limitations: ["The STRK20 viewing key is registered once and immutable; CipherBill never reads or rotates it", "A self-issued credential is cryptographically consistent but is not independent proof of payment", "A service needs an issuer verification policy and revocation channel for cross-device enforcement", "Distinctive payment timing or amounts can reduce the anonymity set"],
  };
}

function issueMembership(input: {
  tier: SubscriptionTier;
  epoch: number;
  serviceRecipient: string;
  paymentTransactionHash: string;
  issuerId: string;
  issuerPrivateKey: string;
  periodStart: Date;
  previousCredential?: SubscriptionCredential;
  previousMembershipSecret?: string;
}, entropy: SubscriptionEntropy): SubscriptionMembershipBundle {
  const tier = requireTier(input.tier);
  const issuerPrivateKey = requireCurveScalar(input.issuerPrivateKey, false, "Issuer private key");
  const membershipSecret = requireSecretScalar(entropy.membershipSecret ?? randomScalar(), "Membership secret");
  const serviceViewingKey = requireRandomBytes(entropy.serviceViewingKey ?? randomBytes(32), "Service viewing key");
  const accessTokenBytes = requireRandomBytes(entropy.accessToken ?? randomBytes(32), "Access token");
  const accessToken = `sub_${toBase64Url(accessTokenBytes)}`;
  const paymentSalt = requireSecretScalar(entropy.paymentSalt ?? randomScalar(), "Payment salt");
  const paymentTransactionHash = requireTransactionHash(input.paymentTransactionHash);
  const membershipPublicKey = pointToFelts(multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, membershipSecret));
  const issuerPublicKey = pointToFelts(multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, issuerPrivateKey));
  const periodStart = requireIsoTimestamp(input.periodStart.toISOString(), "Membership period start");
  const periodEnd = addUtcCalendarMonth(input.periodStart).toISOString();
  const graceEndsAt = new Date(Date.parse(periodEnd) + GRACE_PERIOD_DAYS * DAY_MS).toISOString();
  const membershipId = entropy.membershipId ?? `member_${toBase64Url(randomBytes(18))}`;
  if (!/^member_[A-Za-z0-9_-]{16,48}$/.test(membershipId)) throw new Error("Membership ID is invalid.");
  const previousCredentialCommitment = input.previousCredential?.stateCommitment;
  const core: CredentialCore = {
    kind: CREDENTIAL_KIND,
    version: SUBSCRIPTION_ENGINE_VERSION,
    proofSystem: SUBSCRIPTION_PROOF_SYSTEM,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    tokenAddress: STRK_TOKEN_ADDRESS,
    membershipId,
    tier: input.tier,
    epoch: input.epoch,
    serviceRecipient: normalizeStarknetAddress(input.serviceRecipient),
    periodStart,
    periodEnd,
    graceEndsAt,
    priceBaseUnits: decimalToBaseUnits(tier.monthlyPrice, 18),
    membershipPublicKey,
    serviceViewingKeyCommitment: commitText(VIEW_KEY_DOMAIN, toBase64Url(serviceViewingKey)),
    accessTokenCommitment: commitText(ACCESS_TOKEN_DOMAIN, accessToken),
    paymentCommitment: toHex(hashElements([PAYMENT_DOMAIN, paymentTransactionHash, paymentSalt])),
    ...(previousCredentialCommitment ? { previousCredentialCommitment } : {}),
    issuerId: requireText(input.issuerId, "Issuer ID", 64, /^[A-Za-z0-9_.-]+$/),
    issuerPublicKey,
  };
  const stateCommitment = toHex(computeStateCommitment(core));
  const credentialWithoutSignatures = { ...core, stateCommitment };
  const possessionProof = createSchnorrProof(POSSESSION_DOMAIN, membershipSecret, possessionTranscript(credentialWithoutSignatures), entropy.possessionNonce);
  const rotationProof = input.previousCredential && input.previousMembershipSecret
    ? createSchnorrProof(ROTATION_DOMAIN, requireCurveScalar(input.previousMembershipSecret, false, "Previous membership secret"), rotationTranscript(input.previousCredential, credentialWithoutSignatures), entropy.rotationNonce)
    : undefined;
  const unsigned = { ...credentialWithoutSignatures, possessionProof, ...(rotationProof ? { rotationProof } : {}) };
  const issuerSignature = createSchnorrProof(ISSUER_DOMAIN, issuerPrivateKey, issuerTranscript(unsigned), entropy.issuerNonce);
  const credential: SubscriptionCredential = {
    ...unsigned,
    issuerSignature,
    notice: "Application-level anonymous membership proof. The issuer signature certifies private settlement; the wallet retains the immutable STRK20 viewing key. Service-scoped keys rotate each epoch.",
  };
  const secrets: SubscriptionSecrets = {
    membershipSecret: toHex(membershipSecret),
    serviceViewingKey: toBase64Url(serviceViewingKey),
    accessToken,
    paymentSalt: toHex(paymentSalt),
    paymentTransactionHash: toHex(paymentTransactionHash),
  };
  if (!verifySubscriptionOpening({ credential, secrets })) throw new Error("Generated membership failed its own cryptographic verification.");
  if (input.previousCredential && !verifySubscriptionRotation(input.previousCredential, credential)) throw new Error("Generated membership rotation proof is invalid.");
  return { credential, secrets };
}

function validateCredentialShape(value: unknown): asserts value is SubscriptionCredential {
  const baseKeys = ["kind", "version", "proofSystem", "network", "poolAddress", "tokenAddress", "membershipId", "tier", "epoch", "serviceRecipient", "periodStart", "periodEnd", "graceEndsAt", "priceBaseUnits", "membershipPublicKey", "serviceViewingKeyCommitment", "accessTokenCommitment", "paymentCommitment", "stateCommitment", "possessionProof", "issuerId", "issuerPublicKey", "issuerSignature", "notice"];
  assertAllowedKeys(value, [...baseKeys, "previousCredentialCommitment", "rotationProof"], baseKeys, "Membership credential");
  const credential = value as unknown as SubscriptionCredential;
  if (credential.kind !== CREDENTIAL_KIND || credential.version !== SUBSCRIPTION_ENGINE_VERSION || credential.proofSystem !== SUBSCRIPTION_PROOF_SYSTEM || credential.network !== MAINNET_CHAIN_ID || credential.poolAddress !== STRK20_POOL_ADDRESS || credential.tokenAddress !== STRK_TOKEN_ADDRESS) throw new Error("Membership credential context is invalid.");
  if (!/^member_[A-Za-z0-9_-]{16,48}$/.test(credential.membershipId)) throw new Error("Membership ID is invalid.");
  const tier = requireTier(credential.tier);
  if (!Number.isInteger(credential.epoch) || credential.epoch < 1 || credential.epoch > 10_000) throw new Error("Membership epoch is invalid.");
  credential.serviceRecipient = normalizeStarknetAddress(credential.serviceRecipient);
  const periodStart = requireIsoTimestamp(credential.periodStart, "Membership period start");
  const periodEnd = requireIsoTimestamp(credential.periodEnd, "Membership period end");
  const graceEndsAt = requireIsoTimestamp(credential.graceEndsAt, "Membership grace end");
  if (periodEnd !== addUtcCalendarMonth(new Date(periodStart)).toISOString() || Date.parse(graceEndsAt) !== Date.parse(periodEnd) + GRACE_PERIOD_DAYS * DAY_MS) throw new Error("Membership billing period is invalid.");
  if (credential.priceBaseUnits !== decimalToBaseUnits(tier.monthlyPrice, 18)) throw new Error("Membership price does not match its tier.");
  assertPointShape(credential.membershipPublicKey, "Membership public key");
  pointFromFelts(credential.membershipPublicKey, "Membership public key");
  for (const [label, felt] of [["Service viewing key commitment", credential.serviceViewingKeyCommitment], ["Access token commitment", credential.accessTokenCommitment], ["Payment commitment", credential.paymentCommitment], ["State commitment", credential.stateCommitment]] as const) requireFelt(felt, label);
  if (credential.previousCredentialCommitment) requireFelt(credential.previousCredentialCommitment, "Previous credential commitment");
  assertProofShape(credential.possessionProof, "Possession proof");
  if (credential.rotationProof) assertProofShape(credential.rotationProof, "Rotation proof");
  requireText(credential.issuerId, "Issuer ID", 64, /^[A-Za-z0-9_.-]+$/);
  assertPointShape(credential.issuerPublicKey, "Issuer public key");
  pointFromFelts(credential.issuerPublicKey, "Issuer public key");
  assertProofShape(credential.issuerSignature, "Issuer signature");
  if (typeof credential.notice !== "string" || !credential.notice.includes("immutable STRK20 viewing key")) throw new Error("Membership credential notice is invalid.");
}

function computeStateCommitment(core: CredentialCore | SubscriptionCredential): bigint {
  return hashElements([MEMBERSHIP_DOMAIN, ...coreTranscript(core)]);
}

function coreTranscript(core: CredentialCore | SubscriptionCredential): bigint[] {
  const membershipKey = pointFromFelts(core.membershipPublicKey, "Membership public key");
  const issuerKey = pointFromFelts(core.issuerPublicKey, "Issuer public key");
  return [
    BigInt(SUBSCRIPTION_ENGINE_VERSION), hash.starknetKeccak(core.membershipId), tierCode(core.tier), BigInt(core.epoch),
    BigInt(core.serviceRecipient), timestampSeconds(core.periodStart), timestampSeconds(core.periodEnd), timestampSeconds(core.graceEndsAt),
    BigInt(core.priceBaseUnits), membershipKey.x, membershipKey.y, BigInt(core.serviceViewingKeyCommitment), BigInt(core.accessTokenCommitment),
    BigInt(core.paymentCommitment), core.previousCredentialCommitment ? BigInt(core.previousCredentialCommitment) : 0n,
    hash.starknetKeccak(core.issuerId), issuerKey.x, issuerKey.y, BigInt(STRK20_POOL_ADDRESS), BigInt(STRK_TOKEN_ADDRESS),
  ];
}

function possessionTranscript(credential: Pick<SubscriptionCredential, "stateCommitment" | "membershipPublicKey" | "tier" | "epoch">): bigint[] {
  const key = pointFromFelts(credential.membershipPublicKey, "Membership public key");
  return [BigInt(credential.stateCommitment), key.x, key.y, tierCode(credential.tier), BigInt(credential.epoch)];
}

function rotationTranscript(previous: SubscriptionCredential, next: Pick<SubscriptionCredential, "stateCommitment" | "membershipPublicKey" | "tier" | "epoch" | "paymentCommitment" | "periodStart" | "periodEnd">): bigint[] {
  const nextKey = pointFromFelts(next.membershipPublicKey, "Next membership public key");
  return [BigInt(previous.stateCommitment), BigInt(next.stateCommitment), nextKey.x, nextKey.y, tierCode(next.tier), BigInt(next.epoch), BigInt(next.paymentCommitment), timestampSeconds(next.periodStart), timestampSeconds(next.periodEnd)];
}

function issuerTranscript(credential: Pick<SubscriptionCredential, "stateCommitment" | "possessionProof" | "rotationProof" | "issuerId" | "issuerPublicKey">): bigint[] {
  const possessionNonce = pointFromFelts(credential.possessionProof.nonceCommitment, "Possession nonce");
  const rotationNonce = credential.rotationProof ? pointFromFelts(credential.rotationProof.nonceCommitment, "Rotation nonce") : null;
  const issuerKey = pointFromFelts(credential.issuerPublicKey, "Issuer public key");
  return [
    BigInt(credential.stateCommitment), possessionNonce.x, possessionNonce.y, BigInt(credential.possessionProof.response),
    rotationNonce?.x ?? 0n, rotationNonce?.y ?? 0n, credential.rotationProof ? BigInt(credential.rotationProof.response) : 0n,
    hash.starknetKeccak(credential.issuerId), issuerKey.x, issuerKey.y,
  ];
}

function createSchnorrProof(domain: bigint, secret: bigint, transcript: bigint[], suppliedNonce?: bigint): SubscriptionSchnorrProof {
  const nonce = requireSecretScalar(suppliedNonce ?? randomScalar(), "Schnorr nonce");
  const publicKey = multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, secret);
  const noncePoint = multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, nonce);
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(mod(nonce + challenge * secret, CURVE_ORDER)) };
}

function verifySchnorrProof(domain: bigint, publicKey: CurvePoint, proof: SubscriptionSchnorrProof, transcript: bigint[]): boolean {
  const noncePoint = pointFromFelts(proof.nonceCommitment, "Schnorr nonce commitment");
  const response = requireCurveScalar(proof.response, true, "Schnorr response");
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, response).equals(noncePoint.add(multiplyPoint(publicKey, challenge)));
}

function schnorrChallenge(domain: bigint, publicKey: CurvePoint, noncePoint: CurvePoint, transcript: bigint[]): bigint {
  return mod(hashElements([domain, publicKey.x, publicKey.y, noncePoint.x, noncePoint.y, ...transcript]), CURVE_ORDER);
}

function addUtcCalendarMonth(value: Date): Date {
  requireValidDate(value, "Calendar month start");
  const year = value.getUTCFullYear();
  const month = value.getUTCMonth();
  const day = value.getUTCDate();
  const targetMonth = month + 1;
  const lastDay = new Date(Date.UTC(year, targetMonth + 1, 0)).getUTCDate();
  return new Date(Date.UTC(year, targetMonth, Math.min(day, lastDay), value.getUTCHours(), value.getUTCMinutes(), value.getUTCSeconds(), value.getUTCMilliseconds()));
}

function requireTier(tier: SubscriptionTier) {
  const definition = SUBSCRIPTION_TIERS[tier];
  if (!definition) throw new Error("Subscription tier is invalid.");
  return definition;
}

function tierCode(tier: SubscriptionTier): bigint {
  const index = (Object.keys(SUBSCRIPTION_TIERS) as SubscriptionTier[]).indexOf(tier);
  if (index < 0) throw new Error("Subscription tier is invalid.");
  return BigInt(index + 1);
}

function commitText(domain: bigint, value: string): string {
  if (typeof value !== "string" || !value) throw new Error("Rotating membership secret is missing.");
  return toHex(hashElements([domain, hash.starknetKeccak(value)]));
}

function requireTransactionHash(value: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/i.test(value)) throw new Error("Private payment transaction hash is invalid.");
  return requireFelt(value, "Private payment transaction hash");
}

function assertAllowedKeys(value: unknown, allowed: readonly string[], required: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) throw new Error(`${label} contains unsupported or missing fields.`);
}

function assertPointShape(value: unknown, label: string): asserts value is SubscriptionCurvePoint {
  assertAllowedKeys(value, ["x", "y"], ["x", "y"], label);
}

function assertProofShape(value: unknown, label: string): asserts value is SubscriptionSchnorrProof {
  assertAllowedKeys(value, ["nonceCommitment", "response"], ["nonceCommitment", "response"], label);
  assertPointShape(value.nonceCommitment, `${label} nonce`);
  if (typeof value.response !== "string") throw new Error(`${label} response is invalid.`);
  pointFromFelts(value.nonceCommitment, `${label} nonce`);
  requireCurveScalar(value.response, true, `${label} response`);
}

function pointToFelts(point: CurvePoint): SubscriptionCurvePoint {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: SubscriptionCurvePoint, label: string): CurvePoint {
  if (!point || typeof point !== "object") throw new Error(`${label} is invalid.`);
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, label), y: requireFelt(point.y, label) });
  parsed.assertValidity();
  return parsed;
}

function multiplyPoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const normalized = mod(scalar, CURVE_ORDER);
  return normalized === 0n ? ec.starkCurve.ProjectivePoint.ZERO : point.multiply(normalized);
}

function requireFelt(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is not a felt.`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error(`${label} is outside the Stark field.`);
  return parsed;
}

function requireCurveScalar(value: string, allowZero: boolean, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is invalid.`);
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return parsed;
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return value;
}

function requireRandomBytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32 || value.every((byte) => byte === 0)) throw new Error(`${label} must contain 32 non-zero-capable random bytes.`);
  return value;
}

function requireText(value: unknown, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireValidDate(value: Date, label: string): void {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} is invalid.`);
}

function timestampSeconds(value: string): bigint {
  return BigInt(Math.floor(Date.parse(requireIsoTimestamp(value, "Timestamp")) / 1_000));
}

function randomScalar(): bigint {
  return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey());
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function toBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function hashElements(values: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function mod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder >= 0n ? remainder : remainder + modulus;
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

type CurvePoint = ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>;
