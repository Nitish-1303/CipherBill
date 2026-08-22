import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const MULTISIG_ESCROW_VERSION = 1 as const;
export const MULTISIG_ESCROW_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const MAX_ESCROW_PARTICIPANTS = 10;
export const MAX_ESCROW_MILESTONES = 8;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const MAX_TIMELOCK_MS = 2 * 365 * 24 * 60 * 60 * 1_000;
const ESCROW_DOMAIN = hash.starknetKeccak("CipherBill multiparty escrow v1");
const CLAIM_SECRET_DOMAIN = hash.starknetKeccak("CipherBill escrow milestone secret v1");
const CLAIM_COMMITMENT_DOMAIN = hash.starknetKeccak("CipherBill escrow helper claim v1");
const RELEASE_COMMITMENT_DOMAIN = hash.starknetKeccak("CipherBill encrypted escrow release v1");
const APPROVAL_DOMAIN = hash.starknetKeccak("CipherBill escrow guardian approval v1");
const SHARE_TAG_DOMAIN = hash.starknetKeccak("CipherBill escrow private share v1");
const ENVELOPE_KIND = "cipherbill.multisig-escrow" as const;
const SHARE_KIND = "cipherbill.escrow-share" as const;
const ENCRYPTION_ALGORITHM = "AES-GCM-256" as const;

export interface EscrowParticipantInput {
  participantId: string;
  displayAlias: string;
}

export interface EscrowMilestoneInput {
  milestoneId: string;
  title: string;
  recipientAddress: string;
  amountBaseUnits: string;
  unlockAt: string;
}

export interface CreateMultiPartyEscrowInput {
  invoiceId: string;
  organizationName: string;
  threshold: number;
  participants: EscrowParticipantInput[];
  milestones: EscrowMilestoneInput[];
}

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface EscrowParticipantSlot {
  participantId: string;
  displayAlias: string;
  shareIndex: number;
}

export interface EncryptedEscrowMilestone {
  milestoneId: string;
  unlockAt: string;
  claimCommitment: string;
  releaseCommitment: string;
  iv: string;
  ciphertext: string;
  ciphertextDigest: string;
}

export interface MultiPartyEscrowEnvelope {
  kind: typeof ENVELOPE_KIND;
  version: typeof MULTISIG_ESCROW_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  tokenAddress: typeof STRK_TOKEN_ADDRESS;
  algorithm: typeof ENCRYPTION_ALGORITHM;
  escrowId: string;
  organizationName: string;
  threshold: number;
  participantSlots: EscrowParticipantSlot[];
  coefficientCommitments: CurvePointFelts[];
  milestones: EncryptedEscrowMilestone[];
  escrowCommitment: string;
  createdAt: string;
  notice: string;
}

/** Secret bearer material. Never publish or store beside the envelope. */
export interface EscrowKeyShare {
  kind: typeof SHARE_KIND;
  version: typeof MULTISIG_ESCROW_VERSION;
  escrowId: string;
  participantId: string;
  shareIndex: number;
  shareValue: string;
  verificationTag: string;
}

export interface MultiPartyEscrowBundle {
  envelope: MultiPartyEscrowEnvelope;
  shares: EscrowKeyShare[];
}

export interface EscrowApproval {
  version: typeof MULTISIG_ESCROW_VERSION;
  escrowId: string;
  milestoneId: string;
  participantId: string;
  decision: "approve";
  createdAt: string;
  nonceCommitment: CurvePointFelts;
  response: string;
}

export type TimelockEvidence =
  | { source: "local_clock"; timestamp: string }
  | { source: "starknet_block"; timestamp: string; chainId: typeof MAINNET_CHAIN_ID; blockNumber: number; blockHash: string };

export interface EscrowReleasePayload {
  version: typeof MULTISIG_ESCROW_VERSION;
  escrowId: string;
  invoiceId: string;
  milestoneId: string;
  title: string;
  recipientAddress: string;
  tokenAddress: typeof STRK_TOKEN_ADDRESS;
  amountBaseUnits: string;
  unlockAt: string;
}

export interface UnlockedEscrowMilestone {
  payload: EscrowReleasePayload;
  releaseSecret: string;
  approvalCount: number;
  threshold: number;
  timelockEvidence: TimelockEvidence;
  claimCommitment: string;
  releaseCommitment: string;
}

export interface EscrowMilestoneStatus {
  milestoneId: string;
  unlockAt: string;
  unlockedByTime: boolean;
  approvals: number;
  threshold: number;
  thresholdMet: boolean;
  releasable: boolean;
  remainingMs: number;
}

export interface EscrowHelperClaimEncoder {
  contractAddress: string;
  encodeClaim(input: {
    claimCommitment: string;
    releaseSecret: string;
    unlockAtSeconds: string;
    openNoteId: "${openNoteIds[0]}";
    poolAddress: "${poolAddress}";
  }): string[];
}

interface EscrowEntropy {
  secret?: bigint;
  polynomialCoefficients?: bigint[];
  approvalNonce?: bigint;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
  createId?: () => string;
}

export async function createMultiPartyEscrow(
  input: CreateMultiPartyEscrowInput,
  now = new Date(),
  entropy: EscrowEntropy = {},
): Promise<MultiPartyEscrowBundle> {
  const normalized = normalizeCreateInput(input, now);
  const escrowId = entropy.createId?.() ?? `esc_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!/^esc_[A-Za-z0-9_-]{1,48}$/.test(escrowId)) throw new Error("Escrow ID is invalid.");
  const secret = requireSecretScalar(entropy.secret ?? randomScalar(), "Escrow secret");
  const suppliedCoefficients = entropy.polynomialCoefficients ?? [];
  if (suppliedCoefficients.length && suppliedCoefficients.length !== normalized.threshold - 1) {
    throw new Error("Polynomial coefficient count must equal threshold minus one.");
  }
  const coefficients = [secret, ...Array.from({ length: normalized.threshold - 1 }, (_, index) =>
    requireSecretScalar(suppliedCoefficients[index] ?? randomScalar(), `Polynomial coefficient ${index + 1}`))];
  const coefficientCommitments = coefficients.map((coefficient) => pointToFelts(ec.starkCurve.ProjectivePoint.BASE.multiply(coefficient)));
  const participantSlots = normalized.participants.map((participant, index) => ({ ...participant, shareIndex: index + 1 }));

  const milestonePlans = normalized.milestones.map((milestone) => {
    const releaseSecret = deriveReleaseSecret(secret, milestone.milestoneId);
    const unlockSeconds = BigInt(Math.floor(Date.parse(milestone.unlockAt) / 1_000));
    const claimCommitment = hashElements([CLAIM_COMMITMENT_DOMAIN, releaseSecret, unlockSeconds]);
    const payload: EscrowReleasePayload = {
      version: MULTISIG_ESCROW_VERSION,
      escrowId,
      invoiceId: normalized.invoiceId,
      milestoneId: milestone.milestoneId,
      title: milestone.title,
      recipientAddress: milestone.recipientAddress,
      tokenAddress: STRK_TOKEN_ADDRESS,
      amountBaseUnits: milestone.amountBaseUnits,
      unlockAt: milestone.unlockAt,
    };
    const releaseCommitment = computeReleaseCommitment(payload, releaseSecret);
    return { payload, releaseSecret, claimCommitment, releaseCommitment };
  });

  const escrowCommitment = hashElements([
    ESCROW_DOMAIN,
    hash.starknetKeccak(escrowId),
    BigInt(normalized.threshold),
    BigInt(participantSlots.length),
    ...coefficientCommitments.flatMap((point) => [BigInt(point.x), BigInt(point.y)]),
    ...milestonePlans.flatMap((plan) => [plan.claimCommitment, plan.releaseCommitment]),
  ]);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const milestones: EncryptedEscrowMilestone[] = [];
  for (const plan of milestonePlans) {
    const iv = random(new Uint8Array(12));
    if (iv.length !== 12) throw new Error("Escrow encryption nonce must be 12 bytes.");
    const header = {
      escrowId,
      milestoneId: plan.payload.milestoneId,
      unlockAt: plan.payload.unlockAt,
      claimCommitment: toHex(plan.claimCommitment),
      releaseCommitment: toHex(plan.releaseCommitment),
      escrowCommitment: toHex(escrowCommitment),
    };
    const key = await deriveAesKey(plan.releaseSecret, "encrypt");
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: milestoneAssociatedData(header) },
      key,
      new TextEncoder().encode(JSON.stringify(plan.payload)),
    ));
    milestones.push({
      milestoneId: plan.payload.milestoneId,
      unlockAt: plan.payload.unlockAt,
      claimCommitment: header.claimCommitment,
      releaseCommitment: header.releaseCommitment,
      iv: toBase64Url(iv),
      ciphertext: toBase64Url(ciphertext),
      ciphertextDigest: await sha256Base64Url(ciphertext),
    });
  }

  const envelope: MultiPartyEscrowEnvelope = {
    kind: ENVELOPE_KIND,
    version: MULTISIG_ESCROW_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    tokenAddress: STRK_TOKEN_ADDRESS,
    algorithm: ENCRYPTION_ALGORITHM,
    escrowId,
    organizationName: normalized.organizationName,
    threshold: normalized.threshold,
    participantSlots,
    coefficientCommitments,
    milestones,
    escrowCommitment: toHex(escrowCommitment),
    createdAt: now.toISOString(),
    notice: "Client-generated encrypted escrow envelope. Key shares are independent bearer secrets; distribute them over separate authenticated channels. Direct wallet release is threshold-gated by this client, while unavoidable onchain custody requires an audited stateful STRK20 helper.",
  };
  validateEscrowEnvelope(envelope);

  const shares = participantSlots.map((slot) => {
    const shareValue = evaluatePolynomial(coefficients, BigInt(slot.shareIndex));
    return {
      kind: SHARE_KIND,
      version: MULTISIG_ESCROW_VERSION,
      escrowId,
      participantId: slot.participantId,
      shareIndex: slot.shareIndex,
      shareValue: toHex(shareValue),
      verificationTag: toHex(hashElements([
        SHARE_TAG_DOMAIN,
        hash.starknetKeccak(escrowId),
        hash.starknetKeccak(slot.participantId),
        BigInt(slot.shareIndex),
        shareValue,
        escrowCommitment,
      ])),
    } satisfies EscrowKeyShare;
  });
  if (!shares.every((share) => verifyEscrowShare(envelope, share))) throw new Error("Generated threshold shares failed verification.");
  return { envelope, shares };
}

export function verifyEscrowShare(envelope: MultiPartyEscrowEnvelope, share: EscrowKeyShare): boolean {
  try {
    validateEscrowEnvelope(envelope);
    validateEscrowShare(share);
    if (share.escrowId !== envelope.escrowId) return false;
    const slot = envelope.participantSlots.find((candidate) => candidate.participantId === share.participantId);
    if (!slot || slot.shareIndex !== share.shareIndex) return false;
    const value = requireScalar(share.shareValue, true);
    const expectedTag = hashElements([
      SHARE_TAG_DOMAIN,
      hash.starknetKeccak(envelope.escrowId),
      hash.starknetKeccak(share.participantId),
      BigInt(share.shareIndex),
      value,
      BigInt(envelope.escrowCommitment),
    ]);
    if (expectedTag !== BigInt(share.verificationTag)) return false;
    const left = ec.starkCurve.ProjectivePoint.BASE.multiply(value);
    const right = publicSharePoint(envelope, share.shareIndex);
    return left.equals(right);
  } catch {
    return false;
  }
}

export function serializeEscrowShare(share: EscrowKeyShare): string {
  validateEscrowShare(share);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(share)));
}

export function parseEscrowShare(encoded: string): EscrowKeyShare {
  if (typeof encoded !== "string" || !encoded || encoded.length > 4_096 || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error("Escrow share encoding is invalid.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded)));
  } catch {
    throw new Error("Escrow share could not be decoded.");
  }
  validateEscrowShare(parsed);
  return parsed;
}

export function createEscrowApproval(
  envelope: MultiPartyEscrowEnvelope,
  milestoneId: string,
  share: EscrowKeyShare,
  createdAt = new Date(),
  entropy: Pick<EscrowEntropy, "approvalNonce"> = {},
): EscrowApproval {
  validateEscrowEnvelope(envelope);
  if (!verifyEscrowShare(envelope, share)) throw new Error("Escrow share is invalid or belongs to another guardian.");
  const milestone = requireMilestone(envelope, milestoneId);
  const shareScalar = requireScalar(share.shareValue, true);
  const nonce = requireSecretScalar(entropy.approvalNonce ?? randomScalar(), "Approval nonce");
  const nonceCommitment = ec.starkCurve.ProjectivePoint.BASE.multiply(nonce);
  const createdAtIso = createdAt.toISOString();
  const publicShare = publicSharePoint(envelope, share.shareIndex);
  const challenge = approvalChallenge(envelope, milestone, share.participantId, createdAtIso, publicShare, nonceCommitment);
  return {
    version: MULTISIG_ESCROW_VERSION,
    escrowId: envelope.escrowId,
    milestoneId,
    participantId: share.participantId,
    decision: "approve",
    createdAt: createdAtIso,
    nonceCommitment: pointToFelts(nonceCommitment),
    response: toHex(mod(nonce + challenge * shareScalar, CURVE_ORDER)),
  };
}

export function verifyEscrowApproval(envelope: MultiPartyEscrowEnvelope, approval: EscrowApproval): boolean {
  try {
    validateEscrowEnvelope(envelope);
    if (approval.version !== MULTISIG_ESCROW_VERSION || approval.escrowId !== envelope.escrowId || approval.decision !== "approve") return false;
    const milestone = requireMilestone(envelope, approval.milestoneId);
    requireIsoTimestamp(approval.createdAt, "Approval time");
    const slot = envelope.participantSlots.find((candidate) => candidate.participantId === approval.participantId);
    if (!slot) return false;
    const publicShare = publicSharePoint(envelope, slot.shareIndex);
    const nonceCommitment = pointFromFelts(approval.nonceCommitment);
    const response = requireScalar(approval.response, true);
    const challenge = approvalChallenge(envelope, milestone, approval.participantId, approval.createdAt, publicShare, nonceCommitment);
    return ec.starkCurve.ProjectivePoint.BASE.multiply(response).equals(nonceCommitment.add(publicShare.multiply(challenge)));
  } catch {
    return false;
  }
}

export function countValidEscrowApprovals(
  envelope: MultiPartyEscrowEnvelope,
  milestoneId: string,
  approvals: readonly EscrowApproval[],
): number {
  const validParticipants = new Set<string>();
  for (const approval of approvals) {
    if (approval.milestoneId === milestoneId && verifyEscrowApproval(envelope, approval)) validParticipants.add(approval.participantId);
  }
  return validParticipants.size;
}

export function getEscrowMilestoneStatus(
  envelope: MultiPartyEscrowEnvelope,
  milestoneId: string,
  approvals: readonly EscrowApproval[],
  now = new Date(),
): EscrowMilestoneStatus {
  validateEscrowEnvelope(envelope);
  const milestone = requireMilestone(envelope, milestoneId);
  const unlockMs = Date.parse(milestone.unlockAt);
  const approvalCount = countValidEscrowApprovals(envelope, milestoneId, approvals);
  const unlockedByTime = now.getTime() >= unlockMs;
  const thresholdMet = approvalCount >= envelope.threshold;
  return {
    milestoneId,
    unlockAt: milestone.unlockAt,
    unlockedByTime,
    approvals: approvalCount,
    threshold: envelope.threshold,
    thresholdMet,
    releasable: unlockedByTime && thresholdMet,
    remainingMs: Math.max(0, unlockMs - now.getTime()),
  };
}

export async function unlockEscrowMilestone(
  envelope: MultiPartyEscrowEnvelope,
  milestoneId: string,
  shares: readonly EscrowKeyShare[],
  approvals: readonly EscrowApproval[],
  evidence: TimelockEvidence,
): Promise<UnlockedEscrowMilestone> {
  validateEscrowEnvelope(envelope);
  validateTimelockEvidence(evidence);
  const milestone = requireMilestone(envelope, milestoneId);
  if (Date.parse(evidence.timestamp) < Date.parse(milestone.unlockAt)) throw new Error("Escrow timelock has not expired.");
  const validApprovalIds = new Set(approvals.filter((approval) => approval.milestoneId === milestoneId && verifyEscrowApproval(envelope, approval)).map((approval) => approval.participantId));
  if (validApprovalIds.size < envelope.threshold) throw new Error("Escrow approval threshold has not been met.");

  const uniqueShares = new Map<string, EscrowKeyShare>();
  for (const share of shares) {
    if (validApprovalIds.has(share.participantId) && verifyEscrowShare(envelope, share)) uniqueShares.set(share.participantId, share);
  }
  if (uniqueShares.size < envelope.threshold) throw new Error("Threshold key shares are missing or invalid.");
  const selectedShares = [...uniqueShares.values()].slice(0, envelope.threshold);
  const secret = reconstructSecret(selectedShares);
  const secretCommitment = ec.starkCurve.ProjectivePoint.BASE.multiply(secret);
  if (!secretCommitment.equals(pointFromFelts(envelope.coefficientCommitments[0]))) throw new Error("Reconstructed escrow secret does not match the public commitment.");
  const releaseSecret = deriveReleaseSecret(secret, milestoneId);
  const expectedClaimCommitment = hashElements([
    CLAIM_COMMITMENT_DOMAIN,
    releaseSecret,
    BigInt(Math.floor(Date.parse(milestone.unlockAt) / 1_000)),
  ]);
  if (expectedClaimCommitment !== BigInt(milestone.claimCommitment)) throw new Error("Milestone claim commitment does not match the recovered key.");
  const ciphertext = fromBase64Url(milestone.ciphertext);
  if (await sha256Base64Url(ciphertext) !== milestone.ciphertextDigest) throw new Error("Encrypted milestone digest does not match.");
  const header = {
    escrowId: envelope.escrowId,
    milestoneId,
    unlockAt: milestone.unlockAt,
    claimCommitment: milestone.claimCommitment,
    releaseCommitment: milestone.releaseCommitment,
    escrowCommitment: envelope.escrowCommitment,
  };
  const key = await deriveAesKey(releaseSecret, "decrypt");
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(milestone.iv), additionalData: milestoneAssociatedData(header) },
      key,
      ciphertext,
    );
  } catch {
    throw new Error("Escrow release decryption failed. Shares or envelope may be altered.");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new Error("Decrypted escrow release is malformed.");
  }
  validateReleasePayload(payload, envelope, milestone);
  if (computeReleaseCommitment(payload, releaseSecret) !== BigInt(milestone.releaseCommitment)) throw new Error("Escrow release commitment does not match.");
  return {
    payload,
    releaseSecret: toHex(releaseSecret),
    approvalCount: validApprovalIds.size,
    threshold: envelope.threshold,
    timelockEvidence: evidence,
    claimCommitment: milestone.claimCommitment,
    releaseCommitment: milestone.releaseCommitment,
  };
}

/**
 * Direct in-pool release. The Wallet API hides the recipient and amount, but a
 * custodian can bypass this browser policy. Use an audited stateful helper when
 * threshold and timelock rules must be unavoidable onchain.
 */
export function buildDirectEscrowReleaseActions(unlocked: UnlockedEscrowMilestone): STRK20_ACTION[] {
  validateUnlockedMilestone(unlocked);
  return [{
    type: "transfer",
    token: unlocked.payload.tokenAddress,
    amount: unlocked.payload.amountBaseUnits,
    recipient: unlocked.payload.recipientAddress,
  }];
}

/** Builds the two Wallet API actions for an audited helper's claim ABI. */
export function buildEscrowHelperClaimActions(
  unlocked: UnlockedEscrowMilestone,
  encoder: EscrowHelperClaimEncoder,
): STRK20_ACTION[] {
  validateUnlockedMilestone(unlocked);
  const contractAddress = normalizeStarknetAddress(encoder.contractAddress);
  const calldata = encoder.encodeClaim({
    claimCommitment: unlocked.claimCommitment,
    releaseSecret: unlocked.releaseSecret,
    unlockAtSeconds: toHex(BigInt(Math.floor(Date.parse(unlocked.payload.unlockAt) / 1_000))),
    openNoteId: "${openNoteIds[0]}",
    poolAddress: "${poolAddress}",
  });
  if (!Array.isArray(calldata) || !calldata.length || calldata.some((item) => typeof item !== "string" || !item)) {
    throw new Error("Escrow helper encoder returned invalid calldata.");
  }
  return [
    { type: "transfer", token: unlocked.payload.tokenAddress, amount: "OPEN", recipient: contractAddress },
    { type: "invoke", contract: contractAddress, calldata },
  ];
}

function normalizeCreateInput(input: CreateMultiPartyEscrowInput, now: Date): CreateMultiPartyEscrowInput {
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  const organizationName = requireText(input.organizationName, "Organization name", 80);
  if (!Array.isArray(input.participants) || input.participants.length < 2 || input.participants.length > MAX_ESCROW_PARTICIPANTS) {
    throw new Error(`Escrow requires 2 to ${MAX_ESCROW_PARTICIPANTS} guardians.`);
  }
  if (!Number.isInteger(input.threshold) || input.threshold < 2 || input.threshold > input.participants.length) {
    throw new Error("Escrow threshold must be at least 2 and no greater than the guardian count.");
  }
  const participants = input.participants.map((participant) => ({
    participantId: requireText(participant.participantId, "Participant ID", 48, /^[A-Za-z0-9_-]+$/),
    displayAlias: requireText(participant.displayAlias, "Participant alias", 64),
  }));
  if (new Set(participants.map((participant) => participant.participantId)).size !== participants.length) throw new Error("Participant IDs must be unique.");
  if (!Array.isArray(input.milestones) || !input.milestones.length || input.milestones.length > MAX_ESCROW_MILESTONES) {
    throw new Error(`Escrow requires 1 to ${MAX_ESCROW_MILESTONES} milestones.`);
  }
  const milestones = input.milestones.map((milestone) => {
    const unlockAt = requireIsoTimestamp(milestone.unlockAt, "Milestone unlock time");
    const unlockMs = Date.parse(unlockAt);
    if (unlockMs <= now.getTime() || unlockMs - now.getTime() > MAX_TIMELOCK_MS) throw new Error("Milestone unlock must be in the future and within two years.");
    return {
      milestoneId: requireText(milestone.milestoneId, "Milestone ID", 48, /^[A-Za-z0-9_-]+$/),
      title: requireText(milestone.title, "Milestone title", 100),
      recipientAddress: normalizeStarknetAddress(milestone.recipientAddress),
      amountBaseUnits: requireBaseUnits(milestone.amountBaseUnits, "Milestone amount").toString(),
      unlockAt,
    };
  });
  if (new Set(milestones.map((milestone) => milestone.milestoneId)).size !== milestones.length) throw new Error("Milestone IDs must be unique.");
  return { invoiceId, organizationName, threshold: input.threshold, participants, milestones };
}

function validateEscrowEnvelope(envelope: MultiPartyEscrowEnvelope): void {
  if (!envelope || envelope.kind !== ENVELOPE_KIND || envelope.version !== MULTISIG_ESCROW_VERSION || envelope.network !== MAINNET_CHAIN_ID || envelope.poolAddress !== STRK20_POOL_ADDRESS || envelope.tokenAddress !== STRK_TOKEN_ADDRESS || envelope.algorithm !== ENCRYPTION_ALGORITHM) {
    throw new Error("Escrow envelope header is invalid.");
  }
  if (!/^esc_[A-Za-z0-9_-]{1,48}$/.test(envelope.escrowId)) throw new Error("Escrow envelope ID is invalid.");
  requireText(envelope.organizationName, "Organization name", 80);
  requireIsoTimestamp(envelope.createdAt, "Escrow creation time");
  if (!Number.isInteger(envelope.threshold) || envelope.threshold < 2 || envelope.threshold > envelope.participantSlots.length) throw new Error("Escrow threshold is invalid.");
  if (envelope.participantSlots.length < 2 || envelope.participantSlots.length > MAX_ESCROW_PARTICIPANTS) throw new Error("Escrow guardian count is invalid.");
  if (envelope.coefficientCommitments.length !== envelope.threshold) throw new Error("Escrow VSS commitment count is invalid.");
  envelope.coefficientCommitments.forEach(pointFromFelts);
  const participantIds = new Set<string>();
  const shareIndexes = new Set<number>();
  for (const slot of envelope.participantSlots) {
    requireText(slot.participantId, "Participant ID", 48, /^[A-Za-z0-9_-]+$/);
    requireText(slot.displayAlias, "Participant alias", 64);
    if (!Number.isInteger(slot.shareIndex) || slot.shareIndex < 1 || slot.shareIndex > MAX_ESCROW_PARTICIPANTS) throw new Error("Escrow share index is invalid.");
    participantIds.add(slot.participantId);
    shareIndexes.add(slot.shareIndex);
  }
  if (participantIds.size !== envelope.participantSlots.length || shareIndexes.size !== envelope.participantSlots.length) throw new Error("Escrow guardian slots must be unique.");
  if (!Array.isArray(envelope.milestones) || !envelope.milestones.length || envelope.milestones.length > MAX_ESCROW_MILESTONES) throw new Error("Escrow milestone count is invalid.");
  const milestoneIds = new Set<string>();
  for (const milestone of envelope.milestones) {
    requireText(milestone.milestoneId, "Milestone ID", 48, /^[A-Za-z0-9_-]+$/);
    requireIsoTimestamp(milestone.unlockAt, "Milestone unlock time");
    requireFelt(milestone.claimCommitment);
    requireFelt(milestone.releaseCommitment);
    for (const value of [milestone.iv, milestone.ciphertext, milestone.ciphertextDigest]) {
      if (typeof value !== "string" || !value || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Encrypted milestone encoding is invalid.");
    }
    milestoneIds.add(milestone.milestoneId);
  }
  if (milestoneIds.size !== envelope.milestones.length) throw new Error("Escrow milestone IDs must be unique.");
  requireFelt(envelope.escrowCommitment);
  if (typeof envelope.notice !== "string") throw new Error("Escrow notice is missing.");
}

function validateEscrowShare(value: unknown): asserts value is EscrowKeyShare {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Escrow share is invalid.");
  const share = value as EscrowKeyShare;
  const keys = Object.keys(share);
  const allowed = ["kind", "version", "escrowId", "participantId", "shareIndex", "shareValue", "verificationTag"];
  if (keys.some((key) => !allowed.includes(key)) || share.kind !== SHARE_KIND || share.version !== MULTISIG_ESCROW_VERSION || !/^esc_[A-Za-z0-9_-]{1,48}$/.test(share.escrowId)) throw new Error("Escrow share header is invalid.");
  requireText(share.participantId, "Participant ID", 48, /^[A-Za-z0-9_-]+$/);
  if (!Number.isInteger(share.shareIndex) || share.shareIndex < 1 || share.shareIndex > MAX_ESCROW_PARTICIPANTS) throw new Error("Escrow share index is invalid.");
  requireScalar(share.shareValue, true);
  requireFelt(share.verificationTag);
}

function validateTimelockEvidence(evidence: TimelockEvidence): void {
  requireIsoTimestamp(evidence.timestamp, "Timelock evidence time");
  if (evidence.source === "starknet_block") {
    if (evidence.chainId !== MAINNET_CHAIN_ID || !Number.isInteger(evidence.blockNumber) || evidence.blockNumber < 0 || !/^0x[0-9a-f]{1,64}$/i.test(evidence.blockHash)) throw new Error("Starknet timelock evidence is invalid.");
  } else if (evidence.source !== "local_clock") {
    throw new Error("Timelock evidence source is invalid.");
  }
}

function validateReleasePayload(value: unknown, envelope: MultiPartyEscrowEnvelope, milestone: EncryptedEscrowMilestone): asserts value is EscrowReleasePayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Escrow release payload is invalid.");
  const payload = value as EscrowReleasePayload;
  if (payload.version !== MULTISIG_ESCROW_VERSION || payload.escrowId !== envelope.escrowId || payload.milestoneId !== milestone.milestoneId || payload.tokenAddress !== STRK_TOKEN_ADDRESS || payload.unlockAt !== milestone.unlockAt) throw new Error("Escrow release payload does not match its envelope.");
  requireText(payload.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireText(payload.title, "Milestone title", 100);
  normalizeStarknetAddress(payload.recipientAddress);
  requireBaseUnits(payload.amountBaseUnits, "Milestone amount");
}

function validateUnlockedMilestone(unlocked: UnlockedEscrowMilestone): void {
  if (!unlocked || unlocked.approvalCount < unlocked.threshold || unlocked.threshold < 2) throw new Error("Unlocked escrow threshold evidence is invalid.");
  validateTimelockEvidence(unlocked.timelockEvidence);
  const releaseSecret = requireSecretScalar(BigInt(unlocked.releaseSecret), "Release secret");
  const claimCommitment = requireFelt(unlocked.claimCommitment);
  const releaseCommitment = requireFelt(unlocked.releaseCommitment);
  if (!unlocked.payload || unlocked.payload.version !== MULTISIG_ESCROW_VERSION) throw new Error("Unlocked escrow payload is invalid.");
  if (!/^esc_[A-Za-z0-9_-]{1,48}$/.test(unlocked.payload.escrowId)) throw new Error("Unlocked escrow ID is invalid.");
  requireText(unlocked.payload.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireText(unlocked.payload.milestoneId, "Milestone ID", 48, /^[A-Za-z0-9_-]+$/);
  requireText(unlocked.payload.title, "Milestone title", 100);
  const recipientAddress = normalizeStarknetAddress(unlocked.payload.recipientAddress);
  if (recipientAddress !== unlocked.payload.recipientAddress || unlocked.payload.tokenAddress !== STRK_TOKEN_ADDRESS) throw new Error("Unlocked escrow asset details are invalid.");
  requireBaseUnits(unlocked.payload.amountBaseUnits, "Milestone amount");
  requireIsoTimestamp(unlocked.payload.unlockAt, "Milestone unlock time");
  if (Date.parse(unlocked.timelockEvidence.timestamp) < Date.parse(unlocked.payload.unlockAt)) throw new Error("Escrow timelock has not expired.");
  const expectedClaim = hashElements([
    CLAIM_COMMITMENT_DOMAIN,
    releaseSecret,
    BigInt(Math.floor(Date.parse(unlocked.payload.unlockAt) / 1_000)),
  ]);
  if (claimCommitment !== expectedClaim || releaseCommitment !== computeReleaseCommitment(unlocked.payload, releaseSecret)) {
    throw new Error("Unlocked escrow commitments are invalid.");
  }
}

function requireMilestone(envelope: MultiPartyEscrowEnvelope, milestoneId: string): EncryptedEscrowMilestone {
  const milestone = envelope.milestones.find((candidate) => candidate.milestoneId === milestoneId);
  if (!milestone) throw new Error("Escrow milestone does not exist.");
  return milestone;
}

function publicSharePoint(envelope: MultiPartyEscrowEnvelope, shareIndex: number) {
  let result = ec.starkCurve.ProjectivePoint.ZERO;
  let power = 1n;
  for (const commitment of envelope.coefficientCommitments) {
    result = result.add(pointFromFelts(commitment).multiply(power));
    power = mod(power * BigInt(shareIndex), CURVE_ORDER);
  }
  return result;
}

function reconstructSecret(shares: EscrowKeyShare[]): bigint {
  const indexes = new Set(shares.map((share) => share.shareIndex));
  if (indexes.size !== shares.length) throw new Error("Duplicate threshold shares are not allowed.");
  let secret = 0n;
  for (let i = 0; i < shares.length; i += 1) {
    const xi = BigInt(shares[i].shareIndex);
    const yi = requireScalar(shares[i].shareValue, true);
    let numerator = 1n;
    let denominator = 1n;
    for (let j = 0; j < shares.length; j += 1) {
      if (i === j) continue;
      const xj = BigInt(shares[j].shareIndex);
      numerator = mod(numerator * -xj, CURVE_ORDER);
      denominator = mod(denominator * (xi - xj), CURVE_ORDER);
    }
    secret = mod(secret + yi * numerator * modInverse(denominator, CURVE_ORDER), CURVE_ORDER);
  }
  return requireSecretScalar(secret, "Reconstructed escrow secret");
}

function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
  let value = 0n;
  let power = 1n;
  for (const coefficient of coefficients) {
    value = mod(value + coefficient * power, CURVE_ORDER);
    power = mod(power * x, CURVE_ORDER);
  }
  return value;
}

function deriveReleaseSecret(secret: bigint, milestoneId: string): bigint {
  return nonZeroScalar(hashElements([CLAIM_SECRET_DOMAIN, secret, hash.starknetKeccak(milestoneId)]));
}

function computeReleaseCommitment(payload: EscrowReleasePayload, releaseSecret: bigint): bigint {
  return hashElements([
    RELEASE_COMMITMENT_DOMAIN,
    releaseSecret,
    hash.starknetKeccak(payload.escrowId),
    hash.starknetKeccak(payload.invoiceId),
    hash.starknetKeccak(payload.milestoneId),
    hash.starknetKeccak(payload.title),
    BigInt(payload.recipientAddress),
    BigInt(payload.tokenAddress),
    BigInt(payload.amountBaseUnits),
    BigInt(Math.floor(Date.parse(payload.unlockAt) / 1_000)),
  ]);
}

function approvalChallenge(
  envelope: MultiPartyEscrowEnvelope,
  milestone: EncryptedEscrowMilestone,
  participantId: string,
  createdAt: string,
  publicShare: ReturnType<typeof publicSharePoint>,
  nonceCommitment: ReturnType<typeof publicSharePoint>,
): bigint {
  return mod(hashElements([
    APPROVAL_DOMAIN,
    hash.starknetKeccak(envelope.escrowId),
    hash.starknetKeccak(milestone.milestoneId),
    hash.starknetKeccak(participantId),
    BigInt(Math.floor(Date.parse(createdAt) / 1_000)),
    publicShare.x,
    publicShare.y,
    nonceCommitment.x,
    nonceCommitment.y,
    BigInt(envelope.escrowCommitment),
    BigInt(milestone.claimCommitment),
  ]), CURVE_ORDER);
}

function pointToFelts(point: ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>): CurvePointFelts {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: CurvePointFelts) {
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x), y: requireFelt(point.y) });
  parsed.assertValidity();
  return parsed;
}

function milestoneAssociatedData(header: { escrowId: string; milestoneId: string; unlockAt: string; claimCommitment: string; releaseCommitment: string; escrowCommitment: string }): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode([header.escrowId, header.milestoneId, header.unlockAt, header.claimCommitment, header.releaseCommitment, header.escrowCommitment].join("|"));
}

async function deriveAesKey(secret: bigint, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  const scalarBytes = bigintToBytes(secret, 32);
  const domain = new TextEncoder().encode("cipherbill.escrow-release-key.v1");
  const input = new Uint8Array(domain.length + scalarBytes.length);
  input.set(domain);
  input.set(scalarBytes, domain.length);
  const keyBytes = await crypto.subtle.digest("SHA-256", input);
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM", length: 256 }, false, [usage]);
}

function requireText(value: string, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireBaseUnits(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an integer in base units.`);
  const amount = BigInt(value);
  if (amount <= 0n || amount > U128_MAX) throw new Error(`${label} is outside the STRK20 u128 range.`);
  return amount;
}

function requireFelt(value: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Escrow value is not a felt.");
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("Escrow felt is outside the Stark field.");
  return parsed;
}

function requireScalar(value: string, allowZero = false): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Escrow value is not a scalar.");
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error("Escrow scalar is outside the Stark curve order.");
  return parsed;
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return value;
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
  if (low === 0n) throw new Error("Threshold shares cannot be interpolated.");
  return mod(resultLow, modulus);
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function bigintToBytes(value: bigint, length: number): Uint8Array<ArrayBuffer> {
  const hex = value.toString(16).padStart(length * 2, "0");
  if (hex.length > length * 2) throw new Error("Escrow scalar is too large.");
  return Uint8Array.from({ length }, (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

async function sha256Base64Url(value: Uint8Array<ArrayBuffer>): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", value)));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url value.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
