import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const DISPUTE_VAULT_VERSION = 1 as const;
export const DISPUTE_VAULT_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const MAX_DISPUTE_ARBITRATORS = 15;

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const MAX_CASE_LIFETIME_MS = 180 * 24 * 60 * 60 * 1_000;
const VAULT_DOMAIN = hash.starknetKeccak("CipherBill anonymous dispute vault v1");
const VOTE_DOMAIN = hash.starknetKeccak("CipherBill hidden arbitration vote v1");
const AUTH_DOMAIN = hash.starknetKeccak("CipherBill arbitration vote authorization v1");
const RESOLUTION_DOMAIN = hash.starknetKeccak("CipherBill dispute resolution v1");
const EVIDENCE_DOMAIN = hash.starknetKeccak("CipherBill encrypted dispute evidence v1");
const EVIDENCE_KIND = "cipherbill.dispute-evidence.encrypted" as const;
const EVIDENCE_ALGORITHM = "AES-GCM-256" as const;

export type ArbitrationChoice = "claimant" | "respondent" | "split";
export type DisputeOutcome = ArbitrationChoice | "no_quorum";

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface ArbitratorKeypair {
  privateKey: string;
  publicKey: CurvePointFelts;
}

export interface DisputePartyInput {
  displayAlias: string;
  payoutAddress: string;
  collateralBaseUnits: string;
}

export interface DisputeArbitratorInput {
  arbitratorId: string;
  displayAlias: string;
  payoutAddress: string;
  bondBaseUnits: string;
  votingPublicKey: CurvePointFelts;
}

export interface CreateDisputeVaultInput {
  invoiceId: string;
  tokenAddress: string;
  invoicePrincipalBaseUnits: string;
  claimant: DisputePartyInput;
  respondent: DisputePartyInput;
  arbitrators: DisputeArbitratorInput[];
  quorum: number;
  commitDeadline: string;
  revealDeadline: string;
  evidenceCommitment: string;
  treasuryAddress: string;
  loserCollateralSlashBps?: number;
  nonRevealBondSlashBps?: number;
}

export interface DisputeVault {
  version: typeof DISPUTE_VAULT_VERSION;
  vaultId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  tokenAddress: string;
  invoicePrincipalBaseUnits: string;
  claimant: DisputePartyInput;
  respondent: DisputePartyInput;
  arbitrators: DisputeArbitratorInput[];
  quorum: number;
  commitDeadline: string;
  revealDeadline: string;
  evidenceCommitment: string;
  treasuryAddress: string;
  loserCollateralSlashBps: number;
  nonRevealBondSlashBps: number;
  totalVaultBaseUnits: string;
  vaultCommitment: string;
  createdAt: string;
  notice: string;
}

export interface VoteAuthorizationProof {
  nonceCommitment: CurvePointFelts;
  response: string;
}

/** Public record: the choice and salt are deliberately absent until reveal. */
export interface VoteCommitment {
  version: typeof DISPUTE_VAULT_VERSION;
  vaultId: string;
  arbitratorId: string;
  commitment: string;
  committedAt: string;
  authorization: VoteAuthorizationProof;
}

/** Bearer secret. Keep this separate from the public commitment. */
export interface VoteOpening {
  version: typeof DISPUTE_VAULT_VERSION;
  vaultId: string;
  arbitratorId: string;
  choice: ArbitrationChoice;
  salt: string;
}

export interface VoteCommitmentBundle {
  commitment: VoteCommitment;
  opening: VoteOpening;
}

export interface VoteReveal extends VoteOpening {
  revealedAt: string;
}

export interface EvidenceAttachment {
  name: string;
  mediaType: string;
  size: number;
  digest: string;
}

export interface DisputeEvidencePayload {
  disputeReference: string;
  submittedBy: "claimant" | "respondent";
  statement: string;
  attachments: EvidenceAttachment[];
  submittedAt: string;
}

export interface EncryptedDisputeEvidence {
  kind: typeof EVIDENCE_KIND;
  version: typeof DISPUTE_VAULT_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  algorithm: typeof EVIDENCE_ALGORITHM;
  evidenceCommitment: string;
  iv: string;
  ciphertext: string;
  ciphertextDigest: string;
  notice: string;
}

export interface EncryptedDisputeEvidenceBundle {
  envelope: EncryptedDisputeEvidence;
  accessKey: string;
}

export interface ResolutionAllocation {
  recipientAddress: string;
  amountBaseUnits: string;
  reason: "invoice_award" | "collateral_return" | "collateral_award" | "bond_return" | "non_reveal_reward" | "slashing_treasury";
}

export interface SlashingEvent {
  source: "claimant_collateral" | "respondent_collateral" | "arbitrator_bond";
  subjectId: string;
  amountBaseUnits: string;
  reason: "losing_party" | "missing_or_invalid_reveal";
}

export interface DisputeResolution {
  version: typeof DISPUTE_VAULT_VERSION;
  vaultId: string;
  outcome: DisputeOutcome;
  quorum: number;
  validRevealCount: number;
  tallies: Record<ArbitrationChoice, number>;
  allocations: ResolutionAllocation[];
  slashingEvents: SlashingEvent[];
  totalVaultBaseUnits: string;
  resolvedAt: string;
  resolutionCommitment: string;
  notice: string;
}

export interface DisputeHelperEncoder {
  contractAddress: string;
  encodeResolution(input: {
    vaultCommitment: string;
    resolutionCommitment: string;
    outcome: DisputeOutcome;
    tokenAddress: string;
    allocations: Array<ResolutionAllocation & { openNoteId: `\${openNoteIds[${number}]}` }>;
    poolAddress: "${poolAddress}";
  }): string[];
}

export interface DisputeEntropy {
  createId?: () => string;
  privateKey?: bigint;
  voteSalt?: bigint;
  signatureNonce?: bigint;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export function generateArbitratorKeypair(entropy: DisputeEntropy = {}): ArbitratorKeypair {
  const privateKey = requireSecretScalar(entropy.privateKey ?? randomScalar(), "Arbitrator private key");
  return { privateKey: toHex(privateKey), publicKey: pointToFelts(ec.starkCurve.ProjectivePoint.BASE.multiply(privateKey)) };
}

export function createDisputeVault(
  input: CreateDisputeVaultInput,
  now = new Date(),
  entropy: DisputeEntropy = {},
): DisputeVault {
  const normalized = normalizeCreateInput(input, now);
  const vaultId = entropy.createId?.() ?? `dsv_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!/^dsv_[A-Za-z0-9_-]{1,48}$/.test(vaultId)) throw new Error("Dispute vault ID is invalid.");
  const total = calculateVaultTotal(normalized);
  const base: Omit<DisputeVault, "vaultCommitment" | "notice"> = {
    version: DISPUTE_VAULT_VERSION,
    vaultId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    ...normalized,
    totalVaultBaseUnits: total.toString(),
    createdAt: now.toISOString(),
  };
  const vault: DisputeVault = {
    ...base,
    vaultCommitment: toHex(computeVaultCommitment(base)),
    notice: "Client-side signed commit-reveal arbitration. Vote commitments hide choices until opening; they are not zk-SNARKs. Direct wallet settlement is client policy, while unavoidable custody and slashing require an audited stateful STRK20 privacy_invoke helper.",
  };
  validateVault(vault);
  return vault;
}

export async function encryptDisputeEvidence(
  payload: DisputeEvidencePayload,
  entropy: DisputeEntropy = {},
): Promise<EncryptedDisputeEvidenceBundle> {
  const normalized = normalizeEvidence(payload);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const accessKey = random(new Uint8Array(32));
  const iv = random(new Uint8Array(12));
  if (accessKey.length !== 32 || iv.length !== 12) throw new Error("Evidence encryption entropy returned an invalid byte length.");
  const plaintext = new TextEncoder().encode(JSON.stringify(normalized));
  const key = await importEvidenceKey(accessKey, "encrypt");
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: evidenceAssociatedData() },
    key,
    plaintext,
  ));
  const ciphertextDigest = await sha256Base64Url(ciphertext);
  const evidenceCommitment = toHex(hashElements([
    EVIDENCE_DOMAIN,
    bytesToBigint((await crypto.subtle.digest("SHA-256", ciphertext)).slice(0, 31)),
    bytesToBigint(iv),
  ]));
  const envelope: EncryptedDisputeEvidence = {
    kind: EVIDENCE_KIND,
    version: DISPUTE_VAULT_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    algorithm: EVIDENCE_ALGORITHM,
    evidenceCommitment,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
    ciphertextDigest,
    notice: "Encrypted locally. Share the access key with authorized reviewers through a separate authenticated channel; it is not a STRK20 viewing or spending key.",
  };
  validateEvidenceEnvelope(envelope);
  return { envelope, accessKey: toBase64Url(accessKey) };
}

export async function decryptDisputeEvidence(
  envelope: EncryptedDisputeEvidence,
  accessKey: string,
): Promise<DisputeEvidencePayload> {
  validateEvidenceEnvelope(envelope);
  const keyBytes = fromBase64Url(accessKey);
  if (keyBytes.length !== 32) throw new Error("Evidence access key must be 32 bytes.");
  const ciphertext = fromBase64Url(envelope.ciphertext);
  if (await sha256Base64Url(ciphertext) !== envelope.ciphertextDigest) throw new Error("Encrypted evidence digest does not match.");
  const iv = fromBase64Url(envelope.iv);
  const expectedCommitment = toHex(hashElements([
    EVIDENCE_DOMAIN,
    bytesToBigint((await crypto.subtle.digest("SHA-256", ciphertext)).slice(0, 31)),
    bytesToBigint(iv),
  ]));
  if (expectedCommitment !== envelope.evidenceCommitment) throw new Error("Encrypted evidence commitment does not match.");
  try {
    const key = await importEvidenceKey(keyBytes, "decrypt");
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: evidenceAssociatedData() },
      key,
      ciphertext,
    );
    return normalizeEvidence(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as DisputeEvidencePayload);
  } catch (error) {
    if (error instanceof Error && error.message.includes("invalid")) throw error;
    throw new Error("Evidence decryption failed. The access key or envelope may be altered.");
  }
}

export function serializeEncryptedEvidence(envelope: EncryptedDisputeEvidence): string {
  validateEvidenceEnvelope(envelope);
  return JSON.stringify(envelope, null, 2);
}

export function parseEncryptedEvidence(serialized: string): EncryptedDisputeEvidence {
  let value: unknown;
  try { value = JSON.parse(serialized); } catch { throw new Error("Encrypted evidence JSON is malformed."); }
  validateEvidenceEnvelope(value);
  return value;
}

export function commitArbitrationVote(
  vault: DisputeVault,
  arbitratorId: string,
  choice: ArbitrationChoice,
  privateKey: string,
  now = new Date(),
  entropy: DisputeEntropy = {},
): VoteCommitmentBundle {
  validateVault(vault);
  const arbitrator = requireArbitrator(vault, arbitratorId);
  requireChoice(choice);
  requireCommitPhase(vault, now);
  const secretKey = requireScalar(privateKey, false);
  const suppliedPublicKey = ec.starkCurve.ProjectivePoint.BASE.multiply(secretKey);
  if (!suppliedPublicKey.equals(pointFromFelts(arbitrator.votingPublicKey))) throw new Error("Voting private key does not match this arbitrator.");
  const salt = requireSecretScalar(entropy.voteSalt ?? randomScalar(), "Vote salt");
  const commitmentValue = computeVoteCommitment(vault, arbitratorId, choice, salt);
  const committedAt = now.toISOString();
  const nonce = requireSecretScalar(entropy.signatureNonce ?? randomScalar(), "Vote authorization nonce");
  const noncePoint = ec.starkCurve.ProjectivePoint.BASE.multiply(nonce);
  const challenge = voteAuthorizationChallenge(vault, arbitratorId, commitmentValue, committedAt, suppliedPublicKey, noncePoint);
  const response = mod(nonce + challenge * secretKey, CURVE_ORDER);
  return {
    commitment: {
      version: DISPUTE_VAULT_VERSION,
      vaultId: vault.vaultId,
      arbitratorId,
      commitment: toHex(commitmentValue),
      committedAt,
      authorization: { nonceCommitment: pointToFelts(noncePoint), response: toHex(response) },
    },
    opening: {
      version: DISPUTE_VAULT_VERSION,
      vaultId: vault.vaultId,
      arbitratorId,
      choice,
      salt: toHex(salt),
    },
  };
}

export function verifyVoteCommitment(vault: DisputeVault, commitment: VoteCommitment): boolean {
  try {
    validateVault(vault);
    const arbitrator = requireArbitrator(vault, commitment.arbitratorId);
    if (commitment.version !== DISPUTE_VAULT_VERSION || commitment.vaultId !== vault.vaultId) return false;
    const committedMs = Date.parse(requireIsoTimestamp(commitment.committedAt, "Vote commitment time"));
    if (committedMs < Date.parse(vault.createdAt) || committedMs > Date.parse(vault.commitDeadline)) return false;
    const commitmentValue = requireFelt(commitment.commitment, "Vote commitment");
    const response = requireScalar(commitment.authorization.response, true);
    const publicKey = pointFromFelts(arbitrator.votingPublicKey);
    const noncePoint = pointFromFelts(commitment.authorization.nonceCommitment);
    const challenge = voteAuthorizationChallenge(vault, commitment.arbitratorId, commitmentValue, commitment.committedAt, publicKey, noncePoint);
    return ec.starkCurve.ProjectivePoint.BASE.multiply(response).equals(noncePoint.add(publicKey.multiply(challenge)));
  } catch { return false; }
}

export function revealArbitrationVote(
  vault: DisputeVault,
  commitment: VoteCommitment,
  opening: VoteOpening,
  now = new Date(),
): VoteReveal {
  validateVault(vault);
  requireRevealPhase(vault, now);
  if (!verifyVoteCommitment(vault, commitment)) throw new Error("Vote commitment authorization is invalid.");
  if (opening.version !== DISPUTE_VAULT_VERSION || opening.vaultId !== vault.vaultId || opening.arbitratorId !== commitment.arbitratorId) {
    throw new Error("Vote opening does not match its commitment.");
  }
  const salt = requireScalar(opening.salt, false);
  requireChoice(opening.choice);
  if (computeVoteCommitment(vault, opening.arbitratorId, opening.choice, salt) !== BigInt(commitment.commitment)) {
    throw new Error("Vote opening does not match its commitment.");
  }
  return { ...opening, revealedAt: now.toISOString() };
}

export function verifyVoteReveal(vault: DisputeVault, commitment: VoteCommitment, reveal: VoteReveal): boolean {
  try {
    if (!verifyVoteCommitment(vault, commitment) || reveal.vaultId !== vault.vaultId || reveal.arbitratorId !== commitment.arbitratorId || reveal.version !== DISPUTE_VAULT_VERSION) return false;
    requireChoice(reveal.choice);
    const revealedMs = Date.parse(requireIsoTimestamp(reveal.revealedAt, "Vote reveal time"));
    if (revealedMs < Date.parse(vault.commitDeadline) || revealedMs > Date.parse(vault.revealDeadline)) return false;
    return computeVoteCommitment(vault, reveal.arbitratorId, reveal.choice, requireScalar(reveal.salt, false)) === BigInt(commitment.commitment);
  } catch { return false; }
}

export function resolveDisputeVault(
  vault: DisputeVault,
  commitments: readonly VoteCommitment[],
  reveals: readonly VoteReveal[],
  now = new Date(),
): DisputeResolution {
  validateVault(vault);
  if (now.getTime() < Date.parse(vault.revealDeadline)) throw new Error("Dispute reveal window has not closed.");
  assertUnique(commitments.map((item) => item.arbitratorId), "Duplicate vote commitments are not allowed.");
  assertUnique(reveals.map((item) => item.arbitratorId), "Duplicate vote reveals are not allowed.");
  const commitmentByArbitrator = new Map(commitments.filter((item) => verifyVoteCommitment(vault, item)).map((item) => [item.arbitratorId, item]));
  const validReveals = new Map<string, VoteReveal>();
  for (const reveal of reveals) {
    const commitment = commitmentByArbitrator.get(reveal.arbitratorId);
    if (commitment && verifyVoteReveal(vault, commitment, reveal)) validReveals.set(reveal.arbitratorId, reveal);
  }
  const tallies: Record<ArbitrationChoice, number> = { claimant: 0, respondent: 0, split: 0 };
  for (const reveal of validReveals.values()) tallies[reveal.choice] += 1;
  const outcome = determineOutcome(tallies, validReveals.size, vault.quorum);
  const allocations: ResolutionAllocation[] = [];
  const slashingEvents: SlashingEvent[] = [];
  allocatePartyStake(vault, outcome, allocations, slashingEvents);
  allocateArbitratorBonds(vault, validReveals, allocations, slashingEvents);
  const consolidated = consolidateAllocations(allocations);
  const total = consolidated.reduce((sum, allocation) => sum + BigInt(allocation.amountBaseUnits), 0n);
  if (total !== BigInt(vault.totalVaultBaseUnits)) throw new Error("Dispute allocation conservation invariant failed.");
  const resolvedAt = now.toISOString();
  const resolutionBase = {
    version: DISPUTE_VAULT_VERSION,
    vaultId: vault.vaultId,
    outcome,
    quorum: vault.quorum,
    validRevealCount: validReveals.size,
    tallies,
    allocations: consolidated,
    slashingEvents,
    totalVaultBaseUnits: total.toString(),
    resolvedAt,
  };
  return {
    ...resolutionBase,
    resolutionCommitment: toHex(computeResolutionCommitment(vault, resolutionBase)),
    notice: "Deterministic client-side resolution. Only missing or invalid reveals slash arbitrator bonds; an honest minority vote is never slashed. Use an audited stateful helper for unavoidable onchain enforcement.",
  };
}

export function verifyDisputeResolution(
  vault: DisputeVault,
  resolution: DisputeResolution,
  commitments: readonly VoteCommitment[],
  reveals: readonly VoteReveal[],
): boolean {
  try {
    const expected = resolveDisputeVault(vault, commitments, reveals, new Date(resolution.resolvedAt));
    return JSON.stringify(expected) === JSON.stringify(resolution);
  } catch { return false; }
}

/** Private transfers hide their ordinary note recipients and amounts, but this browser rule is bypassable by the connected account. */
export function buildDirectDisputeReleaseActions(vault: DisputeVault, resolution: DisputeResolution): STRK20_ACTION[] {
  validateResolutionPair(vault, resolution);
  return resolution.allocations.map((allocation) => ({
    type: "transfer",
    token: vault.tokenAddress,
    amount: allocation.amountBaseUnits,
    recipient: allocation.recipientAddress,
  }));
}

/** Open-note amounts are public. The exact audited helper ABI remains caller-supplied and is never guessed here. */
export function buildDisputeHelperReleaseActions(
  vault: DisputeVault,
  resolution: DisputeResolution,
  encoder: DisputeHelperEncoder,
): STRK20_ACTION[] {
  validateResolutionPair(vault, resolution);
  const contractAddress = normalizeStarknetAddress(encoder.contractAddress);
  const helperAllocations = resolution.allocations.map((allocation, index) => ({
    ...allocation,
    openNoteId: `\${openNoteIds[${index}]}` as `\${openNoteIds[${number}]}`,
  }));
  const calldata = encoder.encodeResolution({
    vaultCommitment: vault.vaultCommitment,
    resolutionCommitment: resolution.resolutionCommitment,
    outcome: resolution.outcome,
    tokenAddress: vault.tokenAddress,
    allocations: helperAllocations,
    poolAddress: "${poolAddress}",
  });
  if (!Array.isArray(calldata) || !calldata.length || calldata.some((item) => typeof item !== "string" || !item)) {
    throw new Error("Dispute helper encoder returned invalid calldata.");
  }
  return [
    ...helperAllocations.map((): STRK20_ACTION => ({ type: "transfer", token: vault.tokenAddress, amount: "OPEN", recipient: contractAddress })),
    { type: "invoke", contract: contractAddress, calldata },
  ];
}

function normalizeCreateInput(input: CreateDisputeVaultInput, now: Date) {
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  const tokenAddress = normalizeStarknetAddress(input.tokenAddress);
  const invoicePrincipalBaseUnits = requireBaseUnits(input.invoicePrincipalBaseUnits, "Invoice principal").toString();
  const claimant = normalizeParty(input.claimant, "Claimant");
  const respondent = normalizeParty(input.respondent, "Respondent");
  if (claimant.payoutAddress === respondent.payoutAddress) throw new Error("Dispute parties must use distinct payout addresses.");
  if (!Array.isArray(input.arbitrators) || input.arbitrators.length < 3 || input.arbitrators.length > MAX_DISPUTE_ARBITRATORS || input.arbitrators.length % 2 === 0) {
    throw new Error(`Dispute requires an odd panel of 3 to ${MAX_DISPUTE_ARBITRATORS} arbitrators.`);
  }
  const arbitrators = input.arbitrators.map((arbitrator) => ({
    arbitratorId: requireText(arbitrator.arbitratorId, "Arbitrator ID", 48, /^[A-Za-z0-9_-]+$/),
    displayAlias: requireText(arbitrator.displayAlias, "Arbitrator alias", 64),
    payoutAddress: normalizeStarknetAddress(arbitrator.payoutAddress),
    bondBaseUnits: requireBaseUnits(arbitrator.bondBaseUnits, "Arbitrator bond").toString(),
    votingPublicKey: pointToFelts(pointFromFelts(arbitrator.votingPublicKey)),
  }));
  assertUnique(arbitrators.map((item) => item.arbitratorId), "Arbitrator IDs must be unique.");
  assertUnique(arbitrators.map((item) => `${item.votingPublicKey.x}:${item.votingPublicKey.y}`), "Arbitrator voting keys must be unique.");
  if (!Number.isInteger(input.quorum) || input.quorum < 2 || input.quorum > arbitrators.length) throw new Error("Quorum must be between 2 and the panel size.");
  const commitDeadline = requireIsoTimestamp(input.commitDeadline, "Commit deadline");
  const revealDeadline = requireIsoTimestamp(input.revealDeadline, "Reveal deadline");
  if (Date.parse(commitDeadline) <= now.getTime() || Date.parse(revealDeadline) <= Date.parse(commitDeadline) || Date.parse(revealDeadline) - now.getTime() > MAX_CASE_LIFETIME_MS) {
    throw new Error("Commit and reveal deadlines must be ordered, future timestamps within 180 days.");
  }
  const evidenceCommitment = toHex(requireFelt(input.evidenceCommitment, "Evidence commitment"));
  const treasuryAddress = normalizeStarknetAddress(input.treasuryAddress);
  const loserCollateralSlashBps = requireBps(input.loserCollateralSlashBps ?? 2_500, "Losing-party collateral slash");
  const nonRevealBondSlashBps = requireBps(input.nonRevealBondSlashBps ?? 10_000, "Non-reveal bond slash");
  return { invoiceId, tokenAddress, invoicePrincipalBaseUnits, claimant, respondent, arbitrators, quorum: input.quorum, commitDeadline, revealDeadline, evidenceCommitment, treasuryAddress, loserCollateralSlashBps, nonRevealBondSlashBps };
}

function normalizeParty(party: DisputePartyInput, label: string): DisputePartyInput {
  return {
    displayAlias: requireText(party.displayAlias, `${label} alias`, 64),
    payoutAddress: normalizeStarknetAddress(party.payoutAddress),
    collateralBaseUnits: requireBaseUnits(party.collateralBaseUnits, `${label} collateral`).toString(),
  };
}

function normalizeEvidence(payload: DisputeEvidencePayload): DisputeEvidencePayload {
  if (!payload || typeof payload !== "object") throw new Error("Evidence payload is invalid.");
  const disputeReference = requireText(payload.disputeReference, "Dispute reference", 96);
  if (payload.submittedBy !== "claimant" && payload.submittedBy !== "respondent") throw new Error("Evidence submitter is invalid.");
  const statement = requireText(payload.statement, "Evidence statement", 12_000);
  const submittedAt = requireIsoTimestamp(payload.submittedAt, "Evidence submission time");
  if (!Array.isArray(payload.attachments) || payload.attachments.length > 12) throw new Error("Evidence permits at most 12 attachments.");
  const attachments = payload.attachments.map((attachment) => ({
    name: requireText(attachment.name, "Attachment name", 120),
    mediaType: requireText(attachment.mediaType, "Attachment media type", 100, /^[\w.+-]+\/[\w.+-]+$/),
    size: requireSafeInteger(attachment.size, "Attachment size"),
    digest: requireText(attachment.digest, "Attachment digest", 100, /^(sha256:)?[A-Za-z0-9_-]{20,}$/),
  }));
  return { disputeReference, submittedBy: payload.submittedBy, statement, attachments, submittedAt };
}

function validateVault(vault: DisputeVault): void {
  if (!vault || vault.version !== DISPUTE_VAULT_VERSION || vault.network !== MAINNET_CHAIN_ID || vault.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("Dispute vault header is invalid.");
  if (!/^dsv_[A-Za-z0-9_-]{1,48}$/.test(vault.vaultId)) throw new Error("Dispute vault ID is invalid.");
  const normalized = normalizeCreateInput(vault, new Date(Date.parse(vault.createdAt) - 1));
  const total = calculateVaultTotal(normalized);
  if (total.toString() !== vault.totalVaultBaseUnits || computeVaultCommitment({ ...vault, ...normalized }) !== requireFelt(vault.vaultCommitment, "Vault commitment")) throw new Error("Dispute vault commitment is invalid.");
}

function validateEvidenceEnvelope(value: unknown): asserts value is EncryptedDisputeEvidence {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Encrypted evidence envelope is invalid.");
  const envelope = value as EncryptedDisputeEvidence;
  const allowed = ["kind", "version", "network", "poolAddress", "algorithm", "evidenceCommitment", "iv", "ciphertext", "ciphertextDigest", "notice"];
  if (Object.keys(envelope).some((key) => !allowed.includes(key)) || envelope.kind !== EVIDENCE_KIND || envelope.version !== DISPUTE_VAULT_VERSION || envelope.network !== MAINNET_CHAIN_ID || envelope.poolAddress !== STRK20_POOL_ADDRESS || envelope.algorithm !== EVIDENCE_ALGORITHM) throw new Error("Encrypted evidence header is invalid.");
  requireFelt(envelope.evidenceCommitment, "Evidence commitment");
  for (const item of [envelope.iv, envelope.ciphertext, envelope.ciphertextDigest]) if (typeof item !== "string" || !/^[A-Za-z0-9_-]+$/.test(item)) throw new Error("Encrypted evidence encoding is invalid.");
  if (fromBase64Url(envelope.iv).length !== 12 || fromBase64Url(envelope.ciphertextDigest).length !== 32 || typeof envelope.notice !== "string") throw new Error("Encrypted evidence envelope is invalid.");
}

function calculateVaultTotal(input: Pick<DisputeVault, "invoicePrincipalBaseUnits" | "claimant" | "respondent" | "arbitrators">): bigint {
  const total = BigInt(input.invoicePrincipalBaseUnits) + BigInt(input.claimant.collateralBaseUnits) + BigInt(input.respondent.collateralBaseUnits) + input.arbitrators.reduce((sum, item) => sum + BigInt(item.bondBaseUnits), 0n);
  if (total <= 0n || total > U128_MAX) throw new Error("Total dispute vault amount is outside the STRK20 u128 range.");
  return total;
}

function computeVaultCommitment(vault: Omit<DisputeVault, "vaultCommitment" | "notice"> | DisputeVault): bigint {
  return hashElements([
    VAULT_DOMAIN, hash.starknetKeccak(vault.vaultId), hash.starknetKeccak(vault.invoiceId), BigInt(vault.tokenAddress),
    BigInt(vault.invoicePrincipalBaseUnits), BigInt(vault.claimant.payoutAddress), BigInt(vault.claimant.collateralBaseUnits),
    BigInt(vault.respondent.payoutAddress), BigInt(vault.respondent.collateralBaseUnits), BigInt(vault.quorum),
    BigInt(Math.floor(Date.parse(vault.commitDeadline) / 1_000)), BigInt(Math.floor(Date.parse(vault.revealDeadline) / 1_000)),
    BigInt(vault.evidenceCommitment), BigInt(vault.treasuryAddress), BigInt(vault.loserCollateralSlashBps), BigInt(vault.nonRevealBondSlashBps),
    ...vault.arbitrators.flatMap((item) => [hash.starknetKeccak(item.arbitratorId), BigInt(item.payoutAddress), BigInt(item.bondBaseUnits), BigInt(item.votingPublicKey.x), BigInt(item.votingPublicKey.y)]),
  ]);
}

function computeVoteCommitment(vault: DisputeVault, arbitratorId: string, choice: ArbitrationChoice, salt: bigint): bigint {
  return hashElements([VOTE_DOMAIN, BigInt(vault.vaultCommitment), hash.starknetKeccak(arbitratorId), choiceCode(choice), salt]);
}

function voteAuthorizationChallenge(vault: DisputeVault, arbitratorId: string, commitment: bigint, committedAt: string, publicKey: ReturnType<typeof pointFromFelts>, noncePoint: ReturnType<typeof pointFromFelts>): bigint {
  return mod(hashElements([AUTH_DOMAIN, BigInt(vault.vaultCommitment), hash.starknetKeccak(arbitratorId), commitment, BigInt(Math.floor(Date.parse(committedAt) / 1_000)), publicKey.x, publicKey.y, noncePoint.x, noncePoint.y]), CURVE_ORDER);
}

function determineOutcome(tallies: Record<ArbitrationChoice, number>, count: number, quorum: number): DisputeOutcome {
  if (count < quorum) return "no_quorum";
  const entries = Object.entries(tallies) as Array<[ArbitrationChoice, number]>;
  entries.sort((a, b) => b[1] - a[1]);
  if (entries[0][1] === entries[1][1] || entries[0][1] * 2 <= count) return "split";
  return entries[0][0];
}

function allocatePartyStake(vault: DisputeVault, outcome: DisputeOutcome, allocations: ResolutionAllocation[], events: SlashingEvent[]): void {
  const principal = BigInt(vault.invoicePrincipalBaseUnits);
  const claimantCollateral = BigInt(vault.claimant.collateralBaseUnits);
  const respondentCollateral = BigInt(vault.respondent.collateralBaseUnits);
  if (outcome === "claimant") {
    const slash = respondentCollateral * BigInt(vault.loserCollateralSlashBps) / 10_000n;
    addAllocation(allocations, vault.claimant.payoutAddress, principal, "invoice_award");
    addAllocation(allocations, vault.claimant.payoutAddress, claimantCollateral, "collateral_return");
    addAllocation(allocations, vault.claimant.payoutAddress, slash, "collateral_award");
    addAllocation(allocations, vault.respondent.payoutAddress, respondentCollateral - slash, "collateral_return");
    if (slash) events.push({ source: "respondent_collateral", subjectId: "respondent", amountBaseUnits: slash.toString(), reason: "losing_party" });
  } else if (outcome === "respondent") {
    const slash = claimantCollateral * BigInt(vault.loserCollateralSlashBps) / 10_000n;
    addAllocation(allocations, vault.respondent.payoutAddress, principal, "invoice_award");
    addAllocation(allocations, vault.respondent.payoutAddress, respondentCollateral, "collateral_return");
    addAllocation(allocations, vault.respondent.payoutAddress, slash, "collateral_award");
    addAllocation(allocations, vault.claimant.payoutAddress, claimantCollateral - slash, "collateral_return");
    if (slash) events.push({ source: "claimant_collateral", subjectId: "claimant", amountBaseUnits: slash.toString(), reason: "losing_party" });
  } else if (outcome === "split") {
    addAllocation(allocations, vault.claimant.payoutAddress, principal / 2n, "invoice_award");
    addAllocation(allocations, vault.respondent.payoutAddress, principal - principal / 2n, "invoice_award");
    addAllocation(allocations, vault.claimant.payoutAddress, claimantCollateral, "collateral_return");
    addAllocation(allocations, vault.respondent.payoutAddress, respondentCollateral, "collateral_return");
  } else {
    addAllocation(allocations, vault.respondent.payoutAddress, principal, "invoice_award");
    addAllocation(allocations, vault.claimant.payoutAddress, claimantCollateral, "collateral_return");
    addAllocation(allocations, vault.respondent.payoutAddress, respondentCollateral, "collateral_return");
  }
}

function allocateArbitratorBonds(vault: DisputeVault, validReveals: Map<string, VoteReveal>, allocations: ResolutionAllocation[], events: SlashingEvent[]): void {
  let rewardPool = 0n;
  const valid = vault.arbitrators.filter((item) => validReveals.has(item.arbitratorId));
  for (const arbitrator of vault.arbitrators) {
    const bond = BigInt(arbitrator.bondBaseUnits);
    if (validReveals.has(arbitrator.arbitratorId)) addAllocation(allocations, arbitrator.payoutAddress, bond, "bond_return");
    else {
      const slash = bond * BigInt(vault.nonRevealBondSlashBps) / 10_000n;
      addAllocation(allocations, arbitrator.payoutAddress, bond - slash, "bond_return");
      rewardPool += slash;
      if (slash) events.push({ source: "arbitrator_bond", subjectId: arbitrator.arbitratorId, amountBaseUnits: slash.toString(), reason: "missing_or_invalid_reveal" });
    }
  }
  if (!rewardPool) return;
  if (!valid.length) { addAllocation(allocations, vault.treasuryAddress, rewardPool, "slashing_treasury"); return; }
  const share = rewardPool / BigInt(valid.length);
  let remainder = rewardPool % BigInt(valid.length);
  for (const arbitrator of valid) {
    const reward = share + (remainder > 0n ? 1n : 0n);
    if (remainder > 0n) remainder -= 1n;
    addAllocation(allocations, arbitrator.payoutAddress, reward, "non_reveal_reward");
  }
}

function consolidateAllocations(allocations: ResolutionAllocation[]): ResolutionAllocation[] {
  const byKey = new Map<string, ResolutionAllocation>();
  for (const item of allocations) {
    if (BigInt(item.amountBaseUnits) === 0n) continue;
    const key = `${item.recipientAddress}|${item.reason}`;
    const current = byKey.get(key);
    if (current) current.amountBaseUnits = (BigInt(current.amountBaseUnits) + BigInt(item.amountBaseUnits)).toString();
    else byKey.set(key, { ...item });
  }
  return [...byKey.values()].sort((a, b) => `${a.recipientAddress}|${a.reason}`.localeCompare(`${b.recipientAddress}|${b.reason}`));
}

function computeResolutionCommitment(vault: DisputeVault, resolution: Omit<DisputeResolution, "resolutionCommitment" | "notice">): bigint {
  return hashElements([
    RESOLUTION_DOMAIN, BigInt(vault.vaultCommitment), outcomeCode(resolution.outcome), BigInt(resolution.validRevealCount),
    BigInt(resolution.tallies.claimant), BigInt(resolution.tallies.respondent), BigInt(resolution.tallies.split), BigInt(Math.floor(Date.parse(resolution.resolvedAt) / 1_000)),
    ...resolution.allocations.flatMap((item) => [BigInt(item.recipientAddress), BigInt(item.amountBaseUnits), hash.starknetKeccak(item.reason)]),
    ...resolution.slashingEvents.flatMap((item) => [hash.starknetKeccak(item.source), hash.starknetKeccak(item.subjectId), BigInt(item.amountBaseUnits)]),
  ]);
}

function validateResolutionPair(vault: DisputeVault, resolution: DisputeResolution): void {
  validateVault(vault);
  if (!resolution || resolution.version !== DISPUTE_VAULT_VERSION || resolution.vaultId !== vault.vaultId || resolution.totalVaultBaseUnits !== vault.totalVaultBaseUnits) throw new Error("Dispute resolution does not match its vault.");
  const total = resolution.allocations.reduce((sum, item) => sum + requireBaseUnits(item.amountBaseUnits, "Resolution allocation"), 0n);
  if (total !== BigInt(vault.totalVaultBaseUnits)) throw new Error("Dispute resolution does not conserve vault value.");
  if (computeResolutionCommitment(vault, resolution) !== requireFelt(resolution.resolutionCommitment, "Resolution commitment")) throw new Error("Dispute resolution commitment is invalid.");
}

function requireArbitrator(vault: DisputeVault, arbitratorId: string): DisputeArbitratorInput {
  const arbitrator = vault.arbitrators.find((item) => item.arbitratorId === arbitratorId);
  if (!arbitrator) throw new Error("Arbitrator is not registered for this dispute.");
  return arbitrator;
}

function requireCommitPhase(vault: DisputeVault, now: Date): void {
  if (now.getTime() < Date.parse(vault.createdAt) || now.getTime() > Date.parse(vault.commitDeadline)) throw new Error("Vote commitment window is closed.");
}

function requireRevealPhase(vault: DisputeVault, now: Date): void {
  if (now.getTime() < Date.parse(vault.commitDeadline) || now.getTime() > Date.parse(vault.revealDeadline)) throw new Error("Vote reveal window is not active.");
}

function addAllocation(allocations: ResolutionAllocation[], recipientAddress: string, amount: bigint, reason: ResolutionAllocation["reason"]): void {
  if (amount < 0n || amount > U128_MAX) throw new Error("Resolution allocation is outside the STRK20 u128 range.");
  if (amount) allocations.push({ recipientAddress, amountBaseUnits: amount.toString(), reason });
}

function requireChoice(value: string): asserts value is ArbitrationChoice {
  if (value !== "claimant" && value !== "respondent" && value !== "split") throw new Error("Arbitration choice is invalid.");
}

function choiceCode(choice: ArbitrationChoice): bigint { return choice === "claimant" ? 1n : choice === "respondent" ? 2n : 3n; }
function outcomeCode(outcome: DisputeOutcome): bigint { return outcome === "no_quorum" ? 0n : choiceCode(outcome); }

function requireText(value: string, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireBaseUnits(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an integer in base units.`);
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed > U128_MAX) throw new Error(`${label} is outside the STRK20 u128 range.`);
  return parsed;
}

function requireBps(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 10_000) throw new Error(`${label} must be between 0 and 10000 basis points.`);
  return value;
}

function requireSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer.`);
  return value;
}

function requireFelt(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is not a felt.`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error(`${label} is outside the Stark field.`);
  return parsed;
}

function requireScalar(value: string, allowZero: boolean): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Vote value is not a curve scalar.");
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error("Vote scalar is outside the Stark curve order.");
  return parsed;
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return value;
}

function pointToFelts(point: ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>): CurvePointFelts { return { x: toHex(point.x), y: toHex(point.y) }; }
function pointFromFelts(point: CurvePointFelts) {
  if (!point || typeof point !== "object") throw new Error("Voting public key is invalid.");
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, "Voting public key"), y: requireFelt(point.y, "Voting public key") });
  parsed.assertValidity();
  return parsed;
}

function randomScalar(): bigint { return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey()); }
function hashElements(values: bigint[]): bigint { return BigInt(hash.computePoseidonHashOnElements(values)); }
function mod(value: bigint, modulus: bigint): bigint { const remainder = value % modulus; return remainder >= 0n ? remainder : remainder + modulus; }
function toHex(value: bigint): string { return `0x${value.toString(16)}`; }

function assertUnique(values: string[], message: string): void { if (new Set(values).size !== values.length) throw new Error(message); }

function evidenceAssociatedData(): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${EVIDENCE_KIND}|${DISPUTE_VAULT_VERSION}|${MAINNET_CHAIN_ID}|${STRK20_POOL_ADDRESS}`);
}

async function importEvidenceKey(bytes: Uint8Array<ArrayBuffer>, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, [usage]);
}

async function sha256Base64Url(value: Uint8Array<ArrayBuffer>): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", value)));
}

function bytesToBigint(value: ArrayBuffer | Uint8Array): bigint {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return BigInt(`0x${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("") || "0"}`);
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
