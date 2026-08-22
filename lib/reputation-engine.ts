import { ec, hash } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const REPUTATION_ENGINE_VERSION = 1 as const;
export const REPUTATION_PROOF_SYSTEM = "pedersen-schnorr-linear-v1" as const;
export const MAX_REPUTATION_CREDENTIALS = 32;
export const MAX_REPUTATION_VALIDITY_DAYS = 90;
export const REPUTATION_SCORE_BASE = 600;
export const REPUTATION_ATTESTATION_STORAGE_KEY = "cipherbill.reputation.attestation.v1";

const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const HISTORY_DOMAIN = hash.starknetKeccak("CipherBill private reputation history v1");
const CREDENTIAL_DOMAIN = hash.starknetKeccak("CipherBill settlement credential v1");
const SCORE_OPENING_DOMAIN = hash.starknetKeccak("CipherBill reputation score opening v1");
const SCORE_RELATION_DOMAIN = hash.starknetKeccak("CipherBill reputation score relation v1");
const SUCCESS_PARTITION_DOMAIN = hash.starknetKeccak("CipherBill reputation success partition v1");
const TOTAL_PARTITION_DOMAIN = hash.starknetKeccak("CipherBill reputation total partition v1");
const ATTESTATION_DOMAIN = hash.starknetKeccak("CipherBill reputation attestation v1");
const PEDERSEN_H = deriveIndependentGenerator();

type CountKey = "total" | "successful" | "onTime" | "late" | "disputed" | "score";
export type ReputationTier = "elite" | "trusted" | "established" | "developing" | "guarded";
export type SettlementOutcome = "settled" | "disputed";

export interface CurvePointFelts {
  x: string;
  y: string;
}

export interface ReputationAttestorKeypair {
  privateKey: string;
  publicKey: CurvePointFelts;
}

/** Private input. Amounts and counterparty identifiers are deliberately not part of this schema. */
export interface PrivateSettlementCredential {
  credentialId: string;
  invoiceCommitment: string;
  settlementCommitment: string;
  dueAt: string;
  settledAt?: string;
  outcome: SettlementOutcome;
}

export interface ReputationAggregates {
  total: number;
  successful: number;
  onTime: number;
  late: number;
  disputed: number;
  score: number;
  tier: ReputationTier;
  historyRoot: string;
}

export interface ReputationCommitments {
  total: CurvePointFelts;
  successful: CurvePointFelts;
  onTime: CurvePointFelts;
  late: CurvePointFelts;
  disputed: CurvePointFelts;
  score: CurvePointFelts;
}

export interface LinearKnowledgeProof {
  nonceCommitment: CurvePointFelts;
  response: string;
}

export interface ReputationZkProof {
  scoreOpening: LinearKnowledgeProof;
  scoreRelation: LinearKnowledgeProof;
  successPartition: LinearKnowledgeProof;
  totalPartition: LinearKnowledgeProof;
}

export interface ReputationAuthoritySignature {
  nonceCommitment: CurvePointFelts;
  response: string;
}

export interface ReputationAttestation {
  version: typeof REPUTATION_ENGINE_VERSION;
  proofSystem: typeof REPUTATION_PROOF_SYSTEM;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  merchantAddress: string;
  historyRoot: string;
  score: number;
  tier: ReputationTier;
  commitments: ReputationCommitments;
  proof: ReputationZkProof;
  attestorId: string;
  attestorPublicKey: CurvePointFelts;
  issuedAt: string;
  validUntil: string;
  signature: ReputationAuthoritySignature;
  notice: string;
}

export interface ReputationPrivateOpening {
  credentials: PrivateSettlementCredential[];
  blindings: Record<CountKey, string>;
}

export interface ReputationProofBundle {
  attestation: ReputationAttestation;
  opening: ReputationPrivateOpening;
}

export interface ReputationVerification {
  cryptographicallyValid: boolean;
  attestorTrusted: boolean;
  current: boolean;
  score: number | null;
  tier: ReputationTier | null;
  reason: string;
}

export interface ReputationEntropy {
  privateKey?: bigint;
  blindings?: Partial<Record<CountKey, bigint>>;
  proofNonces?: bigint[];
  signatureNonce?: bigint;
}

export interface CreateReputationProofInput {
  merchantAddress: string;
  credentials: PrivateSettlementCredential[];
  attestorId: string;
  attestorPrivateKey: string;
  validityDays?: number;
}

export interface ReputationSecurityModel {
  zeroKnowledgeProofs: string[];
  attestorGuarantees: string[];
  hidden: string[];
  limitations: string[];
}

interface ReputationStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export function generateReputationAttestorKeypair(entropy: Pick<ReputationEntropy, "privateKey"> = {}): ReputationAttestorKeypair {
  const privateKey = requireSecretScalar(entropy.privateKey ?? randomScalar(), "Attestor private key");
  return { privateKey: toHex(privateKey), publicKey: pointToFelts(ec.starkCurve.ProjectivePoint.BASE.multiply(privateKey)) };
}

export function aggregatePrivateSettlements(
  credentials: PrivateSettlementCredential[],
  assessedAt = new Date(),
): ReputationAggregates {
  const normalized = normalizeCredentials(credentials, assessedAt);
  let successful = 0;
  let onTime = 0;
  let late = 0;
  let disputed = 0;
  for (const credential of normalized) {
    if (credential.outcome === "disputed") {
      disputed += 1;
      continue;
    }
    successful += 1;
    if (Date.parse(credential.settledAt as string) <= Date.parse(credential.dueAt)) onTime += 1;
    else late += 1;
  }
  if (!successful) throw new Error("Reputation requires at least one successfully settled invoice credential.");
  const total = normalized.length;
  const score = REPUTATION_SCORE_BASE + 4 * successful + 2 * onTime - 3 * late - 8 * disputed;
  if (score < 300 || score > 850) throw new Error("Reputation score is outside the supported credit band.");
  return {
    total,
    successful,
    onTime,
    late,
    disputed,
    score,
    tier: tierForScore(score),
    historyRoot: toHex(computeHistoryRoot(normalized)),
  };
}

export function createReputationProof(
  input: CreateReputationProofInput,
  now = new Date(),
  entropy: ReputationEntropy = {},
): ReputationProofBundle {
  const merchantAddress = normalizeStarknetAddress(input.merchantAddress);
  const attestorId = requireText(input.attestorId, "Attestor ID", 64, /^[A-Za-z0-9_.-]+$/);
  const attestorPrivateKey = requireCurveScalar(input.attestorPrivateKey, false, "Attestor private key");
  const attestorPublicPoint = ec.starkCurve.ProjectivePoint.BASE.multiply(attestorPrivateKey);
  const issuedAtMs = now.getTime();
  if (!Number.isFinite(issuedAtMs)) throw new Error("Reputation issue time is invalid.");
  const validityDays = requireBoundedInteger(input.validityDays ?? 30, "Reputation validity", 1, MAX_REPUTATION_VALIDITY_DAYS);
  const issuedAt = now.toISOString();
  const validUntil = new Date(issuedAtMs + validityDays * 86_400_000).toISOString();
  const credentials = normalizeCredentials(input.credentials, now);
  const aggregates = aggregatePrivateSettlements(credentials, now);
  const values: Record<CountKey, number> = {
    total: aggregates.total,
    successful: aggregates.successful,
    onTime: aggregates.onTime,
    late: aggregates.late,
    disputed: aggregates.disputed,
    score: aggregates.score,
  };
  const blindingValues = Object.fromEntries((Object.keys(values) as CountKey[]).map((key) => [key, requireSecretScalar(entropy.blindings?.[key] ?? randomScalar(), `${key} blinding`)])) as Record<CountKey, bigint>;
  const commitmentPoints = Object.fromEntries((Object.keys(values) as CountKey[]).map((key) => [key, pedersenCommit(BigInt(values[key]), blindingValues[key])])) as Record<CountKey, CurvePoint>;
  const commitments = mapCommitmentPoints(commitmentPoints);
  const transcript = proofTranscript(merchantAddress, aggregates.historyRoot, aggregates.score, aggregates.tier, commitments, issuedAt, validUntil);
  const nonces = entropy.proofNonces ?? [];
  const scoreOpeningStatement = commitmentPoints.score.subtract(ec.starkCurve.ProjectivePoint.BASE.multiply(BigInt(aggregates.score)));
  const scoreRelationStatement = commitmentPoints.score
    .subtract(ec.starkCurve.ProjectivePoint.BASE.multiply(BigInt(REPUTATION_SCORE_BASE)))
    .subtract(commitmentPoints.successful.multiply(4n))
    .subtract(commitmentPoints.onTime.multiply(2n))
    .add(commitmentPoints.late.multiply(3n))
    .add(commitmentPoints.disputed.multiply(8n));
  const successPartitionStatement = commitmentPoints.onTime.add(commitmentPoints.late).subtract(commitmentPoints.successful);
  const totalPartitionStatement = commitmentPoints.successful.add(commitmentPoints.disputed).subtract(commitmentPoints.total);
  const proof: ReputationZkProof = {
    scoreOpening: createLinearProof(SCORE_OPENING_DOMAIN, scoreOpeningStatement, blindingValues.score, transcript, nonces[0]),
    scoreRelation: createLinearProof(
      SCORE_RELATION_DOMAIN,
      scoreRelationStatement,
      mod(blindingValues.score - 4n * blindingValues.successful - 2n * blindingValues.onTime + 3n * blindingValues.late + 8n * blindingValues.disputed, CURVE_ORDER),
      transcript,
      nonces[1],
    ),
    successPartition: createLinearProof(
      SUCCESS_PARTITION_DOMAIN,
      successPartitionStatement,
      mod(blindingValues.onTime + blindingValues.late - blindingValues.successful, CURVE_ORDER),
      transcript,
      nonces[2],
    ),
    totalPartition: createLinearProof(
      TOTAL_PARTITION_DOMAIN,
      totalPartitionStatement,
      mod(blindingValues.successful + blindingValues.disputed - blindingValues.total, CURVE_ORDER),
      transcript,
      nonces[3],
    ),
  };
  const unsigned = {
    version: REPUTATION_ENGINE_VERSION,
    proofSystem: REPUTATION_PROOF_SYSTEM,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    merchantAddress,
    historyRoot: aggregates.historyRoot,
    score: aggregates.score,
    tier: aggregates.tier,
    commitments,
    proof,
    attestorId,
    attestorPublicKey: pointToFelts(attestorPublicPoint),
    issuedAt,
    validUntil,
  } as const;
  const signature = signAttestation(unsigned, attestorPrivateKey, entropy.signatureNonce);
  const attestation: ReputationAttestation = {
    ...unsigned,
    signature,
    notice: "Zero-knowledge Schnorr proofs verify the public score's linear relation to hidden Pedersen-committed aggregates. The attestor signature—not the ZK relations—certifies credential provenance and count bounds. This is separate from STRK20 transaction STARK proofs.",
  };
  const opening: ReputationPrivateOpening = {
    credentials,
    blindings: Object.fromEntries((Object.keys(blindingValues) as CountKey[]).map((key) => [key, toHex(blindingValues[key])])) as Record<CountKey, string>,
  };
  const verification = verifyReputationProof(attestation, { trustedAttestor: unsigned.attestorPublicKey, now });
  if (!verification.cryptographicallyValid) throw new Error(`Generated reputation proof did not verify: ${verification.reason}`);
  return { attestation, opening };
}

export function verifyReputationProof(
  attestation: ReputationAttestation,
  options: { trustedAttestor?: CurvePointFelts; now?: Date } = {},
): ReputationVerification {
  try {
    validateAttestationShape(attestation);
    const now = options.now ?? new Date();
    const nowMs = now.getTime();
    if (!Number.isFinite(nowMs)) throw new Error("Reputation verification time is invalid.");
    const points = parseCommitmentPoints(attestation.commitments);
    const transcript = proofTranscript(attestation.merchantAddress, attestation.historyRoot, attestation.score, attestation.tier, attestation.commitments, attestation.issuedAt, attestation.validUntil);
    const scoreOpeningStatement = points.score.subtract(ec.starkCurve.ProjectivePoint.BASE.multiply(BigInt(attestation.score)));
    const scoreRelationStatement = points.score
      .subtract(ec.starkCurve.ProjectivePoint.BASE.multiply(BigInt(REPUTATION_SCORE_BASE)))
      .subtract(points.successful.multiply(4n))
      .subtract(points.onTime.multiply(2n))
      .add(points.late.multiply(3n))
      .add(points.disputed.multiply(8n));
    const successPartitionStatement = points.onTime.add(points.late).subtract(points.successful);
    const totalPartitionStatement = points.successful.add(points.disputed).subtract(points.total);
    if (!verifyLinearProof(SCORE_OPENING_DOMAIN, scoreOpeningStatement, attestation.proof.scoreOpening, transcript)) throw new Error("Score opening proof is invalid.");
    if (!verifyLinearProof(SCORE_RELATION_DOMAIN, scoreRelationStatement, attestation.proof.scoreRelation, transcript)) throw new Error("Score relation proof is invalid.");
    if (!verifyLinearProof(SUCCESS_PARTITION_DOMAIN, successPartitionStatement, attestation.proof.successPartition, transcript)) throw new Error("Successful-settlement partition proof is invalid.");
    if (!verifyLinearProof(TOTAL_PARTITION_DOMAIN, totalPartitionStatement, attestation.proof.totalPartition, transcript)) throw new Error("Total-history partition proof is invalid.");
    if (!verifyAttestationSignature(attestation)) throw new Error("Reputation attestor signature is invalid.");
    const attestorTrusted = options.trustedAttestor ? pointFromFelts(options.trustedAttestor, "Trusted attestor").equals(pointFromFelts(attestation.attestorPublicKey, "Attestor public key")) : false;
    const current = nowMs >= Date.parse(attestation.issuedAt) && nowMs <= Date.parse(attestation.validUntil);
    return {
      cryptographicallyValid: true,
      attestorTrusted,
      current,
      score: attestation.score,
      tier: attestation.tier,
      reason: current ? attestorTrusted ? "Proof, attestor, and validity window verified." : "Proof is valid, but this verifier has not trusted its attestor." : "Proof is cryptographically valid but outside its validity window.",
    };
  } catch (error) {
    return { cryptographicallyValid: false, attestorTrusted: false, current: false, score: null, tier: null, reason: error instanceof Error ? error.message : "Reputation proof is invalid." };
  }
}

export function verifyReputationOpening(bundle: ReputationProofBundle): boolean {
  try {
    const { attestation, opening } = bundle;
    const publicVerification = verifyReputationProof(attestation, { trustedAttestor: attestation.attestorPublicKey, now: new Date(attestation.issuedAt) });
    if (!publicVerification.cryptographicallyValid) return false;
    const credentials = normalizeCredentials(opening.credentials, new Date(attestation.issuedAt));
    const aggregates = aggregatePrivateSettlements(credentials, new Date(attestation.issuedAt));
    if (aggregates.historyRoot !== attestation.historyRoot || aggregates.score !== attestation.score || aggregates.tier !== attestation.tier) return false;
    const values: Record<CountKey, number> = { total: aggregates.total, successful: aggregates.successful, onTime: aggregates.onTime, late: aggregates.late, disputed: aggregates.disputed, score: aggregates.score };
    return (Object.keys(values) as CountKey[]).every((key) => {
      const expected = pedersenCommit(BigInt(values[key]), requireCurveScalar(opening.blindings[key], false, `${key} blinding`));
      return expected.equals(pointFromFelts(attestation.commitments[key], `${key} commitment`));
    });
  } catch { return false; }
}

export function serializeReputationAttestation(attestation: ReputationAttestation): string {
  validateAttestationShape(attestation);
  return JSON.stringify(attestation, null, 2);
}

export function parseReputationAttestation(serialized: string): ReputationAttestation {
  let value: unknown;
  try { value = JSON.parse(serialized); } catch { throw new Error("Reputation attestation JSON is malformed."); }
  validateAttestationShape(value);
  const verification = verifyReputationProof(value, { now: new Date(value.issuedAt) });
  if (!verification.cryptographicallyValid) throw new Error(verification.reason);
  return value;
}

/** Stores public proof material only. Private credentials, blindings, and issuer keys are never persisted. */
export function writeReputationAttestation(
  attestation: ReputationAttestation | null,
  storage: ReputationStorage | undefined = browserStorage(),
): boolean {
  if (!storage) return false;
  if (!attestation) {
    storage.removeItem(REPUTATION_ATTESTATION_STORAGE_KEY);
    return true;
  }
  const serialized = serializeReputationAttestation(attestation);
  const verification = verifyReputationProof(attestation, { now: new Date(attestation.issuedAt) });
  if (!verification.cryptographicallyValid) throw new Error(verification.reason);
  storage.setItem(REPUTATION_ATTESTATION_STORAGE_KEY, serialized);
  return true;
}

export function readReputationAttestation(
  storage: ReputationStorage | undefined = browserStorage(),
): ReputationAttestation | null {
  if (!storage) return null;
  const serialized = storage.getItem(REPUTATION_ATTESTATION_STORAGE_KEY);
  if (!serialized) return null;
  try {
    return parseReputationAttestation(serialized);
  } catch {
    storage.removeItem(REPUTATION_ATTESTATION_STORAGE_KEY);
    return null;
  }
}

export function getReputationSecurityModel(): ReputationSecurityModel {
  return {
    zeroKnowledgeProofs: [
      "A Schnorr proof opens the score commitment to the displayed score without revealing its blinding.",
      "A second proof verifies the score formula over hidden successful, on-time, late, and disputed count commitments.",
      "Two partition proofs verify on-time plus late equals successful, and successful plus disputed equals total.",
    ],
    attestorGuarantees: [
      "The signed transcript binds the merchant, opaque history root, score, commitments, proofs, issuer, and validity window.",
      "A trusted independent attestor is responsible for validating settlement credentials and count bounds before signing.",
    ],
    hidden: ["Transaction amounts", "Counterparty names and addresses", "Invoice identifiers", "Settlement timestamps", "Aggregate counts and commitment blindings"],
    limitations: [
      "The linear ZK proof does not prove credential provenance or count ranges; those claims rely on the attestor signature.",
      "A self-issued demonstration attestation is cryptographically consistent but does not establish independent trust.",
      "This application proof is not the STRK20 pool's transaction STARK proof and reveals the merchant address, score, tier, issuer, and validity window.",
      "Public timing, deposits, withdrawals, fees, nullifiers, open-note values, and correlation remain outside this badge.",
    ],
  };
}

export function credentialFromSettlement(input: {
  credentialId: string;
  invoiceId: string;
  transactionHash: string;
  dueAt: string;
  settledAt?: string;
  outcome: SettlementOutcome;
}): PrivateSettlementCredential {
  const credentialId = requireText(input.credentialId, "Credential ID", 64, /^[A-Za-z0-9_-]+$/);
  if (!/^0x[0-9a-f]{1,64}$/i.test(input.transactionHash)) throw new Error("Settlement transaction hash is invalid.");
  const invoiceId = requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  return {
    credentialId,
    invoiceCommitment: toHex(hashElements([CREDENTIAL_DOMAIN, hash.starknetKeccak(invoiceId)])),
    settlementCommitment: toHex(hashElements([CREDENTIAL_DOMAIN, BigInt(input.transactionHash), hash.starknetKeccak(credentialId)])),
    dueAt: requireIsoTimestamp(input.dueAt, "Credential due time"),
    ...(input.settledAt ? { settledAt: requireIsoTimestamp(input.settledAt, "Credential settlement time") } : {}),
    outcome: input.outcome,
  };
}

function normalizeCredentials(credentials: PrivateSettlementCredential[], assessedAt: Date): PrivateSettlementCredential[] {
  if (!Array.isArray(credentials) || !credentials.length || credentials.length > MAX_REPUTATION_CREDENTIALS) throw new Error(`Reputation requires 1 to ${MAX_REPUTATION_CREDENTIALS} private settlement credentials.`);
  if (!Number.isFinite(assessedAt.getTime())) throw new Error("Credential assessment time is invalid.");
  const normalized = credentials.map((credential) => {
    if (!credential || typeof credential !== "object") throw new Error("Settlement credential is invalid.");
    const credentialId = requireText(credential.credentialId, "Credential ID", 64, /^[A-Za-z0-9_-]+$/);
    const invoiceCommitment = toHex(requireFelt(credential.invoiceCommitment, "Invoice commitment"));
    const settlementCommitment = toHex(requireFelt(credential.settlementCommitment, "Settlement commitment"));
    const dueAt = requireIsoTimestamp(credential.dueAt, "Credential due time");
    if (credential.outcome !== "settled" && credential.outcome !== "disputed") throw new Error("Settlement credential outcome is invalid.");
    if (credential.outcome === "settled") {
      const settledAt = requireIsoTimestamp(credential.settledAt as string, "Credential settlement time");
      if (Date.parse(settledAt) > assessedAt.getTime()) throw new Error("Settlement credential cannot be from the future.");
      return { credentialId, invoiceCommitment, settlementCommitment, dueAt, settledAt, outcome: "settled" as const };
    }
    if (credential.settledAt !== undefined) throw new Error("Disputed credentials cannot include a settlement time.");
    return { credentialId, invoiceCommitment, settlementCommitment, dueAt, outcome: "disputed" as const };
  }).sort((left, right) => left.credentialId.localeCompare(right.credentialId));
  if (new Set(normalized.map((credential) => credential.credentialId)).size !== normalized.length) throw new Error("Settlement credential IDs must be unique.");
  return normalized;
}

function computeHistoryRoot(credentials: PrivateSettlementCredential[]): bigint {
  return hashElements([
    HISTORY_DOMAIN,
    BigInt(credentials.length),
    ...credentials.map((credential) => hashElements([
      CREDENTIAL_DOMAIN,
      hash.starknetKeccak(credential.credentialId),
      BigInt(credential.invoiceCommitment),
      BigInt(credential.settlementCommitment),
      timestampMs(credential.dueAt),
      credential.settledAt ? timestampMs(credential.settledAt) : 0n,
      credential.outcome === "settled" ? 1n : 2n,
    ])),
  ]);
}

function pedersenCommit(value: bigint, blinding: bigint): CurvePoint {
  return multiplyCurvePoint(ec.starkCurve.ProjectivePoint.BASE, value).add(multiplyCurvePoint(PEDERSEN_H, blinding));
}

function createLinearProof(domain: bigint, statement: CurvePoint, witness: bigint, transcript: bigint[], suppliedNonce?: bigint): LinearKnowledgeProof {
  const nonce = requireSecretScalar(suppliedNonce ?? randomScalar(), "ZK proof nonce");
  const noncePoint = PEDERSEN_H.multiply(nonce);
  const challenge = linearChallenge(domain, statement, noncePoint, transcript);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(mod(nonce + challenge * witness, CURVE_ORDER)) };
}

function verifyLinearProof(domain: bigint, statement: CurvePoint, proof: LinearKnowledgeProof, transcript: bigint[]): boolean {
  const noncePoint = pointFromFelts(proof.nonceCommitment, "ZK nonce commitment");
  const response = requireCurveScalar(proof.response, true, "ZK proof response");
  const challenge = linearChallenge(domain, statement, noncePoint, transcript);
  return multiplyCurvePoint(PEDERSEN_H, response).equals(noncePoint.add(multiplyCurvePoint(statement, challenge)));
}

function linearChallenge(domain: bigint, statement: CurvePoint, noncePoint: CurvePoint, transcript: bigint[]): bigint {
  return mod(hashElements([domain, ...transcript, statement.x, statement.y, noncePoint.x, noncePoint.y]), CURVE_ORDER);
}

function proofTranscript(
  merchantAddress: string,
  historyRoot: string,
  score: number,
  tier: ReputationTier,
  commitments: ReputationCommitments,
  issuedAt: string,
  validUntil: string,
): bigint[] {
  return [
    BigInt(merchantAddress), BigInt(historyRoot), BigInt(score), tierCode(tier),
    ...commitmentElements(commitments), timestampMs(issuedAt), timestampMs(validUntil),
  ];
}

function signAttestation(
  unsigned: Omit<ReputationAttestation, "signature" | "notice">,
  privateKey: bigint,
  suppliedNonce?: bigint,
): ReputationAuthoritySignature {
  const nonce = requireSecretScalar(suppliedNonce ?? randomScalar(), "Attestation signature nonce");
  const noncePoint = ec.starkCurve.ProjectivePoint.BASE.multiply(nonce);
  const publicKey = pointFromFelts(unsigned.attestorPublicKey, "Attestor public key");
  const challenge = attestationSignatureChallenge(unsigned, publicKey, noncePoint);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(mod(nonce + challenge * privateKey, CURVE_ORDER)) };
}

function verifyAttestationSignature(attestation: ReputationAttestation): boolean {
  const publicKey = pointFromFelts(attestation.attestorPublicKey, "Attestor public key");
  const noncePoint = pointFromFelts(attestation.signature.nonceCommitment, "Attestation signature nonce");
  const response = requireCurveScalar(attestation.signature.response, true, "Attestation signature response");
  const challenge = attestationSignatureChallenge(attestation, publicKey, noncePoint);
  return multiplyCurvePoint(ec.starkCurve.ProjectivePoint.BASE, response).equals(noncePoint.add(multiplyCurvePoint(publicKey, challenge)));
}

function attestationSignatureChallenge(
  attestation: Omit<ReputationAttestation, "signature" | "notice"> | ReputationAttestation,
  publicKey: CurvePoint,
  noncePoint: CurvePoint,
): bigint {
  return mod(hashElements([
    ATTESTATION_DOMAIN,
    hash.starknetKeccak(attestation.attestorId),
    ...proofTranscript(attestation.merchantAddress, attestation.historyRoot, attestation.score, attestation.tier, attestation.commitments, attestation.issuedAt, attestation.validUntil),
    ...proofElements(attestation.proof),
    publicKey.x, publicKey.y, noncePoint.x, noncePoint.y,
  ]), CURVE_ORDER);
}

function proofElements(proof: ReputationZkProof): bigint[] {
  return ([proof.scoreOpening, proof.scoreRelation, proof.successPartition, proof.totalPartition] as LinearKnowledgeProof[]).flatMap((item) => {
    const nonce = pointFromFelts(item.nonceCommitment, "ZK nonce commitment");
    return [nonce.x, nonce.y, requireCurveScalar(item.response, true, "ZK proof response")];
  });
}

function commitmentElements(commitments: ReputationCommitments): bigint[] {
  return (["total", "successful", "onTime", "late", "disputed", "score"] as CountKey[]).flatMap((key) => {
    const point = pointFromFelts(commitments[key], `${key} commitment`);
    return [point.x, point.y];
  });
}

function mapCommitmentPoints(points: Record<CountKey, CurvePoint>): ReputationCommitments {
  return Object.fromEntries((Object.keys(points) as CountKey[]).map((key) => [key, pointToFelts(points[key])])) as unknown as ReputationCommitments;
}

function parseCommitmentPoints(commitments: ReputationCommitments): Record<CountKey, CurvePoint> {
  return Object.fromEntries((["total", "successful", "onTime", "late", "disputed", "score"] as CountKey[]).map((key) => [key, pointFromFelts(commitments[key], `${key} commitment`)])) as Record<CountKey, CurvePoint>;
}

function validateAttestationShape(value: unknown): asserts value is ReputationAttestation {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Reputation attestation is invalid.");
  const attestation = value as ReputationAttestation;
  assertExactKeys(attestation, ["version", "proofSystem", "network", "poolAddress", "merchantAddress", "historyRoot", "score", "tier", "commitments", "proof", "attestorId", "attestorPublicKey", "issuedAt", "validUntil", "signature", "notice"], "Reputation attestation");
  if (attestation.version !== REPUTATION_ENGINE_VERSION || attestation.proofSystem !== REPUTATION_PROOF_SYSTEM || attestation.network !== MAINNET_CHAIN_ID || attestation.poolAddress !== STRK20_POOL_ADDRESS) throw new Error("Reputation proof context is invalid.");
  attestation.merchantAddress = normalizeStarknetAddress(attestation.merchantAddress);
  requireFelt(attestation.historyRoot, "Reputation history root");
  if (!Number.isInteger(attestation.score) || attestation.score < 300 || attestation.score > 850 || tierForScore(attestation.score) !== attestation.tier) throw new Error("Reputation score or tier is invalid.");
  assertExactKeys(attestation.commitments, ["total", "successful", "onTime", "late", "disputed", "score"], "Reputation commitments");
  for (const [name, point] of Object.entries(attestation.commitments)) assertPointShape(point, `${name} commitment`);
  parseCommitmentPoints(attestation.commitments);
  assertExactKeys(attestation.proof, ["scoreOpening", "scoreRelation", "successPartition", "totalPartition"], "Reputation proof");
  for (const [name, proof] of Object.entries(attestation.proof)) assertLinearProofShape(proof, `${name} proof`);
  proofElements(attestation.proof);
  requireText(attestation.attestorId, "Attestor ID", 64, /^[A-Za-z0-9_.-]+$/);
  assertPointShape(attestation.attestorPublicKey, "Attestor public key");
  pointFromFelts(attestation.attestorPublicKey, "Attestor public key");
  const issuedAt = requireIsoTimestamp(attestation.issuedAt, "Reputation issue time");
  const validUntil = requireIsoTimestamp(attestation.validUntil, "Reputation validity time");
  const validity = Date.parse(validUntil) - Date.parse(issuedAt);
  if (validity <= 0 || validity > MAX_REPUTATION_VALIDITY_DAYS * 86_400_000) throw new Error("Reputation validity window is invalid.");
  assertLinearProofShape(attestation.signature, "Attestation signature");
  pointFromFelts(attestation.signature.nonceCommitment, "Attestation signature nonce");
  requireCurveScalar(attestation.signature?.response, true, "Attestation signature response");
  if (typeof attestation.notice !== "string" || !attestation.notice) throw new Error("Reputation proof notice is missing.");
}

function assertExactKeys(value: unknown, allowed: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  const keys = Object.keys(value);
  if (keys.length !== allowed.length || keys.some((key) => !allowed.includes(key))) throw new Error(`${label} contains unsupported or missing fields.`);
}

function assertPointShape(value: unknown, label: string): asserts value is CurvePointFelts {
  assertExactKeys(value, ["x", "y"], label);
}

function assertLinearProofShape(value: unknown, label: string): asserts value is LinearKnowledgeProof {
  assertExactKeys(value, ["nonceCommitment", "response"], label);
  assertPointShape(value.nonceCommitment, `${label} nonce`);
}

function browserStorage(): ReputationStorage | undefined {
  return typeof window === "undefined" ? undefined : window.localStorage;
}

function deriveIndependentGenerator(): CurvePoint {
  const field = ec.starkCurve.CURVE.Fp;
  const a = ec.starkCurve.CURVE.a;
  const b = ec.starkCurve.CURVE.b;
  let x = BigInt(hash.starknetKeccak("CipherBill reputation Pedersen H v1")) % FIELD_PRIME;
  for (let attempt = 0; attempt < 1_024; attempt += 1) {
    try {
      const right = field.add(field.add(field.mul(field.mul(x, x), x), field.mul(a, x)), b);
      let y = field.sqrt(right);
      if ((y & 1n) === 1n) y = field.neg(y);
      const point = ec.starkCurve.ProjectivePoint.fromAffine({ x, y });
      point.assertValidity();
      if (!point.equals(ec.starkCurve.ProjectivePoint.BASE) && !point.equals(ec.starkCurve.ProjectivePoint.ZERO)) return point;
    } catch { /* try the next x-coordinate */ }
    x = (x + 1n) % FIELD_PRIME;
  }
  throw new Error("Could not derive the reputation Pedersen generator.");
}

function pointToFelts(point: CurvePoint): CurvePointFelts { return { x: toHex(point.x), y: toHex(point.y) }; }

function pointFromFelts(point: CurvePointFelts, label: string): CurvePoint {
  if (!point || typeof point !== "object") throw new Error(`${label} is invalid.`);
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, label), y: requireFelt(point.y, label) });
  parsed.assertValidity();
  return parsed;
}

function tierForScore(score: number): ReputationTier {
  return score >= 750 ? "elite" : score >= 700 ? "trusted" : score >= 620 ? "established" : score >= 500 ? "developing" : "guarded";
}

function tierCode(tier: ReputationTier): bigint {
  const index = ["guarded", "developing", "established", "trusted", "elite"].indexOf(tier);
  if (index < 0) throw new Error("Reputation tier is invalid.");
  return BigInt(index + 1);
}

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

function requireBoundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${label} must be a whole number from ${minimum} to ${maximum}.`);
  return value;
}

function timestampMs(value: string): bigint { return BigInt(Date.parse(requireIsoTimestamp(value, "Timestamp"))); }
function randomScalar(): bigint { return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey()); }
function hashElements(values: bigint[]): bigint { return BigInt(hash.computePoseidonHashOnElements(values)); }
function mod(value: bigint, modulus: bigint): bigint { const remainder = value % modulus; return remainder >= 0n ? remainder : remainder + modulus; }
function toHex(value: bigint): string { return `0x${value.toString(16)}`; }

function multiplyCurvePoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const normalized = mod(scalar, CURVE_ORDER);
  return normalized === 0n ? ec.starkCurve.ProjectivePoint.ZERO : point.multiply(normalized);
}

type CurvePoint = ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>;
