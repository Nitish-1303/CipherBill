import { ec, hash, type STRK20_ACTION } from "starknet";

import { decodeInvoicePayload, encodeInvoicePayload, type ShareableInvoice } from "./invoices";
import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { decimalToBaseUnits, normalizeStarknetAddress } from "./strk20/validation";

export const EPHEMERAL_INVOICE_VERSION = 1 as const;
export const EPHEMERAL_INVOICE_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const MAX_EPHEMERAL_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
export const MIN_EPHEMERAL_TTL_MS = 60_000;
export const MAX_EPHEMERAL_CAPABILITY_LENGTH = 16_384;

const ENVELOPE_KIND = "cipherbill.ephemeral-invoice" as const;
const CAPABILITY_KIND = "cipherbill.ephemeral-capability" as const;
const ENCRYPTION_ALGORITHM = "AES-GCM-256" as const;
const STORAGE_KEY = "cipherbill.ephemeral-state.v1";
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const KEY_DOMAIN = hash.starknetKeccak("CipherBill ephemeral viewing key v1");
const INVOICE_DOMAIN = hash.starknetKeccak("CipherBill ephemeral invoice payload v1");
const LINK_DOMAIN = hash.starknetKeccak("CipherBill ephemeral payment link v1");
const STATE_DOMAIN = hash.starknetKeccak("CipherBill ephemeral TTL state v1");

export type EphemeralStatus = "sealed" | "opened" | "settlement_pending" | "burned" | "expired";
export type EphemeralBurnReason = "settlement" | "expiration";

export interface EphemeralInvoiceEnvelope {
  kind: typeof ENVELOPE_KIND;
  version: typeof EPHEMERAL_INVOICE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  algorithm: typeof ENCRYPTION_ALGORITHM;
  invoiceCommitment: string;
  viewingKeyCommitment: string;
  linkCommitment: string;
  expiresAt: string;
  iv: string;
  ciphertext: string;
  ciphertextDigest: string;
  notice: string;
}

export interface EphemeralInvoiceBundle {
  envelope: EphemeralInvoiceEnvelope;
  viewingKey: string;
}

export interface EphemeralCapability {
  kind: typeof CAPABILITY_KIND;
  version: typeof EPHEMERAL_INVOICE_VERSION;
  envelope: EphemeralInvoiceEnvelope;
  viewingKey: string;
}

export interface EphemeralInvoiceState {
  version: typeof EPHEMERAL_INVOICE_VERSION;
  linkCommitment: string;
  status: EphemeralStatus;
  createdAt: string;
  updatedAt: string;
  openedAt?: string;
  submittedAt?: string;
  destroyedAt?: string;
  transactionHash?: string;
  burnReason?: EphemeralBurnReason;
  stateCommitment: string;
}

export interface EphemeralInvoiceSession {
  invoice: ShareableInvoice | null;
  viewingKey: Uint8Array<ArrayBuffer>;
  linkCommitment: string;
  status: "open" | "destroyed";
}

export interface EphemeralClaimResult {
  session: EphemeralInvoiceSession;
  state: EphemeralInvoiceState;
}

export interface EphemeralBurnReceipt {
  version: typeof EPHEMERAL_INVOICE_VERSION;
  linkCommitment: string;
  finalStateCommitment: string;
  reason: EphemeralBurnReason;
  destroyedAt: string;
  transactionHash?: string;
  erasureAttestation: string;
}

export interface EphemeralSecurityModel {
  enforcedHere: string[];
  cannotGuarantee: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
}

export interface EphemeralEntropy {
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export async function createEphemeralInvoice(
  invoice: ShareableInvoice,
  now = new Date(),
  entropy: EphemeralEntropy = {},
): Promise<EphemeralInvoiceBundle> {
  const encodedInvoice = await validateEphemeralInvoice(invoice, now);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const viewingKey = random(new Uint8Array(32));
  const iv = random(new Uint8Array(12));
  if (viewingKey.length !== 32 || iv.length !== 12) throw new Error("Ephemeral entropy returned an invalid byte length.");

  const invoiceCommitment = await commitmentFromBytes(INVOICE_DOMAIN, new TextEncoder().encode(encodedInvoice));
  const viewingKeyCommitment = await commitmentFromBytes(KEY_DOMAIN, viewingKey);
  const header = {
    kind: ENVELOPE_KIND,
    version: EPHEMERAL_INVOICE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    algorithm: ENCRYPTION_ALGORITHM,
    invoiceCommitment,
    viewingKeyCommitment,
    expiresAt: invoice.expiresAt,
  } as const;
  const key = await importAesKey(viewingKey, "encrypt");
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: envelopeAssociatedData(header) },
    key,
    new TextEncoder().encode(encodedInvoice),
  ));
  const ciphertextDigest = await sha256Base64Url(ciphertext);
  const envelopeWithoutLink = {
    ...header,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
    ciphertextDigest,
  };
  const envelope: EphemeralInvoiceEnvelope = {
    ...envelopeWithoutLink,
    linkCommitment: computeLinkCommitment(envelopeWithoutLink),
    notice: "One-claim capability with local TTL and settlement burn state. The key travels only in the URL fragment, but a copied capability cannot be globally revoked without shared state. JavaScript zeroization is best-effort and not a proof of physical memory erasure.",
  };
  validateEnvelope(envelope);
  return { envelope, viewingKey: toBase64Url(viewingKey) };
}

export function createEphemeralInvoiceState(envelope: EphemeralInvoiceEnvelope, now = new Date()): EphemeralInvoiceState {
  validateEnvelope(envelope);
  const timestamp = requireIsoTimestamp(now.toISOString(), "State creation time");
  const state = {
    version: EPHEMERAL_INVOICE_VERSION,
    linkCommitment: envelope.linkCommitment,
    status: "sealed" as const,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
  return withStateCommitment(state);
}

export async function claimEphemeralInvoice(
  envelope: EphemeralInvoiceEnvelope,
  viewingKeyValue: string,
  state: EphemeralInvoiceState,
  now = new Date(),
): Promise<EphemeralClaimResult> {
  validateEnvelope(envelope);
  validateState(envelope, state);
  if (now.getTime() >= Date.parse(envelope.expiresAt)) throw new Error("Ephemeral invoice has expired. Destroy the local capability instead of opening it.");
  if (state.status !== "sealed") throw new Error("Ephemeral capability was already claimed or destroyed in this browser.");
  const viewingKey = fromBase64Url(viewingKeyValue);
  if (viewingKey.length !== 32) throw new Error("Ephemeral viewing key must be 32 bytes.");
  try {
    if (await commitmentFromBytes(KEY_DOMAIN, viewingKey) !== envelope.viewingKeyCommitment) throw new Error("Ephemeral viewing key does not match this invoice.");
    const ciphertext = fromBase64Url(envelope.ciphertext);
    if (await sha256Base64Url(ciphertext) !== envelope.ciphertextDigest) throw new Error("Ephemeral ciphertext digest does not match.");
    const key = await importAesKey(viewingKey, "decrypt");
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(envelope.iv), additionalData: envelopeAssociatedData(envelope) },
      key,
      ciphertext,
    );
    const encodedInvoice = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    if (await commitmentFromBytes(INVOICE_DOMAIN, new TextEncoder().encode(encodedInvoice)) !== envelope.invoiceCommitment) throw new Error("Ephemeral invoice commitment does not match.");
    const decoded = await decodeInvoicePayload(encodedInvoice, now.getTime());
    if (decoded.status !== "valid") throw new Error(decoded.status === "expired" ? "Ephemeral invoice has expired." : decoded.message);
    await validateEphemeralInvoice(decoded.invoice, new Date(Date.parse(decoded.invoice.createdAt)));
    const openedAt = now.toISOString();
    const next = withStateCommitment({
      version: EPHEMERAL_INVOICE_VERSION,
      linkCommitment: envelope.linkCommitment,
      status: "opened",
      createdAt: state.createdAt,
      updatedAt: openedAt,
      openedAt,
    });
    return {
      session: { invoice: decoded.invoice, viewingKey, linkCommitment: envelope.linkCommitment, status: "open" },
      state: next,
    };
  } catch (error) {
    viewingKey.fill(0);
    if (error instanceof Error) throw error;
    throw new Error("Ephemeral invoice decryption failed.");
  }
}

export function buildEphemeralSettlementActions(
  envelope: EphemeralInvoiceEnvelope,
  session: EphemeralInvoiceSession,
  state: EphemeralInvoiceState,
  now = new Date(),
): STRK20_ACTION[] {
  validateActiveSession(envelope, session, state, now, "opened");
  const invoice = requireSessionInvoice(session);
  return [{
    type: "transfer",
    token: normalizeStarknetAddress(invoice.tokenAddress),
    amount: decimalToBaseUnits(invoice.amount, invoice.tokenDecimals),
    recipient: normalizeStarknetAddress(invoice.recipientAddress),
  }];
}

export function recordEphemeralSubmission(
  envelope: EphemeralInvoiceEnvelope,
  session: EphemeralInvoiceSession,
  state: EphemeralInvoiceState,
  transactionHash: string,
  now = new Date(),
): EphemeralInvoiceState {
  validateActiveSession(envelope, session, state, now, "opened");
  const normalizedHash = requireTransactionHash(transactionHash);
  const submittedAt = now.toISOString();
  return withStateCommitment({
    ...withoutCommitment(state),
    status: "settlement_pending",
    updatedAt: submittedAt,
    submittedAt,
    transactionHash: normalizedHash,
  });
}

export function failEphemeralSubmission(
  envelope: EphemeralInvoiceEnvelope,
  session: EphemeralInvoiceSession,
  state: EphemeralInvoiceState,
  transactionHash: string,
  now = new Date(),
): EphemeralInvoiceState {
  validateActiveSession(envelope, session, state, now, "settlement_pending");
  if (state.transactionHash !== requireTransactionHash(transactionHash)) throw new Error("Failed transaction does not match the pending ephemeral settlement.");
  return withStateCommitment({
    version: EPHEMERAL_INVOICE_VERSION,
    linkCommitment: state.linkCommitment,
    status: "opened",
    createdAt: state.createdAt,
    updatedAt: now.toISOString(),
    openedAt: state.openedAt,
  });
}

export function burnEphemeralAfterSettlement(
  envelope: EphemeralInvoiceEnvelope,
  session: EphemeralInvoiceSession,
  state: EphemeralInvoiceState,
  transactionHash: string,
  now = new Date(),
): { state: EphemeralInvoiceState; receipt: EphemeralBurnReceipt } {
  validateActiveSession(envelope, session, state, now, "settlement_pending");
  const normalizedHash = requireTransactionHash(transactionHash);
  if (state.transactionHash !== normalizedHash) throw new Error("Confirmed transaction does not match the pending ephemeral settlement.");
  const destroyedAt = now.toISOString();
  destroyEphemeralSession(session);
  const next = withStateCommitment({
    ...withoutCommitment(state),
    status: "burned",
    updatedAt: destroyedAt,
    destroyedAt,
    burnReason: "settlement",
  });
  return { state: next, receipt: createBurnReceipt(next) };
}

export function expireEphemeralInvoice(
  envelope: EphemeralInvoiceEnvelope,
  state: EphemeralInvoiceState,
  session: EphemeralInvoiceSession | null,
  now = new Date(),
): { state: EphemeralInvoiceState; receipt: EphemeralBurnReceipt } {
  validateEnvelope(envelope);
  validateState(envelope, state);
  if (now.getTime() < Date.parse(envelope.expiresAt)) throw new Error("Ephemeral invoice TTL is still active.");
  if (state.status === "burned" || state.status === "expired") throw new Error("Ephemeral invoice is already in a terminal state.");
  if (session) {
    if (session.linkCommitment !== envelope.linkCommitment) throw new Error("Ephemeral session belongs to another invoice.");
    destroyEphemeralSession(session);
  }
  const destroyedAt = now.toISOString();
  const next = withStateCommitment({
    ...withoutCommitment(state),
    status: "expired",
    updatedAt: destroyedAt,
    destroyedAt,
    burnReason: "expiration",
  });
  return { state: next, receipt: createBurnReceipt(next) };
}

export function destroyEphemeralSession(session: EphemeralInvoiceSession): void {
  if (!session || session.status === "destroyed") return;
  session.viewingKey.fill(0);
  session.invoice = null;
  session.status = "destroyed";
}

export function getEphemeralStatus(
  envelope: EphemeralInvoiceEnvelope,
  state: EphemeralInvoiceState,
  now = new Date(),
): EphemeralStatus {
  validateEnvelope(envelope);
  validateState(envelope, state);
  if (state.status !== "burned" && state.status !== "expired" && now.getTime() >= Date.parse(envelope.expiresAt)) return "expired";
  return state.status;
}

export function serializeEphemeralEnvelope(envelope: EphemeralInvoiceEnvelope): string {
  validateEnvelope(envelope);
  return JSON.stringify(envelope);
}

export function parseEphemeralEnvelope(value: string): EphemeralInvoiceEnvelope {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error("Ephemeral envelope JSON is malformed."); }
  validateEnvelope(parsed);
  return parsed;
}

export function encodeEphemeralCapability(bundle: EphemeralInvoiceBundle): string {
  validateEnvelope(bundle.envelope);
  const viewingKey = fromBase64Url(bundle.viewingKey);
  if (viewingKey.length !== 32) throw new Error("Ephemeral viewing key must be 32 bytes.");
  const capability: EphemeralCapability = {
    kind: CAPABILITY_KIND,
    version: EPHEMERAL_INVOICE_VERSION,
    envelope: bundle.envelope,
    viewingKey: bundle.viewingKey,
  };
  const encoded = toBase64Url(new TextEncoder().encode(JSON.stringify(capability)));
  if (encoded.length > MAX_EPHEMERAL_CAPABILITY_LENGTH) throw new Error("Ephemeral capability exceeds the safe URL size limit.");
  return encoded;
}

export function decodeEphemeralCapability(encoded: string): EphemeralInvoiceBundle {
  if (typeof encoded !== "string" || !encoded || encoded.length > MAX_EPHEMERAL_CAPABILITY_LENGTH) throw new Error("Ephemeral capability is missing or oversized.");
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded))); } catch { throw new Error("Ephemeral capability is malformed."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Ephemeral capability is invalid.");
  const capability = parsed as EphemeralCapability;
  const allowed = ["kind", "version", "envelope", "viewingKey"];
  if (Object.keys(capability).some((key) => !allowed.includes(key)) || capability.kind !== CAPABILITY_KIND || capability.version !== EPHEMERAL_INVOICE_VERSION) throw new Error("Ephemeral capability header is invalid.");
  validateEnvelope(capability.envelope);
  if (fromBase64Url(capability.viewingKey).length !== 32) throw new Error("Ephemeral capability viewing key is invalid.");
  return { envelope: capability.envelope, viewingKey: capability.viewingKey };
}

export function createEphemeralPaymentLink(origin: string, bundle: EphemeralInvoiceBundle): string {
  let base: URL;
  try { base = new URL(origin); } catch { throw new Error("Payment link origin is invalid."); }
  if (base.protocol !== "https:" && base.hostname !== "localhost" && base.hostname !== "127.0.0.1") throw new Error("Ephemeral payment links require HTTPS outside localhost.");
  base.pathname = "/pay/ephemeral";
  base.search = "";
  base.hash = encodeEphemeralCapability(bundle);
  return base.toString();
}

export function readEphemeralState(
  envelope: EphemeralInvoiceEnvelope,
  storage?: Pick<Storage, "getItem">,
  now = new Date(),
): EphemeralInvoiceState {
  validateEnvelope(envelope);
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return createEphemeralInvoiceState(envelope, now);
    const registry: unknown = JSON.parse(target.getItem(STORAGE_KEY) ?? "{}");
    if (!registry || typeof registry !== "object" || Array.isArray(registry)) return createEphemeralInvoiceState(envelope, now);
    const state = (registry as Record<string, unknown>)[envelope.linkCommitment];
    validateState(envelope, state);
    return state;
  } catch {
    return createEphemeralInvoiceState(envelope, now);
  }
}

export function writeEphemeralState(
  envelope: EphemeralInvoiceEnvelope,
  state: EphemeralInvoiceState,
  storage?: Pick<Storage, "getItem" | "setItem">,
): boolean {
  validateEnvelope(envelope);
  validateState(envelope, state);
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return false;
    const parsed: unknown = JSON.parse(target.getItem(STORAGE_KEY) ?? "{}");
    const registry = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
    const existing = registry[envelope.linkCommitment];
    if (existing) {
      validateState(envelope, existing);
      if ((existing.status === "burned" || existing.status === "expired") && existing.stateCommitment !== state.stateCommitment) {
        throw new Error("Terminal ephemeral state cannot be overwritten.");
      }
    }
    target.setItem(STORAGE_KEY, JSON.stringify({ ...registry, [envelope.linkCommitment]: state }));
    return true;
  } catch (error) {
    if (error instanceof Error && error.message.includes("cannot be overwritten")) throw error;
    return false;
  }
}

export function verifyEphemeralState(envelope: EphemeralInvoiceEnvelope, state: EphemeralInvoiceState): boolean {
  try { validateEnvelope(envelope); validateState(envelope, state); return true; } catch { return false; }
}

export function getEphemeralSecurityModel(): EphemeralSecurityModel {
  return {
    enforcedHere: [
      "AES-GCM invoice confidentiality before capability redemption",
      "One successful capability claim per intact browser registry",
      "Exact full-balance STRK20 transfer plan and no partial payments",
      "Terminal local state after confirmed settlement or TTL expiration",
      "Best-effort zeroization of the mutable in-memory viewing-key buffer",
    ],
    cannotGuarantee: [
      "Revocation of a capability copied to another browser or offline backup",
      "Physical erasure of immutable URL strings, browser history, clipboard data, or JavaScript engine copies",
      "Global single use without an onchain or shared revocation registry",
    ],
    hiddenInPool: ["ordinary private-transfer sender", "recipient", "token", "amount", "spent-note linkage"],
    publicOrObservable: ["transaction timing", "relayer submission", "public shielding and withdrawal edges", "application-side capability sharing"],
  };
}

async function validateEphemeralInvoice(invoice: ShareableInvoice, now: Date): Promise<string> {
  const encoded = await encodeInvoicePayload(invoice);
  const decoded = await decodeInvoicePayload(encoded, now.getTime());
  if (decoded.status !== "valid") throw new Error(decoded.status === "expired" ? "Ephemeral invoice expiration must be in the future." : decoded.message);
  const ttl = Date.parse(decoded.invoice.expiresAt) - now.getTime();
  if (ttl < MIN_EPHEMERAL_TTL_MS || ttl > MAX_EPHEMERAL_TTL_MS) throw new Error("Ephemeral invoice TTL must be between one minute and 30 days.");
  if (decoded.invoice.allowPartialPayments || decoded.invoice.milestones?.length) throw new Error("Ephemeral invoices require one exact settlement and cannot use partial payments or milestones.");
  return encoded;
}

function validateEnvelope(value: unknown): asserts value is EphemeralInvoiceEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Ephemeral envelope is invalid.");
  const envelope = value as EphemeralInvoiceEnvelope;
  const allowed = ["kind", "version", "network", "poolAddress", "algorithm", "invoiceCommitment", "viewingKeyCommitment", "linkCommitment", "expiresAt", "iv", "ciphertext", "ciphertextDigest", "notice"];
  if (Object.keys(envelope).some((key) => !allowed.includes(key)) || envelope.kind !== ENVELOPE_KIND || envelope.version !== EPHEMERAL_INVOICE_VERSION || envelope.network !== MAINNET_CHAIN_ID || envelope.poolAddress !== STRK20_POOL_ADDRESS || envelope.algorithm !== ENCRYPTION_ALGORITHM) throw new Error("Ephemeral envelope header is invalid.");
  requireFelt(envelope.invoiceCommitment, "Invoice commitment");
  requireFelt(envelope.viewingKeyCommitment, "Viewing-key commitment");
  requireFelt(envelope.linkCommitment, "Link commitment");
  requireIsoTimestamp(envelope.expiresAt, "Ephemeral expiration");
  if (typeof envelope.notice !== "string" || !envelope.notice) throw new Error("Ephemeral envelope notice is missing.");
  for (const valueToCheck of [envelope.iv, envelope.ciphertext, envelope.ciphertextDigest]) if (typeof valueToCheck !== "string" || !/^[A-Za-z0-9_-]+$/.test(valueToCheck)) throw new Error("Ephemeral envelope encoding is invalid.");
  if (fromBase64Url(envelope.iv).length !== 12 || fromBase64Url(envelope.ciphertextDigest).length !== 32) throw new Error("Ephemeral envelope byte lengths are invalid.");
  const expectedLink = computeLinkCommitment({
    kind: envelope.kind,
    version: envelope.version,
    network: envelope.network,
    poolAddress: envelope.poolAddress,
    algorithm: envelope.algorithm,
    invoiceCommitment: envelope.invoiceCommitment,
    viewingKeyCommitment: envelope.viewingKeyCommitment,
    expiresAt: envelope.expiresAt,
    iv: envelope.iv,
    ciphertext: envelope.ciphertext,
    ciphertextDigest: envelope.ciphertextDigest,
  });
  if (expectedLink !== envelope.linkCommitment) throw new Error("Ephemeral link commitment is invalid.");
}

function validateState(envelope: EphemeralInvoiceEnvelope, value: unknown): asserts value is EphemeralInvoiceState {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Ephemeral state is invalid.");
  const state = value as EphemeralInvoiceState;
  const allowed = ["version", "linkCommitment", "status", "createdAt", "updatedAt", "openedAt", "submittedAt", "destroyedAt", "transactionHash", "burnReason", "stateCommitment"];
  if (Object.keys(state).some((key) => !allowed.includes(key)) || state.version !== EPHEMERAL_INVOICE_VERSION || state.linkCommitment !== envelope.linkCommitment || !["sealed", "opened", "settlement_pending", "burned", "expired"].includes(state.status)) throw new Error("Ephemeral state header is invalid.");
  requireIsoTimestamp(state.createdAt, "State creation time");
  requireIsoTimestamp(state.updatedAt, "State update time");
  if (state.openedAt) requireIsoTimestamp(state.openedAt, "State opening time");
  if (state.submittedAt) requireIsoTimestamp(state.submittedAt, "State submission time");
  if (state.destroyedAt) requireIsoTimestamp(state.destroyedAt, "State destruction time");
  if (state.transactionHash) requireTransactionHash(state.transactionHash);
  if (state.burnReason && state.burnReason !== "settlement" && state.burnReason !== "expiration") throw new Error("Ephemeral burn reason is invalid.");
  if (state.status === "sealed" && (state.openedAt || state.transactionHash || state.destroyedAt || state.burnReason)) throw new Error("Sealed ephemeral state contains terminal fields.");
  if (state.status === "opened" && (!state.openedAt || state.transactionHash || state.destroyedAt || state.burnReason)) throw new Error("Opened ephemeral state is invalid.");
  if (state.status === "settlement_pending" && (!state.openedAt || !state.submittedAt || !state.transactionHash || state.destroyedAt || state.burnReason)) throw new Error("Pending ephemeral state is invalid.");
  if (state.status === "burned" && (!state.openedAt || !state.submittedAt || !state.transactionHash || !state.destroyedAt || state.burnReason !== "settlement")) throw new Error("Burned ephemeral state is invalid.");
  if (state.status === "expired" && (!state.destroyedAt || state.burnReason !== "expiration")) throw new Error("Expired ephemeral state is invalid.");
  const supplied = requireFelt(state.stateCommitment, "State commitment");
  if (computeStateCommitment(withoutCommitment(state)) !== supplied) throw new Error("Ephemeral state commitment is invalid.");
}

function validateActiveSession(envelope: EphemeralInvoiceEnvelope, session: EphemeralInvoiceSession, state: EphemeralInvoiceState, now: Date, expectedStatus: "opened" | "settlement_pending"): void {
  validateEnvelope(envelope);
  validateState(envelope, state);
  if (state.status !== expectedStatus) throw new Error(`Ephemeral invoice must be ${expectedStatus.replaceAll("_", " ")} for this action.`);
  if (now.getTime() >= Date.parse(envelope.expiresAt)) throw new Error("Ephemeral invoice TTL has expired.");
  if (!session || session.status !== "open" || session.linkCommitment !== envelope.linkCommitment || session.viewingKey.length !== 32 || session.viewingKey.every((byte) => byte === 0)) throw new Error("Ephemeral viewing session is destroyed or invalid.");
  requireSessionInvoice(session);
}

function requireSessionInvoice(session: EphemeralInvoiceSession): ShareableInvoice {
  if (!session.invoice) throw new Error("Ephemeral invoice payload was destroyed.");
  return session.invoice;
}

function withStateCommitment(state: Omit<EphemeralInvoiceState, "stateCommitment">): EphemeralInvoiceState {
  return { ...state, stateCommitment: toHex(computeStateCommitment(state)) };
}

function withoutCommitment(state: EphemeralInvoiceState): Omit<EphemeralInvoiceState, "stateCommitment"> {
  const rest = { ...state } as Partial<EphemeralInvoiceState>;
  delete rest.stateCommitment;
  return rest as Omit<EphemeralInvoiceState, "stateCommitment">;
}

function computeStateCommitment(state: Omit<EphemeralInvoiceState, "stateCommitment">): bigint {
  return hashElements([
    STATE_DOMAIN,
    BigInt(state.linkCommitment),
    statusCode(state.status),
    timestampCode(state.createdAt),
    timestampCode(state.updatedAt),
    state.openedAt ? timestampCode(state.openedAt) : 0n,
    state.submittedAt ? timestampCode(state.submittedAt) : 0n,
    state.destroyedAt ? timestampCode(state.destroyedAt) : 0n,
    state.transactionHash ? BigInt(state.transactionHash) : 0n,
    state.burnReason === "settlement" ? 1n : state.burnReason === "expiration" ? 2n : 0n,
  ]);
}

function computeLinkCommitment(envelope: Omit<EphemeralInvoiceEnvelope, "linkCommitment" | "notice">): string {
  return toHex(hashElements([
    LINK_DOMAIN,
    BigInt(envelope.invoiceCommitment),
    BigInt(envelope.viewingKeyCommitment),
    timestampCode(envelope.expiresAt),
    hash.starknetKeccak(envelope.iv),
    hash.starknetKeccak(envelope.ciphertext),
    hash.starknetKeccak(envelope.ciphertextDigest),
    BigInt(envelope.poolAddress),
  ]));
}

function envelopeAssociatedData(envelope: Pick<EphemeralInvoiceEnvelope, "kind" | "version" | "network" | "poolAddress" | "algorithm" | "invoiceCommitment" | "viewingKeyCommitment" | "expiresAt">): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode([envelope.kind, envelope.version, envelope.network, envelope.poolAddress, envelope.algorithm, envelope.invoiceCommitment, envelope.viewingKeyCommitment, envelope.expiresAt].join("|"));
}

function createBurnReceipt(state: EphemeralInvoiceState): EphemeralBurnReceipt {
  if (!state.burnReason || !state.destroyedAt) throw new Error("Terminal ephemeral state is incomplete.");
  return {
    version: EPHEMERAL_INVOICE_VERSION,
    linkCommitment: state.linkCommitment,
    finalStateCommitment: state.stateCommitment,
    reason: state.burnReason,
    destroyedAt: state.destroyedAt,
    transactionHash: state.transactionHash,
    erasureAttestation: "Local application attestation only. It proves a terminal state transition, not physical erasure or global revocation of copied capabilities.",
  };
}

function statusCode(status: EphemeralStatus): bigint {
  return status === "sealed" ? 1n : status === "opened" ? 2n : status === "settlement_pending" ? 3n : status === "burned" ? 4n : 5n;
}

function timestampCode(value: string): bigint { return BigInt(Date.parse(value)); }

function requireTransactionHash(value: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/i.test(value)) throw new Error("Ephemeral settlement transaction hash is invalid.");
  return toHex(BigInt(value));
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

async function commitmentFromBytes(domain: bigint, value: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
  return toHex(hashElements([domain, bytesToBigint(digest.slice(0, 31))]));
}

async function importAesKey(bytes: Uint8Array<ArrayBuffer>, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, [usage]);
}

async function sha256Base64Url(value: Uint8Array<ArrayBuffer>): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", value)));
}

function hashElements(values: bigint[]): bigint { return BigInt(hash.computePoseidonHashOnElements(values)); }
function toHex(value: bigint): string { return `0x${value.toString(16)}`; }
function bytesToBigint(value: Uint8Array): bigint { return BigInt(`0x${[...value].map((byte) => byte.toString(16).padStart(2, "0")).join("") || "0"}`); }

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
