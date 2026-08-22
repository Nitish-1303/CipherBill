/**
 * Encrypted auditor disclosure exports ("view-keys") for CipherBill invoices.
 *
 * WHAT THIS IS
 * ------------
 * A merchant can take one invoice plus its recorded payments, choose exactly which
 * fields to reveal, and encrypt that selection in the browser under a freshly
 * generated 256-bit AES-GCM key. The merchant then hands the auditor two things
 * over two different channels:
 *
 *   1. the envelope  - `EncryptedAuditDisclosure`, inert on its own;
 *   2. the view-key  - a base64url AES-256-GCM key, never stored in the envelope.
 *
 * The envelope carries no invoice data in plaintext: the invoice id, merchant
 * fields, amounts and transaction hashes all live inside the ciphertext. Only the
 * algorithm header, the network, the STRK20 pool address, and a truncated
 * key-check value are readable without the key, and those header bytes are bound
 * into the AES-GCM tag as additional authenticated data, so editing them makes
 * decryption fail rather than silently succeed.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * -----------------------------------------------------------------------------
 * - It is NOT a STRK20 protocol viewing key. A STRK20 viewing keypair `K = k·G`
 *   is registered once per account via the `SetViewingKey` action and is then
 *   immutable; only the account owner can register it, and there is no per-invoice
 *   variant. CipherBill never requests, derives, or stores one.
 * - It is NOT part of the STRK20 auditor key escrow. That escrow is created at
 *   registration, when the account's private viewing key is encrypted to the
 *   governance-set auditor public key. Application code cannot write to it.
 * - It CANNOT decrypt STRK20 pool notes, derive nullifiers, read shielded
 *   balances, or authorize spending. Its authority begins and ends at one bundle.
 * - It is NOT a zero-knowledge proof and carries no merchant signature. It is
 *   application metadata plus on-chain transaction hashes that an auditor is
 *   expected to verify independently on Starknet.
 * - It does not make already-public data private. Deposits and withdrawals at the
 *   STRK20 pool edges are public on Starknet by design; encrypting a report about
 *   them does not retract them.
 * - Nothing here is written to Starknet. Generating or sharing an export creates
 *   no on-chain record and makes no contract call. `STRK20_POOL_ADDRESS` is
 *   recorded as provenance for the disclosed settlement hashes only.
 *
 * All amount arithmetic goes through bigint and the shared base-unit helpers, so
 * no invoice total is ever routed through a float.
 */

import {
  getInvoiceAccounting,
  type InvoiceLifecycle,
  type InvoicePaymentRecord,
  type InvoicePaymentStatus,
} from "./invoice-lifecycle";
import type { ShareableInvoice } from "./invoices";
import { type ReceiptDisclosureSelection } from "./selective-receipts";
import { getStarknetExplorerTransactionUrl, MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal } from "./strk20/validation";

export const AUDIT_DISCLOSURE_VERSION = 1 as const;
export const AUDIT_DISCLOSURE_ALGORITHM = "AES-GCM-256" as const;
export const AUDIT_KEY_BYTES = 32;
export const AUDIT_IV_BYTES = 12;
export const AUDIT_KEY_CHECK_BYTES = 8;
export const MAX_ENCODED_DISCLOSURE_LENGTH = 32_768;

const KEY_CHECK_DOMAIN = "cipherbill.audit-key-check.v1";
const PAYLOAD_DIGEST_BYTES = 16;
const BUNDLE_KIND = "cipherbill.audit-disclosure" as const;
const ENVELOPE_KIND = "cipherbill.encrypted-audit-disclosure" as const;

const DISCLOSURE_NOTICE =
  "COMPLIANCE: application-level encrypted disclosure generated in the merchant's browser. "
  + "The accompanying view-key is an AES-256-GCM key produced by CipherBill. It is NOT a STRK20 protocol "
  + "viewing key and NOT part of the STRK20 auditor key escrow. It decrypts only this bundle: it cannot "
  + "decrypt STRK20 pool notes, derive nullifiers, read shielded balances, or authorize spending. "
  + "Disclosed settlement hashes must be verified independently on Starknet mainnet.";

const ENVELOPE_NOTICE =
  "Encrypted CipherBill audit disclosure. Inert without its separately delivered view-key. "
  + "No invoice data is readable from this envelope. Nothing here was written to Starknet.";

const DISCLOSURE_LIMITATIONS: readonly string[] = [
  "A STRK20 viewing key is registered once per account and is immutable, and only the account owner can register it. This export neither contains nor substitutes for one.",
  "Deposits and withdrawals at the STRK20 pool edges are already public on Starknet, including their addresses and amounts. Encrypting this report does not make them private.",
  "This bundle is application metadata plus on-chain transaction hashes. It is not a zero-knowledge proof and carries no merchant digital signature.",
  "Anyone holding both the envelope and its view-key can read every disclosed field. Deliver the view-key over a separate channel from the envelope.",
  "Payment records reflect what this merchant's browser observed. Independently confirm every disclosed hash on Starknet mainnet before relying on it.",
];

export type AuditDisclosureErrorCode =
  | "invalid_key"
  | "invalid_envelope"
  | "decryption_failed"
  | "oversized"
  | "unsupported_version";

export class AuditDisclosureError extends Error {
  constructor(readonly code: AuditDisclosureErrorCode, message: string) {
    super(message);
    this.name = "AuditDisclosureError";
  }
}

/** A generated view-key. `key` is the secret; `checkValue` is safe to show beside an envelope. */
export interface AuditDisclosureKey {
  key: string;
  checkValue: string;
}

export interface AuditDisclosurePayment {
  hash: string;
  status: InvoicePaymentStatus;
  amount: string;
  amountBaseUnits: string;
  milestoneId?: string;
  milestoneLabel?: string;
  submittedAt: string;
  confirmedAt?: string;
  explorerUrl: string;
}

export interface AuditDisclosureTotals {
  tokenSymbol: string;
  tokenDecimals: number;
  totalBaseUnits: string;
  confirmedBaseUnits: string;
  pendingBaseUnits: string;
  remainingBaseUnits: string;
  total: string;
  confirmed: string;
  pending: string;
  remaining: string;
}

/** The plaintext report. Exists in memory and inside ciphertext only - never in the envelope. */
export interface AuditDisclosureBundle {
  kind: typeof BUNDLE_KIND;
  version: typeof AUDIT_DISCLOSURE_VERSION;
  invoiceId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: string;
  generatedAt: string;
  payloadDigest?: string;
  disclosedFields: string[];
  disclosed: Record<string, string>;
  payments: AuditDisclosurePayment[];
  totals: AuditDisclosureTotals;
  notice: string;
  limitations: string[];
}

/** The shareable envelope. Readable fields are header-only and authenticated via AES-GCM AAD. */
export interface EncryptedAuditDisclosure {
  kind: typeof ENVELOPE_KIND;
  version: typeof AUDIT_DISCLOSURE_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: string;
  algorithm: typeof AUDIT_DISCLOSURE_ALGORITHM;
  keyCheckValue: string;
  iv: string;
  ciphertext: string;
  notice: string;
}

export interface BuildAuditDisclosureOptions {
  /** Restrict the export to one milestone's payments. Omit to include every recorded payment. */
  milestoneId?: string;
  /** Omit failed payments. Defaults to false so an auditor sees reverted attempts too. */
  confirmedOnly?: boolean;
  /** The invoice's encoded link, bound in as a digest so the auditor can match bundle to link. */
  encodedPayload?: string;
  generatedAt?: Date;
}

/** WebCrypto's BufferSource requires a non-shared buffer, so byte arrays are pinned to ArrayBuffer. */
type Bytes = Uint8Array<ArrayBuffer>;

type RandomBytes = (target: Bytes) => Bytes;

const defaultRandomBytes: RandomBytes = (target) => crypto.getRandomValues(target);

/**
 * Generate a fresh 256-bit view-key. `random` is injectable so tests stay deterministic
 * without mocking globals.
 */
export async function generateAuditDisclosureKey(random: RandomBytes = defaultRandomBytes): Promise<AuditDisclosureKey> {
  const bytes = random(new Uint8Array(AUDIT_KEY_BYTES));
  if (bytes.byteLength !== AUDIT_KEY_BYTES) {
    throw new AuditDisclosureError("invalid_key", `A view-key must be exactly ${AUDIT_KEY_BYTES} bytes.`);
  }
  const key = bytesToBase64Url(bytes);
  return { key, checkValue: await computeKeyCheckValue(bytes) };
}

/** Recompute the check value for a supplied key, so a merchant can pair a key with an envelope. */
export async function auditKeyCheckValue(key: string): Promise<string> {
  return computeKeyCheckValue(parseAuditKey(key));
}

/**
 * Assemble the plaintext disclosure. `selection` reuses the selective-receipt field
 * allow-list, so the merchant's choices mean the same thing here as on a receipt.
 *
 * When `options.encodedPayload` is supplied, its SHA-256 prefix is recorded as
 * `payloadDigest`, letting an auditor confirm the bundle describes the exact invoice
 * link the merchant shared rather than some other invoice with similar figures.
 */
export async function buildAuditDisclosureBundle(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  selection: ReceiptDisclosureSelection,
  options: BuildAuditDisclosureOptions = {},
): Promise<AuditDisclosureBundle> {
  const generatedAt = options.generatedAt ?? new Date();
  const accounting = getInvoiceAccounting(invoice, lifecycle);
  const decimals = invoice.tokenDecimals;

  const selected = lifecycle.payments
    .filter((payment) => (options.milestoneId ? payment.milestoneId === options.milestoneId : true))
    .filter((payment) => (options.confirmedOnly ? payment.status === "confirmed" : true));

  const disclosed: Record<string, string> = {};
  if (selection.merchantName) disclosed.merchantName = invoice.merchantName;
  if (selection.recipientAddress) disclosed.recipientAddress = invoice.recipientAddress;
  if (selection.amount) {
    disclosed.invoiceAmount = invoice.amount;
    disclosed.tokenSymbol = invoice.tokenSymbol;
    disclosed.tokenAddress = invoice.tokenAddress;
  }
  if (selection.description) disclosed.description = invoice.description;
  if (selection.referenceNumber && invoice.referenceNumber) disclosed.referenceNumber = invoice.referenceNumber;
  if (selection.timestamps) {
    disclosed.invoiceCreatedAt = invoice.createdAt;
    disclosed.invoiceExpiresAt = invoice.expiresAt;
  }
  if (selection.milestone && options.milestoneId) {
    const milestone = invoice.milestones?.find((candidate) => candidate.id === options.milestoneId);
    disclosed.milestoneId = options.milestoneId;
    if (milestone) {
      disclosed.milestoneLabel = milestone.label;
      disclosed.milestoneAmount = milestone.amount;
    }
  }

  const payloadDigest = options.encodedPayload ? await computePayloadDigest(options.encodedPayload) : undefined;

  return {
    kind: BUNDLE_KIND,
    version: AUDIT_DISCLOSURE_VERSION,
    invoiceId: invoice.invoiceId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    generatedAt: generatedAt.toISOString(),
    disclosedFields: Object.keys(disclosed),
    disclosed,
    payments: selected.map((payment) => describePayment(payment, invoice, selection)),
    totals: {
      tokenSymbol: invoice.tokenSymbol,
      tokenDecimals: decimals,
      totalBaseUnits: accounting.totalBaseUnits.toString(),
      confirmedBaseUnits: accounting.confirmedBaseUnits.toString(),
      pendingBaseUnits: accounting.pendingBaseUnits.toString(),
      remainingBaseUnits: accounting.remainingBaseUnits.toString(),
      total: baseUnitsToDecimal(accounting.totalBaseUnits, decimals),
      confirmed: baseUnitsToDecimal(accounting.confirmedBaseUnits, decimals),
      pending: baseUnitsToDecimal(accounting.pendingBaseUnits, decimals),
      remaining: baseUnitsToDecimal(accounting.remainingBaseUnits, decimals),
    },
    notice: DISCLOSURE_NOTICE,
    limitations: [...DISCLOSURE_LIMITATIONS],
    ...(payloadDigest ? { payloadDigest } : {}),
  };
}

/** SHA-256 prefix of an encoded invoice link, used to bind a bundle to one invoice. */
export async function computePayloadDigest(encodedPayload: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(encodedPayload)));
  return bytesToBase64Url(digest.slice(0, PAYLOAD_DIGEST_BYTES));
}

/**
 * Encrypt a bundle under a view-key. The envelope header is bound in as AES-GCM
 * additional authenticated data, so header tampering fails the tag check.
 */
export async function encryptAuditDisclosure(
  bundle: AuditDisclosureBundle,
  key: string,
  random: RandomBytes = defaultRandomBytes,
): Promise<EncryptedAuditDisclosure> {
  const keyBytes = parseAuditKey(key);
  const iv = random(new Uint8Array(AUDIT_IV_BYTES));
  if (iv.byteLength !== AUDIT_IV_BYTES) {
    throw new AuditDisclosureError("invalid_envelope", `The AES-GCM nonce must be ${AUDIT_IV_BYTES} bytes.`);
  }

  const header = {
    kind: ENVELOPE_KIND,
    version: AUDIT_DISCLOSURE_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    algorithm: AUDIT_DISCLOSURE_ALGORITHM,
    keyCheckValue: await computeKeyCheckValue(keyBytes),
  } as const;

  const cryptoKey = await importAesKey(keyBytes, "encrypt");
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: associatedData(header) },
    cryptoKey,
    new TextEncoder().encode(JSON.stringify(bundle)),
  ));

  return {
    ...header,
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(ciphertext),
    notice: ENVELOPE_NOTICE,
  };
}

/** The auditor's side: recover the plaintext bundle, or fail loudly. */
export async function decryptAuditDisclosure(
  envelope: EncryptedAuditDisclosure,
  key: string,
): Promise<AuditDisclosureBundle> {
  if (!envelope || envelope.kind !== ENVELOPE_KIND) {
    throw new AuditDisclosureError("invalid_envelope", "This is not a CipherBill encrypted audit disclosure.");
  }
  if (envelope.version !== AUDIT_DISCLOSURE_VERSION) {
    throw new AuditDisclosureError("unsupported_version", "This disclosure version is not supported.");
  }
  if (envelope.algorithm !== AUDIT_DISCLOSURE_ALGORITHM) {
    throw new AuditDisclosureError("invalid_envelope", "Unsupported disclosure algorithm.");
  }

  const keyBytes = parseAuditKey(key);
  const cryptoKey = await importAesKey(keyBytes, "decrypt");
  const header = {
    kind: envelope.kind,
    version: envelope.version,
    network: envelope.network,
    poolAddress: envelope.poolAddress,
    algorithm: envelope.algorithm,
    keyCheckValue: envelope.keyCheckValue,
  } as const;

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(envelope.iv), additionalData: associatedData(header) },
      cryptoKey,
      base64UrlToBytes(envelope.ciphertext),
    );
  } catch {
    throw new AuditDisclosureError(
      "decryption_failed",
      "Decryption failed. The view-key does not match this envelope, or the envelope was altered.",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new AuditDisclosureError("decryption_failed", "The decrypted disclosure is not valid JSON.");
  }
  if (!isAuditDisclosureBundle(parsed)) {
    throw new AuditDisclosureError("decryption_failed", "The decrypted disclosure is not a CipherBill audit bundle.");
  }
  return parsed;
}

/** Compact, URL-safe envelope encoding for handing an auditor a single string. */
export function encodeAuditDisclosurePayload(envelope: EncryptedAuditDisclosure): string {
  const encoded = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(envelope)));
  if (encoded.length > MAX_ENCODED_DISCLOSURE_LENGTH) {
    throw new AuditDisclosureError("oversized", "This disclosure is too large to encode. Narrow the disclosed fields.");
  }
  return encoded;
}

export function decodeAuditDisclosurePayload(encoded: string): EncryptedAuditDisclosure {
  if (!encoded || encoded.length > MAX_ENCODED_DISCLOSURE_LENGTH) {
    throw new AuditDisclosureError("invalid_envelope", "Encoded disclosure is missing or too large.");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new AuditDisclosureError("invalid_envelope", "Encoded disclosure is not valid URL-safe data.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(base64UrlToBytes(encoded)));
  } catch {
    throw new AuditDisclosureError("invalid_envelope", "Encoded disclosure could not be parsed.");
  }
  if (!isEncryptedAuditDisclosure(parsed)) {
    throw new AuditDisclosureError("invalid_envelope", "Encoded disclosure is not a CipherBill envelope.");
  }
  return parsed;
}

export function serializeEncryptedAuditDisclosure(envelope: EncryptedAuditDisclosure): string {
  return JSON.stringify(envelope, null, 2);
}

/** Group a key into 8-character blocks so a human can read it aloud or check it by eye. */
export function formatAuditKeyForTransfer(key: string): string {
  parseAuditKey(key);
  return key.replaceAll(" ", "").replace(/(.{8})(?=.)/g, "$1 ");
}

export function auditDisclosureFileName(invoiceId: string, generatedAt = new Date()): string {
  const stamp = generatedAt.toISOString().replaceAll(/[:.]/g, "-");
  return `cipherbill-audit-${invoiceId}-${stamp}.json`;
}

function describePayment(
  payment: InvoicePaymentRecord,
  invoice: ShareableInvoice,
  selection: ReceiptDisclosureSelection,
): AuditDisclosurePayment {
  const milestone = payment.milestoneId
    ? invoice.milestones?.find((candidate) => candidate.id === payment.milestoneId)
    : undefined;
  return {
    hash: payment.hash,
    status: payment.status,
    amount: baseUnitsToDecimal(payment.amountBaseUnits, invoice.tokenDecimals),
    amountBaseUnits: payment.amountBaseUnits,
    ...(selection.milestone && payment.milestoneId ? { milestoneId: payment.milestoneId } : {}),
    ...(selection.milestone && milestone ? { milestoneLabel: milestone.label } : {}),
    submittedAt: payment.submittedAt,
    ...(payment.confirmedAt ? { confirmedAt: payment.confirmedAt } : {}),
    explorerUrl: getStarknetExplorerTransactionUrl(payment.hash),
  };
}

/**
 * Fixed-order header serialization used as AES-GCM additional authenticated data.
 * Written out field by field rather than via JSON.stringify so the byte layout can
 * never drift with key insertion order.
 */
function associatedData(header: {
  kind: string;
  version: number;
  network: string;
  poolAddress: string;
  algorithm: string;
  keyCheckValue: string;
}): Bytes {
  return new TextEncoder().encode(
    [header.kind, header.version, header.network, header.poolAddress, header.algorithm, header.keyCheckValue].join("|"),
  );
}

async function importAesKey(keyBytes: Bytes, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM", length: 256 }, false, [usage]);
}

async function computeKeyCheckValue(keyBytes: Bytes): Promise<string> {
  const input = new Uint8Array(KEY_CHECK_DOMAIN.length + keyBytes.byteLength);
  input.set(new TextEncoder().encode(KEY_CHECK_DOMAIN), 0);
  input.set(keyBytes, KEY_CHECK_DOMAIN.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  return bytesToBase64Url(digest.slice(0, AUDIT_KEY_CHECK_BYTES));
}

function parseAuditKey(key: string): Bytes {
  if (typeof key !== "string" || !key.trim()) {
    throw new AuditDisclosureError("invalid_key", "A view-key is required.");
  }
  const normalized = key.replaceAll(" ", "").trim();
  if (!/^[A-Za-z0-9_-]+$/.test(normalized)) {
    throw new AuditDisclosureError("invalid_key", "A view-key must be base64url text.");
  }
  let bytes: Bytes;
  try {
    bytes = base64UrlToBytes(normalized);
  } catch {
    throw new AuditDisclosureError("invalid_key", "This view-key could not be decoded.");
  }
  if (bytes.byteLength !== AUDIT_KEY_BYTES) {
    throw new AuditDisclosureError("invalid_key", `A view-key must decode to ${AUDIT_KEY_BYTES} bytes.`);
  }
  return bytes;
}

function isAuditDisclosureBundle(value: unknown): value is AuditDisclosureBundle {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<AuditDisclosureBundle>;
  return candidate.kind === BUNDLE_KIND
    && candidate.version === AUDIT_DISCLOSURE_VERSION
    && typeof candidate.invoiceId === "string"
    && Array.isArray(candidate.payments)
    && Boolean(candidate.totals)
    && Boolean(candidate.disclosed);
}

function isEncryptedAuditDisclosure(value: unknown): value is EncryptedAuditDisclosure {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<EncryptedAuditDisclosure>;
  return candidate.kind === ENVELOPE_KIND
    && candidate.version === AUDIT_DISCLOSURE_VERSION
    && typeof candidate.iv === "string"
    && typeof candidate.ciphertext === "string"
    && typeof candidate.keyCheckValue === "string";
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlToBytes(value: string): Bytes {
  if (value.length % 4 === 1) throw new AuditDisclosureError("invalid_envelope", "Invalid base64url length.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
