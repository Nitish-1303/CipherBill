import { MAINNET_CHAIN_ID } from "./strk20/config";
import { decimalToBaseUnits, normalizeStarknetAddress } from "./strk20/validation";

export const INVOICE_SCHEMA_VERSION = 1 as const;
export const MAX_ENCODED_INVOICE_LENGTH = 2_048;
export const MAX_INVOICE_JSON_BYTES = 1_200;
export const MAX_TOKEN_DECIMALS = 18;
export const MAX_INVOICE_LIFETIME_MS = 365 * 24 * 60 * 60 * 1_000;

const CHECKSUM_BYTES = 16;
const STORAGE_KEY = "cipherbill.invoices.v2";
const SECRET_FIELD = /(api.?key|private.?key|seed|mnemonic|viewing.?key|secret)/i;
const SECRET_VALUE = /\b(api key|private key|seed phrase|mnemonic|viewing key)\b/i;
const ALLOWED_FIELDS = new Set([
  "version", "invoiceId", "merchantName", "recipientAddress", "tokenAddress", "tokenSymbol",
  "tokenDecimals", "amount", "description", "referenceNumber", "createdAt", "expiresAt", "network",
]);

export interface ShareableInvoiceV1 {
  version: typeof INVOICE_SCHEMA_VERSION;
  invoiceId: string;
  merchantName: string;
  recipientAddress: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: number;
  amount: string;
  description: string;
  referenceNumber?: string;
  createdAt: string;
  expiresAt: string;
  network: typeof MAINNET_CHAIN_ID;
}

export interface CreateInvoiceInput {
  merchantName: string;
  recipientAddress: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: number;
  amount: string;
  description: string;
  referenceNumber?: string;
  expiresAt: string;
}

export interface LocalInvoiceRecord {
  invoice: ShareableInvoiceV1;
  encodedPayload: string;
  savedAt: string;
}

export type InvoiceErrorCode =
  | "malformed" | "checksum" | "unsupported_version" | "oversized" | "expired" | "incomplete"
  | "invalid_address" | "invalid_decimals" | "invalid_amount" | "unsafe_field";

export type InvoiceDecodeResult =
  | { status: "valid"; invoice: ShareableInvoiceV1 }
  | { status: "expired"; invoice: ShareableInvoiceV1; message: string }
  | { status: "invalid"; code: InvoiceErrorCode; message: string };

class InvoiceValidationError extends Error {
  constructor(readonly code: InvoiceErrorCode, message: string) {
    super(message);
  }
}

export function createShareableInvoice(
  input: CreateInvoiceInput,
  now = new Date(),
  createId = () => `inv_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
): ShareableInvoiceV1 {
  const invoice = validateInvoice({
    version: INVOICE_SCHEMA_VERSION,
    invoiceId: createId(),
    merchantName: input.merchantName,
    recipientAddress: input.recipientAddress,
    tokenAddress: input.tokenAddress,
    tokenSymbol: input.tokenSymbol,
    tokenDecimals: input.tokenDecimals,
    amount: input.amount,
    description: input.description,
    referenceNumber: input.referenceNumber || undefined,
    createdAt: now.toISOString(),
    expiresAt: input.expiresAt,
    network: MAINNET_CHAIN_ID,
  });

  if (Date.parse(invoice.expiresAt) <= now.getTime()) {
    throw new InvoiceValidationError("expired", "Expiration must be in the future.");
  }
  return invoice;
}

export async function encodeInvoicePayload(invoice: ShareableInvoiceV1): Promise<string> {
  const canonical = validateInvoice(invoice);
  const jsonBytes = new TextEncoder().encode(JSON.stringify(canonical));
  if (jsonBytes.byteLength > MAX_INVOICE_JSON_BYTES) {
    throw new InvoiceValidationError("oversized", "Invoice payload exceeds the maximum size.");
  }
  const data = bytesToBase64Url(jsonBytes);
  const encoded = `${data}.${await checksumFor(data)}`;
  if (encoded.length > MAX_ENCODED_INVOICE_LENGTH) {
    throw new InvoiceValidationError("oversized", "Encoded invoice link exceeds the maximum size.");
  }
  return encoded;
}

export async function decodeInvoicePayload(encoded: string, now = Date.now()): Promise<InvoiceDecodeResult> {
  try {
    if (!encoded) throw new InvoiceValidationError("malformed", "Invoice payload is missing.");
    if (encoded.length > MAX_ENCODED_INVOICE_LENGTH) {
      throw new InvoiceValidationError("oversized", "Invoice payload is too large.");
    }

    const parts = encoded.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new InvoiceValidationError("malformed", "Invoice payload format is invalid.");
    }
    const [data, suppliedChecksum] = parts;
    if (!/^[A-Za-z0-9_-]+$/.test(data) || !/^[A-Za-z0-9_-]{22}$/.test(suppliedChecksum)) {
      throw new InvoiceValidationError("malformed", "Invoice payload is not valid URL-safe data.");
    }

    const expectedChecksum = await checksumFor(data);
    if (!constantTimeEqual(suppliedChecksum, expectedChecksum)) {
      throw new InvoiceValidationError("checksum", "Invoice checksum does not match. The link may be corrupted.");
    }

    const jsonBytes = base64UrlToBytes(data);
    if (jsonBytes.byteLength > MAX_INVOICE_JSON_BYTES) {
      throw new InvoiceValidationError("oversized", "Decoded invoice payload exceeds the maximum size.");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(jsonBytes));
    } catch {
      throw new InvoiceValidationError("malformed", "Invoice payload does not contain valid JSON.");
    }

    const invoice = validateInvoice(parsed);
    if (Date.parse(invoice.expiresAt) <= now) {
      return { status: "expired", invoice, message: "This invoice has expired and cannot be paid." };
    }
    if (Date.parse(invoice.createdAt) > now + 5 * 60 * 1_000) {
      return { status: "invalid", code: "malformed", message: "Invoice creation time is in the future." };
    }
    return { status: "valid", invoice };
  } catch (error) {
    if (error instanceof InvoiceValidationError) {
      return { status: "invalid", code: error.code, message: error.message };
    }
    return { status: "invalid", code: "malformed", message: "Invoice payload could not be decoded." };
  }
}

export function invoicePaymentUrl(encodedPayload: string, origin = window.location.origin): string {
  return `${origin.replace(/\/$/, "")}/pay/${encodedPayload}`;
}

export function readInvoices(storage?: Pick<Storage, "getItem">): LocalInvoiceRecord[] {
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return [];
    const raw = target.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(isLocalInvoiceRecord) : [];
  } catch {
    return [];
  }
}

export function writeInvoices(invoices: LocalInvoiceRecord[], storage?: Pick<Storage, "setItem">): boolean {
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return false;
    target.setItem(STORAGE_KEY, JSON.stringify(invoices));
    return true;
  } catch {
    return false;
  }
}

function validateInvoice(value: unknown): ShareableInvoiceV1 {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvoiceValidationError("malformed", "Invoice payload must be an object.");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.some((key) => SECRET_FIELD.test(key))) {
    throw new InvoiceValidationError("unsafe_field", "Secret-like fields are not allowed in invoice links.");
  }
  if (keys.some((key) => !ALLOWED_FIELDS.has(key))) {
    throw new InvoiceValidationError("unsafe_field", "Invoice payload contains unsupported fields.");
  }
  if (record.version !== INVOICE_SCHEMA_VERSION) {
    throw new InvoiceValidationError("unsupported_version", "This invoice schema version is not supported.");
  }

  const invoiceId = requiredText(record.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  const merchantName = requiredText(record.merchantName, "Merchant name", 80);
  const tokenSymbol = requiredText(record.tokenSymbol, "Token symbol", 12, /^[A-Za-z0-9]+$/).toUpperCase();
  const description = requiredText(record.description, "Description", 160);
  const referenceNumber = optionalText(record.referenceNumber, "Reference number", 64);
  const amount = requiredText(record.amount, "Amount", 96);
  const createdAt = isoTimestamp(record.createdAt, "Created timestamp");
  const expiresAt = isoTimestamp(record.expiresAt, "Expiration timestamp");

  if (SECRET_VALUE.test(`${merchantName} ${description} ${referenceNumber ?? ""}`)) {
    throw new InvoiceValidationError("unsafe_field", "Secret-like content must not be placed in an invoice link.");
  }
  if (record.network !== MAINNET_CHAIN_ID) {
    throw new InvoiceValidationError("incomplete", "Invoice network must be SN_MAIN.");
  }
  if (!Number.isInteger(record.tokenDecimals) || (record.tokenDecimals as number) < 0 || (record.tokenDecimals as number) > MAX_TOKEN_DECIMALS) {
    throw new InvoiceValidationError("invalid_decimals", `Token decimals must be an integer from 0 to ${MAX_TOKEN_DECIMALS}.`);
  }

  let recipientAddress: string;
  let tokenAddress: string;
  try {
    recipientAddress = normalizeStarknetAddress(requiredText(record.recipientAddress, "Merchant address", 66));
    tokenAddress = normalizeStarknetAddress(requiredText(record.tokenAddress, "Token address", 66));
  } catch {
    throw new InvoiceValidationError("invalid_address", "Invoice contains an invalid Starknet address.");
  }

  try {
    decimalToBaseUnits(amount, record.tokenDecimals as number);
  } catch {
    throw new InvoiceValidationError("invalid_amount", "Invoice amount is invalid for the token decimals.");
  }

  const createdMs = Date.parse(createdAt);
  const expiresMs = Date.parse(expiresAt);
  if (expiresMs <= createdMs || expiresMs - createdMs > MAX_INVOICE_LIFETIME_MS) {
    throw new InvoiceValidationError("expired", "Invoice expiration must be after creation and within one year.");
  }

  return {
    version: INVOICE_SCHEMA_VERSION,
    invoiceId,
    merchantName,
    recipientAddress,
    tokenAddress,
    tokenSymbol,
    tokenDecimals: record.tokenDecimals as number,
    amount,
    description,
    ...(referenceNumber ? { referenceNumber } : {}),
    createdAt,
    expiresAt,
    network: MAINNET_CHAIN_ID,
  };
}

function requiredText(value: unknown, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new InvoiceValidationError("incomplete", `${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) {
    throw new InvoiceValidationError("incomplete", `${label} is missing or invalid.`);
  }
  return normalized;
}

function optionalText(value: unknown, label: string, maxLength: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new InvoiceValidationError("incomplete", `${label} is invalid.`);
  const normalized = value.trim();
  if (!normalized) return undefined;
  if (normalized.length > maxLength) throw new InvoiceValidationError("incomplete", `${label} is too long.`);
  return normalized;
}

function isoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > 32) {
    throw new InvoiceValidationError("incomplete", `${label} is required.`);
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) {
    throw new InvoiceValidationError("incomplete", `${label} must be an ISO timestamp.`);
  }
  return value;
}

async function checksumFor(data: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data)));
  return bytesToBase64Url(digest.slice(0, CHECKSUM_BYTES));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  if (value.length % 4 === 1) throw new InvoiceValidationError("malformed", "Invoice payload has invalid base64url length.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function isLocalInvoiceRecord(value: unknown): value is LocalInvoiceRecord {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<LocalInvoiceRecord>;
  try {
    return typeof record.encodedPayload === "string"
      && record.encodedPayload.length <= MAX_ENCODED_INVOICE_LENGTH
      && typeof record.savedAt === "string"
      && Boolean(validateInvoice(record.invoice));
  } catch {
    return false;
  }
}
