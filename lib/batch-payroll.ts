import { decimalToBaseUnits, normalizeStarknetAddress } from "./strk20/validation";

export const BATCH_PAYROLL_VERSION = 2 as const;
export const MAX_ENCODED_BATCH_LENGTH = 16384;
export const MAX_BATCH_JSON_BYTES = 12000;
const CHECKSUM_BYTES = 16;
const BATCH_LIFECYCLE_STORAGE_KEY = "cipherbill.batch-lifecycle.v1";
const BATCH_LIST_STORAGE_KEY = "cipherbill.batch-list.v1";

export interface BatchRecipient {
  id: string;
  recipientAddress: string;
  amount: string;
  name: string;
  description: string;
}

export interface ShareableBatchInvoice {
  version: typeof BATCH_PAYROLL_VERSION;
  batchId: string;
  organizationName: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: number;
  totalAmount: string;
  recipients: BatchRecipient[];
  createdAt: string;
  expiresAt: string;
  network: "SN_MAIN";
  isBatchPayroll: true;
}

export interface CreateBatchInput {
  organizationName: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: number;
  recipients: Omit<BatchRecipient, "id">[];
  expiresAt: string;
}

export interface BatchPaymentRecord {
  recipientId: string;
  hash: string;
  status: "submitted" | "confirmed" | "failed";
  submittedAt: string;
  confirmedAt?: string;
}

export interface BatchLifecycle {
  status: "batch_pending" | "partially_distributed" | "batch_settled";
  payments: BatchPaymentRecord[];
  updatedAt: string;
}

export interface LocalBatchRecord {
  invoice: ShareableBatchInvoice;
  encodedPayload: string;
  savedAt: string;
  lifecycle: BatchLifecycle;
}

export type BatchErrorCode =
  | "malformed"
  | "checksum"
  | "unsupported_version"
  | "oversized"
  | "expired"
  | "incomplete"
  | "invalid_address"
  | "invalid_decimals"
  | "invalid_amount";

export type BatchDecodeResult =
  | { status: "valid"; invoice: ShareableBatchInvoice }
  | { status: "expired"; invoice: ShareableBatchInvoice; message: string }
  | { status: "invalid"; code: BatchErrorCode; message: string };

class BatchValidationError extends Error {
  constructor(readonly code: BatchErrorCode, message: string) {
    super(message);
  }
}

export function createBatchLifecycle(now = new Date()): BatchLifecycle {
  return { status: "batch_pending", payments: [], updatedAt: now.toISOString() };
}

export function createShareableBatchInvoice(
  input: CreateBatchInput,
  now = new Date(),
  createId = () => `batch_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
): ShareableBatchInvoice {
  const recipientsWithIds = input.recipients.map((r, index) => ({
    ...r,
    id: `rec_${index + 1}`,
  }));

  // Strict BigInt safety calculation of totalAmount
  let totalBaseUnits = 0n;
  for (const r of recipientsWithIds) {
    try {
      totalBaseUnits += BigInt(decimalToBaseUnits(r.amount, input.tokenDecimals));
    } catch {
      throw new BatchValidationError("invalid_amount", `Amount is invalid for recipient: ${r.name}`);
    }
  }

  const totalAmount = (Number(totalBaseUnits) / 10 ** input.tokenDecimals).toFixed(input.tokenDecimals).replace(/\.?0+$/, "");

  const invoice: ShareableBatchInvoice = {
    version: BATCH_PAYROLL_VERSION,
    batchId: createId(),
    organizationName: input.organizationName.trim(),
    tokenAddress: normalizeStarknetAddress(input.tokenAddress),
    tokenSymbol: input.tokenSymbol,
    tokenDecimals: input.tokenDecimals,
    totalAmount,
    recipients: recipientsWithIds.map((r) => ({
      ...r,
      recipientAddress: normalizeStarknetAddress(r.recipientAddress),
      name: r.name.trim(),
      description: r.description.trim(),
    })),
    createdAt: now.toISOString(),
    expiresAt: input.expiresAt,
    network: "SN_MAIN",
    isBatchPayroll: true,
  };

  validateBatchInvoice(invoice);

  if (Date.parse(invoice.expiresAt) <= now.getTime()) {
    throw new BatchValidationError("expired", "Expiration must be in the future.");
  }

  return invoice;
}

export function validateBatchInvoice(invoice: ShareableBatchInvoice): void {
  if (invoice.version !== BATCH_PAYROLL_VERSION) {
    throw new BatchValidationError("unsupported_version", "Unsupported version.");
  }
  if (!invoice.batchId || !invoice.organizationName || !invoice.recipients.length) {
    throw new BatchValidationError("incomplete", "Missing required fields.");
  }
  try {
    normalizeStarknetAddress(invoice.tokenAddress);
  } catch {
    throw new BatchValidationError("invalid_address", "Invalid token address.");
  }

  let computedBaseUnits = 0n;
  for (const r of invoice.recipients) {
    try {
      normalizeStarknetAddress(r.recipientAddress);
    } catch {
      throw new BatchValidationError("invalid_address", `Invalid recipient address: ${r.name}`);
    }
    try {
      computedBaseUnits += BigInt(decimalToBaseUnits(r.amount, invoice.tokenDecimals));
    } catch {
      throw new BatchValidationError("invalid_amount", `Invalid amount for recipient: ${r.name}`);
    }
  }
  const expectedBaseUnits = BigInt(decimalToBaseUnits(invoice.totalAmount, invoice.tokenDecimals));
  if (computedBaseUnits !== expectedBaseUnits) {
    throw new BatchValidationError("invalid_amount", "Recipient total does not match totalAmount.");
  }
}

export async function encodeBatchPayload(batch: ShareableBatchInvoice): Promise<string> {
  validateBatchInvoice(batch);
  const jsonBytes = new TextEncoder().encode(JSON.stringify(batch));
  if (jsonBytes.byteLength > MAX_BATCH_JSON_BYTES) {
    throw new BatchValidationError("oversized", "Batch payload exceeds maximum size.");
  }
  const data = bytesToBase64Url(jsonBytes);
  const encoded = `${data}.${await checksumFor(data)}`;
  if (encoded.length > MAX_ENCODED_BATCH_LENGTH) {
    throw new BatchValidationError("oversized", "Encoded payload exceeds maximum size.");
  }
  return encoded;
}

export async function decodeBatchPayload(encoded: string, now = Date.now()): Promise<BatchDecodeResult> {
  try {
    if (!encoded) throw new BatchValidationError("malformed", "Payload is missing.");
    if (encoded.length > MAX_ENCODED_BATCH_LENGTH) {
      throw new BatchValidationError("oversized", "Payload is too large.");
    }
    const parts = encoded.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new BatchValidationError("malformed", "Format is invalid.");
    }
    const [data, suppliedChecksum] = parts;
    const expectedChecksum = await checksumFor(data);
    if (suppliedChecksum !== expectedChecksum) {
      throw new BatchValidationError("checksum", "Checksum mismatch.");
    }
    const jsonBytes = base64UrlToBytes(data);
    const parsed = JSON.parse(new TextDecoder("utf-8").decode(jsonBytes));
    if (!parsed.isBatchPayroll) {
      throw new BatchValidationError("malformed", "Not a batch payroll payload.");
    }
    const invoice = parsed as ShareableBatchInvoice;
    validateBatchInvoice(invoice);

    if (Date.parse(invoice.expiresAt) <= now) {
      return { status: "expired", invoice, message: "This batch payroll has expired." };
    }
    return { status: "valid", invoice };
  } catch (error) {
    if (error instanceof BatchValidationError) {
      return { status: "invalid", code: error.code, message: error.message };
    }
    return { status: "invalid", code: "malformed", message: "Batch payload could not be decoded." };
  }
}

export function deriveBatchStatus(
  invoice: ShareableBatchInvoice,
  lifecycle: BatchLifecycle,
): "batch_pending" | "partially_distributed" | "batch_settled" {
  const confirmedCount = lifecycle.payments.filter((p) => p.status === "confirmed").length;
  if (confirmedCount === 0) return "batch_pending";
  if (confirmedCount === invoice.recipients.length) return "batch_settled";
  return "partially_distributed";
}

export function readLocalBatchRecord(batchId: string, storage?: Pick<Storage, "getItem">): BatchLifecycle {
  const fallback = createBatchLifecycle();
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return fallback;
    const parsed = JSON.parse(target.getItem(BATCH_LIFECYCLE_STORAGE_KEY) ?? "{}");
    return parsed[batchId] ?? fallback;
  } catch {
    return fallback;
  }
}

export function writeLocalBatchRecord(
  batchId: string,
  lifecycle: BatchLifecycle,
  storage?: Pick<Storage, "getItem" | "setItem">,
): boolean {
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return false;
    const parsed = JSON.parse(target.getItem(BATCH_LIFECYCLE_STORAGE_KEY) ?? "{}");
    target.setItem(BATCH_LIFECYCLE_STORAGE_KEY, JSON.stringify({ ...parsed, [batchId]: lifecycle }));
    return true;
  } catch {
    return false;
  }
}

export function readBatchList(storage?: Pick<Storage, "getItem">): LocalBatchRecord[] {
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return [];
    return JSON.parse(target.getItem(BATCH_LIST_STORAGE_KEY) ?? "[]");
  } catch {
    return [];
  }
}

export function writeBatchList(list: LocalBatchRecord[], storage?: Pick<Storage, "setItem">): boolean {
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return false;
    target.setItem(BATCH_LIST_STORAGE_KEY, JSON.stringify(list));
    return true;
  } catch {
    return false;
  }
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
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
