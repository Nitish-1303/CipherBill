import type { ShareableInvoice } from "./invoices";
import { decimalToBaseUnits } from "./strk20/validation";

export type InvoiceLifecycleStatus =
  | "draft"
  | "active"
  | "partially_paid"
  | "confirming"
  | "paid"
  | "expired"
  | "cancelled"
  | "disputed";

export type InvoicePaymentStatus = "submitted" | "confirmed" | "failed";

export interface InvoicePaymentRecord {
  hash: string;
  amountBaseUnits: string;
  milestoneId?: string;
  status: InvoicePaymentStatus;
  submittedAt: string;
  confirmedAt?: string;
}

export interface InvoiceLifecycle {
  status: InvoiceLifecycleStatus;
  payments: InvoicePaymentRecord[];
  updatedAt: string;
}

export interface InvoiceAccounting {
  totalBaseUnits: bigint;
  confirmedBaseUnits: bigint;
  pendingBaseUnits: bigint;
  remainingBaseUnits: bigint;
}

export interface InvoiceMilestoneAccounting extends InvoiceAccounting {
  milestoneId: string;
}

const PAYMENT_LIFECYCLE_STORAGE_KEY = "cipherbill.payment-lifecycle.v1";

export function createInvoiceLifecycle(status: "draft" | "active" = "draft", now = new Date()): InvoiceLifecycle {
  return { status, payments: [], updatedAt: now.toISOString() };
}

export function activateInvoice(lifecycle: InvoiceLifecycle, now = new Date()): InvoiceLifecycle {
  if (lifecycle.status !== "draft") throw new Error("Only a draft invoice can be activated.");
  return { ...lifecycle, status: "active", updatedAt: now.toISOString() };
}

export function cancelInvoice(lifecycle: InvoiceLifecycle, now = new Date()): InvoiceLifecycle {
  if (["confirming", "paid", "cancelled", "expired"].includes(lifecycle.status)) throw new Error("This invoice cannot be cancelled.");
  return { ...lifecycle, status: "cancelled", updatedAt: now.toISOString() };
}

export function disputeInvoice(lifecycle: InvoiceLifecycle, now = new Date()): InvoiceLifecycle {
  if (!lifecycle.payments.some((payment) => payment.status === "confirmed")) {
    throw new Error("Only an invoice with a confirmed payment can be disputed.");
  }
  return { ...lifecycle, status: "disputed", updatedAt: now.toISOString() };
}

export function getInvoiceAccounting(invoice: ShareableInvoice, lifecycle: InvoiceLifecycle): InvoiceAccounting {
  const totalBaseUnits = BigInt(decimalToBaseUnits(invoice.amount, invoice.tokenDecimals));
  const confirmedBaseUnits = sumPayments(lifecycle, "confirmed");
  const pendingBaseUnits = sumPayments(lifecycle, "submitted");
  return {
    totalBaseUnits,
    confirmedBaseUnits,
    pendingBaseUnits,
    remainingBaseUnits: totalBaseUnits - confirmedBaseUnits,
  };
}

export function getMilestoneAccounting(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  milestoneId: string,
): InvoiceMilestoneAccounting {
  const milestone = invoice.milestones?.find((candidate) => candidate.id === milestoneId);
  if (!milestone) throw new Error("Selected milestone does not exist.");
  const payments = lifecycle.payments.filter((payment) => payment.milestoneId === milestoneId);
  const totalBaseUnits = BigInt(decimalToBaseUnits(milestone.amount, invoice.tokenDecimals));
  const confirmedBaseUnits = sumPaymentRecords(payments, "confirmed");
  const pendingBaseUnits = sumPaymentRecords(payments, "submitted");
  return {
    milestoneId,
    totalBaseUnits,
    confirmedBaseUnits,
    pendingBaseUnits,
    remainingBaseUnits: totalBaseUnits - confirmedBaseUnits,
  };
}

export function validateInvoicePayment(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  payment: Pick<InvoicePaymentRecord, "amountBaseUnits" | "milestoneId">,
): void {
  const effectiveStatus = deriveInvoiceStatus(invoice, lifecycle);
  if (!["active", "partially_paid"].includes(effectiveStatus)) {
    throw new Error("This invoice is not accepting payments.");
  }

  if (!/^\d+$/.test(payment.amountBaseUnits)) throw new Error("Payment amount is invalid.");
  const amount = BigInt(payment.amountBaseUnits);
  if (amount <= 0n) throw new Error("Payment amount must be positive.");
  const accounting = getInvoiceAccounting(invoice, lifecycle);
  if (amount + accounting.pendingBaseUnits > accounting.remainingBaseUnits) {
    throw new Error("Payment exceeds the exact remaining balance.");
  }

  if (invoice.milestones?.length) {
    validateMilestonePayment(invoice, lifecycle, payment.milestoneId, amount);
  } else {
    if (payment.milestoneId) throw new Error("This invoice does not define milestones.");
    if (!invoice.allowPartialPayments && amount !== accounting.remainingBaseUnits) {
      throw new Error("This invoice requires payment of the exact remaining balance.");
    }
  }
}

export function submitInvoicePayment(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  payment: Omit<InvoicePaymentRecord, "status">,
): InvoiceLifecycle {
  if (!/^0x[0-9a-f]{1,64}$/i.test(payment.hash)) throw new Error("Transaction hash is invalid.");
  if (!isIsoTimestamp(payment.submittedAt)) throw new Error("Payment submission time is invalid.");
  if (lifecycle.payments.some((existing) => existing.hash.toLowerCase() === payment.hash.toLowerCase())) {
    throw new Error("This transaction hash was already recorded.");
  }
  validateInvoicePayment(invoice, lifecycle, payment);

  return {
    status: "confirming",
    payments: [...lifecycle.payments, { ...payment, status: "submitted" }],
    updatedAt: payment.submittedAt,
  };
}

export function confirmInvoicePayment(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  hash: string,
  confirmedAt = new Date().toISOString(),
): InvoiceLifecycle {
  let found = false;
  const payments = lifecycle.payments.map((payment) => {
    if (payment.hash.toLowerCase() !== hash.toLowerCase()) return payment;
    if (payment.status !== "submitted") throw new Error("Only a submitted payment can be confirmed.");
    found = true;
    return { ...payment, status: "confirmed" as const, confirmedAt };
  });
  if (!found) throw new Error("Submitted payment was not found.");
  const next = { ...lifecycle, payments, updatedAt: confirmedAt };
  const accounting = getInvoiceAccounting(invoice, next);
  return { ...next, status: accounting.confirmedBaseUnits === accounting.totalBaseUnits ? "paid" : "partially_paid" };
}

export function failInvoicePayment(invoice: ShareableInvoice, lifecycle: InvoiceLifecycle, hash: string, now = new Date()): InvoiceLifecycle {
  let found = false;
  const payments = lifecycle.payments.map((payment) => {
    if (payment.hash.toLowerCase() !== hash.toLowerCase()) return payment;
    if (payment.status !== "submitted") throw new Error("Only a submitted payment can be marked failed.");
    found = true;
    return { ...payment, status: "failed" as const };
  });
  if (!found) throw new Error("Submitted payment was not found.");
  const next = { ...lifecycle, payments, updatedAt: now.toISOString() };
  return { ...next, status: getInvoiceAccounting(invoice, next).confirmedBaseUnits > 0n ? "partially_paid" : "active" };
}

export function deriveInvoiceStatus(invoice: ShareableInvoice, lifecycle: InvoiceLifecycle, now = Date.now()): InvoiceLifecycleStatus {
  if (["paid", "cancelled", "disputed"].includes(lifecycle.status)) return lifecycle.status;
  if (Date.parse(invoice.expiresAt) <= now) return "expired";
  return lifecycle.status;
}

export function readPayerInvoiceLifecycle(
  invoiceId: string,
  storage?: Pick<Storage, "getItem">,
): InvoiceLifecycle {
  const fallback = createInvoiceLifecycle("active");
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return fallback;
    const parsed: unknown = JSON.parse(target.getItem(PAYMENT_LIFECYCLE_STORAGE_KEY) ?? "{}");
    if (!parsed || typeof parsed !== "object") return fallback;
    const candidate = (parsed as Record<string, unknown>)[invoiceId];
    return normalizeInvoiceLifecycle(candidate, fallback);
  } catch {
    return fallback;
  }
}

export function writePayerInvoiceLifecycle(
  invoiceId: string,
  lifecycle: InvoiceLifecycle,
  storage?: Pick<Storage, "getItem" | "setItem">,
): boolean {
  try {
    const target = storage ?? (typeof window === "undefined" ? null : window.localStorage);
    if (!target) return false;
    const parsed: unknown = JSON.parse(target.getItem(PAYMENT_LIFECYCLE_STORAGE_KEY) ?? "{}");
    const records = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
    target.setItem(PAYMENT_LIFECYCLE_STORAGE_KEY, JSON.stringify({ ...records, [invoiceId]: lifecycle }));
    return true;
  } catch {
    return false;
  }
}

function sumPayments(lifecycle: InvoiceLifecycle, status: InvoicePaymentStatus): bigint {
  return sumPaymentRecords(lifecycle.payments, status);
}

function sumPaymentRecords(payments: InvoicePaymentRecord[], status: InvoicePaymentStatus): bigint {
  return payments
    .filter((payment) => payment.status === status)
    .reduce((sum, payment) => sum + BigInt(payment.amountBaseUnits), 0n);
}

function validateMilestonePayment(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  milestoneId: string | undefined,
  amount: bigint,
): void {
  if (!invoice.milestones?.length) {
    if (milestoneId) throw new Error("This invoice does not define milestones.");
    return;
  }
  if (!milestoneId) throw new Error("Select a milestone for this payment.");
  const accounting = getMilestoneAccounting(invoice, lifecycle, milestoneId);
  if (accounting.pendingBaseUnits + amount > accounting.remainingBaseUnits) {
    throw new Error("Payment exceeds the milestone balance.");
  }
  if (!invoice.allowPartialPayments && accounting.pendingBaseUnits + amount !== accounting.remainingBaseUnits) {
    throw new Error("This milestone requires its exact remaining balance.");
  }
}

export function normalizeInvoiceLifecycle(value: unknown, fallback = createInvoiceLifecycle("active")): InvoiceLifecycle {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
  const candidate = value as Omit<Partial<InvoiceLifecycle>, "status"> & { status?: InvoiceLifecycleStatus | "partially_submitted" };
  const statuses: Array<InvoiceLifecycleStatus | "partially_submitted"> = ["draft", "active", "partially_paid", "partially_submitted", "confirming", "paid", "expired", "cancelled", "disputed"];
  if (!candidate.status || !statuses.includes(candidate.status) || !Array.isArray(candidate.payments) || !isIsoTimestamp(candidate.updatedAt)) {
    return fallback;
  }
  if (!candidate.payments.every(isInvoicePaymentRecord)) return fallback;
  return {
    status: candidate.status === "partially_submitted" ? "partially_paid" : candidate.status,
    payments: candidate.payments,
    updatedAt: candidate.updatedAt,
  };
}

function isInvoicePaymentRecord(value: unknown): value is InvoicePaymentRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const payment = value as Partial<InvoicePaymentRecord>;
  return Boolean(
    typeof payment.hash === "string"
      && /^0x[0-9a-f]{1,64}$/i.test(payment.hash)
      && typeof payment.amountBaseUnits === "string"
      && /^\d+$/.test(payment.amountBaseUnits)
      && BigInt(payment.amountBaseUnits) > 0n
      && (!payment.milestoneId || /^[A-Za-z0-9_-]{1,40}$/.test(payment.milestoneId))
      && payment.status
      && ["submitted", "confirmed", "failed"].includes(payment.status)
      && isIsoTimestamp(payment.submittedAt)
      && (payment.status === "confirmed" ? isIsoTimestamp(payment.confirmedAt) : payment.confirmedAt === undefined),
  );
}

function isIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}
