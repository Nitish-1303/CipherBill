import { isValidAmount, isValidStarknetAddress } from "./strk20/validation";

export type InvoiceStatus = "draft" | "pending" | "paid" | "failed";

export interface Invoice {
  id: string;
  recipient: string;
  amount: string;
  token: "STRK";
  description: string;
  dueDate: string;
  status: InvoiceStatus;
  transactionHash?: string;
}

const STORAGE_KEY = "shadowpay.invoices.v1";

export function readInvoices(storage: Pick<Storage, "getItem"> = window.localStorage): Invoice[] {
  try {
    const value = storage.getItem(STORAGE_KEY);
    if (!value) return [];
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter(isInvoice) : [];
  } catch {
    return [];
  }
}

export function writeInvoices(invoices: Invoice[], storage: Pick<Storage, "setItem"> = window.localStorage) {
  storage.setItem(STORAGE_KEY, JSON.stringify(invoices));
}

export function createInvoice(input: Omit<Invoice, "id" | "status">): Invoice {
  if (!isValidStarknetAddress(input.recipient)) throw new Error("Enter a valid Starknet recipient address.");
  if (!isValidAmount(input.amount)) throw new Error("Enter a positive STRK amount.");
  if (!input.dueDate || Number.isNaN(Date.parse(input.dueDate))) throw new Error("Enter a valid due date.");

  return { ...input, id: `inv_${crypto.randomUUID()}`, status: "draft" };
}

export function paymentLink(invoice: Invoice, origin = window.location.origin): string {
  return `${origin}/?invoice=${encodeURIComponent(invoice.id)}`;
}

export function selectiveReceipt(invoice: Invoice) {
  return {
    invoiceId: invoice.id,
    status: invoice.status,
    amount: invoice.amount,
    token: invoice.token,
    dueDate: invoice.dueDate,
    transactionHash: invoice.transactionHash ?? null,
  };
}

function isInvoice(value: unknown): value is Invoice {
  if (!value || typeof value !== "object") return false;
  const invoice = value as Partial<Invoice>;
  return typeof invoice.id === "string" && typeof invoice.recipient === "string" && typeof invoice.amount === "string" && invoice.token === "STRK" && typeof invoice.description === "string" && typeof invoice.dueDate === "string" && ["draft", "pending", "paid", "failed"].includes(invoice.status ?? "");
}