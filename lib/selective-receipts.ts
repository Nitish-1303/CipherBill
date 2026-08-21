import type { InvoicePaymentRecord } from "./invoice-lifecycle";
import type { ShareableInvoice } from "./invoices";
import { baseUnitsToDecimal } from "./strk20/validation";

export const SELECTIVE_RECEIPT_VERSION = 1 as const;

export interface ReceiptDisclosureSelection {
  merchantName: boolean;
  recipientAddress: boolean;
  amount: boolean;
  milestone: boolean;
  description: boolean;
  referenceNumber: boolean;
  transactionHash: boolean;
  timestamps: boolean;
}

export const DEFAULT_RECEIPT_SELECTION: ReceiptDisclosureSelection = {
  merchantName: true,
  recipientAddress: false,
  amount: true,
  milestone: true,
  description: false,
  referenceNumber: false,
  transactionHash: true,
  timestamps: true,
};

export interface SelectiveReceipt {
  kind: "cipherbill.selective-receipt";
  version: typeof SELECTIVE_RECEIPT_VERSION;
  invoiceId: string;
  network: "SN_MAIN";
  paymentStatus: InvoicePaymentRecord["status"];
  generatedAt: string;
  disclosedFields: string[];
  disclosed: Record<string, string>;
  notice: string;
}

export function createSelectiveReceipt(
  invoice: ShareableInvoice,
  payment: InvoicePaymentRecord,
  selection: ReceiptDisclosureSelection,
  generatedAt = new Date(),
): SelectiveReceipt {
  const disclosed: Record<string, string> = {};
  if (selection.merchantName) disclosed.merchantName = invoice.merchantName;
  if (selection.recipientAddress) disclosed.recipientAddress = invoice.recipientAddress;
  if (selection.amount) {
    disclosed.amount = baseUnitsToDecimal(payment.amountBaseUnits, invoice.tokenDecimals);
    disclosed.tokenSymbol = invoice.tokenSymbol;
    disclosed.tokenAddress = invoice.tokenAddress;
  }
  if (selection.milestone && payment.milestoneId) {
    const milestone = invoice.milestones?.find((candidate) => candidate.id === payment.milestoneId);
    disclosed.milestoneId = payment.milestoneId;
    if (milestone) disclosed.milestoneLabel = milestone.label;
  }
  if (selection.description) disclosed.description = invoice.description;
  if (selection.referenceNumber && invoice.referenceNumber) disclosed.referenceNumber = invoice.referenceNumber;
  if (selection.transactionHash) disclosed.transactionHash = payment.hash;
  if (selection.timestamps) {
    disclosed.submittedAt = payment.submittedAt;
    if (payment.confirmedAt) disclosed.confirmedAt = payment.confirmedAt;
  }

  return {
    kind: "cipherbill.selective-receipt",
    version: SELECTIVE_RECEIPT_VERSION,
    invoiceId: invoice.invoiceId,
    network: invoice.network,
    paymentStatus: payment.status,
    generatedAt: generatedAt.toISOString(),
    disclosedFields: Object.keys(disclosed),
    disclosed,
    notice: "User-selected application receipt. It is not a merchant signature or a zero-knowledge proof; verify any disclosed transaction hash on Starknet.",
  };
}

export function serializeSelectiveReceipt(receipt: SelectiveReceipt): string {
  return JSON.stringify(receipt, null, 2);
}
