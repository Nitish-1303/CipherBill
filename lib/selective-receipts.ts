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
    if (milestone) {
      disclosed.milestoneLabel = milestone.label;
      disclosed.milestoneAmount = milestone.amount;
    }
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
    notice: "COMPLIANCE: This is a user-generated application receipt for selective disclosure. It verifies an on-chain STRK20 pool settlement hash but is NOT a cryptographic zero-knowledge proof, NOT a merchant digital signature, and does NOT authenticate payer identity. Any disclosed transaction hash should be independently verified on Starknet mainnet via block explorers. Milestones and partial payment amounts reflect application metadata only.",
  };
}

export function serializeSelectiveReceipt(receipt: SelectiveReceipt): string {
  return JSON.stringify(receipt, null, 2);
}

export function formatPrintableReceipt(receipt: SelectiveReceipt): string {
  const lines = [
    "═══════════════════════════════════════════════════",
    "            CIPHERBILL SELECTIVE RECEIPT",
    "═══════════════════════════════════════════════════",
    "",
    `Invoice ID: ${receipt.invoiceId}`,
    `Network: ${receipt.network} (Starknet Mainnet)`,
    `Payment Status: ${receipt.paymentStatus.toUpperCase()}`,
    `Generated: ${new Date(receipt.generatedAt).toLocaleString()}`,
    "",
    "─────────────────────────────────────────────────────",
    "DISCLOSED FIELDS (User-Selected)",
    "─────────────────────────────────────────────────────",
    "",
  ];

  const { disclosed } = receipt;
  if (disclosed.merchantName) lines.push(`Merchant: ${disclosed.merchantName}`);
  if (disclosed.recipientAddress) lines.push(`Merchant Address: ${disclosed.recipientAddress}`);
  if (disclosed.amount) {
    lines.push(`Amount: ${disclosed.amount} ${disclosed.tokenSymbol}`);
    if (disclosed.tokenAddress) lines.push(`Token Contract: ${disclosed.tokenAddress}`);
  }
  if (disclosed.milestoneId) {
    lines.push(`Milestone: ${disclosed.milestoneLabel || disclosed.milestoneId}`);
    if (disclosed.milestoneAmount) lines.push(`Milestone Total: ${disclosed.milestoneAmount} ${disclosed.tokenSymbol}`);
  }
  if (disclosed.description) lines.push(`Description: ${disclosed.description}`);
  if (disclosed.referenceNumber) lines.push(`Reference: ${disclosed.referenceNumber}`);
  if (disclosed.transactionHash) {
    lines.push("");
    lines.push(`Transaction Hash: ${disclosed.transactionHash}`);
    lines.push("Verify independently on Starknet block explorers");
  }
  if (disclosed.submittedAt) {
    lines.push("");
    lines.push(`Submitted: ${new Date(disclosed.submittedAt).toLocaleString()}`);
    if (disclosed.confirmedAt) {
      lines.push(`Confirmed: ${new Date(disclosed.confirmedAt).toLocaleString()}`);
    }
  }

  lines.push("");
  lines.push("─────────────────────────────────────────────────────");
  lines.push("COMPLIANCE NOTICE");
  lines.push("─────────────────────────────────────────────────────");
  lines.push("");
  lines.push(wrapText(receipt.notice, 53));
  lines.push("");
  lines.push("═══════════════════════════════════════════════════");

  return lines.join("\n");
}

function wrapText(text: string, maxWidth: number): string {
  const words = text.split(" ");
  const lines: string[] = [];
  let currentLine = "";

  for (const word of words) {
    if (currentLine.length + word.length + 1 <= maxWidth) {
      currentLine += (currentLine ? " " : "") + word;
    } else {
      if (currentLine) lines.push(currentLine);
      currentLine = word;
    }
  }
  if (currentLine) lines.push(currentLine);

  return lines.join("\n");
}
