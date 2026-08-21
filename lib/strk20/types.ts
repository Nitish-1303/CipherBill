export type PrivacyAction = "shield" | "private_transfer" | "unshield";

export type TransactionStatus = "idle" | "preparing" | "awaiting_wallet" | "submitted" | "confirmed" | "failed";

export interface PrivatePaymentRequest {
  recipient: string;
  amount: string;
  token: "STRK";
  memo?: string;
}

export interface PrivacyTransaction {
  action: PrivacyAction;
  hash: string;
  status: TransactionStatus;
  submittedAt: string;
}

export interface Strk20Client {
  shield(amount: string): Promise<PrivacyTransaction>;
  privateTransfer(request: PrivatePaymentRequest): Promise<PrivacyTransaction>;
  unshield(amount: string, recipient: string): Promise<PrivacyTransaction>;
}
