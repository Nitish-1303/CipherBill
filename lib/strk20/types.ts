export type PrivacyAction = "shield" | "private_transfer" | "unshield";

export type TransactionStatus =
  | "idle"
  | "preparing"
  | "awaiting_wallet"
  | "submitted"
  | "confirmed"
  | "failed";

export type Strk20ErrorCode =
  | "configuration"
  | "invalid_input"
  | "unsupported_network"
  | "unsupported_wallet"
  | "wallet_rejected"
  | "submission_failed"
  | "confirmation_failed";

export type WalletStatus =
  | "disconnected"
  | "connecting"
  | "connected"
  | "unsupported_wallet"
  | "wrong_network"
  | "rejected";

export interface WalletCapabilities {
  walletApiVersions: string[];
  supportedSpecs: string[];
  strk20: boolean;
}

export interface Strk20Error {
  code: Strk20ErrorCode;
  message: string;
}

export interface Strk20Config {
  chainId: "SN_MAIN";
  providerUrl: string;
  tokenAddress: string;
  poolAddress: string;
}

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
  error?: Strk20Error;
}

export interface ShieldedBalance {
  token: string;
  amount: string;
}

export interface Strk20Client {
  getBalance(): Promise<ShieldedBalance>;
  getFeeAmount(): Promise<string>;
  shield(amount: string): Promise<PrivacyTransaction>;
  privateTransfer(request: PrivatePaymentRequest): Promise<PrivacyTransaction>;
  unshield(amount: string, recipient: string): Promise<PrivacyTransaction>;
}
