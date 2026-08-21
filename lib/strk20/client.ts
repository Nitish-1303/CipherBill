import type { PrivatePaymentRequest, PrivacyTransaction, Strk20Client } from "./types";

const notConfigured = (action: string): never => {
  throw new Error(
    `${action} is not configured. Connect the official STRK20 Privacy SDK and mainnet wallet before submitting transactions.`,
  );
};

/**
 * Production integration boundary for the official STRK20 Privacy SDK.
 * Keeping blockchain calls behind this adapter prevents the UI from claiming
 * privacy guarantees until the live SDK, pool addresses and prover are wired.
 */
export class MainnetStrk20Client implements Strk20Client {
  async shield(_amount: string): Promise<PrivacyTransaction> {
    return notConfigured("Shield");
  }

  async privateTransfer(_request: PrivatePaymentRequest): Promise<PrivacyTransaction> {
    return notConfigured("Private transfer");
  }

  async unshield(_amount: string, _recipient: string): Promise<PrivacyTransaction> {
    return notConfigured("Unshield");
  }
}
