import { WalletAccountV6, type STRK20_ACTION } from "starknet";

import { CONFIRMATION_TIMEOUT_MS, getStrk20Config } from "./config";
import { awaitSubmittedTransaction } from "./transaction";
import { areSameStarknetAddress, decimalToBaseUnits, normalizeStarknetAddress } from "./validation";
import type {
  PrivatePaymentRequest,
  PrivacyAction,
  PrivacyTransaction,
  ShieldedBalance,
  Strk20Client,
  TransactionSubmittedCallback,
} from "./types";

/**
 * Production integration boundary for the official STRK20 Privacy SDK.
 * Keeping blockchain calls behind this adapter prevents the UI from claiming
 * privacy guarantees until the live SDK, pool addresses and prover are wired.
 */
export class MainnetStrk20Client implements Strk20Client {
  constructor(private readonly account: WalletAccountV6) {}

  async getBalance(): Promise<ShieldedBalance> {
    const config = this.requireConfig();
    const balances = await this.account.strk20Balances([config.tokenAddress]);
    const balance = balances.find((entry) => areSameStarknetAddress(entry.token, config.tokenAddress));

    return { token: config.tokenAddress, amount: balance?.balance ?? "0" };
  }

  async getFeeAmount(): Promise<string> {
    const config = this.requireConfig();
    const result = await this.account.provider.callContract({
      contractAddress: config.poolAddress,
      entrypoint: "get_fee_amount",
      calldata: [],
    });
    return result[0] ?? "0";
  }

  async shield(amount: string): Promise<PrivacyTransaction> {
    return this.invoke("shield", [{ type: "deposit", token: this.requireConfig().tokenAddress, amount: decimalToBaseUnits(amount) }]);
  }

  async privateTransfer(request: PrivatePaymentRequest, onSubmitted?: TransactionSubmittedCallback): Promise<PrivacyTransaction> {
    const config = this.requireConfig();
    return this.invoke("private_transfer", [
      {
        type: "transfer",
        token: config.tokenAddress,
        amount: decimalToBaseUnits(request.amount),
        recipient: normalizeStarknetAddress(request.recipient),
      },
    ], onSubmitted);
  }

  async unshield(amount: string, recipient: string): Promise<PrivacyTransaction> {
    const config = this.requireConfig();
    return this.invoke("unshield", [
      { type: "withdraw", token: config.tokenAddress, amount: decimalToBaseUnits(amount), recipient: normalizeStarknetAddress(recipient) },
    ]);
  }

  private requireConfig() {
    const config = getStrk20Config();
    if (!config) {
      throw new Error("Mainnet STRK20 configuration is pending verified pool and provider values.");
    }
    return config;
  }

  private async invoke(action: PrivacyAction, actions: STRK20_ACTION[], onSubmitted?: TransactionSubmittedCallback): Promise<PrivacyTransaction> {
    this.requireConfig();
    const result = await this.account.strk20InvokeTransaction(actions);
    const submittedAt = new Date().toISOString();
    onSubmitted?.({ action, hash: result.transaction_hash, status: "submitted", submittedAt });
    return awaitSubmittedTransaction({
      action,
      hash: result.transaction_hash,
      timeoutMs: CONFIRMATION_TIMEOUT_MS,
      submittedAt,
      waitForReceipt: () => this.account.provider.waitForTransaction(result.transaction_hash, {
        retries: 40,
        retryInterval: 3000,
      }),
      isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
    });
  }
}
