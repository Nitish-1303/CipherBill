import { WalletAccountV6, type STRK20_ACTION } from "starknet";

import { getStrk20Config } from "./config";
import { decimalToBaseUnits } from "./validation";
import type {
  PrivatePaymentRequest,
  PrivacyAction,
  PrivacyTransaction,
  ShieldedBalance,
  Strk20Client,
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
    const balance = balances.find((entry) => entry.token.toLowerCase() === config.tokenAddress.toLowerCase());

    return { token: config.tokenAddress, amount: balance?.balance ?? "0" };
  }

  async shield(amount: string): Promise<PrivacyTransaction> {
    return this.invoke("shield", [{ type: "deposit", token: this.requireConfig().tokenAddress, amount: decimalToBaseUnits(amount) }]);
  }

  async privateTransfer(request: PrivatePaymentRequest): Promise<PrivacyTransaction> {
    const config = this.requireConfig();
    return this.invoke("private_transfer", [
      {
        type: "transfer",
        token: config.tokenAddress,
        amount: decimalToBaseUnits(request.amount),
        recipient: request.recipient,
      },
    ]);
  }

  async unshield(amount: string, recipient: string): Promise<PrivacyTransaction> {
    const config = this.requireConfig();
    return this.invoke("unshield", [
      { type: "withdraw", token: config.tokenAddress, amount: decimalToBaseUnits(amount), recipient },
    ]);
  }

  private requireConfig() {
    const config = getStrk20Config();
    if (!config) {
      throw new Error("Mainnet STRK20 configuration is pending verified pool and provider values.");
    }
    return config;
  }

  private async invoke(action: PrivacyAction, actions: STRK20_ACTION[]): Promise<PrivacyTransaction> {
    this.requireConfig();
    const result = await this.account.strk20InvokeTransaction(actions);
    const receipt = await this.account.provider.waitForTransaction(result.transaction_hash, {
      retries: 400,
      retryInterval: 3000,
    });

    if ("execution_status" in receipt && receipt.execution_status === "REVERTED") {
      throw new Error("The mainnet transaction reverted.");
    }

    return {
      action,
      hash: result.transaction_hash,
      status: "confirmed",
      submittedAt: new Date().toISOString(),
    };
  }
}
