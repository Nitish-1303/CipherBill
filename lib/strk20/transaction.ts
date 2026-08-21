import type { PrivacyAction, PrivacyTransaction } from "./types";

export interface SubmissionLock {
  current: boolean;
}

interface AwaitSubmittedTransactionOptions<TReceipt> {
  action: PrivacyAction;
  hash: string;
  timeoutMs: number;
  waitForReceipt: () => Promise<TReceipt>;
  isReverted: (receipt: TReceipt) => boolean;
}

export function acquireSubmission(lock: SubmissionLock): boolean {
  if (lock.current) return false;
  lock.current = true;
  return true;
}

export function releaseSubmission(lock: SubmissionLock): void {
  lock.current = false;
}

export async function awaitSubmittedTransaction<TReceipt>({
  action,
  hash,
  timeoutMs,
  waitForReceipt,
  isReverted,
}: AwaitSubmittedTransactionOptions<TReceipt>): Promise<PrivacyTransaction> {
  const submitted: PrivacyTransaction = {
    action,
    hash,
    status: "submitted",
    submittedAt: new Date().toISOString(),
  };

  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    const receipt = await Promise.race([
      waitForReceipt(),
      new Promise<null>((resolve) => {
        timeout = setTimeout(() => resolve(null), timeoutMs);
      }),
    ]);

    if (receipt === null) return submitted;
    if (isReverted(receipt)) {
      return {
        ...submitted,
        status: "failed",
        error: {
          code: "confirmation_failed",
          message: "The submitted mainnet transaction reverted.",
        },
      };
    }

    return { ...submitted, status: "confirmed" };
  } catch {
    return submitted;
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
