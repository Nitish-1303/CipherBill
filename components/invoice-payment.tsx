"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  describeGaslessPlan,
  GASLESS_LIMITATIONS,
  GASLESS_NOTICE,
  mapWalletGaslessError,
  planGaslessPayment,
} from "@/lib/gasless-relayer";
import {
  confirmInvoicePayment,
  deriveInvoiceStatus,
  failInvoicePayment,
  getInvoiceAccounting,
  getMilestoneAccounting,
  readPayerInvoiceLifecycle,
  submitInvoicePayment,
  validateInvoicePayment,
  writePayerInvoiceLifecycle,
  type InvoiceLifecycle,
} from "@/lib/invoice-lifecycle";
import { decodeInvoicePayload, type InvoiceDecodeResult, type ShareableInvoice } from "@/lib/invoices";
import {
  createSelectiveReceipt,
  DEFAULT_RECEIPT_SELECTION,
  formatPrintableReceipt,
  serializeSelectiveReceipt,
  type ReceiptDisclosureSelection,
} from "@/lib/selective-receipts";
import { MainnetStrk20Client } from "@/lib/strk20/client";
import { getStarknetExplorerTransactionUrl, STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { acquireSubmission, releaseSubmission } from "@/lib/strk20/transaction";
import type { PrivacyTransaction } from "@/lib/strk20/types";
import { areSameStarknetAddress, baseUnitsToDecimal, decimalToBaseUnits, isValidAmount } from "@/lib/strk20/validation";

import { ReputationBadge } from "./reputation-badge";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type PaymentPhase = "idle" | "checking_registration" | "preparing" | "confirming" | "confirmed" | "delayed" | "rejected" | "failed_before_submission" | "reverted";

const receiptFieldLabels: Record<keyof ReceiptDisclosureSelection, string> = {
  merchantName: "Merchant name",
  recipientAddress: "Merchant address",
  amount: "Amount and token",
  milestone: "Milestone",
  description: "Description",
  referenceNumber: "Reference number",
  transactionHash: "Transaction hash",
  timestamps: "Submission timestamps",
};

export function InvoicePayment({
  encodedPayload,
  ephemeralBanner,
  onPaymentSubmitted,
  onPaymentConfirmed,
  onPaymentFailed,
}: Readonly<{
  encodedPayload: string;
  ephemeralBanner?: React.ReactNode;
  onPaymentSubmitted?: (transactionHash: string) => void;
  onPaymentConfirmed?: (transactionHash: string) => void;
  onPaymentFailed?: (transactionHash: string) => void;
}>) {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [decoded, setDecoded] = useState<InvoiceDecodeResult | null>(null);
  const [lifecycle, setLifecycle] = useState<InvoiceLifecycle | null>(null);
  const [selectedMilestoneId, setSelectedMilestoneId] = useState("");
  const [paymentAmount, setPaymentAmount] = useState("");
  const [paymentPhase, setPaymentPhase] = useState<PaymentPhase>("idle");
  const [gaslessRelayed, setGaslessRelayed] = useState(true);
  const [transaction, setTransaction] = useState<PrivacyTransaction | null>(null);
  const [message, setMessage] = useState("Review every invoice field before connecting a wallet.");
  const [receiptSelection, setReceiptSelection] = useState(DEFAULT_RECEIPT_SELECTION);
  const [receiptGeneratedAt, setReceiptGeneratedAt] = useState(() => new Date());
  const [receiptMessage, setReceiptMessage] = useState("");
  const paymentLock = useRef(false);

  useEffect(() => {
    let active = true;
    setDecoded(null);
    setLifecycle(null);
    decodeInvoicePayload(encodedPayload).then((result) => {
      if (!active) return;
      setDecoded(result);
      if (result.status !== "valid") return;
      const storedLifecycle = readPayerInvoiceLifecycle(result.invoice.invoiceId);
      setLifecycle(storedLifecycle);
      setPaymentTarget(result.invoice, storedLifecycle, setSelectedMilestoneId, setPaymentAmount);
      const pending = [...storedLifecycle.payments].reverse().find((payment) => payment.status === "submitted");
      if (pending) {
        setTransaction({ action: "private_transfer", hash: pending.hash, status: "submitted", submittedAt: pending.submittedAt });
        setPaymentPhase("delayed");
        setMessage("A payment from this browser is already submitted. Verify its saved hash before attempting any further payment.");
      }
    });
    return () => { active = false; };
  }, [encodedPayload]);

  if (!decoded) return <InvoiceState title="Checking invoice integrity..." message="Validating schema, size, fields, and checksum." />;
  if (decoded.status === "invalid") return <InvoiceState title="Invalid invoice link" message={decoded.message} />;
  if (decoded.status === "expired") return <InvoiceDetails invoice={decoded.invoice} expired message={decoded.message} />;
  if (!lifecycle) return <InvoiceState title="Loading invoice" message="Restoring this browser's local payment state." />;

  const invoice = decoded.invoice;
  const currentLifecycle = lifecycle;
  const accounting = getInvoiceAccounting(invoice, currentLifecycle);
  const lifecycleStatus = deriveInvoiceStatus(invoice, currentLifecycle);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const tokenSupported = areSameStarknetAddress(invoice.tokenAddress, STRK_TOKEN_ADDRESS)
    && invoice.tokenSymbol === "STRK"
    && invoice.tokenDecimals === 18;
  const paymentError = getPaymentValidationError(invoice, currentLifecycle, paymentAmount, selectedMilestoneId);
  const acceptingPayments = ["active", "partially_paid"].includes(lifecycleStatus);
  const paymentInFlight = ["checking_registration", "preparing", "confirming", "delayed"].includes(paymentPhase);
  const latestReceiptPayment = [...currentLifecycle.payments].reverse().find((payment) => payment.status !== "failed");
  const receipt = latestReceiptPayment
    ? createSelectiveReceipt(invoice, latestReceiptPayment, receiptSelection, receiptGeneratedAt)
    : null;
  const receiptJson = receipt ? serializeSelectiveReceipt(receipt) : "";

  function persist(next: InvoiceLifecycle): void {
    setLifecycle(next);
    if (!writePayerInvoiceLifecycle(invoice.invoiceId, next)) {
      setMessage("Payment state changed, but this browser could not persist local lifecycle data. Keep the transaction hash.");
    }
  }

  function chooseMilestone(milestoneId: string): void {
    setSelectedMilestoneId(milestoneId);
    if (!milestoneId) {
      setPaymentAmount("");
      return;
    }
    const milestoneAccounting = getMilestoneAccounting(invoice, currentLifecycle, milestoneId);
    setPaymentAmount(baseUnitsToDecimal(milestoneAccounting.remainingBaseUnits - milestoneAccounting.pendingBaseUnits, invoice.tokenDecimals));
  }

  async function pay(): Promise<void> {
    if (!account || !walletReady || !tokenSupported || paymentError || !acquireSubmission(paymentLock)) return;
    setPaymentPhase("checking_registration");
    setMessage("Verifying merchant registration with the official STRK20 pool contract...");
    let submittedLifecycle: InvoiceLifecycle | null = null;

    try {
      const amountBaseUnits = decimalToBaseUnits(paymentAmount, invoice.tokenDecimals);
      validateInvoicePayment(invoice, currentLifecycle, {
        amountBaseUnits,
        milestoneId: selectedMilestoneId || undefined,
      });

      const client = new MainnetStrk20Client(account);

      // Check recipient registration status
      try {
        await client.getBalance(); // This validates STRK20 capability
        setMessage("Merchant appears registered. Proceeding with payment preparation...");
      } catch {
        setPaymentPhase("failed_before_submission");
        setMessage("Unable to verify STRK20 pool access. Ensure your wallet supports STRK20 operations and the merchant is registered.");
        return;
      }

      setPaymentPhase("preparing");
      const token = { symbol: invoice.tokenSymbol, decimals: invoice.tokenDecimals };

      if (gaslessRelayed) {
        // Gasless preflight. The relayer fee is withdrawn from the same shielded balance
        // this payment spends, so a balance covering only the payment is still short. The
        // wallet would reject it with INSUFFICIENT_PRIVATE_BALANCE after the payer has
        // already sat through proof generation; reserving for it here fails fast instead.
        setMessage("Reading your shielded balance and the current pool fee, so the relayer fee is reserved before you sign anything.");
        const [balance, fee] = await Promise.all([client.getBalance(), client.getFeeAmount()]);
        const plan = planGaslessPayment({
          paymentBaseUnits: amountBaseUnits,
          shieldedBalanceBaseUnits: balance.amount,
          relayerFeeBaseUnits: fee,
        });

        if (!plan.sufficient) {
          setPaymentPhase("failed_before_submission");
          setMessage(describeGaslessPlan(plan, token));
          return;
        }

        setMessage(`${describeGaslessPlan(plan, token)} Confirm the private transfer in your wallet.`);
      } else {
        // Direct submission. Still relayed, still no public gas token needed - the only
        // difference is that CipherBill does not read the fee first, so the wallet is the
        // one that reports a shortfall.
        setMessage(`Submitting directly to the official pool ${STRK20_POOL_ADDRESS.slice(0, 10)}... without a local fee-reserve check. Your wallet will report a shortfall itself if your shielded balance cannot cover this payment plus the relayer fee it withdraws. Confirm the private transfer in your wallet.`);
      }

      const result = await client.privateTransfer({
        recipient: invoice.recipientAddress,
        amount: paymentAmount,
        token: "STRK",
        memo: invoice.referenceNumber,
      }, (submittedTransaction) => {
        submittedLifecycle = submitInvoicePayment(invoice, currentLifecycle, {
          hash: submittedTransaction.hash,
          amountBaseUnits,
          milestoneId: selectedMilestoneId || undefined,
          submittedAt: submittedTransaction.submittedAt,
        });
        persist(submittedLifecycle);
        setTransaction(submittedTransaction);
        setReceiptGeneratedAt(new Date());
        setPaymentPhase("confirming");
        setMessage("Submitted to official STRK20 pool. Confirming on Starknet mainnet; do not submit this invoice again. Hash is immutably retained.");
        onPaymentSubmitted?.(submittedTransaction.hash);
      });

      setTransaction(result);
      if (!submittedLifecycle) throw new Error("The wallet returned without a recorded submission.");
      if (result.status === "confirmed") {
        const confirmed = confirmInvoicePayment(invoice, submittedLifecycle, result.hash);
        persist(confirmed);
        setReceiptGeneratedAt(new Date());
        setPaymentPhase("confirmed");
        setMessage("Payment confirmed by the configured Starknet RPC. Transaction hash is immutably retained for receipt generation.");
        setPaymentTarget(invoice, confirmed, setSelectedMilestoneId, setPaymentAmount);
        onPaymentConfirmed?.(result.hash);
      } else if (result.status === "submitted") {
        setPaymentPhase("delayed");
        setMessage("Payment submitted to official pool, but confirmation is delayed. The transaction hash is immutably preserved below; do not resubmit.");
      } else {
        const failed = failInvoicePayment(invoice, submittedLifecycle, result.hash);
        persist(failed);
        setPaymentPhase("reverted");
        setMessage("The submitted payment reverted. The transaction hash is immutably preserved below and the unpaid balance is available again.");
        onPaymentFailed?.(result.hash);
      }
    } catch (error) {
      if (submittedLifecycle) {
        setPaymentPhase("delayed");
        setMessage("Payment was submitted to official pool, but confirmation could not be observed. Transaction hash is immutably retained; do not resubmit.");
      } else if (isWalletRejection(error)) {
        setPaymentPhase("rejected");
        setMessage("Wallet request rejected. No transaction hash was returned.");
      } else {
        // Documented STRK20 wallet failures get their own explanation; anything else keeps
        // its own message, which is usually a local validation error worth reading verbatim.
        const explained = mapWalletGaslessError(error);
        setPaymentPhase("failed_before_submission");
        setMessage(explained.code === "UNKNOWN_ERROR"
          ? (error instanceof Error ? error.message : explained.message)
          : explained.message);
      }
    } finally {
      releaseSubmission(paymentLock);
    }
  }

  async function copyReceipt(): Promise<void> {
    try {
      await navigator.clipboard.writeText(receiptJson);
      setReceiptMessage("Selective receipt copied.");
    } catch {
      setReceiptMessage("Copy unavailable. Select the receipt JSON manually.");
    }
  }

  function downloadReceipt(): void {
    if (!receipt) return;
    const url = URL.createObjectURL(new Blob([receiptJson], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cipherbill-${invoice.invoiceId}-${latestReceiptPayment?.hash.slice(2, 10) ?? "receipt"}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    setReceiptMessage("Selective receipt JSON download started.");
  }

  function downloadPrintableReceipt(): void {
    if (!receipt) return;
    const printable = formatPrintableReceipt(receipt);
    const url = URL.createObjectURL(new Blob([printable], { type: "text/plain" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cipherbill-${invoice.invoiceId}-${latestReceiptPayment?.hash.slice(2, 10) ?? "receipt"}.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
    setReceiptMessage("Printable receipt download started.");
  }

  return (
    <InvoiceDetails invoice={invoice} lifecycle={currentLifecycle} message={message}>
      {ephemeralBanner}
      <section className="invoice-payment-controls" aria-labelledby="payment-heading">
        <h2 id="payment-heading">Choose this payment</h2>
        {invoice.milestones?.length ? (
          <label>Milestone
            <select value={selectedMilestoneId} onChange={(event) => chooseMilestone(event.target.value)} disabled={!acceptingPayments}>
              <option value="">Select a milestone</option>
              {invoice.milestones.map((milestone) => {
                const milestoneAccounting = getMilestoneAccounting(invoice, currentLifecycle, milestone.id);
                const available = milestoneAccounting.remainingBaseUnits - milestoneAccounting.pendingBaseUnits;
                return <option value={milestone.id} key={milestone.id} disabled={available <= 0n}>{milestone.label} - {baseUnitsToDecimal(available, invoice.tokenDecimals)} {invoice.tokenSymbol} remaining</option>;
              })}
            </select>
          </label>
        ) : null}
        <label>Payment amount
          <input
            inputMode="decimal"
            value={paymentAmount}
            onChange={(event) => setPaymentAmount(event.target.value)}
            readOnly={!invoice.allowPartialPayments}
            disabled={!acceptingPayments}
          />
        </label>
        <p className="status">{invoice.allowPartialPayments ? "A smaller positive amount is allowed up to the selected balance." : invoice.milestones?.length ? "Each milestone is paid at its exact remaining balance." : "This invoice requires its exact remaining balance."}</p>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={gaslessRelayed}
            onChange={(event) => setGaslessRelayed(event.target.checked)}
            disabled={!acceptingPayments || paymentInFlight}
          />
          Pay Gasless (Relayed)
        </label>
        <p className="status">
          {gaslessRelayed
            ? "On: CipherBill reads the current pool fee and reserves it from your shielded balance before you sign, so a payment is not rejected after proving for a shortfall it could have predicted."
            : "Off: CipherBill skips that local check and submits directly. The payment is still relayed and still needs no public gas token - your wallet reports any shortfall itself."}
        </p>
        {paymentError && acceptingPayments ? <p className="error-message">{paymentError}</p> : null}
      </section>

      <div className="payment-status-panel" aria-live="polite">
        <div><span>Lifecycle State</span><strong>{formatStatus(lifecycleStatus)}</strong></div>
        <div><span>Total Invoice</span><strong>{baseUnitsToDecimal(accounting.totalBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</strong></div>
        <div><span>Confirmed</span><strong>{baseUnitsToDecimal(accounting.confirmedBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</strong></div>
        <div><span>Pending</span><strong>{baseUnitsToDecimal(accounting.pendingBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</strong></div>
        <div><span>Remaining</span><strong>{baseUnitsToDecimal(accounting.remainingBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</strong></div>
      </div>
      {currentLifecycle.payments.length > 0 ? (
        <section className="payment-history" aria-labelledby="history-heading">
          <h3 id="history-heading">Payment History (Immutably Retained)</h3>
          <p className="status">Transaction hashes are permanently retained in this browser for receipt generation and dispute resolution.</p>
          {[...currentLifecycle.payments].reverse().map((payment, index) => (
            <div key={payment.hash} className={`payment-record payment-${payment.status}`}>
              <div className="payment-header">
                <span className="payment-number">Payment {currentLifecycle.payments.length - index}</span>
                <span className={`payment-badge payment-badge-${payment.status}`}>{payment.status}</span>
              </div>
              <div className="payment-details">
                <div><strong>Amount:</strong> {baseUnitsToDecimal(payment.amountBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</div>
                {payment.milestoneId ? <div><strong>Milestone:</strong> {invoice.milestones?.find(m => m.id === payment.milestoneId)?.label || payment.milestoneId}</div> : null}
                <div><strong>Hash:</strong> <code>{payment.hash.slice(0, 10)}...{payment.hash.slice(-8)}</code></div>
                <div><strong>Submitted:</strong> {new Date(payment.submittedAt).toLocaleString()}</div>
                {payment.confirmedAt ? <div><strong>Confirmed:</strong> {new Date(payment.confirmedAt).toLocaleString()}</div> : null}
                <a href={getStarknetExplorerTransactionUrl(payment.hash)} target="_blank" rel="noreferrer" className="transaction-link">View on Voyager</a>
              </div>
            </div>
          ))}
        </section>
      ) : null}
      {!tokenSupported ? <p className="error-message">This CipherBill build supports STRK invoices with 18 decimals only. Payment is blocked.</p> : null}
      {!walletReady ? <div className="invoice-wallet"><p>Connect a privacy-enabled wallet on SN_MAIN with Wallet API 0.10.3 or newer.</p><WalletConnect /></div> : null}
      <button className="pay-invoice-button" type="button" onClick={pay} disabled={!walletReady || !tokenSupported || !acceptingPayments || Boolean(paymentError) || paymentInFlight}>
        {paymentPhase === "checking_registration" ? "Verifying registration..." : paymentPhase === "preparing" ? "Preparing..." : paymentPhase === "confirming" ? "Confirming..." : paymentPhase === "delayed" ? "Confirmation delayed" : lifecycleStatus === "paid" ? "Invoice paid" : gaslessRelayed ? "Pay privately (gasless)" : "Pay privately"}
      </button>
      {transaction ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(transaction.hash)} target="_blank" rel="noreferrer">View submitted transaction on Voyager</a> : null}

      {/*
        Rendered whether or not the toggle is on. A payer who switches it off has not opted
        out of relaying - relaying is how the STRK20 wallet method works - so the wording
        that explains what "gasless" costs and who submits has to be visible either way.
      */}
      <div className="privacy-notice">
        <strong>What &ldquo;gasless&rdquo; means here</strong>
        <p>{GASLESS_NOTICE}</p>
        {GASLESS_LIMITATIONS.map((limitation) => <p key={limitation}>&middot; {limitation}</p>)}
      </div>

      {receipt ? (
        <section className="receipt-builder" aria-labelledby="receipt-heading">
          <div><span className="eyebrow">Selective disclosure</span><h2 id="receipt-heading">Build a minimal receipt</h2></div>
          <p>Choose each field deliberately. CipherBill never adds a payer address, viewing key, note data, proof, or complete wallet history.</p>
          <div className="receipt-options">
            {(Object.keys(receiptFieldLabels) as Array<keyof ReceiptDisclosureSelection>).map((field) => (
              <label key={field}><input type="checkbox" checked={receiptSelection[field]} onChange={(event) => setReceiptSelection({ ...receiptSelection, [field]: event.target.checked })} />{receiptFieldLabels[field]}</label>
            ))}
          </div>
          <textarea aria-label="Selective receipt JSON" readOnly value={receiptJson} rows={14} />
          <div className="invoice-actions"><button type="button" onClick={copyReceipt}>Copy receipt</button><button type="button" onClick={downloadReceipt}>Download JSON</button><button type="button" onClick={downloadPrintableReceipt}>Download printable</button></div>
          <p className="status" role="status">{receiptMessage || receipt.notice}</p>
        </section>
      ) : null}
    </InvoiceDetails>
  );
}

function InvoiceDetails({
  invoice,
  lifecycle,
  expired = false,
  message,
  children,
}: Readonly<{
  invoice: ShareableInvoice;
  lifecycle?: InvoiceLifecycle;
  expired?: boolean;
  message: string;
  children?: React.ReactNode;
}>) {
  const [copyMessage, setCopyMessage] = useState("");
  const shortAddress = `${invoice.recipientAddress.slice(0, 8)}...${invoice.recipientAddress.slice(-6)}`;

  async function copyAddress(): Promise<void> {
    try {
      await navigator.clipboard.writeText(invoice.recipientAddress);
      setCopyMessage("Merchant address copied.");
    } catch {
      setCopyMessage("Copy unavailable; select the full address below.");
    }
  }

  return (
    <main className="pay-page">
      <nav className="pay-nav"><Link className="brand" href="/"><span aria-hidden="true">CB</span> CipherBill</Link><span className="network-badge">SN_MAIN - Starknet Mainnet</span></nav>
      <section className="pay-shell">
        <div className="pay-heading"><span className="eyebrow">Invoice {invoice.invoiceId}</span><h1>{invoice.merchantName}</h1><p>{invoice.description}</p></div>
        <div className="reputation-public-row"><span>Verify merchant reliability before payment</span><ReputationBadge context="public" merchantAddress={invoice.recipientAddress} attestation={invoice.reputationProof} /></div>
        <div className="invoice-amount"><strong>{invoice.amount}</strong><span>{invoice.tokenSymbol}</span></div>
        <dl className="invoice-facts">
          <div><dt>Merchant address</dt><dd><code title={invoice.recipientAddress}>{shortAddress}</code><button type="button" onClick={copyAddress}>Copy full address</button></dd></div>
          <div><dt>Token</dt><dd>{invoice.tokenSymbol} - {invoice.tokenDecimals} decimals</dd></div>
          <div><dt>Token address</dt><dd><code>{`${invoice.tokenAddress.slice(0, 10)}...${invoice.tokenAddress.slice(-8)}`}</code></dd></div>
          {invoice.referenceNumber ? <div><dt>Reference</dt><dd>{invoice.referenceNumber}</dd></div> : null}
          <div><dt>Payment policy</dt><dd>{invoice.allowPartialPayments ? "Partial payments allowed" : invoice.milestones?.length ? "Exact milestone installments" : "Exact total only"}</dd></div>
          <div><dt>Created</dt><dd>{new Date(invoice.createdAt).toLocaleString()}</dd></div>
          <div><dt>Expires</dt><dd className={expired ? "expired-text" : ""}>{new Date(invoice.expiresAt).toLocaleString()} - {expired ? "expired" : "payable"}</dd></div>
        </dl>
        {invoice.milestones?.length ? (
          <section className="milestone-summary" aria-labelledby="milestone-heading">
            <h2 id="milestone-heading">Milestones</h2>
            {invoice.milestones.map((milestone) => {
              const progress = lifecycle ? getMilestoneAccounting(invoice, lifecycle, milestone.id) : null;
              return <div key={milestone.id}><span>{milestone.label}</span><strong>{milestone.amount} {invoice.tokenSymbol}</strong>{progress ? <small>{baseUnitsToDecimal(progress.confirmedBaseUnits, invoice.tokenDecimals)} confirmed</small> : null}</div>;
            })}
          </section>
        ) : null}
        {copyMessage ? <p className="status">{copyMessage}</p> : null}
        <p className={expired ? "error-message" : "status"}>{message}</p>
        <aside className="integrity-notice"><strong>Verify the merchant address before paying.</strong><p>The checksum detects accidental or malicious edits to this payload, but it is not merchant authentication or a signature.</p></aside>
        <aside className="privacy-preview">
          <strong>Privacy preview</strong>
          <div className="privacy-preview-grid">
            <div><span>Visible in this link</span><p>Merchant identity and address, token, amount, description, reference, milestones, dates, payment policy, and any attached public reputation attestation.</p></div>
            <div><span>Hidden in a private transfer</span><p>In-pool sender, recipient, token, amount, spent-note linkage, and encrypted note values.</p></div>
            <div><span>Still public or observable</span><p>Deposits, withdrawals, timing, fees, nullifiers, open-note values, this app&apos;s metadata, and distinctive-activity correlation.</p></div>
          </div>
        </aside>
        <p className="status">The merchant must already be registered with STRK20. Only the merchant can register their wallet. Portable links cannot be remotely revoked or synchronized without a shared backend, and this browser&apos;s lifecycle is local metadata.</p>
        {!expired ? children : <button type="button" disabled>Invoice expired</button>}
      </section>
    </main>
  );
}

function InvoiceState({ title, message }: Readonly<{ title: string; message: string }>) {
  return <main className="pay-page"><nav className="pay-nav"><Link className="brand" href="/"><span aria-hidden="true">CB</span> CipherBill</Link></nav><section className="pay-shell empty-pay-state"><div className="eyebrow">Invoice link</div><h1>{title}</h1><p>{message}</p><Link className="secondary" href="/">Return to CipherBill</Link></section></main>;
}

function getPaymentValidationError(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  amount: string,
  milestoneId: string,
): string | null {
  if (!isValidAmount(amount)) return "Enter a positive payment amount with no more than 18 decimals.";
  try {
    validateInvoicePayment(invoice, lifecycle, {
      amountBaseUnits: decimalToBaseUnits(amount, invoice.tokenDecimals),
      milestoneId: milestoneId || undefined,
    });
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : "This payment selection is invalid.";
  }
}

function setPaymentTarget(
  invoice: ShareableInvoice,
  lifecycle: InvoiceLifecycle,
  setMilestoneId: (value: string) => void,
  setAmount: (value: string) => void,
): void {
  if (invoice.milestones?.length) {
    const milestone = invoice.milestones.find((candidate) => {
      const accounting = getMilestoneAccounting(invoice, lifecycle, candidate.id);
      return accounting.remainingBaseUnits - accounting.pendingBaseUnits > 0n;
    });
    setMilestoneId(milestone?.id ?? "");
    if (!milestone) {
      setAmount("");
      return;
    }
    const accounting = getMilestoneAccounting(invoice, lifecycle, milestone.id);
    setAmount(baseUnitsToDecimal(accounting.remainingBaseUnits - accounting.pendingBaseUnits, invoice.tokenDecimals));
    return;
  }
  const accounting = getInvoiceAccounting(invoice, lifecycle);
  setMilestoneId("");
  setAmount(baseUnitsToDecimal(accounting.remainingBaseUnits - accounting.pendingBaseUnits, invoice.tokenDecimals));
}

function formatStatus(status: string): string {
  return status.replaceAll("_", " ");
}

function isWalletRejection(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as { code?: unknown; message?: unknown };
  return candidate.code === 4001 || (typeof candidate.message === "string" && /reject|denied|cancel/i.test(candidate.message));
}
