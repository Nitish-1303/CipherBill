"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { decodeInvoicePayload, type InvoiceDecodeResult, type ShareableInvoiceV1 } from "@/lib/invoices";
import { MainnetStrk20Client } from "@/lib/strk20/client";
import { getStarknetExplorerTransactionUrl, STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { acquireSubmission, releaseSubmission } from "@/lib/strk20/transaction";
import type { PrivacyTransaction } from "@/lib/strk20/types";
import { areSameStarknetAddress, decimalToBaseUnits } from "@/lib/strk20/validation";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type PaymentPhase = "idle" | "preparing" | "confirming" | "confirmed" | "delayed" | "rejected" | "failed_before_submission" | "reverted";

export function InvoicePayment({ encodedPayload }: Readonly<{ encodedPayload: string }>) {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [decoded, setDecoded] = useState<InvoiceDecodeResult | null>(null);
  const [paymentPhase, setPaymentPhase] = useState<PaymentPhase>("idle");
  const [transaction, setTransaction] = useState<PrivacyTransaction | null>(null);
  const [message, setMessage] = useState("Review every invoice field before connecting a wallet.");
  const paymentLock = useRef(false);

  useEffect(() => {
    let active = true;
    decodeInvoicePayload(encodedPayload).then((result) => {
      if (active) setDecoded(result);
    });
    return () => { active = false; };
  }, [encodedPayload]);

  if (!decoded) return <InvoiceState title="Checking invoice integrity…" message="Validating schema, size, fields, and checksum." />;
  if (decoded.status === "invalid") return <InvoiceState title="Invalid invoice link" message={decoded.message} />;
  if (decoded.status === "expired") return <InvoiceDetails invoice={decoded.invoice} expired message={decoded.message} />;

  const invoice = decoded.invoice;
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const tokenSupported = areSameStarknetAddress(invoice.tokenAddress, STRK_TOKEN_ADDRESS)
    && invoice.tokenSymbol === "STRK"
    && invoice.tokenDecimals === 18;

  async function pay() {
    if (!account || !walletReady || !tokenSupported || !acquireSubmission(paymentLock)) return;
    setPaymentPhase("preparing");
    setMessage("Requesting shielded-balance access to verify the amount and dynamic pool fee.");
    let submitted = false;

    try {
      const client = new MainnetStrk20Client(account);
      const [balance, fee] = await Promise.all([client.getBalance(), client.getFeeAmount()]);
      const amount = BigInt(decimalToBaseUnits(invoice.amount, invoice.tokenDecimals));
      const poolFee = BigInt(fee);
      if (amount + poolFee > BigInt(balance.amount)) {
        setPaymentPhase("failed_before_submission");
        setMessage(`Insufficient shielded STRK for the invoice plus the current pool fee of ${poolFee.toString()} base units.`);
        return;
      }

      setMessage(`Confirm the private transfer in your wallet. Current pool fee: ${poolFee.toString()} base units.`);
      const result = await client.privateTransfer({
        recipient: invoice.recipientAddress,
        amount: invoice.amount,
        token: "STRK",
        memo: invoice.referenceNumber,
      }, (submittedTransaction) => {
        submitted = true;
        setTransaction(submittedTransaction);
        setPaymentPhase("confirming");
        setMessage("Submitted. Confirming on Starknet mainnet; do not submit this invoice again.");
      });

      setTransaction(result);
      if (result.status === "confirmed") {
        setPaymentPhase("confirmed");
        setMessage("Payment confirmed by the configured Starknet RPC.");
      } else if (result.status === "submitted") {
        setPaymentPhase("delayed");
        setMessage("Payment submitted, but confirmation is delayed. The transaction hash is preserved below; do not resubmit.");
      } else {
        setPaymentPhase("reverted");
        setMessage("The submitted payment reverted. The transaction hash is preserved below.");
      }
    } catch (error) {
      if (submitted) {
        setPaymentPhase("delayed");
        setMessage("Payment was submitted, but confirmation could not be observed. Keep the transaction hash and do not resubmit.");
      } else if (isWalletRejection(error)) {
        setPaymentPhase("rejected");
        setMessage("Wallet request rejected. No transaction hash was returned.");
      } else {
        setPaymentPhase("failed_before_submission");
        setMessage("Payment failed before submission. No transaction hash was returned.");
      }
    } finally {
      releaseSubmission(paymentLock);
    }
  }

  return (
    <InvoiceDetails invoice={invoice} message={message}>
      <div className="payment-status-panel" aria-live="polite">
        <div><span>Submission</span><strong>{transaction ? "submitted" : paymentPhase === "rejected" ? "rejected" : "not submitted"}</strong></div>
        <div><span>Confirmation</span><strong>{confirmationLabel(paymentPhase)}</strong></div>
      </div>
      {!tokenSupported ? <p className="error-message">This CipherBill build supports STRK invoices with 18 decimals only. Payment is blocked.</p> : null}
      {!walletReady ? <div className="invoice-wallet"><p>Connect a privacy-enabled wallet on SN_MAIN with Wallet API 0.10.3 or newer.</p><WalletConnect /></div> : null}
      <button className="pay-invoice-button" type="button" onClick={pay} disabled={!walletReady || !tokenSupported || ["preparing", "confirming", "delayed", "confirmed"].includes(paymentPhase)}>
        {paymentPhase === "preparing" ? "Preparing…" : paymentPhase === "confirming" ? "Confirming…" : paymentPhase === "confirmed" ? "Payment confirmed" : paymentPhase === "delayed" ? "Confirmation delayed" : "Pay privately"}
      </button>
      {transaction ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(transaction.hash)} target="_blank" rel="noreferrer">View submitted transaction on Voyager ↗</a> : null}
    </InvoiceDetails>
  );
}

function InvoiceDetails({ invoice, expired = false, message, children }: Readonly<{ invoice: ShareableInvoiceV1; expired?: boolean; message: string; children?: React.ReactNode }>) {
  const [copyMessage, setCopyMessage] = useState("");
  const shortAddress = `${invoice.recipientAddress.slice(0, 8)}…${invoice.recipientAddress.slice(-6)}`;

  async function copyAddress() {
    try {
      await navigator.clipboard.writeText(invoice.recipientAddress);
      setCopyMessage("Merchant address copied.");
    } catch {
      setCopyMessage("Copy unavailable; select the full address below.");
    }
  }

  return (
    <main className="pay-page">
      <nav className="pay-nav"><Link className="brand" href="/"><span>◒</span> CipherBill</Link><span className="network-badge">SN_MAIN · Starknet Mainnet</span></nav>
      <section className="pay-shell">
        <div className="pay-heading"><span className="eyebrow">Invoice {invoice.invoiceId}</span><h1>{invoice.merchantName}</h1><p>{invoice.description}</p></div>
        <div className="invoice-amount"><strong>{invoice.amount}</strong><span>{invoice.tokenSymbol}</span></div>
        <dl className="invoice-facts">
          <div><dt>Merchant address</dt><dd><code title={invoice.recipientAddress}>{shortAddress}</code><button type="button" onClick={copyAddress}>Copy full address</button></dd></div>
          <div><dt>Token</dt><dd>{invoice.tokenSymbol} · {invoice.tokenDecimals} decimals</dd></div>
          <div><dt>Token address</dt><dd><code>{`${invoice.tokenAddress.slice(0, 10)}…${invoice.tokenAddress.slice(-8)}`}</code></dd></div>
          {invoice.referenceNumber ? <div><dt>Reference</dt><dd>{invoice.referenceNumber}</dd></div> : null}
          <div><dt>Created</dt><dd>{new Date(invoice.createdAt).toLocaleString()}</dd></div>
          <div><dt>Expires</dt><dd className={expired ? "expired-text" : ""}>{new Date(invoice.expiresAt).toLocaleString()} · {expired ? "expired" : "payable"}</dd></div>
        </dl>
        {copyMessage ? <p className="status">{copyMessage}</p> : null}
        <p className={expired ? "error-message" : "status"}>{message}</p>
        <aside className="integrity-notice"><strong>Verify the merchant address before paying.</strong><p>This link provides integrity checking, not authenticated merchant identity.</p></aside>
        <aside className="privacy-notice"><strong>Privacy boundary</strong><p>The STRK20 private transfer hides sender, recipient, token, amount, and note linkage inside the pool. This invoice link exposes its encoded fields to anyone who receives it. Application metadata and link sharing are outside STRK20 privacy. Deposits, withdrawals, and timing remain public.</p></aside>
        <p className="status">The merchant must already be registered with STRK20. Only the merchant can register their wallet.</p>
        {!expired ? children : <button type="button" disabled>Invoice expired</button>}
      </section>
    </main>
  );
}

function InvoiceState({ title, message }: Readonly<{ title: string; message: string }>) {
  return <main className="pay-page"><nav className="pay-nav"><Link className="brand" href="/"><span>◒</span> CipherBill</Link></nav><section className="pay-shell empty-pay-state"><div className="eyebrow">Invoice link</div><h1>{title}</h1><p>{message}</p><Link className="secondary" href="/">Return to CipherBill</Link></section></main>;
}

function confirmationLabel(phase: PaymentPhase): string {
  if (phase === "confirming") return "confirming";
  if (phase === "confirmed") return "confirmed";
  if (phase === "delayed") return "confirmation delayed";
  if (phase === "reverted") return "failed / reverted";
  if (phase === "rejected") return "wallet rejected";
  if (phase === "failed_before_submission") return "failed before submission";
  return "not started";
}

function isWalletRejection(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as { code?: unknown; message?: unknown };
  return candidate.code === 4001 || (typeof candidate.message === "string" && /reject|denied|cancel/i.test(candidate.message));
}
