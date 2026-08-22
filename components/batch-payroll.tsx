"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  createShareableBatchInvoice,
  encodeBatchPayload,
  deriveBatchStatus,
  readLocalBatchRecord,
  writeLocalBatchRecord,
  readBatchList,
  writeBatchList,
  type ShareableBatchInvoice,
  type BatchLifecycle,
  type BatchRecipient,
  type LocalBatchRecord,
} from "@/lib/batch-payroll";
import { MainnetStrk20Client } from "@/lib/strk20/client";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { acquireSubmission, releaseSubmission } from "@/lib/strk20/transaction";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

export function BatchPayrollDashboard() {
  const [orgName, setOrgName] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [recipients, setRecipients] = useState<Array<{ name: string; address: string; amount: string; description: string }>>([]);
  const [batchList, setBatchList] = useState<LocalBatchRecord[]>([]);
  const [generatedUrl, setGeneratedUrl] = useState("");
  const [message, setMessage] = useState("Generate private batch dispersal payroll links.");

  useEffect(() => {
    setBatchList(readBatchList());
  }, []);

  function addRecipient() {
    setRecipients([...recipients, { name: "", address: "", amount: "", description: "" }]);
  }

  function updateRecipient(index: number, key: string, value: string) {
    setRecipients(recipients.map((r, i) => (i === index ? { ...r, [key]: value } : r)));
  }

  function removeRecipient(index: number) {
    setRecipients(recipients.filter((_, i) => i !== index));
  }

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    if (!recipients.length) {
      setMessage("Please add at least one recipient.");
      return;
    }
    try {
      const invoice = createShareableBatchInvoice({
        organizationName: orgName,
        tokenAddress: STRK_TOKEN_ADDRESS,
        tokenSymbol: "STRK",
        tokenDecimals: 18,
        recipients: recipients.map((r) => ({
          recipientAddress: r.address,
          amount: r.amount,
          name: r.name,
          description: r.description,
        })),
        expiresAt: new Date(expiresAt).toISOString(),
      });
      const payload = await encodeBatchPayload(invoice);
      const url = `${window.location.origin}/pay/${payload}`;
      const record: LocalBatchRecord = {
        invoice,
        encodedPayload: payload,
        savedAt: new Date().toISOString(),
        lifecycle: { status: "batch_pending", payments: [], updatedAt: new Date().toISOString() },
      };
      const updatedList = [record, ...batchList];
      setBatchList(updatedList);
      writeBatchList(updatedList);
      setGeneratedUrl(url);
      setOrgName("");
      setExpiresAt("");
      setRecipients([]);
      setMessage(`Successfully generated payroll link with ${invoice.recipients.length} recipients!`);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Failed to generate batch payroll.");
    }
  }

  function copyToClipboard(val: string) {
    navigator.clipboard.writeText(val);
    setMessage("Copied to clipboard!");
  }

  return (
    <div className="invoice-grid">
      <form className="invoice-form" onSubmit={handleGenerate}>
        <label>Organization Name
          <input required placeholder="Cipher Corp" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
        </label>
        <label>Expires At
          <input required type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </label>

        <fieldset className="milestone-editor" style={{ marginTop: "16px" }}>
          <legend>Recipients / Contractors</legend>
          {recipients.map((r, index) => (
            <div key={index} style={{ display: "grid", gap: "8px", borderBottom: "1px solid rgba(255,255,255,0.1)", paddingBottom: "12px", marginBottom: "12px" }}>
              <input required placeholder="Contractor Name" value={r.name} onChange={(e) => updateRecipient(index, "name", e.target.value)} />
              <input required placeholder="Starknet Address (0x...)" value={r.address} onChange={(e) => updateRecipient(index, "address", e.target.value)} />
              <input required placeholder="Amount (e.g. 10.5)" value={r.amount} onChange={(e) => updateRecipient(index, "amount", e.target.value)} />
              <input required placeholder="Description (e.g. August retainer)" value={r.description} onChange={(e) => updateRecipient(index, "description", e.target.value)} />
              <button type="button" onClick={() => removeRecipient(index)} style={{ background: "#991b1b" }}>Remove Contractor</button>
            </div>
          ))}
          <button type="button" onClick={addRecipient}>Add Contractor</button>
        </fieldset>

        <button type="submit" style={{ marginTop: "16px", background: "#f59e0b", color: "#1e1b4b" }}>
          Generate Batch Payroll Link
        </button>
        <p className="status">{message}</p>
      </form>

      <div className="invoice-list">
        {generatedUrl && (
          <article className="invoice-item invoice-preview">
            <div><strong>Batch Dispersal Link Ready</strong></div>
            <textarea readOnly value={generatedUrl} rows={4} style={{ width: "100%", marginTop: "8px" }} />
            <div className="invoice-actions" style={{ marginTop: "8px" }}>
              <button type="button" onClick={() => copyToClipboard(generatedUrl)}>Copy Dispersal Link</button>
              <Link className="transaction-link" href={generatedUrl}>Open Dispersal Link</Link>
            </div>
          </article>
        )}

        <div className="history-heading"><strong>Batch Payroll History</strong></div>
        {batchList.length ? batchList.map((record) => {
          const url = `${window.location.origin}/pay/${record.encodedPayload}`;
          const currentLifecycle = readLocalBatchRecord(record.invoice.batchId);
          const status = deriveBatchStatus(record.invoice, currentLifecycle);
          return (
            <article className="invoice-item" key={record.invoice.batchId}>
              <div><strong>{record.invoice.totalAmount} STRK</strong><span>{status.replaceAll("_", " ")}</span></div>
              <p>Org: {record.invoice.organizationName} - {record.invoice.recipients.length} contractors</p>
              <div className="invoice-actions">
                <button type="button" onClick={() => copyToClipboard(url)}>Copy Link</button>
                <Link className="transaction-link" href={url}>Open Execution Screen</Link>
              </div>
            </article>
          );
        }) : <p className="dialog-copy">No local batch records found.</p>}
      </div>
    </div>
  );
}

export function BatchPayrollExecution({ invoice }: { invoice: ShareableBatchInvoice }) {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [lifecycle, setLifecycle] = useState<BatchLifecycle | null>(null);
  const [revealAmountIndex, setRevealAmountIndex] = useState<Record<number, boolean>>({});
  const [message, setMessage] = useState("Execute private contractor payouts securely.");
  const [processingIndex, setProcessingIndex] = useState<number | null>(null);
  const paymentLock = useRef(false);

  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);

  useEffect(() => {
    setLifecycle(readLocalBatchRecord(invoice.batchId));
  }, [invoice.batchId]);

  if (!lifecycle) return <div>Loading payroll data...</div>;

  const currentStatus = deriveBatchStatus(invoice, lifecycle);

  function toggleReveal(index: number) {
    setRevealAmountIndex((prev) => ({ ...prev, [index]: !prev[index] }));
  }

  function persist(next: BatchLifecycle) {
    setLifecycle(next);
    writeLocalBatchRecord(invoice.batchId, next);
  }

  async function executePayout(recipient: BatchRecipient, index: number) {
    if (!account || !walletReady || !lifecycle || !acquireSubmission(paymentLock)) return;
    setProcessingIndex(index);
    setMessage(`Preparing private payout for ${recipient.name}...`);

    try {
      const client = new MainnetStrk20Client(account);
      
      const record = lifecycle.payments.find((p) => p.recipientId === recipient.id);
      if (record && record.status === "confirmed") {
        throw new Error("Payout already confirmed for this recipient.");
      }

      setMessage(`Confirm private transfer of ${recipient.amount} STRK to ${recipient.name} inside your wallet...`);

      const result = await client.privateTransfer({
        recipient: recipient.recipientAddress,
        amount: recipient.amount,
        token: "STRK",
        memo: `Payroll ${invoice.batchId.slice(0, 8)}`,
      });

      if (result.status === "confirmed") {
        const newPayments = [
          ...lifecycle.payments.filter((p) => p.recipientId !== recipient.id),
          {
            recipientId: recipient.id,
            hash: result.hash,
            status: "confirmed" as const,
            submittedAt: result.submittedAt || new Date().toISOString(),
            confirmedAt: new Date().toISOString(),
          },
        ];
        const next: BatchLifecycle = {
          status: deriveBatchStatus(invoice, { ...lifecycle, payments: newPayments }),
          payments: newPayments,
          updatedAt: new Date().toISOString(),
        };
        persist(next);
        setMessage(`Successfully paid ${recipient.name}!`);
      } else {
        throw new Error("Transaction was not confirmed.");
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Payout failed.");
    } finally {
      setProcessingIndex(null);
      releaseSubmission(paymentLock);
    }
  }

  return (
    <main className="pay-page">
      <nav className="pay-nav">
        <Link className="brand" href="/">CB CipherBill</Link>
        <span className="network-badge">Enterprise Payroll Portal</span>
      </nav>
      <section className="pay-shell">
        <div className="pay-heading">
          <span className="eyebrow" style={{ display: "inline-flex", background: "#3b82f6", color: "white", padding: "2px 6px", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "bold" }}>
            👥 Multi-Recipient Payroll
          </span>
          <h1 style={{ marginTop: "12px" }}>{invoice.organizationName}</h1>
          <p>Total payroll: {invoice.totalAmount} STRK | Expires: {new Date(invoice.expiresAt).toLocaleDateString()}</p>
        </div>

        <div className="payment-status-panel">
          <div><span>Payroll Status</span><strong>{currentStatus.replaceAll("_", " ")}</strong></div>
          <div><span>Contractors Paid</span><strong>{lifecycle.payments.filter(p => p.status === "confirmed").length} / {invoice.recipients.length}</strong></div>
        </div>

        <section style={{ marginTop: "24px" }}>
          <h2>Recipient Dispersal Panel</h2>
          <p style={{ fontSize: "0.85rem", opacity: 0.7, marginBottom: "16px" }}>
            Dispersals route through the official STRK20 privacy pool contract (<code>0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a</code>).
          </p>

          <div style={{ display: "grid", gap: "16px" }}>
            {invoice.recipients.map((recipient, idx) => {
              const isPaid = lifecycle.payments.some((p) => p.recipientId === recipient.id && p.status === "confirmed");
              const isRevealed = revealAmountIndex[idx];
              const isProcessing = processingIndex === idx;

              return (
                <div key={recipient.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "8px", padding: "16px", background: "rgba(255,255,255,0.02)" }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: "1rem" }}>{recipient.name}</h3>
                    <code style={{ fontSize: "0.75rem", opacity: 0.6 }}>{recipient.recipientAddress.slice(0, 10)}...{recipient.recipientAddress.slice(-8)}</code>
                    <p style={{ margin: "4px 0 0 0", fontSize: "0.8rem", opacity: 0.8 }}>{recipient.description}</p>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontWeight: "bold", fontSize: "1.1rem" }}>
                        {isRevealed ? `${recipient.amount} STRK` : "•••• STRK"}
                      </div>
                      <button type="button" onClick={() => toggleReveal(idx)} style={{ fontSize: "0.7rem", padding: "2px 6px", background: "none", border: "1px solid rgba(255,255,255,0.3)", borderRadius: "4px", color: "white", cursor: "pointer" }}>
                        {isRevealed ? "Hide Salary" : "Reveal Salary"}
                      </button>
                    </div>

                    {isPaid ? (
                      <span style={{ color: "#4ade80", fontWeight: "bold", fontSize: "0.9rem" }}>✓ Settled</span>
                    ) : (
                      <button type="button" onClick={() => executePayout(recipient, idx)} disabled={!walletReady || isProcessing} style={{ background: isProcessing ? "#f59e0b" : "#2563eb", color: "white", padding: "8px 16px", borderRadius: "6px", border: "none", cursor: "pointer", fontWeight: "bold" }}>
                        {isProcessing ? "Paying..." : "Pay Contractor"}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <div style={{ marginTop: "24px" }}>
          {!walletReady ? (
            <div className="invoice-wallet" style={{ display: "grid", justifyContent: "center" }}>
              <p>Connect your wallet to disburse batch payouts privately.</p>
              <WalletConnect />
            </div>
          ) : null}
          <p className="status" style={{ textAlign: "center", marginTop: "16px" }}>{message}</p>
        </div>
      </section>
    </main>
  );
}
