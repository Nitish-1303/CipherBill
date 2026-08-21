"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import { createInvoice, Invoice, paymentLink, readInvoices, selectiveReceipt, writeInvoices } from "@/lib/invoices";
import { MainnetStrk20Client } from "@/lib/strk20/client";
import { getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { useWallet } from "./wallet-provider";

const emptyForm = { recipient: "", amount: "", description: "", dueDate: "" };

export function InvoicePanel() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [form, setForm] = useState(emptyForm);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [message, setMessage] = useState("Invoice metadata stays in this browser only.");
  const [settling, setSettling] = useState<string | null>(null);

  useEffect(() => setInvoices(readInvoices()), []);

  const latestInvoice = useMemo(() => invoices[0], [invoices]);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);

  function updateInvoices(next: Invoice[]) {
    setInvoices(next);
    writeInvoices(next);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const invoice = createInvoice({ ...form, token: "STRK" });
      updateInvoices([invoice, ...invoices]);
      setForm(emptyForm);
      setMessage(`Invoice ${invoice.id} created. Share the payment link with the recipient.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invoice could not be created.");
    }
  }

  async function settle(invoice: Invoice) {
    if (!account || !walletReady) {
      setMessage("Connect a compatible Starknet mainnet wallet before settling an invoice.");
      return;
    }

    setSettling(invoice.id);
    try {
      const client = new MainnetStrk20Client(account);
      const fee = await client.getFeeAmount();
      setMessage(`Confirm the private settlement. The recipient must be registered with STRK20. Current pool fee: ${BigInt(fee).toString()} base units.`);
      const transaction = await client.privateTransfer({
        recipient: invoice.recipient,
        amount: invoice.amount,
        token: "STRK",
      });

      const nextStatus: Invoice["status"] = transaction.status === "confirmed"
        ? "paid"
        : transaction.status === "submitted"
          ? "pending"
          : "failed";

      updateInvoices(invoices.map((item) => item.id === invoice.id ? { ...item, status: nextStatus, transactionHash: transaction.hash } : item));

      if (transaction.status === "confirmed") {
        setMessage(`Invoice ${invoice.id} is paid after confirmed settlement.`);
      } else if (transaction.status === "submitted") {
        setMessage(`Invoice ${invoice.id} was submitted, but RPC confirmation is delayed. Keep the explorer link and do not resubmit.`);
      } else {
        setMessage(`Invoice ${invoice.id} settlement reverted. Its transaction hash is preserved.`);
      }
    } catch {
      updateInvoices(invoices.map((item) => item.id === invoice.id ? { ...item, status: "failed" } : item));
      setMessage("Invoice settlement failed or was rejected. The invoice remains available to retry.");
    } finally {
      setSettling(null);
    }
  }

  function downloadReceipt(invoice: Invoice) {
    const blob = new Blob([JSON.stringify(selectiveReceipt(invoice), null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${invoice.id}-receipt.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="invoice-panel" id="invoices">
      <div className="section-heading"><span>Private invoicing</span><h2>Private by default, disclosable when required.</h2></div>
      <div className="invoice-grid">
        <form className="invoice-form" onSubmit={submit}>
          <label>Recipient<input required placeholder="0x..." value={form.recipient} onChange={(event) => setForm({ ...form, recipient: event.target.value })} /></label>
          <label>Amount in STRK<input required inputMode="decimal" placeholder="2.5" value={form.amount} onChange={(event) => setForm({ ...form, amount: event.target.value })} /></label>
          <label>Description<input required placeholder="Design retainer" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></label>
          <label>Due date<input required type="date" value={form.dueDate} onChange={(event) => setForm({ ...form, dueDate: event.target.value })} /></label>
          <button type="submit">Create invoice</button>
          <p className="status">Private settlement requires the recipient to register their wallet with STRK20 first.</p>
        </form>
        <div className="invoice-list">
          <p className="status">{message}</p>
          {latestInvoice ? invoices.map((invoice) => (
            <article className="invoice-item" key={invoice.id}>
              <div><strong>{invoice.amount} STRK</strong><span>{invoice.status}</span></div>
              <p>{invoice.description}</p>
              <small>{invoice.id} · due {invoice.dueDate}</small>
              <div className="invoice-actions">
                <button type="button" onClick={() => navigator.clipboard.writeText(paymentLink(invoice))}>Copy payment link</button>
                {invoice.transactionHash ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(invoice.transactionHash)} target="_blank" rel="noreferrer">View transaction ↗</a> : null}
                {invoice.status === "paid"
                  ? <button type="button" onClick={() => downloadReceipt(invoice)}>Export receipt</button>
                  : invoice.status === "pending"
                    ? <button type="button" disabled>Awaiting confirmation</button>
                    : <button type="button" disabled={!walletReady || settling === invoice.id} onClick={() => settle(invoice)}>{settling === invoice.id ? "Settling..." : "Settle privately"}</button>}
              </div>
            </article>
          )) : <p className="dialog-copy">No invoices yet. Draft metadata is stored locally and contains no keys, notes, proofs, or wallet history.</p>}
        </div>
      </div>
    </section>
  );
}
