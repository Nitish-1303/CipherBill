"use client";

import { FormEvent, useEffect, useState } from "react";

import {
  createShareableInvoice,
  encodeInvoicePayload,
  invoicePaymentUrl,
  type LocalInvoiceRecord,
  readInvoices,
  writeInvoices,
} from "@/lib/invoices";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";

const emptyForm = {
  merchantName: "",
  recipientAddress: "",
  amount: "",
  description: "",
  referenceNumber: "",
  expiresAt: "",
};

interface GeneratedInvoice {
  record: LocalInvoiceRecord;
  url: string;
}

export function InvoicePanel() {
  const [form, setForm] = useState(emptyForm);
  const [invoices, setInvoices] = useState<LocalInvoiceRecord[]>([]);
  const [generated, setGenerated] = useState<GeneratedInvoice | null>(null);
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState("Create a self-contained link that can be opened on another device.");

  useEffect(() => setInvoices(readInvoices()), []);

  function persist(next: LocalInvoiceRecord[]) {
    setInvoices(next);
    if (!writeInvoices(next)) setMessage("Invoice created, but local history is unavailable in this browser.");
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (creating) return;
    setCreating(true);

    try {
      const invoice = createShareableInvoice({
        merchantName: form.merchantName,
        recipientAddress: form.recipientAddress,
        tokenAddress: STRK_TOKEN_ADDRESS,
        tokenSymbol: "STRK",
        tokenDecimals: 18,
        amount: form.amount,
        description: form.description,
        referenceNumber: form.referenceNumber || undefined,
        expiresAt: new Date(form.expiresAt).toISOString(),
      });
      const encodedPayload = await encodeInvoicePayload(invoice);
      const record: LocalInvoiceRecord = { invoice, encodedPayload, savedAt: new Date().toISOString() };
      const url = invoicePaymentUrl(encodedPayload);
      persist([record, ...invoices]);
      setGenerated({ record, url });
      setForm(emptyForm);
      setMessage(`Invoice ${invoice.invoiceId} created. Verify the URL preview before sharing it.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invoice could not be created.");
    } finally {
      setCreating(false);
    }
  }

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage("Invoice link copied.");
    } catch {
      setMessage("Copy was unavailable. Select and copy the URL manually.");
    }
  }

  function removeInvoice(invoiceId: string) {
    if (!window.confirm(`Delete local history for ${invoiceId}? This does not cancel the shared link.`)) return;
    const next = invoices.filter((record) => record.invoice.invoiceId !== invoiceId);
    persist(next);
    if (generated?.record.invoice.invoiceId === invoiceId) setGenerated(null);
    setMessage("Local invoice history entry deleted. Any previously shared link still works until expiration.");
  }

  function clearHistory() {
    if (!invoices.length || !window.confirm("Clear all local invoice history? Shared links will not be revoked.")) return;
    persist([]);
    setGenerated(null);
    setMessage("Local invoice history cleared. Shared links remain independent of this browser.");
  }

  return (
    <section className="invoice-panel" id="invoices">
      <div className="section-heading"><span>Shareable invoicing</span><h2>Create once. Pay privately from another device.</h2></div>
      <div className="invoice-grid">
        <form className="invoice-form" onSubmit={submit} aria-busy={creating}>
          <label>Merchant display name<input required maxLength={80} placeholder="Cipher Studio" value={form.merchantName} onChange={(event) => setForm({ ...form, merchantName: event.target.value })} /></label>
          <label>Merchant Starknet address<input required maxLength={66} placeholder="0x..." value={form.recipientAddress} onChange={(event) => setForm({ ...form, recipientAddress: event.target.value })} /></label>
          <div className="form-row">
            <label>Amount<input required inputMode="decimal" maxLength={96} placeholder="2.5" value={form.amount} onChange={(event) => setForm({ ...form, amount: event.target.value })} /></label>
            <label>Token<input value="STRK · 18 decimals" readOnly /></label>
          </div>
          <label>Description<input required maxLength={160} placeholder="Design retainer" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></label>
          <label>Reference number (optional)<input maxLength={64} placeholder="PO-1042" value={form.referenceNumber} onChange={(event) => setForm({ ...form, referenceNumber: event.target.value })} /></label>
          <label>Expires at<input required type="datetime-local" value={form.expiresAt} onChange={(event) => setForm({ ...form, expiresAt: event.target.value })} /></label>
          <button type="submit" disabled={creating}>{creating ? "Generating..." : "Generate private payment link"}</button>
          <p className="status">Network: SN_MAIN · Token address and payment amount are locked into the link.</p>
          <p className="status">Never put private keys, seed phrases, viewing keys, RPC keys, or confidential notes in invoice fields.</p>
        </form>

        <div className="invoice-list">
          <p className="status" role="status">{message}</p>
          {generated ? (
            <article className="invoice-item invoice-preview">
              <div><strong>Generated link</strong><span>schema v{generated.record.invoice.version}</span></div>
              <p>{generated.record.invoice.amount} {generated.record.invoice.tokenSymbol} for {generated.record.invoice.merchantName}</p>
              <textarea aria-label="Generated invoice URL" readOnly value={generated.url} rows={5} />
              <div className="invoice-actions">
                <button type="button" onClick={() => copy(generated.url)}>Copy link</button>
                <a className="transaction-link" href={generated.url}>Open invoice →</a>
              </div>
              <small>Integrity checksum included. This is not a merchant signature.</small>
            </article>
          ) : null}

          <div className="history-heading"><strong>Local history</strong><button type="button" onClick={clearHistory} disabled={!invoices.length}>Clear history</button></div>
          <p className="status">Local history is demo convenience only. It is not proof of payment or on-chain confirmation.</p>
          {invoices.length ? invoices.map((record) => {
            const url = invoicePaymentUrl(record.encodedPayload);
            return (
              <article className="invoice-item" key={record.invoice.invoiceId}>
                <div><strong>{record.invoice.amount} {record.invoice.tokenSymbol}</strong><span>created</span></div>
                <p>{record.invoice.description}</p>
                <small>{record.invoice.invoiceId} · expires {new Date(record.invoice.expiresAt).toLocaleString()}</small>
                <div className="invoice-actions">
                  <button type="button" onClick={() => copy(url)}>Copy link</button>
                  <a className="transaction-link" href={url}>Open</a>
                  <button type="button" onClick={() => removeInvoice(record.invoice.invoiceId)}>Delete local entry</button>
                </div>
              </article>
            );
          }) : <p className="dialog-copy">No local invoices. Shared links do not depend on this list.</p>}
        </div>
      </div>
    </section>
  );
}
