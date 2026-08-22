"use client";

import { FormEvent, useEffect, useState } from "react";

import { activateInvoice, cancelInvoice, createInvoiceLifecycle, deriveInvoiceStatus } from "@/lib/invoice-lifecycle";
import {
  createShareableInvoice,
  encodeInvoicePayload,
  invoicePaymentUrl,
  type LocalInvoiceRecord,
  type ShareableInvoice,
  readInvoices,
  writeInvoices,
} from "@/lib/invoices";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";

import { EphemeralLinkGenerator } from "./ephemeral-badge";

const emptyForm = {
  merchantName: "",
  recipientAddress: "",
  amount: "",
  description: "",
  referenceNumber: "",
  expiresAt: "",
  ephemeral: false,
  allowPartialPayments: false,
  milestones: [] as Array<{ id: string; label: string; amount: string }>,
};

interface GeneratedInvoice {
  record: LocalInvoiceRecord;
  url: string;
}

export function InvoicePanel() {
  const [form, setForm] = useState(emptyForm);
  const [invoices, setInvoices] = useState<LocalInvoiceRecord[]>([]);
  const [generated, setGenerated] = useState<GeneratedInvoice | null>(null);
  const [ephemeralInvoice, setEphemeralInvoice] = useState<ShareableInvoice | null>(null);
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
      const submitter = (event.nativeEvent as SubmitEvent).submitter;
      const saveAsDraft = submitter instanceof HTMLButtonElement && submitter.value === "draft";
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
        allowPartialPayments: form.ephemeral ? false : form.allowPartialPayments,
        milestones: !form.ephemeral && form.milestones.length ? form.milestones : undefined,
      });
      if (form.ephemeral) {
        if (saveAsDraft) throw new Error("Ephemeral invoices cannot be drafts because their capability key is generated only once.");
        setEphemeralInvoice(invoice);
        setGenerated(null);
        setForm(emptyForm);
        setMessage(`Encrypting one-time invoice ${invoice.invoiceId}. It will not be written to ordinary local invoice history.`);
        return;
      }
      const encodedPayload = await encodeInvoicePayload(invoice);
      const record: LocalInvoiceRecord = {
        invoice,
        encodedPayload,
        savedAt: new Date().toISOString(),
        lifecycle: createInvoiceLifecycle(saveAsDraft ? "draft" : "active"),
      };
      const url = invoicePaymentUrl(encodedPayload);
      persist([record, ...invoices]);
      setEphemeralInvoice(null);
      setGenerated(saveAsDraft ? null : { record, url });
      setForm(emptyForm);
      setMessage(saveAsDraft
        ? `Draft ${invoice.invoiceId} saved locally. Activate it before sharing.`
        : `Invoice ${invoice.invoiceId} activated. Verify the URL preview before sharing it.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invoice could not be created.");
    } finally {
      setCreating(false);
    }
  }

  function addMilestone() {
    if (form.milestones.length >= 8) return;
    let next = 1;
    while (form.milestones.some((milestone) => milestone.id === `m${next}`)) next += 1;
    setForm({ ...form, milestones: [...form.milestones, { id: `m${next}`, label: "", amount: "" }] });
  }

  function updateMilestone(index: number, field: "label" | "amount", value: string) {
    setForm({
      ...form,
      milestones: form.milestones.map((milestone, position) => position === index ? { ...milestone, [field]: value } : milestone),
    });
  }

  function removeMilestone(index: number) {
    setForm({ ...form, milestones: form.milestones.filter((_, position) => position !== index) });
  }

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage("Invoice link copied.");
    } catch {
      setMessage("Copy was unavailable. Select and copy the URL manually.");
    }
  }

  function activate(record: LocalInvoiceRecord) {
    try {
      const updated = { ...record, lifecycle: activateInvoice(record.lifecycle) };
      persist(invoices.map((candidate) => candidate.invoice.invoiceId === record.invoice.invoiceId ? updated : candidate));
      setGenerated({ record: updated, url: invoicePaymentUrl(updated.encodedPayload) });
      setMessage(`Invoice ${record.invoice.invoiceId} is active and ready to share.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invoice could not be activated.");
    }
  }

  function cancel(record: LocalInvoiceRecord) {
    try {
      const updated = { ...record, lifecycle: cancelInvoice(record.lifecycle) };
      persist(invoices.map((candidate) => candidate.invoice.invoiceId === record.invoice.invoiceId ? updated : candidate));
      setMessage("Invoice marked cancelled in this browser. Portable links cannot be remotely revoked without a shared backend.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invoice could not be cancelled.");
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
            <label>Token<input value="STRK - 18 decimals" readOnly /></label>
          </div>
          <label>Description<input required maxLength={160} placeholder="Design retainer" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></label>
          <label>Reference number (optional)<input maxLength={64} placeholder="PO-1042" value={form.referenceNumber} onChange={(event) => setForm({ ...form, referenceNumber: event.target.value })} /></label>
          <label>Expires at<input required type="datetime-local" value={form.expiresAt} onChange={(event) => setForm({ ...form, expiresAt: event.target.value })} /></label>
          <label className="checkbox-label ephemeral-toggle"><input type="checkbox" checked={form.ephemeral} onChange={(event) => setForm({ ...form, ephemeral: event.target.checked, allowPartialPayments: event.target.checked ? false : form.allowPartialPayments, milestones: event.target.checked ? [] : form.milestones })} />Burn after one settlement or TTL expiry</label>
          <label className="checkbox-label"><input type="checkbox" disabled={form.ephemeral} checked={form.allowPartialPayments} onChange={(event) => setForm({ ...form, allowPartialPayments: event.target.checked })} />Allow partial payments</label>
          <fieldset className="milestone-editor" disabled={form.ephemeral}>
            <legend>Milestones (optional, maximum 8)</legend>
            {form.milestones.map((milestone, index) => (
              <div className="milestone-row" key={milestone.id}>
                <input aria-label={`Milestone ${index + 1} label`} required maxLength={80} placeholder="Milestone label" value={milestone.label} onChange={(event) => updateMilestone(index, "label", event.target.value)} />
                <input aria-label={`Milestone ${index + 1} amount`} required inputMode="decimal" placeholder="Amount" value={milestone.amount} onChange={(event) => updateMilestone(index, "amount", event.target.value)} />
                <button type="button" onClick={() => removeMilestone(index)} aria-label={`Remove milestone ${index + 1}`}>Remove</button>
              </div>
            ))}
            <button type="button" onClick={addMilestone} disabled={form.milestones.length >= 8}>Add milestone</button>
            <p className="status">Milestone amounts must equal the invoice total exactly.</p>
          </fieldset>
          <div className="invoice-submit-row">
            <button type="submit" value="draft" disabled={creating || form.ephemeral}>{creating ? "Saving..." : "Save draft"}</button>
            <button type="submit" value="active" disabled={creating}>{creating ? "Generating..." : form.ephemeral ? "Encrypt one-time link" : "Activate and generate link"}</button>
          </div>
          <p className="status">Network: SN_MAIN. Token address and payment amount are locked into the link.</p>
          <p className="status">Never put private keys, seed phrases, viewing keys, RPC keys, wallet history, notes, or proofs in invoice fields.</p>
          <aside className="composer-privacy-preview">
            <strong>{form.ephemeral ? "Ephemeral privacy preview" : "Link privacy preview"}</strong>
            <p>{form.ephemeral ? "Invoice fields are AES-GCM encrypted. The bearer key stays after # in the URL fragment, which browsers do not send in HTTP requests." : "Anyone with the URL can read the merchant name and address, amount, description, reference, expiration, payment policy, and every milestone entered above."}</p>
            <p>{form.ephemeral ? "One exact payment only. This browser burns its mutable key buffer after confirmation or expiry, but copied URLs cannot be globally revoked without shared state." : "The link contains no payer identity or wallet state. Its checksum detects edits but does not authenticate the merchant."}</p>
          </aside>
        </form>

        <div className="invoice-list">
          <p className="status" role="status" aria-live="polite">{message}</p>
          {ephemeralInvoice ? <EphemeralLinkGenerator invoice={ephemeralInvoice} onMessage={setMessage} /> : null}
          {generated ? (
            <article className="invoice-item invoice-preview">
              <div><strong>Generated link</strong><span>schema v{generated.record.invoice.version}</span></div>
              <p>{generated.record.invoice.amount} {generated.record.invoice.tokenSymbol} for {generated.record.invoice.merchantName}</p>
              <textarea aria-label="Generated invoice URL" readOnly value={generated.url} rows={5} />
              <div className="invoice-actions">
                <button type="button" onClick={() => copy(generated.url)}>Copy link</button>
                <a className="transaction-link" href={generated.url}>Open invoice</a>
              </div>
              <small>Integrity checksum included. This is not authentication or a merchant signature.</small>
            </article>
          ) : null}

          <div className="history-heading"><strong>Local history</strong><button type="button" onClick={clearHistory} disabled={!invoices.length}>Clear history</button></div>
          <p className="status">Local history is application metadata only. It is not proof of payment or shared merchant state.</p>
          {invoices.length ? invoices.map((record) => {
            const url = invoicePaymentUrl(record.encodedPayload);
            const status = deriveInvoiceStatus(record.invoice, record.lifecycle);
            return (
              <article className="invoice-item" key={record.invoice.invoiceId}>
                <div><strong>{record.invoice.amount} {record.invoice.tokenSymbol}</strong><span>{status}</span></div>
                <p>{record.invoice.description}</p>
                <small>{record.invoice.invoiceId} - expires {new Date(record.invoice.expiresAt).toLocaleString()}</small>
                <div className="invoice-actions">
                  {status === "draft" ? <button type="button" onClick={() => activate(record)}>Activate</button> : null}
                  {["active", "partially_paid"].includes(status) ? <button type="button" onClick={() => copy(url)}>Copy link</button> : null}
                  {["active", "partially_paid", "confirming", "paid"].includes(status) ? <a className="transaction-link" href={url}>Open</a> : null}
                  {["draft", "active", "partially_paid"].includes(status) ? <button type="button" onClick={() => cancel(record)}>Cancel locally</button> : null}
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
