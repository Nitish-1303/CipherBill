"use client";

import { useEffect, useMemo, useState } from "react";

import { readInvoices, type LocalInvoiceRecord } from "@/lib/invoices";
import { DEFAULT_RECEIPT_SELECTION, type ReceiptDisclosureSelection } from "@/lib/selective-receipts";
import {
  auditDisclosureFileName,
  buildAuditDisclosureBundle,
  decryptAuditDisclosure,
  encodeAuditDisclosurePayload,
  encryptAuditDisclosure,
  formatAuditKeyForTransfer,
  generateAuditDisclosureKey,
  serializeEncryptedAuditDisclosure,
  type EncryptedAuditDisclosure,
} from "@/lib/view-key";

const fieldLabels: Record<keyof ReceiptDisclosureSelection, string> = {
  merchantName: "Merchant name",
  recipientAddress: "Recipient address",
  amount: "Invoice amount and token",
  milestone: "Milestone breakdown",
  description: "Description",
  referenceNumber: "Reference number",
  transactionHash: "Settlement hashes",
  timestamps: "Timestamps",
};

interface ExportedDisclosure {
  invoiceId: string;
  envelope: EncryptedAuditDisclosure;
  json: string;
  encoded: string;
  link: string;
  key: string;
  checkValue: string;
  paymentCount: number;
}

export function InvoiceDashboard() {
  const [invoices, setInvoices] = useState<LocalInvoiceRecord[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [selection, setSelection] = useState<ReceiptDisclosureSelection>(DEFAULT_RECEIPT_SELECTION);
  const [milestoneId, setMilestoneId] = useState("");
  const [confirmedOnly, setConfirmedOnly] = useState(false);
  const [exported, setExported] = useState<ExportedDisclosure | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("Select an invoice, choose exactly what an auditor may read, then export.");
  const [verifyKey, setVerifyKey] = useState("");
  const [verifyResult, setVerifyResult] = useState("");

  useEffect(() => {
    const records = readInvoices();
    setInvoices(records);
    if (records.length > 0) setSelectedId(records[0].invoice.invoiceId);
  }, []);

  const selected = useMemo(
    () => invoices.find((record) => record.invoice.invoiceId === selectedId),
    [invoices, selectedId],
  );

  function chooseInvoice(invoiceId: string): void {
    setSelectedId(invoiceId);
    setMilestoneId("");
    setExported(null);
    setVerifyKey("");
    setVerifyResult("");
  }

  async function exportViewKey(): Promise<void> {
    if (!selected || busy) return;
    setBusy(true);
    setVerifyKey("");
    setVerifyResult("");

    try {
      const { key, checkValue } = await generateAuditDisclosureKey();
      const bundle = await buildAuditDisclosureBundle(selected.invoice, selected.lifecycle, selection, {
        ...(milestoneId ? { milestoneId } : {}),
        confirmedOnly,
        encodedPayload: selected.encodedPayload,
      });
      const envelope = await encryptAuditDisclosure(bundle, key);
      const encoded = encodeAuditDisclosurePayload(envelope);
      setExported({
        invoiceId: selected.invoice.invoiceId,
        envelope,
        json: serializeEncryptedAuditDisclosure(envelope),
        encoded,
        link: `${window.location.origin}/audit#${encoded}`,
        key,
        checkValue,
        paymentCount: bundle.payments.length,
      });
      setMessage(
        bundle.payments.length === 0
          ? "Exported. This invoice has no recorded payments yet, so the bundle discloses invoice terms only."
          : `Exported. Send the link and the view-key over two different channels.`,
      );
    } catch (error) {
      setExported(null);
      setMessage(error instanceof Error ? error.message : "Export failed in this browser.");
    } finally {
      setBusy(false);
    }
  }

  async function copy(value: string, label: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      setMessage(`${label} copied.`);
    } catch {
      setMessage(`Copy unavailable. Select the ${label.toLowerCase()} manually.`);
    }
  }

  function downloadEnvelope(): void {
    if (!exported) return;
    const url = URL.createObjectURL(new Blob([exported.json], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = auditDisclosureFileName(exported.invoiceId);
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage("Encrypted envelope download started. The view-key is not in that file.");
  }

  async function verify(): Promise<void> {
    if (!exported) return;
    try {
      const bundle = await decryptAuditDisclosure(exported.envelope, verifyKey);
      setVerifyResult(
        `Opened successfully: invoice ${bundle.invoiceId}, ${bundle.disclosedFields.length} disclosed field(s), ${bundle.payments.length} payment record(s).`,
      );
    } catch (error) {
      setVerifyResult(error instanceof Error ? error.message : "Verification failed.");
    }
  }

  return (
    <section className="invoice-panel" id="audit-exports">
      <div className="section-heading">
        <span className="eyebrow">Compliance</span>
        <h2>Encrypted auditor disclosures</h2>
      </div>

      <div className="invoice-grid">
        <div className="invoice-form">
          {invoices.length === 0 ? (
            <p className="status">No local invoices yet. Create one in the Invoices tab, then return here to export a disclosure.</p>
          ) : (
            <>
              <label>Invoice
                <select value={selectedId} onChange={(event) => chooseInvoice(event.target.value)}>
                  {invoices.map((record) => (
                    <option key={record.invoice.invoiceId} value={record.invoice.invoiceId}>
                      {record.invoice.merchantName} - {record.invoice.amount} {record.invoice.tokenSymbol}
                    </option>
                  ))}
                </select>
              </label>

              {selected?.invoice.milestones?.length ? (
                <label>Scope
                  <select value={milestoneId} onChange={(event) => setMilestoneId(event.target.value)}>
                    <option value="">Whole invoice</option>
                    {selected.invoice.milestones.map((milestone) => (
                      <option key={milestone.id} value={milestone.id}>{milestone.label} only</option>
                    ))}
                  </select>
                </label>
              ) : null}

              <fieldset className="milestone-editor">
                <legend>Fields the auditor may read</legend>
                <div className="receipt-options">
                  {(Object.keys(fieldLabels) as Array<keyof ReceiptDisclosureSelection>).map((field) => (
                    <label key={field}>
                      <input
                        type="checkbox"
                        checked={selection[field]}
                        onChange={(event) => setSelection({ ...selection, [field]: event.target.checked })}
                      />
                      {fieldLabels[field]}
                    </label>
                  ))}
                </div>
                <label className="checkbox-label">
                  <input type="checkbox" checked={confirmedOnly} onChange={(event) => setConfirmedOnly(event.target.checked)} />
                  Confirmed payments only (hide submitted and failed attempts)
                </label>
              </fieldset>

              <button type="button" onClick={exportViewKey} disabled={busy || !selected}>
                {busy ? "Encrypting..." : "Export View-Key"}
              </button>
              <p className="status" role="status">{message}</p>
            </>
          )}

          <div className="composer-privacy-preview">
            <strong>What this view-key is</strong>
            <p>
              A fresh AES-256-GCM key generated in this browser. It decrypts one disclosure bundle and nothing else.
            </p>
            <p>
              It is <strong>not</strong> a STRK20 protocol viewing key and not part of the STRK20 auditor key escrow.
              A STRK20 viewing key is registered once per account, is immutable, and only the account owner can register
              it. CipherBill never asks for, derives, or stores one. This key cannot decrypt pool notes, derive
              nullifiers, read shielded balances, or authorize spending.
            </p>
            <p>
              Nothing here is written to Starknet. Deposits and withdrawals at the pool edges are already public, so
              this export narrows what <em>you</em> hand over &mdash; it cannot retract on-chain data.
            </p>
          </div>
        </div>

        <div className="invoice-list">
          {exported ? (
            <>
              <article className="invoice-item invoice-preview">
                <div><strong>Encrypted envelope</strong><span>Safe to send</span></div>
                <p>Inert without the view-key. Carries no invoice data in plaintext.</p>
                <textarea aria-label="Encrypted audit disclosure JSON" readOnly rows={12} value={exported.json} />
                <div className="invoice-actions">
                  <button type="button" onClick={() => copy(exported.link, "Audit link")}>Copy audit link</button>
                  <button type="button" onClick={() => copy(exported.json, "Envelope JSON")}>Copy JSON</button>
                  <button type="button" onClick={downloadEnvelope}>Download JSON</button>
                </div>
                <small>
                  Key check value <code>{exported.checkValue}</code> &middot; {exported.paymentCount} payment record(s)
                  {exported.encoded.length > 8_000 ? " - this link is long; send the JSON file instead if a mail client truncates it." : ""}
                </small>
              </article>

              <article className="invoice-item">
                <div><strong>View-key</strong><span>Send separately</span></div>
                <p>
                  Deliver this over a different channel from the link. Anyone holding both can read every disclosed
                  field. CipherBill does not store it &mdash; leaving this page loses it permanently.
                </p>
                <textarea aria-label="Audit view-key" readOnly rows={2} value={formatAuditKeyForTransfer(exported.key)} />
                <div className="invoice-actions">
                  <button type="button" onClick={() => copy(exported.key, "View-key")}>Copy view-key</button>
                </div>
              </article>

              <article className="invoice-item">
                <div><strong>Verify before sending</strong><span>Optional</span></div>
                <p>Paste the view-key back to confirm the auditor will be able to open this exact envelope.</p>
                <label className="field-caption" htmlFor="verify-key">View-key</label>
                <input
                  id="verify-key"
                  value={verifyKey}
                  onChange={(event) => setVerifyKey(event.target.value)}
                  placeholder="Paste the view-key"
                />
                <div className="invoice-actions">
                  <button type="button" onClick={verify} disabled={!verifyKey.trim()}>Test decryption</button>
                </div>
                {verifyResult ? <p className="status" role="status">{verifyResult}</p> : null}
              </article>
            </>
          ) : (
            <article className="invoice-item">
              <div><strong>No disclosure exported yet</strong><span>Ready</span></div>
              <p>
                An export produces two artefacts: an encrypted envelope you can send freely, and a view-key you send
                over a separate channel. Both are generated locally; neither touches a server.
              </p>
            </article>
          )}
        </div>
      </div>
    </section>
  );
}
