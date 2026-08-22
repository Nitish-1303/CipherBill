"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import {
  decodeAuditDisclosurePayload,
  decryptAuditDisclosure,
  type AuditDisclosureBundle,
} from "@/lib/view-key";

/**
 * Auditor-facing viewer for an encrypted CipherBill disclosure.
 *
 * The envelope arrives in the URL fragment, which browsers never send to a server, so
 * opening this link does not transmit the envelope anywhere. The view-key is typed in
 * here and is never placed in the URL. Decryption happens entirely in this browser.
 */
export default function AuditDisclosurePage() {
  const [encoded, setEncoded] = useState("");
  const [key, setKey] = useState("");
  const [bundle, setBundle] = useState<AuditDisclosureBundle | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const fragment = window.location.hash.replace(/^#/, "");
    if (fragment) setEncoded(fragment);
  }, []);

  async function open(): Promise<void> {
    setError("");
    setBundle(null);
    try {
      const decrypted = await decryptAuditDisclosure(decodeAuditDisclosurePayload(encoded.trim()), key);
      setBundle(decrypted);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "This disclosure could not be opened.");
    }
  }

  return (
    <main className="pay-page">
      <nav className="pay-nav">
        <Link className="brand" href="/"><span>◈</span>CipherBill</Link>
        <span className="network-badge">Auditor disclosure viewer</span>
      </nav>

      <section className="pay-shell">
        <div className="pay-heading">
          <span className="eyebrow">Selective disclosure</span>
          <h1>Open a disclosure</h1>
          <p>
            Paste the view-key the merchant sent you over a separate channel. Decryption happens in this browser; the
            envelope travels in the URL fragment, which is never sent to a server.
          </p>
        </div>

        <div className="invoice-payment-controls">
          <label>Encrypted envelope
            <input
              value={encoded}
              onChange={(event) => setEncoded(event.target.value)}
              placeholder="Paste the encoded envelope, or open the merchant's audit link"
            />
          </label>
          <label>View-key
            <input value={key} onChange={(event) => setKey(event.target.value)} placeholder="Paste the view-key" />
          </label>
          <button type="button" onClick={open} disabled={!encoded.trim() || !key.trim()}>Open disclosure</button>
          {error ? <p className="error-message">{error}</p> : null}
        </div>

        {bundle ? (
          <>
            <div className="payment-status-panel" aria-live="polite">
              <div><span>Invoice</span><strong>{bundle.invoiceId}</strong></div>
              <div><span>Network</span><strong>{bundle.network}</strong></div>
              <div><span>Confirmed</span><strong>{bundle.totals.confirmed} {bundle.totals.tokenSymbol}</strong></div>
              <div><span>Remaining</span><strong>{bundle.totals.remaining} {bundle.totals.tokenSymbol}</strong></div>
            </div>

            <dl className="invoice-facts">
              {Object.entries(bundle.disclosed).map(([field, value]) => (
                <div key={field}><dt>{field}</dt><dd><code>{value}</code></dd></div>
              ))}
              <div><dt>Generated at</dt><dd>{new Date(bundle.generatedAt).toLocaleString()}</dd></div>
              <div><dt>STRK20 pool</dt><dd><code>{bundle.poolAddress}</code></dd></div>
              {bundle.payloadDigest ? (
                <div><dt>Invoice link digest</dt><dd><code>{bundle.payloadDigest}</code></dd></div>
              ) : null}
            </dl>

            {bundle.payments.length > 0 ? (
              <section className="payment-history">
                <h3>Disclosed settlements</h3>
                <p className="status">
                  A disclosed hash shows only that a STRK20 pool transaction executed. In-pool movement publishes
                  just an unlinkable nullifier, so the amounts and counterparties below cannot be corroborated from
                  Starknet without that account&apos;s escrowed viewing key.
                </p>
                {bundle.payments.map((payment, index) => (
                  <div key={payment.hash ?? `${payment.submittedAt}-${index}`} className={`payment-record payment-${payment.status}`}>
                    <div className="payment-header">
                      <span className="payment-number">{payment.milestoneLabel ?? payment.milestoneId ?? "Payment"}</span>
                      <span className={`payment-badge payment-badge-${payment.status}`}>{payment.status}</span>
                    </div>
                    <div className="payment-details">
                      <div><strong>Amount:</strong> {payment.amount} {bundle.totals.tokenSymbol}</div>
                      <div><strong>Base units:</strong> <code>{payment.amountBaseUnits}</code></div>
                      {payment.hash
                        ? <div><strong>Hash:</strong> <code>{payment.hash}</code></div>
                        : <div><strong>Hash:</strong> withheld by the merchant</div>}
                      <div><strong>Submitted:</strong> {new Date(payment.submittedAt).toLocaleString()}</div>
                      {payment.confirmedAt ? <div><strong>Confirmed:</strong> {new Date(payment.confirmedAt).toLocaleString()}</div> : null}
                      {payment.explorerUrl ? (
                        <a href={payment.explorerUrl} target="_blank" rel="noreferrer" className="transaction-link">View on Voyager</a>
                      ) : null}
                    </div>
                  </div>
                ))}
              </section>
            ) : (
              <p className="status">This disclosure contains invoice terms only; no payment records were included.</p>
            )}

            <div className="privacy-notice">
              <strong>Scope of this disclosure</strong>
              <p>{bundle.notice}</p>
              {bundle.limitations.map((limitation) => <p key={limitation}>&middot; {limitation}</p>)}
            </div>
          </>
        ) : null}

        {/*
          Rendered unconditionally, outside the bundle gate. An auditor reaching this page with a
          wrong key - or before pasting anything - is exactly the reader who most needs to know what
          the view-key is not, so this cannot live only in the success branch.
        */}
        <div className="privacy-notice">
          <strong>What a CipherBill view-key is</strong>
          <p>
            An AES-256-GCM key the merchant generated in their own browser for one disclosure bundle. It is{" "}
            <strong>not</strong> a STRK20 protocol viewing key and not part of the STRK20 auditor key escrow. A STRK20
            viewing key is registered once per account, is immutable, and only the account owner can register it.
          </p>
          <p>
            &middot; This key cannot decrypt STRK20 pool notes, derive nullifiers, read shielded balances, or authorize
            spending. Its authority begins and ends at one bundle.
          </p>
          <p>
            &middot; A bundle is application metadata the merchant&apos;s browser recorded, plus transaction hashes. It is
            not a zero-knowledge proof and carries no merchant signature.
          </p>
          <p>
            &middot; Deposits and withdrawals at the STRK20 pool edges are already public on Starknet, addresses and
            amounts included. Encrypting a report about them does not make them private.
          </p>
          <p>
            &middot; Totals cover only the scope the merchant disclosed. A milestone-scoped or confirmed-only export
            reports figures for the records it includes, not for the whole invoice.
          </p>
        </div>
      </section>
    </main>
  );
}
