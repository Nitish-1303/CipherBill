"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  REFUND_POOL_ADDRESS,
  buildClaimReceipt,
  buildCreditNoteBadge,
  createRefundClaimKey,
  createRefundIssuerKey,
  formatRefundBaseUnits,
  getRefundVisibilityModel,
  issueCreditNote,
  openCreditNote,
  parseClaimReceipt,
  parseCreditNote,
  serializeClaimReceipt,
  serializeCreditNote,
  serializeCreditNoteSecret,
  summarizeRefundTrust,
  verifyClaimReceipt,
  verifyCreditNote,
  type ClaimReceipt,
  type CreditNote,
  type CreditNoteOpening,
  type IssuedCreditNote,
  type RefundKeypair,
} from "@/lib/refund-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./refund-portal.module.css";

const INTRO =
  "Issue a commitment-bound credit note against a settled invoice and prove, in zero knowledge, that the private refund lies within the original invoice total — without revealing the figure, the customer, or the original payment path. The note is signed by the merchant and sealed to the customer's claim key. It does not settle on-chain, move pool funds, or call the STRK20 pool contract.";

const TRUST = summarizeRefundTrust();
const VISIBILITY = getRefundVisibilityModel();
const BIT_LENGTHS = [16, 32, 64, 128] as const;

/** Abbreviates a long hex value for display; short values pass through unchanged. */
function shorten(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

/** Renders an ISO timestamp as a short local date; falls back to the raw string. */
function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** Streams a text payload to a downloaded file; the copyable textarea stays as a fallback. */
function download(filename: string, text: string): void {
  if (!text) return;
  try {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch {
    /* A blocked download still leaves the copyable textarea in place. */
  }
}

interface OpenState {
  ok: boolean;
  note?: CreditNote;
  opening?: CreditNoteOpening;
  receipt?: string;
  error?: string;
}

interface VerifyState {
  ok: boolean;
  note?: CreditNote;
  receiptOk?: boolean;
  error?: string;
}

export function RefundPortal() {
  // Key vault
  const [issuerKey, setIssuerKey] = useState<RefundKeypair | null>(null);
  const [claimKey, setClaimKey] = useState<RefundKeypair | null>(null);
  const [revealIssuerSecret, setRevealIssuerSecret] = useState(false);
  const [revealClaimSecret, setRevealClaimSecret] = useState(false);

  // Issue form
  const [merchantAlias, setMerchantAlias] = useState("Northwind Labs");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState(18);
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [invoiceRef, setInvoiceRef] = useState("INV-2026-0042");
  const [refundAmount, setRefundAmount] = useState("120.50");
  const [ceilingAmount, setCeilingAmount] = useState("500");
  const [bitLength, setBitLength] = useState<number>(128);
  const [memo, setMemo] = useState("");
  const [issuerSecretInput, setIssuerSecretInput] = useState("");
  const [claimPubX, setClaimPubX] = useState("");
  const [claimPubY, setClaimPubY] = useState("");

  const [built, setBuilt] = useState<IssuedCreditNote | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revealOpening, setRevealOpening] = useState(false);
  // Claim / verify inputs
  const [openNoteInput, setOpenNoteInput] = useState("");
  const [openSecretInput, setOpenSecretInput] = useState("");
  const [openState, setOpenState] = useState<OpenState | null>(null);
  const [verifyNoteInput, setVerifyNoteInput] = useState("");
  const [verifyReceiptInput, setVerifyReceiptInput] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState | null>(null);

  const serializedNote = useMemo(() => (built ? serializeCreditNote(built.note) : ""), [built]);
  const serializedSecret = useMemo(() => (built ? serializeCreditNoteSecret(built.secret) : ""), [built]);
  const badge = useMemo(() => (built ? buildCreditNoteBadge(built.note) : null), [built]);

  function generateIssuerKey() {
    const key = createRefundIssuerKey();
    setIssuerKey(key);
    setIssuerSecretInput(key.secretKey);
    setRevealIssuerSecret(false);
  }

  function generateClaimKey() {
    const key = createRefundClaimKey();
    setClaimKey(key);
    setClaimPubX(key.publicKey.x);
    setClaimPubY(key.publicKey.y);
    setRevealClaimSecret(false);
  }

  function handleIssue(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setBuildError(null);
    setRevealOpening(false);
    try {
      const refundBaseUnits = decimalToBaseUnits(refundAmount.trim(), assetDecimals);
      const invoiceCeilingBaseUnits = decimalToBaseUnits(ceilingAmount.trim(), assetDecimals);
      const result = issueCreditNote({
        merchantAlias: merchantAlias.trim(),
        asset: { symbol: assetSymbol.trim(), tokenAddress: tokenAddress.trim(), decimals: assetDecimals },
        invoiceRef: invoiceRef.trim(),
        refundBaseUnits,
        invoiceCeilingBaseUnits,
        claimPublicKey: { x: claimPubX.trim(), y: claimPubY.trim() },
        issuerSecretKey: issuerSecretInput.trim(),
        bitLength,
        memo: memo.trim() || undefined,
      });
      setBuilt(result);
    } catch (error) {
      setBuilt(null);
      setBuildError(error instanceof Error ? error.message : "Could not issue the credit note.");
    } finally {
      setBusy(false);
    }
  }
  function handleOpen(event: FormEvent) {
    event.preventDefault();
    try {
      const note = parseCreditNote(openNoteInput.trim());
      if (!verifyCreditNote(note)) {
        setOpenState({ ok: false, error: "The note's proof does not validate; refusing to open it." });
        return;
      }
      const opening = openCreditNote(note, openSecretInput.trim());
      if (!opening) {
        setOpenState({ ok: false, note, error: "This claim key does not open the note." });
        return;
      }
      const receipt = serializeClaimReceipt(buildClaimReceipt(note, openSecretInput.trim()));
      setOpenState({ ok: true, note, opening, receipt });
    } catch (error) {
      setOpenState({ ok: false, error: error instanceof Error ? error.message : "Could not open the note." });
    }
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const note = parseCreditNote(verifyNoteInput.trim());
      const ok = verifyCreditNote(note);
      let receiptOk: boolean | undefined;
      if (verifyReceiptInput.trim()) {
        const receipt: ClaimReceipt = parseClaimReceipt(verifyReceiptInput.trim());
        receiptOk = verifyClaimReceipt(note, receipt);
      }
      setVerifyState({ ok, note, receiptOk });
    } catch (error) {
      setVerifyState({ ok: false, error: error instanceof Error ? error.message : "Could not decode the note." });
    }
  }
  return (
    <section className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Private Refunds</span>
          <h2>Zero-knowledge <em>credit notes</em></h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(REFUND_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div><dt>Refund ≤ invoice</dt><dd className={styles.yes}>ZK proven</dd></div>
          <div><dt>Issuer signature</dt><dd className={styles.yes}>Authenticated</dd></div>
          <div><dt>On-chain settlement</dt><dd className={styles.no}>Not proven</dd></div>
          <div><dt>Pool contract</dt><dd className={styles.no}>Never called</dd></div>
        </dl>
      </header>

      <div className={styles.vault}>
        <div className={styles.vaultHead}>
          <span>00 · Key vault</span>
          <div className={styles.vaultActions}>
            <button type="button" className={styles.ghost} onClick={generateIssuerKey}>Generate issuer key</button>
            <button type="button" className={styles.ghost} onClick={generateClaimKey}>Generate claim key</button>
          </div>
        </div>
        <div className={styles.keyGrid}>
          <div className={styles.keyCard}>
            <h4>Merchant issuer key</h4>
            {issuerKey ? (
              <dl>
                <div><dt>Public key</dt><dd>{shorten(issuerKey.publicKey.x)}</dd></div>
                <dt className={styles.secretTag}>Secret signing key {revealIssuerSecret ? "" : "(hidden)"}
                  <button type="button" className={styles.ghost} onClick={() => setRevealIssuerSecret((v) => !v)}>{revealIssuerSecret ? "Hide" : "Reveal"}</button>
                </dt>
                <dd>{revealIssuerSecret ? issuerKey.secretKey : "•••••••• — the merchant keeps this to sign notes"}</dd>
              </dl>
            ) : (
              <p className={styles.hint}>Generate a signing key, or paste an existing issuer secret into the issue form.</p>
            )}
          </div>
          <div className={styles.keyCard}>
            <h4>Customer claim key</h4>
            {claimKey ? (
              <dl>
                <div><dt>Public key (share with merchant)</dt><dd>{shorten(claimKey.publicKey.x)}</dd></div>
                <dt className={styles.secretTag}>Secret claim key {revealClaimSecret ? "" : "(hidden)"}
                  <button type="button" className={styles.ghost} onClick={() => setRevealClaimSecret((v) => !v)}>{revealClaimSecret ? "Hide" : "Reveal"}</button>
                </dt>
                <dd>{revealClaimSecret ? claimKey.secretKey : "•••••••• — the customer keeps this to open and claim"}</dd>
              </dl>
            ) : (
              <p className={styles.hint}>The customer generates this and shares only the public key. Generate one here to run the full demo.</p>
            )}
          </div>
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue</span>
            <h3>Commitment-bound credit note</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} placeholder="Northwind Labs" />
            </label>
            <label>Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} placeholder="STRK" />
            </label>
            <label>Decimals
              <input type="number" min={0} max={38} value={assetDecimals} onChange={(e) => setAssetDecimals(Number(e.target.value))} />
            </label>
            <label className={styles.wide}>Token address <small>provenance only — never called</small>
              <input value={tokenAddress} onChange={(e) => setTokenAddress(e.target.value)} spellCheck={false} />
            </label>
            <label className={styles.wide}>Invoice reference
              <input value={invoiceRef} onChange={(e) => setInvoiceRef(e.target.value)} placeholder="INV-2026-0042" />
            </label>
            <label>Refund amount <small>private — hidden in note</small>
              <input value={refundAmount} onChange={(e) => setRefundAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>Invoice ceiling <small>public bound</small>
              <input value={ceilingAmount} onChange={(e) => setCeilingAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>Range bits
              <select value={bitLength} onChange={(e) => setBitLength(Number(e.target.value))}>
                {BIT_LENGTHS.map((b) => <option key={b} value={b}>{b}-bit</option>)}
              </select>
            </label>
            <label>Memo <small>optional</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="Partial refund" />
            </label>
            <label className={styles.wide}>Issuer secret signing key
              <input value={issuerSecretInput} onChange={(e) => setIssuerSecretInput(e.target.value)} placeholder="0x… (or generate above)" spellCheck={false} />
            </label>
            <label>Claim public key · x
              <input value={claimPubX} onChange={(e) => setClaimPubX(e.target.value)} placeholder="0x…" spellCheck={false} />
            </label>
            <label>Claim public key · y
              <input value={claimPubY} onChange={(e) => setClaimPubY(e.target.value)} placeholder="0x…" spellCheck={false} />
            </label>
          </div>
          {buildError && <p className={styles.error}>{buildError}</p>}
          <button type="submit" disabled={busy}>{busy ? "Proving range…" : "Issue credit note"}</button>
        </form>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <span>02 · Issued note</span>
            <h3>Shareable credit note</h3>
          </div>
          {built && badge ? (
            <>
              <div className={styles.badge}>
                <div className={styles.badgeTop}>
                  <div>
                    <strong>{badge.merchantAlias}</strong>
                    <small>{badge.invoiceRef} · {formatDate(badge.createdAt)}</small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  Refund ≤ <b>{badge.invoiceCeilingDisplay} {badge.assetSymbol}</b>
                  <small>Exact refund stays hidden inside the commitment.</small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div><dt>Note id</dt><dd>{badge.noteId}</dd></div>
                  <div><dt>Range</dt><dd>{built.note.proof.bitLength}-bit</dd></div>
                  <div><dt>Proof system</dt><dd>{built.note.proof.proofSystem}</dd></div>
                  <div><dt>Binding</dt><dd>{shorten(badge.bindingHash)}</dd></div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Credit note (safe to publish)</span>
                  <button type="button" className={styles.ghost} onClick={() => download(`${built.note.noteId}.note.txt`, serializedNote)}>Download</button>
                </div>
                <textarea readOnly value={serializedNote} rows={4} />
              </div>
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Issuer opening secret {revealOpening ? "" : "(hidden)"}</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealOpening((v) => !v)}>{revealOpening ? "Hide" : "Reveal"}</button>
                    <button type="button" className={styles.ghost} onClick={() => download(`${built.note.noteId}.secret.txt`, serializedSecret)}>Download</button>
                  </div>
                </div>
                <p className={styles.warn}>Holds the refund figure and blinding in the clear. Never publish it; the customer opens the note with their claim key instead.</p>
                {revealOpening && <textarea readOnly value={serializedSecret} rows={3} />}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>Issue a note to produce a shareable, publicly verifiable credit note and a private issuer opening secret.</p>
          )}
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.claim} onSubmit={handleOpen}>
          <div className={styles.panelHead}>
            <span>03 · Claim</span>
            <h3>Open with the claim key</h3>
          </div>
          <div className={styles.claimFields}>
            <label className={styles.toggle}>Credit note
              <textarea value={openNoteInput} onChange={(e) => setOpenNoteInput(e.target.value)} placeholder="Paste a serialized credit note…" spellCheck={false} />
            </label>
            <label className={styles.toggle}>Secret claim key
              <textarea value={openSecretInput} onChange={(e) => setOpenSecretInput(e.target.value)} placeholder="0x… the customer's private claim key" spellCheck={false} />
            </label>
          </div>
          <button type="submit">Open &amp; build receipt</button>
          {openState && (openState.ok ? (
            <div className={styles.pass}>
              <strong>Opened · {openState.opening ? formatRefundBaseUnits(openState.opening.refundBaseUnits, openState.note?.assetDecimals ?? 0) : "—"} {openState.note?.assetSymbol}</strong>
              <dl className={styles.resultMeta}>
                <div><dt>Note id</dt><dd>{openState.note?.noteId}</dd></div>
                <div><dt>Invoice</dt><dd>{openState.note?.invoiceRef}</dd></div>
              </dl>
              <small>The figure above matches the sealed commitment and never leaves this browser.</small>
              {openState.receipt && (
                <div className={styles.export}>
                  <div className={styles.exportHead}>
                    <span>Claim receipt (DLEQ)</span>
                    <button type="button" className={styles.ghost} onClick={() => download(`${openState.note?.noteId}.receipt.txt`, openState.receipt ?? "")}>Download</button>
                  </div>
                  <textarea readOnly value={openState.receipt} rows={3} />
                </div>
              )}
            </div>
          ) : (
            <div className={styles.fail}><strong>Cannot open</strong><small>{openState.error}</small></div>
          ))}
        </form>
        <form className={styles.verify} onSubmit={handleVerify}>
          <div className={styles.panelHead}>
            <span>04 · Verify</span>
            <h3>Check a note &amp; receipt</h3>
          </div>
          <label className={styles.toggle}>Credit note
            <textarea value={verifyNoteInput} onChange={(e) => setVerifyNoteInput(e.target.value)} placeholder="Paste a serialized credit note…" spellCheck={false} />
          </label>
          <label className={styles.toggle}>Claim receipt <small>optional</small>
            <textarea value={verifyReceiptInput} onChange={(e) => setVerifyReceiptInput(e.target.value)} placeholder="Paste a claim receipt to check the claimant…" spellCheck={false} />
          </label>
          <button type="submit">Verify</button>
          {verifyState && (verifyState.error ? (
            <div className={styles.fail}><strong>Cannot decode</strong><small>{verifyState.error}</small></div>
          ) : (
            <div className={verifyState.ok ? styles.pass : styles.fail}>
              <strong>{verifyState.ok ? "Note proof valid" : "Note proof invalid"}</strong>
              <dl className={styles.resultMeta}>
                <div><dt>Refund ≤ invoice</dt><dd>{verifyState.ok ? "ZK proven" : "rejected"}</dd></div>
                <div><dt>Issuer signature</dt><dd>{verifyState.ok ? "authenticated" : "rejected"}</dd></div>
                {verifyState.receiptOk !== undefined && (
                  <div><dt>Claim receipt</dt><dd>{verifyState.receiptOk ? "claimant proven" : "does not match"}</dd></div>
                )}
                {verifyState.note && <div><dt>Ceiling</dt><dd>{formatRefundBaseUnits(verifyState.note.invoiceCeilingBaseUnits, verifyState.note.assetDecimals)} {verifyState.note.assetSymbol}</dd></div>}
              </dl>
              <small>Verification is arithmetic only: no pool contract call, no on-chain settlement.</small>
            </div>
          ))}
        </form>
      </div>
      <div className={styles.model}>
        <div>
          <h4>Hidden from the verifier</h4>
          <ul>{VISIBILITY.hiddenFromVerifier.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
        <div>
          <h4>Disclosed to the verifier</h4>
          <ul>{VISIBILITY.disclosedToVerifier.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
        <div>
          <h4>Application layer only</h4>
          <ul>{VISIBILITY.applicationOnly.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      </div>

      <div className={styles.limitation}>
        <p>{VISIBILITY.limitation}</p>
        <p className={styles.statement}>{TRUST.statement}</p>
      </div>
    </section>
  );
}









