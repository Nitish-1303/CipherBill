"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  BATCH_POOL_ADDRESS,
  assessBatchConcentration,
  buildBatchAmountDisclosure,
  buildBatchCertificateBadge,
  buildBatchInclusionProof,
  buildBatchRecipientDisclosure,
  computeBatchState,
  createBatchIssuerKey,
  estimateBatchEfficiency,
  formatBatchBaseUnits,
  formatShare,
  getBatchVisibilityModel,
  issueBatchCertificate,
  parseBatchAmountDisclosure,
  parseBatchCertificate,
  parseBatchInclusionProof,
  parseBatchRecipientDisclosure,
  serializeBatchAmountDisclosure,
  serializeBatchCertificate,
  serializeBatchCertificateSecret,
  serializeBatchInclusionProof,
  serializeBatchRecipientDisclosure,
  summarizeBatchTrust,
  verifyBatchAmountDisclosure,
  verifyBatchCertificate,
  verifyBatchInclusionProof,
  verifyBatchRecipientDisclosure,
  type BatchCertificate,
  type BatchConcentrationBand,
  type BatchInvoiceInput,
  type BatchKeypair,
} from "@/lib/batcher-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./batcher-portal.module.css";
const INTRO =
  "Reconcile many settled invoices across several merchant labels into one signed batch, then prove the batch total equals the sum of the hidden per-invoice amounts — without revealing any single amount or recipient. This is a client-side attestation only.";

const TRUST = summarizeBatchTrust();
const VISIBILITY = getBatchVisibilityModel();

const BAND_LABEL: Record<BatchConcentrationBand, string> = {
  low: "Low",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

const BIT_OPTIONS = [8, 16, 24, 32, 48, 64] as const;

interface QueueRow {
  merchantLabel: string;
  invoiceRef: string;
  amount: string;
  recipientRef: string;
}

const SAMPLE_ROWS: QueueRow[] = [
  { merchantLabel: "Acme", invoiceRef: "INV-1041", amount: "180.00", recipientRef: "acct_acme_ops" },
  { merchantLabel: "Globex", invoiceRef: "INV-2277", amount: "95.50", recipientRef: "" },
  { merchantLabel: "Initech", invoiceRef: "INV-3390", amount: "42.25", recipientRef: "acct_initech" },
];

function shorten(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function download(filename: string, text: string): void {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
interface DisclosureCheck {
  type: "amount" | "recipient" | "inclusion";
  ok: boolean;
  detail: string;
}

interface VerifyState {
  certificateOk: boolean;
  certificate?: BatchCertificate;
  disclosure?: DisclosureCheck;
  error?: string;
}

export function BatcherPortal() {
  const [issuerKey, setIssuerKey] = useState<BatchKeypair>(() => createBatchIssuerKey());
  const [revealIssuerSecret, setRevealIssuerSecret] = useState(false);

  const [operatorAlias, setOperatorAlias] = useState("Aurora Treasury");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("2");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [batchRef, setBatchRef] = useState("BATCH-2026-0007");
  const [batchLabel, setBatchLabel] = useState("August cross-merchant settlement");
  const [amountBitLength, setAmountBitLength] = useState("32");
  const [memo, setMemo] = useState("");

  const [rows, setRows] = useState<QueueRow[]>(SAMPLE_ROWS);

  const [built, setBuilt] = useState<{ certificate: BatchCertificate; secret: ReturnType<typeof issueBatchCertificate>["secret"] } | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revealSecret, setRevealSecret] = useState(false);
  const [discloseIndex, setDiscloseIndex] = useState(0);

  const [verifyCertInput, setVerifyCertInput] = useState("");
  const [verifyDisclosureInput, setVerifyDisclosureInput] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState | null>(null);
  const decimals = useMemo(() => {
    const n = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(n) && n >= 0 && n <= 18 ? n : 2;
  }, [assetDecimals]);

  const bitLength = useMemo(() => {
    const n = Number.parseInt(amountBitLength, 10);
    return Number.isFinite(n) ? n : 32;
  }, [amountBitLength]);

  const preview = useMemo(() => {
    try {
      const invoices: BatchInvoiceInput[] = rows.map((row) => {
        const recipientRef = row.recipientRef.trim();
        return {
          merchantLabel: row.merchantLabel.trim(),
          invoiceRef: row.invoiceRef.trim(),
          amountBaseUnits: decimalToBaseUnits(row.amount, decimals),
          ...(recipientRef ? { recipientRef } : {}),
        };
      });
      const state = computeBatchState(invoices);
      return {
        invoices,
        state,
        concentration: assessBatchConcentration(state),
        efficiency: estimateBatchEfficiency(state, bitLength),
        declaredTotalBaseUnits: state.totalBaseUnits,
        error: null as string | null,
      };
    } catch (error) {
      return { invoices: null, state: null, concentration: null, efficiency: null, declaredTotalBaseUnits: null, error: (error as Error).message };
    }
  }, [rows, decimals, bitLength]);
  const badge = useMemo(() => (built ? buildBatchCertificateBadge(built.certificate) : null), [built]);
  const serializedCertificate = useMemo(() => (built ? serializeBatchCertificate(built.certificate) : ""), [built]);
  const serializedSecret = useMemo(() => (built ? serializeBatchCertificateSecret(built.secret) : ""), [built]);

  const disclosures = useMemo(() => {
    if (!built) return null;
    const index = Math.min(Math.max(discloseIndex, 0), built.certificate.invoiceCount - 1);
    const amount = serializeBatchAmountDisclosure(buildBatchAmountDisclosure(built.secret, index));
    const inclusion = serializeBatchInclusionProof(buildBatchInclusionProof(built.certificate, index));
    let recipient: string | null = null;
    try {
      recipient = serializeBatchRecipientDisclosure(buildBatchRecipientDisclosure(built.secret, index));
    } catch {
      recipient = null;
    }
    return { index, amount, inclusion, recipient };
  }, [built, discloseIndex]);

  function regenerateKey(): void {
    setIssuerKey(createBatchIssuerKey());
    setRevealIssuerSecret(false);
  }

  function addRow(): void {
    setRows((prev) => [...prev, { merchantLabel: "", invoiceRef: "", amount: "", recipientRef: "" }]);
  }

  function removeRow(index: number): void {
    setRows((prev) => (prev.length <= 1 ? prev : prev.filter((_, i) => i !== index)));
  }

  function updateRow(index: number, patch: Partial<QueueRow>): void {
    setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }
  async function handleIssue(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBuildError(null);
    if (!preview.invoices || !preview.state) {
      setBuildError(preview.error ?? "Add at least one invoice with a valid amount.");
      return;
    }
    setBusy(true);
    setRevealSecret(false);
    setDiscloseIndex(0);
    // Yield one frame so the "Proving…" state paints before the synchronous prover blocks the thread.
    await new Promise((resolve) => setTimeout(resolve, 30));
    try {
      const result = issueBatchCertificate({
        operatorAlias,
        asset: { symbol: assetSymbol, tokenAddress, decimals },
        batchRef,
        batchLabel,
        invoices: preview.invoices,
        declaredBatchTotalBaseUnits: preview.state.totalBaseUnits,
        issuerSecretKey: issuerKey.secretKey,
        amountBitLength: bitLength,
        ...(memo.trim() ? { memo: memo.trim() } : {}),
      });
      setBuilt(result);
    } catch (error) {
      setBuilt(null);
      setBuildError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function handleVerify(event: FormEvent): void {
    event.preventDefault();
    try {
      const certificate = parseBatchCertificate(verifyCertInput.trim());
      const certificateOk = verifyBatchCertificate(certificate);

      let disclosure: DisclosureCheck | undefined;
      const raw = verifyDisclosureInput.trim();
      if (raw) {
        disclosure = checkDisclosure(certificate, raw);
      }
      setVerifyState({ certificateOk, certificate, disclosure });
    } catch (error) {
      setVerifyState({ certificateOk: false, error: (error as Error).message });
    }
  }

  function checkDisclosure(certificate: BatchCertificate, raw: string): DisclosureCheck {
    try {
      const amount = parseBatchAmountDisclosure(raw);
      const ok = verifyBatchAmountDisclosure(certificate, amount);
      return { type: "amount", ok, detail: `Invoice #${amount.index + 1} amount ${amount.amountBaseUnits} base units` };
    } catch {
      /* not an amount disclosure */
    }
    try {
      const recipient = parseBatchRecipientDisclosure(raw);
      const ok = verifyBatchRecipientDisclosure(certificate, recipient);
      return { type: "recipient", ok, detail: `Invoice #${recipient.index + 1} recipient "${recipient.value}"` };
    } catch {
      /* not a recipient disclosure */
    }
    const inclusion = parseBatchInclusionProof(raw);
    const ok = verifyBatchInclusionProof(certificate, inclusion);
    return { type: "inclusion", ok, detail: `Invoice #${inclusion.index + 1} Merkle inclusion against the batch root` };
  }
  const trustRows: Array<[string, boolean]> = [
    ["Zero-knowledge (hides per-invoice amounts)", TRUST.hidesIndividualInvoiceAmounts],
    ["Proves batch sum = declared total", TRUST.provesBatchSumEqualsDeclaredTotal],
    ["Binds all invoices under one signed root", TRUST.bindsAllInvoicesUnderOneSignedRoot],
    ["Authenticates the issuer", TRUST.authenticatesIssuer],
    ["Decentralized", TRUST.isDecentralized],
    ["Settles / disburses / moves funds", TRUST.settlesOrDisbursesFunds],
    ["Calls the STRK20 pool contract", TRUST.callsPoolContract],
    ["Reduces on-chain gas", TRUST.reducesOnChainGas],
  ];

  return (
    <section className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Multi-merchant batch reconciliation</span>
          <h2>
            One signed <em>batch root</em>, many hidden invoices
          </h2>
          <p>{INTRO}</p>
          <p className={styles.provenance}>
            Pool provenance (never called): {shorten(BATCH_POOL_ADDRESS)}
          </p>
        </div>
        <dl className={styles.trust}>
          {trustRows.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd className={value ? styles.yes : styles.no}>{value ? "Yes" : "No"}</dd>
            </div>
          ))}
        </dl>
      </header>
      <div className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Live reconciliation dashboard</span>
          <small>Application-only local view · not published in the certificate</small>
        </div>
        {preview.state && preview.concentration && preview.efficiency ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={styles.metric}>
                <dt>Invoices</dt>
                <dd>{preview.state.invoiceCount}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Merchants</dt>
                <dd>{preview.state.merchantCount}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Batch total</dt>
                <dd>
                  {formatBatchBaseUnits(preview.state.totalBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={`${styles.metric} ${styles.risk}`} data-band={preview.concentration.band}>
                <dt>Concentration</dt>
                <dd>
                  {BAND_LABEL[preview.concentration.band]} · {formatShare(Number(preview.state.concentrationBps))}
                </dd>
              </div>
            </dl>
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>Merchant</th>
                    <th>Invoices</th>
                    <th>Subtotal</th>
                    <th>Share</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.state.merchants.map((merchant) => (
                    <tr key={merchant.merchantLabel}>
                      <td>{merchant.merchantLabel}</td>
                      <td>{merchant.invoiceCount}</td>
                      <td className={styles.rateCell}>
                        {formatBatchBaseUnits(merchant.subtotalBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td className={styles.warnCell}>{formatShare(Number(merchant.shareBps))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className={styles.hint}>
              Illustrative aggregation: {preview.efficiency.batchedProofElements} batched range-proof elements,{" "}
              {preview.efficiency.signaturesForBatch} issuer signature vs {preview.efficiency.signaturesIfSeparate} if
              each invoice were attested separately. {preview.efficiency.aggregationNote}
            </p>
          </>
        ) : (
          <p className={styles.warn}>{preview.error ?? "Add at least one invoice to reconcile."}</p>
        )}
      </div>
      <div className={styles.vault}>
        <div className={styles.vaultHead}>
          <span>Issuer key vault</span>
          <div className={styles.vaultActions}>
            <button type="button" className={styles.ghost} onClick={() => setRevealIssuerSecret((v) => !v)}>
              {revealIssuerSecret ? "Hide secret" : "Reveal secret"}
            </button>
            <button type="button" className={styles.ghost} onClick={regenerateKey}>
              Regenerate
            </button>
          </div>
        </div>
        <div className={styles.keyGrid}>
          <div className={styles.keyCard}>
            <h4>STARK-curve Schnorr issuer key</h4>
            <dl>
              <dt>Public key · x</dt>
              <dd>{issuerKey.publicKey.x}</dd>
              <dt>Public key · y</dt>
              <dd>{issuerKey.publicKey.y}</dd>
              <dt className={styles.secretTag}>Secret key (never published)</dt>
              <dd>{revealIssuerSecret ? issuerKey.secretKey : "•".repeat(48)}</dd>
            </dl>
          </div>
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>Issue batch certificate</span>
            <h3>Reconcile &amp; sign a batch</h3>
          </div>
          <div className={styles.fields}>
            <label>
              Operator alias
              <input value={operatorAlias} onChange={(e) => setOperatorAlias(e.target.value)} />
            </label>
            <label>
              Batch reference <small>public</small>
              <input value={batchRef} onChange={(e) => setBatchRef(e.target.value)} />
            </label>
            <label className={styles.wide}>
              Batch label <small>public</small>
              <input value={batchLabel} onChange={(e) => setBatchLabel(e.target.value)} />
            </label>
            <label>
              Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} />
            </label>
            <label>
              Decimals <small>lower = faster proof</small>
              <input value={assetDecimals} inputMode="numeric" onChange={(e) => setAssetDecimals(e.target.value)} />
            </label>
            <label className={styles.wide}>
              Token address <small>provenance only</small>
              <input value={tokenAddress} onChange={(e) => setTokenAddress(e.target.value)} />
            </label>
            <label>
              Amount bit length
              <select value={amountBitLength} onChange={(e) => setAmountBitLength(e.target.value)}>
                {BIT_OPTIONS.map((bits) => (
                  <option key={bits} value={bits}>
                    {bits}-bit
                  </option>
                ))}
              </select>
            </label>
            <label>
              Memo <small>optional, public</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} />
            </label>
          </div>
          <div className={styles.queue}>
            <div className={styles.queueHead}>
              <span>Batch queue · {rows.length} invoices</span>
              <button type="button" className={styles.ghost} onClick={addRow}>
                Add invoice
              </button>
            </div>
            {rows.map((row, index) => (
              <div className={styles.queueRow} key={index}>
                <label>
                  Merchant
                  <input value={row.merchantLabel} onChange={(e) => updateRow(index, { merchantLabel: e.target.value })} />
                </label>
                <label>
                  Invoice ref
                  <input value={row.invoiceRef} onChange={(e) => updateRow(index, { invoiceRef: e.target.value })} />
                </label>
                <label>
                  Amount
                  <input value={row.amount} inputMode="decimal" onChange={(e) => updateRow(index, { amount: e.target.value })} />
                </label>
                <label>
                  Recipient <small>secret</small>
                  <input value={row.recipientRef} onChange={(e) => updateRow(index, { recipientRef: e.target.value })} />
                </label>
                <button
                  type="button"
                  className={styles.removeBtn}
                  onClick={() => removeRow(index)}
                  disabled={rows.length <= 1}
                  aria-label={`Remove invoice ${index + 1}`}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          {preview.state ? (
            <p className={styles.hint}>
              Auto-computed declared total:{" "}
              <strong>
                {formatBatchBaseUnits(preview.state.totalBaseUnits, decimals)} {assetSymbol}
              </strong>{" "}
              ({preview.state.totalBaseUnits} base units) — proven equal to the hidden per-invoice sum.
            </p>
          ) : null}
          <button type="submit" disabled={busy || !preview.state}>
            {busy ? "Proving in zero knowledge…" : "Issue batch certificate"}
          </button>
          {buildError ? <p className={styles.error}>{buildError}</p> : null}
        </form>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <span>Issued certificate</span>
            <h3>Signed batch attestation</h3>
          </div>
          {built && badge ? (
            <>
              <div className={styles.badge}>
                <div className={styles.badgeTop}>
                  <div>
                    <strong>{badge.batchLabel}</strong>
                    <small>
                      {badge.batchRef} · {badge.operatorAlias}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK-VERIFIED</span>
                </div>
                <p className={styles.badgeClaim}>
                  <b>{badge.batchTotalDisplay}</b> reconciled across {badge.invoiceCountDisplay} /{" "}
                  {badge.merchantCountDisplay}
                  <small>
                    The batch total is proven equal to the sum of the hidden per-invoice amounts, each proven
                    non-negative and in range — no individual amount or recipient is revealed.
                  </small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div>
                    <dt>Certificate ID</dt>
                    <dd>{shorten(badge.certificateId)}</dd>
                  </div>
                  <div>
                    <dt>Issued</dt>
                    <dd>{formatDate(badge.createdAt)}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.inspector}>
                <div className={styles.inspectorHead}>
                  <span>Cryptographic proof inspector</span>
                  <small>{built.certificate.proof.proofSystem}</small>
                </div>
                <dl className={styles.inspectorGrid}>
                  <div>
                    <dt>Batch root (Poseidon Merkle)</dt>
                    <dd>{shorten(built.certificate.proof.batchRoot)}</dd>
                  </div>
                  <div>
                    <dt>Binding hash</dt>
                    <dd>{shorten(built.certificate.bindingHash)}</dd>
                  </div>
                  <div>
                    <dt>Generator H · x</dt>
                    <dd>{shorten(built.certificate.proof.generatorH.x)}</dd>
                  </div>
                  <div>
                    <dt>Amount bit length</dt>
                    <dd>{built.certificate.proof.amountBitLength}-bit range proofs</dd>
                  </div>
                  <div>
                    <dt>Sum-reconciliation challenge</dt>
                    <dd>{shorten(built.certificate.proof.sumReconciliation.challenge)}</dd>
                  </div>
                  <div>
                    <dt>Sum-reconciliation response</dt>
                    <dd>{shorten(built.certificate.proof.sumReconciliation.response)}</dd>
                  </div>
                  <div>
                    <dt>Issuer signature challenge</dt>
                    <dd>{shorten(built.certificate.issuerSignature.challenge)}</dd>
                  </div>
                  <div>
                    <dt>Issuer signature response</dt>
                    <dd>{shorten(built.certificate.issuerSignature.response)}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.jurTable}>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Merchant</th>
                      <th>Invoice</th>
                      <th>Commitment · x</th>
                      <th>Leaf hash</th>
                      <th>Recipient</th>
                    </tr>
                  </thead>
                  <tbody>
                    {built.certificate.proof.invoices.map((invoice) => (
                      <tr key={invoice.index}>
                        <td>{invoice.index + 1}</td>
                        <td>{invoice.merchantLabel}</td>
                        <td>{invoice.invoiceRef}</td>
                        <td className={styles.rateCell}>{shorten(invoice.commitment.x)}</td>
                        <td>{shorten(invoice.leafHash)}</td>
                        <td className={invoice.recipientCommitted ? styles.rateCell : styles.warnCell}>
                          {invoice.recipientCommitted ? "committed" : "none"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Publishable certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`${built.certificate.certificateId}.batch.json`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              {disclosures ? (
                <div className={styles.export}>
                  <div className={styles.exportHead}>
                    <span>Selective disclosure</span>
                  </div>
                  <label className={styles.inlineField}>
                    Invoice
                    <select value={discloseIndex} onChange={(e) => setDiscloseIndex(Number(e.target.value))}>
                      {built.certificate.proof.invoices.map((invoice) => (
                        <option key={invoice.index} value={invoice.index}>
                          #{invoice.index + 1} · {invoice.merchantLabel} · {invoice.invoiceRef}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className={styles.secretActions}>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`invoice-${disclosures.index + 1}.amount.json`, disclosures.amount)}
                    >
                      Amount proof
                    </button>
                    <button
                      type="button"
                      className={styles.ghost}
                      disabled={!disclosures.recipient}
                      onClick={() => disclosures.recipient && download(`invoice-${disclosures.index + 1}.recipient.json`, disclosures.recipient)}
                    >
                      {disclosures.recipient ? "Recipient proof" : "No recipient"}
                    </button>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`invoice-${disclosures.index + 1}.inclusion.json`, disclosures.inclusion)}
                    >
                      Inclusion proof
                    </button>
                  </div>
                </div>
              ) : null}
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Issuer opening secret · never share</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>
                      {revealSecret ? "Hide" : "Reveal"}
                    </button>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`${built.certificate.certificateId}.secret.json`, serializedSecret)}
                    >
                      Download
                    </button>
                  </div>
                </div>
                {revealSecret ? (
                  <textarea readOnly value={serializedSecret} spellCheck={false} />
                ) : (
                  <p className={styles.hint}>
                    Holds every invoice amount, blinding, and recipient salt. Keep it offline; it can open the entire
                    batch.
                  </p>
                )}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>
              Build a batch queue and issue a certificate to see the badge, proof inspector, and disclosure exports.
            </p>
          )}
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.verify} onSubmit={handleVerify}>
          <div className={styles.panelHead}>
            <span>Verify</span>
            <h3>Check a batch certificate</h3>
          </div>
          <label className={styles.inlineField}>
            Certificate (base64url)
            <textarea
              value={verifyCertInput}
              onChange={(e) => setVerifyCertInput(e.target.value)}
              placeholder="Paste a serialized batch certificate…"
              spellCheck={false}
            />
          </label>
          <label className={styles.inlineField}>
            Optional disclosure <small>amount · recipient · inclusion</small>
            <textarea
              value={verifyDisclosureInput}
              onChange={(e) => setVerifyDisclosureInput(e.target.value)}
              placeholder="Paste a selective-disclosure proof to check it against the certificate…"
              spellCheck={false}
            />
          </label>
          <button type="submit" disabled={!verifyCertInput.trim()}>
            Verify certificate
          </button>
          {verifyState ? (
            verifyState.error ? (
              <div className={styles.fail}>
                <strong>Could not parse</strong>
                <small>{verifyState.error}</small>
              </div>
            ) : (
              <div className={verifyState.certificateOk ? styles.pass : styles.fail}>
                <strong>{verifyState.certificateOk ? "Certificate valid" : "Certificate invalid"}</strong>
                {verifyState.certificate ? (
                  <dl className={styles.resultMeta}>
                    <div>
                      <dt>Batch</dt>
                      <dd>{verifyState.certificate.batchRef}</dd>
                    </div>
                    <div>
                      <dt>Declared total</dt>
                      <dd>{verifyState.certificate.declaredBatchTotalBaseUnits}</dd>
                    </div>
                    <div>
                      <dt>Invoices</dt>
                      <dd>{verifyState.certificate.invoiceCount}</dd>
                    </div>
                    <div>
                      <dt>Merchants</dt>
                      <dd>{verifyState.certificate.merchantCount}</dd>
                    </div>
                  </dl>
                ) : null}
                {verifyState.disclosure ? (
                  <small className={verifyState.disclosure.ok ? styles.yes : styles.no}>
                    {verifyState.disclosure.ok ? "✓ disclosure verified" : "✗ disclosure rejected"} —{" "}
                    {verifyState.disclosure.detail}
                  </small>
                ) : null}
              </div>
            )
          ) : null}
        </form>
        <div className={styles.model}>
          <div>
            <h4>Hidden from the verifier</h4>
            <ul>
              {VISIBILITY.hiddenFromVerifier.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <h4>Disclosed to the verifier</h4>
            <ul>
              {VISIBILITY.disclosedToVerifier.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <h4>Application-only (local)</h4>
            <ul>
              {VISIBILITY.applicationOnly.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      <div className={styles.limitation}>
        <p>{VISIBILITY.limitation}</p>
        <p className={styles.statement}>{TRUST.statement}</p>
      </div>
    </section>
  );
}
