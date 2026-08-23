"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import {
  TAX_AUDIT_POOL_ADDRESS,
  buildTaxAuditAuthorization,
  buildTaxAuditBundle,
  buildTaxAuditBundleDigest,
  createTaxAuditProfile,
  formatTaxAuditBaseUnits,
  getTaxAuditVisibilityModel,
  proveEntryInclusion,
  recordSettledInvoice,
  registerTaxAuditExporterKey,
  serializeTaxAuditAuthorization,
  serializeTaxAuditBundle,
  serializeTaxAuditBundleDigest,
  serializeTaxAuditInclusionProof,
  summarizeTaxAuditTrust,
  verifyTaxAuditAuthorization,
  type TaxAuditBundle,
  type TaxAuditEntry,
  type TaxAuditExporterKey,
  type TaxAuditProfile,
} from "@/lib/tax-audit-engine";
import { STRK_TOKEN_ADDRESS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";

import styles from "./tax-audit-portal.module.css";

type BusyAction = "profile" | "record" | "bundle" | "inclusion" | "auth" | null;

const INTRO =
  "Create a tax-audit profile, record your settled invoices as salted commitments in this browser, then aggregate a date range into a tamper-evident bundle. CipherBill totals every asset and category with exact integer math and builds a Merkle root over the entries. Nothing is sent on-chain, nothing is filed automatically, and the settlement hashes it cites are already-public pool edges.";

/** Abbreviates a long hex value (address or hash) for display; short values pass through unchanged. */
function shorten(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

/** Renders an ISO timestamp as a short local date; falls back to the raw string if unparseable. */
function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** A calendar date from an <input type="date"> becomes the full-day UTC instant the engine's ISO check accepts. */
function toIsoTimestamp(date: string): string {
  return `${date}T00:00:00.000Z`;
}

/** Streams a text payload to a downloaded file; the copyable textarea stays as a fallback if a browser blocks it. */
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

/**
 * Merchant tax & compliance audit export console for the CipherBill dashboard.
 *
 * Every claim here is deliberately narrow. A merchant records settled invoices in this browser, aggregates a
 * date range into a tamper-evident bundle with exact per-asset and per-category totals and a Merkle root, and
 * discloses a redacted digest, a single-entry inclusion proof, or a zero-knowledge export authorization. It is
 * not decentralized, not automatic, and not zero-knowledge as a system: no contract records or files anything,
 * the entries are local merchant assertions, and the only zero-knowledge element is the export authorization
 * proving knowledge of an exporter key. It needs no wallet — an export never moves funds.
 */
export function TaxAuditPortal() {
  const [open, setOpen] = useState(false);
  const [merchant, setMerchant] = useState("");
  const [jurisdiction, setJurisdiction] = useState("US-CA");
  const [profileMemo, setProfileMemo] = useState("");
  const [profile, setProfile] = useState<TaxAuditProfile | null>(null);

  const [invoiceId, setInvoiceId] = useState("inv_001");
  const [transactionHash, setTransactionHash] = useState("");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetToken, setAssetToken] = useState(STRK_TOKEN_ADDRESS);
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [gross, setGross] = useState("");
  const [fee, setFee] = useState("");
  const [category, setCategory] = useState("sales");
  const [settledAt, setSettledAt] = useState("2026-07-15");
  const [counterpartyRef, setCounterpartyRef] = useState("");
  const [entryMemo, setEntryMemo] = useState("");
  const [entries, setEntries] = useState<TaxAuditEntry[]>([]);

  const [periodStart, setPeriodStart] = useState("2026-07-01");
  const [periodEnd, setPeriodEnd] = useState("2026-07-31");
  const [bundle, setBundle] = useState<TaxAuditBundle | null>(null);

  const [bundleText, setBundleText] = useState("");
  const [digestText, setDigestText] = useState("");
  const [inclusionEntryId, setInclusionEntryId] = useState("");
  const [inclusionText, setInclusionText] = useState("");
  const [exporterKey, setExporterKey] = useState<TaxAuditExporterKey | null>(null);
  const [authText, setAuthText] = useState("");
  const [authVerified, setAuthVerified] = useState<boolean | null>(null);

  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState(INTRO);

  const visibility = useMemo(() => getTaxAuditVisibilityModel(), []);
  const trust = useMemo(() => summarizeTaxAuditTrust(), []);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, open]);

  /** Any bundle and its derived artifacts go stale the moment the entry set changes; drop them together. */
  function resetExports(): void {
    setBundle(null);
    setBundleText("");
    setDigestText("");
    setInclusionEntryId("");
    setInclusionText("");
    setExporterKey(null);
    setAuthText("");
    setAuthVerified(null);
  }

  function setUpProfile(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("profile");
    try {
      const next = createTaxAuditProfile({ merchant, jurisdiction: jurisdiction || undefined, memo: profileMemo || undefined });
      setProfile(next);
      setEntries([]);
      resetExports();
      setMessage(`Profile ${next.profileId} created${next.jurisdiction ? ` for ${next.jurisdiction}` : ""}. The merchant address, memo, and every entry live in this browser under salted commitments — none of it is on-chain.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The profile could not be created.");
    } finally {
      setBusy(null);
    }
  }
  function recordInvoice(event: FormEvent): void {
    event.preventDefault();
    if (!profile || busy) return;
    setBusy("record");
    try {
      const entry = recordSettledInvoice(profile, {
        invoiceId,
        transactionHash,
        asset: { symbol: assetSymbol, tokenAddress: assetToken, decimals: Number(assetDecimals) },
        gross,
        fee: fee || undefined,
        category,
        settledAt: toIsoTimestamp(settledAt),
        counterpartyRef: counterpartyRef || undefined,
        memo: entryMemo || undefined,
      });
      setEntries((current) => [...current, entry]);
      resetExports();
      setGross("");
      setFee("");
      setMessage(`Recorded ${formatTaxAuditBaseUnits(entry.netBaseUnits, entry.assetDecimals)} ${entry.assetSymbol} net on ${entry.invoiceId} under "${entry.category}". This is a local, salted record binding the invoice to its settlement hash — not proof the invoice is real, paid, or completely recorded.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The settled invoice could not be recorded.");
    } finally {
      setBusy(null);
    }
  }

  function removeEntry(entryId: string): void {
    setEntries((current) => current.filter((entry) => entry.entryId !== entryId));
    resetExports();
  }

  function assemble(event: FormEvent): void {
    event.preventDefault();
    if (!profile || busy) return;
    setBusy("bundle");
    try {
      const next = buildTaxAuditBundle(profile, entries, { periodStart, periodEnd });
      setBundle(next);
      setBundleText(serializeTaxAuditBundle(next));
      setDigestText("");
      setInclusionEntryId(next.entries[0]?.entryId ?? "");
      setInclusionText("");
      setExporterKey(null);
      setAuthText("");
      setAuthVerified(null);
      setMessage(`Bundle ${next.bundleId} aggregates ${next.entryCount} in-period entr${next.entryCount === 1 ? "y" : "ies"} across ${next.assetTotals.length} asset${next.assetTotals.length === 1 ? "" : "s"}. The Merkle root, period, and totals are bound under one commitment; recomputing them detects any later change. It proves tamper-evidence, not that the set is complete or truthful.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The audit bundle could not be built.");
    } finally {
      setBusy(null);
    }
  }
  function shareDigest(): void {
    if (!bundle || busy) return;
    try {
      setDigestText(serializeTaxAuditBundleDigest(buildTaxAuditBundleDigest(bundle)));
      setMessage("Redacted digest built. It carries the period, entry count, Merkle root, and per-asset and per-category totals — never the invoice ids, settlement hashes, counterparty references, or memos. An auditor verifies it against a full bundle opening.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The bundle digest could not be built.");
    }
  }

  function proveInclusion(): void {
    if (!bundle || !inclusionEntryId || busy) return;
    setBusy("inclusion");
    try {
      const proof = proveEntryInclusion(bundle, inclusionEntryId);
      setInclusionText(serializeTaxAuditInclusionProof(proof));
      setMessage(`Inclusion proof built for ${proof.entry.invoiceId}. It discloses this one entry in full and proves it belongs to the committed Merkle root without revealing the others. This is selective disclosure, not a zero-knowledge proof.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The inclusion proof could not be built.");
    } finally {
      setBusy(null);
    }
  }

  function authorize(): void {
    if (!bundle || busy) return;
    setBusy("auth");
    try {
      const key = exporterKey ?? registerTaxAuditExporterKey();
      const auth = buildTaxAuditAuthorization(bundle, key);
      const verified = verifyTaxAuditAuthorization(auth, bundle);
      setExporterKey(key);
      setAuthText(serializeTaxAuditAuthorization(auth));
      setAuthVerified(verified);
      setMessage(verified
        ? "Export authorization proved and verified. This is the only genuine zero-knowledge element: a Schnorr proof that the holder knows the exporter key bound to this bundle's root, period, and totals. It reveals nothing about the key and does not vouch that the invoices are complete or truthful."
        : "The authorization did not verify against the exporter key.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The export authorization could not be built.");
    } finally {
      setBusy(null);
    }
  }

  async function copy(text: string): Promise<void> {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setMessage("Copied to the clipboard.");
    } catch {
      setMessage("The clipboard is unavailable; select and copy the text manually.");
    }
  }

  function resetWorkspace(): void {
    setProfile(null);
    setEntries([]);
    resetExports();
    setMessage(INTRO);
  }
  return (
    <section className={styles.launch} id="tax-audit">
      <div className={styles.launchCopy}>
        <span>Tax &amp; compliance</span>
        <h2>Export <em>auditor-ready</em> proof, keep the PII local.</h2>
        <p>
          CipherBill lets a merchant record settled invoices in this browser, aggregate any date range into a
          tamper-evident bundle with exact per-asset and per-category totals, and share a redacted digest, a
          single-entry inclusion proof, or a zero-knowledge export authorization. No contract files anything,
          and the settlement hashes it cites are already-public pool edges.
        </p>
        <button type="button" onClick={() => setOpen(true)}>Open the audit console →</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not decentralized</strong><span>The profile, entries, bundle, and every total are computed in this browser. There is no on-chain registry or audit contract.</span></div>
        <div><strong>Not automatic</strong><span>Nothing files a return. A merchant records each settled invoice and assembles an export by hand.</span></div>
        <div><strong>Tamper-evident, not truth</strong><span>Recomputing the commitments and Merkle root detects any change — it cannot prove the set is complete or the categories correct.</span></div>
      </div>
      {open && renderModal()}
    </section>
  );

  function renderModal() {
    return (
      <div className={styles.backdrop} role="presentation" onClick={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
        <div className={styles.modal} role="dialog" aria-modal="true" aria-label="Tax and compliance audit console">
          <div className={styles.modalHeader}>
            <div>
              <span>CipherBill · tax &amp; compliance export</span>
              <h2>Merchant audit export console</h2>
              <p>Pool <code>{shorten(TAX_AUDIT_POOL_ADDRESS)}</code> · Starknet mainnet · every bundle is a local, tamper-evident record — never an on-chain filing</p>
            </div>
            <button type="button" aria-label="Close" onClick={() => { if (!busy) setOpen(false); }}>×</button>
          </div>
          <div className={styles.truth}>
            <div><b>Not a filer</b><span>No contract aggregates or files anything. The merchant assembles each export by hand.</span></div>
            <div><b>Records are claims</b><span>Entries are the merchant&apos;s local assertions; the engine cannot prove an invoice is real or complete.</span></div>
            <div><b>Edges are public</b><span>The settlement hashes, deposits, withdrawals, and timing the entries cite are observable.</span></div>
            <div><b>One zero-knowledge part</b><span>Only the export authorization is a real zero-knowledge proof — of knowing the exporter key, nothing more.</span></div>
          </div>
          {profile ? renderWorkspace() : renderComposer()}
          {message && <p className={styles.message}>{message}</p>}
        </div>
      </div>
    );
  }
  function renderComposer() {
    return (
      <form className={styles.form} onSubmit={setUpProfile}>
        <fieldset className={styles.fieldset}>
          <legend>Tax-audit profile</legend>
          <div className={styles.fields}>
            <label className={styles.wide}>Merchant (in-pool address)
              <input value={merchant} onChange={(e) => setMerchant(e.target.value)} placeholder="0x…" />
            </label>
            <label>Jurisdiction (optional)
              <input value={jurisdiction} onChange={(e) => setJurisdiction(e.target.value)} placeholder="US-CA" />
            </label>
            <span />
            <label className={styles.wide}>Memo (optional, local only)
              <input value={profileMemo} onChange={(e) => setProfileMemo(e.target.value)} placeholder="FY2026 exports" />
            </label>
          </div>
        </fieldset>
        <div className={styles.actions}>
          <button type="button" className={styles.ghost} onClick={() => setOpen(false)} disabled={busy !== null}>Cancel</button>
          <button type="submit" disabled={busy !== null}>{busy === "profile" ? "Creating…" : "Create profile"}</button>
        </div>
      </form>
    );
  }

  function renderWorkspace() {
    if (!profile) return null;
    return (
      <div className={styles.plan}>
        <aside className={styles.sidebar}>
          <span>Tax-audit profile</span>
          <div className={styles.headline}>
            <strong>{profile.jurisdiction || "No jurisdiction"}</strong>
            <small>{entries.length} settled invoice{entries.length === 1 ? "" : "s"} recorded locally</small>
          </div>
          <dl>
            <div><dt>Profile</dt><dd>{shorten(profile.profileId)}</dd></div>
            <div><dt>Merchant</dt><dd>{shorten(profile.merchant)}</dd></div>
            <div><dt>Entries</dt><dd>{entries.length}</dd></div>
            <div><dt>Bundle</dt><dd>{bundle ? shorten(bundle.bundleId) : "none yet"}</dd></div>
            <div><dt>In-period</dt><dd>{bundle ? bundle.entryCount : "—"}</dd></div>
            <div><dt>Merkle root</dt><dd>{bundle ? shorten(bundle.merkleRoot) : "—"}</dd></div>
          </dl>
          <button type="button" className={styles.ghost} onClick={resetWorkspace} disabled={busy !== null}>Reset console</button>
        </aside>
        <div className={styles.main}>
          {renderEntries()}
          {renderBundle()}
          {renderExports()}
          {renderDisclosure()}
        </div>
      </div>
    );
  }
  function renderEntries() {
    if (!profile) return null;
    return (
      <div className={styles.card}>
        <div><span>Settled invoices</span></div>
        <h3>Record the invoices you settled through the pool</h3>
        <p>Each entry is a local, salted commitment binding an invoice, its settlement transaction hash, the asset, a gross amount, an optional fee disclosure, and a tax category. CipherBill totals them with exact integer math; it cannot prove an invoice is real, paid, or completely recorded.</p>
        <form className={styles.form} onSubmit={recordInvoice}>
          <div className={styles.fields}>
            <label>Invoice ID
              <input value={invoiceId} onChange={(e) => setInvoiceId(e.target.value)} placeholder="inv_001" />
            </label>
            <label>Category
              <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="sales" />
            </label>
            <label>Settled on
              <input type="date" value={settledAt} onChange={(e) => setSettledAt(e.target.value)} />
            </label>
            <label>Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} placeholder="STRK" />
            </label>
            <label className={styles.wide}>Settlement transaction hash
              <input value={transactionHash} onChange={(e) => setTransactionHash(e.target.value)} placeholder="0x…" />
            </label>
            <label className={styles.wide}>Token address
              <input value={assetToken} onChange={(e) => setAssetToken(e.target.value)} placeholder="0x…" />
            </label>
            <label>Decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" placeholder="18" />
            </label>
            <label>Gross ({assetSymbol})
              <input value={gross} onChange={(e) => setGross(e.target.value)} inputMode="decimal" placeholder="1000" />
            </label>
            <label>Fee ({assetSymbol}, optional)
              <input value={fee} onChange={(e) => setFee(e.target.value)} inputMode="decimal" placeholder="20" />
            </label>
            <label>Counterparty (optional, local)
              <input value={counterpartyRef} onChange={(e) => setCounterpartyRef(e.target.value)} placeholder="acme-co" />
            </label>
            <label className={styles.wide}>Memo (optional, local only)
              <input value={entryMemo} onChange={(e) => setEntryMemo(e.target.value)} placeholder="Q3 retainer" />
            </label>
          </div>
          <div className={styles.actions}>
            <button type="submit" disabled={busy !== null}>{busy === "record" ? "Recording…" : "Record settled invoice"}</button>
          </div>
        </form>
        {renderLedger()}
      </div>
    );
  }
  function renderLedger() {
    if (entries.length === 0) return <p className={styles.code}>No settled invoices recorded yet.</p>;
    return (
      <div className={styles.ledger}>
        {entries.map((entry) => (
          <div key={entry.entryId} className={styles.ledgerRow}>
            <div>
              <strong>{entry.invoiceId}</strong>
              <small>{entry.category} · {formatDate(entry.settledAt)}</small>
            </div>
            <span>
              <a className={styles.link} href={getStarknetExplorerTransactionUrl(entry.transactionHash)} target="_blank" rel="noreferrer">{shorten(entry.transactionHash)} ↗</a>
            </span>
            <span>{formatTaxAuditBaseUnits(entry.netBaseUnits, entry.assetDecimals)} {entry.assetSymbol}</span>
            <button type="button" className={styles.rowButton} onClick={() => removeEntry(entry.entryId)}>Remove</button>
          </div>
        ))}
      </div>
    );
  }

  function renderBundle() {
    if (!profile) return null;
    return (
      <div className={styles.card}>
        <div><span>Audit bundle</span></div>
        <h3>Aggregate a date range into a tamper-evident bundle</h3>
        <p>Choose a period; CipherBill filters the settled invoices into it, sums per-asset and per-category totals with exact integer math, and builds a Merkle root over the entry commitments. The root, period, and totals are bound under one commitment.</p>
        <form className={styles.fields} onSubmit={assemble}>
          <label>Period start
            <input type="date" value={periodStart} onChange={(e) => setPeriodStart(e.target.value)} />
          </label>
          <label>Period end
            <input type="date" value={periodEnd} onChange={(e) => setPeriodEnd(e.target.value)} />
          </label>
          <span />
          <div className={styles.actions}>
            <button type="submit" disabled={busy !== null || entries.length === 0}>{busy === "bundle" ? "Building…" : "Build bundle"}</button>
          </div>
        </form>
        {bundle && renderTotals()}
      </div>
    );
  }
  function renderTotals() {
    if (!bundle) return null;
    return (
      <>
        <div className={styles.metrics}>
          <div className={styles.metric}><span>In-period entries</span><b>{bundle.entryCount}</b><small>of {entries.length} recorded</small></div>
          <div className={styles.metric}><span>Assets</span><b>{bundle.assetTotals.length}</b><small>distinct tokens</small></div>
          <div className={styles.metric}><span>Categories</span><b>{bundle.categoryTotals.length}</b><small>category × asset</small></div>
          <div className={styles.metric}><span>Generated</span><b>{formatDate(bundle.generatedAt)}</b><small>{bundle.periodStart.slice(0, 10)} → {bundle.periodEnd.slice(0, 10)}</small></div>
        </div>
        <p className={styles.code}>Merkle root {bundle.merkleRoot}</p>
        <div className={styles.totals}>
          <div className={styles.totalRow}>
            <strong className={styles.totalHead}>Asset</strong>
            <span className={styles.totalHead}>Entries</span>
            <span className={styles.totalHead}>Gross</span>
            <span className={styles.totalHead}>Net</span>
          </div>
          {bundle.assetTotals.map((total) => (
            <div key={total.assetTokenAddress} className={styles.totalRow}>
              <strong>{total.assetSymbol}<small>{shorten(total.assetTokenAddress)}</small></strong>
              <span>{total.entryCount}</span>
              <span>{total.grossDisplay}</span>
              <span>{total.netDisplay}</span>
            </div>
          ))}
        </div>
        <div className={styles.totals}>
          <div className={styles.totalRow}>
            <strong className={styles.totalHead}>Category</strong>
            <span className={styles.totalHead}>Entries</span>
            <span className={styles.totalHead}>Gross</span>
            <span className={styles.totalHead}>Net</span>
          </div>
          {bundle.categoryTotals.map((total) => (
            <div key={`${total.category} ${total.assetTokenAddress}`} className={styles.totalRow}>
              <strong>{total.category}<small>{total.assetSymbol}</small></strong>
              <span>{total.entryCount}</span>
              <span>{total.grossDisplay}</span>
              <span>{total.netDisplay}</span>
            </div>
          ))}
        </div>
      </>
    );
  }
  function renderExports() {
    if (!bundle) return null;
    return (
      <div className={styles.card}>
        <div><span>Auditor export package</span></div>
        <h3>Copy or download the tamper-evident artifacts</h3>
        <p>The full bundle carries every entry and total. The redacted digest and single-entry inclusion proof are selective disclosures; the export authorization is the only zero-knowledge proof. The bundle is a local record, not an on-chain fact — verify the cited settlement hashes on the explorer.</p>
        <div className={styles.share}>
          <textarea readOnly value={bundleText} aria-label="Full audit bundle" />
          <div>
            <button type="button" onClick={() => copy(bundleText)}>Copy bundle</button>
            <button type="button" className={styles.ghost} onClick={() => download(`cipherbill-tax-audit-bundle-${bundle.bundleId}.txt`, bundleText)}>Download bundle</button>
          </div>
        </div>
        <div className={styles.opsRow}>
          <div>
            <span>Redacted digest</span>
            <h4>Aggregates only</h4>
            <p>Period, entry count, Merkle root, and totals — never any per-entry PII.</p>
            <button type="button" onClick={shareDigest} disabled={busy !== null}>Build digest</button>
          </div>
          <div>
            <span>Inclusion proof</span>
            <h4>Disclose one entry</h4>
            <select value={inclusionEntryId} onChange={(e) => setInclusionEntryId(e.target.value)}>
              {bundle.entries.map((entry) => (
                <option key={entry.entryId} value={entry.entryId}>{entry.invoiceId} · {shorten(entry.entryId)}</option>
              ))}
            </select>
            <button type="button" onClick={proveInclusion} disabled={busy !== null || !inclusionEntryId}>{busy === "inclusion" ? "Proving…" : "Prove inclusion"}</button>
          </div>
          <div>
            <span>Export authorization · zero-knowledge</span>
            <h4>{authVerified === null ? "Not proved yet" : authVerified ? "Verified" : "Did not verify"}{authVerified !== null && <span className={`${styles.badge} ${authVerified ? "" : styles.badgeBad}`}>{authVerified ? "✓" : "✗"}</span>}</h4>
            <p>{exporterKey ? `Exporter public key ${shorten(exporterKey.exporterPublicKey.x)} — the secret stays in this browser and is never shown.` : "Generates an exporter key in this browser and proves knowledge of it bound to this bundle."}</p>
            <button type="button" onClick={authorize} disabled={busy !== null}>{busy === "auth" ? "Proving…" : authText ? "Re-prove authorization" : "Prove & verify"}</button>
          </div>
        </div>
        {digestText && (
          <div className={styles.share}>
            <textarea readOnly value={digestText} aria-label="Redacted bundle digest" />
            <div>
              <button type="button" onClick={() => copy(digestText)}>Copy digest</button>
              <button type="button" className={styles.ghost} onClick={() => download(`cipherbill-tax-audit-digest-${bundle.bundleId}.txt`, digestText)}>Download digest</button>
            </div>
          </div>
        )}
        {inclusionText && (
          <div className={styles.share}>
            <textarea readOnly value={inclusionText} aria-label="Merkle inclusion proof" />
            <div>
              <button type="button" onClick={() => copy(inclusionText)}>Copy proof</button>
              <button type="button" className={styles.ghost} onClick={() => download(`cipherbill-tax-audit-inclusion-${bundle.bundleId}.txt`, inclusionText)}>Download proof</button>
            </div>
          </div>
        )}
        {authText && (
          <div className={styles.share}>
            <textarea readOnly value={authText} aria-label="Export authorization" />
            <div>
              <button type="button" onClick={() => copy(authText)}>Copy authorization</button>
              <button type="button" className={styles.ghost} onClick={() => download(`cipherbill-tax-audit-authorization-${bundle.bundleId}.txt`, authText)}>Download authorization</button>
            </div>
          </div>
        )}
      </div>
    );
  }
  function renderDisclosure() {
    return (
      <div className={styles.card}>
        <div><span>Honest disclosure model</span></div>
        <h3>What stays local, what is public, what is trusted</h3>
        <div className={styles.visibility}>
          <div>
            <span>Application-only (this browser)</span>
            {visibility.applicationOnly.map((entry) => <p key={entry}>{entry}</p>)}
          </div>
          <div>
            <span>Hidden inside the pool</span>
            {visibility.hiddenInPool.map((entry) => <p key={entry}>{entry}</p>)}
          </div>
          <div>
            <span>Public or observable</span>
            {visibility.publicOrObservable.map((entry) => <p key={entry}>{entry}</p>)}
          </div>
          <div>
            <span>Trust summary</span>
            <p>Decentralized: {trust.isDecentralized ? "yes" : "no"} · Automatic: {trust.isAutomatic ? "yes" : "no"} · Proves tamper-evidence: {trust.provesTamperEvidence ? "yes" : "no"} · Proves completeness: {trust.provesCompleteness ? "yes" : "no"} · Proves truthfulness: {trust.provesTruthfulness ? "yes" : "no"}</p>
          </div>
        </div>
        <ul className={styles.trustList}>
          <li>{trust.statement}</li>
          <li>{trust.zeroKnowledgeElement}</li>
          {trust.trustedParties.map((party) => <li key={party}>Trusted: {party}</li>)}
        </ul>
        <span className={styles.limitation}>{visibility.limitation}</span>
        {profile?.limitations.map((limit) => <span key={limit} className={styles.limitation}>{limit}</span>)}
      </div>
    );
  }

}
