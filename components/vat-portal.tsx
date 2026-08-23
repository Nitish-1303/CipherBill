"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  VAT_POOL_ADDRESS,
  buildVatTaxDisclosure,
  buildVatTaxIdDisclosure,
  buildVatVoucherBadge,
  computeVat,
  createVatIssuerKey,
  formatVatBaseUnits,
  formatVatRate,
  getVatJurisdictions,
  getVatVisibilityModel,
  issueVatVoucher,
  parseVatTaxDisclosure,
  parseVatTaxIdDisclosure,
  parseVatVoucher,
  serializeVatTaxDisclosure,
  serializeVatTaxIdDisclosure,
  serializeVatVoucher,
  serializeVatVoucherSecret,
  summarizeVatTrust,
  verifyVatTaxDisclosure,
  verifyVatTaxIdDisclosure,
  verifyVatVoucher,
  type IssuedVatVoucher,
  type VatKeypair,
  type VatVoucher,
} from "@/lib/vat-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./vat-portal.module.css";

const INTRO =
  "Compute a jurisdiction-specific indirect tax at a public statutory rate and prove, in zero knowledge, that the committed tax equals the exact floor-division of a committed net amount — tax = floor(net × rate ÷ 10000) — without revealing the net, gross, or tax, while binding the customer tax ID under a salted commitment. The merchant signs the voucher so anyone can authenticate it offline. It does not file, remit, or settle any tax, and never calls the STRK20 pool contract.";

const TRUST = summarizeVatTrust();
const VISIBILITY = getVatVisibilityModel();
const JURISDICTIONS = getVatJurisdictions();

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

interface DisclosureResult {
  type: "tax" | "taxId";
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  voucher?: VatVoucher;
  disclosure?: DisclosureResult;
  error?: string;
}
export function VatPortal() {
  // Key vault
  const [issuerKey, setIssuerKey] = useState<VatKeypair | null>(null);
  const [revealIssuerSecret, setRevealIssuerSecret] = useState(false);

  // Issue form
  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState(18);
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [invoiceRef, setInvoiceRef] = useState("INV-2026-0007");
  const [jurisdictionCode, setJurisdictionCode] = useState("GB");
  const [rateBasisPoints, setRateBasisPoints] = useState("2000");
  const [netAmount, setNetAmount] = useState("1000.00");
  const [customerTaxId, setCustomerTaxId] = useState("GB123456789");
  const [memo, setMemo] = useState("");
  const [issuerSecretInput, setIssuerSecretInput] = useState("");

  const [built, setBuilt] = useState<IssuedVatVoucher | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealTaxId, setRevealTaxId] = useState(false);

  // Verify inputs
  const [verifyVoucherInput, setVerifyVoucherInput] = useState("");
  const [verifyDisclosureInput, setVerifyDisclosureInput] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState | null>(null);

  const selected = useMemo(() => JURISDICTIONS.find((j) => j.code === jurisdictionCode), [jurisdictionCode]);
  const jurisdictionLabel = selected?.label ?? "Custom rate";
  const taxKind = selected?.taxKind ?? "VAT";

  /** Live, pre-issue tax breakdown; hidden once issued and always local to this browser. */
  const preview = useMemo(() => {
    try {
      const netBaseUnits = decimalToBaseUnits(netAmount.trim(), assetDecimals);
      const rate = Number(rateBasisPoints);
      if (!Number.isInteger(rate)) return null;
      const c = computeVat(netBaseUnits, rate);
      return {
        net: formatVatBaseUnits(c.netBaseUnits, assetDecimals),
        tax: formatVatBaseUnits(c.taxBaseUnits, assetDecimals),
        gross: formatVatBaseUnits(c.grossBaseUnits, assetDecimals),
        rate: formatVatRate(c.rateBasisPoints),
      };
    } catch {
      return null;
    }
  }, [netAmount, rateBasisPoints, assetDecimals]);

  const serializedVoucher = useMemo(() => (built ? serializeVatVoucher(built.voucher) : ""), [built]);
  const serializedSecret = useMemo(() => (built ? serializeVatVoucherSecret(built.secret) : ""), [built]);
  const serializedTaxDisclosure = useMemo(() => (built ? serializeVatTaxDisclosure(buildVatTaxDisclosure(built.secret)) : ""), [built]);
  const serializedTaxIdDisclosure = useMemo(
    () => (built && built.secret.taxIdCommitted ? serializeVatTaxIdDisclosure(buildVatTaxIdDisclosure(built.secret)) : ""),
    [built],
  );
  const badge = useMemo(() => (built ? buildVatVoucherBadge(built.voucher) : null), [built]);

  function generateIssuerKey() {
    const key = createVatIssuerKey();
    setIssuerKey(key);
    setIssuerSecretInput(key.secretKey);
    setRevealIssuerSecret(false);
  }

  function selectJurisdiction(code: string) {
    setJurisdictionCode(code);
    const next = JURISDICTIONS.find((j) => j.code === code);
    if (next && next.code !== "CUSTOM") setRateBasisPoints(String(next.standardRateBasisPoints));
  }
  function handleIssue(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setBuildError(null);
    setRevealSecret(false);
    setRevealTaxId(false);
    try {
      const netBaseUnits = decimalToBaseUnits(netAmount.trim(), assetDecimals);
      const rate = Number(rateBasisPoints.trim());
      const result = issueVatVoucher(
        {
          merchantAlias: merchantAlias.trim(),
          asset: { symbol: assetSymbol.trim(), tokenAddress: tokenAddress.trim(), decimals: assetDecimals },
          invoiceRef: invoiceRef.trim(),
          jurisdictionCode: jurisdictionCode.trim(),
          jurisdictionLabel,
          taxKind,
          rateBasisPoints: rate,
          netBaseUnits,
          customerTaxId: customerTaxId.trim() || undefined,
          issuerSecretKey: issuerSecretInput.trim(),
          memo: memo.trim() || undefined,
        },
        new Date(),
      );
      setBuilt(result);
    } catch (error) {
      setBuilt(null);
      setBuildError(error instanceof Error ? error.message : "Could not issue the VAT voucher.");
    } finally {
      setBusy(false);
    }
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const voucher = parseVatVoucher(verifyVoucherInput.trim());
      const ok = verifyVatVoucher(voucher);
      let disclosure: DisclosureResult | undefined;
      const raw = verifyDisclosureInput.trim();
      if (raw) {
        try {
          const tax = parseVatTaxDisclosure(raw);
          disclosure = {
            type: "tax",
            ok: verifyVatTaxDisclosure(voucher, tax),
            value: `${formatVatBaseUnits(tax.taxBaseUnits, voucher.assetDecimals)} ${voucher.assetSymbol}`,
          };
        } catch {
          const taxId = parseVatTaxIdDisclosure(raw);
          disclosure = { type: "taxId", ok: verifyVatTaxIdDisclosure(voucher, taxId), value: taxId.customerTaxId || "(empty)" };
        }
      }
      setVerifyState({ ok, voucher, disclosure });
    } catch (error) {
      setVerifyState({ ok: false, error: error instanceof Error ? error.message : "Could not decode the voucher." });
    }
  }
  return (
    <section className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Cross-Border VAT &amp; Indirect Tax</span>
          <h2>Zero-knowledge <em>tax vouchers</em></h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(VAT_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div><dt>tax = floor(net × rate ÷ 10000)</dt><dd className={styles.yes}>ZK proven</dd></div>
          <div><dt>Issuer signature</dt><dd className={styles.yes}>Authenticated</dd></div>
          <div><dt>Files / remits tax</dt><dd className={styles.no}>Never</dd></div>
          <div><dt>Pool contract</dt><dd className={styles.no}>Never called</dd></div>
        </dl>
      </header>

      <div className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Compliance dashboard · live estimate</span>
          <small>Local to this browser · illustrative rates, not tax advice</small>
        </div>
        <dl className={styles.dashGrid}>
          <div className={styles.metric}><dt>Net (pre-tax)</dt><dd>{preview ? `${preview.net} ${assetSymbol}` : "—"}</dd></div>
          <div className={`${styles.metric} ${styles.effective}`}><dt>{taxKind} @ {preview ? preview.rate : formatVatRate(rateBasisPoints || "0")}</dt><dd>{preview ? `${preview.tax} ${assetSymbol}` : "—"}</dd></div>
          <div className={styles.metric}><dt>Gross total</dt><dd>{preview ? `${preview.gross} ${assetSymbol}` : "—"}</dd></div>
          <div className={styles.metric}><dt>Jurisdiction</dt><dd>{jurisdictionCode}</dd></div>
        </dl>
        <div className={styles.tableWrap}>
          <table className={styles.jurTable}>
            <thead><tr><th>Code</th><th>Jurisdiction</th><th>Kind</th><th>Standard rate</th><th className={styles.noteCell}>Note</th></tr></thead>
            <tbody>
              {JURISDICTIONS.map((j) => (
                <tr key={j.code}>
                  <td>{j.code}</td>
                  <td>{j.label}</td>
                  <td>{j.taxKind}</td>
                  <td className={styles.rateCell}>{j.code === "CUSTOM" ? "—" : formatVatRate(j.standardRateBasisPoints)}</td>
                  <td className={styles.noteCell}>{j.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className={styles.vault}>
        <div className={styles.vaultHead}>
          <span>00 · Issuer key vault</span>
          <div className={styles.vaultActions}>
            <button type="button" className={styles.ghost} onClick={generateIssuerKey}>Generate issuer key</button>
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
                <dd>{revealIssuerSecret ? issuerKey.secretKey : "•••••••• — the merchant keeps this to sign and open vouchers"}</dd>
              </dl>
            ) : (
              <p className={styles.hint}>Generate a signing key, or paste an existing issuer secret into the issue form. The same key signs the voucher and later opens selective disclosures.</p>
            )}
          </div>
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue</span>
            <h3>Cryptographic tax voucher</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} placeholder="Aurora Studio" />
            </label>
            <label>Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} placeholder="STRK" />
            </label>
            <label>Decimals
              <input type="number" min={0} max={18} value={assetDecimals} onChange={(e) => setAssetDecimals(Number(e.target.value))} />
            </label>
            <label className={styles.wide}>Token address <small>provenance only — never called</small>
              <input value={tokenAddress} onChange={(e) => setTokenAddress(e.target.value)} spellCheck={false} />
            </label>
            <label className={styles.wide}>Invoice reference
              <input value={invoiceRef} onChange={(e) => setInvoiceRef(e.target.value)} placeholder="INV-2026-0007" />
            </label>
            <label>Jurisdiction
              <select value={jurisdictionCode} onChange={(e) => selectJurisdiction(e.target.value)}>
                {JURISDICTIONS.map((j) => <option key={j.code} value={j.code}>{j.label}</option>)}
              </select>
            </label>
            <label>Rate <small>basis points, 0–10000</small>
              <input value={rateBasisPoints} onChange={(e) => setRateBasisPoints(e.target.value)} inputMode="numeric" />
            </label>
            <label>Net amount <small>private — hidden in voucher</small>
              <input value={netAmount} onChange={(e) => setNetAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>Customer tax ID <small>committed, not revealed</small>
              <input value={customerTaxId} onChange={(e) => setCustomerTaxId(e.target.value)} placeholder="optional — blank = B2C" />
            </label>
            <label className={styles.wide}>Issuer secret signing key
              <input value={issuerSecretInput} onChange={(e) => setIssuerSecretInput(e.target.value)} placeholder="0x… (or generate above)" spellCheck={false} />
            </label>
            <label className={styles.wide}>Memo <small>optional</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="Q3 cross-border sale" />
            </label>
          </div>
          {buildError && <p className={styles.error}>{buildError}</p>}
          <button type="submit" disabled={busy}>{busy ? "Proving in zero knowledge…" : "Issue tax voucher"}</button>
        </form>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <span>02 · Issued voucher</span>
            <h3>Shareable tax-proof voucher</h3>
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
                  {badge.taxKind} proven at <b>{badge.rateDisplay}</b>
                  <small>Net, tax, and gross stay hidden inside the commitments.</small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div><dt>Jurisdiction</dt><dd>{badge.jurisdictionLabel}</dd></div>
                  <div><dt>Tax ID</dt><dd>{badge.taxIdCommitted ? "committed" : "none (B2C)"}</dd></div>
                  <div><dt>Voucher id</dt><dd>{badge.voucherId}</dd></div>
                  <div><dt>Binding</dt><dd>{shorten(badge.bindingHash)}</dd></div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Tax voucher (safe to publish)</span>
                  <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.voucher.txt`, serializedVoucher)}>Download</button>
                </div>
                <textarea readOnly value={serializedVoucher} rows={4} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Tax-figure disclosure</span>
                  <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.tax-disclosure.txt`, serializedTaxDisclosure)}>Download</button>
                </div>
                <p className={styles.hint}>Opens the tax figure alone for authority reporting; net and gross stay hidden.</p>
                <textarea readOnly value={serializedTaxDisclosure} rows={3} />
              </div>
              {built.secret.taxIdCommitted && (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Customer tax-ID disclosure {revealTaxId ? "" : "(hidden)"}</span>
                    <div className={styles.secretActions}>
                      <button type="button" className={styles.ghost} onClick={() => setRevealTaxId((v) => !v)}>{revealTaxId ? "Hide" : "Reveal"}</button>
                      <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.taxid-disclosure.txt`, serializedTaxIdDisclosure)}>Download</button>
                    </div>
                  </div>
                  <p className={styles.warn}>Reveals the committed customer tax ID. Share only with a party entitled to it.</p>
                  {revealTaxId && <textarea readOnly value={serializedTaxIdDisclosure} rows={3} />}
                </div>
              )}
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Issuer opening secret {revealSecret ? "" : "(hidden)"}</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>{revealSecret ? "Hide" : "Reveal"}</button>
                    <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.secret.txt`, serializedSecret)}>Download</button>
                  </div>
                </div>
                <p className={styles.warn}>Holds the net, tax, gross, blindings, and tax-ID salt in the clear. Never publish it.</p>
                {revealSecret && <textarea readOnly value={serializedSecret} rows={3} />}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>Issue a voucher to produce a publicly verifiable tax proof, selective tax-figure and tax-ID disclosures, and a private issuer opening secret.</p>
          )}
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.verify} onSubmit={handleVerify}>
          <div className={styles.panelHead}>
            <span>03 · Verify</span>
            <h3>Check a voucher &amp; disclosure</h3>
          </div>
          <label className={styles.toggle}>Tax voucher
            <textarea value={verifyVoucherInput} onChange={(e) => setVerifyVoucherInput(e.target.value)} placeholder="Paste a serialized tax voucher…" spellCheck={false} />
          </label>
          <label className={styles.toggle}>Disclosure <small>optional — tax figure or tax ID</small>
            <textarea value={verifyDisclosureInput} onChange={(e) => setVerifyDisclosureInput(e.target.value)} placeholder="Paste a tax-figure or tax-ID disclosure to check it…" spellCheck={false} />
          </label>
          <button type="submit">Verify</button>
          {verifyState && (verifyState.error ? (
            <div className={styles.fail}><strong>Cannot decode</strong><small>{verifyState.error}</small></div>
          ) : (
            <div className={verifyState.ok ? styles.pass : styles.fail}>
              <strong>{verifyState.ok ? "Voucher proof valid" : "Voucher proof invalid"}</strong>
              <dl className={styles.resultMeta}>
                <div><dt>tax = floor(net × rate ÷ 10000)</dt><dd>{verifyState.ok ? "ZK proven" : "rejected"}</dd></div>
                <div><dt>Issuer signature</dt><dd>{verifyState.ok ? "authenticated" : "rejected"}</dd></div>
                {verifyState.voucher && <div><dt>Rate</dt><dd>{formatVatRate(verifyState.voucher.rateBasisPoints)}</dd></div>}
                {verifyState.voucher && <div><dt>Jurisdiction</dt><dd>{verifyState.voucher.jurisdictionLabel}</dd></div>}
                {verifyState.disclosure && (
                  <div>
                    <dt>{verifyState.disclosure.type === "tax" ? "Tax disclosure" : "Tax-ID disclosure"}</dt>
                    <dd>{verifyState.disclosure.ok ? `opens · ${verifyState.disclosure.value}` : "does not match"}</dd>
                  </div>
                )}
              </dl>
              <small>Verification is arithmetic only: no pool contract call, no on-chain settlement, no tax filed or remitted.</small>
            </div>
          ))}
        </form>
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
      </div>

      <div className={styles.limitation}>
        <p>{VISIBILITY.limitation}</p>
        <p className={styles.statement}>{TRUST.statement}</p>
      </div>
    </section>
  );
}


