"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  CASHFLOW_POOL_ADDRESS,
  aggregateAgingSchedule,
  assessCashflowRisk,
  buildCashflowAmountDisclosure,
  buildCashflowBookRefDisclosure,
  buildCashflowCertificateBadge,
  buildCashflowCounterpartyDisclosure,
  computeCashflowState,
  createCashflowIssuerKey,
  formatCashflowBaseUnits,
  formatDsoDays,
  formatRunwayDays,
  formatShareBps,
  getCashflowVisibilityModel,
  issueCashflowCertificate,
  parseCashflowAmountDisclosure,
  parseCashflowCertificate,
  parseCashflowRefDisclosure,
  projectRollingRunway,
  serializeCashflowAmountDisclosure,
  serializeCashflowCertificate,
  serializeCashflowCertificateSecret,
  serializeCashflowRefDisclosure,
  summarizeCashflowTrust,
  verifyCashflowAmountDisclosure,
  verifyCashflowCertificate,
  verifyCashflowRefDisclosure,
  type CashflowCertificate,
  type CashflowInvoiceRow,
  type CashflowKeypair,
  type CashflowRiskBand,
  type IssuedCashflowCertificate,
} from "@/lib/cashflow-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./cashflow-portal.module.css";

const INTRO =
  "Prove in zero knowledge that five hidden AR aging buckets conserve a committed total and that committed liquidity, burn, and weighted settlement satisfy public runway, DSO, and 90+-day concentration covenants — without revealing bucket amounts, invoice rows, or counterparty references. The merchant signs the certificate so anyone can authenticate it offline. Rolling runway projections and risk bands are deterministic heuristics — not a credit score, a predictive model, or financial advice — and this engine never calls the STRK20 pool contract.";

const TRUST = summarizeCashflowTrust();
const VISIBILITY = getCashflowVisibilityModel();

const BAND_LABEL: Record<CashflowRiskBand, string> = {
  low: "Low",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

interface InvoiceDraft {
  id: string;
  alias: string;
  dueDate: string;
  amount: string;
  settlementDays: string;
}

interface DisclosureResult {
  type: string;
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  certificate?: CashflowCertificate;
  disclosure?: DisclosureResult;
  error?: string;
}

const DEFAULT_INVOICES: InvoiceDraft[] = [
  { id: "inv_1", alias: "Northwind", dueDate: "2026-09-01", amount: "2", settlementDays: "5" },
  { id: "inv_2", alias: "Contoso", dueDate: "2026-07-01", amount: "1.5", settlementDays: "10" },
  { id: "inv_3", alias: "Fabrikam", dueDate: "2026-06-01", amount: "1", settlementDays: "15" },
];

function shorten(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

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

function toInvoiceRows(drafts: InvoiceDraft[], decimals: number): CashflowInvoiceRow[] {
  return drafts.map((row) => ({
    alias: row.alias,
    dueDate: new Date(`${row.dueDate}T00:00:00.000Z`).toISOString(),
    amountBaseUnits: decimalToBaseUnits(row.amount.trim(), decimals),
    settlementDays: Number.parseInt(row.settlementDays, 10),
  }));
}

export function CashflowPortal() {
  const [issuer, setIssuer] = useState<CashflowKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [bookRef, setBookRef] = useState("AR-BOOK-2026-Q3");
  const [programLabel, setProgramLabel] = useState("Rolling Forecast");
  const [minRunwayDays, setMinRunwayDays] = useState("30");
  const [maxDsoDays, setMaxDsoDays] = useState("45");
  const [maxPastDueShareBps, setMaxPastDueShareBps] = useState("5000");
  const [liquidityAmount, setLiquidityAmount] = useState("10");
  const [burnAmount, setBurnAmount] = useState("0.05");
  const [counterpartyRef, setCounterpartyRef] = useState("book_counterparty_v1");
  const [invoices, setInvoices] = useState<InvoiceDraft[]>(DEFAULT_INVOICES);

  const [issued, setIssued] = useState<IssuedCashflowCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealCounterparty, setRevealCounterparty] = useState(false);

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 30 ? parsed : 18;
  }, [assetDecimals]);

  const policy = useMemo(
    () => ({
      minRunwayDays: Number.parseInt(minRunwayDays, 10),
      maxDsoDays: Number.parseInt(maxDsoDays, 10),
      maxPastDueShareBps: Number.parseInt(maxPastDueShareBps, 10),
    }),
    [minRunwayDays, maxDsoDays, maxPastDueShareBps],
  );

  const preview = useMemo(() => {
    try {
      const rows = toInvoiceRows(invoices, decimals);
      const aging = aggregateAgingSchedule(rows);
      const liquidityBaseUnits = decimalToBaseUnits(liquidityAmount.trim(), decimals);
      const burnBaseUnits = decimalToBaseUnits(burnAmount.trim(), decimals);
      const state = computeCashflowState(liquidityBaseUnits, burnBaseUnits, aging, policy);
      const risk = assessCashflowRisk(state);
      const runway = projectRollingRunway(rows, liquidityBaseUnits, burnBaseUnits, 8);
      const minRunway = Number.parseInt(minRunwayDays, 10);
      const runwayRatio = minRunway > 0 ? Math.min(100, (Number(state.runwayDays) / minRunway) * 100) : 100;
      return { aging, state, risk, runway, runwayRatio };
    } catch {
      return null;
    }
  }, [invoices, liquidityAmount, burnAmount, decimals, policy, minRunwayDays]);

  const badge = useMemo(() => (issued ? buildCashflowCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(() => (issued ? serializeCashflowCertificate(issued.certificate) : ""), [issued]);
  const serializedSecret = useMemo(() => (issued ? serializeCashflowCertificateSecret(issued.secret) : ""), [issued]);
  const liquidityDisclosure = useMemo(
    () => (issued ? serializeCashflowAmountDisclosure(buildCashflowAmountDisclosure(issued.secret, "liquidity")) : ""),
    [issued],
  );
  const burnDisclosure = useMemo(
    () => (issued ? serializeCashflowAmountDisclosure(buildCashflowAmountDisclosure(issued.secret, "burn")) : ""),
    [issued],
  );
  const bookDisclosure = useMemo(
    () => (issued ? serializeCashflowRefDisclosure(buildCashflowBookRefDisclosure(issued.secret)) : ""),
    [issued],
  );
  const counterpartyDisclosure = useMemo(
    () =>
      issued && issued.certificate.counterpartyCommitted
        ? serializeCashflowRefDisclosure(buildCashflowCounterpartyDisclosure(issued.secret))
        : "",
    [issued],
  );

  function generateIssuerKey() {
    setIssuer(createCashflowIssuerKey());
    setRevealSecretKey(false);
  }

  function updateInvoice(id: string, patch: Partial<InvoiceDraft>) {
    setInvoices((rows) => rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  function addInvoiceRow() {
    setInvoices((rows) => [
      ...rows,
      { id: `inv_${Date.now()}`, alias: "Counterparty", dueDate: "2026-10-01", amount: "1", settlementDays: "7" },
    ]);
  }

  function handleIssue(event: FormEvent) {
    event.preventDefault();
    if (!issuer) {
      setIssueError("Generate an issuer key in the vault above before issuing a certificate.");
      return;
    }
    setIssuing(true);
    setIssueError(null);
    setIssued(null);
    setRevealSecret(false);
    setRevealCounterparty(false);
    setTimeout(() => {
      try {
        const rows = toInvoiceRows(invoices, decimals);
        const aging = aggregateAgingSchedule(rows);
        const bucketAmounts = aging.buckets.map((b) => b.amountBaseUnits) as [string, string, string, string, string];
        const result = issueCashflowCertificate({
          merchantAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          bookRef,
          programLabel,
          policy,
          liquidityBaseUnits: decimalToBaseUnits(liquidityAmount.trim(), decimals),
          burnRateBaseUnits: decimalToBaseUnits(burnAmount.trim(), decimals),
          bucketAmountsBaseUnits: bucketAmounts,
          weightedSettlementDays: aging.weightedSettlementDays,
          counterpartyRef,
          issuerSecretKey: issuer.secretKey,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the cash-flow certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseCashflowCertificate(verifyInput.trim());
      const ok = verifyCashflowCertificate(certificate);
      let disclosure: DisclosureResult | undefined;
      const raw = disclosureInput.trim();
      if (raw) {
        try {
          const amount = parseCashflowAmountDisclosure(raw);
          disclosure = {
            type: amount.field,
            ok: verifyCashflowAmountDisclosure(certificate, amount),
            value: `${formatCashflowBaseUnits(amount.amountBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
          };
        } catch {
          const ref = parseCashflowRefDisclosure(raw);
          disclosure = {
            type: ref.field,
            ok: verifyCashflowRefDisclosure(certificate, ref),
            value: ref.value || "(empty)",
          };
        }
      }
      setVerifyResult({ ok, certificate, disclosure });
    } catch (error) {
      setVerifyResult({ ok: false, error: error instanceof Error ? error.message : "The certificate could not be parsed." });
    }
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Accounts receivable aging & cash-flow forecast</span>
          <h2>
            Prove runway, DSO, and <em>concentration</em> in zero knowledge.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(CASHFLOW_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Aging conservation + 3 covenants</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Issuer signature</dt>
            <dd className={styles.yes}>Authenticated</dd>
          </div>
          <div>
            <dt>Collects or advances funds</dt>
            <dd className={styles.no}>Never</dd>
          </div>
          <div>
            <dt>STRK20 pool contract</dt>
            <dd className={styles.no}>Never called</dd>
          </div>
        </dl>
      </header>

      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Institutional forecast dashboard</span>
          <small>Deterministic heuristics · not a credit score, model, or financial advice</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Runway</dt>
                <dd>{formatRunwayDays(preview.state.runwayDays)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>DSO</dt>
                <dd>{formatDsoDays(preview.state.dsoDays)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Past-due share</dt>
                <dd>{formatShareBps(preview.state.pastDueShareBps)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Cash-flow risk</dt>
                <dd>{BAND_LABEL[preview.risk.band]}</dd>
              </div>
            </dl>
            {!preview.state.eligible ? (
              <p className={styles.warn}>
                One or more policy surpluses is negative — no honest eligibility proof exists until liquidity, burn, aging,
                or the public covenants change.
              </p>
            ) : null}
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>Runway vs minimum covenant</span>
                <span>
                  {formatRunwayDays(preview.state.runwayDays)} / {minRunwayDays} days
                </span>
              </div>
              <div className={styles.meter}>
                <span style={{ width: `${Math.min(100, preview.runwayRatio)}%` }} />
              </div>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>Bucket</th>
                    <th>Invoices</th>
                    <th>Amount</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.aging.buckets.map((bucket) => (
                    <tr key={bucket.label}>
                      <td>{bucket.label}</td>
                      <td>{bucket.invoiceCount}</td>
                      <td>
                        {formatCashflowBaseUnits(bucket.amountBaseUnits, decimals)} {assetSymbol}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>Week</th>
                    <th>Collections</th>
                    <th>Burn</th>
                    <th>Closing</th>
                    <th>Runway</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.runway.map((week) => (
                    <tr key={week.weekIndex}>
                      <td>W{week.weekIndex}</td>
                      <td>{formatCashflowBaseUnits(week.collectionsBaseUnits, decimals)}</td>
                      <td>{formatCashflowBaseUnits(week.weeklyBurnBaseUnits, decimals)}</td>
                      <td>{formatCashflowBaseUnits(week.closingLiquidityBaseUnits, decimals)}</td>
                      <td>{formatRunwayDays(week.runwayDays)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className={styles.hint}>
              Aging as of {formatDate(preview.aging.asOf)} · total AR{" "}
              {formatCashflowBaseUnits(preview.aging.totalArBaseUnits, decimals)} {assetSymbol}. Rolling runway folds any
              remainder into the final week; nothing executes on-chain.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>
            Enter liquidity, burn, policy covenants, and invoice rows to preview aging buckets, runway, and an eight-week
            simulator. Amounts stay in your browser.
          </p>
        )}
      </section>

      <section className={styles.vault}>
        <div className={styles.vaultHead}>
          <span>00 · Issuer key vault</span>
          <div className={styles.vaultActions}>
            <button type="button" className={styles.ghost} onClick={generateIssuerKey}>
              {issuer ? "Regenerate issuer key" : "Generate issuer key"}
            </button>
            {issuer ? (
              <button type="button" className={styles.ghost} onClick={() => setRevealSecretKey((v) => !v)}>
                {revealSecretKey ? "Hide secret" : "Reveal secret"}
              </button>
            ) : null}
          </div>
        </div>
        {issuer ? (
          <div className={styles.keyGrid}>
            <div className={styles.keyCard}>
              <h4>Public key — share to let anyone authenticate certificates offline</h4>
              <dl>
                <dt>X</dt>
                <dd>{issuer.publicKey.x}</dd>
                <dt>Y</dt>
                <dd>{issuer.publicKey.y}</dd>
              </dl>
            </div>
            {revealSecretKey ? (
              <div className={styles.keyCard}>
                <h4 className={styles.secretTag}>Secret signing scalar — never publish or commit this</h4>
                <dl>
                  <dt>Secret key</dt>
                  <dd>{issuer.secretKey}</dd>
                </dl>
              </div>
            ) : null}
          </div>
        ) : (
          <p className={styles.placeholder}>
            The issuer key signs each certificate. It stays in your browser; only the public key is embedded so anyone can
            verify authenticity offline.
          </p>
        )}
      </section>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue</span>
            <h3>Attest aging & cash-flow covenants</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>
              Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} />
            </label>
            <label>
              Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} />
            </label>
            <label>
              Decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" />
            </label>
            <label className={styles.wide}>
              Token address <small>provenance only — never called</small>
              <input value={tokenAddress} onChange={(e) => setTokenAddress(e.target.value)} />
            </label>
            <label>
              Book reference <small>public</small>
              <input value={bookRef} onChange={(e) => setBookRef(e.target.value)} />
            </label>
            <label>
              Program label <small>public</small>
              <input value={programLabel} onChange={(e) => setProgramLabel(e.target.value)} />
            </label>
            <label>
              Min runway (days) <small>public</small>
              <input value={minRunwayDays} onChange={(e) => setMinRunwayDays(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Max DSO (days) <small>public</small>
              <input value={maxDsoDays} onChange={(e) => setMaxDsoDays(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Max 90+ share (bps) <small>public</small>
              <input value={maxPastDueShareBps} onChange={(e) => setMaxPastDueShareBps(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Liquidity reserve <small>hidden</small>
              <input value={liquidityAmount} onChange={(e) => setLiquidityAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Daily burn <small>hidden</small>
              <input value={burnAmount} onChange={(e) => setBurnAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label className={styles.wide}>
              Counterparty reference <small>committed, optional</small>
              <input value={counterpartyRef} onChange={(e) => setCounterpartyRef(e.target.value)} />
            </label>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Encrypted invoice book</span>
              <button type="button" className={styles.ghost} onClick={addInvoiceRow}>
                Add row
              </button>
            </div>
            <div className={styles.tierEditor}>
              {invoices.map((row) => (
                <div key={row.id} className={styles.tierEditRow}>
                  <input value={row.alias} onChange={(e) => updateInvoice(row.id, { alias: e.target.value })} placeholder="Alias" />
                  <input
                    value={row.dueDate}
                    onChange={(e) => updateInvoice(row.id, { dueDate: e.target.value })}
                    type="date"
                  />
                  <input
                    value={row.amount}
                    onChange={(e) => updateInvoice(row.id, { amount: e.target.value })}
                    inputMode="decimal"
                    placeholder="Amount"
                  />
                  <input
                    value={row.settlementDays}
                    onChange={(e) => updateInvoice(row.id, { settlementDays: e.target.value })}
                    inputMode="numeric"
                    placeholder="Settle days"
                  />
                </div>
              ))}
            </div>
            <p className={styles.hint}>Customer aliases stay local; only salted commitments and aggregated bucket totals enter the proof.</p>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing}>
            {issuing ? "Proving in zero knowledge…" : "Issue cash-flow certificate"}
          </button>
        </form>

        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <span>02 · Issued certificate</span>
            <h3>Signed, ready to authenticate offline</h3>
          </div>
          {issued && badge ? (
            <>
              <div className={styles.badge}>
                <div className={styles.badgeTop}>
                  <div>
                    <strong>{badge.merchantAlias}</strong>
                    <small>
                      {badge.programLabel} · {badge.bookRef}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  Runway <b>{badge.minRunwayDisplay}</b>
                  <small>
                    {badge.maxDsoDisplay} · {badge.maxConcentrationDisplay} · issued {formatDate(badge.createdAt)}
                  </small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div>
                    <dt>Certificate</dt>
                    <dd>{shorten(badge.certificateId)}</dd>
                  </div>
                  <div>
                    <dt>Network</dt>
                    <dd>{badge.network}</dd>
                  </div>
                  <div>
                    <dt>Counterparty</dt>
                    <dd>{badge.counterpartyCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                  <div>
                    <dt>Binding</dt>
                    <dd>{shorten(badge.bindingHash)}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Serialized certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`cashflow-certificate-${issued.certificate.certificateId}.txt`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Liquidity disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`cashflow-liquidity-${issued.certificate.certificateId}.txt`, liquidityDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={liquidityDisclosure} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Burn disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`cashflow-burn-${issued.certificate.certificateId}.txt`, burnDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={burnDisclosure} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Book reference disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`cashflow-book-${issued.certificate.certificateId}.txt`, bookDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={bookDisclosure} spellCheck={false} />
              </div>
              {issued.certificate.counterpartyCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Counterparty disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealCounterparty((v) => !v)}>
                      {revealCounterparty ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealCounterparty ? (
                    <>
                      <p className={styles.warn}>Reveals the committed counterparty reference. Share only with the counterparty.</p>
                      <textarea readOnly value={counterpartyDisclosure} spellCheck={false} />
                    </>
                  ) : null}
                </div>
              ) : null}
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Issuer secret — full opening</span>
                  <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>
                    {revealSecret ? "Hide" : "Reveal"}
                  </button>
                </div>
                {revealSecret ? (
                  <>
                    <p className={styles.warn}>
                      Contains liquidity, burn, bucket amounts, blindings, and salts. Never publish or commit it — hand it only
                      to a counterparty you are opening the figures to.
                    </p>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`cashflow-secret-${issued.certificate.certificateId}.txt`, serializedSecret)}
                      >
                        Download secret
                      </button>
                    </div>
                    <textarea readOnly value={serializedSecret} spellCheck={false} />
                  </>
                ) : null}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>
              Issue a certificate to see the public badge, its serialized form, and selective-disclosure payloads. Liquidity,
              burn, and bucket amounts never appear in the certificate.
            </p>
          )}
        </div>
      </div>

      <div className={styles.grid}>
        <form className={styles.verify} onSubmit={handleVerify}>
          <div className={styles.panelHead}>
            <span>03 · Verify</span>
            <h3>Authenticate a certificate offline</h3>
          </div>
          <label className={styles.toggle}>
            Serialized certificate
            <textarea
              value={verifyInput}
              onChange={(e) => setVerifyInput(e.target.value)}
              placeholder="Paste a serialized cash-flow certificate"
              spellCheck={false}
            />
          </label>
          <label className={styles.toggle}>
            Optional disclosure <small>liquidity, burn, bucket, book, or counterparty</small>
            <textarea
              value={disclosureInput}
              onChange={(e) => setDisclosureInput(e.target.value)}
              placeholder="Paste a selective-disclosure payload to check it against the certificate"
              spellCheck={false}
            />
          </label>
          <button type="submit">Verify certificate</button>
          {verifyResult ? (
            verifyResult.error ? (
              <div className={styles.fail}>
                <strong>Could not parse</strong>
                <small>{verifyResult.error}</small>
              </div>
            ) : (
              <div className={verifyResult.ok ? styles.pass : styles.fail}>
                <strong>{verifyResult.ok ? "Signature and range proofs valid" : "Verification failed"}</strong>
                {verifyResult.certificate ? (
                  <dl className={styles.resultMeta}>
                    <div>
                      <dt>Merchant</dt>
                      <dd>{verifyResult.certificate.merchantAlias}</dd>
                    </div>
                    <div>
                      <dt>Min runway</dt>
                      <dd>{formatRunwayDays(verifyResult.certificate.minRunwayDays)}</dd>
                    </div>
                    <div>
                      <dt>Certificate</dt>
                      <dd>{shorten(verifyResult.certificate.certificateId)}</dd>
                    </div>
                    <div>
                      <dt>Binding</dt>
                      <dd>{shorten(verifyResult.certificate.bindingHash)}</dd>
                    </div>
                  </dl>
                ) : null}
                {verifyResult.disclosure ? (
                  <small>
                    {verifyResult.disclosure.type} disclosure {verifyResult.disclosure.ok ? "matches" : "does NOT match"} the
                    certificate → {verifyResult.disclosure.value}
                  </small>
                ) : null}
              </div>
            )
          ) : null}
        </form>
        <section className={styles.model}>
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
            <h4>Application-side only</h4>
            <ul>
              {VISIBILITY.applicationOnly.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        </section>
      </div>

      <section className={styles.limitation}>
        <p>{VISIBILITY.limitation}</p>
        <p className={styles.statement}>{TRUST.statement}</p>
      </section>
    </div>
  );
}
