"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  CREDIT_POOL_ADDRESS,
  assessCreditRisk,
  buildCreditBookDisclosure,
  buildCreditCertificateBadge,
  buildCreditMetricDisclosure,
  buildCreditUnderwriterDisclosure,
  computeCreditState,
  createCreditIssuerKey,
  formatCreditBaseUnits,
  getCreditVisibilityModel,
  issueCreditCertificate,
  parseCreditCertificate,
  parseCreditMetricDisclosure,
  parseCreditRefDisclosure,
  serializeCreditCertificate,
  serializeCreditCertificateSecret,
  serializeCreditMetricDisclosure,
  serializeCreditRefDisclosure,
  summarizeCreditTrust,
  verifyCreditCertificate,
  verifyCreditMetricDisclosure,
  verifyCreditRefDisclosure,
  type CreditCertificate,
  type CreditKeypair,
  type CreditMetric,
  type CreditRiskBand,
  type CreditTier,
  type IssuedCreditCertificate,
} from "@/lib/credit-scoring-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./credit-scoring-portal.module.css";
const INTRO =
  "Prove in zero knowledge that a merchant's published underwriting index is the exact public weighting of its hidden invoice-fulfilment counts — index = base + wF·fulfilled + wO·on-time − wD·disputed — and that its hidden liquidity reserve and settled volume each clear a public covenant floor, without revealing any count, either cash-flow figure, or the customer list. The merchant signs the certificate so anyone can authenticate it offline. Its index, tier, and risk band are deterministic heuristics — not a credit-bureau score, a predictive model, or financial advice — and it never extends, disburses, or settles funds and never calls the STRK20 pool contract.";

const TRUST = summarizeCreditTrust();
const VISIBILITY = getCreditVisibilityModel();

const BAND_LABEL: Record<CreditRiskBand, string> = {
  low: "Low",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

const TIER_LABEL: Record<CreditTier, string> = {
  prime: "Prime",
  preferred: "Preferred",
  standard: "Standard",
  watch: "Watch",
  substandard: "Substandard",
};

const TIER_TABLE: Array<{ tier: CreditTier; band: string }> = [
  { tier: "prime", band: "≥ 800" },
  { tier: "preferred", band: "720 – 799" },
  { tier: "standard", band: "620 – 719" },
  { tier: "watch", band: "540 – 619" },
  { tier: "substandard", band: "< 540" },
];

const METRICS: Array<{ key: CreditMetric; label: string; amount: boolean }> = [
  { key: "fulfilled", label: "Fulfilled invoices", amount: false },
  { key: "onTime", label: "On-time settlements", amount: false },
  { key: "disputed", label: "Disputed invoices", amount: false },
  { key: "volume", label: "Settled volume", amount: true },
  { key: "reserve", label: "Liquidity reserve", amount: true },
];

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
  label: string;
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  certificate?: CreditCertificate;
  disclosure?: DisclosureResult;
  error?: string;
}

export function CreditScoringPortal() {
  const [issuer, setIssuer] = useState<CreditKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [assessmentRef, setAssessmentRef] = useState("ASSESS-2026-0007");
  const [programLabel, setProgramLabel] = useState("Merchant Underwriting");
  const [baseIndex, setBaseIndex] = useState("500");
  const [fulfilledWeight, setFulfilledWeight] = useState("3");
  const [onTimeWeight, setOnTimeWeight] = useState("2");
  const [disputeWeight, setDisputeWeight] = useState("15");
  const [reserveFloor, setReserveFloor] = useState("100");
  const [volumeFloor, setVolumeFloor] = useState("1000");
  const [fulfilledInvoices, setFulfilledInvoices] = useState("40");
  const [onTimeSettlements, setOnTimeSettlements] = useState("35");
  const [disputedInvoices, setDisputedInvoices] = useState("4");
  const [settledVolume, setSettledVolume] = useState("5000");
  const [liquidityReserve, setLiquidityReserve] = useState("250");
  const [underwriterRef, setUnderwriterRef] = useState("uw_acme_v1");
  const [bookRef, setBookRef] = useState("book_ledger_9");

  const [issued, setIssued] = useState<IssuedCreditCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealUnderwriter, setRevealUnderwriter] = useState(false);
  const [revealBook, setRevealBook] = useState(false);

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 30 ? parsed : 18;
  }, [assetDecimals]);

  const preview = useMemo(() => {
    try {
      const policy = {
        baseIndex: Number.parseInt(baseIndex, 10),
        fulfilledWeight: Number.parseInt(fulfilledWeight, 10),
        onTimeWeight: Number.parseInt(onTimeWeight, 10),
        disputeWeight: Number.parseInt(disputeWeight, 10),
        reserveFloorBaseUnits: decimalToBaseUnits(reserveFloor.trim(), decimals),
        volumeFloorBaseUnits: decimalToBaseUnits(volumeFloor.trim(), decimals),
      };
      const metrics = {
        fulfilledInvoices: fulfilledInvoices.trim(),
        onTimeSettlements: onTimeSettlements.trim(),
        disputedInvoices: disputedInvoices.trim(),
        settledVolumeBaseUnits: decimalToBaseUnits(settledVolume.trim(), decimals),
        liquidityReserveBaseUnits: decimalToBaseUnits(liquidityReserve.trim(), decimals),
      };
      const state = computeCreditState(metrics, policy);
      return { state, risk: assessCreditRisk(state) };
    } catch {
      return null;
    }
  }, [baseIndex, fulfilledWeight, onTimeWeight, disputeWeight, reserveFloor, volumeFloor, fulfilledInvoices, onTimeSettlements, disputedInvoices, settledVolume, liquidityReserve, decimals]);

  const badge = useMemo(() => (issued ? buildCreditCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(() => (issued ? serializeCreditCertificate(issued.certificate) : ""), [issued]);
  const serializedSecret = useMemo(() => (issued ? serializeCreditCertificateSecret(issued.secret) : ""), [issued]);
  const metricDisclosures = useMemo(
    () =>
      issued
        ? METRICS.map((m) => ({ ...m, payload: serializeCreditMetricDisclosure(buildCreditMetricDisclosure(issued.secret, m.key)) }))
        : [],
    [issued],
  );
  const underwriterDisclosure = useMemo(
    () => (issued && issued.certificate.underwriterCommitted ? serializeCreditRefDisclosure(buildCreditUnderwriterDisclosure(issued.secret)) : ""),
    [issued],
  );
  const bookDisclosure = useMemo(
    () => (issued && issued.certificate.bookCommitted ? serializeCreditRefDisclosure(buildCreditBookDisclosure(issued.secret)) : ""),
    [issued],
  );
  function generateIssuerKey() {
    setIssuer(createCreditIssuerKey());
    setRevealSecretKey(false);
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
    setRevealUnderwriter(false);
    setRevealBook(false);
    // Defer so the "Proving in zero knowledge…" label paints before the synchronous proof blocks the thread.
    setTimeout(() => {
      try {
        const result = issueCreditCertificate({
          merchantAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          assessmentRef,
          programLabel,
          policy: {
            baseIndex: Number.parseInt(baseIndex, 10),
            fulfilledWeight: Number.parseInt(fulfilledWeight, 10),
            onTimeWeight: Number.parseInt(onTimeWeight, 10),
            disputeWeight: Number.parseInt(disputeWeight, 10),
            reserveFloorBaseUnits: decimalToBaseUnits(reserveFloor.trim(), decimals),
            volumeFloorBaseUnits: decimalToBaseUnits(volumeFloor.trim(), decimals),
          },
          metrics: {
            fulfilledInvoices: fulfilledInvoices.trim(),
            onTimeSettlements: onTimeSettlements.trim(),
            disputedInvoices: disputedInvoices.trim(),
            settledVolumeBaseUnits: decimalToBaseUnits(settledVolume.trim(), decimals),
            liquidityReserveBaseUnits: decimalToBaseUnits(liquidityReserve.trim(), decimals),
          },
          underwriterRef,
          bookRef,
          issuerSecretKey: issuer.secretKey,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the credit certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }
  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseCreditCertificate(verifyInput.trim());
      const ok = verifyCreditCertificate(certificate);
      let disclosure: DisclosureResult | undefined;
      const raw = disclosureInput.trim();
      if (raw) {
        try {
          const metric = parseCreditMetricDisclosure(raw);
          const meta = METRICS.find((m) => m.key === metric.metric);
          const value = meta?.amount
            ? `${formatCreditBaseUnits(metric.valueBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`
            : metric.valueBaseUnits;
          disclosure = {
            label: `${meta?.label ?? metric.metric} disclosure`,
            ok: verifyCreditMetricDisclosure(certificate, metric),
            value,
          };
        } catch {
          const ref = parseCreditRefDisclosure(raw);
          disclosure = {
            label: ref.field === "book" ? "Loan-book disclosure" : "Underwriter disclosure",
            ok: verifyCreditRefDisclosure(certificate, ref),
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
          <span>Merchant credit underwriting</span>
          <h2>
            Prove a credit index over <em>hidden history</em>.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(CREDIT_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Index = weighting of hidden counts</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Reserve &amp; volume clear floors</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Credit-bureau score or model</dt>
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
          <span>Institutional credit rating</span>
          <small>Deterministic heuristic · not a credit score, model, or financial advice</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Credit index</dt>
                <dd>{preview.state.index}</dd>
              </div>
              <div className={`${styles.metric} ${styles.tier}`} data-tier={preview.state.tier}>
                <dt>Underwriting tier</dt>
                <dd>{TIER_LABEL[preview.state.tier]}</dd>
              </div>
              <div className={`${styles.metric} ${styles.risk}`} data-band={preview.risk.band}>
                <dt>Risk band</dt>
                <dd>{BAND_LABEL[preview.risk.band]}</dd>
              </div>
              <div className={styles.metric}>
                <dt>On-time rate</dt>
                <dd>{(Number(preview.state.onTimeRateBps) / 100).toFixed(2)}%</dd>
              </div>
            </dl>
            <dl className={styles.covenants}>
              <div className={styles.cov} data-ok={preview.state.clearsReserveFloor}>
                <dt>Reserve ≥ floor</dt>
                <dd>{preview.state.clearsReserveFloor ? "Clears" : "Below floor"}</dd>
              </div>
              <div className={styles.cov} data-ok={preview.state.clearsVolumeFloor}>
                <dt>Volume ≥ floor</dt>
                <dd>{preview.state.clearsVolumeFloor ? "Clears" : "Below floor"}</dd>
              </div>
              <div className={styles.cov} data-ok={preview.state.punctualityConsistent}>
                <dt>On-time ≤ fulfilled</dt>
                <dd>{preview.state.punctualityConsistent ? "Consistent" : "Broken"}</dd>
              </div>
              <div className={styles.cov} data-ok={preview.state.eligible}>
                <dt>Attestable</dt>
                <dd>{preview.state.eligible ? "Eligible" : "Ineligible"}</dd>
              </div>
            </dl>
            {!preview.state.eligible ? (
              <p className={styles.warn}>
                A covenant is broken or the index is negative — no honest proof exists until every floor clears, on-time
                settlements do not exceed fulfilled invoices, and the index is non-negative.
              </p>
            ) : null}
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>Tier</th>
                    <th>Index band</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {TIER_TABLE.map((row) => (
                    <tr key={row.tier} className={row.tier === preview.state.tier ? styles.activeTier : undefined}>
                      <td>{TIER_LABEL[row.tier]}</td>
                      <td>{row.band}</td>
                      <td>{row.tier === preview.state.tier ? "◆ current" : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className={styles.hint}>
              Dispute rate {(Number(preview.state.disputeRateBps) / 100).toFixed(2)}% · the index, tier, and risk band are
              deterministic heuristics computed in your browser. They are never proven, published, or a credit-bureau score.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>
            Enter the public policy and the private counts, settled volume, and liquidity reserve to preview the index,
            tier, and risk band. Every figure stays in your browser.
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
            The issuer key signs each certificate. It stays in your browser; only the public key is embedded so anyone
            can verify authenticity offline.
          </p>
        )}
      </section>
      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue</span>
            <h3>Attest a credit index over hidden history</h3>
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
              Assessment reference <small>public</small>
              <input value={assessmentRef} onChange={(e) => setAssessmentRef(e.target.value)} />
            </label>
            <label>
              Program label <small>public</small>
              <input value={programLabel} onChange={(e) => setProgramLabel(e.target.value)} />
            </label>
            <label>
              Base index <small>public</small>
              <input value={baseIndex} onChange={(e) => setBaseIndex(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Fulfilled weight <small>public</small>
              <input value={fulfilledWeight} onChange={(e) => setFulfilledWeight(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              On-time weight <small>public</small>
              <input value={onTimeWeight} onChange={(e) => setOnTimeWeight(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Dispute weight <small>public, subtracted</small>
              <input value={disputeWeight} onChange={(e) => setDisputeWeight(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Reserve floor <small>public</small>
              <input value={reserveFloor} onChange={(e) => setReserveFloor(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Volume floor <small>public</small>
              <input value={volumeFloor} onChange={(e) => setVolumeFloor(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Fulfilled invoices <small>hidden count</small>
              <input value={fulfilledInvoices} onChange={(e) => setFulfilledInvoices(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              On-time settlements <small>hidden count</small>
              <input value={onTimeSettlements} onChange={(e) => setOnTimeSettlements(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Disputed invoices <small>hidden count</small>
              <input value={disputedInvoices} onChange={(e) => setDisputedInvoices(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Settled volume <small>hidden</small>
              <input value={settledVolume} onChange={(e) => setSettledVolume(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Liquidity reserve <small>hidden</small>
              <input value={liquidityReserve} onChange={(e) => setLiquidityReserve(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Underwriter reference <small>committed, optional</small>
              <input value={underwriterRef} onChange={(e) => setUnderwriterRef(e.target.value)} />
            </label>
            <label className={styles.wide}>
              Loan-book reference <small>committed, optional</small>
              <input value={bookRef} onChange={(e) => setBookRef(e.target.value)} />
            </label>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing}>
            {issuing ? "Proving in zero knowledge…" : "Issue credit certificate"}
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
                      {badge.programLabel} · {badge.assessmentRef}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  Index <b>{badge.index}</b> · {TIER_LABEL[badge.tier]}
                  <small>
                    {badge.weightingDisplay} · issued {formatDate(badge.createdAt)}
                  </small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div>
                    <dt>Reserve floor</dt>
                    <dd>{badge.reserveFloorDisplay}</dd>
                  </div>
                  <div>
                    <dt>Volume floor</dt>
                    <dd>{badge.volumeFloorDisplay}</dd>
                  </div>
                  <div>
                    <dt>Underwriter</dt>
                    <dd>{badge.underwriterCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                  <div>
                    <dt>Loan book</dt>
                    <dd>{badge.bookCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Serialized certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`credit-certificate-${issued.certificate.certificateId}.txt`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Metric disclosures</span>
                </div>
                {metricDisclosures.map((m) => (
                  <div className={styles.exportHead} key={m.key}>
                    <span>{m.label}</span>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`credit-${m.key}-${issued.certificate.certificateId}.txt`, m.payload)}
                    >
                      Download
                    </button>
                  </div>
                ))}
                <p className={styles.hint}>
                  Each payload opens exactly one committed metric to a counterparty; the others stay hidden. Counts open
                  as integers, cash-flow figures in base units.
                </p>
              </div>
              {issued.certificate.underwriterCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Underwriter disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealUnderwriter((v) => !v)}>
                      {revealUnderwriter ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealUnderwriter ? (
                    <>
                      <p className={styles.warn}>Reveals the committed underwriter reference. Share only with the counterparty.</p>
                      <textarea readOnly value={underwriterDisclosure} spellCheck={false} />
                    </>
                  ) : null}
                </div>
              ) : null}
              {issued.certificate.bookCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Loan-book disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealBook((v) => !v)}>
                      {revealBook ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealBook ? (
                    <>
                      <p className={styles.warn}>Reveals the committed loan-book reference. Share only with the counterparty.</p>
                      <textarea readOnly value={bookDisclosure} spellCheck={false} />
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
                      Contains every count, both cash-flow figures, the blindings, and the salts. Never publish or commit
                      it — hand it only to a counterparty you are opening the figures to.
                    </p>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`credit-secret-${issued.certificate.certificateId}.txt`, serializedSecret)}
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
              Issue a certificate to see the public badge, its serialized form, and selective-disclosure payloads. No
              count and neither cash-flow figure ever appears in the certificate.
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
              placeholder="Paste a serialized credit certificate"
              spellCheck={false}
            />
          </label>
          <label className={styles.toggle}>
            Optional disclosure <small>a metric, underwriter, or loan-book payload</small>
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
                      <dt>Index · tier</dt>
                      <dd>
                        {verifyResult.certificate.index} · {TIER_LABEL[verifyResult.certificate.tier]}
                      </dd>
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
                    {verifyResult.disclosure.label} {verifyResult.disclosure.ok ? "matches" : "does NOT match"} the
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
