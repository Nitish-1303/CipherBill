"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  FINANCING_POOL_ADDRESS,
  assessFinancingRisk,
  buildFinancingAdvanceDisclosure,
  buildFinancingCertificateBadge,
  buildFinancingFinancierDisclosure,
  buildFinancingPayoutAccountDisclosure,
  buildFinancingRevenueDisclosure,
  computeFinancingState,
  computeRepaymentSchedule,
  createFinancingIssuerKey,
  formatFinancingBaseUnits,
  getFinancingVisibilityModel,
  issueFinancingCertificate,
  parseFinancingAmountDisclosure,
  parseFinancingCertificate,
  parseFinancingRefDisclosure,
  serializeFinancingAmountDisclosure,
  serializeFinancingCertificate,
  serializeFinancingCertificateSecret,
  serializeFinancingRefDisclosure,
  summarizeFinancingTrust,
  verifyFinancingAmountDisclosure,
  verifyFinancingCertificate,
  verifyFinancingRefDisclosure,
  type FinancingCertificate,
  type FinancingKeypair,
  type FinancingRiskBand,
  type IssuedFinancingCertificate,
} from "@/lib/financing-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./financing-portal.module.css";
const INTRO =
  "Prove in zero knowledge that a requested capital advance is within a public advance factor of a merchant's committed historical settlement revenue — advance ≤ factor · revenue — without revealing the revenue figure, the requested advance, the customer list, or any individual invoice amount. The merchant signs the certificate so anyone can authenticate it offline. It computes a repayment plan and a deterministic credit-limit heuristic, but it does not advance, disburse, or settle any funds, does not verify that the revenue is real, and never calls the STRK20 pool contract.";

const TRUST = summarizeFinancingTrust();
const VISIBILITY = getFinancingVisibilityModel();

const BAND_LABEL: Record<FinancingRiskBand, string> = {
  low: "Low",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

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
  type: "revenue" | "advance" | "financier" | "payoutAccount";
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  certificate?: FinancingCertificate;
  disclosure?: DisclosureResult;
  error?: string;
}

export function FinancingPortal() {
  const [issuer, setIssuer] = useState<FinancingKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [advanceRef, setAdvanceRef] = useState("ADV-2026-0007");
  const [programLabel, setProgramLabel] = useState("Growth Advance");
  const [advanceFactorBps, setAdvanceFactorBps] = useState("8000");
  const [feeBps, setFeeBps] = useState("1200");
  const [installments, setInstallments] = useState("12");
  const [intervalDays, setIntervalDays] = useState("30");
  const [revenueAmount, setRevenueAmount] = useState("1000");
  const [requestedAdvance, setRequestedAdvance] = useState("500");
  const [financierRef, setFinancierRef] = useState("fin_acme_v1");
  const [payoutAccountRef, setPayoutAccountRef] = useState("payout_ledger_9");

  const [issued, setIssued] = useState<IssuedFinancingCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealFinancier, setRevealFinancier] = useState(false);
  const [revealPayout, setRevealPayout] = useState(false);

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 30 ? parsed : 18;
  }, [assetDecimals]);

  const policy = useMemo(
    () => ({
      advanceFactorBps: Number.parseInt(advanceFactorBps, 10),
      feeBps: Number.parseInt(feeBps, 10),
      installments: Number.parseInt(installments, 10),
      intervalDays: Number.parseInt(intervalDays, 10),
    }),
    [advanceFactorBps, feeBps, installments, intervalDays],
  );

  const preview = useMemo(() => {
    try {
      const revenueBaseUnits = decimalToBaseUnits(revenueAmount.trim(), decimals);
      const advanceBaseUnits = decimalToBaseUnits(requestedAdvance.trim(), decimals);
      const state = computeFinancingState(revenueBaseUnits, advanceBaseUnits, policy);
      const risk = assessFinancingRisk(state);
      const schedule = computeRepaymentSchedule(advanceBaseUnits, policy);
      return { state, risk, schedule };
    } catch {
      return null;
    }
  }, [revenueAmount, requestedAdvance, decimals, policy]);

  const badge = useMemo(() => (issued ? buildFinancingCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(() => (issued ? serializeFinancingCertificate(issued.certificate) : ""), [issued]);
  const serializedSecret = useMemo(() => (issued ? serializeFinancingCertificateSecret(issued.secret) : ""), [issued]);
  const revenueDisclosure = useMemo(
    () => (issued ? serializeFinancingAmountDisclosure(buildFinancingRevenueDisclosure(issued.secret)) : ""),
    [issued],
  );
  const advanceDisclosure = useMemo(
    () => (issued ? serializeFinancingAmountDisclosure(buildFinancingAdvanceDisclosure(issued.secret)) : ""),
    [issued],
  );
  const financierDisclosure = useMemo(
    () => (issued && issued.certificate.financierCommitted ? serializeFinancingRefDisclosure(buildFinancingFinancierDisclosure(issued.secret)) : ""),
    [issued],
  );
  const payoutDisclosure = useMemo(
    () => (issued && issued.certificate.payoutAccountCommitted ? serializeFinancingRefDisclosure(buildFinancingPayoutAccountDisclosure(issued.secret)) : ""),
    [issued],
  );

  function generateIssuerKey() {
    setIssuer(createFinancingIssuerKey());
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
    setRevealFinancier(false);
    setRevealPayout(false);
    // Defer so the "Proving in zero knowledge…" label paints before the synchronous proof blocks the thread.
    setTimeout(() => {
      try {
        const result = issueFinancingCertificate({
          merchantAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          advanceRef,
          programLabel,
          policy,
          revenueBaseUnits: decimalToBaseUnits(revenueAmount.trim(), decimals),
          requestedAdvanceBaseUnits: decimalToBaseUnits(requestedAdvance.trim(), decimals),
          financierRef,
          payoutAccountRef,
          issuerSecretKey: issuer.secretKey,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the financing certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseFinancingCertificate(verifyInput.trim());
      const ok = verifyFinancingCertificate(certificate);
      let disclosure: DisclosureResult | undefined;
      const raw = disclosureInput.trim();
      if (raw) {
        try {
          const amount = parseFinancingAmountDisclosure(raw);
          disclosure = {
            type: amount.field === "advance" ? "advance" : "revenue",
            ok: verifyFinancingAmountDisclosure(certificate, amount),
            value: `${formatFinancingBaseUnits(amount.amountBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
          };
        } catch {
          const ref = parseFinancingRefDisclosure(raw);
          disclosure = {
            type: ref.field === "payoutAccount" ? "payoutAccount" : "financier",
            ok: verifyFinancingRefDisclosure(certificate, ref),
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
          <span>Revenue-based financing</span>
          <h2>
            Prove advances stay <em>within revenue</em>.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(FINANCING_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Advance ≤ factor · revenue</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Issuer signature</dt>
            <dd className={styles.yes}>Authenticated</dd>
          </div>
          <div>
            <dt>Advances or disburses funds</dt>
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
          <span>Credit-limit calculator</span>
          <small>Deterministic heuristic · not a credit score, model, or financial advice</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={styles.metric}>
                <dt>Credit limit</dt>
                <dd>
                  {formatFinancingBaseUnits(preview.state.creditLimitBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Headroom</dt>
                <dd>
                  {formatFinancingBaseUnits(preview.state.headroomBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Utilization</dt>
                <dd>{(Number(preview.state.utilizationBps) / 100).toFixed(2)}%</dd>
              </div>
              <div className={`${styles.metric} ${styles.risk}`} data-band={preview.risk.band}>
                <dt>Financing risk</dt>
                <dd>{BAND_LABEL[preview.risk.band]}</dd>
              </div>

            </dl>
            {!preview.state.eligible ? (
              <p className={styles.warn}>
                The requested advance exceeds the eligible credit limit for the committed revenue — no honest proof
                exists until the advance drops to the limit or below.
              </p>
            ) : null}
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Day</th>
                    <th>Installment</th>
                    <th>Cumulative</th>
                    <th>Remaining</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.schedule.map((entry) => (
                    <tr key={entry.installment}>
                      <td>{entry.installment}</td>
                      <td>+{entry.dayOffset}d</td>
                      <td className={styles.rateCell}>{formatFinancingBaseUnits(entry.amountBaseUnits, decimals)}</td>
                      <td>{formatFinancingBaseUnits(entry.cumulativeBaseUnits, decimals)}</td>
                      <td className={styles.warnCell}>{formatFinancingBaseUnits(entry.remainingBaseUnits, decimals)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className={styles.hint}>
              The repayment plan totals principal plus the public fee across {policy.installments || 0} installments; a
              financier executes it out of band. This engine never advances, disburses, or settles funds.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>
            Enter a revenue figure, requested advance, and policy to preview the credit limit, utilization, and
            repayment plan. Amounts stay in your browser.
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
            <h3>Attest an advance within revenue</h3>
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
              Advance reference <small>public</small>
              <input value={advanceRef} onChange={(e) => setAdvanceRef(e.target.value)} />
            </label>
            <label>
              Program label <small>public</small>
              <input value={programLabel} onChange={(e) => setProgramLabel(e.target.value)} />
            </label>
            <label>
              Advance factor (bps) <small>public</small>
              <input value={advanceFactorBps} onChange={(e) => setAdvanceFactorBps(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Fee (bps) <small>public</small>
              <input value={feeBps} onChange={(e) => setFeeBps(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Installments
              <input value={installments} onChange={(e) => setInstallments(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Interval (days)
              <input value={intervalDays} onChange={(e) => setIntervalDays(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Historical revenue <small>hidden</small>
              <input value={revenueAmount} onChange={(e) => setRevenueAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Requested advance <small>hidden</small>
              <input value={requestedAdvance} onChange={(e) => setRequestedAdvance(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Financier reference <small>committed, optional</small>
              <input value={financierRef} onChange={(e) => setFinancierRef(e.target.value)} />
            </label>
            <label>
              Payout account <small>committed, optional</small>
              <input value={payoutAccountRef} onChange={(e) => setPayoutAccountRef(e.target.value)} />
            </label>

          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing}>
            {issuing ? "Proving in zero knowledge…" : "Issue financing certificate"}
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
                      {badge.programLabel} · {badge.advanceRef}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  Advance <b>{badge.advanceFactorDisplay}</b>
                  <small>
                    {badge.feeDisplay} · {badge.installmentsDisplay} · issued {formatDate(badge.createdAt)}
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
                    <dt>Financier</dt>
                    <dd>{badge.financierCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                  <div>
                    <dt>Payout account</dt>
                    <dd>{badge.payoutAccountCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Serialized certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`financing-certificate-${issued.certificate.certificateId}.txt`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Revenue disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`financing-revenue-${issued.certificate.certificateId}.txt`, revenueDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={revenueDisclosure} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Advance disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`financing-advance-${issued.certificate.certificateId}.txt`, advanceDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={advanceDisclosure} spellCheck={false} />
              </div>
              {issued.certificate.financierCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Financier disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealFinancier((v) => !v)}>
                      {revealFinancier ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealFinancier ? (
                    <>
                      <p className={styles.warn}>Reveals the committed financier reference. Share only with the counterparty.</p>
                      <textarea readOnly value={financierDisclosure} spellCheck={false} />
                    </>
                  ) : null}
                </div>
              ) : null}
              {issued.certificate.payoutAccountCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Payout-account disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealPayout((v) => !v)}>
                      {revealPayout ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealPayout ? (
                    <>
                      <p className={styles.warn}>Reveals the committed payout-account reference. Share only with the counterparty.</p>
                      <textarea readOnly value={payoutDisclosure} spellCheck={false} />
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
                      Contains the revenue, requested advance, blindings, and salts. Never publish or commit it — hand it
                      only to a financier you are opening the figures to.
                    </p>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`financing-secret-${issued.certificate.certificateId}.txt`, serializedSecret)}
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
              Issue a certificate to see the public badge, its serialized form, and selective-disclosure payloads. The
              revenue and requested advance never appear in the certificate.
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
              placeholder="Paste a serialized financing certificate"
              spellCheck={false}
            />
          </label>
          <label className={styles.toggle}>
            Optional disclosure <small>revenue, advance, financier, or payout account</small>
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
                      <dt>Advance factor</dt>
                      <dd>≤ {(Number(verifyResult.certificate.advanceFactorBps) / 100).toFixed(2)}% of revenue</dd>
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


