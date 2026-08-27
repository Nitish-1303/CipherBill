"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  FX_HEDGING_POOL_ADDRESS,
  buildFxHedgingAmountDisclosure,
  buildFxHedgingPairDisclosure,
  computeForwardRate,
  computeHedgingState,
  createFxHedgingIssuerKey,
  formatFxHedgingBaseUnits,
  getFxHedgingVisibilityModel,
  issueFxHedgingCertificate,
  monitorHedgingPositions,
  parseFxHedgingCertificate,
  serializeFxHedgingCertificate,
  serializeFxHedgingCertificateSecret,
  summarizeFxHedgingTrust,
  verifyFxHedgingCertificate,
  type FxHedgingKeypair,
  type IssuedFxHedgingCertificate,
} from "@/lib/fx-hedging-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./fx-hedging-portal.module.css";

const INTRO =
  "Lock forward exchange rates for future STRK20 invoice settlement while hiding notional, currency pair labels, and counterparty references behind Pedersen commitments. " +
  "Public spot reference and policy band only — the pool address is provenance and never called.";

const TRUST = summarizeFxHedgingTrust();
const VISIBILITY = getFxHedgingVisibilityModel();

function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function FxHedgingPortal() {
  const [issuer, setIssuer] = useState<FxHedgingKeypair | null>(null);
  const [merchantAlias, setMerchantAlias] = useState("Aurora Desk");
  const [deskLabel, setDeskLabel] = useState("Treasury FX");
  const [baseCurrency, setBaseCurrency] = useState("USD");
  const [quoteCurrency, setQuoteCurrency] = useState("STRK");
  const [counterpartyRef, setCounterpartyRef] = useState("counterparty_alpha");
  const [spotRate, setSpotRate] = useState("2.50");
  const [forwardPointsBps, setForwardPointsBps] = useState("120");
  const [notionalAmount, setNotionalAmount] = useState("5");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [settlementDate, setSettlementDate] = useState("2026-11-01");
  const [maxTenorDays, setMaxTenorDays] = useState("90");
  const [maxPremiumBps, setMaxPremiumBps] = useState("250");
  const [maxDiscountBps, setMaxDiscountBps] = useState("150");
  const [markSpot, setMarkSpot] = useState("2.55");
  const [issued, setIssued] = useState<IssuedFxHedgingCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [verifyInput, setVerifyInput] = useState("");
  const [verifyOk, setVerifyOk] = useState<boolean | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 30 ? parsed : 18;
  }, [assetDecimals]);

  const policy = useMemo(
    () => ({
      maxTenorDays: Number.parseInt(maxTenorDays, 10) || 90,
      maxForwardPremiumBps: Number.parseInt(maxPremiumBps, 10) || 0,
      maxForwardDiscountBps: Number.parseInt(maxDiscountBps, 10) || 0,
    }),
    [maxTenorDays, maxPremiumBps, maxDiscountBps],
  );

  const preview = useMemo(() => {
    try {
      const forward = computeForwardRate(spotRate, Number.parseInt(forwardPointsBps, 10) || 0, 2, policy);
      const notionalBaseUnits = decimalToBaseUnits(notionalAmount, decimals);
      const settlementIso = new Date(`${settlementDate}T00:00:00.000Z`).toISOString();
      const tenorDays = Math.max(0, Math.ceil((Date.parse(settlementIso) - Date.now()) / 86_400_000));
      const state = computeHedgingState(notionalBaseUnits, forward.lockedRateScaled, forward.spotRateScaled, tenorDays, policy);
      return { forward, state, notionalBaseUnits, settlementIso, tenorDays };
    } catch {
      return null;
    }
  }, [spotRate, forwardPointsBps, policy, notionalAmount, decimals, settlementDate]);

  const monitorRows = useMemo(() => {
    if (!issued || !preview) return [];
    return monitorHedgingPositions(
      [
        {
          positionId: issued.certificate.certificateId,
          baseCurrency,
          quoteCurrency,
          notionalBaseUnits: issued.secret.notionalBaseUnits,
          lockedRateScaled: issued.secret.lockedRateScaled,
          spotRateScaled: issued.certificate.spotRateScaled,
          settlementDate: issued.certificate.settlementDate,
          lockedAt: issued.certificate.lockedAt,
        },
      ],
      { [`${baseCurrency}/${quoteCurrency}`]: markSpot },
      2,
      decimals,
    );
  }, [issued, preview, baseCurrency, quoteCurrency, markSpot, decimals]);

  function generateIssuerKey() {
    setIssuer(createFxHedgingIssuerKey());
  }

  async function handleIssue(event: FormEvent) {
    event.preventDefault();
    if (!issuer || !preview || issuing) return;
    setIssuing(true);
    setIssueError(null);
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    try {
      const next = issueFxHedgingCertificate({
        merchantAlias,
        deskLabel,
        asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals },
        baseCurrency,
        quoteCurrency,
        counterpartyRef,
        spotRate,
        rateDecimals: 2,
        forwardPointsBps: Number.parseInt(forwardPointsBps, 10) || 0,
        notionalBaseUnits: preview.notionalBaseUnits,
        settlementDate: preview.settlementIso,
        policy,
        issuerSecretKey: issuer.secretKey,
        amountBitLength: 64,
      });
      setIssued(next);
      setVerifyInput(serializeFxHedgingCertificate(next.certificate));
      setVerifyOk(true);
    } catch (error) {
      setIssueError(error instanceof Error ? error.message : "Certificate could not be issued.");
    } finally {
      setIssuing(false);
    }
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseFxHedgingCertificate(verifyInput);
      setVerifyOk(verifyFxHedgingCertificate(certificate));
    } catch {
      setVerifyOk(false);
    }
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Multi-currency settlement · FX hedging</span>
          <h2>
            Forward-rate locks.
            <br />
            <em>Hidden notionals.</em>
          </h2>
          <p>{INTRO}</p>
          <p className={styles.provenance}>Pool provenance · {FX_HEDGING_POOL_ADDRESS}</p>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Zero-knowledge proofs</dt>
            <dd className={TRUST.zeroKnowledge ? styles.yes : styles.no}>{TRUST.zeroKnowledge ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt>On-chain pool integration</dt>
            <dd className={styles.no}>{TRUST.poolIntegrated ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt>Oracle-backed rates</dt>
            <dd className={styles.no}>{TRUST.oracleBacked ? "Yes" : "No"}</dd>
          </div>
        </dl>
      </header>

      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Forward-rate calculator</span>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={styles.metric}>
                <dt>Spot</dt>
                <dd>{spotRate}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Locked forward</dt>
                <dd>{(Number(preview.forward.lockedRateScaled) / 100).toFixed(2)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Tenor</dt>
                <dd>{preview.tenorDays} days</dd>
              </div>
              <div className={styles.metric}>
                <dt>Policy eligible</dt>
                <dd className={preview.state.eligible ? styles.statusOk : styles.statusWarn}>
                  {preview.state.eligible ? "Yes" : "No"}
                </dd>
              </div>
            </dl>
            <p className={styles.hint}>
              Band {Number(preview.forward.minLockedRateScaled) / 100} – {Number(preview.forward.maxLockedRateScaled) / 100} ·
              settlement {formatDate(preview.settlementIso)} · notional {notionalAmount} STRK (hidden in certificate).
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>Enter spot, forward points, and policy band to preview the lock.</p>
        )}
      </section>

      <section className={styles.vault}>
        <div className={styles.vaultHead}>
          <span>00 · Issuer key vault</span>
          <button type="button" className={styles.ghost} onClick={generateIssuerKey}>
            {issuer ? "Regenerate issuer key" : "Generate issuer key"}
          </button>
        </div>
        {issuer ? (
          <div className={styles.keyCard}>
            <h4>Public key — embed in certificates for offline authentication</h4>
            <dl>
              <dt>X</dt>
              <dd>{issuer.publicKey.x}</dd>
              <dt>Y</dt>
              <dd>{issuer.publicKey.y}</dd>
            </dl>
          </div>
        ) : (
          <p className={styles.placeholder}>Generate an issuer key before locking a forward rate.</p>
        )}
      </section>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Lock</span>
            <h3>Issue forward-rate certificate</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>
              Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} />
            </label>
            <label>
              Desk label
              <input value={deskLabel} onChange={(e) => setDeskLabel(e.target.value)} />
            </label>
            <label>
              Base currency <small>hidden until disclosed</small>
              <input value={baseCurrency} onChange={(e) => setBaseCurrency(e.target.value)} />
            </label>
            <label>
              Quote currency <small>hidden until disclosed</small>
              <input value={quoteCurrency} onChange={(e) => setQuoteCurrency(e.target.value)} />
            </label>
            <label>
              Spot rate <small>public reference</small>
              <input value={spotRate} onChange={(e) => setSpotRate(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Forward points (bps)
              <input value={forwardPointsBps} onChange={(e) => setForwardPointsBps(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Notional <small>hidden</small>
              <input value={notionalAmount} onChange={(e) => setNotionalAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Asset decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Settlement date
              <input value={settlementDate} onChange={(e) => setSettlementDate(e.target.value)} type="date" />
            </label>
            <label>
              Max tenor (days) <small>public</small>
              <input value={maxTenorDays} onChange={(e) => setMaxTenorDays(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Max premium (bps)
              <input value={maxPremiumBps} onChange={(e) => setMaxPremiumBps(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Max discount (bps)
              <input value={maxDiscountBps} onChange={(e) => setMaxDiscountBps(e.target.value)} inputMode="numeric" />
            </label>
            <label className={styles.wide}>
              Counterparty reference <small>committed, optional</small>
              <input value={counterpartyRef} onChange={(e) => setCounterpartyRef(e.target.value)} />
            </label>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={!issuer || !preview?.state.eligible || issuing}>
            {issuing ? "Issuing proofs…" : "Issue hedging certificate"}
          </button>
        </form>

        <form className={styles.verify} onSubmit={handleVerify}>
          <div className={styles.panelHead}>
            <span>02 · Verify</span>
            <h3>Authenticate certificate offline</h3>
          </div>
          <textarea
            value={verifyInput}
            onChange={(e) => setVerifyInput(e.target.value)}
            placeholder="Paste certificate JSON…"
            aria-label="Certificate JSON"
          />
          <button type="submit">Verify certificate</button>
          {verifyOk === true ? (
            <div className={styles.pass}>
              <strong>Certificate verified</strong>
            </div>
          ) : null}
          {verifyOk === false ? (
            <div className={styles.fail}>
              <strong>Verification failed</strong>
            </div>
          ) : null}
        </form>
      </div>

      {issued ? (
        <section className={styles.dashboard}>
          <div className={styles.dashHead}>
            <span>Position monitor</span>
          </div>
          <label className={styles.fields}>
            Mark spot ({baseCurrency}/{quoteCurrency})
            <input value={markSpot} onChange={(e) => setMarkSpot(e.target.value)} inputMode="decimal" />
          </label>
          <div className={styles.tableWrap}>
            <table className={styles.jurTable}>
              <thead>
                <tr>
                  <th>Pair</th>
                  <th>Notional</th>
                  <th>Locked</th>
                  <th>Mark</th>
                  <th>PnL (bps)</th>
                  <th>Tenor left</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {monitorRows.map((row) => (
                  <tr key={row.positionId}>
                    <td>{row.pairLabel}</td>
                    <td>{row.notionalDisplay}</td>
                    <td>{row.lockedRateDisplay}</td>
                    <td>{row.markRateDisplay}</td>
                    <td>{row.unrealizedPnlBps}</td>
                    <td>{row.tenorDaysRemaining}d</td>
                    <td className={row.status === "in-band" ? styles.statusOk : styles.statusWarn}>{row.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.badge}>
            <div className={styles.badgeTop}>
              <div>
                <strong>{issued.certificate.merchantAlias}</strong>
                <small>{issued.certificate.deskLabel}</small>
              </div>
              <span className={styles.verified}>Verified lock</span>
            </div>
            <dl className={styles.badgeMeta}>
              <div>
                <dt>Settlement</dt>
                <dd>{formatDate(issued.certificate.settlementDate)}</dd>
              </div>
              <div>
                <dt>Forward points</dt>
                <dd>{issued.secret.forwardPointsBps} bps</dd>
              </div>
              <div>
                <dt>Notional (secret)</dt>
                <dd>{formatFxHedgingBaseUnits(issued.secret.notionalBaseUnits, decimals)} STRK</dd>
              </div>
              <div>
                <dt>Pair opening</dt>
                <dd>
                  {buildFxHedgingPairDisclosure(issued.certificate, issued.secret).baseCurrency}/
                  {buildFxHedgingPairDisclosure(issued.certificate, issued.secret).quoteCurrency}
                </dd>
              </div>
            </dl>
            <div className={styles.export}>
              <textarea readOnly value={serializeFxHedgingCertificate(issued.certificate)} aria-label="Exported certificate" />
            </div>
            <div className={styles.secret}>
              <textarea readOnly value={serializeFxHedgingCertificateSecret(issued.secret)} aria-label="Issuer secret bundle" />
              <p className={styles.hint}>
                Amount disclosure sample:{" "}
                {buildFxHedgingAmountDisclosure(issued.certificate, issued.secret, "notional").value} base units
              </p>
            </div>
          </div>
        </section>
      ) : null}

      <section className={styles.model}>
        <div>
          <h4>Hidden from verifier</h4>
          <ul>
            {VISIBILITY.hiddenFromVerifier.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>Disclosed to verifier</h4>
          <ul>
            {VISIBILITY.disclosedToVerifier.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>Limitation</h4>
          <p className={styles.hint}>{VISIBILITY.limitation}</p>
        </div>
      </section>
    </div>
  );
}
