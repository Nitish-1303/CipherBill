"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  LOYALTY_POOL_ADDRESS,
  MAX_LOYALTY_MONTHS,
  buildLoyaltyAccountDisclosure,
  buildLoyaltyCertificateBadge,
  buildLoyaltyMetricDisclosure,
  buildLoyaltyMonthDisclosure,
  buildLoyaltyRebateClaim,
  computeLoyaltyState,
  createLoyaltyIssuerKey,
  formatLoyaltyBaseUnits,
  formatLoyaltyBps,
  getLoyaltyVisibilityModel,
  issueLoyaltyCertificate,
  parseLoyaltyCertificate,
  parseLoyaltyMetricDisclosure,
  parseLoyaltyMonthDisclosure,
  parseLoyaltyRefDisclosure,
  serializeLoyaltyCertificate,
  serializeLoyaltyCertificateSecret,
  serializeLoyaltyMetricDisclosure,
  serializeLoyaltyMonthDisclosure,
  serializeLoyaltyRefDisclosure,
  summarizeLoyaltyTrust,
  verifyLoyaltyCertificate,
  verifyLoyaltyMetricDisclosure,
  verifyLoyaltyMonthDisclosure,
  verifyLoyaltyRefDisclosure,
  type IssuedLoyaltyCertificate,
  type LoyaltyCertificate,
  type LoyaltyKeypair,
  type LoyaltyPolicy,
} from "@/lib/loyalty-rebate-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./loyalty-rebate-portal.module.css";
const INTRO =
  "Prove in zero knowledge that a merchant's hidden monthly settlement volumes aggregate into a total that lands in a public loyalty tier — earning that tier's published protocol-fee discount and tokenized cashback rate — and that the hidden cashback commitment is exactly floor(cashbackBps · total / 10000), without revealing any single month, the aggregate, the cashback amount, or the customer list. The merchant signs the certificate so anyone can authenticate it offline, and the cashback opening doubles as a rebate-claim voucher. Tiers, discounts, and cashback are deterministic heuristics settled out of band — not a financial product or advice. Nothing here moves funds, reduces an on-chain fee or gas, or calls the STRK20 pool contract; the pool address is provenance only.";

const TRUST = summarizeLoyaltyTrust();
const VISIBILITY = getLoyaltyVisibilityModel();

interface TierRow {
  name: string;
  floor: string;
  feeDiscountBps: string;
  cashbackBps: string;
}

const DEFAULT_TIERS: TierRow[] = [
  { name: "Bronze", floor: "0", feeDiscountBps: "0", cashbackBps: "0" },
  { name: "Silver", floor: "1000", feeDiscountBps: "500", cashbackBps: "100" },
  { name: "Gold", floor: "5000", feeDiscountBps: "1500", cashbackBps: "250" },
  { name: "Platinum", floor: "20000", feeDiscountBps: "3000", cashbackBps: "500" },
];

const DEFAULT_MONTHS = ["2500", "3100", "1800"];

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
/** Converts a decimal amount to base units, mapping an explicit zero to "0". The loyalty engine
 *  requires the base tier floor to be 0 and allows zero-value months, but decimalToBaseUnits only
 *  accepts strictly positive amounts — so route zeros around it. */
function toBaseUnitsAllowingZero(value: string, decimals: number): string {
  const trimmed = value.trim();
  if (trimmed === "" || /^0(?:\.0+)?$/.test(trimmed)) return "0";
  return decimalToBaseUnits(trimmed, decimals);
}

/** Builds the public policy (floors in base units) from the editable tier rows. */
function buildPolicy(tiers: TierRow[], decimals: number): LoyaltyPolicy {
  return {
    tiers: tiers.map((t) => ({
      name: t.name.trim(),
      floorBaseUnits: toBaseUnitsAllowingZero(t.floor, decimals),
      feeDiscountBps: Number.parseInt(t.feeDiscountBps, 10),
      cashbackBps: Number.parseInt(t.cashbackBps, 10),
    })),
  };
}

/** Converts the decimal monthly-volume inputs into base-unit strings. */
function buildMonthlyVolumes(months: string[], decimals: number): string[] {
  return months.filter((m) => m.trim().length > 0).map((m) => toBaseUnitsAllowingZero(m, decimals));
}

interface DisclosureResult {
  label: string;
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  certificate?: LoyaltyCertificate;
  disclosure?: DisclosureResult;
  error?: string;
}

export function LoyaltyRebatePortal() {
  const [issuer, setIssuer] = useState<LoyaltyKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [merchantAlias, setMerchantAlias] = useState("Northwind Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [periodLabel, setPeriodLabel] = useState("FY26 H1");
  const [programLabel, setProgramLabel] = useState("Merchant Volume Loyalty");
  const [accountRef, setAccountRef] = useState("member:northwind-0xabc");
  const [memo, setMemo] = useState("H1 aggregate");
  const [tiers, setTiers] = useState<TierRow[]>(DEFAULT_TIERS);
  const [months, setMonths] = useState<string[]>(DEFAULT_MONTHS);

  const [issued, setIssued] = useState<IssuedLoyaltyCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealAccount, setRevealAccount] = useState(false);
  const [revealClaim, setRevealClaim] = useState(false);

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);
  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 18 ? parsed : 18;
  }, [assetDecimals]);

  const preview = useMemo(() => {
    try {
      const policy = buildPolicy(tiers, decimals);
      const metrics = { monthlyVolumesBaseUnits: buildMonthlyVolumes(months, decimals) };
      return computeLoyaltyState(metrics, policy);
    } catch {
      return null;
    }
  }, [tiers, months, decimals]);

  const badge = useMemo(() => (issued ? buildLoyaltyCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(() => (issued ? serializeLoyaltyCertificate(issued.certificate) : ""), [issued]);
  const serializedSecret = useMemo(() => (issued ? serializeLoyaltyCertificateSecret(issued.secret) : ""), [issued]);
  const totalDisclosure = useMemo(
    () => (issued ? serializeLoyaltyMetricDisclosure(buildLoyaltyMetricDisclosure(issued.secret, "total")) : ""),
    [issued],
  );
  const rebateClaim = useMemo(
    () => (issued ? serializeLoyaltyMetricDisclosure(buildLoyaltyRebateClaim(issued.secret)) : ""),
    [issued],
  );
  const monthDisclosures = useMemo(
    () =>
      issued
        ? issued.secret.monthlyVolumesBaseUnits.map((_, i) => ({
            index: i,
            payload: serializeLoyaltyMonthDisclosure(buildLoyaltyMonthDisclosure(issued.secret, i)),
          }))
        : [],
    [issued],
  );
  const accountDisclosure = useMemo(
    () => (issued && issued.certificate.accountCommitted ? serializeLoyaltyRefDisclosure(buildLoyaltyAccountDisclosure(issued.secret)) : ""),
    [issued],
  );

  function updateTier(index: number, key: keyof TierRow, value: string) {
    setTiers((rows) => rows.map((row, i) => (i === index ? { ...row, [key]: value } : row)));
  }

  function updateMonth(index: number, value: string) {
    setMonths((list) => list.map((m, i) => (i === index ? value : m)));
  }

  function addMonth() {
    setMonths((list) => (list.length >= MAX_LOYALTY_MONTHS ? list : [...list, "0"]));
  }

  function removeMonth(index: number) {
    setMonths((list) => (list.length <= 1 ? list : list.filter((_, i) => i !== index)));
  }

  function generateIssuerKey() {
    setIssuer(createLoyaltyIssuerKey());
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
    setRevealAccount(false);
    setRevealClaim(false);
    // Defer so the "Proving in zero knowledge…" label paints before the synchronous proof blocks the thread.
    setTimeout(() => {
      try {
        const result = issueLoyaltyCertificate({
          merchantAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          periodLabel,
          programLabel,
          policy: buildPolicy(tiers, decimals),
          metrics: { monthlyVolumesBaseUnits: buildMonthlyVolumes(months, decimals) },
          accountRef: accountRef.trim() || undefined,
          issuerSecretKey: issuer.secretKey,
          memo: memo.trim() || undefined,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the loyalty certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseLoyaltyCertificate(verifyInput.trim());
      const ok = verifyLoyaltyCertificate(certificate);
      let disclosure: DisclosureResult | undefined;
      const raw = disclosureInput.trim();
      if (raw) {
        disclosure = evaluateDisclosure(certificate, raw);
      }
      setVerifyResult({ ok, certificate, disclosure });
    } catch (error) {
      setVerifyResult({ ok: false, error: error instanceof Error ? error.message : "The certificate could not be parsed." });
    }
  }

  /** Detects the disclosure kind, verifies it against the certificate, and formats the opened figure. */
  function evaluateDisclosure(certificate: LoyaltyCertificate, raw: string): DisclosureResult {
    const asAmount = (value: string) => `${formatLoyaltyBaseUnits(value, certificate.assetDecimals)} ${certificate.assetSymbol}`;
    try {
      const metric = parseLoyaltyMetricDisclosure(raw);
      return {
        label: metric.metric === "cashback" ? "Cashback / rebate-claim" : "Aggregate volume",
        ok: verifyLoyaltyMetricDisclosure(certificate, metric),
        value: asAmount(metric.valueBaseUnits),
      };
    } catch {
      /* not a metric disclosure */
    }
    try {
      const month = parseLoyaltyMonthDisclosure(raw);
      return {
        label: `Month ${month.monthIndex + 1} volume`,
        ok: verifyLoyaltyMonthDisclosure(certificate, month),
        value: asAmount(month.valueBaseUnits),
      };
    } catch {
      /* not a month disclosure */
    }
    const ref = parseLoyaltyRefDisclosure(raw);
    return {
      label: "Account reference",
      ok: verifyLoyaltyRefDisclosure(certificate, ref),
      value: ref.value || "(empty)",
    };
  }
  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Merchant volume loyalty</span>
          <h2>
            Prove a loyalty tier over <em>hidden volume</em>.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(LOYALTY_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Aggregate lands in a public tier band</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Cashback = exact floor of tier rate</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Applies or settles any fee or cashback</dt>
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
          <span>Loyalty standing</span>
          <small>Deterministic heuristic · discounts and cashback settle out of band, not on-chain</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Tier</dt>
                <dd>{preview.tierName}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Fee discount</dt>
                <dd>{formatLoyaltyBps(preview.feeDiscountBps)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Cashback rate</dt>
                <dd>{formatLoyaltyBps(preview.cashbackBps)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Aggregate volume</dt>
                <dd>
                  {formatLoyaltyBaseUnits(preview.totalVolumeBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
            </dl>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>
                  {preview.isTopTier
                    ? "Top tier reached"
                    : `${formatLoyaltyBaseUnits(preview.volumeToNextTierBaseUnits ?? "0", decimals)} ${assetSymbol} to next tier`}
                </span>
                <span>{(Number(preview.tierProgressBps) / 100).toFixed(1)}%</span>
              </div>
              <div className={styles.meter} role="progressbar" aria-valuenow={Number(preview.tierProgressBps) / 100} aria-valuemin={0} aria-valuemax={100}>
                <span style={{ width: `${Math.min(100, Number(preview.tierProgressBps) / 100)}%` }} />
              </div>
              <p className={styles.hint}>
                Estimated cashback at this tier: {formatLoyaltyBaseUnits(preview.cashbackBaseUnits, decimals)} {assetSymbol} ·
                floor(cashbackBps · aggregate / 10000). Computed in your browser; the proof binds it without revealing it.
              </p>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>Tier</th>
                    <th>Floor</th>
                    <th>Fee discount</th>
                    <th>Cashback</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {tiers.map((row, i) => (
                    <tr key={`${row.name}-${i}`} className={i === preview.tierIndex ? styles.activeTier : undefined}>
                      <td>{row.name}</td>
                      <td>
                        {row.floor} {assetSymbol}
                      </td>
                      <td>{formatLoyaltyBps(row.feeDiscountBps || "0")}</td>
                      <td>{formatLoyaltyBps(row.cashbackBps || "0")}</td>
                      <td>{i === preview.tierIndex ? "◆ current" : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <p className={styles.placeholder}>
            Enter a valid ascending tier ladder (base tier at floor 0) and at least one monthly volume to preview the tier,
            fee discount, cashback rate, and progress to the next tier. Every figure stays in your browser.
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
            <h3>Attest a loyalty tier over hidden volume</h3>
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
              Period label <small>public</small>
              <input value={periodLabel} onChange={(e) => setPeriodLabel(e.target.value)} />
            </label>
            <label>
              Program label <small>public</small>
              <input value={programLabel} onChange={(e) => setProgramLabel(e.target.value)} />
            </label>
            <label>
              Account reference <small>committed, optional</small>
              <input value={accountRef} onChange={(e) => setAccountRef(e.target.value)} />
            </label>
            <label>
              Memo <small>public, optional</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} />
            </label>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Public tier ladder</span>
              <small>ascending floors · base tier at 0</small>
            </div>
            <div className={styles.tierEditor}>
              {tiers.map((row, i) => (
                <div className={styles.tierEditRow} key={`tier-${i}`}>
                  <input aria-label={`Tier ${i + 1} name`} value={row.name} onChange={(e) => updateTier(i, "name", e.target.value)} placeholder="Name" />
                  <input aria-label={`Tier ${i + 1} floor`} value={row.floor} onChange={(e) => updateTier(i, "floor", e.target.value)} inputMode="decimal" placeholder="Floor" />
                  <input aria-label={`Tier ${i + 1} fee bps`} value={row.feeDiscountBps} onChange={(e) => updateTier(i, "feeDiscountBps", e.target.value)} inputMode="numeric" placeholder="Fee bps" />
                  <input aria-label={`Tier ${i + 1} cashback bps`} value={row.cashbackBps} onChange={(e) => updateTier(i, "cashbackBps", e.target.value)} inputMode="numeric" placeholder="Cash bps" />
                </div>
              ))}
            </div>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Hidden monthly volumes</span>
              <button type="button" className={styles.ghost} onClick={addMonth} disabled={months.length >= MAX_LOYALTY_MONTHS}>
                + Add month
              </button>
            </div>
            <div className={styles.monthEditor}>
              {months.map((value, i) => (
                <div className={styles.monthRow} key={`month-${i}`}>
                  <span>M{i + 1}</span>
                  <input aria-label={`Month ${i + 1} volume`} value={value} onChange={(e) => updateMonth(i, e.target.value)} inputMode="decimal" />
                  <button type="button" className={styles.ghost} onClick={() => removeMonth(i)} disabled={months.length <= 1} aria-label={`Remove month ${i + 1}`}>
                    ×
                  </button>
                </div>
              ))}
            </div>
            <p className={styles.hint}>
              Each month is committed and range-proven separately, so proving time grows with the month count and the
              value bit-width. A handful of months keeps the in-browser proof responsive.
            </p>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing}>
            {issuing ? "Proving in zero knowledge…" : "Issue loyalty certificate"}
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
                      {badge.programLabel} · {badge.periodLabel}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  <b>{badge.tierName}</b> tier
                  <small>
                    {badge.feeDiscountDisplay} fee discount · {badge.cashbackDisplay} cashback · issued {formatDate(badge.createdAt)}
                  </small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div>
                    <dt>Tier floor</dt>
                    <dd>{badge.tierFloorDisplay}</dd>
                  </div>
                  <div>
                    <dt>Next floor</dt>
                    <dd>{badge.nextTierFloorDisplay}</dd>
                  </div>
                  <div>
                    <dt>Months aggregated</dt>
                    <dd>{badge.monthCount}</dd>
                  </div>
                  <div>
                    <dt>Account</dt>
                    <dd>{badge.accountCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Serialized certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`loyalty-certificate-${issued.certificate.certificateId}.txt`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Aggregate-volume disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`loyalty-total-${issued.certificate.certificateId}.txt`, totalDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <p className={styles.hint}>Opens only the aggregate volume against the summed commitments; each month stays hidden.</p>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Per-month disclosures</span>
                </div>
                {monthDisclosures.map((m) => (
                  <div className={styles.exportHead} key={m.index}>
                    <span>Month {m.index + 1}</span>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`loyalty-month-${m.index + 1}-${issued.certificate.certificateId}.txt`, m.payload)}
                    >
                      Download
                    </button>
                  </div>
                ))}
                <p className={styles.hint}>Each payload opens exactly one committed month to a counterparty; the others stay hidden.</p>
              </div>
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Cashback — rebate-claim voucher</span>
                  <button type="button" className={styles.ghost} onClick={() => setRevealClaim((v) => !v)}>
                    {revealClaim ? "Hide" : "Reveal"}
                  </button>
                </div>
                {revealClaim ? (
                  <>
                    <p className={styles.warn}>
                      Opens the exact cashback amount so a counterparty can verify and settle the rebate out of band.
                      Revealing it also reveals the aggregate (cashback = rate · aggregate). It does not itself move funds.
                    </p>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`loyalty-rebate-claim-${issued.certificate.certificateId}.txt`, rebateClaim)}
                      >
                        Download voucher
                      </button>
                    </div>
                    <textarea readOnly value={rebateClaim} spellCheck={false} />
                  </>
                ) : null}
              </div>
              {issued.certificate.accountCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Account disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealAccount((v) => !v)}>
                      {revealAccount ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealAccount ? (
                    <>
                      <p className={styles.warn}>Reveals the committed account reference. Share only with the counterparty.</p>
                      <textarea readOnly value={accountDisclosure} spellCheck={false} />
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
                      Contains every monthly volume, the aggregate, the cashback, all blindings, and the account salt.
                      Never publish or commit it — hand it only to a counterparty you are opening every figure to.
                    </p>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`loyalty-secret-${issued.certificate.certificateId}.txt`, serializedSecret)}
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
              month, the aggregate, nor the cashback amount ever appears in the certificate.
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
              placeholder="Paste a serialized loyalty certificate"
              spellCheck={false}
            />
          </label>
          <label className={styles.toggle}>
            Optional disclosure <small>an aggregate, cashback, month, or account payload</small>
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
                      <dt>Tier</dt>
                      <dd>
                        {verifyResult.certificate.tierName} · {formatLoyaltyBps(verifyResult.certificate.feeDiscountBps)} /{" "}
                        {formatLoyaltyBps(verifyResult.certificate.cashbackBps)}
                      </dd>
                    </div>
                    <div>
                      <dt>Months</dt>
                      <dd>{verifyResult.certificate.monthCount}</dd>
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
