"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  MAX_ASSET_DECIMALS,
  TREASURY_SWEEP_POOL_ADDRESS,
  aggregateIdleLedger,
  assessSweepEfficiency,
  buildTreasurySweepAmountDisclosure,
  buildTreasurySweepCertificateBadge,
  buildTreasurySweepMandateDisclosure,
  buildTreasurySweepVenueDisclosure,
  computeTreasurySweepState,
  createTreasurySweepIssuerKey,
  evaluateSweepTrigger,
  formatBpsShare,
  formatIdleDays,
  formatTreasuryBaseUnits,
  getTreasurySweepVisibilityModel,
  issueTreasurySweepCertificate,
  parseTreasurySweepAmountDisclosure,
  parseTreasurySweepCertificate,
  parseTreasurySweepRefDisclosure,
  projectSweepYieldSchedule,
  serializeTreasurySweepAmountDisclosure,
  serializeTreasurySweepCertificate,
  serializeTreasurySweepCertificateSecret,
  serializeTreasurySweepRefDisclosure,
  summarizeTreasurySweepTrust,
  verifyTreasurySweepAmountDisclosure,
  verifyTreasurySweepCertificate,
  verifyTreasurySweepRefDisclosure,
  type IssuedTreasurySweepCertificate,
  type SweepEfficiencyBand,
  type TreasuryBalanceRow,
  type TreasurySweepAmountField,
  type TreasurySweepCertificate,
  type TreasurySweepKeypair,
} from "@/lib/treasury-sweep-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./treasury-sweep-portal.module.css";
const INTRO =
  "Prove in zero knowledge that four hidden idle-age treasury tiers conserve a committed total, that a hidden sweep amount is drawn only from the eligible idle band, leaves a public retained reserve intact, and stays under a public share cap, and that a hidden projected yield clears a public hurdle — without revealing any tier balance, the sweep size, the yield figure, or the venue label. The merchant signs the certificate so anyone can authenticate it offline. Nothing here sweeps, moves, deposits, stakes, lends, or invests value: there is no vault and no counterparty, accrual schedules are deterministic integer arithmetic at an operator-typed rate, and this engine never reads from or writes to the STRK20 pool contract.";

const TRUST = summarizeTreasurySweepTrust();
const VISIBILITY = getTreasurySweepVisibilityModel();

const BAND_LABEL: Record<SweepEfficiencyBand, string> = {
  optimal: "Optimal",
  adequate: "Adequate",
  lagging: "Lagging",
  "idle-heavy": "Idle-heavy",
};

const AMOUNT_FIELDS: { value: TreasurySweepAmountField; label: string }[] = [
  { value: "totalIdle", label: "Total idle capital" },
  { value: "eligibleIdle", label: "Eligible idle band" },
  { value: "sweep", label: "Sweep amount" },
  { value: "yield", label: "Projected yield" },
  { value: "tier0", label: "Tier 0 · Active" },
  { value: "tier1", label: "Tier 1 · Idle 7-30" },
  { value: "tier2", label: "Tier 2 · Idle 31-90" },
  { value: "tier3", label: "Tier 3 · Idle 90+" },
];

const BIT_LENGTHS = ["32", "48", "64", "96", "128"];

interface BalanceDraft {
  id: string;
  alias: string;
  lastMovedAt: string;
  amount: string;
}

interface DisclosureResult {
  type: string;
  ok: boolean;
  value: string;
}

interface VerifyMetaRow {
  label: string;
  value: string;
}

interface VerifyState {
  ok: boolean;
  meta?: VerifyMetaRow[];
  disclosure?: DisclosureResult;
  error?: string;
}
const DEFAULT_BALANCES: BalanceDraft[] = [
  { id: "bal_1", alias: "ops-hot", lastMovedAt: "2026-08-29", amount: "2" },
  { id: "bal_2", alias: "ops-warm", lastMovedAt: "2026-08-11", amount: "3" },
  { id: "bal_3", alias: "reserve-q3", lastMovedAt: "2026-07-01", amount: "4" },
  { id: "bal_4", alias: "vault-cold", lastMovedAt: "2026-01-15", amount: "6" },
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

/** decimalToBaseUnits rejects "0", so an explicit zero floor is routed around it. */
function toBaseUnitsAllowingZero(value: string, decimals: number): string {
  const trimmed = value.trim();
  if (!trimmed || /^0*(\.0*)?$/.test(trimmed)) return "0";
  return decimalToBaseUnits(trimmed, decimals);
}

function toBalanceRows(drafts: BalanceDraft[], decimals: number): TreasuryBalanceRow[] {
  return drafts.map((row) => ({
    alias: row.alias,
    lastMovedAt: new Date(`${row.lastMovedAt}T00:00:00.000Z`).toISOString(),
    balanceBaseUnits: toBaseUnitsAllowingZero(row.amount, decimals),
  }));
}

function parseIntOrZero(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Classifies a pasted disclosure payload. Every branch — including the last —
 * returns a neutral result instead of throwing, so an unrecognized payload can
 * never overwrite an otherwise valid certificate verdict.
 */
function evaluateDisclosure(certificate: TreasurySweepCertificate, raw: string): DisclosureResult {
  try {
    const amount = parseTreasurySweepAmountDisclosure(raw);
    const ok = verifyTreasurySweepAmountDisclosure(certificate, amount);
    let value: string;
    try {
      value = `${formatTreasuryBaseUnits(amount.amountBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`;
    } catch {
      value = `${amount.amountBaseUnits} base units`;
    }
    return { type: amount.field, ok, value };
  } catch {
    /* Not an amount disclosure — try the reference form below. */
  }
  try {
    const ref = parseTreasurySweepRefDisclosure(raw);
    return { type: ref.field, ok: verifyTreasurySweepRefDisclosure(certificate, ref), value: ref.value || "(empty)" };
  } catch {
    return { type: "unrecognized", ok: false, value: "This payload is not a treasury sweep disclosure." };
  }
}

/**
 * Flattens a pasted certificate into display rows. Parsing only checks the
 * envelope kind, so every field here is still untrusted: formatting runs inside
 * handleVerify's try block so a malformed figure surfaces as a read error
 * instead of throwing during render.
 */
function describeCertificate(certificate: TreasurySweepCertificate): VerifyMetaRow[] {
  return [
    { label: "Merchant", value: certificate.merchantAlias },
    { label: "Mandate", value: certificate.mandateRef },
    {
      label: "Reserve floor",
      value: `${formatTreasuryBaseUnits(certificate.minReserveBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    },
    { label: "Share cap", value: `${formatBpsShare(certificate.maxSweepShareBps)} of total idle` },
    { label: "Yield hurdle", value: `${formatBpsShare(certificate.minYieldBps)} (operator-typed)` },
    { label: "Issued", value: formatDate(certificate.createdAt) },
    { label: "Pool provenance", value: shorten(certificate.poolAddress) },
    { label: "Binding", value: shorten(certificate.bindingHash) },
  ];
}
export function TreasurySweepPortal() {
  const [issuer, setIssuer] = useState<TreasurySweepKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [mandateRef, setMandateRef] = useState("TREAS-2026-Q3");
  const [programLabel, setProgramLabel] = useState("Idle Capital Sweep");
  const [minReserveAmount, setMinReserveAmount] = useState("4");
  const [maxSweepShareBps, setMaxSweepShareBps] = useState("6500");
  const [minYieldBps, setMinYieldBps] = useState("400");
  const [sweepAmount, setSweepAmount] = useState("9");
  const [projectedYieldAmount, setProjectedYieldAmount] = useState("0.45");
  const [venueRef, setVenueRef] = useState("strategy_ladder_v1");
  const [triggerAmount, setTriggerAmount] = useState("8");
  const [amountBitLength, setAmountBitLength] = useState("64");
  const [balances, setBalances] = useState<BalanceDraft[]>(DEFAULT_BALANCES);

  const [annualRateBps, setAnnualRateBps] = useState("500");
  const [periodsPerYear, setPeriodsPerYear] = useState("12");
  const [periodCount, setPeriodCount] = useState("6");
  const [compounding, setCompounding] = useState(true);

  const [issued, setIssued] = useState<IssuedTreasurySweepCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealVenue, setRevealVenue] = useState(false);
  const [amountField, setAmountField] = useState<TreasurySweepAmountField>("sweep");

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= MAX_ASSET_DECIMALS ? parsed : 18;
  }, [assetDecimals]);

  const bitLength = useMemo(() => {
    const parsed = Number.parseInt(amountBitLength, 10);
    return Number.isFinite(parsed) && parsed >= 8 && parsed <= 128 ? parsed : 64;
  }, [amountBitLength]);

  const bandCeiling = useMemo(() => {
    try {
      return formatTreasuryBaseUnits((2n ** BigInt(bitLength) - 1n).toString(), decimals);
    } catch {
      return null;
    }
  }, [bitLength, decimals]);

  const preview = useMemo(() => {
    try {
      const policy = {
        minReserveBaseUnits: toBaseUnitsAllowingZero(minReserveAmount, decimals),
        maxSweepShareBps: parseIntOrZero(maxSweepShareBps),
        minYieldBps: parseIntOrZero(minYieldBps),
      };
      const ledger = aggregateIdleLedger(toBalanceRows(balances, decimals));
      const tiers = ledger.tiers.map((tier) => tier.balanceBaseUnits) as [string, string, string, string];
      const sweepBaseUnits = toBaseUnitsAllowingZero(sweepAmount, decimals);
      const yieldBaseUnits = toBaseUnitsAllowingZero(projectedYieldAmount, decimals);
      const state = computeTreasurySweepState(tiers, sweepBaseUnits, yieldBaseUnits, policy);
      const efficiency = assessSweepEfficiency(state);
      const trigger = evaluateSweepTrigger(state, toBaseUnitsAllowingZero(triggerAmount, decimals));
      const schedule = projectSweepYieldSchedule(
        sweepBaseUnits,
        parseIntOrZero(annualRateBps),
        parseIntOrZero(periodsPerYear),
        parseIntOrZero(periodCount),
        compounding,
      );
      const shareRatio = policy.maxSweepShareBps > 0 ? (Number(state.sweepShareBps) / policy.maxSweepShareBps) * 100 : 0;
      const hurdleRatio = policy.minYieldBps > 0 ? (Number(state.impliedYieldBps) / policy.minYieldBps) * 100 : 100;
      return { policy, ledger, tiers, state, efficiency, trigger, schedule, shareRatio, hurdleRatio };
    } catch {
      return null;
    }
  }, [
    balances,
    decimals,
    minReserveAmount,
    maxSweepShareBps,
    minYieldBps,
    sweepAmount,
    projectedYieldAmount,
    triggerAmount,
    annualRateBps,
    periodsPerYear,
    periodCount,
    compounding,
  ]);

  const badge = useMemo(() => (issued ? buildTreasurySweepCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(() => (issued ? serializeTreasurySweepCertificate(issued.certificate) : ""), [issued]);
  const serializedSecret = useMemo(() => (issued ? serializeTreasurySweepCertificateSecret(issued.secret) : ""), [issued]);
  const amountDisclosure = useMemo(() => {
    if (!issued) return "";
    try {
      return serializeTreasurySweepAmountDisclosure(buildTreasurySweepAmountDisclosure(issued.secret, amountField));
    } catch {
      return "";
    }
  }, [issued, amountField]);

  const mandateDisclosure = useMemo(
    () => (issued ? serializeTreasurySweepRefDisclosure(buildTreasurySweepMandateDisclosure(issued.secret)) : ""),
    [issued],
  );

  const venueDisclosure = useMemo(() => {
    if (!issued || !issued.certificate.venueCommitted) return "";
    try {
      return serializeTreasurySweepRefDisclosure(buildTreasurySweepVenueDisclosure(issued.secret));
    } catch {
      return "";
    }
  }, [issued]);

  function generateIssuerKey() {
    setIssuer(createTreasurySweepIssuerKey());
    setRevealSecretKey(false);
  }

  function updateBalance(id: string, patch: Partial<BalanceDraft>) {
    setBalances((rows) => rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  function addBalanceRow() {
    setBalances((rows) => [
      ...rows,
      { id: `bal_${Date.now()}`, alias: "treasury-account", lastMovedAt: "2026-06-01", amount: "1" },
    ]);
  }

  function removeBalanceRow(id: string) {
    setBalances((rows) => (rows.length > 1 ? rows.filter((row) => row.id !== id) : rows));
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
    setRevealVenue(false);
    setTimeout(() => {
      try {
        const ledger = aggregateIdleLedger(toBalanceRows(balances, decimals));
        const tiers = ledger.tiers.map((tier) => tier.balanceBaseUnits) as [string, string, string, string];
        const result = issueTreasurySweepCertificate({
          merchantAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          mandateRef,
          programLabel,
          policy: {
            minReserveBaseUnits: toBaseUnitsAllowingZero(minReserveAmount, decimals),
            maxSweepShareBps: parseIntOrZero(maxSweepShareBps),
            minYieldBps: parseIntOrZero(minYieldBps),
          },
          tierBalancesBaseUnits: tiers,
          sweepBaseUnits: toBaseUnitsAllowingZero(sweepAmount, decimals),
          projectedYieldBaseUnits: toBaseUnitsAllowingZero(projectedYieldAmount, decimals),
          venueRef,
          issuerSecretKey: issuer.secretKey,
          amountBitLength: bitLength,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the treasury sweep certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }
  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseTreasurySweepCertificate(verifyInput.trim());
      const ok = verifyTreasurySweepCertificate(certificate);
      const raw = disclosureInput.trim();
      const disclosure = raw ? evaluateDisclosure(certificate, raw) : undefined;
      setVerifyResult({ ok, meta: describeCertificate(certificate), disclosure });
    } catch (error) {
      setVerifyResult({ ok: false, error: error instanceof Error ? error.message : "The certificate could not be parsed." });
    }
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Treasury yield & idle capital sweep</span>
          <h2>
            Prove idle-tier <em>covenants</em> without revealing the treasury.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(TREASURY_SWEEP_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Tier conservation + 4 covenants</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Issuer signature</dt>
            <dd className={styles.yes}>Authenticated</dd>
          </div>
          <div>
            <dt>Sweeps, stakes, or invests funds</dt>
            <dd className={styles.no}>Never</dd>
          </div>
          <div>
            <dt>Vault, venue, or interest</dt>
            <dd className={styles.no}>None exists</dd>
          </div>
          <div>
            <dt>STRK20 pool contract</dt>
            <dd className={styles.no}>Never called</dd>
          </div>
        </dl>
      </header>
      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Institutional idle-capital dashboard</span>
          <small>Deterministic arithmetic · no vault, no venue, no offered rate, not financial advice</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Idle capital</dt>
                <dd>
                  {formatTreasuryBaseUnits(preview.ledger.totalIdleBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Eligible band</dt>
                <dd>
                  {formatTreasuryBaseUnits(preview.ledger.eligibleIdleBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Avg. idle age</dt>
                <dd>{formatIdleDays(preview.ledger.averageIdleDays)}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Sweep efficiency</dt>
                <dd>
                  {BAND_LABEL[preview.efficiency.band]} · {preview.efficiency.score}
                </dd>
              </div>
            </dl>
            {!preview.state.eligible ? (
              <p className={styles.warn}>
                One or more covenant surpluses is negative — no honest eligibility proof exists until the tiers, the sweep,
                the projected yield, or the public covenants change.
              </p>
            ) : null}
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>Sweep share vs public cap</span>
                <span>
                  {formatBpsShare(preview.state.sweepShareBps)} / {formatBpsShare(preview.state.maxSweepShareBps)}
                </span>
              </div>
              <div className={`${styles.meter} ${styles.meterCap}`}>
                <span style={{ width: `${Math.max(0, Math.min(100, preview.shareRatio))}%` }} />
              </div>
            </div>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>Implied yield vs public hurdle</span>
                <span>
                  {formatBpsShare(preview.state.impliedYieldBps)} / {formatBpsShare(preview.state.minYieldBps)}
                </span>
              </div>
              <div className={styles.meter}>
                <span style={{ width: `${Math.max(0, Math.min(100, preview.hurdleRatio))}%` }} />
              </div>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.tierTable}>
                <thead>
                  <tr>
                    <th>Idle-age tier</th>
                    <th>Accounts</th>
                    <th>Balance</th>
                    <th>Sweep-eligible</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.ledger.tiers.map((tier) => (
                    <tr key={tier.label} className={tier.sweepEligible ? styles.activeTier : styles.mutedRow}>
                      <td>{tier.label}</td>
                      <td>{tier.accountCount}</td>
                      <td>
                        {formatTreasuryBaseUnits(tier.balanceBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td>{tier.sweepEligible ? "Eligible" : "Working capital"}</td>
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr>
                    <td>Total idle</td>
                    <td>{preview.ledger.tiers.reduce((acc, tier) => acc + tier.accountCount, 0)}</td>
                    <td>
                      {formatTreasuryBaseUnits(preview.ledger.totalIdleBaseUnits, decimals)} {assetSymbol}
                    </td>
                    <td>{formatBpsShare(preview.ledger.eligibleShareBps)} eligible</td>
                  </tr>
                </tfoot>
              </table>
            </div>
            <div className={styles.subSection}>
              <div className={styles.subHead}>
                <span>Deterministic accrual projection</span>
                <small>
                  {formatBpsShare(preview.schedule.annualRateBps)} operator-typed rate · {preview.schedule.periodsPerYear}{" "}
                  periods per year · {preview.schedule.compounding ? "compounding" : "simple"}
                </small>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.tierTable}>
                  <thead>
                    <tr>
                      <th>Period</th>
                      <th>Opening</th>
                      <th>Accrued</th>
                      <th>Closing</th>
                      <th>Cumulative</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.schedule.periods.map((period) => (
                      <tr key={period.periodIndex}>
                        <td>{period.periodIndex + 1}</td>
                        <td>{formatTreasuryBaseUnits(period.openingBalanceBaseUnits, decimals)}</td>
                        <td>{formatTreasuryBaseUnits(period.accruedBaseUnits, decimals)}</td>
                        <td>{formatTreasuryBaseUnits(period.closingBalanceBaseUnits, decimals)}</td>
                        <td>{formatTreasuryBaseUnits(period.cumulativeAccruedBaseUnits, decimals)}</td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot>
                    <tr>
                      <td>Totals · {assetSymbol}</td>
                      <td>{formatTreasuryBaseUnits(preview.schedule.principalBaseUnits, decimals)}</td>
                      <td>{formatTreasuryBaseUnits(preview.schedule.totalAccruedBaseUnits, decimals)}</td>
                      <td>{formatTreasuryBaseUnits(preview.schedule.endingBalanceBaseUnits, decimals)}</td>
                      <td>projection only</td>
                    </tr>
                  </tfoot>
                </table>
              </div>
              <p className={styles.warn}>
                Projection only. Every figure above is integer arithmetic over a rate you typed — not an offered rate, not
                a quote, not achievable, not a guarantee, and not financial advice. No vault, venue, or counterparty
                exists, nothing accrues, and nothing here earns interest.
              </p>
            </div>
            <div className={styles.trigger}>
              <div className={styles.triggerTop}>
                <strong>Sweep trigger threshold</strong>
                <span className={`${styles.chip} ${preview.trigger.armed ? styles.chipGo : styles.chipHold}`}>
                  {preview.trigger.armed ? "Threshold met" : "Below threshold"}
                </span>
              </div>
              <ul className={styles.reasons}>
                <li>
                  Eligible idle band {formatTreasuryBaseUnits(preview.trigger.eligibleIdleBaseUnits, decimals)}{" "}
                  {assetSymbol} vs threshold {formatTreasuryBaseUnits(preview.trigger.triggerBaseUnits, decimals)}{" "}
                  {assetSymbol}.
                </li>
                <li>
                  Shortfall {formatTreasuryBaseUnits(preview.trigger.shortfallBaseUnits, decimals)} {assetSymbol}.
                </li>
                <li>{preview.efficiency.rationale}</li>
                <li>
                  A met threshold arms nothing and executes nothing: this is a comparison of two numbers you typed. No
                  transfer, deposit, withdrawal, stake, or order is created, scheduled, or queued anywhere.
                </li>
              </ul>
            </div>
            <p className={styles.hint}>
              Idle age is measured from the last-moved date you type against {formatDate(preview.ledger.asOf)}. Tier
              balances, the sweep amount, and the projected yield stay hidden inside the certificate; only the covenants,
              the asset, and the mandate reference are published. Nothing on this dashboard reads a real shielded balance,
              queries Starknet, or touches the STRK20 pool contract.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>
            One or more inputs cannot be parsed yet — check the tier dates, the decimal amounts, and the basis-point
            covenants. The dashboard returns as soon as every field is valid.
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
            The issuer key signs each treasury certificate. It is generated and kept in this browser tab only; nothing is
            uploaded, and only the public key is embedded so a counterparty can authenticate the signature offline.
          </p>
        )}
      </section>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue a treasury sweep certificate</span>
            <h3>Public covenants in, hidden treasury out.</h3>
          </div>
          <div className={styles.fields}>
            <label>
              Merchant alias <small>public</small>
              <input value={merchantAlias} onChange={(event) => setMerchantAlias(event.target.value)} />
            </label>
            <label>
              Mandate reference <small>public</small>
              <input value={mandateRef} onChange={(event) => setMandateRef(event.target.value)} />
            </label>
            <label>
              Program label <small>public</small>
              <input value={programLabel} onChange={(event) => setProgramLabel(event.target.value)} />
            </label>
            <label>
              Asset symbol <small>public</small>
              <input value={assetSymbol} onChange={(event) => setAssetSymbol(event.target.value)} />
            </label>
            <label>
              Asset decimals <small>public · 0–{MAX_ASSET_DECIMALS}</small>
              <input
                inputMode="numeric"
                value={assetDecimals}
                onChange={(event) => setAssetDecimals(event.target.value)}
              />
            </label>
            <label>
              Proof band <small>bits per hidden amount</small>
              <select value={amountBitLength} onChange={(event) => setAmountBitLength(event.target.value)}>
                {BIT_LENGTHS.map((bits) => (
                  <option key={bits} value={bits}>
                    {bits}-bit range
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.wide}>
              Token address <small>public · provenance label only, never called</small>
              <input value={tokenAddress} onChange={(event) => setTokenAddress(event.target.value)} />
            </label>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Public covenants</span>
              <small>published in the clear · proven against hidden figures</small>
            </div>
            <div className={styles.fields}>
              <label>
                Retained reserve floor <small>public · {assetSymbol}</small>
                <input value={minReserveAmount} onChange={(event) => setMinReserveAmount(event.target.value)} />
              </label>
              <label>
                Max sweep share <small>public · bps of total idle</small>
                <input
                  inputMode="numeric"
                  value={maxSweepShareBps}
                  onChange={(event) => setMaxSweepShareBps(event.target.value)}
                />
              </label>
              <label>
                Yield hurdle <small>public · bps, operator-typed, not offered</small>
                <input inputMode="numeric" value={minYieldBps} onChange={(event) => setMinYieldBps(event.target.value)} />
              </label>
              <label>
                Trigger threshold <small>local only · never certified</small>
                <input value={triggerAmount} onChange={(event) => setTriggerAmount(event.target.value)} />
              </label>
            </div>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Hidden treasury figures</span>
              <small>committed, never published</small>
            </div>
            <div className={styles.fields}>
              <label>
                Sweep amount <small>secret · {assetSymbol}</small>
                <input value={sweepAmount} onChange={(event) => setSweepAmount(event.target.value)} />
              </label>
              <label>
                Projected yield <small>secret · {assetSymbol}, your own figure</small>
                <input
                  value={projectedYieldAmount}
                  onChange={(event) => setProjectedYieldAmount(event.target.value)}
                />
              </label>
              <label className={styles.wide}>
                Strategy or venue label <small>secret · only a salted commitment is published</small>
                <input value={venueRef} onChange={(event) => setVenueRef(event.target.value)} />
              </label>
            </div>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Treasury balance rows</span>
              <div className={styles.vaultActions}>
                <button type="button" className={styles.ghost} onClick={addBalanceRow}>
                  Add row
                </button>
              </div>
            </div>
            <div className={styles.tierEditor}>
              {balances.map((row) => (
                <div key={row.id} className={styles.tierEditRow}>
                  <input
                    value={row.alias}
                    aria-label="Account alias"
                    onChange={(event) => updateBalance(row.id, { alias: event.target.value })}
                  />
                  <input
                    type="date"
                    value={row.lastMovedAt}
                    aria-label="Last moved date"
                    onChange={(event) => updateBalance(row.id, { lastMovedAt: event.target.value })}
                  />
                  <input
                    value={row.amount}
                    aria-label={`Balance in ${assetSymbol}`}
                    onChange={(event) => updateBalance(row.id, { amount: event.target.value })}
                  />
                  <button
                    type="button"
                    className={styles.ghost}
                    disabled={balances.length < 2}
                    onClick={() => removeBalanceRow(row.id)}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
            <p className={styles.hint}>
              Rows are aggregated into the four idle-age tiers locally. Individual aliases, dates, and balances never leave
              this tab and never enter the certificate — only the four tier commitments do.
            </p>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Accrual projection controls</span>
              <small>local arithmetic only · never certified, never offered</small>
            </div>
            <div className={styles.fields}>
              <label>
                Annual rate <small>bps · your own assumption</small>
                <input inputMode="numeric" value={annualRateBps} onChange={(event) => setAnnualRateBps(event.target.value)} />
              </label>
              <label>
                Periods per year <small>1–365</small>
                <input inputMode="numeric" value={periodsPerYear} onChange={(event) => setPeriodsPerYear(event.target.value)} />
              </label>
              <label>
                Periods to project <small>1–120</small>
                <input inputMode="numeric" value={periodCount} onChange={(event) => setPeriodCount(event.target.value)} />
              </label>
              <label className={styles.toggle}>
                Compounding <small>off = simple interest arithmetic</small>
                <input type="checkbox" checked={compounding} onChange={(event) => setCompounding(event.target.checked)} />
              </label>
            </div>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing || !issuer}>
            {issuing ? "Proving in zero knowledge…" : "Issue treasury sweep certificate"}
          </button>
          <p className={styles.hint}>
            Proving builds bit-decomposition range proofs for ten committed legs, so a {bitLength}-bit band takes a while on
            a laptop and blocks this tab. Every hidden figure must fit the band in base units, which at {decimals} decimals
            caps each one at {bandCeiling ?? "the band maximum"} {assetSymbol}. Raise the band for a larger treasury; lower
            it only for a faster demo, and expect a range error if a balance no longer fits.
          </p>
        </form>

        <section className={styles.panel}>
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
                      {badge.programLabel} · {badge.mandateRef}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK proof attached</span>
                </div>
                <p className={styles.badgeClaim}>
                  Covenants hold · <b>{badge.assetSymbol}</b>
                  <small>
                    {badge.minReserveDisplay} · {badge.maxShareDisplay} · {badge.minYieldDisplay} · issued{" "}
                    {formatDate(badge.createdAt)}
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
                    <dt>Venue label</dt>
                    <dd>{badge.venueCommitted ? "Committed, hidden" : "Not committed"}</dd>
                  </div>
                  <div>
                    <dt>Binding</dt>
                    <dd>{shorten(badge.bindingHash)}</dd>
                  </div>
                </dl>
                <p className={styles.hint}>
                  The proof is attached but not yet checked here — paste this certificate into section 03, or hand it to a
                  counterparty, to run the full verification independently.
                </p>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Serialized certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() =>
                      download(`treasury-sweep-certificate-${issued.certificate.certificateId}.txt`, serializedCertificate)
                    }
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Amount disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    disabled={!amountDisclosure}
                    onClick={() =>
                      download(`treasury-sweep-${amountField}-${issued.certificate.certificateId}.txt`, amountDisclosure)
                    }
                  >
                    Download
                  </button>
                </div>
                <div className={styles.discGrid}>
                  {AMOUNT_FIELDS.map((field) => (
                    <button
                      key={field.value}
                      type="button"
                      className={styles.ghost}
                      aria-pressed={amountField === field.value}
                      onClick={() => setAmountField(field.value)}
                    >
                      {field.label}
                    </button>
                  ))}
                </div>
                <textarea readOnly value={amountDisclosure} spellCheck={false} />
                <p className={styles.warn}>
                  Each payload opens exactly one committed amount to whoever receives it. Sending the sweep or yield
                  disclosure reveals that figure permanently — hand it only to a counterparty entitled to see it.
                </p>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Mandate reference disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    disabled={!mandateDisclosure}
                    onClick={() =>
                      download(`treasury-sweep-mandate-${issued.certificate.certificateId}.txt`, mandateDisclosure)
                    }
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={mandateDisclosure} spellCheck={false} />
              </div>
              {issued.certificate.venueCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Venue label disclosure</span>
                    <div className={styles.secretActions}>
                      <button type="button" className={styles.ghost} onClick={() => setRevealVenue((v) => !v)}>
                        {revealVenue ? "Hide" : "Reveal"}
                      </button>
                      <button
                        type="button"
                        className={styles.ghost}
                        disabled={!venueDisclosure}
                        onClick={() =>
                          download(`treasury-sweep-venue-${issued.certificate.certificateId}.txt`, venueDisclosure)
                        }
                      >
                        Download
                      </button>
                    </div>
                  </div>
                  {revealVenue ? (
                    <>
                      <textarea readOnly value={venueDisclosure} spellCheck={false} />
                      <p className={styles.warn}>
                        This opens the salted commitment to your strategy or venue label. Anyone holding it learns the label
                        verbatim.
                      </p>
                    </>
                  ) : (
                    <p className={styles.hint}>The label stays committed and hidden until you reveal it here.</p>
                  )}
                </div>
              ) : null}
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Certificate secret — keep private</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>
                      {revealSecret ? "Hide secret" : "Reveal secret"}
                    </button>
                    <button
                      type="button"
                      className={styles.ghost}
                      disabled={!revealSecret || !serializedSecret}
                      onClick={() =>
                        download(`treasury-sweep-secret-${issued.certificate.certificateId}.txt`, serializedSecret)
                      }
                    >
                      Download
                    </button>
                  </div>
                </div>
                {revealSecret ? (
                  <>
                    <textarea readOnly value={serializedSecret} spellCheck={false} />
                    <p className={styles.warn}>
                      This blob holds every tier balance, the sweep amount, the projected yield, all blindings, and both
                      salts. Publishing it destroys the zero-knowledge property of this certificate. Store it like a key.
                    </p>
                  </>
                ) : (
                  <p className={styles.hint}>
                    The secret is what lets you build selective disclosures later. It is never embedded in the certificate.
                  </p>
                )}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>
              No certificate yet. Generate an issuer key, set the public covenants, enter the hidden treasury figures, and
              issue. Proving runs entirely in this tab.
            </p>
          )}
        </section>
      </div>

      <form className={styles.verify} onSubmit={handleVerify}>
        <div className={styles.panelHead}>
          <span>03 · Verify as a counterparty</span>
          <h3>Authenticate a certificate you were handed.</h3>
        </div>
        <label className={styles.toggle}>
          Serialized certificate
          <textarea
            value={verifyInput}
            onChange={(event) => setVerifyInput(event.target.value)}
            placeholder="cipherbill.treasury-sweep-certificate payload…"
            spellCheck={false}
          />
        </label>
        <label className={styles.toggle}>
          Optional disclosure payload <small>amount, mandate, or venue</small>
          <textarea
            value={disclosureInput}
            onChange={(event) => setDisclosureInput(event.target.value)}
            placeholder="amount or reference disclosure payload…"
            spellCheck={false}
          />
        </label>
        <button type="submit">Verify certificate</button>
        {verifyResult ? (
          <div className={verifyResult.ok ? styles.pass : styles.fail}>
            <strong>
              {verifyResult.ok
                ? "Valid — every covenant proof and the issuer signature check out"
                : verifyResult.error
                  ? "Could not read this certificate"
                  : "Invalid — a proof, a commitment, or the signature failed"}
            </strong>
            {verifyResult.error ? <small>{verifyResult.error}</small> : null}
            {verifyResult.meta ? (
              <dl className={styles.resultMeta}>
                {verifyResult.meta.map((row) => (
                  <div key={row.label}>
                    <dt>{row.label}</dt>
                    <dd>{row.value}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
            {verifyResult.disclosure ? (
              <dl className={styles.resultMeta}>
                <div>
                  <dt>Disclosure · {verifyResult.disclosure.type}</dt>
                  <dd>
                    {verifyResult.disclosure.ok ? "Matches the commitment" : "Does not match"} ·{" "}
                    {verifyResult.disclosure.value}
                  </dd>
                </div>
              </dl>
            ) : null}
            <small>
              A valid certificate proves the four tier commitments sum to the committed total and that all four covenant
              surpluses are non-negative. It does not prove the tier balances are real, that any capital exists, or that
              anything was ever swept, deposited, or invested.
            </small>
          </div>
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
          <h4>Proven to the verifier</h4>
          <ul>
            {VISIBILITY.disclosedToVerifier.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>Application metadata only</h4>
          <ul>
            {VISIBILITY.applicationOnly.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className={`${styles.model} ${styles.limitation}`}>
        <div>
          <h4>What this proves</h4>
          <p>{VISIBILITY.limitation}</p>
        </div>
        <div>
          <h4>What this is not</h4>
          <p className={styles.statement}>{TRUST.statement}</p>
        </div>
        <div>
          <h4>Proof system</h4>
          <p>
            Pedersen commitments on the STARK curve with bit-decomposition range proofs over ten committed legs — four idle
            tiers, the sweep, the projected yield, and four covenant surpluses — each bit a Fiat–Shamir Schnorr one-of-two
            proof, bound together by an issuer Schnorr signature. Everything runs in this browser tab.
          </p>
        </div>
      </section>
    </div>
  );
}
