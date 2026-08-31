"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  DAY_COUNT_BASIS,
  FACTORING_POOL_ADDRESS,
  FACTORING_VAULT_BUCKET_LABELS,
  FACTORING_VAULT_DEFAULT_BIT_LENGTH,
  FACTORING_VAULT_MAX_COVERAGE_RATIO_BPS,
  FACTORING_VAULT_MAX_HAIRCUT_BPS,
  FACTORING_VAULT_SURPLUS_HEADROOM_BITS,
  FEE_BPS_DENOMINATOR,
  MAX_ASSET_DECIMALS,
  MAX_TENOR_DAYS,
  auditFactoringVaultCertificate,
  buildFactoringVaultBadge,
  discloseFactoringVaultFigure,
  estimateFactoringVaultProofCount,
  formatFactoringBaseUnits,
  generateFactoringVaultIssuerKey,
  getFactoringVaultTrustModel,
  issueFactoringVaultCertificate,
  parseFactoringVaultCertificate,
  parseFactoringVaultDisclosure,
  serializeFactoringVaultCertificate,
  serializeFactoringVaultDisclosure,
  serializeFactoringVaultSecret,
  verifyFactoringVaultDisclosure,
  type FactoringVaultCertificate,
  type FactoringVaultCheck,
  type FactoringVaultCovenants,
  type FactoringVaultFigure,
  type FactoringVaultIssuerKey,
  type FactoringVaultSecret,
} from "@/lib/factoring-engine";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./factoring-portal.module.css";

const INTRO =
  "Commit an aged receivables schedule and a requested draw as Pedersen commitments, then prove in zero knowledge that the hidden figures satisfy every published underwriting covenant: per-bucket haircuts, the advance rate, a minimum coverage ratio, a holdback floor, single-debtor and stale-receivables caps, net-proceeds solvency, and a discount charge pinned to an exact ceiling-rounded formula. No bucket balance, face value, advance, discount charge, or debtor exposure is ever published. The issuer signs the certificate so any counterparty can authenticate it offline. Nothing here is decentralized, tokenized, or funded: no stablecoin moves, no liquidity is advanced, no receivable is pledged, locked, assigned, or seizable, no registry, coordinator, or on-chain verifier exists, and this engine never reads on-chain state or calls the STRK20 pool contract.";

const TRUST = getFactoringVaultTrustModel();

const BIT_LENGTHS = ["16", "24", "32", "48", "64", "96", "128"];

const FIGURES: { value: FactoringVaultFigure; label: string }[] = [
  { value: "face", label: "Face value" },
  { value: "eligible", label: "Eligible collateral" },
  { value: "advance", label: "Requested advance" },
  { value: "discountCharge", label: "Discount charge" },
  { value: "concentration", label: "Largest debtor" },
  ...FACTORING_VAULT_BUCKET_LABELS.map((label, index) => ({
    value: `bucket${index}` as FactoringVaultFigure,
    label: `Bucket ${label}`,
  })),
];

interface BucketDraft {
  amount: string;
  haircutBps: string;
}

const DEFAULT_BUCKETS: BucketDraft[] = [
  { amount: "120000", haircutBps: "500" },
  { amount: "62000", haircutBps: "1000" },
  { amount: "24000", haircutBps: "2000" },
  { amount: "9000", haircutBps: "5000" },
];

interface DisclosureResult {
  figure: string;
  ok: boolean;
  value: string;
}

interface VerifyMetaRow {
  label: string;
  value: string;
}

interface VerifyState {
  ok: boolean;
  checks?: FactoringVaultCheck[];
  meta?: VerifyMetaRow[];
  disclosure?: DisclosureResult;
  error?: string;
}

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

/** decimalToBaseUnits rejects "0", so an empty or zero bucket is routed around it. */
function toBaseUnitsAllowingZero(value: string, decimals: number): string {
  const trimmed = value.trim();
  if (!trimmed || /^0*(\.0*)?$/.test(trimmed)) return "0";
  return decimalToBaseUnits(trimmed, decimals);
}

function parseIntOrZero(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

/** The engine rounds the discount charge up; the preview must round identically or it lies. */
function divideCeil(numerator: bigint, denominator: bigint): bigint {
  return numerator === 0n ? 0n : (numerator + denominator - 1n) / denominator;
}

function formatBps(bps: bigint | number): string {
  return `${(Number(bps) / 100).toFixed(2)}%`;
}

/** Percentage fill for a meter, clamped so a breach shows a full bar rather than overflowing. */
function fill(part: bigint, whole: bigint): number {
  if (whole <= 0n) return part > 0n ? 100 : 0;
  const ratio = (Number(part) / Number(whole)) * 100;
  return Math.max(0, Math.min(100, Number.isFinite(ratio) ? ratio : 0));
}

interface PreviewBucket {
  label: string;
  amount: bigint;
  haircutBps: number;
  weighted: bigint;
  shareBps: bigint;
}

interface Preview {
  band: bigint;
  buckets: PreviewBucket[];
  face: bigint;
  eligible: bigint;
  advance: bigint;
  concentration: bigint;
  eligibilityCeiling: bigint;
  eligibilityHeadroom: bigint;
  advanceCap: bigint;
  advanceHeadroom: bigint;
  coverageRatioBps: bigint;
  coverageSurplus: bigint;
  holdback: bigint;
  holdbackSurplus: bigint;
  discountCharge: bigint;
  chargeRemainder: bigint;
  platformFee: bigint;
  netProceeds: bigint;
  concentrationCap: bigint;
  concentrationShareBps: bigint;
  concentrationSurplus: bigint;
  staleCap: bigint;
  staleShareBps: bigint;
  staleSurplus: bigint;
  blockers: string[];
  proofCount: number;
}

/**
 * Restates the engine's own clear-text covenant arithmetic locally so a merchant sees which
 * covenant fails before paying for a proof. Every formula here mirrors
 * issueFactoringVaultCertificate exactly, including the ceiling division on the discount charge —
 * a preview that rounded differently would advertise a charge the certificate cannot prove.
 */
function buildPreview(
  covenants: FactoringVaultCovenants,
  bucketBaseUnits: string[],
  eligibleBaseUnits: string,
  advanceBaseUnits: string,
  concentrationBaseUnits: string,
  bitLength: number,
): Preview {
  const band = 1n << BigInt(bitLength);
  const amounts = bucketBaseUnits.map((value) => BigInt(value));
  const face = amounts.reduce((total, value) => total + value, 0n);
  const eligible = BigInt(eligibleBaseUnits);
  const advance = BigInt(advanceBaseUnits);
  const concentration = BigInt(concentrationBaseUnits);
  const holdback = BigInt(covenants.holdbackBaseUnits);
  const platformFee = BigInt(covenants.platformFeeBaseUnits);

  const buckets: PreviewBucket[] = amounts.map((amount, index) => ({
    label: FACTORING_VAULT_BUCKET_LABELS[index],
    amount,
    haircutBps: covenants.haircutBps[index],
    weighted: (FEE_BPS_DENOMINATOR - BigInt(covenants.haircutBps[index])) * amount,
    shareBps: face > 0n ? (FEE_BPS_DENOMINATOR * amount) / face : 0n,
  }));

  const weightedBase = buckets.reduce((total, bucket) => total + bucket.weighted, 0n);
  const eligibilityCeiling = weightedBase / FEE_BPS_DENOMINATOR;
  const eligibilityHeadroom = weightedBase - FEE_BPS_DENOMINATOR * eligible;
  const advanceCap = (BigInt(covenants.advanceRateBps) * eligible) / FEE_BPS_DENOMINATOR;
  const advanceHeadroom = BigInt(covenants.advanceRateBps) * eligible - FEE_BPS_DENOMINATOR * advance;
  const coverageRatioBps = advance > 0n ? (FEE_BPS_DENOMINATOR * eligible) / advance : 0n;
  const coverageSurplus = FEE_BPS_DENOMINATOR * eligible - BigInt(covenants.minCoverageRatioBps) * advance;
  const holdbackSurplus = eligible - advance - holdback;

  const chargeMultiplier = BigInt(covenants.discountRateBps) * BigInt(covenants.tenorDays);
  const chargeDenominator = FEE_BPS_DENOMINATOR * DAY_COUNT_BASIS;
  const discountCharge = divideCeil(advance * chargeMultiplier, chargeDenominator);
  const chargeRemainder = discountCharge * chargeDenominator - advance * chargeMultiplier;
  const netProceeds = advance - discountCharge - platformFee;

  const concentrationCap = (BigInt(covenants.maxConcentrationBps) * face) / FEE_BPS_DENOMINATOR;
  const concentrationShareBps = face > 0n ? (FEE_BPS_DENOMINATOR * concentration) / face : 0n;
  const concentrationSurplus = BigInt(covenants.maxConcentrationBps) * face - FEE_BPS_DENOMINATOR * concentration;
  const stale = amounts[amounts.length - 1];
  const staleCap = (BigInt(covenants.maxStaleBps) * face) / FEE_BPS_DENOMINATOR;
  const staleShareBps = face > 0n ? (FEE_BPS_DENOMINATOR * stale) / face : 0n;
  const staleSurplus = BigInt(covenants.maxStaleBps) * face - FEE_BPS_DENOMINATOR * stale;
  const blockers: string[] = [];
  buckets.forEach((bucket) => {
    if (bucket.amount >= band) blockers.push(`The ${bucket.label} bucket exceeds the ${bitLength}-bit band.`);
  });
  if (eligible >= band) blockers.push(`The eligible collateral exceeds the ${bitLength}-bit band.`);
  if (advance >= band) blockers.push(`The requested advance exceeds the ${bitLength}-bit band.`);
  if (concentration >= band) blockers.push(`The largest debtor exposure exceeds the ${bitLength}-bit band.`);
  if (eligibilityHeadroom < 0n) blockers.push("The eligible collateral exceeds what the aging buckets support after haircuts.");
  if (advanceHeadroom < 0n) blockers.push("The requested advance exceeds the advance rate against eligible collateral.");
  if (coverageSurplus < 0n) blockers.push("The requested advance breaches the minimum coverage ratio.");
  if (holdbackSurplus < 0n) blockers.push("The requested advance would eat into the holdback reserve.");
  if (discountCharge >= band) blockers.push(`The discount charge exceeds the ${bitLength}-bit band.`);
  if (netProceeds < 0n) blockers.push("The discount charge and platform fee exceed the requested advance.");
  if (concentrationSurplus < 0n) blockers.push("The largest debtor exposure breaches the concentration cap.");
  if (staleSurplus < 0n) blockers.push("The 90+ day bucket breaches the stale-receivables cap.");

  return {
    band,
    buckets,
    face,
    eligible,
    advance,
    concentration,
    eligibilityCeiling,
    eligibilityHeadroom,
    advanceCap,
    advanceHeadroom,
    coverageRatioBps,
    coverageSurplus,
    holdback,
    holdbackSurplus,
    discountCharge,
    chargeRemainder,
    platformFee,
    netProceeds,
    concentrationCap,
    concentrationShareBps,
    concentrationSurplus,
    staleCap,
    staleShareBps,
    staleSurplus,
    blockers,
    proofCount: estimateFactoringVaultProofCount(bitLength),
  };
}

/**
 * Flattens a pasted certificate into display rows. Parsing only checks the envelope, so every
 * field here is still untrusted: formatting runs inside handleVerify so a malformed figure
 * surfaces as a read error instead of throwing during render.
 */
function describeCertificate(certificate: FactoringVaultCertificate): VerifyMetaRow[] {
  const covenants = certificate.covenants;
  return [
    { label: "Facility", value: shorten(certificate.facilityRef) },
    { label: "Merchant", value: shorten(certificate.merchantRef) },
    { label: "Underwriter", value: shorten(certificate.underwriterRef) },
    { label: "Asset", value: `${certificate.assetSymbol} · ${certificate.assetDecimals} decimals` },
    { label: "Amount band", value: `[0, 2^${certificate.amountBitLength}) base units` },
    { label: "Advance rate", value: `${formatBps(covenants.advanceRateBps)} of eligible collateral` },
    { label: "Minimum coverage", value: formatBps(covenants.minCoverageRatioBps) },
    {
      label: "Discount",
      value: `${formatBps(covenants.discountRateBps)} per annum · ${covenants.tenorDays} days · 365-day basis`,
    },
    {
      label: "Holdback",
      value: `${formatFactoringBaseUnits(covenants.holdbackBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    },
    {
      label: "Platform fee",
      value: `${formatFactoringBaseUnits(covenants.platformFeeBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`,
    },
    { label: "Ledger as of", value: formatDate(certificate.asOf) },
    { label: "Maturity", value: formatDate(certificate.maturity) },
    { label: "Proof legs", value: `${estimateFactoringVaultProofCount(certificate.amountBitLength)} bit proofs` },
    { label: "Pool provenance", value: shorten(certificate.poolAddress) },
    { label: "Binding hash", value: shorten(certificate.bindingHash) },
  ];
}

/** Classifies a pasted disclosure payload without ever throwing over a valid audit verdict. */
function evaluateDisclosure(certificate: FactoringVaultCertificate, raw: string): DisclosureResult {
  try {
    const disclosure = parseFactoringVaultDisclosure(raw);
    const ok = verifyFactoringVaultDisclosure(certificate, disclosure);
    let value: string;
    try {
      value = `${formatFactoringBaseUnits(disclosure.valueBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`;
    } catch {
      value = `${disclosure.valueBaseUnits} base units`;
    }
    return { figure: disclosure.figure, ok, value };
  } catch {
    return { figure: "unrecognized", ok: false, value: "This payload is not a factoring vault disclosure." };
  }
}

export function FactoringPortal() {
  const [issuer, setIssuer] = useState<FactoringVaultIssuerKey | null>(null);
  const [revealIssuerSecret, setRevealIssuerSecret] = useState(false);

  const [facilityLabel, setFacilityLabel] = useState("Northwind receivables facility");
  const [merchantAlias, setMerchantAlias] = useState("Northwind Trading");
  const [underwriterAlias, setUnderwriterAlias] = useState("Harbour Credit Partners");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [amountBitLength, setAmountBitLength] = useState(String(FACTORING_VAULT_DEFAULT_BIT_LENGTH));

  const [buckets, setBuckets] = useState<BucketDraft[]>(DEFAULT_BUCKETS);
  const [eligibleAmount, setEligibleAmount] = useState("190000");
  const [advanceAmount, setAdvanceAmount] = useState("145000");
  const [concentrationAmount, setConcentrationAmount] = useState("52000");

  const [advanceRateBps, setAdvanceRateBps] = useState("8000");
  const [minCoverageRatioBps, setMinCoverageRatioBps] = useState("12500");
  const [maxConcentrationBps, setMaxConcentrationBps] = useState("3000");
  const [maxStaleBps, setMaxStaleBps] = useState("1500");
  const [discountRateBps, setDiscountRateBps] = useState("1200");
  const [tenorDays, setTenorDays] = useState("60");
  const [holdbackAmount, setHoldbackAmount] = useState("40000");
  const [platformFeeAmount, setPlatformFeeAmount] = useState("500");

  const [asOf, setAsOf] = useState("2026-08-31");
  const [maturity, setMaturity] = useState("2026-10-30");
  const [memo, setMemo] = useState("Q3 revolving draw");

  const [issued, setIssued] = useState<{ certificate: FactoringVaultCertificate; secret: FactoringVaultSecret } | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [figure, setFigure] = useState<FactoringVaultFigure>("advance");

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= MAX_ASSET_DECIMALS ? parsed : 6;
  }, [assetDecimals]);

  const bitLength = useMemo(() => {
    const parsed = Number.parseInt(amountBitLength, 10);
    return Number.isFinite(parsed) && parsed >= 8 && parsed <= 128 ? parsed : FACTORING_VAULT_DEFAULT_BIT_LENGTH;
  }, [amountBitLength]);

  const covenants = useMemo<FactoringVaultCovenants | null>(() => {
    try {
      return {
        haircutBps: buckets.map((row) => parseIntOrZero(row.haircutBps)),
        advanceRateBps: parseIntOrZero(advanceRateBps),
        minCoverageRatioBps: parseIntOrZero(minCoverageRatioBps),
        maxConcentrationBps: parseIntOrZero(maxConcentrationBps),
        maxStaleBps: parseIntOrZero(maxStaleBps),
        discountRateBps: parseIntOrZero(discountRateBps),
        tenorDays: parseIntOrZero(tenorDays),
        holdbackBaseUnits: toBaseUnitsAllowingZero(holdbackAmount, decimals),
        platformFeeBaseUnits: toBaseUnitsAllowingZero(platformFeeAmount, decimals),
      };
    } catch {
      return null;
    }
  }, [
    buckets,
    advanceRateBps,
    minCoverageRatioBps,
    maxConcentrationBps,
    maxStaleBps,
    discountRateBps,
    tenorDays,
    holdbackAmount,
    platformFeeAmount,
    decimals,
  ]);

  const figures = useMemo(() => {
    try {
      return {
        bucketBaseUnits: buckets.map((row) => toBaseUnitsAllowingZero(row.amount, decimals)),
        eligibleBaseUnits: toBaseUnitsAllowingZero(eligibleAmount, decimals),
        advanceBaseUnits: toBaseUnitsAllowingZero(advanceAmount, decimals),
        concentrationBaseUnits: toBaseUnitsAllowingZero(concentrationAmount, decimals),
      };
    } catch {
      return null;
    }
  }, [buckets, eligibleAmount, advanceAmount, concentrationAmount, decimals]);

  const preview = useMemo(() => {
    if (!covenants || !figures) return null;
    try {
      return buildPreview(
        covenants,
        figures.bucketBaseUnits,
        figures.eligibleBaseUnits,
        figures.advanceBaseUnits,
        figures.concentrationBaseUnits,
        bitLength,
      );
    } catch {
      return null;
    }
  }, [covenants, figures, bitLength]);

  const badge = useMemo(() => (issued ? buildFactoringVaultBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(
    () => (issued ? serializeFactoringVaultCertificate(issued.certificate) : ""),
    [issued],
  );
  const serializedSecret = useMemo(() => (issued ? serializeFactoringVaultSecret(issued.secret) : ""), [issued]);
  const serializedDisclosure = useMemo(() => {
    if (!issued) return "";
    try {
      return serializeFactoringVaultDisclosure(discloseFactoringVaultFigure(issued.certificate, issued.secret, figure));
    } catch {
      return "";
    }
  }, [issued, figure]);

  const disclosedValue = useMemo(() => {
    if (!issued) return "";
    try {
      const disclosure = discloseFactoringVaultFigure(issued.certificate, issued.secret, figure);
      return `${disclosure.valueDisplay} ${issued.certificate.assetSymbol}`;
    } catch {
      return "";
    }
  }, [issued, figure]);

  const bandCeiling = useMemo(() => {
    try {
      return formatFactoringBaseUnits((1n << BigInt(bitLength)) - 1n, decimals);
    } catch {
      return null;
    }
  }, [bitLength, decimals]);

  function updateBucket(index: number, patch: Partial<BucketDraft>) {
    setBuckets((rows) => rows.map((row, position) => (position === index ? { ...row, ...patch } : row)));
  }

  function generateIssuerKey() {
    setIssuer(generateFactoringVaultIssuerKey());
    setRevealIssuerSecret(false);
  }

  function handleIssue(event: FormEvent) {
    event.preventDefault();
    if (!issuer) {
      setIssueError("Generate an issuer key in the vault above before issuing a certificate.");
      return;
    }
    if (!covenants || !figures) {
      setIssueError("One or more amounts cannot be parsed yet — check the decimal figures and the basis-point covenants.");
      return;
    }
    setIssuing(true);
    setIssueError(null);
    setIssued(null);
    setRevealSecret(false);
    // Deferred one tick so the button repaints as busy before the prover blocks this tab.
    setTimeout(() => {
      try {
        setIssued(
          issueFactoringVaultCertificate({
            facilityLabel,
            merchantAlias,
            underwriterAlias,
            assetSymbol,
            assetDecimals: decimals,
            amountBitLength: bitLength,
            bucketBaseUnits: figures.bucketBaseUnits,
            eligibleBaseUnits: figures.eligibleBaseUnits,
            advanceBaseUnits: figures.advanceBaseUnits,
            concentrationBaseUnits: figures.concentrationBaseUnits,
            covenants,
            asOf: `${asOf}T00:00:00.000Z`,
            maturity: `${maturity}T00:00:00.000Z`,
            memo,
            issuerKey: issuer,
          }),
        );
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the vault certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    setVerifying(true);
    setVerifyResult(null);
    // Auditing re-runs every bit proof, so it is deferred for the same reason issuing is.
    setTimeout(() => {
      try {
        const certificate = parseFactoringVaultCertificate(verifyInput.trim());
        const audit = auditFactoringVaultCertificate(certificate);
        const raw = disclosureInput.trim();
        setVerifyResult({
          ok: audit.ok,
          checks: audit.checks,
          meta: describeCertificate(certificate),
          disclosure: raw ? evaluateDisclosure(certificate, raw) : undefined,
        });
      } catch (error) {
        setVerifyResult({
          ok: false,
          error: error instanceof Error ? error.message : "The certificate could not be parsed.",
        });
      } finally {
        setVerifying(false);
      }
    }, 40);
  }

  function loadIssuedIntoVerifier() {
    setVerifyInput(serializedCertificate);
    setDisclosureInput(serializedDisclosure);
    setVerifyResult(null);
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Invoice factoring &amp; receivables collateralization vault</span>
          <h2>
            Prove the <em>covenants</em>, publish none of the receivables.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(FACTORING_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Face sum + 8 covenants</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Issuer signature</dt>
            <dd className={styles.yes}>Authenticated</dd>
          </div>
          <div>
            <dt>Advances or delivers funds</dt>
            <dd className={styles.no}>Never</dd>
          </div>
          <div>
            <dt>Tokenizes or pledges a receivable</dt>
            <dd className={styles.no}>Nothing exists</dd>
          </div>
          <div>
            <dt>Registry or on-chain verifier</dt>
            <dd className={styles.no}>None</dd>
          </div>
          <div>
            <dt>STRK20 pool contract</dt>
            <dd className={styles.no}>Never called</dd>
          </div>
        </dl>
      </header>

      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Institutional discounting desk</span>
          <small>Local integer arithmetic · no funding, no assignment, not an offer of credit</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Net proceeds</dt>
                <dd>
                  {preview.netProceeds >= 0n
                    ? `${formatFactoringBaseUnits(preview.netProceeds, decimals)} ${assetSymbol}`
                    : "covenant breach"}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Face value</dt>
                <dd>
                  {formatFactoringBaseUnits(preview.face, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Discount charge</dt>
                <dd>
                  {formatFactoringBaseUnits(preview.discountCharge, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Coverage ratio</dt>
                <dd>{formatBps(preview.coverageRatioBps)}</dd>
              </div>
            </dl>
            <div className={styles.trigger}>
              <div className={styles.triggerTop}>
                <strong>Covenant eligibility</strong>
                <span className={`${styles.chip} ${preview.blockers.length === 0 ? styles.chipGo : styles.chipStop}`}>
                  {preview.blockers.length === 0 ? "All covenants satisfied" : `${preview.blockers.length} blocking`}
                </span>
              </div>
              <ul className={styles.reasons}>
                {preview.blockers.length === 0 ? (
                  <li>
                    Every covenant surplus is non-negative, so an honest certificate exists for these figures. Issuing one
                    proves the arithmetic and nothing else: no receivable is verified, funded, or assigned.
                  </li>
                ) : (
                  preview.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)
                )}
              </ul>
            </div>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>Requested advance vs advance-rate cap</span>
                <span>
                  {formatFactoringBaseUnits(preview.advance, decimals)} / {formatFactoringBaseUnits(preview.advanceCap, decimals)}{" "}
                  {assetSymbol}
                </span>
              </div>
              <div className={`${styles.meter} ${preview.advanceHeadroom < 0n ? styles.meterCap : ""}`}>
                <span style={{ width: `${fill(preview.advance, preview.advanceCap)}%` }} />
              </div>
            </div>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>Eligible collateral vs haircut-adjusted ceiling</span>
                <span>
                  {formatFactoringBaseUnits(preview.eligible, decimals)} /{" "}
                  {formatFactoringBaseUnits(preview.eligibilityCeiling, decimals)} {assetSymbol}
                </span>
              </div>
              <div className={`${styles.meter} ${preview.eligibilityHeadroom < 0n ? styles.meterCap : ""}`}>
                <span style={{ width: `${fill(preview.eligible, preview.eligibilityCeiling)}%` }} />
              </div>
            </div>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>Largest debtor share vs concentration cap</span>
                <span>
                  {formatBps(preview.concentrationShareBps)} / {formatBps(parseIntOrZero(maxConcentrationBps))}
                </span>
              </div>
              <div className={`${styles.meter} ${preview.concentrationSurplus < 0n ? styles.meterCap : ""}`}>
                <span style={{ width: `${fill(preview.concentrationShareBps, BigInt(parseIntOrZero(maxConcentrationBps)))}%` }} />
              </div>
            </div>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>90+ day share vs stale-receivables cap</span>
                <span>
                  {formatBps(preview.staleShareBps)} / {formatBps(parseIntOrZero(maxStaleBps))}
                </span>
              </div>
              <div className={`${styles.meter} ${preview.staleSurplus < 0n ? styles.meterCap : ""}`}>
                <span style={{ width: `${fill(preview.staleShareBps, BigInt(parseIntOrZero(maxStaleBps)))}%` }} />
              </div>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.tierTable}>
                <thead>
                  <tr>
                    <th>Aging bucket</th>
                    <th>Balance</th>
                    <th>Share of face</th>
                    <th>Haircut</th>
                    <th>Post-haircut value</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.buckets.map((bucket) => (
                    <tr key={bucket.label} className={bucket.amount > 0n ? styles.activeTier : styles.mutedRow}>
                      <td>{bucket.label}</td>
                      <td>
                        {formatFactoringBaseUnits(bucket.amount, decimals)} {assetSymbol}
                      </td>
                      <td>{formatBps(bucket.shareBps)}</td>
                      <td>{formatBps(bucket.haircutBps)}</td>
                      <td>{formatFactoringBaseUnits(bucket.weighted / FEE_BPS_DENOMINATOR, decimals)}</td>
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr>
                    <td>Face value · {assetSymbol}</td>
                    <td>{formatFactoringBaseUnits(preview.face, decimals)}</td>
                    <td>100.00%</td>
                    <td>weighted</td>
                    <td>{formatFactoringBaseUnits(preview.eligibilityCeiling, decimals)}</td>
                  </tr>
                </tfoot>
              </table>
            </div>
            <div className={styles.subSection}>
              <div className={styles.subHead}>
                <span>Discount charge derivation</span>
                <small>
                  ceil(advance × {parseIntOrZero(discountRateBps)} bps × {parseIntOrZero(tenorDays)} days ÷ (10000 × 365))
                </small>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.tierTable}>
                  <tbody>
                    <tr>
                      <td>Requested advance</td>
                      <td>
                        {formatFactoringBaseUnits(preview.advance, decimals)} {assetSymbol}
                      </td>
                      <td>hidden · committed</td>
                    </tr>
                    <tr>
                      <td>Discount charge, rounded up</td>
                      <td>
                        {formatFactoringBaseUnits(preview.discountCharge, decimals)} {assetSymbol}
                      </td>
                      <td>hidden · committed</td>
                    </tr>
                    <tr>
                      <td>Rounding remainder</td>
                      <td>{preview.chargeRemainder.toString()}</td>
                      <td>pins the charge to the exact ceiling</td>
                    </tr>
                    <tr>
                      <td>Platform fee</td>
                      <td>
                        {formatFactoringBaseUnits(preview.platformFee, decimals)} {assetSymbol}
                      </td>
                      <td>public covenant</td>
                    </tr>
                    <tr>
                      <td>Holdback reserve</td>
                      <td>
                        {formatFactoringBaseUnits(preview.holdback, decimals)} {assetSymbol}
                      </td>
                      <td>public covenant</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <div className={styles.subSection}>
              <div className={styles.subHead}>
                <span>Covenant surplus ledger</span>
                <small>
                  each surplus is range-proved in a {bitLength + FACTORING_VAULT_SURPLUS_HEADROOM_BITS}-bit band ·{" "}
                  {preview.proofCount} bit proofs in total
                </small>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.tierTable}>
                  <thead>
                    <tr>
                      <th>Covenant leg</th>
                      <th>Surplus, scaled base units</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { label: "Haircut eligibility headroom", value: preview.eligibilityHeadroom },
                      { label: "Advance rate cap", value: preview.advanceHeadroom },
                      { label: "Minimum coverage ratio", value: preview.coverageSurplus },
                      { label: "Holdback floor", value: preview.holdbackSurplus },
                      { label: "Net proceeds solvency", value: preview.netProceeds },
                      { label: "Concentration cap", value: preview.concentrationSurplus },
                      { label: "Stale receivables cap", value: preview.staleSurplus },
                    ].map((row) => (
                      <tr key={row.label} className={row.value >= 0n ? styles.activeTier : styles.mutedRow}>
                        <td>{row.label}</td>
                        <td>{row.value.toString()}</td>
                        <td>{row.value >= 0n ? "provable" : "negative · no honest proof exists"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <p className={styles.hint}>
              Every figure on this dashboard is computed in this tab from numbers you typed, using the same integer
              formulas the prover uses. It reads no accounting system, no invoice, and no on-chain state, so it cannot tell
              whether a receivable exists, has already been factored, or will ever be paid. Only the covenants, the asset,
              the band, and the timestamps are published on a certificate; every amount above stays committed.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>
            One or more inputs cannot be parsed yet — check the decimal amounts and the basis-point covenants. The desk
            returns as soon as every field is valid.
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
              <button type="button" className={styles.ghost} onClick={() => setRevealIssuerSecret((value) => !value)}>
                {revealIssuerSecret ? "Hide secret" : "Reveal secret"}
              </button>
            ) : null}
          </div>
        </div>
        {issuer ? (
          <div className={styles.keyGrid}>
            <div className={styles.keyCard}>
              <h4>Public key — share it so anyone can authenticate certificates offline</h4>
              <dl>
                <dt>X</dt>
                <dd>{issuer.publicKey.x}</dd>
                <dt>Y</dt>
                <dd>{issuer.publicKey.y}</dd>
              </dl>
            </div>
            {revealIssuerSecret ? (
              <div className={styles.keyCard}>
                <h4 className={styles.secretTag}>Secret signing scalar — never publish or commit this</h4>
                <dl>
                  <dt>Secret scalar</dt>
                  <dd>{issuer.secretScalar}</dd>
                </dl>
              </div>
            ) : null}
          </div>
        ) : (
          <p className={styles.placeholder}>
            The issuer key signs each vault certificate. It is drawn and held in this browser tab only, is never uploaded
            or persisted, and only the public key is embedded so an underwriter can authenticate the signature offline.
            Regenerating it invalidates nothing already issued, but no certificate signed by the old key can be reissued.
          </p>
        )}
      </section>
      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue a vault certificate</span>
            <h3>Public covenants in, hidden receivables out.</h3>
          </div>
          <div className={styles.fields}>
            <label>
              Facility label <small>hashed into a salted reference</small>
              <input value={facilityLabel} onChange={(event) => setFacilityLabel(event.target.value)} />
            </label>
            <label>
              Merchant alias <small>hashed into a salted reference</small>
              <input value={merchantAlias} onChange={(event) => setMerchantAlias(event.target.value)} />
            </label>
            <label>
              Underwriter alias <small>hashed into a salted reference</small>
              <input value={underwriterAlias} onChange={(event) => setUnderwriterAlias(event.target.value)} />
            </label>
            <label>
              Asset symbol <small>public</small>
              <input value={assetSymbol} onChange={(event) => setAssetSymbol(event.target.value)} />
            </label>
            <label>
              Asset decimals <small>public · 0–{MAX_ASSET_DECIMALS}</small>
              <input inputMode="numeric" value={assetDecimals} onChange={(event) => setAssetDecimals(event.target.value)} />
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
            <label>
              Ledger as of <small>public · cannot be in the future</small>
              <input type="date" value={asOf} onChange={(event) => setAsOf(event.target.value)} />
            </label>
            <label>
              Facility maturity <small>public · must be after issuance</small>
              <input type="date" value={maturity} onChange={(event) => setMaturity(event.target.value)} />
            </label>
            <label className={styles.wide}>
              Memo <small>public · up to 240 characters</small>
              <input value={memo} onChange={(event) => setMemo(event.target.value)} />
            </label>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Aging schedule — hidden amounts, public haircuts</span>
              <small>
                face value {preview ? formatFactoringBaseUnits(preview.face, decimals) : "—"} {assetSymbol}
              </small>
            </div>
            <div className={styles.tierEditor}>
              {buckets.map((bucket, index) => (
                <div className={styles.tierEditRow} key={FACTORING_VAULT_BUCKET_LABELS[index]}>
                  <label>
                    {FACTORING_VAULT_BUCKET_LABELS[index]} <small>hidden amount</small>
                    <input
                      inputMode="decimal"
                      value={bucket.amount}
                      onChange={(event) => updateBucket(index, { amount: event.target.value })}
                    />
                  </label>
                  <label>
                    Haircut <small>bps · public · ≤ {FACTORING_VAULT_MAX_HAIRCUT_BPS}</small>
                    <input
                      inputMode="numeric"
                      value={bucket.haircutBps}
                      onChange={(event) => updateBucket(index, { haircutBps: event.target.value })}
                    />
                  </label>
                  <label>
                    Post-haircut <small>derived</small>
                    <input
                      readOnly
                      value={
                        preview
                          ? formatFactoringBaseUnits(preview.buckets[index].weighted / FEE_BPS_DENOMINATOR, decimals)
                          : "—"
                      }
                    />
                  </label>
                </div>
              ))}
            </div>
            <p className={styles.hint}>
              Each bucket amount stays hidden behind its own {bitLength}-bit range proof. Only the haircut basis points are
              published, so a counterparty can recompute the eligibility ceiling without learning a single invoice.
            </p>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Balance inputs</span>
              <small>three range-proved secrets plus the published holdback</small>
            </div>
            <div className={styles.fields}>
              <label>
                Eligible collateral <small>after haircuts</small>
                <input inputMode="decimal" value={eligibleAmount} onChange={(event) => setEligibleAmount(event.target.value)} />
              </label>
              <label>
                Requested advance <small>drawn against the eligible pool</small>
                <input inputMode="decimal" value={advanceAmount} onChange={(event) => setAdvanceAmount(event.target.value)} />
              </label>
              <label>
                Largest debtor exposure <small>concentration test input</small>
                <input
                  inputMode="decimal"
                  value={concentrationAmount}
                  onChange={(event) => setConcentrationAmount(event.target.value)}
                />
              </label>
              <label>
                Holdback reserve <small>public · retained behind the advance</small>
                <input inputMode="decimal" value={holdbackAmount} onChange={(event) => setHoldbackAmount(event.target.value)} />
              </label>
            </div>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Public covenants</span>
              <small>printed on the certificate in clear text</small>
            </div>
            <div className={styles.fields}>
              <label>
                Advance rate <small>bps · ≤ {FEE_BPS_DENOMINATOR.toString()}</small>
                <input inputMode="numeric" value={advanceRateBps} onChange={(event) => setAdvanceRateBps(event.target.value)} />
              </label>
              <label>
                Minimum coverage <small>bps · {FEE_BPS_DENOMINATOR.toString()}–{FACTORING_VAULT_MAX_COVERAGE_RATIO_BPS}</small>
                <input
                  inputMode="numeric"
                  value={minCoverageRatioBps}
                  onChange={(event) => setMinCoverageRatioBps(event.target.value)}
                />
              </label>
              <label>
                Debtor concentration cap <small>bps of face value</small>
                <input
                  inputMode="numeric"
                  value={maxConcentrationBps}
                  onChange={(event) => setMaxConcentrationBps(event.target.value)}
                />
              </label>
              <label>
                Stale receivable cap <small>bps of face value in 90+ days</small>
                <input inputMode="numeric" value={maxStaleBps} onChange={(event) => setMaxStaleBps(event.target.value)} />
              </label>
              <label>
                Discount rate <small>bps per annum</small>
                <input
                  inputMode="numeric"
                  value={discountRateBps}
                  onChange={(event) => setDiscountRateBps(event.target.value)}
                />
              </label>
              <label>
                Tenor <small>days · 1–{MAX_TENOR_DAYS}</small>
                <input inputMode="numeric" value={tenorDays} onChange={(event) => setTenorDays(event.target.value)} />
              </label>
              <label className={styles.wide}>
                Platform fee <small>public · deducted from the advance</small>
                <input
                  inputMode="decimal"
                  value={platformFeeAmount}
                  onChange={(event) => setPlatformFeeAmount(event.target.value)}
                />
              </label>
            </div>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing || !issuer}>
            {issuing ? "Proving covenants…" : "Issue vault certificate"}
          </button>
          <p className={styles.hint}>
            This band needs {estimateFactoringVaultProofCount(bitLength)} bit proofs and every hidden amount must stay at
            or below {bandCeiling ?? "the band ceiling"} {assetSymbol}. Proving runs in this tab on your own machine, so
            widen the band only when a figure needs it.
          </p>
        </form>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <span>02 · Issued certificate</span>
            <h3>Exactly what a counterparty receives.</h3>
          </div>
          {issued && badge ? (
            <>
              <div className={styles.badge}>
                <div className={styles.badgeTop}>
                  <div>
                    <strong>{badge.headline}</strong>
                    <small>
                      {badge.assetSymbol} · {badge.band}
                    </small>
                  </div>
                  <span className={styles.verified}>Signed · {badge.proofCount} legs</span>
                </div>
                <p className={styles.badgeClaim}>
                  {badge.claim}
                  <small>{badge.notice}</small>
                </p>
                <dl className={styles.badgeMeta}>
                  {describeCertificate(issued.certificate).map((row) => (
                    <div key={row.label}>
                      <dt>{row.label}</dt>
                      <dd>{row.value}</dd>
                    </div>
                  ))}
                </dl>
                <ul className={styles.covenantList}>
                  {badge.covenantSummary.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Certificate payload</span>
                  <div className={styles.secretActions}>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`${issued.certificate.vaultId}-certificate.txt`, serializedCertificate)}
                    >
                      Download
                    </button>
                    <button type="button" className={styles.ghost} onClick={loadIssuedIntoVerifier}>
                      Load into verifier
                    </button>
                  </div>
                </div>
                <textarea readOnly value={serializedCertificate} />
                <p className={styles.hint}>
                  Safe to publish. It carries the commitments, the covenants, and the signature — no amount and no client
                  name.
                </p>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Selective disclosure</span>
                  <small className={styles.hint}>{disclosedValue}</small>
                </div>
                <div className={styles.discGrid}>
                  {FIGURES.map((entry) => (
                    <button
                      key={entry.value}
                      type="button"
                      className={styles.ghost}
                      aria-pressed={figure === entry.value}
                      onClick={() => setFigure(entry.value)}
                    >
                      {entry.label}
                    </button>
                  ))}
                </div>
                <textarea readOnly value={serializedDisclosure} />
                <p className={styles.warn}>
                  A disclosure opens exactly one figure and nothing else. Every other commitment stays sealed, but once you
                  hand this payload over the number is public forever — there is no revocation.
                </p>
              </div>
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Blinding secret — merchant only</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealSecret((value) => !value)}>
                      {revealSecret ? "Hide" : "Reveal"}
                    </button>
                    <button
                      type="button"
                      className={styles.ghost}
                      disabled={!revealSecret}
                      onClick={() => download(`${issued.certificate.vaultId}-secret.txt`, serializedSecret)}
                    >
                      Download
                    </button>
                  </div>
                </div>
                {revealSecret ? <textarea readOnly value={serializedSecret} /> : null}
                <p className={styles.warn}>
                  This payload holds every hidden amount and every blinding factor. Publishing it, pasting it into a chat,
                  or committing it to a repository destroys the privacy of the whole facility. Keep it beside your own
                  books.
                </p>
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>
              Issue a certificate to see the badge, the publishable payload, and the per-figure disclosures a counterparty
              can check.
            </p>
          )}
        </div>
      </div>
      <form className={styles.verify} onSubmit={handleVerify}>
        <div className={styles.panelHead}>
          <span>03 · Verify as a counterparty</span>
          <h3>Re-run every leg on your own machine.</h3>
        </div>
        <label>
          Certificate payload <small>required</small>
          <textarea
            value={verifyInput}
            onChange={(event) => setVerifyInput(event.target.value)}
            placeholder="Paste a factoring vault certificate"
            spellCheck={false}
          />
        </label>
        <label>
          Disclosure payload <small>optional · opens one figure</small>
          <textarea
            value={disclosureInput}
            onChange={(event) => setDisclosureInput(event.target.value)}
            placeholder="Paste a disclosure payload to check one number against the same certificate"
            spellCheck={false}
          />
        </label>
        <button type="submit" disabled={verifying || !verifyInput.trim()}>
          {verifying ? "Re-running every leg…" : "Audit the certificate"}
        </button>
        {verifyResult ? (
          <div className={verifyResult.ok ? styles.pass : styles.fail}>
            <strong>
              {verifyResult.error
                ? "Could not read this payload"
                : verifyResult.ok
                  ? "Every leg closed"
                  : "This certificate does not hold"}
            </strong>
            {verifyResult.error ? (
              <small>{verifyResult.error}</small>
            ) : (
              <small>
                {verifyResult.ok
                  ? "The signature authenticates the issuer, every hidden figure sits inside the declared band, and each covenant closes against the same commitments. It says nothing about whether those receivables exist."
                  : "The first failing leg is marked below. Auditing stops there, so later legs are not evaluated."}
              </small>
            )}
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
            {verifyResult.checks ? (
              <div className={styles.tableWrap}>
                <table className={`${styles.tierTable} ${styles.checkTable}`}>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Leg</th>
                      <th>Result</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {verifyResult.checks.map((check, index) => (
                      <tr key={check.label}>
                        <td>{index + 1}</td>
                        <td>{check.label}</td>
                        <td className={check.passed ? styles.checkOk : styles.checkBad}>
                          {check.passed ? "pass" : "fail"}
                        </td>
                        <td className={styles.checkDetail}>{check.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            {verifyResult.disclosure ? (
              <dl className={styles.resultMeta}>
                <div>
                  <dt>Disclosed figure</dt>
                  <dd>{verifyResult.disclosure.figure}</dd>
                </div>
                <div>
                  <dt>{verifyResult.disclosure.ok ? "Opens the commitment" : "Rejected"}</dt>
                  <dd className={verifyResult.disclosure.ok ? styles.yes : styles.no}>
                    {verifyResult.disclosure.value}
                  </dd>
                </div>
              </dl>
            ) : null}
          </div>
        ) : (
          <p className={styles.placeholder}>
            Paste a payload, or press Load into verifier above, to re-run the whole audit here. Nothing leaves this tab.
          </p>
        )}
      </form>
      <section className={styles.model}>
        <div>
          <h4>Proven by the certificate</h4>
          <ul>
            {TRUST.proven.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>Hidden from the verifier</h4>
          <ul>
            {TRUST.hidden.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>Visible to anyone holding it</h4>
          <ul>
            {TRUST.visible.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      </section>
      <section className={`${styles.model} ${styles.limitation}`}>
        <div>
          <h4 className={styles.statement}>What this does not do</h4>
          <p>
            The certificate proves that the numbers a merchant committed to are internally consistent with the covenants
            printed beside them. It proves nothing about whether those receivables exist, whether the debtors will pay, or
            whether the same invoices have already been factored somewhere else.
          </p>
          <ul>
            {TRUST.limitations.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p>
            Proof system: Pedersen-style commitments on the STARK curve with a second generator derived by hashing the
            first, per-bit range proofs over {estimateFactoringVaultProofCount(bitLength)} legs at this band, and a Schnorr
            signature over a Poseidon binding hash. Covenant tests are homomorphic identities between those commitments, so
            a verifier recomputes each one without learning any figure. The pool address is carried as provenance for the
            facility this prototype was written against; the engine never calls it and never reads on-chain state.
          </p>
        </div>
      </section>
    </div>
  );
}
