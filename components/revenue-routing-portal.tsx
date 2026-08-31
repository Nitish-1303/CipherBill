"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  MAX_ASSET_DECIMALS,
  MAX_ROUTING_DUST_BASE_UNITS,
  REVENUE_ROUTING_CHECK_COUNT,
  REVENUE_ROUTING_POOL_ADDRESS,
  REVENUE_ROUTING_SLOTS,
  aggregateCorridorLedger,
  assessRoutingConcentration,
  assessRoutingPolicy,
  auditRevenueRoutingCertificate,
  buildRevenueRoutingAgreementDisclosure,
  buildRevenueRoutingAmountDisclosure,
  buildRevenueRoutingCertificateBadge,
  buildRevenueRoutingPayerDisclosure,
  buildRevenueRoutingRecipientDisclosure,
  buildRoutingWaterfall,
  computeRevenueRoutingPlan,
  createRevenueRoutingIssuerKey,
  estimateRevenueRoutingProofCount,
  evaluateRoutingRelease,
  formatRoutingBaseUnits,
  formatRoutingBps,
  formatSettlementAgeDays,
  getRevenueRoutingTrustModel,
  getRevenueRoutingVisibilityModel,
  issueRevenueRoutingCertificate,
  parseRevenueRoutingAmountDisclosure,
  parseRevenueRoutingCertificate,
  parseRevenueRoutingRefDisclosure,
  serializeRevenueRoutingAmountDisclosure,
  serializeRevenueRoutingCertificate,
  serializeRevenueRoutingCertificateSecret,
  serializeRevenueRoutingRefDisclosure,
  verifyRevenueRoutingAmountDisclosure,
  verifyRevenueRoutingRefDisclosure,
  type IssuedRevenueRoutingCertificate,
  type RevenueRoutingAmountField,
  type RevenueRoutingCertificate,
  type RevenueRoutingCheck,
  type RevenueRoutingKeypair,
  type RoutingConcentrationBand,
  type RoutingJurisdictions,
  type RoutingRecipientRefs,
  type RoutingSplitBps,
  type SettlementRow,
  type WaterfallStepKind,
} from "@/lib/revenue-routing-engine";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./revenue-routing-portal.module.css";

const INTRO =
  "Prove in zero knowledge that a hidden gross settlement splits across six routing slots exactly at a published basis-point schedule, that the six hidden payouts plus a hidden rounding remainder conserve that gross to the last base unit, and that four public covenants hold — a settlement floor, an affiliate cap, a tax-reserve floor, and a rounding tolerance — without revealing the gross, any payout, the remainder, the payer, or any recipient reference. The merchant signs the certificate so anyone can authenticate it offline. Nothing here routes value: no stakeholder is paid, no affiliate is credited, no tax is withheld, no incoming payment is observed, and this engine never reads from or writes to the STRK20 pool contract.";

/** Starknet mainnet USDC. A provenance label on the certificate; never called. */
const USDC_TOKEN_ADDRESS = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";

const TRUST = getRevenueRoutingTrustModel();
const VISIBILITY = getRevenueRoutingVisibilityModel();

const BAND_LABEL: Record<RoutingConcentrationBand, string> = {
  balanced: "Balanced",
  tilted: "Tilted",
  concentrated: "Concentrated",
  "single-party": "Single-party",
};

/** Waterfall bars are tinted by step kind; stakeholders keep the default mint. */
const WATERFALL_CLASS: Record<WaterfallStepKind, string> = {
  stakeholder: "",
  affiliate: styles.waterKindAffiliate,
  tax: styles.waterKindTax,
  remainder: styles.waterKindRemainder,
};

const AMOUNT_FIELDS: { value: RevenueRoutingAmountField; label: string }[] = [
  { value: "gross", label: "Gross settlement" },
  { value: "slot0", label: "Stakeholder A" },
  { value: "slot1", label: "Stakeholder B" },
  { value: "slot2", label: "Stakeholder C" },
  { value: "slot3", label: "Stakeholder D" },
  { value: "slot4", label: "Affiliate pool" },
  { value: "slot5", label: "Tax reserve" },
  { value: "dust", label: "Rounding remainder" },
];

const BIT_LENGTHS = ["32", "48", "64", "96", "128"];

interface SlotDraft {
  bps: string;
  jurisdiction: string;
  recipient: string;
}

interface SettlementDraft {
  id: string;
  reference: string;
  jurisdiction: string;
  receivedAt: string;
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
  checks?: RevenueRoutingCheck[];
  disclosure?: DisclosureResult;
  error?: string;
}

const DEFAULT_SLOTS: SlotDraft[] = [
  { bps: "3000", jurisdiction: "DE", recipient: "stakeholder_a_berlin" },
  { bps: "2500", jurisdiction: "SG", recipient: "stakeholder_b_singapore" },
  { bps: "1500", jurisdiction: "US", recipient: "stakeholder_c_delaware" },
  { bps: "1000", jurisdiction: "BR", recipient: "stakeholder_d_sao_paulo" },
  { bps: "1000", jurisdiction: "GB", recipient: "affiliate_pool_london" },
  { bps: "1000", jurisdiction: "NL", recipient: "tax_reserve_amsterdam" },
];

const DEFAULT_SETTLEMENTS: SettlementDraft[] = [
  { id: "set_1", reference: "INV-8841", jurisdiction: "DE", receivedAt: "2026-08-24", amount: "82" },
  { id: "set_2", reference: "INV-8842", jurisdiction: "SG", receivedAt: "2026-08-19", amount: "47" },
  { id: "set_3", reference: "INV-8843", jurisdiction: "DE", receivedAt: "2026-08-02", amount: "40" },
  { id: "set_4", reference: "INV-8844", jurisdiction: "BR", receivedAt: "2026-07-28", amount: "30" },
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

function parseIntOrZero(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

/** Covenant surpluses go negative; formatRoutingBaseUnits only accepts ≥ 0. */
function formatSignedBaseUnits(value: string, decimals: number): string {
  const negative = value.startsWith("-");
  try {
    return `${negative ? "−" : ""}${formatRoutingBaseUnits(negative ? value.slice(1) : value, decimals)}`;
  } catch {
    return value;
  }
}

/** Basis-point readout that degrades to the raw figure instead of throwing. */
function safeBps(value: string | number): string {
  const parsed = typeof value === "number" ? value : Number.parseInt(value, 10);
  try {
    return formatRoutingBps(parsed);
  } catch {
    return `${value} bps`;
  }
}

/**
 * The slot drafts are a fixed six-element list — the editor can change a row but
 * never add or remove one — so the tuple casts below are shape-preserving. The
 * engine re-validates the length anyway and throws if it ever drifts.
 */
function toSplitBps(drafts: SlotDraft[]): RoutingSplitBps {
  return drafts.map((slot) => parseIntOrZero(slot.bps)) as unknown as RoutingSplitBps;
}

function toJurisdictions(drafts: SlotDraft[]): RoutingJurisdictions {
  return drafts.map((slot) => slot.jurisdiction) as unknown as RoutingJurisdictions;
}

function toRecipientRefs(drafts: SlotDraft[]): RoutingRecipientRefs {
  return drafts.map((slot) => slot.recipient) as unknown as RoutingRecipientRefs;
}

function toSettlementRows(drafts: SettlementDraft[], decimals: number): SettlementRow[] {
  return drafts.map((row) => ({
    reference: row.reference,
    jurisdiction: row.jurisdiction,
    receivedAt: new Date(`${row.receivedAt}T00:00:00.000Z`).toISOString(),
    amountBaseUnits: toBaseUnitsAllowingZero(row.amount, decimals),
  }));
}

/**
 * Classifies a pasted disclosure payload. Every branch — including the last —
 * returns a neutral result instead of throwing, so an unrecognized payload can
 * never overwrite an otherwise valid certificate verdict.
 */
function evaluateDisclosure(certificate: RevenueRoutingCertificate, raw: string): DisclosureResult {
  try {
    const amount = parseRevenueRoutingAmountDisclosure(raw);
    const ok = verifyRevenueRoutingAmountDisclosure(certificate, amount);
    let value: string;
    try {
      value =
        amount.field === "dust"
          ? `${amount.amountBaseUnits} base units`
          : `${formatRoutingBaseUnits(amount.amountBaseUnits, certificate.assetDecimals)} ${certificate.assetSymbol}`;
    } catch {
      value = `${amount.amountBaseUnits} base units`;
    }
    return { type: amount.field, ok, value };
  } catch {
    /* Not an amount disclosure — try the reference form below. */
  }
  try {
    const ref = parseRevenueRoutingRefDisclosure(raw);
    return { type: ref.field, ok: verifyRevenueRoutingRefDisclosure(certificate, ref), value: ref.value || "(empty)" };
  } catch {
    return { type: "unrecognized", ok: false, value: "This payload is not a revenue routing disclosure." };
  }
}

/**
 * Flattens a pasted certificate into display rows. Parsing only checks the
 * envelope kind, so every field here is still untrusted: formatting runs inside
 * handleVerify's try block so a malformed figure surfaces as a read error
 * instead of throwing during render.
 */
function describeCertificate(certificate: RevenueRoutingCertificate): VerifyMetaRow[] {
  const asset = certificate.assetSymbol;
  const decimals = certificate.assetDecimals;
  return [
    { label: "Merchant", value: certificate.merchantAlias },
    { label: "Programme", value: certificate.programLabel },
    { label: "Entitlement schedule", value: certificate.splitBps.map((bps) => safeBps(bps)).join(" / ") },
    { label: "Corridors", value: certificate.jurisdictions.join(" · ") },
    {
      label: "Settlement floor",
      value: `${formatRoutingBaseUnits(certificate.minGrossBaseUnits, decimals)} ${asset}`,
    },
    {
      label: "Affiliate cap",
      value: `${formatRoutingBaseUnits(certificate.maxAffiliatePayoutBaseUnits, decimals)} ${asset}`,
    },
    {
      label: "Tax reserve floor",
      value: `${formatRoutingBaseUnits(certificate.minTaxReserveBaseUnits, decimals)} ${asset}`,
    },
    { label: "Rounding tolerance", value: `${certificate.maxDustBaseUnits} base units` },
    { label: "Agreement reference", value: certificate.agreementCommitted ? "Committed, hidden" : "Not committed" },
    { label: "Payer reference", value: certificate.payerCommitted ? "Committed, hidden" : "Not committed" },
    { label: "Issued", value: formatDate(certificate.createdAt) },
    { label: "Pool provenance", value: shorten(certificate.poolAddress) },
    { label: "Binding", value: shorten(certificate.bindingHash) },
  ];
}

export function RevenueRoutingPortal() {
  const [issuer, setIssuer] = useState<RevenueRoutingKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [programLabel, setProgramLabel] = useState("Cross-Border Revenue Routing");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [tokenAddress, setTokenAddress] = useState(USDC_TOKEN_ADDRESS);
  const [memo, setMemo] = useState("Quarterly multi-party revenue split attestation");

  const [minGrossAmount, setMinGrossAmount] = useState("100");
  const [maxAffiliateAmount, setMaxAffiliateAmount] = useState("40");
  const [minTaxReserveAmount, setMinTaxReserveAmount] = useState("10");
  const [maxDustUnits, setMaxDustUnits] = useState("5");

  const [grossAmount, setGrossAmount] = useState("199");
  const [agreementRef, setAgreementRef] = useState("REV-SHARE-2026-Q3");
  const [payerRef, setPayerRef] = useState("acquirer_eu_channel");
  const [concentrationThreshold, setConcentrationThreshold] = useState("40");
  const [amountBitLength, setAmountBitLength] = useState("48");
  const [slots, setSlots] = useState<SlotDraft[]>(DEFAULT_SLOTS);
  const [settlements, setSettlements] = useState<SettlementDraft[]>(DEFAULT_SETTLEMENTS);

  const [issued, setIssued] = useState<IssuedRevenueRoutingCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealAgreement, setRevealAgreement] = useState(false);
  const [revealPayer, setRevealPayer] = useState(false);
  const [amountField, setAmountField] = useState<RevenueRoutingAmountField>("slot5");
  const [recipientSlot, setRecipientSlot] = useState(0);

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= MAX_ASSET_DECIMALS ? parsed : 6;
  }, [assetDecimals]);

  const bitLength = useMemo(() => {
    const parsed = Number.parseInt(amountBitLength, 10);
    return Number.isFinite(parsed) && parsed >= 8 && parsed <= 128 ? parsed : 48;
  }, [amountBitLength]);

  const bandCeiling = useMemo(() => {
    try {
      return formatRoutingBaseUnits((2n ** BigInt(bitLength) - 1n).toString(), decimals);
    } catch {
      return null;
    }
  }, [bitLength, decimals]);

  const proofCount = useMemo(() => {
    try {
      return estimateRevenueRoutingProofCount(bitLength);
    } catch {
      return 0;
    }
  }, [bitLength]);

  const scheduleTotal = useMemo(() => slots.reduce((acc, slot) => acc + parseIntOrZero(slot.bps), 0), [slots]);

  const preview = useMemo(() => {
    try {
      const policy = {
        minGrossBaseUnits: toBaseUnitsAllowingZero(minGrossAmount, decimals),
        maxAffiliatePayoutBaseUnits: toBaseUnitsAllowingZero(maxAffiliateAmount, decimals),
        minTaxReserveBaseUnits: toBaseUnitsAllowingZero(minTaxReserveAmount, decimals),
        maxDustBaseUnits: parseIntOrZero(maxDustUnits).toString(),
      };
      const threshold = Math.max(0, Math.min(100, parseIntOrZero(concentrationThreshold)));
      const plan = computeRevenueRoutingPlan(toBaseUnitsAllowingZero(grossAmount, decimals), toSplitBps(slots));
      const waterfall = buildRoutingWaterfall(plan);
      const assessment = assessRoutingPolicy(plan, policy);
      const concentration = assessRoutingConcentration(plan);
      const release = evaluateRoutingRelease(plan, threshold);
      const ledger = aggregateCorridorLedger(toSettlementRows(settlements, decimals));
      const realizedTotalBps = plan.slots.reduce((acc, slot) => acc + parseIntOrZero(slot.realizedShareBps), 0);
      const uniqueCorridors = new Set(slots.map((slot) => slot.jurisdiction)).size;
      return {
        policy,
        threshold,
        plan,
        waterfall,
        assessment,
        concentration,
        release,
        ledger,
        realizedTotalBps,
        uniqueCorridors,
        ledgerMatchesGross: ledger.grossBaseUnits === plan.grossBaseUnits,
      };
    } catch {
      return null;
    }
  }, [
    concentrationThreshold,
    decimals,
    grossAmount,
    maxAffiliateAmount,
    maxDustUnits,
    minGrossAmount,
    minTaxReserveAmount,
    settlements,
    slots,
  ]);

  const badge = useMemo(() => (issued ? buildRevenueRoutingCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(
    () => (issued ? serializeRevenueRoutingCertificate(issued.certificate) : ""),
    [issued],
  );
  const serializedSecret = useMemo(
    () => (issued ? serializeRevenueRoutingCertificateSecret(issued.secret) : ""),
    [issued],
  );

  const amountDisclosure = useMemo(() => {
    if (!issued) return "";
    try {
      return serializeRevenueRoutingAmountDisclosure(buildRevenueRoutingAmountDisclosure(issued.secret, amountField));
    } catch {
      return "";
    }
  }, [issued, amountField]);

  const recipientDisclosure = useMemo(() => {
    if (!issued) return "";
    try {
      return serializeRevenueRoutingRefDisclosure(
        buildRevenueRoutingRecipientDisclosure(issued.secret, recipientSlot),
      );
    } catch {
      return "";
    }
  }, [issued, recipientSlot]);

  const agreementDisclosure = useMemo(() => {
    if (!issued || !issued.certificate.agreementCommitted) return "";
    try {
      return serializeRevenueRoutingRefDisclosure(buildRevenueRoutingAgreementDisclosure(issued.secret));
    } catch {
      return "";
    }
  }, [issued]);

  const payerDisclosure = useMemo(() => {
    if (!issued || !issued.certificate.payerCommitted) return "";
    try {
      return serializeRevenueRoutingRefDisclosure(buildRevenueRoutingPayerDisclosure(issued.secret));
    } catch {
      return "";
    }
  }, [issued]);

  function generateIssuerKey() {
    setIssuer(createRevenueRoutingIssuerKey());
    setRevealSecretKey(false);
  }

  function updateSlot(index: number, patch: Partial<SlotDraft>) {
    setSlots((rows) => rows.map((row, position) => (position === index ? { ...row, ...patch } : row)));
  }

  function updateSettlement(id: string, patch: Partial<SettlementDraft>) {
    setSettlements((rows) => rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  function addSettlementRow() {
    setSettlements((rows) => [
      ...rows,
      { id: `set_${Date.now()}`, reference: "INV-0000", jurisdiction: "DE", receivedAt: "2026-08-01", amount: "10" },
    ]);
  }

  function removeSettlementRow(id: string) {
    setSettlements((rows) => (rows.length > 1 ? rows.filter((row) => row.id !== id) : rows));
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
    setRevealAgreement(false);
    setRevealPayer(false);
    setTimeout(() => {
      try {
        const result = issueRevenueRoutingCertificate({
          merchantAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          agreementRef: agreementRef.trim() || undefined,
          programLabel,
          splitBps: toSplitBps(slots),
          jurisdictions: toJurisdictions(slots),
          policy: {
            minGrossBaseUnits: toBaseUnitsAllowingZero(minGrossAmount, decimals),
            maxAffiliatePayoutBaseUnits: toBaseUnitsAllowingZero(maxAffiliateAmount, decimals),
            minTaxReserveBaseUnits: toBaseUnitsAllowingZero(minTaxReserveAmount, decimals),
            maxDustBaseUnits: parseIntOrZero(maxDustUnits).toString(),
          },
          grossBaseUnits: toBaseUnitsAllowingZero(grossAmount, decimals),
          recipientRefs: toRecipientRefs(slots),
          payerRef: payerRef.trim() || undefined,
          issuerSecretKey: issuer.secretKey,
          amountBitLength: bitLength,
          memo: memo.trim() || undefined,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the revenue routing certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseRevenueRoutingCertificate(verifyInput.trim());
      const checks = auditRevenueRoutingCertificate(certificate);
      const ok = checks.length === REVENUE_ROUTING_CHECK_COUNT && checks.every((row) => row.passed);
      const raw = disclosureInput.trim();
      const disclosure = raw ? evaluateDisclosure(certificate, raw) : undefined;
      setVerifyResult({ ok, meta: describeCertificate(certificate), checks, disclosure });
    } catch (error) {
      setVerifyResult({
        ok: false,
        error: error instanceof Error ? error.message : "The certificate could not be parsed.",
      });
    }
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Cross-border split payment &amp; revenue routing</span>
          <h2>
            Prove a <em>six-way split</em> without revealing the revenue.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(REVENUE_ROUTING_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Conservation + exact floors + 4 covenants</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Issuer signature</dt>
            <dd className={styles.yes}>Authenticated</dd>
          </div>
          <div>
            <dt>Routes, pays, or withholds value</dt>
            <dd className={styles.no}>Never</dd>
          </div>
          <div>
            <dt>Observes an incoming payment</dt>
            <dd className={styles.no}>Never</dd>
          </div>
          <div>
            <dt>Entitlement schedule &amp; corridors</dt>
            <dd className={styles.no}>Public by design</dd>
          </div>
          <div>
            <dt>STRK20 pool contract</dt>
            <dd className={styles.no}>Never called</dd>
          </div>
        </dl>
      </header>

      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Institutional revenue splitting dashboard</span>
          <small>Deterministic integer arithmetic · nothing is routed, paid, withheld, scheduled, or queued</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Gross settlement</dt>
                <dd>
                  {formatRoutingBaseUnits(preview.plan.grossBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Allocated to slots</dt>
                <dd>
                  {formatRoutingBaseUnits(preview.plan.allocatedBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Rounding remainder</dt>
                <dd>{preview.plan.dustBaseUnits} base units</dd>
              </div>
              <div className={styles.metric}>
                <dt>Concentration</dt>
                <dd>
                  {BAND_LABEL[preview.concentration.band]} · {preview.concentration.score}
                </dd>
              </div>
            </dl>
            {!preview.assessment.eligible ? (
              <div className={styles.monitor}>
                <div className={styles.monitorTop}>
                  <strong>Covenant preview</strong>
                  <span className={`${styles.chip} ${styles.chipStop}`}>No honest proof exists</span>
                </div>
                <ul className={styles.reasons}>
                  {preview.assessment.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            <div className={styles.subSection}>
              <div className={styles.subHead}>
                <span>Distribution waterfall</span>
                <small>
                  seven steps draw the gross down to exactly zero · closing balance{" "}
                  {formatRoutingBaseUnits(
                    preview.waterfall[preview.waterfall.length - 1].closingBalanceBaseUnits,
                    decimals,
                  )}{" "}
                  {assetSymbol}
                </small>
              </div>
              <div className={styles.waterfall}>
                {preview.waterfall.map((step) => (
                  <div key={`${step.index}-${step.label}`} className={styles.waterRow}>
                    <div className={styles.waterLabel}>
                      {step.label}
                      <small>{step.kind}</small>
                    </div>
                    <div className={`${styles.waterBar} ${WATERFALL_CLASS[step.kind]}`.trim()}>
                      <span
                        style={{ width: `${Math.max(0, Math.min(100, parseIntOrZero(step.shareBps) / 100))}%` }}
                      />
                    </div>
                    <span className={styles.waterValue}>
                      {formatRoutingBaseUnits(step.deductionBaseUnits, decimals)}
                    </span>
                    <span className={styles.waterShare}>{safeBps(step.shareBps)}</span>
                  </div>
                ))}
              </div>
              <p className={styles.hint}>
                Each bar is a deduction from the running balance, sized by its realized share of the gross. The bars are
                presentation arithmetic over figures you typed — no balance is read, no transfer is built, and the final
                step is the unallocated rounding remainder, not a payment.
              </p>
            </div>

            <div className={styles.tableWrap}>
              <table className={styles.tierTable}>
                <thead>
                  <tr>
                    <th>Routing slot</th>
                    <th>Corridor</th>
                    <th>Entitlement</th>
                    <th>Payout</th>
                    <th>Realized</th>
                    <th>Discarded numerator</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.plan.slots.map((slot) => (
                    <tr
                      key={slot.key}
                      className={parseIntOrZero(slot.payoutBaseUnits) > 0 ? styles.activeTier : styles.mutedRow}
                    >
                      <td>{slot.label}</td>
                      <td>{slots[slot.index].jurisdiction}</td>
                      <td>{formatRoutingBps(Number(slot.entitlementBps))}</td>
                      <td>
                        {formatRoutingBaseUnits(slot.payoutBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td>{safeBps(slot.realizedShareBps)}</td>
                      <td>{slot.roundingRemainder} / 10000</td>
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr>
                    <td>Totals · {assetSymbol}</td>
                    <td>{preview.uniqueCorridors} corridors</td>
                    <td>{safeBps(preview.plan.totalEntitlementBps)}</td>
                    <td>{formatRoutingBaseUnits(preview.plan.allocatedBaseUnits, decimals)}</td>
                    <td>{safeBps(preview.realizedTotalBps)}</td>
                    <td>
                      {preview.plan.dustBaseUnits} of at most {preview.plan.maxPossibleDustBaseUnits} base units
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>

            <div className={styles.subSection}>
              <div className={styles.subHead}>
                <span>Covenant surpluses</span>
                <small>each one is range-proven non-negative inside the certificate</small>
              </div>
              <dl className={styles.dashGrid}>
                <div className={styles.metric}>
                  <dt>Settlement floor</dt>
                  <dd>
                    {formatSignedBaseUnits(preview.assessment.grossFloorSurplus, decimals)} {assetSymbol}
                  </dd>
                </div>
                <div className={styles.metric}>
                  <dt>Affiliate cap</dt>
                  <dd>
                    {formatSignedBaseUnits(preview.assessment.affiliateCapSurplus, decimals)} {assetSymbol}
                  </dd>
                </div>
                <div className={styles.metric}>
                  <dt>Tax reserve floor</dt>
                  <dd>
                    {formatSignedBaseUnits(preview.assessment.taxFloorSurplus, decimals)} {assetSymbol}
                  </dd>
                </div>
                <div className={styles.metric}>
                  <dt>Rounding tolerance</dt>
                  <dd>{preview.assessment.dustCeilingSurplus} base units</dd>
                </div>
              </dl>
            </div>
            <div className={styles.subSection}>
              <div className={styles.subHead}>
                <span>Cross-border corridor ledger</span>
                <small>
                  {preview.ledger.rowCount} settlement rows · {preview.ledger.corridorCount} corridors · as of{" "}
                  {formatDate(preview.ledger.asOf)}
                </small>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.tierTable}>
                  <thead>
                    <tr>
                      <th>Corridor</th>
                      <th>Rows</th>
                      <th>Amount</th>
                      <th>Share of ledger</th>
                      <th>Oldest row</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.ledger.corridors.map((corridor) => (
                      <tr key={corridor.jurisdiction}>
                        <td>{corridor.jurisdiction}</td>
                        <td>{corridor.rowCount}</td>
                        <td>
                          {formatRoutingBaseUnits(corridor.amountBaseUnits, decimals)} {assetSymbol}
                        </td>
                        <td>{safeBps(corridor.shareBps)}</td>
                        <td>{formatSettlementAgeDays(corridor.oldestAgeDays)}</td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot>
                    <tr>
                      <td>Ledger total</td>
                      <td>{preview.ledger.rowCount}</td>
                      <td>
                        {formatRoutingBaseUnits(preview.ledger.grossBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td>{safeBps(preview.ledger.largestCorridorShareBps)} largest</td>
                      <td>{formatSettlementAgeDays(preview.ledger.averageAgeDays)} average</td>
                    </tr>
                  </tfoot>
                </table>
              </div>
              <p className={styles.hint}>
                The rows are aggregated locally and never enter the certificate — not the references, not the corridors,
                not the dates. They exist so you can reconcile the gross you type against the settlements you believe
                arrived; the engine cannot check that any of them arrived, because it observes no incoming payment.
              </p>
            </div>
            <div className={styles.monitor}>
              <div className={styles.monitorTop}>
                <strong>Cryptographic settlement monitor</strong>
                <span
                  className={`${styles.chip} ${preview.release.withinThreshold ? styles.chipGo : styles.chipHold}`}
                >
                  {preview.release.withinThreshold ? "Within concentration threshold" : "Above concentration threshold"}
                </span>
              </div>
              <ul className={styles.reasons}>
                <li>
                  Concentration score {preview.release.concentrationScore} against a threshold of {preview.threshold} ·
                  band {BAND_LABEL[preview.release.band]}.
                </li>
                <li>{preview.concentration.rationale}</li>
                <li>
                  Largest realized share {safeBps(preview.concentration.largestShareBps)} · Herfindahl index{" "}
                  {preview.concentration.herfindahlIndex} of 10000 · stakeholders{" "}
                  {safeBps(preview.concentration.stakeholderShareBps)}, affiliate{" "}
                  {safeBps(preview.concentration.affiliateShareBps)}, reserve{" "}
                  {safeBps(preview.concentration.reserveShareBps)}.
                </li>
                <li>
                  Schedule totals {scheduleTotal} of 10000 basis points, and the settlement rows{" "}
                  {preview.ledgerMatchesGross ? "reconcile exactly to" : "do not reconcile to"} the gross you typed.
                </li>
                <li>
                  Crossing the threshold arms nothing and executes nothing: the engine reports executesAnything as{" "}
                  {String(preview.release.executesAnything)} by construction. There is no scheduler, no relayer, no
                  counterparty, and no contract call anywhere in this module.
                </li>
              </ul>
            </div>
            <p className={styles.hint}>
              The gross, every payout, and the remainder stay hidden inside the certificate; only the entitlement
              schedule, the corridor tags, the four covenant scalars, and the asset are published. Because the schedule
              is public, a verifier who learns any single payout can derive the gross and every other payout from it.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>
            One or more inputs cannot be parsed yet — check that the six entitlement shares are whole basis points
            totalling 10000, that the rounding tolerance is at most {MAX_ROUTING_DUST_BASE_UNITS.toString()} base units,
            and that every settlement row has a date and a decimal amount. The dashboard returns as soon as every field
            is valid.
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
            The issuer key signs each routing certificate. It is generated and kept in this browser tab only; nothing is
            uploaded, and only the public key is embedded so a counterparty can authenticate the signature offline.
          </p>
        )}
      </section>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue a revenue routing certificate</span>
            <h3>Split a hidden gross across six slots</h3>
          </div>
          <div className={styles.fields}>
            <label>
              Merchant alias <small>public</small>
              <input value={merchantAlias} onChange={(event) => setMerchantAlias(event.target.value)} />
            </label>
            <label>
              Programme label <small>public</small>
              <input value={programLabel} onChange={(event) => setProgramLabel(event.target.value)} />
            </label>
            <label>
              Asset symbol <small>public</small>
              <input value={assetSymbol} onChange={(event) => setAssetSymbol(event.target.value)} />
            </label>
            <label>
              Asset decimals <small>0 to {MAX_ASSET_DECIMALS}</small>
              <input
                type="number"
                min={0}
                max={MAX_ASSET_DECIMALS}
                value={assetDecimals}
                onChange={(event) => setAssetDecimals(event.target.value)}
              />
            </label>
            <label>
              Proof band <small>bits per amount leg</small>
              <select value={amountBitLength} onChange={(event) => setAmountBitLength(event.target.value)}>
                {BIT_LENGTHS.map((bits) => (
                  <option key={bits} value={bits}>
                    {bits} bits
                  </option>
                ))}
              </select>
            </label>
            <label>
              Concentration threshold <small>0 to 100 · local heuristic only</small>
              <input
                type="number"
                min={0}
                max={100}
                value={concentrationThreshold}
                onChange={(event) => setConcentrationThreshold(event.target.value)}
              />
            </label>
            <label className={styles.wide}>
              Token address <small>provenance label · never called</small>
              <input value={tokenAddress} onChange={(event) => setTokenAddress(event.target.value)} />
            </label>
            <label className={styles.wide}>
              Memo <small>public · optional</small>
              <input value={memo} onChange={(event) => setMemo(event.target.value)} />
            </label>
          </div>

          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Public covenants</span>
              <small>published in the clear and range-proven against the hidden figures</small>
            </div>
            <div className={styles.fields}>
              <label>
                Settlement floor <small>gross must be at least this</small>
                <input value={minGrossAmount} onChange={(event) => setMinGrossAmount(event.target.value)} />
              </label>
              <label>
                Affiliate cap <small>slot 4 payout must not exceed this</small>
                <input value={maxAffiliateAmount} onChange={(event) => setMaxAffiliateAmount(event.target.value)} />
              </label>
              <label>
                Tax reserve floor <small>slot 5 payout must be at least this</small>
                <input value={minTaxReserveAmount} onChange={(event) => setMinTaxReserveAmount(event.target.value)} />
              </label>
              <label>
                Rounding tolerance <small>base units · at most {MAX_ROUTING_DUST_BASE_UNITS.toString()}</small>
                <input
                  type="number"
                  min={0}
                  value={maxDustUnits}
                  onChange={(event) => setMaxDustUnits(event.target.value)}
                />
              </label>
            </div>
          </div>

          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Hidden figures</span>
              <small>committed, never published</small>
            </div>
            <div className={styles.fields}>
              <label>
                Gross settlement <small>hidden · {assetSymbol}</small>
                <input value={grossAmount} onChange={(event) => setGrossAmount(event.target.value)} />
              </label>
              <label>
                Agreement reference <small>hidden · optional</small>
                <input value={agreementRef} onChange={(event) => setAgreementRef(event.target.value)} />
              </label>
              <label className={styles.wide}>
                Payer reference <small>hidden · optional · a label, never an address</small>
                <input value={payerRef} onChange={(event) => setPayerRef(event.target.value)} />
              </label>
            </div>
          </div>

          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Entitlement schedule</span>
              <small>
                {scheduleTotal} of 10000 bps · shares and corridors are PUBLIC, recipient references are committed
              </small>
            </div>
            <div className={styles.slotEditor}>
              {slots.map((slot, index) => (
                <div key={REVENUE_ROUTING_SLOTS[index].key} className={styles.slotEditRow}>
                  <span className={styles.slotTag}>
                    {REVENUE_ROUTING_SLOTS[index].label} · {REVENUE_ROUTING_SLOTS[index].kind}
                  </span>
                  <input
                    type="number"
                    min={0}
                    max={10000}
                    value={slot.bps}
                    aria-label={`${REVENUE_ROUTING_SLOTS[index].label} entitlement in basis points`}
                    onChange={(event) => updateSlot(index, { bps: event.target.value })}
                  />
                  <input
                    value={slot.jurisdiction}
                    aria-label={`${REVENUE_ROUTING_SLOTS[index].label} corridor`}
                    onChange={(event) => updateSlot(index, { jurisdiction: event.target.value })}
                  />
                  <input
                    value={slot.recipient}
                    aria-label={`${REVENUE_ROUTING_SLOTS[index].label} recipient reference`}
                    onChange={(event) => updateSlot(index, { recipient: event.target.value })}
                  />
                </div>
              ))}
            </div>
            <p className={styles.hint}>
              The six shares must be whole basis points totalling exactly 10000. Each payout is proven to be the exact
              floor of its share of the hidden gross, so a schedule that does not total 10000 has no honest proof.
            </p>
          </div>

          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Settlement rows</span>
              <small>local reconciliation only · never committed, never proven, never published</small>
            </div>
            <div className={styles.rowEditor}>
              {settlements.map((row) => (
                <div key={row.id} className={styles.rowEditRow}>
                  <input
                    value={row.reference}
                    aria-label="Settlement reference"
                    onChange={(event) => updateSettlement(row.id, { reference: event.target.value })}
                  />
                  <input
                    value={row.jurisdiction}
                    aria-label="Settlement corridor"
                    onChange={(event) => updateSettlement(row.id, { jurisdiction: event.target.value })}
                  />
                  <input
                    type="date"
                    value={row.receivedAt}
                    aria-label="Settlement date"
                    onChange={(event) => updateSettlement(row.id, { receivedAt: event.target.value })}
                  />
                  <input
                    value={row.amount}
                    aria-label="Settlement amount"
                    onChange={(event) => updateSettlement(row.id, { amount: event.target.value })}
                  />
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => removeSettlementRow(row.id)}
                    disabled={settlements.length < 2}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
            <button type="button" className={styles.ghost} onClick={addSettlementRow}>
              Add settlement row
            </button>
          </div>

          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing || !issuer}>
            {issuing ? "Proving in zero knowledge…" : "Issue routing certificate"}
          </button>
          <p className={styles.hint}>
            Issuing builds {proofCount} single-bit proofs at {bitLength} bits per amount leg
            {bandCeiling ? ` (a ceiling of ${bandCeiling} ${assetSymbol} per figure)` : ""} and runs entirely in this tab.
            Expect a visible pause on a wider band. Nothing is uploaded, nothing is signed on chain, and no stakeholder,
            affiliate, or tax authority is contacted.
          </p>
        </form>

        <section className={styles.panel}>
          <div className={styles.panelHead}>
            <span>02 · Issued certificate</span>
            <h3>Publish the proof, keep the figures</h3>
          </div>
          {issued && badge ? (
            <>
              <div className={styles.badge}>
                <div className={styles.badgeTop}>
                  <div>
                    <strong>{badge.headline}</strong>
                    <small>
                      {badge.merchantAlias} · {badge.programLabel} · {badge.assetSymbol}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK PROVEN</span>
                </div>
                <p className={styles.badgeClaim}>
                  {badge.claim}
                  <small>{badge.jurisdictionSummary}</small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div>
                    <dt>Certificate</dt>
                    <dd>{shorten(badge.certificateId)}</dd>
                  </div>
                  <div>
                    <dt>Bit proofs</dt>
                    <dd>{badge.proofCount}</dd>
                  </div>
                  <div>
                    <dt>Payer</dt>
                    <dd>{badge.payerCommitted ? "Committed, hidden" : "Not committed"}</dd>
                  </div>
                  <div>
                    <dt>Issued</dt>
                    <dd>{formatDate(badge.createdAt)}</dd>
                  </div>
                </dl>
                <ul className={styles.badgeList}>
                  {badge.scheduleSummary.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
                <ul className={styles.badgeList}>
                  {badge.covenantSummary.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </div>

              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Certificate · safe to publish</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`${issued.certificate.certificateId}.json`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} aria-label="Serialized routing certificate" />
              </div>

              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Amount disclosure · opens one figure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`${issued.certificate.certificateId}-${amountField}.json`, amountDisclosure)}
                    disabled={!amountDisclosure}
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
                      onClick={() => setAmountField(field.value)}
                      disabled={amountField === field.value}
                    >
                      {field.label}
                    </button>
                  ))}
                </div>
                <textarea readOnly value={amountDisclosure} aria-label="Amount disclosure payload" />
                <p className={styles.warn}>
                  The schedule is public, so opening any single payout lets the holder derive the gross and every other
                  payout. Only the rounding remainder leaks nothing on its own.
                </p>
              </div>

              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Recipient disclosure · opens one reference</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() =>
                      download(`${issued.certificate.certificateId}-recipient${recipientSlot}.json`, recipientDisclosure)
                    }
                    disabled={!recipientDisclosure}
                  >
                    Download
                  </button>
                </div>
                <div className={styles.discGrid}>
                  {REVENUE_ROUTING_SLOTS.map((slot, index) => (
                    <button
                      key={slot.key}
                      type="button"
                      className={styles.ghost}
                      onClick={() => setRecipientSlot(index)}
                      disabled={recipientSlot === index}
                    >
                      {slot.label}
                    </button>
                  ))}
                </div>
                <textarea readOnly value={recipientDisclosure} aria-label="Recipient disclosure payload" />
              </div>

              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Agreement reference · discloses the hidden label</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => setRevealAgreement((v) => !v)}
                    disabled={!agreementDisclosure}
                  >
                    {revealAgreement ? "Hide" : "Reveal"}
                  </button>
                </div>
                {revealAgreement && agreementDisclosure ? (
                  <textarea readOnly value={agreementDisclosure} aria-label="Agreement reference disclosure" />
                ) : (
                  <p className={styles.warn}>
                    {agreementDisclosure
                      ? "Hidden. Revealing opens the agreement reference to whoever receives this payload."
                      : "No agreement reference was committed to this certificate."}
                  </p>
                )}
              </div>

              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Payer reference · discloses the hidden label</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => setRevealPayer((v) => !v)}
                    disabled={!payerDisclosure}
                  >
                    {revealPayer ? "Hide" : "Reveal"}
                  </button>
                </div>
                {revealPayer && payerDisclosure ? (
                  <textarea readOnly value={payerDisclosure} aria-label="Payer reference disclosure" />
                ) : (
                  <p className={styles.warn}>
                    {payerDisclosure
                      ? "Hidden. Revealing opens the payer reference to whoever receives this payload."
                      : "No payer reference was committed to this certificate."}
                  </p>
                )}
              </div>

              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Opening material · SECRET, never publish</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>
                      {revealSecret ? "Hide" : "Reveal"}
                    </button>
                    <button
                      type="button"
                      className={styles.ghost}
                      onClick={() => download(`${issued.certificate.certificateId}-secret.json`, serializedSecret)}
                      disabled={!revealSecret}
                    >
                      Download
                    </button>
                  </div>
                </div>
                {revealSecret ? (
                  <textarea readOnly value={serializedSecret} aria-label="Certificate opening material" />
                ) : (
                  <p className={styles.warn}>
                    Hidden by default. This payload holds the gross, all six payouts, the remainder, every blinding, and
                    every recipient reference — publishing it opens the entire certificate. Keep it with the issuer key
                    and disclose single fields with the buttons above instead.
                  </p>
                )}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>
              Nothing has been issued in this tab yet. Generate an issuer key, set the schedule and covenants, then issue
              a certificate — the badge, the publishable certificate, and the selective-disclosure payloads appear here.
            </p>
          )}
        </section>
      </div>

      <form className={styles.verify} onSubmit={handleVerify}>
        <div className={styles.panelHead}>
          <span>03 · Verify as a counterparty</span>
          <h3>Audit a certificate you did not issue</h3>
        </div>
        <p className={styles.hint}>
          Paste a certificate to re-run all {REVENUE_ROUTING_CHECK_COUNT} checks offline: the envelope, the published
          schedule, the issuer signature, the conservation identity, every bit proof, the exact-floor legs, and the four
          covenant surpluses. Optionally paste one disclosure payload to test it against the same certificate.
        </p>
        <textarea
          value={verifyInput}
          onChange={(event) => setVerifyInput(event.target.value)}
          placeholder="Paste a revenue routing certificate JSON payload"
          aria-label="Certificate to verify"
        />
        <textarea
          value={disclosureInput}
          onChange={(event) => setDisclosureInput(event.target.value)}
          placeholder="Optional: paste one amount or reference disclosure payload"
          aria-label="Disclosure payload to check"
        />
        <button type="submit">Verify certificate</button>
        {verifyResult ? (
          verifyResult.error ? (
            <div className={styles.fail}>
              <strong>Unreadable</strong>
              <small>{verifyResult.error}</small>
            </div>
          ) : (
            <div className={verifyResult.ok ? styles.pass : styles.fail}>
              <strong>{verifyResult.ok ? "Certificate verifies" : "Certificate does not verify"}</strong>
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
                <ul className={styles.checkList}>
                  {verifyResult.checks.map((check) => (
                    <li key={check.label} className={check.passed ? styles.checkOk : styles.checkBad}>
                      <b>{check.label}</b>
                      {check.detail}
                    </li>
                  ))}
                </ul>
              ) : null}
              {verifyResult.disclosure ? (
                <ul className={styles.checkList}>
                  <li className={verifyResult.disclosure.ok ? styles.checkOk : styles.checkBad}>
                    <b>Disclosure · {verifyResult.disclosure.type}</b>
                    {verifyResult.disclosure.ok
                      ? `Opens against this certificate: ${verifyResult.disclosure.value}`
                      : verifyResult.disclosure.value}
                  </li>
                </ul>
              ) : null}
              <small>
                {verifyResult.ok
                  ? "The arithmetic is sound and the issuer signature authenticates. That says nothing about whether the gross, the payouts, or the recipients are real, whether any settlement arrived, or whether a single unit was ever routed — no value moved, and the pool contract was never called."
                  : "At least one check failed, so this payload is not a sound revenue routing attestation. A failure can also mean the payload was edited after issuing."}
              </small>
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
          <h4>Never leaves this tab</h4>
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
          <ul>
            {TRUST.proven.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>What it does not do</h4>
          <ul>
            {TRUST.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <h4>Reading the model</h4>
          <p>{VISIBILITY.limitation}</p>
          <p>{TRUST.zeroKnowledgeElement}</p>
          <p>
            Verification runs from the certificate alone — no prover service, no relayer, no RPC, and no network call of
            any kind.
          </p>
          <p className={styles.statement}>{TRUST.statement}</p>
        </div>
      </section>
    </div>
  );
}
