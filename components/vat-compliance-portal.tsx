"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  VAT_COMPLIANCE_POOL_ADDRESS,
  aggregateJurisdictionBreakdown,
  buildComplianceJurisdictionDisclosure,
  buildComplianceNetDisclosure,
  computeComplianceBatchState,
  createVatComplianceIssuerKey,
  formatComplianceBaseUnits,
  getComplianceJurisdictions,
  getVatComplianceVisibilityModel,
  issueVatComplianceCertificate,
  parseVatComplianceCertificate,
  serializeVatComplianceCertificate,
  serializeVatComplianceSecret,
  summarizeVatComplianceTrust,
  verifyVatComplianceCertificate,
  type ComplianceLineInput,
  type IssuedVatComplianceCertificate,
  type VatComplianceKeypair,
} from "@/lib/vat-compliance-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";

import styles from "./vat-compliance-portal.module.css";

const INTRO =
  "Attest multi-jurisdiction VAT/GST obligations over hidden invoice streams with Pedersen batch commitments and range proofs. " +
  "Customer regions and net amounts stay private; filing period and statutory rates per slot are public. Pool address is provenance only.";

const TRUST = summarizeVatComplianceTrust();
const VISIBILITY = getVatComplianceVisibilityModel();
const JURISDICTIONS = getComplianceJurisdictions();

interface LineDraft {
  id: string;
  jurisdictionCode: string;
  netBaseUnits: string;
  customerRegionRef: string;
}

const DEFAULT_LINES: LineDraft[] = [
  { id: "l1", jurisdictionCode: "GB", netBaseUnits: "1000", customerRegionRef: "eu-west-1" },
  { id: "l2", jurisdictionCode: "EU-DE", netBaseUnits: "800", customerRegionRef: "eu-central-1" },
  { id: "l3", jurisdictionCode: "SG", netBaseUnits: "500", customerRegionRef: "ap-southeast-1" },
];

function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function toLineInputs(drafts: LineDraft[]): ComplianceLineInput[] {
  return drafts.map((row) => ({
    jurisdictionCode: row.jurisdictionCode,
    netBaseUnits: row.netBaseUnits.trim(),
    customerRegionRef: row.customerRegionRef.trim(),
  }));
}

export function VatCompliancePortal() {
  const [issuer, setIssuer] = useState<VatComplianceKeypair | null>(null);
  const [merchantAlias, setMerchantAlias] = useState("Northwind Labs");
  const [filingPeriodLabel, setFilingPeriodLabel] = useState("2026-Q3");
  const [filingDueDate, setFilingDueDate] = useState("2026-10-31");
  const [maxNetPerLine, setMaxNetPerLine] = useState("2000");
  const [maxTotalTax, setMaxTotalTax] = useState("800");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [lines, setLines] = useState<LineDraft[]>(DEFAULT_LINES);
  const [issued, setIssued] = useState<IssuedVatComplianceCertificate | null>(null);
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
      maxNetPerLineBaseUnits: maxNetPerLine,
      maxTotalTaxBaseUnits: maxTotalTax,
    }),
    [maxNetPerLine, maxTotalTax],
  );

  const preview = useMemo(() => {
    try {
      return computeComplianceBatchState(toLineInputs(lines), policy);
    } catch {
      return null;
    }
  }, [lines, policy]);

  const breakdownRows = useMemo(() => {
    if (!issued) return [];
    return aggregateJurisdictionBreakdown(issued.certificate, issued.secret);
  }, [issued]);

  function generateIssuerKey() {
    setIssuer(createVatComplianceIssuerKey());
  }

  function updateLine(id: string, patch: Partial<LineDraft>) {
    setLines((rows) => rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  function addLine() {
    if (lines.length >= 4) return;
    setLines((rows) => [...rows, { id: `l${rows.length + 1}`, jurisdictionCode: "GB", netBaseUnits: "0", customerRegionRef: "" }]);
  }

  async function handleIssue(event: FormEvent) {
    event.preventDefault();
    if (!issuer || !preview?.eligible || issuing) return;
    setIssuing(true);
    setIssueError(null);
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    try {
      const next = issueVatComplianceCertificate({
        merchantAlias,
        asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals },
        filing: {
          filingPeriodLabel,
          filingDueDate: new Date(`${filingDueDate}T00:00:00.000Z`).toISOString(),
        },
        policy,
        lines: toLineInputs(lines),
        issuerSecretKey: issuer.secretKey,
        amountBitLength: 64,
      });
      setIssued(next);
      setVerifyInput(serializeVatComplianceCertificate(next.certificate));
      setVerifyOk(true);
    } catch (error) {
      setIssueError(error instanceof Error ? error.message : "Compliance certificate could not be issued.");
    } finally {
      setIssuing(false);
    }
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseVatComplianceCertificate(verifyInput);
      setVerifyOk(verifyVatComplianceCertificate(certificate));
    } catch {
      setVerifyOk(false);
    }
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Tax jurisdiction · VAT compliance</span>
          <h2>
            Filing proofs.
            <br />
            <em>Hidden streams.</em>
          </h2>
          <p>{INTRO}</p>
          <p className={styles.provenance}>Pool provenance · {VAT_COMPLIANCE_POOL_ADDRESS}</p>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Zero-knowledge proofs</dt>
            <dd className={TRUST.zeroKnowledge ? styles.yes : styles.no}>{TRUST.zeroKnowledge ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt>Authority filing integration</dt>
            <dd className={styles.no}>{TRUST.filesWithAuthority ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt>On-chain pool integration</dt>
            <dd className={styles.no}>{TRUST.poolIntegrated ? "Yes" : "No"}</dd>
          </div>
        </dl>
      </header>

      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Filing obligation preview</span>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={styles.metric}>
                <dt>Jurisdictions</dt>
                <dd>{preview.lineCount}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Hidden net total</dt>
                <dd>{preview.totalNetBaseUnits}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Hidden tax total</dt>
                <dd>{preview.totalTaxBaseUnits}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Policy eligible</dt>
                <dd className={preview.eligible ? styles.statusOk : styles.statusWarn}>{preview.eligible ? "Yes" : "No"}</dd>
              </div>
            </dl>
            <p className={styles.hint}>
              Due {formatDate(new Date(`${filingDueDate}T00:00:00.000Z`).toISOString())} · tax surplus {preview.taxSurplus} base units under cap.
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>Configure jurisdiction lines and policy caps to preview obligations.</p>
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
            <h4>Public key — embed in compliance certificates for offline authentication</h4>
            <dl>
              <dt>X</dt>
              <dd>{issuer.publicKey.x}</dd>
              <dt>Y</dt>
              <dd>{issuer.publicKey.y}</dd>
            </dl>
          </div>
        ) : (
          <p className={styles.placeholder}>Generate an issuer key before attesting a compliance batch.</p>
        )}
      </section>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Configure</span>
            <h3>Issue compliance certificate</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>
              Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} />
            </label>
            <label>
              Filing period <small>public</small>
              <input value={filingPeriodLabel} onChange={(e) => setFilingPeriodLabel(e.target.value)} />
            </label>
            <label>
              Filing due date
              <input value={filingDueDate} onChange={(e) => setFilingDueDate(e.target.value)} type="date" />
            </label>
            <label>
              Max net per line <small>public cap</small>
              <input value={maxNetPerLine} onChange={(e) => setMaxNetPerLine(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Max total tax <small>public cap</small>
              <input value={maxTotalTax} onChange={(e) => setMaxTotalTax(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Asset decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" />
            </label>
          </div>
          <div className={styles.fields}>
            {lines.map((row) => (
              <div key={row.id} className={`${styles.lineRow} ${styles.wide}`}>
                <label>
                  Jurisdiction <small>hidden until disclosed</small>
                  <select value={row.jurisdictionCode} onChange={(e) => updateLine(row.id, { jurisdictionCode: e.target.value })}>
                    {JURISDICTIONS.map((entry) => (
                      <option key={entry.code} value={entry.code}>
                        {entry.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Net base units <small>hidden</small>
                  <input value={row.netBaseUnits} onChange={(e) => updateLine(row.id, { netBaseUnits: e.target.value })} inputMode="numeric" />
                </label>
                <label>
                  Customer region <small>hidden</small>
                  <input value={row.customerRegionRef} onChange={(e) => updateLine(row.id, { customerRegionRef: e.target.value })} />
                </label>
              </div>
            ))}
          </div>
          {lines.length < 4 ? (
            <button type="button" className={styles.ghost} onClick={addLine}>
              Add jurisdiction line
            </button>
          ) : null}
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={!issuer || !preview?.eligible || issuing}>
            {issuing ? "Issuing proofs…" : "Issue compliance certificate"}
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
            <span>Jurisdiction breakdown</span>
          </div>
          <div className={styles.tableWrap}>
            <table className={styles.jurTable}>
              <thead>
                <tr>
                  <th>Jurisdiction</th>
                  <th>Kind</th>
                  <th>Rate</th>
                  <th>Net</th>
                  <th>Tax</th>
                  <th>Gross</th>
                  <th>Member</th>
                </tr>
              </thead>
              <tbody>
                {breakdownRows.map((row) => (
                  <tr key={row.lineIndex}>
                    <td>{row.jurisdictionLabel}</td>
                    <td>{row.taxKind}</td>
                    <td>{row.rateDisplay}</td>
                    <td>{row.netDisplay}</td>
                    <td>{row.taxDisplay}</td>
                    <td>{row.grossDisplay}</td>
                    <td className={row.membershipOk ? styles.statusOk : styles.statusWarn}>{row.membershipOk ? "ok" : "fail"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.badge}>
            <div className={styles.badgeTop}>
              <div>
                <strong>{issued.certificate.merchantAlias}</strong>
                <small>{issued.certificate.filing.filingPeriodLabel}</small>
              </div>
              <span className={styles.verified}>Verified filing</span>
            </div>
            <dl className={styles.badgeMeta}>
              <div>
                <dt>Due date</dt>
                <dd>{formatDate(issued.certificate.filing.filingDueDate)}</dd>
              </div>
              <div>
                <dt>Total tax (secret)</dt>
                <dd>{formatComplianceBaseUnits(issued.secret.totalTaxBaseUnits, decimals)} STRK</dd>
              </div>
              <div>
                <dt>Membership root</dt>
                <dd>{issued.certificate.membershipRoot.slice(0, 18)}…</dd>
              </div>
              <div>
                <dt>Sample disclosure</dt>
                <dd>{buildComplianceJurisdictionDisclosure(issued.certificate, issued.secret, 0).jurisdictionCode}</dd>
              </div>
            </dl>
            <div className={styles.export}>
              <textarea readOnly value={serializeVatComplianceCertificate(issued.certificate)} aria-label="Exported certificate" />
            </div>
            <div className={styles.secret}>
              <textarea readOnly value={serializeVatComplianceSecret(issued.secret)} aria-label="Issuer secret bundle" />
              <p className={styles.hint}>
                Net disclosure sample: {buildComplianceNetDisclosure(issued.certificate, issued.secret, 0).value} base units
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
