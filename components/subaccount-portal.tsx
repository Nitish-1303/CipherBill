"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  MAX_SUBACCOUNT_DEPARTMENTS,
  SUBACCOUNT_POOL_ADDRESS,
  buildSubaccountCertificateBadge,
  buildSubaccountDepartmentDisclosure,
  buildSubaccountEnterpriseDisclosure,
  buildSubaccountLabelDisclosure,
  buildSubaccountMetricDisclosure,
  computeSubaccountState,
  createSubaccountIssuerKey,
  formatSubaccountBaseUnits,
  formatSubaccountBps,
  getSubaccountVisibilityModel,
  issueSubaccountCertificate,
  parseSubaccountCertificate,
  parseSubaccountDepartmentDisclosure,
  parseSubaccountLabelDisclosure,
  parseSubaccountMetricDisclosure,
  parseSubaccountRefDisclosure,
  serializeSubaccountCertificate,
  serializeSubaccountCertificateSecret,
  serializeSubaccountDepartmentDisclosure,
  serializeSubaccountLabelDisclosure,
  serializeSubaccountMetricDisclosure,
  serializeSubaccountRefDisclosure,
  summarizeSubaccountTrust,
  verifySubaccountCertificate,
  verifySubaccountDepartmentDisclosure,
  verifySubaccountLabelDisclosure,
  verifySubaccountMetricDisclosure,
  verifySubaccountRefDisclosure,
  type IssuedSubaccountCertificate,
  type SubaccountCertificate,
  type SubaccountKeypair,
  type SubaccountLedger,
} from "@/lib/subaccount-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./subaccount-portal.module.css";

const INTRO =
  "Prove in zero knowledge that an enterprise's hidden departmental budget allocations aggregate into a total that does not exceed a public budget cap, and that every department's hidden spend is at most its own hidden allocation — no cost centre overspends — without revealing any department's allocation, its spend, its cost-centre label, or any aggregate. Each department is committed separately; a homomorphic sum proves the cap, and each department's headroom is proven from A_i − S_i. The enterprise signs the certificate so anyone can authenticate it offline, and any figure can be selectively disclosed later. Allocations and spends are enterprise-supplied figures the proof binds — this does not move, allocate, partition, or disburse funds, create or fund any sub-account, enforce any spending limit, reduce gas, or call the STRK20 pool contract; the pool address is provenance only, and it is neither decentralized nor financial advice.";

const TRUST = summarizeSubaccountTrust();
const VISIBILITY = getSubaccountVisibilityModel();

interface DeptRow {
  label: string;
  allocation: string;
  spend: string;
}

const DEFAULT_DEPTS: DeptRow[] = [
  { label: "Engineering", allocation: "30000", spend: "18500" },
  { label: "Marketing", allocation: "15000", spend: "9200" },
  { label: "Operations", allocation: "8000", spend: "8000" },
];

const DEFAULT_BUDGET_CAP = "60000";

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

/** Converts a decimal amount to base units, mapping an explicit zero to "0". Allocations, spends,
 *  and the budget cap may legitimately be zero, but decimalToBaseUnits rejects "0" — route it around. */
function toBaseUnitsAllowingZero(value: string, decimals: number): string {
  const trimmed = value.trim();
  if (trimmed === "" || /^0(?:\.0+)?$/.test(trimmed)) return "0";
  return decimalToBaseUnits(trimmed, decimals);
}

/** Builds the private departmental ledger (allocations and spends in base units) from the editor rows. */
function buildLedger(depts: DeptRow[], decimals: number): SubaccountLedger {
  return {
    departments: depts.map((d) => ({
      label: d.label.trim() || undefined,
      allocationBaseUnits: toBaseUnitsAllowingZero(d.allocation, decimals),
      spendBaseUnits: toBaseUnitsAllowingZero(d.spend, decimals),
    })),
  };
}

interface DisclosureResult {
  label: string;
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  certificate?: SubaccountCertificate;
  disclosure?: DisclosureResult;
  error?: string;
}

export function SubaccountPortal() {
  const [issuer, setIssuer] = useState<SubaccountKeypair | null>(null);
  const [revealSecretKey, setRevealSecretKey] = useState(false);

  const [enterpriseAlias, setEnterpriseAlias] = useState("Acme Robotics");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [periodLabel, setPeriodLabel] = useState("FY26 Q3");
  const [programLabel, setProgramLabel] = useState("Departmental Operating Budget");
  const [budgetCap, setBudgetCap] = useState(DEFAULT_BUDGET_CAP);
  const [enterpriseRef, setEnterpriseRef] = useState("member:acme-holdings-0xabc");
  const [memo, setMemo] = useState("Q3 governance attestation");
  const [depts, setDepts] = useState<DeptRow[]>(DEFAULT_DEPTS);

  const [issued, setIssued] = useState<IssuedSubaccountCertificate | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealEnterprise, setRevealEnterprise] = useState(false);

  const [verifyInput, setVerifyInput] = useState("");
  const [disclosureInput, setDisclosureInput] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyState | null>(null);

  const decimals = useMemo(() => {
    const parsed = Number.parseInt(assetDecimals, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 18 ? parsed : 18;
  }, [assetDecimals]);

  const preview = useMemo(() => {
    try {
      return computeSubaccountState(buildLedger(depts, decimals), toBaseUnitsAllowingZero(budgetCap, decimals));
    } catch {
      return null;
    }
  }, [depts, budgetCap, decimals]);

  const badge = useMemo(() => (issued ? buildSubaccountCertificateBadge(issued.certificate) : null), [issued]);
  const serializedCertificate = useMemo(() => (issued ? serializeSubaccountCertificate(issued.certificate) : ""), [issued]);
  const serializedSecret = useMemo(() => (issued ? serializeSubaccountCertificateSecret(issued.secret) : ""), [issued]);
  const allocatedDisclosure = useMemo(
    () => (issued ? serializeSubaccountMetricDisclosure(buildSubaccountMetricDisclosure(issued.secret, "allocated")) : ""),
    [issued],
  );
  const spentDisclosure = useMemo(
    () => (issued ? serializeSubaccountMetricDisclosure(buildSubaccountMetricDisclosure(issued.secret, "spent")) : ""),
    [issued],
  );
  const departmentDisclosures = useMemo(
    () =>
      issued
        ? issued.secret.allocationsBaseUnits.map((_, i) => ({
            index: i,
            allocation: serializeSubaccountDepartmentDisclosure(buildSubaccountDepartmentDisclosure(issued.secret, i, "allocated")),
            spend: serializeSubaccountDepartmentDisclosure(buildSubaccountDepartmentDisclosure(issued.secret, i, "spent")),
            label: issued.secret.labelsCommitted[i]
              ? serializeSubaccountLabelDisclosure(buildSubaccountLabelDisclosure(issued.secret, i))
              : "",
          }))
        : [],
    [issued],
  );
  const enterpriseDisclosure = useMemo(
    () => (issued && issued.certificate.enterpriseCommitted ? serializeSubaccountRefDisclosure(buildSubaccountEnterpriseDisclosure(issued.secret)) : ""),
    [issued],
  );

  function updateDept(index: number, key: keyof DeptRow, value: string) {
    setDepts((rows) => rows.map((row, i) => (i === index ? { ...row, [key]: value } : row)));
  }

  function addDept() {
    setDepts((list) => (list.length >= MAX_SUBACCOUNT_DEPARTMENTS ? list : [...list, { label: "", allocation: "0", spend: "0" }]));
  }

  function removeDept(index: number) {
    setDepts((list) => (list.length <= 1 ? list : list.filter((_, i) => i !== index)));
  }

  function generateIssuerKey() {
    setIssuer(createSubaccountIssuerKey());
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
    setRevealEnterprise(false);
    // Defer so the "Proving in zero knowledge…" label paints before the synchronous proof blocks the thread.
    setTimeout(() => {
      try {
        const result = issueSubaccountCertificate({
          enterpriseAlias,
          asset: { symbol: assetSymbol, tokenAddress, decimals },
          periodLabel,
          programLabel,
          budgetCapBaseUnits: toBaseUnitsAllowingZero(budgetCap, decimals),
          ledger: buildLedger(depts, decimals),
          enterpriseRef: enterpriseRef.trim() || undefined,
          issuerSecretKey: issuer.secretKey,
          memo: memo.trim() || undefined,
        });
        setIssued(result);
      } catch (error) {
        setIssueError(error instanceof Error ? error.message : "Failed to issue the sub-account certificate.");
      } finally {
        setIssuing(false);
      }
    }, 40);
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parseSubaccountCertificate(verifyInput.trim());
      const ok = verifySubaccountCertificate(certificate);
      let disclosure: DisclosureResult | undefined;
      const raw = disclosureInput.trim();
      if (raw) disclosure = evaluateDisclosure(certificate, raw);
      setVerifyResult({ ok, certificate, disclosure });
    } catch (error) {
      setVerifyResult({ ok: false, error: error instanceof Error ? error.message : "The certificate could not be parsed." });
    }
  }

  /** Detects the disclosure kind, verifies it against the certificate, and formats the opened figure. */
  function evaluateDisclosure(certificate: SubaccountCertificate, raw: string): DisclosureResult {
    const asAmount = (value: string) => `${formatSubaccountBaseUnits(value, certificate.assetDecimals)} ${certificate.assetSymbol}`;
    try {
      const metric = parseSubaccountMetricDisclosure(raw);
      return {
        label: metric.metric === "allocated" ? "Aggregate allocated" : "Aggregate spent",
        ok: verifySubaccountMetricDisclosure(certificate, metric),
        value: asAmount(metric.valueBaseUnits),
      };
    } catch {
      /* not a metric disclosure */
    }
    try {
      const dept = parseSubaccountDepartmentDisclosure(raw);
      return {
        label: `Department ${dept.departmentIndex + 1} ${dept.field}`,
        ok: verifySubaccountDepartmentDisclosure(certificate, dept),
        value: asAmount(dept.valueBaseUnits),
      };
    } catch {
      /* not a department disclosure */
    }
    try {
      const label = parseSubaccountLabelDisclosure(raw);
      return {
        label: `Department ${label.departmentIndex + 1} cost centre`,
        ok: verifySubaccountLabelDisclosure(certificate, label),
        value: label.value || "(empty)",
      };
    } catch {
      /* not a label disclosure */
    }
    try {
      const ref = parseSubaccountRefDisclosure(raw);
      return {
        label: "Enterprise reference",
        ok: verifySubaccountRefDisclosure(certificate, ref),
        value: ref.value || "(empty)",
      };
    } catch {
      /* not any recognized disclosure kind */
    }
    // Keep the certificate verdict intact: report only that the disclosure box held nothing we recognize.
    return { label: "Unrecognized disclosure", ok: false, value: "not a recognized selective-disclosure payload" };
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Departmental budget governance</span>
          <h2>
            Prove a budget fits <em>hidden allocations</em>.
          </h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(SUBACCOUNT_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div>
            <dt>Allocations fit a public budget cap</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>No department overspends its allocation</dt>
            <dd className={styles.yes}>ZK proven</dd>
          </div>
          <div>
            <dt>Moves, allocates, or funds any sub-account</dt>
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
          <span>Budget standing</span>
          <small>Deterministic heuristic · figures are enterprise-supplied and unverified — this moves no funds and calls no contract</small>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={`${styles.metric} ${styles.index}`}>
                <dt>Departments</dt>
                <dd>{preview.departmentCount}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Allocated</dt>
                <dd>
                  {formatSubaccountBaseUnits(preview.totalAllocatedBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Spent</dt>
                <dd>
                  {formatSubaccountBaseUnits(preview.totalSpentBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
              <div className={styles.metric}>
                <dt>Unallocated headroom</dt>
                <dd>
                  {formatSubaccountBaseUnits(preview.unallocatedBaseUnits, decimals)} {assetSymbol}
                </dd>
              </div>
            </dl>
            <div className={styles.meterWrap}>
              <div className={styles.meterHead}>
                <span>
                  {preview.fitsBudget ? "Allocations fit the budget cap" : "Allocations exceed the budget cap"} ·{" "}
                  {formatSubaccountBaseUnits(preview.budgetCapBaseUnits, decimals)} {assetSymbol} cap
                </span>
                <span>{(Number(preview.budgetUtilizationBps) / 100).toFixed(1)}%</span>
              </div>
              <div
                className={styles.meter}
                role="progressbar"
                aria-valuenow={Number(preview.budgetUtilizationBps) / 100}
                aria-valuemin={0}
                aria-valuemax={100}
              >
                <span style={{ width: `${Math.min(100, Number(preview.budgetUtilizationBps) / 100)}%` }} />
              </div>
              <p className={styles.hint}>
                Budget utilization = floor(total allocated · 10000 / cap). Computed in your browser; the proof binds the
                aggregate to the public cap without revealing it.
              </p>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.jurTable}>
                <thead>
                  <tr>
                    <th>Department</th>
                    <th>Allocation</th>
                    <th>Spent</th>
                    <th>Headroom</th>
                    <th>Utilization</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.departments.map((row) => (
                    <tr key={row.index}>
                      <td>{row.label || `Department ${row.index + 1}`}</td>
                      <td>
                        {formatSubaccountBaseUnits(row.allocationBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td>
                        {formatSubaccountBaseUnits(row.spendBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td>
                        {formatSubaccountBaseUnits(row.headroomBaseUnits, decimals)} {assetSymbol}
                      </td>
                      <td>{formatSubaccountBps(row.utilizationBps)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <p className={styles.placeholder}>
            Enter a public budget cap and at least one department whose spend does not exceed its allocation and whose
            allocations sum within the cap, to preview utilization, headroom, and per-department standing. Every figure
            stays in your browser.
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
            <h3>Attest a budget over hidden departments</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>
              Enterprise alias
              <input value={enterpriseAlias} onChange={(e) => setEnterpriseAlias(e.target.value)} />
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
              Budget cap <small>public</small>
              <input value={budgetCap} onChange={(e) => setBudgetCap(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Enterprise reference <small>committed, optional</small>
              <input value={enterpriseRef} onChange={(e) => setEnterpriseRef(e.target.value)} />
            </label>
            <label className={styles.wide}>
              Memo <small>public, optional</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} />
            </label>
          </div>
          <div className={styles.subSection}>
            <div className={styles.subHead}>
              <span>Hidden departmental ledger</span>
              <button type="button" className={styles.ghost} onClick={addDept} disabled={depts.length >= MAX_SUBACCOUNT_DEPARTMENTS}>
                + Add department
              </button>
            </div>
            <div className={styles.tierEditor}>
              {depts.map((row, i) => (
                <div className={styles.tierEditRow} key={`dept-${i}`}>
                  <input aria-label={`Department ${i + 1} label`} value={row.label} onChange={(e) => updateDept(i, "label", e.target.value)} placeholder="Cost centre (optional)" />
                  <input aria-label={`Department ${i + 1} allocation`} value={row.allocation} onChange={(e) => updateDept(i, "allocation", e.target.value)} inputMode="decimal" placeholder="Allocation" />
                  <input aria-label={`Department ${i + 1} spend`} value={row.spend} onChange={(e) => updateDept(i, "spend", e.target.value)} inputMode="decimal" placeholder="Spent" />
                  <button type="button" className={styles.ghost} onClick={() => removeDept(i)} disabled={depts.length <= 1} aria-label={`Remove department ${i + 1}`}>
                    ×
                  </button>
                </div>
              ))}
            </div>
            <p className={styles.hint}>
              Each department is committed and range-proven separately — allocation, spend, and a no-overspend headroom
              leg — so proving time grows with the department count and the value bit-width. A handful of departments
              keeps the in-browser proof responsive.
            </p>
          </div>
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={issuing}>
            {issuing ? "Proving in zero knowledge…" : "Issue sub-account certificate"}
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
                    <strong>{badge.enterpriseAlias}</strong>
                    <small>
                      {badge.programLabel} · {badge.periodLabel}
                    </small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  <b>{badge.departmentCount}</b> hidden departments
                  <small>
                    under a {badge.budgetCapDisplay} cap · issued {formatDate(badge.createdAt)}
                  </small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div>
                    <dt>Budget cap</dt>
                    <dd>{badge.budgetCapDisplay}</dd>
                  </div>
                  <div>
                    <dt>Departments</dt>
                    <dd>{badge.departmentCount}</dd>
                  </div>
                  <div>
                    <dt>Enterprise ref</dt>
                    <dd>{badge.enterpriseCommitted ? "Committed" : "Not committed"}</dd>
                  </div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Serialized certificate</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`subaccount-certificate-${issued.certificate.certificateId}.txt`, serializedCertificate)}
                  >
                    Download
                  </button>
                </div>
                <textarea readOnly value={serializedCertificate} spellCheck={false} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Aggregate-allocated disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`subaccount-allocated-${issued.certificate.certificateId}.txt`, allocatedDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <p className={styles.hint}>Opens only the total allocated against the summed allocation commitments; each department stays hidden.</p>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Aggregate-spent disclosure</span>
                  <button
                    type="button"
                    className={styles.ghost}
                    onClick={() => download(`subaccount-spent-${issued.certificate.certificateId}.txt`, spentDisclosure)}
                  >
                    Download
                  </button>
                </div>
                <p className={styles.hint}>Opens only the total spent against the summed spend commitments; each department stays hidden.</p>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Per-department disclosures</span>
                </div>
                {departmentDisclosures.map((d) => (
                  <div className={styles.exportHead} key={d.index}>
                    <span>Department {d.index + 1}</span>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`subaccount-dept-${d.index + 1}-allocation-${issued.certificate.certificateId}.txt`, d.allocation)}
                      >
                        Allocation
                      </button>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`subaccount-dept-${d.index + 1}-spend-${issued.certificate.certificateId}.txt`, d.spend)}
                      >
                        Spend
                      </button>
                      {d.label ? (
                        <button
                          type="button"
                          className={styles.ghost}
                          onClick={() => download(`subaccount-dept-${d.index + 1}-label-${issued.certificate.certificateId}.txt`, d.label)}
                        >
                          Label
                        </button>
                      ) : null}
                    </div>
                  </div>
                ))}
                <p className={styles.hint}>Each payload opens exactly one department&apos;s allocation, spend, or cost-centre label; the others stay hidden.</p>
              </div>
              {issued.certificate.enterpriseCommitted ? (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Enterprise-reference disclosure</span>
                    <button type="button" className={styles.ghost} onClick={() => setRevealEnterprise((v) => !v)}>
                      {revealEnterprise ? "Hide" : "Reveal"}
                    </button>
                  </div>
                  {revealEnterprise ? (
                    <>
                      <p className={styles.warn}>Opens the committed enterprise reference. Share only with the counterparty.</p>
                      <textarea readOnly value={enterpriseDisclosure} spellCheck={false} />
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
                      Contains every department&apos;s allocation and spend, both aggregates, all blindings, and the
                      enterprise-reference salt. Never publish or commit it — hand it only to a counterparty you are
                      opening every figure to.
                    </p>
                    <div className={styles.secretActions}>
                      <button
                        type="button"
                        className={styles.ghost}
                        onClick={() => download(`subaccount-secret-${issued.certificate.certificateId}.txt`, serializedSecret)}
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
              department allocation, spend, cost-centre label, nor either aggregate ever appears in the certificate.
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
              placeholder="Paste a serialized sub-account certificate"
              spellCheck={false}
            />
          </label>
          <label className={styles.toggle}>
            Optional disclosure <small>an aggregate, department, label, or enterprise-reference payload</small>
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
                      <dt>Enterprise</dt>
                      <dd>{verifyResult.certificate.enterpriseAlias}</dd>
                    </div>
                    <div>
                      <dt>Budget cap</dt>
                      <dd>
                        {formatSubaccountBaseUnits(verifyResult.certificate.budgetCapBaseUnits, verifyResult.certificate.assetDecimals)}{" "}
                        {verifyResult.certificate.assetSymbol}
                      </dd>
                    </div>
                    <div>
                      <dt>Departments</dt>
                      <dd>{verifyResult.certificate.departmentCount}</dd>
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





