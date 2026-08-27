"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  PAYROLL_POOL_ADDRESS,
  buildPayrollAmountDisclosure,
  buildPayrollEmployeeDisclosure,
  computePayrollBatchState,
  createPayrollIssuerKey,
  formatPayrollBaseUnits,
  getPayrollVisibilityModel,
  issuePayrollBatchCertificate,
  monitorPayrollBatch,
  parsePayrollBatchCertificate,
  serializePayrollBatchCertificate,
  serializePayrollBatchSecret,
  summarizePayrollTrust,
  verifyPayrollBatchCertificate,
  type IssuedPayrollBatchCertificate,
  type PayeeKind,
  type PayrollKeypair,
  type PayrollPayeeInput,
} from "@/lib/payroll-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./payroll-portal.module.css";

const INTRO =
  "Attest encrypted salary and contractor milestone batches with Pedersen commitments while hiding payee identities, line amounts, and departmental totals. " +
  "Public schedule and policy caps only — the pool address is provenance and never called.";

const TRUST = summarizePayrollTrust();
const VISIBILITY = getPayrollVisibilityModel();

interface PayeeDraft {
  id: string;
  employeeRef: string;
  amount: string;
  payeeKind: PayeeKind;
}

const DEFAULT_PAYEES: PayeeDraft[] = [
  { id: "p1", employeeRef: "emp_alice", amount: "1200", payeeKind: "employee" },
  { id: "p2", employeeRef: "emp_bob", amount: "800", payeeKind: "employee" },
  { id: "p3", employeeRef: "ctr_carol", amount: "500", payeeKind: "contractor" },
];

function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function toPayeeInputs(drafts: PayeeDraft[], decimals: number): PayrollPayeeInput[] {
  return drafts.map((row) => ({
    employeeRef: row.employeeRef.trim(),
    amountBaseUnits: decimalToBaseUnits(row.amount.trim(), decimals),
    payeeKind: row.payeeKind,
  }));
}

export function PayrollPortal() {
  const [issuer, setIssuer] = useState<PayrollKeypair | null>(null);
  const [organizationAlias, setOrganizationAlias] = useState("Northwind Labs");
  const [departmentLabel, setDepartmentLabel] = useState("Engineering");
  const [payPeriodLabel, setPayPeriodLabel] = useState("2026-08");
  const [disbursementDate, setDisbursementDate] = useState("2026-08-28");
  const [maxPayeeAmount, setMaxPayeeAmount] = useState("2000");
  const [maxBatchTotal, setMaxBatchTotal] = useState("5000");
  const [maxContractorShareBps, setMaxContractorShareBps] = useState("4000");
  const [assetDecimals, setAssetDecimals] = useState("18");
  const [payees, setPayees] = useState<PayeeDraft[]>(DEFAULT_PAYEES);
  const [issued, setIssued] = useState<IssuedPayrollBatchCertificate | null>(null);
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
      maxPayeeAmountBaseUnits: decimalToBaseUnits(maxPayeeAmount, decimals),
      maxBatchTotalBaseUnits: decimalToBaseUnits(maxBatchTotal, decimals),
      maxContractorShareBps: Number.parseInt(maxContractorShareBps, 10) || 0,
    }),
    [maxPayeeAmount, maxBatchTotal, maxContractorShareBps, decimals],
  );

  const preview = useMemo(() => {
    try {
      const inputs = toPayeeInputs(payees, decimals);
      return computePayrollBatchState(inputs, policy);
    } catch {
      return null;
    }
  }, [payees, policy, decimals]);

  const monitorRows = useMemo(() => {
    if (!issued) return [];
    return monitorPayrollBatch(issued.certificate, issued.secret);
  }, [issued]);

  function generateIssuerKey() {
    setIssuer(createPayrollIssuerKey());
  }

  function updatePayee(id: string, patch: Partial<PayeeDraft>) {
    setPayees((rows) => rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  function addPayee() {
    if (payees.length >= 4) return;
    setPayees((rows) => [...rows, { id: `p${rows.length + 1}`, employeeRef: "", amount: "0", payeeKind: "employee" }]);
  }

  async function handleIssue(event: FormEvent) {
    event.preventDefault();
    if (!issuer || !preview?.eligible || issuing) return;
    setIssuing(true);
    setIssueError(null);
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    try {
      const next = issuePayrollBatchCertificate({
        organizationAlias,
        departmentLabel,
        asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals },
        schedule: {
          payPeriodLabel,
          disbursementDate: new Date(`${disbursementDate}T00:00:00.000Z`).toISOString(),
        },
        policy,
        payees: toPayeeInputs(payees, decimals),
        issuerSecretKey: issuer.secretKey,
        amountBitLength: 64,
      });
      setIssued(next);
      setVerifyInput(serializePayrollBatchCertificate(next.certificate));
      setVerifyOk(true);
    } catch (error) {
      setIssueError(error instanceof Error ? error.message : "Batch certificate could not be issued.");
    } finally {
      setIssuing(false);
    }
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const certificate = parsePayrollBatchCertificate(verifyInput);
      setVerifyOk(verifyPayrollBatchCertificate(certificate));
    } catch {
      setVerifyOk(false);
    }
  }

  return (
    <div className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Enterprise payroll · contractor payouts</span>
          <h2>
            Batch salaries.
            <br />
            <em>Hidden lines.</em>
          </h2>
          <p>{INTRO}</p>
          <p className={styles.provenance}>Pool provenance · {PAYROLL_POOL_ADDRESS}</p>
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
            <dt>Automated disbursement</dt>
            <dd className={styles.no}>{TRUST.automated ? "Yes" : "No"}</dd>
          </div>
        </dl>
      </header>

      <section className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Batch schedule preview</span>
        </div>
        {preview ? (
          <>
            <dl className={styles.dashGrid}>
              <div className={styles.metric}>
                <dt>Payees</dt>
                <dd>{preview.payeeCount}</dd>
              </div>
              <div className={styles.metric}>
                <dt>Hidden total</dt>
                <dd>{preview.totalBaseUnits} base units</dd>
              </div>
              <div className={styles.metric}>
                <dt>Contractor share</dt>
                <dd>{preview.contractorShareBps} bps</dd>
              </div>
              <div className={styles.metric}>
                <dt>Policy eligible</dt>
                <dd className={preview.eligible ? styles.statusOk : styles.statusWarn}>{preview.eligible ? "Yes" : "No"}</dd>
              </div>
            </dl>
            <p className={styles.hint}>
              Disbursement {formatDate(new Date(`${disbursementDate}T00:00:00.000Z`).toISOString())} · batch surplus {preview.batchSurplus} base units
              (hidden until disclosed).
            </p>
          </>
        ) : (
          <p className={styles.placeholder}>Configure payees and policy caps to preview the batch.</p>
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
            <h4>Public key — embed in batch certificates for offline authentication</h4>
            <dl>
              <dt>X</dt>
              <dd>{issuer.publicKey.x}</dd>
              <dt>Y</dt>
              <dd>{issuer.publicKey.y}</dd>
            </dl>
          </div>
        ) : (
          <p className={styles.placeholder}>Generate an issuer key before attesting a payroll batch.</p>
        )}
      </section>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Configure</span>
            <h3>Issue batch payroll certificate</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>
              Organization alias
              <input value={organizationAlias} onChange={(e) => setOrganizationAlias(e.target.value)} />
            </label>
            <label>
              Department <small>public label</small>
              <input value={departmentLabel} onChange={(e) => setDepartmentLabel(e.target.value)} />
            </label>
            <label>
              Pay period <small>public</small>
              <input value={payPeriodLabel} onChange={(e) => setPayPeriodLabel(e.target.value)} />
            </label>
            <label>
              Disbursement date
              <input value={disbursementDate} onChange={(e) => setDisbursementDate(e.target.value)} type="date" />
            </label>
            <label>
              Max payee amount <small>public cap</small>
              <input value={maxPayeeAmount} onChange={(e) => setMaxPayeeAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Max batch total <small>public cap</small>
              <input value={maxBatchTotal} onChange={(e) => setMaxBatchTotal(e.target.value)} inputMode="decimal" />
            </label>
            <label>
              Max contractor share (bps)
              <input value={maxContractorShareBps} onChange={(e) => setMaxContractorShareBps(e.target.value)} inputMode="numeric" />
            </label>
            <label>
              Asset decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" />
            </label>
          </div>
          <div className={styles.fields}>
            {payees.map((row) => (
              <div key={row.id} className={`${styles.payeeRow} ${styles.wide}`}>
                <label>
                  Employee ref <small>hidden</small>
                  <input value={row.employeeRef} onChange={(e) => updatePayee(row.id, { employeeRef: e.target.value })} />
                </label>
                <label>
                  Kind
                  <select value={row.payeeKind} onChange={(e) => updatePayee(row.id, { payeeKind: e.target.value as PayeeKind })}>
                    <option value="employee">Employee</option>
                    <option value="contractor">Contractor</option>
                  </select>
                </label>
                <label>
                  Amount <small>hidden</small>
                  <input value={row.amount} onChange={(e) => updatePayee(row.id, { amount: e.target.value })} inputMode="decimal" />
                </label>
              </div>
            ))}
          </div>
          {payees.length < 4 ? (
            <button type="button" className={styles.ghost} onClick={addPayee}>
              Add payee line
            </button>
          ) : null}
          {issueError ? <p className={styles.error}>{issueError}</p> : null}
          <button type="submit" disabled={!issuer || !preview?.eligible || issuing}>
            {issuing ? "Issuing proofs…" : "Issue payroll certificate"}
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
            <span>Payout verification monitor</span>
          </div>
          <div className={styles.tableWrap}>
            <table className={styles.jurTable}>
              <thead>
                <tr>
                  <th>Ref</th>
                  <th>Kind</th>
                  <th>Amount</th>
                  <th>Disbursement</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {monitorRows.map((row) => (
                  <tr key={row.payeeIndex}>
                    <td>{row.employeeLabel}</td>
                    <td>{row.payeeKind}</td>
                    <td>{row.amountDisplay}</td>
                    <td>{formatDate(row.disbursementDate)}</td>
                    <td className={row.status === "ready" ? styles.statusOk : styles.statusWarn}>{row.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className={styles.badge}>
            <div className={styles.badgeTop}>
              <div>
                <strong>{issued.certificate.organizationAlias}</strong>
                <small>{issued.certificate.departmentLabel}</small>
              </div>
              <span className={styles.verified}>Verified batch</span>
            </div>
            <dl className={styles.badgeMeta}>
              <div>
                <dt>Pay period</dt>
                <dd>{issued.certificate.schedule.payPeriodLabel}</dd>
              </div>
              <div>
                <dt>Payees</dt>
                <dd>{issued.certificate.payeeCount}</dd>
              </div>
              <div>
                <dt>Total (secret)</dt>
                <dd>{formatPayrollBaseUnits(issued.secret.totalBaseUnits, decimals)} STRK</dd>
              </div>
              <div>
                <dt>Sample disclosure</dt>
                <dd>{buildPayrollEmployeeDisclosure(issued.certificate, issued.secret, 0).employeeRef}</dd>
              </div>
            </dl>
            <div className={styles.export}>
              <textarea readOnly value={serializePayrollBatchCertificate(issued.certificate)} aria-label="Exported certificate" />
            </div>
            <div className={styles.secret}>
              <textarea readOnly value={serializePayrollBatchSecret(issued.secret)} aria-label="Issuer secret bundle" />
              <p className={styles.hint}>
                Amount disclosure sample: {buildPayrollAmountDisclosure(issued.certificate, issued.secret, 0).value} base units
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
