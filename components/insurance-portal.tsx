"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  authorizeInsuranceClaim,
  buildDirectClaimPayoutActions,
  buildDirectPremiumFundingActions,
  createDefaultClaim,
  createInsurancePolicy,
  generateInsuranceAuthorityKeypair,
  getInsuranceSecurityModel,
  INSURANCE_POOL_ADDRESS,
  serializePublicInsuranceCommitment,
  type InsuranceAuthorityKeypair,
  type InsuranceClaimAuthorization,
  type InsuranceClaimBundle,
  type InsuranceClaimReason,
  type InsurancePolicyBundle,
} from "@/lib/insurance-engine";
import { readInvoices, type LocalInvoiceRecord } from "@/lib/invoices";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress, baseUnitsToDecimal, decimalToBaseUnits } from "@/lib/strk20/validation";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

const DEFAULT_RESERVE_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000007701";
const DEFAULT_EVIDENCE_DIGEST = "sha256:replace_with_a_real_document_digest_000001";

type InsurancePhase = "quote" | "funded" | "claim" | "approved" | "paid";

export function InsurancePortal() {
  const { account, address, status: walletStatus, capabilities } = useWallet();
  const [invoices, setInvoices] = useState<LocalInvoiceRecord[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [authority, setAuthority] = useState<InsuranceAuthorityKeypair | null>(null);
  const [coveragePercent, setCoveragePercent] = useState(80);
  const [deductiblePercent, setDeductiblePercent] = useState(10);
  const [tenureDays, setTenureDays] = useState(400);
  const [successfulSettlements, setSuccessfulSettlements] = useState(20);
  const [lateSettlements, setLateSettlements] = useState(2);
  const [disputedSettlements, setDisputedSettlements] = useState(1);
  const [concentrationPercent, setConcentrationPercent] = useState(35);
  const [collateralPercent, setCollateralPercent] = useState(20);
  const [reserveAddress, setReserveAddress] = useState(DEFAULT_RESERVE_ADDRESS);
  const [capitalReserve, setCapitalReserve] = useState("100000");
  const [existingExposure, setExistingExposure] = useState("25000");
  const [minimumSolvencyPercent, setMinimumSolvencyPercent] = useState(150);
  const [graceDays, setGraceDays] = useState(7);
  const [claimWindowDays, setClaimWindowDays] = useState(30);
  const [policyBundle, setPolicyBundle] = useState<InsurancePolicyBundle | null>(null);
  const [premiumHash, setPremiumHash] = useState("");
  const [claimLoss, setClaimLoss] = useState("");
  const [claimReason, setClaimReason] = useState<InsuranceClaimReason>("nonpayment");
  const [evidenceDigests, setEvidenceDigests] = useState(DEFAULT_EVIDENCE_DIGEST);
  const [claim, setClaim] = useState<InsuranceClaimBundle | null>(null);
  const [authorization, setAuthorization] = useState<InsuranceClaimAuthorization | null>(null);
  const [payoutHash, setPayoutHash] = useState("");
  const [message, setMessage] = useState("Select a local invoice and bind a private coverage proposal. Nothing is uploaded by this portal.");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => new Date());
  const submissionLock = useRef(false);

  useEffect(() => {
    const records = readInvoices();
    setInvoices(records);
    if (records[0]) {
      setSelectedId(records[0].invoice.invoiceId);
      setClaimLoss(records[0].invoice.amount);
    }
    setAuthority(generateInsuranceAuthorityKeypair());
    const timer = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(timer);
  }, []);

  const selected = useMemo(() => invoices.find((record) => record.invoice.invoiceId === selectedId) ?? null, [invoices, selectedId]);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const reserveWalletReady = Boolean(walletReady && address && policyBundle && areSameStarknetAddress(address, policyBundle.policy.insurerReserveAddress));
  const phase: InsurancePhase = payoutHash ? "paid" : authorization?.decision === "approved" ? "approved" : claim ? "claim" : premiumHash ? "funded" : "quote";
  const security = getInsuranceSecurityModel();

  function chooseInvoice(invoiceId: string): void {
    const record = invoices.find((item) => item.invoice.invoiceId === invoiceId);
    setSelectedId(invoiceId);
    setClaimLoss(record?.invoice.amount ?? "");
    resetPolicy("Invoice changed. Configure and calculate a new coverage proposal.");
  }

  function resetPolicy(nextMessage = "Coverage workspace reset."): void {
    setPolicyBundle(null);
    setPremiumHash("");
    setClaim(null);
    setAuthorization(null);
    setPayoutHash("");
    setMessage(nextMessage);
  }

  function calculatePolicy(event: React.FormEvent): void {
    event.preventDefault();
    if (!selected || !authority) return;
    try {
      const bundle = createInsurancePolicy({
        risk: {
          invoiceId: selected.invoice.invoiceId,
          invoicePrincipalBaseUnits: decimalToBaseUnits(selected.invoice.amount, selected.invoice.tokenDecimals),
          dueAt: selected.invoice.expiresAt,
          counterpartyTenureDays: tenureDays,
          successfulSettlements,
          lateSettlements,
          disputedSettlements,
          concentrationBps: concentrationPercent * 100,
          collateralBps: collateralPercent * 100,
        },
        pricing: {
          coverageBps: coveragePercent * 100,
          deductibleBps: deductiblePercent * 100,
          reserveLoadingBps: 2_500,
          protocolFeeBps: 50,
          capitalReserveBaseUnits: decimalToBaseUnits(capitalReserve, selected.invoice.tokenDecimals),
          existingPoolExposureBaseUnits: decimalToBaseUnits(existingExposure, selected.invoice.tokenDecimals),
          minimumSolvencyBps: minimumSolvencyPercent * 100,
          claimGracePeriodDays: graceDays,
          claimWindowDays,
        },
        tokenAddress: selected.invoice.tokenAddress,
        merchantPayoutAddress: selected.invoice.recipientAddress,
        insurerReserveAddress: reserveAddress,
        claimsPublicKey: authority.publicKey,
      });
      setPolicyBundle(bundle);
      setPremiumHash("");
      setClaim(null);
      setAuthorization(null);
      setPayoutHash("");
      setMessage(`Policy ${bundle.policy.policyId} committed locally. Review every actuarial component and reserve assumption before funding.`);
    } catch (error) {
      setPolicyBundle(null);
      setMessage(error instanceof Error ? error.message : "Insurance coverage could not be calculated.");
    }
  }

  async function fundPremium(): Promise<void> {
    if (!policyBundle || !account || !walletReady || !acquireSubmission(submissionLock)) return;
    setBusy(true);
    try {
      const actions = buildDirectPremiumFundingActions(policyBundle);
      setMessage("Confirm the private premium transfer in your STRK20 wallet. This prototype transfers custody to the configured reserve address.");
      const submission = await account.strk20InvokeTransaction(actions);
      setPremiumHash(submission.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submission.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submission.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed"
        ? "Premium transfer confirmed inside STRK20. Production activation still requires an insurer or audited helper to acknowledge the policy commitment."
        : result.status === "failed"
          ? "Premium transaction reverted. Its hash is preserved for review; create a fresh policy before retrying."
          : "Premium submitted and its hash preserved. Confirmation is delayed; do not fund it again.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Private premium funding failed.");
    } finally {
      releaseSubmission(submissionLock);
      setBusy(false);
    }
  }

  function fileClaim(): void {
    if (!policyBundle) return;
    try {
      const filed = createDefaultClaim(policyBundle, {
        defaultLossBaseUnits: decimalToBaseUnits(claimLoss, selected?.invoice.tokenDecimals ?? 18),
        reason: claimReason,
        evidenceDigests: evidenceDigests.split(/\r?\n/).map((item) => item.trim()).filter(Boolean),
      }, new Date());
      setClaim(filed);
      setAuthorization(null);
      setPayoutHash("");
      setMessage("Claim sealed as an opaque Poseidon commitment. Loss, requested payout, reason, evidence digests, and invoice identity remain in its private opening.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Insurance claim could not be filed.");
    }
  }

  function simulateIndependentApproval(): void {
    if (!policyBundle || !claim || !authority) return;
    try {
      const approved = authorizeInsuranceClaim(policyBundle, claim, "approved", authority.privateKey, new Date());
      buildDirectClaimPayoutActions(policyBundle, claim, approved);
      setAuthorization(approved);
      setMessage("Demo claims committee signature verified. Production deployments must replace this in-browser demonstration key with independent governance or an oracle threshold.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Claim authorization failed.");
    }
  }

  async function payApprovedClaim(): Promise<void> {
    if (!policyBundle || !claim || !authorization || !account || !reserveWalletReady || !acquireSubmission(submissionLock)) return;
    setBusy(true);
    try {
      const actions = buildDirectClaimPayoutActions(policyBundle, claim, authorization);
      setMessage("Confirm the authorized private payout from the insurer reserve wallet.");
      const submission = await account.strk20InvokeTransaction(actions);
      setPayoutHash(submission.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submission.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submission.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed" ? "Authorized claim payout confirmed privately inside STRK20." : result.status === "failed" ? "Claim payout reverted; its transaction hash remains preserved." : "Payout submitted; confirmation remains pending and the hash is preserved.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Private claim payout failed.");
    } finally {
      releaseSubmission(submissionLock);
      setBusy(false);
    }
  }

  async function copyPublicCommitment(): Promise<void> {
    if (!policyBundle) return;
    try {
      await navigator.clipboard.writeText(serializePublicInsuranceCommitment(policyBundle));
      setMessage("Opaque public policy commitments copied without risk inputs, amounts, invoice identity, or addresses.");
    } catch {
      setMessage("Copy unavailable. No policy opening was placed on the clipboard.");
    }
  }

  return (
    <section className="insurance-portal" aria-labelledby="insurance-title">
      <header className="insurance-hero">
        <div><span>Anonymous receivables protection</span><h2 id="insurance-title">Insure the invoice.<br />Keep the book private.</h2><p>Price default protection with auditable bigint arithmetic, bind risk inputs to hiding commitments, and route premium or authorized payout value through STRK20.</p></div>
        <div className="insurance-pool"><span><i /> STRK20 mainnet</span><code>{shorten(INSURANCE_POOL_ADDRESS, 14, 11)}</code><small>Private-transfer settlement rail</small></div>
      </header>

      <div className="insurance-pillars">
        <article><b>01</b><div><strong>Actuarial, not opaque</strong><p>Every basis-point contribution is inspectable and reproducible.</p></div></article>
        <article><b>02</b><div><strong>Commitment privacy</strong><p>Risk, coverage, premium, and claims open independently.</p></div></article>
        <article><b>03</b><div><strong>Solvency before bind</strong><p>Coverage fails closed if post-bind capital falls below policy.</p></div></article>
      </div>

      <div className="insurance-stagebar" aria-label="Insurance workflow">
        {(["quote", "funded", "claim", "approved", "paid"] as InsurancePhase[]).map((item, index) => <div key={item} className={phase === item ? "active" : phaseIndex(phase) > index ? "done" : ""}><b>{String(index + 1).padStart(2, "0")}</b><span>{humanize(item)}</span></div>)}
      </div>

      {!invoices.length ? (
        <div className="insurance-empty"><span>Coverage desk</span><h3>No local invoices available</h3><p>Create an invoice in the Single Invoice tab, then return here to price private default protection.</p></div>
      ) : (
        <div className="insurance-layout">
          <form className="insurance-underwriting" onSubmit={calculatePolicy}>
            <div className="insurance-section-title"><span>Underwriting desk</span><h3>Select coverage</h3></div>
            <label>Local invoice<select value={selectedId} onChange={(event) => chooseInvoice(event.target.value)}>{invoices.map((record) => <option key={record.invoice.invoiceId} value={record.invoice.invoiceId}>{record.invoice.invoiceId} · {record.invoice.amount} {record.invoice.tokenSymbol}</option>)}</select></label>
            {selected ? <div className="insurance-invoice-card"><div><span>Principal</span><strong>{selected.invoice.amount} {selected.invoice.tokenSymbol}</strong></div><div><span>Due</span><strong>{formatDate(selected.invoice.expiresAt)}</strong></div><div><span>Merchant</span><strong>{shorten(selected.invoice.recipientAddress, 9, 7)}</strong></div></div> : null}

            <label className="insurance-range"><span>Coverage limit <strong>{coveragePercent}%</strong></span><input type="range" min={10} max={100} value={coveragePercent} onChange={(event) => { const next = Number(event.target.value); setCoveragePercent(next); setDeductiblePercent((current) => Math.min(current, next - 1)); resetPolicy("Coverage changed. Recalculate the policy."); }} /></label>
            <label className="insurance-range"><span>Merchant deductible <strong>{deductiblePercent}%</strong></span><input type="range" min={0} max={Math.max(0, coveragePercent - 1)} value={Math.min(deductiblePercent, coveragePercent - 1)} onChange={(event) => { setDeductiblePercent(Number(event.target.value)); resetPolicy("Deductible changed. Recalculate the policy."); }} /></label>

            <fieldset className="insurance-fieldset"><legend>Private counterparty signals</legend><div className="insurance-form-grid">
              <label>Relationship tenure (days)<input type="number" min={0} max={36500} value={tenureDays} onChange={(event) => { setTenureDays(Number(event.target.value)); resetPolicy("Risk inputs changed. Recalculate the policy."); }} /></label>
              <label>Successful settlements<input type="number" min={0} max={100000} value={successfulSettlements} onChange={(event) => { setSuccessfulSettlements(Number(event.target.value)); resetPolicy("Risk inputs changed. Recalculate the policy."); }} /></label>
              <label>Late settlements<input type="number" min={0} max={100000} value={lateSettlements} onChange={(event) => { setLateSettlements(Number(event.target.value)); resetPolicy("Risk inputs changed. Recalculate the policy."); }} /></label>
              <label>Disputed settlements<input type="number" min={0} max={100000} value={disputedSettlements} onChange={(event) => { setDisputedSettlements(Number(event.target.value)); resetPolicy("Risk inputs changed. Recalculate the policy."); }} /></label>
              <label>Portfolio concentration (%)<input type="number" min={0} max={100} value={concentrationPercent} onChange={(event) => { setConcentrationPercent(Number(event.target.value)); resetPolicy("Risk inputs changed. Recalculate the policy."); }} /></label>
              <label>Collateral coverage (%)<input type="number" min={0} max={100} value={collateralPercent} onChange={(event) => { setCollateralPercent(Number(event.target.value)); resetPolicy("Risk inputs changed. Recalculate the policy."); }} /></label>
            </div><p>These fields remain in the private opening. The public policy carries only a salted risk commitment.</p></fieldset>

            <fieldset className="insurance-fieldset"><legend>Mutual reserve assumptions</legend><div className="insurance-form-grid">
              <label className="insurance-wide">Registered reserve address<input required value={reserveAddress} onChange={(event) => { setReserveAddress(event.target.value); resetPolicy("Reserve inputs changed. Recalculate the policy."); }} /></label>
              <label>Capital reserve (STRK)<input required inputMode="decimal" value={capitalReserve} onChange={(event) => { setCapitalReserve(cleanAmount(event.target.value)); resetPolicy("Reserve inputs changed. Recalculate the policy."); }} /></label>
              <label>Existing exposure (STRK)<input required inputMode="decimal" value={existingExposure} onChange={(event) => { setExistingExposure(cleanAmount(event.target.value)); resetPolicy("Reserve inputs changed. Recalculate the policy."); }} /></label>
              <label>Minimum solvency (%)<input type="number" min={100} max={300} value={minimumSolvencyPercent} onChange={(event) => { setMinimumSolvencyPercent(Number(event.target.value)); resetPolicy("Reserve inputs changed. Recalculate the policy."); }} /></label>
              <label>Default grace (days)<input type="number" min={0} max={90} value={graceDays} onChange={(event) => { setGraceDays(Number(event.target.value)); resetPolicy("Claim terms changed. Recalculate the policy."); }} /></label>
              <label>Claim window (days)<input type="number" min={1} max={180} value={claimWindowDays} onChange={(event) => { setClaimWindowDays(Number(event.target.value)); resetPolicy("Claim terms changed. Recalculate the policy."); }} /></label>
            </div></fieldset>
            <button className="insurance-primary" type="submit" disabled={!authority}>Calculate & commit coverage</button>
          </form>

          <div className="insurance-workspace">
            {policyBundle ? <PolicyWorkspace bundle={policyBundle} premiumHash={premiumHash} busy={busy} walletReady={walletReady} onFund={fundPremium} onCopy={copyPublicCommitment} /> : <div className="insurance-placeholder"><span>Risk engine ready</span><h3>Configure the left panel</h3><p>The quote will show default probability, grade, capital utilization, coverage, deductible, maximum payout, and every premium component.</p></div>}

            {policyBundle ? (
              <section className="insurance-claim-desk">
                <div className="insurance-section-title"><span>Claim desk</span><h3>File without exposing the invoice</h3></div>
                <div className="claim-window"><div><span>Default eligible</span><strong>{formatDate(policyBundle.policy.defaultEligibleAt)}</strong></div><div><span>Claim deadline</span><strong>{formatDate(policyBundle.policy.claimDeadline)}</strong></div><div><span>Window status</span><strong>{claimWindowStatus(policyBundle, now)}</strong></div></div>
                <div className="insurance-form-grid">
                  <label>Verified default loss ({selected?.invoice.tokenSymbol ?? "STRK"})<input inputMode="decimal" value={claimLoss} onChange={(event) => setClaimLoss(cleanAmount(event.target.value))} /></label>
                  <label>Private reason<select value={claimReason} onChange={(event) => setClaimReason(event.target.value as InsuranceClaimReason)}><option value="nonpayment">Nonpayment</option><option value="counterparty_insolvency">Counterparty insolvency</option><option value="arbitration_award">Arbitration award</option></select></label>
                  <label className="insurance-wide">Evidence digests, one per line<textarea rows={4} value={evidenceDigests} onChange={(event) => setEvidenceDigests(event.target.value)} /></label>
                </div>
                <div className="insurance-actions"><button type="button" onClick={fileClaim} disabled={busy || claimWindowStatus(policyBundle, now) !== "Open"}>File hiding claim</button>{claim ? <button className="insurance-secondary" type="button" onClick={simulateIndependentApproval}>Simulate committee approval</button> : null}</div>
                {claim ? <div className="claim-commitment"><div><span>Claim commitment</span><code>{shorten(claim.commitment.claimCommitment, 18, 12)}</code></div><div><span>Private payout opening</span><strong>{formatToken(claim.opening.payoutBaseUnits)} {selected?.invoice.tokenSymbol}</strong></div><div><span>Authority</span><strong>{authorization ? authorization.decision : "Awaiting decision"}</strong></div></div> : null}
                {authorization?.decision === "approved" ? <div className="insurance-payout"><p>The payout action is cryptographically capped and signed. To execute the direct prototype path, connect the configured insurer reserve wallet.</p><div className="insurance-actions"><button type="button" onClick={payApprovedClaim} disabled={!reserveWalletReady || busy || Boolean(payoutHash)}>{payoutHash ? "Payout submitted" : "Pay approved claim privately"}</button>{!walletReady ? <WalletConnect /> : !reserveWalletReady ? <span>Connected wallet is not the insurer reserve.</span> : null}</div>{payoutHash ? <a href={getStarknetExplorerTransactionUrl(payoutHash)} target="_blank" rel="noreferrer">Track payout transaction ↗</a> : null}</div> : null}
              </section>
            ) : null}
          </div>
        </div>
      )}

      <section className="insurance-boundaries">
        <div><strong>Commitment layer</strong><p>{security.limitations[0]} Risk inputs are revealed only to a chosen verifier.</p></div>
        <div><strong>Direct prototype path</strong><p>{security.limitations[1]} A transfer to a reserve is private custody, not escrow.</p></div>
        <div><strong>Enforceable pool path</strong><p>{security.limitations[2]} Claim helper outputs use public-amount open notes.</p></div>
      </section>
      <p className="insurance-message" role="status" aria-live="polite">{message}</p>
    </section>
  );
}

function PolicyWorkspace({ bundle, premiumHash, busy, walletReady, onFund, onCopy }: Readonly<{ bundle: InsurancePolicyBundle; premiumHash: string; busy: boolean; walletReady: boolean; onFund: () => void; onCopy: () => void }>) {
  const policy = bundle.policy;
  return <section className="insurance-policy-card">
    <div className="policy-heading"><div><span>Bound policy proposal</span><h3>{policy.policyId}</h3></div><div className={`risk-grade grade-${policy.assessment.grade.toLowerCase()}`}><small>Risk grade</small><strong>{policy.assessment.grade}</strong><span>{formatBps(policy.assessment.defaultProbabilityBps)} PD</span></div></div>
    <div className="risk-meter"><i style={{ width: `${Math.max(2, policy.assessment.defaultProbabilityBps / 50)}%` }} /></div>
    <div className="risk-breakdown">
      <div><span>Baseline</span><strong>+{formatBps(policy.assessment.components.baselineBps)}</strong></div><div><span>History</span><strong>+{formatBps(policy.assessment.components.lateHistoryBps + policy.assessment.components.disputeHistoryBps + policy.assessment.components.sparseHistoryBps)}</strong></div><div><span>Term</span><strong>+{formatBps(policy.assessment.components.termRiskBps)}</strong></div><div><span>Concentration</span><strong>+{formatBps(policy.assessment.components.concentrationRiskBps)}</strong></div><div><span>Collateral credit</span><strong>−{formatBps(policy.assessment.components.collateralCreditBps)}</strong></div>
    </div>
    <div className="coverage-ledger"><div><span>Coverage limit</span><strong>{formatToken(policy.coverageLimitBaseUnits)} STRK</strong></div><div><span>Deductible</span><strong>{formatToken(policy.deductibleBaseUnits)} STRK</strong></div><div><span>Maximum payout</span><strong>{formatToken(policy.maximumPayoutBaseUnits)} STRK</strong></div><div className="premium-total"><span>Private premium</span><strong>{formatToken(policy.premiumBaseUnits)} STRK</strong></div></div>
    <div className="premium-breakdown"><div><span>Expected loss</span><strong>{formatToken(policy.expectedLossBaseUnits)}</strong></div><div><span>Reserve loading</span><strong>{formatToken(policy.reserveLoadingBaseUnits)}</strong></div><div><span>Protocol fee</span><strong>{formatToken(policy.protocolFeeBaseUnits)}</strong></div></div>
    <div className="solvency-card"><div><span>Post-bind utilization</span><strong>{formatBps(policy.postBindUtilizationBps)}</strong></div><div><span>Capital requirement</span><strong>{formatToken(policy.capitalRequirementBaseUnits)} STRK</strong></div><div><span>Remaining buffer</span><strong>{formatToken(policy.remainingCapitalBufferBaseUnits)} STRK</strong></div></div>
    <div className="policy-commitments"><div><span>Risk</span><code>{shorten(policy.riskCommitment, 12, 8)}</code></div><div><span>Coverage</span><code>{shorten(policy.coverageCommitment, 12, 8)}</code></div><div><span>Premium</span><code>{shorten(policy.premiumCommitment, 12, 8)}</code></div></div>
    <div className="insurance-actions"><button type="button" onClick={onFund} disabled={!walletReady || busy || Boolean(premiumHash)}>{busy ? "Submitting..." : premiumHash ? "Premium submitted" : "Fund premium privately"}</button><button className="insurance-secondary" type="button" onClick={onCopy}>Copy opaque commitments</button>{!walletReady ? <WalletConnect /> : null}</div>
    {premiumHash ? <a className="insurance-tx" href={getStarknetExplorerTransactionUrl(premiumHash)} target="_blank" rel="noreferrer">Track premium transaction ↗</a> : null}
    <p className="insurance-custody-note">Direct funding transfers premium custody to <code>{shorten(policy.insurerReserveAddress, 12, 9)}</code>. An audited stateful helper is required for non-custodial escrow, onchain activation, reserve enforcement, and double-claim protection.</p>
  </section>;
}

function cleanAmount(value: string): string { return value.replaceAll(",", "").replace(/[^\d.]/g, ""); }
function shorten(value: string, start: number, end: number): string { return value.length <= start + end + 1 ? value : `${value.slice(0, start)}…${value.slice(-end)}`; }
function humanize(value: string): string { return value.replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase()); }
function phaseIndex(value: InsurancePhase): number { return ["quote", "funded", "claim", "approved", "paid"].indexOf(value); }
function formatBps(value: number): string { return `${(value / 100).toFixed(2)}%`; }
function formatDate(value: string): string { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }
function formatToken(value: string): string {
  const [whole, fraction = ""] = baseUnitsToDecimal(value).split(".");
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const visibleFraction = fraction.slice(0, 4).replace(/0+$/, "");
  return visibleFraction ? `${grouped}.${visibleFraction}` : grouped;
}
function claimWindowStatus(bundle: InsurancePolicyBundle, now: Date): string {
  if (now.getTime() < Date.parse(bundle.policy.defaultEligibleAt)) return "Not open";
  if (now.getTime() > Date.parse(bundle.policy.claimDeadline)) return "Closed";
  return "Open";
}
