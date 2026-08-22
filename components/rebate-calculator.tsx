"use client";

import { useEffect, useMemo, useState } from "react";

import type { ShareableInvoice } from "@/lib/invoices";
import {
  calculateEligibleRebateBps,
  calculateRebate,
  createRebateCommitment,
  getRebateSecurityModel,
  serializeRebateProof,
  verifyRebateCommitment,
  type RebateClaim,
} from "@/lib/rebate-engine";
import { baseUnitsToDecimal, decimalToBaseUnits } from "@/lib/strk20/validation";

interface RebateCalculatorProps {
  invoice: ShareableInvoice;
  appliedClaim: RebateClaim | null;
  disabled?: boolean;
  onApply: (claim: RebateClaim | null) => void;
}

export function RebateCalculator({ invoice, appliedClaim, disabled = false, onApply }: Readonly<RebateCalculatorProps>) {
  const policy = invoice.rebatePolicy;
  const [now, setNow] = useState(() => new Date());
  const [selectedBps, setSelectedBps] = useState(() => invoice.rebatePolicy?.maximumRebateBps ?? 1);
  const [message, setMessage] = useState("Select any rate up to the vendor's current ceiling, then lock a five-minute private adjustment.");
  const [copyMessage, setCopyMessage] = useState("");

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(timer);
  }, []);

  const eligibility = useMemo(
    () => policy ? calculateEligibleRebateBps(policy, invoice.expiresAt, now) : { eligibleRebateBps: 0, leadTimeSeconds: 0 },
    [invoice.expiresAt, now, policy],
  );
  const effectiveBps = Math.min(Math.max(selectedBps, 1), Math.max(eligibility.eligibleRebateBps, 1));
  const principal = BigInt(decimalToBaseUnits(invoice.amount, invoice.tokenDecimals));
  const preview = policy && eligibility.eligibleRebateBps > 0
    ? calculateRebate(principal, policy, invoice.expiresAt, effectiveBps, now)
    : null;
  const security = getRebateSecurityModel();
  const claimExpired = appliedClaim ? now.getTime() > Date.parse(appliedClaim.proof.validUntil) : false;

  if (!policy) return null;

  function selectRate(value: number): void {
    setSelectedBps(value);
    setCopyMessage("");
    if (appliedClaim) onApply(null);
    setMessage("Rate changed. Lock a fresh commitment before paying.");
  }

  function apply(): void {
    try {
      const claim = createRebateCommitment(invoice, effectiveBps, new Date());
      verifyRebateCommitment(invoice, claim, new Date());
      onApply(claim);
      setMessage(`Rebate locked until ${new Date(claim.proof.validUntil).toLocaleTimeString()}. The private transfer amount now reflects this adjustment.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Rebate commitment could not be created.");
    }
  }

  function remove(): void {
    onApply(null);
    setMessage("Rebate removed. The invoice's exact undiscounted balance is restored.");
  }

  async function copyProof(): Promise<void> {
    if (!appliedClaim) return;
    try {
      await navigator.clipboard.writeText(serializeRebateProof(appliedClaim.proof));
      setCopyMessage("Opaque public commitment copied without its private opening.");
    } catch {
      setCopyMessage("Copy unavailable. No opening or invoice metadata was placed on the clipboard.");
    }
  }

  return (
    <section className="rebate-calculator" aria-labelledby="rebate-heading">
      <div className="rebate-header">
        <div><span className="eyebrow">Vendor-funded early settlement</span><h2 id="rebate-heading">Claim an encrypted rebate</h2></div>
        <span className={`rebate-lock ${appliedClaim && !claimExpired ? "locked" : ""}`}>{appliedClaim ? claimExpired ? "Quote expired" : "Commitment locked" : "Not claimed"}</span>
      </div>

      <div className="rebate-timing">
        <div><span>Time before due</span><strong>{formatLeadTime(eligibility.leadTimeSeconds)}</strong></div>
        <div><span>Current ceiling</span><strong>{formatBps(eligibility.eligibleRebateBps)}</strong></div>
        <div><span>Vendor maximum</span><strong>{formatBps(policy.maximumRebateBps)}</strong></div>
      </div>

      {eligibility.eligibleRebateBps > 0 && preview ? (
        <>
          <label className="rebate-slider-label" htmlFor="rebate-rate">
            <span>Early-payment discount</span><strong>{formatBps(effectiveBps)}</strong>
          </label>
          <input
            id="rebate-rate"
            className="rebate-slider"
            type="range"
            min={1}
            max={eligibility.eligibleRebateBps}
            step={1}
            value={effectiveBps}
            onChange={(event) => selectRate(Number(event.target.value))}
            disabled={disabled}
          />
          <div className="rebate-math">
            <div><span>Original</span><strong>{invoice.amount} {invoice.tokenSymbol}</strong></div>
            <div className="rebate-saving"><span>Private rebate</span><strong>-{baseUnitsToDecimal(preview.rebateBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</strong></div>
            <div className="rebate-net"><span>Shielded settlement</span><strong>{baseUnitsToDecimal(preview.settlementBaseUnits, invoice.tokenDecimals)} {invoice.tokenSymbol}</strong></div>
          </div>
          <div className="rebate-actions">
            <button type="button" onClick={apply} disabled={disabled}>{appliedClaim ? "Refresh commitment" : "Claim rebate"}</button>
            {appliedClaim ? <button className="rebate-secondary" type="button" onClick={copyProof}>Copy public proof</button> : null}
            {appliedClaim ? <button className="rebate-secondary" type="button" onClick={remove} disabled={disabled}>Remove</button> : null}
          </div>
        </>
      ) : (
        <p className="rebate-unavailable">The vendor&apos;s minimum early-payment window has closed. The original invoice balance remains payable.</p>
      )}

      <p className="rebate-message" role="status" aria-live="polite">{claimExpired ? "This commitment expired. Refresh it before paying." : message} {copyMessage}</p>
      {appliedClaim ? (
        <dl className="rebate-proof-details">
          <div><dt>Adjustment</dt><dd><code>{shortHex(appliedClaim.proof.adjustmentCommitment)}</code></dd></div>
          <div><dt>Pool binding</dt><dd><code>{shortHex(appliedClaim.proof.poolAddress)}</code></dd></div>
          <div><dt>Valid until</dt><dd>{new Date(appliedClaim.proof.validUntil).toLocaleTimeString()}</dd></div>
        </dl>
      ) : null}
      <details className="rebate-boundary">
        <summary>What this proof does—and does not—prove</summary>
        <p>{security.provenLocally[1]}</p>
        <p>{security.limitations[0]}</p>
        <p>{security.limitations[2]}</p>
      </details>
    </section>
  );
}

function formatBps(bps: number): string {
  return `${(bps / 100).toFixed(2)}%`;
}

function formatLeadTime(seconds: number): string {
  if (seconds >= 86_400) return `${Math.floor(seconds / 86_400)}d ${Math.floor(seconds % 86_400 / 3_600)}h`;
  if (seconds >= 3_600) return `${Math.floor(seconds / 3_600)}h ${Math.floor(seconds % 3_600 / 60)}m`;
  return `${Math.floor(seconds / 60)}m`;
}

function shortHex(value: string): string {
  return value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}
