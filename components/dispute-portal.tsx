"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  buildDisputeCaseDigest,
  buildDisputeOutcomeAttestation,
  buildEvidenceDigest,
  buildResolutionActions,
  createDisputeCase,
  createDisputeResolution,
  createEvidence,
  DISPUTE_POOL_ADDRESS,
  formatDisputeBaseUnits,
  getDisputeVisibilityModel,
  MAX_ARBITER_FEE_BPS,
  MAX_EVIDENCE_ITEMS,
  serializeDisputeCaseDigest,
  serializeDisputeOutcome,
  serializeEvidenceDigest,
  summarizeDisputeTrust,
  type DisputeCase,
  type DisputeFault,
  type DisputeResolution,
  type EvidenceParty,
} from "@/lib/dispute-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./dispute-portal.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type BusyAction = "solve" | "balance" | "settle" | "outcome" | "evidence" | null;

/**
 * Escrow arbitration portal for the merchant dashboard.
 *
 * Every claim here is deliberately narrow. CipherBill solves the dispute allocation in exact
 * integers, binds the case and resolution with salted Poseidon commitments, commits evidence for
 * selective disclosure, and submits the settlement as private in-pool transfers. It generates no
 * zero-knowledge proof, escrows and slashes nothing, runs no on-chain court, and keeps no
 * reputation score. The fund-holder must voluntarily sign, and the arbiter is trusted.
 */
export function DisputePortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState("inv_dispute_001");
  const [escrowValue, setEscrowValue] = useState("");
  const [collateralValue, setCollateralValue] = useState("");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetToken, setAssetToken] = useState("");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [buyerRecipient, setBuyerRecipient] = useState("");
  const [vendorRecipient, setVendorRecipient] = useState("");
  const [arbiterRecipient, setArbiterRecipient] = useState("");
  const [arbiterLabel, setArbiterLabel] = useState("");
  const [claimSummary, setClaimSummary] = useState("");
  const [respondBy, setRespondBy] = useState("");
  const [memo, setMemo] = useState("");
  const [faultAssessment, setFaultAssessment] = useState<DisputeFault>("vendor_at_fault");
  const [buyerRefundBps, setBuyerRefundBps] = useState("4000");
  const [arbiterFeeBps, setArbiterFeeBps] = useState("0");
  const [penaltyBps, setPenaltyBps] = useState("0");
  const [resolvedBy, setResolvedBy] = useState("");
  const [note, setNote] = useState("");
  const [disputeCase, setDisputeCase] = useState<DisputeCase | null>(null);
  const [resolution, setResolution] = useState<DisputeResolution | null>(null);
  const [caseDigest, setCaseDigest] = useState("");
  const [outcome, setOutcome] = useState("");
  const [evidenceParty, setEvidenceParty] = useState<EvidenceParty>("buyer");
  const [evidenceItems, setEvidenceItems] = useState("");
  const [evidenceNote, setEvidenceNote] = useState("");
  const [evidenceDigest, setEvidenceDigest] = useState("");
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [settlementHash, setSettlementHash] = useState("");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Open a dispute over an escrowed invoice, set the arbiter's allocation in basis points, and CipherBill solves the split in exact integers, then settles it as private in-pool transfers.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const visibility = useMemo(() => resolution ? getDisputeVisibilityModel(resolution) : null, [resolution]);
  const trust = useMemo(() => resolution ? summarizeDisputeTrust(resolution) : null, [resolution]);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, open]);

  function solve(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("solve");
    try {
      const nextCase = createDisputeCase({
        invoiceId,
        asset: { symbol: assetSymbol, tokenAddress: assetToken, decimals: Number(assetDecimals) },
        escrowValue,
        collateralValue: collateralValue || undefined,
        buyerRecipient,
        vendorRecipient,
        arbiterRecipient: arbiterRecipient || undefined,
        arbiterLabel: arbiterLabel || undefined,
        claimSummary,
        respondBy: toIso(respondBy, "response deadline"),
        memo: memo || undefined,
      });
      const nextResolution = createDisputeResolution(nextCase, {
        faultAssessment,
        buyerRefundBps: Number(buyerRefundBps),
        arbiterFeeBps: Number(arbiterFeeBps),
        penaltyBps: Number(penaltyBps),
        resolvedBy,
        note: note || undefined,
      });
      invalidate();
      setDisputeCase(nextCase);
      setResolution(nextResolution);
      setMessage(`Solved: fault "${nextResolution.faultAssessment.replaceAll("_", " ")}". The buyer receives ${nextResolution.buyerTotalDisplay} ${nextResolution.asset.symbol}, the vendor ${nextResolution.vendorTotalDisplay} ${nextResolution.asset.symbol}, and any arbiter ${nextResolution.arbiterFeeDisplay} ${nextResolution.asset.symbol}. Every base unit of the escrow and collateral is accounted for.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The dispute allocation could not be solved.");
    } finally {
      setBusy(null);
    }
  }

  async function shareCaseDigest(): Promise<void> {
    if (!disputeCase) return;
    const encoded = serializeDisputeCaseDigest(buildDisputeCaseDigest(disputeCase));
    setCaseDigest(encoded);
    await copy(encoded, "Case digest copied. It carries the invoice ID, deadline, a claim hash, and the Poseidon commitment only: no amounts, parties, claim text, salt, or memo. Never share the full case object.");
  }

  async function shareOutcome(): Promise<void> {
    if (!resolution) return;
    const encoded = serializeDisputeOutcome(buildDisputeOutcomeAttestation(resolution));
    setOutcome(encoded);
    await copy(encoded, "Outcome attestation copied. It binds the case and resolution to the fault finding. It is a hash you may choose to disclose, not an on-chain record, a portable score, or a reputation system.");
  }

  async function commitEvidence(): Promise<void> {
    if (!disputeCase || busy) return;
    setBusy("evidence");
    try {
      const items = evidenceItems.split("\n").map((item) => item.trim()).filter(Boolean);
      const bundle = createEvidence({
        caseCommitment: disputeCase.caseCommitment,
        submittedBy: evidenceParty,
        items,
        note: evidenceNote || undefined,
      });
      const encoded = serializeEvidenceDigest(buildEvidenceDigest(bundle));
      setEvidenceDigest(encoded);
      await copy(encoded, `Committed and copied ${items.length} evidence item${items.length === 1 ? "" : "s"} for the ${evidenceParty}. The digest carries each item's keccak hash and a root, never the item content. Disclose the full bundle to the arbiter out of band; low-entropy items can be guessed from their hash.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The evidence could not be committed.");
    } finally {
      setBusy(null);
    }
  }

  async function checkCoverage(): Promise<void> {
    if (!resolution || !account || !walletReady || busy) return;
    const token = resolution.asset.tokenAddress;
    const required = BigInt(resolution.escrowBaseUnits) + BigInt(resolution.collateralBaseUnits);
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setWalletBalance(balance);
      setMessage(BigInt(balance) >= required
        ? "This shielded balance covers the escrow and collateral the settlement moves. The pool fee the wallet adds is not included in that comparison."
        : "This shielded balance is below the escrow plus collateral. The fund-holder must hold both before the settlement can be signed.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function submitSettlement(): Promise<void> {
    if (!resolution || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    setBusy("settle");
    setSettlementHash("");
    try {
      const actions = buildResolutionActions(resolution);
      setMessage(`Confirm the settlement in the fund-holder's wallet: ${actions.length} private in-pool transfer${actions.length === 1 ? "" : "s"} to the buyer, the vendor, and any arbiter. The relayer submits it, so never attribute the sender to the fund-holder.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setSettlementHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed"
        ? "Settlement confirmed inside the pool. The allocation has moved to the parties. Nothing was escrowed or slashed: the fund-holder signed it voluntarily, and the arbiter's finding is not enforced on-chain."
        : result.status === "failed"
          ? "The submitted settlement reverted. The hash is preserved; re-solve the allocation before retrying."
          : "Submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it stays pending.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Submission failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }

  async function copy(text: string, ok: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      setMessage(ok);
    } catch {
      setMessage("Clipboard access was refused. Copy the text below by hand.");
    }
  }

  function invalidate(): void {
    setDisputeCase(null);
    setResolution(null);
    setCaseDigest("");
    setOutcome("");
    setEvidenceDigest("");
    setWalletBalance(null);
    setSettlementHash("");
  }

  function resetComposer(): void {
    setEscrowValue("");
    setCollateralValue("");
    setBuyerRecipient("");
    setVendorRecipient("");
    setArbiterRecipient("");
    setArbiterLabel("");
    setClaimSummary("");
    setRespondBy("");
    setMemo("");
    setResolvedBy("");
    setNote("");
    setEvidenceItems("");
    setEvidenceNote("");
    invalidate();
    setMessage("Composer reset. Nothing was persisted: cases, resolutions, evidence, salts, and commitments live only in this browser tab.");
  }

  return (
    <section className={styles.launch} aria-labelledby="dispute-launch-title">
      <div className={styles.launchCopy}>
        <span>Escrow arbitration &amp; selective evidence</span>
        <h2 id="dispute-launch-title">Settle disputes.<br /><em>Keep the terms private.</em></h2>
        <p>Open a dispute over an escrowed invoice, commit each side&apos;s evidence for selective disclosure, and let an agreed arbiter set the allocation. CipherBill solves the refund, release, fee, and collateral penalty in exact integers, then settles them as private in-pool STRK20 transfers.</p>
        <button type="button" onClick={() => setOpen(true)}>Open the arbitration portal</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not zero-knowledge</strong><span>Commitments are salted Poseidon hashes. The wallet proves each transfer; CipherBill proves nothing and no contract verifies a case, evidence, or verdict.</span></div>
        <div><strong>Not escrow or slashing</strong><span>Nothing holds or seizes the funds. The disputed amount and collateral sit in the fund-holder&apos;s shielded balance and only move if that party signs.</span></div>
        <div><strong>Not a court or reputation</strong><span>Resolution is a local computation in one browser. The arbiter is trusted, the outcome is a disclosable hash, not an on-chain record or a portable score.</span></div>
      </div>

      {open ? (
        <div className={styles.backdrop} role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
          <section className={styles.modal} role="dialog" aria-modal="true" aria-labelledby="dispute-modal-title">
            <header className={styles.modalHeader}>
              <div><span>Escrow arbitration · SN_MAIN</span><h2 id="dispute-modal-title">Resolve an escrowed dispute</h2><p>Settlement transfers act on <code>{shorten(DISPUTE_POOL_ADDRESS)}</code></p></div>
              <button type="button" onClick={() => setOpen(false)} disabled={Boolean(busy)} aria-label="Close the arbitration portal">×</button>
            </header>

            <div className={styles.truth}>
              <div><b>Executable here</b><span>One wallet request: the settlement transfers to the buyer, vendor, and any arbiter, through the connected wallet.</span></div>
              <div><b>Computed only</b><span>The allocation, the commitments, and the evidence hashes. No case registry, escrow, or proof exists.</span></div>
              <div><b>Exact integers</b><span>Shares floor in basis points; the vendor takes the exact remainder so no base unit is lost.</span></div>
              <div><b>Trust is explicit</b><span>The arbiter&apos;s finding is caller-supplied and never judged for fairness. The fund-holder must sign.</span></div>
            </div>

            {!resolution ? (
              <form className={styles.form} onSubmit={solve}>
                <fieldset className={styles.fieldset}>
                  <span>The escrowed dispute</span>
                  <div className={styles.fields}>
                    <label>Invoice ID<input required maxLength={64} value={invoiceId} onChange={(event) => setInvoiceId(event.target.value)} /></label>
                    <label>Escrow value (disputed)<input required inputMode="decimal" placeholder="1000" value={escrowValue} onChange={(event) => setEscrowValue(event.target.value)} /></label>
                    <label>Vendor collateral (optional)<input inputMode="decimal" placeholder="0" value={collateralValue} onChange={(event) => setCollateralValue(event.target.value)} /></label>
                    <label>Asset symbol<input required maxLength={12} value={assetSymbol} onChange={(event) => setAssetSymbol(event.target.value)} /></label>
                    <label>Asset decimals<input required inputMode="numeric" min="0" max="18" value={assetDecimals} onChange={(event) => setAssetDecimals(event.target.value)} /></label>
                    <label>Respond by (within 90 days)<input required type="datetime-local" value={respondBy} onChange={(event) => setRespondBy(event.target.value)} /></label>
                    <label className={styles.wide}>Settlement token contract<input required maxLength={66} placeholder="0x…" value={assetToken} onChange={(event) => setAssetToken(event.target.value)} /></label>
                    <label className={styles.wide}>Buyer recipient (registered, in-pool)<input required maxLength={66} placeholder="0x…" value={buyerRecipient} onChange={(event) => setBuyerRecipient(event.target.value)} /></label>
                    <label className={styles.wide}>Vendor recipient (registered, in-pool)<input required maxLength={66} placeholder="0x…" value={vendorRecipient} onChange={(event) => setVendorRecipient(event.target.value)} /></label>
                    <label className={styles.wide}>Arbiter recipient (optional, for a fee)<input maxLength={66} placeholder="0x…" value={arbiterRecipient} onChange={(event) => setArbiterRecipient(event.target.value)} /></label>
                    <label className={styles.wide}>Arbiter label (optional)<input maxLength={96} placeholder="Neutral Arbiter" value={arbiterLabel} onChange={(event) => setArbiterLabel(event.target.value)} /></label>
                    <label className={styles.wide}>Claim summary (stays in this browser)<input required maxLength={240} placeholder="Delivered goods did not match the agreed specification." value={claimSummary} onChange={(event) => setClaimSummary(event.target.value)} /></label>
                    <label className={styles.wide}>Memo (optional, stays here)<input maxLength={160} placeholder="batch 7" value={memo} onChange={(event) => setMemo(event.target.value)} /></label>
                  </div>
                </fieldset>

                <fieldset className={styles.fieldset}>
                  <span>The arbiter&apos;s finding</span>
                  <div className={styles.fields}>
                    <label>Fault assessment<select value={faultAssessment} onChange={(event) => setFaultAssessment(event.target.value as DisputeFault)}><option value="vendor_at_fault">Vendor at fault</option><option value="buyer_at_fault">Buyer at fault</option><option value="shared">Shared fault</option><option value="no_fault">No fault</option></select></label>
                    <label>Buyer refund (bps of escrow)<input required inputMode="numeric" min="0" max="10000" value={buyerRefundBps} onChange={(event) => setBuyerRefundBps(event.target.value)} /></label>
                    <label>Arbiter fee (bps, max {MAX_ARBITER_FEE_BPS})<input required inputMode="numeric" min="0" max={MAX_ARBITER_FEE_BPS} value={arbiterFeeBps} onChange={(event) => setArbiterFeeBps(event.target.value)} /></label>
                    <label>Collateral penalty (bps)<input required inputMode="numeric" min="0" max="10000" value={penaltyBps} onChange={(event) => setPenaltyBps(event.target.value)} /></label>
                    <label className={styles.wide}>Resolved by (arbiter name)<input required maxLength={96} placeholder="Neutral Arbiter" value={resolvedBy} onChange={(event) => setResolvedBy(event.target.value)} /></label>
                    <label className={styles.wide}>Resolution note (optional, stays here)<input maxLength={160} placeholder="Vendor shipped the wrong grade." value={note} onChange={(event) => setNote(event.target.value)} /></label>
                  </div>
                </fieldset>

                <div className={styles.actions}><button type="button" className={styles.ghost} onClick={resetComposer}>Reset composer</button><button type="submit" disabled={busy === "solve"}>{busy === "solve" ? "Solving…" : "Solve the resolution"}</button></div>
              </form>
            ) : (
              <div className={styles.plan}>
                <aside className={styles.sidebar}>
                  <span>Allocation solved</span>
                  <div className={styles.headline}><strong>{resolution.buyerTotalDisplay} {resolution.asset.symbol}</strong><small>to the buyer, {resolution.vendorTotalDisplay} {resolution.asset.symbol} to the vendor · fault &ldquo;{resolution.faultAssessment.replaceAll("_", " ")}&rdquo;</small></div>
                  <dl>
                    <div><dt>Escrow disputed</dt><dd>{formatDisputeBaseUnits(resolution.escrowBaseUnits, resolution.asset.decimals)} {resolution.asset.symbol}</dd></div>
                    <div><dt>Collateral posted</dt><dd>{formatDisputeBaseUnits(resolution.collateralBaseUnits, resolution.asset.decimals)} {resolution.asset.symbol}</dd></div>
                    <div><dt>Buyer refund</dt><dd>{resolution.buyerRefundDisplay} {resolution.asset.symbol}</dd></div>
                    <div><dt>Vendor release</dt><dd>{resolution.vendorReleaseDisplay} {resolution.asset.symbol}</dd></div>
                    <div><dt>Collateral penalty</dt><dd>{resolution.penaltyDisplay} {resolution.asset.symbol}</dd></div>
                    <div><dt>Collateral returned</dt><dd>{resolution.collateralReturnDisplay} {resolution.asset.symbol}</dd></div>
                    <div><dt>Arbiter fee</dt><dd>{resolution.arbiterFeeDisplay} {resolution.asset.symbol}</dd></div>
                    <div><dt>Resolution commitment</dt><dd><code>{shorten(resolution.resolutionCommitment)}</code></dd></div>
                    {walletBalance !== null ? <div><dt>Shielded balance</dt><dd className={BigInt(walletBalance) >= BigInt(resolution.escrowBaseUnits) + BigInt(resolution.collateralBaseUnits) ? styles.shielded : styles.exposed}>{formatDisputeBaseUnits(walletBalance, resolution.asset.decimals)} {resolution.asset.symbol}</dd></div> : null}
                  </dl>
                  <button type="button" onClick={invalidate} disabled={Boolean(busy)}>Edit the terms</button>
                </aside>

                <div className={styles.main}>
                  <section className={styles.card}>
                    <div><span>One private settlement</span><h3>Refund, release &amp; fee in one transaction</h3></div>
                    <p>CipherBill batches the allocation into one in-pool transfer per recipient and drops any zero leg. The fund-holder signs once; the wallet appends its own relayer fee, so none is added here.</p>
                    <div className={styles.legRow}>
                      <div><strong>Buyer</strong><small>{shorten(resolution.buyerRecipient)}</small></div>
                      <div><b>{resolution.buyerTotalDisplay} {resolution.asset.symbol}</b><em>refund + any penalty</em></div>
                      <div><b className={styles.shielded}>In-pool transfer</b><em>hides sender, recipient, token, amount</em></div>
                    </div>
                    <div className={styles.legRow}>
                      <div><strong>Vendor</strong><small>{shorten(resolution.vendorRecipient)}</small></div>
                      <div><b>{resolution.vendorTotalDisplay} {resolution.asset.symbol}</b><em>release + returned collateral</em></div>
                      <div><b className={styles.shielded}>In-pool transfer</b><em>the exact remainder, no unit lost</em></div>
                    </div>
                    {resolution.arbiterRecipient ? (
                      <div className={styles.legRow}>
                        <div><strong>Arbiter</strong><small>{shorten(resolution.arbiterRecipient)}</small></div>
                        <div><b>{resolution.arbiterFeeDisplay} {resolution.asset.symbol}</b><em>agreed fee, if any</em></div>
                        <div><b className={styles.shielded}>In-pool transfer</b><em>dropped when the fee is zero</em></div>
                      </div>
                    ) : null}
                  </section>
                  <div className={styles.opsRow}>
                    <div>
                      <span>01 · Consent-driven read</span><h4>Shielded coverage</h4>
                      <p>Reads the fund-holder&apos;s balance of the settlement token with permission and keeps it in component memory only. Coverage is compared against the escrow plus collateral.</p>
                      <button type="button" onClick={checkCoverage} disabled={!walletReady || Boolean(busy)}>{busy === "balance" ? "Reading…" : "Check coverage"}</button>
                    </div>
                    <div>
                      <span>02 · Fund-holder signs</span><h4>Send the settlement</h4>
                      <p>One wallet request: the merged in-pool transfers to the parties. No relayer-fee action is added because the wallet appends its own.</p>
                      {!walletReady ? <WalletConnect /> : <button type="button" onClick={submitSettlement} disabled={Boolean(busy)}>{busy === "settle" ? "Submitting…" : "Send the settlement"}</button>}
                      {settlementHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(settlementHash)} target="_blank" rel="noreferrer">Track settlement hash ↗</a> : null}
                    </div>
                    <div>
                      <span>03 · Disclosable record</span><h4>Outcome attestation</h4>
                      <p>Builds a hash binding the case and resolution to the fault finding. Share it if you choose; it is not on-chain, not portable without you, and not a reputation score.</p>
                      <button type="button" onClick={shareOutcome} disabled={Boolean(busy)}>Build &amp; copy attestation</button>
                    </div>
                  </div>

                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Selective disclosure</span><h3>Shareable case digest</h3></div>
                    <p>The digest carries the invoice ID, the response deadline, a keccak hash of the claim, and the case&apos;s Poseidon commitment. It carries no amount, party address, claim text, salt, or memo, so a counterparty or arbiter can see the shape of the case and later verify the disclosed case against it. The full case holds the salt and stays here.</p>
                    <textarea readOnly value={caseDigest} placeholder="Copy the digest to publish this dispute's shape without its amounts, parties, or claim text." />
                    <div><button type="button" onClick={shareCaseDigest}>Copy case digest</button></div>
                  </section>
                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Evidence commitment</span><h3>Commit evidence, disclose selectively</h3></div>
                    <p>Enter document hashes or references, one per line (1 to {MAX_EVIDENCE_ITEMS}). Each is keccak-hashed and folded into a root, so the digest proves which items were committed without revealing them. Disclose the full bundle to the arbiter out of band; a low-entropy item can be guessed from its hash.</p>
                    <label>Submitted by<select value={evidenceParty} onChange={(event) => setEvidenceParty(event.target.value as EvidenceParty)}><option value="buyer">Buyer</option><option value="vendor">Vendor</option></select></label>
                    <label>Evidence items (one per line)<textarea value={evidenceItems} onChange={(event) => setEvidenceItems(event.target.value)} placeholder={"ipfs://bafy…\nsha256:9f2c…delivery-note"} /></label>
                    <label>Note (optional, stays here)<input maxLength={160} value={evidenceNote} onChange={(event) => setEvidenceNote(event.target.value)} placeholder="photos and the signed delivery note" /></label>
                    <textarea readOnly value={evidenceDigest} placeholder="The evidence digest appears here: item hashes and a root, never the item content." />
                    <div><button type="button" onClick={commitEvidence} disabled={!disputeCase || Boolean(busy)}>{busy === "evidence" ? "Committing…" : "Commit & copy evidence digest"}</button></div>
                  </section>

                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Outcome attestation</span><h3>Disclosable outcome record</h3></div>
                    <p>A hash binding this case and resolution to the arbiter&apos;s fault finding. A vindicated party may share it, and a counterparty can later verify it against the full resolution. It is not on-chain, not a portable score, and not a reputation system.</p>
                    <textarea readOnly value={outcome} placeholder="Build the attestation above to copy a disclosable record of this outcome." />
                    <div><button type="button" onClick={shareOutcome} disabled={Boolean(busy)}>Build &amp; copy attestation</button></div>
                  </section>
                  {visibility ? (
                    <section className={styles.card}>
                      <div><span>Visibility model</span><h3>Who sees what</h3></div>
                      <div className={styles.visibility}>
                        <div><span>This browser only</span><p>{visibility.applicationOnly.join(" · ")}</p></div>
                        <div><span>Wallet request</span><p>{visibility.walletRequest.join(" · ")}</p></div>
                        <div><span>Hidden in-pool</span><p>{visibility.hiddenInPool.join(" · ")}</p></div>
                        <div><span>Public or observable</span><p>{visibility.publicOrObservable.join(" · ")}</p></div>
                      </div>
                      <small className={styles.limitation}>{visibility.limitation}</small>
                    </section>
                  ) : null}

                  {trust ? (
                    <section className={styles.card}>
                      <div><span>Trust model</span><h3>Not escrowed, not proven, not on-chain reputation</h3></div>
                      <p>{trust.statement}</p>
                      <ul className={styles.trustList}>{trust.trustedParties.map((party) => <li key={party}>{party}</li>)}</ul>
                    </section>
                  ) : null}

                  <section className={styles.card}>
                    <div><span>Stated limitations</span><h3>Read before relying on this resolution</h3></div>
                    <ul className={styles.trustList}>{resolution.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
                  </section>
                </div>
              </div>
            )}
            <p className={styles.message} role="status" aria-live="polite">{message}</p>
          </section>
        </div>
      ) : null}
    </section>
  );
}

function toIso(value: string, label: string): string {
  const parsed = new Date(value);
  if (!value || Number.isNaN(parsed.getTime())) throw new Error(`A ${label} is required.`);
  return parsed.toISOString();
}

function shorten(value: string): string {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}
