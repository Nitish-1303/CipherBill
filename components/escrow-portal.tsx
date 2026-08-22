"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  buildDirectEscrowReleaseActions,
  createEscrowApproval,
  createMultiPartyEscrow,
  getEscrowMilestoneStatus,
  MAX_ESCROW_MILESTONES,
  MAX_ESCROW_PARTICIPANTS,
  MULTISIG_ESCROW_POOL_ADDRESS,
  parseEscrowShare,
  serializeEscrowShare,
  unlockEscrowMilestone,
  verifyEscrowShare,
  type EscrowApproval,
  type EscrowKeyShare,
  type MultiPartyEscrowBundle,
  type TimelockEvidence,
  type UnlockedEscrowMilestone,
} from "@/lib/multisig-escrow";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { baseUnitsToDecimal, decimalToBaseUnits } from "@/lib/strk20/validation";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

interface GuardianDraft {
  participantId: string;
  displayAlias: string;
}

interface MilestoneDraft {
  milestoneId: string;
  title: string;
  recipientAddress: string;
  amount: string;
  unlockAt: string;
}

const INITIAL_GUARDIANS: GuardianDraft[] = [
  { participantId: "buyer_controller", displayAlias: "Buyer controller" },
  { participantId: "supplier_controller", displayAlias: "Supplier controller" },
  { participantId: "independent_auditor", displayAlias: "Independent auditor" },
];

const EMPTY_MILESTONE: MilestoneDraft = {
  milestoneId: "delivery_acceptance",
  title: "Delivery acceptance",
  recipientAddress: "",
  amount: "",
  unlockAt: "",
};

export function EscrowPortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [organizationName, setOrganizationName] = useState("Cipher Industrial");
  const [invoiceId, setInvoiceId] = useState("INV-1042");
  const [threshold, setThreshold] = useState(2);
  const [guardians, setGuardians] = useState<GuardianDraft[]>(INITIAL_GUARDIANS);
  const [milestones, setMilestones] = useState<MilestoneDraft[]>([{ ...EMPTY_MILESTONE }]);
  const [bundle, setBundle] = useState<MultiPartyEscrowBundle | null>(null);
  const [selectedMilestoneId, setSelectedMilestoneId] = useState("");
  const [shareInput, setShareInput] = useState("");
  const [collectedShares, setCollectedShares] = useState<EscrowKeyShare[]>([]);
  const [approvals, setApprovals] = useState<EscrowApproval[]>([]);
  const [unlocked, setUnlocked] = useState<UnlockedEscrowMilestone | null>(null);
  const [transactionHash, setTransactionHash] = useState("");
  const [now, setNow] = useState(() => new Date());
  const [message, setMessage] = useState("Create an encrypted envelope, distribute shares separately, then collect a quorum at release time.");
  const [busy, setBusy] = useState(false);
  const releaseLock = useRef(false);

  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const selectedMilestone = bundle?.envelope.milestones.find((item) => item.milestoneId === selectedMilestoneId) ?? null;
  const status = useMemo(
    () => bundle && selectedMilestoneId
      ? getEscrowMilestoneStatus(bundle.envelope, selectedMilestoneId, approvals, now)
      : null,
    [approvals, bundle, now, selectedMilestoneId],
  );

  useEffect(() => {
    const interval = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(interval);
  }, []);

  function updateGuardian(index: number, field: keyof GuardianDraft, value: string) {
    setGuardians((current) => current.map((guardian, candidate) => candidate === index ? { ...guardian, [field]: value } : guardian));
  }

  function addGuardian() {
    if (guardians.length >= MAX_ESCROW_PARTICIPANTS) return;
    const next = guardians.length + 1;
    setGuardians((current) => [...current, { participantId: `guardian_${next}`, displayAlias: `Guardian ${next}` }]);
  }

  function removeGuardian(index: number) {
    if (guardians.length <= 2) return;
    setGuardians((current) => current.filter((_, candidate) => candidate !== index));
    setThreshold((current) => Math.min(current, guardians.length - 1));
  }

  function updateMilestone(index: number, field: keyof MilestoneDraft, value: string) {
    setMilestones((current) => current.map((milestone, candidate) => candidate === index ? { ...milestone, [field]: value } : milestone));
  }

  function addMilestone() {
    if (milestones.length >= MAX_ESCROW_MILESTONES) return;
    const next = milestones.length + 1;
    setMilestones((current) => [...current, { ...EMPTY_MILESTONE, milestoneId: `milestone_${next}`, title: `Milestone ${next}` }]);
  }

  function removeMilestone(index: number) {
    if (milestones.length <= 1) return;
    setMilestones((current) => current.filter((_, candidate) => candidate !== index));
  }

  async function createEscrow(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("Encrypting milestone terms and generating verifiable guardian shares locally…");
    try {
      const created = await createMultiPartyEscrow({
        invoiceId,
        organizationName,
        threshold,
        participants: guardians,
        milestones: milestones.map((milestone) => ({
          milestoneId: milestone.milestoneId,
          title: milestone.title,
          recipientAddress: milestone.recipientAddress,
          amountBaseUnits: decimalToBaseUnits(milestone.amount),
          unlockAt: new Date(milestone.unlockAt).toISOString(),
        })),
      });
      setBundle(created);
      setSelectedMilestoneId(created.envelope.milestones[0].milestoneId);
      setApprovals([]);
      setCollectedShares([]);
      setUnlocked(null);
      setTransactionHash("");
      setShareInput("");
      setMessage(`Escrow ${created.envelope.escrowId} created. Download and deliver each bearer share over a separate authenticated channel.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Escrow generation failed.");
    } finally {
      setBusy(false);
    }
  }

  async function copyText(value: string, confirmation: string) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage(confirmation);
    } catch {
      setMessage("Clipboard permission was denied. Select and copy the value manually.");
    }
  }

  function downloadShare(share: EscrowKeyShare) {
    const encoded = serializeEscrowShare(share);
    const blob = new Blob([encoded], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${share.escrowId}-${share.participantId}.escrow-share`;
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage(`Downloaded the bearer share for ${share.participantId}. Do not send it beside the public envelope.`);
  }

  function importAndApprove(encoded = shareInput) {
    if (!bundle || !selectedMilestoneId) return;
    try {
      const share = parseEscrowShare(encoded.trim());
      if (!verifyEscrowShare(bundle.envelope, share)) throw new Error("This share is altered or belongs to another escrow.");
      const approval = createEscrowApproval(bundle.envelope, selectedMilestoneId, share);
      setCollectedShares((current) => [...current.filter((candidate) => candidate.participantId !== share.participantId), share]);
      setApprovals((current) => [
        ...current.filter((candidate) => !(candidate.milestoneId === selectedMilestoneId && candidate.participantId === share.participantId)),
        approval,
      ]);
      setUnlocked(null);
      setTransactionHash("");
      setShareInput("");
      setMessage(`${share.participantId} produced a valid Schnorr approval for ${selectedMilestoneId}. The imported bearer share remains in memory only.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The guardian share could not be approved.");
    }
  }

  async function verifyRelease() {
    if (!bundle || !selectedMilestoneId) return;
    setBusy(true);
    try {
      const evidence: TimelockEvidence = { source: "local_clock", timestamp: new Date().toISOString() };
      const result = await unlockEscrowMilestone(bundle.envelope, selectedMilestoneId, collectedShares, approvals, evidence);
      setUnlocked(result);
      setMessage("Quorum and encrypted release commitments verified. Local-clock evidence is a preview; wallet submission rechecks an accepted Starknet block.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Conditional release verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function submitRelease() {
    if (!bundle || !selectedMilestoneId || !account || !walletReady || !acquireSubmission(releaseLock)) return;
    setBusy(true);
    setTransactionHash("");
    try {
      setMessage("Reading the latest accepted Starknet block for verifiable timelock evidence…");
      const block = await account.provider.getBlock("latest");
      const evidence: TimelockEvidence = {
        source: "starknet_block",
        timestamp: new Date(Number(block.timestamp) * 1_000).toISOString(),
        chainId: "SN_MAIN",
        blockNumber: block.block_number,
        blockHash: block.block_hash,
      };
      const verified = await unlockEscrowMilestone(bundle.envelope, selectedMilestoneId, collectedShares, approvals, evidence);
      setUnlocked(verified);
      const actions = buildDirectEscrowReleaseActions(verified);
      setMessage("Conditions verified against Starknet block time. Confirm the private STRK20 transfer in your wallet…");
      const submission = await account.strk20InvokeTransaction(actions);
      setTransactionHash(submission.transaction_hash);
      const transaction = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submission.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submission.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(transaction.status === "confirmed"
        ? "Milestone settlement confirmed inside the STRK20 privacy pool."
        : "The transfer was submitted. Confirmation is still pending; the transaction hash is preserved below.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Private escrow release failed.");
    } finally {
      releaseSubmission(releaseLock);
      setBusy(false);
    }
  }

  return (
    <section className="escrow-portal" aria-labelledby="escrow-title">
      <header className="escrow-hero">
        <div>
          <span className="escrow-kicker">Enterprise settlement control plane</span>
          <h2 id="escrow-title">Encrypted multi-party escrow</h2>
          <p>Seal invoice terms client-side, require a cryptographic guardian quorum, and release only after a verifiable milestone timelock.</p>
        </div>
        <div className="escrow-pool-badge">
          <span>STRK20 privacy pool</span>
          <code>{shorten(MULTISIG_ESCROW_POOL_ADDRESS, 12, 10)}</code>
          <i>Starknet mainnet</i>
        </div>
      </header>

      <div className="escrow-principles" aria-label="Escrow guarantees">
        <div><span>01</span><strong>Encrypted terms</strong><small>AES-GCM invoice payloads never enter the public envelope.</small></div>
        <div><span>02</span><strong>Threshold control</strong><small>Feldman-verifiable shares and Schnorr guardian approvals.</small></div>
        <div><span>03</span><strong>Timed release</strong><small>Submission rechecks the latest accepted Starknet block timestamp.</small></div>
      </div>

      {!bundle ? (
        <form className="escrow-composer" onSubmit={createEscrow}>
          <div className="escrow-section-heading"><span>New mandate</span><h3>Configure settlement authority</h3></div>
          <div className="escrow-form-grid">
            <label>Organization<input required value={organizationName} maxLength={80} onChange={(event) => setOrganizationName(event.target.value)} /></label>
            <label>Private invoice reference<input required value={invoiceId} maxLength={64} pattern="[A-Za-z0-9_-]+" onChange={(event) => setInvoiceId(event.target.value)} /></label>
            <label>Approval threshold
              <select value={threshold} onChange={(event) => setThreshold(Number(event.target.value))}>
                {guardians.slice(1).map((_, index) => <option key={index + 2} value={index + 2}>{index + 2} of {guardians.length}</option>)}
              </select>
            </label>
          </div>

          <fieldset className="escrow-fieldset">
            <legend>Guardian committee</legend>
            {guardians.map((guardian, index) => (
              <div className="guardian-editor" key={`${index}-${guardian.participantId}`}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <input aria-label={`Guardian ${index + 1} ID`} required pattern="[A-Za-z0-9_-]+" value={guardian.participantId} onChange={(event) => updateGuardian(index, "participantId", event.target.value)} />
                <input aria-label={`Guardian ${index + 1} alias`} required value={guardian.displayAlias} onChange={(event) => updateGuardian(index, "displayAlias", event.target.value)} />
                <button className="escrow-quiet-button" type="button" disabled={guardians.length <= 2} onClick={() => removeGuardian(index)}>Remove</button>
              </div>
            ))}
            <button className="escrow-outline-button" type="button" disabled={guardians.length >= MAX_ESCROW_PARTICIPANTS} onClick={addGuardian}>+ Add guardian</button>
          </fieldset>

          <fieldset className="escrow-fieldset">
            <legend>Encrypted milestones</legend>
            {milestones.map((milestone, index) => (
              <div className="milestone-editor-card" key={`${index}-${milestone.milestoneId}`}>
                <div className="milestone-editor-top"><strong>Milestone {index + 1}</strong><button className="escrow-quiet-button" type="button" disabled={milestones.length <= 1} onClick={() => removeMilestone(index)}>Remove</button></div>
                <div className="escrow-form-grid">
                  <label>Public milestone ID<input required pattern="[A-Za-z0-9_-]+" value={milestone.milestoneId} onChange={(event) => updateMilestone(index, "milestoneId", event.target.value)} /></label>
                  <label>Private title<input required value={milestone.title} onChange={(event) => updateMilestone(index, "title", event.target.value)} /></label>
                  <label>Private recipient<input required placeholder="0x…" value={milestone.recipientAddress} onChange={(event) => updateMilestone(index, "recipientAddress", event.target.value)} /></label>
                  <label>Private amount (STRK)<input required inputMode="decimal" placeholder="25,000" value={milestone.amount} onChange={(event) => updateMilestone(index, "amount", event.target.value.replaceAll(",", ""))} /></label>
                  <label>Public unlock time<input required type="datetime-local" value={milestone.unlockAt} onChange={(event) => updateMilestone(index, "unlockAt", event.target.value)} /></label>
                </div>
              </div>
            ))}
            <button className="escrow-outline-button" type="button" disabled={milestones.length >= MAX_ESCROW_MILESTONES} onClick={addMilestone}>+ Add encrypted milestone</button>
          </fieldset>

          <div className="escrow-compose-footer">
            <p><strong>Dealer setup:</strong> this browser generates the initial shares. Deliver them separately, then close this session on a trusted device.</p>
            <button type="submit" disabled={busy}>{busy ? "Sealing terms…" : "Create encrypted escrow"}</button>
          </div>
        </form>
      ) : (
        <div className="escrow-workspace">
          <aside className="escrow-sidebar">
            <div className="escrow-id-block"><span>Escrow mandate</span><strong>{bundle.envelope.organizationName}</strong><code>{bundle.envelope.escrowId}</code></div>
            <nav aria-label="Escrow milestones">
              {bundle.envelope.milestones.map((milestone, index) => {
                const itemStatus = getEscrowMilestoneStatus(bundle.envelope, milestone.milestoneId, approvals, now);
                return (
                  <button className={selectedMilestoneId === milestone.milestoneId ? "active" : ""} type="button" key={milestone.milestoneId} onClick={() => { setSelectedMilestoneId(milestone.milestoneId); setUnlocked(null); setTransactionHash(""); }}>
                    <span>{String(index + 1).padStart(2, "0")} · {milestone.milestoneId.replaceAll("_", " ")}</span>
                    <small>{itemStatus.releasable ? "Release ready" : itemStatus.thresholdMet ? "Awaiting timelock" : `${itemStatus.approvals}/${itemStatus.threshold} approvals`}</small>
                  </button>
                );
              })}
            </nav>
            <button className="escrow-outline-button" type="button" onClick={() => { setBundle(null); setApprovals([]); setCollectedShares([]); setUnlocked(null); }}>Create another mandate</button>
          </aside>

          <div className="escrow-main">
            <div className="escrow-status-grid">
              <div><span>Guardian quorum</span><strong>{status?.approvals ?? 0} / {bundle.envelope.threshold}</strong><i className={status?.thresholdMet ? "ok" : ""}>{status?.thresholdMet ? "Threshold met" : "Pending signatures"}</i></div>
              <div><span>Timelock</span><strong>{status?.unlockedByTime ? "Open" : formatCountdown(status?.remainingMs ?? 0)}</strong><i className={status?.unlockedByTime ? "ok" : ""}>{selectedMilestone ? formatDate(selectedMilestone.unlockAt) : "—"}</i></div>
              <div><span>Release state</span><strong>{transactionHash ? "Submitted" : unlocked ? "Verified" : status?.releasable ? "Ready" : "Locked"}</strong><i className={transactionHash ? "ok" : ""}>{transactionHash ? shorten(transactionHash, 8, 7) : "Client-side custody policy"}</i></div>
            </div>

            <section className="escrow-panel">
              <div className="escrow-panel-title"><div><span>Key ceremony</span><h3>Distribute guardian shares</h3></div><button className="escrow-outline-button" type="button" onClick={() => copyText(JSON.stringify(bundle.envelope), "Public encrypted envelope copied.")}>Copy public envelope</button></div>
              <p className="escrow-muted">The envelope reveals aliases, milestone IDs, unlock times, ciphertext, and commitments—not invoice references, titles, recipients, or amounts.</p>
              <div className="share-grid">
                {bundle.shares.map((share) => {
                  const approved = approvals.some((approval) => approval.milestoneId === selectedMilestoneId && approval.participantId === share.participantId);
                  const alias = bundle.envelope.participantSlots.find((slot) => slot.participantId === share.participantId)?.displayAlias;
                  return (
                    <article key={share.participantId} className={approved ? "approved" : ""}>
                      <div><span>Share {share.shareIndex}</span><i>{approved ? "Approved" : "Unopened"}</i></div>
                      <strong>{alias}</strong><code>{share.participantId}</code>
                      <div className="share-actions"><button type="button" onClick={() => downloadShare(share)}>Download</button><button type="button" onClick={() => importAndApprove(serializeEscrowShare(share))}>Approve here</button></div>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="escrow-panel approval-panel">
              <div className="escrow-panel-title"><div><span>Approval workstation</span><h3>Import a guardian bearer share</h3></div><div className="threshold-meter" aria-label={`${status?.approvals ?? 0} of ${bundle.envelope.threshold} approvals`}><i style={{ width: `${Math.min(100, ((status?.approvals ?? 0) / bundle.envelope.threshold) * 100)}%` }} /></div></div>
              <textarea aria-label="Encoded guardian share" value={shareInput} onChange={(event) => setShareInput(event.target.value)} placeholder="Paste cipherbill.escrow-share bearer material…" rows={3} />
              <div className="approval-footer"><p>Approval proves possession using Schnorr verification. Imported shares stay in memory and are required for local threshold reconstruction.</p><button type="button" disabled={!shareInput.trim()} onClick={() => importAndApprove()}>Verify & approve</button></div>
            </section>

            <section className="escrow-panel release-panel">
              <div className="escrow-panel-title"><div><span>Conditional release</span><h3>{selectedMilestoneId.replaceAll("_", " ")}</h3></div><span className={`release-chip ${status?.releasable ? "ready" : ""}`}>{status?.releasable ? "Quorum ready" : "Conditions locked"}</span></div>
              <div className="commitment-list">
                <div><span>Claim commitment</span><code>{selectedMilestone?.claimCommitment}</code></div>
                <div><span>Release commitment</span><code>{selectedMilestone?.releaseCommitment}</code></div>
                <div><span>Encrypted payload</span><code>{selectedMilestone?.ciphertextDigest}</code></div>
              </div>
              {unlocked ? (
                <div className="release-details">
                  <span>Decrypted only after quorum</span>
                  <strong>{unlocked.payload.title}</strong>
                  <div><p><small>Amount</small>{baseUnitsToDecimal(unlocked.payload.amountBaseUnits)} STRK</p><p><small>Recipient</small><code>{shorten(unlocked.payload.recipientAddress, 12, 10)}</code></p></div>
                </div>
              ) : null}
              <div className="release-actions">
                <button className="escrow-outline-button" type="button" disabled={!status?.releasable || busy} onClick={verifyRelease}>Preview verified terms</button>
                <button type="button" disabled={!status?.releasable || !walletReady || busy} onClick={submitRelease}>{busy ? "Verifying…" : "Release privately via STRK20"}</button>
              </div>
              {!walletReady ? <div className="escrow-wallet-row"><span>A mainnet wallet with STRK20 Wallet API support is required for release.</span><WalletConnect /></div> : null}
              {transactionHash ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(transactionHash)} target="_blank" rel="noreferrer">Track submitted release ↗</a> : null}
            </section>

            <section className="escrow-enforcement-note">
              <strong>Enforcement boundary</strong>
              <p>This portal cryptographically verifies the quorum and block timelock before asking the wallet to submit. A custodian can bypass browser policy; unavoidable onchain custody requires an audited, stateful STRK20 <code>privacy_invoke</code> helper. The engine exposes a strict caller-supplied ABI adapter for that deployment path.</p>
            </section>
          </div>
        </div>
      )}

      <p className="escrow-message" role="status">{message}</p>
    </section>
  );
}

function shorten(value: string, start: number, end: number): string {
  return value.length <= start + end + 1 ? value : `${value.slice(0, start)}…${value.slice(-end)}`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatCountdown(milliseconds: number): string {
  const seconds = Math.max(0, Math.floor(milliseconds / 1_000));
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return days ? `${days}d ${hours}h` : `${hours}h ${minutes}m`;
}
