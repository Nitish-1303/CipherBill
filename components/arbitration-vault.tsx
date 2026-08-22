"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  buildDirectDisputeReleaseActions,
  commitArbitrationVote,
  createDisputeVault,
  DISPUTE_VAULT_POOL_ADDRESS,
  encryptDisputeEvidence,
  generateArbitratorKeypair,
  resolveDisputeVault,
  revealArbitrationVote,
  serializeEncryptedEvidence,
  type ArbitrationChoice,
  type ArbitratorKeypair,
  type DisputeResolution,
  type DisputeVault,
  type EncryptedDisputeEvidenceBundle,
  type EvidenceAttachment,
  type VoteCommitmentBundle,
  type VoteReveal,
} from "@/lib/dispute-vault";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl, STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { baseUnitsToDecimal, decimalToBaseUnits } from "@/lib/strk20/validation";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

interface ArbitratorDraft {
  arbitratorId: string;
  displayAlias: string;
  payoutAddress: string;
  bond: string;
}

const CLAIMANT_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000002201";
const RESPONDENT_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000003301";
const TREASURY_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000004401";
const INITIAL_ARBITRATORS: ArbitratorDraft[] = [
  { arbitratorId: "arb_trade", displayAlias: "Trade standards", payoutAddress: "0x0000000000000000000000000000000000000000000000000000000000006601", bond: "100" },
  { arbitratorId: "arb_legal", displayAlias: "Independent counsel", payoutAddress: "0x0000000000000000000000000000000000000000000000000000000000006602", bond: "100" },
  { arbitratorId: "arb_audit", displayAlias: "Settlement auditor", payoutAddress: "0x0000000000000000000000000000000000000000000000000000000000006603", bond: "100" },
];

export function ArbitrationVault() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [invoiceId, setInvoiceId] = useState("INV-DISPUTE-1042");
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [principal, setPrincipal] = useState("2500");
  const [claimantAlias, setClaimantAlias] = useState("Private supplier");
  const [claimantAddress, setClaimantAddress] = useState(CLAIMANT_ADDRESS);
  const [claimantCollateral, setClaimantCollateral] = useState("250");
  const [respondentAlias, setRespondentAlias] = useState("Private buyer");
  const [respondentAddress, setRespondentAddress] = useState(RESPONDENT_ADDRESS);
  const [respondentCollateral, setRespondentCollateral] = useState("250");
  const [treasuryAddress, setTreasuryAddress] = useState(TREASURY_ADDRESS);
  const [quorum, setQuorum] = useState(2);
  const [loserSlashBps, setLoserSlashBps] = useState(2500);
  const [nonRevealSlashBps, setNonRevealSlashBps] = useState(10000);
  const [commitDeadline, setCommitDeadline] = useState("");
  const [revealDeadline, setRevealDeadline] = useState("");
  const [arbitrators, setArbitrators] = useState<ArbitratorDraft[]>(INITIAL_ARBITRATORS);
  const [statement, setStatement] = useState("Goods were delivered under the encrypted invoice terms; the attached digest binds the signed acceptance record.");
  const [submittedBy, setSubmittedBy] = useState<"claimant" | "respondent">("claimant");
  const [attachments, setAttachments] = useState<EvidenceAttachment[]>([]);
  const [keys, setKeys] = useState<Record<string, ArbitratorKeypair>>({});
  const [caseVault, setCaseVault] = useState<DisputeVault | null>(null);
  const [evidence, setEvidence] = useState<EncryptedDisputeEvidenceBundle | null>(null);
  const [choices, setChoices] = useState<Record<string, ArbitrationChoice>>({});
  const [ballots, setBallots] = useState<Record<string, VoteCommitmentBundle>>({});
  const [reveals, setReveals] = useState<Record<string, VoteReveal>>({});
  const [resolution, setResolution] = useState<DisputeResolution | null>(null);
  const [transactionHash, setTransactionHash] = useState("");
  const [message, setMessage] = useState("Prepare encrypted evidence and a bonded panel. Nothing is uploaded by this portal.");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => new Date());
  const submitLock = useRef(false);

  useEffect(() => {
    const base = Date.now();
    setCommitDeadline(toDateTimeLocal(new Date(base + 60 * 60 * 1_000)));
    setRevealDeadline(toDateTimeLocal(new Date(base + 2 * 60 * 60 * 1_000)));
    const interval = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(interval);
  }, []);

  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const phase = useMemo(() => {
    if (!caseVault) return "setup" as const;
    if (now.getTime() <= Date.parse(caseVault.commitDeadline)) return "commit" as const;
    if (now.getTime() <= Date.parse(caseVault.revealDeadline)) return "reveal" as const;
    return "resolve" as const;
  }, [caseVault, now]);
  const committedCount = Object.keys(ballots).length;
  const revealedCount = Object.keys(reveals).length;

  function updateArbitrator(index: number, field: keyof ArbitratorDraft, value: string) {
    setArbitrators((current) => current.map((item, candidate) => candidate === index ? { ...item, [field]: value } : item));
  }

  async function addEvidenceFiles(files: FileList | null) {
    if (!files?.length) return;
    setBusy(true);
    try {
      const remaining = Math.max(0, 12 - attachments.length);
      const selected = [...files].slice(0, remaining);
      const hashed = await Promise.all(selected.map(async (file): Promise<EvidenceAttachment> => ({
        name: file.name,
        mediaType: file.type || "application/octet-stream",
        size: file.size,
        digest: `sha256:${await sha256Base64Url(await file.arrayBuffer())}`,
      })));
      setAttachments((current) => [...current, ...hashed]);
      setMessage(`${hashed.length} file${hashed.length === 1 ? "" : "s"} hashed locally. File bytes never left this browser.`);
    } catch {
      setMessage("One or more evidence files could not be hashed.");
    } finally {
      setBusy(false);
    }
  }

  async function createCase(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("Encrypting evidence, generating panel keys, and binding the collateral ledger locally...");
    try {
      const panelKeys = Object.fromEntries(arbitrators.map((item) => [item.arbitratorId, generateArbitratorKeypair()]));
      const evidenceBundle = await encryptDisputeEvidence({
        disputeReference: invoiceId,
        submittedBy,
        statement,
        attachments,
        submittedAt: new Date().toISOString(),
      });
      const created = createDisputeVault({
        invoiceId,
        tokenAddress,
        invoicePrincipalBaseUnits: decimalToBaseUnits(principal),
        claimant: { displayAlias: claimantAlias, payoutAddress: claimantAddress, collateralBaseUnits: decimalToBaseUnits(claimantCollateral) },
        respondent: { displayAlias: respondentAlias, payoutAddress: respondentAddress, collateralBaseUnits: decimalToBaseUnits(respondentCollateral) },
        arbitrators: arbitrators.map((item) => ({
          ...item,
          bondBaseUnits: decimalToBaseUnits(item.bond),
          votingPublicKey: panelKeys[item.arbitratorId].publicKey,
        })),
        quorum,
        commitDeadline: new Date(commitDeadline).toISOString(),
        revealDeadline: new Date(revealDeadline).toISOString(),
        evidenceCommitment: evidenceBundle.envelope.evidenceCommitment,
        treasuryAddress,
        loserCollateralSlashBps: loserSlashBps,
        nonRevealBondSlashBps: nonRevealSlashBps,
      });
      setKeys(panelKeys);
      setEvidence(evidenceBundle);
      setCaseVault(created);
      setChoices(Object.fromEntries(arbitrators.map((item) => [item.arbitratorId, "split"])));
      setBallots({});
      setReveals({});
      setResolution(null);
      setTransactionHash("");
      setMessage(`Vault ${created.vaultId} sealed. Download secrets separately before any arbitrator commits.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The dispute vault could not be created.");
    } finally {
      setBusy(false);
    }
  }

  function commitVote(arbitratorId: string) {
    if (!caseVault || !keys[arbitratorId]) return;
    try {
      const ballot = commitArbitrationVote(caseVault, arbitratorId, choices[arbitratorId] ?? "split", keys[arbitratorId].privateKey);
      setBallots((current) => ({ ...current, [arbitratorId]: ballot }));
      setReveals((current) => { const next = { ...current }; delete next[arbitratorId]; return next; });
      setResolution(null);
      setMessage(`${arbitratorId} published an authenticated hiding commitment. Its choice is absent from the public record.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Vote commitment failed."); }
  }

  function revealVote(arbitratorId: string) {
    if (!caseVault || !ballots[arbitratorId]) return;
    try {
      const opened = revealArbitrationVote(caseVault, ballots[arbitratorId].commitment, ballots[arbitratorId].opening);
      setReveals((current) => ({ ...current, [arbitratorId]: opened }));
      setResolution(null);
      setMessage(`${arbitratorId} revealed a valid opening. The salted commitment now verifies against ${opened.choice}.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Vote reveal failed."); }
  }

  function resolveCase() {
    if (!caseVault) return;
    try {
      const result = resolveDisputeVault(caseVault, Object.values(ballots).map((item) => item.commitment), Object.values(reveals));
      setResolution(result);
      setTransactionHash("");
      setMessage(`Resolution committed: ${humanize(result.outcome)}. ${result.slashingEvents.length} slash event${result.slashingEvents.length === 1 ? "" : "s"} conserved exactly across the vault ledger.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Dispute resolution failed."); }
  }

  async function submitSettlement() {
    if (!caseVault || !resolution || !account || !walletReady || !acquireSubmission(submitLock)) return;
    setBusy(true);
    setTransactionHash("");
    try {
      const actions = buildDirectDisputeReleaseActions(caseVault, resolution);
      setMessage(`Confirm ${actions.length} private STRK20 allocation${actions.length === 1 ? "" : "s"} in your wallet...`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setTransactionHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed"
        ? "Private settlement allocations confirmed inside the STRK20 pool."
        : "Settlement submitted; confirmation remains pending and the transaction hash is preserved below.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Private dispute settlement failed.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(false);
    }
  }

  function resetCase() {
    setCaseVault(null); setEvidence(null); setKeys({}); setBallots({}); setReveals({}); setResolution(null); setTransactionHash("");
    setMessage("Prepare a new encrypted evidence package and bonded arbitration panel.");
  }

  return (
    <section className="arbitration-vault" aria-labelledby="arbitration-title">
      <header className="arbitration-hero">
        <div><span>Anonymous commercial justice layer</span><h2 id="arbitration-title">Dispute without disclosure.</h2><p>Bind private invoice evidence to a bonded commit-reveal panel, calculate slashing deterministically, and settle awards through STRK20.</p></div>
        <div className="arbitration-pool"><span><i /> STRK20 mainnet pool</span><code>{shorten(DISPUTE_VAULT_POOL_ADDRESS, 14, 11)}</code><small>Client proof workspace</small></div>
      </header>

      <div className="arbitration-guarantees">
        <article><b>01</b><div><strong>Opaque evidence</strong><p>AES-GCM payloads and local attachment hashing.</p></div></article>
        <article><b>02</b><div><strong>Hidden ballots</strong><p>Salted Poseidon commitments plus Schnorr authorization.</p></div></article>
        <article><b>03</b><div><strong>Conserved slashing</strong><p>Bigint-only allocation with exact vault reconciliation.</p></div></article>
      </div>

      {!caseVault ? (
        <form className="arbitration-composer" onSubmit={createCase}>
          <section className="arbitration-form-card">
            <div className="arbitration-section-title"><span>Case 01</span><h3>Invoice & bonded collateral</h3></div>
            <div className="arbitration-form-grid">
              <label>Private invoice reference<input required pattern="[A-Za-z0-9_-]+" value={invoiceId} onChange={(event) => setInvoiceId(event.target.value)} /></label>
              <label className="arbitration-wide">Settlement token<input required value={tokenAddress} onChange={(event) => setTokenAddress(event.target.value)} /></label>
              <label>Invoice principal<input required inputMode="decimal" value={principal} onChange={(event) => setPrincipal(cleanAmount(event.target.value))} /><small>STRK-denominated display units</small></label>
              <label>Claimant alias<input required value={claimantAlias} onChange={(event) => setClaimantAlias(event.target.value)} /></label>
              <label className="arbitration-wide">Claimant payout address<input required value={claimantAddress} onChange={(event) => setClaimantAddress(event.target.value)} /></label>
              <label>Claimant collateral<input required inputMode="decimal" value={claimantCollateral} onChange={(event) => setClaimantCollateral(cleanAmount(event.target.value))} /></label>
              <label>Respondent alias<input required value={respondentAlias} onChange={(event) => setRespondentAlias(event.target.value)} /></label>
              <label className="arbitration-wide">Respondent payout address<input required value={respondentAddress} onChange={(event) => setRespondentAddress(event.target.value)} /></label>
              <label>Respondent collateral<input required inputMode="decimal" value={respondentCollateral} onChange={(event) => setRespondentCollateral(cleanAmount(event.target.value))} /></label>
            </div>
          </section>

          <section className="arbitration-form-card evidence-card">
            <div className="arbitration-section-title"><span>Evidence 02</span><h3>Seal the evidence room</h3></div>
            <div className="arbitration-evidence-meta"><label>Submitted by<select value={submittedBy} onChange={(event) => setSubmittedBy(event.target.value as "claimant" | "respondent")}><option value="claimant">Claimant</option><option value="respondent">Respondent</option></select></label><label className="arbitration-file">Hash attachments<input type="file" multiple onChange={(event) => void addEvidenceFiles(event.target.files)} /><span>Choose local files</span></label></div>
            <label>Encrypted statement<textarea required rows={7} maxLength={12000} value={statement} onChange={(event) => setStatement(event.target.value)} /></label>
            <div className="evidence-digests">
              {attachments.length ? attachments.map((item, index) => <div key={`${item.digest}-${index}`}><span>{shorten(item.name, 20, 7)}</span><code>{shorten(item.digest, 15, 10)}</code><button type="button" onClick={() => setAttachments((current) => current.filter((_, candidate) => candidate !== index))}>Remove</button></div>) : <p>No files selected. Files are hashed locally and never uploaded.</p>}
            </div>
          </section>

          <section className="arbitration-form-card panel-card">
            <div className="arbitration-section-title"><span>Panel 03</span><h3>Configure bonded adjudicators</h3></div>
            <div className="arbitrator-editor-header"><span>Identity</span><span>Payout address</span><span>Bond</span></div>
            {arbitrators.map((item, index) => <div className="arbitrator-editor" key={item.arbitratorId}><b>{index + 1}</b><div><input aria-label={`Arbitrator ${index + 1} ID`} required pattern="[A-Za-z0-9_-]+" value={item.arbitratorId} onChange={(event) => updateArbitrator(index, "arbitratorId", event.target.value)} /><input aria-label={`Arbitrator ${index + 1} alias`} required value={item.displayAlias} onChange={(event) => updateArbitrator(index, "displayAlias", event.target.value)} /></div><input aria-label={`Arbitrator ${index + 1} payout address`} required value={item.payoutAddress} onChange={(event) => updateArbitrator(index, "payoutAddress", event.target.value)} /><input aria-label={`Arbitrator ${index + 1} bond`} required inputMode="decimal" value={item.bond} onChange={(event) => updateArbitrator(index, "bond", cleanAmount(event.target.value))} /></div>)}
            <div className="arbitration-policy-grid">
              <label>Quorum<select value={quorum} onChange={(event) => setQuorum(Number(event.target.value))}><option value={2}>2 of 3</option><option value={3}>3 of 3</option></select></label>
              <label>Commit deadline<input required type="datetime-local" value={commitDeadline} onChange={(event) => setCommitDeadline(event.target.value)} /></label>
              <label>Reveal deadline<input required type="datetime-local" value={revealDeadline} onChange={(event) => setRevealDeadline(event.target.value)} /></label>
              <label>Loser slash<input type="number" min={0} max={100} value={loserSlashBps / 100} onChange={(event) => setLoserSlashBps(Math.round(Number(event.target.value) * 100))} /><small>Percent of losing collateral</small></label>
              <label>Non-reveal slash<input type="number" min={0} max={100} value={nonRevealSlashBps / 100} onChange={(event) => setNonRevealSlashBps(Math.round(Number(event.target.value) * 100))} /><small>Honest minority votes are never slashed</small></label>
              <label className="arbitration-wide">Fallback treasury<input required value={treasuryAddress} onChange={(event) => setTreasuryAddress(event.target.value)} /></label>
            </div>
            <div className="arbitration-dealer-warning"><strong>Prototype key ceremony</strong><p>This demo creates each voting secret in this browser so the full flow is inspectable. Production arbitrators should create keys on their own devices and share only public keys.</p></div>
            <button className="arbitration-primary" type="submit" disabled={busy || !commitDeadline || !revealDeadline}>{busy ? "Sealing vault..." : "Create encrypted dispute vault"}</button>
          </section>
        </form>
      ) : (
        <div className="arbitration-workspace">
          <aside className="arbitration-case-rail">
            <span>Active mandate</span><h3>{caseVault.invoiceId}</h3><code>{caseVault.vaultId}</code>
            <div className="case-phase-list"><div className={phase === "commit" ? "active" : "done"}><b>01</b><span>Commit ballots<small>{committedCount}/{caseVault.arbitrators.length} received</small></span></div><div className={phase === "reveal" ? "active" : phase === "resolve" ? "done" : ""}><b>02</b><span>Reveal openings<small>{revealedCount}/{caseVault.arbitrators.length} verified</small></span></div><div className={phase === "resolve" ? "active" : ""}><b>03</b><span>Resolve & release<small>{resolution ? humanize(resolution.outcome) : "Awaiting timelock"}</small></span></div></div>
            <dl><div><dt>Vault total</dt><dd>{formatToken(caseVault.totalVaultBaseUnits)} STRK</dd></div><div><dt>Quorum</dt><dd>{caseVault.quorum}/{caseVault.arbitrators.length}</dd></div><div><dt>Evidence</dt><dd>{shorten(caseVault.evidenceCommitment, 8, 6)}</dd></div></dl>
            <button type="button" onClick={resetCase}>New dispute</button>
          </aside>

          <div className="arbitration-main">
            <section className="arbitration-timeline">
              <div><span>Commit closes</span><strong>{formatDate(caseVault.commitDeadline)}</strong><small>{phase === "commit" ? formatCountdown(Date.parse(caseVault.commitDeadline) - now.getTime()) : "Window closed"}</small></div>
              <div><span>Reveal closes</span><strong>{formatDate(caseVault.revealDeadline)}</strong><small>{phase === "reveal" ? formatCountdown(Date.parse(caseVault.revealDeadline) - now.getTime()) : phase === "commit" ? "Not open" : "Ready to resolve"}</small></div>
              <div><span>Enforcement</span><strong>{resolution ? "Ledger verified" : "Time-locked"}</strong><small>Exact bigint conservation</small></div>
            </section>

            <section className="arbitration-room">
              <div className="arbitration-room-title"><div><span>Encrypted evidence room</span><h3>Review package</h3></div><div className="evidence-lock">AES-256 <i /> Locked</div></div>
              <p>Invoice reference, statement, attachment names, and digests exist only inside the encrypted envelope. The public case binds one opaque commitment.</p>
              <div className="evidence-export-grid"><button type="button" onClick={() => evidence && downloadText(`${caseVault.vaultId}.evidence.json`, serializeEncryptedEvidence(evidence.envelope), "application/json")}>Download encrypted evidence</button><button type="button" onClick={() => evidence && downloadText(`${caseVault.vaultId}.evidence-key`, evidence.accessKey, "text/plain")}>Download access key separately</button><button type="button" onClick={() => downloadText(`${caseVault.vaultId}.manifest.json`, JSON.stringify(caseVault, null, 2), "application/json")}>Export local case manifest</button></div>
            </section>

            <section className="arbitration-ballots">
              <div className="arbitration-room-title"><div><span>Commit-reveal panel</span><h3>Bonded votes</h3></div><div className={`phase-badge ${phase}`}>{phase} phase</div></div>
              <div className="ballot-list">
                {caseVault.arbitrators.map((arbitrator, index) => {
                  const ballot = ballots[arbitrator.arbitratorId];
                  const opened = reveals[arbitrator.arbitratorId];
                  return <article className={opened ? "revealed" : ballot ? "committed" : ""} key={arbitrator.arbitratorId}>
                    <div className="ballot-identity"><b>{String(index + 1).padStart(2, "0")}</b><div><strong>{arbitrator.displayAlias}</strong><code>{arbitrator.arbitratorId}</code></div></div>
                    <div className="ballot-bond"><span>Bond</span><strong>{formatToken(arbitrator.bondBaseUnits)} STRK</strong></div>
                    <div className="ballot-proof"><span>{opened ? "Revealed verdict" : ballot ? "Hiding commitment" : "No commitment"}</span><strong>{opened ? humanize(opened.choice) : ballot ? shorten(ballot.commitment.commitment, 9, 7) : "—"}</strong></div>
                    <select aria-label={`${arbitrator.displayAlias} vote`} disabled={phase !== "commit" || Boolean(ballot)} value={choices[arbitrator.arbitratorId] ?? "split"} onChange={(event) => setChoices((current) => ({ ...current, [arbitrator.arbitratorId]: event.target.value as ArbitrationChoice }))}><option value="claimant">Award claimant</option><option value="respondent">Award respondent</option><option value="split">Split award</option></select>
                    {!ballot ? <button type="button" disabled={phase !== "commit"} onClick={() => commitVote(arbitrator.arbitratorId)}>Commit</button> : !opened ? <button type="button" disabled={phase !== "reveal"} onClick={() => revealVote(arbitrator.arbitratorId)}>Reveal</button> : <span className="verified-mark">Verified</span>}
                    <button className="ballot-download" type="button" onClick={() => downloadText(`${caseVault.vaultId}-${arbitrator.arbitratorId}.secret.json`, JSON.stringify({ keypair: keys[arbitrator.arbitratorId], opening: ballot?.opening ?? null }, null, 2), "application/json")}>Download secret</button>
                  </article>;
                })}
              </div>
              <div className="ballot-privacy-note"><strong>Why the ballot stays hidden</strong><p>The public commitment contains neither choice nor salt. A Schnorr proof authenticates the panel member without exposing their private voting key. This is a hiding commit-reveal protocol, not a zk-SNARK.</p></div>
            </section>

            <section className="arbitration-resolution">
              <div className="arbitration-room-title"><div><span>Deterministic slashing ledger</span><h3>Resolution & release</h3></div><button className="arbitration-primary" type="button" disabled={phase !== "resolve" || busy} onClick={resolveCase}>{resolution ? "Recompute resolution" : "Resolve after timelock"}</button></div>
              {resolution ? <>
                <div className="resolution-summary"><div><span>Outcome</span><strong>{humanize(resolution.outcome)}</strong></div><div><span>Valid reveals</span><strong>{resolution.validRevealCount}/{caseVault.arbitrators.length}</strong></div><div><span>Claimant / Respondent / Split</span><strong>{resolution.tallies.claimant} / {resolution.tallies.respondent} / {resolution.tallies.split}</strong></div><div><span>Conserved total</span><strong>{formatToken(resolution.totalVaultBaseUnits)} STRK</strong></div></div>
                <div className="resolution-ledger"><div className="ledger-column"><span>Release allocations</span>{resolution.allocations.map((item, index) => <div key={`${item.recipientAddress}-${item.reason}-${index}`}><code>{shorten(item.recipientAddress, 9, 7)}</code><small>{humanize(item.reason)}</small><strong>{formatToken(item.amountBaseUnits)} STRK</strong></div>)}</div><div className="ledger-column slash-column"><span>Slash events</span>{resolution.slashingEvents.length ? resolution.slashingEvents.map((item, index) => <div key={`${item.subjectId}-${index}`}><code>{item.subjectId}</code><small>{humanize(item.reason)}</small><strong>−{formatToken(item.amountBaseUnits)} STRK</strong></div>) : <p>No arbitrator bonds were slashed.</p>}</div></div>
                <div className="release-boundary"><div><strong>Direct private settlement</strong><p>The connected wallet can execute these in-pool transfers. Browser policy remains bypassable by a custodian.</p></div><div><strong>Unavoidable enforcement</strong><p>Use an audited stateful <code>privacy_invoke</code> helper. Open-note amounts at that helper edge are public.</p></div></div>
                <div className="resolution-actions"><button type="button" disabled={!walletReady || busy || Boolean(transactionHash)} onClick={submitSettlement}>{busy ? "Submitting private allocations..." : transactionHash ? "Settlement submitted" : "Release through STRK20 wallet"}</button>{!walletReady ? <WalletConnect /> : null}{transactionHash ? <a href={getStarknetExplorerTransactionUrl(transactionHash)} target="_blank" rel="noreferrer">Track transaction ↗</a> : null}</div>
              </> : <div className="resolution-empty"><span>⌛</span><h4>Resolution is timelocked</h4><p>After the reveal deadline, the engine filters invalid openings, tests quorum, computes the award, and redistributes every slashed base unit.</p></div>}
            </section>
          </div>
        </div>
      )}
      <p className="arbitration-message" role="status">{message}</p>
    </section>
  );
}

function cleanAmount(value: string): string { return value.replaceAll(",", "").replace(/[^\d.]/g, ""); }
function shorten(value: string, start: number, end: number): string { return value.length <= start + end + 1 ? value : `${value.slice(0, start)}…${value.slice(-end)}`; }
function humanize(value: string): string { return value.replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase()); }
function formatDate(value: string): string { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }
function formatToken(value: string): string {
  const [whole, fraction = ""] = baseUnitsToDecimal(value).split(".");
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const visibleFraction = fraction.slice(0, 4).replace(/0+$/, "");
  return visibleFraction ? `${grouped}.${visibleFraction}` : grouped;
}
function formatCountdown(ms: number): string { const seconds = Math.max(0, Math.floor(ms / 1000)); const hours = Math.floor(seconds / 3600); const minutes = Math.floor((seconds % 3600) / 60); return `${hours}h ${minutes}m ${seconds % 60}s`; }
function toDateTimeLocal(value: Date): string { const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000); return local.toISOString().slice(0, 16); }

async function sha256Base64Url(value: ArrayBuffer): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function downloadText(filename: string, value: string, type: string) {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}
