"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  buildContingencyActions,
  buildDeadmanAttestation,
  buildDeadmanPlanDigest,
  createDeadmanPlan,
  DEADMAN_POOL_ADDRESS,
  evaluateLiveness,
  formatDeadmanBaseUnits,
  getDeadmanVisibilityModel,
  MAX_BENEFICIARIES,
  serializeDeadmanAttestation,
  serializeDeadmanPlanDigest,
  summarizeDeadmanTrust,
  type DeadmanBeneficiaryInput,
  type DeadmanPlan,
} from "@/lib/deadman-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./deadman-portal.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type BusyAction = "arm" | "balance" | "route" | "attest" | null;

interface BeneficiaryRow {
  recipient: string;
  shareBps: string;
  label: string;
}

const HOUR_MS = 3_600_000;

/**
 * Liveness-gated contingency portal ("dead-man switch") for the merchant dashboard.
 *
 * Every claim here is deliberately narrow. CipherBill runs a client-side liveness clock, solves the
 * beneficiary split in exact integers, binds the plan with a salted Poseidon commitment, and — only
 * when a live signer chooses — submits the payout as private in-pool transfers. It is not
 * autonomous, not a time-lock, not zero-knowledge, and not escrow: nothing fires on its own, no
 * contract watches the account or holds the funds, and the routed balance stays spendable.
 */
export function DeadmanPortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState("inv_deadman_001");
  const [switchValue, setSwitchValue] = useState("");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetToken, setAssetToken] = useState("");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [beneficiaries, setBeneficiaries] = useState<BeneficiaryRow[]>([
    { recipient: "", shareBps: "6000", label: "" },
    { recipient: "", shareBps: "4000", label: "" },
  ]);
  const [checkInIntervalHours, setCheckInIntervalHours] = useState("24");
  const [graceHours, setGraceHours] = useState("48");
  const [executorLabel, setExecutorLabel] = useState("");
  const [memo, setMemo] = useState("");
  const [plan, setPlan] = useState<DeadmanPlan | null>(null);
  const [lastCheckIn, setLastCheckIn] = useState("");
  const [hoursSince, setHoursSince] = useState("0");
  const [now, setNow] = useState(() => Date.now());
  const [planDigest, setPlanDigest] = useState("");
  const [attestation, setAttestation] = useState("");
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [payoutHash, setPayoutHash] = useState("");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Arm a plan: name beneficiaries and their basis-point shares, set a check-in cadence and grace window, and CipherBill runs the liveness clock in this browser and pre-composes the payout. Nothing sends until you sign it.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const visibility = useMemo(() => plan ? getDeadmanVisibilityModel(plan) : null, [plan]);
  const trust = useMemo(() => plan ? summarizeDeadmanTrust(plan) : null, [plan]);
  const liveness = useMemo(() => {
    if (!plan || !lastCheckIn) return null;
    try {
      return evaluateLiveness(plan, lastCheckIn, new Date(now));
    } catch {
      return null;
    }
  }, [plan, lastCheckIn, now]);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, open]);

  useEffect(() => {
    if (!open || !plan) return;
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, [open, plan]);

  function arm(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("arm");
    try {
      const rows: DeadmanBeneficiaryInput[] = beneficiaries.map((row) => ({
        recipient: row.recipient,
        shareBps: Number(row.shareBps),
        label: row.label || undefined,
      }));
      const nextPlan = createDeadmanPlan({
        invoiceId,
        asset: { symbol: assetSymbol, tokenAddress: assetToken, decimals: Number(assetDecimals) },
        switchValue,
        beneficiaries: rows,
        checkInIntervalHours: Number(checkInIntervalHours),
        graceHours: graceHours ? Number(graceHours) : undefined,
        executorLabel: executorLabel || undefined,
        memo: memo || undefined,
      });
      invalidate();
      setPlan(nextPlan);
      setLastCheckIn(nextPlan.armedAt);
      setHoursSince("0");
      setMessage(`Armed: ${nextPlan.switchValueDisplay} ${nextPlan.asset.symbol} would route to ${nextPlan.beneficiaries.length} beneficiar${nextPlan.beneficiaries.length === 1 ? "y" : "ies"} after a lapse. The liveness clock runs in this browser. Nothing is on-chain and nothing sends until a live signer confirms the payout.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The plan could not be armed.");
    } finally {
      setBusy(null);
    }
  }

  function addBeneficiary(): void {
    if (beneficiaries.length >= MAX_BENEFICIARIES) return;
    setBeneficiaries((rows) => [...rows, { recipient: "", shareBps: "0", label: "" }]);
  }

  function removeBeneficiary(index: number): void {
    setBeneficiaries((rows) => rows.length > 1 ? rows.filter((_, position) => position !== index) : rows);
  }

  function updateBeneficiary(index: number, field: keyof BeneficiaryRow, value: string): void {
    setBeneficiaries((rows) => rows.map((row, position) => position === index ? { ...row, [field]: value } : row));
  }

  function checkInNow(): void {
    setHoursSince("0");
    setLastCheckIn(new Date().toISOString());
    setMessage("Checked in. The liveness clock resets from now, so the account reads as active again and the contingency payout is no longer eligible.");
  }

  function simulateHoursSince(value: string): void {
    setHoursSince(value);
    const hours = Number(value);
    if (!Number.isFinite(hours) || hours < 0) return;
    setLastCheckIn(new Date(Date.now() - hours * HOUR_MS).toISOString());
  }

  async function sharePlanDigest(): Promise<void> {
    if (!plan) return;
    const encoded = serializeDeadmanPlanDigest(buildDeadmanPlanDigest(plan));
    setPlanDigest(encoded);
    await copy(encoded, "Plan digest copied. It carries the invoice ID, cadence, beneficiary count, and the Poseidon commitment only: no amounts, addresses, executor, salt, or memo. Never share the full plan except with a chosen executor.");
  }

  async function buildAttestation(): Promise<void> {
    if (!plan || busy) return;
    setBusy("attest");
    try {
      const attest = buildDeadmanAttestation(plan, { lastCheckInAt: lastCheckIn, triggeredAt: new Date().toISOString() });
      const encoded = serializeDeadmanAttestation(attest);
      setAttestation(encoded);
      await copy(encoded, "Attestation copied. It binds the plan commitment to the claimed last check-in and the trigger time. It is a hash you may disclose, not an on-chain record, a proof of inactivity, or a death certificate.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The attestation could not be built.");
    } finally {
      setBusy(null);
    }
  }

  async function checkCoverage(): Promise<void> {
    if (!plan || !account || !walletReady || busy) return;
    const token = plan.asset.tokenAddress;
    const required = BigInt(plan.switchValueBaseUnits);
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setWalletBalance(balance);
      setMessage(BigInt(balance) >= required
        ? "This shielded balance covers the routed switch value. The pool fee the wallet adds is not included in that comparison."
        : "This shielded balance is below the switch value. The signer must hold the full routed balance before the payout can be sent.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function routePayout(): Promise<void> {
    if (!plan || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    setBusy("route");
    setPayoutHash("");
    try {
      const actions = buildContingencyActions(plan);
      const early = liveness?.state !== "lapsed";
      setMessage(early
        ? `Warning: the plan has not lapsed (it reads "${liveness?.state ?? "unknown"}"). Sending now routes the balance early. This is not blocked — no contract enforces the clock — but confirm you intend to trigger the payout before the lapse.`
        : `Confirm the payout in the signer's wallet: ${actions.length} private in-pool transfer${actions.length === 1 ? "" : "s"} to the beneficiaries. The relayer submits it, so never attribute the sender to the merchant.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setPayoutHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed"
        ? "Payout confirmed inside the pool. The routed balance has moved to the beneficiaries. Nothing was escrowed or automated: a live signer sent it, and the clock never enforced anything on-chain."
        : result.status === "failed"
          ? "The submitted payout reverted. The hash is preserved; re-arm the plan before retrying."
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
    setPlan(null);
    setLastCheckIn("");
    setPlanDigest("");
    setAttestation("");
    setWalletBalance(null);
    setPayoutHash("");
  }

  function resetComposer(): void {
    setSwitchValue("");
    setAssetToken("");
    setBeneficiaries([{ recipient: "", shareBps: "6000", label: "" }, { recipient: "", shareBps: "4000", label: "" }]);
    setExecutorLabel("");
    setMemo("");
    setHoursSince("0");
    invalidate();
    setMessage("Composer reset. Nothing was persisted: plans, salts, beneficiary amounts, and commitments live only in this browser tab.");
  }

  return (
    <section className={styles.launch} aria-labelledby="deadman-launch-title">
      <div className={styles.launchCopy}>
        <span>Liveness-gated contingency &amp; encrypted reminders</span>
        <h2 id="deadman-launch-title">Route on lapse.<br /><em>Prove nothing you needn&apos;t.</em></h2>
        <p>Name the beneficiaries of a shielded balance, set how often you must check in, and CipherBill runs the liveness clock and pre-composes the payout. If you stop checking in, a trusted signer can route the balance — but only by signing it. Nothing is autonomous.</p>
        <button type="button" onClick={() => setOpen(true)}>Arm a contingency plan</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not autonomous</strong><span>Nothing fires on its own. The payout is a set of in-pool transfers a live signer must send after a lapse; there is no keeper and no scheduled transaction.</span></div>
        <div><strong>Not a time-lock or escrow</strong><span>The clock is a local computation. The pool holds no timer and no funds; the routed balance sits in your shielded balance and stays spendable.</span></div>
        <div><strong>Not zero-knowledge</strong><span>Commitments are salted Poseidon hashes. The wallet proves each transfer; CipherBill proves nothing and no contract verifies the plan or a lapse.</span></div>
      </div>

      {open ? (
        <div className={styles.backdrop} role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
          <section className={styles.modal} role="dialog" aria-modal="true" aria-labelledby="deadman-modal-title">
            <header className={styles.modalHeader}>
              <div><span>Dead-man switch · SN_MAIN</span><h2 id="deadman-modal-title">Arm a contingency payout</h2><p>Payout transfers act on <code>{shorten(DEADMAN_POOL_ADDRESS)}</code></p></div>
              <button type="button" onClick={() => setOpen(false)} disabled={Boolean(busy)} aria-label="Close the dead-man portal">×</button>
            </header>
            <div className={styles.truth}>
              <div><b>Executable here</b><span>One wallet request: the merged in-pool payout transfers to the beneficiaries, through the connected wallet.</span></div>
              <div><b>Computed only</b><span>The liveness clock, the allocation, and the commitment. No plan registry, timer, or proof exists.</span></div>
              <div><b>Exact integers</b><span>Shares floor in basis points; the last beneficiary takes the exact remainder so no base unit is lost.</span></div>
              <div><b>Trust is explicit</b><span>A signer holding a valid key must send the payout, and is trusted to wait for a genuine lapse.</span></div>
            </div>

            {!plan ? (
              <form className={styles.form} onSubmit={arm}>
                <fieldset className={styles.fieldset}>
                  <span>The shielded plan</span>
                  <div className={styles.fields}>
                    <label>Invoice ID<input required maxLength={64} value={invoiceId} onChange={(event) => setInvoiceId(event.target.value)} /></label>
                    <label>Switch value (routed)<input required inputMode="decimal" placeholder="1000" value={switchValue} onChange={(event) => setSwitchValue(event.target.value)} /></label>
                    <label>Asset symbol<input required maxLength={12} value={assetSymbol} onChange={(event) => setAssetSymbol(event.target.value)} /></label>
                    <label>Asset decimals<input required inputMode="numeric" min="0" max="18" value={assetDecimals} onChange={(event) => setAssetDecimals(event.target.value)} /></label>
                    <label>Check-in every (hours)<input required inputMode="numeric" min="1" placeholder="24" value={checkInIntervalHours} onChange={(event) => setCheckInIntervalHours(event.target.value)} /></label>
                    <label>Grace window (hours)<input inputMode="numeric" min="0" placeholder="48" value={graceHours} onChange={(event) => setGraceHours(event.target.value)} /></label>
                    <label className={styles.wide}>Routed token contract<input required maxLength={66} placeholder="0x…" value={assetToken} onChange={(event) => setAssetToken(event.target.value)} /></label>
                    <label className={styles.wide}>Executor label (optional, stays here)<input maxLength={96} placeholder="Trusted Executor" value={executorLabel} onChange={(event) => setExecutorLabel(event.target.value)} /></label>
                    <label className={styles.wide}>Memo (optional, stays here)<input maxLength={160} placeholder="batch 7" value={memo} onChange={(event) => setMemo(event.target.value)} /></label>
                  </div>
                </fieldset>
                <fieldset className={styles.fieldset}>
                  <span>Beneficiaries (shares sum to 10000 bps)</span>
                  <div className={styles.beneList}>
                    {beneficiaries.map((row, index) => (
                      <div className={styles.beneRow} key={index}>
                        <input maxLength={66} placeholder="Recipient 0x… (registered, in-pool)" value={row.recipient} onChange={(event) => updateBeneficiary(index, "recipient", event.target.value)} />
                        <input inputMode="numeric" min="1" max="10000" placeholder="bps" value={row.shareBps} onChange={(event) => updateBeneficiary(index, "shareBps", event.target.value)} />
                        <input maxLength={64} placeholder="Label (optional)" value={row.label} onChange={(event) => updateBeneficiary(index, "label", event.target.value)} />
                        <button type="button" className={styles.ghost} onClick={() => removeBeneficiary(index)} disabled={beneficiaries.length <= 1} aria-label={`Remove beneficiary ${index + 1}`}>×</button>
                      </div>
                    ))}
                  </div>
                  <button type="button" className={styles.ghost} onClick={addBeneficiary} disabled={beneficiaries.length >= MAX_BENEFICIARIES}>Add beneficiary</button>
                </fieldset>
                <div className={styles.actions}><button type="button" className={styles.ghost} onClick={resetComposer}>Reset composer</button><button type="submit" disabled={busy === "arm"}>{busy === "arm" ? "Arming…" : "Arm the plan"}</button></div>
              </form>
            ) : (
              <div className={styles.plan}>
                <aside className={styles.sidebar}>
                  <span>Plan armed</span>
                  <div className={styles.headline}><strong>{plan.switchValueDisplay} {plan.asset.symbol}</strong><small>routes to {plan.beneficiaries.length} beneficiar{plan.beneficiaries.length === 1 ? "y" : "ies"} on a lapse</small></div>
                  <dl>
                    <div><dt>Check-in every</dt><dd>{formatDuration(plan.checkInIntervalMs)}</dd></div>
                    <div><dt>Grace window</dt><dd>{plan.graceMs ? formatDuration(plan.graceMs) : "none"}</dd></div>
                    <div><dt>Liveness</dt><dd className={liveness?.state === "lapsed" ? styles.exposed : styles.shielded}>{liveness ? liveness.state : "—"}</dd></div>
                    <div><dt>Executor</dt><dd>{plan.executorLabel || "unnamed"}</dd></div>
                    <div><dt>Plan commitment</dt><dd><code>{shorten(plan.planCommitment)}</code></dd></div>
                    {walletBalance !== null ? <div><dt>Shielded balance</dt><dd className={BigInt(walletBalance) >= BigInt(plan.switchValueBaseUnits) ? styles.shielded : styles.exposed}>{formatDeadmanBaseUnits(walletBalance, plan.asset.decimals)} {plan.asset.symbol}</dd></div> : null}
                  </dl>
                  <button type="button" onClick={invalidate} disabled={Boolean(busy)}>Edit the plan</button>
                </aside>

                <div className={styles.main}>
                  <section className={styles.card}>
                    <div><span>Liveness clock</span><h3>Local check-in monitor</h3></div>
                    <p>Computed in this browser from your last check-in. The pool holds no timer; a signer can send the payout early, late, or never. Check in to reset the clock.</p>
                    <dl className={styles.clock}>
                      <div><dt>Last check-in</dt><dd>{liveness ? shorten(liveness.lastCheckInAt) : "—"}</dd></div>
                      <div><dt>Check-in due</dt><dd>{liveness ? shorten(liveness.checkInDueAt) : "—"}</dd></div>
                      <div><dt>Lapses at</dt><dd>{liveness ? shorten(liveness.lapseAt) : "—"}</dd></div>
                      <div><dt>{liveness?.state === "lapsed" ? "Status" : "Time until lapse"}</dt><dd className={liveness?.state === "lapsed" ? styles.exposed : styles.shielded}>{liveness ? (liveness.state === "lapsed" ? "eligible to route" : formatDuration(liveness.msUntilLapse)) : "—"}</dd></div>
                    </dl>
                    <div className={styles.clockActions}>
                      <button type="button" onClick={checkInNow} disabled={Boolean(busy)}>Check in now</button>
                      <label>Simulate hours since check-in<input inputMode="numeric" min="0" value={hoursSince} onChange={(event) => simulateHoursSince(event.target.value)} /></label>
                    </div>
                  </section>
                  <section className={styles.card}>
                    <div><span>Contingency payout</span><h3>One transfer per beneficiary</h3></div>
                    <p>CipherBill batches the routed balance into one in-pool transfer per beneficiary and drops any zero leg. A signer confirms once; the wallet appends its own relayer fee, so none is added here.</p>
                    {plan.beneficiaries.map((beneficiary, index) => (
                      <div className={styles.legRow} key={`${beneficiary.recipient}-${index}`}>
                        <div><strong>{beneficiary.label || `Beneficiary ${index + 1}`}</strong><small>{shorten(beneficiary.recipient)}</small></div>
                        <div><b>{beneficiary.amountDisplay} {plan.asset.symbol}</b><em>{(beneficiary.shareBps / 100).toFixed(2)}% share</em></div>
                        <div><b className={styles.shielded}>In-pool transfer</b><em>hides sender, recipient, token, amount</em></div>
                      </div>
                    ))}
                  </section>
                  <div className={styles.opsRow}>
                    <div>
                      <span>01 · Consent-driven read</span><h4>Shielded coverage</h4>
                      <p>Reads the signer&apos;s balance of the routed token with permission and keeps it in component memory only. Coverage is compared against the switch value.</p>
                      <button type="button" onClick={checkCoverage} disabled={!walletReady || Boolean(busy)}>{busy === "balance" ? "Reading…" : "Check coverage"}</button>
                    </div>
                    <div>
                      <span>02 · A live signer sends</span><h4>Route the payout</h4>
                      <p>One wallet request: the merged in-pool transfers to the beneficiaries. Sending before a lapse is not blocked, since no contract enforces the clock.</p>
                      {!walletReady ? <WalletConnect /> : <button type="button" onClick={routePayout} disabled={Boolean(busy)}>{busy === "route" ? "Submitting…" : "Send the payout"}</button>}
                      {payoutHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(payoutHash)} target="_blank" rel="noreferrer">Track payout hash ↗</a> : null}
                    </div>
                    <div>
                      <span>03 · Disclosable record</span><h4>Trigger attestation</h4>
                      <p>Builds a hash binding the plan to the claimed last check-in and trigger time. It refuses to attest a trigger before the lapse. Not on-chain, not a proof of inactivity.</p>
                      <button type="button" onClick={buildAttestation} disabled={Boolean(busy)}>{busy === "attest" ? "Building…" : "Build & copy attestation"}</button>
                    </div>
                  </div>
                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Selective disclosure</span><h3>Shareable plan digest</h3></div>
                    <p>The digest carries the invoice ID, the cadence, the beneficiary count, and the plan&apos;s Poseidon commitment. It carries no amount, address, executor, salt, or memo, so a chosen executor can verify the disclosed plan against it later. The full plan holds the salt and stays here.</p>
                    <textarea readOnly value={planDigest} placeholder="Copy the digest to publish this plan's shape without its amounts, beneficiaries, or memo." />
                    <div><button type="button" onClick={sharePlanDigest}>Copy plan digest</button></div>
                  </section>
                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Trigger attestation</span><h3>Disclosable trigger record</h3></div>
                    <p>A hash binding this plan to the claimed last check-in and the trigger time. A beneficiary or executor may share it, and a counterparty can verify it against the full plan. It refuses to attest a trigger before the computed lapse, and it is not on-chain.</p>
                    <textarea readOnly value={attestation} placeholder="Build the attestation above to copy a disclosable record of this trigger." />
                    <div><button type="button" onClick={buildAttestation} disabled={Boolean(busy)}>Build &amp; copy attestation</button></div>
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
                      <div><span>Trust model</span><h3>Not autonomous, not time-locked, not escrowed, not proven</h3></div>
                      <p>{trust.statement}</p>
                      <ul className={styles.trustList}>{trust.trustedParties.map((party) => <li key={party}>{party}</li>)}</ul>
                    </section>
                  ) : null}

                  <section className={styles.card}>
                    <div><span>Stated limitations</span><h3>Read before relying on this plan</h3></div>
                    <ul className={styles.trustList}>{plan.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
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

function shorten(value: string): string {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function formatDuration(ms: number): string {
  if (ms <= 0) return "0m";
  const totalMinutes = Math.floor(ms / 60_000);
  const days = Math.floor(totalMinutes / 1_440);
  const hours = Math.floor((totalMinutes % 1_440) / 60);
  const minutes = totalMinutes % 60;
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", `${minutes}m`].filter(Boolean).join(" ");
}

