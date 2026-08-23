"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  buildBillingSchedule,
  buildCycleDrawActions,
  buildCycleReceiptAttestation,
  buildCycleReminders,
  buildMandateAuthorization,
  buildRecurringPlanDigest,
  createRecurringPlan,
  evaluateBillingCycle,
  evaluateBillingStatus,
  formatRecurringBaseUnits,
  getRecurringVisibilityModel,
  RECURRING_POOL_ADDRESS,
  registerBillingMandate,
  serializeRecurringCycleReceipt,
  serializeRecurringPlanDigest,
  summarizeRecurringTrust,
  verifyMandateAuthorization,
  type BillingCycle,
  type BillingCycleState,
  type RecurringBillingPlan,
  type RecurringMandate,
} from "@/lib/recurring-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./recurring-portal.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type BusyAction = "create" | "balance" | "draw" | "receipt" | "mandate" | null;

const DAY_MS = 86_400_000;

/** Never throws: a malformed plan yields an empty schedule so the view degrades instead of crashing. */
function safeSchedule(plan: RecurringBillingPlan): BillingCycle[] {
  try {
    return buildBillingSchedule(plan);
  } catch {
    return [];
  }
}

/** Abbreviates a long hex value (address or hash) for display; short values pass through unchanged. */
function shorten(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

/** Formats a positive millisecond span as a coarse, human countdown; 0 or less reads as "now". */
function formatCountdown(ms: number): string {
  if (ms <= 0) return "now";
  const days = Math.floor(ms / DAY_MS);
  if (days >= 1) return `${days} day${days === 1 ? "" : "s"}`;
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 1) return `${hours} hour${hours === 1 ? "" : "s"}`;
  const minutes = Math.max(1, Math.floor(ms / 60_000));
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

/** Renders an ISO timestamp as a short local date; falls back to the raw string if unparseable. */
function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/**
 * Recurring-billing and subscription-management portal for the merchant dashboard.
 *
 * Every claim here is deliberately narrow. CipherBill splits an invoice total into exact-integer
 * installments, computes each cycle's due date in this browser, and — only when a live signer chooses —
 * submits a single private in-pool transfer per cycle. It is not automated, not decentralized, not
 * escrow, and not zero-knowledge as a system: nothing draws on a schedule, no contract bills anyone or
 * holds the funds, and the only zero-knowledge element is the optional per-cycle mandate authorization.
 */
export function RecurringPortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState("inv_recurring_001");
  const [totalValue, setTotalValue] = useState("");
  const [merchantRecipient, setMerchantRecipient] = useState("");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetToken, setAssetToken] = useState("");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [cycleCount, setCycleCount] = useState("12");
  const [cadenceDays, setCadenceDays] = useState("30");
  const [graceDays, setGraceDays] = useState("7");
  const [payerLabel, setPayerLabel] = useState("");
  const [memo, setMemo] = useState("");
  const [plan, setPlan] = useState<RecurringBillingPlan | null>(null);
  const [settledIndices, setSettledIndices] = useState<number[]>([]);
  const [selectedCycle, setSelectedCycle] = useState(1);
  const [now, setNow] = useState(() => Date.now());
  const [autoReminders, setAutoReminders] = useState(false);
  const [planDigest, setPlanDigest] = useState("");
  const [receipt, setReceipt] = useState("");
  const [mandate, setMandate] = useState<RecurringMandate | null>(null);
  const [mandateAuth, setMandateAuth] = useState("");
  const [mandateVerified, setMandateVerified] = useState<boolean | null>(null);
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [drawHash, setDrawHash] = useState("");
  const [drawnCycle, setDrawnCycle] = useState<number | null>(null);
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Set up a plan: name the invoice total, the number of cycles, and the cadence. CipherBill splits the total into exact installments and computes each cycle's due date in this browser. Nothing is drawn until the customer signs each cycle.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const schedule = useMemo(() => plan ? safeSchedule(plan) : [], [plan]);
  const status = useMemo(() => {
    if (!plan) return null;
    try { return evaluateBillingStatus(plan, settledIndices, new Date(now)); } catch { return null; }
  }, [plan, settledIndices, now]);
  const selectedEval = useMemo(() => {
    if (!plan) return null;
    try { return evaluateBillingCycle(plan, selectedCycle, settledIndices, new Date(now)); } catch { return null; }
  }, [plan, selectedCycle, settledIndices, now]);
  const visibility = useMemo(() => {
    if (!plan) return null;
    try { return getRecurringVisibilityModel(plan); } catch { return null; }
  }, [plan]);
  const trust = useMemo(() => {
    if (!plan) return null;
    try { return summarizeRecurringTrust(plan); } catch { return null; }
  }, [plan]);
  const reminders = useMemo(() => {
    if (!plan || !autoReminders) return [];
    try { return buildCycleReminders(plan, selectedCycle, 3); } catch { return []; }
  }, [plan, autoReminders, selectedCycle]);

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

  function setUpPlan(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("create");
    try {
      const nextPlan = createRecurringPlan({
        invoiceId,
        merchant: merchantRecipient,
        asset: { symbol: assetSymbol, tokenAddress: assetToken, decimals: Number(assetDecimals) },
        totalValue,
        cycleCount: Number(cycleCount),
        cadenceDays: Number(cadenceDays),
        graceDays: graceDays ? Number(graceDays) : undefined,
        payerLabel: payerLabel || undefined,
        memo: memo || undefined,
      });
      invalidate();
      setPlan(nextPlan);
      setSelectedCycle(1);
      setMessage(`Plan set: ${nextPlan.totalValueDisplay} ${nextPlan.asset.symbol} across ${nextPlan.cycleCount} cycle${nextPlan.cycleCount === 1 ? "" : "s"}. The schedule is computed here; nothing is on-chain and no cycle is drawn until the customer signs it.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The plan could not be set up.");
    } finally {
      setBusy(null);
    }
  }

  function toggleSettled(index: number): void {
    setSettledIndices((current) => current.includes(index) ? current.filter((value) => value !== index) : [...current, index].sort((a, b) => a - b));
  }

  async function checkCoverage(): Promise<void> {
    if (!plan || !account || !walletReady || busy) return;
    const token = plan.asset.tokenAddress;
    const required = BigInt(schedule[selectedCycle - 1]?.amountBaseUnits ?? "0");
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setWalletBalance(balance);
      setMessage(BigInt(balance) >= required
        ? `This shielded balance covers cycle ${selectedCycle}'s installment. The pool fee the wallet adds is not included in that comparison.`
        : `This shielded balance is below cycle ${selectedCycle}'s installment. The customer must hold the full amount before signing this cycle's draw.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function drawCycle(): Promise<void> {
    if (!plan || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    const cycle = selectedCycle;
    setBusy("draw");
    setDrawHash("");
    setDrawnCycle(null);
    try {
      const actions = buildCycleDrawActions(plan, cycle);
      setMessage(`Confirm cycle ${cycle} in the wallet: one private in-pool transfer of ${schedule[cycle - 1].amountDisplay} ${plan.asset.symbol} to the merchant. The relayer submits it, so never attribute the sender to the customer; the wallet appends its own fee, so none is added here.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setDrawHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      if (result.status === "confirmed") {
        setDrawnCycle(cycle);
        setSettledIndices((current) => current.includes(cycle) ? current : [...current, cycle].sort((a, b) => a - b));
        setMessage(`Cycle ${cycle} settled inside the pool. Nothing recurring was authorized: the customer signed this cycle only, and the next cycle still needs its own signature.`);
      } else {
        setMessage(result.status === "failed" ? `The cycle ${cycle} draw reverted. The hash is preserved; retry when ready.` : "Submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it stays pending.");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Submission failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }

  function selectCycle(index: number): void {
    setSelectedCycle(index);
    setWalletBalance(null);
  }

  function sharePlanDigest(): void {
    if (!plan) return;
    try {
      setPlanDigest(serializeRecurringPlanDigest(buildRecurringPlanDigest(plan)));
      setMessage("Plan digest built. It carries the cadence, cycle count, and commitment — never the amounts, the merchant, the payer, the memo, or the salt — so the customer can verify the plan against it without the merchant revealing the private fields.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The plan digest could not be built.");
    }
  }

  function buildReceipt(): void {
    if (!plan || drawnCycle === null || !drawHash) return;
    setBusy("receipt");
    try {
      const attestation = buildCycleReceiptAttestation(plan, { cycleIndex: drawnCycle, settledAt: new Date().toISOString(), transactionHash: drawHash });
      setReceipt(serializeRecurringCycleReceipt(attestation));
      setMessage(`Receipt built for cycle ${drawnCycle}. It records the cycle, its due date, the amount, and the transaction hash under a commitment. It is a disclosable record, not on-chain and not proof the transfer confirmed — verify the hash on the explorer.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The cycle receipt could not be built.");
    } finally {
      setBusy(null);
    }
  }

  async function copy(text: string): Promise<void> {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setMessage("Copied to the clipboard.");
    } catch {
      setMessage("The clipboard is unavailable; select and copy the text manually.");
    }
  }

  function registerMandate(): void {
    if (busy) return;
    try {
      setMandate(registerBillingMandate());
      setMandateAuth("");
      setMandateVerified(null);
      setMessage("Mandate keypair generated in this browser. The secret stays with the customer and is never shown, sent, or written into any payload; only the public key is shared with the merchant out of band. This creates no on-chain mandate and grants no ability to pull funds.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The mandate keypair could not be generated.");
    }
  }

  function authorizeMandate(): void {
    if (!plan || !mandate || busy) return;
    setBusy("mandate");
    try {
      const auth = buildMandateAuthorization(plan, selectedCycle, mandate.mandateSecret);
      const verified = verifyMandateAuthorization(auth, plan, mandate.mandatePublicKey);
      setMandateAuth(JSON.stringify({ ...auth }, null, 2));
      setMandateVerified(verified);
      setMessage(verified
        ? `Cycle ${selectedCycle} authorization proved and verified. This is a genuine zero-knowledge proof of knowledge of the mandate key, bound to this plan and cycle — it authorizes the draw and reveals nothing about the secret. It is not proof of payment: the customer must still sign the transfer.`
        : "The authorization did not verify against the recorded mandate key.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The mandate authorization could not be built.");
    } finally {
      setBusy(null);
    }
  }

  function invalidate(): void {
    setPlanDigest("");
    setReceipt("");
    setMandate(null);
    setMandateAuth("");
    setMandateVerified(null);
    setWalletBalance(null);
    setDrawHash("");
    setDrawnCycle(null);
    setSettledIndices([]);
  }

  function resetComposer(): void {
    setPlan(null);
    invalidate();
    setSelectedCycle(1);
    setAutoReminders(false);
    setMessage("Composer reset. Set up a new plan: name the invoice total, the number of cycles, and the cadence. CipherBill splits the total into exact installments and computes each cycle's due date in this browser.");
  }

  return (
    <section className={styles.launch} id="recurring">
      <div className={styles.launchCopy}>
        <span>Recurring &amp; subscriptions</span>
        <h2>Bill on a <em>cadence</em>, sign every cycle.</h2>
        <p>
          CipherBill splits an invoice total into exact-integer installments and computes each cycle&apos;s due date
          in this browser. When a cycle comes due, the customer signs one private in-pool transfer to the merchant.
          Nothing draws on a schedule, no contract holds the funds, and no cycle is charged without a fresh signature.
        </p>
        <button type="button" onClick={() => setOpen(true)}>Open the billing composer →</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not automated</strong><span>STRK20 has no direct-debit primitive. Every cycle needs the customer to sign it; nothing pulls funds on a timer.</span></div>
        <div><strong>Not decentralized</strong><span>The schedule, cadence, and amounts are computed in this browser. There is no on-chain billing registry or mandate.</span></div>
        <div><strong>One zero-knowledge part</strong><span>Only the optional mandate authorization is a real zero-knowledge proof — of knowing a key, never of payment.</span></div>
      </div>
      {open && renderModal()}
    </section>
  );

  function renderModal() {
    return (
      <div className={styles.backdrop} role="presentation" onClick={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
        <div className={styles.modal} role="dialog" aria-modal="true" aria-label="Recurring billing composer">
          <div className={styles.modalHeader}>
            <div>
              <span>CipherBill · recurring billing</span>
              <h2>Subscription &amp; recurring invoice composer</h2>
              <p>Pool <code>{shorten(RECURRING_POOL_ADDRESS)}</code> · Starknet mainnet · every cycle is a single manually-signed in-pool transfer</p>
            </div>
            <button type="button" aria-label="Close" onClick={() => { if (!busy) setOpen(false); }}>×</button>
          </div>
          <div className={styles.truth}>
            <div><b>Not escrow</b><span>No contract holds funds. The customer keeps custody and signs each draw.</span></div>
            <div><b>Not auto-draw</b><span>The &quot;automated&quot; toggle only builds local reminders; it charges nothing.</span></div>
            <div><b>Edges are public</b><span>Deposits, withdrawals, timing, and a rigid cadence are observable.</span></div>
            <div><b>No payment proof</b><span>The wallet proves each transfer; CipherBill proves no payment.</span></div>
          </div>
          {plan ? renderPlan() : renderComposer()}
          {message && <p className={styles.message}>{message}</p>}
        </div>
      </div>
    );
  }

  function renderComposer() {
    return (
      <form className={styles.form} onSubmit={setUpPlan}>
        <fieldset className={styles.fieldset}>
          <legend>Invoice &amp; merchant</legend>
          <div className={styles.fields}>
            <label className={styles.wide}>Invoice ID
              <input value={invoiceId} onChange={(e) => setInvoiceId(e.target.value)} placeholder="inv_recurring_001" />
            </label>
            <label className={styles.wide}>Merchant recipient (in-pool address)
              <input value={merchantRecipient} onChange={(e) => setMerchantRecipient(e.target.value)} placeholder="0x…" />
            </label>
          </div>
        </fieldset>
        <fieldset className={styles.fieldset}>
          <legend>Billed asset</legend>
          <div className={styles.fields}>
            <label>Symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} placeholder="USDC" />
            </label>
            <label className={styles.wide}>Token address
              <input value={assetToken} onChange={(e) => setAssetToken(e.target.value)} placeholder="0x…" />
            </label>
            <label>Decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" placeholder="6" />
            </label>
          </div>
        </fieldset>
        <fieldset className={styles.fieldset}>
          <legend>Total &amp; schedule</legend>
          <div className={styles.fields}>
            <label>Total value
              <input value={totalValue} onChange={(e) => setTotalValue(e.target.value)} inputMode="decimal" placeholder="1200" />
            </label>
            <label>Cycles
              <input value={cycleCount} onChange={(e) => setCycleCount(e.target.value)} inputMode="numeric" placeholder="12" />
            </label>
            <label>Cadence (days)
              <input value={cadenceDays} onChange={(e) => setCadenceDays(e.target.value)} inputMode="numeric" placeholder="30" />
            </label>
            <label>Grace (days)
              <input value={graceDays} onChange={(e) => setGraceDays(e.target.value)} inputMode="numeric" placeholder="7" />
            </label>
          </div>
        </fieldset>
        {renderComposerTail()}
      </form>
    );
  }

  function renderComposerTail() {
    return (
      <>
        <fieldset className={styles.fieldset}>
          <legend>Optional labels (local only)</legend>
          <div className={styles.fields}>
            <label className={styles.wide}>Payer label
              <input value={payerLabel} onChange={(e) => setPayerLabel(e.target.value)} placeholder="Acme Corp — never an address" />
            </label>
            <label className={styles.wide}>Memo
              <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="annual plan" />
            </label>
          </div>
        </fieldset>
        <div className={styles.actions}>
          <button type="button" className={styles.ghost} onClick={() => setOpen(false)} disabled={busy !== null}>Cancel</button>
          <button type="submit" disabled={busy !== null}>{busy === "create" ? "Composing…" : "Compose plan"}</button>
        </div>
      </>
    );
  }

  function renderPlan() {
    if (!plan) return null;
    return (
      <div className={styles.plan}>
        <aside className={styles.sidebar}>
          <span>Plan</span>
          <div className={styles.headline}>
            <strong>{plan.totalValueDisplay} {plan.asset.symbol}</strong>
            <small>{plan.cycleCount} cycle{plan.cycleCount === 1 ? "" : "s"} · every {Math.round(plan.cadenceMs / DAY_MS)} day{plan.cadenceMs === DAY_MS ? "" : "s"}</small>
          </div>
          <dl>
            <div><dt>Invoice</dt><dd>{plan.invoiceId}</dd></div>
            <div><dt>Merchant</dt><dd>{shorten(plan.merchant)}</dd></div>
            <div><dt>Status</dt><dd>{status ? status.state.replace(/_/g, " ") : "—"}</dd></div>
            <div><dt>Settled</dt><dd>{status ? `${status.settledCount} / ${plan.cycleCount}` : "—"}</dd></div>
            <div><dt>Outstanding</dt><dd>{status ? `${formatRecurringBaseUnits(status.outstandingValueBaseUnits, plan.asset.decimals)} ${plan.asset.symbol}` : "—"}</dd></div>
            <div><dt>Next unsettled</dt><dd>{status && status.nextUnsettledIndex ? `cycle ${status.nextUnsettledIndex}` : "none"}</dd></div>
          </dl>
          <button type="button" onClick={sharePlanDigest}>Build shareable digest</button>
          <button type="button" className={styles.ghost} onClick={resetComposer} disabled={busy !== null}>Reset composer</button>
        </aside>
        <div className={styles.main}>
          {renderSchedule()}
          {renderOps()}
          {renderMandate()}
          {renderShare()}
          {renderDisclosure()}
        </div>
      </div>
    );
  }

  function cycleState(index: number): BillingCycleState {
    if (settledIndices.includes(index)) return "settled";
    const cycle = schedule[index - 1];
    if (!cycle) return "upcoming";
    if (now < Date.parse(cycle.dueAt)) return "upcoming";
    return now < Date.parse(cycle.graceEndsAt) ? "due" : "overdue";
  }

  function renderSchedule() {
    if (!plan) return null;
    return (
      <div className={styles.card}>
        <div><span>Installment schedule</span></div>
        <h3>Each cycle is signed on its own</h3>
        <p>Amounts are split by exact integer base units — the last cycle carries any rounding remainder so the sum equals the total. Select a cycle to check coverage and draw it; marking a cycle settled is a local bookkeeping flag, not an on-chain state.</p>
        <div className={styles.schedule}>
          {schedule.map((cycle) => {
            const state = cycleState(cycle.index);
            return (
              <div key={cycle.index} className={`${styles.cycleRow} ${cycle.index === selectedCycle ? styles.selected : ""}`}>
                <b>#{cycle.index}</b>
                <div>
                  <strong>{cycle.amountDisplay} {plan.asset.symbol}</strong>
                  <small>due {formatDate(cycle.dueAt)} · grace ends {formatDate(cycle.graceEndsAt)}</small>
                </div>
                <span className={`${styles.pill} ${styles[state]}`}>{state}</span>
                <div>
                  <button type="button" className={styles.rowButton} onClick={() => selectCycle(cycle.index)}>Select</button>
                  <button type="button" className={styles.rowButton} onClick={() => toggleSettled(cycle.index)}>{settledIndices.includes(cycle.index) ? "Unmark" : "Mark settled"}</button>
                </div>
              </div>
            );
          })}
        </div>
        {renderReminders()}
      </div>
    );
  }

  function renderReminders() {
    return (
      <>
        <label className={styles.toggle}>
          <input type="checkbox" checked={autoReminders} onChange={(e) => setAutoReminders(e.target.checked)} />
          <span>&quot;Automated billing&quot; — build local reminders for the selected cycle (this only schedules notices in this browser; it never draws funds)</span>
        </label>
        {autoReminders && reminders.length > 0 && (
          <ul className={styles.reminderList}>
            {reminders.map((reminder, i) => (
              <li key={`${reminder.kind}-${i}`}>{formatDate(reminder.at)} — {reminder.note}</li>
            ))}
          </ul>
        )}
      </>
    );
  }

  function renderOps() {
    if (!plan) return null;
    const selectedAmount = schedule[selectedCycle - 1]?.amountDisplay ?? "0";
    return (
      <div className={styles.card}>
        <div><span>Cycle {selectedCycle}</span></div>
        <h3>{selectedAmount} {plan.asset.symbol} · {selectedEval ? selectedEval.state : "—"}{selectedEval && selectedEval.state === "upcoming" ? ` · due in ${formatCountdown(selectedEval.msUntilDue)}` : ""}</h3>
        <p>Checking coverage reads the customer&apos;s shielded balance; drawing submits exactly one private in-pool transfer to the merchant for this cycle only. The relayer submits it, so its sender is never the customer, and the wallet appends its own fee.</p>
        {!walletReady ? (
          <div className={styles.opsRow}>
            <div>
              <span>Wallet</span>
              <h4>Connect a STRK20 wallet</h4>
              <p>Coverage and draws need a connected wallet with STRK20 support. Nothing is submitted until the customer confirms in the wallet.</p>
              <WalletConnect />
            </div>
          </div>
        ) : (
          <div className={styles.opsRow}>
            <div>
              <span>Coverage</span>
              <h4>Shielded balance</h4>
              <p>{walletBalance !== null ? `${formatRecurringBaseUnits(walletBalance, plan.asset.decimals)} ${plan.asset.symbol} available` : "Not checked yet."}</p>
              <button type="button" onClick={checkCoverage} disabled={busy !== null}>{busy === "balance" ? "Checking…" : "Check coverage"}</button>
            </div>
            <div>
              <span>Draw</span>
              <h4>Sign cycle {selectedCycle}</h4>
              <p>{drawHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(drawHash)} target="_blank" rel="noreferrer">{shorten(drawHash)} ↗</a> : "One transfer, signed by the customer."}</p>
              <button type="button" onClick={drawCycle} disabled={busy !== null}>{busy === "draw" ? "Awaiting confirmation…" : `Draw cycle ${selectedCycle}`}</button>
            </div>
            <div>
              <span>Receipt</span>
              <h4>Disclosable record</h4>
              <p>{drawnCycle !== null ? `Cycle ${drawnCycle} settled — build its receipt.` : "Draw a cycle first."}</p>
              <button type="button" onClick={buildReceipt} disabled={busy !== null || drawnCycle === null || !drawHash}>{busy === "receipt" ? "Building…" : "Build receipt"}</button>
            </div>
          </div>
        )}
      </div>
    );
  }

  function renderMandate() {
    if (!plan) return null;
    return (
      <div className={styles.card}>
        <div><span>Mandate authorization · the only zero-knowledge part</span></div>
        <h3>Prove the mandate key without revealing it</h3>
        <p>
          Generate a mandate keypair in this browser, then prove — in zero knowledge — knowledge of its secret bound to
          this plan and the selected cycle. This is a genuine Schnorr proof of knowledge: it authorizes a draw and reveals
          nothing about the secret. It is <strong>not</strong> proof of payment and creates no on-chain mandate; the customer
          must still sign the transfer to settle the cycle. The secret never leaves this browser and is never displayed.
        </p>
        <div className={styles.opsRow}>
          <div>
            <span>Keypair</span>
            <h4>{mandate ? "Mandate registered" : "No mandate yet"}</h4>
            <p>{mandate ? `Public key ${shorten(mandate.mandatePublicKey.x)} — share this out of band; the secret stays hidden.` : "Generate a keypair the customer keeps."}</p>
            <button type="button" onClick={registerMandate} disabled={busy !== null}>{mandate ? "Regenerate keypair" : "Generate keypair"}</button>
          </div>
          <div>
            <span>Proof</span>
            <h4>Authorize cycle {selectedCycle}</h4>
            <p>{mandateVerified === null ? "Not proved yet." : mandateVerified ? "Verified against the recorded key." : "Did not verify."}</p>
            <button type="button" onClick={authorizeMandate} disabled={busy !== null || !mandate}>{busy === "mandate" ? "Proving…" : "Prove & verify"}</button>
          </div>
        </div>
        {mandateAuth && (
          <div className={styles.share}>
            <textarea readOnly value={mandateAuth} aria-label="Mandate authorization proof" />
            <div><button type="button" onClick={() => copy(mandateAuth)}>Copy proof</button></div>
          </div>
        )}
      </div>
    );
  }

  function renderShare() {
    if (!planDigest && !receipt) return null;
    return (
      <div className={styles.card}>
        <div><span>Selective disclosure</span></div>
        <h3>Share a digest or a cycle receipt</h3>
        <p>The digest carries the cadence, cycle count, and commitment — never amounts, the merchant, the payer, the memo, or the salt. A receipt records one settled cycle under a commitment; it is disclosable evidence, not on-chain and not proof the transfer confirmed.</p>
        {planDigest && (
          <div className={styles.share}>
            <textarea readOnly value={planDigest} aria-label="Plan digest" />
            <div><button type="button" onClick={() => copy(planDigest)}>Copy digest</button></div>
          </div>
        )}
        {receipt && (
          <div className={styles.share}>
            <textarea readOnly value={receipt} aria-label="Cycle receipt" />
            <div><button type="button" onClick={() => copy(receipt)}>Copy receipt</button></div>
          </div>
        )}
      </div>
    );
  }

  function renderDisclosure() {
    if (!plan) return null;
    return (
      <div className={styles.card}>
        <div><span>Honest edges</span></div>
        <h3>What is hidden, what is public, what is trusted</h3>
        {visibility && (
          <div className={styles.visibility}>
            <div>
              <span className={styles.shielded}>Hidden inside the pool</span>
              {visibility.hiddenInPool.map((entry) => <p key={entry}>{entry}</p>)}
            </div>
            <div>
              <span className={styles.exposed}>Public or observable</span>
              {visibility.publicOrObservable.map((entry) => <p key={entry}>{entry}</p>)}
            </div>
          </div>
        )}
        {trust && (
          <ul className={styles.trustList}>
            <li>{trust.statement}</li>
            <li>{trust.zeroKnowledgeElement}</li>
            {trust.trustedParties.map((party) => <li key={party}>Trusted: {party}</li>)}
          </ul>
        )}
        {visibility && <span className={styles.limitation}>{visibility.limitation}</span>}
        {plan.limitations.map((limit) => <span key={limit} className={styles.limitation}>{limit}</span>)}
      </div>
    );
  }
}
