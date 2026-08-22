"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  buildOptimizedExpenseCalldata,
  createExpenseSettlementPlan,
  estimateExpenseBatchSavings,
  EXPENSE_SPLITTER_POOL_ADDRESS,
  getExpenseVisibilityModel,
  MAX_PENDING_EXPENSES,
  type ExpenseFeeSavingsEstimate,
  type ExpenseSettlementPlan,
  type PendingExpenseInput,
} from "@/lib/expense-splitter";
import { FIAT_CURRENCIES, type FiatCurrency } from "@/lib/fiat-shielding";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

interface ExpenseRow {
  rowId: string;
  invoiceId: string;
  vendorLabel: string;
  costCenter: string;
  recipientAddress: string;
  invoiceCurrency: FiatCurrency;
  invoiceAmount: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: string;
  rate: string;
  rateSource: string;
  rateExpiresAt: string;
}

type BusyAction = "plan" | "fee" | "balance" | "preflight" | "submit" | null;
type BalanceMap = Record<string, string>;

const currencies = Object.entries(FIAT_CURRENCIES) as Array<[FiatCurrency, (typeof FIAT_CURRENCIES)[FiatCurrency]]>;

export function ExpenseSplitterModal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<ExpenseRow[]>(() => [newExpenseRow(1), newExpenseRow(2)]);
  const [plan, setPlan] = useState<ExpenseSettlementPlan | null>(null);
  const [feeEstimate, setFeeEstimate] = useState<ExpenseFeeSavingsEstimate | null>(null);
  const [balances, setBalances] = useState<BalanceMap>({});
  const [preflightCommitment, setPreflightCommitment] = useState("");
  const [transactionHash, setTransactionHash] = useState("");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Add at least two pending invoices. No amount or FX term leaves this browser until you ask the wallet to settle.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const visibility = useMemo(() => plan ? getExpenseVisibilityModel(plan) : null, [plan]);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, open]);

  function updateRow(rowId: string, field: keyof Omit<ExpenseRow, "rowId">, value: string): void {
    setRows((current) => current.map((row) => row.rowId === rowId ? { ...row, [field]: value } : row));
    invalidatePlan();
  }

  function addRow(): void {
    if (rows.length >= MAX_PENDING_EXPENSES) return;
    const nextNumber = rows.length + 1;
    const source = rows[0];
    setRows([...rows, {
      ...newExpenseRow(nextNumber),
      tokenAddress: source?.tokenAddress ?? "",
      tokenSymbol: source?.tokenSymbol ?? "USDC",
      tokenDecimals: source?.tokenDecimals ?? "6",
      rateSource: source?.rateSource ?? "Treasury rate desk",
      rateExpiresAt: source?.rateExpiresAt ?? "",
    }]);
    invalidatePlan();
  }

  function removeRow(rowId: string): void {
    if (rows.length <= 2) return;
    setRows(rows.filter((row) => row.rowId !== rowId));
    invalidatePlan();
  }

  function copySettlementAsset(): void {
    const source = rows[0];
    if (!source) return;
    setRows(rows.map((row) => ({
      ...row,
      tokenAddress: source.tokenAddress,
      tokenSymbol: source.tokenSymbol,
      tokenDecimals: source.tokenDecimals,
      rateSource: source.rateSource,
      rateExpiresAt: source.rateExpiresAt,
    })));
    invalidatePlan();
    setMessage("Settlement asset, quote source, and expiry copied. Each currency still needs its own exact rate.");
  }

  function buildPlan(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("plan");
    try {
      const built = createExpenseSettlementPlan(rows.map(toPendingExpense));
      setPlan(built);
      setFeeEstimate(null);
      setBalances({});
      setPreflightCommitment("");
      setTransactionHash("");
      setMessage(`Batch optimized from ${built.expenses.length} invoice payments into ${built.transfers.length} private transfer action${built.transfers.length === 1 ? "" : "s"}. Review every allocation before opening the wallet.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Expense batch could not be built.");
    } finally {
      setBusy(null);
    }
  }

  async function readPoolFee(): Promise<void> {
    if (!plan || !account || !walletReady || busy) return;
    setBusy("fee");
    try {
      const result = await account.provider.callContract({ contractAddress: EXPENSE_SPLITTER_POOL_ADDRESS, entrypoint: "get_fee_amount", calldata: [] });
      const estimate = estimateExpenseBatchSavings(plan, result[0] ?? "0");
      setFeeEstimate(estimate);
      setMessage("Current pool fee read from the configured mainnet contract. Savings remain an estimate until the wallet previews this exact batch.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The current pool fee could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function checkShieldedBalances(): Promise<void> {
    if (!plan || !account || !walletReady || busy) return;
    setBusy("balance");
    try {
      const entries = await account.strk20Balances(plan.tokenTotals.map((total) => total.tokenAddress));
      const next = Object.fromEntries(plan.tokenTotals.map((total) => {
        const balance = entries.find((entry) => areSameStarknetAddress(entry.token, total.tokenAddress))?.balance ?? "0";
        return [total.tokenAddress, balance];
      }));
      setBalances(next);
      setMessage("Shielded balances read with wallet consent. This application keeps the returned values only in component memory.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Shielded balances could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function dryRun(): Promise<void> {
    if (!plan || !account || !walletReady || busy) return;
    setBusy("preflight");
    setMessage("The wallet is building and proving a simulation without submission. This can take roughly half a minute or longer depending on hardware.");
    try {
      await account.strk20PrepareInvoke(buildOptimizedExpenseCalldata(plan), true);
      setPreflightCommitment(plan.planCommitment);
      setMessage("Wallet preflight completed without submission. A later settlement may require fresh proving against a newer block anchor.");
    } catch (error) {
      setPreflightCommitment("");
      setMessage(error instanceof Error ? error.message : "Wallet preflight failed.");
    } finally {
      setBusy(null);
    }
  }

  async function submitBatch(): Promise<void> {
    if (!plan || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    setBusy("submit");
    setTransactionHash("");
    try {
      const actions = buildOptimizedExpenseCalldata(plan);
      setMessage(`Confirm one STRK20 wallet request containing ${actions.length} private transfer action${actions.length === 1 ? "" : "s"}. Every recipient must already be registered.`);
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
        ? "Batch settlement confirmed inside the STRK20 pool. Keep the local allocation plan for reconciliation."
        : result.status === "failed"
          ? "The submitted batch reverted. The transaction hash is preserved; rebuild the plan before retrying."
          : "Batch submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it remains pending.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Batch settlement failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }

  function invalidatePlan(): void {
    setPlan(null);
    setFeeEstimate(null);
    setBalances({});
    setPreflightCommitment("");
    setTransactionHash("");
  }

  function resetDesk(): void {
    setRows([newExpenseRow(1), newExpenseRow(2)]);
    invalidatePlan();
    setMessage("Expense desk reset. No settlement data was persisted.");
  }

  return (
    <section className="expense-launch" aria-labelledby="expense-launch-title">
      <div className="expense-launch-copy"><span>Private treasury orchestration</span><h2 id="expense-launch-title">Settle every desk.<br /><em>Sign only once.</em></h2><p>Convert global invoice totals with exact integer math, merge duplicate vendor routes, and hand one canonical action batch to a privacy-enabled wallet.</p><button type="button" onClick={() => setOpen(true)}>Open expense settlement desk</button></div>
      <div className="expense-launch-visual" aria-hidden="true"><div><i>USD</i><i>EUR</i><i>JPY</i></div><span>exact FX</span><b>→</b><div><strong>1</strong><small>wallet request</small></div></div>
      <div className="expense-launch-principles"><div><strong>Bigint exact</strong><span>Ceiling conversion into base units</span></div><div><strong>Canonical merge</strong><span>Same token + recipient becomes one action</span></div><div><strong>Honest privacy</strong><span>Commercial metadata never enters actions</span></div></div>

      {open ? (
        <div className="expense-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
          <section className="expense-modal" role="dialog" aria-modal="true" aria-labelledby="expense-modal-title">
            <header className="expense-modal-header"><div><span>Team treasury · SN_MAIN</span><h2 id="expense-modal-title">Multi-currency settlement desk</h2><p>Private batch routed through <code>{shorten(EXPENSE_SPLITTER_POOL_ADDRESS)}</code></p></div><button type="button" onClick={() => setOpen(false)} disabled={Boolean(busy)} aria-label="Close expense settlement desk">×</button></header>

            <div className="expense-boundary-strip"><div><b>One spender</b><span>The connected treasury wallet controls every input note.</span></div><div><b>Many vendors</b><span>Registered recipients may receive different shielded tokens.</span></div><div><b>One proof request</b><span>The wallet proves and relays the complete action array.</span></div></div>

            {!plan ? (
              <form className="expense-composer" onSubmit={buildPlan}>
                <div className="expense-toolbar"><div><span>Pending invoice ledger</span><strong>{rows.length} / {MAX_PENDING_EXPENSES}</strong></div><button type="button" onClick={copySettlementAsset}>Copy first asset to all</button><button type="button" onClick={addRow} disabled={rows.length >= MAX_PENDING_EXPENSES}>Add invoice</button></div>
                <div className="expense-row-list">
                  {rows.map((row, index) => (
                    <article className="expense-row" key={row.rowId}>
                      <div className="expense-row-index"><span>{String(index + 1).padStart(2, "0")}</span><button type="button" onClick={() => removeRow(row.rowId)} disabled={rows.length <= 2}>Remove</button></div>
                      <div className="expense-fields">
                        <label>Invoice ID<input required maxLength={64} value={row.invoiceId} onChange={(event) => updateRow(row.rowId, "invoiceId", event.target.value)} /></label>
                        <label>Vendor label<input required maxLength={80} placeholder="Cloud vendor" value={row.vendorLabel} onChange={(event) => updateRow(row.rowId, "vendorLabel", event.target.value)} /></label>
                        <label>Cost center<input required maxLength={64} placeholder="Platform" value={row.costCenter} onChange={(event) => updateRow(row.rowId, "costCenter", event.target.value)} /></label>
                        <label>Invoice currency<select value={row.invoiceCurrency} onChange={(event) => updateRow(row.rowId, "invoiceCurrency", event.target.value)}>{currencies.map(([code, details]) => <option key={code} value={code}>{code} · {details.name}</option>)}</select></label>
                        <label>Invoice total<input required inputMode="decimal" placeholder="1200.00" value={row.invoiceAmount} onChange={(event) => updateRow(row.rowId, "invoiceAmount", event.target.value)} /></label>
                        <label>Token symbol<input required maxLength={12} placeholder="USDC" value={row.tokenSymbol} onChange={(event) => updateRow(row.rowId, "tokenSymbol", event.target.value)} /></label>
                        <label>Token decimals<input required inputMode="numeric" min="0" max="18" value={row.tokenDecimals} onChange={(event) => updateRow(row.rowId, "tokenDecimals", event.target.value)} /></label>
                        <label>Exact rate<small>1 {row.invoiceCurrency} = ? {row.tokenSymbol || "token"}</small><input required inputMode="decimal" placeholder="1.0875" value={row.rate} onChange={(event) => updateRow(row.rowId, "rate", event.target.value)} /></label>
                        <label className="expense-wide">Registered recipient<input required maxLength={66} placeholder="0x…" value={row.recipientAddress} onChange={(event) => updateRow(row.rowId, "recipientAddress", event.target.value)} /></label>
                        <label className="expense-wide">Settlement token contract<input required maxLength={66} placeholder="0x…" value={row.tokenAddress} onChange={(event) => updateRow(row.rowId, "tokenAddress", event.target.value)} /></label>
                        <label>Rate source<input required maxLength={96} value={row.rateSource} onChange={(event) => updateRow(row.rowId, "rateSource", event.target.value)} /></label>
                        <label>Rate expires<input required type="datetime-local" value={row.rateExpiresAt} onChange={(event) => updateRow(row.rowId, "rateExpiresAt", event.target.value)} /></label>
                      </div>
                    </article>
                  ))}
                </div>
                <aside className="expense-asset-warning"><strong>Verify every asset and recipient.</strong><p>CipherBill validates arithmetic and address shape, not token issuer, peg, liquidity, or recipient registration. FX quotes are manually supplied and remain your responsibility.</p></aside>
                <div className="expense-compose-actions"><button type="button" onClick={resetDesk}>Reset desk</button><button type="submit" disabled={busy === "plan"}>{busy === "plan" ? "Optimizing…" : "Build exact settlement batch"}</button></div>
              </form>
            ) : (
              <div className="expense-plan">
                <aside className="expense-plan-sidebar">
                  <span>Optimization result</span><div className="expense-score"><strong>{plan.expenses.length}</strong><small>invoices</small><b>→</b><strong>{plan.transfers.length}</strong><small>actions</small></div>
                  <dl><div><dt>Routes merged</dt><dd>{plan.optimization.duplicateTransfersMerged}</dd></div><div><dt>Wallet requests avoided</dt><dd>{plan.optimization.walletRequestsAvoided}</dd></div><div><dt>Rate lock</dt><dd>{new Date(plan.expiresAt).toLocaleString()}</dd></div><div><dt>Plan commitment</dt><dd><code>{shorten(plan.planCommitment)}</code></dd></div></dl>
                  <button type="button" onClick={invalidatePlan} disabled={Boolean(busy)}>Edit invoice ledger</button>
                </aside>

                <div className="expense-plan-main">
                  <section className="expense-totals"><div><span>Token liquidity required</span><h3>Exact batch totals</h3></div>{plan.tokenTotals.map((total) => { const balance = balances[total.tokenAddress]; const enough = balance === undefined || BigInt(balance) >= BigInt(total.amountBaseUnits); return <article key={total.tokenAddress}><div><strong>{total.displayAmount} {total.symbol}</strong><code>{shorten(total.tokenAddress)}</code></div><span>{total.transferCount} vendor route{total.transferCount === 1 ? "" : "s"}</span>{balance !== undefined ? <b className={enough ? "expense-enough" : "expense-short"}>{formatBaseUnits(BigInt(balance), total.decimals)} shielded · {enough ? "transfers covered, fee excluded" : "transfer shortfall"}</b> : null}</article>; })}</section>

                  <section className="expense-actions-preview"><div><span>Canonical Wallet API calldata</span><h3>{plan.transfers.length} private transfers · 1 invocation</h3></div>{plan.transfers.map((transfer, index) => <article key={transfer.transferId}><i>{String(index + 1).padStart(2, "0")}</i><div><strong>{transfer.displayAmount} {transfer.tokenSymbol}</strong><span>to <code>{shorten(transfer.recipientAddress)}</code></span></div><b>{transfer.invoiceIds.length} invoice{transfer.invoiceIds.length === 1 ? "" : "s"} merged</b></article>)}</section>

                  <section className="expense-operations">
                    <div><span>01 · Read only when needed</span><h3>Consent-driven checks</h3><p>Balance access is a wallet permission. Pool fee is read directly from the configured contract and never hardcoded.</p><div><button type="button" onClick={checkShieldedBalances} disabled={!walletReady || Boolean(busy)}>{busy === "balance" ? "Reading balances…" : "Check shielded coverage"}</button><button type="button" onClick={readPoolFee} disabled={!walletReady || Boolean(busy)}>{busy === "fee" ? "Reading fee…" : "Estimate pool-fee savings"}</button></div>{feeEstimate ? <aside><strong>{feeEstimate.estimatedPoolFeeSavingsBaseUnits}</strong><span>estimated base-unit pool fees avoided across {feeEstimate.walletInvocationsAvoided} fewer invocations</span><small>{feeEstimate.notice}</small></aside> : null}</div>
                    <div><span>02 · Optional simulation</span><h3>Prove without submission</h3><p>Ask the wallet to build and simulate this action shape. No proof or private wallet state is stored by CipherBill.</p><button type="button" onClick={dryRun} disabled={!walletReady || Boolean(busy)}>{busy === "preflight" ? "Wallet proving…" : preflightCommitment === plan.planCommitment ? "Preflight complete ✓" : "Run wallet preflight"}</button></div>
                    <div className="expense-submit-card"><span>03 · Atomic settlement request</span><h3>Settle the optimized batch</h3><p>One connected treasury wallet signs. The relayer submits; never attribute the transaction sender to the payer.</p>{!walletReady ? <WalletConnect /> : <button type="button" onClick={submitBatch} disabled={Boolean(busy)}>{busy === "submit" ? "Submitting private batch…" : "Settle all privately"}</button>}{transactionHash ? <a href={getStarknetExplorerTransactionUrl(transactionHash)} target="_blank" rel="noreferrer">Track submitted hash ↗</a> : null}</div>
                  </section>

                  {visibility ? <section className="expense-visibility"><div><span>Client only</span><p>{visibility.applicationOnly.join(" · ")}</p></div><div><span>Wallet sees</span><p>{visibility.walletRequest.join(" · ")}</p></div><div><span>Hidden in-pool</span><p>{visibility.hiddenInPool.join(" · ")}</p></div><div><span>Public / observable</span><p>{visibility.publicOrObservable.join(" · ")}</p></div><small>{visibility.limitation}</small></section> : null}
                </div>
              </div>
            )}
            <p className="expense-message" role="status" aria-live="polite">{message}</p>
          </section>
        </div>
      ) : null}
    </section>
  );
}

function newExpenseRow(index: number): ExpenseRow {
  return {
    rowId: `row_${index}_${Math.random().toString(36).slice(2, 8)}`,
    invoiceId: `team_invoice_${String(index).padStart(2, "0")}`,
    vendorLabel: "",
    costCenter: "",
    recipientAddress: "",
    invoiceCurrency: index % 2 === 0 ? "EUR" : "USD",
    invoiceAmount: "",
    tokenAddress: "",
    tokenSymbol: "USDC",
    tokenDecimals: "6",
    rate: index % 2 === 0 ? "1.08" : "1",
    rateSource: "Treasury rate desk",
    rateExpiresAt: "",
  };
}

function toPendingExpense(row: ExpenseRow): PendingExpenseInput {
  const quotedAt = new Date();
  const expiresAt = new Date(row.rateExpiresAt);
  if (!row.rateExpiresAt || Number.isNaN(expiresAt.getTime())) throw new Error(`Rate expiry for ${row.invoiceId} is required.`);
  return {
    invoiceId: row.invoiceId,
    vendorLabel: row.vendorLabel,
    costCenter: row.costCenter,
    recipientAddress: row.recipientAddress,
    invoiceCurrency: row.invoiceCurrency,
    invoiceAmount: row.invoiceAmount,
    settlementAsset: { tokenAddress: row.tokenAddress, symbol: row.tokenSymbol, decimals: Number(row.tokenDecimals) },
    rate: { rate: row.rate, source: row.rateSource, quotedAt: quotedAt.toISOString(), expiresAt: expiresAt.toISOString() },
  };
}

function shorten(value: string): string {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (decimals === 0) return value.toString();
  const padded = value.toString().padStart(decimals + 1, "0");
  const whole = padded.slice(0, -decimals);
  const fraction = padded.slice(-decimals).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}
