"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  BRIDGE_OPERATORS,
  buildRouteDigest,
  buildStarknetLegActions,
  CROSS_CHAIN_ROUTER_POOL_ADDRESS,
  formatRouteBaseUnits,
  getRouteExecutionBoundary,
  getRouteVisibilityModel,
  MAX_ROUTE_LEGS,
  planCrossChainRoute,
  serializeRouteDigest,
  SETTLEMENT_VENUES,
  summarizeRouteTrust,
  type BridgeOperatorId,
  type CrossChainRoute,
  type RouteLegInput,
  type RouteLegKind,
  type SettlementVenueId,
} from "@/lib/cross-chain-router";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./cross-chain-modal.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

interface LegRow {
  rowId: string;
  kind: RouteLegKind;
  toVenue: SettlementVenueId;
  symbol: string;
  decimals: string;
  recipient: string;
  recipientLabel: string;
  operator: BridgeOperatorId;
  feeBps: string;
  fixedFee: string;
  rate: string;
}

type BusyAction = "plan" | "balance" | "preflight" | "submit" | null;

const LEG_KINDS: Array<[RouteLegKind, string]> = [
  ["pool_private_transfer", "Private transfer inside the pool"],
  ["pool_withdraw", "Withdraw the pool balance to a public Starknet address"],
  ["external_bridge", "Bridge to another network — outside CipherBill"],
  ["external_payout", "Payout at the destination venue — outside CipherBill"],
];

const VENUES = Object.entries(SETTLEMENT_VENUES) as Array<[SettlementVenueId, (typeof SETTLEMENT_VENUES)[SettlementVenueId]]>;
const EXTERNAL_VENUES = VENUES.filter(([, venue]) => venue.family !== "starknet");
const OPERATORS = Object.entries(BRIDGE_OPERATORS) as Array<[BridgeOperatorId, (typeof BRIDGE_OPERATORS)[BridgeOperatorId]]>;

/**
 * Route composer and execution portal for the merchant dashboard.
 *
 * Every claim in this UI is deliberately narrow: CipherBill solves the arithmetic of a
 * multi-hop settlement and submits the legs that stay on Starknet. It does not bridge
 * value, generate a zero-knowledge proof, or observe anything that happens off Starknet.
 */
export function CrossChainRouteModal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState("inv_route_001");
  const [deliveryAmount, setDeliveryAmount] = useState("");
  const [deadline, setDeadline] = useState("");
  const [memo, setMemo] = useState("");
  const [sourceSymbol, setSourceSymbol] = useState("USDC");
  const [sourceToken, setSourceToken] = useState("");
  const [sourceDecimals, setSourceDecimals] = useState("6");
  const [legs, setLegs] = useState<LegRow[]>(() => [newLegRow("pool_withdraw")]);
  const [route, setRoute] = useState<CrossChainRoute | null>(null);
  const [digest, setDigest] = useState("");
  const [shieldedBalance, setShieldedBalance] = useState<string | null>(null);
  const [preflighted, setPreflighted] = useState("");
  const [transactionHash, setTransactionHash] = useState("");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Describe the payout you owe. CipherBill solves what must leave the shielded balance and executes only the legs that stay on Starknet.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const boundary = useMemo(() => route ? getRouteExecutionBoundary(route) : null, [route]);
  const visibility = useMemo(() => route ? getRouteVisibilityModel(route) : null, [route]);
  const trust = useMemo(() => route ? summarizeRouteTrust(route) : null, [route]);
  const handoff = useMemo(() => {
    const index = boundary?.firstExternalLegIndex;
    if (!route || index === null || index === undefined) return null;
    const leg = route.legs[index];
    return { summary: boundary?.firstExternalLegSummary ?? "", amount: `${leg.grossInDisplay} ${leg.inputAsset.symbol}` };
  }, [boundary, route]);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, open]);

  function updateLeg(rowId: string, patch: Partial<LegRow>): void {
    setLegs((current) => current.map((leg) => leg.rowId === rowId ? { ...leg, ...patch } : leg));
  }

  function changeKind(rowId: string, kind: RouteLegKind): void {
    updateLeg(rowId, { kind, toVenue: defaultVenue(kind) });
  }

  function addLeg(): void {
    if (legs.length >= MAX_ROUTE_LEGS) return;
    setLegs([...legs, newLegRow(nextKind(legs[legs.length - 1]))]);
  }

  function removeLeg(rowId: string): void {
    if (legs.length <= 1) return;
    setLegs(legs.filter((leg) => leg.rowId !== rowId));
  }

  function buildRoute(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("plan");
    try {
      const planned = planCrossChainRoute({
        invoiceId,
        sourceAsset: { symbol: sourceSymbol, tokenAddress: sourceToken, decimals: Number(sourceDecimals) },
        deliveryAmount,
        deadline: toIsoDeadline(deadline),
        memo: memo || undefined,
        legs: legs.map((leg) => toLegInput(leg, sourceSymbol, sourceToken, sourceDecimals)),
      });
      invalidate();
      setRoute(planned);
      setMessage(`Solved backwards: ${planned.fundingDisplay} ${planned.sourceAsset.symbol} must leave the shielded balance so the payee receives ${planned.deliveryDisplay} ${planned.legs[planned.legs.length - 1].outputAsset.symbol}. CipherBill can execute ${planned.executableLegCount} of ${planned.legs.length} legs.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The settlement route could not be planned.");
    } finally {
      setBusy(null);
    }
  }

  async function shareDigest(): Promise<void> {
    if (!route) return;
    const encoded = serializeRouteDigest(buildRouteDigest(route));
    setDigest(encoded);
    try {
      await navigator.clipboard.writeText(encoded);
      setMessage("Digest copied. It carries leg structure and Poseidon commitments only: no amount, address, memo, or salt. Never share the full route object.");
    } catch {
      setMessage("Clipboard access was refused. Copy the digest text below by hand.");
    }
  }

  async function checkShieldedCoverage(): Promise<void> {
    if (!route || !account || !walletReady || busy) return;
    const token = route.sourceAsset.tokenAddress ?? "";
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setShieldedBalance(balance);
      setMessage(BigInt(balance) >= BigInt(route.fundingBaseUnits)
        ? "Shielded balance covers the funding amount. The pool fee the wallet adds is not included in that comparison."
        : "Shielded balance is below the funding amount this route needs.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function dryRun(): Promise<void> {
    if (!route || !account || !walletReady || busy) return;
    setBusy("preflight");
    setMessage("The wallet is building and proving a simulation of the Starknet legs without submitting. This can take roughly half a minute or longer depending on hardware.");
    try {
      await account.strk20PrepareInvoke(buildStarknetLegActions(route), true);
      setPreflighted(route.routeCommitment);
      setMessage("Wallet preflight completed without submission. Submitting later may require fresh proving against a newer block anchor.");
    } catch (error) {
      setPreflighted("");
      setMessage(error instanceof Error ? error.message : "Wallet preflight failed.");
    } finally {
      setBusy(null);
    }
  }

  async function submitStarknetLegs(): Promise<void> {
    if (!route || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    setBusy("submit");
    setTransactionHash("");
    try {
      const actions = buildStarknetLegActions(route);
      const exits = actions.some((action) => action.type === "withdraw");
      setMessage(`Confirm one STRK20 wallet request with ${actions.length} action${actions.length === 1 ? "" : "s"}.${exits ? " The withdrawal publishes the recipient, token, and exact amount onchain." : ""}`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setTransactionHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: exits ? "unshield" : "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed"
        ? handoff
          ? `Starknet legs confirmed. ${handoff.summary} must now be carried out with ${handoff.amount}, outside this application, and CipherBill can neither observe nor enforce it.`
          : "Every leg of this route is confirmed inside the pool."
        : result.status === "failed"
          ? "The submitted transaction reverted. The hash is preserved; re-plan the route before retrying."
          : "Submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it stays pending.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Submission failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }

  function invalidate(): void {
    setRoute(null);
    setDigest("");
    setShieldedBalance(null);
    setPreflighted("");
    setTransactionHash("");
  }

  function resetPlanner(): void {
    setDeliveryAmount("");
    setDeadline("");
    setMemo("");
    setLegs([newLegRow("pool_withdraw")]);
    invalidate();
    setMessage("Planner reset. Nothing was persisted: routes, salts, and commitments live only in this browser tab.");
  }

  return (
    <section className={styles.launch} aria-labelledby="crosschain-launch-title">
      <div className={styles.launchCopy}>
        <span>Multi-hop settlement planning</span>
        <h2 id="crosschain-launch-title">Plan the whole payout.<br /><em>Execute the Starknet part.</em></h2>
        <p>Solve a multi-hop invoice settlement backwards from the amount your payee must receive, in exact integer arithmetic. CipherBill builds Wallet API actions for the legs that stay on Starknet, then names in writing the leg where it stops.</p>
        <button type="button" onClick={() => setOpen(true)}>Open settlement route planner</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not a bridge</strong><span>Nothing here moves value off Starknet. The STRK20 Wallet API is three methods over four Starknet-only action types.</span></div>
        <div><strong>Not zero-knowledge</strong><span>Route commitments are salted Poseidon hashes. The wallet proves the transaction; CipherBill proves nothing and no contract checks a commitment.</span></div>
        <div><strong>Not untraceable</strong><span>Leaving Starknet begins with a pool withdrawal that publishes recipient, token, and exact amount.</span></div>
      </div>

      {open ? (
        <div className={styles.backdrop} role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
          <section className={styles.modal} role="dialog" aria-modal="true" aria-labelledby="crosschain-modal-title">
            <header className={styles.modalHeader}>
              <div><span>Route planner · SN_MAIN</span><h2 id="crosschain-modal-title">Cross-chain settlement route</h2><p>Starknet legs act on <code>{shorten(CROSS_CHAIN_ROUTER_POOL_ADDRESS)}</code></p></div>
              <button type="button" onClick={() => setOpen(false)} disabled={Boolean(busy)} aria-label="Close settlement route planner">×</button>
            </header>

            <div className={styles.truth}>
              <div><b>Executable here</b><span>In-pool transfers and a single pool withdrawal, through the connected wallet.</span></div>
              <div><b>Planned only</b><span>Bridge and destination payout legs. A human or another tool performs them.</span></div>
              <div><b>Exact integers</b><span>Fees round up, conversions round down, and leftover dust is reported per leg.</span></div>
              <div><b>Rates are yours</b><span>Venue rates are committed exactly as supplied. Fairness, liquidity, and solvency are never checked.</span></div>
            </div>

            {!route ? (
              <form className={styles.form} onSubmit={buildRoute}>
                <div className={styles.fields}>
                  <label>Invoice ID<input required maxLength={64} value={invoiceId} onChange={(event) => setInvoiceId(event.target.value)} /></label>
                  <label>Payee must receive<input required inputMode="decimal" placeholder="90" value={deliveryAmount} onChange={(event) => setDeliveryAmount(event.target.value)} /></label>
                  <label>Settle by (within 7 days)<input required type="datetime-local" value={deadline} onChange={(event) => setDeadline(event.target.value)} /></label>
                  <label>Memo (stays in this browser)<input maxLength={160} placeholder="Contractor payout" value={memo} onChange={(event) => setMemo(event.target.value)} /></label>
                  <label>Shielded asset symbol<input required maxLength={12} value={sourceSymbol} onChange={(event) => setSourceSymbol(event.target.value)} /></label>
                  <label>Shielded asset decimals<input required inputMode="numeric" min="0" max="18" value={sourceDecimals} onChange={(event) => setSourceDecimals(event.target.value)} /></label>
                  <label className={styles.wide}>Shielded token contract<input required maxLength={66} placeholder="0x…" value={sourceToken} onChange={(event) => setSourceToken(event.target.value)} /></label>
                </div>

                <div className={styles.toolbar}>
                  <div><strong>Route legs · {legs.length} of {MAX_ROUTE_LEGS}</strong> <span>Leg 1 is funded from the pool, and a route may exit the pool only once.</span></div>
                  <button type="button" onClick={addLeg} disabled={legs.length >= MAX_ROUTE_LEGS}>Add leg</button>
                </div>

                <div className={styles.legList}>
                  {legs.map((leg, index) => (
                    <article className={styles.leg} key={leg.rowId}>
                      <div className={styles.legIndex}><i>{String(index + 1).padStart(2, "0")}</i><button type="button" onClick={() => removeLeg(leg.rowId)} disabled={legs.length <= 1}>Remove</button></div>
                      <div className={styles.legFields}>
                        <label className={styles.wide}>Leg kind<select value={leg.kind} onChange={(event) => changeKind(leg.rowId, event.target.value as RouteLegKind)}>{LEG_KINDS.map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}</select></label>
                        {isPoolKind(leg.kind) ? (
                          <>
                            <label>Destination<input readOnly value={SETTLEMENT_VENUES[leg.toVenue].label} /></label>
                            <label>Asset (fixed inside the pool)<input readOnly value={`${sourceSymbol} · ${sourceDecimals} dp`} /></label>
                            <label className={styles.wide}>Registered Starknet recipient<input required maxLength={66} placeholder="0x…" value={leg.recipient} onChange={(event) => updateLeg(leg.rowId, { recipient: event.target.value })} /></label>
                            <label className={styles.wide}>Fees<input readOnly value="None charged here. The wallet appends its own relayer fee." /></label>
                          </>
                        ) : (
                          <>
                            <label>Destination network<select value={leg.toVenue} onChange={(event) => updateLeg(leg.rowId, { toVenue: event.target.value as SettlementVenueId })}>{EXTERNAL_VENUES.map(([id, venue]) => <option key={id} value={id}>{venue.network}</option>)}</select></label>
                            <label>Output symbol<input required maxLength={12} value={leg.symbol} onChange={(event) => updateLeg(leg.rowId, { symbol: event.target.value })} /></label>
                            <label>Output decimals<input required inputMode="numeric" min="0" max="18" value={leg.decimals} onChange={(event) => updateLeg(leg.rowId, { decimals: event.target.value })} /></label>
                            <label>Rate (output per input)<input required inputMode="decimal" value={leg.rate} onChange={(event) => updateLeg(leg.rowId, { rate: event.target.value })} /></label>
                            {leg.kind === "external_bridge" ? <label>Operator you must trust<select value={leg.operator} onChange={(event) => updateLeg(leg.rowId, { operator: event.target.value as BridgeOperatorId })}>{OPERATORS.map(([id, operator]) => <option key={id} value={id}>{operator.label}</option>)}</select></label> : null}
                            <label>Venue fee (bps, max 2000)<input required inputMode="numeric" min="0" max="2000" value={leg.feeBps} onChange={(event) => updateLeg(leg.rowId, { feeBps: event.target.value })} /></label>
                            <label>Fixed fee (input base units)<input required inputMode="numeric" value={leg.fixedFee} onChange={(event) => updateLeg(leg.rowId, { fixedFee: event.target.value })} /></label>
                            <label className={styles.wide}>Reconciliation label<input required maxLength={80} placeholder="Base treasury 0xabc…def" value={leg.recipientLabel} onChange={(event) => updateLeg(leg.rowId, { recipientLabel: event.target.value })} /></label>
                          </>
                        )}
                      </div>
                    </article>
                  ))}
                </div>

                <div className={styles.actions}><button type="button" className={styles.ghost} onClick={resetPlanner}>Reset planner</button><button type="submit" disabled={busy === "plan"}>{busy === "plan" ? "Solving…" : "Solve the funding amount"}</button></div>
              </form>
            ) : (
              <div className={styles.plan}>
                <aside className={styles.sidebar}>
                  <span>Funding solved backwards</span>
                  <div className={styles.headline}><strong>{route.fundingDisplay} {route.sourceAsset.symbol}</strong><small>must leave the shielded balance so the payee receives {route.deliveryDisplay} {route.legs[route.legs.length - 1].outputAsset.symbol}</small></div>
                  <dl>
                    <div><dt>Legs executable here</dt><dd>{route.executableLegCount} of {route.legs.length}</dd></div>
                    <div><dt>Fees across the route</dt><dd>{route.feeTotals.map((total) => `${total.feeDisplay} ${total.symbol}`).join(" · ")}</dd></div>
                    <div><dt>Estimated duration</dt><dd>{formatDuration(route.estimatedTotalSeconds)}</dd></div>
                    <div><dt>Deadline</dt><dd>{new Date(route.deadline).toLocaleString()}</dd></div>
                    <div><dt>Route commitment</dt><dd><code>{shorten(route.routeCommitment)}</code></dd></div>
                    {shieldedBalance !== null ? <div><dt>Shielded balance</dt><dd className={BigInt(shieldedBalance) >= BigInt(route.fundingBaseUnits) ? styles.shielded : styles.exposed}>{formatRouteBaseUnits(shieldedBalance, route.sourceAsset.decimals)} {route.sourceAsset.symbol}</dd></div> : null}
                  </dl>
                  <button type="button" onClick={invalidate} disabled={Boolean(busy)}>Edit the route</button>
                </aside>

                <div className={styles.main}>
                  <section className={styles.card}>
                    <div><span>Exact per-leg arithmetic</span><h3>{route.legs.length} leg{route.legs.length === 1 ? "" : "s"} · funding {route.fundingDisplay} {route.sourceAsset.symbol}</h3></div>
                    {route.legs.map((leg) => (
                      <div className={styles.legRow} key={leg.legCommitment}>
                        <i>{String(leg.index + 1).padStart(2, "0")}</i>
                        <div>
                          <strong>{SETTLEMENT_VENUES[leg.fromVenue].label} → {SETTLEMENT_VENUES[leg.toVenue].label}</strong>
                          <small>{leg.recipient ? `to ${shorten(leg.recipient)}` : leg.recipientLabel}{leg.operator ? ` · ${BRIDGE_OPERATORS[leg.operator].label}` : ""}</small>
                        </div>
                        <div>
                          <b>{leg.grossInDisplay} {leg.inputAsset.symbol} in</b>
                          <em>{leg.deliveredOutDisplay} {leg.outputAsset.symbol} out · fee {leg.totalFeeDisplay} {leg.inputAsset.symbol}{leg.surplusOutBaseUnits === "0" ? "" : ` · dust ${formatRouteBaseUnits(leg.surplusOutBaseUnits, leg.outputAsset.decimals)} ${leg.outputAsset.symbol}`}</em>
                        </div>
                        <div>
                          <b className={leg.execution === "starknet_wallet_api" ? styles.shielded : styles.exposed}>{leg.execution === "starknet_wallet_api" ? "CipherBill executes" : "Outside CipherBill"}</b>
                          <em>{leg.visibility.publicOrObservable[0]}</em>
                        </div>
                      </div>
                    ))}
                  </section>

                  {boundary ? (
                    <section className={styles.card}>
                      <div><span>Execution boundary</span><h3>Where this application stops</h3></div>
                      <p>{boundary.statement}</p>
                      {handoff ? <p>Hand off <strong>{handoff.amount}</strong> at the boundary. {handoff.summary} CipherBill cannot observe, prove, or enforce anything past that point, and a delivery failure there is a commercial dispute, not a protocol one.</p> : null}
                      {boundary.publicWithdrawalCount > 0 ? <p className={styles.limitation}>This route exits the pool {boundary.publicWithdrawalCount} time, publishing the recipient, token, and exact amount. Wait between the exit and the next hop, and avoid distinctive amounts.</p> : null}
                    </section>
                  ) : null}

                  <div className={styles.opsRow}>
                    <div>
                      <span>01 · Consent-driven read</span><h4>Shielded coverage</h4>
                      <p>Reads the source token balance with wallet permission and keeps it in component memory only.</p>
                      <button type="button" onClick={checkShieldedCoverage} disabled={!walletReady || Boolean(busy)}>{busy === "balance" ? "Reading…" : "Check coverage"}</button>
                    </div>
                    <div>
                      <span>02 · Optional simulation</span><h4>Prove without submitting</h4>
                      <p>The wallet builds and proves the Starknet legs only. No proof or wallet state is stored here.</p>
                      <button type="button" onClick={dryRun} disabled={!walletReady || Boolean(busy)}>{busy === "preflight" ? "Wallet proving…" : preflighted === route.routeCommitment ? "Preflight complete ✓" : "Run wallet preflight"}</button>
                    </div>
                    <div>
                      <span>03 · Starknet legs</span><h4>Submit {route.executableLegCount} of {route.legs.length}</h4>
                      <p>One wallet request. The relayer submits it, so never attribute the transaction sender to the payer. No relayer-fee action is added here because the wallet appends its own.</p>
                      {!walletReady ? <WalletConnect /> : <button type="button" onClick={submitStarknetLegs} disabled={Boolean(busy)}>{busy === "submit" ? "Submitting…" : "Execute the Starknet legs"}</button>}
                      {transactionHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(transactionHash)} target="_blank" rel="noreferrer">Track submitted hash ↗</a> : null}
                    </div>
                  </div>

                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Selective disclosure</span><h3>Shareable route digest</h3></div>
                    <p>The digest carries leg structure, venue labels, and per-leg commitments. It carries no amount, address, memo, or salt, so a counterparty can check the shape of the route and later verify one disclosed leg against it. The full route object holds the salts and stays here.</p>
                    <textarea readOnly value={digest} placeholder="Copy the digest to publish this route's structure without its amounts." />
                    <div><button type="button" onClick={shareDigest}>Copy route digest</button></div>
                  </section>

                  {visibility ? (
                    <section className={styles.card}>
                      <div><span>Visibility model</span><h3>Who sees what</h3></div>
                      <div className={styles.visibility}>
                        <div><span>This browser only</span><p>{visibility.applicationOnly.join(" · ")}</p></div>
                        <div><span>Wallet request</span><p>{visibility.walletRequest.join(" · ")}</p></div>
                        <div><span>Hidden in-pool</span><p>{visibility.hiddenInPool.join(" · ")}</p></div>
                        <div><span>Public or observable</span><p>{visibility.publicOrObservable.join(" · ")}</p></div>
                        <div><span>Outside this application</span><p>{visibility.outsideThisApplication.join(" · ")}</p></div>
                      </div>
                      <small className={styles.limitation}>{visibility.limitation}</small>
                    </section>
                  ) : null}

                  {trust ? (
                    <section className={styles.card}>
                      <div><span>Trust model</span><h3>{trust.starknetLegs} Starknet leg{trust.starknetLegs === 1 ? "" : "s"} · {trust.externalLegs} external</h3></div>
                      <p>{trust.statement}</p>
                      {trust.trustedParties.length ? <ul className={styles.trustList}>{trust.trustedParties.map((party) => <li key={party}>{party}</li>)}</ul> : null}
                      {trust.operators.map((entry) => <p key={entry.operator}><strong>{entry.label}.</strong> {entry.note}</p>)}
                    </section>
                  ) : null}

                  <section className={styles.card}>
                    <div><span>Stated limitations</span><h3>Read before relying on this plan</h3></div>
                    <ul className={styles.trustList}>{route.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
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

function newLegRow(kind: RouteLegKind): LegRow {
  return {
    rowId: `leg_${Math.random().toString(36).slice(2, 10)}`,
    kind,
    toVenue: defaultVenue(kind),
    symbol: "USDC",
    decimals: "6",
    recipient: "",
    recipientLabel: "",
    operator: "circle_cctp",
    feeBps: "0",
    fixedFee: "0",
    rate: "1",
  };
}

function defaultVenue(kind: RouteLegKind): SettlementVenueId {
  if (kind === "pool_private_transfer") return "strk20_pool";
  if (kind === "pool_withdraw") return "starknet_public";
  return "base";
}

/** The pool can only be exited once, so the natural next leg depends on where the last one ended. */
function nextKind(previous: LegRow | undefined): RouteLegKind {
  if (!previous) return "pool_withdraw";
  if (previous.kind === "pool_private_transfer") return "pool_withdraw";
  if (previous.kind === "pool_withdraw") return "external_bridge";
  return "external_payout";
}

function isPoolKind(kind: RouteLegKind): boolean {
  return kind === "pool_private_transfer" || kind === "pool_withdraw";
}

/** In-pool legs never change the token, so their asset is the shielded source asset. */
function toLegInput(row: LegRow, symbol: string, tokenAddress: string, decimals: string): RouteLegInput {
  const pool = isPoolKind(row.kind);
  return {
    kind: row.kind,
    toVenue: row.toVenue,
    asset: pool ? { symbol, tokenAddress, decimals: Number(decimals) } : { symbol: row.symbol, decimals: Number(row.decimals) },
    recipient: pool ? row.recipient : undefined,
    recipientLabel: pool ? undefined : row.recipientLabel,
    operator: row.kind === "external_bridge" ? row.operator : undefined,
    feeBps: pool ? 0 : Number(row.feeBps || "0"),
    fixedFeeBaseUnits: pool ? "0" : row.fixedFee || "0",
    rate: pool ? undefined : row.rate || "1",
  };
}

function toIsoDeadline(value: string): string {
  const parsed = new Date(value);
  if (!value || Number.isNaN(parsed.getTime())) throw new Error("A settlement deadline is required.");
  return parsed.toISOString();
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}min`;
}

function shorten(value: string): string {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}
