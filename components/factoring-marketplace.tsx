"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  buildAdvanceActions,
  buildInvoiceListingDigest,
  buildRepaymentActions,
  createFactorQuote,
  createInvoiceListing,
  FACTORING_POOL_ADDRESS,
  formatFactoringBaseUnits,
  getFactoringVisibilityModel,
  matchInvoiceFactoring,
  MAX_APR_BPS,
  MAX_DISCOUNT_BPS,
  serializeInvoiceListingDigest,
  summarizeFactoringRisk,
  type FactoringAgreement,
  type FactorPricingInput,
  type FactorPricingMode,
  type InvoiceListing,
} from "@/lib/factoring-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./factoring-marketplace.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type BusyAction = "solve" | "balance" | "advance" | "repayment" | null;

/**
 * Invoice-discounting portal for the merchant dashboard.
 *
 * Every claim here is deliberately narrow. CipherBill solves the discount arithmetic, binds one
 * listing to one quote with salted Poseidon commitments, and submits the two private in-pool
 * transfers that settle the deal. It generates no zero-knowledge proof, runs no on-chain
 * marketplace, escrows nothing, and cannot enforce that the debtor pays.
 */
export function FactoringMarketplace() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState("inv_factor_001");
  const [faceValue, setFaceValue] = useState("");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetToken, setAssetToken] = useState("");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [dueDate, setDueDate] = useState("");
  const [offerExpiry, setOfferExpiry] = useState("");
  const [merchantRecipient, setMerchantRecipient] = useState("");
  const [debtorLabel, setDebtorLabel] = useState("");
  const [memo, setMemo] = useState("");
  const [providerRecipient, setProviderRecipient] = useState("");
  const [pricingMode, setPricingMode] = useState<FactorPricingMode>("flat_discount");
  const [discountBps, setDiscountBps] = useState("250");
  const [aprBps, setAprBps] = useState("1200");
  const [platformFee, setPlatformFee] = useState("0");
  const [quoteExpiry, setQuoteExpiry] = useState("");
  const [note, setNote] = useState("");
  const [listing, setListing] = useState<InvoiceListing | null>(null);
  const [agreement, setAgreement] = useState<FactoringAgreement | null>(null);
  const [digest, setDigest] = useState("");
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [advanceHash, setAdvanceHash] = useState("");
  const [repaymentHash, setRepaymentHash] = useState("");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Enter one unpaid invoice and the discount a liquidity provider offers. CipherBill solves the advance and repayment, then settles both as private in-pool transfers.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const visibility = useMemo(() => agreement ? getFactoringVisibilityModel(agreement) : null, [agreement]);
  const risk = useMemo(() => agreement ? summarizeFactoringRisk(agreement) : null, [agreement]);

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
      const pricing: FactorPricingInput = pricingMode === "annualized"
        ? { mode: "annualized", aprBps: Number(aprBps), platformFeeBaseUnits: platformFee || "0" }
        : { mode: "flat_discount", discountBps: Number(discountBps), platformFeeBaseUnits: platformFee || "0" };
      const nextListing = createInvoiceListing({
        invoiceId,
        asset: { symbol: assetSymbol, tokenAddress: assetToken, decimals: Number(assetDecimals) },
        faceValue,
        dueDate: toIso(dueDate, "invoice due date"),
        offerExpiry: toIso(offerExpiry, "offer expiry"),
        merchantRecipient,
        debtorLabel: debtorLabel || undefined,
        memo: memo || undefined,
      });
      const quote = createFactorQuote({
        invoiceId,
        listingCommitment: nextListing.listingCommitment,
        liquidityProviderRecipient: providerRecipient,
        pricing,
        quoteExpiry: toIso(quoteExpiry, "quote expiry"),
        note: note || undefined,
      });
      const nextAgreement = matchInvoiceFactoring(nextListing, quote);
      invalidate();
      setListing(nextListing);
      setAgreement(nextAgreement);
      setMessage(`Solved: the provider advances ${nextAgreement.advanceDisplay} ${nextAgreement.asset.symbol} now against a ${nextAgreement.faceDisplay} ${nextAgreement.asset.symbol} face value due in ${nextAgreement.tenorDays} day${nextAgreement.tenorDays === 1 ? "" : "s"}. Effective all-in discount ${(nextAgreement.effectiveDiscountBps / 100).toFixed(2)}%.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The factoring terms could not be solved.");
    } finally {
      setBusy(null);
    }
  }

  async function shareDigest(): Promise<void> {
    if (!listing) return;
    const encoded = serializeInvoiceListingDigest(buildInvoiceListingDigest(listing));
    setDigest(encoded);
    try {
      await navigator.clipboard.writeText(encoded);
      setMessage("Digest copied. It carries the due date, tenor, and Poseidon commitment only: no face value, debtor identity, settlement address, or salt. Never share the full listing object.");
    } catch {
      setMessage("Clipboard access was refused. Copy the digest text below by hand.");
    }
  }

  async function checkCoverage(): Promise<void> {
    if (!agreement || !account || !walletReady || busy) return;
    const token = agreement.asset.tokenAddress;
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setWalletBalance(balance);
      setMessage(BigInt(balance) >= BigInt(agreement.advanceBaseUnits)
        ? "This shielded balance covers the advance. The pool fee the wallet adds is not included in that comparison. Only the provider needs to hold the advance; the merchant needs the face value at repayment."
        : "This shielded balance is below the advance amount. The provider's balance must hold the advance before it can be sent.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function submitTransfer(kind: "advance" | "repayment"): Promise<void> {
    if (!agreement || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    setBusy(kind);
    if (kind === "advance") setAdvanceHash(""); else setRepaymentHash("");
    try {
      const actions = kind === "advance" ? buildAdvanceActions(agreement) : buildRepaymentActions(agreement);
      setMessage(kind === "advance"
        ? `Confirm the advance in the provider's wallet: a private in-pool transfer of ${agreement.advanceDisplay} ${agreement.asset.symbol} to the merchant. The relayer submits it, so never attribute the sender to the provider.`
        : `Confirm the repayment in the merchant's wallet: a private in-pool transfer of ${agreement.repaymentDisplay} ${agreement.asset.symbol} to the provider once the debtor has paid.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      if (kind === "advance") setAdvanceHash(submitted.transaction_hash); else setRepaymentHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      setMessage(result.status === "confirmed"
        ? kind === "advance"
          ? "Advance confirmed inside the pool. Repayment is owed at collection and is not enforced on-chain: if the debtor never pays, the provider's recourse is commercial, not a protocol one."
          : "Repayment confirmed inside the pool. The factoring cycle is closed."
        : result.status === "failed"
          ? "The submitted transfer reverted. The hash is preserved; re-solve the terms before retrying."
          : "Submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it stays pending.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Submission failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }

  function invalidate(): void {
    setListing(null);
    setAgreement(null);
    setDigest("");
    setWalletBalance(null);
    setAdvanceHash("");
    setRepaymentHash("");
  }

  function resetComposer(): void {
    setFaceValue("");
    setDueDate("");
    setOfferExpiry("");
    setMerchantRecipient("");
    setDebtorLabel("");
    setMemo("");
    setProviderRecipient("");
    setQuoteExpiry("");
    setNote("");
    invalidate();
    setMessage("Composer reset. Nothing was persisted: listings, quotes, salts, and commitments live only in this browser tab.");
  }

  return (
    <section className={styles.launch} aria-labelledby="factoring-launch-title">
      <div className={styles.launchCopy}>
        <span>Invoice discounting & liquidity matching</span>
        <h2 id="factoring-launch-title">Get paid now.<br /><em>Settle privately.</em></h2>
        <p>Discount an unpaid invoice to a liquidity provider and receive an advance today, repaying the full face value once the debtor pays. CipherBill solves the terms in exact integers, binds the deal with commitments, and settles both legs as private in-pool STRK20 transfers.</p>
        <button type="button" onClick={() => setOpen(true)}>Open the discounting portal</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not zero-knowledge</strong><span>Commitments are salted Poseidon hashes. The wallet proves each transfer; CipherBill proves nothing and no contract verifies a listing or a due date.</span></div>
        <div><strong>Not a marketplace or escrow</strong><span>Matching is a local computation in one browser. Nothing is tokenized, listed on-chain, or held in escrow. Repayment is not enforced on-chain.</span></div>
        <div><strong>Not risk-free</strong><span>If the debtor never pays, the loss sits with the provider who advanced the funds. Rates and fees are committed exactly as supplied and never judged for fairness.</span></div>
      </div>

      {open ? (
        <div className={styles.backdrop} role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
          <section className={styles.modal} role="dialog" aria-modal="true" aria-labelledby="factoring-modal-title">
            <header className={styles.modalHeader}>
              <div><span>Invoice factoring · SN_MAIN</span><h2 id="factoring-modal-title">Discount an invoice for an advance</h2><p>Settlement transfers act on <code>{shorten(FACTORING_POOL_ADDRESS)}</code></p></div>
              <button type="button" onClick={() => setOpen(false)} disabled={Boolean(busy)} aria-label="Close the discounting portal">×</button>
            </header>

            <div className={styles.truth}>
              <div><b>Executable here</b><span>Two private in-pool transfers: the advance now and the repayment at collection, through the connected wallet.</span></div>
              <div><b>Computed only</b><span>The match, the discount, and the commitments. No order book, escrow, or proof exists.</span></div>
              <div><b>Exact integers</b><span>The discount rounds up in the provider&apos;s favour; the platform fee is exact.</span></div>
              <div><b>Terms are yours</b><span>Discount rates, APRs, and fees are committed as supplied. Creditworthiness is never checked.</span></div>
            </div>

            {!agreement ? (
              <form className={styles.form} onSubmit={solve}>
                <fieldset className={styles.fieldset}>
                  <span>Merchant · the unpaid invoice</span>
                  <div className={styles.fields}>
                    <label>Invoice ID<input required maxLength={64} value={invoiceId} onChange={(event) => setInvoiceId(event.target.value)} /></label>
                    <label>Face value (owed at maturity)<input required inputMode="decimal" placeholder="1000" value={faceValue} onChange={(event) => setFaceValue(event.target.value)} /></label>
                    <label>Asset symbol<input required maxLength={12} value={assetSymbol} onChange={(event) => setAssetSymbol(event.target.value)} /></label>
                    <label>Asset decimals<input required inputMode="numeric" min="0" max="18" value={assetDecimals} onChange={(event) => setAssetDecimals(event.target.value)} /></label>
                    <label className={styles.wide}>Settlement token contract<input required maxLength={66} placeholder="0x…" value={assetToken} onChange={(event) => setAssetToken(event.target.value)} /></label>
                    <label className={styles.wide}>Merchant recipient (registered, in-pool)<input required maxLength={66} placeholder="0x…" value={merchantRecipient} onChange={(event) => setMerchantRecipient(event.target.value)} /></label>
                    <label>Invoice due date (within 365 days)<input required type="datetime-local" value={dueDate} onChange={(event) => setDueDate(event.target.value)} /></label>
                    <label>Offer expiry (within 30 days)<input required type="datetime-local" value={offerExpiry} onChange={(event) => setOfferExpiry(event.target.value)} /></label>
                    <label className={styles.wide}>Debtor label (stays in this browser)<input maxLength={96} placeholder="Acme Corp ****4321" value={debtorLabel} onChange={(event) => setDebtorLabel(event.target.value)} /></label>
                    <label className={styles.wide}>Memo (stays in this browser)<input maxLength={160} placeholder="Q3 services" value={memo} onChange={(event) => setMemo(event.target.value)} /></label>
                  </div>
                </fieldset>

                <fieldset className={styles.fieldset}>
                  <span>Liquidity provider · the offer</span>
                  <div className={styles.fields}>
                    <label className={styles.wide}>Provider recipient (registered, in-pool)<input required maxLength={66} placeholder="0x…" value={providerRecipient} onChange={(event) => setProviderRecipient(event.target.value)} /></label>
                    <label>Pricing mode<select value={pricingMode} onChange={(event) => setPricingMode(event.target.value as FactorPricingMode)}><option value="flat_discount">Flat discount on face</option><option value="annualized">Annualized rate (APR)</option></select></label>
                    {pricingMode === "flat_discount"
                      ? <label>Discount (bps, max {MAX_DISCOUNT_BPS})<input required inputMode="numeric" min="1" max={MAX_DISCOUNT_BPS} value={discountBps} onChange={(event) => setDiscountBps(event.target.value)} /></label>
                      : <label>APR (bps, max {MAX_APR_BPS})<input required inputMode="numeric" min="1" max={MAX_APR_BPS} value={aprBps} onChange={(event) => setAprBps(event.target.value)} /></label>}
                    <label>Platform fee (asset base units)<input required inputMode="numeric" min="0" value={platformFee} onChange={(event) => setPlatformFee(event.target.value)} /></label>
                    <label>Quote expiry (within 30 days)<input required type="datetime-local" value={quoteExpiry} onChange={(event) => setQuoteExpiry(event.target.value)} /></label>
                    <label className={styles.wide}>Quote note (stays in this browser)<input maxLength={160} placeholder="Funds available now" value={note} onChange={(event) => setNote(event.target.value)} /></label>
                  </div>
                </fieldset>

                <div className={styles.actions}><button type="button" className={styles.ghost} onClick={resetComposer}>Reset composer</button><button type="submit" disabled={busy === "solve"}>{busy === "solve" ? "Solving…" : "Solve the advance"}</button></div>
              </form>
            ) : (
              <div className={styles.plan}>
                <aside className={styles.sidebar}>
                  <span>Advance solved</span>
                  <div className={styles.headline}><strong>{agreement.advanceDisplay} {agreement.asset.symbol}</strong><small>paid now against a {agreement.faceDisplay} {agreement.asset.symbol} face value due {new Date(agreement.dueDate).toLocaleDateString()}</small></div>
                  <dl>
                    <div><dt>Repaid at collection</dt><dd>{agreement.repaymentDisplay} {agreement.asset.symbol}</dd></div>
                    <div><dt>Discount taken</dt><dd>{agreement.discountDisplay} {agreement.asset.symbol}</dd></div>
                    <div><dt>Platform fee</dt><dd>{agreement.platformFeeDisplay} {agreement.asset.symbol}</dd></div>
                    <div><dt>Effective discount</dt><dd>{(agreement.effectiveDiscountBps / 100).toFixed(2)}%</dd></div>
                    <div><dt>Implied APR</dt><dd>{(agreement.impliedAprBps / 100).toFixed(2)}%</dd></div>
                    <div><dt>Tenor</dt><dd>{agreement.tenorDays} day{agreement.tenorDays === 1 ? "" : "s"}</dd></div>
                    <div><dt>Advance by</dt><dd>{new Date(agreement.advanceDeadline).toLocaleString()}</dd></div>
                    <div><dt>Agreement commitment</dt><dd><code>{shorten(agreement.agreementCommitment)}</code></dd></div>
                    {walletBalance !== null ? <div><dt>Shielded balance</dt><dd className={BigInt(walletBalance) >= BigInt(agreement.advanceBaseUnits) ? styles.shielded : styles.exposed}>{formatFactoringBaseUnits(walletBalance, agreement.asset.decimals)} {agreement.asset.symbol}</dd></div> : null}
                  </dl>
                  <button type="button" onClick={invalidate} disabled={Boolean(busy)}>Edit the terms</button>
                </aside>

                <div className={styles.main}>
                  <section className={styles.card}>
                    <div><span>Two private settlement transfers</span><h3>Advance now · repayment at collection</h3></div>
                    <div className={styles.legRow}>
                      <div><strong>01 · Advance</strong><small>Provider → merchant, in-pool transfer</small></div>
                      <div><b>{agreement.advanceDisplay} {agreement.asset.symbol}</b><em>signed by the provider now</em></div>
                      <div><b className={styles.shielded}>CipherBill executes</b><em>hides sender, recipient, token, amount</em></div>
                    </div>
                    <div className={styles.legRow}>
                      <div><strong>02 · Repayment</strong><small>Merchant → provider, in-pool transfer</small></div>
                      <div><b>{agreement.repaymentDisplay} {agreement.asset.symbol}</b><em>signed by the merchant at collection</em></div>
                      <div><b className={styles.exposed}>Not enforced on-chain</b><em>depends on the debtor paying</em></div>
                    </div>
                  </section>

                  <div className={styles.opsRow}>
                    <div>
                      <span>01 · Consent-driven read</span><h4>Shielded coverage</h4>
                      <p>Reads the connected wallet&apos;s balance of the settlement token with permission and keeps it in component memory only.</p>
                      <button type="button" onClick={checkCoverage} disabled={!walletReady || Boolean(busy)}>{busy === "balance" ? "Reading…" : "Check coverage"}</button>
                    </div>
                    <div>
                      <span>02 · Provider signs</span><h4>Send the advance</h4>
                      <p>One wallet request: a private in-pool transfer to the merchant. No relayer-fee action is added because the wallet appends its own.</p>
                      {!walletReady ? <WalletConnect /> : <button type="button" onClick={() => submitTransfer("advance")} disabled={Boolean(busy)}>{busy === "advance" ? "Submitting…" : "Send the advance"}</button>}
                      {advanceHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(advanceHash)} target="_blank" rel="noreferrer">Track advance hash ↗</a> : null}
                    </div>
                    <div>
                      <span>03 · Merchant signs</span><h4>Repay at collection</h4>
                      <p>Run this only after the debtor pays. A private in-pool transfer of the full face value back to the provider.</p>
                      {!walletReady ? <WalletConnect /> : <button type="button" onClick={() => submitTransfer("repayment")} disabled={Boolean(busy)}>{busy === "repayment" ? "Submitting…" : "Send the repayment"}</button>}
                      {repaymentHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(repaymentHash)} target="_blank" rel="noreferrer">Track repayment hash ↗</a> : null}
                    </div>
                  </div>

                  <section className={`${styles.card} ${styles.share}`}>
                    <div><span>Selective disclosure</span><h3>Shareable listing digest</h3></div>
                    <p>The digest carries the invoice&apos;s due date, tenor, and Poseidon commitment. It carries no face value, debtor identity, settlement address, or salt, so a provider can see the shape of the offer and later verify the disclosed listing against it. The full listing holds the salt and stays here.</p>
                    <textarea readOnly value={digest} placeholder="Copy the digest to publish this invoice's terms without its face value or debtor." />
                    <div><button type="button" onClick={shareDigest}>Copy listing digest</button></div>
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

                  {risk ? (
                    <section className={styles.card}>
                      <div><span>Risk model</span><h3>Non-payment risk sits with the {risk.nonPaymentBearer}</h3></div>
                      <p>{risk.statement}</p>
                      <ul className={styles.trustList}>{risk.trustedParties.map((party) => <li key={party}>{party}</li>)}</ul>
                    </section>
                  ) : null}

                  <section className={styles.card}>
                    <div><span>Stated limitations</span><h3>Read before relying on this deal</h3></div>
                    <ul className={styles.trustList}>{agreement.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
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
