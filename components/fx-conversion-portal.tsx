"use client";

import { FormEvent, useMemo, useRef, useState } from "react";

import {
  buildFxQuoteDigest,
  buildFxRateAuthorization,
  buildFxSettlementReceipt,
  buildSettlementActions,
  createFxQuote,
  DEFAULT_QUOTE_TTL_MINUTES,
  formatFxBaseUnits,
  FX_POOL_ADDRESS,
  getFxVisibilityModel,
  previewFxConversion,
  registerFxRateAuthority,
  serializeFxQuoteDigest,
  serializeFxSettlementReceipt,
  summarizeFxTrust,
  verifyFxRateAuthorization,
  type CreateFxQuoteInput,
  type FxConversionPreview,
  type FxQuote,
  type FxRail,
  type FxRateAuthority,
} from "@/lib/fx-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./fx-conversion-portal.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type BusyAction = "compose" | "balance" | "settle" | "receipt" | "authorize" | null;

interface RailDraft {
  symbol: string;
  tokenAddress: string;
  decimals: string;
  rate: string;
  rateSource: string;
}

const EMPTY_RAIL: RailDraft = { symbol: "", tokenAddress: "", decimals: "18", rate: "", rateSource: "Treasury desk" };

const INITIAL_RAILS: RailDraft[] = [
  { symbol: "USDC", tokenAddress: "", decimals: "6", rate: "1", rateSource: "Treasury desk" },
  { symbol: "STRK", tokenAddress: "", decimals: "18", rate: "2.5", rateSource: "Treasury desk" },
];

/** Abbreviates a long hex value (address or hash) for display; short values pass through unchanged. */
function shorten(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

/** Renders an ISO timestamp as a short local date-time; falls back to the raw string if unparseable. */
function formatWhen(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** Where the quoted settlement sits inside its slippage band, as a 0–100% width for the meter fill. */
function bandFillPercent(rail: FxRail): number {
  try {
    const min = BigInt(rail.minBaseUnits);
    const max = BigInt(rail.maxBaseUnits);
    const settled = BigInt(rail.settlementBaseUnits);
    if (max <= min) return 100;
    const pct = Number(((settled - min) * 10_000n) / (max - min)) / 100;
    return Math.max(0, Math.min(100, pct));
  } catch {
    return 100;
  }
}

/**
 * Multi-currency FX denomination and settlement portal for the merchant dashboard.
 *
 * Every claim here is deliberately narrow. CipherBill lets a merchant denominate an invoice in one
 * currency and offer several candidate settlement tokens ("rails"). Each rail's settlement amount and
 * slippage band are computed with exact integer arithmetic in this browser. When a live signer chooses a
 * rail, CipherBill submits a single private in-pool transfer in that token — no swap, no oracle, no AMM.
 * It is not decentralized and not zero-knowledge as a system: the rate is quoted off-chain, the
 * conversion is local math, and the only zero-knowledge element is the optional rate authorization.
 */
export function FxConversionPortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [invoiceId, setInvoiceId] = useState("inv_fx_001");
  const [merchant, setMerchant] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [denomDecimals, setDenomDecimals] = useState("2");
  const [amount, setAmount] = useState("100.00");
  const [slippageBps, setSlippageBps] = useState("100");
  const [validForMinutes, setValidForMinutes] = useState(String(DEFAULT_QUOTE_TTL_MINUTES));
  const [payerLabel, setPayerLabel] = useState("");
  const [memo, setMemo] = useState("");
  const [rails, setRails] = useState<RailDraft[]>(INITIAL_RAILS);
  const [quote, setQuote] = useState<FxQuote | null>(null);
  const [selectedRail, setSelectedRail] = useState("");
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [settleHash, setSettleHash] = useState("");
  const [settledRail, setSettledRail] = useState<string | null>(null);
  const [digest, setDigest] = useState("");
  const [receipt, setReceipt] = useState("");
  const [authority, setAuthority] = useState<FxRateAuthority | null>(null);
  const [rateAuth, setRateAuth] = useState("");
  const [rateAuthVerified, setRateAuthVerified] = useState<boolean | null>(null);
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState("Denominate the invoice in any currency, then add the settlement rails you accept. CipherBill computes each rail's exact settlement amount and slippage band in this browser — no swap, oracle, or price feed is involved.");
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);

  const railInputs = useMemo(
    () => rails
      .filter((rail) => rail.symbol.trim() && rail.tokenAddress.trim() && rail.rate.trim())
      .map((rail) => ({ symbol: rail.symbol, tokenAddress: rail.tokenAddress, decimals: Number(rail.decimals), rate: rail.rate, rateSource: rail.rateSource })),
    [rails],
  );

  const preview = useMemo<FxConversionPreview | null>(() => {
    if (railInputs.length === 0) return null;
    try {
      return previewFxConversion({
        denomination: { currency, decimals: Number(denomDecimals), amount },
        rails: railInputs,
        slippageBps: Number(slippageBps),
      });
    } catch {
      return null;
    }
  }, [railInputs, currency, denomDecimals, amount, slippageBps]);

  const selected = useMemo(() => quote?.rails.find((rail) => rail.symbol === selectedRail) ?? null, [quote, selectedRail]);
  const visibility = useMemo(() => { if (!quote) return null; try { return getFxVisibilityModel(quote); } catch { return null; } }, [quote]);
  const trust = useMemo(() => { if (!quote) return null; try { return summarizeFxTrust(quote); } catch { return null; } }, [quote]);

  function updateRail(index: number, patch: Partial<RailDraft>): void {
    setRails((current) => current.map((rail, i) => (i === index ? { ...rail, ...patch } : rail)));
  }

  function addRail(): void {
    setRails((current) => (current.length >= 8 ? current : [...current, { ...EMPTY_RAIL }]));
  }

  function removeRail(index: number): void {
    setRails((current) => (current.length <= 1 ? current : current.filter((_, i) => i !== index)));
  }

  function invalidate(): void {
    setSelectedRail("");
    setWalletBalance(null);
    setSettleHash("");
    setSettledRail(null);
    setDigest("");
    setReceipt("");
    setAuthority(null);
    setRateAuth("");
    setRateAuthVerified(null);
  }

  function composeQuote(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("compose");
    try {
      const input: CreateFxQuoteInput = {
        invoiceId,
        merchant,
        denomination: { currency, decimals: Number(denomDecimals), amount },
        rails: railInputs,
        slippageBps: Number(slippageBps),
        validForMinutes: validForMinutes ? Number(validForMinutes) : undefined,
        payerLabel: payerLabel || undefined,
        memo: memo || undefined,
      };
      const next = createFxQuote(input);
      invalidate();
      setQuote(next);
      setSelectedRail(next.rails[0].symbol);
      setMessage(`Quote committed: ${next.denomination.amountDisplay} ${next.denomination.currency} across ${next.rails.length} rail${next.rails.length === 1 ? "" : "s"}. Each amount is exact integer math with a ±${(next.slippageBps / 100).toFixed(2)}% band. Nothing is on-chain; the customer settles one rail with a single signed transfer.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The quote could not be composed.");
    } finally {
      setBusy(null);
    }
  }

  function resetComposer(): void {
    setQuote(null);
    invalidate();
    setMessage("Composer reset. Denominate the invoice and add the settlement rails you accept; CipherBill recomputes each rail's exact settlement and band in this browser.");
  }

  function selectRail(symbol: string): void {
    setSelectedRail(symbol);
    setWalletBalance(null);
    setRateAuth("");
    setRateAuthVerified(null);
  }

  async function checkCoverage(): Promise<void> {
    if (!quote || !selected || !account || !walletReady || busy) return;
    const token = selected.tokenAddress;
    const required = BigInt(selected.settlementBaseUnits);
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setWalletBalance(balance);
      setMessage(BigInt(balance) >= required
        ? `This shielded ${selected.symbol} balance covers the quoted settlement. The pool fee the wallet adds is not included in that comparison.`
        : `This shielded ${selected.symbol} balance is below the quoted settlement. The customer must hold the full amount before signing.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function settle(): Promise<void> {
    if (!quote || !selected || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    const symbol = selected.symbol;
    setBusy("settle");
    setSettleHash("");
    setSettledRail(null);
    try {
      const actions = buildSettlementActions(quote, symbol);
      setMessage(`Confirm in the wallet: one private in-pool transfer of ${selected.settlementDisplay} ${symbol} to the merchant. The relayer submits it, so never attribute the sender to the customer; the wallet appends its own fee, so none is added here.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setSettleHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (r) => "execution_status" in r && r.execution_status === "REVERTED",
      });
      if (result.status === "confirmed") {
        setSettledRail(symbol);
        setMessage(`Settled ${selected.settlementDisplay} ${symbol} inside the pool. This is a single one-off transfer at the quoted rate — no swap ran and no rate was proven on-chain.`);
      } else {
        setMessage(result.status === "failed" ? "The settlement reverted. The hash is preserved; retry when ready." : "Submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it stays pending.");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Submission failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }

  function buildReceipt(): void {
    if (!quote || settledRail === null || !settleHash) return;
    const rail = quote.rails.find((candidate) => candidate.symbol === settledRail);
    if (!rail) return;
    setBusy("receipt");
    try {
      const attestation = buildFxSettlementReceipt(quote, {
        railSelector: settledRail,
        settledBaseUnits: rail.settlementBaseUnits,
        settledAt: new Date().toISOString(),
        transactionHash: settleHash,
      });
      setReceipt(serializeFxSettlementReceipt(attestation));
      setMessage(`Receipt built for the ${settledRail} settlement. It records the rail, the quoted amount, the band, and the transaction hash under a commitment. It is disclosable evidence, not on-chain and not proof the transfer confirmed — verify the hash on the explorer.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The settlement receipt could not be built.");
    } finally {
      setBusy(null);
    }
  }

  function shareDigest(): void {
    if (!quote) return;
    try {
      setDigest(serializeFxQuoteDigest(buildFxQuoteDigest(quote)));
      setMessage("Quote digest built. It carries the currency, rail count, slippage, and commitment — never the amounts, rates, token addresses, merchant, payer, memo, or salt — so a counterparty can verify the quote against it without the merchant revealing the private fields.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The quote digest could not be built.");
    }
  }

  function registerAuthority(): void {
    if (busy) return;
    try {
      setAuthority(registerFxRateAuthority());
      setRateAuth("");
      setRateAuthVerified(null);
      setMessage("Rate-authority keypair generated in this browser. The secret stays local and is never shown, sent, or written into any payload; only the public key is shared out of band. This creates nothing on-chain and grants no ability to move funds.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The rate-authority keypair could not be generated.");
    }
  }

  function authorizeRate(): void {
    if (!quote || !selected || !authority || busy) return;
    setBusy("authorize");
    try {
      const auth = buildFxRateAuthorization(quote, selected.symbol, authority.authoritySecret);
      const verified = verifyFxRateAuthorization(auth, quote, authority.authorityPublicKey);
      setRateAuth(JSON.stringify(auth, null, 2));
      setRateAuthVerified(verified);
      setMessage(verified
        ? `Rate authorization for ${selected.symbol} proved and verified. This is a genuine zero-knowledge proof of knowledge of the rate-authority key, bound to this quote and rail — it attests the rate was authorized and reveals nothing about the key. It does not prove the price is fair or that any payment was made.`
        : "The authorization did not verify against the recorded authority key.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The rate authorization could not be built.");
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

  return (
    <section className={styles.launch} id="fx-shield">
      <div className={styles.launchCopy}>
        <span>Multi-currency FX &amp; settlement</span>
        <h2>Invoice in <em>any currency</em>, settle in one token.</h2>
        <p>
          CipherBill denominates an invoice in the currency you choose, then offers the settlement rails you accept.
          Each rail&apos;s exact settlement amount and slippage band are computed in this browser with integer math.
          When a cycle is settled, the customer signs one private in-pool transfer — no swap, no oracle, no AMM.
        </p>
        <button type="button" onClick={() => setOpen(true)}>Open the FX composer →</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not a swap</strong><span>No DEX, AMM, or bridge runs. The customer settles in one token they already hold; CipherBill never converts on-chain.</span></div>
        <div><strong>Not an oracle</strong><span>Rates are quoted off-chain by the merchant or a rate authority. CipherBill checks the arithmetic, never the price.</span></div>
        <div><strong>One zero-knowledge part</strong><span>Only the optional rate authorization is a real zero-knowledge proof — of knowing a key, never of a fair price or a payment.</span></div>
      </div>
      {open && renderModal()}
    </section>
  );

  function renderModal() {
    return (
      <div className={styles.backdrop} role="presentation" onClick={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
        <div className={styles.modal} role="dialog" aria-modal="true" aria-label="FX conversion composer">
          <div className={styles.modalHeader}>
            <div>
              <span>CipherBill · multi-currency settlement</span>
              <h2>FX denomination &amp; conversion composer</h2>
              <p>Pool <code>{shorten(FX_POOL_ADDRESS)}</code> · Starknet mainnet · each settlement is a single manually-signed in-pool transfer</p>
            </div>
            <button type="button" aria-label="Close" onClick={() => { if (!busy) setOpen(false); }}>×</button>
          </div>
          <div className={styles.truth}>
            <div><b>Not decentralized</b><span>The denomination, rates, and bands are computed in this browser. No contract prices or settles anything.</span></div>
            <div><b>Not a swap</b><span>One token in, same token out. There is no on-chain conversion between the denomination and the rail.</span></div>
            <div><b>Edges are public</b><span>Deposits, withdrawals, timing, and the settlement token are observable at the pool boundary.</span></div>
            <div><b>No price proof</b><span>The wallet proves the transfer; CipherBill proves no rate and no payment.</span></div>
          </div>
          {quote ? renderQuote() : renderComposer()}
          {message && <p className={styles.message}>{message}</p>}
        </div>
      </div>
    );
  }

  function renderComposer() {
    return (
      <form className={styles.form} onSubmit={composeQuote}>
        <fieldset className={styles.fieldset}>
          <legend>Invoice &amp; denomination</legend>
          <div className={styles.fields}>
            <label className={styles.wide}>Invoice ID
              <input value={invoiceId} onChange={(e) => setInvoiceId(e.target.value)} placeholder="inv_fx_001" />
            </label>
            <label className={styles.wide}>Merchant recipient (in-pool address)
              <input value={merchant} onChange={(e) => setMerchant(e.target.value)} placeholder="0x…" />
            </label>
            <label>Currency
              <input value={currency} onChange={(e) => setCurrency(e.target.value)} placeholder="USD" />
            </label>
            <label>Currency decimals
              <input value={denomDecimals} onChange={(e) => setDenomDecimals(e.target.value)} inputMode="numeric" placeholder="2" />
            </label>
            <label>Denominated amount
              <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" placeholder="100.00" />
            </label>
            <label>Slippage (bps)
              <input value={slippageBps} onChange={(e) => setSlippageBps(e.target.value)} inputMode="numeric" placeholder="100" />
            </label>
          </div>
        </fieldset>
        <fieldset className={styles.fieldset}>
          <legend>Settlement rails (candidate tokens the customer may pay in)</legend>
          <div className={styles.railEditor}>
            {rails.map((rail, index) => (
              <div key={index} className={styles.railRowEdit}>
                <label>Symbol
                  <input value={rail.symbol} onChange={(e) => updateRail(index, { symbol: e.target.value })} placeholder="USDC" />
                </label>
                <label>Token address
                  <input value={rail.tokenAddress} onChange={(e) => updateRail(index, { tokenAddress: e.target.value })} placeholder="0x…" />
                </label>
                <label>Decimals
                  <input value={rail.decimals} onChange={(e) => updateRail(index, { decimals: e.target.value })} inputMode="numeric" placeholder="18" />
                </label>
                <label>Rate (per 1 {currency || "unit"})
                  <input value={rail.rate} onChange={(e) => updateRail(index, { rate: e.target.value })} inputMode="decimal" placeholder="1" />
                </label>
                <label>Rate source
                  <input value={rail.rateSource} onChange={(e) => updateRail(index, { rateSource: e.target.value })} placeholder="Treasury desk" />
                </label>
                <button type="button" className={styles.ghost} onClick={() => removeRail(index)} disabled={rails.length <= 1}>Remove</button>
              </div>
            ))}
            <button type="button" className={styles.addRail} onClick={addRail} disabled={rails.length >= 8}>+ Add rail</button>
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
          <legend>Validity &amp; optional labels (local only)</legend>
          <div className={styles.fields}>
            <label>Valid for (minutes)
              <input value={validForMinutes} onChange={(e) => setValidForMinutes(e.target.value)} inputMode="numeric" placeholder={String(DEFAULT_QUOTE_TTL_MINUTES)} />
            </label>
            <label className={styles.wide}>Payer label
              <input value={payerLabel} onChange={(e) => setPayerLabel(e.target.value)} placeholder="Acme Corp — never an address" />
            </label>
            <label>Memo
              <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="q3 retainer" />
            </label>
          </div>
        </fieldset>
        {preview && (
          <fieldset className={styles.fieldset}>
            <span>Live preview · {preview.denominationDisplay} {preview.denominationCurrency} · ±{(preview.slippageBps / 100).toFixed(2)}% band</span>
            <div className={styles.preview}>
              {preview.rails.map((rail) => (
                <div key={rail.symbol} className={styles.previewRail}>
                  <strong>{rail.symbol}</strong>
                  <span>rate {rail.rate}</span>
                  <em>{rail.settlementDisplay} {rail.symbol}</em>
                  <span>band {rail.minDisplay} – {rail.maxDisplay}</span>
                </div>
              ))}
            </div>
          </fieldset>
        )}
        <div className={styles.actions}>
          <button type="button" className={styles.ghost} onClick={() => setOpen(false)} disabled={busy !== null}>Cancel</button>
          <button type="submit" disabled={busy !== null || railInputs.length === 0}>{busy === "compose" ? "Composing…" : "Compose quote"}</button>
        </div>
      </>
    );
  }

  function renderQuote() {
    if (!quote) return null;
    return (
      <div className={styles.plan}>
        <aside className={styles.sidebar}>
          <span>Quote</span>
          <div className={styles.headline}>
            <strong>{quote.denomination.amountDisplay} {quote.denomination.currency}</strong>
            <small>{quote.rails.length} rail{quote.rails.length === 1 ? "" : "s"} · ±{(quote.slippageBps / 100).toFixed(2)}% band</small>
          </div>
          <dl>
            <div><dt>Invoice</dt><dd>{quote.invoiceId}</dd></div>
            <div><dt>Merchant</dt><dd>{shorten(quote.merchant)}</dd></div>
            <div><dt>Quoted</dt><dd>{formatWhen(quote.quotedAt)}</dd></div>
            <div><dt>Expires</dt><dd>{formatWhen(quote.expiresAt)}</dd></div>
            <div><dt>Selected</dt><dd>{selectedRail || "—"}</dd></div>
            <div><dt>Commitment</dt><dd>{shorten(quote.quoteCommitment)}</dd></div>
          </dl>
          <button type="button" onClick={shareDigest}>Build shareable digest</button>
          <button type="button" className={styles.ghost} onClick={resetComposer} disabled={busy !== null}>Reset composer</button>
        </aside>
        <div className={styles.main}>
          {renderRails()}
          {renderOps()}
          {renderAuthority()}
          {renderShare()}
          {renderDisclosure()}
        </div>
      </div>
    );
  }

  function renderRails() {
    if (!quote) return null;
    return (
      <div className={styles.card}>
        <div><span>Exchange-rate visualizer</span></div>
        <h3>One denomination, several settlement rails</h3>
        <p>Each rail converts the {quote.denomination.amountDisplay} {quote.denomination.currency} invoice at its quoted rate using exact integer math, then derives a slippage band. Select the rail the customer will pay in. The meter shows where the quoted amount sits inside its band.</p>
        <div className={styles.rails}>
          {quote.rails.map((rail) => (
            <div key={rail.symbol} className={`${styles.railRow} ${rail.symbol === selectedRail ? styles.selected : ""}`}>
              <div>
                <div className={styles.railHead}>
                  <strong>{rail.symbol}</strong>
                  <small>rate {rail.rate} · {rail.rateSource} · {shorten(rail.tokenAddress)}</small>
                </div>
                <div className={styles.railSettle}>
                  <b>{rail.settlementDisplay} {rail.symbol}</b>
                  <div className={styles.meter}><div className={styles.meterFill} style={{ width: `${bandFillPercent(rail)}%` }} /></div>
                  <span className={styles.bandText}>band {formatFxBaseUnits(rail.minBaseUnits, rail.decimals)} – {formatFxBaseUnits(rail.maxBaseUnits, rail.decimals)} {rail.symbol}</span>
                </div>
              </div>
              <div className={styles.railActions}>
                {rail.symbol === selectedRail && <span className={styles.railPill}>selected</span>}
                <button type="button" className={styles.rowButton} onClick={() => selectRail(rail.symbol)}>{rail.symbol === selectedRail ? "Selected" : "Select rail"}</button>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  function renderOps() {
    if (!quote || !selected) return null;
    return (
      <div className={styles.card}>
        <div><span>Settle · {selected.symbol}</span></div>
        <h3>{selected.settlementDisplay} {selected.symbol} · one signed transfer</h3>
        <p>Checking coverage reads the customer&apos;s shielded {selected.symbol} balance; settling submits exactly one private in-pool transfer to the merchant in {selected.symbol}. The relayer submits it, so its sender is never the customer, and the wallet appends its own fee.</p>
        {!walletReady ? (
          <div className={styles.opsRow}>
            <div>
              <span>Wallet</span>
              <h4>Connect a STRK20 wallet</h4>
              <p>Coverage and settlement need a connected wallet with STRK20 support. Nothing is submitted until the customer confirms in the wallet.</p>
              <WalletConnect />
            </div>
          </div>
        ) : (
          <div className={styles.opsRow}>
            <div>
              <span>Coverage</span>
              <h4>Shielded balance</h4>
              <p>{walletBalance !== null ? `${formatFxBaseUnits(walletBalance, selected.decimals)} ${selected.symbol} available` : "Not checked yet."}</p>
              <button type="button" onClick={checkCoverage} disabled={busy !== null}>{busy === "balance" ? "Checking…" : "Check coverage"}</button>
            </div>
            <div>
              <span>Settle</span>
              <h4>Sign the transfer</h4>
              <p>{settleHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(settleHash)} target="_blank" rel="noreferrer">{shorten(settleHash)} ↗</a> : "One transfer, signed by the customer."}</p>
              <button type="button" onClick={settle} disabled={busy !== null}>{busy === "settle" ? "Awaiting confirmation…" : `Settle in ${selected.symbol}`}</button>
            </div>
            <div>
              <span>Receipt</span>
              <h4>Disclosable record</h4>
              <p>{settledRail !== null ? `${settledRail} settled — build its receipt.` : "Settle a rail first."}</p>
              <button type="button" onClick={buildReceipt} disabled={busy !== null || settledRail === null || !settleHash}>{busy === "receipt" ? "Building…" : "Build receipt"}</button>
            </div>
          </div>
        )}
      </div>
    );
  }

  function renderAuthority() {
    if (!quote || !selected) return null;
    return (
      <div className={styles.card}>
        <div><span>Rate authorization · the only zero-knowledge part</span></div>
        <h3>Prove the rate-authority key without revealing it</h3>
        <p>
          Generate a rate-authority keypair in this browser, then prove — in zero knowledge — knowledge of its secret
          bound to this quote and the selected rail ({selected.symbol}). This is a genuine Schnorr proof of knowledge:
          it attests the rate was authorized and reveals nothing about the key. It is <strong>not</strong> proof that
          the price is fair or that any payment was made, and it creates no on-chain record. The secret never leaves
          this browser and is never displayed.
        </p>
        <div className={styles.opsRow}>
          <div>
            <span>Keypair</span>
            <h4>{authority ? "Authority registered" : "No authority yet"}</h4>
            <p>{authority ? `Public key ${shorten(authority.authorityPublicKey.x)} — share this out of band; the secret stays hidden.` : "Generate a keypair the rate authority keeps."}</p>
            <button type="button" onClick={registerAuthority} disabled={busy !== null}>{authority ? "Regenerate keypair" : "Generate keypair"}</button>
          </div>
          <div>
            <span>Proof</span>
            <h4>Authorize {selected.symbol}</h4>
            <p>{rateAuthVerified === null ? "Not proved yet." : rateAuthVerified ? "Verified against the recorded key." : "Did not verify."}</p>
            <button type="button" onClick={authorizeRate} disabled={busy !== null || !authority}>{busy === "authorize" ? "Proving…" : "Prove & verify"}</button>
          </div>
        </div>
        {rateAuth && (
          <div className={styles.share}>
            <textarea readOnly value={rateAuth} aria-label="Rate authorization proof" />
            <div><button type="button" onClick={() => copy(rateAuth)}>Copy proof</button></div>
          </div>
        )}
      </div>
    );
  }

  function renderShare() {
    if (!digest && !receipt) return null;
    return (
      <div className={styles.card}>
        <div><span>Selective disclosure</span></div>
        <h3>Share a digest or a settlement receipt</h3>
        <p>The digest carries the currency, rail count, slippage, and commitment — never the amounts, rates, token addresses, merchant, payer, memo, or salt. A receipt records one settled rail under a commitment; it is disclosable evidence, not on-chain and not proof the transfer confirmed.</p>
        {digest && (
          <div className={styles.share}>
            <textarea readOnly value={digest} aria-label="Quote digest" />
            <div><button type="button" onClick={() => copy(digest)}>Copy digest</button></div>
          </div>
        )}
        {receipt && (
          <div className={styles.share}>
            <textarea readOnly value={receipt} aria-label="Settlement receipt" />
            <div><button type="button" onClick={() => copy(receipt)}>Copy receipt</button></div>
          </div>
        )}
      </div>
    );
  }

  function renderDisclosure() {
    if (!quote) return null;
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
        {quote.limitations.map((limit) => <span key={limit} className={styles.limitation}>{limit}</span>)}
      </div>
    );
  }
}










