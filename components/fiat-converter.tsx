"use client";

import { useMemo, useRef, useState } from "react";

import {
  buildFiatShieldActions,
  buildPrivateFiatSettlementActions,
  calculateFiatConversion,
  createFiatShieldingPlan,
  decryptFiatShieldingPlan,
  encryptFiatShieldingPlan,
  FIAT_CURRENCIES,
  FIAT_SHIELDING_POOL_ADDRESS,
  getFiatVisibilityModel,
  parseEncryptedFiatShieldingPlan,
  serializeEncryptedFiatShieldingPlan,
  type EncryptedFiatShieldingBundle,
  type FiatCurrency,
  type FiatShieldingPlan,
} from "@/lib/fiat-shielding";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import type { PrivacyAction, PrivacyTransaction } from "@/lib/strk20/types";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

const currencyEntries = Object.entries(FIAT_CURRENCIES) as Array<[FiatCurrency, (typeof FIAT_CURRENCIES)[FiatCurrency]]>;

export function FiatConverter() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [merchantName, setMerchantName] = useState("Cipher Export Studio");
  const [invoiceId, setInvoiceId] = useState("GLOBAL-1042");
  const [invoiceCurrency, setInvoiceCurrency] = useState<FiatCurrency>("EUR");
  const [invoiceAmount, setInvoiceAmount] = useState("12500.37");
  const [pegCurrency, setPegCurrency] = useState<FiatCurrency>("USD");
  const [rate, setRate] = useState("1.07654321");
  const [rateSource, setRateSource] = useState("Merchant treasury rate lock");
  const [expiresAt, setExpiresAt] = useState("");
  const [tokenSymbol, setTokenSymbol] = useState("USDC");
  const [tokenAddress, setTokenAddress] = useState("");
  const [tokenDecimals, setTokenDecimals] = useState(6);
  const [recipientAddress, setRecipientAddress] = useState("");
  const [shieldBufferBps, setShieldBufferBps] = useState(500);
  const [memo, setMemo] = useState("");
  const [plan, setPlan] = useState<FiatShieldingPlan | null>(null);
  const [encrypted, setEncrypted] = useState<EncryptedFiatShieldingBundle | null>(null);
  const [importEnvelope, setImportEnvelope] = useState("");
  const [importKey, setImportKey] = useState("");
  const [maturityConfirmed, setMaturityConfirmed] = useState(false);
  const [shieldTransaction, setShieldTransaction] = useState<PrivacyTransaction | null>(null);
  const [paymentTransaction, setPaymentTransaction] = useState<PrivacyTransaction | null>(null);
  const [busyAction, setBusyAction] = useState<"create" | "import" | "shield" | "pay" | null>(null);
  const [message, setMessage] = useState("Lock an exact FX rate and keep the commercial invoice encrypted offchain.");
  const shieldLock = useRef(false);
  const paymentLock = useRef(false);

  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const preview = useMemo(() => {
    try {
      return calculateFiatConversion({ invoiceCurrency, invoiceAmount, settlementDecimals: tokenDecimals, rate, shieldBufferBps });
    } catch {
      return null;
    }
  }, [invoiceAmount, invoiceCurrency, rate, shieldBufferBps, tokenDecimals]);
  const visibility = plan ? getFiatVisibilityModel(plan) : null;

  async function createPlan(event: React.FormEvent) {
    event.preventDefault();
    setBusyAction("create");
    setMessage("Committing exact conversion terms and encrypting the cross-border quote locally…");
    try {
      const now = new Date();
      const created = createFiatShieldingPlan({
        invoiceId,
        merchantName,
        invoiceCurrency,
        invoiceAmount,
        recipientAddress,
        settlementAsset: { symbol: tokenSymbol, tokenAddress, decimals: tokenDecimals, pegCurrency },
        rateLock: { rate, source: rateSource, asOf: now.toISOString(), expiresAt: new Date(expiresAt).toISOString() },
        shieldBufferBps,
        memo,
      }, now);
      const sealed = await encryptFiatShieldingPlan(created);
      setPlan(created);
      setEncrypted(sealed);
      setMaturityConfirmed(false);
      setShieldTransaction(null);
      setPaymentTransaction(null);
      setMessage("Encrypted quote ready. Send the envelope and access key through separate authenticated channels.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Fiat shielding quote creation failed.");
    } finally {
      setBusyAction(null);
    }
  }

  async function openEncryptedQuote() {
    setBusyAction("import");
    try {
      const envelope = parseEncryptedFiatShieldingPlan(importEnvelope.trim());
      const opened = await decryptFiatShieldingPlan(envelope, importKey.trim());
      setPlan(opened);
      setEncrypted({ envelope, accessKey: importKey.trim() });
      setMaturityConfirmed(false);
      setShieldTransaction(null);
      setPaymentTransaction(null);
      setMessage("Encrypted quote verified and opened locally. Check every asset and rate field before shielding.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Encrypted quote could not be opened.");
    } finally {
      setBusyAction(null);
    }
  }

  async function submitShield() {
    if (!plan || !account || !walletReady || !acquireSubmission(shieldLock)) return;
    setBusyAction("shield");
    setMessage("Shielding is a public edge operation. Complete wallet prompt 1/2 for ERC-20 approval, then 2/2 for the STRK20 deposit.");
    try {
      const actions = buildFiatShieldActions(plan);
      const result = await account.strk20InvokeTransaction(actions);
      const transaction = await awaitWalletTransaction("shield", result.transaction_hash);
      setShieldTransaction(transaction);
      setMessage(transaction.status === "confirmed"
        ? "Shield confirmed. Wait approximately 10 blocks for note maturity before private settlement."
        : "Shield submitted. Preserve the hash, wait for confirmation, then allow approximately 10 blocks for maturity.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Shielding failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(shieldLock);
      setBusyAction(null);
    }
  }

  async function submitPrivatePayment() {
    if (!plan || !account || !walletReady || !maturityConfirmed || !acquireSubmission(paymentLock)) return;
    setBusyAction("pay");
    setMessage("Confirm the exact private stablecoin settlement in your wallet. Invoice currency and FX metadata are not included in the action.");
    try {
      const actions = buildPrivateFiatSettlementActions(plan);
      const result = await account.strk20InvokeTransaction(actions);
      const transaction = await awaitWalletTransaction("private_transfer", result.transaction_hash);
      setPaymentTransaction(transaction);
      setMessage(transaction.status === "confirmed"
        ? "Private cross-border settlement confirmed inside the STRK20 pool."
        : "Private settlement submitted. Confirmation is delayed; do not resubmit while the hash is pending.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Private settlement failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(paymentLock);
      setBusyAction(null);
    }
  }

  async function awaitWalletTransaction(action: PrivacyAction, hash: string): Promise<PrivacyTransaction> {
    if (!account) throw new Error("Wallet disconnected before confirmation.");
    return awaitSubmittedTransaction({
      action,
      hash,
      timeoutMs: CONFIRMATION_TIMEOUT_MS,
      waitForReceipt: () => account.provider.waitForTransaction(hash, { retries: 40, retryInterval: 3_000 }),
      isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
    });
  }

  async function copyValue(value: string, confirmation: string) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage(confirmation);
    } catch {
      setMessage("Clipboard permission was denied. Select and copy the value manually.");
    }
  }

  function downloadEncryptedQuote() {
    if (!encrypted) return;
    const blob = new Blob([serializeEncryptedFiatShieldingPlan(encrypted.envelope)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${plan?.invoiceId ?? "fiat-quote"}.encrypted`;
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage("Encrypted quote downloaded. Send its access key separately.");
  }

  function resetComposer() {
    setPlan(null);
    setEncrypted(null);
    setMaturityConfirmed(false);
    setShieldTransaction(null);
    setPaymentTransaction(null);
    setMessage("Quote closed in memory. Create or import another encrypted cross-border invoice.");
  }

  return (
    <section className="fiat-converter" aria-labelledby="fiat-converter-title">
      <header className="fiat-hero">
        <div><span>Global settlement desk</span><h2 id="fiat-converter-title">Invoice in fiat.<br /><em>Settle in private.</em></h2><p>Pin an exchange rate with exact integer math, shield a configurable fiat-pegged token, then settle the merchant without putting commercial terms onchain.</p></div>
        <div className="fiat-pool-card"><span>Routing layer</span><strong>STRK20 privacy pool</strong><code>{shorten(FIAT_SHIELDING_POOL_ADDRESS, 13, 10)}</code><i>SN_MAIN · Wallet API</i></div>
      </header>

      {!plan ? (
        <div className="fiat-compose-layout">
          <form className="fiat-form" onSubmit={createPlan}>
            <div className="fiat-section-title"><span>01 · Commercial terms</span><h3>Create an encrypted rate lock</h3></div>
            <div className="fiat-form-grid">
              <label>Merchant<input required value={merchantName} onChange={(event) => setMerchantName(event.target.value)} /></label>
              <label>Invoice reference<input required pattern="[A-Za-z0-9_-]+" value={invoiceId} onChange={(event) => setInvoiceId(event.target.value)} /></label>
              <label>Invoice currency<select value={invoiceCurrency} onChange={(event) => setInvoiceCurrency(event.target.value as FiatCurrency)}>{currencyEntries.map(([code, info]) => <option key={code} value={code}>{code} · {info.name}</option>)}</select></label>
              <label>Invoice total<input required inputMode="decimal" value={invoiceAmount} onChange={(event) => setInvoiceAmount(event.target.value.replaceAll(",", ""))} /></label>
              <label>Peg currency<select value={pegCurrency} onChange={(event) => setPegCurrency(event.target.value as FiatCurrency)}>{currencyEntries.map(([code, info]) => <option key={code} value={code}>{code} · {info.name}</option>)}</select></label>
              <label>Rate: 1 {invoiceCurrency} equals<input required inputMode="decimal" value={rate} onChange={(event) => setRate(event.target.value)} /></label>
              <label>Rate source<input required value={rateSource} onChange={(event) => setRateSource(event.target.value)} /></label>
              <label>Rate expires<input required type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
            </div>

            <div className="fiat-divider"><span>02 · Settlement rail</span></div>
            <div className="fiat-form-grid">
              <label>Token symbol<input required value={tokenSymbol} onChange={(event) => setTokenSymbol(event.target.value)} /></label>
              <label className="fiat-wide">Verified Starknet token contract<input required placeholder="0x…" value={tokenAddress} onChange={(event) => setTokenAddress(event.target.value)} /></label>
              <label>Token decimals<input required type="number" min={0} max={18} value={tokenDecimals} onChange={(event) => setTokenDecimals(Number(event.target.value))} /></label>
              <label className="fiat-wide">Registered STRK20 recipient<input required placeholder="0x…" value={recipientAddress} onChange={(event) => setRecipientAddress(event.target.value)} /></label>
              <label>Shield privacy buffer<input type="number" min={0} max={5000} step={25} value={shieldBufferBps} onChange={(event) => setShieldBufferBps(Number(event.target.value))} /><small>{(shieldBufferBps / 100).toFixed(2)}% extra liquidity</small></label>
              <label>Private memo<input maxLength={160} value={memo} onChange={(event) => setMemo(event.target.value)} /></label>
            </div>
            <div className="fiat-token-warning"><strong>Asset verification is yours.</strong><p>CipherBill validates address shape and arithmetic, not the token issuer, peg, liquidity, or pool support. Confirm the contract and decimals from an authoritative source.</p></div>
            <button className="fiat-primary-action" type="submit" disabled={busyAction === "create"}>{busyAction === "create" ? "Encrypting quote…" : "Lock rate & encrypt invoice"}</button>
          </form>

          <aside className="fiat-preview">
            <span className="fiat-preview-label">Live exact preview</span>
            <div className="fiat-preview-pair"><div><small>Invoice</small><strong>{FIAT_CURRENCIES[invoiceCurrency].symbol}{preview?.normalizedInvoiceAmount ?? "—"}</strong><i>{invoiceCurrency}</i></div><span>→</span><div><small>Exact settlement</small><strong>{preview?.settlementDisplayAmount ?? "—"}</strong><i>{tokenSymbol || "TOKEN"}</i></div></div>
            <dl><div><dt>Rate direction</dt><dd>1 {invoiceCurrency} = {preview?.normalizedRate ?? "—"} {pegCurrency}</dd></div><div><dt>Rounding</dt><dd>Ceiling, never underpay</dd></div><div><dt>Shield total</dt><dd>{preview?.shieldDisplayAmount ?? "—"} {tokenSymbol || "TOKEN"}</dd></div><div><dt>Buffer</dt><dd>{preview?.shieldBufferBaseUnits ?? "—"} base units</dd></div></dl>
            <div className="fiat-bigint-badge"><span>BIGINT</span><p>No floating-point conversion. Every minor unit and token base unit remains exact.</p></div>
            <details className="fiat-import"><summary>Open an encrypted quote</summary><textarea aria-label="Encrypted fiat quote" rows={4} value={importEnvelope} onChange={(event) => setImportEnvelope(event.target.value)} placeholder="Encrypted envelope…" /><input aria-label="Fiat quote access key" value={importKey} onChange={(event) => setImportKey(event.target.value)} placeholder="Separate access key" /><button type="button" disabled={busyAction === "import" || !importEnvelope.trim() || !importKey.trim()} onClick={openEncryptedQuote}>{busyAction === "import" ? "Opening…" : "Decrypt & verify"}</button></details>
          </aside>
        </div>
      ) : (
        <div className="fiat-execution">
          <aside className="fiat-quote-card">
            <div className="fiat-quote-top"><span>Rate locked</span><button type="button" onClick={resetComposer}>Close quote</button></div>
            <h3>{plan.merchantName}</h3><code>{plan.invoiceId}</code>
            <div className="fiat-amount-display"><small>Invoice total</small><strong>{FIAT_CURRENCIES[plan.invoiceCurrency].symbol}{plan.conversion.normalizedInvoiceAmount}</strong><i>{plan.invoiceCurrency}</i></div>
            <div className="fiat-rate-line"><span>{plan.rateLock.direction}</span><small>Expires {new Date(plan.rateLock.expiresAt).toLocaleString()}</small></div>
            <dl><div><dt>Exact payment</dt><dd>{plan.conversion.settlementDisplayAmount} {plan.settlementAsset.symbol}</dd></div><div><dt>Buffered shield</dt><dd>{plan.conversion.shieldDisplayAmount} {plan.settlementAsset.symbol}</dd></div><div><dt>Rate source</dt><dd>{plan.rateLock.source}</dd></div><div><dt>Commitment</dt><dd><code>{shorten(plan.quoteCommitment, 12, 10)}</code></dd></div></dl>
          </aside>

          <div className="fiat-action-stack">
            <section className="fiat-action-card quote-export-card"><div className="fiat-step-number">01</div><div><span>Encrypted handoff</span><h3>Share quote without metadata leakage</h3><p>The envelope and key are useless alone. Deliver them over separate authenticated channels.</p></div>{encrypted ? <div className="fiat-export-actions"><button type="button" onClick={downloadEncryptedQuote}>Download envelope</button><button type="button" onClick={() => copyValue(encrypted.accessKey, "Quote access key copied. Send it separately from the envelope.")}>Copy access key</button></div> : null}</section>
            <section className="fiat-action-card public-edge-card"><div className="fiat-step-number">02</div><div><span>Public edge</span><h3>Shield buffered liquidity</h3><p>{plan.conversion.shieldDisplayAmount} {plan.settlementAsset.symbol} enters the privacy pool. The depositor, token, amount, and timing are public.</p></div><button type="button" disabled={!walletReady || busyAction !== null} onClick={submitShield}>{busyAction === "shield" ? "Waiting for wallet…" : "Shield via two prompts"}</button>{shieldTransaction ? <a href={getStarknetExplorerTransactionUrl(shieldTransaction.hash)} target="_blank" rel="noreferrer">Track shield ↗</a> : null}</section>
            <section className="fiat-action-card private-settlement-card"><div className="fiat-step-number">03</div><div><span>Private settlement</span><h3>Pay the exact converted total</h3><p>{plan.conversion.settlementDisplayAmount} {plan.settlementAsset.symbol} moves in-pool. Invoice ID, currencies, rate, sender, recipient, token, and amount are absent from public invoice metadata.</p></div><label className="fiat-maturity-check"><input type="checkbox" checked={maturityConfirmed} onChange={(event) => setMaturityConfirmed(event.target.checked)} /><span>Shield confirmed and note matured for approximately 10 blocks</span></label><button type="button" disabled={!walletReady || !maturityConfirmed || busyAction !== null} onClick={submitPrivatePayment}>{busyAction === "pay" ? "Generating private proof…" : "Settle privately"}</button>{paymentTransaction ? <a href={getStarknetExplorerTransactionUrl(paymentTransaction.hash)} target="_blank" rel="noreferrer">Track private settlement ↗</a> : null}</section>
            {!walletReady ? <div className="fiat-wallet-row"><div><strong>Privacy wallet required</strong><p>Connect a Starknet mainnet wallet advertising STRK20 Wallet API support.</p></div><WalletConnect /></div> : null}
          </div>

          {visibility ? <section className="fiat-visibility"><div><span>Encrypted quote</span><p>{visibility.encryptedQuote.join(" · ")}</p></div><div><span>Public shield edge</span><p>{visibility.publicShieldEdge.join(" · ")}</p></div><div><span>Hidden in-pool</span><p>{visibility.hiddenPrivatePayment.join(" · ")}</p></div></section> : null}
        </div>
      )}
      <p className="fiat-message" role="status">{message}</p>
    </section>
  );
}

function shorten(value: string, start: number, end: number): string {
  return value.length <= start + end + 1 ? value : `${value.slice(0, start)}…${value.slice(-end)}`;
}
