"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  AFFILIATE_POOL_ADDRESS,
  buildAffiliateClaimAuthorization,
  buildAffiliatePayoutReceipt,
  buildAffiliateProgramDigest,
  buildPayoutActions,
  buildReferralLink,
  computeAffiliateReward,
  createAffiliateProgram,
  formatAffiliateBaseUnits,
  getAffiliateVisibilityModel,
  recordReferral,
  registerAffiliate,
  registerAffiliateClaimKey,
  serializeAffiliateClaimAuthorization,
  serializeAffiliatePayoutReceipt,
  serializeAffiliateProgramDigest,
  summarizeAffiliateTrust,
  verifyAffiliateClaimAuthorization,
  type AffiliateAccount,
  type AffiliateClaimKey,
  type AffiliateProgram,
  type AffiliateReferral,
} from "@/lib/affiliate-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

import styles from "./affiliate-portal.module.css";
import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

type BusyAction = "create" | "register" | "referral" | "balance" | "payout" | "receipt" | "claim" | null;

interface TierDraft {
  name: string;
  minVolume: string;
  rateBps: string;
}

const DEFAULT_TIERS: TierDraft[] = [
  { name: "Bronze", minVolume: "0", rateBps: "200" },
  { name: "Silver", minVolume: "1000", rateBps: "500" },
  { name: "Gold", minVolume: "10000", rateBps: "1000" },
];

const INTRO =
  "Define a commission program, register an affiliate with a payout address and a claim key, and record the invoice volume you attribute to them in this browser. CipherBill totals it with exact integer math and, only when you sign, pays one private in-pool transfer. Nothing here is on-chain until you pay.";

/** Abbreviates a long hex value (address or hash) for display; short values pass through unchanged. */
function shorten(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

/** Renders an ISO timestamp as a short local date; falls back to the raw string if unparseable. */
function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
/**
 * Merchant affiliate & referral portal for the CipherBill dashboard.
 *
 * Every claim here is deliberately narrow. CipherBill defines a commission program, tracks the invoice
 * volume a merchant attributes to an affiliate in this browser, resolves the tier with exact integer
 * math, and — only when a live signer chooses — submits a single private in-pool transfer of the
 * commission. It is not automated, not decentralized, and not zero-knowledge as a system: no contract
 * distributes anything, the attribution ledger is a local merchant assertion, and the only
 * zero-knowledge element is the optional claim authorization proving knowledge of an affiliate's key.
 */
export function AffiliatePortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [open, setOpen] = useState(false);
  const [merchant, setMerchant] = useState("");
  const [assetSymbol, setAssetSymbol] = useState("USDC");
  const [assetToken, setAssetToken] = useState("");
  const [assetDecimals, setAssetDecimals] = useState("6");
  const [tiers, setTiers] = useState<TierDraft[]>(DEFAULT_TIERS);
  const [memo, setMemo] = useState("");
  const [program, setProgram] = useState<AffiliateProgram | null>(null);
  const [affLabel, setAffLabel] = useState("");
  const [affPayout, setAffPayout] = useState("");
  const [claimKey, setClaimKey] = useState<AffiliateClaimKey | null>(null);
  const [affiliate, setAffiliate] = useState<AffiliateAccount | null>(null);
  const [referralLink, setReferralLink] = useState("");
  const [refInvoice, setRefInvoice] = useState("inv_001");
  const [refVolume, setRefVolume] = useState("");
  const [referrals, setReferrals] = useState<AffiliateReferral[]>([]);
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [payoutHash, setPayoutHash] = useState("");
  const [paid, setPaid] = useState(false);
  const [receipt, setReceipt] = useState("");
  const [claimPeriod, setClaimPeriod] = useState("2026-Q3");
  const [claimAuth, setClaimAuth] = useState("");
  const [claimVerified, setClaimVerified] = useState<boolean | null>(null);
  const [digest, setDigest] = useState("");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState(INTRO);
  const submitLock = useRef(false);
  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const statement = useMemo(() => {
    if (!program || !affiliate || referrals.length === 0) return null;
    try { return computeAffiliateReward(program, referrals); } catch { return null; }
  }, [program, affiliate, referrals]);
  const activeTier = statement?.tierName ?? null;
  const visibility = useMemo(() => getAffiliateVisibilityModel(), []);
  const trust = useMemo(() => summarizeAffiliateTrust(), []);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !busy) setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, open]);
  function resetAffiliateState(): void {
    setClaimKey(null);
    setAffiliate(null);
    setReferralLink("");
    setReferrals([]);
    setWalletBalance(null);
    setPayoutHash("");
    setPaid(false);
    setReceipt("");
    setClaimAuth("");
    setClaimVerified(null);
  }

  function setUpProgram(event: FormEvent): void {
    event.preventDefault();
    if (busy) return;
    setBusy("create");
    try {
      const next = createAffiliateProgram({
        merchant,
        asset: { symbol: assetSymbol, tokenAddress: assetToken, decimals: Number(assetDecimals) },
        tiers: tiers.map((tier) => ({ name: tier.name, minVolume: tier.minVolume, rateBps: Number(tier.rateBps) })),
        memo: memo || undefined,
      });
      setProgram(next);
      setDigest("");
      resetAffiliateState();
      setMessage(`Program set: ${next.tiers.length} commission tier${next.tiers.length === 1 ? "" : "s"} paying in ${next.asset.symbol}. The program, tiers, and every attribution live in this browser — none of it is on-chain.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The program could not be created.");
    } finally {
      setBusy(null);
    }
  }

  function updateTier(index: number, field: keyof TierDraft, value: string): void {
    setTiers((current) => current.map((tier, i) => i === index ? { ...tier, [field]: value } : tier));
  }

  function addTier(): void {
    setTiers((current) => current.length >= 8 ? current : [...current, { name: "", minVolume: "", rateBps: "" }]);
  }

  function removeTier(index: number): void {
    setTiers((current) => current.length <= 1 ? current : current.filter((_, i) => i !== index));
  }
  function generateClaimKey(): void {
    if (busy) return;
    try {
      setClaimKey(registerAffiliateClaimKey());
      setMessage("Claim keypair generated in this browser. The secret belongs to the affiliate and is never shown, sent, or written into any payload; only the public key is bound to the account. It lets the affiliate later prove a claim — it can never move funds.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The claim keypair could not be generated.");
    }
  }

  function registerAffiliateAccount(): void {
    if (!program || !claimKey || busy) return;
    setBusy("register");
    try {
      const next = registerAffiliate(program, {
        label: affLabel || undefined,
        payoutAddress: affPayout,
        claimPublicKey: claimKey.claimPublicKey,
      });
      setAffiliate(next);
      setReferralLink(buildReferralLink(next));
      setReferrals([]);
      setWalletBalance(null);
      setPayoutHash("");
      setPaid(false);
      setReceipt("");
      setClaimAuth("");
      setClaimVerified(null);
      setMessage(`Affiliate ${next.affiliateId} registered. Their referral code is opaque and carries no address; share the link out of band. The payout address is stored locally, never published, and only surfaces when you sign a payout.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The affiliate could not be registered.");
    } finally {
      setBusy(null);
    }
  }

  function addReferral(event: FormEvent): void {
    event.preventDefault();
    if (!program || !affiliate || busy) return;
    setBusy("referral");
    try {
      const next = recordReferral(program, affiliate, { invoiceId: refInvoice, volume: refVolume });
      setReferrals((current) => [...current, next]);
      setRefVolume("");
      setPaid(false);
      setPayoutHash("");
      setReceipt("");
      setMessage(`Attributed ${next.volumeDisplay} ${program.asset.symbol} on ${next.invoiceId} to this affiliate. This is a local bookkeeping entry, not proof the referral or the invoice is real — CipherBill totals it but cannot vouch for it.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The referral could not be recorded.");
    } finally {
      setBusy(null);
    }
  }

  function removeReferral(referralId: string): void {
    setReferrals((current) => current.filter((entry) => entry.referralId !== referralId));
    setPaid(false);
    setPayoutHash("");
    setReceipt("");
  }
  async function checkCoverage(): Promise<void> {
    if (!program || !statement || !account || !walletReady || busy) return;
    const token = program.asset.tokenAddress;
    const required = BigInt(statement.commissionBaseUnits);
    setBusy("balance");
    try {
      const entries = await account.strk20Balances([token]);
      const balance = entries.find((entry) => areSameStarknetAddress(entry.token, token))?.balance ?? "0";
      setWalletBalance(balance);
      setMessage(BigInt(balance) >= required
        ? `This shielded balance covers the ${statement.commissionDisplay} ${program.asset.symbol} commission. The pool fee the wallet adds is not included in that comparison.`
        : `This shielded balance is below the ${statement.commissionDisplay} ${program.asset.symbol} commission. Fund the payer before signing the payout.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The shielded balance could not be read.");
    } finally {
      setBusy(null);
    }
  }

  async function payCommission(): Promise<void> {
    if (!program || !affiliate || !statement || !account || !walletReady || busy || !acquireSubmission(submitLock)) return;
    setBusy("payout");
    setPayoutHash("");
    try {
      const actions = buildPayoutActions(program, affiliate, statement.commissionBaseUnits);
      setMessage(`Confirm in the wallet: one private in-pool transfer of ${statement.commissionDisplay} ${program.asset.symbol} to the affiliate's payout address. The relayer submits it, so never attribute the sender to the merchant; the wallet appends its own fee, so none is added here.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setPayoutHash(submitted.transaction_hash);
      const result = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      if (result.status === "confirmed") {
        setPaid(true);
        setMessage(`Commission settled inside the pool. Nothing recurring was authorized and no referral was proven — this paid the amount you attributed, and future volume needs its own payout.`);
      } else {
        setMessage(result.status === "failed" ? "The payout reverted. The hash is preserved; retry when ready." : "Submitted, but confirmation is delayed. Preserve the hash and do not resubmit while it stays pending.");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Submission failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(null);
    }
  }
  function buildReceipt(): void {
    if (!program || !affiliate || !statement || !payoutHash || busy) return;
    setBusy("receipt");
    try {
      const built = buildAffiliatePayoutReceipt(program, affiliate, {
        totalVolumeBaseUnits: statement.totalVolumeBaseUnits,
        tierName: statement.tierName,
        tierRateBps: statement.tierRateBps,
        commissionBaseUnits: statement.commissionBaseUnits,
        paidAt: new Date().toISOString(),
        transactionHash: payoutHash,
      });
      setReceipt(serializeAffiliatePayoutReceipt(built));
      setMessage("Receipt built. It records the tier, the attributed volume, the commission, and the transaction hash under a commitment. It is a disclosable record, not on-chain and not proof the transfer confirmed — verify the hash on the explorer.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The payout receipt could not be built.");
    } finally {
      setBusy(null);
    }
  }

  function proveClaim(): void {
    if (!program || !affiliate || !claimKey || !statement || busy) return;
    setBusy("claim");
    try {
      const auth = buildAffiliateClaimAuthorization(program, affiliate, claimKey, {
        commissionBaseUnits: statement.commissionBaseUnits,
        period: claimPeriod,
      });
      const verified = verifyAffiliateClaimAuthorization(auth, program, affiliate);
      setClaimAuth(serializeAffiliateClaimAuthorization(auth));
      setClaimVerified(verified);
      setMessage(verified
        ? `Claim authorization proved and verified. This is a genuine zero-knowledge proof of knowledge of the affiliate's claim key, bound to this program, commission, and period — it reveals nothing about the secret. It is not proof of payment or of the referral: the merchant must still sign the transfer.`
        : "The authorization did not verify against the registered claim key.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The claim authorization could not be built.");
    } finally {
      setBusy(null);
    }
  }

  function shareDigest(): void {
    if (!program) return;
    try {
      setDigest(serializeAffiliateProgramDigest(buildAffiliateProgramDigest(program)));
      setMessage("Program digest built. It carries the asset, tier count, and a commitment — never the tier rates, the memo, or the merchant address — so an affiliate can verify the program against it without the merchant revealing the private terms.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The program digest could not be built.");
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

  function resetComposer(): void {
    setProgram(null);
    setDigest("");
    resetAffiliateState();
    setTiers(DEFAULT_TIERS);
    setMessage(INTRO);
  }
  return (
    <section className={styles.launch} id="affiliate">
      <div className={styles.launchCopy}>
        <span>Affiliate &amp; referrals</span>
        <h2>Reward <em>referral volume</em>, pay it privately.</h2>
        <p>
          CipherBill lets a merchant define commission tiers, register affiliates behind opaque referral
          codes, and track attributed invoice volume in this browser. When it is time to pay, the merchant
          signs one private in-pool transfer of the commission. No contract distributes anything, nothing
          pays on a schedule, and the referral ledger is a local assertion — not an on-chain fact.
        </p>
        <button type="button" onClick={() => setOpen(true)}>Open the affiliate console →</button>
      </div>
      <div className={styles.launchFacts}>
        <div><strong>Not decentralized</strong><span>The program, tiers, and attributions are computed in this browser. There is no on-chain affiliate registry or distributor.</span></div>
        <div><strong>Not automatic</strong><span>Commissions never pay themselves. Each payout is one in-pool transfer the merchant signs by hand.</span></div>
        <div><strong>One zero-knowledge part</strong><span>Only the optional claim authorization is a real zero-knowledge proof — of knowing an affiliate&apos;s key, never of a referral or a payment.</span></div>
      </div>
      {open && renderModal()}
    </section>
  );

  function renderModal() {
    return (
      <div className={styles.backdrop} role="presentation" onClick={(event) => { if (event.target === event.currentTarget && !busy) setOpen(false); }}>
        <div className={styles.modal} role="dialog" aria-modal="true" aria-label="Affiliate program console">
          <div className={styles.modalHeader}>
            <div>
              <span>CipherBill · affiliate rewards</span>
              <h2>Merchant affiliate &amp; referral console</h2>
              <p>Pool <code>{shorten(AFFILIATE_POOL_ADDRESS)}</code> · Starknet mainnet · every payout is a single manually-signed in-pool transfer</p>
            </div>
            <button type="button" aria-label="Close" onClick={() => { if (!busy) setOpen(false); }}>×</button>
          </div>
          <div className={styles.truth}>
            <div><b>Not a distributor</b><span>No contract splits or pays commissions. The merchant keeps custody and signs each payout.</span></div>
            <div><b>Ledger is a claim</b><span>Attribution is the merchant&apos;s local record; the engine cannot prove a referral happened.</span></div>
            <div><b>Edges are public</b><span>The payout&apos;s deposit, withdrawal, timing, and a distinctive amount are observable.</span></div>
            <div><b>No payment proof</b><span>The wallet proves the transfer; CipherBill proves no referral and no payment.</span></div>
          </div>
          {program ? renderProgram() : renderComposer()}
          {message && <p className={styles.message}>{message}</p>}
        </div>
      </div>
    );
  }
  function renderComposer() {
    return (
      <form className={styles.form} onSubmit={setUpProgram}>
        <fieldset className={styles.fieldset}>
          <legend>Merchant &amp; payout asset</legend>
          <div className={styles.fields}>
            <label className={styles.wide}>Merchant (in-pool address)
              <input value={merchant} onChange={(e) => setMerchant(e.target.value)} placeholder="0x…" />
            </label>
            <label>Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} placeholder="USDC" />
            </label>
            <label>Decimals
              <input value={assetDecimals} onChange={(e) => setAssetDecimals(e.target.value)} inputMode="numeric" placeholder="6" />
            </label>
            <label className={styles.wide}>Token address
              <input value={assetToken} onChange={(e) => setAssetToken(e.target.value)} placeholder="0x…" />
            </label>
            <label className={styles.wide}>Memo (optional, local only)
              <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="Q3 partner program" />
            </label>
          </div>
        </fieldset>
        <fieldset className={styles.fieldset}>
          <legend>Commission tiers (cumulative volume, first tier starts at 0)</legend>
          <div className={styles.tierEditor}>
            {tiers.map((tier, index) => (
              <div key={index} className={styles.tierRow}>
                <label>Name
                  <input value={tier.name} onChange={(e) => updateTier(index, "name", e.target.value)} placeholder="Silver" />
                </label>
                <label>Min volume ({assetSymbol})
                  <input value={tier.minVolume} onChange={(e) => updateTier(index, "minVolume", e.target.value)} inputMode="decimal" placeholder="1000" />
                </label>
                <label>Rate (bps)
                  <input value={tier.rateBps} onChange={(e) => updateTier(index, "rateBps", e.target.value)} inputMode="numeric" placeholder="500" />
                </label>
                <button type="button" className={styles.ghost} onClick={() => removeTier(index)} disabled={tiers.length <= 1}>Remove</button>
              </div>
            ))}
            <button type="button" className={styles.addTier} onClick={addTier} disabled={tiers.length >= 8}>+ Add tier</button>
          </div>
        </fieldset>
        <div className={styles.actions}>
          <button type="button" className={styles.ghost} onClick={() => setOpen(false)} disabled={busy !== null}>Cancel</button>
          <button type="submit" disabled={busy !== null}>{busy === "create" ? "Creating…" : "Create program"}</button>
        </div>
      </form>
    );
  }
  function renderProgram() {
    if (!program) return null;
    return (
      <div className={styles.plan}>
        <aside className={styles.sidebar}>
          <span>Program</span>
          <div className={styles.headline}>
            <strong>{program.asset.symbol}</strong>
            <small>{program.tiers.length} tier{program.tiers.length === 1 ? "" : "s"} · commission in {program.asset.symbol}</small>
          </div>
          <dl>
            <div><dt>Merchant</dt><dd>{shorten(program.merchant)}</dd></div>
            <div><dt>Affiliate</dt><dd>{affiliate ? affiliate.affiliateId : "none yet"}</dd></div>
            <div><dt>Referrals</dt><dd>{referrals.length}</dd></div>
            <div><dt>Tier reached</dt><dd>{activeTier ?? "—"}</dd></div>
            <div><dt>Commission</dt><dd>{statement ? `${statement.commissionDisplay} ${program.asset.symbol}` : "—"}</dd></div>
            <div><dt>Expires</dt><dd>{formatDate(program.expiresAt)}</dd></div>
          </dl>
          <button type="button" onClick={shareDigest}>Build shareable digest</button>
          <button type="button" className={styles.ghost} onClick={resetComposer} disabled={busy !== null}>Reset console</button>
        </aside>
        <div className={styles.main}>
          {renderAffiliate()}
          {renderReferrals()}
          {renderPayout()}
          {renderClaim()}
          {renderShare()}
          {renderDisclosure()}
        </div>
      </div>
    );
  }

  function renderAffiliate() {
    if (!program) return null;
    return (
      <div className={styles.card}>
        <div><span>Affiliate &amp; referral link</span></div>
        <h3>Register an affiliate behind an opaque code</h3>
        <p>Generate the affiliate&apos;s claim keypair, then register them with a payout address. The referral code is derived from a random salt and carries no address; the payout address stays local until you sign a payout.</p>
        <div className={styles.tierList}>
          {program.tiers.map((tier, index) => (
            <div key={tier.name} className={`${styles.tierBadgeRow} ${tier.name === activeTier ? styles.active : ""}`}>
              <b>#{index + 1}</b>
              <div>
                <strong>{tier.name}</strong>
                <small>from {tier.minVolumeDisplay} {program.asset.symbol}</small>
              </div>
              <span className={styles.pill}>{(tier.rateBps / 100).toString()}%</span>
              <span>{tier.name === activeTier ? "reached" : ""}</span>
            </div>
          ))}
        </div>
        {renderAffiliateForm()}
      </div>
    );
  }
  function renderAffiliateForm() {
    return (
      <>
        <div className={styles.opsRow}>
          <div>
            <span>Claim key</span>
            <h4>{claimKey ? "Keypair generated" : "No keypair yet"}</h4>
            <p>{claimKey ? `Public key ${shorten(claimKey.claimPublicKey.x)} — the secret stays in this browser and is never shown.` : "Generate a keypair the affiliate keeps; only its public key is bound to the account."}</p>
            <button type="button" onClick={generateClaimKey} disabled={busy !== null}>{claimKey ? "Regenerate keypair" : "Generate keypair"}</button>
          </div>
          <div>
            <span>Label (local)</span>
            <h4>Optional</h4>
            <input value={affLabel} onChange={(e) => setAffLabel(e.target.value)} placeholder="Partner A — never an address" />
          </div>
          <div>
            <span>Payout address</span>
            <h4>In-pool recipient</h4>
            <input value={affPayout} onChange={(e) => setAffPayout(e.target.value)} placeholder="0x…" />
          </div>
        </div>
        <div className={styles.actions}>
          <button type="button" onClick={registerAffiliateAccount} disabled={busy !== null || !claimKey}>{busy === "register" ? "Registering…" : affiliate ? "Re-register affiliate" : "Register affiliate"}</button>
        </div>
        {referralLink && (
          <div className={styles.share}>
            <textarea readOnly value={referralLink} aria-label="Referral link" />
            <div><button type="button" onClick={() => copy(referralLink)}>Copy referral link</button></div>
          </div>
        )}
      </>
    );
  }

  function renderReferrals() {
    if (!program) return null;
    return (
      <div className={styles.card}>
        <div><span>Attributed volume</span></div>
        <h3>Record the invoice volume you credit to this affiliate</h3>
        <p>Each entry is a local, salted record binding an invoice and its volume to the affiliate. The running total resolves a tier with exact integer math; commission floor-rounds so the merchant never overpays.</p>
        {!affiliate ? (
          <p className={styles.code}>Register an affiliate above to start attributing volume.</p>
        ) : (
          <>
            <form className={styles.tierRow} onSubmit={addReferral}>
              <label>Invoice ID
                <input value={refInvoice} onChange={(e) => setRefInvoice(e.target.value)} placeholder="inv_001" />
              </label>
              <label>Volume ({program.asset.symbol})
                <input value={refVolume} onChange={(e) => setRefVolume(e.target.value)} inputMode="decimal" placeholder="5000" />
              </label>
              <span />
              <button type="submit" disabled={busy !== null}>{busy === "referral" ? "Adding…" : "Attribute"}</button>
            </form>
            {renderLedger()}
          </>
        )}
      </div>
    );
  }
  function renderLedger() {
    if (!program || referrals.length === 0) return <p className={styles.code}>No volume attributed yet.</p>;
    return (
      <>
        <div className={styles.ledger}>
          {referrals.map((entry) => (
            <div key={entry.referralId} className={styles.ledgerRow}>
              <div>
                <strong>{entry.invoiceId}</strong>
                <small>{entry.referralId}</small>
              </div>
              <span>{entry.volumeDisplay} {program.asset.symbol}</span>
              <button type="button" className={styles.rowButton} onClick={() => removeReferral(entry.referralId)}>Remove</button>
            </div>
          ))}
        </div>
        {statement && (
          <p className={styles.code}>
            Total {statement.totalVolumeDisplay} {program.asset.symbol} across {statement.referralCount} referral{statement.referralCount === 1 ? "" : "s"} → tier {statement.tierName} ({(statement.tierRateBps / 100).toString()}%) → commission {statement.commissionDisplay} {program.asset.symbol}.
          </p>
        )}
      </>
    );
  }

  function renderPayout() {
    if (!program || !affiliate) return null;
    return (
      <div className={styles.card}>
        <div><span>Payout</span></div>
        <h3>{statement ? `${statement.commissionDisplay} ${program.asset.symbol} commission` : "No commission yet"}</h3>
        <p>Checking coverage reads the payer&apos;s shielded balance; paying submits exactly one private in-pool transfer of the commission to the affiliate&apos;s payout address. The relayer submits it, so its sender is never the merchant, and the wallet appends its own fee.</p>
        {!walletReady ? (
          <div className={styles.opsRow}>
            <div>
              <span>Wallet</span>
              <h4>Connect a STRK20 wallet</h4>
              <p>Coverage checks and payouts need a connected wallet with STRK20 support. Nothing is submitted until you confirm in the wallet.</p>
              <WalletConnect />
            </div>
          </div>
        ) : (
          <div className={styles.opsRow}>
            <div>
              <span>Coverage</span>
              <h4>Shielded balance</h4>
              <p>{walletBalance !== null ? `${formatAffiliateBaseUnits(walletBalance, program.asset.decimals)} ${program.asset.symbol} available` : "Not checked yet."}</p>
              <button type="button" onClick={checkCoverage} disabled={busy !== null || !statement}>{busy === "balance" ? "Checking…" : "Check coverage"}</button>
            </div>
            <div>
              <span>Pay</span>
              <h4>Sign the payout</h4>
              <p>{payoutHash ? <a className={styles.link} href={getStarknetExplorerTransactionUrl(payoutHash)} target="_blank" rel="noreferrer">{shorten(payoutHash)} ↗</a> : "One transfer, signed by the merchant."}</p>
              <button type="button" onClick={payCommission} disabled={busy !== null || !statement}>{busy === "payout" ? "Awaiting confirmation…" : "Pay commission"}</button>
            </div>
            <div>
              <span>Receipt</span>
              <h4>Disclosable record</h4>
              <p>{paid ? "Payout settled — build its receipt." : "Pay the commission first."}</p>
              <button type="button" onClick={buildReceipt} disabled={busy !== null || !paid || !payoutHash}>{busy === "receipt" ? "Building…" : "Build receipt"}</button>
            </div>
          </div>
        )}
        {receipt && (
          <div className={styles.share}>
            <textarea readOnly value={receipt} aria-label="Payout receipt" />
            <div><button type="button" onClick={() => copy(receipt)}>Copy receipt</button></div>
          </div>
        )}
      </div>
    );
  }
  function renderClaim() {
    if (!program || !affiliate) return null;
    return (
      <div className={styles.card}>
        <div><span>Claim authorization · the only zero-knowledge part</span></div>
        <h3>Prove the claim key without revealing it</h3>
        <p>
          Using the affiliate&apos;s claim key, prove — in zero knowledge — knowledge of its secret bound to this
          program, the current commission, and a period. This is a genuine Schnorr proof of knowledge: it reveals
          nothing about the secret. It is <strong>not</strong> proof of payment and does not prove the referral
          happened; the merchant must still sign the transfer to pay. The secret never leaves this browser.
        </p>
        <div className={styles.opsRow}>
          <div>
            <span>Period</span>
            <h4>Claim label</h4>
            <input value={claimPeriod} onChange={(e) => setClaimPeriod(e.target.value)} placeholder="2026-Q3" />
          </div>
          <div>
            <span>Proof</span>
            <h4>{claimVerified === null ? "Not proved yet" : claimVerified ? "Verified" : "Did not verify"}{claimVerified !== null && <span className={`${styles.badge} ${claimVerified ? "" : styles.badgeBad}`}>{claimVerified ? "✓" : "✗"}</span>}</h4>
            <p>{claimKey ? "Proves knowledge of the claim key, bound to this commission." : "Generate the affiliate's claim key first."}</p>
            <button type="button" onClick={proveClaim} disabled={busy !== null || !claimKey || !statement}>{busy === "claim" ? "Proving…" : "Prove & verify"}</button>
          </div>
          <div>
            <span>Scope</span>
            <h4>What it binds</h4>
            <p>Program commitment, affiliate id, payout asset, commission, and period — never the secret, the payout address, or the volume breakdown.</p>
          </div>
        </div>
        {claimAuth && (
          <div className={styles.share}>
            <textarea readOnly value={claimAuth} aria-label="Claim authorization proof" />
            <div><button type="button" onClick={() => copy(claimAuth)}>Copy authorization</button></div>
          </div>
        )}
      </div>
    );
  }

  function renderShare() {
    if (!digest) return null;
    return (
      <div className={styles.card}>
        <div><span>Selective disclosure</span></div>
        <h3>Share a program digest</h3>
        <p>The digest carries the asset, tier count, and a commitment — never the tier rates, the memo, or the merchant address. An affiliate can verify the full program against it later without the merchant revealing the private terms up front.</p>
        <div className={styles.share}>
          <textarea readOnly value={digest} aria-label="Program digest" />
          <div><button type="button" onClick={() => copy(digest)}>Copy digest</button></div>
        </div>
      </div>
    );
  }

  function renderDisclosure() {
    return (
      <div className={styles.card}>
        <div><span>Honest edges</span></div>
        <h3>What is hidden, what is public, what is trusted</h3>
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
        <ul className={styles.trustList}>
          <li>{trust.statement}</li>
          <li>{trust.zeroKnowledgeElement}</li>
          {trust.trustedParties.map((party) => <li key={party}>Trusted: {party}</li>)}
        </ul>
        <span className={styles.limitation}>{visibility.limitation}</span>
        {program?.limitations.map((limit) => <span key={limit} className={styles.limitation}>{limit}</span>)}
      </div>
    );
  }
}
