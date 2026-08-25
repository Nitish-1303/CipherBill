"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  DUNNING_POOL_ADDRESS,
  assessChurnRisk,
  buildDunningBalanceDisclosure,
  buildDunningPaymentTokenDisclosure,
  buildDunningSubscriberDisclosure,
  buildDunningVoucherBadge,
  computeDunningState,
  computeRetrySchedule,
  createDunningIssuerKey,
  formatDunningBaseUnits,
  getDunningVisibilityModel,
  issueDunningVoucher,
  parseDunningBalanceDisclosure,
  parseDunningRefDisclosure,
  parseDunningVoucher,
  serializeDunningBalanceDisclosure,
  serializeDunningRefDisclosure,
  serializeDunningVoucher,
  serializeDunningVoucherSecret,
  summarizeDunningTrust,
  verifyDunningBalanceDisclosure,
  verifyDunningRefDisclosure,
  verifyDunningVoucher,
  type ChurnRiskBand,
  type DunningCadence,
  type DunningKeypair,
  type DunningVoucher,
  type IssuedDunningVoucher,
} from "@/lib/dunning-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./dunning-portal.module.css";
const INTRO =
  "When a recurring subscription invoice fails to settle, prove in zero knowledge that the delinquent subscription is still recoverable under a public dunning policy — failed retries ≤ a public maximum and delinquency age < a public grace period — without revealing the outstanding balance, the exact retry count, the delinquency age, or the subscriber. The merchant signs the voucher so anyone can authenticate it offline. It computes a retry plan but does not charge, retry, or settle any payment, and never calls the STRK20 pool contract.";

const TRUST = summarizeDunningTrust();
const VISIBILITY = getDunningVisibilityModel();

const CADENCES: { value: DunningCadence; label: string }[] = [
  { value: "fixed", label: "Fixed spacing" },
  { value: "exponential", label: "Exponential backoff" },
];

const BAND_LABEL: Record<ChurnRiskBand, string> = {
  low: "Low",
  elevated: "Elevated",
  high: "High",
  critical: "Critical",
};

/** Abbreviates a long hex value for display; short values pass through unchanged. */
function shorten(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

/** Renders an ISO timestamp as a short local date; falls back to the raw string. */
function formatDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** Streams a text payload to a downloaded file; the copyable textarea stays as a fallback. */
function download(filename: string, text: string): void {
  if (!text) return;
  try {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch {
    /* A blocked download still leaves the copyable textarea in place. */
  }
}

interface DisclosureResult {
  type: "balance" | "subscriber" | "paymentToken";
  ok: boolean;
  value: string;
}

interface VerifyState {
  ok: boolean;
  voucher?: DunningVoucher;
  disclosure?: DisclosureResult;
  error?: string;
}
export function DunningPortal() {
  // Key vault
  const [issuerKey, setIssuerKey] = useState<DunningKeypair | null>(null);
  const [revealIssuerSecret, setRevealIssuerSecret] = useState(false);

  // Issue form
  const [merchantAlias, setMerchantAlias] = useState("Aurora Studio");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState(18);
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [subscriptionRef, setSubscriptionRef] = useState("SUB-2026-0007");
  const [planLabel, setPlanLabel] = useState("Pro Monthly");
  const [maxAttempts, setMaxAttempts] = useState("5");
  const [gracePeriodDays, setGracePeriodDays] = useState("14");
  const [retryIntervalHours, setRetryIntervalHours] = useState("24");
  const [cadence, setCadence] = useState<DunningCadence>("fixed");
  const [outstandingAmount, setOutstandingAmount] = useState("1000.00");
  const [attemptsMade, setAttemptsMade] = useState("2");
  const [elapsedDays, setElapsedDays] = useState("5");
  const [subscriberRef, setSubscriberRef] = useState("sub_9f3ac41");
  const [paymentTokenRef, setPaymentTokenRef] = useState("ptok_7b2e19aa");
  const [memo, setMemo] = useState("");
  const [issuerSecretInput, setIssuerSecretInput] = useState("");

  const [built, setBuilt] = useState<IssuedDunningVoucher | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revealSecret, setRevealSecret] = useState(false);
  const [revealSubscriber, setRevealSubscriber] = useState(false);
  const [revealPaymentToken, setRevealPaymentToken] = useState(false);

  // Verify inputs
  const [verifyVoucherInput, setVerifyVoucherInput] = useState("");
  const [verifyDisclosureInput, setVerifyDisclosureInput] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState | null>(null);

  const policy = useMemo(
    () => ({
      maxAttempts: Number(maxAttempts),
      gracePeriodDays: Number(gracePeriodDays),
      retryIntervalHours: Number(retryIntervalHours),
      cadence,
    }),
    [maxAttempts, gracePeriodDays, retryIntervalHours, cadence],
  );
    /** Live, pre-issue dunning breakdown, churn band, and retry plan; local to this browser. */
  const preview = useMemo(() => {
    try {
      const outstandingBaseUnits = decimalToBaseUnits(outstandingAmount.trim(), assetDecimals);
      const state = computeDunningState(outstandingBaseUnits, Number(attemptsMade), Number(elapsedDays), policy);
      const churn = assessChurnRisk(state);
      const schedule = computeRetrySchedule(policy);
      return {
        outstanding: formatDunningBaseUnits(state.outstandingBaseUnits, assetDecimals),
        remainingAttempts: state.remainingAttempts,
        remainingGraceDays: state.remainingGraceDays,
        recoverable: state.recoverable,
        churn,
        schedule,
      };
    } catch {
      return null;
    }
  }, [outstandingAmount, assetDecimals, attemptsMade, elapsedDays, policy]);

  const serializedVoucher = useMemo(() => (built ? serializeDunningVoucher(built.voucher) : ""), [built]);
  const serializedSecret = useMemo(() => (built ? serializeDunningVoucherSecret(built.secret) : ""), [built]);
  const serializedBalanceDisclosure = useMemo(
    () => (built ? serializeDunningBalanceDisclosure(buildDunningBalanceDisclosure(built.secret)) : ""),
    [built],
  );
  const serializedSubscriberDisclosure = useMemo(
    () => (built && built.secret.subscriberCommitted ? serializeDunningRefDisclosure(buildDunningSubscriberDisclosure(built.secret)) : ""),
    [built],
  );
  const serializedPaymentTokenDisclosure = useMemo(
    () => (built && built.secret.paymentTokenCommitted ? serializeDunningRefDisclosure(buildDunningPaymentTokenDisclosure(built.secret)) : ""),
    [built],
  );
  const badge = useMemo(() => (built ? buildDunningVoucherBadge(built.voucher) : null), [built]);

  function generateIssuerKey() {
    const key = createDunningIssuerKey();
    setIssuerKey(key);
    setIssuerSecretInput(key.secretKey);
    setRevealIssuerSecret(false);
  }
    function handleIssue(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setBuildError(null);
    setRevealSecret(false);
    setRevealSubscriber(false);
    setRevealPaymentToken(false);
    try {
      const outstandingBaseUnits = decimalToBaseUnits(outstandingAmount.trim(), assetDecimals);
      const result = issueDunningVoucher(
        {
          merchantAlias: merchantAlias.trim(),
          asset: { symbol: assetSymbol.trim(), tokenAddress: tokenAddress.trim(), decimals: assetDecimals },
          subscriptionRef: subscriptionRef.trim(),
          planLabel: planLabel.trim(),
          policy: {
            maxAttempts: Number(maxAttempts.trim()),
            gracePeriodDays: Number(gracePeriodDays.trim()),
            retryIntervalHours: Number(retryIntervalHours.trim()),
            cadence,
          },
          outstandingBaseUnits,
          attemptsMade: Number(attemptsMade.trim()),
          elapsedDays: Number(elapsedDays.trim()),
          subscriberRef: subscriberRef.trim() || undefined,
          paymentTokenRef: paymentTokenRef.trim() || undefined,
          issuerSecretKey: issuerSecretInput.trim(),
          memo: memo.trim() || undefined,
        },
        new Date(),
      );
      setBuilt(result);
    } catch (error) {
      setBuilt(null);
      setBuildError(error instanceof Error ? error.message : "Could not issue the dunning voucher.");
    } finally {
      setBusy(false);
    }
  }
    function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const voucher = parseDunningVoucher(verifyVoucherInput.trim());
      const ok = verifyDunningVoucher(voucher);
      let disclosure: DisclosureResult | undefined;
      const raw = verifyDisclosureInput.trim();
      if (raw) {
        try {
          const balance = parseDunningBalanceDisclosure(raw);
          disclosure = {
            type: "balance",
            ok: verifyDunningBalanceDisclosure(voucher, balance),
            value: `${formatDunningBaseUnits(balance.outstandingBaseUnits, voucher.assetDecimals)} ${voucher.assetSymbol}`,
          };
        } catch {
          const ref = parseDunningRefDisclosure(raw);
          disclosure = {
            type: ref.field === "paymentToken" ? "paymentToken" : "subscriber",
            ok: verifyDunningRefDisclosure(voucher, ref),
            value: ref.value || "(empty)",
          };
        }
      }
      setVerifyState({ ok, voucher, disclosure });
    } catch (error) {
      setVerifyState({ ok: false, error: error instanceof Error ? error.message : "Could not decode the voucher." });
    }
  }
  const disclosureLabel: Record<DisclosureResult["type"], string> = {
    balance: "Balance disclosure",
    subscriber: "Subscriber disclosure",
    paymentToken: "Payment-token disclosure",
  };

  return (
    <section className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Subscription Dunning &amp; Churn Mitigation</span>
          <h2>Zero-knowledge <em>recovery vouchers</em></h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(DUNNING_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div><dt>retries ≤ max &amp; age &lt; grace</dt><dd className={styles.yes}>ZK proven</dd></div>
          <div><dt>Issuer signature</dt><dd className={styles.yes}>Authenticated</dd></div>
          <div><dt>Charges / retries / settles</dt><dd className={styles.no}>Never</dd></div>
          <div><dt>Pool contract</dt><dd className={styles.no}>Never called</dd></div>
        </dl>
      </header>
      <div className={styles.dashboard}>
        <div className={styles.dashHead}>
          <span>Churn-risk dashboard · live heuristic</span>
          <small>Local to this browser · deterministic band, not a predictive model or financial advice</small>
        </div>
        <dl className={styles.dashGrid}>
          <div className={styles.metric}><dt>Outstanding</dt><dd>{preview ? `${preview.outstanding} ${assetSymbol}` : "—"}</dd></div>
          <div className={styles.metric}><dt>Retries left</dt><dd>{preview ? `${preview.remainingAttempts} of ${maxAttempts}` : "—"}</dd></div>
          <div className={styles.metric}><dt>Grace left</dt><dd>{preview ? `${preview.remainingGraceDays} days` : "—"}</dd></div>
          <div className={`${styles.metric} ${styles.risk}`} data-band={preview?.churn.band ?? "low"}>
            <dt>Churn risk</dt>
            <dd>{preview ? `${BAND_LABEL[preview.churn.band]} · ${preview.churn.score}` : "—"}</dd>
          </div>
        </dl>
        {preview && !preview.recoverable && (
          <p className={styles.warn}>This subscription is outside the recovery policy — retries exhausted or grace lapsed — so no voucher can be issued.</p>
        )}
        <div className={styles.tableWrap}>
          <table className={styles.jurTable}>
            <thead><tr><th>Retry</th><th>Hour offset</th><th>Day offset</th><th>Within grace</th></tr></thead>
            <tbody>
              {(preview?.schedule ?? []).map((entry) => (
                <tr key={entry.attempt}>
                  <td>#{entry.attempt}</td>
                  <td>+{entry.hourOffset}h</td>
                  <td>day {entry.dayOffset}</td>
                  <td className={entry.withinGrace ? styles.rateCell : styles.warnCell}>{entry.withinGrace ? "yes" : "past grace"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className={styles.hint}>The retry cadence is a plan only — CipherBill computes it; the merchant&apos;s own billing scheduler must execute it.</p>
      </div>
      <div className={styles.vault}>
        <div className={styles.vaultHead}>
          <span>00 · Issuer key vault</span>
          <div className={styles.vaultActions}>
            <button type="button" className={styles.ghost} onClick={generateIssuerKey}>Generate issuer key</button>
          </div>
        </div>
        <div className={styles.keyGrid}>
          <div className={styles.keyCard}>
            <h4>Merchant issuer key</h4>
            {issuerKey ? (
              <dl>
                <div><dt>Public key</dt><dd>{shorten(issuerKey.publicKey.x)}</dd></div>
                <dt className={styles.secretTag}>Secret signing key {revealIssuerSecret ? "" : "(hidden)"}
                  <button type="button" className={styles.ghost} onClick={() => setRevealIssuerSecret((v) => !v)}>{revealIssuerSecret ? "Hide" : "Reveal"}</button>
                </dt>
                <dd>{revealIssuerSecret ? issuerKey.secretKey : "•••••••• — the merchant keeps this to sign and open vouchers"}</dd>
              </dl>
            ) : (
              <p className={styles.hint}>Generate a signing key, or paste an existing issuer secret into the issue form. The same key signs the voucher and later opens selective disclosures.</p>
            )}
          </div>
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleIssue}>
          <div className={styles.panelHead}>
            <span>01 · Issue</span>
            <h3>Cryptographic recovery voucher</h3>
          </div>
          <div className={styles.fields}>
            <label className={styles.wide}>Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} placeholder="Aurora Studio" />
            </label>
            <label>Asset symbol
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} placeholder="STRK" />
            </label>
            <label>Decimals
              <input type="number" min={0} max={18} value={assetDecimals} onChange={(e) => setAssetDecimals(Number(e.target.value))} />
            </label>
            <label className={styles.wide}>Token address <small>provenance only — never called</small>
              <input value={tokenAddress} onChange={(e) => setTokenAddress(e.target.value)} spellCheck={false} />
            </label>
            <label>Subscription reference
              <input value={subscriptionRef} onChange={(e) => setSubscriptionRef(e.target.value)} placeholder="SUB-2026-0007" />
            </label>
            <label>Plan label
              <input value={planLabel} onChange={(e) => setPlanLabel(e.target.value)} placeholder="Pro Monthly" />
            </label>
            <label>Max retries <small>public policy, 1–32</small>
              <input value={maxAttempts} onChange={(e) => setMaxAttempts(e.target.value)} inputMode="numeric" />
            </label>
            <label>Grace period <small>public days, 1–365</small>
              <input value={gracePeriodDays} onChange={(e) => setGracePeriodDays(e.target.value)} inputMode="numeric" />
            </label>
            <label>Retry interval <small>public hours</small>
              <input value={retryIntervalHours} onChange={(e) => setRetryIntervalHours(e.target.value)} inputMode="numeric" />
            </label>
            <label>Cadence
              <select value={cadence} onChange={(e) => setCadence(e.target.value as DunningCadence)}>
                {CADENCES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </label>
            <label>Outstanding amount <small>private — hidden in voucher</small>
              <input value={outstandingAmount} onChange={(e) => setOutstandingAmount(e.target.value)} inputMode="decimal" />
            </label>
            <label>Failed retries so far <small>private — proven ≤ max</small>
              <input value={attemptsMade} onChange={(e) => setAttemptsMade(e.target.value)} inputMode="numeric" />
            </label>
            <label>Delinquency age <small>private days — proven &lt; grace</small>
              <input value={elapsedDays} onChange={(e) => setElapsedDays(e.target.value)} inputMode="numeric" />
            </label>
            <label>Subscriber reference <small>committed, not revealed</small>
              <input value={subscriberRef} onChange={(e) => setSubscriberRef(e.target.value)} placeholder="optional — blank = uncommitted" />
            </label>
            <label className={styles.wide}>Payment-token reference <small>committed, not stored or replayable</small>
              <input value={paymentTokenRef} onChange={(e) => setPaymentTokenRef(e.target.value)} placeholder="optional — blank = uncommitted" spellCheck={false} />
            </label>
            <label className={styles.wide}>Issuer secret signing key
              <input value={issuerSecretInput} onChange={(e) => setIssuerSecretInput(e.target.value)} placeholder="0x… (or generate above)" spellCheck={false} />
            </label>
            <label className={styles.wide}>Memo <small>optional</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="Card expired · retry after refresh" />
            </label>
          </div>
          {buildError && <p className={styles.error}>{buildError}</p>}
          <button type="submit" disabled={busy}>{busy ? "Proving in zero knowledge…" : "Issue recovery voucher"}</button>
        </form>
        <div className={styles.panel}>
          <div className={styles.panelHead}>
            <span>02 · Issued voucher</span>
            <h3>Shareable recovery voucher</h3>
          </div>
          {built && badge ? (
            <>
              <div className={styles.badge}>
                <div className={styles.badgeTop}>
                  <div>
                    <strong>{badge.merchantAlias}</strong>
                    <small>{badge.subscriptionRef} · {formatDate(badge.createdAt)}</small>
                  </div>
                  <span className={styles.verified}>ZK verified</span>
                </div>
                <p className={styles.badgeClaim}>
                  Recoverable under <b>{badge.maxAttemptsDisplay}</b> &amp; <b>{badge.gracePeriodDisplay}</b>
                  <small>Balance, exact retry count, and delinquency age stay hidden inside the commitments.</small>
                </p>
                <dl className={styles.badgeMeta}>
                  <div><dt>Plan</dt><dd>{badge.planLabel}</dd></div>
                  <div><dt>Cadence</dt><dd>{badge.cadenceDisplay}</dd></div>
                  <div><dt>Subscriber</dt><dd>{badge.subscriberCommitted ? "committed" : "uncommitted"}</dd></div>
                  <div><dt>Payment token</dt><dd>{badge.paymentTokenCommitted ? "committed" : "uncommitted"}</dd></div>
                  <div><dt>Voucher id</dt><dd>{badge.voucherId}</dd></div>
                  <div><dt>Binding</dt><dd>{shorten(badge.bindingHash)}</dd></div>
                </dl>
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Recovery voucher (safe to publish)</span>
                  <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.voucher.txt`, serializedVoucher)}>Download</button>
                </div>
                <textarea readOnly value={serializedVoucher} rows={4} />
              </div>
              <div className={styles.export}>
                <div className={styles.exportHead}>
                  <span>Balance disclosure</span>
                  <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.balance-disclosure.txt`, serializedBalanceDisclosure)}>Download</button>
                </div>
                <p className={styles.hint}>Opens the outstanding balance alone for a party entitled to it; the retry count and delinquency age stay hidden.</p>
                <textarea readOnly value={serializedBalanceDisclosure} rows={3} />
              </div>
              {built.secret.subscriberCommitted && (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Subscriber disclosure {revealSubscriber ? "" : "(hidden)"}</span>
                    <div className={styles.secretActions}>
                      <button type="button" className={styles.ghost} onClick={() => setRevealSubscriber((v) => !v)}>{revealSubscriber ? "Hide" : "Reveal"}</button>
                      <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.subscriber-disclosure.txt`, serializedSubscriberDisclosure)}>Download</button>
                    </div>
                  </div>
                  <p className={styles.warn}>Reveals the committed subscriber reference. Share only with a party entitled to it.</p>
                  {revealSubscriber && <textarea readOnly value={serializedSubscriberDisclosure} rows={3} />}
                </div>
              )}
              {built.secret.paymentTokenCommitted && (
                <div className={styles.secret}>
                  <div className={styles.exportHead}>
                    <span className={styles.secretTag}>Payment-token disclosure {revealPaymentToken ? "" : "(hidden)"}</span>
                    <div className={styles.secretActions}>
                      <button type="button" className={styles.ghost} onClick={() => setRevealPaymentToken((v) => !v)}>{revealPaymentToken ? "Hide" : "Reveal"}</button>
                      <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.payment-token-disclosure.txt`, serializedPaymentTokenDisclosure)}>Download</button>
                    </div>
                  </div>
                  <p className={styles.warn}>Reveals the committed payment-token reference. It is a one-way commitment, not a reusable payment credential.</p>
                  {revealPaymentToken && <textarea readOnly value={serializedPaymentTokenDisclosure} rows={3} />}
                </div>
              )}
              <div className={styles.secret}>
                <div className={styles.exportHead}>
                  <span className={styles.secretTag}>Issuer opening secret {revealSecret ? "" : "(hidden)"}</span>
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>{revealSecret ? "Hide" : "Reveal"}</button>
                    <button type="button" className={styles.ghost} onClick={() => download(`${built.voucher.voucherId}.secret.txt`, serializedSecret)}>Download</button>
                  </div>
                </div>
                <p className={styles.warn}>Holds the balance, retry count, delinquency age, blindings, and reference salts in the clear. Never publish it.</p>
                {revealSecret && <textarea readOnly value={serializedSecret} rows={3} />}
              </div>
            </>
          ) : (
            <p className={styles.placeholder}>Issue a voucher to produce a publicly verifiable recovery proof, a selective balance disclosure, optional subscriber and payment-token disclosures, and a private issuer opening secret.</p>
          )}
        </div>
      </div>
      <div className={styles.grid}>
        <form className={styles.verify} onSubmit={handleVerify}>
          <div className={styles.panelHead}>
            <span>03 · Verify</span>
            <h3>Check a voucher &amp; disclosure</h3>
          </div>
          <label className={styles.toggle}>Recovery voucher
            <textarea value={verifyVoucherInput} onChange={(e) => setVerifyVoucherInput(e.target.value)} placeholder="Paste a serialized recovery voucher…" spellCheck={false} />
          </label>
          <label className={styles.toggle}>Disclosure <small>optional — balance, subscriber, or payment token</small>
            <textarea value={verifyDisclosureInput} onChange={(e) => setVerifyDisclosureInput(e.target.value)} placeholder="Paste a balance, subscriber, or payment-token disclosure to check it…" spellCheck={false} />
          </label>
          <button type="submit">Verify</button>
          {verifyState && (verifyState.error ? (
            <div className={styles.fail}><strong>Cannot decode</strong><small>{verifyState.error}</small></div>
          ) : (
            <div className={verifyState.ok ? styles.pass : styles.fail}>
              <strong>{verifyState.ok ? "Voucher proof valid" : "Voucher proof invalid"}</strong>
              <dl className={styles.resultMeta}>
                <div><dt>retries ≤ max &amp; age &lt; grace</dt><dd>{verifyState.ok ? "ZK proven" : "rejected"}</dd></div>
                <div><dt>Issuer signature</dt><dd>{verifyState.ok ? "authenticated" : "rejected"}</dd></div>
                {verifyState.voucher && <div><dt>Max retries</dt><dd>≤ {verifyState.voucher.maxAttempts}</dd></div>}
                {verifyState.voucher && <div><dt>Grace period</dt><dd>&lt; {verifyState.voucher.gracePeriodDays} days</dd></div>}
                {verifyState.disclosure && (
                  <div>
                    <dt>{disclosureLabel[verifyState.disclosure.type]}</dt>
                    <dd>{verifyState.disclosure.ok ? `opens · ${verifyState.disclosure.value}` : "does not match"}</dd>
                  </div>
                )}
              </dl>
              <small>Verification is arithmetic only: no pool contract call, no on-chain settlement, no payment charged, retried, or settled.</small>
            </div>
          ))}
        </form>
        <div className={styles.model}>
          <div>
            <h4>Hidden from the verifier</h4>
            <ul>{VISIBILITY.hiddenFromVerifier.map((item) => <li key={item}>{item}</li>)}</ul>
          </div>
          <div>
            <h4>Disclosed to the verifier</h4>
            <ul>{VISIBILITY.disclosedToVerifier.map((item) => <li key={item}>{item}</li>)}</ul>
          </div>
          <div>
            <h4>Application layer only</h4>
            <ul>{VISIBILITY.applicationOnly.map((item) => <li key={item}>{item}</li>)}</ul>
          </div>
        </div>
      </div>

      <div className={styles.limitation}>
        <p>{VISIBILITY.limitation}</p>
        <p className={styles.statement}>{TRUST.statement}</p>
      </div>
    </section>
  );
}
