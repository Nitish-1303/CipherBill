"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  RESERVES_POOL_ADDRESS,
  buildReservesAttestation,
  buildReservesBadge,
  formatReservesBaseUnits,
  getReservesVisibilityModel,
  parseReservesAttestation,
  serializeReservesAttestation,
  serializeReservesSecret,
  summarizeReservesTrust,
  verifyReservesAttestation,
  type BuiltReservesAttestation,
  type ReservesAttestation,
  type ReservesLiability,
} from "@/lib/reserves-engine";
import { STRK_TOKEN_ADDRESS } from "@/lib/strk20/config";
import { decimalToBaseUnits } from "@/lib/strk20/validation";

import styles from "./reserves-attestation-portal.module.css";

const INTRO =
  "Commit a reserve total in this browser and generate a zero-knowledge range proof that it clears a public threshold — without revealing the figure. Counterparties and auditors verify the badge offline. The reserve is a number you assert here; the proof binds it, but does not read the pool contract or prove on-chain custody.";

const TRUST = summarizeReservesTrust();
const VISIBILITY = getReservesVisibilityModel();
const BIT_LENGTHS = [64, 96, 128] as const;

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

interface LiabilityRow {
  label: string;
  amount: string;
}

interface VerifyState {
  ok: boolean;
  attestation?: ReservesAttestation;
  error?: string;
}

export function ReservesAttestationPortal() {
  const [merchantAlias, setMerchantAlias] = useState("Northwind Labs");
  const [assetSymbol, setAssetSymbol] = useState("STRK");
  const [assetDecimals, setAssetDecimals] = useState(18);
  const [tokenAddress, setTokenAddress] = useState(STRK_TOKEN_ADDRESS);
  const [reserveAmount, setReserveAmount] = useState("1250000");
  const [thresholdAmount, setThresholdAmount] = useState("1000000");
  const [bitLength, setBitLength] = useState<number>(128);
  const [memo, setMemo] = useState("");
  const [liabilities, setLiabilities] = useState<LiabilityRow[]>([]);
  const [useLiabilities, setUseLiabilities] = useState(false);

  const [built, setBuilt] = useState<BuiltReservesAttestation | null>(null);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revealSecret, setRevealSecret] = useState(false);

  const [verifyInput, setVerifyInput] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState | null>(null);

  const serializedAttestation = useMemo(
    () => (built ? serializeReservesAttestation(built.attestation) : ""),
    [built],
  );
  const serializedSecret = useMemo(() => (built ? serializeReservesSecret(built.secret) : ""), [built]);
  const badge = useMemo(() => (built ? buildReservesBadge(built.attestation) : null), [built]);

  function addLiability() {
    setLiabilities((rows) => [...rows, { label: "", amount: "" }]);
  }

  function updateLiability(index: number, patch: Partial<LiabilityRow>) {
    setLiabilities((rows) => rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }

  function removeLiability(index: number) {
    setLiabilities((rows) => rows.filter((_, i) => i !== index));
  }

  function handleGenerate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setBuildError(null);
    setRevealSecret(false);
    try {
      const reserveBaseUnits = decimalToBaseUnits(reserveAmount.trim(), assetDecimals);
      const thresholdBaseUnits = decimalToBaseUnits(thresholdAmount.trim(), assetDecimals);
      let liabilityInput: ReservesLiability[] | undefined;
      if (useLiabilities && liabilities.length > 0) {
        liabilityInput = liabilities.map((row) => ({
          label: row.label.trim(),
          amountBaseUnits: decimalToBaseUnits(row.amount.trim(), assetDecimals),
        }));
      }
      const result = buildReservesAttestation({
        merchantAlias: merchantAlias.trim(),
        asset: { symbol: assetSymbol.trim(), tokenAddress: tokenAddress.trim(), decimals: assetDecimals },
        reserveBaseUnits,
        thresholdBaseUnits,
        bitLength,
        memo: memo.trim() || undefined,
        liabilities: liabilityInput,
      });
      setBuilt(result);
    } catch (error) {
      setBuilt(null);
      setBuildError(error instanceof Error ? error.message : "Could not generate the attestation.");
    } finally {
      setBusy(false);
    }
  }

  function handleVerify(event: FormEvent) {
    event.preventDefault();
    try {
      const attestation = parseReservesAttestation(verifyInput.trim());
      setVerifyState({ ok: verifyReservesAttestation(attestation), attestation });
    } catch (error) {
      setVerifyState({ ok: false, error: error instanceof Error ? error.message : "Could not decode the attestation." });
    }
  }

  return (
    <section className={styles.portal}>
      <header className={styles.header}>
        <div className={styles.headline}>
          <span>Proof of Reserves</span>
          <h2>Institutional <em>solvency attestation</em></h2>
          <p>{INTRO}</p>
          <code className={styles.provenance}>Pool provenance · {shorten(RESERVES_POOL_ADDRESS)}</code>
        </div>
        <dl className={styles.trust}>
          <div><dt>Zero-knowledge</dt><dd className={styles.yes}>Range proof</dd></div>
          <div><dt>On-chain custody</dt><dd className={styles.no}>Not proven</dd></div>
          <div><dt>Decentralized</dt><dd className={styles.no}>No</dd></div>
          <div><dt>Pool contract</dt><dd className={styles.no}>Never called</dd></div>
        </dl>
      </header>

      <div className={styles.grid}>
        <form className={styles.panel} onSubmit={handleGenerate}>
          <div className={styles.panelHead}><span>01 · Generate</span><h3>Reserve commitment</h3></div>
          <div className={styles.fields}>
            <label className={styles.wide}>Merchant alias
              <input value={merchantAlias} onChange={(e) => setMerchantAlias(e.target.value)} maxLength={80} required />
            </label>
            <label>Asset
              <input value={assetSymbol} onChange={(e) => setAssetSymbol(e.target.value)} maxLength={16} required />
            </label>
            <label>Decimals
              <input type="number" min={0} max={18} value={assetDecimals} onChange={(e) => setAssetDecimals(Number(e.target.value))} required />
            </label>
            <label className={styles.wide}>Token address (provenance)
              <input value={tokenAddress} onChange={(e) => setTokenAddress(e.target.value)} spellCheck={false} required />
            </label>
            <label>Reserve total <small>(private)</small>
              <input value={reserveAmount} onChange={(e) => setReserveAmount(e.target.value)} inputMode="decimal" required />
            </label>
            <label>Threshold <small>(public)</small>
              <input value={thresholdAmount} onChange={(e) => setThresholdAmount(e.target.value)} inputMode="decimal" required />
            </label>
            <label>Proof range
              <select value={bitLength} onChange={(e) => setBitLength(Number(e.target.value))}>
                {BIT_LENGTHS.map((n) => <option key={n} value={n}>{n}-bit band</option>)}
              </select>
            </label>
            <label className={styles.wide}>Memo <small>(optional)</small>
              <input value={memo} onChange={(e) => setMemo(e.target.value)} maxLength={200} />
            </label>
          </div>

          <label className={styles.toggle}>
            <input type="checkbox" checked={useLiabilities} onChange={(e) => setUseLiabilities(e.target.checked)} />
            Attach a liability breakdown (line items must sum to the threshold)
          </label>
          {useLiabilities && (
            <div className={styles.liabilities}>
              {liabilities.map((row, index) => (
                <div key={index} className={styles.liabilityRow}>
                  <input placeholder="Line item" value={row.label} onChange={(e) => updateLiability(index, { label: e.target.value })} maxLength={60} />
                  <input placeholder="Amount" value={row.amount} onChange={(e) => updateLiability(index, { amount: e.target.value })} inputMode="decimal" />
                  <button type="button" className={styles.ghost} onClick={() => removeLiability(index)}>Remove</button>
                </div>
              ))}
              <button type="button" className={styles.ghost} onClick={addLiability}>+ Add line item</button>
            </div>
          )}

          <button type="submit" disabled={busy}>{busy ? "Proving…" : "Generate attestation"}</button>
          {buildError && <p className={styles.error}>{buildError}</p>}
        </form>

        {built && badge ? (
          <div className={styles.panel}>
            <div className={styles.panelHead}><span>02 · Attestation</span><h3>Solvency badge</h3></div>
            <div className={styles.badge}>
              <div className={styles.badgeTop}>
                <div>
                  <strong>{badge.merchantAlias}</strong>
                  <small>{formatDate(badge.createdAt)} · {badge.network}</small>
                </div>
                <span className={styles.verified}>ZK verified</span>
              </div>
              <div className={styles.badgeClaim}>
                Reserves ≥ <b>{badge.thresholdDisplay}</b> {built.attestation.assetSymbol}
                <small>proven band: {badge.thresholdDisplay} – {badge.bandExclusiveMaxDisplay} (exclusive)</small>
              </div>
              <dl className={styles.badgeMeta}>
                <div><dt>Attestation</dt><dd>{built.attestation.attestationId}</dd></div>
                <div><dt>Proof system</dt><dd>{built.attestation.proof.proofSystem}</dd></div>
                <div><dt>Bit range</dt><dd>{built.attestation.proof.bitLength}-bit · {built.attestation.proof.bitProofs.length} proofs</dd></div>
                <div><dt>Commitment</dt><dd>{shorten(built.attestation.statementCommitment)}</dd></div>
              </dl>
              {built.attestation.liabilities.length > 0 && (
                <ul className={styles.liabilityList}>
                  {built.attestation.liabilities.map((item, index) => (
                    <li key={index}><span>{item.label}</span><span>{formatReservesBaseUnits(item.amountBaseUnits, built.attestation.assetDecimals)}</span></li>
                  ))}
                </ul>
              )}
            </div>

            <div className={styles.export}>
              <div className={styles.exportHead}><span>Share with counterparties</span>
                <button type="button" className={styles.ghost} onClick={() => download(`${built.attestation.attestationId}.attestation.txt`, serializedAttestation)}>Download</button>
              </div>
              <textarea readOnly value={serializedAttestation} spellCheck={false} />
              <small className={styles.hint}>This publishes only the range proof and the public band — the reserve figure stays hidden.</small>
            </div>

            <div className={styles.secret}>
              <div className={styles.exportHead}><span className={styles.secretTag}>Secret opening</span>
                <button type="button" className={styles.ghost} onClick={() => setRevealSecret((v) => !v)}>{revealSecret ? "Hide" : "Reveal"}</button>
              </div>
              {revealSecret ? (
                <>
                  <textarea readOnly value={serializedSecret} spellCheck={false} />
                  <div className={styles.secretActions}>
                    <button type="button" className={styles.ghost} onClick={() => download(`${built.attestation.attestationId}.opening.SECRET.txt`, serializedSecret)}>Download opening</button>
                  </div>
                  <small className={styles.warn}>Reveals the exact reserve and blinding. Only share with an auditor entitled to the precise figure.</small>
                </>
              ) : (
                <small className={styles.hint}>The opening lets a chosen auditor confirm the exact reserve against this commitment. Keep it private.</small>
              )}
            </div>
          </div>
        ) : (
          <div className={styles.panel}>
            <div className={styles.panelHead}><span>02 · Attestation</span><h3>Solvency badge</h3></div>
            <p className={styles.placeholder}>Generate an attestation to produce a shareable badge, a portable proof, and an optional full-disclosure opening.</p>
          </div>
        )}
      </div>

      <form className={styles.verify} onSubmit={handleVerify}>
        <div className={styles.panelHead}><span>03 · Verify</span><h3>Check a counterparty badge</h3></div>
        <textarea placeholder="Paste a serialized attestation…" value={verifyInput} onChange={(e) => setVerifyInput(e.target.value)} spellCheck={false} />
        <div className={styles.verifyActions}>
          <button type="submit" disabled={!verifyInput.trim()}>Verify attestation</button>
        </div>
        {verifyState && (
          verifyState.error ? (
            <p className={styles.error}>{verifyState.error}</p>
          ) : (
            <div className={verifyState.ok ? styles.pass : styles.fail}>
              <strong>{verifyState.ok ? "✓ Proof verified" : "✕ Proof invalid"}</strong>
              {verifyState.attestation && (
                <dl className={styles.verifyMeta}>
                  <div><dt>Merchant</dt><dd>{verifyState.attestation.merchantAlias}</dd></div>
                  <div><dt>Reserves ≥</dt><dd>{formatReservesBaseUnits(verifyState.attestation.thresholdBaseUnits, verifyState.attestation.assetDecimals)} {verifyState.attestation.assetSymbol}</dd></div>
                  <div><dt>Band max</dt><dd>{formatReservesBaseUnits(verifyState.attestation.bandExclusiveMaxBaseUnits, verifyState.attestation.assetDecimals)}</dd></div>
                  <div><dt>Commitment</dt><dd>{shorten(verifyState.attestation.statementCommitment)}</dd></div>
                </dl>
              )}
              <small>{verifyState.ok ? "The committed reserve provably clears the threshold. This does not confirm on-chain custody." : "The proof did not validate against its published statement."}</small>
            </div>
          )
        )}
      </form>

      <footer className={styles.model}>
        <div><h4>Hidden from the verifier</h4><ul>{VISIBILITY.hiddenFromVerifier.map((line) => <li key={line}>{line}</li>)}</ul></div>
        <div><h4>Disclosed to the verifier</h4><ul>{VISIBILITY.disclosedToVerifier.map((line) => <li key={line}>{line}</li>)}</ul></div>
        <div className={styles.limitation}><h4>What this does not prove</h4><p>{VISIBILITY.limitation}</p><p className={styles.statement}>{TRUST.statement}</p></div>
      </footer>
    </section>
  );
}

