"use client";

import { useEffect, useMemo, useState } from "react";

import { deriveInvoiceStatus } from "@/lib/invoice-lifecycle";
import type { LocalInvoiceRecord } from "@/lib/invoices";
import {
  createReputationProof,
  credentialFromSettlement,
  generateReputationAttestorKeypair,
  getReputationSecurityModel,
  parseReputationAttestation,
  serializeReputationAttestation,
  verifyReputationProof,
  writeReputationAttestation,
  type CurvePointFelts,
  type PrivateSettlementCredential,
  type ReputationAttestation,
} from "@/lib/reputation-engine";
import { areSameStarknetAddress } from "@/lib/strk20/validation";

export interface ReputationBadgeProps {
  context: "merchant" | "public";
  merchantAddress?: string;
  attestation?: ReputationAttestation | null;
  records?: LocalInvoiceRecord[];
  trustedAttestor?: CurvePointFelts;
  onAttestationChange?: (attestation: ReputationAttestation | null) => void | Promise<void>;
}

export function ReputationBadge({
  context,
  merchantAddress,
  attestation = null,
  records = [],
  trustedAttestor,
  onAttestationChange,
}: Readonly<ReputationBadgeProps>) {
  const [open, setOpen] = useState(false);
  const [selectedAddress, setSelectedAddress] = useState(merchantAddress ?? attestation?.merchantAddress ?? "");
  const [importValue, setImportValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const security = useMemo(() => getReputationSecurityModel(), []);
  const candidates = useMemo(() => buildReputationCandidates(records), [records]);
  const merchantAddresses = useMemo(() => {
    const addresses = new Set(candidates.map((candidate) => candidate.address));
    if (attestation?.merchantAddress) addresses.add(attestation.merchantAddress);
    if (merchantAddress) addresses.add(merchantAddress);
    return [...addresses];
  }, [attestation, candidates, merchantAddress]);
  const selectedCredentials = candidates.find((candidate) => areSameAddress(candidate.address, selectedAddress))?.credentials ?? [];
  const verification = attestation
    ? verifyReputationProof(attestation, { trustedAttestor, now: new Date() })
    : null;
  const addressMatches = Boolean(attestation && (!merchantAddress || areSameAddress(attestation.merchantAddress, merchantAddress)));
  const proofAccepted = Boolean(verification?.cryptographicallyValid && verification.current && addressMatches);

  useEffect(() => {
    if (!selectedAddress && merchantAddresses[0]) setSelectedAddress(merchantAddresses[0]);
  }, [merchantAddresses, selectedAddress]);

  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  async function generateLocalProof(): Promise<void> {
    if (!selectedAddress || !selectedCredentials.length || busy) return;
    setBusy(true);
    setMessage("Building Pedersen commitments and Schnorr relation proofs locally...");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    try {
      const authority = generateReputationAttestorKeypair();
      const { attestation: next } = createReputationProof({
        merchantAddress: selectedAddress,
        credentials: selectedCredentials,
        attestorId: "cipherbill.local-demo",
        attestorPrivateKey: authority.privateKey,
        validityDays: 30,
      });
      await onAttestationChange?.(next);
      writeReputationAttestation(next);
      setMessage("Local demonstration proof generated. Its math is valid, but payers should not treat a self-issued attestor as independent trust.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Reputation proof could not be generated.");
    } finally {
      setBusy(false);
    }
  }

  async function importProof(): Promise<void> {
    if (!importValue.trim() || busy) return;
    setBusy(true);
    try {
      const next = parseReputationAttestation(importValue);
      if (merchantAddress && !areSameAddress(next.merchantAddress, merchantAddress)) throw new Error("The imported proof belongs to a different merchant address.");
      await onAttestationChange?.(next);
      writeReputationAttestation(next);
      setSelectedAddress(next.merchantAddress);
      setImportValue("");
      setMessage("Cryptographic proof imported. Issuer trust remains separate and must be established out of band.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Reputation proof could not be imported.");
    } finally {
      setBusy(false);
    }
  }

  async function removeProof(): Promise<void> {
    await onAttestationChange?.(null);
    writeReputationAttestation(null);
    setMessage("Public reputation proof removed from this browser and future invoice links.");
  }

  async function copyProof(): Promise<void> {
    if (!attestation) return;
    try {
      await navigator.clipboard.writeText(serializeReputationAttestation(attestation));
      setMessage("Public attestation copied. No credentials or commitment blindings were included.");
    } catch {
      setMessage("Copy unavailable. Use the JSON download instead.");
    }
  }

  function downloadProof(): void {
    if (!attestation) return;
    const url = URL.createObjectURL(new Blob([serializeReputationAttestation(attestation)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cipherbill-reputation-${attestation.merchantAddress.slice(-8)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage("Public attestation download started.");
  }

  const state = !attestation
    ? "unverified"
    : !addressMatches || !verification?.cryptographicallyValid
      ? "invalid"
      : !verification.current
        ? "expired"
        : verification.attestorTrusted
          ? "trusted"
          : "verified";

  return (
    <>
      <button className={`reputation-badge reputation-${state}`} type="button" onClick={() => setOpen(true)} aria-haspopup="dialog">
        <span className="reputation-seal" aria-hidden="true">{proofAccepted ? "✓" : "?"}</span>
        <span><small>{context === "merchant" ? "Vendor credit" : "Merchant reputation"}</small><strong>{attestation && verification?.cryptographicallyValid ? `${attestation.score} · ${attestation.tier}` : "Not verified"}</strong></span>
        <i>{state === "trusted" ? "trusted issuer" : state === "verified" ? "ZK math verified" : state}</i>
      </button>

      {open ? (
        <div className="reputation-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setOpen(false); }}>
          <section className="reputation-modal" role="dialog" aria-modal="true" aria-labelledby="reputation-heading">
            <header>
              <div><span className="reputation-kicker">Encrypted vendor reputation</span><h2 id="reputation-heading">Credit proof inspector</h2></div>
              <button className="reputation-close" type="button" onClick={() => setOpen(false)} aria-label="Close reputation inspector">×</button>
            </header>

            <div className="reputation-score-card">
              <div className={`reputation-score-orb reputation-${state}`}><strong>{attestation?.score ?? "—"}</strong><span>/ 850</span></div>
              <div>
                <span className="reputation-tier">{attestation?.tier ?? "No attestation"}</span>
                <h3>{state === "trusted" ? "Proof and issuer verified" : state === "verified" ? "Proof verified; issuer not allow-listed" : state === "expired" ? "Proof validity window ended" : state === "invalid" ? "Proof rejected" : "No public credit proof"}</h3>
                <p>{verification?.reason ?? "A merchant can attach a signed zero-knowledge score proof without exposing the invoices behind it."}</p>
              </div>
            </div>

            {attestation ? (
              <>
                <div className="reputation-meter" aria-label={`Credit score ${attestation.score} out of 850`}><span style={{ width: `${Math.max(0, Math.min(100, (attestation.score - 300) / 5.5))}%` }} /></div>
                <dl className="reputation-facts">
                  <div><dt>Merchant</dt><dd><code>{shortFelt(attestation.merchantAddress)}</code>{addressMatches ? <b>address bound</b> : <b className="reputation-danger">mismatch</b>}</dd></div>
                  <div><dt>Proof system</dt><dd>Pedersen + Schnorr linear relations <b>{verification?.cryptographicallyValid ? "verified" : "failed"}</b></dd></div>
                  <div><dt>Aggregate relations</dt><dd>Score + 2 private partitions <b>{verification?.cryptographicallyValid ? "verified" : "failed"}</b></dd></div>
                  <div><dt>Attestor</dt><dd>{attestation.attestorId} <b>{verification?.attestorTrusted ? "allow-listed" : "not allow-listed"}</b></dd></div>
                  <div><dt>Validity</dt><dd>{new Date(attestation.issuedAt).toLocaleDateString()} – {new Date(attestation.validUntil).toLocaleDateString()} <b>{verification?.current ? "current" : "expired"}</b></dd></div>
                  <div><dt>History root</dt><dd><code>{shortFelt(attestation.historyRoot)}</code> <b>opaque</b></dd></div>
                </dl>
                <div className="reputation-actions"><button type="button" onClick={copyProof}>Copy public proof</button><button type="button" onClick={downloadProof}>Download JSON</button>{context === "merchant" ? <button className="reputation-danger-button" type="button" onClick={removeProof}>Remove</button> : null}</div>
              </>
            ) : null}

            <div className="reputation-boundary">
              <div><span>Publicly proven</span><p>Displayed score, score formula consistency, aggregate partitions, merchant binding, issuer signature, and validity window.</p></div>
              <div><span>Never attached</span><p>{security.hidden.join(", ")}.</p></div>
              <div><span>Trust boundary</span><p>The issuer—not the ZK equations—certifies credential provenance and bounded counts. This badge is separate from STRK20 transaction STARK proofs.</p></div>
            </div>

            {context === "merchant" ? (
              <section className="reputation-builder" aria-labelledby="reputation-builder-heading">
                <div><span className="reputation-kicker">Merchant controls</span><h3 id="reputation-builder-heading">Issue or import an attestation</h3></div>
                <p>Only locally recorded invoices marked paid or disputed are eligible. One opaque credential is derived per invoice; amounts and counterparties never enter the credential schema.</p>
                <label>Merchant address
                  <select value={selectedAddress} onChange={(event) => setSelectedAddress(event.target.value)}>
                    {!merchantAddresses.length ? <option value="">No eligible merchant history</option> : merchantAddresses.map((address) => <option value={address} key={address}>{shortFelt(address)}</option>)}
                  </select>
                </label>
                <div className="reputation-builder-summary"><div><strong>{selectedCredentials.length}</strong><span>private credentials</span></div><div><strong>{selectedCredentials.filter((item) => item.outcome === "settled").length}</strong><span>settled</span></div><div><strong>{selectedCredentials.filter((item) => item.outcome === "disputed").length}</strong><span>disputed</span></div></div>
                <button type="button" onClick={generateLocalProof} disabled={busy || !selectedCredentials.some((item) => item.outcome === "settled")}>{busy ? "Proving locally..." : "Generate self-issued demo proof"}</button>
                <details>
                  <summary>Import an independently signed attestation</summary>
                  <textarea rows={7} value={importValue} onChange={(event) => setImportValue(event.target.value)} placeholder="Paste public reputation attestation JSON" aria-label="Public reputation attestation JSON" />
                  <button type="button" onClick={importProof} disabled={busy || !importValue.trim()}>Verify and import</button>
                </details>
              </section>
            ) : null}
            <p className="reputation-message" role="status" aria-live="polite">{message || "No transaction amount, counterparty, invoice identifier, or settlement timestamp is disclosed by the public proof."}</p>
          </section>
        </div>
      ) : null}
    </>
  );
}

interface ReputationCandidate {
  address: string;
  credentials: PrivateSettlementCredential[];
}

function buildReputationCandidates(records: LocalInvoiceRecord[]): ReputationCandidate[] {
  const groups = new Map<string, { address: string; credentials: PrivateSettlementCredential[] }>();
  const ordered = [...records].sort((left, right) => Date.parse(right.lifecycle.updatedAt) - Date.parse(left.lifecycle.updatedAt));
  for (const record of ordered) {
    const status = deriveInvoiceStatus(record.invoice, record.lifecycle);
    if (status !== "paid" && status !== "disputed") continue;
    const confirmed = [...record.lifecycle.payments]
      .filter((payment) => payment.status === "confirmed" && payment.confirmedAt)
      .sort((left, right) => Date.parse(right.confirmedAt ?? right.submittedAt) - Date.parse(left.confirmedAt ?? left.submittedAt))[0];
    if (!confirmed?.confirmedAt) continue;
    const address = record.invoice.recipientAddress;
    const key = BigInt(address).toString(16);
    const group = groups.get(key) ?? { address, credentials: [] };
    if (group.credentials.length >= 32) continue;
    group.credentials.push(credentialFromSettlement({
      credentialId: `rep_${record.invoice.invoiceId}`.slice(0, 64),
      invoiceId: record.invoice.invoiceId,
      transactionHash: confirmed.hash,
      dueAt: record.invoice.expiresAt,
      settledAt: status === "paid" ? confirmed.confirmedAt : undefined,
      outcome: status === "paid" ? "settled" : "disputed",
    }));
    groups.set(key, group);
  }
  return [...groups.values()];
}

function areSameAddress(left: string, right: string): boolean {
  try { return areSameStarknetAddress(left, right); } catch { return false; }
}

function shortFelt(value: string): string {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}
