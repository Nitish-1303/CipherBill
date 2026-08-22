"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  burnEphemeralAfterSettlement,
  claimEphemeralInvoice,
  decodeEphemeralCapability,
  destroyEphemeralSession,
  expireEphemeralInvoice,
  failEphemeralSubmission,
  readEphemeralState,
  recordEphemeralSubmission,
  writeEphemeralState,
  type EphemeralInvoiceEnvelope,
  type EphemeralInvoiceSession,
  type EphemeralInvoiceState,
} from "@/lib/ephemeral-engine";
import { encodeInvoicePayload } from "@/lib/invoices";
import { getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";

import { EphemeralBadge } from "./ephemeral-badge";
import { InvoicePayment } from "./invoice-payment";

export function EphemeralPaymentView() {
  const [envelope, setEnvelope] = useState<EphemeralInvoiceEnvelope | null>(null);
  const [state, setState] = useState<EphemeralInvoiceState | null>(null);
  const [encodedInvoice, setEncodedInvoice] = useState("");
  const [message, setMessage] = useState("Redeeming encrypted bearer capability locally...");
  const started = useRef(false);
  const sessionRef = useRef<EphemeralInvoiceSession | null>(null);
  const stateRef = useRef<EphemeralInvoiceState | null>(null);
  const envelopeRef = useRef<EphemeralInvoiceEnvelope | null>(null);

  function persist(next: EphemeralInvoiceState, target = envelopeRef.current) {
    if (!target) return;
    writeEphemeralState(target, next);
    stateRef.current = next;
    setState(next);
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const capability = window.location.hash.slice(1);
    if (!capability) {
      setMessage("The one-time URL fragment is missing. It may already have been consumed or removed from browser history.");
      return;
    }
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    void (async () => {
      try {
        const decoded = decodeEphemeralCapability(capability);
        const targetEnvelope = decoded.envelope;
        envelopeRef.current = targetEnvelope;
        setEnvelope(targetEnvelope);
        const localState = readEphemeralState(targetEnvelope);
        stateRef.current = localState;
        setState(localState);
        const now = new Date();
        if (now.getTime() >= Date.parse(targetEnvelope.expiresAt)) {
          const expired = expireEphemeralInvoice(targetEnvelope, localState, null, now);
          persist(expired.state, targetEnvelope);
          setMessage("The TTL elapsed before redemption. This browser recorded a terminal expiration state.");
          return;
        }
        if (localState.status !== "sealed") {
          setMessage(localState.status === "burned" || localState.status === "expired"
            ? "This capability is already in a terminal state in this browser."
            : "This capability was already claimed in this browser. Reloading cannot recover its cleared URL fragment.");
          return;
        }
        const claimed = await claimEphemeralInvoice(targetEnvelope, decoded.viewingKey, localState, now);
        sessionRef.current = claimed.session;
        persist(claimed.state, targetEnvelope);
        const invoicePayload = await encodeInvoicePayload(claimed.session.invoice!);
        setEncodedInvoice(invoicePayload);
        setMessage("Capability claimed once. The fragment has been removed from browser history; settle before its TTL expires.");
      } catch (error) {
        setMessage(error instanceof Error ? error.message : "Ephemeral capability redemption failed closed.");
      }
    })();
  }, []);

  useEffect(() => {
    const destroyOnExit = () => {
      if (sessionRef.current) destroyEphemeralSession(sessionRef.current);
      sessionRef.current = null;
    };
    window.addEventListener("pagehide", destroyOnExit);
    return () => window.removeEventListener("pagehide", destroyOnExit);
  }, []);

  useEffect(() => {
    if (!envelope || !state || state.status === "burned" || state.status === "expired") return;
    const timer = window.setInterval(() => {
      if (Date.now() < Date.parse(envelope.expiresAt)) return;
      try {
        const current = stateRef.current;
        if (!current || current.status === "burned" || current.status === "expired") return;
        const expired = expireEphemeralInvoice(envelope, current, sessionRef.current, new Date());
        sessionRef.current = null;
        persist(expired.state, envelope);
        setEncodedInvoice("");
        setMessage("TTL elapsed. The in-memory viewing-key buffer was zeroized and this browser marked the capability expired.");
      } catch (error) { setMessage(error instanceof Error ? error.message : "TTL destruction failed closed."); }
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [envelope, state]);

  function onSubmitted(transactionHash: string) {
    const targetEnvelope = envelopeRef.current;
    const currentState = stateRef.current;
    const session = sessionRef.current;
    if (!targetEnvelope || !currentState || !session || currentState.status === "settlement_pending") return;
    const pending = recordEphemeralSubmission(targetEnvelope, session, currentState, transactionHash);
    persist(pending, targetEnvelope);
    setMessage("Settlement submitted. The local state blocks another attempt while Starknet confirmation is pending.");
  }

  function onConfirmed(transactionHash: string) {
    const targetEnvelope = envelopeRef.current;
    let currentState = stateRef.current;
    const session = sessionRef.current;
    if (!targetEnvelope || !currentState || !session) return;
    if (currentState.status === "opened") currentState = recordEphemeralSubmission(targetEnvelope, session, currentState, transactionHash);
    const burned = burnEphemeralAfterSettlement(targetEnvelope, session, currentState, transactionHash);
    sessionRef.current = null;
    persist(burned.state, targetEnvelope);
    setEncodedInvoice("");
    setMessage("Settlement confirmed. The mutable viewing-key buffer was zeroized and the local payment capability is terminal.");
  }

  function onFailed(transactionHash: string) {
    const targetEnvelope = envelopeRef.current;
    const currentState = stateRef.current;
    const session = sessionRef.current;
    if (!targetEnvelope || !currentState || !session || currentState.status !== "settlement_pending") return;
    const reopened = failEphemeralSubmission(targetEnvelope, session, currentState, transactionHash);
    persist(reopened, targetEnvelope);
    setMessage("The submitted settlement reverted. The live in-memory session can retry until TTL expiration.");
  }

  if (envelope && state && encodedInvoice && state.status !== "burned" && state.status !== "expired") {
    return <InvoicePayment
      encodedPayload={encodedInvoice}
      ephemeralBanner={<EphemeralBadge expiresAt={envelope.expiresAt} status={state.status} linkCommitment={envelope.linkCommitment} transactionHash={state.transactionHash} />}
      onPaymentSubmitted={onSubmitted}
      onPaymentConfirmed={onConfirmed}
      onPaymentFailed={onFailed}
    />;
  }

  const terminal = state?.status === "burned" || state?.status === "expired";
  return (
    <main className="pay-page ephemeral-pay-page">
      <nav className="pay-nav"><Link className="brand" href="/"><span aria-hidden="true">CB</span> CipherBill</Link><span className="network-badge">EPHEMERAL · SN_MAIN</span></nav>
      <section className="pay-shell empty-pay-state ephemeral-terminal-state">
        <div className="ephemeral-terminal-mark" aria-hidden="true">{terminal ? "×" : "⌛"}</div>
        <div className="eyebrow">One-time encrypted invoice</div>
        <h1>{terminal ? state?.status === "burned" ? "Settled and burned" : "Capability expired" : envelope ? "Capability unavailable" : "Opening secure link"}</h1>
        <p>{message}</p>
        {envelope && state ? <EphemeralBadge expiresAt={envelope.expiresAt} status={state.status} linkCommitment={envelope.linkCommitment} transactionHash={state.transactionHash} /> : null}
        {state?.transactionHash ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(state.transactionHash)} target="_blank" rel="noreferrer">View settlement transaction ↗</a> : null}
        <aside className="ephemeral-terminal-boundary"><strong>Honest destruction boundary</strong><p>This terminal record prevents reuse in this intact browser registry. It cannot erase a URL copied elsewhere, browser backups, clipboard history, or immutable JavaScript string copies.</p></aside>
        <Link className="secondary" href="/">Return to CipherBill</Link>
      </section>
    </main>
  );
}
