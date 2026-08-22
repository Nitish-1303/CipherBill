"use client";

import { useEffect, useMemo, useState } from "react";

import {
  createEphemeralInvoice,
  createEphemeralPaymentLink,
  getEphemeralSecurityModel,
  serializeEphemeralEnvelope,
  type EphemeralInvoiceBundle,
  type EphemeralStatus,
} from "@/lib/ephemeral-engine";
import type { ShareableInvoice } from "@/lib/invoices";

export function EphemeralBadge({
  expiresAt,
  status,
  linkCommitment,
  transactionHash,
  compact = false,
}: Readonly<{
  expiresAt: string;
  status: EphemeralStatus;
  linkCommitment: string;
  transactionHash?: string;
  compact?: boolean;
}>) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(interval);
  }, []);
  const remaining = Math.max(0, Date.parse(expiresAt) - now);
  const effectiveStatus = status !== "burned" && status !== "expired" && remaining === 0 ? "expired" : status;
  const terminal = effectiveStatus === "burned" || effectiveStatus === "expired";

  return (
    <aside className={`ephemeral-badge ${compact ? "compact" : ""} ${terminal ? "terminal" : effectiveStatus}`} aria-label="Ephemeral invoice status">
      <div className="ephemeral-badge-icon" aria-hidden="true">{terminal ? "×" : "⌛"}</div>
      <div className="ephemeral-badge-copy">
        <span>{terminal ? "Capability destroyed" : "Burn-after-settlement"}</span>
        <strong>{effectiveStatus === "burned" ? "Settled & burned" : effectiveStatus === "expired" ? "TTL expired" : formatCountdown(remaining)}</strong>
        <small>{terminal ? "This browser will not reopen the bearer capability." : "One exact settlement · local single-claim state"}</small>
      </div>
      {!compact ? <div className="ephemeral-badge-proof"><span>Link commitment</span><code>{shorten(linkCommitment, 10, 8)}</code>{transactionHash ? <code>{shorten(transactionHash, 10, 8)}</code> : null}</div> : null}
    </aside>
  );
}

export function EphemeralLinkGenerator({
  invoice,
  onMessage,
}: Readonly<{
  invoice: ShareableInvoice;
  onMessage?: (message: string) => void;
}>) {
  const [generated, setGenerated] = useState<{ bundle: EphemeralInvoiceBundle; link: string } | null>(null);
  const [error, setError] = useState("");
  const security = useMemo(getEphemeralSecurityModel, []);

  useEffect(() => {
    let active = true;
    setGenerated(null);
    setError("");
    createEphemeralInvoice(invoice)
      .then((bundle) => {
        if (!active) return;
        const link = createEphemeralPaymentLink(window.location.origin, bundle);
        setGenerated({ bundle, link });
        onMessage?.(`Ephemeral link ${shorten(bundle.envelope.linkCommitment, 10, 8)} created. Share it once; its fragment is the bearer capability.`);
      })
      .catch((cause) => {
        if (!active) return;
        const message = cause instanceof Error ? cause.message : "Ephemeral link generation failed.";
        setError(message);
        onMessage?.(message);
      });
    return () => { active = false; };
  }, [invoice, onMessage]);

  async function copyLink() {
    if (!generated) return;
    try {
      await navigator.clipboard.writeText(generated.link);
      onMessage?.("One-time payment link copied. Treat it as a bearer secret and send it through one authenticated channel.");
    } catch { onMessage?.("Clipboard access was denied. Select and copy the link manually."); }
  }

  if (error) return <article className="ephemeral-generator error"><strong>Ephemeral link unavailable</strong><p>{error}</p></article>;
  if (!generated) return <article className="ephemeral-generator loading"><span className="ephemeral-pulse" /><strong>Encrypting one-time capability locally...</strong></article>;

  return (
    <article className="ephemeral-generator">
      <div className="ephemeral-generator-heading"><div><span>Ephemeral invoice ready</span><h3>Share once. Settle once. Burn.</h3></div><i>AES-GCM · fragment key</i></div>
      <EphemeralBadge expiresAt={generated.bundle.envelope.expiresAt} status="sealed" linkCommitment={generated.bundle.envelope.linkCommitment} />
      <label>One-time bearer link<textarea readOnly rows={5} value={generated.link} onFocus={(event) => event.currentTarget.select()} /></label>
      <div className="ephemeral-generator-actions"><button type="button" onClick={copyLink}>Copy one-time link</button><a href={generated.link}>Open payment view</a><button type="button" onClick={() => download(`${invoice.invoiceId}.ephemeral-envelope.json`, serializeEphemeralEnvelope(generated.bundle.envelope))}>Export encrypted envelope</button></div>
      <div className="ephemeral-link-anatomy"><div><span>Sent to server</span><strong>Only <code>/pay/ephemeral</code></strong></div><div><span>Browser fragment</span><strong>Encrypted envelope + bearer key</strong></div><div><span>Public chain</span><strong>No invoice metadata</strong></div></div>
      <details className="ephemeral-boundary"><summary>Security boundary — read before sharing</summary><div><strong>Enforced locally</strong><p>{security.enforcedHere.join(" · ")}</p></div><div><strong>Cannot be promised by a static link</strong><p>{security.cannotGuarantee.join(" · ")}</p></div></details>
    </article>
  );
}

function formatCountdown(milliseconds: number): string {
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1_000));
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;
  return days ? `${days}d ${hours}h ${minutes}m` : `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function shorten(value: string, start: number, end: number): string { return value.length <= start + end + 1 ? value : `${value.slice(0, start)}…${value.slice(-end)}`; }

function download(filename: string, value: string) {
  const url = URL.createObjectURL(new Blob([value], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}
