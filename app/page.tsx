"use client";

import { useState } from "react";
import { PrivatePayment } from "@/components/private-payment";
import { InvoicePanel } from "@/components/invoice-panel";
import { WalletConnect } from "@/components/wallet-connect";
import { BatchPayrollDashboard } from "@/components/batch-payroll";
import { InvoiceDashboard } from "@/components/invoice-dashboard";
import { EscrowPortal } from "@/components/escrow-portal";
import { FiatConverter } from "@/components/fiat-converter";
import { ArbitrationVault } from "@/components/arbitration-vault";
import { SubscriptionPortal } from "@/components/subscription-portal";

const tabs = [
  ["invoice", "Single Invoice"],
  ["payroll", "Batch Payroll Dispersal"],
  ["audit", "Auditor Disclosures"],
  ["escrow", "Enterprise Escrow"],
  ["fiat", "Fiat Shielding"],
  ["disputes", "Arbitration Vault"],
  ["subscriptions", "Private Memberships"],
] as const;

type Tab = (typeof tabs)[number][0];

const steps = [
  ["01", "Shield", "Move STRK into a shielded balance through the live privacy pool."],
  ["02", "Settle", "Send a private payment without exposing the payer's balance history."],
  ["03", "Prove", "Share selective transaction evidence for accounting or disputes."],
];

export default function Home() {
  const [tab, setTab] = useState<Tab>("invoice");

  return (
    <main>
      <nav>
        <a className="brand" href="#top"><span>◒</span> CipherBill</a>
        <div className="nav-links"><a href="#workflow">Workflow</a><a href="#demo">Demo</a></div>
        <WalletConnect />
      </nav>

      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="pill"><i /> Built for the STRK20 Private Sprint</div>
          <h1>Private payments.<br/><em>Public confidence.</em></h1>
          <p>Shielded invoicing and settlement for independent workers and global teams—built on Starknet and designed around selective disclosure.</p>
          <div className="hero-actions"><a className="primary" href="#demo">Open prototype →</a><a className="secondary" href="#workflow">See the flow</a></div>
          <div className="proof"><span>STRK20 privacy pool</span><span>Starknet mainnet</span><span>Open source</span></div>
        </div>
        <PrivatePayment />
      </section>

      <section className="workflow" id="workflow">
        <div className="section-heading"><span>How it works</span><h2>Privacy with an auditable edge.</h2></div>
        <div className="steps">
          {steps.map(([number, title, copy]) => <article key={number}><b>{number}</b><h3>{title}</h3><p>{copy}</p></article>)}
        </div>
      </section>

      <section className="dashboard-section" id="demo">
        <div style={{ display: "flex", gap: "16px", justifyContent: "center", marginBottom: "32px", flexWrap: "wrap" }}>
          {tabs.map(([value, label]) => (
            <button key={value} onClick={() => setTab(value)} style={{ background: tab === value ? "#2563eb" : "rgba(255,255,255,0.05)", color: "white", padding: "10px 20px", borderRadius: "8px", border: "none", cursor: "pointer", fontWeight: "bold" }}>
              {label}
            </button>
          ))}
        </div>
        {tab === "invoice" ? <InvoicePanel /> : tab === "payroll" ? <BatchPayrollDashboard /> : tab === "audit" ? <InvoiceDashboard /> : tab === "escrow" ? <EscrowPortal /> : tab === "fiat" ? <FiatConverter /> : tab === "disputes" ? <ArbitrationVault /> : <SubscriptionPortal />}
      </section>

      <section className="privacy-model">
        <div className="section-heading"><span>Selective disclosure</span><h2>Useful privacy, honest edges.</h2></div>
        <div className="privacy-table" role="table" aria-label="CipherBill privacy model">
          <div role="row" className="privacy-row privacy-header"><strong>Hidden inside the pool</strong><strong>Public or observable</strong></div>
          <div role="row" className="privacy-row"><span>In-pool sender, recipient, token and amount</span><span>Shielding deposits and withdrawals, including their public addresses and amounts</span></div>
          <div role="row" className="privacy-row"><span>Which encrypted notes were spent and their linkage</span><span>Timing, fees and published nullifiers, which are unlinkable without a viewing key</span></div>
          <div role="row" className="privacy-row"><span>Ordinary encrypted note values and intentionally undisclosed receipt fields</span><span>Open-note token and amounts, application-side metadata, and correlation risks from distinctive activity</span></div>
        </div>
      </section>

      <footer><a className="brand" href="#top"><span>◒</span> CipherBill</a><p>Open-source infrastructure for private commerce.</p><small>STRK20 Private Sprint · 2026</small></footer>
    </main>
  );
}
