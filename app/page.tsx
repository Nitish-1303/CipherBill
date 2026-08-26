"use client";

import { useMemo, useState } from "react";

import { PrivatePayment } from "@/components/private-payment";
import { InvoicePanel } from "@/components/invoice-panel";
import { WalletConnect } from "@/components/wallet-connect";
import { BatchPayrollDashboard } from "@/components/batch-payroll";
import { InvoiceDashboard } from "@/components/invoice-dashboard";
import { EscrowPortal } from "@/components/escrow-portal";
import { FiatConverter } from "@/components/fiat-converter";
import { ArbitrationVault } from "@/components/arbitration-vault";
import { InsurancePortal } from "@/components/insurance-portal";
import { ExpenseSplitterModal } from "@/components/expense-splitter-modal";
import { SubscriptionPortal } from "@/components/subscription-portal";
import { CrossChainRouteModal } from "@/components/cross-chain-modal";
import { FactoringMarketplace } from "@/components/factoring-marketplace";
import { DisputePortal } from "@/components/dispute-portal";
import { CashflowPortal } from "@/components/cashflow-portal";

import styles from "./home.module.css";

const moduleGroups = [
  {
    id: "invoicing",
    label: "Invoicing",
    modules: [
      ["invoice", "Single Invoice"],
      ["payroll", "Batch Payroll Dispersal"],
      ["audit", "Auditor Disclosures"],
    ],
  },
  {
    id: "treasury",
    label: "Treasury & liquidity",
    modules: [
      ["cashflow", "Cash Flow Forecast"],
      ["factoring", "Invoice Factoring"],
      ["fiat", "Fiat Shielding"],
      ["crosschain", "Settlement Routes"],
    ],
  },
  {
    id: "risk",
    label: "Risk & trust",
    modules: [
      ["escrow", "Enterprise Escrow"],
      ["disputes", "Arbitration Vault"],
      ["resolution", "Dispute Resolution"],
      ["insurance", "Invoice Insurance"],
    ],
  },
  {
    id: "operations",
    label: "Operations",
    modules: [
      ["expenses", "Expense Splitter"],
      ["subscriptions", "Private Memberships"],
    ],
  },
] as const;

type Tab = (typeof moduleGroups)[number]["modules"][number][0];

const steps = [
  ["01", "Shield", "Move STRK into a shielded balance through the live privacy pool."],
  ["02", "Settle", "Send a private payment without exposing the payer's balance history."],
  ["03", "Prove", "Share selective transaction evidence for accounting or disputes."],
] as const;

const hiddenItems = [
  "In-pool sender, recipient, token, and amount",
  "Which encrypted notes were spent and their linkage",
  "Ordinary encrypted note values and undisclosed receipt fields",
];

const publicItems = [
  "Shielding deposits and withdrawals, including public addresses and amounts",
  "Timing, fees, and published nullifiers (unlinkable without a viewing key)",
  "Open-note amounts, app metadata, and correlation risks from distinctive activity",
];

function renderModule(tab: Tab) {
  switch (tab) {
    case "invoice":
      return <InvoicePanel />;
    case "payroll":
      return <BatchPayrollDashboard />;
    case "audit":
      return <InvoiceDashboard />;
    case "escrow":
      return <EscrowPortal />;
    case "fiat":
      return <FiatConverter />;
    case "disputes":
      return <ArbitrationVault />;
    case "insurance":
      return <InsurancePortal />;
    case "expenses":
      return <ExpenseSplitterModal />;
    case "subscriptions":
      return <SubscriptionPortal />;
    case "crosschain":
      return <CrossChainRouteModal />;
    case "factoring":
      return <FactoringMarketplace />;
    case "resolution":
      return <DisputePortal />;
    case "cashflow":
      return <CashflowPortal />;
    default:
      return <InvoicePanel />;
  }
}

export default function Home() {
  const [tab, setTab] = useState<Tab>("invoice");
  const [query, setQuery] = useState("");

  const activeLabel = useMemo(() => {
    for (const group of moduleGroups) {
      const match = group.modules.find(([value]) => value === tab);
      if (match) return match[1];
    }
    return "Single Invoice";
  }, [tab]);

  const filteredGroups = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return moduleGroups;
    return moduleGroups
      .map((group) => ({
        ...group,
        modules: group.modules.filter(([, label]) => label.toLowerCase().includes(needle)),
      }))
      .filter((group) => group.modules.length > 0);
  }, [query]);

  return (
    <div className={styles.shell}>
      <div className={styles.mesh} aria-hidden="true" />

      <header className={styles.topBar}>
        <div className={styles.topBarInner}>
          <a className={styles.brand} href="#top">
            <span className={styles.brandMark} aria-hidden="true">
              ◒
            </span>
            CipherBill
          </a>
          <nav className={styles.navLinks} aria-label="Primary">
            <a href="#workflow">Workflow</a>
            <a href="#demo">Merchant console</a>
            <a href="#privacy">Privacy model</a>
          </nav>
          <WalletConnect />
        </div>
      </header>

      <section className={styles.hero} id="top">
        <div className={styles.heroCopy}>
          <div className={styles.kicker}>
            <span className={styles.kickerDot} aria-hidden="true" />
            Built for the STRK20 Private Sprint
          </div>
          <h1 className={styles.heroTitle}>
            Private payments.
            <br />
            <em>Public confidence.</em>
          </h1>
          <p className={styles.heroLead}>
            Shielded invoicing and settlement for independent workers and global teams—built on Starknet and designed
            around selective disclosure.
          </p>
          <div className={styles.heroActions}>
            <a className={styles.ctaPrimary} href="#demo">
              Open merchant console →
            </a>
            <a className={styles.ctaSecondary} href="#workflow">
              See the flow
            </a>
          </div>
          <dl className={styles.metricStrip}>
            <div>
              <dt>Merchant modules</dt>
              <dd>13 live prototypes</dd>
            </div>
            <div>
              <dt>Network</dt>
              <dd>Starknet mainnet</dd>
            </div>
            <div>
              <dt>Privacy pool</dt>
              <dd>STRK20 · SN_MAIN</dd>
            </div>
          </dl>
        </div>
        <div className={styles.heroPanel}>
          <PrivatePayment />
        </div>
      </section>

      <section className={styles.workflow} id="workflow">
        <div className={styles.workflowInner}>
          <span className={styles.sectionEyebrow}>How it works</span>
          <h2 className={styles.sectionTitle}>Privacy with an auditable edge.</h2>
          <div className={styles.timeline}>
            {steps.map(([number, title, copy]) => (
              <article key={number} className={styles.timelineCard}>
                <span className={styles.stepIndex}>{number}</span>
                <h3>{title}</h3>
                <p>{copy}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.console} id="demo">
        <div className={styles.consoleInner}>
          <div className={styles.consoleHead}>
            <span className={styles.sectionEyebrow}>Merchant console</span>
            <h2 className={styles.sectionTitle}>One surface for every private commerce workflow.</h2>
            <p>
              Browse institutional modules for invoicing, treasury, risk, and operations. Each portal keeps the same
              honest privacy boundaries—nothing executes on-chain unless your wallet signs it.
            </p>
          </div>

          <div className={styles.consoleFrame}>
            <aside className={styles.consoleSidebar} aria-label="Module navigation">
              <input
                className={styles.consoleSearch}
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter modules…"
                aria-label="Filter merchant modules"
              />
              {filteredGroups.map((group) => (
                <div key={group.id} className={styles.moduleGroup}>
                  <div className={styles.groupLabel}>{group.label}</div>
                  {group.modules.map(([value, label]) => (
                    <button
                      key={value}
                      type="button"
                      className={`${styles.moduleButton} ${tab === value ? styles.moduleButtonActive : ""}`}
                      onClick={() => setTab(value)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              ))}
            </aside>
            <div className={styles.consoleMain}>
              <div className={styles.consoleMainHead}>
                <strong>{activeLabel}</strong>
                <span>Client-side · wallet-signed · STRK20 mainnet</span>
              </div>
              {renderModule(tab)}
            </div>
          </div>
        </div>
      </section>

      <section className={styles.privacy} id="privacy">
        <div className={styles.privacyInner}>
          <span className={styles.sectionEyebrow}>Selective disclosure</span>
          <h2 className={styles.sectionTitle}>Useful privacy, honest edges.</h2>
          <div className={styles.privacyGrid}>
            <article className={`${styles.privacyCard} ${styles.privacyCardHidden}`}>
              <h3>Hidden inside the pool</h3>
              <ul>
                {hiddenItems.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
            <article className={`${styles.privacyCard} ${styles.privacyCardPublic}`}>
              <h3>Public or observable</h3>
              <ul>
                {publicItems.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
          </div>
        </div>
      </section>

      <footer className={styles.siteFooter}>
        <div className={styles.footerInner}>
          <div className={styles.footerBrand}>
            <a className={styles.brand} href="#top">
              <span className={styles.brandMark} aria-hidden="true">
                ◒
              </span>
              CipherBill
            </a>
            <p>Open-source infrastructure for private commerce on Starknet—selective disclosure by design, not by accident.</p>
          </div>
          <div className={styles.footerCol}>
            <h4>Product</h4>
            <ul>
              <li>
                <a href="#demo">Merchant console</a>
              </li>
              <li>
                <a href="#workflow">Workflow</a>
              </li>
              <li>
                <a href="#privacy">Privacy model</a>
              </li>
            </ul>
          </div>
          <div className={styles.footerCol}>
            <h4>Network</h4>
            <ul>
              <li>STRK20 privacy pool</li>
              <li>Starknet mainnet (SN_MAIN)</li>
              <li>Open source · 2026</li>
            </ul>
          </div>
        </div>
        <div className={styles.footerBottom}>
          <span>STRK20 Private Sprint · CipherBill</span>
          <span>Shielded by default · auditable when required</span>
        </div>
      </footer>
    </div>
  );
}
