"use client";

import { Suspense, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { motion, useReducedMotion } from "framer-motion";

import { CipherBillLogo, CipherBillWordmark } from "@/components/brand/cipherbill-logo";
import { IconArrowDown, IconBoundary, IconPool, IconProve, IconSettle, IconShield } from "@/components/brand/cipherbill-icons";
import { FlowDiagram } from "@/components/narrative/flow-diagram";
import { HeroSceneFallback } from "@/components/narrative/hero-scene-fallback";
import { MotionField } from "@/components/narrative/motion-field";
import { NarrativeRail } from "@/components/narrative/narrative-rail";
import { SceneErrorBoundary } from "@/components/narrative/scene-error-boundary";
import { StoryChapter } from "@/components/narrative/story-chapter";
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
import { FxHedgingPortal } from "@/components/fx-hedging-portal";
import { PayrollPortal } from "@/components/payroll-portal";
import { VatCompliancePortal } from "@/components/vat-compliance-portal";
import { DunningPortal } from "@/components/dunning-portal";
import { TreasurySweepPortal } from "@/components/treasury-sweep-portal";
import { FactoringPortal } from "@/components/factoring-portal";
import { RevenueRoutingPortal } from "@/components/revenue-routing-portal";

import styles from "./home.module.css";

const HeroScene = dynamic(
  () =>
    import("@/components/narrative/hero-scene")
      .then((mod) => mod.HeroScene)
      .catch(() => HeroSceneFallback),
  {
    ssr: false,
    loading: () => <div className={styles.sceneSkeleton} aria-hidden="true" />,
  },
);

const moduleGroups = [
  {
    id: "invoicing",
    label: "Invoicing",
    modules: [
      ["invoice", "Single Invoice"],
      ["payroll", "Batch Payroll Dispersal"],
      ["zkpayroll", "ZK Payroll Protocol"],
      ["audit", "Auditor Disclosures"],
      ["vatcompliance", "VAT Compliance"],
    ],
  },
  {
    id: "treasury",
    label: "Treasury & liquidity",
    modules: [
      ["cashflow", "Cash Flow Forecast"],
      ["treasurysweep", "Treasury Sweep"],
      ["revenuerouting", "Revenue Routing"],
      ["fxhedging", "FX Hedging"],
      ["factoring", "Invoice Factoring"],
      ["factoringvault", "Factoring Vault"],
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
      ["dunning", "Dunning & Recovery"],
    ],
  },
] as const;

type Tab = (typeof moduleGroups)[number]["modules"][number][0];

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
    case "zkpayroll":
      return <PayrollPortal />;
    case "audit":
      return <InvoiceDashboard />;
    case "vatcompliance":
      return <VatCompliancePortal />;
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
    case "dunning":
      return <DunningPortal />;
    case "crosschain":
      return <CrossChainRouteModal />;
    case "factoring":
      return <FactoringMarketplace />;
    case "factoringvault":
      return <FactoringPortal />;
    case "resolution":
      return <DisputePortal />;
    case "cashflow":
      return <CashflowPortal />;
    case "treasurysweep":
      return <TreasurySweepPortal />;
    case "revenuerouting":
      return <RevenueRoutingPortal />;
    case "fxhedging":
      return <FxHedgingPortal />;
    default:
      return <InvoicePanel />;
  }
}

export default function Home() {
  const [tab, setTab] = useState<Tab>("invoice");
  const [query, setQuery] = useState("");
  const reduce = useReducedMotion();

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
      <MotionField />
      <NarrativeRail />

      <header className={styles.topBar}>
        <div className={styles.topBarInner}>
          <a className={styles.brand} href="#top" aria-label="CipherBill">
            <CipherBillLogo className={styles.brandLogo} size={34} />
            <CipherBillWordmark className={styles.wordmark} />
          </a>
          <nav className={styles.navLinks} aria-label="Primary">
            <a href="#story">Story</a>
            <a href="#demo">Console</a>
            <a href="#privacy">Boundaries</a>
          </nav>
          <WalletConnect />
        </div>
      </header>

      <section className={styles.hero} id="top">
        <motion.div
          className={styles.heroCopy}
          initial={reduce ? false : { opacity: 0, y: 28 }}
          animate={reduce ? undefined : { opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className={styles.kicker}>
            <span className={styles.kickerDot} aria-hidden="true" />
            STRK20 Private Sprint · Starknet mainnet
          </div>
          <h1 className={styles.heroTitle}>
            Private payments.
            <br />
            <em>Public confidence.</em>
          </h1>
          <p className={styles.heroLead}>
            CipherBill is a scroll-through story of shielded commerce: what stays hidden in the STRK20 pool, what remains
            observable, and how merchants run real workflows without leaking their financial graph.
          </p>
          <div className={styles.heroActions}>
            <a className={styles.ctaPrimary} href="#story">
              Start the narrative
            </a>
            <a className={styles.ctaSecondary} href="#demo">
              Jump to live console
            </a>
          </div>
          <a className={styles.scrollCue} href="#story">
            <IconArrowDown size={18} />
            Scroll to prologue
          </a>
        </motion.div>

        <div className={styles.heroStage}>
          <SceneErrorBoundary fallback={<HeroSceneFallback />}>
            <Suspense fallback={<div className={styles.sceneSkeleton} aria-hidden="true" />}>
              <HeroScene />
            </Suspense>
          </SceneErrorBoundary>
          <div className={styles.heroPanel}>
            <PrivatePayment />
          </div>
        </div>
      </section>

      <section className={styles.story} id="story">
        <div className={styles.storyInner}>
          <header className={styles.storyIntro}>
            <span className={styles.sectionEyebrow}>Prologue</span>
            <h2 className={styles.sectionTitle}>Every public payment draws a map of your business.</h2>
            <p>
              On a transparent chain, repeated invoices, payroll, and treasury moves become a readable graph. CipherBill
              keeps day-to-day settlement inside STRK20 while preserving audit paths you control.
            </p>
          </header>

          <FlowDiagram />

          <StoryChapter
            id="shield"
            index="Chapter 01"
            title="Shield — enter the pool with wallet-signed deposits"
            thesis="Public STRK moves into a shielded balance. The deposit edge is observable; the note value inside the pool is not."
            icon={<IconShield />}
            facts={[
              "Two wallet prompts on shield: ERC-20 approval, then the private deposit.",
              "Shielded balance is unavailable until a privacy-enabled Starknet wallet connects.",
              "Deposits publish public addresses and amounts at the pool boundary.",
            ]}
          />

          <StoryChapter
            id="settle"
            index="Chapter 02"
            title="Settle — pay recipients without exposing payer history"
            thesis="Private transfers move shielded value between registered STRK20 accounts. Observers cannot read in-pool sender, recipient, token, or amount."
            icon={<IconSettle />}
            facts={[
              "Both sender and recipient must be registered with STRK20 before a private transfer.",
              "Memos and invoice metadata stay in application fields you choose to share.",
              "Nothing in this demo executes on-chain until your wallet signs it.",
            ]}
          />

          <StoryChapter
            id="prove"
            index="Chapter 03"
            title="Prove — disclose only what auditors need"
            thesis="Selective disclosure lets merchants answer compliance questions without reopening the entire pool history."
            icon={<IconProve />}
            facts={[
              "Viewing keys and proof artifacts are separate from day-to-day settlement.",
              "Published nullifiers are visible but unlinkable without authorized key material.",
              "Open-note flows and app metadata can still leak correlation if used carelessly.",
            ]}
            accent="neutral"
          />
        </div>
      </section>

      <section className={styles.console} id="demo">
        <div className={styles.consoleInner}>
          <div className={styles.consoleHead}>
            <span className={styles.sectionEyebrow}>Live merchant console</span>
            <h2 className={styles.sectionTitle}>Twenty prototypes. One privacy model.</h2>
            <p>
              Each module below is a working surface for judges to inspect: invoicing, treasury, risk controls, and
              operations—all wired to the same STRK20 boundaries described above.
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
          <header className={styles.storyIntro}>
            <span className={styles.sectionEyebrow}>
              <IconBoundary size={14} /> Boundaries
            </span>
            <h2 className={styles.sectionTitle}>Useful privacy, honest edges.</h2>
            <p>No larping: this table states exactly what CipherBill hides, and what remains public on Starknet.</p>
          </header>
          <div className={styles.privacyGrid}>
            <article className={`${styles.privacyCard} ${styles.privacyCardHidden}`}>
              <h3>
                <IconPool size={18} /> Hidden inside the pool
              </h3>
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
            <a className={styles.brand} href="#top" aria-label="CipherBill">
              <CipherBillLogo className={styles.brandLogo} size={34} />
              <CipherBillWordmark className={styles.wordmark} />
            </a>
            <p>
              Open-source merchant infrastructure for STRK20 on Starknet. Built for judges, operators, and developers
              who need privacy without fiction.
            </p>
          </div>
          <div className={styles.footerCol}>
            <h4>Narrative</h4>
            <ul>
              <li>
                <a href="#story">Prologue</a>
              </li>
              <li>
                <a href="#shield">Shield</a>
              </li>
              <li>
                <a href="#settle">Settle</a>
              </li>
              <li>
                <a href="#prove">Prove</a>
              </li>
            </ul>
          </div>
          <div className={styles.footerCol}>
            <h4>Stack</h4>
            <ul>
              <li>STRK20 privacy pool</li>
              <li>Starknet mainnet (SN_MAIN)</li>
              <li>Wallet API · starknet.js</li>
            </ul>
          </div>
        </div>
        <div className={styles.footerBottom}>
          <span>STRK20 Private Sprint · CipherBill</span>
          <span>Original mark & icons · no stock assets</span>
        </div>
      </footer>
    </div>
  );
}
