"use client";

import { useMemo, useState } from "react";

import { CipherBillLogo, CipherBillWordmark } from "@/components/brand/cipherbill-logo";
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

const moduleGroups = [
  {
    id: "invoicing",
    label: "Invoicing",
    modules: [
      ["transfer", "Private payment"],
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
    case "transfer":
      return <PrivatePayment />;
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
  const [tab, setTab] = useState<Tab>("transfer");
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
      <header className={styles.topBar}>
        <a className={styles.brand} href="#top" aria-label="CipherBill home"><CipherBillLogo size={30} /><CipherBillWordmark /></a>
        <nav className={styles.navLinks} aria-label="Primary"><a href="#demo">Workspace</a><a href="#privacy">Privacy</a><a href="#evidence">Evidence</a><a href="/audit">Audit</a><a href="https://github.com/Nitish-1303/CipherBill" target="_blank" rel="noreferrer">Source ↗</a></nav>
        <WalletConnect />
      </header>
      <main>
        <section className={styles.hero} id="top">
          <div className={styles.heroCopy}><CipherBillLogo className={styles.bigLogo} size={48} /><span className={styles.badge}>Private commerce on Starknet</span><h1>Your money,<br /><span>your business.</span></h1><p>Invoice, shield and settle on Starknet. A payment shouldn&apos;t give the world a map of your business.</p><div className={styles.actions}><a className={styles.primary} href="#demo">Open workspace <span aria-hidden="true">→</span></a><a className={styles.secondary} href="#privacy">Learn more</a></div><small>Built for the STRK20 Private Sprint. Mainnet-targeted prototype.</small></div>
          <div className={styles.previewStage}>
            <div className={styles.preview} aria-label="Illustrative workspace preview">
              <div className={styles.previewHead}><span><CipherBillLogo size={25} />CipherBill</span><small>Not connected</small></div>
              <div className={styles.previewBody}>
                <div className={styles.previewTabs}><a href="#demo" onClick={() => setTab("transfer")}>Private payment</a><a href="#demo" onClick={() => setTab("invoice")}>Invoice links</a><a href="#demo" onClick={() => setTab("audit")}>Disclosures</a></div>
                <div className={styles.previewContent}><h2>A little more discretion.</h2><p>Shielded payments start with a compatible wallet.</p><div className={styles.previewColumns}><div className={styles.previewBalance}><span>Shielded STRK balance</span><strong>--</strong><small>Connect a wallet in the workspace to load your balance.</small></div><div className={styles.previewFields}><span>Recipient address</span><div>0x...</div><div className={styles.previewFieldRow}><span>Amount<div>Amount in STRK</div></span><span>Asset<div>STRK</div></span></div><span>Memo (optional)</span><div>Invoice reference</div><button type="button" disabled>Send private payment →</button><small>Both parties must be registered with STRK20. Nothing moves until your wallet signs.</small></div></div></div>
              </div><div className={styles.previewNotice}>Illustrative preview / no real balance, invoice or transaction</div>
            </div>
          </div>
        </section>
        <section className={styles.statusStrip} aria-label="Implementation status"><div><strong>Wallet adapter <span>Built</span></strong><p>Discovery and capability checks implemented.</p></div><div><strong>Payment UI <span>Built</span></strong><p>Shield, balance and private transfer surfaces.</p></div><div><strong>Mainnet acceptance</strong><p>Manual wallet testing and transaction evidence pending.</p></div><div><strong>Selective receipts <span>Built</span></strong><p>Metadata exports implemented. Verified settlement evidence pending.</p></div></section>
        <section className={styles.features}><h2>Built for how you actually get paid.</h2><p>Less exposure inside the pool. Clear boundaries outside it.<br />A working interface, not a completed privacy guarantee.</p><div className={styles.cards}><article><span className={styles.featureIcon}>01</span><h3>Shield your STRK.</h3><p>Move public STRK into a shielded balance. Deposit address and amount remain public. Approval and deposit use separate wallet prompts.</p></article><article><span className={styles.featureIcon}>02</span><h3>Settle privately.</h3><p>Pay a registered STRK20 recipient through a compatible wallet. In-pool details are designed to stay hidden. Withdrawals remain public.</p></article><article><span className={styles.featureIcon}>03</span><h3>Share less evidence.</h3><p>Choose which application receipt fields to disclose. Encrypt a bundle for an auditor. These exports are not ZK proofs or protocol viewing keys.</p><small>Verified mainnet evidence pending</small></article></div></section>
        <section className={styles.privacy} id="privacy"><div className={styles.sectionHeader}><span className={styles.badge}>Privacy / honest boundaries</span><h2>Private inside.<br /><span>Observable at the edges.</span></h2><p>The STRK20 design model, not a claim of completed CipherBill mainnet verification.</p></div><div className={styles.privacyGrid}><article><h3>Designed to stay hidden</h3><ul>{hiddenItems.map(item => <li key={item}>{item}</li>)}</ul></article><article><h3>Public or observable</h3><ul>{publicItems.map(item => <li key={item}>{item}</li>)}</ul></article></div><p className={styles.note}>Anyone holding a standard invoice URL can read its fields. Never put private keys, seed phrases, viewing keys, notes or wallet history in invoice fields.</p></section>
        <section className={styles.evidence} id="evidence"><div className={styles.sectionHeader}><span className={styles.badge}>Evidence / inspect the implementation</span><h2>A working interface.<br /><span>Not a finished promise.</span></h2><p>Built by Yeluru Nitish. Next.js, TypeScript and the Starknet Wallet API.</p></div><div className={styles.evidenceGrid}><article><span className={styles.evidenceLabel}>Implementation</span><h3>Inspect the source.</h3><p>Wallet action adapter, guarded submission and local invoice tooling. A delayed confirmation preserves the submitted hash.</p><a href="https://github.com/Nitish-1303/CipherBill" target="_blank" rel="noreferrer">Open the repository ↗</a></article><article><span className={styles.evidenceLabel}>Mainnet acceptance</span><h3>Evidence pending.</h3><p>No verified transactions or demo video are listed in the current repository manifest. Interface code is not proof of successful settlement.</p><span className={styles.pending}>Awaiting manually verified evidence</span></article><article><span className={styles.evidenceLabel}>Selective disclosure</span><h3>Application metadata.</h3><p>Receipt selectors and encrypted bundles are implemented. An auditor must independently verify any disclosed settlement hash.</p><a href="/audit">Open the auditor viewer →</a></article></div></section>
        <section className={styles.console} id="demo"><div className={styles.sectionHeader}><span className={styles.badge}>The workspace</span><h2>One focused flow.<br /><span>Room to inspect the rest.</span></h2><p>Private payments plus all 20 existing console modules. Wallet-integrated prototypes and local proof tools, not 20 verified financial services.</p></div><div className={styles.consoleFrame}><aside className={styles.consoleSidebar} aria-label="Module navigation"><label className={styles.searchLabel} htmlFor="module-search">Find a module</label><input id="module-search" className={styles.consoleSearch} type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search modules" />{filteredGroups.length === 0 && <p className={styles.note}>No matching modules.</p>}{filteredGroups.map(group => <div key={group.id} className={styles.moduleGroup}><div className={styles.groupLabel}>{group.label}</div>{group.modules.map(([value,label]) => <button key={value} type="button" aria-pressed={tab === value} className={`${styles.moduleButton} ${tab === value ? styles.moduleButtonActive : ""}`} onClick={() => setTab(value)}>{label}</button>)}</div>)}</aside><div className={styles.consoleMain}><div className={styles.consoleMainHead}><strong>{activeLabel}</strong><span>{["zkpayroll","vatcompliance","cashflow","treasurysweep","revenuerouting","fxhedging","factoringvault","dunning"].includes(tab) ? "Local proof tool / no pool execution" : tab === "audit" ? "Encrypted application metadata / not protocol viewing keys" : "Wallet-integrated prototype / mainnet evidence pending"}</span></div>{renderModule(tab)}</div></div></section>
      </main><footer className={styles.footer}><a className={styles.brand} href="#top"><CipherBillLogo size={26} />CipherBill</a><span>Built by Yeluru Nitish / STRK20 Private Sprint</span><a href="https://github.com/Nitish-1303/CipherBill" target="_blank" rel="noreferrer">Open source ↗</a></footer>
    </div>
  );
}
