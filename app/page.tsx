import { PrivatePayment } from "@/components/private-payment";
import { InvoicePanel } from "@/components/invoice-panel";
import { WalletConnect } from "@/components/wallet-connect";

const steps = [
  ["01", "Shield", "Move STRK into a shielded balance through the live privacy pool."],
  ["02", "Settle", "Send a private payment without exposing the payer's balance history."],
  ["03", "Prove", "Share selective transaction evidence for accounting or disputes."],
];

export default function Home() {
  return (
    <main>
      <nav>
        <a className="brand" href="#top"><span>◒</span> ShadowPay</a>
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

      <InvoicePanel />

      <section className="privacy-model">
        <div className="section-heading"><span>Selective disclosure</span><h2>Useful privacy, honest edges.</h2></div>
        <div className="privacy-table" role="table" aria-label="ShadowPay privacy model">
          <div role="row" className="privacy-row privacy-header"><strong>Hidden inside the pool</strong><strong>Public or observable</strong></div>
          <div role="row" className="privacy-row"><span>In-pool sender, recipient, token and amount</span><span>Deposits, withdrawals and their public addresses</span></div>
          <div role="row" className="privacy-row"><span>Private notes used by the wallet</span><span>Timing, fees, nullifiers and app-side metadata</span></div>
          <div role="row" className="privacy-row"><span>Invoice receipt fields shared intentionally</span><span>Distinctive amounts and channel-opening correlation risks</span></div>
        </div>
      </section>

      <footer><a className="brand" href="#top"><span>◒</span> ShadowPay</a><p>Open-source infrastructure for private commerce.</p><small>STRK20 Private Sprint · 2026</small></footer>
    </main>
  );
}
