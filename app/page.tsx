import { PrivatePayment } from "@/components/private-payment";

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
        <button className="wallet" type="button">Connect wallet</button>
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

      <footer><a className="brand" href="#top"><span>◒</span> ShadowPay</a><p>Open-source infrastructure for private commerce.</p><small>STRK20 Private Sprint · 2026</small></footer>
    </main>
  );
}
