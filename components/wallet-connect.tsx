"use client";

import { useState } from "react";

import { useWallet } from "./wallet-provider";

function shortenAddress(address: string) {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function WalletConnect() {
  const { address, wallets, walletName, status, error, capabilities, connect, disconnect } = useWallet();
  const [open, setOpen] = useState(false);

  if (address && status === "connected") {
    return (
      <div className="wallet-status-block">
        <div className="wallet-status-line"><span className="wallet-name">{walletName ?? "Connected wallet"}</span><button className="wallet" type="button" onClick={disconnect} title="Disconnect wallet">{shortenAddress(address)}</button></div>
        <small className="wallet-capability-status">Starknet Mainnet · Wallet API {capabilities?.walletApiVersions.join(", ") ?? "unknown"} · STRK20 supported</small>
      </div>
    );
  }

  return (
    <>
      <button className="wallet" type="button" onClick={() => setOpen(true)} disabled={status === "connecting"}>
        {status === "connecting" ? "Connecting..." : "Connect wallet"}
      </button>
      {open ? (
        <div className="wallet-dialog-backdrop" role="presentation" onClick={() => setOpen(false)}>
          <section className="wallet-dialog" role="dialog" aria-modal="true" aria-labelledby="wallet-title" onClick={(event) => event.stopPropagation()}>
            <div className="dialog-header">
              <div>
                <span className="eyebrow">Starknet mainnet</span>
                <h2 id="wallet-title">Choose a wallet</h2>
              </div>
              <button className="icon-button" type="button" onClick={() => setOpen(false)} aria-label="Close wallet picker">×</button>
            </div>
            {wallets.length ? (
              <div className="wallet-list">
                {wallets.filter((wallet) => !wallet.name.toLowerCase().includes("metamask")).map((wallet) => (
                  <button className="wallet-option" type="button" key={wallet.name} onClick={() => connect(wallet)}>
                    <span>{wallet.name}</span><span aria-hidden="true">→</span>
                  </button>
                ))}
              </div>
            ) : <p className="dialog-copy">Install a Starknet wallet with STRK20 Wallet API support, then reload this page.</p>}
            {capabilities ? <p className={capabilities.strk20 ? "wallet-capability-ok" : "error-message"} role="status">Wallet API {capabilities.walletApiVersions.join(", ") || "unavailable"} · STRK20 {capabilities.strk20 ? "supported" : "unsupported"}</p> : null}
            {error ? <p className="error-message" role="alert">{error}</p> : null}
          </section>
        </div>
      ) : null}
    </>
  );
}