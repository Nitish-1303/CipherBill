"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import { MainnetStrk20Client } from "@/lib/strk20/client";
import { decimalToBaseUnits, validatePaymentInput } from "@/lib/strk20/validation";

import { useWallet } from "./wallet-provider";

type FormState = { recipient: string; amount: string; memo: string };

const initialState: FormState = { recipient: "", amount: "", memo: "" };

export function PrivatePayment() {
  const { account, address, status: walletStatus } = useWallet();
  const [form, setForm] = useState(initialState);
  const [message, setMessage] = useState("Connect a privacy-enabled Starknet wallet to begin.");
  const [txHash, setTxHash] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [shieldAmount, setShieldAmount] = useState("");
  const [shieldedBalance, setShieldedBalance] = useState<string | null>(null);
  const [shieldMessage, setShieldMessage] = useState("Shielded balance unavailable until a wallet is connected.");
  const [shielding, setShielding] = useState(false);
  const valid = useMemo(() => !validatePaymentInput(form.recipient, form.amount), [form]);

  useEffect(() => {
    if (!account) {
      setShieldedBalance(null);
      return;
    }

    new MainnetStrk20Client(account).getBalance()
      .then((balance) => {
        setShieldedBalance(balance.amount);
        setShieldMessage("Shielded STRK balance ready.");
      })
      .catch(() => setShieldMessage("Shielded balance could not be loaded."));
  }, [account]);

  async function shield() {
    if (!account || !isValidShieldAmount()) return;
    setShielding(true);
    setShieldMessage("Confirm the shield deposit in your wallet...");

    try {
      const transaction = await new MainnetStrk20Client(account).shield(shieldAmount);
      setShieldMessage(`Shield confirmed: ${transaction.hash.slice(0, 10)}...`);
      const balance = await new MainnetStrk20Client(account).getBalance();
      setShieldedBalance(balance.amount);
      setShieldAmount("");
    } catch {
      setShieldMessage("The shield was rejected, failed, or could not be confirmed.");
    } finally {
      setShielding(false);
    }
  }

  function isValidShieldAmount() {
    return shieldAmount !== "" && Number(shieldAmount) > 0;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid || !account || submitting) return;

    setSubmitting(true);
    setTxHash(null);
    setMessage("Preparing private transfer...");

    try {
      const client = new MainnetStrk20Client(account);
      const balance = await client.getBalance();
      const requested = BigInt(decimalToBaseUnits(form.amount));

      if (requested > BigInt(balance.amount)) {
        setMessage("Insufficient shielded STRK balance for this payment.");
        return;
      }

      setMessage("Confirm the private transfer in your wallet...");
      const transaction = await client.privateTransfer({
        recipient: form.recipient,
        amount: form.amount,
        token: "STRK",
        memo: form.memo || undefined,
      });
      setTxHash(transaction.hash);
      setMessage("Private transfer confirmed on Starknet mainnet.");
    } catch {
      setMessage("The transfer was rejected, failed, or could not be confirmed. No sensitive wallet data was stored.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="payment-card" id="demo">
      <div className="eyebrow">Private transfer</div>
      <h2>Pay without publishing your financial graph.</h2>
      <div className="balance-strip">
        <div><span className="field-caption">Shielded STRK balance</span><strong>{shieldedBalance ?? "--"}</strong></div>
        <div className="shield-controls">
          <input aria-label="Amount to shield" inputMode="decimal" placeholder="Shield amount" value={shieldAmount} onChange={(event) => setShieldAmount(event.target.value)} />
          <button type="button" onClick={shield} disabled={!account || !isValidShieldAmount() || shielding}>{shielding ? "..." : "Shield"}</button>
        </div>
      </div>
      <p className="status">{shieldMessage}</p>
      <form onSubmit={submit} aria-busy={submitting}>
        <label>
          Recipient address
          <input
            placeholder="0x…"
            value={form.recipient}
            onChange={(event) => setForm({ ...form, recipient: event.target.value })}
          />
        </label>
        <div className="form-row">
          <label>
            Amount
            <input
              inputMode="decimal"
              placeholder="100"
              value={form.amount}
              onChange={(event) => setForm({ ...form, amount: event.target.value })}
            />
          </label>
          <label>
            Asset
            <input value="STRK" disabled />
          </label>
        </div>
        <label>
          Private memo
          <input
            placeholder="Invoice #1042"
            value={form.memo}
            onChange={(event) => setForm({ ...form, memo: event.target.value })}
          />
        </label>
        <button type="submit" disabled={!valid || !account || walletStatus !== "connected" || submitting}>
          {submitting ? "Processing..." : "Send private payment"}
        </button>
      </form>
      <p className="status">{message}</p>
      {txHash ? <a className="transaction-link" href={`https://voyager.online/tx/${txHash}`} target="_blank" rel="noreferrer">View confirmed transaction ↗</a> : null}
      {address ? <small className="wallet-note">Connected account: {address.slice(0, 8)}...{address.slice(-6)}</small> : null}
    </section>
  );
}
