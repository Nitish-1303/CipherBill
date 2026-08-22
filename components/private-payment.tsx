"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import { MainnetStrk20Client } from "@/lib/strk20/client";
import { getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, releaseSubmission } from "@/lib/strk20/transaction";
import type { PrivacyTransaction } from "@/lib/strk20/types";
import { decimalToBaseUnits, isValidAmount, isValidStarknetAddress, validatePaymentInput } from "@/lib/strk20/validation";

import { useWallet } from "./wallet-provider";
import { DirectoryModal, type DirectorySelection } from "./directory-modal";

type FormState = { recipient: string; amount: string; memo: string };

const initialState: FormState = { recipient: "", amount: "", memo: "" };

export function PrivatePayment() {
  const { account, address, status: walletStatus, capabilities } = useWallet();
  const [form, setForm] = useState(initialState);
  const [message, setMessage] = useState("Connect a privacy-enabled Starknet wallet to begin.");
  const [transferTransaction, setTransferTransaction] = useState<PrivacyTransaction | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [shieldAmount, setShieldAmount] = useState("");
  const [shieldedBalance, setShieldedBalance] = useState<string | null>(null);
  const [shieldMessage, setShieldMessage] = useState("Shielded balance unavailable until a wallet is connected.");
  const [shieldTransaction, setShieldTransaction] = useState<PrivacyTransaction | null>(null);
  const [maturityMessage, setMaturityMessage] = useState<string | null>(null);
  const [balanceLoading, setBalanceLoading] = useState(false);
  const [shielding, setShielding] = useState(false);
  const [unshieldAmount, setUnshieldAmount] = useState("");
  const [unshieldRecipient, setUnshieldRecipient] = useState("");
  const [unshielding, setUnshielding] = useState(false);
  const [unshieldMessage, setUnshieldMessage] = useState("No public withdrawal submitted.");
  const [unshieldTransaction, setUnshieldTransaction] = useState<PrivacyTransaction | null>(null);
  const [directoryOpen, setDirectoryOpen] = useState(false);
  const [selectedAlias, setSelectedAlias] = useState<string | null>(null);
  const balanceLock = useRef(false);
  const shieldLock = useRef(false);
  const transferLock = useRef(false);
  const unshieldLock = useRef(false);
  const valid = useMemo(() => !validatePaymentInput(form.recipient, form.amount), [form]);

  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);

  useEffect(() => {
    if (!account) setShieldedBalance(null);
  }, [account]);

  async function loadBalance() {
    if (!account || !walletReady || !acquireSubmission(balanceLock)) return;
    setBalanceLoading(true);
    setShieldMessage("Requesting shielded balance access in your wallet...");
    try {
      const balance = await new MainnetStrk20Client(account).getBalance();
      setShieldedBalance(balance.amount);
      setShieldMessage("Shielded STRK balance ready.");
    } catch {
      setShieldMessage("Shielded balance access was rejected or unavailable.");
    } finally {
      releaseSubmission(balanceLock);
      setBalanceLoading(false);
    }
  }

  async function shield() {
    if (!account || !walletReady || !isValidShieldAmount() || !acquireSubmission(shieldLock)) return;
    setShielding(true);
    setShieldMessage("Shield uses two wallet prompts: first ERC-20 approval, then the STRK20 deposit.");

    try {
      const client = new MainnetStrk20Client(account);
      const fee = await client.getFeeAmount();
      setShieldMessage(`Complete both wallet prompts: 1/2 ERC-20 approval, then 2/2 STRK20 deposit. Current pool fee: ${BigInt(fee).toString()} base units.`);
      const transaction = await client.shield(shieldAmount);
      setShieldTransaction(transaction);

      if (transaction.status === "confirmed") {
        setShieldMessage("Shield confirmed on Starknet mainnet.");
        setMaturityMessage("New shielded note: maturing for approximately 10 blocks before it can be spent.");
        setShieldAmount("");
      } else if (transaction.status === "submitted") {
        setShieldMessage("Shield submitted; RPC confirmation is delayed. The transaction hash is preserved below.");
        setMaturityMessage("After confirmation, the new shielded note needs approximately 10 blocks to mature before spending.");
        setShieldAmount("");
      } else {
        setShieldMessage("The submitted shield reverted. Its transaction hash is preserved below.");
      }
    } catch {
      setShieldMessage("The shield was rejected or failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(shieldLock);
      setShielding(false);
    }
  }

  async function unshield() {
    if (
      !account
      || !walletReady
      || !isValidAmount(unshieldAmount)
      || !isValidStarknetAddress(unshieldRecipient)
      || !acquireSubmission(unshieldLock)
    ) return;

    setUnshielding(true);
    setUnshieldMessage("Preparing a public withdrawal. Recipient, token, amount and timing will be visible.");
    try {
      const client = new MainnetStrk20Client(account);
      const fee = await client.getFeeAmount();
      setUnshieldMessage(`Confirm the public withdrawal in your wallet. Current pool fee: ${BigInt(fee).toString()} base units.`);
      const transaction = await client.unshield(unshieldAmount, unshieldRecipient);
      setUnshieldTransaction(transaction);

      if (transaction.status === "confirmed") {
        setUnshieldMessage("Public withdrawal confirmed on Starknet mainnet.");
      } else if (transaction.status === "submitted") {
        setUnshieldMessage("Public withdrawal submitted; RPC confirmation is delayed. The transaction hash is preserved below.");
      } else {
        setUnshieldMessage("The submitted public withdrawal reverted. Its transaction hash is preserved below.");
      }

      if (transaction.status !== "failed") {
        setUnshieldAmount("");
        setUnshieldRecipient("");
      }
    } catch {
      setUnshieldMessage("The withdrawal was rejected or failed before a transaction hash was returned.");
    } finally {
      releaseSubmission(unshieldLock);
      setUnshielding(false);
    }
  }

  function isValidShieldAmount() {
    return isValidAmount(shieldAmount);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!account || !valid || !walletReady || !acquireSubmission(transferLock)) return;

    setSubmitting(true);
    setMessage("Requesting balance access to validate the amount and dynamic pool fee. The recipient must already be registered with STRK20.");

    try {
      const client = new MainnetStrk20Client(account);
      const [balance, fee] = await Promise.all([client.getBalance(), client.getFeeAmount()]);
      const requested = BigInt(decimalToBaseUnits(form.amount));
      const poolFee = BigInt(fee);

      if (requested + poolFee > BigInt(balance.amount)) {
        setMessage(`Insufficient shielded STRK balance for the payment plus the current pool fee of ${poolFee.toString()} base units.`);
        return;
      }

      setMessage(`Confirm the private transfer in your wallet. Recipient registration is required. Current pool fee: ${poolFee.toString()} base units.`);
      const transaction = await client.privateTransfer({
        recipient: form.recipient,
        amount: form.amount,
        token: "STRK",
        memo: form.memo || undefined,
      });
      setTransferTransaction(transaction);

      if (transaction.status === "confirmed") {
        setMessage("Private transfer confirmed on Starknet mainnet.");
      } else if (transaction.status === "submitted") {
        setMessage("Private transfer submitted; RPC confirmation is delayed. The transaction hash is preserved below—do not resubmit.");
      } else {
        setMessage("The submitted private transfer reverted. Its transaction hash is preserved below.");
      }

      if (transaction.status !== "failed") {
        setForm(initialState);
        setSelectedAlias(null);
      }
    } catch {
      setMessage("The transfer was rejected, the recipient may not be registered, or submission failed before a transaction hash was returned. No sensitive wallet data was stored.");
    } finally {
      releaseSubmission(transferLock);
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
          <button type="button" onClick={loadBalance} disabled={!walletReady || balanceLoading}>{balanceLoading ? "Loading..." : "Load balance"}</button>
          <button type="button" onClick={shield} disabled={!walletReady || !isValidShieldAmount() || shielding}>{shielding ? "..." : "Shield"}</button>
        </div>
      </div>
      <p className="status">Shielding requires two wallet prompts: ERC-20 approval, then the private deposit.</p>
      <p className="status">{shieldMessage}</p>
      {maturityMessage ? <p className="status" role="status">{maturityMessage}</p> : null}
      {shieldTransaction ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(shieldTransaction.hash)} target="_blank" rel="noreferrer">View shield transaction ↗</a> : null}
      <form onSubmit={submit} aria-busy={submitting}>
        <label>
          <span className="recipient-label-row"><span>Recipient address</span>{selectedAlias ? <i>{selectedAlias}</i> : null}</span>
          <span className="recipient-directory-row">
            <input
              placeholder="0x…"
              value={form.recipient}
              onChange={(event) => { setForm({ ...form, recipient: event.target.value }); setSelectedAlias(null); }}
            />
            <button className="directory-trigger" type="button" onClick={() => setDirectoryOpen(true)} aria-label="Open encrypted recipient directory">Directory</button>
          </span>
        </label>
        <p className="status">Private transfers require both sender and recipient to be registered with STRK20. Only the recipient can register their wallet.</p>
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
        <button type="submit" disabled={!valid || !walletReady || submitting}>
          {submitting ? "Processing..." : "Send private payment"}
        </button>
      </form>
      <p className="status">{message}</p>
      {transferTransaction ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(transferTransaction.hash)} target="_blank" rel="noreferrer">View private transfer transaction ↗</a> : null}
      {address ? <small className="wallet-note">Connected account: {address.slice(0, 8)}...{address.slice(-6)}</small> : null}
      <div className="unshield-box">
        <span className="field-caption">Unshield to a public address</span>
        <p className="status">Warning: unshielding makes the recipient, token, amount and timing public on Starknet.</p>
        <div className="form-row">
          <input aria-label="Unshield amount" inputMode="decimal" placeholder="Amount" value={unshieldAmount} onChange={(event) => setUnshieldAmount(event.target.value)} />
          <input aria-label="Public recipient address" placeholder="0x..." value={unshieldRecipient} onChange={(event) => setUnshieldRecipient(event.target.value)} />
        </div>
        <button type="button" onClick={unshield} disabled={!walletReady || !isValidAmount(unshieldAmount) || !isValidStarknetAddress(unshieldRecipient) || unshielding}>{unshielding ? "Processing..." : "Unshield publicly"}</button>
        <p className="status">{unshieldMessage}</p>
        {unshieldTransaction ? <a className="transaction-link" href={getStarknetExplorerTransactionUrl(unshieldTransaction.hash)} target="_blank" rel="noreferrer">View public withdrawal transaction ↗</a> : null}
      </div>
      <DirectoryModal
        open={directoryOpen}
        onClose={() => setDirectoryOpen(false)}
        onSelect={(selection: DirectorySelection) => {
          setForm((current) => ({ ...current, recipient: selection.recipientAddress }));
          setSelectedAlias(selection.alias);
          setMessage(`${selection.alias} resolved locally to a registered STRK20 recipient. Confirm the merchant before paying.`);
        }}
      />
    </section>
  );
}
