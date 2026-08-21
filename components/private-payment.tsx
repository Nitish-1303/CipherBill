"use client";

import { FormEvent, useMemo, useState } from "react";

type FormState = { recipient: string; amount: string; memo: string };

const initialState: FormState = { recipient: "", amount: "", memo: "" };

export function PrivatePayment() {
  const [form, setForm] = useState(initialState);
  const [message, setMessage] = useState("Wallet connection and live STRK20 calls are the next integration milestone.");
  const valid = useMemo(
    () => /^0x[0-9a-fA-F]{10,}$/.test(form.recipient) && Number(form.amount) > 0,
    [form],
  );

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid) return;
    setMessage("Payment prepared locally. Mainnet submission stays disabled until the official STRK20 SDK is connected.");
  }

  return (
    <section className="payment-card" id="demo">
      <div className="eyebrow">Private transfer</div>
      <h2>Pay without publishing your financial graph.</h2>
      <form onSubmit={submit}>
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
        <button type="submit" disabled={!valid}>Prepare private payment</button>
      </form>
      <p className="status">{message}</p>
    </section>
  );
}
