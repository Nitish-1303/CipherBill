# CipherBill Mainnet Testing

These steps intentionally require a person at every wallet prompt. CipherBill must never submit a wallet transaction automatically.

Use a dedicated privacy-enabled Starknet wallet and small amounts of STRK for approval, pool fees, shielding, payment, unshielding, and gas. Never provide CipherBill with a seed phrase, private key, recovery phrase, viewing key, password, note data, or signing credential.

## Before testing

- [ ] Copy `.env.example` to `.env.local`; never print or commit the resulting file.
- [ ] Set `NEXT_PUBLIC_STARKNET_RPC_URL` to a restricted Starknet Mainnet RPC endpoint.
- [ ] Confirm the app reports `SN_MAIN`.
- [ ] Confirm the pool is `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`.
- [ ] Confirm the STRK token is `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`.
- [ ] Connect a privacy-enabled wallet that advertises Wallet API `0.10.3` or newer.
- [ ] Prepare a second, registered privacy-wallet recipient. Only that recipient can register themselves.
- [ ] Start the app with `npm run dev` and keep a Starknet explorer open for independent verification.

## Transaction 1 of 3: shield STRK

1. In CipherBill, enter a small shield amount and choose **Shield**.
2. Read the displayed current pool fee.
3. In the first wallet prompt, inspect and approve the STRK ERC-20 allowance. This approval is a separate public transaction and is not one of the three required pool-touching evidence transactions.
4. In the second wallet prompt, inspect and approve the STRK20 deposit.
5. Wait for confirmation. If CipherBill reports delayed confirmation, keep the displayed hash and verify it before retrying; do not submit a duplicate deposit.
6. In the explorer, confirm the deposit hash succeeded on Starknet Mainnet and touched the official STRK20 pool.
7. Save that verified deposit hash privately for the later evidence update.
8. Wait approximately ten blocks for the new note to mature, then use **Load balance** as an explicit balance-access request.

## Transaction 2 of 3: private invoice payment

1. Create and activate an invoice addressed to the registered recipient wallet. Use a small amount and optionally create milestones or enable split payments.
2. Copy its `/pay/<payload>` link and open it in a separate browser context or device to confirm portability.
3. Review the privacy preview and independently compare the full merchant address, token, amount, milestone, reference, and expiry with the intended invoice.
4. Connect the funded privacy-enabled payer wallet.
5. Choose the intended milestone and amount. Do not proceed if the page reports a lifecycle or amount error.
6. Choose **Pay privately**. CipherBill then requests shielded balance access and reads the current pool fee.
7. Inspect the wallet request and approve the private transfer manually.
8. If the page retains a submitted hash with delayed confirmation, do not resubmit. Verify that hash first.
9. In the explorer, confirm the transaction succeeded on Starknet Mainnet and touched the official STRK20 pool. Do not infer the payer from the transaction envelope sender because the sender may be a relayer.
10. Save the verified private-transfer hash privately for the later evidence update.
11. Build a selective receipt and confirm it contains only deliberately checked fields. Treat it as an application receipt, not a merchant signature or zero-knowledge proof.

## Transaction 3 of 3: unshield STRK

1. In CipherBill's unshield section, enter a small amount and a public Starknet recipient that you control.
2. Read the warning: the withdrawal recipient, token, amount, and timing will be public.
3. Choose **Unshield publicly** and inspect the current pool fee.
4. Inspect and approve the withdrawal in the wallet manually.
5. If confirmation is delayed, keep and verify the displayed hash before taking any further action.
6. In the explorer, confirm the withdrawal succeeded on Starknet Mainnet, touched the official STRK20 pool, and paid the intended public recipient.
7. Save the verified withdrawal hash privately for the later evidence update.

## Evidence gate

Only after all three transactions pass the checks above:

- [ ] Confirm each hash is unique, successful, on `SN_MAIN`, and pool-touching.
- [ ] Exclude the ERC-20 approval hash, failed transactions, testnet transactions, and unrelated wallet activity.
- [ ] Add only the three verified pool-touching hashes to the root `strk20.json` in a separate reviewed change.
- [ ] Never fabricate or guess a hash, contract, deployment URL, or demo-video URL.
- [ ] Confirm no wallet credential, viewing key, note, proof, or complete transaction history appears in code, logs, receipts, screenshots, or commits.

## Privacy review

- [ ] Confirm the invoice URL visibly discloses every field listed in its privacy preview.
- [ ] Confirm the selective receipt omits every unchecked field.
- [ ] Confirm the UI accurately states that deposits, withdrawals, timing, fees, registrations, nullifiers, open-note values, application metadata, and correlation patterns remain observable.
- [ ] Confirm no activity is attributed to a payer from the private transaction envelope sender.
- [ ] Use the product framing: “Private by default, disclosable when required.”
