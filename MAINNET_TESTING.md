# ShadowPay Mainnet Testing

Use a dedicated privacy-enabled Starknet wallet and a small amount of STRK for gas, pool fees, approval, shielding, and testing. Keep all wallet approvals manual. Never provide ShadowPay with a seed phrase, private key, recovery phrase, viewing key, password, or signing credential.

## Before Testing

- [ ] Copy `.env.example` to `.env.local` and set `NEXT_PUBLIC_STARKNET_RPC_URL` to a restricted Alchemy endpoint.
- [ ] Confirm the app is configured for `SN_MAIN`.
- [ ] Confirm the configured pool is `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`.
- [ ] Connect a privacy-enabled Starknet wallet.
- [ ] Confirm the wallet advertises Wallet API version `0.10.3` or newer.
- [ ] Confirm the wallet reports STRK20 capability before requesting balance access.

## Shield and Balance

- [ ] Start a shield and read the current pool fee from `get_fee_amount`.
- [ ] Approve the ERC-20 allowance in the first wallet prompt.
- [ ] Confirm the private deposit in the second wallet prompt.
- [ ] Observe preparing, approval, proving/signature, submitted, confirmed, and failed states.
- [ ] If confirmation times out, retain the submitted hash and resume polling or verify it in an explorer.
- [ ] Wait approximately 10 blocks before attempting to spend newly created change notes.
- [ ] Request and verify the shielded STRK balance only after explicit user action.

## Private Transfer

- [ ] Use a registered recipient, or provide recipient-onboarding guidance before sending.
- [ ] Validate the normalized Starknet recipient and available shielded balance.
- [ ] Confirm the private transfer manually in the wallet.
- [ ] Verify confirmation, timeout recovery, rejection handling, and the explorer hash.
- [ ] Do not attribute the private transfer to the transaction envelope sender; privacy transactions may be submitted by a relayer.

## Unshield

- [ ] Enter a valid public Starknet recipient.
- [ ] Confirm the app warns that recipient, token, amount, and timing become public.
- [ ] Approve the withdrawal manually in the wallet.
- [ ] Verify the confirmed withdrawal in a Starknet explorer.

## Evidence

- [ ] Verify every accepted hash is on Starknet mainnet, succeeded, touched the official STRK20 pool, and represents a real ShadowPay flow.
- [ ] Record three confirmed pool-touching hashes only after verification.
- [ ] Add verified hashes to the root `strk20.json`; never add placeholders, testnet hashes, or failed transactions.
- [ ] Confirm no wallet credentials, viewing keys, notes, proofs, or complete transaction history are included in exported receipts.

## Privacy Review

- [ ] Confirm private in-pool sender, recipient, token, amount, and notes are not shown in the app's selective receipt.
- [ ] Confirm public deposits, withdrawals, timing, fees, nullifiers, app metadata, distinctive amounts, and channel-opening correlation risks are documented.
- [ ] Use the product framing: "Private by default, disclosable when required."
