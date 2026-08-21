# CipherBill

Privacy-first invoicing and settlement for independent workers and global teams, built for the [STRK20 Private Sprint](https://strk20.starknet.io/hackathon).

Builder: Yeluru Nitish · Telegram: `nikki_1303` · Category: Payments · Network: Starknet mainnet (`SN_MAIN`)

> Status: the application, portable invoices, local lifecycle engine, milestone and partial-payment flows, privacy preview, selective receipts, and guarded Wallet API integration are implemented. The three required Mainnet transactions and public evidence must still be completed manually in a privacy-enabled wallet.

## What CipherBill does

CipherBill lets a merchant create a self-contained `/pay/<payload>` link for a STRK invoice. The payer can open that URL on another device, verify its checksum and merchant address, select an installment, and explicitly request a private STRK20 transfer from a compatible wallet.

The link does not depend on a database. It includes its own versioned invoice data and integrity checksum, so it remains portable across browsers and deployments that serve the same route. Schema v2 supports milestones and payment policy; existing schema v1 links remain readable and are safely normalized to v2 defaults.

## Invoice workflow

1. Save a local draft or activate an invoice immediately.
2. Optionally divide the total into as many as eight milestones.
3. Choose whether a payer may split a balance into smaller payments. Without that option, a non-milestone invoice requires the exact remaining total and a milestone invoice requires the exact remaining milestone amount.
4. Copy the generated `/pay/<payload>` URL and verify its privacy preview before sharing.
5. The payer reviews the encoded fields, connects a privacy-enabled mainnet wallet, and confirms every wallet request manually.
6. Submitted and confirmed payments update a browser-local lifecycle: draft, active, confirming, partially paid, paid, expired, cancelled, or disputed.
7. The payer may export a selective JSON receipt containing only explicitly checked fields.

Merchant history and payer payment state are local application metadata. They are not synchronized between devices, are not onchain proof, and cannot remotely revoke a previously shared portable link. Expiration is embedded in the checksummed payload; cancellation is local unless a future shared backend is added.

## Privacy model

The user's wallet owns viewing keys, note discovery, proof generation, signing, and submission. CipherBill never asks for or receives a viewing key.

Hidden inside the STRK20 pool:

- In-pool sender and recipient
- Token and amount for encrypted notes
- Spent-note linkage and encrypted note values

Public or otherwise observable:

- Shielding deposits and withdrawals, including their public addresses and amounts
- Timing, fees, registration events, and published nullifiers
- Open-note token and amount values
- Every field encoded into an invoice URL and any selectively exported receipt field
- Correlation risk from channel opening, distinctive amounts, or rapid activity

Private transactions may be submitted by a relayer, so CipherBill never attributes a payment to the transaction envelope sender. The product framing is: private by default, disclosable when required.

## Selective receipts

After a payment is submitted, the payer can independently include or omit merchant name, merchant address, amount and token, milestone, description, reference number, transaction hash, and timestamps. CipherBill does not add a payer address, viewing key, note data, proof, or complete wallet history.

A selective receipt is a user-generated application record, not a merchant signature or zero-knowledge proof. Verify a disclosed hash on Starknet before treating it as transaction evidence.

## Stack and trust boundary

- Next.js 15, React 18.3, TypeScript, Vitest, and ESLint
- `starknet@10.4.0`
- `@starknet-io/get-starknet-discovery@6.0.3`
- `@starknet-io/get-starknet-wallet-standard@6.0.3`
- `@starknet-io/types-js@0.10.3`
- Starknet Wallet API capability detection at version `0.10.3` or newer
- Starknet mainnet only

The typed STRK20 adapter owns validation, pool-fee reads, action construction, bounded receipt confirmation, and safe failure states. The privacy-enabled wallet owns user keys and proofs. The configured RPC can observe read and confirmation requests, while the pool, relayer, prover, screening service, and wallet have their own protocol-specific visibility.

## Local development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`. To verify the same checks as CI:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

## Mainnet configuration

Copy `.env.example` to `.env.local` and set a restricted public Starknet RPC endpoint. Never print or commit `.env.local`.

CipherBill accepts only:

- Chain: `SN_MAIN`
- STRK token: `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`
- STRK20 pool: `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`

The UI disables shielded actions until configuration is complete and the connected wallet advertises the required Wallet API support. Balance access is requested only after an explicit user action.

Shielding uses two wallet prompts: an ERC-20 approval transaction followed by the STRK20 deposit transaction. New notes generally need about ten blocks to mature. Both private-transfer participants must be registered; only the recipient can register their own wallet. Pool fees are read dynamically and are not hardcoded.

## Testing and evidence

Detailed manual steps are in [MAINNET_TESTING.md](./MAINNET_TESTING.md). The three required pool-touching Mainnet transactions are:

1. Shield STRK into the pool.
2. Send a private STRK transfer to a registered recipient.
3. Unshield STRK to a public Starknet address.

Do not add a transaction to [`strk20.json`](./strk20.json) until it is independently verified as successful on `SN_MAIN` and confirmed to touch the official pool. Do not add placeholders, approval-only hashes, testnet transactions, deployment URLs, or demo videos that do not exist.

## Security posture

- No private key, seed phrase, password, viewing key, note, or proving secret is stored by CipherBill.
- Wallet signatures and transaction submission remain user-controlled.
- Invoice payloads reject unknown fields, secret-like field names and content, unsafe addresses, invalid amounts, oversized data, checksum changes, excessive lifetimes, and inconsistent milestones.
- A checksum provides integrity, not merchant identity or authentication.
- Submitted hashes are preserved when RPC confirmation is delayed to reduce accidental duplicate payments.
- `strk20.json` stays empty until real Mainnet evidence is verified manually.

## License

MIT
