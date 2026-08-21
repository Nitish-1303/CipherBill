# CipherBill

Privacy-first invoicing and settlement for independent workers and global teams, built for the [STRK20 Private Sprint](https://strk20.starknet.io/hackathon).

Builder: Yeluru Nitish · Telegram: `nikki_1303` · Category: Payments · Network: Starknet mainnet (`SN_MAIN`)

> Status: the Wallet API adapter, guarded wallet connection, shielded balance, shield, and private-transfer UI are implemented. Verified mainnet pool configuration, manual wallet acceptance, invoices, selective receipts, and evidence remain pending. The product does not claim completed privacy guarantees yet.

## Problem

Public payment rails leak balances, counterparties and commercial relationships. CipherBill uses STRK20 shielded balances and private transfers while retaining a selective-disclosure path for invoices, accounting and disputes.

## Core flow

1. Connect a Starknet wallet.
2. Shield STRK through the live STRK20 pool.
3. Create an invoice or private payment request.
4. Settle through a private transfer.
5. Export selective evidence without exposing the complete financial graph.

## Stack

- Next.js 15, React 18.3 and TypeScript
- Starknet.js 10.4 Wallet API with the tested get-starknet 6.0.3 stack
- STRK20 wallet integration boundary
- Starknet mainnet target

## Architecture

The browser discovers a compatible wallet, verifies Wallet API support `>= 0.10.3`, and connects through `WalletAccountV6`. The typed STRK20 adapter owns validation, fee reads, action construction, bounded receipt confirmation, and safe error boundaries. The wallet owns viewing keys, note discovery, proving, signing, and submission. Invoice records are non-sensitive browser metadata only.

## Local development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Mainnet configuration

Copy `.env.example` to `.env.local` and provide a public Starknet RPC endpoint and the verified STRK20 mainnet pool address. The application keeps shield, balance, and private-transfer actions disabled until both values are present and the connected wallet reports Starknet mainnet. Do not put private keys, seed phrases, viewing keys, notes, or proving credentials in environment variables.

CipherBill uses the Starknet Wallet API. A privacy-enabled wallet performs note discovery, proving, signing, and submission; the dApp does not receive those secrets. Wallet support is capability-dependent, so a wallet may connect while still being unable to execute STRK20 actions.

Shielding is a separate public ERC-20 approval followed by a private deposit, so the wallet may show two prompts. Private transfers run between registered pool users; a recipient who has not registered must onboard in their privacy-enabled wallet first. Newly created change notes may need roughly ten blocks before they can be spent again. Private transaction envelopes may be submitted by a relayer, so CipherBill does not attribute a private payment to the envelope sender.

## Privacy model

The wallet and STRK20 pool hide in-pool transfer details from ordinary public account history. Deposits, withdrawals, transaction timing, fees, account activity outside the pool, and any data intentionally shared through an invoice remain observable. CipherBill exports only explicitly permitted receipt metadata and does not provide a complete balance or transaction-history export.

## Current limitations

- The verified Starknet mainnet STRK20 pool address is still required in `.env.local`; no Sepolia or demo address is accepted.
- A privacy-enabled wallet with Wallet API STRK20 support is required for shielded actions. Connection support for Argent and Braavos depends on their current capabilities.
- Invoices and selective-disclosure exports are not implemented in this first slice.
- `strk20.json` contains no evidence until three successful mainnet pool-touching transactions are manually verified.

## Mainnet acceptance criteria

- [ ] Wallet connect on Starknet mainnet
- [ ] Shield STRK through the live STRK20 pool
- [ ] Execute private transfers via the official SDK/prover
- [ ] Confirm transaction state and failure handling
- [ ] Add at least three successful pool-touching hashes to `strk20.json`
- [ ] Deploy a public demo
- [ ] Record the three-minute demo video

No mainnet transaction hashes are included until they are manually confirmed as successful `SN_MAIN` transactions touching the verified STRK20 pool.

## Evidence manifest

The hackathon reads submission evidence from [`strk20.json`](./strk20.json). Do not add testnet or unsuccessful hashes.

## Security posture

- No private keys or seed phrases are stored by this application.
- Wallet signatures remain user-controlled.
- Mainnet actions stay disabled until the official SDK integration is configured.
- Transaction evidence must be verified on-chain before submission.

## License

MIT
