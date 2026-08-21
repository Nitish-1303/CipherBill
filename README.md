# ShadowPay AI

Privacy-first invoicing and settlement for independent workers and global teams, built for the [STRK20 Private Sprint](https://strk20.starknet.io/hackathon).

> Status: interface and integration boundary are implemented. Live STRK20 SDK calls, wallet execution and mainnet evidence are the next milestones. The product does not claim completed privacy guarantees yet.

## Problem

Public payment rails leak balances, counterparties and commercial relationships. ShadowPay uses STRK20 shielded balances and private transfers while retaining a selective-disclosure path for invoices, accounting and disputes.

## Core flow

1. Connect a Starknet wallet.
2. Shield STRK through the live STRK20 pool.
3. Create an invoice or private payment request.
4. Settle through a private transfer.
5. Export selective evidence without exposing the complete financial graph.

## Stack

- Next.js 15, React 19 and TypeScript
- Starknet.js and Starknet React
- STRK20 Privacy SDK integration boundary
- Starknet mainnet target

## Local development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Mainnet acceptance criteria

- [ ] Wallet connect on Starknet mainnet
- [ ] Shield STRK through the live STRK20 pool
- [ ] Execute private transfers via the official SDK/prover
- [ ] Confirm transaction state and failure handling
- [ ] Add at least three successful pool-touching hashes to `strk20.json`
- [ ] Deploy a public demo
- [ ] Record the three-minute demo video

## Evidence manifest

The hackathon reads submission evidence from [`strk20.json`](./strk20.json). Do not add testnet or unsuccessful hashes.

## Security posture

- No private keys or seed phrases are stored by this application.
- Wallet signatures remain user-controlled.
- Mainnet actions stay disabled until the official SDK integration is configured.
- Transaction evidence must be verified on-chain before submission.

## License

MIT
