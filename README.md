# CipherBill

<p align="center">
  <img src="assets/assets/cipherbill-logo.svg" alt="CipherBill logo" width="160" />
</p>

**Your money, your business.** Privacy-first invoicing and a private-payment workspace on Starknet, built for the STRK20 Private Sprint.

[Live app](https://cipher-bill.vercel.app/) · [Auditor viewer](https://cipher-bill.vercel.app/audit)

## Walkthrough

A 1:27 tour of the live interface, with narration and captions. No live wallet transaction is shown.

https://github.com/user-attachments/assets/763fc37b-ef41-40f2-ac02-8f0a33c7608e

Built by **Yeluru Nitish** · Telegram: `nikki_1303` · Category: Payments · Target network: Starknet mainnet (`SN_MAIN`)

## Sponsor this project

<p align="center">
  <a href="https://github.com/sponsors/Nitish-1303"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?style=for-the-badge" alt="Sponsor Nitish-1303 on GitHub"></a>
</p>

## Current status

The interface and application tooling are implemented: guarded wallet connection, the STRK20 Wallet API adapter, shielded-balance and private-transfer controls, shareable invoice links, invoice lifecycle accounting, selective receipt exports, encrypted auditor disclosures, and the auditor viewer.

**Verified mainnet settlement evidence is still pending.** The repository's `strk20.json` currently contains no transaction hashes or contract evidence. Implemented code, a deployed interface, and this walkthrough are not proof of successful private settlement or completed privacy guarantees. Wallet execution requires a configured mainnet RPC and a compatible privacy-enabled wallet.

## What you can use

| Area | Implementation |
| --- | --- |
| Private payment | Load a shielded balance, prepare shielding, private transfers, and public withdrawals through the wallet adapter. Signing and execution stay with the wallet. |
| Invoices | Create drafts, activate self-contained payment links, set expiry and partial-payment options, and define milestones. Local lifecycle records track submitted, confirmed, and failed payments. |
| Selective receipts | Choose which application receipt fields to disclose and export JSON or printable receipt text. |
| Auditor disclosures | Encrypt selected invoice and payment metadata in the browser with an AES-256-GCM key. Share the envelope and key separately; open the bundle in the auditor viewer. |
| Workspace | Private payment plus 20 existing modules, grouped by invoicing, treasury, risk, and operations. These are wallet-integrated prototypes and local tools, not 20 verified financial services. |

### Workspace modules

- **Invoicing:** Single Invoice, Batch Payroll Dispersal, ZK Payroll Protocol, Auditor Disclosures, VAT Compliance.
- **Treasasury & liquidity:** Cash Flow Forecast, Treasury Sweep, Revenue Routing, FX Hedging, Invoice Factoring, Factoring Vault, Fiat Shielding, Settlement Routes.
- **Risk & trust:** Enterprise Escrow, Arbitration Vault, Dispute Resolution, Invoice Insurance.
- **Operations:** Expense Splitter, Private Memberships, Dunning & Recovery.

Module names describe the interface and local logic. They do not establish deployed contracts, custody, enforcement, regulatory compliance, or successful mainnet execution.

## Payment flow

1. Open the workspace and connect a compatible Starknet wallet on mainnet.
2. Shield STRK into the configured STRK20 pool. ERC-20 approval and deposit are separate wallet prompts.
3. Create an invoice link or prepare a private payment to a registered pool recipient.
4. Review and sign in the wallet. The adapter validates inputs and tracks submission and receipt confirmation.
5. Choose the receipt fields to export, or create an encrypted disclosure for an auditor.

Both private-transfer participants must be registered with STRK20. The recipient onboards through their own wallet. Newly created change notes may need roughly ten blocks before they can be spent again. A private envelope may be submitted by a relayer; its sender is not necessarily the payer.

## Privacy and trust boundaries

- **In-pool privacy is the STRK20 design model**, not a claim that CipherBill has completed mainnet verification. Deposits, withdrawals, public addresses and amounts at the pool edges, timing, fees, and activity outside the pool remain observable.
- **Standard invoice links are readable by anyone holding the URL.** Invoice fields are not encrypted. The payload checksum detects edits but does not authenticate the merchant.
- **Local history is application metadata**, not shared merchant state or independent proof of payment. Clearing browser storage removes local records; self-contained invoice links do not depend on that history.
- **Receipts are selected application metadata, not zero-knowledge proofs.** An auditor must independently verify any disclosed settlement hash.
- **A CipherBill disclosure key is an application encryption key**, not a STRK20 protocol viewing key or auditor key escrow. It cannot read pool notes or balances, derive nullifiers, or authorize spending. A bundle has no merchant signature.
- **Audit decryption happens in the browser.** The encrypted envelope can travel in the URL fragment, which browsers do not send to the server. Keep the key on a separate channel.

Never put private keys, seed phrases, protocol viewing keys, wallet notes, wallet history, or credentials in invoice fields, links, or exports.

## Architecture

Next.js 15, React 18.3, TypeScript, Starknet.js 10.4, and the get-starknet 6.0.3 Wallet API stack.

The browser checks Wallet API support and connects through `WalletAccountV6`. The typed STRK20 adapter handles validation, fee reads, action construction, bounded receipt confirmation, and error states. The wallet owns note discovery, proving, signing, and submission; CipherBill does not receive its private keys or protocol viewing keys.

- `app/page.tsx`: landing page and module workspace.
- `app/pay/`: invoice payment routes.
- `app/audit/`: browser-side encrypted disclosure viewer.
- `lib/strk20/`: mainnet configuration, validation, and wallet integration.
- `lib/invoices.ts` and `lib/invoice-lifecycle.ts`: invoice payloads, local records, and accounting.
- `lib/selective-receipts.ts` and `lib/view-key.ts`: receipt selection and encrypted disclosure exports.

## Run locally

Use Node.js 20, matching CI.

```bash
npm ci
cp .env.example .env.local
npm run dev
```

Open `http://localhost:3000`.

### Mainnet configuration

Set `NEXT_PUBLIC_STARKNET_RPC_URL` to a Starknet mainnet RPC endpoint. The chain must be `SN_MAIN`; the pool must match the mainnet address pinned in `lib/strk20/config.ts` and `.env.example`. The config returns unavailable when the RPC is missing, the chain is wrong, or the pool address does not match.

`NEXT_PUBLIC_*` values are browser-visible. Never put private keys, seed phrases, viewing keys, notes, proving credentials, or server-only secrets in them. Wallet connection alone does not establish STRK20 support; shielded actions depend on the wallet's capabilities.

## Checks

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm start
```

The repository includes tests for invoice encoding and lifecycle accounting, selective receipts, encrypted disclosures, and module logic. Passing tests does not replace live mainnet acceptance.

## Mainnet acceptance and submission evidence

Still to be demonstrated and independently verified:

- Wallet connection and STRK20 capability on Starknet mainnet.
- Shielding through the configured live pool.
- Successful private transfers and confirmation/failure handling.
- At least three successful mainnet pool-touching transaction hashes in `strk20.json`.

The public app and narrated UI walkthrough are available above. The submission manifest's `demo_url` and `demo_video` fields are currently empty; this README does not update that manifest. Do not add testnet, failed, or unverified hashes as evidence.

## License

MIT
