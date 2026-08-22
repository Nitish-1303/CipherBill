import { TypedDataRevision, typedData as typedDataUtils, type TypedData } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";
import { baseUnitsToDecimal, normalizeStarknetAddress } from "./strk20/validation";

/**
 * Gasless (relayer-paid) STRK20 invoice payments.
 *
 * ## What is already gasless, and what this module adds
 *
 * CipherBill's existing payment path is *already* relayed and already needs no public
 * gas token. The Wallet API says so in its own RPC docstring for
 * `wallet_strk20InvokeTransaction` (`@starknet-io/types-js`,
 * `dist/types/wallet-api/methods.d.ts`):
 *
 *   "The wallet adds the fee action itself: a withdraw action covering the
 *    paymaster/relayer fee required to submit, on top of the actions the dapp supplies."
 *
 * The payer therefore never signs a Starknet fee transfer and needs neither ETH nor
 * public STRK in their account - the relayer fee is withdrawn from their *shielded*
 * balance inside the same proven transaction. This module does not introduce a relayer
 * and cannot make a payment more gasless than that route already is.
 *
 * What it adds is the arithmetic and the disclosure that route needs to be usable:
 *
 * - a bigint-exact fee reserve, so a payment is not bounced at the wallet with
 *   `INSUFFICIENT_PRIVATE_BALANCE` for a shortfall the dapp could have predicted;
 * - the action list for the alternative dapp-submitted route
 *   (`wallet_strk20PrepareInvoke`), where the fee withdrawal is the dapp's job;
 * - proof-anchor staleness math, since a proof is only valid within
 *   `proof_validity_blocks` of the tip;
 * - a mapping from the documented wallet error set to text a payer can act on.
 *
 * ## Typed data: what it signs, and what it does not authorize
 *
 * STRK20 consumes no SNIP-12 typed-data signature anywhere. A pool action is authorized
 * by the SNIP-36 STARK proof plus nullifiers derived from the account's registered
 * viewing key, and the pool checks the proven message hash against the submitted actions
 * (`references/actions-and-proofs.md`, `references/notes-and-nullifiers.md`). There is no
 * outside-execution or meta-transaction entry point among the Wallet API STRK20 methods.
 * A signature produced here consequently cannot move pooled funds, cannot be replayed
 * into the pool, and is not a meta-transaction.
 *
 * `buildInvoiceTermsTypedData` exists for the one thing SNIP-12 genuinely solves in this
 * app. An invoice link is portable and unauthenticated: its checksum proves only that the
 * payload was not accidentally edited, not who wrote it. A merchant signature over the
 * terms lets a payer ask the merchant's *account contract* whether the recipient address
 * really issued those terms - an ordinary off-chain attestation, entirely outside the pool.
 */

/** Largest value a STRK20 note amount can hold: pool amounts are Cairo `u128`. */
export const U128_MAX = (1n << 128n) - 1n;

/**
 * Governance-set default for `proof_validity_blocks`: a proof's anchor block must be
 * within this many blocks of the tip when the transaction is applied (~15 minutes).
 */
export const DEFAULT_PROOF_VALIDITY_BLOCKS = 450;

/** Basis-point denominator for the optional fee headroom. */
const BASIS_POINTS = 10_000n;

/**
 * How the proven transaction reaches Starknet.
 *
 * - `wallet_relayed` - `wallet_strk20InvokeTransaction`. The wallet appends its own
 *   withdraw action for the paymaster/relayer fee and submits. Default, and the only
 *   route CipherBill can take today, because it is the only one that needs no server.
 * - `dapp_submitted` - `wallet_strk20PrepareInvoke` returns the call and proof, and the
 *   dapp submits it. Per that method's docstring the wallet does *not* add a fee
 *   withdrawal, because "the fee belongs to whoever submits, so the dapp covers it (for
 *   instance through its own paymaster)". CipherBill has no server and no paymaster
 *   credentials, so this route is modelled here for correctness, not offered in the UI.
 */
export type GaslessSubmissionRoute = "wallet_relayed" | "dapp_submitted";

export interface GaslessPaymentPlanInput {
  /** Payment amount in the token's base units. */
  paymentBaseUnits: bigint | string;
  /** The payer's shielded balance for the same token, in base units. */
  shieldedBalanceBaseUnits: bigint | string;
  /** Relayer/paymaster fee quoted for this submission, in base units of the same token. */
  relayerFeeBaseUnits: bigint | string;
  route?: GaslessSubmissionRoute;
  /**
   * Optional headroom on the fee, in basis points, for callers who want to absorb a fee
   * quote moving between the read and the submission. Defaults to 0: this module reserves
   * exactly what was quoted and never inflates a number it cannot justify.
   */
  feeHeadroomBasisPoints?: number;
}

export interface GaslessPaymentPlan {
  route: GaslessSubmissionRoute;
  paymentBaseUnits: bigint;
  /** The fee exactly as quoted. */
  relayerFeeBaseUnits: bigint;
  /** Quoted fee plus any requested headroom. Zero on the dapp-submitted route. */
  feeReserveBaseUnits: bigint;
  /** What the shielded balance must cover: payment plus the fee reserve. */
  requiredBaseUnits: bigint;
  shieldedBalanceBaseUnits: bigint;
  /** Shielded balance left over if the payment succeeds. Zero when short. */
  surplusBaseUnits: bigint;
  /** How much more must be shielded first. Zero when sufficient. */
  shortfallBaseUnits: bigint;
  sufficient: boolean;
  /**
   * Always false. On both routes the payer's public account funds nothing, which is the
   * whole substance of "gasless" here - it is a property of the STRK20 wallet methods,
   * not of this module.
   */
  payerNeedsPublicGasToken: false;
  /** True only for `dapp_submitted`, which CipherBill cannot serve. */
  requiresDappPaymaster: boolean;
  feeDrawnFrom: "payer_shielded_balance" | "dapp_paymaster";
}

/**
 * Rejects an amount that could not become a STRK20 note.
 *
 * Pool amounts are `u128`, so a value above `U128_MAX` cannot be represented and a
 * negative one is nonsense. Zero is allowed here because a zero *fee* is a legitimate
 * quote; callers that need a positive payment validate that themselves (invoice
 * validation already does).
 */
export function assertU128Amount(amount: bigint, label = "amount"): void {
  if (amount < 0n) throw new Error(`The ${label} cannot be negative.`);
  if (amount > U128_MAX) throw new Error(`The ${label} exceeds the u128 range STRK20 notes can hold.`);
}

function toBaseUnits(value: bigint | string, label: string): bigint {
  if (typeof value === "bigint") return value;
  const candidate = value.trim();
  if (!/^(?:0x[0-9a-fA-F]+|\d+)$/.test(candidate)) {
    throw new Error(`The ${label} must be a decimal or 0x-hex integer in base units.`);
  }
  return BigInt(candidate);
}

/**
 * Works out whether a payer's shielded balance covers a payment plus the relayer fee the
 * submission costs, and where that fee comes from.
 *
 * This is the part of "gasless" a dapp actually owns. The wallet will withdraw the fee
 * from the same shielded balance the payment spends, so a balance that covers the payment
 * alone is still short. All arithmetic is bigint: base units at 18 decimals overflow
 * `Number.MAX_SAFE_INTEGER` several times over, and a rounded comparison here would
 * approve a payment the pool then rejects.
 */
export function planGaslessPayment(input: GaslessPaymentPlanInput): GaslessPaymentPlan {
  const route = input.route ?? "wallet_relayed";
  const paymentBaseUnits = toBaseUnits(input.paymentBaseUnits, "payment amount");
  const relayerFeeBaseUnits = toBaseUnits(input.relayerFeeBaseUnits, "relayer fee");
  const shieldedBalanceBaseUnits = toBaseUnits(input.shieldedBalanceBaseUnits, "shielded balance");
  const headroom = input.feeHeadroomBasisPoints ?? 0;

  assertU128Amount(paymentBaseUnits, "payment amount");
  assertU128Amount(relayerFeeBaseUnits, "relayer fee");
  // A shielded balance is a sum of notes, so it may legitimately exceed a single note's
  // u128 ceiling. Only its sign is checked.
  if (shieldedBalanceBaseUnits < 0n) throw new Error("The shielded balance cannot be negative.");
  if (!Number.isInteger(headroom) || headroom < 0 || headroom > 10_000) {
    throw new Error("Fee headroom must be an integer between 0 and 10000 basis points.");
  }

  // Round the headroom up: rounding down would reserve less than asked for, which defeats
  // the point of asking for headroom at all.
  const headroomBaseUnits = headroom === 0
    ? 0n
    : (relayerFeeBaseUnits * BigInt(headroom) + BASIS_POINTS - 1n) / BASIS_POINTS;

  const requiresDappPaymaster = route === "dapp_submitted";
  const feeReserveBaseUnits = requiresDappPaymaster ? 0n : relayerFeeBaseUnits + headroomBaseUnits;
  const requiredBaseUnits = paymentBaseUnits + feeReserveBaseUnits;
  const sufficient = shieldedBalanceBaseUnits >= requiredBaseUnits;

  return {
    route,
    paymentBaseUnits,
    relayerFeeBaseUnits,
    feeReserveBaseUnits,
    requiredBaseUnits,
    shieldedBalanceBaseUnits,
    surplusBaseUnits: sufficient ? shieldedBalanceBaseUnits - requiredBaseUnits : 0n,
    shortfallBaseUnits: sufficient ? 0n : requiredBaseUnits - shieldedBalanceBaseUnits,
    sufficient,
    payerNeedsPublicGasToken: false,
    requiresDappPaymaster,
    feeDrawnFrom: requiresDappPaymaster ? "dapp_paymaster" : "payer_shielded_balance",
  };
}

/**
 * One sentence a payer can read before approving, stating the fee, the total, and who
 * pays the gas. Deliberately says "no public STRK or ETH" rather than "free".
 */
export function describeGaslessPlan(
  plan: GaslessPaymentPlan,
  token: Readonly<{ symbol: string; decimals: number }>,
): string {
  const amount = (value: bigint): string => `${baseUnitsToDecimal(value, token.decimals)} ${token.symbol}`;

  if (plan.requiresDappPaymaster) {
    return `Relayed by the dapp: the submitting service pays the Starknet fee, so nothing is withdrawn from your shielded balance beyond the ${amount(plan.paymentBaseUnits)} payment. CipherBill runs no such service, so this route is unavailable here.`;
  }

  if (!plan.sufficient) {
    return `Short by ${amount(plan.shortfallBaseUnits)}. This payment needs ${amount(plan.requiredBaseUnits)} shielded: ${amount(plan.paymentBaseUnits)} to the merchant plus ${amount(plan.feeReserveBaseUnits)} the wallet withdraws to pay the relayer that submits it. You hold ${amount(plan.shieldedBalanceBaseUnits)}.`;
  }

  return `Gasless: your public account pays nothing and needs no STRK or ETH for gas. The wallet withdraws ${amount(plan.feeReserveBaseUnits)} from your shielded balance for the relayer, so ${amount(plan.requiredBaseUnits)} of your ${amount(plan.shieldedBalanceBaseUnits)} is committed and ${amount(plan.surplusBaseUnits)} stays shielded.`;
}

/**
 * A STRK20 action, typed to match `STRK20_TRANSFER_ACTION` / `STRK20_WITHDRAW_ACTION` in
 * the Wallet API components. Amounts are emitted as 0x-hex felts, which is what the
 * `FELT` pattern in those definitions accepts (`^0x(0|[a-fA-F1-9]{1}[a-fA-F0-9]{0,62})$`).
 */
export type Strk20TransferAction = Readonly<{ type: "transfer"; token: string; amount: string; recipient: string }>;
export type Strk20WithdrawAction = Readonly<{ type: "withdraw"; token: string; amount: string; recipient: string }>;
export type Strk20GaslessAction = Strk20TransferAction | Strk20WithdrawAction;

function toFelt(amount: bigint): string {
  return `0x${amount.toString(16)}`;
}

export interface GaslessTransferInput {
  recipient: string;
  amountBaseUnits: bigint | string;
  tokenAddress?: string;
}

/**
 * Actions for the wallet-relayed route (`wallet_strk20InvokeTransaction`).
 *
 * Just the transfer. Adding a fee withdrawal here would be a double charge: the wallet
 * appends its own withdraw action for the paymaster/relayer fee on top of whatever the
 * dapp supplies. Reserve for that fee with `planGaslessPayment`; do not encode it.
 */
export function buildWalletRelayedActions(input: GaslessTransferInput): readonly [Strk20TransferAction] {
  const amount = toBaseUnits(input.amountBaseUnits, "payment amount");
  assertU128Amount(amount, "payment amount");
  if (amount === 0n) throw new Error("A private transfer needs a positive amount.");

  return [{
    type: "transfer",
    token: normalizeStarknetAddress(input.tokenAddress ?? STRK_TOKEN_ADDRESS),
    amount: toFelt(amount),
    recipient: normalizeStarknetAddress(input.recipient),
  }];
}

export interface DappSubmittedGaslessInput extends GaslessTransferInput {
  /** Address the paymaster quote says the fee must be withdrawn to. */
  feeRecipient: string;
  relayerFeeBaseUnits: bigint | string;
}

/**
 * Actions for the dapp-submitted route (`wallet_strk20PrepareInvoke`).
 *
 * Here the fee withdrawal *is* the dapp's responsibility, so it is encoded explicitly:
 * the pool pays the paymaster out of the payer's shielded balance, and the paymaster
 * submits. The documented shape of this flow is a two-pass one - simulate with a
 * placeholder fee, get a quote, then rebuild with the quoted amount and execute - because
 * the fee is not known until the call has been simulated. `simulate: true` skips proof
 * generation, so a simulated call is not submittable on-chain.
 *
 * Nothing in CipherBill calls this today; it has no server to submit from and no
 * paymaster credentials. It is exported so the route is documented and tested rather
 * than half-implemented behind a toggle that pretends to use it.
 */
export function buildDappSubmittedActions(
  input: DappSubmittedGaslessInput,
): readonly [Strk20TransferAction, Strk20WithdrawAction] {
  const [transfer] = buildWalletRelayedActions(input);
  const fee = toBaseUnits(input.relayerFeeBaseUnits, "relayer fee");
  assertU128Amount(fee, "relayer fee");
  if (fee === 0n) throw new Error("A dapp-submitted transaction needs a positive relayer fee to withdraw.");

  return [transfer, {
    type: "withdraw",
    token: transfer.token,
    amount: toFelt(fee),
    recipient: normalizeStarknetAddress(input.feeRecipient),
  }];
}

/**
 * Whether a proof's anchor block has aged out of the pool's validity window.
 *
 * A STRK20 transaction executes against a recent block and the pool rejects it if the
 * anchor is more than `proof_validity_blocks` behind the tip when it is applied. Proving
 * takes tens of seconds, so this is a real failure mode for a slow signer, not a
 * theoretical one.
 *
 * A tip *behind* the anchor is reported as not stale: that means the observed tip is
 * lagging, not that the proof expired.
 */
export function isProofAnchorStale(
  anchorBlock: number,
  tipBlock: number,
  validityBlocks: number = DEFAULT_PROOF_VALIDITY_BLOCKS,
): boolean {
  assertBlockNumber(anchorBlock, "anchor block");
  assertBlockNumber(tipBlock, "tip block");
  if (!Number.isInteger(validityBlocks) || validityBlocks < 1) {
    throw new Error("The proof validity window must be a positive whole number of blocks.");
  }
  return tipBlock - anchorBlock > validityBlocks;
}

/** Blocks of validity left for a proof anchored at `anchorBlock`. Zero once stale. */
export function blocksUntilProofAnchorExpiry(
  anchorBlock: number,
  tipBlock: number,
  validityBlocks: number = DEFAULT_PROOF_VALIDITY_BLOCKS,
): number {
  if (isProofAnchorStale(anchorBlock, tipBlock, validityBlocks)) return 0;
  return Math.max(0, validityBlocks - Math.max(0, tipBlock - anchorBlock));
}

function assertBlockNumber(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) throw new Error(`The ${label} must be a non-negative whole number.`);
}

/**
 * The error set `wallet_strk20InvokeTransaction` and `wallet_strk20PrepareInvoke`
 * document. Anything else is reported as `UNKNOWN_ERROR` rather than guessed at.
 */
export type GaslessErrorCode =
  | "NOT_REGISTERED"
  | "INSUFFICIENT_PRIVATE_BALANCE"
  | "PRIVACY_LEAK"
  | "INVALID_REQUEST_PAYLOAD"
  | "USER_REFUSED_OP"
  | "API_VERSION_NOT_SUPPORTED"
  | "UNKNOWN_ERROR";

export interface GaslessErrorExplanation {
  code: GaslessErrorCode;
  /** Payer-facing text. Never claims a transaction exists when none was submitted. */
  message: string;
  /** True when retrying after the payer changes something can plausibly succeed. */
  recoverable: boolean;
  /** Whether a transaction hash can exist for this failure. All of these precede submission. */
  submitted: false;
  /** The wallet's own message, kept verbatim for support and never parsed for meaning. */
  walletMessage?: string;
}

const GASLESS_ERROR_MESSAGES: Readonly<Record<GaslessErrorCode, Readonly<{ message: string; recoverable: boolean }>>> = {
  NOT_REGISTERED: {
    message: "This wallet is not registered with the STRK20 pool yet. Registration is transparent - the wallet performs it on first use - and only the account owner can register their own account. Open your wallet's privacy section, then try again.",
    recoverable: true,
  },
  INSUFFICIENT_PRIVATE_BALANCE: {
    message: "Your shielded balance does not cover this payment plus the relayer fee the wallet withdraws to submit it. Shield more STRK or pay a smaller amount.",
    recoverable: true,
  },
  PRIVACY_LEAK: {
    message: "The wallet refused to build this transaction because the requested actions would have leaked linkable information. Nothing was submitted and no funds moved.",
    recoverable: false,
  },
  INVALID_REQUEST_PAYLOAD: {
    message: "The wallet rejected the action payload as malformed. Nothing was submitted. This is a CipherBill bug, not something you can fix by retrying.",
    recoverable: false,
  },
  USER_REFUSED_OP: {
    message: "You declined the request in your wallet. Nothing was submitted and no transaction hash exists.",
    recoverable: true,
  },
  API_VERSION_NOT_SUPPORTED: {
    message: "This wallet does not support the STRK20 Wallet API version CipherBill requests. Update the wallet, or connect one with STRK20 support.",
    recoverable: false,
  },
  UNKNOWN_ERROR: {
    message: "The wallet could not complete this private transfer and did not return a documented STRK20 error. Nothing was submitted; check the wallet for details before retrying.",
    recoverable: true,
  },
};

/**
 * Order matters only in that a haystack could contain more than one of these; the most
 * specific reading is checked first.
 */
const GASLESS_ERROR_CODES: readonly GaslessErrorCode[] = [
  "INSUFFICIENT_PRIVATE_BALANCE",
  "API_VERSION_NOT_SUPPORTED",
  "INVALID_REQUEST_PAYLOAD",
  "USER_REFUSED_OP",
  "NOT_REGISTERED",
  "PRIVACY_LEAK",
];

/**
 * Turns a thrown wallet error into text a payer can act on.
 *
 * Matching is done on the documented error *names*, normalised so that both a
 * `code: "INSUFFICIENT_PRIVATE_BALANCE"` and a message reading "insufficient private
 * balance" resolve to the same case. Numeric JSON-RPC error codes are deliberately not
 * used: they are not pinned by the STRK20 method definitions, so keying on them would
 * mean inventing a mapping.
 */
export function mapWalletGaslessError(error: unknown): GaslessErrorExplanation {
  const walletMessage = extractWalletMessage(error);
  const haystack = normalizeErrorText([walletMessage, extractErrorCode(error)].filter(Boolean).join(" "));
  const code = GASLESS_ERROR_CODES.find((candidate) => haystack.includes(candidate)) ?? "UNKNOWN_ERROR";
  const explanation = GASLESS_ERROR_MESSAGES[code];

  return {
    code,
    message: explanation.message,
    recoverable: explanation.recoverable,
    submitted: false,
    ...(walletMessage ? { walletMessage } : {}),
  };
}

function extractWalletMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (!error || typeof error !== "object") return "";
  const candidate = error as { message?: unknown; data?: unknown };
  const parts = [candidate.message, candidate.data].filter((part): part is string => typeof part === "string");
  return parts.join(" ").trim();
}

function extractErrorCode(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  const candidate = error as { code?: unknown };
  return typeof candidate.code === "string" ? candidate.code : "";
}

function normalizeErrorText(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
}

export const INVOICE_TERMS_DOMAIN_NAME = "CipherBill Invoice Terms";
export const INVOICE_TERMS_DOMAIN_VERSION = "1";
export const INVOICE_TERMS_PRIMARY_TYPE = "InvoiceTerms";

export interface InvoiceTermsAttestationInput {
  invoiceId: string;
  recipientAddress: string;
  amountBaseUnits: bigint | string;
  /** ISO timestamp after which the terms are void. */
  expiresAt: string;
  tokenAddress?: string;
  /** Digest of the invoice payload, if the merchant wants the exact link bound in. */
  payloadDigest?: string;
  chainId?: string;
}

/**
 * SNIP-12 (revision 1) typed data over an invoice's terms.
 *
 * Read the module docstring before using this. It is a merchant attestation - "the
 * account at `recipient` issued these terms" - checked against the merchant's account
 * contract. It authorizes nothing in the STRK20 pool, is not a meta-transaction, and no
 * STRK20 method accepts it. A payer verifying it learns that the link is authentic, not
 * that any payment happened.
 *
 * `invoiceId`, `expiresAt`, and `payloadDigest` are typed as revision-1 `string`
 * (ByteArray-hashed) rather than `shortstring`: an invoice id can exceed 31 characters
 * and a 256-bit digest exceeds the felt range, so `shortstring` or `felt` would silently
 * misencode them. `amount` is `u128`, matching the pool's own amount type.
 */
export function buildInvoiceTermsTypedData(input: InvoiceTermsAttestationInput): TypedData {
  const amount = toBaseUnits(input.amountBaseUnits, "payment amount");
  assertU128Amount(amount, "payment amount");
  if (!input.invoiceId.trim()) throw new Error("Invoice terms need an invoice id.");
  if (Number.isNaN(Date.parse(input.expiresAt))) throw new Error("Invoice terms need a valid ISO expiry timestamp.");

  return {
    types: {
      StarknetDomain: [
        { name: "name", type: "shortstring" },
        { name: "version", type: "shortstring" },
        { name: "chainId", type: "shortstring" },
        { name: "revision", type: "shortstring" },
      ],
      [INVOICE_TERMS_PRIMARY_TYPE]: [
        { name: "invoiceId", type: "string" },
        { name: "recipient", type: "ContractAddress" },
        { name: "token", type: "ContractAddress" },
        { name: "amount", type: "u128" },
        { name: "expiresAt", type: "string" },
        { name: "payloadDigest", type: "string" },
        { name: "pool", type: "ContractAddress" },
      ],
    },
    primaryType: INVOICE_TERMS_PRIMARY_TYPE,
    domain: {
      name: INVOICE_TERMS_DOMAIN_NAME,
      version: INVOICE_TERMS_DOMAIN_VERSION,
      chainId: input.chainId ?? MAINNET_CHAIN_ID,
      revision: TypedDataRevision.ACTIVE,
    },
    message: {
      invoiceId: input.invoiceId.trim(),
      recipient: normalizeStarknetAddress(input.recipientAddress),
      token: normalizeStarknetAddress(input.tokenAddress ?? STRK_TOKEN_ADDRESS),
      amount: amount.toString(),
      expiresAt: input.expiresAt,
      payloadDigest: input.payloadDigest ?? "",
      pool: STRK20_POOL_ADDRESS,
    },
  };
}

/**
 * SNIP-12 message hash for a merchant attestation, bound to the signing account.
 *
 * The hash commits to the signer address, so a signature over one merchant's terms cannot
 * be presented as another merchant's.
 */
export function getInvoiceTermsMessageHash(terms: TypedData, signerAddress: string): string {
  if (!typedDataUtils.validateTypedData(terms)) throw new Error("These invoice terms are not valid SNIP-12 typed data.");
  return typedDataUtils.getMessageHash(terms, normalizeStarknetAddress(signerAddress));
}

export interface InvoiceTermsVerification {
  valid: boolean;
  messageHash: string;
  signerAddress: string;
  /** Present when verification failed, explaining what the failure does and does not mean. */
  reason?: string;
}

export interface InvoiceTermsVerificationInput {
  terms: TypedData;
  signerAddress: string;
  signature: readonly string[];
  /**
   * Injected account-contract check, normally an RPC call to the signer's
   * `is_valid_signature` (SNIP-6). Injected rather than built in so this module stays
   * pure and testable, and so the caller decides which provider is trusted.
   */
  isValidSignature: (accountAddress: string, messageHash: string, signature: readonly string[]) => Promise<boolean>;
}

/**
 * Asks the merchant's account contract whether it signed these terms.
 *
 * The account contract is the only authority on this: Starknet accounts are contracts,
 * and a signature is valid exactly when the account says it is. A `false` result means
 * the link's terms were not attested by that address - it does not mean the invoice is
 * fraudulent, since CipherBill invoices are unsigned by default.
 */
export async function verifyInvoiceTermsAttestation(
  input: InvoiceTermsVerificationInput,
): Promise<InvoiceTermsVerification> {
  const signerAddress = normalizeStarknetAddress(input.signerAddress);
  const messageHash = getInvoiceTermsMessageHash(input.terms, signerAddress);

  if (input.signature.length === 0) {
    return { valid: false, messageHash, signerAddress, reason: "No signature was supplied, so these terms are unattested." };
  }

  try {
    const valid = await input.isValidSignature(signerAddress, messageHash, input.signature);
    return valid
      ? { valid: true, messageHash, signerAddress }
      : { valid: false, messageHash, signerAddress, reason: "The merchant's account contract did not accept this signature over these terms." };
  } catch (error) {
    return {
      valid: false,
      messageHash,
      signerAddress,
      reason: error instanceof Error
        ? `The attestation could not be checked: ${error.message}`
        : "The attestation could not be checked against the merchant's account contract.",
    };
  }
}

/**
 * The single claim CipherBill's gasless UI is allowed to make, and the caveats that keep
 * it true. Rendered verbatim next to the toggle so the wording cannot drift from what the
 * code does.
 */
export const GASLESS_NOTICE = "Paying through the STRK20 pool never touches your public account balance: the wallet withdraws the relayer's fee from your shielded balance inside the same proven transaction, so you need no ETH or public STRK for gas. This is how the STRK20 wallet method works, not something CipherBill adds.";

export const GASLESS_LIMITATIONS: readonly string[] = [
  "Gasless is not free. The relayer fee is real and comes out of your shielded balance, so a balance that only covers the payment is still short.",
  "CipherBill does not run a relayer or a paymaster. The wallet chooses who submits, and CipherBill never sees or holds your funds.",
  "Nothing here is a meta-transaction. STRK20 authorizes a pool action with a zero-knowledge proof and nullifiers bound to your registered viewing key, not with an off-chain signature a third party could replay.",
  "Turning this toggle off does not make a payment cost gas from your account. It only skips CipherBill's local fee-reserve check and lets the wallet report a shortfall itself.",
  "The relayer's submitting address is public, and so are any deposits or withdrawals at the pool edges. Only movement inside the pool is hidden.",
];
