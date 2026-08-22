import { hash, type STRK20_ACTION } from "starknet";

import { calculateFiatConversion, FIAT_CURRENCIES, type FiatCurrency } from "./fiat-shielding";
import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const EXPENSE_SPLITTER_VERSION = 1 as const;
export const EXPENSE_SPLITTER_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const MAX_PENDING_EXPENSES = 32;
export const MAX_OPTIMIZED_TRANSFERS = 32;
export const MAX_EXPENSE_QUOTE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;

const PLAN_KIND = "cipherbill.expense-settlement-plan" as const;
const U128_MAX = (1n << 128n) - 1n;
const PLAN_DOMAIN = hash.starknetKeccak("CipherBill exact expense split v1");
const EXPENSE_DOMAIN = hash.starknetKeccak("CipherBill pending expense v1");

export interface ExpenseSettlementAssetInput {
  tokenAddress: string;
  symbol: string;
  decimals: number;
}

export interface ExpenseRateInput {
  rate: string;
  source: string;
  quotedAt: string;
  expiresAt: string;
}

export interface PendingExpenseInput {
  invoiceId: string;
  vendorLabel: string;
  costCenter: string;
  recipientAddress: string;
  invoiceCurrency: FiatCurrency;
  invoiceAmount: string;
  settlementAsset: ExpenseSettlementAssetInput;
  rate: ExpenseRateInput;
}

export interface ExactExpenseConversion {
  invoiceMinorUnits: string;
  normalizedInvoiceAmount: string;
  rateNumerator: string;
  rateScale: string;
  normalizedRate: string;
  settlementBaseUnits: string;
  settlementDisplayAmount: string;
  rounding: "ceil";
  roundingDeltaNumerator: string;
  roundingDenominator: string;
}

export interface ConvertedPendingExpense {
  invoiceId: string;
  vendorLabel: string;
  costCenter: string;
  recipientAddress: string;
  invoiceCurrency: FiatCurrency;
  settlementAsset: ExpenseSettlementAssetInput;
  rate: {
    source: string;
    quotedAt: string;
    expiresAt: string;
    direction: string;
  };
  conversion: ExactExpenseConversion;
}

export interface AggregatedExpenseTransfer {
  transferId: string;
  tokenAddress: string;
  tokenSymbol: string;
  tokenDecimals: number;
  recipientAddress: string;
  amountBaseUnits: string;
  displayAmount: string;
  invoiceIds: string[];
}

export interface ExpenseTokenTotal {
  tokenAddress: string;
  symbol: string;
  decimals: number;
  amountBaseUnits: string;
  displayAmount: string;
  transferCount: number;
}

export interface ExpenseOptimizationSummary {
  pendingInvoiceCount: number;
  optimizedTransferCount: number;
  duplicateTransfersMerged: number;
  walletRequestsAvoided: number;
}

export interface ExpenseSettlementPlan {
  kind: typeof PLAN_KIND;
  version: typeof EXPENSE_SPLITTER_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  createdAt: string;
  expiresAt: string;
  expenses: ConvertedPendingExpense[];
  transfers: AggregatedExpenseTransfer[];
  tokenTotals: ExpenseTokenTotal[];
  optimization: ExpenseOptimizationSummary;
  planCommitment: string;
  privacyNotice: string;
  executionNotice: string;
}

export interface ExpenseFeeSavingsEstimate {
  poolFeePerInvocationBaseUnits: string;
  individualWalletInvocations: number;
  batchedWalletInvocations: 1;
  walletInvocationsAvoided: number;
  estimatedPoolFeeSavingsBaseUnits: string;
  transferActionsEliminated: number;
  notice: string;
}

export interface ExpenseVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

interface ExpensePlanEntropy {
  createId?: () => string;
}

export function calculateExactExpenseConversion(input: {
  invoiceCurrency: FiatCurrency;
  invoiceAmount: string;
  settlementDecimals: number;
  rate: string;
}): ExactExpenseConversion {
  const converted = calculateFiatConversion({
    invoiceCurrency: input.invoiceCurrency,
    invoiceAmount: input.invoiceAmount,
    settlementDecimals: input.settlementDecimals,
    rate: input.rate,
    shieldBufferBps: 0,
  });
  return {
    invoiceMinorUnits: converted.invoiceMinorUnits,
    normalizedInvoiceAmount: converted.normalizedInvoiceAmount,
    rateNumerator: converted.rateNumerator,
    rateScale: converted.rateScale,
    normalizedRate: converted.normalizedRate,
    settlementBaseUnits: converted.settlementBaseUnits,
    settlementDisplayAmount: converted.settlementDisplayAmount,
    rounding: converted.rounding,
    roundingDeltaNumerator: converted.roundingDeltaNumerator,
    roundingDenominator: converted.roundingDenominator,
  };
}

export function createExpenseSettlementPlan(
  inputs: PendingExpenseInput[],
  now = new Date(),
  entropy: ExpensePlanEntropy = {},
): ExpenseSettlementPlan {
  requireValidDate(now, "Plan creation time");
  if (!Array.isArray(inputs) || inputs.length < 2 || inputs.length > MAX_PENDING_EXPENSES) {
    throw new Error(`Expense settlement requires 2 to ${MAX_PENDING_EXPENSES} pending invoices.`);
  }

  const createdAt = now.toISOString();
  const expenses = inputs.map((input, index) => normalizePendingExpense(input, now, index));
  if (new Set(expenses.map((expense) => expense.invoiceId)).size !== expenses.length) {
    throw new Error("Pending invoice IDs must be unique.");
  }
  assertConsistentTokenMetadata(expenses);
  const transfers = deriveAggregatedTransfers(expenses);
  if (!transfers.length || transfers.length > MAX_OPTIMIZED_TRANSFERS) {
    throw new Error(`Optimized settlement supports 1 to ${MAX_OPTIMIZED_TRANSFERS} transfer actions.`);
  }
  const tokenTotals = deriveTokenTotals(transfers);
  const optimization = deriveOptimization(expenses, transfers);
  const planId = entropy.createId?.() ?? `split_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!/^split_[A-Za-z0-9_-]{1,48}$/.test(planId)) throw new Error("Expense settlement plan ID is invalid.");

  const unsigned: Omit<ExpenseSettlementPlan, "planCommitment"> = {
    kind: PLAN_KIND,
    version: EXPENSE_SPLITTER_VERSION,
    planId,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    createdAt,
    expiresAt: expenses.reduce((earliest, expense) => Date.parse(expense.rate.expiresAt) < Date.parse(earliest) ? expense.rate.expiresAt : earliest, expenses[0].rate.expiresAt),
    expenses,
    transfers,
    tokenTotals,
    optimization,
    privacyNotice: "Invoice currencies, rate sources, vendor labels, cost centers, and invoice IDs remain client-side and are excluded from STRK20 Wallet API transfer actions.",
    executionNotice: "One connected privacy-enabled treasury wallet submits this batch. Independent wallets cannot pool separate spending keys into one Wallet API request.",
  };
  const plan = { ...unsigned, planCommitment: toHex(computePlanCommitment(unsigned)) };
  validateExpenseSettlementPlan(plan);
  return plan;
}

export function verifyExpenseSettlementPlan(plan: ExpenseSettlementPlan): boolean {
  try {
    validateExpenseSettlementPlan(plan);
    return true;
  } catch {
    return false;
  }
}

export function assertExpenseSettlementActive(plan: ExpenseSettlementPlan, now = new Date()): void {
  if (!verifyExpenseSettlementPlan(plan)) throw new Error("Expense settlement plan is invalid or altered.");
  requireValidDate(now, "Settlement time");
  if (now.getTime() > Date.parse(plan.expiresAt)) throw new Error("One or more locked exchange rates have expired. Rebuild the batch before settlement.");
}

/**
 * Constructs the exact STRK20 Wallet API action array. Calling
 * account.strk20InvokeTransaction(actions) submits every transfer in one
 * private wallet request; this is not public account.execute calldata.
 */
export function buildOptimizedExpenseCalldata(plan: ExpenseSettlementPlan, now = new Date()): STRK20_ACTION[] {
  assertExpenseSettlementActive(plan, now);
  return plan.transfers.map((transfer) => ({
    type: "transfer",
    token: transfer.tokenAddress,
    amount: transfer.amountBaseUnits,
    recipient: transfer.recipientAddress,
  }));
}

export function estimateExpenseBatchSavings(
  plan: ExpenseSettlementPlan,
  poolFeePerInvocationBaseUnits: string,
): ExpenseFeeSavingsEstimate {
  if (!verifyExpenseSettlementPlan(plan)) throw new Error("Expense settlement plan is invalid or altered.");
  const poolFee = requireUnsignedInteger(poolFeePerInvocationBaseUnits, "Pool fee");
  const walletInvocationsAvoided = plan.expenses.length - 1;
  return {
    poolFeePerInvocationBaseUnits: poolFee.toString(),
    individualWalletInvocations: plan.expenses.length,
    batchedWalletInvocations: 1,
    walletInvocationsAvoided,
    estimatedPoolFeeSavingsBaseUnits: (poolFee * BigInt(walletInvocationsAvoided)).toString(),
    transferActionsEliminated: plan.optimization.duplicateTransfersMerged,
    notice: "Estimate assumes the current pool fee is charged once per wallet invocation. Proving cost and protocol fee policy can change; verify the wallet preview before signing.",
  };
}

export function getExpenseVisibilityModel(plan: ExpenseSettlementPlan): ExpenseVisibilityModel {
  if (!verifyExpenseSettlementPlan(plan)) throw new Error("Expense settlement plan is invalid or altered.");
  return {
    applicationOnly: ["invoice IDs", "vendor labels", "cost centers", "source currencies and totals", "exchange rates and quote sources"],
    walletRequest: ["settlement token addresses", "registered recipients", "exact base-unit transfer amounts", `${plan.transfers.length} transfer actions`],
    hiddenInPool: ["payer", "recipients", "tokens", "amounts", "spent-note linkage"],
    publicOrObservable: ["transaction timing", "relayer-submitted pool transaction", "fees", "published unlinkable nullifiers", "separate deposit and withdrawal edges"],
    limitation: "The connected wallet and this client can see the requested transfers. Distinctive timing or amounts can reduce the anonymity set, and every recipient must already be registered with STRK20.",
  };
}

function normalizePendingExpense(input: PendingExpenseInput, now: Date, index: number): ConvertedPendingExpense {
  if (!input || typeof input !== "object") throw new Error(`Pending expense ${index + 1} is invalid.`);
  const invoiceCurrency = requireFiatCurrency(input.invoiceCurrency);
  const settlementAsset = {
    tokenAddress: normalizeStarknetAddress(input.settlementAsset?.tokenAddress),
    symbol: requireText(input.settlementAsset?.symbol, "Settlement token symbol", 12, /^[A-Za-z0-9._-]+$/).toUpperCase(),
    decimals: requireTokenDecimals(input.settlementAsset?.decimals),
  };
  const quotedAt = requireIsoTimestamp(input.rate?.quotedAt, "Rate observation time");
  const expiresAt = requireIsoTimestamp(input.rate?.expiresAt, "Rate expiry time");
  if (Date.parse(quotedAt) > now.getTime() + 5 * 60 * 1_000) throw new Error("Rate observation time cannot be in the future.");
  if (Date.parse(expiresAt) <= now.getTime() || Date.parse(expiresAt) <= Date.parse(quotedAt) || Date.parse(expiresAt) - now.getTime() > MAX_EXPENSE_QUOTE_LIFETIME_MS) {
    throw new Error("Every rate expiry must be in the future, after its observation, and within seven days.");
  }
  const conversion = calculateExactExpenseConversion({
    invoiceCurrency,
    invoiceAmount: input.invoiceAmount,
    settlementDecimals: settlementAsset.decimals,
    rate: input.rate.rate,
  });
  return {
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    vendorLabel: requireText(input.vendorLabel, "Vendor label", 80),
    costCenter: requireText(input.costCenter, "Cost center", 64),
    recipientAddress: normalizeStarknetAddress(input.recipientAddress),
    invoiceCurrency,
    settlementAsset,
    rate: {
      source: requireText(input.rate.source, "Rate source", 96),
      quotedAt,
      expiresAt,
      direction: `1 ${invoiceCurrency} = ${conversion.normalizedRate} ${settlementAsset.symbol}`,
    },
    conversion,
  };
}

function deriveAggregatedTransfers(expenses: ConvertedPendingExpense[]): AggregatedExpenseTransfer[] {
  const grouped = new Map<string, AggregatedExpenseTransfer>();
  for (const expense of expenses) {
    const key = `${BigInt(expense.settlementAsset.tokenAddress).toString(16)}:${BigInt(expense.recipientAddress).toString(16)}`;
    const existing = grouped.get(key);
    const amount = BigInt(expense.conversion.settlementBaseUnits);
    if (existing) {
      const total = BigInt(existing.amountBaseUnits) + amount;
      requireU128(total, "Aggregated private transfer");
      existing.amountBaseUnits = total.toString();
      existing.displayAmount = formatTokenAmount(total, existing.tokenDecimals);
      existing.invoiceIds.push(expense.invoiceId);
      continue;
    }
    grouped.set(key, {
      transferId: `transfer_${toHex(hash.computePoseidonHash(expense.settlementAsset.tokenAddress, expense.recipientAddress)).slice(2, 18)}`,
      tokenAddress: expense.settlementAsset.tokenAddress,
      tokenSymbol: expense.settlementAsset.symbol,
      tokenDecimals: expense.settlementAsset.decimals,
      recipientAddress: expense.recipientAddress,
      amountBaseUnits: amount.toString(),
      displayAmount: formatTokenAmount(amount, expense.settlementAsset.decimals),
      invoiceIds: [expense.invoiceId],
    });
  }
  return [...grouped.values()]
    .map((transfer) => ({ ...transfer, invoiceIds: [...transfer.invoiceIds].sort() }))
    .sort((left, right) => compareFelts(left.tokenAddress, right.tokenAddress) || compareFelts(left.recipientAddress, right.recipientAddress));
}

function deriveTokenTotals(transfers: AggregatedExpenseTransfer[]): ExpenseTokenTotal[] {
  const totals = new Map<string, ExpenseTokenTotal>();
  for (const transfer of transfers) {
    const key = BigInt(transfer.tokenAddress).toString(16);
    const current = totals.get(key);
    if (current) {
      const amount = BigInt(current.amountBaseUnits) + BigInt(transfer.amountBaseUnits);
      current.amountBaseUnits = amount.toString();
      current.displayAmount = formatTokenAmount(amount, current.decimals);
      current.transferCount += 1;
    } else {
      totals.set(key, {
        tokenAddress: transfer.tokenAddress,
        symbol: transfer.tokenSymbol,
        decimals: transfer.tokenDecimals,
        amountBaseUnits: transfer.amountBaseUnits,
        displayAmount: transfer.displayAmount,
        transferCount: 1,
      });
    }
  }
  return [...totals.values()].sort((left, right) => compareFelts(left.tokenAddress, right.tokenAddress));
}

function deriveOptimization(expenses: ConvertedPendingExpense[], transfers: AggregatedExpenseTransfer[]): ExpenseOptimizationSummary {
  return {
    pendingInvoiceCount: expenses.length,
    optimizedTransferCount: transfers.length,
    duplicateTransfersMerged: expenses.length - transfers.length,
    walletRequestsAvoided: expenses.length - 1,
  };
}

function validateExpenseSettlementPlan(value: unknown): asserts value is ExpenseSettlementPlan {
  assertExactKeys(value, ["kind", "version", "planId", "network", "poolAddress", "createdAt", "expiresAt", "expenses", "transfers", "tokenTotals", "optimization", "planCommitment", "privacyNotice", "executionNotice"], "Expense settlement plan");
  const plan = value as unknown as ExpenseSettlementPlan;
  if (plan.kind !== PLAN_KIND || plan.version !== EXPENSE_SPLITTER_VERSION || plan.network !== MAINNET_CHAIN_ID || plan.poolAddress !== STRK20_POOL_ADDRESS || !/^split_[A-Za-z0-9_-]{1,48}$/.test(plan.planId)) throw new Error("Expense settlement plan header is invalid.");
  const createdAt = requireIsoTimestamp(plan.createdAt, "Plan creation time");
  const expiresAt = requireIsoTimestamp(plan.expiresAt, "Plan expiry time");
  if (Date.parse(expiresAt) <= Date.parse(createdAt) || Date.parse(expiresAt) - Date.parse(createdAt) > MAX_EXPENSE_QUOTE_LIFETIME_MS) throw new Error("Expense settlement plan expiry is invalid.");
  if (!Array.isArray(plan.expenses) || plan.expenses.length < 2 || plan.expenses.length > MAX_PENDING_EXPENSES) throw new Error("Expense settlement invoice count is invalid.");
  const validatedExpenses = plan.expenses.map((expense, index) => validateConvertedExpense(expense, new Date(createdAt), index));
  if (new Set(validatedExpenses.map((expense) => expense.invoiceId)).size !== validatedExpenses.length) throw new Error("Pending invoice IDs must be unique.");
  assertConsistentTokenMetadata(validatedExpenses);
  const expectedTransfers = deriveAggregatedTransfers(validatedExpenses);
  const expectedTotals = deriveTokenTotals(expectedTransfers);
  const expectedOptimization = deriveOptimization(validatedExpenses, expectedTransfers);
  if (JSON.stringify(plan.transfers) !== JSON.stringify(expectedTransfers) || JSON.stringify(plan.tokenTotals) !== JSON.stringify(expectedTotals) || JSON.stringify(plan.optimization) !== JSON.stringify(expectedOptimization)) throw new Error("Expense settlement aggregation does not conserve the invoice ledger.");
  if (plan.expiresAt !== validatedExpenses.reduce((earliest, expense) => Date.parse(expense.rate.expiresAt) < Date.parse(earliest) ? expense.rate.expiresAt : earliest, validatedExpenses[0].rate.expiresAt)) throw new Error("Expense settlement expiry does not match its rate locks.");
  if (typeof plan.privacyNotice !== "string" || !plan.privacyNotice.includes("excluded from STRK20")) throw new Error("Expense settlement privacy notice is invalid.");
  if (typeof plan.executionNotice !== "string" || !plan.executionNotice.includes("One connected")) throw new Error("Expense settlement execution notice is invalid.");
  requireFelt(plan.planCommitment, "Plan commitment");
  if (BigInt(plan.planCommitment) !== computePlanCommitment(plan)) throw new Error("Expense settlement plan commitment does not match.");
}

function validateConvertedExpense(value: unknown, createdAt: Date, index: number): ConvertedPendingExpense {
  assertExactKeys(value, ["invoiceId", "vendorLabel", "costCenter", "recipientAddress", "invoiceCurrency", "settlementAsset", "rate", "conversion"], `Expense ${index + 1}`);
  const expense = value as unknown as ConvertedPendingExpense;
  assertExactKeys(expense.settlementAsset, ["tokenAddress", "symbol", "decimals"], "Settlement asset");
  assertExactKeys(expense.rate, ["source", "quotedAt", "expiresAt", "direction"], "Expense rate");
  assertExactKeys(expense.conversion, ["invoiceMinorUnits", "normalizedInvoiceAmount", "rateNumerator", "rateScale", "normalizedRate", "settlementBaseUnits", "settlementDisplayAmount", "rounding", "roundingDeltaNumerator", "roundingDenominator"], "Expense conversion");
  const reconstructed = normalizePendingExpense({
    invoiceId: expense.invoiceId,
    vendorLabel: expense.vendorLabel,
    costCenter: expense.costCenter,
    recipientAddress: expense.recipientAddress,
    invoiceCurrency: expense.invoiceCurrency,
    invoiceAmount: expense.conversion.normalizedInvoiceAmount,
    settlementAsset: expense.settlementAsset,
    rate: {
      rate: expense.conversion.normalizedRate,
      source: expense.rate.source,
      quotedAt: expense.rate.quotedAt,
      expiresAt: expense.rate.expiresAt,
    },
  }, createdAt, index);
  if (JSON.stringify(reconstructed) !== JSON.stringify(expense)) throw new Error(`Expense ${index + 1} conversion or metadata is inconsistent.`);
  return reconstructed;
}

function assertConsistentTokenMetadata(expenses: ConvertedPendingExpense[]): void {
  const assets = new Map<string, string>();
  for (const expense of expenses) {
    const key = BigInt(expense.settlementAsset.tokenAddress).toString(16);
    const metadata = `${expense.settlementAsset.symbol}:${expense.settlementAsset.decimals}`;
    if (assets.has(key) && assets.get(key) !== metadata) throw new Error("The same settlement token address has conflicting symbol or decimal metadata.");
    assets.set(key, metadata);
  }
}

function computePlanCommitment(plan: Omit<ExpenseSettlementPlan, "planCommitment"> | ExpenseSettlementPlan): bigint {
  return BigInt(hash.computePoseidonHashOnElements([
    PLAN_DOMAIN,
    BigInt(EXPENSE_SPLITTER_VERSION),
    hash.starknetKeccak(plan.planId),
    BigInt(Math.floor(Date.parse(plan.createdAt) / 1_000)),
    BigInt(Math.floor(Date.parse(plan.expiresAt) / 1_000)),
    BigInt(plan.expenses.length),
    ...plan.expenses.map((expense) => BigInt(hash.computePoseidonHashOnElements([
      EXPENSE_DOMAIN,
      hash.starknetKeccak(expense.invoiceId),
      hash.starknetKeccak(expense.vendorLabel),
      hash.starknetKeccak(expense.costCenter),
      hash.starknetKeccak(expense.invoiceCurrency),
      BigInt(expense.conversion.invoiceMinorUnits),
      BigInt(expense.recipientAddress),
      BigInt(expense.settlementAsset.tokenAddress),
      hash.starknetKeccak(expense.settlementAsset.symbol),
      BigInt(expense.settlementAsset.decimals),
      BigInt(expense.conversion.rateNumerator),
      BigInt(expense.conversion.rateScale),
      BigInt(expense.conversion.settlementBaseUnits),
      hash.starknetKeccak(expense.rate.source),
      BigInt(Math.floor(Date.parse(expense.rate.quotedAt) / 1_000)),
      BigInt(Math.floor(Date.parse(expense.rate.expiresAt) / 1_000)),
    ]))),
    BigInt(plan.transfers.length),
    ...plan.transfers.flatMap((transfer) => [BigInt(transfer.tokenAddress), BigInt(transfer.recipientAddress), BigInt(transfer.amountBaseUnits)]),
    BigInt(STRK20_POOL_ADDRESS),
  ]));
}

function assertExactKeys(value: unknown, allowed: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  const keys = Object.keys(value);
  if (keys.length !== allowed.length || keys.some((key) => !allowed.includes(key))) throw new Error(`${label} contains unsupported or missing fields.`);
}

function requireFiatCurrency(currency: FiatCurrency): FiatCurrency {
  if (!FIAT_CURRENCIES[currency]) throw new Error("Unsupported invoice currency.");
  return currency;
}

function requireTokenDecimals(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 18) throw new Error("Settlement token decimals must be an integer from 0 to 18.");
  return value;
}

function requireText(value: unknown, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireValidDate(value: Date, label: string): void {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} is invalid.`);
}

function requireUnsignedInteger(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^(?:0x[0-9a-f]+|\d+)$/i.test(value)) throw new Error(`${label} must be a decimal or 0x-hex unsigned base-unit integer.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value <= 0n || value > U128_MAX) throw new Error(`${label} must fit a positive u128 amount.`);
  return value;
}

function requireFelt(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error(`${label} is not a felt.`);
  return BigInt(value);
}

function compareFelts(left: string, right: string): number {
  const first = BigInt(left);
  const second = BigInt(right);
  return first < second ? -1 : first > second ? 1 : 0;
}

function formatTokenAmount(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Token amount cannot be negative.");
  if (decimals === 0) return value.toString();
  const padded = value.toString().padStart(decimals + 1, "0");
  const whole = padded.slice(0, -decimals);
  const fraction = padded.slice(-decimals).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

function toHex(value: string | bigint): string {
  return `0x${BigInt(value).toString(16)}`;
}
