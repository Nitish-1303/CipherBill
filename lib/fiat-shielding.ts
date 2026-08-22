import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const FIAT_SHIELDING_VERSION = 1 as const;
export const FIAT_SHIELDING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const MAX_RATE_DECIMALS = 18;
export const MAX_SETTLEMENT_TOKEN_DECIMALS = 18;
export const MAX_SHIELD_BUFFER_BPS = 5_000;

export const FIAT_CURRENCIES = {
  USD: { name: "US Dollar", symbol: "$", minorUnits: 2 },
  EUR: { name: "Euro", symbol: "€", minorUnits: 2 },
  GBP: { name: "Pound Sterling", symbol: "£", minorUnits: 2 },
  INR: { name: "Indian Rupee", symbol: "₹", minorUnits: 2 },
  JPY: { name: "Japanese Yen", symbol: "¥", minorUnits: 0 },
  SGD: { name: "Singapore Dollar", symbol: "S$", minorUnits: 2 },
  AED: { name: "UAE Dirham", symbol: "د.إ", minorUnits: 2 },
  CAD: { name: "Canadian Dollar", symbol: "C$", minorUnits: 2 },
  AUD: { name: "Australian Dollar", symbol: "A$", minorUnits: 2 },
  CHF: { name: "Swiss Franc", symbol: "CHF", minorUnits: 2 },
  BRL: { name: "Brazilian Real", symbol: "R$", minorUnits: 2 },
  MXN: { name: "Mexican Peso", symbol: "MX$", minorUnits: 2 },
} as const;

export type FiatCurrency = keyof typeof FIAT_CURRENCIES;

const PLAN_KIND = "cipherbill.fiat-shielding-plan" as const;
const ENVELOPE_KIND = "cipherbill.fiat-shielding.encrypted" as const;
const ENCRYPTION_ALGORITHM = "AES-GCM-256" as const;
const U128_MAX = (1n << 128n) - 1n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const PLAN_DOMAIN = hash.starknetKeccak("CipherBill fiat shielding plan v1");
const MAX_QUOTE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1_000;
const ENVELOPE_NOTICE = "Client-encrypted cross-border invoice quote. Share the access key through a separate authenticated channel; it is not a STRK20 viewing or spending key.";

export interface SettlementAssetInput {
  symbol: string;
  tokenAddress: string;
  decimals: number;
  pegCurrency: FiatCurrency;
}

export interface FiatRateLockInput {
  rate: string;
  source: string;
  asOf: string;
  expiresAt: string;
}

export interface CreateFiatShieldingPlanInput {
  invoiceId: string;
  merchantName: string;
  invoiceCurrency: FiatCurrency;
  invoiceAmount: string;
  recipientAddress: string;
  settlementAsset: SettlementAssetInput;
  rateLock: FiatRateLockInput;
  shieldBufferBps?: number;
  memo?: string;
}

export interface FiatConversionResult {
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
  shieldBufferBps: number;
  shieldBufferBaseUnits: string;
  shieldBaseUnits: string;
  shieldDisplayAmount: string;
}

export interface FiatShieldingPlan {
  kind: typeof PLAN_KIND;
  version: typeof FIAT_SHIELDING_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  merchantName: string;
  invoiceCurrency: FiatCurrency;
  recipientAddress: string;
  settlementAsset: {
    symbol: string;
    tokenAddress: string;
    decimals: number;
    pegCurrency: FiatCurrency;
  };
  rateLock: {
    source: string;
    asOf: string;
    expiresAt: string;
    direction: string;
  };
  conversion: FiatConversionResult;
  memo: string;
  createdAt: string;
  quoteCommitment: string;
  privacyNotice: string;
}

export interface EncryptedFiatShieldingPlan {
  kind: typeof ENVELOPE_KIND;
  version: typeof FIAT_SHIELDING_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  algorithm: typeof ENCRYPTION_ALGORITHM;
  iv: string;
  ciphertext: string;
  ciphertextDigest: string;
  notice: typeof ENVELOPE_NOTICE;
}

export interface EncryptedFiatShieldingBundle {
  envelope: EncryptedFiatShieldingPlan;
  accessKey: string;
}

export interface FiatVisibilityModel {
  encryptedQuote: string[];
  publicShieldEdge: string[];
  hiddenPrivatePayment: string[];
}

interface FiatShieldingEntropy {
  createId?: () => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export function calculateFiatConversion(input: {
  invoiceCurrency: FiatCurrency;
  invoiceAmount: string;
  settlementDecimals: number;
  rate: string;
  shieldBufferBps?: number;
}): FiatConversionResult {
  const currency = requireFiatCurrency(input.invoiceCurrency);
  const settlementDecimals = requireTokenDecimals(input.settlementDecimals);
  const invoiceMinorUnits = parseDecimalUnits(input.invoiceAmount, currency.minorUnits, "Invoice amount");
  const parsedRate = parsePositiveDecimal(input.rate, MAX_RATE_DECIMALS, "Exchange rate");
  const shieldBufferBps = input.shieldBufferBps ?? 500;
  if (!Number.isInteger(shieldBufferBps) || shieldBufferBps < 0 || shieldBufferBps > MAX_SHIELD_BUFFER_BPS) {
    throw new Error(`Shield buffer must be between 0 and ${MAX_SHIELD_BUFFER_BPS} basis points.`);
  }

  const numerator = invoiceMinorUnits * parsedRate.numerator * 10n ** BigInt(settlementDecimals);
  const denominator = 10n ** BigInt(currency.minorUnits) * parsedRate.scale;
  const settlementBaseUnits = divideCeil(numerator, denominator);
  requireU128(settlementBaseUnits, "Converted settlement amount");
  const roundingDeltaNumerator = settlementBaseUnits * denominator - numerator;
  const shieldBaseUnits = divideCeil(settlementBaseUnits * BigInt(10_000 + shieldBufferBps), 10_000n);
  requireU128(shieldBaseUnits, "Buffered shield amount");
  const shieldBufferBaseUnits = shieldBaseUnits - settlementBaseUnits;

  return {
    invoiceMinorUnits: invoiceMinorUnits.toString(),
    normalizedInvoiceAmount: formatBaseUnits(invoiceMinorUnits, currency.minorUnits),
    rateNumerator: parsedRate.numerator.toString(),
    rateScale: parsedRate.scale.toString(),
    normalizedRate: parsedRate.normalized,
    settlementBaseUnits: settlementBaseUnits.toString(),
    settlementDisplayAmount: formatBaseUnits(settlementBaseUnits, settlementDecimals),
    rounding: "ceil",
    roundingDeltaNumerator: roundingDeltaNumerator.toString(),
    roundingDenominator: denominator.toString(),
    shieldBufferBps,
    shieldBufferBaseUnits: shieldBufferBaseUnits.toString(),
    shieldBaseUnits: shieldBaseUnits.toString(),
    shieldDisplayAmount: formatBaseUnits(shieldBaseUnits, settlementDecimals),
  };
}

export function createFiatShieldingPlan(
  input: CreateFiatShieldingPlanInput,
  now = new Date(),
  entropy: Pick<FiatShieldingEntropy, "createId"> = {},
): FiatShieldingPlan {
  const createdAt = requireIsoTimestamp(now.toISOString(), "Plan creation time");
  const invoiceCurrency = requireFiatCurrency(input.invoiceCurrency).code;
  const pegCurrency = requireFiatCurrency(input.settlementAsset.pegCurrency).code;
  const rateAsOf = requireIsoTimestamp(input.rateLock.asOf, "Rate observation time");
  const expiresAt = requireIsoTimestamp(input.rateLock.expiresAt, "Rate expiry time");
  if (Date.parse(rateAsOf) > now.getTime() + 5 * 60 * 1_000) throw new Error("Rate observation time cannot be in the future.");
  if (Date.parse(expiresAt) <= now.getTime() || Date.parse(expiresAt) - now.getTime() > MAX_QUOTE_LIFETIME_MS) throw new Error("Rate expiry must be in the future and within 30 days.");

  const settlementAsset = {
    symbol: requireText(input.settlementAsset.symbol, "Settlement token symbol", 12, /^[A-Za-z0-9._-]+$/).toLocaleUpperCase(),
    tokenAddress: normalizeStarknetAddress(input.settlementAsset.tokenAddress),
    decimals: requireTokenDecimals(input.settlementAsset.decimals),
    pegCurrency,
  };
  const conversion = calculateFiatConversion({
    invoiceCurrency,
    invoiceAmount: input.invoiceAmount,
    settlementDecimals: settlementAsset.decimals,
    rate: input.rateLock.rate,
    shieldBufferBps: input.shieldBufferBps,
  });
  const plan: Omit<FiatShieldingPlan, "quoteCommitment"> = {
    kind: PLAN_KIND,
    version: FIAT_SHIELDING_VERSION,
    planId: entropy.createId?.() ?? `fiat_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    merchantName: requireText(input.merchantName, "Merchant name", 80),
    invoiceCurrency,
    recipientAddress: normalizeStarknetAddress(input.recipientAddress),
    settlementAsset,
    rateLock: {
      source: requireText(input.rateLock.source, "Rate source", 96),
      asOf: rateAsOf,
      expiresAt,
      direction: `1 ${invoiceCurrency} = ${conversion.normalizedRate} ${pegCurrency}`,
    },
    conversion,
    memo: requireOptionalText(input.memo ?? "", "Private memo", 160),
    createdAt,
    privacyNotice: "Invoice metadata and FX terms stay client-side and are excluded from Wallet API actions. Shield deposits remain public at the pool edge; later in-pool settlement hides sender, recipient, token, and amount.",
  };
  if (!/^fiat_[A-Za-z0-9_-]{1,48}$/.test(plan.planId)) throw new Error("Fiat shielding plan ID is invalid.");
  const completed = { ...plan, quoteCommitment: toHex(computePlanCommitment(plan)) };
  validateFiatShieldingPlan(completed);
  return completed;
}

export function verifyFiatShieldingPlan(plan: FiatShieldingPlan): boolean {
  try {
    validateFiatShieldingPlan(plan);
    return BigInt(plan.quoteCommitment) === computePlanCommitment(plan);
  } catch {
    return false;
  }
}

export function assertFiatQuoteActive(plan: FiatShieldingPlan, now = new Date()): void {
  if (!verifyFiatShieldingPlan(plan)) throw new Error("Fiat shielding plan is invalid or altered.");
  if (now.getTime() > Date.parse(plan.rateLock.expiresAt)) throw new Error("The locked exchange rate has expired.");
}

export function buildFiatShieldActions(plan: FiatShieldingPlan, now = new Date()): STRK20_ACTION[] {
  assertFiatQuoteActive(plan, now);
  return [{ type: "deposit", token: plan.settlementAsset.tokenAddress, amount: plan.conversion.shieldBaseUnits }];
}

export function buildPrivateFiatSettlementActions(plan: FiatShieldingPlan, now = new Date()): STRK20_ACTION[] {
  assertFiatQuoteActive(plan, now);
  return [{
    type: "transfer",
    token: plan.settlementAsset.tokenAddress,
    amount: plan.conversion.settlementBaseUnits,
    recipient: plan.recipientAddress,
  }];
}

export function getFiatVisibilityModel(plan: FiatShieldingPlan): FiatVisibilityModel {
  if (!verifyFiatShieldingPlan(plan)) throw new Error("Fiat shielding plan is invalid or altered.");
  return {
    encryptedQuote: ["invoice ID", "merchant", "fiat currency and total", "FX rate and source", "recipient", "private memo"],
    publicShieldEdge: ["depositor", `${plan.settlementAsset.symbol} token address`, `${plan.conversion.shieldDisplayAmount} shield amount`, "timing"],
    hiddenPrivatePayment: ["sender", "recipient", "token", "exact settlement amount", "spent-note linkage"],
  };
}

export async function encryptFiatShieldingPlan(
  plan: FiatShieldingPlan,
  entropy: Pick<FiatShieldingEntropy, "randomBytes"> = {},
): Promise<EncryptedFiatShieldingBundle> {
  if (!verifyFiatShieldingPlan(plan)) throw new Error("Fiat shielding plan is invalid or altered.");
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const keyBytes = random(new Uint8Array(32));
  const iv = random(new Uint8Array(12));
  if (keyBytes.length !== 32 || iv.length !== 12) throw new Error("Fiat quote encryption entropy returned an invalid byte length.");
  const header = encryptedHeader();
  const key = await importAesKey(keyBytes, "encrypt");
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: envelopeAssociatedData(header) },
    key,
    new TextEncoder().encode(JSON.stringify(plan)),
  ));
  return {
    envelope: {
      ...header,
      iv: toBase64Url(iv),
      ciphertext: toBase64Url(ciphertext),
      ciphertextDigest: await sha256Base64Url(ciphertext),
    },
    accessKey: toBase64Url(keyBytes),
  };
}

export async function decryptFiatShieldingPlan(envelope: EncryptedFiatShieldingPlan, accessKey: string): Promise<FiatShieldingPlan> {
  validateEncryptedEnvelope(envelope);
  const keyBytes = fromBase64Url(accessKey);
  const iv = fromBase64Url(envelope.iv);
  const ciphertext = fromBase64Url(envelope.ciphertext);
  if (keyBytes.length !== 32) throw new Error("Fiat quote access key is invalid.");
  if (iv.length !== 12) throw new Error("Fiat quote encryption nonce is invalid.");
  if (await sha256Base64Url(ciphertext) !== envelope.ciphertextDigest) throw new Error("Encrypted fiat quote digest does not match.");
  const key = await importAesKey(keyBytes, "decrypt");
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: envelopeAssociatedData(envelope) },
      key,
      ciphertext,
    );
  } catch {
    throw new Error("Fiat quote could not be decrypted. Its access key or envelope is incorrect.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new Error("Decrypted fiat quote is malformed.");
  }
  validateFiatShieldingPlan(parsed);
  return parsed;
}

export function serializeEncryptedFiatShieldingPlan(envelope: EncryptedFiatShieldingPlan): string {
  validateEncryptedEnvelope(envelope);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(envelope)));
}

export function parseEncryptedFiatShieldingPlan(encoded: string): EncryptedFiatShieldingPlan {
  const parsed = parseEncodedJson(encoded, 1_000_000, "Encrypted fiat quote");
  validateEncryptedEnvelope(parsed);
  return parsed;
}

export function formatFiatMinorUnits(value: string | bigint, currency: FiatCurrency): string {
  const info = requireFiatCurrency(currency);
  const amount = typeof value === "bigint" ? value : BigInt(value);
  if (amount < 0n) throw new Error("Fiat amount cannot be negative.");
  return formatBaseUnits(amount, info.minorUnits);
}

function validateFiatShieldingPlan(value: unknown): asserts value is FiatShieldingPlan {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Fiat shielding plan is invalid.");
  const plan = value as FiatShieldingPlan;
  const allowed = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "merchantName", "invoiceCurrency", "recipientAddress", "settlementAsset", "rateLock", "conversion", "memo", "createdAt", "quoteCommitment", "privacyNotice"];
  if (Object.keys(plan).some((key) => !allowed.includes(key)) || plan.kind !== PLAN_KIND || plan.version !== FIAT_SHIELDING_VERSION || plan.network !== MAINNET_CHAIN_ID || plan.poolAddress !== STRK20_POOL_ADDRESS || !/^fiat_[A-Za-z0-9_-]{1,48}$/.test(plan.planId)) throw new Error("Fiat shielding plan header is invalid.");
  requireText(plan.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireText(plan.merchantName, "Merchant name", 80);
  const invoiceCurrency = requireFiatCurrency(plan.invoiceCurrency).code;
  if (normalizeStarknetAddress(plan.recipientAddress) !== plan.recipientAddress) throw new Error("Fiat settlement recipient is not canonical.");
  if (!plan.settlementAsset || typeof plan.settlementAsset !== "object") throw new Error("Settlement asset is invalid.");
  const symbol = requireText(plan.settlementAsset.symbol, "Settlement token symbol", 12, /^[A-Z0-9._-]+$/);
  if (symbol !== plan.settlementAsset.symbol || normalizeStarknetAddress(plan.settlementAsset.tokenAddress) !== plan.settlementAsset.tokenAddress) throw new Error("Settlement asset is not canonical.");
  const decimals = requireTokenDecimals(plan.settlementAsset.decimals);
  const pegCurrency = requireFiatCurrency(plan.settlementAsset.pegCurrency).code;
  if (!plan.rateLock || typeof plan.rateLock !== "object") throw new Error("Rate lock is invalid.");
  requireText(plan.rateLock.source, "Rate source", 96);
  requireIsoTimestamp(plan.rateLock.asOf, "Rate observation time");
  requireIsoTimestamp(plan.rateLock.expiresAt, "Rate expiry time");
  if (plan.rateLock.direction !== `1 ${invoiceCurrency} = ${plan.conversion?.normalizedRate} ${pegCurrency}`) throw new Error("Rate direction is invalid.");
  validateConversion(plan.conversion, invoiceCurrency, decimals);
  requireOptionalText(plan.memo, "Private memo", 160);
  requireIsoTimestamp(plan.createdAt, "Plan creation time");
  if (Date.parse(plan.rateLock.expiresAt) <= Date.parse(plan.createdAt) || Date.parse(plan.rateLock.expiresAt) - Date.parse(plan.createdAt) > MAX_QUOTE_LIFETIME_MS) throw new Error("Rate expiry is invalid.");
  requireFelt(plan.quoteCommitment);
  if (typeof plan.privacyNotice !== "string" || !plan.privacyNotice.includes("Shield deposits remain public")) throw new Error("Fiat shielding privacy notice is invalid.");
  if (BigInt(plan.quoteCommitment) !== computePlanCommitment(plan)) throw new Error("Fiat shielding plan commitment does not match.");
}

function validateConversion(conversion: FiatConversionResult, invoiceCurrency: FiatCurrency, settlementDecimals: number): void {
  if (!conversion || typeof conversion !== "object" || conversion.rounding !== "ceil") throw new Error("Fiat conversion result is invalid.");
  const recalculated = calculateFiatConversion({
    invoiceCurrency,
    invoiceAmount: conversion.normalizedInvoiceAmount,
    settlementDecimals,
    rate: conversion.normalizedRate,
    shieldBufferBps: conversion.shieldBufferBps,
  });
  if (JSON.stringify(recalculated) !== JSON.stringify(conversion)) throw new Error("Fiat conversion result does not match its exact inputs.");
}

function validateEncryptedEnvelope(value: unknown): asserts value is EncryptedFiatShieldingPlan {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Encrypted fiat quote is invalid.");
  const envelope = value as EncryptedFiatShieldingPlan;
  const allowed = ["kind", "version", "network", "poolAddress", "algorithm", "iv", "ciphertext", "ciphertextDigest", "notice"];
  if (Object.keys(envelope).some((key) => !allowed.includes(key)) || envelope.kind !== ENVELOPE_KIND || envelope.version !== FIAT_SHIELDING_VERSION || envelope.network !== MAINNET_CHAIN_ID || envelope.poolAddress !== STRK20_POOL_ADDRESS || envelope.algorithm !== ENCRYPTION_ALGORITHM || envelope.notice !== ENVELOPE_NOTICE) throw new Error("Encrypted fiat quote header is invalid.");
  for (const encoded of [envelope.iv, envelope.ciphertext, envelope.ciphertextDigest]) {
    if (typeof encoded !== "string" || !encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error("Encrypted fiat quote encoding is invalid.");
  }
}

function computePlanCommitment(plan: Omit<FiatShieldingPlan, "quoteCommitment"> | FiatShieldingPlan): bigint {
  return hashElements([
    PLAN_DOMAIN,
    hash.starknetKeccak(plan.planId),
    hash.starknetKeccak(plan.invoiceId),
    hash.starknetKeccak(plan.merchantName),
    hash.starknetKeccak(plan.invoiceCurrency),
    BigInt(plan.recipientAddress),
    hash.starknetKeccak(plan.settlementAsset.symbol),
    BigInt(plan.settlementAsset.tokenAddress),
    BigInt(plan.settlementAsset.decimals),
    hash.starknetKeccak(plan.settlementAsset.pegCurrency),
    BigInt(plan.conversion.invoiceMinorUnits),
    BigInt(plan.conversion.rateNumerator),
    BigInt(plan.conversion.rateScale),
    BigInt(plan.conversion.settlementBaseUnits),
    BigInt(plan.conversion.shieldBufferBps),
    BigInt(plan.conversion.shieldBaseUnits),
    hash.starknetKeccak(plan.rateLock.source),
    BigInt(Math.floor(Date.parse(plan.rateLock.asOf) / 1_000)),
    BigInt(Math.floor(Date.parse(plan.rateLock.expiresAt) / 1_000)),
    hash.starknetKeccak(plan.memo || "empty"),
    BigInt(STRK20_POOL_ADDRESS),
  ]);
}

function encryptedHeader(): Pick<EncryptedFiatShieldingPlan, "kind" | "version" | "network" | "poolAddress" | "algorithm" | "notice"> {
  return {
    kind: ENVELOPE_KIND,
    version: FIAT_SHIELDING_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    algorithm: ENCRYPTION_ALGORITHM,
    notice: ENVELOPE_NOTICE,
  };
}

function envelopeAssociatedData(envelope: Pick<EncryptedFiatShieldingPlan, "kind" | "version" | "network" | "poolAddress" | "algorithm" | "notice">): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify(encryptedHeaderFrom(envelope)));
}

function encryptedHeaderFrom(envelope: Pick<EncryptedFiatShieldingPlan, "kind" | "version" | "network" | "poolAddress" | "algorithm" | "notice">) {
  return { kind: envelope.kind, version: envelope.version, network: envelope.network, poolAddress: envelope.poolAddress, algorithm: envelope.algorithm, notice: envelope.notice };
}

async function importAesKey(bytes: Uint8Array<ArrayBuffer>, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, [usage]);
}

function requireFiatCurrency(currency: FiatCurrency) {
  const info = FIAT_CURRENCIES[currency];
  if (!info) throw new Error("Unsupported invoice or peg currency.");
  return { ...info, code: currency };
}

function requireTokenDecimals(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > MAX_SETTLEMENT_TOKEN_DECIMALS) throw new Error(`Settlement token decimals must be between 0 and ${MAX_SETTLEMENT_TOKEN_DECIMALS}.`);
  return value;
}

function parseDecimalUnits(value: string, decimals: number, label: string): bigint {
  const parsed = parsePositiveDecimal(value, decimals, label);
  const units = parsed.numerator * 10n ** BigInt(decimals) / parsed.scale;
  if (units <= 0n) throw new Error(`${label} must be positive.`);
  return units;
}

function parsePositiveDecimal(value: string, maxDecimals: number, label: string): { numerator: bigint; scale: bigint; normalized: string } {
  if (typeof value !== "string" || value.length > 80 || !/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)) throw new Error(`${label} must be a positive decimal.`);
  const [whole, rawFraction = ""] = value.split(".");
  if (rawFraction.length > maxDecimals) throw new Error(`${label} supports at most ${maxDecimals} decimal places.`);
  const fraction = rawFraction.replace(/0+$/, "");
  const scale = 10n ** BigInt(fraction.length);
  const numerator = BigInt(`${whole}${fraction}` || "0");
  if (numerator <= 0n) throw new Error(`${label} must be positive.`);
  const normalized = fraction ? `${BigInt(whole).toString()}.${fraction}` : BigInt(whole).toString();
  return { numerator, scale, normalized };
}

function divideCeil(numerator: bigint, denominator: bigint): bigint {
  if (numerator < 0n || denominator <= 0n) throw new Error("Exact division inputs are invalid.");
  return (numerator + denominator - 1n) / denominator;
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Amount cannot be negative.");
  if (decimals === 0) return value.toString();
  const padded = value.toString().padStart(decimals + 1, "0");
  const whole = padded.slice(0, -decimals);
  const fraction = padded.slice(-decimals).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

function requireU128(value: bigint, label: string): bigint {
  if (value <= 0n || value > U128_MAX) throw new Error(`${label} is outside the STRK20 u128 range.`);
  return value;
}

function requireText(value: string, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireOptionalText(value: string, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const normalized = value.normalize("NFKC").trim();
  if (normalized.length > maxLength) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireFelt(value: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Fiat quote value is not a felt.");
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("Fiat quote felt is outside the Stark field.");
  return parsed;
}

function hashElements(values: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function parseEncodedJson(encoded: string, maxLength: number, label: string): unknown {
  if (typeof encoded !== "string" || !encoded || encoded.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} encoding is invalid.`);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded)));
  } catch {
    throw new Error(`${label} could not be decoded.`);
  }
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

async function sha256Base64Url(value: Uint8Array<ArrayBuffer>): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", value)));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url value.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
