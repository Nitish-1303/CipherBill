/**
 * Recurring invoice billing and subscription-cycle planner for CipherBill.
 *
 * WHAT THIS IS
 * - A client-side billing schedule: a merchant sets a total invoice value, a number of cycles, and a
 *   cadence, and this engine splits the total into exact-integer installments (each floored, the last
 *   cycle taking the remainder so every base unit is conserved) and computes each cycle's due date.
 * - A per-cycle draw builder: for a given cycle it composes a single private in-pool STRK20 `transfer`
 *   action moving that installment from the customer to the merchant, which the customer's wallet must
 *   sign at send time. Nothing is drawn on a schedule.
 * - A salted Poseidon commitment scheme for selective disclosure: the merchant commits to the plan
 *   (merchant, amount, cadence, cycle count), publishes a digest that carries no amount, address, payer,
 *   or memo, and later discloses the full plan to the customer, who verifies it against the digest.
 * - Disclosable cycle receipts: a per-cycle attestation binding the plan commitment, the cycle, its
 *   amount, a claimed settlement time, and the settlement transaction hash.
 * - An optional Schnorr zero-knowledge proof of knowledge — the "mandate authorization" — by which the
 *   customer proves, per cycle, knowledge of a private mandate key bound to that cycle without revealing
 *   it. This is the ONLY zero-knowledge element here; it authorizes, it does not pay.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not automated, and it draws nothing. STRK20 has no standing mandate, pull-payment, direct-debit, or
 *   scheduled-transaction primitive. Every cycle is a fresh transfer the customer must voluntarily sign
 *   at send time; a self-custody privacy pool cannot debit an account on a cadence.
 * - Not decentralized. The schedule, cadence, amounts, and cycle states are local computations in one
 *   browser. There is no on-chain billing registry, subscription contract, or keeper watching the clock.
 *   `STRK20_POOL_ADDRESS` is recorded as provenance for the draw legs, not as a contract that bills anyone.
 * - Not zero-knowledge as a system, and it proves no payment. CipherBill generates no proof that a cycle
 *   was paid: the wallet proves each `transfer` and the pool verifies it, and
 *   `wallet_strk20InvokeTransaction` returns only `{ transaction_hash }`. The plan commitment and cycle
 *   receipts are salted Poseidon hashes, not zero-knowledge proofs. Only the optional mandate
 *   authorization is a zero-knowledge proof, and it proves knowledge of a key, never a settlement.
 * - Not escrow, and not a binding subscription. Nothing holds the customer's funds and nothing obliges
 *   them to pay the next cycle; they can stop signing at any time and the merchant cannot force a draw.
 * - Not anonymous end to end. In-pool transfers hide sender, recipient, token, and amount, but a regular
 *   cadence of similar-sized draws to the same merchant is itself a correlation signal, and timing,
 *   fees, nullifiers, and any deposit or withdrawal edge stay public.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const RECURRING_ENGINE_VERSION = 1 as const;
export const RECURRING_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const RECURRING_MANDATE_PROOF_SYSTEM = "stark-schnorr-mandate-v1" as const;
export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;
export const MAX_ASSET_DECIMALS = 18;
export const MIN_CYCLES = 1;
export const MAX_CYCLES = 60; // five years of monthly draws, the longest the UI offers
export const MIN_CADENCE_DAYS = 1;
export const MAX_CADENCE_DAYS = 365;
export const MAX_GRACE_DAYS = 90;
export const MIN_REMINDERS = 1;
export const MAX_REMINDERS = 8;
export const RECURRING_SALT_BYTES = 31;

const PLAN_KIND = "cipherbill.recurring-plan" as const;
const PLAN_DIGEST_KIND = "cipherbill.recurring-plan-digest" as const;
const RECEIPT_KIND = "cipherbill.recurring-receipt" as const;

const PLAN_DOMAIN = hash.starknetKeccak("CipherBill recurring plan v1");
const RECEIPT_DOMAIN = hash.starknetKeccak("CipherBill recurring receipt v1");
const MANDATE_DOMAIN = hash.starknetKeccak("CipherBill recurring mandate authorization v1");
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 200_000;

const RECURRING_NOTICE = "Client-side recurring-billing schedule and per-cycle draw plan. Each cycle is a private in-pool STRK20 transfer that the customer must voluntarily sign at send time; the schedule, amounts, and cycle states are computation held in one browser. Nothing is drawn automatically, no contract bills anyone or holds the funds, the plan commitment and receipts are salted Poseidon hashes rather than proofs, and the customer can stop paying at any time.";

const RECURRING_LIMITATIONS = [
  "Nothing here is automated. STRK20 has no standing mandate, direct-debit, or scheduled transaction; every cycle needs a fresh signature, so a draw happens only when the customer chooses to sign it.",
  "The schedule, cadence, and cycle states are local computations. The pool holds no timer and enforces no due date; a cycle can be paid early, late, or never, and 'overdue' is a UI verdict, not an on-chain state.",
  "The plan commitment and cycle receipts are salted Poseidon hashes, not zero-knowledge proofs, and no contract verifies them. Only the optional mandate authorization is a zero-knowledge proof, and it proves knowledge of a key, not that any cycle was paid.",
  "Nothing is escrowed and no subscription is binding. The customer's funds stay in their own control, and the merchant cannot force a draw or claw back a signed one.",
  "A cycle receipt records a claimed settlement; a self-issued receipt is internally consistent but is not independent proof that the transfer settled. Confirm the transaction hash on-chain.",
  "In-pool transfers hide sender, recipient, token, and amount, but a regular cadence of similar-sized draws to one merchant is itself a correlation signal. Timing, fees, and nullifiers stay public. Vary amounts and avoid rigid schedules.",
] as const;

export type BillingCycleState = "upcoming" | "due" | "overdue" | "settled";
export type BillingPlanState = "scheduled" | "active" | "in_arrears" | "completed";

/** The billed token. Every draw leg is an in-pool transfer of it, so it must be a pool token. */
export interface RecurringAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface RecurringCurvePoint {
  x: string;
  y: string;
}

export interface RecurringSchnorrProof {
  nonceCommitment: RecurringCurvePoint;
  response: string;
}
export interface CreateRecurringPlanInput {
  invoiceId: string;
  /** The payee. Every cycle's draw is an in-pool transfer to this address. */
  merchant: string;
  asset: { symbol: string; tokenAddress: string; decimals: number };
  /** Full invoice value spread across the cycles. Must be positive. */
  totalValue: string;
  /** Number of recurring draws the total is split into. */
  cycleCount: number;
  /** Days between consecutive cycle due dates. */
  cadenceDays: number;
  /** Extra buffer after a due date before a cycle reads as overdue, in days. Defaults to 0. */
  graceDays?: number;
  /** Optional local-only label for the customer. Never an address; nothing can auto-debit it. */
  payerLabel?: string;
  memo?: string;
}

export interface RecurringBillingPlan {
  kind: typeof PLAN_KIND;
  version: typeof RECURRING_ENGINE_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  merchant: string;
  asset: RecurringAsset;
  totalValueBaseUnits: string;
  totalValueDisplay: string;
  cycleCount: number;
  cadenceMs: number;
  graceMs: number;
  /** Empty string when no payer label was named. Bound only as a keccak hash in the digest. */
  payerLabel: string;
  memo: string;
  anchorAt: string;
  /** Secret plan-level blinding factor. Never publish a plan; publish its digest. */
  planSalt: string;
  planCommitment: string;
  notice: typeof RECURRING_NOTICE;
  limitations: string[];
}

/** Plan fields safe to publish: cadence and counts, no amounts, addresses, payer, or memo. */
export interface RecurringPlanDigest {
  kind: typeof PLAN_DIGEST_KIND;
  version: typeof RECURRING_ENGINE_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  assetSymbol: string;
  assetDecimals: number;
  cycleCount: number;
  cadenceMs: number;
  graceMs: number;
  hasPayer: boolean;
  anchorAt: string;
  memoHash: string;
  planCommitment: string;
  notice: typeof RECURRING_NOTICE;
  limitations: string[];
}
/** One plan disclosed against its published digest, for the customer to verify. */
export interface RecurringPlanOpening {
  planId: string;
  planCommitment: string;
  plan: RecurringBillingPlan;
}

export interface BillingCycle {
  index: number;
  dueAt: string;
  graceEndsAt: string;
  amountBaseUnits: string;
  amountDisplay: string;
}

export interface BillingCycleEvaluation {
  index: number;
  state: BillingCycleState;
  dueAt: string;
  graceEndsAt: string;
  amountBaseUnits: string;
  amountDisplay: string;
  settled: boolean;
  /** Milliseconds until the cycle is due; 0 once past it. */
  msUntilDue: number;
  /** Milliseconds until the cycle reads as overdue (due plus grace); 0 once overdue. */
  msUntilOverdue: number;
}

export interface BillingStatus {
  state: BillingPlanState;
  now: string;
  cycleCount: number;
  settledCount: number;
  remainingCount: number;
  /** Unsettled cycles whose due date has passed (due or overdue). */
  dueCount: number;
  /** Unsettled cycles past their grace window. */
  arrearsCount: number;
  /** Earliest unsettled cycle index, or 0 when every cycle is settled. */
  nextUnsettledIndex: number;
  settledValueBaseUnits: string;
  outstandingValueBaseUnits: string;
}

export interface RecurringReminder {
  kind: "cycle_nudge" | "due_notice" | "overdue_notice";
  cycleIndex: number;
  at: string;
  note: string;
}

/** A disclosable record that a cycle was settled. Not on-chain and not proof the transfer confirmed. */
export interface RecurringCycleReceipt {
  kind: typeof RECEIPT_KIND;
  version: typeof RECURRING_ENGINE_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  cycleCount: number;
  cycleIndex: number;
  dueAt: string;
  amountBaseUnits: string;
  settledAt: string;
  transactionHash: string;
  planCommitment: string;
  receiptCommitment: string;
  notice: typeof RECURRING_NOTICE;
  limitations: string[];
}
/** The customer's mandate keypair. The secret never leaves the customer; only the public key is shared. */
export interface RecurringMandate {
  mandateSecret: string;
  mandatePublicKey: RecurringCurvePoint;
}

/**
 * A per-cycle zero-knowledge proof of knowledge of the mandate secret, bound to a specific plan and
 * cycle. It authorizes a draw; it does not move funds or prove payment.
 */
export interface RecurringMandateAuthorization {
  kind: "cipherbill.recurring-mandate-authorization";
  version: typeof RECURRING_ENGINE_VERSION;
  proofSystem: typeof RECURRING_MANDATE_PROOF_SYSTEM;
  planId: string;
  planCommitment: string;
  cycleIndex: number;
  mandatePublicKey: RecurringCurvePoint;
  proof: RecurringSchnorrProof;
  notice: string;
}

export interface RecurringVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface RecurringTrustSummary {
  fundHolder: string;
  isAutomated: boolean;
  isDecentralized: boolean;
  isEscrowed: boolean;
  isOnChainMandate: boolean;
  provesPayment: boolean;
  zeroKnowledgeElement: string;
  trustedParties: string[];
  statement: string;
}

export interface RecurringEntropy {
  createId?: (kind: "plan") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

export interface RecurringMandateEntropy {
  mandateSecret?: bigint;
  nonce?: bigint;
}
/**
 * Composes a recurring-billing plan: the merchant, the full invoice value, the number of cycles and
 * their cadence, bound by a salted Poseidon commitment. Per-cycle installments are derived, not stored.
 * Share the digest from `buildRecurringPlanDigest`, never this object. Composing stores nothing on-chain
 * and moves no funds; it only computes and commits the plan in this browser.
 */
export function createRecurringPlan(
  input: CreateRecurringPlanInput,
  now = new Date(),
  entropy: RecurringEntropy = {},
): RecurringBillingPlan {
  const anchorAt = requireIsoTimestamp(now.toISOString(), "Plan anchor time");
  const asset = normalizeAsset(input.asset, "Billed asset");
  const totalValue = parseDecimalToBaseUnits(input.totalValue, asset.decimals, "Total value");
  requireU128(totalValue, "Total value");
  const cycleCount = requireCount(input.cycleCount, "Cycle count", MIN_CYCLES, MAX_CYCLES);
  const cadenceMs = requireDaysMs(input.cadenceDays, "Cadence", MIN_CADENCE_DAYS * DAY_MS, MAX_CADENCE_DAYS * DAY_MS);
  const graceMs = requireOptionalDaysMs(input.graceDays, "Grace window", 0, MAX_GRACE_DAYS * DAY_MS);
  // Validate the split conserves the total before committing to it.
  computeInstallments(totalValue, cycleCount);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<RecurringBillingPlan, "planCommitment"> = {
    kind: PLAN_KIND,
    version: RECURRING_ENGINE_VERSION,
    planId: makeId(entropy.createId?.("plan"), "rcb"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    merchant: normalizeStarknetAddress(requireText(input.merchant, "Merchant recipient", 66)),
    asset,
    totalValueBaseUnits: totalValue.toString(),
    totalValueDisplay: formatBaseUnits(totalValue, asset.decimals),
    cycleCount,
    cadenceMs,
    graceMs,
    payerLabel: requireOptionalText(input.payerLabel ?? "", "Payer label", 96),
    memo: requireOptionalText(input.memo ?? "", "Plan memo", 160),
    anchorAt,
    planSalt: toHex(randomFelt(random)),
    notice: RECURRING_NOTICE,
    limitations: [...RECURRING_LIMITATIONS],
  };
  const plan: RecurringBillingPlan = { ...draft, planCommitment: toHex(computePlanCommitment(draft)) };
  assertRecurringPlan(plan);
  return plan;
}

export function verifyRecurringPlan(plan: RecurringBillingPlan): boolean {
  try {
    assertRecurringPlan(plan);
    return true;
  } catch {
    return false;
  }
}
/**
 * Splits the total into exact-integer installments: each cycle is floored to an equal share and the
 * last cycle takes the exact remainder, so the installments sum to the total to the base unit. A total
 * smaller than the cycle count leaves early cycles at zero and loads the remainder onto the last.
 */
function computeInstallments(total: bigint, cycleCount: number): bigint[] {
  requireU128(total, "Total value");
  if (total <= 0n) throw new Error("The total value must be positive.");
  if (!Number.isInteger(cycleCount) || cycleCount < MIN_CYCLES || cycleCount > MAX_CYCLES) {
    throw new Error(`A plan must run between ${MIN_CYCLES} and ${MAX_CYCLES} cycles.`);
  }
  const base = total / BigInt(cycleCount);
  const amounts: bigint[] = new Array(cycleCount).fill(base);
  amounts[cycleCount - 1] = total - base * BigInt(cycleCount - 1);
  const sum = amounts.reduce((acc, value) => acc + value, 0n);
  if (sum !== total) throw new Error("The installment split does not conserve the total value.");
  for (const amount of amounts) requireU128(amount, "Installment");
  return amounts;
}

/** Derives the full cycle schedule: each cycle's due date, grace end, and exact installment amount. */
export function buildBillingSchedule(plan: RecurringBillingPlan): BillingCycle[] {
  assertRecurringPlan(plan);
  const amounts = computeInstallments(BigInt(plan.totalValueBaseUnits), plan.cycleCount);
  const anchorMs = Date.parse(plan.anchorAt);
  return amounts.map((amount, offset) => {
    const dueMs = anchorMs + offset * plan.cadenceMs;
    return {
      index: offset + 1,
      dueAt: new Date(dueMs).toISOString(),
      graceEndsAt: new Date(dueMs + plan.graceMs).toISOString(),
      amountBaseUnits: amount.toString(),
      amountDisplay: formatBaseUnits(amount, plan.asset.decimals),
    };
  });
}

/** Normalizes a caller-supplied list of settled cycle indices into a validated, deduplicated set. */
function settledSet(plan: RecurringBillingPlan, settledCycleIndices: number[]): Set<number> {
  if (!Array.isArray(settledCycleIndices)) throw new Error("Settled cycles must be a list of indices.");
  const set = new Set<number>();
  for (const raw of settledCycleIndices) {
    if (!Number.isInteger(raw) || raw < 1 || raw > plan.cycleCount) throw new Error("A settled cycle index is out of range.");
    set.add(raw);
  }
  return set;
}
/**
 * Evaluates one cycle against the caller-supplied settled set and clock: upcoming until its due date,
 * then due until the grace window elapses, then overdue, or settled if the caller marked it paid. This
 * is a local computation; the pool enforces no due date and freezes nothing.
 */
export function evaluateBillingCycle(
  plan: RecurringBillingPlan,
  cycleIndex: number,
  settledCycleIndices: number[],
  now = new Date(),
): BillingCycleEvaluation {
  const schedule = buildBillingSchedule(plan);
  if (!Number.isInteger(cycleIndex) || cycleIndex < 1 || cycleIndex > plan.cycleCount) throw new Error("The cycle index is out of range.");
  const set = settledSet(plan, settledCycleIndices);
  const cycle = schedule[cycleIndex - 1];
  const nowMs = Date.parse(requireIsoTimestamp(now.toISOString(), "Evaluation time"));
  const dueMs = Date.parse(cycle.dueAt);
  const graceEndMs = Date.parse(cycle.graceEndsAt);
  const settled = set.has(cycleIndex);
  const state: BillingCycleState = settled ? "settled" : nowMs < dueMs ? "upcoming" : nowMs < graceEndMs ? "due" : "overdue";
  return {
    index: cycleIndex,
    state,
    dueAt: cycle.dueAt,
    graceEndsAt: cycle.graceEndsAt,
    amountBaseUnits: cycle.amountBaseUnits,
    amountDisplay: cycle.amountDisplay,
    settled,
    msUntilDue: Math.max(0, dueMs - nowMs),
    msUntilOverdue: Math.max(0, graceEndMs - nowMs),
  };
}

/** Rolls the per-cycle evaluations into an overall billing status: settled, due, and arrears counts. */
export function evaluateBillingStatus(
  plan: RecurringBillingPlan,
  settledCycleIndices: number[],
  now = new Date(),
): BillingStatus {
  const schedule = buildBillingSchedule(plan);
  const set = settledSet(plan, settledCycleIndices);
  const nowMs = Date.parse(requireIsoTimestamp(now.toISOString(), "Evaluation time"));
  let settledCount = 0;
  let dueCount = 0;
  let arrearsCount = 0;
  let settledValue = 0n;
  let nextUnsettledIndex = 0;
  for (const cycle of schedule) {
    const dueMs = Date.parse(cycle.dueAt);
    const graceEndMs = Date.parse(cycle.graceEndsAt);
    if (set.has(cycle.index)) {
      settledCount += 1;
      settledValue += BigInt(cycle.amountBaseUnits);
      continue;
    }
    if (nextUnsettledIndex === 0) nextUnsettledIndex = cycle.index;
    if (nowMs >= dueMs) dueCount += 1;
    if (nowMs >= graceEndMs) arrearsCount += 1;
  }
  const total = BigInt(plan.totalValueBaseUnits);
  const state: BillingPlanState = settledCount === plan.cycleCount ? "completed" : arrearsCount > 0 ? "in_arrears" : dueCount > 0 ? "active" : "scheduled";
  return {
    state,
    now: new Date(nowMs).toISOString(),
    cycleCount: plan.cycleCount,
    settledCount,
    remainingCount: plan.cycleCount - settledCount,
    dueCount,
    arrearsCount,
    nextUnsettledIndex,
    settledValueBaseUnits: settledValue.toString(),
    outstandingValueBaseUnits: (total - settledValue).toString(),
  };
}
/**
 * Builds the draw for one cycle: a single private in-pool `transfer` of that cycle's installment from
 * the customer to the merchant, which the customer's wallet must sign. No relayer-fee action is added:
 * `wallet_strk20InvokeTransaction` appends its own, and a second would double-charge. A zero installment
 * (a total smaller than the cycle count) has nothing to draw and is refused.
 */
export function buildCycleDrawActions(plan: RecurringBillingPlan, cycleIndex: number): STRK20_ACTION[] {
  const schedule = buildBillingSchedule(plan);
  if (!Number.isInteger(cycleIndex) || cycleIndex < 1 || cycleIndex > plan.cycleCount) throw new Error("The cycle index is out of range.");
  const cycle = schedule[cycleIndex - 1];
  const amount = requireU128(BigInt(cycle.amountBaseUnits), "Cycle installment");
  if (amount <= 0n) throw new Error("This cycle has nothing to draw.");
  return [{ type: "transfer", token: plan.asset.tokenAddress, amount: amount.toString(), recipient: plan.merchant }];
}

/**
 * Builds a reminder schedule for one cycle: evenly spaced nudges through the cadence leading to the due
 * date, a due notice at the due date, and an overdue notice at the grace end. These are timestamps to
 * act on in this browser or an external scheduler, never autonomous events.
 */
export function buildCycleReminders(plan: RecurringBillingPlan, cycleIndex: number, reminderCount = 3): RecurringReminder[] {
  const schedule = buildBillingSchedule(plan);
  if (!Number.isInteger(cycleIndex) || cycleIndex < 1 || cycleIndex > plan.cycleCount) throw new Error("The cycle index is out of range.");
  const count = requireCount(reminderCount, "Reminder count", MIN_REMINDERS, MAX_REMINDERS);
  const cycle = schedule[cycleIndex - 1];
  const dueMs = Date.parse(cycle.dueAt);
  const graceEndMs = Date.parse(cycle.graceEndsAt);
  const windowStart = dueMs - plan.cadenceMs;
  const reminders: RecurringReminder[] = [];
  for (let index = 1; index <= count; index += 1) {
    const at = windowStart + Math.floor((plan.cadenceMs * index) / (count + 1));
    reminders.push({ kind: "cycle_nudge", cycleIndex, at: new Date(at).toISOString(), note: `Reminder ${index} of ${count}: cycle ${cycleIndex} of ${plan.cycleCount} comes due soon.` });
  }
  reminders.push({ kind: "due_notice", cycleIndex, at: new Date(dueMs).toISOString(), note: `Cycle ${cycleIndex} is now due. Sign the draw to settle it; the grace window begins.` });
  reminders.push({ kind: "overdue_notice", cycleIndex, at: new Date(graceEndMs).toISOString(), note: `Cycle ${cycleIndex} is now overdue. It stays unsettled until the customer signs the draw.` });
  return reminders;
}

/** The only plan object safe to publish. Carries the cadence and counts, no amounts or addresses. */
export function buildRecurringPlanDigest(plan: RecurringBillingPlan): RecurringPlanDigest {
  assertRecurringPlan(plan);
  return {
    kind: PLAN_DIGEST_KIND,
    version: RECURRING_ENGINE_VERSION,
    planId: plan.planId,
    network: plan.network,
    poolAddress: plan.poolAddress,
    invoiceId: plan.invoiceId,
    assetSymbol: plan.asset.symbol,
    assetDecimals: plan.asset.decimals,
    cycleCount: plan.cycleCount,
    cadenceMs: plan.cadenceMs,
    graceMs: plan.graceMs,
    hasPayer: plan.payerLabel !== "",
    anchorAt: plan.anchorAt,
    memoHash: toHex(BigInt(hash.starknetKeccak(plan.memo || "empty"))),
    planCommitment: plan.planCommitment,
    notice: RECURRING_NOTICE,
    limitations: [...RECURRING_LIMITATIONS],
  };
}
/** Discloses the full plan so the customer can check it against a published digest. */
export function openRecurringPlan(plan: RecurringBillingPlan): RecurringPlanOpening {
  assertRecurringPlan(plan);
  return { planId: plan.planId, planCommitment: plan.planCommitment, plan };
}

export function verifyRecurringPlanDisclosure(digest: RecurringPlanDigest, opening: RecurringPlanOpening): boolean {
  try {
    assertRecurringPlanDigest(digest);
    assertRecurringPlan(opening.plan);
    if (digest.planId !== opening.planId || digest.planCommitment !== opening.planCommitment) return false;
    if (digest.planCommitment !== opening.plan.planCommitment) return false;
    return digest.invoiceId === opening.plan.invoiceId
      && digest.assetSymbol === opening.plan.asset.symbol
      && digest.assetDecimals === opening.plan.asset.decimals
      && digest.cycleCount === opening.plan.cycleCount
      && digest.cadenceMs === opening.plan.cadenceMs
      && digest.graceMs === opening.plan.graceMs
      && digest.hasPayer === (opening.plan.payerLabel !== "")
      && digest.anchorAt === opening.plan.anchorAt
      && digest.memoHash === toHex(BigInt(hash.starknetKeccak(opening.plan.memo || "empty")));
  } catch {
    return false;
  }
}
/**
 * Builds a disclosable receipt that a cycle was settled. It binds the plan commitment to the cycle,
 * its exact amount and due date, a claimed settlement time, and the settlement transaction hash, and
 * refuses a settlement time before the plan's anchor. It is not on-chain and not proof the transfer
 * confirmed; confirm the transaction hash independently.
 */
export function buildCycleReceiptAttestation(
  plan: RecurringBillingPlan,
  input: { cycleIndex: number; settledAt: string; transactionHash: string },
): RecurringCycleReceipt {
  const schedule = buildBillingSchedule(plan);
  if (!Number.isInteger(input.cycleIndex) || input.cycleIndex < 1 || input.cycleIndex > plan.cycleCount) throw new Error("The cycle index is out of range.");
  const cycle = schedule[input.cycleIndex - 1];
  const settledAt = requireIsoTimestamp(input.settledAt, "Settlement time");
  if (Date.parse(settledAt) < Date.parse(plan.anchorAt)) throw new Error("The settlement time cannot be before the plan anchor.");
  const transactionHash = toHex(requireTransactionHash(input.transactionHash));
  const draft: Omit<RecurringCycleReceipt, "receiptCommitment"> = {
    kind: RECEIPT_KIND,
    version: RECURRING_ENGINE_VERSION,
    planId: plan.planId,
    network: plan.network,
    poolAddress: plan.poolAddress,
    invoiceId: plan.invoiceId,
    cycleCount: plan.cycleCount,
    cycleIndex: input.cycleIndex,
    dueAt: cycle.dueAt,
    amountBaseUnits: cycle.amountBaseUnits,
    settledAt,
    transactionHash,
    planCommitment: plan.planCommitment,
    notice: RECURRING_NOTICE,
    limitations: [...RECURRING_LIMITATIONS],
  };
  return { ...draft, receiptCommitment: toHex(computeReceiptCommitment(draft)) };
}

export function verifyCycleReceiptAttestation(receipt: RecurringCycleReceipt, plan: RecurringBillingPlan): boolean {
  try {
    assertRecurringCycleReceipt(receipt);
    assertRecurringPlan(plan);
    if (receipt.planId !== plan.planId || receipt.planCommitment !== plan.planCommitment) return false;
    if (receipt.cycleCount !== plan.cycleCount || receipt.cycleIndex < 1 || receipt.cycleIndex > plan.cycleCount) return false;
    const cycle = buildBillingSchedule(plan)[receipt.cycleIndex - 1];
    return receipt.invoiceId === plan.invoiceId && receipt.dueAt === cycle.dueAt && receipt.amountBaseUnits === cycle.amountBaseUnits;
  } catch {
    return false;
  }
}
/**
 * Registers a mandate keypair for the customer. The secret authorizes cycle draws in zero knowledge and
 * never leaves the customer; only the public key is shared with the merchant, out of band. This creates
 * no on-chain mandate and grants no ability to pull funds — every draw still needs a fresh signature.
 */
export function registerBillingMandate(entropy: RecurringMandateEntropy = {}): RecurringMandate {
  const secret = requireSecretScalar(entropy.mandateSecret ?? randomScalar(), "Mandate secret");
  return { mandateSecret: toHex(secret), mandatePublicKey: pointToFelts(multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, secret)) };
}

/**
 * Proves, in zero knowledge, knowledge of the mandate secret bound to a specific plan and cycle. This is
 * the only zero-knowledge element here: it authorizes a draw and reveals nothing about the secret, but
 * it moves no funds and proves no payment. The customer must still sign the transfer to settle the cycle.
 */
export function buildMandateAuthorization(
  plan: RecurringBillingPlan,
  cycleIndex: number,
  mandateSecret: string,
  entropy: RecurringMandateEntropy = {},
): RecurringMandateAuthorization {
  assertRecurringPlan(plan);
  if (!Number.isInteger(cycleIndex) || cycleIndex < 1 || cycleIndex > plan.cycleCount) throw new Error("The cycle index is out of range.");
  const secret = requireCurveScalar(mandateSecret, false, "Mandate secret");
  const cycle = buildBillingSchedule(plan)[cycleIndex - 1];
  const publicKey = multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, secret);
  const proof = createSchnorrProof(MANDATE_DOMAIN, secret, mandateTranscript(plan, cycleIndex, cycle), entropy.nonce);
  return {
    kind: "cipherbill.recurring-mandate-authorization",
    version: RECURRING_ENGINE_VERSION,
    proofSystem: RECURRING_MANDATE_PROOF_SYSTEM,
    planId: plan.planId,
    planCommitment: plan.planCommitment,
    cycleIndex,
    mandatePublicKey: pointToFelts(publicKey),
    proof,
    notice: "Zero-knowledge proof of knowledge of the mandate key, bound to this plan and cycle. It authorizes a draw and proves knowledge of a key, never that any cycle was paid; the customer must still sign the transfer.",
  };
}

/**
 * Verifies a mandate authorization against the plan and the mandate public key the verifier holds out of
 * band. The expected key is required: an authorization only carries a self-asserted key, so a proof is
 * meaningful only when checked against the key the merchant actually recorded for the customer.
 */
export function verifyMandateAuthorization(
  auth: RecurringMandateAuthorization,
  plan: RecurringBillingPlan,
  expectedMandatePublicKey: RecurringCurvePoint,
): boolean {
  try {
    assertMandateAuthorization(auth);
    assertRecurringPlan(plan);
    if (auth.planId !== plan.planId || auth.planCommitment !== plan.planCommitment) return false;
    if (!Number.isInteger(auth.cycleIndex) || auth.cycleIndex < 1 || auth.cycleIndex > plan.cycleCount) return false;
    const expected = pointFromFelts(expectedMandatePublicKey, "Expected mandate public key");
    const presented = pointFromFelts(auth.mandatePublicKey, "Mandate public key");
    if (!presented.equals(expected)) return false;
    const cycle = buildBillingSchedule(plan)[auth.cycleIndex - 1];
    return verifySchnorrProof(MANDATE_DOMAIN, presented, auth.proof, mandateTranscript(plan, auth.cycleIndex, cycle));
  } catch {
    return false;
  }
}
export function getRecurringVisibilityModel(plan: RecurringBillingPlan): RecurringVisibilityModel {
  assertRecurringPlan(plan);
  return {
    applicationOnly: ["invoice ID", "the total value and each cycle's installment amount", "the merchant recipient and the payer label", "the plan memo", "the plan salt", "the cadence, due dates, and which cycles are marked settled"],
    walletRequest: ["billed token address", "the exact base-unit amount of the cycle being drawn", "the in-pool merchant recipient"],
    hiddenInPool: ["in-pool sender and recipient of each cycle draw", "token and amount of each draw", "which encrypted notes were spent"],
    publicOrObservable: ["published nullifiers, unlinkable without a viewing key", "transaction timing and fees for each cycle draw"],
    limitation: "A recurring cadence of similar-sized draws to the same merchant is itself a correlation signal, even though each transfer's amount and parties are hidden inside the pool. Vary amounts and avoid a rigid schedule.",
  };
}

export function summarizeRecurringTrust(plan: RecurringBillingPlan): RecurringTrustSummary {
  assertRecurringPlan(plan);
  const symbol = plan.asset.symbol;
  const payer = plan.payerLabel || "the customer";
  return {
    fundHolder: "the customer, who keeps their funds in their own control and voluntarily signs each cycle's draw",
    isAutomated: false,
    isDecentralized: false,
    isEscrowed: false,
    isOnChainMandate: false,
    provesPayment: false,
    zeroKnowledgeElement: "Only the optional mandate authorization is a zero-knowledge proof, and it proves knowledge of a key for a cycle, never that the cycle was paid.",
    trustedParties: [`${payer} to sign each cycle's draw when it comes due`, "the merchant to bill only the agreed amount on the agreed cadence"],
    statement: `The plan would draw ${plan.totalValueDisplay} ${symbol} from ${payer} across ${plan.cycleCount} cycle${plan.cycleCount === 1 ? "" : "s"}. Nothing is automated, decentralized, or escrowed and no payment is proven: each cycle is a private in-pool transfer ${payer} must voluntarily sign, and they can stop at any time.`,
  };
}
export function serializeRecurringPlan(plan: RecurringBillingPlan): string {
  assertRecurringPlan(plan);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(plan)));
}

export function parseRecurringPlan(encoded: string): RecurringBillingPlan {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Recurring plan");
  assertRecurringPlan(parsed);
  return parsed;
}

export function serializeRecurringPlanDigest(digest: RecurringPlanDigest): string {
  assertRecurringPlanDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseRecurringPlanDigest(encoded: string): RecurringPlanDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Plan digest");
  assertRecurringPlanDigest(parsed);
  return parsed;
}

export function serializeRecurringCycleReceipt(receipt: RecurringCycleReceipt): string {
  assertRecurringCycleReceipt(receipt);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(receipt)));
}

export function parseRecurringCycleReceipt(encoded: string): RecurringCycleReceipt {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Cycle receipt");
  assertRecurringCycleReceipt(parsed);
  return parsed;
}

export function formatRecurringBaseUnits(value: string | bigint, decimals: number): string {
  const amount = typeof value === "bigint" ? value : BigInt(value);
  return formatBaseUnits(amount, requireDecimals(decimals, "Asset decimals"));
}
function makeId(provided: string | undefined, prefix: string): string {
  const id = provided ?? `${prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  if (!new RegExp(`^${prefix}_[A-Za-z0-9_-]{1,48}$`).test(id)) throw new Error(`A ${prefix} identifier is invalid.`);
  return id;
}

function secondsOf(iso: string): bigint {
  return BigInt(Math.floor(Date.parse(iso) / 1_000));
}

/** Draws a non-zero field element from the injected entropy source. */
function randomFelt(random: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>): bigint {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const bytes = random(new Uint8Array(RECURRING_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== RECURRING_SALT_BYTES) throw new Error("The entropy source returned the wrong number of bytes.");
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n && value < FIELD_PRIME) return value;
  }
  throw new Error("Could not draw a usable salt.");
}

function hashElements(values: bigint[]): bigint {
  for (const value of values) {
    if (value < 0n || value >= FIELD_PRIME) throw new Error("A commitment input is outside the STARK field.");
  }
  return BigInt(hash.computePoseidonHashOnElements(values));
}
function computePlanCommitment(p: Omit<RecurringBillingPlan, "planCommitment">): bigint {
  return hashElements([
    PLAN_DOMAIN,
    BigInt(p.version),
    requireFelt(p.planSalt, "Plan salt"),
    BigInt(hash.starknetKeccak(p.planId)),
    BigInt(hash.starknetKeccak(p.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    BigInt(hash.starknetKeccak(p.asset.symbol)),
    BigInt(p.asset.tokenAddress),
    BigInt(p.asset.decimals),
    BigInt(p.merchant),
    BigInt(p.totalValueBaseUnits),
    BigInt(p.cycleCount),
    BigInt(p.cadenceMs),
    BigInt(p.graceMs),
    BigInt(hash.starknetKeccak(p.payerLabel || "none")),
    BigInt(hash.starknetKeccak(p.memo || "empty")),
    secondsOf(p.anchorAt),
  ]);
}

function computeReceiptCommitment(r: Omit<RecurringCycleReceipt, "receiptCommitment">): bigint {
  return hashElements([
    RECEIPT_DOMAIN,
    BigInt(r.version),
    BigInt(hash.starknetKeccak(r.planId)),
    BigInt(hash.starknetKeccak(r.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    requireFelt(r.planCommitment, "Plan commitment"),
    BigInt(r.cycleCount),
    BigInt(r.cycleIndex),
    secondsOf(r.dueAt),
    BigInt(r.amountBaseUnits),
    secondsOf(r.settledAt),
    requireFelt(r.transactionHash, "Settlement transaction hash"),
  ]);
}

/** The transcript the mandate proof is bound to: the plan commitment, the cycle, its amount and due date. */
function mandateTranscript(plan: RecurringBillingPlan, cycleIndex: number, cycle: BillingCycle): bigint[] {
  return [requireFelt(plan.planCommitment, "Plan commitment"), BigInt(cycleIndex), BigInt(cycle.amountBaseUnits), secondsOf(cycle.dueAt)];
}
type CurvePoint = ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>;

function createSchnorrProof(domain: bigint, secret: bigint, transcript: bigint[], suppliedNonce?: bigint): RecurringSchnorrProof {
  const nonce = requireSecretScalar(suppliedNonce ?? randomScalar(), "Schnorr nonce");
  const publicKey = multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, secret);
  const noncePoint = multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, nonce);
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return { nonceCommitment: pointToFelts(noncePoint), response: toHex(mod(nonce + challenge * secret, CURVE_ORDER)) };
}

function verifySchnorrProof(domain: bigint, publicKey: CurvePoint, proof: RecurringSchnorrProof, transcript: bigint[]): boolean {
  const noncePoint = pointFromFelts(proof.nonceCommitment, "Schnorr nonce commitment");
  const response = requireCurveScalar(proof.response, true, "Schnorr response");
  const challenge = schnorrChallenge(domain, publicKey, noncePoint, transcript);
  return multiplyPoint(ec.starkCurve.ProjectivePoint.BASE, response).equals(noncePoint.add(multiplyPoint(publicKey, challenge)));
}

function schnorrChallenge(domain: bigint, publicKey: CurvePoint, noncePoint: CurvePoint, transcript: bigint[]): bigint {
  return mod(hashElements([domain, publicKey.x, publicKey.y, noncePoint.x, noncePoint.y, ...transcript]), CURVE_ORDER);
}

function multiplyPoint(point: CurvePoint, scalar: bigint): CurvePoint {
  const normalized = mod(scalar, CURVE_ORDER);
  return normalized === 0n ? ec.starkCurve.ProjectivePoint.ZERO : point.multiply(normalized);
}

function pointToFelts(point: CurvePoint): RecurringCurvePoint {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: RecurringCurvePoint, label: string): CurvePoint {
  if (!point || typeof point !== "object") throw new Error(`${label} is invalid.`);
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x, label), y: requireFelt(point.y, label) });
  parsed.assertValidity();
  return parsed;
}

function randomScalar(): bigint {
  return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey());
}

function mod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder >= 0n ? remainder : remainder + modulus;
}
function normalizeAsset(asset: { symbol: string; tokenAddress: string; decimals: number } | undefined, label: string): RecurringAsset {
  if (!asset || !asset.tokenAddress) throw new Error(`${label} needs a Starknet token contract address.`);
  return {
    symbol: requireSymbol(asset.symbol, `${label} symbol`),
    tokenAddress: normalizeStarknetAddress(asset.tokenAddress),
    decimals: requireDecimals(asset.decimals, `${label} decimals`),
  };
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Recurring amounts cannot be negative.");
  if (decimals === 0) return value.toString();
  const divisor = 10n ** BigInt(decimals);
  const fraction = (value % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  const whole = (value / divisor).toString();
  return fraction ? `${whole}.${fraction}` : whole;
}

function parseDecimalToBaseUnits(value: unknown, decimals: number, label: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}(\.\d{1,20})?$/.test(value.trim())) throw new Error(`${label} must be a positive decimal number.`);
  const [whole, fraction = ""] = value.trim().split(".");
  if (fraction.length > decimals) throw new Error(`${label} carries more precision than the token's ${decimals} decimals.`);
  const units = BigInt(`${whole}${fraction.padEnd(decimals, "0")}`);
  if (units <= 0n) throw new Error(`${label} must be greater than zero.`);
  return units;
}

function requireBaseUnitString(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error(`${label} must be a base-unit integer string.`);
  return BigInt(value);
}

function requireU128(value: bigint, label: string): bigint {
  if (value < 0n || value > U128_MAX) throw new Error(`${label} is outside the u128 range the privacy pool accepts.`);
  return value;
}
function requireCount(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  return value;
}

/** Converts a positive whole-day value to milliseconds and checks it against a bound. */
function requireDaysMs(value: unknown, label: string, minMs: number, maxMs: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) throw new Error(`${label} must be a positive whole number of days.`);
  const ms = value * DAY_MS;
  if (ms < minMs || ms > maxMs) throw new Error(`${label} must be between ${minMs / DAY_MS} and ${maxMs / DAY_MS} days.`);
  return ms;
}

/** Like requireDaysMs but permits an absent value, treated as zero. */
function requireOptionalDaysMs(value: unknown, label: string, minMs: number, maxMs: number): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) throw new Error(`${label} must be a non-negative whole number of days.`);
  const ms = value * DAY_MS;
  if (ms < minMs || ms > maxMs) throw new Error(`${label} must be between ${minMs / DAY_MS} and ${maxMs / DAY_MS} days.`);
  return ms;
}

function requireSymbol(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9.-]{2,12}$/.test(value)) throw new Error(`${label} must be 2 to 12 letters, digits, dots, or dashes.`);
  return value;
}

function requireDecimals(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_ASSET_DECIMALS) {
    throw new Error(`${label} must be a whole number between 0 and ${MAX_ASSET_DECIMALS}.`);
  }
  return value;
}
function requireText(value: unknown, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) throw new Error(`${label} must be between 1 and ${maxLength} characters.`);
  if (pattern && !pattern.test(trimmed)) throw new Error(`${label} has an unsupported format.`);
  return trimmed;
}

function requireOptionalText(value: unknown, label: string, maxLength: number): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  const trimmed = value.trim();
  if (trimmed.length > maxLength) throw new Error(`${label} must be ${maxLength} characters or fewer.`);
  return trimmed;
}

function requireIsoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 UTC timestamp.`);
  }
  return value;
}

function requireFelt(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,63}$/.test(value)) throw new Error(`${label} must be a lowercase hexadecimal field element.`);
  const parsed = BigInt(value);
  if (parsed >= FIELD_PRIME) throw new Error(`${label} is outside the STARK field.`);
  return parsed;
}

function requireCurveScalar(value: unknown, allowZero: boolean, label: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/.test(value)) throw new Error(`${label} is invalid.`);
  const parsed = BigInt(value);
  if ((allowZero ? parsed < 0n : parsed <= 0n) || parsed >= CURVE_ORDER) throw new Error(`${label} is outside the STARK curve order.`);
  return parsed;
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (typeof value !== "bigint" || value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the STARK curve order.`);
  return value;
}

function requireTransactionHash(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) throw new Error("The settlement transaction hash is invalid.");
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed >= FIELD_PRIME) throw new Error("The settlement transaction hash is outside the STARK field.");
  return parsed;
}

function toHex(value: bigint): string {
  if (value < 0n || value >= FIELD_PRIME) throw new Error("A field element is outside the STARK field.");
  return `0x${value.toString(16)}`;
}
function parseEncodedJson(encoded: string, maxLength: number, label: string): unknown {
  if (typeof encoded !== "string" || !encoded || encoded.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} encoding is invalid.`);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded)));
  } catch {
    throw new Error(`${label} could not be decoded.`);
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url value.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
const ASSET_KEYS = ["symbol", "tokenAddress", "decimals"];
const POINT_KEYS = ["x", "y"];
const PROOF_KEYS = ["nonceCommitment", "response"];
const PLAN_KEYS = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "merchant", "asset", "totalValueBaseUnits", "totalValueDisplay", "cycleCount", "cadenceMs", "graceMs", "payerLabel", "memo", "anchorAt", "planSalt", "planCommitment", "notice", "limitations"];
const PLAN_DIGEST_KEYS = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "assetSymbol", "assetDecimals", "cycleCount", "cadenceMs", "graceMs", "hasPayer", "anchorAt", "memoHash", "planCommitment", "notice", "limitations"];
const RECEIPT_KEYS = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "cycleCount", "cycleIndex", "dueAt", "amountBaseUnits", "settledAt", "transactionHash", "planCommitment", "receiptCommitment", "notice", "limitations"];
const MANDATE_AUTH_KEYS = ["kind", "version", "proofSystem", "planId", "planCommitment", "cycleIndex", "mandatePublicKey", "proof", "notice"];

function hasOnlyKeys(value: object, allowed: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every((key) => allowed.includes(key));
}

function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== RECURRING_LIMITATIONS.length || value.some((entry, index) => entry !== RECURRING_LIMITATIONS[index])) {
    throw new Error("The recurring limitations were altered.");
  }
}

function assertAsset(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ASSET_KEYS)) throw new Error(`${label} is invalid.`);
  const asset = value as RecurringAsset;
  requireSymbol(asset.symbol, `${label} symbol`);
  requireDecimals(asset.decimals, `${label} decimals`);
  if (!asset.tokenAddress || asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) throw new Error(`${label} token address is not canonical.`);
}

function assertPoint(value: unknown, label: string): asserts value is RecurringCurvePoint {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, POINT_KEYS)) throw new Error(`${label} is invalid.`);
  pointFromFelts(value as RecurringCurvePoint, label);
}

function assertProof(value: unknown, label: string): asserts value is RecurringSchnorrProof {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PROOF_KEYS)) throw new Error(`${label} is invalid.`);
  const proof = value as RecurringSchnorrProof;
  assertPoint(proof.nonceCommitment, `${label} nonce`);
  requireCurveScalar(proof.response, true, `${label} response`);
}
function assertRecurringPlan(value: unknown): asserts value is RecurringBillingPlan {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PLAN_KEYS)) throw new Error("Recurring plan is invalid.");
  const p = value as RecurringBillingPlan;
  if (p.kind !== PLAN_KIND || p.version !== RECURRING_ENGINE_VERSION || p.network !== MAINNET_CHAIN_ID
    || p.poolAddress !== STRK20_POOL_ADDRESS || p.notice !== RECURRING_NOTICE
    || !/^rcb_[A-Za-z0-9_-]{1,48}$/.test(p.planId)) throw new Error("Recurring plan header is invalid.");
  assertLimitations(p.limitations);
  requireText(p.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  if (!p.merchant || p.merchant !== normalizeStarknetAddress(p.merchant)) throw new Error("The merchant recipient is not canonical.");
  assertAsset(p.asset, "Billed asset");
  const total = requireU128(requireBaseUnitString(p.totalValueBaseUnits, "Total value"), "Total value");
  if (total <= 0n) throw new Error("The total value must be positive.");
  if (p.totalValueDisplay !== formatBaseUnits(total, p.asset.decimals)) throw new Error("The total value display is inconsistent.");
  if (!Number.isInteger(p.cycleCount) || p.cycleCount < MIN_CYCLES || p.cycleCount > MAX_CYCLES) throw new Error("The cycle count is invalid.");
  computeInstallments(total, p.cycleCount);
  if (!Number.isInteger(p.cadenceMs) || p.cadenceMs < MIN_CADENCE_DAYS * DAY_MS || p.cadenceMs > MAX_CADENCE_DAYS * DAY_MS) throw new Error("The cadence is invalid.");
  if (!Number.isInteger(p.graceMs) || p.graceMs < 0 || p.graceMs > MAX_GRACE_DAYS * DAY_MS) throw new Error("The grace window is invalid.");
  if (typeof p.payerLabel !== "string" || p.payerLabel.length > 96) throw new Error("The payer label is invalid.");
  if (typeof p.memo !== "string" || p.memo.length > 160) throw new Error("The plan memo is invalid.");
  requireIsoTimestamp(p.anchorAt, "Plan anchor time");
  requireFelt(p.planSalt, "Plan salt");
  if (requireFelt(p.planCommitment, "Plan commitment") !== computePlanCommitment(p)) throw new Error("The plan commitment does not match its contents.");
}
function assertRecurringPlanDigest(value: unknown): asserts value is RecurringPlanDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PLAN_DIGEST_KEYS)) throw new Error("Recurring plan digest is invalid.");
  const d = value as RecurringPlanDigest;
  if (d.kind !== PLAN_DIGEST_KIND || d.version !== RECURRING_ENGINE_VERSION || d.network !== MAINNET_CHAIN_ID
    || d.poolAddress !== STRK20_POOL_ADDRESS || d.notice !== RECURRING_NOTICE
    || !/^rcb_[A-Za-z0-9_-]{1,48}$/.test(d.planId)) throw new Error("Recurring plan digest header is invalid.");
  assertLimitations(d.limitations);
  requireText(d.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireSymbol(d.assetSymbol, "Digest asset symbol");
  requireDecimals(d.assetDecimals, "Digest asset decimals");
  if (!Number.isInteger(d.cycleCount) || d.cycleCount < MIN_CYCLES || d.cycleCount > MAX_CYCLES) throw new Error("The digest cycle count is invalid.");
  if (!Number.isInteger(d.cadenceMs) || d.cadenceMs < MIN_CADENCE_DAYS * DAY_MS || d.cadenceMs > MAX_CADENCE_DAYS * DAY_MS) throw new Error("The digest cadence is invalid.");
  if (!Number.isInteger(d.graceMs) || d.graceMs < 0 || d.graceMs > MAX_GRACE_DAYS * DAY_MS) throw new Error("The digest grace window is invalid.");
  if (typeof d.hasPayer !== "boolean") throw new Error("The digest payer flag is invalid.");
  requireIsoTimestamp(d.anchorAt, "Plan anchor time");
  requireFelt(d.memoHash, "Memo hash");
  requireFelt(d.planCommitment, "Plan commitment");
}
function assertRecurringCycleReceipt(value: unknown): asserts value is RecurringCycleReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, RECEIPT_KEYS)) throw new Error("Recurring cycle receipt is invalid.");
  const r = value as RecurringCycleReceipt;
  if (r.kind !== RECEIPT_KIND || r.version !== RECURRING_ENGINE_VERSION || r.network !== MAINNET_CHAIN_ID
    || r.poolAddress !== STRK20_POOL_ADDRESS || r.notice !== RECURRING_NOTICE
    || !/^rcb_[A-Za-z0-9_-]{1,48}$/.test(r.planId)) throw new Error("Recurring cycle receipt header is invalid.");
  assertLimitations(r.limitations);
  requireText(r.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  if (!Number.isInteger(r.cycleCount) || r.cycleCount < MIN_CYCLES || r.cycleCount > MAX_CYCLES) throw new Error("The receipt cycle count is invalid.");
  if (!Number.isInteger(r.cycleIndex) || r.cycleIndex < 1 || r.cycleIndex > r.cycleCount) throw new Error("The receipt cycle index is invalid.");
  requireIsoTimestamp(r.dueAt, "Cycle due time");
  requireU128(requireBaseUnitString(r.amountBaseUnits, "Cycle amount"), "Cycle amount");
  requireIsoTimestamp(r.settledAt, "Settlement time");
  requireFelt(r.transactionHash, "Settlement transaction hash");
  requireFelt(r.planCommitment, "Plan commitment");
  if (requireFelt(r.receiptCommitment, "Receipt commitment") !== computeReceiptCommitment(r)) throw new Error("The receipt commitment does not match its contents.");
}

function assertMandateAuthorization(value: unknown): asserts value is RecurringMandateAuthorization {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, MANDATE_AUTH_KEYS)) throw new Error("The mandate authorization is invalid.");
  const a = value as RecurringMandateAuthorization;
  if (a.kind !== "cipherbill.recurring-mandate-authorization" || a.version !== RECURRING_ENGINE_VERSION
    || a.proofSystem !== RECURRING_MANDATE_PROOF_SYSTEM || !/^rcb_[A-Za-z0-9_-]{1,48}$/.test(a.planId)) throw new Error("The mandate authorization header is invalid.");
  requireFelt(a.planCommitment, "Plan commitment");
  if (!Number.isInteger(a.cycleIndex) || a.cycleIndex < 1 || a.cycleIndex > MAX_CYCLES) throw new Error("The mandate cycle index is invalid.");
  assertPoint(a.mandatePublicKey, "Mandate public key");
  assertProof(a.proof, "Mandate proof");
  if (typeof a.notice !== "string" || !a.notice.includes("knowledge of a key")) throw new Error("The mandate authorization notice is invalid.");
}
