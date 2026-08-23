/**
 * Liveness-gated contingency planner ("dead-man switch") and encrypted invoice reminder engine
 * for CipherBill.
 *
 * WHAT THIS IS
 * - A client-side liveness clock: a merchant arms a plan with a check-in cadence and a grace
 *   window, and this engine computes — from a caller-supplied last-check-in timestamp — whether
 *   the account reads as active, in grace, or lapsed, and when the next reminder and the lapse fall.
 * - An exact-integer contingency allocation: the merchant names beneficiaries with basis-point
 *   shares of a shielded balance, and the engine floors each share and hands the last beneficiary
 *   the exact remainder, so every base unit of the routed balance is conserved.
 * - A salted Poseidon commitment scheme for selective disclosure: the merchant commits to the plan
 *   (beneficiaries, amounts, cadence), publishes a digest that carries no amount, address, or memo,
 *   and later discloses the full plan to a chosen executor or beneficiary who verifies it.
 * - A builder for the payout legs: private in-pool STRK20 `transfer` actions, batched by recipient,
 *   that move the routed balance to the beneficiaries when someone chooses to sign them.
 * - A reminder schedule for an unacknowledged invoice, and a disclosable attestation binding the
 *   plan to a claimed last check-in and a trigger time.
 *
 * WHAT THIS IS NOT  (read before writing any docs or UI copy against this module)
 * - Not autonomous, and it triggers nothing. Nothing here executes, routes, or withdraws by itself.
 *   Every payout is a set of transfers that a live signer — the merchant, or a trusted executor who
 *   holds a valid key — must voluntarily sign after a lapse. A self-custody privacy pool has no
 *   keeper, no scheduled transaction, and no way to move funds without a signature at send time.
 * - Not a time-lock, and it enforces no deadline. The check-in clock, the grace window, and the
 *   "lapsed" verdict are local computations in one browser. The STRK20 pool holds no timer and will
 *   not release, freeze, or route anything on a schedule. `canTriggerContingency` is a UI guard, not
 *   an on-chain constraint; a signer can send the payout early or never.
 * - Not zero-knowledge, and it proves nothing. CipherBill generates no proof of any kind: the
 *   wallet proves the payout transfer and the pool verifies it onchain, and
 *   `wallet_strk20InvokeTransaction` returns only `{ transaction_hash }`. The commitments below are
 *   salted Poseidon hashes; they bind and hide terms and attest nothing about liveness or intent.
 * - Not escrow. Nothing holds the routed balance. It sits in the merchant's ordinary shielded
 *   balance and is spendable by the merchant at any time, so the "switch" is only as reliable as the
 *   key that would sign it after a lapse — a trust assumption, not a cryptographic guarantee.
 * - Not a decentralized contract, dead-man oracle, or estate registry. There is no on-chain plan
 *   registry and no liveness monitor. The STRK20 Wallet API is three methods over four Starknet-only
 *   action types. `STRK20_POOL_ADDRESS` is recorded as provenance for the payout legs, not as a
 *   contract that watches an account, stores a plan, or fires on inactivity.
 * - Not anonymous end to end. In-pool transfers hide sender, recipient, token, and amount, but
 *   registration, timing, and any withdrawal stay public, and a distinctive payout amount can be
 *   correlated. Beneficiary addresses, amounts, and the memo live only in the merchant's browser.
 */
import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const DEADMAN_ENGINE_VERSION = 1 as const;
export const DEADMAN_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const BPS_DENOMINATOR = 10_000;
export const FEE_BPS_DENOMINATOR = 10_000n;
export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;
export const MAX_ASSET_DECIMALS = 18;
export const MIN_BENEFICIARIES = 1;
export const MAX_BENEFICIARIES = 16;
export const MIN_CHECK_IN_INTERVAL_MS = HOUR_MS; // an hour, so a lapse is never instantaneous
export const MAX_CHECK_IN_INTERVAL_MS = 365 * DAY_MS; // a year, the longest cadence the UI offers
export const MAX_GRACE_MS = 180 * DAY_MS; // half a year of buffer after a missed check-in
export const MIN_REMINDERS = 1;
export const MAX_REMINDERS = 8;
export const DEADMAN_SALT_BYTES = 31;

const PLAN_KIND = "cipherbill.deadman-plan" as const;
const PLAN_DIGEST_KIND = "cipherbill.deadman-plan-digest" as const;
const ATTESTATION_KIND = "cipherbill.deadman-attestation" as const;

const PLAN_DOMAIN = hash.starknetKeccak("CipherBill deadman plan v1");
const PLAN_BENEFICIARIES_DOMAIN = hash.starknetKeccak("CipherBill deadman beneficiaries v1");
const ATTESTATION_DOMAIN = hash.starknetKeccak("CipherBill deadman attestation v1");
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const MAX_ENCODED_LENGTH = 200_000;

const DEADMAN_NOTICE = "Client-side liveness clock and contingency payout plan. The beneficiary payout is a set of private in-pool STRK20 transfers that a live signer must voluntarily send after a lapse; everything else here is computation held in one browser. Nothing fires on its own, no proof or time-lock is generated, no contract watches the account or holds the funds, and the routed balance stays spendable by the merchant.";

const DEADMAN_LIMITATIONS = [
  "Nothing here is autonomous. No transfer executes without a signature at send time, so the switch only fires if the merchant or a trusted executor holding a valid key chooses to sign the payout after a lapse.",
  "The check-in clock, grace window, and lapse verdict are local computations. The STRK20 pool holds no timer and enforces no deadline; a signer can send the payout early, late, or never.",
  "Commitments are salted Poseidon hashes. They are not zero-knowledge proofs, no contract verifies them, and they attest nothing about whether the merchant is truly inactive.",
  "Nothing is escrowed. The routed balance sits in the merchant's ordinary shielded balance and stays fully spendable, so the plan is only as reliable as the key that would sign it later.",
  "Entrusting a payout to an executor hands that party the ability to route the funds; the engine cannot check that they wait for a genuine lapse or act honestly.",
  "In-pool transfers hide sender, recipient, token, and amount, but a distinctive payout close in time to a public event can correlate the beneficiaries. Vary timing and avoid round figures.",
] as const;

export type LivenessState = "active" | "grace" | "lapsed";
export type ReminderKind = "check_in" | "final_notice" | "lapse";

/** The routed token. Every payout leg is an in-pool transfer of it, so it must be a pool token. */
export interface DeadmanAsset {
  symbol: string;
  tokenAddress: string;
  decimals: number;
}

export interface DeadmanBeneficiaryInput {
  recipient: string;
  /** Share of the routed balance, in basis points. All shares must sum to exactly 10000. */
  shareBps: number;
  label?: string;
}

export interface DeadmanBeneficiary {
  recipient: string;
  shareBps: number;
  label: string;
  amountBaseUnits: string;
  amountDisplay: string;
}

export interface CreateDeadmanPlanInput {
  invoiceId: string;
  asset: { symbol: string; tokenAddress: string; decimals: number };
  /** Shielded balance to route to the beneficiaries on a lapse. Must be positive. */
  switchValue: string;
  /** Beneficiaries and their basis-point shares. Shares must sum to exactly 10000. */
  beneficiaries: DeadmanBeneficiaryInput[];
  /** How often the merchant must check in to reset the liveness clock, in hours. */
  checkInIntervalHours: number;
  /** Extra buffer after a missed check-in before the plan reads as lapsed, in hours. Defaults to 0. */
  graceHours?: number;
  /** Optional label for the trusted party who would sign the payout after a lapse. */
  executorLabel?: string;
  memo?: string;
}

export interface DeadmanPlan {
  kind: typeof PLAN_KIND;
  version: typeof DEADMAN_ENGINE_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  asset: DeadmanAsset;
  switchValueBaseUnits: string;
  switchValueDisplay: string;
  beneficiaries: DeadmanBeneficiary[];
  checkInIntervalMs: number;
  graceMs: number;
  /** Empty string when no executor was named. A trade secret bound only as a keccak hash in the digest. */
  executorLabel: string;
  memo: string;
  armedAt: string;
  /** Secret plan-level blinding factor. Never publish a plan; publish its digest. */
  planSalt: string;
  planCommitment: string;
  notice: typeof DEADMAN_NOTICE;
  limitations: string[];
}

/** Plan fields safe to publish: cadence and counts, no amounts, addresses, executor, or memo. */
export interface DeadmanPlanDigest {
  kind: typeof PLAN_DIGEST_KIND;
  version: typeof DEADMAN_ENGINE_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  assetSymbol: string;
  assetDecimals: number;
  beneficiaryCount: number;
  checkInIntervalMs: number;
  graceMs: number;
  hasExecutor: boolean;
  armedAt: string;
  memoHash: string;
  planCommitment: string;
  notice: typeof DEADMAN_NOTICE;
  limitations: string[];
}

/** One plan disclosed against its published digest, for a chosen executor or beneficiary. */
export interface DeadmanPlanOpening {
  planId: string;
  planCommitment: string;
  plan: DeadmanPlan;
}

export interface LivenessEvaluation {
  state: LivenessState;
  lastCheckInAt: string;
  /** When the next check-in is due to keep the account active. */
  checkInDueAt: string;
  /** When the plan begins to read as lapsed (check-in due plus grace). */
  lapseAt: string;
  /** Milliseconds until the check-in is due; 0 once past it. */
  msUntilCheckIn: number;
  /** Milliseconds until the lapse; 0 once lapsed. */
  msUntilLapse: number;
  /** True only when the account reads as lapsed. A UI guard, never an on-chain constraint. */
  triggerable: boolean;
}

export interface DeadmanReminder {
  kind: ReminderKind;
  at: string;
  note: string;
}

/** A disclosable record that a plan was triggered after a claimed lapse. Not a proof of death or intent. */
export interface DeadmanAttestation {
  kind: typeof ATTESTATION_KIND;
  version: typeof DEADMAN_ENGINE_VERSION;
  planId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  invoiceId: string;
  beneficiaryCount: number;
  lastCheckInAt: string;
  lapseAt: string;
  triggeredAt: string;
  planCommitment: string;
  attestationCommitment: string;
  notice: typeof DEADMAN_NOTICE;
  limitations: string[];
}

export interface DeadmanVisibilityModel {
  applicationOnly: string[];
  walletRequest: string[];
  hiddenInPool: string[];
  publicOrObservable: string[];
  limitation: string;
}

export interface DeadmanTrustSummary {
  fundHolder: string;
  isAutonomous: boolean;
  isTimeLocked: boolean;
  isEscrowed: boolean;
  isProven: boolean;
  executorLabel: string;
  trustedParties: string[];
  statement: string;
}

export interface DeadmanEntropy {
  createId?: (kind: "plan") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

/**
 * Arms a dead-man plan: the private object holding the routed balance, the beneficiaries and their
 * exact-integer amounts, the check-in cadence, and any executor, bound by a salted Poseidon
 * commitment. Share the digest from `buildDeadmanPlanDigest`, never this object. Arming stores
 * nothing on-chain and moves no funds; it only computes and commits the plan in this browser.
 */
export function createDeadmanPlan(
  input: CreateDeadmanPlanInput,
  now = new Date(),
  entropy: DeadmanEntropy = {},
): DeadmanPlan {
  const armedAt = requireIsoTimestamp(now.toISOString(), "Plan arming time");
  const asset = normalizeAsset(input.asset, "Routed asset");
  const switchValue = parseDecimalToBaseUnits(input.switchValue, asset.decimals, "Switch value");
  requireU128(switchValue, "Switch value");
  const checkInIntervalMs = requireIntervalMs(input.checkInIntervalHours, "Check-in interval", MIN_CHECK_IN_INTERVAL_MS, MAX_CHECK_IN_INTERVAL_MS);
  const graceMs = requireOptionalIntervalMs(input.graceHours, "Grace window", 0, MAX_GRACE_MS);
  const beneficiaries = solveBeneficiaryAllocation(switchValue, input.beneficiaries, asset.decimals);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));

  const draft: Omit<DeadmanPlan, "planCommitment"> = {
    kind: PLAN_KIND,
    version: DEADMAN_ENGINE_VERSION,
    planId: makeId(entropy.createId?.("plan"), "dms"),
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    invoiceId: requireText(input.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/),
    asset,
    switchValueBaseUnits: switchValue.toString(),
    switchValueDisplay: formatBaseUnits(switchValue, asset.decimals),
    beneficiaries,
    checkInIntervalMs,
    graceMs,
    executorLabel: requireOptionalText(input.executorLabel ?? "", "Executor label", 96),
    memo: requireOptionalText(input.memo ?? "", "Plan memo", 160),
    armedAt,
    planSalt: toHex(randomFelt(random)),
    notice: DEADMAN_NOTICE,
    limitations: [...DEADMAN_LIMITATIONS],
  };
  const plan: DeadmanPlan = { ...draft, planCommitment: toHex(computePlanCommitment(draft)) };
  assertDeadmanPlan(plan);
  return plan;
}

export function verifyDeadmanPlan(plan: DeadmanPlan): boolean {
  try {
    assertDeadmanPlan(plan);
    return true;
  } catch {
    return false;
  }
}

/**
 * Solves the beneficiary split in exact integers. Each share is floored; the last beneficiary takes
 * the exact remainder, so every base unit of the routed balance is conserved. Shares must sum to
 * exactly 10000 basis points, so the whole balance is allocated.
 */
function solveBeneficiaryAllocation(switchValue: bigint, inputs: DeadmanBeneficiaryInput[], decimals: number): DeadmanBeneficiary[] {
  requireU128(switchValue, "Switch value");
  if (switchValue <= 0n) throw new Error("The switch value must be positive.");
  if (!Array.isArray(inputs) || inputs.length < MIN_BENEFICIARIES || inputs.length > MAX_BENEFICIARIES) {
    throw new Error(`A plan must route to between ${MIN_BENEFICIARIES} and ${MAX_BENEFICIARIES} beneficiaries.`);
  }
  const recipients = inputs.map((entry, index) => normalizeStarknetAddress(requireText(entry.recipient, `Beneficiary ${index + 1} recipient`, 66)));
  if (new Set(recipients.map((value) => BigInt(value).toString())).size !== recipients.length) {
    throw new Error("Each beneficiary must be a distinct recipient.");
  }
  const shares = inputs.map((entry, index) => requireBps(entry.shareBps, `Beneficiary ${index + 1} share`, 1, BPS_DENOMINATOR));
  if (shares.reduce((sum, value) => sum + value, 0) !== BPS_DENOMINATOR) {
    throw new Error("The beneficiary shares must sum to exactly 10000 basis points.");
  }
  const amounts: bigint[] = shares.map((share) => (switchValue * BigInt(share)) / FEE_BPS_DENOMINATOR);
  const allocatedExceptLast = amounts.slice(0, -1).reduce((sum, value) => sum + value, 0n);
  amounts[amounts.length - 1] = switchValue - allocatedExceptLast;
  const total = amounts.reduce((sum, value) => sum + value, 0n);
  if (total !== switchValue) throw new Error("The beneficiary allocation does not conserve the routed balance.");
  return inputs.map((entry, index) => {
    const amount = requireU128(amounts[index], `Beneficiary ${index + 1} amount`);
    return {
      recipient: recipients[index],
      shareBps: shares[index],
      label: requireOptionalText(entry.label ?? "", `Beneficiary ${index + 1} label`, 64),
      amountBaseUnits: amount.toString(),
      amountDisplay: formatBaseUnits(amount, decimals),
    };
  });
}

/** The only plan object safe to publish. Carries the cadence and counts, no amounts or addresses. */
export function buildDeadmanPlanDigest(plan: DeadmanPlan): DeadmanPlanDigest {
  assertDeadmanPlan(plan);
  return {
    kind: PLAN_DIGEST_KIND,
    version: DEADMAN_ENGINE_VERSION,
    planId: plan.planId,
    network: plan.network,
    poolAddress: plan.poolAddress,
    invoiceId: plan.invoiceId,
    assetSymbol: plan.asset.symbol,
    assetDecimals: plan.asset.decimals,
    beneficiaryCount: plan.beneficiaries.length,
    checkInIntervalMs: plan.checkInIntervalMs,
    graceMs: plan.graceMs,
    hasExecutor: plan.executorLabel !== "",
    armedAt: plan.armedAt,
    memoHash: toHex(BigInt(hash.starknetKeccak(plan.memo || "empty"))),
    planCommitment: plan.planCommitment,
    notice: DEADMAN_NOTICE,
    limitations: [...DEADMAN_LIMITATIONS],
  };
}

/** Discloses the full plan so a chosen executor or beneficiary can check it against a digest. */
export function openDeadmanPlan(plan: DeadmanPlan): DeadmanPlanOpening {
  assertDeadmanPlan(plan);
  return { planId: plan.planId, planCommitment: plan.planCommitment, plan };
}

export function verifyDeadmanPlanDisclosure(digest: DeadmanPlanDigest, opening: DeadmanPlanOpening): boolean {
  try {
    assertDeadmanPlanDigest(digest);
    assertDeadmanPlan(opening.plan);
    if (digest.planId !== opening.planId || digest.planCommitment !== opening.planCommitment) return false;
    if (digest.planCommitment !== opening.plan.planCommitment) return false;
    return digest.invoiceId === opening.plan.invoiceId
      && digest.assetSymbol === opening.plan.asset.symbol
      && digest.assetDecimals === opening.plan.asset.decimals
      && digest.beneficiaryCount === opening.plan.beneficiaries.length
      && digest.checkInIntervalMs === opening.plan.checkInIntervalMs
      && digest.graceMs === opening.plan.graceMs
      && digest.hasExecutor === (opening.plan.executorLabel !== "")
      && digest.armedAt === opening.plan.armedAt
      && digest.memoHash === toHex(BigInt(hash.starknetKeccak(opening.plan.memo || "empty")));
  } catch {
    return false;
  }
}

/**
 * Evaluates the liveness clock against a caller-supplied last check-in. The account reads as active
 * until the check-in is due, then in grace until the grace window elapses, then lapsed. This is a
 * local computation only: the pool holds no timer, and nothing here freezes or releases funds.
 */
export function evaluateLiveness(plan: DeadmanPlan, lastCheckInAt: string, now = new Date()): LivenessEvaluation {
  assertDeadmanPlan(plan);
  const lastCheckIn = requireIsoTimestamp(lastCheckInAt, "Last check-in time");
  const lastMs = Date.parse(lastCheckIn);
  const nowMs = Date.parse(requireIsoTimestamp(now.toISOString(), "Evaluation time"));
  const checkInDueMs = lastMs + plan.checkInIntervalMs;
  const lapseMs = checkInDueMs + plan.graceMs;
  const state: LivenessState = nowMs < checkInDueMs ? "active" : nowMs < lapseMs ? "grace" : "lapsed";
  return {
    state,
    lastCheckInAt: lastCheckIn,
    checkInDueAt: new Date(checkInDueMs).toISOString(),
    lapseAt: new Date(lapseMs).toISOString(),
    msUntilCheckIn: Math.max(0, checkInDueMs - nowMs),
    msUntilLapse: Math.max(0, lapseMs - nowMs),
    triggerable: state === "lapsed",
  };
}

/**
 * True only when the plan reads as lapsed against the supplied last check-in. This is a UI guard to
 * discourage an early payout, never an on-chain constraint: a signer can send the transfers anyway.
 */
export function canTriggerContingency(plan: DeadmanPlan, lastCheckInAt: string, now = new Date()): boolean {
  return evaluateLiveness(plan, lastCheckInAt, now).triggerable;
}

/**
 * Builds a reminder schedule between the last check-in and the lapse for an unacknowledged invoice:
 * evenly spaced check-in nudges, a final notice at the check-in deadline, and the lapse itself.
 * These are timestamps to act on in this browser or an external scheduler, not autonomous events.
 */
export function buildReminderSchedule(plan: DeadmanPlan, lastCheckInAt: string, reminderCount = 3): DeadmanReminder[] {
  assertDeadmanPlan(plan);
  const lastCheckIn = requireIsoTimestamp(lastCheckInAt, "Last check-in time");
  const count = requireBps(reminderCount, "Reminder count", MIN_REMINDERS, MAX_REMINDERS);
  const lastMs = Date.parse(lastCheckIn);
  const checkInDueMs = lastMs + plan.checkInIntervalMs;
  const lapseMs = checkInDueMs + plan.graceMs;
  const reminders: DeadmanReminder[] = [];
  for (let index = 1; index <= count; index += 1) {
    const at = lastMs + Math.floor((plan.checkInIntervalMs * index) / (count + 1));
    reminders.push({ kind: "check_in", at: new Date(at).toISOString(), note: `Check-in reminder ${index} of ${count}: acknowledge to reset the liveness clock.` });
  }
  reminders.push({ kind: "final_notice", at: new Date(checkInDueMs).toISOString(), note: "Final notice: the check-in is now due. The grace window begins." });
  reminders.push({ kind: "lapse", at: new Date(lapseMs).toISOString(), note: "Lapse: the plan now reads as lapsed and the contingency payout becomes eligible to sign." });
  return reminders;
}

/**
 * Builds the payout legs: private in-pool `transfer` actions batched by beneficiary, moving each
 * beneficiary's amount from the merchant's shielded balance. Zero legs are dropped. Whoever signs
 * must hold the routed balance. No relayer-fee action is added: `wallet_strk20InvokeTransaction`
 * appends its own, and a second would double-charge. Building actions triggers nothing on its own.
 */
export function buildContingencyActions(plan: DeadmanPlan): STRK20_ACTION[] {
  assertDeadmanPlan(plan);
  const token = plan.asset.tokenAddress;
  const order: string[] = [];
  const merged = new Map<string, bigint>();
  for (const beneficiary of plan.beneficiaries) {
    const amount = BigInt(beneficiary.amountBaseUnits);
    if (amount <= 0n) continue;
    if (!merged.has(beneficiary.recipient)) order.push(beneficiary.recipient);
    merged.set(beneficiary.recipient, (merged.get(beneficiary.recipient) ?? 0n) + amount);
  }
  if (order.length === 0) throw new Error("The plan has nothing to route.");
  return order.map((recipient) => {
    const amount = requireU128(merged.get(recipient) as bigint, "Payout leg");
    return { type: "transfer", token, amount: amount.toString(), recipient };
  });
}

/**
 * Builds a disclosable attestation that a plan was triggered after a genuine lapse. It binds the
 * plan commitment to a claimed last check-in and a trigger time, and refuses to attest a trigger
 * before the computed lapse. It is not on-chain, not a proof of inactivity, and not a death record.
 */
export function buildDeadmanAttestation(plan: DeadmanPlan, input: { lastCheckInAt: string; triggeredAt: string }): DeadmanAttestation {
  assertDeadmanPlan(plan);
  const lastCheckIn = requireIsoTimestamp(input.lastCheckInAt, "Last check-in time");
  const triggeredAt = requireIsoTimestamp(input.triggeredAt, "Trigger time");
  const lapseMs = Date.parse(lastCheckIn) + plan.checkInIntervalMs + plan.graceMs;
  if (Date.parse(triggeredAt) < lapseMs) throw new Error("The trigger time cannot be before the plan lapses.");
  const draft: Omit<DeadmanAttestation, "attestationCommitment"> = {
    kind: ATTESTATION_KIND,
    version: DEADMAN_ENGINE_VERSION,
    planId: plan.planId,
    network: plan.network,
    poolAddress: plan.poolAddress,
    invoiceId: plan.invoiceId,
    beneficiaryCount: plan.beneficiaries.length,
    lastCheckInAt: lastCheckIn,
    lapseAt: new Date(lapseMs).toISOString(),
    triggeredAt,
    planCommitment: plan.planCommitment,
    notice: DEADMAN_NOTICE,
    limitations: [...DEADMAN_LIMITATIONS],
  };
  return { ...draft, attestationCommitment: toHex(computeAttestationCommitment(draft)) };
}

export function verifyDeadmanAttestation(attestation: DeadmanAttestation, plan: DeadmanPlan): boolean {
  try {
    assertDeadmanAttestation(attestation);
    assertDeadmanPlan(plan);
    if (attestation.planId !== plan.planId || attestation.planCommitment !== plan.planCommitment) return false;
    const lapseMs = Date.parse(attestation.lastCheckInAt) + plan.checkInIntervalMs + plan.graceMs;
    if (attestation.lapseAt !== new Date(lapseMs).toISOString()) return false;
    if (Date.parse(attestation.triggeredAt) < lapseMs) return false;
    return attestation.invoiceId === plan.invoiceId
      && attestation.beneficiaryCount === plan.beneficiaries.length;
  } catch {
    return false;
  }
}

export function getDeadmanVisibilityModel(plan: DeadmanPlan): DeadmanVisibilityModel {
  assertDeadmanPlan(plan);
  return {
    applicationOnly: ["invoice ID", "switch value and each beneficiary's amount", "beneficiary addresses and labels", "the executor label and memo", "the plan salt", "the last check-in time and the liveness clock"],
    walletRequest: ["routed token address", "exact per-beneficiary base-unit amounts", "in-pool beneficiary recipients"],
    hiddenInPool: ["in-pool sender and recipients of the payout transfers", "token and amount of each transfer", "which encrypted notes were spent"],
    publicOrObservable: ["published nullifiers, unlinkable without a viewing key", "transaction timing and fees for the payout"],
    limitation: "The payout moves related amounts from one payer to several beneficiaries close in time. Distinctive amounts settled together can correlate the beneficiaries. Vary timing and avoid round figures.",
  };
}

export function summarizeDeadmanTrust(plan: DeadmanPlan): DeadmanTrustSummary {
  assertDeadmanPlan(plan);
  const symbol = plan.asset.symbol;
  const executor = plan.executorLabel || "a party holding a valid signing key";
  return {
    fundHolder: "the merchant, who keeps the routed balance in an ordinary shielded balance and can spend it at any time",
    isAutonomous: false,
    isTimeLocked: false,
    isEscrowed: false,
    isProven: false,
    executorLabel: plan.executorLabel,
    trustedParties: [`${executor} to sign the payout only after a genuine lapse`, "the merchant to keep the routed balance available until then"],
    statement: `The plan would route ${plan.switchValueDisplay} ${symbol} to ${plan.beneficiaries.length} beneficiar${plan.beneficiaries.length === 1 ? "y" : "ies"} if the merchant stops checking in. Nothing fires on its own and no time-lock or proof is generated: the payout only takes effect when ${executor} voluntarily signs the transfers, and the balance stays spendable by the merchant until then.`,
  };
}

export function serializeDeadmanPlan(plan: DeadmanPlan): string {
  assertDeadmanPlan(plan);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(plan)));
}

export function parseDeadmanPlan(encoded: string): DeadmanPlan {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Dead-man plan");
  assertDeadmanPlan(parsed);
  return parsed;
}

export function serializeDeadmanPlanDigest(digest: DeadmanPlanDigest): string {
  assertDeadmanPlanDigest(digest);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(digest)));
}

export function parseDeadmanPlanDigest(encoded: string): DeadmanPlanDigest {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Plan digest");
  assertDeadmanPlanDigest(parsed);
  return parsed;
}

export function serializeDeadmanAttestation(attestation: DeadmanAttestation): string {
  assertDeadmanAttestation(attestation);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(attestation)));
}

export function parseDeadmanAttestation(encoded: string): DeadmanAttestation {
  const parsed = parseEncodedJson(encoded, MAX_ENCODED_LENGTH, "Dead-man attestation");
  assertDeadmanAttestation(parsed);
  return parsed;
}

export function formatDeadmanBaseUnits(value: string | bigint, decimals: number): string {
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
    const bytes = random(new Uint8Array(DEADMAN_SALT_BYTES));
    if (!(bytes instanceof Uint8Array) || bytes.length !== DEADMAN_SALT_BYTES) throw new Error("The entropy source returned the wrong number of bytes.");
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

function computeBeneficiariesRoot(beneficiaries: DeadmanBeneficiary[]): bigint {
  const elements: bigint[] = [PLAN_BENEFICIARIES_DOMAIN, BigInt(beneficiaries.length)];
  for (const beneficiary of beneficiaries) {
    elements.push(BigInt(beneficiary.recipient));
    elements.push(BigInt(beneficiary.shareBps));
    elements.push(BigInt(beneficiary.amountBaseUnits));
    elements.push(BigInt(hash.starknetKeccak(beneficiary.label || "none")));
  }
  return hashElements(elements);
}

function computePlanCommitment(p: Omit<DeadmanPlan, "planCommitment">): bigint {
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
    BigInt(p.switchValueBaseUnits),
    computeBeneficiariesRoot(p.beneficiaries),
    BigInt(p.checkInIntervalMs),
    BigInt(p.graceMs),
    BigInt(hash.starknetKeccak(p.executorLabel || "none")),
    BigInt(hash.starknetKeccak(p.memo || "empty")),
    secondsOf(p.armedAt),
  ]);
}

function computeAttestationCommitment(a: Omit<DeadmanAttestation, "attestationCommitment">): bigint {
  return hashElements([
    ATTESTATION_DOMAIN,
    BigInt(a.version),
    BigInt(hash.starknetKeccak(a.planId)),
    BigInt(hash.starknetKeccak(a.invoiceId)),
    BigInt(STRK20_POOL_ADDRESS),
    requireFelt(a.planCommitment, "Plan commitment"),
    BigInt(a.beneficiaryCount),
    secondsOf(a.lastCheckInAt),
    secondsOf(a.lapseAt),
    secondsOf(a.triggeredAt),
  ]);
}

function normalizeAsset(asset: { symbol: string; tokenAddress: string; decimals: number } | undefined, label: string): DeadmanAsset {
  if (!asset || !asset.tokenAddress) throw new Error(`${label} needs a Starknet token contract address.`);
  return {
    symbol: requireSymbol(asset.symbol, `${label} symbol`),
    tokenAddress: normalizeStarknetAddress(asset.tokenAddress),
    decimals: requireDecimals(asset.decimals, `${label} decimals`),
  };
}

function formatBaseUnits(value: bigint, decimals: number): string {
  if (value < 0n) throw new Error("Dead-man amounts cannot be negative.");
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

function requireBps(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  return value;
}

/** Converts a positive hours value to whole milliseconds and checks it against a bound. */
function requireIntervalMs(value: unknown, label: string, minMs: number, maxMs: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) throw new Error(`${label} must be a positive number of hours.`);
  const ms = value * HOUR_MS;
  if (!Number.isInteger(ms)) throw new Error(`${label} must land on a whole millisecond.`);
  if (ms < minMs || ms > maxMs) throw new Error(`${label} must be between ${minMs / HOUR_MS} and ${maxMs / HOUR_MS} hours.`);
  return ms;
}

/** Like requireIntervalMs but permits an absent value, treated as zero. */
function requireOptionalIntervalMs(value: unknown, label: string, minMs: number, maxMs: number): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error(`${label} must be a non-negative number of hours.`);
  const ms = value * HOUR_MS;
  if (!Number.isInteger(ms)) throw new Error(`${label} must land on a whole millisecond.`);
  if (ms < minMs || ms > maxMs) throw new Error(`${label} must be between ${minMs / HOUR_MS} and ${maxMs / HOUR_MS} hours.`);
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
const BENEFICIARY_KEYS = ["recipient", "shareBps", "label", "amountBaseUnits", "amountDisplay"];
const PLAN_KEYS = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "asset", "switchValueBaseUnits", "switchValueDisplay", "beneficiaries", "checkInIntervalMs", "graceMs", "executorLabel", "memo", "armedAt", "planSalt", "planCommitment", "notice", "limitations"];
const PLAN_DIGEST_KEYS = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "assetSymbol", "assetDecimals", "beneficiaryCount", "checkInIntervalMs", "graceMs", "hasExecutor", "armedAt", "memoHash", "planCommitment", "notice", "limitations"];
const ATTESTATION_KEYS = ["kind", "version", "planId", "network", "poolAddress", "invoiceId", "beneficiaryCount", "lastCheckInAt", "lapseAt", "triggeredAt", "planCommitment", "attestationCommitment", "notice", "limitations"];

function hasOnlyKeys(value: object, allowed: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every((key) => allowed.includes(key));
}

function assertLimitations(value: unknown): void {
  if (!Array.isArray(value) || value.length !== DEADMAN_LIMITATIONS.length || value.some((entry, index) => entry !== DEADMAN_LIMITATIONS[index])) {
    throw new Error("The dead-man limitations were altered.");
  }
}

function assertAsset(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ASSET_KEYS)) throw new Error(`${label} is invalid.`);
  const asset = value as DeadmanAsset;
  requireSymbol(asset.symbol, `${label} symbol`);
  requireDecimals(asset.decimals, `${label} decimals`);
  if (!asset.tokenAddress || asset.tokenAddress !== normalizeStarknetAddress(asset.tokenAddress)) throw new Error(`${label} token address is not canonical.`);
}

function assertBeneficiaries(value: unknown, switchValue: bigint, decimals: number): void {
  if (!Array.isArray(value) || value.length < MIN_BENEFICIARIES || value.length > MAX_BENEFICIARIES) throw new Error("The beneficiary list is invalid.");
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || !hasOnlyKeys(entry, BENEFICIARY_KEYS)) throw new Error("A beneficiary record is invalid.");
    const b = entry as DeadmanBeneficiary;
    if (typeof b.label !== "string" || b.label.length > 64) throw new Error("A beneficiary label is invalid.");
    requireBaseUnitString(b.amountBaseUnits, "Beneficiary amount");
  }
  const beneficiaries = value as DeadmanBeneficiary[];
  const resolved = solveBeneficiaryAllocation(
    switchValue,
    beneficiaries.map((b) => ({ recipient: b.recipient, shareBps: b.shareBps, label: b.label })),
    decimals,
  );
  if (JSON.stringify(resolved) !== JSON.stringify(beneficiaries)) throw new Error("The beneficiary allocation does not reconcile.");
}

function assertDeadmanPlan(value: unknown): asserts value is DeadmanPlan {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PLAN_KEYS)) throw new Error("Dead-man plan is invalid.");
  const p = value as DeadmanPlan;
  if (p.kind !== PLAN_KIND || p.version !== DEADMAN_ENGINE_VERSION || p.network !== MAINNET_CHAIN_ID
    || p.poolAddress !== STRK20_POOL_ADDRESS || p.notice !== DEADMAN_NOTICE
    || !/^dms_[A-Za-z0-9_-]{1,48}$/.test(p.planId)) throw new Error("Dead-man plan header is invalid.");
  assertLimitations(p.limitations);
  requireText(p.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  assertAsset(p.asset, "Routed asset");
  const switchValue = requireU128(requireBaseUnitString(p.switchValueBaseUnits, "Switch value"), "Switch value");
  if (switchValue <= 0n) throw new Error("The switch value must be positive.");
  if (p.switchValueDisplay !== formatBaseUnits(switchValue, p.asset.decimals)) throw new Error("The switch value display is inconsistent.");
  assertBeneficiaries(p.beneficiaries, switchValue, p.asset.decimals);
  if (!Number.isInteger(p.checkInIntervalMs) || p.checkInIntervalMs < MIN_CHECK_IN_INTERVAL_MS || p.checkInIntervalMs > MAX_CHECK_IN_INTERVAL_MS) throw new Error("The check-in interval is invalid.");
  if (!Number.isInteger(p.graceMs) || p.graceMs < 0 || p.graceMs > MAX_GRACE_MS) throw new Error("The grace window is invalid.");
  if (typeof p.executorLabel !== "string" || p.executorLabel.length > 96) throw new Error("The executor label is invalid.");
  if (typeof p.memo !== "string" || p.memo.length > 160) throw new Error("The plan memo is invalid.");
  requireIsoTimestamp(p.armedAt, "Plan arming time");
  requireFelt(p.planSalt, "Plan salt");
  if (requireFelt(p.planCommitment, "Plan commitment") !== computePlanCommitment(p)) throw new Error("The plan commitment does not match its contents.");
}

function assertDeadmanPlanDigest(value: unknown): asserts value is DeadmanPlanDigest {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, PLAN_DIGEST_KEYS)) throw new Error("Dead-man plan digest is invalid.");
  const d = value as DeadmanPlanDigest;
  if (d.kind !== PLAN_DIGEST_KIND || d.version !== DEADMAN_ENGINE_VERSION || d.network !== MAINNET_CHAIN_ID
    || d.poolAddress !== STRK20_POOL_ADDRESS || d.notice !== DEADMAN_NOTICE
    || !/^dms_[A-Za-z0-9_-]{1,48}$/.test(d.planId)) throw new Error("Dead-man plan digest header is invalid.");
  assertLimitations(d.limitations);
  requireText(d.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  requireSymbol(d.assetSymbol, "Digest asset symbol");
  requireDecimals(d.assetDecimals, "Digest asset decimals");
  if (!Number.isInteger(d.beneficiaryCount) || d.beneficiaryCount < MIN_BENEFICIARIES || d.beneficiaryCount > MAX_BENEFICIARIES) throw new Error("The digest beneficiary count is invalid.");
  if (!Number.isInteger(d.checkInIntervalMs) || d.checkInIntervalMs < MIN_CHECK_IN_INTERVAL_MS || d.checkInIntervalMs > MAX_CHECK_IN_INTERVAL_MS) throw new Error("The digest check-in interval is invalid.");
  if (!Number.isInteger(d.graceMs) || d.graceMs < 0 || d.graceMs > MAX_GRACE_MS) throw new Error("The digest grace window is invalid.");
  if (typeof d.hasExecutor !== "boolean") throw new Error("The digest executor flag is invalid.");
  requireIsoTimestamp(d.armedAt, "Plan arming time");
  requireFelt(d.memoHash, "Memo hash");
  requireFelt(d.planCommitment, "Plan commitment");
}

function assertDeadmanAttestation(value: unknown): asserts value is DeadmanAttestation {
  if (!value || typeof value !== "object" || Array.isArray(value) || !hasOnlyKeys(value, ATTESTATION_KEYS)) throw new Error("Dead-man attestation is invalid.");
  const a = value as DeadmanAttestation;
  if (a.kind !== ATTESTATION_KIND || a.version !== DEADMAN_ENGINE_VERSION || a.network !== MAINNET_CHAIN_ID
    || a.poolAddress !== STRK20_POOL_ADDRESS || a.notice !== DEADMAN_NOTICE
    || !/^dms_[A-Za-z0-9_-]{1,48}$/.test(a.planId)) throw new Error("Dead-man attestation header is invalid.");
  assertLimitations(a.limitations);
  requireText(a.invoiceId, "Invoice ID", 64, /^[A-Za-z0-9_-]+$/);
  if (!Number.isInteger(a.beneficiaryCount) || a.beneficiaryCount < MIN_BENEFICIARIES || a.beneficiaryCount > MAX_BENEFICIARIES) throw new Error("The attestation beneficiary count is invalid.");
  requireIsoTimestamp(a.lastCheckInAt, "Last check-in time");
  requireIsoTimestamp(a.lapseAt, "Lapse time");
  requireIsoTimestamp(a.triggeredAt, "Trigger time");
  if (Date.parse(a.triggeredAt) < Date.parse(a.lapseAt)) throw new Error("The attested trigger time precedes the lapse.");
  requireFelt(a.planCommitment, "Plan commitment");
  if (requireFelt(a.attestationCommitment, "Attestation commitment") !== computeAttestationCommitment(a)) throw new Error("The attestation commitment does not match its contents.");
}







