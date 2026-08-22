import { describe, expect, it } from "vitest";

import {
  assertU128Amount,
  blocksUntilProofAnchorExpiry,
  buildDappSubmittedActions,
  buildInvoiceTermsTypedData,
  buildWalletRelayedActions,
  describeGaslessPlan,
  DEFAULT_PROOF_VALIDITY_BLOCKS,
  GASLESS_LIMITATIONS,
  GASLESS_NOTICE,
  getInvoiceTermsMessageHash,
  isProofAnchorStale,
  mapWalletGaslessError,
  planGaslessPayment,
  U128_MAX,
  verifyInvoiceTermsAttestation,
} from "./gasless-relayer";
import { STRK_TOKEN_ADDRESS } from "./strk20/config";

const MERCHANT = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
const PAYER = "0x0574bd20a5f0e39d2ce0e34d0f2b7fd8b1b9d0b6f0f2c7f0e9d8c7b6a5948372";
const FEE_RECIPIENT = "0x06d1f2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff";
const STRK = { symbol: "STRK", decimals: 18 } as const;

/** The `FELT` pattern the Wallet API component definitions accept for action amounts. */
const FELT_PATTERN = /^0x(?:0|[a-fA-F1-9][a-fA-F0-9]{0,62})$/;

describe("planGaslessPayment", () => {
  it("reserves the relayer fee on top of the payment on the wallet-relayed route", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: "1000000000000000000",
      relayerFeeBaseUnits: "2500000000000000",
      shieldedBalanceBaseUnits: "5000000000000000000",
    });

    expect(plan.route).toBe("wallet_relayed");
    expect(plan.feeDrawnFrom).toBe("payer_shielded_balance");
    expect(plan.feeReserveBaseUnits).toBe(2_500_000_000_000_000n);
    expect(plan.requiredBaseUnits).toBe(1_002_500_000_000_000_000n);
    expect(plan.surplusBaseUnits).toBe(3_997_500_000_000_000_000n);
    expect(plan.shortfallBaseUnits).toBe(0n);
    expect(plan.sufficient).toBe(true);
    expect(plan.requiresDappPaymaster).toBe(false);
  });

  it("catches a one-base-unit shortfall that float arithmetic would approve", () => {
    // 1e18 + 1 is beyond Number.MAX_SAFE_INTEGER, so a Number-based comparison reports
    // these as equal and lets the wallet reject the payment instead.
    const payment = "1000000000000000000";
    expect(Number(payment) + Number("1")).toBe(Number(payment));

    const plan = planGaslessPayment({
      paymentBaseUnits: payment,
      relayerFeeBaseUnits: "1",
      shieldedBalanceBaseUnits: payment,
    });

    expect(plan.sufficient).toBe(false);
    expect(plan.shortfallBaseUnits).toBe(1n);
    expect(plan.surplusBaseUnits).toBe(0n);
  });

  it("treats a balance exactly equal to the required total as sufficient", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: 700n,
      relayerFeeBaseUnits: 300n,
      shieldedBalanceBaseUnits: 1000n,
    });

    expect(plan.sufficient).toBe(true);
    expect(plan.surplusBaseUnits).toBe(0n);
    expect(plan.shortfallBaseUnits).toBe(0n);
  });

  it("reserves exactly the quoted fee unless headroom is requested, and rounds headroom up", () => {
    const exact = planGaslessPayment({
      paymentBaseUnits: 1n,
      relayerFeeBaseUnits: 1001n,
      shieldedBalanceBaseUnits: 0n,
    });
    expect(exact.feeReserveBaseUnits).toBe(1001n);

    // 1001 * 5% = 50.05 base units of headroom; rounding down would reserve less than asked.
    const padded = planGaslessPayment({
      paymentBaseUnits: 1n,
      relayerFeeBaseUnits: 1001n,
      shieldedBalanceBaseUnits: 0n,
      feeHeadroomBasisPoints: 500,
    });
    expect(padded.relayerFeeBaseUnits).toBe(1001n);
    expect(padded.feeReserveBaseUnits).toBe(1052n);
  });

  it("moves the fee to the dapp on the dapp-submitted route and flags the missing paymaster", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: 1000n,
      relayerFeeBaseUnits: 300n,
      shieldedBalanceBaseUnits: 1000n,
      route: "dapp_submitted",
    });

    expect(plan.requiresDappPaymaster).toBe(true);
    expect(plan.feeDrawnFrom).toBe("dapp_paymaster");
    expect(plan.feeReserveBaseUnits).toBe(0n);
    expect(plan.requiredBaseUnits).toBe(1000n);
    expect(plan.sufficient).toBe(true);
  });

  it("never asks the payer for a public gas token on either route", () => {
    for (const route of ["wallet_relayed", "dapp_submitted"] as const) {
      const plan = planGaslessPayment({
        paymentBaseUnits: 1n,
        relayerFeeBaseUnits: 1n,
        shieldedBalanceBaseUnits: 2n,
        route,
      });
      expect(plan.payerNeedsPublicGasToken).toBe(false);
    }
  });

  it("rejects amounts a STRK20 note could not hold, and unparseable inputs", () => {
    expect(() => planGaslessPayment({
      paymentBaseUnits: U128_MAX + 1n,
      relayerFeeBaseUnits: 0n,
      shieldedBalanceBaseUnits: 0n,
    })).toThrow(/u128/);

    expect(() => planGaslessPayment({
      paymentBaseUnits: 1n,
      relayerFeeBaseUnits: -1n,
      shieldedBalanceBaseUnits: 0n,
    })).toThrow(/relayer fee cannot be negative/);

    expect(() => planGaslessPayment({
      paymentBaseUnits: 1n,
      relayerFeeBaseUnits: 0n,
      shieldedBalanceBaseUnits: -1n,
    })).toThrow(/shielded balance cannot be negative/);

    expect(() => planGaslessPayment({
      paymentBaseUnits: "1.5",
      relayerFeeBaseUnits: 0n,
      shieldedBalanceBaseUnits: 0n,
    })).toThrow(/base units/);

    expect(() => planGaslessPayment({
      paymentBaseUnits: 1n,
      relayerFeeBaseUnits: 1n,
      shieldedBalanceBaseUnits: 1n,
      feeHeadroomBasisPoints: 10_001,
    })).toThrow(/basis points/);
  });

  it("accepts hex base units as readily as decimal", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: "0xff",
      relayerFeeBaseUnits: "0x1",
      shieldedBalanceBaseUnits: "256",
    });

    expect(plan.paymentBaseUnits).toBe(255n);
    expect(plan.requiredBaseUnits).toBe(256n);
    expect(plan.sufficient).toBe(true);
  });

  it("accepts the u128 ceiling and rejects a step past it", () => {
    expect(() => assertU128Amount(U128_MAX)).not.toThrow();
    expect(() => assertU128Amount(0n)).not.toThrow();
    expect(() => assertU128Amount(U128_MAX + 1n)).toThrow(/u128/);
    expect(() => assertU128Amount(-1n, "relayer fee")).toThrow(/relayer fee cannot be negative/);
  });
});

describe("describeGaslessPlan", () => {
  it("names the fee and the total rather than calling the payment free", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: "1000000000000000000",
      relayerFeeBaseUnits: "10000000000000000",
      shieldedBalanceBaseUnits: "2000000000000000000",
    });
    const text = describeGaslessPlan(plan, STRK);

    expect(text).toContain("0.01 STRK");
    expect(text).toContain("1.01 STRK");
    expect(text).toMatch(/needs no STRK or ETH for gas/);
    expect(text).not.toMatch(/\bfree\b/i);
  });

  it("quantifies a shortfall instead of only reporting failure", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: "1000000000000000000",
      relayerFeeBaseUnits: "10000000000000000",
      shieldedBalanceBaseUnits: "1000000000000000000",
    });

    expect(describeGaslessPlan(plan, STRK)).toContain("Short by 0.01 STRK");
  });

  it("says the dapp-submitted route is unavailable rather than implying it works", () => {
    const plan = planGaslessPayment({
      paymentBaseUnits: 1n,
      relayerFeeBaseUnits: 1n,
      shieldedBalanceBaseUnits: 1n,
      route: "dapp_submitted",
    });

    expect(describeGaslessPlan(plan, STRK)).toMatch(/unavailable/i);
  });
});

describe("buildWalletRelayedActions", () => {
  it("emits one transfer action with a FELT-conformant amount and normalised addresses", () => {
    const actions = buildWalletRelayedActions({ recipient: MERCHANT, amountBaseUnits: "1000000000000000000" });

    expect(actions).toHaveLength(1);
    expect(actions[0].type).toBe("transfer");
    expect(actions[0].amount).toBe("0xde0b6b3a7640000");
    expect(actions[0].amount).toMatch(FELT_PATTERN);
    expect(BigInt(actions[0].amount)).toBe(1_000_000_000_000_000_000n);
    expect(BigInt(actions[0].recipient)).toBe(BigInt(MERCHANT));
    expect(BigInt(actions[0].token)).toBe(BigInt(STRK_TOKEN_ADDRESS));
  });

  it("does not encode a fee withdrawal, because the wallet appends its own", () => {
    // Regression guard for the double-charge: wallet_strk20InvokeTransaction adds a
    // withdraw action for the paymaster/relayer fee on top of whatever the dapp supplies.
    const actions = buildWalletRelayedActions({ recipient: MERCHANT, amountBaseUnits: 5n });

    expect(actions.map((action) => action.type)).toEqual(["transfer"]);
  });

  it("refuses a zero or oversized transfer and an invalid recipient", () => {
    expect(() => buildWalletRelayedActions({ recipient: MERCHANT, amountBaseUnits: 0n })).toThrow(/positive amount/);
    expect(() => buildWalletRelayedActions({ recipient: MERCHANT, amountBaseUnits: U128_MAX + 1n })).toThrow(/u128/);
    expect(() => buildWalletRelayedActions({ recipient: "not-an-address", amountBaseUnits: 1n })).toThrow();
  });
});

describe("buildDappSubmittedActions", () => {
  it("encodes the fee withdrawal the dapp is responsible for on that route", () => {
    const actions = buildDappSubmittedActions({
      recipient: MERCHANT,
      amountBaseUnits: 1000n,
      feeRecipient: FEE_RECIPIENT,
      relayerFeeBaseUnits: 7n,
    });

    expect(actions.map((action) => action.type)).toEqual(["transfer", "withdraw"]);
    expect(actions[1].amount).toBe("0x7");
    expect(actions[1].amount).toMatch(FELT_PATTERN);
    expect(BigInt(actions[1].recipient)).toBe(BigInt(FEE_RECIPIENT));
    // The fee leaves the pool in the same token as the payment.
    expect(actions[1].token).toBe(actions[0].token);
  });

  it("refuses to build a dapp-submitted batch with nothing to pay the submitter", () => {
    expect(() => buildDappSubmittedActions({
      recipient: MERCHANT,
      amountBaseUnits: 1000n,
      feeRecipient: FEE_RECIPIENT,
      relayerFeeBaseUnits: 0n,
    })).toThrow(/positive relayer fee/);
  });
});

describe("isProofAnchorStale", () => {
  it("expires an anchor exactly one block past the validity window", () => {
    expect(DEFAULT_PROOF_VALIDITY_BLOCKS).toBe(450);
    expect(isProofAnchorStale(1000, 1450)).toBe(false);
    expect(isProofAnchorStale(1000, 1451)).toBe(true);
    expect(isProofAnchorStale(1000, 1000)).toBe(false);
  });

  it("reads a tip behind the anchor as a lagging tip, not an expired proof", () => {
    expect(isProofAnchorStale(1000, 990)).toBe(false);
    expect(blocksUntilProofAnchorExpiry(1000, 990)).toBe(DEFAULT_PROOF_VALIDITY_BLOCKS);
  });

  it("counts down the remaining window and floors it at zero", () => {
    expect(blocksUntilProofAnchorExpiry(1000, 1000)).toBe(450);
    expect(blocksUntilProofAnchorExpiry(1000, 1440)).toBe(10);
    expect(blocksUntilProofAnchorExpiry(1000, 1450)).toBe(0);
    expect(blocksUntilProofAnchorExpiry(1000, 9999)).toBe(0);
  });

  it("honours a governance window other than the default", () => {
    expect(isProofAnchorStale(1000, 1100, 100)).toBe(false);
    expect(isProofAnchorStale(1000, 1101, 100)).toBe(true);
  });

  it("rejects nonsense block numbers and windows", () => {
    expect(() => isProofAnchorStale(-1, 10)).toThrow(/anchor block/);
    expect(() => isProofAnchorStale(1.5, 10)).toThrow(/anchor block/);
    expect(() => isProofAnchorStale(10, -1)).toThrow(/tip block/);
    expect(() => isProofAnchorStale(10, 20, 0)).toThrow(/validity window/);
  });
});

describe("mapWalletGaslessError", () => {
  it("explains each documented STRK20 error from its code", () => {
    const cases = [
      ["NOT_REGISTERED", /registered with the STRK20 pool/],
      ["INSUFFICIENT_PRIVATE_BALANCE", /shielded balance does not cover/],
      ["PRIVACY_LEAK", /leaked linkable information/],
      ["INVALID_REQUEST_PAYLOAD", /malformed/],
      ["USER_REFUSED_OP", /declined the request/],
      ["API_VERSION_NOT_SUPPORTED", /Wallet API version/],
    ] as const;

    for (const [code, expected] of cases) {
      const explained = mapWalletGaslessError({ code, message: "wallet said no" });
      expect(explained.code).toBe(code);
      expect(explained.message).toMatch(expected);
      expect(explained.walletMessage).toBe("wallet said no");
    }
  });

  it("recognises the documented condition from prose as well as from a code", () => {
    expect(mapWalletGaslessError(new Error("Insufficient private balance for this transfer")).code)
      .toBe("INSUFFICIENT_PRIVATE_BALANCE");
    expect(mapWalletGaslessError("account is not registered").code).toBe("NOT_REGISTERED");
  });

  it("falls back to UNKNOWN_ERROR rather than guessing at an undocumented failure", () => {
    const explained = mapWalletGaslessError(new Error("socket hang up"));

    expect(explained.code).toBe("UNKNOWN_ERROR");
    expect(explained.walletMessage).toBe("socket hang up");
    expect(mapWalletGaslessError(undefined).walletMessage).toBeUndefined();
  });

  it("never reports a submitted transaction, because every documented case precedes submission", () => {
    const codes = [
      "NOT_REGISTERED", "INSUFFICIENT_PRIVATE_BALANCE", "PRIVACY_LEAK",
      "INVALID_REQUEST_PAYLOAD", "USER_REFUSED_OP", "API_VERSION_NOT_SUPPORTED", "anything else",
    ];

    for (const code of codes) {
      const explained = mapWalletGaslessError({ code });
      expect(explained.submitted).toBe(false);
      expect(explained.message).not.toMatch(/transaction hash 0x/i);
    }
  });

  it("marks a payer-fixable failure as recoverable and a protocol refusal as not", () => {
    expect(mapWalletGaslessError({ code: "INSUFFICIENT_PRIVATE_BALANCE" }).recoverable).toBe(true);
    expect(mapWalletGaslessError({ code: "USER_REFUSED_OP" }).recoverable).toBe(true);
    expect(mapWalletGaslessError({ code: "PRIVACY_LEAK" }).recoverable).toBe(false);
    expect(mapWalletGaslessError({ code: "INVALID_REQUEST_PAYLOAD" }).recoverable).toBe(false);
  });
});

describe("buildInvoiceTermsTypedData", () => {
  const terms = {
    invoiceId: "inv-2026-0001",
    recipientAddress: MERCHANT,
    amountBaseUnits: "1000000000000000000",
    expiresAt: "2026-09-01T00:00:00.000Z",
  };

  it("produces SNIP-12 revision 1 typed data bound to SN_MAIN and the STRK20 pool", () => {
    const typedData = buildInvoiceTermsTypedData(terms);

    expect(typedData.primaryType).toBe("InvoiceTerms");
    expect(typedData.domain.revision).toBe("1");
    expect(typedData.domain.chainId).toBe("SN_MAIN");
    expect(typedData.types.StarknetDomain).toBeDefined();
    expect(typedData.message).toMatchObject({ amount: "1000000000000000000", expiresAt: terms.expiresAt });
  });

  it("hashes deterministically, pinning the encoding against a starknet.js change", () => {
    const hash = getInvoiceTermsMessageHash(buildInvoiceTermsTypedData(terms), PAYER);

    expect(hash).toBe("0x7d5744183d0eddc88843947646aa991183a6ca98a4cb3ba89b317af8f6bf56f");
    expect(getInvoiceTermsMessageHash(buildInvoiceTermsTypedData(terms), PAYER)).toBe(hash);
  });

  it("binds the hash to the signing account, so one merchant's signature is not another's", () => {
    const typedData = buildInvoiceTermsTypedData(terms);

    expect(getInvoiceTermsMessageHash(typedData, PAYER)).not.toBe(getInvoiceTermsMessageHash(typedData, MERCHANT));
  });

  it("changes the hash when any term changes", () => {
    const baseline = getInvoiceTermsMessageHash(buildInvoiceTermsTypedData(terms), PAYER);
    const variants = [
      { ...terms, amountBaseUnits: "1000000000000000001" },
      { ...terms, expiresAt: "2026-09-01T00:00:01.000Z" },
      { ...terms, invoiceId: "inv-2026-0002" },
      { ...terms, payloadDigest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" },
      { ...terms, recipientAddress: FEE_RECIPIENT },
    ];

    for (const variant of variants) {
      expect(getInvoiceTermsMessageHash(buildInvoiceTermsTypedData(variant), PAYER)).not.toBe(baseline);
    }
  });

  it("carries an invoice id past the 31-character short-string ceiling without truncating it", () => {
    const long = "inv-2026-0001-milestone-discovery-phase";
    expect(long.length).toBeGreaterThan(31);

    const longHash = getInvoiceTermsMessageHash(buildInvoiceTermsTypedData({ ...terms, invoiceId: long }), PAYER);
    const clippedHash = getInvoiceTermsMessageHash(
      buildInvoiceTermsTypedData({ ...terms, invoiceId: long.slice(0, 31) }),
      PAYER,
    );

    expect(longHash).not.toBe(clippedHash);
  });

  it("rejects terms it cannot faithfully encode", () => {
    expect(() => buildInvoiceTermsTypedData({ ...terms, invoiceId: "   " })).toThrow(/invoice id/);
    expect(() => buildInvoiceTermsTypedData({ ...terms, expiresAt: "next tuesday" })).toThrow(/expiry/);
    expect(() => buildInvoiceTermsTypedData({ ...terms, amountBaseUnits: U128_MAX + 1n })).toThrow(/u128/);
    expect(() => buildInvoiceTermsTypedData({ ...terms, recipientAddress: "0xnope" })).toThrow();
  });
});

describe("verifyInvoiceTermsAttestation", () => {
  const terms = buildInvoiceTermsTypedData({
    invoiceId: "inv-2026-0001",
    recipientAddress: MERCHANT,
    amountBaseUnits: "1000000000000000000",
    expiresAt: "2026-09-01T00:00:00.000Z",
  });

  it("asks the merchant's account contract about the exact hash it reports", async () => {
    const seen: Array<{ account: string; hash: string; signature: readonly string[] }> = [];
    const result = await verifyInvoiceTermsAttestation({
      terms,
      signerAddress: MERCHANT,
      signature: ["0x1", "0x2"],
      isValidSignature: async (account, hash, signature) => {
        seen.push({ account, hash, signature });
        return true;
      },
    });

    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(seen).toHaveLength(1);
    expect(seen[0].hash).toBe(result.messageHash);
    expect(seen[0].hash).toBe(getInvoiceTermsMessageHash(terms, MERCHANT));
    expect(BigInt(seen[0].account)).toBe(BigInt(MERCHANT));
  });

  it("reports a rejected signature without calling the invoice fraudulent", async () => {
    const result = await verifyInvoiceTermsAttestation({
      terms,
      signerAddress: MERCHANT,
      signature: ["0x1"],
      isValidSignature: async () => false,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/did not accept this signature/);
    expect(result.reason).not.toMatch(/fraud/i);
  });

  it("treats an absent signature as unattested rather than invalid", async () => {
    let called = false;
    const result = await verifyInvoiceTermsAttestation({
      terms,
      signerAddress: MERCHANT,
      signature: [],
      isValidSignature: async () => {
        called = true;
        return true;
      },
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/unattested/);
    expect(called).toBe(false);
  });

  it("does not report a valid attestation when the check itself failed", async () => {
    const result = await verifyInvoiceTermsAttestation({
      terms,
      signerAddress: MERCHANT,
      signature: ["0x1"],
      isValidSignature: async () => { throw new Error("RPC unreachable"); },
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/could not be checked: RPC unreachable/);
  });
});

describe("gasless disclosure copy", () => {
  const text = [GASLESS_NOTICE, ...GASLESS_LIMITATIONS].join(" ");

  it("says where the fee comes from instead of calling the payment free", () => {
    expect(text).toMatch(/paymaster or relayer fee required to submit, drawn from your shielded balance/);
    expect(text).toMatch(/not free/i);
    expect(text).not.toMatch(/\bno fee\b|\bzero fee\b|\bfee-free\b|\bcompletely free\b|\bfor free\b/i);
  });

  it("does not claim CipherBill operates a relayer or holds funds", () => {
    expect(text).toMatch(/CipherBill does not run a relayer or a paymaster/);
    expect(text).toMatch(/never sees or holds your funds/);
    expect(text).not.toMatch(/our relayer|CipherBill's relayer|CipherBill relays/i);
  });

  it("denies the meta-transaction framing rather than borrowing it", () => {
    expect(text).toMatch(/Nothing here is a meta-transaction/);
    expect(text).toMatch(/zero-knowledge proof and nullifiers/);
    expect(text).not.toMatch(/signed meta-transaction|meta-transaction relayer|outside execution/i);
  });

  it("keeps the credit with the protocol and states what stays public", () => {
    expect(GASLESS_NOTICE).toMatch(/not something CipherBill adds/);
    expect(text).toMatch(/only movement inside the pool is hidden/i);
    expect(text).toMatch(/submitting address is public/);
    // The sender of a relayed transaction is the relayer's account for every user.
    expect(text).toMatch(/never be attributed to a transaction's sender/);
  });

  it("explains what turning the toggle off actually changes", () => {
    expect(text).toMatch(/skips CipherBill's local fee-reserve check/);
    expect(text).not.toMatch(/costs? gas from your account\b(?!\.)/i);
  });
});
