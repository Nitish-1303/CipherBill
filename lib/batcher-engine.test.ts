import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  assessBatchConcentration,
  buildBatchAmountDisclosure,
  buildBatchCertificateBadge,
  buildBatchInclusionProof,
  buildBatchOpening,
  buildBatchRecipientDisclosure,
  computeBatchState,
  createBatchIssuerKey,
  deriveBatchGenerator,
  estimateBatchEfficiency,
  formatBatchBaseUnits,
  formatInvoiceCount,
  formatMerchantCount,
  formatShare,
  getBatchVisibilityModel,
  issueBatchCertificate,
  MAX_BATCH_INVOICES,
  parseBatchAmountDisclosure,
  parseBatchCertificate,
  parseBatchCertificateSecret,
  parseBatchInclusionProof,
  parseBatchRecipientDisclosure,
  serializeBatchAmountDisclosure,
  serializeBatchCertificate,
  serializeBatchCertificateSecret,
  serializeBatchInclusionProof,
  serializeBatchRecipientDisclosure,
  summarizeBatchTrust,
  verifyBatchAmountDisclosure,
  verifyBatchCertificate,
  verifyBatchInclusionProof,
  verifyBatchOpening,
  verifyBatchRecipientDisclosure,
  type BatchCertificate,
  type BatchInvoiceInput,
  type IssueBatchCertificateInput,
} from "./batcher-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T00:00:00.000Z");
const PROOF_TIMEOUT = 60_000;

/** Deterministic, collision-free entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `batch_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}
function issuerKey(seed = "issuer") {
  return createBatchIssuerKey(makeEntropy(seed));
}

/** Four invoices across three merchant labels; total 100000. */
const BASE_INVOICES: BatchInvoiceInput[] = [
  { merchantLabel: "Acme", invoiceRef: "INV-1", amountBaseUnits: "40000", recipientRef: "acct_a" },
  { merchantLabel: "Acme", invoiceRef: "INV-2", amountBaseUnits: "20000", recipientRef: "acct_b" },
  { merchantLabel: "Globex", invoiceRef: "INV-3", amountBaseUnits: "30000" },
  { merchantLabel: "Initech", invoiceRef: "INV-4", amountBaseUnits: "10000", recipientRef: "acct_c" },
];

function baseInput(overrides: Partial<IssueBatchCertificateInput> = {}): IssueBatchCertificateInput {
  return {
    operatorAlias: "Aurora Treasury",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    batchRef: "BATCH-2026-0007",
    batchLabel: "August cross-merchant settlement",
    invoices: BASE_INVOICES,
    declaredBatchTotalBaseUnits: "100000",
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 16,
    ...overrides,
  };
}

function clone(certificate: BatchCertificate): BatchCertificate {
  return JSON.parse(JSON.stringify(certificate)) as BatchCertificate;
}
describe("pure batch reconciliation, concentration, and efficiency", () => {
  it("reconciles totals, per-merchant subtotals, shares, and concentration", () => {
    const state = computeBatchState(BASE_INVOICES);
    expect(state).toMatchObject({
      invoiceCount: 4,
      merchantCount: 3,
      totalBaseUnits: "100000",
      largestInvoiceBaseUnits: "40000",
      concentrationBps: "6000",
    });
    expect(state.lines[0]).toMatchObject({ index: 0, merchantLabel: "Acme", amountBaseUnits: "40000", shareBps: "4000" });
    const acme = state.merchants.find((m) => m.merchantLabel === "Acme");
    expect(acme).toMatchObject({ invoiceCount: 2, subtotalBaseUnits: "60000", shareBps: "6000" });
  });

  it("bands concentration deterministically, calling a single-merchant batch critical", () => {
    expect(assessBatchConcentration(computeBatchState(BASE_INVOICES)).band).toBe("high");
    const single = computeBatchState([
      { merchantLabel: "Acme", invoiceRef: "A1", amountBaseUnits: "10" },
      { merchantLabel: "Acme", invoiceRef: "A2", amountBaseUnits: "20" },
    ]);
    expect(assessBatchConcentration(single).band).toBe("critical");
  });

  it("estimates illustrative aggregation without claiming an on-chain cost", () => {
    const estimate = estimateBatchEfficiency(computeBatchState(BASE_INVOICES), 16);
    expect(estimate).toMatchObject({
      illustrative: true,
      invoiceCount: 4,
      perInvoiceProofElements: 16,
      batchedProofElements: 64,
      signaturesForBatch: 1,
      signaturesIfSeparate: 4,
    });
    expect(estimate.aggregationNote).toMatch(/not a measured on-chain gas/i);
  });

  it("validates invoice input bounds", () => {
    expect(() => computeBatchState([])).toThrow(/at least/i);
    const tooMany = Array.from({ length: MAX_BATCH_INVOICES + 1 }, (_, i) => ({
      merchantLabel: "M",
      invoiceRef: `R${i}`,
      amountBaseUnits: "1",
    }));
    expect(() => computeBatchState(tooMany)).toThrow(/at most/i);
  });
});
describe("certificate lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a batch certificate", () => {
    const { certificate, secret } = issueBatchCertificate(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(certificate.proof.proofSystem).toBe("stark-pedersen-batch-reconciliation-v1");
    expect(certificate.invoiceCount).toBe(4);
    expect(certificate.merchantCount).toBe(3);
    expect(certificate.declaredBatchTotalBaseUnits).toBe("100000");
    expect(verifyBatchCertificate(certificate)).toBe(true);

    const round = parseBatchCertificate(serializeBatchCertificate(certificate));
    expect(round.bindingHash).toBe(certificate.bindingHash);
    expect(verifyBatchCertificate(round)).toBe(true);

    expect(secret.invoices).toHaveLength(4);
    const secretRound = parseBatchCertificateSecret(serializeBatchCertificateSecret(secret));
    expect(secretRound).toMatchObject({ certificateId: secret.certificateId, declaredBatchTotalBaseUnits: "100000" });
  });

  it("verifies a trivial single-invoice batch", () => {
    const { certificate } = issueBatchCertificate(
      baseInput({ invoices: [{ merchantLabel: "Solo", invoiceRef: "S1", amountBaseUnits: "500" }], declaredBatchTotalBaseUnits: "500" }),
      NOW,
      makeEntropy("solo"),
    );
    expect(certificate.invoiceCount).toBe(1);
    expect(verifyBatchCertificate(certificate)).toBe(true);
  });

  it("verifies a wider 64-bit institutional-scale batch", { timeout: 120_000 }, () => {
    const { certificate } = issueBatchCertificate(
      baseInput({
        invoices: [
          { merchantLabel: "Acme", invoiceRef: "L1", amountBaseUnits: "1000000000000" },
          { merchantLabel: "Globex", invoiceRef: "L2", amountBaseUnits: "2000000000000" },
        ],
        declaredBatchTotalBaseUnits: "3000000000000",
        amountBitLength: 64,
      }),
      NOW,
      makeEntropy("wide"),
    );
    expect(verifyBatchCertificate(certificate)).toBe(true);
  });

  it("builds a badge with public display only and no secret figures", () => {
    const { certificate, secret } = issueBatchCertificate(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildBatchCertificateBadge(certificate);
    expect(badge.invoiceCountDisplay).toBe("4 invoices");
    expect(badge.merchantCountDisplay).toBe("3 merchants");
    expect(badge.batchRoot).toBe(certificate.proof.batchRoot);
    const json = JSON.stringify(badge);
    for (const invoice of secret.invoices) expect(json).not.toContain(invoice.blinding);
  });
});
describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest a declared total that is not the sum of the invoice amounts", () => {
    expect(() => issueBatchCertificate(baseInput({ declaredBatchTotalBaseUnits: "99999" }), NOW, makeEntropy("g1"))).toThrow(
      /does not equal the sum/i,
    );
  });

  it("rejects an invoice amount outside the provable bit band", () => {
    expect(() =>
      issueBatchCertificate(
        baseInput({
          invoices: [{ merchantLabel: "Acme", invoiceRef: "X", amountBaseUnits: (1n << 16n).toString() }],
          declaredBatchTotalBaseUnits: (1n << 16n).toString(),
        }),
        NOW,
        makeEntropy("g2"),
      ),
    ).toThrow(/16-bit band/i);
  });

  it("rejects a missing operator alias and a malformed token address", () => {
    expect(() => issueBatchCertificate(baseInput({ operatorAlias: "   " }), NOW, makeEntropy("g3"))).toThrow(/operator alias/i);
    expect(() =>
      issueBatchCertificate(baseInput({ asset: { symbol: "STRK", tokenAddress: "not-an-address", decimals: 18 } }), NOW, makeEntropy("g4")),
    ).toThrow(/0x prefix/i);
  });

  it("rejects an over-long invoice reference", () => {
    expect(() =>
      issueBatchCertificate(
        baseInput({ invoices: [{ merchantLabel: "Acme", invoiceRef: "R".repeat(97), amountBaseUnits: "1" }], declaredBatchTotalBaseUnits: "1" }),
        NOW,
        makeEntropy("g5"),
      ),
    ).toThrow(/reference/i);
  });

  it("rejects a malformed issuer secret key", () => {
    expect(() => issueBatchCertificate(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("g6"))).toThrow(/scalar/i);
  });
});
describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueBatchCertificate(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyBatchCertificate(issued.certificate)).toBe(true);
  });

  it("rejects a changed public declared total", () => {
    const v = clone(issued.certificate);
    v.declaredBatchTotalBaseUnits = "100001";
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects a changed merchant count", () => {
    const v = clone(issued.certificate);
    v.merchantCount = 2;
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects an altered batch root", () => {
    const v = clone(issued.certificate);
    v.proof.batchRoot = v.proof.batchRoot === "0x0" ? "0x1" : `${v.proof.batchRoot}0`;
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const v = clone(issued.certificate);
    v.bindingHash = v.bindingHash === "0x0" ? "0x1" : `${v.bindingHash}0`;
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const v = clone(issued.certificate);
    v.issuerSignature = { ...v.issuerSignature, response: "0x1" };
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects a tampered range-proof bit", () => {
    const v = clone(issued.certificate);
    v.proof.invoices[0].bits[0] = { ...v.proof.invoices[0].bits[0], response0: "0x1" };
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects a tampered sum-reconciliation response", () => {
    const v = clone(issued.certificate);
    v.proof.sumReconciliation = { ...v.proof.sumReconciliation, response: "0x1" };
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const v = clone(issued.certificate);
    v.proof.generatorH = { ...v.issuerPublicKey };
    expect(verifyBatchCertificate(v)).toBe(false);
  });

  it("rejects a corrupted invoice commitment", () => {
    const v = clone(issued.certificate);
    v.proof.invoices[0].commitment = { x: "0x1", y: "0x1" };
    expect(verifyBatchCertificate(v)).toBe(false);
  });
});
describe("selective disclosure, openings, and inclusion", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueBatchCertificate(baseInput(), NOW, makeEntropy("disc"));

  it("discloses a single invoice amount and verifies it", () => {
    const disclosure = buildBatchAmountDisclosure(issued.secret, 0);
    expect(disclosure.amountBaseUnits).toBe("40000");
    expect(verifyBatchAmountDisclosure(issued.certificate, disclosure)).toBe(true);

    const round = parseBatchAmountDisclosure(serializeBatchAmountDisclosure(disclosure));
    expect(verifyBatchAmountDisclosure(issued.certificate, round)).toBe(true);
    expect(verifyBatchAmountDisclosure(issued.certificate, { ...disclosure, amountBaseUnits: "1" })).toBe(false);
    expect(verifyBatchAmountDisclosure(issued.certificate, { ...disclosure, certificateId: "batch_other" })).toBe(false);
  });

  it("discloses a committed recipient reference and verifies it", () => {
    const disclosure = buildBatchRecipientDisclosure(issued.secret, 0);
    expect(disclosure.value).toBe("acct_a");
    expect(verifyBatchRecipientDisclosure(issued.certificate, disclosure)).toBe(true);
    const round = parseBatchRecipientDisclosure(serializeBatchRecipientDisclosure(disclosure));
    expect(verifyBatchRecipientDisclosure(issued.certificate, round)).toBe(true);
    expect(verifyBatchRecipientDisclosure(issued.certificate, { ...disclosure, value: "acct_x" })).toBe(false);
  });

  it("refuses to disclose a recipient for an uncommitted invoice", () => {
    expect(() => buildBatchRecipientDisclosure(issued.secret, 2)).toThrow(/no committed recipient/i);
  });

  it("verifies a full opening and rejects a wrong figure", () => {
    const opening = buildBatchOpening(issued.secret);
    expect(verifyBatchOpening(issued.certificate, opening)).toBe(true);
    const wrong = { invoices: opening.invoices.map((entry, i) => (i === 0 ? { ...entry, amountBaseUnits: "1" } : entry)) };
    expect(verifyBatchOpening(issued.certificate, wrong)).toBe(false);
  });

  it("proves Merkle inclusion of one invoice against just the batch root", () => {
    const inclusion = buildBatchInclusionProof(issued.certificate, 2);
    expect(verifyBatchInclusionProof(issued.certificate, inclusion)).toBe(true);
    const round = parseBatchInclusionProof(serializeBatchInclusionProof(inclusion));
    expect(verifyBatchInclusionProof(issued.certificate, round)).toBe(true);
    expect(verifyBatchInclusionProof(issued.certificate, { ...inclusion, leafHash: "0x1" })).toBe(false);
  });
});
describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds any invoice amount, blinding, salt, or recipient in the certificate", () => {
    const { certificate, secret } = issueBatchCertificate(
      baseInput({
        invoices: [
          { merchantLabel: "Acme", invoiceRef: "H1", amountBaseUnits: "31337", recipientRef: "SECRET-RECIP-ZZZ" },
          { merchantLabel: "Globex", invoiceRef: "H2", amountBaseUnits: "13337" },
        ],
        declaredBatchTotalBaseUnits: "44674",
      }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyBatchCertificate(certificate)).toBe(true);

    const structured = JSON.stringify(certificate);
    const serialized = serializeBatchCertificate(certificate);
    for (const surface of [structured, serialized]) {
      for (const invoice of secret.invoices) {
        expect(surface).not.toContain(invoice.blinding);
        expect(surface).not.toContain(invoice.recipientSalt);
      }
      expect(surface).not.toContain("31337");
      expect(surface).not.toContain("13337");
      expect(surface).not.toContain("SECRET-RECIP-ZZZ");
    }
    // The public batch total and invoice refs are deliberately disclosed.
    expect(structured).toContain("44674");
    expect(structured).toContain("H1");
  });

  it("keeps identical batches unlinkable by producing distinct commitments", () => {
    const a = issueBatchCertificate(baseInput(), NOW, makeEntropy("ua"));
    const b = issueBatchCertificate(baseInput(), NOW, makeEntropy("ub"));
    expect(a.certificate.proof.invoices[0].commitment.x).not.toBe(b.certificate.proof.invoices[0].commitment.x);
    expect(verifyBatchCertificate(a.certificate)).toBe(true);
    expect(verifyBatchCertificate(b.certificate)).toBe(true);
  });
});
describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeBatchTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesInvoiceAmountsAreBoundedNonNegative).toBe(true);
    expect(trust.provesBatchSumEqualsDeclaredTotal).toBe(true);
    expect(trust.bindsAllInvoicesUnderOneSignedRoot).toBe(true);
    expect(trust.hidesIndividualInvoiceAmounts).toBe(true);
    expect(trust.hidesRecipientAddresses).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.supportsSelectiveDisclosure).toBe(true);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.settlesOrDisbursesFunds).toBe(false);
    expect(trust.settlesOnChain).toBe(false);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.reducesOnChainGas).toBe(false);
    expect(trust.callsPoolContract).toBe(false);
    expect(trust.verifiesInvoicesAreRealOrSettled).toBe(false);
    expect(trust.observesRealPaymentStreams).toBe(false);
    expect(trust.metricsAreMeasuredOnChain).toBe(false);
    expect(trust.statement).toContain("neither decentralized nor automatic");
    expect(trust.statement).toContain("does not settle, disburse, net, or move any funds");
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getBatchVisibilityModel();
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
    expect(model.applicationOnly.length).toBeGreaterThan(0);
  });
});

describe("generator and formatting helpers", () => {
  it("derives a stable, canonical generator H", () => {
    const a = deriveBatchGenerator();
    const b = deriveBatchGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
  });

  it("formats shares, counts, and base-unit amounts for display", () => {
    expect(formatShare(6250)).toBe("62.5%");
    expect(formatInvoiceCount(1)).toBe("1 invoice");
    expect(formatInvoiceCount(4)).toBe("4 invoices");
    expect(formatMerchantCount(1)).toBe("1 merchant");
    expect(formatMerchantCount(3)).toBe("3 merchants");
    expect(formatBatchBaseUnits("200000000000000000000", 18)).toBe("200");
    expect(formatBatchBaseUnits("1500", 0)).toBe("1500");
  });

  it("rejects a malformed encoded certificate", () => {
    expect(() => parseBatchCertificate("!!not base64!!")).toThrow(/encoding is invalid/i);
  });
});
