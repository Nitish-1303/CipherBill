import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  buildClaimReceipt,
  buildCreditNoteBadge,
  createRefundClaimKey,
  createRefundIssuerKey,
  deriveRefundGenerator,
  formatRefundBaseUnits,
  getRefundVisibilityModel,
  issueCreditNote,
  openCreditNote,
  parseClaimReceipt,
  parseCreditNote,
  parseCreditNoteSecret,
  serializeClaimReceipt,
  serializeCreditNote,
  serializeCreditNoteSecret,
  summarizeRefundTrust,
  verifyClaimReceipt,
  verifyCreditNote,
  verifyCreditNoteOpening,
  type IssueCreditNoteInput,
  type RefundAsset,
} from "./refund-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const ASSET: RefundAsset = { symbol: "USDC", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 0 };
const NOW = new Date("2026-08-23T00:00:00.000Z");
// Two bit-range legs run many curve multiplications in pure JS; give crypto-heavy
// suites ample headroom so a loaded CI box never trips the 5s default mid-proof.
const PROOF_TIMEOUT = 60_000;

/** Deterministic entropy: stable per-seed ids and a reproducible stream of nonzero scalars. */
function makeEntropy(seed = 1) {
  let idCounter = 0;
  let counter = 0;
  return {
    createId: () => `cn_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () => {
      counter += 1;
      const v = BigInt(hash.computePoseidonHashOnElements([BigInt(seed), BigInt(counter)]));
      return (v % (CURVE_ORDER - 1n)) + 1n;
    },
  };
}

/** Issues a note with independent deterministic issuer and claim keys for the seed. */
function issue(overrides: Partial<IssueCreditNoteInput> = {}, seed = 1) {
  const issuer = createRefundIssuerKey(makeEntropy(seed + 101));
  const claim = createRefundClaimKey(makeEntropy(seed + 202));
  const input: IssueCreditNoteInput = {
    merchantAlias: "Northwind Labs",
    asset: ASSET,
    invoiceRef: "INV-2026-0042",
    refundBaseUnits: "40",
    invoiceCeilingBaseUnits: "100",
    claimPublicKey: claim.publicKey,
    issuerSecretKey: issuer.secretKey,
    bitLength: 16,
    memo: "Partial refund",
    ...overrides,
  };
  const issued = issueCreditNote(input, NOW, makeEntropy(seed));
  return { ...issued, issuer, claim };
}

describe("credit note lifecycle", { timeout: PROOF_TIMEOUT }, () => {
  it("issues a bounded-range credit note that verifies and round-trips", () => {
    const { note, secret } = issue();
    expect(note.kind).toBe("cipherbill.credit-note");
    expect(note.noteId).toMatch(/^cn_/);
    expect(note.proof.proofSystem).toBe("stark-pedersen-bounded-credit-v1");
    expect(note.proof.bitLength).toBe(16);
    expect(note.proof.lowerBits).toHaveLength(16);
    expect(note.proof.upperBits).toHaveLength(16);
    expect(note.invoiceCeilingBaseUnits).toBe("100");
    expect(verifyCreditNote(note)).toBe(true);
    expect(parseCreditNote(serializeCreditNote(note))).toEqual(note);
    expect(secret.kind).toBe("cipherbill.credit-note-opening");
    expect(parseCreditNoteSecret(serializeCreditNoteSecret(secret))).toEqual(secret);
  });

  it("proves the zero-refund boundary (a = 0)", () => {
    expect(verifyCreditNote(issue({ refundBaseUnits: "0" }).note)).toBe(true);
  });

  it("proves the full-invoice boundary (a = L)", () => {
    expect(verifyCreditNote(issue({ refundBaseUnits: "100", invoiceCeilingBaseUnits: "100" }).note)).toBe(true);
  });

  it("supports the full u128 bit length by default", () => {
    const { note } = issue({ bitLength: undefined, refundBaseUnits: "5000", invoiceCeilingBaseUnits: "1000000000000" });
    expect(note.proof.bitLength).toBe(128);
    expect(verifyCreditNote(note)).toBe(true);
  });
});

describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses a refund that exceeds the invoice it credits", () => {
    expect(() => issue({ refundBaseUnits: "101", invoiceCeilingBaseUnits: "100" })).toThrow(/exceeds the invoice total/i);
  });

  it("refuses an invoice ceiling outside the provable band", () => {
    expect(() => issue({ refundBaseUnits: "1", invoiceCeilingBaseUnits: "70000", bitLength: 16 })).toThrow(/provable.*band/i);
  });

  it("rejects an amount outside the u128 range", () => {
    const overflow = ((1n << 128n) + 5n).toString();
    expect(() => issue({ refundBaseUnits: overflow, invoiceCeilingBaseUnits: overflow, bitLength: 128 })).toThrow(/u128/i);
  });

  it("rejects a missing merchant alias", () => {
    expect(() => issue({ merchantAlias: "   " })).toThrow(/merchant alias/i);
  });
});

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  it("rejects a raised invoice ceiling", () => {
    const { note } = issue();
    expect(verifyCreditNote({ ...note, invoiceCeilingBaseUnits: "101" })).toBe(false);
  });

  it("rejects a tampered lower-leg bit response", () => {
    const { note } = issue();
    const lowerBits = note.proof.lowerBits.map((bit, i) =>
      i === 0 ? { ...bit, response0: "0x" + (BigInt(bit.response0) + 1n).toString(16) } : bit,
    );
    expect(verifyCreditNote({ ...note, proof: { ...note.proof, lowerBits } })).toBe(false);
  });

  it("rejects a tampered upper-leg bit response", () => {
    const { note } = issue();
    const upperBits = note.proof.upperBits.map((bit, i) =>
      i === 0 ? { ...bit, response1: "0x" + (BigInt(bit.response1) + 1n).toString(16) } : bit,
    );
    expect(verifyCreditNote({ ...note, proof: { ...note.proof, upperBits } })).toBe(false);
  });

  it("rejects a swapped amount commitment", () => {
    const a = issue({}, 1).note;
    const b = issue({}, 2).note;
    expect(verifyCreditNote({ ...a, proof: { ...a.proof, amountCommitment: b.proof.amountCommitment } })).toBe(false);
  });

  it("rejects a prover-substituted generator (unknown-DL requirement)", () => {
    const { note } = issue();
    const base = ec.starkCurve.ProjectivePoint.BASE;
    const malicious = { x: "0x" + base.x.toString(16), y: "0x" + base.y.toString(16) };
    expect(verifyCreditNote({ ...note, proof: { ...note.proof, generatorH: malicious } })).toBe(false);
  });

  it("rejects a tampered issuer signature", () => {
    const { note } = issue();
    const issuerSignature = { ...note.issuerSignature, response: "0x" + (BigInt(note.issuerSignature.response) + 1n).toString(16) };
    expect(verifyCreditNote({ ...note, issuerSignature })).toBe(false);
  });

  it("rejects a substituted issuer key", () => {
    const { note } = issue({}, 1);
    const other = issue({}, 2).note;
    expect(verifyCreditNote({ ...note, issuerPublicKey: other.issuerPublicKey })).toBe(false);
  });

  it("rejects a proof whose bit count no longer matches the declared length", () => {
    const { note } = issue();
    const lowerBits = note.proof.lowerBits.slice(0, -1);
    expect(verifyCreditNote({ ...note, proof: { ...note.proof, lowerBits } })).toBe(false);
  });

  it("rejects a tampered binding hash", () => {
    const { note } = issue();
    expect(verifyCreditNote({ ...note, bindingHash: "0x1" })).toBe(false);
  });
});

describe("recipient sealing and opening", { timeout: PROOF_TIMEOUT }, () => {
  it("opens with the correct claim key and matches the issuer's secret", () => {
    const { note, secret, claim } = issue();
    const opening = openCreditNote(note, claim.secretKey);
    expect(opening).not.toBeNull();
    expect(opening?.refundBaseUnits).toBe("40");
    expect(opening?.blinding).toBe(secret.blinding);
    expect(verifyCreditNoteOpening(note, opening!)).toBe(true);
  });

  it("does not open with the wrong claim key", () => {
    const { note } = issue();
    const stranger = createRefundClaimKey(makeEntropy(999));
    expect(openCreditNote(note, stranger.secretKey)).toBeNull();
  });

  it("rejects an opening that does not match the amount commitment", () => {
    const { note, secret } = issue();
    expect(verifyCreditNoteOpening(note, { refundBaseUnits: "41", blinding: secret.blinding })).toBe(false);
  });
});

describe("claim receipt (DLEQ)", { timeout: PROOF_TIMEOUT }, () => {
  it("builds a receipt that verifies and round-trips", () => {
    const { note, claim } = issue();
    const receipt = buildClaimReceipt(note, claim.secretKey, makeEntropy(7));
    expect(receipt.kind).toBe("cipherbill.credit-note-receipt");
    expect(verifyClaimReceipt(note, receipt)).toBe(true);
    expect(parseClaimReceipt(serializeClaimReceipt(receipt))).toEqual(receipt);
  });

  it("refuses to build a receipt from the wrong claimant", () => {
    const { note } = issue();
    const stranger = createRefundClaimKey(makeEntropy(999));
    expect(() => buildClaimReceipt(note, stranger.secretKey)).toThrow(/does not match/i);
  });

  it("does not verify a receipt against a different note", () => {
    const { note, claim } = issue({}, 1);
    const other = issue({}, 2).note;
    const receipt = buildClaimReceipt(note, claim.secretKey, makeEntropy(7));
    expect(verifyClaimReceipt(other, receipt)).toBe(false);
  });

  it("rejects a tampered nullifier", () => {
    const { note, claim } = issue();
    const receipt = buildClaimReceipt(note, claim.secretKey, makeEntropy(7));
    expect(verifyClaimReceipt(note, { ...receipt, nullifier: deriveRefundGenerator() })).toBe(false);
  });

  it("rejects a tampered response", () => {
    const { note, claim } = issue();
    const receipt = buildClaimReceipt(note, claim.secretKey, makeEntropy(7));
    const response = "0x" + (BigInt(receipt.response) + 1n).toString(16);
    expect(verifyClaimReceipt(note, { ...receipt, response })).toBe(false);
  });

  it("derives a stable per-note nullifier independent of proof randomness", () => {
    const { note, claim } = issue();
    const first = buildClaimReceipt(note, claim.secretKey, makeEntropy(7));
    const second = buildClaimReceipt(note, claim.secretKey, makeEntropy(8));
    expect(second.nullifier).toEqual(first.nullifier);
    expect(second.commitmentG).not.toEqual(first.commitmentG);
    expect(verifyClaimReceipt(note, second)).toBe(true);
  });
});

describe("zero-knowledge / hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("does not carry the secret refund or blinding in the published note", () => {
    const { note, secret } = issue({ refundBaseUnits: "1000042", invoiceCeilingBaseUnits: "2000000", bitLength: 32 });
    const plain = JSON.stringify(note);
    const encoded = serializeCreditNote(note);
    expect(plain).not.toContain("1000042");
    expect(plain).not.toContain(secret.blinding);
    expect(encoded).not.toContain(secret.blinding);
  });

  it("yields distinct commitments for different refunds under the same ceiling", () => {
    const low = issue({ refundBaseUnits: "40", invoiceCeilingBaseUnits: "100" }, 3).note;
    const high = issue({ refundBaseUnits: "60", invoiceCeilingBaseUnits: "100" }, 4).note;
    expect(low.proof.amountCommitment).not.toEqual(high.proof.amountCommitment);
    expect(verifyCreditNote(low)).toBe(true);
    expect(verifyCreditNote(high)).toBe(true);
  });
});

describe("honest disclosure model", () => {
  it("does not overstate the trust properties", () => {
    const trust = summarizeRefundTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesRefundWithinInvoice).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.sealsRefundToClaimant).toBe(true);
    expect(trust.provesOnChainSettlement).toBe(false);
    expect(trust.bindsToRealFunds).toBe(false);
    expect(trust.enforcesSingleRedemption).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.statement.toLowerCase()).toContain("neither decentralized nor automatic");
    expect(trust.statement.toLowerCase()).toContain("does not settle on-chain");
    expect(trust.statement.toLowerCase()).toContain("never reads from or writes to the strk20 pool contract");
  });

  it("is explicit that the engine never touches the pool contract", () => {
    const model = getRefundVisibilityModel();
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
    expect(model.applicationOnly.length).toBeGreaterThan(0);
    expect(model.limitation.toLowerCase()).toContain("never reads from or writes to the strk20 pool contract");
  });
});

describe("helpers", { timeout: PROOF_TIMEOUT }, () => {
  it("derives a stable independent generator", () => {
    expect(deriveRefundGenerator()).toEqual(deriveRefundGenerator());
  });

  it("tags generated keypairs with their role", () => {
    expect(createRefundIssuerKey(makeEntropy(11)).role).toBe("issuer");
    expect(createRefundClaimKey(makeEntropy(12)).role).toBe("claim");
  });

  it("summarizes a note into a shareable badge", () => {
    const { note } = issue();
    const badge = buildCreditNoteBadge(note);
    expect(badge.kind).toBe("cipherbill.credit-note-badge");
    expect(badge.invoiceCeilingDisplay).toBe("100");
    expect(badge.bindingHash).toBe(note.bindingHash);
  });

  it("formats integer base units as a decimal amount", () => {
    expect(formatRefundBaseUnits("1000000", 6)).toBe("1");
    expect(formatRefundBaseUnits("1500000", 6)).toBe("1.5");
    expect(formatRefundBaseUnits(500n, 0)).toBe("500");
  });

  it("rejects a malformed serialized note", () => {
    expect(() => parseCreditNote("!!not base64url!!")).toThrow(/encoding is invalid/i);
  });
});





