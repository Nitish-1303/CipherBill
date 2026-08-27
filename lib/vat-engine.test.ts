import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  buildVatTaxDisclosure,
  buildVatTaxIdDisclosure,
  buildVatVoucherBadge,
  computeVat,
  createVatIssuerKey,
  deriveVatGenerator,
  formatVatBaseUnits,
  formatVatRate,
  getVatJurisdictions,
  getVatVisibilityModel,
  issueVatVoucher,
  MAX_VAT_RATE_BASIS_POINTS,
  parseVatTaxDisclosure,
  parseVatTaxIdDisclosure,
  parseVatVoucher,
  parseVatVoucherSecret,
  serializeVatTaxDisclosure,
  serializeVatTaxIdDisclosure,
  serializeVatVoucher,
  serializeVatVoucherSecret,
  summarizeVatTrust,
  VAT_PROOF_SYSTEM,
  VAT_RATE_DENOMINATOR,
  verifyVatTaxDisclosure,
  verifyVatTaxIdDisclosure,
  verifyVatVoucher,
  verifyVatVoucherOpening,
  type IssueVatVoucherInput,
  type VatVoucher,
  type VatVoucherOpening,
  type VatVoucherSecret,
} from "./vat-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-23T00:00:00.000Z");
const PROOF_TIMEOUT = 120_000;

/** Deterministic, collision-free entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `vat_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createVatIssuerKey(makeEntropy(seed));
}

function baseInput(overrides: Partial<IssueVatVoucherInput> = {}): IssueVatVoucherInput {
  return {
    merchantAlias: "Aurora Studio",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    invoiceRef: "INV-2026-0007",
    jurisdictionCode: "GB",
    jurisdictionLabel: "United Kingdom — VAT",
    taxKind: "VAT",
    rateBasisPoints: 2000,
    netBaseUnits: "1000000000000000000000",
    customerTaxId: "GB123456789",
    issuerSecretKey: issuerKey().secretKey,
    ...overrides,
  };
}
describe("computeVat arithmetic", () => {
  it("computes an exact 20% VAT with no remainder", () => {
    const c = computeVat("1000000000000000000000", 2000);
    expect(c.taxBaseUnits).toBe("200000000000000000000");
    expect(c.grossBaseUnits).toBe("1200000000000000000000");
    expect(c.remainderBaseUnits).toBe("0");
    expect(c.rateBasisPoints).toBe("2000");
  });

  it("floors the tax and exposes the true remainder", () => {
    // 7 × 1900 = 13300 ⇒ tax = floor(13300/10000) = 1, rem = 3300, gross = 8.
    const c = computeVat("7", 1900);
    expect(c.taxBaseUnits).toBe("1");
    expect(c.remainderBaseUnits).toBe("3300");
    expect(c.grossBaseUnits).toBe("8");
  });

  it("treats a zero rate and a zero net as tax-free", () => {
    expect(computeVat("999", 0)).toMatchObject({ taxBaseUnits: "0", grossBaseUnits: "999", remainderBaseUnits: "0" });
    expect(computeVat("0", 2000)).toMatchObject({ taxBaseUnits: "0", grossBaseUnits: "0", remainderBaseUnits: "0" });
  });

  it("rejects an out-of-range rate, a non-integer net, and an oversized net", () => {
    expect(() => computeVat("1000", MAX_VAT_RATE_BASIS_POINTS + 1)).toThrow(/rate basis points/i);
    expect(() => computeVat("12.5", 2000)).toThrow(/base units/i);
    expect(() => computeVat(((1n << 128n)).toString(), 2000)).toThrow(/u128/i);
  });

  it("agrees with the exact division identity for a large net and awkward rate", () => {
    const c = computeVat("999999999999999999", 1234);
    const net = 999999999999999999n;
    const scaled = net * 1234n;
    expect(BigInt(c.taxBaseUnits)).toBe(scaled / VAT_RATE_DENOMINATOR);
    expect(BigInt(c.remainderBaseUnits)).toBe(scaled % VAT_RATE_DENOMINATOR);
    expect(BigInt(c.taxBaseUnits) * VAT_RATE_DENOMINATOR + BigInt(c.remainderBaseUnits)).toBe(scaled);
  });
});
describe("voucher lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a voucher", () => {
    const { voucher, secret } = issueVatVoucher(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(voucher.proof.proofSystem).toBe(VAT_PROOF_SYSTEM);
    expect(verifyVatVoucher(voucher)).toBe(true);

    const round = parseVatVoucher(serializeVatVoucher(voucher));
    expect(round.bindingHash).toBe(voucher.bindingHash);
    expect(verifyVatVoucher(round)).toBe(true);

    // The secret matches the pure arithmetic for the same inputs.
    const computed = computeVat(secret.netBaseUnits, Number(secret.rateBasisPoints));
    expect(secret.taxBaseUnits).toBe(computed.taxBaseUnits);
    expect(secret.grossBaseUnits).toBe(computed.grossBaseUnits);
    expect(secret.remainderBaseUnits).toBe(computed.remainderBaseUnits);

    const secretRound = parseVatVoucherSecret(serializeVatVoucherSecret(secret));
    expect(secretRound).toMatchObject({ netBaseUnits: secret.netBaseUnits, taxBaseUnits: secret.taxBaseUnits });
  });

  it("verifies a voucher whose division leaves a non-zero remainder", () => {
    const { voucher, secret } = issueVatVoucher(baseInput({ netBaseUnits: "7", rateBasisPoints: 1900 }), NOW, makeEntropy("rem"));
    expect(secret.remainderBaseUnits).toBe("3300");
    expect(secret.taxBaseUnits).toBe("1");
    expect(verifyVatVoucher(voucher)).toBe(true);
  });

  it("builds a badge with the public rate and no secret figures", () => {
    const { voucher, secret } = issueVatVoucher(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildVatVoucherBadge(voucher);
    expect(badge.rateDisplay).toBe("20.00%");
    expect(badge.taxIdCommitted).toBe(true);
    expect(badge.jurisdictionLabel).toBe("United Kingdom — VAT");
    const json = JSON.stringify(badge);
    expect(json).not.toContain(secret.netBaseUnits);
    expect(json).not.toContain(secret.taxBaseUnits);
    expect(json).not.toContain(secret.grossBaseUnits);
  });

  it("marks a B2C voucher (no tax ID) as uncommitted", () => {
    const { voucher } = issueVatVoucher(baseInput({ customerTaxId: "" }), NOW, makeEntropy("b2c"));
    expect(voucher.taxIdCommitted).toBe(false);
    expect(verifyVatVoucher(voucher)).toBe(true);
  });
});
describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("rejects an out-of-range rate", () => {
    expect(() => issueVatVoucher(baseInput({ rateBasisPoints: 12000 }), NOW, makeEntropy("g1"))).toThrow(/rate basis points/i);
  });

  it("rejects a fractional net amount", () => {
    expect(() => issueVatVoucher(baseInput({ netBaseUnits: "10.5" }), NOW, makeEntropy("g2"))).toThrow(/base units/i);
  });

  it("rejects a missing merchant alias and a malformed token address", () => {
    expect(() => issueVatVoucher(baseInput({ merchantAlias: "   " }), NOW, makeEntropy("g3"))).toThrow(/merchant alias/i);
    expect(() =>
      issueVatVoucher(baseInput({ asset: { symbol: "STRK", tokenAddress: "not-an-address", decimals: 18 } }), NOW, makeEntropy("g4")),
    ).toThrow(/0x prefix/i);
  });

  it("rejects a customer tax id that is too long", () => {
    expect(() => issueVatVoucher(baseInput({ customerTaxId: "X".repeat(65) }), NOW, makeEntropy("g5"))).toThrow(/tax id/i);
  });

  it("rejects a net that exceeds the provable bit band", () => {
    expect(() =>
      issueVatVoucher(baseInput({ netBaseUnits: (1n << 16n).toString(), netBitLength: 16 }), NOW, makeEntropy("g6")),
    ).toThrow(/16-bit band/i);
  });

  it("rejects a malformed issuer secret key", () => {
    expect(() => issueVatVoucher(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("g7"))).toThrow(/scalar/i);
  });
});
function clone(voucher: VatVoucher): VatVoucher {
  return JSON.parse(JSON.stringify(voucher)) as VatVoucher;
}

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueVatVoucher(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyVatVoucher(issued.voucher)).toBe(true);
  });

  it("rejects a changed public rate", () => {
    const v = clone(issued.voucher);
    v.rateBasisPoints = "1000";
    expect(verifyVatVoucher(v)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const v = clone(issued.voucher);
    v.bindingHash = v.bindingHash === "0x0" ? "0x1" : `${v.bindingHash}0`;
    expect(verifyVatVoucher(v)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const v = clone(issued.voucher);
    v.issuerSignature = { ...v.issuerSignature, response: "0x1" };
    expect(verifyVatVoucher(v)).toBe(false);
  });

  it("rejects a tampered range-proof bit", () => {
    const v = clone(issued.voucher);
    v.proof.netBits[0] = { ...v.proof.netBits[0], response0: "0x1" };
    expect(verifyVatVoucher(v)).toBe(false);
  });

  it("rejects a tampered link proof", () => {
    const v = clone(issued.voucher);
    v.proof.link = { ...v.proof.link, response: "0x1" };
    expect(verifyVatVoucher(v)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const v = clone(issued.voucher);
    v.proof.generatorH = { ...v.issuerPublicKey };
    expect(verifyVatVoucher(v)).toBe(false);
  });

  it("rejects a corrupted commitment point", () => {
    const v = clone(issued.voucher);
    v.proof.taxCommitment = { x: "0x1", y: "0x1" };
    expect(verifyVatVoucher(v)).toBe(false);
  });
});
function openingFromSecret(secret: VatVoucherSecret): VatVoucherOpening {
  return {
    netBaseUnits: secret.netBaseUnits,
    netBlinding: secret.netBlinding,
    taxBaseUnits: secret.taxBaseUnits,
    taxBlinding: secret.taxBlinding,
    remainderBaseUnits: secret.remainderBaseUnits,
    remainderBlinding: secret.remainderBlinding,
  };
}

describe("selective disclosure and openings", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueVatVoucher(baseInput(), NOW, makeEntropy("disc"));

  it("discloses the tax figure alone and verifies it", () => {
    const disclosure = buildVatTaxDisclosure(issued.secret);
    expect(disclosure.taxBaseUnits).toBe(issued.secret.taxBaseUnits);
    expect(verifyVatTaxDisclosure(issued.voucher, disclosure)).toBe(true);

    const round = parseVatTaxDisclosure(serializeVatTaxDisclosure(disclosure));
    expect(verifyVatTaxDisclosure(issued.voucher, round)).toBe(true);
  });

  it("rejects a tax disclosure with the wrong figure or wrong voucher", () => {
    const disclosure = buildVatTaxDisclosure(issued.secret);
    expect(verifyVatTaxDisclosure(issued.voucher, { ...disclosure, taxBaseUnits: "1" })).toBe(false);
    expect(verifyVatTaxDisclosure(issued.voucher, { ...disclosure, voucherId: "vat_other" })).toBe(false);
  });

  it("discloses the committed customer tax id and verifies it", () => {
    const disclosure = buildVatTaxIdDisclosure(issued.secret);
    expect(disclosure.customerTaxId).toBe("GB123456789");
    expect(verifyVatTaxIdDisclosure(issued.voucher, disclosure)).toBe(true);

    const round = parseVatTaxIdDisclosure(serializeVatTaxIdDisclosure(disclosure));
    expect(verifyVatTaxIdDisclosure(issued.voucher, round)).toBe(true);
    expect(verifyVatTaxIdDisclosure(issued.voucher, { ...disclosure, customerTaxId: "GB000000000" })).toBe(false);
  });

  it("verifies a full auditor opening and rejects a wrong figure", () => {
    const opening = openingFromSecret(issued.secret);
    expect(verifyVatVoucherOpening(issued.voucher, opening)).toBe(true);
    expect(verifyVatVoucherOpening(issued.voucher, { ...opening, taxBaseUnits: "1" })).toBe(false);
    expect(verifyVatVoucherOpening(issued.voucher, { ...opening, netBaseUnits: "1" })).toBe(false);
  });
});
describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds the net, tax, gross, blindings, tax id, or salt in the voucher", () => {
    const { voucher, secret } = issueVatVoucher(
      baseInput({ netBaseUnits: "999999999999999999", rateBasisPoints: 1234, customerTaxId: "SECRET-TAXID-ZZZ" }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyVatVoucher(voucher)).toBe(true);

    const structured = JSON.stringify(voucher);
    const serialized = serializeVatVoucher(voucher);
    for (const surface of [structured, serialized]) {
      expect(surface).not.toContain(secret.netBaseUnits);
      expect(surface).not.toContain(secret.taxBaseUnits);
      expect(surface).not.toContain(secret.grossBaseUnits);
      expect(surface).not.toContain(secret.netBlinding);
      expect(surface).not.toContain(secret.taxBlinding);
      expect(surface).not.toContain(secret.remainderBlinding);
      expect(surface).not.toContain(secret.taxIdSalt);
      expect(surface).not.toContain("SECRET-TAXID-ZZZ");
    }
    // The public rate, by contrast, is deliberately disclosed.
    expect(structured).toContain("1234");
  });

  it("keeps distinct nets unlinkable by producing distinct commitments", () => {
    const a = issueVatVoucher(baseInput({ netBaseUnits: "500000000000000000" }), NOW, makeEntropy("za"));
    const b = issueVatVoucher(baseInput({ netBaseUnits: "500000000000000000" }), NOW, makeEntropy("zb"));
    expect(a.voucher.proof.netCommitment.x).not.toBe(b.voucher.proof.netCommitment.x);
    expect(verifyVatVoucher(a.voucher)).toBe(true);
    expect(verifyVatVoucher(b.voucher)).toBe(true);
  });
});

describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeVatTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesCorrectTaxComputation).toBe(true);
    expect(trust.hidesNetAndGross).toBe(true);
    expect(trust.hidesCustomerTaxId).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.supportsSelectiveDisclosure).toBe(true);
    expect(trust.filesOrRemitsTax).toBe(false);
    expect(trust.validatesTaxIdRegistration).toBe(false);
    expect(trust.provesOnChainSettlement).toBe(false);
    expect(trust.bindsToRealFunds).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isTaxAdvice).toBe(false);
    expect(trust.harmonizesTaxLaw).toBe(false);
    expect(trust.statement).toContain("neither decentralized nor automatic");
    expect(trust.statement).toContain("does not file, remit, or settle any tax");
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getVatVisibilityModel();
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
  });
});

describe("generator, jurisdictions, and formatting helpers", () => {
  it("derives a stable, canonical generator H", () => {
    const a = deriveVatGenerator();
    const b = deriveVatGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
  });

  it("exposes illustrative jurisdictions with in-range rates and a custom entry", () => {
    const jurisdictions = getVatJurisdictions();
    expect(jurisdictions.length).toBeGreaterThan(0);
    for (const j of jurisdictions) {
      expect(j.standardRateBasisPoints).toBeGreaterThanOrEqual(0);
      expect(j.standardRateBasisPoints).toBeLessThanOrEqual(10000);
      expect(j.code.length).toBeGreaterThan(0);
      expect(j.label.length).toBeGreaterThan(0);
    }
    expect(jurisdictions.some((j) => j.code === "GB")).toBe(true);
    expect(jurisdictions.some((j) => j.code === "CUSTOM" && j.standardRateBasisPoints === 0)).toBe(true);
  });

  it("formats basis-point rates and base-unit amounts for display", () => {
    expect(formatVatRate(2000)).toBe("20.00%");
    expect(formatVatRate(1900)).toBe("19.00%");
    expect(formatVatRate(810)).toBe("8.10%");
    expect(formatVatRate("0")).toBe("0.00%");
    expect(formatVatBaseUnits("200000000000000000000", 18)).toBe("200");
    expect(formatVatBaseUnits("1500", 0)).toBe("1500");
  });

  it("rejects a malformed encoded voucher", () => {
    expect(() => parseVatVoucher("!!not base64!!")).toThrow(/encoding is invalid/i);
  });
});
