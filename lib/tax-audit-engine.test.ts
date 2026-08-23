import { describe, expect, it } from "vitest";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  buildTaxAuditAuthorization,
  buildTaxAuditBundle,
  buildTaxAuditBundleDigest,
  createTaxAuditProfile,
  formatTaxAuditBaseUnits,
  getTaxAuditVisibilityModel,
  openTaxAuditBundle,
  parseTaxAuditAuthorization,
  parseTaxAuditBundle,
  parseTaxAuditBundleDigest,
  parseTaxAuditEntry,
  parseTaxAuditInclusionProof,
  parseTaxAuditProfile,
  previewTaxAuditTotals,
  proveEntryInclusion,
  recordSettledInvoice,
  registerTaxAuditExporterKey,
  serializeTaxAuditAuthorization,
  serializeTaxAuditBundle,
  serializeTaxAuditBundleDigest,
  serializeTaxAuditEntry,
  serializeTaxAuditInclusionProof,
  serializeTaxAuditProfile,
  summarizeTaxAuditTrust,
  verifyEntryInclusion,
  verifyTaxAuditAuthorization,
  verifyTaxAuditBundle,
  verifyTaxAuditBundleDisclosure,
  verifyTaxAuditEntry,
  verifyTaxAuditProfile,
  type RecordSettledInvoiceInput,
} from "./tax-audit-engine";

const MERCHANT = "0x0111";
const USDC = { symbol: "USDC", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 6 };
const ETH = { symbol: "ETH", tokenAddress: "0x0333", decimals: 18 };
const TX1 = "0x02f6a8b9c0d1e2f3040506070809111213141516171819202122232425262728";
const TX2 = "0x0134a5b6c7d8e9f0010203040506070809101112131415161718192021222324";
const TX3 = "0x00bc0000000000000000000000000000000000000000000000000000000000ab";
const NOW = new Date("2026-08-20T00:00:00.000Z");

/** Deterministic entropy: incrementing ids and a fixed non-zero salt so every run is reproducible. */
function makeEntropy() {
  let counter = 0;
  return {
    createId: (kind: "profile" | "entry" | "bundle") => {
      const prefix = kind === "profile" ? "tap" : kind === "entry" ? "tae" : "tab";
      counter += 1;
      return `${prefix}_t${counter}`;
    },
    randomBytes: (target: Uint8Array<ArrayBuffer>) => {
      target.fill(7);
      return target;
    },
  };
}

function makeProfile(overrides: { merchant?: string; jurisdiction?: string; memo?: string } = {}) {
  return createTaxAuditProfile(
    { merchant: MERCHANT, jurisdiction: "US-CA", memo: "FY2026 exports", ...overrides },
    NOW,
    makeEntropy(),
  );
}

function record(profile = makeProfile(), overrides: Partial<RecordSettledInvoiceInput> = {}) {
  const input: RecordSettledInvoiceInput = {
    entryId: "tae_solo",
    invoiceId: "inv-1",
    transactionHash: TX1,
    asset: USDC,
    gross: "1000",
    fee: "20",
    category: "sales",
    settledAt: "2026-08-10T12:00:00.000Z",
    counterpartyRef: "acme-co",
    memo: "Q3 retainer",
    ...overrides,
  };
  return recordSettledInvoice(profile, input, NOW, makeEntropy());
}

describe("tax-audit profile", () => {
  it("creates a profile that verifies and round-trips through serialization", () => {
    const profile = makeProfile();
    expect(profile.kind).toBe("cipherbill.tax-audit-profile");
    expect(profile.profileId).toMatch(/^tap_/);
    expect(profile.merchant).not.toBe(MERCHANT); // normalized/padded
    expect(verifyTaxAuditProfile(profile)).toBe(true);
    expect(parseTaxAuditProfile(serializeTaxAuditProfile(profile))).toEqual(profile);
  });

  it("does not carry the profile salt in the serialized commitment inputs it exposes", () => {
    const profile = makeProfile();
    // The salt is part of the profile record (needed to reopen), but the commitment is a hash, not the memo.
    expect(profile.profileCommitment).toMatch(/^0x[0-9a-f]+$/);
    expect(profile.profileCommitment).not.toContain("FY2026");
  });

  it("rejects a tampered profile commitment", () => {
    const profile = makeProfile();
    expect(verifyTaxAuditProfile({ ...profile, memo: "a different memo" })).toBe(false);
  });

  it("accepts a profile with no jurisdiction or memo", () => {
    const profile = makeProfile({ jurisdiction: undefined, memo: undefined });
    expect(profile.jurisdiction).toBe("");
    expect(profile.memo).toBe("");
    expect(verifyTaxAuditProfile(profile)).toBe(true);
  });
});

describe("settled-invoice entries", () => {
  it("records an entry that verifies and round-trips", () => {
    const profile = makeProfile();
    const entry = record(profile);
    expect(entry.entryId).toMatch(/^tae_/);
    expect(entry.grossBaseUnits).toBe("1000000000");
    expect(entry.feeBaseUnits).toBe("20000000");
    expect(entry.netBaseUnits).toBe("980000000"); // gross - fee
    expect(verifyTaxAuditEntry(entry, profile)).toBe(true);
    expect(parseTaxAuditEntry(serializeTaxAuditEntry(entry))).toEqual(entry);
  });

  it("defaults the fee to zero so net equals gross", () => {
    const entry = record(makeProfile(), { fee: undefined });
    expect(entry.feeBaseUnits).toBe("0");
    expect(entry.netBaseUnits).toBe(entry.grossBaseUnits);
  });

  it("rejects a fee that exceeds the gross amount", () => {
    expect(() => record(makeProfile(), { gross: "100", fee: "101" })).toThrow(/cannot exceed the gross/i);
  });

  it("rejects a non-positive gross amount", () => {
    expect(() => record(makeProfile(), { gross: "0" })).toThrow(/greater than zero/i);
  });

  it("rejects a settlement dated in the future", () => {
    expect(() => record(makeProfile(), { settledAt: "2026-08-25T00:00:00.000Z" })).toThrow(/future/i);
  });

  it("rejects a gross amount outside the pool's u128 range", () => {
    // A large whole amount scaled by 18 decimals overflows u128 (2^128 - 1 ≈ 3.4e38).
    const overflow = "1000000000000000000000"; // 1e21 → 1e39 base units at 18 decimals
    const asset = { symbol: "BIG", tokenAddress: "0x0444", decimals: 18 };
    expect(() => record(makeProfile(), { asset, gross: overflow })).toThrow(/u128/i);
  });

  it("rejects a tampered entry commitment", () => {
    const profile = makeProfile();
    const entry = record(profile);
    expect(verifyTaxAuditEntry({ ...entry, grossBaseUnits: "999" }, profile)).toBe(false);
  });

  it("rejects an entry checked against a different profile", () => {
    const entry = record(makeProfile());
    const otherProfile = makeProfile({ memo: "another profile" });
    expect(verifyTaxAuditEntry(entry, otherProfile)).toBe(false);
  });
});

const PERIOD_START = "2026-07-01";
const PERIOD_END = "2026-07-31";

/**
 * Builds four entries against one profile using a SHARED entropy source so the incrementing
 * ids stay distinct (tae_t1..tae_t4) — fill(7) salts are identical, so distinct ids are what
 * keep the per-entry commitments (and the Merkle set) well-defined. Three fall inside July;
 * `eJune` sits outside the period so date-range filtering has something to drop.
 */
function makeEntries(profile = makeProfile()) {
  const entropy = makeEntropy();
  const mk = (overrides: Partial<RecordSettledInvoiceInput> & { settledAt: string }) =>
    recordSettledInvoice(
      profile,
      {
        invoiceId: "inv",
        transactionHash: TX1,
        asset: USDC,
        gross: "1",
        category: "sales",
        counterpartyRef: "acme-co",
        memo: "memo",
        ...overrides,
      },
      NOW,
      entropy,
    );
  const e1 = mk({ invoiceId: "inv-secret-1", transactionHash: TX1, asset: USDC, gross: "1000", fee: "20", category: "sales", settledAt: "2026-07-05T10:00:00.000Z", counterpartyRef: "acme-secret", memo: "confidential-q3" });
  const e2 = mk({ invoiceId: "inv-2", transactionHash: TX2, asset: USDC, gross: "500", fee: "5", category: "consulting", settledAt: "2026-07-20T10:00:00.000Z" });
  const e3 = mk({ invoiceId: "inv-3", transactionHash: TX3, asset: ETH, gross: "2", category: "sales", settledAt: "2026-07-25T10:00:00.000Z" });
  const eJune = mk({ invoiceId: "inv-old", transactionHash: TX1, asset: USDC, gross: "9", category: "sales", settledAt: "2026-06-15T10:00:00.000Z" });
  return { profile, entries: [e1, e2, e3, eJune] };
}

function makeBundle() {
  const { profile, entries } = makeEntries();
  const bundle = buildTaxAuditBundle(profile, entries, { periodStart: PERIOD_START, periodEnd: PERIOD_END }, NOW, makeEntropy());
  return { profile, entries, bundle };
}

describe("audit bundles", () => {
  it("aggregates the in-period entries into a bundle that verifies and round-trips", () => {
    const { bundle } = makeBundle();
    expect(bundle.kind).toBe("cipherbill.tax-audit-bundle");
    expect(bundle.bundleId).toMatch(/^tab_/);
    expect(bundle.entryCount).toBe(3); // the June entry is filtered out by the July period
    expect(bundle.merkleRoot).toMatch(/^0x[0-9a-f]+$/);
    expect(verifyTaxAuditBundle(bundle)).toBe(true);
    expect(parseTaxAuditBundle(serializeTaxAuditBundle(bundle))).toEqual(bundle);
  });

  it("snaps a bare calendar-date period to the full UTC day", () => {
    const { bundle } = makeBundle();
    expect(bundle.periodStart).toBe("2026-07-01T00:00:00.000Z");
    expect(bundle.periodEnd).toBe("2026-07-31T23:59:59.999Z");
  });

  it("computes exact per-asset totals with integer base units", () => {
    const { bundle } = makeBundle();
    const usdc = bundle.assetTotals.find((t) => t.assetSymbol === "USDC")!;
    const eth = bundle.assetTotals.find((t) => t.assetSymbol === "ETH")!;
    expect(usdc.entryCount).toBe(2);
    expect(usdc.grossBaseUnits).toBe("1500000000"); // 1000 + 500 USDC
    expect(usdc.feeBaseUnits).toBe("25000000"); // 20 + 5 USDC
    expect(usdc.netBaseUnits).toBe("1475000000"); // gross - fee
    expect(usdc.grossDisplay).toBe("1500");
    expect(eth.entryCount).toBe(1);
    expect(eth.grossBaseUnits).toBe("2000000000000000000"); // 2 ETH, 18 decimals
    expect(eth.netDisplay).toBe("2");
  });

  it("splits category totals by (category, asset)", () => {
    const { bundle } = makeBundle();
    expect(bundle.categoryTotals).toHaveLength(3); // (sales,USDC) (consulting,USDC) (sales,ETH)
    const salesUsdc = bundle.categoryTotals.find((t) => t.category === "sales" && t.assetSymbol === "USDC")!;
    expect(salesUsdc.grossBaseUnits).toBe("1000000000");
    const salesEth = bundle.categoryTotals.find((t) => t.category === "sales" && t.assetSymbol === "ETH")!;
    expect(salesEth.grossBaseUnits).toBe("2000000000000000000");
  });
  it("rejects a period that captures no settled invoices", () => {
    const { profile, entries } = makeEntries();
    expect(() => buildTaxAuditBundle(profile, entries, { periodStart: "2020-01-01", periodEnd: "2020-12-31" }, NOW, makeEntropy())).toThrow(/within the selected period/i);
  });

  it("rejects a period whose end precedes its start", () => {
    const { profile, entries } = makeEntries();
    expect(() => buildTaxAuditBundle(profile, entries, { periodStart: "2026-07-31", periodEnd: "2026-07-01" }, NOW, makeEntropy())).toThrow(/cannot precede/i);
  });

  it("rejects an entry that belongs to a different profile", () => {
    const { entries } = makeEntries();
    const stranger = makeProfile({ memo: "a different merchant" });
    expect(() => buildTaxAuditBundle(stranger, entries, { periodStart: PERIOD_START, periodEnd: PERIOD_END }, NOW, makeEntropy())).toThrow(/different tax-audit profile/i);
  });

  it("fails verification when a total is tampered after the fact", () => {
    const { bundle } = makeBundle();
    const tampered = {
      ...bundle,
      assetTotals: [{ ...bundle.assetTotals[0], grossBaseUnits: "1" }, ...bundle.assetTotals.slice(1)],
    };
    expect(verifyTaxAuditBundle(tampered)).toBe(false);
  });

  it("previews totals over an unbounded entry set without building a bundle", () => {
    const { entries } = makeEntries();
    const preview = previewTaxAuditTotals(entries);
    expect(preview.entryCount).toBe(4); // preview does not date-filter
    expect(preview.assetTotals.find((t) => t.assetSymbol === "USDC")!.entryCount).toBe(3);
  });

});

describe("bundle digest (selective disclosure)", () => {
  it("omits every per-entry PII field while keeping the aggregates", () => {
    const { bundle } = makeBundle();
    const digest = buildTaxAuditBundleDigest(bundle);
    const json = JSON.stringify(digest);
    expect(json).not.toContain("inv-secret-1"); // invoice id
    expect(json).not.toContain("acme-secret"); // counterparty reference
    expect(json).not.toContain("confidential-q3"); // memo
    expect(json).not.toContain(TX1); // settlement transaction hash
    expect(json).not.toContain(TX2);
    // The disclosed aggregates survive.
    expect(digest.entryCount).toBe(3);
    expect(digest.assetTotals.find((t) => t.assetSymbol === "USDC")!.grossBaseUnits).toBe("1500000000");
    expect(digest.merkleRoot).toBe(bundle.merkleRoot);
  });

  it("round-trips through serialization", () => {
    const digest = buildTaxAuditBundleDigest(makeBundle().bundle);
    expect(parseTaxAuditBundleDigest(serializeTaxAuditBundleDigest(digest))).toEqual(digest);
  });

  it("verifies the digest against a full opening of the same bundle", () => {
    const { bundle } = makeBundle();
    const opening = openTaxAuditBundle(bundle);
    const digest = buildTaxAuditBundleDigest(bundle);
    expect(verifyTaxAuditBundleDisclosure(opening, digest)).toBe(true);
  });

  it("rejects a digest that does not match the opening", () => {
    const { profile, entries, bundle } = makeBundle();
    const opening = openTaxAuditBundle(bundle);
    // A digest for a narrower period commits to a different entry set.
    const narrower = buildTaxAuditBundle(profile, entries, { periodStart: "2026-07-01", periodEnd: "2026-07-10" }, NOW, makeEntropy());
    expect(verifyTaxAuditBundleDisclosure(opening, buildTaxAuditBundleDigest(narrower))).toBe(false);
  });

  it("rejects an opening whose commitment was swapped out", () => {
    const { bundle } = makeBundle();
    const opening = openTaxAuditBundle(bundle);
    const digest = buildTaxAuditBundleDigest(bundle);
    expect(verifyTaxAuditBundleDisclosure({ ...opening, bundleCommitment: "0x1" }, digest)).toBe(false);
  });
});

describe("merkle inclusion proofs", () => {
  it("proves a single entry belongs to the committed bundle and round-trips", () => {
    const { profile, bundle } = makeBundle();
    const target = bundle.entries[1];
    const proof = proveEntryInclusion(bundle, target.entryId);
    expect(proof.kind).toBe("cipherbill.tax-audit-inclusion-proof");
    expect(proof.entry.entryId).toBe(target.entryId);
    expect(proof.merkleRoot).toBe(bundle.merkleRoot);
    expect(verifyEntryInclusion(proof)).toBe(true);
    expect(verifyEntryInclusion(proof, profile)).toBe(true);
    expect(parseTaxAuditInclusionProof(serializeTaxAuditInclusionProof(proof))).toEqual(proof);
  });

  it("throws when the entry is not part of the bundle", () => {
    const { bundle } = makeBundle();
    expect(() => proveEntryInclusion(bundle, "tae_absent")).toThrow(/not part of this bundle/i);
  });

  it("fails when the proven entry is tampered", () => {
    const { bundle } = makeBundle();
    const proof = proveEntryInclusion(bundle, bundle.entries[0].entryId);
    // The commitment no longer matches the (tampered) entry contents.
    expect(verifyEntryInclusion({ ...proof, entry: { ...proof.entry, grossBaseUnits: "1" } })).toBe(false);
  });

  it("fails when the Merkle root is swapped", () => {
    const { bundle } = makeBundle();
    const proof = proveEntryInclusion(bundle, bundle.entries[0].entryId);
    expect(verifyEntryInclusion({ ...proof, merkleRoot: "0x1" })).toBe(false);
  });

  it("fails against an unrelated profile", () => {
    const { bundle } = makeBundle();
    const proof = proveEntryInclusion(bundle, bundle.entries[0].entryId);
    expect(verifyEntryInclusion(proof, makeProfile({ memo: "someone else" }))).toBe(false);
  });
});

describe("export authorization (Schnorr ZKPoK)", () => {
  it("proves knowledge of the exporter key bound to the bundle and round-trips", () => {
    const { bundle } = makeBundle();
    const key = registerTaxAuditExporterKey({ exporterSecret: 7n });
    const auth = buildTaxAuditAuthorization(bundle, key, { nonce: 11n });
    expect(auth.proofSystem).toBe("stark-schnorr-tax-audit-v1");
    expect(auth.merkleRoot).toBe(bundle.merkleRoot);
    expect(verifyTaxAuditAuthorization(auth, bundle)).toBe(true);
    expect(parseTaxAuditAuthorization(serializeTaxAuditAuthorization(auth))).toEqual(auth);
  });

  it("fails when the proof response is tampered", () => {
    const { bundle } = makeBundle();
    const auth = buildTaxAuditAuthorization(bundle, registerTaxAuditExporterKey({ exporterSecret: 7n }), { nonce: 11n });
    const tampered = { ...auth, proof: { ...auth.proof, response: "0x" + (BigInt(auth.proof.response) + 1n).toString(16) } };
    expect(verifyTaxAuditAuthorization(tampered, bundle)).toBe(false);
  });

  it("fails against a bundle it was not issued for", () => {
    const { profile, entries, bundle } = makeBundle();
    const auth = buildTaxAuditAuthorization(bundle, registerTaxAuditExporterKey({ exporterSecret: 7n }), { nonce: 11n });
    const other = buildTaxAuditBundle(profile, entries, { periodStart: "2026-07-01", periodEnd: "2026-07-10" }, NOW, makeEntropy());
    expect(verifyTaxAuditAuthorization(auth, other)).toBe(false);
  });

  it("refuses to build an authorization when the secret and public key disagree", () => {
    const { bundle } = makeBundle();
    const k1 = registerTaxAuditExporterKey({ exporterSecret: 7n });
    const k2 = registerTaxAuditExporterKey({ exporterSecret: 9n });
    expect(() => buildTaxAuditAuthorization(bundle, { exporterSecret: k1.exporterSecret, exporterPublicKey: k2.exporterPublicKey }, { nonce: 11n })).toThrow(/does not match/i);
  });
});

describe("honest disclosure model", () => {
  it("does not overstate the trust properties of the export", () => {
    const trust = summarizeTaxAuditTrust();
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.provesTamperEvidence).toBe(true);
    expect(trust.provesCompleteness).toBe(false);
    expect(trust.provesTruthfulness).toBe(false);
    // The only genuine ZK element is the export authorization, and the copy says so.
    expect(trust.zeroKnowledgeElement.toLowerCase()).toContain("authorization");
    expect(trust.statement.toLowerCase()).toContain("neither decentralized nor automatic");
  });

  it("is explicit that the engine never touches the pool contract", () => {
    const model = getTaxAuditVisibilityModel();
    expect(model.applicationOnly.length).toBeGreaterThan(0);
    expect(model.publicOrObservable.length).toBeGreaterThan(0);
    expect(model.limitation.toLowerCase()).toContain("never reads from or writes to the pool contract");
  });
});

describe("base-unit formatter", () => {
  it("renders integer base units as a decimal amount", () => {
    expect(formatTaxAuditBaseUnits("1000000000", 6)).toBe("1000");
    expect(formatTaxAuditBaseUnits(1000000n, 6)).toBe("1");
    expect(formatTaxAuditBaseUnits("500", 0)).toBe("500");
  });

  it("accepts hex-encoded base units", () => {
    expect(formatTaxAuditBaseUnits("0x3e8", 6)).toBe("0.001"); // 0x3e8 = 1000 base units
  });
});
