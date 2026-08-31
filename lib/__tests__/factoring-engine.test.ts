/**
 * Vault-layer tests for `lib/factoring-engine.ts`.
 *
 * The plan layer (listings, quotes, agreements) is covered by `lib/factoring-engine.test.ts`.
 * This suite covers the zero-knowledge receivables-collateralization vault: the exact discount
 * arithmetic, every collateralization covenant, the range proofs and signature, selective
 * disclosure, and a permanent block of forgery regressions.
 *
 * Bands are deliberately small (8-bit figures) so the 258 bit proofs a fixture needs stay well
 * inside the suite timeout. The proof system does not change with the band, only its width.
 */
import { describe, expect, it } from "vitest";

import {
  FACTORING_VAULT_BUCKET_COUNT,
  FACTORING_VAULT_REMAINDER_BITS,
  FACTORING_VAULT_SURPLUS_HEADROOM_BITS,
  type FactoringVaultCertificate,
  type FactoringVaultCovenants,
  type FactoringVaultSecret,
  auditFactoringVaultCertificate,
  buildFactoringVaultBadge,
  discloseFactoringVaultFigure,
  estimateFactoringVaultProofCount,
  generateFactoringVaultIssuerKey,
  getFactoringVaultTrustModel,
  issueFactoringVaultCertificate,
  parseFactoringVaultCertificate,
  parseFactoringVaultDisclosure,
  parseFactoringVaultSecret,
  serializeFactoringVaultCertificate,
  serializeFactoringVaultDisclosure,
  serializeFactoringVaultSecret,
  verifyFactoringVaultCertificate,
  verifyFactoringVaultDisclosure,
} from "../factoring-engine";

const FIELD_PRIME = 2n ** 251n + 17n * 2n ** 192n + 1n;
const CURVE_ORDER = 3618502788666131213697322783095070105526743751716087489154079457884512865583n;
/** A shift that is congruent to zero under both moduli at once: the PR-49 forgery. */
const DUAL_MODULUS_SHIFT = FIELD_PRIME * CURVE_ORDER;

const BIT_LENGTH = 8;

/** Counter-based entropy so a failure is reproducible rather than a one-in-a-run curiosity. */
function seededEntropy(seed: number) {
  let state = BigInt(seed) | 1n;
  return {
    random: (target: Uint8Array<ArrayBuffer>) => {
      for (let index = 0; index < target.length; index += 1) {
        state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
        target[index] = Number((state >> 33n) & 0xffn);
      }
      return target;
    },
  };
}

const COVENANTS: FactoringVaultCovenants = {
  haircutBps: [500, 1000, 2000, 5000],
  advanceRateBps: 8000,
  minCoverageRatioBps: 12500,
  maxConcentrationBps: 3000,
  maxStaleBps: 1500,
  discountRateBps: 1200,
  tenorDays: 60,
  holdbackBaseUnits: "30",
  platformFeeBaseUnits: "5",
};

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    facilityLabel: "Northwind receivables facility",
    merchantAlias: "Northwind Trading",
    underwriterAlias: "Harbour Credit Partners",
    assetSymbol: "USDC",
    assetDecimals: 2,
    amountBitLength: BIT_LENGTH,
    bucketBaseUnits: ["100", "60", "31", "11"],
    eligibleBaseUnits: "170",
    advanceBaseUnits: "130",
    concentrationBaseUnits: "50",
    covenants: COVENANTS,
    asOf: "2026-08-01T00:00:00.000Z",
    maturity: "2026-10-01T00:00:00.000Z",
    createdAt: "2026-08-02T00:00:00.000Z",
    memo: "Q3 revolving draw",
    issuerKey: generateFactoringVaultIssuerKey(seededEntropy(7)),
    ...overrides,
  };
}

let cachedFixture: { certificate: FactoringVaultCertificate; secret: FactoringVaultSecret } | null = null;

/** One valid certificate, proved once and shared. Tamper tests deep-clone it. */
function fixture() {
  if (!cachedFixture) cachedFixture = issueFactoringVaultCertificate(baseInput(), seededEntropy(11));
  return cachedFixture;
}

function clone(certificate: FactoringVaultCertificate): FactoringVaultCertificate {
  return JSON.parse(JSON.stringify(certificate)) as FactoringVaultCertificate;
}

/** The engine's own ceiling division, restated independently so the test is not circular. */
function expectedCharge(advance: bigint, rateBps: bigint, tenorDays: bigint): bigint {
  const numerator = advance * rateBps * tenorDays;
  const denominator = 10_000n * 365n;
  return numerator === 0n ? 0n : (numerator + denominator - 1n) / denominator;
}

describe("vault proving cost", () => {
  it("counts every leg the issuer actually proves", () => {
    const amount = 16;
    const surplus = amount + FACTORING_VAULT_SURPLUS_HEADROOM_BITS;
    const expected =
      (FACTORING_VAULT_BUCKET_COUNT + 6) * amount + 5 * surplus + 2 * FACTORING_VAULT_REMAINDER_BITS;
    expect(estimateFactoringVaultProofCount(amount)).toBe(expected);
  });

  it("grows monotonically with the band and rejects bands outside the supported range", () => {
    expect(estimateFactoringVaultProofCount(48)).toBeGreaterThan(estimateFactoringVaultProofCount(16));
    expect(() => estimateFactoringVaultProofCount(7)).toThrow();
    expect(() => estimateFactoringVaultProofCount(129)).toThrow();
    expect(() => estimateFactoringVaultProofCount(16.5)).toThrow();
  });
});

describe("issuer keys", () => {
  it("derives the public key from the secret scalar and is deterministic under fixed entropy", () => {
    const first = generateFactoringVaultIssuerKey(seededEntropy(3));
    const second = generateFactoringVaultIssuerKey(seededEntropy(3));
    expect(first).toEqual(second);
    expect(first.secretScalar).toMatch(/^0x[0-9a-f]{1,63}$/);
    expect(BigInt(first.secretScalar)).toBeGreaterThan(0n);
    expect(BigInt(first.secretScalar)).toBeLessThan(CURVE_ORDER);
  });

  it("draws different keys from different entropy", () => {
    expect(generateFactoringVaultIssuerKey(seededEntropy(3)).secretScalar).not.toBe(
      generateFactoringVaultIssuerKey(seededEntropy(4)).secretScalar,
    );
  });
});

describe("certificate issuance", () => {
  it("issues a certificate that audits clean on every row", () => {
    const { certificate } = fixture();
    const audit = auditFactoringVaultCertificate(certificate);
    const failed = audit.checks.filter((check) => !check.passed).map((check) => check.label);
    expect(failed).toEqual([]);
    expect(audit.checks).toHaveLength(18);
    expect(audit.ok).toBe(true);
    expect(verifyFactoringVaultCertificate(certificate)).toBe(true);
  });

  it("publishes bands, labels, and provenance but never a plaintext figure", () => {
    const { certificate } = fixture();
    expect(certificate.amountBitLength).toBe(BIT_LENGTH);
    expect(certificate.surplusBitLength).toBe(BIT_LENGTH + FACTORING_VAULT_SURPLUS_HEADROOM_BITS);
    expect(certificate.remainderBitLength).toBe(FACTORING_VAULT_REMAINDER_BITS);
    expect(certificate.network).toBe("SN_MAIN");
    expect(certificate.poolAddress).toBe(
      "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
    );
    expect(certificate.bucketCommitments).toHaveLength(FACTORING_VAULT_BUCKET_COUNT);
    const published = JSON.stringify(certificate);
    // The aliases are hashed into refs; the figures are only ever committed.
    expect(published).not.toContain("Northwind Trading");
    expect(published).not.toContain("Harbour Credit Partners");
    for (const figure of ["100", "60", "31", "11", "170", "130", "50"]) {
      expect(published).not.toContain(`"${figure}"`);
    }
  });

  it("keeps the openings out of the certificate and inside the secret", () => {
    const { certificate, secret } = fixture();
    expect(secret.vaultId).toBe(certificate.vaultId);
    expect(secret.bindingHash).toBe(certificate.bindingHash);
    expect(secret.buckets.map((entry) => entry.value)).toEqual(["100", "60", "31", "11"]);
    expect(secret.face.value).toBe("202");
    expect(secret.eligible.value).toBe("170");
    expect(secret.advance.value).toBe("130");
    expect(secret.concentration.value).toBe("50");
    expect(JSON.stringify(certificate)).not.toContain(secret.advance.blinding);
  });
});

describe("discount rate calculations", () => {
  it("charges the exact ceiling of advance · rate · tenor / (10000 · 365)", () => {
    const { certificate, secret } = fixture();
    const advance = BigInt(secret.advance.value);
    const charge = expectedCharge(advance, BigInt(COVENANTS.discountRateBps), BigInt(COVENANTS.tenorDays));
    expect(charge).toBe(3n); // 130 · 1200 · 60 / 3650000 = 2.564..., rounded up
    expect(secret.discountCharge.value).toBe(charge.toString());
    expect(certificate.covenants.discountRateBps).toBe(1200);
    expect(certificate.covenants.tenorDays).toBe(60);
  });

  it("rounds up rather than truncating, so the facility is never undercharged", () => {
    const { secret } = issueFactoringVaultCertificate(
      baseInput({ covenants: { ...COVENANTS, discountRateBps: 1, tenorDays: 1 } }),
      seededEntropy(13),
    );
    // 130 · 1 · 1 / 3650000 = 0.0000356..., which must round up to 1, not down to 0.
    expect(secret.discountCharge.value).toBe("1");
  });

  it("charges nothing when the discount rate is zero", () => {
    const zeroRate = issueFactoringVaultCertificate(
      baseInput({ covenants: { ...COVENANTS, discountRateBps: 0 } }),
      seededEntropy(17),
    );
    expect(zeroRate.secret.discountCharge.value).toBe("0");
    expect(verifyFactoringVaultCertificate(zeroRate.certificate)).toBe(true);
  });

  it("refuses to issue when the charge and the fee exceed the advance", () => {
    expect(() =>
      issueFactoringVaultCertificate(
        baseInput({
          advanceBaseUnits: "10",
          covenants: { ...COVENANTS, holdbackBaseUnits: "0", platformFeeBaseUnits: "20" },
        }),
        seededEntropy(19),
      ),
    ).toThrow(/discount charge and platform fee exceed/i);
  });
});
describe("collateralization ratios", () => {
  const cases: [string, Record<string, unknown>, RegExp][] = [
    [
      "eligible collateral above the haircut-weighted book",
      { eligibleBaseUnits: "180" },
      /aging buckets support after haircuts/i,
    ],
    ["an advance above the advance rate", { advanceBaseUnits: "137" }, /exceeds the advance rate/i],
    [
      "an advance that breaches the coverage floor",
      { covenants: { ...COVENANTS, advanceRateBps: 10_000, minCoverageRatioBps: 15_000 } },
      /minimum coverage ratio/i,
    ],
    [
      "an advance that eats the holdback reserve",
      { covenants: { ...COVENANTS, holdbackBaseUnits: "50" } },
      /holdback reserve/i,
    ],
    ["a debtor above the concentration cap", { concentrationBaseUnits: "70" }, /concentration cap/i],
    [
      "a 90+ day bucket above the stale cap",
      { bucketBaseUnits: ["100", "60", "31", "41"] },
      /stale-receivables cap/i,
    ],
    [
      "a coverage ratio below par",
      { covenants: { ...COVENANTS, minCoverageRatioBps: 9_000 } },
      /cannot be below 100%/i,
    ],
    [
      "a tenor outside the supported window",
      { covenants: { ...COVENANTS, tenorDays: 0 } },
      /tenor must be between 1 and 365 days/i,
    ],
    [
      "the wrong number of aging buckets",
      { bucketBaseUnits: ["20000", "15000", "10000"] },
      /exactly 4 aging buckets/i,
    ],
    [
      "the wrong number of haircut rates",
      { covenants: { ...COVENANTS, haircutBps: [500, 1000, 2000] } },
      /exactly 4 haircut rates/i,
    ],
  ];

  for (const [label, overrides, message] of cases) {
    it(`refuses to issue for ${label}`, () => {
      expect(() => issueFactoringVaultCertificate(baseInput(overrides), seededEntropy(23))).toThrow(message);
    });
  }

  it("accepts a facility that sits exactly on every covenant boundary", () => {
    const { certificate, secret } = issueFactoringVaultCertificate(
      baseInput({
        bucketBaseUnits: ["100", "0", "0", "0"],
        eligibleBaseUnits: "95",
        advanceBaseUnits: "76",
        concentrationBaseUnits: "30",
        covenants: { ...COVENANTS, holdbackBaseUnits: "19", platformFeeBaseUnits: "0" },
      }),
      seededEntropy(29),
    );
    // eligible · 10000 = 950 000 = Σ (10000 − haircut) · bucket, advance · 10000 = eligible · 8000,
    // eligible · 10000 = advance · 12500, eligible − advance = holdback, debtor · 10000 = face · 3000.
    expect(secret.eligible.value).toBe("95");
    expect(secret.advance.value).toBe("76");
    expect(verifyFactoringVaultCertificate(certificate)).toBe(true);
  });
});

describe("zero-knowledge proof validation", () => {
  function firstFailure(certificate: FactoringVaultCertificate): string {
    const audit = auditFactoringVaultCertificate(certificate);
    expect(audit.ok).toBe(false);
    expect(verifyFactoringVaultCertificate(certificate)).toBe(false);
    const failed = audit.checks.find((check) => !check.passed);
    return failed ? failed.label : "no failure";
  }

  it("rejects a rewritten second generator", () => {
    const certificate = clone(fixture().certificate);
    certificate.generatorH = { ...certificate.bucketCommitments[0] };
    expect(firstFailure(certificate)).toBe("Second generator");
  });

  it("rejects a rewritten memo", () => {
    const certificate = clone(fixture().certificate);
    certificate.memo = "Q4 revolving draw";
    expect(firstFailure(certificate)).toBe("Binding hash");
  });

  it("rejects a loosened covenant", () => {
    const certificate = clone(fixture().certificate);
    certificate.covenants = { ...certificate.covenants, advanceRateBps: 9_500 };
    expect(firstFailure(certificate)).toBe("Binding hash");
  });

  it("rejects a swapped commitment", () => {
    const certificate = clone(fixture().certificate);
    const [first, second] = certificate.bucketCommitments;
    certificate.bucketCommitments[0] = second;
    certificate.bucketCommitments[1] = first;
    expect(firstFailure(certificate)).toBe("Binding hash");
  });

  it("rejects a substituted issuer public key", () => {
    const certificate = clone(fixture().certificate);
    certificate.issuerPublicKey = generateFactoringVaultIssuerKey(seededEntropy(31)).publicKey;
    expect(firstFailure(certificate)).toBe("Binding hash");
  });
});
describe("proof tampering", () => {
  it("rejects a forged signature", () => {
    const certificate = clone(fixture().certificate);
    certificate.signature = {
      challenge: certificate.signature.response,
      response: certificate.signature.challenge,
    };
    const audit = auditFactoringVaultCertificate(certificate);
    expect(audit.ok).toBe(false);
    expect(audit.checks[audit.checks.length - 1].label).toBe("Issuer signature");
  });

  it("rejects a signature from a different issuer", () => {
    const other = issueFactoringVaultCertificate(
      baseInput({ issuerKey: generateFactoringVaultIssuerKey(seededEntropy(37)) }),
      seededEntropy(41),
    );
    const certificate = clone(fixture().certificate);
    certificate.signature = other.certificate.signature;
    expect(verifyFactoringVaultCertificate(certificate)).toBe(false);
    expect(verifyFactoringVaultCertificate(other.certificate)).toBe(true);
  });

  it("rejects a corrupted bit response inside a bucket range proof", () => {
    const certificate = clone(fixture().certificate);
    const target = certificate.bucketProofs[0][0];
    target.response0 = certificate.bucketProofs[0][1].response0;
    const audit = auditFactoringVaultCertificate(certificate);
    expect(audit.ok).toBe(false);
    expect(audit.checks[audit.checks.length - 1].label).toBe("Aging buckets in band");
  });

  it("rejects a range proof lifted from another certificate leg", () => {
    const certificate = clone(fixture().certificate);
    certificate.eligibleProof = certificate.advanceProof;
    const audit = auditFactoringVaultCertificate(certificate);
    expect(audit.ok).toBe(false);
    expect(audit.checks[audit.checks.length - 1].label).toBe("Eligible collateral in band");
  });

  it("rejects a truncated proof array before touching the curve", () => {
    const certificate = clone(fixture().certificate);
    certificate.coverageProof = certificate.coverageProof.slice(0, -1);
    const audit = auditFactoringVaultCertificate(certificate);
    expect(audit.ok).toBe(false);
    expect(audit.checks).toHaveLength(1);
    expect(audit.checks[0].label).toBe("Certificate structure");
  });
});
describe("band bounds", () => {
  const overBand: [string, Record<string, unknown>, RegExp][] = [
    ["a bucket", { bucketBaseUnits: ["300", "60", "31", "11"] }, /0-30 days bucket exceeds the 8-bit band/],
    ["eligible collateral", { eligibleBaseUnits: "300" }, /eligible collateral exceeds the 8-bit band/i],
    ["the requested advance", { advanceBaseUnits: "300" }, /requested advance exceeds the 8-bit band/i],
    ["the largest debtor", { concentrationBaseUnits: "300" }, /largest debtor exposure exceeds the 8-bit band/i],
    [
      "the holdback reserve",
      { covenants: { ...COVENANTS, holdbackBaseUnits: "300" } },
      /holdback reserve exceeds the 8-bit band/i,
    ],
    [
      "the platform fee",
      { covenants: { ...COVENANTS, platformFeeBaseUnits: "300" } },
      /platform fee exceeds the 8-bit band/i,
    ],
  ];

  for (const [label, overrides, message] of overBand) {
    it(`refuses ${label} above the declared band`, () => {
      expect(() => issueFactoringVaultCertificate(baseInput(overrides), seededEntropy(43))).toThrow(message);
    });
  }

  it("refuses a discount charge that overflows the band", () => {
    expect(() =>
      issueFactoringVaultCertificate(
        baseInput({
          covenants: { ...COVENANTS, discountRateBps: 100_000, tenorDays: 365, holdbackBaseUnits: "0" },
        }),
        seededEntropy(47),
      ),
    ).toThrow(/discount charge exceeds the 8-bit band/i);
  });

  it("refuses a band outside the supported window", () => {
    expect(() => issueFactoringVaultCertificate(baseInput({ amountBitLength: 4 }), seededEntropy(53))).toThrow();
    expect(() => issueFactoringVaultCertificate(baseInput({ amountBitLength: 256 }), seededEntropy(53))).toThrow();
  });
});
describe("selective disclosure", () => {
  const figures = [
    "face",
    "eligible",
    "advance",
    "discountCharge",
    "concentration",
    "bucket0",
    "bucket1",
    "bucket2",
    "bucket3",
  ] as const;

  it("opens every committed figure and verifies each against its commitment", () => {
    const { certificate, secret } = fixture();
    for (const figure of figures) {
      const disclosure = discloseFactoringVaultFigure(certificate, secret, figure);
      expect(disclosure.figure).toBe(figure);
      expect(verifyFactoringVaultDisclosure(certificate, disclosure)).toBe(true);
    }
  });

  it("renders the display string from the certificate's own decimals", () => {
    const { certificate, secret } = fixture();
    // Trailing zeros are trimmed, so 130 base units at 2 decimals render as "1.3", not "1.30".
    expect(discloseFactoringVaultFigure(certificate, secret, "advance").valueDisplay).toBe("1.3");
    expect(discloseFactoringVaultFigure(certificate, secret, "face").valueDisplay).toBe("2.02");
  });

  it("rejects a disclosure whose value was edited", () => {
    const { certificate, secret } = fixture();
    const disclosure = discloseFactoringVaultFigure(certificate, secret, "advance");
    expect(
      verifyFactoringVaultDisclosure(certificate, { ...disclosure, valueBaseUnits: "131", valueDisplay: "1.31" }),
    ).toBe(false);
  });

  it("rejects a disclosure whose display string was edited", () => {
    const { certificate, secret } = fixture();
    const disclosure = discloseFactoringVaultFigure(certificate, secret, "advance");
    expect(verifyFactoringVaultDisclosure(certificate, { ...disclosure, valueDisplay: "13.00" })).toBe(false);
  });

  it("rejects a blinding taken from a different figure", () => {
    const { certificate, secret } = fixture();
    const advance = discloseFactoringVaultFigure(certificate, secret, "advance");
    const eligible = discloseFactoringVaultFigure(certificate, secret, "eligible");
    expect(verifyFactoringVaultDisclosure(certificate, { ...advance, blinding: eligible.blinding })).toBe(false);
  });
});
describe("selective disclosure boundaries", () => {
  it("refuses to open a figure with openings from another vault", () => {
    const { certificate } = fixture();
    const other = issueFactoringVaultCertificate(baseInput({ memo: "different draw" }), seededEntropy(59));
    expect(() => discloseFactoringVaultFigure(certificate, other.secret, "advance")).toThrow(
      /different vault certificate/i,
    );
  });

  it("refuses a disclosure carrying another vault's binding hash", () => {
    const { certificate, secret } = fixture();
    const disclosure = discloseFactoringVaultFigure(certificate, secret, "advance");
    expect(verifyFactoringVaultDisclosure(certificate, { ...disclosure, bindingHash: certificate.facilityRef })).toBe(
      false,
    );
  });

  it("refuses a value outside its canonical band even though the string is well formed", () => {
    const { certificate, secret } = fixture();
    const disclosure = discloseFactoringVaultFigure(certificate, secret, "advance");
    // 2^8 is outside the band for every figure except `face`, which is allowed 4 · 2^8.
    expect(
      verifyFactoringVaultDisclosure(certificate, { ...disclosure, valueBaseUnits: "256", valueDisplay: "2.56" }),
    ).toBe(false);
  });

  it("allows the face value the full four-bucket band and nothing beyond it", () => {
    const { certificate, secret } = fixture();
    const face = discloseFactoringVaultFigure(certificate, secret, "face");
    const limit = BigInt(FACTORING_VAULT_BUCKET_COUNT) << BigInt(BIT_LENGTH);
    expect(BigInt(face.valueBaseUnits)).toBeLessThan(limit);
    expect(
      verifyFactoringVaultDisclosure(certificate, {
        ...face,
        valueBaseUnits: limit.toString(),
        valueDisplay: "10.24",
      }),
    ).toBe(false);
  });

  it("refuses a congruent re-opening shifted by the curve order", () => {
    const { certificate, secret } = fixture();
    const disclosure = discloseFactoringVaultFigure(certificate, secret, "advance");
    // value + n opens the same Pedersen commitment. Only the explicit band bound stops it.
    const shifted = (BigInt(disclosure.valueBaseUnits) + CURVE_ORDER).toString();
    expect(verifyFactoringVaultDisclosure(certificate, { ...disclosure, valueBaseUnits: shifted })).toBe(false);
  });
});
describe("envelope round trips", () => {
  it("round-trips a certificate through its base64url envelope", () => {
    const { certificate } = fixture();
    const encoded = serializeFactoringVaultCertificate(certificate);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    const parsed = parseFactoringVaultCertificate(encoded);
    expect(parsed).toEqual(certificate);
  });

  it("round-trips the openings and the disclosure", () => {
    const { certificate, secret } = fixture();
    expect(parseFactoringVaultSecret(serializeFactoringVaultSecret(secret))).toEqual(secret);
    const disclosure = discloseFactoringVaultFigure(certificate, secret, "bucket2");
    const parsed = parseFactoringVaultDisclosure(serializeFactoringVaultDisclosure(disclosure));
    expect(parsed).toEqual(disclosure);
    expect(verifyFactoringVaultDisclosure(certificate, parsed)).toBe(true);
  });

  it("refuses an envelope from the wrong layer or with unknown keys", () => {
    const { certificate, secret } = fixture();
    expect(() => parseFactoringVaultCertificate(serializeFactoringVaultSecret(secret))).toThrow();
    const extra = { ...certificate, extraField: 1 } as unknown as FactoringVaultCertificate;
    expect(() => serializeFactoringVaultCertificate(extra)).toThrow(/invalid/i);
    expect(verifyFactoringVaultCertificate(extra)).toBe(false);
  });

  it("refuses a truncated or non-base64url envelope", () => {
    const encoded = serializeFactoringVaultCertificate(fixture().certificate);
    expect(() => parseFactoringVaultCertificate(encoded.slice(0, -8))).toThrow();
    expect(() => parseFactoringVaultCertificate(`${encoded}***`)).toThrow();
    expect(() => parseFactoringVaultCertificate("")).toThrow();
  });
});

describe("badge and trust model", () => {
  it("summarises the certificate without leaking a figure", () => {
    const { certificate } = fixture();
    const badge = buildFactoringVaultBadge(certificate);
    expect(badge.facilityRef).toBe(certificate.facilityRef);
    expect(badge.band).toContain(String(BIT_LENGTH));
    expect(badge.proofCount).toBe(estimateFactoringVaultProofCount(BIT_LENGTH));
    expect(badge.notice).toBe(certificate.notice);
    expect(JSON.stringify(badge)).not.toContain('"170"');
    expect(JSON.stringify(badge)).not.toContain('"130"');
  });

  it("states what is proven, what is hidden, what is public, and what is not covered", () => {
    const model = getFactoringVaultTrustModel();
    expect(model.proven.length).toBeGreaterThan(0);
    expect(model.hidden.length).toBeGreaterThan(0);
    expect(model.visible.length).toBeGreaterThan(0);
    expect(model.limitations).toEqual(fixture().certificate.limitations);
    const claims = [...model.proven, ...model.hidden, ...model.visible, ...model.limitations].join(" ");
    expect(claims).toMatch(/on-chain|onchain/i);
  });
});
/**
 * Permanent regressions. Each entry is a forgery a sibling CipherBill engine accepted, or would
 * accept without the bound named in the comment. Do not delete these when refactoring.
 */
describe("forgery regressions", () => {
  function structureRejects(mutate: (certificate: FactoringVaultCertificate) => void) {
    const certificate = clone(fixture().certificate);
    mutate(certificate);
    const audit = auditFactoringVaultCertificate(certificate);
    expect(audit.ok).toBe(false);
    expect(audit.checks).toHaveLength(1);
    expect(audit.checks[0].label).toBe("Certificate structure");
    expect(verifyFactoringVaultCertificate(certificate)).toBe(false);
  }

  it("sanity-checks the two moduli the shift exploits", () => {
    expect(CURVE_ORDER).toBeLessThan(FIELD_PRIME);
    expect(DUAL_MODULUS_SHIFT % FIELD_PRIME).toBe(0n);
    expect(DUAL_MODULUS_SHIFT % CURVE_ORDER).toBe(0n);
  });

  // A public scalar folded in as `scalar·G` and shifted by FIELD_PRIME · CURVE_ORDER stays
  // congruent under the Poseidon field AND under the curve order, so the binding hash, the issuer
  // signature, and the homomorphic leg all still close. Only an explicit band bound stops it.
  it("rejects a holdback floor shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const honest = BigInt(fixture().certificate.covenants.holdbackBaseUnits);
    structureRejects((certificate) => {
      certificate.covenants.holdbackBaseUnits = (honest + DUAL_MODULUS_SHIFT).toString();
    });
  });

  it("rejects a platform fee shifted by FIELD_PRIME · CURVE_ORDER", () => {
    const honest = BigInt(fixture().certificate.covenants.platformFeeBaseUnits);
    structureRejects((certificate) => {
      certificate.covenants.platformFeeBaseUnits = (honest + DUAL_MODULUS_SHIFT).toString();
    });
  });

  it("rejects a holdback floor lifted above the declared band", () => {
    structureRejects((certificate) => {
      certificate.covenants.holdbackBaseUnits = "300";
    });
  });

  it("rejects a covenant amount in non-canonical form", () => {
    // A leading zero survives a bigint comparison but changes the bytes the binding hash covered.
    structureRejects((certificate) => {
      certificate.covenants.holdbackBaseUnits = "030";
    });
  });
});
