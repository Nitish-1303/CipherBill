import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  aggregateAgingSchedule,
  assessCashflowRisk,
  buildCashflowAmountDisclosure,
  buildCashflowBookRefDisclosure,
  buildCashflowCertificateBadge,
  buildCashflowCounterpartyDisclosure,
  CASHFLOW_POOL_ADDRESS,
  CASHFLOW_PROOF_SYSTEM,
  CASHFLOW_SURPLUS_EXTRA_BITS,
  MAX_DSO_DAYS,
  commitInvoiceRecord,
  computeCashflowState,
  createCashflowIssuerKey,
  deriveCashflowGenerator,
  formatCashflowBaseUnits,
  formatDsoDays,
  formatRunwayDays,
  formatShareBps,
  getCashflowVisibilityModel,
  issueCashflowCertificate,
  parseCashflowAmountDisclosure,
  parseCashflowCertificate,
  parseCashflowCertificateSecret,
  parseCashflowRefDisclosure,
  projectRollingRunway,
  requireCashflowPolicy,
  serializeCashflowAmountDisclosure,
  serializeCashflowCertificate,
  serializeCashflowCertificateSecret,
  serializeCashflowRefDisclosure,
  summarizeCashflowTrust,
  verifyCashflowAmountDisclosure,
  verifyCashflowCertificate,
  verifyCashflowRefDisclosure,
  type CashflowCertificate,
  type CashflowInvoiceRow,
  type CashflowPolicy,
  type IssueCashflowCertificateInput,
} from "./cashflow-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T00:00:00.000Z");
const PROOF_TIMEOUT = 120_000;

function makeEntropy(seed: string): { createId: () => string; randomScalar: () => bigint } {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `cf_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createCashflowIssuerKey(makeEntropy(seed));
}

const BASE_POLICY: CashflowPolicy = { minRunwayDays: 30, maxDsoDays: 45, maxPastDueShareBps: 5000 };

const SAMPLE_ROWS: CashflowInvoiceRow[] = [
  { alias: "Northwind", dueDate: "2026-09-01T00:00:00.000Z", amountBaseUnits: "3000000", settlementDays: 5 },
  { alias: "Contoso", dueDate: "2026-07-01T00:00:00.000Z", amountBaseUnits: "2000000", settlementDays: 10 },
  { alias: "Fabrikam", dueDate: "2026-06-01T00:00:00.000Z", amountBaseUnits: "1000000", settlementDays: 15 },
];

function baseInput(overrides: Partial<IssueCashflowCertificateInput> = {}): IssueCashflowCertificateInput {
  return {
    merchantAlias: "Aurora Studio",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    bookRef: "AR-BOOK-2026-Q3",
    programLabel: "Rolling Forecast",
    policy: BASE_POLICY,
    liquidityBaseUnits: "5000000",
    burnRateBaseUnits: "50000",
    bucketAmountsBaseUnits: ["3000000", "2000000", "1000000", "0", "0"],
    weightedSettlementDays: "50000000",
    counterpartyRef: "book_counterparty_v1",
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 32,
    ...overrides,
  };
}

function clone(certificate: CashflowCertificate): CashflowCertificate {
  return JSON.parse(JSON.stringify(certificate)) as CashflowCertificate;
}

describe("aging arithmetic, runway projection, and risk", () => {
  it("aggregates invoice rows into five aging buckets with DSO and share metrics", () => {
    const aging = aggregateAgingSchedule(SAMPLE_ROWS, NOW);
    expect(aging.buckets.map((b) => b.amountBaseUnits)).toEqual(["3000000", "0", "2000000", "1000000", "0"]);
    expect(aging.buckets.map((b) => b.invoiceCount)).toEqual([1, 0, 1, 1, 0]);
    expect(aging.totalArBaseUnits).toBe("6000000");
    expect(aging.weightedSettlementDays).toBe("50000000");
    expect(aging.dsoDays).toBe("8");
    expect(aging.pastDueShareBps).toBe("5000");
    expect(aging.ninetyPlusShareBps).toBe("0");
  });

  it("commits invoice rows under salted Poseidon commitments without revealing aliases in the digest surface", () => {
    const a = commitInvoiceRecord("Northwind", "2026-09-01T00:00:00.000Z", "3000000", 5, 42n);
    const b = commitInvoiceRecord("Northwind", "2026-09-01T00:00:00.000Z", "3000000", 5, 43n);
    expect(a).toMatch(/^0x[0-9a-f]+$/);
    expect(a).not.toBe(b);
  });

  it("computes an eligible cash-flow state with positive policy surpluses", () => {
    const aging = aggregateAgingSchedule(SAMPLE_ROWS, NOW);
    const state = computeCashflowState("5000000", "50000", aging, BASE_POLICY);
    expect(state).toMatchObject({
      liquidityBaseUnits: "5000000",
      burnRateBaseUnits: "50000",
      totalArBaseUnits: "6000000",
      runwayDays: "100",
      dsoDays: "8",
      eligible: true,
    });
    expect(BigInt(state.runwaySurplus)).toBeGreaterThan(0n);
    expect(BigInt(state.dsoSurplus)).toBeGreaterThan(0n);
    expect(BigInt(state.concentrationSurplus)).toBeGreaterThan(0n);
  });

  it("flags a broken runway covenant as ineligible with a negative runway surplus", () => {
    const aging = aggregateAgingSchedule(SAMPLE_ROWS, NOW);
    const state = computeCashflowState("1000000", "50000", aging, BASE_POLICY);
    expect(state.eligible).toBe(false);
    expect(BigInt(state.runwaySurplus)).toBeLessThan(0n);
  });

  it("projects a rolling runway schedule that burns weekly and collects on settlement dates", () => {
    const weeks = projectRollingRunway(SAMPLE_ROWS, "5000000", "50000", 4, NOW);
    expect(weeks).toHaveLength(4);
    expect(weeks[0].openingLiquidityBaseUnits).toBe("5000000");
    expect(BigInt(weeks[0].weeklyBurnBaseUnits)).toBe(350000n);
    expect(weeks.every((w) => BigInt(w.closingLiquidityBaseUnits) >= 0n)).toBe(true);
  });

  it("bands cash-flow risk deterministically and marks ineligible states critical", () => {
    const aging = aggregateAgingSchedule(SAMPLE_ROWS, NOW);
    const eligible = assessCashflowRisk(computeCashflowState("5000000", "50000", aging, BASE_POLICY));
    expect(eligible.band).toBe("low");
    expect(eligible.eligible).toBe(true);
    const broken = assessCashflowRisk(computeCashflowState("1000000", "50000", aging, BASE_POLICY));
    expect(broken.band).toBe("critical");
    expect(broken.eligible).toBe(false);
  });

  it("validates the public policy bounds", () => {
    expect(() => requireCashflowPolicy({ ...BASE_POLICY, minRunwayDays: -1 })).toThrow(/minimum runway/i);
    expect(() => requireCashflowPolicy({ ...BASE_POLICY, maxDsoDays: MAX_DSO_DAYS + 1 })).toThrow(/maximum DSO/i);
    expect(() => requireCashflowPolicy({ ...BASE_POLICY, maxPastDueShareBps: 10001 })).toThrow(/past-due share/i);
  });
});

describe("certificate lifecycle and round-trip", { timeout: PROOF_TIMEOUT }, () => {
  it("issues, verifies, serializes, and re-verifies a certificate", () => {
    const { certificate, secret } = issueCashflowCertificate(baseInput(), NOW, makeEntropy("lifecycle"));
    expect(certificate.proof.proofSystem).toBe(CASHFLOW_PROOF_SYSTEM);
    expect(certificate.proof.surplusBitLength).toBe(32 + CASHFLOW_SURPLUS_EXTRA_BITS);
    expect(certificate.poolAddress).toBe(STRK20_POOL_ADDRESS);
    expect(CASHFLOW_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
    expect(verifyCashflowCertificate(certificate)).toBe(true);

    const round = parseCashflowCertificate(serializeCashflowCertificate(certificate));
    expect(round.bindingHash).toBe(certificate.bindingHash);
    expect(verifyCashflowCertificate(round)).toBe(true);

    const secretRound = parseCashflowCertificateSecret(serializeCashflowCertificateSecret(secret));
    expect(secretRound.liquidityBaseUnits).toBe(secret.liquidityBaseUnits);
    expect(secretRound.bucketAmountsBaseUnits).toEqual(secret.bucketAmountsBaseUnits);
  });

  it("verifies a request sitting right at the runway floor (zero runway surplus)", () => {
    const { certificate } = issueCashflowCertificate(
      baseInput({
        liquidityBaseUnits: "1500000",
        burnRateBaseUnits: "50000",
        policy: { ...BASE_POLICY, minRunwayDays: 30 },
      }),
      NOW,
      makeEntropy("edge"),
    );
    expect(verifyCashflowCertificate(certificate)).toBe(true);
  });

  it("builds a badge with public display and no secret figures", () => {
    const { certificate, secret } = issueCashflowCertificate(baseInput(), NOW, makeEntropy("badge"));
    const badge = buildCashflowCertificateBadge(certificate);
    expect(badge.bookRef).toBe("AR-BOOK-2026-Q3");
    expect(badge.counterpartyCommitted).toBe(true);
    const json = JSON.stringify(badge);
    expect(json).not.toContain(secret.counterpartyRef);
    expect(json).not.toContain(secret.liquidityBaseUnits);
  });
});

describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest when a policy surplus is negative", () => {
    expect(() => issueCashflowCertificate(baseInput({ liquidityBaseUnits: "1000000" }), NOW, makeEntropy("g1"))).toThrow(
      /no honest eligibility proof/i,
    );
  });

  it("rejects liquidity outside the provable bit band", () => {
    expect(() => issueCashflowCertificate(baseInput({ liquidityBaseUnits: (1n << 32n).toString() }), NOW, makeEntropy("g2"))).toThrow(
      /32-bit band/i,
    );
  });

  it("rejects a malformed issuer secret key", () => {
    expect(() => issueCashflowCertificate(baseInput({ issuerSecretKey: "0xnothex" }), NOW, makeEntropy("g3"))).toThrow(/scalar/i);
  });
});

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueCashflowCertificate(baseInput(), NOW, makeEntropy("tamper"));

  it("baseline verifies", () => {
    expect(verifyCashflowCertificate(issued.certificate)).toBe(true);
  });

  it("rejects a changed public minimum runway", () => {
    const v = clone(issued.certificate);
    v.minRunwayDays = "60";
    expect(verifyCashflowCertificate(v)).toBe(false);
  });

  it("rejects an altered binding hash", () => {
    const v = clone(issued.certificate);
    v.bindingHash = v.bindingHash === "0x0" ? "0x1" : `${v.bindingHash}0`;
    expect(verifyCashflowCertificate(v)).toBe(false);
  });

  it("rejects a forged issuer signature", () => {
    const v = clone(issued.certificate);
    v.issuerSignature = { ...v.issuerSignature, response: "0x1" };
    expect(verifyCashflowCertificate(v)).toBe(false);
  });

  it("rejects a tampered runway surplus range-proof bit", () => {
    const v = clone(issued.certificate);
    v.proof.runwaySurplusBits[0] = { ...v.proof.runwaySurplusBits[0], response0: "0x1" };
    expect(verifyCashflowCertificate(v)).toBe(false);
  });

  it("rejects a prover-substituted generator H", () => {
    const v = clone(issued.certificate);
    v.proof.generatorH = { ...v.issuerPublicKey };
    expect(verifyCashflowCertificate(v)).toBe(false);
  });
});

describe("selective disclosure", { timeout: PROOF_TIMEOUT }, () => {
  const issued = issueCashflowCertificate(baseInput(), NOW, makeEntropy("disc"));

  it("discloses liquidity alone and verifies it", () => {
    const disclosure = buildCashflowAmountDisclosure(issued.secret, "liquidity");
    expect(disclosure.amountBaseUnits).toBe(issued.secret.liquidityBaseUnits);
    expect(verifyCashflowAmountDisclosure(issued.certificate, disclosure)).toBe(true);
    const round = parseCashflowAmountDisclosure(serializeCashflowAmountDisclosure(disclosure));
    expect(verifyCashflowAmountDisclosure(issued.certificate, round)).toBe(true);
    expect(verifyCashflowAmountDisclosure(issued.certificate, { ...disclosure, amountBaseUnits: "1" })).toBe(false);
  });

  it("discloses book and counterparty references and verifies them", () => {
    const book = buildCashflowBookRefDisclosure(issued.secret);
    expect(book.value).toBe("AR-BOOK-2026-Q3");
    expect(verifyCashflowRefDisclosure(issued.certificate, book)).toBe(true);
    const counterparty = buildCashflowCounterpartyDisclosure(issued.secret);
    expect(verifyCashflowRefDisclosure(issued.certificate, counterparty)).toBe(true);
    const round = parseCashflowRefDisclosure(serializeCashflowRefDisclosure(counterparty));
    expect(verifyCashflowRefDisclosure(issued.certificate, round)).toBe(true);
    expect(verifyCashflowRefDisclosure(issued.certificate, { ...counterparty, value: "other" })).toBe(false);
  });
});

describe("zero-knowledge hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("never embeds liquidity, burn, bucket amounts, or counterparty refs in the certificate", () => {
    const { certificate, secret } = issueCashflowCertificate(
      baseInput({
        liquidityBaseUnits: "3813579246",
        burnRateBaseUnits: "7123456",
        bucketAmountsBaseUnits: ["8888888", "7777777", "6666666", "0", "0"],
        weightedSettlementDays: "222222210",
        counterpartyRef: "SECRET-COUNTERPARTY-ZZZ",
      }),
      NOW,
      makeEntropy("hiding"),
    );
    expect(verifyCashflowCertificate(certificate)).toBe(true);
    const structured = JSON.stringify(certificate);
    const serialized = serializeCashflowCertificate(certificate);
    for (const surface of [structured, serialized]) {
      expect(surface).not.toContain(secret.liquidityBlinding);
      expect(surface).not.toContain(secret.burnBlinding);
      expect(surface).not.toContain(secret.liquidityBaseUnits);
      expect(surface).not.toContain(secret.burnRateBaseUnits);
      expect(surface).not.toContain("SECRET-COUNTERPARTY-ZZZ");
      for (const blinding of secret.bucketBlindings) expect(surface).not.toContain(blinding);
      for (const amount of secret.bucketAmountsBaseUnits) {
        if (amount !== "0") expect(surface).not.toContain(amount);
      }
    }
    expect(structured).toContain("AR-BOOK-2026-Q3");
  });
});

describe("honest trust and visibility model", () => {
  it("summarizes the trust model with the required honest limits", () => {
    const trust = summarizeCashflowTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesRunwayCovenant).toBe(true);
    expect(trust.provesDsoCovenant).toBe(true);
    expect(trust.provesConcentrationCovenant).toBe(true);
    expect(trust.hidesInvoiceList).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isFinancialAdvice).toBe(false);
    expect(trust.statement).toContain("never reads from or writes to the STRK20 pool contract");
  });

  it("states the visibility limitation and lists hidden vs disclosed data", () => {
    const model = getCashflowVisibilityModel();
    expect(model.limitation).toContain("never reads from or writes to the STRK20 pool contract");
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
  });
});

describe("generator and formatting helpers", () => {
  it("derives a stable, canonical generator H", () => {
    const a = deriveCashflowGenerator();
    const b = deriveCashflowGenerator();
    expect(a).toEqual(b);
  });

  it("formats runway, DSO, share, and base-unit amounts for display", () => {
    expect(formatRunwayDays(100)).toBe("100 days");
    expect(formatDsoDays(8)).toBe("8 days");
    expect(formatShareBps(5000)).toBe("50%");
    expect(formatCashflowBaseUnits("200000000000000000000", 18)).toBe("200");
  });

  it("rejects a malformed encoded certificate", () => {
    expect(() => parseCashflowCertificate("!!not base64!!")).toThrow(/encoding is invalid/i);
  });
});
