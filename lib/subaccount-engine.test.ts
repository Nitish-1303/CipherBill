import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import {
  buildSubaccountCertificateBadge,
  buildSubaccountCertificateOpening,
  buildSubaccountDepartmentDisclosure,
  buildSubaccountEnterpriseDisclosure,
  buildSubaccountLabelDisclosure,
  buildSubaccountMetricDisclosure,
  computeSubaccountState,
  createSubaccountIssuerKey,
  deriveSubaccountGenerator,
  formatSubaccountBps,
  getSubaccountVisibilityModel,
  issueSubaccountCertificate,
  parseSubaccountCertificate,
  parseSubaccountCertificateSecret,
  parseSubaccountDepartmentDisclosure,
  parseSubaccountLabelDisclosure,
  parseSubaccountMetricDisclosure,
  parseSubaccountRefDisclosure,
  serializeSubaccountCertificate,
  serializeSubaccountCertificateSecret,
  serializeSubaccountDepartmentDisclosure,
  serializeSubaccountLabelDisclosure,
  serializeSubaccountMetricDisclosure,
  serializeSubaccountRefDisclosure,
  summarizeSubaccountTrust,
  verifySubaccountCertificate,
  verifySubaccountCertificateOpening,
  verifySubaccountDepartmentDisclosure,
  verifySubaccountLabelDisclosure,
  verifySubaccountMetricDisclosure,
  verifySubaccountRefDisclosure,
  type IssuedSubaccountCertificate,
  type IssueSubaccountCertificateInput,
  type SubaccountLedger,
} from "./subaccount-engine";

// Proving is synchronous and CPU-bound; a 16-bit band keeps every leg fast.
const PROVE_TIMEOUT = { timeout: 120_000 };
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

/** Deterministic entropy so proofs are reproducible in tests. */
function makeEntropy(seed: string) {
  const seedFelt = hash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `subaccount_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(hash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

const TOKEN = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
const ISSUER = createSubaccountIssuerKey();

// Distinctive, non-overlapping figures so the ZK-hiding test can grep for them.
const LEDGER: SubaccountLedger = {
  departments: [
    { label: "Engineering", allocationBaseUnits: "31337", spendBaseUnits: "27183" },
    { label: "Marketing", allocationBaseUnits: "18000", spendBaseUnits: "12000" },
    { allocationBaseUnits: "0", spendBaseUnits: "0" }, // an unlabelled, unfunded department
  ],
};
const BUDGET_CAP = "60000"; // total allocated (49337) fits under this public cap

const BASE_INPUT: IssueSubaccountCertificateInput = {
  enterpriseAlias: "Acme Robotics",
  asset: { symbol: "USDC", tokenAddress: TOKEN, decimals: 6 },
  periodLabel: "FY26 Q3",
  programLabel: "Departmental Operating Budget",
  budgetCapBaseUnits: BUDGET_CAP,
  ledger: LEDGER,
  enterpriseRef: "acme-holdings-ein-88-1234567",
  issuerSecretKey: ISSUER.secretKey,
  amountBitLength: 16,
  memo: "Q3 governance attestation",
};

let cachedSample: IssuedSubaccountCertificate | null = null;
function sample(): IssuedSubaccountCertificate {
  if (!cachedSample) cachedSample = issueSubaccountCertificate(BASE_INPUT);
  return cachedSample;
}

let cachedOther: IssuedSubaccountCertificate | null = null;
function other(): IssuedSubaccountCertificate {
  if (!cachedOther) {
    cachedOther = issueSubaccountCertificate({
      ...BASE_INPUT,
      enterpriseAlias: "Globex Interstellar",
      issuerSecretKey: createSubaccountIssuerKey().secretKey,
    });
  }
  return cachedOther;
}

describe("computeSubaccountState", () => {
  it("breaks down headroom, utilization, aggregates, and cap fit", () => {
    const state = computeSubaccountState(LEDGER, BUDGET_CAP);
    expect(state.departmentCount).toBe(3);
    expect(state.totalAllocatedBaseUnits).toBe("49337");
    expect(state.totalSpentBaseUnits).toBe("39183");
    expect(state.unallocatedBaseUnits).toBe("10663");
    expect(state.totalHeadroomBaseUnits).toBe("10154");
    expect(state.fitsBudget).toBe(true);
    expect(state.departments[0].headroomBaseUnits).toBe("4154");
    expect(state.departments[2].headroomBaseUnits).toBe("0");
  });

  it("rejects a department that overspends its allocation", () => {
    const bad: SubaccountLedger = { departments: [{ allocationBaseUnits: "100", spendBaseUnits: "101" }] };
    expect(() => computeSubaccountState(bad, "1000")).toThrow(/exceeds its allocation/);
  });

  it("rejects an aggregate allocation that breaches the budget cap", () => {
    expect(() => computeSubaccountState(LEDGER, "40000")).toThrow(/exceeds the budget cap/);
  });

  it("rejects an empty or oversized department set", () => {
    expect(() => computeSubaccountState({ departments: [] }, "1000")).toThrow(/between/);
    const many = { departments: Array.from({ length: 17 }, () => ({ allocationBaseUnits: "1", spendBaseUnits: "0" })) };
    expect(() => computeSubaccountState(many, "1000000")).toThrow(/between/);
  });

  it("formats basis points for display", () => {
    expect(formatSubaccountBps(2500)).toBe("25%");
    expect(formatSubaccountBps("250")).toBe("2.5%");
  });
});

describe("input validation", () => {
  it("rejects a blank enterprise alias", () => {
    expect(() => issueSubaccountCertificate({ ...BASE_INPUT, enterpriseAlias: "  " })).toThrow(/enterprise alias/);
  });

  it("rejects asset decimals outside [0, 18]", () => {
    expect(() => issueSubaccountCertificate({ ...BASE_INPUT, asset: { ...BASE_INPUT.asset, decimals: 19 } })).toThrow(/asset decimals/);
  });

  it("rejects a figure that overflows the proven bit band", () => {
    const over: SubaccountLedger = { departments: [{ allocationBaseUnits: "70000", spendBaseUnits: "0" }] };
    expect(() => issueSubaccountCertificate({ ...BASE_INPUT, ledger: over, budgetCapBaseUnits: "70000" })).toThrow(/bit band/);
  });

  it("rejects an aggregate allocation above the budget cap", () => {
    expect(() => issueSubaccountCertificate({ ...BASE_INPUT, budgetCapBaseUnits: "40000" })).toThrow(/exceeds the budget cap/);
  });

  it("rejects a non-scalar issuer secret key", () => {
    expect(() => issueSubaccountCertificate({ ...BASE_INPUT, issuerSecretKey: "not-a-scalar" })).toThrow(/scalar/);
  });
});

describe("pure primitives", () => {
  it("derives a deterministic independent generator distinct from G", () => {
    const a = deriveSubaccountGenerator();
    const b = deriveSubaccountGenerator();
    expect(a).toEqual(b);
    expect(a.x).toMatch(/^0x[0-9a-f]+$/);
    expect(a.y).toMatch(/^0x[0-9a-f]+$/);
    expect(BigInt(a.x)).not.toBe(1n); // G.x on the Stark curve is 1
  });

  it("mints distinct issuer keypairs", () => {
    const k1 = createSubaccountIssuerKey();
    const k2 = createSubaccountIssuerKey();
    expect(k1.role).toBe("issuer");
    expect(k1.secretKey).toMatch(/^0x[0-9a-f]+$/);
    expect(k1.secretKey).not.toBe(k2.secretKey);
  });
});

describe("issue and verify", () => {
  it("issues a certificate that verifies end to end", PROVE_TIMEOUT, () => {
    const { certificate } = sample();
    expect(certificate.departmentCount).toBe(3);
    expect(certificate.budgetCapBaseUnits).toBe(BUDGET_CAP);
    expect(certificate.proof.amountBitLength).toBe(16);
    expect(verifySubaccountCertificate(certificate)).toBe(true);
  });

  it("rejects a tampered issuer signature", PROVE_TIMEOUT, () => {
    const bad = clone(sample().certificate);
    bad.issuerSignature.response = `0x${(BigInt(bad.issuerSignature.response) ^ 1n).toString(16)}`;
    expect(verifySubaccountCertificate(bad)).toBe(false);
  });

  it("rejects a tampered department commitment", PROVE_TIMEOUT, () => {
    const bad = clone(sample().certificate);
    const c = bad.proof.departments[0].allocationCommitment;
    c.x = `0x${(BigInt(c.x) ^ 1n).toString(16)}`;
    expect(verifySubaccountCertificate(bad)).toBe(false);
  });

  it("rejects an altered department count", PROVE_TIMEOUT, () => {
    const bad = clone(sample().certificate);
    bad.departmentCount = 2;
    expect(verifySubaccountCertificate(bad)).toBe(false);
  });

  it("rejects an altered public budget cap", PROVE_TIMEOUT, () => {
    const bad = clone(sample().certificate);
    bad.budgetCapBaseUnits = "70000";
    expect(verifySubaccountCertificate(bad)).toBe(false);
  });

  it("rejects an altered enterprise alias", PROVE_TIMEOUT, () => {
    const bad = clone(sample().certificate);
    bad.enterpriseAlias = "Someone Else";
    expect(verifySubaccountCertificate(bad)).toBe(false);
  });
});

describe("zero-knowledge hiding", () => {
  it("never leaks a hidden figure, label, or reference in the public certificate", PROVE_TIMEOUT, () => {
    const hidingLedger: SubaccountLedger = {
      departments: [
        { label: "LABEL-ENG-ZZZ", allocationBaseUnits: "918273645981", spendBaseUnits: "827364591237" },
        { label: "LABEL-MKT-ZZZ", allocationBaseUnits: "718273645981", spendBaseUnits: "617273645981" },
        { allocationBaseUnits: "0", spendBaseUnits: "0" },
      ],
    };
    const hidingCap = "2800000000000";
    const { certificate, secret } = issueSubaccountCertificate(
      {
        ...BASE_INPUT,
        ledger: hidingLedger,
        budgetCapBaseUnits: hidingCap,
        enterpriseRef: "SECRET-ENT-ZZZ",
        amountBitLength: 48,
      },
      new Date(),
      makeEntropy("hiding"),
    );
    expect(verifySubaccountCertificate(certificate)).toBe(true);

    const structured = JSON.stringify(certificate);
    const serialized = serializeSubaccountCertificate(certificate);
    for (const surface of [structured, serialized]) {
      for (const allocation of secret.allocationsBaseUnits) {
        if (allocation !== "0") expect(surface).not.toContain(allocation);
      }
      for (const spend of secret.spendsBaseUnits) {
        if (spend !== "0") expect(surface).not.toContain(spend);
      }
      for (const blinding of secret.allocationBlindings) expect(surface).not.toContain(blinding);
      for (const blinding of secret.spendBlindings) expect(surface).not.toContain(blinding);
      for (const salt of secret.labelSalts) expect(surface).not.toContain(salt);
      for (const label of secret.labels) {
        if (label) expect(surface).not.toContain(label);
      }
      expect(surface).not.toContain(secret.totalAllocatedBlinding);
      expect(surface).not.toContain(secret.totalSpentBlinding);
      expect(surface).not.toContain(secret.enterpriseRef);
      expect(surface).not.toContain(secret.enterpriseSalt);
      expect(surface).not.toContain("SECRET-ENT-ZZZ");
    }
    // The public cap and department count are disclosed by design.
    expect(structured).toContain(hidingCap);
    expect(structured).toContain("\"departmentCount\":3");
  });
});

describe("selective disclosure", () => {
  it("opens a single aggregate (allocated or spent) without opening the other", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const allocated = buildSubaccountMetricDisclosure(secret, "allocated");
    const spent = buildSubaccountMetricDisclosure(secret, "spent");
    expect(allocated.valueBaseUnits).toBe("49337");
    expect(spent.valueBaseUnits).toBe("39183");
    expect(verifySubaccountMetricDisclosure(certificate, allocated)).toBe(true);
    expect(verifySubaccountMetricDisclosure(certificate, spent)).toBe(true);
  });

  it("rejects a metric disclosure with a doctored value", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const bad = buildSubaccountMetricDisclosure(secret, "allocated");
    bad.valueBaseUnits = "49338";
    expect(verifySubaccountMetricDisclosure(certificate, bad)).toBe(false);
  });

  it("opens a single department's allocation and spend", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const alloc = buildSubaccountDepartmentDisclosure(secret, 0, "allocated");
    const spend = buildSubaccountDepartmentDisclosure(secret, 0, "spent");
    expect(alloc.valueBaseUnits).toBe("31337");
    expect(spend.valueBaseUnits).toBe("27183");
    expect(verifySubaccountDepartmentDisclosure(certificate, alloc)).toBe(true);
    expect(verifySubaccountDepartmentDisclosure(certificate, spend)).toBe(true);
  });

  it("opens the unfunded department's zero figures", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const alloc = buildSubaccountDepartmentDisclosure(secret, 2, "allocated");
    expect(alloc.valueBaseUnits).toBe("0");
    expect(verifySubaccountDepartmentDisclosure(certificate, alloc)).toBe(true);
  });

  it("discloses and rejects a department cost-centre label", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const label = buildSubaccountLabelDisclosure(secret, 0);
    expect(label.value).toBe("Engineering");
    expect(verifySubaccountLabelDisclosure(certificate, label)).toBe(true);
    const tampered = { ...label, value: "Finance" };
    expect(verifySubaccountLabelDisclosure(certificate, tampered)).toBe(false);
  });

  it("refuses to build a label disclosure for an unlabelled department", PROVE_TIMEOUT, () => {
    expect(() => buildSubaccountLabelDisclosure(sample().secret, 2)).toThrow(/no label commitment/);
  });

  it("discloses the enterprise reference", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const ref = buildSubaccountEnterpriseDisclosure(secret);
    expect(ref.value).toBe("acme-holdings-ein-88-1234567");
    expect(verifySubaccountRefDisclosure(certificate, ref)).toBe(true);
  });

  it("rejects a disclosure presented against a different certificate", PROVE_TIMEOUT, () => {
    const disclosure = buildSubaccountMetricDisclosure(sample().secret, "allocated");
    expect(verifySubaccountMetricDisclosure(other().certificate, disclosure)).toBe(false);
  });
});

describe("full opening", () => {
  it("verifies a complete opening of every committed figure", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const opening = buildSubaccountCertificateOpening(secret);
    expect(verifySubaccountCertificateOpening(certificate, opening)).toBe(true);
  });

  it("rejects an opening whose figures no longer sum to the aggregate", PROVE_TIMEOUT, () => {
    const { certificate, secret } = sample();
    const opening = buildSubaccountCertificateOpening(secret);
    opening.allocationsBaseUnits[0] = "31338"; // no longer opens the committed point
    expect(verifySubaccountCertificateOpening(certificate, opening)).toBe(false);
  });

  it("rejects an opening from a different certificate", PROVE_TIMEOUT, () => {
    const opening = buildSubaccountCertificateOpening(sample().secret);
    expect(verifySubaccountCertificateOpening(other().certificate, opening)).toBe(false);
  });
});

describe("serialization round-trips", () => {
  it("round-trips a certificate and re-verifies it", PROVE_TIMEOUT, () => {
    const parsed = parseSubaccountCertificate(serializeSubaccountCertificate(sample().certificate));
    expect(parsed).toEqual(sample().certificate);
    expect(verifySubaccountCertificate(parsed)).toBe(true);
  });

  it("round-trips the secret record", PROVE_TIMEOUT, () => {
    const parsed = parseSubaccountCertificateSecret(serializeSubaccountCertificateSecret(sample().secret));
    expect(parsed).toEqual(sample().secret);
  });

  it("round-trips each disclosure kind", PROVE_TIMEOUT, () => {
    const { secret } = sample();
    const metric = buildSubaccountMetricDisclosure(secret, "spent");
    const dept = buildSubaccountDepartmentDisclosure(secret, 1, "allocated");
    const label = buildSubaccountLabelDisclosure(secret, 1);
    const ref = buildSubaccountEnterpriseDisclosure(secret);
    expect(parseSubaccountMetricDisclosure(serializeSubaccountMetricDisclosure(metric))).toEqual(metric);
    expect(parseSubaccountDepartmentDisclosure(serializeSubaccountDepartmentDisclosure(dept))).toEqual(dept);
    expect(parseSubaccountLabelDisclosure(serializeSubaccountLabelDisclosure(label))).toEqual(label);
    expect(parseSubaccountRefDisclosure(serializeSubaccountRefDisclosure(ref))).toEqual(ref);
  });

  it("rejects a token of the wrong kind", PROVE_TIMEOUT, () => {
    const secretToken = serializeSubaccountCertificateSecret(sample().secret);
    expect(() => parseSubaccountCertificate(secretToken)).toThrow(/not a subaccount certificate/);
  });

  it("rejects malformed encodings", () => {
    expect(() => parseSubaccountCertificate("!!!not-base64!!!")).toThrow();
  });
});

describe("presentation honesty", () => {
  it("summarizes the badge from public fields only", PROVE_TIMEOUT, () => {
    const badge = buildSubaccountCertificateBadge(sample().certificate);
    expect(badge.departmentCount).toBe(3);
    expect(badge.enterpriseCommitted).toBe(true);
    expect(badge.budgetCapDisplay).toContain("USDC");
    expect(badge.budgetCapDisplay).toContain("0.06"); // 60000 base units at 6 decimals
  });

  it("states honestly what a passing verdict does NOT establish", () => {
    const trust = summarizeSubaccountTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesNoDepartmentOverspends).toBe(true);
    expect(trust.provesAllocationsFitBudgetCap).toBe(true);
    expect(trust.authenticatesIssuer).toBe(true);
    expect(trust.hidesDepartmentAllocations).toBe(true);
    // The honesty guarantees: this is not a funds-moving, on-chain, or automated product.
    expect(trust.movesOrAllocatesFunds).toBe(false);
    expect(trust.createsOrFundsSubAccounts).toBe(false);
    expect(trust.enforcesSpendingConstraints).toBe(false);
    expect(trust.reducesGas).toBe(false);
    expect(trust.movesPoolFunds).toBe(false);
    expect(trust.verifiesFiguresAreReal).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.isBudgetGuaranteeOrFinancialAdvice).toBe(false);
    expect(trust.statement).toMatch(/does NOT/);
  });

  it("splits visibility into hidden, disclosed, and application-only", () => {
    const model = getSubaccountVisibilityModel();
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
    expect(model.limitation).toMatch(/cannot confirm/);
  });
});









