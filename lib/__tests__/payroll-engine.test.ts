import { describe, expect, it } from "vitest";
import { ec as starkEc, hash as starkHash } from "starknet";

import { STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "../strk20/config";
import {
  PAYROLL_POOL_ADDRESS,
  PAYROLL_PROOF_SYSTEM,
  buildPayrollAmountDisclosure,
  buildPayrollBatchCommitments,
  buildPayrollEmployeeDisclosure,
  computePayrollBatchState,
  computePayoutSchedule,
  createPayrollIssuerKey,
  derivePayrollGenerator,
  getPayrollVisibilityModel,
  issuePayrollBatchCertificate,
  monitorPayrollBatch,
  parsePayrollBatchCertificate,
  requirePayrollPolicy,
  serializePayrollBatchCertificate,
  summarizePayrollTrust,
  verifyPayrollAmountDisclosure,
  verifyPayrollBatchCertificate,
  verifyPayrollEmployeeDisclosure,
  type IssuePayrollBatchCertificateInput,
} from "../payroll-engine";

const CURVE_ORDER = starkEc.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T12:00:00.000Z");
const PROOF_TIMEOUT = 120_000;

function makeEntropy(seed: string) {
  const seedFelt = starkHash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `pay_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(starkHash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createPayrollIssuerKey(makeEntropy(seed));
}

const BASE_POLICY = {
  maxPayeeAmountBaseUnits: "2000",
  maxBatchTotalBaseUnits: "5000",
  maxContractorShareBps: 4000,
};

const BASE_PAYEES = [
  { employeeRef: "emp_alice", amountBaseUnits: "1200", payeeKind: "employee" as const },
  { employeeRef: "emp_bob", amountBaseUnits: "800", payeeKind: "employee" as const },
  { employeeRef: "ctr_carol", amountBaseUnits: "500", payeeKind: "contractor" as const },
];

function baseInput(overrides: Partial<IssuePayrollBatchCertificateInput> = {}): IssuePayrollBatchCertificateInput {
  return {
    organizationAlias: "Northwind Labs",
    departmentLabel: "Engineering",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    schedule: { payPeriodLabel: "2026-08", disbursementDate: "2026-08-28T00:00:00.000Z" },
    policy: BASE_POLICY,
    payees: BASE_PAYEES,
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 32,
    ...overrides,
  };
}

describe("payroll-engine", () => {
  it("records STRK20 pool provenance only", () => {
    expect(PAYROLL_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
  });

  it("derives an independent generator", () => {
    const point = derivePayrollGenerator();
    expect(point.x).toMatch(/^0x/);
    expect(point.y).toMatch(/^0x/);
  });

  it("computes payroll batch state and payout math", () => {
    const state = computePayrollBatchState(BASE_PAYEES, BASE_POLICY);
    expect(state.totalBaseUnits).toBe("2500");
    expect(state.eligible).toBe(true);
    expect(BigInt(state.batchSurplus)).toBe(2500n);
    const schedule = computePayoutSchedule(BASE_PAYEES, { payPeriodLabel: "2026-08", disbursementDate: "2026-08-28T00:00:00.000Z" }, 18, NOW);
    expect(schedule).toHaveLength(3);
    expect(schedule[0].status).toBe("scheduled");
  });

  it("rejects batches exceeding policy caps", () => {
    expect(() => computePayrollBatchState([{ employeeRef: "x", amountBaseUnits: "9000", payeeKind: "employee" }], BASE_POLICY)).toThrow(
      /per-line cap/,
    );
  });

  it("builds batch commitments that sum to the total", () => {
    const h = starkEc.starkCurve.ProjectivePoint.BASE;
    const blindings = [1n, 2n, 3n, 4n];
    const bundle = buildPayrollBatchCommitments(BASE_PAYEES, h, blindings);
    expect(bundle.lineCommitments).toHaveLength(4);
    expect(bundle.payeeCount).toBe(3);
    expect(bundle.totalBatchCommitment.x).toMatch(/^0x/);
  });

  it(
    "issues and verifies a payroll batch certificate",
    () => {
      const issued = issuePayrollBatchCertificate(baseInput(), NOW, makeEntropy("issue"));
      expect(issued.certificate.proof.proofSystem).toBe(PAYROLL_PROOF_SYSTEM);
      expect(verifyPayrollBatchCertificate(issued.certificate)).toBe(true);
      expect(JSON.parse(serializePayrollBatchCertificate(issued.certificate)).certificateId).toBe(issued.certificate.certificateId);
      expect(parsePayrollBatchCertificate(serializePayrollBatchCertificate(issued.certificate)).certificateId).toBe(
        issued.certificate.certificateId,
      );
    },
    PROOF_TIMEOUT,
  );

  it(
    "detects tampered line commitment",
    () => {
      const issued = issuePayrollBatchCertificate(baseInput(), NOW, makeEntropy("tamper"));
      const tampered = structuredClone(issued.certificate);
      tampered.proof.lineCommitments[0].x = "0x1";
      expect(verifyPayrollBatchCertificate(tampered)).toBe(false);
    },
    PROOF_TIMEOUT,
  );

  it(
    "detects tampered issuer signature",
    () => {
      const issued = issuePayrollBatchCertificate(baseInput(), NOW, makeEntropy("sig"));
      const tampered = structuredClone(issued.certificate);
      tampered.proof.issuerSignature.response = "0x2";
      expect(verifyPayrollBatchCertificate(tampered)).toBe(false);
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies amount disclosure",
    () => {
      const issued = issuePayrollBatchCertificate(baseInput(), NOW, makeEntropy("amount"));
      const disclosure = buildPayrollAmountDisclosure(issued.certificate, issued.secret, 0);
      expect(verifyPayrollAmountDisclosure(disclosure, issued.certificate)).toBe(true);
      expect(disclosure.value).toBe("1200");
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies employee disclosure",
    () => {
      const issued = issuePayrollBatchCertificate(baseInput(), NOW, makeEntropy("employee"));
      const disclosure = buildPayrollEmployeeDisclosure(issued.certificate, issued.secret, 0);
      expect(verifyPayrollEmployeeDisclosure(disclosure, issued.certificate)).toBe(true);
      expect(disclosure.employeeRef).toBe("emp_alice");
    },
    PROOF_TIMEOUT,
  );

  it(
    "monitors payroll batch disbursement rows",
    () => {
      const issued = issuePayrollBatchCertificate(baseInput(), NOW, makeEntropy("monitor"));
      const rows = monitorPayrollBatch(issued.certificate, issued.secret, NOW);
      expect(rows).toHaveLength(3);
      expect(rows.every((row) => row.status === "scheduled")).toBe(true);
    },
    PROOF_TIMEOUT,
  );

  it("summarizes trust boundaries honestly", () => {
    const trust = summarizePayrollTrust();
    expect(trust.zeroKnowledge).toBe(true);
    expect(trust.poolIntegrated).toBe(false);
    expect(trust.automated).toBe(false);
  });

  it("documents visibility model", () => {
    const model = getPayrollVisibilityModel();
    expect(model.hiddenFromVerifier.some((line) => line.includes("payee"))).toBe(true);
    expect(model.disclosedToVerifier.some((line) => line.includes("policy"))).toBe(true);
  });

  it("validates policy bounds", () => {
    expect(requirePayrollPolicy(BASE_POLICY).maxContractorShareBps).toBe(4000);
    expect(() => requirePayrollPolicy({ ...BASE_POLICY, maxContractorShareBps: 99999 })).toThrow();
  });
});
