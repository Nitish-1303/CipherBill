import { describe, expect, it } from "vitest";
import { ec as starkEc, hash as starkHash } from "starknet";

import { STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "../strk20/config";
import { computeVat } from "../vat-engine";
import {
  VAT_COMPLIANCE_POOL_ADDRESS,
  VAT_COMPLIANCE_PROOF_SYSTEM,
  aggregateJurisdictionBreakdown,
  buildComplianceCommitments,
  buildComplianceJurisdictionDisclosure,
  buildComplianceNetDisclosure,
  computeComplianceBatchState,
  computeComplianceLine,
  computeMembershipRoot,
  createVatComplianceIssuerKey,
  deriveVatComplianceGenerator,
  getComplianceJurisdictions,
  getVatComplianceVisibilityModel,
  issueVatComplianceCertificate,
  parseVatComplianceCertificate,
  requireVatCompliancePolicy,
  resolveComplianceJurisdiction,
  serializeVatComplianceCertificate,
  summarizeVatComplianceTrust,
  verifyComplianceJurisdictionDisclosure,
  verifyComplianceNetDisclosure,
  verifyJurisdictionMembership,
  verifyVatComplianceCertificate,
  type IssueVatComplianceCertificateInput,
} from "../vat-compliance-engine";

const CURVE_ORDER = starkEc.starkCurve.CURVE.n;
const NOW = new Date("2026-08-25T12:00:00.000Z");
const PROOF_TIMEOUT = 120_000;

function makeEntropy(seed: string) {
  const seedFelt = starkHash.starknetKeccak(seed);
  let counter = 0;
  let idCounter = 0;
  return {
    createId: () => `vcomp_test_${seed}_${(idCounter += 1)}`,
    randomScalar: () =>
      (BigInt(starkHash.computePoseidonHashOnElements([seedFelt, BigInt((counter += 1))])) % (CURVE_ORDER - 1n)) + 1n,
  };
}

function issuerKey(seed = "issuer") {
  return createVatComplianceIssuerKey(makeEntropy(seed));
}

const BASE_POLICY = {
  maxNetPerLineBaseUnits: "2000",
  maxTotalTaxBaseUnits: "800",
};

const BASE_LINES = [
  { jurisdictionCode: "GB", netBaseUnits: "1000", customerRegionRef: "eu-west-1" },
  { jurisdictionCode: "EU-DE", netBaseUnits: "800", customerRegionRef: "eu-central-1" },
  { jurisdictionCode: "SG", netBaseUnits: "500", customerRegionRef: "ap-southeast-1" },
];

function baseInput(overrides: Partial<IssueVatComplianceCertificateInput> = {}): IssueVatComplianceCertificateInput {
  return {
    merchantAlias: "Northwind Labs",
    asset: { symbol: "STRK", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 18 },
    filing: { filingPeriodLabel: "2026-Q3", filingDueDate: "2026-10-31T00:00:00.000Z" },
    policy: BASE_POLICY,
    lines: BASE_LINES,
    issuerSecretKey: issuerKey().secretKey,
    amountBitLength: 32,
    ...overrides,
  };
}

describe("vat-compliance-engine", () => {
  it("records STRK20 pool provenance only", () => {
    expect(VAT_COMPLIANCE_POOL_ADDRESS).toBe(STRK20_POOL_ADDRESS);
  });

  it("derives an independent generator", () => {
    const point = deriveVatComplianceGenerator();
    expect(point.x).toMatch(/^0x/);
    expect(point.y).toMatch(/^0x/);
  });

  it("maps jurisdictions and verifies membership", () => {
    const gb = resolveComplianceJurisdiction("gb");
    expect(gb.code).toBe("GB");
    expect(verifyJurisdictionMembership("EU-DE")).toBe(true);
    expect(verifyJurisdictionMembership("XX")).toBe(false);
    expect(getComplianceJurisdictions().length).toBeGreaterThan(5);
  });

  it("computes jurisdiction VAT using statutory rates", () => {
    const gb = computeComplianceLine({ jurisdictionCode: "GB", netBaseUnits: "1000" });
    const expected = computeVat("1000", 2000);
    expect(gb.taxBaseUnits).toBe(expected.taxBaseUnits);
    expect(gb.grossBaseUnits).toBe(expected.grossBaseUnits);
  });

  it("computes batch state and membership root", () => {
    const state = computeComplianceBatchState(BASE_LINES, BASE_POLICY);
    expect(state.lineCount).toBe(3);
    expect(state.eligible).toBe(true);
    expect(BigInt(state.totalTaxBaseUnits)).toBeGreaterThan(0n);
    expect(computeMembershipRoot(BASE_LINES.map((line) => line.jurisdictionCode))).toMatch(/^0x/);
  });

  it("builds compliance commitments that sum to totals", () => {
    const h = starkEc.starkCurve.ProjectivePoint.BASE;
    const blindings = [1n, 2n, 3n, 4n];
    const bundle = buildComplianceCommitments(BASE_LINES, h, blindings, blindings);
    expect(bundle.netLineCommitments).toHaveLength(4);
    expect(bundle.lineCount).toBe(3);
  });

  it(
    "issues and verifies a compliance certificate",
    () => {
      const issued = issueVatComplianceCertificate(baseInput(), NOW, makeEntropy("issue"));
      expect(issued.certificate.proof.proofSystem).toBe(VAT_COMPLIANCE_PROOF_SYSTEM);
      expect(verifyVatComplianceCertificate(issued.certificate)).toBe(true);
      expect(JSON.parse(serializeVatComplianceCertificate(issued.certificate)).certificateId).toBe(issued.certificate.certificateId);
      expect(parseVatComplianceCertificate(serializeVatComplianceCertificate(issued.certificate)).certificateId).toBe(
        issued.certificate.certificateId,
      );
    },
    PROOF_TIMEOUT,
  );

  it(
    "detects tampered net line commitment",
    () => {
      const issued = issueVatComplianceCertificate(baseInput(), NOW, makeEntropy("tamper"));
      const tampered = structuredClone(issued.certificate);
      tampered.proof.netLineCommitments[0].x = "0x1";
      expect(verifyVatComplianceCertificate(tampered)).toBe(false);
    },
    PROOF_TIMEOUT,
  );

  it(
    "detects tampered issuer signature",
    () => {
      const issued = issueVatComplianceCertificate(baseInput(), NOW, makeEntropy("sig"));
      const tampered = structuredClone(issued.certificate);
      tampered.proof.issuerSignature.response = "0x2";
      expect(verifyVatComplianceCertificate(tampered)).toBe(false);
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies net disclosure",
    () => {
      const issued = issueVatComplianceCertificate(baseInput(), NOW, makeEntropy("net"));
      const disclosure = buildComplianceNetDisclosure(issued.certificate, issued.secret, 0);
      expect(verifyComplianceNetDisclosure(disclosure, issued.certificate)).toBe(true);
      expect(disclosure.value).toBe("1000");
    },
    PROOF_TIMEOUT,
  );

  it(
    "opens and verifies jurisdiction disclosure",
    () => {
      const issued = issueVatComplianceCertificate(baseInput(), NOW, makeEntropy("jurisdiction"));
      const disclosure = buildComplianceJurisdictionDisclosure(issued.certificate, issued.secret, 0);
      expect(verifyComplianceJurisdictionDisclosure(disclosure, issued.certificate)).toBe(true);
      expect(disclosure.jurisdictionCode).toBe("GB");
    },
    PROOF_TIMEOUT,
  );

  it(
    "aggregates jurisdiction breakdown rows",
    () => {
      const issued = issueVatComplianceCertificate(baseInput(), NOW, makeEntropy("breakdown"));
      const rows = aggregateJurisdictionBreakdown(issued.certificate, issued.secret);
      expect(rows).toHaveLength(3);
      expect(rows.every((row) => row.membershipOk)).toBe(true);
    },
    PROOF_TIMEOUT,
  );

  it("summarizes trust boundaries honestly", () => {
    const trust = summarizeVatComplianceTrust();
    expect(trust.zeroKnowledge).toBe(true);
    expect(trust.filesWithAuthority).toBe(false);
    expect(trust.poolIntegrated).toBe(false);
  });

  it("documents visibility model", () => {
    const model = getVatComplianceVisibilityModel();
    expect(model.hiddenFromVerifier.some((line) => line.includes("jurisdiction"))).toBe(true);
    expect(model.disclosedToVerifier.some((line) => line.includes("Filing"))).toBe(true);
  });

  it("validates policy bounds", () => {
    expect(requireVatCompliancePolicy(BASE_POLICY).maxTotalTaxBaseUnits).toBe("800");
    expect(() => requireVatCompliancePolicy({ ...BASE_POLICY, maxTotalTaxBaseUnits: "-1" })).toThrow();
  });
});
