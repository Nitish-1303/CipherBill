import { describe, expect, it } from "vitest";
import { ec, hash } from "starknet";

import { STRK_TOKEN_ADDRESS } from "./strk20/config";
import {
  buildReservesAttestation,
  buildReservesBadge,
  deriveReservesGenerator,
  formatReservesBaseUnits,
  getReservesVisibilityModel,
  parseReservesAttestation,
  parseReservesSecret,
  serializeReservesAttestation,
  serializeReservesSecret,
  summarizeReservesTrust,
  verifyReservesAttestation,
  verifyReservesOpening,
  type BuildReservesAttestationInput,
  type ReservesAsset,
} from "./reserves-engine";

const CURVE_ORDER = ec.starkCurve.CURVE.n;
const USDC: ReservesAsset = { symbol: "USDC", tokenAddress: STRK_TOKEN_ADDRESS, decimals: 6 };
const NOW = new Date("2026-08-23T00:00:00.000Z");
// Bit-range proofs run many curve multiplications in pure JS; give each suite ample
// headroom so a loaded CI box never trips the 5s default before the proof completes.
const PROOF_TIMEOUT = 60_000;

/** Deterministic entropy: stable ids and a reproducible stream of nonzero scalars. */
function makeEntropy(seed = 1) {
  let idCounter = 0;
  let counter = 0;
  return {
    createId: () => `res_test_${(idCounter += 1)}`,
    randomScalar: () => {
      counter += 1;
      const v = BigInt(hash.computePoseidonHashOnElements([BigInt(seed), BigInt(counter)]));
      return (v % (CURVE_ORDER - 1n)) + 1n;
    },
  };
}

function build(overrides: Partial<BuildReservesAttestationInput> = {}, seed = 1) {
  const input: BuildReservesAttestationInput = {
    merchantAlias: "Northwind Labs",
    asset: USDC,
    reserveBaseUnits: "1000042",
    thresholdBaseUnits: "1000000",
    bitLength: 32,
    memo: "Q3 attestation",
    ...overrides,
  };
  return buildReservesAttestation(input, NOW, makeEntropy(seed));
}

describe("attestation lifecycle", { timeout: PROOF_TIMEOUT }, () => {
  it("builds a range-proof attestation that verifies and round-trips", () => {
    const { attestation, secret } = build();
    expect(attestation.kind).toBe("cipherbill.reserves-attestation");
    expect(attestation.attestationId).toMatch(/^res_/);
    expect(attestation.proof.proofSystem).toBe("stark-pedersen-bit-range-v1");
    expect(attestation.proof.bitProofs).toHaveLength(32);
    expect(attestation.thresholdBaseUnits).toBe("1000000");
    expect(attestation.bandExclusiveMaxBaseUnits).toBe((1000000n + (1n << 32n)).toString());
    expect(verifyReservesAttestation(attestation)).toBe(true);
    expect(parseReservesAttestation(serializeReservesAttestation(attestation))).toEqual(attestation);
    expect(secret.kind).toBe("cipherbill.reserves-opening");
  });

  it("proves the exact-threshold edge where the reserve equals the threshold", () => {
    const { attestation } = build({ reserveBaseUnits: "1000000", thresholdBaseUnits: "1000000" });
    expect(verifyReservesAttestation(attestation)).toBe(true);
  });

  it("supports the full u128 bit length by default", () => {
    const { attestation } = buildReservesAttestation(
      { merchantAlias: "Wide Merchant", asset: USDC, reserveBaseUnits: "5000000000000", thresholdBaseUnits: "1000000000000" },
      NOW,
      makeEntropy(),
    );
    expect(attestation.proof.bitLength).toBe(128);
    expect(verifyReservesAttestation(attestation)).toBe(true);
  }, 60_000);

  it("attaches a liability breakdown that must sum to the threshold", () => {
    const { attestation } = build({
      thresholdBaseUnits: "1000000",
      liabilities: [
        { label: "Payroll", amountBaseUnits: "600000" },
        { label: "Vendors", amountBaseUnits: "400000" },
      ],
    });
    expect(attestation.liabilities).toHaveLength(2);
    expect(verifyReservesAttestation(attestation)).toBe(true);
  });
});

describe("input guards", { timeout: PROOF_TIMEOUT }, () => {
  it("refuses to attest when the reserve is below the threshold", () => {
    expect(() => build({ reserveBaseUnits: "999999", thresholdBaseUnits: "1000000" })).toThrow(/below the threshold/i);
  });

  it("refuses a reserve that exceeds the provable band for the bit length", () => {
    expect(() => build({ reserveBaseUnits: "257", thresholdBaseUnits: "1", bitLength: 8 })).toThrow(/provable band/i);
  });

  it("rejects liabilities that do not sum to the threshold", () => {
    expect(() =>
      build({ thresholdBaseUnits: "1000000", liabilities: [{ label: "Payroll", amountBaseUnits: "600000" }] }),
    ).toThrow(/sum to the threshold/i);
  });

  it("rejects a reserve outside the u128 range", () => {
    const overflow = ((1n << 128n) + 5n).toString();
    expect(() => build({ reserveBaseUnits: overflow, thresholdBaseUnits: "1" })).toThrow(/u128/i);
  });
});

describe("tamper resistance", { timeout: PROOF_TIMEOUT }, () => {
  it("rejects a raised threshold", () => {
    const { attestation } = build();
    expect(verifyReservesAttestation({ ...attestation, thresholdBaseUnits: "1000041" })).toBe(false);
  });

  it("rejects a tampered bit-proof response", () => {
    const { attestation } = build();
    const bitProofs = attestation.proof.bitProofs.map((bit, index) =>
      index === 0 ? { ...bit, response0: "0x" + (BigInt(bit.response0) + 1n).toString(16) } : bit,
    );
    const tampered = { ...attestation, proof: { ...attestation.proof, bitProofs } };
    expect(verifyReservesAttestation(tampered)).toBe(false);
  });

  it("rejects a swapped reserve commitment", () => {
    const a = build({}, 1).attestation;
    const b = build({}, 2).attestation;
    const tampered = { ...a, proof: { ...a.proof, reserveCommitment: b.proof.reserveCommitment } };
    expect(verifyReservesAttestation(tampered)).toBe(false);
  });

  it("rejects a prover-substituted generator (unknown-DL requirement)", () => {
    const { attestation } = build();
    const base = ec.starkCurve.ProjectivePoint.BASE;
    const malicious = { x: "0x" + base.x.toString(16), y: "0x" + base.y.toString(16) };
    const tampered = { ...attestation, proof: { ...attestation.proof, generatorH: malicious } };
    expect(verifyReservesAttestation(tampered)).toBe(false);
  });

  it("rejects a tampered statement commitment", () => {
    const { attestation } = build();
    expect(verifyReservesAttestation({ ...attestation, statementCommitment: "0x1" })).toBe(false);
  });

  it("rejects a proof whose bit count no longer matches the declared length", () => {
    const { attestation } = build();
    const bitProofs = attestation.proof.bitProofs.slice(0, -1);
    expect(verifyReservesAttestation({ ...attestation, proof: { ...attestation.proof, bitProofs } })).toBe(false);
  });
});

describe("zero-knowledge / hiding", { timeout: PROOF_TIMEOUT }, () => {
  it("does not carry the secret reserve or blinding in the published attestation", () => {
    const { attestation, secret } = build({ reserveBaseUnits: "1000042", thresholdBaseUnits: "1000000" });
    const json = serializeReservesAttestation(attestation);
    const plain = JSON.stringify(attestation);
    expect(plain).not.toContain("1000042");
    expect(plain).not.toContain(secret.blinding);
    expect(json).not.toContain(secret.blinding);
  });

  it("yields distinct commitments for different reserves that both clear the same threshold", () => {
    const low = build({ reserveBaseUnits: "1000042", thresholdBaseUnits: "1000000" }, 3).attestation;
    const high = build({ reserveBaseUnits: "1000999", thresholdBaseUnits: "1000000" }, 4).attestation;
    expect(low.proof.reserveCommitment).not.toEqual(high.proof.reserveCommitment);
    expect(verifyReservesAttestation(low)).toBe(true);
    expect(verifyReservesAttestation(high)).toBe(true);
  });
});

describe("full disclosure opening", { timeout: PROOF_TIMEOUT }, () => {
  it("confirms a correct opening against the published commitment", () => {
    const { attestation, secret } = build();
    expect(verifyReservesOpening(attestation, secret)).toBe(true);
    expect(parseReservesSecret(serializeReservesSecret(secret))).toEqual(secret);
  });

  it("rejects an opening with the wrong reserve figure", () => {
    const { attestation, secret } = build();
    expect(verifyReservesOpening(attestation, { ...secret, reserveBaseUnits: "1000043" })).toBe(false);
  });

  it("rejects an opening with a mismatched blinding", () => {
    const { attestation, secret } = build();
    const wrong = "0x" + ((BigInt(secret.blinding) + 1n) % CURVE_ORDER).toString(16);
    expect(verifyReservesOpening(attestation, { ...secret, blinding: wrong })).toBe(false);
  });

  it("rejects an opening bound to a different attestation", () => {
    const { secret } = build({}, 1);
    const other = build({}, 2).attestation;
    expect(verifyReservesOpening(other, secret)).toBe(false);
  });
});

describe("honest disclosure model", () => {
  it("does not overstate the trust properties", () => {
    const trust = summarizeReservesTrust();
    expect(trust.isZeroKnowledge).toBe(true);
    expect(trust.provesThresholdRelation).toBe(true);
    expect(trust.provesOnChainCustody).toBe(false);
    expect(trust.bindsToRealFunds).toBe(false);
    expect(trust.isDecentralized).toBe(false);
    expect(trust.isAutomatic).toBe(false);
    expect(trust.statement.toLowerCase()).toContain("neither decentralized nor automatic");
    expect(trust.statement.toLowerCase()).toContain("does not prove on-chain custody");
  });

  it("is explicit that the engine never touches the pool contract", () => {
    const model = getReservesVisibilityModel();
    expect(model.hiddenFromVerifier.length).toBeGreaterThan(0);
    expect(model.disclosedToVerifier.length).toBeGreaterThan(0);
    expect(model.limitation.toLowerCase()).toContain("never reads from or writes to the pool contract");
  });
});

describe("helpers", { timeout: PROOF_TIMEOUT }, () => {
  it("derives a stable independent generator", () => {
    expect(deriveReservesGenerator()).toEqual(deriveReservesGenerator());
  });

  it("summarizes an attestation into a shareable badge", () => {
    const { attestation } = build();
    const badge = buildReservesBadge(attestation);
    expect(badge.kind).toBe("cipherbill.reserves-badge");
    expect(badge.thresholdDisplay).toBe("1");
    expect(badge.statementCommitment).toBe(attestation.statementCommitment);
  });

  it("formats integer base units as a decimal amount", () => {
    expect(formatReservesBaseUnits("1000000", 6)).toBe("1");
    expect(formatReservesBaseUnits("1500000", 6)).toBe("1.5");
    expect(formatReservesBaseUnits(500n, 0)).toBe("500");
  });

  it("rejects a malformed serialized attestation", () => {
    expect(() => parseReservesAttestation("!!not base64url!!")).toThrow(/encoding is invalid/i);
  });
});

