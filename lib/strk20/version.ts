export const MINIMUM_STRK20_WALLET_API_VERSION = "0.10.3";

interface ParsedVersion {
  core: [bigint, bigint, bigint];
  prerelease: string[];
}

const SEMANTIC_VERSION = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseSemanticVersion(version: string): ParsedVersion | null {
  const match = SEMANTIC_VERSION.exec(version.trim());
  if (!match) return null;

  const prerelease = match[4]?.split(".") ?? [];
  if (prerelease.some((part) => !part || (/^\d+$/.test(part) && part.length > 1 && part.startsWith("0")))) {
    return null;
  }

  return {
    core: [BigInt(match[1]), BigInt(match[2]), BigInt(match[3])],
    prerelease,
  };
}

function comparePrerelease(left: string[], right: string[]): number {
  if (!left.length && !right.length) return 0;
  if (!left.length) return 1;
  if (!right.length) return -1;

  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const leftPart = left[index];
    const rightPart = right[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;

    const leftNumeric = /^\d+$/.test(leftPart);
    const rightNumeric = /^\d+$/.test(rightPart);
    if (leftNumeric && rightNumeric) return BigInt(leftPart) > BigInt(rightPart) ? 1 : -1;
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftPart > rightPart ? 1 : -1;
  }

  return 0;
}

export function compareSemanticVersions(left: string, right: string): number {
  const parsedLeft = parseSemanticVersion(left);
  const parsedRight = parseSemanticVersion(right);
  if (!parsedLeft || !parsedRight) throw new Error("Wallet API versions must be valid semantic versions.");

  for (let index = 0; index < parsedLeft.core.length; index += 1) {
    if (parsedLeft.core[index] > parsedRight.core[index]) return 1;
    if (parsedLeft.core[index] < parsedRight.core[index]) return -1;
  }

  return comparePrerelease(parsedLeft.prerelease, parsedRight.prerelease);
}

export function supportsStrk20WalletApi(version: string): boolean {
  try {
    return compareSemanticVersions(version, MINIMUM_STRK20_WALLET_API_VERSION) >= 0;
  } catch {
    return false;
  }
}
