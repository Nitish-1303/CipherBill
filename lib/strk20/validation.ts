import { validateAndParseAddress } from "starknet";

const DECIMAL_AMOUNT = /^(?:0|[1-9]\d*)(?:\.\d{1,18})?$/;

export function isValidStarknetAddress(value: string): boolean {
  if (!/^0x/i.test(value)) return false;

  try {
    validateAndParseAddress(value);
    return true;
  } catch {
    return false;
  }
}

export function normalizeStarknetAddress(value: string): string {
  if (!/^0x/i.test(value)) throw new Error("Starknet addresses must use a 0x prefix.");
  return validateAndParseAddress(value);
}

export function isValidAmount(value: string): boolean {
  if (!DECIMAL_AMOUNT.test(value)) return false;
  const [whole, fraction = ""] = value.split(".");
  return BigInt(`${whole}${fraction.padEnd(18, "0")}`) > 0n;
}

export function decimalToBaseUnits(value: string, decimals = 18): string {
  if (!isValidAmount(value)) throw new Error("Enter a valid positive amount.");

  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals) throw new Error("Amount has too many decimal places.");

  return `${whole}${fraction.padEnd(decimals, "0")}`.replace(/^0+(?=\d)/, "");
}

export function validatePaymentInput(recipient: string, amount: string): string | null {
  if (!isValidStarknetAddress(recipient)) return "Enter a valid Starknet recipient address.";
  if (!isValidAmount(amount)) return "Enter a positive STRK amount with up to 18 decimals.";
  return null;
}