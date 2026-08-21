const STARKNET_ADDRESS = /^0x[0-9a-fA-F]{1,64}$/;
const DECIMAL_AMOUNT = /^(?:0|[1-9]\d*)(?:\.\d{1,18})?$/;

export function isValidStarknetAddress(value: string): boolean {
  return STARKNET_ADDRESS.test(value);
}

export function isValidAmount(value: string): boolean {
  return DECIMAL_AMOUNT.test(value) && Number(value) > 0;
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