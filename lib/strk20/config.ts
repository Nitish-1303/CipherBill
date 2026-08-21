import type { Strk20Config } from "./types";

export const MAINNET_CHAIN_ID = "SN_MAIN" as const;
export const STRK_TOKEN_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

export function getStrk20Config(): Strk20Config | null {
  const providerUrl = process.env.NEXT_PUBLIC_PROVIDER_URL;
  const poolAddress = process.env.NEXT_PUBLIC_STRK20_POOL_ADDRESS;

  if (!providerUrl || !poolAddress) return null;

  return {
    chainId: MAINNET_CHAIN_ID,
    providerUrl,
    tokenAddress: STRK_TOKEN_ADDRESS,
    poolAddress,
  };
}