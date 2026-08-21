import type { Strk20Config } from "./types";

export const MAINNET_CHAIN_ID = "SN_MAIN" as const;
export const STRK_TOKEN_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
export const STRK20_POOL_ADDRESS = "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
export const CONFIRMATION_TIMEOUT_MS = 120_000;

export function getStrk20Config(): Strk20Config | null {
  const providerUrl = process.env.NEXT_PUBLIC_STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_PROVIDER_URL;
  const poolAddress = process.env.NEXT_PUBLIC_STRK20_POOL_ADDRESS ?? STRK20_POOL_ADDRESS;
  const configuredChainId = process.env.NEXT_PUBLIC_STARKNET_CHAIN_ID ?? MAINNET_CHAIN_ID;

  if (!providerUrl || !poolAddress || configuredChainId !== MAINNET_CHAIN_ID) return null;

  return {
    chainId: MAINNET_CHAIN_ID,
    providerUrl,
    tokenAddress: STRK_TOKEN_ADDRESS,
    poolAddress,
  };
}