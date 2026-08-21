"use client";

import { createStore, type Store } from "@starknet-io/get-starknet-discovery";
import type { WalletWithStarknetFeatures } from "@starknet-io/get-starknet-wallet-standard-v6/features";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { constants, RpcProvider, walletV6, WalletAccountV6 } from "starknet";

import { getStrk20Config } from "@/lib/strk20/config";
import type { WalletCapabilities, WalletStatus } from "@/lib/strk20/types";

const MINIMUM_WALLET_API_VERSION = [0, 10, 3];

interface WalletContextValue {
  account: WalletAccountV6 | null;
  address: string | null;
  wallets: WalletWithStarknetFeatures[];
  status: WalletStatus;
  error: string | null;
  capabilities: WalletCapabilities | null;
  connect: (wallet: WalletWithStarknetFeatures) => Promise<void>;
  disconnect: () => void;
}

const WalletContext = createContext<WalletContextValue | null>(null);

export function WalletProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [wallets, setWallets] = useState<WalletWithStarknetFeatures[]>([]);
  const [account, setAccount] = useState<WalletAccountV6 | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [status, setStatus] = useState<WalletStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<WalletCapabilities | null>(null);

  useEffect(() => {
    const store: Store = createStore({ eip1193Adapters: [] });
    const readWallets = () => store.getWallets().slice() as unknown as WalletWithStarknetFeatures[];
    setWallets(readWallets());
    return store.subscribe(() => setWallets(readWallets()));
  }, []);

  async function connect(wallet: WalletWithStarknetFeatures) {
    const config = getStrk20Config();
    setStatus("connecting");
    setError(null);
    setCapabilities(null);

    if (!config) {
      setStatus("unsupported_wallet");
      setError("Mainnet provider and verified STRK20 pool configuration are required.");
      return;
    }

    try {
      const provider = new RpcProvider({ nodeUrl: config.providerUrl });
      const walletApiVersions = await walletV6.supportedWalletApi(wallet);
      const supportedSpecs = await walletV6.supportedSpecs(wallet);
      const supportsRequiredApi = walletApiVersions.some((version) => isAtLeastVersion(version, MINIMUM_WALLET_API_VERSION));
      const supportsStrk20 = walletApiVersions.length > 0 && supportsRequiredApi;

      setCapabilities({
        walletApiVersions,
        supportedSpecs,
        strk20: supportsStrk20,
      });

      if (!supportsStrk20) {
        setStatus("unsupported_wallet");
        setError("This wallet does not advertise STRK20 Wallet API support version 0.10.3 or newer.");
        return;
      }

      const connectedAccount = await WalletAccountV6.connect(provider, wallet);
      const accounts = await connectedAccount.requestAccounts();
      const chainId = await connectedAccount.provider.getChainId();

      if (chainId !== constants.StarknetChainId.SN_MAIN) {
        setStatus("wrong_network");
        setError("Switch your wallet to Starknet mainnet before using ShadowPay.");
        return;
      }

      if (!accounts[0]) {
        setStatus("rejected");
        setError("The wallet did not approve an account.");
        return;
      }

      setAccount(connectedAccount);
      setAddress(accounts[0]);
      setStatus("connected");
    } catch {
      setStatus("rejected");
      setError("Wallet connection was rejected or is not compatible with STRK20.");
    }
  }

  function disconnect() {
    setAccount(null);
    setAddress(null);
    setStatus("disconnected");
    setError(null);
      setCapabilities(null);
  }

  const value = useMemo(
    () => ({ account, address, wallets, status, error, capabilities, connect, disconnect }),
    [account, address, wallets, status, error, capabilities],
  );

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function useWallet() {
  const value = useContext(WalletContext);
  if (!value) throw new Error("useWallet must be used inside WalletProvider");
  return value;
}

function isAtLeastVersion(version: string, minimum: number[]) {
  const parsed = version.split(".").map((part) => Number.parseInt(part, 10));
  for (let index = 0; index < minimum.length; index += 1) {
    const current = parsed[index] ?? 0;
    if (current > minimum[index]) return true;
    if (current < minimum[index]) return false;
  }
  return true;
}