"use client";

import { createStore, type Store } from "@starknet-io/get-starknet-discovery";
import type { WalletWithStarknetFeatures } from "@starknet-io/get-starknet-wallet-standard-v6/features";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { constants, RpcProvider, WalletAccountV6 } from "starknet";

import { getStrk20Config } from "@/lib/strk20/config";

type WalletStatus = "disconnected" | "connecting" | "connected" | "unsupported" | "rejected";

interface WalletContextValue {
  account: WalletAccountV6 | null;
  address: string | null;
  wallets: WalletWithStarknetFeatures[];
  status: WalletStatus;
  error: string | null;
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

    if (!config) {
      setStatus("unsupported");
      setError("Mainnet provider and verified STRK20 pool configuration are required.");
      return;
    }

    try {
      const provider = new RpcProvider({ nodeUrl: config.providerUrl });
      const connectedAccount = await WalletAccountV6.connect(provider, wallet);
      const accounts = await connectedAccount.requestAccounts();
      const chainId = await connectedAccount.provider.getChainId();

      if (chainId !== constants.StarknetChainId.SN_MAIN) {
        setStatus("unsupported");
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
  }

  const value = useMemo(
    () => ({ account, address, wallets, status, error, connect, disconnect }),
    [account, address, wallets, status, error],
  );

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function useWallet() {
  const value = useContext(WalletContext);
  if (!value) throw new Error("useWallet must be used inside WalletProvider");
  return value;
}