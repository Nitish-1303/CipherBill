import type { Metadata } from "next";
import "./globals.css";
import { WalletProvider } from "@/components/wallet-provider";

export const metadata: Metadata = {
  title: "ShadowPay AI — Private payments on Starknet",
  description: "Privacy-first invoicing and settlement powered by STRK20.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body><WalletProvider>{children}</WalletProvider></body>
    </html>
  );
}
