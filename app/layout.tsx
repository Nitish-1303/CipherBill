import type { Metadata } from "next";
import { Inter } from "next/font/google";

import "./globals.css";
import { WalletProvider } from "@/components/wallet-provider";

const inter = Inter({ subsets: ["latin"], display: "swap" });

export const metadata: Metadata = {
  title: "CipherBill — Private invoices on Starknet",
  description: "Privacy-first invoicing and settlement powered by STRK20.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <WalletProvider>{children}</WalletProvider>
      </body>
    </html>
  );
}
