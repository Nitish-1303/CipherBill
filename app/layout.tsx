import type { Metadata } from "next";
import localFont from "next/font/local";

import "./globals.css";
import { WalletProvider } from "@/components/wallet-provider";

const geist = localFont({ src: "./fonts/geist.woff2", display: "swap", variable: "--font-geist" });

export const metadata: Metadata = {
  title: "CipherBill — Private invoices on Starknet",
  description: "Privacy-first invoicing and settlement powered by STRK20.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${geist.className} ${geist.variable}`}>
        <WalletProvider>{children}</WalletProvider>
      </body>
    </html>
  );
}
