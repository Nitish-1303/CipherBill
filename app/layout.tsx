import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShadowPay AI — Private payments on Starknet",
  description: "Privacy-first invoicing and settlement powered by STRK20.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
