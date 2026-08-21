"use client";

export default function Error({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="error-screen">
      <span className="eyebrow">ShadowPay</span>
      <h1>Something went wrong.</h1>
      <p>The page could not complete that request. Wallet and transaction details were not recorded here.</p>
      <button type="button" onClick={reset}>Try again</button>
    </main>
  );
}