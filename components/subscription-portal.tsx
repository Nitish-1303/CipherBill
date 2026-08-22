"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  buildSubscriptionPaymentActions,
  createSubscriptionMembership,
  generateSubscriptionIssuerKeypair,
  getSubscriptionCountdown,
  getSubscriptionSecurityModel,
  parseSubscriptionCredential,
  renewSubscriptionMembership,
  serializeSubscriptionCredential,
  SUBSCRIPTION_POOL_ADDRESS,
  SUBSCRIPTION_TIERS,
  verifySubscriptionCredential,
  verifySubscriptionOpening,
  verifySubscriptionRotation,
  type SubscriptionCredential,
  type SubscriptionIssuerKeypair,
  type SubscriptionMembershipBundle,
  type SubscriptionStatus,
  type SubscriptionTier,
} from "@/lib/subscription-engine";
import { CONFIRMATION_TIMEOUT_MS, getStarknetExplorerTransactionUrl } from "@/lib/strk20/config";
import { acquireSubmission, awaitSubmittedTransaction, releaseSubmission } from "@/lib/strk20/transaction";

import { WalletConnect } from "./wallet-connect";
import { useWallet } from "./wallet-provider";

const DEMO_SERVICE_RECIPIENT = "0x0000000000000000000000000000000000000000000000000000000000007711";
const DEMO_ISSUER_ID = "cipherbill.local-demo-issuer";

interface InspectedCredential {
  credential: SubscriptionCredential;
  source: "current" | "imported";
}

const statusLabels: Record<SubscriptionStatus, string> = {
  active: "Active",
  renewal_due: "Renewal due",
  grace: "Grace period",
  expired: "Expired",
};

export function SubscriptionPortal() {
  const { account, status: walletStatus, capabilities } = useWallet();
  const [selectedTier, setSelectedTier] = useState<SubscriptionTier>("professional");
  const [serviceRecipient, setServiceRecipient] = useState(DEMO_SERVICE_RECIPIENT);
  const [membership, setMembership] = useState<SubscriptionMembershipBundle | null>(null);
  const [inspected, setInspected] = useState<InspectedCredential | null>(null);
  const [credentialInput, setCredentialInput] = useState("");
  const [showSecrets, setShowSecrets] = useState(false);
  const [rotationVerified, setRotationVerified] = useState<boolean | null>(null);
  const [transactionHash, setTransactionHash] = useState("");
  const [message, setMessage] = useState("Choose a tier. Membership secrets are generated only after a private renewal confirms.");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => new Date());
  const issuerKey = useRef<SubscriptionIssuerKeypair | null>(null);
  const submitLock = useRef(false);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(timer);
  }, []);

  const walletReady = Boolean(account && walletStatus === "connected" && capabilities?.strk20);
  const countdown = useMemo(() => membership ? getSubscriptionCountdown(membership.credential, now) : null, [membership, now]);
  const status = countdown?.status ?? null;
  const tierChange = Boolean(membership && membership.credential.tier !== selectedTier);
  const needsFreshMembership = !membership || status === "expired";
  const renewalAllowed = needsFreshMembership || tierChange || Boolean(countdown?.renewalOpen);
  const selectedDefinition = SUBSCRIPTION_TIERS[selectedTier];
  const securityModel = useMemo(() => getSubscriptionSecurityModel(), []);
  const inspection = useMemo(() => {
    if (!inspected) return null;
    return verifySubscriptionCredential(inspected.credential, {
      trustedIssuer: inspected.source === "current" ? issuerKey.current?.publicKey : undefined,
      now,
    });
  }, [inspected, now]);

  async function settleMembership() {
    if (!account || !walletReady || !renewalAllowed || !acquireSubmission(submitLock)) return;
    setBusy(true);
    setTransactionHash("");
    setRotationVerified(null);
    try {
      const actions = buildSubscriptionPaymentActions(selectedTier, serviceRecipient);
      setMessage(`Confirm the ${selectedDefinition.monthlyPrice} STRK private ${needsFreshMembership ? "activation" : tierChange ? "tier change" : "renewal"} in your wallet. Network fees are separate.`);
      const submitted = await account.strk20InvokeTransaction(actions);
      setTransactionHash(submitted.transaction_hash);
      const confirmation = await awaitSubmittedTransaction({
        action: "private_transfer",
        hash: submitted.transaction_hash,
        timeoutMs: CONFIRMATION_TIMEOUT_MS,
        waitForReceipt: () => account.provider.waitForTransaction(submitted.transaction_hash, { retries: 40, retryInterval: 3_000 }),
        isReverted: (receipt) => "execution_status" in receipt && receipt.execution_status === "REVERTED",
      });
      if (confirmation.status !== "confirmed") {
        setMessage(confirmation.status === "failed"
          ? "The private payment reverted. No membership credential or key rotation was issued."
          : "Payment submitted but not yet confirmed. No membership credential or key rotation was issued; check the explorer before retrying.");
        return;
      }

      issuerKey.current ??= generateSubscriptionIssuerKeypair();
      const activationTime = new Date();
      const next = needsFreshMembership
        ? createSubscriptionMembership({
            tier: selectedTier,
            serviceRecipient,
            paymentTransactionHash: submitted.transaction_hash,
            issuerId: DEMO_ISSUER_ID,
            issuerPrivateKey: issuerKey.current.privateKey,
          }, activationTime)
        : renewSubscriptionMembership(membership, {
            tier: selectedTier,
            paymentTransactionHash: submitted.transaction_hash,
            issuerId: DEMO_ISSUER_ID,
            issuerPrivateKey: issuerKey.current.privateKey,
          }, activationTime);

      const continuity = membership && !needsFreshMembership
        ? verifySubscriptionRotation(membership.credential, next.credential)
        : null;
      setMembership(next);
      setInspected({ credential: next.credential, source: "current" });
      setCredentialInput(serializeSubscriptionCredential(next.credential));
      setRotationVerified(continuity);
      setShowSecrets(false);
      setMessage(continuity === true
        ? `Epoch ${next.credential.epoch} confirmed. Membership key, service decryption key, access token, and payment salt all rotated with a valid continuity proof.`
        : `Anonymous ${SUBSCRIPTION_TIERS[next.credential.tier].name} membership activated. A new service-scoped key set is live for this billing epoch.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The private membership payment could not be completed.");
    } finally {
      releaseSubmission(submitLock);
      setBusy(false);
    }
  }

  function inspectCredential(event: React.FormEvent) {
    event.preventDefault();
    try {
      const credential = parseSubscriptionCredential(credentialInput);
      setInspected({ credential, source: membership?.credential.stateCommitment === credential.stateCommitment ? "current" : "imported" });
      setMessage("Credential structure and cryptographic proofs verified locally. Issuer trust is evaluated separately.");
    } catch (error) {
      setInspected(null);
      setMessage(error instanceof Error ? error.message : "The membership credential could not be verified.");
    }
  }

  async function copySecret(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage(`${label} copied. Treat it as a bearer secret and clear clipboard history after use.`);
    } catch {
      setMessage("Clipboard permission was denied. Reveal and copy the value manually.");
    }
  }

  function exportCredential() {
    if (!membership) return;
    downloadText(`${membership.credential.membershipId}-credential.json`, serializeSubscriptionCredential(membership.credential));
    setMessage("Public credential exported. It reveals the selected tier and validity window, but not payment origin or membership secrets.");
  }

  function exportRecoveryBundle() {
    if (!membership) return;
    downloadText(`${membership.credential.membershipId}-private-recovery.json`, JSON.stringify(membership, null, 2));
    setMessage("Private recovery bundle exported. It contains bearer secrets and the private transaction hash; store it encrypted and never share it as a credential.");
  }

  const actionLabel = busy
    ? "Awaiting private confirmation..."
    : needsFreshMembership
      ? `Activate ${selectedDefinition.name} privately`
      : tierChange
        ? `Change to ${selectedDefinition.name}`
        : countdown?.renewalOpen
          ? `Renew & rotate epoch ${membership.credential.epoch + 1}`
          : `Renewal opens in ${formatCountdown(Math.max(0, (Date.parse(membership.credential.periodEnd) - 7 * 86_400_000 - now.getTime()) / 1_000))}`;

  return (
    <section className="subscription-portal" aria-labelledby="subscription-title">
      <header className="subscription-hero">
        <div>
          <span>Private recurring access</span>
          <h2 id="subscription-title">Membership without an identity trail.</h2>
          <p>Settle a monthly tier through STRK20, prove anonymous membership, and rotate every service-scoped secret without exposing the payer or payment origin.</p>
        </div>
        <div className="subscription-pool"><span><i /> STRK20 mainnet pool</span><code>{shorten(SUBSCRIPTION_POOL_ADDRESS, 15, 11)}</code><small>Wallet-held privacy keys remain untouched</small></div>
      </header>

      <div className="subscription-trust-strip">
        <article><b>01</b><div><strong>Private settlement</strong><p>One exact STRK transfer; tier metadata stays outside wallet calldata.</p></div></article>
        <article><b>02</b><div><strong>ZK possession</strong><p>Stark-curve Schnorr proof verifies the current anonymous member.</p></div></article>
        <article><b>03</b><div><strong>Atomic rotation</strong><p>Four service-scoped secrets change only after confirmation.</p></div></article>
      </div>

      <div className="subscription-layout">
        <section className="subscription-market" aria-label="Subscription tier marketplace">
          <div className="subscription-section-heading"><div><span>Tier marketplace</span><h3>Choose a private service plan</h3></div>{membership ? <span className={`subscription-status ${status}`}>{status ? statusLabels[status] : "Unknown"}</span> : <span className="subscription-status dormant">No credential</span>}</div>
          <div className="subscription-tier-grid">
            {(Object.entries(SUBSCRIPTION_TIERS) as [SubscriptionTier, (typeof SUBSCRIPTION_TIERS)[SubscriptionTier]][]).map(([tier, definition]) => (
              <button className={`subscription-tier ${selectedTier === tier ? "selected" : ""} ${membership?.credential.tier === tier ? "current" : ""}`} type="button" key={tier} onClick={() => setSelectedTier(tier)}>
                <span>{membership?.credential.tier === tier ? "Current tier" : definition.name}</span>
                <div><strong>{definition.monthlyPrice}</strong><small>STRK / month</small></div>
                <p>{definition.description}</p>
                <ul>{definition.features.map((feature) => <li key={feature}>{feature}</li>)}</ul>
                <i>{selectedTier === tier ? "Selected" : "Select tier"}</i>
              </button>
            ))}
          </div>

          <div className="subscription-checkout">
            <label>Registered service recipient<input value={serviceRecipient} disabled={Boolean(membership)} onChange={(event) => setServiceRecipient(event.target.value)} spellCheck={false} /><small>The recipient must already be registered with the STRK20 pool. It is bound to the membership credential.</small></label>
            <div className="subscription-price"><span>Private monthly settlement</span><strong>{selectedDefinition.monthlyPrice} STRK</strong><small>Exact bigint amount + wallet-reported network fee</small></div>
            <div className="subscription-wallet"><div><span>Wallet route</span><strong>{walletReady ? "STRK20 Wallet API ready" : "Compatible wallet required"}</strong></div><WalletConnect /></div>
            <button className="subscription-primary" type="button" disabled={!walletReady || busy || !renewalAllowed} onClick={() => void settleMembership()}>{actionLabel}</button>
            {transactionHash ? <a className="subscription-transaction" href={getStarknetExplorerTransactionUrl(transactionHash)} target="_blank" rel="noreferrer">View submitted pool transaction - {shorten(transactionHash, 12, 8)}</a> : null}
            <p className="subscription-message" role="status" aria-live="polite">{message}</p>
          </div>
        </section>

        <aside className="subscription-membership" aria-label="Current private membership">
          <div className="subscription-section-heading"><div><span>Membership vault</span><h3>{membership ? `${SUBSCRIPTION_TIERS[membership.credential.tier].name} / epoch ${membership.credential.epoch}` : "Awaiting activation"}</h3></div>{membership && verifySubscriptionOpening(membership) ? <span className="subscription-proof-mark">Proof valid</span> : null}</div>
          {membership && countdown ? (
            <>
              <div className={`subscription-countdown ${countdown.status}`}>
                <span>{countdown.status === "grace" ? "Grace expires in" : "Current epoch ends in"}</span>
                <strong>{formatCountdown(countdown.remainingSeconds)}</strong>
                <small>{formatDate(countdown.target)}</small>
                <div aria-hidden="true"><i style={{ width: `${periodProgress(membership.credential, now)}%` }} /></div>
              </div>
              <dl className="subscription-ledger">
                <div><dt>Anonymous ID</dt><dd><code>{membership.credential.membershipId}</code></dd></div>
                <div><dt>State commitment</dt><dd><code>{shorten(membership.credential.stateCommitment, 16, 10)}</code></dd></div>
                <div><dt>Billing period</dt><dd>{formatDate(membership.credential.periodStart)} - {formatDate(membership.credential.periodEnd)}</dd></div>
                <div><dt>Rotation</dt><dd>{rotationVerified === true ? "Continuity verified" : membership.credential.epoch === 1 ? "Initial key ceremony" : "Credential imported"}</dd></div>
              </dl>
              <div className="subscription-key-vault">
                <div><span>Service key vault</span><button type="button" onClick={() => setShowSecrets((current) => !current)}>{showSecrets ? "Conceal" : "Reveal"}</button></div>
                <label>Bearer access token<code>{showSecrets ? membership.secrets.accessToken : maskSecret(membership.secrets.accessToken)}</code><button type="button" disabled={!showSecrets} onClick={() => void copySecret(membership.secrets.accessToken, "Access token")}>Copy</button></label>
                <label>Service metadata decryption key<code>{showSecrets ? membership.secrets.serviceViewingKey : maskSecret(membership.secrets.serviceViewingKey)}</code><button type="button" disabled={!showSecrets} onClick={() => void copySecret(membership.secrets.serviceViewingKey, "Service key")}>Copy</button></label>
                <p>These are application secrets, not the immutable STRK20 pool viewing key. They exist in memory unless you explicitly export a recovery bundle.</p>
              </div>
              <div className="subscription-export-actions"><button type="button" onClick={exportCredential}>Export public credential</button><button type="button" onClick={exportRecoveryBundle}>Export private recovery</button></div>
            </>
          ) : (
            <div className="subscription-empty"><b>0</b><h4>No linkable account required</h4><p>A confirmed private payment creates a fresh anonymous membership secret, service decryption key, and bearer token entirely in this browser.</p></div>
          )}
        </aside>
      </div>

      <section className="subscription-verifier">
        <div className="subscription-section-heading"><div><span>Merchant verifier</span><h3>Inspect a membership credential locally</h3></div><span className="subscription-local-only">No upload</span></div>
        <div className="subscription-verifier-grid">
          <form onSubmit={inspectCredential}>
            <label>Public credential JSON<textarea rows={9} value={credentialInput} onChange={(event) => setCredentialInput(event.target.value)} placeholder="Paste a CipherBill subscription credential..." spellCheck={false} /></label>
            <button type="submit">Verify credential</button>
          </form>
          <div className={`subscription-inspection ${inspection?.cryptographicallyValid ? "valid" : ""}`}>
            {inspection && inspected ? (
              <>
                <span>{inspection.cryptographicallyValid ? "Cryptographic proof valid" : "Verification failed"}</span>
                <h4>{inspection.tier ? SUBSCRIPTION_TIERS[inspection.tier].name : "Invalid credential"}</h4>
                <p>{inspection.reason}</p>
                <dl><div><dt>Status</dt><dd>{inspection.status ? statusLabels[inspection.status] : "Invalid"}</dd></div><div><dt>Issuer</dt><dd>{inspection.issuerTrusted ? "Allow-listed" : "Not allow-listed"}</dd></div><div><dt>Epoch</dt><dd>{inspected.credential.epoch}</dd></div><div><dt>Expires</dt><dd>{formatDate(inspected.credential.periodEnd)}</dd></div></dl>
              </>
            ) : <><span>Local proof inspector</span><h4>Separate validity from trust.</h4><p>The verifier checks credential shape, state commitment, member-possession proof, and issuer signature. A service must still allow-list the issuer public key.</p></>}
          </div>
        </div>
      </section>

      <section className="subscription-boundaries">
        <div><span>Rotated every epoch</span>{securityModel.rotated.map((item) => <strong key={item}>{item}</strong>)}</div>
        <div><span>Never disclosed</span>{securityModel.hidden.slice(0, 4).map((item) => <strong key={item}>{item}</strong>)}</div>
        <div className="subscription-boundary-note"><span>Trust boundary</span><p>This prototype uses a browser-local demo issuer after RPC confirmation, so it demonstrates the proof and rotation flow but is not independent evidence of payment. Production services must issue credentials only after observing the private settlement and must allow-list their issuer key.</p></div>
      </section>
    </section>
  );
}

function formatCountdown(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const remainder = seconds % 60;
  return `${String(days).padStart(2, "0")}d ${String(hours).padStart(2, "0")}h ${String(minutes).padStart(2, "0")}m ${String(remainder).padStart(2, "0")}s`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat("en", { year: "numeric", month: "short", day: "2-digit", timeZone: "UTC" }).format(new Date(value));
}

function periodProgress(credential: SubscriptionCredential, now: Date): number {
  const start = Date.parse(credential.periodStart);
  const end = Date.parse(credential.periodEnd);
  if (now.getTime() <= start) return 0;
  if (now.getTime() >= end) return 100;
  return Math.max(0, Math.min(100, ((now.getTime() - start) / (end - start)) * 100));
}

function maskSecret(value: string): string {
  return `${value.slice(0, 5)}${"*".repeat(22)}${value.slice(-4)}`;
}

function shorten(value: string, start = 10, end = 7): string {
  return value.length <= start + end + 3 ? value : `${value.slice(0, start)}...${value.slice(-end)}`;
}

function downloadText(filename: string, value: string) {
  const url = URL.createObjectURL(new Blob([value], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
