"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  createStealthBillingProfile,
  createStealthDirectory,
  decryptStealthDirectory,
  encryptStealthDirectory,
  parseEncryptedStealthDirectory,
  parseStealthBillingProfile,
  removeDirectoryContact,
  searchDirectoryContacts,
  serializeEncryptedStealthDirectory,
  STEALTH_DIRECTORY_POOL_ADDRESS,
  upsertDirectoryContact,
  type EncryptedStealthDirectory,
  type StealthBillingProfile,
  type StealthDirectory,
} from "@/lib/stealth-directory";

const DIRECTORY_STORAGE_KEY = "cipherbill.stealth-directory.v1";

export interface DirectorySelection {
  alias: string;
  merchantName: string;
  recipientAddress: string;
  profile: StealthBillingProfile;
}

interface DirectoryModalProps {
  open: boolean;
  onClose: () => void;
  onSelect: (selection: DirectorySelection) => void;
}

interface ManualProfileDraft {
  alias: string;
  merchantName: string;
  stealthAddress: string;
  viewingKeyX: string;
  viewingKeyY: string;
  tags: string;
  note: string;
}

const EMPTY_PROFILE: ManualProfileDraft = {
  alias: "",
  merchantName: "",
  stealthAddress: "",
  viewingKeyX: "",
  viewingKeyY: "",
  tags: "",
  note: "",
};

export function DirectoryModal({ open, onClose, onSelect }: DirectoryModalProps) {
  const [envelope, setEnvelope] = useState<EncryptedStealthDirectory | null>(null);
  const [directory, setDirectory] = useState<StealthDirectory | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [directoryName, setDirectoryName] = useState("Treasury payees");
  const [ownerAlias, setOwnerAlias] = useState("Accounts payable");
  const [search, setSearch] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [manualProfile, setManualProfile] = useState<ManualProfileDraft>(EMPTY_PROFILE);
  const [encodedProfile, setEncodedProfile] = useState("");
  const [encodedBackup, setEncodedBackup] = useState("");
  const [message, setMessage] = useState("Your alias book is encrypted before it reaches browser storage.");
  const [busy, setBusy] = useState(false);

  const contacts = useMemo(() => directory ? searchDirectoryContacts(directory, search) : [], [directory, search]);
  const closeSecurely = useCallback(() => {
    setDirectory(null);
    setPassphrase("");
    setConfirmPassphrase("");
    setSearch("");
    setShowAdd(false);
    setEncodedProfile("");
    setManualProfile(EMPTY_PROFILE);
    onClose();
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    try {
      const stored = window.localStorage.getItem(DIRECTORY_STORAGE_KEY);
      if (!stored) {
        setEnvelope(null);
        setMessage("Create a passphrase-protected directory. CipherBill stores only its encrypted envelope.");
        return;
      }
      const parsed = parseEncryptedStealthDirectory(stored);
      setEnvelope(parsed);
      setMessage(`Encrypted vault found: ${parsed.contactCount} contact${parsed.contactCount === 1 ? "" : "s"}. Enter its passphrase to search.`);
    } catch {
      setEnvelope(null);
      setMessage("The saved directory envelope is malformed. Import a valid backup to recover it.");
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function handleKeydown(event: KeyboardEvent) {
      if (event.key === "Escape") closeSecurely();
    }
    window.addEventListener("keydown", handleKeydown);
    return () => window.removeEventListener("keydown", handleKeydown);
  }, [closeSecurely, open]);

  if (!open) return null;

  async function setupDirectory(event: React.FormEvent) {
    event.preventDefault();
    if (passphrase !== confirmPassphrase) {
      setMessage("Passphrases do not match.");
      return;
    }
    setBusy(true);
    try {
      const created = createStealthDirectory({ directoryName, ownerAlias });
      const encrypted = await encryptStealthDirectory(created, passphrase);
      saveEnvelope(encrypted);
      setDirectory(created);
      setEnvelope(encrypted);
      setConfirmPassphrase("");
      setMessage("Encrypted directory created. Add a merchant-issued billing profile or pin one manually.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Encrypted directory setup failed.");
    } finally {
      setBusy(false);
    }
  }

  async function unlockDirectory(event: React.FormEvent) {
    event.preventDefault();
    if (!envelope) return;
    setBusy(true);
    try {
      const unlocked = await decryptStealthDirectory(envelope, passphrase);
      setDirectory(unlocked);
      setMessage("Vault unlocked in memory. Aliases and recipient addresses remain local to this browser.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Directory unlock failed.");
    } finally {
      setBusy(false);
    }
  }

  function lockDirectory() {
    setDirectory(null);
    setPassphrase("");
    setSearch("");
    setShowAdd(false);
    setEncodedProfile("");
    setManualProfile(EMPTY_PROFILE);
    setMessage("Directory locked. Plaintext contacts and passphrase were cleared from component memory.");
  }

  async function persist(next: StealthDirectory, successMessage: string) {
    if (!passphrase) throw new Error("Unlock the directory before changing it.");
    const encrypted = await encryptStealthDirectory(next, passphrase);
    saveEnvelope(encrypted);
    setDirectory(next);
    setEnvelope(encrypted);
    setMessage(successMessage);
  }

  async function importMerchantProfile() {
    if (!directory) return;
    setBusy(true);
    try {
      const profile = parseStealthBillingProfile(encodedProfile.trim());
      await persist(upsertDirectoryContact(directory, profile), `${profile.alias} was verified, pinned, and re-encrypted in this vault.`);
      setEncodedProfile("");
      setShowAdd(false);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Merchant billing profile import failed.");
    } finally {
      setBusy(false);
    }
  }

  async function pinManualProfile(event: React.FormEvent) {
    event.preventDefault();
    if (!directory) return;
    setBusy(true);
    try {
      const profile = createStealthBillingProfile({
        alias: manualProfile.alias,
        merchantName: manualProfile.merchantName,
        stealthAddress: manualProfile.stealthAddress,
        directoryViewingPublicKey: { x: manualProfile.viewingKeyX, y: manualProfile.viewingKeyY },
        tags: manualProfile.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        note: manualProfile.note,
      });
      await persist(upsertDirectoryContact(directory, profile), `${profile.alias} was pinned and the encrypted vault was updated.`);
      setManualProfile(EMPTY_PROFILE);
      setShowAdd(false);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Billing profile could not be pinned.");
    } finally {
      setBusy(false);
    }
  }

  async function deleteContact(profile: StealthBillingProfile) {
    if (!directory) return;
    setBusy(true);
    try {
      await persist(removeDirectoryContact(directory, profile.profileId), `${profile.alias} was removed and the vault was re-encrypted.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Contact removal failed.");
    } finally {
      setBusy(false);
    }
  }

  function selectContact(profile: StealthBillingProfile) {
    onSelect({ alias: profile.alias, merchantName: profile.merchantName, recipientAddress: profile.stealthAddress, profile });
    closeSecurely();
  }

  function exportBackup() {
    if (!envelope) return;
    const encoded = serializeEncryptedStealthDirectory(envelope);
    const blob = new Blob([encoded], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cipherbill-directory-${envelope.updatedAt.slice(0, 10)}.encrypted`;
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage("Encrypted backup downloaded. Store its passphrase separately.");
  }

  function importBackup() {
    try {
      const imported = parseEncryptedStealthDirectory(encodedBackup.trim());
      saveEnvelope(imported);
      setEnvelope(imported);
      setDirectory(null);
      setPassphrase("");
      setEncodedBackup("");
      setMessage(`Encrypted backup imported with ${imported.contactCount} contact${imported.contactCount === 1 ? "" : "s"}. Unlock it to verify the passphrase.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Encrypted backup import failed.");
    }
  }

  function saveEnvelope(value: EncryptedStealthDirectory) {
    window.localStorage.setItem(DIRECTORY_STORAGE_KEY, serializeEncryptedStealthDirectory(value));
  }

  return (
    <div className="directory-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) closeSecurely(); }}>
      <section className="directory-modal" role="dialog" aria-modal="true" aria-labelledby="directory-title">
        <header className="directory-header">
          <div className="directory-mark" aria-hidden="true">C</div>
          <div><span>Encrypted alias layer</span><h2 id="directory-title">Stealth recipient directory</h2></div>
          <button className="directory-close" type="button" aria-label="Close recipient directory" onClick={closeSecurely}>×</button>
        </header>

        <div className="directory-contract-strip">
          <span><i /> STRK20 mainnet</span><code>{shorten(STEALTH_DIRECTORY_POOL_ADDRESS, 13, 10)}</code><small>Wallet API private transfer</small>
        </div>

        {!envelope && !directory ? (
          <form className="directory-gate" onSubmit={setupDirectory}>
            <div className="directory-gate-copy"><span>01 · Create vault</span><h3>A contact book only you can read.</h3><p>Aliases, addresses, notes, tags, and directory public keys are encrypted with AES-GCM before browser storage.</p></div>
            <div className="directory-form-grid">
              <label>Directory name<input required value={directoryName} maxLength={80} onChange={(event) => setDirectoryName(event.target.value)} /></label>
              <label>Owner alias<input required value={ownerAlias} maxLength={64} onChange={(event) => setOwnerAlias(event.target.value)} /></label>
              <label>Passphrase<input required type="password" minLength={12} autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>
              <label>Confirm passphrase<input required type="password" minLength={12} autoComplete="new-password" value={confirmPassphrase} onChange={(event) => setConfirmPassphrase(event.target.value)} /></label>
            </div>
            <button type="submit" disabled={busy}>{busy ? "Encrypting…" : "Create encrypted directory"}</button>
            <details className="directory-import"><summary>Restore an encrypted backup</summary><textarea aria-label="Encrypted directory backup" rows={3} placeholder="Paste cipherbill.stealth-directory.encrypted…" value={encodedBackup} onChange={(event) => setEncodedBackup(event.target.value)} /><button type="button" disabled={!encodedBackup.trim()} onClick={importBackup}>Import backup</button></details>
          </form>
        ) : !directory ? (
          <form className="directory-gate directory-unlock" onSubmit={unlockDirectory}>
            <div className="directory-vault-icon" aria-hidden="true"><span>•••</span></div>
            <div className="directory-gate-copy"><span>Encrypted vault detected</span><h3>{envelope?.contactCount ?? 0} pinned billing profiles</h3><p>The passphrase is used locally for PBKDF2-SHA-256 key derivation. It is never stored or sent to CipherBill.</p></div>
            <label>Vault passphrase<input autoFocus required type="password" minLength={12} autoComplete="current-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>
            <button type="submit" disabled={busy}>{busy ? "Opening…" : "Unlock directory"}</button>
            <div className="directory-gate-actions"><button type="button" onClick={exportBackup}>Download encrypted backup</button></div>
            <details className="directory-import"><summary>Replace with another encrypted backup</summary><textarea aria-label="Replacement encrypted directory backup" rows={3} value={encodedBackup} onChange={(event) => setEncodedBackup(event.target.value)} /><button type="button" disabled={!encodedBackup.trim()} onClick={importBackup}>Import replacement</button></details>
          </form>
        ) : (
          <div className="directory-workspace">
            <div className="directory-toolbar">
              <label className="directory-search"><span aria-hidden="true">⌕</span><input autoFocus placeholder="Search aliases, merchants, tags…" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
              <button className="directory-add-button" type="button" onClick={() => setShowAdd((current) => !current)}>{showAdd ? "Close form" : "+ Add profile"}</button>
              <button className="directory-lock-button" type="button" onClick={lockDirectory}>Lock</button>
            </div>

            {showAdd ? (
              <section className="directory-add-panel">
                <div><span>Recommended</span><h3>Import a merchant-issued profile</h3><p>The embedded commitment detects edits before the profile is pinned.</p></div>
                <textarea aria-label="Encoded merchant billing profile" rows={3} placeholder="Paste cipherbill.stealth-billing-profile…" value={encodedProfile} onChange={(event) => setEncodedProfile(event.target.value)} />
                <button type="button" disabled={busy || !encodedProfile.trim()} onClick={importMerchantProfile}>Verify & pin profile</button>
                <details><summary>Advanced: pin profile fields manually</summary>
                  <form className="directory-manual-form" onSubmit={pinManualProfile}>
                    <label>Alias<input required placeholder="acme.ops" value={manualProfile.alias} onChange={(event) => setManualProfile({ ...manualProfile, alias: event.target.value })} /></label>
                    <label>Merchant name<input required value={manualProfile.merchantName} onChange={(event) => setManualProfile({ ...manualProfile, merchantName: event.target.value })} /></label>
                    <label className="directory-wide">Registered STRK20 recipient<input required placeholder="0x…" value={manualProfile.stealthAddress} onChange={(event) => setManualProfile({ ...manualProfile, stealthAddress: event.target.value })} /></label>
                    <label>Directory public key X<input required placeholder="0x…" value={manualProfile.viewingKeyX} onChange={(event) => setManualProfile({ ...manualProfile, viewingKeyX: event.target.value })} /></label>
                    <label>Directory public key Y<input required placeholder="0x…" value={manualProfile.viewingKeyY} onChange={(event) => setManualProfile({ ...manualProfile, viewingKeyY: event.target.value })} /></label>
                    <label>Tags<input placeholder="vendor, priority" value={manualProfile.tags} onChange={(event) => setManualProfile({ ...manualProfile, tags: event.target.value })} /></label>
                    <label>Private note<input maxLength={240} value={manualProfile.note} onChange={(event) => setManualProfile({ ...manualProfile, note: event.target.value })} /></label>
                    <button className="directory-wide" type="submit" disabled={busy}>{busy ? "Encrypting…" : "Pin & encrypt"}</button>
                  </form>
                </details>
              </section>
            ) : null}

            <div className="directory-list-heading"><div><span>{contacts.length.toString().padStart(2, "0")}</span><strong>{search ? "Search results" : directory.directoryName}</strong></div><button type="button" onClick={exportBackup}>Export encrypted vault</button></div>
            <div className="directory-contact-list">
              {contacts.length ? contacts.map((profile) => (
                <article className="directory-contact" key={profile.profileId}>
                  <button className="directory-contact-select" type="button" onClick={() => selectContact(profile)}>
                    <span className="directory-avatar">{initials(profile.merchantName)}</span>
                    <span className="directory-contact-identity"><strong>{profile.alias}</strong><small>{profile.merchantName}</small></span>
                    <span className="directory-contact-tags">{profile.tags.slice(0, 2).map((tag) => <i key={tag}>{tag}</i>)}</span>
                    <span className="directory-address"><small>Private recipient</small><code>{shorten(profile.stealthAddress, 10, 8)}</code></span>
                    <span className="directory-select-arrow" aria-hidden="true">→</span>
                  </button>
                  <button className="directory-delete" type="button" aria-label={`Remove ${profile.alias}`} disabled={busy} onClick={() => deleteContact(profile)}>Remove</button>
                </article>
              )) : (
                <div className="directory-empty"><span>⌁</span><h3>{search ? "No private contacts match" : "No billing profiles pinned"}</h3><p>{search ? "Try a merchant name, alias, tag, or private note." : "Import a merchant-issued profile to resolve its alias without a server-side directory."}</p></div>
              )}
            </div>

            <div className="directory-privacy-boundary">
              <div><span>Hidden locally</span><strong>Alias · recipient · profile notes</strong></div>
              <div><span>Sent to wallet</span><strong>Registered address · exact amount</strong></div>
              <p>The directory public key is separate from the immutable STRK20 viewing key. CipherBill never requests protocol viewing secrets. Recipient registration is still required before private payment.</p>
            </div>
          </div>
        )}

        <footer className="directory-footer"><span className="directory-status-dot" /> <p role="status">{message}</p></footer>
      </section>
    </div>
  );
}

function shorten(value: string, start: number, end: number): string {
  return value.length <= start + end + 1 ? value : `${value.slice(0, start)}…${value.slice(-end)}`;
}

function initials(value: string): string {
  return value.split(/\s+/u).slice(0, 2).map((part) => part[0]?.toLocaleUpperCase()).join("");
}
