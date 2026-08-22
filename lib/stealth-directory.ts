import { ec, hash, type STRK20_ACTION } from "starknet";

import { MAINNET_CHAIN_ID, STRK20_POOL_ADDRESS, STRK_TOKEN_ADDRESS } from "./strk20/config";
import { normalizeStarknetAddress } from "./strk20/validation";

export const STEALTH_DIRECTORY_VERSION = 1 as const;
export const STEALTH_DIRECTORY_POOL_ADDRESS = STRK20_POOL_ADDRESS;
export const DIRECTORY_KDF_ITERATIONS = 310_000;
export const MAX_DIRECTORY_CONTACTS = 250;
export const MAX_DIRECTORY_TAGS = 8;

const PROFILE_KIND = "cipherbill.stealth-billing-profile" as const;
const DIRECTORY_KIND = "cipherbill.stealth-directory.private" as const;
const ENVELOPE_KIND = "cipherbill.stealth-directory.encrypted" as const;
const ENCRYPTION_ALGORITHM = "PBKDF2-SHA256/AES-GCM-256" as const;
const CURVE_ORDER = ec.starkCurve.CURVE.n;
const FIELD_PRIME = ec.starkCurve.CURVE.Fp.ORDER;
const U128_MAX = (1n << 128n) - 1n;
const PROFILE_DOMAIN = hash.starknetKeccak("CipherBill stealth billing profile v1");
const DIRECTORY_DOMAIN = hash.starknetKeccak("CipherBill encrypted alias directory v1");
const CHANNEL_DOMAIN = hash.starknetKeccak("CipherBill directory viewing channel v1");
const MIN_KDF_ITERATIONS = 100_000;
const PROFILE_NOTICE = "This public profile contains a directory-only viewing public key. It is not a STRK20 protocol viewing key and grants no note-reading or spending authority.";
const ENVELOPE_NOTICE = "Encrypted client-side alias book. The passphrase and plaintext contacts never leave this browser; back up this envelope separately from the passphrase.";

export interface DirectoryViewingPublicKey {
  x: string;
  y: string;
}

export interface DirectoryViewingKeypair {
  algorithm: "stark-curve-ecdh";
  privateKey: string;
  publicKey: DirectoryViewingPublicKey;
  notice: string;
}

export interface StealthBillingProfileInput {
  alias: string;
  merchantName: string;
  stealthAddress: string;
  directoryViewingPublicKey: DirectoryViewingPublicKey;
  tags?: string[];
  note?: string;
}

export interface StealthBillingProfile {
  kind: typeof PROFILE_KIND;
  version: typeof STEALTH_DIRECTORY_VERSION;
  profileId: string;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  tokenAddress: typeof STRK_TOKEN_ADDRESS;
  alias: string;
  canonicalAlias: string;
  merchantName: string;
  stealthAddress: string;
  directoryViewingPublicKey: DirectoryViewingPublicKey;
  tags: string[];
  note: string;
  issuedAt: string;
  profileCommitment: string;
  notice: typeof PROFILE_NOTICE;
}

export interface CreateStealthDirectoryInput {
  directoryName: string;
  ownerAlias: string;
  contacts?: StealthBillingProfile[];
}

export interface StealthDirectory {
  kind: typeof DIRECTORY_KIND;
  version: typeof STEALTH_DIRECTORY_VERSION;
  directoryId: string;
  directoryName: string;
  ownerAlias: string;
  contacts: StealthBillingProfile[];
  createdAt: string;
  updatedAt: string;
  directoryCommitment: string;
}

export interface EncryptedStealthDirectory {
  kind: typeof ENVELOPE_KIND;
  version: typeof STEALTH_DIRECTORY_VERSION;
  network: typeof MAINNET_CHAIN_ID;
  poolAddress: typeof STRK20_POOL_ADDRESS;
  tokenAddress: typeof STRK_TOKEN_ADDRESS;
  algorithm: typeof ENCRYPTION_ALGORITHM;
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    salt: string;
  };
  iv: string;
  ciphertext: string;
  ciphertextDigest: string;
  contactCount: number;
  updatedAt: string;
  notice: typeof ENVELOPE_NOTICE;
}

export interface DirectoryPaymentResolution {
  profile: StealthBillingProfile;
  actions: STRK20_ACTION[];
  poolAddress: typeof STRK20_POOL_ADDRESS;
  privacyNotice: string;
}

interface DirectoryEntropy {
  createId?: (kind: "profile" | "directory") => string;
  randomBytes?: (target: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
  privateScalar?: bigint;
  kdfIterations?: number;
}

export function generateDirectoryViewingKeypair(entropy: Pick<DirectoryEntropy, "privateScalar"> = {}): DirectoryViewingKeypair {
  const privateScalar = requireSecretScalar(entropy.privateScalar ?? randomScalar(), "Directory viewing private key");
  const publicKey = pointToFelts(ec.starkCurve.ProjectivePoint.BASE.multiply(privateScalar));
  return {
    algorithm: "stark-curve-ecdh",
    privateKey: toHex(privateScalar),
    publicKey,
    notice: "Directory-only ECDH keypair. Never substitute this value for, or import a STRK20 account viewing key into, CipherBill.",
  };
}

export function deriveDirectoryChannelTag(
  privateKey: string,
  otherPartyPublicKey: DirectoryViewingPublicKey,
  context: string,
): string {
  const scalar = requireScalar(privateKey);
  const publicPoint = pointFromFelts(otherPartyPublicKey);
  const shared = publicPoint.multiply(scalar);
  const normalizedContext = requireText(context, "Directory channel context", 128);
  return toHex(hashElements([CHANNEL_DOMAIN, shared.x, shared.y, hash.starknetKeccak(normalizedContext)]));
}

export function createStealthBillingProfile(
  input: StealthBillingProfileInput,
  issuedAt = new Date(),
  entropy: Pick<DirectoryEntropy, "createId"> = {},
): StealthBillingProfile {
  const alias = requireText(input.alias, "Merchant alias", 48, /^[\p{L}\p{N}][\p{L}\p{N}._ -]*$/u);
  const canonicalAlias = canonicalizeAlias(alias);
  const profile: Omit<StealthBillingProfile, "profileCommitment"> = {
    kind: PROFILE_KIND,
    version: STEALTH_DIRECTORY_VERSION,
    profileId: entropy.createId?.("profile") ?? `profile_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    tokenAddress: STRK_TOKEN_ADDRESS,
    alias,
    canonicalAlias,
    merchantName: requireText(input.merchantName, "Merchant name", 80),
    stealthAddress: normalizeStarknetAddress(input.stealthAddress),
    directoryViewingPublicKey: normalizePublicKey(input.directoryViewingPublicKey),
    tags: normalizeTags(input.tags ?? []),
    note: requireOptionalText(input.note ?? "", "Contact note", 240),
    issuedAt: requireIsoTimestamp(issuedAt.toISOString(), "Profile issue time"),
    notice: PROFILE_NOTICE,
  };
  if (!/^profile_[A-Za-z0-9_-]{1,48}$/.test(profile.profileId)) throw new Error("Billing profile ID is invalid.");
  const completed = { ...profile, profileCommitment: toHex(computeProfileCommitment(profile)) };
  validateBillingProfile(completed);
  return completed;
}

export function verifyStealthBillingProfile(profile: StealthBillingProfile): boolean {
  try {
    validateBillingProfile(profile);
    return BigInt(profile.profileCommitment) === computeProfileCommitment(profile);
  } catch {
    return false;
  }
}

export function serializeStealthBillingProfile(profile: StealthBillingProfile): string {
  if (!verifyStealthBillingProfile(profile)) throw new Error("Billing profile is invalid or altered.");
  return toBase64Url(new TextEncoder().encode(JSON.stringify(profile)));
}

export function parseStealthBillingProfile(encoded: string): StealthBillingProfile {
  const parsed = parseEncodedJson(encoded, 16_384, "Billing profile");
  validateBillingProfile(parsed);
  if (!verifyStealthBillingProfile(parsed)) throw new Error("Billing profile commitment does not match.");
  return parsed;
}

export function createStealthDirectory(
  input: CreateStealthDirectoryInput,
  now = new Date(),
  entropy: Pick<DirectoryEntropy, "createId"> = {},
): StealthDirectory {
  const timestamp = requireIsoTimestamp(now.toISOString(), "Directory creation time");
  const contacts = normalizeContactSet(input.contacts ?? []);
  const directory: Omit<StealthDirectory, "directoryCommitment"> = {
    kind: DIRECTORY_KIND,
    version: STEALTH_DIRECTORY_VERSION,
    directoryId: entropy.createId?.("directory") ?? `directory_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
    directoryName: requireText(input.directoryName, "Directory name", 80),
    ownerAlias: requireText(input.ownerAlias, "Directory owner alias", 64),
    contacts,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
  if (!/^directory_[A-Za-z0-9_-]{1,48}$/.test(directory.directoryId)) throw new Error("Directory ID is invalid.");
  const completed = { ...directory, directoryCommitment: toHex(computeDirectoryCommitment(directory)) };
  validateDirectory(completed);
  return completed;
}

export function upsertDirectoryContact(
  directory: StealthDirectory,
  profile: StealthBillingProfile,
  now = new Date(),
): StealthDirectory {
  validateDirectory(directory);
  if (!verifyStealthBillingProfile(profile)) throw new Error("Billing profile is invalid or altered.");
  const existing = directory.contacts.find((contact) => contact.canonicalAlias === profile.canonicalAlias);
  const contacts = directory.contacts
    .filter((contact) => contact.profileId !== profile.profileId && contact.canonicalAlias !== profile.canonicalAlias)
    .concat(profile);
  if (!existing && contacts.length > MAX_DIRECTORY_CONTACTS) throw new Error(`A directory supports at most ${MAX_DIRECTORY_CONTACTS} contacts.`);
  return finalizeDirectory({ ...directory, contacts: normalizeContactSet(contacts), updatedAt: requireIsoTimestamp(now.toISOString(), "Directory update time") });
}

export function removeDirectoryContact(directory: StealthDirectory, profileId: string, now = new Date()): StealthDirectory {
  validateDirectory(directory);
  const contacts = directory.contacts.filter((contact) => contact.profileId !== profileId);
  if (contacts.length === directory.contacts.length) throw new Error("Directory contact does not exist.");
  return finalizeDirectory({ ...directory, contacts, updatedAt: requireIsoTimestamp(now.toISOString(), "Directory update time") });
}

export function searchDirectoryContacts(directory: StealthDirectory, query: string): StealthBillingProfile[] {
  validateDirectory(directory);
  const terms = query.normalize("NFKC").trim().toLocaleLowerCase().split(/\s+/u).filter(Boolean);
  if (!terms.length) return [...directory.contacts];
  return directory.contacts.filter((contact) => {
    const searchable = [contact.alias, contact.merchantName, ...contact.tags, contact.note].join(" ").normalize("NFKC").toLocaleLowerCase();
    return terms.every((term) => searchable.includes(term));
  });
}

export function resolveDirectoryAlias(directory: StealthDirectory, alias: string): StealthBillingProfile {
  validateDirectory(directory);
  const canonical = canonicalizeAlias(alias);
  const profile = directory.contacts.find((contact) => contact.canonicalAlias === canonical);
  if (!profile) throw new Error("Merchant alias was not found in this directory.");
  return profile;
}

export function buildPrivateDirectoryPaymentActions(profile: StealthBillingProfile, amountBaseUnits: string): STRK20_ACTION[] {
  if (!verifyStealthBillingProfile(profile)) throw new Error("Billing profile is invalid or altered.");
  const amount = requireBaseUnits(amountBaseUnits, "Private payment amount");
  return [{ type: "transfer", token: STRK_TOKEN_ADDRESS, amount: amount.toString(), recipient: profile.stealthAddress }];
}

export function resolvePrivateDirectoryPayment(
  directory: StealthDirectory,
  alias: string,
  amountBaseUnits: string,
): DirectoryPaymentResolution {
  const profile = resolveDirectoryAlias(directory, alias);
  return {
    profile,
    actions: buildPrivateDirectoryPaymentActions(profile, amountBaseUnits),
    poolAddress: STRK20_POOL_ADDRESS,
    privacyNotice: "The alias is resolved locally and is never sent to STRK20. The wallet receives only the registered recipient address and amount; the pool hides sender, recipient, token, and amount for the in-pool transfer.",
  };
}

export async function encryptStealthDirectory(
  directory: StealthDirectory,
  passphrase: string,
  entropy: Pick<DirectoryEntropy, "randomBytes" | "kdfIterations"> = {},
): Promise<EncryptedStealthDirectory> {
  validateDirectory(directory);
  const iterations = normalizeIterations(entropy.kdfIterations ?? DIRECTORY_KDF_ITERATIONS);
  const random = entropy.randomBytes ?? ((target: Uint8Array<ArrayBuffer>) => crypto.getRandomValues(target));
  const salt = random(new Uint8Array(16));
  const iv = random(new Uint8Array(12));
  if (salt.length !== 16 || iv.length !== 12) throw new Error("Directory encryption entropy returned an invalid byte length.");
  const header: Pick<EncryptedStealthDirectory, "kind" | "version" | "network" | "poolAddress" | "tokenAddress" | "algorithm" | "kdf" | "contactCount" | "updatedAt" | "notice"> = {
    kind: ENVELOPE_KIND,
    version: STEALTH_DIRECTORY_VERSION,
    network: MAINNET_CHAIN_ID,
    poolAddress: STRK20_POOL_ADDRESS,
    tokenAddress: STRK_TOKEN_ADDRESS,
    algorithm: ENCRYPTION_ALGORITHM,
    kdf: { name: "PBKDF2" as const, hash: "SHA-256" as const, iterations, salt: toBase64Url(salt) },
    contactCount: directory.contacts.length,
    updatedAt: directory.updatedAt,
    notice: ENVELOPE_NOTICE,
  };
  const key = await deriveDirectoryKey(passphrase, salt, iterations, "encrypt");
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: envelopeAssociatedData(header) },
    key,
    new TextEncoder().encode(JSON.stringify(directory)),
  ));
  return {
    ...header,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
    ciphertextDigest: await sha256Base64Url(ciphertext),
  };
}

export async function decryptStealthDirectory(envelope: EncryptedStealthDirectory, passphrase: string): Promise<StealthDirectory> {
  validateEncryptedEnvelope(envelope);
  const salt = fromBase64Url(envelope.kdf.salt);
  const iv = fromBase64Url(envelope.iv);
  if (salt.length !== 16 || iv.length !== 12) throw new Error("Encrypted directory parameters are invalid.");
  const ciphertext = fromBase64Url(envelope.ciphertext);
  if (await sha256Base64Url(ciphertext) !== envelope.ciphertextDigest) throw new Error("Encrypted directory digest does not match.");
  const key = await deriveDirectoryKey(passphrase, salt, envelope.kdf.iterations, "decrypt");
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: envelopeAssociatedData(envelope) },
      key,
      ciphertext,
    );
  } catch {
    throw new Error("Directory could not be unlocked. The passphrase or encrypted envelope is incorrect.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new Error("Decrypted directory payload is malformed.");
  }
  validateDirectory(parsed);
  if (parsed.contacts.length !== envelope.contactCount || parsed.updatedAt !== envelope.updatedAt) throw new Error("Encrypted directory header does not match its payload.");
  return parsed;
}

export function serializeEncryptedStealthDirectory(envelope: EncryptedStealthDirectory): string {
  validateEncryptedEnvelope(envelope);
  return toBase64Url(new TextEncoder().encode(JSON.stringify(envelope)));
}

export function parseEncryptedStealthDirectory(encoded: string): EncryptedStealthDirectory {
  const parsed = parseEncodedJson(encoded, 2_000_000, "Encrypted directory");
  validateEncryptedEnvelope(parsed);
  return parsed;
}

function finalizeDirectory(directory: Omit<StealthDirectory, "directoryCommitment"> | StealthDirectory): StealthDirectory {
  const withoutCommitment: Omit<StealthDirectory, "directoryCommitment"> = {
    kind: directory.kind,
    version: directory.version,
    directoryId: directory.directoryId,
    directoryName: directory.directoryName,
    ownerAlias: directory.ownerAlias,
    contacts: directory.contacts,
    createdAt: directory.createdAt,
    updatedAt: directory.updatedAt,
  };
  const completed = { ...withoutCommitment, directoryCommitment: toHex(computeDirectoryCommitment(withoutCommitment)) };
  validateDirectory(completed);
  return completed;
}

function validateBillingProfile(value: unknown): asserts value is StealthBillingProfile {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Billing profile is invalid.");
  const profile = value as StealthBillingProfile;
  const allowed = ["kind", "version", "profileId", "network", "poolAddress", "tokenAddress", "alias", "canonicalAlias", "merchantName", "stealthAddress", "directoryViewingPublicKey", "tags", "note", "issuedAt", "profileCommitment", "notice"];
  if (Object.keys(profile).some((key) => !allowed.includes(key)) || profile.kind !== PROFILE_KIND || profile.version !== STEALTH_DIRECTORY_VERSION || profile.network !== MAINNET_CHAIN_ID || profile.poolAddress !== STRK20_POOL_ADDRESS || profile.tokenAddress !== STRK_TOKEN_ADDRESS || profile.notice !== PROFILE_NOTICE) throw new Error("Billing profile header is invalid.");
  if (!/^profile_[A-Za-z0-9_-]{1,48}$/.test(profile.profileId)) throw new Error("Billing profile ID is invalid.");
  const alias = requireText(profile.alias, "Merchant alias", 48, /^[\p{L}\p{N}][\p{L}\p{N}._ -]*$/u);
  if (profile.canonicalAlias !== canonicalizeAlias(alias)) throw new Error("Canonical merchant alias is invalid.");
  requireText(profile.merchantName, "Merchant name", 80);
  if (normalizeStarknetAddress(profile.stealthAddress) !== profile.stealthAddress) throw new Error("Stealth payment address is not canonical.");
  normalizePublicKey(profile.directoryViewingPublicKey);
  if (JSON.stringify(normalizeTags(profile.tags)) !== JSON.stringify(profile.tags)) throw new Error("Billing profile tags are invalid.");
  requireOptionalText(profile.note, "Contact note", 240);
  requireIsoTimestamp(profile.issuedAt, "Profile issue time");
  requireFelt(profile.profileCommitment);
}

function validateDirectory(value: unknown): asserts value is StealthDirectory {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Stealth directory is invalid.");
  const directory = value as StealthDirectory;
  const allowed = ["kind", "version", "directoryId", "directoryName", "ownerAlias", "contacts", "createdAt", "updatedAt", "directoryCommitment"];
  if (Object.keys(directory).some((key) => !allowed.includes(key)) || directory.kind !== DIRECTORY_KIND || directory.version !== STEALTH_DIRECTORY_VERSION || !/^directory_[A-Za-z0-9_-]{1,48}$/.test(directory.directoryId)) throw new Error("Stealth directory header is invalid.");
  requireText(directory.directoryName, "Directory name", 80);
  requireText(directory.ownerAlias, "Directory owner alias", 64);
  if (!Array.isArray(directory.contacts) || directory.contacts.length > MAX_DIRECTORY_CONTACTS) throw new Error("Stealth directory contact count is invalid.");
  const normalized = normalizeContactSet(directory.contacts);
  if (normalized.some((contact, index) => contact.profileId !== directory.contacts[index]?.profileId)) throw new Error("Stealth directory contacts are not canonically ordered.");
  requireIsoTimestamp(directory.createdAt, "Directory creation time");
  requireIsoTimestamp(directory.updatedAt, "Directory update time");
  if (Date.parse(directory.updatedAt) < Date.parse(directory.createdAt)) throw new Error("Directory update time precedes creation.");
  requireFelt(directory.directoryCommitment);
  if (BigInt(directory.directoryCommitment) !== computeDirectoryCommitment(directory)) throw new Error("Stealth directory commitment does not match.");
}

function validateEncryptedEnvelope(value: unknown): asserts value is EncryptedStealthDirectory {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Encrypted directory envelope is invalid.");
  const envelope = value as EncryptedStealthDirectory;
  const allowed = ["kind", "version", "network", "poolAddress", "tokenAddress", "algorithm", "kdf", "iv", "ciphertext", "ciphertextDigest", "contactCount", "updatedAt", "notice"];
  if (Object.keys(envelope).some((key) => !allowed.includes(key)) || envelope.kind !== ENVELOPE_KIND || envelope.version !== STEALTH_DIRECTORY_VERSION || envelope.network !== MAINNET_CHAIN_ID || envelope.poolAddress !== STRK20_POOL_ADDRESS || envelope.tokenAddress !== STRK_TOKEN_ADDRESS || envelope.algorithm !== ENCRYPTION_ALGORITHM || envelope.notice !== ENVELOPE_NOTICE) throw new Error("Encrypted directory header is invalid.");
  if (!envelope.kdf || envelope.kdf.name !== "PBKDF2" || envelope.kdf.hash !== "SHA-256") throw new Error("Encrypted directory KDF is invalid.");
  normalizeIterations(envelope.kdf.iterations);
  for (const encoded of [envelope.kdf.salt, envelope.iv, envelope.ciphertext, envelope.ciphertextDigest]) {
    if (typeof encoded !== "string" || !encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error("Encrypted directory encoding is invalid.");
  }
  if (!Number.isInteger(envelope.contactCount) || envelope.contactCount < 0 || envelope.contactCount > MAX_DIRECTORY_CONTACTS) throw new Error("Encrypted directory contact count is invalid.");
  requireIsoTimestamp(envelope.updatedAt, "Encrypted directory update time");
}

function normalizeContactSet(contacts: StealthBillingProfile[]): StealthBillingProfile[] {
  if (!Array.isArray(contacts) || contacts.length > MAX_DIRECTORY_CONTACTS) throw new Error(`A directory supports at most ${MAX_DIRECTORY_CONTACTS} contacts.`);
  for (const profile of contacts) if (!verifyStealthBillingProfile(profile)) throw new Error("A billing profile is invalid or altered.");
  if (new Set(contacts.map((profile) => profile.profileId)).size !== contacts.length) throw new Error("Billing profile IDs must be unique.");
  if (new Set(contacts.map((profile) => profile.canonicalAlias)).size !== contacts.length) throw new Error("Merchant aliases must be unique.");
  return [...contacts].sort((left, right) => left.canonicalAlias.localeCompare(right.canonicalAlias));
}

function computeProfileCommitment(profile: Omit<StealthBillingProfile, "profileCommitment"> | StealthBillingProfile): bigint {
  return hashElements([
    PROFILE_DOMAIN,
    hash.starknetKeccak(profile.profileId),
    hash.starknetKeccak(profile.canonicalAlias),
    hash.starknetKeccak(profile.merchantName),
    BigInt(profile.stealthAddress),
    BigInt(profile.directoryViewingPublicKey.x),
    BigInt(profile.directoryViewingPublicKey.y),
    ...profile.tags.map((tag) => hash.starknetKeccak(tag)),
    hash.starknetKeccak(profile.note || "empty"),
    BigInt(Math.floor(Date.parse(profile.issuedAt) / 1_000)),
    BigInt(STRK20_POOL_ADDRESS),
  ]);
}

function computeDirectoryCommitment(directory: Omit<StealthDirectory, "directoryCommitment"> | StealthDirectory): bigint {
  return hashElements([
    DIRECTORY_DOMAIN,
    hash.starknetKeccak(directory.directoryId),
    hash.starknetKeccak(directory.directoryName),
    hash.starknetKeccak(directory.ownerAlias),
    BigInt(Math.floor(Date.parse(directory.createdAt) / 1_000)),
    BigInt(Math.floor(Date.parse(directory.updatedAt) / 1_000)),
    BigInt(directory.contacts.length),
    ...directory.contacts.map((profile) => BigInt(profile.profileCommitment)),
  ]);
}

function canonicalizeAlias(alias: string): string {
  return requireText(alias, "Merchant alias", 48).normalize("NFKC").trim().toLocaleLowerCase().replace(/\s+/gu, " ");
}

function normalizeTags(tags: string[]): string[] {
  if (!Array.isArray(tags) || tags.length > MAX_DIRECTORY_TAGS) throw new Error(`A billing profile supports at most ${MAX_DIRECTORY_TAGS} tags.`);
  const normalized = tags.map((tag) => requireText(tag, "Contact tag", 24).normalize("NFKC").toLocaleLowerCase());
  return [...new Set(normalized)].sort();
}

function normalizePublicKey(key: DirectoryViewingPublicKey): DirectoryViewingPublicKey {
  return pointToFelts(pointFromFelts(key));
}

function pointToFelts(point: ReturnType<typeof ec.starkCurve.ProjectivePoint.BASE.multiply>): DirectoryViewingPublicKey {
  return { x: toHex(point.x), y: toHex(point.y) };
}

function pointFromFelts(point: DirectoryViewingPublicKey) {
  if (!point || typeof point !== "object") throw new Error("Directory viewing public key is invalid.");
  const parsed = ec.starkCurve.ProjectivePoint.fromAffine({ x: requireFelt(point.x), y: requireFelt(point.y) });
  parsed.assertValidity();
  return parsed;
}

async function deriveDirectoryKey(passphrase: string, salt: Uint8Array<ArrayBuffer>, iterations: number, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  const normalized = normalizePassphrase(passphrase);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(normalized), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

function envelopeAssociatedData(envelope: Pick<EncryptedStealthDirectory, "kind" | "version" | "network" | "poolAddress" | "tokenAddress" | "algorithm" | "kdf" | "contactCount" | "updatedAt" | "notice">): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify({
    kind: envelope.kind,
    version: envelope.version,
    network: envelope.network,
    poolAddress: envelope.poolAddress,
    tokenAddress: envelope.tokenAddress,
    algorithm: envelope.algorithm,
    kdf: envelope.kdf,
    contactCount: envelope.contactCount,
    updatedAt: envelope.updatedAt,
    notice: envelope.notice,
  }));
}

function normalizePassphrase(value: string): string {
  if (typeof value !== "string") throw new Error("Directory passphrase is required.");
  const normalized = value.normalize("NFKC");
  if (normalized.length < 12 || normalized.length > 1_024) throw new Error("Directory passphrase must contain 12 to 1024 characters.");
  return normalized;
}

function normalizeIterations(value: number): number {
  if (!Number.isInteger(value) || value < MIN_KDF_ITERATIONS || value > 2_000_000) throw new Error("Directory KDF work factor is invalid.");
  return value;
}

function requireText(value: string, label: string, maxLength: number, pattern?: RegExp): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || normalized.length > maxLength || (pattern && !pattern.test(normalized))) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireOptionalText(value: string, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const normalized = value.normalize("NFKC").trim();
  if (normalized.length > maxLength) throw new Error(`${label} is invalid.`);
  return normalized;
}

function requireIsoTimestamp(value: string, label: string): string {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) throw new Error(`${label} must be an ISO timestamp.`);
  return value;
}

function requireBaseUnits(value: string, label: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an integer in base units.`);
  const amount = BigInt(value);
  if (amount <= 0n || amount > U128_MAX) throw new Error(`${label} is outside the STRK20 u128 range.`);
  return amount;
}

function requireFelt(value: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Directory value is not a felt.");
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error("Directory felt is outside the Stark field.");
  return parsed;
}

function requireScalar(value: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new Error("Directory value is not a scalar.");
  return requireSecretScalar(BigInt(value), "Directory private key");
}

function requireSecretScalar(value: bigint, label: string): bigint {
  if (value <= 0n || value >= CURVE_ORDER) throw new Error(`${label} is outside the Stark curve order.`);
  return value;
}

function randomScalar(): bigint {
  return ec.starkCurve.utils.normPrivateKeyToScalar(ec.starkCurve.utils.randomPrivateKey());
}

function hashElements(values: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(values));
}

function parseEncodedJson(encoded: string, maxLength: number, label: string): unknown {
  if (typeof encoded !== "string" || !encoded || encoded.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} encoding is invalid.`);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encoded)));
  } catch {
    throw new Error(`${label} could not be decoded.`);
  }
}

function toHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

async function sha256Base64Url(value: Uint8Array<ArrayBuffer>): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", value)));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("Invalid base64url value.");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
