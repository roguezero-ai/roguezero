/**
 * Credential vault — envelope encryption for the downstream secrets the runtime injects on an
 * agent's behalf (ADR 0005). The agent never holds these; the vault holds them encrypted at rest,
 * and the runtime decrypts one, transiently, only after a call is authorized (ADR 0005 D0).
 *
 * Envelope (three tiers), file format v1 — hardened per the 2026-07-11 crypto review:
 *   root ─wrap─▶ master secret ─HKDF─▶ { DEK (per-credential AEAD), MAC key (whole-file manifest) }
 * A `KeyProvider` wraps/unwraps the master secret; it never exposes the root key, so a local root
 * (self-host) and a KMS (enterprise) share one format. Each credential is sealed with
 * XChaCha20-Poly1305 (24-byte random nonces — misuse-resistant, which is *why* XChaCha over the
 * 96-bit-nonce variant; do not "optimize" to it). The AAD is an **injective** length-prefixed
 * encoding of (toolId, ref) — plain concatenation with a delimiter is not injective and permits a
 * cross-inject collision, so we length-prefix.
 *
 * Whole-file integrity: an HMAC-SHA256 **manifest** over (version, generation, wrappedSecret, all
 * entries) is verified on load. Without it, an attacker with write access could delete entries or
 * roll the file back to an earlier valid snapshot (resurrecting a rotated-out, still-live
 * credential) — the AEAD on individual entries does not catch that. The `generation` counter makes
 * that rollback detectable against trusted external state (KMS/sidecar — enforced by the store
 * layer). The manifest alone catches all *partial* tamper; full-file rollback needs the external
 * counter and is a documented residual for the raw-local root mode (the weakest supported).
 *
 * Invariants (ADR 0005): vetted crypto only (`@noble`); every auth/decrypt failure throws (fail
 * closed); `getCredential` returns bytes, never an (unzeroable) string, so the injection path can
 * zero them; nothing here logs a secret.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { z } from "zod";

const KEY_BYTES = 32;
const NONCE_BYTES = 24; // XChaCha20 nonce
const SECRET_BYTES = 32;
export const VAULT_VERSION = 1 as const;

// Distinct HKDF labels give cryptographically independent keys from one wrapped secret, so the
// manifest MAC key is never the DEK (domain separation).
const DEK_INFO = new TextEncoder().encode("roguezero-vault-dek-v1");
const MAC_INFO = new TextEncoder().encode("roguezero-vault-mac-v1");
const NO_SALT = new Uint8Array(0);

/** Credential refs and tool ids: a conservative charset (also keeps the manifest/AAD sane). */
const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

const b64 = (u: Uint8Array): string => Buffer.from(u).toString("base64");
const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));

function assertId(kind: string, value: string): void {
  if (!ID_RE.test(value)) {
    throw new Error(`${kind} must match ${ID_RE} (got ${JSON.stringify(value).slice(0, 40)})`);
  }
}

/**
 * Injective AAD for (toolId, ref): `u32(len)‖toolId‖u32(len)‖ref`. Unlike `toolId ‖ "\n" ‖ ref`,
 * no two distinct pairs can produce the same bytes — closing the confused-deputy cross-inject an
 * attacker could otherwise craft by registering an id containing the delimiter.
 */
function bindAad(toolId: string, ref: string): Uint8Array {
  const t = new TextEncoder().encode(toolId);
  const r = new TextEncoder().encode(ref);
  const out = new Uint8Array(4 + t.length + 4 + r.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, t.length);
  out.set(t, 4);
  dv.setUint32(4 + t.length, r.length);
  out.set(r, 8 + t.length);
  return out;
}

/** HKDF the wrapped master secret into the two independent keys. Caller zeroes both after use. */
function deriveKeys(secret: Uint8Array): { dek: Uint8Array; macKey: Uint8Array } {
  return {
    dek: hkdf(sha256, secret, NO_SALT, DEK_INFO, KEY_BYTES),
    macKey: hkdf(sha256, secret, NO_SALT, MAC_INFO, KEY_BYTES),
  };
}

/**
 * Wraps/unwraps the master secret. `localKeyProvider` does it with a root key held on the box; a KMS
 * provider (additive, later) delegates to KMS Encrypt/Decrypt so the root key never leaves the KMS.
 * The vault never sees the root key — this is the seam that lets self-host and KMS share one format
 * (ADR 0005 D2). `unwrap` MUST throw on any auth failure (fail closed); it never returns the root.
 */
export interface KeyProvider {
  wrap(secret: Uint8Array): Promise<Uint8Array>;
  unwrap(wrapped: Uint8Array): Promise<Uint8Array>;
}

/**
 * Root key held locally — a 32-byte secret. The **weakest** supported provider: whoever reads this
 * key reads every credential, so it must not co-reside with the vault or its backups. Prefer an
 * argon2id-passphrase or KMS provider (added behind this interface) for anything real.
 */
export function localKeyProvider(rootKey: Uint8Array): KeyProvider {
  if (rootKey.length !== KEY_BYTES) {
    throw new Error(`root key must be ${KEY_BYTES} bytes, got ${rootKey.length}`);
  }
  return {
    async wrap(secret) {
      const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
      const ct = xchacha20poly1305(rootKey, nonce).encrypt(secret);
      const out = new Uint8Array(nonce.length + ct.length);
      out.set(nonce);
      out.set(ct, nonce.length);
      return out;
    },
    async unwrap(wrapped) {
      if (wrapped.length <= NONCE_BYTES) throw new Error("wrapped secret is malformed");
      return xchacha20poly1305(rootKey, wrapped.slice(0, NONCE_BYTES)).decrypt(
        wrapped.slice(NONCE_BYTES),
      );
    },
  };
}

/** One sealed credential. Every field is covered by the manifest MAC, so none can be silently edited. */
export interface VaultEntry {
  toolId: string;
  nonce: string; // base64, per-entry
  ciphertext: string; // base64, AEAD tag included
}

/** The serializable vault (format v1). */
export interface VaultFile {
  version: typeof VAULT_VERSION;
  /** Monotonic; bumped on every mutation. Lets the store detect rollback against external state. */
  generation: number;
  wrappedSecret: string; // base64
  entries: Record<string, VaultEntry>;
  /** HMAC-SHA256 over the canonical (version, generation, wrappedSecret, sorted entries). */
  manifestMac: string; // base64
}

/** In-memory handle: the file plus the provider that can unwrap its secret. */
export interface Vault {
  file: VaultFile;
  keyProvider: KeyProvider;
}

const B64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, "not base64");
const vaultEntrySchema = z
  .object({ toolId: z.string(), nonce: B64, ciphertext: B64.min(1) })
  .strict();
const vaultFileSchema = z
  .object({
    version: z.number().int(),
    generation: z.number().int().positive(),
    wrappedSecret: B64.min(1),
    entries: z.record(vaultEntrySchema),
    manifestMac: B64.min(1),
  })
  .strict();

/** Canonical bytes for the manifest MAC: deterministic, entries sorted by ref. Excludes the MAC. */
function canonicalManifest(file: Omit<VaultFile, "manifestMac">): Uint8Array {
  const entries = Object.entries(file.entries)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([ref, e]) => [ref, e.toolId, e.nonce, e.ciphertext]);
  const canonical = JSON.stringify([file.version, file.generation, file.wrappedSecret, entries]);
  return new TextEncoder().encode(canonical);
}

function computeManifestMac(macKey: Uint8Array, file: Omit<VaultFile, "manifestMac">): Uint8Array {
  return hmac(sha256, macKey, canonicalManifest(file));
}

/** Recompute the manifest MAC after a mutation. Bumps the generation first (rollback signal). */
async function reseal(vault: Vault): Promise<void> {
  const secret = await vault.keyProvider.unwrap(unb64(vault.file.wrappedSecret));
  try {
    const { macKey } = deriveKeys(secret);
    try {
      vault.file.generation += 1;
      vault.file.manifestMac = b64(computeManifestMac(macKey, vault.file));
    } finally {
      macKey.fill(0);
    }
  } finally {
    secret.fill(0);
  }
}

/** Create an empty vault with a fresh master secret, wrapped by the provider. */
export async function createVault(keyProvider: KeyProvider): Promise<Vault> {
  const secret = new Uint8Array(randomBytes(SECRET_BYTES));
  try {
    const wrapped = await keyProvider.wrap(secret);
    const { macKey } = deriveKeys(secret);
    try {
      const file: VaultFile = {
        version: VAULT_VERSION,
        generation: 1,
        wrappedSecret: b64(wrapped),
        entries: Object.create(null) as Record<string, VaultEntry>,
        manifestMac: "",
      };
      file.manifestMac = b64(computeManifestMac(macKey, file));
      return { keyProvider, file };
    } finally {
      macKey.fill(0);
    }
  } finally {
    secret.fill(0);
  }
}

/**
 * Rehydrate a vault from its serialized file. Validates the shape (Zod), unwraps the secret, and
 * **verifies the manifest MAC** before trusting any entry — so a tampered, truncated, or
 * partially-rolled-back file is rejected here, fail closed. Throws on an unknown version.
 */
export async function loadVault(file: unknown, keyProvider: KeyProvider): Promise<Vault> {
  const parsed = vaultFileSchema.parse(file);
  if (parsed.version !== VAULT_VERSION) {
    throw new Error(`unsupported vault version ${parsed.version}`);
  }

  const secret = await keyProvider.unwrap(unb64(parsed.wrappedSecret));
  try {
    const { macKey } = deriveKeys(secret);
    try {
      const expected = computeManifestMac(macKey, parsed as Omit<VaultFile, "manifestMac">);
      const actual = unb64(parsed.manifestMac);
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        throw new Error("vault manifest integrity check failed (tampered or rolled back)");
      }
    } finally {
      macKey.fill(0);
    }
  } finally {
    secret.fill(0);
  }

  // Rebuild entries on a null-prototype object (no `__proto__` pollution) and validate every id.
  const entries = Object.create(null) as Record<string, VaultEntry>;
  for (const [ref, entry] of Object.entries(parsed.entries)) {
    assertId("credential ref", ref);
    assertId("tool id", entry.toolId);
    entries[ref] = entry;
  }
  return {
    keyProvider,
    file: {
      version: VAULT_VERSION,
      generation: parsed.generation,
      wrappedSecret: parsed.wrappedSecret,
      entries,
      manifestMac: parsed.manifestMac,
    },
  };
}

/** Store (or replace) a credential under `ref`, cryptographically bound to `toolId`. */
export async function putCredential(
  vault: Vault,
  params: { ref: string; toolId: string; value: string },
): Promise<void> {
  assertId("credential ref", params.ref);
  assertId("tool id", params.toolId);
  const secret = await vault.keyProvider.unwrap(unb64(vault.file.wrappedSecret));
  const plaintext = new TextEncoder().encode(params.value);
  try {
    const { dek } = deriveKeys(secret);
    try {
      const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
      const ciphertext = xchacha20poly1305(dek, nonce, bindAad(params.toolId, params.ref)).encrypt(
        plaintext,
      );
      vault.file.entries[params.ref] = {
        toolId: params.toolId,
        nonce: b64(nonce),
        ciphertext: b64(ciphertext),
      };
    } finally {
      dek.fill(0);
    }
  } finally {
    secret.fill(0);
    plaintext.fill(0);
  }
  await reseal(vault);
}

/**
 * Decrypt the credential for `(ref, toolId)`, returning the raw bytes. Throws (fail closed) if the
 * entry is missing, is bound to a different tool, or the AEAD tag fails. Returns **`Uint8Array`, not
 * a string**, so the injection path can build the header bytes and then zero them — a returned
 * string would be immutable and unzeroable, defeating the no-leak guarantee (ADR 0005 D3). A single
 * uniform error avoids an existence-enumeration oracle.
 */
export async function getCredential(
  vault: Vault,
  params: { ref: string; toolId: string },
): Promise<Uint8Array> {
  const entry = vault.file.entries[params.ref];
  if (!entry || entry.toolId !== params.toolId) {
    throw new Error("no credential available for this tool");
  }
  const secret = await vault.keyProvider.unwrap(unb64(vault.file.wrappedSecret));
  try {
    const { dek } = deriveKeys(secret);
    try {
      // Throws on auth failure; the caller owns zeroing the returned bytes after injection.
      return xchacha20poly1305(dek, unb64(entry.nonce), bindAad(params.toolId, params.ref)).decrypt(
        unb64(entry.ciphertext),
      );
    } finally {
      dek.fill(0);
    }
  } finally {
    secret.fill(0);
  }
}

/** Remove a credential and re-seal. Idempotent. */
export async function removeCredential(vault: Vault, ref: string): Promise<void> {
  if (ref in vault.file.entries) {
    delete vault.file.entries[ref];
    await reseal(vault);
  }
}

/** The references currently stored (never the values). */
export function listCredentialRefs(vault: Vault): string[] {
  return Object.keys(vault.file.entries);
}
