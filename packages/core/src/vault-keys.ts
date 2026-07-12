/**
 * Root-key providers for the credential vault (ADR 0005 D2, review follow-up). These wrap/unwrap the
 * vault's master secret; they are the vault's actual security boundary (whoever can unwrap reads
 * every credential), so this is where the "raw 32-byte key in a file" gap gets closed.
 *
 * Providers, strongest-posture first:
 *   - `kmsKeyProvider`     — the root never leaves a KMS; wrap/unwrap delegate to KMS Encrypt/Decrypt.
 *   - `argon2idKeyProvider`— **recommended self-host default**: nothing secret at rest. The key is
 *                            derived from an operator passphrase (env/prompt) via argon2id; only the
 *                            salt + params sit on disk, so a stolen disk/backup yields nothing.
 *   - `localKeyProvider`   — (in `vault.ts`) a raw 32-byte key; the weakest supported option.
 *
 * Performance invariant (Vera): the vault decrypts a credential per tool call, so `unwrap` must be
 * cheap. argon2id is memory-hard and slow *by design* — so we derive the key-encryption-key **once**
 * and cache it in memory (keyed by the salt in the blob); the expensive derivation is paid at boot /
 * first call, never per request. Holding the derived key in memory for the process lifetime is
 * inherent to any KMS-less running server and is stated honestly, not hidden.
 */

import { randomBytes } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { argon2id } from "@noble/hashes/argon2";
import type { KeyProvider } from "./vault.js";

const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const SALT_BYTES = 16;
const ARGON_BLOB_VERSION = 1;

/** argon2id cost parameters (stored per-vault in the blob, so they can be raised without migration). */
export interface Argon2idParams {
  /** iterations (time cost) */
  t: number;
  /** memory in KiB */
  m: number;
  /** parallelism */
  p: number;
}

/**
 * Default cost — strong and above the OWASP argon2id floor, tuned to derive once in ~1–2s. (The
 * 2026-07-11 review suggested ≥256 MiB; we default to 64 MiB for boot/CLI usability, store the
 * params per-vault so they upgrade freely, and expose `ARGON2ID_HIGH` for high-security deployments.
 * Vera's sign-off: acceptable because derivation is once-per-process, not per-request.)
 */
export const ARGON2ID_DEFAULT: Argon2idParams = { t: 3, m: 64 * 1024, p: 1 };
export const ARGON2ID_HIGH: Argon2idParams = { t: 3, m: 256 * 1024, p: 1 };

const toBytes = (s: string | Uint8Array): Uint8Array =>
  typeof s === "string" ? new TextEncoder().encode(s) : s;

function encodeArgonBlob(
  params: Argon2idParams,
  salt: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(1 + 12 + 1 + salt.length + nonce.length + ct.length);
  const dv = new DataView(out.buffer);
  out[0] = ARGON_BLOB_VERSION;
  dv.setUint32(1, params.t);
  dv.setUint32(5, params.m);
  dv.setUint32(9, params.p);
  out[13] = salt.length;
  out.set(salt, 14);
  out.set(nonce, 14 + salt.length);
  out.set(ct, 14 + salt.length + nonce.length);
  return out;
}

function decodeArgonBlob(blob: Uint8Array): {
  params: Argon2idParams;
  salt: Uint8Array;
  nonce: Uint8Array;
  ct: Uint8Array;
} {
  if (blob.length < 14 || blob[0] !== ARGON_BLOB_VERSION) {
    throw new Error("malformed argon2id key blob");
  }
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const params = { t: dv.getUint32(1), m: dv.getUint32(5), p: dv.getUint32(9) };
  const saltLen = blob[13]!; // guarded above: blob.length >= 14
  const saltEnd = 14 + saltLen;
  const nonceEnd = saltEnd + NONCE_BYTES;
  if (blob.length <= nonceEnd) throw new Error("malformed argon2id key blob");
  return {
    params,
    salt: blob.slice(14, saltEnd),
    nonce: blob.slice(saltEnd, nonceEnd),
    ct: blob.slice(nonceEnd),
  };
}

/**
 * Passphrase-derived provider (recommended self-host default). Nothing secret is stored: the master
 * secret is sealed under a KEK = argon2id(passphrase, salt, params); salt + params ride in the blob.
 * The KEK is derived once and cached in memory so per-call `unwrap` is a fast symmetric decrypt.
 */
export function argon2idKeyProvider(
  passphrase: string | Uint8Array,
  params: Argon2idParams = ARGON2ID_DEFAULT,
): KeyProvider {
  const pass = toBytes(passphrase);
  let cachedKek: Uint8Array | undefined;
  let cachedSaltKey: string | undefined;

  const kekFor = (salt: Uint8Array, p: Argon2idParams): Uint8Array => {
    const saltKey = Buffer.from(salt).toString("hex");
    if (cachedKek && cachedSaltKey === saltKey) return cachedKek;
    const kek = argon2id(pass, salt, { t: p.t, m: p.m, p: p.p, dkLen: KEY_BYTES });
    cachedKek = kek;
    cachedSaltKey = saltKey;
    return kek;
  };

  return {
    async wrap(secret) {
      const salt = new Uint8Array(randomBytes(SALT_BYTES));
      const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
      const kek = kekFor(salt, params); // wrap uses the provider's params (a new vault)
      const ct = xchacha20poly1305(kek, nonce).encrypt(secret);
      return encodeArgonBlob(params, salt, nonce, ct);
    },
    async unwrap(wrapped) {
      // Params come from the blob, not the provider — a default-constructed provider can still open a
      // vault sealed with different (e.g. upgraded) params. Throws on auth failure (wrong passphrase).
      const { params: p, salt, nonce, ct } = decodeArgonBlob(wrapped);
      return xchacha20poly1305(kekFor(salt, p), nonce).decrypt(ct);
    },
  };
}

/**
 * Adapter to an external KMS. `encrypt`/`decrypt` wrap the KMS's own Encrypt/Decrypt (bind an
 * encryption context if the KMS supports it). We deliberately depend on no cloud SDK — the operator
 * supplies the two calls, so any KMS/HSM/Vault-Transit plugs in.
 */
export interface KmsAdapter {
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

/**
 * KMS-backed provider — the root key never leaves the KMS (strongest posture). Note: `unwrap` is a
 * KMS round-trip, so the runtime should cache the loaded vault's material rather than unwrapping per
 * call; a KMS outage → throw → fail closed, which is correct.
 */
export function kmsKeyProvider(adapter: KmsAdapter): KeyProvider {
  return {
    wrap: (secret) => adapter.encrypt(secret),
    unwrap: (wrapped) => adapter.decrypt(wrapped),
  };
}
