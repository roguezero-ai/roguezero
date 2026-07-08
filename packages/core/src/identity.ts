/**
 * Agent identity: Ed25519 key generation and `did:key` create / resolve.
 *
 * Crypto and encoding go through vetted libraries only (a core security principle:
 * never invent crypto). We use `@noble/curves` for Ed25519, `multiformats` for
 * multibase/base58, and the DIF `did-resolver` + `key-did-resolver` for resolution.
 * did:web lands in F3; this module is did:key only.
 *
 * did:key for Ed25519 (per the did:key spec): the identifier is the multibase-base58btc
 * encoding of the public key prefixed with the `ed25519-pub` multicodec (0xed as an
 * unsigned varint = the two bytes 0xed 0x01). Such identifiers always start with `z6Mk`.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "multiformats/bases/base58";
import { DidError } from "./errors.js";
import type { AgentKeyPair, Did } from "./types.js";

/** Multicodec prefix for Ed25519 public keys: varint(0xed) = [0xed, 0x01]. */
const ED25519_PUB_MULTICODEC = Uint8Array.of(0xed, 0x01);
const ED25519_PUBLIC_KEY_LENGTH = 32;
const DID_KEY_PREFIX = "did:key:";

/** A raw Ed25519 key pair. Private material is a plain byte array; never log it. */
export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generate a fresh Ed25519 key pair. */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Multibase-base58btc encoding of an Ed25519 public key prefixed with its multicodec.
 * This is both the `did:key` identifier suffix and the `publicKeyMultibase` value used in
 * Ed25519VerificationKey2020 verification methods (so did:web reuses it).
 */
export function ed25519PublicKeyToMultibase(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new DidError(
      `Ed25519 public key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
      "malformed-key",
    );
  }
  const prefixed = new Uint8Array(ED25519_PUB_MULTICODEC.length + publicKey.length);
  prefixed.set(ED25519_PUB_MULTICODEC);
  prefixed.set(publicKey, ED25519_PUB_MULTICODEC.length);
  // base58btc.encode returns the multibase form already prefixed with 'z'.
  return base58btc.encode(prefixed);
}

/** Encode an Ed25519 public key as a `did:key` identifier. */
export function didKeyFromEd25519PublicKey(publicKey: Uint8Array): Did {
  return `${DID_KEY_PREFIX}${ed25519PublicKeyToMultibase(publicKey)}`;
}

/**
 * Decode the Ed25519 public key back out of a `did:key` identifier. This is what
 * verification uses to check signatures, so its failure modes are precise and typed.
 */
export function ed25519PublicKeyFromDidKey(did: Did): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new DidError(`Not a did:key identifier: ${did}`, "unsupported-method");
  }
  const multibase = did.slice(DID_KEY_PREFIX.length);
  if (!multibase.startsWith("z")) {
    throw new DidError(`did:key must use base58btc ('z') multibase: ${did}`, "malformed-did");
  }

  let decoded: Uint8Array;
  try {
    decoded = base58btc.decode(multibase);
  } catch {
    throw new DidError(`did:key is not valid base58btc: ${did}`, "malformed-did");
  }

  const prefixOk =
    decoded.length >= ED25519_PUB_MULTICODEC.length &&
    decoded[0] === ED25519_PUB_MULTICODEC[0] &&
    decoded[1] === ED25519_PUB_MULTICODEC[1];
  if (!prefixOk) {
    throw new DidError(`did:key is not an Ed25519 key (bad multicodec): ${did}`, "unsupported-key");
  }

  const publicKey = decoded.slice(ED25519_PUB_MULTICODEC.length);
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new DidError(
      `did:key Ed25519 key must be ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
      "malformed-did",
    );
  }
  return publicKey;
}

/** Generate a new Ed25519 key pair and its `did:key` identity. */
export function createDidKey(): AgentKeyPair {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const did = didKeyFromEd25519PublicKey(publicKey);
  // For did:key, the multibase-encoded key is exactly the identifier suffix.
  const publicKeyMultibase = did.slice(DID_KEY_PREFIX.length);
  return { did, publicKeyMultibase, privateKey };
}
