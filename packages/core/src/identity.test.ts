import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "multiformats/bases/base58";
import { DidError } from "./errors.js";
import {
  createDidKey,
  didKeyFromEd25519PublicKey,
  ed25519PublicKeyFromDidKey,
  generateEd25519KeyPair,
} from "./identity.js";
import { resolveDid } from "./resolver.js";

describe("did:key create", () => {
  it("generates a did:key that starts with the Ed25519 prefix z6Mk", () => {
    const { did } = createDidKey();
    expect(did.startsWith("did:key:z6Mk")).toBe(true);
  });

  it("does not leak private key material into the identifier", () => {
    const { did, privateKey } = createDidKey();
    expect(privateKey).toHaveLength(32);
    expect(did).not.toContain(base58btc.encode(privateKey));
  });

  it("produces a working signing key pair", () => {
    // Sanity: the generated keys actually sign/verify (proves keygen is real).
    const { publicKey, privateKey } = generateEd25519KeyPair();
    const msg = new TextEncoder().encode("roguezero");
    const sig = ed25519.sign(msg, privateKey);
    expect(ed25519.verify(sig, msg, publicKey)).toBe(true);
  });
});

describe("did:key encode/decode round trip", () => {
  it("decodes back to the exact public key it was created from", () => {
    const { publicKey } = generateEd25519KeyPair();
    const did = didKeyFromEd25519PublicKey(publicKey);
    expect(ed25519PublicKeyFromDidKey(did)).toEqual(publicKey);
  });

  it("is stable: same key always yields the same did:key", () => {
    const { publicKey } = generateEd25519KeyPair();
    expect(didKeyFromEd25519PublicKey(publicKey)).toBe(didKeyFromEd25519PublicKey(publicKey));
  });
});

describe("did:key decode — negative cases", () => {
  it("rejects a non-did:key method", () => {
    expect(() => ed25519PublicKeyFromDidKey("did:web:acme.example")).toThrowError(DidError);
    try {
      ed25519PublicKeyFromDidKey("did:web:acme.example");
    } catch (e) {
      expect((e as DidError).code).toBe("unsupported-method");
    }
  });

  it("rejects a non-base58btc multibase prefix", () => {
    expect(() => ed25519PublicKeyFromDidKey("did:key:Qm-not-multibase-z")).toThrowError(DidError);
  });

  it("rejects garbage base58 content", () => {
    // '0OIl' are not in the base58btc alphabet.
    expect(() => ed25519PublicKeyFromDidKey("did:key:z0OIl")).toThrowError(DidError);
  });

  it("rejects a did:key whose multicodec is not Ed25519", () => {
    // Prefix a 32-byte payload with a bogus multicodec (secp256k1 = 0xe7 0x01).
    const payload = new Uint8Array(32).fill(7);
    const prefixed = new Uint8Array([0xe7, 0x01, ...payload]);
    const did = `did:key:${base58btc.encode(prefixed)}`;
    try {
      ed25519PublicKeyFromDidKey(did);
      throw new Error("expected DidError");
    } catch (e) {
      expect(e).toBeInstanceOf(DidError);
      expect((e as DidError).code).toBe("unsupported-key");
    }
  });

  it("rejects an Ed25519-prefixed key of the wrong length", () => {
    const prefixed = new Uint8Array([0xed, 0x01, 1, 2, 3]); // too short
    const did = `did:key:${base58btc.encode(prefixed)}`;
    expect(() => ed25519PublicKeyFromDidKey(did)).toThrowError(/32 bytes/);
  });
});

describe("did:key resolve", () => {
  it("resolves a created did:key to a DID document with the same id", async () => {
    const { did } = createDidKey();
    const result = await resolveDid(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didDocument?.verificationMethod?.length).toBeGreaterThan(0);
  });

  it("fails closed on an unresolvable did:key (error in metadata, no throw)", async () => {
    const result = await resolveDid("did:key:zNotARealKey");
    expect(result.didResolutionMetadata.error).toBeDefined();
    expect(result.didDocument).toBeNull();
  });
});
