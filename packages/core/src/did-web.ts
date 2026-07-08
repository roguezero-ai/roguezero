/**
 * did:web: build identifiers, map them to their document URL (per the did:web method
 * spec), and generate a DID document from an Ed25519 public key.
 *
 * did:web trust is domain/HTTPS-based: `did:web:acme.example` publishes its document at
 * `https://acme.example/.well-known/did.json`; path segments (`did:web:acme.example:u:bob`)
 * map to `https://acme.example/u/bob/did.json`. A host port's colon is percent-encoded
 * as `%3A`. Resolution (including a no-domain local dev helper) lives in `resolver.ts`.
 */

import type { DIDDocument } from "did-resolver";
import { DidError } from "./errors.js";
import { ed25519PublicKeyToMultibase } from "./identity.js";
import type { Did } from "./types.js";

const DID_WEB_PREFIX = "did:web:";

/**
 * Build a `did:web` identifier from a host and optional path segments.
 * `didWebFromHost("localhost:8080")` → `did:web:localhost%3A8080`.
 * `didWebFromHost("acme.example", "u", "bob")` → `did:web:acme.example:u:bob`.
 */
export function didWebFromHost(host: string, ...path: string[]): Did {
  if (!host) {
    throw new DidError("did:web requires a host", "malformed-did");
  }
  if (host.includes("/")) {
    throw new DidError(`did:web host must not contain '/': ${host}`, "malformed-did");
  }
  for (const segment of path) {
    if (!segment || segment.includes("/") || segment.includes(":")) {
      throw new DidError(
        `invalid did:web path segment: ${JSON.stringify(segment)}`,
        "malformed-did",
      );
    }
  }
  const encodedHost = host.replace(/:/g, "%3A");
  return `${DID_WEB_PREFIX}${[encodedHost, ...path].join(":")}`;
}

/**
 * Map a `did:web` identifier to the HTTPS URL its DID document is served from.
 * Throws a typed DidError for non-did:web input or a malformed identifier.
 */
export function didWebToUrl(did: Did): URL {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new DidError(`Not a did:web identifier: ${did}`, "unsupported-method");
  }
  const rest = did.slice(DID_WEB_PREFIX.length);
  if (!rest) {
    throw new DidError(`did:web is missing a host: ${did}`, "malformed-did");
  }
  const [rawHost, ...pathSegments] = rest.split(":");
  const host = decodeURIComponent(rawHost as string);
  const path =
    pathSegments.length > 0
      ? `/${pathSegments.map(decodeURIComponent).join("/")}/did.json`
      : "/.well-known/did.json";
  try {
    return new URL(`https://${host}${path}`);
  } catch {
    throw new DidError(`did:web does not map to a valid URL: ${did}`, "malformed-did");
  }
}

/**
 * Generate a spec-correct DID document for a `did:web` from an Ed25519 public key.
 * The key is exposed as an Ed25519VerificationKey2020 and referenced by both
 * `authentication` and `assertionMethod` (the latter is what VC issuance verifies against).
 */
export function createDidWebDocument(did: Did, publicKey: Uint8Array): DIDDocument {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new DidError(`Not a did:web identifier: ${did}`, "unsupported-method");
  }
  const keyId = `${did}#key-1`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: ed25519PublicKeyToMultibase(publicKey),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}
