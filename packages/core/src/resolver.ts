/**
 * DID resolution across the MVP's two methods (did:key, did:web), composed from the DIF
 * resolver stack behind our own small interface.
 *
 * Dev helper: `localDidWebDocuments` lets the golden-path demo resolve did:web documents
 * from memory, so it needs no real domain, DNS, or TLS. Real did:web identifiers still
 * resolve over HTTPS via `web-did-resolver`. Resolution fails closed — failures surface in
 * `didResolutionMetadata.error` rather than throwing.
 */

import {
  Resolver,
  type DIDDocument,
  type DIDResolutionResult,
  type DIDResolver,
} from "did-resolver";
import { getResolver as getKeyDidResolver } from "key-did-resolver";
import { getResolver as getWebDidResolver } from "web-did-resolver";
import type { Did } from "./types.js";

// Re-export the resolver interface type so consumers (middleware, CLI) don't depend on
// did-resolver directly — core owns the DID-resolution abstraction.
export type { Resolvable } from "did-resolver";

export interface ResolverOptions {
  /**
   * did:web documents to serve from memory (dev/demo). Keyed by DID. When a resolved
   * did:web identifier is present here, its document is returned without any network call.
   */
  localDidWebDocuments?: Record<Did, DIDDocument>;
}

/** Build a resolver for did:key + did:web, optionally with in-memory did:web docs. */
export function createResolver(options: ResolverOptions = {}): Resolver {
  const local = options.localDidWebDocuments ?? {};
  const resolveWebOverHttps = getWebDidResolver().web;
  /* c8 ignore next 3 -- defensive: web-did-resolver always provides a 'web' resolver */
  if (!resolveWebOverHttps) {
    throw new Error("web-did-resolver did not provide a 'web' resolver");
  }

  const webWithLocalOverride: DIDResolver = async (did, parsed, resolver, resolutionOptions) => {
    const doc = local[did];
    if (doc) {
      return {
        didResolutionMetadata: { contentType: "application/did+ld+json" },
        didDocument: doc,
        didDocumentMetadata: {},
      };
    }
    return resolveWebOverHttps(did, parsed, resolver, resolutionOptions);
  };

  return new Resolver({
    ...getKeyDidResolver(),
    web: webWithLocalOverride,
  });
}

/** A default resolver: did:key plus real (HTTPS) did:web, no local overrides. */
const defaultResolver = createResolver();

/**
 * Resolve a DID to its DID document. Pass a resolver from `createResolver` to supply
 * in-memory did:web documents (the demo does this); omit it for the default resolver.
 */
export async function resolveDid(
  did: Did,
  resolver: Resolver = defaultResolver,
): Promise<DIDResolutionResult> {
  return resolver.resolve(did);
}
