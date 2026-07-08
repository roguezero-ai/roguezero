import { describe, expect, it } from "vitest";
import { DidError } from "./errors.js";
import { createDidWebDocument, didWebFromHost, didWebToUrl } from "./did-web.js";
import { ed25519PublicKeyFromDidKey, generateEd25519KeyPair } from "./identity.js";
import { createResolver, resolveDid } from "./resolver.js";

describe("didWebFromHost", () => {
  it("builds a bare-domain did:web", () => {
    expect(didWebFromHost("acme.example")).toBe("did:web:acme.example");
  });

  it("percent-encodes a host port", () => {
    expect(didWebFromHost("localhost:8080")).toBe("did:web:localhost%3A8080");
  });

  it("appends path segments with colons", () => {
    expect(didWebFromHost("acme.example", "u", "bob")).toBe("did:web:acme.example:u:bob");
  });

  it("rejects an empty host and slashes in inputs", () => {
    expect(() => didWebFromHost("")).toThrowError(DidError);
    expect(() => didWebFromHost("acme.example/path")).toThrowError(DidError);
    expect(() => didWebFromHost("acme.example", "a/b")).toThrowError(DidError);
  });
});

describe("didWebToUrl", () => {
  it("maps a bare domain to /.well-known/did.json", () => {
    expect(didWebToUrl("did:web:acme.example").href).toBe(
      "https://acme.example/.well-known/did.json",
    );
  });

  it("maps path segments to a nested did.json", () => {
    expect(didWebToUrl("did:web:acme.example:u:bob").href).toBe(
      "https://acme.example/u/bob/did.json",
    );
  });

  it("decodes a percent-encoded port", () => {
    expect(didWebToUrl("did:web:localhost%3A8080").href).toBe(
      "https://localhost:8080/.well-known/did.json",
    );
  });

  it("round-trips with didWebFromHost", () => {
    const did = didWebFromHost("acme.example", "agents", "reporter");
    expect(didWebToUrl(did).href).toBe("https://acme.example/agents/reporter/did.json");
  });

  it("rejects a non-did:web method", () => {
    try {
      didWebToUrl("did:key:z6MkExample");
      throw new Error("expected DidError");
    } catch (e) {
      expect(e).toBeInstanceOf(DidError);
      expect((e as DidError).code).toBe("unsupported-method");
    }
  });

  it("rejects a did:web with no host", () => {
    expect(() => didWebToUrl("did:web:")).toThrowError(DidError);
  });
});

describe("createDidWebDocument", () => {
  it("produces a document whose key round-trips back to the public key", () => {
    const { publicKey } = generateEd25519KeyPair();
    const did = didWebFromHost("acme.example");
    const doc = createDidWebDocument(did, publicKey);

    expect(doc.id).toBe(did);
    const vm = doc.verificationMethod?.[0];
    expect(vm?.type).toBe("Ed25519VerificationKey2020");
    expect(vm?.controller).toBe(did);
    expect(doc.assertionMethod).toContain(`${did}#key-1`);

    // The published multibase key must decode to the exact key we put in.
    const decoded = ed25519PublicKeyFromDidKey(`did:key:${vm?.publicKeyMultibase}`);
    expect(decoded).toEqual(publicKey);
  });

  it("rejects a non-did:web identifier", () => {
    const { publicKey } = generateEd25519KeyPair();
    expect(() => createDidWebDocument("did:key:z6MkExample", publicKey)).toThrowError(DidError);
  });
});

describe("did:web resolve via the local dev helper (no domain needed)", () => {
  it("resolves an in-memory did:web document", async () => {
    const { publicKey } = generateEd25519KeyPair();
    const did = didWebFromHost("acme.example");
    const doc = createDidWebDocument(did, publicKey);
    const resolver = createResolver({ localDidWebDocuments: { [did]: doc } });

    const result = await resolveDid(did, resolver);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didDocument?.assertionMethod).toContain(`${did}#key-1`);
  });

  it("still resolves did:key through the same resolver", async () => {
    const { publicKey } = generateEd25519KeyPair();
    const orgDid = didWebFromHost("acme.example");
    const resolver = createResolver({
      localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, publicKey) },
    });
    const { createDidKey } = await import("./identity.js");
    const agent = createDidKey();

    const result = await resolveDid(agent.did, resolver);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(agent.did);
  });
});
