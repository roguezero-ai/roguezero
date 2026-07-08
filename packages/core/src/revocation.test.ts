import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFileRevocationChecker,
  createRevocationChecker,
  createUrlRevocationChecker,
  loadRevocationListFromFile,
  revokeCredential,
} from "./revocation.js";
import {
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  type CredentialSigner,
} from "./credentials.js";
import { createDidWebDocument, didWebFromHost } from "./did-web.js";
import { createDidKey, generateEd25519KeyPair } from "./identity.js";
import { createInMemoryNonceStore } from "./nonce.js";
import { createPresentation } from "./presentation.js";
import { createResolver } from "./resolver.js";
import { VerificationError } from "./errors.js";
import { verifyRequest } from "./verify.js";

const tmpFiles: string[] = [];
async function tempPath(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rz-revocation-"));
  tmpFiles.push(dir);
  return join(dir, "revocations.json");
}

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(tmpFiles.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("revoke + file checker", () => {
  it("revokes a credential id and detects it (idempotently)", async () => {
    const path = await tempPath();
    const checker = createFileRevocationChecker(path);

    expect(await checker({ id: "urn:uuid:abc", issuer: "did:web:acme.example" })).toBe(false);

    await revokeCredential(path, "urn:uuid:abc");
    await revokeCredential(path, "urn:uuid:abc"); // idempotent
    const revoked = await loadRevocationListFromFile(path);
    expect([...revoked]).toEqual(["urn:uuid:abc"]);

    expect(await checker({ id: "urn:uuid:abc", issuer: "did:web:acme.example" })).toBe(true);
    expect(await checker({ id: "urn:uuid:other", issuer: "did:web:acme.example" })).toBe(false);
  });

  it("treats a credential with no id as not revocable", async () => {
    const path = await tempPath();
    await revokeCredential(path, "urn:uuid:abc");
    const checker = createFileRevocationChecker(path);
    expect(await checker({ issuer: "did:web:acme.example" })).toBe(false);
  });
});

describe("url checker — fail closed", () => {
  it("throws when the list cannot be fetched (so the pipeline denies)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 503, statusText: "Service Unavailable" })),
    );
    const checker = createUrlRevocationChecker("https://revocations.example/list.json");
    await expect(checker({ id: "urn:uuid:abc", issuer: "did:web:acme.example" })).rejects.toThrow(
      /fetch failed/,
    );
  });

  it("reads revoked ids from a successful response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ revoked: ["urn:uuid:abc"] })),
    );
    const checker = createUrlRevocationChecker("https://revocations.example/list.json");
    expect(await checker({ id: "urn:uuid:abc", issuer: "did:web:acme.example" })).toBe(true);
  });
});

describe("pipeline integration — revoke then deny", () => {
  it("allows before revocation and denies (revoked) after", async () => {
    const audience = "mcp://reports.acme.example";
    const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
    const orgDid = didWebFromHost("acme.example");
    const resolver = createResolver({
      localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
    });
    const org: CredentialSigner = { did: orgDid, privateKey: orgPriv };
    const agent = createDidKey();

    const profileVc = await issueAgentProfileCredential(org, {
      id: agent.did,
      controller: orgDid,
      name: "Reporter",
    });
    const capabilityVc = await issueAgentCapabilityCredential(org, {
      id: agent.did,
      tools: [{ name: "read_report", scopes: ["reports:read"] }],
      audience,
    });

    const path = await tempPath();
    await writeFile(path, JSON.stringify({ revoked: [] }), "utf8");
    const isRevoked = createFileRevocationChecker(path);
    const nonceStore = createInMemoryNonceStore();

    const present = async () => {
      const challenge = await nonceStore.issue(audience);
      return createPresentation(
        { did: agent.did, privateKey: agent.privateKey },
        { profileVc, capabilityVc },
        { challenge: challenge.nonce, audience },
      );
    };
    const run = async (presentation: string) =>
      verifyRequest({
        presentation,
        audience,
        resolver,
        trustedIssuers: [orgDid],
        nonceStore,
        isRevoked,
      });

    // Allowed before revocation.
    const before = await run(await present());
    expect(before.agent).toBe(agent.did);

    // Revoke the capability id, then a fresh call is denied.
    const capId = (await import("did-jwt")).decodeJWT(capabilityVc).payload.jti as string;
    await revokeCredential(path, capId);

    await expect(run(await present())).rejects.toSatisfy(
      (e: unknown) => e instanceof VerificationError && e.reason === "revoked",
    );
  });
});

describe("createRevocationChecker", () => {
  it("checks membership against the loader", async () => {
    const checker = createRevocationChecker(async () => new Set(["urn:uuid:x"]));
    expect(await checker({ id: "urn:uuid:x", issuer: "did:web:a" })).toBe(true);
    expect(await checker({ id: "urn:uuid:y", issuer: "did:web:a" })).toBe(false);
  });
});
