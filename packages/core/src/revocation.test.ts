import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFileRevocationChecker,
  createRevocationChecker,
  createUrlRevocationChecker,
  loadRevocationListFromFile,
  pruneExpiredEntries,
  revokeCredential,
  signRevocationList,
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

describe("signed revocation list", () => {
  const URL = "https://revocations.example/list.jwt";
  const CRED = { id: "urn:uuid:abc", issuer: "did:web:acme.example" };

  /** A publisher whose DID resolves locally, so signatures verify without network. */
  function publisher() {
    const kp = createDidKey();
    return {
      signer: { did: kp.did, privateKey: kp.privateKey } satisfies CredentialSigner,
      did: kp.did,
    };
  }
  const serve = (jwt: string) =>
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(jwt)),
    );
  const reason = (r: string) => (e: unknown) => e instanceof VerificationError && e.reason === r;

  it("round-trips: a signed list is fetched, verified, and its ids checked", async () => {
    const pub = publisher();
    serve(await signRevocationList(pub.signer, [{ id: "urn:uuid:abc" }], { seq: 1 }));

    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did],
    });
    expect(await checker(CRED)).toBe(true);
    expect(await checker({ ...CRED, id: "urn:uuid:other" })).toBe(false);
  });

  it("rejects a list signed by an untrusted publisher (it could hide a revocation)", async () => {
    const pub = publisher();
    const attacker = publisher();
    serve(await signRevocationList(attacker.signer, [], { seq: 99 }));

    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did], // not the attacker
    });
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-untrusted"));
  });

  it("rejects a stale list rather than treating it as 'nothing is revoked'", async () => {
    const pub = publisher();
    // Signed in the past with a window that has already closed.
    const past = Math.floor(Date.now() / 1000) - 7200;
    serve(await signRevocationList(pub.signer, [], { seq: 1, ttlSeconds: 60, now: () => past }));

    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did],
    });
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-stale"));
  });

  it("rejects a list older than the verifier's own tolerance, even if the publisher says it's fresh", async () => {
    const pub = publisher();
    const now = Math.floor(Date.now() / 1000);
    // Publisher promises a 1h window, but issued it 10 minutes ago.
    serve(
      await signRevocationList(pub.signer, [], { seq: 1, ttlSeconds: 3600, now: () => now - 600 }),
    );

    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did],
      maxAgeSeconds: 60,
    });
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-stale"));
  });

  it("rejects a rollback: an older, still-valid list that omits a fresh revocation", async () => {
    const pub = publisher();
    const resolver = createResolver();

    const oldList = await signRevocationList(pub.signer, [], { seq: 1 });
    const newList = await signRevocationList(pub.signer, [{ id: "urn:uuid:abc" }], { seq: 2 });

    // Serve the current list first, so the verifier learns seq=2.
    serve(newList);
    const checker = createUrlRevocationChecker(URL, { resolver, trustedIssuers: [pub.did] });
    expect(await checker(CRED)).toBe(true);

    // An attacker (or a stale mirror) replays seq=1 — cryptographically valid, not yet expired,
    // and missing the revocation. It must not resurrect the credential.
    serve(oldList);
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-rollback"));
  });

  it("rejects a tampered list", async () => {
    const pub = publisher();
    const jwt = await signRevocationList(pub.signer, [{ id: "urn:uuid:abc" }], { seq: 1 });
    const [header, , signature] = jwt.split(".");
    const forged = Buffer.from(
      JSON.stringify({ rzrl: 1, seq: 1, iat: 1, exp: 9e9, revoked: [] }),
    ).toString("base64url");
    serve(`${header}.${forged}.${signature}`);

    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did],
    });
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-invalid"));
  });

  it("fails closed when the list cannot be fetched", async () => {
    const pub = publisher();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 503, statusText: "Service Unavailable" })),
    );
    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did],
    });
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-unavailable"));
  });

  it("refuses an unsigned list served over the network", async () => {
    const pub = publisher();
    serve(JSON.stringify({ revoked: ["urn:uuid:abc"] }));
    const checker = createUrlRevocationChecker(URL, {
      resolver: createResolver(),
      trustedIssuers: [pub.did],
    });
    await expect(checker(CRED)).rejects.toSatisfy(reason("revocation-list-invalid"));
  });
});

describe("pruneExpiredEntries", () => {
  it("drops entries whose credential has expired, keeps the rest (bounds list growth)", () => {
    const now = 1_000_000;
    expect(
      pruneExpiredEntries(
        [
          { id: "expired", expiresAt: now - 1 },
          { id: "live", expiresAt: now + 1 },
          { id: "no-expiry" },
        ],
        now,
      ).map((e) => e.id),
    ).toEqual(["live", "no-expiry"]);
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
