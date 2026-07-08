import { describe, expect, it } from "vitest";
import { VerificationError } from "./errors.js";
import type { VerificationFailureReason } from "./types.js";
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
import { verifyRequest, type RevocationChecker } from "./verify.js";

const AUDIENCE = "mcp://reports.acme.example";

/** A complete, valid golden-path scenario; individual tests override one piece. */
async function scenario() {
  const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
  const orgDid = didWebFromHost("acme.example");
  const resolver = createResolver({
    localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
  });
  const org: CredentialSigner = { did: orgDid, privateKey: orgPriv };
  const agent = createDidKey();
  const agentSigner: CredentialSigner = { did: agent.did, privateKey: agent.privateKey };

  const profileVc = await issueAgentProfileCredential(org, {
    id: agent.did,
    controller: orgDid,
    name: "Reporter",
  });
  const capabilityVc = await issueAgentCapabilityCredential(org, {
    id: agent.did,
    tools: [{ name: "read_report", scopes: ["reports:read"] }],
    audience: AUDIENCE,
  });

  const nonceStore = createInMemoryNonceStore();
  const challenge = await nonceStore.issue(AUDIENCE);
  const presentation = await createPresentation(
    agentSigner,
    { profileVc, capabilityVc },
    { challenge: challenge.nonce, audience: AUDIENCE },
  );

  return {
    orgDid,
    org,
    agent,
    agentSigner,
    resolver,
    nonceStore,
    presentation,
    profileVc,
    capabilityVc,
  };
}

/**
 * Corrupt a JWT signature by mutating the first character of the signature segment. The
 * first base64url char is fully significant, so the decoded signature bytes are guaranteed
 * to change — unlike the last char of a 64-byte Ed25519 signature, whose low bits are unused
 * padding and can flip without altering the bytes.
 */
function tamperSignature(jwt: string): string {
  const [header, payload, signature] = jwt.split(".");
  const firstChar = signature?.[0];
  const swapped = firstChar === "A" ? "B" : "A";
  return `${header}.${payload}.${swapped}${signature?.slice(1)}`;
}

/** Assert a promise rejects with a VerificationError of a specific reason. */
async function expectReason(promise: Promise<unknown>, reason: VerificationFailureReason) {
  await expect(promise).rejects.toSatisfy(
    (e: unknown) => e instanceof VerificationError && e.reason === reason,
  );
}

describe("verifyRequest — golden path", () => {
  it("allows a valid presentation and returns the grant", async () => {
    const s = await scenario();
    const result = await verifyRequest({
      presentation: s.presentation,
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
    });

    expect(result.agent).toBe(s.agent.did);
    expect(result.controller).toBe(s.orgDid);
    expect(result.issuer).toBe(s.orgDid);
    expect(result.tools[0]?.name).toBe("read_report");
    expect(result.audience).toBe(AUDIENCE);
    expect(result.evidence.capabilityVc).toMatch(/^sha256:/);
    expect(result.evidence.profileVc).toMatch(/^sha256:/);
  });
});

describe("verifyRequest — replay and audience binding", () => {
  it("rejects a replayed presentation (nonce single-use)", async () => {
    const s = await scenario();
    const opts = {
      presentation: s.presentation,
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
    };
    await verifyRequest(opts); // first use consumes the nonce
    await expectReason(verifyRequest(opts), "nonce-replayed");
  });

  it("rejects a forged/unknown nonce", async () => {
    const s = await scenario();
    const forged = await createPresentation(
      s.agentSigner,
      { profileVc: s.profileVc, capabilityVc: s.capabilityVc },
      { challenge: "never-issued", audience: AUDIENCE },
    );
    await expectReason(
      verifyRequest({
        presentation: forged,
        audience: AUDIENCE,
        resolver: s.resolver,
        trustedIssuers: [s.orgDid],
        nonceStore: s.nonceStore,
      }),
      "nonce-invalid",
    );
  });

  it("rejects a presentation bound to a different audience (no cross-tool replay)", async () => {
    const s = await scenario();
    // Presentation was minted for AUDIENCE; verify it at a different tool.
    await expectReason(
      verifyRequest({
        presentation: s.presentation,
        audience: "mcp://other.acme.example",
        resolver: s.resolver,
        trustedIssuers: [s.orgDid],
        nonceStore: s.nonceStore,
      }),
      "audience-mismatch",
    );
  });
});

describe("verifyRequest — issuer trust and binding", () => {
  it("rejects an issuer not on the allowlist", async () => {
    const s = await scenario();
    await expectReason(
      verifyRequest({
        presentation: s.presentation,
        audience: AUDIENCE,
        resolver: s.resolver,
        trustedIssuers: ["did:web:evil.example"],
        nonceStore: s.nonceStore,
      }),
      "untrusted-issuer",
    );
  });

  it("rejects a capability presented by an agent it was not issued to (confused deputy)", async () => {
    const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
    const orgDid = didWebFromHost("acme.example");
    const resolver = createResolver({
      localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
    });
    const org: CredentialSigner = { did: orgDid, privateKey: orgPriv };
    const agent = createDidKey();
    const victim = createDidKey();

    const profileVc = await issueAgentProfileCredential(org, {
      id: agent.did,
      controller: orgDid,
      name: "Reporter",
    });
    // Capability was granted to the victim, not to the presenting agent.
    const capabilityVc = await issueAgentCapabilityCredential(org, {
      id: victim.did,
      tools: [{ name: "read_report", scopes: ["reports:read"] }],
      audience: AUDIENCE,
    });

    const nonceStore = createInMemoryNonceStore();
    const challenge = await nonceStore.issue(AUDIENCE);
    const presentation = await createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );

    await expectReason(
      verifyRequest({
        presentation,
        audience: AUDIENCE,
        resolver,
        trustedIssuers: [orgDid],
        nonceStore,
      }),
      "holder-mismatch",
    );
  });

  it("rejects a profile whose issuer is not the declared controller", async () => {
    const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
    const orgDid = didWebFromHost("acme.example");
    const resolver = createResolver({
      localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
    });
    const org: CredentialSigner = { did: orgDid, privateKey: orgPriv };
    const agent = createDidKey();

    // Profile claims a controller different from its actual issuer (org).
    const profileVc = await issueAgentProfileCredential(org, {
      id: agent.did,
      controller: "did:web:someone-else.example",
      name: "Reporter",
    });
    const capabilityVc = await issueAgentCapabilityCredential(org, {
      id: agent.did,
      tools: [{ name: "read_report", scopes: ["reports:read"] }],
      audience: AUDIENCE,
    });

    const nonceStore = createInMemoryNonceStore();
    const challenge = await nonceStore.issue(AUDIENCE);
    const presentation = await createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );

    await expectReason(
      verifyRequest({
        presentation,
        audience: AUDIENCE,
        resolver,
        trustedIssuers: [orgDid, "did:web:someone-else.example"],
        nonceStore,
      }),
      "untrusted-issuer",
    );
  });
});

describe("verifyRequest — capability scope, revocation, integrity", () => {
  it("rejects a capability scoped to a different audience", async () => {
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
      audience: "mcp://a-different-tool.example",
    });

    const nonceStore = createInMemoryNonceStore();
    const challenge = await nonceStore.issue(AUDIENCE);
    const presentation = await createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );

    await expectReason(
      verifyRequest({
        presentation,
        audience: AUDIENCE,
        resolver,
        trustedIssuers: [orgDid],
        nonceStore,
      }),
      "audience-mismatch",
    );
  });

  it("rejects a revoked credential", async () => {
    const s = await scenario();
    const alwaysRevoked: RevocationChecker = async () => true;
    await expectReason(
      verifyRequest({
        presentation: s.presentation,
        audience: AUDIENCE,
        resolver: s.resolver,
        trustedIssuers: [s.orgDid],
        nonceStore: s.nonceStore,
        isRevoked: alwaysRevoked,
      }),
      "revoked",
    );
  });

  it("rejects a tampered presentation signature", async () => {
    const s = await scenario();
    const tampered = tamperSignature(s.presentation);
    await expectReason(
      verifyRequest({
        presentation: tampered,
        audience: AUDIENCE,
        resolver: s.resolver,
        trustedIssuers: [s.orgDid],
        nonceStore: s.nonceStore,
      }),
      "bad-signature",
    );
  });

  it("rejects an expired embedded capability", async () => {
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
    const capabilityVc = await issueAgentCapabilityCredential(
      org,
      {
        id: agent.did,
        tools: [{ name: "read_report", scopes: ["reports:read"] }],
        audience: AUDIENCE,
      },
      { issuedAt: Math.floor(Date.now() / 1000) - 4000, expiresInSeconds: 60 },
    );

    const nonceStore = createInMemoryNonceStore();
    const challenge = await nonceStore.issue(AUDIENCE);
    const presentation = await createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );

    await expectReason(
      verifyRequest({
        presentation,
        audience: AUDIENCE,
        resolver,
        trustedIssuers: [orgDid],
        nonceStore,
      }),
      "expired",
    );
  });
});
