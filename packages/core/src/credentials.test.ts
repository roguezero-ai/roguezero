import { describe, expect, it } from "vitest";
import { createVerifiableCredentialJwt } from "did-jwt-vc";
import { ed25519 } from "@noble/curves/ed25519";
import type { Signer } from "did-jwt";
import { VerificationError } from "./errors.js";
import {
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  verifyAgentCapabilityCredential,
  verifyAgentProfileCredential,
  type CredentialSigner,
} from "./credentials.js";
import { createDidKey, generateEd25519KeyPair } from "./identity.js";
import { createDidWebDocument, didWebFromHost } from "./did-web.js";
import { createResolver } from "./resolver.js";

/** An org identity backed by did:web, resolvable through a local (no-domain) resolver. */
function makeWebOrg(host = "acme.example") {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const did = didWebFromHost(host);
  const document = createDidWebDocument(did, publicKey);
  const resolver = createResolver({ localDidWebDocuments: { [did]: document } });
  const signer: CredentialSigner = { did, privateKey };
  return { did, signer, resolver };
}

describe("AgentProfile credential (did:key issuer)", () => {
  it("issues and verifies, recovering issuer and subject", async () => {
    const controller = createDidKey();
    const agent = createDidKey();
    const resolver = createResolver();
    const signer: CredentialSigner = { did: controller.did, privateKey: controller.privateKey };

    const jwt = await issueAgentProfileCredential(signer, {
      id: agent.did,
      controller: controller.did,
      name: "Report Reader",
      description: "Reads quarterly reports",
    });

    const verified = await verifyAgentProfileCredential(jwt, resolver);
    expect(verified.issuer).toBe(controller.did);
    expect(verified.subject.id).toBe(agent.did);
    expect(verified.subject.controller).toBe(controller.did);
    expect(verified.subject.name).toBe("Report Reader");
    expect(verified.expiresAt).toBeGreaterThan(verified.issuedAt ?? 0);
  });
});

describe("AgentCapability credential (did:web issuer)", () => {
  it("issues from a did:web org and verifies through the generated document", async () => {
    const org = makeWebOrg();
    const agent = createDidKey();

    const jwt = await issueAgentCapabilityCredential(org.signer, {
      id: agent.did,
      tools: [{ name: "read_report", scopes: ["reports:read"] }],
      audience: "mcp://reports.acme.example",
    });

    const verified = await verifyAgentCapabilityCredential(jwt, org.resolver);
    expect(verified.issuer).toBe(org.did);
    expect(verified.subject.id).toBe(agent.did);
    expect(verified.subject.tools[0]?.name).toBe("read_report");
    expect(verified.subject.audience).toBe("mcp://reports.acme.example");
  });
});

describe("verification — negative cases", () => {
  it("rejects a tampered signature (bad-signature)", async () => {
    const controller = createDidKey();
    const agent = createDidKey();
    const resolver = createResolver();
    const jwt = await issueAgentProfileCredential(
      { did: controller.did, privateKey: controller.privateKey },
      { id: agent.did, controller: controller.did, name: "Tamper Target" },
    );

    // Corrupt the first (fully significant) character of the signature segment. Flipping the
    // last char is unreliable: the low bits of a 64-byte Ed25519 signature's final base64url
    // char are unused padding and can change without altering the decoded bytes.
    const [header, payload, signature] = jwt.split(".");
    const swapped = signature?.[0] === "A" ? "B" : "A";
    const tampered = `${header}.${payload}.${swapped}${signature?.slice(1)}`;

    await expect(verifyAgentProfileCredential(tampered, resolver)).rejects.toMatchObject({
      name: "VerificationError",
    });
  });

  it("rejects an expired credential (expired)", async () => {
    const org = makeWebOrg();
    const agent = createDidKey();
    // Issued well in the past, already expired beyond clock-skew tolerance.
    const jwt = await issueAgentCapabilityCredential(
      org.signer,
      {
        id: agent.did,
        tools: [{ name: "read_report", scopes: ["reports:read"] }],
        audience: "mcp://reports.acme.example",
      },
      { issuedAt: Math.floor(Date.now() / 1000) - 4000, expiresInSeconds: 60 },
    );

    await expect(verifyAgentCapabilityCredential(jwt, org.resolver)).rejects.toSatisfy(
      (e: unknown) => e instanceof VerificationError && e.reason === "expired",
    );
  });

  it("rejects the wrong credential type (malformed-credential)", async () => {
    const controller = createDidKey();
    const agent = createDidKey();
    const resolver = createResolver();
    const profileJwt = await issueAgentProfileCredential(
      { did: controller.did, privateKey: controller.privateKey },
      { id: agent.did, controller: controller.did, name: "Not A Capability" },
    );

    await expect(verifyAgentCapabilityCredential(profileJwt, resolver)).rejects.toSatisfy(
      (e: unknown) => e instanceof VerificationError && e.reason === "malformed-credential",
    );
  });

  it("rejects a capability with an invalid subject at verify time", async () => {
    // Craft a capability-typed VC with an empty tools array, bypassing our issue-time
    // validation, to prove verify independently enforces the subject schema.
    const org = makeWebOrg();
    const agent = createDidKey();
    const signer: Signer = async (data) => {
      const msg = typeof data === "string" ? new TextEncoder().encode(data) : data;
      return Buffer.from(ed25519.sign(msg, org.signer.privateKey)).toString("base64url");
    };
    const now = Math.floor(Date.now() / 1000);
    const badJwt = await createVerifiableCredentialJwt(
      {
        sub: agent.did,
        nbf: now,
        exp: now + 600,
        vc: {
          "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: ["VerifiableCredential", "AgentCapability"],
          credentialSubject: { id: agent.did, tools: [], audience: "mcp://x" },
        },
      },
      { did: org.did, alg: "EdDSA", signer },
    );

    await expect(verifyAgentCapabilityCredential(badJwt, org.resolver)).rejects.toSatisfy(
      (e: unknown) => e instanceof VerificationError && e.reason === "malformed-credential",
    );
  });
});

describe("issuance — subject validation", () => {
  it("refuses to issue a capability with no tools", async () => {
    const org = makeWebOrg();
    const agent = createDidKey();
    await expect(
      issueAgentCapabilityCredential(org.signer, {
        id: agent.did,
        tools: [],
        audience: "mcp://reports.acme.example",
      }),
    ).rejects.toThrow();
  });
});

describe("clock-skew tolerance (tight, in seconds)", () => {
  const now = () => Math.floor(Date.now() / 1000);

  it("accepts a credential expired within the skew window", async () => {
    const org = makeWebOrg();
    const agent = createDidKey();
    // Expired 10s ago; within the 30s skew it must still verify (proves skew is seconds,
    // not milliseconds — 10s would fail a sub-second window).
    const jwt = await issueAgentProfileCredential(
      org.signer,
      { id: agent.did, controller: org.did, name: "Edge" },
      { issuedAt: now() - 3610, expiresInSeconds: 3600 },
    );
    const verified = await verifyAgentProfileCredential(jwt, org.resolver);
    expect(verified.subject.name).toBe("Edge");
  });

  it("rejects a credential expired beyond the skew window", async () => {
    const org = makeWebOrg();
    const agent = createDidKey();
    // Expired ~120s ago; beyond the 30s skew, and far below did-jwt's loose 300s default.
    const jwt = await issueAgentProfileCredential(
      org.signer,
      { id: agent.did, controller: org.did, name: "Stale" },
      { issuedAt: now() - 3720, expiresInSeconds: 3600 },
    );
    await expect(verifyAgentProfileCredential(jwt, org.resolver)).rejects.toSatisfy(
      (e: unknown) => e instanceof VerificationError && e.reason === "expired",
    );
  });
});
