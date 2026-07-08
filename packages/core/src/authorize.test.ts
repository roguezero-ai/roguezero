import { describe, expect, it } from "vitest";
import { authorizeToolCall } from "./authorize.js";
import { createInMemoryAuditSink, type AuditSink } from "./audit.js";
import {
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  type CredentialSigner,
} from "./credentials.js";
import { createDidWebDocument, didWebFromHost } from "./did-web.js";
import { createDidKey, generateEd25519KeyPair } from "./identity.js";
import { createInMemoryNonceStore } from "./nonce.js";
import type { Policy } from "./policy.js";
import { createPresentation } from "./presentation.js";
import { createResolver } from "./resolver.js";

const AUDIENCE = "mcp://reports.acme.example";

/** A scenario with a two-tool capability (read + delete) and a fresh-presentation helper. */
async function scenario() {
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
    tools: [
      { name: "read_report", scopes: ["reports:read"] },
      { name: "delete_report", scopes: ["reports:delete"] },
    ],
    audience: AUDIENCE,
  });

  const nonceStore = createInMemoryNonceStore();
  const present = async () => {
    const challenge = await nonceStore.issue(AUDIENCE);
    return createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );
  };

  // Policy allows only read_report; delete_report is granted by the capability but denied here.
  const policy: Policy = {
    rules: [{ agent: agent.did, tool: "read_report", scopes: ["reports:read"], effect: "allow" }],
  };

  return { orgDid, agent, resolver, nonceStore, policy, present };
}

describe("authorizeToolCall", () => {
  it("allows a call the capability grants and policy permits, auditing allow", async () => {
    const s = await scenario();
    const auditSink = createInMemoryAuditSink();
    const result = await authorizeToolCall({
      presentation: await s.present(),
      tool: "read_report",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink,
    });

    expect(result.decision).toBe("allow");
    expect(result.request?.agent).toBe(s.agent.did);
    expect(auditSink.events).toHaveLength(1);
    expect(auditSink.events[0]?.decision).toBe("allow");
    expect(auditSink.events[0]?.actor).toBe(s.agent.did);
    expect(auditSink.events[0]?.correlationId).toBe(result.correlationId);
  });

  it("denies (policy) a granted tool the policy does not permit, auditing deny", async () => {
    const s = await scenario();
    const auditSink = createInMemoryAuditSink();
    const result = await authorizeToolCall({
      presentation: await s.present(),
      tool: "delete_report",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("policy:default-deny");
    expect(result.request).toBeUndefined();
    expect(auditSink.events).toHaveLength(1);
    expect(auditSink.events[0]?.decision).toBe("deny");
  });

  it("denies a tool the capability does not grant at all", async () => {
    const s = await scenario();
    const auditSink = createInMemoryAuditSink();
    const result = await authorizeToolCall({
      presentation: await s.present(),
      tool: "wipe_everything",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("capability:tool-not-granted");
    expect(auditSink.events[0]?.reason).toBe("capability:tool-not-granted");
  });

  it("denies and audits a verification failure without leaking an actor", async () => {
    const s = await scenario();
    const auditSink = createInMemoryAuditSink();
    const result = await authorizeToolCall({
      presentation: await s.present(),
      tool: "read_report",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: ["did:web:evil.example"], // real issuer not trusted
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("verify:untrusted-issuer");
    expect(auditSink.events).toHaveLength(1);
    expect(auditSink.events[0]?.actor).toBe("unknown");
    // Attempted-presentation hash is recorded so repeated attempts are correlatable.
    expect(auditSink.events[0]?.evidence.presentation).toMatch(/^sha256:/);
  });

  it("names the agent on a revoked denial (H12 — not 'unknown')", async () => {
    const s = await scenario();
    const auditSink = createInMemoryAuditSink();
    const result = await authorizeToolCall({
      presentation: await s.present(),
      tool: "read_report",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink,
      isRevoked: async () => true,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("verify:revoked");
    // The credential passed binding before revocation failed it, so the actor is known.
    const event = auditSink.events[0];
    expect(event?.actor).toBe(s.agent.did);
    expect(event?.subject).toBe(s.orgDid);
    expect(event?.evidence.capabilityVc).toMatch(/^sha256:/);
  });

  it("denies with audit-write-failed when the sink fails (audit is load-bearing)", async () => {
    const s = await scenario();
    const failingSink: AuditSink = {
      write: async () => {
        throw new Error("audit sink is down");
      },
    };
    const result = await authorizeToolCall({
      presentation: await s.present(),
      tool: "read_report",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink: failingSink,
    });

    // An otherwise-allowable call must NOT proceed if it can't be audited.
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("audit-write-failed");
    expect(result.request).toBeUndefined();
  });
});
