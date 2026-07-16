import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { type AddressInfo } from "node:net";
import { handleToolCall } from "./runtime.js";
import { createInMemoryAuditSink } from "./audit.js";
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
import { parseToolRegistry, type ToolRegistry } from "./registry.js";
import { createVault, localKeyProvider, putCredential, type Vault } from "./vault.js";
import { neverRevoked } from "./verify.js";

const AUDIENCE = "runtime://acme";
const SECRET = "ghp_live_SECRET_TOKEN";

// The downstream "tool": records the Authorization header it received and how often it was hit.
let server: Server;
let port = 0;
let hits = 0;
let lastAuth: string | undefined;

beforeAll(async () => {
  server = createServer((req, res) => {
    hits += 1;
    lastAuth = req.headers.authorization;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  hits = 0;
  lastAuth = undefined;
});

/** A full scenario: an agent granted tool "gh", a registry pointing "gh" at the local server, and a
 *  vault holding "gh"'s bearer token. `call()` runs the whole spine. */
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
    name: "Agent",
  });
  const capabilityVc = await issueAgentCapabilityCredential(org, {
    id: agent.did,
    tools: [{ name: "gh", scopes: ["gh:call"] }],
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

  const policy: Policy = {
    rules: [{ agent: agent.did, tool: "gh", scopes: ["gh:call"], effect: "allow" }],
  };

  const registry: ToolRegistry = parseToolRegistry({
    tools: [
      {
        id: "gh",
        method: "GET",
        scheme: "http",
        host: "127.0.0.1",
        port,
        path: "/echo",
        internal: true, // loopback is only reachable because we say so
        credential: { ref: "gh-token", placement: "bearer" },
      },
    ],
  });

  const vault: Vault = await createVault(localKeyProvider(new Uint8Array(32).fill(9)));
  await putCredential(vault, { ref: "gh-token", toolId: "gh", value: SECRET });

  return { agent, orgDid, resolver, nonceStore, policy, registry, vault, present };
}

describe("handleToolCall — the runtime spine", () => {
  it("authorizes, injects the credential server-side, and the agent never holds it", async () => {
    const s = await scenario();
    const result = await handleToolCall({
      presentation: await s.present(),
      tool: "gh",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink: createInMemoryAuditSink(),
      isRevoked: neverRevoked,
      registry: s.registry,
      vault: s.vault,
    });

    expect(result.ok).toBe(true);
    expect(result.decision).toBe("allow");
    expect(result.response?.status).toBe(200);
    // The downstream saw the real token; the agent's presentation never contained it.
    expect(hits).toBe(1);
    expect(lastAuth).toBe(`Bearer ${SECRET}`);
  });

  it("D0: a revoked call is denied and NEVER contacts the downstream (decrypt is last)", async () => {
    const s = await scenario();
    const result = await handleToolCall({
      presentation: await s.present(),
      tool: "gh",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink: createInMemoryAuditSink(),
      isRevoked: async () => true, // killed
      registry: s.registry,
      vault: s.vault,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("verify:revoked");
    expect(result.ok).toBe(false);
    // The credential was never decrypted and the tool was never called.
    expect(hits).toBe(0);
  });

  it("records what the agent TRIED on a revoked call — and never the token", async () => {
    const s = await scenario();
    const audit = createInMemoryAuditSink();
    const attemptedArgs = { title: "hello from my agent", body: "please fix this" };
    const result = await handleToolCall({
      presentation: await s.present(),
      tool: "gh",
      args: attemptedArgs,
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink: audit,
      isRevoked: async () => true, // killed
      registry: s.registry,
      vault: s.vault,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("verify:revoked");
    // The audit shows exactly what was blocked — the message the agent tried to send.
    const denied = audit.events.find((e) => e.decision === "deny");
    expect(denied?.attempt?.args).toEqual(attemptedArgs);
    // Vera's invariant: capturing more must never capture the credential. It is decrypted after
    // authorization, so a denied call has no token — and it appears nowhere in the log.
    expect(hits).toBe(0);
    expect(JSON.stringify(audit.events)).not.toContain(SECRET);
  });

  it("records the resolved TARGET actually dispatched on an allowed call — never the token", async () => {
    const s = await scenario();
    const audit = createInMemoryAuditSink();
    const result = await handleToolCall({
      presentation: await s.present(),
      tool: "gh",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink: audit,
      isRevoked: neverRevoked,
      registry: s.registry,
      vault: s.vault,
    });

    expect(result.ok).toBe(true);
    // The executed outcome names the exact request the runtime sent downstream.
    const executed = audit.events.find((e) => e.reason.startsWith("executed:"));
    expect(executed?.attempt?.target).toEqual({
      method: "GET",
      url: `http://127.0.0.1:${port}/echo`,
    });
    // The real bearer token went to the downstream, but never into the audit.
    expect(lastAuth).toBe(`Bearer ${SECRET}`);
    expect(JSON.stringify(audit.events)).not.toContain(SECRET);
  });

  it("denies a tool the capability does not grant, without dispatching", async () => {
    const s = await scenario();
    const result = await handleToolCall({
      presentation: await s.present(),
      tool: "wipe",
      audience: AUDIENCE,
      resolver: s.resolver,
      trustedIssuers: [s.orgDid],
      nonceStore: s.nonceStore,
      policy: s.policy,
      auditSink: createInMemoryAuditSink(),
      isRevoked: neverRevoked,
      registry: s.registry,
      vault: s.vault,
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("capability:tool-not-granted");
    expect(hits).toBe(0);
  });
});
