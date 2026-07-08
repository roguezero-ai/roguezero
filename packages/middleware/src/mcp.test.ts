import { describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createDidKey,
  createDidWebDocument,
  createInMemoryAuditSink,
  createInMemoryNonceStore,
  createPresentation,
  createResolver,
  didWebFromHost,
  generateEd25519KeyPair,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  type CredentialSigner,
  type Policy,
  type RevocationChecker,
} from "@roguezero/core";
import { createMcpGuard } from "./mcp.js";

const AUDIENCE = "mcp://reports.acme.example";

interface ChallengeResponse {
  nonce: string;
  audience: string;
  expiresAt: number;
}

function textOf(result: { content?: Array<{ type: string; text?: string }> }): string {
  const block = result.content?.find((c) => c.type === "text");
  return block?.text ?? "";
}

/** Read a JWT VC's id (jti) from its payload without pulling in a JWT dependency. */
function credentialId(jwt: string): string {
  const segment = jwt.split(".")[1] ?? "";
  const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as { jti: string };
  return payload.jti;
}

/** Stand up a protected in-process MCP server + a connected client, plus issued credentials. */
async function harness() {
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
  const capabilityId = credentialId(capabilityVc);

  // Policy permits read_report only; delete_report is granted by the capability but denied here.
  const policy: Policy = {
    rules: [{ agent: agent.did, tool: "read_report", scopes: ["reports:read"], effect: "allow" }],
  };

  const auditSink = createInMemoryAuditSink();
  const nonceStore = createInMemoryNonceStore();
  const revoked = new Set<string>();
  const isRevoked: RevocationChecker = async (c) => !!c.id && revoked.has(c.id);

  const guard = createMcpGuard({
    audience: AUDIENCE,
    resolver,
    trustedIssuers: [orgDid],
    nonceStore,
    policy,
    auditSink,
    isRevoked,
  });

  const server = new McpServer({ name: "reports", version: "0.0.0" });
  guard.registerChallengeTool(server);
  guard.protect(server, { name: "read_report", description: "Read a report" }, () => ({
    content: [{ type: "text", text: "Q3 revenue: up and to the right" }],
  }));
  guard.protect(server, { name: "delete_report", description: "Delete a report" }, () => ({
    content: [{ type: "text", text: "deleted" }],
  }));

  const client = new Client({ name: "agent", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  // The agent obtains a challenge and builds a presentation bound to it.
  const present = async (): Promise<string> => {
    const raw = await client.callTool({ name: "request_challenge", arguments: {} });
    const challenge = JSON.parse(textOf(raw as never)) as ChallengeResponse;
    return createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );
  };

  const call = (name: string, presentation: string) =>
    client.callTool({ name, arguments: { presentation } });

  return { client, auditSink, revoked, capabilityId, present, call };
}

describe("MCP middleware — end-to-end round trip", () => {
  it("allows read_report, denies delete_report (policy), denies after revoke", async () => {
    const h = await harness();

    // 1. Allowed call runs the real tool.
    const allowed = (await h.call("read_report", await h.present())) as {
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    };
    expect(allowed.isError).toBeFalsy();
    expect(textOf(allowed)).toContain("Q3 revenue");

    // 2. Policy denies a granted-but-not-permitted tool.
    const denied = (await h.call("delete_report", await h.present())) as {
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    };
    expect(denied.isError).toBe(true);
    expect(textOf(denied)).toContain("policy:default-deny");

    // 3. Revoke the capability; the same read call is now denied.
    h.revoked.add(h.capabilityId);
    const revokedResult = (await h.call("read_report", await h.present())) as {
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    };
    expect(revokedResult.isError).toBe(true);
    expect(textOf(revokedResult)).toContain("verify:revoked");

    // Audit recorded all three decisions with the right outcomes.
    const decisions = h.auditSink.events.map((e) => `${e.tool}:${e.decision}`);
    expect(decisions).toEqual(["read_report:allow", "delete_report:deny", "read_report:deny"]);
  });

  it("denies a replayed presentation (nonce single-use)", async () => {
    const h = await harness();
    const presentation = await h.present();

    const first = (await h.call("read_report", presentation)) as { isError?: boolean };
    expect(first.isError).toBeFalsy();

    const replay = (await h.call("read_report", presentation)) as {
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    };
    expect(replay.isError).toBe(true);
    expect(textOf(replay)).toContain("verify:nonce-replayed");
  });
});
