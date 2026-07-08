/**
 * The golden-path demo, runnable end to end and asserted by CI.
 *
 * A real in-process MCP client ↔ server (official SDK, InMemoryTransport) protected by
 * @roguezero/middleware. It walks the whole story: create identities, issue credentials,
 * call a protected tool (allowed), call one policy denies, revoke, and watch the same call
 * get denied — then prints the audit trail. Any wrong outcome exits non-zero.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createDidKey,
  createFileRevocationChecker,
  createInMemoryNonceStore,
  createJsonlAuditSink,
  createPresentation,
  createResolver,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  revokeCredential,
  type CredentialSigner,
  type Policy,
} from "@roguezero/core";
import { createMcpGuard } from "@roguezero/middleware/mcp";
import { credentialIdFromJwt, inspectAuditCommand } from "@roguezero/cli";

const AUDIENCE = "mcp://reports.acme.example";

function step(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}
function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`\n\x1b[31m✗ ASSERTION FAILED:\x1b[0m ${message}`);
    process.exit(1);
  }
}
function textOf(result: { content?: Array<{ type: string; text?: string }> }): string {
  return result.content?.find((c) => c.type === "text")?.text ?? "";
}

async function main(): Promise<void> {
  const work = await mkdtemp(join(tmpdir(), "roguezero-demo-"));
  const auditPath = join(work, "audit.jsonl");
  const revocationPath = join(work, "revocations.json");

  step("1. Create identities (did:key)");
  const controllerKp = createDidKey();
  const agentKp = createDidKey();
  const controller: CredentialSigner = {
    did: controllerKp.did,
    privateKey: controllerKp.privateKey,
  };
  console.log(`   controller (operator): ${controller.did}`);
  console.log(`   agent:                 ${agentKp.did}`);

  step("2. Issue credentials (the controller authorizes the agent)");
  const profileVc = await issueAgentProfileCredential(controller, {
    id: agentKp.did,
    controller: controller.did,
    name: "Quarterly Report Reader",
  });
  const capabilityVc = await issueAgentCapabilityCredential(controller, {
    id: agentKp.did,
    tools: [
      { name: "read_report", scopes: ["reports:read"] },
      { name: "delete_report", scopes: ["reports:delete"] },
    ],
    audience: AUDIENCE,
  });
  const capabilityId = credentialIdFromJwt(capabilityVc);
  console.log("   AgentProfile + AgentCapability issued (read + delete granted).");

  step("3. Stand up a protected MCP tool server");
  // Policy grants read_report only; delete_report is delegated by the capability but denied here.
  const policy: Policy = {
    rules: [{ agent: agentKp.did, tool: "read_report", scopes: ["reports:read"], effect: "allow" }],
  };
  const resolver = createResolver();
  const nonceStore = createInMemoryNonceStore();
  const guard = createMcpGuard({
    audience: AUDIENCE,
    resolver,
    trustedIssuers: [controller.did],
    nonceStore,
    policy,
    auditSink: createJsonlAuditSink(auditPath),
    isRevoked: createFileRevocationChecker(revocationPath),
  });

  const server = new McpServer({ name: "reports", version: "1.0.0" });
  guard.registerChallengeTool(server);
  guard.protect(server, { name: "read_report", description: "Read the quarterly report" }, () => ({
    content: [{ type: "text", text: "Q3 revenue: up and to the right." }],
  }));
  guard.protect(
    server,
    { name: "delete_report", description: "Delete the quarterly report" },
    () => ({
      content: [{ type: "text", text: "(report deleted)" }],
    }),
  );
  console.log("   Tools: read_report, delete_report — each requires a verifiable presentation.");

  const client = new Client({ name: "agent-client", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  // The agent obtains a one-time challenge and builds a presentation bound to it.
  const present = async (): Promise<string> => {
    const raw = await client.callTool({ name: "request_challenge", arguments: {} });
    const challenge = JSON.parse(textOf(raw as never)) as { nonce: string };
    return createPresentation(
      { did: agentKp.did, privateKey: agentKp.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );
  };
  const call = (name: string, presentation: string) =>
    client.callTool({ name, arguments: { presentation } }) as Promise<{
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    }>;

  step("4. Agent calls read_report  → expect ALLOW");
  const allow = await call("read_report", await present());
  console.log(`   → ${allow.isError ? "DENIED" : "ALLOWED"}: ${textOf(allow)}`);
  assert(allow.isError !== true, "read_report should be allowed");

  step("5. Agent calls delete_report  → expect DENY (policy)");
  const policyDeny = await call("delete_report", await present());
  console.log(`   → ${textOf(policyDeny)}`);
  assert(policyDeny.isError === true, "delete_report should be denied by policy");

  step("6. Revoke the capability, then call read_report again  → expect DENY (revoked)");
  await revokeCredential(revocationPath, capabilityId);
  console.log(`   revoked capability ${capabilityId}`);
  const revokedDeny = await call("read_report", await present());
  console.log(`   → ${textOf(revokedDeny)}`);
  assert(revokedDeny.isError === true, "read_report should be denied after revocation");
  assert(textOf(revokedDeny).includes("revoked"), "denial reason should be 'revoked'");

  step("7. The audit trail (every decision, with evidence)");
  console.log(await inspectAuditCommand({ auditPath }));

  await client.close();
  await server.close();
  await rm(work, { recursive: true, force: true });

  console.log("\n\x1b[32m✓ Golden path verified: allowed → policy-denied → revoked-denied.\x1b[0m");
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
