/**
 * The real-transport golden path: this orchestrator provisions an agent, spawns the
 * standalone stdio MCP server (server.ts) as an actual child process, and drives it over
 * the real MCP stdio transport — allow → policy-deny → revoke → revoked-deny — then prints
 * the audit trail. Any wrong outcome exits non-zero (CI-enforced).
 *
 * This mirrors a real deployment: the operator provisions the server's trust config
 * (trusted issuer, policy) and the agent holds its own credentials.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  createDidKey,
  createPresentation,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  revokeCredential,
} from "@roguezero/core";
import { credentialIdFromJwt, inspectAuditCommand } from "@roguezero/cli";

const AUDIENCE = "mcp://reports.acme.example";
const here = dirname(fileURLToPath(import.meta.url));

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
  const work = await mkdtemp(join(tmpdir(), "roguezero-stdio-"));
  const auditPath = join(work, "audit.jsonl");
  const revocationPath = join(work, "revocations.json");
  const policyPath = join(work, "policy.json");
  const configPath = join(work, "server-config.json");

  step("1. Provision the agent (operator creates identities + credentials)");
  const controller = createDidKey();
  const agent = createDidKey();
  const controllerSigner = { did: controller.did, privateKey: controller.privateKey };
  const profileVc = await issueAgentProfileCredential(controllerSigner, {
    id: agent.did,
    controller: controller.did,
    name: "Quarterly Report Reader",
  });
  const capabilityVc = await issueAgentCapabilityCredential(controllerSigner, {
    id: agent.did,
    tools: [
      { name: "read_report", scopes: ["reports:read"] },
      { name: "delete_report", scopes: ["reports:delete"] },
    ],
    audience: AUDIENCE,
  });
  const capabilityId = credentialIdFromJwt(capabilityVc);
  console.log(`   agent: ${agent.did}`);

  step("2. Configure the server (trusts the operator; policy allows read_report only)");
  await writeFile(
    policyPath,
    JSON.stringify(
      {
        rules: [
          { agent: agent.did, tool: "read_report", scopes: ["reports:read"], effect: "allow" },
        ],
      },
      null,
      2,
    ),
  );
  await writeFile(revocationPath, JSON.stringify({ revoked: [] }));
  await writeFile(
    configPath,
    JSON.stringify(
      {
        version: 1,
        audience: AUDIENCE,
        trustedIssuers: [controller.did],
        policy: { path: policyPath },
        audit: { sink: "file", path: auditPath },
        revocation: { source: "file", path: revocationPath },
      },
      null,
      2,
    ),
  );

  step("3. Spawn the protected MCP server as a real subprocess (stdio)");
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) env[k] = v;
  env.RZ_CONFIG = configPath;
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(here, "server.js")],
    env,
  });
  const client = new Client({ name: "agent-client", version: "1.0.0" });
  await client.connect(transport);
  console.log("   connected over stdio.");

  const present = async (): Promise<string> => {
    const raw = await client.callTool({ name: "request_challenge", arguments: {} });
    const challenge = JSON.parse(textOf(raw as never)) as { nonce: string };
    return createPresentation(
      { did: agent.did, privateKey: agent.privateKey },
      { profileVc, capabilityVc },
      { challenge: challenge.nonce, audience: AUDIENCE },
    );
  };
  const call = (name: string, presentation: string) =>
    client.callTool({ name, arguments: { presentation } }) as Promise<{
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    }>;

  step("4. read_report  → expect ALLOW");
  const allow = await call("read_report", await present());
  console.log(`   → ${allow.isError ? "DENIED" : "ALLOWED"}: ${textOf(allow)}`);
  assert(allow.isError !== true, "read_report should be allowed");

  step("5. delete_report  → expect DENY (policy)");
  const policyDeny = await call("delete_report", await present());
  console.log(`   → ${textOf(policyDeny)}`);
  assert(policyDeny.isError === true, "delete_report should be denied by policy");

  step("6. Revoke, then read_report again  → expect DENY (revoked)");
  await revokeCredential(revocationPath, capabilityId);
  const revokedDeny = await call("read_report", await present());
  console.log(`   → ${textOf(revokedDeny)}`);
  assert(revokedDeny.isError === true, "read_report should be denied after revocation");
  assert(textOf(revokedDeny).includes("revoked"), "denial reason should be 'revoked'");

  step("7. Audit trail");
  console.log(await inspectAuditCommand({ auditPath }));

  await client.close();
  await rm(work, { recursive: true, force: true });
  console.log("\n\x1b[32m✓ Real stdio transport: allowed → policy-denied → revoked-denied.\x1b[0m");
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
