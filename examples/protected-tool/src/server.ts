/**
 * A standalone, RogueZero-protected MCP server that speaks the real stdio transport — the
 * shape a partner actually deploys and points an agent (or any MCP client) at. This is the
 * template to copy: wrap your own tools with `guard.protect(...)`.
 *
 * Config comes from a JSON file named by the RZ_CONFIG env var, so the deployment's trust
 * settings (audience, trusted issuers, policy, audit + revocation paths) live outside the
 * code. Everything human-facing goes to stderr — stdout is the MCP channel.
 */

import { readFile } from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createFileRevocationChecker,
  createInMemoryNonceStore,
  createJsonlAuditSink,
  createResolver,
  loadPolicyFromFile,
} from "@roguezero/core";
import { createMcpGuard } from "@roguezero/middleware/mcp";

interface ServerConfig {
  audience: string;
  trustedIssuers: string[];
  policyPath: string;
  auditPath: string;
  revocationPath: string;
}

async function main(): Promise<void> {
  const configPath = process.env.RZ_CONFIG;
  if (!configPath) throw new Error("RZ_CONFIG (path to server config JSON) is required");
  const config = JSON.parse(await readFile(configPath, "utf8")) as ServerConfig;

  const guard = createMcpGuard({
    audience: config.audience,
    resolver: createResolver(),
    trustedIssuers: config.trustedIssuers,
    nonceStore: createInMemoryNonceStore(),
    policy: await loadPolicyFromFile(config.policyPath),
    auditSink: createJsonlAuditSink(config.auditPath),
    isRevoked: createFileRevocationChecker(config.revocationPath),
  });

  const server = new McpServer({ name: "reports", version: "1.0.0" });

  // The unprotected tool an agent calls first to get a one-time challenge.
  guard.registerChallengeTool(server);

  // Your tools — each requires a verifiable presentation before its handler runs.
  guard.protect(server, { name: "read_report", description: "Read the quarterly report" }, () => ({
    content: [{ type: "text", text: "Q3 revenue: up and to the right." }],
  }));
  guard.protect(
    server,
    { name: "delete_report", description: "Delete the quarterly report" },
    () => ({ content: [{ type: "text", text: "(report deleted)" }] }),
  );

  await server.connect(new StdioServerTransport());
  process.stderr.write("[reports] RogueZero-protected MCP server ready on stdio\n");
}

main().catch((error: unknown) => {
  process.stderr.write(
    `[reports] fatal: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
