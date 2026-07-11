/**
 * The plug-and-play golden path: an ordinary MCP client, containing **zero** RogueZero code,
 * talks to a RogueZero-protected server through `roguezero connect`.
 *
 * Everything below the `--- agent side ---` marker is what a customer's agent looks like: an
 * MCP client, a server command, `callTool`. No challenge, no presentation, no keys. The proxy
 * holds the bundle and mints a fresh presentation per call.
 *
 * This is what CI enforces: allow → denied-because-not-granted → revoke → denied-because-revoked,
 * with the agent never once mentioning RogueZero. Any wrong outcome exits non-zero.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { initCommand, onboardCommand, parseToolSpec, revokeCommand } from "@roguezero/cli";
import { inspectAuditCommand } from "@roguezero/cli";
import { loadGuardConfig, writableRevocationPath } from "@roguezero/core";

const AUDIENCE = "mcp://reports.acme.example";
const here = dirname(fileURLToPath(import.meta.url));
const CLI_BIN = join(here, "../../../packages/cli/dist/bin.js");
const SERVER = join(here, "server.js");

function step(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}
function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    console.error(`\n\x1b[31m✗ ASSERTION FAILED:\x1b[0m ${message}`);
    process.exit(1);
  }
}
function textOf(result: { content?: Array<{ type: string; text?: string }> }): string {
  return result.content?.find((c) => c.type === "text")?.text ?? "";
}

async function main(): Promise<void> {
  const work = await mkdtemp(join(tmpdir(), "roguezero-connect-"));

  step("1. roguezero init  (controller + config + deny-everything policy)");
  const { configPath, controllerPath } = await initCommand({ dir: work, audience: AUDIENCE });
  console.log(`   config: ${configPath}`);

  step("2. roguezero onboard reporter --tool read_report=reports:read");
  const { bundlePath, agentDid } = await onboardCommand({
    name: "reporter",
    configPath,
    controllerPath,
    tools: [parseToolSpec("read_report=reports:read")],
  });
  console.log(`   agent:  ${agentDid}`);
  console.log(`   bundle: ${bundlePath}`);
  console.log(`   note:   delete_report was never granted.`);

  // --- agent side -------------------------------------------------------------------
  // A stock MCP client. It spawns `roguezero connect`, which spawns the protected server.
  // Nothing below knows what a presentation is.

  step("3. Agent connects — through `roguezero connect`, not to the server directly");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      CLI_BIN,
      "connect",
      "--agent",
      "reporter",
      "--config",
      configPath,
      "--",
      process.execPath,
      SERVER,
    ],
    env: { ...(process.env as Record<string, string>), RZ_CONFIG: configPath },
    stderr: "inherit",
  });
  const client = new Client({ name: "some-agent", version: "1.0.0" });
  await client.connect(transport);

  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  console.log(`   tools visible to the agent: ${names.join(", ")}`);
  assert(!names.includes("request_challenge"), "the challenge tool must stay hidden");
  const readTool = tools.find((t) => t.name === "read_report");
  const props = Object.keys(
    (readTool?.inputSchema as { properties?: Record<string, unknown> })?.properties ?? {},
  );
  assert(!props.includes("presentation"), "`presentation` must not leak into the tool schema");
  console.log(`   read_report args: [${props.join(", ")}]  ← no "presentation"`);

  const call = (name: string) =>
    client.callTool({ name, arguments: {} }) as Promise<{
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    }>;

  step("4. read_report  → expect ALLOW  (agent wrote no crypto)");
  const allow = await call("read_report");
  console.log(`   → ${allow.isError ? "DENIED" : "ALLOWED"}: ${textOf(allow)}`);
  assert(allow.isError !== true, "read_report should be allowed");

  step("5. delete_report  → expect DENY  (never delegated)");
  const denied = await call("delete_report");
  console.log(`   → ${textOf(denied)}`);
  assert(denied.isError === true, "delete_report should be denied");
  assert(
    textOf(denied).includes("tool-not-granted"),
    "denial should name the capability, not policy",
  );

  step("6. roguezero revoke --agent reporter   (server keeps running)");
  const config = await loadGuardConfig(configPath);
  const listPath = writableRevocationPath(config);
  assert(listPath !== undefined, "this demo uses a local revocation list");
  const { revokedId } = await revokeCommand({ listPath, bundlePath });
  console.log(`   revoked ${revokedId}`);

  step("7. read_report again  → expect DENY (revoked), same session");
  const revoked = await call("read_report");
  console.log(`   → ${textOf(revoked)}`);
  assert(revoked.isError === true, "read_report should be denied after revocation");
  assert(textOf(revoked).includes("revoked"), "denial reason should be 'revoked'");

  step("8. Audit trail");
  assert(config.audit.sink === "file", "this demo writes audit events to a file");
  console.log(await inspectAuditCommand({ auditPath: config.audit.path }));

  await client.close();
  await rm(work, { recursive: true, force: true });
  console.log(
    "\n\x1b[32m✓ Unmodified MCP client: allowed → not-granted → revoked. Zero agent-side code.\x1b[0m",
  );
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
