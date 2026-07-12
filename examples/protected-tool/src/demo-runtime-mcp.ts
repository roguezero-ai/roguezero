/**
 * The plug-and-play tool runtime: an **unmodified MCP client** (zero RogueZero code) calls a real
 * HTTP tool through `roguezero connect` → `roguezero runtime mcp`, and **never holds the tool's
 * credential**. This is the "point your agent at it, it can use your tools, it never has the keys,
 * revoke it and it dies — all self-hosted" story, end to end over real stdio.
 *
 * Everything below `--- agent side ---` is a stock MCP client. `connect` mints the presentation; the
 * runtime authenticates the agent, injects the vaulted credential server-side, calls the tool, and
 * audits it. Revocation lands on the next call, before the credential is even decrypted.
 *
 * CI-enforces the claim: the agent sees only its tool (no challenge tool, no presentation arg), the
 * call is allowed with the token injected, and after revoke it is denied. Any wrong outcome exits 1.
 */

import { createServer } from "node:http";
import { type AddressInfo } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  inspectAuditCommand,
  onboardCommand,
  parseToolSpec,
  revokeCommand,
  runtimeInitCommand,
  secretSetCommand,
  toolAddCommand,
} from "@roguezero/cli";

const AUDIENCE = "runtime://acme";
const TOKEN = "ghp_DEMO_the_agent_never_sees_this";
const PASS = "demo-passphrase";
const here = dirname(fileURLToPath(import.meta.url));
const CLI_BIN = join(here, "../../../packages/cli/dist/bin.js");

function step(t: string): void {
  console.log(`\n\x1b[1m${t}\x1b[0m`);
}
function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) {
    console.error(`\n\x1b[31m✗ ASSERTION FAILED:\x1b[0m ${msg}`);
    process.exit(1);
  }
}
function textOf(r: { content?: { type: string; text?: string }[] }): string {
  return r.content?.find((c) => c.type === "text")?.text ?? "";
}

async function main(): Promise<void> {
  let downstreamAuth: string | undefined;
  const downstream = createServer((req, res) => {
    downstreamAuth = req.headers.authorization;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ login: "octocat" }));
  });
  const ghPort = await new Promise<number>((r) =>
    downstream.listen(0, "127.0.0.1", () => r((downstream.address() as AddressInfo).port)),
  );

  const work = await mkdtemp(join(tmpdir(), "roguezero-runtime-mcp-"));

  step("1. Operator sets up the runtime (init → tool add → secret set → onboard)");
  const ws = await runtimeInitCommand({
    dir: work,
    audience: AUDIENCE,
    passphrase: PASS,
    argonParams: { t: 1, m: 8 * 1024, p: 1 },
  });
  await toolAddCommand({
    configPath: ws.configPath,
    tool: {
      id: "gh",
      method: "GET",
      url: `http://127.0.0.1:${ghPort}/user`,
      credentialRef: "gh-token",
      placement: "bearer",
      internal: true,
    },
  });
  await secretSetCommand({
    configPath: ws.configPath,
    tool: "gh",
    ref: "gh-token",
    value: TOKEN,
    passphrase: PASS,
  });
  const onboard = await onboardCommand({
    name: "agent",
    configPath: ws.configPath,
    controllerPath: ws.controllerPath,
    tools: [parseToolSpec("gh=gh:read")],
  });
  console.log("   tool 'gh' registered; token sealed in the vault; agent 'agent' granted it.");

  // --- agent side: a stock MCP client, spawning connect → runtime mcp ---
  step("2. Unmodified MCP client connects through `connect` → `runtime mcp`");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      CLI_BIN,
      "connect",
      "--agent",
      "agent",
      "--config",
      ws.configPath,
      "--",
      process.execPath,
      CLI_BIN,
      "runtime",
      "mcp",
      "--config",
      ws.configPath,
    ],
    env: { ...(process.env as Record<string, string>), RZ_VAULT_PASSPHRASE: PASS },
    stderr: "inherit",
  });
  const client = new Client({ name: "some-agent", version: "1.0.0" });
  await client.connect(transport);

  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  console.log(`   tools visible to the agent: ${names.join(", ")}`);
  assert(!names.includes("request_challenge"), "the challenge tool must stay hidden");
  assert(names.includes("gh"), "the agent should see the gh tool");
  const gh = tools.find((t) => t.name === "gh");
  const props = Object.keys(
    (gh?.inputSchema as { properties?: Record<string, unknown> })?.properties ?? {},
  );
  assert(!props.includes("presentation"), "`presentation` must not leak into the tool schema");

  const call = () =>
    client.callTool({ name: "gh", arguments: {} }) as Promise<{
      isError?: boolean;
      content: { type: string; text?: string }[];
    }>;

  step("3. gh  → expect ALLOW (token injected by the runtime, not the agent)");
  const allow = await call();
  console.log(`   → ${allow.isError ? "DENIED" : "ALLOWED"}: ${textOf(allow)}`);
  assert(allow.isError !== true, "gh should be allowed");
  assert(downstreamAuth === `Bearer ${TOKEN}`, "the downstream must receive the injected token");
  assert(!textOf(allow).includes(TOKEN), "the agent must never receive the token");

  step("4. roguezero revoke --agent agent   (the kill switch)");
  await revokeCommand({ listPath: join(work, "revocations.json"), bundlePath: onboard.bundlePath });
  console.log("   revoked.");

  step("5. gh again  → expect DENY (revoked)");
  const revoked = await call();
  console.log(`   → ${textOf(revoked)}`);
  assert(revoked.isError === true, "gh should be denied after revocation");
  assert(textOf(revoked).includes("revoked"), "denial reason should be 'revoked'");

  step("6. Audit trail");
  console.log(await inspectAuditCommand({ auditPath: join(work, "audit.jsonl") }));

  await client.close();
  downstream.close();
  await rm(work, { recursive: true, force: true });
  console.log(
    "\n\x1b[32m✓ Unmodified MCP agent used a real tool through the runtime, never held the " +
      "credential, and revocation killed it. Self-hosted, zero agent-side code.\x1b[0m",
  );
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
