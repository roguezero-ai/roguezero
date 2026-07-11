/**
 * The unattended-agent reference deployment (ADR 0003 + 0004): an agent that runs with **no
 * human and no IdP**, whose credentials are rotated by a controller-side scheduler, and which
 * dies — and *stays* dead — the instant it is revoked.
 *
 * This is the story the "identity for agents that run without you" positioning has to make true.
 * CI enforces the whole arc, so the claim fails the build if it ever stops holding:
 *
 *   allow  →  scheduler renews mid-flight (no restart)  →  still allow (new credential)
 *          →  revoke  →  deny  →  scheduler runs again  →  NOT resurrected  →  still deny
 *
 * The load-bearing trick: `renew` revokes the superseded capability. So after the scheduler
 * rotates the agent, if `connect` were still holding the *old* bundle, the next call would fail
 * as `revoked`. It succeeds — which is proof the running proxy picked up the new credential with
 * no restart. And after a real `revoke`, the next scheduler tick refuses to renew (it would
 * resurrect a kill), so the agent cannot come back.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  initCommand,
  inspectAuditCommand,
  loadBundle,
  onboardCommand,
  parseToolSpec,
  renewAllCommand,
  revokeCommand,
} from "@roguezero/cli";
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
  const work = await mkdtemp(join(tmpdir(), "roguezero-unattended-"));

  step(
    "1. roguezero init  (controller key stays here, on the scheduler host — never on the agent)",
  );
  const { configPath, controllerPath } = await initCommand({ dir: work, audience: AUDIENCE });
  console.log(`   config: ${configPath}`);

  step("2. roguezero onboard reporter --tool read_report=reports:read  (short grant)");
  // A short grant so the scheduler treats it as due for renewal immediately — in production the
  // grant is 30 days and the cron renews inside a window, but the logic is identical.
  const { bundlePath } = await onboardCommand({
    name: "reporter",
    configPath,
    controllerPath,
    tools: [parseToolSpec("read_report=reports:read")],
    expiresInSeconds: 120,
  });
  const capBorn = (await loadBundle(bundlePath)).capabilityId;
  console.log(`   capability: ${capBorn}`);

  // --- agent side: a stock MCP client, no RogueZero code, running unattended -------------
  step("3. The unattended agent connects through `roguezero connect` and starts working");
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
  const client = new Client({ name: "unattended-agent", version: "1.0.0" });
  await client.connect(transport);
  const call = () =>
    client.callTool({ name: "read_report", arguments: {} }) as Promise<{
      isError?: boolean;
      content: Array<{ type: string; text?: string }>;
    }>;

  step("4. read_report  → expect ALLOW");
  const first = await call();
  console.log(`   → ${first.isError ? "DENIED" : "ALLOWED"}: ${textOf(first)}`);
  assert(first.isError !== true, "the agent should be allowed before renewal");

  step("5. The controller-side scheduler runs (a cron would do this): roguezero renew --all");
  const { outcomes } = await renewAllCommand({ dir: work, configPath, controllerPath });
  console.log(`   ${outcomes.map((o) => `${o.name}: ${o.outcome}`).join(", ")}`);
  assert(
    outcomes.find((o) => o.name === "reporter")?.outcome === "renewed",
    "reporter should renew",
  );
  const capRenewed = (await loadBundle(bundlePath)).capabilityId;
  assert(capRenewed !== capBorn, "renewal should mint a new capability id");
  console.log(`   rotated:  ${capBorn}\n          → ${capRenewed}  (old one revoked)`);

  step(
    "6. read_report again — SAME running agent, no restart  → expect ALLOW on the NEW credential",
  );
  const afterRenew = await call();
  console.log(`   → ${afterRenew.isError ? "DENIED" : "ALLOWED"}: ${textOf(afterRenew)}`);
  // If connect had cached the old bundle, this would fail as `revoked` (renewal revoked the old
  // capability). Its success is the proof that rotation reached the running agent live.
  assert(
    afterRenew.isError !== true,
    "the agent must pick up the renewed credential with no restart",
  );

  step("7. roguezero revoke --agent reporter   (kill it for real)");
  const config = await loadGuardConfig(configPath);
  const listPath = writableRevocationPath(config);
  assert(listPath !== undefined, "this demo uses a local revocation list");
  const { revokedId } = await revokeCommand({ listPath, bundlePath });
  console.log(`   revoked ${revokedId}`);

  step("8. read_report  → expect DENY (revoked)");
  const killed = await call();
  console.log(`   → ${textOf(killed)}`);
  assert(killed.isError === true, "a revoked agent must be denied");
  assert(textOf(killed).includes("revoked"), "denial reason should be 'revoked'");

  step("9. The scheduler runs AGAIN — the kill must survive it: roguezero renew --all");
  const again = await renewAllCommand({ dir: work, configPath, controllerPath });
  console.log(`   ${again.outcomes.map((o) => `${o.name}: ${o.outcome}`).join(", ")}`);
  assert(
    again.outcomes.find((o) => o.name === "reporter")?.outcome === "skipped-revoked",
    "the scheduler must refuse to renew a revoked agent — no resurrection",
  );
  const capAfterKill = (await loadBundle(bundlePath)).capabilityId;
  assert(capAfterKill === capRenewed, "a killed agent's bundle must not change");

  step("10. read_report once more  → still DENY (the kill held)");
  const stillDead = await call();
  console.log(`   → ${textOf(stillDead)}`);
  assert(stillDead.isError === true, "the agent must stay dead after the scheduler ran");

  step("11. Audit trail");
  assert(config.audit.sink === "file", "this demo writes audit events to a file");
  console.log(await inspectAuditCommand({ auditPath: config.audit.path }));

  await client.close();
  await rm(work, { recursive: true, force: true });
  console.log(
    "\n\x1b[32m✓ Unattended: allowed → renewed live (no restart) → revoked → NOT resurrected. " +
      "No human, no IdP.\x1b[0m",
  );
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
