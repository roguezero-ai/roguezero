/**
 * `roguezero quickstart` — the astonishingly-easy first run. One interactive command takes a stranger
 * from nothing to "my agent uses GitHub through RogueZero, and never holds my token," then tells them
 * to restart Claude. It sequences the real commands (`runtime init` → `add` → `onboard` →
 * `mcp-config --write`) with sensible defaults, so the concepts the target user shouldn't need to
 * know (audience, vault passphrase, tool scopes, secret piping) get pressed-through defaults instead
 * of prompts.
 *
 * The vault passphrase is generated and saved (never typed) — a local-dev convenience: the key then
 * sits beside the ciphertext, so shared/prod deployments must use a real secret manager. That
 * boundary is the same one `mcp-config` already accepts by embedding the passphrase in the Claude
 * env. Decided with the founder 2026-07-15 (auto-generate & save).
 *
 * The orchestration is a pure function over an injected `QuickstartIo`, so it is fully testable
 * without a TTY, a browser, or a real Claude config.
 */

import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import type { Argon2idParams } from "@roguezero/core";
import { addIntegrationCommand, runtimeInitCommand } from "./runtime.js";
import { CONFIG_FILENAME, onboardCommand } from "./workspace.js";
import { mcpConfigCommand } from "./mcp-config.js";
import { getIntegration, listIntegrations, type Integration } from "./integrations.js";

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

const DEFAULT_DIR = "roguezero";
const DEFAULT_AUDIENCE = "urn:roguezero:local";
const DEFAULT_AGENT = "claude";
const DEFAULT_SCOPE = "call";
const PASSPHRASE_FILE = "vault.pass";

/** The side-effecting surface quickstart needs — injected so the flow is testable end to end. */
export interface QuickstartIo {
  /** Human-facing line (stderr in the real CLI). */
  print(msg: string): void;
  /** A free-text answer, with a default the user accepts by pressing Enter. */
  prompt(question: string, def?: string): Promise<string>;
  /** A masked answer (the credential) — never echoed, never in history. */
  promptSecret(question: string): Promise<string>;
  /** Best-effort: open the credential-creation page. Never fatal if it fails. */
  openUrl(url: string): Promise<void>;
}

export interface QuickstartOptions {
  io: QuickstartIo;
  /** Workspace directory (default ./roguezero). */
  dir?: string;
  audience?: string;
  agent?: string;
  /** Pre-selected integration id — skips the menu. */
  integrationId?: string;
  scope?: string;
  /** Credential value supplied out-of-band (RZ_SECRET) — skips the masked prompt. */
  secret?: string;
  /** Merge into the Claude Desktop config (default true). */
  write?: boolean;
  /** Override the Claude config path (tests). */
  claudeConfigPath?: string;
  /** argon2id cost for sealing a fresh vault (tests seal cheaply; the blob records the cost). */
  argonParams?: Argon2idParams;
}

export interface QuickstartResult {
  dir: string;
  configPath: string;
  agent: string;
  integrationId: string;
  addedTools: string[];
  scope: string;
  agentDid: string;
  claudeConfigPath: string;
  wrote: boolean;
  backupPath?: string;
  passphrasePath: string;
  reusedWorkspace: boolean;
}

/** A strong, url-safe passphrase the user never has to see or remember. */
function generatePassphrase(): string {
  return randomBytes(24).toString("base64url");
}

/** Resolve a menu answer (a 1-based number or an id/name) to an integration. */
function resolveChoice(list: Integration[], answer: string): Integration | undefined {
  const trimmed = answer.trim().toLowerCase();
  const asNum = Number(trimmed);
  if (Number.isInteger(asNum) && asNum >= 1 && asNum <= list.length) return list[asNum - 1];
  return list.find((i) => i.id === trimmed || i.name.toLowerCase() === trimmed);
}

/**
 * Run the whole flow. Pure over `opts.io`: every prompt, print, and browser-open goes through the
 * injected surface, so a test drives it with scripted answers and asserts the on-disk result.
 */
export async function runQuickstart(opts: QuickstartOptions): Promise<QuickstartResult> {
  const { io } = opts;
  const dir = resolve(opts.dir ?? DEFAULT_DIR);
  const configPath = join(dir, CONFIG_FILENAME);
  const audience = opts.audience ?? DEFAULT_AUDIENCE;
  const scope = opts.scope ?? DEFAULT_SCOPE;
  const write = opts.write ?? true;
  const passphrasePath = join(dir, PASSPHRASE_FILE);

  io.print("");
  io.print("  RogueZero — let's give your agent scoped access to a tool, without the keys.");
  io.print("");

  // 1. Workspace + passphrase. A fresh run generates and saves the passphrase; re-running against an
  //    existing workspace reuses it (from the saved file, else asked) so we never clobber the vault.
  let passphrase: string;
  let reusedWorkspace = false;
  if (await exists(configPath)) {
    reusedWorkspace = true;
    const saved = (await readFile(passphrasePath, "utf8").catch(() => "")).trim();
    passphrase = saved || (await io.promptSecret("Existing vault passphrase"));
    if (!passphrase) throw new Error("this workspace's vault passphrase is required to add to it.");
    io.print(`  ✔ Using existing workspace at ${dir}`);
  } else {
    passphrase = generatePassphrase();
    await runtimeInitCommand({ dir, audience, passphrase, argonParams: opts.argonParams });
    await writeFile(passphrasePath, `${passphrase}\n`, { mode: 0o600 });
    io.print(`  ✔ Workspace created            ${dir}`);
    io.print(`  ✔ Vault passphrase             generated & saved (you never type this)`);
  }

  // 2. Choose the integration.
  const list = listIntegrations();
  let integration: Integration;
  if (opts.integrationId) {
    const found = getIntegration(opts.integrationId);
    if (!found) {
      throw new Error(
        `unknown integration "${opts.integrationId}"; available: ${list.map((i) => i.id).join(", ")}`,
      );
    }
    integration = found;
  } else {
    io.print("");
    io.print("  Which tool should your agent reach?");
    list.forEach((i, idx) => io.print(`    ${idx + 1}. ${i.name.padEnd(9)} ${i.description}`));
    const answer = await io.prompt("  Choose (number or name)", list[0]!.id);
    const chosen = resolveChoice(list, answer);
    if (!chosen)
      throw new Error(`didn't recognize "${answer}" — re-run and pick one of the above.`);
    integration = chosen;
  }

  // 3. Capture the credential (masked, or from RZ_SECRET), and store it encrypted.
  io.print("");
  io.print(`  ${integration.name} needs a credential.`);
  io.print(`    ${integration.secret.help}`);
  io.print(`    Opening ${integration.docsUrl} …`);
  await io.openUrl(integration.docsUrl);
  const secret = (
    opts.secret ?? (await io.promptSecret(`  Paste your ${integration.secret.label}`))
  ).trim();
  if (!secret) {
    throw new Error("no credential provided — re-run `roguezero quickstart` when you have it.");
  }
  const added = await addIntegrationCommand({
    configPath,
    integration: integration.id,
    secret,
    passphrase,
  });
  io.print(`  ✔ ${integration.name} added — credential stored encrypted; the agent never sees it.`);

  // 4. Create + credential + allow-list the agent.
  const agent = opts.agent ?? ((await io.prompt("  Agent name", DEFAULT_AGENT)) || DEFAULT_AGENT);
  const tools = integration.tools.map((t) => ({ name: t.id, scopes: [scope] }));
  const onboarded = await onboardCommand({
    name: agent,
    configPath,
    controllerPath: join(dir, "controller.key.json"),
    tools,
  });
  io.print(`  ✔ Agent "${agent}" created, credentialed, and allow-listed`);

  // 5. Wire Claude Desktop (correct absolute paths + embedded passphrase, backed up).
  const mcp = await mcpConfigCommand({
    agent,
    configPath,
    passphrase,
    write,
    claudeConfigPath: opts.claudeConfigPath,
  });
  if (mcp.wrote) {
    io.print(`  ✔ Wrote Claude Desktop config${mcp.backupPath ? "  (backed up the old one)" : ""}`);
  }

  // 6. The one manual step left.
  io.print("");
  io.print("  ─────────────────────────────────────────────");
  if (mcp.wrote) {
    io.print("  One thing left:  fully quit Claude (⌘Q) and reopen.");
  } else {
    io.print("  Add this to your Claude Desktop config, then fully quit Claude (⌘Q) and reopen:");
    io.print(`    ${mcp.claudeConfigPath}`);
  }
  io.print(`  Then ask Claude to use ${integration.name} — e.g. "${exampleFor(integration)}".`);
  io.print("");

  return {
    dir,
    configPath,
    agent,
    integrationId: integration.id,
    addedTools: added.addedTools,
    scope,
    agentDid: onboarded.agentDid,
    claudeConfigPath: mcp.claudeConfigPath,
    wrote: mcp.wrote,
    backupPath: mcp.backupPath,
    passphrasePath,
    reusedWorkspace,
  };
}

/** A friendly one-liner the user can paste to Claude to see the tool work. */
function exampleFor(integration: Integration): string {
  switch (integration.id) {
    case "github":
      return "open an issue titled 'hello from my agent' on my repo";
    case "slack":
      return "post 'hello from my agent' to #general";
    case "stripe":
      return "list my recent charges";
    case "notion":
      return "search my Notion for 'roadmap'";
    case "sentry":
      return "list my open Sentry issues";
    default:
      return `use ${integration.name}`;
  }
}

/** Open a URL in the default browser — best-effort, never throws. */
function openInBrowser(url: string): Promise<void> {
  return new Promise((res) => {
    try {
      const cmd =
        process.platform === "darwin"
          ? "open"
          : process.platform === "win32"
            ? "start"
            : "xdg-open";
      const child = spawn(cmd, process.platform === "win32" ? ["", url] : [url], {
        stdio: "ignore",
        detached: true,
        shell: process.platform === "win32",
      });
      child.on("error", () => res());
      child.unref();
      res();
    } catch {
      res();
    }
  });
}

/** Ask one line on the terminal, optionally masked, with an accept-by-Enter default. */
function ask(question: string, def: string | undefined, mask: boolean): Promise<string> {
  return new Promise((res) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const suffix = def ? ` [${def}]` : "";
    if (mask) {
      // Suppress the echo of typed characters, but still let the prompt itself print.
      let muted = false;
      const out = process.stdout;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (rl as any)._writeToOutput = (chunk: string) => {
        if (muted) {
          if (chunk.includes("\n") || chunk.includes("\r")) out.write("\n");
          return;
        }
        out.write(chunk);
      };
      rl.question(`${question}${suffix}: `, (answer) => {
        rl.close();
        res(answer);
      });
      muted = true;
    } else {
      rl.question(`${question}${suffix}: `, (answer) => {
        rl.close();
        const v = answer.trim();
        res(v || def || "");
      });
    }
  });
}

/** The real terminal IO: readline prompts (masked for secrets) and a best-effort browser open. */
export function createTerminalIo(): QuickstartIo {
  return {
    print: (msg) => process.stderr.write(`${msg}\n`),
    prompt: (question, def) => ask(question, def, false),
    promptSecret: (question) => ask(question, undefined, true).then((s) => s.trim()),
    openUrl: openInBrowser,
  };
}
