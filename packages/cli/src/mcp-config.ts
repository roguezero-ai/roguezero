/**
 * `roguezero mcp-config` — generate a correct Claude Desktop MCP entry for THIS machine, and
 * optionally write it in. Born from Dogfood Session 1, where a real user hit three walls assembling
 * this by hand: the nvm PATH (`#!/usr/bin/env node` fails under Claude's minimal launch PATH), the
 * absolute paths (node + bin + config, duplicated across `connect` and the `runtime mcp` it spawns),
 * and an empty/edited-wrong config with no feedback. This command removes all three.
 *
 * It uses `process.execPath` (the absolute node running us — guaranteed to work) and the real path to
 * our own `bin.js` (a sibling in dist/), so the generated config never depends on PATH.
 */

import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PLACEHOLDER_PASSPHRASE = "PUT_YOUR_RZ_VAULT_PASSPHRASE_HERE";

export interface McpServerEntry {
  command: string;
  args: string[];
  env: Record<string, string>;
}

/** The absolute path to our own `bin.js` (sibling of this module in dist/) — never a PATH lookup. */
function selfBinPath(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "bin.js");
}

/** The Claude Desktop config file for this OS. */
export function claudeDesktopConfigPath(platform: NodeJS.Platform = process.platform): string {
  if (platform === "darwin") {
    return join(
      homedir(),
      "Library",
      "Application Support",
      "Claude",
      "claude_desktop_config.json",
    );
  }
  if (platform === "win32") {
    const appData = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return join(appData, "Claude", "claude_desktop_config.json");
  }
  return join(homedir(), ".config", "Claude", "claude_desktop_config.json");
}

/**
 * Build the `mcpServers.<name>` entry: `node bin.js connect … -- node bin.js runtime mcp …`, all
 * absolute. The passphrase is embedded if given (plaintext, local-dev only), else a placeholder.
 */
export function buildMcpServerEntry(opts: {
  agent: string;
  configPath: string;
  passphrase?: string;
  nodePath?: string;
  binPath?: string;
}): McpServerEntry {
  const node = opts.nodePath ?? process.execPath;
  const bin = opts.binPath ?? selfBinPath();
  const cfg = resolve(opts.configPath);
  return {
    command: node,
    args: [
      bin,
      "connect",
      "--agent",
      opts.agent,
      "--config",
      cfg,
      "--",
      node,
      bin,
      "runtime",
      "mcp",
      "--config",
      cfg,
    ],
    env: { RZ_VAULT_PASSPHRASE: opts.passphrase ?? PLACEHOLDER_PASSPHRASE },
  };
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

export interface McpConfigResult {
  serverName: string;
  entry: McpServerEntry;
  claudeConfigPath: string;
  /** True if we merged it into the Claude config file. */
  wrote: boolean;
  /** Present when we wrote and a prior config existed. */
  backupPath?: string;
  passphraseEmbedded: boolean;
  /** Non-fatal setup problems worth telling the user about (missing workspace / agent bundle). */
  warnings: string[];
}

/**
 * Produce the entry, and (with `write`) merge it into the Claude Desktop config — preserving all
 * existing keys, backing the file up first. Fails closed only on genuinely broken input; missing
 * workspace pieces are surfaced as warnings, not errors, so the user still gets a config to fix.
 */
export async function mcpConfigCommand(opts: {
  agent: string;
  configPath: string;
  serverName?: string;
  passphrase?: string;
  write?: boolean;
  /** Override the Claude config location (tests). */
  claudeConfigPath?: string;
}): Promise<McpConfigResult> {
  const serverName = opts.serverName ?? "roguezero";
  const cfg = resolve(opts.configPath);
  const entry = buildMcpServerEntry({
    agent: opts.agent,
    configPath: cfg,
    passphrase: opts.passphrase,
  });

  // Mini-doctor: catch the setup mistakes that would make the server fail after they wire it.
  const warnings: string[] = [];
  if (!(await exists(cfg))) {
    warnings.push(`no runtime workspace at ${cfg} — run \`roguezero runtime init\` first.`);
  }
  const bundlePath = join(dirname(cfg), `${opts.agent}.rz.json`);
  if (!(await exists(bundlePath))) {
    warnings.push(
      `no agent bundle at ${bundlePath} — run \`roguezero onboard ${opts.agent} --tool <t>=<scope>\`.`,
    );
  }

  const claudeConfigPath = opts.claudeConfigPath ?? claudeDesktopConfigPath();
  let wrote = false;
  let backupPath: string | undefined;

  if (opts.write) {
    let current: { mcpServers?: Record<string, unknown> } = {};
    if (await exists(claudeConfigPath)) {
      // Preserve every existing key; back up before touching an outward-facing app's config.
      current = JSON.parse(await readFile(claudeConfigPath, "utf8")) as typeof current;
      backupPath = `${claudeConfigPath}.bak`;
      await copyFile(claudeConfigPath, backupPath);
    } else {
      await mkdir(dirname(claudeConfigPath), { recursive: true });
    }
    current.mcpServers = { ...(current.mcpServers ?? {}), [serverName]: entry };
    await writeFile(claudeConfigPath, `${JSON.stringify(current, null, 2)}\n`, "utf8");
    wrote = true;
  }

  return {
    serverName,
    entry,
    claudeConfigPath,
    wrote,
    backupPath,
    passphraseEmbedded: opts.passphrase !== undefined,
    warnings,
  };
}
