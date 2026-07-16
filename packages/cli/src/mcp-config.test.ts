import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildMcpServerEntry, claudeDesktopConfigPath, mcpConfigCommand } from "./mcp-config.js";

let dir = "";
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("buildMcpServerEntry", () => {
  it("uses absolute node + bin, the connect→runtime-mcp topology, and never a PATH lookup", () => {
    const entry = buildMcpServerEntry({
      agent: "claude",
      configPath: "/ws/roguezero.config.json",
      nodePath: "/abs/node",
      binPath: "/abs/bin.js",
    });
    // command is an absolute node — the nvm-PATH fix.
    expect(entry.command).toBe("/abs/node");
    // node + bin appear twice: once for connect, once for the runtime mcp it spawns.
    expect(entry.args.filter((a) => a === "/abs/node")).toHaveLength(1); // command is separate
    expect(entry.args.filter((a) => a === "/abs/bin.js")).toHaveLength(2);
    expect(entry.args).toContain("connect");
    expect(entry.args).toContain("runtime");
    expect(entry.args).toContain("mcp");
    expect(entry.args).toContain("--agent");
    expect(entry.args).toContain("claude");
    // The `--` separates the proxy args from the upstream command.
    expect(entry.args).toContain("--");
  });

  it("embeds the passphrase when given, else a clear placeholder", () => {
    const withPass = buildMcpServerEntry({
      agent: "a",
      configPath: "/c.json",
      passphrase: "s3cret",
    });
    expect(withPass.env.RZ_VAULT_PASSPHRASE).toBe("s3cret");
    const without = buildMcpServerEntry({ agent: "a", configPath: "/c.json" });
    expect(without.env.RZ_VAULT_PASSPHRASE).toContain("PUT_YOUR");
  });
});

describe("claudeDesktopConfigPath", () => {
  it("resolves the right file per OS", () => {
    expect(claudeDesktopConfigPath("darwin")).toMatch(/Library\/Application Support\/Claude/);
    expect(claudeDesktopConfigPath("linux")).toMatch(/\.config\/Claude/);
    expect(claudeDesktopConfigPath("win32")).toMatch(/Claude/);
  });
});

describe("mcpConfigCommand --write", () => {
  async function workspace() {
    dir = await mkdtemp(join(tmpdir(), "rz-mcpcfg-"));
    const configPath = join(dir, "roguezero.config.json");
    await writeFile(configPath, "{}"); // stand-in workspace
    await writeFile(join(dir, "claude.rz.json"), "{}"); // stand-in agent bundle
    return { configPath, claudeConfigPath: join(dir, "claude_desktop_config.json") };
  }

  it("merges the server into a fresh config, preserving nothing to lose", async () => {
    const { configPath, claudeConfigPath } = await workspace();
    const res = await mcpConfigCommand({
      agent: "claude",
      configPath,
      passphrase: "pw",
      write: true,
      claudeConfigPath,
    });
    expect(res.wrote).toBe(true);
    const written = JSON.parse(await readFile(claudeConfigPath, "utf8")) as {
      mcpServers: Record<string, { env: Record<string, string> }>;
    };
    expect(written.mcpServers.roguezero).toBeDefined();
    expect(written.mcpServers.roguezero!.env.RZ_VAULT_PASSPHRASE).toBe("pw");
    expect(res.warnings).toHaveLength(0); // workspace + bundle present
  });

  it("preserves existing keys and backs up the old config", async () => {
    const { configPath, claudeConfigPath } = await workspace();
    await writeFile(
      claudeConfigPath,
      JSON.stringify({ preferences: { theme: "dark" }, mcpServers: { other: { command: "x" } } }),
    );
    const res = await mcpConfigCommand({
      agent: "claude",
      configPath,
      write: true,
      claudeConfigPath,
    });
    const written = JSON.parse(await readFile(claudeConfigPath, "utf8")) as {
      preferences: { theme: string };
      mcpServers: Record<string, unknown>;
    };
    // Existing user settings and other servers survive.
    expect(written.preferences.theme).toBe("dark");
    expect(written.mcpServers.other).toBeDefined();
    expect(written.mcpServers.roguezero).toBeDefined();
    // A backup was made.
    expect(res.backupPath).toBeDefined();
    await expect(readFile(res.backupPath!, "utf8")).resolves.toContain("theme");
  });

  it("warns (not errors) when the workspace or agent bundle is missing", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-mcpcfg-"));
    const res = await mcpConfigCommand({
      agent: "ghost",
      configPath: join(dir, "roguezero.config.json"), // does not exist
      claudeConfigPath: join(dir, "cfg.json"),
    });
    expect(res.wrote).toBe(false);
    expect(res.warnings.join(" ")).toMatch(/no runtime workspace/);
    expect(res.warnings.join(" ")).toMatch(/no agent bundle/);
    expect(res.entry.command).toBeTruthy(); // still produced a usable entry
  });
});
