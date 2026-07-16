import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runQuickstart, type QuickstartIo } from "./quickstart.js";

/** Cheap KDF cost so the vault seal/open doesn't dominate the suite (the blob records the cost). */
const CHEAP_ARGON = { t: 1, m: 8, p: 1 };

let dir = "";
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

/** A scripted IO: prompt/secret answers are consumed in order; prints and opened URLs are recorded. */
function fakeIo(answers: { prompts?: string[]; secrets?: string[] }): QuickstartIo & {
  lines: string[];
  opened: string[];
} {
  const prompts = [...(answers.prompts ?? [])];
  const secrets = [...(answers.secrets ?? [])];
  const lines: string[] = [];
  const opened: string[] = [];
  return {
    lines,
    opened,
    print: (m) => lines.push(m),
    prompt: async (_q, def) => prompts.shift() ?? def ?? "",
    promptSecret: async () => secrets.shift() ?? "",
    openUrl: async (url) => {
      opened.push(url);
    },
  };
}

async function workspaceDir(): Promise<{ ws: string; claudeCfg: string }> {
  dir = await mkdtemp(join(tmpdir(), "rz-quickstart-"));
  return { ws: join(dir, "roguezero"), claudeCfg: join(dir, "claude_desktop_config.json") };
}

describe("runQuickstart — fresh workspace", () => {
  it("creates the workspace, saves the passphrase, onboards, and wires Claude in one pass", async () => {
    const { ws, claudeCfg } = await workspaceDir();
    const io = fakeIo({ secrets: ["ghp_fake_token_value"] });

    const res = await runQuickstart({
      io,
      dir: ws,
      integrationId: "github", // skip the menu
      agent: "claude",
      claudeConfigPath: claudeCfg,
      argonParams: CHEAP_ARGON,
    });

    expect(res.reusedWorkspace).toBe(false);
    expect(res.integrationId).toBe("github");
    expect(res.addedTools).toContain("github_create_issue");
    expect(res.agentDid.startsWith("did:key:")).toBe(true);
    expect(res.wrote).toBe(true);

    // The passphrase was generated, saved, and is the SAME one embedded in the Claude config —
    // so a restart of Claude opens the vault without the user ever typing it.
    const saved = (await readFile(res.passphrasePath, "utf8")).trim();
    expect(saved.length).toBeGreaterThan(20);
    const claude = JSON.parse(await readFile(claudeCfg, "utf8")) as {
      mcpServers: Record<string, { env: Record<string, string> }>;
    };
    expect(claude.mcpServers.roguezero!.env.RZ_VAULT_PASSPHRASE).toBe(saved);

    // The agent bundle and the credential-bearing registry exist.
    await expect(readFile(join(ws, "claude.rz.json"), "utf8")).resolves.toContain(res.agentDid);
    await expect(readFile(join(ws, "registry.json"), "utf8")).resolves.toContain(
      "github_create_issue",
    );

    // The browser was pointed at the token-creation page.
    expect(io.opened).toEqual(["https://github.com/settings/tokens"]);
  });

  it("writes a .gitignore that keeps the secrets uncommittable", async () => {
    const { ws, claudeCfg } = await workspaceDir();
    await runQuickstart({
      io: fakeIo({ secrets: ["ghp_fake"] }),
      dir: ws,
      integrationId: "github",
      agent: "claude",
      claudeConfigPath: claudeCfg,
      argonParams: CHEAP_ARGON,
    });
    const ignore = await readFile(join(ws, ".gitignore"), "utf8");
    for (const secretFile of ["vault.pass", "vault.json", "controller.key.json", "*.rz.json"]) {
      expect(ignore).toContain(secretFile);
    }
  });

  it("selects the integration from the menu by number", async () => {
    const { ws, claudeCfg } = await workspaceDir();
    // No integrationId → the menu runs; "1" picks the first listed integration (github).
    const io = fakeIo({ prompts: ["1", "claude"], secrets: ["ghp_fake"] });
    const res = await runQuickstart({
      io,
      dir: ws,
      claudeConfigPath: claudeCfg,
      argonParams: CHEAP_ARGON,
    });
    expect(res.integrationId).toBe("github");
    expect(res.agent).toBe("claude");
  });

  it("uses RZ_SECRET when supplied, without ever asking for the credential", async () => {
    const { ws, claudeCfg } = await workspaceDir();
    const io = fakeIo({ secrets: [] }); // no scripted secret — must not be consulted
    const res = await runQuickstart({
      io,
      dir: ws,
      integrationId: "github",
      agent: "claude",
      secret: "ghp_from_env",
      claudeConfigPath: claudeCfg,
      argonParams: CHEAP_ARGON,
    });
    expect(res.addedTools).toContain("github_create_issue");
  });

  it("refuses to proceed with an empty credential", async () => {
    const { ws, claudeCfg } = await workspaceDir();
    const io = fakeIo({ secrets: ["   "] }); // whitespace only → empty
    await expect(
      runQuickstart({
        io,
        dir: ws,
        integrationId: "github",
        agent: "claude",
        claudeConfigPath: claudeCfg,
        argonParams: CHEAP_ARGON,
      }),
    ).rejects.toThrow(/no credential/i);
  });
});

describe("runQuickstart — existing workspace", () => {
  it("reuses the saved passphrase and does not clobber the vault", async () => {
    const { ws, claudeCfg } = await workspaceDir();
    // First run creates the workspace with github.
    const first = await runQuickstart({
      io: fakeIo({ secrets: ["ghp_first"] }),
      dir: ws,
      integrationId: "github",
      agent: "claude",
      claudeConfigPath: claudeCfg,
      argonParams: CHEAP_ARGON,
    });
    const savedPass = (await readFile(first.passphrasePath, "utf8")).trim();

    // Second run against the same workspace, adding a different integration.
    const second = await runQuickstart({
      io: fakeIo({ secrets: ["xoxb-slack"] }),
      dir: ws,
      integrationId: "slack",
      agent: "claude2",
      claudeConfigPath: claudeCfg,
      argonParams: CHEAP_ARGON,
    });
    expect(second.reusedWorkspace).toBe(true);
    // Same passphrase — the vault was reused, not recreated.
    expect((await readFile(second.passphrasePath, "utf8")).trim()).toBe(savedPass);
    // The Claude config for the second agent embeds that same passphrase.
    const claude = JSON.parse(await readFile(claudeCfg, "utf8")) as {
      mcpServers: Record<string, { env: Record<string, string> }>;
    };
    expect(claude.mcpServers.roguezero!.env.RZ_VAULT_PASSPHRASE).toBe(savedPass);
    // Both integrations are now registered — the first was not wiped.
    const registry = await readFile(join(ws, "registry.json"), "utf8");
    expect(registry).toContain("github_create_issue");
    expect(registry).toContain("slack_post_message");
  });
});
