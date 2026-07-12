import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  argon2idKeyProvider,
  getCredential,
  parseToolRegistry,
  readVaultFromFile,
  resolveRequest,
} from "@roguezero/core";
import { INTEGRATIONS, listIntegrations } from "./integrations.js";
import { addIntegrationCommand, runtimeInitCommand } from "./runtime.js";

const PASS = "correct horse battery staple";
const FAST = { t: 1, m: 8 * 1024, p: 1 };

let dir = "";
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("starter-pack integrations", () => {
  it("every shipped template is a valid registry definition", () => {
    for (const integration of listIntegrations()) {
      // Each integration's tools must parse as a real registry — the shipped defs are correct.
      expect(() => parseToolRegistry({ tools: integration.tools })).not.toThrow();
      // Least-privilege hygiene: a credential is referenced, never a query placement.
      for (const tool of integration.tools) {
        expect(["bearer", "basic", "header"]).toContain(tool.credential.placement);
      }
    }
  });

  it("resolves the GitHub tool into a pinned request with static headers and path/body params", () => {
    const registry = parseToolRegistry({ tools: INTEGRATIONS.github!.tools });
    const plan = resolveRequest(registry, "github_create_issue", {
      owner: "acme",
      repo: "app",
      title: "hello",
      body: "world",
    });
    expect(plan.url).toBe("https://api.github.com/repos/acme/app/issues");
    expect(plan.method).toBe("POST");
    expect(plan.headers["user-agent"]).toBe("roguezero"); // the header GitHub 403s without
    expect(plan.headers["x-github-api-version"]).toBe("2022-11-28");
    expect(plan.credential.ref).toBe("github-token"); // referenced, not present
    expect(JSON.parse(plan.body!)).toEqual({ title: "hello", body: "world" });
  });

  it("carries Notion's required version header and Airtable's pinned path params", () => {
    const notionPlan = resolveRequest(
      parseToolRegistry({ tools: INTEGRATIONS.notion!.tools }),
      "notion_search",
      { query: "roadmap" },
    );
    expect(notionPlan.headers["notion-version"]).toBe("2022-06-28"); // Notion 400s without it
    expect(notionPlan.url).toBe("https://api.notion.com/v1/search");

    const airtablePlan = resolveRequest(
      parseToolRegistry({ tools: INTEGRATIONS.airtable!.tools }),
      "airtable_list_records",
      { base: "app123", table: "Tasks", maxRecords: 5 },
    );
    expect(airtablePlan.url).toBe("https://api.airtable.com/v0/app123/Tasks?maxRecords=5");
  });

  it("ships a pack of at least seven recognizable integrations", () => {
    expect(listIntegrations().length).toBeGreaterThanOrEqual(7);
  });

  it("resolves OpenAI's nested chat body via bodyTemplate (agent fills only the leaves)", () => {
    const plan = resolveRequest(
      parseToolRegistry({ tools: INTEGRATIONS.openai!.tools }),
      "openai_chat",
      { model: "gpt-4o-mini", prompt: "summarize this" },
    );
    expect(plan.url).toBe("https://api.openai.com/v1/chat/completions");
    expect(JSON.parse(plan.body!)).toEqual({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "summarize this" }],
      max_tokens: 1024,
    });
  });
});

describe("roguezero add — the one-command integration path", () => {
  async function workspace() {
    dir = await mkdtemp(join(tmpdir(), "rz-add-"));
    const ws = await runtimeInitCommand({
      dir,
      audience: "runtime://acme.test",
      passphrase: PASS,
      argonParams: FAST,
    });
    return ws;
  }

  it("registers the integration's tool(s) and stores the credential bound to the tool", async () => {
    const ws = await workspace();
    const result = await addIntegrationCommand({
      configPath: ws.configPath,
      integration: "github",
      secret: "ghp_the_agent_never_sees_this",
      passphrase: PASS,
    });

    expect(result.addedTools).toEqual(["github_create_issue"]);
    expect(result.secretStored).toBe(true);

    // The tool landed in the registry.
    const registry = JSON.parse(await readFile(ws.registryPath, "utf8")) as {
      tools: { id: string }[];
    };
    expect(registry.tools.map((t) => t.id)).toContain("github_create_issue");

    // The credential is in the vault, bound to that tool, retrievable only under its tool id.
    const vault = await readVaultFromFile(
      join(dirname(ws.configPath), "vault.json"),
      argon2idKeyProvider(PASS),
    );
    const bytes = await getCredential(vault, {
      ref: "github-token",
      toolId: "github_create_issue",
    });
    expect(new TextDecoder().decode(bytes)).toBe("ghp_the_agent_never_sees_this");
  });

  it("adds the tools without a secret when none is supplied (secret set later)", async () => {
    const ws = await workspace();
    const result = await addIntegrationCommand({ configPath: ws.configPath, integration: "slack" });
    expect(result.secretStored).toBe(false);
    expect(result.addedTools).toEqual(["slack_post_message"]);
  });

  it("refuses an unknown integration, naming the available ones", async () => {
    const ws = await workspace();
    await expect(
      addIntegrationCommand({ configPath: ws.configPath, integration: "myspace" }),
    ).rejects.toThrow(/unknown integration.*github/);
  });

  it("refuses to re-add a tool that is already registered", async () => {
    const ws = await workspace();
    await addIntegrationCommand({ configPath: ws.configPath, integration: "stripe" });
    await expect(
      addIntegrationCommand({ configPath: ws.configPath, integration: "stripe" }),
    ).rejects.toThrow(/already in the registry/);
  });
});
