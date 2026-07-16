import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { type AddressInfo } from "node:net";
import { join } from "node:path";
import { createPresentation } from "@roguezero/core";
import { bundleSigner, loadBundle } from "./bundle.js";
import { parseToolSpec } from "./commands.js";
import { onboardCommand } from "./workspace.js";
import { runtimeInitCommand, secretSetCommand, serveCommand, toolAddCommand } from "./runtime.js";

const AUDIENCE = "runtime://acme.test";
const TOKEN = "ghp_TOKEN_the_agent_never_sees";
const PASS = "correct horse battery staple";
const FAST = { t: 1, m: 8 * 1024, p: 1 }; // seal the vault cheaply; opens read cost from the blob

let dir = "";
let downstream: Server | undefined;
let runtime: Server | undefined;
afterEach(async () => {
  runtime?.close();
  downstream?.close();
  runtime = undefined;
  downstream = undefined;
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

describe("runtime CLI — self-host flow", () => {
  it("creates the workspace directory when it doesn't exist (`init <newdir>`, no mkdir first)", async () => {
    // Dogfood regression: a stranger runs `roguezero runtime init myruntime` with no dir yet.
    // Tests here previously always mkdtemp'd the dir first, so this failed only in the real world.
    const root = await mkdtemp(join(tmpdir(), "rz-init-"));
    dir = root; // afterEach cleans the whole tree
    const target = join(root, "does", "not", "exist", "yet");
    const ws = await runtimeInitCommand({
      dir: target,
      audience: AUDIENCE,
      passphrase: PASS,
      argonParams: FAST,
    });
    expect(ws.controllerDid).toMatch(/^did:key:/);
    const { readFile } = await import("node:fs/promises");
    await expect(readFile(ws.registryPath, "utf8")).resolves.toContain("tools");
  });

  it("init → tool add → secret set → onboard → serve → agent calls it, never holding the token", async () => {
    // The downstream tool.
    let downstreamAuth: string | undefined;
    downstream = createServer((req, res) => {
      downstreamAuth = req.headers.authorization;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ login: "octocat" }));
    });
    const ghPort = await new Promise<number>((r) =>
      downstream!.listen(0, "127.0.0.1", () => r((downstream!.address() as AddressInfo).port)),
    );

    // 1. init the runtime workspace.
    dir = await mkdtemp(join(tmpdir(), "rz-runtime-"));
    const ws = await runtimeInitCommand({
      dir,
      audience: AUDIENCE,
      passphrase: PASS,
      argonParams: FAST,
    });

    // 2. register a tool pinned at the downstream (loopback → internal).
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

    // 3. store the tool's credential in the vault.
    await secretSetCommand({
      configPath: ws.configPath,
      tool: "gh",
      ref: "gh-token",
      value: TOKEN,
      passphrase: PASS,
    });

    // 4. onboard an agent that is granted the tool (mints its bundle + a policy allow).
    const onboard = await onboardCommand({
      name: "agent",
      configPath: ws.configPath,
      controllerPath: ws.controllerPath,
      tools: [parseToolSpec("gh=gh:read")],
    });

    // 5. serve.
    runtime = await serveCommand({
      configPath: ws.configPath,
      passphrase: PASS,
      port: 0,
      log: () => {},
    });
    const base = `http://127.0.0.1:${(runtime.address() as AddressInfo).port}`;

    // --- agent side: challenge → present → call, with only the mounted bundle ---
    const bundle = await loadBundle(onboard.bundlePath);
    const call = async (tool: string) => {
      const { nonce } = (await (await fetch(`${base}/challenge`)).json()) as { nonce: string };
      const presentation = await createPresentation(
        bundleSigner(bundle),
        { profileVc: bundle.profileVc, capabilityVc: bundle.capabilityVc },
        { challenge: nonce, audience: AUDIENCE },
      );
      const res = await fetch(`${base}/call`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tool, presentation }),
      });
      return { status: res.status, body: (await res.json()) as Record<string, unknown> };
    };

    const allow = await call("gh");
    expect(allow.status).toBe(200);
    expect(downstreamAuth).toBe(`Bearer ${TOKEN}`);
    expect(JSON.stringify(allow.body)).not.toContain(TOKEN); // agent never receives the token

    const denied = await call("not-a-tool");
    expect(denied.status).toBe(403);
    expect(denied.body.reason).toBe("capability:tool-not-granted");
  });

  it("rejects an http tool that isn't marked internal (SSRF guard, at config time)", async () => {
    dir = await mkdtemp(join(tmpdir(), "rz-runtime-"));
    const ws = await runtimeInitCommand({
      dir,
      audience: AUDIENCE,
      passphrase: PASS,
      argonParams: FAST,
    });
    await expect(
      toolAddCommand({
        configPath: ws.configPath,
        tool: { id: "x", method: "GET", url: "http://example.com/x", credentialRef: "k" },
      }),
    ).rejects.toThrow();
  });
});
