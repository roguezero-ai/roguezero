import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  createDidKey,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
} from "@roguezero/core";
import { credentialIdFromJwt } from "./commands.js";
import { connect, stripPresentationArg } from "./connect.js";
import type { AgentBundle } from "./bundle.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("stripPresentationArg", () => {
  it("removes the reserved arg from properties and required", () => {
    const tool = {
      name: "read_report",
      inputSchema: {
        type: "object",
        properties: { since: { type: "string" }, presentation: { type: "string" } },
        required: ["since", "presentation"],
      },
    } as unknown as Tool;

    const stripped = stripPresentationArg(tool);
    const schema = stripped.inputSchema as {
      properties: Record<string, unknown>;
      required?: string[];
    };
    expect(Object.keys(schema.properties)).toEqual(["since"]);
    expect(schema.required).toEqual(["since"]);
  });

  it("leaves a tool without the reserved arg untouched", () => {
    const tool = {
      name: "ping",
      inputSchema: { type: "object", properties: { host: { type: "string" } } },
    } as unknown as Tool;
    expect(stripPresentationArg(tool)).toBe(tool);
  });
});

describe("connect", () => {
  /** A real bundle: `connect` reads the capability's expiry before it does anything else. */
  async function bundleFor(expiresInSeconds: number): Promise<AgentBundle> {
    const controller = createDidKey();
    const agent = createDidKey();
    const signer = { did: controller.did, privateKey: controller.privateKey };
    const profileVc = await issueAgentProfileCredential(
      signer,
      { id: agent.did, controller: controller.did, name: "reporter" },
      { expiresInSeconds },
    );
    const capabilityVc = await issueAgentCapabilityCredential(
      signer,
      {
        id: agent.did,
        tools: [{ name: "read_report", scopes: ["reports:read"] }],
        audience: "mcp://x",
      },
      { expiresInSeconds },
    );
    return {
      version: 1,
      name: "reporter",
      did: agent.did,
      controller: controller.did,
      audience: "mcp://x",
      privateKey: Buffer.from(agent.privateKey).toString("base64url"),
      profileVc,
      capabilityVc,
      capabilityId: credentialIdFromJwt(capabilityVc),
    };
  }

  it("refuses to proxy a server that is not RogueZero-protected", async () => {
    const bundle = await bundleFor(3600);
    await expect(
      connect({
        loadBundle: async () => bundle,
        upstream: [process.execPath, join(here, "fixtures/unprotected-server.mjs")],
        log: () => {},
      }),
    ).rejects.toThrow(/not RogueZero-protected/);
  });

  it("requires an upstream command", async () => {
    const bundle = await bundleFor(3600);
    await expect(
      connect({ loadBundle: async () => bundle, upstream: [], log: () => {} }),
    ).rejects.toThrow(/upstream command/);
  });

  it("refuses to start on an expired bundle, naming `renew` instead of denying every call", async () => {
    // An expired capability would make the guard answer `verify:expired` forever, which reads
    // to the agent's owner like the tool is broken rather than the credential.
    const bundle = await bundleFor(-60);
    await expect(
      connect({
        loadBundle: async () => bundle,
        upstream: [process.execPath, join(here, "fixtures/unprotected-server.mjs")],
        log: () => {},
      }),
    ).rejects.toThrow(/expired.*roguezero renew --agent reporter/s);
  });
});
