import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { type AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createDidWebDocument,
  createInMemoryAuditSink,
  createInMemoryNonceStore,
  createPresentation,
  createResolver,
  createVault,
  didWebFromHost,
  generateEd25519KeyPair,
  createDidKey,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  localKeyProvider,
  parseToolRegistry,
  putCredential,
  type CredentialSigner,
  type Policy,
} from "@roguezero/core";
import { createRuntimeMcpServer } from "./runtime-mcp.js";
import type { RuntimeServerOptions } from "./runtime-server.js";

const AUDIENCE = "runtime://acme.mcp";
const TOKEN = "ghp_TOKEN_the_agent_never_sees";

let downstream: Server | undefined;
afterEach(() => {
  downstream?.close();
  downstream = undefined;
});

async function scenario(killedRef: { killed: boolean }) {
  let hits = 0;
  let auth: string | undefined;
  downstream = createServer((req, res) => {
    hits += 1;
    auth = req.headers.authorization;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ login: "octocat" }));
  });
  const port = await new Promise<number>((r) =>
    downstream!.listen(0, "127.0.0.1", () => r((downstream!.address() as AddressInfo).port)),
  );

  const { publicKey: orgPub, privateKey: orgPriv } = generateEd25519KeyPair();
  const orgDid = didWebFromHost("acme.example");
  const resolver = createResolver({
    localDidWebDocuments: { [orgDid]: createDidWebDocument(orgDid, orgPub) },
  });
  const org: CredentialSigner = { did: orgDid, privateKey: orgPriv };
  const agent = createDidKey();
  const agentSigner: CredentialSigner = { did: agent.did, privateKey: agent.privateKey };

  const profileVc = await issueAgentProfileCredential(org, {
    id: agent.did,
    controller: orgDid,
    name: "Agent",
  });
  const capabilityVc = await issueAgentCapabilityCredential(org, {
    id: agent.did,
    tools: [{ name: "gh", scopes: ["gh:read"] }],
    audience: AUDIENCE,
  });

  const registry = parseToolRegistry({
    tools: [
      {
        id: "gh",
        method: "GET",
        scheme: "http",
        host: "127.0.0.1",
        port,
        path: "/user",
        internal: true,
        credential: { ref: "gh-token", placement: "bearer" },
      },
    ],
  });
  const vault = await createVault(localKeyProvider(new Uint8Array(32).fill(1)));
  await putCredential(vault, { ref: "gh-token", toolId: "gh", value: TOKEN });

  const policy: Policy = {
    rules: [{ agent: agent.did, tool: "gh", scopes: ["gh:read"], effect: "allow" }],
  };
  const options: RuntimeServerOptions = {
    audience: AUDIENCE,
    resolver,
    trustedIssuers: [orgDid],
    nonceStore: createInMemoryNonceStore(),
    policy,
    auditSink: createInMemoryAuditSink(),
    isRevoked: async () => killedRef.killed,
    registry,
    vault,
  };

  const server = createRuntimeMcpServer(options);
  const client = new Client({ name: "unmodified-agent", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const callGh = async () => {
    const challenge = (await client.callTool({
      name: "request_challenge",
      arguments: {},
    })) as { content: { type: string; text?: string }[] };
    const { nonce } = JSON.parse(challenge.content[0]?.text ?? "{}") as { nonce: string };
    const presentation = await createPresentation(
      agentSigner,
      { profileVc, capabilityVc },
      { challenge: nonce, audience: AUDIENCE },
    );
    return (await client.callTool({ name: "gh", arguments: { presentation } })) as {
      isError?: boolean;
      content: { type: string; text?: string }[];
    };
  };

  return { client, callGh, hits: () => hits, auth: () => auth };
}

describe("createRuntimeMcpServer", () => {
  it("lets an MCP client call a tool, injecting the credential it never holds", async () => {
    const killed = { killed: false };
    const s = await scenario(killed);

    const { tools } = await s.client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("request_challenge");
    expect(names).toContain("gh");

    const res = await s.callGh();
    expect(res.isError).not.toBe(true);
    expect(res.content[0]?.text).toContain("octocat");
    expect(s.auth()).toBe(`Bearer ${TOKEN}`); // downstream got the token
    expect(s.hits()).toBe(1);
    await s.client.close();
  });

  it("denies a revoked agent without contacting the downstream", async () => {
    const killed = { killed: true };
    const s = await scenario(killed);
    const res = await s.callGh();
    expect(res.isError).toBe(true);
    expect(res.content[0]?.text).toContain("revoked");
    expect(s.hits()).toBe(0);
    await s.client.close();
  });
});
