/**
 * The tool-runtime golden path (M1 Definition of Done): an agent calls a real HTTP tool through the
 * RogueZero runtime and **never holds the tool's credential**. The runtime authenticates the agent,
 * enforces policy, injects the credential the agent never sees, dispatches, audits — and a revoked
 * agent is denied without the downstream ever being contacted.
 *
 * Everything below `--- agent side ---` is what a customer's agent looks like: it fetches a
 * challenge, signs a presentation, and POSTs the tool call. It never sees the GitHub token; only the
 * runtime does, decrypted transiently from the vault and injected server-side.
 *
 * CI-enforces the whole claim: allow (token injected) → not-granted deny → revoked deny (downstream
 * never hit). Any wrong outcome exits non-zero.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";
import {
  argon2idKeyProvider,
  createDidKey,
  createDidWebDocument,
  createInMemoryAuditSink,
  createInMemoryNonceStore,
  createPresentation,
  createResolver,
  createVault,
  didWebFromHost,
  generateEd25519KeyPair,
  handleToolCall,
  issueAgentCapabilityCredential,
  issueAgentProfileCredential,
  parseToolRegistry,
  putCredential,
  type CredentialSigner,
  type Policy,
  type RuntimeToolCallOptions,
} from "@roguezero/core";

const AUDIENCE = "runtime://acme";
const GH_TOKEN = "ghp_DEMO_the_agent_never_sees_this";

function step(t: string): void {
  console.log(`\n\x1b[1m${t}\x1b[0m`);
}
function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) {
    console.error(`\n\x1b[31m✗ ASSERTION FAILED:\x1b[0m ${msg}`);
    process.exit(1);
  }
}
function json(res: ServerResponse, status: number, obj: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}
interface CallBody {
  tool: string;
  args?: Record<string, unknown>;
  presentation: string;
}
async function readBody(req: IncomingMessage): Promise<CallBody> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as CallBody;
}
async function listen(server: Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}

async function main(): Promise<void> {
  // The downstream "GitHub" — records the token it was handed and how often it was called.
  let downstreamHits = 0;
  let tokenSeen: string | undefined;
  const downstream = createServer((req, res) => {
    downstreamHits += 1;
    tokenSeen = req.headers.authorization;
    json(res, 200, { login: "octocat", authenticated: !!req.headers.authorization });
  });
  const ghPort = await listen(downstream);

  step("1. Operator sets up the runtime (identities, policy, vault, tool registry)");
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
    name: "Reporter",
  });
  const capabilityVc = await issueAgentCapabilityCredential(org, {
    id: agent.did,
    tools: [{ name: "gh-user", scopes: ["gh:read"] }], // granted gh-user only
    audience: AUDIENCE,
  });

  // The tool: pinned at the downstream, credential injected as a bearer token.
  const registry = parseToolRegistry({
    tools: [
      {
        id: "gh-user",
        method: "GET",
        scheme: "http",
        host: "127.0.0.1",
        port: ghPort,
        path: "/user",
        internal: true, // loopback reachable only because the operator said so
        credential: { ref: "gh-token", placement: "bearer" },
      },
    ],
  });

  // The vault: passphrase-derived key (fast params for the demo), the token sealed inside.
  const vault = await createVault(
    argon2idKeyProvider("demo-passphrase", { t: 1, m: 8 * 1024, p: 1 }),
  );
  await putCredential(vault, { ref: "gh-token", toolId: "gh-user", value: GH_TOKEN });
  console.log(`   vault sealed the GitHub token; the agent will never receive it.`);

  const policy: Policy = {
    rules: [{ agent: agent.did, tool: "gh-user", scopes: ["gh:read"], effect: "allow" }],
  };
  const auditSink = createInMemoryAuditSink();
  const nonceStore = createInMemoryNonceStore();

  let killed = false; // the kill switch, flipped by "revoke" below
  const runtimeConfig: Omit<RuntimeToolCallOptions, "presentation" | "tool" | "args"> = {
    audience: AUDIENCE,
    resolver,
    trustedIssuers: [orgDid],
    nonceStore,
    policy,
    auditSink,
    isRevoked: async () => killed,
    registry,
    vault,
  };

  // The runtime HTTP entrypoint: /challenge issues a nonce, /call runs the full spine.
  const runtime = createServer((req, res) => {
    void (async () => {
      try {
        if (req.method === "GET" && req.url === "/challenge") {
          const challenge = await nonceStore.issue(AUDIENCE);
          return json(res, 200, { nonce: challenge.nonce });
        }
        if (req.method === "POST" && req.url === "/call") {
          const body = await readBody(req);
          const result = await handleToolCall({
            ...runtimeConfig,
            tool: body.tool,
            args: body.args ?? {},
            presentation: body.presentation,
          });
          if (result.ok)
            return json(res, 200, { decision: result.decision, response: result.response });
          return json(res, result.decision === "deny" ? 403 : 502, {
            decision: result.decision,
            reason: result.reason,
            error: result.error,
          });
        }
        json(res, 404, { error: "not found" });
      } catch (e) {
        json(res, 500, { error: (e as Error).message });
      }
    })();
  });
  const rtPort = await listen(runtime);
  const base = `http://127.0.0.1:${rtPort}`;
  console.log(`   runtime listening at ${base}`);

  // --- agent side: no RogueZero secrets, just challenge → present → call ---------------------
  const callTool = async (tool: string, args: Record<string, unknown> = {}) => {
    const { nonce } = (await (await fetch(`${base}/challenge`)).json()) as { nonce: string };
    const presentation = await createPresentation(
      agentSigner,
      { profileVc, capabilityVc },
      { challenge: nonce, audience: AUDIENCE },
    );
    const res = await fetch(`${base}/call`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tool, args, presentation }),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };

  step("2. Agent calls gh-user  → expect ALLOW (token injected by the runtime, not the agent)");
  const allow = await callTool("gh-user");
  console.log(`   → HTTP ${allow.status}: ${JSON.stringify(allow.body.response ?? allow.body)}`);
  assert(allow.status === 200, "gh-user should be allowed");
  assert(downstreamHits === 1, "the downstream should have been called once");
  assert(tokenSeen === `Bearer ${GH_TOKEN}`, "the downstream must receive the injected token");
  assert(!JSON.stringify(allow.body).includes(GH_TOKEN), "the agent must never receive the token");
  console.log(`   downstream saw "Bearer ${GH_TOKEN}"; the agent only saw {login: octocat}.`);

  step("3. Agent calls gh-admin  → expect DENY (capability never granted it)");
  const denied = await callTool("gh-admin");
  console.log(`   → HTTP ${denied.status}: ${denied.body.reason}`);
  assert(denied.status === 403, "gh-admin should be denied");
  assert(denied.body.reason === "capability:tool-not-granted", "reason should name the capability");
  assert(downstreamHits === 1, "a denied call must NOT contact the downstream");

  step("4. Operator revokes the agent   (the kill switch)");
  killed = true;
  console.log("   agent revoked.");

  step("5. Agent calls gh-user again  → expect DENY (revoked); downstream never touched");
  const revoked = await callTool("gh-user");
  console.log(`   → HTTP ${revoked.status}: ${revoked.body.reason}`);
  assert(revoked.status === 403, "a revoked agent should be denied");
  assert(revoked.body.reason === "verify:revoked", "reason should be revoked");
  assert(
    downstreamHits === 1,
    "a revoked call must NOT decrypt the credential or hit the downstream",
  );

  step("6. Audit trail");
  for (const e of auditSink.events) {
    console.log(`   ${e.decision.toUpperCase().padEnd(5)} ${e.tool.padEnd(10)} ${e.reason}`);
  }

  runtime.close();
  downstream.close();
  console.log(
    "\n\x1b[32m✓ Agent called a real tool through the runtime, never held the credential, " +
      "and revocation stopped it before the downstream was ever touched.\x1b[0m",
  );
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
