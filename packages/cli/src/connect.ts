/**
 * `roguezero connect` — the agent-side proxy. This is what makes RogueZero a one-line change
 * for the *tool* and a zero-line change for the *agent*.
 *
 * An MCP client (Cursor, VS Code, any stdio MCP client) spawns this instead of the protected
 * server. We speak plain MCP downstream — no presentation, no challenge, no RogueZero in the
 * tool schemas — and RogueZero-protected MCP upstream, minting a fresh holder-signed
 * presentation for every single call. The agent's code, prompts, and tool definitions never
 * learn that any of this happened.
 *
 * Security posture, and why stdio specifically:
 * - The client spawns us as a child process, so the agent↔proxy hop is a private pipe, 1:1,
 *   with no listening socket. Nothing else on the machine can drive this proxy as a confused
 *   deputy. An HTTP proxy on localhost would not have that property — every process on the box
 *   could reach it — which is precisely the boundary the AutoJack write-up describes. If we
 *   ever add an HTTP variant it gets a unix socket at 0600, never a TCP port.
 * - We hold the agent's private key. It never leaves this process: presentations are signed
 *   here, and only the signed presentation crosses to the upstream server.
 * - Per-call presentations, not a session token. Revocation lands on the very next tool call.
 *
 * stdout is the downstream MCP channel. Every diagnostic goes to stderr or the protocol breaks.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { createPresentation } from "@roguezero/core";
import { bundleExpiry, bundleSigner, type AgentBundle } from "./bundle.js";

/** Warn an operator this far ahead of a capability expiring, so rotation is never a surprise. */
export const RENEWAL_WARNING_DAYS = 3;

/** The unprotected tool a guarded server exposes so callers can obtain a one-time nonce. */
export const CHALLENGE_TOOL = "request_challenge";
/** The reserved argument the guard reads the presentation from. */
const PRESENTATION_ARG = "presentation";

export interface ConnectOptions {
  /**
   * Loads the current bundle. Called at startup and again for every presentation, so a bundle
   * renewed on disk (ADR 0004) is picked up without restarting the proxy. Reading per mint costs
   * a disk read + parse — trivially less than the verification it precedes.
   */
  loadBundle: () => Promise<AgentBundle>;
  /** The protected MCP server to spawn: command plus arguments. */
  upstream: string[];
  /** Name of the upstream's challenge tool, if it was registered under a custom name. */
  challengeTool?: string;
  log?: (message: string) => void;
}

/** Hide the guard's machinery from the agent: the reserved arg is ours, not the tool's. */
export function stripPresentationArg(tool: Tool): Tool {
  const schema = tool.inputSchema as
    { properties?: Record<string, unknown>; required?: string[] } | undefined;
  if (!schema?.properties || !(PRESENTATION_ARG in schema.properties)) return tool;

  const properties = { ...schema.properties };
  delete properties[PRESENTATION_ARG];
  return {
    ...tool,
    inputSchema: {
      ...schema,
      properties,
      required: schema.required?.filter((r) => r !== PRESENTATION_ARG),
    } as Tool["inputSchema"],
  };
}

function textOf(result: CallToolResult): string {
  const first = result.content.find((c) => c.type === "text");
  return first && "text" in first ? first.text : "";
}

/**
 * Wire the proxy: connect upstream, then serve downstream on stdio. Resolves when the
 * downstream transport closes.
 */
export async function connect(options: ConnectOptions): Promise<void> {
  const log = options.log ?? ((m: string) => process.stderr.write(`${m}\n`));
  const challengeTool = options.challengeTool ?? CHALLENGE_TOOL;
  // Loaded once here for startup validation and logging; re-read per mint below so renewal lands.
  const bundle = await options.loadBundle();

  const [command, ...args] = options.upstream;
  if (!command) throw new Error("connect requires an upstream command after `--`");

  // Refuse to start on an expired bundle. The guard would deny every call with `verify:expired`,
  // which reads to an agent's owner like the tool is broken rather than the credential.
  const { expiresAt, expired } = bundleExpiry(bundle);
  if (expired) {
    throw new Error(
      `"${bundle.name}"'s capability expired on ${new Date((expiresAt ?? 0) * 1000).toISOString()}. ` +
        `Every call would be denied. Run \`roguezero renew --agent ${bundle.name}\`.`,
    );
  }
  if (expiresAt !== undefined) {
    const daysLeft = (expiresAt - Math.floor(Date.now() / 1000)) / 86_400;
    if (daysLeft < RENEWAL_WARNING_DAYS) {
      log(
        `[roguezero] WARNING: "${bundle.name}" expires in ${daysLeft.toFixed(1)} days. ` +
          `Run \`roguezero renew --agent ${bundle.name}\`.`,
      );
    }
  }

  // The SDK spawns children with a scrubbed environment by default. A proxy must not do that:
  // the upstream server is the operator's process and reads its own configuration from the
  // environment we were started with (RZ_CONFIG, credentials for the tool itself, PATH…).
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) env[key] = value;
  }

  const upstream = new Client({ name: "roguezero-connect", version: "0.1.0" });
  await upstream.connect(
    new StdioClientTransport({
      command,
      args,
      env,
      // The protected server's own logging belongs on our stderr, not swallowed.
      stderr: "inherit",
    }),
  );

  const { tools } = await upstream.listTools();
  if (!tools.some((t) => t.name === challengeTool)) {
    throw new Error(
      `The upstream server exposes no "${challengeTool}" tool, so it is not RogueZero-protected. ` +
        `Point --agent at a guarded server, or drop \`connect\` and call it directly.`,
    );
  }

  /** A fresh, single-use presentation bound to this server's audience. */
  const mintPresentation = async (): Promise<string> => {
    // Re-read the bundle every call: a controller-side renewal (ADR 0004) rewrites this file in
    // place, and the running agent must pick up the new credentials without a restart.
    const current = await options.loadBundle();
    const { expired, expiresAt: currentExp } = bundleExpiry(current);
    if (expired) {
      throw new Error(
        `"${current.name}"'s capability expired on ${new Date((currentExp ?? 0) * 1000).toISOString()}. ` +
          `Renewal has not reached this bundle. Run \`roguezero renew --agent ${current.name}\`.`,
      );
    }

    const raw = (await upstream.callTool({
      name: challengeTool,
      arguments: {},
    })) as CallToolResult;
    const body = textOf(raw);
    let nonce: string | undefined;
    try {
      nonce = (JSON.parse(body) as { nonce?: string }).nonce;
    } catch {
      throw new Error(`challenge tool returned a non-JSON response: ${body.slice(0, 120)}`);
    }
    if (!nonce) throw new Error(`challenge tool returned no nonce: ${body.slice(0, 120)}`);

    return createPresentation(
      bundleSigner(current),
      { profileVc: current.profileVc, capabilityVc: current.capabilityVc },
      { challenge: nonce, audience: current.audience },
    );
  };

  const server = new Server(
    { name: "roguezero-connect", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const { tools: upstreamTools } = await upstream.listTools();
    return {
      tools: upstreamTools
        .filter((t) => t.name !== challengeTool)
        .map((t) => stripPresentationArg(t)),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: toolArgs } = request.params;
    let presentation: string;
    try {
      presentation = await mintPresentation();
    } catch (error) {
      // Fail closed and legibly: the agent sees a tool error, not a dead server.
      const message = error instanceof Error ? error.message : String(error);
      return {
        isError: true,
        content: [{ type: "text", text: `RogueZero could not present credentials: ${message}` }],
      } satisfies CallToolResult;
    }

    // The upstream guard's denial text already names the failed check and the fix; pass it
    // through untouched so the agent (and its human) see the real reason.
    return (await upstream.callTool({
      name,
      arguments: { ...(toolArgs ?? {}), [PRESENTATION_ARG]: presentation },
    })) as CallToolResult;
  });

  log(`[roguezero] "${bundle.name}" → ${command} ${args.join(" ")}`);
  log(`[roguezero] audience ${bundle.audience}; presenting on every call.`);

  await server.connect(new StdioServerTransport());

  // Keep the upstream child alive for as long as the client holds us open.
  await new Promise<void>((resolve) => {
    server.onclose = () => resolve();
  });
  await upstream.close();
}
