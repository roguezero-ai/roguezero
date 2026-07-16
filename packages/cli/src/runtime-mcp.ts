/**
 * `createRuntimeMcpServer` — the runtime exposed as an MCP server, so an **unmodified MCP agent**
 * (Cursor, VS Code, an SDK client) can call your tools through `roguezero connect` and never
 * hold a credential. It speaks the same contract `connect` already drives:
 *
 *   - a `request_challenge` tool → a one-time nonce
 *   - every registered tool carries a reserved `presentation` argument (connect hides it from the
 *     agent and fills it per call)
 *
 * On a tool call it strips the presentation, runs the full spine (`handleToolCall`: authenticate →
 * policy → revocation → resolve → decrypt → inject → dispatch → audit), and returns the downstream
 * response — or the denial. This is the MCP twin of `createRuntimeServer`; both are thin transport
 * glue over `handleToolCall`. Requires `@modelcontextprotocol/sdk` (an optional peer).
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { handleToolCall } from "@roguezero/core";
import type { RuntimeServerOptions } from "./runtime-server.js";

/** The unprotected tool a client calls first to obtain a nonce (matches `connect`). */
export const CHALLENGE_TOOL = "request_challenge";
const PRESENTATION_ARG = "presentation";

export function createRuntimeMcpServer(options: RuntimeServerOptions): Server {
  const server = new Server(
    { name: "roguezero-runtime", version: "0.4.1" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () => {
    const tools: Tool[] = [
      {
        name: CHALLENGE_TOOL,
        description: "Obtain a one-time challenge nonce.",
        inputSchema: { type: "object", properties: {} },
      },
    ];
    for (const [id, def] of options.registry.byId) {
      const properties: Record<string, object> = { [PRESENTATION_ARG]: { type: "string" } };
      const required: string[] = [PRESENTATION_ARG];
      for (const p of def.params ?? []) {
        properties[p.name] =
          p.type === "number"
            ? { type: "number" }
            : p.enum
              ? { type: "string", enum: p.enum }
              : { type: "string" };
        if (p.required) required.push(p.name);
      }
      tools.push({
        name: id,
        description: `${def.method} ${def.host}${def.path} (credential injected by the runtime)`,
        inputSchema: { type: "object", properties, required },
      });
    }
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const { name, arguments: rawArgs } = request.params;

    if (name === CHALLENGE_TOOL) {
      const challenge = await options.nonceStore.issue(options.audience);
      return { content: [{ type: "text", text: JSON.stringify({ nonce: challenge.nonce }) }] };
    }

    const args: Record<string, unknown> = { ...(rawArgs ?? {}) };
    const presentation = args[PRESENTATION_ARG];
    delete args[PRESENTATION_ARG];
    if (typeof presentation !== "string") {
      return { isError: true, content: [{ type: "text", text: "missing presentation" }] };
    }

    const result = await handleToolCall({ ...options, tool: name, args, presentation });
    if (result.ok) {
      return { content: [{ type: "text", text: result.response?.body ?? "" }] };
    }
    // Pass the precise reason through so the agent (and its human) see why.
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `RogueZero denied this call (${result.reason})${result.error ? `: ${result.error}` : ""}`,
        },
      ],
    };
  });

  return server;
}
