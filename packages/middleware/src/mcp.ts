/**
 * MCP server wrapper: require and verify a holder-signed presentation on every protected
 * tool call, then run policy and emit an audit event — all via `@roguezero/core`'s
 * `authorizeToolCall`. This module is thin transport glue; no verification logic lives here.
 *
 * Transport choice (per ARCHITECTURE's open question, decided at D1): the presentation rides
 * per-call, in a reserved `presentation` argument. Per-call is the strongest security story
 * (every call is verified at action time) and the clearest demo. The agent first calls the
 * unprotected `request_challenge` tool to get a one-time nonce, binds a presentation to it,
 * then calls the protected tool. Keeping this in one module means a future move to a
 * different MCP auth convention is a localized change.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z, type ZodRawShape } from "zod";
import { authorizeToolCall, explainDenial } from "@roguezero/core";
import type { AuthorizedContext, RogueZeroGuardOptions } from "./shared.js";

export interface ProtectedToolConfig {
  name: string;
  title?: string;
  description?: string;
  /** The tool's own argument shape (excluding `presentation`, which is added automatically). */
  inputSchema?: ZodRawShape;
}

export type ProtectedToolHandler = (
  args: Record<string, unknown>,
  context: AuthorizedContext,
) => CallToolResult | Promise<CallToolResult>;

const presentationField = z
  .string()
  .describe("A holder-signed Verifiable Presentation bound to a request_challenge nonce.");

function denyResult(reason: string): CallToolResult {
  const e = explainDenial(reason);
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: `RogueZero denied this call: ${e.summary} (reason: ${reason}) Fix: ${e.fix}`,
      },
    ],
  };
}

/**
 * Create an MCP guard bound to a verification context. Register the challenge tool once, then
 * wrap each protected tool with `protect`.
 */
export function createMcpGuard(options: RogueZeroGuardOptions) {
  return {
    /** Register the unprotected tool an agent calls to obtain a one-time challenge. */
    registerChallengeTool(server: McpServer, name = "request_challenge"): void {
      server.registerTool(
        name,
        {
          description:
            "Obtain a one-time challenge (nonce + audience) to bind a presentation to this server.",
          inputSchema: {},
        },
        async () => {
          const challenge = await options.nonceStore.issue(options.audience);
          return { content: [{ type: "text", text: JSON.stringify(challenge) }] };
        },
      );
    },

    /** Register a protected tool: verify → policy → audit run before the handler executes. */
    protect(server: McpServer, config: ProtectedToolConfig, handler: ProtectedToolHandler): void {
      const inputSchema: ZodRawShape = {
        ...(config.inputSchema ?? {}),
        presentation: presentationField,
      };

      server.registerTool(
        config.name,
        { title: config.title, description: config.description, inputSchema },
        async (args: Record<string, unknown>) => {
          const { presentation, ...toolArgs } = args;
          const result = await authorizeToolCall({
            presentation: typeof presentation === "string" ? presentation : "",
            tool: config.name,
            audience: options.audience,
            resolver: options.resolver,
            trustedIssuers: options.trustedIssuers,
            nonceStore: options.nonceStore,
            policy: options.policy,
            auditSink: options.auditSink,
            isRevoked: options.isRevoked,
          });

          if (result.decision !== "allow" || !result.request) {
            return denyResult(result.reason);
          }
          return handler(toolArgs, {
            authorized: result.request,
            correlationId: result.correlationId,
          });
        },
      );
    },
  };
}
