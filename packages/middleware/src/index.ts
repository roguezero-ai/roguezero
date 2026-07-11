/**
 * @roguezero/middleware — root entry.
 *
 * Only the transport-agnostic shared types and config loading live here, so importing the
 * package root pulls in neither the MCP SDK nor Hono. Import the transport you use:
 *   - `@roguezero/middleware/mcp`  → createMcpGuard  (peer: @modelcontextprotocol/sdk)
 *   - `@roguezero/middleware/http` → createHttpGuard (peer: hono)
 */

export * from "./config.js";
export * from "./shared.js";
