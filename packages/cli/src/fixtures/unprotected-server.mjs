// A plain MCP server with no RogueZero guard — no `request_challenge` tool.
// `connect` must refuse to proxy this rather than silently forwarding unauthenticated calls.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "unprotected", version: "1.0.0" });
server.registerTool("read_report", { description: "Read it", inputSchema: {} }, () => ({
  content: [{ type: "text", text: "wide open" }],
}));
await server.connect(new StdioServerTransport());
