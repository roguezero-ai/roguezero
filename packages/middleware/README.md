# @roguezero/middleware

MCP server wrapper + HTTP (Hono) middleware. Extracts a presentation from a tool call,
runs the `@roguezero/core` pipeline (verify → policy → audit), and either lets the call
through or denies it with a protocol-appropriate, precise error (including the likely fix).

Import only the transport you use — the MCP SDK and Hono are **optional peer dependencies**,
so protecting an HTTP tool doesn't pull in the MCP SDK, and vice versa:

```ts
// MCP — peer: @modelcontextprotocol/sdk
import { createMcpGuard } from "@roguezero/middleware/mcp";

// HTTP — peer: hono
import { createHttpGuard } from "@roguezero/middleware/http";

// transport-agnostic shared types (no peer needed)
import type { RogueZeroGuardOptions } from "@roguezero/middleware";
```

Status: **early beta**, pre-1.0. Both transports work and are exercised end-to-end
(CI-enforced). See `examples/protected-tool` for a runnable demo and `docs/CONCEPTS.md`
for the plain-language overview.
