# examples/protected-tool

The golden path — create identity → issue credentials → call a protected tool → verify →
policy → audit → revoke → denied — in three runnable forms. All are enforced in CI.

| Script | What it shows |
|---|---|
| `pnpm demo` | In-process MCP client ↔ server (fastest; the quick tour). |
| `pnpm demo:stdio` | The **real** MCP **stdio** transport: spawns a standalone server as a child process. |
| _`http.test.ts` in `@roguezero/middleware`_ | The same flow over HTTP (Hono). |

```bash
pnpm install && pnpm build
pnpm --filter @roguezero/example-protected-tool demo:stdio
```

Each prints the whole story and ends with the audit trail:

```
ALLOW read_report      reason=policy:rule-0:allow
DENY  delete_report    reason=policy:default-deny
DENY  read_report      reason=verify:revoked
```

## Protect your own tool in ~15 minutes

`src/server.ts` is the template — a standalone, config-driven, RogueZero-protected MCP
server. To wrap your own tool:

**1. Create the operator + agent identities, and issue a capability** (CLI):

```bash
rz() { node ../../packages/cli/dist/bin.js "$@"; }
rz create --out controller.key.json          # your operator identity (the issuer)
rz create --out agent.key.json                # the agent's identity
rz issue capability \
  --issuer controller.key.json \
  --subject "$(node -e 'console.log(require("./agent.key.json").did)')" \
  --audience mcp://reports.acme.example \
  --tool read_report=reports:read \
  --out capability.jwt
```

**2. Write the server's trust config** — `server-config.json`:

```json
{
  "audience": "mcp://reports.acme.example",
  "trustedIssuers": ["did:key:...controller..."],
  "policyPath": "./policy.json",
  "auditPath": "./audit.jsonl",
  "revocationPath": "./revocations.json"
}
```

and `policy.json` (default deny; list what you allow):

```json
{ "rules": [{ "agent": "did:key:...agent...", "tool": "read_report", "scopes": ["reports:read"], "effect": "allow" }] }
```

**3. Replace the tool handlers in `server.ts`** with your real tools (keep the
`guard.protect(...)` wrapper), then run it: `RZ_CONFIG=./server-config.json node dist/server.js`.
Point any MCP client at it. Every call now needs a verifiable presentation, is checked
against the capability + policy, and lands in the audit log.

### HTTP instead of MCP

Same core, different transport — use `createHttpGuard` from `@roguezero/middleware`:
a challenge route plus `guard.protect(toolName)` middleware on your Hono routes. The agent
sends the presentation in the `x-roguezero-presentation` header. See `http.test.ts` for a
complete round trip.

## Revoke

```bash
rz revoke --list revocations.json --jwt capability.jwt   # the next call is denied
rz inspect --audit audit.jsonl                            # see every decision
```
