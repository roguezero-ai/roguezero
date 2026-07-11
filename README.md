# RogueZero

**The kill switch and flight recorder for AI agents.** Revoke any agent's access in one command — its next call is denied — and reconstruct every decision from an append-only audit trail.

AI agents are being wired into real tools faster than teams can control them. Today the credential is a shared API key in a config file: when an agent misbehaves, the logs blame a service account, and the only way to shut it off is to rotate the key — which breaks everything else using it. RogueZero gives every agent a **scoped, expiring, revocable** permission, checks it on **every call**, and denies anything that doesn't match — with a decision log you can actually prove. Drop-in middleware for MCP and HTTP tools; runs entirely on your own machines.

> Built on W3C DIDs and Verifiable Credentials under the hood — but you never touch them. No blockchain, no wallets, no tokens. New to the idea? [`docs/CONCEPTS.md`](docs/CONCEPTS.md) explains it in five plain concepts.

## Status

🚧 **Early beta**, pre-1.0. The verification core and both middlewares work; the golden-path demo runs end to end and is enforced in CI. See [`CONTRIBUTING.md`](CONTRIBUTING.md) to build and run it.

## How it works

Put RogueZero in front of any tool. Every call runs one fail-closed sequence before your tool executes:

```
roguezero onboard   → agent identity + AgentProfile + Capability credentials, one bundle file
roguezero connect   → proxies the agent's MCP calls, presenting its credentials on each one
  → middleware verifies: signature · issuer trust · expiry · audience/nonce · revocation
  → policy allow/deny
  → audit event (actor, subject, tool, decision, evidence, timestamp)
roguezero revoke    → the same call is now denied
```

Your agent talks plain MCP to `connect` and never learns any of this happened. Your tool wraps
its handlers with one `guard.protect(...)` call. Nobody writes crypto.

**The moment that matters:** one `revoke` kills one agent's one permission — its next call is denied, with the reason in the log. No key rotation. No collateral damage to anything else.

## Quickstart

Nothing to clone, nothing to build, and **no changes to your agent**. Three commands:

```bash
npx @roguezero/cli init --audience "mcp://reports.local"
npx @roguezero/cli onboard reporter --tool read_report=reports:read
npx @roguezero/cli connect --agent reporter -- node ./your-mcp-server.js
```

`init` writes a config, a controller identity, and a deny-everything policy. `onboard` mints
the agent, issues its credentials, and grants it exactly one tool — writing `reporter.rz.json`,
a single file the agent mounts, like a kubeconfig. `connect` is a proxy: it speaks plain MCP to
your agent and proves the agent's identity to the tool on every call.

Requires Node ≥ 20. Then, whenever you want it to stop:

```bash
npx @roguezero/cli revoke --agent reporter    # the next call is denied
```

### Plug it into a real MCP client

Point Cursor, VS Code, or any MCP client at `connect` instead of your server. Nothing
else changes — no SDK, no code, no presentation logic:

```jsonc
{
  "mcpServers": {
    "reports": {
      "command": "npx",
      "args": ["@roguezero/cli", "connect", "--agent", "reporter",
               "--", "node", "/path/to/your-mcp-server.js"]
    }
  }
}
```

The agent never sees a credential, a nonce, or a DID. It calls `read_report` and gets a report —
or a denial that says exactly which check failed and how to fix it.

### Run the full demo

The end-to-end demo needs a checkout, Node ≥ 22.13, and [pnpm](https://pnpm.io)
(`corepack enable` provides it). Node 22.13 is a pnpm 11 requirement; the published
packages themselves run on Node ≥ 20.

```bash
pnpm install
pnpm demo
```

That's it. The demo stands up a real MCP client ↔ server protected by RogueZero and walks
the whole story: an allowed call, a call the policy denies, then the same call **denied
after revocation** — printing the audit trail at the end. (`pnpm demo:stdio` runs the same
thing over a real spawned MCP server.) It writes the audit log and revocation list to a
throwaway temp directory — nothing lands in your working tree.

**`pnpm demo:connect` is the one to watch.** It drives a stock MCP client — containing no
RogueZero code at all — through `roguezero connect`: the call is allowed, a tool that was never
granted is denied, then the agent is revoked mid-session and the same call dies. All three
demos run in CI, so if any of this stops being true, the build goes red.

### Try the CLI

Use the published CLI directly — no checkout required:

```bash
alias rz="npx @roguezero/cli"
```

Or, from a clone, run it from the built output (`pnpm demo` above already builds it):
`alias rz="node packages/cli/dist/bin.js"`.

```bash
CONTROLLER=$(rz create --out controller.key.json)     # the operator's identity
AGENT=$(rz create --out agent.key.json)               # the agent's identity

rz issue capability \
  --issuer controller.key.json \
  --subject "$AGENT" \
  --audience mcp://reports.acme.example \
  --tool read_report=reports:read \
  --out capability.jwt

rz verify --jwt capability.jwt                        # signature · issuer · expiry · shape
rz verify --jwt capability.jwt --revocations revocations.json   # …and revocation status
rz inspect --jwt capability.jwt                       # look inside the credential
rz revoke --list revocations.json --jwt capability.jwt
```

Each command prints only its result on stdout (`create` prints the DID, nothing else), so
`$(...)` capture works and no DID is ever copied by hand.

The **audit log** is written by a protected tool at request time, not by these CLI commands —
`pnpm demo` prints a full trail, and `rz inspect --audit <file>` pretty-prints any log a
guard has written. Everything runs locally — no accounts, no hosted services, no blockchain.

## Layout

| Path | Contents |
|---|---|
| `packages/core` | DID create/resolve, VC issue/verify, policy, revocation, audit |
| `packages/middleware` | MCP server wrapper + HTTP middleware |
| `packages/cli` | `init` / `onboard` / `connect` / `revoke` — plus `create` / `issue` / `verify` / `inspect` |
| `examples/protected-tool` | End-to-end golden-path demos, including the unmodified-client proxy demo |
| `docs/` | [Concepts](docs/CONCEPTS.md) · [Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY.md) · [Threat model](docs/THREAT-MODEL.md) · ADRs |

Contributing? See [`CONTRIBUTING.md`](CONTRIBUTING.md), and start with [`docs/CONCEPTS.md`](docs/CONCEPTS.md). Security reports: [`SECURITY.md`](SECURITY.md).

## License

[Apache-2.0](LICENSE). Free forever for the open-source SDK, middleware, and CLI.
