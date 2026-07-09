# RogueZero

**The kill switch and flight recorder for AI agents.** Revoke any agent's access in one command — its next call is denied — and reconstruct every decision from an append-only audit trail.

AI agents are being wired into real tools faster than teams can control them. Today the credential is a shared API key in a config file: when an agent misbehaves, the logs blame a service account, and the only way to shut it off is to rotate the key — which breaks everything else using it. RogueZero gives every agent a **scoped, expiring, revocable** permission, checks it on **every call**, and denies anything that doesn't match — with a decision log you can actually prove. Drop-in middleware for MCP and HTTP tools; runs entirely on your own machines.

> Built on W3C DIDs and Verifiable Credentials under the hood — but you never touch them. No blockchain, no wallets, no tokens. New to the idea? [`docs/CONCEPTS.md`](docs/CONCEPTS.md) explains it in five plain concepts.

## Status

🚧 **Early beta**, pre-1.0. The verification core and both middlewares work; the golden-path demo runs end to end and is enforced in CI. See [`CONTRIBUTING.md`](CONTRIBUTING.md) to build and run it.

## How it works

Put RogueZero in front of any tool. Every call runs one fail-closed sequence before your tool executes:

```
create agent identity (did:key / did:web)
  → issue AgentProfile + Capability credentials
  → agent calls a protected MCP/HTTP tool with a verifiable presentation
  → middleware verifies: signature · issuer trust · expiry · audience/nonce · revocation
  → policy allow/deny
  → audit event (actor, subject, tool, decision, evidence, timestamp)
  → revoke → the same call is now denied
```

**The moment that matters:** one `revoke` kills one agent's one permission — its next call is denied, with the reason in the log. No key rotation. No collateral damage to anything else.

## Quickstart

Requires Node ≥ 20 and [pnpm](https://pnpm.io) (`corepack enable` provides it).

```bash
pnpm install
pnpm demo
```

That's it. The demo stands up a real MCP client ↔ server protected by RogueZero and walks
the whole story: an allowed call, a call the policy denies, then the same call **denied
after revocation** — printing the audit trail at the end. (`pnpm demo:stdio` runs the same
thing over a real spawned MCP server.) It writes the audit log and revocation list to a
throwaway temp directory — nothing lands in your working tree.

### Try the CLI

The CLI runs from the built output, so build once first (`pnpm demo` above already does
this). A one-command `npx @roguezero/cli` lands with the npm release.

```bash
pnpm build                                           # produces packages/cli/dist
alias rz="node packages/cli/dist/bin.js"

rz create --out controller.key.json                 # the operator's identity
rz create --out agent.key.json                       # the agent's identity
AGENT=$(rz create) ; # or read the DID from a keystore

rz issue capability \
  --issuer controller.key.json \
  --subject "$AGENT" \
  --audience mcp://reports.acme.example \
  --tool read_report=reports:read \
  --out capability.jwt

rz verify --jwt capability.jwt                        # signature · issuer · expiry · shape
rz revoke --list revocations.json --jwt capability.jwt
rz inspect --audit audit.jsonl                        # pretty-print a decision log
```

Everything runs locally — no accounts, no hosted services, no blockchain.

## Layout

| Path | Contents |
|---|---|
| `packages/core` | DID create/resolve, VC issue/verify, policy, revocation, audit |
| `packages/middleware` | MCP server wrapper + HTTP middleware |
| `packages/cli` | `create` / `issue` / `verify` / `revoke` / `inspect` |
| `examples/protected-tool` | End-to-end golden-path demo |
| `docs/` | [Concepts](docs/CONCEPTS.md) · [Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY.md) · [Threat model](docs/THREAT-MODEL.md) · ADRs |

Contributing? See [`CONTRIBUTING.md`](CONTRIBUTING.md), and start with [`docs/CONCEPTS.md`](docs/CONCEPTS.md). Security reports: [`SECURITY.md`](SECURITY.md).

## License

[Apache-2.0](LICENSE). Free forever for the open-source SDK, middleware, and CLI.
