# RogueZero

**Give an AI agent scoped access to your tools — without handing it the credentials.**

Open-source and self-hosted. The runtime holds your tools' API keys; agents authenticate, and the
runtime injects the key server-side on every call. Revoke an agent and its next call is denied —
*before the credential is even decrypted*. It runs entirely on your own machines: no hosted service,
no accounts, no blockchain, and your secrets never leave your infrastructure.

Today an agent is handed a long-lived API key in an env var: if it goes rogue you rotate the key and
pray, the logs blame a service account, and you can't prove what it did. RogueZero puts a **credential
firewall** between the agent and the tool that answers the four questions that matter — *who is this
agent, what may it do, can I kill it, and can I prove what happened.*

> New to the idea? [`docs/CONCEPTS.md`](docs/CONCEPTS.md) explains it in plain language. Built on W3C
> DIDs and Verifiable Credentials under the hood — but you never touch them.

## Status

🚧 **Early beta**, pre-1.0. The runtime (vault, SSRF-contained tool registry, credential injection,
the request spine), the HTTP and MCP entrypoints, and the self-host CLI all work and are exercised by
CI-enforced end-to-end demos. See [`CONTRIBUTING.md`](CONTRIBUTING.md) to build and run it.

## Quickstart — one command, then restart Claude

Give Claude scoped access to a tool without ever handing it your token. One interactive command
creates the runtime, stores your credential encrypted, onboards the agent, and writes your Claude
Desktop config:

```bash
npx @roguezero/cli quickstart
```

It asks which tool (GitHub, Slack, Stripe, …), opens the page to create the credential, and takes the
value. You **never pick a vault passphrase** — it generates and saves one for you. When it finishes,
fully quit Claude (⌘Q), reopen, and ask it to use the tool. That's it.

<details>
<summary>Prefer the explicit steps? Here's what quickstart runs for you.</summary>

```bash
export RZ_VAULT_PASSPHRASE="a long passphrase"

npx @roguezero/cli runtime init ./runtime --audience runtime://acme
echo "$GITHUB_TOKEN" | npx @roguezero/cli add github   # a curated, least-privilege tool def
npx @roguezero/cli onboard my-agent --tool github_create_issue=call
npx @roguezero/cli mcp-config --agent my-agent --write  # wire Claude Desktop for this machine
# …or `runtime serve` to expose the tools over HTTP instead
```

</details>

The token is sealed in an **encrypted vault** (a passphrase-derived key — nothing secret at rest).
The agent authenticates and calls the tool; the runtime injects the token server-side, calls the API,
and returns the result. The agent only ever holds *its own identity* — never your API key. Revoke it:

```bash
npx @roguezero/cli revoke --agent my-agent    # the next call is denied — before decrypt
```

## Plug into any MCP agent — zero agent-side code

Expose the same tools over MCP and point an **unmodified** MCP client (Cursor, VS Code, your SDK
agent) at them through `connect`. The agent sees your tools, calls them, and never learns a credential
existed:

```jsonc
{
  "mcpServers": {
    "tools": {
      "command": "npx",
      "args": ["@roguezero/cli", "connect", "--agent", "my-agent",
               "--", "npx", "@roguezero/cli", "runtime", "mcp"]
    }
  }
}
```

## How it works

Every call runs one ordered, **fail-closed** sequence — and the credential is decrypted **last**, only
after the call has earned it:

```
authenticate the agent   (signature · issuer trust · expiry · audience/nonce)
  → capability + policy   (may THIS agent call THIS tool, now? — default deny)
  → revocation            (checked fresh on every call — the kill switch)
  → resolve the request   (the agent named a TOOL, never a URL — the runtime pins the target)
  → decrypt + inject      (the credential, injected server-side — never logged, never returned)
  → call the tool → audit (actor, tool, decision, evidence, timestamp)
```

A call that fails authentication, policy, or revocation **never decrypts a credential** and never
touches the tool. One `revoke` kills one agent — no key rotation, no collateral damage.

## Why it's safe

- **Agents name a tool, never a URL.** The runtime pins scheme/host/path/method, refuses private and
  cloud-metadata addresses, connects to the validated IP (no DNS-rebind window), and never follows
  redirects — so it can't be turned into an SSRF machine.
- **Credentials are encrypted at rest** (envelope encryption, per-credential AEAD, whole-file
  integrity), injected server-side, and **never** logged, returned, or placed in a URL.
- **You hold the keys.** Root key from a passphrase (`argon2id`) or your KMS; secrets go in via
  env/stdin, never argv. Nothing leaves your box.

Full detail: [`docs/SECURITY.md`](docs/SECURITY.md) · [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) ·
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Also: agent identity for your own MCP/HTTP tools

The runtime is built on a reusable trust spine you can use on its own — give an agent a scoped,
revocable identity and protect *your own* tool with one `guard.protect(...)` call, no credential
injection involved. That's the `init` / `onboard` / `connect` / `revoke` flow, and the unattended
lifecycle (`renew --all`) that rotates credentials on a schedule without ever letting an agent mint
its own. See [`packages/cli/README.md`](packages/cli/README.md).

## Run the demos

From a checkout (Node ≥ 22.13 and [pnpm](https://pnpm.io) via `corepack enable`; the published
packages run on Node ≥ 20):

```bash
pnpm install && pnpm build
node examples/protected-tool/dist/demo-runtime-mcp.js   # the one to watch
```

**`demo-runtime-mcp` is the headline:** a stock MCP client — no RogueZero code — reaches a real tool
through `connect` → `runtime mcp`, the credential is injected server-side, and after `revoke` the same
call dies. It writes everything to a throwaway temp dir. Every demo runs in CI, so if any of this
stops being true, the build goes red.

## Layout

| Path | Contents |
|---|---|
| `packages/core` | The runtime spine, credential vault + key providers, tool registry, injection proxy — plus DID/VC identity, policy, revocation, audit |
| `packages/middleware` | MCP server wrapper + HTTP middleware over the identity spine |
| `packages/cli` | `quickstart` (one-command setup) · `runtime init/tool/secret/serve/mcp` · `add/onboard/mcp-config/connect/renew/revoke` · lower-level identity ops |
| `examples/protected-tool` | CI-enforced end-to-end demos (runtime over HTTP + MCP, unattended lifecycle, plug-and-play proxy) |
| `docs/` | [Concepts](docs/CONCEPTS.md) · [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) · [Threat model](docs/THREAT-MODEL.md) |

Contributing? See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports: [`SECURITY.md`](SECURITY.md).

## License

[Apache-2.0](LICENSE). Free forever for the open-source runtime, SDK, middleware, and CLI.
