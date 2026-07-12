# @roguezero/cli

**Give an agent scoped access to a tool — without handing it the credential.** Open-source and
self-hosted: the runtime holds your tool's API key, the agent authenticates, and the runtime injects
the key server-side on every call. Revoke, and the next call dies — before the key is even decrypted.

## Self-host a tool runtime

```bash
export RZ_VAULT_PASSPHRASE="a long passphrase"

npx @roguezero/cli runtime init ./runtime --audience runtime://acme
npx @roguezero/cli runtime tool add github --url https://api.github.com/user --cred-ref gh
echo "$GITHUB_TOKEN" | npx @roguezero/cli runtime secret set --tool github --ref gh
npx @roguezero/cli onboard my-agent --tool github=gh:read   # grant an agent the tool
npx @roguezero/cli runtime serve                            # http://127.0.0.1:8787
```

Now an agent calls the tool through the runtime and **never holds the token**:

- `GET /challenge` → a one-time nonce
- `POST /call {tool, presentation}` → the runtime authenticates the agent, checks policy and
  revocation, decrypts the credential, injects it, calls the tool, audits, and returns the result.

The token lives **encrypted in the vault** (a passphrase-derived key — nothing secret at rest). The
agent only ever holds its own identity, never your API key. Revoke the agent and the next call is
denied *before the credential is even decrypted*.

### Why it's safe

- Agents name a **tool**, never a URL — the runtime pins scheme/host/path/method, so there's no SSRF
  (private/metadata addresses are refused unless a tool is explicitly `--internal`).
- Credentials are AEAD-encrypted at rest (envelope encryption, whole-file integrity), injected
  server-side, and **never logged, returned, or placed in a URL**.
- The vault passphrase and the secrets come from **env/stdin, never argv** (no shell-history leaks).
- **Decrypt is last:** an unauthenticated, unauthorized, or revoked call never touches the vault.

## Agent identity (how agents authenticate)

`onboard` writes `my-agent.rz.json` — one file (mode `0600`) holding the agent's key and credentials,
the way a kubeconfig holds a cluster's. The agent presents it on every call; it never sees your tool
credential, only its own identity. For **MCP** tools instead of the HTTP runtime, `connect` is a
stdio proxy that does the same on the agent side with zero agent-side code:

```bash
npx @roguezero/cli connect --agent my-agent -- node ./your-mcp-server.js
```

`connect` needs `@modelcontextprotocol/sdk` (an optional peer); every other command works without it.

## Agents that run unattended

Credentials still rotate — but an agent that can renew itself can't be killed, so renewal runs
**where the controller key lives** (a cron host), never on the agent:

```bash
roguezero renew --all      # renew every agent that's due; refuse any you've revoked
```

`connect` and the runtime re-read on every call, so a renewed credential reaches a running agent with
no restart — and `renew --all` refuses a revoked agent, so `revoke` is final. CI-enforced.

## Command reference

```
roguezero runtime init | tool add | secret set | serve   self-host a credential-injecting runtime
roguezero init | onboard | connect | renew | revoke      agent identity: scaffold, grant, run, kill
roguezero create | issue | verify | inspect              lower-level identity/credential ops
roguezero revocations publish                            sign a fleet-wide kill switch
```

`RZ_VAULT_PASSPHRASE` is required for `runtime` commands; secrets go in via `RZ_SECRET` or stdin.
Run `roguezero --help` for flags.

Status: **early beta**, pre-1.0. The runtime, unattended lifecycle, and plug-and-play MCP flows are
each exercised by CI-enforced end-to-end demos.
